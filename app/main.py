from __future__ import annotations

import asyncio
import json
import os
from contextlib import asynccontextmanager
from zoneinfo import ZoneInfo

from aiokafka import AIOKafkaConsumer, AIOKafkaProducer
from fastapi import Body, FastAPI, HTTPException, Query
from fastapi.responses import HTMLResponse, StreamingResponse
from prometheus_client import CONTENT_TYPE_LATEST, Counter, Histogram, generate_latest
from starlette.responses import Response

from .context import ContextAnalyzer
from .detector import RiskEngine
from .models import Detection, TelemetryEvent
from .policy import PolicyEngine
from .store import AuditStore
from .tetragon import normalize_tetragon_event

KAFKA_BOOTSTRAP = os.getenv("KAFKA_BOOTSTRAP", "redpanda:9092")
TOPIC = os.getenv("TELEMETRY_TOPIC", "security.telemetry")
USE_KAFKA = os.getenv("USE_KAFKA", "true").lower() == "true"
ENFORCEMENT_MODE = os.getenv("ENFORCEMENT_MODE", "simulate")
DB_PATH = os.getenv("DB_PATH", "/data/security.db")
IST = ZoneInfo("Asia/Kolkata")

EVENTS = Counter("security_events_total", "Telemetry events processed", ["type", "severity"])
LATENCY = Histogram("security_pipeline_seconds", "Fast scoring pipeline latency")
ACTIONS = Counter("security_actions_total", "Policy actions", ["action", "status"])

detector = RiskEngine()
analyzer = ContextAnalyzer()
policy = PolicyEngine()
store = AuditStore(DB_PATH)

producer: AIOKafkaProducer | None = None
consumer_task: asyncio.Task | None = None
subscribers: set[asyncio.Queue] = set()
ollama_tasks: set[asyncio.Task] = set()


def ist_time(dt) -> str:
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=ZoneInfo("UTC"))
    return dt.astimezone(IST).strftime("%H:%M:%S IST")


def soc_payload(detection: Detection, phase: str = "final") -> dict:
    data = detection.model_dump(mode="json")
    data["timestamp_ist"] = ist_time(detection.event.timestamp)
    data["phase"] = phase
    data["risk_score_100"] = round(float(detection.anomaly_score) * 100)
    return data


async def broadcast_payload(payload: dict) -> None:
    for queue in list(subscribers):
        try:
            queue.put_nowait(payload)
        except asyncio.QueueFull:
            try:
                queue.get_nowait()
                queue.put_nowait(payload)
            except Exception:
                subscribers.discard(queue)


def action_status(action: str, approval_required: bool) -> str:
    if action == "allow":
        return "not_required"
    if ENFORCEMENT_MODE == "simulate":
        return "simulated"
    if approval_required or ENFORCEMENT_MODE == "require-approval":
        return "approval_required"
    return "applied"


def immediate_summary(event: TelemetryEvent, risk: float, reasons: list[str], action: str) -> str:
    command = " ".join(x for x in [event.binary, event.args] if x).strip() or "runtime activity"
    if risk < 0.35:
        return f"{command} was observed by Tetragon. Initial scoring found no elevated-risk indicators; Ollama analysis is being generated."
    why = "; ".join(reasons[:2])
    return f"{command} was observed by Tetragon. Initial risk is {risk:.2f}/1.00 because {why} Ollama analysis is being generated."


async def enrich_with_ollama(
    event: TelemetryEvent,
    risk: float,
    factors,
    reasons: list[str],
    decision,
    status: str,
) -> None:
    try:
        # Critical fix: the Ollama SDK is synchronous. Run it in a worker thread
        # so the Kafka consumer and SSE event loop never wait for LLM inference.
        summary, source = await asyncio.to_thread(
            analyzer.summarize,
            event,
            risk,
            reasons,
            decision.action,
            factors,
        )

        detection = Detection(
            event=event,
            anomaly_score=risk,
            severity=decision.severity,
            risk_factors=factors,
            reasons=reasons,
            context_summary=summary,
            recommended_action=decision.action,
            enforcement_status=status,
            explanation_source=source,
        )
        store.save(detection)
        await broadcast_payload(soc_payload(detection, "final"))
    except Exception as exc:
        print(f"ollama enrichment failed for {event.event_id}: {exc}", flush=True)


async def evaluate(event: TelemetryEvent) -> Detection:
    """Fast path: score, store, and broadcast before Ollama runs."""
    with LATENCY.time():
        risk, factors, reasons = detector.score(event)
        decision = policy.decide(event, risk)
        status = action_status(decision.action, decision.approval_required)

        pending = Detection(
            event=event,
            anomaly_score=risk,
            severity=decision.severity,
            risk_factors=factors,
            reasons=reasons,
            context_summary=immediate_summary(event, risk, reasons, decision.action),
            recommended_action=decision.action,
            enforcement_status=status,
            explanation_source="deterministic",
        )

        # Persist and push immediately. This is the event the UI sees first.
        store.save(pending)
        EVENTS.labels(event.event_type, decision.severity).inc()
        ACTIONS.labels(decision.action, status).inc()
        await broadcast_payload(soc_payload(pending, "pending_ai"))

        task = asyncio.create_task(
            enrich_with_ollama(event, risk, factors, reasons, decision, status)
        )
        ollama_tasks.add(task)
        task.add_done_callback(ollama_tasks.discard)
        return pending


async def consume_loop() -> None:
    consumer = AIOKafkaConsumer(
        TOPIC,
        bootstrap_servers=KAFKA_BOOTSTRAP,
        group_id="security-detector-v3-instant",
        auto_offset_reset="latest",
        enable_auto_commit=True,
    )
    await consumer.start()
    try:
        async for msg in consumer:
            try:
                # evaluate() no longer waits for Ollama, so the consumer can keep
                # draining Tetragon events at full speed.
                await evaluate(TelemetryEvent.model_validate_json(msg.value))
            except Exception as exc:
                print("bad event:", exc, flush=True)
    finally:
        await consumer.stop()


@asynccontextmanager
async def lifespan(app: FastAPI):
    global producer, consumer_task
    if USE_KAFKA:
        for attempt in range(20):
            try:
                producer = AIOKafkaProducer(bootstrap_servers=KAFKA_BOOTSTRAP)
                await producer.start()
                consumer_task = asyncio.create_task(consume_loop())
                break
            except Exception as exc:
                print(f"Kafka not ready {attempt + 1}/20: {exc}", flush=True)
                await asyncio.sleep(2)
    yield
    if consumer_task:
        consumer_task.cancel()
        try:
            await consumer_task
        except asyncio.CancelledError:
            pass
    for task in list(ollama_tasks):
        task.cancel()
    if producer:
        await producer.stop()


app = FastAPI(title="Tetragon AI SOC", version="3.0.0", lifespan=lifespan)


@app.get("/health")
def health():
    return {
        "status": "ok",
        "version": "3.0.0",
        "kafka": bool(producer),
        "topic": TOPIC,
        "enforcement_mode": ENFORCEMENT_MODE,
        "timezone": "Asia/Kolkata",
        "streaming": "SSE",
        "ollama_mode": "asynchronous_enrichment",
    }


@app.post("/v1/evaluate", response_model=Detection)
async def direct(event: TelemetryEvent):
    return await evaluate(event)


@app.post("/v1/tetragon")
async def tetragon(raw: dict = Body(...), cluster: str | None = Query(default=None)):
    try:
        event = normalize_tetragon_event(raw, cluster)
    except Exception as exc:
        raise HTTPException(422, f"Unable to normalize Tetragon event: {exc}") from exc

    if producer is not None:
        await producer.send_and_wait(TOPIC, event.model_dump_json().encode())
        return {"accepted": True, "event_id": event.event_id, "pipeline": "kafka"}

    detection = await evaluate(event)
    return {
        "accepted": True,
        "event_id": event.event_id,
        "pipeline": "direct",
        "risk": detection.anomaly_score,
    }


@app.post("/v1/telemetry")
async def telemetry(event: TelemetryEvent):
    if producer is not None:
        await producer.send_and_wait(TOPIC, event.model_dump_json().encode())
        return {"accepted": True, "event_id": event.event_id, "pipeline": "kafka"}
    return await evaluate(event)


@app.get("/v1/detections")
def detections(limit: int = 100):
    out = []
    for row in store.latest(min(max(limit, 1), 500)):
        try:
            out.append(soc_payload(Detection.model_validate(row), "final"))
        except Exception:
            out.append(row)
    return out


@app.get("/v1/stream")
async def stream():
    queue: asyncio.Queue = asyncio.Queue(maxsize=500)
    subscribers.add(queue)

    async def generate():
        try:
            yield ": connected\n\n"
            while True:
                try:
                    item = await asyncio.wait_for(queue.get(), timeout=10)
                    yield "data: " + json.dumps(item) + "\n\n"
                except asyncio.TimeoutError:
                    yield ": keepalive\n\n"
        finally:
            subscribers.discard(queue)

    return StreamingResponse(
        generate(),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache, no-transform",
            "Connection": "keep-alive",
            "X-Accel-Buffering": "no",
        },
    )


@app.get("/metrics")
def metrics():
    return Response(generate_latest(), media_type=CONTENT_TYPE_LATEST)


@app.get("/", response_class=HTMLResponse)
def dashboard():
    return HTMLResponse(r'''<!doctype html>
<html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Tetragon AI Security Operations Center</title>
<style>
:root{--bg:#06101c;--panel:#0d1929;--line:#203650;--text:#edf5ff;--muted:#8299b7;--green:#41df9b;--yellow:#ffd166;--orange:#ff984f;--red:#ff5570;--blue:#63b4ff}
*{box-sizing:border-box}body{margin:0;background:radial-gradient(circle at 12% 0,#10294a 0,transparent 30%),var(--bg);color:var(--text);font-family:Inter,system-ui,-apple-system,Segoe UI,sans-serif}.wrap{max-width:1650px;margin:auto;padding:24px}
header{display:flex;justify-content:space-between;align-items:center;gap:20px;margin-bottom:18px}h1{margin:0;font-size:25px}.sub{font-size:13px;color:var(--muted);margin-top:5px}.live{font-size:12px;font-weight:900;color:var(--green);border:1px solid #235844;background:#0c261e;border-radius:99px;padding:9px 13px}
.stats{display:grid;grid-template-columns:repeat(5,1fr);gap:10px;margin-bottom:12px}.stat,.event{background:linear-gradient(145deg,#101e31,#091522);border:1px solid var(--line);border-radius:14px}.stat{padding:14px}.label{font-size:10px;color:var(--muted);letter-spacing:.9px;text-transform:uppercase}.number{font-size:26px;font-weight:900;margin-top:5px}
.toolbar{display:flex;gap:7px;flex-wrap:wrap;margin:12px 0}button,input{background:#091625;border:1px solid var(--line);color:var(--text);border-radius:8px;padding:8px 11px}button{color:var(--muted);cursor:pointer}button.on{background:#15365c;color:#c5e4ff;border-color:#3a6fa5}input{margin-left:auto;min-width:330px}
.feed{display:grid;gap:10px}.event{position:relative;overflow:hidden;padding:16px 18px 16px 20px}.event:before{content:"";position:absolute;left:0;top:0;bottom:0;width:4px;background:var(--green)}.event.medium:before{background:var(--yellow)}.event.high:before{background:var(--orange)}.event.critical:before{background:var(--red)}
.eventhead{display:flex;justify-content:space-between;gap:12px;align-items:center;margin-bottom:14px}.time{font-size:18px;font-weight:900}.phase{font-size:10px;color:var(--blue);letter-spacing:.8px}.grid{display:grid;grid-template-columns:repeat(4,minmax(160px,1fr));gap:9px}.field{background:#091524;border:1px solid #1b3049;border-radius:9px;padding:10px;min-height:66px}.field.wide{grid-column:span 2}.field.full{grid-column:1/-1}.value{font-size:13px;line-height:1.42;margin-top:5px;word-break:break-word}.mono{font-family:ui-monospace,SFMono-Regular,Consolas,monospace}.ai{background:linear-gradient(135deg,#0c1d32,#0b1728);border-color:#28517a}.ai .label{color:#74bcff}.riskrow{display:grid;grid-template-columns:1fr 1fr;gap:9px}.risknum{font-size:30px;font-weight:900}.severity{font-size:22px;font-weight:900}.lowtxt{color:var(--green)}.mediumtxt{color:var(--yellow)}.hightxt{color:var(--orange)}.criticaltxt{color:var(--red)}.bar{height:7px;background:#17283d;border-radius:10px;overflow:hidden;margin-top:8px}.fill{height:100%}.chips{display:flex;gap:5px;flex-wrap:wrap;margin-top:10px}.chip{font-size:10px;color:#afc4de;border:1px solid #243c57;border-radius:6px;padding:4px 6px}.foot{font-size:10px;color:var(--muted);margin-top:10px}.empty{padding:55px;text-align:center;color:var(--muted)}
@media(max-width:1000px){.stats{grid-template-columns:repeat(2,1fr)}.grid{grid-template-columns:repeat(2,1fr)}}@media(max-width:650px){.wrap{padding:12px}.grid{grid-template-columns:1fr}.field.wide,.field.full{grid-column:auto}.riskrow{grid-template-columns:1fr}.eventhead,header{align-items:flex-start;flex-direction:column}input{margin-left:0;min-width:100%}}
</style></head><body><div class="wrap">
<header><div><h1>Tetragon AI Security Operations Center</h1><div class="sub">Instant Kubernetes runtime telemetry · asynchronous Ollama enrichment · explainable risk · IST</div></div><div class="live" id="live">● CONNECTING</div></header>
<div class="stats"><div class="stat"><div class="label">Events</div><div class="number" id="n">0</div></div><div class="stat"><div class="label">Critical</div><div class="number" id="c">0</div></div><div class="stat"><div class="label">High</div><div class="number" id="h">0</div></div><div class="stat"><div class="label">Needs Action</div><div class="number" id="a">0</div></div><div class="stat"><div class="label">Average Risk</div><div class="number" id="avg">0</div></div></div>
<div class="toolbar"><button class="on" data-f="all">All</button><button data-f="critical">Critical</button><button data-f="high">High</button><button data-f="medium">Medium</button><button data-f="low">Low</button><input id="q" placeholder="Search user, process, command, pod, node, destination…"></div><div id="feed" class="feed"></div></div>
<script>
let D=[],F="all";const esc=v=>String(v??"").replace(/[&<>"']/g,m=>({"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;","'":"&#039;"}[m]));
function basename(p){if(!p)return"unknown";let x=String(p).split("/");return x[x.length-1]||p}function command(e){return [e.binary,e.args].filter(Boolean).join(" ")||"unknown"}
function user(e){if(e.user)return e.user;if(e.uid===0)return"root";if(e.uid!==null&&e.uid!==undefined)return`UID ${e.uid}`;return"unknown"}
function kernel(e){let t=e.tetragon_event_type||e.event_type;if(e.destination_ip)return"execve → socket → connect";if(t==="process_exec")return"execve";if(t==="process_exit")return"process exit";if(t==="process_kprobe")return e.syscall?`kprobe → ${e.syscall}`:"kprobe";if(t==="process_tracepoint")return e.syscall?`tracepoint → ${e.syscall}`:"tracepoint";return t||"runtime event"}
function destination(e){return e.destination_ip?`${e.destination_ip}${e.destination_port?":"+e.destination_port:""}`:"Not present in this event"}
function eventName(e){if(e.destination_ip)return"Outbound command execution";if(e.tetragon_event_type==="process_exec")return"Process execution";if(e.tetragon_event_type==="process_exit")return"Process exit";return (e.tetragon_event_type||e.event_type||"Runtime event").replaceAll("_"," ")}
function color(r){return r>=80?"#ff5570":r>=65?"#ff984f":r>=35?"#ffd166":"#41df9b"}function cls(s){return s+"txt"}
function visible(x){if(F!=="all"&&x.severity!==F)return false;let s=q.value.trim().toLowerCase();if(!s)return true;return (JSON.stringify(x.event)+" "+x.context_summary).toLowerCase().includes(s)}
function upsert(x){let i=D.findIndex(v=>v.event?.event_id===x.event?.event_id);if(i>=0)D[i]=x;else D.unshift(x);if(D.length>500)D.length=500;render()}
function render(){let z=D.filter(visible);n.textContent=z.length;c.textContent=z.filter(x=>x.severity==="critical").length;h.textContent=z.filter(x=>x.severity==="high").length;a.textContent=z.filter(x=>["alert","quarantine","block"].includes(x.recommended_action)).length;avg.textContent=z.length?Math.round(z.reduce((s,x)=>s+Number(x.risk_score_100??x.anomaly_score*100),0)/z.length):0;
feed.innerHTML=z.map(x=>{let e=x.event||{},r=Number(x.risk_score_100??Math.round(Number(x.anomaly_score||0)*100)),pending=x.phase==="pending_ai";let factors=(x.risk_factors||[]).map(f=>`<span class="chip" title="${esc(f.evidence)}">${esc(f.label)} +${Math.round(Number(f.weight)*100)}</span>`).join("");return `<article class="event ${esc(x.severity)}"><div class="eventhead"><div><div class="time">${esc(x.timestamp_ist||e.timestamp)}</div><div class="phase">${pending?"EVENT RECEIVED · OLLAMA ANALYSIS IN PROGRESS":"EVENT ANALYZED"}</div></div><div class="severity ${cls(x.severity)}">${esc(x.severity.toUpperCase())}</div></div><div class="grid">
<div class="field wide"><div class="label">Event</div><div class="value">${esc(eventName(e))}</div></div><div class="field"><div class="label">User</div><div class="value">${esc(user(e))}</div></div><div class="field"><div class="label">Parent</div><div class="value mono">${esc(basename(e.parent_binary))}</div></div>
<div class="field"><div class="label">Process</div><div class="value mono">${esc(e.binary||"unknown")}</div></div><div class="field wide"><div class="label">Command</div><div class="value mono">${esc(command(e))}</div></div><div class="field"><div class="label">Kernel Activity</div><div class="value mono">${esc(kernel(e))}</div></div>
<div class="field wide"><div class="label">Destination</div><div class="value mono">${esc(destination(e))}</div></div><div class="field"><div class="label">Pod / Namespace</div><div class="value">${esc((e.pod_name||"-")+" / "+(e.namespace||"-"))}</div></div><div class="field"><div class="label">Node</div><div class="value">${esc(e.node_name||"-")}</div></div>
<div class="field full ai"><div class="label">✦ Ollama Analysis</div><div class="value">${pending?'<span style="color:#7ebcff">Analyzing event asynchronously…</span><br>':''}${esc(x.context_summary||"")}</div></div>
<div class="field wide"><div class="label">Risk Score</div><div class="risknum" style="color:${color(r)}">${r} / 100</div><div class="bar"><div class="fill" style="width:${r}%;background:${color(r)}"></div></div></div><div class="field wide"><div class="label">Severity</div><div class="severity ${cls(x.severity)}">${esc(x.severity.toUpperCase())}</div><div class="value">Recommended action: ${esc((x.recommended_action||"").toUpperCase())}</div></div>
</div><div class="chips">${factors}</div><div class="foot">Cluster: ${esc(e.cluster_name||"-")} · Event ID: ${esc(e.event_id||"-")} · Enforcement: ${esc(x.enforcement_status||"-")}</div></article>`}).join("")||'<div class="stat empty">Waiting for Tetragon events…</div>'}
document.querySelectorAll("button[data-f]").forEach(b=>b.onclick=()=>{document.querySelectorAll("button[data-f]").forEach(x=>x.classList.remove("on"));b.classList.add("on");F=b.dataset.f;render()});q.oninput=render;
fetch("/v1/detections?limit=150",{cache:"no-store"}).then(r=>r.json()).then(x=>{D=x;render()});const stream=new EventSource("/v1/stream");stream.onopen=()=>live.textContent="● LIVE";stream.onerror=()=>live.textContent="● RECONNECTING";stream.onmessage=e=>upsert(JSON.parse(e.data));
</script></body></html>''')
