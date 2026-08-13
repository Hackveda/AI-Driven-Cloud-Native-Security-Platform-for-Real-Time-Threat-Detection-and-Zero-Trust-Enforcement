from __future__ import annotations
import asyncio, json, os
from contextlib import asynccontextmanager
from fastapi import FastAPI, HTTPException
from fastapi.responses import HTMLResponse
from prometheus_client import Counter, Histogram, generate_latest, CONTENT_TYPE_LATEST
from starlette.responses import Response
from aiokafka import AIOKafkaConsumer, AIOKafkaProducer

from .models import TelemetryEvent, Detection
from .detector import AnomalyDetector
from .context import ContextAnalyzer
from .policy import PolicyEngine
from .store import AuditStore

KAFKA_BOOTSTRAP = os.getenv("KAFKA_BOOTSTRAP", "redpanda:9092")
TOPIC = os.getenv("TELEMETRY_TOPIC", "security.telemetry")
USE_KAFKA = os.getenv("USE_KAFKA", "true").lower() == "true"
ENFORCEMENT_MODE = os.getenv("ENFORCEMENT_MODE", "simulate")  # simulate | require-approval | active
DB_PATH = os.getenv("DB_PATH", "/data/security.db")

EVENTS = Counter("security_events_total", "Telemetry events processed", ["type", "severity"])
LATENCY = Histogram("security_inference_seconds", "Detection pipeline latency")
ACTIONS = Counter("security_actions_total", "Policy actions", ["action", "status"])

detector = AnomalyDetector(); analyzer = ContextAnalyzer(); policy = PolicyEngine(); store = AuditStore(DB_PATH)
producer: AIOKafkaProducer | None = None
consumer_task: asyncio.Task | None = None

async def evaluate(event: TelemetryEvent) -> Detection:
    with LATENCY.time():
        risk, reasons = detector.score(event)
        decision = policy.decide(event, risk)
        if decision.action == "allow": status = "not_required"
        elif ENFORCEMENT_MODE == "simulate": status = "simulated"
        elif decision.approval_required or ENFORCEMENT_MODE == "require-approval": status = "approval_required"
        else: status = "applied"  # Adapter hook for firewall / identity / Tetragon controller.
        summary = analyzer.summarize(event, risk, reasons, decision.action)
        d = Detection(event=event, anomaly_score=risk, severity=decision.severity, reasons=reasons,
                      context_summary=summary, recommended_action=decision.action, enforcement_status=status)
        store.save(d)
        EVENTS.labels(event.event_type, decision.severity).inc(); ACTIONS.labels(decision.action, status).inc()
        return d

async def consume_loop() -> None:
    consumer = AIOKafkaConsumer(TOPIC, bootstrap_servers=KAFKA_BOOTSTRAP, group_id="security-detector",
                               auto_offset_reset="earliest", enable_auto_commit=True)
    await consumer.start()
    try:
        async for msg in consumer:
            try: await evaluate(TelemetryEvent.model_validate_json(msg.value))
            except Exception as exc: print("bad event:", exc, flush=True)
    finally: await consumer.stop()

@asynccontextmanager
async def lifespan(app: FastAPI):
    global producer, consumer_task
    if USE_KAFKA:
        for attempt in range(20):
            try:
                producer = AIOKafkaProducer(bootstrap_servers=KAFKA_BOOTSTRAP)
                await producer.start(); consumer_task = asyncio.create_task(consume_loop()); break
            except Exception as exc:
                print(f"Kafka not ready ({attempt+1}/20): {exc}", flush=True); await asyncio.sleep(2)
        else: print("Starting without Kafka; direct /v1/evaluate still works", flush=True)
    yield
    if consumer_task: consumer_task.cancel()
    if producer: await producer.stop()

app = FastAPI(title="AI Cloud-Native Security Platform", version="1.0.0", lifespan=lifespan)

@app.get("/health")
def health(): return {"status":"ok", "kafka": bool(producer), "enforcement_mode": ENFORCEMENT_MODE}

@app.post("/v1/evaluate", response_model=Detection)
async def direct_evaluate(event: TelemetryEvent): return await evaluate(event)

@app.post("/v1/telemetry")
async def ingest(event: TelemetryEvent):
    if producer is None: raise HTTPException(503, "Kafka producer unavailable; use /v1/evaluate for direct mode")
    await producer.send_and_wait(TOPIC, event.model_dump_json().encode())
    return {"accepted": True, "event_id": event.event_id}

@app.get("/v1/detections")
def detections(limit: int = 100): return store.latest(min(max(limit, 1), 500))

@app.get("/metrics")
def metrics(): return Response(generate_latest(), media_type=CONTENT_TYPE_LATEST)

@app.get("/", response_class=HTMLResponse)
def dashboard():
    return HTMLResponse('''<!doctype html><html><head><meta charset="utf-8"><title>Security Command Center</title>
<style>body{font-family:system-ui;margin:0;background:#0b1020;color:#eef2ff}.wrap{max-width:1180px;margin:auto;padding:30px}.hero{display:flex;justify-content:space-between;align-items:center}.pill{background:#18213c;padding:8px 12px;border-radius:999px}.grid{display:grid;grid-template-columns:repeat(4,1fr);gap:12px;margin:20px 0}.card{background:#121a30;border:1px solid #27314d;border-radius:14px;padding:16px}.events{display:grid;gap:10px}.event{background:#121a30;border-left:5px solid #748ffc;border-radius:10px;padding:14px}.critical{border-color:#ff6b6b}.high{border-color:#ffa94d}.medium{border-color:#ffd43b}.low{border-color:#69db7c}small{color:#a5b4d4}code{color:#9de1ff}@media(max-width:800px){.grid{grid-template-columns:1fr 1fr}}</style></head>
<body><div class="wrap"><div class="hero"><div><h1>AI Security Command Center</h1><small>Telemetry → ML score → Context → Zero Trust policy → Enforcement</small></div><span class="pill">LIVE DEMO</span></div>
<div class="grid"><div class="card"><b id="total">0</b><br><small>Detections</small></div><div class="card"><b id="critical">0</b><br><small>Critical</small></div><div class="card"><b id="blocked">0</b><br><small>Block/Quarantine</small></div><div class="card"><b id="avg">0</b><br><small>Avg risk</small></div></div><div class="events" id="events"></div></div>
<script>async function load(){let d=await(await fetch('/v1/detections?limit=50')).json();total.textContent=d.length;critical.textContent=d.filter(x=>x.severity==='critical').length;blocked.textContent=d.filter(x=>['block','quarantine'].includes(x.recommended_action)).length;avg.textContent=d.length?(d.reduce((a,x)=>a+x.anomaly_score,0)/d.length).toFixed(2):'0';events.innerHTML=d.map(x=>`<div class="event ${x.severity}"><b>${x.severity.toUpperCase()} · ${x.recommended_action.toUpperCase()}</b> <small>${x.event.event_type} · ${x.event.event_id}</small><br><code>risk=${x.anomaly_score}</code> · ${x.reasons.join(', ')}<br><small>${x.context_summary}</small></div>`).join('')||'<div class="card">No events yet. Run the simulator.</div>'}load();setInterval(load,2500)</script></body></html>''')
