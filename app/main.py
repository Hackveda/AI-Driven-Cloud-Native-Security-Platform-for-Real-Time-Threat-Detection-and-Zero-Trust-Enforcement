from __future__ import annotations
import asyncio,json,os
from contextlib import asynccontextmanager
from zoneinfo import ZoneInfo
from aiokafka import AIOKafkaConsumer,AIOKafkaProducer
from fastapi import Body,FastAPI,HTTPException,Query
from fastapi.responses import HTMLResponse,StreamingResponse
from prometheus_client import CONTENT_TYPE_LATEST,Counter,Histogram,generate_latest
from starlette.responses import Response
from .context import ContextAnalyzer
from .detector import RiskEngine
from .models import Detection,TelemetryEvent
from .policy import PolicyEngine
from .store import AuditStore
from .tetragon import normalize_tetragon_event

KAFKA_BOOTSTRAP=os.getenv("KAFKA_BOOTSTRAP","redpanda:9092")
TOPIC=os.getenv("TELEMETRY_TOPIC","security.telemetry")
USE_KAFKA=os.getenv("USE_KAFKA","true").lower()=="true"
ENFORCEMENT_MODE=os.getenv("ENFORCEMENT_MODE","simulate")
DB_PATH=os.getenv("DB_PATH","/data/security.db")
IST=ZoneInfo("Asia/Kolkata")
EVENTS=Counter("security_events_total","Telemetry events processed",["type","severity"])
LATENCY=Histogram("security_inference_seconds","Risk pipeline latency")
ACTIONS=Counter("security_actions_total","Policy actions",["action","status"])
detector=RiskEngine(); analyzer=ContextAnalyzer(); policy=PolicyEngine(); store=AuditStore(DB_PATH)
producer=None; consumer_task=None; subscribers=set()

def ist(dt):
    if dt.tzinfo is None:dt=dt.replace(tzinfo=ZoneInfo("UTC"))
    return dt.astimezone(IST).strftime("%d %b %Y, %I:%M:%S %p IST")
def soc(d):
    x=d.model_dump(mode="json"); x["timestamp_ist"]=ist(d.event.timestamp); return x

async def broadcast(d):
    x=soc(d)
    for q in list(subscribers):
        try:q.put_nowait(x)
        except asyncio.QueueFull:
            try:q.get_nowait(); q.put_nowait(x)
            except Exception:subscribers.discard(q)

async def evaluate(event):
    with LATENCY.time():
        risk,factors,reasons=detector.score(event)
        decision=policy.decide(event,risk)
        if decision.action=="allow":status="not_required"
        elif ENFORCEMENT_MODE=="simulate":status="simulated"
        elif decision.approval_required or ENFORCEMENT_MODE=="require-approval":status="approval_required"
        else:status="applied"
        summary,source=analyzer.summarize(event,risk,reasons,decision.action,factors)
        d=Detection(event=event,anomaly_score=risk,severity=decision.severity,risk_factors=factors,reasons=reasons,context_summary=summary,recommended_action=decision.action,enforcement_status=status,explanation_source=source)
        store.save(d); EVENTS.labels(event.event_type,decision.severity).inc(); ACTIONS.labels(decision.action,status).inc()
        await broadcast(d); return d

async def consume_loop():
    c=AIOKafkaConsumer(TOPIC,bootstrap_servers=KAFKA_BOOTSTRAP,group_id="security-detector-v2",auto_offset_reset="latest",enable_auto_commit=True)
    await c.start()
    try:
        async for msg in c:
            try:await evaluate(TelemetryEvent.model_validate_json(msg.value))
            except Exception as e:print("bad event",e,flush=True)
    finally:await c.stop()

@asynccontextmanager
async def lifespan(app):
    global producer,consumer_task
    if USE_KAFKA:
        for i in range(20):
            try:
                producer=AIOKafkaProducer(bootstrap_servers=KAFKA_BOOTSTRAP); await producer.start()
                consumer_task=asyncio.create_task(consume_loop()); break
            except Exception as e:print(f"Kafka not ready {i+1}/20: {e}",flush=True); await asyncio.sleep(2)
    yield
    if consumer_task:
        consumer_task.cancel()
        try:await consumer_task
        except asyncio.CancelledError:pass
    if producer:await producer.stop()

app=FastAPI(title="Tetragon AI SOC",version="2.0.0",lifespan=lifespan)

@app.get("/health")
def health():return {"status":"ok","kafka":bool(producer),"topic":TOPIC,"enforcement_mode":ENFORCEMENT_MODE,"timezone":"Asia/Kolkata"}

@app.post("/v1/evaluate",response_model=Detection)
async def direct(event:TelemetryEvent):return await evaluate(event)

@app.post("/v1/tetragon")
async def tetragon(raw:dict=Body(...),cluster:str|None=Query(default=None)):
    try:event=normalize_tetragon_event(raw,cluster)
    except Exception as e:raise HTTPException(422,f"Unable to normalize Tetragon event: {e}") from e
    if producer is not None:
        await producer.send_and_wait(TOPIC,event.model_dump_json().encode())
        return {"accepted":True,"event_id":event.event_id,"pipeline":"kafka"}
    d=await evaluate(event)
    return {"accepted":True,"event_id":event.event_id,"pipeline":"direct","risk":d.anomaly_score}

@app.post("/v1/telemetry")
async def telemetry(event:TelemetryEvent):
    if producer is not None:
        await producer.send_and_wait(TOPIC,event.model_dump_json().encode())
        return {"accepted":True,"event_id":event.event_id,"pipeline":"kafka"}
    return await evaluate(event)

@app.get("/v1/detections")
def detections(limit:int=100):
    out=[]
    for row in store.latest(min(max(limit,1),500)):
        try:out.append(soc(Detection.model_validate(row)))
        except Exception:out.append(row)
    return out

@app.get("/v1/stream")
async def stream():
    q=asyncio.Queue(maxsize=200); subscribers.add(q)
    async def gen():
        try:
            yield ": connected\n\n"
            while True:
                try:yield "data: "+json.dumps(await asyncio.wait_for(q.get(),15))+"\n\n"
                except asyncio.TimeoutError:yield ": keepalive\n\n"
        finally:subscribers.discard(q)
    return StreamingResponse(gen(),media_type="text/event-stream",headers={"Cache-Control":"no-cache","X-Accel-Buffering":"no"})

@app.get("/metrics")
def metrics():return Response(generate_latest(),media_type=CONTENT_TYPE_LATEST)

@app.get("/",response_class=HTMLResponse)
def dashboard():
    return HTMLResponse('''
<!doctype html><html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Tetragon AI SOC</title>
<style>
:root{--bg:#07101d;--p:#0d1829;--b:#20344f;--t:#e9f1ff;--m:#88a0bf;--g:#3ee69a;--y:#ffd166;--o:#ff984f;--r:#ff5470}
*{box-sizing:border-box}body{margin:0;background:radial-gradient(circle at 15% 0,#10264a 0,transparent 28%),var(--bg);color:var(--t);font-family:Inter,system-ui,sans-serif}.w{max-width:1650px;margin:auto;padding:22px}
header{display:flex;justify-content:space-between;align-items:center;margin-bottom:16px}h1{margin:0;font-size:24px}.sub{color:var(--m);font-size:13px}.live{color:var(--g);border:1px solid #245b49;border-radius:99px;padding:8px 12px}
.stats{display:grid;grid-template-columns:repeat(5,1fr);gap:9px}.card,.ev{background:linear-gradient(145deg,#101e32,#0a1423);border:1px solid var(--b);border-radius:13px}.card{padding:13px}.lab{font-size:10px;color:var(--m);text-transform:uppercase}.num{font-size:25px;font-weight:900;margin-top:4px}
.tools{display:flex;gap:7px;margin:12px 0}button,input{background:#0b1728;color:var(--t);border:1px solid var(--b);border-radius:8px;padding:8px 10px}button{color:var(--m);cursor:pointer}button.on{color:#bde0ff;background:#14345c}input{margin-left:auto;min-width:300px}
.list{display:grid;gap:9px}.ev{position:relative;padding:15px 16px 13px 18px}.ev:before{content:"";position:absolute;left:0;top:0;bottom:0;width:4px;background:var(--g);border-radius:13px 0 0 13px}.ev.medium:before{background:var(--y)}.ev.high:before{background:var(--o)}.ev.critical:before{background:var(--r)}
.top,.foot{display:flex;justify-content:space-between;gap:12px}.sev{font-size:11px;font-weight:900}.low .sev{color:var(--g)}.medium .sev{color:var(--y)}.high .sev{color:var(--o)}.critical .sev{color:var(--r)}.cmd{margin-left:8px;font:13px ui-monospace,monospace}.time,.foot{font-size:11px;color:var(--m)}
.mid{display:grid;grid-template-columns:170px 1fr;gap:10px;margin-top:11px}.risk,.ai{background:#091523;border:1px solid #203b58;border-radius:9px;padding:10px}.rn{font-size:28px;font-weight:900}.bar{height:6px;background:#17273b;border-radius:10px;overflow:hidden}.fill{height:100%}.ai h4{font-size:10px;color:#79bdff;margin:0 0 6px}.ai div{font-size:13px;line-height:1.45}
.chips{display:flex;gap:5px;flex-wrap:wrap;margin-top:9px}.chip{font-size:10px;color:#aec3dd;border:1px solid #233c58;border-radius:6px;padding:4px 6px}.foot{margin-top:10px;padding-top:9px;border-top:1px solid #1a2c43}.act{font-weight:900}.allow{color:var(--g)}.alert{color:var(--y)}.quarantine{color:var(--o)}.block{color:var(--r)}
@media(max-width:850px){.stats{grid-template-columns:1fr 1fr}.mid{grid-template-columns:1fr}.top,.foot{flex-direction:column}input{margin-left:0;min-width:100%}}
</style></head><body><div class="w">
<header><div><h1>Tetragon AI Security Operations Center</h1><div class="sub">Real-time Kubernetes runtime telemetry · explainable risk · Ollama context · IST</div></div><div class="live" id="live">● LIVE</div></header>
<div class="stats"><div class="card"><div class="lab">Events</div><div class="num" id="n">0</div></div><div class="card"><div class="lab">Critical</div><div class="num" id="c">0</div></div><div class="card"><div class="lab">High</div><div class="num" id="h">0</div></div><div class="card"><div class="lab">Needs action</div><div class="num" id="a">0</div></div><div class="card"><div class="lab">Avg risk</div><div class="num" id="avg">0.00</div></div></div>
<div class="tools"><button class="on" data-f="all">All</button><button data-f="critical">Critical</button><button data-f="high">High</button><button data-f="medium">Medium</button><button data-f="low">Low</button><input id="q" placeholder="Search command, pod, namespace, node, IP…"></div>
<div id="list" class="list"></div></div>
<script>
let D=[],F="all";const E=v=>String(v??"").replace(/[&<>"']/g,m=>({"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;","'":"&#039;"}[m]));
function col(r){return r>=.8?"#ff5470":r>=.65?"#ff984f":r>=.35?"#ffd166":"#3ee69a"}function cmd(e){return [e.binary,e.args].filter(Boolean).join(" ")||(e.tetragon_event_type||e.event_type)}
function ok(x){if(F!="all"&&x.severity!=F)return false;let s=q.value.toLowerCase();if(!s)return true;return JSON.stringify(x.event).toLowerCase().includes(s)||String(x.context_summary).toLowerCase().includes(s)}
function render(){let z=D.filter(ok);n.textContent=z.length;c.textContent=z.filter(x=>x.severity=="critical").length;h.textContent=z.filter(x=>x.severity=="high").length;a.textContent=z.filter(x=>["alert","quarantine","block"].includes(x.recommended_action)).length;avg.textContent=z.length?(z.reduce((s,x)=>s+Number(x.anomaly_score),0)/z.length).toFixed(2):"0.00";
list.innerHTML=z.map(x=>{let e=x.event||{},r=Number(x.anomaly_score||0),chips=[`cluster: ${e.cluster_name}`,e.namespace&&`ns: ${e.namespace}`,e.pod_name&&`pod: ${e.pod_name}`,e.node_name&&`node: ${e.node_name}`,e.uid!==null&&e.uid!==undefined&&`uid: ${e.uid}`,e.cwd&&`cwd: ${e.cwd}`,e.parent_binary&&`parent: ${e.parent_binary}`,e.destination_ip&&`dst: ${e.destination_ip}${e.destination_port?":"+e.destination_port:""}`].filter(Boolean);let fs=(x.risk_factors||[]).map(f=>`<span class="chip" title="${E(f.evidence)}">${E(f.label)} +${Number(f.weight).toFixed(2)}</span>`).join("");
return `<div class="ev ${E(x.severity)}"><div class="top"><div><span class="sev">${E(x.severity.toUpperCase())}</span><span class="cmd">${E(cmd(e))}</span></div><div class="time">${E(x.timestamp_ist||e.timestamp)}</div></div><div class="mid"><div class="risk"><div class="lab">Risk score</div><div class="rn" style="color:${col(r)}">${r.toFixed(2)}</div><div class="bar"><div class="fill" style="width:${r*100}%;background:${col(r)}"></div></div></div><div class="ai"><h4>✦ SOC EXPLANATION · ${E((x.explanation_source||"").toUpperCase())}</h4><div>${E(x.context_summary)}</div></div></div><div class="chips">${chips.map(v=>`<span class="chip">${E(v)}</span>`).join("")}${fs}</div><div class="foot"><div>${E(e.tetragon_event_type||e.event_type)} · ${E(e.event_id)}</div><div>Recommended: <span class="act ${E(x.recommended_action)}">${E(x.recommended_action.toUpperCase())}</span> · ${E(x.enforcement_status)}</div></div></div>`}).join("")||'<div class="card" style="padding:40px;text-align:center;color:#88a0bf">Waiting for Tetragon events…</div>'}
document.querySelectorAll("button").forEach(b=>b.onclick=()=>{document.querySelectorAll("button").forEach(x=>x.classList.remove("on"));b.classList.add("on");F=b.dataset.f;render()});q.oninput=render;
fetch("/v1/detections?limit=150").then(r=>r.json()).then(x=>{D=x;render()});let s=new EventSource("/v1/stream");s.onopen=()=>live.textContent="● LIVE";s.onerror=()=>live.textContent="● RECONNECTING";s.onmessage=e=>{D.unshift(JSON.parse(e.data));if(D.length>500)D.pop();render()};
</script></body></html>''')
