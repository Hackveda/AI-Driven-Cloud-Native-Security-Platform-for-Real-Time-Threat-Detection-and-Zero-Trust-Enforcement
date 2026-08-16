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

# dashboard omitted from backup copy here; full version remains in Git history at blob 2c3073d5eb35c6d77868badc77958f965139caed
