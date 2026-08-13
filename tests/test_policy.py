from app.models import TelemetryEvent
from app.detector import AnomalyDetector
from app.policy import PolicyEngine

def event(**kw):
    base=dict(event_id="e1", event_type="network", destination_port=443, bytes_out=1000)
    base.update(kw); return TelemetryEvent(**base)

def test_known_ioc_becomes_critical_block():
    e=event(known_bad_ioc=True, privileged=True, failed_auth_count=8, destination_port=4444)
    risk,_=AnomalyDetector().score(e); d=PolicyEngine().decide(e,risk)
    assert risk >= .95 and d.severity == "critical" and d.action == "block" and d.approval_required

def test_normal_event_is_not_blocked():
    e=event(); risk,_=AnomalyDetector().score(e); d=PolicyEngine().decide(e,risk)
    assert d.action in {"allow","alert"}
