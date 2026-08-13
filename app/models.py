from datetime import datetime, timezone
from typing import Literal
from pydantic import BaseModel, Field

EventType = Literal["network", "process", "file", "auth", "k8s"]

class TelemetryEvent(BaseModel):
    event_id: str
    event_type: EventType
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    source_ip: str = "10.0.0.10"
    destination_ip: str = "10.0.0.20"
    destination_port: int = 443
    process: str = "unknown"
    user: str = "unknown"
    namespace: str = "default"
    bytes_out: int = 0
    failed_auth_count: int = 0
    privileged: bool = False
    known_bad_ioc: bool = False

class Detection(BaseModel):
    event: TelemetryEvent
    anomaly_score: float
    severity: Literal["low", "medium", "high", "critical"]
    reasons: list[str]
    context_summary: str
    recommended_action: Literal["allow", "alert", "quarantine", "block"]
    enforcement_status: Literal["not_required", "simulated", "applied", "approval_required"]
