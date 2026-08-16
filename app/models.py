from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Literal

from pydantic import BaseModel, Field

Severity = Literal["low", "medium", "high", "critical"]
Action = Literal["allow", "alert", "quarantine", "block"]


class RiskFactor(BaseModel):
    code: str
    label: str
    weight: float
    evidence: str


class TelemetryEvent(BaseModel):
    event_id: str
    event_type: str
    tetragon_event_type: str | None = None
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))

    cluster_name: str = "default-cluster"
    node_name: str | None = None
    namespace: str | None = None
    pod_name: str | None = None
    pod_uid: str | None = None
    workload: str | None = None
    container_name: str | None = None
    container_id: str | None = None
    pod_labels: dict[str, str] = Field(default_factory=dict)

    exec_id: str | None = None
    binary: str | None = None
    args: str | None = None
    cwd: str | None = None
    pid: int | None = None
    uid: int | None = None
    username: str | None = None

    parent_exec_id: str | None = None
    parent_binary: str | None = None
    parent_args: str | None = None
    parent_pid: int | None = None
    parent_uid: int | None = None

    source_ip: str | None = None
    destination_ip: str | None = None
    source_port: int | None = None
    destination_port: int | None = None
    destination_host: str | None = None
    protocol: str | None = None

    syscall: str | None = None
    policy_name: str | None = None
    kernel_activity: list[str] = Field(default_factory=list)
    tags: list[str] = Field(default_factory=list)

    privileged: bool = False
    known_bad_ioc: bool = False

    raw_event: dict[str, Any] = Field(default_factory=dict)


class Detection(BaseModel):
    event: TelemetryEvent
    anomaly_score: float
    severity: Severity
    risk_factors: list[RiskFactor] = Field(default_factory=list)
    reasons: list[str] = Field(default_factory=list)
    context_summary: str
    recommended_action: Action
    enforcement_status: Literal[
        "not_required",
        "simulated",
        "applied",
        "approval_required",
    ]
    explanation_source: Literal["ollama", "deterministic"]
