from dataclasses import dataclass
from .models import TelemetryEvent

@dataclass
class Decision:
    severity: str
    action: str
    approval_required: bool = False

class PolicyEngine:
    """Zero-Trust decision policy with staged enforcement to reduce blast radius."""
    def decide(self, event: TelemetryEvent, risk: float) -> Decision:
        if event.known_bad_ioc and risk >= 0.95:
            return Decision("critical", "block", approval_required=True)
        if risk >= 0.85:
            return Decision("high", "quarantine", approval_required=True)
        if risk >= 0.60:
            return Decision("medium", "alert")
        return Decision("low", "allow")
