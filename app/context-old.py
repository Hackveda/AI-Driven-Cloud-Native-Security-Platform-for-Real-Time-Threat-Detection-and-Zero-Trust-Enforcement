from .models import TelemetryEvent

class ContextAnalyzer:
    """Offline LLM-style explanation layer. Replace this class with an approved LLM endpoint in production."""
    def summarize(self, event: TelemetryEvent, risk: float, reasons: list[str], action: str) -> str:
        why = "; ".join(reasons)
        return (
            f"{event.event_type.upper()} event from {event.source_ip} to {event.destination_ip}:"
            f"{event.destination_port} scored {risk:.2f}. Evidence: {why}. "
            f"Recommended playbook: {action}. Validate identity, workload owner, recent deployments, "
            "and correlated events before irreversible enforcement."
        )
