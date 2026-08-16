import ollama
from .models import TelemetryEvent

class ContextAnalyzer:
    """
    Local Ollama LLM-powered explanation layer. 
    Analyzes cluster security anomalies directly using local compute resources.
    """
    def __init__(self, model_name: str = "llama3.2:1b"):
        # Explicitly targets your downloaded lightweight 1B model variant
        self.model_name = model_name

    def summarize(self, event: TelemetryEvent, risk: float, reasons: list[str], action: str) -> str:
        why = "; ".join(reasons)
        
        # 1. Structure a concise prompt optimized for a 1B model context
        prompt = (
            f"Analyze this security anomaly and write a sharp, single-sentence summary.\n\n"
            f"Event Classification: {event.event_type.upper()}\n"
            f"Network Path: {event.source_ip} -> {event.destination_ip}:{event.destination_port}\n"
            f"Risk Score Assessment: {risk:.2f}/1.0\n"
            f"Correlated Evidence: {why}\n"
            f"Mitigation Playbook: {action}\n\n"
            f"Rule: Keep it to one precise sentence. Conclude by telling the operator to validate "
            f"workload identity and recent configurations before enforcing."
        )

        try:
            # 2. Trigger local offline inference matching your active model setup
            response = ollama.generate(
                model=self.model_name,
                prompt=prompt,
                options={
                    "temperature": 0.1,  # Kept ultra-low for high security predictability
                    "num_ctx": 1024      # Tight context window for zero-latency CPU performance
                }
            )
            return response['response'].strip()

        except Exception as e:
            # 3. Fail-safe Fallback: If the Ollama system daemon blips, gracefully pass structured data
            return (
                f"[FALLBACK LOG] {event.event_type.upper()} event from {event.source_ip} to "
                f"{event.destination_ip}:{event.destination_port} scored {risk:.2f}. "
                f"Evidence: {why}. Recommended playbook: {action}. (Local LLM unavailable: {e})"
            )
