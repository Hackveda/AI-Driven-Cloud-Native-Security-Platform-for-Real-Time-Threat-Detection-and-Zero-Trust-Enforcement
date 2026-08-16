from __future__ import annotations
import numpy as np
from sklearn.ensemble import IsolationForest
from .models import TelemetryEvent

class AnomalyDetector:
    """Small demo model. A production system would load a signed, versioned model artifact."""
    def __init__(self) -> None:
        rng = np.random.default_rng(42)
        normal = np.column_stack([
            rng.normal(7.0, 1.2, 500).clip(0, 12),       # log1p(bytes_out)
            rng.poisson(0.2, 500).clip(0, 8),           # failed auth
            rng.binomial(1, 0.03, 500),                 # privileged
            rng.binomial(1, 0.005, 500),                # IOC
            rng.choice([22, 53, 80, 443, 5432], 500),   # port
        ])
        self.model = IsolationForest(n_estimators=120, contamination=0.04, random_state=42)
        self.model.fit(normal)

    @staticmethod
    def features(event: TelemetryEvent) -> np.ndarray:
        return np.array([[np.log1p(max(event.bytes_out, 0)), event.failed_auth_count,
                          int(event.privileged), int(event.known_bad_ioc), event.destination_port]], dtype=float)

    def score(self, event: TelemetryEvent) -> tuple[float, list[str]]:
        x = self.features(event)
        # IsolationForest decision_function: larger = more normal. Convert to intuitive 0..1 risk.
        raw = float(self.model.decision_function(x)[0])
        risk = float(np.clip((0.16 - raw) / 0.32, 0.0, 1.0))
        reasons: list[str] = []
        if event.known_bad_ioc:
            risk = max(risk, 0.98); reasons.append("destination matched threat-intelligence IOC")
        if event.failed_auth_count >= 5:
            risk = max(risk, 0.82); reasons.append("repeated authentication failures")
        if event.privileged:
            risk = min(1.0, risk + 0.12); reasons.append("privileged execution context")
        if event.bytes_out >= 50_000_000:
            risk = max(risk, 0.90); reasons.append("unusually large outbound transfer")
        if event.destination_port not in {22, 53, 80, 443, 5432, 6379, 9092}:
            risk = min(1.0, risk + 0.08); reasons.append("unusual destination port")
        if not reasons and risk >= 0.6:
            reasons.append("multivariate behavior deviates from baseline")
        if not reasons:
            reasons.append("behavior is close to learned baseline")
        return round(risk, 4), reasons
