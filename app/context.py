from __future__ import annotations

import os
import re

import ollama

from .models import RiskFactor, TelemetryEvent

BAD_LOW = re.compile(
    r"\b(attack|attacker|malicious|compromise|compromised|threat|anomaly|"
    r"suspicious|contain|quarantine|block)\b",
    re.IGNORECASE,
)


class ContextAnalyzer:
    def __init__(self, model_name: str | None = None):
        self.model_name = model_name or os.getenv("OLLAMA_MODEL", "llama3.2:1b")

    @staticmethod
    def command(event: TelemetryEvent) -> str:
        return " ".join(x for x in [event.binary, event.args] if x).strip() or "unknown command"

    @staticmethod
    def actor(event: TelemetryEvent) -> str:
        if event.username:
            return (
                f"{event.username} (UID {event.uid})"
                if event.uid is not None
                else event.username
            )
        if event.uid == 0:
            return "root (UID 0)"
        if event.uid is not None:
            return f"UID {event.uid}"
        return "unknown"

    @staticmethod
    def location(event: TelemetryEvent) -> str:
        parts = []
        if event.cluster_name:
            parts.append(f"cluster {event.cluster_name}")
        if event.namespace:
            parts.append(f"namespace {event.namespace}")
        if event.pod_name:
            parts.append(f"pod {event.pod_name}")
        if event.node_name:
            parts.append(f"node {event.node_name}")
        return ", ".join(parts) or "unknown workload"

    @staticmethod
    def destination(event: TelemetryEvent) -> str:
        port = f":{event.destination_port}" if event.destination_port else ""
        if event.destination_host and event.destination_ip:
            return f"{event.destination_host}{port} ({event.destination_ip})"
        if event.destination_host:
            return f"{event.destination_host}{port}"
        if event.destination_ip:
            return f"{event.destination_ip}{port}"
        return "none observed"

    @staticmethod
    def kernel_activity(event: TelemetryEvent) -> str:
        return " -> ".join(event.kernel_activity) if event.kernel_activity else "not available"

    def fallback(
        self,
        event: TelemetryEvent,
        risk: float,
        reasons: list[str],
        action: str,
    ) -> str:
        command = self.command(event)
        actor = self.actor(event)
        parent = event.parent_binary or "unknown parent"
        destination = self.destination(event)

        if risk < 0.35:
            return (
                f"{actor} executed {command} from {parent}; Tetragon observed "
                f"{self.kernel_activity(event)} and destination {destination}. "
                f"The current evidence gives a {round(risk * 100)}/100 risk score, "
                f"so the recommended action is {action.upper()}."
            )

        evidence = "; ".join(reasons[:3])
        return (
            f"{actor} executed {command} from {parent}; Tetragon observed "
            f"{self.kernel_activity(event)} and destination {destination}. "
            f"Risk is {round(risk * 100)}/100 because {evidence} "
            f"Recommended action: {action.upper()}."
        )

    def summarize(
        self,
        event: TelemetryEvent,
        risk: float,
        reasons: list[str],
        action: str,
        risk_factors: list[RiskFactor] | None = None,
    ) -> tuple[str, str]:
        factors = risk_factors or []
        evidence = "\n".join(
            f"- {factor.label}: {factor.evidence}"
            for factor in factors
        ) or "- No elevated-risk indicators."

        level = (
            "LOW"
            if risk < 0.35
            else "MEDIUM"
            if risk < 0.65
            else "HIGH"
            if risk < 0.80
            else "CRITICAL"
        )

        prompt = f"""You are a Security Operations Center event explainer.

You are NOT the detector. Explain only the supplied Tetragon facts.
Never invent malware, attacker intent, compromise, data theft, a file read,
a network connection, a hostname, a parent process, or Kubernetes metadata.

FACTS
Tetragon event: {event.tetragon_event_type or event.event_type}
User: {self.actor(event)}
Process: {event.binary or 'unknown'}
Command: {self.command(event)}
Parent: {event.parent_binary or 'unknown'}
CWD: {event.cwd or 'unknown'}
Location: {self.location(event)}
Kernel activity observed/correlated: {self.kernel_activity(event)}
Destination: {self.destination(event)}
Risk score: {round(risk * 100)}/100
Risk level: {level}
Policy action: {action.upper()}

DETECTOR EVIDENCE
{evidence}

RULES
1. If risk is below 35 and action is ALLOW, describe it as low risk.
2. Do not call LOW/ALLOW activity an anomaly, attack, threat, suspicious,
   malicious, or compromised unless an explicit evidence item says so.
3. State what the user/process actually did and why the score makes sense.
4. If destination is "none observed", do not claim network activity occurred.
5. Treat command-line references to sensitive files as context, not proof of theft.
6. Use at most two concise sentences suitable for a SOC analyst.
"""

        fallback = self.fallback(event, risk, reasons, action)

        try:
            response = ollama.generate(
                model=self.model_name,
                prompt=prompt,
                options={
                    "temperature": 0.0,
                    "num_ctx": 2048,
                    "num_predict": 140,
                },
            )
            text = (response.get("response") or "").strip()
            if not text:
                return fallback, "deterministic"

            if risk < 0.35 and action == "allow" and BAD_LOW.search(text):
                return fallback, "deterministic"

            if (
                not event.destination_ip
                and not event.destination_host
                and re.search(r"\bconnected|connection to|outbound connection\b", text, re.I)
            ):
                return fallback, "deterministic"

            return text, "ollama"
        except Exception:
            return fallback, "deterministic"
