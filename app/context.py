from __future__ import annotations
import os,re,ollama
from .models import RiskFactor,TelemetryEvent

BAD_LOW=re.compile(r"\b(attack|attacker|malicious|compromise|compromised|threat|anomaly|suspicious|contain|quarantine|block)\b",re.I)

class ContextAnalyzer:
    def __init__(self,model_name:str|None=None):
        self.model_name=model_name or os.getenv("OLLAMA_MODEL","llama3.2:1b")
    def cmd(self,e):return " ".join(x for x in [e.binary,e.args] if x).strip() or "unknown command"
    def where(self,e):
        x=[]
        if e.cluster_name:x.append(f"cluster {e.cluster_name}")
        if e.namespace:x.append(f"namespace {e.namespace}")
        if e.pod_name:x.append(f"pod {e.pod_name}")
        if e.node_name:x.append(f"node {e.node_name}")
        return ", ".join(x) or "unknown workload"
    def fallback(self,e,risk,reasons,action):
        cmd=self.cmd(e)
        if e.event_type=="process" and risk<.35:
            return f"{cmd} executed in {self.where(e)}" + (f" as UID {e.uid}" if e.uid is not None else "") + f". No elevated-risk indicators were identified; risk is {risk:.2f}/1.00 and the recommended action is {action.upper()}."
        why="; ".join(reasons[:3])
        return f"Tetragon observed {e.tetragon_event_type or e.event_type} for {cmd} in {self.where(e)}. Risk is {risk:.2f}/1.00 because {why} Recommended action: {action.upper()}."
    def summarize(self,event:TelemetryEvent,risk:float,reasons:list[str],action:str,risk_factors:list[RiskFactor]|None=None):
        fs=risk_factors or []
        net="not present in this event" if not event.destination_ip else f"{event.source_ip or 'workload'} -> {event.destination_ip}" + (f":{event.destination_port}" if event.destination_port else "")
        evidence="\n".join(f"- {f.label}: {f.evidence}" for f in fs) or "- No elevated-risk indicators."
        level="LOW" if risk<.35 else "MEDIUM" if risk<.65 else "HIGH" if risk<.80 else "CRITICAL"
        prompt=f"""You are a Security Operations Center event explainer.
You are NOT the detector. Only explain supplied facts. Never invent malware, attacker intent, compromise, data theft, network activity, or Kubernetes activity.

FACTS
Tetragon event: {event.tetragon_event_type or event.event_type}
Command: {self.cmd(event)}
Parent: {event.parent_binary or 'unknown'}
UID: {event.uid if event.uid is not None else 'unknown'}
CWD: {event.cwd or 'unknown'}
Location: {self.where(event)}
Network path: {net}
Risk: {risk:.2f}/1.00 ({level})
Policy action: {action.upper()}

DETECTOR EVIDENCE
{evidence}

RULES
- If risk < 0.35 and action is ALLOW, describe it as low risk.
- Never call LOW/ALLOW activity an anomaly, threat, attack, suspicious, malicious or compromised unless evidence explicitly says so.
- Never invent a network connection when Network path says it is not present.
- Mention the concrete command/operation and why the score/action makes sense.
- Maximum two concise sentences."""
        fb=self.fallback(event,risk,reasons,action)
        try:
            r=ollama.generate(model=self.model_name,prompt=prompt,options={"temperature":0.0,"num_ctx":2048,"num_predict":120})
            text=(r.get("response") or "").strip()
            if not text:return fb,"deterministic"
            if risk<.35 and action=="allow" and BAD_LOW.search(text):return fb,"deterministic"
            if not event.destination_ip and re.search(r"\bconnected|connection to|network path\b",text,re.I):return fb,"deterministic"
            return text,"ollama"
        except Exception:
            return fb,"deterministic"
