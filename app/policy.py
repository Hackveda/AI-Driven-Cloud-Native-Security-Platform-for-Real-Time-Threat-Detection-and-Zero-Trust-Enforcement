from dataclasses import dataclass
from .models import TelemetryEvent

@dataclass
class Decision:
    severity:str
    action:str
    approval_required:bool=False

class PolicyEngine:
    def decide(self,event:TelemetryEvent,risk:float)->Decision:
        if event.known_bad_ioc and risk>=.90:return Decision("critical","block",True)
        if risk>=.80:return Decision("critical","quarantine",True)
        if risk>=.65:return Decision("high","quarantine",True)
        if risk>=.35:return Decision("medium","alert",False)
        return Decision("low","allow",False)
