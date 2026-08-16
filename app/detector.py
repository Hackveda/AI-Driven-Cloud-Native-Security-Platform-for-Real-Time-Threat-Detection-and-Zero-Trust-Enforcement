from __future__ import annotations
import ipaddress, os, re
from .models import RiskFactor, TelemetryEvent

SHELLS={"sh","bash","dash","zsh","ash","ksh"}
REMOTE={"curl","wget","nc","ncat","netcat","socat","telnet"}
PRIV={"nsenter","unshare","mount","umount","chroot","capsh","setcap","setpriv","su","sudo"}
DISC={"whoami","id","uname","hostname","ps","ss","netstat","ip","ifconfig","env","printenv"}
LOW={"ls","cat","head","tail","grep","sed","awk","date","echo","true","false","sleep","pwd"}
SENSITIVE=("/etc/shadow","/root/.ssh","/.ssh/","/var/run/secrets/kubernetes.io","/proc/1/root","/proc/1/ns/","/var/lib/kubelet","/etc/kubernetes/")
TEMP=("/tmp/","/var/tmp/","/dev/shm/")
CHAIN=re.compile(r"(curl|wget).*(\||;|&&).*(sh|bash)|(base64\s+-d|python\s+-c|perl\s+-e|ruby\s+-e)",re.I)

class RiskEngine:
    def add(self, fs, code, label, weight, evidence):
        fs.append(RiskFactor(code=code,label=label,weight=weight,evidence=evidence))
    def public(self,ip):
        if not ip:return False
        try:
            x=ipaddress.ip_address(ip)
            return not (x.is_private or x.is_loopback or x.is_link_local or x.is_multicast or x.is_reserved)
        except ValueError:return False
    def score(self,event:TelemetryEvent):
        fs=[]; risk=.02
        binary=(event.binary or "").lower(); name=os.path.basename(binary); args=(event.args or "").lower()
        parent=os.path.basename((event.parent_binary or "").lower()); cmd=f"{binary} {args}"
        if event.known_bad_ioc:self.add(fs,"KNOWN_BAD_IOC","Known malicious indicator",.95,"Artifact or destination matched trusted threat intelligence.")
        if event.event_type=="process":
            if event.uid==0:self.add(fs,"ROOT","Executed as root",.06,f"{event.binary or 'process'} ran with UID 0.")
            if name in SHELLS:self.add(fs,"SHELL","Shell execution",.12,f"Shell {name} executed.")
            if name in REMOTE:self.add(fs,"REMOTE_TOOL","Network-capable utility",.12,f"{name} can retrieve data or establish connections.")
            if name in PRIV:self.add(fs,"PRIV_TOOL","Privilege/container namespace utility",.28,f"{name} can alter namespaces, mounts or privileges.")
            if name in DISC:self.add(fs,"DISCOVERY","Discovery command",.04,f"{name} can enumerate workload/host information.")
            if binary.startswith(TEMP):self.add(fs,"TEMP_EXEC","Execution from writable temp storage",.28,f"Binary executed from {event.binary}.")
            hits=[p for p in SENSITIVE if p in cmd]
            if hits:self.add(fs,"SENSITIVE_PATH","Sensitive path referenced",.30,f"Command referenced {', '.join(hits[:3])}.")
            if CHAIN.search(cmd):self.add(fs,"EXEC_CHAIN","Download/decode-and-execute chain",.38,"Command resembles download/decode-and-execute behavior.")
            if name in SHELLS and parent and parent not in SHELLS|{"kubectl","runc","containerd-shim"}:
                self.add(fs,"APP_SHELL","Application spawned a shell",.24,f"Parent {parent} spawned {name}.")
        if event.destination_ip:
            if self.public(event.destination_ip):self.add(fs,"PUBLIC_EGRESS","Connection to public IP",.08,f"Workload connected to {event.destination_ip}.")
            if event.destination_port in {4444,5555,6666,1337,31337}:self.add(fs,"RISK_PORT","Unusual high-risk destination port",.20,f"Destination port {event.destination_port} is unusual.")
        if event.known_bad_ioc:risk=max(risk,.95)
        risk=max(risk,min(.92,risk+sum(f.weight for f in fs if f.code!="KNOWN_BAD_IOC")))
        meaningful=[f for f in fs if f.code not in {"ROOT","DISCOVERY"}]
        if len(meaningful)>=3:
            risk=min(1,risk+.08); self.add(fs,"CORRELATED","Multiple correlated signals",.08,f"{len(meaningful)} suspicious signals correlated.")
        if event.event_type=="process" and name in LOW and not meaningful:risk=min(risk,.10)
        risk=round(max(0,min(1,risk)),3)
        reasons=[f.evidence for f in fs] or ["No elevated-risk indicators were found in the available Tetragon context."]
        return risk,fs,reasons

AnomalyDetector=RiskEngine
