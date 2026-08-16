from __future__ import annotations
import hashlib, ipaddress, json
from datetime import datetime, timezone
from typing import Any
from .models import TelemetryEvent

EVENT_KEYS = ("process_exec","process_exit","process_kprobe","process_tracepoint","process_uprobe","process_loader","process_lsm")

def _time(v):
    if not v:
        return datetime.now(timezone.utc)
    s = str(v).replace("Z","+00:00")
    try:
        if "." in s:
            head, tail = s.split(".",1)
            pos = next((i for i,c in enumerate(tail) if c in "+-"), len(tail))
            s = head + "." + tail[:pos][:6] + tail[pos:]
        return datetime.fromisoformat(s)
    except Exception:
        return datetime.now(timezone.utc)

def _int(v):
    try: return int(v)
    except Exception: return None

def _args(v):
    if v is None: return None
    return v if isinstance(v,str) else " ".join(map(str,v)) if isinstance(v,list) else str(v)

def _network(obj):
    out={}
    def walk(x):
        if isinstance(x,dict):
            low={str(k).lower():v for k,v in x.items()}
            for k in ("daddr","dst_addr","destination_ip","address","ip"):
                v=low.get(k)
                if isinstance(v,str):
                    try:
                        ipaddress.ip_address(v); out.setdefault("destination_ip",v)
                    except ValueError: pass
            for k in ("saddr","src_addr","source_ip"):
                v=low.get(k)
                if isinstance(v,str):
                    try:
                        ipaddress.ip_address(v); out.setdefault("source_ip",v)
                    except ValueError: pass
            for k in ("dport","dst_port","destination_port","port"):
                n=_int(low.get(k))
                if n and 0<n<=65535: out.setdefault("destination_port",n)
            for k in ("sport","src_port","source_port"):
                n=_int(low.get(k))
                if n and 0<n<=65535: out.setdefault("source_port",n)
            for v in x.values(): walk(v)
        elif isinstance(x,list):
            for v in x: walk(v)
    walk(obj); return out

def normalize_tetragon_event(raw: dict[str,Any], cluster_name: str|None=None) -> TelemetryEvent:
    key=next((k for k in EVENT_KEYS if isinstance(raw.get(k),dict)),"unknown")
    block=raw.get(key,{}) if key!="unknown" else {}
    proc=block.get("process") or {}
    parent=block.get("parent") or proc.get("parent") or {}
    pod=proc.get("pod") or {}
    container=pod.get("container") or {}
    labels=proc.get("pod_labels") or pod.get("pod_labels") or pod.get("labels") or {}
    net=_network(block) if key in {"process_kprobe","process_tracepoint"} else {}
    policy=block.get("policy_name") or block.get("policy") or raw.get("policy_name")
    if isinstance(policy,dict): policy=policy.get("name")
    uid=_int(proc.get("uid"))
    seed=json.dumps({"k":key,"exec":proc.get("exec_id"),"time":raw.get("time"),"node":raw.get("node_name"),"bin":proc.get("binary"),"args":proc.get("args") or proc.get("arguments")},sort_keys=True,default=str).encode()
    eid=hashlib.sha256(seed).hexdigest()[:32]
    return TelemetryEvent(
        event_id=eid,
        event_type={"process_exec":"process","process_exit":"process_exit","process_kprobe":"kernel","process_tracepoint":"kernel"}.get(key,key),
        tetragon_event_type=key,
        timestamp=_time(raw.get("time")),
        cluster_name=cluster_name or raw.get("_soc_cluster_name") or raw.get("cluster_name") or "default-cluster",
        node_name=raw.get("node_name"),
        namespace=pod.get("namespace"),
        pod_name=pod.get("name"),
        pod_uid=pod.get("uid"),
        workload=proc.get("workload") or pod.get("workload"),
        container_name=container.get("name") or proc.get("container_name"),
        container_id=proc.get("docker") or proc.get("container_id") or container.get("id"),
        pod_labels={str(k):str(v) for k,v in labels.items()} if isinstance(labels,dict) else {},
        binary=proc.get("binary"),
        args=_args(proc.get("arguments") or proc.get("args")),
        cwd=proc.get("cwd"),
        pid=_int(proc.get("pid")),
        uid=uid,
        parent_binary=parent.get("binary"),
        parent_args=_args(parent.get("arguments") or parent.get("args")),
        parent_exec_id=proc.get("parent_exec_id"),
        source_ip=net.get("source_ip"),
        destination_ip=net.get("destination_ip"),
        source_port=net.get("source_port"),
        destination_port=net.get("destination_port"),
        protocol="tcp" if policy=="connect" else None,
        syscall=block.get("function_name") or block.get("syscall"),
        policy_name=str(policy) if policy else None,
        tags=[str(x) for x in (block.get("tags") or [])],
        privileged=(uid==0),
        raw_event=raw,
    )
