from __future__ import annotations

import hashlib
import ipaddress
import json
import re
from datetime import datetime, timezone
from typing import Any
from urllib.parse import urlparse

from .models import TelemetryEvent

EVENT_KEYS = (
    "process_exec",
    "process_exit",
    "process_kprobe",
    "process_tracepoint",
    "process_uprobe",
    "process_loader",
    "process_lsm",
)

URL_RE = re.compile(r"https?://[^\s'\"]+", re.IGNORECASE)


def _time(value: Any) -> datetime:
    if not value:
        return datetime.now(timezone.utc)
    text = str(value).replace("Z", "+00:00")
    try:
        if "." in text:
            head, tail = text.split(".", 1)
            pos = next((i for i, char in enumerate(tail) if char in "+-"), len(tail))
            text = head + "." + tail[:pos][:6] + tail[pos:]
        return datetime.fromisoformat(text)
    except Exception:
        return datetime.now(timezone.utc)


def _int(value: Any) -> int | None:
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def _args(value: Any) -> str | None:
    if value is None:
        return None
    if isinstance(value, str):
        return value
    if isinstance(value, list):
        return " ".join(str(x) for x in value)
    return str(value)


def _username(process: dict[str, Any], uid: int | None) -> str | None:
    for key in ("user", "username"):
        value = process.get(key)
        if isinstance(value, str) and value.strip():
            return value.strip()
    if uid == 0:
        return "root"
    return None


def _host_from_command(binary: str | None, args: str | None) -> tuple[str | None, int | None]:
    command = " ".join(x for x in (binary, args) if x)
    match = URL_RE.search(command)
    if not match:
        return None, None
    try:
        parsed = urlparse(match.group(0))
        if not parsed.hostname:
            return None, None
        port = parsed.port or (443 if parsed.scheme == "https" else 80)
        return parsed.hostname, port
    except Exception:
        return None, None


def _network(obj: Any) -> dict[str, Any]:
    """Best-effort extraction from Tetragon sock/sockaddr kprobe payloads."""
    out: dict[str, Any] = {}

    def walk(value: Any) -> None:
        if isinstance(value, dict):
            lower = {str(k).lower(): v for k, v in value.items()}

            for key in ("daddr", "dst_addr", "destination_ip"):
                candidate = lower.get(key)
                if isinstance(candidate, str):
                    try:
                        ipaddress.ip_address(candidate)
                        out.setdefault("destination_ip", candidate)
                    except ValueError:
                        pass

            for key in ("saddr", "src_addr", "source_ip"):
                candidate = lower.get(key)
                if isinstance(candidate, str):
                    try:
                        ipaddress.ip_address(candidate)
                        out.setdefault("source_ip", candidate)
                    except ValueError:
                        pass

            for key in ("dport", "dst_port", "destination_port"):
                port = _int(lower.get(key))
                if port and 0 < port <= 65535:
                    out.setdefault("destination_port", port)

            for key in ("sport", "src_port", "source_port"):
                port = _int(lower.get(key))
                if port and 0 < port <= 65535:
                    out.setdefault("source_port", port)

            # Tetragon sock payloads can use nested destination/source objects.
            for key in ("destination", "dst", "remote"):
                nested = lower.get(key)
                if isinstance(nested, dict):
                    address = nested.get("address") or nested.get("ip")
                    port = _int(nested.get("port"))
                    if isinstance(address, str):
                        try:
                            ipaddress.ip_address(address)
                            out.setdefault("destination_ip", address)
                        except ValueError:
                            pass
                    if port and 0 < port <= 65535:
                        out.setdefault("destination_port", port)

            for child in value.values():
                walk(child)
        elif isinstance(value, list):
            for child in value:
                walk(child)

    walk(obj)
    return out


def normalize_tetragon_event(
    raw: dict[str, Any],
    cluster_name: str | None = None,
) -> TelemetryEvent:
    key = next((k for k in EVENT_KEYS if isinstance(raw.get(k), dict)), "unknown")
    block = raw.get(key, {}) if key != "unknown" else {}
    process = block.get("process") or {}
    parent = block.get("parent") or process.get("parent") or {}
    pod = process.get("pod") or {}
    container = pod.get("container") or {}

    labels = process.get("pod_labels") or pod.get("pod_labels") or pod.get("labels") or {}
    if not isinstance(labels, dict):
        labels = {}

    uid = _int(process.get("uid"))
    parent_uid = _int(parent.get("uid"))
    binary = process.get("binary")
    arguments = _args(process.get("arguments") or process.get("args"))

    policy = block.get("policy_name") or block.get("policy") or raw.get("policy_name")
    if isinstance(policy, dict):
        policy = policy.get("name")

    function_name = block.get("function_name") or block.get("syscall") or block.get("function")
    net = _network(block) if key in {"process_kprobe", "process_tracepoint"} else {}

    destination_host, command_port = _host_from_command(binary, arguments)
    destination_port = net.get("destination_port") or command_port if net.get("destination_ip") else net.get("destination_port")

    if key == "process_exec":
        kernel_activity = ["execve"]
        event_type = "process"
    elif key == "process_exit":
        kernel_activity = ["process_exit"]
        event_type = "process_exit"
    elif key == "process_kprobe":
        fn = str(function_name or "kprobe")
        kernel_activity = ["connect" if "connect" in fn else fn]
        event_type = "network" if "connect" in fn or net.get("destination_ip") else "kernel"
    elif key == "process_tracepoint":
        kernel_activity = [str(function_name or "tracepoint")]
        event_type = "kernel"
    else:
        kernel_activity = [key]
        event_type = key

    seed = json.dumps(
        {
            "event": key,
            "exec_id": process.get("exec_id"),
            "time": raw.get("time"),
            "node": raw.get("node_name"),
            "binary": binary,
            "args": arguments,
            "function": function_name,
        },
        sort_keys=True,
        default=str,
    ).encode()
    event_id = hashlib.sha256(seed).hexdigest()[:32]

    return TelemetryEvent(
        event_id=event_id,
        event_type=event_type,
        tetragon_event_type=key,
        timestamp=_time(raw.get("time")),
        cluster_name=(
            cluster_name
            or raw.get("_soc_cluster_name")
            or raw.get("cluster_name")
            or "default-cluster"
        ),
        node_name=raw.get("node_name"),
        namespace=pod.get("namespace"),
        pod_name=pod.get("name"),
        pod_uid=pod.get("uid"),
        workload=process.get("workload") or pod.get("workload"),
        container_name=container.get("name") or process.get("container_name"),
        container_id=(
            process.get("docker")
            or process.get("container_id")
            or container.get("id")
        ),
        pod_labels={str(k): str(v) for k, v in labels.items()},
        exec_id=process.get("exec_id"),
        binary=binary,
        args=arguments,
        cwd=process.get("cwd"),
        pid=_int(process.get("pid")),
        uid=uid,
        username=_username(process, uid),
        parent_exec_id=process.get("parent_exec_id") or parent.get("exec_id"),
        parent_binary=parent.get("binary"),
        parent_args=_args(parent.get("arguments") or parent.get("args")),
        parent_pid=_int(parent.get("pid")),
        parent_uid=parent_uid,
        source_ip=net.get("source_ip"),
        destination_ip=net.get("destination_ip"),
        source_port=net.get("source_port"),
        destination_port=destination_port,
        destination_host=destination_host,
        protocol="tcp" if "connect" in str(function_name or "").lower() else None,
        syscall=str(function_name) if function_name else None,
        policy_name=str(policy) if policy else None,
        kernel_activity=kernel_activity,
        tags=[str(x) for x in (block.get("tags") or [])],
        privileged=(uid == 0),
        raw_event=raw,
    )
