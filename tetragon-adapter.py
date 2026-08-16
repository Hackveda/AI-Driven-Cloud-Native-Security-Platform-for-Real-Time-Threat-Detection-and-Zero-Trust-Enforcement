from __future__ import annotations

import json
import os
import subprocess
import sys
import time

import httpx

API_URL = os.getenv("SOC_TETRAGON_URL", "http://127.0.0.1:8080/v1/tetragon")
CLUSTER_NAME = os.getenv("CLUSTER_NAME", "security-demo")
TETRAGON_NAMESPACE = os.getenv("TETRAGON_NAMESPACE", "kube-system")
TETRAGON_LABEL = os.getenv("TETRAGON_LABEL", "app.kubernetes.io/name=tetragon")
TETRAGON_CONTAINER = os.getenv("TETRAGON_CONTAINER", "export-stdout")


def kubectl_command() -> list[str]:
    """
    Start at the current end of the Tetragon log.

    --tail=0 is important: without it kubectl can replay older events before
    reaching the command that the SOC analyst just executed.
    """
    return [
        "kubectl",
        "logs",
        "-n",
        TETRAGON_NAMESPACE,
        "-l",
        TETRAGON_LABEL,
        "-c",
        TETRAGON_CONTAINER,
        "--tail=0",
        "--max-log-requests=20",
        "-f",
    ]


def forward(client: httpx.Client, event: dict) -> None:
    """Forward the untouched Tetragon JSON. Never invent security fields."""
    response = client.post(
        API_URL,
        params={"cluster": CLUSTER_NAME},
        json=event,
    )
    response.raise_for_status()

    key = next(
        (
            name
            for name in (
                "process_exec",
                "process_exit",
                "process_kprobe",
                "process_tracepoint",
                "process_uprobe",
                "process_loader",
                "process_lsm",
            )
            if isinstance(event.get(name), dict)
        ),
        "unknown",
    )
    block = event.get(key) or {}
    process_info = block.get("process") or {}
    binary = process_info.get("binary") or "-"
    arguments = process_info.get("arguments") or process_info.get("args") or ""
    print(
        f"Forwarded {key}: {binary} {arguments} -> {response.status_code}",
        flush=True,
    )


def run_once() -> int:
    command = kubectl_command()
    print("Starting raw Tetragon realtime forwarder", flush=True)
    print("Command:", " ".join(command), flush=True)
    print("SOC endpoint:", API_URL, flush=True)
    print("Cluster:", CLUSTER_NAME, flush=True)

    process = subprocess.Popen(
        command,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        bufsize=1,
    )

    assert process.stdout is not None

    with httpx.Client(timeout=5.0) as client:
        try:
            for line in process.stdout:
                line = line.strip()
                if not line:
                    continue

                try:
                    event = json.loads(line)
                except json.JSONDecodeError:
                    # Ignore non-JSON kubectl/log noise rather than creating a
                    # fake event from it.
                    continue

                try:
                    forward(client, event)
                except Exception as exc:
                    print(f"Forward error: {exc}", file=sys.stderr, flush=True)
        except KeyboardInterrupt:
            print("Stopping Tetragon forwarder...", flush=True)
            process.terminate()
            try:
                process.wait(timeout=3)
            except subprocess.TimeoutExpired:
                process.kill()
            return 0

    stderr = ""
    if process.stderr is not None:
        stderr = process.stderr.read().strip()
    code = process.wait()
    if stderr:
        print(stderr, file=sys.stderr, flush=True)
    return code


def main() -> None:
    while True:
        code = run_once()
        if code == 0:
            return
        print(f"kubectl log stream ended with code {code}; reconnecting in 2s", flush=True)
        time.sleep(2)


if __name__ == "__main__":
    main()
