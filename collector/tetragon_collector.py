from __future__ import annotations

import json
import os
import threading
import time

import httpx
from kubernetes import client, config

SOC_API_URL = os.getenv(
    "SOC_API_URL",
    "http://security-api.default.svc.cluster.local/v1/tetragon",
)
TETRAGON_NAMESPACE = os.getenv("TETRAGON_NAMESPACE", "kube-system")
TETRAGON_LABEL = os.getenv(
    "TETRAGON_LABEL",
    "app.kubernetes.io/name=tetragon",
)
TETRAGON_CONTAINER = os.getenv("TETRAGON_CONTAINER", "export-stdout")
CLUSTER_NAME = os.getenv("CLUSTER_NAME", "kubernetes-cluster")


def load_config() -> None:
    try:
        config.load_incluster_config()
    except config.ConfigException:
        config.load_kube_config()


def stream_pod(pod_name: str) -> None:
    api = client.CoreV1Api()
    print(f"Streaming live Tetragon events from {pod_name}", flush=True)

    with httpx.Client(timeout=5.0) as http:
        while True:
            try:
                # tail_lines=0 prevents replaying old Tetragon history. The SOC
                # receives only events produced after this stream starts.
                response = api.read_namespaced_pod_log(
                    name=pod_name,
                    namespace=TETRAGON_NAMESPACE,
                    container=TETRAGON_CONTAINER,
                    follow=True,
                    timestamps=False,
                    tail_lines=0,
                    _preload_content=False,
                )

                for raw_line in response.stream():
                    line = raw_line.decode("utf-8", errors="replace").strip()
                    if not line:
                        continue
                    try:
                        event = json.loads(line)
                    except json.JSONDecodeError:
                        continue

                    try:
                        result = http.post(
                            SOC_API_URL,
                            params={"cluster": CLUSTER_NAME},
                            json=event,
                        )
                        result.raise_for_status()
                    except Exception as exc:
                        print(f"{pod_name}: forward failed: {exc}", flush=True)

            except Exception as exc:
                print(f"{pod_name}: stream disconnected: {exc}; reconnecting", flush=True)
                time.sleep(2)


def main() -> None:
    load_config()
    api = client.CoreV1Api()
    started: set[str] = set()

    while True:
        try:
            pods = api.list_namespaced_pod(
                namespace=TETRAGON_NAMESPACE,
                label_selector=TETRAGON_LABEL,
            ).items

            running = {
                pod.metadata.name
                for pod in pods
                if pod.status.phase == "Running" and pod.metadata.name
            }

            for pod_name in sorted(running - started):
                threading.Thread(
                    target=stream_pod,
                    args=(pod_name,),
                    daemon=True,
                ).start()
                started.add(pod_name)

            # Permit recreation of a DaemonSet pod with a new name.
            started.intersection_update(running)
            time.sleep(5)
        except Exception as exc:
            print(f"Tetragon pod discovery error: {exc}", flush=True)
            time.sleep(3)


if __name__ == "__main__":
    main()
