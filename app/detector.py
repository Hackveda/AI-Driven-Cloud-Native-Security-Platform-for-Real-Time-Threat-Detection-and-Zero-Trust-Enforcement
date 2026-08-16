from __future__ import annotations

import ipaddress
import os
import re

from .models import RiskFactor, TelemetryEvent

SHELLS = {"sh", "bash", "dash", "zsh", "ash", "ksh"}
REMOTE = {"curl", "wget", "nc", "ncat", "netcat", "socat", "telnet"}
PRIV = {
    "nsenter",
    "unshare",
    "mount",
    "umount",
    "chroot",
    "capsh",
    "setcap",
    "setpriv",
    "su",
    "sudo",
}
DISCOVERY = {
    "whoami",
    "id",
    "uname",
    "hostname",
    "ps",
    "ss",
    "netstat",
    "ip",
    "ifconfig",
    "env",
    "printenv",
}
COMMON_LOW = {
    "ls",
    "cat",
    "head",
    "tail",
    "grep",
    "sed",
    "awk",
    "date",
    "echo",
    "true",
    "false",
    "sleep",
    "pwd",
}

# These are contextual weights, not probabilities of compromise.
SENSITIVE_PATHS = {
    "/etc/passwd": (0.18, "System account database referenced"),
    "/etc/shadow": (0.38, "Password hash database referenced"),
    "/root/.ssh": (0.35, "Root SSH material referenced"),
    "/.ssh/": (0.28, "SSH credential material referenced"),
    "/var/run/secrets/kubernetes.io": (0.35, "Kubernetes service-account credentials referenced"),
    "/proc/1/root": (0.35, "Host/container root path referenced"),
    "/proc/1/ns/": (0.35, "Process namespace handles referenced"),
    "/var/lib/kubelet": (0.38, "Kubelet data referenced"),
    "/etc/kubernetes/": (0.38, "Kubernetes control-plane configuration referenced"),
}

TEMP_PREFIXES = ("/tmp/", "/var/tmp/", "/dev/shm/")
CHAIN = re.compile(
    r"(curl|wget).*(\||;|&&).*(sh|bash)|"
    r"(base64\s+-d|python\s+-c|perl\s+-e|ruby\s+-e)",
    re.IGNORECASE,
)


class RiskEngine:
    def add(
        self,
        factors: list[RiskFactor],
        code: str,
        label: str,
        weight: float,
        evidence: str,
    ) -> None:
        factors.append(
            RiskFactor(
                code=code,
                label=label,
                weight=weight,
                evidence=evidence,
            )
        )

    @staticmethod
    def public_ip(value: str | None) -> bool:
        if not value:
            return False
        try:
            ip = ipaddress.ip_address(value)
            return not (
                ip.is_private
                or ip.is_loopback
                or ip.is_link_local
                or ip.is_multicast
                or ip.is_reserved
            )
        except ValueError:
            return False

    def score(
        self,
        event: TelemetryEvent,
    ) -> tuple[float, list[RiskFactor], list[str]]:
        factors: list[RiskFactor] = []
        risk = 0.02

        binary = (event.binary or "").lower()
        name = os.path.basename(binary)
        args = (event.args or "").lower()
        parent = os.path.basename((event.parent_binary or "").lower())
        command = f"{binary} {args}".strip()

        if event.known_bad_ioc:
            self.add(
                factors,
                "KNOWN_BAD_IOC",
                "Known malicious indicator",
                0.95,
                "Artifact or destination matched trusted threat intelligence.",
            )

        if event.event_type == "process":
            if event.uid == 0:
                self.add(
                    factors,
                    "ROOT",
                    "Executed as root",
                    0.06,
                    f"{event.binary or 'process'} ran with UID 0.",
                )

            if name in SHELLS:
                self.add(
                    factors,
                    "SHELL",
                    "Shell execution",
                    0.12,
                    f"Shell {name} executed.",
                )

            if name in REMOTE:
                self.add(
                    factors,
                    "REMOTE_TOOL",
                    "Network-capable utility",
                    0.12,
                    f"{name} can retrieve data or establish connections.",
                )

            if name in PRIV:
                self.add(
                    factors,
                    "PRIV_TOOL",
                    "Privilege/container namespace utility",
                    0.28,
                    f"{name} can alter namespaces, mounts or privileges.",
                )

            if name in DISCOVERY:
                self.add(
                    factors,
                    "DISCOVERY",
                    "Discovery command",
                    0.04,
                    f"{name} can enumerate workload or host information.",
                )

            if binary.startswith(TEMP_PREFIXES):
                self.add(
                    factors,
                    "TEMP_EXEC",
                    "Execution from writable temporary storage",
                    0.28,
                    f"Binary executed from {event.binary}.",
                )

            for path, (weight, label) in SENSITIVE_PATHS.items():
                if path in command:
                    self.add(
                        factors,
                        "SENSITIVE_PATH",
                        label,
                        weight,
                        f"Command referenced {path}.",
                    )

            if CHAIN.search(command):
                self.add(
                    factors,
                    "EXEC_CHAIN",
                    "Download/decode-and-execute chain",
                    0.38,
                    "Command resembles download/decode-and-execute behavior.",
                )

            if (
                name in SHELLS
                and parent
                and parent not in SHELLS | {"kubectl", "runc", "containerd-shim"}
            ):
                self.add(
                    factors,
                    "APP_SHELL",
                    "Application spawned a shell",
                    0.24,
                    f"Parent {parent} spawned {name}.",
                )

        if event.destination_ip:
            if self.public_ip(event.destination_ip):
                self.add(
                    factors,
                    "PUBLIC_EGRESS",
                    "Connection to public IP",
                    0.08,
                    f"Workload connected to {event.destination_ip}.",
                )
            if event.destination_port in {4444, 5555, 6666, 1337, 31337}:
                self.add(
                    factors,
                    "RISK_PORT",
                    "Unusual high-risk destination port",
                    0.20,
                    f"Destination port {event.destination_port} is unusual.",
                )

        if event.known_bad_ioc:
            risk = max(risk, 0.95)

        risk = max(
            risk,
            min(
                0.92,
                risk + sum(
                    factor.weight
                    for factor in factors
                    if factor.code != "KNOWN_BAD_IOC"
                ),
            ),
        )

        meaningful = [
            factor
            for factor in factors
            if factor.code not in {"ROOT", "DISCOVERY"}
        ]
        if len(meaningful) >= 3:
            risk = min(1.0, risk + 0.08)
            self.add(
                factors,
                "CORRELATED",
                "Multiple correlated signals",
                0.08,
                f"{len(meaningful)} suspicious signals correlated.",
            )

        # Keep ordinary read-only utilities low only when they do not touch a
        # sensitive path or participate in stronger behavior.
        if event.event_type == "process" and name in COMMON_LOW and not meaningful:
            risk = min(risk, 0.10)

        risk = round(max(0.0, min(1.0, risk)), 3)
        reasons = [factor.evidence for factor in factors] or [
            "No elevated-risk indicators were found in the available Tetragon context."
        ]
        return risk, factors, reasons


AnomalyDetector = RiskEngine
