from app.tetragon import normalize_tetragon_event


def test_process_exec_preserves_real_context():
    raw = {
        "process_exec": {
            "process": {
                "exec_id": "exec-1",
                "pid": 101,
                "uid": 0,
                "cwd": "/",
                "binary": "/usr/bin/cat",
                "arguments": "/etc/passwd",
                "parent_exec_id": "exec-parent",
                "pod": {
                    "namespace": "default",
                    "name": "security-demo",
                    "container": {
                        "id": "containerd://abc",
                        "name": "security-demo",
                    },
                },
            },
            "parent": {
                "exec_id": "exec-parent",
                "pid": 99,
                "uid": 0,
                "binary": "/bin/bash",
                "arguments": "",
            },
        },
        "node_name": "worker-1",
        "time": "2026-08-16T08:17:00Z",
    }

    event = normalize_tetragon_event(raw, "security-demo")
    assert event.binary == "/usr/bin/cat"
    assert event.args == "/etc/passwd"
    assert event.uid == 0
    assert event.username == "root"
    assert event.parent_binary == "/bin/bash"
    assert event.exec_id == "exec-1"
    assert event.parent_exec_id == "exec-parent"
    assert event.namespace == "default"
    assert event.pod_name == "security-demo"
    assert event.node_name == "worker-1"
    assert event.destination_ip is None
    assert event.kernel_activity == ["execve"]


def test_curl_url_is_preserved_without_inventing_an_ip():
    raw = {
        "process_exec": {
            "process": {
                "exec_id": "curl-1",
                "uid": 0,
                "binary": "/usr/bin/curl",
                "arguments": "-I https://hackveda.in",
            },
            "parent": {
                "binary": "/bin/bash",
                "uid": 0,
            },
        },
        "time": "2026-08-16T08:18:00Z",
    }

    event = normalize_tetragon_event(raw, "security-demo")
    assert event.destination_host == "hackveda.in"
    assert event.destination_port == 443
    assert event.destination_ip is None
    assert event.kernel_activity == ["execve"]
