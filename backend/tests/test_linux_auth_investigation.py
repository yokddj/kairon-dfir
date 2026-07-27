from app.services.linux_auth_investigation import build_linux_auth_investigation


def _doc(message, ts, pid=1):
    return {
        "id": f"id-{ts}-{pid}-{message[:8]}",
        "case_id": "case-1",
        "evidence_id": "evidence-1",
        "source_file": "/var/log/auth.log",
        "@timestamp": ts,
        "host": {"name": "victoria", "evidence_host_id": "host-1"},
        "linux": {"artifact_type": "auth_log", "message": message, "process": "sshd", "pid": pid, "service": "sshd"},
    }


def test_reconstructs_complete_ssh_session(monkeypatch):
    docs = [
        _doc("Accepted password for mail from 192.168.210.131 port 57708 ssh2", "2026-10-05T13:23:34+00:00", 3156),
        _doc("pam_unix(sshd:session): session opened for user mail by (uid=0)", "2026-10-05T13:23:34+00:00", 3156),
        _doc("pam_unix(sshd:session): session closed for user mail", "2026-10-05T13:24:11+00:00", 3156),
    ]
    monkeypatch.setattr("app.services.linux_auth_investigation._fetch_auth_docs", lambda case_id: docs)
    result = build_linux_auth_investigation("case-1")
    assert result["sessions"][0]["username"] == "mail"
    assert result["sessions"][0]["source_port"] == 57708
    assert result["sessions"][0]["duration_seconds"] == 37
    assert result["sessions"][0]["status"] == "complete"


def test_bruteforce_avoids_pam_double_count(monkeypatch):
    docs = [
        _doc("Failed none for invalid user ulysses from 192.168.56.1 port 34431 ssh2", "2026-02-06T15:16:20+00:00", 2085),
        _doc("pam_unix(sshd:auth): authentication failure; logname= uid=0 euid=0 tty=ssh ruser= rhost=192.168.56.1", "2026-02-06T15:16:24+00:00", 2085),
        _doc("Failed password for invalid user ulysses from 192.168.56.1 port 34431 ssh2", "2026-02-06T15:16:26+00:00", 2085),
        _doc("Failed password for invalid user ulysses from 192.168.56.1 port 34431 ssh2", "2026-02-06T15:16:32+00:00", 2085),
        _doc("Failed password for invalid user ulysses from 192.168.56.1 port 34431 ssh2", "2026-02-06T15:16:40+00:00", 2085),
        _doc("PAM 2 more authentication failures; logname= uid=0 euid=0 tty=ssh ruser= rhost=192.168.56.1", "2026-02-06T15:16:40+00:00", 2085),
    ]
    monkeypatch.setattr("app.services.linux_auth_investigation._fetch_auth_docs", lambda case_id: docs)
    result = build_linux_auth_investigation("case-1")
    assert result["brute_force"][0]["target_account"] == "ulysses"
    assert result["brute_force"][0]["explicit_failed_events"] == 4
    assert result["brute_force"][0]["pam_aggregate_failures"] == 3
    assert result["brute_force"][0]["effective_attempts"] == 4


def test_incomplete_session(monkeypatch):
    docs = [_doc("Accepted password for root from 10.0.0.5 port 2222 ssh2", "2026-01-01T00:00:00+00:00", 42)]
    monkeypatch.setattr("app.services.linux_auth_investigation._fetch_auth_docs", lambda case_id: docs)
    result = build_linux_auth_investigation("case-1")
    assert result["sessions"][0]["status"] == "accepted_without_pam_session"
