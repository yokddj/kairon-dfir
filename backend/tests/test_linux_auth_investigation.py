from app.services.linux_auth_investigation import build_linux_auth_investigation

_counter = iter(range(1, 1_000_000))


def _doc(message, ts, pid=1, *, process="sshd", carrier="auth_log", **linux):
    family = {"auth_log": "linux_auth", "wtmp": "linux_auth", "btmp": "linux_auth", "journal": "linux_journal", "audit": "linux_audit"}[carrier]
    artifact_type = {"auth_log": "auth_log", "wtmp": "wtmp", "btmp": "btmp", "journal": "linux_journal", "audit": "audit_log"}[carrier]
    return {
        "event_id": f"ev-{next(_counter)}",
        "case_id": "case-1",
        "evidence_id": "evidence-1",
        "source_file": f"/var/log/{artifact_type}",
        "@timestamp": ts,
        "host": {"name": "victoria", "evidence_host_id": "host-1"},
        "artifact": {"type": family, "name": artifact_type},
        "linux": {"artifact_type": artifact_type, "message": message, "process": process, "pid": pid, **linux},
    }


def _passwd(name, uid, shell="/bin/bash"):
    return {
        "event_id": f"id-{name}", "case_id": "case-1", "evidence_id": "evidence-1",
        "artifact": {"type": "linux_identity", "name": "passwd"},
        "linux": {"artifact_type": "passwd", "username": name, "uid": str(uid), "shell": shell},
    }


def _run(monkeypatch, docs, **kwargs):
    monkeypatch.setattr("app.services.linux_auth_investigation._fetch_auth_docs", lambda case_id: (docs, False))
    return build_linux_auth_investigation("case-1", **kwargs)


def _kinds(result):
    return {finding["kind"] for finding in result["findings"]}


def test_reconstructs_complete_ssh_session(monkeypatch):
    docs = [
        _doc("Accepted password for mail from 198.51.100.77 port 57708 ssh2", "2026-10-05T13:23:34+00:00", 3156),
        _doc("pam_unix(sshd:session): session opened for user mail by (uid=0)", "2026-10-05T13:23:34+00:00", 3156),
        _doc("pam_unix(sshd:session): session closed for user mail", "2026-10-05T13:24:11+00:00", 3156),
    ]
    result = _run(monkeypatch, docs)
    session = result["sessions"][0]
    assert (session["username"], session["source_port"], session["method"], session["kind"]) == ("mail", 57708, "password", "ssh")
    assert session["duration_seconds"] == 37
    assert session["status"] == "closed"
    assert result["overview"]["successful_logins"] == 1


def test_an_attempt_written_by_sshd_pam_and_btmp_counts_once(monkeypatch):
    # One connection (PID 2085): three explicit failures, the matching pam_unix lines, and btmp.
    docs = [
        _doc("pam_unix(sshd:auth): authentication failure; logname= uid=0 euid=0 tty=ssh ruser= rhost=192.0.2.1", "2026-02-06T15:16:24+00:00", 2085),
        _doc("Failed password for invalid user ulysses from 192.0.2.1 port 34431 ssh2", "2026-02-06T15:16:26+00:00", 2085),
        _doc("Failed password for invalid user ulysses from 192.0.2.1 port 34431 ssh2", "2026-02-06T15:16:32+00:00", 2085),
        _doc("Failed password for invalid user ulysses from 192.0.2.1 port 34431 ssh2", "2026-02-06T15:16:40+00:00", 2085),
        _doc("PAM 2 more authentication failures; logname= uid=0 euid=0 tty=ssh ruser= rhost=192.0.2.1", "2026-02-06T15:16:40+00:00", 2085),
    ] + [
        _doc("btmp login failure user=ulysses terminal=ssh:notty source=192.0.2.1", f"2026-02-06T15:16:{second}+00:00", 2085, process="login", carrier="btmp",
             auth_event_type="login_failure", username="ulysses", source_ip="192.0.2.1", terminal="ssh:notty")
        for second in (26, 32, 40)
    ]
    result = _run(monkeypatch, docs)
    assert result["overview"]["failed_attempts"] == 3
    group = result["failures"][0]
    assert (group["source_ip"], group["username"], group["attempts"], group["connections"]) == ("192.0.2.1", "ulysses", 3, 1)


def test_journal_only_host_with_modern_openssh(monkeypatch):
    # No auth.log at all (Debian 12, Fedora...): the same messages, from the journal, under sshd-session.
    docs = [
        _doc(f"Failed password for root from 203.0.113.9 port {40000 + i} ssh2", f"2026-03-01T10:00:{i:02d}+00:00", 500 + i, process="sshd-session", carrier="journal")
        for i in range(12)
    ] + [
        _doc("Accepted password for root from 203.0.113.9 port 41000 ssh2", "2026-03-01T10:01:00+00:00", 600, process="sshd-session", carrier="journal"),
    ]
    result = _run(monkeypatch, docs)
    campaign = result["campaigns"][0]
    assert (campaign["source_ip"], campaign["pattern"], campaign["attempts"], campaign["success_account"]) == ("203.0.113.9", "brute_force", 12, "root")
    assert "success_after_attack" in _kinds(result)
    assert next(source for source in result["coverage"] if source["carrier"] == "journal")["events"] == 13


def test_auditd_only_host(monkeypatch):
    docs = [
        _doc("op=PAM:authentication acct=admin res=failed", f"2026-03-02T08:00:{i:02d}+00:00", 900 + i, process="", carrier="audit",
             audit_type="USER_AUTH", audit_res="failed", audit_acct="admin", audit_addr="198.51.100.4", exe="/usr/sbin/sshd")
        for i in range(10)
    ] + [
        _doc("op=login res=success", "2026-03-02T08:00:30+00:00", 950, process="", carrier="audit",
             audit_type="USER_LOGIN", audit_res="success", audit_id="1001", audit_addr="198.51.100.4", exe="/usr/sbin/sshd"),
        _passwd("admin", 1001),
    ]
    result = _run(monkeypatch, docs)
    assert result["overview"]["failed_attempts"] == 10
    assert result["sessions"][0]["username"] == "admin"
    assert "success_after_attack" in _kinds(result)
    assert "no_text_auth_logs" in _kinds(result)


def test_password_spray_is_told_apart_from_brute_force(monkeypatch):
    users = ["alice", "bob", "carol", "dave", "erin", "frank"]
    docs = [
        _doc(f"Failed password for {user} from 192.0.2.50 port {41000 + n} ssh2", f"2026-04-01T12:{n:02d}:00+00:00", 700 + n)
        for n, user in enumerate(users * 2)
    ]
    result = _run(monkeypatch, docs)
    campaign = result["campaigns"][0]
    assert (campaign["pattern"], campaign["account_count"], campaign["attempts"]) == ("password_spray", 6, 12)
    assert "password_spray" in _kinds(result)


def test_account_changes_and_their_findings(monkeypatch):
    docs = [
        _doc("new user: name=backup2, UID=0, GID=0, home=/root, shell=/bin/bash", "2026-05-01T09:00:00+00:00", 10, process="useradd"),
        _doc("add 'deploy' to group 'wheel'", "2026-05-01T09:01:00+00:00", 11, process="usermod"),
        _doc("add 'deploy' to shadow group 'wheel'", "2026-05-01T09:01:00+00:00", 11, process="usermod"),
        _doc("changed user 'www-data' shell to '/bin/bash'", "2026-05-01T09:02:00+00:00", 12, process="chsh"),
        _doc("pam_unix(passwd:chauthtok): password changed for deploy", "2026-05-01T09:03:00+00:00", 13, process="passwd"),
        _passwd("www-data", 33, "/usr/sbin/nologin"),
        _passwd("deploy", 1002),
    ]
    result = _run(monkeypatch, docs)
    actions = [(change["action"], change["account"], change["group"]) for change in result["account_changes"]]
    assert ("group_member_added", "deploy", "wheel") in actions
    assert sum(1 for action in actions if action[0] == "group_member_added") == 1  # shadow-group duplicate folded
    assert ("password_changed", "deploy", "") in actions
    assert {"privileged_account_change", "system_account_shell"} <= _kinds(result)
    critical = [finding for finding in result["findings"] if finding["severity"] == "critical"]
    assert critical and critical[0]["account"] == "backup2"


def test_su_is_attributed_to_the_login_name(monkeypatch):
    docs = [
        _doc("Successful su for root by root", "2026-06-01T10:00:00+00:00", 77, process="su"),
        _doc("+ /dev/pts/1 root:root", "2026-06-01T10:00:00+00:00", 77, process="su"),
        _doc("pam_unix(su:session): session opened for user root by mail(uid=0)", "2026-06-01T10:00:00+00:00", 77, process="su"),
        _doc("pam_unix(su:auth): authentication failure; logname=bob uid=1001 euid=0 tty=pts/2 ruser=bob rhost=  user=root", "2026-06-01T11:00:00+00:00", 88, process="su"),
    ]
    result = _run(monkeypatch, docs)
    rows = {(row["user"], row["target"], row["result"]) for row in result["privilege"]}
    assert ("mail", "root", "allowed") in rows
    assert result["overview"]["failed_attempts"] == 0  # a failed su is not a login attempt
    assert result["overview"]["successful_logins"] == 0


def test_system_account_login_and_logins_missing_from_logs(monkeypatch):
    docs = [
        _doc("Accepted password for alice from 10.0.0.5 port 2222 ssh2", "2026-07-01T08:00:00+00:00", 40),
        _doc("Accepted password for mail from 10.0.0.9 port 2223 ssh2", "2026-07-01T09:00:00+00:00", 41),
        _doc("Server listening on 0.0.0.0 port 22.", "2026-07-01T12:00:00+00:00", 1),
        # wtmp knows a login the log does not, inside the period the log covers.
        _doc("wtmp login success user=bob", "2026-07-01T10:00:00+00:00", 42, process="login", carrier="wtmp",
             auth_event_type="login_success", username="bob", source_ip="10.0.0.7", terminal="pts/3"),
        _passwd("mail", 8),
        _passwd("alice", 1000),
    ]
    result = _run(monkeypatch, docs)
    assert {"system_account_login", "login_missing_from_logs"} <= _kinds(result)
    assert {session["username"] for session in result["sessions"]} == {"alice", "mail", "bob"}


def test_events_are_paged_and_grouped(monkeypatch):
    docs = [_doc(f"Failed password for root from 192.0.2.9 port {30000 + i} ssh2", f"2026-08-01T00:00:{i:02d}+00:00", 100 + i) for i in range(30)]
    result = _run(monkeypatch, docs, event_group="failures", offset=10, limit=5)
    assert result["events"]["total"] == 30
    assert len(result["events"]["items"]) == 5
    assert result["events"]["items"][0]["time"] == "2026-08-01T00:00:19Z"
