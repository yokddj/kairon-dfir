"""auth.log lines that matter in an investigation are classified. Users and addresses are synthetic."""
from __future__ import annotations

from unittest.mock import MagicMock

import pytest

from app.core import opensearch as os_module
from app.ingest.artifact_normalizers import normalize_linux_row
from app.ingest.linux.auth import parse_auth
from app.ingest.linux.database_logs import parse_database_log
from app.ingest.normalizer import base_document
from app.search.query_syntax import analyze_query_syntax


def _one(line: str) -> dict:
    return parse_auth(line + "\n", source_path="var/log/auth.log")[0]


def test_a_sudo_command_names_the_user_the_target_account_and_the_command():
    row = _one("Apr 16 15:20:01 web sudo: admin : TTY=pts/0 ; PWD=/home/admin ; USER=root ; COMMAND=/bin/cat /etc/shadow")
    assert row["event_action"] == "sudo_command" and row["authentication_result"] == "success"
    assert (row["username"], row["run_as"], row["cwd"], row["terminal"], row["command"]) == ("admin", "root", "/home/admin", "pts/0", "/bin/cat /etc/shadow")


def test_a_refused_sudo_is_a_failure():
    row = _one("Apr 16 15:20:01 web sudo: guest : 3 incorrect password attempts ; TTY=pts/1 ; PWD=/tmp ; USER=root ; COMMAND=/bin/bash")
    assert (row["event_action"], row["authentication_result"], row["username"], row["command"]) == ("sudo_failed", "failure", "guest", "/bin/bash")


def test_too_many_attempts_is_a_failed_login_with_its_source():
    row = _one("Oct  5 13:20:59 web sshd[2000]: error: maximum authentication attempts exceeded for root from 203.0.113.9 port 57418 ssh2 [preauth]")
    assert (row["event_action"], row["auth_event_type"], row["username"], row["source_ip"], row["source_port"]) == ("max_auth_attempts", "login_failure", "root", "203.0.113.9", 57418)


@pytest.mark.parametrize("line, user, tty", [
    ("Apr 16 15:20:01 web login[900]: ROOT LOGIN  on '/dev/tty1'", "root", "tty1"),
    ("Apr 16 15:20:01 web login[900]: LOGIN ON tty2 BY admin", "admin", "tty2"),
])
def test_console_logins(line, user, tty):
    row = _one(line)
    assert (row["event_action"], row["auth_event_type"], row["username"], row["terminal"]) == ("console_login", "login_success", user, tty)


@pytest.mark.parametrize("line, action", [
    ("Oct  5 13:20:59 web sshd[2000]: Connection closed by 203.0.113.9 [preauth]", "preauth_disconnect"),
    ("Oct  5 13:20:59 web sshd[2000]: Received disconnect from 203.0.113.9: 11: disconnected by user", "ssh_disconnect"),
    ("Oct  5 13:20:59 web sshd[2000]: Server listening on 0.0.0.0 port 22.", "sshd_listening"),
])
def test_other_sshd_lines_are_named(line, action):
    assert _one(line)["event_action"] == action


def test_a_postgres_fatal_is_an_error_not_a_server_failure():
    rows = parse_database_log('2016-04-03 10:00:00 UTC [1] root@app FATAL:  role "root" does not exist\n2016-04-03 10:00:01 UTC [2] PANIC:  could not write\n', source_path="var/log/postgresql/postgresql-9.3-main.log")
    severities = []
    for row in rows:
        base = base_document("c", "e", "a", row, {"artifact_type": "linux_database"})
        severities.append(normalize_linux_row(base, row, source_path=row["source_file"], artifact_type="linux_database")["event"]["severity"])
    assert severities == ["medium", "high"]


def test_sudo_targets_terminals_and_web_flags_are_searchable(monkeypatch):
    client = MagicMock()
    monkeypatch.setattr(os_module, "get_opensearch_client", lambda **_: client)
    monkeypatch.setattr(os_module, "index_exists", lambda *_a, **_k: False)
    monkeypatch.setattr(os_module, "_apply_safe_index_settings", lambda *_a, **_k: None, raising=False)
    os_module.ensure_case_index("11111111-1111-4111-8111-111111111111")
    properties = client.indices.create.call_args.kwargs["body"]["mappings"]["properties"]["linux"]["properties"]
    assert {"run_as", "terminal", "suspicious_url_indicators"} <= set(properties)
    query = str(analyze_query_syntax("indicator:embedded_base64", lambda t: {"simple_query_string": {"query": t}})["query"])
    assert "linux.suspicious_url_indicators" in query
    assert "linux.run_as" in str(analyze_query_syntax("runas:root", lambda t: {"simple_query_string": {"query": t}})["query"])


@pytest.mark.parametrize("line, package, version, previous, status, action", [
    ("2014-04-16 21:02:50 install base-passwd:i386 <none> 3.5.33", "base-passwd:i386", "3.5.33", None, None, "install"),
    ("2016-05-04 17:45:00 upgrade dpkg 1.17.5ubuntu5 1.17.5ubuntu5.7", "dpkg", "1.17.5ubuntu5.7", "1.17.5ubuntu5", None, "upgrade"),
    ("2016-05-04 17:45:00 status installed man-db:i386 2.6.7.1-1ubuntu1", "man-db:i386", "2.6.7.1-1ubuntu1", None, "installed", "status"),
    ("2016-05-04 17:45:00 remove ubuntu-minimal:i386 1.325 <none>", "ubuntu-minimal:i386", "1.325", None, None, "remove"),
    ("2016-05-04 17:45:00 startup archives unpack", None, None, None, None, "startup"),
])
def test_dpkg_log_lines_name_the_package_and_its_versions(line, package, version, previous, status, action):
    from app.ingest.linux.packages import parse_packages

    row = parse_packages(line + "\n", source_path="var/log/dpkg.log")[0]
    assert (row["package"], row["version"], row["previous_version"], row["package_status"], row["action"]) == (package, version, previous, status, action)
    if package:
        base = base_document("c", "e", "a", row, {"artifact_type": "linux_packages"})
        doc = normalize_linux_row(base, row, source_path="var/log/dpkg.log", artifact_type="linux_packages")
        assert (doc["linux"]["package"], doc["linux"]["package_action"]) == (package, action)
        assert "linux.package" in str(analyze_query_syntax("package:netcat*", lambda t: {"simple_query_string": {"query": t}})["query"])
