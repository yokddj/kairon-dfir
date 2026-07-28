import pytest
from pathlib import Path
import struct
import gzip

FIXTURES_DIR = Path(__file__).parent / "fixtures" / "linux"


class TestApacheParser:
    def test_common_log_format_access(self):
        from app.ingest.linux.apache import parse_apache

        rows = parse_apache('192.0.2.10 - frank [10/Oct/2024:13:55:36 +0000] "GET /apache_pb.gif HTTP/1.0" 200 2326\n', source_path="/var/log/apache2/access.log")

        assert rows[0]["artifact_family"] == "linux_apache"
        assert rows[0]["artifact_type"] == "apache_access"
        assert rows[0]["source_ip"] == "192.0.2.10"
        assert rows[0]["username"] == "frank"
        assert rows[0]["http_method"] == "GET"
        assert rows[0]["url_path"] == "/apache_pb.gif"
        assert rows[0]["http_status"] == 200
        assert rows[0]["bytes_sent"] == 2326
        assert rows[0]["timestamp"] == "2024-10-10T13:55:36+00:00"

    def test_combined_log_format_access(self):
        from app.ingest.linux.apache import parse_apache

        rows = parse_apache('198.51.100.5 - - [10/Oct/2024:13:56:36 +0000] "POST /login HTTP/1.1" 302 123 "https://example.test/" "curl/8.0"\n', source_path="/var/log/httpd/access_log")

        assert rows[0]["http_method"] == "POST"
        assert rows[0]["url_path"] == "/login"
        assert rows[0]["http_referrer"] == "https://example.test/"
        assert rows[0]["http_user_agent"] == "curl/8.0"

    def test_error_log(self):
        from app.ingest.linux.apache import parse_apache

        rows = parse_apache("[Thu Oct 10 13:55:37.123456 2024] [core:error] [pid 123:tid 456] [client 203.0.113.9:4444] File does not exist: /var/www/html/admin\n", source_path="/var/log/apache2/error.log")

        assert rows[0]["artifact_type"] == "apache_error"
        assert rows[0]["apache_module"] == "core"
        assert rows[0]["http_severity"] == "error"
        assert rows[0]["pid"] == 123
        assert rows[0]["thread_id"] == 456
        assert rows[0]["source_ip"] == "203.0.113.9"
        assert rows[0]["source_port"] == 4444

    def test_rotated_gzip_access_normalizes_with_provenance(self, tmp_path):
        from app.ingest.normalizer import normalize_file

        path = tmp_path / "access.log.1.gz"
        with gzip.open(path, "wt", encoding="utf-8") as handle:
            handle.write('192.0.2.10 - - [10/Oct/2024:13:55:36 +0000] "GET /index.html HTTP/1.1" 404 2326 "-" "Mozilla/5"\n')
        artifact_meta = {
            "artifact_family": "linux_apache",
            "artifact_type": "apache_access",
            "parser": "linux_apache_raw",
            "name": "access.log.1.gz",
            "source_path": "/var/log/apache2/access.log.1.gz",
            "detected_host": "web01",
        }

        docs = normalize_file("case-1", "ev-1", "art-1", path, artifact_meta)

        assert len(docs) == 1
        doc = docs[0]
        assert doc["case_id"] == "case-1"
        assert doc["evidence_id"] == "ev-1"
        assert doc["artifact_id"] == "art-1"
        assert doc["artifact"]["type"] == "linux_apache"
        assert doc["artifact"]["parser"] == "linux_apache_raw"
        assert doc["source_file"] == "/var/log/apache2/access.log.1.gz"
        assert doc["linux"]["http_status"] == 404
        assert doc["linux"]["url_path"] == "/index.html"
        assert doc["linux"]["line_number"] == 1
        assert doc["network"]["source_ip"] == "192.0.2.10"
        assert doc["url"]["path"] == "/index.html"
        assert doc["http"]["request"]["method"] == "GET"
        assert doc["http"]["response"]["status_code"] == 404
        assert doc["user_agent"]["original"] == "Mozilla/5"
        assert doc["@timestamp"] == "2024-10-10T13:55:36+00:00"
        assert "GET" in doc["search_text"]
        assert "/index.html" in doc["search_text"]
        assert "Mozilla/5" in doc["search_text"]
        assert artifact_meta["ingest_audit"]["parser_status"] == "parsed"

    def test_error_log_normalizes_network_and_severity(self, tmp_path):
        from app.ingest.normalizer import normalize_file

        path = tmp_path / "error.log"
        path.write_text("[Thu Oct 10 13:55:37.123456 2024] [core:error] [pid 123] [client 203.0.113.9:4444] File does not exist: /var/www/html/admin\n", encoding="utf-8")
        artifact_meta = {
            "artifact_family": "linux_apache",
            "artifact_type": "apache_error",
            "parser": "linux_apache_raw",
            "name": "error.log",
            "source_path": "/var/log/apache2/error.log",
            "detected_host": "web01",
        }

        docs = normalize_file("case-1", "ev-1", "art-1", path, artifact_meta)

        assert docs[0]["event"]["severity"] == "medium"
        assert docs[0]["linux"]["http_severity"] == "error"
        assert docs[0]["linux"]["line_number"] == 1
        assert docs[0]["network"]["source_ip"] == "203.0.113.9"
        assert docs[0]["network"]["source_port"] == 4444
        assert docs[0]["title"] == "File does not exist: /var/www/html/admin"

    def test_raw_parser_name_maps_to_normalized_apache_family(self, tmp_path):
        from app.ingest.normalizer import normalize_file

        path = tmp_path / "access.log"
        path.write_text('192.0.2.10 - - [10/Oct/2024:13:55:36 +0000] "GET /health HTTP/1.1" 200 10 "-" "curl/8"\n', encoding="utf-8")
        artifact_meta = {
            "artifact_family": "linux_apache",
            "artifact_type": "apache_access",
            "parser": "linux_apache_raw",
            "name": "access.log",
            "source_path": "/var/log/apache2/access.log",
        }

        doc = normalize_file("case-1", "ev-1", "art-1", path, artifact_meta)[0]

        assert doc["artifact"]["type"] == "linux_apache"
        assert doc["artifact"]["family"] == "linux_apache"
        assert doc["artifact"]["parser"] == "linux_apache_raw"
        assert doc["source_tool"] == "linux_apache_raw"


class TestEximParser:
    def test_mainlog_message_received(self):
        from app.ingest.linux.exim import parse_exim

        rows = parse_exim(
            "2024-10-10 13:55:36 1abcDE-0001fG-2H <= sender@example.test H=mail.example.test [192.0.2.10]:587 I=[198.51.100.10]:25 P=esmtpsa A=dovecot_login:user S=1234 id=<msg-1@example.test>\n",
            source_path="/var/log/exim4/mainlog",
        )

        row = rows[0]
        assert row["artifact_family"] == "linux_exim"
        assert row["artifact_type"] == "exim_main"
        assert row["event_action"] == "message_received"
        assert row["event_outcome"] == "success"
        assert row["sender"] == "sender@example.test"
        assert row["queue_id"] == "1abcDE-0001fG-2H"
        assert row["message_id"] == "msg-1@example.test"
        assert row["remote_ip"] == "192.0.2.10"
        assert row["source_port"] == 587
        assert row["local_ip"] == "198.51.100.10"
        assert row["destination_port"] == 25
        assert row["helo"] == "mail.example.test"
        assert row["authentication"] == "dovecot_login:user"
        assert row["timestamp"] == "2024-10-10T13:55:36+00:00"

    def test_delivery_and_reject_lines(self):
        from app.ingest.linux.exim import parse_exim

        delivered = parse_exim("2024-10-10 13:56:36 1abcDE-0001fG-2H => recipient@example.test R=dnslookup T=remote_smtp H=mx.example.test [203.0.113.20] C=250 OK\n", source_path="/var/log/exim/mainlog.1")
        rejected = parse_exim("2024-10-10 13:57:36 H=badhost [203.0.113.9] F=<spam@example.test> rejected RCPT recipient@example.test: relay not permitted\n", source_path="/var/log/exim4/rejectlog")

        assert delivered[0]["event_action"] == "message_delivered"
        assert delivered[0]["recipient"] == "recipient@example.test"
        assert delivered[0]["smtp_status"] == 250
        assert delivered[0]["event_outcome"] == "success"
        assert rejected[0]["artifact_type"] == "exim_reject"
        assert rejected[0]["event_action"] == "message_rejected"
        assert rejected[0]["sender"] == "spam@example.test"
        assert rejected[0]["recipient"] == "recipient@example.test"
        assert rejected[0]["remote_ip"] == "203.0.113.9"
        assert rejected[0]["event_outcome"] == "failure"

    def test_reject_from_and_mail_sender_variants(self):
        from app.ingest.linux.exim import parse_exim

        from_sender = parse_exim("2024-10-10 13:57:36 1abcDE-0001fG-2H rejected from <root@local.test> H=(badhost) [203.0.113.9]: message too big\n", source_path="/var/log/exim4/mainlog")
        mail_sender = parse_exim("2024-10-10 13:57:37 H=(badhost) [203.0.113.9] temporarily rejected MAIL <root@local.test>: failed ACL\n", source_path="/var/log/exim4/rejectlog")

        assert from_sender[0]["queue_id"] == "1abcDE-0001fG-2H"
        assert from_sender[0]["sender"] == "root@local.test"
        assert mail_sender[0]["sender"] == "root@local.test"

    def test_panic_and_malformed_lines_are_preserved(self):
        from app.ingest.linux.exim import parse_exim

        panic = parse_exim("2024-10-10 13:58:36 exim user lost privilege for using -C option\n", source_path="/var/log/exim4/paniclog")
        malformed = parse_exim("not a timestamped exim line but still forensic content\n", source_path="/var/log/exim4/mainlog")

        assert panic[0]["artifact_type"] == "exim_panic"
        assert panic[0]["event_action"] == "panic"
        assert panic[0]["event_severity"] == "high"
        assert malformed[0]["timestamp"] is None
        assert malformed[0]["message"] == "not a timestamped exim line but still forensic content"
        assert malformed[0]["line_number"] == 1

    def test_rotated_gzip_normalizes_with_search_fields_and_provenance(self, tmp_path):
        from app.ingest.normalizer import normalize_file

        path = tmp_path / "mainlog.1.gz"
        with gzip.open(path, "wt", encoding="utf-8") as handle:
            handle.write("2024-10-10 13:55:36 1abcDE-0001fG-2H <= sender@example.test H=mail.example.test [192.0.2.10]:587 I=[198.51.100.10]:25 A=plain:user id=<msg-1@example.test>\n")
        artifact_meta = {
            "artifact_family": "linux_exim",
            "artifact_type": "exim_main",
            "parser": "linux_exim_raw",
            "name": "mainlog.1.gz",
            "source_path": "/var/log/exim4/mainlog.1.gz",
            "detected_host": "mail01",
        }

        docs = normalize_file("case-1", "ev-1", "art-1", path, artifact_meta)

        assert len(docs) == 1
        doc = docs[0]
        assert doc["case_id"] == "case-1"
        assert doc["evidence_id"] == "ev-1"
        assert doc["artifact_id"] == "art-1"
        assert doc["artifact"]["type"] == "linux_exim"
        assert doc["artifact"]["family"] == "linux_exim"
        assert doc["artifact"]["parser"] == "linux_exim_raw"
        assert doc["source_tool"] == "linux_exim_raw"
        assert doc["source_file"] == "/var/log/exim4/mainlog.1.gz"
        assert doc["evidence_source"]["logical_source_path"] == "/var/log/exim4/mainlog.1.gz"
        assert doc["event"]["type"] == "exim_main"
        assert doc["event"]["action"] == "message_received"
        assert doc["event"]["outcome"] == "success"
        assert doc["event"]["severity"] == "info"
        assert doc["network"]["source_ip"] == "192.0.2.10"
        assert doc["destination"]["ip"] == "198.51.100.10"
        assert doc["email"]["from"]["address"] == "sender@example.test"
        assert doc["email"]["message_id"] == "msg-1@example.test"
        assert doc["linux"]["queue_id"] == "1abcDE-0001fG-2H"
        assert doc["linux"]["authentication"] == "plain:user"
        assert doc["linux"]["line_number"] == 1
        assert "sender@example.test" in doc["search_text"]
        assert "1abcDE-0001fG-2H" in doc["search_text"]
        assert artifact_meta["ingest_audit"]["parser_status"] == "parsed"


class TestAuthLogParser:
    @pytest.fixture
    def auth_log_content(self):
        return (FIXTURES_DIR / "auth.log").read_text()

    def test_accepted_ssh_login(self, auth_log_content):
        from app.ingest.linux.auth import parse_auth
        results = parse_auth(auth_log_content, source_path="/var/log/auth.log")
        accepted = [r for r in results if r.get("event_action") == "publickey_accepted"]
        assert len(accepted) >= 1
        entry = accepted[0]
        assert entry["username"] == "analyst"
        assert entry["auth_method"] == "publickey"
        assert entry["source_ip"] == "10.0.0.50"
        assert "RSA" in entry.get("message", "")
        assert entry["artifact_family"] == "linux_auth"
        assert entry["source_file"] == "/var/log/auth.log"

    def test_failed_ssh_password(self, auth_log_content):
        from app.ingest.linux.auth import parse_auth
        results = parse_auth(auth_log_content, source_path="/var/log/auth.log")
        failed = [r for r in results if r.get("event_action") == "password_failed"]
        assert len(failed) >= 1
        entry = failed[0]
        assert entry["username"] == "root"
        assert entry["auth_method"] == "password"
        assert entry["source_ip"] == "192.168.1.100"

    def test_sudo_command(self, auth_log_content):
        from app.ingest.linux.auth import parse_auth
        results = parse_auth(auth_log_content, source_path="/var/log/auth.log")
        sudo_cmds = [r for r in results if r.get("process") == "sudo"]
        assert len(sudo_cmds) >= 1
        entry = sudo_cmds[0]
        assert entry["username"] == "root"
        assert "systemctl" in entry.get("message", "")

    def test_su_auth(self, auth_log_content):
        from app.ingest.linux.auth import parse_auth
        results = parse_auth(auth_log_content, source_path="/var/log/auth.log")
        su_entries = [r for r in results if r.get("process") == "su"]
        assert len(su_entries) >= 1
        entry = su_entries[0]
        assert "Successful su" in entry.get("message", "")

    def test_invalid_user(self, auth_log_content):
        from app.ingest.linux.auth import parse_auth
        results = parse_auth(auth_log_content, source_path="/var/log/auth.log")
        invalid = [r for r in results if r.get("event_action") == "invalid_user"]
        assert len(invalid) >= 1
        entry = invalid[0]
        assert entry["username"] == "admin"
        assert entry["source_ip"] == "172.16.0.5"

    def test_pam_session_opened(self, auth_log_content):
        from app.ingest.linux.auth import parse_auth
        results = parse_auth(auth_log_content, source_path="/var/log/auth.log")
        opened = [r for r in results if r.get("event_action") == "session_opened"]
        assert len(opened) >= 1
        entry = opened[0]
        assert "analyst" in entry.get("message", "")

    def test_pam_session_closed(self, auth_log_content):
        from app.ingest.linux.auth import parse_auth
        results = parse_auth(auth_log_content, source_path="/var/log/auth.log")
        closed = [r for r in results if r.get("event_action") == "session_closed"]
        assert len(closed) >= 1
        entry = closed[0]
        assert "analyst" in entry.get("message", "")

    def test_authentication_failure(self, auth_log_content):
        from app.ingest.linux.auth import parse_auth
        results = parse_auth(auth_log_content, source_path="/var/log/auth.log")
        failures = [r for r in results if r.get("event_action") == "auth_failure"]
        assert len(failures) >= 1
        entry = failures[0]
        assert "dbadmin" in entry.get("message", "")

    def test_all_lines_parsed(self, auth_log_content):
        from app.ingest.linux.auth import parse_auth
        results = parse_auth(auth_log_content, source_path="/var/log/auth.log")
        assert len(results) == 8

    def test_timestamps_parsed(self, auth_log_content):
        from app.ingest.linux.auth import parse_auth
        results = parse_auth(auth_log_content, source_path="/var/log/auth.log")
        for result in results:
            assert result["timestamp"] is not None

    def test_source_port_and_attempted_username_extracted(self):
        from app.ingest.linux.auth import parse_auth
        rows = parse_auth("Feb  6 15:16:26 victoria sshd[2085]: Failed password for invalid user ulysses from 192.168.56.1 port 34431 ssh2\n", source_path="/var/log/auth.log")
        assert rows[0]["auth_event_type"] == "login_failure"
        assert rows[0]["attempted_username"] == "ulysses"
        assert rows[0]["source_ip"] == "192.168.56.1"
        assert rows[0]["source_port"] == 34431

    def test_pam_aggregate_failure_count_extracted(self):
        from app.ingest.linux.auth import parse_auth
        rows = parse_auth("Feb  6 15:16:40 victoria sshd[2085]: PAM 2 more authentication failures; logname= uid=0 euid=0 tty=ssh ruser= rhost=192.168.56.1\n", source_path="/var/log/auth.log")
        assert rows[0]["auth_event_type"] == "authentication_failure"
        assert rows[0]["effective_failure_count"] == 2
        assert rows[0]["terminal"] == "ssh"

    def test_wtmp_parsing(self):
        from app.ingest.linux.auth import parse_auth
        record = struct.pack("hi32s4s32s256shhiii4i20s", 7, 1234, b"pts/0\0", b"id\0", b"mail\0", b"192.168.1.5\0", 0, 0, 0, 1710000000, 0, 0, 0, 0, 0, b"\0" * 20)
        rows = parse_auth(record, source_path="/var/log/wtmp")
        assert rows[0]["artifact_type"] == "wtmp"
        assert rows[0]["auth_event_type"] == "login_success"
        assert rows[0]["username"] == "mail"

    def test_btmp_parsing(self):
        from app.ingest.linux.auth import parse_auth
        record = struct.pack("hi32s4s32s256shhiii4i20s", 7, 1234, b"ssh\0", b"id\0", b"root\0", b"10.0.0.9\0", 0, 0, 0, 1710000000, 0, 0, 0, 0, 0, b"\0" * 20)
        rows = parse_auth(record, source_path="/var/log/btmp")
        assert rows[0]["artifact_type"] == "btmp"
        assert rows[0]["auth_event_type"] == "login_failure"

    def test_lastlog_parsing(self):
        from app.ingest.linux.auth import parse_auth
        empty = b"\0" * 292
        record = struct.pack("i32s256s", 1710000000, b"pts/1\0", b"10.0.0.10\0")
        rows = parse_auth(empty + record, source_path="/var/log/lastlog")
        assert rows[0]["artifact_type"] == "lastlog"
        assert rows[0]["uid"] == 1
        assert rows[0]["source_ip"] == "10.0.0.10"

    def test_unsupported_binary_layout_returns_empty(self):
        from app.ingest.linux.auth import parse_auth
        assert parse_auth(b"not-a-valid-utmp", source_path="/var/log/wtmp") == []


class TestSyslogParser:
    @pytest.fixture
    def syslog_content(self):
        return (FIXTURES_DIR / "syslog").read_text()

    def test_kernel_message(self, syslog_content):
        from app.ingest.linux.syslog import parse_syslog
        results = parse_syslog(syslog_content, source_path="/var/log/syslog")
        kernel = [r for r in results if r.get("process") == "kernel"]
        assert len(kernel) >= 2
        linux_entry = [r for r in kernel if "Linux version" in r.get("message", "")]
        assert len(linux_entry) >= 1
        assert "5.15.0" in linux_entry[0]["message"]

    def test_cron_message(self, syslog_content):
        from app.ingest.linux.syslog import parse_syslog
        results = parse_syslog(syslog_content, source_path="/var/log/syslog")
        cron = [r for r in results if r.get("process") == "CRON"]
        assert len(cron) >= 1
        entry = cron[0]
        assert "cmd" in entry.get("message", "").lower() or "CMD" in entry.get("message", "")

    def test_systemd_message(self, syslog_content):
        from app.ingest.linux.syslog import parse_syslog
        results = parse_syslog(syslog_content, source_path="/var/log/syslog")
        systemd = [r for r in results if r.get("process") == "systemd"]
        assert len(systemd) >= 2

    def test_all_entries_have_timestamp(self, syslog_content):
        from app.ingest.linux.syslog import parse_syslog
        results = parse_syslog(syslog_content, source_path="/var/log/syslog")
        for result in results:
            assert result["timestamp"] is not None

    def test_artifact_family_is_syslog(self, syslog_content):
        from app.ingest.linux.syslog import parse_syslog
        results = parse_syslog(syslog_content, source_path="/var/log/syslog")
        for result in results:
            assert result["artifact_family"] == "linux_syslog"

    def test_source_file_tracked(self, syslog_content):
        from app.ingest.linux.syslog import parse_syslog
        results = parse_syslog(syslog_content, source_path="/var/log/kern.log")
        for result in results:
            assert result["source_file"] == "/var/log/kern.log"


class TestAuditParser:
    @pytest.fixture
    def audit_content(self):
        return (FIXTURES_DIR / "audit.log").read_text()

    def test_syscall_entry(self, audit_content):
        from app.ingest.linux.audit import parse_audit
        results = parse_audit(audit_content, source_path="/var/log/audit/audit.log")
        syscalls = [r for r in results if r.get("audit_type") == "SYSCALL"]
        assert len(syscalls) >= 2
        entry = syscalls[0]
        assert entry["success"] == "yes"
        assert entry["exe"] == "/usr/bin/sudo"

    def test_execve_with_arguments(self, audit_content):
        from app.ingest.linux.audit import parse_audit
        results = parse_audit(audit_content, source_path="/var/log/audit/audit.log")
        execve = [r for r in results if r.get("audit_type") == "EXECVE"]
        assert len(execve) >= 1
        entry = execve[0]
        message = entry.get("message", "")
        assert "sudo" in message

    def test_user_auth(self, audit_content):
        from app.ingest.linux.audit import parse_audit
        results = parse_audit(audit_content, source_path="/var/log/audit/audit.log")
        user_auth = [r for r in results if r.get("audit_type") == "USER_AUTH"]
        assert len(user_auth) >= 1
        entry = user_auth[0]
        assert "analyst" in entry.get("message", "")

    def test_path_entry_parsed(self, audit_content):
        from app.ingest.linux.audit import parse_audit
        results = parse_audit(audit_content, source_path="/var/log/audit/audit.log")
        paths = [r for r in results if r.get("audit_type") == "PATH"]
        assert len(paths) >= 1
        entry = paths[0]
        assert "/etc/ssh/sshd_config" in entry.get("message", "")

    def test_audit_timestamps_parsed(self, audit_content):
        from app.ingest.linux.audit import parse_audit
        results = parse_audit(audit_content, source_path="/var/log/audit/audit.log")
        with_timestamps = [r for r in results if r["timestamp"] is not None]
        assert len(with_timestamps) >= 1


class TestShellHistoryParser:
    @pytest.fixture
    def bash_history_content(self):
        return (FIXTURES_DIR / ".bash_history").read_text()

    @pytest.fixture
    def zsh_history_content(self):
        return (FIXTURES_DIR / ".zsh_history").read_text()

    def test_bash_history_simple_commands(self, bash_history_content):
        from app.ingest.linux.shell_history import parse_shell_history
        results = parse_shell_history(
            bash_history_content,
            source_path="/home/analyst/.bash_history",
        )
        assert len(results) == 8
        commands = [r["command"] for r in results]
        assert "ls -la /var/log" in commands
        assert "sudo systemctl restart nginx" in commands
        assert "cat /etc/shadow" in commands

    def test_shell_history_dispatch_normalizes_commands(self, tmp_path):
        from app.ingest.normalizer import normalize_file

        history = tmp_path / ".bash_history"
        history.write_text("whoami\ncat /etc/passwd\n", encoding="utf-8")
        artifact_meta = {
            "artifact_family": "linux_shell_history",
            "artifact_type": "bash_history",
            "parser": "linux_shell_raw",
            "name": ".bash_history",
            "source_path": "/root/.bash_history",
            "detected_host": "victoria",
        }

        docs = normalize_file("case-1", "ev-1", "art-1", history, artifact_meta)

        assert [doc["linux"]["command"] for doc in docs] == ["whoami", "cat /etc/passwd"]
        assert docs[0]["artifact"]["type"] == "linux_shell_history"
        assert docs[0]["artifact"]["parser"] == "linux_shell_raw"
        assert docs[0]["source_file"] == "/root/.bash_history"
        assert docs[0]["evidence_id"] == "ev-1"
        assert artifact_meta["ingest_audit"]["parser_status"] == "parsed"
        assert artifact_meta["ingest_audit"]["records_indexed"] == 2

    def test_linux_dispatch_failures_are_visible(self, tmp_path):
        from app.ingest.linux.dispatch import LinuxParserDispatchError
        from app.ingest.normalizer import normalize_file

        history = tmp_path / ".bash_history"
        history.write_text("whoami\n", encoding="utf-8")
        artifact_meta = {
            "artifact_family": "linux_shell_history",
            "artifact_type": "bash_history",
            "parser": "linux_missing_raw",
            "name": ".bash_history",
            "source_path": "/root/.bash_history",
        }

        with pytest.raises(LinuxParserDispatchError):
            normalize_file("case-1", "ev-1", "art-1", history, artifact_meta)

        assert artifact_meta["raw_parser_status"] == "failed_dispatch"
        assert artifact_meta["ingest_audit"]["parser_status"] == "failed_dispatch"
        assert "No Linux parser dispatch target" in artifact_meta["ingest_audit"]["parser_errors"][0]

    def test_linux_dispatch_table_resolves_all_known_raw_parsers(self):
        from app.ingest.linux.dispatch import LINUX_PARSER_TARGETS, resolve_linux_parser
        from app.ingest.linux.helpers import _LINUX_ARTIFACT_MAP

        expected_parsers = {parser for _, _, parser in _LINUX_ARTIFACT_MAP.values()}
        assert expected_parsers <= set(LINUX_PARSER_TARGETS)

        for parser in expected_parsers:
            target, parse_func = resolve_linux_parser(parser)
            assert target.parser == parser
            assert callable(parse_func)

    def test_linux_triage_dispatch_invokes_shell_history_parser(self, tmp_path):
        from app.parsers.linux.triage import LinuxTriageParser

        history = tmp_path / ".bash_history"
        history.write_text("id\n", encoding="utf-8")

        rows = LinuxTriageParser().parse(
            {
                "artifact_family": "linux_shell_history",
                "artifact_type": "bash_history",
                "parser": "linux_shell_raw",
                "source_path": "/root/.bash_history",
                "full_path": str(history),
            }
        )

        assert rows[0]["artifact_family"] == "linux_shell_history"
        assert rows[0]["command"] == "id"

    def test_bash_history_shell_type(self, bash_history_content):
        from app.ingest.linux.shell_history import parse_shell_history
        results = parse_shell_history(
            bash_history_content,
            source_path="/home/analyst/.bash_history",
        )
        for result in results:
            assert result["shell_type"] == "bash"
            assert result["artifact_type"] == "bash_history"

    def test_zsh_history_extended_format(self, zsh_history_content):
        from app.ingest.linux.shell_history import parse_shell_history
        results = parse_shell_history(
            zsh_history_content,
            source_path="/home/devops/.zsh_history",
        )
        assert len(results) == 7
        commands = [r["command"] for r in results]
        assert "ls -la /var/log" in commands
        assert "kubectl get pods -n production" in commands
        assert "docker ps -a" in commands

    def test_zsh_history_timestamps(self, zsh_history_content):
        from app.ingest.linux.shell_history import parse_shell_history
        results = parse_shell_history(
            zsh_history_content,
            source_path="/home/devops/.zsh_history",
        )
        with_timestamps = [r for r in results if r["timestamp"] is not None]
        assert len(with_timestamps) >= 1

    def test_zsh_history_shell_type(self, zsh_history_content):
        from app.ingest.linux.shell_history import parse_shell_history
        results = parse_shell_history(
            zsh_history_content,
            source_path="/home/devops/.zsh_history",
        )
        for result in results:
            assert result["shell_type"] == "zsh"
            assert result["artifact_type"] == "zsh_history"

    def test_username_inferred_from_path(self, bash_history_content):
        from app.ingest.linux.shell_history import parse_shell_history
        results = parse_shell_history(
            bash_history_content,
            source_path="/home/analyst/.bash_history",
        )
        for result in results:
            assert result["username"] == "analyst"

    def test_root_user_inferred(self):
        from app.ingest.linux.shell_history import parse_shell_history
        results = parse_shell_history(
            "ls -la /root\n",
            source_path="/root/.bash_history",
        )
        assert len(results) == 1
        assert results[0]["username"] == "root"


class TestCronParser:
    @pytest.fixture
    def crontab_content(self):
        return (FIXTURES_DIR / "root-crontab").read_text()

    def test_crontab_entries_with_schedule(self, crontab_content):
        from app.ingest.linux.cron import parse_cron
        results = parse_cron(crontab_content, source_path="/etc/crontab")
        assert len(results) >= 6

    def test_crontab_schedule_extraction(self, crontab_content):
        from app.ingest.linux.cron import parse_cron
        results = parse_cron(crontab_content, source_path="/etc/crontab")
        hourly = [r for r in results if "cron.hourly" in r.get("command", "")]
        assert len(hourly) >= 1
        assert hourly[0]["schedule"] == "17 * * * *"

    def test_crontab_user_field(self, crontab_content):
        from app.ingest.linux.cron import parse_cron
        results = parse_cron(crontab_content, source_path="/etc/crontab")
        analysts = [r for r in results if r.get("username") == "analyst"]
        assert len(analysts) >= 1
        entry = analysts[0]
        assert "health_check" in entry.get("command", "")

    def test_crontab_comments_skipped(self, crontab_content):
        from app.ingest.linux.cron import parse_cron
        results = parse_cron(crontab_content, source_path="/etc/crontab")
        messages = [r.get("message", "") for r in results]
        for msg in messages:
            assert not msg.startswith("#")
            assert "job definition" not in msg.lower()

    def test_crontab_env_vars_skipped(self, crontab_content):
        from app.ingest.linux.cron import parse_cron
        results = parse_cron(crontab_content, source_path="/etc/crontab")
        for result in results:
            assert "SHELL=" not in result.get("command", "")
            assert "PATH=" not in result.get("command", "")

    def test_crontab_artifact_family(self, crontab_content):
        from app.ingest.linux.cron import parse_cron
        results = parse_cron(crontab_content, source_path="/etc/crontab")
        for result in results:
            assert result["artifact_family"] == "linux_cron"
            assert result["artifact_type"] == "crontab"


class TestSystemdParser:
    @pytest.fixture
    def service_content(self):
        return (FIXTURES_DIR / "nginx.service").read_text()

    def test_service_unit_description(self, service_content):
        from app.ingest.linux.systemd import parse_systemd
        results = parse_systemd(service_content, source_path="/etc/systemd/system/nginx.service")
        assert len(results) == 1
        entry = results[0]
        assert "nginx" in entry.get("description", "")
        assert entry["unit_type"] == "service"

    def test_service_execstart(self, service_content):
        from app.ingest.linux.systemd import parse_systemd
        results = parse_systemd(service_content, source_path="/etc/systemd/system/nginx.service")
        entry = results[0]
        assert entry["exec_start"] is not None
        assert "/usr/sbin/nginx" in entry["exec_start"]

    def test_service_wantedby(self, service_content):
        from app.ingest.linux.systemd import parse_systemd
        results = parse_systemd(service_content, source_path="/etc/systemd/system/nginx.service")
        entry = results[0]
        assert entry["wanted_by"] == "multi-user.target"

    def test_service_unit_name(self, service_content):
        from app.ingest.linux.systemd import parse_systemd
        results = parse_systemd(service_content, source_path="/etc/systemd/system/nginx.service")
        entry = results[0]
        assert entry["unit_name"] == "nginx.service"
        assert entry["unit_type"] == "service"

    def test_service_execstartpre(self, service_content):
        from app.ingest.linux.systemd import parse_systemd
        results = parse_systemd(service_content, source_path="/etc/systemd/system/nginx.service")
        entry = results[0]
        assert entry["exec_start_pre"] is not None
        assert "/usr/sbin/nginx" in entry["exec_start_pre"]

    def test_timer_unit_type_detected(self):
        from app.ingest.linux.systemd import parse_systemd
        results = parse_systemd(
            "[Unit]\nDescription=Daily cleanup\n[Timer]\nOnCalendar=daily\n",
            source_path="/etc/systemd/system/cleanup.timer",
        )
        assert len(results) == 1
        assert results[0]["unit_type"] == "timer"


class TestSSHArtifactsParser:
    @pytest.fixture
    def authorized_keys_content(self):
        return (FIXTURES_DIR / "authorized_keys").read_text()

    @pytest.fixture
    def known_hosts_content(self):
        return (FIXTURES_DIR / "known_hosts").read_text()

    @pytest.fixture
    def ssh_config_content(self):
        return (FIXTURES_DIR / "ssh_config").read_text()

    def test_authorized_keys_entries(self, authorized_keys_content):
        from app.ingest.linux.ssh_artifacts import parse_ssh_artifacts
        results = parse_ssh_artifacts(
            authorized_keys_content,
            source_path="/home/analyst/.ssh/authorized_keys",
        )
        assert len(results) == 3

    def test_authorized_keys_key_type(self, authorized_keys_content):
        from app.ingest.linux.ssh_artifacts import parse_ssh_artifacts
        results = parse_ssh_artifacts(
            authorized_keys_content,
            source_path="/home/analyst/.ssh/authorized_keys",
        )
        key_types = [r["key_type"] for r in results]
        assert "ssh-rsa" in key_types
        assert "ssh-ed25519" in key_types
        assert "ecdsa-sha2-nistp256" in key_types

    def test_authorized_keys_fingerprint_present(self, authorized_keys_content):
        from app.ingest.linux.ssh_artifacts import parse_ssh_artifacts
        results = parse_ssh_artifacts(
            authorized_keys_content,
            source_path="/home/analyst/.ssh/authorized_keys",
        )
        for result in results:
            fingerprint = result.get("key_fingerprint", "")
            assert fingerprint
            assert "..." in fingerprint or fingerprint == "[redacted]"

    def test_authorized_keys_full_key_not_present(self, authorized_keys_content):
        from app.ingest.linux.ssh_artifacts import parse_ssh_artifacts
        results = parse_ssh_artifacts(
            authorized_keys_content,
            source_path="/home/analyst/.ssh/authorized_keys",
        )
        for result in results:
            fingerprint = result.get("key_fingerprint", "")
            assert fingerprint.endswith("...") or fingerprint == "[redacted]", \
                f"key_fingerprint should be truncated, got: {fingerprint}"

    def test_authorized_keys_comment(self, authorized_keys_content):
        from app.ingest.linux.ssh_artifacts import parse_ssh_artifacts
        results = parse_ssh_artifacts(
            authorized_keys_content,
            source_path="/home/analyst/.ssh/authorized_keys",
        )
        comments = [r["key_comment"] for r in results]
        assert "analyst@workstation" in comments

    def test_known_hosts_parsed(self, known_hosts_content):
        from app.ingest.linux.ssh_artifacts import parse_ssh_artifacts
        results = parse_ssh_artifacts(
            known_hosts_content,
            source_path="/home/analyst/.ssh/known_hosts",
        )
        assert len(results) == 3
        hosts = [r["host_pattern"] for r in results]
        assert "git.example.com" in hosts

    def test_known_hosts_key_redacted(self, known_hosts_content):
        from app.ingest.linux.ssh_artifacts import parse_ssh_artifacts
        results = parse_ssh_artifacts(
            known_hosts_content,
            source_path="/home/analyst/.ssh/known_hosts",
        )
        for result in results:
            assert result["key_fingerprint"] == "[redacted]"

    def test_ssh_config_parsed(self, ssh_config_content):
        from app.ingest.linux.ssh_artifacts import parse_ssh_artifacts
        results = parse_ssh_artifacts(
            ssh_config_content,
            source_path="/home/analyst/.ssh/config",
        )
        assert len(results) > 0

    def test_ssh_config_host_blocks(self, ssh_config_content):
        from app.ingest.linux.ssh_artifacts import parse_ssh_artifacts
        results = parse_ssh_artifacts(
            ssh_config_content,
            source_path="/home/analyst/.ssh/config",
        )
        host_patterns = [r.get("host_pattern") for r in results if r.get("host_pattern")]
        assert "*" in host_patterns

    def test_ssh_config_username_inferred(self, ssh_config_content):
        from app.ingest.linux.ssh_artifacts import parse_ssh_artifacts
        results = parse_ssh_artifacts(
            ssh_config_content,
            source_path="/home/analyst/.ssh/config",
        )
        assert len(results) > 0


class TestIdentityParser:
    @pytest.fixture
    def passwd_content(self):
        return (FIXTURES_DIR / "passwd").read_text()

    @pytest.fixture
    def group_content(self):
        return (FIXTURES_DIR / "group").read_text()

    @pytest.fixture
    def shadow_content(self):
        return (FIXTURES_DIR / "shadow").read_text()

    def test_passwd_entries(self, passwd_content):
        from app.ingest.linux.identity import parse_identity
        results = parse_identity(passwd_content, source_path="/etc/passwd")
        assert len(results) >= 5

    def test_passwd_user_fields(self, passwd_content):
        from app.ingest.linux.identity import parse_identity
        results = parse_identity(passwd_content, source_path="/etc/passwd")
        usernames = [r["username"] for r in results]
        assert "root" in usernames
        assert "analyst" in usernames
        assert "nobody" in usernames

    def test_passwd_uid_gid(self, passwd_content):
        from app.ingest.linux.identity import parse_identity
        results = parse_identity(passwd_content, source_path="/etc/passwd")
        root = [r for r in results if r["username"] == "root"]
        assert len(root) == 1
        assert root[0]["uid"] == "0"
        assert root[0]["gid"] == "0"

    def test_passwd_home_and_shell(self, passwd_content):
        from app.ingest.linux.identity import parse_identity
        results = parse_identity(passwd_content, source_path="/etc/passwd")
        analyst = [r for r in results if r["username"] == "analyst"]
        assert len(analyst) == 1
        assert analyst[0]["home"] == "/home/analyst"
        assert analyst[0]["shell"] == "/bin/bash"

    def test_group_entries(self, group_content):
        from app.ingest.linux.identity import parse_identity
        results = parse_identity(group_content, source_path="/etc/group")
        assert len(results) >= 5

    def test_group_members(self, group_content):
        from app.ingest.linux.identity import parse_identity
        results = parse_identity(group_content, source_path="/etc/group")
        sudo_group = [r for r in results if r["group_name"] == "sudo"]
        assert len(sudo_group) == 1
        assert "analyst" in sudo_group[0]["members"]

    def test_group_gid(self, group_content):
        from app.ingest.linux.identity import parse_identity
        results = parse_identity(group_content, source_path="/etc/group")
        docker = [r for r in results if r["group_name"] == "docker"]
        assert len(docker) == 1
        assert docker[0]["gid"] == "999"

    def test_shadow_no_hashes_stored(self, shadow_content):
        from app.ingest.linux.identity import parse_identity
        results = parse_identity(shadow_content, source_path="/etc/shadow")
        assert len(results) == 1
        entry = results[0]
        message = entry.get("message", "")
        assert "hashes not stored" in message
        assert "root" in entry.get("username", "")


class TestSudoersParser:
    @pytest.fixture
    def sudoers_content(self):
        return (FIXTURES_DIR / "sudoers").read_text()

    def test_sudoers_rules(self, sudoers_content):
        from app.ingest.linux.sudoers import parse_sudoers
        results = parse_sudoers(sudoers_content, source_path="/etc/sudoers")
        rules = [r for r in results if not r.get("is_defaults")]
        assert len(rules) >= 5

    def test_sudoers_defaults(self, sudoers_content):
        from app.ingest.linux.sudoers import parse_sudoers
        results = parse_sudoers(sudoers_content, source_path="/etc/sudoers")
        defaults = [r for r in results if r.get("is_defaults")]
        assert len(defaults) >= 3

    def test_sudoers_principal(self, sudoers_content):
        from app.ingest.linux.sudoers import parse_sudoers
        results = parse_sudoers(sudoers_content, source_path="/etc/sudoers")
        principals = [r["principal"] for r in results if r.get("principal")]
        assert "analyst" in principals
        assert "devops" in principals

    def test_sudoers_nopasswd_option(self, sudoers_content):
        from app.ingest.linux.sudoers import parse_sudoers
        results = parse_sudoers(sudoers_content, source_path="/etc/sudoers")
        analyst_rules = [r for r in results if r.get("principal") == "analyst"]
        assert len(analyst_rules) >= 1
        assert "NOPASSWD" in analyst_rules[0].get("options", [])

    def test_sudoers_run_as(self, sudoers_content):
        from app.ingest.linux.sudoers import parse_sudoers
        results = parse_sudoers(sudoers_content, source_path="/etc/sudoers")
        dbadmin_rules = [r for r in results if r.get("principal") == "dbadmin"]
        assert len(dbadmin_rules) >= 1
        assert "postgres" in dbadmin_rules[0].get("run_as", "")

    def test_sudoers_defaults_values(self, sudoers_content):
        from app.ingest.linux.sudoers import parse_sudoers
        results = parse_sudoers(sudoers_content, source_path="/etc/sudoers")
        defaults = [r for r in results if r.get("is_defaults")]
        secure_path = [d for d in defaults if "secure_path" in (d.get("defaults_value") or "")]
        assert len(secure_path) >= 1


class TestPackagesParser:
    @pytest.fixture
    def dpkg_content(self):
        return (FIXTURES_DIR / "dpkg.log").read_text()

    def test_dpkg_install(self, dpkg_content):
        from app.ingest.linux.packages import parse_packages
        results = parse_packages(dpkg_content, source_path="/var/log/dpkg.log")
        installs = [r for r in results if r.get("action") == "install"]
        assert len(installs) >= 1
        entry = installs[0]
        assert entry["package"] == "nginx:amd64"

    def test_dpkg_upgrade(self, dpkg_content):
        from app.ingest.linux.packages import parse_packages
        results = parse_packages(dpkg_content, source_path="/var/log/dpkg.log")
        upgrades = [r for r in results if r.get("action") == "upgrade"]
        assert len(upgrades) >= 1
        entry = upgrades[0]
        assert "libssl" in entry.get("package", "")

    def test_dpkg_all_lines_parsed(self, dpkg_content):
        from app.ingest.linux.packages import parse_packages
        results = parse_packages(dpkg_content, source_path="/var/log/dpkg.log")
        assert len(results) == 10

    def test_dpkg_timestamps(self, dpkg_content):
        from app.ingest.linux.packages import parse_packages
        results = parse_packages(dpkg_content, source_path="/var/log/dpkg.log")
        with_timestamps = [r for r in results if r["timestamp"] is not None]
        assert len(with_timestamps) >= 1

    def test_dpkg_package_manager_field(self, dpkg_content):
        from app.ingest.linux.packages import parse_packages
        results = parse_packages(dpkg_content, source_path="/var/log/dpkg.log")
        for result in results:
            assert result["package_manager"] == "dpkg"


class TestOSInfoParser:
    @pytest.fixture
    def os_release_content(self):
        return (FIXTURES_DIR / "os-release").read_text()

    @pytest.fixture
    def hostname_content(self):
        return (FIXTURES_DIR / "hostname").read_text()

    def test_os_release_name_and_version(self, os_release_content):
        from app.ingest.linux.os_info import parse_os_info
        results = parse_os_info(os_release_content, source_path="/etc/os-release")
        assert len(results) == 1
        entry = results[0]
        assert entry["os_name"] == "Ubuntu"
        assert "22.04" in entry.get("os_version", "")

    def test_os_release_type(self, os_release_content):
        from app.ingest.linux.os_info import parse_os_info
        results = parse_os_info(os_release_content, source_path="/etc/os-release")
        assert results[0]["artifact_type"] == "os_release"

    def test_hostname_extraction(self, hostname_content):
        from app.ingest.linux.os_info import parse_os_info
        results = parse_os_info(hostname_content, source_path="/etc/hostname")
        assert len(results) == 1
        entry = results[0]
        assert entry["hostname"] == "app-server-prod-01"
        assert entry["detected_host"] == "app-server-prod-01"

    def test_hostname_artifact_type(self, hostname_content):
        from app.ingest.linux.os_info import parse_os_info
        results = parse_os_info(hostname_content, source_path="/etc/hostname")
        assert results[0]["artifact_type"] == "hostname"

    def test_kernel_version_extraction(self):
        from app.ingest.linux.os_info import parse_os_info
        results = parse_os_info(
            "Linux version 5.15.0-91-generic (buildd@lcy02-amd64-101) Ubuntu",
            source_path="/proc/version",
        )
        assert len(results) == 1
        assert results[0]["artifact_type"] == "kernel_version"

    def test_unknown_os_info_fallback(self):
        from app.ingest.linux.os_info import parse_os_info
        results = parse_os_info(
            "Some unknown OS info text",
            source_path="/tmp/some_os_file.txt",
        )
        assert len(results) == 1
        assert results[0]["artifact_type"] == "os_info"


class TestPlatformDetection:
    def test_linux_paths_detected_as_linux(self):
        from app.models.evidence import detect_evidence_platform
        linux_paths = [
            "/var/log/auth.log",
            "/etc/passwd",
            "/home/analyst/.bash_history",
            "/var/log/syslog",
        ]
        platform = detect_evidence_platform(paths=linux_paths)
        assert platform == "linux"

    def test_windows_paths_detected_as_windows(self):
        from app.models.evidence import detect_evidence_platform
        windows_paths = [
            "C:\\Windows\\System32\\winevt\\Logs\\Security.evtx",
        ]
        platform = detect_evidence_platform(paths=windows_paths)
        assert platform == "windows"

    def test_windows_paths_detected_as_windows_forward_slash(self):
        from app.models.evidence import detect_evidence_platform
        windows_paths = [
            "C:/Windows/System32/winevt/Logs/Security.evtx",
        ]
        platform = detect_evidence_platform(paths=windows_paths)
        assert platform == "windows"

    def test_macos_paths_detected(self):
        from app.models.evidence import detect_evidence_platform
        macos_paths = [
            "/Users/jdoe/Library/Preferences/com.apple.finder.plist",
        ]
        platform = detect_evidence_platform(paths=macos_paths)
        assert platform == "macos"

    def test_macos_direct_selection_rejected(self):
        import pytest as pt
        from fastapi import HTTPException
        from app.api.routes_evidence import _resolve_requested_platform
        with pt.raises(HTTPException) as exc_info:
            _resolve_requested_platform("macos", filename="macos_artifacts.zip")
        assert exc_info.value.status_code == 400

    def test_unknown_paths_detected_as_unknown(self):
        from app.models.evidence import detect_evidence_platform
        platform = detect_evidence_platform(paths=["/tmp/some_random.log"])
        assert platform == "unknown"

    def test_lime_memory_detected_as_memory(self):
        from app.models.evidence import detect_evidence_platform
        platform = detect_evidence_platform(paths=["memory.lime"])
        assert platform == "memory"


class TestSecretsAreNeverStored:
    @pytest.fixture
    def authorized_keys_content(self):
        return (FIXTURES_DIR / "authorized_keys").read_text()

    @pytest.fixture
    def shadow_content(self):
        return (FIXTURES_DIR / "shadow").read_text()

    def test_authorized_keys_raw_key_not_in_structured(self, authorized_keys_content):
        from app.ingest.linux.ssh_artifacts import parse_ssh_artifacts
        results = parse_ssh_artifacts(
            authorized_keys_content,
            source_path="/home/analyst/.ssh/authorized_keys",
        )
        for result in results:
            fingerprint = result.get("key_fingerprint", "")
            assert fingerprint.endswith("...") or fingerprint == "[redacted]", \
                f"fingerprint should be redacted, got: {fingerprint}"
            raw = result.get("raw_excerpt", "")
            assert len(raw) > len(fingerprint) or fingerprint == "[redacted]", \
                f"redacted fingerprint should be shorter than raw content"

    def test_shadow_no_hashes_in_message(self, shadow_content):
        from app.ingest.linux.identity import parse_identity
        results = parse_identity(shadow_content, source_path="/etc/shadow")
        entry = results[0]
        assert entry["artifact_type"] == "shadow"
        message = entry.get("message", "")
        assert "6$" not in message
        assert "hashes not stored" in entry.get("message", "")
        username_field = entry.get("username", "")
        assert "$" not in username_field


class TestArtifactMarkerMatching:
    """Filename-scoped markers must match the basename, not any substring of
    the full path — otherwise unrelated dependency files (venvs, node_modules,
    site-packages) that happen to contain a marker word get misclassified as
    forensic artifacts and fed to the wrong parser."""

    def test_python_protobuf_file_not_misclassified_as_syslog(self):
        from app.ingest.linux.helpers import looks_like_linux_artifact
        path = "home/user/.venv/lib/python3.12/site-packages/google/protobuf/more_messages_pb2.py"
        assert looks_like_linux_artifact(path) is None

    def test_group_helper_module_not_misclassified_as_identity(self):
        from app.ingest.linux.helpers import looks_like_linux_artifact
        path = "home/user/.venv/lib/python3.12/site-packages/somepkg/group_utils.py"
        assert looks_like_linux_artifact(path) is None

    def test_exact_basename_still_matches(self):
        from app.ingest.linux.helpers import looks_like_linux_artifact
        assert looks_like_linux_artifact("var/log/messages") == ("linux_syslog", "syslog", "linux_syslog_raw")
        assert looks_like_linux_artifact("etc/passwd") == ("linux_identity", "passwd", "linux_identity_raw")
        assert looks_like_linux_artifact("etc/group") == ("linux_identity", "group", "linux_identity_raw")

    def test_rotated_log_suffix_still_matches(self):
        from app.ingest.linux.helpers import looks_like_linux_artifact
        assert looks_like_linux_artifact("var/log/messages.1") is not None
        assert looks_like_linux_artifact("var/log/messages-20230101") is not None
        assert looks_like_linux_artifact("var/log/auth.log.1") is not None

    def test_directory_scoped_marker_still_matches(self):
        from app.ingest.linux.helpers import looks_like_linux_artifact
        assert looks_like_linux_artifact("etc/cron.d/backup") is not None
        assert looks_like_linux_artifact("var/lib/dpkg/status") is not None


class TestKapeArtifactExclusions:
    def test_site_packages_and_venv_dirs_pruned(self, tmp_path):
        from app.ingest.kape import list_kape_artifacts
        noisy = tmp_path / ".venv" / "lib" / "site-packages" / "google" / "protobuf"
        noisy.mkdir(parents=True)
        (noisy / "more_messages_pb2.py").write_text("# generated\n")
        real_log = tmp_path / "var" / "log"
        real_log.mkdir(parents=True)
        (real_log / "syslog").write_text("Jan 1 00:00:00 host kernel: boot\n")
        artifacts = list_kape_artifacts(tmp_path)
        names = {a["name"] for a in artifacts}
        assert "more_messages_pb2.py" not in names
        assert "syslog" in names
