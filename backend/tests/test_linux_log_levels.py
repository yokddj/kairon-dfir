"""Log level -> severity, and the journal fields that must reach the indexed document."""
from __future__ import annotations

import gzip
from pathlib import Path
from unittest.mock import MagicMock

import pytest

from app.core import opensearch as os_module
from app.ingest.artifact_normalizers import _log_level_severity, normalize_linux_row
from app.ingest.linux.fail2ban import parse_fail2ban
from app.ingest.linux.generic_log import parse_generic_log
from app.ingest.linux.journal import parse_journal_binary_file, _row_from_fields
from app.ingest.linux.syslog import parse_syslog
from app.ingest.normalizer import base_document

FIXTURE = Path(__file__).parent / "fixtures" / "journal" / "debian_12.journal.gz"


def _doc(row: dict, source: str = "") -> dict:
    base = base_document("case-1", "ev-1", "art-1", row, {"artifact_type": row["artifact_family"]})
    return normalize_linux_row(base, row, source_path=source or row.get("source_file") or row.get("source_path", ""), artifact_type=row["artifact_family"])


@pytest.mark.parametrize(
    "value, expected",
    [
        ("0", "high"), ("1", "high"), ("2", "high"), (3, "medium"), ("3", "medium"), ("4", "low"), ("5", "info"), ("6", "info"), (7, "info"),
        ("emerg", "high"), ("ALERT", "high"), ("crit", "high"), ("Critical", "high"), ("fatal", "high"),
        ("err", "medium"), ("error", "medium"), ("warn", "low"), ("WARNING", "low"),
        ("notice", "info"), ("info", "info"), ("debug", "info"),
        ("auth.err", "medium"), ("kern.crit", "high"), ("daemon.warning", "low"), ("user.notice", "info"),
        ("", None), (None, None), ("banana", None), ("9", None),
    ],
)
def test_level_mapping(value, expected):
    assert _log_level_severity(value) == expected


def test_a_journal_error_is_no_longer_shown_as_info():
    error = _doc(_row_from_fields({"MESSAGE": "disk failure", "PRIORITY": "3", "SYSLOG_IDENTIFIER": "kernel", "__REALTIME_TIMESTAMP": "1709288430123456"}, "j.export"))
    routine = _doc(_row_from_fields({"MESSAGE": "started", "PRIORITY": "6", "SYSLOG_IDENTIFIER": "app", "__REALTIME_TIMESTAMP": "1709288430123456"}, "j.export"))
    assert (error["event"]["severity"], routine["event"]["severity"]) == ("medium", "info")


def test_syslog_facility_level_tag_sets_the_severity():
    rows = parse_syslog("Mar  1 10:20:30 <auth.err> h sshd[1]: bad thing happened", source_path="var/log/syslog")
    assert _doc(rows[0])["event"]["severity"] == "medium"


def test_generic_log_level_words_set_the_severity():
    rows = parse_generic_log("2024-03-01T10:20:30Z ERROR boom\n2024-03-01T10:20:31Z INFO fine\n", source_path="var/log/app.log")
    assert [_doc(r)["event"]["severity"] for r in rows] == ["medium", "info"]


def test_fail2ban_levels():
    rows = parse_fail2ban("2024-03-01 10:20:30,123 fail2ban.actions [1]: WARNING [sshd] 198.51.100.7 already banned\n2024-03-01 10:20:31,000 fail2ban.actions [1]: NOTICE [sshd] Ban 203.0.113.9\n", source_path="var/log/fail2ban.log")
    assert [_doc(r)["event"]["severity"] for r in rows] == ["low", "info"]


def test_rows_without_a_level_keep_the_previous_default():
    row = parse_syslog("Mar  1 10:20:30 h cron[1]: (root) CMD (run-parts /etc/cron.hourly)", source_path="var/log/syslog")[0]
    assert _doc(row)["event"]["severity"] == "info"


# ------------------------------------------------------------ journal fields

@pytest.fixture()
def journal_doc(tmp_path):
    path = tmp_path / "system.journal"
    path.write_bytes(gzip.decompress(FIXTURE.read_bytes()))
    row = parse_journal_binary_file(path, source_path="var/log/journal/abc/system.journal")[0]
    return _doc(row)


def test_unit_transport_boot_and_sequence_reach_the_document(journal_doc):
    linux = journal_doc["linux"]
    assert linux["unit"] == "ssh.service" and linux["transport"] == "syslog"
    assert linux["boot_id"] == "0123456789abcdef0123456789abcdef" and linux["seqnum"] == 1
    assert linux["exe"] == "/usr/sbin/sshd"


def test_the_journal_priority_reaches_the_event(journal_doc):
    assert journal_doc["event"]["severity"] == "info"  # PRIORITY 6 in the fixture's first entry


def test_a_numeric_uid_is_not_shown_as_a_user_name(tmp_path):
    path = tmp_path / "system.journal"
    path.write_bytes(gzip.decompress(FIXTURE.read_bytes()))
    docs = [_doc(r) for r in parse_journal_binary_file(path, source_path="var/log/journal/abc/system.journal") if r.get("uid")]
    by_uid = {d["user"]["id"]: d["user"].get("name") for d in docs}
    assert by_uid["0"] == "root"
    assert by_uid["1000"] is None and by_uid["1001"] is None


@pytest.mark.parametrize("exists", [False, True], ids=["new-index", "existing-index-backfill"])
def test_journal_fields_are_declared_in_the_index_mapping(monkeypatch, exists):
    client = MagicMock()
    monkeypatch.setattr(os_module, "get_opensearch_client", lambda **_: client)
    monkeypatch.setattr(os_module, "index_exists", lambda *_a, **_k: exists)
    monkeypatch.setattr(os_module, "_apply_safe_index_settings", lambda *_a, **_k: None, raising=False)
    os_module.ensure_case_index("11111111-1111-4111-8111-111111111111")
    call = client.indices.put_mapping if exists else client.indices.create
    body = call.call_args.kwargs["body"]
    assert {"unit", "transport", "boot_id", "seqnum"} <= set(body.get("mappings", body)["properties"]["linux"]["properties"])
