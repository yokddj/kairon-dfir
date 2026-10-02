"""fail2ban log parser. Addresses are documentation ranges; jails and hosts are invented."""
from __future__ import annotations

from unittest.mock import MagicMock

import pytest

from app.core import opensearch as os_module
from app.ingest.artifact_normalizers import normalize_linux_row
from app.ingest.linux.dispatch import parse_linux_artifact_file
from app.ingest.linux.fail2ban import parse_fail2ban
from app.ingest.linux.helpers import looks_like_linux_artifact
from app.ingest.normalizer import base_document

LOG = """\
2024-03-01 10:20:30,123 fail2ban.filter         [1234]: INFO    [sshd] Found 203.0.113.9 - 2024-03-01 10:20:29
2024-03-01 10:20:31,456 fail2ban.actions        [1234]: NOTICE  [sshd] Ban 203.0.113.9
2024-03-01 10:50:31,456 fail2ban.actions        [1234]: NOTICE  [sshd] Unban 203.0.113.9
2024-03-01 10:51:00,000 fail2ban.actions        [1234]: NOTICE  [nginx-botsearch] Restore Ban 2001:db8::5
2024-03-01 10:51:01,000 fail2ban.actions        [1234]: WARNING [sshd] 198.51.100.7 already banned
2024-03-01 10:00:00,000 fail2ban.jail           [1234]: INFO    Jail 'sshd' started
2024-03-01 10:59:00,000 fail2ban.jail           [1234]: INFO    Jail 'sshd' stopped
2024-03-01 09:00:00,500 fail2ban.actions: WARNING [ssh] Ban 192.0.2.99
"""


def _rows() -> dict[str, list[dict]]:
    grouped: dict[str, list[dict]] = {}
    for row in parse_fail2ban(LOG, source_path="var/log/fail2ban.log"):
        grouped.setdefault(row["event_action"], []).append(row)
    return grouped


def _doc(row: dict) -> dict:
    base = base_document("case-1", "ev-1", "art-1", row, {"artifact_type": row["artifact_family"]})
    return normalize_linux_row(base, row, source_path=row["source_file"], artifact_type=row["artifact_family"])


@pytest.mark.parametrize("path", ["var/log/fail2ban.log", "var/log/fail2ban.log.1", "var/log/fail2ban.log.3.gz", "triage/h1/var/log/fail2ban.log"])
def test_fail2ban_logs_are_detected(path):
    assert looks_like_linux_artifact(path) == ("linux_fail2ban", "fail2ban_log", "linux_fail2ban_raw")


def test_a_found_line_carries_the_attacker_not_the_event_time():
    found = _rows()["found"][0]
    assert found["source_ip"] == "203.0.113.9" and found["jail"] == "sshd"
    assert found["timestamp"] == "2024-03-01T10:20:30.123000+00:00"  # when fail2ban logged it
    assert found["severity"] == "info" and found["pid"] == 1234 and found["component"] == "fail2ban.filter"


def test_ban_unban_and_restore():
    grouped = _rows()
    ban = [r for r in grouped["ban"] if r["jail"] == "sshd"][0]
    assert (ban["source_ip"], ban["severity"], ban["timestamp_status"]) == ("203.0.113.9", "notice", "assumed_utc")
    assert grouped["unban"][0]["source_ip"] == "203.0.113.9"
    restored = grouped["restore_ban"][0]
    assert restored["source_ip"] == "2001:db8::5" and restored["jail"] == "nginx-botsearch"


def test_already_banned_is_not_a_new_ban():
    row = _rows()["already_banned"][0]
    assert row["source_ip"] == "198.51.100.7" and row["severity"] == "warning"


def test_jail_lifecycle_has_no_address():
    grouped = _rows()
    assert (grouped["jail_started"][0]["jail"], grouped["jail_started"][0].get("source_ip")) == ("sshd", None)
    assert grouped["jail_stopped"][0]["jail"] == "sshd"


def test_older_format_without_a_pid_still_parses():
    old = [r for r in _rows()["ban"] if r["jail"] == "ssh"][0]
    assert old["source_ip"] == "192.0.2.99" and old["pid"] is None
    assert old["timestamp"] == "2024-03-01T09:00:00.500000+00:00"


def test_unrecognised_lines_are_kept_undated():
    rows = parse_fail2ban("something unrelated\n\n2024-03-01 10:00:00,000 other.thing: INFO nope\n", source_path="var/log/fail2ban.log")
    assert len(rows) == 2
    assert all(r["timestamp"] is None and r["timestamp_status"] == "missing" for r in rows)
    assert rows[0]["message"] == "something unrelated"


def test_a_time_is_not_mistaken_for_an_address():
    row = parse_fail2ban("2024-03-01 10:00:00,000 fail2ban.filter [1]: INFO [sshd] Found - 2024-03-01 10:20:29\n", source_path="x")[0]
    assert row.get("source_ip") is None


def test_dispatch_reads_a_compressed_rotated_log(tmp_path):
    import gzip

    path = tmp_path / "fail2ban.log.2.gz"
    path.write_bytes(gzip.compress(LOG.encode()))
    rows = parse_linux_artifact_file(path, parser="linux_fail2ban_raw", artifact_type="fail2ban_log", source_path="var/log/fail2ban.log.2.gz")
    assert len(rows) == 8 and rows[1]["event_action"] == "ban"


def test_ban_normalizes_to_network_and_a_readable_title():
    doc = _doc(_rows()["ban"][0])
    assert doc["event"]["type"] == "fail2ban" and doc["event"]["action"] == "fail2ban_ban"
    assert doc["network"]["source_ip"] == "203.0.113.9"
    assert doc["title"] == "fail2ban ban: 203.0.113.9 [sshd]"
    assert doc["linux"]["jail"] == "sshd" and doc["linux"]["timestamp_status"] == "assumed_utc"
    assert doc["@timestamp"].startswith("2024-03-01T10:20:31")


def test_lifecycle_title_without_an_address():
    assert _doc(_rows()["jail_started"][0])["title"] == "fail2ban jail started [sshd]"


@pytest.mark.parametrize("exists", [False, True], ids=["new-index", "existing-index-backfill"])
def test_jail_is_declared_in_the_index_mapping(monkeypatch, exists):
    client = MagicMock()
    monkeypatch.setattr(os_module, "get_opensearch_client", lambda **_: client)
    monkeypatch.setattr(os_module, "index_exists", lambda *_a, **_k: exists)
    monkeypatch.setattr(os_module, "_apply_safe_index_settings", lambda *_a, **_k: None, raising=False)
    os_module.ensure_case_index("11111111-1111-4111-8111-111111111111")
    call = client.indices.put_mapping if exists else client.indices.create
    body = call.call_args.kwargs["body"]
    assert "jail" in body.get("mappings", body)["properties"]["linux"]["properties"]


def test_registry_and_inventory_know_fail2ban():
    from app.core.artifact_registry import ARTIFACT_REGISTRY  # type: ignore[attr-defined]
    from app.ingest.linux.discovery import build_linux_inventory
    from pathlib import Path

    assert ARTIFACT_REGISTRY["linux_fail2ban"]["parser"] == "linux_fail2ban_raw"
    inventory = build_linux_inventory(Path("."), ["var/log/fail2ban.log"])
    assert [i["key"] for i in inventory["detected_artifacts"]] == ["fail2ban"]
