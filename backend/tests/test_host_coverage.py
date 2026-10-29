from __future__ import annotations

from app.services import host_coverage


def _hosts():
    return [
        {"id": "h-ws01", "canonical_name": "ws01", "display_name": "WS01", "all_names": ["ws01"], "event_count": 361643},
        {"id": "h-srv01", "canonical_name": "srv01", "display_name": "SRV01", "all_names": ["srv01"], "event_count": 14364},
    ]


def test_flags_a_host_missing_a_family_its_peers_have(monkeypatch) -> None:
    """Reproduces the real gap that cost an investigation two answers: SRV01
    ingested cleanly, reported no error, and simply had no filesystem data
    while every other host had hundreds of thousands of entries."""
    monkeypatch.setattr(host_coverage, "get_case_hosts", lambda db, case_id: _hosts())
    monkeypatch.setattr(
        host_coverage,
        "_artifact_type_counts_by_host",
        lambda case_id: {
            "ws01": {"mft": 283494, "windows_event": 40000, "powershell": 500},
            "srv01": {"windows_event": 4861, "powershell": 1786},  # sin MFT
        },
    )

    result = host_coverage.build_case_host_coverage(None, "case-1")
    srv01 = next(row for row in result["hosts"] if row["host"] == "SRV01")

    assert "Filesystem (MFT)" in srv01["missing_families"]
    assert "Filesystem (MFT)" in srv01["missing_critical_families"]
    assert any("SRV01" in warning and "Filesystem" in warning for warning in result["warnings"])

    ws01 = next(row for row in result["hosts"] if row["host"] == "WS01")
    assert ws01["missing_families"] == []


def test_does_not_flag_a_family_no_host_in_the_case_has(monkeypatch) -> None:
    """Only families some peer actually produced count as expected. Otherwise
    every server without a browser profile would raise a permanent false alarm
    and the signal would be ignored."""
    monkeypatch.setattr(host_coverage, "get_case_hosts", lambda db, case_id: _hosts())
    monkeypatch.setattr(
        host_coverage,
        "_artifact_type_counts_by_host",
        lambda case_id: {
            "ws01": {"mft": 10, "windows_event": 10},
            "srv01": {"mft": 10, "windows_event": 10},
        },
    )

    result = host_coverage.build_case_host_coverage(None, "case-1")

    assert result["warnings"] == []
    for row in result["hosts"]:
        assert row["missing_families"] == []
    assert "Browser" not in result["expected_families"]


def test_host_aliases_are_merged_before_deciding_a_family_is_missing(monkeypatch) -> None:
    """Counts arrive keyed by the raw host.name in the documents. If aliases
    were not merged, a host indexed as both HOSTA and hosta.corp.local would
    look like it is missing data it actually has."""
    monkeypatch.setattr(
        host_coverage,
        "get_case_hosts",
        lambda db, case_id: [
            {"id": "h-1", "canonical_name": "hosta", "display_name": "HOSTA",
             "all_names": ["hosta", "hosta.corp.local"], "event_count": 10}
        ],
    )
    monkeypatch.setattr(
        host_coverage,
        "_artifact_type_counts_by_host",
        lambda case_id: {"hosta.corp.local": {"mft": 5000}, "hosta": {"windows_event": 20}},
    )

    result = host_coverage.build_case_host_coverage(None, "case-1")
    row = result["hosts"][0]

    assert row["families"]["Filesystem (MFT)"] == 5000
    assert row["missing_families"] == []


def test_flags_a_host_without_process_creation_records_its_peers_have(monkeypatch) -> None:
    """A host can ingest event logs and still have no record of which processes
    ran (no Sysmon / process auditing). Telemetry is matched by event type, so
    it reads the same for Windows and Linux hosts."""
    hosts = [
        {"id": "h-a", "canonical_name": "a", "display_name": "A", "all_names": ["a"], "event_count": 10},
        {"id": "h-b", "canonical_name": "b", "display_name": "B", "all_names": ["b"], "event_count": 10},
        {"id": "h-c", "canonical_name": "c", "display_name": "C", "all_names": ["c"], "event_count": 10},
    ]
    monkeypatch.setattr(host_coverage, "get_case_hosts", lambda db, case_id: hosts)
    monkeypatch.setattr(
        host_coverage,
        "_artifact_type_counts_by_host",
        lambda case_id: {
            "a": {"windows_event": 50, "event:sysmon_process_created": 20, "event:logon_success": 5},
            "b": {"windows_event": 50, "event:logon_success": 5},  # event logs, no process creation
            "c": {"linux_auth": 9, "event:execve": 3, "event:login_success": 2},
        },
    )

    result = host_coverage.build_case_host_coverage(None, "case-1")
    by_host = {row["host"]: row for row in result["hosts"]}

    assert "Process creation log" in by_host["B"]["missing_critical_families"]
    assert "Process creation log" not in by_host["C"]["missing_families"]  # auditd execve counts
    assert "Logon records" not in by_host["C"]["missing_families"]
    assert any(warning.startswith("B ") and "Process creation log" in warning for warning in result["warnings"])


def test_reports_log_clears_and_when_process_records_begin(monkeypatch) -> None:
    """A host whose logs were cleared has no record of what happened before:
    the coverage says when, by whom, and from when its records start."""
    hosts = [{"id": "h-a", "canonical_name": "a", "display_name": "A", "all_names": ["a"], "event_count": 10}]
    monkeypatch.setattr(host_coverage, "get_case_hosts", lambda db, case_id: hosts)
    monkeypatch.setattr(
        host_coverage,
        "_artifact_type_counts_by_host",
        lambda case_id: {"a": {
            "windows_event": 5, "event:sysmon_process_created": 3, "first:sysmon_process_created": "2024-03-22T12:45:12.060Z",
            "log_clears": [
                {"@timestamp": "2024-03-22T12:45:25Z", "windows": {"channel": "Security", "event_data": {"SubjectUserName": "admin", "SubjectDomainName": "CORP"}}},
                {"@timestamp": "2024-03-22T12:45:26Z", "windows": {"channel": "System", "event_data": {"Channel": "System"}}},
            ],
        }},
    )

    result = host_coverage.build_case_host_coverage(None, "case-1")
    row = result["hosts"][0]

    assert row["telemetry_first_seen"]["Process creation log"] == "2024-03-22T12:45:12.060Z"
    assert [clear["user"] for clear in row["log_clears"]] == ["CORP\\admin", None]
    assert result["warnings"] == [
        "A: event logs were cleared 2024-03-22 12:45:25 to 2024-03-22 12:45:26 by CORP\\admin (2 records). "
        "Activity on this host before then is missing from those logs; its process creation records begin 2024-03-22 12:45:12."
    ]
