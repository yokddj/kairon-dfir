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
