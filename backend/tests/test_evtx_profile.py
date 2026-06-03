from types import SimpleNamespace

from app.services.evtx_profile import apply_evtx_profile_to_selection, is_high_value_evtx_candidate
from app.services.ingest_plan import build_plan
from app.services.problematic_artifacts import build_problematic_artifacts_report
from app.ingest.raw_parsers.evtx_parser import EvtxRawParser


def _candidate(candidate_id: str, path: str) -> dict:
    return {
        "id": candidate_id,
        "original_path": path,
        "artifact_type": "windows_event",
        "parser": "evtx_raw",
        "supported": True,
        "category": "evtx",
    }


def _evidence() -> SimpleNamespace:
    return SimpleNamespace(id="ev-1", case_id="case-1", stored_path="/tmp/collection.zip", storage_mode=None, evidence_type="velociraptor_zip")


def test_usable_search_many_evtx_defaults_to_full_evtx_backend() -> None:
    candidates = [_candidate("security", "Windows/System32/winevt/Logs/Security.evtx")]
    candidates.extend(_candidate(f"noise-{index}", f"Windows/System32/winevt/Logs/Noise-{index}.evtx") for index in range(25))
    metadata = {"ingest_mode": "usable_search", "velociraptor_discovery": {"candidates": candidates}}

    plan = build_plan(
        _evidence(),
        metadata,
        discovery_mode="updated_discovery",
        selected_candidate_ids=[candidate["id"] for candidate in candidates],
        selected_reason="recommended",
    )

    assert plan["evtx_profile"] == "full"
    assert {item["candidate_id"] for item in plan["selected_candidates"]} == {candidate["id"] for candidate in candidates}
    assert plan["evtx_deferred_count"] == 0


def test_plan_persists_requested_evtx_parser_backend() -> None:
    candidates = [_candidate("security", "Windows/System32/winevt/Logs/Security.evtx")]
    metadata = {"ingest_mode": "usable_search", "velociraptor_discovery": {"candidates": candidates}}

    plan = build_plan(
        _evidence(),
        metadata,
        discovery_mode="updated_discovery",
        selected_candidate_ids=["security"],
        parser_options={"ingest_mode": "usable_search", "evtx_profile": "full", "evtx_parser_backend": "evtxecmd_csv"},
    )

    assert plan["evtx_parser_backend"] == "evtxecmd_csv"
    assert plan["parser_options"]["evtx_parser_backend"] == "evtxecmd_csv"


def test_full_forensic_defaults_to_full_evtx_without_profile_deferrals() -> None:
    candidates = [_candidate("security", "Security.evtx"), _candidate("noise", "Noise.evtx")]
    metadata = {"ingest_mode": "full_forensic", "velociraptor_discovery": {"candidates": candidates}}

    plan = build_plan(
        _evidence(),
        metadata,
        discovery_mode="updated_discovery",
        selected_candidate_ids=[candidate["id"] for candidate in candidates],
    )

    assert plan["evtx_profile"] == "full"
    assert plan["evtx_deferred_count"] == 0
    assert {item["candidate_id"] for item in plan["selected_candidates"]} == {"security", "noise"}


def test_fast_profile_matches_high_value_channels_and_encoded_paths() -> None:
    assert is_high_value_evtx_candidate(_candidate("ps", "Windows/System32/winevt/Logs/Microsoft-Windows-PowerShell%254Operational.evtx"))
    assert is_high_value_evtx_candidate(_candidate("sysmon", "Windows/System32/winevt/Logs/Microsoft-Windows-Sysmon%4Operational.evtx"))
    assert is_high_value_evtx_candidate(_candidate("system", "Windows/System32/winevt/Logs/System.evtx"))


def test_deferred_evtx_appears_in_problematic_report_and_debug_source() -> None:
    evidence = _evidence()
    evidence.metadata_json = {
        "evtx_deferred_files": [
            {
                "artifact_id": "noise",
                "path": "Windows/System32/winevt/Logs/Noise.evtx",
                "artifact_type": "windows_event",
                "reason": "evtx_profile_deferred",
                "profile": "fast_high_value",
                "can_run_later": True,
                "suggested_action": "Run Full EVTX indexing / Deep retry",
            }
        ]
    }

    report = build_problematic_artifacts_report(evidence, {"artifacts": [], "errors": []})

    assert report["summary"]["evtx_profile_deferred"] == 1
    assert report["items"][0]["status"] == "deferred_evtx_profile"
    assert report["items"][0]["suggested_primary_action"] == "Run Full EVTX indexing / Deep retry"


def test_partial_evtx_appears_in_problematic_report() -> None:
    evidence = _evidence()
    evidence.metadata_json = {
        "evtx_partial_files": [
            {
                "artifact_id": "security",
                "file": "Security.evtx",
                "path": "Windows/System32/winevt/Logs/Security.evtx",
                "reason": "max_records_per_file",
                "records_read": 5000,
                "records_indexed": 5000,
                "can_continue_later": True,
            }
        ]
    }

    report = build_problematic_artifacts_report(evidence, {"artifacts": [], "errors": []})

    assert report["summary"]["evtx_profile_partial"] == 1
    assert report["items"][0]["status"] == "partial_evtx_profile"
    assert report["items"][0]["effective_resolution"] == "evtx_profile_partial"


def test_fast_profile_keeps_selected_evtx_as_windows_event_candidates() -> None:
    candidates = [_candidate("security", "Security.evtx"), _candidate("application", "Application.evtx"), _candidate("noise", "Noise.evtx")]
    result = apply_evtx_profile_to_selection(
        candidates,
        [candidate["id"] for candidate in candidates],
        ingest_mode="usable_search",
        requested_profile="fast_high_value",
    )

    assert result["evtx_profile"] == "fast_high_value"
    assert result["selected_candidate_ids"] == ["application", "security"]
    assert result["evtx_deferred_count"] == 1


def _xml_record(record_id: int) -> str:
    return f"""
    <Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
      <System>
        <Provider Name="Microsoft-Windows-Security-Auditing" />
        <EventID>4624</EventID>
        <Channel>Security</Channel>
        <Computer>HOST1</Computer>
        <EventRecordID>{record_id}</EventRecordID>
        <TimeCreated SystemTime="2026-05-28T10:00:00Z" />
      </System>
      <EventData><Data Name="TargetUserName">alex</Data></EventData>
    </Event>
    """


def test_fast_evtx_parser_applies_max_records_per_file(monkeypatch, tmp_path) -> None:
    import app.ingest.raw_parsers.evtx_parser as evtx_parser

    def fake_records(path, *, record_timeout_seconds=None):  # noqa: ARG001
        for index in range(1, 8):
            yield index, _xml_record(index), None

    monkeypatch.setattr(evtx_parser, "iter_evtx_xml_record_results", fake_records)
    path = tmp_path / "Security.evtx"
    path.write_bytes(b"Evtx")

    results = list(
        EvtxRawParser().iter_batches(
            path,
            case_id="case-1",
            evidence_id="ev-1",
            artifact_id="art-1",
            artifact_meta={"source_path": "Security.evtx"},
            batch_size=10,
            max_records=3,
        )
    )

    final = results[-1]
    assert final.parser_status == "partial"
    assert final.records_read == 3
    assert len(final.events) == 3
    assert final.metadata["limit_reason"] == "max_records_per_file"


def test_full_evtx_parser_has_no_fast_limit(monkeypatch, tmp_path) -> None:
    import app.ingest.raw_parsers.evtx_parser as evtx_parser

    def fake_records(path, *, record_timeout_seconds=None):  # noqa: ARG001
        for index in range(1, 8):
            yield index, _xml_record(index), None

    monkeypatch.setattr(evtx_parser, "iter_evtx_xml_record_results", fake_records)
    path = tmp_path / "Security.evtx"
    path.write_bytes(b"Evtx")

    results = list(
        EvtxRawParser().iter_batches(
            path,
            case_id="case-1",
            evidence_id="ev-1",
            artifact_id="art-1",
            artifact_meta={"source_path": "Security.evtx"},
            batch_size=10,
        )
    )

    final = results[-1]
    assert final.parser_status == "parsed_native"
    assert final.records_read == 7
    assert len(final.events) == 7
