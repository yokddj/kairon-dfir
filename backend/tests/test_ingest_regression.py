from datetime import UTC, datetime
from types import SimpleNamespace

from app.api.routes_evidence import _capture_reingest_baseline
from app.schemas.debug_export import DebugExportRequest
from app.services.debug_export import (
    _DebugPackContext,
    _FetchedEvents,
    _build_debug_export_scope_report,
    _build_ingest_regression_report,
)


def test_capture_reingest_baseline_uses_previous_manifest_stats() -> None:
    evidence = SimpleNamespace(
        id="ev-1",
        case_id="case-1",
        updated_at=datetime(2026, 5, 18, tzinfo=UTC),
        detected_host="movistar-pc",
    )
    existing_metadata = {
        "selected_candidates": 877,
        "selected_files_total": 883,
        "selected_files_extracted": 883,
        "candidate_files": 1196,
        "source_type": "velociraptor_collection",
    }
    previous_manifest = {
        "stats": {
            "indexed_events": 98359,
            "detected_artifacts": 877,
            "results_artifacts_parsed": 877,
            "raw_artifacts_parsed": 577,
            "failed_artifacts": 0,
        },
        "artifacts": [
            {"artifact_type": "windows_event", "parser": "evtx_raw", "ingest_audit": {"events_indexed": 96000}},
            {"artifact_type": "amcache", "parser": "amcache_raw", "ingest_audit": {"events_indexed": 900}},
        ],
    }

    baseline = _capture_reingest_baseline(evidence, existing_metadata, previous_manifest)

    assert baseline["expected_events_baseline"] == 98359
    assert baseline["selected_candidates"] == 877
    assert baseline["by_parser"]["evtx_raw"] == 96000
    assert baseline["by_artifact_type"]["windows_event"] == 96000


def test_build_ingest_regression_report_reports_baseline_delta() -> None:
    case = SimpleNamespace(id="case-1")
    evidence = SimpleNamespace(
        id="ev-1",
        metadata_json={
            "reingest_baseline": {
                "expected_events_baseline": 98359,
                "selected_candidates": 877,
                "selected_files_total": 883,
            },
        },
    )
    context = _DebugPackContext(case=case, evidences=[evidence], request=DebugExportRequest(scope="evidence", evidence_id="ev-1"), export_timestamp=datetime.now(UTC))
    manifests = {
        "ev-1": {
            "stats": {"total_files": 3130, "processed_files": 883},
        }
    }
    parser_audit = [
        {
            "evidence_id": "ev-1",
            "artifact_type": "windows_event",
            "parser_name": "evtx_raw",
            "events_indexed": 97712,
            "records_read": 98000,
            "records_parsed": 97712,
            "records_failed": 0,
            "source_file": "System.evtx",
        }
    ]
    ingest_summary = [
        {
            "evidence_id": "ev-1",
            "status": "completed",
            "indexed_events": 97712,
            "artifacts_parseable": 877,
            "artifacts_parsed": 1454,
            "artifacts_failed": 0,
            "artifacts_selected": 877,
            "files_extracted": 883,
            "storage_mode": "uploaded",
            "parser_errors": [],
            "bulk_index_errors": [],
        }
    ]

    report = _build_ingest_regression_report(
        context,
        manifests=manifests,
        parser_audit=parser_audit,
        ingest_summary=ingest_summary,
        host_attribution_report={"primary_host": "movistar-pc"},
    )

    assert report["expected_events_baseline"] == 98359
    assert report["current_events_indexed"] == 97712
    assert report["delta"] == -647
    assert "events_below_baseline" in report["warnings"]
    assert "baseline_delta_unexplained_requires_family_comparison" in report["suspected_regression_causes"]


def test_scope_report_includes_ingest_regression_summary() -> None:
    context = _DebugPackContext(
        case=SimpleNamespace(id="case-1"),
        evidences=[SimpleNamespace(id="ev-1")],
        request=DebugExportRequest(scope="evidence", evidence_id="ev-1"),
        export_timestamp=datetime.now(UTC),
    )
    report = _build_debug_export_scope_report(
        context,
        manifests={"ev-1": {"artifacts": []}},
        parser_audit=[],
        discovery_candidates=[],
        ingest_summary=[{"indexed_events": 10, "opensearch_bulk": {}, "opensearch_refresh": {}, "performance_profile": "balanced", "performance_settings": {}}],
        fetched_events=_FetchedEvents(sampled_events=[], total_events=10, evtx_classification_sample=[]),
        selected_artifact_types=[],
        host_attribution_report={"primary_host": "movistar-pc", "primary_host_source": "evtx_computer", "primary_host_confidence": "high", "hosts_accepted": [{"host": "movistar-pc"}], "host_alias_candidates": [], "host_candidates_rejected": []},
        ingest_regression_report={"expected_events_baseline": 12, "current_events_indexed": 10, "delta": -2, "status": "completed", "artifacts_failed": 0, "suspected_regression_causes": ["baseline_delta_unexplained_requires_family_comparison"]},
    )

    assert report["ingest_regression_summary"]["delta"] == -2
    assert report["ingest_regression_summary"]["current_events_indexed"] == 10
