from datetime import UTC, datetime
from types import SimpleNamespace

from app.api.routes_evidence import _capture_reingest_baseline


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
