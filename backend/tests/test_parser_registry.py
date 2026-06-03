from app.services.parser_registry import (
    build_indexed_field_coverage_by_artifact_type,
    build_parser_coverage_matrix,
    build_parser_registry_report,
    build_searchable_contract_report,
    get_parser_registry,
    get_searchable_document_contract,
)
from app.ingest.normalizer import base_document
from app.api.routes_evidence import _build_evidence_search_summary
from types import SimpleNamespace


def _sample_windows_event() -> dict:
    return {
        "case_id": "case-1",
        "evidence_id": "evidence-1",
        "source_file": "Security.evtx",
        "ingest_run_id": "run-1",
        "@timestamp": "2026-05-26T10:00:00Z",
        "artifact": {"type": "windows_event", "parser": "evtx_raw"},
        "host": {"name": "HOSTA"},
        "user": {"name": "bob"},
        "windows": {"event_id": 4624},
        "event": {"message": "Logon", "category": "authentication"},
    }


def _sample_browser_event() -> dict:
    return {
        "case_id": "case-1",
        "evidence_id": "evidence-1",
        "source_file": "History",
        "ingest_run_id": "run-1",
        "@timestamp": "2026-05-26T10:05:00Z",
        "artifact": {"type": "browser", "parser": "browser_chromium_history"},
        "browser": {"url": "https://example.com", "domain": "example.com", "profile": "Default"},
        "title": "Example Domain",
    }


def test_parser_registry_contains_core_entries() -> None:
    registry = get_parser_registry()
    for artifact_type in ("windows_event", "browser", "prefetch", "scheduled_task", "jumplist", "amcache", "shimcache", "powershell"):
        assert artifact_type in registry
        entry = registry[artifact_type]
        assert entry["artifact_type"] == artifact_type
        assert entry["parser_name"]
        assert entry["maturity"] in {"stable", "beta", "experimental", "disabled"}
        assert entry["output_contract_version"] == "v1"


def test_searchable_document_contract_has_minimum_fields() -> None:
    contract = get_searchable_document_contract()
    assert contract["version"] == "v1"
    for field in ("evidence_id", "case_id", "artifact.type", "artifact.parser", "source_file", "ingest_run_id"):
        assert field in contract["required_fields"]


def test_searchable_contract_report_marks_pass_and_partial() -> None:
    artifacts = [
        {"artifact_type": "windows_event", "parser": "evtx_raw", "status": "completed", "source_path": "Security.evtx"},
        {"artifact_type": "browser", "parser": "browser_chromium_history", "status": "completed", "source_path": "History"},
    ]
    report = build_searchable_contract_report(
        artifacts=artifacts,
        sampled_events=[_sample_windows_event(), _sample_browser_event(), {"artifact": {"type": "browser", "parser": "browser_chromium_history"}}],
    )
    by_type = {item["artifact_type"]: item for item in report["artifact_types"]}
    assert by_type["windows_event"]["contract_status"] == "pass"
    assert by_type["browser"]["contract_status"] == "partial"


def test_indexed_field_coverage_by_artifact_type_tracks_presence() -> None:
    coverage = build_indexed_field_coverage_by_artifact_type([_sample_windows_event(), _sample_browser_event()])
    assert coverage["by_artifact_type"]["windows_event"]["documents_indexed"] == 1
    assert coverage["by_artifact_type"]["browser"]["field_presence"]["browser.url"] == 1


def test_parser_registry_report_can_be_filtered() -> None:
    report = build_parser_registry_report(artifact_types=["browser", "windows_event"])
    assert report["contract_version"] == "v1"
    assert report["artifact_types"] == ["browser", "windows_event"]


def test_parser_coverage_matrix_uses_artifact_audit_fallback_for_unsampled_types() -> None:
    artifacts = [
        {
            "artifact_type": "browser",
            "parser": "browser_chromium_history",
            "status": "completed",
            "source_path": "History",
            "ingest_audit": {"events_indexed": 53},
        },
        {
            "artifact_type": "prefetch",
            "parser": "prefetch_raw",
            "status": "completed",
            "source_path": "calc.pf",
            "ingest_audit": {"events_indexed": 1},
        },
    ]
    matrix = build_parser_coverage_matrix(
        artifacts=artifacts,
        sampled_events=[_sample_browser_event()],
    )
    by_type = {item["artifact_type"]: item for item in matrix["artifact_types"]}
    assert by_type["browser"]["documents_indexed"] == 1
    assert by_type["browser"]["documents_indexed_source"] == "sampled_events"
    assert by_type["prefetch"]["documents_indexed"] == 1
    assert by_type["prefetch"]["documents_indexed_source"] == "artifact_audit_fallback"


def test_base_document_includes_ingest_run_id_and_contract_version() -> None:
    document = base_document(
        "case-1",
        "evidence-1",
        "artifact-1",
        {},
        {
            "artifact_type": "browser",
            "parser": "browser_chromium_history",
            "source_path": "History",
            "ingest_run_id": "run-123",
            "contract_version": "v1",
        },
    )
    assert document["ingest_run_id"] == "run-123"
    assert document["contract_version"] == "v1"


def test_evidence_search_summary_aggregates_core_facets(monkeypatch) -> None:
    monkeypatch.setattr("app.api.routes_evidence.count_documents", lambda index, query: {"count": 53})
    monkeypatch.setattr("app.api.routes_evidence.get_opensearch_client", lambda: object())
    monkeypatch.setattr("app.api.routes_evidence.resolve_aggregatable_field", lambda client, index, field: field)
    monkeypatch.setattr(
        "app.api.routes_evidence.search_documents",
        lambda index, body: {
            "aggregations": {
                "artifact_type": {"buckets": [{"key": "browser", "doc_count": 53}]},
                "parser": {"buckets": [{"key": "browser_chromium_history", "doc_count": 53}]},
                "source_file": {"buckets": [{"key": "History", "doc_count": 53}]},
                "host": {"buckets": [{"key": "HOSTA", "doc_count": 53}]},
                "user": {"buckets": [{"key": "bob", "doc_count": 3}]},
            }
        },
    )
    evidence = SimpleNamespace(
        id="evidence-1",
        case_id="case-1",
        ingest_status=SimpleNamespace(value="completed"),
        metadata_json={"latest_ingest_run_id": "run-1"},
    )
    summary = _build_evidence_search_summary(evidence)
    assert summary["total_indexed_docs"] == 53
    assert summary["artifact_type_counts"]["browser"] == 53
    assert summary["parser_counts"]["browser_chromium_history"] == 53
    assert summary["source_file_counts"]["History"] == 53
