import logging
import math
import multiprocessing as mp
import queue
import signal
import shutil
import subprocess
import time
from collections import Counter
from concurrent.futures import FIRST_COMPLETED, ThreadPoolExecutor, wait
from contextlib import contextmanager
from datetime import datetime
import hashlib
import json
from pathlib import Path
from types import SimpleNamespace
import threading

import psutil
from redis import Redis
from rq import Queue, get_current_job
from rq.registry import StartedJobRegistry
from opensearchpy.exceptions import RequestError
from sqlalchemy.exc import OperationalError
from sqlalchemy.orm import Session
from sqlalchemy.orm.attributes import flag_modified
from sqlalchemy.orm.exc import ObjectDeletedError, StaleDataError

from app.core.activity import log_activity
from app.core.app_settings import PERFORMANCE_PROFILE_KEY, load_runtime_settings
from app.core.config import get_settings
from app.core.database import SessionLocal, engine, utc_now, utc_now_naive
from app.core.detections import create_detection_if_missing, create_detections_bulk_if_missing
from app.core.manifest import build_file_entry, default_manifest, write_manifest
from app.core.opensearch import (
    OpenSearchIngestBlockedError,
    assert_opensearch_ingest_ready,
    bulk_index_events_with_report,
    count_documents,
    delete_events_by_evidence,
    ensure_case_index,
    get_events_index,
    get_opensearch_client,
    refresh_index,
    search_documents,
)
from app.core.performance import build_resource_warnings, describe_ingest_parallelism, performance_snapshot_for_ingest, system_snapshot, validate_and_normalize_settings
from app.core.rules import load_builtin_detection_overrides
from app.core.storage import build_evidence_root, evidence_manifest_path, evidence_staging_dir, reset_extracted_dir, reset_staging_dir, sanitize_relative_path
from app.analysis.semi_auto import SemiAutoAnalysisCancelled, build_case_semi_auto_analysis
from app.ingest.browser.normalizer import BrowserAudit, normalize_browser_event
from app.ingest.browser.sqlite_chromium import parse_chromium_history_sqlite
from app.ingest.browser.sqlite_firefox import parse_firefox_places_sqlite
from app.ingest.archive import copy_folder, extract_archive, inventory_folder, write_tree_metadata
from app.ingest.csv_json import list_generic_artifacts
from app.ingest.detector import detect_evidence_type
from app.ingest.host_detection import detect_host_from_artifacts, detect_host_from_velociraptor_collection, normalize_hostname
from app.ingest.normalizer import base_document, build_raw_summary
from app.ingest.raw_parsers.evtxecmd_backend import EVTXECMD_BACKEND_CSV, EVTX_RAW_PYTHON_BACKEND, EvtxECmdCsvBackend, select_evtx_parser_backend
from app.ingest.raw_parsers.defender_evtx_backend import DEFENDER_EVTX_BACKEND, build_defender_documents_from_sources, iter_defender_evtx_source_docs
from app.ingest.raw_parsers.mftecmd_backend import MFTECMD_BACKEND_CSV, detect_mftecmd_backend, iter_mftecmd_raw_full_batches, iter_mftecmd_raw_summary_batches
from app.ingest.raw_parsers.recmd_backend import RECMD_BACKEND_CSV, USER_ACTIVITY_ARTIFACT_TYPES, detect_recmd_backend, iter_recmd_user_activity_batches
from app.ingest.raw_parsers.srumecmd_backend import SRUMECMD_BACKEND_CSV, detect_srumecmd_backend, find_srum_databases, iter_srumecmd_batches
from app.ingest.raw_parsers.evtx_parser import EvtxRawParser
from app.ingest.eztools.mftecmd import iter_mftecmd_batches
from app.ingest.kape import list_kape_artifacts
from app.ingest.normalizer import normalize_file
from app.ingest.velociraptor import list_velociraptor_artifacts, open_evidence_container
from app.models.artifact import Artifact
from app.models.case_analysis_job import CaseAnalysisJob, CaseAnalysisJobStatus
from app.models.detection_result import DetectionResult
from app.models.rule_run import RuleRun, RuleRunStatus
from app.models.evidence import Evidence, EvidenceType, IngestStatus, resolve_public_evidence_type
from app.models.rule import Rule
from app.models.rule_set import RuleSet
from app.rules_engine.heuristic import build_heuristic_query, load_heuristic_rule
from app.rules_engine.builtin_catalog import get_builtin_detection_definition
from app.rules_engine.sigma import (
    build_sigma_case_profile,
    build_sigma_query,
    build_sigma_query_from_compiled,
    compile_sigma_rule,
    evaluate_sigma_rule,
    evaluate_compiled_sigma_rule,
    extract_sigma_metadata,
    parse_sigma_rule,
    preflight_compiled_sigma_rule,
    preflight_sigma_rule,
)
from app.rules_engine.yara_engine import run_yara_rule_on_evidence, run_yara_rule_set_on_evidence, yara_available
from app.services.host_attribution import choose_primary_host, classify_host_candidate
from app.services.host_identity import apply_case_host_identity
from app.services.parser_backend_evaluation import _tool_dll_path
from app.services.evidence_runs import get_evidence_run, merge_evidence_metadata, start_ingest_run, sync_ingest_run_from_metadata, upsert_ingest_run
from app.services.evtx_profile import EVTX_PROFILE_FAST_HIGH_VALUE, normalize_evtx_fast_limits
from app.services.ingest_benchmarks import (
    build_parser_breakdown,
    classify_benchmark_bottleneck,
    get_ingest_benchmark_by_run_id,
    summarize_benchmark_artifact_counts,
    upsert_ingest_benchmark,
)
from app.services.ingest_plan import append_plan_snapshot, apply_last_reprocess_summary, build_plan_from_artifacts, get_requested_plan, persist_successful_plan
from app.services.problematic_artifacts import build_problematic_artifacts_report, problematic_artifacts_require_error_status
from app.services.reconciliation import capture_reprocess_baseline, reconcile_reprocessed_evidence
from app.services.usable_ingest import (
    FULL_FORENSIC_MODE,
    USABLE_INGEST_MODE,
    build_mode_effective_plan,
    build_indexed_document_counts_by_artifact_type,
    deferred_retry_mode,
    ingest_mode_metadata,
    normalize_ingest_mode,
    parser_capability_profile,
    should_process_artifact_in_mode,
)


settings = get_settings()
logger = logging.getLogger(__name__)
redis_conn = Redis.from_url(settings.redis_url)
ingest_queue = Queue("dfir-ingest", connection=redis_conn)
rules_queue = Queue("dfir-rules", connection=redis_conn)
analysis_queue = Queue("dfir-analysis", connection=redis_conn)


def _debug_db_trace(
    function: str,
    *,
    db: Session | None = None,
    run_id: str | None = None,
    benchmark_id: str | None = None,
    artifact_id: str | None = None,
) -> None:
    if not logger.isEnabledFor(logging.DEBUG):
        return
    connection_id = None
    if db is not None:
        try:
            connection = db.connection()
            connection_id = id(connection.connection)
        except Exception:  # noqa: BLE001
            connection_id = None
    logger.debug(
        "db_trace function=%s thread=%s thread_id=%s session_id=%s connection_id=%s run_id=%s benchmark_id=%s artifact_id=%s",
        function,
        threading.current_thread().name,
        threading.get_ident(),
        id(db) if db is not None else None,
        connection_id,
        run_id,
        benchmark_id,
        artifact_id,
    )


def _is_busy_connection_error(exc: BaseException) -> bool:
    return "another command is already in progress" in str(exc).lower()


def _dispose_engine_after_busy_connection() -> None:
    try:
        engine.dispose(close=False)
    except TypeError:
        engine.dispose()


def _close_session_quietly(db: Session) -> None:
    try:
        db.close()
    except Exception:  # noqa: BLE001
        logger.debug("Suppressed session close failure after recoverable DB error", exc_info=True)


def _run_isolated_session_write(
    operation: str,
    callback,
    *,
    run_id: str | None = None,
    benchmark_id: str | None = None,
    artifact_id: str | None = None,
    max_attempts: int = 3,
):
    last_exc: OperationalError | None = None
    for attempt in range(1, max_attempts + 1):
        isolated_db: Session = SessionLocal()
        session_closed = False
        try:
            _debug_db_trace(
                operation,
                db=isolated_db,
                run_id=run_id,
                benchmark_id=benchmark_id,
                artifact_id=artifact_id,
            )
            return callback(isolated_db)
        except OperationalError as exc:
            try:
                isolated_db.rollback()
            except Exception:  # noqa: BLE001
                logger.debug("Rollback failed after recoverable DB write error", exc_info=True)
            if not _is_busy_connection_error(exc) or attempt >= max_attempts:
                raise
            last_exc = exc
            logger.warning(
                "Recovered busy DB connection during %s on attempt %s/%s",
                operation,
                attempt,
                max_attempts,
            )
            _dispose_engine_after_busy_connection()
            _close_session_quietly(isolated_db)
            session_closed = True
            time.sleep(min(0.05 * attempt, 0.2))
            continue
        finally:
            if not session_closed:
                _close_session_quietly(isolated_db)
    if last_exc is not None:
        raise last_exc
    raise RuntimeError(f"Failed isolated DB write for {operation}")


def _safe_update_progress_isolated(
    evidence_id: str,
    *,
    phase: str,
    progress_pct: int,
    phases: list[str] | None = None,
    extra: dict | None = None,
) -> None:
    try:
        _update_progress_isolated(
            evidence_id,
            phase=phase,
            progress_pct=progress_pct,
            phases=phases,
            extra=extra,
        )
    except Exception:  # noqa: BLE001
        logger.warning(
            "Progress update skipped after DB write failure",
            extra={"evidence_id": evidence_id, "phase": phase},
            exc_info=True,
        )


def _safe_persist_benchmark_snapshot(
    evidence_id: str,
    state: dict | None,
    *,
    status: str,
    effective_parallelism: int | None,
    artifacts_total: int | None = None,
    artifacts_completed: int | None = None,
    records_read: int | None = None,
    records_indexed: int | None = None,
) -> None:
    try:
        _persist_benchmark_snapshot(
            evidence_id,
            state,
            status=status,
            effective_parallelism=effective_parallelism,
            artifacts_total=artifacts_total,
            artifacts_completed=artifacts_completed,
            records_read=records_read,
            records_indexed=records_indexed,
        )
    except Exception:  # noqa: BLE001
        logger.warning(
            "Benchmark snapshot skipped after DB write failure",
            extra={
                "evidence_id": evidence_id,
                "benchmark_id": str((state or {}).get("benchmark_id") or "") or None,
            },
            exc_info=True,
        )


@contextmanager
def _timed_evtx_operation(seconds: int | None, label: str):
    timeout_seconds = max(int(seconds or 0), 0)
    if timeout_seconds <= 0 or threading.current_thread() is not threading.main_thread() or not hasattr(signal, "setitimer"):
        yield
        return

    previous_handler = signal.getsignal(signal.SIGALRM)

    def _handle_timeout(signum, frame):  # noqa: ARG001
        raise TimeoutError(f"{label} timed out after {timeout_seconds}s")

    signal.signal(signal.SIGALRM, _handle_timeout)
    signal.setitimer(signal.ITIMER_REAL, timeout_seconds)
    try:
        yield
    finally:
        signal.setitimer(signal.ITIMER_REAL, 0)
        signal.signal(signal.SIGALRM, previous_handler)


def _update_rule_run(db: Session, rule_run: RuleRun | None, **fields) -> RuleRun | None:
    if not rule_run:
        return None
    for key, value in fields.items():
        setattr(rule_run, key, value)
    rule_run.heartbeat_at = utc_now().isoformat()
    db.commit()
    db.refresh(rule_run)
    return rule_run


def _infer_scope(evidence_id: str | None, scan_options: dict | None) -> str:
    if evidence_id or (scan_options or {}).get("evidence_id"):
        return "evidence"
    if (scan_options or {}).get("host"):
        return "host"
    return "case"


def _is_rule_run_cancel_requested(run_id: str | None) -> bool:
    if not run_id:
        return False
    local_db: Session = SessionLocal()
    try:
        run = local_db.get(RuleRun, run_id)
        return bool(run and run.cancel_requested)
    finally:
        local_db.close()


SIGMA_RUN_MODE_CONFIG = {
    "fast_triage": {
        "max_matches_per_rule": 500,
        "max_detections_per_rule": 200,
        "max_candidate_events_per_rule": 5000,
        "skip_broad_contains_without_prefilter": True,
    },
    "balanced": {
        "max_matches_per_rule": 5000,
        "max_detections_per_rule": 1000,
        "max_candidate_events_per_rule": 25000,
        "skip_broad_contains_without_prefilter": False,
    },
    "exhaustive": {
        "max_matches_per_rule": 50000,
        "max_detections_per_rule": 10000,
        "max_candidate_events_per_rule": 200000,
        "skip_broad_contains_without_prefilter": False,
    },
}


def _resolve_sigma_run_mode(scan_options: dict | None) -> str:
    requested = str((scan_options or {}).get("sigma_run_mode") or "balanced").strip().lower()
    return requested if requested in SIGMA_RUN_MODE_CONFIG else "balanced"


def _resolve_sigma_mode_config(scan_options: dict | None, runtime_settings: dict | None = None) -> dict:
    runtime_settings = runtime_settings or {}
    mode = _resolve_sigma_run_mode(scan_options)
    base = dict(SIGMA_RUN_MODE_CONFIG.get(mode) or SIGMA_RUN_MODE_CONFIG["balanced"])
    base["max_matches_per_rule"] = max(
        int((scan_options or {}).get("sigma_max_matches_per_rule") or runtime_settings.get("SIGMA_MAX_MATCHES_PER_RULE") or base["max_matches_per_rule"]),
        1,
    )
    base["max_detections_per_rule"] = max(
        int((scan_options or {}).get("sigma_max_detections_per_rule") or runtime_settings.get("SIGMA_MAX_DETECTIONS_PER_RULE") or base["max_detections_per_rule"]),
        1,
    )
    base["max_candidate_events_per_rule"] = max(int(base["max_candidate_events_per_rule"]), 1)
    return base


def _sigma_prefilter_has_precision(prefilter: dict | None) -> bool:
    prefilter = prefilter or {}
    return bool(prefilter.get("event_ids") or prefilter.get("artifact_types") or prefilter.get("channels") or prefilter.get("field_exists"))


def _sigma_broadness_reason(*, candidate_count_estimate: int, preflight: dict | None, mode_config: dict) -> str | None:
    preflight = preflight or {}
    if candidate_count_estimate > int(mode_config.get("max_candidate_events_per_rule") or 0):
        return f"candidate estimate {candidate_count_estimate} exceeds per-rule limit {mode_config.get('max_candidate_events_per_rule')}"
    if bool(mode_config.get("skip_broad_contains_without_prefilter")) and not _sigma_prefilter_has_precision(preflight.get("prefilter") or {}):
        return "rule has no precise EventID/channel/field prefilter"
    return None


def enqueue_ingest(evidence_id: str) -> str:
    preflight_db: Session | None = None
    try:
        preflight_db = SessionLocal()
        evidence = preflight_db.get(Evidence, evidence_id)
        if evidence is not None:
            assert_opensearch_ingest_ready(evidence.case_id)
    finally:
        if preflight_db is not None:
            preflight_db.close()
    for job_id in ingest_queue.job_ids:
        job = ingest_queue.fetch_job(job_id)
        if job and job.func_name == "app.workers.tasks.ingest_evidence" and tuple(job.args or ()) == (evidence_id,):
            return job.id
    started = StartedJobRegistry(queue=ingest_queue)
    for job_id in started.get_job_ids():
        job = ingest_queue.fetch_job(job_id)
        if job and job.func_name == "app.workers.tasks.ingest_evidence" and tuple(job.args or ()) == (evidence_id,):
            return job.id
    job = ingest_queue.enqueue(
        "app.workers.tasks.ingest_evidence",
        evidence_id,
        job_timeout=max(int(settings.ingest_job_timeout_seconds or 0), 60),
    )
    return job.id


def enqueue_problematic_artifact_retry(
    *,
    evidence_id: str,
    artifact_ids: list[str],
    mode: str = "default",
    timeout_seconds: int | None = None,
    preserve_existing_events: bool = True,
    replace_existing_events_for_artifact: bool = False,
) -> str:
    job = ingest_queue.enqueue(
        "app.workers.tasks.retry_problematic_artifacts",
        evidence_id,
        artifact_ids,
        mode,
        timeout_seconds,
        preserve_existing_events,
        replace_existing_events_for_artifact,
        job_timeout=max(int(settings.artifact_retry_job_timeout_seconds or settings.ingest_job_timeout_seconds or 0), 60),
    )
    return job.id


def enqueue_mft_summary_index(evidence_id: str, *, max_records: int | None = None, force: bool = False) -> str:
    job = ingest_queue.enqueue(
        "app.workers.tasks.index_mft_summary_for_evidence",
        evidence_id,
        max_records,
        force,
        job_timeout=max(int(settings.artifact_retry_job_timeout_seconds or settings.ingest_job_timeout_seconds or 0), 60),
    )
    return job.id


def enqueue_mft_full_index(evidence_id: str, *, max_records: int | None = None, force: bool = False) -> str:
    job = ingest_queue.enqueue(
        "app.workers.tasks.index_mft_full_for_evidence",
        evidence_id,
        max_records,
        force,
        job_timeout=max(int(settings.artifact_retry_job_timeout_seconds or settings.ingest_job_timeout_seconds or 0), 60),
    )
    return job.id


def enqueue_recmd_user_activity_index(evidence_id: str, *, force: bool = False) -> str:
    job = ingest_queue.enqueue(
        "app.workers.tasks.index_recmd_user_activity_for_evidence",
        evidence_id,
        force,
        job_timeout=max(int(settings.artifact_retry_job_timeout_seconds or settings.ingest_job_timeout_seconds or 0), 60),
    )
    return job.id


def enqueue_defender_evtx_index(evidence_id: str, *, force: bool = False) -> str:
    job = ingest_queue.enqueue(
        "app.workers.tasks.index_defender_evtx_for_evidence",
        evidence_id,
        force,
        job_timeout=max(int(settings.artifact_retry_job_timeout_seconds or settings.ingest_job_timeout_seconds or 0), 60),
    )
    return job.id


def enqueue_srum_index(evidence_id: str, *, force: bool = False) -> str:
    job = ingest_queue.enqueue(
        "app.workers.tasks.index_srum_for_evidence",
        evidence_id,
        force,
        job_timeout=max(int(settings.artifact_retry_job_timeout_seconds or settings.ingest_job_timeout_seconds or 0), 60),
    )
    return job.id


def enqueue_core_ez_rebuild(evidence_id: str, artifact_type: str, *, force: bool = True) -> str:
    job = ingest_queue.enqueue(
        "app.workers.tasks.rebuild_core_ez_artifact_for_evidence",
        evidence_id,
        artifact_type,
        force,
        job_timeout=max(int(settings.artifact_retry_job_timeout_seconds or settings.ingest_job_timeout_seconds or 0), 60),
    )
    return job.id


def _merge_bulk_report(aggregate: dict, report: dict | None, warnings: list) -> None:
    if not report:
        return
    aggregate["attempted"] = aggregate["attempted"] or bool(report.get("attempted"))
    aggregate["success"] = aggregate["success"] and bool(report.get("success", True))
    aggregate["timeouts"] += int(report.get("timeouts") or 0)
    aggregate["retries"] += int(report.get("retries") or 0)
    aggregate["documents_expected"] += int(report.get("documents_expected") or 0)
    aggregate["documents_indexed"] += int(report.get("documents_indexed") or 0)
    aggregate["documents_recovered_after_timeout"] += int(report.get("documents_recovered_after_timeout") or 0)
    aggregate["request_timeout"] = max(aggregate["request_timeout"], int(report.get("request_timeout") or 0))
    initial = int(report.get("chunk_size_initial") or 0)
    if initial:
        aggregate["chunk_size_initial"] = initial if not aggregate["chunk_size_initial"] else min(aggregate["chunk_size_initial"], initial)
    final = int(report.get("chunk_size_final") or 0)
    if final:
        aggregate["chunk_size_final"] = final if not aggregate["chunk_size_final"] else min(aggregate["chunk_size_final"], final)
    aggregate_host_identity = aggregate.setdefault(
        "host_identity",
        {
            "upserts": 0,
            "conflicts_recovered": 0,
            "host_identity_conflict_retries": 0,
            "aliases_updated": 0,
        },
    )
    report_host_identity = dict(report.get("host_identity") or {})
    aggregate_host_identity["upserts"] += int(report_host_identity.get("upserts") or 0)
    aggregate_host_identity["conflicts_recovered"] += int(report_host_identity.get("conflicts_recovered") or 0)
    aggregate_host_identity["host_identity_conflict_retries"] += int(report_host_identity.get("host_identity_conflict_retries") or 0)
    aggregate_host_identity["aliases_updated"] += int(report_host_identity.get("aliases_updated") or 0)
    for warning in report.get("warnings") or []:
        if warning not in aggregate["warnings"]:
            aggregate["warnings"].append(warning)
        if warning not in warnings:
            warnings.append(warning)


def enqueue_rule_run(*, rule_id: str | None, case_id: str, evidence_id: str | None = None, dry_run: bool = False, run_id: str | None = None, rule_set_id: str | None = None, scan_options: dict | None = None) -> str:
    job = rules_queue.enqueue("app.workers.tasks.run_rule_on_case", rule_id, case_id, evidence_id, dry_run, run_id, rule_set_id, scan_options, job_timeout=3600)
    return job.id


def enqueue_rules_run(*, case_id: str, engines: list[str], rule_ids: list[str], enabled_only: bool = True, scan_options: dict | None = None, run_id: str | None = None) -> str:
    job = rules_queue.enqueue("app.workers.tasks.run_rules_on_case", case_id, engines, rule_ids, enabled_only, scan_options, run_id, job_timeout=3600)
    return job.id


def enqueue_semi_auto_analysis(job_run_id: str) -> str:
    job = analysis_queue.enqueue("app.workers.tasks.run_case_semi_auto_analysis", job_run_id, job_timeout=3600)
    with SessionLocal() as db:
        run = db.get(CaseAnalysisJob, job_run_id)
        if run:
            run.job_id = job.id
            db.commit()
    return job.id


def _metadata_phase_timings_snapshot(metadata: dict) -> list[dict]:
    snapshot = [dict(item) for item in metadata.get("phase_timings") or [] if isinstance(item, dict)]
    current = metadata.get("current_phase_timing")
    if isinstance(current, dict):
        current_snapshot = dict(current)
        started_at = current_snapshot.get("started_at")
        if started_at and not current_snapshot.get("finished_at"):
            try:
                current_snapshot["duration_seconds"] = round(
                    max((utc_now() - datetime.fromisoformat(str(started_at))).total_seconds(), 0.0),
                    2,
                )
            except Exception:  # noqa: BLE001
                current_snapshot["duration_seconds"] = current_snapshot.get("duration_seconds") or 0.0
        snapshot.append(current_snapshot)
    return snapshot


def _transition_metadata_phase_timing(metadata: dict, phase: str) -> None:
    now_iso = utc_now().isoformat()
    current = metadata.get("current_phase_timing")
    if isinstance(current, dict) and str(current.get("phase") or "") == phase:
        current["duration_seconds"] = round(
            max((utc_now() - datetime.fromisoformat(str(current.get("started_at") or now_iso))).total_seconds(), 0.0),
            2,
        )
        metadata["current_phase_timing"] = current
        metadata["phase_timings"] = _metadata_phase_timings_snapshot(metadata)
        return
    if isinstance(current, dict):
        try:
            started = datetime.fromisoformat(str(current.get("started_at") or now_iso))
            duration = round(max((utc_now() - started).total_seconds(), 0.0), 2)
        except Exception:  # noqa: BLE001
            duration = float(current.get("duration_seconds") or 0.0)
        finished = {
            **current,
            "finished_at": now_iso,
            "duration_seconds": duration,
        }
        metadata.setdefault("phase_timings", []).append(finished)
    metadata["current_phase_timing"] = {
        "phase": phase,
        "started_at": now_iso,
        "finished_at": None,
        "duration_seconds": 0.0,
    }
    metadata["phase_timings"] = _metadata_phase_timings_snapshot(metadata)


def _finish_metadata_phase_timing(metadata: dict, *, phase: str | None = None, finished_at: datetime | None = None) -> None:
    finished = finished_at or utc_now()
    current = metadata.get("current_phase_timing")
    if not isinstance(current, dict):
        metadata["phase_timings"] = _metadata_phase_timings_snapshot(metadata)
        return
    if phase and str(current.get("phase") or "") != phase:
        metadata["phase_timings"] = _metadata_phase_timings_snapshot(metadata)
        return
    started_at = str(current.get("started_at") or finished.isoformat())
    try:
        started = datetime.fromisoformat(started_at)
        duration = round(max((finished - started).total_seconds(), 0.0), 2)
    except Exception:  # noqa: BLE001
        duration = float(current.get("duration_seconds") or 0.0)
    completed = {
        **current,
        "finished_at": finished.isoformat(),
        "duration_seconds": duration,
    }
    phase_timings = []
    current_phase = str(current.get("phase") or "")
    current_started = str(current.get("started_at") or "")
    for item in metadata.get("phase_timings") or []:
        if not isinstance(item, dict):
            continue
        if str(item.get("phase") or "") == current_phase and str(item.get("started_at") or "") == current_started and not item.get("finished_at"):
            continue
        phase_timings.append(dict(item))
    phase_timings.append(completed)
    metadata["phase_timings"] = phase_timings
    metadata["current_phase_timing"] = None
    metadata["phase_timings"] = _metadata_phase_timings_snapshot(metadata)


def _update_progress(db: Session, evidence: Evidence, *, phase: str, progress_pct: int, phases: list[str] | None = None, extra: dict | None = None) -> None:
    metadata = dict(evidence.metadata_json or {})
    metadata["current_phase"] = phase
    metadata["progress_pct"] = max(0, min(100, progress_pct))
    metadata["heartbeat_at"] = utc_now().isoformat()
    _transition_metadata_phase_timing(metadata, phase)
    if phases is not None:
        metadata["phases"] = phases
    if extra:
        metadata.update(extra)
    if phase in {"completed", "completed_with_errors", "failed"}:
        finished_at = None
        raw_finished_at = metadata.get("finished_at")
        if raw_finished_at:
            try:
                finished_at = datetime.fromisoformat(str(raw_finished_at))
            except Exception:  # noqa: BLE001
                finished_at = None
        _finish_metadata_phase_timing(metadata, phase=phase, finished_at=finished_at)
    metadata["phase_timings"] = _metadata_phase_timings_snapshot(metadata)
    run_id = str(metadata.get("current_ingest_run_id") or (metadata.get("reprocess_request") or {}).get("run_id") or "")
    if run_id:
        metadata = sync_ingest_run_from_metadata(
            metadata,
            run_id=run_id,
            ingest_status=evidence.ingest_status.value if hasattr(evidence.ingest_status, "value") else str(evidence.ingest_status),
        )
    benchmark_id = str((metadata.get("benchmark_request") or {}).get("benchmark_id") or "")
    _debug_db_trace("_update_progress", db=db, run_id=run_id, benchmark_id=benchmark_id or None)
    evidence.metadata_json = merge_evidence_metadata(evidence.metadata_json or {}, metadata)
    db.commit()


def _update_progress_isolated(evidence_id: str, *, phase: str, progress_pct: int, phases: list[str] | None = None, extra: dict | None = None) -> None:
    def _write(isolated_db: Session) -> None:
        isolated_evidence = isolated_db.get(Evidence, evidence_id)
        if not isolated_evidence:
            return
        _update_progress(isolated_db, isolated_evidence, phase=phase, progress_pct=progress_pct, phases=phases, extra=extra)

    _run_isolated_session_write("_update_progress_isolated", _write)


def _update_artifact_row_isolated(artifact_id: str, **fields) -> bool:
    isolated_db: Session = SessionLocal()
    try:
        _debug_db_trace("_update_artifact_row_isolated", db=isolated_db, artifact_id=artifact_id)
        artifact = isolated_db.get(Artifact, artifact_id)
        if not artifact:
            return False
        for key, value in fields.items():
            setattr(artifact, key, value)
        isolated_db.commit()
        return True
    except (StaleDataError, ObjectDeletedError):
        isolated_db.rollback()
        logger.warning("Artifact %s became stale during isolated update", artifact_id)
        return False
    finally:
        isolated_db.close()


def _create_artifact_row_isolated(
    *,
    case_id: str,
    evidence_id: str,
    name: str,
    artifact_type: str,
    source_path: str,
    parser: str,
    status: str,
) -> str:
    isolated_db: Session = SessionLocal()
    try:
        _debug_db_trace("_create_artifact_row_isolated", db=isolated_db)
        artifact = Artifact(
            case_id=case_id,
            evidence_id=evidence_id,
            name=name,
            artifact_type=artifact_type,
            source_path=source_path,
            parser=parser,
            status=status,
        )
        isolated_db.add(artifact)
        isolated_db.commit()
        isolated_db.refresh(artifact)
        return artifact.id
    finally:
        isolated_db.close()


def _mark_artifact_row_processing_start(artifact_id: str) -> bool:
    return _update_artifact_row_isolated(artifact_id, status="processing")


def _artifact_is_raw_not_parsed(artifact_info: dict) -> bool:
    return artifact_info.get("status") == "detected_not_parsed" or artifact_info.get("parser") == "not_implemented"


def _initial_runtime_artifact_status(*, artifact_info: dict, parallel_safe: bool) -> str:
    if _artifact_is_raw_not_parsed(artifact_info):
        return "detected_not_parsed"
    return "queued_parallel" if parallel_safe else "processing"


def _finalize_artifact_status(*, parser_name: str | None, record_count: int, raw_parser_status: str | None) -> str:
    parser_name = str(parser_name or "").lower()
    raw_parser_status = str(raw_parser_status or "").lower()
    native_raw_parsers = {"evtx_raw", "lnk_raw", "prefetch_raw", "amcache_raw", "shimcache_raw", "windows_service_registry"}
    if parser_name == "evtx_raw" and record_count == 0 and raw_parser_status == "parsed_empty":
        return "skipped_empty"
    if parser_name in native_raw_parsers and record_count == 0:
        if raw_parser_status in {"partial", "failed", "failed_unsupported"}:
            return raw_parser_status
        return "failed"
    if raw_parser_status == "partial":
        return "partial"
    return "completed"


def _is_non_terminal_artifact_status(status: str | None) -> bool:
    normalized = str(status or "").strip().lower()
    return normalized in {
        "",
        "detected",
        "queued",
        "pending",
        "processing",
        "running",
        "parsing",
        "indexing",
        "materializing",
        "unknown",
    }


def _classify_ingest_abort(exc: Exception) -> tuple[str, str, str]:
    if isinstance(exc, OpenSearchIngestBlockedError):
        return "infrastructure_blocked_opensearch", "failed_aborted", str(exc)
    message = str(exc)
    lowered = message.lower()
    if "task exceeded maximum timeout value" in lowered:
        return "timeout", "failed_timeout", message
    if "cancel" in lowered:
        return "cancelled", "cancelled", message
    return "aborted", "failed_aborted", message


def _artifact_progress_snapshot(metadata: dict[str, object]) -> dict[str, dict[str, int]]:
    progress: dict[str, dict[str, int]] = {}
    parallel_ingest = metadata.get("parallel_ingest") or {}
    if isinstance(parallel_ingest, dict):
        for item in parallel_ingest.get("running_artifacts") or []:
            if not isinstance(item, dict):
                continue
            key = str(item.get("artifact") or "").strip()
            if not key:
                continue
            progress[key] = {
                "records_read": int(item.get("records_read") or 0),
                "records_indexed": int(item.get("records_indexed") or 0),
            }
    current_artifact = str(metadata.get("current_artifact") or metadata.get("current_artifact_path") or "").strip()
    if current_artifact:
        progress.setdefault(
            current_artifact,
            {
                "records_read": int(metadata.get("current_artifact_records_read") or 0),
                "records_indexed": int(metadata.get("current_artifact_records_indexed") or 0),
            },
        )
    return progress


def _reconcile_artifact_states_on_ingest_close(
    db: Session,
    *,
    evidence: Evidence,
    manifest: dict,
    run_id: str,
    terminal_status: str,
    terminal_phase: str,
    terminal_error: str | None,
    timeout_seconds: int | None = None,
) -> dict[str, object]:
    artifact_rows = db.query(Artifact).filter(Artifact.evidence_id == evidence.id).all()
    artifact_rows_by_name = {str(artifact.name or ""): artifact for artifact in artifact_rows}
    manifest_artifacts = [item for item in (manifest.get("artifacts") or []) if isinstance(item, dict)]
    manifest_by_name = {str(item.get("name") or ""): item for item in manifest_artifacts if str(item.get("name") or "").strip()}
    progress_by_name = _artifact_progress_snapshot(dict(evidence.metadata_json or {}))
    abort_kind = terminal_phase if terminal_phase in {"timeout", "cancelled"} else "aborted"
    reconciled_status = "failed_timeout" if abort_kind == "timeout" else "cancelled" if abort_kind == "cancelled" else "failed_aborted"
    error_label = (
        f"Artifact did not finish before the ingest run timed out after {int(timeout_seconds or 0)}s"
        if abort_kind == "timeout"
        else "Artifact was cancelled before completion"
        if abort_kind == "cancelled"
        else "Artifact was aborted before completion"
    )
    existing_errors = list(manifest.get("errors") or [])
    reconciled_items: list[dict[str, object]] = []

    for artifact in artifact_rows:
        if not _is_non_terminal_artifact_status(artifact.status):
            continue
        progress = progress_by_name.get(str(artifact.name or ""), {})
        artifact.status = reconciled_status
        artifact.record_count = max(int(artifact.record_count or 0), int(progress.get("records_indexed") or 0))
        manifest_artifact = manifest_by_name.get(str(artifact.name or ""))
        if manifest_artifact is None:
            manifest_artifact = {
                "name": artifact.name,
                "source_path": artifact.source_path,
                "artifact_type": artifact.artifact_type,
                "parser": artifact.parser,
            }
            manifest_artifacts.append(manifest_artifact)
            manifest_by_name[str(artifact.name or "")] = manifest_artifact
        manifest_artifact["status"] = reconciled_status
        ingest_audit = dict(manifest_artifact.get("ingest_audit") or {})
        ingest_audit["records_read"] = max(int(ingest_audit.get("records_read") or 0), int(progress.get("records_read") or 0))
        ingest_audit["records_indexed"] = max(
            int(ingest_audit.get("records_indexed") or ingest_audit.get("events_indexed") or 0),
            int(progress.get("records_indexed") or 0),
        )
        ingest_audit["events_indexed"] = int(ingest_audit.get("records_indexed") or 0)
        if timeout_seconds:
            ingest_audit["timeout_seconds"] = int(timeout_seconds)
        ingest_audit["top_errors"] = [error_label]
        manifest_artifact["ingest_audit"] = ingest_audit
        error_entry = {
            "artifact": artifact.name,
            "error": f"{error_label}. {terminal_error or ''}".strip(),
        }
        if not any(str(item.get("artifact") or "") == artifact.name for item in existing_errors if isinstance(item, dict)):
            existing_errors.append(error_entry)
        reconciled_items.append(
            {
                "artifact_id": artifact.id,
                "name": artifact.name,
                "status": reconciled_status,
                "records_read": ingest_audit["records_read"],
                "records_indexed": ingest_audit["records_indexed"],
            }
        )

    manifest["artifacts"] = manifest_artifacts
    manifest["errors"] = existing_errors
    completed_statuses = {"completed", "parsed_with_warning", "partial", "failed_unsupported"}
    completed_count = sum(1 for artifact in artifact_rows if str(artifact.status or "") in completed_statuses)
    failed_count = sum(1 for artifact in artifact_rows if str(artifact.status or "").startswith("failed") or str(artifact.status or "") in {"stalled", "cancelled"})
    return {
        "completed_count": completed_count,
        "failed_count": failed_count,
        "reconciled_items": reconciled_items,
        "artifact_statuses": {str(artifact.id): str(artifact.status or "") for artifact in artifact_rows},
    }


def _run_pending_reprocess_cleanup(db: Session, evidence: Evidence, metadata: dict) -> dict:
    cleanup = dict(metadata.get("reprocess_cleanup_pending") or {})
    if not cleanup:
        return metadata
    cleanup_report = dict(metadata.get("reprocess_cleanup_report") or {})
    if cleanup.get("delete_events"):
        delete_events_by_evidence(evidence.id, evidence.case_id)
        cleanup_report["events_cleanup_completed"] = True
        cleanup_report["events_cleanup_completed_at"] = utc_now().isoformat()
    stale_statuses = [str(item) for item in (cleanup.get("stale_detection_statuses") or []) if item]
    if stale_statuses:
        db.query(DetectionResult).filter(
            DetectionResult.evidence_id == evidence.id,
            DetectionResult.deleted_at.is_(None),
            DetectionResult.status.in_(stale_statuses),
        ).update({"status": "stale"}, synchronize_session=False)
        cleanup_report["detections_cleanup_completed"] = True
        cleanup_report["detections_cleanup_completed_at"] = utc_now().isoformat()
        cleanup_report["detections_cleanup_skipped"] = False
    elif cleanup.get("detections_cleanup_skipped"):
        cleanup_report["detections_cleanup_skipped"] = True
        cleanup_report["detection_cleanup_reason"] = str(cleanup.get("detection_cleanup_reason") or "benchmark_skip_detections")
    if cleanup.get("delete_artifacts"):
        db.query(Artifact).filter(Artifact.evidence_id == evidence.id).delete()
    if cleanup.get("reset_extracted_dir"):
        reset_extracted_dir(evidence.case_id, evidence.id)
    if cleanup.get("reset_staging_dir"):
        reset_staging_dir(evidence.case_id, evidence.id)
    else:
        evidence_staging_dir(evidence.case_id, evidence.id)
    metadata = dict(metadata)
    metadata["reprocess_cleanup_completed_at"] = utc_now().isoformat()
    if cleanup_report:
        metadata["reprocess_cleanup_report"] = cleanup_report
    metadata.pop("reprocess_cleanup_pending", None)
    evidence.metadata_json = merge_evidence_metadata(evidence.metadata_json or {}, metadata)
    db.commit()
    db.refresh(evidence)
    return dict(evidence.metadata_json or {})


def _run_pending_reconciliation_baseline(db: Session, evidence: Evidence, metadata: dict) -> dict:
    pending = dict(metadata.get("reconciliation_baseline_pending") or {})
    if not pending:
        return metadata
    benchmark_request = dict(metadata.get("benchmark_request") or {})
    if bool(benchmark_request.get("skip_detections")) or bool(benchmark_request.get("skip_rules")):
        metadata = dict(metadata)
        metadata["reconciliation_baseline_skipped"] = {
            "skipped": True,
            "reason": "benchmark_skip_detections",
            "skipped_at": utc_now().isoformat(),
        }
        metadata.pop("reconciliation_baseline_pending", None)
        evidence.metadata_json = merge_evidence_metadata(evidence.metadata_json or {}, metadata)
        db.commit()
        db.refresh(evidence)
        return dict(evidence.metadata_json or {})
    metadata = dict(metadata)
    metadata["reconciliation_baseline"] = capture_reprocess_baseline(db, evidence)
    metadata["reconciliation_baseline_captured_at"] = utc_now().isoformat()
    metadata.pop("reconciliation_baseline_pending", None)
    evidence.metadata_json = merge_evidence_metadata(evidence.metadata_json or {}, metadata)
    db.commit()
    db.refresh(evidence)
    return dict(evidence.metadata_json or {})


PARSER_CAPABILITIES: dict[str, dict] = {
    "evtx_raw": {
        "parallel_safe": True,
        "resource_class": "cpu_io",
        "max_parallelism": 4,
        "requires_ordering": False,
        "shared_state": False,
    },
    "lnk_raw": {
        "parallel_safe": True,
        "resource_class": "cpu_io",
        "max_parallelism": 4,
        "requires_ordering": False,
        "shared_state": False,
    },
    "prefetch_raw": {
        "parallel_safe": True,
        "resource_class": "cpu_io",
        "max_parallelism": 4,
        "requires_ordering": False,
        "shared_state": False,
    },
    "scheduled_task_xml": {
        "parallel_safe": True,
        "resource_class": "cpu_io",
        "max_parallelism": 4,
        "requires_ordering": False,
        "shared_state": False,
    },
    "browser_chromium_history": {
        "parallel_safe": True,
        "resource_class": "cpu_io",
        "max_parallelism": 2,
        "requires_ordering": False,
        "shared_state": False,
    },
    "browser_firefox_places": {
        "parallel_safe": True,
        "resource_class": "cpu_io",
        "max_parallelism": 2,
        "requires_ordering": False,
        "shared_state": False,
    },
    "amcache_raw": {
        "parallel_safe": True,
        "resource_class": "cpu_io",
        "max_parallelism": 2,
        "requires_ordering": False,
        "shared_state": False,
    },
    "shimcache_raw": {
        "parallel_safe": True,
        "resource_class": "cpu_io",
        "max_parallelism": 2,
        "requires_ordering": False,
        "shared_state": False,
    },
    "windows_service_registry": {
        "parallel_safe": True,
        "resource_class": "cpu_io",
        "max_parallelism": 2,
        "requires_ordering": False,
        "shared_state": False,
    },
}


def _parser_capabilities(parser_name: str | None, artifact_type: str | None = None) -> dict[str, object]:
    parser_key = str(parser_name or "").lower()
    base = dict(PARSER_CAPABILITIES.get(parser_key) or {})
    if not base:
        base = {
            "parallel_safe": False,
            "resource_class": "unknown",
            "max_parallelism": 1,
            "requires_ordering": False,
            "shared_state": True,
        }
    base["parser"] = parser_key
    base["artifact_type"] = str(artifact_type or "")
    base.update(parser_capability_profile(parser_name, artifact_type))
    return base


def _ingest_mode_from_evidence(evidence: Evidence) -> str:
    return normalize_ingest_mode((evidence.metadata_json or {}).get("ingest_mode"))


def _build_skipped_artifact_entry(artifact_info: dict[str, object], *, status: str) -> dict[str, object]:
    suggested_retry = deferred_retry_mode(artifact_info.get("parser"), artifact_info.get("artifact_type"))
    profile = parser_capability_profile(artifact_info.get("parser"), artifact_info.get("artifact_type"))
    return {
        "name": artifact_info.get("name"),
        "source_path": artifact_info.get("source_path"),
        "artifact_type": artifact_info.get("artifact_type"),
        "parser": artifact_info.get("parser"),
        "profile": artifact_info.get("profile"),
        "record_count": 0,
        "status": status,
        "reason": artifact_info.get("reason") or status,
        "planned_parser": artifact_info.get("planned_parser"),
        "usable_mode_tier": profile.get("tier"),
        "retryable": status in {"skipped_experimental", "skipped_unsupported", "deferred_long_tail", "partial_indexed_deferred"},
        "suggested_retry_mode": suggested_retry,
        "partial_docs_available": False,
        "data_loss_expected": False,
    }


def _partition_artifacts_for_ingest_mode(
    artifacts: list[dict[str, object]],
    *,
    ingest_mode: str,
) -> tuple[list[dict[str, object]], list[dict[str, object]]]:
    processable: list[dict[str, object]] = []
    skipped: list[dict[str, object]] = []
    for artifact in artifacts:
        allowed, status = should_process_artifact_in_mode(artifact, ingest_mode)
        if allowed:
            processable.append(artifact)
        else:
            skipped.append({**artifact, "status": status or "skipped_experimental"})
    return processable, skipped


def _artifact_can_parallelize(artifact_info: dict) -> bool:
    if _artifact_is_raw_not_parsed(artifact_info):
        return False
    capabilities = _parser_capabilities(artifact_info.get("parser"), artifact_info.get("artifact_type"))
    return bool(capabilities.get("parallel_safe"))


def _split_parallel_and_sequential_artifacts(
    artifacts: list[dict],
    *,
    metadata: dict | None,
    parallel_enabled: bool,
) -> tuple[list[dict], list[dict]]:
    parallel_candidates = [
        item
        for item in artifacts
        if _artifact_can_parallelize(item)
        and not (str(item.get("parser") or "").lower() == "evtx_raw" and _evtx_fast_limits_for_run(metadata or {}))
    ]
    if not parallel_enabled:
        return [], list(artifacts)
    return parallel_candidates, [item for item in artifacts if item not in parallel_candidates]


def _classify_ingest_bottleneck(*, active_workers: int, queued_artifacts: int, opensearch_bulk: dict | None = None) -> str:
    if int((opensearch_bulk or {}).get("timeouts") or 0) > 0:
        return "OpenSearch"
    if active_workers <= 0 and queued_artifacts > 0:
        return "waiting_for_worker"
    if active_workers > 0:
        return "parsing"
    return "unknown"


def _parallel_tail_metadata(
    runtime_snapshot: dict,
    *,
    artifacts_processed: int,
    failed_artifacts: int,
    elapsed_seconds: float,
) -> dict[str, object]:
    running_artifacts = list(runtime_snapshot.get("running_artifacts") or [])
    queued_count = int(runtime_snapshot.get("queued_count") or 0)
    tail_records_read = int(runtime_snapshot.get("read_pending") or 0)
    tail_records_indexed = int(runtime_snapshot.get("indexed_pending") or 0)
    current_artifact = None
    current_artifact_path = None
    current_artifact_label = None
    current_artifact_records_read = tail_records_read
    current_artifact_records_indexed = tail_records_indexed
    current_artifact_source = None
    if running_artifacts:
        current_artifact_source = "parallel_running_artifacts"
        if len(running_artifacts) == 1:
            active = running_artifacts[0]
            current_artifact = str(active.get("artifact") or "").strip() or None
            current_artifact_path = str(active.get("source_path") or "").strip() or current_artifact
            current_artifact_records_read = int(active.get("records_read") or 0)
            current_artifact_records_indexed = int(active.get("records_indexed") or 0)
            current_artifact_label = (
                f"{active.get('artifact')} · "
                f"{current_artifact_records_read} records read / "
                f"{current_artifact_records_indexed} indexed"
            )
        else:
            preview_names = [str(item.get("artifact") or "").strip() for item in running_artifacts[:3] if str(item.get("artifact") or "").strip()]
            current_artifact = "Multiple artifacts running"
            current_artifact_label = (
                f"{len(running_artifacts)} artifacts active · "
                f"{tail_records_read} records read / {tail_records_indexed} indexed"
            )
            if preview_names:
                current_artifact_path = ", ".join(preview_names) + (" …" if len(running_artifacts) > len(preview_names) else "")
    return {
        "current_artifact": current_artifact,
        "current_artifact_path": current_artifact_path,
        "current_artifact_source": current_artifact_source,
        "current_artifact_progress_label": current_artifact_label,
        "current_artifact_records_read": current_artifact_records_read,
        "current_artifact_records_indexed": current_artifact_records_indexed,
        "tail_artifacts_total": len(running_artifacts) + queued_count,
        "tail_artifacts_running": len(running_artifacts),
        "tail_artifacts_queued": queued_count,
        "tail_artifacts_completed": int(artifacts_processed or 0),
        "tail_artifacts_failed": int(failed_artifacts or 0),
        "tail_records_read": tail_records_read,
        "tail_records_indexed": tail_records_indexed,
        "tail_last_progress_at": utc_now().isoformat(),
        "tail_records_per_sec": round(tail_records_read / max(elapsed_seconds, 0.001), 2),
        "tail_current_artifacts": running_artifacts,
        "tail_slowest_artifacts": list(runtime_snapshot.get("slowest_artifacts") or []),
        "tail_elapsed_seconds": round(elapsed_seconds, 2),
    }


def _benchmark_elapsed_seconds(state: dict | None) -> float:
    if not state:
        return 0.0
    return round(max(time.perf_counter() - float(state.get("started_monotonic") or time.perf_counter()), 0.0), 2)


def _benchmark_transition_phase(
    state: dict | None,
    phase: str,
    *,
    records_read: int | None = None,
    records_indexed: int | None = None,
    artifacts_processed: int | None = None,
    error: str | None = None,
) -> None:
    if not state:
        return
    now = time.perf_counter()
    now_iso = utc_now().isoformat()
    current = state.get("current_phase")
    if current and current.get("phase") == phase:
        return
    if current:
        current["finished_at"] = now_iso
        current["duration_seconds"] = round(max(now - float(current.get("started_monotonic") or now), 0.0), 2)
        if records_read is not None:
            current["records_read"] = int(records_read)
        if records_indexed is not None:
            current["records_indexed"] = int(records_indexed)
        if artifacts_processed is not None:
            current["artifacts_processed"] = int(artifacts_processed)
        if error:
            current.setdefault("errors", []).append(str(error))
        current.pop("started_monotonic", None)
        state.setdefault("phase_timings", []).append(current)
    state["current_phase"] = {
        "phase": phase,
        "started_at": now_iso,
        "started_monotonic": now,
        "finished_at": None,
        "duration_seconds": 0.0,
        "records_read": int(records_read or 0),
        "records_indexed": int(records_indexed or 0),
        "artifacts_processed": int(artifacts_processed or 0),
        "errors": [],
    }


def _benchmark_mark_first(state: dict | None, key: str) -> None:
    if not state or state.get(key) is not None:
        return
    state[key] = _benchmark_elapsed_seconds(state)


def _benchmark_sample_resources(
    state: dict | None,
    *,
    active_workers: int | None = None,
    queue_depth: int | None = None,
    force: bool = False,
) -> None:
    if not state:
        return
    now = time.perf_counter()
    if not force and (now - float(state.get("last_sample_monotonic") or 0.0)) < float(state.get("sample_interval_seconds") or 5.0):
        return
    state["last_sample_monotonic"] = now
    sample: dict[str, object] = {
        "t": _benchmark_elapsed_seconds(state),
        "worker_cpu_percent": None,
        "worker_memory_rss_bytes": None,
        "postgres_cpu_percent": None,
        "backend_cpu_percent": None,
        "opensearch_heap_percent": None,
        "queue_depth": int(queue_depth or 0),
        "active_workers": int(active_workers or 0),
        "disk_free_bytes": None,
    }
    try:
        process = psutil.Process()
        sample["worker_cpu_percent"] = process.cpu_percent(interval=None)
        sample["worker_memory_rss_bytes"] = process.memory_info().rss
    except Exception:  # noqa: BLE001
        pass
    try:
        sample["queue_depth"] = ingest_queue.count
    except Exception:  # noqa: BLE001
        pass
    try:
        sample["active_workers"] = len(StartedJobRegistry("dfir-ingest", connection=redis_conn))
    except Exception:  # noqa: BLE001
        pass
    try:
        sample["disk_free_bytes"] = psutil.disk_usage(str(Path(settings.backend_data_dir))).free
    except Exception:  # noqa: BLE001
        pass
    try:
        stats = get_opensearch_client().cluster.stats()
        sample["opensearch_heap_percent"] = int((((stats.get("nodes") or {}).get("jvm") or {}).get("mem") or {}).get("heap_used_percent") or 0)
    except Exception:  # noqa: BLE001
        sample["opensearch_heap_percent"] = None
    state.setdefault("resource_samples", []).append(sample)
    state["resource_samples"] = state["resource_samples"][-120:]


def _benchmark_phase_snapshot(state: dict | None) -> list[dict]:
    if not state:
        return []
    snapshot = [dict(item) for item in state.get("phase_timings") or [] if isinstance(item, dict)]
    current = state.get("current_phase")
    if current and isinstance(current, dict):
        current_snapshot = dict(current)
        current_snapshot["duration_seconds"] = round(
            max(time.perf_counter() - float(current_snapshot.get("started_monotonic") or time.perf_counter()), 0.0),
            2,
        )
        current_snapshot.pop("started_monotonic", None)
        snapshot.append(current_snapshot)
    return snapshot


def _parallel_evidence_ref(evidence: Evidence) -> dict[str, object]:
    metadata = dict(getattr(evidence, "metadata_json", None) or {})
    preferred_host = str(metadata.get("provided_host") or getattr(evidence, "detected_host", None) or "").strip() or None
    evidence_ref: dict[str, object] = {
        "id": str(evidence.id),
        "case_id": str(evidence.case_id),
        "detected_host": preferred_host,
        "detected_user": getattr(evidence, "detected_user", None),
    }
    provided_host = str(metadata.get("provided_host") or "").strip()
    if provided_host:
        evidence_ref["provided_host"] = provided_host
    ingest_run_id = str(metadata.get("current_ingest_run_id") or metadata.get("latest_ingest_run_id") or "").strip()
    if ingest_run_id:
        evidence_ref["ingest_run_id"] = ingest_run_id
    evtx_profile = str(metadata.get("evtx_profile") or "").strip()
    if evtx_profile:
        evidence_ref["evtx_profile"] = evtx_profile
    evtx_fast_limits = metadata.get("evtx_fast_limits")
    if isinstance(evtx_fast_limits, dict):
        evidence_ref["evtx_fast_limits"] = normalize_evtx_fast_limits(evtx_fast_limits)
    evtx_parser_backend = str(metadata.get("evtx_parser_backend") or "").strip()
    if evtx_parser_backend:
        evidence_ref["evtx_parser_backend"] = evtx_parser_backend
    return evidence_ref


def _coerce_parallel_evidence_ref(evidence_ref: dict | None) -> dict[str, object]:
    if not isinstance(evidence_ref, dict):
        raise TypeError("parallel artifact workers require an isolated evidence_ref dict, not an ORM object")
    if not evidence_ref.get("id") or not evidence_ref.get("case_id"):
        raise ValueError("parallel artifact workers require evidence_ref.id and evidence_ref.case_id")
    return evidence_ref


def _ensure_parallel_submit_payload_isolation(payload: dict[str, object]) -> None:
    forbidden_types = (Session, Evidence, Artifact)
    for key, value in payload.items():
        if isinstance(value, forbidden_types):
            raise TypeError(f"parallel artifact workers cannot receive {type(value).__name__} via {key}")


def _benchmark_runtime_status(state: dict | None) -> dict[str, object]:
    if not state:
        return {}
    now = time.perf_counter()
    last_progress_monotonic = float(state.get("last_progress_monotonic") or state.get("started_monotonic") or now)
    stalled_threshold_seconds = max(int(state.get("stalled_threshold_seconds") or 30), 5)
    stalled_seconds = round(max(now - last_progress_monotonic, 0.0), 2)
    current_phase = str(((state.get("current_phase") or {}).get("phase")) or "")
    is_extracting = current_phase in {"extracting", "extracting_selected", "materializing_and_parsing"}
    stalled = bool(is_extracting and stalled_seconds >= stalled_threshold_seconds)
    warning = None
    if stalled:
        warning = f"No extraction/materialization progress observed for {stalled_seconds}s while in {current_phase}."
    return {
        "current_action": state.get("current_action"),
        "current_selected_path": state.get("current_selected_path"),
        "last_progress_at": state.get("last_progress_at"),
        "last_progress_seconds_ago": stalled_seconds,
        "stalled_phase_warning": warning,
        "current_phase_stalled": stalled,
    }


def _persist_benchmark_snapshot(
    evidence_id: str,
    state: dict | None,
    *,
    status: str | None = None,
    effective_parallelism: int | None = None,
    artifacts_total: int | None = None,
    artifacts_completed: int | None = None,
    records_read: int | None = None,
    records_indexed: int | None = None,
) -> None:
    if not state or not state.get("benchmark_id"):
        return
    def _write(isolated_db: Session) -> None:
        evidence = isolated_db.get(Evidence, evidence_id)
        if not evidence:
            return
        metadata = dict(evidence.metadata_json or {})
        runtime_status = _benchmark_runtime_status(state)
        metadata = upsert_ingest_benchmark(
            metadata,
            str(state.get("benchmark_id") or ""),
            {
                "status": status or "running",
                "run_id": state.get("run_id"),
                "started_at": state.get("started_at"),
                "effective_parallelism": effective_parallelism,
                "effective_cpu_count": int(state.get("effective_cpu_count") or 1),
                "memory_limit_source": state.get("memory_limit_source"),
                "source_evidence_name": state.get("source_evidence_name"),
                "artifacts_total": artifacts_total,
                "artifacts_completed": artifacts_completed,
                "records_read": records_read,
                "records_indexed": records_indexed,
                "selected_total": int(state.get("selected_total") or 0),
                "current_action": runtime_status.get("current_action"),
                "current_selected_path": runtime_status.get("current_selected_path"),
                "last_progress_at": runtime_status.get("last_progress_at"),
                "last_progress_seconds_ago": runtime_status.get("last_progress_seconds_ago"),
                "stalled_phase_warning": runtime_status.get("stalled_phase_warning"),
                "current_phase_stalled": runtime_status.get("current_phase_stalled"),
                "time_to_first_artifact_ready": state.get("time_to_first_artifact_ready"),
                "time_to_first_parse_start": state.get("time_to_first_parse_start"),
                "time_to_first_event_indexed": state.get("time_to_first_event_indexed"),
                "phase_timings": _benchmark_phase_snapshot(state),
                "resource_samples": list(state.get("resource_samples") or []),
            },
        )
        evidence.metadata_json = merge_evidence_metadata(evidence.metadata_json or {}, metadata)
        isolated_db.commit()

    _run_isolated_session_write(
        "_persist_benchmark_snapshot",
        _write,
        run_id=str(state.get("run_id") or ""),
        benchmark_id=str(state.get("benchmark_id") or ""),
    )


def _benchmark_finalize_state(
    state: dict | None,
    *,
    metadata: dict,
    manifest: dict,
    run_id: str,
    status: str,
    records_read: int,
    events_indexed: int,
    artifacts_total: int,
    artifacts_processed: int,
    artifacts_failed: int,
    effective_parallelism: int,
    performance_profile: str,
    opensearch_bulk: dict,
    problem_report: dict,
    stale_data_error_seen: bool = False,
    unique_violation_seen: bool = False,
) -> dict | None:
    if not state:
        return None
    _benchmark_transition_phase(
        state,
        "completed",
        records_read=records_read,
        records_indexed=events_indexed,
        artifacts_processed=artifacts_processed,
    )
    current_phase = state.pop("current_phase", None)
    if current_phase:
        current_phase["finished_at"] = utc_now().isoformat()
        current_phase["duration_seconds"] = round(max(time.perf_counter() - float(current_phase.get("started_monotonic") or time.perf_counter()), 0.0), 2)
        current_phase.pop("started_monotonic", None)
        state.setdefault("phase_timings", []).append(current_phase)
    parser_breakdown = build_parser_breakdown(manifest, problem_report)
    counts = summarize_benchmark_artifact_counts(manifest, selected_total=int(state.get("selected_total") or 0))
    phase_map = {str(item.get("phase") or ""): dict(item) for item in state.get("phase_timings") or [] if isinstance(item, dict)}
    runtime_status = _benchmark_runtime_status(state)
    benchmark = {
        "benchmark_id": state.get("benchmark_id"),
        "evidence_id": state.get("evidence_id"),
        "case_id": state.get("case_id"),
        "run_id": run_id,
        "label": state.get("label"),
        "notes": state.get("notes"),
        "mode": state.get("mode"),
        "profile": state.get("profile") or performance_profile,
        "status": status,
        "requested_at": state.get("requested_at"),
        "started_at": state.get("started_at"),
        "finished_at": utc_now().isoformat(),
        "effective_parallelism": int(effective_parallelism or 1),
        "effective_cpu_count": int(state.get("effective_cpu_count") or 1),
        "memory_limit_source": state.get("memory_limit_source"),
        "source_evidence_name": state.get("source_evidence_name"),
        "total_duration_seconds": _benchmark_elapsed_seconds(state),
        "time_to_first_artifact_ready": state.get("time_to_first_artifact_ready"),
        "time_to_first_parse_start": state.get("time_to_first_parse_start"),
        "time_to_first_event_indexed": state.get("time_to_first_event_indexed"),
        "extracting_selected_seconds": float((phase_map.get("extracting_selected") or {}).get("duration_seconds") or 0),
        "materialization_seconds": float((phase_map.get("materializing_and_parsing") or {}).get("duration_seconds") or 0),
        "parsing_seconds": float((phase_map.get("parsing") or {}).get("duration_seconds") or 0),
        "indexing_seconds": float((phase_map.get("bulk_indexing") or {}).get("duration_seconds") or 0),
        "db_seconds": float((phase_map.get("reconciliation") or {}).get("duration_seconds") or 0),
        "finalizer_seconds": float((phase_map.get("finalizer") or {}).get("duration_seconds") or 0),
        "debug_export_seconds": 0.0,
        "records_read": int(records_read),
        "records_indexed": int(events_indexed),
        "events_indexed": int(events_indexed),
        "selected_total": int(counts.get("selected_total") or 0),
        "artifacts_total": int(counts.get("artifacts_created_for_run") or artifacts_total),
        "artifacts_created_for_run": int(counts.get("artifacts_created_for_run") or 0),
        "artifacts_processed_for_run": int(counts.get("artifacts_processed_for_run") or 0),
        "artifacts_failed_for_run": int(counts.get("artifacts_failed_for_run") or artifacts_failed),
        "unsupported_count": int(counts.get("unsupported_count") or 0),
        "synthetic_artifacts_count": int(counts.get("synthetic_artifacts_count") or 0),
        "skipped_count": int(counts.get("skipped_count") or 0),
        "artifacts_completed": int(artifacts_processed),
        "artifacts_failed": int(artifacts_failed),
        "problematic_count": int(((problem_report.get("summary") or {}).get("problematic_count")) or 0),
        "records_per_sec": round(records_read / max(_benchmark_elapsed_seconds(state), 0.001), 2) if records_read else 0.0,
        "events_per_sec": round(events_indexed / max(_benchmark_elapsed_seconds(state), 0.001), 2) if events_indexed else 0.0,
        "artifacts_per_sec": round(artifacts_processed / max(_benchmark_elapsed_seconds(state), 0.001), 2) if artifacts_processed else 0.0,
        "metadata_opensearch_delta": int(((metadata.get("ingest_performance") or {}).get("metadata_coherence") or {}).get("delta") or 0),
        "stale_data_error_seen": bool(stale_data_error_seen),
        "unique_violation_seen": bool(unique_violation_seen),
        "timeout_count": sum(1 for item in (problem_report.get("items") or []) if str(item.get("error_type") or "") == "timeout"),
        "slow_artifacts_count": len([item for item in (metadata.get("ingest_performance") or {}).get("slow_artifacts") or [] if item]),
        "phase_timings": list(state.get("phase_timings") or []),
        "resource_samples": list(state.get("resource_samples") or []),
        "by_parser": parser_breakdown,
        "benchmark_options": dict(state.get("benchmark_options") or {}),
        "current_action": runtime_status.get("current_action"),
        "current_selected_path": runtime_status.get("current_selected_path"),
        "last_progress_at": runtime_status.get("last_progress_at"),
        "last_progress_seconds_ago": runtime_status.get("last_progress_seconds_ago"),
        "stalled_phase_warning": runtime_status.get("stalled_phase_warning"),
        "current_phase_stalled": runtime_status.get("current_phase_stalled"),
        "host_identity_conflict_retries": int((((opensearch_bulk.get("host_identity") or {}).get("host_identity_conflict_retries")) or 0)),
    }
    benchmark["bottleneck_report"] = classify_benchmark_bottleneck(benchmark)
    return benchmark


def _merge_host_metadata(evidence_id: str, row_hosts: Counter[str]) -> None:
    if not row_hosts:
        return
    def _write(isolated_db: Session) -> None:
        evidence = isolated_db.get(Evidence, evidence_id)
        if not evidence:
            return
        metadata = dict(evidence.metadata_json or {})
        metadata["detected_hosts"] = sorted(set((metadata.get("detected_hosts") or []) + list(row_hosts.keys())))
        host_counts = Counter({str(key): int(value or 0) for key, value in dict(metadata.get("detected_host_counts") or {}).items()})
        host_counts.update(row_hosts)
        metadata["detected_host_counts"] = dict(host_counts)
        evidence.metadata_json = merge_evidence_metadata(evidence.metadata_json or {}, metadata)
        primary_host = choose_primary_host(
            collection_candidate=metadata.get("collection_host_candidate"),
            host_counts=metadata["detected_host_counts"],
        )
        evidence.detected_host = primary_host.get("host")
        isolated_db.commit()

    _run_isolated_session_write("_merge_host_metadata", _write)


def _parallel_progress_callback(
    tracker: dict,
    tracker_lock: threading.Lock,
    *,
    artifact_id: str,
) -> callable:
    def _callback(payload: dict) -> None:
        with tracker_lock:
            state = tracker.setdefault(artifact_id, {})
            state.update(
                {
                    "records_read": int(payload.get("records_read") or state.get("records_read") or 0),
                    "records_indexed": int(payload.get("records_indexed") or state.get("records_indexed") or 0),
                    "current_label": payload.get("progress_label") or state.get("current_label"),
                    "last_progress_monotonic": time.perf_counter(),
                    "status": "running",
                }
            )

    return _callback


def _evtx_fast_limits_for_run(metadata_or_ref: dict | None) -> dict[str, object]:
    source = metadata_or_ref or {}
    if str(source.get("evtx_profile") or "").strip().lower() != EVTX_PROFILE_FAST_HIGH_VALUE:
        return {}
    limits = normalize_evtx_fast_limits(source.get("evtx_fast_limits"))
    limits["enabled"] = True
    return limits


def _evtx_fast_batch_size(default_batch_size: int | None) -> int:
    return min(max(int(default_batch_size or 0), 1), 100)


def _iter_full_evtx_batches_with_backend(
    *,
    path: Path,
    case_id: str,
    evidence_id: str,
    artifact_id: str,
    artifact_meta: dict,
    batch_size: int,
    progress_cb=None,
    record_timeout_seconds: int = 0,
    requested_backend: object | None = None,
):
    selection = select_evtx_parser_backend(requested_backend)
    if selection.get("selected") == EVTXECMD_BACKEND_CSV:
        try:
            parser = EvtxECmdCsvBackend()
            for result in parser.iter_batches(
                path,
                case_id=case_id,
                evidence_id=evidence_id,
                artifact_id=artifact_id,
                artifact_meta=artifact_meta,
                batch_size=max(int(batch_size or 0), 500),
                progress_cb=progress_cb,
            ):
                result.metadata["evtx_parser_backend"] = EVTXECMD_BACKEND_CSV
                result.metadata["evtx_parser_backend_version"] = selection.get("version") or ""
                result.metadata["evtx_parser_backend_fallback"] = False
                result.metadata["evtx_parser_backend_error"] = None
                yield selection, result
            return
        except Exception as exc:  # noqa: BLE001
            fallback_selection = {
                **selection,
                "selected": EVTX_RAW_PYTHON_BACKEND,
                "fallback": True,
                "error": str(exc),
            }
            parser = EvtxRawParser()
            for result in parser.iter_batches(
                path,
                case_id=case_id,
                evidence_id=evidence_id,
                artifact_id=artifact_id,
                artifact_meta=artifact_meta,
                batch_size=max(int(batch_size or 0), 500),
                progress_cb=progress_cb,
                record_timeout_seconds=record_timeout_seconds,
            ):
                result.metadata["evtx_parser_backend"] = EVTX_RAW_PYTHON_BACKEND
                result.metadata["evtx_parser_backend_version"] = ""
                result.metadata["evtx_parser_backend_fallback"] = True
                result.metadata["evtx_parser_backend_error"] = str(exc)
                yield fallback_selection, result
            return

    parser = EvtxRawParser()
    for result in parser.iter_batches(
        path,
        case_id=case_id,
        evidence_id=evidence_id,
        artifact_id=artifact_id,
        artifact_meta=artifact_meta,
        batch_size=max(int(batch_size or 0), 500),
        progress_cb=progress_cb,
        record_timeout_seconds=record_timeout_seconds,
    ):
        result.metadata["evtx_parser_backend"] = EVTX_RAW_PYTHON_BACKEND
        result.metadata["evtx_parser_backend_version"] = ""
        result.metadata["evtx_parser_backend_fallback"] = bool(selection.get("fallback"))
        result.metadata["evtx_parser_backend_error"] = selection.get("error")
        yield selection, result


def _evtx_partial_entry(
    *,
    artifact_id: str,
    artifact_name: str,
    source_path: str,
    reason: str,
    records_read: int,
    records_indexed: int,
    limits: dict,
) -> dict[str, object]:
    return {
        "artifact_id": artifact_id,
        "file": artifact_name,
        "path": source_path,
        "artifact_type": "windows_event",
        "parser": "evtx_raw",
        "reason": reason,
        "records_read": int(records_read or 0),
        "records_indexed": int(records_indexed or 0),
        "records_remaining_unknown": True,
        "can_continue_later": True,
        "profile": EVTX_PROFILE_FAST_HIGH_VALUE,
        "limits": dict(limits or {}),
        "suggested_action": "Continue EVTX indexing / Full EVTX indexing",
    }


def _make_parallel_evtx_limit_checker(
    *,
    tracker: dict,
    tracker_lock: threading.Lock,
    artifact_id: str,
    limits: dict,
):
    if not limits:
        return None

    def _checker(*, records_read: int, events_indexed: int, elapsed_seconds: float) -> str | None:  # noqa: ARG001
        with tracker_lock:
            state = tracker.setdefault(artifact_id, {})
            state["records_read"] = int(records_read or 0)
            state["last_progress_monotonic"] = time.perf_counter()
            meta = tracker.setdefault("__evtx_fast_meta", {})
            if not meta.get("started_monotonic"):
                meta["started_monotonic"] = time.perf_counter()
            total_read = sum(
                int(item.get("records_read") or 0)
                for key, item in tracker.items()
                if isinstance(item, dict) and not str(key).startswith("__")
            )
            max_total_records = int(limits.get("max_total_records") or 0)
            if max_total_records and total_read >= max_total_records:
                return "max_total_records"
            max_total_seconds = int(limits.get("max_total_seconds") or 0)
            started = float(meta.get("started_monotonic") or time.perf_counter())
            if max_total_seconds and (time.perf_counter() - started) >= max_total_seconds:
                return "max_total_seconds"
        return None

    return _checker


def _evtx_fast_parse_worker(
    output_queue,
    *,
    path: str,
    case_id: str,
    evidence_id: str,
    artifact_id: str,
    artifact_meta: dict,
    batch_size: int,
    record_timeout_seconds: int,
    max_records: int | None,
) -> None:
    parser = EvtxRawParser()

    def _progress(progress: dict) -> None:
        output_queue.put({"type": "progress", "progress": dict(progress or {})})

    try:
        for result in parser.iter_batches(
            Path(path),
            case_id=case_id,
            evidence_id=evidence_id,
            artifact_id=artifact_id,
            artifact_meta=artifact_meta,
            batch_size=max(1, min(int(batch_size or 500), 500)),
            progress_cb=_progress,
            record_timeout_seconds=record_timeout_seconds,
            max_records=max_records,
        ):
            output_queue.put(
                {
                    "type": "batch",
                    "parser_name": result.parser_name,
                    "artifact_type": result.artifact_type,
                    "source_path": result.source_path,
                    "records_read": int(result.records_read or 0),
                    "events": list(result.events or []),
                    "warnings": list(result.warnings or []),
                    "errors": list(result.errors or []),
                    "parser_status": result.parser_status,
                    "metadata": dict(result.metadata or {}),
                }
            )
        output_queue.put({"type": "done"})
    except Exception as exc:  # noqa: BLE001
        output_queue.put({"type": "error", "error": str(exc)})


def _partial_evtx_timeout_result(
    *,
    source_path: str,
    records_read: int,
    reason: str,
    started_monotonic: float,
    limits: dict,
) -> SimpleNamespace:
    warnings = [f"evtx_fast_limit_reached:{reason}"]
    metadata = {
        "parse_duration_ms": int((time.perf_counter() - started_monotonic) * 1000),
        "evtx_files_seen": 1,
        "evtx_files_parsed": 0,
        "evtx_records_read": int(records_read or 0),
        "evtx_records_indexed": 0,
        "evtx_records_failed": 0,
        "channels_seen": [],
        "event_ids_seen": [],
        "classification_counts": {},
        "completed": False,
        "partial": True,
        "limit_reason": reason,
        "evtx_partial": True,
        "records_remaining_unknown": True,
        "evtx_fast_limits": dict(limits or {}),
    }
    metadata["audit"] = {
        "parser_name": "evtx_raw",
        "source_file": source_path,
        "records_read": int(records_read or 0),
        "records_indexed": 0,
        "events_indexed": 0,
        "warnings_count": len(warnings),
        "errors_count": 0,
        "parser_status": "partial",
    }
    return SimpleNamespace(
        parser_name="evtx_raw",
        artifact_type="windows_event",
        source_path=source_path,
        records_read=int(records_read or 0),
        events=[],
        warnings=warnings,
        errors=[],
        parser_status="partial",
        metadata=metadata,
    )


def _iter_evtx_fast_batches_with_hard_timeout(
    *,
    path: Path,
    case_id: str,
    evidence_id: str,
    artifact_id: str,
    artifact_meta: dict,
    batch_size: int,
    progress_cb,
    record_timeout_seconds: int,
    max_records: int | None,
    max_seconds: int | None,
    limits: dict,
    limit_checker=None,
):
    timeout_seconds = max(int(max_seconds or 0), 0)
    if timeout_seconds <= 0:
        parser = EvtxRawParser()
        yield from parser.iter_batches(
            path,
            case_id=case_id,
            evidence_id=evidence_id,
            artifact_id=artifact_id,
            artifact_meta=artifact_meta,
            batch_size=batch_size,
            progress_cb=progress_cb,
            record_timeout_seconds=record_timeout_seconds,
            max_records=max_records,
        )
        return

    ctx = mp.get_context("spawn")
    output_queue = ctx.Queue()
    started = time.perf_counter()
    last_records_read = 0
    process = ctx.Process(
        target=_evtx_fast_parse_worker,
        kwargs={
            "output_queue": output_queue,
            "path": str(path),
            "case_id": case_id,
            "evidence_id": evidence_id,
            "artifact_id": artifact_id,
            "artifact_meta": dict(artifact_meta or {}),
            "batch_size": batch_size,
            "record_timeout_seconds": record_timeout_seconds,
            "max_records": max_records,
        },
    )
    process.start()
    try:
        while True:
            if limit_checker:
                limit_reason = limit_checker(
                    records_read=last_records_read,
                    events_indexed=last_records_read,
                    elapsed_seconds=max(time.perf_counter() - started, 0.001),
                )
                if limit_reason:
                    process.terminate()
                    process.join(timeout=5)
                    yield _partial_evtx_timeout_result(
                        source_path=str(artifact_meta.get("source_path") or path),
                        records_read=last_records_read,
                        reason=str(limit_reason),
                        started_monotonic=started,
                        limits=limits,
                    )
                    return
            if time.perf_counter() - started >= timeout_seconds:
                process.terminate()
                process.join(timeout=5)
                yield _partial_evtx_timeout_result(
                    source_path=str(artifact_meta.get("source_path") or path),
                    records_read=last_records_read,
                    reason="max_seconds_per_file",
                    started_monotonic=started,
                    limits=limits,
                )
                return
            try:
                message = output_queue.get(timeout=1)
            except queue.Empty:
                if not process.is_alive():
                    process.join(timeout=1)
                    yield _partial_evtx_timeout_result(
                        source_path=str(artifact_meta.get("source_path") or path),
                        records_read=last_records_read,
                        reason="max_seconds_per_file",
                        started_monotonic=started,
                        limits=limits,
                    )
                    return
                continue
            message_type = str(message.get("type") or "")
            if message_type == "progress":
                progress = dict(message.get("progress") or {})
                last_records_read = max(last_records_read, int(progress.get("records_read") or 0))
                if progress_cb:
                    progress_cb(progress)
            elif message_type == "batch":
                last_records_read = max(last_records_read, int(message.get("records_read") or 0))
                yield SimpleNamespace(
                    parser_name=message.get("parser_name") or "evtx_raw",
                    artifact_type=message.get("artifact_type") or "windows_event",
                    source_path=message.get("source_path") or str(artifact_meta.get("source_path") or path),
                    records_read=int(message.get("records_read") or 0),
                    events=list(message.get("events") or []),
                    warnings=list(message.get("warnings") or []),
                    errors=list(message.get("errors") or []),
                    parser_status=message.get("parser_status") or "parsed_native",
                    metadata=dict(message.get("metadata") or {}),
                )
            elif message_type == "done":
                process.join(timeout=1)
                return
            elif message_type == "error":
                yield _partial_evtx_timeout_result(
                    source_path=str(artifact_meta.get("source_path") or path),
                    records_read=last_records_read,
                    reason="max_seconds_per_file",
                    started_monotonic=started,
                    limits=limits,
                )
                return
    finally:
        if process.is_alive():
            process.terminate()
            process.join(timeout=5)


def _process_parallel_evtx_artifact(
    *,
    evidence_ref: dict,
    artifact_info: dict,
    artifact_id: str,
    ingest_batch_size: int,
    index_name: str,
    max_bulk_docs: int,
    max_bulk_bytes: int,
    tracker: dict,
    tracker_lock: threading.Lock,
    detections_enabled: bool = True,
) -> dict:
    evidence_ref = _coerce_parallel_evidence_ref(evidence_ref)
    artifact_meta = {
        **artifact_info,
        "detected_host": evidence_ref.get("detected_host"),
        "detected_user": evidence_ref.get("detected_user"),
        "ingest_run_id": evidence_ref.get("ingest_run_id"),
        "contract_version": "v1",
    }
    parser = EvtxRawParser()
    row_hosts = Counter()
    opensearch_bulk = {
        "attempted": False,
        "success": True,
        "timeouts": 0,
        "retries": 0,
        "chunk_size_initial": 0,
        "chunk_size_final": 0,
        "request_timeout": 0,
        "documents_expected": 0,
        "documents_indexed": 0,
        "documents_recovered_after_timeout": 0,
        "warnings": [],
        "host_identity": {
            "upserts": 0,
            "conflicts_recovered": 0,
            "host_identity_conflict_retries": 0,
            "aliases_updated": 0,
        },
    }
    detection_warnings: list = []
    docs_processed_in_artifact = 0
    final_result = None
    evtx_backend_selection: dict | None = None
    batches = 0
    progress_cb = _parallel_progress_callback(tracker, tracker_lock, artifact_id=artifact_id)
    evtx_fast_limits = _evtx_fast_limits_for_run(evidence_ref)
    evtx_limit_checker = _make_parallel_evtx_limit_checker(
        tracker=tracker,
        tracker_lock=tracker_lock,
        artifact_id=artifact_id,
        limits=evtx_fast_limits,
    )

    with tracker_lock:
        state = tracker.setdefault(artifact_id, {})
        state.update(
            {
                "artifact_id": artifact_id,
                "name": artifact_info["name"],
                "source_path": artifact_info["source_path"],
                "status": "running",
                "records_read": 0,
                "records_indexed": 0,
                "current_label": "Starting EVTX parser",
                "started_monotonic": time.perf_counter(),
                "last_progress_monotonic": time.perf_counter(),
            }
        )
    _mark_artifact_row_processing_start(artifact_id)

    try:
        if evtx_fast_limits:
            batch_results = _iter_evtx_fast_batches_with_hard_timeout(
                path=Path(artifact_info["path"]),
                case_id=str(evidence_ref["case_id"]),
                evidence_id=str(evidence_ref["id"]),
                artifact_id=artifact_id,
                artifact_meta=artifact_meta,
                batch_size=_evtx_fast_batch_size(ingest_batch_size),
                progress_cb=progress_cb,
                record_timeout_seconds=max(int(settings.evtx_artifact_stall_seconds or 0), 0),
                max_records=int(evtx_fast_limits.get("max_records_per_file") or 0) if evtx_fast_limits else None,
                max_seconds=int(evtx_fast_limits.get("max_seconds_per_file") or 0) if evtx_fast_limits else None,
                limits=evtx_fast_limits,
            )
            wrapped_batch_results = ((None, item) for item in batch_results)
        else:
            wrapped_batch_results = _iter_full_evtx_batches_with_backend(
                path=Path(artifact_info["path"]),
                case_id=str(evidence_ref["case_id"]),
                evidence_id=str(evidence_ref["id"]),
                artifact_id=artifact_id,
                artifact_meta=artifact_meta,
                batch_size=max(int(ingest_batch_size or 0), 500),
                progress_cb=progress_cb,
                record_timeout_seconds=max(int(settings.evtx_artifact_stall_seconds or 0), 0),
                requested_backend=evidence_ref.get("evtx_parser_backend"),
            )
        for backend_selection, batch_result in wrapped_batch_results:
            if backend_selection:
                evtx_backend_selection = backend_selection
            final_result = batch_result
            batch_documents = batch_result.events
            if not batch_documents:
                continue
            batches += 1
            row_hosts.update(
                normalize_hostname(document.get("host", {}).get("name"))
                for document in batch_documents
                if normalize_hostname(document.get("host", {}).get("name"))
            )
            bulk_report = bulk_index_events_with_report(
                str(evidence_ref["case_id"]),
                batch_documents,
                index=index_name,
                refresh=False,
                max_bulk_docs=max_bulk_docs,
                max_bulk_bytes=max_bulk_bytes,
                apply_host_identity=False,
            )
            _merge_bulk_report(opensearch_bulk, bulk_report, detection_warnings)
            created_count = 0
            warning = None
            if detections_enabled:
                created_count, warning = _safe_create_builtin_detections_isolated(
                    case_id=str(evidence_ref["case_id"]),
                    evidence_id=str(evidence_ref["id"]),
                    artifact_id=artifact_id,
                    artifact_name=artifact_info["name"],
                    documents=batch_documents,
                )
            if warning:
                detection_warnings.append({"artifact": artifact_info["name"], "warning": warning})
            docs_processed_in_artifact += len(batch_documents)
            with tracker_lock:
                state = tracker.setdefault(artifact_id, {})
                state.update(
                    {
                        "records_read": int(batch_result.records_read or docs_processed_in_artifact),
                        "records_indexed": docs_processed_in_artifact,
                        "current_label": f"{batch_result.records_read} records read / {docs_processed_in_artifact} indexed",
                        "batches": batches,
                        "detections_created": int(state.get("detections_created") or 0) + int(created_count or 0),
                        "last_progress_monotonic": time.perf_counter(),
                    }
                )
        if final_result is None:
            final_result = parser.parse(
                artifact_info["path"],
                case_id=str(evidence_ref["case_id"]),
                evidence_id=str(evidence_ref["id"]),
                artifact_id=artifact_id,
                artifact_meta=artifact_meta,
                progress_cb=progress_cb,
            )
            docs_processed_in_artifact = len(final_result.events)
        artifact_meta["raw_parser_status"] = final_result.parser_status
        artifact_meta["raw_parser_warnings"] = list(final_result.warnings)
        artifact_meta["raw_parser_errors"] = list(final_result.errors)
        artifact_meta["ingest_audit"] = final_result.metadata.get("audit") or {
            "parser_name": final_result.parser_name,
            "source_file": final_result.source_path,
            "records_read": final_result.records_read,
            "events_indexed": docs_processed_in_artifact,
            "warnings_count": len(final_result.warnings),
            "errors_count": len(final_result.errors),
            "parser_status": final_result.parser_status,
        }
        ingest_audit = artifact_meta.get("ingest_audit") or {}
        ingest_audit["records_read"] = int(final_result.records_read or docs_processed_in_artifact)
        ingest_audit["records_indexed"] = docs_processed_in_artifact
        ingest_audit["events_indexed"] = docs_processed_in_artifact
        if evtx_fast_limits:
            ingest_audit["evtx_fast_limits"] = dict(evtx_fast_limits)
            ingest_audit["evtx_parser_backend"] = EVTX_RAW_PYTHON_BACKEND
            ingest_audit["evtx_parser_backend_version"] = ""
            ingest_audit["evtx_parser_backend_fallback"] = False
            ingest_audit["evtx_parser_backend_error"] = None
        else:
            ingest_audit["evtx_parser_backend"] = str(final_result.metadata.get("evtx_parser_backend") or (evtx_backend_selection or {}).get("selected") or EVTX_RAW_PYTHON_BACKEND)
            ingest_audit["evtx_parser_backend_version"] = str(final_result.metadata.get("evtx_parser_backend_version") or (evtx_backend_selection or {}).get("version") or "")
            ingest_audit["evtx_parser_backend_fallback"] = bool(final_result.metadata.get("evtx_parser_backend_fallback") or (evtx_backend_selection or {}).get("fallback"))
            ingest_audit["evtx_parser_backend_error"] = final_result.metadata.get("evtx_parser_backend_error") or (evtx_backend_selection or {}).get("error")
        if final_result.parser_status == "partial":
            limit_reason = str(final_result.metadata.get("limit_reason") or "evtx_fast_limit")
            ingest_audit["parser_status"] = "partial"
            ingest_audit["partial"] = True
            ingest_audit["limit_reason"] = limit_reason
            artifact_meta["evtx_partial"] = _evtx_partial_entry(
                artifact_id=artifact_id,
                artifact_name=artifact_info["name"],
                source_path=artifact_info["source_path"],
                reason=limit_reason,
                records_read=int(final_result.records_read or docs_processed_in_artifact),
                records_indexed=docs_processed_in_artifact,
                limits=evtx_fast_limits,
            )
        ingest_audit["duration_seconds"] = round(time.perf_counter() - float((tracker.get(artifact_id) or {}).get("started_monotonic") or time.perf_counter()), 2)
        final_status = _finalize_artifact_status(
            parser_name=artifact_info.get("parser"),
            record_count=docs_processed_in_artifact,
            raw_parser_status=artifact_meta.get("raw_parser_status"),
        )
        _update_artifact_row_isolated(artifact_id, status=final_status, record_count=docs_processed_in_artifact)
        with tracker_lock:
            tracker.setdefault(artifact_id, {}).update(
                {
                    "status": final_status,
                    "records_read": int(final_result.records_read or docs_processed_in_artifact),
                    "records_indexed": docs_processed_in_artifact,
                    "current_label": f"{int(final_result.records_read or docs_processed_in_artifact)} records read / {docs_processed_in_artifact} indexed",
                    "finished_monotonic": time.perf_counter(),
                }
            )
        return {
            "artifact_id": artifact_id,
            "artifact_name": artifact_info["name"],
            "artifact_type": artifact_info["artifact_type"],
            "status": final_status,
            "record_count": docs_processed_in_artifact,
            "records_read": int(final_result.records_read or docs_processed_in_artifact),
            "indexed_count": docs_processed_in_artifact,
            "detection_count": int((tracker.get(artifact_id) or {}).get("detections_created") or 0),
            "row_hosts": row_hosts,
            "ingest_audit": ingest_audit,
            "evtx_partial": artifact_meta.get("evtx_partial"),
            "bulk_report": opensearch_bulk,
            "warnings": detection_warnings,
            "error": None,
            "duration_seconds": round(time.perf_counter() - float((tracker.get(artifact_id) or {}).get("started_monotonic") or time.perf_counter()), 2),
        }
    except Exception as exc:  # noqa: BLE001
        _update_artifact_row_isolated(artifact_id, status="failed")
        with tracker_lock:
            tracker.setdefault(artifact_id, {}).update(
                {
                    "status": "failed",
                    "error": str(exc),
                    "finished_monotonic": time.perf_counter(),
                }
            )
        return {
            "artifact_id": artifact_id,
            "artifact_name": artifact_info["name"],
            "artifact_type": artifact_info["artifact_type"],
            "status": "failed",
            "record_count": 0,
            "records_read": int((tracker.get(artifact_id) or {}).get("records_read") or 0),
            "indexed_count": int((tracker.get(artifact_id) or {}).get("records_indexed") or 0),
            "detection_count": int((tracker.get(artifact_id) or {}).get("detections_created") or 0),
            "row_hosts": row_hosts,
            "ingest_audit": artifact_meta.get("ingest_audit") or {},
            "bulk_report": opensearch_bulk,
            "warnings": detection_warnings,
            "error": str(exc),
            "duration_seconds": round(time.perf_counter() - float((tracker.get(artifact_id) or {}).get("started_monotonic") or time.perf_counter()), 2),
        }


def _process_parallel_normalized_artifact(
    *,
    evidence_ref: dict,
    artifact_info: dict,
    artifact_id: str,
    ingest_batch_size: int,
    index_name: str,
    max_bulk_docs: int,
    max_bulk_bytes: int,
    tracker: dict,
    tracker_lock: threading.Lock,
    detections_enabled: bool = True,
) -> dict:
    evidence_ref = _coerce_parallel_evidence_ref(evidence_ref)
    artifact_meta = {
        **artifact_info,
        "detected_host": evidence_ref.get("detected_host"),
        "detected_user": evidence_ref.get("detected_user"),
        "ingest_run_id": evidence_ref.get("ingest_run_id"),
        "contract_version": "v1",
    }
    opensearch_bulk = {
        "attempted": False,
        "success": True,
        "timeouts": 0,
        "retries": 0,
        "chunk_size_initial": 0,
        "chunk_size_final": 0,
        "request_timeout": 0,
        "documents_expected": 0,
        "documents_indexed": 0,
        "documents_recovered_after_timeout": 0,
        "warnings": [],
        "host_identity": {
            "upserts": 0,
            "conflicts_recovered": 0,
            "host_identity_conflict_retries": 0,
            "aliases_updated": 0,
        },
    }
    detection_warnings: list = []
    row_hosts = Counter()

    with tracker_lock:
        tracker.setdefault(artifact_id, {}).update(
            {
                "artifact_id": artifact_id,
                "name": artifact_info["name"],
                "source_path": artifact_info["source_path"],
                "status": "running",
                "records_read": 0,
                "records_indexed": 0,
                "current_label": "Normalizing artifact",
                "started_monotonic": time.perf_counter(),
                "last_progress_monotonic": time.perf_counter(),
            }
        )
    _mark_artifact_row_processing_start(artifact_id)

    try:
        documents = normalize_file(
            str(evidence_ref["case_id"]),
            str(evidence_ref["id"]),
            artifact_id,
            artifact_info["path"],
            artifact_meta,
            progress_cb=None,
        )
        ingest_audit = artifact_meta.get("ingest_audit")
        if isinstance(ingest_audit, dict):
            ingest_audit["duration_seconds"] = round(time.perf_counter() - float((tracker.get(artifact_id) or {}).get("started_monotonic") or time.perf_counter()), 2)
        docs_processed_in_artifact = 0
        row_hosts = Counter(
            normalize_hostname(document.get("host", {}).get("name"))
            for document in documents
            if normalize_hostname(document.get("host", {}).get("name"))
        )
        batches = math.ceil(len(documents) / ingest_batch_size) if documents and ingest_batch_size else (1 if documents else 0)
        detections_created = 0
        for batch_index in range(max(batches, 1)):
            start = batch_index * ingest_batch_size
            end = start + ingest_batch_size
            batch_documents = documents[start:end]
            if not batch_documents:
                continue
            bulk_report = bulk_index_events_with_report(
                str(evidence_ref["case_id"]),
                batch_documents,
                index=index_name,
                refresh=False,
                max_bulk_docs=max_bulk_docs,
                max_bulk_bytes=max_bulk_bytes,
                apply_host_identity=False,
            )
            _merge_bulk_report(opensearch_bulk, bulk_report, detection_warnings)
            created_count = 0
            warning = None
            if detections_enabled:
                created_count, warning = _safe_create_builtin_detections_isolated(
                    case_id=str(evidence_ref["case_id"]),
                    evidence_id=str(evidence_ref["id"]),
                    artifact_id=artifact_id,
                    artifact_name=artifact_info["name"],
                    documents=batch_documents,
                )
            detections_created += created_count
            if warning:
                detection_warnings.append({"artifact": artifact_info["name"], "warning": warning})
            docs_processed_in_artifact += len(batch_documents)
            with tracker_lock:
                tracker.setdefault(artifact_id, {}).update(
                    {
                        "records_read": len(documents),
                        "records_indexed": docs_processed_in_artifact,
                        "current_label": f"{len(documents)} records read / {docs_processed_in_artifact} indexed",
                        "batches": batches,
                        "detections_created": detections_created,
                        "last_progress_monotonic": time.perf_counter(),
                    }
                )
        final_status = _finalize_artifact_status(
            parser_name=artifact_info.get("parser"),
            record_count=len(documents),
            raw_parser_status=str((artifact_meta.get("raw_parser_status") or "")).lower() or None,
        )
        _update_artifact_row_isolated(artifact_id, status=final_status, record_count=len(documents))
        with tracker_lock:
            tracker.setdefault(artifact_id, {}).update(
                {
                    "status": final_status,
                    "records_read": len(documents),
                    "records_indexed": len(documents),
                    "current_label": f"{len(documents)} records read / {len(documents)} indexed",
                    "finished_monotonic": time.perf_counter(),
                }
            )
        return {
            "artifact_id": artifact_id,
            "artifact_name": artifact_info["name"],
            "artifact_type": artifact_info["artifact_type"],
            "status": final_status,
            "record_count": len(documents),
            "records_read": len(documents),
            "indexed_count": len(documents),
            "detection_count": detections_created,
            "row_hosts": row_hosts,
            "ingest_audit": ingest_audit,
            "bulk_report": opensearch_bulk,
            "warnings": detection_warnings,
            "error": None,
            "duration_seconds": round(time.perf_counter() - float((tracker.get(artifact_id) or {}).get("started_monotonic") or time.perf_counter()), 2),
        }
    except Exception as exc:  # noqa: BLE001
        _update_artifact_row_isolated(artifact_id, status="failed")
        with tracker_lock:
            tracker.setdefault(artifact_id, {}).update(
                {
                    "status": "failed",
                    "error": str(exc),
                    "finished_monotonic": time.perf_counter(),
                }
            )
        return {
            "artifact_id": artifact_id,
            "artifact_name": artifact_info["name"],
            "artifact_type": artifact_info["artifact_type"],
            "status": "failed",
            "record_count": 0,
            "records_read": int((tracker.get(artifact_id) or {}).get("records_read") or 0),
            "indexed_count": int((tracker.get(artifact_id) or {}).get("records_indexed") or 0),
            "detection_count": int((tracker.get(artifact_id) or {}).get("detections_created") or 0),
            "row_hosts": row_hosts,
            "ingest_audit": artifact_meta.get("ingest_audit") or {},
            "bulk_report": opensearch_bulk,
            "warnings": detection_warnings,
            "error": str(exc),
            "duration_seconds": round(time.perf_counter() - float((tracker.get(artifact_id) or {}).get("started_monotonic") or time.perf_counter()), 2),
        }


def _process_parallel_safe_artifact(**kwargs) -> dict:
    artifact_info = kwargs["artifact_info"]
    parser_name = str(artifact_info.get("parser") or "").lower()
    if parser_name == "evtx_raw":
        return _process_parallel_evtx_artifact(**kwargs)
    return _process_parallel_normalized_artifact(**kwargs)


def _schedule_parallel_artifact(
    *,
    executor: ThreadPoolExecutor,
    evidence: Evidence,
    artifact_info: dict,
    ingest_batch_size: int,
    index_name: str,
    max_bulk_docs: int,
    max_bulk_bytes: int,
    tracker: dict,
    tracker_lock: threading.Lock,
    manifest: dict,
    parallel_futures: dict,
    detections_enabled: bool = True,
) -> None:
    evidence_ref = _parallel_evidence_ref(evidence)
    initial_status = _initial_runtime_artifact_status(artifact_info=artifact_info, parallel_safe=True)
    artifact_id = _create_artifact_row_isolated(
        case_id=evidence.case_id,
        evidence_id=evidence.id,
        name=artifact_info["name"],
        artifact_type=artifact_info["artifact_type"],
        source_path=artifact_info["source_path"],
        parser=artifact_info["parser"],
        status=initial_status,
    )
    manifest_artifact = {
        "name": artifact_info["name"],
        "source_path": artifact_info["source_path"],
        "artifact_type": artifact_info["artifact_type"],
        "parser": artifact_info["parser"],
        "profile": artifact_info.get("profile"),
        "record_count": 0,
        "status": initial_status,
        "reason": artifact_info.get("reason"),
        "planned_parser": artifact_info.get("planned_parser"),
        "parallel_safe": True,
    }
    manifest["artifacts"].append(manifest_artifact)
    submit_kwargs = {
        "evidence_ref": evidence_ref,
        "artifact_info": artifact_info,
        "artifact_id": artifact_id,
        "ingest_batch_size": ingest_batch_size,
        "index_name": index_name,
        "max_bulk_docs": max_bulk_docs,
        "max_bulk_bytes": max_bulk_bytes,
        "tracker": tracker,
        "tracker_lock": tracker_lock,
        "detections_enabled": detections_enabled,
    }
    _ensure_parallel_submit_payload_isolation(submit_kwargs)
    future = executor.submit(_process_parallel_safe_artifact, **submit_kwargs)
    parallel_futures[future] = {
        "artifact": artifact_info,
        "artifact_id": artifact_id,
        "manifest_artifact": manifest_artifact,
    }


def _is_raw_collection_with_discovery(evidence: Evidence) -> bool:
    metadata = dict(evidence.metadata_json or {})
    if not metadata.get("velociraptor_discovery"):
        return False
    if evidence.evidence_type == EvidenceType.velociraptor_zip:
        return True
    return str(metadata.get("collection_kind") or "") == "raw_evidence_collection" or str(metadata.get("source_type") or "") == "raw_collection"


def _selected_velociraptor_candidates(evidence: Evidence) -> list[dict] | None:
    metadata = dict(evidence.metadata_json or {})
    selected_ids = set(metadata.get("velociraptor_selected_candidate_ids") or [])
    discovery_candidates = metadata.get("velociraptor_discovery", {}).get("candidates") or []
    if not selected_ids:
        return None
    return [candidate for candidate in discovery_candidates if candidate.get("id") in selected_ids]


def _selected_single_file_artifacts(evidence: Evidence, root: Path) -> list[dict]:
    metadata = dict(evidence.metadata_json or {})
    plan = (metadata.get("ingest_plan") or metadata.get("last_successful_ingest_plan") or {})
    selected_candidates = list(plan.get("selected_candidates") or [])
    artifacts: list[dict] = []
    for candidate in selected_candidates:
        relative_path = str(
            candidate.get("relative_path")
            or candidate.get("source_path")
            or candidate.get("display_name")
            or ""
        ).strip()
        if not relative_path:
            continue
        artifact_path = root if root.is_file() else root / relative_path
        if not artifact_path.exists() and root.is_dir():
            artifact_path = root / Path(relative_path).name
        if not artifact_path.exists():
            continue
        artifacts.append(
            {
                "name": str(candidate.get("display_name") or Path(relative_path).name),
                "source_path": str(candidate.get("source_path") or relative_path),
                "artifact_type": str(candidate.get("artifact_type") or "windows_event"),
                "parser": str(candidate.get("parser") or "evtx_raw"),
                "profile": str(candidate.get("category") or "evtx"),
                "reason": candidate.get("reason"),
                "path": artifact_path,
            }
        )
    return artifacts


def _select_artifacts(evidence: Evidence, root: Path, progress_cb=None) -> list[dict]:
    evidence_type = evidence.evidence_type
    if evidence_type == EvidenceType.velociraptor_zip or _is_raw_collection_with_discovery(evidence):
        return list_velociraptor_artifacts(root, _selected_velociraptor_candidates(evidence), progress_cb=progress_cb)
    if evidence_type in {EvidenceType.kape_archive, EvidenceType.parsed_folder, EvidenceType.linux_triage, EvidenceType.macos_triage}:
        return list_kape_artifacts(root)
    if evidence_type == EvidenceType.evtx:
        selected = _selected_single_file_artifacts(evidence, root)
        if selected:
            return selected
    return list_generic_artifacts(root)


def _candidate_required_paths(candidate: dict) -> list[str]:
    paths = [str(candidate.get("original_path") or "")]
    paths.extend(str(item) for item in (candidate.get("companion_files") or []) if item)
    return [path for path in dict.fromkeys(paths) if path]


def _prepare_velociraptor_selected_staging(
    evidence: Evidence,
    *,
    progress_cb=None,
) -> tuple[Path, list[dict], list[dict], dict]:
    selected = _selected_velociraptor_candidates(evidence) or []
    return _prepare_velociraptor_selected_staging_from_candidates(evidence, selected, progress_cb=progress_cb)


def _prepare_velociraptor_selected_staging_from_candidates(
    evidence: Evidence,
    selected: list[dict],
    *,
    container=None,
    staging_dir: Path | None = None,
    progress_cb=None,
) -> tuple[Path, list[dict], list[dict], dict]:
    if container is None:
        stored_path = Path(evidence.stored_path)
        container = open_evidence_container(stored_path)
    if staging_dir is None:
        staging_dir = evidence_staging_dir(evidence.case_id, evidence.id)
    selected_paths: list[str] = []
    for candidate in selected:
        selected_paths.extend(_candidate_required_paths(candidate))
    selected_paths = [path for path in dict.fromkeys(selected_paths)]
    total_files = len(selected_paths)
    inventory_started = time.perf_counter()
    if hasattr(container, "list_entries"):
        entries_by_path = {entry.path: entry for entry in container.list_entries()}
    else:
        entries_by_path = {}
    inventory_seconds = time.perf_counter() - inventory_started
    metadata_started = time.perf_counter()
    metadata_map = {
        item: entries_by_path.get(item) if entries_by_path else container.get_metadata(item)
        for item in selected_paths
    }
    metadata_lookup_seconds = time.perf_counter() - metadata_started
    total_bytes = sum(metadata.size for metadata in metadata_map.values() if metadata)
    extracted_files: list[dict] = []
    bytes_materialized = 0
    files_reused = 0
    files_materialized = 0
    extraction_errors = 0
    paths_to_extract: list[str] = []
    extracted_result_map: dict[str, dict] = {}

    for index, source_path in enumerate(selected_paths, start=1):
        metadata = metadata_map.get(source_path)
        try:
            local_candidate = staging_dir / str(sanitize_relative_path(source_path))
        except Exception:
            local_candidate = None
        if local_candidate and local_candidate.exists() and local_candidate.is_file() and (not metadata or local_candidate.stat().st_size == metadata.size):
            files_reused += 1
            files_materialized += 1
            if metadata:
                bytes_materialized += metadata.size
            extracted_result_map[source_path] = {
                "path": source_path,
                "ignored": False,
                "reason": None,
                "size": metadata.size if metadata else 0,
                "status": "reused",
                "local_path": str(local_candidate),
            }
            if progress_cb and (index == 1 or index == total_files or index % 25 == 0):
                progress_cb(
                    {
                        "processed_files": index,
                        "total_files": total_files,
                        "processed_bytes": bytes_materialized,
                        "total_bytes": total_bytes,
                        "current_path": source_path,
                        "current_action": "skipping_existing",
                        "files_materialized": files_materialized,
                        "files_skipped_existing": files_reused,
                        "extraction_errors": extraction_errors,
                    }
                )
        else:
            paths_to_extract.append(source_path)

    if progress_cb and paths_to_extract:
        progress_cb(
            {
                "processed_files": files_materialized,
                "total_files": total_files,
                "processed_bytes": bytes_materialized,
                "total_bytes": total_bytes,
                "current_path": paths_to_extract[0],
                "current_action": "extracting_archive_batch",
                "files_materialized": files_materialized,
                "files_skipped_existing": files_reused,
                "extraction_errors": extraction_errors,
            }
        )
    batch_started = time.perf_counter()
    batch_results = container.extract_entries(paths_to_extract, staging_dir) if paths_to_extract else []
    batch_extract_seconds = time.perf_counter() - batch_started
    for result in batch_results:
        source_path = str(result.get("path") or "")
        metadata = metadata_map.get(source_path)
        normalized = {
            "path": source_path,
            "ignored": False,
            "reason": None if result.get("status") == "extracted" else result.get("error"),
            "size": metadata.size if metadata else 0,
            "status": result.get("status") or "failed",
            "local_path": result.get("local_path"),
        }
        extracted_result_map[source_path] = normalized
        if normalized["status"] == "extracted":
            files_materialized += 1
            if metadata:
                bytes_materialized += metadata.size
        else:
            extraction_errors += 1

    def should_emit_selected_progress(index: int, status: str) -> bool:
        return index == 1 or index == total_files or index % 25 == 0 or status == "failed"

    verify_started = time.perf_counter()
    for index, source_path in enumerate(selected_paths, start=1):
        current_result = extracted_result_map.get(source_path) or {
            "path": source_path,
            "ignored": False,
            "reason": "missing_extraction_result",
            "size": metadata_map.get(source_path).size if metadata_map.get(source_path) else 0,
            "status": "failed",
            "local_path": None,
        }
        extracted_files.append(current_result)
        if progress_cb and should_emit_selected_progress(index, str(current_result.get("status") or "")):
            progress_cb(
                {
                    "processed_files": index,
                    "total_files": total_files,
                    "processed_bytes": bytes_materialized,
                    "total_bytes": total_bytes,
                    "current_path": source_path,
                    "current_action": "verifying_candidate" if current_result["status"] == "reused" else "extracting_archive_entry",
                    "files_materialized": files_materialized,
                    "files_skipped_existing": files_reused,
                    "extraction_errors": extraction_errors,
                }
            )

    extracted_map = {entry["path"]: entry["local_path"] for entry in extracted_files if entry["status"] == "extracted" and entry["local_path"]}
    extracted_map.update({entry["path"]: entry["local_path"] for entry in extracted_files if entry["status"] == "reused" and entry["local_path"]})
    prepared_candidates: list[dict] = []
    for candidate in selected:
        selected_candidate = dict(candidate)
        primary_path = str(candidate.get("original_path") or "")
        selected_candidate["local_staging_path"] = extracted_map.get(primary_path)
        selected_candidate["local_path"] = extracted_map.get(primary_path) or selected_candidate.get("local_path") or ""
        selected_candidate["extraction_status"] = "extracted" if primary_path in extracted_map else "failed"
        prepared_candidates.append(selected_candidate)

    verify_seconds = time.perf_counter() - verify_started
    stats = {
        "selected_files_total": total_files,
        "selected_files_extracted": sum(1 for entry in extracted_files if entry["status"] == "extracted"),
        "selected_files_reused": sum(1 for entry in extracted_files if entry["status"] == "reused"),
        "selected_files_materialized": sum(1 for entry in extracted_files if entry["status"] in {"extracted", "reused"}),
        "bytes_extracted": sum((entry.get("size") or 0) for entry in extracted_files if entry["status"] == "extracted"),
        "bytes_materialized": bytes_materialized,
        "extraction_errors": extraction_errors,
        "sqlite_files_extracted": sum(1 for entry in extracted_files if Path(entry["path"]).name.lower() in {"history", "places.sqlite"} and entry["status"] in {"extracted", "reused"}),
        "wal_shm_files_extracted": sum(1 for entry in extracted_files if Path(entry["path"]).name.lower().endswith(("-wal", "-shm")) and entry["status"] in {"extracted", "reused"}),
        "inventory_seconds": round(inventory_seconds, 4),
        "metadata_lookup_seconds": round(metadata_lookup_seconds, 4),
        "selected_materialization_seconds": round(batch_extract_seconds, 4),
        "selected_verification_seconds": round(verify_seconds, 4),
        "extractor_strategy": f"{getattr(container, 'type', 'unknown')}_batch_selected",
        "paths_to_extract": len(paths_to_extract),
    }
    return staging_dir, prepared_candidates, extracted_files, stats


def _normalize_velociraptor_browser_rows(
    case_id: str,
    evidence_id: str,
    artifact_id: str,
    rows: list[dict],
    artifact_meta: dict,
    *,
    collection_id: str,
    original_path: str,
    normalized_windows_path: str | None,
    parser_status: str | None,
    browser_audit: BrowserAudit,
) -> list[dict]:
    documents: list[dict] = []
    for row in rows:
        document = base_document(case_id, evidence_id, artifact_id, row, artifact_meta)
        document["raw"] = dict(row)
        document["raw_summary"] = build_raw_summary(row)
        normalize_browser_event(document, row, artifact_meta, browser_audit)
        document["velociraptor"].update(
            {
                "collection_id": collection_id,
                "original_path": original_path,
                "normalized_windows_path": normalized_windows_path,
                "artifact_category": "browser",
                "parser_status": parser_status,
            }
        )
        documents.append(document)
    return documents


def _browser_audit_rollups(documents: list[dict]) -> tuple[dict[str, int], dict[str, int], dict[str, int], dict[str, int], dict[str, int], dict[str, int]]:
    by_browser: Counter[str] = Counter()
    by_artifact_type: Counter[str] = Counter()
    by_event_type: Counter[str] = Counter()
    danger_type_counts: Counter[str] = Counter()
    data_quality_counts: Counter[str] = Counter()
    suspicious_reason_counts: Counter[str] = Counter()
    for document in documents:
        browser = document.get("browser", {}) or {}
        event = document.get("event", {}) or {}
        if browser.get("browser"):
            by_browser[str(browser.get("browser")).lower()] += 1
        if browser.get("artifact_type"):
            by_artifact_type[str(browser.get("artifact_type"))] += 1
        if event.get("type"):
            by_event_type[str(event.get("type"))] += 1
        if browser.get("danger_type"):
            danger_type_counts[str(browser.get("danger_type"))] += 1
        for quality in document.get("data_quality") or []:
            data_quality_counts[str(quality)] += 1
        for reason in document.get("suspicious_reasons") or []:
            suspicious_reason_counts[str(reason)] += 1
    return (
        dict(sorted(by_browser.items())),
        dict(sorted(by_artifact_type.items())),
        dict(sorted(by_event_type.items())),
        dict(sorted(danger_type_counts.items())),
        dict(sorted(data_quality_counts.items())),
        dict(sorted(suspicious_reason_counts.items())),
    )


def _manifest_for_evidence(evidence: Evidence) -> dict:
    manifest_path = evidence_manifest_path(evidence.case_id, evidence.id)
    if manifest_path.exists():
        import json

        return json.loads(manifest_path.read_text(encoding="utf-8"))
    return default_manifest(evidence)


def _builtin_detection_from_document(document: dict) -> tuple[str, str, str, str] | None:
    tags = set(document.get("tags", []))
    severity = document.get("event", {}).get("severity", "info")
    event_type = str((document.get("event", {}) or {}).get("type") or "")
    suspicious_reasons = " ".join(document.get("suspicious_reasons", [])).lower()
    powershell_command = str((document.get("powershell", {}) or {}).get("command") or "").lower()
    execution = document.get("execution", {}) or {}
    process = document.get("process", {}) or {}
    file_data = document.get("file", {}) or {}
    disabled_rules = set(load_builtin_detection_overrides().get("disabled_rules", []))
    if event_type in {"program_observed", "installed_program_observed", "execution_candidate"} and str((document.get("artifact", {}) or {}).get("type") or "") == "amcache":
        target_path = str(file_data.get("path") or process.get("path") or "").lower()
        publisher = str(process.get("publisher") or "").strip()
        if "defender_correlated" in tags:
            return None if "program_observed_and_detected_by_defender" in disabled_rules else ("program_observed_and_detected_by_defender", "Program Observed And Detected By Defender", severity, "Program observed in Amcache later matched a Defender detection.")
        if "executed_after_download" in tags or "prefetch_correlated" in tags or "evtx_correlated" in tags:
            return None if "program_observed_and_executed" in disabled_rules else ("program_observed_and_executed", "Program Observed And Executed", severity, "Program observed in Amcache later matched stronger execution evidence.")
        if "download_correlated" in tags:
            return None if "downloaded_program_observed_in_amcache" in disabled_rules else ("downloaded_program_observed_in_amcache", "Downloaded Program Observed In Amcache", severity, "Downloaded file was later observed in Amcache.")
        if "remote_access_tool" in tags:
            return None if "remote_access_tool_observed" in disabled_rules else ("remote_access_tool_observed", "Remote Access Tool Observed", severity, "Remote access tooling observed in Amcache/AppCompat artifact.")
        if "lolbin" in tags:
            return None if "appcompat_lolbin_observed" in disabled_rules else ("appcompat_lolbin_observed", "AppCompat LOLBin Observed", severity, "LOLBin observed in Amcache/AppCompat artifact.")
        if "double_extension" in tags:
            return None if "double_extension_program_observed" in disabled_rules else ("double_extension_program_observed", "Double Extension Program Observed", severity, "Program observed with suspicious double extension in execution artifact.")
        if "suspicious_path" in tags and "\\downloads\\" in target_path:
            return None if "amcache_executable_in_downloads" in disabled_rules else ("amcache_executable_in_downloads", "Amcache Executable In Downloads", severity, "Amcache observed an executable in Downloads.")
        if "suspicious_path" in tags and "\\appdata\\" in target_path:
            return None if "amcache_executable_in_appdata" in disabled_rules else ("amcache_executable_in_appdata", "Amcache Executable In AppData", severity, "Amcache observed an executable in AppData.")
        if "suspicious_path" in tags and not publisher:
            return None if "unsigned_or_unknown_publisher_in_suspicious_path" in disabled_rules else ("unsigned_or_unknown_publisher_in_suspicious_path", "Unsigned Or Unknown Publisher In Suspicious Path", severity, "Program in suspicious path has empty or unknown publisher metadata.")
    if event_type in {"shimcache_entry", "appcompat_entry", "recentfilecache_entry"} or (
        event_type == "execution_candidate" and str((document.get("artifact", {}) or {}).get("type") or "") in {"shimcache", "appcompat"}
    ):
        if "remote_access_tool" in tags:
            return None if "remote_access_tool_observed" in disabled_rules else ("remote_access_tool_observed", "Remote Access Tool Observed", severity, "Remote access tooling observed in AppCompat artifact.")
        if "lolbin" in tags:
            return None if "appcompat_lolbin_observed" in disabled_rules else ("appcompat_lolbin_observed", "AppCompat LOLBin Observed", severity, "LOLBin observed in AppCompat artifact.")
        if "double_extension" in tags:
            return None if "double_extension_program_observed" in disabled_rules else ("double_extension_program_observed", "Double Extension Program Observed", severity, "Program observed with suspicious double extension in execution artifact.")
        if "suspicious_path" in tags:
            return None if "shimcache_suspicious_path" in disabled_rules else ("shimcache_suspicious_path", "ShimCache Suspicious Path", severity, "ShimCache/AppCompat entry points to a suspicious path.")
    if event_type == "registry_run_key" and ("suspicious" in tags or suspicious_reasons):
        if "unc_path" in tags or "network_path" in tags:
            return None if "registry_persistence_unc_path" in disabled_rules else ("registry_persistence_unc_path", "Registry persistence via UNC path", severity, "Registry persistence points to a UNC/network path.")
        return None if "suspicious_run_key_command" in disabled_rules else ("suspicious_run_key_command", "Suspicious Run Key Command", severity, "Suspicious Run key persistence observed in normalized event.")
    if event_type in {"registry_service", "service"} and ("suspicious" in tags or suspicious_reasons):
        if "unc_path" in tags or "network_path" in tags:
            return None if "registry_persistence_unc_path" in disabled_rules else ("registry_persistence_unc_path", "Registry persistence via UNC path", severity, "Registry service configuration points to a UNC/network path.")
        return None if "service_imagepath_suspicious" in disabled_rules else ("service_imagepath_suspicious", "Service ImagePath in suspicious path", severity, "Registry service configuration uses a suspicious ImagePath or ServiceDll.")
    if event_type == "run_mru_command" and ("suspicious" in tags or suspicious_reasons):
        return None if "run_mru_suspicious_command" in disabled_rules else ("run_mru_suspicious_command", "RunMRU Suspicious Command", severity, "Suspicious command observed in RunMRU history.")
    if event_type == "rdp_mru":
        return None if "rdp_mru_entry" in disabled_rules else ("rdp_mru_entry", "RDP MRU Entry", severity, "RDP client history entry observed in the registry.")
    if event_type in {"usb_device_seen", "mounted_device", "usb_connected", "usb_disconnected", "usb_installed", "usb_observed"}:
        return None if "usb_device_seen" in disabled_rules else ("usb_device_seen", "USB Device Seen", severity, "USB-related registry artifact observed.")
    if event_type == "userassist_execution" and "lolbin" in tags:
        return None if "userassist_lolbin_execution" in disabled_rules else ("userassist_lolbin_execution", "UserAssist LOLBin Execution", severity, "UserAssist indicates execution of a LOLBin or sensitive utility.")
    if event_type in {"bam_execution", "dam_execution"} and "suspicious_path" in tags:
        return None if "bam_execution_suspicious_path" in disabled_rules else ("bam_execution_suspicious_path", "BAM Execution from Suspicious Path", severity, "BAM/DAM indicates execution from a suspicious user-writable path.")
    if event_type == "alternate_data_stream":
        return None if "alternate_data_stream_detected" in disabled_rules else ("alternate_data_stream_detected", "Alternate Data Stream Detected", severity, "NTFS alternate data stream observed in filesystem evidence.")
    if event_type == "file_downloaded":
        target_path = str((document.get("file", {}) or {}).get("path") or "").lower()
        browser_tags = tags
        if "defender_correlated" in browser_tags:
            return None if "browser_download_detected_by_defender" in disabled_rules else ("browser_download_detected_by_defender", "Browser Download Detected By Defender", severity, "Downloaded file was later matched to a Defender detection.")
        if "executed_after_download" in browser_tags:
            return None if "downloaded_file_later_executed" in disabled_rules else ("downloaded_file_later_executed", "Downloaded File Later Executed", severity, "Downloaded file later matched execution evidence.")
        if any("double extension" in reason.lower() for reason in document.get("suspicious_reasons", [])):
            return None if "double_extension_download" in disabled_rules else ("double_extension_download", "Double Extension Download", severity, "Downloaded file has a suspicious double extension.")
        if "script_download" in browser_tags:
            return None if "script_downloaded" in disabled_rules else ("script_downloaded", "Script Downloaded", severity, "Browser download points to a script-like file.")
        if "executable_download" in browser_tags:
            return None if "executable_downloaded" in disabled_rules else ("executable_downloaded", "Executable Downloaded", severity, "Browser download points to an executable or installer.")
        if "archive_download" in browser_tags and "cloud_storage" in browser_tags:
            return None if "archive_downloaded_from_file_sharing" in disabled_rules else ("archive_downloaded_from_file_sharing", "Archive Downloaded From File Sharing", severity, "Archive download came from a file-sharing or cloud-storage service.")
        if "suspicious_path" in browser_tags and any(token in target_path for token in ["\\downloads\\", "\\appdata\\", "\\temp\\", "\\desktop\\", "\\users\\public\\", "\\programdata\\"]):
            return None if "browser_download_to_suspicious_path" in disabled_rules else ("browser_download_to_suspicious_path", "Browser Download To Suspicious Path", severity, "Browser download landed in a suspicious user-writable path.")
        if any("raw ip address" in reason.lower() for reason in document.get("suspicious_reasons", [])):
            return None if "download_from_raw_ip" in disabled_rules else ("download_from_raw_ip", "Download From Raw IP", severity, "Browser download originated from a raw IP URL.")
    if event_type in {"browser_history", "browser_visit"}:
        if "paste_site" in tags:
            return None if "browser_visit_to_paste_site" in disabled_rules else ("browser_visit_to_paste_site", "Browser Visit To Paste Site", severity, "Browser history includes a paste site visit.")
        if "remote_access_tool" in tags:
            return None if "browser_visit_to_remote_access_tool" in disabled_rules else ("browser_visit_to_remote_access_tool", "Browser Visit To Remote Access Tool", severity, "Browser history includes a remote access tooling site visit.")
    if event_type in {"srum_network_usage", "srum_application_resource_usage", "srum_energy_usage", "srum_record", "network_usage", "app_resource_usage", "energy_usage", "network_connectivity_observed"}:
        if "browser_download_correlated" in tags and "downloaded_and_network_active" not in tags:
            return None if "srum_browser_download_correlation" in disabled_rules else ("srum_browser_download_correlation", "SRUM Browser Download Correlation", severity, "SRUM application usage correlates with a browser-downloaded program.")
        if "downloaded_and_network_active" in tags or "browser_download_correlated" in tags:
            return None if "srum_downloaded_program_network_active" in disabled_rules else ("srum_downloaded_program_network_active", "SRUM Downloaded Program Network Active", severity, "Program seen in browser download evidence later showed SRUM network activity.")
        if "high_upload" in tags and "possible_exfiltration" in tags:
            return None if "srum_possible_exfiltration_candidate" in disabled_rules else ("srum_possible_exfiltration_candidate", "SRUM Possible Exfiltration Candidate", severity, "SRUM observed high outbound traffic with an exfiltration-like ratio.")
        if "high_upload" in tags:
            return None if "srum_high_upload" in disabled_rules else ("srum_high_upload", "SRUM High Upload", severity, "SRUM observed high outbound network volume for one application.")
        if "remote_access_tool" in tags:
            return None if "srum_remote_access_tool_network_usage" in disabled_rules else ("srum_remote_access_tool_network_usage", "SRUM Remote Access Tool Network Usage", severity, "SRUM observed network usage by a remote access tool.")
        if "file_transfer_tool" in tags:
            return None if "srum_file_transfer_tool_network_usage" in disabled_rules else ("srum_file_transfer_tool_network_usage", "SRUM File Transfer Tool Network Usage", severity, "SRUM observed network usage by a file transfer or sync tool.")
        if "lolbin_network" in tags:
            return None if "srum_lolbin_network_usage" in disabled_rules else ("srum_lolbin_network_usage", "SRUM LOLBin Network Usage", severity, "SRUM observed network usage by a LOLBin.")
        if "suspicious_path" in tags:
            return None if "srum_suspicious_path_network_usage" in disabled_rules else ("srum_suspicious_path_network_usage", "SRUM Suspicious Path Network Usage", severity, "SRUM observed network activity from a suspicious user-writable path.")
    if event_type in {"scheduled_task_definition", "scheduled_task_com_handler", "scheduled_task"}:
        if "browser_download_correlated" in tags:
            return None if "downloaded_file_persisted_as_scheduled_task" in disabled_rules else ("downloaded_file_persisted_as_scheduled_task", "Downloaded File Persisted As Scheduled Task", severity, "A browser-downloaded file appears configured as a scheduled task action.")
        if "encoded_command" in tags:
            return None if "scheduled_task_powershell_encoded" in disabled_rules else ("scheduled_task_powershell_encoded", "Scheduled Task PowerShell Encoded", severity, "Scheduled task runs PowerShell with encoded command.")
        if "com_handler" in tags or "com_handler_task" in (document.get("data_quality") or []):
            return None if "scheduled_task_com_handler" in disabled_rules else ("scheduled_task_com_handler", "Scheduled Task COM Handler", severity, "Scheduled task uses a COM handler action.")
        if "unc_path" in tags or "network_path" in tags:
            return None if "scheduled_task_unc_path" in disabled_rules else ("scheduled_task_unc_path", "Scheduled Task UNC Path", severity, "Scheduled task points to a UNC path.")
        if "lolbin" in tags:
            return None if "scheduled_task_lolbin" in disabled_rules else ("scheduled_task_lolbin", "Scheduled Task LOLBin", severity, "Scheduled task uses a LOLBin as its action.")
        if "hidden_task" in tags and document.get("persistence", {}).get("enabled") is True and ("suspicious_path" in tags or "encoded_command" in tags or "lolbin" in tags):
            return None if "scheduled_task_hidden_and_enabled" in disabled_rules else ("scheduled_task_hidden_and_enabled", "Scheduled Task Hidden And Enabled", severity, "Scheduled task is hidden, enabled, and suspicious.")
        if "suspicious_path" in tags:
            task_path = str((document.get("file", {}) or {}).get("path") or "").lower()
            if "\\appdata\\" in task_path:
                return None if "scheduled_task_runs_from_appdata" in disabled_rules else ("scheduled_task_runs_from_appdata", "Scheduled Task Runs From AppData", severity, "Scheduled task runs a command from AppData.")
            if "\\temp\\" in task_path:
                return None if "scheduled_task_runs_from_temp" in disabled_rules else ("scheduled_task_runs_from_temp", "Scheduled Task Runs From Temp", severity, "Scheduled task runs a command from Temp.")
    if event_type in {"file_recycled", "file_deleted"} and str((document.get("artifact", {}) or {}).get("type") or "") == "recycle_bin":
        recycle = document.get("recycle", {}) or {}
        original_path = str(recycle.get("original_path") or (document.get("file", {}) or {}).get("path") or "").lower()
        original_name = str(recycle.get("original_file_name") or (document.get("file", {}) or {}).get("name") or "").lower()
        if "defender_correlated" in tags or "deleted_detected_file" in tags:
            return None if "recycle_bin_deleted_defender_detection" in disabled_rules else ("recycle_bin_deleted_defender_detection", "Recycle Bin Deleted Defender Detection", severity, "Recycle Bin item matches a Defender-detected file.")
        if "browser_download_correlated" in tags or "deleted_download" in tags:
            return None if "recycle_bin_deleted_download" in disabled_rules else ("recycle_bin_deleted_download", "Recycle Bin Deleted Download", severity, "Recycle Bin item matches a browser-downloaded file.")
        if "content_missing" in tags or "cleanup_candidate" in tags:
            return None if "recycle_bin_content_missing" in disabled_rules else ("recycle_bin_content_missing", "Recycle Bin Content Missing", severity, "Recycle Bin metadata exists but the recycled content file is missing.")
        if "double_extension" in tags:
            return None if "recycle_bin_double_extension_deleted" in disabled_rules else ("recycle_bin_double_extension_deleted", "Recycle Bin Double Extension Deleted", severity, "Recycle Bin item has a suspicious double extension.")
        if "executable_deleted" in tags:
            return None if "recycle_bin_executable_deleted" in disabled_rules else ("recycle_bin_executable_deleted", "Recycle Bin Executable Deleted", severity, "Executable moved to Recycle Bin.")
        if "script_deleted" in tags:
            return None if "recycle_bin_script_deleted" in disabled_rules else ("recycle_bin_script_deleted", "Recycle Bin Script Deleted", severity, "Script moved to Recycle Bin.")
        if any(token in original_path or token in original_name for token in ["mimikatz", "rclone", "anydesk", "teamviewer", "ngrok", "payload", "credential", "lsass", "dump", "runme"]):
            return None if "recycle_bin_suspicious_tool_deleted" in disabled_rules else ("recycle_bin_suspicious_tool_deleted", "Recycle Bin Suspicious Tool Deleted", severity, "Potential tool, payload, or credential-related file moved to Recycle Bin.")
        if "user_writable_path" in tags or any(token in original_path for token in ["\\downloads\\", "\\desktop\\", "\\temp\\", "\\appdata\\", "\\users\\public\\", "\\programdata\\"]):
            return None if "recycle_bin_deleted_file_in_user_writable_path" in disabled_rules else ("recycle_bin_deleted_file_in_user_writable_path", "Recycle Bin Deleted File In User Writable Path", severity, "Recycle Bin item originated from a user-writable suspicious path.")
    if event_type in {"shellbag_folder_access", "folder_opened", "folder_observed"} or document.get("artifact", {}).get("type") == "shellbags":
        shellbag = document.get("shellbag", {}) or {}
        shellbag_path = str(shellbag.get("path") or (document.get("file", {}) or {}).get("path") or "").lower()
        if "browser_download_correlated" in tags or "folder_related_to_deleted_download" in tags:
            return None if "shellbag_folder_related_to_deleted_download" in disabled_rules else ("shellbag_folder_related_to_deleted_download", "Shellbag Folder Related To Deleted Download", severity, "Shellbag path matched the parent folder of a downloaded file later deleted or recycled.")
        if "deleted_or_missing_candidate" in tags or bool(shellbag.get("is_deleted")):
            return None if "shellbag_deleted_or_missing_folder_candidate" in disabled_rules else ("shellbag_deleted_or_missing_folder_candidate", "Shellbag Deleted Or Missing Folder Candidate", severity, "Shellbag entry appears to reference a deleted or missing folder.")
        if "cloud_sync" in tags:
            return None if "shellbag_cloud_sync_folder" in disabled_rules else ("shellbag_cloud_sync_folder", "Shellbag Cloud Sync Folder", severity, "Shellbag references a cloud sync folder.")
        if "network_path" in tags or bool(shellbag.get("is_network_path")):
            return None if "shellbag_network_share_accessed" in disabled_rules else ("shellbag_network_share_accessed", "Shellbag Network Share Accessed", severity, "Shellbag references a UNC or network share path.")
        if "usb_path" in tags or bool(shellbag.get("is_usb_path")):
            return None if "shellbag_usb_folder_accessed" in disabled_rules else ("shellbag_usb_folder_accessed", "Shellbag USB Folder Accessed", severity, "Shellbag references a removable or USB-backed path.")
        if any(token in shellbag_path for token in ["mimikatz", "rclone", "payload", "anydesk", "teamviewer", "ngrok", "credentials", "dump", "lsass", "exfil", "\\tools\\"]):
            return None if "shellbag_suspicious_tool_folder" in disabled_rules else ("shellbag_suspicious_tool_folder", "Shellbag Suspicious Tool Folder", severity, "Shellbag references a folder name associated with tools, payloads, or credential material.")
        if "suspicious_path" in tags and "user_writable_path" in tags:
            return None if "shellbag_user_writable_suspicious_path" in disabled_rules else ("shellbag_user_writable_suspicious_path", "Shellbag User Writable Suspicious Path", severity, "Shellbag references a suspicious user-writable folder path.")
    if event_type in {"jumplist_recent_item", "file_opened", "document_opened", "folder_opened", "program_or_script_opened"} and document.get("artifact", {}).get("type") == "jumplist":
        jumplist = document.get("jumplist", {}) or {}
        jump_path = str(jumplist.get("effective_path") or (document.get("file", {}) or {}).get("path") or "").lower()
        arguments = str(jumplist.get("arguments") or "").lower()
        if "browser_download_correlated" in tags or "downloaded_file_opened" in tags:
            return None if "jumplist_downloaded_file_opened" in disabled_rules else ("jumplist_downloaded_file_opened", "JumpList Downloaded File Opened", severity, "JumpList item matched a browser-downloaded file.")
        if "recycle_bin_correlated" in tags or "deleted_file_was_opened" in tags:
            return None if "jumplist_deleted_file_was_opened" in disabled_rules else ("jumplist_deleted_file_was_opened", "JumpList Deleted File Was Opened", severity, "JumpList item matched a file later deleted or recycled.")
        if "double_extension" in tags:
            return None if "jumplist_double_extension" in disabled_rules else ("jumplist_double_extension", "JumpList Double Extension", severity, "JumpList references a suspicious double-extension file.")
        if "network_path" in tags or "unc_path" in tags:
            return None if "jumplist_network_share_accessed" in disabled_rules else ("jumplist_network_share_accessed", "JumpList Network Share Accessed", severity, "JumpList references a UNC or network share path.")
        if "removable_media" in tags or "usb_candidate" in tags:
            return None if "jumplist_usb_item_accessed" in disabled_rules else ("jumplist_usb_item_accessed", "JumpList USB Item Accessed", severity, "JumpList references a removable or USB-backed path.")
        if any(token in jump_path for token in ["mimikatz", "rclone", "payload", "anydesk", "teamviewer", "ngrok", "credentials", "dump", "lsass", "exfil", "\\tools\\"]):
            return None if "jumplist_suspicious_tool_item" in disabled_rules else ("jumplist_suspicious_tool_item", "JumpList Suspicious Tool Item", severity, "JumpList references a file name associated with suspicious tooling or payloads.")
        if any(token in arguments for token in ["-enc", "-encodedcommand", "bypass", "powershell", "cmd /c", "mshta", "rundll32", "regsvr32"]):
            return None if "jumplist_suspicious_command_arguments" in disabled_rules else ("jumplist_suspicious_command_arguments", "JumpList Suspicious Command Arguments", severity, "JumpList item contains suspicious command arguments.")
        if "user_writable_path" in tags and str((document.get("file", {}) or {}).get("extension") or "").lower() in {".exe", ".dll", ".scr", ".msi"}:
            return None if "jumplist_executable_in_user_writable_path" in disabled_rules else ("jumplist_executable_in_user_writable_path", "JumpList Executable In User Writable Path", severity, "JumpList references an executable in a suspicious user-writable path.")
        if "user_writable_path" in tags and str((document.get("file", {}) or {}).get("extension") or "").lower() in {".ps1", ".bat", ".cmd", ".vbs", ".js", ".jse", ".wsf", ".hta"}:
            return None if "jumplist_script_in_user_writable_path" in disabled_rules else ("jumplist_script_in_user_writable_path", "JumpList Script In User Writable Path", severity, "JumpList references a script in a suspicious user-writable path.")
    if event_type in {"powershell_console_history", "powershell_transcript_command", "powershell_script_file_observed"}:
        path_blob = str((document.get("file", {}) or {}).get("path") or "").lower()
        if "credential_access" in tags:
            return None if "powershell_credential_access_keywords" in disabled_rules else ("powershell_credential_access_keywords", "PowerShell Credential Access Keywords", severity, "PowerShell artifact references credential access or LSASS-related keywords.")
        if "defender_tampering" in tags:
            return None if "powershell_defender_tampering" in disabled_rules else ("powershell_defender_tampering", "PowerShell Defender Tampering", severity, "PowerShell artifact contains Defender tampering commands.")
        if "download_cradle" in tags and "raw_ip_url" in tags:
            return None if "powershell_download_from_raw_ip" in disabled_rules else ("powershell_download_from_raw_ip", "PowerShell Download From Raw IP", severity, "PowerShell download cradle points to a raw IP address.")
        if "download_cradle" in tags:
            return None if "powershell_download_cradle" in disabled_rules else ("powershell_download_cradle", "PowerShell Download Cradle", severity, "PowerShell artifact contains download cradle behavior.")
        if "invoke_expression" in tags:
            return None if "powershell_invoke_expression" in disabled_rules else ("powershell_invoke_expression", "PowerShell Invoke-Expression", severity, "PowerShell artifact uses Invoke-Expression.")
        if "execution_policy_bypass" in tags:
            return None if "powershell_execution_policy_bypass" in disabled_rules else ("powershell_execution_policy_bypass", "PowerShell ExecutionPolicy Bypass", severity, "PowerShell artifact uses ExecutionPolicy Bypass.")
        if "encoded_command" in tags:
            return None if "powershell_encoded_command" in disabled_rules else ("powershell_encoded_command", "PowerShell Encoded Command", severity, "PowerShell artifact contains an encoded command.")
        if "persistence" in tags and any(token in powershell_command for token in ["register-scheduledtask", "new-scheduledtask", "schtasks"]):
            return None if "powershell_scheduled_task_persistence" in disabled_rules else ("powershell_scheduled_task_persistence", "PowerShell Scheduled Task Persistence", severity, "PowerShell artifact references scheduled task persistence.")
        if "persistence" in tags and any(token in powershell_command for token in ["reg add", "currentversion\\run", "set-itemproperty"]):
            return None if "powershell_run_key_persistence" in disabled_rules else ("powershell_run_key_persistence", "PowerShell Run Key Persistence", severity, "PowerShell artifact references Run key persistence.")
        if str((document.get("powershell", {}) or {}).get("artifact_type") or "") == "powershell_script" and "suspicious_path" in tags:
            return None if "powershell_script_in_user_writable_path" in disabled_rules else ("powershell_script_in_user_writable_path", "PowerShell Script In User Writable Path", severity, "PowerShell script file was observed in a user-writable suspicious path.")
    if document.get("artifact", {}).get("type") == "wmi":
        wmi = document.get("wmi", {}) or {}
        command_line = str(wmi.get("command_line_template") or (document.get("process", {}) or {}).get("command_line") or "").lower()
        script_preview = str(wmi.get("script_preview") or "").lower()
        if event_type in {"wmi_persistence", "wmi_filter_consumer_binding"} or ("wmi_persistence_candidate" in tags and "wmi_binding" in tags):
            return None if "wmi_persistence_chain_detected" in disabled_rules else ("wmi_persistence_chain_detected", "WMI Persistence Chain Detected", severity, "WMI filter, consumer and binding form a persistence chain candidate.")
        if event_type in {"wmi_event_consumer", "wmi_active_script_consumer"} and str(wmi.get("script_preview") or wmi.get("script_text") or "").strip():
            return None if "wmi_active_script_event_consumer" in disabled_rules else ("wmi_active_script_event_consumer", "WMI ActiveScriptEventConsumer", severity, "WMI ActiveScriptEventConsumer contains script content.")
        if event_type in {"wmi_event_consumer", "wmi_command_line_consumer"} and any(token in command_line for token in ["powershell", "cmd.exe", "wscript", "cscript", "mshta", "rundll32", "regsvr32", "certutil", "bitsadmin", "curl", "wget", "schtasks", "reg.exe"]):
            return None if "wmi_command_line_event_consumer_suspicious_command" in disabled_rules else ("wmi_command_line_event_consumer_suspicious_command", "WMI CommandLineEventConsumer Suspicious Command", severity, "WMI CommandLineEventConsumer executes a suspicious command.")
        if "encoded_powershell" in tags:
            return None if "wmi_encoded_powershell_consumer" in disabled_rules else ("wmi_encoded_powershell_consumer", "WMI Encoded PowerShell Consumer", severity, "WMI consumer contains encoded PowerShell.")
        if "download_command" in tags:
            return None if "wmi_download_command" in disabled_rules else ("wmi_download_command", "WMI Download Command", severity, "WMI consumer command or script downloads remote content.")
        if "registry_trigger" in tags:
            return None if "wmi_registry_trigger" in disabled_rules else ("wmi_registry_trigger", "WMI Registry Trigger", severity, "WMI filter uses a registry trigger.")
        if "process_trigger" in tags:
            return None if "wmi_process_start_trigger" in disabled_rules else ("wmi_process_start_trigger", "WMI Process Start Trigger", severity, "WMI filter uses a process start or creation trigger.")
        if "user_writable_path" in tags:
            return None if "wmi_consumer_references_user_writable_path" in disabled_rules else ("wmi_consumer_references_user_writable_path", "WMI Consumer References User Writable Path", severity, "WMI consumer command or executable points to a user-writable path.")
        if "defender_correlated" in tags:
            return None if "wmi_consumer_payload_detected_by_defender" in disabled_rules else ("wmi_consumer_payload_detected_by_defender", "WMI Consumer Payload Detected By Defender", severity, "Defender matched a payload referenced by WMI.")
        if "executed_after_download" in tags or "prefetch_correlated" in tags or "execution_related" in tags:
            return None if "wmi_consumer_payload_executed" in disabled_rules else ("wmi_consumer_payload_executed", "WMI Consumer Payload Executed", severity, "Execution evidence later matched a payload referenced by WMI.")
    if event_type in {
        "defender_detection",
        "defender_log_observed",
        "threat_detected",
        "threat_blocked",
        "threat_quarantined",
        "threat_removed",
        "threat_allowed",
        "remediation_started",
        "remediation_completed",
        "remediation_failed",
        "defender_observed",
    }:
        detection = document.get("detection", {}) or {}
        category = str(detection.get("category") or "").lower()
        action = str(detection.get("action") or document.get("event", {}).get("action") or "").lower()
        threat = str(detection.get("threat_name") or "").lower()
        target_path = str(detection.get("path") or (document.get("file", {}) or {}).get("path") or "").lower()
        if "network_correlated" in tags or "defender_with_network_activity" in tags:
            return None if "defender_detection_with_network_activity" in disabled_rules else ("defender_detection_with_network_activity", "Defender Detection With Network Activity", severity, "Defender detection matched a program with network activity.")
        if "persistence_correlated" in tags:
            return None if "defender_detection_in_scheduled_task" in disabled_rules else ("defender_detection_in_scheduled_task", "Defender Detection In Scheduled Task", severity, "Defender-detected file appears configured in a scheduled task or persistence source.")
        if "execution_correlated" in tags:
            return None if "defender_detected_executed_file" in disabled_rules else ("defender_detected_executed_file", "Defender Detected Executed File", severity, "Defender-detected file also matched execution evidence.")
        if "browser_download_correlated" in tags:
            return None if "defender_detected_downloaded_file" in disabled_rules else ("defender_detected_downloaded_file", "Defender Detected Downloaded File", severity, "Defender-detected file also matched a browser download.")
        if "failed" in action:
            return None if "defender_remediation_failed" in disabled_rules else ("defender_remediation_failed", "Defender Remediation Failed", severity, "Defender reported that remediation failed.")
        if "allowed" in action:
            return None if "defender_allowed_threat" in disabled_rules else ("defender_allowed_threat", "Defender Allowed Threat", severity, "Defender reported a threat that was allowed or not remediated.")
        if "quarantine" in action:
            return None if "defender_quarantined_file" in disabled_rules else ("defender_quarantined_file", "Defender Quarantined File", severity, "Defender quarantined the detected file.")
        if "hacktool" in threat or "pua" in threat or category in {"pua", "hacktool"}:
            return None if "defender_hacktool_or_pua" in disabled_rules else ("defender_hacktool_or_pua", "Defender HackTool Or PUA", severity, "Defender detected a HackTool or PUA category threat.")
        if severity in {"high", "critical"} or str(detection.get("severity") or "").lower() in {"high", "severe", "critical"}:
            return None if "defender_high_severity_detection" in disabled_rules else ("defender_high_severity_detection", "Defender High Severity Detection", severity, "Defender reported a high severity detection.")
        if any(token in target_path for token in ["\\downloads\\", "\\appdata\\", "\\temp\\", "\\users\\public\\", "\\programdata\\", "\\desktop\\"]):
            return None if "defender_detection_in_user_writable_path" in disabled_rules else ("defender_detection_in_user_writable_path", "Defender Detection In User Writable Path", severity, "Defender detected a file in a suspicious user-writable path.")
    if event_type in {"file_deleted_or_not_in_use", "file_deleted"} and {"executable", "script"} & tags:
        return None if "deleted_executable_candidate" in disabled_rules else ("deleted_executable_candidate", "Deleted Executable Candidate", severity, "MFT entry not in use points to an executable or script.")
    if any("double extension" in reason.lower() for reason in document.get("suspicious_reasons", [])):
        return None if "double_extension_file" in disabled_rules else ("double_extension_file", "Double Extension File", severity, "File observed with suspicious double extension.")
    if (document.get("filesystem", {}) or {}).get("timestomp_suspected"):
        return None if "possible_timestomping_si_fn_mismatch" in disabled_rules else ("possible_timestomping_si_fn_mismatch", "Possible Timestomping SI/FN Mismatch", severity, "Large mismatch between $SI and $FN timestamps observed.")
    target_path = str((document.get("file", {}) or {}).get("path") or "").lower()
    if {"executable", "script"} & tags and "suspicious_path" in tags and any(token in target_path for token in ["\\downloads\\", "\\appdata\\", "\\temp\\", "\\users\\public\\", "\\programdata\\", "\\desktop\\"]):
        return None if "executable_in_downloads" in disabled_rules else ("executable_in_downloads", "Executable in Downloads", severity, "Executable or script observed in a suspicious user-writable path.")
    if "suspicious_command" in tags:
        return None if "suspicious_command_line" in disabled_rules else ("suspicious_command_line", "Suspicious command line", severity, "Suspicious command line observed in normalized event.")
    if "persistence" in tags and "service_install" in tags:
        return None if "service_installation" in disabled_rules else ("service_installation", "Service installation", severity, "Persistence-relevant service installation detected.")
    if "scheduled_task" in tags and "persistence" in tags:
        return None if "scheduled_task_persistence" in disabled_rules else ("scheduled_task_persistence", "Scheduled task persistence", severity, "Scheduled task persistence pattern detected.")
    if "possible_exfiltration" in tags:
        return None if "possible_exfiltration_tool" in disabled_rules else ("possible_exfiltration_tool", "Possible exfiltration tool", severity, "Potential exfiltration tooling was observed.")
    if "rdp" in tags:
        return None if "rdp_activity" in disabled_rules else ("rdp_activity", "RDP activity", severity, "RDP-related activity detected.")
    if "lateral_movement_candidate" in tags:
        return None if "lateral_movement_candidate" in disabled_rules else ("lateral_movement_candidate", "Lateral movement candidate", severity, "Potential lateral movement activity detected.")
    if severity in {"high", "critical"}:
        return None if "high_risk_event" in disabled_rules else ("high_risk_event", "High-risk event", severity, "High-risk normalized event generated a built-in detection.")
    return None


def _create_builtin_detections_for_ids(
    db: Session,
    *,
    case_id: str,
    evidence_id: str,
    artifact_id: str,
    documents: list[dict],
) -> int:
    if not settings.auto_create_heuristic_detections:
        return 0
    created_count = 0
    created_rule_names: set[str] = set()
    seen_targets: set[tuple[str, str, str]] = set()
    for document in documents:
        candidate = _builtin_detection_from_document(document)
        if not candidate:
            continue
        rule_key, rule_name, severity, message = candidate
        definition = get_builtin_detection_definition(rule_key)
        opensearch_id = str(document.get("event_id") or "")
        stable_event_id = str(document.get("stable_event_id") or document.get("event_fingerprint") or "")
        target_path = str((document.get("file", {}) or {}).get("path") or "")
        dedupe_key = (rule_name, opensearch_id, target_path)
        if dedupe_key in seen_targets:
            continue
        seen_targets.add(dedupe_key)
        detection, created = create_detection_if_missing(
            db,
            case_id=case_id,
            evidence_id=evidence_id,
            artifact_id=artifact_id,
            rule_id=None,
            rule_set_id=None,
            engine="builtin",
            source_engine="builtin",
            rule_name=f"Built-in: {rule_name}",
            severity=severity,
            confidence=None,
            event_id=document.get("event_id"),
            event_index=get_events_index(case_id),
            opensearch_id=document.get("event_id"),
            target_type="event",
            target_path=(document.get("file", {}) or {}).get("path"),
            message=message,
            matched_stable_event_id=stable_event_id or None,
            dedup_fingerprint=_dedup_fingerprint(case_id, "builtin", rule_key, stable_event_id or document.get("event_id"), target_path),
            raw={
                "builtin_rule_key": rule_key,
                "event_type": document.get("event", {}).get("type"),
                "tags": document.get("tags", []),
                "match_reason": message,
                "description": definition.description,
                "investigation_guidance": definition.investigation_guidance,
            },
            commit=False,
        )
        if created:
            created_count += 1
            created_rule_names.add(rule_name)
    if created_count:
        log_activity(
            db,
            activity_type="detection_created",
            title="Built-in detections generated",
            message=f"Generated {created_count} built-in detections for artifact {artifact_id}",
            case_id=case_id,
            evidence_id=evidence_id,
            metadata={"count": created_count, "rule_names": sorted(created_rule_names), "artifact_id": artifact_id},
            commit=False,
        )
        db.commit()
    return created_count


def _create_builtin_detections(db: Session, evidence: Evidence, artifact: Artifact, documents: list[dict]) -> int:
    return _create_builtin_detections_for_ids(
        db,
        case_id=evidence.case_id,
        evidence_id=evidence.id,
        artifact_id=artifact.id,
        documents=documents,
    )


def _create_builtin_detections_isolated(*, case_id: str, evidence_id: str, artifact_id: str, documents: list[dict]) -> int:
    isolated_db: Session = SessionLocal()
    try:
        return _create_builtin_detections_for_ids(
            isolated_db,
            case_id=case_id,
            evidence_id=evidence_id,
            artifact_id=artifact_id,
            documents=documents,
        )
    finally:
        isolated_db.close()


def _safe_create_builtin_detections_isolated(
    *,
    case_id: str,
    evidence_id: str,
    artifact_id: str,
    artifact_name: str,
    documents: list[dict],
) -> tuple[int, str | None]:
    try:
        return (
            _create_builtin_detections_isolated(
                case_id=case_id,
                evidence_id=evidence_id,
                artifact_id=artifact_id,
                documents=documents,
            ),
            None,
        )
    except Exception as exc:  # noqa: BLE001
        logger.warning("Built-in detection generation failed for artifact %s: %s", artifact_name, exc)
        return 0, str(exc)


def _estimate_remaining_seconds(*, elapsed_seconds: float, progress_pct: int) -> float | None:
    if progress_pct <= 0:
        return None
    return max((elapsed_seconds / progress_pct) * (100 - progress_pct), 0.0)


def _artifact_batch_progress_pct(*, artifact_index: int, total_artifacts: int, batch_index: int, total_batches: int) -> int:
    progress_base = 30
    progress_span = 65
    completed_fraction = (artifact_index - 1) / max(total_artifacts, 1)
    current_fraction = batch_index / max(total_batches, 1)
    overall_fraction = completed_fraction + (current_fraction / max(total_artifacts, 1))
    return int(progress_base + (progress_span * min(max(overall_fraction, 0.0), 1.0)))


def _artifact_progress_callback(
    *,
    evidence_id: str,
    artifact_name: str,
    artifact_index: int,
    total_artifacts: int,
    artifacts_processed: int,
    indexed_count: int,
    records_processed: int,
    detection_count: int,
    raw_artifacts_detected: int,
    raw_artifacts_not_parsed: int,
    started_monotonic: float,
    state: dict | None = None,
):
    progress_base = 30
    progress_span = 65
    artifact_start_progress = int(progress_base + (progress_span * max(artifact_index - 1, 0) / max(total_artifacts, 1)))
    tracker = state if state is not None else {}
    tracker.setdefault("artifact_started_monotonic", time.perf_counter())
    tracker.setdefault("last_progress_monotonic", tracker["artifact_started_monotonic"])
    tracker.setdefault("last_records_read", 0)
    tracker.setdefault("records_indexed_in_artifact", 0)
    tracker.setdefault("events_indexed_total", indexed_count)
    tracker.setdefault("slow_artifact_logged", False)

    def _callback(progress: dict) -> None:
        now = time.perf_counter()
        elapsed_seconds = max(time.perf_counter() - started_monotonic, 0.001)
        current_records_read = int(progress.get("records_read") or 0)
        current_events_buffered = int(progress.get("events_buffered") or 0)
        current_errors = int(progress.get("errors_count") or 0)
        tracker["last_progress_monotonic"] = now
        tracker["last_records_read"] = current_records_read
        current_records_indexed = int(progress.get("records_indexed") or tracker.get("records_indexed_in_artifact") or 0)
        events_indexed_total = int(progress.get("events_indexed_total") or tracker.get("events_indexed_total") or indexed_count)
        pending_index_records = max(current_records_read - current_records_indexed, 0)
        artifact_elapsed_seconds = max(now - float(tracker.get("artifact_started_monotonic") or now), 0.001)
        max_seconds = max(int(settings.evtx_artifact_max_seconds or 0), 0)
        is_slow = max_seconds > 0 and artifact_elapsed_seconds >= max_seconds
        if is_slow and not tracker.get("slow_artifact_logged"):
            logger.warning(
                "EVTX artifact %s exceeded max runtime (%ss) after %s records read / %s indexed",
                artifact_name,
                max_seconds,
                current_records_read,
                current_records_indexed,
            )
            tracker["slow_artifact_logged"] = True
        _update_progress_isolated(
            evidence_id,
            phase="parsing",
            progress_pct=artifact_start_progress,
            extra={
                "processed_artifacts": artifacts_processed,
                "detected_artifacts": total_artifacts,
                "indexed_events": events_indexed_total,
                "last_artifact": artifact_name,
                "generated_detections": int(tracker.get("detection_count") or detection_count),
                "records_processed": int(tracker.get("records_processed_total") or records_processed),
                "events_indexed": events_indexed_total,
                "current_artifact": artifact_name,
                "current_artifact_records_read": current_records_read,
                "current_artifact_events_buffered": current_events_buffered,
                "current_artifact_records_indexed": current_records_indexed,
                "current_artifact_pending_index_records": pending_index_records,
                "current_artifact_errors": current_errors,
                "current_artifact_progress_label": f"{current_records_read} records read / {current_records_indexed} indexed",
                "current_artifact_elapsed_seconds": round(artifact_elapsed_seconds, 2),
                "current_artifact_is_slow": is_slow,
                "artifacts_processed": artifacts_processed,
                "artifacts_total": total_artifacts,
                "elapsed_seconds": round(elapsed_seconds, 2),
                "records_per_second": round((int(tracker.get("records_processed_total") or records_processed) + pending_index_records) / elapsed_seconds, 2),
                "estimated_remaining_seconds": round(_estimate_remaining_seconds(elapsed_seconds=elapsed_seconds, progress_pct=artifact_start_progress) or 0.0, 2),
                "raw_artifacts_detected": raw_artifacts_detected,
                "raw_artifacts_not_parsed": raw_artifacts_not_parsed,
            },
        )
        if is_slow:
            raise TimeoutError(
                f"EVTX artifact exceeded {max_seconds}s: {artifact_name} ({current_records_read} read / {current_records_indexed} indexed)"
            )

    _callback._tracker = tracker  # type: ignore[attr-defined]
    return _callback


def ingest_evidence(evidence_id: str) -> None:
    db: Session = SessionLocal()
    evidence = db.get(Evidence, evidence_id)
    if not evidence:
        logger.error("Evidence %s not found", evidence_id)
        db.close()
        return

    manifest = _manifest_for_evidence(evidence)
    manifest_path = evidence_manifest_path(evidence.case_id, evidence.id)
    metadata_preview = dict(evidence.metadata_json or {})
    benchmark_request = dict(metadata_preview.get("benchmark_request") or {})
    benchmark_profile = str(benchmark_request.get("profile") or "").strip().lower()
    runtime_settings = load_runtime_settings(db)
    runtime_overrides: dict[str, object] = {}
    if benchmark_profile and benchmark_profile not in {"", "current"}:
        runtime_overrides = {
            key: value
            for key, value in validate_and_normalize_settings(benchmark_profile).items()
            if key in runtime_settings
        }
        runtime_settings = {**runtime_settings, **runtime_overrides}
    ingest_batch_size = max(1, int(runtime_settings.get("INGEST_BATCH_SIZE", settings.ingest_batch_size)))
    performance_snapshot = performance_snapshot_for_ingest(
        db,
        profile_override=benchmark_profile if benchmark_profile and benchmark_profile != "current" else None,
        runtime_overrides=runtime_overrides,
    )
    performance_system = system_snapshot()
    performance_warnings = build_resource_warnings(
        {
            **performance_system,
            "opensearch_status": performance_system.get("services", {}).get("opensearch", {}).get("status"),
        },
        performance_snapshot["performance_profile"],
    )
    started_at = utc_now_naive()
    started_monotonic = time.perf_counter()
    try:
        metadata = dict(evidence.metadata_json or {})
        ingest_mode = normalize_ingest_mode(metadata.get("ingest_mode"))
        requested_evtx_backend = str(metadata.get("evtx_parser_backend") or settings.evtx_parser_backend or "auto").strip() or "auto"
        metadata["evtx_parser_backend_requested"] = requested_evtx_backend
        metadata["evtx_parser_backends"] = select_evtx_parser_backend(requested_evtx_backend).get("backends") or {}
        metadata["evtx_parser_backend"] = requested_evtx_backend
        if str(metadata.get("evtx_profile") or "").strip().lower() == EVTX_PROFILE_FAST_HIGH_VALUE:
            env_limits = normalize_evtx_fast_limits(
                {
                    "max_records_per_file": settings.evtx_fast_max_records_per_file,
                    "max_seconds_per_file": settings.evtx_fast_max_seconds_per_file,
                    "max_total_records": settings.evtx_fast_max_total_records,
                    "max_total_seconds": settings.evtx_fast_max_total_seconds,
                    "on_limit": "defer_remaining",
                }
            )
            requested_limits = normalize_evtx_fast_limits(metadata.get("evtx_fast_limits"))
            metadata["evtx_fast_limits"] = {**env_limits, **requested_limits}
            metadata.setdefault("evtx_partial_files", [])
            metadata["evtx_partial_count"] = int(len(metadata.get("evtx_partial_files") or []))
            if int(metadata.get("evtx_deferred_count") or 0) > 0:
                metadata.setdefault("evtx_coverage_status", "deferred_fast_profile")
        mode_metadata = ingest_mode_metadata(ingest_mode)
        evidence.metadata_json = merge_evidence_metadata(evidence.metadata_json or {}, metadata)
        db.commit()
        db.refresh(evidence)
        current_run_id = str(metadata.get("current_ingest_run_id") or (metadata.get("reprocess_request") or {}).get("run_id") or "") or f"ingest-{evidence.id}"
        benchmark_request = dict(metadata.get("benchmark_request") or {})
        if metadata.get("reprocess_cleanup_pending") or metadata.get("reconciliation_baseline_pending"):
            _update_progress(
                db,
                evidence,
                phase="cleanup_previous_run",
                progress_pct=2,
                phases=["queued", "cleanup_previous_run", "extracting_selected", "parsing", "indexing", "finalizer"],
                extra={
                    "started_at": started_at.isoformat(),
                    "phase_started_at": started_at.isoformat(),
                    "current_action": "cleanup_previous_run",
                },
            )
            if benchmark_request and str(benchmark_request.get("run_id") or "") == current_run_id:
                cleanup_metadata = upsert_ingest_benchmark(
                    metadata,
                    str(benchmark_request.get("benchmark_id") or ""),
                    {
                        "status": "running",
                        "run_id": current_run_id,
                        "started_at": started_at.isoformat(),
                        "current_action": "cleanup_previous_run",
                        "last_progress_at": utc_now().isoformat(),
                        "phase_timings": [
                            {
                                "phase": "cleanup_previous_run",
                                "started_at": utc_now().isoformat(),
                                "finished_at": None,
                                "duration_seconds": 0.0,
                                "records_read": 0,
                                "records_indexed": 0,
                                "artifacts_processed": 0,
                                "errors": [],
                            }
                        ],
                    },
                )
                evidence.metadata_json = merge_evidence_metadata(evidence.metadata_json or {}, cleanup_metadata)
                db.commit()
                db.refresh(evidence)
                metadata = dict(evidence.metadata_json or {})
        if metadata.get("reprocess_cleanup_pending"):
            metadata = _run_pending_reprocess_cleanup(db, evidence, metadata)
        if metadata.get("reconciliation_baseline_pending"):
            metadata = _run_pending_reconciliation_baseline(db, evidence, metadata)
        if not current_run_id:
            current_run_id = f"ingest-{evidence.id}"
        if not metadata.get("current_ingest_run_id"):
            mode = "previous_selection" if metadata.get("requested_ingest_plan") else "first_ingest"
            metadata["current_ingest_run_id"] = current_run_id
            metadata = start_ingest_run(
                metadata,
                run_id=current_run_id,
                run_type="reprocess" if metadata.get("reprocess_request") else "ingest",
                mode=str((metadata.get("reprocess_request") or {}).get("mode") or mode),
                status="running",
                selected_by_artifact_type=dict(((metadata.get("requested_ingest_plan") or metadata.get("ingest_plan") or {}).get("selected_by_artifact_type") or {})),
                selected_by_parser=dict(((metadata.get("requested_ingest_plan") or metadata.get("ingest_plan") or {}).get("selected_by_parser") or {})),
            )
            metadata = merge_evidence_metadata(metadata, mode_metadata)
            evidence.metadata_json = merge_evidence_metadata(evidence.metadata_json or {}, metadata)
            db.commit()
            db.refresh(evidence)
        opensearch_preflight = assert_opensearch_ingest_ready(evidence.case_id)
        metadata = dict(evidence.metadata_json or {})
        metadata["opensearch_preflight"] = opensearch_preflight
        evidence.metadata_json = merge_evidence_metadata(evidence.metadata_json or {}, metadata)
        db.commit()
        db.refresh(evidence)
        benchmark_request = dict(metadata.get("benchmark_request") or {})
        benchmark_state = None
        if benchmark_request and str(benchmark_request.get("run_id") or "") == current_run_id:
            requested_plan = dict((metadata.get("requested_ingest_plan") or metadata.get("ingest_plan") or {}))
            selected_total = int(sum(int(value or 0) for value in dict(requested_plan.get("selected_by_parser") or {}).values()) or len(requested_plan.get("selected_candidates") or []))
            benchmark_state = {
                "benchmark_id": str(benchmark_request.get("benchmark_id") or ""),
                "evidence_id": evidence.id,
                "case_id": evidence.case_id,
                "run_id": current_run_id,
                "label": benchmark_request.get("label"),
                "notes": benchmark_request.get("notes"),
                "mode": benchmark_request.get("mode"),
                "profile": benchmark_request.get("profile") or performance_snapshot["performance_profile"],
                "requested_at": benchmark_request.get("requested_at"),
                "started_at": started_at.isoformat(),
                "started_monotonic": started_monotonic,
                "selected_total": selected_total,
                "effective_cpu_count": int(performance_system.get("cpu_count_container") or performance_system.get("cpu_count") or 1),
                "memory_limit_source": performance_system.get("memory_limit_source"),
                "source_evidence_name": evidence.original_filename,
                "phase_timings": [],
                "resource_samples": [],
                "sample_interval_seconds": 5.0,
                "stalled_threshold_seconds": 30,
                "current_action": "starting_benchmark",
                "current_selected_path": None,
                "last_progress_at": started_at.isoformat(),
                "last_progress_monotonic": started_monotonic,
                "benchmark_options": {
                    "stop_after_overlap_observed": bool(benchmark_request.get("stop_after_overlap_observed")),
                    "max_duration_seconds": int(benchmark_request.get("max_duration_seconds") or 3600),
                    "skip_detections": bool(benchmark_request.get("skip_detections")),
                    "skip_rules": bool(benchmark_request.get("skip_rules", True)),
                },
            }
            _benchmark_transition_phase(benchmark_state, "queued_wait")
            _benchmark_transition_phase(benchmark_state, "extracting_selected" if _is_raw_collection_with_discovery(evidence) and bool(_selected_velociraptor_candidates(evidence)) else "extracting")
            _benchmark_sample_resources(benchmark_state, force=True)
            metadata = upsert_ingest_benchmark(
                metadata,
                str(benchmark_request.get("benchmark_id") or ""),
                {
                    "status": "running",
                    "run_id": current_run_id,
                    "started_at": started_at.isoformat(),
                    "effective_cpu_count": int(performance_system.get("cpu_count_container") or performance_system.get("cpu_count") or 1),
                    "memory_limit_source": performance_system.get("memory_limit_source"),
                    "source_evidence_name": evidence.original_filename,
                    "selected_total": selected_total,
                },
            )
            evidence.metadata_json = merge_evidence_metadata(evidence.metadata_json or {}, metadata)
            db.commit()
            db.refresh(evidence)
            _safe_persist_benchmark_snapshot(evidence.id, benchmark_state, status="running", effective_parallelism=None)
        else:
            benchmark_state = None
        detections_enabled = not bool((benchmark_state or {}).get("benchmark_options", {}).get("skip_detections"))
        if ingest_mode == USABLE_INGEST_MODE:
            detections_enabled = False
        evidence.ingest_status = IngestStatus.processing
        db.commit()
        log_activity(
            db,
            activity_type="evidence_processing_started",
            title="Evidence processing started",
            message=f"Started processing {evidence.original_filename}",
            case_id=evidence.case_id,
            evidence_id=evidence.id,
        )
        is_selected_velociraptor = _is_raw_collection_with_discovery(evidence) and bool(_selected_velociraptor_candidates(evidence))
        initial_phase = "extracting_selected" if is_selected_velociraptor else "extracting"
        initial_phases = ["uploaded", "indexing_zip", "discovering_candidates", "waiting_selection", "extracting_selected", "parsing", "indexing_events"] if is_selected_velociraptor else ["uploaded", "extracting", "detecting", "parsing", "indexing"]
        stored_path = Path(evidence.stored_path)
        discovery_candidates = list(((metadata.get("velociraptor_discovery") or {}).get("candidates") or []))
        selected_artifact_types = sorted(
            {
                str(item).strip()
                for item in (metadata.get("selected_artifact_types") or [])
                if str(item).strip()
            }
        )
        available_artifact_types = sorted(
            {
                str((candidate or {}).get("artifact_type") or "").strip()
                for candidate in discovery_candidates
                if str((candidate or {}).get("artifact_type") or "").strip()
            }
        )
        extractor_used = (
            "7z_native_batch_selected" if is_selected_velociraptor else "7z_native"
            if stored_path.suffix.lower() in {".7z", ".rar"} or any(suffix in {".7z", ".rar"} for suffix in stored_path.suffixes)
            else "zipfile_python"
            if stored_path.suffix.lower() == ".zip"
            else "filesystem_copy"
            if stored_path.is_dir()
            else "archive_auto"
        )
        _update_progress(
            db,
            evidence,
            phase=initial_phase,
            progress_pct=30 if is_selected_velociraptor else 5,
            phases=initial_phases,
            extra={
                "started_at": started_at.isoformat(),
                "phase_started_at": started_at.isoformat(),
                "container_type": "zip" if stored_path.suffix.lower() == ".zip" else "directory" if stored_path.is_dir() else "file",
                "extractor_used": extractor_used,
                "mode_effective_plan": build_mode_effective_plan(
                    ingest_mode,
                    selected_artifact_types=selected_artifact_types,
                    available_artifact_types=available_artifact_types,
                ),
                "performance_profile": performance_snapshot["performance_profile"],
                "performance_settings": performance_snapshot["effective_settings"],
                "resource_warnings": performance_warnings,
            },
        )

        streaming_materialization_enabled = False
        streaming_materialization_batch_size = 0
        streaming_max_pending_futures = 0
        executor = None
        parallel_tracker: dict[str, dict] = {}
        parallel_tracker_lock = threading.Lock()
        parallel_futures: dict = {}
        parallel_results: list[dict] = []
        artifacts_parallelized_by_type: Counter[str] = Counter()
        artifacts_sequential_by_type: Counter[str] = Counter()
        parser_capabilities_used: dict[str, dict] = {}
        desired_parallel: dict = {"desired_parallelism": 1, "effective_parallelism": 1, "limit_reason": "unsupported_artifact_type"}
        effective_parallelism = 1
        parallel_enabled = False
        indexed_count = 0
        detection_count = 0
        errors = []
        records_processed = 0
        artifacts_processed = 0
        detected_host_counts_local = Counter(
            {
                str(key): int(value or 0)
                for key, value in dict((metadata_preview.get("detected_host_counts") or {})).items()
            }
        )
        slow_artifacts: list[dict] = []
        detection_warnings: list = []
        opensearch_bulk = {
            "attempted": False,
            "success": True,
            "timeouts": 0,
            "retries": 0,
            "chunk_size_initial": 0,
            "chunk_size_final": 0,
            "request_timeout": 0,
            "documents_expected": 0,
            "documents_indexed": 0,
            "documents_recovered_after_timeout": 0,
            "warnings": [],
            "host_identity": {
                "upserts": 0,
                "conflicts_recovered": 0,
                "host_identity_conflict_retries": 0,
                "aliases_updated": 0,
            },
        }

        extraction_progress_state = {"last_emit": 0.0, "last_processed": -1}
        existing_files = manifest.get("files", [])
        manifest["files"] = existing_files if is_selected_velociraptor else []
        manifest["artifacts"] = []
        manifest["errors"] = []

        def extraction_progress(extra: dict) -> None:
            elapsed_seconds = max(time.perf_counter() - started_monotonic, 0.001)
            processed_files = int(extra.get("processed_files") or 0)
            total_files = int(extra.get("total_files") or 0)
            now_iso = utc_now().isoformat()
            if is_selected_velociraptor:
                extraction_pct = 30 if total_files <= 0 else min(45, 30 + int((processed_files / max(total_files, 1)) * 15))
                phase_name = "materializing_and_parsing" if streaming_materialization_enabled else "extracting_selected"
            else:
                extraction_pct = 5 if total_files <= 0 else min(18, 5 + int((processed_files / max(total_files, 1)) * 13))
                phase_name = "extracting"
            estimated_remaining = _estimate_remaining_seconds(elapsed_seconds=elapsed_seconds, progress_pct=extraction_pct)
            now_monotonic = time.perf_counter()
            should_emit = (
                processed_files >= total_files > 0
                or processed_files == 0
                or processed_files - int(extraction_progress_state["last_processed"]) >= 5
                or now_monotonic - float(extraction_progress_state["last_emit"]) >= 1.0
            )
            if not should_emit:
                return
            if benchmark_state is not None:
                benchmark_state["current_action"] = extra.get("current_action") or phase_name
                benchmark_state["current_selected_path"] = extra.get("current_path")
                benchmark_state["last_progress_at"] = now_iso
                benchmark_state["last_progress_monotonic"] = now_monotonic
            _benchmark_sample_resources(
                benchmark_state,
                force=processed_files == 0 or processed_files >= total_files > 0,
            )
            extraction_progress_state["last_emit"] = now_monotonic
            extraction_progress_state["last_processed"] = processed_files
            processed_bytes = int(extra.get("processed_bytes") or 0)
            _safe_update_progress_isolated(
                evidence.id,
                phase=phase_name,
                progress_pct=extraction_pct,
                extra={
                    "elapsed_seconds": round(elapsed_seconds, 2),
                    "extracting_selected_elapsed_seconds": round(elapsed_seconds, 2) if is_selected_velociraptor else None,
                    "estimated_remaining_seconds": round(estimated_remaining, 2) if estimated_remaining is not None else None,
                    "files_extracted": processed_files,
                    "files_total": total_files,
                    "selected_files_extracted": processed_files if is_selected_velociraptor else None,
                    "selected_files_total": total_files if is_selected_velociraptor else None,
                    "selected_files_processed": processed_files if is_selected_velociraptor else None,
                    "bytes_extracted": processed_bytes,
                    "bytes_total": int(extra.get("total_bytes") or 0),
                    "current_selected_path": extra.get("current_path") if is_selected_velociraptor else None,
                    "current_action": extra.get("current_action"),
                    "current_item": extra.get("current_path"),
                    "files_materialized": int(extra.get("files_materialized") or 0),
                    "files_skipped_existing": int(extra.get("files_skipped_existing") or 0),
                    "extraction_errors": int(extra.get("extraction_errors") or 0),
                    "extraction_rate_files_per_sec": round(processed_files / elapsed_seconds, 2),
                    "extraction_rate_mb_per_sec": round((processed_bytes / (1024 * 1024)) / elapsed_seconds, 2),
                },
            )
            _safe_persist_benchmark_snapshot(
                evidence.id,
                benchmark_state,
                status="running",
                effective_parallelism=int(effective_parallelism or 1),
                artifacts_total=None,
                artifacts_completed=int(artifacts_processed or 0),
                records_read=int(records_processed or 0),
                records_indexed=int(indexed_count or 0),
            )

        def _parallel_runtime_snapshot() -> dict:
            now = time.perf_counter()
            artifact_context_by_id = {
                str(context.get("artifact_id") or ""): dict(context.get("artifact") or {})
                for context in parallel_futures.values()
            }
            artifact_type_by_id = {
                artifact_id: str(context.get("artifact_type") or "")
                for artifact_id, context in artifact_context_by_id.items()
            }
            pending_artifact_ids = set(artifact_type_by_id)
            with parallel_tracker_lock:
                tracker_snapshot = {
                    key: dict(value)
                    for key, value in parallel_tracker.items()
                    if isinstance(value, dict) and str((value or {}).get("artifact_id") or "") in pending_artifact_ids
                }
            running_snapshot = [item for item in tracker_snapshot.values() if str(item.get("status") or "") == "running"]
            queued_count = max(len(parallel_futures) - len(running_snapshot), 0)
            indexed_pending = sum(int(item.get("records_indexed") or 0) for item in tracker_snapshot.values())
            read_pending = sum(int(item.get("records_read") or 0) for item in tracker_snapshot.values())
            running_artifacts = []
            running_types: set[str] = set()
            for item in running_snapshot[:5]:
                artifact_id = str(item.get("artifact_id") or "")
                artifact_type = artifact_type_by_id.get(artifact_id, "")
                artifact_context = artifact_context_by_id.get(artifact_id, {})
                if artifact_type:
                    running_types.add(artifact_type)
                started_monotonic = float(item.get("started_monotonic") or now)
                last_progress_monotonic = float(item.get("last_progress_monotonic") or started_monotonic)
                running_artifacts.append(
                    {
                        "artifact": item.get("name"),
                        "artifact_type": artifact_type,
                        "parser": artifact_context.get("parser"),
                        "source_path": artifact_context.get("source_path"),
                        "records_read": int(item.get("records_read") or 0),
                        "records_indexed": int(item.get("records_indexed") or 0),
                        "elapsed_seconds": round(max(now - started_monotonic, 0.0), 2),
                        "last_progress_seconds_ago": round(max(now - last_progress_monotonic, 0.0), 2),
                    }
                )
            return {
                "running_snapshot": running_snapshot,
                "running_artifacts": running_artifacts,
                "running_artifact_types": sorted(running_types),
                "slowest_artifacts": sorted(running_artifacts, key=lambda item: float(item.get("elapsed_seconds") or 0.0), reverse=True)[:5],
                "queued_count": queued_count,
                "indexed_pending": indexed_pending,
                "read_pending": read_pending,
            }

        def _drain_completed_parallel_futures(*, block: bool) -> int:
            nonlocal indexed_count, records_processed, detection_count, artifacts_processed
            drained = 0
            if not parallel_futures:
                return drained
            while parallel_futures:
                done, _pending = wait(
                    list(parallel_futures.keys()),
                    timeout=1.0 if block else 0.0,
                    return_when=FIRST_COMPLETED,
                )
                if not done:
                    break
                for future in done:
                    context = parallel_futures.pop(future)
                    result = future.result()
                    parallel_results.append(result)
                    manifest_artifact = context["manifest_artifact"]
                    manifest_artifact["status"] = result.get("status")
                    manifest_artifact["record_count"] = int(result.get("record_count") or 0)
                    if result.get("ingest_audit"):
                        manifest_artifact["ingest_audit"] = result.get("ingest_audit")
                    if result.get("evtx_partial"):
                        manifest_artifact["evtx_partial"] = result.get("evtx_partial")
                    indexed_count += int(result.get("indexed_count") or 0)
                    records_processed += int(result.get("records_read") or 0)
                    if int(result.get("indexed_count") or 0) > 0:
                        _benchmark_mark_first(benchmark_state, "time_to_first_event_indexed")
                    detection_count += int(result.get("detection_count") or 0)
                    artifacts_processed += 1
                    drained += 1
                    _merge_bulk_report(opensearch_bulk, result.get("bulk_report"), detection_warnings)
                    for warning in result.get("warnings") or []:
                        if warning not in detection_warnings:
                            detection_warnings.append(warning)
                    if result.get("row_hosts"):
                        _merge_host_metadata(evidence.id, result["row_hosts"])
                    if result.get("error"):
                        errors.append({"artifact": result.get("artifact_name"), "error": str(result.get("error"))})
                        manifest["errors"].append({"artifact": result.get("artifact_name"), "error": str(result.get("error"))})
                        slow_artifacts.append(
                            {
                                "artifact": result.get("artifact_name"),
                                "path": context["artifact"].get("source_path"),
                                "parser": context["artifact"].get("parser"),
                                "error": str(result.get("error")),
                            }
                        )
                if not block:
                    break
            return drained

        if is_selected_velociraptor:
            selected_candidates_source = _selected_velociraptor_candidates(evidence) or []
            supported_selected_candidates = [candidate for candidate in selected_candidates_source if candidate.get("supported")]
            candidate_parser_names = [
                str(candidate.get("parser") or candidate.get("artifact_type") or "").lower()
                for candidate in supported_selected_candidates
                if str(candidate.get("parser") or candidate.get("artifact_type") or "").strip()
            ]
            desired_parallel = describe_ingest_parallelism(
                {**runtime_settings, PERFORMANCE_PROFILE_KEY: performance_snapshot["performance_profile"]},
                system=performance_system,
                artifact_count=len(supported_selected_candidates),
                artifact_types=candidate_parser_names,
                supported_artifact_types=list(PARSER_CAPABILITIES.keys()),
            )
            parser_parallel_limit = min(
                [int((_parser_capabilities(parser_name).get("max_parallelism") or 1)) for parser_name in candidate_parser_names] or [1]
            )
            effective_parallelism = min(int(desired_parallel.get("effective_parallelism") or 1), max(parser_parallel_limit, 1))
            parallel_enabled = effective_parallelism > 1 and len(supported_selected_candidates) > 1
            streaming_materialization_enabled = parallel_enabled and bool(supported_selected_candidates)
            streaming_materialization_batch_size = max(effective_parallelism * 2, 4) if streaming_materialization_enabled else 0
            streaming_max_pending_futures = max(effective_parallelism * 2, streaming_materialization_batch_size) if streaming_materialization_enabled else 0
            extract_dir = evidence_staging_dir(evidence.case_id, evidence.id)
            selected_candidates = []
            archive_entries = []
            selective_stats = {
                "selected_files_total": len(
                    [
                        path
                        for candidate in supported_selected_candidates
                        for path in _candidate_required_paths(candidate)
                    ]
                ),
                "selected_files_extracted": 0,
                "selected_files_reused": 0,
                "selected_files_materialized": 0,
                "bytes_extracted": 0,
                "bytes_materialized": 0,
                "extraction_errors": 0,
                "sqlite_files_extracted": 0,
                "wal_shm_files_extracted": 0,
            }
            if streaming_materialization_enabled:
                _benchmark_transition_phase(benchmark_state, "materializing_and_parsing")
                executor = ThreadPoolExecutor(max_workers=effective_parallelism)
                _update_progress(
                    db,
                    evidence,
                    phase="materializing_and_parsing",
                    progress_pct=30,
                    extra={
                        "parallel_ingest": {
                            "enabled": True,
                            "mode": "generic_artifact_scheduler",
                            "effective_parallelism": effective_parallelism,
                            "desired_parallelism": int(desired_parallel.get("desired_parallelism") or effective_parallelism),
                            "supported_artifact_types": sorted(set(candidate_parser_names)),
                            "running_artifacts": [],
                            "running_artifact_types": [],
                            "completed_artifacts": 0,
                            "queued_artifacts": len(supported_selected_candidates),
                            "failed_artifacts": 0,
                            "records_per_second_total": 0,
                            "bottleneck": "materialization",
                            "artifacts_parallelized_by_type": {},
                            "artifacts_sequential_by_type": {},
                            "materialization_queue_depth": 0,
                            "parser_queue_depth": 0,
                            "active_artifact_workers": 0,
                            "limitation_reason": None,
                        }
                    },
                )
                container = open_evidence_container(stored_path)
                materialized_artifacts: list[dict] = []
                total_artifacts_estimate = len(supported_selected_candidates)
                for batch_start in range(0, len(supported_selected_candidates), streaming_materialization_batch_size):
                    batch_candidates = supported_selected_candidates[batch_start : batch_start + streaming_materialization_batch_size]
                    batch_base = {
                        "processed_files": int(selective_stats.get("selected_files_materialized") or 0),
                        "processed_bytes": int(selective_stats.get("bytes_materialized") or 0),
                        "files_materialized": int(selective_stats.get("selected_files_materialized") or 0),
                        "files_skipped_existing": int(selective_stats.get("selected_files_reused") or 0),
                        "extraction_errors": int(selective_stats.get("extraction_errors") or 0),
                    }

                    def batch_extraction_progress(extra: dict, *, _batch_base=batch_base) -> None:
                        extraction_progress(
                            {
                                **extra,
                                "processed_files": _batch_base["processed_files"] + int(extra.get("processed_files") or 0),
                                "total_files": int(selective_stats.get("selected_files_total") or 0),
                                "processed_bytes": _batch_base["processed_bytes"] + int(extra.get("processed_bytes") or 0),
                                "total_bytes": int(selective_stats.get("bytes_materialized") or 0) + int(
                                    selective_stats.get("bytes_extracted") or 0
                                ),
                                "files_materialized": _batch_base["files_materialized"] + int(extra.get("files_materialized") or 0),
                                "files_skipped_existing": _batch_base["files_skipped_existing"] + int(
                                    extra.get("files_skipped_existing") or 0
                                ),
                                "extraction_errors": _batch_base["extraction_errors"] + int(extra.get("extraction_errors") or 0),
                            }
                        )

                    _extract_dir, prepared_candidates, batch_entries, batch_stats = _prepare_velociraptor_selected_staging_from_candidates(
                        evidence,
                        batch_candidates,
                        container=container,
                        staging_dir=extract_dir,
                        progress_cb=batch_extraction_progress,
                    )
                    selected_candidates.extend(prepared_candidates)
                    archive_entries.extend(batch_entries)
                    selective_stats["selected_files_extracted"] += int(batch_stats.get("selected_files_extracted") or 0)
                    selective_stats["selected_files_reused"] += int(batch_stats.get("selected_files_reused") or 0)
                    selective_stats["selected_files_materialized"] += int(batch_stats.get("selected_files_materialized") or 0)
                    selective_stats["bytes_extracted"] += int(batch_stats.get("bytes_extracted") or 0)
                    selective_stats["bytes_materialized"] += int(batch_stats.get("bytes_materialized") or 0)
                    selective_stats["extraction_errors"] += int(batch_stats.get("extraction_errors") or 0)
                    selective_stats["sqlite_files_extracted"] += int(batch_stats.get("sqlite_files_extracted") or 0)
                    selective_stats["wal_shm_files_extracted"] += int(batch_stats.get("wal_shm_files_extracted") or 0)
                    batch_artifacts = list_velociraptor_artifacts(extract_dir, prepared_candidates)
                    if batch_artifacts:
                        _benchmark_mark_first(benchmark_state, "time_to_first_artifact_ready")
                    materialized_artifacts.extend(batch_artifacts)
                    for artifact_info in batch_artifacts:
                        parser_capabilities_used[str(artifact_info.get("parser") or "").lower()] = _parser_capabilities(
                            artifact_info.get("parser"),
                            artifact_info.get("artifact_type"),
                        )
                        if _artifact_can_parallelize(artifact_info) and not (
                            str(artifact_info.get("parser") or "").lower() == "evtx_raw" and _evtx_fast_limits_for_run(metadata)
                        ):
                            artifacts_parallelized_by_type[str(artifact_info.get("artifact_type") or "unknown")] += 1
                            _benchmark_mark_first(benchmark_state, "time_to_first_parse_start")
                            _benchmark_transition_phase(
                                benchmark_state,
                                "parsing",
                                records_read=records_processed,
                                records_indexed=indexed_count,
                                artifacts_processed=artifacts_processed,
                            )
                            _schedule_parallel_artifact(
                                executor=executor,
                                evidence=evidence,
                                artifact_info=artifact_info,
                                ingest_batch_size=ingest_batch_size,
                                index_name=ensure_case_index(evidence.case_id),
                                max_bulk_docs=max(1, int(runtime_settings.get("OPENSEARCH_BULK_DOCS", settings.opensearch_bulk_docs))),
                                max_bulk_bytes=max(1024, int(runtime_settings.get("OPENSEARCH_BULK_BYTES", settings.opensearch_bulk_bytes))),
                                tracker=parallel_tracker,
                                tracker_lock=parallel_tracker_lock,
                                manifest=manifest,
                                parallel_futures=parallel_futures,
                                detections_enabled=detections_enabled,
                            )
                            while len(parallel_futures) >= streaming_max_pending_futures:
                                if _drain_completed_parallel_futures(block=True) == 0:
                                    break
                        else:
                            artifacts_sequential_by_type[str(artifact_info.get("artifact_type") or "unknown")] += 1
                    _drain_completed_parallel_futures(block=False)
                    runtime_snapshot = _parallel_runtime_snapshot()
                    _benchmark_sample_resources(
                        benchmark_state,
                        active_workers=len(runtime_snapshot["running_snapshot"]),
                        queue_depth=len(parallel_futures),
                    )
                    running_snapshot = runtime_snapshot["running_snapshot"]
                    indexed_partial = indexed_count + int(runtime_snapshot["indexed_pending"] or 0)
                    records_partial = records_processed + int(runtime_snapshot["read_pending"] or 0)
                    elapsed_seconds = max(time.perf_counter() - started_monotonic, 0.001)
                    tail_metadata = _parallel_tail_metadata(
                        runtime_snapshot,
                        artifacts_processed=artifacts_processed,
                        failed_artifacts=len([item for item in parallel_results if item.get("error")]),
                        elapsed_seconds=elapsed_seconds,
                    )
                    _safe_update_progress_isolated(
                        evidence.id,
                        phase="materializing_and_parsing",
                        progress_pct=min(45, 30 + int((len(selected_candidates) / max(len(supported_selected_candidates), 1)) * 15)),
                        extra={
                            "selected_files_total": selective_stats.get("selected_files_total"),
                            "selected_files_processed": selective_stats.get("selected_files_materialized"),
                            "selected_files_reused": selective_stats.get("selected_files_reused"),
                            "selected_files_extracted": selective_stats.get("selected_files_extracted"),
                            "selected_failed": selective_stats.get("extraction_errors"),
                            "records_processed": records_partial,
                            "events_indexed": indexed_partial,
                            "records_per_second": round(records_partial / elapsed_seconds, 2),
                            **tail_metadata,
                            "parallel_ingest": {
                                "enabled": True,
                                "mode": "generic_artifact_scheduler",
                                "effective_parallelism": effective_parallelism,
                                "desired_parallelism": int(desired_parallel.get("desired_parallelism") or effective_parallelism),
                                "running_artifacts": runtime_snapshot["running_artifacts"],
                                "running_artifact_types": runtime_snapshot["running_artifact_types"],
                                "completed_artifacts": artifacts_processed,
                                "queued_artifacts": runtime_snapshot["queued_count"],
                                "failed_artifacts": len([item for item in parallel_results if item.get("error")]),
                                "records_per_second_total": round(records_partial / elapsed_seconds, 2),
                                "bottleneck": "materialization" if not running_snapshot else "parsing",
                                "artifacts_parallelized_by_type": dict(artifacts_parallelized_by_type),
                                "artifacts_sequential_by_type": dict(artifacts_sequential_by_type),
                                "materialization_queue_depth": max(len(materialized_artifacts) - artifacts_processed, 0),
                                "parser_queue_depth": len(parallel_futures),
                                "active_artifact_workers": len(running_snapshot),
                                "limitation_reason": None,
                            },
                        },
                    )
                artifacts = materialized_artifacts
            else:
                extract_dir, selected_candidates, archive_entries, selective_stats = _prepare_velociraptor_selected_staging(
                    evidence,
                    progress_cb=extraction_progress,
                )
                artifacts = list_velociraptor_artifacts(extract_dir, selected_candidates)
                if artifacts:
                    _benchmark_mark_first(benchmark_state, "time_to_first_artifact_ready")
        else:
            managed_extract_dir = reset_extracted_dir(evidence.case_id, evidence.id)
            use_external_directory = bool(getattr(evidence, "is_external", False)) and stored_path.is_dir()
            extract_dir = stored_path if use_external_directory else managed_extract_dir
            if stored_path.is_dir():
                extracted_files, archive_entries = inventory_folder(stored_path, progress_cb=extraction_progress) if use_external_directory else copy_folder(stored_path, extract_dir, progress_cb=extraction_progress)
            elif stored_path.suffix.lower() in {".zip", ".7z"}:
                extracted_files, archive_entries = extract_archive(stored_path, extract_dir, progress_cb=extraction_progress)
            else:
                target = extract_dir / stored_path.name
                target.write_bytes(stored_path.read_bytes())
                extracted_files = [target.name]
                archive_entries = [{"path": target.name, "ignored": False, "reason": None, "size": target.stat().st_size, "status": "extracted", "local_path": str(target)}]
            selected_candidates = None
            selective_stats = {}
            artifacts = []

        extracted_files = [entry["path"] for entry in archive_entries if entry.get("status") == "extracted"]
        if is_selected_velociraptor:
            manifest["stats"]["selected_files_total"] = selective_stats.get("selected_files_total", 0)
            manifest["stats"]["selected_files_extracted"] = selective_stats.get("selected_files_extracted", 0)
            manifest["stats"]["selected_files_reused"] = selective_stats.get("selected_files_reused", 0)
            manifest["stats"]["selected_files_materialized"] = selective_stats.get("selected_files_materialized", 0)
            manifest["stats"]["bytes_extracted"] = selective_stats.get("bytes_extracted", 0)
            manifest["stats"]["bytes_materialized"] = selective_stats.get("bytes_materialized", 0)
            manifest["stats"]["extraction_errors"] = selective_stats.get("extraction_errors", 0)
            manifest["stats"]["sqlite_files_extracted"] = selective_stats.get("sqlite_files_extracted", 0)
            manifest["stats"]["wal_shm_files_extracted"] = selective_stats.get("wal_shm_files_extracted", 0)
            manifest["stats"]["processed_files"] = selective_stats.get("selected_files_materialized", 0)
        else:
            for entry in archive_entries:
                file_path = extract_dir / entry["path"]
                manifest["files"].append(
                    build_file_entry(file_path, extract_dir, ignored=entry.get("ignored", False), reason=entry.get("reason"))
                    if not entry.get("ignored")
                    else {"path": entry["path"], "size": entry.get("size", 0), "sha256": None, "extension": Path(entry["path"]).suffix.lower(), "ignored": True, "reason": entry.get("reason")}
                )
            manifest["stats"]["total_files"] = len(archive_entries)
            manifest["stats"]["ignored_files"] = sum(1 for entry in archive_entries if entry.get("ignored"))
            manifest["stats"]["processed_files"] = len(extracted_files)
            write_tree_metadata(reset_staging_dir(evidence.case_id, evidence.id) / "tree.json", extracted_files)
        extraction_diagnostics = {
            "archive_size_bytes": stored_path.stat().st_size if stored_path.exists() and stored_path.is_file() else None,
            "container_type": "directory" if stored_path.is_dir() else stored_path.suffix.lower().lstrip(".") or "file",
            "extractor_used": extractor_used,
            "archive_entries_total": len(archive_entries),
            "archive_entries_extracted": sum(1 for entry in archive_entries if not entry.get("ignored")),
            "archive_entries_ignored": sum(1 for entry in archive_entries if entry.get("ignored")),
            "archive_bytes_total": sum(int(entry.get("size") or 0) for entry in archive_entries),
            "archive_bytes_extracted": sum(int(entry.get("size") or 0) for entry in archive_entries if not entry.get("ignored")),
            "selected_extraction": bool(is_selected_velociraptor),
            "selected_extraction_stats": selective_stats if is_selected_velociraptor else {},
        }
        metadata["extraction_diagnostics"] = extraction_diagnostics
        evidence.metadata_json = metadata
        db.add(evidence)
        db.commit()
        write_manifest(manifest_path, manifest)
        if artifacts:
            _benchmark_mark_first(benchmark_state, "time_to_first_artifact_ready")
            _safe_persist_benchmark_snapshot(
                evidence.id,
                benchmark_state,
                status="running",
                effective_parallelism=int(effective_parallelism or 1),
                artifacts_total=len(artifacts),
                artifacts_completed=int(artifacts_processed or 0),
                records_read=int(records_processed or 0),
                records_indexed=int(indexed_count or 0),
            )

        if not is_selected_velociraptor:
            _update_progress(
                db,
                evidence,
                phase="detecting",
                progress_pct=20,
                extra={
                    "tree": extracted_files,
                    "original_files": len(extracted_files),
                    "files_extracted": len(archive_entries),
                    "files_total": len(archive_entries),
                    "current_item": None,
                },
            )
        if _is_raw_collection_with_discovery(evidence):
            # Preserve the legacy persisted enum for DB compatibility, but keep the
            # public classification anchored to raw_collection via source_tool/metadata.
            evidence.evidence_type = EvidenceType.velociraptor_zip
            evidence.source_tool = "raw_collection"
        else:
            evidence.evidence_type = detect_evidence_type(stored_path, extracted_files if not is_selected_velociraptor else [])
            if evidence.evidence_type == EvidenceType.velociraptor_zip:
                evidence.source_tool = "velociraptor"
            elif evidence.evidence_type in {EvidenceType.kape_archive, EvidenceType.parsed_folder}:
                evidence.source_tool = "kape"
            elif evidence.evidence_type == EvidenceType.evtx:
                evidence.source_tool = "windows_event_log"

        def discovery_progress(extra: dict) -> None:
            elapsed_seconds = max(time.perf_counter() - started_monotonic, 0.001)
            scanned = int(extra.get("files_scanned") or 0)
            total = int(extra.get("total_files") or 0)
            discovery_pct = 20 if total <= 0 else min(28, 20 + int((scanned / max(total, 1)) * 8))
            estimated_remaining = _estimate_remaining_seconds(elapsed_seconds=elapsed_seconds, progress_pct=discovery_pct)
            _safe_update_progress_isolated(
                evidence.id,
                phase="discovering",
                progress_pct=discovery_pct,
                extra={
                    "elapsed_seconds": round(elapsed_seconds, 2),
                    "estimated_remaining_seconds": round(estimated_remaining, 2) if estimated_remaining is not None else None,
                    "discovery_files_scanned": scanned,
                    "discovery_total_files": total,
                    "discovery_candidates_detected": int(extra.get("candidates") or 0),
                    "current_item": extra.get("current_path"),
                },
            )
            _benchmark_sample_resources(benchmark_state)

        if not is_selected_velociraptor:
            artifacts = _select_artifacts(evidence, extract_dir, progress_cb=discovery_progress if evidence.evidence_type == EvidenceType.velociraptor_zip else None)
        processable_artifacts, skipped_mode_artifacts = _partition_artifacts_for_ingest_mode(artifacts, ingest_mode=ingest_mode)
        artifacts = processable_artifacts
        skipped_manifest_entries = [_build_skipped_artifact_entry(item, status=str(item.get("status") or "skipped_experimental")) for item in skipped_mode_artifacts]
        for skipped_item, manifest_item in zip(skipped_mode_artifacts, skipped_manifest_entries, strict=False):
            _create_artifact_row_isolated(
                case_id=evidence.case_id,
                evidence_id=evidence.id,
                name=str(skipped_item.get("name") or skipped_item.get("source_path") or "skipped_artifact"),
                artifact_type=str(skipped_item.get("artifact_type") or "unknown"),
                source_path=str(skipped_item.get("source_path") or skipped_item.get("name") or ""),
                parser=str(skipped_item.get("parser") or "unknown"),
                status=str(skipped_item.get("status") or "skipped_experimental"),
            )
            manifest["artifacts"].append(manifest_item)
        candidate_hosts: list[str] = []
        detected_host_counts: Counter[str] = Counter()
        collection_host_candidate: str | None = None
        if evidence.evidence_type == EvidenceType.velociraptor_zip:
            velo_host = detect_host_from_velociraptor_collection(stored_path)
            if velo_host:
                collection_host_candidate = velo_host
                candidate_hosts.append(velo_host)
                detected_host_counts[velo_host] += 1
        artifact_host = detect_host_from_artifacts(artifacts)
        if artifact_host:
            candidate_hosts.append(artifact_host)
            detected_host_counts[artifact_host] += 1
        candidate_hosts = [
            host
            for host in dict.fromkeys(filter(None, map(normalize_hostname, candidate_hosts)))
            if classify_host_candidate(host, source="collection_filename" if host == collection_host_candidate else "explicit_field")["accepted"]
        ]
        metadata = dict(evidence.metadata_json or {})
        metadata["detected_hosts"] = candidate_hosts
        metadata["detected_host_counts"] = dict(detected_host_counts)
        if collection_host_candidate:
            metadata["collection_host_candidate"] = collection_host_candidate
        primary_host = choose_primary_host(collection_candidate=collection_host_candidate, host_counts=metadata["detected_host_counts"])
        evidence.detected_host = primary_host.get("host")
        evidence.metadata_json = merge_evidence_metadata(evidence.metadata_json or {}, metadata)
        db.commit()

        total_artifacts = len(artifacts) + len(skipped_mode_artifacts)
        artifacts_processed = len(skipped_mode_artifacts)
        raw_artifacts = [item for item in artifacts if _artifact_is_raw_not_parsed(item)]
        result_artifacts = [item for item in artifacts if not _artifact_is_raw_not_parsed(item)]
        native_raw_artifacts = [item for item in result_artifacts if str(item.get("parser") or "").lower() in {"evtx_raw", "lnk_raw", "prefetch_raw", "amcache_raw", "shimcache_raw", "windows_service_registry"}]
        manifest["stats"]["detected_artifacts"] = total_artifacts
        manifest["stats"]["skipped_artifacts"] = len(skipped_mode_artifacts)
        manifest["stats"]["results_artifacts_skipped"] = len(skipped_mode_artifacts)
        manifest["stats"]["results_artifacts_detected"] = len(result_artifacts)
        manifest["stats"]["raw_artifacts_detected"] = len(raw_artifacts) + len(native_raw_artifacts)
        manifest["stats"]["raw_artifacts_parsed"] = len(native_raw_artifacts)
        manifest["stats"]["raw_artifacts_not_parsed"] = len(raw_artifacts)
        write_manifest(manifest_path, manifest)
        _update_progress(
            db,
            evidence,
            phase="parsing",
            progress_pct=45 if is_selected_velociraptor else 30,
            extra={
                "detected_artifacts": total_artifacts,
                "processed_artifacts": 0,
                "indexed_events": 0,
                "artifacts_total": total_artifacts,
                "raw_artifacts_detected": len(raw_artifacts) + len(native_raw_artifacts),
                "raw_artifacts_parsed": len(native_raw_artifacts),
                "raw_artifacts_not_parsed": len(raw_artifacts),
                "discovery_files_scanned": len(extracted_files) if not is_selected_velociraptor else evidence.metadata_json.get("total_zip_entries"),
                "discovery_total_files": len(extracted_files) if not is_selected_velociraptor else evidence.metadata_json.get("total_zip_entries"),
                "discovery_candidates_detected": total_artifacts,
                "selected_files_total": selective_stats.get("selected_files_total") if is_selected_velociraptor else None,
                "selected_files_extracted": selective_stats.get("selected_files_extracted") if is_selected_velociraptor else None,
                "bytes_extracted": selective_stats.get("bytes_extracted") if is_selected_velociraptor else None,
            },
        )
        index_name = ensure_case_index(evidence.case_id)
        max_bulk_docs = max(1, int(runtime_settings.get("OPENSEARCH_BULK_DOCS", settings.opensearch_bulk_docs)))
        max_bulk_bytes = max(1024, int(runtime_settings.get("OPENSEARCH_BULK_BYTES", settings.opensearch_bulk_bytes)))
        parser_capabilities_used = {
            str(item.get("parser") or "").lower(): _parser_capabilities(item.get("parser"), item.get("artifact_type"))
            for item in artifacts
            if item.get("parser")
        }
        parallel_candidate_artifacts = [
            item
            for item in artifacts
            if _artifact_can_parallelize(item)
            and not (str(item.get("parser") or "").lower() == "evtx_raw" and _evtx_fast_limits_for_run(metadata))
        ]
        desired_parallel = describe_ingest_parallelism(
            {**runtime_settings, PERFORMANCE_PROFILE_KEY: performance_snapshot["performance_profile"]},
            system=performance_system,
            artifact_count=len(parallel_candidate_artifacts),
            artifact_types=[str(item.get("parser") or "").lower() for item in parallel_candidate_artifacts if item.get("parser")],
            supported_artifact_types=list(PARSER_CAPABILITIES.keys()),
        )
        parser_parallel_limit = min(
            [int((_parser_capabilities(item.get("parser"), item.get("artifact_type")).get("max_parallelism") or 1)) for item in parallel_candidate_artifacts] or [1]
        )
        effective_parallelism = min(int(desired_parallel.get("effective_parallelism") or 1), max(parser_parallel_limit, 1))
        parallel_enabled = effective_parallelism > 1 and len(parallel_candidate_artifacts) > 1
        parallel_safe_artifacts, sequential_artifacts = _split_parallel_and_sequential_artifacts(
            artifacts,
            metadata=metadata,
            parallel_enabled=parallel_enabled,
        )
        if not streaming_materialization_enabled:
            artifacts_parallelized_by_type = Counter(str(item.get("artifact_type") or "unknown") for item in parallel_safe_artifacts)
            artifacts_sequential_by_type = Counter(str(item.get("artifact_type") or "unknown") for item in sequential_artifacts)
            parser_capabilities_used = {
                str(item.get("parser") or "").lower(): _parser_capabilities(item.get("parser"), item.get("artifact_type"))
                for item in artifacts
                if item.get("parser")
            }
        if parallel_safe_artifacts and not streaming_materialization_enabled:
            _update_progress(
                db,
                evidence,
                phase="parsing",
                progress_pct=45 if is_selected_velociraptor else 30,
                extra={
                    "parallel_ingest": {
                        "enabled": parallel_enabled,
                        "mode": "threads" if parallel_enabled else "off",
                        "effective_parallelism": effective_parallelism if parallel_enabled else 1,
                        "desired_parallelism": int(desired_parallel.get("desired_parallelism") or 1),
                        "supported_artifact_types": sorted({str(item.get("artifact_type") or "") for item in parallel_safe_artifacts if item.get("artifact_type")}),
                        "running_artifacts": [],
                        "running_artifact_types": [],
                        "completed_artifacts": 0,
                        "queued_artifacts": len(parallel_safe_artifacts),
                        "failed_artifacts": 0,
                        "records_per_second_total": 0,
                        "bottleneck": "waiting_for_worker" if parallel_enabled else "sequential_fallback",
                        "artifacts_parallelized_by_type": dict(artifacts_parallelized_by_type),
                        "artifacts_sequential_by_type": dict(artifacts_sequential_by_type),
                        "limitation_reason": None if parallel_enabled else (desired_parallel.get("limit_reason") or "unsupported_artifact_type"),
                    }
                },
            )
        if not streaming_materialization_enabled:
            executor = ThreadPoolExecutor(max_workers=effective_parallelism) if parallel_enabled else None
            if executor:
                for artifact_info in parallel_safe_artifacts:
                    _benchmark_mark_first(benchmark_state, "time_to_first_parse_start")
                    _benchmark_transition_phase(
                        benchmark_state,
                        "parsing",
                        records_read=records_processed,
                        records_indexed=indexed_count,
                        artifacts_processed=artifacts_processed,
                    )
                    _schedule_parallel_artifact(
                        executor=executor,
                        evidence=evidence,
                        artifact_info=artifact_info,
                        ingest_batch_size=ingest_batch_size,
                        index_name=index_name,
                        max_bulk_docs=max_bulk_docs,
                        max_bulk_bytes=max_bulk_bytes,
                        tracker=parallel_tracker,
                        tracker_lock=parallel_tracker_lock,
                        manifest=manifest,
                        parallel_futures=parallel_futures,
                        detections_enabled=detections_enabled,
                    )

        sequential_evtx_fast_limits = _evtx_fast_limits_for_run(metadata)
        sequential_evtx_fast_started = time.perf_counter()
        sequential_evtx_records_read = 0

        for index, artifact_info in enumerate(sequential_artifacts, start=1):
            _benchmark_mark_first(benchmark_state, "time_to_first_parse_start")
            _benchmark_transition_phase(
                benchmark_state,
                "parsing",
                records_read=records_processed,
                records_indexed=indexed_count,
                artifacts_processed=artifacts_processed,
            )
            initial_status = _initial_runtime_artifact_status(artifact_info=artifact_info, parallel_safe=False)
            artifact_id = _create_artifact_row_isolated(
                case_id=evidence.case_id,
                evidence_id=evidence.id,
                name=artifact_info["name"],
                artifact_type=artifact_info["artifact_type"],
                source_path=artifact_info["source_path"],
                parser=artifact_info["parser"],
                status=initial_status,
            )
            artifact_record_count = 0

            manifest_artifact = {
                "name": artifact_info["name"],
                "source_path": artifact_info["source_path"],
                "artifact_type": artifact_info["artifact_type"],
                "parser": artifact_info["parser"],
                "profile": artifact_info.get("profile"),
                "record_count": 0,
                "status": initial_status,
                "reason": artifact_info.get("reason"),
                "planned_parser": artifact_info.get("planned_parser"),
            }
            manifest["artifacts"].append(manifest_artifact)

            try:
                if _artifact_is_raw_not_parsed(artifact_info):
                    _update_artifact_row_isolated(artifact_id, status="detected_not_parsed")
                    manifest_artifact["status"] = "detected_not_parsed"
                else:
                    preferred_host = str((evidence.metadata_json or {}).get("provided_host") or evidence.detected_host or "").strip() or None
                    artifact_meta = {
                        **artifact_info,
                        "detected_host": preferred_host,
                        "provided_host": str((evidence.metadata_json or {}).get("provided_host") or "").strip() or None,
                        "detected_user": evidence.detected_user,
                        "ingest_run_id": current_run_id,
                        "contract_version": "v1",
                    }
                    ingest_audit = None
                    documents: list[dict] = []
                    row_hosts: Counter[str] = Counter()
                    detections_created_inline = False
                    if artifact_info.get("parser") in {"sqlite_chromium", "sqlite_firefox", "browser_chromium_history", "browser_firefox_places"} and artifact_info["artifact_type"] == "browser":
                        browser_audit = BrowserAudit()
                        source_path = str(artifact_info.get("velociraptor_original_path") or artifact_info.get("source_path") or artifact_info["name"])
                        if artifact_info.get("parser") in {"sqlite_chromium", "browser_chromium_history"}:
                            rows, sqlite_copies = parse_chromium_history_sqlite(artifact_info["path"], source_path=source_path)
                        else:
                            rows, sqlite_copies = parse_firefox_places_sqlite(artifact_info["path"], source_path=source_path)
                        documents = _normalize_velociraptor_browser_rows(
                            evidence.case_id,
                            evidence.id,
                            artifact_id,
                            rows,
                            artifact_meta,
                            collection_id=evidence.id,
                            original_path=source_path,
                            normalized_windows_path=artifact_info.get("velociraptor_normalized_windows_path"),
                            parser_status=artifact_info.get("velociraptor_parser_status"),
                            browser_audit=browser_audit,
                        )
                        if documents and ingest_batch_size and len(documents) > ingest_batch_size:
                            batches = math.ceil(len(documents) / ingest_batch_size)
                        else:
                            batches = 1 if documents else 0
                        docs_processed_in_artifact = 0
                        row_hosts = Counter(
                            normalize_hostname(document.get("host", {}).get("name"))
                            for document in documents
                            if normalize_hostname(document.get("host", {}).get("name"))
                        )
                        for batch_index in range(batches):
                            start = batch_index * ingest_batch_size
                            end = start + ingest_batch_size
                            batch_documents = documents[start:end]
                            bulk_report = bulk_index_events_with_report(
                                evidence.case_id,
                                batch_documents,
                                index=index_name,
                                refresh=False,
                                max_bulk_docs=max_bulk_docs,
                                max_bulk_bytes=max_bulk_bytes,
                            )
                            _merge_bulk_report(opensearch_bulk, bulk_report, detection_warnings)
                            created_count = 0
                            warning = None
                            if detections_enabled:
                                created_count, warning = _safe_create_builtin_detections_isolated(
                                    case_id=evidence.case_id,
                                    evidence_id=evidence.id,
                                    artifact_id=artifact_id,
                                    artifact_name=artifact_info["name"],
                                    documents=batch_documents,
                                )
                            detection_count += created_count
                            if warning:
                                detection_warnings.append({"artifact": artifact_info["name"], "warning": warning})
                            detections_created_inline = True
                            docs_processed_in_artifact += len(batch_documents)
                            if batch_documents:
                                _benchmark_mark_first(benchmark_state, "time_to_first_event_indexed")
                            elapsed_seconds = max(time.perf_counter() - started_monotonic, 0.001)
                            batch_progress = _artifact_batch_progress_pct(
                                artifact_index=index,
                                total_artifacts=total_artifacts,
                                batch_index=batch_index + 1,
                                total_batches=batches,
                            )
                            _safe_update_progress_isolated(
                                evidence.id,
                                phase="indexing",
                                progress_pct=batch_progress,
                                extra={
                                    "processed_artifacts": artifacts_processed,
                                    "detected_artifacts": total_artifacts,
                                    "indexed_events": indexed_count + docs_processed_in_artifact,
                                    "last_artifact": artifact_info["name"],
                                    "generated_detections": detection_count,
                                    "records_processed": records_processed + docs_processed_in_artifact,
                                    "events_indexed": indexed_count + docs_processed_in_artifact,
                                    "current_artifact": artifact_info["name"],
                                    "current_artifact_path": artifact_info["source_path"],
                                    "current_artifact_index": index,
                                    "artifacts_processed": artifacts_processed,
                                    "artifacts_total": total_artifacts,
                                    "artifacts_done": artifacts_processed,
                                    "artifacts_failed": len(errors),
                                    "artifact_batch": batch_index + 1,
                                    "artifact_batches_total": batches,
                                    "elapsed_seconds": round(elapsed_seconds, 2),
                                    "records_per_second": round((records_processed + docs_processed_in_artifact) / elapsed_seconds, 2),
                                    "estimated_remaining_seconds": round(_estimate_remaining_seconds(elapsed_seconds=elapsed_seconds, progress_pct=batch_progress) or 0.0, 2),
                                    "raw_artifacts_detected": len(raw_artifacts),
                                    "raw_artifacts_not_parsed": len(raw_artifacts),
                                },
                            )
                        artifact_record_count = len(documents)
                        _update_artifact_row_isolated(artifact_id, record_count=artifact_record_count)
                        indexed_count += len(documents)
                        records_processed += len(documents)
                        ingest_audit = browser_audit.as_dict(
                            artifact_name=artifact_info["name"],
                            parser_name=str(artifact_info.get("parser") or "browser_csv"),
                            bulk_index_errors=0,
                        )
                        ingest_audit["sqlite_copies"] = sqlite_copies
                        (
                            ingest_audit["by_browser"],
                            ingest_audit["by_artifact_type"],
                            ingest_audit["by_event_type"],
                            ingest_audit["danger_type_counts"],
                            ingest_audit["data_quality_counts"],
                            ingest_audit["suspicious_reason_counts"],
                        ) = _browser_audit_rollups(documents)
                    elif artifact_info["artifact_type"] in {"mft", "usn"} and artifact_info.get("parser") == "zimmerman":
                        batch_counter = 0
                        total_documents = 0
                        use_mft_fast_path = bool(runtime_settings.get("MFT_FAST_PATH", settings.mft_fast_path)) and artifact_info["artifact_type"] == "mft"
                        for batch_documents in iter_mftecmd_batches(
                            evidence.case_id,
                            evidence.id,
                            artifact_id,
                            artifact_info["path"],
                            artifact_meta,
                            batch_size=ingest_batch_size,
                            fast_path=use_mft_fast_path,
                        ):
                            if not batch_documents:
                                continue
                            batch_counter += 1
                            total_documents += len(batch_documents)
                            for document in batch_documents:
                                normalized_host = normalize_hostname(document.get("host", {}).get("name"))
                                if normalized_host:
                                    row_hosts[normalized_host] += 1
                            bulk_report = bulk_index_events_with_report(
                                evidence.case_id,
                                batch_documents,
                                index=index_name,
                                refresh=False,
                                max_bulk_docs=max_bulk_docs,
                                max_bulk_bytes=max_bulk_bytes,
                            )
                            _merge_bulk_report(opensearch_bulk, bulk_report, detection_warnings)
                            created_count = 0
                            warning = None
                            if detections_enabled:
                                created_count, warning = _safe_create_builtin_detections_isolated(
                                    case_id=evidence.case_id,
                                    evidence_id=evidence.id,
                                    artifact_id=artifact_id,
                                    artifact_name=artifact_info["name"],
                                    documents=batch_documents,
                                )
                            detection_count += created_count
                            if warning:
                                detection_warnings.append({"artifact": artifact_info["name"], "warning": warning})
                            indexed_count += len(batch_documents)
                            records_processed += len(batch_documents)
                            if batch_documents:
                                _benchmark_mark_first(benchmark_state, "time_to_first_event_indexed")
                            elapsed_seconds = max(time.perf_counter() - started_monotonic, 0.001)
                            batch_progress = min(90, 30 + min(60, batch_counter))
                            _safe_update_progress_isolated(
                                evidence.id,
                                phase="indexing",
                                progress_pct=batch_progress,
                                extra={
                                    "processed_artifacts": artifacts_processed,
                                    "detected_artifacts": total_artifacts,
                                    "indexed_events": indexed_count,
                                    "last_artifact": artifact_info["name"],
                                    "generated_detections": detection_count,
                                    "records_processed": records_processed,
                                    "events_indexed": indexed_count,
                                    "current_artifact": artifact_info["name"],
                                    "artifacts_processed": artifacts_processed,
                                    "artifacts_total": total_artifacts,
                                    "artifact_batch": batch_counter,
                                    "artifact_batches_total": max(batch_counter, 1),
                                    "elapsed_seconds": round(elapsed_seconds, 2),
                                    "records_per_second": round(records_processed / elapsed_seconds, 2),
                                    "estimated_remaining_seconds": round(_estimate_remaining_seconds(elapsed_seconds=elapsed_seconds, progress_pct=batch_progress) or 0.0, 2),
                                    "raw_artifacts_detected": len(raw_artifacts),
                                    "raw_artifacts_not_parsed": len(raw_artifacts),
                                },
                            )
                        artifact_record_count = total_documents
                        _update_artifact_row_isolated(artifact_id, record_count=artifact_record_count)
                        ingest_audit = artifact_meta.get("ingest_audit")
                    else:
                        raw_progress_cb = None
                        if str(artifact_info.get("parser") or "").lower() == "evtx_raw":
                            raw_progress_cb = _artifact_progress_callback(
                                evidence_id=evidence.id,
                                artifact_name=artifact_info["name"],
                                artifact_index=index,
                                total_artifacts=total_artifacts,
                                artifacts_processed=artifacts_processed,
                                indexed_count=indexed_count,
                                records_processed=records_processed,
                                detection_count=detection_count,
                                raw_artifacts_detected=len(raw_artifacts),
                                raw_artifacts_not_parsed=len(raw_artifacts),
                                started_monotonic=started_monotonic,
                                state={
                                    "records_indexed_in_artifact": 0,
                                    "events_indexed_total": indexed_count,
                                    "records_processed_total": records_processed,
                                    "detection_count": detection_count,
                                },
                            )
                        if str(artifact_info.get("parser") or "").lower() == "evtx_raw":
                            documents = []
                            docs_processed_in_artifact = 0
                            evtx_batches = 0
                            final_result = None
                            row_hosts = Counter()
                            parser = EvtxRawParser()
                            evtx_backend_selection: dict | None = None

                            def _sequential_evtx_limit_checker(*, records_read: int, events_indexed: int, elapsed_seconds: float) -> str | None:  # noqa: ARG001
                                if not sequential_evtx_fast_limits:
                                    return None
                                current_total = sequential_evtx_records_read + int(records_read or 0)
                                max_total_records = int(sequential_evtx_fast_limits.get("max_total_records") or 0)
                                if max_total_records and current_total >= max_total_records:
                                    return "max_total_records"
                                max_total_seconds = int(sequential_evtx_fast_limits.get("max_total_seconds") or 0)
                                if max_total_seconds and (time.perf_counter() - sequential_evtx_fast_started) >= max_total_seconds:
                                    return "max_total_seconds"
                                return None

                            if sequential_evtx_fast_limits:
                                batch_results = _iter_evtx_fast_batches_with_hard_timeout(
                                    path=Path(artifact_info["path"]),
                                    case_id=evidence.case_id,
                                    evidence_id=evidence.id,
                                    artifact_id=artifact_id,
                                    artifact_meta=artifact_meta,
                                    batch_size=_evtx_fast_batch_size(ingest_batch_size),
                                    progress_cb=raw_progress_cb,
                                    record_timeout_seconds=max(int(settings.evtx_artifact_stall_seconds or 0), 0),
                                    max_records=int(sequential_evtx_fast_limits.get("max_records_per_file") or 0),
                                    max_seconds=int(sequential_evtx_fast_limits.get("max_seconds_per_file") or 0),
                                    limits=sequential_evtx_fast_limits,
                                    limit_checker=_sequential_evtx_limit_checker,
                                )
                                wrapped_batch_results = ((None, item) for item in batch_results)
                            else:
                                wrapped_batch_results = _iter_full_evtx_batches_with_backend(
                                    path=Path(artifact_info["path"]),
                                    case_id=evidence.case_id,
                                    evidence_id=evidence.id,
                                    artifact_id=artifact_id,
                                    artifact_meta=artifact_meta,
                                    batch_size=max(int(ingest_batch_size or 0), 500),
                                    progress_cb=raw_progress_cb,
                                    record_timeout_seconds=max(int(settings.evtx_artifact_stall_seconds or 0), 0),
                                    requested_backend=metadata.get("evtx_parser_backend"),
                                )

                            for backend_selection, batch_result in wrapped_batch_results:
                                if backend_selection:
                                    evtx_backend_selection = backend_selection
                                final_result = batch_result
                                batch_documents = batch_result.events
                                if not batch_documents:
                                    continue
                                evtx_batches += 1
                                row_hosts.update(
                                    normalize_hostname(document.get("host", {}).get("name"))
                                    for document in batch_documents
                                    if normalize_hostname(document.get("host", {}).get("name"))
                                )
                                with _timed_evtx_operation(settings.evtx_artifact_stall_seconds, f"EVTX bulk index stalled for {artifact_info['name']}"):
                                    bulk_report = bulk_index_events_with_report(
                                        evidence.case_id,
                                        batch_documents,
                                        index=index_name,
                                        refresh=False,
                                        max_bulk_docs=max_bulk_docs,
                                        max_bulk_bytes=max_bulk_bytes,
                                    )
                                _merge_bulk_report(opensearch_bulk, bulk_report, detection_warnings)
                                with _timed_evtx_operation(settings.evtx_artifact_stall_seconds, f"EVTX detections stalled for {artifact_info['name']}"):
                                    created_count = 0
                                    warning = None
                                    if detections_enabled:
                                        created_count, warning = _safe_create_builtin_detections_isolated(
                                            case_id=evidence.case_id,
                                            evidence_id=evidence.id,
                                            artifact_id=artifact_id,
                                            artifact_name=artifact_info["name"],
                                            documents=batch_documents,
                                        )
                                detection_count += created_count
                                if warning:
                                    detection_warnings.append({"artifact": artifact_info["name"], "warning": warning})
                                detections_created_inline = True
                                indexed_count += len(batch_documents)
                                records_processed += len(batch_documents)
                                docs_processed_in_artifact += len(batch_documents)
                                _benchmark_mark_first(benchmark_state, "time_to_first_event_indexed")
                                raw_progress_tracker = getattr(raw_progress_cb, "_tracker", None)
                                if isinstance(raw_progress_tracker, dict):
                                    raw_progress_tracker["records_indexed_in_artifact"] = docs_processed_in_artifact
                                    raw_progress_tracker["events_indexed_total"] = indexed_count
                                    raw_progress_tracker["records_processed_total"] = records_processed
                                    raw_progress_tracker["detection_count"] = detection_count
                                elapsed_seconds = max(time.perf_counter() - started_monotonic, 0.001)
                                batch_progress = _artifact_batch_progress_pct(
                                    artifact_index=index,
                                    total_artifacts=total_artifacts,
                                    batch_index=evtx_batches,
                                    total_batches=max(evtx_batches + (0 if batch_result.metadata.get("completed") else 1), evtx_batches, 1),
                                )
                                _safe_update_progress_isolated(
                                    evidence.id,
                                    phase="parsing",
                                    progress_pct=batch_progress,
                                    extra={
                                        "processed_artifacts": artifacts_processed,
                                        "detected_artifacts": total_artifacts,
                                        "indexed_events": indexed_count,
                                        "last_artifact": artifact_info["name"],
                                        "generated_detections": detection_count,
                                        "records_processed": records_processed,
                                        "events_indexed": indexed_count,
                                    "current_artifact": artifact_info["name"],
                                    "current_artifact_path": artifact_info["source_path"],
                                    "current_artifact_records_read": batch_result.records_read,
                                    "current_artifact_events_buffered": len(batch_documents),
                                    "current_artifact_records_indexed": docs_processed_in_artifact,
                                        "current_artifact_pending_index_records": max(batch_result.records_read - docs_processed_in_artifact, 0),
                                        "current_artifact_errors": len(batch_result.errors),
                                        "current_artifact_progress_label": f"{batch_result.records_read} records read / {docs_processed_in_artifact} indexed",
                                        "artifacts_processed": artifacts_processed,
                                        "artifacts_total": total_artifacts,
                                        "artifacts_done": artifacts_processed,
                                        "artifacts_failed": len(errors),
                                        "current_artifact_index": index,
                                        "artifact_batch": evtx_batches,
                                        "artifact_batches_total": max(evtx_batches, 1),
                                        "elapsed_seconds": round(elapsed_seconds, 2),
                                        "records_per_second": round((records_processed + docs_processed_in_artifact) / elapsed_seconds, 2),
                                        "estimated_remaining_seconds": round(_estimate_remaining_seconds(elapsed_seconds=elapsed_seconds, progress_pct=batch_progress) or 0.0, 2),
                                        "raw_artifacts_detected": len(raw_artifacts),
                                        "raw_artifacts_not_parsed": len(raw_artifacts),
                                        "selected_files_total": selective_stats.get("selected_files_total") if is_selected_velociraptor else None,
                                        "selected_files_extracted": selective_stats.get("selected_files_extracted") if is_selected_velociraptor else None,
                                        "bytes_extracted": selective_stats.get("bytes_extracted") if is_selected_velociraptor else None,
                                    },
                                )
                                stall_seconds = max(int(settings.evtx_artifact_stall_seconds or 0), 0)
                                last_progress_monotonic = float((raw_progress_tracker or {}).get("last_progress_monotonic", 0.0))
                                if stall_seconds > 0 and last_progress_monotonic > 0 and (time.perf_counter() - last_progress_monotonic) > stall_seconds:
                                    raise TimeoutError(
                                        f"EVTX artifact stalled for {stall_seconds}s: {artifact_info['name']} ({batch_result.records_read} read / {docs_processed_in_artifact} indexed)"
                                    )
                            if final_result is None:
                                final_result = parser.parse(
                                    artifact_info["path"],
                                    case_id=evidence.case_id,
                                    evidence_id=evidence.id,
                                    artifact_id=artifact_id,
                                    artifact_meta=artifact_meta,
                                    progress_cb=raw_progress_cb,
                                )
                                docs_processed_in_artifact = len(final_result.events)
                            artifact_meta["raw_parser_status"] = final_result.parser_status
                            artifact_meta["raw_parser_warnings"] = list(final_result.warnings)
                            artifact_meta["raw_parser_errors"] = list(final_result.errors)
                            artifact_meta["ingest_audit"] = final_result.metadata.get("audit") or {
                                "parser_name": final_result.parser_name,
                                "source_file": final_result.source_path,
                                "records_read": final_result.records_read,
                                "events_indexed": docs_processed_in_artifact,
                                "warnings_count": len(final_result.warnings),
                                "errors_count": len(final_result.errors),
                                "parser_status": final_result.parser_status,
                            }
                            ingest_audit = artifact_meta.get("ingest_audit")
                            if isinstance(ingest_audit, dict):
                                ingest_audit["records_read"] = int(final_result.records_read or docs_processed_in_artifact)
                                ingest_audit["records_indexed"] = docs_processed_in_artifact
                                ingest_audit["events_indexed"] = docs_processed_in_artifact
                                if sequential_evtx_fast_limits:
                                    ingest_audit["evtx_fast_limits"] = dict(sequential_evtx_fast_limits)
                                    ingest_audit["evtx_parser_backend"] = EVTX_RAW_PYTHON_BACKEND
                                    ingest_audit["evtx_parser_backend_version"] = ""
                                    ingest_audit["evtx_parser_backend_fallback"] = False
                                    ingest_audit["evtx_parser_backend_error"] = None
                                else:
                                    ingest_audit["evtx_parser_backend"] = str(final_result.metadata.get("evtx_parser_backend") or (evtx_backend_selection or {}).get("selected") or EVTX_RAW_PYTHON_BACKEND)
                                    ingest_audit["evtx_parser_backend_version"] = str(final_result.metadata.get("evtx_parser_backend_version") or (evtx_backend_selection or {}).get("version") or "")
                                    ingest_audit["evtx_parser_backend_fallback"] = bool(final_result.metadata.get("evtx_parser_backend_fallback") or (evtx_backend_selection or {}).get("fallback"))
                                    ingest_audit["evtx_parser_backend_error"] = final_result.metadata.get("evtx_parser_backend_error") or (evtx_backend_selection or {}).get("error")
                                if final_result.parser_status == "partial":
                                    limit_reason = str(final_result.metadata.get("limit_reason") or "evtx_fast_limit")
                                    ingest_audit["parser_status"] = "partial"
                                    ingest_audit["partial"] = True
                                    ingest_audit["limit_reason"] = limit_reason
                                    artifact_meta["evtx_partial"] = _evtx_partial_entry(
                                        artifact_id=artifact_id,
                                        artifact_name=artifact_info["name"],
                                        source_path=artifact_info["source_path"],
                                        reason=limit_reason,
                                        records_read=int(final_result.records_read or docs_processed_in_artifact),
                                        records_indexed=docs_processed_in_artifact,
                                        limits=sequential_evtx_fast_limits,
                                    )
                            sequential_evtx_records_read += int(final_result.records_read or docs_processed_in_artifact)
                            artifact_record_count = docs_processed_in_artifact
                            if not _update_artifact_row_isolated(artifact_id, record_count=artifact_record_count):
                                detection_warnings.append({"artifact": artifact_info["name"], "warning": "artifact_state_stale_after_evtx_parse"})
                        else:
                            documents = normalize_file(
                                evidence.case_id,
                                evidence.id,
                                artifact_id,
                                artifact_info["path"],
                                artifact_meta,
                                progress_cb=raw_progress_cb,
                            )
                            ingest_audit = artifact_meta.get("ingest_audit")
                            if ingest_batch_size and len(documents) > ingest_batch_size:
                                batches = math.ceil(len(documents) / ingest_batch_size)
                            else:
                                batches = 1
                            docs_processed_in_artifact = 0
                            row_hosts = Counter(
                                normalize_hostname(document.get("host", {}).get("name"))
                                for document in documents
                                if normalize_hostname(document.get("host", {}).get("name"))
                            )
                            for batch_index in range(batches):
                                start = batch_index * ingest_batch_size
                                end = start + ingest_batch_size
                                batch_documents = documents[start:end]
                                bulk_report = bulk_index_events_with_report(
                                    evidence.case_id,
                                    batch_documents,
                                    index=index_name,
                                    refresh=False,
                                    max_bulk_docs=max_bulk_docs,
                                    max_bulk_bytes=max_bulk_bytes,
                                )
                                _merge_bulk_report(opensearch_bulk, bulk_report, detection_warnings)
                                docs_processed_in_artifact += len(batch_documents)
                                elapsed_seconds = max(time.perf_counter() - started_monotonic, 0.001)
                                batch_progress = _artifact_batch_progress_pct(
                                    artifact_index=index,
                                    total_artifacts=total_artifacts,
                                    batch_index=batch_index + 1,
                                    total_batches=batches,
                                )
                            _safe_update_progress_isolated(
                                evidence.id,
                                phase="indexing",
                                progress_pct=batch_progress,
                                extra={
                                        "processed_artifacts": artifacts_processed,
                                        "detected_artifacts": total_artifacts,
                                        "indexed_events": indexed_count + docs_processed_in_artifact,
                                        "last_artifact": artifact_info["name"],
                                        "generated_detections": detection_count,
                                        "records_processed": records_processed + docs_processed_in_artifact,
                                        "events_indexed": indexed_count + docs_processed_in_artifact,
                                    "current_artifact": artifact_info["name"],
                                    "current_artifact_path": artifact_info["source_path"],
                                    "current_artifact_records_indexed": docs_processed_in_artifact,
                                        "artifacts_processed": artifacts_processed,
                                        "artifacts_total": total_artifacts,
                                        "artifacts_done": artifacts_processed,
                                        "artifacts_failed": len(errors),
                                        "current_artifact_index": index,
                                        "artifact_batch": batch_index + 1,
                                        "artifact_batches_total": batches,
                                        "elapsed_seconds": round(elapsed_seconds, 2),
                                        "records_per_second": round((records_processed + docs_processed_in_artifact) / elapsed_seconds, 2),
                                        "estimated_remaining_seconds": round(_estimate_remaining_seconds(elapsed_seconds=elapsed_seconds, progress_pct=batch_progress) or 0.0, 2),
                                        "raw_artifacts_detected": len(raw_artifacts),
                                        "raw_artifacts_not_parsed": len(raw_artifacts),
                                        "selected_files_total": selective_stats.get("selected_files_total") if is_selected_velociraptor else None,
                                        "selected_files_extracted": selective_stats.get("selected_files_extracted") if is_selected_velociraptor else None,
                                        "bytes_extracted": selective_stats.get("bytes_extracted") if is_selected_velociraptor else None,
                                    },
                                )
                            artifact_record_count = len(documents)
                            if not _update_artifact_row_isolated(artifact_id, record_count=artifact_record_count):
                                detection_warnings.append({"artifact": artifact_info["name"], "warning": "artifact_state_stale_after_parse"})
                            indexed_count += len(documents)
                            records_processed += len(documents)
                            if documents:
                                _benchmark_mark_first(benchmark_state, "time_to_first_event_indexed")
                    row_hosts_list = sorted(row_hosts)
                    if row_hosts_list:
                        detected_host_counts_local.update(row_hosts)
                        primary_host = choose_primary_host(
                            collection_candidate=(metadata_preview.get("collection_host_candidate") if isinstance(metadata_preview, dict) else None),
                            host_counts=dict(detected_host_counts_local),
                        )
                        evidence.detected_host = primary_host.get("host")
                        _merge_host_metadata(evidence.id, row_hosts)
                    final_status = _finalize_artifact_status(
                        parser_name=artifact_info.get("parser"),
                        record_count=artifact_record_count,
                        raw_parser_status=artifact_meta.get("raw_parser_status"),
                    )
                    if not _update_artifact_row_isolated(artifact_id, status=final_status, record_count=artifact_record_count):
                        detection_warnings.append({"artifact": artifact_info["name"], "warning": "artifact_state_stale_during_finalize"})
                    manifest_artifact["status"] = final_status
                    manifest_artifact["record_count"] = artifact_record_count
                    if ingest_audit:
                        ingest_audit["events_indexed"] = artifact_record_count
                        manifest_artifact["ingest_audit"] = ingest_audit
                    if artifact_meta.get("evtx_partial"):
                        manifest_artifact["evtx_partial"] = artifact_meta.get("evtx_partial")
                    if manifest_artifact["status"] in {"failed", "failed_unsupported"}:
                        reason = "; ".join(
                            [*map(str, artifact_meta.get("raw_parser_errors") or []), *map(str, artifact_meta.get("raw_parser_warnings") or [])]
                        )[:1000] or "Raw parser failed without indexed events"
                        if not any(item.get("artifact") == artifact_info["name"] and item.get("error") == reason for item in errors):
                            errors.append({"artifact": artifact_info["name"], "error": reason})
                            manifest["errors"].append({"artifact": artifact_info["name"], "error": reason})
                    artifacts_processed += 1
                    manifest["stats"]["results_artifacts_parsed"] = artifacts_processed
                    if documents and not detections_created_inline and detections_enabled:
                        created_count, warning = _safe_create_builtin_detections_isolated(
                            case_id=evidence.case_id,
                            evidence_id=evidence.id,
                            artifact_id=artifact_id,
                            artifact_name=artifact_info["name"],
                            documents=documents,
                        )
                        detection_count += created_count
                        if warning:
                            detection_warnings.append({"artifact": artifact_info["name"], "warning": warning})
            except Exception as exc:  # noqa: BLE001
                db.rollback()
                is_fast_evtx_timeout = (
                    isinstance(exc, TimeoutError)
                    and str(artifact_info.get("parser") or "").lower() == "evtx_raw"
                    and bool(sequential_evtx_fast_limits)
                )
                if is_fast_evtx_timeout:
                    limit_reason = "max_seconds_per_file"
                    records_read = int(
                        ((artifact_meta.get("ingest_audit") or {}).get("records_read"))
                        or docs_processed_in_artifact
                        or artifact_record_count
                        or 0
                    )
                    records_indexed = int(docs_processed_in_artifact or artifact_record_count or 0)
                    ingest_audit = dict(artifact_meta.get("ingest_audit") or {})
                    ingest_audit.update(
                        {
                            "parser_name": "evtx_raw",
                            "source_file": artifact_info.get("source_path"),
                            "records_read": records_read,
                            "records_indexed": records_indexed,
                            "events_indexed": records_indexed,
                            "warnings_count": int(ingest_audit.get("warnings_count") or 0) + 1,
                            "errors_count": int(ingest_audit.get("errors_count") or 0),
                            "parser_status": "partial",
                            "partial": True,
                            "limit_reason": limit_reason,
                            "evtx_fast_limits": dict(sequential_evtx_fast_limits),
                        }
                    )
                    artifact_meta["ingest_audit"] = ingest_audit
                    artifact_meta["raw_parser_status"] = "partial"
                    artifact_meta["raw_parser_warnings"] = [f"evtx_fast_limit_reached:{limit_reason}", str(exc)]
                    artifact_meta["raw_parser_errors"] = []
                    artifact_meta["evtx_partial"] = _evtx_partial_entry(
                        artifact_id=artifact_id,
                        artifact_name=artifact_info["name"],
                        source_path=artifact_info["source_path"],
                        reason=limit_reason,
                        records_read=records_read,
                        records_indexed=records_indexed,
                        limits=sequential_evtx_fast_limits,
                    )
                    _update_artifact_row_isolated(artifact_id, status="partial", record_count=records_indexed)
                    manifest_artifact["status"] = "partial"
                    manifest_artifact["record_count"] = records_indexed
                    manifest_artifact["ingest_audit"] = ingest_audit
                    manifest_artifact["evtx_partial"] = artifact_meta["evtx_partial"]
                    slow_artifact = {
                        "artifact": artifact_info["name"],
                        "path": artifact_info.get("source_path"),
                        "parser": artifact_info.get("parser"),
                        "warning": str(exc),
                        "status": "partial",
                    }
                    slow_artifacts.append(slow_artifact)
                    detection_warnings.append({"artifact": artifact_info["name"], "warning": "evtx_fast_partial_limit_reached"})
                    artifacts_processed += 1
                    manifest["stats"]["results_artifacts_parsed"] = artifacts_processed
                else:
                    _update_artifact_row_isolated(artifact_id, status="failed")
                    manifest_artifact["status"] = "failed"
                if isinstance(exc, TimeoutError) and not is_fast_evtx_timeout:
                    slow_artifact = {
                        "artifact": artifact_info["name"],
                        "path": artifact_info.get("source_path"),
                        "parser": artifact_info.get("parser"),
                        "error": str(exc),
                    }
                    slow_artifacts.append(slow_artifact)
                    detection_warnings.append({"artifact": artifact_info["name"], "warning": "artifact_marked_slow_or_stalled"})
                if artifact_meta.get("ingest_audit"):
                    ingest_audit = dict(artifact_meta["ingest_audit"])
                    ingest_audit["bulk_index_errors"] = 1
                    ingest_audit["top_errors"] = [str(exc)]
                    manifest_artifact["ingest_audit"] = ingest_audit
                if not is_fast_evtx_timeout:
                    errors.append({"artifact": artifact_info["name"], "error": str(exc)})
                    manifest["errors"].append({"artifact": artifact_info["name"], "error": str(exc)})
            manifest["stats"]["indexed_events"] = indexed_count
            manifest["stats"]["failed_artifacts"] = len(errors)
            progress_base = 30
            progress_span = 65
            artifact_progress = int(progress_base + (progress_span * index / max(total_artifacts, 1)))
            elapsed_seconds = max(time.perf_counter() - started_monotonic, 0.001)
            _update_progress(
                db,
                evidence,
                phase="indexing_events" if index == total_artifacts else "parsing",
                progress_pct=artifact_progress,
                extra={
                    "processed_artifacts": index,
                    "detected_artifacts": total_artifacts,
                    "indexed_events": indexed_count,
                    "last_artifact": artifact_info["name"],
                    "generated_detections": detection_count,
                    "records_processed": records_processed,
                    "events_indexed": indexed_count,
                    "current_artifact": artifact_info["name"],
                    "artifacts_processed": artifacts_processed,
                    "artifacts_total": total_artifacts,
                    "artifacts_done": artifacts_processed,
                    "artifacts_failed": len(errors),
                    "current_artifact_index": index,
                    "elapsed_seconds": round(elapsed_seconds, 2),
                    "records_per_second": round(records_processed / elapsed_seconds, 2),
                    "estimated_remaining_seconds": round(_estimate_remaining_seconds(elapsed_seconds=elapsed_seconds, progress_pct=artifact_progress) or 0.0, 2),
                    "raw_artifacts_detected": len(raw_artifacts),
                    "raw_artifacts_not_parsed": len(raw_artifacts),
                    "selected_files_total": selective_stats.get("selected_files_total") if is_selected_velociraptor else None,
                    "selected_files_extracted": selective_stats.get("selected_files_extracted") if is_selected_velociraptor else None,
                    "bytes_extracted": selective_stats.get("bytes_extracted") if is_selected_velociraptor else None,
                },
            )
            write_manifest(manifest_path, manifest)

        if parallel_futures:
            while parallel_futures:
                runtime_snapshot = _parallel_runtime_snapshot()
                running_snapshot = runtime_snapshot["running_snapshot"]
                queued_count = runtime_snapshot["queued_count"]
                indexed_parallel = int(runtime_snapshot["indexed_pending"] or 0)
                read_parallel = int(runtime_snapshot["read_pending"] or 0)
                elapsed_seconds = max(time.perf_counter() - started_monotonic, 0.001)
                _benchmark_sample_resources(
                    benchmark_state,
                    active_workers=len(running_snapshot),
                    queue_depth=queued_count,
                )
                _safe_update_progress_isolated(
                    evidence.id,
                    phase="parsing",
                    progress_pct=min(95, 30 + int((artifacts_processed / max(total_artifacts, 1)) * 60)),
                    extra={
                        "artifacts_done": artifacts_processed,
                        "artifacts_total": total_artifacts,
                        "artifacts_failed": len(errors),
                        "records_processed": records_processed + read_parallel,
                        "events_indexed": indexed_count + indexed_parallel,
                        "records_per_second": round((records_processed + read_parallel) / elapsed_seconds, 2),
                        **_parallel_tail_metadata(
                            runtime_snapshot,
                            artifacts_processed=artifacts_processed,
                            failed_artifacts=len(errors),
                            elapsed_seconds=elapsed_seconds,
                        ),
                        "parallel_ingest": {
                            "enabled": True,
                            "mode": "threads",
                            "effective_parallelism": effective_parallelism,
                            "desired_parallelism": int(desired_parallel.get("desired_parallelism") or effective_parallelism),
                            "running_artifacts": runtime_snapshot["running_artifacts"],
                            "running_artifact_types": runtime_snapshot["running_artifact_types"],
                            "completed_artifacts": artifacts_processed,
                            "queued_artifacts": queued_count,
                            "failed_artifacts": len([item for item in parallel_results if item.get("error")]),
                            "records_per_second_total": round((records_processed + read_parallel) / elapsed_seconds, 2),
                            "bottleneck": _classify_ingest_bottleneck(active_workers=len(running_snapshot), queued_artifacts=queued_count, opensearch_bulk=opensearch_bulk),
                            "artifacts_parallelized_by_type": dict(artifacts_parallelized_by_type),
                            "artifacts_sequential_by_type": dict(artifacts_sequential_by_type),
                            "limitation_reason": None if parallel_enabled else desired_parallel.get("limit_reason"),
                        },
                    },
                )
                _drain_completed_parallel_futures(block=True)
            executor.shutdown(wait=True)

        refresh_report = None
        if indexed_count:
            refresh_report = refresh_index(
                index_name,
                request_timeout=120,
                attempts=3,
                backoff_seconds=(2.0, 5.0, 10.0),
                raise_on_error=False,
            )
            if not refresh_report.get("success"):
                detection_warnings.append("opensearch_refresh_timeout_non_fatal")
        db.close()
        db = SessionLocal()
        evidence = db.get(Evidence, evidence_id)
        if not evidence:
            raise RuntimeError(f"Evidence {evidence_id} disappeared before ingest finalization")
        _debug_db_trace(
            "_finalization_session_reset",
            db=db,
            run_id=current_run_id,
            benchmark_id=str((benchmark_request or {}).get("benchmark_id") or ""),
        )
        _benchmark_transition_phase(
            benchmark_state,
            "finalizer",
            records_read=records_processed,
            records_indexed=indexed_count,
            artifacts_processed=artifacts_processed,
        )

        if errors and indexed_count > 0:
            evidence.ingest_status = IngestStatus.completed_with_errors
        elif errors:
            evidence.ingest_status = IngestStatus.failed
        else:
            evidence.ingest_status = IngestStatus.completed
        evidence.processed_at = utc_now_naive()
        metadata = dict(evidence.metadata_json or {})
        metadata["opensearch_bulk"] = {
            "attempted": bool(opensearch_bulk.get("attempted")),
            "success": bool(opensearch_bulk.get("success")),
            "timeouts": int(opensearch_bulk.get("timeouts") or 0),
            "retries": int(opensearch_bulk.get("retries") or 0),
            "chunk_size_initial": int(opensearch_bulk.get("chunk_size_initial") or 0),
            "chunk_size_final": int(opensearch_bulk.get("chunk_size_final") or 0),
            "request_timeout": int(opensearch_bulk.get("request_timeout") or 0),
            "documents_expected": int(opensearch_bulk.get("documents_expected") or 0),
            "documents_indexed": int(opensearch_bulk.get("documents_indexed") or 0),
            "documents_recovered_after_timeout": int(opensearch_bulk.get("documents_recovered_after_timeout") or 0),
            "non_fatal": bool(opensearch_bulk.get("success")),
            "warnings": list(opensearch_bulk.get("warnings") or []),
            "host_identity": {
                "upserts": int(((opensearch_bulk.get("host_identity") or {}).get("upserts")) or 0),
                "conflicts_recovered": int(((opensearch_bulk.get("host_identity") or {}).get("conflicts_recovered")) or 0),
                "host_identity_conflict_retries": int(((opensearch_bulk.get("host_identity") or {}).get("host_identity_conflict_retries")) or 0),
                "aliases_updated": int(((opensearch_bulk.get("host_identity") or {}).get("aliases_updated")) or 0),
            },
        }
        if refresh_report:
            metadata["opensearch_refresh"] = {
                "attempted": bool(refresh_report.get("attempted")),
                "success": bool(refresh_report.get("success")),
                "timeout": bool(refresh_report.get("timeout")),
                "non_fatal": bool(refresh_report.get("non_fatal")),
                "attempts": int(refresh_report.get("attempts") or 0),
                "refresh_timeout_seconds": int(refresh_report.get("request_timeout") or 0),
                "error_summary": refresh_report.get("error_summary"),
            }
        total_elapsed_seconds = max(time.perf_counter() - started_monotonic, 0.001)
        duration_by_parser = Counter()
        throughput_by_parser: dict[str, float] = {}
        for item in (manifest.get("artifacts") or []):
            parser_name = str(item.get("parser") or "unknown")
            duration = float(((item.get("ingest_audit") or {}).get("duration_seconds") or 0) or 0)
            if duration > 0:
                duration_by_parser[parser_name] += duration
        for parser_name, duration in duration_by_parser.items():
            records_for_parser = sum(
                int(((item.get("ingest_audit") or {}).get("records_indexed") or item.get("record_count") or 0))
                for item in (manifest.get("artifacts") or [])
                if str(item.get("parser") or "unknown") == parser_name
            )
            throughput_by_parser[parser_name] = round(records_for_parser / max(duration, 0.001), 2)
        evtx_partial_files = [
            dict(item.get("evtx_partial") or {})
            for item in (manifest.get("artifacts") or [])
            if isinstance(item, dict) and item.get("evtx_partial")
        ]
        if evtx_partial_files:
            metadata["evtx_partial_files"] = evtx_partial_files
            metadata["evtx_partial_count"] = len(evtx_partial_files)
            metadata["evtx_coverage_status"] = "partial_fast_profile"
        elif str(metadata.get("evtx_profile") or "").lower() == EVTX_PROFILE_FAST_HIGH_VALUE and int(metadata.get("evtx_deferred_count") or 0) > 0:
            metadata["evtx_partial_files"] = list(metadata.get("evtx_partial_files") or [])
            metadata["evtx_partial_count"] = int(len(metadata.get("evtx_partial_files") or []))
            metadata["evtx_coverage_status"] = "deferred_fast_profile"
        else:
            metadata["evtx_partial_files"] = list(metadata.get("evtx_partial_files") or [])
            metadata["evtx_partial_count"] = int(len(metadata.get("evtx_partial_files") or []))
            metadata.setdefault("evtx_coverage_status", "full")
        parser_breakdown = build_parser_breakdown(manifest, None)
        skipped_empty_artifacts = sum(
            1
            for item in (manifest.get("artifacts") or [])
            if str(item.get("status") or "").lower() in {"skipped_empty", "completed_no_records", "unsupported_no_records"}
        )
        metadata["skipped_empty_artifacts"] = skipped_empty_artifacts
        metadata["real_failed_artifacts"] = len(errors)
        metadata["investigation_ready"] = indexed_count > 0
        metadata["searchable_documents_count"] = indexed_count
        if indexed_count > 0 and skipped_empty_artifacts > 0 and not errors:
            metadata["display_status"] = "completed_with_warnings"
            metadata["status_reason"] = "indexed_with_empty_or_no_record_artifacts"
        elif indexed_count > 0:
            metadata["display_status"] = "completed_with_errors" if errors else "completed"
            metadata["status_reason"] = "indexed_with_parser_errors" if errors else "indexed"
        evtx_backend_audits = [
            dict(item.get("ingest_audit") or {})
            for item in (manifest.get("artifacts") or [])
            if str(item.get("parser") or "").lower() == "evtx_raw" and isinstance(item.get("ingest_audit"), dict)
        ]
        evtx_backend_counts = Counter(str(audit.get("evtx_parser_backend") or "unknown") for audit in evtx_backend_audits)
        selected_evtx_backend = evtx_backend_counts.most_common(1)[0][0] if evtx_backend_counts else str(metadata.get("evtx_parser_backend") or settings.evtx_parser_backend or "auto")
        metadata["evtx_parser_backend"] = selected_evtx_backend
        metadata["evtx_parser_backend_requested"] = str(metadata.get("evtx_parser_backend_requested") or settings.evtx_parser_backend or "auto")
        metadata["evtx_parser_backend_version"] = next((str(audit.get("evtx_parser_backend_version") or "") for audit in evtx_backend_audits if audit.get("evtx_parser_backend_version")), "")
        metadata["evtx_parser_backend_fallback"] = any(bool(audit.get("evtx_parser_backend_fallback")) for audit in evtx_backend_audits)
        metadata["evtx_parser_backend_error"] = next((audit.get("evtx_parser_backend_error") for audit in evtx_backend_audits if audit.get("evtx_parser_backend_error")), None)
        metadata["ingest_performance"] = {
            "duration_seconds": round(total_elapsed_seconds, 2),
            "records_per_sec": round(records_processed / total_elapsed_seconds, 2),
            "artifacts_per_sec": round(artifacts_processed / total_elapsed_seconds, 2),
            "current_run_id": current_run_id,
            "ingest_mode": ingest_mode,
            "skipped_features": list(mode_metadata.get("skipped_features") or []),
            "parser_tiers_enabled": list(mode_metadata.get("parser_tiers_enabled") or []),
            "parallel_enabled": parallel_enabled,
            "parallel_mode": "threads" if parallel_enabled else "off",
            "effective_parallelism": effective_parallelism if parallel_enabled else 1,
            "parser_capabilities_used": parser_capabilities_used,
            "artifacts_parallelized_by_type": dict(artifacts_parallelized_by_type),
            "artifacts_sequential_by_type": dict(artifacts_sequential_by_type),
            "artifacts_skipped_by_type": dict(Counter(str(item.get("artifact_type") or "unknown") for item in skipped_mode_artifacts)),
            "duration_by_parser": dict(duration_by_parser),
            "throughput_by_parser": throughput_by_parser,
            "bottleneck": _classify_ingest_bottleneck(
                active_workers=0,
                queued_artifacts=0,
                opensearch_bulk=opensearch_bulk,
            ),
            "bulk_batches": max(1, math.ceil(int(opensearch_bulk.get("documents_indexed") or 0) / max(1, int(opensearch_bulk.get("chunk_size_final") or max_bulk_docs)))) if indexed_count else 0,
            "bulk_docs_per_batch": int(opensearch_bulk.get("chunk_size_final") or max_bulk_docs),
            "evtx_files_total": sum(1 for item in artifacts if str(item.get("parser") or "").lower() == "evtx_raw"),
            "evtx_files_parsed": sum(1 for item in manifest.get("artifacts") or [] if item.get("parser") == "evtx_raw" and item.get("status") == "completed"),
            "evtx_records_read": sum(int(((item.get("ingest_audit") or {}).get("records_read") or item.get("record_count") or 0)) for item in manifest.get("artifacts") or [] if item.get("parser") == "evtx_raw"),
            "evtx_records_indexed": sum(int(((item.get("ingest_audit") or {}).get("records_indexed") or item.get("record_count") or 0)) for item in manifest.get("artifacts") or [] if item.get("parser") == "evtx_raw"),
            "evtx_parser_backend": selected_evtx_backend,
            "evtx_parser_backend_counts": dict(evtx_backend_counts),
            "ignored_zip_entries": {
                "__MACOSX": sum(1 for entry in manifest.get("files") or [] if "__MACOSX" in str(entry.get("path") or "")),
                "appledouble": sum(1 for entry in manifest.get("files") or [] if Path(str(entry.get("path") or "")).name.startswith("._")),
            },
            "metadata_events_indexed": indexed_count,
            "slow_artifacts": slow_artifacts,
            "failed_artifacts": list(errors),
            "skipped_empty_artifacts": skipped_empty_artifacts,
            "by_parser": parser_breakdown,
            "indexed_document_counts_by_artifact_type": build_indexed_document_counts_by_artifact_type(list(manifest.get("artifacts") or [])),
        }
        metadata["current_artifact"] = None
        metadata["current_artifact_path"] = None
        metadata["current_artifact_source"] = None
        metadata["current_artifact_records_read"] = 0
        metadata["current_artifact_records_indexed"] = 0
        metadata["tail_artifacts_total"] = 0
        metadata["tail_artifacts_running"] = 0
        metadata["tail_artifacts_queued"] = 0
        metadata["tail_artifacts_completed"] = 0
        metadata["tail_artifacts_failed"] = 0
        metadata["tail_records_read"] = 0
        metadata["tail_records_indexed"] = 0
        metadata["tail_last_progress_at"] = None
        metadata["tail_records_per_sec"] = 0
        metadata["tail_current_artifacts"] = []
        metadata["tail_slowest_artifacts"] = []
        metadata["tail_elapsed_seconds"] = round(total_elapsed_seconds, 2)
        _finish_metadata_phase_timing(metadata, phase="parsing", finished_at=evidence.processed_at or utc_now())
        requested_plan = get_requested_plan(metadata) or {}
        plan = build_plan_from_artifacts(
            evidence,
            metadata,
            artifacts=db.query(Artifact).filter(Artifact.evidence_id == evidence.id).order_by(Artifact.created_at.asc()).all(),
            discovery_mode=str((requested_plan or {}).get("discovery_mode") or "manual"),
            plan_source="last_ingest_artifacts",
        ) or requested_plan
        reprocess_summary = {
            "reprocess_mode": plan.get("discovery_mode"),
            "previous_plan_id": None,
            "plan_version": plan.get("plan_version"),
            "selected_candidates": len(plan.get("selected_candidates") or []),
            "parsed_candidates": max(artifacts_processed - len(skipped_mode_artifacts), 0),
            "missing_candidates": sum(1 for item in (metadata.get("ingest_plan_preview") or {}).get("missing_candidates") or [] if item),
            "changed_candidates": sum(1 for item in (metadata.get("ingest_plan_preview") or {}).get("changed_candidates") or [] if item),
            "new_candidates_not_selected": max(
                int(((metadata.get("ingest_plan_preview") or {}).get("summary") or {}).get("new_candidates") or 0)
                - sum(1 for item in (plan.get("selected_candidates") or []) if item.get("status") == "new"),
                0,
            ),
            "full_rediscovery": plan.get("discovery_mode") == "full_rediscovery",
            "preserve_analyst_state": bool(metadata.get("reconciliation_baseline")),
            "warnings": list(detection_warnings),
            "failed_candidates": len(errors),
            "skipped_candidates": sum(1 for item in (metadata.get("ingest_plan_preview") or {}).get("missing_candidates") or [] if item),
            "usable_search_skipped": len(skipped_mode_artifacts),
        }
        if plan:
            plan = apply_last_reprocess_summary(plan, reprocess_summary)
            metadata = persist_successful_plan(metadata, plan)
            metadata = append_plan_snapshot(
                metadata,
                plan=plan,
                phase="completed" if not errors else "completed_with_errors" if indexed_count > 0 else "failed",
                summary={
                    "parsed_count": artifacts_processed,
                    "failed_count": len(errors),
                    "skipped_count": reprocess_summary["skipped_candidates"],
                    "warnings": detection_warnings,
                    "indexed_events": indexed_count,
                },
            )
        evidence.metadata_json = merge_evidence_metadata(evidence.metadata_json or {}, metadata)
        evidence.error_log = {"errors": errors, "warnings": detection_warnings}
        db.commit()
        final_phase = "completed" if evidence.ingest_status == IngestStatus.completed else "completed_with_errors" if evidence.ingest_status == IngestStatus.completed_with_errors else "failed"
        final_metadata = dict(evidence.metadata_json or {})
        run_id = str(final_metadata.get("current_ingest_run_id") or "")
        if run_id:
            final_metadata = upsert_ingest_run(
                final_metadata,
                run_id,
                {
                    "status": evidence.ingest_status.value,
                    "phase": final_phase,
                    "finished_at": evidence.processed_at.isoformat() if evidence.processed_at else None,
                    "elapsed_seconds": round(total_elapsed_seconds, 2),
                    "last_error": "; ".join(str(item.get("error")) for item in errors[:3]) if errors else None,
                    "warnings": list(detection_warnings),
                    "parsed_by_artifact_type": {
                        str(item.get("artifact_type") or "unknown"): sum(
                            1
                            for candidate in (manifest.get("artifacts") or [])
                            if str(candidate.get("artifact_type") or "unknown") == str(item.get("artifact_type") or "unknown")
                            and str(candidate.get("status") or "") not in {"failed", "failed_unsupported"}
                        )
                        for item in (manifest.get("artifacts") or [])
                    },
                    "failed_artifacts_count": len(errors),
                },
            )
            final_metadata["current_ingest_run_id"] = None
            evidence.metadata_json = merge_evidence_metadata(evidence.metadata_json or {}, final_metadata)
            db.commit()
        _benchmark_transition_phase(
            benchmark_state,
            "reconciliation",
            records_read=records_processed,
            records_indexed=indexed_count,
            artifacts_processed=artifacts_processed,
        )
        reconcile_reprocessed_evidence(db, evidence)
        problem_report = build_problematic_artifacts_report(evidence, manifest)
        parser_breakdown = build_parser_breakdown(manifest, problem_report)
        refreshed_metadata = dict(evidence.metadata_json or {})
        refreshed_metadata["ingest_performance"] = {
            **dict(refreshed_metadata.get("ingest_performance") or {}),
            "by_parser": parser_breakdown,
        }
        benchmark_result = _benchmark_finalize_state(
            benchmark_state,
            metadata=refreshed_metadata,
            manifest=manifest,
            run_id=current_run_id,
            status=evidence.ingest_status.value,
            records_read=records_processed,
            events_indexed=indexed_count,
            artifacts_total=total_artifacts,
            artifacts_processed=artifacts_processed,
            artifacts_failed=len(errors),
            effective_parallelism=effective_parallelism if parallel_enabled else 1,
            performance_profile=performance_snapshot["performance_profile"],
            opensearch_bulk=opensearch_bulk,
            problem_report=problem_report,
            stale_data_error_seen=any("stale" in json.dumps(item).lower() for item in detection_warnings if item),
            unique_violation_seen=any("uniqueviolation" in json.dumps(item).lower() for item in errors + detection_warnings),
        )
        if benchmark_result:
            refreshed_metadata = upsert_ingest_benchmark(
                refreshed_metadata,
                str(benchmark_result.get("benchmark_id") or ""),
                benchmark_result,
            )
            refreshed_metadata.pop("benchmark_request", None)
            evidence.metadata_json = merge_evidence_metadata(evidence.metadata_json or {}, refreshed_metadata)
            db.commit()
            db.refresh(evidence)

        manifest["processed_at"] = evidence.processed_at.isoformat() if evidence.processed_at else None
        manifest["evidence_type"] = resolve_public_evidence_type(
            evidence.evidence_type,
            source_tool=evidence.source_tool,
            metadata=evidence.metadata_json,
        ).value
        manifest["source_tool"] = evidence.source_tool
        elapsed_seconds = max(time.perf_counter() - started_monotonic, 0.001)
        write_manifest(manifest_path, manifest)
        _update_progress(
            db,
            evidence,
            phase=final_phase,
            progress_pct=100 if evidence.ingest_status == IngestStatus.completed else 95,
            extra={
                "indexed_events": indexed_count,
                "records_processed": records_processed,
                "events_indexed": indexed_count,
                "artifacts_processed": artifacts_processed,
                "artifacts_total": total_artifacts,
                "elapsed_seconds": round(elapsed_seconds, 2),
                "records_per_second": round(records_processed / elapsed_seconds, 2),
                "estimated_remaining_seconds": 0,
                "finished_at": evidence.processed_at.isoformat() if evidence.processed_at else None,
                "raw_artifacts_detected": len(raw_artifacts),
                "raw_artifacts_not_parsed": len(raw_artifacts),
                "warnings": detection_warnings,
                "parallel_ingest": {
                    "enabled": parallel_enabled,
                    "mode": "threads" if parallel_enabled else "off",
                    "effective_parallelism": effective_parallelism if parallel_enabled else 1,
                    "running_artifacts": [],
                    "running_artifact_types": [],
                    "completed_artifacts": artifacts_processed,
                    "queued_artifacts": 0,
                    "failed_artifacts": len(errors),
                    "records_per_second_total": round(records_processed / elapsed_seconds, 2),
                    "bottleneck": _classify_ingest_bottleneck(active_workers=0, queued_artifacts=0, opensearch_bulk=opensearch_bulk),
                    "artifacts_parallelized_by_type": dict(artifacts_parallelized_by_type),
                    "artifacts_sequential_by_type": dict(artifacts_sequential_by_type),
                    "limitation_reason": None if parallel_enabled else desired_parallel.get("limit_reason"),
                },
            },
        )
        log_activity(
            db,
            activity_type="evidence_processing_completed" if evidence.ingest_status != IngestStatus.failed else "evidence_processing_failed",
            title="Evidence processing completed" if evidence.ingest_status != IngestStatus.failed else "Evidence processing failed",
            message=f"Processed {evidence.original_filename} with status {evidence.ingest_status.value}",
            severity="warning" if evidence.ingest_status == IngestStatus.completed_with_errors else "error" if evidence.ingest_status == IngestStatus.failed else "info",
            case_id=evidence.case_id,
            evidence_id=evidence.id,
            metadata={"indexed_events": indexed_count, "generated_detections": detection_count, "errors": errors, "warnings": detection_warnings},
        )
    except Exception as exc:  # noqa: BLE001
        logger.exception("Ingest failed for evidence %s", evidence_id)
        db.rollback()
        failed_db: Session = SessionLocal()
        finished_at = utc_now_naive()
        elapsed_seconds = round(max(time.perf_counter() - started_monotonic, 0.001), 2)
        evidence_name = evidence_id
        final_progress_phase = "failed"
        final_progress_pct = 95
        final_error_message = str(exc)
        try:
            failed_evidence = failed_db.get(Evidence, evidence_id)
            if failed_evidence:
                evidence_name = failed_evidence.original_filename
                metadata = dict(failed_evidence.metadata_json or {})
                run_id = str(metadata.get("current_ingest_run_id") or "")
                run_snapshot = get_evidence_run(metadata, run_id) if run_id else None
                records_read = int((run_snapshot or {}).get("records_read") or metadata.get("records_processed") or metadata.get("current_artifact_records_read") or 0)
                events_indexed = int((run_snapshot or {}).get("events_indexed") or metadata.get("events_indexed") or metadata.get("current_artifact_records_indexed") or 0)
                artifacts_total = int((run_snapshot or {}).get("artifacts_total") or metadata.get("artifacts_total") or len((manifest.get("artifacts") or [])) or 0)
                abort_kind, artifact_terminal_status, raw_error_message = _classify_ingest_abort(exc)
                timeout_seconds = 3600 if abort_kind == "timeout" else 0
                reconciliation = _reconcile_artifact_states_on_ingest_close(
                    failed_db,
                    evidence=failed_evidence,
                    manifest=manifest,
                    run_id=run_id,
                    terminal_status="failed",
                    terminal_phase=abort_kind,
                    terminal_error=raw_error_message,
                    timeout_seconds=timeout_seconds,
                )
                completed_count = int(reconciliation.get("completed_count") or 0)
                failed_count = int(reconciliation.get("failed_count") or 0)
                if abort_kind == "timeout" and completed_count > 0 and completed_count + failed_count >= max(artifacts_total, completed_count + failed_count):
                    failed_evidence.ingest_status = IngestStatus.completed_with_errors
                else:
                    failed_evidence.ingest_status = IngestStatus.failed
                concise_error = (
                    f"Run timed out after {timeout_seconds}s. {completed_count}/{artifacts_total or completed_count + failed_count} artifacts completed. "
                    f"{failed_count} artifact was marked problematic and can be retried."
                    if abort_kind == "timeout"
                    else "OpenSearch is not writable or cannot create indices. Ingest has not started."
                    if abort_kind == "infrastructure_blocked_opensearch"
                    else str(exc)
                )
                final_progress_phase = failed_evidence.ingest_status.value
                final_progress_pct = 95 if failed_evidence.ingest_status != IngestStatus.completed else 100
                final_error_message = concise_error
                plan = dict(get_requested_plan(metadata) or {})
                if plan:
                    reprocess_summary = {
                        "reprocess_mode": plan.get("discovery_mode"),
                        "plan_version": plan.get("plan_version"),
                        "selected_candidates": len(plan.get("selected_candidates") or []),
                        "parsed_candidates": completed_count,
                        "missing_candidates": sum(1 for item in (metadata.get("ingest_plan_preview") or {}).get("missing_candidates") or [] if item),
                        "changed_candidates": sum(1 for item in (metadata.get("ingest_plan_preview") or {}).get("changed_candidates") or [] if item),
                        "new_candidates_not_selected": 0,
                        "full_rediscovery": plan.get("discovery_mode") == "full_rediscovery",
                        "preserve_analyst_state": bool(metadata.get("reconciliation_baseline")),
                        "warnings": [concise_error],
                        "failed_candidates": failed_count,
                        "skipped_candidates": 0,
                    }
                    plan = apply_last_reprocess_summary(plan, reprocess_summary)
                    metadata["requested_ingest_plan"] = plan
                    metadata = append_plan_snapshot(
                        metadata,
                        plan=plan,
                        phase="completed_with_errors" if failed_evidence.ingest_status == IngestStatus.completed_with_errors else "failed",
                        summary={"parsed_count": completed_count, "failed_count": failed_count, "skipped_count": 0, "warnings": [concise_error]},
                    )
                metadata["current_artifact"] = None
                metadata["current_artifact_path"] = None
                metadata["current_artifact_source"] = None
                metadata["current_artifact_records_read"] = 0
                metadata["current_artifact_records_indexed"] = 0
                metadata["tail_artifacts_total"] = 0
                metadata["tail_artifacts_running"] = 0
                metadata["tail_artifacts_queued"] = 0
                metadata["tail_artifacts_completed"] = completed_count
                metadata["tail_artifacts_failed"] = failed_count
                metadata["tail_records_read"] = 0
                metadata["tail_records_indexed"] = 0
                metadata["tail_last_progress_at"] = finished_at.isoformat()
                metadata["tail_records_per_sec"] = 0
                metadata["tail_current_artifacts"] = []
                metadata["tail_slowest_artifacts"] = []
                metadata["tail_elapsed_seconds"] = elapsed_seconds
                metadata["current_ingest_run_id"] = None
                metadata["opensearch_bulk"] = {
                    **dict(metadata.get("opensearch_bulk") or {}),
                    "attempted": bool((metadata.get("opensearch_bulk") or {}).get("attempted")),
                    "success": bool((metadata.get("opensearch_bulk") or {}).get("success", True)),
                    "documents_indexed": events_indexed,
                    "documents_expected": max(int((metadata.get("opensearch_bulk") or {}).get("documents_expected") or 0), events_indexed),
                }
                ingest_performance = dict(metadata.get("ingest_performance") or {})
                parallel_ingest = dict(metadata.get("parallel_ingest") or {})
                ingest_performance.update(
                    {
                        "current_run_id": run_id or None,
                        "duration_seconds": elapsed_seconds,
                        "records_per_sec": round(records_read / max(elapsed_seconds, 0.001), 2) if records_read else 0,
                        "artifacts_per_sec": round((completed_count + failed_count) / max(elapsed_seconds, 0.001), 2) if (completed_count + failed_count) else 0,
                        "parallel_enabled": bool(parallel_ingest.get("enabled")),
                        "parallel_mode": str(parallel_ingest.get("mode") or ingest_performance.get("parallel_mode") or "off"),
                        "effective_parallelism": int(parallel_ingest.get("effective_parallelism") or ingest_performance.get("effective_parallelism") or 1),
                        "artifacts_parallelized_by_type": dict(parallel_ingest.get("artifacts_parallelized_by_type") or ingest_performance.get("artifacts_parallelized_by_type") or {}),
                        "artifacts_sequential_by_type": dict(parallel_ingest.get("artifacts_sequential_by_type") or ingest_performance.get("artifacts_sequential_by_type") or {}),
                        "metadata_events_indexed": events_indexed,
                    }
                )
                metadata["ingest_performance"] = ingest_performance
                metadata["error_log"] = {"fatal": concise_error, "fatal_raw": str(exc), "fatal_type": abort_kind}
                failed_evidence.metadata_json = merge_evidence_metadata(failed_evidence.metadata_json or {}, metadata)
                failed_evidence.error_log = {"fatal": concise_error, "fatal_raw": str(exc), "fatal_type": abort_kind}
                failed_evidence.processed_at = finished_at
                if run_id:
                    metadata = upsert_ingest_run(
                        metadata,
                        run_id,
                        {
                            "status": failed_evidence.ingest_status.value,
                            "phase": failed_evidence.ingest_status.value,
                            "finished_at": finished_at.isoformat(),
                            "elapsed_seconds": elapsed_seconds,
                            "last_error": concise_error,
                            "current_artifact": None,
                            "artifact_progress": None,
                            "artifacts_total": artifacts_total,
                            "artifacts_done": completed_count,
                            "artifacts_failed": failed_count,
                            "failed_artifacts_count": failed_count,
                            "records_read": records_read,
                            "records_indexed": events_indexed,
                            "events_indexed": events_indexed,
                            "records_per_sec": round(records_read / max(elapsed_seconds, 0.001), 2) if records_read else 0,
                        },
                    )
                    metadata["current_ingest_run_id"] = None
                    failed_evidence.metadata_json = merge_evidence_metadata(failed_evidence.metadata_json or {}, metadata)
                report = build_problematic_artifacts_report(failed_evidence, manifest)
                ingest_performance["by_parser"] = build_parser_breakdown(manifest, report)
                metadata["ingest_performance"] = ingest_performance
                metadata["problematic_artifacts_summary"] = report.get("summary") or {}
                benchmark_entry = get_ingest_benchmark_by_run_id(metadata, run_id) if run_id else None
                if benchmark_entry:
                    benchmark_state = benchmark_state or {
                        "benchmark_id": str(benchmark_entry.get("benchmark_id") or ""),
                        "evidence_id": failed_evidence.id,
                        "case_id": failed_evidence.case_id,
                        "run_id": run_id,
                        "label": benchmark_entry.get("label"),
                        "notes": benchmark_entry.get("notes"),
                        "mode": benchmark_entry.get("mode"),
                        "profile": benchmark_entry.get("profile"),
                        "requested_at": benchmark_entry.get("requested_at"),
                        "started_at": benchmark_entry.get("started_at"),
                        "started_monotonic": started_monotonic,
                        "phase_timings": list(benchmark_entry.get("phase_timings") or []),
                        "resource_samples": list(benchmark_entry.get("resource_samples") or []),
                        "benchmark_options": dict(benchmark_entry.get("benchmark_options") or {}),
                        "effective_cpu_count": benchmark_entry.get("effective_cpu_count"),
                        "memory_limit_source": benchmark_entry.get("memory_limit_source"),
                        "source_evidence_name": failed_evidence.original_filename,
                    }
                    benchmark_result = _benchmark_finalize_state(
                        benchmark_state,
                        metadata=metadata,
                        manifest=manifest,
                        run_id=run_id,
                        status=failed_evidence.ingest_status.value,
                        records_read=records_read,
                        events_indexed=events_indexed,
                        artifacts_total=artifacts_total,
                        artifacts_processed=completed_count,
                        artifacts_failed=failed_count,
                        effective_parallelism=int(parallel_ingest.get("effective_parallelism") or ingest_performance.get("effective_parallelism") or 1),
                        performance_profile=str(benchmark_entry.get("profile") or metadata.get("performance_profile") or "current"),
                        opensearch_bulk=dict(metadata.get("opensearch_bulk") or {}),
                        problem_report=report,
                        stale_data_error_seen="staledataerror" in str(exc).lower(),
                        unique_violation_seen="uniqueviolation" in str(exc).lower(),
                    )
                    if benchmark_result:
                        if abort_kind == "infrastructure_blocked_opensearch":
                            benchmark_result["bottleneck_report"] = {
                                "bottleneck": "infrastructure_blocked",
                                "confidence": "high",
                                "reasons": [concise_error],
                                "recommendations": [
                                    "Unblock OpenSearch create-index/write operations before retrying ingest or benchmarks.",
                                ],
                                "dominant_phase": "preflight",
                            }
                            benchmark_result["watchdog_status"] = benchmark_result.get("watchdog_status") or "infrastructure_blocked"
                            benchmark_result["final_recommendation"] = concise_error
                        metadata = upsert_ingest_benchmark(
                            metadata,
                            str(benchmark_result.get("benchmark_id") or ""),
                            benchmark_result,
                        )
                        metadata.pop("benchmark_request", None)
                failed_evidence.metadata_json = merge_evidence_metadata(failed_evidence.metadata_json or {}, metadata)
                failed_db.commit()
            else:
                failed_db.rollback()
        finally:
            failed_db.close()
        manifest["errors"].append({"fatal": final_error_message})
        manifest["processed_at"] = finished_at.isoformat()
        write_manifest(manifest_path, manifest)
        _safe_update_progress_isolated(
            evidence_id,
            phase=final_progress_phase,
            progress_pct=final_progress_pct,
            extra={
                "finished_at": finished_at.isoformat(),
                "elapsed_seconds": elapsed_seconds,
                "estimated_remaining_seconds": None,
                "current_artifact": None,
                "current_artifact_path": None,
                "current_artifact_source": None,
                "current_artifact_records_read": 0,
                "current_artifact_records_indexed": 0,
                "tail_artifacts_total": 0,
                "tail_artifacts_running": 0,
                "tail_artifacts_queued": 0,
                "tail_artifacts_completed": 0,
                "tail_artifacts_failed": 0,
                "tail_records_read": 0,
                "tail_records_indexed": 0,
                "tail_last_progress_at": finished_at.isoformat(),
                "tail_records_per_sec": 0,
                "tail_current_artifacts": [],
                "tail_slowest_artifacts": [],
                "tail_elapsed_seconds": elapsed_seconds,
            },
        )
        log_activity(
            db,
            activity_type="evidence_processing_failed",
            title="Evidence processing failed",
            message=f"Fatal ingest error for {evidence_name}: {exc}",
            severity="error",
            case_id=evidence.case_id,
            evidence_id=evidence.id,
            metadata={"fatal": str(exc)},
        )
    finally:
        db.close()


def _update_artifact_retry_run_metadata(
    evidence_id: str,
    run_id: str,
    updates: dict,
) -> None:
    isolated_db: Session = SessionLocal()
    try:
        evidence = isolated_db.get(Evidence, evidence_id)
        if not evidence:
            return
        metadata = dict(evidence.metadata_json or {})
        runs = list(metadata.get("artifact_retry_runs") or [])
        matched = False
        for index, run in enumerate(runs):
            if str(run.get("run_id") or "") == run_id:
                next_run = dict(run)
                next_run.update(updates)
                runs[index] = next_run
                matched = True
                break
        if not matched:
            runs.append({"run_id": run_id, **updates})
        metadata["artifact_retry_runs"] = runs[-25:]
        evidence.metadata_json = merge_evidence_metadata(evidence.metadata_json or {}, metadata)
        isolated_db.commit()
    finally:
        isolated_db.close()


def _resolve_retry_profile(mode: str, timeout_seconds: int | None) -> dict:
    performance_mode = str(mode or "default").strip().lower()
    runtime_settings = load_runtime_settings()
    base_timeout = int(timeout_seconds or settings.evtx_artifact_stall_seconds or 45)
    effective_timeout = base_timeout
    detections_enabled = True
    parse_only = False
    max_artifact_seconds: int | None = None
    ingest_batch_size = max(int((runtime_settings.get("INGEST_BATCH_SIZE") or settings.ingest_batch_size) or 1000), 250)
    if performance_mode in {"higher_timeout", "safe_mode", "deep_safe_mode"}:
        effective_timeout = max(effective_timeout, int(settings.evtx_artifact_stall_seconds or 45) * 2, 300)
    if performance_mode in {"no_detections", "safe_mode", "deep_safe_mode"}:
        detections_enabled = False
    if performance_mode == "safe_mode":
        ingest_batch_size = 250
    if performance_mode == "deep_safe_mode":
        ingest_batch_size = 100
        max_artifact_seconds = 600
    if performance_mode == "parse_only":
        detections_enabled = False
        parse_only = True
    return {
        "retry_mode": performance_mode,
        "effective_timeouts": {
            "record_timeout_seconds": effective_timeout,
            "artifact_stall_seconds": effective_timeout,
            "bulk_timeout_seconds": effective_timeout,
        },
        "detections_enabled": detections_enabled,
        "parse_only": parse_only,
        "bulk_batch_size": ingest_batch_size,
        "max_artifact_seconds": max_artifact_seconds,
    }


def _artifact_retry_run_id(evidence_id: str, artifact_ids: list[str]) -> str:
    digest = hashlib.sha256(f"{evidence_id}|{'|'.join(sorted(artifact_ids))}|{time.time_ns()}".encode("utf-8")).hexdigest()
    return f"artifact-retry-{digest[:16]}"


def retry_problematic_artifacts(
    evidence_id: str,
    artifact_ids: list[str],
    mode: str = "default",
    timeout_seconds: int | None = None,
    preserve_existing_events: bool = True,  # noqa: ARG001
    replace_existing_events_for_artifact: bool = False,
) -> None:
    if replace_existing_events_for_artifact:
        raise ValueError("replace_existing_events_for_artifact is not supported yet")
    db: Session = SessionLocal()
    current_job = get_current_job()
    run_id = current_job.id if current_job and current_job.id else _artifact_retry_run_id(evidence_id, artifact_ids)
    started_monotonic = time.perf_counter()
    try:
        evidence = db.get(Evidence, evidence_id)
        if not evidence:
            logger.warning("Artifact retry aborted, missing evidence %s", evidence_id)
            return
        manifest = _manifest_for_evidence(evidence)
        artifact_rows = db.query(Artifact).filter(Artifact.evidence_id == evidence.id).all()
        artifact_id_by_key: dict[tuple[str, str], str] = {}
        for row in artifact_rows:
            source_path = str(row.source_path or "")
            parser_name = str(row.parser or "")
            artifact_name = str(row.name or "")
            for key in (
                (source_path, parser_name),
                (source_path, ""),
                (artifact_name, parser_name),
                (artifact_name, ""),
            ):
                if key[0]:
                    artifact_id_by_key[key] = row.id
        report = build_problematic_artifacts_report(evidence, manifest, artifact_id_by_key=artifact_id_by_key)
        selected_items = [item for item in report.get("items", []) if str(item.get("artifact_id") or "") in set(artifact_ids)]
        metadata = dict(evidence.metadata_json or {})
        discovery_candidates = list((metadata.get("velociraptor_discovery") or {}).get("candidates") or [])
        selected_candidates: list[dict] = []
        selected_items_by_key = {(str(item.get("source_path") or ""), str(item.get("parser") or "")): item for item in selected_items}
        for candidate in discovery_candidates:
            key = (str(candidate.get("original_path") or ""), str(candidate.get("parser") or ""))
            if key in selected_items_by_key:
                selected_candidates.append(candidate)
        retry_profile = _resolve_retry_profile(mode, timeout_seconds)
        _update_artifact_retry_run_metadata(
            evidence.id,
            run_id,
            {
                "status": "running",
                "phase": "retry_running",
                "progress": 0,
                "started_at": utc_now().isoformat(),
                "mode": mode,
                "artifact_ids": artifact_ids,
                "retry_candidates_count": len(artifact_ids),
                "retry_of_artifact_ids": artifact_ids,
                "artifacts_total": len(artifact_ids),
                "artifacts_done": 0,
                "artifacts_failed": 0,
                "records_read": 0,
                "records_indexed": 0,
                "recovered_count": 0,
                "still_failed_count": 0,
                "skipped_count": 0,
                "items": selected_items,
                "retry_profile": retry_profile,
            },
        )
        if not selected_candidates:
            _update_artifact_retry_run_metadata(
                evidence.id,
                run_id,
                {
                    "status": "failed",
                    "phase": "retry_completed_still_failed",
                    "progress": 100,
                    "artifacts_total": len(artifact_ids),
                    "artifacts_done": 0,
                    "artifacts_failed": len(artifact_ids),
                    "still_failed_count": len(artifact_ids),
                    "final_message": "No retryable discovery candidates matched the selected artifacts.",
                    "error": "No retryable discovery candidates matched the selected artifacts.",
                },
            )
            return
        staging_dir, prepared_candidates, _extracted_files, _stats = _prepare_velociraptor_selected_staging_from_candidates(evidence, selected_candidates)
        artifacts = [artifact for artifact in list_velociraptor_artifacts(staging_dir, prepared_candidates) if str(artifact.get("parser") or "").lower() == "evtx_raw"]
        artifacts_total = len(artifacts) or len(selected_candidates) or len(artifact_ids)
        _update_artifact_retry_run_metadata(
            evidence.id,
            run_id,
            {
                "artifacts_total": artifacts_total,
                "artifacts_done": 0,
                "artifacts_failed": 0,
                "progress": 0,
            },
        )
        performance_mode = str(retry_profile["retry_mode"])
        effective_timeout = int((retry_profile.get("effective_timeouts") or {}).get("record_timeout_seconds") or settings.evtx_artifact_stall_seconds or 45)
        ingest_batch_size = int(retry_profile.get("bulk_batch_size") or 250)
        max_artifact_seconds = int(retry_profile.get("max_artifact_seconds") or 0)
        retry_results: list[dict] = []
        retry_errors: list[dict] = []
        total_records_read = 0
        total_records_indexed = 0
        for artifact_index, artifact_info in enumerate(artifacts, start=1):
            source_path = str(artifact_info.get("source_path") or "")
            _update_artifact_retry_run_metadata(
                evidence.id,
                run_id,
                {
                    "status": "running",
                    "phase": "retry_running",
                    "current_artifact": artifact_info.get("name") or source_path,
                    "current_artifact_source": source_path,
                    "artifacts_total": artifacts_total,
                    "artifacts_done": artifact_index - 1,
                    "progress": int(((artifact_index - 1) / artifacts_total) * 100) if artifacts_total else 0,
                    "heartbeat_at": utc_now().isoformat(),
                },
            )
            retry_artifact_id = _create_artifact_row_isolated(
                case_id=evidence.case_id,
                evidence_id=evidence.id,
                name=f"{artifact_info['name']} [retry]",
                artifact_type=artifact_info["artifact_type"],
                source_path=artifact_info["source_path"],
                parser=artifact_info["parser"],
                status="processing",
            )
            docs_processed = 0
            final_result = None
            bulk_batches = 0
            artifact_started_monotonic = time.perf_counter()
            parser = EvtxRawParser()
            try:
                for batch_result in parser.iter_batches(
                    artifact_info["path"],
                    case_id=evidence.case_id,
                    evidence_id=evidence.id,
                    artifact_id=retry_artifact_id,
                    artifact_meta=artifact_info,
                    batch_size=ingest_batch_size,
                    record_timeout_seconds=effective_timeout,
                ):
                    if max_artifact_seconds > 0 and (time.perf_counter() - artifact_started_monotonic) > max_artifact_seconds:
                        raise TimeoutError(f"EVTX deep retry exceeded {max_artifact_seconds}s for {artifact_info['name']}")
                    final_result = batch_result
                    batch_documents = batch_result.events
                    if performance_mode == "parse_only":
                        continue
                    if batch_documents:
                        bulk_batches += 1
                        bulk_index_events_with_report(
                            evidence.case_id,
                            batch_documents,
                            index=get_events_index(evidence.case_id),
                            refresh=False,
                            max_bulk_docs=max(int(settings.opensearch_bulk_docs or 1000), 100),
                            max_bulk_bytes=max(int(settings.opensearch_bulk_bytes or (2 * 1024 * 1024)), 64 * 1024),
                        )
                        docs_processed += len(batch_documents)
                        if retry_profile.get("detections_enabled"):
                            _safe_create_builtin_detections_isolated(
                                case_id=evidence.case_id,
                                evidence_id=evidence.id,
                                artifact_id=retry_artifact_id,
                                artifact_name=artifact_info["name"],
                                documents=batch_documents,
                            )
                if final_result is None:
                    final_result = parser.parse(
                        artifact_info["path"],
                        case_id=evidence.case_id,
                        evidence_id=evidence.id,
                        artifact_id=retry_artifact_id,
                        artifact_meta=artifact_info,
                    )
                    if performance_mode != "parse_only":
                        docs_processed = len(final_result.events)
                records_read = int(final_result.records_read or 0)
                total_records_read += records_read
                total_records_indexed += docs_processed
                if records_read > 0 and docs_processed == records_read:
                    fine_status = "parsed_with_warning"
                elif records_read > docs_processed > 0:
                    fine_status = "partially_parsed"
                elif docs_processed == 0 and records_read == 0:
                    fine_status = "skipped_timeout"
                else:
                    fine_status = "failed"
                outcome = "recovered_more_data" if docs_processed > 0 else "parsed_only_ok" if performance_mode == "parse_only" and records_read > 0 else "same_failure"
                _update_artifact_row_isolated(retry_artifact_id, status=fine_status, record_count=docs_processed)
                retry_results.append(
                    {
                        "artifact_id": retry_artifact_id,
                        "source_path": source_path,
                        "parser": artifact_info["parser"],
                        "name": artifact_info["name"],
                        "status": fine_status,
                        "records_read": records_read,
                        "records_indexed": docs_processed,
                        "bulk_batches": bulk_batches,
                        "mode": performance_mode,
                        "effective_timeouts": retry_profile.get("effective_timeouts"),
                        "detections_enabled": retry_profile.get("detections_enabled"),
                        "bulk_batch_size": retry_profile.get("bulk_batch_size"),
                        "outcome": outcome,
                    }
                )
                _update_artifact_retry_run_metadata(
                    evidence.id,
                    run_id,
                    {
                        "artifacts_total": artifacts_total,
                        "artifacts_done": artifact_index,
                        "records_read": total_records_read,
                        "records_indexed": total_records_indexed,
                        "events_indexed": total_records_indexed,
                        "progress": int((artifact_index / artifacts_total) * 100) if artifacts_total else 100,
                        "heartbeat_at": utc_now().isoformat(),
                    },
                )
            except Exception as exc:  # noqa: BLE001
                _update_artifact_row_isolated(retry_artifact_id, status="failed", record_count=0)
                retry_errors.append(
                    {
                        "artifact_id": retry_artifact_id,
                        "source_path": source_path,
                        "parser": artifact_info["parser"],
                        "name": artifact_info["name"],
                        "status": "failed",
                        "error": str(exc),
                        "mode": performance_mode,
                        "effective_timeouts": retry_profile.get("effective_timeouts"),
                        "detections_enabled": retry_profile.get("detections_enabled"),
                        "bulk_batch_size": retry_profile.get("bulk_batch_size"),
                        "outcome": "failed_different_reason" if docs_processed > 0 else "same_failure",
                    }
                )
                total_records_indexed += docs_processed
                _update_artifact_retry_run_metadata(
                    evidence.id,
                    run_id,
                    {
                        "artifacts_total": artifacts_total,
                        "artifacts_done": artifact_index,
                        "artifacts_failed": len(retry_errors),
                        "records_read": total_records_read,
                        "records_indexed": total_records_indexed,
                        "events_indexed": total_records_indexed,
                        "progress": int((artifact_index / artifacts_total) * 100) if artifacts_total else 100,
                        "heartbeat_at": utc_now().isoformat(),
                    },
                )
        elapsed_seconds = max(time.perf_counter() - started_monotonic, 0.001)
        recovered_count = sum(1 for item in retry_results if int(item.get("records_indexed") or 0) > 0)
        still_failed_count = len(retry_errors) + sum(1 for item in retry_results if int(item.get("records_indexed") or 0) <= 0 and item.get("outcome") != "parsed_only_ok")
        skipped_count = max(0, artifacts_total - recovered_count - still_failed_count)
        retry_phase = "retry_completed_recovered" if recovered_count and not still_failed_count else "retry_completed_still_failed" if still_failed_count and not recovered_count else "retry_completed_partial" if still_failed_count else "retry_completed_recovered"
        final_message = "Recovered" if retry_phase == "retry_completed_recovered" else "Still failing" if retry_phase == "retry_completed_still_failed" else "Partially recovered"
        _update_artifact_retry_run_metadata(
            evidence.id,
            run_id,
            {
                "status": "completed_with_errors" if still_failed_count else "completed",
                "phase": retry_phase,
                "progress": 100,
                "finished_at": utc_now().isoformat(),
                "elapsed_seconds": round(elapsed_seconds, 2),
                "artifacts_total": artifacts_total,
                "artifacts_done": artifacts_total,
                "artifacts_failed": still_failed_count,
                "records_read": total_records_read,
                "records_indexed": total_records_indexed,
                "events_indexed": total_records_indexed,
                "current_artifact": None,
                "recovered_count": recovered_count,
                "still_failed_count": still_failed_count,
                "skipped_count": skipped_count,
                "final_message": final_message,
                "items": retry_results + retry_errors,
                "retry_profile": retry_profile,
            },
        )
        manifest["problematic_artifact_retries"] = list((manifest.get("problematic_artifact_retries") or [])) + [
            {
                "run_id": run_id,
                "mode": performance_mode,
                "elapsed_seconds": round(elapsed_seconds, 2),
                "retry_profile": retry_profile,
                "items": retry_results + retry_errors,
            }
        ]
        write_manifest(evidence_manifest_path(evidence.case_id, evidence.id), manifest)
        refreshed_evidence = db.get(Evidence, evidence.id)
        if refreshed_evidence:
            refreshed_manifest = _manifest_for_evidence(refreshed_evidence)
            refreshed_artifact_rows = db.query(Artifact).filter(Artifact.evidence_id == refreshed_evidence.id).all()
            refreshed_artifact_id_by_key: dict[tuple[str, str], str] = {}
            for row in refreshed_artifact_rows:
                source_path = str(row.source_path or "")
                parser_name = str(row.parser or "")
                artifact_name = str(row.name or "")
                for key in (
                    (source_path, parser_name),
                    (source_path, ""),
                    (artifact_name, parser_name),
                    (artifact_name, ""),
                ):
                    if key[0]:
                        refreshed_artifact_id_by_key[key] = row.id
            refreshed_report = build_problematic_artifacts_report(
                refreshed_evidence,
                refreshed_manifest,
                artifact_id_by_key=refreshed_artifact_id_by_key,
            )
            refreshed_summary = dict(refreshed_report.get("summary") or {})
            has_real_parser_failures = problematic_artifacts_require_error_status(refreshed_report)
            refreshed_metadata = dict(refreshed_evidence.metadata_json or {})
            refreshed_metadata["problematic_artifacts_summary"] = refreshed_summary
            refreshed_metadata["investigation_ready"] = True
            refreshed_metadata["retry_recovered_count"] = recovered_count
            refreshed_metadata["retry_still_failed_count"] = still_failed_count
            refreshed_metadata["retry_skipped_count"] = skipped_count
            refreshed_metadata["latest_retry_run_id"] = run_id
            refreshed_metadata["error_count"] = int(refreshed_summary.get("data_loss_expected_count") or 0) if has_real_parser_failures else 0
            refreshed_metadata["warning_count"] = int(refreshed_summary.get("indexed_with_warning") or 0) + int(refreshed_summary.get("skipped_empty") or 0)
            if has_real_parser_failures:
                refreshed_metadata["display_status"] = "completed_with_errors"
                refreshed_metadata["current_phase"] = "completed_with_errors"
                refreshed_metadata["status_reason"] = "retry_completed_still_has_parser_failures"
                refreshed_evidence.ingest_status = IngestStatus.completed_with_errors
            else:
                refreshed_evidence.ingest_status = IngestStatus.completed
                refreshed_metadata["display_status"] = "completed_with_warnings" if refreshed_metadata["warning_count"] else "completed"
                refreshed_metadata["current_phase"] = refreshed_metadata["display_status"]
                refreshed_metadata["progress_pct"] = 100
                if refreshed_metadata.get("artifacts_total"):
                    refreshed_metadata["artifacts_done"] = refreshed_metadata.get("artifacts_total")
                    refreshed_metadata["artifacts_processed"] = refreshed_metadata.get("artifacts_total")
                refreshed_metadata["artifacts_failed"] = 0
                refreshed_metadata["problematic_artifacts_resolved_at"] = utc_now().isoformat()
                refreshed_metadata["status_reason"] = "retry_resolved_real_parser_failures"
            refreshed_evidence.metadata_json = merge_evidence_metadata(refreshed_evidence.metadata_json or {}, refreshed_metadata)
            flag_modified(refreshed_evidence, "metadata_json")
            db.commit()
            if refreshed_evidence.ingest_status == IngestStatus.completed_with_errors and not has_real_parser_failures:
                refreshed_evidence.ingest_status = IngestStatus.completed
                db.commit()
    except Exception as exc:  # noqa: BLE001
        logger.exception("Problematic artifact retry failed for evidence %s", evidence_id)
        _update_artifact_retry_run_metadata(evidence_id, run_id, {"status": "failed", "finished_at": utc_now().isoformat(), "error": str(exc)})
        raise
    finally:
        db.close()


def _mft_summary_run_id(evidence_id: str) -> str:
    current_job = get_current_job(connection=redis_conn)
    return current_job.id if current_job and current_job.id else f"mft-summary-{evidence_id}-{int(time.time())}"


def _mft_source_candidates_from_metadata(evidence: Evidence) -> list[str]:
    metadata = dict(evidence.metadata_json or {})
    values: list[str] = []
    for container in (
        (metadata.get("ingest_plan") or {}).get("disabled_candidates") or [],
        (metadata.get("velociraptor_discovery") or {}).get("candidates") or [],
        metadata.get("raw_artifacts") or [],
    ):
        for entry in container if isinstance(container, list) else []:
            if not isinstance(entry, dict):
                continue
            blob = " ".join(str(entry.get(key) or "").lower() for key in ("name", "source_path", "relative_path", "path", "artifact_type", "parser", "planned_parser"))
            if "$mft" not in blob and "ntfs_raw" not in blob:
                continue
            candidate = str(entry.get("source_path") or entry.get("relative_path") or entry.get("path") or entry.get("name") or "").strip()
            if candidate:
                values.append(candidate)
    return list(dict.fromkeys(values))


def _resolve_mft_raw_path(evidence: Evidence) -> tuple[Path, str]:
    root = build_evidence_root(evidence.case_id, evidence.id)
    search_roots = [evidence_staging_dir(evidence.case_id, evidence.id), root / "extracted", root / "original_folder", root / "original"]
    source_candidates = _mft_source_candidates_from_metadata(evidence)
    for source_path in source_candidates:
        try:
            relative = sanitize_relative_path(source_path)
        except ValueError:
            continue
        for base in search_roots:
            path = base / relative
            if path.is_file() and path.name.lower() == "$mft":
                return path, source_path
    matches = sorted(path for path in root.rglob("*") if path.is_file() and path.name.lower() == "$mft")
    if matches:
        first = matches[0]
        try:
            return first, str(first.relative_to(root))
        except ValueError:
            return first, str(first)
    archive_dir = root / "original"
    archives = sorted(path for path in archive_dir.glob("*") if path.is_file() and path.suffix.lower() in {".7z", ".zip"})
    for archive_path in archives:
        for source_path in source_candidates:
            try:
                relative = sanitize_relative_path(source_path)
            except ValueError:
                continue
            if relative.name.lower() != "$mft":
                continue
            extract_dir = root / "derived" / "mft_raw" / hashlib.sha1(str(relative).encode("utf-8", "ignore")).hexdigest()[:12]
            extracted = extract_dir / "$MFT"
            if extracted.is_file():
                return extracted, source_path
            extract_dir.mkdir(parents=True, exist_ok=True)
            result = subprocess.run(
                ["7z", "e", str(archive_path), str(relative), f"-o{extract_dir}", "-y"],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                timeout=600,
                check=False,
            )
            if result.returncode != 0:
                continue
            if extracted.is_file():
                return extracted, source_path
    raise RuntimeError("No raw $MFT file is available for this evidence.")


def _mft_docs_count(case_id: str, evidence_id: str) -> int:
    try:
        return int(
            (
                count_documents(
                    get_events_index(case_id),
                    {
                        "bool": {
                            "filter": [
                                {"term": {"case_id": case_id}},
                                {"term": {"evidence_id": evidence_id}},
                                {"term": {"artifact.type": "mft"}},
                            ]
                        }
                    },
                ).get("count")
                or 0
            )
        )
    except Exception:
        return 0


def _user_activity_docs_count(case_id: str, evidence_id: str) -> dict[str, int]:
    counts: dict[str, int] = {}
    index_name = get_events_index(case_id)
    for artifact_type in sorted(USER_ACTIVITY_ARTIFACT_TYPES):
        try:
            counts[artifact_type] = int(
                (
                    count_documents(
                        index_name,
                        {
                            "bool": {
                                "filter": [
                                    {"term": {"case_id": case_id}},
                                    {"term": {"evidence_id": evidence_id}},
                                    {"term": {"artifact.type": artifact_type}},
                                    {"term": {"source_tool": "recmd"}},
                                ]
                            }
                        },
                    ).get("count")
                    or 0
                )
            )
        except Exception:
            counts[artifact_type] = 0
    return counts


def _update_recmd_user_activity_metadata(evidence_id: str, run: dict) -> None:
    isolated_db = SessionLocal()
    try:
        evidence = isolated_db.get(Evidence, evidence_id)
        if not evidence:
            return
        metadata = dict(evidence.metadata_json or {})
        runs = [item for item in list(metadata.get("recmd_user_activity_runs") or []) if isinstance(item, dict) and str(item.get("run_id") or "") != str(run.get("run_id") or "")]
        runs.append(run)
        metadata["recmd_user_activity_runs"] = runs[-10:]
        metadata["recmd_user_activity"] = dict(run)
        metadata["registry_user_activity_backend"] = run.get("backend") or metadata.get("registry_user_activity_backend")
        metadata["recmd_version"] = run.get("backend_version") or metadata.get("recmd_version") or ""
        metadata["registry_user_activity_status"] = run.get("status") or metadata.get("registry_user_activity_status")
        metadata["registry_user_activity_records_indexed"] = int(run.get("records_indexed") or metadata.get("registry_user_activity_records_indexed") or 0)
        metadata["registry_user_activity_counts"] = dict(run.get("records_indexed_by_family") or metadata.get("registry_user_activity_counts") or {})
        metadata["registry_user_activity_hives_processed"] = int(run.get("hives_processed") or metadata.get("registry_user_activity_hives_processed") or 0)
        metadata["registry_user_activity_hives_failed"] = int(run.get("hives_failed") or metadata.get("registry_user_activity_hives_failed") or 0)
        metadata["investigation_ready"] = True
        evidence.metadata_json = merge_evidence_metadata(evidence.metadata_json or {}, metadata)
        isolated_db.commit()
    finally:
        isolated_db.close()


def _srum_docs_count(case_id: str, evidence_id: str) -> int:
    try:
        index = get_events_index(case_id)
        return int(
            (
                count_documents(
                    index,
                    {
                        "bool": {
                            "filter": [
                                {"term": {"case_id": case_id}},
                                {"term": {"evidence_id": evidence_id}},
                                {"term": {"artifact.type": "srum"}},
                                {"term": {"artifact.parser": SRUMECMD_BACKEND_CSV}},
                            ]
                        }
                    },
                ).get("count")
                or 0
            )
        )
    except Exception as exc:  # noqa: BLE001
        logger.warning("Could not count SRUM docs for evidence %s: %s", evidence_id, exc)
        return 0


def _update_srum_metadata(evidence_id: str, run: dict) -> None:
    isolated_db = SessionLocal()
    try:
        evidence = isolated_db.get(Evidence, evidence_id)
        if not evidence:
            return
        metadata = dict(evidence.metadata_json or {})
        runs = [item for item in list(metadata.get("srum_runs") or []) if isinstance(item, dict) and str(item.get("run_id") or "") != str(run.get("run_id") or "")]
        runs.append(run)
        metadata["srum_runs"] = runs[-10:]
        metadata["srum"] = dict(run)
        metadata["srum_status"] = run.get("status") or metadata.get("srum_status")
        metadata["srum_parser_backend"] = run.get("backend") or metadata.get("srum_parser_backend")
        metadata["srum_parser_version"] = run.get("backend_version") or metadata.get("srum_parser_version") or ""
        metadata["srum_records_indexed"] = int(run.get("records_indexed") or metadata.get("srum_records_indexed") or 0)
        metadata["srum_tables_detected"] = dict(run.get("tables") or metadata.get("srum_tables_detected") or {})
        metadata["srum_sources_detected"] = int(run.get("sources_total") or metadata.get("srum_sources_detected") or 0)
        metadata["srum_sources_parsed"] = int(run.get("sources_parsed") or metadata.get("srum_sources_parsed") or 0)
        metadata["srum_sources_failed"] = int(run.get("sources_failed") or metadata.get("srum_sources_failed") or 0)
        metadata["srum_no_data"] = bool(run.get("no_data", False))
        metadata["srum_tooling_missing"] = bool(run.get("tooling_missing", False))
        metadata["investigation_ready"] = True
        evidence.metadata_json = merge_evidence_metadata(evidence.metadata_json or {}, metadata)
        isolated_db.commit()
    finally:
        isolated_db.close()


CORE_EZ_ADVANCED_BACKENDS: dict[str, dict[str, object]] = {
    "lnk": {
        "tool": "LECmd",
        "backend": "lecmd_csv",
        "parser": "lecmd",
        "name": "LNK advanced - LECmd",
        "patterns": (".lnk",),
        "command_mode": "file",
    },
    "jumplist": {
        "tool": "JLECmd",
        "backend": "jlecmd_csv",
        "parser": "jlecmd",
        "name": "JumpList advanced - JLECmd",
        "patterns": (".automaticdestinations-ms", ".customdestinations-ms"),
        "command_mode": "file",
    },
    "amcache": {
        "tool": "AmcacheParser",
        "backend": "amcacheparser_csv",
        "parser": "amcacheparser_csv",
        "name": "Amcache advanced - AmcacheParser",
        "patterns": ("amcache.hve",),
        "command_mode": "file",
    },
    "shimcache": {
        "tool": "AppCompatCacheParser",
        "backend": "appcompatcacheparser_csv",
        "parser": "appcompatcacheparser_csv",
        "name": "Shimcache advanced - AppCompatCacheParser",
        "patterns": ("/system", "\\system", "system"),
        "command_mode": "file",
    },
}


def _core_ez_source_paths(evidence: Evidence, artifact_type: str) -> list[str]:
    config = CORE_EZ_ADVANCED_BACKENDS[artifact_type]
    patterns = tuple(str(item).lower() for item in config["patterns"])  # type: ignore[index]
    metadata = dict(evidence.metadata_json or {})
    candidates: list[dict] = []
    for key in ("ingest_plan", "velociraptor_discovery", "parser_audit"):
        value = metadata.get(key)
        if isinstance(value, dict):
            candidates.extend([item for item in list(value.get("candidates") or []) if isinstance(item, dict)])
            candidates.extend([item for item in list(value.get("selected_candidates") or []) if isinstance(item, dict)])
            candidates.extend([item for item in list(value.get("disabled_candidates") or []) if isinstance(item, dict)])
    for key in ("raw_artifact_inventory", "inventory", "detected_artifacts"):
        value = metadata.get(key)
        if isinstance(value, list):
            candidates.extend([item for item in value if isinstance(item, dict)])

    paths: list[str] = []
    seen: set[str] = set()

    def add_path(raw: object) -> None:
        text = str(raw or "").strip()
        if not text:
            return
        lower = text.replace("\\", "/").lower()
        match = False
        if artifact_type == "shimcache":
            match = lower.endswith("/windows/system32/config/system") or lower.endswith("/system") or lower == "system"
        else:
            match = any(lower.endswith(pattern) for pattern in patterns)
        if not match:
            return
        if lower in seen:
            return
        seen.add(lower)
        paths.append(text)

    for candidate in candidates:
        candidate_type = str(candidate.get("artifact_type") or candidate.get("category") or "").strip().lower()
        parser = str(candidate.get("parser") or candidate.get("planned_parser") or "").strip().lower()
        if artifact_type == "lnk" and candidate_type not in {"", "lnk", "shortcut", "windows_shortcut"} and parser != "lnk_raw":
            pass
        elif artifact_type == "jumplist" and candidate_type not in {"", "jumplist", "automatic_destinations", "custom_destinations"}:
            pass
        elif artifact_type == "amcache" and candidate_type not in {"", "amcache"} and parser != "amcache_raw":
            pass
        elif artifact_type == "shimcache" and candidate_type not in {"", "shimcache", "registry_hive_raw"} and parser != "shimcache_raw":
            pass
        for key in ("source_path", "relative_path", "path", "original_path", "container_path"):
            add_path(candidate.get(key))

    stored = Path(evidence.stored_path or "")
    if stored.exists():
        try:
            for entry in open_evidence_container(stored).list_entries():
                add_path(entry.path)
        except Exception as exc:  # noqa: BLE001
            logger.warning("Could not list evidence container for EZ rebuild %s/%s: %s", evidence.id, artifact_type, exc)
    return paths


def _run_core_ez_tool(tool: str, source_path: Path, output_dir: Path) -> tuple[bool, str, str]:
    dll = _tool_dll_path(tool)
    if not dll:
        return False, "", f"{tool} DLL not found"
    command = ["dotnet", str(dll), "-f", str(source_path), "--csv", str(output_dir)]
    if tool in {"AmcacheParser", "AppCompatCacheParser"}:
        command.append("--nl")
    completed = subprocess.run(command, capture_output=True, text=True, timeout=max(int(settings.artifact_retry_job_timeout_seconds or 900), 120))
    stdout = completed.stdout or ""
    stderr = completed.stderr or ""
    return completed.returncode == 0, stdout, stderr


def _core_ez_csv_paths(output_dir: Path) -> list[Path]:
    return sorted(path for path in output_dir.rglob("*.csv") if path.is_file())


def _mark_core_ez_doc(document: dict, *, evidence: Evidence, artifact: Artifact, artifact_type: str, backend: str, source_path: str) -> dict:
    artifact_payload = dict(document.get("artifact") or {})
    artifact_payload.update(
        {
            "type": artifact_type,
            "parser_backend": backend,
            "backend_variant": "advanced",
            "default_backend": False,
            "advanced_backend": True,
            "supersedes_internal": False,
            "source_artifact_fingerprint": hashlib.sha1(f"{evidence.id}|{artifact_type}|{source_path}".encode("utf-8")).hexdigest(),
        }
    )
    document["artifact"] = artifact_payload
    document["artifact_id"] = artifact.id
    document["backend_variant"] = "advanced"
    document["parser_backend"] = backend
    source_identity = "|".join(
        str(value or "")
        for value in (
            evidence.id,
            artifact_type,
            backend,
            source_path,
            (document.get("file") or {}).get("path"),
            (document.get("file") or {}).get("name"),
            (document.get("lnk") or {}).get("target_path"),
            (document.get("jumplist") or {}).get("target_path"),
            (document.get("amcache") or {}).get("file_path"),
            (document.get("shimcache") or {}).get("path"),
            document.get("key_entity"),
            document.get("@timestamp"),
        )
    )
    stable_id = hashlib.sha1(source_identity.encode("utf-8")).hexdigest()
    document["event_id"] = f"ez-{backend}-{stable_id}"
    document["stable_event_id"] = document["event_id"]
    tags = set(str(item) for item in list(document.get("tags") or []) if item)
    tags.update({"eztool", "advanced_backend"})
    document["tags"] = sorted(tags)
    return document


def _core_ez_docs_count(case_id: str, evidence_id: str, artifact_type: str, backend: str) -> int:
    try:
        index = get_events_index(case_id)
        return int(
            (
                count_documents(
                    index,
                    {
                        "bool": {
                            "filter": [
                                {"term": {"case_id": case_id}},
                                {"term": {"evidence_id": evidence_id}},
                                {"term": {"artifact.type": artifact_type}},
                                {"term": {"artifact.parser_backend": backend}},
                                {"term": {"artifact.backend_variant": "advanced"}},
                            ]
                        }
                    },
                ).get("count")
                or 0
            )
        )
    except Exception as exc:  # noqa: BLE001
        logger.warning("Could not count core EZ docs for evidence %s artifact %s: %s", evidence_id, artifact_type, exc)
        return 0


def _update_core_ez_metadata(evidence_id: str, artifact_type: str, run: dict) -> None:
    isolated_db = SessionLocal()
    try:
        evidence = isolated_db.get(Evidence, evidence_id)
        if not evidence:
            return
        metadata = dict(evidence.metadata_json or {})
        all_runs = dict(metadata.get("core_ez_rebuilds") or {})
        runs = [item for item in list(all_runs.get(artifact_type) or []) if isinstance(item, dict) and str(item.get("run_id") or "") != str(run.get("run_id") or "")]
        runs.append(run)
        all_runs[artifact_type] = runs[-10:]
        metadata["core_ez_rebuilds"] = all_runs
        metadata[f"{artifact_type}_ez_rebuild"] = dict(run)
        metadata["investigation_ready"] = True
        evidence.metadata_json = merge_evidence_metadata(evidence.metadata_json or {}, metadata)
        isolated_db.commit()
    finally:
        isolated_db.close()


def rebuild_core_ez_artifact_for_evidence(evidence_id: str, artifact_type: str, force: bool = True) -> dict:
    normalized_type = str(artifact_type or "").strip().lower()
    if normalized_type == "appcompat":
        normalized_type = "shimcache"
    if normalized_type not in CORE_EZ_ADVANCED_BACKENDS:
        raise RuntimeError(f"Unsupported core EZ artifact type: {artifact_type}")
    config = CORE_EZ_ADVANCED_BACKENDS[normalized_type]
    tool = str(config["tool"])
    backend = str(config["backend"])
    parser = str(config["parser"])
    run_id = f"core-ez-{normalized_type}-{evidence_id}-{int(time.time())}"
    started_at = utc_now().isoformat()
    _update_core_ez_metadata(evidence_id, normalized_type, {"run_id": run_id, "status": "running", "started_at": started_at, "finished_at": None, "tool": tool, "backend": backend, "records_indexed": 0})
    db = SessionLocal()
    started = time.perf_counter()
    try:
        evidence = db.get(Evidence, evidence_id)
        if not evidence:
            raise RuntimeError("Evidence not found")
        dll = _tool_dll_path(tool)
        if not dll:
            result = {"run_id": run_id, "status": "tooling_missing", "started_at": started_at, "finished_at": utc_now().isoformat(), "tool": tool, "backend": backend, "records_indexed": 0, "error": f"{tool} DLL not found"}
            _update_core_ez_metadata(evidence_id, normalized_type, result)
            return result
        index_name = ensure_case_index(evidence.case_id)
        existing = _core_ez_docs_count(evidence.case_id, evidence.id, normalized_type, backend)
        if existing > 0 and not force:
            result = {"run_id": run_id, "status": "completed", "started_at": started_at, "finished_at": utc_now().isoformat(), "tool": tool, "backend": backend, "records_indexed": existing, "elapsed_seconds": 0, "warnings": ["core_ez_already_indexed"]}
            _update_core_ez_metadata(evidence_id, normalized_type, result)
            return result
        if existing > 0 and force:
            get_opensearch_client().delete_by_query(
                index=index_name,
                body={
                    "query": {
                        "bool": {
                            "filter": [
                                {"term": {"case_id": evidence.case_id}},
                                {"term": {"evidence_id": evidence.id}},
                                {"term": {"artifact.type": normalized_type}},
                                {"term": {"artifact.parser_backend": backend}},
                                {"term": {"artifact.backend_variant": "advanced"}},
                            ]
                        }
                    }
                },
                params={"refresh": "true", "ignore_unavailable": "true"},
            )
        artifact = (
            db.query(Artifact)
            .filter(Artifact.evidence_id == evidence.id, Artifact.artifact_type == normalized_type, Artifact.parser == backend)
            .first()
        )
        if not artifact:
            artifact = Artifact(case_id=evidence.case_id, evidence_id=evidence.id, name=str(config["name"]), artifact_type=normalized_type, source_path=f"{tool} advanced rebuild", parser=backend, status="processing", record_count=0)
            db.add(artifact)
            db.commit()
            db.refresh(artifact)
        else:
            artifact.status = "processing"
            db.commit()
        source_paths = _core_ez_source_paths(evidence, normalized_type)
        if not source_paths:
            result = {"run_id": run_id, "status": "no_data", "started_at": started_at, "finished_at": utc_now().isoformat(), "tool": tool, "backend": backend, "sources_detected": 0, "records_indexed": 0, "warnings": ["no_matching_raw_artifacts_detected"], "elapsed_seconds": round(time.perf_counter() - started, 2)}
            artifact.status = "parsed_empty"
            db.commit()
            _update_core_ez_metadata(evidence_id, normalized_type, result)
            return result
        container = open_evidence_container(Path(evidence.stored_path or ""))
        work_dir = build_evidence_root(evidence.case_id, evidence.id) / "derived" / "core_ez" / normalized_type
        extracted_dir = work_dir / "sources"
        output_dir = work_dir / "csv"
        extracted_dir.mkdir(parents=True, exist_ok=True)
        output_dir.mkdir(parents=True, exist_ok=True)
        extracted = container.extract_entries(source_paths, extracted_dir)
        runtime_settings = load_runtime_settings(db)
        batch_size = max(int(runtime_settings.get("OPENSEARCH_BULK_DOCS") or settings.opensearch_bulk_docs or 1000), 1)
        max_bulk_bytes = int(runtime_settings.get("OPENSEARCH_BULK_BYTES") or settings.opensearch_bulk_bytes or 10485760)
        errors: list[str] = []
        tool_runs = 0
        documents: list[dict] = []
        seen_ids: set[str] = set()
        csv_files_seen: set[str] = set()
        artifact_meta = {
            **dict(evidence.metadata_json or {}),
            "name": str(config["name"]),
            "source_path": f"{tool} advanced rebuild",
            "artifact_type": normalized_type,
            "parser": parser,
            "source_tool": tool.lower(),
            "source_format": "csv",
            "detected_host": str((evidence.metadata_json or {}).get("provided_host") or evidence.detected_host or "").strip() or None,
            "provided_host": str((evidence.metadata_json or {}).get("provided_host") or "").strip() or None,
            "detected_user": evidence.detected_user,
        }
        for item in extracted:
            if item.get("status") != "extracted" or not item.get("local_path"):
                errors.append(f"{item.get('path')}: {item.get('error') or 'extract_failed'}")
                continue
            local_path = Path(str(item["local_path"]))
            source_path = str(item.get("path") or local_path)
            run_output_dir = output_dir / hashlib.sha1(source_path.encode("utf-8")).hexdigest()
            if run_output_dir.exists():
                shutil.rmtree(run_output_dir)
            run_output_dir.mkdir(parents=True, exist_ok=True)
            ok, stdout, stderr = _run_core_ez_tool(tool, local_path, run_output_dir)
            tool_runs += 1
            if not ok:
                errors.append(f"{source_path}: {stderr or stdout or 'tool_failed'}")
                continue
            for csv_path in _core_ez_csv_paths(run_output_dir):
                key = str(csv_path)
                if key in csv_files_seen:
                    continue
                csv_files_seen.add(key)
                docs = normalize_file(evidence.case_id, evidence.id, artifact.id, csv_path, {**artifact_meta, "source_path": source_path})
                for doc in docs:
                    _mark_core_ez_doc(doc, evidence=evidence, artifact=artifact, artifact_type=normalized_type, backend=backend, source_path=source_path)
                    if doc["event_id"] in seen_ids:
                        continue
                    seen_ids.add(doc["event_id"])
                    apply_case_host_identity(db, evidence.case_id, doc)
                    documents.append(doc)
                    if len(documents) >= batch_size:
                        bulk_index_events_with_report(evidence.case_id, documents, index=index_name, refresh=False, max_bulk_docs=batch_size, max_bulk_bytes=max_bulk_bytes, apply_host_identity=False, apply_fingerprint=False)
                        documents.clear()
        if documents:
            bulk_index_events_with_report(evidence.case_id, documents, index=index_name, refresh=False, max_bulk_docs=batch_size, max_bulk_bytes=max_bulk_bytes, apply_host_identity=False, apply_fingerprint=False)
        refresh_index(index_name, raise_on_error=False)
        indexed = _core_ez_docs_count(evidence.case_id, evidence.id, normalized_type, backend)
        artifact.record_count = indexed
        artifact.status = "completed" if indexed else "parsed_empty"
        db.commit()
        result = {
            "run_id": run_id,
            "status": "completed" if indexed else "no_data",
            "started_at": started_at,
            "finished_at": utc_now().isoformat(),
            "artifact_type": normalized_type,
            "tool": tool,
            "backend": backend,
            "backend_variant": "advanced",
            "sources_detected": len(source_paths),
            "sources_extracted": sum(1 for item in extracted if item.get("status") == "extracted"),
            "tool_runs": tool_runs,
            "csv_files": len(csv_files_seen),
            "records_indexed": indexed,
            "duplicates": 0,
            "errors": errors[:20],
            "warnings": [] if indexed else ["core_ez_no_records_indexed"],
            "elapsed_seconds": round(time.perf_counter() - started, 2),
            "artifact_id": artifact.id,
        }
        _update_core_ez_metadata(evidence_id, normalized_type, result)
        log_activity(db, activity_type="core_ez_rebuild", title=f"{tool} advanced rebuild", message=f"Indexed {indexed} advanced {normalized_type} records for {evidence.original_filename}", case_id=evidence.case_id, evidence_id=evidence.id, metadata=result)
        return result
    except Exception as exc:  # noqa: BLE001
        logger.exception("Core EZ rebuild failed for evidence %s artifact %s", evidence_id, normalized_type)
        _update_core_ez_metadata(evidence_id, normalized_type, {"run_id": run_id, "status": "failed", "started_at": started_at, "finished_at": utc_now().isoformat(), "artifact_type": normalized_type, "tool": tool, "backend": backend, "error": str(exc)})
        raise
    finally:
        db.close()


def index_srum_for_evidence(evidence_id: str, force: bool = False) -> dict:
    run_id = f"srum-{evidence_id}-{int(time.time())}"
    started_at = utc_now().isoformat()
    _update_srum_metadata(evidence_id, {"run_id": run_id, "status": "running", "started_at": started_at, "finished_at": None, "backend": SRUMECMD_BACKEND_CSV, "records_indexed": 0, "no_data": False})
    db = SessionLocal()
    try:
        evidence = db.get(Evidence, evidence_id)
        if not evidence:
            raise RuntimeError("Evidence not found")
        backend = detect_srumecmd_backend()
        if not backend.get("available"):
            result = {
                "run_id": run_id,
                "status": "tooling_missing",
                "started_at": started_at,
                "finished_at": utc_now().isoformat(),
                "backend": SRUMECMD_BACKEND_CSV,
                "backend_version": "",
                "records_indexed": 0,
                "sources_total": len(find_srum_databases(evidence.case_id, evidence.id, dict(evidence.metadata_json or {}))),
                "sources_parsed": 0,
                "sources_failed": 0,
                "tables": {},
                "no_data": True,
                "tooling_missing": True,
                "error": str(backend.get("error") or "SrumECmd backend is not available"),
                "warnings": ["srumecmd_tooling_missing"],
            }
            _update_srum_metadata(evidence_id, result)
            return result
        existing = _srum_docs_count(evidence.case_id, evidence.id)
        if existing > 0 and not force:
            result = {
                "run_id": run_id,
                "status": "completed",
                "started_at": started_at,
                "finished_at": utc_now().isoformat(),
                "backend": SRUMECMD_BACKEND_CSV,
                "backend_version": backend.get("version") or "",
                "records_indexed": existing,
                "sources_total": int((evidence.metadata_json or {}).get("srum_sources_detected") or 0),
                "sources_parsed": int((evidence.metadata_json or {}).get("srum_sources_parsed") or 0),
                "sources_failed": int((evidence.metadata_json or {}).get("srum_sources_failed") or 0),
                "tables": dict((evidence.metadata_json or {}).get("srum_tables_detected") or {}),
                "elapsed_seconds": 0,
                "warnings": ["srum_already_indexed"],
            }
            _update_srum_metadata(evidence_id, result)
            return result
        index_name = ensure_case_index(evidence.case_id)
        if existing > 0 and force:
            client = get_opensearch_client()
            try:
                client.delete_by_query(
                    index=index_name,
                    body={
                        "query": {
                            "bool": {
                                "filter": [
                                    {"term": {"case_id": evidence.case_id}},
                                    {"term": {"evidence_id": evidence.id}},
                                    {"term": {"artifact.type": "srum"}},
                                    {"term": {"artifact.parser": SRUMECMD_BACKEND_CSV}},
                                ]
                            }
                        }
                    },
                    params={"refresh": "true", "ignore_unavailable": "true"},
                )
            except Exception as exc:  # noqa: BLE001
                logger.warning("Could not clear previous SRUM docs for evidence %s: %s", evidence.id, exc)
        artifact = (
            db.query(Artifact)
            .filter(Artifact.evidence_id == evidence.id, Artifact.artifact_type == "srum", Artifact.parser == SRUMECMD_BACKEND_CSV)
            .first()
        )
        if not artifact:
            artifact = Artifact(case_id=evidence.case_id, evidence_id=evidence.id, name="SRUM", artifact_type="srum", source_path="SRUDB.dat", parser=SRUMECMD_BACKEND_CSV, status="processing", record_count=0)
            db.add(artifact)
            db.commit()
            db.refresh(artifact)
        else:
            artifact.status = "processing"
            db.commit()
        runtime_settings = load_runtime_settings(db)
        batch_size = max(int(runtime_settings.get("OPENSEARCH_BULK_DOCS") or settings.opensearch_bulk_docs or 1000), 1)
        artifact_meta = {
            **dict(evidence.metadata_json or {}),
            "name": artifact.name,
            "source_path": artifact.source_path,
            "artifact_type": "srum",
            "parser": SRUMECMD_BACKEND_CSV,
            "detected_host": str((evidence.metadata_json or {}).get("provided_host") or evidence.detected_host or "").strip() or None,
            "provided_host": str((evidence.metadata_json or {}).get("provided_host") or "").strip() or None,
            "detected_user": evidence.detected_user,
        }
        started = time.perf_counter()
        indexed = 0
        latest: dict = {}
        for batch, progress in iter_srumecmd_batches(case_id=evidence.case_id, evidence_id=evidence.id, artifact_id=artifact.id, artifact_meta=artifact_meta, batch_size=batch_size):
            latest = dict(progress)
            if not batch:
                continue
            for doc in batch:
                apply_case_host_identity(db, evidence.case_id, doc)
            bulk_index_events_with_report(
                evidence.case_id,
                batch,
                index=index_name,
                refresh=False,
                max_bulk_docs=batch_size,
                max_bulk_bytes=int(runtime_settings.get("OPENSEARCH_BULK_BYTES") or settings.opensearch_bulk_bytes or 10485760),
                apply_host_identity=False,
                apply_fingerprint=False,
            )
            indexed += len(batch)
            _update_srum_metadata(
                evidence_id,
                {
                    "run_id": run_id,
                    "status": "running",
                    "started_at": started_at,
                    "finished_at": None,
                    "backend": SRUMECMD_BACKEND_CSV,
                    "backend_version": latest.get("backend_version") or backend.get("version") or "",
                    "records_indexed": indexed,
                    "sources_total": int(latest.get("sources_total") or 0),
                    "sources_parsed": int(latest.get("sources_parsed") or 0),
                    "sources_failed": int(latest.get("sources_failed") or 0),
                    "tables": latest.get("tables") or {},
                    "event_types": latest.get("event_types") or {},
                    "top_apps": latest.get("top_apps") or {},
                    "errors": latest.get("errors") or [],
                    "elapsed_seconds": round(time.perf_counter() - started, 2),
                    "artifact_id": artifact.id,
                },
            )
        refresh_index(index_name, raise_on_error=False)
        indexed = _srum_docs_count(evidence.case_id, evidence.id)
        artifact.record_count = indexed
        artifact.status = "completed" if indexed else "parsed_empty"
        db.commit()
        source_total = int(latest.get("sources_total") or len(find_srum_databases(evidence.case_id, evidence.id, dict(evidence.metadata_json or {}))))
        result = {
            "run_id": run_id,
            "status": "completed" if indexed else "no_data",
            "started_at": started_at,
            "finished_at": utc_now().isoformat(),
            "backend": SRUMECMD_BACKEND_CSV,
            "backend_version": latest.get("backend_version") or backend.get("version") or "",
            "records_indexed": indexed,
            "sources_total": source_total,
            "sources_parsed": int(latest.get("sources_parsed") or 0),
            "sources_failed": int(latest.get("sources_failed") or 0),
            "tables": latest.get("tables") or {},
            "event_types": latest.get("event_types") or {},
            "top_apps": latest.get("top_apps") or {},
            "errors": latest.get("errors") or [],
            "no_data": indexed == 0,
            "elapsed_seconds": round(time.perf_counter() - started, 2),
            "artifact_id": artifact.id,
            "warnings": [] if indexed else (["srum_no_data"] if source_total else ["srum_database_not_detected"]),
        }
        _update_srum_metadata(evidence_id, result)
        log_activity(db, activity_type="srum_indexed", title="SRUM indexed", message=f"Indexed {indexed} SRUM records for {evidence.original_filename}", case_id=evidence.case_id, evidence_id=evidence.id, metadata=result)
        return result
    except Exception as exc:  # noqa: BLE001
        logger.exception("SRUM indexing failed for evidence %s", evidence_id)
        _update_srum_metadata(evidence_id, {"run_id": run_id, "status": "failed", "started_at": started_at, "finished_at": utc_now().isoformat(), "backend": SRUMECMD_BACKEND_CSV, "error": str(exc)})
        raise
    finally:
        db.close()


def _defender_docs_count(case_id: str, evidence_id: str) -> int:
    try:
        index = get_events_index(case_id)
        return int(
            (count_documents(index, {"bool": {"filter": [{"term": {"case_id": case_id}}, {"term": {"evidence_id": evidence_id}}, {"term": {"artifact.type": "defender"}}, {"term": {"artifact.parser": DEFENDER_EVTX_BACKEND}}]}}).get("count") or 0)
        )
    except Exception as exc:  # noqa: BLE001
        logger.warning("Could not count Defender docs for evidence %s: %s", evidence_id, exc)
        return 0


def _defender_evtx_candidate_paths(evidence: Evidence) -> list[str]:
    metadata = dict(evidence.metadata_json or {})
    candidates: list[dict] = []
    candidates.extend(list(((metadata.get("ingest_plan") or {}).get("disabled_candidates") or [])))
    candidates.extend(list(((metadata.get("velociraptor_discovery") or {}).get("candidates") or [])))
    paths: list[str] = []
    seen: set[str] = set()
    for candidate in candidates:
        if not isinstance(candidate, dict):
            continue
        artifact_type = str(candidate.get("artifact_type") or "").strip().lower()
        parser = str(candidate.get("parser") or "").strip().lower()
        path = str(candidate.get("source_path") or candidate.get("relative_path") or candidate.get("path") or "").strip()
        text = " ".join(str(candidate.get(key) or "") for key in ("display_name", "name", "source_path", "relative_path", "path")).lower()
        is_defender_evtx = (
            artifact_type == "defender_evtx"
            or parser == "defender_evtx"
            or ("defender" in text and ".evtx" in text)
        )
        if not is_defender_evtx or not path or path in seen:
            continue
        seen.add(path)
        paths.append(path)
    return paths


def _build_defender_docs_from_raw_evtx(
    evidence: Evidence,
    artifact: Artifact,
    *,
    batch_size: int,
) -> tuple[list[dict], dict]:
    source_paths = _defender_evtx_candidate_paths(evidence)
    if not source_paths:
        return [], {"raw_sources_detected": 0, "raw_sources_parsed": 0, "raw_source_errors": []}
    container_path = Path(evidence.stored_path or "")
    if not container_path.exists():
        return [], {"raw_sources_detected": len(source_paths), "raw_sources_parsed": 0, "raw_source_errors": [f"stored_path_missing:{container_path}"]}
    output_dir = build_evidence_root(evidence.case_id, evidence.id) / "derived" / "defender_evtx"
    output_dir.mkdir(parents=True, exist_ok=True)
    docs: list[dict] = []
    errors: list[str] = []
    parsed_sources = 0
    container = open_evidence_container(container_path)
    extracted = container.extract_entries(source_paths, output_dir)
    for item in extracted:
        if item.get("status") != "extracted" or not item.get("local_path"):
            errors.append(f"{item.get('path')}: {item.get('error') or 'extract_failed'}")
            continue
        local_path = Path(str(item["local_path"]))
        source_path = str(item.get("path") or local_path)
        artifact_meta = {
            **dict(evidence.metadata_json or {}),
            "artifact_type": "windows_event",
            "parser": EVTXECMD_BACKEND_CSV,
            "source_tool": "evtxecmd",
            "source_format": "evtx",
            "source_path": source_path,
            "name": f"Defender EVTX - {Path(source_path).name}",
            "detected_host": str((evidence.metadata_json or {}).get("provided_host") or evidence.detected_host or "").strip() or None,
            "provided_host": str((evidence.metadata_json or {}).get("provided_host") or "").strip() or None,
            "detected_user": evidence.detected_user,
        }
        try:
            for _selection, result in _iter_full_evtx_batches_with_backend(
                path=local_path,
                case_id=evidence.case_id,
                evidence_id=evidence.id,
                artifact_id=artifact.id,
                artifact_meta=artifact_meta,
                batch_size=max(int(batch_size or 0), 500),
                requested_backend=EVTXECMD_BACKEND_CSV,
            ):
                for source_doc in result.events or []:
                    defender_docs, _ = build_defender_documents_from_sources([(str(source_doc.get("event_id") or ""), source_doc)])
                    docs.extend(defender_docs)
            parsed_sources += 1
        except Exception as exc:  # noqa: BLE001
            errors.append(f"{source_path}: {exc}")
    return docs, {"raw_sources_detected": len(source_paths), "raw_sources_parsed": parsed_sources, "raw_source_errors": errors}


def _update_defender_evtx_metadata(evidence_id: str, run: dict) -> None:
    isolated_db = SessionLocal()
    try:
        evidence = isolated_db.get(Evidence, evidence_id)
        if not evidence:
            return
        metadata = dict(evidence.metadata_json or {})
        runs = [item for item in list(metadata.get("defender_evtx_runs") or []) if isinstance(item, dict) and str(item.get("run_id") or "") != str(run.get("run_id") or "")]
        runs.append(run)
        metadata["defender_evtx_runs"] = runs[-10:]
        metadata["defender_evtx"] = dict(run)
        metadata["defender_evtx_status"] = run.get("status") or metadata.get("defender_evtx_status")
        metadata["defender_evtx_docs_indexed"] = int(run.get("docs_indexed") or metadata.get("defender_evtx_docs_indexed") or 0)
        metadata["defender_evtx_no_data"] = bool(run.get("no_data", False))
        metadata["defender_evtx_sources_detected"] = int(run.get("sources_detected") or metadata.get("defender_evtx_sources_detected") or 0)
        metadata["defender_evtx_by_event_id"] = dict(run.get("by_event_id") or metadata.get("defender_evtx_by_event_id") or {})
        metadata["defender_evtx_by_threat"] = dict(run.get("by_threat") or metadata.get("defender_evtx_by_threat") or {})
        metadata["investigation_ready"] = True
        evidence.metadata_json = merge_evidence_metadata(evidence.metadata_json or {}, metadata)
        isolated_db.commit()
    finally:
        isolated_db.close()


def index_defender_evtx_for_evidence(evidence_id: str, force: bool = False) -> dict:
    run_id = f"defender-evtx-{evidence_id}-{int(time.time())}"
    started_at = utc_now().isoformat()
    _update_defender_evtx_metadata(evidence_id, {"run_id": run_id, "status": "running", "started_at": started_at, "finished_at": None, "parser": DEFENDER_EVTX_BACKEND, "docs_indexed": 0, "no_data": False})
    db = SessionLocal()
    try:
        evidence = db.get(Evidence, evidence_id)
        if not evidence:
            raise RuntimeError("Evidence not found")
        index_name = ensure_case_index(evidence.case_id)
        existing = _defender_docs_count(evidence.case_id, evidence.id)
        if existing > 0 and not force:
            result = {
                "run_id": run_id,
                "status": "completed",
                "started_at": started_at,
                "finished_at": utc_now().isoformat(),
                "parser": DEFENDER_EVTX_BACKEND,
                "docs_indexed": existing,
                "sources_detected": existing,
                "no_data": False,
                "elapsed_seconds": 0,
                "warnings": ["defender_evtx_already_indexed"],
            }
            _update_defender_evtx_metadata(evidence_id, result)
            return result
        client = get_opensearch_client()
        if existing > 0 and force:
            client.delete_by_query(
                index=index_name,
                body={
                    "query": {
                        "bool": {
                            "filter": [
                                {"term": {"case_id": evidence.case_id}},
                                {"term": {"evidence_id": evidence.id}},
                                {"term": {"artifact.type": "defender"}},
                                {"term": {"artifact.parser": DEFENDER_EVTX_BACKEND}},
                            ]
                        }
                    }
                },
                params={"refresh": "true", "ignore_unavailable": "true"},
            )
        artifact = (
            db.query(Artifact)
            .filter(Artifact.evidence_id == evidence.id, Artifact.artifact_type == "defender", Artifact.parser == DEFENDER_EVTX_BACKEND)
            .first()
        )
        if not artifact:
            artifact = Artifact(case_id=evidence.case_id, evidence_id=evidence.id, name="Microsoft Defender EVTX", artifact_type="defender", source_path="Windows Defender Operational EVTX", parser=DEFENDER_EVTX_BACKEND, status="processing", record_count=0)
            db.add(artifact)
            db.commit()
            db.refresh(artifact)
        else:
            artifact.status = "processing"
            db.commit()
        started = time.perf_counter()
        sources = list(iter_defender_evtx_source_docs(index_name, evidence.case_id, evidence.id))
        docs, stats = build_defender_documents_from_sources(sources)
        raw_stats: dict = {}
        if not docs:
            runtime_settings = load_runtime_settings(db)
            docs, raw_stats = _build_defender_docs_from_raw_evtx(
                evidence,
                artifact,
                batch_size=max(int(runtime_settings.get("OPENSEARCH_BULK_DOCS") or settings.opensearch_bulk_docs or 1000), 1),
            )
            raw_doc_stats = build_defender_documents_from_sources([(str(doc.get("event_id") or ""), doc) for doc in docs])[1] if docs else {}
            if raw_doc_stats:
                stats = raw_doc_stats
        for doc in docs:
            doc["artifact_id"] = artifact.id
            apply_case_host_identity(db, evidence.case_id, doc)
        if docs:
            runtime_settings = load_runtime_settings(db)
            bulk_index_events_with_report(
                evidence.case_id,
                docs,
                index=index_name,
                refresh=False,
                max_bulk_docs=max(int(runtime_settings.get("OPENSEARCH_BULK_DOCS") or settings.opensearch_bulk_docs or 1000), 1),
                max_bulk_bytes=int(runtime_settings.get("OPENSEARCH_BULK_BYTES") or settings.opensearch_bulk_bytes or 10485760),
                apply_host_identity=False,
                apply_fingerprint=False,
            )
            refresh_index(index_name, raise_on_error=False)
        indexed = _defender_docs_count(evidence.case_id, evidence.id)
        artifact.record_count = indexed
        artifact.status = "completed" if indexed else "parsed_empty"
        db.commit()
        result = {
            "run_id": run_id,
            "status": "completed",
            "started_at": started_at,
            "finished_at": utc_now().isoformat(),
            "parser": DEFENDER_EVTX_BACKEND,
            "docs_indexed": indexed,
            "sources_detected": len(sources) or int(raw_stats.get("raw_sources_detected") or 0),
            "raw_sources_detected": int(raw_stats.get("raw_sources_detected") or 0),
            "raw_sources_parsed": int(raw_stats.get("raw_sources_parsed") or 0),
            "raw_source_errors": raw_stats.get("raw_source_errors") or [],
            "no_data": indexed == 0,
            "by_event_id": stats.get("by_event_id") or {},
            "by_threat": stats.get("by_threat") or {},
            "elapsed_seconds": round(time.perf_counter() - started, 2),
            "artifact_id": artifact.id,
            "warnings": [] if indexed else ["defender_evtx_no_relevant_events"],
        }
        _update_defender_evtx_metadata(evidence_id, result)
        log_activity(db, activity_type="defender_evtx_indexed", title="Defender EVTX indexed", message=f"Indexed {indexed} Defender events for {evidence.original_filename}", case_id=evidence.case_id, evidence_id=evidence.id, metadata=result)
        return result
    except Exception as exc:  # noqa: BLE001
        logger.exception("Defender EVTX indexing failed for evidence %s", evidence_id)
        _update_defender_evtx_metadata(evidence_id, {"run_id": run_id, "status": "failed", "started_at": started_at, "finished_at": utc_now().isoformat(), "parser": DEFENDER_EVTX_BACKEND, "error": str(exc)})
        raise
    finally:
        db.close()


def index_recmd_user_activity_for_evidence(evidence_id: str, force: bool = False) -> dict:
    run_id = f"recmd-user-activity-{evidence_id}-{int(time.time())}"
    started_at = utc_now().isoformat()
    _update_recmd_user_activity_metadata(
        evidence_id,
        {"run_id": run_id, "status": "running", "started_at": started_at, "finished_at": None, "backend": RECMD_BACKEND_CSV, "records_indexed": 0, "records_indexed_by_family": {}},
    )
    db = SessionLocal()
    try:
        evidence = db.get(Evidence, evidence_id)
        if not evidence:
            raise RuntimeError("Evidence not found")
        existing_counts = _user_activity_docs_count(evidence.case_id, evidence.id)
        existing_total = sum(existing_counts.values())
        if existing_total > 0 and not force:
            result = {
                "run_id": run_id,
                "status": "completed",
                "started_at": started_at,
                "finished_at": utc_now().isoformat(),
                "backend": RECMD_BACKEND_CSV,
                "backend_version": detect_recmd_backend().get("version") or "",
                "records_indexed": existing_total,
                "records_indexed_by_family": existing_counts,
                "hives_processed": int((evidence.metadata_json or {}).get("registry_user_activity_hives_processed") or 0),
                "hives_failed": int((evidence.metadata_json or {}).get("registry_user_activity_hives_failed") or 0),
                "elapsed_seconds": 0,
                "warnings": ["recmd_user_activity_already_indexed"],
            }
            _update_recmd_user_activity_metadata(evidence_id, result)
            return result
        backend = detect_recmd_backend()
        if not backend.get("available"):
            raise RuntimeError(str(backend.get("error") or "RECmd backend is not available"))
        index_name = ensure_case_index(evidence.case_id)
        if existing_total > 0 and force:
            client = get_opensearch_client()
            try:
                client.delete_by_query(
                    index=index_name,
                    body={
                        "query": {
                            "bool": {
                                "filter": [
                                    {"term": {"case_id": evidence.case_id}},
                                    {"term": {"evidence_id": evidence.id}},
                                    {"terms": {"artifact.type": sorted(USER_ACTIVITY_ARTIFACT_TYPES)}},
                                    {"term": {"source_tool": "recmd"}},
                                ]
                            }
                        }
                    },
                    params={"refresh": "true", "ignore_unavailable": "true"},
                )
            except Exception as exc:  # noqa: BLE001
                logger.warning("Could not clear previous RECmd user activity docs for evidence %s: %s", evidence.id, exc)
        artifact = (
            db.query(Artifact)
            .filter(Artifact.evidence_id == evidence.id, Artifact.artifact_type == "user_activity", Artifact.parser == RECMD_BACKEND_CSV)
            .first()
        )
        if not artifact:
            artifact = Artifact(case_id=evidence.case_id, evidence_id=evidence.id, name="RECmd user activity", artifact_type="user_activity", source_path="NTUSER.DAT / UsrClass.dat", parser=RECMD_BACKEND_CSV, status="processing", record_count=0)
            db.add(artifact)
            db.commit()
            db.refresh(artifact)
        else:
            artifact.status = "processing"
            db.commit()
        runtime_settings = load_runtime_settings(db)
        batch_size = max(int(runtime_settings.get("OPENSEARCH_BULK_DOCS") or settings.opensearch_bulk_docs or 1000), 1)
        artifact_meta = {
            **dict(evidence.metadata_json or {}),
            "name": artifact.name,
            "source_path": artifact.source_path,
            "artifact_type": "user_activity",
            "parser": RECMD_BACKEND_CSV,
            "detected_host": str((evidence.metadata_json or {}).get("provided_host") or evidence.detected_host or "").strip() or None,
            "provided_host": str((evidence.metadata_json or {}).get("provided_host") or "").strip() or None,
            "detected_user": evidence.detected_user,
        }
        started = time.perf_counter()
        indexed = 0
        latest: dict = {}
        for batch, progress in iter_recmd_user_activity_batches(case_id=evidence.case_id, evidence_id=evidence.id, artifact_id=artifact.id, artifact_meta=artifact_meta, batch_size=batch_size):
            latest = dict(progress)
            if not batch:
                continue
            bulk_index_events_with_report(
                evidence.case_id,
                batch,
                index=index_name,
                refresh=False,
                max_bulk_docs=batch_size,
                max_bulk_bytes=int(runtime_settings.get("OPENSEARCH_BULK_BYTES") or settings.opensearch_bulk_bytes or 10485760),
                apply_host_identity=False,
                apply_fingerprint=False,
            )
            indexed += len(batch)
            _update_recmd_user_activity_metadata(
                evidence_id,
                {
                    "run_id": run_id,
                    "status": "running",
                    "started_at": started_at,
                    "finished_at": None,
                    "backend": RECMD_BACKEND_CSV,
                    "backend_version": latest.get("backend_version") or backend.get("version") or "",
                    "records_indexed": indexed,
                    "records_indexed_by_family": latest.get("records_indexed_by_family") or {},
                    "hives_total": int(latest.get("hives_total") or 0),
                    "hives_processed": int(latest.get("hives_processed") or 0),
                    "hives_failed": int(latest.get("hives_failed") or 0),
                    "errors": latest.get("errors") or [],
                    "elapsed_seconds": round(time.perf_counter() - started, 2),
                    "artifact_id": artifact.id,
                },
            )
        refresh_index(index_name, raise_on_error=False)
        final_counts = _user_activity_docs_count(evidence.case_id, evidence.id)
        indexed = sum(final_counts.values())
        artifact.record_count = indexed
        artifact.status = "completed" if indexed else "parsed_empty"
        db.commit()
        result = {
            "run_id": run_id,
            "status": "completed",
            "started_at": started_at,
            "finished_at": utc_now().isoformat(),
            "backend": RECMD_BACKEND_CSV,
            "backend_version": latest.get("backend_version") or backend.get("version") or "",
            "records_indexed": indexed,
            "records_indexed_by_family": final_counts,
            "hives_total": int(latest.get("hives_total") or 0),
            "hives_processed": int(latest.get("hives_processed") or 0),
            "hives_failed": int(latest.get("hives_failed") or 0),
            "errors": latest.get("errors") or [],
            "elapsed_seconds": round(time.perf_counter() - started, 2),
            "artifact_id": artifact.id,
            "warnings": [] if indexed else ["recmd_user_activity_no_data"],
        }
        _update_recmd_user_activity_metadata(evidence_id, result)
        log_activity(db, activity_type="recmd_user_activity_indexed", title="RECmd user activity indexed", message=f"Indexed {indexed} user activity records for {evidence.original_filename}", case_id=evidence.case_id, evidence_id=evidence.id, metadata=result)
        return result
    except Exception as exc:  # noqa: BLE001
        logger.exception("RECmd user activity indexing failed for evidence %s", evidence_id)
        _update_recmd_user_activity_metadata(evidence_id, {"run_id": run_id, "status": "failed", "started_at": started_at, "finished_at": utc_now().isoformat(), "backend": RECMD_BACKEND_CSV, "error": str(exc)})
        raise
    finally:
        db.close()


def _update_mft_summary_metadata(evidence_id: str, run: dict) -> None:
    isolated_db = SessionLocal()
    try:
        evidence = isolated_db.get(Evidence, evidence_id)
        if not evidence:
            return
        metadata = dict(evidence.metadata_json or {})
        runs = [item for item in list(metadata.get("mft_summary_runs") or []) if isinstance(item, dict) and str(item.get("run_id") or "") != str(run.get("run_id") or "")]
        runs.append(run)
        metadata["mft_summary_runs"] = runs[-10:]
        metadata["mft_summary"] = dict(run)
        if run.get("status") == "completed":
            metadata["mft_parser_backend"] = MFTECMD_BACKEND_CSV
            metadata["mft_parser_backend_version"] = run.get("backend_version") or ""
            metadata["mft_index_mode"] = "summary"
            metadata["mft_records_total"] = int(run.get("records_total") or 0)
            metadata["mft_records_indexed"] = int(run.get("records_indexed") or 0)
            metadata["mft_records_skipped"] = int(run.get("records_skipped") or 0)
            metadata["mft_summary_limits"] = dict(run.get("limits") or {})
            metadata["mft_elapsed_seconds"] = float(run.get("elapsed_seconds") or 0)
            metadata["mft_coverage_status"] = run.get("coverage_status") or "partial_summary"
            metadata["investigation_ready"] = True
            if run.get("coverage_status") == "partial_summary":
                warnings = list(metadata.get("warnings") or [])
                if "mft_summary_partial" not in warnings:
                    warnings.append("mft_summary_partial")
                metadata["warnings"] = warnings
                metadata["warning_count"] = max(int(metadata.get("warning_count") or 0), len(warnings))
                metadata["display_status"] = "completed_with_warnings"
        evidence.metadata_json = merge_evidence_metadata(evidence.metadata_json or {}, metadata)
        isolated_db.commit()
    finally:
        isolated_db.close()


def _update_mft_full_metadata(evidence_id: str, run: dict) -> None:
    isolated_db = SessionLocal()
    try:
        evidence = isolated_db.get(Evidence, evidence_id)
        if not evidence:
            return
        metadata = dict(evidence.metadata_json or {})
        runs = [item for item in list(metadata.get("mft_full_runs") or []) if isinstance(item, dict) and str(item.get("run_id") or "") != str(run.get("run_id") or "")]
        runs.append(run)
        metadata["mft_full_runs"] = runs[-10:]
        metadata["mft_full"] = dict(run)
        metadata["mft_full_status"] = run.get("status") or metadata.get("mft_full_status")
        metadata["mft_full_backend"] = run.get("backend") or metadata.get("mft_full_backend")
        metadata["mft_full_records_total"] = int(run.get("records_total") or metadata.get("mft_full_records_total") or 0)
        metadata["mft_full_records_indexed"] = int(run.get("records_indexed") or metadata.get("mft_full_records_indexed") or 0)
        metadata["mft_full_started_at"] = run.get("started_at") or metadata.get("mft_full_started_at")
        metadata["mft_full_finished_at"] = run.get("finished_at") or metadata.get("mft_full_finished_at")
        metadata["mft_full_elapsed_seconds"] = float(run.get("elapsed_seconds") or metadata.get("mft_full_elapsed_seconds") or 0)
        metadata["mft_full_coverage_status"] = run.get("coverage_status") or metadata.get("mft_full_coverage_status")
        metadata["mft_full_limits"] = dict(run.get("limits") or metadata.get("mft_full_limits") or {})
        if run.get("status") == "completed":
            metadata["mft_parser_backend"] = MFTECMD_BACKEND_CSV
            metadata["mft_parser_backend_version"] = run.get("backend_version") or ""
            metadata["mft_index_mode"] = "full"
            metadata["mft_records_total"] = int(run.get("records_total") or 0)
            metadata["mft_records_indexed"] = int(run.get("records_indexed") or 0)
            metadata["mft_records_skipped"] = int(run.get("records_skipped") or 0)
            metadata["mft_elapsed_seconds"] = float(run.get("elapsed_seconds") or 0)
            metadata["mft_phase_timings"] = dict(run.get("phase_timings") or {})
            metadata["mft_coverage_status"] = run.get("coverage_status") or "full"
            metadata["investigation_ready"] = True
            warnings = list(metadata.get("warnings") or [])
            if run.get("coverage_status") == "partial_full" and "mft_full_partial" not in warnings:
                warnings.append("mft_full_partial")
            if warnings:
                metadata["warnings"] = warnings
                metadata["warning_count"] = max(int(metadata.get("warning_count") or 0), len(warnings))
        evidence.metadata_json = merge_evidence_metadata(evidence.metadata_json or {}, metadata)
        isolated_db.commit()
    finally:
        isolated_db.close()


def index_mft_summary_for_evidence(evidence_id: str, max_records: int | None = None, force: bool = False) -> dict:
    run_id = _mft_summary_run_id(evidence_id)
    started_at = utc_now().isoformat()
    _update_mft_summary_metadata(
        evidence_id,
        {"run_id": run_id, "status": "running", "started_at": started_at, "finished_at": None, "backend": MFTECMD_BACKEND_CSV, "mode": "summary", "records_total": 0, "records_indexed": 0, "records_skipped": 0, "coverage_status": "partial_summary"},
    )
    db = SessionLocal()
    try:
        evidence = db.get(Evidence, evidence_id)
        if not evidence:
            raise RuntimeError("Evidence not found")
        existing_count = _mft_docs_count(evidence.case_id, evidence.id)
        if existing_count > 0 and not force:
            (
                db.query(Artifact)
                .filter(Artifact.evidence_id == evidence.id, Artifact.artifact_type == "mft", Artifact.parser == MFTECMD_BACKEND_CSV)
                .update({"status": "completed", "record_count": existing_count}, synchronize_session=False)
            )
            db.commit()
            result = {
                "run_id": run_id,
                "status": "completed",
                "started_at": started_at,
                "finished_at": utc_now().isoformat(),
                "backend": MFTECMD_BACKEND_CSV,
                "backend_version": detect_mftecmd_backend().get("version") or "",
                "mode": "summary",
                "records_total": existing_count,
                "records_indexed": existing_count,
                "records_skipped": 0,
                "coverage_status": "partial_summary",
                "limits": {"existing_docs_reused": True},
                "elapsed_seconds": 0,
                "warnings": ["mft_summary_partial", "mft_summary_already_indexed"],
            }
            _update_mft_summary_metadata(evidence_id, result)
            return result
        if existing_count > 0 and force:
            client = get_opensearch_client()
            index_name = get_events_index(evidence.case_id)
            try:
                client.delete_by_query(
                    index=index_name,
                    body={
                        "query": {
                            "bool": {
                                "filter": [
                                    {"term": {"case_id": evidence.case_id}},
                                    {"term": {"evidence_id": evidence.id}},
                                    {"term": {"artifact.type": "mft"}},
                                    {"term": {"artifact.parser": MFTECMD_BACKEND_CSV}},
                                ]
                            }
                        }
                    },
                    params={"refresh": "true", "ignore_unavailable": "true"},
                )
            except Exception as exc:  # noqa: BLE001
                logger.warning("Could not clear previous MFT summary docs for evidence %s: %s", evidence.id, exc)
        backend = detect_mftecmd_backend()
        if not backend.get("available"):
            raise RuntimeError(str(backend.get("error") or "MFTECmd backend is not available"))
        raw_mft_path, source_path = _resolve_mft_raw_path(evidence)
        artifact = (
            db.query(Artifact)
            .filter(Artifact.evidence_id == evidence.id, Artifact.source_path == source_path, Artifact.artifact_type == "mft", Artifact.parser == MFTECMD_BACKEND_CSV)
            .first()
        )
        if not artifact:
            artifact = Artifact(case_id=evidence.case_id, evidence_id=evidence.id, name="$MFT summary", artifact_type="mft", source_path=source_path, parser=MFTECMD_BACKEND_CSV, status="processing", record_count=0)
            db.add(artifact)
            db.commit()
            db.refresh(artifact)
        else:
            artifact.status = "processing"
            db.commit()
        runtime_settings = load_runtime_settings(db)
        batch_size = max(int(runtime_settings.get("OPENSEARCH_BULK_DOCS") or settings.opensearch_bulk_docs or 1000), 1)
        effective_max_records = max(int(max_records or settings.mft_summary_max_records or 250000), 1)
        effective_max_seconds = max(int(settings.mft_summary_max_seconds or 0), 0)
        artifact_meta = {
            "name": artifact.name,
            "source_path": source_path,
            "artifact_type": "mft",
            "parser": MFTECMD_BACKEND_CSV,
            "detected_host": str((evidence.metadata_json or {}).get("provided_host") or evidence.detected_host or "").strip() or None,
            "provided_host": str((evidence.metadata_json or {}).get("provided_host") or "").strip() or None,
            "detected_user": evidence.detected_user,
            "mft_index_mode": "summary",
        }
        index_name = ensure_case_index(evidence.case_id)
        started = time.perf_counter()
        indexed = 0
        latest: dict = {}
        bulk_index_seconds = 0.0
        progress_update_seconds = 0.0
        for batch, progress in iter_mftecmd_raw_summary_batches(
            raw_mft_path=raw_mft_path,
            case_id=evidence.case_id,
            evidence_id=evidence.id,
            artifact_id=artifact.id,
            artifact_meta=artifact_meta,
            batch_size=batch_size,
            max_records=effective_max_records,
            max_seconds=effective_max_seconds,
            fast_path=bool(runtime_settings.get("MFT_FAST_PATH", settings.mft_fast_path)),
        ):
            if not batch:
                continue
            bulk_started = time.perf_counter()
            bulk_index_events_with_report(
                evidence.case_id,
                batch,
                index=index_name,
                refresh=False,
                max_bulk_docs=batch_size,
                max_bulk_bytes=int(runtime_settings.get("OPENSEARCH_BULK_BYTES") or settings.opensearch_bulk_bytes or 10485760),
                # MFT summary documents are scoped to one evidence and already
                # carry the provided host. Avoid per-document DB host
                # reconciliation here; query-time host aliases cover legacy
                # variants without turning MFT summary indexing into a
                # per-row database workload.
                apply_host_identity=False,
                apply_fingerprint=False,
            )
            bulk_index_seconds += time.perf_counter() - bulk_started
            indexed += len(batch)
            latest = dict(progress)
            latest_timings = dict(latest.get("phase_timings") or {})
            latest_timings["bulk_index_seconds"] = round(bulk_index_seconds, 2)
            latest_timings["indexing_seconds"] = round(latest_timings.get("normalization_seconds", 0) + bulk_index_seconds, 2)
            latest["phase_timings"] = latest_timings
            progress_started = time.perf_counter()
            _update_mft_summary_metadata(
                evidence_id,
                {
                    "run_id": run_id,
                    "status": "running",
                    "started_at": started_at,
                    "finished_at": None,
                    "backend": MFTECMD_BACKEND_CSV,
                    "backend_version": latest.get("backend_version") or backend.get("version") or "",
                    "mode": "summary",
                    "records_total": int(latest.get("records_total") or 0),
                    "records_indexed": indexed,
                    "records_skipped": max(int(latest.get("records_total") or 0) - indexed, 0),
                    "coverage_status": latest.get("coverage_status") or "partial_summary",
                    "limits": latest.get("limits") or {},
                    "elapsed_seconds": round(time.perf_counter() - started, 2),
                    "phase_timings": latest.get("phase_timings") or {},
                    "selection_strategy": latest.get("selection_strategy"),
                    "source_hits": latest.get("source_hits") or {},
                    "records_selected": int(latest.get("records_selected") or indexed),
                    "artifact_id": artifact.id,
                    "source_file": source_path,
                },
            )
            progress_update_seconds += time.perf_counter() - progress_started
            latest["phase_timings"]["progress_update_seconds"] = round(progress_update_seconds, 2)
        refresh_index(index_name, raise_on_error=False)
        records_total = int(latest.get("records_total") or indexed)
        coverage = "full_summary" if indexed >= records_total else "partial_summary"
        artifact.record_count = indexed
        artifact.status = "completed" if indexed else "parsed_empty"
        db.commit()
        result = {
            "run_id": run_id,
            "status": "completed",
            "started_at": started_at,
            "finished_at": utc_now().isoformat(),
            "backend": MFTECMD_BACKEND_CSV,
            "backend_version": latest.get("backend_version") or backend.get("version") or "",
            "mode": "summary",
            "records_total": records_total,
            "records_indexed": indexed,
            "records_skipped": max(records_total - indexed, 0),
            "coverage_status": coverage,
            "limits": latest.get("limits") or {"max_records": effective_max_records, "max_seconds": effective_max_seconds, "batch_size": batch_size},
            "elapsed_seconds": round(time.perf_counter() - started, 2),
            "phase_timings": latest.get("phase_timings") or {},
            "selection_strategy": latest.get("selection_strategy"),
            "source_hits": latest.get("source_hits") or {},
            "records_selected": int(latest.get("records_selected") or indexed),
            "artifact_id": artifact.id,
            "source_file": source_path,
            "warnings": ["mft_summary_partial"] if coverage == "partial_summary" else [],
        }
        _update_mft_summary_metadata(evidence_id, result)
        log_activity(db, activity_type="mft_summary_indexed", title="MFT summary indexed", message=f"Indexed {indexed} MFT summary records for {evidence.original_filename}", case_id=evidence.case_id, evidence_id=evidence.id, metadata=result)
        return result
    except Exception as exc:  # noqa: BLE001
        logger.exception("MFT summary indexing failed for evidence %s", evidence_id)
        _update_mft_summary_metadata(evidence_id, {"run_id": run_id, "status": "failed", "started_at": started_at, "finished_at": utc_now().isoformat(), "backend": MFTECMD_BACKEND_CSV, "mode": "summary", "error": str(exc)})
        raise
    finally:
        db.close()


def index_mft_full_for_evidence(evidence_id: str, max_records: int | None = None, force: bool = False) -> dict:
    run_id = _mft_summary_run_id(evidence_id)
    started_at = utc_now().isoformat()
    _update_mft_full_metadata(
        evidence_id,
        {"run_id": run_id, "status": "running", "started_at": started_at, "finished_at": None, "backend": MFTECMD_BACKEND_CSV, "mode": "full", "records_total": 0, "records_indexed": 0, "records_skipped": 0, "coverage_status": "partial_full"},
    )
    db = SessionLocal()
    try:
        evidence = db.get(Evidence, evidence_id)
        if not evidence:
            raise RuntimeError("Evidence not found")
        metadata = dict(evidence.metadata_json or {})
        existing_full = dict(metadata.get("mft_full") or {})
        if existing_full.get("status") == "completed" and int(existing_full.get("records_indexed") or 0) > 0 and not force:
            return existing_full
        backend = detect_mftecmd_backend()
        if not backend.get("available"):
            raise RuntimeError(str(backend.get("error") or "MFTECmd backend is not available"))
        raw_mft_path, source_path = _resolve_mft_raw_path(evidence)
        index_name = ensure_case_index(evidence.case_id)
        client = get_opensearch_client()
        try:
            client.delete_by_query(
                index=index_name,
                body={
                    "query": {
                        "bool": {
                            "filter": [
                                {"term": {"case_id": evidence.case_id}},
                                {"term": {"evidence_id": evidence.id}},
                                {"term": {"artifact.type": "mft"}},
                                {"term": {"artifact.parser": MFTECMD_BACKEND_CSV}},
                            ]
                        }
                    }
                },
                params={"refresh": "true", "ignore_unavailable": "true"},
            )
        except Exception as exc:  # noqa: BLE001
            logger.warning("Could not clear previous MFT docs for evidence %s before full indexing: %s", evidence.id, exc)
        artifact = (
            db.query(Artifact)
            .filter(Artifact.evidence_id == evidence.id, Artifact.source_path == source_path, Artifact.artifact_type == "mft", Artifact.parser == MFTECMD_BACKEND_CSV)
            .first()
        )
        if not artifact:
            artifact = Artifact(case_id=evidence.case_id, evidence_id=evidence.id, name="$MFT full", artifact_type="mft", source_path=source_path, parser=MFTECMD_BACKEND_CSV, status="processing", record_count=0)
            db.add(artifact)
            db.commit()
            db.refresh(artifact)
        else:
            artifact.name = "$MFT full"
            artifact.status = "processing"
            db.commit()
        runtime_settings = load_runtime_settings(db)
        batch_size = max(int(runtime_settings.get("OPENSEARCH_BULK_DOCS") or settings.opensearch_bulk_docs or 1000), 1)
        effective_max_seconds = max(int(settings.mft_summary_max_seconds or 0), 0)
        artifact_meta = {
            "name": artifact.name,
            "source_path": source_path,
            "artifact_type": "mft",
            "parser": MFTECMD_BACKEND_CSV,
            "detected_host": str((evidence.metadata_json or {}).get("provided_host") or evidence.detected_host or "").strip() or None,
            "provided_host": str((evidence.metadata_json or {}).get("provided_host") or "").strip() or None,
            "detected_user": evidence.detected_user,
            "mft_index_mode": "full",
        }
        started = time.perf_counter()
        indexed = 0
        latest: dict = {}
        bulk_index_seconds = 0.0
        progress_update_seconds = 0.0
        for batch, progress in iter_mftecmd_raw_full_batches(
            raw_mft_path=raw_mft_path,
            case_id=evidence.case_id,
            evidence_id=evidence.id,
            artifact_id=artifact.id,
            artifact_meta=artifact_meta,
            batch_size=batch_size,
            max_records=max_records,
            max_seconds=effective_max_seconds,
            fast_path=bool(runtime_settings.get("MFT_FAST_PATH", settings.mft_fast_path)),
        ):
            if not batch:
                continue
            bulk_started = time.perf_counter()
            bulk_index_events_with_report(
                evidence.case_id,
                batch,
                index=index_name,
                refresh=False,
                max_bulk_docs=batch_size,
                max_bulk_bytes=int(runtime_settings.get("OPENSEARCH_BULK_BYTES") or settings.opensearch_bulk_bytes or 10485760),
                apply_host_identity=False,
                apply_fingerprint=False,
            )
            bulk_index_seconds += time.perf_counter() - bulk_started
            indexed += len(batch)
            latest = dict(progress)
            latest_timings = dict(latest.get("phase_timings") or {})
            latest_timings["bulk_index_seconds"] = round(bulk_index_seconds, 2)
            latest_timings["indexing_seconds"] = round(latest_timings.get("normalization_seconds", 0) + bulk_index_seconds, 2)
            latest["phase_timings"] = latest_timings
            progress_started = time.perf_counter()
            _update_mft_full_metadata(
                evidence_id,
                {
                    "run_id": run_id,
                    "status": "running",
                    "started_at": started_at,
                    "finished_at": None,
                    "backend": MFTECMD_BACKEND_CSV,
                    "backend_version": latest.get("backend_version") or backend.get("version") or "",
                    "mode": "full",
                    "records_total": int(latest.get("records_total") or 0),
                    "records_indexed": indexed,
                    "records_skipped": max(int(latest.get("records_total") or 0) - indexed, 0),
                    "coverage_status": latest.get("coverage_status") or "partial_full",
                    "limits": latest.get("limits") or {},
                    "elapsed_seconds": round(time.perf_counter() - started, 2),
                    "phase_timings": latest.get("phase_timings") or {},
                    "selection_strategy": latest.get("selection_strategy"),
                    "source_hits": latest.get("source_hits") or {},
                    "records_selected": int(latest.get("records_selected") or indexed),
                    "artifact_id": artifact.id,
                    "source_file": source_path,
                },
            )
            progress_update_seconds += time.perf_counter() - progress_started
            latest["phase_timings"]["progress_update_seconds"] = round(progress_update_seconds, 2)
        refresh_index(index_name, raise_on_error=False)
        records_total = int(latest.get("records_total") or indexed)
        coverage = "full" if indexed >= records_total else "partial_full"
        artifact.record_count = indexed
        artifact.status = "completed" if indexed else "parsed_empty"
        db.commit()
        result = {
            "run_id": run_id,
            "status": "completed",
            "started_at": started_at,
            "finished_at": utc_now().isoformat(),
            "backend": MFTECMD_BACKEND_CSV,
            "backend_version": latest.get("backend_version") or backend.get("version") or "",
            "mode": "full",
            "records_total": records_total,
            "records_indexed": indexed,
            "records_skipped": max(records_total - indexed, 0),
            "coverage_status": coverage,
            "limits": latest.get("limits") or {"max_records": max_records, "max_seconds": effective_max_seconds, "batch_size": batch_size},
            "elapsed_seconds": round(time.perf_counter() - started, 2),
            "phase_timings": latest.get("phase_timings") or {},
            "selection_strategy": latest.get("selection_strategy"),
            "source_hits": latest.get("source_hits") or {},
            "records_selected": int(latest.get("records_selected") or indexed),
            "artifact_id": artifact.id,
            "source_file": source_path,
            "warnings": ["mft_full_partial"] if coverage == "partial_full" else [],
        }
        _update_mft_full_metadata(evidence_id, result)
        log_activity(db, activity_type="mft_full_indexed", title="Full MFT indexed", message=f"Indexed {indexed} full MFT records for {evidence.original_filename}", case_id=evidence.case_id, evidence_id=evidence.id, metadata=result)
        return result
    except Exception as exc:  # noqa: BLE001
        logger.exception("Full MFT indexing failed for evidence %s", evidence_id)
        _update_mft_full_metadata(evidence_id, {"run_id": run_id, "status": "failed", "started_at": started_at, "finished_at": utc_now().isoformat(), "backend": MFTECMD_BACKEND_CSV, "mode": "full", "error": str(exc), "coverage_status": "failed"})
        raise
    finally:
        db.close()


def _event_search_body(case_id: str, evidence_id: str | None, rule: Rule) -> dict:
    if rule.engine.value == "heuristic":
        query = build_heuristic_query(load_heuristic_rule(rule.content))
    elif rule.engine.value == "sigma":
        sigma_rules = parse_sigma_rule(rule.content)
        if not sigma_rules:
            raise ValueError("No Sigma rules found in content")
        query = build_sigma_query(sigma_rules[0])
    elif rule.engine.value == "yara":
        raise ValueError("YARA rules must be run in files mode.")
    else:
        raise ValueError(f"Unsupported rule engine {rule.engine.value}")
    bool_query = query.setdefault("query", {}).setdefault("bool", {})
    filters = bool_query.setdefault("filter", [])
    filters.append({"term": {"case_id": case_id}})
    if evidence_id:
        filters.append({"term": {"evidence_id": evidence_id}})
    query.setdefault("size", 1000)
    return query


def _severity_to_confidence(severity: str | None) -> float | None:
    return {
        "info": 0.25,
        "informational": 0.25,
        "low": 0.4,
        "medium": 0.65,
        "high": 0.85,
        "critical": 0.95,
    }.get(str(severity or "").lower()) or None


def _dedup_fingerprint(*parts: object) -> str:
    blob = "|".join(str(part or "") for part in parts)
    return hashlib.sha256(blob.encode("utf-8", errors="ignore")).hexdigest()


def _event_value(source: dict, dotted: str) -> object:
    current: object = source
    for part in dotted.split("."):
        if not isinstance(current, dict):
            return None
        current = current.get(part)
    return current


def _event_timestamp(source: dict) -> str | None:
    return str(source.get("@timestamp") or source.get("timestamp") or "").strip() or None


def _sigma_rule_source_fields(compiled_rule: dict | None) -> list[str]:
    fields = {
        "@timestamp",
        "timestamp",
        "stable_event_id",
        "event_fingerprint",
        "event_id",
        "evidence_id",
        "artifact_id",
        "risk_score",
        "event.message",
        "event.severity",
        "artifact.name",
        "artifact.type",
        "artifact.parser",
        "host.name",
        "file.path",
        "file.sha256",
        "dns.domain",
        "destination.ip",
        "destination.hostname",
        "network.destination_ip",
        "url.full",
        "registry.key_path",
    }
    field_mappings = dict((compiled_rule or {}).get("sigma_field_mappings") or {})
    for mapped_fields in field_mappings.values():
        for field_name in mapped_fields or []:
            if str(field_name).strip():
                fields.add(str(field_name).strip())
    return sorted(fields)


def _build_sigma_detection_payload(
    *,
    case_id: str,
    rule: Rule,
    rule_run_id: str | None,
    sigma_metadata: dict,
    sigma_eval: dict,
    source: dict,
    hit: dict,
) -> dict:
    stable_event_id = str(source.get("stable_event_id") or source.get("event_fingerprint") or "").strip()
    rule_metadata = dict(rule.metadata_json or {})
    return {
        "case_id": case_id,
        "evidence_id": source.get("evidence_id"),
        "artifact_id": source.get("artifact_id"),
        "rule_id": rule.id,
        "rule_set_id": None,
        "engine": rule.engine.value,
        "source_engine": rule.engine.value,
        "rule_name": rule.name,
        "rule_title": rule.title or sigma_metadata.get("title") or rule.name,
        "rule_version": rule.rule_version or sigma_metadata.get("rule_version"),
        "rule_author": rule.author or sigma_metadata.get("author"),
        "rule_level": rule.level or sigma_metadata.get("level"),
        "severity": rule.severity or source.get("event", {}).get("severity"),
        "confidence": _severity_to_confidence(rule.severity or source.get("event", {}).get("severity")),
        "event_id": source.get("event_id"),
        "event_index": hit.get("_index"),
        "opensearch_id": hit.get("_id"),
        "target_type": "event",
        "target_path": source.get("file", {}).get("path"),
        "matched_at": _event_timestamp(source),
        "matched_stable_event_id": stable_event_id or None,
        "host_name": str((source.get("host") or {}).get("name") or "").strip() or None,
        "message": source.get("event", {}).get("message"),
        "matched_fields": sigma_eval.get("matched_fields") or {},
        "condition_summary": str(sigma_eval.get("condition_summary") or ""),
        "description": rule.description or sigma_metadata.get("description"),
        "false_positives": rule.false_positives or sigma_metadata.get("false_positives") or [],
        "references": rule.references or sigma_metadata.get("references") or [],
        "tags": list(dict.fromkeys((rule.tags or []) + (sigma_metadata.get("tags") or []) + ["sigma"])),
        "mitre": rule.mitre or sigma_metadata.get("mitre") or [],
        "related_event_ids": [source.get("event_id")] if source.get("event_id") else [],
        "related_iocs": {
            "files": [str(_event_value(source, "file.path"))] if _event_value(source, "file.path") else [],
            "hashes": [str(_event_value(source, "file.sha256"))] if _event_value(source, "file.sha256") else [],
            "domains": [str(_event_value(source, "dns.domain"))] if _event_value(source, "dns.domain") else [],
            "ips": [str(_event_value(source, "network.destination_ip"))] if _event_value(source, "network.destination_ip") else [],
            "urls": [str(_event_value(source, "url.full"))] if _event_value(source, "url.full") else [],
            "registry": [str(_event_value(source, "registry.key_path"))] if _event_value(source, "registry.key_path") else [],
        },
        "risk_score": float(max(int(source.get("risk_score") or 0), {"info": 10, "low": 30, "medium": 55, "high": 75, "critical": 95}.get(str((rule.severity or source.get("event", {}).get("severity") or "medium")).lower(), 55))),
        "dedup_fingerprint": _dedup_fingerprint(case_id, rule.id, stable_event_id or source.get("event_id"), source.get("artifact", {}).get("parser")),
        "engine_version": "rules_v2",
        "data_quality": sigma_eval.get("data_quality") or [],
        "raw": {
            "rule": rule.name,
            "rule_engine": rule.engine.value,
            "rule_title": rule.title or sigma_metadata.get("title") or rule.name,
            "rule_level": rule.level or sigma_metadata.get("level"),
            "expected_logsource": sigma_eval.get("expected_logsource") or sigma_metadata.get("logsource") or {},
            "actual_event_source": sigma_eval.get("actual_event_source") or {},
            "sigma_to_normalized_fields": sigma_eval.get("matched_fields") or {},
            "rule_run_id": rule_run_id,
            "rule_import_run_id": rule_metadata.get("import_run_id"),
            "rule_source_pack": rule_metadata.get("source_pack"),
            "matched_event": source.get("event_id"),
            "match_reason": source.get("event", {}).get("message"),
            "target_kind": "indexed_event",
            "artifact_name": source.get("artifact", {}).get("name"),
        },
    }


def _build_sigma_search_body(case_id: str, evidence_id: str | None, rule: Rule, metadata_json: dict, runtime_settings: dict | None = None) -> dict:
    body = _event_search_body(case_id, evidence_id, rule)
    bool_query = body.setdefault("query", {}).setdefault("bool", {})
    filters = bool_query.setdefault("filter", [])
    filters[:] = _sigma_scope_filter_clauses(case_id, evidence_id, metadata_json)
    prefilter = dict(metadata_json.get("_sigma_prefilter") or {})
    artifact_types = [str(item) for item in (prefilter.get("artifact_types") or []) if str(item).strip()]
    event_ids = [int(item) for item in (prefilter.get("event_ids") or []) if str(item).strip().isdigit()]
    channels = [str(item) for item in (prefilter.get("channels") or []) if str(item).strip()]
    field_exists = [str(item) for item in (prefilter.get("field_exists") or []) if str(item).strip()]
    if artifact_types:
        filters.append({"terms": {"artifact.type": artifact_types}})
    if event_ids:
        filters.append({"terms": {"windows.event_id": event_ids}})
    if channels:
        filters.append({"terms": {"windows.channel": channels}})
    for field_name in field_exists[:8]:
        bool_query.setdefault("should", []).append({"exists": {"field": field_name}})
    if bool_query.get("should"):
        bool_query["minimum_should_match"] = max(int(bool_query.get("minimum_should_match") or 0), 1)
    compiled_rule = dict(metadata_json.get("_sigma_compiled") or {})
    runtime_settings = runtime_settings or {}
    runtime_sigma_cap = int(runtime_settings.get("SIGMA_MAX_MATCHES_PER_RULE") or settings.sigma_max_matches_per_rule or 5000)
    max_events = min(
        int(metadata_json.get("max_events", runtime_sigma_cap) or runtime_sigma_cap),
        runtime_sigma_cap,
    )
    body["size"] = max(max_events, 1)
    body["_source"] = _sigma_rule_source_fields(compiled_rule)
    body["track_total_hits"] = False
    return body


def _collect_related_event_ids(case_id: str, *, file_path: str | None = None, file_hash: str | None = None) -> list[str]:
    clauses = []
    if file_path:
        clauses.append({"term": {"file.path.keyword": file_path}})
        clauses.append({"term": {"process.path.keyword": file_path}})
        clauses.append({"term": {"download.target_path.keyword": file_path}})
    if file_hash:
        clauses.append({"term": {"file.sha256.keyword": file_hash}})
        clauses.append({"term": {"hash.sha256.keyword": file_hash}})
    if not clauses:
        return []
    result = search_documents(
        get_events_index(case_id),
        {
            "size": 25,
            "_source": ["event_id"],
            "query": {
                "bool": {
                    "filter": [{"term": {"case_id": case_id}}],
                    "should": clauses,
                    "minimum_should_match": 1,
                }
            },
        },
    )
    event_ids: list[str] = []
    for hit in result.get("hits", {}).get("hits", []):
        event_id = str((hit.get("_source") or {}).get("event_id") or "").strip()
        if event_id and event_id not in event_ids:
            event_ids.append(event_id)
    return event_ids


def _sigma_scope_filter_clauses(case_id: str, evidence_id: str | None, metadata_json: dict | None = None) -> list[dict]:
    metadata_json = metadata_json or {}
    filters: list[dict] = [{"term": {"case_id": case_id}}]
    if evidence_id:
        filters.append({"term": {"evidence_id": evidence_id}})
    host = metadata_json.get("host")
    if host:
        filters.append({"term": {"host.name": host}})
    time_from = metadata_json.get("time_from")
    time_to = metadata_json.get("time_to")
    if time_from or time_to:
        filters.append({"range": {"@timestamp": {**({"gte": time_from} if time_from else {}), **({"lte": time_to} if time_to else {})}}})
    return filters


def _build_sigma_case_profile_for_scope(case_id: str, evidence_id: str | None, metadata_json: dict | None = None) -> dict:
    filters = _sigma_scope_filter_clauses(case_id, evidence_id, metadata_json)
    query = {"bool": {"filter": filters}}
    total_events = int(count_documents(get_events_index(case_id), query).get("count", 0))
    result = search_documents(
        get_events_index(case_id),
        {
            "size": min(int((metadata_json or {}).get("profile_sample_size", 1000) or 1000), 2000),
            "_source": [
                "artifact.type",
                "artifact.parser",
                "windows.event_id",
                "windows.channel",
                "windows.provider",
                "host.name",
                "user.name",
                "process.path",
                "process.name",
                "process.command_line",
                "process.parent_path",
                "process.parent_name",
                "process.parent_command_line",
                "file.path",
                "module.path",
                "network.destination_ip",
                "destination.ip",
                "destination.hostname",
                "dns.domain",
                "url.domain",
                "url.full",
                "registry.key_path",
                "registry.value_data",
                "powershell.script_block_text",
                "search_text",
            ],
            "query": query,
        },
    )
    hits = [hit.get("_source") or {} for hit in result.get("hits", {}).get("hits", [])]
    profile = build_sigma_case_profile(hits, total_events=total_events)
    profile["case_id"] = case_id
    if evidence_id:
        profile["evidence_id"] = evidence_id
    return profile


def run_rule_on_case(rule_id: str | None, case_id: str, evidence_id: str | None = None, dry_run: bool = False, run_id: str | None = None, rule_set_id: str | None = None, scan_options: dict | None = None) -> dict:
    db: Session = SessionLocal()
    runtime_settings = load_runtime_settings(db)
    rule = db.get(Rule, rule_id) if rule_id else None
    rule_set = db.get(RuleSet, rule_set_id) if rule_set_id else None
    detection_rule_run_id = run_id or str((scan_options or {}).get("_aggregate_rule_run_id") or "").strip() or None
    if not rule and not rule_set:
        db.close()
        return {"status": "missing", "matched": 0, "created_detections": 0, "duplicates": 0, "scanned_events": 0, "scanned_files": 0, "skipped_files": 0, "errors": ["rule_not_found"], "warnings": []}
    runnable = rule or rule_set
    rule_run = db.get(RuleRun, run_id) if run_id else None
    try:
        if rule_run:
            _update_rule_run(
                db,
                rule_run,
                status=RuleRunStatus.running,
                started_at=rule_run.started_at or utc_now().isoformat(),
                finished_at=None,
                scope=rule_run.scope or _infer_scope(evidence_id, scan_options),
                total_rules=max(int(rule_run.total_rules or 0), 1),
                processed_rules=0,
                current_phase="preparing_scope",
                last_error=None,
            )
            if rule_run.cancel_requested:
                _update_rule_run(
                    db,
                    rule_run,
                    status=RuleRunStatus.cancelled,
                    finished_at=utc_now().isoformat(),
                    current_phase="cancelled",
                    last_error="Cancelled before execution.",
                )
                return {"status": "cancelled", "matched": 0, "created_detections": 0, "duplicates": 0, "scanned_events": 0, "scanned_files": 0, "skipped_files": 0, "errors": [], "warnings": []}
        log_activity(
            db,
            activity_type="rule_run_started",
            title="Rule run started",
            message=f"Running {'rule pack' if rule_set else 'rule'} {runnable.name} on case {case_id}",
            case_id=case_id,
            evidence_id=evidence_id,
            metadata={"rule_id": rule.id if rule else None, "rule_set_id": rule_set.id if rule_set else None, "dry_run": dry_run},
        )
        created_count = 0
        duplicates = 0
        hits = []
        candidate_hits: list[dict] = []
        scanned_files = 0
        skipped_files = 0
        errors: list[str] = []
        runtime_errors_local: list[str] = []
        skipped_by_reason: dict[str, int] = {}
        candidate_breakdown: dict[str, int] = {}
        warnings: list[str] = []
        query_time_ms_total = 0
        dedupe_time_ms_total = 0
        write_time_ms_total = 0
        bulk_insert_batches = 0
        bulk_duplicate_lookups = 0
        current_rule_matches = 0
        current_rule_created = 0
        current_rule_duplicates = 0
        noisy_rules_count = 0
        capped_rules_count = 0
        skipped_too_broad_count = 0
        matches_capped_count = 0
        detections_capped_count = 0
        top_noisy_rules: list[dict[str, object]] = []
        if runnable.engine.value == "yara":
            if not yara_available():
                if rule_run:
                    _update_rule_run(
                        db,
                        rule_run,
                        status=RuleRunStatus.skipped,
                        finished_at=utc_now().isoformat(),
                        current_phase="completed",
                        errors=["YARA engine unavailable in this build."],
                        last_error="YARA engine unavailable in this build.",
                        metadata_json={"reason": "yara-python not installed"},
                    )
                log_activity(
                    db,
                    activity_type="rule_run_skipped",
                    title="YARA engine unavailable",
                    message=f"YARA {'rule pack' if rule_set else 'rule'} {runnable.name} requested but yara-python is not available.",
                    severity="warning",
                    case_id=case_id,
                    evidence_id=evidence_id,
                    metadata={"rule_id": rule.id if rule else None, "rule_set_id": rule_set.id if rule_set else None},
                )
                return {"status": "skipped", "matched": 0, "created_detections": 0, "duplicates": 0, "scanned_events": 0, "scanned_files": 0, "skipped_files": 0, "errors": ["YARA engine unavailable in this build."], "warnings": []}
            evidence_query = db.query(Evidence).filter(Evidence.case_id == case_id)
            if evidence_id:
                evidence_query = evidence_query.filter(Evidence.id == evidence_id)
            candidate_evidences = evidence_query.all()
            if rule_run:
                _update_rule_run(
                    db,
                    rule_run,
                    current_phase="scanning_files",
                    total_files=len(candidate_evidences),
                    scanned_files=0,
                )
            for evidence in candidate_evidences:
                if _is_rule_run_cancel_requested(run_id):
                    if rule_run:
                        _update_rule_run(
                            db,
                            rule_run,
                            status=RuleRunStatus.cancelled,
                            finished_at=utc_now().isoformat(),
                            current_phase="cancelled",
                            last_error="Cancelled at worker checkpoint.",
                        )
                    return {
                        "status": "cancelled",
                        "matched": len(hits),
                        "created_detections": created_count,
                        "duplicates": duplicates,
                        "scanned_events": 0,
                        "scanned_files": scanned_files,
                        "skipped_files": skipped_files,
                        "errors": errors,
                        "warnings": warnings,
                    }
                yara_result = run_yara_rule_set_on_evidence(rule_set, evidence, scan_options=scan_options) if rule_set else run_yara_rule_on_evidence(rule, evidence, scan_options=scan_options)
                scanned_files += int(yara_result.get("scanned_files", 0))
                skipped_files += int(yara_result.get("skipped_files", 0))
                errors.extend(yara_result.get("errors", []))
                warnings.extend(yara_result.get("warnings", []))
                for key, value in (yara_result.get("skipped_by_reason", {}) or {}).items():
                    skipped_by_reason[key] = skipped_by_reason.get(key, 0) + int(value)
                for key, value in (yara_result.get("candidate_breakdown", {}) or {}).items():
                    candidate_breakdown[key] = candidate_breakdown.get(key, 0) + int(value)
                if rule_run:
                    _update_rule_run(
                        db,
                        rule_run,
                        current_phase="scanning_files",
                        total_files=max(int(rule_run.total_files or 0), scanned_files + skipped_files),
                        scanned_files=scanned_files,
                        skipped_files=skipped_files,
                    )
                for match in yara_result["matches"]:
                    if _is_rule_run_cancel_requested(run_id):
                        if rule_run:
                            _update_rule_run(
                                db,
                                rule_run,
                                status=RuleRunStatus.cancelled,
                                finished_at=utc_now().isoformat(),
                                current_phase="cancelled",
                                last_error="Cancelled at worker checkpoint.",
                            )
                        return {
                            "status": "cancelled",
                            "matched": len(hits),
                            "created_detections": created_count,
                            "duplicates": duplicates,
                            "scanned_events": 0,
                            "scanned_files": scanned_files,
                            "skipped_files": skipped_files,
                            "errors": errors,
                            "warnings": warnings,
                        }
                    matched_rule_names = match.get("match_names", []) or [runnable.name]
                    detection_rule_name = matched_rule_names[0] if rule_set else runnable.name
                    related_event_ids = _collect_related_event_ids(case_id, file_path=match.get("path"), file_hash=match.get("file_sha256"))
                    dedup_fingerprint = _dedup_fingerprint(case_id, rule.id if rule else "", rule_set.id if rule_set else "", match.get("path"), match.get("file_sha256"), detection_rule_name)
                    detection, created = create_detection_if_missing(
                        db,
                        case_id=case_id,
                        evidence_id=evidence.id,
                        artifact_id=None,
                        rule_id=rule.id if rule else None,
                        rule_set_id=rule_set.id if rule_set else None,
                        engine="yara",
                        source_engine="yara",
                        rule_name=detection_rule_name,
                        rule_title=runnable.title or detection_rule_name,
                        rule_version=runnable.rule_version,
                        rule_author=runnable.author,
                        rule_level=runnable.level or runnable.severity,
                        severity=runnable.severity or "medium",
                        confidence=_severity_to_confidence(runnable.severity or "medium"),
                        event_id=None,
                        event_index=None,
                        opensearch_id=None,
                        target_type="file",
                        target_path=match["path"],
                        matched_at=utc_now().isoformat(),
                        matched_stable_event_id=None,
                        matched_file_hash=match.get("file_sha256"),
                        host_name=(scan_options or {}).get("host"),
                        message=f"YARA match {detection_rule_name}{f' from ruleset {rule_set.name}' if rule_set else ''} on {match['path']}",
                        matched_fields={"file.path": match.get("path"), "file.sha256": match.get("file_sha256")},
                        matched_strings=match.get("matched_strings") or [],
                        condition_summary=f"YARA matched rule {detection_rule_name}",
                        description=runnable.description,
                        false_positives=getattr(runnable, "false_positives", []) or [],
                        references=getattr(runnable, "references", []) or [],
                        tags=list(dict.fromkeys((getattr(runnable, "tags", []) or []) + ["yara"])),
                        mitre=getattr(runnable, "mitre", []) or [],
                        related_event_ids=related_event_ids,
                        related_iocs={
                            "files": [match.get("path")] if match.get("path") else [],
                            "hashes": [match.get("file_sha256")] if match.get("file_sha256") else [],
                            "domains": [],
                            "ips": [],
                            "urls": [],
                            "registry": [],
                        },
                        risk_score=float({"low": 35, "medium": 60, "high": 80, "critical": 95}.get(str((runnable.severity or "medium")).lower(), 60)),
                        dedup_fingerprint=dedup_fingerprint,
                        engine_version="rules_v2",
                        raw={
                            **match,
                            "rule_engine": "yara",
                            "rule_title": runnable.title or detection_rule_name,
                            "rule_level": runnable.level or runnable.severity,
                            "rule_run_id": detection_rule_run_id,
                            "rule_import_run_id": (dict(rule.metadata_json or {}).get("import_run_id") if rule else None),
                            "rule_source_pack": (dict(rule.metadata_json or {}).get("source_pack") if rule else None),
                            "rule_set_id": rule_set.id if rule_set else None,
                            "rule_set_name": rule_set.name if rule_set else None,
                            "match_reason": f"YARA matched {', '.join(matched_rule_names)}",
                            "target_kind": "file",
                            "skipped_by_reason": yara_result.get("skipped_by_reason", {}),
                            "candidate_breakdown": yara_result.get("candidate_breakdown", {}),
                        },
                    )
                    if created:
                        created_count += 1
                    else:
                        duplicates += 1
                hits.extend(yara_result["matches"])
        else:
            sigma_rule_data = None
            sigma_compiled = None
            sigma_metadata = {}
            if rule.engine.value == "sigma":
                sigma_compiled = dict((rule.metadata_json or {}).get("sigma_compilation") or {})
                if sigma_compiled.get("compile_status") != "compiled":
                    sigma_rule_data = parse_sigma_rule(rule.content)[0]
                    sigma_compiled = compile_sigma_rule(sigma_rule_data)
                sigma_metadata = extract_sigma_metadata(sigma_rule_data) if sigma_rule_data else {
                    "title": rule.title or rule.name,
                    "description": rule.description,
                    "author": rule.author,
                    "rule_version": rule.rule_version,
                    "level": rule.level,
                    "tags": list(rule.tags or []),
                    "references": list(rule.references or []),
                    "false_positives": list(rule.false_positives or []),
                }
            sigma_case_profile = None
            sigma_preflight = None
            if rule.engine.value == "sigma":
                sigma_case_profile = (scan_options or {}).get("_sigma_case_profile")
                if not isinstance(sigma_case_profile, dict):
                    sigma_case_profile = _build_sigma_case_profile_for_scope(case_id, evidence_id, scan_options or {})
                sigma_preflight = (scan_options or {}).get("_sigma_preflight")
                if not isinstance(sigma_preflight, dict):
                    sigma_preflight = preflight_compiled_sigma_rule(sigma_compiled or {}, sigma_case_profile, enabled=rule.enabled)
                if str(sigma_preflight.get("status") or "").startswith("skipped_"):
                    warnings.append(f"Sigma rule skipped: {sigma_preflight.get('status')}")
                    if rule_run:
                        _update_rule_run(
                            db,
                            rule_run,
                            status=RuleRunStatus.skipped,
                            finished_at=utc_now().isoformat(),
                            matched=0,
                            created_detections=0,
                            duplicates=0,
                            scanned_events=0,
                            processed_rules=1,
                            current_phase="completed",
                            last_error=None,
                            errors=[],
                            metadata_json={
                                "dry_run": dry_run,
                                "evidence_id": evidence_id,
                                "rule_set_id": rule_set.id if rule_set else None,
                                "scan_options": scan_options or {},
                                "warnings": warnings,
                                "skipped_by_reason": {str(sigma_preflight.get("status")).replace("skipped_", ""): 1},
                                "sigma_case_profile": sigma_case_profile,
                                "sigma_preflight": sigma_preflight,
                                "current_phase": "completed",
                            },
                        )
                    return {
                        "status": "skipped",
                        "matched": 0,
                        "created_detections": 0,
                        "duplicates": 0,
                        "scanned_events": 0,
                        "scanned_files": scanned_files,
                        "skipped_files": skipped_files,
                        "errors": [],
                        "warnings": warnings,
                        "skipped_by_reason": {str(sigma_preflight.get("status")).replace("skipped_", ""): 1},
                    }
            sigma_runtime_options = dict(scan_options or {})
            if sigma_preflight:
                sigma_runtime_options["_sigma_preflight"] = sigma_preflight
            if sigma_case_profile:
                sigma_runtime_options["_sigma_case_profile"] = sigma_case_profile
            if sigma_compiled:
                sigma_runtime_options["_sigma_compiled"] = sigma_compiled
            sigma_run_mode = _resolve_sigma_run_mode(sigma_runtime_options)
            sigma_mode_config = _resolve_sigma_mode_config(sigma_runtime_options, runtime_settings)
            body = _build_sigma_search_body(case_id, evidence_id, rule, sigma_runtime_options, runtime_settings) if rule.engine.value == "sigma" else _event_search_body(case_id, evidence_id, rule)
            if rule.engine.value == "sigma" and sigma_compiled:
                sigma_body = build_sigma_query_from_compiled(sigma_compiled)
                if isinstance(body, dict) and isinstance(sigma_body, dict):
                    body["query"] = sigma_body.get("query")
            query = body.get("query") if isinstance(body, dict) else None
            try:
                query_started = time.perf_counter()
                total_events = int(count_documents(get_events_index(case_id), query).get("count", 0))
                broadness_reason = _sigma_broadness_reason(
                    candidate_count_estimate=total_events,
                    preflight=sigma_preflight,
                    mode_config=sigma_mode_config,
                ) if rule.engine.value == "sigma" else None
                if broadness_reason and rule.engine.value == "sigma":
                    status_name = "skipped_too_broad" if sigma_run_mode == "fast_triage" else "noisy_capped"
                    if sigma_run_mode == "fast_triage":
                        skipped_too_broad_count += 1
                        skipped_by_reason["too_broad"] = int(skipped_by_reason.get("too_broad") or 0) + 1
                        top_noisy_rules.append(
                            {
                                "rule_id": rule.id,
                                "rule_name": rule.name,
                                "candidate_count": total_events,
                                "matches_found": 0,
                                "created_detections": 0,
                                "duplicates": 0,
                                "duration_ms": 0,
                                "capped": False,
                                "skipped": True,
                                "status": "skipped_too_broad",
                                "reason": broadness_reason,
                            }
                        )
                        warning_text = f"Rule {rule.name} was skipped in {sigma_run_mode} mode because it is too broad: {broadness_reason}."
                        if warning_text not in warnings:
                            warnings.append(warning_text)
                        if rule_run:
                            _update_rule_run(
                                db,
                                rule_run,
                                status=RuleRunStatus.completed,
                                finished_at=utc_now().isoformat(),
                                matched=0,
                                created_detections=0,
                                duplicates=0,
                                scanned_events=0,
                                processed_rules=1,
                                current_phase="completed",
                                last_error=None,
                                errors=[],
                                metadata_json={
                                    **(rule_run.metadata_json or {}),
                                    "dry_run": dry_run,
                                    "evidence_id": evidence_id,
                                    "rule_set_id": rule_set.id if rule_set else None,
                                    "scan_options": scan_options or {},
                                    "sigma_run_mode": sigma_run_mode,
                                    "sigma_run_mode_config": sigma_mode_config,
                                    "warnings": warnings,
                                    "skipped_by_reason": skipped_by_reason,
                                    "sigma_case_profile": sigma_case_profile,
                                    "sigma_preflight": sigma_preflight,
                                    "candidate_count_estimate": total_events,
                                    "current_phase": "completed",
                                    "noisy_rules_count": noisy_rules_count,
                                    "capped_rules_count": capped_rules_count,
                                    "skipped_too_broad_count": skipped_too_broad_count,
                                    "matches_capped_count": matches_capped_count,
                                    "detections_capped_count": detections_capped_count,
                                    "top_noisy_rules": top_noisy_rules[:10],
                                    "display_status": "completed_with_warnings",
                                },
                            )
                        return {
                            "status": "skipped",
                            "matched": 0,
                            "created_detections": 0,
                            "duplicates": 0,
                            "scanned_events": 0,
                            "scanned_files": scanned_files,
                            "skipped_files": skipped_files,
                            "errors": [],
                            "warnings": warnings,
                            "skipped_by_reason": skipped_by_reason,
                            "candidate_events_prefiltered": 0,
                            "candidate_count_estimate": total_events,
                            "sigma_run_mode": sigma_run_mode,
                            "skipped_too_broad_count": skipped_too_broad_count,
                            "top_noisy_rules": top_noisy_rules[:10],
                        }
                    sigma_runtime_options["max_events"] = min(
                        max(int(sigma_mode_config.get("max_candidate_events_per_rule") or 0), 1),
                        max(total_events, 1),
                    )
                    body["size"] = max(int(sigma_runtime_options["max_events"]), 1)
                if rule_run:
                    _update_rule_run(
                        db,
                        rule_run,
                        current_phase="counting_events",
                        total_events=total_events,
                        scanned_events=0,
                    )
                result = search_documents(get_events_index(case_id), body)
                query_time_ms_total += int((time.perf_counter() - query_started) * 1000)
            except RequestError as exc:
                if rule.engine.value == "sigma":
                    request_error = str(exc)
                    skip_reason = "unsupported_condition"
                    if "failed to create query" not in request_error.lower():
                        skip_reason = "execution_error"
                    warnings.append(request_error)
                    if rule_run:
                        metadata = rule_run.metadata_json or {}
                        _update_rule_run(
                            db,
                            rule_run,
                            status=RuleRunStatus.completed,
                            finished_at=utc_now().isoformat(),
                            matched=0,
                            created_detections=0,
                            duplicates=0,
                            scanned_events=0,
                            processed_rules=1,
                            current_phase="completed",
                            last_error=None,
                            errors=[],
                            metadata_json={
                                **metadata,
                                "warnings": warnings,
                                "skipped_by_reason": {skip_reason: 1},
                                "sigma_case_profile": sigma_case_profile if rule.engine.value == "sigma" else None,
                                "sigma_preflight": sigma_preflight if rule.engine.value == "sigma" else None,
                                "candidate_events_prefiltered": 0,
                                "current_phase": "completed",
                            },
                        )
                    return {
                        "status": "skipped",
                        "matched": 0,
                        "created_detections": 0,
                        "duplicates": 0,
                        "scanned_events": 0,
                        "scanned_files": scanned_files,
                        "skipped_files": skipped_files,
                        "errors": [],
                        "warnings": warnings,
                        "skipped_by_reason": {skip_reason: 1},
                        "candidate_events_prefiltered": 0,
                    }
                raise
            candidate_hits = result.get("hits", {}).get("hits", [])
            if rule_run:
                _update_rule_run(
                    db,
                    rule_run,
                    current_phase="matching_events",
                    total_events=int((sigma_case_profile or {}).get("total_events") or len(candidate_hits)),
                    scanned_events=int((sigma_case_profile or {}).get("total_events") or len(candidate_hits)),
                )
            hits = []
            if not dry_run:
                max_detections_per_rule = max(
                    int(sigma_mode_config.get("max_detections_per_rule") or 0),
                    0,
                )
                max_matches_per_rule = max(int(sigma_mode_config.get("max_matches_per_rule") or 0), 0)
                noisy_rule_threshold = max(
                    int((scan_options or {}).get("sigma_noisy_rule_threshold") or runtime_settings.get("SIGMA_NOISY_RULE_THRESHOLD") or settings.sigma_noisy_rule_threshold),
                    0,
                )
                detection_write_batch_size = max(int(runtime_settings.get("DETECTION_WRITE_BATCH_SIZE") or 1000), 100)
                duplicate_lookup_batch_size = max(int(runtime_settings.get("DETECTION_DUPLICATE_LOOKUP_BATCH_SIZE") or 2000), 100)
                detection_candidates: list[dict] = []
                rule_capped = False
                rule_marked_noisy = False
                rule_started = time.perf_counter()
                for hit in candidate_hits:
                    if _is_rule_run_cancel_requested(run_id):
                        if rule_run:
                            _update_rule_run(
                                db,
                                rule_run,
                                status=RuleRunStatus.cancelled,
                                finished_at=utc_now().isoformat(),
                                current_phase="cancelled",
                                last_error="Cancelled at worker checkpoint.",
                            )
                        return {
                            "status": "cancelled",
                            "matched": len(hits),
                            "created_detections": created_count,
                            "duplicates": duplicates,
                            "scanned_events": len(candidate_hits),
                            "scanned_files": scanned_files,
                            "skipped_files": skipped_files,
                            "errors": errors,
                            "warnings": warnings,
                        }
                    source = hit["_source"]
                    sigma_eval = {"matched": True, "matched_fields": {}, "condition_summary": None, "data_quality": []}
                    if rule.engine.value == "sigma" and sigma_compiled:
                        sigma_eval = evaluate_compiled_sigma_rule(sigma_compiled, source)
                        if not sigma_eval["matched"]:
                            continue
                    hits.append(hit)
                    if max_matches_per_rule and len(hits) >= max_matches_per_rule:
                        rule_capped = True
                        matches_capped_count += 1
                        break
                    if max_detections_per_rule and len(detection_candidates) >= max_detections_per_rule:
                        rule_capped = True
                        detections_capped_count += 1
                        break
                    detection_payload = _build_sigma_detection_payload(
                        case_id=case_id,
                        rule=rule,
                        rule_run_id=detection_rule_run_id,
                        sigma_metadata=sigma_metadata,
                        sigma_eval=sigma_eval,
                        source=source,
                        hit=hit,
                    )
                    if str((scan_options or {}).get("run_type") or "").lower() == "smoke":
                        detection_payload["dedup_fingerprint"] = _dedup_fingerprint(
                            case_id,
                            rule.id,
                            detection_rule_run_id,
                            source.get("stable_event_id") or source.get("event_fingerprint") or source.get("event_id"),
                            "sigma_smoke",
                        )
                        detection_payload.setdefault("tags", [])
                        if "smoke" not in detection_payload["tags"]:
                            detection_payload["tags"].append("smoke")
                        raw = dict(detection_payload.get("raw") or {})
                        raw.update(
                            {
                                "run_type": "smoke",
                                "smoke": True,
                                "smoke_rule_run_id": detection_rule_run_id,
                                "field_mapping_explanation": {
                                    "expected_logsource": raw.get("expected_logsource") or sigma_metadata.get("logsource") or {},
                                    "sigma_to_normalized_fields": raw.get("sigma_to_normalized_fields") or {},
                                    "actual_event_source": raw.get("actual_event_source") or {},
                                },
                            }
                        )
                        detection_payload["raw"] = raw
                    detection_candidates.append(detection_payload)
                current_rule_matches = len(hits)
                if noisy_rule_threshold and current_rule_matches >= noisy_rule_threshold:
                    noisy_rules_count += 1
                    rule_marked_noisy = True
                if rule_capped or (max_detections_per_rule and len(detection_candidates) >= max_detections_per_rule and len(candidate_hits) >= max_detections_per_rule):
                    capped_rules_count += 1
                    if not rule_marked_noisy:
                        noisy_rules_count += 1
                        rule_marked_noisy = True
                    warning_text = f"Rule {rule.name} produced too many matches in {sigma_run_mode} mode and was capped."
                    if warning_text not in warnings:
                        warnings.append(warning_text)
                if detection_candidates:
                    try:
                        bulk_result = create_detections_bulk_if_missing(
                            db,
                            case_id=case_id,
                            detection_payloads=detection_candidates,
                            duplicate_lookup_batch_size=duplicate_lookup_batch_size,
                            insert_batch_size=detection_write_batch_size,
                        )
                        created_count += int(bulk_result.get("created_count") or 0)
                        duplicates += int(bulk_result.get("duplicate_count") or 0)
                        current_rule_created = int(bulk_result.get("created_count") or 0)
                        current_rule_duplicates = int(bulk_result.get("duplicate_count") or 0)
                        dedupe_time_ms_total += int(bulk_result.get("dedupe_time_ms") or 0)
                        write_time_ms_total += int(bulk_result.get("write_time_ms") or 0)
                        bulk_insert_batches += int(bulk_result.get("bulk_insert_batches") or 0)
                        bulk_duplicate_lookups += int(bulk_result.get("bulk_lookup_count") or 0)
                    except Exception as exc:  # noqa: BLE001
                        db.rollback()
                        error_detail = str(exc).splitlines()[0].strip() or exc.__class__.__name__
                        error_text = f"Detection creation failed for rule {rule.name}: {error_detail}"
                        if error_text not in runtime_errors_local:
                            runtime_errors_local.append(error_text)
                        if error_text not in warnings:
                            warnings.append(error_text)
                if rule_capped:
                    top_noisy_rules.append(
                        {
                            "rule_id": rule.id,
                            "rule_name": rule.name,
                            "level": sigma_metadata.get("level"),
                            "source_pack": (rule.metadata_json or {}).get("source_pack"),
                            "logsource": sigma_metadata.get("logsource") or {},
                            "candidate_count": total_events,
                            "matches_found": current_rule_matches,
                            "created_detections": current_rule_created,
                            "duplicates": current_rule_duplicates,
                            "duration_ms": int((time.perf_counter() - rule_started) * 1000),
                            "detections_capped_at": max_detections_per_rule,
                            "candidate_count_cap": sigma_mode_config.get("max_candidate_events_per_rule"),
                            "broadness_reason": broadness_reason if 'broadness_reason' in locals() else None,
                            "capped": True,
                            "skipped": False,
                            "status": "noisy_capped",
                            "reason": broadness_reason if 'broadness_reason' in locals() else "match/detection cap applied",
                        }
                    )
                if rule_run:
                    _update_rule_run(
                        db,
                        rule_run,
                        current_phase="matching_events",
                        matched=current_rule_matches,
                        created_detections=created_count,
                        duplicates=duplicates,
                        metadata_json={
                            **(rule_run.metadata_json or {}),
                            "current_rule": rule.id,
                            "current_rule_title": rule.title or rule.name,
                            "current_rule_matches": current_rule_matches,
                            "current_rule_created": current_rule_created,
                            "current_rule_duplicates": current_rule_duplicates,
                            "current_rule_duration_ms": int((time.perf_counter() - rule_started) * 1000),
                            "query_time_ms_total": query_time_ms_total,
                            "write_time_ms_total": write_time_ms_total,
                            "dedupe_time_ms_total": dedupe_time_ms_total,
                            "bulk_insert_batches": bulk_insert_batches,
                            "bulk_duplicate_lookups": bulk_duplicate_lookups,
                            "noisy_rules_count": noisy_rules_count,
                            "capped_rules_count": capped_rules_count,
                            "skipped_too_broad_count": skipped_too_broad_count,
                            "matches_capped_count": matches_capped_count,
                            "detections_capped_count": detections_capped_count,
                            "sigma_run_mode": sigma_run_mode,
                            "sigma_run_mode_config": sigma_mode_config,
                            "top_noisy_rules": top_noisy_rules[:10],
                        },
                    )
            else:
                hits = candidate_hits
        if rule_run:
            _update_rule_run(
                db,
                rule_run,
                status=RuleRunStatus.completed if not errors else RuleRunStatus.failed,
                finished_at=utc_now().isoformat(),
                matched=len(hits),
                created_detections=created_count,
                duplicates=duplicates,
                scanned_files=scanned_files,
                skipped_files=skipped_files,
                processed_rules=1,
                scanned_events=len(candidate_hits) if runnable.engine.value != "yara" else int(rule_run.scanned_events or 0),
                current_phase="completed" if not errors else "failed",
                last_error="; ".join(errors)[:2048] if errors else None,
                errors=errors,
                metadata_json={
                    "dry_run": dry_run,
                    "evidence_id": evidence_id,
                    "rule_set_id": rule_set.id if rule_set else None,
                    "scan_options": scan_options or {},
                    "skipped_by_reason": skipped_by_reason,
                    "candidate_breakdown": candidate_breakdown,
                    "warnings": warnings,
                    "rules_evaluated": 1,
                    "events_in_scope": int((sigma_case_profile or {}).get("total_events") or len(candidate_hits)) if rule.engine.value == "sigma" else 0,
                    "candidate_event_evaluations": len(candidate_hits) if runnable.engine.value != "yara" else 0,
                    "matches_found": len(hits),
                    "rules_runtime_error": 1 if runtime_errors_local else 0,
                    "runtime_error_events_count": len(runtime_errors_local),
                    "runtime_errors": runtime_errors_local,
                    "events_scanned": len(candidate_hits) if runnable.engine.value != "yara" else 0,
                    "files_scanned": scanned_files,
                    "current_rule": rule.id if rule else None,
                    "current_rule_title": rule.title if rule else None,
                    "current_rule_matches": current_rule_matches,
                    "current_rule_created": current_rule_created,
                    "current_rule_duplicates": current_rule_duplicates,
                    "query_time_ms_total": query_time_ms_total,
                    "write_time_ms_total": write_time_ms_total,
                    "dedupe_time_ms_total": dedupe_time_ms_total,
                    "bulk_insert_batches": bulk_insert_batches,
                    "bulk_duplicate_lookups": bulk_duplicate_lookups,
                    "noisy_rules_count": noisy_rules_count,
                    "capped_rules_count": capped_rules_count,
                    "skipped_too_broad_count": skipped_too_broad_count,
                    "matches_capped_count": matches_capped_count,
                    "detections_capped_count": detections_capped_count,
                    "top_noisy_rules": top_noisy_rules[:10],
                    "sigma_run_mode": sigma_run_mode if rule.engine.value == "sigma" else None,
                    "sigma_run_mode_config": sigma_mode_config if rule.engine.value == "sigma" else None,
                    "sigma_case_profile": sigma_case_profile if rule.engine.value == "sigma" else None,
                    "sigma_preflight": sigma_preflight if rule.engine.value == "sigma" else None,
                    "sigma_compilation": sigma_compiled if rule.engine.value == "sigma" else None,
                    "candidate_events_prefiltered": len(candidate_hits) if rule.engine.value == "sigma" else None,
                    "candidate_count_estimate": total_events if rule.engine.value == "sigma" else None,
                    "display_status": "completed_with_warnings" if warnings or runtime_errors_local or capped_rules_count else "completed",
                    "current_phase": "completed" if not errors else "failed",
                },
            )
        log_activity(
            db,
            activity_type="rule_run_completed",
            title="Rule run completed",
            message=f"{'Rule pack' if rule_set else 'Rule'} {runnable.name} completed with {len(hits)} hits and {created_count} new detections",
            case_id=case_id,
            evidence_id=evidence_id,
            metadata={"rule_id": rule.id if rule else None, "rule_set_id": rule_set.id if rule_set else None, "hits": len(hits), "created_detections": created_count, "duplicates": duplicates, "dry_run": dry_run, "scanned_files": scanned_files, "skipped_files": skipped_files, "skipped_by_reason": skipped_by_reason, "candidate_breakdown": candidate_breakdown, "warnings": warnings, "errors": errors, "run_id": rule_run.id if rule_run else None},
        )
        return {
            "status": "completed" if not errors else "failed",
            "matched": len(hits),
            "created_detections": created_count,
            "duplicates": duplicates,
            "matches_found": len(hits),
            "rules_runtime_error": 1 if runtime_errors_local else 0,
            "runtime_errors_count": 1 if runtime_errors_local else 0,
            "runtime_error_events_count": len(runtime_errors_local),
            "runtime_errors": runtime_errors_local,
            "scanned_events": len(candidate_hits) if runnable.engine.value != "yara" else 0,
            "scanned_files": scanned_files,
            "skipped_files": skipped_files,
            "errors": errors,
            "warnings": warnings,
            "candidate_events_prefiltered": len(candidate_hits) if runnable.engine.value != "yara" else 0,
            "query_time_ms_total": query_time_ms_total,
            "write_time_ms_total": write_time_ms_total,
            "dedupe_time_ms_total": dedupe_time_ms_total,
            "bulk_insert_batches": bulk_insert_batches,
            "bulk_duplicate_lookups": bulk_duplicate_lookups,
            "current_rule": rule.id if rule else None,
            "current_rule_title": rule.title if rule else None,
            "current_rule_matches": current_rule_matches,
            "current_rule_created": current_rule_created,
            "current_rule_duplicates": current_rule_duplicates,
            "current_rule_duration_ms": int((time.perf_counter() - rule_started) * 1000) if runnable.engine.value == "sigma" and not dry_run else 0,
            "noisy_rules_count": noisy_rules_count,
            "capped_rules_count": capped_rules_count,
            "skipped_too_broad_count": skipped_too_broad_count,
            "matches_capped_count": matches_capped_count,
            "detections_capped_count": detections_capped_count,
            "sigma_run_mode": sigma_run_mode if rule and rule.engine.value == "sigma" else None,
            "sigma_run_mode_config": sigma_mode_config if rule and rule.engine.value == "sigma" else None,
            "candidate_count_estimate": total_events if rule and rule.engine.value == "sigma" else None,
            "top_noisy_rules": top_noisy_rules[:10],
        }
    except Exception as exc:  # noqa: BLE001
        try:
            db.rollback()
        except Exception:  # noqa: BLE001
            pass
        if rule_run:
            _update_rule_run(
                db,
                rule_run,
                status=RuleRunStatus.failed,
                finished_at=utc_now().isoformat(),
                current_phase="failed",
                last_error=str(exc)[:2048],
                errors=[str(exc)],
                metadata_json={"dry_run": dry_run, "evidence_id": evidence_id, "rule_set_id": rule_set.id if rule_set else None, "current_phase": "failed"},
            )
        severity = "warning" if runnable.engine.value == "yara" else "error"
        log_activity(
            db,
            activity_type="rule_run_failed",
            title="Rule run failed",
            message=f"{'Rule pack' if rule_set else 'Rule'} {runnable.name} failed: {exc}",
            severity=severity,
            case_id=case_id,
            evidence_id=evidence_id,
            metadata={"rule_id": rule.id if rule else None, "rule_set_id": rule_set.id if rule_set else None, "run_id": rule_run.id if rule_run else None},
        )
        return {
            "status": "failed",
            "matched": 0,
            "created_detections": 0,
            "duplicates": 0,
            "scanned_events": 0,
            "scanned_files": 0,
            "skipped_files": 0,
            "errors": [str(exc)],
            "warnings": [],
        }
    finally:
        db.close()


def run_rules_on_case(case_id: str, engines: list[str], rule_ids: list[str], enabled_only: bool = True, scan_options: dict | None = None, run_id: str | None = None) -> None:
    db: Session = SessionLocal()
    runtime_settings = load_runtime_settings(db)
    aggregate_run = db.get(RuleRun, run_id) if run_id else None
    if run_id and not aggregate_run:
        logger.warning("Aborting orphaned rules job for missing run_id %s on case %s", run_id, case_id)
        db.close()
        return

    total_matched = 0
    total_created = 0
    total_duplicates = 0
    total_scanned_events = 0
    total_event_evaluations = 0
    total_scanned_files = 0
    total_skipped_files = 0
    total_errors: list[str] = []
    runtime_rule_errors: list[str] = []
    warnings: list[str] = []
    resolved_rule_ids: list[str] = []
    skipped_by_reason: Counter[str] = Counter()
    sigma_rule_preflight: list[dict] = []
    sigma_case_profile: dict | None = None
    total_rules_considered = 0
    total_rules_executed = 0
    total_runtime_errors = 0
    total_runtime_error_events = 0
    total_query_time_ms = 0
    total_dedupe_time_ms = 0
    total_write_time_ms = 0
    total_bulk_insert_batches = 0
    total_bulk_duplicate_lookups = 0
    total_noisy_rules = 0
    total_capped_rules = 0
    total_skipped_too_broad = 0
    total_matches_capped = 0
    total_detections_capped = 0
    top_matched_rules: list[dict] = []
    top_noisy_rules: list[dict] = []
    top_duration_rules: list[dict] = []
    top_duplicate_rules: list[dict] = []
    try:
        if aggregate_run:
            metadata = aggregate_run.metadata_json or {}
            top_skipped_examples = [item for item in sigma_rule_preflight if str(item.get("status") or "").startswith("skipped_")][:10]
            _update_rule_run(
                db,
                aggregate_run,
                status=RuleRunStatus.running,
                started_at=aggregate_run.started_at or utc_now().isoformat(),
                finished_at=None,
                scope=aggregate_run.scope or _infer_scope((scan_options or {}).get("evidence_id"), scan_options),
                total_rules=len(rule_ids) if rule_ids else int(aggregate_run.total_rules or 0),
                processed_rules=0,
                current_phase="loading_rules",
                last_error=None,
                metadata_json={
                    **metadata,
                    "requested_rule_ids": rule_ids,
                    "scan_options": scan_options or {},
                    "current_phase": "loading_rules",
                },
            )
            if aggregate_run.cancel_requested:
                _update_rule_run(
                    db,
                    aggregate_run,
                    status=RuleRunStatus.cancelled,
                    finished_at=utc_now().isoformat(),
                    current_phase="cancelled",
                    last_error="Cancelled before execution.",
                )
                return
        query = db.query(Rule)
        if rule_ids:
            query = query.filter(Rule.id.in_(rule_ids))
        elif engines:
            query = query.filter(Rule.engine.in_(engines))
        if enabled_only:
            query = query.filter(Rule.enabled.is_(True))
        resolved_rules = query.all()
        total_rules_considered = len(resolved_rules)
        resolved_rule_ids = [str(item.id) for item in resolved_rules]
        runnable_rules: list[dict[str, Any]] = []
        if any(item.engine.value == "sigma" for item in resolved_rules):
            sigma_case_profile = _build_sigma_case_profile_for_scope(case_id, (scan_options or {}).get("evidence_id"), scan_options or {})
        for item in resolved_rules:
            if item.engine.value != "sigma":
                runnable_rules.append(
                    {
                        "id": item.id,
                        "name": item.name,
                        "engine": item.engine.value if item.engine else None,
                    }
                )
                continue
            try:
                sigma_compiled = dict((item.metadata_json or {}).get("sigma_compilation") or {})
                if sigma_compiled.get("compile_status") != "compiled":
                    sigma_rules = parse_sigma_rule(item.content)
                    sigma_rule_data = sigma_rules[0]
                    sigma_compiled = compile_sigma_rule(sigma_rule_data)
                preflight = preflight_compiled_sigma_rule(sigma_compiled, sigma_case_profile or {}, enabled=item.enabled)
            except Exception as exc:  # noqa: BLE001
                preflight = {
                    "status": "skipped_parse_error",
                    "reason": str(exc),
                    "logsource": {},
                    "missing_fields": [],
                    "fields": [],
                    "prefilter": {},
                }
            entry = {
                "rule_id": item.id,
                "rule_name": item.name,
                "compile_status": str((item.metadata_json or {}).get("sigma_compilation", {}).get("compile_status") or "compiled"),
                "status": preflight.get("status"),
                "reason": preflight.get("reason"),
                "logsource": preflight.get("logsource") or {},
                "missing_fields": preflight.get("missing_fields") or [],
                "fields": preflight.get("fields") or [],
                "prefilter": preflight.get("prefilter") or {},
            }
            sigma_rule_preflight.append(entry)
            status_name = str(preflight.get("status") or "")
            if status_name.startswith("skipped_"):
                skipped_by_reason[status_name.replace("skipped_", "")] += 1
                continue
            runnable_rules.append(
                {
                    "id": item.id,
                    "name": item.name,
                    "engine": item.engine.value if item.engine else None,
                }
            )
        total_rules_executed = len(runnable_rules)
        if aggregate_run:
            metadata = aggregate_run.metadata_json or {}
            _update_rule_run(
                db,
                aggregate_run,
                total_rules=total_rules_considered,
                current_phase="loading_rules",
                metadata_json={
                    **metadata,
                    "rules_evaluated": total_rules_considered,
                    "resolved_rule_ids": resolved_rule_ids,
                    "total_rules_considered": total_rules_considered,
                    "rules_considered": total_rules_considered,
                    "rules_compiled": int(sum(1 for item in sigma_rule_preflight if str(item.get("compile_status") or "compiled") == "compiled")),
                    "rules_runnable_in_scope": total_rules_executed,
                    "total_rules_runnable": total_rules_executed,
                    "total_rules_executed": 0,
                    "total_rules_skipped": int(sum(skipped_by_reason.values())),
                    "rules_runtime_error": 0,
                    "skipped_by_reason": dict(skipped_by_reason),
                    "sigma_case_profile": sigma_case_profile or {},
                    "sigma_rule_preflight_report": sigma_rule_preflight[:200],
                    "top_skipped_examples": top_skipped_examples,
                    "scan_options": scan_options or {},
                    "current_phase": "loading_rules",
                },
            )
        if not resolved_rule_ids:
            warnings.append("No enabled rules selected.")
            if aggregate_run:
                metadata = aggregate_run.metadata_json or {}
                _update_rule_run(
                    db,
                    aggregate_run,
                    status=RuleRunStatus.completed,
                    finished_at=utc_now().isoformat(),
                    total_rules=0,
                    processed_rules=0,
                    total_events=0,
                    scanned_events=0,
                    current_phase="completed",
                    last_error=None,
                    errors=[],
                    metadata_json={
                        **metadata,
                        "warnings": warnings,
                        "events_scanned": 0,
                        "files_scanned": 0,
                        "current_phase": "completed",
                    },
                )
            return
        if not runnable_rules:
            warnings.append("No compatible rules were runnable in the selected scope.")
            if aggregate_run:
                metadata = aggregate_run.metadata_json or {}
                _update_rule_run(
                    db,
                    aggregate_run,
                    status=RuleRunStatus.completed,
                    finished_at=utc_now().isoformat(),
                    total_rules=total_rules_considered,
                    processed_rules=total_rules_considered,
                    total_events=int((sigma_case_profile or {}).get("total_events") or 0),
                    scanned_events=0,
                    current_phase="completed",
                    last_error=None,
                    errors=[],
                    metadata_json={
                        **metadata,
                        "warnings": warnings,
                        "total_rules_considered": total_rules_considered,
                        "rules_considered": total_rules_considered,
                        "rules_compiled": int(sum(1 for item in sigma_rule_preflight if str(item.get("compile_status") or "compiled") == "compiled")),
                        "rules_runnable_in_scope": 0,
                        "total_rules_runnable": 0,
                        "total_rules_executed": 0,
                        "total_rules_skipped": int(sum(skipped_by_reason.values())),
                        "skipped_by_reason": dict(skipped_by_reason),
                        "sigma_case_profile": sigma_case_profile or {},
                        "sigma_rule_preflight_report": sigma_rule_preflight[:200],
                        "top_skipped_examples": [item for item in sigma_rule_preflight if str(item.get("status") or "").startswith("skipped_")][:10],
                        "events_scanned": 0,
                        "files_scanned": 0,
                        "current_phase": "completed",
                    },
                )
            return
        db.close()
        executed_rules = 0
        for index, rule_record in enumerate(runnable_rules, start=1):
            if _is_rule_run_cancel_requested(run_id):
                db_cancel = SessionLocal()
                try:
                    aggregate_cancel = db_cancel.get(RuleRun, run_id) if run_id else None
                    if aggregate_cancel:
                        _update_rule_run(
                            db_cancel,
                            aggregate_cancel,
                            status=RuleRunStatus.cancelled,
                            finished_at=utc_now().isoformat(),
                            current_phase="cancelled",
                            last_error="Cancelled at worker checkpoint.",
                        )
                finally:
                    db_cancel.close()
                return
            child_scan_options = dict(scan_options or {})
            if run_id:
                child_scan_options["_aggregate_rule_run_id"] = run_id
            if rule_record.get("engine") == "sigma":
                preflight = next((item for item in sigma_rule_preflight if item.get("rule_id") == rule_record.get("id")), None)
                if preflight:
                    child_scan_options["_sigma_preflight"] = dict(preflight)
                if sigma_case_profile:
                    child_scan_options["_sigma_case_profile"] = sigma_case_profile
            child_result = run_rule_on_case(str(rule_record.get("id")), case_id, evidence_id=(scan_options or {}).get("evidence_id"), scan_options=child_scan_options)
            executed_rules += 1
            total_matched += int(child_result.get("matched") or 0)
            total_created += int(child_result.get("created_detections") or 0)
            total_duplicates += int(child_result.get("duplicates") or 0)
            total_event_evaluations += int(child_result.get("scanned_events") or 0)
            total_query_time_ms += int(child_result.get("query_time_ms_total") or 0)
            total_dedupe_time_ms += int(child_result.get("dedupe_time_ms_total") or 0)
            total_write_time_ms += int(child_result.get("write_time_ms_total") or 0)
            total_bulk_insert_batches += int(child_result.get("bulk_insert_batches") or 0)
            total_bulk_duplicate_lookups += int(child_result.get("bulk_duplicate_lookups") or 0)
            total_noisy_rules += int(child_result.get("noisy_rules_count") or 0)
            total_capped_rules += int(child_result.get("capped_rules_count") or 0)
            total_skipped_too_broad += int(child_result.get("skipped_too_broad_count") or 0)
            total_matches_capped += int(child_result.get("matches_capped_count") or 0)
            total_detections_capped += int(child_result.get("detections_capped_count") or 0)
            total_scanned_events = int((sigma_case_profile or {}).get("total_events") or total_scanned_events)
            total_scanned_files += int(child_result.get("scanned_files") or 0)
            total_skipped_files += int(child_result.get("skipped_files") or 0)
            child_errors = [str(item) for item in (child_result.get("errors") or [])]
            child_runtime_errors = [str(item) for item in (child_result.get("runtime_errors") or [])]
            child_runtime_error_count = int(child_result.get("runtime_errors_count") or child_result.get("rules_runtime_error") or 0)
            child_runtime_error_events_count = int(child_result.get("runtime_error_events_count") or 0)
            total_runtime_error_events += child_runtime_error_events_count
            warnings.extend(str(item) for item in (child_result.get("warnings") or []))
            if child_result.get("status") == "failed":
                total_runtime_errors += 1
                runtime_rule_errors.extend(child_errors)
                warnings.extend(child_errors)
            elif child_result.get("status") == "skipped" and child_result.get("warnings"):
                total_runtime_errors += 1
            if child_runtime_errors or child_runtime_error_count:
                total_runtime_errors += max(child_runtime_error_count, 1)
                runtime_rule_errors.extend(child_runtime_errors)
            for key, value in (child_result.get("skipped_by_reason") or {}).items():
                skipped_by_reason[str(key)] += int(value or 0)
            if int(child_result.get("matched") or 0) > 0:
                top_matched_rules.append(
                    {
                        "rule_id": rule_record.get("id"),
                        "rule_name": rule_record.get("name"),
                        "matched": int(child_result.get("matched") or 0),
                        "created_detections": int(child_result.get("created_detections") or 0),
                    }
                )
                top_matched_rules = sorted(top_matched_rules, key=lambda item: int(item.get("matched") or 0), reverse=True)[:10]
            for noisy_rule in child_result.get("top_noisy_rules") or []:
                if len(top_noisy_rules) >= 10:
                    break
                top_noisy_rules.append(dict(noisy_rule))
            child_duration_ms = int(child_result.get("current_rule_duration_ms") or 0)
            if child_duration_ms > 0:
                top_duration_rules.append(
                    {
                        "rule_id": rule_record.get("id"),
                        "rule_name": rule_record.get("name"),
                        "duration_ms": child_duration_ms,
                    }
                )
                top_duration_rules = sorted(top_duration_rules, key=lambda item: int(item.get("duration_ms") or 0), reverse=True)[:10]
            child_duplicates = int(child_result.get("duplicates") or 0)
            if child_duplicates > 0:
                top_duplicate_rules.append(
                    {
                        "rule_id": rule_record.get("id"),
                        "rule_name": rule_record.get("name"),
                        "duplicates": child_duplicates,
                    }
                )
                top_duplicate_rules = sorted(top_duplicate_rules, key=lambda item: int(item.get("duplicates") or 0), reverse=True)[:10]
            if run_id:
                db_progress = SessionLocal()
                aggregate_run_progress = db_progress.get(RuleRun, run_id)
                if aggregate_run_progress:
                    current_phase = "scanning_files" if total_scanned_files > 0 else "matching_events"
                    metadata = aggregate_run_progress.metadata_json or {}
                    _update_rule_run(
                        db_progress,
                        aggregate_run_progress,
                        processed_rules=min(total_rules_considered, int(sum(skipped_by_reason.values())) + executed_rules),
                        scanned_events=total_scanned_events,
                        scanned_files=total_scanned_files,
                        skipped_files=total_skipped_files,
                        created_detections=total_created,
                        duplicates=total_duplicates,
                        matched=total_matched,
                        current_phase=current_phase,
                        metadata_json={
                            **metadata,
                            "warnings": list(dict.fromkeys(warnings)),
                            "current_phase": current_phase,
                            "total_rules_considered": total_rules_considered,
                            "rules_considered": total_rules_considered,
                            "rules_compiled": int(sum(1 for item in sigma_rule_preflight if str(item.get("compile_status") or "compiled") == "compiled")),
                            "rules_runnable_in_scope": total_rules_executed,
                            "total_rules_runnable": total_rules_executed,
                            "total_rules_executed": executed_rules,
                            "total_rules_skipped": int(sum(skipped_by_reason.values())),
                            "rules_runtime_error": total_runtime_errors,
                            "runtime_error_events_count": total_runtime_error_events,
                            "runtime_errors": list(dict.fromkeys(runtime_rule_errors)),
                            "skipped_by_reason": dict(skipped_by_reason),
                            "events_in_scope": int((sigma_case_profile or {}).get("total_events") or 0),
                            "candidate_event_evaluations": total_event_evaluations,
                            "matches_found": total_matched,
                            "candidate_events_prefiltered": total_event_evaluations,
                            "query_time_ms_total": total_query_time_ms,
                            "dedupe_time_ms_total": total_dedupe_time_ms,
                            "write_time_ms_total": total_write_time_ms,
                            "bulk_insert_batches": total_bulk_insert_batches,
                            "bulk_duplicate_lookups": total_bulk_duplicate_lookups,
                            "noisy_rules_count": total_noisy_rules,
                            "capped_rules_count": total_capped_rules,
                            "skipped_too_broad_count": total_skipped_too_broad,
                            "matches_capped_count": total_matches_capped,
                            "detections_capped_count": total_detections_capped,
                            "sigma_run_mode": _resolve_sigma_run_mode(scan_options),
                            "sigma_run_mode_config": _resolve_sigma_mode_config(scan_options, runtime_settings),
                            "top_noisy_rules": top_noisy_rules[:10],
                            "top_duration_rules": top_duration_rules,
                            "top_duplicate_rules": top_duplicate_rules,
                            "sigma_case_profile": sigma_case_profile or {},
                            "top_skipped_examples": [item for item in sigma_rule_preflight if str(item.get("status") or "").startswith("skipped_")][:10],
                            "top_matched_rules": top_matched_rules,
                        },
                    )
                db_progress.close()
        if aggregate_run:
            db = SessionLocal()
            aggregate_run = db.get(RuleRun, run_id)
            if aggregate_run:
                metadata = aggregate_run.metadata_json or {}
                final_status = RuleRunStatus.completed
                display_status = "completed_with_warnings" if warnings or skipped_by_reason or total_runtime_errors or runtime_rule_errors else final_status.value
                _update_rule_run(
                    db,
                    aggregate_run,
                    status=final_status,
                    finished_at=utc_now().isoformat(),
                    matched=total_matched,
                    created_detections=total_created,
                    duplicates=total_duplicates,
                    processed_rules=total_rules_considered,
                    scanned_events=total_scanned_events,
                    scanned_files=total_scanned_files,
                    skipped_files=total_skipped_files,
                    total_events=int((sigma_case_profile or {}).get("total_events") or aggregate_run.total_events or 0),
                    current_phase="completed",
                    last_error="; ".join(runtime_rule_errors)[:2048] if runtime_rule_errors else None,
                    errors=list(dict.fromkeys(runtime_rule_errors)),
                    metadata_json={
                        **metadata,
                        "warnings": list(dict.fromkeys(warnings)),
                        "total_rules_considered": total_rules_considered,
                        "rules_considered": total_rules_considered,
                        "rules_compiled": int(sum(1 for item in sigma_rule_preflight if str(item.get("compile_status") or "compiled") == "compiled")),
                        "rules_runnable_in_scope": total_rules_executed,
                        "total_rules_runnable": total_rules_executed,
                        "total_rules_executed": executed_rules,
                        "total_rules_skipped": int(sum(skipped_by_reason.values())),
                        "rules_runtime_error": total_runtime_errors,
                        "runtime_error_events_count": total_runtime_error_events,
                        "runtime_errors": list(dict.fromkeys(runtime_rule_errors)),
                        "skipped_by_reason": dict(skipped_by_reason),
                        "sigma_case_profile": sigma_case_profile or {},
                        "sigma_rule_preflight_report": sigma_rule_preflight[:200],
                        "top_skipped_examples": [item for item in sigma_rule_preflight if str(item.get("status") or "").startswith("skipped_")][:10],
                        "top_matched_rules": top_matched_rules,
                        "events_in_scope": int((sigma_case_profile or {}).get("total_events") or 0),
                        "candidate_event_evaluations": total_event_evaluations,
                        "candidate_events_prefiltered": total_event_evaluations,
                        "matches_found": total_matched,
                        "events_scanned": total_event_evaluations,
                        "files_scanned": total_scanned_files,
                        "query_time_ms_total": total_query_time_ms,
                        "dedupe_time_ms_total": total_dedupe_time_ms,
                        "write_time_ms_total": total_write_time_ms,
                        "bulk_insert_batches": total_bulk_insert_batches,
                        "bulk_duplicate_lookups": total_bulk_duplicate_lookups,
                        "noisy_rules_count": total_noisy_rules,
                        "capped_rules_count": total_capped_rules,
                        "skipped_too_broad_count": total_skipped_too_broad,
                        "matches_capped_count": total_matches_capped,
                        "detections_capped_count": total_detections_capped,
                        "sigma_run_mode": _resolve_sigma_run_mode(scan_options),
                        "sigma_run_mode_config": _resolve_sigma_mode_config(scan_options, runtime_settings),
                        "top_noisy_rules": top_noisy_rules[:10],
                        "top_duration_rules": top_duration_rules,
                        "top_duplicate_rules": top_duplicate_rules,
                        "display_status": display_status,
                        "current_phase": "completed",
                    },
                )
            db.close()
    except Exception as exc:  # noqa: BLE001
        logger.exception("Rule batch run failed for case %s", case_id)
        db_error = SessionLocal()
        try:
            aggregate_error = db_error.get(RuleRun, run_id) if run_id else None
            if aggregate_error:
                metadata = aggregate_error.metadata_json or {}
                _update_rule_run(
                    db_error,
                    aggregate_error,
                    status=RuleRunStatus.failed,
                    finished_at=utc_now().isoformat(),
                    total_rules=len(resolved_rule_ids) if resolved_rule_ids else int(aggregate_error.total_rules or 0),
                    processed_rules=int(aggregate_error.processed_rules or 0),
                    current_phase="failed",
                    last_error=str(exc)[:2048],
                    errors=[str(exc)],
                    metadata_json={
                        **metadata,
                        "warnings": list(dict.fromkeys(warnings)),
                        "current_phase": "failed",
                    },
                )
        finally:
            db_error.close()
        raise
    finally:
        db.close()


def run_case_semi_auto_analysis(job_run_id: str) -> None:
    db: Session = SessionLocal()
    run = db.get(CaseAnalysisJob, job_run_id)
    if not run:
        db.close()
        return
    if run.cancel_requested or run.status == CaseAnalysisJobStatus.cancelled:
        run.status = CaseAnalysisJobStatus.cancelled
        run.current_phase = "cancelled"
        run.finished_at = run.finished_at or utc_now_naive()
        db.commit()
        db.close()
        return

    started_at = utc_now_naive()
    run.status = CaseAnalysisJobStatus.running
    run.started_at = started_at
    run.finished_at = None
    run.error_message = None
    run.progress_pct = max(run.progress_pct, 1)
    run.current_phase = run.current_phase or "starting"
    run.phases = run.phases or [
        "fetching_events",
        "building_activities",
        "correlating_execution",
        "correlating_browser",
        "correlating_defender",
        "building_timeline",
        "completed",
    ]
    run.metrics_json = {
        **(run.metrics_json or {}),
        "elapsed_seconds": 0,
    }
    db.commit()

    def progress_cb(phase: str, pct: int, extra: dict | None = None) -> None:
        local_db: Session = SessionLocal()
        try:
            local_run = local_db.get(CaseAnalysisJob, job_run_id)
            if not local_run:
                return
            elapsed = max((utc_now_naive() - (local_run.started_at or started_at)).total_seconds(), 0.0)
            estimate = None
            if pct > 0:
                estimate = max((elapsed / pct) * (100 - pct), 0.0)
            metrics = dict(local_run.metrics_json or {})
            metrics.update(extra or {})
            metrics["elapsed_seconds"] = round(elapsed, 2)
            if estimate is not None:
                metrics["estimated_remaining_seconds"] = round(estimate, 2)
            local_run.current_phase = phase
            local_run.progress_pct = max(0, min(100, pct))
            local_run.metrics_json = metrics
            local_db.commit()
        finally:
            local_db.close()

    def cancel_cb() -> bool:
        local_db: Session = SessionLocal()
        try:
            local_run = local_db.get(CaseAnalysisJob, job_run_id)
            return bool(local_run and local_run.cancel_requested)
        finally:
            local_db.close()

    try:
        params = dict(run.parameters_json or {})
        result = build_case_semi_auto_analysis(
            run.case_id,
            time_from=params.get("time_from"),
            time_to=params.get("time_to"),
            progress_cb=progress_cb,
            cancel_cb=cancel_cb,
        )
        fresh = db.get(CaseAnalysisJob, job_run_id)
        if not fresh:
            return
        fresh.status = CaseAnalysisJobStatus.completed
        fresh.progress_pct = 100
        fresh.current_phase = "completed"
        fresh.result_json = result
        fresh.finished_at = utc_now_naive()
        metrics = dict(fresh.metrics_json or {})
        metrics["elapsed_seconds"] = round(max((fresh.finished_at - (fresh.started_at or started_at)).total_seconds(), 0.0), 2)
        metrics["estimated_remaining_seconds"] = 0
        fresh.metrics_json = metrics
        db.commit()
    except SemiAutoAnalysisCancelled:
        fresh = db.get(CaseAnalysisJob, job_run_id)
        if fresh:
            fresh.status = CaseAnalysisJobStatus.cancelled
            fresh.finished_at = utc_now_naive()
            fresh.current_phase = "cancelled"
            db.commit()
    except Exception as exc:  # noqa: BLE001
        logger.exception("Semi-automatic analysis job failed for case %s", run.case_id)
        fresh = db.get(CaseAnalysisJob, job_run_id)
        if fresh:
            fresh.status = CaseAnalysisJobStatus.failed
            fresh.finished_at = utc_now_naive()
            fresh.error_message = str(exc)
            fresh.current_phase = "failed"
            db.commit()
    finally:
        db.close()
