from __future__ import annotations

from datetime import UTC, datetime
import json
from pathlib import Path
from typing import Any
from uuid import uuid4

from redis import Redis
from rq import Queue
from rq.job import Job
from rq.registry import FailedJobRegistry, StartedJobRegistry
from sqlalchemy.orm import Session

from app.core.activity import log_activity
from app.core.config import get_settings
from app.core.manifest import default_manifest, write_manifest
from app.core.storage import evidence_manifest_path
from app.models.evidence import Evidence, IngestStatus
from app.services.evidence_runs import get_evidence_run, merge_evidence_metadata, start_ingest_run, upsert_ingest_run
from app.services.ingest_benchmarks import (
    benchmark_mode_to_reprocess_mode,
    build_parser_breakdown,
    classify_benchmark_bottleneck,
    get_ingest_benchmark,
    upsert_ingest_benchmark,
)
from app.services.problematic_artifacts import build_problematic_artifacts_report
from app.workers.tasks import _reconcile_artifact_states_on_ingest_close, enqueue_ingest


settings = get_settings()
redis_conn = Redis.from_url(settings.redis_url)
ingest_queue = Queue("dfir-ingest", connection=redis_conn)

DEFAULT_AUTOPILOT_POLICY = {
    "autopilot": False,
    "max_attempts": 1,
    "max_wall_time_seconds": 7200,
    "no_progress_timeout_seconds": 600,
    "heartbeat_timeout_seconds": 300,
    "allow_reconcile_orphaned_run": True,
    "allow_cancel_stalled_run": True,
    "allow_retry_benchmark": True,
    "allow_clear_current_ingest_run_id": True,
    "allow_delete_data": False,
    "allow_prune_docker": False,
    "allow_restart_services": False,
}

ACTIVE_RUN_STATUSES = {"queued", "pending", "running", "processing"}
TERMINAL_RUN_STATUSES = {"completed", "completed_with_errors", "failed", "cancelled", "stale"}


def _utcnow_iso() -> str:
    return datetime.now(UTC).isoformat()


def _parse_iso(value: Any) -> datetime | None:
    raw = str(value or "").strip()
    if not raw:
        return None
    try:
        parsed = datetime.fromisoformat(raw.replace("Z", "+00:00"))
    except ValueError:
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=UTC)
    return parsed


def _elapsed_seconds_since(value: Any) -> float | None:
    parsed = _parse_iso(value)
    if parsed is None:
        return None
    return round(max((datetime.now(UTC) - parsed).total_seconds(), 0.0), 2)


def _job_matches_evidence(job: Job | None, evidence_id: str) -> bool:
    if job is None:
        return False
    return (
        job.func_name == "app.workers.tasks.ingest_evidence"
        and tuple(job.args or ()) == (evidence_id,)
    )


def _find_ingest_job(evidence_id: str) -> dict[str, Any]:
    started = StartedJobRegistry(queue=ingest_queue)
    failed = FailedJobRegistry(queue=ingest_queue)
    for job_id in started.get_job_ids():
        job = ingest_queue.fetch_job(job_id)
        if _job_matches_evidence(job, evidence_id):
            return {"exists": True, "status": "started", "job_id": job.id}
    for job_id in ingest_queue.job_ids:
        job = ingest_queue.fetch_job(job_id)
        if _job_matches_evidence(job, evidence_id):
            return {"exists": True, "status": "queued", "job_id": job.id}
    for job_id in failed.get_job_ids():
        job = ingest_queue.fetch_job(job_id)
        if _job_matches_evidence(job, evidence_id):
            return {"exists": True, "status": "failed", "job_id": job.id}
    return {"exists": False, "status": "missing", "job_id": None}


def _coerce_policy(benchmark: dict[str, Any] | None) -> dict[str, Any]:
    options = dict((benchmark or {}).get("benchmark_options") or {})
    policy = {**DEFAULT_AUTOPILOT_POLICY}
    policy.update({key: value for key, value in options.items() if key in policy})
    policy["autopilot"] = bool(options.get("autopilot", policy["autopilot"]))
    policy["max_attempts"] = max(int(options.get("max_attempts") or policy["max_attempts"]), 1)
    policy["max_wall_time_seconds"] = max(int(options.get("max_wall_time_seconds") or policy["max_wall_time_seconds"]), 60)
    policy["no_progress_timeout_seconds"] = max(int(options.get("no_progress_timeout_seconds") or policy["no_progress_timeout_seconds"]), 30)
    policy["heartbeat_timeout_seconds"] = max(int(options.get("heartbeat_timeout_seconds") or policy["heartbeat_timeout_seconds"]), 30)
    return policy


def _append_watchdog_action(benchmark: dict[str, Any], action: dict[str, Any]) -> dict[str, Any]:
    actions = [dict(item) for item in (benchmark.get("watchdog_actions") or []) if isinstance(item, dict)]
    actions.append(action)
    benchmark["watchdog_actions"] = actions[-50:]
    benchmark["last_watchdog_check_at"] = action.get("timestamp")
    benchmark["last_watchdog_action"] = action.get("action")
    return benchmark


def _ensure_attempts(benchmark: dict[str, Any]) -> dict[str, Any]:
    attempts = [dict(item) for item in (benchmark.get("attempts") or []) if isinstance(item, dict)]
    if attempts:
        benchmark["attempts"] = attempts
        benchmark["current_attempt"] = max(int(benchmark.get("current_attempt") or 1), 1)
        return benchmark
    attempts = [
        {
            "attempt_number": 1,
            "run_id": benchmark.get("run_id"),
            "status": benchmark.get("status"),
            "requested_at": benchmark.get("requested_at"),
            "started_at": benchmark.get("started_at"),
            "finished_at": benchmark.get("finished_at"),
            "reason": benchmark.get("error"),
        }
    ]
    benchmark["attempts"] = attempts
    benchmark["current_attempt"] = 1
    return benchmark


def _derive_terminal_watchdog_status(benchmark: dict[str, Any]) -> str:
    current = str(benchmark.get("watchdog_status") or "").strip()
    if current and current not in {"healthy", "idle", "stalled"}:
        return current
    actions = [dict(item) for item in (benchmark.get("watchdog_actions") or []) if isinstance(item, dict)]
    if actions:
        last_action = str(actions[-1].get("action") or "").strip()
        if last_action == "reconcile_orphaned_run":
            return "orphaned_reconciled"
        if last_action == "retry_benchmark_attempt":
            return "retrying"
        if last_action == "stop_after_max_attempts":
            return "stopped"
    return current or "terminal"


def _update_current_attempt(benchmark: dict[str, Any], updates: dict[str, Any]) -> dict[str, Any]:
    benchmark = _ensure_attempts(benchmark)
    current_attempt = max(int(benchmark.get("current_attempt") or 1), 1)
    attempts = [dict(item) for item in benchmark.get("attempts") or []]
    matched = False
    for index, attempt in enumerate(attempts):
        if int(attempt.get("attempt_number") or 0) != current_attempt:
            continue
        attempts[index] = {**attempt, **updates}
        matched = True
        break
    if not matched:
        attempts.append({"attempt_number": current_attempt, **updates})
    benchmark["attempts"] = attempts
    return benchmark


def inspect_ingest_run(evidence: Evidence, run_id: str, *, queue: Queue | None = None) -> dict[str, Any]:
    metadata = dict(evidence.metadata_json or {})
    run = dict(get_evidence_run(metadata, run_id) or {})
    job_info = _find_ingest_job(evidence.id) if queue is None else _find_ingest_job(evidence.id)
    heartbeat_age = _elapsed_seconds_since(run.get("heartbeat_at"))
    return {
        "run_id": run_id,
        "run": run,
        "job": job_info,
        "heartbeat_age_seconds": heartbeat_age,
        "has_active_job": bool(job_info.get("exists") and job_info.get("status") in {"started", "queued"}),
        "queue_depth": ingest_queue.count,
        "current_ingest_run_id": str(metadata.get("current_ingest_run_id") or ""),
        "evidence_status": str(evidence.ingest_status.value),
    }


def inspect_benchmark(db: Session, evidence_id: str, benchmark_id: str) -> dict[str, Any] | None:
    evidence = db.get(Evidence, evidence_id)
    if not evidence:
        return None
    metadata = dict(evidence.metadata_json or {})
    benchmark = dict(get_ingest_benchmark(metadata, benchmark_id) or {})
    if not benchmark:
        return None
    benchmark = _ensure_attempts(benchmark)
    run_id = str(benchmark.get("run_id") or "")
    run = dict(get_evidence_run(metadata, run_id) or {}) if run_id else {}
    policy = _coerce_policy(benchmark)
    heartbeat_age = _elapsed_seconds_since(run.get("heartbeat_at"))
    progress_age = _elapsed_seconds_since(benchmark.get("last_progress_at"))
    started_at = _parse_iso(run.get("started_at") or benchmark.get("started_at") or benchmark.get("requested_at"))
    wall_time_seconds = round(max((datetime.now(UTC) - started_at).total_seconds(), 0.0), 2) if started_at else None
    configured_max_duration = int(((benchmark.get("benchmark_options") or {}).get("max_duration_seconds") or 0) or 0)
    max_allowed_seconds = configured_max_duration if configured_max_duration > 0 else int(policy["max_wall_time_seconds"])
    job = _find_ingest_job(evidence.id)
    orphaned = (
        str(benchmark.get("status") or "") in {"queued", "running"}
        and run_id
        and heartbeat_age is not None
        and heartbeat_age >= float(policy["heartbeat_timeout_seconds"])
        and not bool(job.get("exists"))
    )
    stalled = (
        str(benchmark.get("status") or "") in {"queued", "running"}
        and progress_age is not None
        and progress_age >= float(policy["no_progress_timeout_seconds"])
    )
    exceeded_wall_time = (
        str(benchmark.get("status") or "") in {"queued", "running"}
        and wall_time_seconds is not None
        and wall_time_seconds >= float(max_allowed_seconds)
    )
    attempts = [dict(item) for item in benchmark.get("attempts") or []]
    return {
        "evidence": evidence,
        "metadata": metadata,
        "benchmark": benchmark,
        "run": run,
        "policy": policy,
        "job": job,
        "heartbeat_age_seconds": heartbeat_age,
        "progress_age_seconds": progress_age,
        "wall_time_seconds": wall_time_seconds,
        "max_allowed_seconds": max_allowed_seconds,
        "orphaned": orphaned,
        "stalled": stalled,
        "exceeded_wall_time": exceeded_wall_time,
        "attempts": attempts,
        "current_attempt": max(int(benchmark.get("current_attempt") or 1), 1),
        "attempt_count": len(attempts) or 1,
    }


def _build_watchdog_action(
    *,
    action: str,
    benchmark_id: str,
    run_id: str,
    reason: str,
    before_state: dict[str, Any],
    after_state: dict[str, Any],
) -> dict[str, Any]:
    return {
        "timestamp": _utcnow_iso(),
        "action": action,
        "benchmark_id": benchmark_id,
        "run_id": run_id,
        "reason": reason,
        "before_state": before_state,
        "after_state": after_state,
    }


def _benchmark_before_state(inspection: dict[str, Any]) -> dict[str, Any]:
    benchmark = inspection["benchmark"]
    run = inspection["run"]
    return {
        "benchmark_status": benchmark.get("status"),
        "run_status": run.get("status"),
        "run_phase": run.get("phase"),
        "heartbeat_at": run.get("heartbeat_at"),
        "current_ingest_run_id": inspection["metadata"].get("current_ingest_run_id"),
        "job": inspection["job"],
    }


def _queue_benchmark_retry(db: Session, inspection: dict[str, Any], *, reason: str) -> dict[str, Any]:
    evidence: Evidence = inspection["evidence"]
    metadata = dict(evidence.metadata_json or {})
    benchmark = dict(inspection["benchmark"])
    policy = inspection["policy"]
    current_attempt = int(inspection["current_attempt"] or 1)
    new_attempt = current_attempt + 1
    new_run_id = f"ingest-{uuid4()}"
    benchmark_mode = str(benchmark.get("mode") or "reprocess_previous_selection")
    reprocess_mode = benchmark_mode_to_reprocess_mode(benchmark_mode)
    requested_plan = dict(metadata.get("requested_ingest_plan") or metadata.get("ingest_plan") or {})
    selected_candidate_ids = [
        str(item.get("id") or "")
        for item in (requested_plan.get("selected_candidates") or [])
        if isinstance(item, dict) and str(item.get("id") or "").strip()
    ]
    benchmark_request = {
        "benchmark_id": benchmark["benchmark_id"],
        "run_id": new_run_id,
        "mode": benchmark_mode,
        "profile": benchmark.get("profile"),
        "label": benchmark.get("label"),
        "notes": benchmark.get("notes"),
        "requested_at": _utcnow_iso(),
        "stop_after_overlap_observed": bool((benchmark.get("benchmark_options") or {}).get("stop_after_overlap_observed")),
        "max_duration_seconds": int((benchmark.get("benchmark_options") or {}).get("max_duration_seconds") or 3600),
        "skip_detections": bool((benchmark.get("benchmark_options") or {}).get("skip_detections")),
        "skip_rules": bool((benchmark.get("benchmark_options") or {}).get("skip_rules", True)),
        "autopilot": bool(policy.get("autopilot")),
        "max_attempts": int(policy.get("max_attempts") or 1),
        "max_wall_time_seconds": int(policy.get("max_wall_time_seconds") or 7200),
        "no_progress_timeout_seconds": int(policy.get("no_progress_timeout_seconds") or 600),
        "heartbeat_timeout_seconds": int(policy.get("heartbeat_timeout_seconds") or 300),
        "allow_reconcile_orphaned_run": bool(policy.get("allow_reconcile_orphaned_run")),
        "allow_cancel_stalled_run": bool(policy.get("allow_cancel_stalled_run")),
        "allow_retry_benchmark": bool(policy.get("allow_retry_benchmark")),
        "allow_clear_current_ingest_run_id": bool(policy.get("allow_clear_current_ingest_run_id")),
    }
    skip_detection_cleanup = bool(benchmark_request["skip_detections"])
    metadata["reprocess_request"] = {
        "run_id": new_run_id,
        "mode": reprocess_mode,
        "selected_candidate_ids": selected_candidate_ids,
        "requested_at": _utcnow_iso(),
    }
    metadata["benchmark_request"] = benchmark_request
    metadata["reprocess_cleanup_pending"] = {
        "delete_events": True,
        "stale_detection_statuses": [] if skip_detection_cleanup else ["new", "open", "stale"],
        "detections_cleanup_skipped": bool(skip_detection_cleanup),
        "detection_cleanup_reason": "benchmark_skip_detections" if skip_detection_cleanup else None,
        "delete_artifacts": True,
        "reset_extracted_dir": True,
        "reset_staging_dir": bool(reprocess_mode == "full_rediscovery"),
        "preserve_staging": bool(reprocess_mode != "full_rediscovery"),
        "requested_at": _utcnow_iso(),
    }
    if not (benchmark_request["skip_detections"] or benchmark_request["skip_rules"]):
        metadata["reconciliation_baseline_pending"] = {
            "requested_at": _utcnow_iso(),
            "preserve_analyst_state": True,
        }
    else:
        metadata.pop("reconciliation_baseline_pending", None)
    metadata = start_ingest_run(
        metadata,
        run_id=new_run_id,
        run_type="reprocess",
        mode=reprocess_mode,
        status="queued",
        selected_by_artifact_type=dict(requested_plan.get("selected_by_artifact_type") or {}),
        selected_by_parser=dict(requested_plan.get("selected_by_parser") or {}),
    )
    benchmark = _ensure_attempts(benchmark)
    attempts = [dict(item) for item in benchmark.get("attempts") or []]
    attempts.append(
        {
            "attempt_number": new_attempt,
            "run_id": new_run_id,
            "status": "queued",
            "requested_at": _utcnow_iso(),
            "retried_from_run_id": inspection["run"].get("run_id"),
            "reason": reason,
        }
    )
    benchmark.update(
        {
            "run_id": new_run_id,
            "status": "queued",
            "started_at": None,
            "finished_at": None,
            "phase": "queued",
            "current_action": "watchdog_retry_queued",
            "current_phase_stalled": False,
            "stalled_phase_warning": None,
            "last_progress_at": _utcnow_iso(),
            "last_progress_seconds_ago": 0.0,
            "current_attempt": new_attempt,
            "attempts": attempts,
            "watchdog_status": "retrying",
            "final_recommendation": f"Retrying benchmark attempt {new_attempt}/{policy['max_attempts']}.",
            "total_duration_seconds": None,
            "records_read": None,
            "records_indexed": None,
            "events_indexed": None,
            "artifacts_total": None,
            "artifacts_completed": None,
            "artifacts_failed": None,
            "artifacts_created_for_run": None,
            "artifacts_processed_for_run": None,
            "artifacts_failed_for_run": None,
            "problematic_count": None,
            "records_per_sec": None,
            "events_per_sec": None,
            "artifacts_per_sec": None,
            "metadata_opensearch_delta": None,
            "phase_timings": [],
            "resource_samples": [],
            "by_parser": {},
            "bottleneck_report": {},
        }
    )
    action = _build_watchdog_action(
        action="retry_benchmark_attempt",
        benchmark_id=str(benchmark["benchmark_id"]),
        run_id=new_run_id,
        reason=reason,
        before_state=_benchmark_before_state(inspection),
        after_state={"benchmark_status": "queued", "run_status": "queued", "attempt_number": new_attempt},
    )
    _append_watchdog_action(benchmark, action)
    metadata = upsert_ingest_benchmark(metadata, str(benchmark["benchmark_id"]), benchmark)
    evidence.ingest_status = IngestStatus.pending
    evidence.error_log = {}
    evidence.processed_at = None
    evidence.metadata_json = merge_evidence_metadata(evidence.metadata_json or {}, metadata)
    db.commit()
    db.refresh(evidence)
    enqueue_ingest(evidence.id)
    log_activity(
        db,
        activity_type="benchmark_watchdog_retry",
        title="Benchmark watchdog retried ingest",
        message=f"Autopilot queued attempt {new_attempt}/{policy['max_attempts']} for {evidence.original_filename}",
        case_id=evidence.case_id,
        evidence_id=evidence.id,
        metadata=action,
    )
    return benchmark


def reconcile_orphaned_ingest(
    db: Session,
    *,
    evidence: Evidence,
    benchmark_id: str,
    reason: str,
    watchdog_status: str = "orphaned_reconciled",
    action_name: str = "reconcile_orphaned_run",
    final_recommendation: str = "The benchmark run became orphaned and was automatically reconciled.",
    current_action: str = "watchdog_orphaned_reconciled",
    fatal_type: str = "watchdog_orphaned",
) -> dict[str, Any]:
    metadata = dict(evidence.metadata_json or {})
    benchmark = dict(get_ingest_benchmark(metadata, benchmark_id) or {})
    if not benchmark:
        return {}
    run_id = str(benchmark.get("run_id") or "")
    run = dict(get_evidence_run(metadata, run_id) or {})
    manifest_path = evidence_manifest_path(evidence.case_id, evidence.id)
    manifest = default_manifest(evidence)
    if manifest_path.exists():
        try:
            manifest = json.loads(Path(manifest_path).read_text(encoding="utf-8"))
        except Exception:  # noqa: BLE001
            manifest = default_manifest(evidence)
    reconciliation = _reconcile_artifact_states_on_ingest_close(
        db,
        evidence=evidence,
        manifest=manifest,
        run_id=run_id,
        terminal_status="cancelled",
        terminal_phase="cancelled",
        terminal_error=reason,
        timeout_seconds=None,
    )
    completed_count = int(reconciliation.get("completed_count") or 0)
    failed_count = int(reconciliation.get("failed_count") or 0)
    records_read = int((run.get("records_read") or benchmark.get("records_read") or 0) or 0)
    events_indexed = int((run.get("events_indexed") or benchmark.get("events_indexed") or benchmark.get("records_indexed") or 0) or 0)
    selected_total = int(benchmark.get("selected_total") or run.get("artifacts_total") or 0)
    finished_at = _utcnow_iso()
    started_at = _parse_iso(run.get("started_at") or benchmark.get("started_at"))
    elapsed_seconds = round(max((datetime.now(UTC) - started_at).total_seconds(), 0.0), 2) if started_at else None
    report = build_problematic_artifacts_report(evidence, manifest)
    parser_breakdown = build_parser_breakdown(manifest, report)
    artifacts_created_for_run = int(sum(int((row or {}).get("artifacts") or 0) for row in parser_breakdown.values()) or 0)
    benchmark = _ensure_attempts(benchmark)
    benchmark = _update_current_attempt(
        benchmark,
        {
            "status": "cancelled",
            "finished_at": finished_at,
            "reason": reason,
        },
    )
    before_state = {
        "benchmark_status": benchmark.get("status"),
        "run_status": run.get("status"),
        "current_ingest_run_id": metadata.get("current_ingest_run_id"),
    }
    benchmark.update(
        {
            "status": "cancelled",
            "finished_at": finished_at,
            "total_duration_seconds": elapsed_seconds,
            "records_read": records_read,
            "records_indexed": events_indexed,
            "events_indexed": events_indexed,
            "artifacts_total": selected_total,
            "artifacts_completed": completed_count,
            "artifacts_failed": failed_count,
            "artifacts_created_for_run": artifacts_created_for_run,
            "artifacts_processed_for_run": completed_count + failed_count,
            "artifacts_failed_for_run": failed_count,
            "problematic_count": int((report.get("summary") or {}).get("problematic_count") or 0),
            "records_per_sec": round(records_read / max(elapsed_seconds or 0.001, 0.001), 2) if records_read else 0,
            "events_per_sec": round(events_indexed / max(elapsed_seconds or 0.001, 0.001), 2) if events_indexed else 0,
            "artifacts_per_sec": round((completed_count + failed_count) / max(elapsed_seconds or 0.001, 0.001), 2) if completed_count + failed_count else 0,
            "metadata_opensearch_delta": 0,
            "by_parser": parser_breakdown,
            "watchdog_status": watchdog_status,
            "final_recommendation": final_recommendation,
            "stale_data_error_seen": False,
            "unique_violation_seen": False,
            "timeout_count": int(benchmark.get("timeout_count") or 0),
            "last_progress_at": finished_at,
            "current_phase_stalled": False,
            "stalled_phase_warning": None,
            "current_action": current_action,
        }
    )
    benchmark["bottleneck_report"] = classify_benchmark_bottleneck(benchmark)
    action = _build_watchdog_action(
        action=action_name,
        benchmark_id=benchmark_id,
        run_id=run_id,
        reason=reason,
        before_state=before_state,
        after_state={
            "benchmark_status": "cancelled",
            "run_status": "cancelled",
            "completed_count": completed_count,
            "failed_count": failed_count,
        },
    )
    _append_watchdog_action(benchmark, action)
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
    metadata["tail_last_progress_at"] = finished_at
    metadata["tail_records_per_sec"] = 0
    metadata["tail_current_artifacts"] = []
    metadata["tail_slowest_artifacts"] = []
    metadata["tail_elapsed_seconds"] = elapsed_seconds
    metadata["current_phase"] = "cancelled"
    metadata["current_action"] = current_action
    metadata["current_ingest_run_id"] = None
    metadata["error_log"] = {"fatal": reason, "fatal_type": fatal_type}
    metadata["problematic_artifacts_summary"] = report.get("summary") or {}
    metadata = upsert_ingest_run(
        metadata,
        run_id,
        {
            "status": "cancelled",
            "phase": "cancelled",
            "finished_at": finished_at,
            "elapsed_seconds": elapsed_seconds,
            "last_error": reason,
            "current_artifact": None,
            "artifact_progress": None,
            "artifacts_total": selected_total,
            "artifacts_done": completed_count,
            "artifacts_failed": failed_count,
            "failed_artifacts_count": failed_count,
            "records_read": records_read,
            "records_indexed": events_indexed,
            "events_indexed": events_indexed,
            "records_per_sec": round(records_read / max(elapsed_seconds or 0.001, 0.001), 2) if records_read else 0,
            "heartbeat_at": finished_at,
        },
    )
    metadata = upsert_ingest_benchmark(metadata, benchmark_id, benchmark)
    evidence.ingest_status = IngestStatus.completed_with_errors if completed_count > 0 else IngestStatus.failed
    evidence.metadata_json = merge_evidence_metadata(evidence.metadata_json or {}, metadata)
    evidence.error_log = {"fatal": reason, "fatal_type": fatal_type}
    evidence.processed_at = datetime.now(UTC).replace(tzinfo=None)
    write_manifest(manifest_path, manifest)
    db.commit()
    db.refresh(evidence)
    log_activity(
        db,
        activity_type="benchmark_watchdog_reconciled",
        title="Benchmark watchdog reconciled orphaned ingest",
        message=f"Autopilot reconciled orphaned run {run_id} for {evidence.original_filename}",
        case_id=evidence.case_id,
        evidence_id=evidence.id,
        metadata=action,
    )
    return benchmark


def maybe_retry_benchmark(db: Session, inspection: dict[str, Any], *, reason: str) -> dict[str, Any] | None:
    policy = inspection["policy"]
    if not bool(policy.get("allow_retry_benchmark")):
        return None
    if int(inspection["attempt_count"] or 1) >= int(policy["max_attempts"]):
        evidence: Evidence = inspection["evidence"]
        metadata = dict(evidence.metadata_json or {})
        benchmark = dict(inspection["benchmark"])
        benchmark["status"] = "failed"
        benchmark["watchdog_status"] = "stopped"
        benchmark["final_recommendation"] = "Autopilot stopped after max_attempts."
        benchmark = _update_current_attempt(
            benchmark,
            {
                "status": "cancelled",
                "finished_at": _utcnow_iso(),
                "reason": reason,
            },
        )
        action = _build_watchdog_action(
            action="stop_after_max_attempts",
            benchmark_id=str(benchmark["benchmark_id"]),
            run_id=str(benchmark.get("run_id") or ""),
            reason="Autopilot stopped after max_attempts.",
            before_state=_benchmark_before_state(inspection),
            after_state={"benchmark_status": "failed", "attempt_count": inspection["attempt_count"]},
        )
        _append_watchdog_action(benchmark, action)
        metadata = upsert_ingest_benchmark(metadata, str(benchmark["benchmark_id"]), benchmark)
        evidence.metadata_json = merge_evidence_metadata(evidence.metadata_json or {}, metadata)
        db.commit()
        return benchmark
    return _queue_benchmark_retry(db, inspection, reason=reason)


def generate_watchdog_report(benchmark: dict[str, Any] | None) -> dict[str, Any]:
    benchmark = dict(benchmark or {})
    return {
        "benchmark_id": benchmark.get("benchmark_id"),
        "run_id": benchmark.get("run_id"),
        "watchdog_status": benchmark.get("watchdog_status"),
        "last_watchdog_check_at": benchmark.get("last_watchdog_check_at"),
        "autopilot_enabled": bool(benchmark.get("autopilot_enabled")),
        "current_attempt": benchmark.get("current_attempt"),
        "attempts": benchmark.get("attempts") or [],
        "actions": benchmark.get("watchdog_actions") or [],
        "final_recommendation": benchmark.get("final_recommendation"),
    }


def run_benchmark_watchdog(db: Session, evidence_id: str, benchmark_id: str) -> dict[str, Any] | None:
    inspection = inspect_benchmark(db, evidence_id, benchmark_id)
    if not inspection:
        return None
    benchmark = dict(inspection["benchmark"])
    if not bool(inspection["policy"].get("autopilot")):
        benchmark["watchdog_status"] = "disabled"
        benchmark["last_watchdog_check_at"] = _utcnow_iso()
        evidence: Evidence = inspection["evidence"]
        metadata = upsert_ingest_benchmark(dict(evidence.metadata_json or {}), benchmark_id, benchmark)
        evidence.metadata_json = merge_evidence_metadata(evidence.metadata_json or {}, metadata)
        db.commit()
        return benchmark

    if str(benchmark.get("status") or "") in TERMINAL_RUN_STATUSES:
        benchmark["last_watchdog_check_at"] = _utcnow_iso()
        benchmark["watchdog_status"] = _derive_terminal_watchdog_status(benchmark)
        evidence: Evidence = inspection["evidence"]
        metadata = upsert_ingest_benchmark(dict(evidence.metadata_json or {}), benchmark_id, benchmark)
        evidence.metadata_json = merge_evidence_metadata(evidence.metadata_json or {}, metadata)
        db.commit()
        return benchmark

    reason = "Auto-reconciled by benchmark watchdog: run had no heartbeat and no active RQ job."
    if inspection["exceeded_wall_time"] and bool(inspection["policy"].get("allow_cancel_stalled_run")):
        timeout_reason = (
            f"Auto-cancelled by benchmark watchdog: benchmark exceeded configured max duration "
            f"({int(inspection['max_allowed_seconds'])}s) without reaching a terminal state."
        )
        return reconcile_orphaned_ingest(
            db,
            evidence=inspection["evidence"],
            benchmark_id=benchmark_id,
            reason=timeout_reason,
            watchdog_status="timed_out_reconciled",
            action_name="cancel_stalled_run",
            final_recommendation="The benchmark exceeded its configured max duration and was automatically reconciled.",
            current_action="watchdog_timeout_reconciled",
            fatal_type="watchdog_timeout",
        )

    if inspection["orphaned"] and bool(inspection["policy"].get("allow_reconcile_orphaned_run")):
        benchmark = reconcile_orphaned_ingest(db, evidence=inspection["evidence"], benchmark_id=benchmark_id, reason=reason)
        if benchmark and bool(inspection["policy"].get("allow_retry_benchmark")):
            refreshed = inspect_benchmark(db, evidence_id, benchmark_id)
            if refreshed:
                benchmark = maybe_retry_benchmark(db, refreshed, reason=reason) or dict(get_ingest_benchmark(dict(refreshed["evidence"].metadata_json or {}), benchmark_id) or {})
        return benchmark

    evidence: Evidence = inspection["evidence"]
    metadata = dict(evidence.metadata_json or {})
    benchmark["watchdog_status"] = "stalled" if inspection["stalled"] else "healthy"
    benchmark["last_watchdog_check_at"] = _utcnow_iso()
    benchmark["final_recommendation"] = (
        "The benchmark appears stalled and will be reconciled automatically if the run loses heartbeat."
        if inspection["stalled"]
        else benchmark.get("final_recommendation")
    )
    metadata = upsert_ingest_benchmark(metadata, benchmark_id, benchmark)
    evidence.metadata_json = merge_evidence_metadata(evidence.metadata_json or {}, metadata)
    db.commit()
    return benchmark
