from __future__ import annotations

from datetime import datetime
import json
from typing import Any


HISTORY_KEYS = (
    "artifact_retry_runs",
    "ingest_runs",
    "ingest_benchmark_runs",
    "ingest_plan_snapshots",
)


def _coerce_run_list(metadata: dict | None) -> list[dict]:
    return [dict(item) for item in ((metadata or {}).get("ingest_runs") or []) if isinstance(item, dict)]


def _merge_list_by_key(existing: list[Any], incoming: list[Any], *, key: str) -> list[Any]:
    merged: list[Any] = []
    seen: dict[str, int] = {}
    for item in existing + incoming:
        if not isinstance(item, dict):
            if item not in merged:
                merged.append(item)
            continue
        item_key = str(item.get(key) or "")
        if not item_key:
            payload = json.dumps(item, sort_keys=True, default=str)
            if payload not in seen:
                seen[payload] = len(merged)
                merged.append(dict(item))
            continue
        if item_key in seen:
            merged[seen[item_key]] = {**merged[seen[item_key]], **item}
        else:
            seen[item_key] = len(merged)
            merged.append(dict(item))
    return merged


def merge_evidence_metadata(existing: dict | None, patch: dict | None) -> dict:
    result = dict(existing or {})
    patch_dict = dict(patch or {})
    result.update(patch_dict)
    for key in HISTORY_KEYS:
        existing_value = list((existing or {}).get(key) or [])
        incoming_value = list(patch_dict.get(key) or [])
        if key == "artifact_retry_runs":
            result[key] = _merge_list_by_key(existing_value, incoming_value, key="run_id")
        elif key == "ingest_runs":
            result[key] = _merge_list_by_key(existing_value, incoming_value, key="run_id")
        elif key == "ingest_benchmark_runs":
            result[key] = _merge_list_by_key(existing_value, incoming_value, key="benchmark_id")
        elif key == "ingest_plan_snapshots":
            result[key] = _merge_list_by_key(existing_value, incoming_value, key="phase")
    if "latest_ingest_run_id" not in patch_dict and not result.get("latest_ingest_run_id") and (existing or {}).get("latest_ingest_run_id"):
        result["latest_ingest_run_id"] = (existing or {}).get("latest_ingest_run_id")
    if "current_ingest_run_id" not in patch_dict and not result.get("current_ingest_run_id") and (existing or {}).get("current_ingest_run_id"):
        result["current_ingest_run_id"] = (existing or {}).get("current_ingest_run_id")
    return result


def _sort_runs(runs: list[dict]) -> list[dict]:
    def _sort_key(item: dict) -> tuple[str, str]:
        finished = str(item.get("finished_at") or "")
        started = str(item.get("started_at") or item.get("created_at") or "")
        return (finished or started, str(item.get("run_id") or ""))

    return sorted(runs, key=_sort_key, reverse=True)


def upsert_ingest_run(metadata: dict | None, run_id: str, updates: dict[str, Any]) -> dict:
    next_metadata = dict(metadata or {})
    runs = _coerce_run_list(next_metadata)
    matched = False
    for index, run in enumerate(runs):
        if str(run.get("run_id") or "") == run_id:
            merged = dict(run)
            merged.update(updates)
            runs[index] = merged
            matched = True
            break
    if not matched:
        runs.append({"run_id": run_id, **updates})
    next_metadata["ingest_runs"] = _sort_runs(runs)[0:50]
    next_metadata["latest_ingest_run_id"] = run_id
    return next_metadata


def start_ingest_run(
    metadata: dict | None,
    *,
    run_id: str,
    run_type: str,
    mode: str,
    status: str = "queued",
    selected_by_artifact_type: dict[str, int] | None = None,
    selected_by_parser: dict[str, int] | None = None,
    warnings: list[str] | None = None,
    retry_profile: dict[str, Any] | None = None,
) -> dict:
    created_at = datetime.utcnow().isoformat()
    base_metadata = {
        **dict(metadata or {}),
        "current_ingest_run_id": run_id,
        "error_log": {},
        "current_phase": "queued" if status == "queued" else None,
        "current_action": None,
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
        "tail_last_progress_at": None,
        "tail_records_per_sec": 0,
        "tail_current_artifacts": [],
        "tail_slowest_artifacts": [],
        "tail_elapsed_seconds": 0,
    }
    return upsert_ingest_run(
        base_metadata,
        run_id,
        {
            "run_type": run_type,
            "mode": mode,
            "status": status,
            "phase": "queued" if status == "queued" else None,
            "created_at": created_at,
            "started_at": None,
            "finished_at": None,
            "heartbeat_at": None,
            "elapsed_seconds": None,
            "last_error": None,
            "warnings": list(warnings or []),
            "selected_by_artifact_type": dict(selected_by_artifact_type or {}),
            "selected_by_parser": dict(selected_by_parser or {}),
            "retry_profile": dict(retry_profile or {}),
            "failed_artifacts_count": 0,
        },
    )


def sync_ingest_run_from_metadata(metadata: dict | None, *, run_id: str, ingest_status: str | None = None) -> dict:
    next_metadata = dict(metadata or {})
    runs = _coerce_run_list(next_metadata)
    terminal_statuses = {"completed", "completed_with_errors", "failed", "cancelled"}
    benchmark_snapshot = None
    try:
        from app.services.ingest_benchmarks import get_ingest_benchmark_by_run_id

        benchmark_snapshot = get_ingest_benchmark_by_run_id(next_metadata, run_id)
    except Exception:  # noqa: BLE001
        benchmark_snapshot = None
    parallel_ingest = dict(next_metadata.get("parallel_ingest") or {})
    running_parallel = [
        dict(item)
        for item in (parallel_ingest.get("running_artifacts") or [])
        if isinstance(item, dict) and str(item.get("artifact") or "").strip()
    ]
    current_artifact_override: str | None = None
    artifact_progress_override: str | None = None
    current_artifact_source: str | None = None
    if running_parallel:
        current_artifact_source = "parallel_running_artifacts"
        tail_records_read = int(next_metadata.get("tail_records_read") or 0)
        tail_records_indexed = int(next_metadata.get("tail_records_indexed") or 0)
        if len(running_parallel) == 1:
            active = running_parallel[0]
            current_artifact_override = str(active.get("source_path") or active.get("artifact") or "").strip() or None
            artifact_progress_override = (
                f"{active.get('artifact')} · "
                f"{int(active.get('records_read') or 0)} records read / "
                f"{int(active.get('records_indexed') or 0)} indexed"
            )
        else:
            current_artifact_override = "Multiple artifacts running"
            artifact_progress_override = (
                f"{len(running_parallel)} artifacts active · "
                f"{tail_records_read} records read / {tail_records_indexed} indexed"
            )
    elif next_metadata.get("current_artifact") or next_metadata.get("current_artifact_path"):
        current_artifact_source = "sequential"
    elif parallel_ingest:
        current_artifact_source = "stale_fallback"
    for index, run in enumerate(runs):
        if str(run.get("run_id") or "") != run_id:
            continue
        merged = dict(run)
        raw_status_value = str(ingest_status or merged.get("status") or "running")
        status_value = raw_status_value.split(".")[-1].strip().lower() or "running"
        is_terminal = status_value in terminal_statuses
        phase = str(next_metadata.get("current_phase") or merged.get("phase") or "")
        progress = next_metadata.get("progress_pct")
        fatal_error = ((next_metadata.get("error_log") or {}).get("fatal") if isinstance(next_metadata.get("error_log"), dict) else None)
        benchmark_artifacts_total = (
            benchmark_snapshot.get("selected_total")
            or benchmark_snapshot.get("artifacts_created_for_run")
            or benchmark_snapshot.get("artifacts_total")
            if isinstance(benchmark_snapshot, dict)
            else None
        )
        benchmark_artifacts_done = (
            benchmark_snapshot.get("artifacts_processed_for_run")
            or benchmark_snapshot.get("artifacts_completed")
            if isinstance(benchmark_snapshot, dict)
            else None
        )
        benchmark_artifacts_failed = (
            benchmark_snapshot.get("artifacts_failed_for_run")
            or benchmark_snapshot.get("artifacts_failed")
            if isinstance(benchmark_snapshot, dict)
            else None
        )
        merged.update(
            {
                "status": status_value,
                "phase": phase or merged.get("phase"),
                "progress": progress if isinstance(progress, (int, float)) else merged.get("progress"),
                "current_artifact": None
                if is_terminal
                else (
                    current_artifact_override
                    or next_metadata.get("current_artifact")
                    or next_metadata.get("current_artifact_path")
                    or merged.get("current_artifact")
                ),
                "artifact_progress": None
                if is_terminal
                else (
                    artifact_progress_override
                    or next_metadata.get("current_artifact_progress_label")
                    or merged.get("artifact_progress")
                ),
                "current_artifact_source": None if is_terminal else (current_artifact_source or merged.get("current_artifact_source")),
                "artifacts_total": benchmark_artifacts_total or next_metadata.get("artifacts_total"),
                "artifacts_done": benchmark_artifacts_done or next_metadata.get("artifacts_done") or next_metadata.get("artifacts_processed"),
                "artifacts_failed": benchmark_artifacts_failed or next_metadata.get("artifacts_failed"),
                "records_read": next_metadata.get("current_artifact_records_read") or next_metadata.get("records_processed"),
                "records_indexed": next_metadata.get("current_artifact_records_indexed") or next_metadata.get("events_indexed"),
                "events_indexed": next_metadata.get("events_indexed"),
                "records_per_sec": next_metadata.get("records_per_second"),
                "tail_artifacts_total": next_metadata.get("tail_artifacts_total"),
                "tail_artifacts_running": next_metadata.get("tail_artifacts_running"),
                "tail_artifacts_queued": next_metadata.get("tail_artifacts_queued"),
                "tail_artifacts_completed": next_metadata.get("tail_artifacts_completed"),
                "tail_artifacts_failed": next_metadata.get("tail_artifacts_failed"),
                "tail_records_read": next_metadata.get("tail_records_read"),
                "tail_records_indexed": next_metadata.get("tail_records_indexed"),
                "tail_last_progress_at": next_metadata.get("tail_last_progress_at"),
                "tail_records_per_sec": next_metadata.get("tail_records_per_sec"),
                "tail_current_artifacts": list(next_metadata.get("tail_current_artifacts") or []),
                "tail_slowest_artifacts": list(next_metadata.get("tail_slowest_artifacts") or []),
                "tail_elapsed_seconds": next_metadata.get("tail_elapsed_seconds"),
                "heartbeat_at": next_metadata.get("heartbeat_at") or merged.get("heartbeat_at"),
                "created_at": merged.get("created_at"),
                "started_at": merged.get("started_at") or next_metadata.get("started_at"),
                "elapsed_seconds": next_metadata.get("elapsed_seconds"),
                "last_error": fatal_error or (merged.get("last_error") if status_value in {"completed", "completed_with_errors", "failed", "cancelled"} else None),
                "warnings": list(next_metadata.get("warnings") or merged.get("warnings") or []),
                "selected_by_artifact_type": dict(((next_metadata.get("ingest_plan") or {}).get("selected_by_artifact_type") or merged.get("selected_by_artifact_type") or {})),
                "parsed_by_artifact_type": dict(
                    (next_metadata.get("ingest_performance") or {}).get("parsed_by_artifact_type")
                    or (next_metadata.get("last_successful_ingest_plan") or {}).get("selected_by_artifact_type")
                    or merged.get("parsed_by_artifact_type")
                    or {}
                ),
                "failed_artifacts_count": int(next_metadata.get("artifacts_failed") or merged.get("failed_artifacts_count") or 0),
            }
        )
        runs[index] = merged
        break
    next_metadata["ingest_runs"] = _sort_runs(runs)[0:50]
    return next_metadata


def list_evidence_runs(metadata: dict | None) -> list[dict]:
    next_metadata = dict(metadata or {})
    ingest_runs = _coerce_run_list(next_metadata)
    artifact_retry_runs = [dict(item, run_type="artifact_retry") for item in (next_metadata.get("artifact_retry_runs") or []) if isinstance(item, dict)]
    return _sort_runs(ingest_runs + artifact_retry_runs)


def get_evidence_run(metadata: dict | None, run_id: str) -> dict | None:
    for run in list_evidence_runs(metadata):
        if str(run.get("run_id") or "") == run_id:
            return run
    return None


def get_latest_ingest_run(metadata: dict | None) -> dict | None:
    runs = [run for run in _coerce_run_list(metadata) if str(run.get("run_type") or "").strip().lower() in {"ingest", "reprocess"}]
    if not runs:
        return None
    return _sort_runs(runs)[0]


def mark_opensearch_infrastructure_block(
    metadata: dict | None,
    *,
    reason: str,
    run_id: str | None = None,
    benchmark_id: str | None = None,
    preflight: dict | None = None,
    finished_at: str | None = None,
) -> dict:
    timestamp = str(finished_at or datetime.utcnow().isoformat())
    next_metadata = dict(metadata or {})
    next_metadata["current_ingest_run_id"] = None
    next_metadata["error_log"] = {
        "fatal": reason,
        "fatal_type": "infrastructure_blocked_opensearch",
    }
    if preflight is not None:
        next_metadata["opensearch_preflight"] = dict(preflight)
    if run_id:
        next_metadata = upsert_ingest_run(
            next_metadata,
            run_id,
            {
                "status": "failed",
                "phase": "failed",
                "finished_at": timestamp,
                "last_error": reason,
                "current_artifact": None,
                "artifact_progress": None,
            },
        )
        next_metadata["current_ingest_run_id"] = None
    if benchmark_id:
        from app.services.ingest_benchmarks import upsert_ingest_benchmark

        next_metadata = upsert_ingest_benchmark(
            next_metadata,
            benchmark_id,
            {
                "status": "failed",
                "finished_at": timestamp,
                "run_id": run_id,
                "error": reason,
                "watchdog_status": "infrastructure_blocked",
                "current_action": "opensearch_preflight_blocked",
                "final_recommendation": "OpenSearch is not writable or cannot create indices. Ingest has not started.",
                "bottleneck_report": {
                    "bottleneck": "infrastructure_blocked",
                    "confidence": "high",
                    "reasons": [reason],
                    "recommendations": [
                        "Unblock OpenSearch create-index/write operations before retrying ingest or benchmarks.",
                    ],
                    "dominant_phase": "preflight",
                },
            },
        )
    return next_metadata
