from __future__ import annotations

from datetime import UTC, datetime
from statistics import quantiles
from typing import Any


BENCHMARK_HISTORY_KEY = "ingest_benchmark_runs"


def _coerce_benchmark_list(metadata: dict | None) -> list[dict]:
    return [dict(item) for item in ((metadata or {}).get(BENCHMARK_HISTORY_KEY) or []) if isinstance(item, dict)]


def _sort_benchmarks(items: list[dict]) -> list[dict]:
    def _sort_key(item: dict) -> tuple[str, str]:
        finished = str(item.get("finished_at") or "")
        started = str(item.get("started_at") or item.get("requested_at") or item.get("created_at") or "")
        return (finished or started, str(item.get("benchmark_id") or ""))

    return sorted(items, key=_sort_key, reverse=True)


def _parse_iso_datetime(value: Any) -> datetime | None:
    raw = str(value or "").strip()
    if not raw:
        return None
    try:
        return datetime.fromisoformat(raw.replace("Z", "+00:00"))
    except ValueError:
        return None


def _decorate_runtime_benchmark(item: dict[str, Any]) -> dict[str, Any]:
    benchmark = dict(item)
    current_phase = ""
    for phase in reversed(list(benchmark.get("phase_timings") or [])):
        if isinstance(phase, dict) and not phase.get("finished_at"):
            current_phase = str(phase.get("phase") or "")
            break
    if current_phase:
        benchmark["phase"] = current_phase
    status = str(benchmark.get("status") or "").strip().lower()
    if status not in {"running", "queued"}:
        return benchmark
    last_progress_at = _parse_iso_datetime(benchmark.get("last_progress_at")) or _parse_iso_datetime(benchmark.get("started_at")) or _parse_iso_datetime(benchmark.get("requested_at"))
    if last_progress_at is None:
        return benchmark
    now = datetime.now(UTC)
    if last_progress_at.tzinfo is None:
        last_progress_at = last_progress_at.replace(tzinfo=UTC)
    stalled_seconds = round(max((now - last_progress_at).total_seconds(), 0.0), 2)
    stalled_threshold_seconds = max(int(benchmark.get("stalled_threshold_seconds") or 30), 5)
    benchmark["last_progress_seconds_ago"] = stalled_seconds
    if bool(benchmark.get("current_phase_stalled")) or stalled_seconds >= stalled_threshold_seconds:
        if not current_phase:
            current_phase = str(benchmark.get("current_action") or benchmark.get("status") or "running")
        benchmark["current_phase_stalled"] = True
        benchmark["stalled_phase_warning"] = (
            benchmark.get("stalled_phase_warning")
            or f"No progress observed for {stalled_seconds}s while benchmark remained in {current_phase}."
        )
    return benchmark


def list_ingest_benchmarks(metadata: dict | None) -> list[dict]:
    return [_decorate_runtime_benchmark(item) for item in _sort_benchmarks(_coerce_benchmark_list(metadata))]


def get_ingest_benchmark(metadata: dict | None, benchmark_id: str) -> dict | None:
    benchmark_id = str(benchmark_id or "")
    for item in list_ingest_benchmarks(metadata):
        if str(item.get("benchmark_id") or "") == benchmark_id:
            return _decorate_runtime_benchmark(item)
    return None


def get_ingest_benchmark_by_run_id(metadata: dict | None, run_id: str) -> dict | None:
    normalized = str(run_id or "")
    if not normalized:
        return None
    for item in list_ingest_benchmarks(metadata):
        if str(item.get("run_id") or "") == normalized:
            return _decorate_runtime_benchmark(item)
    return None


def upsert_ingest_benchmark(metadata: dict | None, benchmark_id: str, updates: dict[str, Any]) -> dict:
    next_metadata = dict(metadata or {})
    items = _coerce_benchmark_list(next_metadata)
    matched = False
    for index, item in enumerate(items):
        if str(item.get("benchmark_id") or "") == str(benchmark_id):
            merged = dict(item)
            merged.update(updates)
            items[index] = merged
            matched = True
            break
    if not matched:
        items.append({"benchmark_id": benchmark_id, **updates})
    next_metadata[BENCHMARK_HISTORY_KEY] = _sort_benchmarks(items)[0:50]
    return next_metadata


def create_ingest_benchmark(
    metadata: dict | None,
    *,
    benchmark_id: str,
    evidence_id: str,
    case_id: str,
    run_id: str,
    mode: str,
    profile: str,
    label: str | None = None,
    notes: str | None = None,
    status: str = "queued",
    benchmark_options: dict[str, Any] | None = None,
) -> dict:
    requested_at = datetime.now(UTC).isoformat()
    options = dict(benchmark_options or {})
    autopilot_enabled = bool(options.get("autopilot"))
    return upsert_ingest_benchmark(
        metadata,
        benchmark_id,
        {
            "benchmark_id": benchmark_id,
            "evidence_id": evidence_id,
            "case_id": case_id,
            "run_id": run_id,
            "requested_at": requested_at,
            "started_at": None,
            "finished_at": None,
            "mode": mode,
            "profile": profile,
            "label": label,
            "notes": notes,
            "status": status,
            "benchmark_options": options,
            "autopilot_enabled": autopilot_enabled,
            "current_attempt": 1,
            "attempts": [
                {
                    "attempt_number": 1,
                    "run_id": run_id,
                    "status": status,
                    "requested_at": requested_at,
                    "started_at": None,
                    "finished_at": None,
                }
            ],
            "watchdog_status": "idle" if autopilot_enabled else "disabled",
            "last_watchdog_check_at": None,
            "watchdog_actions": [],
            "final_recommendation": None,
        },
    )


def benchmark_mode_to_reprocess_mode(mode: str | None) -> str:
    normalized = str(mode or "").strip().lower()
    mapping = {
        "ingest": "previous_selection",
        "reprocess_previous_selection": "previous_selection",
        "reprocess_full": "full_rediscovery",
        "current": "previous_selection",
    }
    return mapping.get(normalized, "previous_selection")


def build_parser_breakdown(manifest: dict | None, problematic_report: dict | None = None) -> dict[str, dict[str, Any]]:
    manifest = dict(manifest or {})
    problematic_by_name = {
        str(item.get("name") or ""): dict(item)
        for item in ((problematic_report or {}).get("items") or [])
        if isinstance(item, dict)
    }
    grouped: dict[str, list[dict[str, Any]]] = {}
    for artifact in manifest.get("artifacts") or []:
        if not isinstance(artifact, dict):
            continue
        parser_name = str(artifact.get("parser") or "unknown")
        grouped.setdefault(parser_name, []).append(artifact)
    results: dict[str, dict[str, Any]] = {}
    for parser_name, items in sorted(grouped.items()):
        durations = [
            float(((item.get("ingest_audit") or {}).get("duration_seconds") or 0) or 0)
            for item in items
            if float(((item.get("ingest_audit") or {}).get("duration_seconds") or 0) or 0) > 0
        ]
        total_duration = round(sum(durations), 2)
        total_records_read = sum(int(((item.get("ingest_audit") or {}).get("records_read") or 0) or 0) for item in items)
        total_records_indexed = sum(
            int(((item.get("ingest_audit") or {}).get("records_indexed") or (item.get("ingest_audit") or {}).get("events_indexed") or item.get("record_count") or 0) or 0)
            for item in items
        )
        slow_rows = []
        for item in sorted(items, key=lambda row: float(((row.get("ingest_audit") or {}).get("duration_seconds") or 0) or 0), reverse=True)[:5]:
            artifact_name = str(item.get("name") or "")
            problematic = problematic_by_name.get(artifact_name) or {}
            audit = dict(item.get("ingest_audit") or {})
            duration = round(float(audit.get("duration_seconds") or 0) or 0, 2)
            slow_rows.append(
                {
                    "artifact_name": artifact_name,
                    "parser": parser_name,
                    "duration_seconds": duration,
                    "records_read": int(audit.get("records_read") or 0),
                    "records_indexed": int(audit.get("records_indexed") or audit.get("events_indexed") or item.get("record_count") or 0),
                    "status": str(problematic.get("effective_status") or item.get("status") or ""),
                    "error": problematic.get("error_message") or "; ".join(str(entry) for entry in audit.get("top_errors") or []),
                    "retryable": bool(problematic.get("retryable")),
                    "suggested_action": problematic.get("suggested_primary_action") or problematic.get("suggested_retry_mode") or None,
                }
            )
        results[parser_name] = {
            "artifacts": len(items),
            "completed": sum(1 for item in items if str(item.get("status") or "") in {"completed", "parsed_with_warning", "partial"}),
            "failed": sum(1 for item in items if str(item.get("status") or "").startswith("failed") or str(item.get("status") or "") in {"cancelled", "stalled"}),
            "duration_seconds": total_duration,
            "records_read": total_records_read,
            "records_indexed": total_records_indexed,
            "records_per_sec": round(total_records_indexed / max(total_duration, 0.001), 2) if total_duration else 0.0,
            "avg_artifact_seconds": round(total_duration / max(len(items), 1), 2),
            "p95_artifact_seconds": round(quantiles(durations, n=20)[-1], 2) if len(durations) >= 2 else round(durations[0], 2) if durations else 0.0,
            "top_slow_artifacts": slow_rows,
        }
    return results


def summarize_benchmark_artifact_counts(manifest: dict | None, *, selected_total: int | None = None) -> dict[str, int]:
    manifest = dict(manifest or {})
    artifacts = [item for item in (manifest.get("artifacts") or []) if isinstance(item, dict)]
    terminal_statuses = {
        "completed",
        "parsed_with_warning",
        "partial",
        "failed",
        "failed_timeout",
        "failed_aborted",
        "failed_unsupported",
        "cancelled",
        "stalled",
    }
    failed_statuses = {"failed", "failed_timeout", "failed_aborted", "failed_unsupported", "cancelled", "stalled"}
    unsupported_count = sum(1 for item in artifacts if str(item.get("status") or "") == "failed_unsupported")
    skipped_count = sum(1 for item in artifacts if str(item.get("status") or "") in {"skipped", "reused_existing"})
    synthetic_count = sum(1 for item in artifacts if bool(item.get("synthetic")))
    created_for_run = len(artifacts)
    processed_for_run = sum(1 for item in artifacts if str(item.get("status") or "") in terminal_statuses)
    failed_for_run = sum(1 for item in artifacts if str(item.get("status") or "") in failed_statuses)
    return {
        "selected_total": max(int(selected_total or 0), 0),
        "artifacts_created_for_run": created_for_run,
        "artifacts_processed_for_run": processed_for_run,
        "artifacts_failed_for_run": failed_for_run,
        "unsupported_count": unsupported_count,
        "synthetic_artifacts_count": synthetic_count,
        "skipped_count": skipped_count,
    }


def classify_benchmark_bottleneck(benchmark: dict[str, Any]) -> dict[str, Any]:
    total_duration = float(benchmark.get("total_duration_seconds") or 0) or 0.0
    phases = {str(item.get("phase") or ""): dict(item) for item in benchmark.get("phase_timings") or [] if isinstance(item, dict)}
    by_parser = dict(benchmark.get("by_parser") or {})
    effective_parallelism = int(benchmark.get("effective_parallelism") or 1)
    active_worker_max = max(int(sample.get("active_workers") or 0) for sample in (benchmark.get("resource_samples") or []) if isinstance(sample, dict)) if benchmark.get("resource_samples") else 0
    metadata_delta = int(benchmark.get("metadata_opensearch_delta") or 0)
    time_to_first_event = float(benchmark.get("time_to_first_event_indexed") or 0) or 0.0
    first_parse = float(benchmark.get("time_to_first_parse_start") or 0) or 0.0
    extraction_seconds = float(benchmark.get("extracting_selected_seconds") or 0) or 0.0
    parsing_seconds = float(benchmark.get("parsing_seconds") or 0) or 0.0
    indexing_seconds = float(benchmark.get("indexing_seconds") or 0) or 0.0
    db_seconds = float(benchmark.get("db_seconds") or 0) or 0.0
    timeout_count = int(benchmark.get("timeout_count") or 0)

    slowest: dict[str, Any] | None = None
    for parser_row in by_parser.values():
        for item in parser_row.get("top_slow_artifacts") or []:
            if slowest is None or float(item.get("duration_seconds") or 0) > float(slowest.get("duration_seconds") or 0):
                slowest = dict(item)

    reasons: list[str] = []
    recommendations: list[str] = []
    bottleneck = "unknown"
    confidence = "low"

    if time_to_first_event > 0 and first_parse <= 0:
        bottleneck = "materialization"
        confidence = "medium"
        reasons.append("Parsing did not start before the first-event delay was observed.")
        recommendations.append("Reduce extraction/materialization latency before increasing parallelism.")
    elif slowest and total_duration > 0 and float(slowest.get("duration_seconds") or 0) >= total_duration * 0.35:
        bottleneck = "single_slow_artifact"
        confidence = "high"
        reasons.append(f"{slowest.get('artifact_name')} consumed {round((float(slowest.get('duration_seconds') or 0) / max(total_duration, 0.001)) * 100)}% of wall time.")
        recommendations.append("Defer slow artifacts to targeted retry or deep_safe_mode instead of blocking the main run.")
    elif indexing_seconds > max(parsing_seconds, extraction_seconds, db_seconds) and indexing_seconds > 0:
        bottleneck = "open_search_indexing"
        confidence = "medium"
        reasons.append("Bulk indexing time dominated measured ingest phases.")
        recommendations.append("Tune bulk batch size or OpenSearch capacity before increasing parser concurrency.")
    elif db_seconds >= max(indexing_seconds, parsing_seconds, extraction_seconds) and db_seconds > 0:
        bottleneck = "postgres_metadata"
        confidence = "medium"
        reasons.append("Metadata/finalizer time dominated measured phases.")
        recommendations.append("Reduce metadata churn and favor batched updates.")
    elif effective_parallelism <= 1 and str(benchmark.get("profile") or "") in {"performance", "max"}:
        bottleneck = "low_parallelism"
        confidence = "medium"
        reasons.append("The selected profile requested parallelism but the effective parallelism remained 1.")
        recommendations.append("Check worker/container CPU limits before using higher-performance profiles.")
    elif active_worker_max and effective_parallelism > 1 and active_worker_max < effective_parallelism:
        bottleneck = "low_parallelism"
        confidence = "medium"
        reasons.append("Observed active worker capacity stayed below effective ingest parallelism.")
        recommendations.append("Increase worker capacity or reduce per-artifact scheduling bottlenecks.")
    elif timeout_count > 0:
        bottleneck = "single_slow_artifact"
        confidence = "medium"
        reasons.append("One or more artifacts timed out during ingest.")
        recommendations.append("Use targeted retries with higher artifact timeout instead of increasing global timeout.")

    if metadata_delta == 0:
        reasons.append("OpenSearch and metadata event counts stayed coherent.")
    if not recommendations:
        recommendations.append("Compare another profile to confirm whether the observed limit is systemic or profile-specific.")
    return {
        "bottleneck": bottleneck,
        "confidence": confidence,
        "reasons": reasons,
        "recommendations": recommendations,
        "dominant_phase": max(
            (
                ("extracting_selected", extraction_seconds),
                ("parsing", parsing_seconds),
                ("bulk_indexing", indexing_seconds),
                ("postgres_metadata", db_seconds),
                ("finalizer", float((phases.get("finalizer") or {}).get("duration_seconds") or 0)),
            ),
            key=lambda item: float(item[1]),
        )[0] if total_duration > 0 else "unknown",
    }


def compare_ingest_benchmarks(baseline: dict[str, Any], candidate: dict[str, Any]) -> dict[str, Any]:
    baseline_bottleneck = str(((baseline.get("bottleneck_report") or {}).get("bottleneck")) or "")
    candidate_bottleneck = str(((candidate.get("bottleneck_report") or {}).get("bottleneck")) or "")
    infrastructure_blocked = "infrastructure_blocked" in {baseline_bottleneck, candidate_bottleneck}
    baseline_duration = float(baseline.get("total_duration_seconds") or 0) or 0.0
    candidate_duration = float(candidate.get("total_duration_seconds") or 0) or 0.0
    baseline_rps = float(baseline.get("records_per_sec") or 0) or 0.0
    candidate_rps = float(candidate.get("records_per_sec") or 0) or 0.0
    baseline_aps = float(baseline.get("artifacts_per_sec") or 0) or 0.0
    candidate_aps = float(candidate.get("artifacts_per_sec") or 0) or 0.0
    baseline_first_event = float(baseline.get("time_to_first_event_indexed") or 0) or 0.0
    candidate_first_event = float(candidate.get("time_to_first_event_indexed") or 0) or 0.0
    baseline_problematic = int(baseline.get("problematic_count") or 0)
    candidate_problematic = int(candidate.get("problematic_count") or 0)

    speedup_duration = round(baseline_duration / max(candidate_duration, 0.001), 2) if baseline_duration and candidate_duration else None
    speedup_records = round(candidate_rps / max(baseline_rps, 0.001), 2) if baseline_rps and candidate_rps else None
    speedup_artifacts = round(candidate_aps / max(baseline_aps, 0.001), 2) if baseline_aps and candidate_aps else None

    recommendation = str(candidate.get("profile") or "candidate")
    reason = "Candidate benchmark improved throughput."
    measurement_reliable = not infrastructure_blocked
    if infrastructure_blocked:
        recommendation = None
        reason = "One or more benchmarks were blocked by OpenSearch infrastructure state and should not be used for profile recommendation."
    elif speedup_records is not None and speedup_records < 1 and speedup_duration is not None and speedup_duration <= 1:
        recommendation = str(baseline.get("profile") or "baseline")
        reason = (
            f"{candidate.get('profile')} did not improve throughput; bottleneck was "
            f"{((candidate.get('bottleneck_report') or {}).get('bottleneck') or 'unknown')}."
        )
    elif candidate_problematic > baseline_problematic:
        recommendation = str(baseline.get("profile") or "baseline")
        reason = "Candidate benchmark increased problematic artifacts."
    elif speedup_records is not None and speedup_records >= 1 and candidate_problematic <= baseline_problematic:
        reason = f"{candidate.get('profile')} delivered {speedup_records}x records/sec with no worse problematic artifact count."

    return {
        "baseline": baseline,
        "candidate": candidate,
        "speedup_duration": speedup_duration,
        "speedup_records_per_sec": speedup_records,
        "speedup_artifacts_per_sec": speedup_artifacts,
        "time_to_first_event_indexed_delta": round(candidate_first_event - baseline_first_event, 2),
        "effective_parallelism_delta": int(candidate.get("effective_parallelism") or 0) - int(baseline.get("effective_parallelism") or 0),
        "problematic_delta": candidate_problematic - baseline_problematic,
        "metadata_coherence_delta": int(candidate.get("metadata_opensearch_delta") or 0) - int(baseline.get("metadata_opensearch_delta") or 0),
        "measurement_reliable": measurement_reliable,
        "bottleneck_difference": [
            {
                "baseline": baseline_bottleneck or None,
                "candidate": candidate_bottleneck or None,
            }
        ],
        "profile_recommendation": recommendation,
        "reason": reason,
    }
