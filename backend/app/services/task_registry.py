from __future__ import annotations

from collections import Counter
from copy import deepcopy
from typing import Any

from redis import Redis
from rq import Queue, Worker
from rq.job import Job
from rq.registry import FailedJobRegistry, FinishedJobRegistry, StartedJobRegistry

from app.core.config import get_settings
from app.services.usable_ingest import FULL_FORENSIC_MODE, USABLE_INGEST_MODE, normalize_ingest_mode

settings = get_settings()

KNOWN_QUEUES: dict[str, dict[str, Any]] = {
    "dfir-ingest": {
        "category": "core",
        "status": "stable",
        "notes": "Core ingest and targeted artifact retry queue.",
    },
    "dfir-rules": {
        "category": "on_demand",
        "status": "stable",
        "notes": "Manual Sigma/YARA execution queue.",
    },
    "dfir-analysis": {
        "category": "advanced",
        "status": "beta",
        "notes": "Heavy/advanced case analysis jobs.",
    },
}

TASK_REGISTRY: dict[str, dict[str, Any]] = {
    "app.workers.tasks.ingest_evidence": {
        "task_name": "usable_search_ingest",
        "category": "core",
        "queue": "dfir-ingest",
        "entrypoint": "app.workers.tasks.ingest_evidence",
        "allowed_ingest_modes": [USABLE_INGEST_MODE, FULL_FORENSIC_MODE],
        "triggered_by": ["evidence_upload", "evidence_reprocess", "manual_retry"],
        "destructive": False,
        "idempotent": "unknown",
        "status": "stable",
        "notes": "Primary ingest worker task that performs discovery, parsing and indexing.",
    },
    "app.workers.tasks.retry_problematic_artifacts": {
        "task_name": "problematic_artifact_retry",
        "category": "on_demand",
        "queue": "dfir-ingest",
        "entrypoint": "app.workers.tasks.retry_problematic_artifacts",
        "allowed_ingest_modes": [USABLE_INGEST_MODE, FULL_FORENSIC_MODE],
        "triggered_by": ["problematic_artifacts_ui", "explicit_retry"],
        "destructive": False,
        "idempotent": False,
        "status": "beta",
        "notes": "Explicit artifact retry path that preserves the main ingest result.",
    },
    "app.workers.tasks.run_rules_on_case": {
        "task_name": "rules_batch_run",
        "category": "on_demand",
        "queue": "dfir-rules",
        "entrypoint": "app.workers.tasks.run_rules_on_case",
        "allowed_ingest_modes": [USABLE_INGEST_MODE, FULL_FORENSIC_MODE],
        "triggered_by": ["rules_ui", "evidence_on_demand_rules"],
        "destructive": False,
        "idempotent": False,
        "status": "stable",
        "notes": "Preferred on-demand rules execution entrypoint.",
    },
    "app.workers.tasks.run_rule_on_case": {
        "task_name": "single_rule_run",
        "category": "on_demand",
        "queue": "dfir-rules",
        "entrypoint": "app.workers.tasks.run_rule_on_case",
        "allowed_ingest_modes": [USABLE_INGEST_MODE, FULL_FORENSIC_MODE],
        "triggered_by": ["rules_ui_single_rule"],
        "destructive": False,
        "idempotent": False,
        "status": "advanced",
        "notes": "Single-rule execution path kept for focused/manual runs.",
    },
    "app.services.report_service.generate_evidence_summary_report": {
        "task_name": "evidence_summary_report",
        "category": "on_demand",
        "queue": "inline",
        "entrypoint": "app.services.report_service.generate_evidence_summary_report",
        "allowed_ingest_modes": [USABLE_INGEST_MODE, FULL_FORENSIC_MODE],
        "triggered_by": ["reports_ui", "evidence_on_demand_reports"],
        "destructive": False,
        "idempotent": False,
        "status": "stable",
        "notes": "Synchronous on-demand report generation using indexed data only.",
    },
    "app.workers.tasks.run_case_semi_auto_analysis": {
        "task_name": "case_semi_auto_analysis",
        "category": "advanced",
        "queue": "dfir-analysis",
        "entrypoint": "app.workers.tasks.run_case_semi_auto_analysis",
        "allowed_ingest_modes": [FULL_FORENSIC_MODE],
        "triggered_by": ["case_workspace_advanced"],
        "destructive": False,
        "idempotent": False,
        "status": "beta",
        "notes": "Advanced case analysis flow outside the Search-first core path.",
    },
    "app.services.job_watchdog.run_benchmark_watchdog": {
        "task_name": "benchmark_watchdog",
        "category": "maintenance",
        "queue": "inline",
        "entrypoint": "app.services.job_watchdog.run_benchmark_watchdog",
        "allowed_ingest_modes": [USABLE_INGEST_MODE, FULL_FORENSIC_MODE],
        "triggered_by": ["benchmark_polling", "watchdog_manual_run"],
        "destructive": False,
        "idempotent": True,
        "status": "stable",
        "notes": "Safe watchdog/reconciliation for benchmark and orphaned ingest state.",
    },
    "app.services.debug_export.generate_debug_pack": {
        "task_name": "advanced_debug_export",
        "category": "advanced",
        "queue": "inline",
        "entrypoint": "app.services.debug_export.generate_debug_pack",
        "allowed_ingest_modes": [USABLE_INGEST_MODE, FULL_FORENSIC_MODE],
        "triggered_by": ["advanced_export_ui"],
        "destructive": False,
        "idempotent": False,
        "status": "advanced",
        "notes": "Diagnostic export outside the core evidence-to-search workflow.",
    },
    "app.services.ingest_benchmarks.create_ingest_benchmark": {
        "task_name": "benchmark_tuning",
        "category": "advanced",
        "queue": "dfir-ingest",
        "entrypoint": "app.services.ingest_benchmarks.create_ingest_benchmark",
        "allowed_ingest_modes": [FULL_FORENSIC_MODE],
        "triggered_by": ["benchmark_ui"],
        "destructive": False,
        "idempotent": False,
        "status": "advanced",
        "notes": "Advanced benchmark/tuning path kept outside the recommended ingest flow.",
    },
}


def build_task_registry() -> dict[str, dict[str, Any]]:
    return deepcopy(TASK_REGISTRY)


def list_task_registry_entries() -> list[dict[str, Any]]:
    return [dict(value) for _, value in sorted(TASK_REGISTRY.items(), key=lambda item: item[0])]


def get_task_registry_entry(entrypoint: str | None) -> dict[str, Any] | None:
    if not entrypoint:
        return None
    item = TASK_REGISTRY.get(str(entrypoint).strip())
    return deepcopy(item) if item else None


def automatic_task_entrypoints_for_ingest_mode(mode: object | None) -> list[str]:
    normalized = normalize_ingest_mode(mode)
    automatic = []
    for entrypoint, entry in TASK_REGISTRY.items():
        if entry.get("category") != "core":
            continue
        allowed = set(entry.get("allowed_ingest_modes") or [])
        if normalized not in allowed:
            continue
        automatic.append(entrypoint)
    return sorted(set(automatic))


def automatic_task_categories_for_ingest_mode(mode: object | None) -> list[str]:
    categories = {
        str((TASK_REGISTRY.get(entrypoint) or {}).get("category") or "unknown")
        for entrypoint in automatic_task_entrypoints_for_ingest_mode(mode)
    }
    return sorted(category for category in categories if category)


def build_task_registry_summary() -> dict[str, Any]:
    entries = list_task_registry_entries()
    categories = Counter(str(entry.get("category") or "unknown") for entry in entries)
    statuses = Counter(str(entry.get("status") or "unknown") for entry in entries)
    queues = Counter(str(entry.get("queue") or "inline") for entry in entries)
    return {
        "entries": entries,
        "summary": {
            "by_category": dict(categories),
            "by_status": dict(statuses),
            "by_queue": dict(queues),
            "known_queues": deepcopy(KNOWN_QUEUES),
        },
    }


def _queue_job_samples(queue: Queue, *, limit: int = 5) -> list[dict[str, Any]]:
    samples: list[dict[str, Any]] = []
    for job_id in list(queue.job_ids)[:limit]:
        job = queue.fetch_job(job_id)
        if job is None:
            continue
        entry = get_task_registry_entry(job.func_name)
        samples.append(
            {
                "job_id": job.id,
                "entrypoint": job.func_name,
                "task_name": (entry or {}).get("task_name"),
                "category": (entry or {}).get("category", "unknown"),
                "queue": queue.name,
                "status": "queued",
            }
        )
    return samples


def _started_job_samples(connection: Redis, queue_name: str, *, limit: int = 5) -> list[dict[str, Any]]:
    registry = StartedJobRegistry(queue_name, connection=connection)
    queue = Queue(queue_name, connection=connection)
    samples: list[dict[str, Any]] = []
    for job_id in registry.get_job_ids()[:limit]:
        job = queue.fetch_job(job_id)
        if job is None:
            continue
        entry = get_task_registry_entry(job.func_name)
        samples.append(
            {
                "job_id": job.id,
                "entrypoint": job.func_name,
                "task_name": (entry or {}).get("task_name"),
                "category": (entry or {}).get("category", "unknown"),
                "queue": queue_name,
                "status": "running",
            }
        )
    return samples


def build_task_health_snapshot(connection: Redis | None = None) -> dict[str, Any]:
    connection = connection or Redis.from_url(settings.redis_url)
    workers = Worker.all(connection=connection)
    worker_queue_map: dict[str, list[str]] = {}
    queue_worker_counts: Counter[str] = Counter()
    for worker in workers:
        names: list[str] = []
        for queue in getattr(worker, "queues", []) or []:
            queue_name = str(getattr(queue, "name", "") or "").strip()
            if not queue_name:
                continue
            names.append(queue_name)
            queue_worker_counts[queue_name] += 1
        worker_queue_map[worker.name] = names

    queues: dict[str, Any] = {}
    warnings: list[str] = []
    stale_orphan_candidates = 0
    for queue_name, meta in KNOWN_QUEUES.items():
        queue = Queue(queue_name, connection=connection)
        started_registry = StartedJobRegistry(queue_name, connection=connection)
        failed_registry = FailedJobRegistry(queue_name, connection=connection)
        finished_registry = FinishedJobRegistry(queue_name, connection=connection)
        queued_samples = _queue_job_samples(queue)
        running_samples = _started_job_samples(connection, queue_name)
        sample_categories = Counter(
            str(sample.get("category") or "unknown")
            for sample in queued_samples + running_samples
        )
        started_count = len(started_registry)
        worker_count = int(queue_worker_counts.get(queue_name) or 0)
        orphan_candidates = started_count if worker_count == 0 else max(started_count - worker_count, 0)
        stale_orphan_candidates += orphan_candidates
        if orphan_candidates:
            warnings.append(f"Queue {queue_name} has {orphan_candidates} started job(s) without enough active workers.")
        queues[queue_name] = {
            "category": meta.get("category"),
            "status": meta.get("status"),
            "queued": queue.count,
            "started": started_count,
            "failed": len(failed_registry),
            "finished": len(finished_registry),
            "active_workers": worker_count,
            "orphan_candidates": orphan_candidates,
            "job_categories": dict(sample_categories),
            "queued_samples": queued_samples,
            "running_samples": running_samples,
        }

    registry_summary = build_task_registry_summary()
    return {
        "workers": {
            "alive": len(workers),
            "known": [worker.name for worker in workers],
            "queues": worker_queue_map,
        },
        "queues": queues,
        "task_registry": registry_summary["summary"],
        "stale_orphan_candidates": stale_orphan_candidates,
        "warnings": warnings,
    }
