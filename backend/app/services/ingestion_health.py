"""Server Health Check for the ingestion wizard (Step 0, before "What are you adding?").

A lightweight readiness probe over the dependencies evidence processing
actually needs: storage, search, database, and workers. Reuses the existing
task/queue health snapshot (app.services.task_registry) instead of building
a second worker-health mechanism.
"""
from __future__ import annotations

import shutil

from redis import Redis
from sqlalchemy import text
from sqlalchemy.orm import Session

from app.core.config import get_settings
from app.core.opensearch import get_opensearch_client
from app.services.task_registry import build_task_health_snapshot

INGEST_QUEUES = ("dfir-ingest", "dfir-rules", "dfir-analysis")
MEMORY_QUEUE = "memory"


def _check(label: str, ok: bool, detail: str) -> dict:
    return {"label": label, "ok": ok, "detail": detail}


def check_ingestion_readiness(db: Session) -> dict:
    settings = get_settings()
    checks: list[dict] = []

    try:
        settings.backend_temp_dir.mkdir(parents=True, exist_ok=True)
        probe = settings.backend_temp_dir / ".health_check_probe"
        probe.write_text("ok", encoding="utf-8")
        probe.unlink(missing_ok=True)
        usage = shutil.disk_usage(settings.backend_temp_dir)
        checks.append(_check("Storage", True, f"{usage.free / (1024**3):.1f} GB available"))
        available_bytes = usage.free
    except OSError as exc:
        checks.append(_check("Storage", False, f"Temp storage is not writable: {exc}"))
        available_bytes = 0

    try:
        client = get_opensearch_client(timeout_seconds=5)
        health = client.cluster.health()
        cluster_status = str(health.get("status") or "unknown")
        checks.append(_check("Search", cluster_status in {"green", "yellow"}, f"OpenSearch cluster status: {cluster_status}"))
    except Exception as exc:  # noqa: BLE001
        checks.append(_check("Search", False, f"OpenSearch is unreachable: {exc.__class__.__name__}"))

    try:
        db.execute(text("SELECT 1"))
        checks.append(_check("Database", True, "Reachable"))
    except Exception as exc:  # noqa: BLE001
        checks.append(_check("Database", False, f"Database is unreachable: {exc.__class__.__name__}"))

    try:
        connection = Redis.from_url(settings.redis_url)
        snapshot = build_task_health_snapshot(connection)
        worker_queue_names = {name for names in snapshot.get("workers", {}).get("queues", {}).values() for name in names}
        ingest_ok = bool(worker_queue_names.intersection(INGEST_QUEUES))
        memory_ok = MEMORY_QUEUE in worker_queue_names
        checks.append(_check("Workers", ingest_ok, "Active worker(s) on the ingest/rules/analysis queues" if ingest_ok else "No active worker found for ingest/rules/analysis queues"))
        checks.append(_check("Memory Worker", memory_ok, "Active worker on the memory queue" if memory_ok else "No active worker found for the memory queue"))
    except Exception as exc:  # noqa: BLE001
        checks.append(_check("Workers", False, f"Could not reach the task queue: {exc.__class__.__name__}"))
        checks.append(_check("Memory Worker", False, f"Could not reach the task queue: {exc.__class__.__name__}"))

    critical_ok = all(check["ok"] for check in checks if check["label"] in {"Storage", "Database"})
    overall_ok = all(check["ok"] for check in checks)

    return {
        "checks": checks,
        "available_disk_space_bytes": available_bytes,
        "configured_upload_limit_bytes": int(settings.backend_max_upload_size),
        "configured_extraction_limit_bytes": int(settings.backend_max_extracted_bytes),
        "ready": overall_ok,
        "critical_ready": critical_ok,
        "unified_upload_evidence_memory_dump": bool(settings.unified_upload_evidence_memory_dump),
        "unified_upload_evidence_disk_image": bool(settings.unified_upload_evidence_disk_image),
    }
