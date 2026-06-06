from __future__ import annotations

import math
import os
from pathlib import Path
from typing import Any

import psutil
from redis import Redis
from rq import Queue, Worker
from rq.registry import FailedJobRegistry, FinishedJobRegistry, StartedJobRegistry
from sqlalchemy.orm import Session

from app.core.app_settings import (
    DEPLOYMENT_DEFAULTS,
    PERFORMANCE_PROFILE_KEY,
    PERFORMANCE_PROFILES,
    RUNTIME_DEFAULTS,
    SETTING_META,
    get_performance_profile,
    get_setting,
    set_setting,
)
from app.core.config import get_settings
from app.core.evidence_paths import storage_capabilities
from app.core.opensearch import get_opensearch_client, get_opensearch_ingest_preflight


settings = get_settings()

LOW_DISK_FREE_BYTES = 10 * 1024 * 1024 * 1024
LOW_DISK_FREE_PERCENT = 15.0
LOW_MEMORY_AVAILABLE_BYTES = 2 * 1024 * 1024 * 1024
DISK_DEGRADED_PERCENT = 80.0
DISK_CRITICAL_PERCENT = 90.0

SETTING_ALIASES = {
    "INGEST_BATCH_SIZE": "ingest_batch_size",
    "OPENSEARCH_BULK_DOCS": "opensearch_bulk_docs",
    "OPENSEARCH_BULK_BYTES": "opensearch_bulk_bytes",
    "OPENSEARCH_BULK_TIMEOUT": "opensearch_bulk_timeout",
    "OPENSEARCH_REFRESH_TIMEOUT": "opensearch_refresh_timeout",
    "MAX_PARALLEL_ARTIFACTS": "ingest_parallelism",
    "MAX_PARALLEL_RULE_RUNS": "rule_parallelism",
    "SEARCH_DEFAULT_PAGE_SIZE": "search_default_page_size",
    "SEARCH_MAX_PAGE_SIZE": "search_max_page_size",
    "AUTO_CREATE_HEURISTIC_DETECTIONS": "auto_create_heuristic_detections",
    "MFT_FAST_PATH": "mft_fast_path",
    "MOUNTED_PATH_SCAN_LIMIT": "mounted_path_scan_limit",
    "PROCESS_GRAPH_MAX_NODES": "process_graph_max_nodes",
    "CORRELATION_MAX_EVENTS": "correlation_max_events",
    "DEBUG_EXPORT_MAX_EVENTS": "debug_export_max_events",
    "SIGMA_MAX_MATCHES_PER_RULE": "sigma_max_matches_per_rule",
    "SIGMA_MAX_DETECTIONS_PER_RULE": "sigma_max_detections_per_rule",
    "SIGMA_NOISY_RULE_THRESHOLD": "sigma_noisy_rule_threshold",
    "DETECTION_WRITE_BATCH_SIZE": "detection_write_batch_size",
    "DETECTION_DUPLICATE_LOOKUP_BATCH_SIZE": "duplicate_lookup_batch_size",
    "METADATA_UPDATE_THROTTLE_SECONDS": "metadata_update_throttle_seconds",
    "OPENSEARCH_JAVA_HEAP": "opensearch_java_heap",
    "BACKEND_UVICORN_WORKERS": "backend_workers",
    "WORKER_SCALE": "worker_concurrency",
    "DOCKER_CPU_LIMIT": "docker_cpu_limit",
    "DOCKER_MEMORY_LIMIT": "docker_memory_limit",
    "OPENSEARCH_DASHBOARDS_PUBLIC_URL": "opensearch_dashboards_public_url",
    "REPORT_BRAND_NAME": "report_brand_name",
    "REPORT_BRAND_SUBTITLE": "report_brand_subtitle",
    "REPORT_BRAND_PRIMARY_COLOR": "report_brand_primary_color",
    "REPORT_INCLUDE_LOGO": "report_include_logo",
    "REPORT_LOGO_PATH": "report_logo_path",
}

ALIAS_TO_KEY = {alias: key for key, alias in SETTING_ALIASES.items()}


def _queue_stats(connection: Redis, name: str) -> dict[str, int]:
    queue = Queue(name, connection=connection)
    return {
        "queued": queue.count,
        "started": len(StartedJobRegistry(name, connection=connection)),
        "failed": len(FailedJobRegistry(name, connection=connection)),
        "finished": len(FinishedJobRegistry(name, connection=connection)),
    }


def _safe_read_int(path: str) -> int | None:
    try:
        raw = Path(path).read_text(encoding="utf-8").strip()
    except OSError:
        return None
    if not raw or raw == "max":
        return None
    try:
        return int(raw)
    except ValueError:
        return None


def _container_cpu_count() -> int | None:
    try:
        affinity = os.sched_getaffinity(0)
        if affinity:
            return len(affinity)
    except Exception:  # noqa: BLE001
        pass
    quota_v1 = _safe_read_int("/sys/fs/cgroup/cpu/cpu.cfs_quota_us")
    period_v1 = _safe_read_int("/sys/fs/cgroup/cpu/cpu.cfs_period_us")
    if quota_v1 and period_v1 and quota_v1 > 0 and period_v1 > 0:
        return max(1, math.ceil(quota_v1 / period_v1))
    return None


def _container_memory_limit_bytes() -> int | None:
    for path in ("/sys/fs/cgroup/memory.max", "/sys/fs/cgroup/memory/memory.limit_in_bytes"):
        value = _safe_read_int(path)
        if value is None:
            continue
        if value > 1 << 60:
            return None
        return value
    return None


def _memory_limit_source() -> str:
    for path in ("/sys/fs/cgroup/memory.max", "/sys/fs/cgroup/memory/memory.limit_in_bytes"):
        if Path(path).exists():
            return "cgroup"
    return "/proc/meminfo"


def describe_ingest_parallelism(
    runtime_settings: dict[str, Any] | None = None,
    *,
    system: dict[str, Any] | None = None,
    artifact_count: int | None = None,
    artifact_types: list[str] | None = None,
    supported_artifact_types: list[str] | None = None,
) -> dict[str, Any]:
    runtime_settings = runtime_settings or {}
    system = system or system_snapshot()
    supported = {str(item).lower() for item in (supported_artifact_types or ["evtx_raw", "windows_event"])}
    desired = max(int(runtime_settings.get("MAX_PARALLEL_ARTIFACTS") or 1), 1)
    cpu_limit = max(int(system.get("cpu_count_container") or system.get("cpu_count") or 1), 1)
    profile = str(runtime_settings.get(PERFORMANCE_PROFILE_KEY) or "").lower()
    effective = min(desired, cpu_limit)
    enabled = effective > 1
    reason = None

    if profile == "safe" or desired <= 1:
        effective = 1
        enabled = False
        reason = "profile_safe"
    elif artifact_count is not None and artifact_count <= 1:
        effective = 1
        enabled = False
        reason = "single_artifact"
    elif artifact_count is not None and effective > artifact_count:
        effective = max(1, artifact_count)
        enabled = effective > 1
        reason = "limited_by_artifact_count" if effective < desired else reason
    if artifact_types:
        normalized = {str(item).lower() for item in artifact_types if item}
        if normalized and not normalized.issubset(supported):
            effective = 1
            enabled = False
            reason = "unsupported_artifact_type"
    if effective < desired and reason is None:
        reason = "container_cpu_limit"

    return {
        "enabled": enabled,
        "mode": "threads" if enabled else "off",
        "desired_parallelism": desired,
        "effective_parallelism": max(effective, 1),
        "supported_artifact_types": sorted(supported),
        "limit_reason": reason,
        "effective_cpu_count": cpu_limit,
    }


def _worker_queue_names(worker: Worker) -> list[str]:
    names: list[str] = []
    try:
        for queue in getattr(worker, "queues", []) or []:
            queue_name = getattr(queue, "name", None)
            if queue_name:
                names.append(str(queue_name))
    except Exception:  # noqa: BLE001
        return []
    return names


def _coerce_value(key: str, value: Any) -> Any:
    meta = SETTING_META.get(key, {})
    value_type = meta.get("value_type")
    if value is None:
        return None
    if value_type == "bool":
        if isinstance(value, bool):
            coerced = value
        elif isinstance(value, str):
            lowered = value.strip().lower()
            if lowered in {"true", "1", "yes", "on"}:
                coerced = True
            elif lowered in {"false", "0", "no", "off"}:
                coerced = False
            else:
                raise ValueError(f"Invalid boolean for {key}")
        else:
            coerced = bool(value)
    elif value_type == "int":
        try:
            coerced = int(value)
        except Exception as exc:  # noqa: BLE001
            raise ValueError(f"Invalid integer for {key}") from exc
        minimum = meta.get("min")
        maximum = meta.get("max")
        if minimum is not None and coerced < int(minimum):
            raise ValueError(f"{key} must be >= {minimum}")
        if maximum is not None and coerced > int(maximum):
            raise ValueError(f"{key} must be <= {maximum}")
    elif value_type == "string":
        coerced = str(value).strip()
        allowed = meta.get("allowed")
        if allowed and coerced not in allowed:
            raise ValueError(f"{key} must be one of: {', '.join(allowed)}")
    else:
        coerced = value
    return coerced


def _runtime_effective_settings(db: Session) -> dict[str, Any]:
    return {key: _coerce_value(key, get_setting(db, key, RUNTIME_DEFAULTS[key])) for key in RUNTIME_DEFAULTS}


def _deployment_current_settings() -> dict[str, Any]:
    snapshot = system_snapshot()
    worker_active = ((snapshot.get("services") or {}).get("worker") or {}).get("active")
    current = dict(DEPLOYMENT_DEFAULTS)
    current.update({
        "OPENSEARCH_JAVA_HEAP": settings.opensearch_java_heap,
        "BACKEND_UVICORN_WORKERS": settings.backend_uvicorn_workers,
        "WORKER_SCALE": int(worker_active or 1),
    })
    return current


def _deployment_pending_settings(db: Session) -> dict[str, Any]:
    current = _deployment_current_settings()
    pending: dict[str, Any] = {}
    for key in DEPLOYMENT_DEFAULTS:
        saved = get_setting(db, key, current[key])
        desired = _coerce_value(key, saved)
        if desired != current[key]:
            pending[key] = desired
    return pending


def _disk_status(used_percent: float) -> str:
    if used_percent >= DISK_CRITICAL_PERCENT:
        return "critical"
    if used_percent >= DISK_DEGRADED_PERCENT:
        return "degraded"
    return "healthy"


def _opensearch_watermark_risk(disk_used_percent: float, write_blocked: bool | None = None) -> str:
    if write_blocked or disk_used_percent >= DISK_CRITICAL_PERCENT:
        return "high"
    if disk_used_percent >= DISK_DEGRADED_PERCENT:
        return "medium"
    return "low"


def _services_snapshot(connection: Redis | None = None, *, disk_used_percent: float | None = None) -> dict[str, Any]:
    connection = connection or Redis.from_url(settings.redis_url)
    workers = Worker.all(connection=connection)
    worker_names = [worker.name for worker in workers]
    worker_queues = {worker.name: _worker_queue_names(worker) for worker in workers}
    worker_status = "ok" if worker_names else "warning"
    opensearch = {
        "status": "unknown",
        "cluster_status": "unknown",
        "heap_used_percent": None,
        "disk_watermark": None,
        "write_blocked": None,
        "ingest_writable": None,
        "watermark_risk": "unknown",
        "blocking_reasons": [],
    }
    try:
        client = get_opensearch_client()
        health = client.cluster.health()
        nodes = client.nodes.stats(metric="jvm")
        cluster_settings = client.cluster.get_settings(include_defaults=True)
        preflight = get_opensearch_ingest_preflight(None)
        heap_used_percent = None
        for node in (nodes.get("nodes") or {}).values():
            heap_used_percent = node.get("jvm", {}).get("mem", {}).get("heap_used_percent")
            if heap_used_percent is not None:
                break
        disk_watermark = (
            ((cluster_settings.get("transient") or {}).get("cluster") or {}).get("routing", {}).get("allocation", {}).get("disk", {}).get("watermark", {})
            or ((cluster_settings.get("persistent") or {}).get("cluster") or {}).get("routing", {}).get("allocation", {}).get("disk", {}).get("watermark", {})
            or ((cluster_settings.get("defaults") or {}).get("cluster") or {}).get("routing", {}).get("allocation", {}).get("disk", {}).get("watermark", {})
        )
        write_blocked = bool(
            preflight.get("cluster_create_index_blocked")
            or preflight.get("cluster_write_blocked")
            or preflight.get("cluster_read_only_allow_delete")
            or preflight.get("target_index_write_blocked")
            or preflight.get("target_index_read_only_allow_delete")
        )
        opensearch = {
            "status": "critical" if write_blocked else "ok",
            "cluster_status": health.get("status", "unknown"),
            "heap_used_percent": heap_used_percent,
            "disk_watermark": preflight.get("disk_watermark") or disk_watermark or None,
            "write_blocked": write_blocked,
            "ingest_writable": bool(preflight.get("ingest_writable")),
            "watermark_risk": _opensearch_watermark_risk(float(disk_used_percent or 0), write_blocked),
            "blocking_reasons": list(preflight.get("blocking_reasons") or []),
        }
    except Exception:  # noqa: BLE001
        opensearch = {
            "status": "error",
            "cluster_status": "unreachable",
            "heap_used_percent": None,
            "disk_watermark": None,
            "write_blocked": None,
            "ingest_writable": False,
            "watermark_risk": "unknown",
            "blocking_reasons": ["opensearch_unreachable"],
        }
    return {
        "backend": {"status": "ok", "workers": settings.backend_uvicorn_workers},
        "worker": {"status": worker_status, "active": len(worker_names), "known": worker_names, "queues": worker_queues},
        "frontend": {"status": "ok"},
        "opensearch": opensearch,
    }


def build_resource_warnings(system: dict[str, Any], profile: str | None = None) -> list[str]:
    warnings: list[str] = []
    disk_free = int(system.get("disk_free_bytes") or 0)
    disk_total = max(int(system.get("disk_total_bytes") or 0), 1)
    disk_free_percent = (disk_free / disk_total) * 100
    disk_used_percent = float(system.get("disk_used_percent") or (100.0 - disk_free_percent))
    if disk_free < LOW_DISK_FREE_BYTES or disk_free_percent < LOW_DISK_FREE_PERCENT:
        warnings.append("low_disk_space")
    if disk_used_percent >= DISK_DEGRADED_PERCENT:
        warnings.append("disk_usage_degraded")
    if disk_used_percent >= DISK_CRITICAL_PERCENT:
        warnings.append("disk_usage_critical")
    if int(system.get("memory_available_bytes") or 0) < LOW_MEMORY_AVAILABLE_BYTES:
        warnings.append("low_available_memory")
    if profile == "max" and int(system.get("memory_available_bytes") or 0) < 8 * 1024 * 1024 * 1024:
        warnings.append("max_profile_low_memory_risk")
    if str(system.get("opensearch_status") or "") != "ok":
        warnings.append("opensearch_unavailable")
    services = system.get("services") or {}
    opensearch = services.get("opensearch") or {}
    if opensearch.get("write_blocked"):
        warnings.append("opensearch_write_blocked")
    if opensearch.get("watermark_risk") in {"medium", "high"}:
        warnings.append(f"opensearch_watermark_risk_{opensearch.get('watermark_risk')}")
    return warnings


def system_snapshot() -> dict[str, Any]:
    data_dir = Path(settings.backend_data_dir)
    disk = psutil.disk_usage(str(data_dir))
    vm = psutil.virtual_memory()
    cpu_count = psutil.cpu_count() or 1
    cpu_percent = psutil.cpu_percent(interval=0.1)
    storage_used_bytes = 0
    evidence_root = data_dir / "evidence"
    if evidence_root.exists():
        for candidate in evidence_root.rglob("*"):
            if candidate.is_file():
                try:
                    storage_used_bytes += candidate.stat().st_size
                except OSError:
                    continue
    connection = Redis.from_url(settings.redis_url)
    queues = {
        "dfir-ingest": _queue_stats(connection, "dfir-ingest"),
        "dfir-rules": _queue_stats(connection, "dfir-rules"),
    }
    services = _services_snapshot(connection=connection, disk_used_percent=float(disk.percent))
    opensearch_status = services.get("opensearch", {}).get("status")
    return {
        "cpu_count": cpu_count,
        "cpu_count_host": cpu_count,
        "cpu_count_container": _container_cpu_count() or cpu_count,
        "cpu_percent": cpu_percent,
        "memory_total_bytes": vm.total,
        "memory_host_total_bytes": vm.total,
        "memory_visible_total_bytes": vm.total,
        "memory_available_bytes": vm.available,
        "memory_container_limit_bytes": _container_memory_limit_bytes(),
        "memory_limit_source": _memory_limit_source(),
        "memory_used_percent": vm.percent,
        "disk_total_bytes": disk.total,
        "disk_free_bytes": disk.free,
        "disk_used_percent": disk.percent,
        "disk_status": _disk_status(float(disk.percent)),
        "disk_warning_threshold_percent": DISK_DEGRADED_PERCENT,
        "disk_critical_threshold_percent": DISK_CRITICAL_PERCENT,
        "storage_used_bytes": storage_used_bytes,
        "queues": queues,
        "services": services,
        "opensearch_status": opensearch_status,
    }


def build_recommendation_payload(system: dict[str, Any] | None = None) -> dict[str, Any]:
    system = system or system_snapshot()
    cpu_count = int(system.get("cpu_count_container") or system.get("cpu_count") or 1)
    memory_available = int(system.get("memory_available_bytes") or 0)
    opensearch_heap = (system.get("services") or {}).get("opensearch", {}).get("heap_used_percent")
    reasons = [
        f"{cpu_count} CPU cores detected",
        f"{round(memory_available / 1024 / 1024 / 1024, 1)} GB RAM available",
        f"{round(int(system['disk_free_bytes']) / 1024 / 1024 / 1024, 1)} GB disk free in data volume",
    ]
    recommended = "balanced"
    if cpu_count <= 2 or memory_available < 4 * 1024 * 1024 * 1024:
        recommended = "safe"
    elif cpu_count >= 8 and memory_available >= 16 * 1024 * 1024 * 1024 and str(system.get("opensearch_status")) == "ok":
        recommended = "performance"
    elif cpu_count >= 4 and memory_available >= 8 * 1024 * 1024 * 1024 and str(system.get("opensearch_status")) == "ok":
        recommended = "balanced"
    if cpu_count >= 12 and memory_available >= 24 * 1024 * 1024 * 1024 and str(system.get("opensearch_status")) == "ok":
        recommended = "max"
    if opensearch_heap is not None and int(opensearch_heap) >= 80 and recommended in {"performance", "max"}:
        recommended = "balanced"
        reasons.append("OpenSearch heap pressure is elevated, lowering the recommendation")
    warnings = build_resource_warnings(system, recommended)
    if warnings:
        reasons.append("Resource guards detected constraints")
    return {
        "recommended_profile": recommended,
        "reasons": reasons,
        "warnings": warnings,
        "estimated_changes": {SETTING_ALIASES[key]: value for key, value in PERFORMANCE_PROFILES.get(recommended, {}).items()},
    }


def performance_setting_entries(db: Session) -> list[dict[str, Any]]:
    runtime = _runtime_effective_settings(db)
    deployment_current = _deployment_current_settings()
    deployment_pending = _deployment_pending_settings(db)
    entries: list[dict[str, Any]] = []
    for key in [*RUNTIME_DEFAULTS.keys(), *DEPLOYMENT_DEFAULTS.keys()]:
        meta = SETTING_META[key]
        is_runtime = meta["category"] == "runtime"
        current_value = runtime[key] if is_runtime else deployment_current[key]
        pending_value = None if is_runtime else deployment_pending.get(key)
        effective_value = current_value if not pending_value else current_value
        entries.append(
            {
                "name": SETTING_ALIASES[key],
                "key": key,
                "category": meta["category"],
                "scope": "runtime" if is_runtime else "deployment",
                "group": meta.get("group", meta["category"]),
                "description": meta["description"],
                "value_type": meta.get("value_type"),
                "min": meta.get("min"),
                "max": meta.get("max"),
                "current_value": current_value,
                "pending_value": pending_value,
                "effective_value": effective_value,
                "requires_restart": meta["restart_scope"],
                "requires_restart_services": [] if meta["restart_scope"] == "none" else [meta["restart_scope"]],
                "applies_immediately": bool(meta["applies_immediately"]),
                "editable": True,
            }
        )
    return entries


def performance_resources(db: Session) -> dict[str, Any]:
    profile = get_performance_profile(db)
    runtime = _runtime_effective_settings(db)
    deployment_current = _deployment_current_settings()
    deployment_pending = _deployment_pending_settings(db)
    snapshot = system_snapshot()
    services = snapshot.get("services") or {}
    ingest_parallel = describe_ingest_parallelism(
        {**runtime, PERFORMANCE_PROFILE_KEY: profile},
        system=snapshot,
    )
    return {
        "cpu_count_host": snapshot.get("cpu_count_host"),
        "cpu_count_container": snapshot.get("cpu_count_container"),
        "effective_cpu_count": ingest_parallel.get("effective_cpu_count"),
        "memory_total": snapshot.get("memory_total_bytes"),
        "memory_host_total": snapshot.get("memory_host_total_bytes"),
        "memory_visible_total": snapshot.get("memory_visible_total_bytes"),
        "memory_available": snapshot.get("memory_available_bytes"),
        "memory_container_limit": snapshot.get("memory_container_limit_bytes"),
        "memory_limit_source": snapshot.get("memory_limit_source"),
        "memory_explanation": "The app can only use memory available to the container or VM. Your physical machine may have more RAM.",
        "disk_free": snapshot.get("disk_free_bytes"),
        "disk_status": snapshot.get("disk_status"),
        "disk_used_percent": snapshot.get("disk_used_percent"),
        "opensearch_health": services.get("opensearch", {}).get("cluster_status"),
        "opensearch_heap_percent": services.get("opensearch", {}).get("heap_used_percent"),
        "opensearch_disk_watermark": services.get("opensearch", {}).get("disk_watermark"),
        "opensearch_write_blocked": services.get("opensearch", {}).get("write_blocked"),
        "opensearch_ingest_writable": services.get("opensearch", {}).get("ingest_writable"),
        "opensearch_watermark_risk": services.get("opensearch", {}).get("watermark_risk"),
        "redis_queue_status": snapshot.get("queues"),
        "active_workers": services.get("worker", {}).get("active"),
        "worker_queues": services.get("worker", {}).get("queues"),
        "current_concurrency": {
            "backend_workers": deployment_current.get("BACKEND_UVICORN_WORKERS"),
            "worker_scale": deployment_pending.get("WORKER_SCALE", deployment_current.get("WORKER_SCALE")),
            "ingest_parallelism": runtime.get("MAX_PARALLEL_ARTIFACTS"),
            "desired_ingest_parallelism": ingest_parallel.get("desired_parallelism"),
            "effective_ingest_parallelism": ingest_parallel.get("effective_parallelism"),
            "ingest_parallelism_reason": ingest_parallel.get("limit_reason"),
            "rules_parallelism": runtime.get("MAX_PARALLEL_RULE_RUNS"),
            "sigma_max_matches_per_rule": runtime.get("SIGMA_MAX_MATCHES_PER_RULE"),
            "sigma_max_detections_per_rule": runtime.get("SIGMA_MAX_DETECTIONS_PER_RULE"),
            "detection_write_batch_size": runtime.get("DETECTION_WRITE_BATCH_SIZE"),
            "duplicate_lookup_batch_size": runtime.get("DETECTION_DUPLICATE_LOOKUP_BATCH_SIZE"),
        },
        "current_profile": profile,
        "warnings": build_resource_warnings({**snapshot, "opensearch_status": services.get("opensearch", {}).get("status")}, profile),
    }


def performance_state(db: Session) -> dict[str, Any]:
    profile = get_performance_profile(db)
    runtime = _runtime_effective_settings(db)
    deployment_current = _deployment_current_settings()
    deployment_pending = _deployment_pending_settings(db)
    effective_settings = {
        SETTING_ALIASES[key]: value for key, value in {**runtime, **deployment_current}.items()
    }
    pending_settings = {
        SETTING_ALIASES[key]: value for key, value in deployment_pending.items()
    }
    requires_restart = sorted({SETTING_META[key]["restart_scope"] for key in deployment_pending})
    services_to_restart = _services_for_restart_scopes(requires_restart)
    restart_info = manual_restart_instructions(services_to_restart)
    system = system_snapshot()
    system_warnings = build_resource_warnings(system, profile)
    services = system.pop("services")
    queues = system.pop("queues")
    storage = storage_capabilities()
    deployment_pending_details = []
    for key, value in deployment_pending.items():
        alias = SETTING_ALIASES[key]
        deployment_pending_details.append(
            {
                "name": alias,
                "key": key,
                "old_value": deployment_current[key],
                "new_value": value,
                "scope": "deployment",
                "status": "requires_restart",
                "requires_restart_services": _services_for_restart_scopes([SETTING_META[key]["restart_scope"]]),
                "diagnostic": _deployment_change_diagnostic(key, deployment_current[key], value),
            }
        )
    return {
        "profile": profile,
        "effective_settings": effective_settings,
        "pending_settings": pending_settings,
        "requires_restart": requires_restart,
        "restart_supported": restart_info["restart_supported"],
        "restart_method": restart_info["restart_method"],
        "services_to_restart": services_to_restart,
        "restart_instructions": restart_info["restart_instructions"],
        "system": {
            **system,
            "warnings": system_warnings,
            "allowed_roots": storage["allowed_roots"],
            "allow_host_path_import": storage["allow_host_path_import"],
            "cpu_count_host": system.get("cpu_count_host"),
            "cpu_count_container": system.get("cpu_count_container"),
            "memory_container_limit_bytes": system.get("memory_container_limit_bytes"),
        },
        "services": {
            **services,
            "queues": queues,
        },
        "resources": performance_resources(db),
        "evidence_storage": storage,
        "deployment": {
            "restart_enabled": bool(storage.get("restart_enabled")),
            "can_edit_deployment_settings": bool(storage.get("can_edit_deployment_settings")),
            "restart_commands": storage.get("restart_commands") or [],
            "restart_supported": restart_info["restart_supported"],
            "restart_method": restart_info["restart_method"],
            "services_to_restart": services_to_restart,
            "restart_instructions": restart_info["restart_instructions"],
            "pending_changes": deployment_pending_details,
        },
        "settings": performance_setting_entries(db),
        "profiles": {
            name: {SETTING_ALIASES[key]: value for key, value in values.items()}
            for name, values in PERFORMANCE_PROFILES.items()
        },
        "recommendation": build_recommendation_payload({**system, "opensearch_status": services.get("opensearch", {}).get("status")}),
        "queue_architecture": {
            "current_worker_queues": services.get("worker", {}).get("queues", {}),
            "recommended_workers": ["worker-ingest", "worker-rules", "worker-heavy", "worker-maintenance"],
            "recommended_queues": ["dfir-ingest", "dfir-rules", "dfir-heavy", "dfir-maintenance"],
            "mode": "single-worker-safe" if int(services.get("worker", {}).get("active") or 0) <= 1 else "shared-workers",
        },
    }


def validate_and_normalize_settings(profile: str, incoming: dict[str, Any] | None = None) -> dict[str, Any]:
    normalized_profile = str(profile or "balanced").strip().lower()
    if normalized_profile not in {"safe", "balanced", "performance", "max", "custom"}:
        raise ValueError("profile must be safe, balanced, performance, max or custom")
    desired: dict[str, Any] = {}
    if normalized_profile != "custom":
        desired.update(PERFORMANCE_PROFILES[normalized_profile])
    for alias, value in (incoming or {}).items():
        key = ALIAS_TO_KEY.get(alias, alias if alias in SETTING_META else None)
        if not key or key not in SETTING_META:
            raise ValueError(f"Unknown setting: {alias}")
        desired[key] = _coerce_value(key, value)
    if normalized_profile == "custom" and not desired:
        raise ValueError("custom profile requires at least one setting override")
    for key, value in list(desired.items()):
        desired[key] = _coerce_value(key, value)
    return desired


def _services_for_restart_scopes(scopes: list[str]) -> list[str]:
    ordered: list[str] = []
    for scope in scopes:
        items: list[str]
        if scope == "worker":
            items = ["worker"]
        elif scope == "backend":
            items = ["backend"]
        elif scope == "opensearch":
            items = ["opensearch"]
        elif scope == "full_stack":
            items = ["backend", "worker", "frontend"]
        else:
            items = []
        for item in items:
            if item not in ordered:
                ordered.append(item)
    return ordered


def _deployment_change_diagnostic(key: str, old_value: Any, new_value: Any) -> dict[str, Any]:
    if key == "OPENSEARCH_JAVA_HEAP":
        return {
            "setting_key": key,
            "setting_name": SETTING_ALIASES.get(key, key),
            "current_value": old_value,
            "expected_value": new_value,
            "affected_services": ["opensearch"],
            "change_location": {
                "type": "env_file",
                "path": ".env",
                "variable": "OPENSEARCH_JAVA_HEAP",
                "compose_reference": "docker-compose.yml -> services.opensearch.environment.OPENSEARCH_JAVA_OPTS",
            },
            "reason": "The service is still running with the old JVM heap value from deployment configuration.",
            "steps": [
                "Edit .env and set OPENSEARCH_JAVA_HEAP to the expected value.",
                "Recreate opensearch so the container picks up the new heap setting.",
            ],
            "commands": [
                f"OPENSEARCH_JAVA_HEAP={new_value}",
                "docker compose up -d --build opensearch",
            ],
        }
    if key == "BACKEND_UVICORN_WORKERS":
        return {
            "setting_key": key,
            "setting_name": SETTING_ALIASES.get(key, key),
            "current_value": old_value,
            "expected_value": new_value,
            "affected_services": ["backend"],
            "change_location": {
                "type": "env_file",
                "path": ".env",
                "variable": "BACKEND_UVICORN_WORKERS",
                "compose_reference": "docker-compose.yml -> services.backend.command",
            },
            "reason": "The backend container restarted, but it is still starting uvicorn with the old worker count.",
            "steps": [
                "Edit .env and set BACKEND_UVICORN_WORKERS to the expected value.",
                "Recreate backend so uvicorn starts with the new worker count.",
            ],
            "commands": [
                f"BACKEND_UVICORN_WORKERS={new_value}",
                "docker compose up -d --build backend",
            ],
        }
    if key == "WORKER_SCALE":
        return {
            "setting_key": key,
            "setting_name": SETTING_ALIASES.get(key, key),
            "current_value": old_value,
            "expected_value": new_value,
            "affected_services": ["worker"],
            "change_location": {
                "type": "compose_scale",
                "path": "docker compose runtime scale",
                "variable": "WORKER_SCALE",
                "compose_reference": "docker-compose.yml -> services.worker (scaled via docker compose up --scale)",
            },
            "reason": "Worker scale is not changed by a plain restart. The compose service count is still at the old value.",
            "steps": [
                "Scale the worker service to the expected count from the deployment directory.",
                "Use docker compose up with --scale so the extra worker containers are actually created.",
            ],
            "commands": [
                f"docker compose up -d --scale worker={new_value}",
                f"docker compose up -d --build worker --scale worker={new_value}",
            ],
        }
    return {
        "setting_key": key,
        "setting_name": SETTING_ALIASES.get(key, key),
        "current_value": old_value,
        "expected_value": new_value,
        "affected_services": _services_for_restart_scopes([SETTING_META[key]["restart_scope"]]),
        "change_location": {
            "type": "deployment",
            "path": ".env or docker-compose.yml",
            "variable": key,
            "compose_reference": None,
        },
        "reason": "The deployment configuration still differs from the saved desired value.",
        "steps": ["Update the deployment configuration.", "Recreate the affected services."],
        "commands": [],
    }


def manual_restart_instructions(services: list[str]) -> dict[str, Any]:
    ordered = [str(item).strip() for item in services if str(item).strip()]
    if not ordered:
        ordered = ["backend", "worker"]
    service_list = " ".join(ordered)
    return {
        "restart_supported": False,
        "restart_method": "manual",
        "services_to_restart": ordered,
        "restart_instructions": {
            "title": "Manual restart required",
            "description": "Run these commands on the server where Kairon DFIR is deployed.",
            "commands": [
                {
                    "label": "Restart affected services",
                    "command": f"docker compose restart {service_list}",
                },
                {
                    "label": "Rebuild if environment or image settings changed",
                    "command": f"docker compose up -d --build {service_list}",
                },
            ],
            "notes": [
                "Use restart for runtime service reloads.",
                "Use up -d --build when Docker image, environment variables or compose settings changed.",
                "The web UI cannot restart Docker services in this deployment.",
                "Do not run these commands on your analyst workstation unless the application is deployed there.",
            ],
        },
    }


def save_performance_profile(
    db: Session,
    profile: str,
    settings_patch: dict[str, Any] | None = None,
    *,
    confirm_max: bool = False,
) -> dict[str, Any]:
    normalized_profile = str(profile or "balanced").strip().lower()
    if normalized_profile == "max" and not confirm_max:
        raise ValueError("max profile requires explicit confirmation")
    desired = validate_and_normalize_settings(normalized_profile, settings_patch)
    updated_keys: list[str] = []
    runtime_applied: list[str] = []
    requires_restart: list[str] = []
    warnings: list[str] = []
    set_setting(db, PERFORMANCE_PROFILE_KEY, normalized_profile)
    updated_keys.append(PERFORMANCE_PROFILE_KEY)
    for key, value in desired.items():
        set_setting(db, key, value)
        updated_keys.append(key)
        meta = SETTING_META[key]
        if meta["applies_immediately"]:
            runtime_applied.append(key)
        elif meta["restart_scope"] not in requires_restart:
            requires_restart.append(meta["restart_scope"])
    services_to_restart = _services_for_restart_scopes(requires_restart)
    restart_info = manual_restart_instructions(services_to_restart)
    if "worker" in requires_restart:
        worker_scale = desired.get("WORKER_SCALE", DEPLOYMENT_DEFAULTS["WORKER_SCALE"])
        warnings.append(f"Run: docker compose up -d --scale worker={worker_scale}")
    if "backend" in requires_restart:
        warnings.append("Run: docker compose up -d --force-recreate backend")
    if "opensearch" in requires_restart:
        heap = desired.get("OPENSEARCH_JAVA_HEAP", DEPLOYMENT_DEFAULTS["OPENSEARCH_JAVA_HEAP"])
        warnings.append(f"Set OPENSEARCH_JAVA_HEAP={heap} and run: docker compose up -d --force-recreate opensearch")
    if "full_stack" in requires_restart:
        warnings.append("Update Docker resource limits and recreate affected services")
    return {
        "saved": True,
        "profile": normalized_profile,
        "updated": updated_keys,
        "runtime_applied": runtime_applied,
        "requires_restart": requires_restart,
        "applied_now": runtime_applied,
        "pending_restart": requires_restart,
        "services_to_restart": services_to_restart,
        "restart_supported": restart_info["restart_supported"],
        "restart_method": restart_info["restart_method"],
        "restart_instructions": restart_info["restart_instructions"],
        "warnings": warnings,
        "effective_after_restart": performance_state(db),
    }


def apply_recommended_profile(db: Session, *, confirm_max: bool = False) -> dict[str, Any]:
    recommendation = build_recommendation_payload()
    profile = str(recommendation.get("recommended_profile") or "balanced")
    result = save_performance_profile(db, profile, confirm_max=confirm_max)
    result["recommendation"] = recommendation
    return result


def restart_plan(services: list[str]) -> dict[str, Any]:
    requested = [str(item).strip() for item in services if str(item).strip()]
    if not requested:
        raise ValueError("services must not be empty")
    restart_info = manual_restart_instructions(requested)
    return {
        "accepted": True,
        "services": requested,
        "restart_enabled": False,
        "message": "Manual restart required in this deployment mode",
        **restart_info,
    }


def performance_snapshot_for_ingest(
    db: Session,
    *,
    profile_override: str | None = None,
    runtime_overrides: dict[str, Any] | None = None,
) -> dict[str, Any]:
    runtime = _runtime_effective_settings(db)
    profile = str(profile_override or get_performance_profile(db) or "balanced").strip().lower()
    if runtime_overrides:
        runtime.update(dict(runtime_overrides))
    return {
        "performance_profile": profile,
        "effective_settings": {
            SETTING_ALIASES[key]: runtime[key]
            for key in (
                "INGEST_BATCH_SIZE",
                "OPENSEARCH_BULK_DOCS",
                "OPENSEARCH_BULK_BYTES",
                "OPENSEARCH_BULK_TIMEOUT",
                "OPENSEARCH_REFRESH_TIMEOUT",
                "MAX_PARALLEL_ARTIFACTS",
                "MAX_PARALLEL_RULE_RUNS",
                "MOUNTED_PATH_SCAN_LIMIT",
                "SIGMA_MAX_MATCHES_PER_RULE",
                "SIGMA_MAX_DETECTIONS_PER_RULE",
                "SIGMA_NOISY_RULE_THRESHOLD",
                "DETECTION_WRITE_BATCH_SIZE",
                "DETECTION_DUPLICATE_LOOKUP_BATCH_SIZE",
                "METADATA_UPDATE_THROTTLE_SECONDS",
            )
        },
    }
