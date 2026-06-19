from __future__ import annotations

import os
import stat
from pathlib import Path

from sqlalchemy.orm import Session

from app.core.config import get_settings
from app.core.database import utc_now_naive
from app.models.memory import MemoryCachedSymbol, MemoryScanRun, MemorySymbolAcquisition, MemorySymbolRequirement
from app.services.memory.symbol_fetcher import SymbolFetchError, SymbolIdentity
from app.services.memory.symbol_worker_capability import fetcher_online
from redis import Redis
from rq import Queue


NETWORK_ISOLATION_REQUIRED = "SYMBOL_ACQUISITION_NETWORK_ISOLATION_REQUIRED"
ADMIN_AUTH_REQUIRED = "SYMBOL_ACQUISITION_ADMIN_AUTH_REQUIRED"
ADMIN_AUTHORIZATION_IMPLEMENTED = False


class SymbolControlError(RuntimeError):
    def __init__(self, code: str, message: str):
        super().__init__(message)
        self.code = code
        self.message = message


def acquisition_gate(settings=None) -> tuple[bool, str | None, str]:
    settings = settings or get_settings()
    if settings.memory_symbol_execution_mode != "managed_download" or not settings.memory_symbol_managed_download_enabled:
        return False, "SYMBOL_ACQUISITION_DISABLED", "Managed symbol acquisition is disabled. Offline-only mode remains active."
    if not settings.memory_symbol_network_isolation_ready:
        return False, NETWORK_ISOLATION_REQUIRED, "Managed symbol acquisition is unavailable until restricted egress is verified by an administrator."
    if settings.memory_symbol_admin_authorization_required and (not ADMIN_AUTHORIZATION_IMPLEMENTED or not settings.memory_symbol_admin_authorization_enforced):
        return False, ADMIN_AUTH_REQUIRED, "Managed symbol acquisition is unavailable until administrator authorization is enforced."
    if settings.memory_symbol_initial_host != "msdl.microsoft.com" or not settings.memory_symbol_redirect_host_suffixes:
        return False, "SYMBOL_SOURCE_NOT_ALLOWED", "No reviewed official symbol destinations are configured."
    return True, None, "Managed symbol acquisition is available."


def latest_symbols_failure(db: Session, case_id: str, evidence_id: str) -> MemoryScanRun | None:
    run = (
        db.query(MemoryScanRun)
        .filter(MemoryScanRun.case_id == case_id, MemoryScanRun.evidence_id == evidence_id)
        .order_by(MemoryScanRun.created_at.desc())
        .first()
    )
    return run if run is not None and (run.error_log or {}).get("code") == "SYMBOLS_UNAVAILABLE" else None


def record_symbol_requirement(db: Session, run: MemoryScanRun, plugin_run_id: str, payload: dict[str, object]) -> MemorySymbolRequirement | None:
    try:
        identity = SymbolIdentity(
            str(payload.get("pdb_name") or ""),
            str(payload.get("pdb_guid") or "").upper(),
            int(payload.get("pdb_age") or 0),
            str(payload.get("architecture") or "x64"),
        )
        identity.validate()
    except (SymbolFetchError, TypeError, ValueError):
        return None
    existing = db.query(MemorySymbolRequirement).filter(MemorySymbolRequirement.evidence_id == run.evidence_id, MemorySymbolRequirement.symbol_key == identity.key).first()
    if existing:
        return existing
    requirement = MemorySymbolRequirement(
        case_id=run.case_id,
        evidence_id=run.evidence_id,
        source_run_id=run.id,
        source_plugin_run_id=plugin_run_id,
        pdb_name=identity.pdb_name,
        pdb_guid=identity.guid,
        pdb_age=identity.age,
        architecture=identity.architecture,
        symbol_key=identity.key,
        status="unavailable_offline",
        sanitized_message="Required Windows symbols are not present in the offline cache.",
    )
    db.add(requirement)
    db.commit()
    return requirement


def queue_symbol_acquisition(db: Session, case_id: str, evidence_id: str, *, settings=None) -> MemorySymbolAcquisition:
    settings = settings or get_settings()
    requirement = (
        db.query(MemorySymbolRequirement)
        .filter(MemorySymbolRequirement.case_id == case_id, MemorySymbolRequirement.evidence_id == evidence_id)
        .order_by(MemorySymbolRequirement.created_at.desc())
        .first()
    )
    if requirement is None:
        raise SymbolControlError("SYMBOL_REQUIREMENT_MISSING", "The exact Windows symbol requirement has not been recorded.")
    cached = db.query(MemoryCachedSymbol).filter(MemoryCachedSymbol.symbol_key == requirement.symbol_key).first()
    if cached:
        completed = MemorySymbolAcquisition(requirement_id=requirement.id, status="completed", validated=True, cached=True, completed_at=utc_now_naive())
        db.add(completed)
        requirement.status, requirement.cached_symbol_id = "cached", cached.id
        db.commit()
        return completed
    active = (
        db.query(MemorySymbolAcquisition)
        .join(MemorySymbolRequirement, MemorySymbolRequirement.id == MemorySymbolAcquisition.requirement_id)
        .filter(MemorySymbolRequirement.symbol_key == requirement.symbol_key, MemorySymbolAcquisition.status.in_(["queued", "resolving", "connecting", "downloading", "validating_pdb", "generating_isf", "validating_isf", "caching"]))
        .first()
    )
    if active:
        return active
    redis_conn = Redis.from_url(settings.redis_url)
    if not fetcher_online(redis_conn):
        raise SymbolControlError("SYMBOL_FETCHER_OFFLINE", "The isolated symbol fetcher is not online.")
    total, _, _ = _cache_usage(settings.memory_symbol_cache_path)
    if total + int(settings.memory_symbol_download_max_bytes) > int(settings.memory_symbol_cache_max_bytes):
        raise SymbolControlError("SYMBOL_CACHE_FULL", "The configured symbol cache capacity is insufficient.")
    request = MemorySymbolAcquisition(requirement_id=requirement.id, status="queued")
    db.add(request)
    db.flush()
    requirement.status, requirement.acquisition_request_id = "acquisition_queued", request.id
    db.commit()
    Queue(settings.memory_symbol_queue_name, connection=redis_conn).enqueue(
        "app.workers.symbol_tasks.acquire_windows_symbol",
        request.id,
        job_timeout=max(60, int(settings.memory_symbol_download_timeout_seconds) + 300),
    )
    return request


def evidence_symbol_readiness(db: Session, case_id: str, evidence_id: str, *, settings=None) -> dict[str, object]:
    settings = settings or get_settings()
    failed_run = latest_symbols_failure(db, case_id, evidence_id)
    available, _, _ = acquisition_gate(settings)
    requirement = (
        db.query(MemorySymbolRequirement)
        .filter(MemorySymbolRequirement.case_id == case_id, MemorySymbolRequirement.evidence_id == evidence_id)
        .order_by(MemorySymbolRequirement.created_at.desc())
        .first()
    )
    cached = db.query(MemoryCachedSymbol).filter(MemoryCachedSymbol.symbol_key == requirement.symbol_key).first() if requirement else None
    symbols_required = failed_run is not None and cached is None
    return {
        "symbols_required": symbols_required,
        "symbol_identifier_present": requirement is not None,
        "acquisition_available": bool(available and symbols_required and requirement is not None),
        "acquisition_status": requirement.status if requirement else ("symbols_required" if symbols_required else None),
        "can_analyze_offline": cached is not None or not symbols_required,
    }


def _cache_usage(root: Path) -> tuple[int, int, int]:
    total = pdb_count = isf_count = 0
    try:
        root_stat = root.lstat()
    except OSError:
        return 0, 0, 0
    if not stat.S_ISDIR(root_stat.st_mode) or root.is_symlink():
        return 0, 0, 0
    for current, directories, files in os.walk(root, followlinks=False):
        directories[:] = [name for name in directories if not (Path(current) / name).is_symlink()]
        for name in files:
            candidate = Path(current) / name
            try:
                metadata = candidate.lstat()
            except OSError:
                continue
            if stat.S_ISREG(metadata.st_mode) and not candidate.is_symlink():
                total += metadata.st_size
                if name.lower().endswith(".pdb"):
                    pdb_count += 1
                if name.lower().endswith((".json", ".json.xz", ".isf")):
                    isf_count += 1
    return total, pdb_count, isf_count


def cache_status(*, settings=None, db: Session | None = None) -> dict[str, object]:
    settings = settings or get_settings()
    total, pdb_count, isf_count = _cache_usage(settings.memory_symbol_cache_path)
    maximum = max(0, int(settings.memory_symbol_cache_max_bytes))
    available, error_code, message = acquisition_gate(settings)
    active = failed = 0
    last_success = None
    if db is not None:
        active = db.query(MemorySymbolAcquisition).filter(MemorySymbolAcquisition.status.in_(["queued", "resolving", "connecting", "downloading", "validating_pdb", "generating_isf", "validating_isf", "caching"])).count()
        failed = db.query(MemorySymbolAcquisition).filter(MemorySymbolAcquisition.status.in_(["failed", "timeout", "stale", "rejected"])).count()
        latest = db.query(MemorySymbolAcquisition).filter(MemorySymbolAcquisition.status == "completed").order_by(MemorySymbolAcquisition.completed_at.desc()).first()
        last_success = latest.completed_at if latest else None
    try:
        online = fetcher_online(Redis.from_url(settings.redis_url))
    except Exception:
        online = False
    return {
        "mode": settings.memory_symbol_execution_mode,
        "managed_download_enabled": bool(settings.memory_symbol_managed_download_enabled),
        "acquisition_enabled": available,
        "network_isolation_ready": bool(settings.memory_symbol_network_isolation_ready),
        "administrator_authorization_available": bool(settings.memory_symbol_admin_authorization_enforced),
        "total_bytes": total,
        "configured_max_bytes": maximum,
        "max_bytes": maximum,
        "available_bytes": max(0, maximum - total),
        "symbol_count": isf_count,
        "pdb_count": pdb_count,
        "isf_count": isf_count,
        "fetcher_online": online,
        "active_requests": active,
        "failed_requests": failed,
        "last_success_at": last_success,
        "error_code": error_code,
        "message": message,
    }
