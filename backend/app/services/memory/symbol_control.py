from __future__ import annotations

import os
import stat
from pathlib import Path

from sqlalchemy.orm import Session

from app.core.config import get_settings
from app.core.database import utc_now_naive
from app.models.memory import (
    MemoryCachedSymbol,
    MemoryScanRun,
    MemorySymbolAcquisition,
    MemorySymbolAcquisitionRequest,
    MemorySymbolRequirement,
)
from app.services.memory.symbol_approval import (
    ApprovalError,
    active_approval_for_request,
    consume_approval,
    ensure_pending_request,
    requirement_fingerprint,
)
from app.services.memory.symbol_fetcher import SymbolFetchError, SymbolIdentity
from app.services.memory.symbol_worker_capability import fetcher_online
from redis import Redis
from rq import Queue


# Status / error codes shared with the API and CLI.
NETWORK_ISOLATION_REQUIRED = "SYMBOL_ACQUISITION_NETWORK_ISOLATION_REQUIRED"
LOCAL_APPROVAL_DISABLED = "SYMBOL_ACQUISITION_LOCAL_APPROVAL_DISABLED"
ADMIN_AUTH_REQUIRED = "SYMBOL_ACQUISITION_ADMIN_AUTH_REQUIRED"


class SymbolControlError(RuntimeError):
    def __init__(self, code: str, message: str):
        super().__init__(message)
        self.code = code
        self.message = message


def acquisition_gate(settings=None) -> tuple[bool, str | None, str]:
    """Report whether the system is ready to accept *executable* acquisitions.

    The check is conservative: even if isolation and approval are ready, an
    acquisition still requires an active approval on a specific request.  Use
    ``request_symbol_acquisition_awaiting_approval`` for the full lifecycle.
    """
    settings = settings or get_settings()
    if settings.memory_symbol_execution_mode != "managed_download" or not settings.memory_symbol_managed_download_enabled:
        return False, "SYMBOL_ACQUISITION_DISABLED", "Managed symbol acquisition is disabled. Offline-only mode remains active."
    if not settings.memory_symbol_network_isolation_ready:
        return False, NETWORK_ISOLATION_REQUIRED, "Managed symbol acquisition is unavailable until restricted egress is verified by an administrator."
    local_approval_enabled = bool(getattr(settings, "memory_symbol_local_approval_enabled", False))
    admin_required = bool(getattr(settings, "memory_symbol_admin_authorization_required", True))
    if admin_required and not local_approval_enabled:
        return False, LOCAL_APPROVAL_DISABLED, "Managed symbol acquisition is unavailable until local-operator approval is enabled."
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
        pdb_age=int(identity.age),
        requested_pdb_age=int(identity.age),
        age_corrected=False,
        architecture=identity.architecture,
        symbol_key=identity.key,
        status="unavailable_offline",
        source="probe",
        confidence="high",
        metadata_json={},
        sanitized_message="Required Windows symbols are not present in the offline cache.",
    )
    db.add(requirement)
    db.commit()
    return requirement


# ---------------------------------------------------------------------------
# New lifecycle
# ---------------------------------------------------------------------------

def request_symbol_acquisition_awaiting_approval(db: Session, *, case_id: str, evidence_id: str) -> MemorySymbolAcquisitionRequest:
    """Idempotent: ensure a pending acquisition request exists for the evidence.

    The request transitions through:

    awaiting_network_isolation
      -> awaiting_operator_approval
        -> approved (after CLI approval)
          -> queued -> ... -> completed
    """
    return ensure_pending_request(db, case_id=case_id, evidence_id=evidence_id)


def queue_symbol_acquisition(db: Session, case_id: str, evidence_id: str, *, settings=None) -> MemorySymbolAcquisition:
    """Queue a managed acquisition after verifying all gates.

    * The request MUST have a currently active approval bound to the same
      requirement fingerprint.
    * The approval is consumed atomically.
    * Exactly one MemorySymbolAcquisition row is created.
    """
    settings = settings or get_settings()
    available, error_code, message = acquisition_gate(settings)
    if not available:
        raise SymbolControlError(error_code or "SYMBOL_ACQUISITION_DISABLED", message)

    request = (
        db.query(MemorySymbolAcquisitionRequest)
        .filter(
            MemorySymbolAcquisitionRequest.case_id == case_id,
            MemorySymbolAcquisitionRequest.evidence_id == evidence_id,
            MemorySymbolAcquisitionRequest.status.in_(
                ["awaiting_operator_approval", "approved", "queued", "resolving", "downloading", "validating_pdb", "generating_isf", "validating_isf", "caching"]
            ),
        )
        .order_by(MemorySymbolAcquisitionRequest.created_at.desc())
        .first()
    )
    if request is None:
        raise SymbolControlError("SYMBOL_REQUIREMENT_MISSING", "The exact Windows symbol requirement has not been recorded.")
    if request.status == "awaiting_operator_approval":
        raise SymbolControlError("SYMBOL_APPROVAL_REQUIRED", "The acquisition requires an active local-operator approval.")

    requirement = db.get(MemorySymbolRequirement, request.requirement_id)
    if requirement is None:
        raise SymbolControlError("SYMBOL_REQUIREMENT_MISSING", "The exact Windows symbol requirement has not been recorded.")
    fingerprint = requirement_fingerprint(requirement)
    if request.requirement_fingerprint != fingerprint:
        raise SymbolControlError("SYMBOL_APPROVAL_FINGERPRINT_MISMATCH", "The approval is bound to a different symbol identity.")

    # Consume the active approval atomically.
    try:
        consume_approval(db, request_id=request.id, requirement_fingerprint_value=fingerprint)
    except ApprovalError as exc:
        raise SymbolControlError(exc.code, exc.message) from exc

    # Skip work if the symbol is already cached.
    cached = (
        db.query(MemoryCachedSymbol)
        .filter(
            MemoryCachedSymbol.symbol_key == requirement.symbol_key,
            MemoryCachedSymbol.cache_classification == "exact",
        )
        .first()
    )
    if cached:
        completed = MemorySymbolAcquisition(
            requirement_id=requirement.id,
            status="completed",
            validated=True,
            cached=True,
            completed_at=utc_now_naive(),
        )
        db.add(completed)
        requirement.status, requirement.cached_symbol_id = "cached", cached.id
        request.status = "completed"
        request.queued_at = request.queued_at or utc_now_naive()
        request.started_at = request.started_at or utc_now_naive()
        request.completed_at = utc_now_naive()
        request.sanitized_message = "The required symbol was already present in the cache."
        db.commit()
        return completed

    # Prevent duplicate active acquisitions for the same symbol.
    active = (
        db.query(MemorySymbolAcquisition)
        .join(MemorySymbolRequirement, MemorySymbolRequirement.id == MemorySymbolAcquisition.requirement_id)
        .filter(
            MemorySymbolRequirement.symbol_key == requirement.symbol_key,
            MemorySymbolAcquisition.status.in_(
                ["queued", "resolving", "connecting", "downloading", "validating_pdb", "generating_isf", "validating_isf", "caching"]
            ),
        )
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

    acquisition = MemorySymbolAcquisition(requirement_id=requirement.id, status="queued")
    db.add(acquisition)
    db.flush()
    request.status = "queued"
    request.queued_at = utc_now_naive()
    request.downloaded_bytes = 0
    request.redirect_count = 0
    requirement.status = "acquisition_queued"
    requirement.acquisition_request_id = acquisition.id
    db.commit()
    Queue(settings.memory_symbol_queue_name, connection=redis_conn).enqueue(
        "app.workers.symbol_tasks.acquire_windows_symbol",
        acquisition.id,
        request.id,
        job_timeout=max(60, int(settings.memory_symbol_download_timeout_seconds) + 300),
    )
    return acquisition


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
    cached = (
        db.query(MemoryCachedSymbol)
        .filter(
            MemoryCachedSymbol.symbol_key == requirement.symbol_key,
            MemoryCachedSymbol.cache_classification == "exact",
        )
        .first()
        if requirement
        else None
    )
    symbols_required = failed_run is not None and cached is None
    pending_request = (
        db.query(MemorySymbolAcquisitionRequest)
        .filter(
            MemorySymbolAcquisitionRequest.case_id == case_id,
            MemorySymbolAcquisitionRequest.evidence_id == evidence_id,
            MemorySymbolAcquisitionRequest.status.in_(
                ["awaiting_network_isolation", "awaiting_operator_approval", "approved", "queued", "resolving", "downloading", "validating_pdb", "generating_isf", "validating_isf", "caching"]
            ),
        )
        .order_by(MemorySymbolAcquisitionRequest.created_at.desc())
        .first()
    )
    return {
        "symbols_required": symbols_required,
        "symbol_identifier_present": requirement is not None,
        "acquisition_available": bool(available and symbols_required and requirement is not None and pending_request is not None),
        "acquisition_status": pending_request.status if pending_request else (requirement.status if requirement else ("symbols_required" if symbols_required else None)),
        "can_analyze_offline": cached is not None or not symbols_required,
        "pending_request_id": pending_request.id if pending_request else None,
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
        active = db.query(MemorySymbolAcquisition).filter(
            MemorySymbolAcquisition.status.in_(["queued", "resolving", "connecting", "downloading", "validating_pdb", "generating_isf", "validating_isf", "caching"])
        ).count()
        failed = db.query(MemorySymbolAcquisition).filter(
            MemorySymbolAcquisition.status.in_(["failed", "timeout", "stale", "rejected"])
        ).count()
        latest = db.query(MemorySymbolAcquisition).filter(MemorySymbolAcquisition.status == "completed").order_by(MemorySymbolAcquisition.completed_at.desc()).first()
        last_success = latest.completed_at if latest else None
    try:
        online = fetcher_online(Redis.from_url(settings.redis_url))
    except Exception:
        online = False
    pending_requests = 0
    approved_pending = 0
    awaiting_approval = 0
    if db is not None:
        pending_requests = db.query(MemorySymbolAcquisitionRequest).filter(
            MemorySymbolAcquisitionRequest.status.in_(["awaiting_network_isolation", "awaiting_operator_approval", "approved", "queued", "resolving", "downloading", "validating_pdb", "generating_isf", "validating_isf", "caching"])
        ).count()
        awaiting_approval = db.query(MemorySymbolAcquisitionRequest).filter(
            MemorySymbolAcquisitionRequest.status == "awaiting_operator_approval"
        ).count()
        approved_pending = db.query(MemorySymbolAcquisitionRequest).filter(
            MemorySymbolAcquisitionRequest.status.in_(["approved", "queued", "resolving", "downloading", "validating_pdb", "generating_isf", "validating_isf", "caching"])
        ).count()
    return {
        "mode": settings.memory_symbol_execution_mode,
        "managed_download_enabled": bool(settings.memory_symbol_managed_download_enabled),
        "acquisition_enabled": available,
        "network_isolation_ready": bool(settings.memory_symbol_network_isolation_ready),
        "administrator_authorization_available": bool(getattr(settings, "memory_symbol_local_approval_enabled", False)),
        "local_approval_enabled": bool(getattr(settings, "memory_symbol_local_approval_enabled", False)),
        "pending_requests": pending_requests,
        "awaiting_operator_approval": awaiting_approval,
        "approved_pending": approved_pending,
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


def request_status_dict(request: MemorySymbolAcquisitionRequest, approval: MemorySymbolAcquisition | None = None) -> dict[str, object]:
    return {
        "request_id": request.id,
        "requirement_id": request.requirement_id,
        "case_id": request.case_id,
        "evidence_id": request.evidence_id,
        "status": request.status,
        "source_category": request.source_category,
        "requirement_fingerprint": request.requirement_fingerprint,
        "downloaded_bytes": request.downloaded_bytes,
        "redirect_count": request.redirect_count,
        "error_code": request.error_code,
        "sanitized_message": request.sanitized_message,
        "created_at": request.created_at,
        "updated_at": request.updated_at,
        "approved_at": request.approved_at,
        "approval_expires_at": request.approval_expires_at,
        "approval_consumed_at": request.approval_consumed_at,
        "queued_at": request.queued_at,
        "started_at": request.started_at,
        "completed_at": request.completed_at,
        "acquisition_id": approval.id if approval is not None else None,
    }
