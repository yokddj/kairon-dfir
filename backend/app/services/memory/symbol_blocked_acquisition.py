"""Managed exact symbol acquisition for memory evidence blocked by missing symbols.

The platform already exposes a single-purpose, isolated, signed
symbol-fetcher service (``app.workers.symbol_fetcher``) and an
allowlisted egress gateway (``app.services.memory.symbol_egress_gateway``).
This module is the operator-facing integration point that wires
those approved components into the bounded-discovery preparation
state machine.

The contract is intentionally narrow:

* The endpoint receives **only** the ``(case_id, evidence_id)``
  pair — the exact PDB name, GUID, age, and architecture are
  read exclusively from the persisted
  ``MemorySymbolRequirement`` produced by the bounded probe.

* Client-supplied URLs, PDB names, GUIDs, ages, architectures,
  or filesystem destinations are never accepted.

* The acquisition is enqueued on the ``memory-symbols`` queue,
  consumed only by the ``symbol-fetcher`` worker, which runs in
  an isolated Docker network with no default route to the
  public internet.  The normal ``memory-worker`` never opens a
  network connection.

* Only one active acquisition is allowed per
  ``MemorySymbolRequirement`` (``symbol_key`` uniqueness).

* Successful validation produces a ``MemoryCachedSymbol`` row
  whose ``symbol_key`` matches the requirement exactly.  A
  cached symbol with a different ``symbol_key`` (e.g. a
  different GUID or age) is never treated as satisfying the
  current requirement.
"""
from __future__ import annotations

from typing import Any

from redis import Redis
from rq import Queue
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
from app.services.memory import symbol_control as _symbol_control
from app.services.memory.symbol_control import SymbolControlError
from app.services.memory.symbol_fetcher import (
    SymbolFetchError,
    SymbolIdentity,
)
from app.services.memory.symbol_worker_capability import fetcher_online


# ---------------------------------------------------------------------------
# Error codes shared with the API and UI.
# ---------------------------------------------------------------------------

ACQ_NOTHING_TO_DO = "SYMBOL_ACQUISITION_NOTHING_TO_DO"
ACQ_REQUIREMENT_MISSING = "SYMBOL_REQUIREMENT_MISSING"
ACQ_FETCHER_OFFLINE = "SYMBOL_FETCHER_OFFLINE"
ACQ_CACHE_FULL = "SYMBOL_CACHE_FULL"
ACQ_DISPATCH_FAILED = "SYMBOL_DISPATCH_FAILED"
ACQ_DUPLICATE_FINGERPRINT = "SYMBOL_FINGERPRINT_DRIFT"


# State strings reported through the API for client UX.
# These mirror the ``MemorySymbolAcquisition.status`` enum.
ACQ_STATE_QUEUED = "queued"
ACQ_STATE_DOWNLOADING = "downloading"
ACQ_STATE_VALIDATING_PDB = "validating_pdb"
ACQ_STATE_GENERATING_ISF = "generating_isf"
ACQ_STATE_VALIDATING_ISF = "validating_isf"
ACQ_STATE_CACHING = "caching"
ACQ_STATE_COMPLETED = "completed"
ACQ_STATE_FAILED = "failed"
ACQ_STATE_TIMEOUT = "timeout"
ACQ_STATE_REJECTED = "rejected"

ACTIVE_ACQUISITION_STATES: tuple[str, ...] = (
    ACQ_STATE_QUEUED,
    "resolving",
    "connecting",
    ACQ_STATE_DOWNLOADING,
    ACQ_STATE_VALIDATING_PDB,
    ACQ_STATE_GENERATING_ISF,
    ACQ_STATE_VALIDATING_ISF,
    ACQ_STATE_CACHING,
)


class BlockedAcquisitionError(RuntimeError):
    def __init__(self, code: str, message: str, *, retryable: bool = False, http_status: int = 503):
        super().__init__(message)
        self.code = code
        self.message = message
        self.retryable = retryable
        self.http_status = http_status


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


def load_active_requirement(db: Session, *, case_id: str, evidence_id: str) -> MemorySymbolRequirement | None:
    """Return the latest persisted requirement for the evidence, if any.

    The bounded-discovery probe may persist multiple
    ``MemorySymbolRequirement`` rows for a given evidence if the
    analyst re-runs the probe with a different symbol hypothesis.
    The bounded flow guarantees that the most recently persisted
    row is the authoritative one for the current ``blocked_symbols``
    preparation.
    """
    return (
        db.query(MemorySymbolRequirement)
        .filter(
            MemorySymbolRequirement.case_id == case_id,
            MemorySymbolRequirement.evidence_id == evidence_id,
        )
        .order_by(MemorySymbolRequirement.created_at.desc())
        .first()
    )


def find_exact_cache(db: Session, requirement: MemorySymbolRequirement) -> MemoryCachedSymbol | None:
    """Return the validated cache entry whose identity matches exactly.

    Identity match is computed solely from the persisted
    ``symbol_key`` (PDB name lowercase + GUID upper + age).  The
    architecture is checked as a secondary safeguard so a
    cross-architecture entry cannot accidentally satisfy a
    same-symbol-key, different-arch requirement.
    """
    cached = (
        db.query(MemoryCachedSymbol)
        .filter(MemoryCachedSymbol.symbol_key == requirement.symbol_key)
        .first()
    )
    if cached is None:
        return None
    if (cached.architecture or "").lower() != (requirement.architecture or "").lower():
        return None
    return cached


def find_active_acquisition(db: Session, requirement: MemorySymbolRequirement) -> MemorySymbolAcquisition | None:
    """Return the in-flight acquisition for the exact symbol, if any.

    Identity is matched on ``MemorySymbolRequirement.symbol_key``
    so a different GUID or age produces a different ``symbol_key``
    and therefore a different active-acquisition scope.
    """
    return (
        db.query(MemorySymbolAcquisition)
        .join(MemorySymbolRequirement, MemorySymbolRequirement.id == MemorySymbolAcquisition.requirement_id)
        .filter(
            MemorySymbolRequirement.symbol_key == requirement.symbol_key,
            MemorySymbolAcquisition.status.in_(list(ACTIVE_ACQUISITION_STATES)),
        )
        .order_by(MemorySymbolAcquisition.created_at.desc())
        .first()
    )


def find_active_request(db: Session, requirement: MemorySymbolRequirement) -> MemorySymbolAcquisitionRequest | None:
    """Return the in-flight request for the exact symbol, if any."""
    return (
        db.query(MemorySymbolAcquisitionRequest)
        .filter(
            MemorySymbolAcquisitionRequest.requirement_id == requirement.id,
            MemorySymbolAcquisitionRequest.status.in_(
                [
                    "awaiting_network_isolation",
                    "awaiting_operator_approval",
                    "approved",
                    "queued",
                    "resolving",
                    "downloading",
                    "validating_pdb",
                    "generating_isf",
                    "validating_isf",
                    "caching",
                ]
            ),
        )
        .order_by(MemorySymbolAcquisitionRequest.created_at.desc())
        .first()
    )


def queue_blocked_symbols_acquisition(
    db: Session,
    case_id: str,
    evidence_id: str,
    *,
    settings: Any = None,
) -> dict[str, Any]:
    """Queue a managed acquisition for evidence blocked by missing symbols.

    The function is the single entry point for the operator-facing
    ``POST .../symbols/acquire`` route.  It is safe to call
    repeatedly: subsequent invocations return the same in-flight
    acquisition (or, if a validated cache entry already exists,
    return a ``completed`` result without touching the network).

    The HTTP request is never blocked on a download: the
    acquisition is enqueued on the isolated ``memory-symbols``
    queue and the function returns once the row is persisted.
    """
    settings = settings or get_settings()
    requirement = load_active_requirement(db, case_id=case_id, evidence_id=evidence_id)
    if requirement is None:
        raise BlockedAcquisitionError(
            ACQ_REQUIREMENT_MISSING,
            "The exact Windows symbol requirement has not been recorded for this evidence.",
            retryable=False,
            http_status=409,
        )
    try:
        identity = SymbolIdentity(
            requirement.pdb_name,
            requirement.pdb_guid,
            int(requirement.pdb_age),
            requirement.architecture,
        )
        identity.validate()
    except SymbolFetchError as exc:
        raise BlockedAcquisitionError(
            exc.code,
            "The recorded symbol identity failed validation; refusing to acquire.",
            retryable=False,
            http_status=409,
        ) from exc

    cached = find_exact_cache(db, requirement)
    if cached is not None:
        if requirement.cached_symbol_id != cached.id:
            requirement.status = "cached"
            requirement.cached_symbol_id = cached.id
            db.commit()
        return {
            "request_id": None,
            "acquisition_id": None,
            "requirement_id": str(requirement.id),
            "cached_symbol_id": str(cached.id),
            "state": ACQ_STATE_COMPLETED,
            "queue": settings.memory_symbol_queue_name,
            "task_id": None,
            "task_alive": False,
            "retryable": False,
            "source_category": cached.source_category,
            "pdb_name": cached.pdb_name,
            "pdb_guid": cached.pdb_guid,
            "pdb_age": int(cached.pdb_age),
            "architecture": cached.architecture,
            "symbol_key": cached.symbol_key,
            "message": "The exact symbol is already present in the validated cache.",
            "error_code": None,
        }

    available, gate_code, gate_message = _symbol_control.acquisition_gate(settings)
    if not available:
        raise BlockedAcquisitionError(
            gate_code or "SYMBOL_ACQUISITION_DISABLED",
            gate_message,
            retryable=False,
            http_status=503,
        )

    active = find_active_acquisition(db, requirement)
    active_request = find_active_request(db, requirement)
    if active is not None and active_request is not None:
        return _dispatch_payload(
            requirement=requirement,
            request=active_request,
            acquisition=active,
            settings=settings,
        )

    redis_conn = Redis.from_url(settings.redis_url)
    if not fetcher_online(redis_conn):
        raise BlockedAcquisitionError(
            ACQ_FETCHER_OFFLINE,
            "The isolated symbol fetcher is not online. Verify the symbol-fetcher container is running.",
            retryable=True,
            http_status=503,
        )

    total, _, _ = _symbol_control._cache_usage(settings.memory_symbol_cache_path)
    if total + int(settings.memory_symbol_download_max_bytes) > int(settings.memory_symbol_cache_max_bytes):
        raise BlockedAcquisitionError(
            ACQ_CACHE_FULL,
            "The configured symbol cache capacity is insufficient for the next download.",
            retryable=False,
            http_status=507,
        )

    now = utc_now_naive()
    request = MemorySymbolAcquisitionRequest(
        requirement_id=requirement.id,
        case_id=case_id,
        evidence_id=evidence_id,
        status="queued",
        source_category="official_microsoft_symbols",
        requirement_fingerprint=_fingerprint(requirement),
        queued_at=now,
        sanitized_message="The acquisition was queued on the isolated symbol-fetcher queue.",
    )
    db.add(request)
    db.flush()
    acquisition = MemorySymbolAcquisition(
        requirement_id=requirement.id,
        status="queued",
    )
    db.add(acquisition)
    db.flush()
    requirement.status = "acquisition_queued"
    requirement.acquisition_request_id = acquisition.id
    db.commit()

    queue = Queue(settings.memory_symbol_queue_name, connection=redis_conn)
    try:
        job = queue.enqueue(
            "app.workers.symbol_tasks.acquire_windows_symbol",
            acquisition.id,
            request.id,
            job_timeout=max(60, int(settings.memory_symbol_download_timeout_seconds) + 300),
        )
    except Exception as exc:  # noqa: BLE001
        acquisition.status = "failed"
        acquisition.error_code = ACQ_DISPATCH_FAILED
        acquisition.sanitized_message = f"The symbol-fetcher queue rejected the job: {type(exc).__name__}: {str(exc)[:200]}"
        acquisition.completed_at = utc_now_naive()
        request.status = "failed"
        request.error_code = acquisition.error_code
        request.sanitized_message = acquisition.sanitized_message
        request.completed_at = utc_now_naive()
        db.commit()
        raise BlockedAcquisitionError(
            ACQ_DISPATCH_FAILED,
            "The symbol-fetcher queue rejected the job.",
            retryable=True,
            http_status=503,
        ) from exc

    request.metadata_json = {**(request.metadata_json or {}), "rq_job_id": str(getattr(job, "id", "") or "")}
    db.commit()

    return _dispatch_payload(
        requirement=requirement,
        request=request,
        acquisition=acquisition,
        settings=settings,
        task_id=str(getattr(job, "id", "") or "") or None,
    )


def summarize_active_acquisition(
    db: Session,
    case_id: str,
    evidence_id: str,
    *,
    settings: Any = None,
) -> dict[str, Any] | None:
    """Return a read-only summary of the current acquisition, or ``None``."""
    settings = settings or get_settings()
    requirement = load_active_requirement(db, case_id=case_id, evidence_id=evidence_id)
    if requirement is None:
        return None
    cached = find_exact_cache(db, requirement)
    if cached is not None:
        return {
            "requirement_id": str(requirement.id),
            "cached_symbol_id": str(cached.id),
            "state": ACQ_STATE_COMPLETED,
            "queue": settings.memory_symbol_queue_name,
            "task_id": None,
            "task_alive": False,
            "retryable": False,
            "source_category": cached.source_category,
            "pdb_name": cached.pdb_name,
            "pdb_guid": cached.pdb_guid,
            "pdb_age": int(cached.pdb_age),
            "architecture": cached.architecture,
            "symbol_key": cached.symbol_key,
            "message": "The exact symbol is already present in the validated cache.",
            "error_code": None,
        }
    acquisition = find_active_acquisition(db, requirement)
    request = find_active_request(db, requirement)
    if acquisition is None or request is None:
        # Show the latest terminal state if there is one.
        latest = (
            db.query(MemorySymbolAcquisition)
            .filter(MemorySymbolAcquisition.requirement_id == requirement.id)
            .order_by(MemorySymbolAcquisition.created_at.desc())
            .first()
        )
        if latest is None:
            return None
        return {
            "requirement_id": str(requirement.id),
            "cached_symbol_id": None,
            "state": latest.status,
            "queue": settings.memory_symbol_queue_name,
            "task_id": None,
            "task_alive": False,
            "retryable": bool(latest.retryable),
            "source_category": "official_microsoft_symbols",
            "pdb_name": requirement.pdb_name,
            "pdb_guid": requirement.pdb_guid,
            "pdb_age": int(requirement.pdb_age),
            "architecture": requirement.architecture,
            "symbol_key": requirement.symbol_key,
            "message": latest.sanitized_message or "",
            "error_code": latest.error_code,
        }
    return _dispatch_payload(
        requirement=requirement,
        request=request,
        acquisition=acquisition,
        settings=settings,
    )


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _fingerprint(requirement: MemorySymbolRequirement) -> str:
    import hashlib

    payload = f"{requirement.pdb_name.lower()}|{requirement.pdb_guid.upper()}|{int(requirement.pdb_age)}|{requirement.architecture.lower()}"
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def _dispatch_payload(
    *,
    requirement: MemorySymbolRequirement,
    request: MemorySymbolAcquisitionRequest,
    acquisition: MemorySymbolAcquisition,
    settings: Any,
    task_id: str | None = None,
) -> dict[str, Any]:
    retryable = bool(acquisition.retryable) or acquisition.status in {ACQ_STATE_FAILED, ACQ_STATE_TIMEOUT}
    return {
        "request_id": str(request.id),
        "acquisition_id": str(acquisition.id),
        "requirement_id": str(requirement.id),
        "cached_symbol_id": None,
        "state": acquisition.status,
        "queue": settings.memory_symbol_queue_name,
        "task_id": task_id,
        "task_alive": acquisition.status in ACTIVE_ACQUISITION_STATES,
        "retryable": retryable,
        "source_category": request.source_category,
        "pdb_name": requirement.pdb_name,
        "pdb_guid": requirement.pdb_guid,
        "pdb_age": int(requirement.pdb_age),
        "architecture": requirement.architecture,
        "symbol_key": requirement.symbol_key,
        "message": (acquisition.sanitized_message or request.sanitized_message or ""),
        "error_code": acquisition.error_code,
    }


__all__ = [
    "ACQ_NOTHING_TO_DO",
    "ACQ_REQUIREMENT_MISSING",
    "ACQ_FETCHER_OFFLINE",
    "ACQ_CACHE_FULL",
    "ACQ_DISPATCH_FAILED",
    "ACQ_DUPLICATE_FINGERPRINT",
    "ACQ_STATE_QUEUED",
    "ACQ_STATE_DOWNLOADING",
    "ACQ_STATE_VALIDATING_PDB",
    "ACQ_STATE_GENERATING_ISF",
    "ACQ_STATE_VALIDATING_ISF",
    "ACQ_STATE_CACHING",
    "ACQ_STATE_COMPLETED",
    "ACQ_STATE_FAILED",
    "ACQ_STATE_TIMEOUT",
    "ACQ_STATE_REJECTED",
    "ACTIVE_ACQUISITION_STATES",
    "BlockedAcquisitionError",
    "find_active_acquisition",
    "find_active_request",
    "find_exact_cache",
    "load_active_requirement",
    "queue_blocked_symbols_acquisition",
    "summarize_active_acquisition",
]
