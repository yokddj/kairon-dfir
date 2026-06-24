"""OS-agnostic memory preparation runtime.

The v1 critical sprint introduced platform adapters and a
single documented queue for preparation.  This module owns
the worker-side logic:

1. ``execute_memory_preparation`` runs in the dedicated
   memory-worker.  It probes the image, evaluates readiness
   through the platform adapter and persists a terminal
   state.

2. ``dispatch_memory_preparation`` runs in the API after the
   evidence row commits.  It creates or reuses a single
   active preparation row and enqueues a worker task.

3. ``reconcile_stale_preparations`` is called periodically
   and on startup.  It re-dispatches a missing task at most
   once per row, and marks the row ``stale`` or
   ``dispatch_failed`` if the broker cannot accept the job.

The module never raises during dispatch: a preparation
failure becomes a structured error in the database row so
the UI can surface a Retry action.
"""
from __future__ import annotations

import logging
from datetime import datetime
from pathlib import Path
from typing import Any

from sqlalchemy.orm import Session

from app.core.config import get_settings
from app.core.database import SessionLocal, utc_now_naive

logger = logging.getLogger(__name__)


# Sprint 6: structured error codes for the preparation pipeline.
PREP_DISPATCH_FAILED = "MEMORY_PREPARATION_DISPATCH_FAILED"
PREP_QUEUE_MISMATCH = "MEMORY_PREPARATION_QUEUE_MISMATCH"
PREP_PLATFORM_NOT_IDENTIFIED = "PLATFORM_NOT_IDENTIFIED"
PREP_PLATFORM_NOT_SUPPORTED = "PLATFORM_NOT_SUPPORTED"
# Sprint: bounded Windows requirement discovery.
PREP_BLOCKED_SYMBOLS_ERROR = "WINDOWS_EXACT_SYMBOLS_MISSING"
PREP_REQUIREMENT_UNKNOWN_ERROR = "WINDOWS_REQUIREMENT_UNKNOWN"
PREP_DISCOVERY_FAILED_ERROR = "WINDOWS_DISCOVERY_FAILED"
PREP_STALE_TIMEOUT = "MEMORY_PREPARATION_STALE"


def _get_active_preparation(db: Session, evidence_id: str):
    from app.models.memory import MemorySymbolPreparation

    return (
        db.query(MemorySymbolPreparation)
        .filter(
            MemorySymbolPreparation.evidence_id == evidence_id,
            MemorySymbolPreparation.active == True,  # noqa: E712
        )
        .order_by(MemorySymbolPreparation.created_at.desc())
        .first()
    )


def _latest_terminal_preparation(db: Session, evidence_id: str):
    """Return the latest terminal preparation row for an evidence.

    Terminal states (ready, unsupported, cancelled) are kept
    as historical records.  The function looks at the most
    recent row of any state to decide whether the next call
    should create a new row.
    """
    from app.models.memory import MemorySymbolPreparation

    return (
        db.query(MemorySymbolPreparation)
        .filter(MemorySymbolPreparation.evidence_id == evidence_id)
        .order_by(MemorySymbolPreparation.created_at.desc())
        .first()
    )


def _evidence_canonical_path(evidence) -> Path:
    """Return the absolute path of the canonical blob."""
    stored = getattr(evidence, "stored_path", None) or getattr(evidence, "original_path", None)
    if not stored:
        raise ValueError("evidence is missing stored_path")
    return Path(stored)


def _evidence_filename(evidence) -> str | None:
    return (
        getattr(evidence, "original_filename", None)
        or getattr(evidence, "display_name", None)
        or getattr(evidence, "filename", None)
    )


def _probe_evidence(evidence) -> dict[str, Any]:
    """Run the bounded platform probe on the canonical blob.

    The probe is read-only and bounded to the first 4 KiB of
    the image.  It NEVER downloads symbols.
    """
    from app.services.memory.platform import probe_memory_platform

    try:
        path = _evidence_canonical_path(evidence)
    except ValueError as exc:
        return {
            "platform": "unknown",
            "format": "unknown",
            "architecture": "unknown",
            "confidence": "low",
            "reason": f"path_unavailable:{exc}",
            "adapter": "unsupported",
        }
    result = probe_memory_platform(
        canonical_path=path,
        detected_format=getattr(evidence, "detected_format", None),
        filename=_evidence_filename(evidence),
        use_volatility_fallback=True,
        evidence=evidence,
    )
    return {
        "platform": result.platform.value,
        "format": result.format,
        "architecture": result.architecture.value,
        "confidence": result.confidence.value,
        "reason": result.reason,
        "adapter": result.platform.value,
    }


def _cache_state_for(evidence) -> dict[str, Any]:
    """Read facts from the DB that influence the readiness decision.

    This thin wrapper exists for the probe / cache state
    correlation tests.  The real implementation that joins on
    the active session is :func:`_gather_cache_state`.
    """
    return {}


def _persist_heartbeat(prep, *, current_step: str, progress: int = 0) -> None:
    """Update a preparation row with a fresh heartbeat."""
    prep.last_heartbeat_at = utc_now_naive()
    prep.updated_at = utc_now_naive()
    prep.current_step = current_step
    if progress:
        prep.progress_percent = max(int(prep.progress_percent or 0), int(progress))


def _persist_terminal(
    prep,
    *,
    state: str,
    reason: str,
    error_code: str | None,
    sanitized_message: str | None = None,
    requirement_id: str | None = None,
    probe_metadata: dict[str, Any] | None = None,
) -> None:
    prep.state = state
    prep.state_reason = reason
    prep.error_code = error_code
    prep.sanitized_message = sanitized_message
    if requirement_id is not None:
        prep.requirement_id = requirement_id
    prep.completed_at = utc_now_naive()
    prep.last_heartbeat_at = utc_now_naive()
    prep.updated_at = utc_now_naive()
    prep.current_step = state
    if probe_metadata:
        meta = dict(prep.metadata_json or {})
        meta.update(probe_metadata)
        prep.metadata_json = meta


def dispatch_memory_preparation(
    db: Session,
    *,
    evidence,
    force: bool = False,
) -> dict[str, Any]:
    """Create or refresh a queued preparation and enqueue a task.

    Behaviour:

    * If the evidence already has a terminal preparation row
      (ready, unsupported, cancelled) AND ``force=False``, the
      function returns the existing row without enqueuing
      anything.
    * If the evidence already has an ``active=True`` row in
      any non-terminal state, the function REUSES the same
      row.  The partial unique index guarantees at most one
      active row per evidence.  This is the duplicate-request
      idempotency contract.
    * Otherwise it creates a single ``active=True``
      preparation row, calls ``enqueue_memory_preparation``
      and stores both the RQ job id and the queue name on
      the row.
    * If the enqueue raises, the row is marked
      ``dispatch_failed`` with the structured error code
      ``MEMORY_PREPARATION_DISPATCH_FAILED`` and is left
      retryable.

    The function never raises: the caller is the API route
    that returns the structured payload.
    """
    from app.models.memory import MemorySymbolPreparation
    from app.services.memory.symbol_preparation import (
        PREP_DISPATCH_FAILED_STATE,
        PREP_QUEUED,
        PREP_READY,
        PREP_UNSUPPORTED,
        PREP_CANCELLED,
    )
    from app.workers.tasks import enqueue_memory_preparation

    settings = get_settings()
    queue = settings.memory_queue_name

    terminal_states = {PREP_READY, PREP_UNSUPPORTED, PREP_CANCELLED}
    latest = _latest_terminal_preparation(db, evidence.id)
    if not force and latest is not None and latest.state in terminal_states:
        return {
            "preparation_id": latest.id,
            "state": latest.state,
            "task_active": False,
            "queue": latest.queue_name,
            "worker_task_id": latest.worker_task_id,
            "retryable": False,
        }

    # Sprint 6: reuse the active row if one already exists
    # (idempotent dispatch).  The row is reset to ``queued``
    # and the previous worker task id is preserved for
    # audit.  The partial unique index prevents duplicates
    # at the DB level.
    prep = _get_active_preparation(db, evidence.id)
    if prep is None:
        prep = MemorySymbolPreparation(
            case_id=evidence.case_id,
            evidence_id=evidence.id,
            state=PREP_QUEUED,
            state_reason="auto_dispatch",
            attempts=0,
            active=True,
            queue_name=queue,
            current_step="waiting_for_worker",
        )
        db.add(prep)
        try:
            db.flush()
        except Exception as exc:  # noqa: BLE001
            logger.exception("preparation row insert failed: %s", exc)
            db.rollback()
            return {
                "preparation_id": None,
                "state": PREP_DISPATCH_FAILED_STATE,
                "task_active": False,
                "queue": queue,
                "worker_task_id": None,
                "retryable": True,
                "error_code": PREP_DISPATCH_FAILED,
            }
    else:
        # Reset the existing active row.
        prep.state = PREP_QUEUED
        prep.state_reason = "auto_dispatch"
        prep.error_code = None
        prep.sanitized_message = None
        prep.current_step = "waiting_for_worker"
        prep.queue_name = queue

    # Commit the row BEFORE enqueueing so a broker outage
    # cannot leave the row un-inserted.
    try:
        db.commit()
        db.refresh(prep)
    except Exception as exc:  # noqa: BLE001
        logger.exception("preparation row commit failed: %s", exc)
        db.rollback()
        return {
            "preparation_id": None,
            "state": PREP_DISPATCH_FAILED_STATE,
            "task_active": False,
            "queue": queue,
            "worker_task_id": None,
            "retryable": True,
            "error_code": PREP_DISPATCH_FAILED,
        }

    # Enqueue after the commit.  Failures leave the row in
    # ``dispatch_failed`` so the operator can retry safely.
    try:
        job_id = enqueue_memory_preparation(evidence.id)
    except Exception as exc:  # noqa: BLE001
        logger.exception("preparation enqueue failed: %s", exc)
        prep.state = PREP_DISPATCH_FAILED_STATE
        prep.error_code = PREP_DISPATCH_FAILED
        prep.sanitized_message = str(exc)[:200] or None
        prep.state_reason = "enqueue_raised"
        db.commit()
        return {
            "preparation_id": prep.id,
            "state": PREP_DISPATCH_FAILED_STATE,
            "task_active": False,
            "queue": queue,
            "worker_task_id": None,
            "retryable": True,
            "error_code": PREP_DISPATCH_FAILED,
        }

    prep.worker_task_id = job_id
    prep.queue_name = queue
    prep.state = PREP_QUEUED
    prep.state_reason = "auto_dispatch"
    db.commit()
    return {
        "preparation_id": prep.id,
        "state": prep.state,
        "task_active": True,
        "queue": queue,
        "worker_task_id": job_id,
        "retryable": False,
    }


# ---------------------------------------------------------------------------
# Bounded Windows requirement discovery
# ---------------------------------------------------------------------------


# Bounded-discovery terminal values.  These are local
# representations, not the public ``PREP_*`` state strings: the
# orchestrator maps them to ``PREP_READY``, ``PREP_BLOCKED_SYMBOLS``
# or ``PREP_FAILED`` after the persistence step.

_DISCOVERY_OK = "ok"
_DISCOVERY_BLOCKED_SYMBOLS = "blocked_symbols"
_DISCOVERY_REQUIREMENT_UNKNOWN = "requirement_unknown"
_DISCOVERY_RETRYABLE = "retryable"


def _run_bounded_requirement_discovery(
    db: Session,
    *,
    evidence,
    probe_result,
    readiness,
) -> tuple[str | None, str | None, str | None, str | None, dict[str, Any]]:
    """Run bounded Windows requirement discovery and re-evaluate readiness.

    Returns a tuple of ``(state, reason, error_code,
    requirement_id, metadata)``.  The ``state`` is one of the
    internal ``_DISCOVERY_*`` constants above; a ``None`` state
    means the discovery was skipped (platform != Windows, no
    discovery method available, etc.) and the caller should keep
    the original readiness result.

    The function NEVER raises to the caller.  Process failures
    are translated into ``(PREP_FAILED, retryable)`` so the
    operator can re-run preparation without an explicit
    ``unsupported`` verdict.
    """
    from app.services.memory.symbol_requirement_discovery import (
        BoundedDiscoveryError,
        discover_windows_symbol_requirement,
        persist_discovered_requirement,
    )

    if probe_result.platform.value != "windows":
        # Linux / macOS / unknown must never invoke Windows
        # discovery.  Keep the original ``windows_probe_required``
        # result so the operator sees the correct reason.
        return None, None, None, None, {
            "skipped": True,
            "reason": "platform_not_windows",
            "platform": probe_result.platform.value,
        }

    work_dir = _discovery_work_dir(evidence)
    try:
        canonical = _evidence_canonical_path(evidence)
    except ValueError as exc:
        return _DISCOVERY_RETRYABLE, "windows_evidence_path_missing", (
            "WINDOWS_DISCOVERY_EVIDENCE_PATH_MISSING"
        ), None, {"platform": "windows", "error": str(exc)[:200]}

    try:
        discovered = discover_windows_symbol_requirement(canonical, work_dir)
    except BoundedDiscoveryError as exc:
        # A bounded-process failure is a retryable probe failure
        # (``PREP_FAILED``), never ``PREP_UNSUPPORTED`` (Windows
        # is Windows in every outcome).
        if not exc.retryable:
            return _DISCOVERY_REQUIREMENT_UNKNOWN, exc.code, exc.code, None, {
                "method": "bounded_discovery",
                "code": exc.code,
                "message": str(exc)[:200],
                "retryable": False,
            }
        return _DISCOVERY_RETRYABLE, exc.code, exc.code, None, {
            "method": "bounded_discovery",
            "code": exc.code,
            "message": str(exc)[:200],
            "retryable": True,
        }
    except Exception as exc:  # noqa: BLE001
        logger.exception(
            "bounded Windows discovery raised an unexpected error"
        )
        return _DISCOVERY_RETRYABLE, (
            "WINDOWS_DISCOVERY_UNEXPECTED"
        ), "WINDOWS_DISCOVERY_UNEXPECTED", None, {
            "method": "bounded_discovery",
            "code": "WINDOWS_DISCOVERY_UNEXPECTED",
            "message": str(exc)[:200],
            "retryable": True,
        }

    try:
        requirement, cached, created = persist_discovered_requirement(
            db, evidence=evidence, discovered=discovered
        )
    except Exception as exc:  # noqa: BLE001
        # Persistence failures are retryable as well; the bounded
        # probe succeeded but the row write did not.
        logger.exception(
            "bounded Windows discovery: persistence failed"
        )
        return _DISCOVERY_RETRYABLE, (
            "WINDOWS_DISCOVERY_PERSIST_FAILED"
        ), "WINDOWS_DISCOVERY_PERSIST_FAILED", None, {
            "method": "bounded_discovery",
            "code": "WINDOWS_DISCOVERY_PERSIST_FAILED",
            "discovered": discovered.to_dict(),
            "message": str(exc)[:200],
            "retryable": True,
        }

    requirement_id = str(requirement.id)
    if cached is not None:
        return _DISCOVERY_OK, "windows_cache_match", "WINDOWS_EXACT_CACHE_HIT", requirement_id, {
            "method": discovered.discovery_method,
            "created": created,
            "platform": "windows",
            "requirement": discovered.to_dict(),
            "cached_symbol_id": str(cached.id),
            "cached_symbol_key": cached.symbol_key,
        }

    # Requirement is known but the exact validated symbol is not
    # cached.  ``blocked_symbols`` (Windows exact symbols
    # missing) is distinct from ``requirement_unknown`` (we
    # could not derive the identity).
    return _DISCOVERY_BLOCKED_SYMBOLS, "windows_symbols_missing", (
        PREP_BLOCKED_SYMBOLS_ERROR
    ), requirement_id, {
        "method": discovered.discovery_method,
        "created": created,
        "platform": "windows",
        "requirement": discovered.to_dict(),
        "symbol_key": requirement.symbol_key,
    }


def _discovery_work_dir(evidence) -> Path:
    """Return a writable work dir for bounded discovery output.

    The discovery service writes nothing to disk except for
    Volatility's temporary scratch files; the work dir is a
    per-evidence subdirectory under the configured output root.
    """
    from app.core.config import get_settings

    settings = get_settings()
    root = settings.memory_output_dir or "/tmp"
    try:
        base = Path(root) / "bounded_discovery" / str(evidence.id)
        base.mkdir(parents=True, exist_ok=True)
        return base
    except OSError:
        return Path("/tmp")


def execute_memory_preparation(evidence_id: str) -> dict[str, Any]:
    """Run the OS-agnostic preparation for a single evidence.

    The function is called by the memory-worker.  It does
    NOT download symbols, does NOT open OpenSearch indices
    and does NOT enqueue further work.
    """
    from app.models.evidence import Evidence
    from app.services.memory.platform import (
        ReadinessState,
        get_adapter_for_probe,
    )
    from app.services.memory.symbol_preparation import (
        PREP_BLOCKED,
        PREP_BLOCKED_SYMBOLS,
        PREP_FAILED,
        PREP_PROBING,
        PREP_READY,
        PREP_UNSUPPORTED,
        PREP_STALE,
    )

    db = SessionLocal()
    try:
        evidence = db.get(Evidence, evidence_id)
        if evidence is None:
            logger.warning("preparation: evidence %s not found", evidence_id)
            return {"state": "failed", "error_code": "EVIDENCE_NOT_FOUND"}
        prep = _get_active_preparation(db, evidence_id)
        if prep is None:
            # No active row.  Nothing to do.  The dispatcher
            # is responsible for creating one.
            return {"state": "no_active_preparation"}

        # 1. Move to ``probing``.
        prep.state = PREP_PROBING
        _persist_heartbeat(prep, current_step="probing_platform")
        db.commit()

        # 2. Run the bounded probe.
        probe_summary = _probe_evidence(evidence)

        # 3. Build the adapter and evaluate readiness.
        from app.services.memory.platform import (
            PlatformFamily,
            probe_memory_platform,
        )
        probe_result = probe_memory_platform(
            canonical_path=_evidence_canonical_path(evidence),
            detected_format=getattr(evidence, "detected_format", None),
            filename=_evidence_filename(evidence),
        )
        adapter = get_adapter_for_probe(probe_result)
        cache_state = _gather_cache_state(db, evidence)
        readiness = adapter.check_readiness(probe=probe_result, cache_state=cache_state)

        # 3a. Bounded discovery (Windows only): when the adapter
        # signals a discovery step we have not already produced
        # a terminal state, run the bounded ``windows.info``
        # probe, persist the discovered requirement and
        # re-evaluate the cache.  The function returns a
        # (state, reason, error_code, requirement_id, meta)
        # tuple that the downstream state-mapping branch
        # consumes.  ``None`` means "no discovery was performed
        # or the discovery was inconclusive"; the original
        # readiness result stands.
        if readiness.state.value == PREP_BLOCKED and getattr(
            readiness, "requires_discovery", False
        ):
            new_state, new_reason, new_error, new_requirement_id, discovery_meta = (
                _run_bounded_requirement_discovery(
                    db,
                    evidence=evidence,
                    probe_result=probe_result,
                    readiness=readiness,
                )
            )
            if new_state is not None:
                readiness.state = (
                    ReadinessState.READY
                    if new_state == _DISCOVERY_OK
                    else ReadinessState.BLOCKED_SYMBOLS
                    if new_state == _DISCOVERY_BLOCKED_SYMBOLS
                    else ReadinessState.BLOCKED
                    if new_state == _DISCOVERY_REQUIREMENT_UNKNOWN
                    else ReadinessState.FAILED
                )
                readiness.reason = new_reason or readiness.reason
                readiness.error_code = new_error or readiness.error_code
                readiness.requirement_id = new_requirement_id or readiness.requirement_id
                readiness.requires_discovery = False
                readiness.metadata = {
                    **dict(readiness.metadata or {}),
                    "discovery": discovery_meta,
                }

        # 4. Persist the terminal state.
        from app.services.memory.symbol_preparation import (
            mark_preparation,
        )
        if readiness.state.value == PREP_READY:
            mark_preparation(
                db,
                evidence=evidence,
                state=PREP_READY,
                reason=readiness.reason,
                requirement_id=readiness.requirement_id,
            )
        elif readiness.state.value == ReadinessState.BLOCKED_SYMBOLS.value:
            # Requirement known, exact validated symbol absent.
            # Distinct from ``requirement_unknown`` (we did
            # derive the identity) and from ``unsupported``
            # (the operator must seed the cache or approve a
            # managed acquisition).
            mark_preparation(
                db,
                evidence=evidence,
                state=PREP_BLOCKED_SYMBOLS,
                reason=readiness.reason or "windows_symbols_missing",
                sanitized_message=readiness.error_code or "WINDOWS_EXACT_SYMBOLS_MISSING",
                requirement_id=readiness.requirement_id,
            )
        elif readiness.state.value == PREP_BLOCKED:
            from app.services.memory.symbol_preparation import (
                PREP_REQUIREMENT_UNKNOWN as PREP_BLOCKED_LEGACY,
            )
            mark_preparation(
                db,
                evidence=evidence,
                state=PREP_BLOCKED_LEGACY,
                reason=readiness.reason,
                sanitized_message=readiness.error_code or "blocked",
            )
        elif readiness.state.value == PREP_UNSUPPORTED:
            # Use structured states: platform_not_identified when
            # the OS could not be determined, platform_not_supported
            # when a known OS lacks an adapter implementation.
            from app.services.memory.symbol_preparation import (
                PREP_PLATFORM_NOT_IDENTIFIED_STATE,
                PREP_PLATFORM_NOT_SUPPORTED_STATE,
            )
            terminal_state = PREP_PLATFORM_NOT_SUPPORTED_STATE
            if readiness.error_code == "PLATFORM_NOT_IDENTIFIED":
                terminal_state = PREP_PLATFORM_NOT_IDENTIFIED_STATE
            elif readiness.error_code == "PLATFORM_NOT_SUPPORTED":
                terminal_state = PREP_PLATFORM_NOT_SUPPORTED_STATE
            mark_preparation(
                db,
                evidence=evidence,
                state=terminal_state,
                reason=readiness.reason,
                sanitized_message=readiness.error_code or "platform_not_supported",
            )
        else:  # failed
            mark_preparation(
                db,
                evidence=evidence,
                state=PREP_FAILED,
                reason=readiness.reason,
                sanitized_message=readiness.error_code or "preparation_failed",
            )

        # Persist the probe summary in the metadata for the UI.
        prep = _get_active_preparation(db, evidence_id)
        if prep is not None:
            meta = dict(prep.metadata_json or {})
            meta["platform_probe"] = probe_summary
            meta["platform_adapter"] = adapter.platform.value
            meta["readiness"] = readiness.to_dict()
            prep.metadata_json = meta
        db.commit()
        return {
            "state": readiness.state.value,
            "platform": probe_result.platform.value,
            "reason": readiness.reason,
        }
    except Exception as exc:  # noqa: BLE001
        logger.exception("preparation execution failed: %s", exc)
        db.rollback()
        try:
            prep = _get_active_preparation(db, evidence_id)
            if prep is not None:
                prep.state = PREP_FAILED
                prep.error_code = "PREPARATION_RUNTIME_ERROR"
                prep.sanitized_message = str(exc)[:200] or None
                prep.completed_at = utc_now_naive()
                db.commit()
        except Exception:  # noqa: BLE001
            db.rollback()
        return {"state": "failed", "error_code": "PREPARATION_RUNTIME_ERROR"}
    finally:
        db.close()


def _gather_cache_state(db: Session, evidence) -> dict[str, Any]:
    """Build the cache_state dict the adapters expect.

    The dict is consumed by ``check_readiness`` and contains
    the cached requirement, the exact cache match and the
    latest successful metadata run.  The function is
    side-effect free.
    """
    from app.models.memory import (
        MemoryEvidenceSymbolLink,
        MemoryScanRun,
        MemorySymbolRequirement,
    )
    from app.services.memory.symbol_preparation import (
        exact_cache_match_for_requirement,
        find_requirement_by_content_identity,
    )

    state: dict[str, Any] = {
        "exact_cache_match": False,
        "successful_metadata_run": False,
        "isf_available": False,
        "requirement_id": None,
    }

    # 1. Cached requirement by content identity.
    reused = find_requirement_by_content_identity(db, evidence=evidence)
    if reused is not None:
        state["requirement_id"] = reused.id
        if exact_cache_match_for_requirement(db, reused) is not None:
            state["exact_cache_match"] = True
            state["isf_available"] = True

    # 2. Successful metadata run.
    latest_metadata = (
        db.query(MemoryScanRun)
        .filter(
            MemoryScanRun.evidence_id == evidence.id,
            MemoryScanRun.profile == "metadata_only",
        )
        .order_by(MemoryScanRun.created_at.desc())
        .first()
    )
    if (
        latest_metadata is not None
        and latest_metadata.status in ("completed", "completed_with_errors")
        and int(latest_metadata.plugins_failed or 0) == 0
        and int(latest_metadata.plugins_completed or 0) >= 1
    ):
        state["successful_metadata_run"] = True

    # 3. ISF availability: a completed ISF is implicit in the
    # exact cache match.
    return state


def reconcile_stale_preparations(
    db: Session,
    *,
    max_rows: int = 200,
) -> dict[str, int]:
    """Reconcile stale preparation rows.

    A row is considered stale when:

    * it is in a non-terminal state (queued, probing, etc.);
    * the worker task is not alive in Redis;
    * and the row has not received a heartbeat within the
      configured timeout.

    For each stale row the function re-dispatches at most one
    task.  If the re-dispatch fails the row is marked
    ``dispatch_failed`` so the operator sees an explicit
    error instead of a silent queue.
    """
    from app.core.config import get_settings
    from app.models.memory import MemorySymbolPreparation
    from app.services.memory.symbol_preparation import (
        _task_is_alive,
        PREP_DISPATCH_FAILED_STATE,
        PREP_STALE,
    )
    from app.models.evidence import Evidence

    settings = get_settings()
    timeout = int(getattr(settings, "memory_preparation_stale_seconds", 600))
    stats = {"scanned": 0, "redispatched": 0, "marked_stale": 0, "marked_dispatch_failed": 0}
    non_terminal = {
        "queued", "probing", "acquiring", "converting", "verifying",
    }
    rows = (
        db.query(MemorySymbolPreparation)
        .filter(
            MemorySymbolPreparation.state.in_(tuple(non_terminal)),
            MemorySymbolPreparation.active == True,  # noqa: E712
        )
        .order_by(MemorySymbolPreparation.updated_at.asc())
        .limit(max_rows)
        .all()
    )
    for row in rows:
        stats["scanned"] += 1
        last = row.last_heartbeat_at or row.updated_at or row.created_at
        if last is None:
            continue
        age = (utc_now_naive() - last).total_seconds()
        if age < timeout:
            continue
        if _task_is_alive(row.worker_task_id):
            continue
        # Stale and no live task.  Re-dispatch once.
        evidence = db.get(Evidence, row.evidence_id)
        if evidence is None:
            row.state = PREP_STALE
            row.state_reason = "evidence_missing"
            row.completed_at = utc_now_naive()
            row.active = False
            stats["marked_stale"] += 1
            db.commit()
            continue
        result = dispatch_memory_preparation(db, evidence=evidence, force=False)
        if result.get("state") == PREP_DISPATCH_FAILED_STATE:
            row.state = PREP_DISPATCH_FAILED_STATE
            row.error_code = result.get("error_code")
            row.sanitized_message = "auto_redispatch_failed"
            row.completed_at = utc_now_naive()
            stats["marked_dispatch_failed"] += 1
        else:
            stats["redispatched"] += 1
        db.commit()
    return stats


def preparation_diagnostics(db: Session, evidence_id: str) -> dict[str, Any]:
    """Return a structured diagnostics payload for an evidence.

    The payload is intended for the diagnostics endpoint
    ``/api/memory/evidences/{id}/preparation/diagnostics`` and
    surfaces the queue the API enqueued to, the queue the
    row records, the worker task id, the heartbeat, the
    source of truth and a structured error code if any.
    """
    from app.core.config import get_settings
    from app.models.memory import MemorySymbolPreparation
    from app.services.memory.symbol_preparation import (
        _task_is_alive,
    )

    settings = get_settings()
    expected_queue = settings.memory_queue_name
    prep = _get_active_preparation(db, evidence_id)
    task_alive = _task_is_alive(prep.worker_task_id if prep is not None else None)
    last_heartbeat = (
        prep.last_heartbeat_at.isoformat()
        if prep is not None and prep.last_heartbeat_at is not None
        else None
    )
    persisted_queue = prep.queue_name if prep is not None else None
    queue_match = (persisted_queue == expected_queue) if persisted_queue else False
    return {
        "expected_queue": expected_queue,
        "persisted_queue": persisted_queue,
        "queue_match": queue_match,
        "task_registered": bool(prep.worker_task_id) if prep is not None else False,
        "task_alive": task_alive,
        "worker_task_id": prep.worker_task_id if prep is not None else None,
        "preparation_id": prep.id if prep is not None else None,
        "state": prep.state if prep is not None else None,
        "current_step": prep.current_step if prep is not None else None,
        "last_heartbeat_at": last_heartbeat,
        "error_code": prep.error_code if prep is not None else None,
        "retryable": (
            prep is not None and prep.state in ("queued", "dispatch_failed", "stale")
        ),
    }
