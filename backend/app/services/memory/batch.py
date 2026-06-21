"""Server-side batch orchestration for memory analysis.

A :class:`MemoryAnalysisBatch` represents an orchestrated execution
of multiple analysis profiles against a single memory evidence, one
profile at a time.  The batch is the source of truth for:

* the ordered list of profiles to execute;
* which profile is currently running;
* which profiles have already completed or failed;
* whether cancellation was requested.

The batch never executes two profiles in parallel and never
silently retries a profile that has already completed successfully
in ``missing_or_failed`` mode.

Public surface:

* :func:`plan_run_all`        - resolve which profiles to run/skip
* :func:`create_run_all_batch` - create a batch + enqueue first profile
* :func:`get_batch`            - read a batch by id
* :func:`find_active_batch`    - locate the in-flight batch for evidence
* :func:`cancel_batch`         - request cancellation
* :func:`advance_batch`        - called by the worker after a run finishes
"""
from __future__ import annotations

import logging
from datetime import datetime, timezone
from typing import Any

from sqlalchemy import desc
from sqlalchemy.orm import Session

from app.core.database import utc_now_naive
from app.models.memory import (
    MemoryAnalysisBatch,
    MemoryScanRun,
    MEMORY_BATCH_MODES,
    MEMORY_BATCH_STATUSES,
)
from app.services.memory.catalogue import (
    NETWORK_UNAVAILABLE_REASON,
    PROFILE_CATALOGUE,
)
from app.services.memory.execution import (
    MemoryExecutionValidationError,
    create_memory_metadata_run,
    mark_run_queued,
)
from app.services.memory.volatility_runner import network_basic_available


logger = logging.getLogger(__name__)


#: Profiles executed by ``Run all supported profiles`` in the order
#: they appear in the catalogue.  ``processes_basic`` is intentionally
#: excluded: it is an alternative to ``processes_extended`` and would
#: generate overlapping coverage.  ``network_basic`` is excluded by
#: availability filtering below (network plugin is not shipped).
RUN_ALL_PROFILES: tuple[str, ...] = (
    "metadata_only",
    "processes_extended",
    "modules_basic",
    "handles_basic",
    "kernel_basic",
    "suspicious_memory",
)

#: ``processes_basic`` is only used as a manual fallback, never as part
#: of run-all.  Excluded profiles are surfaced to the operator.
RUN_ALL_EXCLUDED_PROFILES: dict[str, str] = {
    "processes_basic": "standard process analysis is replaced by the extended profile in run-all",
}


class MemoryBatchError(RuntimeError):
    """Raised for any business-rule violation in batch operations."""

    def __init__(self, code: str, message: str, status_code: int = 400):
        super().__init__(message)
        self.code = code
        self.message = message
        self.status_code = status_code


def _family_for_profile(profile: str) -> str | None:
    for entry in PROFILE_CATALOGUE:
        if entry["profile"] == profile:
            return entry["family"]
    return None


def _profile_available(profile: str) -> tuple[bool, str | None]:
    if profile == "network_basic":
        ok, reason = network_basic_available()
        if not ok:
            return False, reason or NETWORK_UNAVAILABLE_REASON
    return True, None


def _profile_completed_successfully(db: Session, *, case_id: str, evidence_id: str, profile: str) -> bool:
    """Return True if the evidence has at least one successful run for this profile."""
    return (
        db.query(MemoryScanRun)
        .filter(
            MemoryScanRun.case_id == case_id,
            MemoryScanRun.evidence_id == evidence_id,
            MemoryScanRun.profile == profile,
            MemoryScanRun.status.in_(("completed", "completed_with_errors")),
        )
        .first()
        is not None
    )


def _profile_latest_status(db: Session, *, case_id: str, evidence_id: str, profile: str) -> str | None:
    row = (
        db.query(MemoryScanRun)
        .filter(
            MemoryScanRun.case_id == case_id,
            MemoryScanRun.evidence_id == evidence_id,
            MemoryScanRun.profile == profile,
        )
        .order_by(desc(MemoryScanRun.created_at))
        .first()
    )
    return row.status if row else None


def plan_run_all(
    db: Session,
    *,
    case_id: str,
    evidence_id: str,
    mode: str,
) -> dict[str, Any]:
    """Resolve the ordered list of profiles to run and the skipped ones.

    The plan is computed server-side from an allowlist; the client
    cannot inject arbitrary plugins.
    """
    if mode not in MEMORY_BATCH_MODES:
        raise MemoryBatchError("MEMORY_BATCH_INVALID_MODE", f"Unknown run-all mode: {mode}", status_code=400)

    selected: list[str] = []
    skipped: list[dict[str, str]] = []
    for profile in RUN_ALL_PROFILES:
        ok, reason = _profile_available(profile)
        if not ok:
            skipped.append({"profile": profile, "reason": reason or "unavailable"})
            continue
        if mode == "missing_or_failed" and _profile_completed_successfully(
            db, case_id=case_id, evidence_id=evidence_id, profile=profile,
        ):
            skipped.append({"profile": profile, "reason": "already_completed"})
            continue
        selected.append(profile)

    excluded = [
        {"profile": p, "reason": r} for p, r in RUN_ALL_EXCLUDED_PROFILES.items()
    ]
    # network_basic is never part of run-all; surface it under
    # ``excluded_profiles`` so the UI can show the operator why it is
    # absent.
    network_ok, network_reason = _profile_available("network_basic")
    if not network_ok:
        excluded.append(
            {
                "profile": "network_basic",
                "reason": network_reason or NETWORK_UNAVAILABLE_REASON,
            }
        )

    return {
        "selected_profiles": selected,
        "skipped_profiles": skipped,
        "excluded_profiles": excluded,
    }


def _reject_incompatible_profiles(profile_list: list[str]) -> None:
    """Enforce the allowlist server-side.

    The endpoint should never accept an arbitrary list of plugins.
    This helper documents and enforces the rule.
    """
    allowed = set(RUN_ALL_PROFILES) | set(RUN_ALL_EXCLUDED_PROFILES)
    for profile in profile_list:
        if profile not in allowed:
            raise MemoryBatchError(
                "MEMORY_BATCH_PROFILE_NOT_ALLOWLISTED",
                f"Profile '{profile}' is not allowlisted for run-all.",
                status_code=400,
            )


def find_active_batch(db: Session, *, case_id: str, evidence_id: str) -> MemoryAnalysisBatch | None:
    return (
        db.query(MemoryAnalysisBatch)
        .filter(
            MemoryAnalysisBatch.case_id == case_id,
            MemoryAnalysisBatch.evidence_id == evidence_id,
            MemoryAnalysisBatch.status.in_(("queued", "running")),
        )
        .order_by(desc(MemoryAnalysisBatch.created_at))
        .first()
    )


def get_batch(db: Session, *, batch_id: str) -> MemoryAnalysisBatch | None:
    return db.get(MemoryAnalysisBatch, batch_id)


def create_run_all_batch(
    db: Session,
    *,
    case_id: str,
    evidence_id: str,
    mode: str,
    authorization_acknowledged: bool,
    continue_on_failure: bool = True,
    enqueue_fn,
) -> dict[str, Any]:
    """Create a batch and enqueue the first profile (if any).

    ``enqueue_fn`` is a callable ``(run_id) -> worker_task_id`` that
    pushes the run onto the worker's queue.  The callable is injected
    so the batch service can be unit-tested without Redis.
    """
    if not authorization_acknowledged:
        raise MemoryBatchError(
            "MEMORY_BATCH_AUTHORIZATION_REQUIRED",
            "Authorization acknowledgement is required to start a run-all batch.",
            status_code=400,
        )

    # Reject profile injection early.
    _reject_incompatible_profiles(list(RUN_ALL_PROFILES) + list(RUN_ALL_EXCLUDED_PROFILES))

    # Preflight: evidence belongs to case and is a memory dump.
    # The full ``validate_memory_execution_request`` also stat()s the
    # evidence file and validates output paths; those checks are
    # deferred to per-profile execution because the file may not be
    # reachable from the API process in every deployment.  We only
    # verify the type, the case ownership and the readiness signal
    # available in the DB.
    from app.models.evidence import Evidence, EvidenceType
    from app.services.memory.evidence_access import (
        MemoryStorageAccessError,
        validate_current_process_evidence_access,
    )
    from app.core.config import get_settings

    evidence = db.get(Evidence, evidence_id)
    if evidence is None:
        raise MemoryBatchError("EVIDENCE_NOT_FOUND", "Evidence not found.", status_code=404)
    if evidence.evidence_type != EvidenceType.memory_dump:
        raise MemoryBatchError(
            "INVALID_EVIDENCE_TYPE",
            "Run-all batches are only supported for memory_dump evidence.",
            status_code=400,
        )
    try:
        validate_current_process_evidence_access(evidence, settings=get_settings())
    except MemoryStorageAccessError as exc:
        # Storage access is a soft check at batch creation; the
        # actual scan will retry.  We only hard-fail on truly missing
        # evidence.
        if exc.code in {"EVIDENCE_NOT_FOUND", "EVIDENCE_FILE_MISSING"}:
            raise MemoryBatchError(exc.code, exc.message, status_code=400) from exc

    # Idempotency: reject if another batch is already active.
    existing = find_active_batch(db, case_id=case_id, evidence_id=evidence_id)
    if existing is not None:
        raise MemoryBatchError(
            "MEMORY_BATCH_ALREADY_ACTIVE",
            f"An active run-all batch already exists for this evidence: {existing.id}",
            status_code=409,
        )

    plan = plan_run_all(db, case_id=case_id, evidence_id=evidence_id, mode=mode)

    batch = MemoryAnalysisBatch(
        case_id=case_id,
        evidence_id=evidence_id,
        mode=mode,
        status="queued",
        requested_profiles=list(plan["selected_profiles"]),
        skipped_profiles=list(plan["skipped_profiles"]) + list(plan["excluded_profiles"]),
        completed_profiles=[],
        failed_profiles=[],
        continue_on_failure=continue_on_failure,
        authorization_acknowledged=True,
        authorization_acknowledged_at=utc_now_naive(),
        audit_metadata_json={"requested_mode": mode},
    )
    db.add(batch)
    db.flush()

    # Enqueue the first profile (if any).
    if batch.requested_profiles:
        first = batch.requested_profiles[0]
        batch.current_profile = first
        batch.status = "running"
        batch.started_at = utc_now_naive()
        run = _enqueue_profile(db, batch=batch, profile=first, position=1, enqueue_fn=enqueue_fn)
        db.commit()
        db.refresh(batch)
        return {"batch": batch, "first_run": run, "plan": plan}

    # No profiles to run.
    batch.status = "completed"
    batch.completed_at = utc_now_naive()
    db.commit()
    db.refresh(batch)
    return {"batch": batch, "first_run": None, "plan": plan}


def _enqueue_profile(
    db: Session,
    *,
    batch: MemoryAnalysisBatch,
    profile: str,
    position: int,
    enqueue_fn,
) -> MemoryScanRun:
    run = create_memory_metadata_run(db, batch.evidence_id, profile)
    run.batch_id = batch.id
    run.batch_position = position
    run.batch_total = len(batch.requested_profiles)
    db.flush()
    worker_task_id = enqueue_fn(run.id)
    run = mark_run_queued(db, run.id, worker_task_id) or run
    return run


def cancel_batch(db: Session, *, batch_id: str) -> MemoryAnalysisBatch | None:
    batch = db.get(MemoryAnalysisBatch, batch_id)
    if batch is None:
        return None
    if batch.status not in ("queued", "running"):
        return batch
    batch.cancellation_requested = True
    batch.cancellation_reason = "operator_requested"
    db.commit()
    db.refresh(batch)
    return batch


def advance_batch(
    db: Session,
    *,
    run: MemoryScanRun,
    enqueue_fn=None,
) -> MemoryAnalysisBatch | None:
    """Called by the worker after a run reaches a terminal state.

    Updates the batch state, advances the pointer and (optionally)
    enqueues the next profile.  The function is idempotent: a second
    call with the same run has no effect.
    """
    if run.batch_id is None:
        return None
    if enqueue_fn is None:
        enqueue_fn = _default_enqueue_fn

    batch = db.get(MemoryAnalysisBatch, run.batch_id)
    if batch is None:
        return None

    # Idempotency: only the *first* advance call for a run updates
    # the batch's "current" state.
    if batch.current_profile and run.profile != batch.current_profile:
        # A late callback for a run that no longer matches the
        # current profile (e.g. after a cancellation re-pointed the
        # batch).  Ignore.
        return batch
    if run.profile in (batch.completed_profiles or []) + (batch.failed_profiles or []):
        return batch

    terminal_success = run.status in ("completed", "completed_with_errors")
    terminal_failure = run.status in (
        "failed",
        "timed_out",
        "cancelled",
        "backend_unavailable",
        "invalid_evidence",
    )

    if terminal_success:
        batch.completed_profiles = list(batch.completed_profiles or []) + [run.profile]
    elif terminal_failure:
        batch.failed_profiles = list(batch.failed_profiles or []) + [run.profile]
    else:
        # Non-terminal (still running or pending): leave the batch alone.
        return batch

    # Determine the next profile to enqueue.
    next_profile: str | None = None
    completed = set(batch.completed_profiles or [])
    failed = set(batch.failed_profiles or [])
    used = completed | failed
    for profile in batch.requested_profiles:
        if profile not in used:
            next_profile = profile
            break

    # Cancellation short-circuits the queue.
    if batch.cancellation_requested:
        next_profile = None

    # If the previous run was a fundamental failure, stop here.
    if run.profile == "metadata_only" and terminal_failure:
        next_profile = None
        batch.status = "failed"

    if next_profile is None:
        batch.current_profile = None
        if batch.status != "failed":
            if batch.failed_profiles:
                batch.status = "completed_with_errors"
            else:
                batch.status = "completed"
        batch.completed_at = utc_now_naive()
        db.commit()
        db.refresh(batch)
        return batch

    # Enqueue the next profile.
    position = (run.batch_position or 0) + 1
    batch.current_profile = next_profile
    if not batch.started_at:
        batch.started_at = utc_now_naive()
    batch.status = "running"
    next_run = _enqueue_profile(db, batch=batch, profile=next_profile, position=position, enqueue_fn=enqueue_fn)
    db.commit()
    db.refresh(batch)
    return batch


def _default_enqueue_fn(run_id: str) -> str:
    """Lazy default enqueue function used by :func:`advance_batch`.

    The lazy import keeps the ``app.services.memory.batch`` module
    importable from both the API process and the dedicated memory
    worker process (which is the only caller of ``advance_batch``).
    """
    from app.workers.tasks import enqueue_memory_metadata_scan

    return enqueue_memory_metadata_scan(run_id)


def serialize_batch(batch: MemoryAnalysisBatch, evidence: dict[str, Any] | None = None) -> dict[str, Any]:
    payload = {
        "id": batch.id,
        "case_id": batch.case_id,
        "evidence_id": batch.evidence_id,
        "mode": batch.mode,
        "status": batch.status,
        "requested_profiles": list(batch.requested_profiles or []),
        "skipped_profiles": list(batch.skipped_profiles or []),
        "current_profile": batch.current_profile,
        "completed_profiles": list(batch.completed_profiles or []),
        "failed_profiles": list(batch.failed_profiles or []),
        "continue_on_failure": batch.continue_on_failure,
        "cancellation_requested": batch.cancellation_requested,
        "authorization_acknowledged": batch.authorization_acknowledged,
        "created_at": batch.created_at.isoformat() if batch.created_at else None,
        "started_at": batch.started_at.isoformat() if batch.started_at else None,
        "completed_at": batch.completed_at.isoformat() if batch.completed_at else None,
    }
    if evidence is not None:
        payload["evidence"] = evidence
    return payload
