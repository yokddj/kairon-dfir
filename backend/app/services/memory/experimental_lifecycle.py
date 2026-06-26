"""Lifecycle controller for the experimental mismatched-symbol analysis.

This module is the single entry point for creating, advancing,
cancelling, and deleting an ``MemoryExperimentalRun`` row.  Every
caller in the API / worker / CLI uses the helpers here so the
trust boundary is enforced uniformly.

Design rules:

* The exact symbol cache row, the requirement, the requirement's
  ``pdb_age``, the validated ``MemoryScanRun`` rows, the
  validated OpenSearch index, the validated detection
  pipeline, and the validated export are NEVER touched.
* Every state transition is a single ``db.commit()`` so the
  lifecycle is observable.
* The run never advances past ``canary_queued`` /
  ``canary_running`` / ``canary_*`` without a recorded
  acknowledgement payload.
* The canary outcome is evaluated by the worker; this module
  only persists the outcome and decides whether a full run may
  start.
"""
from __future__ import annotations

import logging
import uuid
from datetime import datetime
from typing import Any

from sqlalchemy.orm import Session

from app.core.config import get_settings
from app.core.database import utc_now_naive
from app.models.memory import (
    MemoryCachedSymbol,
    MemoryExperimentalRun,
    MemoryExperimentalSymbolCandidate,
    MemoryScanRun,
    MemorySymbolRequirement,
)
from app.services.memory.experimental_acknowledgement import (
    EXPERIMENTAL_ACK_WARNING_TEXT,
    validate_acknowledgement_payload,
)
from app.services.memory.experimental_import import (
    ExperimentalImportError,
    verify_candidate_integrity,
)
from app.services.memory.experimental_catalogue import (
    EXPERIMENTAL_CANARY_PLUGINS,
    EXPERIMENTAL_CANARY_PROFILE,
    allowed_profiles_for_canary_outcome,
    list_experimental_profiles,
)
from app.services.memory.experimental_trust import (
    ANALYSIS_MODE_EXPERIMENTAL,
    CACHE_CLASSIFICATION_EXPERIMENTAL_CANDIDATE,
    RUN_STATUS_ACKNOWLEDGEMENT_REQUIRED,
    RUN_STATUS_CANDIDATE_UNAVAILABLE,
    RUN_STATUS_CANCELLED,
    RUN_STATUS_CANARY_DEGRADED,
    RUN_STATUS_CANARY_FAILED,
    RUN_STATUS_CANARY_INCONCLUSIVE,
    RUN_STATUS_CANARY_PASSED,
    RUN_STATUS_CANARY_QUEUED,
    RUN_STATUS_CANARY_RUNNING,
    RUN_STATUS_COMPLETED_UNTRUSTED,
    RUN_STATUS_DELETED,
    RUN_STATUS_FAILED_UNTRUSTED,
    RUN_STATUS_FULL_RUN_QUEUED,
    RUN_STATUS_FULL_RUN_RUNNING,
    RUN_STATUS_PARTIAL_UNTRUSTED,
    SYMBOL_MATCH_TYPE_GUID_ONLY_AGE_MISMATCH,
    TRUST_LEVEL_UNTRUSTED,
    compute_trust_state,
    evaluate_candidate_eligibility,
    is_experimental_enabled,
)
from app.services.memory.experimental_canary import (
    CANARY_STATUS_DEGRADED,
    CANARY_STATUS_FAILED,
    CANARY_STATUS_INCONCLUSIVE,
    CANARY_STATUS_PASSED,
    evaluate_canary,
    persist_canary_result,
)


logger = logging.getLogger(__name__)


class ExperimentalLifecycleError(Exception):
    """Raised by the lifecycle controller on a hard failure.

    The error code is exposed to the API layer which turns it
    into an HTTP error response.  The message is sanitised and
    safe to return to the analyst.
    """

    def __init__(self, error_code: str, message: str, *, http_status: int = 400):
        super().__init__(message)
        self.error_code = error_code
        self.message = message
        self.http_status = http_status


def require_feature_enabled() -> None:
    """Raise ``ExperimentalLifecycleError`` when the feature is off.

    The error code is ``EXPERIMENTAL_DISABLED`` and the HTTP
    status is 404 (matches the policy: the feature is not
    advertised to untrusted callers).
    """
    if not is_experimental_enabled():
        raise ExperimentalLifecycleError(
            "EXPERIMENTAL_DISABLED",
            "Experimental mismatched-symbol analysis is disabled.",
            http_status=404,
        )


def build_required_identity_block(requirement: MemorySymbolRequirement) -> dict[str, Any]:
    return {
        "pdb_name": requirement.pdb_name,
        "pdb_guid": requirement.pdb_guid,
        "pdb_age": int(requirement.pdb_age),
        "architecture": requirement.architecture,
    }


def build_observed_identity_block(cache: MemoryCachedSymbol) -> dict[str, Any]:
    return {
        "pdb_name": cache.pdb_name,
        "pdb_guid": cache.pdb_guid,
        "pdb_age": int(cache.pdb_age),
        "architecture": cache.architecture,
    }


def upsert_candidate(
    db: Session,
    *,
    case_id: str,
    evidence_id: str,
    requirement: MemorySymbolRequirement,
    cache: MemoryCachedSymbol,
    source_host_path: str | None = None,
    actor: str = "server-operator",
) -> MemoryExperimentalSymbolCandidate:
    """Create or update the active candidate for a requirement.

    The cache row must be classified as ``experimental_candidate``
    (set when the operator CLI imports a mismatched symbol).  The
    function is idempotent: if an active candidate already exists
    for the requirement the function returns it after back-filling
    any missing fields.  A new row is created otherwise.
    """
    require_feature_enabled()
    # Revoke the previous active candidate (if any).  Multiple
    # terminal rows are allowed; only one active row at a time.
    existing = (
        db.query(MemoryExperimentalSymbolCandidate)
        .filter(
            MemoryExperimentalSymbolCandidate.requirement_id == requirement.id,
            MemoryExperimentalSymbolCandidate.revoked_at.is_(None),
        )
        .first()
    )
    if existing is not None:
        return existing
    verdict = evaluate_candidate_eligibility(requirement, cache)
    if not verdict["eligible"]:
        raise ExperimentalLifecycleError(
            verdict["error_code"] or "EXPERIMENTAL_NOT_ELIGIBLE",
            verdict["reason"] or "Candidate is not eligible for experimental analysis.",
        )
    candidate = MemoryExperimentalSymbolCandidate(
        id=str(uuid.uuid4()),
        case_id=case_id,
        evidence_id=evidence_id,
        requirement_id=requirement.id,
        cached_symbol_id=cache.id,
        required_pdb_name=requirement.pdb_name,
        required_pdb_guid=requirement.pdb_guid,
        required_pdb_age=int(requirement.pdb_age),
        required_architecture=requirement.architecture,
        observed_pdb_name=cache.pdb_name,
        observed_pdb_guid=cache.pdb_guid,
        observed_pdb_age=int(cache.pdb_age),
        observed_architecture=cache.architecture,
        symbol_match_type=verdict["match_type"] or SYMBOL_MATCH_TYPE_GUID_ONLY_AGE_MISMATCH,
        symbol_warning=verdict["warning"] or "Symbol age mismatch",
        provenance_source_type=cache.provenance_source_type or "operator_cli_pdb",
        provenance_source_name=cache.provenance_source_name or "Operator CLI",
        provenance_actor=actor,
        source_host_path=source_host_path,
        pdb_sha256=cache.pdb_sha256,
        isf_sha256=cache.isf_sha256,
        isf_validation_status=cache.validation_status or "validated",
        metadata_json={"cache_classification": CACHE_CLASSIFICATION_EXPERIMENTAL_CANDIDATE},
    )
    db.add(candidate)
    db.commit()
    db.refresh(candidate)
    return candidate


def revoke_candidate(
    db: Session,
    *,
    candidate: MemoryExperimentalSymbolCandidate,
    actor: str,
    reason: str,
) -> MemoryExperimentalSymbolCandidate:
    candidate.revoked_at = utc_now_naive()
    candidate.revoked_by = actor
    candidate.revocation_reason = reason
    db.add(candidate)
    db.commit()
    db.refresh(candidate)
    return candidate


def list_candidates(
    db: Session,
    *,
    case_id: str,
    evidence_id: str,
) -> list[MemoryExperimentalSymbolCandidate]:
    return (
        db.query(MemoryExperimentalSymbolCandidate)
        .filter(
            MemoryExperimentalSymbolCandidate.case_id == case_id,
            MemoryExperimentalSymbolCandidate.evidence_id == evidence_id,
        )
        .order_by(MemoryExperimentalSymbolCandidate.created_at.desc())
        .all()
    )


def record_cli_candidate(
    db: Session,
    *,
    case_id: str,
    evidence_id: str,
    cached_symbol_id: str,
    source_host_path: str | None = None,
    actor: str = "server-operator",
) -> MemoryExperimentalSymbolCandidate:
    """CLI-friendly helper: load the requirement and the cache row
    by id and call ``upsert_candidate``.  Used by
    ``memory_symbols.py``'s ``import-experimental-candidate``
    subcommand.

    The function is intentionally a thin wrapper so the eligibility
    check, the trust filter, and the audit metadata all live in
    the lifecycle controller.
    """
    require_feature_enabled()
    requirement = _load_requirement(db, case_id=case_id, evidence_id=evidence_id)
    cache = db.get(MemoryCachedSymbol, cached_symbol_id)
    if cache is None:
        raise ExperimentalLifecycleError(
            "EXPERIMENTAL_CANDIDATE_MISSING",
            "The candidate symbol was not found in the cache.",
        )
    return upsert_candidate(
        db,
        case_id=case_id,
        evidence_id=evidence_id,
        requirement=requirement,
        cache=cache,
        source_host_path=source_host_path,
        actor=actor,
    )


def _load_requirement(
    db: Session, *, case_id: str, evidence_id: str
) -> MemorySymbolRequirement:
    requirement = (
        db.query(MemorySymbolRequirement)
        .filter(
            MemorySymbolRequirement.case_id == case_id,
            MemorySymbolRequirement.evidence_id == evidence_id,
        )
        .order_by(MemorySymbolRequirement.created_at.desc())
        .first()
    )
    if requirement is None:
        raise ExperimentalLifecycleError(
            "EXPERIMENTAL_REQUIREMENT_MISSING",
            "No exact symbol requirement is recorded for this evidence.",
        )
    return requirement


def get_active_candidate(
    db: Session,
    *,
    requirement_id: str,
) -> MemoryExperimentalSymbolCandidate | None:
    return (
        db.query(MemoryExperimentalSymbolCandidate)
        .filter(
            MemoryExperimentalSymbolCandidate.requirement_id == requirement_id,
            MemoryExperimentalSymbolCandidate.revoked_at.is_(None),
        )
        .first()
    )


def create_run(
    db: Session,
    *,
    case_id: str,
    evidence_id: str,
    candidate: MemoryExperimentalSymbolCandidate,
    requested_profiles: list[str] | None = None,
    actor: str,
) -> MemoryExperimentalRun:
    """Create a new experimental run in ``acknowledgement_required`` state."""
    require_feature_enabled()
    if candidate.revoked_at is not None:
        raise ExperimentalLifecycleError(
            "EXPERIMENTAL_CANDIDATE_REVOKED",
            "The candidate was revoked; create a new candidate first.",
        )
    try:
        verify_candidate_integrity(db, candidate=candidate)
    except ExperimentalImportError as exc:
        raise ExperimentalLifecycleError(
            "EXPERIMENTAL_CANDIDATE_UNAVAILABLE",
            exc.message,
            http_status=409,
        ) from exc
    # Disallow two active runs for the same evidence + candidate
    # at the same time.  "Active" means any non-terminal run.
    active = (
        db.query(MemoryExperimentalRun)
        .filter(
            MemoryExperimentalRun.case_id == case_id,
            MemoryExperimentalRun.evidence_id == evidence_id,
            MemoryExperimentalRun.deleted_at.is_(None),
            MemoryExperimentalRun.status.notin_(
                [
                    RUN_STATUS_DELETED,
                    RUN_STATUS_CANCELLED,
                ]
            ),
        )
        .first()
    )
    if active is not None:
        raise ExperimentalLifecycleError(
            "EXPERIMENTAL_RUN_ALREADY_ACTIVE",
            "An experimental run is already active for this evidence.",
            http_status=409,
        )
    if requested_profiles is None or not requested_profiles:
        requested_profiles = [
            item["profile"] for item in list_experimental_profiles()
        ]
    # Validate the requested profile names.
    valid_names = {item["profile"] for item in list_experimental_profiles()}
    unknown = [name for name in requested_profiles if name not in valid_names]
    if unknown:
        raise ExperimentalLifecycleError(
            "EXPERIMENTAL_PROFILE_UNKNOWN",
            f"Unknown experimental profile(s): {', '.join(sorted(unknown))}.",
        )
    run = MemoryExperimentalRun(
        id=str(uuid.uuid4()),
        case_id=case_id,
        evidence_id=evidence_id,
        candidate_id=candidate.id,
        requirement_id=candidate.requirement_id,
        cached_symbol_id=candidate.cached_symbol_id,
        status=RUN_STATUS_ACKNOWLEDGEMENT_REQUIRED,
        requested_profiles=list(requested_profiles),
        canary_profiles=[EXPERIMENTAL_CANARY_PROFILE],
        audit_metadata_json={"requested_actor": actor},
    )
    db.add(run)
    db.commit()
    db.refresh(run)
    return run


def record_acknowledgement(
    db: Session,
    *,
    run: MemoryExperimentalRun,
    candidate: MemoryExperimentalSymbolCandidate,
    payload: Any,
) -> MemoryExperimentalRun:
    """Record the acknowledgement payload on the run row.

    The function is the single server-side gate.  It validates
    the payload, persists the snapshot, and does NOT change
    ``status`` past ``acknowledgement_required`` (the lifecycle
    controller advances to ``canary_queued`` only when the canary
    worker picks up the run).
    """
    require_feature_enabled()
    if run.status != RUN_STATUS_ACKNOWLEDGEMENT_REQUIRED:
        raise ExperimentalLifecycleError(
            "EXPERIMENTAL_RUN_NOT_IN_ACK_STATE",
            f"Run is in status {run.status!r}; acknowledgement is no longer accepted.",
            http_status=409,
        )
    expected_required = build_required_identity_block(
        db.get(MemorySymbolRequirement, run.requirement_id)
    )
    try:
        _, _, _ = verify_candidate_integrity(db, candidate=candidate)
    except ExperimentalImportError as exc:
        raise ExperimentalLifecycleError(
            "EXPERIMENTAL_CANDIDATE_UNAVAILABLE",
            exc.message,
            http_status=409,
        ) from exc
    expected_observed = build_observed_identity_block(
        db.get(MemoryCachedSymbol, run.cached_symbol_id)
    )
    ok, error_code, normalised = validate_acknowledgement_payload(
        payload,
        run_id=run.id,
        expected_required=expected_required,
        expected_observed=expected_observed,
    )
    if not ok:
        raise ExperimentalLifecycleError(
            error_code or "EXPERIMENTAL_ACK_INVALID",
            "Acknowledgement payload was rejected.",
        )
    run.acknowledgement_actor = normalised["actor"]
    run.acknowledgement_at = utc_now_naive()
    run.acknowledgement_warning_version = normalised["warning_version"]
    run.acknowledgement_warning_text = EXPERIMENTAL_ACK_WARNING_TEXT
    run.acknowledgement_required_pdb_name = expected_required["pdb_name"]
    run.acknowledgement_required_pdb_guid = expected_required["pdb_guid"]
    run.acknowledgement_required_pdb_age = expected_required["pdb_age"]
    run.acknowledgement_required_architecture = expected_required["architecture"]
    run.acknowledgement_observed_pdb_name = expected_observed["pdb_name"]
    run.acknowledgement_observed_pdb_guid = expected_observed["pdb_guid"]
    run.acknowledgement_observed_pdb_age = expected_observed["pdb_age"]
    run.acknowledgement_observed_architecture = expected_observed["architecture"]
    run.audit_metadata_json = {
        **(run.audit_metadata_json or {}),
        "acknowledgement_fingerprint": normalised["fingerprint"],
        "acknowledged_at_iso": normalised["acknowledged_at"],
        "acknowledgement_actor_trust": normalised.get("actor_trust") or "unauthenticated_client_label",
    }
    db.add(run)
    db.commit()
    db.refresh(run)
    return run


def advance_to_canary_queue(
    db: Session,
    *,
    run: MemoryExperimentalRun,
    worker_task_id: str | None = None,
) -> MemoryExperimentalRun:
    """Mark the run as ready for the canary worker.

    The function is called by the API when the analyst confirms
    "Run canary" *after* the acknowledgement has been recorded.
    """
    if run.acknowledgement_at is None:
        raise ExperimentalLifecycleError(
            "EXPERIMENTAL_ACK_REQUIRED",
            "Acknowledgement must be recorded before the canary can start.",
            http_status=409,
        )
    if run.status not in {
        RUN_STATUS_ACKNOWLEDGEMENT_REQUIRED,
        RUN_STATUS_CANARY_QUEUED,
    }:
        raise ExperimentalLifecycleError(
            "EXPERIMENTAL_RUN_NOT_IN_ACK_STATE",
            f"Run is in status {run.status!r}; the canary cannot be enqueued.",
            http_status=409,
        )
    run.status = RUN_STATUS_CANARY_QUEUED
    run.canary_status = "pending"
    run.canary_worker_task_id = worker_task_id
    run.started_at = run.started_at or utc_now_naive()
    db.add(run)
    db.commit()
    db.refresh(run)
    return run


def mark_canary_running(db: Session, *, run: MemoryExperimentalRun) -> MemoryExperimentalRun:
    if run.status != RUN_STATUS_CANARY_QUEUED:
        raise ExperimentalLifecycleError(
            "EXPERIMENTAL_RUN_NOT_QUEUED",
            f"Run is in status {run.status!r}; cannot mark canary running.",
            http_status=409,
        )
    run.status = RUN_STATUS_CANARY_RUNNING
    run.canary_status = "running"
    run.canary_started_at = utc_now_naive()
    db.add(run)
    db.commit()
    db.refresh(run)
    return run


def finalize_canary(
    db: Session,
    *,
    run: MemoryExperimentalRun,
    rows: list[dict[str, Any]],
    plugin_rows: dict[str, list[dict[str, Any]]] | None = None,
    plugin_results: dict[str, dict[str, Any]] | None = None,
) -> MemoryExperimentalRun:
    """Evaluate the canary and persist the result.

    The function consumes the bounded plugin output the worker
    passes in and records the per-check status onto the run.
    A failed / inconclusive canary blocks continuation; a passed
    or degraded canary requires an operator override for the
    degraded case.
    """
    if run.status not in {RUN_STATUS_CANARY_RUNNING, RUN_STATUS_CANARY_QUEUED}:
        raise ExperimentalLifecycleError(
            "EXPERIMENTAL_RUN_NOT_RUNNING",
            f"Run is in status {run.status!r}; cannot finalize canary.",
            http_status=409,
        )
    result = evaluate_canary(rows=rows, plugin_rows=plugin_rows, plugin_results=plugin_results)
    run = persist_canary_result(db, run, result)
    aggregate = result["status"]
    if aggregate == CANARY_STATUS_PASSED:
        run.status = RUN_STATUS_CANARY_PASSED
    elif aggregate == CANARY_STATUS_DEGRADED:
        run.status = RUN_STATUS_CANARY_DEGRADED
    elif aggregate == CANARY_STATUS_INCONCLUSIVE:
        run.status = RUN_STATUS_CANARY_INCONCLUSIVE
    else:
        run.status = RUN_STATUS_CANARY_FAILED
        run.completed_at = utc_now_naive()
    db.add(run)
    db.commit()
    db.refresh(run)
    return run


def record_canary_override(
    db: Session,
    *,
    run: MemoryExperimentalRun,
    actor: str,
    reason: str,
) -> MemoryExperimentalRun:
    """Record an explicit operator override for a degraded or
    inconclusive canary.

    The override is the only path that allows a full run to
    proceed when the canary is not ``passed``.  The function
    does NOT change ``status``; the lifecycle controller
    advances the run to ``canary_passed`` / ``canary_degraded``
    after recording the override.
    """
    if run.status not in {RUN_STATUS_CANARY_DEGRADED, RUN_STATUS_CANARY_INCONCLUSIVE}:
        raise ExperimentalLifecycleError(
            "EXPERIMENTAL_CANARY_NOT_OVERRIDEABLE",
            f"Canary status is {run.canary_status!r}; override is not required.",
            http_status=409,
        )
    run.canary_override_at = utc_now_naive()
    run.canary_override_actor = actor
    run.canary_override_reason = reason
    run.canary_override_required = False
    # The override promotes the run to the canary outcome that
    # the analyst accepted.
    if run.canary_status == CANARY_STATUS_DEGRADED:
        run.status = RUN_STATUS_CANARY_DEGRADED
    else:
        run.status = RUN_STATUS_CANARY_INCONCLUSIVE
    db.add(run)
    db.commit()
    db.refresh(run)
    return run


def request_full_run(
    db: Session,
    *,
    run: MemoryExperimentalRun,
    worker_task_id: str | None = None,
) -> MemoryExperimentalRun:
    """Request the full experimental run.

    Allowed only when the canary is ``passed`` OR an explicit
    operator override has been recorded.  The full run is
    restricted to the profile subset allowed by the canary
    outcome.
    """
    if run.status not in {RUN_STATUS_CANARY_PASSED, RUN_STATUS_CANARY_DEGRADED, RUN_STATUS_CANARY_INCONCLUSIVE}:
        raise ExperimentalLifecycleError(
            "EXPERIMENTAL_CANARY_NOT_PASSED",
            f"Canary status is {run.canary_status!r}; full run is blocked.",
            http_status=409,
        )
    if run.status == RUN_STATUS_CANARY_INCONCLUSIVE:
        raise ExperimentalLifecycleError(
            "EXPERIMENTAL_CANARY_INCONCLUSIVE_BLOCKED",
            "Inconclusive canary runs cannot continue to a full experimental run.",
            http_status=409,
        )
    if run.status == RUN_STATUS_CANARY_DEGRADED and run.canary_override_at is None:
        raise ExperimentalLifecycleError(
            "EXPERIMENTAL_CANARY_OVERRIDE_REQUIRED",
            "Canary outcome is not 'passed'; operator override is required.",
            http_status=409,
        )
    run.status = RUN_STATUS_FULL_RUN_QUEUED
    run.full_worker_task_id = worker_task_id
    db.add(run)
    db.commit()
    db.refresh(run)
    return run


def mark_full_run_running(db: Session, *, run: MemoryExperimentalRun) -> MemoryExperimentalRun:
    if run.status != RUN_STATUS_FULL_RUN_QUEUED:
        raise ExperimentalLifecycleError(
            "EXPERIMENTAL_RUN_NOT_QUEUED",
            f"Run is in status {run.status!r}; cannot start full run.",
            http_status=409,
        )
    run.status = RUN_STATUS_FULL_RUN_RUNNING
    db.add(run)
    db.commit()
    db.refresh(run)
    return run


def record_profile_progress(
    db: Session,
    *,
    run: MemoryExperimentalRun,
    status_increment: dict[str, int] | None = None,
) -> MemoryExperimentalRun:
    """Bump the run's aggregate counters."""
    if status_increment:
        run.profiles_queued += int(status_increment.get("queued", 0) or 0)
        run.profiles_completed += int(status_increment.get("completed", 0) or 0)
        run.profiles_failed += int(status_increment.get("failed", 0) or 0)
        run.profiles_cancelled += int(status_increment.get("cancelled", 0) or 0)
    db.add(run)
    db.commit()
    db.refresh(run)
    return run


def finalise_run(
    db: Session,
    *,
    run: MemoryExperimentalRun,
    outcome: str,
) -> MemoryExperimentalRun:
    """Move a run to a terminal experimental outcome.

    ``outcome`` is one of:
        ``completed_untrusted`` / ``partial_untrusted`` /
        ``failed_untrusted``.
    """
    if outcome not in {
        RUN_STATUS_COMPLETED_UNTRUSTED,
        RUN_STATUS_PARTIAL_UNTRUSTED,
        RUN_STATUS_FAILED_UNTRUSTED,
    }:
        raise ExperimentalLifecycleError(
            "EXPERIMENTAL_RUN_OUTCOME_INVALID",
            f"Unknown outcome {outcome!r}.",
        )
    run.status = outcome
    run.completed_at = utc_now_naive()
    db.add(run)
    db.commit()
    db.refresh(run)
    return run


def cancel_run(
    db: Session,
    *,
    run: MemoryExperimentalRun,
    actor: str,
    reason: str,
) -> MemoryExperimentalRun:
    run.status = RUN_STATUS_CANCELLED
    run.cancelled_at = utc_now_naive()
    run.cancelled_by = actor
    run.cancellation_reason = reason
    run.completed_at = utc_now_naive()
    db.add(run)
    db.commit()
    db.refresh(run)
    return run


def delete_run(
    db: Session,
    *,
    run: MemoryExperimentalRun,
    actor: str,
    reason: str,
) -> MemoryExperimentalRun:
    """Mark a run as deleted and orphan its scan runs.

    The function only sets the run's ``deleted_at`` /
    ``deleted_by`` / ``deletion_reason`` fields; the actual
    OpenSearch cleanup is performed by the worker (so the
    API call remains cheap).  The exact symbol cache, the
    requirement and the validated runs are NEVER touched.
    """
    if run.status not in {
        RUN_STATUS_CANCELLED,
        RUN_STATUS_CANARY_FAILED,
        RUN_STATUS_CANARY_INCONCLUSIVE,
        RUN_STATUS_COMPLETED_UNTRUSTED,
        RUN_STATUS_PARTIAL_UNTRUSTED,
        RUN_STATUS_FAILED_UNTRUSTED,
    }:
        raise ExperimentalLifecycleError(
            "EXPERIMENTAL_DELETE_REQUIRES_TERMINAL_OR_CANCELLED",
            "Experimental runs can only be deleted after cancellation or a terminal state.",
            http_status=409,
        )
    run.status = RUN_STATUS_DELETED
    run.deleted_at = utc_now_naive()
    run.deleted_by = actor
    run.deletion_reason = reason
    run.completed_at = run.completed_at or utc_now_naive()
    db.add(run)
    db.commit()
    db.refresh(run)
    return run


def list_runs(
    db: Session,
    *,
    case_id: str,
    evidence_id: str,
    include_deleted: bool = False,
) -> list[MemoryExperimentalRun]:
    query = (
        db.query(MemoryExperimentalRun)
        .filter(
            MemoryExperimentalRun.case_id == case_id,
            MemoryExperimentalRun.evidence_id == evidence_id,
        )
    )
    if not include_deleted:
        query = query.filter(MemoryExperimentalRun.deleted_at.is_(None))
    return query.order_by(MemoryExperimentalRun.created_at.desc()).all()


def get_run(
    db: Session,
    *,
    case_id: str,
    evidence_id: str,
    run_id: str,
) -> MemoryExperimentalRun:
    run = db.get(MemoryExperimentalRun, run_id)
    if run is None:
        raise ExperimentalLifecycleError(
            "EXPERIMENTAL_RUN_NOT_FOUND",
            "Experimental run was not found.",
            http_status=404,
        )
    if run.case_id != case_id or run.evidence_id != evidence_id:
        raise ExperimentalLifecycleError(
            "EXPERIMENTAL_RUN_CROSS_CASE",
            "Run does not belong to the given case or evidence.",
            http_status=404,
        )
    return run


def canary_plugins() -> list[str]:
    return list(EXPERIMENTAL_CANARY_PLUGINS)


def canary_profile() -> str:
    return str(EXPERIMENTAL_CANARY_PROFILE)


def allowed_profiles(canary_status: str | None) -> list[str]:
    return allowed_profiles_for_canary_outcome(canary_status)


def trust_state(db: Session, *, case_id: str, evidence_id: str) -> dict[str, Any]:
    state = compute_trust_state(db, case_id=case_id, evidence_id=evidence_id)
    return state.to_dict()


def update_worker_heartbeat(
    db: Session,
    *,
    run: MemoryExperimentalRun,
    stage: str,
) -> MemoryExperimentalRun:
    run.audit_metadata_json = {
        **(run.audit_metadata_json or {}),
        "worker_heartbeat_at": utc_now_naive().isoformat(),
        "worker_stage": stage,
    }
    db.add(run)
    db.commit()
    db.refresh(run)
    return run


__all__ = [
    "ExperimentalLifecycleError",
    "advance_to_canary_queue",
    "allowed_profiles",
    "build_observed_identity_block",
    "build_required_identity_block",
    "cancel_run",
    "canary_plugins",
    "canary_profile",
    "create_run",
    "delete_run",
    "finalise_run",
    "finalize_canary",
    "get_active_candidate",
    "get_run",
    "list_candidates",
    "list_runs",
    "mark_canary_running",
    "mark_full_run_running",
    "record_acknowledgement",
    "record_canary_override",
    "record_profile_progress",
    "record_cli_candidate",
    "request_full_run",
    "require_feature_enabled",
    "revoke_candidate",
    "trust_state",
    "upsert_candidate",
    "update_worker_heartbeat",
]
