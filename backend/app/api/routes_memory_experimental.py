"""API routes for the experimental mismatched-symbol analysis.

The routes are intentionally isolated from the validated
artifact routes: a single dedicated router, a single dedicated
Pydantic payload set, and a single dedicated
trust-filter-on-every-query discipline.

All routes return 404 when the server-side experimental flag
is off, so the existence of the feature is not advertised to
untrusted callers.  The flag is read on every request; a
restart-free flag flip is reflected immediately.

The routes never expose the exact symbol cache, the exact
symbol requirement, the validated scan runs, the validated
OpenSearch index, the validated detection pipeline, or the
validated export.  The experimental artefacts are read
exclusively from the experimental OpenSearch index.
"""
from __future__ import annotations

import logging
from typing import Any

from fastapi import APIRouter, Body, Depends, HTTPException
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from app.api.routes_memory import _require_case
from app.core.database import get_db
from app.core.opensearch import get_opensearch_client
from app.models.case import Case
from app.models.evidence import Evidence, EvidenceType
from app.models.memory import (
    MemoryCachedSymbol,
    MemoryExperimentalRun,
    MemoryExperimentalSymbolCandidate,
    MemorySymbolRequirement,
)
from app.services.memory.experimental_acknowledgement import (
    build_warning_payload,
)
from app.services.memory.experimental_catalogue import (
    list_experimental_profiles,
)
from app.services.memory.experimental_indexing import (
    delete_experimental_documents_by_run,
    search_experimental_documents,
)
from app.services.memory.experimental_lifecycle import (
    ExperimentalLifecycleError,
    advance_to_canary_queue,
    allowed_profiles,
    build_observed_identity_block,
    build_required_identity_block,
    cancel_run,
    canary_plugins,
    canary_profile,
    create_run,
    delete_run,
    finalise_run,
    finalize_canary,
    get_active_candidate,
    get_run,
    list_candidates,
    list_runs,
    record_acknowledgement,
    record_canary_override,
    request_full_run,
    require_feature_enabled,
    revoke_candidate,
    trust_state,
    upsert_candidate,
)
from app.services.memory.experimental_trust import (
    RUN_STATUS_CANARY_PASSED,
    RUN_STATUS_DELETED,
    TRUST_LEVEL_UNTRUSTED,
    is_experimental_enabled,
)


logger = logging.getLogger(__name__)


router = APIRouter(prefix="/api", tags=["memory-experimental"])


# ---------------------------------------------------------------------------
# Pydantic payloads
# ---------------------------------------------------------------------------


class ExperimentalIdentityBlock(BaseModel):
    pdb_name: str
    pdb_guid: str
    pdb_age: int
    architecture: str


class ExperimentalAcknowledgementRequest(BaseModel):
    checkbox_confirmed: bool
    client_actor_label: str | None = None


class ExperimentalCreateRunRequest(BaseModel):
    requested_profiles: list[str] | None = None


class ExperimentalCanaryOverrideRequest(BaseModel):
    client_actor_label: str | None = None
    reason: str


class ExperimentalCancelRequest(BaseModel):
    client_actor_label: str | None = None
    reason: str


class ExperimentalDeleteRequest(BaseModel):
    client_actor_label: str | None = None
    reason: str


class ExperimentalFinalizeRequest(BaseModel):
    outcome: str  # completed_untrusted | partial_untrusted | failed_untrusted


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _require_evidence(db: Session, case_id: str, evidence_id: str) -> Evidence:
    evidence = db.get(Evidence, evidence_id)
    if evidence is None or evidence.case_id != case_id:
        raise HTTPException(status_code=404, detail="Evidence not found")
    if evidence.evidence_type != EvidenceType.memory_dump:
        raise HTTPException(
            status_code=400, detail="Experimental analysis is only supported for memory evidence."
        )
    return evidence


def _require_requirement_for_evidence(
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
        raise HTTPException(
            status_code=409,
            detail={
                "error_code": "EXPERIMENTAL_REQUIREMENT_MISSING",
                "message": "No exact symbol requirement is recorded for this evidence.",
            },
        )
    return requirement


def _require_candidate_scope(
    db: Session,
    *,
    case_id: str,
    evidence_id: str,
    candidate_id: str,
) -> MemoryExperimentalSymbolCandidate:
    candidate = db.get(MemoryExperimentalSymbolCandidate, candidate_id)
    if candidate is None or candidate.case_id != case_id or candidate.evidence_id != evidence_id:
        raise HTTPException(
            status_code=404,
            detail={
                "error_code": "EXPERIMENTAL_CANDIDATE_NOT_FOUND",
                "message": "Candidate was not found.",
            },
        )
    requirement = db.get(MemorySymbolRequirement, candidate.requirement_id)
    if requirement is None or requirement.case_id != case_id or requirement.evidence_id != evidence_id:
        raise HTTPException(status_code=404, detail="Candidate requirement not found")
    return candidate


def _require_run_scope(
    db: Session,
    *,
    case_id: str,
    evidence_id: str,
    run_id: str,
) -> MemoryExperimentalRun:
    run = db.get(MemoryExperimentalRun, run_id)
    if run is None or run.case_id != case_id or run.evidence_id != evidence_id:
        raise HTTPException(
            status_code=404,
            detail={"error_code": "EXPERIMENTAL_RUN_NOT_FOUND", "message": "Experimental run was not found."},
        )
    candidate = db.get(MemoryExperimentalSymbolCandidate, run.candidate_id)
    if candidate is None or candidate.case_id != case_id or candidate.evidence_id != evidence_id:
        raise HTTPException(status_code=404, detail="Run candidate not found")
    requirement = db.get(MemorySymbolRequirement, run.requirement_id)
    if requirement is None or requirement.case_id != case_id or requirement.evidence_id != evidence_id:
        raise HTTPException(status_code=404, detail="Run requirement not found")
    return run


def _candidate_to_dict(candidate: MemoryExperimentalSymbolCandidate) -> dict[str, Any]:
    return {
        "id": candidate.id,
        "case_id": candidate.case_id,
        "evidence_id": candidate.evidence_id,
        "requirement_id": candidate.requirement_id,
        "cached_symbol_id": candidate.cached_symbol_id,
        "required_identity": {
            "pdb_name": candidate.required_pdb_name,
            "pdb_guid": candidate.required_pdb_guid,
            "pdb_age": int(candidate.required_pdb_age),
            "architecture": candidate.required_architecture,
        },
        "observed_identity": {
            "pdb_name": candidate.observed_pdb_name,
            "pdb_guid": candidate.observed_pdb_guid,
            "pdb_age": int(candidate.observed_pdb_age),
            "architecture": candidate.observed_architecture,
        },
        "symbol_match_type": candidate.symbol_match_type,
        "symbol_warning": candidate.symbol_warning,
        "provenance_source_type": candidate.provenance_source_type,
        "provenance_source_name": candidate.provenance_source_name,
        "provenance_actor": candidate.provenance_actor,
        "pdb_sha256": candidate.pdb_sha256,
        "isf_sha256": candidate.isf_sha256,
        "isf_validation_status": candidate.isf_validation_status,
        "created_at": candidate.created_at.isoformat() if candidate.created_at else None,
        "revoked_at": candidate.revoked_at.isoformat() if candidate.revoked_at else None,
        "revoked_by": candidate.revoked_by,
        "revocation_reason": candidate.revocation_reason,
    }


def _run_to_dict(run: MemoryExperimentalRun) -> dict[str, Any]:
    return {
        "id": run.id,
        "case_id": run.case_id,
        "evidence_id": run.evidence_id,
        "candidate_id": run.candidate_id,
        "requirement_id": run.requirement_id,
        "cached_symbol_id": run.cached_symbol_id,
        "status": run.status,
        "acknowledgement": {
            "actor": run.acknowledgement_actor,
            "actor_trust": (run.audit_metadata_json or {}).get("acknowledgement_actor_trust"),
            "acknowledged_at": (
                run.acknowledgement_at.isoformat() if run.acknowledgement_at else None
            ),
            "warning_version": run.acknowledgement_warning_version,
            "required_identity": {
                "pdb_name": run.acknowledgement_required_pdb_name,
                "pdb_guid": run.acknowledgement_required_pdb_guid,
                "pdb_age": (
                    int(run.acknowledgement_required_pdb_age)
                    if run.acknowledgement_required_pdb_age is not None
                    else None
                ),
                "architecture": run.acknowledgement_required_architecture,
            },
            "observed_identity": {
                "pdb_name": run.acknowledgement_observed_pdb_name,
                "pdb_guid": run.acknowledgement_observed_pdb_guid,
                "pdb_age": (
                    int(run.acknowledgement_observed_pdb_age)
                    if run.acknowledgement_observed_pdb_age is not None
                    else None
                ),
                "architecture": run.acknowledgement_observed_architecture,
            },
        },
        "canary": {
            "status": run.canary_status,
            "score": run.canary_score,
            "checks": list(run.canary_checks or []),
            "summary": dict(run.canary_summary or {}),
            "started_at": (
                run.canary_started_at.isoformat() if run.canary_started_at else None
            ),
            "completed_at": (
                run.canary_completed_at.isoformat() if run.canary_completed_at else None
            ),
            "override_required": bool(run.canary_override_required),
            "override_at": (
                run.canary_override_at.isoformat() if run.canary_override_at else None
            ),
            "override_actor": run.canary_override_actor,
            "override_reason": run.canary_override_reason,
        },
        "requested_profiles": list(run.requested_profiles or []),
        "canary_profiles": list(run.canary_profiles or []),
        "allowed_profiles": allowed_profiles(run.canary_status),
        "canary_profile": canary_profile(),
        "canary_plugins": canary_plugins(),
        "profiles_queued": int(run.profiles_queued or 0),
        "profiles_completed": int(run.profiles_completed or 0),
        "profiles_failed": int(run.profiles_failed or 0),
        "profiles_cancelled": int(run.profiles_cancelled or 0),
        "started_at": run.started_at.isoformat() if run.started_at else None,
        "completed_at": run.completed_at.isoformat() if run.completed_at else None,
        "cancelled_at": run.cancelled_at.isoformat() if run.cancelled_at else None,
        "cancelled_by": run.cancelled_by,
        "cancellation_reason": run.cancellation_reason,
        "deleted_at": run.deleted_at.isoformat() if run.deleted_at else None,
        "deleted_by": run.deleted_by,
        "deletion_reason": run.deletion_reason,
        "created_at": run.created_at.isoformat() if run.created_at else None,
        "updated_at": run.updated_at.isoformat() if run.updated_at else None,
    }


def _feature_guard() -> None:
    """Return 404 when the experimental feature is off.

    The single source of truth is
    ``is_experimental_enabled()``.  The error code is the
    constant ``EXPERIMENTAL_DISABLED`` so the UI can render a
    stable, never-translated error string.
    """
    if not is_experimental_enabled():
        raise HTTPException(
            status_code=404,
            detail={
                "error_code": "EXPERIMENTAL_DISABLED",
                "message": "Experimental mismatched-symbol analysis is disabled.",
            },
        )


def _handle_lifecycle_error(exc: ExperimentalLifecycleError) -> HTTPException:
    return HTTPException(status_code=exc.http_status, detail={
        "error_code": exc.error_code,
        "message": exc.message,
    })


# ---------------------------------------------------------------------------
# Trust / catalogue / warning
# ---------------------------------------------------------------------------


@router.get(
    "/cases/{case_id}/memory/evidences/{evidence_id}/experimental-trust",
    response_model=None,
)
def get_experimental_trust(
    case_id: str,
    evidence_id: str,
    db: Session = Depends(get_db),
) -> dict[str, Any]:
    _feature_guard()
    _require_case(db, case_id)
    _require_evidence(db, case_id, evidence_id)
    return trust_state(db, case_id=case_id, evidence_id=evidence_id)


@router.get(
    "/cases/{case_id}/memory/evidences/{evidence_id}/experimental-warning",
    response_model=None,
)
def get_experimental_warning(
    case_id: str,
    evidence_id: str,
    db: Session = Depends(get_db),
) -> dict[str, Any]:
    _feature_guard()
    _require_case(db, case_id)
    _require_evidence(db, case_id, evidence_id)
    return build_warning_payload()


@router.get(
    "/cases/{case_id}/memory/evidences/{evidence_id}/experimental-profile-catalogue",
    response_model=None,
)
def get_experimental_profile_catalogue(
    case_id: str,
    evidence_id: str,
    db: Session = Depends(get_db),
) -> dict[str, Any]:
    _feature_guard()
    _require_case(db, case_id)
    _require_evidence(db, case_id, evidence_id)
    return {
        "canary_profile": canary_profile(),
        "canary_plugins": canary_plugins(),
        "profiles": list_experimental_profiles(),
    }


# ---------------------------------------------------------------------------
# Candidate lifecycle
# ---------------------------------------------------------------------------


@router.get(
    "/cases/{case_id}/memory/evidences/{evidence_id}/experimental-symbol-candidates",
    response_model=None,
)
def list_experimental_symbol_candidates(
    case_id: str,
    evidence_id: str,
    db: Session = Depends(get_db),
) -> dict[str, Any]:
    _feature_guard()
    _require_case(db, case_id)
    _require_evidence(db, case_id, evidence_id)
    candidates = list_candidates(db, case_id=case_id, evidence_id=evidence_id)
    return {
        "case_id": case_id,
        "evidence_id": evidence_id,
        "items": [_candidate_to_dict(c) for c in candidates],
    }


@router.post(
    "/cases/{case_id}/memory/evidences/{evidence_id}/experimental-symbol-candidates",
    response_model=None,
    status_code=201,
)
def create_experimental_symbol_candidate(
    case_id: str,
    evidence_id: str,
    payload: dict[str, Any] = Body(...),
    db: Session = Depends(get_db),
) -> dict[str, Any]:
    _feature_guard()
    _require_case(db, case_id)
    _require_evidence(db, case_id, evidence_id)
    requirement = _require_requirement_for_evidence(db, case_id=case_id, evidence_id=evidence_id)
    cached_symbol_id = payload.get("cached_symbol_id")
    if not cached_symbol_id:
        raise HTTPException(
            status_code=400,
            detail={
                "error_code": "EXPERIMENTAL_CANDIDATE_MISSING",
                "message": "A cached_symbol_id must be supplied.",
            },
        )
    cache = db.get(MemoryCachedSymbol, cached_symbol_id)
    if cache is None:
        raise HTTPException(
            status_code=404,
            detail={
                "error_code": "EXPERIMENTAL_CANDIDATE_MISSING",
                "message": "The candidate symbol was not found in the cache.",
            },
        )
    try:
        candidate = upsert_candidate(
            db,
            case_id=case_id,
            evidence_id=evidence_id,
            requirement=requirement,
            cache=cache,
            source_host_path=payload.get("source_host_path"),
            actor=str(payload.get("actor") or "server-operator"),
        )
    except ExperimentalLifecycleError as exc:
        raise _handle_lifecycle_error(exc)
    return _candidate_to_dict(candidate)


@router.post(
    "/cases/{case_id}/memory/evidences/{evidence_id}/experimental-symbol-candidates/{candidate_id}/revoke",
    response_model=None,
)
def revoke_experimental_symbol_candidate(
    case_id: str,
    evidence_id: str,
    candidate_id: str,
    payload: ExperimentalCancelRequest,
    db: Session = Depends(get_db),
) -> dict[str, Any]:
    _feature_guard()
    _require_case(db, case_id)
    _require_evidence(db, case_id, evidence_id)
    candidate = _require_candidate_scope(
        db,
        case_id=case_id,
        evidence_id=evidence_id,
        candidate_id=candidate_id,
    )
    candidate = revoke_candidate(
        db,
        candidate=candidate,
        actor=f"unauthenticated_client_label:{(payload.client_actor_label or '').strip() or 'anonymous'}",
        reason=payload.reason,
    )
    return _candidate_to_dict(candidate)


# ---------------------------------------------------------------------------
# Run lifecycle
# ---------------------------------------------------------------------------


@router.get(
    "/cases/{case_id}/memory/evidences/{evidence_id}/experimental-runs",
    response_model=None,
)
def list_experimental_runs(
    case_id: str,
    evidence_id: str,
    include_deleted: bool = False,
    db: Session = Depends(get_db),
) -> dict[str, Any]:
    _feature_guard()
    _require_case(db, case_id)
    _require_evidence(db, case_id, evidence_id)
    runs = list_runs(
        db,
        case_id=case_id,
        evidence_id=evidence_id,
        include_deleted=include_deleted,
    )
    return {
        "case_id": case_id,
        "evidence_id": evidence_id,
        "items": [_run_to_dict(r) for r in runs],
    }


@router.post(
    "/cases/{case_id}/memory/evidences/{evidence_id}/experimental-runs",
    response_model=None,
    status_code=201,
)
def create_experimental_run(
    case_id: str,
    evidence_id: str,
    payload: ExperimentalCreateRunRequest,
    db: Session = Depends(get_db),
) -> dict[str, Any]:
    _feature_guard()
    _require_case(db, case_id)
    _require_evidence(db, case_id, evidence_id)
    candidate = _get_active_candidate_for(db, case_id=case_id, evidence_id=evidence_id)
    try:
        run = create_run(
            db,
            case_id=case_id,
            evidence_id=evidence_id,
            candidate=candidate,
            requested_profiles=payload.requested_profiles,
            actor="server-operator",
        )
    except ExperimentalLifecycleError as exc:
        raise _handle_lifecycle_error(exc)
    return _run_to_dict(run)


@router.get(
    "/cases/{case_id}/memory/evidences/{evidence_id}/experimental-runs/{run_id}",
    response_model=None,
)
def get_experimental_run(
    case_id: str,
    evidence_id: str,
    run_id: str,
    db: Session = Depends(get_db),
) -> dict[str, Any]:
    _feature_guard()
    _require_case(db, case_id)
    _require_evidence(db, case_id, evidence_id)
    try:
        run = get_run(db, case_id=case_id, evidence_id=evidence_id, run_id=run_id)
        run = _require_run_scope(db, case_id=case_id, evidence_id=evidence_id, run_id=run.id)
    except ExperimentalLifecycleError as exc:
        raise _handle_lifecycle_error(exc)
    return _run_to_dict(run)


@router.post(
    "/cases/{case_id}/memory/evidences/{evidence_id}/experimental-runs/{run_id}/acknowledge",
    response_model=None,
)
def acknowledge_experimental_run(
    case_id: str,
    evidence_id: str,
    run_id: str,
    payload: ExperimentalAcknowledgementRequest,
    db: Session = Depends(get_db),
) -> dict[str, Any]:
    _feature_guard()
    _require_case(db, case_id)
    _require_evidence(db, case_id, evidence_id)
    try:
        run = get_run(db, case_id=case_id, evidence_id=evidence_id, run_id=run_id)
        run = _require_run_scope(db, case_id=case_id, evidence_id=evidence_id, run_id=run.id)
    except ExperimentalLifecycleError as exc:
        raise _handle_lifecycle_error(exc)
    candidate = db.get(MemoryExperimentalSymbolCandidate, run.candidate_id)
    if candidate is None:
        raise HTTPException(
            status_code=404,
            detail={
                "error_code": "EXPERIMENTAL_CANDIDATE_NOT_FOUND",
                "message": "Candidate was not found.",
            },
        )
    try:
        run = record_acknowledgement(db, run=run, candidate=candidate, payload=payload.dict())
    except ExperimentalLifecycleError as exc:
        raise _handle_lifecycle_error(exc)
    return _run_to_dict(run)


@router.post(
    "/cases/{case_id}/memory/evidences/{evidence_id}/experimental-runs/{run_id}/start-canary",
    response_model=None,
)
def start_experimental_canary(
    case_id: str,
    evidence_id: str,
    run_id: str,
    db: Session = Depends(get_db),
) -> dict[str, Any]:
    _feature_guard()
    _require_case(db, case_id)
    _require_evidence(db, case_id, evidence_id)
    try:
        run = get_run(db, case_id=case_id, evidence_id=evidence_id, run_id=run_id)
        run = _require_run_scope(db, case_id=case_id, evidence_id=evidence_id, run_id=run.id)
    except ExperimentalLifecycleError as exc:
        raise _handle_lifecycle_error(exc)
    try:
        run = advance_to_canary_queue(db, run=run, worker_task_id=None)
    except ExperimentalLifecycleError as exc:
        raise _handle_lifecycle_error(exc)
    # Dispatch on the dedicated experimental queue.
    try:
        from app.workers.tasks import enqueue_experimental_canary

        worker_task_id = enqueue_experimental_canary(run.id)
        from app.core.database import SessionLocal
        from app.core.database import utc_now_naive as _now

        with SessionLocal() as session:
            local = session.get(MemoryExperimentalRun, run.id)
            if local is not None:
                local.canary_worker_task_id = worker_task_id
                session.add(local)
                session.commit()
                run = session.get(MemoryExperimentalRun, run.id)
    except Exception as exc:  # noqa: BLE001
        logger.warning("could not enqueue experimental canary: %s", exc)
    return _run_to_dict(run)


@router.post(
    "/cases/{case_id}/memory/evidences/{evidence_id}/experimental-runs/{run_id}/canary-override",
    response_model=None,
)
def override_experimental_canary(
    case_id: str,
    evidence_id: str,
    run_id: str,
    payload: ExperimentalCanaryOverrideRequest,
    db: Session = Depends(get_db),
) -> dict[str, Any]:
    _feature_guard()
    _require_case(db, case_id)
    _require_evidence(db, case_id, evidence_id)
    try:
        run = get_run(db, case_id=case_id, evidence_id=evidence_id, run_id=run_id)
        run = _require_run_scope(db, case_id=case_id, evidence_id=evidence_id, run_id=run.id)
    except ExperimentalLifecycleError as exc:
        raise _handle_lifecycle_error(exc)
    try:
        run = record_canary_override(
            db,
            run=run,
            actor=f"unauthenticated_client_label:{(payload.client_actor_label or '').strip() or 'anonymous'}",
            reason=payload.reason,
        )
    except ExperimentalLifecycleError as exc:
        raise _handle_lifecycle_error(exc)
    return _run_to_dict(run)


@router.post(
    "/cases/{case_id}/memory/evidences/{evidence_id}/experimental-runs/{run_id}/continue",
    response_model=None,
)
def continue_experimental_run(
    case_id: str,
    evidence_id: str,
    run_id: str,
    db: Session = Depends(get_db),
) -> dict[str, Any]:
    _feature_guard()
    _require_case(db, case_id)
    _require_evidence(db, case_id, evidence_id)
    try:
        run = get_run(db, case_id=case_id, evidence_id=evidence_id, run_id=run_id)
        run = _require_run_scope(db, case_id=case_id, evidence_id=evidence_id, run_id=run.id)
    except ExperimentalLifecycleError as exc:
        raise _handle_lifecycle_error(exc)
    try:
        from app.services.memory.experimental_worker import queue_experimental_full_run

        queue_experimental_full_run(db, run=run)
        run = db.get(MemoryExperimentalRun, run.id) or run
    except ExperimentalLifecycleError as exc:
        raise _handle_lifecycle_error(exc)
    allowed = allowed_profiles(run.canary_status)
    try:
        from app.workers.tasks import enqueue_experimental_profile

        for profile in allowed:
            if profile in set(run.requested_profiles or []):
                enqueue_experimental_profile(run.id, profile)
    except Exception as exc:  # noqa: BLE001
        logger.warning("could not enqueue experimental profiles: %s", exc)
    return _run_to_dict(run)


@router.post(
    "/cases/{case_id}/memory/evidences/{evidence_id}/experimental-runs/{run_id}/cancel",
    response_model=None,
)
def cancel_experimental_run(
    case_id: str,
    evidence_id: str,
    run_id: str,
    payload: ExperimentalCancelRequest,
    db: Session = Depends(get_db),
) -> dict[str, Any]:
    _feature_guard()
    _require_case(db, case_id)
    _require_evidence(db, case_id, evidence_id)
    try:
        run = get_run(db, case_id=case_id, evidence_id=evidence_id, run_id=run_id)
        run = _require_run_scope(db, case_id=case_id, evidence_id=evidence_id, run_id=run.id)
    except ExperimentalLifecycleError as exc:
        raise _handle_lifecycle_error(exc)
    try:
        run = cancel_run(
            db,
            run=run,
            actor=f"unauthenticated_client_label:{(payload.client_actor_label or '').strip() or 'anonymous'}",
            reason=payload.reason,
        )
    except ExperimentalLifecycleError as exc:
        raise _handle_lifecycle_error(exc)
    return _run_to_dict(run)


@router.post(
    "/cases/{case_id}/memory/evidences/{evidence_id}/experimental-runs/{run_id}/finalize",
    response_model=None,
)
def finalize_experimental_run(
    case_id: str,
    evidence_id: str,
    run_id: str,
    payload: ExperimentalFinalizeRequest,
    db: Session = Depends(get_db),
) -> dict[str, Any]:
    _feature_guard()
    _require_case(db, case_id)
    _require_evidence(db, case_id, evidence_id)
    try:
        run = get_run(db, case_id=case_id, evidence_id=evidence_id, run_id=run_id)
    except ExperimentalLifecycleError as exc:
        raise _handle_lifecycle_error(exc)
    try:
        run = finalise_run(db, run=run, outcome=payload.outcome)
    except ExperimentalLifecycleError as exc:
        raise _handle_lifecycle_error(exc)
    return _run_to_dict(run)


@router.delete(
    "/cases/{case_id}/memory/evidences/{evidence_id}/experimental-runs/{run_id}",
    response_model=None,
)
def delete_experimental_run(
    case_id: str,
    evidence_id: str,
    run_id: str,
    payload: ExperimentalDeleteRequest,
    db: Session = Depends(get_db),
) -> dict[str, Any]:
    _feature_guard()
    _require_case(db, case_id)
    _require_evidence(db, case_id, evidence_id)
    try:
        run = get_run(db, case_id=case_id, evidence_id=evidence_id, run_id=run_id)
        run = _require_run_scope(db, case_id=case_id, evidence_id=evidence_id, run_id=run.id)
    except ExperimentalLifecycleError as exc:
        raise _handle_lifecycle_error(exc)
    run = delete_run(
        db,
        run=run,
        actor=f"unauthenticated_client_label:{(payload.client_actor_label or '').strip() or 'anonymous'}",
        reason=payload.reason,
    )
    # Schedule OpenSearch cleanup.  The endpoint is cheap even
    # if the worker is offline: the next worker start will pick
    # the job up and clear the documents.
    try:
        from app.workers.tasks import enqueue_experimental_deletion

        enqueue_experimental_deletion(case_id, evidence_id, run.id)
    except Exception as exc:  # noqa: BLE001
        logger.warning("could not enqueue experimental deletion: %s", exc)
    return _run_to_dict(run)


# ---------------------------------------------------------------------------
# Experimental artefacts (read-only)
# ---------------------------------------------------------------------------


@router.get(
    "/cases/{case_id}/memory/evidences/{evidence_id}/experimental-runs/{run_id}/artifacts",
    response_model=None,
)
def get_experimental_run_artifacts(
    case_id: str,
    evidence_id: str,
    run_id: str,
    document_type: str | None = None,
    page: int = 1,
    page_size: int = 50,
    db: Session = Depends(get_db),
) -> dict[str, Any]:
    _feature_guard()
    _require_case(db, case_id)
    _require_evidence(db, case_id, evidence_id)
    try:
        run = get_run(db, case_id=case_id, evidence_id=evidence_id, run_id=run_id)
        run = _require_run_scope(db, case_id=case_id, evidence_id=evidence_id, run_id=run.id)
    except ExperimentalLifecycleError as exc:
        raise _handle_lifecycle_error(exc)
    if run.status == RUN_STATUS_DELETED:
        return {
            "items": [],
            "total": 0,
            "page": page,
            "page_size": page_size,
            "run_status": run.status,
        }
    result = search_experimental_documents(
        case_id,
        experimental_run_id=run.id,
        evidence_id=evidence_id,
        document_type=document_type,
        page=page,
        page_size=page_size,
    )
    result["run_status"] = run.status
    result["trust_level"] = TRUST_LEVEL_UNTRUSTED
    return result


@router.get(
    "/cases/{case_id}/memory/evidences/{evidence_id}/experimental-runs/{run_id}/export",
    response_model=None,
)
def export_experimental_run(
    case_id: str,
    evidence_id: str,
    run_id: str,
    db: Session = Depends(get_db),
) -> dict[str, Any]:
    """Return an experimental export payload with mandatory warnings.

    The payload is consumed by the UI to render a printable
    PDF / JSON export.  Every record carries the required and
    observed identities, the canary outcome, and the
    unmissable "experimental / untrusted" warning.  The
    payload is NEVER merged into the standard case export.
    """
    _feature_guard()
    _require_case(db, case_id)
    _require_evidence(db, case_id, evidence_id)
    try:
        run = get_run(db, case_id=case_id, evidence_id=evidence_id, run_id=run_id)
        run = _require_run_scope(db, case_id=case_id, evidence_id=evidence_id, run_id=run.id)
    except ExperimentalLifecycleError as exc:
        raise _handle_lifecycle_error(exc)
    artefacts = search_experimental_documents(
        case_id, experimental_run_id=run.id, evidence_id=evidence_id, page=1, page_size=1000,
    )
    warning = (
        "EXPERIMENTAL MISMATCHED-SYMBOL ANALYSIS -- NOT VALIDATED FORENSIC EVIDENCE"
    )
    return {
        "warning": warning,
        "warning_full_text": build_warning_payload()["warning_text"],
        "trust_level": TRUST_LEVEL_UNTRUSTED,
        "run_id": run.id,
        "case_id": case_id,
        "evidence_id": evidence_id,
        "required_identity": {
            "pdb_name": run.acknowledgement_required_pdb_name,
            "pdb_guid": run.acknowledgement_required_pdb_guid,
            "pdb_age": (
                int(run.acknowledgement_required_pdb_age)
                if run.acknowledgement_required_pdb_age is not None
                else None
            ),
            "architecture": run.acknowledgement_required_architecture,
        },
        "observed_identity": {
            "pdb_name": run.acknowledgement_observed_pdb_name,
            "pdb_guid": run.acknowledgement_observed_pdb_guid,
            "pdb_age": (
                int(run.acknowledgement_observed_pdb_age)
                if run.acknowledgement_observed_pdb_age is not None
                else None
            ),
            "architecture": run.acknowledgement_observed_architecture,
        },
        "canary": {
            "status": run.canary_status,
            "score": run.canary_score,
            "checks": list(run.canary_checks or []),
            "summary": dict(run.canary_summary or {}),
        },
        "status": run.status,
        "items": artefacts.get("items", []),
        "total": artefacts.get("total", 0),
    }


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------


def _get_active_candidate_for(
    db: Session, *, case_id: str, evidence_id: str
) -> MemoryExperimentalSymbolCandidate:
    """Return the active candidate for an evidence or raise 409."""
    candidates = list_candidates(db, case_id=case_id, evidence_id=evidence_id)
    for c in candidates:
        if c.revoked_at is None:
            return c
    raise HTTPException(
        status_code=409,
        detail={
            "error_code": "EXPERIMENTAL_CANDIDATE_UNAVAILABLE",
            "message": "No active experimental symbol candidate for this evidence.",
        },
    )
