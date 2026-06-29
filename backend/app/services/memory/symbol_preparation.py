"""Content-identity and per-evidence symbol preparation.

This module is the core of the automatic Windows symbol resolution
flow.  It introduces three concepts that decouple the analyst's
mental model from the database identity:

* ``MemoryEvidenceContent`` — a stable content identity
  (``evidence_sha256`` + ``size_bytes``) that survives re-uploads.
* ``MemoryEvidenceSymbolLink`` — a per-evidence link to a
  ``MemorySymbolRequirement``.  Several evidences can share the
  same requirement.
* ``MemorySymbolPreparation`` — the per-evidence state machine
  that drives the preparation pipeline (probe → cache check →
  acquisition → ready).

The public functions are:

* :func:`register_evidence_content_identity` — called on upload /
  register; idempotent and SHA-based.
* :func:`link_evidence_to_requirement` — attach a requirement to an
  evidence.
* :func:`find_requirement_by_content_identity` — look for an
  existing requirement that matches the same SHA + size.
* :func:`schedule_preparation` — create a queued preparation row.
* :func:`mark_preparation` — transition the preparation state.
* :func:`consume_preparation` — read the latest preparation.
* :func:`reconcile_memory_symbol_readiness` — global reconciliation
  (called at startup and periodically).
"""
from __future__ import annotations

import logging
from dataclasses import dataclass
from datetime import timedelta
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.config import get_settings
from app.core.database import utc_now_naive
from app.models.case import Case
from app.models.evidence import Evidence
from app.models.memory import (
    MemoryCachedSymbol,
    MemoryEvidenceContent,
    MemoryEvidenceSymbolLink,
    MemorySymbolNegativeCache,
    MemorySymbolPendingAnalysis,
    MemorySymbolPreparation,
    MemorySymbolRequirement,
)
from app.services.memory.symbol_resolver import (
    normalize_age,
    normalize_architecture,
    normalize_guid,
    normalize_pdb_name,
    symbol_identifier,
)


logger = logging.getLogger(__name__)


# Preparation state values (single source of truth; see migration
# documentation).  These are the values the UI sees as well.
#
# v1 stabilization set: pending, queued, probing, acquiring,
# converting, verifying, ready, failed, cancelled, stale.  The
# legacy identifiers (identified, cache_hit, acquisition_pending,
# isf_creation, requirement_unknown, acquisition_failed,
# unsupported, negative_cached) are kept as aliases for the
# migration period but new code should only emit the canonical
# names below.
PREP_PENDING = "pending"
PREP_QUEUED = "queued"
PREP_PROBING = "probing"
PREP_ACQUIRING = "acquiring"
PREP_CONVERTING = "converting"
PREP_VERIFYING = "verifying"
PREP_READY = "ready"
PREP_FAILED = "failed"
PREP_CANCELLED = "cancelled"
PREP_STALE = "stale"
# Sprint 6 (OS-agnostic preparation) additions.
PREP_DISPATCH_FAILED_STATE = "dispatch_failed"
PREP_PLATFORM_NOT_IDENTIFIED_STATE = "platform_not_identified"
PREP_PLATFORM_NOT_SUPPORTED_STATE = "platform_not_supported"
PREP_BLOCKED = "blocked"
# Sprint: bounded requirement discovery.  The preparation knows
# the exact symbol requirement but the offline cache is empty;
# the operator must approve a managed acquisition or seed the
# cache for preparation to advance to ``ready``.
PREP_BLOCKED_SYMBOLS = "blocked_symbols"

# Legacy aliases (kept for the migration period).
PREP_IDENTIFIED = "identified"
PREP_CACHE_HIT = "cache_hit"
PREP_ACQUISITION_PENDING = "acquisition_pending"
PREP_ISF_CREATION = "isf_creation"
PREP_REQUIREMENT_UNKNOWN = "requirement_unknown"
PREP_ACQUISITION_FAILED = "acquisition_failed"
PREP_UNSUPPORTED = "unsupported"
PREP_NEGATIVE_CACHED = "negative_cached"

ALL_PREP_STATES = frozenset(
    {
        PREP_PENDING,
        PREP_QUEUED,
        PREP_PROBING,
        PREP_ACQUIRING,
        PREP_CONVERTING,
        PREP_VERIFYING,
        PREP_READY,
        PREP_FAILED,
        PREP_CANCELLED,
        PREP_STALE,
        PREP_DISPATCH_FAILED_STATE,
        PREP_PLATFORM_NOT_IDENTIFIED_STATE,
        PREP_PLATFORM_NOT_SUPPORTED_STATE,
        PREP_BLOCKED,
        PREP_BLOCKED_SYMBOLS,
        # Legacy aliases (still in the DB; keep them in the set so
        # older rows pass validation).
        PREP_IDENTIFIED,
        PREP_CACHE_HIT,
        PREP_ACQUISITION_PENDING,
        PREP_ISF_CREATION,
        PREP_REQUIREMENT_UNKNOWN,
        PREP_ACQUISITION_FAILED,
        PREP_UNSUPPORTED,
        PREP_NEGATIVE_CACHED,
    }
)


# Top-level states exposed to the UI.  These group the preparation
# sub-states into a small set the analyst needs to act on.
UI_STATE_READY = "ready"
UI_STATE_PREPARING = "preparing"
UI_STATE_BLOCKED = "blocked"
UI_STATE_FAILED = "failed"


def ui_state_for(prep_state: str) -> str:
    if prep_state == PREP_READY:
        return UI_STATE_READY
    if prep_state == PREP_REQUIREMENT_UNKNOWN:
        return UI_STATE_PREPARING
    if prep_state in {PREP_NEGATIVE_CACHED}:
        return UI_STATE_BLOCKED
    if prep_state in {PREP_BLOCKED, PREP_BLOCKED_SYMBOLS, PREP_PLATFORM_NOT_IDENTIFIED_STATE, PREP_PLATFORM_NOT_SUPPORTED_STATE}:
        return UI_STATE_BLOCKED
    if prep_state in {PREP_CANCELLED, PREP_ACQUISITION_FAILED, PREP_UNSUPPORTED, PREP_FAILED, PREP_DISPATCH_FAILED_STATE}:
        return UI_STATE_FAILED
    return UI_STATE_PREPARING


# -----------------------------------------------------------------------------
# Content identity
# -----------------------------------------------------------------------------


def normalize_sha256(value: str | None) -> str:
    """Lower-case, strip whitespace."""
    if not value:
        return ""
    return str(value).strip().lower()


def content_identity_key(evidence: Evidence) -> tuple[str, int]:
    """Return the (sha256, size) tuple that uniquely identifies the
    content of a memory evidence.  When the SHA is missing we use a
    deterministic placeholder so the lookup still works (the
    reuse path will simply miss).
    """
    sha = normalize_sha256(evidence.sha256)
    if not sha:
        sha = f"unknown:{evidence.id}"
    return (sha, int(evidence.size_bytes or 0))


def register_evidence_content_identity(
    db: Session,
    *,
    evidence: Evidence,
) -> MemoryEvidenceContent:
    """Ensure a ``MemoryEvidenceContent`` row exists for the evidence.

    Idempotent: re-uploading the same file produces the same
    content identity.  When the file's SHA-256 differs, a new
    content row is created.
    """
    sha, size = content_identity_key(evidence)
    content = (
        db.query(MemoryEvidenceContent)
        .filter(
            MemoryEvidenceContent.evidence_sha256 == sha,
            MemoryEvidenceContent.size_bytes == size,
        )
        .first()
    )
    if content is not None:
        # Refresh acquisition metadata from the latest registration.
        if not content.acquisition_metadata:
            content.acquisition_metadata = {}
        ingest_source = (evidence.ingest_source or {}) if isinstance(evidence.ingest_source, dict) else {}
        for key in ("provided_host", "upload_state"):
            value = ingest_source.get(key)
            if value and key not in content.acquisition_metadata:
                content.acquisition_metadata[key] = value
        return content
    content = MemoryEvidenceContent(
        evidence_sha256=sha,
        size_bytes=size,
        acquisition_metadata={
            "first_evidence_id": evidence.id,
            "first_filename": evidence.original_filename,
        },
    )
    db.add(content)
    db.flush()
    return content


def find_requirement_by_content_identity(
    db: Session,
    *,
    evidence: Evidence,
) -> MemorySymbolRequirement | None:
    """Return the most recent requirement for the same content
    identity (SHA + size), if any.
    """
    sha, size = content_identity_key(evidence)
    content = (
        db.query(MemoryEvidenceContent)
        .filter(
            MemoryEvidenceContent.evidence_sha256 == sha,
            MemoryEvidenceContent.size_bytes == size,
        )
        .first()
    )
    if content is None or content.last_requirement_id is None:
        return None
    return db.get(MemorySymbolRequirement, content.last_requirement_id)


# -----------------------------------------------------------------------------
# Per-evidence link
# -----------------------------------------------------------------------------


def link_evidence_to_requirement(
    db: Session,
    *,
    evidence: Evidence,
    requirement: MemorySymbolRequirement,
    link_source: str = "probe",
    state: str = PREP_IDENTIFIED,
) -> MemoryEvidenceSymbolLink:
    """Create or update a per-evidence link to a requirement.

    Idempotent: re-linking the same evidence + requirement pair
    is a no-op (other than the state transition).
    """
    link = (
        db.query(MemoryEvidenceSymbolLink)
        .filter(
            MemoryEvidenceSymbolLink.evidence_id == evidence.id,
            MemoryEvidenceSymbolLink.requirement_id == requirement.id,
        )
        .first()
    )
    if link is None:
        link = MemoryEvidenceSymbolLink(
            case_id=evidence.case_id,
            evidence_id=evidence.id,
            requirement_id=requirement.id,
            link_source=link_source,
            state=state,
        )
        db.add(link)
    else:
        link.state = state
        if not link.link_source or link_source == "probe":
            link.link_source = link_source
    db.flush()
    return link


# -----------------------------------------------------------------------------
# Preparation state machine
# -----------------------------------------------------------------------------


@dataclass
class PreparationSummary:
    evidence_id: str
    state: str
    requirement_id: str | None
    error_code: str | None
    sanitized_message: str | None
    attempts: int
    next_attempt_at: str | None
    started_at: str | None
    completed_at: str | None
    negative_cached: bool

    def to_dict(self) -> dict[str, Any]:
        return {
            "evidence_id": self.evidence_id,
            "state": self.state,
            "requirement_id": self.requirement_id,
            "error_code": self.error_code,
            "sanitized_message": self.sanitized_message,
            "attempts": self.attempts,
            "next_attempt_at": self.next_attempt_at,
            "started_at": self.started_at,
            "completed_at": self.completed_at,
            "negative_cached": self.negative_cached,
        }


def schedule_preparation(
    db: Session,
    *,
    evidence: Evidence,
    state: str = PREP_QUEUED,
    reason: str | None = None,
) -> MemorySymbolPreparation:
    """Create or refresh a queued preparation row for the evidence.

    If a terminal preparation already exists, the scheduler does
    not re-queue; the caller must explicitly call
    :func:`requeue_preparation` for retries.
    """
    preparation = (
        db.query(MemorySymbolPreparation)
        .filter(MemorySymbolPreparation.evidence_id == evidence.id)
        .order_by(MemorySymbolPreparation.created_at.desc())
        .first()
    )
    terminal_states = {PREP_READY, PREP_UNSUPPORTED, PREP_CANCELLED}
    if preparation is not None and preparation.state in terminal_states:
        return preparation
    if preparation is None:
        preparation = MemorySymbolPreparation(
            case_id=evidence.case_id,
            evidence_id=evidence.id,
            state=state,
            state_reason=reason,
            attempts=0,
        )
        db.add(preparation)
    else:
        preparation.state = state
        preparation.state_reason = reason
    db.flush()
    return preparation


def requeue_preparation(
    db: Session,
    *,
    evidence: Evidence,
    state: str = PREP_QUEUED,
    reason: str | None = None,
) -> MemorySymbolPreparation:
    """Reset a preparation row's state without enqueueing.

    This is an internal state-reset helper.  It does NOT enqueue
    an RQ job.  Use
    :func:`app.services.memory.preparation_runtime.dispatch_memory_preparation`
    for any user-visible retry that must dispatch a worker task.
    """
    preparation = schedule_preparation(db, evidence=evidence, state=state, reason=reason)
    preparation.attempts = 0
    preparation.error_code = None
    preparation.sanitized_message = None
    preparation.next_attempt_at = None
    db.flush()
    return preparation


def mark_preparation(
    db: Session,
    *,
    evidence: Evidence,
    state: str,
    reason: str | None = None,
    error_code: str | None = None,
    sanitized_message: str | None = None,
    requirement_id: str | None = None,
) -> MemorySymbolPreparation | None:
    """Update the latest preparation row for an evidence."""
    if state not in ALL_PREP_STATES:
        raise ValueError(f"Unknown preparation state: {state!r}")
    preparation = (
        db.query(MemorySymbolPreparation)
        .filter(MemorySymbolPreparation.evidence_id == evidence.id)
        .order_by(MemorySymbolPreparation.created_at.desc())
        .first()
    )
    if preparation is None:
        preparation = MemorySymbolPreparation(
            case_id=evidence.case_id,
            evidence_id=evidence.id,
            state=state,
            state_reason=reason,
            error_code=error_code,
            sanitized_message=sanitized_message,
            requirement_id=requirement_id,
        )
        db.add(preparation)
    else:
        preparation.state = state
        preparation.state_reason = reason or preparation.state_reason
        if error_code is not None:
            preparation.error_code = error_code
        if sanitized_message is not None:
            preparation.sanitized_message = sanitized_message
        if requirement_id is not None:
            preparation.requirement_id = requirement_id
    if state in {PREP_READY, PREP_ACQUISITION_FAILED, PREP_REQUIREMENT_UNKNOWN, PREP_UNSUPPORTED, PREP_CANCELLED, PREP_NEGATIVE_CACHED, PREP_BLOCKED, PREP_BLOCKED_SYMBOLS, PREP_PLATFORM_NOT_IDENTIFIED_STATE, PREP_PLATFORM_NOT_SUPPORTED_STATE}:
        preparation.completed_at = utc_now_naive()
    if state == PREP_PROBING and preparation.started_at is None:
        preparation.started_at = utc_now_naive()
    preparation.attempts = (preparation.attempts or 0) + 1
    db.flush()
    return preparation


def consume_preparation(
    db: Session,
    *,
    evidence_id: str,
) -> PreparationSummary | None:
    preparation = (
        db.query(MemorySymbolPreparation)
        .filter(MemorySymbolPreparation.evidence_id == evidence_id)
        .order_by(MemorySymbolPreparation.created_at.desc())
        .first()
    )
    if preparation is None:
        return None
    negative_cached = (
        db.query(MemorySymbolNegativeCache)
        .filter(
            MemorySymbolNegativeCache.symbol_key
            == _requirement_symbol_key_for(db, preparation.requirement_id)
        )
        .first()
        if preparation.requirement_id
        else None
    )
    return PreparationSummary(
        evidence_id=preparation.evidence_id,
        state=preparation.state,
        requirement_id=preparation.requirement_id,
        error_code=preparation.error_code,
        sanitized_message=preparation.sanitized_message,
        attempts=preparation.attempts or 0,
        next_attempt_at=preparation.next_attempt_at.isoformat() if preparation.next_attempt_at else None,
        started_at=preparation.started_at.isoformat() if preparation.started_at else None,
        completed_at=preparation.completed_at.isoformat() if preparation.completed_at else None,
        negative_cached=bool(negative_cached),
    )


def _requirement_symbol_key_for(db: Session, requirement_id: str | None) -> str:
    if not requirement_id:
        return ""
    requirement = db.get(MemorySymbolRequirement, requirement_id)
    if requirement is None:
        return ""
    return requirement.symbol_key


# -----------------------------------------------------------------------------
# Negative cache
# -----------------------------------------------------------------------------


def record_negative_cache(
    db: Session,
    *,
    symbol_key: str,
    error_code: str,
    sanitized_message: str | None = None,
    ttl_seconds: int | None = None,
) -> MemorySymbolNegativeCache:
    settings = get_settings()
    ttl = int(ttl_seconds or settings.memory_symbol_negative_cache_ttl_seconds)
    record = (
        db.query(MemorySymbolNegativeCache)
        .filter(MemorySymbolNegativeCache.symbol_key == symbol_key)
        .first()
    )
    if record is None:
        record = MemorySymbolNegativeCache(
            symbol_key=symbol_key,
            error_code=error_code,
            sanitized_message=sanitized_message,
            attempts=1,
            expires_at=utc_now_naive() + timedelta(seconds=ttl),
        )
        db.add(record)
    else:
        record.error_code = error_code
        record.sanitized_message = sanitized_message
        record.attempts = (record.attempts or 0) + 1
        record.expires_at = utc_now_naive() + timedelta(seconds=ttl)
    db.flush()
    return record


def negative_cache_active(db: Session, *, symbol_key: str) -> MemorySymbolNegativeCache | None:
    record = (
        db.query(MemorySymbolNegativeCache)
        .filter(MemorySymbolNegativeCache.symbol_key == symbol_key)
        .first()
    )
    if record is None:
        return None
    if record.expires_at and record.expires_at < utc_now_naive():
        return None
    return record


# -----------------------------------------------------------------------------
# Cache match (exact identifier)
# -----------------------------------------------------------------------------


def exact_cache_match_for_requirement(
    db: Session,
    requirement: MemorySymbolRequirement,
) -> MemoryCachedSymbol | None:
    """Return the cached symbol row for the exact normalized
    identifier, or ``None``.  Architecture is part of the match.
    """
    cached = (
        db.query(MemoryCachedSymbol)
        .filter(MemoryCachedSymbol.symbol_key == requirement.symbol_key)
        .filter(MemoryCachedSymbol.cache_classification == "exact")
        .first()
    )
    if cached is None:
        return None
    if cached.architecture.lower() != (requirement.architecture or "").lower():
        return None
    return cached


# -----------------------------------------------------------------------------
# Pending analysis
# -----------------------------------------------------------------------------


def record_pending_analysis(
    db: Session,
    *,
    case_id: str,
    evidence_id: str,
    kind: str,
    profile: str | None = None,
    mode: str = "missing_or_failed",
    requested_profiles: list[str] | None = None,
) -> MemorySymbolPendingAnalysis:
    pending = MemorySymbolPendingAnalysis(
        case_id=case_id,
        evidence_id=evidence_id,
        kind=kind,
        profile=profile,
        mode=mode,
        requested_profiles=requested_profiles or [],
        status="pending",
    )
    db.add(pending)
    db.flush()
    return pending


def consume_pending_for_evidence(
    db: Session,
    *,
    evidence_id: str,
) -> list[MemorySymbolPendingAnalysis]:
    return (
        db.query(MemorySymbolPendingAnalysis)
        .filter(
            MemorySymbolPendingAnalysis.evidence_id == evidence_id,
            MemorySymbolPendingAnalysis.status == "pending",
        )
        .all()
    )


def mark_pending_materialized(
    db: Session,
    pending: MemorySymbolPendingAnalysis,
    *,
    batch_id: str | None = None,
    run_id: str | None = None,
) -> None:
    pending.status = "materialized"
    pending.materialized_batch_id = batch_id
    pending.materialized_run_id = run_id
    db.flush()


def cancel_pending(
    db: Session,
    pending: MemorySymbolPendingAnalysis,
    *,
    reason: str | None = None,
) -> None:
    pending.status = "cancelled"
    pending.sanitized_message = reason
    db.flush()


# -----------------------------------------------------------------------------
# Canonical authorization
# -----------------------------------------------------------------------------


def _load_native_compat(
    db: Session,
    evidence: Evidence,
    requirement_row: MemorySymbolRequirement | None,
) -> tuple[bool, str | None]:
    if requirement_row is None:
        return False, None
    from app.services.memory.native_probe import check_native_compatibility

    native = check_native_compatibility(
        db, evidence_id=evidence.id, requirement_id=requirement_row.id
    )
    if native and native.get("compatible"):
        return True, native.get("reason")
    return False, None


def can_execute_validated_memory_analysis(
    db: Session,
    *,
    evidence_id: str,
) -> tuple[bool, str, str | None]:
    """Canonical authorization for validated memory analysis.

    Returns ``(allowed, readiness_source, blocker)``.  Accepts
    evidence when any supported validated path is ready:

    1. Exact symbols present in the cache.
    2. Volatility native compatibility confirmed.
    3. Successful validated metadata preparation already established.

    The caller may use ``readiness_source`` to tailor the UI message.
    """
    from app.models.evidence import Evidence

    evidence = db.get(Evidence, evidence_id)
    if evidence is None:
        return False, "blocked", "Evidence not found."

    readiness = compute_memory_readiness(db, evidence=evidence)
    if readiness.can_analyze_metadata:
        if readiness.native_compatible:
            return True, "volatility_native_compatible", None
        if readiness.exact_match:
            return True, "exact_cache_hit", None
        return True, "prior_metadata_preparation", None
    if readiness.preparation_state == "blocked_symbols":
        return False, "blocked_symbols", readiness.blocker or readiness.sanitized_message or "Windows symbols are not ready for this evidence."
    return False, "blocked", readiness.blocker or readiness.sanitized_message or "Windows symbols are not ready."


# -----------------------------------------------------------------------------
# Top-level readiness
# -----------------------------------------------------------------------------


@dataclass
class MemoryReadiness:
    """Top-level readiness state for the UI.

    Combines the global cache state, the per-evidence preparation
    state, the link source and the analyst's pending intents.
    """

    evidence_id: str
    ui_state: str
    preparation_state: str
    requirement: dict[str, Any] | None
    cache_status: str  # "hit" | "miss" | "negative" | "unknown"
    exact_match: bool
    pending_request_id: str | None
    blocker: str | None
    sanitized_message: str | None
    can_analyze_metadata: bool
    can_run_all: bool
    progress_label: str
    progress_percent: int
    pending_intent_kind: str | None  # "single_profile" | "run_all" | None
    link_source: str | None
    content_reused_by_hash: bool
    native_compatible: bool = False
    native_compatibility_reason: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "evidence_id": self.evidence_id,
            "ui_state": self.ui_state,
            "preparation_state": self.preparation_state,
            "requirement": self.requirement,
            "cache_status": self.cache_status,
            "exact_match": self.exact_match,
            "native_compatible": self.native_compatible,
            "native_compatibility_reason": self.native_compatibility_reason,
            "pending_request_id": self.pending_request_id,
            "blocker": self.blocker,
            "sanitized_message": self.sanitized_message,
            "can_analyze_metadata": self.can_analyze_metadata,
            "can_run_all": self.can_run_all,
            "progress_label": self.progress_label,
            "progress_percent": self.progress_percent,
            "pending_intent_kind": self.pending_intent_kind,
            "link_source": self.link_source,
            "content_reused_by_hash": self.content_reused_by_hash,
        }


def progress_for_state(state: str) -> tuple[str, int]:
    """Map a preparation state to a progress label + percent.

    Sprint 6: removed the fake ``Queued = 5%`` placeholder.  A
    queued row either has a real task (indeterminate) or has
    failed to dispatch (0).  Percentages are reserved for
    states that have measurable progress (probing, ready, etc.).
    """
    if state == PREP_QUEUED:
        # Indeterminate indicator in the UI; progress is 0
        # (the row has no measurable progress yet).
        return ("Queued", 0)
    if state == PREP_PROBING:
        return ("Identifying platform", 20)
    if state == PREP_IDENTIFIED:
        return ("Requirement identified", 45)
    if state == PREP_CACHE_HIT:
        return ("Symbol cache matched", 90)
    if state == PREP_ACQUISITION_PENDING:
        return ("Awaiting authorization", 55)
    if state == PREP_ACQUIRING:
        return ("Downloading required public symbols", 70)
    if state == PREP_ISF_CREATION:
        return ("Building offline symbol table", 85)
    if state == PREP_READY:
        return ("Ready", 100)
    if state == PREP_DISPATCH_FAILED_STATE:
        return ("Worker dispatch failed — retry", 0)
    if state == PREP_PLATFORM_NOT_IDENTIFIED_STATE:
        return ("Platform not identified", 0)
    if state == PREP_PLATFORM_NOT_SUPPORTED_STATE:
        return ("Platform not supported", 0)
    if state == PREP_BLOCKED:
        return ("Blocked", 0)
    if state == PREP_STALE:
        return ("Stale — re-dispatching", 0)
    if state == PREP_REQUIREMENT_UNKNOWN:
        return ("Identifying Windows kernel symbols", 0)
    if state == PREP_ACQUISITION_FAILED:
        return ("Acquisition failed", 0)
    if state == PREP_UNSUPPORTED:
        return ("Unsupported", 0)
    if state == PREP_NEGATIVE_CACHED:
        return ("Symbol unavailable at the source", 0)
    if state == PREP_CANCELLED:
        return ("Cancelled", 0)
    return (state, 0)


def compute_memory_readiness(
    db: Session,
    *,
    evidence: Evidence,
) -> MemoryReadiness:
    """Build the canonical readiness for the UI.

    The function reads (in order):

    * the per-evidence preparation state (if any)
    * the per-evidence link + linked requirement
    * the content-identity reuse (by SHA + size)
    * the global cache
    * the negative cache
    * the pending intents
    """
    preparation = (
        db.query(MemorySymbolPreparation)
        .filter(MemorySymbolPreparation.evidence_id == evidence.id)
        .order_by(MemorySymbolPreparation.created_at.desc())
        .first()
    )
    link = (
        db.query(MemoryEvidenceSymbolLink)
        .filter(MemoryEvidenceSymbolLink.evidence_id == evidence.id)
        .order_by(MemoryEvidenceSymbolLink.created_at.desc())
        .first()
    )
    requirement_id = (preparation.requirement_id if preparation else None) or (
        link.requirement_id if link else None
    )
    requirement_row = (
        db.get(MemorySymbolRequirement, requirement_id) if requirement_id else None
    )
    if requirement_row is None and preparation is None:
        # Try the content-identity reuse.
        reused = find_requirement_by_content_identity(db, evidence=evidence)
        requirement_row = reused
    if requirement_row is not None:
        symbol_key = requirement_row.symbol_key
    else:
        symbol_key = ""
    cache_status = "unknown"
    exact_match = False
    if requirement_row is not None:
        cached = exact_cache_match_for_requirement(db, requirement_row)
        if cached is not None:
            cache_status = "hit"
            exact_match = True
        else:
            negative = negative_cache_active(db, symbol_key=symbol_key)
            cache_status = "negative" if negative is not None else "miss"
    link_source = link.link_source if link is not None else None
    content_reused_by_hash = link_source == "cache_reuse_by_hash"
    preparation_state = preparation.state if preparation else PREP_QUEUED
    if preparation is None and requirement_row is not None and exact_match:
        # Legacy data: the requirement is recorded and the cache
        # hits, but no preparation row exists yet.  Treat as ready.
        preparation_state = PREP_READY
    elif preparation is None and requirement_row is not None and not exact_match:
        preparation_state = (
            PREP_NEGATIVE_CACHED
            if negative_cache_active(db, symbol_key=symbol_key) is not None
            else PREP_QUEUED
        )
    elif preparation is None and requirement_row is None:
        # No requirement, no preparation.  Try the legacy state
        # machine as a last resort so legacy data still works.
        try:
            from app.services.memory.symbol_state import (
                evidence_symbol_state,
                STATE_CACHED,
            )
            legacy = evidence_symbol_state(
                db, case_id=evidence.case_id, evidence_id=evidence.id,
            )
            if legacy.state == STATE_CACHED:
                preparation_state = PREP_READY
                exact_match = True
                cache_status = "hit"
                if legacy.requirement is not None and requirement_row is None:
                    requirement_row = _legacy_to_requirement(legacy)
        except Exception:  # noqa: BLE001
            pass
    native_compat, native_reason = _load_native_compat(db, evidence, requirement_row)
    ui_state = ui_state_for(preparation_state)
    if preparation_state == PREP_READY or preparation_state in {PREP_CACHE_HIT}:
        can_analyze = True
        can_run_all = True
        blocker: str | None = None
        if native_compat:
            sanitized = (
                "Volatility native compatibility confirmed. "
                "The evidence is ready for validated analysis."
            )
        elif exact_match:
            sanitized = "The exact required Windows symbols are present in the cache."
        else:
            sanitized = "A successful metadata preparation already established readiness for this evidence."
    elif preparation_state in {PREP_PROBING, PREP_QUEUED, PREP_IDENTIFIED, PREP_ACQUISITION_PENDING, PREP_ACQUIRING, PREP_ISF_CREATION}:
        can_analyze = False
        can_run_all = False
        blocker = "Windows symbols are being prepared for this evidence."
        sanitized = blocker
    elif preparation_state == PREP_REQUIREMENT_UNKNOWN:
        can_analyze = False
        can_run_all = False
        blocker = "Windows symbol requirement has not been identified yet."
        sanitized = "Kairon can retry automatic probing; no manual symbol identifier is required."
    elif preparation_state == PREP_NEGATIVE_CACHED:
        can_analyze = False
        can_run_all = False
        blocker = "The required symbol is not available at the configured source."
        sanitized = blocker
    elif preparation_state == PREP_UNSUPPORTED:
        can_analyze = False
        can_run_all = False
        blocker = "This image is not a supported Windows memory image."
        sanitized = blocker
    elif preparation_state == PREP_BLOCKED_SYMBOLS:
        if native_compat:
            can_analyze = True
            can_run_all = True
            blocker = None
            sanitized = (
                "Volatility successfully resolved and validated the Windows "
                "symbols for this evidence."
            )
        else:
            can_analyze = False
            can_run_all = False
            blocker = "Windows symbols are not ready yet."
            sanitized = blocker
    elif preparation_state in {PREP_ACQUISITION_FAILED, PREP_CANCELLED}:
        can_analyze = False
        can_run_all = False
        blocker = "Symbol preparation failed."
        sanitized = blocker
    else:
        can_analyze = False
        can_run_all = False
        blocker = "Windows symbols are not ready yet."
        sanitized = blocker
    pending_intents = consume_pending_for_evidence(db, evidence_id=evidence.id)
    pending_kind = pending_intents[0].kind if pending_intents else None
    progress_label, progress_percent = progress_for_state(preparation_state)
    requirement_dict: dict[str, Any] | None = None
    if requirement_row is not None:
        requirement_dict = {
            "pdb_name": requirement_row.pdb_name,
            "pdb_guid": requirement_row.pdb_guid,
            "pdb_age": int(requirement_row.pdb_age),
            "architecture": requirement_row.architecture,
            "source": requirement_row.source,
            "confidence": requirement_row.confidence,
        }
    return MemoryReadiness(
        evidence_id=evidence.id,
        ui_state=ui_state,
        preparation_state=preparation_state,
        requirement=requirement_dict,
        cache_status=cache_status,
        exact_match=exact_match,
        native_compatible=native_compat,
        native_compatibility_reason=native_reason,
        pending_request_id=None,
        blocker=blocker,
        sanitized_message=sanitized,
        can_analyze_metadata=can_analyze,
        can_run_all=can_run_all,
        progress_label=progress_label,
        progress_percent=progress_percent,
        pending_intent_kind=pending_kind,
        link_source=link_source,
        content_reused_by_hash=content_reused_by_hash,
    )


# -----------------------------------------------------------------------------
# Global reconciliation
# -----------------------------------------------------------------------------


def _legacy_to_requirement(legacy) -> MemorySymbolRequirement | None:
    """Build a transient MemorySymbolRequirement from a legacy
    SymbolReadiness payload (used to short-circuit the catalogue
    when only a legacy state is available).  Returns ``None`` when
    the legacy payload has no requirement.
    """
    if legacy.requirement is None:
        return None
    return MemorySymbolRequirement(
        pdb_name=legacy.requirement.pdb_name,
        pdb_guid=legacy.requirement.pdb_guid,
        pdb_age=int(legacy.requirement.pdb_age),
        architecture=legacy.requirement.architecture,
    )


def reconcile_memory_symbol_readiness(
    db: Session,
    *,
    max_evidences: int = 200,
) -> dict[str, int]:
    """Walk every memory evidence and ensure a preparation row
    exists.  Terminal states (ready, unsupported, cancelled) are
    not re-queued.  Returns a small stats dict for the operator.

    The function is idempotent: it is safe to run on every
    startup and on a periodic schedule.
    """
    settings = get_settings()
    if not bool(getattr(settings, "memory_auto_symbol_probe", True)):
        return {"scanned": 0, "queued": 0, "skipped_terminal": 0, "skipped_ready": 0}
    stats = {"scanned": 0, "queued": 0, "skipped_terminal": 0, "skipped_ready": 0}
    terminal = {PREP_READY, PREP_UNSUPPORTED, PREP_CANCELLED}
    evidences = (
        db.query(Evidence)
        .filter(Evidence.evidence_type == "memory_dump")
        .order_by(Evidence.created_at.desc())
        .limit(max_evidences)
        .all()
    )
    for evidence in evidences:
        stats["scanned"] += 1
        preparation = (
            db.query(MemorySymbolPreparation)
            .filter(MemorySymbolPreparation.evidence_id == evidence.id)
            .order_by(MemorySymbolPreparation.created_at.desc())
            .first()
        )
        if preparation is not None and preparation.state in terminal:
            stats["skipped_terminal"] += 1
            continue
        # If the requirement is already linked + cached, mark ready
        # without re-queueing a probe.
        link = (
            db.query(MemoryEvidenceSymbolLink)
            .filter(MemoryEvidenceSymbolLink.evidence_id == evidence.id)
            .order_by(MemoryEvidenceSymbolLink.created_at.desc())
            .first()
        )
        requirement_id = link.requirement_id if link is not None else None
        requirement_row = (
            db.get(MemorySymbolRequirement, requirement_id) if requirement_id else None
        )
        if requirement_row is None:
            reused = find_requirement_by_content_identity(db, evidence=evidence)
            requirement_row = reused
            if requirement_row is not None and link is not None:
                link.requirement_id = requirement_row.id
                link.link_source = "cache_reuse_by_hash"
        if requirement_row is not None:
            cached = exact_cache_match_for_requirement(db, requirement_row)
            if cached is not None:
                if link is None:
                    link_evidence_to_requirement(
                        db,
                        evidence=evidence,
                        requirement=requirement_row,
                        link_source="cache_reuse_by_hash",
                        state=PREP_READY,
                    )
                else:
                    link.state = PREP_READY
                    link.link_source = link.link_source or "cache_reuse_by_hash"
                if preparation is None:
                    mark_preparation(
                        db,
                        evidence=evidence,
                        state=PREP_READY,
                        reason="cache_reuse_by_hash",
                        requirement_id=requirement_row.id,
                    )
                else:
                    mark_preparation(
                        db,
                        evidence=evidence,
                        state=PREP_READY,
                        reason="cache_reuse_by_hash",
                        requirement_id=requirement_row.id,
                    )
                stats["skipped_ready"] += 1
                continue
        # Otherwise, queue a fresh preparation.  Sprint 6
        # delegates the dispatch to the new dispatcher so the
        # row actually receives a worker task id.
        try:
            from app.services.memory.preparation_runtime import (
                dispatch_memory_preparation,
            )
            dispatch_memory_preparation(db, evidence=evidence)
            stats["queued"] += 1
        except Exception as exc:  # noqa: BLE001
            logger.warning("reconcile: dispatch failed for %s: %s", evidence.id, exc)
            stats["queued"] += 1
    db.commit()
    return stats


# ---------------------------------------------------------------------------
# v1 stabilization: effective state resolution + stale cleanup
# ---------------------------------------------------------------------------


def _latest_metadata_run_for_evidence(
    db: Session,
    *,
    case_id: str,
    evidence_id: str,
) -> dict | None:
    """Return the most recent ``metadata_only`` scan run for the
    evidence, or None if no run exists.

    The shape is the same as the /api/memory/runs/{run_id} response
    so callers can use the same code path.
    """
    from app.models.memory import MemoryScanRun
    run = (
        db.query(MemoryScanRun)
        .filter(
            MemoryScanRun.case_id == case_id,
            MemoryScanRun.evidence_id == evidence_id,
            MemoryScanRun.profile == "metadata_only",
        )
        .order_by(MemoryScanRun.completed_at.desc().nullslast())
        .first()
    )
    if run is None:
        return None
    return {
        "id": run.id,
        "status": run.status,
        "started_at": run.started_at.isoformat() if run.started_at else None,
        "completed_at": run.completed_at.isoformat() if run.completed_at else None,
        "duration_ms": run.duration_ms,
        "plugins_completed": int(run.plugins_completed),
        "plugins_failed": int(run.plugins_failed),
    }


def _task_is_alive(worker_task_id: str | None) -> bool:
    """Probe Redis for an active RQ job.

    Returns False when the worker_task_id is empty, the Redis
    connection is unavailable, or the job is missing / terminal.
    """
    if not worker_task_id:
        return False
    try:
        from redis import Redis
        from rq.job import Job
        from app.core.config import get_settings
        settings = get_settings()
        redis_url = settings.redis_url
        if not redis_url:
            return False
        conn = Redis.from_url(redis_url)
        try:
            job = Job.fetch(worker_task_id, connection=conn)
        except Exception:  # noqa: BLE001
            return False
        if job is None:
            return False
        if job.get_status() in {"finished", "failed", "canceled", "stopped"}:
            return False
        return True
    except Exception:  # noqa: BLE001
        return False


def resolve_effective_memory_preparation_state(
    db: Session,
    *,
    case_id: str,
    evidence_id: str,
) -> dict:
    """Single source of truth for the effective preparation state.

    Returns a dict with:

    * ``persisted_state`` - the state stored in
      ``memory_symbol_preparations.state`` (or ``queued`` if no row)
    * ``effective_state`` - the state the UI should display, derived
      from facts: a successful metadata_only run, an exact cache
      hit, an active RQ task, or a stale timeout
    * ``reconciled``       - True if the persisted state was changed
      to match the effective state during this call
    * ``source_of_truth``  - the fact that pinned the effective
      state (e.g. ``successful_metadata_run``)
    * ``progress``         - 0..100 progress; 0 means unknown
    * ``reconciled_at``    - timestamp of the reconciliation
    * ``preparation_id``   - the preparation row id (or None)
    * ``stale``            - True if the persisted state is stale
    * ``stale_reason``     - the reason for staleness
    * ``task_alive``       - True if the RQ task is still active

    The function does NOT execute Volatility, does NOT download
    symbols and does NOT create a new preparation row.  It only
    rewrites the existing row to match the facts.
    """
    from app.models.evidence import Evidence
    from app.models.memory import MemorySymbolPreparation
    from app.core.config import get_settings
    from app.core.database import utc_now_naive
    settings = get_settings()
    evidence = db.get(Evidence, evidence_id)
    if evidence is None or evidence.case_id != case_id:
        return {
            "persisted_state": None,
            "effective_state": None,
            "reconciled": False,
            "source_of_truth": "evidence_missing",
            "progress": 0,
            "reconciled_at": None,
            "preparation_id": None,
            "stale": False,
            "stale_reason": "evidence_missing",
            "task_alive": False,
        }
    # The newest ACTIVE preparation row.
    prep = (
        db.query(MemorySymbolPreparation)
        .filter(
            MemorySymbolPreparation.evidence_id == evidence_id,
            MemorySymbolPreparation.active == True,  # noqa: E712
        )
        .order_by(MemorySymbolPreparation.created_at.desc())
        .first()
    )
    if prep is None:
        # Fall back to the newest row of any active flag (legacy data).
        prep = (
            db.query(MemorySymbolPreparation)
            .filter(MemorySymbolPreparation.evidence_id == evidence_id)
            .order_by(MemorySymbolPreparation.created_at.desc())
            .first()
        )
    persisted_state = prep.state if prep is not None else PREP_QUEUED
    progress = int(getattr(prep, "progress_percent", 0) or 0) if prep is not None else 0
    task_alive = _task_is_alive(prep.worker_task_id if prep is not None else None)
    metadata_run = _latest_metadata_run_for_evidence(
        db, case_id=case_id, evidence_id=evidence_id,
    )
    metadata_succeeded = (
        metadata_run is not None
        and metadata_run.get("status") == "completed"
        and int(metadata_run.get("plugins_failed", 0)) == 0
        and int(metadata_run.get("plugins_completed", 0)) >= 1
    )
    # The order of resolution (per spec).
    # 1. Evidence is accessible. (Already verified above.)
    # 2. metadata_only completed with windows.info valid?
    # 3. exact symbol cache hit or ISF used by the run?
    # 4. preparation task really active?
    # 5. preparation row persisted.
    new_state: str | None = None
    new_progress: int | None = None
    source_of_truth = None
    if metadata_succeeded:
        # 2+3: a successful metadata run is the strongest signal
        # we have.  The Volatility execution already used the
        # symbol table (or the kernel detector) and returned
        # 200; we can pin the preparation to ready regardless
        # of what the persisted state says.
        new_state = PREP_READY
        new_progress = 100
        source_of_truth = "successful_metadata_run"
    elif persisted_state == PREP_BLOCKED_SYMBOLS:
        # Check if a volatility-native probe has marked this
        # evidence compatible.  The native probe successfully ran
        # stock Volatility with full automagic against the real
        # evidence.
        from app.services.memory.native_probe import check_native_compatibility

        req_id = prep.requirement_id if prep is not None else None
        if req_id:
            native = check_native_compatibility(
                db, evidence_id=evidence_id, requirement_id=req_id,
            )
            if native and native.get("compatible"):
                new_state = PREP_READY
                new_progress = 100
                source_of_truth = "volatility_native_compatible"
    if new_state is not None:
        pass  # fall through to state reconciliation below
    elif task_alive:
        # 4: the RQ worker is still working on this row.  We do
        # NOT touch the persisted state; the worker will.
        return {
            "persisted_state": persisted_state,
            "effective_state": persisted_state,
            "reconciled": False,
            "source_of_truth": "active_task",
            "progress": progress,
            "reconciled_at": None,
            "preparation_id": prep.id if prep is not None else None,
            "stale": False,
            "stale_reason": None,
            "task_alive": True,
            "error_code": prep.error_code if prep is not None else None,
            "sanitized_message": prep.sanitized_message if prep is not None else None,
        }
    elif (
        prep is not None
        and persisted_state in {PREP_QUEUED, PREP_PROBING, PREP_ACQUIRING, PREP_CONVERTING, PREP_VERIFYING}
    ):
        # 5: no active task and no successful metadata.  Check if
        # the row is stale (no recent heartbeat and the persisted
        # state has been queued too long).
        last_heartbeat = (
            prep.last_heartbeat_at
            or prep.updated_at
            or prep.created_at
        )
        age_seconds = (utc_now_naive() - last_heartbeat).total_seconds()
        if age_seconds > settings.memory_preparation_stale_seconds:
            new_state = PREP_STALE
            new_progress = 0
            source_of_truth = "stale_timeout"
        else:
            # Within the timeout window: trust the persisted state.
            return {
                "persisted_state": persisted_state,
                "effective_state": persisted_state,
                "reconciled": False,
                "source_of_truth": "persisted_state_in_window",
                "progress": progress,
                "reconciled_at": None,
                "preparation_id": prep.id if prep is not None else None,
                "stale": False,
                "stale_reason": None,
                "task_alive": False,
                "error_code": prep.error_code if prep is not None else None,
                "sanitized_message": prep.sanitized_message if prep is not None else None,
            }
    elif prep is None:
        # No row at all.  Try the cache hit fallback used by
        # compute_memory_readiness: if a requirement exists and
        # the cache matches, the preparation is implicitly ready.
        reused = find_requirement_by_content_identity(db, evidence=evidence)
        if reused is not None:
            from app.services.memory.symbol_preparation import (
                exact_cache_match_for_requirement,
            )
            if exact_cache_match_for_requirement(db, reused) is not None:
                new_state = PREP_READY
                new_progress = 100
                source_of_truth = "exact_cache_match_no_row"
    # Persist the correction.
    reconciled = False
    reconciled_at = None
    stale_reason = None
    if new_state is not None and prep is not None and new_state != persisted_state:
        prep.state = new_state
        if new_progress is not None:
            prep.progress_percent = int(new_progress)
        if source_of_truth:
            prep.source_of_truth = source_of_truth
        if new_state == PREP_READY:
            prep.completed_at = utc_now_naive()
        if new_state == PREP_STALE:
            stale_reason = "no_task_no_metadata"
            prep.failure_code = "MEMORY_PREPARATION_STALE"
        prep.reconciled_at = utc_now_naive()
        db.commit()
        reconciled = True
        reconciled_at = prep.reconciled_at.isoformat()
    elif new_state is not None and prep is None and new_state == PREP_READY:
        # Synthesize a preparation row so the UI sees one active row.
        # This is the "no row but cache hit" branch.
        prep = MemorySymbolPreparation(
            case_id=case_id,
            evidence_id=evidence_id,
            state=PREP_READY,
            state_reason="reconcile_no_row",
            progress_percent=100,
            completed_at=utc_now_naive(),
            source_of_truth=source_of_truth or "exact_cache_match_no_row",
            reconciled_at=utc_now_naive(),
            active=True,
            attempts=0,
            metadata_json={},
        )
        db.add(prep)
        db.commit()
        reconciled = True
        reconciled_at = prep.reconciled_at.isoformat()
    effective_state = new_state if new_state is not None else persisted_state
    final_progress = new_progress if new_progress is not None else progress
    return {
        "persisted_state": persisted_state,
        "effective_state": effective_state,
        "reconciled": reconciled,
        "source_of_truth": source_of_truth or "persisted_state",
        "progress": final_progress,
        "reconciled_at": reconciled_at,
        "preparation_id": prep.id if prep is not None else None,
        "stale": effective_state == PREP_STALE,
        "stale_reason": stale_reason,
        "task_alive": task_alive,
        "error_code": prep.error_code if prep is not None else None,
        "sanitized_message": prep.sanitized_message if prep is not None else None,
    }


def reconcile_memory_preparation_states(
    db: Session,
    *,
    max_evidences: int = 200,
) -> dict:
    """Idempotent reconciliation pass.

    For every memory evidence, compute the effective state via
    :func:`resolve_effective_memory_preparation_state` and
    persist any correction.  Terminal rows (ready, cancelled,
    failed, unsupported, requirement_unknown, negative_cached)
    are NOT re-queued.

    The pass also audits duplicate preparation rows: if more
    than one ``active=True`` row exists for a single evidence,
    the older rows are deactivated (``active=False``).  Historical
    rows are kept for audit.

    Returns a stats dict:

    * ``scanned``         - number of memory evidences visited
    * ``reconciled``      - rows where the persisted state changed
    * ``promoted_ready``  - rows promoted to ready from a queued state
    * ``marked_stale``    - rows marked stale
    * ``deactivated``     - duplicate active rows deactivated
    * ``already_ready``   - rows that were already ready
    """
    from app.models.case import Case
    from app.models.evidence import Evidence, EvidenceType
    from app.models.memory import MemorySymbolPreparation
    from app.core.database import utc_now_naive
    stats = {
        "scanned": 0,
        "reconciled": 0,
        "promoted_ready": 0,
        "marked_stale": 0,
        "deactivated": 0,
        "already_ready": 0,
    }
    terminal_states = {
        PREP_READY,
        PREP_CANCELLED,
        PREP_FAILED,
        PREP_UNSUPPORTED,
        PREP_REQUIREMENT_UNKNOWN,
        PREP_NEGATIVE_CACHED,
        PREP_STALE,
    }
    evidences = (
        db.query(Evidence)
        .filter(Evidence.evidence_type == EvidenceType.memory_dump.value)
        .order_by(Evidence.created_at.desc())
        .limit(max_evidences)
        .all()
    )
    for evidence in evidences:
        stats["scanned"] += 1
        # Deactivate duplicate active rows: keep the newest, mark
        # the rest as inactive (they become historical).
        active_rows = (
            db.query(MemorySymbolPreparation)
            .filter(
                MemorySymbolPreparation.evidence_id == evidence.id,
                MemorySymbolPreparation.active == True,  # noqa: E712
            )
            .order_by(MemorySymbolPreparation.created_at.desc())
            .all()
        )
        if len(active_rows) > 1:
            for older in active_rows[1:]:
                older.active = False
                stats["deactivated"] += 1
        # If there are multiple ACTIVE rows even after deactivation
        # (e.g. because they were created before the partial unique
        # index was applied), keep only the newest.
        active_rows = [r for r in active_rows if r.active]
        if len(active_rows) > 1:
            for older in active_rows[1:]:
                older.active = False
                stats["deactivated"] += 1
        # Run the resolution.
        result = resolve_effective_memory_preparation_state(
            db, case_id=evidence.case_id, evidence_id=evidence.id,
        )
        if not result["reconciled"]:
            if result["effective_state"] == PREP_READY:
                stats["already_ready"] += 1
            continue
        stats["reconciled"] += 1
        if result["effective_state"] == PREP_READY:
            stats["promoted_ready"] += 1
        elif result["effective_state"] == PREP_STALE:
            stats["marked_stale"] += 1
    db.commit()
    return stats


__all__ = [
    "ALL_PREP_STATES",
    "MemoryReadiness",
    "PreparationSummary",
    "PREP_ACQUIRING",
    "PREP_ACQUISITION_FAILED",
    "PREP_ACQUISITION_PENDING",
    "PREP_CACHE_HIT",
    "PREP_CANCELLED",
    "PREP_CONVERTING",
    "PREP_FAILED",
    "PREP_IDENTIFIED",
    "PREP_ISF_CREATION",
    "PREP_NEGATIVE_CACHED",
    "PREP_PENDING",
    "PREP_PROBING",
    "PREP_QUEUED",
    "PREP_READY",
    "PREP_REQUIREMENT_UNKNOWN",
    "PREP_STALE",
    "PREP_UNSUPPORTED",
    "PREP_VERIFYING",
    "UI_STATE_BLOCKED",
    "UI_STATE_FAILED",
    "UI_STATE_PREPARING",
    "UI_STATE_READY",
    "compute_memory_readiness",
    "consume_preparation",
    "content_identity_key",
    "exact_cache_match_for_requirement",
    "find_requirement_by_content_identity",
    "link_evidence_to_requirement",
    "mark_pending_materialized",
    "mark_preparation",
    "negative_cache_active",
    "normalize_sha256",
    "progress_for_state",
    "reconcile_memory_preparation_states",
    "reconcile_memory_symbol_readiness",
    "record_negative_cache",
    "record_pending_analysis",
    "register_evidence_content_identity",
    "cancel_pending",
    "consume_pending_for_evidence",
    "requeue_preparation",
    "resolve_effective_memory_preparation_state",
    "schedule_preparation",
    "ui_state_for",
]
