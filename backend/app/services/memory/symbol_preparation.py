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
PREP_QUEUED = "queued"
PREP_PROBING = "probing"
PREP_IDENTIFIED = "identified"
PREP_CACHE_HIT = "cache_hit"
PREP_ACQUISITION_PENDING = "acquisition_pending"
PREP_ACQUIRING = "acquiring"
PREP_ISF_CREATION = "isf_creation"
PREP_READY = "ready"
PREP_REQUIREMENT_UNKNOWN = "requirement_unknown"
PREP_ACQUISITION_FAILED = "acquisition_failed"
PREP_UNSUPPORTED = "unsupported"
PREP_NEGATIVE_CACHED = "negative_cached"
PREP_CANCELLED = "cancelled"

ALL_PREP_STATES = frozenset(
    {
        PREP_QUEUED,
        PREP_PROBING,
        PREP_IDENTIFIED,
        PREP_CACHE_HIT,
        PREP_ACQUISITION_PENDING,
        PREP_ACQUIRING,
        PREP_ISF_CREATION,
        PREP_READY,
        PREP_REQUIREMENT_UNKNOWN,
        PREP_ACQUISITION_FAILED,
        PREP_UNSUPPORTED,
        PREP_NEGATIVE_CACHED,
        PREP_CANCELLED,
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
    if prep_state in {PREP_CANCELLED, PREP_REQUIREMENT_UNKNOWN, PREP_ACQUISITION_FAILED, PREP_UNSUPPORTED, PREP_NEGATIVE_CACHED}:
        return UI_STATE_BLOCKED if prep_state in {PREP_REQUIREMENT_UNKNOWN, PREP_NEGATIVE_CACHED} else UI_STATE_FAILED
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
    if state in {PREP_READY, PREP_ACQUISITION_FAILED, PREP_REQUIREMENT_UNKNOWN, PREP_UNSUPPORTED, PREP_CANCELLED, PREP_NEGATIVE_CACHED}:
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

    def to_dict(self) -> dict[str, Any]:
        return {
            "evidence_id": self.evidence_id,
            "ui_state": self.ui_state,
            "preparation_state": self.preparation_state,
            "requirement": self.requirement,
            "cache_status": self.cache_status,
            "exact_match": self.exact_match,
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
    """Map a preparation state to a progress label + percent."""
    if state == PREP_QUEUED:
        return ("Queued", 5)
    if state == PREP_PROBING:
        return ("Identifying Windows kernel symbols", 20)
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
    if state == PREP_REQUIREMENT_UNKNOWN:
        return ("Requirement not identified", 0)
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
    ui_state = ui_state_for(preparation_state)
    if preparation_state == PREP_READY:
        can_analyze = True
        can_run_all = True
        blocker: str | None = None
        sanitized = "The exact required Windows symbols are present in the cache."
    elif preparation_state in {PREP_CACHE_HIT}:
        can_analyze = True
        can_run_all = True
        blocker = None
        sanitized = "The exact required Windows symbols are present in the cache."
    elif preparation_state in {PREP_PROBING, PREP_QUEUED, PREP_IDENTIFIED, PREP_ACQUISITION_PENDING, PREP_ACQUIRING, PREP_ISF_CREATION}:
        can_analyze = False
        can_run_all = False
        blocker = "Windows symbols are being prepared for this evidence."
        sanitized = blocker
    elif preparation_state == PREP_REQUIREMENT_UNKNOWN:
        can_analyze = False
        can_run_all = False
        blocker = "Windows symbol requirement could not be identified."
        sanitized = blocker
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
        # Otherwise, queue a fresh preparation.
        schedule_preparation(db, evidence=evidence, state=PREP_QUEUED, reason="reconcile")
        stats["queued"] += 1
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
    "PREP_IDENTIFIED",
    "PREP_ISF_CREATION",
    "PREP_NEGATIVE_CACHED",
    "PREP_PROBING",
    "PREP_QUEUED",
    "PREP_READY",
    "PREP_REQUIREMENT_UNKNOWN",
    "PREP_UNSUPPORTED",
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
    "reconcile_memory_symbol_readiness",
    "record_negative_cache",
    "record_pending_analysis",
    "register_evidence_content_identity",
    "cancel_pending",
    "consume_pending_for_evidence",
    "requeue_preparation",
    "schedule_preparation",
    "ui_state_for",
]
