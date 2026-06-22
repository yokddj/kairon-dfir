"""Per-evidence Windows symbol state.

Each memory evidence has its own symbol requirement (PDB name, GUID,
age, architecture) which is distinct from other evidences: a Windows 11
symbol does not satisfy a Windows XP evidence. The state machine in
this module is the single source of truth for the UI and the
run-all preflight.

States
------

* ``unknown``               - nothing is known yet (initial state)
* ``probing``               - a probe is in progress
* ``cached``                - the exact required symbol is in the cache
* ``missing``               - the exact symbol is not in the cache
* ``acquisition_required``  - operator must trigger an acquisition
* ``acquisition_pending``   - an acquisition is queued / in progress
* ``acquiring``             - download / validation in progress
* ``acquired``              - the symbol was just acquired for this evidence
* ``incompatible``          - the image is not a supported Windows memory
* ``unsupported``           - the symbol source does not provide the
                              required PDB
* ``failed``                - the last acquisition or probe failed
"""
from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.models.memory import (
    MemoryCachedSymbol,
    MemorySymbolRequirement,
)


# Canonical status strings.  These are the only values the UI should
# ever see; any other value is treated as ``unknown``.
STATE_UNKNOWN = "unknown"
STATE_PROBING = "probing"
STATE_CACHED = "cached"
STATE_MISSING = "missing"
STATE_ACQUISITION_REQUIRED = "acquisition_required"
STATE_ACQUISITION_PENDING = "acquisition_pending"
STATE_ACQUIRING = "acquiring"
STATE_ACQUIRED = "acquired"
STATE_INCOMPATIBLE = "incompatible"
STATE_UNSUPPORTED = "unsupported"
STATE_FAILED = "failed"

ALL_STATES = frozenset({
    STATE_UNKNOWN,
    STATE_PROBING,
    STATE_CACHED,
    STATE_MISSING,
    STATE_ACQUISITION_REQUIRED,
    STATE_ACQUISITION_PENDING,
    STATE_ACQUIRING,
    STATE_ACQUIRED,
    STATE_INCOMPATIBLE,
    STATE_UNSUPPORTED,
    STATE_FAILED,
})


# Error codes that the UI / API consume.  These are returned alongside
# the state so the analyst can tell *why* a state was reached.
EC_SYMBOLS_REQUIRED = "MEMORY_SYMBOLS_REQUIRED"
EC_SYMBOL_REQUIREMENT_UNKNOWN = "MEMORY_SYMBOL_REQUIREMENT_UNKNOWN"
EC_SYMBOL_ACQUISITION_PENDING = "MEMORY_SYMBOL_ACQUISITION_PENDING"
EC_SYMBOL_ACQUISITION_FAILED = "MEMORY_SYMBOL_ACQUISITION_FAILED"
EC_SYMBOL_CACHE_MISMATCH = "MEMORY_SYMBOL_CACHE_MISMATCH"
EC_LAYER_CONSTRUCTION_FAILED = "MEMORY_LAYER_CONSTRUCTION_FAILED"
EC_OS_UNSUPPORTED = "MEMORY_OS_UNSUPPORTED"


@dataclass
class SymbolRequirement:
    """Exact symbol identity required for an evidence."""

    pdb_name: str
    pdb_guid: str
    pdb_age: int
    architecture: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "pdb_name": self.pdb_name,
            "pdb_guid": self.pdb_guid,
            "pdb_age": int(self.pdb_age),
            "architecture": self.architecture,
        }

    @property
    def identifier(self) -> str:
        """Canonical identifier used to match the cache.

        Mirrors ``SymbolIdentity.key`` exactly: ``name/guid-age``.
        The architecture is recorded separately and used as a
        second-line check in the UI but it is **not** part of the
        cache key (the existing schema stores
        ``MemoryCachedSymbol.symbol_key`` without the architecture
        suffix).
        """
        return f"{self.pdb_name.lower()}/{self.pdb_guid.upper()}-{int(self.pdb_age)}"

    @classmethod
    def from_dict(cls, payload: dict[str, Any]) -> "SymbolRequirement":
        return cls(
            pdb_name=str(payload.get("pdb_name") or "").strip(),
            pdb_guid=str(payload.get("pdb_guid") or "").strip().upper(),
            pdb_age=int(payload.get("pdb_age") or 0),
            architecture=str(payload.get("architecture") or "x64").strip().lower(),
        )

    def is_valid(self) -> bool:
        """Validate the identifier; never returns True for an unparseable payload."""
        if not re.fullmatch(r"[A-Za-z0-9_.-]{1,120}\.pdb", self.pdb_name, re.IGNORECASE):
            return False
        if not re.fullmatch(r"[0-9A-F]{32}", self.pdb_guid):
            return False
        if not 0 <= self.pdb_age <= 0xFFFFFFFF:
            return False
        return self.architecture in {"x64", "x86", "arm64"}


@dataclass
class CacheMatch:
    """Result of comparing a requirement against the cache."""

    cache_status: str  # "hit" or "miss"
    exact_match: bool
    required_identifier: str | None
    cached_identifiers: list[str] = field(default_factory=list)
    matched_pdb: str | None = None
    matched_guid: str | None = None
    matched_age: int | None = None
    matched_architecture: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "cache_status": self.cache_status,
            "exact_match": self.exact_match,
            "required_identifier": self.required_identifier,
            "cached_identifiers": list(self.cached_identifiers),
            "matched": {
                "pdb_name": self.matched_pdb,
                "pdb_guid": self.matched_guid,
                "pdb_age": self.matched_age,
                "architecture": self.matched_architecture,
            }
            if self.exact_match
            else None,
        }


@dataclass
class SymbolReadiness:
    """Structured per-evidence symbol readiness for the UI."""

    evidence_id: str
    state: str
    requirement: SymbolRequirement | None
    cache: CacheMatch | None
    last_probe: str | None = None  # ISO8601
    last_acquisition: str | None = None  # ISO8601
    can_analyze_metadata: bool = False
    can_run_all: bool = False
    blocker: str | None = None
    error_code: str | None = None
    sanitized_message: str | None = None
    acquisition_supported: bool = False
    pending_request_id: str | None = None
    source: str | None = None
    confidence: str | None = None
    reconstructed_at: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "evidence_id": self.evidence_id,
            "state": self.state,
            "requirement": self.requirement.to_dict() if self.requirement else None,
            "cache": self.cache.to_dict() if self.cache else None,
            "last_probe": self.last_probe,
            "last_acquisition": self.last_acquisition,
            "can_analyze_metadata": self.can_analyze_metadata,
            "can_run_all": self.can_run_all,
            "blocker": self.blocker,
            "error_code": self.error_code,
            "sanitized_message": self.sanitized_message,
            "acquisition_supported": self.acquisition_supported,
            "pending_request_id": self.pending_request_id,
            "source": self.source,
            "confidence": self.confidence,
            "reconstructed_at": self.reconstructed_at,
        }


def _serialize_requirement(requirement: MemorySymbolRequirement | None) -> SymbolRequirement | None:
    if requirement is None:
        return None
    return SymbolRequirement(
        pdb_name=requirement.pdb_name,
        pdb_guid=requirement.pdb_guid,
        pdb_age=int(requirement.pdb_age),
        architecture=requirement.architecture,
    )


def _exact_cache_match(
    db: Session,
    requirement: SymbolRequirement,
) -> CacheMatch:
    """Return a CacheMatch that compares the requirement against the
    cache **by exact identifier** (PDB name, GUID, age, architecture).

    A Windows 11 cached symbol does NOT match a Windows XP evidence.
    The function never returns ``exact_match=True`` for a partial
    match, and the ``cached_identifiers`` list always includes the
    full list of cached identifiers so the UI can show them.
    """
    cached_rows = db.query(MemoryCachedSymbol).all()
    cached_identifiers = sorted({row.symbol_key for row in cached_rows})
    if not cached_rows:
        return CacheMatch(
            cache_status="miss",
            exact_match=False,
            required_identifier=requirement.identifier,
            cached_identifiers=[],
        )
    required = requirement.identifier
    for row in cached_rows:
        if row.symbol_key == required and row.architecture.lower() == requirement.architecture.lower():
            return CacheMatch(
                cache_status="hit",
                exact_match=True,
                required_identifier=required,
                cached_identifiers=cached_identifiers,
                matched_pdb=row.pdb_name,
                matched_guid=row.pdb_guid,
                matched_age=int(row.pdb_age),
                matched_architecture=row.architecture,
            )
    return CacheMatch(
        cache_status="miss",
        exact_match=False,
        required_identifier=required,
        cached_identifiers=cached_identifiers,
    )


def latest_requirement(db: Session, *, case_id: str, evidence_id: str) -> MemorySymbolRequirement | None:
    return (
        db.query(MemorySymbolRequirement)
        .filter(
            MemorySymbolRequirement.case_id == case_id,
            MemorySymbolRequirement.evidence_id == evidence_id,
        )
        .order_by(MemorySymbolRequirement.created_at.desc())
        .first()
    )


def evidence_symbol_state(
    db: Session,
    *,
    case_id: str,
    evidence_id: str,
    acquisition_gate_available: bool = False,
    pending_request_status: str | None = None,
) -> SymbolReadiness:
    """Build the canonical symbol-readiness object for an evidence.

    The state machine reads from ``MemorySymbolRequirement`` (the
    recorded per-evidence requirement, optionally reconstructed
    from history) and ``MemoryCachedSymbol`` (the cache).  The
    acquisition gate is passed in by the caller so this function
    does not import the symbol-fetcher service (which would pull
    in Redis / RQ in unit tests).

    The function never executes Volatility and never downloads
    symbols; when no persisted requirement is found and no
    historical data can reconstruct one, the state is
    ``unknown`` and the UI shows "Probe symbol requirements".
    """
    from app.services.memory.symbol_resolver import (
        ReconstructedRequirement,
        cache_match_status as resolver_cache_status,
        reconstruct_requirement,
        symbol_identifier,
        normalize_age,
        normalize_architecture,
        normalize_guid,
        normalize_pdb_name,
        SOURCE_HISTORICAL_PLUGIN,
        SOURCE_HISTORICAL_PROCESS,
        SOURCE_HISTORICAL_RUN,
        SOURCE_HISTORICAL_SYSTEM_INFO,
        SOURCE_PROBE,
    )

    requirement_row = latest_requirement(db, case_id=case_id, evidence_id=evidence_id)
    requirement: SymbolRequirement | None = _serialize_requirement(requirement_row)
    source: str | None = None
    confidence: str | None = None
    reconstructed_at: str | None = None
    if requirement is not None:
        # Prefer the persisted source field; fall back to "probe"
        # for legacy rows that pre-date the field.
        source = getattr(requirement_row, "source", None) or SOURCE_PROBE
        confidence = getattr(requirement_row, "confidence", None) or "high"
        if getattr(requirement_row, "reconstructed_at", None) is not None:
            reconstructed_at = requirement_row.reconstructed_at.isoformat()
    if requirement is None:
        # Try to reconstruct from history.  This is a read-only
        # operation: no Volatility, no downloads, no DB writes.
        reconstructed = reconstruct_requirement(
            db, case_id=case_id, evidence_id=evidence_id
        )
        if reconstructed is not None and reconstructed.is_valid():
            requirement = SymbolRequirement(
                pdb_name=reconstructed.pdb_name,
                pdb_guid=reconstructed.pdb_guid,
                pdb_age=int(reconstructed.pdb_age),
                architecture=reconstructed.architecture,
            )
            source = reconstructed.source
            confidence = reconstructed.confidence
            from app.core.database import utc_now_naive
            reconstructed_at = utc_now_naive().isoformat()
    cache: CacheMatch | None = None
    if requirement is not None and requirement.is_valid():
        cache = _exact_cache_match(db, requirement)
    elif requirement is not None:
        # The recorded requirement is malformed; treat as unknown.
        requirement = None
    state = STATE_UNKNOWN
    blocker: str | None = None
    error_code: str | None = None
    sanitized_message: str | None = "Windows symbol requirement for this evidence has not been recorded."
    can_analyze_metadata = False
    can_run_all = False
    if requirement is None:
        state = STATE_UNKNOWN
        blocker = "Windows symbol requirement for this evidence has not been recorded. Run a probe to identify the requirement."
        sanitized_message = blocker
        error_code = EC_SYMBOL_REQUIREMENT_UNKNOWN
    elif cache is not None and cache.exact_match:
        state = STATE_CACHED
        sanitized_message = "The exact required Windows symbols are present in the cache."
        can_analyze_metadata = True
        can_run_all = True
    else:
        # We have a requirement but no exact cache hit.
        error_code = EC_SYMBOLS_REQUIRED
        blocker = "Windows symbols required for this evidence are not cached."
        sanitized_message = blocker
        if pending_request_status in {"queued", "resolving", "connecting", "downloading", "validating_pdb", "generating_isf", "validating_isf", "caching"}:
            state = STATE_ACQUIRING
        elif pending_request_status in {"approved"}:
            state = STATE_ACQUISITION_PENDING
        elif pending_request_status in {"awaiting_operator_approval", "awaiting_network_isolation"}:
            state = STATE_ACQUISITION_REQUIRED
        else:
            state = STATE_MISSING
    acquisition_supported = bool(acquisition_gate_available and requirement is not None and cache is not None and not cache.exact_match)
    return SymbolReadiness(
        evidence_id=evidence_id,
        state=state,
        requirement=requirement,
        cache=cache,
        last_probe=requirement_row.created_at.isoformat() if requirement_row else None,
        last_acquisition=None,
        can_analyze_metadata=can_analyze_metadata,
        can_run_all=can_run_all,
        blocker=blocker,
        error_code=error_code,
        sanitized_message=sanitized_message,
        acquisition_supported=acquisition_supported,
        pending_request_id=None,
        source=source,
        confidence=confidence,
        reconstructed_at=reconstructed_at,
    )


# Re-exports for convenience.
# Gate types for the catalogue and UI.  A profile is one of:
# * "available"                - plugin and symbols are both OK
# * "blocked_symbol_probe_required" - plugin OK, requirement unknown
# * "blocked_symbols_missing"  - requirement known, exact cache miss
# * "blocked_acquisition_pending" - acquisition in progress
# * "unavailable"              - plugin absent, OS/arch unsupported,
#                                 import error, runtime incompatible
GATE_TYPE_AVAILABLE = "available"
GATE_TYPE_BLOCKED_SYMBOL_PROBE = "blocked_symbol_probe_required"
GATE_TYPE_BLOCKED_SYMBOLS_MISSING = "blocked_symbols_missing"
GATE_TYPE_BLOCKED_ACQUISITION_PENDING = "blocked_acquisition_pending"
GATE_TYPE_UNAVAILABLE = "unavailable"


def gate_type_from_state(state: str) -> str:
    """Map a ``SymbolReadiness.state`` to a catalogue ``gate_type``."""
    if state == STATE_CACHED or state == STATE_ACQUIRED:
        return GATE_TYPE_AVAILABLE
    if state == STATE_PROBING:
        return GATE_TYPE_BLOCKED_SYMBOL_PROBE
    if state == STATE_ACQUIRING:
        return GATE_TYPE_BLOCKED_ACQUISITION_PENDING
    if state == STATE_ACQUISITION_PENDING or state == STATE_ACQUISITION_REQUIRED:
        return GATE_TYPE_BLOCKED_ACQUISITION_PENDING
    if state == STATE_MISSING:
        return GATE_TYPE_BLOCKED_SYMBOLS_MISSING
    if state == STATE_UNKNOWN:
        return GATE_TYPE_BLOCKED_SYMBOL_PROBE
    # failed, incompatible, unsupported
    return GATE_TYPE_UNAVAILABLE


__all__ = [
    "ALL_STATES",
    "CacheMatch",
    "EC_LAYER_CONSTRUCTION_FAILED",
    "EC_OS_UNSUPPORTED",
    "EC_SYMBOLS_REQUIRED",
    "EC_SYMBOL_ACQUISITION_FAILED",
    "EC_SYMBOL_ACQUISITION_PENDING",
    "EC_SYMBOL_CACHE_MISMATCH",
    "EC_SYMBOL_REQUIREMENT_UNKNOWN",
    "GATE_TYPE_AVAILABLE",
    "GATE_TYPE_BLOCKED_ACQUISITION_PENDING",
    "GATE_TYPE_BLOCKED_SYMBOLS_MISSING",
    "GATE_TYPE_BLOCKED_SYMBOL_PROBE",
    "GATE_TYPE_UNAVAILABLE",
    "STATE_ACQUIRED",
    "STATE_ACQUIRING",
    "STATE_ACQUISITION_PENDING",
    "STATE_ACQUISITION_REQUIRED",
    "STATE_CACHED",
    "STATE_FAILED",
    "STATE_INCOMPATIBLE",
    "STATE_MISSING",
    "STATE_PROBING",
    "STATE_UNKNOWN",
    "STATE_UNSUPPORTED",
    "SymbolReadiness",
    "SymbolRequirement",
    "evidence_symbol_state",
    "gate_type_from_state",
    "latest_requirement",
]
