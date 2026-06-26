"""Trust boundary for the experimental mismatched-symbol analysis mode.

This module is the single source of truth for the trust boundary
between validated forensic analysis and experimental, untrusted
mismatched-symbol analysis.  The boundary is enforced in two
ways:

1. The configuration flag
   ``memory_symbol_experimental_mismatch_enabled`` gates the
   entire experimental feature.  When ``False`` the API returns
   404 and the CLI refuses to create candidates.  The default is
   ``False``.

2. Server-side trust fields on every ``MemoryScanRun`` /
   ``MemoryPluginRun`` row.  Normal artifact and timeline views
   filter on ``trust_level = "validated"``; experimental views
   filter on ``trust_level = "untrusted"``.  A client cannot
   remove the filter without server-side cooperation because the
   filter is applied at the database / OpenSearch query level.

The module also exposes a small, well-named set of constants that
the routes, services, and worker code all import.  Tests assert
on these constants.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from sqlalchemy.orm import Session

from app.core.config import get_settings
from app.models.memory import (
    EXPERIMENTAL_ACK_WARNING_VERSION,
    EXPERIMENTAL_ANALYSIS_MODES,
    EXPERIMENTAL_CANARY_STATUSES,
    EXPERIMENTAL_RUN_STATUSES,
    EXPERIMENTAL_SYMBOL_MATCH_TYPES,
    EXPERIMENTAL_TRUST_LEVELS,
    MemoryCachedSymbol,
    MemoryExperimentalRun,
    MemoryExperimentalSymbolCandidate,
    MemoryPluginRun,
    MemoryScanRun,
    MemorySymbolRequirement,
)


ANALYSIS_MODE_VALIDATED = "validated"
ANALYSIS_MODE_EXPERIMENTAL = "experimental"

TRUST_LEVEL_VALIDATED = "validated"
TRUST_LEVEL_UNTRUSTED = "untrusted"

SYMBOL_MATCH_TYPE_EXACT = "exact"
SYMBOL_MATCH_TYPE_GUID_ONLY_AGE_MISMATCH = "guid_only_age_mismatch"

CACHE_CLASSIFICATION_EXACT = "exact"
CACHE_CLASSIFICATION_EXPERIMENTAL_CANDIDATE = "experimental_candidate"

RUN_STATUS_CANDIDATE_UNAVAILABLE = "candidate_unavailable"
RUN_STATUS_ACKNOWLEDGEMENT_REQUIRED = "acknowledgement_required"
RUN_STATUS_CANARY_QUEUED = "canary_queued"
RUN_STATUS_CANARY_RUNNING = "canary_running"
RUN_STATUS_CANARY_PASSED = "canary_passed"
RUN_STATUS_CANARY_DEGRADED = "canary_degraded"
RUN_STATUS_CANARY_FAILED = "canary_failed"
RUN_STATUS_CANARY_INCONCLUSIVE = "canary_inconclusive"
RUN_STATUS_FULL_RUN_QUEUED = "full_run_queued"
RUN_STATUS_FULL_RUN_RUNNING = "full_run_running"
RUN_STATUS_COMPLETED_UNTRUSTED = "completed_untrusted"
RUN_STATUS_PARTIAL_UNTRUSTED = "partial_untrusted"
RUN_STATUS_FAILED_UNTRUSTED = "failed_untrusted"
RUN_STATUS_CANCELLED = "cancelled"
RUN_STATUS_DELETED = "deleted"

CANARY_STATUS_PENDING = "pending"
CANARY_STATUS_RUNNING = "running"
CANARY_STATUS_PASSED = "passed"
CANARY_STATUS_DEGRADED = "degraded"
CANARY_STATUS_FAILED = "failed"
CANARY_STATUS_INCONCLUSIVE = "inconclusive"
CANARY_STATUS_SKIPPED = "skipped"

# Acknowledgement contract.  The frontend must send these fields
# verbatim and the server validates them.
ACK_REQUIRED_FIELDS = frozenset(
    {
        "actor",
        "acknowledged_at",
        "warning_version",
        "required_identity",
        "observed_identity",
        "warning_text",
        "checkbox_confirmed",
    }
)
ACK_CHECKBOX_CONFIRMED_TEXT = (
    "I understand this is experimental and not validated forensic evidence."
)


@dataclass(frozen=True)
class ExperimentalTrustState:
    """Read-only view of the trust state for a given evidence/run.

    The endpoint that returns the experimental state uses this
    dataclass to keep the surface small and stable.
    """

    enabled: bool
    has_active_candidate: bool
    has_active_run: bool
    run_id: str | None
    run_status: str | None
    canary_status: str | None
    last_completed_at: str | None

    def to_dict(self) -> dict[str, Any]:
        return {
            "enabled": self.enabled,
            "has_active_candidate": self.has_active_candidate,
            "has_active_run": self.has_active_run,
            "run_id": self.run_id,
            "run_status": self.run_status,
            "canary_status": self.canary_status,
            "last_completed_at": self.last_completed_at,
        }


def is_experimental_enabled() -> bool:
    """Return ``True`` when the server-side experimental flag is on.

    The flag is read from the ``memory_symbol_experimental_mismatch_enabled``
    setting (env: ``MEMORY_SYMBOL_EXPERIMENTAL_MISMATCH_ENABLED``).
    The default is ``False``.  Every API path that mutates or
    returns experimental state MUST call this function first.
    """
    try:
        settings = get_settings()
    except Exception:  # noqa: BLE001
        return False
    return bool(getattr(settings, "memory_symbol_experimental_mismatch_enabled", False))


def is_validated_run(run: MemoryScanRun | None) -> bool:
    """Return ``True`` when a scan run is part of the validated trust
    domain.  Unknown / missing runs are treated as validated (the
    default of the column is ``validated``).
    """
    if run is None:
        return True
    mode = getattr(run, "analysis_mode", ANALYSIS_MODE_VALIDATED) or ANALYSIS_MODE_VALIDATED
    trust = getattr(run, "trust_level", TRUST_LEVEL_VALIDATED) or TRUST_LEVEL_VALIDATED
    return mode == ANALYSIS_MODE_VALIDATED and trust == TRUST_LEVEL_VALIDATED


def is_experimental_run(run: MemoryScanRun | None) -> bool:
    if run is None:
        return False
    mode = getattr(run, "analysis_mode", None)
    trust = getattr(run, "trust_level", None)
    return mode == ANALYSIS_MODE_EXPERIMENTAL and trust == TRUST_LEVEL_UNTRUSTED


def is_validated_plugin(plugin: MemoryPluginRun | None) -> bool:
    if plugin is None:
        return True
    mode = getattr(plugin, "analysis_mode", ANALYSIS_MODE_VALIDATED) or ANALYSIS_MODE_VALIDATED
    return mode == ANALYSIS_MODE_VALIDATED


def is_experimental_candidate_cache_row(cache: MemoryCachedSymbol | None) -> bool:
    if cache is None:
        return False
    classification = getattr(cache, "cache_classification", CACHE_CLASSIFICATION_EXACT)
    return classification == CACHE_CLASSIFICATION_EXPERIMENTAL_CANDIDATE


def normalize_pdb_name(name: str) -> str:
    """Return the canonical lowercase form of a PDB name.

    The exact-symbol path already enforces case-sensitive matching
    against the Microsoft symbol server, but the experimental
    eligibility check must be permissive enough to accept
    ``ntkrnlmp.pdb`` and ``NTKRNLMP.PDB`` interchangeably while
    still rejecting ``ntkrnlmp`` (extension mismatch) and
    ``ntoskrnl.pdb`` (name mismatch).
    """
    if name is None:
        return ""
    return str(name).strip().lower()


def architectures_compatible(required: str, observed: str) -> bool:
    """Return ``True`` when two architecture labels are compatible.

    Compatibility is a permissive check: ``x64`` matches
    ``amd64``; ``x86`` matches ``i386``; ``arm64`` matches
    ``aarch64``.  Other pairs are rejected.
    """
    if not required or not observed:
        return False
    a = str(required).strip().lower()
    b = str(observed).strip().lower()
    if a == b:
        return True
    pairs = {
        frozenset({"x64", "amd64"}),
        frozenset({"x86", "i386"}),
        frozenset({"arm64", "aarch64"}),
    }
    return frozenset({a, b}) in pairs


def evaluate_candidate_eligibility(
    requirement: MemorySymbolRequirement,
    cache: MemoryCachedSymbol,
) -> dict[str, Any]:
    """Return an eligibility verdict for ``(requirement, cache)``.

    The verdict has the following shape::

        {
            "eligible": bool,
            "reason": str | None,        # human-readable explanation
            "error_code": str | None,    # canonical code
            "match_type": str | None,    # "guid_only_age_mismatch" if eligible
            "warning": str | None,       # human-readable mismatch description
        }

    The function is the single decision point.  Routes and CLI
    paths both call this function.  The check never mutates state.
    """
    if requirement is None:
        return {
            "eligible": False,
            "reason": "No exact symbol requirement is recorded for this evidence.",
            "error_code": "EXPERIMENTAL_REQUIREMENT_MISSING",
            "match_type": None,
            "warning": None,
        }
    if cache is None:
        return {
            "eligible": False,
            "reason": "The candidate symbol is not present in the cache.",
            "error_code": "EXPERIMENTAL_CANDIDATE_MISSING",
            "match_type": None,
            "warning": None,
        }
    # GUID mismatch is NEVER eligible.
    if normalize_pdb_name(cache.pdb_guid) != normalize_pdb_name(requirement.pdb_guid):
        return {
            "eligible": False,
            "reason": (
                f"Candidate GUID {cache.pdb_guid!r} does not match the required "
                f"GUID {requirement.pdb_guid!r}."
            ),
            "error_code": "EXPERIMENTAL_GUID_MISMATCH",
            "match_type": None,
            "warning": None,
        }
    # PDB name mismatch is NEVER eligible.
    if normalize_pdb_name(cache.pdb_name) != normalize_pdb_name(requirement.pdb_name):
        return {
            "eligible": False,
            "reason": (
                f"Candidate PDB name {cache.pdb_name!r} does not match the "
                f"required name {requirement.pdb_name!r}."
            ),
            "error_code": "EXPERIMENTAL_NAME_MISMATCH",
            "match_type": None,
            "warning": None,
        }
    # Architecture mismatch is NEVER eligible.
    if not architectures_compatible(cache.architecture, requirement.architecture):
        return {
            "eligible": False,
            "reason": (
                f"Candidate architecture {cache.architecture!r} is not "
                f"compatible with the required architecture "
                f"{requirement.architecture!r}."
            ),
            "error_code": "EXPERIMENTAL_ARCHITECTURE_MISMATCH",
            "match_type": None,
            "warning": None,
        }
    # Identity completeness.
    if not cache.pdb_guid or not cache.pdb_name:
        return {
            "eligible": False,
            "reason": "Candidate identity is incomplete (empty GUID or name).",
            "error_code": "EXPERIMENTAL_IDENTITY_INCOMPLETE",
            "match_type": None,
            "warning": None,
        }
    # The cache row must be classified as an experimental candidate.
    if cache.cache_classification != CACHE_CLASSIFICATION_EXPERIMENTAL_CANDIDATE:
        return {
            "eligible": False,
            "reason": (
                "Candidate cache row is not classified as "
                f"'{CACHE_CLASSIFICATION_EXPERIMENTAL_CANDIDATE}'."
            ),
            "error_code": "EXPERIMENTAL_CANDIDATE_NOT_CLASSIFIED",
            "match_type": None,
            "warning": None,
        }
    # ISF schema must be valid.
    if cache.validation_status not in {"validated", "usable", "ready"}:
        return {
            "eligible": False,
            "reason": (
                f"Candidate ISF validation_status={cache.validation_status!r} "
                "is not in the accepted set."
            ),
            "error_code": "EXPERIMENTAL_ISF_SCHEMA_INVALID",
            "match_type": None,
            "warning": None,
        }
    # Age mismatch is the only allowed mismatch type.  Exact match is
    # NEVER eligible for the experimental flow; the exact path is
    # the canonical one.
    if int(cache.pdb_age) == int(requirement.pdb_age):
        return {
            "eligible": False,
            "reason": (
                "The candidate has the same age as the requirement.  "
                "Use the exact symbol path; experimental analysis is only "
                "available for mismatched symbols."
            ),
            "error_code": "EXPERIMENTAL_EXACT_MATCH_NOT_ELIGIBLE",
            "match_type": None,
            "warning": None,
        }
    return {
        "eligible": True,
        "reason": None,
        "error_code": None,
        "match_type": SYMBOL_MATCH_TYPE_GUID_ONLY_AGE_MISMATCH,
        "warning": (
            f"Same name and GUID, but age differs "
            f"(required={int(requirement.pdb_age)}, "
            f"observed={int(cache.pdb_age)})."
        ),
    }


def compute_trust_state(
    db: Session,
    *,
    case_id: str,
    evidence_id: str,
) -> ExperimentalTrustState:
    """Return a read-only view of the experimental trust state."""
    candidate = (
        db.query(MemoryExperimentalSymbolCandidate)
        .filter(
            MemoryExperimentalSymbolCandidate.case_id == case_id,
            MemoryExperimentalSymbolCandidate.evidence_id == evidence_id,
            MemoryExperimentalSymbolCandidate.revoked_at.is_(None),
        )
        .order_by(MemoryExperimentalSymbolCandidate.created_at.desc())
        .first()
    )
    has_active_candidate = candidate is not None
    if candidate is not None:
        from app.services.memory.experimental_import import ExperimentalImportError, verify_candidate_integrity

        try:
            verify_candidate_integrity(db, candidate=candidate)
        except ExperimentalImportError:
            has_active_candidate = False
    active_run = (
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
        .order_by(MemoryExperimentalRun.created_at.desc())
        .first()
    )
    last_run = (
        db.query(MemoryExperimentalRun)
        .filter(
            MemoryExperimentalRun.case_id == case_id,
            MemoryExperimentalRun.evidence_id == evidence_id,
        )
        .order_by(MemoryExperimentalRun.created_at.desc())
        .first()
    )
    last_completed_at = None
    if last_run is not None and last_run.completed_at is not None:
        last_completed_at = last_run.completed_at.isoformat()
    return ExperimentalTrustState(
        enabled=is_experimental_enabled(),
        has_active_candidate=has_active_candidate,
        has_active_run=active_run is not None,
        run_id=active_run.id if active_run is not None else None,
        run_status=active_run.status if active_run is not None else None,
        canary_status=active_run.canary_status if active_run is not None else None,
        last_completed_at=last_completed_at,
    )


__all__ = [
    "ACK_CHECKBOX_CONFIRMED_TEXT",
    "ACK_REQUIRED_FIELDS",
    "ANALYSIS_MODE_EXPERIMENTAL",
    "ANALYSIS_MODE_VALIDATED",
    "CACHE_CLASSIFICATION_EXACT",
    "CACHE_CLASSIFICATION_EXPERIMENTAL_CANDIDATE",
    "CANARY_STATUS_DEGRADED",
    "CANARY_STATUS_FAILED",
    "CANARY_STATUS_INCONCLUSIVE",
    "CANARY_STATUS_PASSED",
    "CANARY_STATUS_PENDING",
    "CANARY_STATUS_RUNNING",
    "CANARY_STATUS_SKIPPED",
    "EXPERIMENTAL_ACK_WARNING_VERSION",
    "EXPERIMENTAL_ANALYSIS_MODES",
    "EXPERIMENTAL_CANARY_STATUSES",
    "EXPERIMENTAL_RUN_STATUSES",
    "EXPERIMENTAL_SYMBOL_MATCH_TYPES",
    "EXPERIMENTAL_TRUST_LEVELS",
    "ExperimentalTrustState",
    "RUN_STATUS_ACKNOWLEDGEMENT_REQUIRED",
    "RUN_STATUS_CANDIDATE_UNAVAILABLE",
    "RUN_STATUS_CANCELLED",
    "RUN_STATUS_CANARY_DEGRADED",
    "RUN_STATUS_CANARY_FAILED",
    "RUN_STATUS_CANARY_INCONCLUSIVE",
    "RUN_STATUS_CANARY_PASSED",
    "RUN_STATUS_CANARY_QUEUED",
    "RUN_STATUS_CANARY_RUNNING",
    "RUN_STATUS_COMPLETED_UNTRUSTED",
    "RUN_STATUS_DELETED",
    "RUN_STATUS_FAILED_UNTRUSTED",
    "RUN_STATUS_FULL_RUN_QUEUED",
    "RUN_STATUS_FULL_RUN_RUNNING",
    "RUN_STATUS_PARTIAL_UNTRUSTED",
    "SYMBOL_MATCH_TYPE_EXACT",
    "SYMBOL_MATCH_TYPE_GUID_ONLY_AGE_MISMATCH",
    "TRUST_LEVEL_UNTRUSTED",
    "TRUST_LEVEL_VALIDATED",
    "architectures_compatible",
    "compute_trust_state",
    "evaluate_candidate_eligibility",
    "is_experimental_candidate_cache_row",
    "is_experimental_enabled",
    "is_experimental_run",
    "is_validated_plugin",
    "is_validated_run",
    "normalize_pdb_name",
]
