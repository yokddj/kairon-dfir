"""Public entry point for Memory Evidence Preparation.

``get_preparation_status`` is the ONLY function this package exposes for
outside callers. It orchestrates existing services -- it introduces no
new detection, readiness, or symbol-validation logic of its own:

- platform detection: app.services.memory.platform.probe_memory_platform
- capability registry: app.services.memory.capability_registry
- plugin-selection choke point: app.services.memory.analysis_plan
  .build_memory_analysis_plan
- existing readiness: app.services.memory.symbol_control
  .evidence_symbol_readiness (Windows) / the Linux symbol status already
  embedded in the plan by app.services.memory.linux_symbols
  .resolve_linux_symbols (Linux)

No code here is specific to a platform beyond selecting which adapter to
delegate the final translation step to (app.services.memory.preparation
.adapters) -- see that module for why Windows and Linux need genuinely
different internal logic despite sharing this same public entry point
and output shape.

This module is currently unused by any route, worker task, or frontend
code. It exists as infrastructure for a future phase; calling it has no
visible effect on the product today.
"""
from __future__ import annotations

from pathlib import Path

from sqlalchemy.orm import Session

from app.models.evidence import Evidence, EvidenceType
from app.services.memory.analysis_plan import build_memory_analysis_plan
from app.services.memory.platform import Architecture, PlatformFamily, probe_memory_platform
from app.services.memory.preparation.adapters import LinuxPreparationAdapter, WindowsPreparationAdapter
from app.services.memory.preparation.models import MemoryEvidencePreparation, PreparationState


class MemoryPreparationError(ValueError):
    """Raised when get_preparation_status cannot describe the requested evidence at all
    (not found, or not memory_dump evidence) -- distinct from a normal
    "not ready yet" outcome, which is always a MemoryEvidencePreparation
    value, never an exception.
    """


# Platform -> adapter. Only Windows and Linux are implemented in this
# phase; any other detected/undetected platform falls through to the
# generic handling in get_preparation_status below rather than a
# per-platform adapter, so adding a new platform later never requires
# touching this orchestrator's control flow -- only registering a new
# adapter here.
_ADAPTERS = {
    PlatformFamily.WINDOWS: WindowsPreparationAdapter(),
    PlatformFamily.LINUX: LinuxPreparationAdapter(),
}


def _resolve_canonical_path(evidence: Evidence) -> Path:
    """Best-effort path resolution mirroring build_memory_analysis_plan's own
    fallback (app.services.memory.analysis_plan), so this module's direct
    probe call and the plan's internal probe call see the same path.
    Calls the same existing resolver that function calls
    (app.services.memory.evidence_access.resolve_memory_evidence_path) --
    this is plumbing around that call, not a reimplementation of it.
    """
    from app.core.config import get_settings
    from app.services.memory.evidence_access import resolve_memory_evidence_path

    try:
        return resolve_memory_evidence_path(evidence, settings=get_settings())
    except Exception:  # noqa: BLE001
        fallback = str(getattr(evidence, "stored_path", "") or "").strip()
        return Path(fallback) if fallback else Path("/nonexistent-evidence-path")


def get_preparation_status(db: Session, evidence_id: str) -> MemoryEvidencePreparation:
    """Compute the current, read-only preparation status for one memory evidence item.

    Never persists anything, never enqueues work, never mutates the
    evidence row. Safe to call repeatedly; always recomputed from current
    state.
    """
    evidence = db.get(Evidence, evidence_id)
    if evidence is None:
        raise MemoryPreparationError(f"Evidence {evidence_id} was not found.")
    if evidence.evidence_type != EvidenceType.memory_dump:
        raise MemoryPreparationError(f"Evidence {evidence_id} is not memory_dump evidence.")

    # Mirrors the exact same confirmation gate POST /evidences/{id}/memory
    # /scan already enforces (app/api/routes_memory.py) against the same
    # two already-persisted Evidence fields -- not a second
    # implementation of that rule, a second, read-only site that checks
    # it the same way, since no shared helper function for this specific
    # check exists to import (it is inline route logic there).
    if evidence.detection_status == "probable_disk":
        return MemoryEvidencePreparation(
            evidence_id=evidence_id,
            platform=PlatformFamily.UNKNOWN,
            architecture=Architecture.UNKNOWN,
            readiness=PreparationState.BLOCKED,
            requires_symbols=False,
            can_start_analysis=False,
            human_message=(
                "This evidence was classified as a probable disk image. Import it as disk "
                "evidence or confirm it as memory before analyzing."
            ),
        )
    if evidence.detection_status == "ambiguous_raw" and not evidence.operator_override:
        return MemoryEvidencePreparation(
            evidence_id=evidence_id,
            platform=PlatformFamily.UNKNOWN,
            architecture=Architecture.UNKNOWN,
            readiness=PreparationState.AWAITING_USER,
            requires_symbols=False,
            can_start_analysis=False,
            human_message=(
                "This evidence has an ambiguous probe verdict. Confirm the evidence type "
                "before Kairon can assess memory readiness."
            ),
        )

    canonical_path = _resolve_canonical_path(evidence)
    filename = evidence.original_filename or None

    # Two separate calls to existing platform-detection entry points
    # (probe_memory_platform directly here for architecture, and again
    # inside build_memory_analysis_plan for platform/readiness/
    # capabilities) -- an accepted, documented duplication of *effort*
    # (a second bounded probe, occasionally a second Volatility fallback
    # probe if static detection is inconclusive), not of *logic*.
    # build_memory_analysis_plan's own dataclass does not expose
    # architecture, and this phase's constraint is zero changes to any
    # existing file -- see the technical report for why extending that
    # dataclass was considered and deliberately deferred rather than done
    # here.
    probe = probe_memory_platform(
        canonical_path=canonical_path,
        detected_format=evidence.detected_format,
        filename=filename,
        use_volatility_fallback=True,
        evidence=evidence,
    )
    plan = build_memory_analysis_plan(evidence, canonical_path=canonical_path)

    adapter = _ADAPTERS.get(plan.detected_platform)
    if adapter is not None:
        return adapter.describe(plan, probe, db=db, evidence=evidence)

    # No adapter for this platform (unknown, macOS, or any other
    # capability-registry-unsupported family) -- generic handling, no
    # platform-specific logic.
    state = PreparationState.INSPECTING if plan.detected_platform == PlatformFamily.UNKNOWN else PreparationState.BLOCKED
    return MemoryEvidencePreparation(
        evidence_id=evidence_id,
        platform=plan.detected_platform,
        architecture=probe.architecture,
        readiness=state,
        requires_symbols=False,
        can_start_analysis=False,
        human_message=plan.readiness_reason,
    )
