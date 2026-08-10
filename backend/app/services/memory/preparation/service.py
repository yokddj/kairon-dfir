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

Wired into ``GET /cases/{case_id}/memory/evidences/{evidence_id}/preparation``
(app/api/routes_memory.py) as a pure passthrough, and consumed by the
frontend's Memory Preparation surfaces.
"""
from __future__ import annotations

from dataclasses import replace
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


def _compute_base_preparation(db: Session, evidence_id: str) -> MemoryEvidencePreparation:
    """Compute the current, read-only preparation status for one memory evidence item.

    Never persists anything, never enqueues work, never mutates the
    evidence row. Safe to call repeatedly; always recomputed from current
    state.

    This is the pre-Phase-2 body of what used to be ``get_preparation_status``,
    unchanged, renamed only so the public function below can wrap it with
    the platform-agnostic VMware companion fields without touching a
    single line of this platform-adapter-driven logic.
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


# VMware companion (Phase 2) -- deliberately platform-agnostic: this
# section never imports anything Linux- or Windows-specific, and it runs
# for every memory_dump evidence regardless of which adapter (or no
# adapter at all) produced the base preparation above.

VMWARE_COMPANION_WARNING_TEXT = (
    "VMware memory can sometimes be analyzed without snapshot metadata. "
    "A matching .vmsn or .vmss file may be required for reliable analysis."
)


def _vmware_companion_applicable(evidence: Evidence, canonical_path: Path) -> bool:
    """Conservative signal for "this evidence might benefit from a VMware
    companion" -- never treated as proof the evidence definitely is a
    VMware capture, only as a reason to *offer* the option.

    Two real signals, combined rather than used alone:

    1. ``Evidence.detected_format == "vmware_vmem"`` -- the upload-time
       magic-byte probe (app.services.memory.probe) positively identified
       the VMware sparse-memory header. High confidence when present, but
       real VMware .vmem captures do not always carry that exact
       signature within the probe's read window (verified against real
       evidence during this phase's runtime validation, where a genuine
       VMware capture probed as ``ambiguous_raw``/``raw_candidate``) -- so
       its absence must not be treated as "not VMware".
    2. The primary file's own canonical/resolved basename ends in
       ``.vmem``. This is not "extension alone" standing in for content
       inspection: it is the literal, verified condition Volatility 3's
       own VmwareStacker uses to decide whether to even attempt companion
       discovery (``location.endswith(".vmem")`` in
       volatility3/framework/layers/vmware.py) -- so it is the one signal
       guaranteed to correlate with whether attaching a companion could
       ever matter for this file, independent of Kairon's own narrower
       probe. By the time this function runs, the evidence has already
       passed every earlier "this probably isn't memory at all" gate in
       ``_compute_base_preparation`` (probable_disk / unconfirmed
       ambiguous_raw both return before this point is ever reached).
    """
    detected_format = str(evidence.detected_format or "").strip().lower()
    if detected_format == "vmware_vmem":
        return True
    try:
        return canonical_path.suffix.lower() == ".vmem"
    except (TypeError, ValueError):
        return False


def _vmware_companion_fields(db: Session, evidence: Evidence, canonical_path: Path) -> dict[str, object]:
    from app.services.memory.companion_files import get_evidence_companion_status

    status = get_evidence_companion_status(db, evidence.id)
    has_companion = bool(status["has_vmware_companion"])
    applicable = _vmware_companion_applicable(evidence, canonical_path)
    recommended = applicable and not has_companion
    return {
        "has_vmware_companion": has_companion,
        "vmware_companion_id": status["companion_id"],
        "vmware_companion_type": status["companion_type"],
        "vmware_companion_filename": status["original_filename"],
        "vmware_companion_sha256": status["sha256"],
        "vmware_companion_size_bytes": status["size_bytes"],
        "vmware_companion_recommended": recommended,
        "vmware_companion_warning": VMWARE_COMPANION_WARNING_TEXT if recommended else None,
    }


def _zero_result_warning_fields(db: Session, evidence_id: str) -> dict[str, object]:
    """Surfaces app.services.memory.execution's VMWARE_METADATA_MAY_BE_
    REQUIRED plugin-run warning (Phase 2) right next to the companion
    section that resolves it, rather than through the family-results
    tables (app.services.memory.active_result): the "processes" family's
    existing active-run resolution requires a non-zero canonical entity
    count to promote a run to "active" at all (see
    active_result._is_canonical_usable), which means a genuinely empty
    linux.pslist/windows.pslist result -- exactly this warning's own
    trigger condition -- would never reach that surface. This reads the
    single most recent MemoryPluginRun for the evidence (any plugin): if
    it is the same run that would show anywhere else, its warning_code is
    already stale the moment a newer run (e.g. after attaching a
    companion) completes without it -- no companion-presence check
    needed here, this already self-corrects.
    """
    from app.models.memory import MemoryPluginRun

    latest = (
        db.query(MemoryPluginRun)
        .filter(MemoryPluginRun.evidence_id == evidence_id)
        .order_by(MemoryPluginRun.created_at.desc())
        .first()
    )
    if latest is None or not latest.warning_code:
        return {
            "zero_result_warning_code": None,
            "zero_result_warning_message": None,
            "zero_result_warning_plugin": None,
        }
    return {
        "zero_result_warning_code": latest.warning_code,
        "zero_result_warning_message": latest.warning_message,
        "zero_result_warning_plugin": latest.plugin,
    }


def get_preparation_status(db: Session, evidence_id: str) -> MemoryEvidencePreparation:
    """Public entry point (see the package docstring). Computes the base,
    platform-specific preparation exactly as before, then augments it with
    the platform-agnostic VMware companion fields (Phase 2) -- purely
    informational, never able to change ``can_start_analysis``.
    """
    base = _compute_base_preparation(db, evidence_id)
    evidence = db.get(Evidence, evidence_id)
    if evidence is None:
        # _compute_base_preparation would already have raised
        # MemoryPreparationError for this -- unreachable in practice, but
        # falling back to the base result (no companion fields) rather
        # than risking a second, differently-worded error is strictly
        # safer for a read-only status endpoint.
        return base
    companion_fields = _vmware_companion_fields(db, evidence, _resolve_canonical_path(evidence))
    warning_fields = _zero_result_warning_fields(db, evidence_id)
    return replace(base, **companion_fields, **warning_fields)
