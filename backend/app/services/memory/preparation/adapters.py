"""Internal platform adapters for Memory Evidence Preparation.

Not public API: app.services.memory.preparation.service is the only
caller. Each adapter's ``describe()`` turns an already-computed
MemoryAnalysisPlan (app.services.memory.analysis_plan
.build_memory_analysis_plan -- the existing single choke point between
platform detection and plugin selection) into a MemoryEvidencePreparation.
Neither adapter re-detects platform, re-derives plugin eligibility, or
re-implements symbol validation -- they only read what the plan (and, for
Windows, the existing evidence_symbol_readiness() service) already
computed, and translate it into the six-value PreparationState vocabulary.

Naming note: these are DELIBERATELY distinct from
app.services.memory.platform.WindowsMemoryAdapter / LinuxMemoryAdapter,
which are a different, pre-existing pair of adapters driving the
asynchronous MemorySymbolPreparation pipeline
(app.services.memory.preparation_runtime). Do not conflate the two --
see the module docstring on app.services.memory.preparation.models for
the full distinction. The similar names are an acknowledged, documented
risk of this phase, not an oversight.
"""
from __future__ import annotations

from typing import Protocol

from app.services.memory.analysis_plan import MemoryAnalysisPlan
from app.services.memory.capability_registry import MemoryCapability, specs_for_platform
from app.services.memory.platform import MemoryProbeResult, PlatformFamily, ReadinessState
from app.services.memory.preparation.models import MemoryEvidencePreparation, PreparationState

# Pure translation of the existing, generic ReadinessState vocabulary
# (app.services.memory.platform.ReadinessState, already produced by
# build_memory_analysis_plan for both platforms) onto this module's
# narrower six-state vocabulary. Holds no platform-specific case --
# both adapters start from this same mapping.
_READINESS_STATE_MAP: dict[ReadinessState, PreparationState] = {
    ReadinessState.READY: PreparationState.READY,
    ReadinessState.PARTIALLY_READY: PreparationState.READY,
    ReadinessState.BLOCKED_SYMBOLS: PreparationState.SYMBOLS_REQUIRED,
    ReadinessState.PLATFORM_UNKNOWN: PreparationState.INSPECTING,
    ReadinessState.PLATFORM_UNSUPPORTED: PreparationState.BLOCKED,
    ReadinessState.PROFILE_UNAVAILABLE: PreparationState.BLOCKED,
    ReadinessState.FRAMEWORK_UNAVAILABLE: PreparationState.BLOCKED,
    ReadinessState.BLOCKED: PreparationState.BLOCKED,
    ReadinessState.INVALID_EVIDENCE: PreparationState.FAILED,
    ReadinessState.FAILED: PreparationState.FAILED,
}


def _map_readiness(state: ReadinessState) -> PreparationState:
    return _READINESS_STATE_MAP.get(state, PreparationState.BLOCKED)


def _capability_requires_symbols(platform: PlatformFamily, eligible_capabilities: tuple[MemoryCapability, ...]) -> bool:
    """True if any capability this plan already marked eligible needs symbols.

    Pure read over app.services.memory.capability_registry.specs_for_platform
    -- every CapabilityPluginSpec already carries a ``requires_symbols``
    field for exactly this question; this helper does not add a new
    concept, it composes an existing one.
    """
    specs = specs_for_platform(platform)
    return any(spec.requires_symbols for spec in specs if spec.capability in eligible_capabilities)


class PlatformPreparationAdapter(Protocol):
    """Internal adapter contract. Not part of the public API surface."""

    def describe(
        self,
        plan: MemoryAnalysisPlan,
        probe: MemoryProbeResult,
        *,
        db: object,
        evidence: object,
    ) -> MemoryEvidencePreparation: ...


class WindowsPreparationAdapter:
    """Windows: build_memory_analysis_plan() only confirms plugins are
    *registered* for Windows -- it deliberately does not check whether
    this evidence's specific PDB/GUID/age symbol is cached (see that
    module's docstring: symbol readiness is a separate concern). So a
    plan.readiness of READY here is necessary but not sufficient; this
    adapter additionally consults the existing, already-production
    app.services.memory.symbol_control.evidence_symbol_readiness() --
    the same function the real /memory/evidences/{id}/readiness endpoint
    already calls -- rather than re-deriving Windows symbol-cache state.
    """

    def describe(self, plan: MemoryAnalysisPlan, probe: MemoryProbeResult, *, db, evidence) -> MemoryEvidencePreparation:
        requires_symbols = _capability_requires_symbols(plan.detected_platform, plan.eligible_capabilities)
        state = _map_readiness(plan.readiness)
        can_start = False
        message = plan.readiness_reason or "This evidence cannot be analyzed yet."

        if state is PreparationState.READY:
            from app.services.memory.symbol_control import evidence_symbol_readiness

            symbol_readiness = evidence_symbol_readiness(db, evidence.case_id, evidence.id)
            can_analyze_offline = bool(symbol_readiness.get("can_analyze_offline"))
            if symbol_readiness.get("symbols_required") and not can_analyze_offline:
                state = PreparationState.SYMBOLS_REQUIRED
                message = "This Windows dump requires kernel symbols Kairon does not currently have cached."
            else:
                can_start = True
                message = (
                    "Compatible Windows symbols are already available."
                    if requires_symbols
                    else "This evidence is ready to analyze."
                )
        elif state is PreparationState.SYMBOLS_REQUIRED:
            message = "This Windows dump requires kernel symbols Kairon does not currently have."
        elif state is PreparationState.INSPECTING:
            message = "Kairon could not yet determine this evidence's operating system."

        return MemoryEvidencePreparation(
            evidence_id=plan.evidence_id,
            platform=plan.detected_platform,
            architecture=probe.architecture,
            readiness=state,
            requires_symbols=requires_symbols,
            can_start_analysis=can_start,
            human_message=message,
        )


class LinuxPreparationAdapter:
    """Linux: unlike Windows, build_memory_analysis_plan() already folds
    real Linux symbol/ISF availability into its readiness verdict for
    this platform (it calls app.services.memory.linux_symbols
    .resolve_linux_symbols() internally and returns BLOCKED_SYMBOLS when
    no compatible, Volatility-selectable ISF is cached) -- so, unlike the
    Windows adapter, no second readiness call is needed or made here.
    This adapter only translates what the plan already computed; it does
    not implement any Linux-specific detection or validation of its own.
    """

    def describe(self, plan: MemoryAnalysisPlan, probe: MemoryProbeResult, *, db, evidence) -> MemoryEvidencePreparation:
        requires_symbols = _capability_requires_symbols(plan.detected_platform, plan.eligible_capabilities)
        state = _map_readiness(plan.readiness)
        can_start = state is PreparationState.READY
        message = plan.readiness_reason or "This evidence cannot be analyzed yet."

        if state is PreparationState.READY:
            message = (
                "Compatible Linux symbols are already available."
                if requires_symbols
                else "This evidence is ready to analyze."
            )
        elif state is PreparationState.SYMBOLS_REQUIRED:
            reason_code = str((plan.symbol_status or {}).get("reason_code") or "")
            if reason_code == "kernel_identity_unknown":
                message = (
                    "Kairon does not yet know this dump's kernel identity, so Linux symbol "
                    "compatibility cannot be checked."
                )
            else:
                message = "This Linux dump requires Volatility symbols (ISF) Kairon does not currently have."
        elif state is PreparationState.INSPECTING:
            message = "Kairon could not yet determine this evidence's operating system."

        return MemoryEvidencePreparation(
            evidence_id=plan.evidence_id,
            platform=plan.detected_platform,
            architecture=probe.architecture,
            readiness=state,
            requires_symbols=requires_symbols,
            can_start_analysis=can_start,
            human_message=message,
        )
