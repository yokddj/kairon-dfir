"""Single choke point between platform detection and plugin selection.

app.services.memory.platform already detects Linux vs Windows correctly.
app.services.memory.execution used to pick plugins from a Windows-only
table with zero awareness of that detection, which is how Linux evidence
ended up running Windows plugins. build_memory_analysis_plan() is the one
place allowed to turn "detected platform" into "these plugins run" --
execution.py, routes_memory.py and batch.py must all call this instead of
inspecting the capability registry or the platform probe themselves.

Listing a plugin here as SELECTED is a claim that the platform genuinely
matches (real magic-byte/detected-format/history evidence, never a
default) and the plugin is a real, registered capability binding for
that platform -- see app.services.memory.capability_registry, whose
entries were verified importable in the real memory-worker deployment
before being added. It is deliberately NOT a second, redundant
import-check performed here: this function commonly runs in the API
process at run-creation time, which does not have Volatility 3
installed (only the dedicated memory-worker container does), so a
local ``import volatility3`` probe here would be either meaningless or
actively wrong. The authoritative, live "is this plugin importable
right now" check already exists and runs where it is truthful -- inside
the worker, at execution time -- via
app.services.memory.execution.OPTIONAL_RUNTIME_PROBED_PLUGINS and
volatility_runner.probe_volatility_plugin(). A selected plugin can
still fail for real at execution time (e.g. genuinely missing ISF
symbols, or turning out not to be importable after all), and that
failure must be classified from Volatility's actual error text /
runtime probe, not predicted here.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from app.core.config import get_settings
from app.services.memory.capability_registry import (
    MemoryCapability,
    SkipReason,
    capabilities_for_platform,
    plugins_for_capability,
)
from app.services.memory.platform import (
    PlatformFamily,
    ProbeConfidence,
    ReadinessState,
    probe_memory_platform,
)
from app.services.memory.linux_symbols import expected_linux_identity_from_evidence, resolve_linux_symbols

# Platform families the capability registry has zero entries for today.
# Kept separate from PlatformFamily.UNKNOWN (probe could not decide) --
# these are RECOGNIZED families Kairon simply has no plugins for yet.
_REGISTRY_UNSUPPORTED_PLATFORMS = (PlatformFamily.MACOS, PlatformFamily.UNSUPPORTED)


@dataclass(frozen=True)
class MemoryAnalysisPlan:
    """Platform-aware plan: what this evidence is, and what may run against it."""

    evidence_id: str
    detected_platform: PlatformFamily
    platform_confidence: ProbeConfidence
    platform_signals: str
    framework: str
    readiness: ReadinessState
    readiness_reason: str
    eligible_capabilities: tuple[MemoryCapability, ...] = field(default_factory=tuple)
    ineligible_capabilities: tuple[tuple[MemoryCapability, SkipReason], ...] = field(default_factory=tuple)
    selected_plugins: tuple[str, ...] = field(default_factory=tuple)
    skipped_plugins: tuple[tuple[str, SkipReason], ...] = field(default_factory=tuple)
    symbol_status: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "evidence_id": self.evidence_id,
            "detected_platform": self.detected_platform.value,
            "platform_confidence": self.platform_confidence.value,
            "platform_signals": self.platform_signals,
            "framework": self.framework,
            "readiness": self.readiness.value,
            "readiness_reason": self.readiness_reason,
            "eligible_capabilities": [c.value for c in self.eligible_capabilities],
            "ineligible_capabilities": {c.value: r.value for c, r in self.ineligible_capabilities},
            "selected_plugins": list(self.selected_plugins),
            "skipped_plugins": {plugin: r.value for plugin, r in self.skipped_plugins},
            "symbol_status": dict(self.symbol_status),
        }


def _empty_plan(
    evidence_id: str,
    *,
    platform: PlatformFamily,
    confidence: ProbeConfidence,
    signals: str,
    readiness: ReadinessState,
    readiness_reason: str,
    framework: str = "",
) -> MemoryAnalysisPlan:
    return MemoryAnalysisPlan(
        evidence_id=evidence_id,
        detected_platform=platform,
        platform_confidence=confidence,
        platform_signals=signals,
        framework=framework,
        readiness=readiness,
        readiness_reason=readiness_reason,
    )


def _linux_symbol_status(evidence: Any) -> dict[str, Any]:
    """Real, direct check of the offline ISF symbol cache -- never assumed.

    The memory worker runs Volatility offline (no network access), so this
    directory is authoritative: if it has no Linux tables, a
    symbol-requiring Linux plugin genuinely cannot resolve one. Verified
    against the real deployment: /volatility-cache/volatility3/symbols
    currently has a populated windows/ subdirectory and no linux/ one.
    """
    required_identity = expected_linux_identity_from_evidence(evidence)
    status = resolve_linux_symbols(get_settings(), required_identity=required_identity)
    return {
        "symbols_found": status.found,
        "symbols_valid": status.valid,
        "symbols_compatible": status.compatible,
        "volatility_selectable": status.volatility_selectable,
        "symbol_source": status.source,
        "symbol_identity": status.identity,
        "symbol_identity_details": status.identity_details,
        "symbol_path": status.path,
        "symbol_sha256": status.sha256,
        "reason_code": status.reason_code,
    }


def build_memory_analysis_plan(
    evidence: Any,
    *,
    canonical_path: Path | None = None,
    requested_capabilities: list[MemoryCapability] | None = None,
) -> MemoryAnalysisPlan:
    """Build the canonical plan for one evidence item.

    Never defaults an unresolved platform to Windows. A capability is
    eligible only when the real platform probe matched it to a registry
    entry for that platform -- see the module docstring for why
    plugin-level import verification is deliberately deferred to
    execution time rather than duplicated here.

    ``canonical_path``, when given, is used as-is instead of re-resolving
    evidence storage access -- callers that already validated evidence
    access (e.g. ``execution.create_memory_metadata_run`` via
    ``validate_memory_execution_request``) should pass that resolved path
    through rather than have it re-derived here, since storage access can
    legitimately differ by process (API vs. worker) and re-resolving
    would either duplicate work or reject a path the caller already
    proved readable.
    """
    from app.services.memory.evidence_access import resolve_memory_evidence_path

    evidence_id = str(getattr(evidence, "id", ""))
    path_resolution_error: str | None = None

    if canonical_path is None:
        try:
            canonical_path = resolve_memory_evidence_path(evidence, settings=get_settings())
        except Exception as exc:  # noqa: BLE001
            # Storage access could not be validated from this process, but
            # detected_format/history are legitimate platform signals
            # independent of live readability (storage access can differ
            # by process -- see the canonical_path docstring above). Fall
            # through to a best-effort probe on the declared stored path
            # instead of giving up on platform detection entirely; a
            # nonexistent/unreadable path degrades gracefully to an empty
            # magic-byte read (see platform._read_head).
            path_resolution_error = str(exc)
            fallback_raw = str(getattr(evidence, "stored_path", "") or "").strip()
            canonical_path = Path(fallback_raw) if fallback_raw else Path("/nonexistent-evidence-path")

    filename = (
        getattr(evidence, "original_filename", None)
        or getattr(evidence, "display_name", None)
        or getattr(evidence, "filename", None)
    )
    probe = probe_memory_platform(
        canonical_path=canonical_path,
        detected_format=getattr(evidence, "detected_format", None),
        filename=filename,
        use_volatility_fallback=True,
        evidence=evidence,
    )
    platform = probe.platform

    if platform == PlatformFamily.UNKNOWN:
        if path_resolution_error is not None:
            return _empty_plan(
                evidence_id,
                platform=platform,
                confidence=probe.confidence,
                signals=f"path_unavailable:{path_resolution_error}; {probe.reason}",
                readiness=ReadinessState.INVALID_EVIDENCE,
                readiness_reason=(
                    "Memory evidence storage could not be resolved to a readable path from this "
                    "process, and no declared format or history resolved the platform either."
                ),
            )
        return _empty_plan(
            evidence_id,
            platform=platform,
            confidence=probe.confidence,
            signals=probe.reason,
            readiness=ReadinessState.PLATFORM_UNKNOWN,
            readiness_reason=(
                "The evidence's operating-system family could not be determined from its "
                "header, declared format, or history. No plugins were selected -- an unknown "
                "platform is never silently treated as Windows."
            ),
        )

    if platform in _REGISTRY_UNSUPPORTED_PLATFORMS:
        return _empty_plan(
            evidence_id,
            platform=platform,
            confidence=probe.confidence,
            signals=probe.reason,
            readiness=ReadinessState.PLATFORM_UNSUPPORTED,
            readiness_reason=f"Kairon's memory capability registry has no plugins for platform '{platform.value}'.",
        )

    all_capabilities = capabilities_for_platform(platform)
    requested = requested_capabilities if requested_capabilities is not None else all_capabilities

    if not requested:
        return _empty_plan(
            evidence_id,
            platform=platform,
            confidence=probe.confidence,
            signals=probe.reason,
            readiness=ReadinessState.PLATFORM_UNSUPPORTED,
            readiness_reason=f"No capability requested for platform '{platform.value}'.",
        )

    linux_symbol_status = _linux_symbol_status(evidence) if platform == PlatformFamily.LINUX else {}
    linux_symbols_present = bool(
        linux_symbol_status.get("symbols_found")
        and linux_symbol_status.get("symbols_valid")
        and linux_symbol_status.get("symbols_compatible")
        and linux_symbol_status.get("volatility_selectable")
    )

    eligible: list[MemoryCapability] = []
    ineligible: list[tuple[MemoryCapability, SkipReason]] = []
    selected_plugins: list[str] = []
    frameworks_used: set[str] = set()

    for capability in requested:
        specs = plugins_for_capability(platform, capability)
        if not specs:
            # Registered for some other platform, or not a real
            # capability for this one -- never silently dropped.
            ineligible.append((capability, SkipReason.PLATFORM_MISMATCH))
            continue
        for spec in specs:
            selected_plugins.append(spec.plugin)
            frameworks_used.add(spec.framework)
        eligible.append(capability)

    if "volatility3" in frameworks_used:
        framework = "volatility3"
    elif frameworks_used:
        framework = next(iter(frameworks_used))
    else:
        framework = ""

    if not eligible:
        readiness = ReadinessState.PLATFORM_UNSUPPORTED
        readiness_reason = f"No requested capability has a registry entry for platform '{platform.value}'."
    elif platform == PlatformFamily.LINUX and not linux_symbols_present:
        readiness = ReadinessState.PARTIALLY_READY if ineligible else ReadinessState.BLOCKED_SYMBOLS
        linux_reason = str(linux_symbol_status.get("reason_code") or "symbols_unavailable")
        readiness_reason = (
            f"Linux symbols are not ready ({linux_reason}). Kairon requires a resolved evidence "
            "kernel identity plus a validated, compatible, Volatility-selectable Linux ISF in the offline cache."
        )
    elif ineligible:
        readiness = ReadinessState.PARTIALLY_READY
        readiness_reason = f"{len(eligible)} of {len(requested)} requested capabilities are eligible for platform '{platform.value}'."
    else:
        readiness = ReadinessState.READY
        readiness_reason = f"All requested capabilities are eligible for platform '{platform.value}'."

    return MemoryAnalysisPlan(
        evidence_id=evidence_id,
        detected_platform=platform,
        platform_confidence=probe.confidence,
        platform_signals=probe.reason,
        framework=framework,
        readiness=readiness,
        readiness_reason=readiness_reason,
        eligible_capabilities=tuple(eligible),
        ineligible_capabilities=tuple(ineligible),
        selected_plugins=tuple(selected_plugins),
        skipped_plugins=(),
        symbol_status=linux_symbol_status,
    )
