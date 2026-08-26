"""Canonical memory analysis capability registry.

Maps a platform-independent *capability* (what an analyst wants to know:
processes, network connections, ...) to the concrete framework/plugin that
answers it on each platform. This is the single place that decides "which
plugin runs for which platform" -- app.services.memory.execution and
app.services.memory.analysis_plan both read from here instead of each
carrying their own platform assumptions, which is exactly how a Linux
evidence item ended up running app.services.memory.execution's old,
Windows-only PROFILE_PLUGINS table.

Listing a plugin here is a structural claim only ("this plugin exists for
this platform in Kairon's capability model"). It is never a compatibility
or support claim by itself -- app.services.memory.analysis_plan is what
turns a capability into ELIGIBLE (real image, real symbols, real plugin
import) before anything is ever queued for execution.
"""
from __future__ import annotations

import enum
from dataclasses import dataclass, field

from app.services.memory.platform import PlatformFamily

FRAMEWORK_VOLATILITY3 = "volatility3"


class MemoryCapability(str, enum.Enum):
    """Platform-independent analytical capability."""

    IDENTIFICATION = "identification"
    PROCESSES = "processes"
    PROCESSES_EXTENDED = "processes_extended"
    NETWORK = "network"
    MODULES = "modules"
    HANDLES = "handles"
    KERNEL_MODULES = "kernel_modules"
    SUSPICIOUS_REGIONS = "suspicious_regions"
    SHELL_HISTORY = "shell_history"


class SkipReason(str, enum.Enum):
    """Typed reason a capability or plugin was not selected/executed.

    Never replace one of these with a free-form string when the situation
    actually matches one of these meanings -- these are what
    app.services.memory.analysis_plan and the persisted MemoryPluginRun
    rows use so the UI can render a real cause instead of a symbol error
    that was never really about symbols.
    """

    PLATFORM_MISMATCH = "platform_mismatch"
    SYMBOLS_UNAVAILABLE = "symbols_unavailable"
    PROFILE_UNAVAILABLE = "profile_unavailable"
    PLUGIN_UNSUPPORTED = "plugin_unsupported"
    DEPENDENCY_UNAVAILABLE = "dependency_unavailable"
    DEPENDENCY_FAILED = "dependency_failed"
    FRAMEWORK_UNAVAILABLE = "framework_unavailable"
    NOT_SELECTED = "not_selected"


@dataclass(frozen=True)
class CapabilityPluginSpec:
    """One (capability, platform) -> concrete plugin binding."""

    capability: MemoryCapability
    platform: PlatformFamily
    framework: str
    plugin: str
    # Dependencies within the SAME platform that must complete first
    # (mirrors execution.py's existing dependency-skip behavior for
    # windows.info -> pslist/pstree/cmdline). Empty for a root capability.
    depends_on: tuple[MemoryCapability, ...] = field(default_factory=tuple)
    # Whether this plugin needs a resolved symbol/ISF table to run at
    # all. Windows plugins always do; a handful of lightweight Linux
    # plugins could in principle run against unresolved layers, but none
    # in this registry currently do -- kept as an explicit field rather
    # than assumed, since that assumption is exactly what caused this
    # sprint's bug in a different layer.
    requires_symbols: bool = True
    # Normalized document/artifact family this plugin's output becomes,
    # for reuse of existing normalizers/presentation instead of a new one
    # (see app.services.memory.artifact_normalizers / normalizers).
    presentation_family: str = "memory_process"


# ---------------------------------------------------------------------------
# Windows entries -- unchanged behavior, moved here from the flat
# execution.PROFILE_PLUGINS table so both Windows and Linux are declared
# through the same mechanism. See execution.py's PROFILE_PLUGINS_LEGACY
# note for how these compose back into the pre-existing profile names.
# ---------------------------------------------------------------------------

_WINDOWS: tuple[CapabilityPluginSpec, ...] = (
    CapabilityPluginSpec(MemoryCapability.IDENTIFICATION, PlatformFamily.WINDOWS, FRAMEWORK_VOLATILITY3, "windows.info", presentation_family="memory_system_info"),
    CapabilityPluginSpec(MemoryCapability.PROCESSES, PlatformFamily.WINDOWS, FRAMEWORK_VOLATILITY3, "windows.pslist", depends_on=(MemoryCapability.IDENTIFICATION,), presentation_family="memory_process"),
    CapabilityPluginSpec(MemoryCapability.PROCESSES, PlatformFamily.WINDOWS, FRAMEWORK_VOLATILITY3, "windows.pstree", depends_on=(MemoryCapability.IDENTIFICATION,), presentation_family="memory_process"),
    CapabilityPluginSpec(MemoryCapability.PROCESSES, PlatformFamily.WINDOWS, FRAMEWORK_VOLATILITY3, "windows.cmdline", depends_on=(MemoryCapability.IDENTIFICATION,), presentation_family="memory_process"),
    CapabilityPluginSpec(MemoryCapability.PROCESSES_EXTENDED, PlatformFamily.WINDOWS, FRAMEWORK_VOLATILITY3, "windows.psscan", presentation_family="memory_process"),
    CapabilityPluginSpec(MemoryCapability.PROCESSES_EXTENDED, PlatformFamily.WINDOWS, FRAMEWORK_VOLATILITY3, "windows.envars", presentation_family="memory_process_observation"),
    CapabilityPluginSpec(MemoryCapability.PROCESSES_EXTENDED, PlatformFamily.WINDOWS, FRAMEWORK_VOLATILITY3, "windows.getsids", presentation_family="memory_process_observation"),
    CapabilityPluginSpec(MemoryCapability.PROCESSES_EXTENDED, PlatformFamily.WINDOWS, FRAMEWORK_VOLATILITY3, "windows.privileges", presentation_family="memory_process_observation"),
    CapabilityPluginSpec(MemoryCapability.NETWORK, PlatformFamily.WINDOWS, FRAMEWORK_VOLATILITY3, "windows.netscan", presentation_family="memory_network_connection"),
    CapabilityPluginSpec(MemoryCapability.NETWORK, PlatformFamily.WINDOWS, FRAMEWORK_VOLATILITY3, "windows.netstat", presentation_family="memory_network_connection"),
    CapabilityPluginSpec(MemoryCapability.MODULES, PlatformFamily.WINDOWS, FRAMEWORK_VOLATILITY3, "windows.dlllist", presentation_family="memory_process_module"),
    CapabilityPluginSpec(MemoryCapability.MODULES, PlatformFamily.WINDOWS, FRAMEWORK_VOLATILITY3, "windows.ldrmodules", presentation_family="memory_process_module"),
    CapabilityPluginSpec(MemoryCapability.MODULES, PlatformFamily.WINDOWS, FRAMEWORK_VOLATILITY3, "windows.info", presentation_family="memory_system_info"),
    CapabilityPluginSpec(MemoryCapability.HANDLES, PlatformFamily.WINDOWS, FRAMEWORK_VOLATILITY3, "windows.handles", presentation_family="memory_handle"),
    CapabilityPluginSpec(MemoryCapability.HANDLES, PlatformFamily.WINDOWS, FRAMEWORK_VOLATILITY3, "windows.info", presentation_family="memory_system_info"),
    CapabilityPluginSpec(MemoryCapability.KERNEL_MODULES, PlatformFamily.WINDOWS, FRAMEWORK_VOLATILITY3, "windows.modules", presentation_family="memory_kernel_module"),
    CapabilityPluginSpec(MemoryCapability.KERNEL_MODULES, PlatformFamily.WINDOWS, FRAMEWORK_VOLATILITY3, "windows.driverscan", presentation_family="memory_driver"),
    CapabilityPluginSpec(MemoryCapability.KERNEL_MODULES, PlatformFamily.WINDOWS, FRAMEWORK_VOLATILITY3, "windows.info", presentation_family="memory_system_info"),
    CapabilityPluginSpec(MemoryCapability.SUSPICIOUS_REGIONS, PlatformFamily.WINDOWS, FRAMEWORK_VOLATILITY3, "windows.malfind", presentation_family="memory_suspicious_region"),
    CapabilityPluginSpec(MemoryCapability.SUSPICIOUS_REGIONS, PlatformFamily.WINDOWS, FRAMEWORK_VOLATILITY3, "windows.vadinfo", presentation_family="memory_vad"),
    # windows.consoles recovers conhost.exe console command-history
    # buffers (cmd.exe/PowerShell), the direct Windows analog of
    # linux.bash below -- both feed the same platform-agnostic
    # memory_shell_history document type.
    CapabilityPluginSpec(MemoryCapability.SHELL_HISTORY, PlatformFamily.WINDOWS, FRAMEWORK_VOLATILITY3, "windows.consoles", depends_on=(MemoryCapability.IDENTIFICATION,), presentation_family="memory_shell_history"),
)

# ---------------------------------------------------------------------------
# Linux entries -- new. Plugin names verified importable against the
# installed Volatility 3 framework during this sprint's diagnosis
# (app.services.memory.volatility_runner.VOLATILITY_PLUGIN_CLASSES).
# Per-image compatibility (symbols/ISF) is NOT claimed here -- see
# analysis_plan.py, which is the only place allowed to mark a Linux
# capability ELIGIBLE.
# ---------------------------------------------------------------------------

_LINUX: tuple[CapabilityPluginSpec, ...] = (
    # Deliberately no IDENTIFICATION entry for Linux: there is no
    # dedicated "banner only" plugin in this Volatility 3 install
    # (verified: no `linux.banners` module exists), so there is no real,
    # executable plugin to bind here. Platform identification for Linux
    # evidence is already answered by Kairon's own bounded probe
    # (app.services.memory.platform) and surfaced directly on
    # MemoryAnalysisPlan.detected_platform/platform_confidence/
    # platform_signals -- it does not need a MemoryScanRun/
    # MemoryPluginRun entry of its own, and adding a fake plugin name
    # here just to have one would be exactly the "declared support that
    # doesn't exist" this sprint exists to eliminate.
    CapabilityPluginSpec(MemoryCapability.PROCESSES, PlatformFamily.LINUX, FRAMEWORK_VOLATILITY3, "linux.pslist", presentation_family="memory_process"),
    CapabilityPluginSpec(MemoryCapability.PROCESSES, PlatformFamily.LINUX, FRAMEWORK_VOLATILITY3, "linux.pstree", presentation_family="memory_process"),
    CapabilityPluginSpec(MemoryCapability.NETWORK, PlatformFamily.LINUX, FRAMEWORK_VOLATILITY3, "linux.sockstat", presentation_family="memory_network_connection"),
    CapabilityPluginSpec(MemoryCapability.SHELL_HISTORY, PlatformFamily.LINUX, FRAMEWORK_VOLATILITY3, "linux.bash", presentation_family="memory_shell_history"),
)

MEMORY_CAPABILITY_REGISTRY: tuple[CapabilityPluginSpec, ...] = _WINDOWS + _LINUX


def specs_for_platform(platform: PlatformFamily) -> list[CapabilityPluginSpec]:
    """All registry entries declared for this platform, in registry order."""
    return [spec for spec in MEMORY_CAPABILITY_REGISTRY if spec.platform == platform]


def capabilities_for_platform(platform: PlatformFamily) -> list[MemoryCapability]:
    """Distinct capabilities this platform has any registry entry for."""
    seen: list[MemoryCapability] = []
    for spec in specs_for_platform(platform):
        if spec.capability not in seen:
            seen.append(spec.capability)
    return seen


def plugins_for_capability(platform: PlatformFamily, capability: MemoryCapability) -> list[CapabilityPluginSpec]:
    return [spec for spec in MEMORY_CAPABILITY_REGISTRY if spec.platform == platform and spec.capability == capability]


def spec_for_plugin(platform: PlatformFamily, plugin: str) -> CapabilityPluginSpec | None:
    for spec in MEMORY_CAPABILITY_REGISTRY:
        if spec.platform == platform and spec.plugin == plugin:
            return spec
    return None


def resolved_plugins_for_capability(platform: PlatformFamily, capability: MemoryCapability) -> list[str]:
    """Full plugin list for one capability, dependency plugins first.

    e.g. Windows PROCESSES depends_on IDENTIFICATION, so this returns
    ``["windows.info", "windows.pslist", "windows.pstree",
    "windows.cmdline"]`` -- reproducing execution.py's old flat
    ``PROFILE_PLUGINS["processes_basic"]`` list exactly, without either
    module hardcoding the other's plugin names.
    """
    own_specs = plugins_for_capability(platform, capability)
    dep_capabilities: list[MemoryCapability] = []
    for spec in own_specs:
        for dep in spec.depends_on:
            if dep not in dep_capabilities:
                dep_capabilities.append(dep)
    plugins: list[str] = []
    for dep_capability in dep_capabilities:
        for spec in plugins_for_capability(platform, dep_capability):
            if spec.plugin not in plugins:
                plugins.append(spec.plugin)
    for spec in own_specs:
        if spec.plugin not in plugins:
            plugins.append(spec.plugin)
    return plugins
