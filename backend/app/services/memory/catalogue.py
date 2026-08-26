"""Analysis catalogue for memory images.

Returns the list of all analysis profiles the analyst can run on
an evidence, with availability, est. duration, last status, count,
cost label, and per-plugin capability details. Profiles with partial
plugin availability stay runnable; unavailable plugins are skipped at
execution time with explicit reasons.

This is the single source of truth used by the "Run analysis"
catalogue modal in the UI.

Two families of profiles feed this catalogue, with two different
availability mechanisms:

* The original 8 profiles resolve their plugin list from
  ``execution.PROFILE_PLUGINS`` (a flat, Windows-plugin-named list per
  profile) via ``plan_profile_capability`` -- this path has always been
  platform-blind: it checks whether the named plugins are enabled/
  importable, never whether the evidence's actual detected platform can
  run them.
* A capability-registry-only profile (no ``PROFILE_PLUGINS`` entry, e.g.
  ``shell_history_basic``) has no fixed plugin list to check -- its real
  plugin depends on the evidence's detected platform. For these,
  ``_plan_capability_registry_profile`` below builds this evidence's
  ``MemoryAnalysisPlan`` and resolves the plugin list through
  ``execution.resolve_profile_plugins`` (the same capability_registry
  path used at execution time), so a Linux evidence correctly sees
  ``linux.bash`` as available while a Windows evidence correctly sees
  ``windows.consoles`` as available (both have a registered
  CapabilityPluginSpec for ``MemoryCapability.SHELL_HISTORY``) -- a
  platform with no registered producer at all would instead be gated
  "unavailable" here, never a fabricated plugin binding.
"""
from __future__ import annotations

from typing import Any

from sqlalchemy.orm import Session

from app.core.config import get_settings
from app.models.evidence import Evidence
from app.models.memory import MemoryScanRun
from app.services.memory.analysis_plan import build_memory_analysis_plan
from app.services.memory.capability_registry import resolved_plugins_for_capability
from app.services.memory.execution import PROFILE_CAPABILITY, PROFILE_PLUGINS, resolve_profile_plugins
from app.services.memory.platform import PlatformFamily
from app.services.memory.profile_planning import PLUGIN_AVAILABLE, PLUGIN_DISABLED, PLUGIN_UNKNOWN, _plugin_worker_state, plan_profile_capability
from app.services.memory import profile_planning
from app.services.memory.validation import MemoryExecutionValidationError


# Sprint 3 (Memory Technical Debt Cleanup) audit: network_basic keeps a
# legacy PROFILE_PLUGINS entry (predates Linux support) alongside its
# real capability_registry mapping, so it always took the platform-blind
# branch below and could show Windows plugin names for Linux evidence
# even though real execution (resolve_profile_plugins, unaffected by
# this) already resolves linux.sockstat correctly. Verified this profile
# is safe to force onto the platform-aware path: its Windows-resolved
# plugin set is byte-identical either way (["windows.netscan",
# "windows.netstat"]), so switching changes nothing for Windows evidence
# and only fixes the Linux catalogue display. NOT extended to every
# profile with a capability mapping -- five of the other seven legacy
# profiles (metadata_only, processes_basic, modules_basic, handles_basic,
# kernel_basic) resolve to a DIFFERENT Windows plugin set through
# capability_registry (it additionally includes windows.info), so forcing
# them onto this path would change already-validated Windows catalogue
# behavior for no demonstrated benefit -- exactly what this cleanup must
# not do.
_CAPABILITY_AWARE_DESPITE_LEGACY_PLUGINS = {"network_basic"}


def _supported_os_families(profile: str) -> list[str]:
    """Which platforms genuinely have a registered plugin producer for
    this profile's capability, derived from capability_registry.

    Not hardcoded per profile: PROFILE_CATALOGUE's own static
    "supported_os_families" literal is what drifted stale for
    network_basic (still said Windows-only after Sprint 1 added real
    Linux support) -- this is the actual value returned by the API,
    computed fresh so it can't silently drift again.
    """
    capability = PROFILE_CAPABILITY.get(profile)
    if capability is None:
        return []
    return [
        platform.value
        for platform in (PlatformFamily.WINDOWS, PlatformFamily.LINUX, PlatformFamily.MACOS)
        if resolved_plugins_for_capability(platform, capability)
    ]

# Profiles in stable order.  ``family`` maps to the active-result
# resolver family.  ``plugins`` mirrors the runtime plugin list.
PROFILE_CATALOGUE: list[dict[str, Any]] = [
    {
        "profile": "metadata_only",
        "family": "system_info",
        "title": "System metadata",
        "description": "Capture the windows.info block (OS family, kernel base, architecture) without running plugin logic.",
        "cost_label": "Fast",
        "est_duration_seconds": 20,
        "requires_windows_symbols": True,
        "can_run_without_symbols": True,
        "supported_os_families": ["windows"],
    },
    {
        "profile": "processes_basic",
        "family": "processes",
        "title": "Standard process analysis",
        "description": "Active processes, parent-child relationships and command lines.",
        "cost_label": "Medium",
        "est_duration_seconds": 90,
        "requires_windows_symbols": True,
        "can_run_without_symbols": True,
        "supported_os_families": ["windows"],
    },
    {
        "profile": "processes_extended",
        "family": "processes",
        "title": "Extended Processes",
        "description": "Scanned processes, environment variables, SIDs and privileges.",
        "cost_label": "Medium",
        "est_duration_seconds": 240,
        "requires_windows_symbols": True,
        "can_run_without_symbols": True,
        "supported_os_families": ["windows"],
    },
    {
        "profile": "network_basic",
        "family": "network",
        "title": "Network Connections",
        "description": "Active and historical network endpoints found in memory.",
        "cost_label": "Medium",
        "est_duration_seconds": 90,
        "requires_windows_symbols": True,
        "can_run_without_symbols": True,
        "supported_os_families": ["windows"],
    },
    {
        "profile": "modules_basic",
        "family": "modules",
        "title": "Process modules (DLLs)",
        "description": "Loaded modules per process plus ldrmodule list comparison.",
        "cost_label": "Medium",
        "est_duration_seconds": 120,
        "requires_windows_symbols": True,
        "can_run_without_symbols": True,
        "supported_os_families": ["windows"],
    },
    {
        "profile": "handles_basic",
        "family": "handles",
        "title": "Process handles",
        "description": "Open handles per process (files, registry keys, mutants, sections).",
        "cost_label": "High volume",
        "est_duration_seconds": 1800,
        "requires_windows_symbols": True,
        "can_run_without_symbols": True,
        "supported_os_families": ["windows"],
    },
    {
        "profile": "kernel_basic",
        "family": "kernel_modules",
        "title": "Kernel modules & drivers",
        "description": "Kernel modules and loaded drivers.",
        "cost_label": "Medium",
        "est_duration_seconds": 180,
        "requires_windows_symbols": True,
        "can_run_without_symbols": True,
        "supported_os_families": ["windows"],
    },
    {
        "profile": "suspicious_memory",
        "family": "suspicious_regions",
        "title": "Suspicious Memory",
        "description": "Suspicious executable regions and VAD metadata.",
        "cost_label": "Slow",
        "est_duration_seconds": 1800,
        "requires_windows_symbols": True,
        "can_run_without_symbols": True,
        "supported_os_families": ["windows"],
    },
    {
        "profile": "shell_history_basic",
        "family": "shell_history",
        "title": "Shell History",
        "description": "Recover interactive shell command history from memory when supported by the target platform.",
        # linux.bash scans every bash/sh/dash process's heap for resident
        # history entries -- it carries the same explicit 1800s timeout as
        # the other full-heap/VAD scan profiles (ARTIFACT_PLUGIN_LIMITS in
        # execution.py). "Slow" reflects that real bound, not a benchmark;
        # never label this profile "Fast".
        "cost_label": "Slow",
        "est_duration_seconds": 1800,
        "requires_windows_symbols": False,
        "can_run_without_symbols": True,
        # Both platforms have a real producer (linux.bash / windows.consoles)
        # -- see PROFILE_CAPABILITY in execution.py and
        # MemoryCapability.SHELL_HISTORY. NOTE: this static literal is not
        # what the API actually returns -- ``_supported_os_families()``
        # above recomputes it live from capability_registry, exactly to
        # avoid this literal drifting stale the way network_basic's did.
        "supported_os_families": ["windows", "linux"],
    },
    {
        "profile": "files_basic",
        "family": "files",
        "title": "Files",
        "description": "Browsable, searchable list of file objects Windows currently references in memory (windows.filescan).",
        # windows.filescan walks pool allocations image-wide -- benchmarked
        # under 240s on a real 4GB image (13,191 rows). Matches
        # FILESCAN_TIMEOUT_SECONDS, the same bound the separate on-demand
        # "recover this exact file" action already uses for the identical
        # plugin.
        "cost_label": "Slow",
        "est_duration_seconds": 240,
        "requires_windows_symbols": True,
        "can_run_without_symbols": False,
        # Windows-only producer today -- see PROFILE_CAPABILITY in
        # execution.py and MemoryCapability.FILES. This static literal is
        # not what the API returns; _supported_os_families() recomputes it
        # live from capability_registry (see the shell_history_basic note
        # above for why that matters).
        "supported_os_families": ["windows"],
    },
]


NETWORK_UNAVAILABLE_REASON = (
    "Network analysis is not available in this runtime. "
    "The capability must be probed in the memory-worker process."
)
NETWORK_REQUIRES_VALIDATION_REASON = (
    "Network analysis is available in the worker runtime. "
    "Requirements for this evidence have not been validated yet."
)


def _probe_network_via_worker() -> tuple[bool, str]:
    """Compatibility wrapper for older tests and callers.

    New catalogue rendering uses per-plugin capability records, but the
    network profile is still summarized here for existing monkeypatches.
    """
    plan = plan_profile_capability("network_basic")
    if plan["unknown_plugins"]:
        return True, "Availability will be validated in the memory-worker at execution time."
    available = bool(plan["available_plugins"])
    return available, "importable" if available else NETWORK_UNAVAILABLE_REASON


def _probe_plugins_via_worker(plugins: list[str]) -> dict[str, bool] | None:
    """Compatibility wrapper over the worker capability heartbeat.

    Older tests monkeypatch this seam.  The default implementation no
    longer shells out from the API process; it only reads the same worker
    capability state used by direct scan and run-all planning.
    """
    capability = profile_planning._current_worker_capability()
    if not capability or not isinstance(capability.get("plugins"), dict):
        return None
    result: dict[str, bool] = {}
    for plugin in plugins:
        entry = capability["plugins"].get(plugin)
        if isinstance(entry, dict) and str(entry.get("state") or "").lower() == "available":
            result[plugin] = True
        elif isinstance(entry, dict) and str(entry.get("state") or "").lower() in {"unavailable", "unsupported", "unsupported_by_installed_volatility"}:
            result[plugin] = False
    return result if result else None


def _plan_capability_registry_profile(
    profile: str,
    evidence: Any,
    *,
    worker_capability: dict[str, Any] | None,
) -> dict[str, Any]:
    """``plan_profile_capability()``-shaped result for a profile that has
    no ``PROFILE_PLUGINS`` entry (resolved via capability_registry only).

    Builds this evidence's real ``MemoryAnalysisPlan`` (the same bounded,
    read-only platform probe used at execution time) and resolves the
    profile's plugin list through ``execution.resolve_profile_plugins``,
    so the result reflects the evidence's ACTUAL detected platform instead
    of a fixed Windows plugin list. When the evidence's platform has no
    registered producer for the profile's capability (e.g. Windows for
    shell_history_basic today), ``resolve_profile_plugins`` raises
    ``PROFILE_CAPABILITY_UNAVAILABLE`` -- caught here and turned into an
    empty, ``platform_ineligible`` plugin list rather than propagating,
    so one profile's platform mismatch never breaks the whole catalogue
    listing.
    """
    settings = get_settings()
    plan = build_memory_analysis_plan(evidence)
    try:
        plugin_names = resolve_profile_plugins(profile, plan=plan)
    except MemoryExecutionValidationError:
        plugin_names = []

    allowed = set(settings.allowed_memory_plugins)
    plugins: list[dict[str, str]] = []
    for plugin in plugin_names:
        if plugin not in allowed:
            plugins.append({"plugin": plugin, "state": PLUGIN_DISABLED, "reason": f"{plugin} is disabled by memory plugin configuration."})
            continue
        state, reason = _plugin_worker_state(plugin, worker_capability)
        plugins.append({"plugin": plugin, "state": state, "reason": reason})
    enabled_plugins = [item["plugin"] for item in plugins if item["state"] != PLUGIN_DISABLED]
    available_plugins = [item for item in plugins if item["state"] == PLUGIN_AVAILABLE]
    unknown_plugins = [item for item in plugins if item["state"] == PLUGIN_UNKNOWN]
    return {
        "profile": profile,
        "plugins": plugins,
        "plugin_names": plugin_names,
        "enabled_plugins": enabled_plugins,
        "disabled_plugins": [item for item in plugins if item["state"] == PLUGIN_DISABLED],
        "available_plugins": available_plugins,
        "runnable_plugins": [item for item in plugins if item["state"] in {PLUGIN_AVAILABLE, PLUGIN_UNKNOWN}],
        "has_enabled_plugins": bool(enabled_plugins),
        "available_plugin_count": len(available_plugins) + len(unknown_plugins),
        # Distinct from "no plugins for this profile at all" (which never
        # happens for a real profile) -- this specifically means the
        # evidence's detected platform has no registered producer.
        "platform_ineligible": not plugin_names,
        "detected_platform": plan.detected_platform.value,
    }


def build_analysis_catalogue(
    db: Session,
    *,
    case_id: str,
    evidence_id: str,
) -> list[dict[str, Any]]:
    """Return the analysis-profile catalogue with availability, last status
    and per-profile count for an evidence.

    The function reads ``MemoryScanRun`` for this evidence + profile
    and delegates the per-family count to the unified
    :func:`app.services.memory.counts.get_memory_family_count` so
    that every consumer (catalogue, Overview, landing, run-all plan)
    sees the same number.
    """
    from app.services.memory.counts import get_memory_family_count

    runs_by_profile: dict[str, MemoryScanRun] = {}
    for profile_def in PROFILE_CATALOGUE:
        run = (
            db.query(MemoryScanRun)
            .filter(
                MemoryScanRun.case_id == case_id,
                MemoryScanRun.evidence_id == evidence_id,
                MemoryScanRun.profile == profile_def["profile"],
            )
            .order_by(MemoryScanRun.created_at.desc())
            .first()
        )
        runs_by_profile[profile_def["profile"]] = run

    # linux.bash has no PROFILE_PLUGINS entry (shell_history_basic resolves
    # through capability_registry only -- see module docstring), but its
    # real state still belongs in the worker probe, or it would always
    # report PLUGIN_UNKNOWN even when the worker heartbeat already knows.
    all_plugins = sorted({plugin for plugins in PROFILE_PLUGINS.values() for plugin in plugins} | {"linux.bash"})
    worker_probe = _probe_plugins_via_worker(all_plugins)
    worker_capability = None
    if worker_probe is not None:
        worker_capability = {
            "plugins": {
                plugin: {"state": "available" if available else "unavailable"}
                for plugin, available in worker_probe.items()
            }
        }

    from app.services.memory.symbol_state import GATE_TYPE_AVAILABLE, GATE_TYPE_UNAVAILABLE

    items: list[dict[str, Any]] = []
    evidence: Evidence | None = None
    for profile_def in PROFILE_CATALOGUE:
        profile = profile_def["profile"]
        family = profile_def["family"]
        last_run = runs_by_profile.get(profile)
        last_run_dict = _serialize(last_run) if last_run else None
        if last_run is not None:
            count_payload = get_memory_family_count(
                case_id=case_id,
                evidence_id=evidence_id,
                family=family,
                active_run_id=last_run.id,
                db=db,
            )
            last_count = int(count_payload["total"])
        else:
            last_count = 0
        last_status = last_run.status if last_run else None

        # The gate_type is the single source of truth for the UI:
        # "available" | "blocked_*" | "unavailable".  It is computed
        # only after every per-profile branch has been considered.
        gate_type = GATE_TYPE_AVAILABLE
        available = True
        availability_reason: str | None = None
        legacy_plugin_names = list(PROFILE_PLUGINS.get(profile, []))
        use_capability_aware_path = (
            (not legacy_plugin_names and profile in PROFILE_CAPABILITY)
            or profile in _CAPABILITY_AWARE_DESPITE_LEGACY_PLUGINS
        )
        if use_capability_aware_path:
            # No PROFILE_PLUGINS entry (or a demonstrated-safe override,
            # see _CAPABILITY_AWARE_DESPITE_LEGACY_PLUGINS above) --
            # resolve through the real, platform-aware capability_registry
            # path instead of the platform-blind Windows plugin-name
            # check every other profile uses (see module docstring).
            if evidence is None:
                evidence = db.get(Evidence, evidence_id)
            plan = _plan_capability_registry_profile(profile, evidence, worker_capability=worker_capability) if evidence is not None else {"plugin_names": [], "platform_ineligible": True, "detected_platform": "unknown", "available_plugin_count": 0}
        else:
            plan = plan_profile_capability(profile, worker_capability=worker_capability)
        plugin_names = list(plan["plugin_names"])
        plugin_capabilities = _profile_plugin_capabilities(plugin_names, plan)
        available_plugin_count = int(plan["available_plugin_count"])
        unavailable_plugins = [item for item in plugin_capabilities if item["state"] in {"disabled", "unavailable"}]
        if plan.get("platform_ineligible"):
            gate_type = GATE_TYPE_UNAVAILABLE
            available = False
            availability_reason = f"{profile_def['title']} has no plugin producer for this evidence's detected platform ('{plan.get('detected_platform', 'unknown')}') in this runtime."
        elif plugin_names and available_plugin_count == 0:
            gate_type = GATE_TYPE_UNAVAILABLE
            available = False
            availability_reason = "; ".join(item["reason"] for item in unavailable_plugins[:3]) or "No profile plugins are available."
        elif unavailable_plugins:
            available = True
            availability_reason = f"{available_plugin_count}/{len(plugin_names)} plugins available; unavailable plugins will be skipped."
        # Do not pre-block on symbols or preparation state.  Volatility
        # resolves symbols at plugin execution time and reports the real
        # plugin stderr if resolution fails.
        items.append(
            {
                "profile": profile,
                "family": family,
                "title": profile_def["title"],
                "description": profile_def["description"],
                "cost_label": profile_def["cost_label"],
                "est_duration_seconds": profile_def["est_duration_seconds"],
                "available": available,
                "gate_type": gate_type,
                "availability_reason": availability_reason,
                "last_run": last_run_dict,
                "last_status": last_status,
                "last_count": last_count,
                "requires_windows_symbols": bool(profile_def.get("requires_windows_symbols", False)),
                "can_run_without_symbols": bool(profile_def.get("can_run_without_symbols", False)),
                "supported_os_families": _supported_os_families(profile),
                "plugins": plugin_names,
                "plugin_count": len(plugin_names),
                "available_plugin_count": available_plugin_count,
                "unavailable_plugins": unavailable_plugins,
            }
        )
    return items


def _profile_plugin_capabilities(plugin_names: list[str], plan: dict[str, Any]) -> list[dict[str, str]]:
    by_plugin = {item["plugin"]: item for item in plan.get("plugins", [])}
    return [by_plugin[plugin] for plugin in plugin_names if plugin in by_plugin]


def _serialize(run: MemoryScanRun) -> dict[str, Any]:
    return {
        "id": run.id,
        "profile": run.profile,
        "status": run.status,
        "started_at": run.started_at.isoformat() if run.started_at else None,
        "completed_at": run.completed_at.isoformat() if run.completed_at else None,
        "duration_seconds": (run.duration_ms or 0) / 1000.0,
        "evidence_id": run.evidence_id,
        "case_id": run.case_id,
    }


class MemoryProfileUnavailableError(Exception):
    """Raised when a profile is not available in the current runtime."""

    def __init__(self, profile: str, reason: str):
        self.profile = profile
        self.reason = reason
        super().__init__(f"{profile}: {reason}")
