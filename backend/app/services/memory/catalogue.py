"""Analysis catalogue for memory images.

Returns the list of all 8 analysis profiles the analyst can run on
an evidence, with availability, est. duration, last status, count,
cost label, and per-plugin capability details. Profiles with partial
plugin availability stay runnable; unavailable plugins are skipped at
execution time with explicit reasons.

This is the single source of truth used by the "Run analysis"
catalogue modal in the UI.
"""
from __future__ import annotations

from typing import Any

from sqlalchemy.orm import Session

from app.core.config import get_settings
from app.models.memory import MemoryScanRun
from app.services.memory.execution import PROFILE_PLUGINS
from app.services.memory.profile_planning import plan_profile_capability
from app.services.memory import profile_planning


# 8 profiles in stable order.  ``family`` maps to the active-result
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


def build_analysis_catalogue(
    db: Session,
    *,
    case_id: str,
    evidence_id: str,
) -> list[dict[str, Any]]:
    """Return the 8-profile catalogue with availability, last status
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

    all_plugins = sorted({plugin for plugins in PROFILE_PLUGINS.values() for plugin in plugins})
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
        plugin_names = list(PROFILE_PLUGINS.get(profile, []))
        plan = plan_profile_capability(profile, worker_capability=worker_capability)
        plugin_capabilities = _profile_plugin_capabilities(plugin_names, plan)
        available_plugin_count = int(plan["available_plugin_count"])
        unavailable_plugins = [item for item in plugin_capabilities if item["state"] in {"disabled", "unavailable"}]
        if plugin_names and available_plugin_count == 0:
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
                "supported_os_families": list(profile_def.get("supported_os_families", [])),
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
