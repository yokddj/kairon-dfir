"""Analysis catalogue for memory images.

Returns the list of all 8 analysis profiles the analyst can run on
an evidence, with availability, est. duration, last status, count
and a cost label (Fast / Medium / Slow / High volume).  The network
profile is always rendered as Unavailable in the current runtime
(volatility 3.28.0 is missing ``windows.netscan`` /
``windows.netstat``).

This is the single source of truth used by the "Run analysis"
catalogue modal in the UI.
"""
from __future__ import annotations

import ast
import subprocess
from dataclasses import dataclass
from typing import Any

from sqlalchemy.orm import Session

from app.core.config import get_settings
from app.models.memory import MemoryScanRun
from app.services.memory.volatility_runner import network_basic_available


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
        "can_run_without_symbols": False,
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
        "can_run_without_symbols": False,
        "supported_os_families": ["windows"],
    },
    {
        "profile": "processes_extended",
        "family": "processes",
        "title": "Extended process analysis",
        "description": "Adds memory scanning for terminated or unlinked processes. Builds on the standard analysis.",
        "cost_label": "Medium",
        "est_duration_seconds": 240,
        "requires_windows_symbols": True,
        "can_run_without_symbols": False,
        "supported_os_families": ["windows"],
    },
    {
        "profile": "network_basic",
        "family": "network",
        "title": "Network connections",
        "description": "Active and recent TCP/UDP endpoints.",
        "cost_label": "Medium",
        "est_duration_seconds": 90,
        "requires_windows_symbols": True,
        "can_run_without_symbols": False,
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
        "can_run_without_symbols": False,
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
        "can_run_without_symbols": False,
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
        "can_run_without_symbols": False,
        "supported_os_families": ["windows"],
    },
    {
        "profile": "suspicious_memory",
        "family": "suspicious_regions",
        "title": "Suspicious memory regions",
        "description": "RX/RWX memory regions with no mapped file (windows.malfind).",
        "cost_label": "Slow",
        "est_duration_seconds": 1800,
        "requires_windows_symbols": True,
        "can_run_without_symbols": False,
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
    """Ask the memory-worker process for its network capability.

    The API process does not install volatility3.  Calling
    :func:`network_basic_available` from the API process would
    always return ``absent_in_runtime`` regardless of what the
    worker can actually do.  Instead we shell out to the worker
    container (or fall back to the in-process probe when the
    worker is unreachable).

    The probe is read-only and bounded.
    """
    settings = get_settings()
    try:
        # Re-use the same Docker invocation the backend uses to
        # reach the worker.  ``docker exec`` is the contract the
        # backend already has with the worker; no new channels.
        result = subprocess.run(
            [
                "docker", "exec",
                settings.memory_worker_container_name or "dfir_app-memory-worker-1",
                "python3", "-c",
                "from app.services.memory.volatility_runner import network_basic_available; "
                "import sys; r = network_basic_available(); sys.stdout.write(repr(r))",
            ],
            capture_output=True, text=True, timeout=20,
        )
    except Exception as exc:  # noqa: BLE001
        return False, f"Could not probe memory-worker: {exc}"
    if result.returncode != 0:
        return False, (
            f"Memory-worker probe failed: {result.stderr.strip()[:200] or 'unknown error'}"
        )
    try:
        available, explanation = ast.literal_eval(result.stdout.strip())
    except Exception as exc:  # noqa: BLE001
        return False, f"Could not parse worker probe output: {exc}"
    return bool(available), str(explanation)


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

    # The API process does not install volatility3.  Probe the
    # memory-worker instead so the catalogue reflects the actual
    # worker runtime, not the API's own import graph.
    network_available, network_explanation = _probe_network_via_worker()
    network_state = "available" if network_available else "unavailable"

    # Per-evidence symbol readiness.  Profiles that require
    # Windows symbols must be blocked when the exact required
    # symbol is not cached for THIS evidence.  The metadata_only
    # profile is also blocked; the previous sprint allowed a single
    # attempt to probe the requirement, but the analyst is much
    # better served by an explicit "Probe symbols" step in the UI.
    from app.services.memory.symbol_state import (
        STATE_CACHED,
        evidence_symbol_state,
        gate_type_from_state,
        GATE_TYPE_AVAILABLE,
        GATE_TYPE_BLOCKED_SYMBOL_PROBE,
        GATE_TYPE_BLOCKED_SYMBOLS_MISSING,
        GATE_TYPE_BLOCKED_ACQUISITION_PENDING,
        GATE_TYPE_UNAVAILABLE,
    )

    symbol_state_obj = evidence_symbol_state(
        db,
        case_id=case_id,
        evidence_id=evidence_id,
        acquisition_gate_available=False,
    )
    symbol_status = symbol_state_obj.state
    symbol_blocker = symbol_state_obj.blocker
    symbols_ok = symbol_status == STATE_CACHED

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

        is_network = profile == "network_basic"
        # The gate_type is the single source of truth for the UI:
        # "available" | "blocked_*" | "unavailable".  It is computed
        # only after every per-profile branch has been considered.
        gate_type = GATE_TYPE_AVAILABLE
        available = True
        availability_reason: str | None = None
        # Network gate: a profile that requires a missing network
        # plugin is truly unavailable; this wins over the symbol gate
        # because the symbol gate would otherwise be misleading
        # (the symbol work is moot without the plugin).
        if is_network and network_state == "unavailable":
            gate_type = GATE_TYPE_UNAVAILABLE
            available = False
            availability_reason = NETWORK_UNAVAILABLE_REASON
        elif is_network and network_available:
            # Plugin is importable in the memory-worker runtime.  The
            # backend process itself does not probe the plugin; the
            # frontend should display "Available · Not analyzed"
            # until the first analysis actually runs.
            gate_type = GATE_TYPE_AVAILABLE
            available = True
            availability_reason = "Available · Requirements not yet validated"
        # Symbol gating.  Profiles that require Windows symbols are
        # blocked (NOT marked unavailable) when the exact required
        # symbol is missing for this evidence.  ``Unavailable`` is
        # reserved for plugin absence, runtime issues and OS/arch
        # mismatches.  When the profile is already marked
        # ``unavailable`` by the network branch above, we keep that
        # verdict; the symbol check is a no-op.
        if profile_def.get("requires_windows_symbols") and not symbols_ok and gate_type != GATE_TYPE_UNAVAILABLE:
            available = False
            symbol_gate = gate_type_from_state(symbol_status)
            if symbol_gate in {GATE_TYPE_BLOCKED_SYMBOLS_MISSING, GATE_TYPE_BLOCKED_SYMBOL_PROBE, GATE_TYPE_BLOCKED_ACQUISITION_PENDING}:
                gate_type = symbol_gate
            else:
                # failed, incompatible, unsupported, etc.
                gate_type = GATE_TYPE_UNAVAILABLE
            if symbol_state_obj.requirement is None:
                availability_reason = (
                    "Windows symbol requirement for this evidence has not "
                    "been identified yet. Probe the symbol requirements "
                    "before running this profile."
                )
            else:
                availability_reason = (
                    f"Symbols for this evidence are not cached "
                    f"(state: {symbol_status.replace('_', ' ')}). "
                    f"{symbol_blocker or ''}"
                ).strip()
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
            }
        )
    return items


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
