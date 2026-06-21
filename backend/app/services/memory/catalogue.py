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

from dataclasses import dataclass
from typing import Any

from sqlalchemy.orm import Session

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
    },
    {
        "profile": "processes_basic",
        "family": "processes",
        "title": "Standard process analysis",
        "description": "Active processes, parent-child relationships and command lines.",
        "cost_label": "Medium",
        "est_duration_seconds": 90,
    },
    {
        "profile": "processes_extended",
        "family": "processes",
        "title": "Extended process analysis",
        "description": "Adds memory scanning for terminated or unlinked processes. Builds on the standard analysis.",
        "cost_label": "Medium",
        "est_duration_seconds": 240,
    },
    {
        "profile": "network_basic",
        "family": "network",
        "title": "Network connections",
        "description": "Active and recent TCP/UDP endpoints.",
        "cost_label": "Medium",
        "est_duration_seconds": 90,
    },
    {
        "profile": "modules_basic",
        "family": "modules",
        "title": "Process modules (DLLs)",
        "description": "Loaded modules per process plus ldrmodule list comparison.",
        "cost_label": "Medium",
        "est_duration_seconds": 120,
    },
    {
        "profile": "handles_basic",
        "family": "handles",
        "title": "Process handles",
        "description": "Open handles per process (files, registry keys, mutants, sections).",
        "cost_label": "High volume",
        "est_duration_seconds": 1800,
    },
    {
        "profile": "kernel_basic",
        "family": "kernel_modules",
        "title": "Kernel modules & drivers",
        "description": "Kernel modules and loaded drivers.",
        "cost_label": "Medium",
        "est_duration_seconds": 180,
    },
    {
        "profile": "suspicious_memory",
        "family": "suspicious_regions",
        "title": "Suspicious memory regions",
        "description": "RX/RWX memory regions with no mapped file (windows.malfind).",
        "cost_label": "Slow",
        "est_duration_seconds": 1800,
    },
]


NETWORK_UNAVAILABLE_REASON = (
    "No compatible Windows network plugin is available in the installed Volatility runtime."
)


def build_analysis_catalogue(
    db: Session,
    *,
    case_id: str,
    evidence_id: str,
) -> list[dict[str, Any]]:
    """Return the 8-profile catalogue with availability, last status
    and per-profile count for an evidence.

    The function reads ``MemoryScanRun`` for this evidence + profile
    and joins with the run's ``MemoryArtifactSummary`` to obtain the
    last artifact count.
    """
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

    network_unavailable = not network_basic_available()[0]

    items: list[dict[str, Any]] = []
    for profile_def in PROFILE_CATALOGUE:
        profile = profile_def["profile"]
        last_run = runs_by_profile.get(profile)
        last_run_dict = _serialize(last_run) if last_run else None
        last_count = _safe_count(db, last_run) if last_run else 0
        last_status = last_run.status if last_run else None

        is_network = profile == "network_basic"
        available = True
        availability_reason: str | None = None
        if is_network and network_unavailable:
            available = False
            availability_reason = NETWORK_UNAVAILABLE_REASON

        items.append(
            {
                "profile": profile,
                "family": profile_def["family"],
                "title": profile_def["title"],
                "description": profile_def["description"],
                "cost_label": profile_def["cost_label"],
                "est_duration_seconds": profile_def["est_duration_seconds"],
                "available": available,
                "availability_reason": availability_reason,
                "last_run": last_run_dict,
                "last_status": last_status,
                "last_count": last_count,
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


def _safe_count(db: Session, run: MemoryScanRun) -> int:
    """Return the last artifact count for the run by querying the
    ``MemoryArtifactSummary`` table for any summary row matching the
    run.  Falls back to 0 when the table is empty.
    """
    from app.models.memory import MemoryArtifactSummary

    summaries = (
        db.query(MemoryArtifactSummary)
        .filter(MemoryArtifactSummary.memory_run_id == run.id)
        .all()
    )
    if not summaries:
        return 0
    total = 0
    for s in summaries:
        meta = s.metadata_json or {}
        total += int(meta.get("accepted_count", 0) or 0) or int(getattr(s, "count", 0) or 0)
    return int(total)


class MemoryProfileUnavailableError(Exception):
    """Raised when a profile is not available in the current runtime."""

    def __init__(self, profile: str, reason: str):
        self.profile = profile
        self.reason = reason
        super().__init__(f"{profile}: {reason}")
