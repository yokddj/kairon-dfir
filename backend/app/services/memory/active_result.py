"""Centralized active-result resolution for memory analysis.

A single function, :func:`resolve_active_memory_result`, is the
authoritative source for the question: "Which ``MemoryScanRun`` is the
analyst currently looking at for this evidence + family?".

The function is the only place that knows the per-family resolution
rules.  Other endpoints (counts, listings, dashboards) call into
it; they never duplicate the logic.

Per-family rules:

* system_info:       latest completed metadata_only, else latest run
                      that emitted a memory_system_info document.
* processes:         latest completed processes_extended, else
                      processes_basic.  Never mix the two in one view.
* network:           latest completed network_basic (may be unavailable
                      in this runtime).
* modules:           latest completed modules_basic.
* handles:           latest completed handles_basic.
* kernel_modules:    latest completed kernel_basic.
* drivers:           latest completed kernel_basic.
* suspicious_regions: latest completed suspicious_memory.
* raw_observations:  latest run with ``memory_artifact_type = memory_process``
                      or ``memory_artifact_type = memory_system_info``;
                      fallback to any non-failed run.

When the latest attempt of a family failed, the function still
returns the last successful result and flags
``using_fallback = True`` with an explanation in
``selection_reason`` so the UI can show "latest attempt failed,
showing last successful result".
"""
from __future__ import annotations

from typing import Any

from sqlalchemy import desc, func, or_
from sqlalchemy.orm import Session

from app.models.memory import MemoryScanRun


# Per-family resolution preferences.  The ``preferred_profiles`` are
# tried in order; the first profile that has a successful run wins.
# The ``fallback_plugins`` list is the set of plugins the run must
# have executed for the family to be considered available.
FAMILY_RESOLUTION = {
    "system_info": {
        "preferred_profiles": ["metadata_only"],
        "fallback_plugins": ["windows.info"],
        "fallback_doc_types": ["memory_system_info"],
        "evidence_id_required": True,
    },
    "processes": {
        "preferred_profiles": ["processes_extended", "processes_basic"],
        "fallback_doc_types": ["memory_process_entity", "memory_process"],
        "evidence_id_required": True,
    },
    "network": {
        "preferred_profiles": ["network_basic"],
        "fallback_doc_types": ["memory_network_connection"],
        "evidence_id_required": True,
    },
    "modules": {
        "preferred_profiles": ["modules_basic"],
        "fallback_doc_types": ["memory_process_module"],
        "evidence_id_required": True,
    },
    "handles": {
        "preferred_profiles": ["handles_basic"],
        "fallback_doc_types": ["memory_handle"],
        "evidence_id_required": True,
    },
    "kernel_modules": {
        "preferred_profiles": ["kernel_basic"],
        "fallback_doc_types": ["memory_kernel_module"],
        "evidence_id_required": True,
    },
    "drivers": {
        "preferred_profiles": ["kernel_basic"],
        "fallback_doc_types": ["memory_driver"],
        "evidence_id_required": True,
    },
    "suspicious_regions": {
        "preferred_profiles": ["suspicious_memory"],
        "fallback_doc_types": ["memory_suspicious_region"],
        "evidence_id_required": True,
    },
    "raw_observations": {
        "preferred_profiles": [
            "processes_extended",
            "processes_basic",
            "metadata_only",
            "modules_basic",
            "handles_basic",
            "kernel_basic",
            "suspicious_memory",
        ],
        "fallback_doc_types": ["memory_process", "memory_system_info"],
        "evidence_id_required": True,
    },
}


TERMINAL_SUCCESS_STATUSES = {"completed", "completed_with_errors"}


def list_families() -> list[str]:
    return list(FAMILY_RESOLUTION.keys())


def resolve_active_memory_result(
    db: Session,
    *,
    case_id: str,
    evidence_id: str,
    family: str,
    preferred_run_id: str | None = None,
) -> dict[str, Any]:
    """Resolve the active memory scan run for an evidence + family.

    Returns a dict with the active run metadata, the latest attempt,
    and the selection reason.  Never raises for "no run found" - the
    function returns a structured result with ``active_run=None`` and
    an ``analysis_state`` describing the gap.
    """
    if family not in FAMILY_RESOLUTION:
        return {
            "case_id": case_id,
            "evidence_id": evidence_id,
            "artifact_family": family,
            "active_run": None,
            "latest_attempt": None,
            "selection_reason": "unknown_family",
            "using_fallback": False,
            "historical_override": False,
            "total": 0,
            "items": [],
            "analysis_state": "unknown_family",
        }

    rules = FAMILY_RESOLUTION[family]
    if rules.get("evidence_id_required") and not evidence_id:
        return {
            "case_id": case_id,
            "evidence_id": evidence_id,
            "artifact_family": family,
            "active_run": None,
            "latest_attempt": None,
            "selection_reason": "evidence_id_required",
            "using_fallback": False,
            "historical_override": False,
            "total": 0,
            "items": [],
            "analysis_state": "evidence_scope_required",
        }

    base_query = (
        db.query(MemoryScanRun)
        .filter(MemoryScanRun.case_id == case_id)
        .filter(MemoryScanRun.evidence_id == evidence_id)
    )

    # Historical override: validate it is a real run for this evidence.
    if preferred_run_id:
        override_run = base_query.filter(MemoryScanRun.id == preferred_run_id).first()
        if override_run is None:
            return {
                "case_id": case_id,
                "evidence_id": evidence_id,
                "artifact_family": family,
                "active_run": None,
                "latest_attempt": None,
                "selection_reason": "historical_override_rejected",
                "using_fallback": False,
                "historical_override": True,
                "total": 0,
                "items": [],
                "analysis_state": "historical_override_invalid",
            }
        return _build_response(
            case_id=case_id,
            evidence_id=evidence_id,
            family=family,
            active_run=override_run,
            latest_attempt=override_run,
            selection_reason="historical_override",
            using_fallback=False,
            historical_override=True,
        )

    # Latest attempt: any run for this evidence + family, regardless
    # of status.  We iterate the preferred profiles in order so the
    # "latest attempt" is consistent with the family preference.
    latest_attempt = None
    for preferred_profile in rules["preferred_profiles"]:
        candidate = (
            base_query.filter(MemoryScanRun.profile == preferred_profile)
            .order_by(
                desc(MemoryScanRun.completed_at.is_(None)),
                desc(func.coalesce(MemoryScanRun.completed_at, MemoryScanRun.created_at)),
                desc(MemoryScanRun.created_at),
            )
            .first()
        )
        if candidate is not None:
            latest_attempt = candidate
            break

    # Active run: latest successful run for this family.  We iterate
    # the preferred profiles in order and pick the latest successful
    # run for the FIRST profile that has one.  This guarantees that
    # the "processes_extended > processes_basic" rule is enforced:
    # we never return a basic run when an extended run is available,
    # even if the basic run was started more recently.
    active_run = None
    for preferred_profile in rules["preferred_profiles"]:
        candidate = (
            base_query.filter(
                MemoryScanRun.profile == preferred_profile,
                MemoryScanRun.status.in_(list(TERMINAL_SUCCESS_STATUSES)),
            )
            .order_by(
                desc(func.coalesce(MemoryScanRun.completed_at, MemoryScanRun.created_at)),
                desc(MemoryScanRun.created_at),
            )
            .first()
        )
        if candidate is not None:
            active_run = candidate
            break

    using_fallback = False
    selection_reason = "latest_successful"
    if active_run is None and latest_attempt is not None:
        # No successful run for this family.  We do NOT promote the
        # failed run to active.  Return the latest attempt so the UI
        # can show the failure.
        return _build_response(
            case_id=case_id,
            evidence_id=evidence_id,
            family=family,
            active_run=None,
            latest_attempt=latest_attempt,
            selection_reason="no_successful_result",
            using_fallback=False,
            historical_override=False,
        )
    if active_run is None:
        return _build_response(
            case_id=case_id,
            evidence_id=evidence_id,
            family=family,
            active_run=None,
            latest_attempt=None,
            selection_reason="not_analyzed",
            using_fallback=False,
            historical_override=False,
        )

    # Detect fallback: if the active run is not the latest attempt,
    # the latest attempt is a failed run and we kept the last success.
    if latest_attempt is not None and latest_attempt.id != active_run.id:
        if latest_attempt.status not in TERMINAL_SUCCESS_STATUSES:
            using_fallback = True
            selection_reason = "latest_attempt_failed_kept_last_success"

    return _build_response(
        case_id=case_id,
        evidence_id=evidence_id,
        family=family,
        active_run=active_run,
        latest_attempt=latest_attempt or active_run,
        selection_reason=selection_reason,
        using_fallback=using_fallback,
        historical_override=False,
    )


def _build_response(
    *,
    case_id: str,
    evidence_id: str,
    family: str,
    active_run: MemoryScanRun | None,
    latest_attempt: MemoryScanRun | None,
    selection_reason: str,
    using_fallback: bool,
    historical_override: bool,
) -> dict[str, Any]:
    return {
        "case_id": case_id,
        "evidence_id": evidence_id,
        "artifact_family": family,
        "active_run": _serialize_run(active_run) if active_run else None,
        "latest_attempt": _serialize_run(latest_attempt) if latest_attempt else None,
        "selection_reason": selection_reason,
        "using_fallback": using_fallback,
        "historical_override": historical_override,
        "total": 0,
        "items": [],
        "analysis_state": _state_for(active_run, latest_attempt, family),
    }


def _state_for(active_run: MemoryScanRun | None, latest_attempt: MemoryScanRun | None, family: str) -> str:
    if active_run is not None:
        return "completed"
    if latest_attempt is None:
        return "not_analyzed"
    if family == "network":
        return "unavailable"
    return "latest_attempt_failed"


def _serialize_run(run: MemoryScanRun) -> dict[str, Any]:
    return {
        "id": run.id,
        "profile": run.profile,
        "status": run.status,
        "started_at": run.started_at.isoformat() if run.started_at else None,
        "completed_at": run.completed_at.isoformat() if run.completed_at else None,
        "duration_seconds": (run.duration_ms or 0) / 1000.0,
        "plugin_count": run.plugin_count,
        "plugins_completed": run.plugins_completed,
        "plugins_failed": run.plugins_failed,
        "evidence_id": run.evidence_id,
        "case_id": run.case_id,
    }
