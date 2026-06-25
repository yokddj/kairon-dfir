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

The function also returns the real per-family document count and
the paginated items (when an active run exists).  The frontend
uses this data directly instead of issuing a second round-trip
with the global default run.  The analysis state is one of:

* ``not_analyzed``        - no compatible successful run for this family.
* ``analyzed_empty``      - compatible run completed with zero rows.
* ``analyzed_with_results`` - compatible run completed with rows.
* ``failed``              - latest attempt failed; no successful result.
* ``partial``             - latest attempt is partial / has plugin failures.
* ``unavailable``         - family is unavailable in this runtime
                            (e.g. network plugin not installed).
* ``unknown_family``      - family name is not a recognised value.
"""
from __future__ import annotations

import logging
from typing import Any

from sqlalchemy import desc, func, or_
from sqlalchemy.orm import Session

from app.models.memory import MemoryScanRun

logger = logging.getLogger(__name__)


# Maximum page size for items returned by the active-result endpoint.
# The endpoint is the single canonical family-level query for the
# UI; bounding the page size keeps the OpenSearch round-trip
# predictable and prevents accidental fetches of very large
# result sets (e.g. all 97k handles) into a single payload.
_ACTIVE_RESULT_MAX_PAGE_SIZE = 200


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


# Profiles that REQUIRE canonical materialization to be considered
# usable as the active processes result.  These profiles produce raw
# observations that must be deduplicated into canonical entities.
_CANONICAL_REQUIRED_PROFILES = frozenset({"processes_extended", "processes_basic"})


def _is_canonical_usable(run: MemoryScanRun) -> bool:
    """Return True when ``run`` has a completed canonical materialization
    with at least one entity.

    For profiles that produce raw observations (``processes_extended``,
    ``processes_basic``), the run is usable only when its materialization
    status is ``completed`` AND its canonical entity count is > 0.
    A run that has raw observations but no canonical entities (status
    ``not_required``, ``pending``, ``running`` or ``failed``) is NEVER
    eligible as the active result.

    For other profiles (metadata_only, handles_basic, modules_basic,
    kernel_basic, suspicious_memory, network_basic) the materialization
    status is ``not_required`` and the run is usable when the run itself
    reached a terminal successful state.
    """
    status = (getattr(run, "canonical_materialization_status", None) or "not_required")
    if run.profile in _CANONICAL_REQUIRED_PROFILES:
        if status != "completed":
            return False
        return int(getattr(run, "canonical_entity_count", 0) or 0) > 0
    if status == "not_required":
        return True
    if status != "completed":
        return False
    return int(getattr(run, "canonical_entity_count", 0) or 0) > 0


def list_families() -> list[str]:
    return list(FAMILY_RESOLUTION.keys())


def resolve_active_memory_result(
    db: Session,
    *,
    case_id: str,
    evidence_id: str,
    family: str,
    preferred_run_id: str | None = None,
    page: int = 1,
    page_size: int = 50,
    filters: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Resolve the active memory scan run for an evidence + family.

    Returns a dict with the active run metadata, the latest attempt,
    the selection reason, the real per-family total count, the
    paginated items, and a truthful analysis state.  Never raises
    for "no run found" - the function returns a structured result
    with ``active_run=None`` and an ``analysis_state`` describing
    the gap.
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
            "page": page,
            "page_size": min(max(int(page_size or 50), 1), _ACTIVE_RESULT_MAX_PAGE_SIZE),
            "count_source": None,
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
            "page": page,
            "page_size": min(max(int(page_size or 50), 1), _ACTIVE_RESULT_MAX_PAGE_SIZE),
            "count_source": None,
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
                "page": page,
                "page_size": min(max(int(page_size or 50), 1), _ACTIVE_RESULT_MAX_PAGE_SIZE),
                "count_source": None,
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
            page=page,
            page_size=page_size,
            filters=filters,
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
    # USABLE run for the FIRST profile that has one.  This guarantees
    # that the "processes_extended > processes_basic" rule is enforced:
    # we never return a basic run when an extended run is available,
    # even if the basic run was started more recently.
    #
    # The processes family additionally requires the run to have a
    # completed canonical materialization with at least one entity.
    # A run that has raw observations but no canonical entities is
    # NEVER promoted to active; the previous usable run is preserved.
    # We therefore iterate ALL runs for the profile (newest first) and
    # pick the first one that is canonically usable.
    requires_canonical = family in {"processes"}
    active_run = None
    for preferred_profile in rules["preferred_profiles"]:
        candidates = (
            base_query.filter(
                MemoryScanRun.profile == preferred_profile,
                MemoryScanRun.status.in_(list(TERMINAL_SUCCESS_STATUSES)),
            )
            .order_by(
                desc(func.coalesce(MemoryScanRun.completed_at, MemoryScanRun.created_at)),
                desc(MemoryScanRun.created_at),
            )
            .all()
        )
        if not candidates:
            continue
        for candidate in candidates:
            if requires_canonical and not _is_canonical_usable(candidate):
                continue
            active_run = candidate
            break
        if active_run is not None:
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
            page=page,
            page_size=page_size,
            filters=filters,
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
            page=page,
            page_size=page_size,
            filters=filters,
        )

    # Detect fallback: if the active run is not the latest attempt,
    # the latest attempt is a failed run and we kept the last success.
    if latest_attempt is not None and latest_attempt.id != active_run.id:
        if latest_attempt.status not in TERMINAL_SUCCESS_STATUSES:
            using_fallback = True
            selection_reason = "latest_attempt_failed_kept_last_success"
        elif requires_canonical and not _is_canonical_usable(latest_attempt):
            # Latest attempt reached a terminal status but its
            # canonical materialization did NOT complete.  The active
            # run is the previous usable canonical result.
            using_fallback = True
            selection_reason = "latest_attempt_materialization_failed_kept_last_usable_canonical"

    return _build_response(
        case_id=case_id,
        evidence_id=evidence_id,
        family=family,
        active_run=active_run,
        latest_attempt=latest_attempt or active_run,
        selection_reason=selection_reason,
        using_fallback=using_fallback,
        historical_override=False,
        page=page,
        page_size=page_size,
        filters=filters,
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
    page: int = 1,
    page_size: int = 50,
    filters: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Build the canonical family response.

    When ``active_run`` is set, the function asks the canonical
    per-family counter for the real total and the artifact list
    for the paginated items.  When ``active_run`` is ``None`` the
    family is ``not_analyzed`` and the totals/items remain empty
    without hitting OpenSearch at all.
    """
    base = {
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
        "page": page,
        "page_size": page_size,
        "count_source": None,
        "analysis_state": "not_analyzed",
    }
    if active_run is None:
        base["analysis_state"] = _state_for(active_run, latest_attempt, family)
        return base

    counts = _family_count(
        case_id=case_id,
        evidence_id=evidence_id,
        family=family,
        active_run=active_run,
    )
    base["total"] = int(counts["total"])
    base["count_source"] = counts.get("count_source")
    bounded_page_size = min(max(int(page_size or 50), 1), _ACTIVE_RESULT_MAX_PAGE_SIZE)
    items, items_source = _family_items(
        case_id=case_id,
        evidence_id=evidence_id,
        family=family,
        active_run=active_run,
        page=page,
        page_size=bounded_page_size,
        filters=filters,
    )
    base["items"] = items
    base["page"] = page
    base["page_size"] = bounded_page_size
    if counts.get("count_source") == "summary_fallback" and items_source == "summary_fallback":
        base["count_source"] = "summary_fallback"
    elif items_source == "summary_fallback":
        base["count_source"] = items_source
    base["analysis_state"] = _state_for(active_run, latest_attempt, family, base["total"])
    return base


def _state_for(
    active_run: MemoryScanRun | None,
    latest_attempt: MemoryScanRun | None,
    family: str,
    total: int = 0,
) -> str:
    """Return the truthful analysis state for a family.

    The function distinguishes:

    * no compatible run yet (not_analyzed / unknown_family);
    * compatible run finished with rows (analyzed_with_results);
    * compatible run finished with zero rows (analyzed_empty);
    * compatible run finished but with partial / failed plugins (partial);
    * latest attempt failed with no usable fallback (failed);
    * network family with no plugin available (unavailable).
    """
    if active_run is not None:
        if total > 0:
            base = "analyzed_with_results"
        else:
            base = "analyzed_empty"
        if _run_has_partial_failures(active_run):
            return "partial"
        return base
    if latest_attempt is None:
        return "not_analyzed"
    if family == "network":
        return "unavailable"
    return "failed"


def _run_has_partial_failures(run: MemoryScanRun) -> bool:
    if run.status == "completed_with_errors":
        return True
    if (run.plugins_failed or 0) > 0:
        return True
    return False


def _family_count(
    *,
    case_id: str,
    evidence_id: str,
    family: str,
    active_run: MemoryScanRun,
) -> dict[str, Any]:
    """Return the canonical per-family count for the active run.

    The function delegates to
    :func:`app.services.memory.counts.get_memory_family_count` so the
    counter, the catalogue, the landing, and the active-result
    endpoint can never disagree about the size of a family.
    """
    from app.services.memory.counts import get_memory_family_count

    payload = get_memory_family_count(
        case_id=case_id,
        evidence_id=evidence_id,
        family=family,
        active_run_id=str(active_run.id),
    )
    return payload


def _family_items(
    *,
    case_id: str,
    evidence_id: str,
    family: str,
    active_run: MemoryScanRun,
    page: int,
    page_size: int,
    filters: dict[str, Any] | None,
) -> tuple[list[dict[str, Any]], str]:
    """Return the paginated items for the active run, when the family
    has a corresponding OpenSearch document type.

    For families that do not have a document type in the canonical
    index (e.g. ``system_info``, ``raw_observations``) the function
    returns an empty list and the count is the only data the UI
    needs to display.
    """
    from app.services.memory.counts import FAMILY_TO_DOCUMENT_TYPE
    from app.services.memory.artifact_indexing import (
        search_artifact_documents,
    )

    if family not in FAMILY_TO_DOCUMENT_TYPE:
        return [], "not_applicable"
    document_type = FAMILY_TO_DOCUMENT_TYPE[family]
    try:
        payload = search_artifact_documents(
            case_id,
            document_type=document_type,
            run_id=str(active_run.id),
            evidence_id=evidence_id,
            page=page,
            page_size=page_size,
            filters=filters,
        )
        return list(payload.get("items", [])), "opensearch"
    except Exception as exc:  # noqa: BLE001
        logger.warning(
            "active-result items fallback: case=%s family=%s run=%s: %s",
            case_id, family, active_run.id, exc,
        )
        return _summary_items(
            case_id=case_id,
            evidence_id=evidence_id,
            family=family,
            active_run=active_run,
        )


def _summary_items(
    *,
    case_id: str,
    evidence_id: str,
    family: str,
    active_run: MemoryScanRun,
) -> tuple[list[dict[str, Any]], str]:
    """Fallback: return items from the ``MemoryArtifactSummary`` table.

    The summary table does not store the underlying rows, only the
    per-family count.  When OpenSearch is unavailable we surface the
    count alone and the UI can show "analyzed_empty" or
    "analyzed_with_results" with the count number.
    """
    return [], "summary_fallback"


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
        "canonical_materialization_status": getattr(
            run, "canonical_materialization_status", "not_required"
        ),
        "canonical_entity_count": int(
            getattr(run, "canonical_entity_count", 0) or 0
        ),
        "canonical_root_count": int(
            getattr(run, "canonical_root_count", 0) or 0
        ),
        "canonical_orphan_count": int(
            getattr(run, "canonical_orphan_count", 0) or 0
        ),
        "canonical_scan_only_count": int(
            getattr(run, "canonical_scan_only_count", 0) or 0
        ),
    }
