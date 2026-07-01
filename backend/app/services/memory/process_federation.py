"""Federated process context resolver.

Resolves the latest compatible processes_basic and processes_extended
runs for a given Evidence, producing a unified process analysis context
that merges observations from both profiles transparently.
"""

from __future__ import annotations

from typing import Any

from sqlalchemy.orm import Session
import math


def resolve_federated_process_context(
    db: Session,
    *,
    case_id: str,
    evidence_id: str,
) -> dict[str, Any]:
    """Resolve the best compatible process runs for one Evidence.

    Returns a dict with basic_run_id, extended_run_id, contributing_runs,
    compatibility status, and resolution metadata. Falls back to partial
    availability when only one family is complete.
    """
    from app.models.memory import MemoryScanRun

    basic = (
        db.query(MemoryScanRun)
        .filter(
            MemoryScanRun.case_id == case_id,
            MemoryScanRun.evidence_id == evidence_id,
            MemoryScanRun.profile == "processes_basic",
            MemoryScanRun.status.in_(["completed", "completed_with_errors"]),
            MemoryScanRun.canonical_materialization_status == "completed",
            MemoryScanRun.canonical_entity_count > 0,
        )
        .order_by(MemoryScanRun.completed_at.desc().nullslast(), MemoryScanRun.created_at.desc())
        .first()
    )

    extended = (
        db.query(MemoryScanRun)
        .filter(
            MemoryScanRun.case_id == case_id,
            MemoryScanRun.evidence_id == evidence_id,
            MemoryScanRun.profile == "processes_extended",
            MemoryScanRun.status.in_(["completed", "completed_with_errors"]),
            MemoryScanRun.canonical_materialization_status == "completed",
            MemoryScanRun.canonical_entity_count > 0,
        )
        .order_by(MemoryScanRun.completed_at.desc().nullslast(), MemoryScanRun.created_at.desc())
        .first()
    )

    contributing: list[dict[str, Any]] = []
    basic_id = basic.id if basic else None
    extended_id = extended.id if extended else None

    if basic:
        contributing.append({
            "run_id": basic.id,
            "profile": "processes_basic",
            "completed_at": basic.completed_at.isoformat() if basic.completed_at else None,
            "status": basic.status,
            "entity_count": basic.canonical_entity_count,
        })
    if extended:
        contributing.append({
            "run_id": extended.id,
            "profile": "processes_extended",
            "completed_at": extended.completed_at.isoformat() if extended.completed_at else None,
            "status": extended.status,
            "entity_count": extended.canonical_entity_count,
        })

    if basic_id and extended_id:
        compatibility = "compatible"
        resolution = "both_successful"
    elif basic_id and not extended_id:
        compatibility = "partial"
        resolution = "basic_only"
    elif extended_id and not basic_id:
        compatibility = "partial"
        resolution = "extended_only"
    else:
        compatibility = "unavailable"
        resolution = "no_completed_runs"

    return {
        "evidence_id": evidence_id,
        "basic_run_id": basic_id,
        "extended_run_id": extended_id,
        "primary_run_id": basic_id or extended_id,
        "contributing_runs": contributing,
        "compatibility": compatibility,
        "resolution": resolution,
        "topology_source": "processes_basic" if basic_id else None,
        "command_line_source": "processes_basic" if basic_id else None,
        "enrichment_available": extended_id is not None,
    }


def fetch_federated_process_entities(
    case_id: str,
    *,
    basic_run_id: str | None,
    extended_run_id: str | None,
    evidence_id: str | None = None,
    pid: int | None = None,
    process_name: str | None = None,
    page: int = 1,
    page_size: int = 50,
) -> dict[str, Any]:
    """Fetch and merge canonical process entities from both runs.

    Entities are merged by PID + creation time identity.  The basic run's
    pslist/pstree data takes precedence for name/ppid/create_time, but
    psscan observations from the extended run enrich visibility.
    """
    from app.services.memory.process_entities import fetch_canonical_entities
    import hashlib

    run_ids = [r for r in [basic_run_id, extended_run_id] if r]
    if not run_ids:
        return {"items": [], "total": 0, "page": page, "page_size": page_size}

    basic_entities: dict[str, dict[str, Any]] = {}
    extended_entities: dict[str, dict[str, Any]] = {}

    if basic_run_id:
        basic_result = fetch_canonical_entities(
            case_id, run_id=basic_run_id,
            pid=pid, process_name=process_name,
            page=1, page_size=50000,
        )
        for ent in basic_result.get("items", []):
            key = _entity_merge_key(ent)
            basic_entities[key] = ent

    if extended_run_id:
        extended_result = fetch_canonical_entities(
            case_id, run_id=extended_run_id,
            pid=pid, process_name=process_name,
            page=1, page_size=50000,
        )
        for ent in extended_result.get("items", []):
            key = _entity_merge_key(ent)
            extended_entities[key] = ent

    merged: dict[str, dict[str, Any]] = {}
    all_keys = set(basic_entities.keys()) | set(extended_entities.keys())

    for key in all_keys:
        basic = basic_entities.get(key)
        extended = extended_entities.get(key)
        if basic and extended:
            merged[key] = _merge_entities(basic, extended, basic_run_id, extended_run_id)
        elif basic:
            merged[key] = _format_entity(basic, basic_run_id, None)
        elif extended:
            merged[key] = _format_entity(extended, None, extended_run_id)

    items = sorted(merged.values(), key=lambda e: e.get("process", {}).get("pid", 0))
    total = len(items)
    start = (page - 1) * page_size
    paged = items[start:start + page_size]

    return {
        "items": paged,
        "total": total,
        "page": page,
        "page_size": page_size,
        "federated": True,
        "basic_run_id": basic_run_id,
        "extended_run_id": extended_run_id,
    }


def _entity_merge_key(entity: dict[str, Any]) -> str:
    """A stable identity key: PID. Handles PID reuse by using entity_id as fallback."""
    proc = entity.get("process", {})
    pid = proc.get("pid", 0)
    return f"pid:{pid}"


def _merge_entities(
    basic: dict[str, Any], extended: dict[str, Any],
    basic_run_id: str | None, extended_run_id: str | None,
) -> dict[str, Any]:
    """Merge two entities representing the same process incarnation.

    Basic run (pslist/pstree) takes precedence for identity fields.
    Extended run (psscan) enriches visibility.
    """
    bp = basic.get("process", {})
    ep = extended.get("process", {})

    merged_proc = {
        "pid": bp.get("pid") or ep.get("pid"),
        "ppid": bp.get("ppid") or ep.get("ppid"),
        "name": bp.get("name") or ep.get("name"),
        "command_line": bp.get("command_line") or ep.get("command_line"),
        "create_time": bp.get("create_time") or ep.get("create_time"),
        "exit_time": bp.get("exit_time") or ep.get("exit_time"),
        "session_id": bp.get("session_id", ep.get("session_id")),
        "wow64": bp.get("wow64", ep.get("wow64")),
    }

    b_vis = basic.get("visibility", {})
    e_vis = extended.get("visibility", {})
    merged_vis = {
        "listed": bool(b_vis.get("listed") or e_vis.get("listed")),
        "scan_only": bool(e_vis.get("scan_only") or b_vis.get("scan_only")),
        "terminated": bool(b_vis.get("terminated") or e_vis.get("terminated")),
        "hidden_candidate": bool(e_vis.get("hidden_candidate") or b_vis.get("hidden_candidate")),
        "unknown": bool(e_vis.get("unknown") or b_vis.get("unknown")),
    }

    merged_sources = sorted(set(
        basic.get("source_plugins", []) + extended.get("source_plugins", []),
    ))
    merged_source_plugins = sorted(set(
        basic.get("sources", []) + extended.get("sources", []),
    ))

    entity_id = basic.get("process_entity_id") or extended.get("process_entity_id")

    return {
        "process_entity_id": str(entity_id or ""),
        "process": merged_proc,
        "visibility": merged_vis,
        "source_plugins": merged_sources,
        "sources": merged_source_plugins,
        "contributing_run_ids": [r for r in [basic_run_id, extended_run_id] if r],
        "federated": True,
    }


def _format_entity(
    entity: dict[str, Any], basic_run_id: str | None, extended_run_id: str | None,
) -> dict[str, Any]:
    return {
        "process_entity_id": entity.get("process_entity_id", ""),
        "process": entity.get("process", {}),
        "visibility": entity.get("visibility", {}),
        "source_plugins": entity.get("source_plugins", entity.get("sources", [])),
        "sources": entity.get("sources", entity.get("source_plugins", [])),
        "contributing_run_ids": [r for r in [basic_run_id, extended_run_id] if r],
        "federated": True,
    }
