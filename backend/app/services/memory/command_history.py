"""Command-line history service.

Builds a chronological list of observed process command lines from
normalized canonical process entities and command-line observations.
"""

from __future__ import annotations

import re
from typing import Any

from app.core.database import SessionLocal
from app.models.memory import MemoryScanRun
from app.services.memory.process_entities import fetch_canonical_entities


_NUMBER = re.compile(r"\d+")


def _command_key(command_line: str) -> str:
    # Same command up to whitespace, letter case (Windows paths ignore case)
    # and numbers: instances of one program that differ only in a worker
    # index, PID, session or port ("[kworker/0:1]", "-ServerName:...{n}")
    # are one row with their count.
    return _NUMBER.sub("#", " ".join(command_line.split()).casefold())


def group_identical_command_lines(items: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Collapse command lines that are the same but for numbers into one row
    each (keeping the first as its example, and how many distinct variants
    there were), with how many processes ran it, the PIDs, process names and
    first/last start. The ones run fewest times come first: a command line
    seen once stands out from dozens of service hosts or kernel workers.
    Nothing is dropped."""
    groups: dict[str, dict[str, Any]] = {}
    for item in items:
        key = _command_key(item["command_line"])
        group = groups.get(key)
        if group is None:
            group = groups[key] = {**item, "count": 0, "variants": 0, "pids": [], "process_names": [], "first_start": None, "last_start": None, "_seen": set()}
        group["count"] += 1
        exact = " ".join(item["command_line"].split()).casefold()
        if exact not in group["_seen"]:
            group["_seen"].add(exact)
            group["variants"] += 1
        if item.get("pid") is not None and len(group["pids"]) < 50:
            group["pids"].append(item["pid"])
        if item.get("process_name") and item["process_name"] not in group["process_names"]:
            group["process_names"].append(item["process_name"])
        start = item.get("create_time")
        if start:
            group["first_start"] = min(filter(None, [group["first_start"], start]))
            group["last_start"] = max(filter(None, [group["last_start"], start]))
    for group in groups.values():
        group.pop("_seen", None)
    return sorted(groups.values(), key=lambda g: (g["count"], g["first_start"] is None, g["first_start"] or ""))


def build_command_line_history(
    *,
    case_id: str,
    evidence_id: str,
    run_id: str | None = None,
    pid: int | None = None,
    ppid: int | None = None,
    process_name: str | None = None,
    command_contains: str | None = None,
    source_plugin: str | None = None,
    visibility: str | None = None,
    time_from: str | None = None,
    time_to: str | None = None,
    profile: str | None = None,
    sort_order: str = "oldest_first",
    group_identical: bool = False,
    page: int = 1,
    page_size: int = 50,
) -> dict[str, Any]:
    db = SessionLocal()
    try:
        from app.services.memory.process_federation import resolve_federated_process_context

        effective_run_id = run_id
        if not effective_run_id:
            ctx = resolve_federated_process_context(db, case_id=case_id, evidence_id=evidence_id)
            effective_run_id = ctx.get("basic_run_id") or ctx.get("primary_run_id")

        if not effective_run_id:
            return {
                "items": [], "total": 0, "page": page, "page_size": page_size,
                "sort_order": sort_order, "selected_run": None,
                "contributing_runs": [], "coverage": {"entities_with_command_lines": 0, "total_entities": 0, "unknown_timestamps": 0},
            }

        result = fetch_canonical_entities(
            case_id,
            run_id=effective_run_id,
            process_name=process_name,
            pid=pid,
            page=1,
            page_size=50000,
        )
        all_entities: list[dict[str, Any]] = result.get("items", [])

        items: list[dict[str, Any]] = []
        for entity in all_entities:
            proc = entity.get("process", {})
            cmd_line = proc.get("command_line")
            if not cmd_line or not isinstance(cmd_line, str) or not cmd_line.strip():
                continue
            ent_id = entity.get("process_entity_id", "")

            if pid is not None and proc.get("pid") != pid:
                continue
            if ppid is not None and proc.get("ppid") != ppid:
                continue
            if command_contains and command_contains.lower() not in cmd_line.lower():
                continue
            if source_plugin and source_plugin not in entity.get("source_plugins", []):
                continue
            if visibility:
                vis = entity.get("visibility", {})
                if visibility == "listed" and not vis.get("listed"):
                    continue
                if visibility == "scan_only" and not vis.get("scan_only"):
                    continue
                if visibility == "terminated" and not vis.get("terminated"):
                    continue
            create_time = proc.get("create_time") or None
            # A range keeps only processes known to have started inside it.
            if (time_from or time_to) and not create_time:
                continue
            if time_from and create_time < time_from:
                continue
            if time_to and create_time > time_to:
                continue

            items.append({
                "process_entity_id": ent_id,
                "pid": proc.get("pid"),
                "ppid": proc.get("ppid"),
                "process_name": proc.get("name"),
                "command_line": cmd_line,
                "create_time": create_time,
                "exit_time": proc.get("exit_time"),
                "timestamp_source": "process_creation_time" if create_time else None,
                "visibility": {
                    "listed": entity.get("visibility", {}).get("listed", False),
                    "scan_only": entity.get("visibility", {}).get("scan_only", False),
                    "terminated": entity.get("visibility", {}).get("terminated", False),
                },
                "source_plugins": entity.get("source_plugins", []),
                "source_observations": entity.get("sources", []),
                "parent_entity_id": entity.get("parent_entity_id"),
                "findings": entity.get("findings", []),
                "record_refs": [],
            })

        if sort_order == "newest_first":
            items.sort(key=lambda x: (x["create_time"] is None, x["create_time"] or ""), reverse=True)
        else:
            items.sort(key=lambda x: (x["create_time"] is None, x["create_time"] or ""))

        unknown = [i for i in items if i["create_time"] is None]
        dated = [i for i in items if i["create_time"] is not None]
        ordered = dated + unknown if sort_order == "oldest_first" else unknown + dated

        listed = group_identical_command_lines(ordered) if group_identical else ordered
        total = len(listed)
        start = (page - 1) * page_size
        paged = listed[start:start + page_size]

        run_info = None
        if effective_run_id:
            run = db.query(MemoryScanRun).filter(MemoryScanRun.id == effective_run_id).first()
            if run:
                run_info = {"id": run.id, "profile": run.profile, "status": run.status}

        return {
            "items": paged,
            "total": total,
            "page": page,
            "page_size": page_size,
            "sort_order": sort_order,
            "grouped": group_identical,
            "selected_run": run_info,
            "contributing_runs": [],
            "coverage": {
                "entities_with_command_lines": len(ordered),
                "total_entities": len(all_entities),
                "unknown_timestamps": len(unknown) if sort_order == "oldest_first" else len([i for i in items if i["create_time"] is None]),
            },
        }
    finally:
        db.close()
