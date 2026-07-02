from __future__ import annotations

from collections import Counter
from typing import Any

from fastapi import HTTPException
from sqlalchemy.orm import Session

from app.core.database import SessionLocal
from app.models.evidence import Evidence, EvidenceType
from app.services.memory.command_history import build_command_line_history
from app.services.memory.search import search_memory_artifacts
from app.services.memory.timeline import get_memory_timeline


SOURCE_CATEGORY_MEMORY = "Memory"


def normalize_source_category(value: str | None) -> str | None:
    text = str(value or "").strip().lower().replace("_", " ").replace("-", " ")
    if not text or text == "all sources":
        return None
    aliases = {
        "memory": "Memory",
        "disk": "Disk",
        "event": "Event Log",
        "event log": "Event Log",
        "registry": "Registry",
        "browser": "Browser",
        "network": "Network Log",
        "network log": "Network Log",
        "cloud": "Cloud",
        "email": "Email",
        "system": "System",
        "other": "Other",
    }
    return aliases.get(text, value)


def wants_memory_source(params: dict[str, Any]) -> bool:
    category = normalize_source_category(params.get("source_category") or params.get("source"))
    return category == SOURCE_CATEGORY_MEMORY


def wants_non_memory_source(params: dict[str, Any]) -> bool:
    category = normalize_source_category(params.get("source_category") or params.get("source"))
    return bool(category and category != SOURCE_CATEGORY_MEMORY)


def source_category_for_event(raw: dict[str, Any]) -> str:
    artifact = raw.get("artifact") if isinstance(raw.get("artifact"), dict) else {}
    artifact_type = str(artifact.get("type") or raw.get("artifact_type") or "").lower()
    parser = str(artifact.get("parser") or raw.get("parser") or "").lower()
    if artifact_type in {"evtx", "windows_event"} or "evtx" in parser or raw.get("windows"):
        return "Event Log"
    if artifact_type.startswith("registry") or "registry" in parser or raw.get("registry"):
        return "Registry"
    if "browser" in artifact_type or "browser" in parser or raw.get("browser"):
        return "Browser"
    if "email" in artifact_type or "email" in parser:
        return "Email"
    if artifact_type in {"dns", "network", "srum"} or raw.get("network"):
        return "Network Log"
    if artifact_type in {"system", "host"}:
        return "System"
    return "Disk"


def add_event_source_provenance(row: dict[str, Any]) -> dict[str, Any]:
    raw = row.get("raw") if isinstance(row.get("raw"), dict) else {}
    artifact = raw.get("artifact") if isinstance(raw.get("artifact"), dict) else {}
    category = source_category_for_event(raw)
    row.setdefault("source_category", category)
    row.setdefault("source_plugin_or_parser", row.get("parser") or artifact.get("parser"))
    raw.setdefault("source_category", category)
    raw.setdefault("source_plugin_or_parser", row.get("source_plugin_or_parser"))
    return row


def memory_evidences(db: Session, case_id: str, evidence_id: str | None = None) -> list[Evidence]:
    query = db.query(Evidence).filter(Evidence.case_id == case_id)
    if evidence_id:
        evidence = db.get(Evidence, evidence_id)
        if not evidence or evidence.case_id != case_id:
            raise HTTPException(status_code=404, detail="Evidence was not found in this case.")
        query = query.filter(Evidence.id == evidence_id)
    evidences = list(query.all())
    return [e for e in evidences if str(e.evidence_type) == EvidenceType.memory_dump.value or e.evidence_type == EvidenceType.memory_dump or e.detected_format or e.detection_status]


def memory_search_results(db: Session, case_id: str, params: dict[str, Any]) -> dict[str, Any]:
    page = max(int(params.get("page") or 1), 1)
    page_size = min(max(int(params.get("page_size") or 100), 1), 500)
    artifact_types = params.get("artifact_family") or params.get("memory_artifact_family") or params.get("artifact_type")
    if isinstance(artifact_types, str):
        artifact_types = [artifact_types]
    q = params.get("q") or params.get("query")
    all_results: list[dict[str, Any]] = []
    facets: dict[str, Counter[str]] = {"source_category": Counter(), "artifact_family": Counter(), "artifact_type": Counter(), "source_plugin_or_parser": Counter(), "evidence": Counter()}
    warnings: list[str] = []
    for evidence in memory_evidences(db, case_id, params.get("evidence_id")):
        payload = search_memory_artifacts(
            db,
            case_id=case_id,
            evidence_id=str(evidence.id),
            query=q,
            artifact_types=artifact_types,
            run_id=params.get("run_id") or params.get("memory_run_id"),
            page=1,
            page_size=page_size,
            sort=_memory_search_sort(str(params.get("sort") or "relevance")),
            pid=_int_or_none(params.get("pid")),
            ppid=_int_or_none(params.get("ppid")),
            process_name=params.get("process_name"),
            source_plugin=params.get("source_plugin") or params.get("source_plugin_or_parser"),
            local_port=_int_or_none(params.get("local_port")),
            remote_port=_int_or_none(params.get("remote_port")),
            local_address=params.get("local_address"),
            remote_address=params.get("remote_address"),
            time_from=params.get("time_from"),
            time_to=params.get("time_to"),
            mixed_run=True,
        )
        warnings.extend(payload.get("warnings") or [])
        for result in payload.get("results") or []:
            row = _memory_search_row(case_id, result)
            all_results.append(row)
            facets["source_category"][SOURCE_CATEGORY_MEMORY] += 1
            facets["artifact_family"][str(result.get("artifact_family") or "memory")] += 1
            facets["artifact_type"][str(result.get("artifact_type") or "memory_artifact")] += 1
            if result.get("source_plugin"):
                facets["source_plugin_or_parser"][str(result.get("source_plugin"))] += 1
            if result.get("evidence_name") or result.get("evidence_id"):
                facets["evidence"][str(result.get("evidence_name") or result.get("evidence_id"))] += 1
    all_results.sort(key=lambda item: (item.get("timestamp") is None, item.get("timestamp") or "", item.get("id") or ""), reverse=str(params.get("sort") or "").endswith("desc"))
    total = len(all_results)
    start = (page - 1) * page_size
    return {
        "total": total,
        "page": page,
        "page_size": page_size,
        "items_count": len(all_results[start:start + page_size]),
        "total_pages": (total + page_size - 1) // page_size if total else 0,
        "next_cursor": None,
        "has_next": start + page_size < total,
        "results": all_results[start:start + page_size],
        "facets": {key: dict(value) for key, value in facets.items()},
        "warnings": warnings,
        "query": {"q": q or "", "source_category": SOURCE_CATEGORY_MEMORY},
    }


def memory_timeline_items(db: Session, case_id: str, params: dict[str, Any]) -> dict[str, Any]:
    page = max(int(params.get("page") or 1), 1)
    page_size = min(max(int(params.get("page_size") or 100), 1), 500)
    items: list[dict[str, Any]] = []
    undated_count = 0
    for evidence in memory_evidences(db, case_id, params.get("evidence_id")):
        payload = get_memory_timeline(
            db,
            case_id=case_id,
            evidence_id=str(evidence.id),
            memory_run_id=params.get("run_id") or params.get("memory_run_id"),
            time_from=params.get("time_from"),
            time_to=params.get("time_to"),
            artifact_families=params.get("artifact_family") or params.get("artifact_type"),
            event_kinds=params.get("event_kind") or params.get("event_type"),
            process_entity_id=params.get("process_entity_id"),
            pid=_int_or_none(params.get("pid")),
            process_name=params.get("process_name"),
            source_plugin=params.get("source_plugin") or params.get("source_plugin_or_parser"),
            has_correlations=params.get("has_correlations"),
            correlation_confidence=params.get("confidence"),
            include_undated=bool(params.get("include_undated")),
            page=1,
            page_size=500,
            sort_order="desc" if str(params.get("sort") or "").endswith("desc") else "asc",
        )
        undated_count += int(payload.get("undated_count") or 0)
        items.extend(_memory_timeline_row(case_id, row) for row in payload.get("items") or [] if not row.get("is_undated"))
    items.sort(key=lambda item: (item.get("timestamp") or "", item.get("id") or ""), reverse=str(params.get("sort") or "").endswith("desc"))
    total = len(items)
    start = (page - 1) * page_size
    page_items = items[start:start + page_size]
    return {
        "case_id": case_id,
        "mode": "full",
        "total": total,
        "page": page,
        "page_size": page_size,
        "next_cursor": None,
        "items": page_items,
        "groups": [],
        "facets": _timeline_facets(items),
        "undated_count": undated_count,
        "warnings": [],
    }


def memory_command_history(db: Session | None, case_id: str, params: dict[str, Any]) -> dict[str, Any]:
    owned_db = None
    if db is None:
        owned_db = SessionLocal()
        db = owned_db
    try:
        return _memory_command_history(db, case_id, params)
    finally:
        if owned_db is not None:
            owned_db.close()


def _memory_command_history(db: Session, case_id: str, params: dict[str, Any]) -> dict[str, Any]:
    page = max(int(params.get("page") or 1), 1)
    page_size = min(max(int(params.get("page_size") or 100), 1), 500)
    rows: list[dict[str, Any]] = []
    for evidence in memory_evidences(db, case_id, params.get("evidence_id")):
        payload = build_command_line_history(
            case_id=case_id,
            evidence_id=str(evidence.id),
            run_id=params.get("run_id") or params.get("memory_run_id"),
            pid=_int_or_none(params.get("pid")),
            ppid=_int_or_none(params.get("ppid")),
            process_name=params.get("process_name"),
            command_contains=params.get("q") or params.get("command_contains"),
            source_plugin=params.get("source_plugin") or params.get("source_plugin_or_parser"),
            time_from=params.get("time_from"),
            time_to=params.get("time_to"),
            sort_order="newest_first" if str(params.get("sort") or params.get("sort_order") or "").endswith("desc") else "oldest_first",
            page=1,
            page_size=500,
        )
        rows.extend(_memory_command_row(case_id, evidence, row, payload.get("selected_run")) for row in payload.get("items") or [])
    rows.sort(key=lambda item: (item.get("timestamp") is None, item.get("timestamp") or "", item.get("id") or ""), reverse=str(params.get("sort") or params.get("sort_order") or "").endswith("desc"))
    total = len(rows)
    start = (page - 1) * page_size
    page_rows = rows[start:start + page_size]
    return {
        "total": total,
        "page": page,
        "page_size": page_size,
        "sort": params.get("sort") or "timestamp_desc",
        "sort_by": "timestamp",
        "sort_order": "desc" if str(params.get("sort") or params.get("sort_order") or "").endswith("desc") else "asc",
        "items": page_rows,
        "facets": _command_facets(rows),
        "summary": {
            "commands_total": total,
            "suspicious_total": 0,
            "high_confidence": 0,
            "with_command_line": sum(1 for item in rows if item.get("command")),
            "with_supporting_events": sum(1 for item in rows if item.get("supporting_events")),
        },
    }


def _memory_search_row(case_id: str, result: dict[str, Any]) -> dict[str, Any]:
    raw = dict(result.get("raw") or {})
    raw.update({
        "source_category": SOURCE_CATEGORY_MEMORY,
        "source_plugin_or_parser": result.get("source_plugin"),
        "evidence_name": result.get("evidence_name"),
        "navigation_target": result.get("navigation_target"),
        "raw_reference": result.get("raw_reference"),
    })
    return {
        "kind": "event",
        "id": f"memory:{result.get('result_id')}",
        "timestamp": result.get("timestamp"),
        "title": result.get("title") or "Memory artifact",
        "summary": result.get("summary") or "",
        "artifact_type": result.get("artifact_type"),
        "artifact_family": result.get("artifact_family"),
        "parser": result.get("source_plugin"),
        "source_category": SOURCE_CATEGORY_MEMORY,
        "source_plugin_or_parser": result.get("source_plugin"),
        "event_type": result.get("artifact_family"),
        "severity": None,
        "risk_score": 0,
        "host": None,
        "user": None,
        "source_file": result.get("evidence_name"),
        "matched_fields": result.get("matched_fields") or [],
        "highlights": {},
        "raw": {"case_id": case_id, **raw, **{k: result.get(k) for k in ("evidence_id", "memory_run_id", "process_entity_id", "pid", "ppid", "process_name")}},
    }


def _memory_timeline_row(case_id: str, row: dict[str, Any]) -> dict[str, Any]:
    return {
        "id": f"memory-timeline:{row.get('event_id')}",
        "kind": "event",
        "timestamp": row.get("occurred_at"),
        "time_bucket": None,
        "title": row.get("title") or row.get("event_kind") or "Memory event",
        "summary": row.get("summary") or "",
        "artifact_type": row.get("artifact_type"),
        "artifact_family": row.get("artifact_family"),
        "parser": row.get("source_plugin") or row.get("source_parser"),
        "source_category": SOURCE_CATEGORY_MEMORY,
        "source_plugin_or_parser": row.get("source_plugin") or row.get("source_parser"),
        "event_type": row.get("event_kind"),
        "event_category": row.get("artifact_family"),
        "risk_score": 0,
        "severity": None,
        "host": None,
        "user": None,
        "evidence_id": row.get("evidence_id"),
        "source_file": None,
        "key_entity": row.get("process_name") or row.get("executable_path") or row.get("event_kind"),
        "related_finding_ids": [],
        "related_process_node_ids": [row.get("process_entity_id")] if row.get("process_entity_id") else [],
        "is_key_event": False,
        "bookmark": None,
        "data_quality": row.get("normalization_warnings") or [],
        "raw": {"case_id": case_id, **row, "source_category": SOURCE_CATEGORY_MEMORY, "source_plugin_or_parser": row.get("source_plugin") or row.get("source_parser")},
    }


def _memory_command_row(case_id: str, evidence: Evidence, row: dict[str, Any], selected_run: dict[str, Any] | None) -> dict[str, Any]:
    run_id = (selected_run or {}).get("id")
    plugin = ",".join(row.get("source_plugins") or []) or "windows.cmdline"
    command_id = f"memory-command:{evidence.id}:{run_id or 'active'}:{row.get('process_entity_id')}:{row.get('pid')}"
    return {
        "id": command_id,
        "command_id": command_id,
        "case_id": case_id,
        "evidence_id": str(evidence.id),
        "evidence_name": evidence.original_filename,
        "run_id": run_id,
        "host": evidence.detected_host,
        "timestamp": row.get("create_time"),
        "timestamp_status": "process_creation_time" if row.get("create_time") else "undated",
        "timestamp_semantics": row.get("timestamp_source"),
        "command": row.get("command_line"),
        "command_line": row.get("command_line"),
        "command_normalized": str(row.get("command_line") or "").lower(),
        "shell": "memory",
        "launcher": row.get("process_name"),
        "launcher_path": None,
        "shell_family": "memory",
        "classification_confidence": "observed",
        "parent_shell": None,
        "parent_context": None,
        "source_type": "memory",
        "source_category": SOURCE_CATEGORY_MEMORY,
        "source_plugin_or_parser": plugin,
        "artifact_type": "memory_command_line",
        "source_event_id": command_id,
        "source_file": evidence.original_filename,
        "user": None,
        "process": {"name": row.get("process_name"), "pid": row.get("pid"), "guid": row.get("process_entity_id"), "entity_id": row.get("process_entity_id"), "command_line": row.get("command_line")},
        "parent_process": {"pid": row.get("ppid"), "guid": row.get("parent_entity_id")},
        "process_entity_id": row.get("process_entity_id"),
        "risk_score": 0,
        "risk_reasons": [],
        "confidence": "observed",
        "supporting_events": [],
        "raw_reference": {"process_entity_id": row.get("process_entity_id"), "run_id": run_id},
        "navigation_target": {"kind": "memory_process", "case_id": case_id, "evidence_id": str(evidence.id), "run_id": run_id, "process_entity_id": row.get("process_entity_id"), "tab": "graph"},
    }


def _memory_search_sort(sort: str) -> str:
    if sort == "timestamp_desc":
        return "newest"
    if sort == "timestamp_asc":
        return "oldest"
    return sort if sort in {"relevance", "newest", "oldest", "artifact_type", "pid", "process_name"} else "relevance"


def _int_or_none(value: Any) -> int | None:
    if value is None or value == "":
        return None
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def _timeline_facets(items: list[dict[str, Any]]) -> dict[str, dict[str, int]]:
    counters: dict[str, Counter[str]] = {"source_category": Counter(), "artifact_family": Counter(), "artifact_type": Counter(), "event_type": Counter(), "evidence": Counter()}
    for item in items:
        for key in counters:
            value = item.get(key) or item.get("raw", {}).get(key)
            if value:
                counters[key][str(value)] += 1
    return {key: dict(value) for key, value in counters.items()}


def _command_facets(items: list[dict[str, Any]]) -> dict[str, dict[str, int]]:
    counters: dict[str, Counter[str]] = {"source_category": Counter(), "source_type": Counter(), "source_plugin_or_parser": Counter(), "family": Counter(), "evidence": Counter()}
    for item in items:
        counters["source_category"][str(item.get("source_category") or SOURCE_CATEGORY_MEMORY)] += 1
        for key in ("source_type", "source_plugin_or_parser", "shell_family"):
            if item.get(key):
                counters["family" if key == "shell_family" else key][str(item[key])] += 1
        if item.get("evidence_name") or item.get("evidence_id"):
            counters["evidence"][str(item.get("evidence_name") or item.get("evidence_id"))] += 1
    return {key: dict(value) for key, value in counters.items()}
