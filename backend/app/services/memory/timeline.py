from __future__ import annotations

import hashlib
import math
import re
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any

from dateutil import parser as date_parser
from sqlalchemy.orm import Session

from app.core.opensearch import get_events_index, get_memory_index, get_opensearch_client
from app.models.evidence import Evidence
from app.models.memory import MemoryScanRun
from app.services.memory.active_result import resolve_active_memory_result
from app.services.memory.artifact_indexing import _prepare_artifact_document_for_response


TIMELINE_RULE_VERSION = "memory_timeline_v1"
CORRELATION_RULE_VERSION = "memory_correlation_v1"
PAGE_SIZES = {50, 100, 250, 500}
LOW_CONFIDENCE = "low"


@dataclass(frozen=True)
class TimestampSpec:
    fields: tuple[str, ...]
    semantics: str
    confidence: str


MEMORY_TIMESTAMP_MATRIX: dict[str, dict[str, Any]] = {
    "memory_process_entity": {"source_plugin": "windows.pslist/psscan/pstree/cmdline", "fields": {"process.create_time": "process_start", "process.exit_time": "process_exit"}, "timezone": "source/UTC-normalized when parseable", "precision": "second", "nullable": True, "occurrence": True, "historical": "legacy process rows may expose CreateTime/ExitTime via observations"},
    "memory_process_observation": {"source_plugin": "windows.pslist/psscan/pstree/cmdline", "fields": {"observed.create_time": "process_start", "observed.exit_time": "process_exit"}, "timezone": "source/UTC-normalized when parseable", "precision": "second", "nullable": True, "occurrence": True, "historical": "raw source_fields may contain CreateTime/ExitTime"},
    "memory_command_line": {"source_plugin": "windows.cmdline", "fields": {}, "timezone": "unknown", "precision": "unknown", "nullable": True, "occurrence": False, "historical": "command lines generally have no own occurrence time; process start may be shown only as process context"},
    "memory_network_connection": {"source_plugin": "windows.netscan/netstat", "fields": {"create_time": "connection_created"}, "timezone": "source/UTC-normalized when parseable", "precision": "second", "nullable": True, "occurrence": True, "historical": "older rows may have null create_time"},
    "memory_process_module": {"source_plugin": "windows.dlllist/ldrmodules", "fields": {}, "timezone": "unknown", "precision": "unknown", "nullable": True, "occurrence": False, "historical": "module load time is not normalized unless a future source field is present"},
    "memory_handle": {"source_plugin": "windows.handles", "fields": {}, "timezone": "unknown", "precision": "unknown", "nullable": True, "occurrence": False, "historical": "undated observation"},
    "memory_suspicious_region": {"source_plugin": "windows.malfind", "fields": {"create_time": "owning_process_created_when_reported"}, "timezone": "source/UTC-normalized when parseable", "precision": "second", "nullable": True, "occurrence": True, "historical": "may be process create time rather than injection time; labelled as suspicious memory observation"},
    "memory_vad": {"source_plugin": "windows.vadinfo", "fields": {}, "timezone": "unknown", "precision": "unknown", "nullable": True, "occurrence": False, "historical": "undated observation"},
    "memory_driver": {"source_plugin": "windows.driverscan", "fields": {}, "timezone": "unknown", "precision": "unknown", "nullable": True, "occurrence": False, "historical": "undated unless source adds a real timestamp"},
    "memory_kernel_module": {"source_plugin": "windows.modules", "fields": {}, "timezone": "unknown", "precision": "unknown", "nullable": True, "occurrence": False, "historical": "undated unless source adds a real timestamp"},
    "memory_system_info": {"source_plugin": "windows.info", "fields": {"memory.system_time": "system_clock_observation"}, "timezone": "UTC/source", "precision": "second", "nullable": True, "occurrence": False, "historical": "operational context; not process occurrence timeline"},
}

DISK_TIMESTAMP_MATRIX: dict[str, dict[str, Any]] = {
    "windows_event_4688": {"timestamp": "@timestamp", "semantics": "event record time/process creation", "process_fields": ["process.name", "process.path", "process.command_line", "process.pid", "process.parent.pid"], "user_fields": ["user.name", "user.sid"], "parser": "artifact.parser", "raw_reference": "stable_event_id/_id"},
    "powershell": {"timestamp": "@timestamp", "semantics": "PowerShell operational/script event time", "process_fields": ["process.pid", "process.name", "powershell.command", "powershell.script_block_text"], "user_fields": ["user.name", "user.sid"], "parser": "artifact.parser", "raw_reference": "stable_event_id/_id"},
    "prefetch": {"timestamp": "@timestamp/file timestamps", "semantics": "executable execution evidence, not exact process-instance proof", "process_fields": ["process.name", "file.name", "file.path"], "user_fields": [], "parser": "artifact.parser", "raw_reference": "stable_event_id/_id"},
    "amcache": {"timestamp": "@timestamp", "semantics": "program/file inventory timestamp; execution semantics depend on parser fields", "process_fields": ["process.name", "process.path", "file.path", "amcache.program_name"], "user_fields": [], "parser": "artifact.parser", "raw_reference": "stable_event_id/_id"},
    "shimcache": {"timestamp": "@timestamp", "semantics": "AppCompat/Shimcache observation; not execution proof by default", "process_fields": ["file.path", "shimcache.path", "appcompat.path"], "user_fields": [], "parser": "artifact.parser", "raw_reference": "stable_event_id/_id"},
    "services": {"timestamp": "@timestamp", "semantics": "service install/change/event time", "process_fields": ["service.name", "service.image_path", "process.path"], "user_fields": ["user.name", "user.sid"], "parser": "artifact.parser", "raw_reference": "stable_event_id/_id"},
    "scheduled_tasks": {"timestamp": "@timestamp", "semantics": "task registration/execution event time", "process_fields": ["task.command", "task.arguments", "process.command_line"], "user_fields": ["user.name", "user.sid"], "parser": "artifact.parser", "raw_reference": "stable_event_id/_id"},
    "registry_persistence": {"timestamp": "@timestamp", "semantics": "persistence configuration observation", "process_fields": ["registry.value_data", "autoruns.image_path", "autoruns.command_line", "persistence.command"], "user_fields": ["user.name", "user.sid", "autoruns.sid"], "parser": "artifact.parser", "raw_reference": "stable_event_id/_id"},
    "network_logs": {"timestamp": "@timestamp", "semantics": "network/DNS/firewall event time", "process_fields": ["process.name", "process.pid"], "user_fields": ["user.name", "user.sid"], "parser": "artifact.parser", "raw_reference": "stable_event_id/_id"},
}


def get_memory_timeline(
    db: Session,
    *,
    case_id: str,
    evidence_id: str,
    memory_run_id: str | None = None,
    time_from: str | None = None,
    time_to: str | None = None,
    artifact_families: list[str] | None = None,
    event_kinds: list[str] | None = None,
    process_entity_id: str | None = None,
    pid: int | None = None,
    process_name: str | None = None,
    source_plugin: str | None = None,
    source_parser: str | None = None,
    has_correlations: bool | None = None,
    correlation_confidence: str | None = None,
    include_undated: bool = False,
    page: int = 1,
    page_size: int = 100,
    sort_order: str = "asc",
) -> dict[str, Any]:
    page, page_size = _bounded_page(page, page_size)
    active_run_id = _active_run_id(db, case_id, evidence_id)
    # Default timeline scope is the selected Evidence across compatible
    # active materialized families. Explicit memory_run_id remains a hard
    # single-run filter for historical inspection.
    memory_docs = _fetch_memory_docs(case_id, evidence_id, run_id=memory_run_id, process_entity_id=process_entity_id, pid=pid, process_name=process_name, source_plugin=source_plugin)
    events, undated = _memory_events(case_id, evidence_id, memory_run_id or active_run_id, memory_docs)
    disk_docs = _fetch_disk_docs(case_id, source_parser=source_parser)
    disk_events = _disk_events(case_id, disk_docs)
    correlations = _build_correlations(events, disk_events, include_low=correlation_confidence == LOW_CONFIDENCE)
    corr_by_event: dict[str, list[dict[str, Any]]] = {}
    for corr in correlations:
        corr_by_event.setdefault(corr["left_artifact_id"], []).append(corr)
    items = events + disk_events
    if include_undated:
        items.extend(undated)
    for item in items:
        item["correlations"] = _bounded_correlations(corr_by_event.get(item["event_id"], []), correlation_confidence)
    filtered = _filter_events(items, time_from=time_from, time_to=time_to, artifact_families=artifact_families, event_kinds=event_kinds, has_correlations=has_correlations, correlation_confidence=correlation_confidence, include_undated=include_undated)
    filtered.sort(key=lambda e: (_sort_key(e), e["event_id"]), reverse=sort_order == "desc")
    total = len(filtered)
    page_items = filtered[(page - 1) * page_size : page * page_size]
    return {
        "items": page_items,
        "total": total,
        "page": page,
        "page_size": page_size,
        "total_pages": math.ceil(total / page_size) if total else 0,
        "time_range": {"from": time_from, "to": time_to, "sort_order": sort_order},
        "selected_evidence": _evidence_payload(db, evidence_id),
        "selected_memory_context": {"mode": "historical_run" if memory_run_id else "evidence_active_families", "memory_run_id": memory_run_id, "default_process_run_id": active_run_id},
        "event_kind_counts": _counts(filtered, "event_kind"),
        "artifact_family_counts": _counts(filtered, "artifact_family"),
        "timestamp_quality_summary": _timestamp_quality(events, undated),
        "correlated_event_count": len({c["left_artifact_id"] for c in correlations if c["confidence"] != LOW_CONFIDENCE}),
        "undated_count": len(undated),
        "warnings": [],
        "coverage": _coverage(memory_docs, disk_docs, events, undated, correlations),
    }


def get_memory_correlations(db: Session, *, case_id: str, evidence_id: str, process_entity_id: str | None = None, correlation_type: str | None = None, confidence: str | None = None, artifact_type: str | None = None, time_from: str | None = None, time_to: str | None = None, page: int = 1, page_size: int = 100) -> dict[str, Any]:
    timeline = get_memory_timeline(db, case_id=case_id, evidence_id=evidence_id, process_entity_id=process_entity_id, time_from=time_from, time_to=time_to, include_undated=True, correlation_confidence=confidence, page=1, page_size=500)
    correlations = [corr for item in timeline["items"] for corr in item.get("correlations", [])]
    if correlation_type:
        correlations = [c for c in correlations if c.get("correlation_type") == correlation_type]
    if confidence:
        correlations = [c for c in correlations if c.get("confidence") == confidence]
    if artifact_type:
        correlations = [c for c in correlations if artifact_type in {c.get("left_artifact_type"), c.get("right_artifact_type")}]
    page, page_size = _bounded_page(page, page_size)
    total = len(correlations)
    return {"items": correlations[(page - 1) * page_size : page * page_size], "total": total, "page": page, "page_size": page_size, "total_pages": math.ceil(total / page_size) if total else 0, "coverage": timeline["coverage"]}


def get_memory_correlation_detail(db: Session, *, case_id: str, evidence_id: str, correlation_id: str) -> dict[str, Any]:
    payload = get_memory_correlations(db, case_id=case_id, evidence_id=evidence_id, page=1, page_size=500)
    for corr in payload["items"]:
        if corr["correlation_id"] == correlation_id:
            return corr
    return {"correlation_id": correlation_id, "found": False}


def materialize_timeline(db: Session, *, case_id: str, evidence_id: str, memory_run_id: str | None = None, apply: bool = False, batch_size: int = 500, confidence_min: str | None = None) -> dict[str, Any]:
    timeline = get_memory_timeline(db, case_id=case_id, evidence_id=evidence_id, memory_run_id=memory_run_id, include_undated=True, correlation_confidence=confidence_min, page=1, page_size=500)
    docs = []
    for item in timeline["items"]:
        docs.append({**item, "document_type": "memory_timeline_event", "materialized_rule_version": TIMELINE_RULE_VERSION})
        for corr in item.get("correlations", []):
            docs.append({**corr, "document_type": "memory_artifact_correlation", "case_id": case_id, "evidence_id": evidence_id})
    unique = {doc.get("event_id") or doc.get("correlation_id"): doc for doc in docs}
    report = {"dry_run": not apply, "case_id": case_id, "evidence_id": evidence_id, "memory_run_id": memory_run_id, "created_or_updated": len(unique) if apply else 0, "would_create_or_update": len(unique), "skipped": 0, "rejected": timeline["coverage"].get("rejected_correlation_candidates", 0), "timeline_events": len(timeline["items"]), "correlations": sum(len(i.get("correlations", [])) for i in timeline["items"]), "rule_versions": [TIMELINE_RULE_VERSION, CORRELATION_RULE_VERSION]}
    if apply and unique:
        client = get_opensearch_client()
        body = []
        for key, doc in list(unique.items())[:batch_size]:
            body.append({"index": {"_index": get_memory_index(case_id), "_id": str(key)}})
            body.append(doc)
        client.bulk(body=body, refresh=True)
    return report


def _fetch_memory_docs(case_id: str, evidence_id: str, *, run_id: str | None, process_entity_id: str | None, pid: int | None, process_name: str | None, source_plugin: str | None) -> list[dict[str, Any]]:
    base_filters: list[dict[str, Any]] = [{"term": {"evidence_id": evidence_id}}]
    if run_id:
        base_filters.append({"term": {"scan_run_id.keyword": run_id}})
    if process_entity_id:
        base_filters.append(_any_term(["process_entity_id", "process_entity_id.keyword"], process_entity_id))
    if pid is not None:
        base_filters.append(_any_term(["pid", "process.pid", "observed.pid"], pid))
    if process_name:
        base_filters.append(_any_term(["process_name", "process.name", "observed.name"], process_name))
    if source_plugin:
        base_filters.append(_any_term(["source_plugin", "source_plugins", "plugin_name"], source_plugin))
    client = get_opensearch_client()
    docs: list[dict[str, Any]] = []
    for doc_type in MEMORY_TIMESTAMP_MATRIX:
        filters = [*base_filters, _any_term(["document_type"], doc_type)]
        body = {"query": {"bool": {"filter": filters}}, "size": 10000, "track_total_hits": True, "sort": [{"scan_run_id.keyword": {"order": "desc", "unmapped_type": "keyword"}}, {"document_id": {"order": "asc"}}]}
        response = client.search(index=get_memory_index(case_id), body=body, params={"ignore_unavailable": "true"})
        docs.extend(_prepare_artifact_document_for_response(h.get("_source", {}) | {"document_id": h.get("_id")}) for h in response.get("hits", {}).get("hits", []))
    return docs


def _fetch_disk_docs(case_id: str, *, source_parser: str | None = None) -> list[dict[str, Any]]:
    filters: list[dict[str, Any]] = [{"term": {"case_id": case_id}}, {"exists": {"field": "@timestamp"}}]
    if source_parser:
        filters.append(_any_term(["artifact.parser", "artifact.parser.keyword"], source_parser))
    should = [
        {"terms": {"windows.event_id": [4688, 1, 4697, 7045, 4698, 4702]}},
        {"wildcard": {"artifact.type.keyword": "*prefetch*"}},
        {"wildcard": {"artifact.type.keyword": "*amcache*"}},
        {"wildcard": {"artifact.type.keyword": "*shimcache*"}},
        {"wildcard": {"artifact.type.keyword": "*appcompat*"}},
        {"exists": {"field": "powershell.command"}},
        {"exists": {"field": "service.image_path"}},
        {"exists": {"field": "task.command"}},
        {"exists": {"field": "autoruns.command_line"}},
        {"exists": {"field": "registry.value_data"}},
        {"exists": {"field": "network.destination_ip"}},
    ]
    body = {"query": {"bool": {"filter": filters, "should": should, "minimum_should_match": 1}}, "size": 1000, "track_total_hits": True, "sort": [{"@timestamp": {"order": "asc", "missing": "_last"}}]}
    try:
        response = get_opensearch_client().search(index=get_events_index(), body=body, params={"ignore_unavailable": "true"})
    except Exception:
        return []
    return [h.get("_source", {}) | {"_id": h.get("_id")} for h in response.get("hits", {}).get("hits", [])]


def _memory_events(case_id: str, evidence_id: str, run_id: str | None, docs: list[dict[str, Any]]) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    events: list[dict[str, Any]] = []
    undated: list[dict[str, Any]] = []
    for doc in docs:
        doc_type = doc.get("document_type") or doc.get("memory_artifact_type")
        if doc_type == "memory_process_entity":
            process = doc.get("process") if isinstance(doc.get("process"), dict) else {}
            for field, kind, semantics in (("create_time", "process_start", "process creation time reported by memory plugin"), ("exit_time", "process_exit", "process exit time reported by memory plugin")):
                event = _base_memory_event(case_id, evidence_id, run_id, doc, artifact_family="processes", event_kind=kind, timestamp=process.get(field), timestamp_source=f"process.{field}", timestamp_semantics=semantics)
                if event["is_undated"]:
                    if kind == "process_exit":
                        continue
                    undated.append(event)
                else:
                    events.append(event)
            continue
        if doc_type == "memory_process_observation":
            observed = doc.get("observed") if isinstance(doc.get("observed"), dict) else {}
            timestamp = observed.get("create_time") if observed.get("command_line") else None
            event = _base_memory_event(case_id, evidence_id, run_id, doc, artifact_family="raw_observations", event_kind="command_line" if observed.get("command_line") else "undated_observation", timestamp=timestamp, timestamp_source="observed.create_time" if timestamp else None, timestamp_semantics="command line observation associated with process create time" if timestamp else "raw memory observation without occurrence timestamp")
        elif doc_type == "memory_network_connection":
            event = _base_memory_event(case_id, evidence_id, run_id, doc, artifact_family="network", event_kind="network_connection", timestamp=doc.get("create_time"), timestamp_source="create_time", timestamp_semantics="network connection creation time reported by plugin")
        elif doc_type == "memory_suspicious_region":
            event = _base_memory_event(case_id, evidence_id, run_id, doc, artifact_family="suspicious", event_kind="suspicious_memory", timestamp=doc.get("create_time"), timestamp_source="create_time", timestamp_semantics="suspicious memory observation timestamp when reported by source")
        else:
            event = _base_memory_event(case_id, evidence_id, run_id, doc, artifact_family=_memory_family(doc_type), event_kind=_undated_kind(doc_type), timestamp=None, timestamp_source=None, timestamp_semantics="memory artifact has no reliable occurrence timestamp")
        (undated if event["is_undated"] else events).append(event)
    return events, undated


def _base_memory_event(case_id: str, evidence_id: str, run_id: str | None, doc: dict[str, Any], *, artifact_family: str, event_kind: str, timestamp: Any, timestamp_source: str | None, timestamp_semantics: str) -> dict[str, Any]:
    process = doc.get("process") if isinstance(doc.get("process"), dict) else {}
    observed = doc.get("observed") if isinstance(doc.get("observed"), dict) else {}
    occurred_at, precision, tz_label = _normalize_timestamp(timestamp)
    pid = doc.get("pid", process.get("pid", observed.get("pid")))
    ppid = process.get("ppid", observed.get("ppid"))
    process_name = doc.get("process_name") or process.get("name") or observed.get("name")
    source_plugin = doc.get("source_plugin") or doc.get("plugin_name") or ",".join(doc.get("source_plugins") or [])
    title = _memory_title(event_kind, doc, process, observed)
    return {
        "event_id": _stable_id("timeline", case_id, evidence_id, run_id, doc.get("document_id"), event_kind, timestamp_source or "undated"),
        "case_id": case_id,
        "evidence_id": evidence_id,
        "memory_context_id": run_id,
        "memory_run_id": doc.get("scan_run_id") or run_id,
        "artifact_type": doc.get("document_type") or doc.get("memory_artifact_type"),
        "artifact_family": artifact_family,
        "event_kind": event_kind,
        "occurred_at": occurred_at,
        "occurred_at_end": None,
        "timestamp_source": timestamp_source,
        "timestamp_semantics": timestamp_semantics,
        "timestamp_precision": precision,
        "timestamp_confidence": "observed" if occurred_at else "unknown",
        "timestamp_timezone": tz_label,
        "is_undated": occurred_at is None,
        "process_entity_id": doc.get("process_entity_id"),
        "pid": pid,
        "ppid": ppid,
        "process_name": process_name,
        "executable_path": process.get("executable_path") or process.get("path") or doc.get("path"),
        "command_line_summary": _clip(process.get("command_line") or observed.get("command_line")),
        "local_endpoint": _endpoint(doc.get("local_address"), doc.get("local_port")),
        "remote_endpoint": _endpoint(doc.get("remote_address"), doc.get("remote_port")),
        "source_plugin": source_plugin,
        "source_parser": None,
        "title": title,
        "summary": _memory_summary(doc, process, observed),
        "provenance": doc.get("provenance") or {"document_id": doc.get("document_id"), "scan_run_id": doc.get("scan_run_id"), "source_plugin": source_plugin},
        "raw_reference": {"document_id": doc.get("document_id"), "plugin_run_id": doc.get("plugin_run_id"), "source_record_index": doc.get("source_record_index")},
        "navigation_target": {"tab": _nav_tab(artifact_family), "target_tab": _nav_tab(artifact_family), "artifact_id": doc.get("document_id"), "artifact_type": doc.get("document_type"), "run_id": doc.get("scan_run_id") or run_id, "evidence_id": evidence_id, "process_entity_id": doc.get("process_entity_id"), "pid": pid},
        "normalization_warnings": [doc.get("normalization_warning")] if doc.get("normalization_warning") else [],
        "correlations": [],
    }


def _disk_events(case_id: str, docs: list[dict[str, Any]]) -> list[dict[str, Any]]:
    events: list[dict[str, Any]] = []
    for doc in docs:
        timestamp = doc.get("@timestamp")
        occurred_at, precision, tz_label = _normalize_timestamp(timestamp)
        family, kind, semantics = _disk_family_kind(doc)
        event_id = doc.get("stable_event_id") or doc.get("event_fingerprint") or doc.get("_id")
        process = doc.get("process") if isinstance(doc.get("process"), dict) else {}
        parent = process.get("parent") if isinstance(process.get("parent"), dict) else {}
        events.append({"event_id": _stable_id("timeline-disk", case_id, event_id, kind), "case_id": case_id, "evidence_id": doc.get("evidence_id"), "memory_context_id": None, "memory_run_id": None, "artifact_type": _get(doc, "artifact.type") or family, "artifact_family": family, "event_kind": kind, "occurred_at": occurred_at, "occurred_at_end": None, "timestamp_source": "@timestamp", "timestamp_semantics": semantics, "timestamp_precision": precision, "timestamp_confidence": "observed" if occurred_at else "unknown", "timestamp_timezone": tz_label, "is_undated": occurred_at is None, "process_entity_id": None, "pid": _get(doc, "process.pid"), "ppid": parent.get("pid") or _get(doc, "process.parent_pid"), "process_name": _get(doc, "process.name"), "executable_path": _first(doc, ["process.path", "file.path", "service.image_path", "autoruns.image_path", "shimcache.path", "appcompat.path"]), "command_line_summary": _clip(_first(doc, ["process.command_line", "powershell.command", "task.command", "autoruns.command_line", "registry.value_data"])), "local_endpoint": _endpoint(_first(doc, ["source.ip", "network.source_ip"]), _first(doc, ["source.port", "network.source_port"])), "remote_endpoint": _endpoint(_first(doc, ["destination.ip", "network.destination_ip"]), _first(doc, ["destination.port", "network.destination_port"])), "source_plugin": None, "source_parser": _get(doc, "artifact.parser"), "title": _disk_title(kind, doc), "summary": _clip(_first(doc, ["event.message", "raw_summary", "search_text", "process.command_line", "powershell.command", "file.path"])), "provenance": {"stable_event_id": event_id, "index": get_events_index(), "parser": _get(doc, "artifact.parser")}, "raw_reference": {"stable_event_id": event_id, "opensearch_id": doc.get("_id")}, "navigation_target": {"tab": "search", "target_tab": "search", "event_id": event_id, "evidence_id": doc.get("evidence_id")}, "normalization_warnings": [], "correlations": []})
    return events


def _build_correlations(memory_events: list[dict[str, Any]], disk_events: list[dict[str, Any]], *, include_low: bool = False) -> list[dict[str, Any]]:
    correlations: list[dict[str, Any]] = []
    rejected = 0
    for mem in memory_events:
        for disk in disk_events:
            corr = _correlate_pair(mem, disk)
            if not corr:
                rejected += 1
                continue
            corr["rejected_candidates_seen"] = rejected
            if corr["confidence"] == LOW_CONFIDENCE and not include_low:
                continue
            correlations.append(corr)
    return correlations


def _correlate_pair(mem: dict[str, Any], disk: dict[str, Any]) -> dict[str, Any] | None:
    if mem.get("is_undated") or disk.get("is_undated"):
        return None
    reasons: list[str] = []
    matched: list[str] = []
    contradictions: list[str] = []
    delta = _time_delta(mem.get("occurred_at"), disk.get("occurred_at"))
    mem_name = _norm_name(mem.get("process_name"))
    disk_name = _norm_name(disk.get("process_name") or disk.get("executable_path") or disk.get("title"))
    mem_path = _norm_path(mem.get("executable_path") or _extract_executable(mem.get("command_line_summary")))
    disk_path = _norm_path(disk.get("executable_path") or _extract_executable(disk.get("command_line_summary")))
    if mem.get("pid") is not None and disk.get("pid") is not None and int(mem["pid"]) == int(disk["pid"]):
        reasons.append("same PID")
        matched.append("pid")
    elif mem.get("pid") is not None and disk.get("pid") is not None:
        contradictions.append("different PID")
    if mem_name and disk_name and mem_name == disk_name:
        reasons.append("same normalized process name")
        matched.append("process.name")
    elif mem_name and disk_name and _basename(disk_name) != mem_name:
        contradictions.append("mismatched process name")
    if mem_path and disk_path and mem_path == disk_path:
        reasons.append("same executable path")
        matched.append("path")
    elif mem_path and disk_path and _is_absolute_windows_path(mem_path) and _is_absolute_windows_path(disk_path):
        contradictions.append("mismatched executable path")
    elif mem_path and disk_path and _basename(mem_path) == _basename(disk_path):
        reasons.append("compatible executable name")
        matched.append("path")
    elif mem_path and disk_path and _basename(mem_path) != _basename(disk_path):
        contradictions.append("mismatched executable path")
    if mem.get("command_line_summary") and disk.get("command_line_summary") and _norm_text(mem["command_line_summary"]) == _norm_text(disk["command_line_summary"]):
        reasons.append("matching command line")
        matched.append("command_line")
    if delta is not None:
        if delta <= 5:
            reasons.append(f"timestamps within {delta:.1f} seconds")
            matched.append("timestamp")
        elif delta <= 30:
            reasons.append(f"timestamps within {delta:.1f} seconds")
            matched.append("timestamp")
        elif disk.get("artifact_family") in {"prefetch", "amcache", "shimcache", "registry_persistence"}:
            reasons.append(f"timestamp delta {delta:.1f} seconds; executable-level relationship only")
        else:
            contradictions.append("incompatible timestamps")
    if contradictions and any(c in contradictions for c in ("mismatched executable path", "incompatible timestamps")):
        return None
    non_pid_matches = [m for m in matched if m != "pid"]
    if not non_pid_matches:
        return None
    confidence = _confidence(matched, delta, disk.get("artifact_family"), contradictions)
    if disk.get("artifact_family") in {"prefetch", "amcache", "shimcache", "registry_persistence"}:
        reasons.append("executable-level relationship only; not exact process-instance proof")
    if confidence == "low":
        reasons.append("weak match hidden by default")
    ctype = _correlation_type(disk.get("artifact_family"), disk.get("event_kind"))
    return {"correlation_id": _stable_id("corr", mem["event_id"], disk["event_id"], ctype), "left_artifact_id": mem["event_id"], "right_artifact_id": disk["event_id"], "left_artifact_type": mem["artifact_type"], "right_artifact_type": disk["artifact_type"], "process_entity_id": mem.get("process_entity_id"), "correlation_type": ctype, "confidence": confidence, "confidence_score": {"exact": 100, "high": 85, "medium": 60, "low": 30}[confidence], "reasons": reasons, "matched_fields": matched, "time_delta_seconds": delta, "contradictory_fields": contradictions, "source_provenance": {"memory": mem.get("provenance"), "disk": disk.get("provenance")}, "created_by_rule_version": CORRELATION_RULE_VERSION, "navigation_targets": {"memory": mem.get("navigation_target"), "disk": disk.get("navigation_target")}, "left_artifact": mem, "right_artifact": disk}


def _filter_events(items: list[dict[str, Any]], **kwargs: Any) -> list[dict[str, Any]]:
    out = []
    start = _parse_dt(kwargs.get("time_from"))
    end = _parse_dt(kwargs.get("time_to"))
    families = set(kwargs.get("artifact_families") or [])
    kinds = set(kwargs.get("event_kinds") or [])
    conf = kwargs.get("correlation_confidence")
    for item in items:
        if item.get("is_undated") and not kwargs.get("include_undated"):
            continue
        dt = _parse_dt(item.get("occurred_at"))
        if start and dt and dt < start:
            continue
        if end and dt and dt > end:
            continue
        if families and item.get("artifact_family") not in families:
            continue
        if kinds and item.get("event_kind") not in kinds:
            continue
        if kwargs.get("has_correlations") is True and not item.get("correlations"):
            continue
        if kwargs.get("has_correlations") is False and item.get("correlations"):
            continue
        if conf and not any(c.get("confidence") == conf for c in item.get("correlations", [])):
            continue
        out.append(item)
    return out


def _bounded_correlations(correlations: list[dict[str, Any]], confidence: str | None) -> list[dict[str, Any]]:
    result = []
    for corr in correlations:
        if corr.get("confidence") == LOW_CONFIDENCE and confidence != LOW_CONFIDENCE:
            continue
        if confidence and corr.get("confidence") != confidence:
            continue
        result.append({k: v for k, v in corr.items() if k not in {"left_artifact", "right_artifact"}})
    return result[:5]


def _normalize_timestamp(value: Any) -> tuple[str | None, str, str]:
    if value in (None, "", "N/A"):
        return None, "unknown", "unknown"
    try:
        dt = date_parser.parse(str(value))
    except Exception:
        return None, "unknown", "unparseable"
    tz_label = "source_timezone_unknown" if dt.tzinfo is None else str(dt.tzinfo)
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=UTC)
    return dt.astimezone(UTC).isoformat().replace("+00:00", "Z"), _precision(str(value)), tz_label


def _precision(raw: str) -> str:
    text = raw.strip()
    if re.search(r"\d{2}:\d{2}:\d{2}", text):
        return "second"
    if re.fullmatch(r"\d{4}-\d{2}-\d{2}", text):
        return "day"
    if re.fullmatch(r".*\d{2}:\d{2}(?:Z|[+-]\d{2}:?\d{2})?", text):
        return "minute"
    return "exact"


def _active_run_id(db: Session, case_id: str, evidence_id: str) -> str | None:
    resolved = resolve_active_memory_result(db, case_id=case_id, evidence_id=evidence_id, family="processes")
    run = resolved.get("active_run") if isinstance(resolved, dict) else None
    return run.get("id") if isinstance(run, dict) else None


def _evidence_payload(db: Session, evidence_id: str) -> dict[str, Any] | None:
    evidence = db.get(Evidence, evidence_id)
    if not evidence:
        return None
    return {"id": evidence.id, "case_id": evidence.case_id, "name": getattr(evidence, "filename", None) or getattr(evidence, "original_filename", None) or evidence.id}


def _bounded_page(page: int, page_size: int) -> tuple[int, int]:
    page = max(int(page or 1), 1)
    page_size = int(page_size or 100)
    return page, page_size if page_size in PAGE_SIZES else 100


def _stable_id(*parts: Any) -> str:
    return hashlib.sha256("|".join(str(p) for p in parts).encode()).hexdigest()[:32]


def _any_term(fields: list[str], value: Any) -> dict[str, Any]:
    expanded = []
    for field in fields:
        expanded.append(field)
        if isinstance(value, str) and not field.endswith(".keyword"):
            expanded.append(f"{field}.keyword")
    return {"bool": {"should": [{"term": {field: value}} for field in expanded], "minimum_should_match": 1}}


def _get(doc: dict[str, Any], dotted: str) -> Any:
    cur: Any = doc
    for part in dotted.split("."):
        if not isinstance(cur, dict):
            return None
        cur = cur.get(part)
    return cur


def _first(doc: dict[str, Any], fields: list[str]) -> Any:
    for field in fields:
        value = _get(doc, field)
        if value not in (None, ""):
            return value
    return None


def _parse_dt(value: Any) -> datetime | None:
    if not value:
        return None
    try:
        dt = date_parser.parse(str(value).replace("Z", "+00:00"))
    except Exception:
        return None
    return dt if dt.tzinfo else dt.replace(tzinfo=UTC)


def _time_delta(left: Any, right: Any) -> float | None:
    ldt, rdt = _parse_dt(left), _parse_dt(right)
    if not ldt or not rdt:
        return None
    return abs((ldt - rdt).total_seconds())


def _sort_key(event: dict[str, Any]) -> str:
    return event.get("occurred_at") or "9999-12-31T23:59:59Z"


def _counts(items: list[dict[str, Any]], field: str) -> dict[str, int]:
    counts: dict[str, int] = {}
    for item in items:
        key = str(item.get(field) or "unknown")
        counts[key] = counts.get(key, 0) + 1
    return counts


def _timestamp_quality(events: list[dict[str, Any]], undated: list[dict[str, Any]]) -> dict[str, int]:
    out = {"timestamped": len(events), "undated": len(undated), "exact": 0, "second": 0, "minute": 0, "day": 0, "unknown": len(undated)}
    for event in events:
        key = event.get("timestamp_precision") or "unknown"
        out[key] = out.get(key, 0) + 1
    return out


def _coverage(memory_docs: list[dict[str, Any]], disk_docs: list[dict[str, Any]], events: list[dict[str, Any]], undated: list[dict[str, Any]], correlations: list[dict[str, Any]]) -> dict[str, Any]:
    return {"memory_artifact_families_available": sorted({_memory_family(d.get("document_type")) for d in memory_docs}), "disk_artifact_families_available": sorted({_disk_family_kind(d)[0] for d in disk_docs}), "timestamped_row_counts": _counts(events, "artifact_family"), "undated_row_counts": _counts(undated, "artifact_family"), "correlated_row_counts": _counts(correlations, "confidence"), "rejected_correlation_candidates": max(0, len(memory_docs) * len(disk_docs) - len(correlations)), "correlation_rule_versions": [CORRELATION_RULE_VERSION], "historical_compatibility_warnings": []}


def _memory_family(doc_type: str | None) -> str:
    return {"memory_process_entity": "processes", "memory_process_observation": "raw_observations", "memory_network_connection": "network", "memory_process_module": "modules", "memory_handle": "handles", "memory_suspicious_region": "suspicious", "memory_vad": "vads", "memory_driver": "drivers", "memory_kernel_module": "kernel", "memory_system_info": "system"}.get(doc_type or "", "memory")


def _undated_kind(doc_type: str | None) -> str:
    return {"memory_process_module": "module_load", "memory_handle": "undated_observation", "memory_vad": "vad_observation", "memory_driver": "driver_observation", "memory_kernel_module": "kernel_module_observation"}.get(doc_type or "", "undated_observation")


def _disk_family_kind(doc: dict[str, Any]) -> tuple[str, str, str]:
    artifact = str(_get(doc, "artifact.type") or "").lower()
    parser = str(_get(doc, "artifact.parser") or "").lower()
    event_id = _get(doc, "windows.event_id")
    if str(event_id) in {"4688", "1"}:
        return "event_logs", "event_log_process_creation", "event log process creation time"
    if "powershell" in artifact or "powershell" in parser or _get(doc, "powershell.command"):
        return "powershell", "powershell_execution", "PowerShell event timestamp"
    if "prefetch" in artifact or "prefetch" in parser:
        return "prefetch", "prefetch_execution", "Prefetch execution timestamp; executable-level evidence"
    if "amcache" in artifact or "amcache" in parser:
        return "amcache", "amcache_observation", "Amcache observation timestamp"
    if "shimcache" in artifact or "appcompat" in artifact or "shimcache" in parser or "appcompat" in parser:
        return "shimcache", "shimcache_observation", "Shimcache/AppCompat observation timestamp; not execution proof"
    if _get(doc, "service.image_path") or str(event_id) in {"4697", "7045"}:
        return "services", "service_execution", "service event timestamp"
    if _get(doc, "task.command") or str(event_id) in {"4698", "4702"}:
        return "scheduled_tasks", "scheduled_task_execution", "scheduled task event timestamp"
    if _get(doc, "autoruns.command_line") or _get(doc, "registry.value_data"):
        return "registry_persistence", "registry_persistence", "registry persistence configuration timestamp"
    if _get(doc, "network.destination_ip") or _get(doc, "dns.domain"):
        return "network_logs", "network_log_event", "network/DNS/firewall event timestamp"
    return "disk", "disk_observation", "disk artifact timestamp"


def _correlation_type(family: str | None, kind: str | None) -> str:
    if kind == "event_log_process_creation":
        return "memory_process_to_event_log_process_creation"
    if family == "prefetch":
        return "memory_process_to_prefetch_executable"
    if family == "amcache":
        return "memory_process_to_amcache_file"
    if family == "shimcache":
        return "memory_process_to_shimcache_observation"
    if family == "powershell":
        return "memory_process_to_powershell_event"
    if family == "services":
        return "memory_process_to_service"
    if family == "scheduled_tasks":
        return "memory_process_to_scheduled_task"
    if family == "registry_persistence":
        return "memory_process_to_registry_persistence"
    if family == "network_logs":
        return "memory_network_to_network_log"
    return "memory_to_disk_artifact"


def _confidence(matched: list[str], delta: float | None, family: str | None, contradictions: list[str]) -> str:
    non_pid = len([m for m in matched if m != "pid"])
    if contradictions:
        return "medium" if non_pid >= 2 else "low"
    if family in {"prefetch", "shimcache", "amcache", "registry_persistence"}:
        return "high" if non_pid >= 2 else "medium"
    if non_pid >= 2 and delta is not None and delta <= 5:
        return "exact"
    if non_pid >= 2 and (delta is None or delta <= 30):
        return "high"
    if non_pid >= 1 and delta is not None and delta <= 30:
        return "medium"
    return "low"


def _memory_title(kind: str, doc: dict[str, Any], process: dict[str, Any], observed: dict[str, Any]) -> str:
    name = doc.get("process_name") or process.get("name") or observed.get("name") or "process"
    if kind == "process_start":
        return f"Process started: {name}"
    if kind == "process_exit":
        return f"Process exited: {name}"
    if kind == "network_connection":
        return f"{doc.get('protocol') or 'network'} connection"
    if kind == "command_line":
        return f"Command line observed: {name}"
    return str(doc.get("document_type") or "Memory artifact")


def _memory_summary(doc: dict[str, Any], process: dict[str, Any], observed: dict[str, Any]) -> str:
    parts = [process.get("command_line"), observed.get("command_line"), doc.get("path"), doc.get("object_name"), doc.get("description"), doc.get("connection_state") or doc.get("state")]
    return _clip(" | ".join(str(p) for p in parts if p)) or ""


def _disk_title(kind: str, doc: dict[str, Any]) -> str:
    if kind == "event_log_process_creation":
        return f"Windows process creation event: {_get(doc, 'process.name') or 'process'}"
    if kind == "powershell_execution":
        return "PowerShell event"
    return str(_get(doc, "artifact.type") or kind).replace("_", " ")


def _endpoint(address: Any, port: Any) -> dict[str, Any] | None:
    if address in (None, "") and port in (None, ""):
        return None
    return {"address": address, "port": port}


def _clip(value: Any, limit: int = 512) -> str | None:
    if value in (None, ""):
        return None
    return str(value)[:limit]


def _nav_tab(family: str) -> str:
    return {"processes": "processes", "raw_observations": "raw", "network": "artifacts", "modules": "artifacts", "handles": "artifacts", "suspicious": "artifacts", "vads": "artifacts", "drivers": "artifacts", "kernel": "artifacts", "system": "system"}.get(family, "artifacts")


def _norm_name(value: Any) -> str | None:
    if not value:
        return None
    text = str(value).lower().strip().strip('"')
    return text.rsplit("\\", 1)[-1].rsplit("/", 1)[-1]


def _norm_path(value: Any) -> str | None:
    if not value:
        return None
    text = str(value).lower().strip().strip('"')
    return text.replace("/", "\\")


def _basename(path: str | None) -> str | None:
    if not path:
        return None
    return path.rsplit("\\", 1)[-1].rsplit("/", 1)[-1]


def _norm_text(value: Any) -> str | None:
    if not value:
        return None
    return re.sub(r"\s+", " ", str(value).lower().strip())


def _extract_executable(value: Any) -> str | None:
    if not value:
        return None
    text = str(value).strip()
    if text.startswith('"') and '"' in text[1:]:
        return text[1:].split('"', 1)[0]
    match = re.search(r"[A-Za-z]:\\[^\s]+?\.exe", text, flags=re.IGNORECASE)
    if match:
        return match.group(0)
    first = text.split()[0] if text.split() else text
    return first if first.lower().endswith(".exe") else None


def _is_absolute_windows_path(value: str | None) -> bool:
    return bool(value and re.match(r"^[a-z]:\\", value, flags=re.IGNORECASE))
