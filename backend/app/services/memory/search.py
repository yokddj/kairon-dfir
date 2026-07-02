from __future__ import annotations

from dataclasses import dataclass
from ipaddress import ip_address
import re
from typing import Any

from sqlalchemy.orm import Session

from app.core.opensearch import get_memory_index, get_opensearch_client
from app.models.evidence import Evidence
from app.models.memory import MemoryScanRun
from app.services.memory.active_result import resolve_active_memory_result
from app.services.memory.artifact_indexing import _prepare_artifact_document_for_response


PAGE_SIZES = {50, 100, 250, 500}


@dataclass(frozen=True)
class FamilySpec:
    family: str
    document_type: str
    active_family: str
    title_fields: tuple[str, ...]
    summary_fields: tuple[str, ...]
    text_fields: tuple[str, ...]
    exact_fields: tuple[str, ...]
    numeric_fields: tuple[str, ...] = ()
    timestamp_fields: tuple[str, ...] = ()


FAMILY_SPECS: dict[str, FamilySpec] = {
    "processes": FamilySpec("processes", "memory_process_entity", "processes", ("process.name",), ("process.command_line",), ("process.name.text", "process.command_line"), ("process_entity_id", "source_plugins", "confidence"), ("process.pid", "process.ppid"), ("process.create_time", "process.exit_time")),
    "command_lines": FamilySpec("command_lines", "memory_process_entity", "processes", ("process.name",), ("process.command_line",), ("process.command_line", "process.name.text"), ("process_entity_id", "source_plugins"), ("process.pid", "process.ppid"), ("process.create_time",)),
    "raw_observations": FamilySpec("raw_observations", "memory_process_observation", "processes", ("observed.name",), ("observed.command_line",), ("observed.name", "observed.command_line"), ("process_entity_id", "plugin_name", "confidence"), ("observed.pid", "observed.ppid"), ("observed.create_time", "observed.exit_time")),
    "network": FamilySpec("network", "memory_network_connection", "network", ("process_name", "protocol"), ("local_address", "remote_address", "connection_state"), ("process_name.text",), ("protocol", "connection_state", "source_plugin", "process_entity_id"), ("pid", "local_port", "remote_port"), ("create_time",)),
    "environment": FamilySpec("environment", "memory_environment_variable", "raw_observations", ("variable",), ("value", "process_name"), ("variable", "value", "process_name.text"), ("variable", "source_plugin"), ("pid",)),
    "sids": FamilySpec("sids", "memory_sid", "raw_observations", ("sid",), ("resolved_name", "process_name"), ("resolved_name", "process_name.text"), ("sid", "source_plugin"), ("pid",)),
    "privileges": FamilySpec("privileges", "memory_privilege", "raw_observations", ("privilege",), ("description", "process_name"), ("privilege", "description", "process_name.text"), ("privilege", "source_plugin"), ("pid",)),
    "modules": FamilySpec("modules", "memory_process_module", "modules", ("module_name",), ("path", "process_name"), ("module_name.text", "path", "process_name.text"), ("module_name", "load_state", "findings", "source_plugins", "process_entity_id"), ("pid", "base_address")),
    "handles": FamilySpec("handles", "memory_handle", "handles", ("object_type",), ("object_name", "process_name"), ("object_name", "object_type", "process_name.text"), ("object_type", "source_plugin", "process_entity_id"), ("pid", "handle_value", "granted_access")),
    "kernel": FamilySpec("kernel", "memory_kernel_module", "kernel_modules", ("module_name",), ("path",), ("module_name.text", "path"), ("module_name", "source_plugin"), ("base_address", "size")),
    "drivers": FamilySpec("drivers", "memory_driver", "drivers", ("driver_name",), ("service_key",), ("driver_name.text", "service_key"), ("driver_name", "source_plugin"), ("start_address", "size")),
    "suspicious": FamilySpec("suspicious", "memory_suspicious_region", "suspicious_regions", ("process_name", "protection"), ("disassembly_preview_bounded", "hexdump_preview_bounded"), ("process_name.text", "protection", "tag", "disassembly_preview_bounded", "hexdump_preview_bounded"), ("protection", "tag", "review_status", "source_plugin", "process_entity_id"), ("pid",), ("create_time",)),
    "vads": FamilySpec("vads", "memory_vad", "suspicious_regions", ("process_name", "protection"), ("file_object", "tag"), ("process_name.text", "protection", "tag", "file_object"), ("protection", "tag", "source_plugin", "process_entity_id"), ("pid",)),
    "system": FamilySpec("system", "memory_system_info", "system_info", ("kernel_base",), ("os", "build"), ("os", "build", "kernel"), ("source_plugin",), (), ()),
}

DOC_TYPE_TO_FAMILY: dict[str, str] = {}
for spec in FAMILY_SPECS.values():
    DOC_TYPE_TO_FAMILY.setdefault(spec.document_type, spec.family)
SUPPORTED_FAMILIES = tuple(FAMILY_SPECS.keys())
SID_RE = re.compile(r"^S-\d(?:-\d+){1,}$", re.IGNORECASE)


def search_memory_artifacts(
    db: Session,
    *,
    case_id: str,
    evidence_id: str,
    query: str | None = None,
    artifact_types: list[str] | None = None,
    run_id: str | None = None,
    page: int = 1,
    page_size: int = 100,
    sort: str = "relevance",
    pid: int | None = None,
    ppid: int | None = None,
    process_name: str | None = None,
    source_plugin: str | None = None,
    protocol: str | None = None,
    state: str | None = None,
    local_address: str | None = None,
    local_port: int | None = None,
    remote_address: str | None = None,
    remote_port: int | None = None,
    time_from: str | None = None,
    time_to: str | None = None,
    has_process: bool | None = None,
    warnings_only: bool = False,
    mixed_run: bool = False,
) -> dict[str, Any]:
    page_size = int(page_size or 100)
    if page_size not in PAGE_SIZES:
        page_size = 100
    page = max(int(page or 1), 1)
    families = _selected_families(artifact_types)
    evidence = db.get(Evidence, evidence_id)
    run_context = _resolve_run_context(db, case_id=case_id, evidence_id=evidence_id, families=families, run_id=run_id, mixed_run=mixed_run)

    filters: list[dict[str, Any]] = [{"term": {"evidence_id": evidence_id}}]
    scope_filter = _scope_filter(run_context)
    if scope_filter:
        filters.append(scope_filter)
    filters.extend(_explicit_filters(pid=pid, ppid=ppid, process_name=process_name, source_plugin=source_plugin, protocol=protocol, state=state, local_address=local_address, local_port=local_port, remote_address=remote_address, remote_port=remote_port, has_process=has_process, time_from=time_from, time_to=time_to, warnings_only=warnings_only))
    must, interpretation = _query_clauses(query, families)
    body: dict[str, Any] = {
        "query": {"bool": {"filter": filters, "must": must}},
        "from": (page - 1) * page_size,
        "size": page_size,
        "track_total_hits": True,
        "timeout": "8s",
        "sort": _sort(sort),
        "aggs": _aggs(),
        "highlight": {"fields": _highlight_fields(families), "fragment_size": 120, "number_of_fragments": 2},
    }
    client = get_opensearch_client()
    response = client.search(index=get_memory_index(case_id), body=body, params={"ignore_unavailable": "true"})
    hits = response.get("hits", {})
    total = hits.get("total", {})
    total_value = int(total.get("value", 0) if isinstance(total, dict) else total or 0)
    results = [_result_from_hit(hit, evidence_name=getattr(evidence, "filename", None) or getattr(evidence, "name", None) or str(evidence_id), families=families) for hit in hits.get("hits", [])]
    coverage = _coverage(db, case_id=case_id, evidence_id=evidence_id, families=families, run_context=run_context, total=total_value)
    return {
        "case_id": case_id,
        "evidence_id": evidence_id,
        "evidence_name": getattr(evidence, "filename", None) or getattr(evidence, "name", None),
        "query": query or "",
        "query_interpretation": interpretation,
        "selected_run_context": run_context,
        "total": total_value,
        "page": page,
        "page_size": page_size,
        "total_pages": (total_value + page_size - 1) // page_size if total_value else 0,
        "sort": sort,
        "results": results,
        "facets": _facets(response.get("aggregations", {})),
        "coverage": coverage,
        "warnings": [],
    }


def _selected_families(raw: list[str] | None) -> list[str]:
    if not raw:
        return list(SUPPORTED_FAMILIES)
    selected: list[str] = []
    aliases: dict[str, str] = {}
    for name, spec in FAMILY_SPECS.items():
        aliases.setdefault(spec.document_type, name)
    for item in raw:
        key = item.strip()
        key = aliases.get(key, key)
        if key in FAMILY_SPECS and key not in selected:
            selected.append(key)
    return selected or list(SUPPORTED_FAMILIES)


def _resolve_run_context(db: Session, *, case_id: str, evidence_id: str, families: list[str], run_id: str | None, mixed_run: bool) -> dict[str, Any]:
    if run_id:
        run = db.get(MemoryScanRun, run_id)
        return {"mode": "historical_run", "mixed_run": False, "runs": {family: _run_payload(run) for family in families if run and run.case_id == case_id and run.evidence_id == evidence_id}, "contributing_runs": [run_id]}
    runs: dict[str, Any] = {}
    contributing: list[str] = []
    for family in families:
        active_family = FAMILY_SPECS[family].active_family
        resolved = resolve_active_memory_result(db, case_id=case_id, evidence_id=evidence_id, family=active_family)
        run = resolved.get("active_run") if isinstance(resolved, dict) else None
        runs[family] = run
        if isinstance(run, dict) and run.get("id") and run["id"] not in contributing:
            contributing.append(run["id"])
    return {"mode": "per_family_active", "mixed_run": bool(mixed_run), "runs": runs, "contributing_runs": contributing}


def _run_payload(run: MemoryScanRun | None) -> dict[str, Any] | None:
    if run is None:
        return None
    return {"id": str(run.id), "profile": run.profile, "status": run.status, "evidence_id": run.evidence_id}


def _scope_filter(run_context: dict[str, Any]) -> dict[str, Any] | None:
    runs = run_context.get("runs") or {}
    should = []
    for family, run in runs.items():
        run_id = run.get("id") if isinstance(run, dict) else None
        if not run_id:
            continue
        should.append({"bool": {"filter": [_any_term(["document_type"], FAMILY_SPECS[family].document_type), {"term": {"scan_run_id.keyword": run_id}}]}})
    if not should:
        return {"terms": {"document_type": []}}
    return {"bool": {"should": should, "minimum_should_match": 1}}


def _explicit_filters(**kwargs: Any) -> list[dict[str, Any]]:
    filters: list[dict[str, Any]] = []
    if kwargs.get("pid") is not None:
        filters.append(_any_term(["pid", "process.pid", "observed.pid"], kwargs["pid"]))
    if kwargs.get("ppid") is not None:
        filters.append(_any_term(["process.ppid", "observed.ppid"], kwargs["ppid"]))
    if kwargs.get("process_name"):
        filters.append(_any_term(["process_name", "process.name", "observed.name"], kwargs["process_name"]))
    if kwargs.get("source_plugin"):
        filters.append(_any_term(["source_plugin", "source_plugins", "plugin_name"], kwargs["source_plugin"]))
    for field in ("protocol", "local_address", "local_port", "remote_address", "remote_port"):
        if kwargs.get(field) is not None:
            filters.append(_any_term([field], kwargs[field]))
    if kwargs.get("state"):
        filters.append(_any_term(["connection_state", "state"], kwargs["state"]))
    if kwargs.get("has_process") is True:
        filters.append({"exists": {"field": "process_entity_id"}})
    if kwargs.get("has_process") is False:
        filters.append({"bool": {"must_not": [{"exists": {"field": "process_entity_id"}}]}})
    if kwargs.get("warnings_only"):
        filters.append({"exists": {"field": "normalization_warning"}})
    if kwargs.get("time_from") or kwargs.get("time_to"):
        range_filter: dict[str, Any] = {}
        if kwargs.get("time_from"):
            range_filter["gte"] = kwargs["time_from"]
        if kwargs.get("time_to"):
            range_filter["lte"] = kwargs["time_to"]
        filters.append({"bool": {"should": [{"range": {field: range_filter}} for field in ("process.create_time", "observed.create_time", "create_time")], "minimum_should_match": 1}})
    return filters


def _query_clauses(query: str | None, families: list[str]) -> tuple[list[dict[str, Any]], str]:
    text = (query or "").strip()
    if not text:
        return [], "none"
    if SID_RE.match(text):
        return [_any_term(["sid"], text)], "sid"
    try:
        ip_address(text.strip("[]"))
        return [_any_term(["local_address", "remote_address"], text.strip("[]"))], "ip_address"
    except ValueError:
        pass
    if text.isdigit():
        value = int(text)
        return [_any_term(["pid", "process.pid", "observed.pid", "process.ppid", "observed.ppid", "local_port", "remote_port"], value)], "numeric_exact"
    fields: list[str] = []
    for family in families:
        fields.extend(FAMILY_SPECS[family].text_fields)
    return [{"multi_match": {"query": text, "fields": sorted(set(fields)), "type": "best_fields", "operator": "and", "lenient": True}}], "full_text"


def _any_term(fields: list[str], value: Any) -> dict[str, Any]:
    expanded: list[str] = []
    for field in fields:
        expanded.append(field)
        if isinstance(value, str) and not field.endswith(".keyword"):
            expanded.append(f"{field}.keyword")
    return {"bool": {"should": [{"term": {field: value}} for field in expanded], "minimum_should_match": 1}}


def _sort(sort: str) -> list[dict[str, Any]]:
    if sort == "newest":
        return [{"create_time": {"order": "desc", "missing": "_last", "unmapped_type": "date"}}, {"process.create_time": {"order": "desc", "missing": "_last", "unmapped_type": "date"}}, {"document_id": {"order": "asc"}}]
    if sort == "oldest":
        return [{"create_time": {"order": "asc", "missing": "_last", "unmapped_type": "date"}}, {"process.create_time": {"order": "asc", "missing": "_last", "unmapped_type": "date"}}, {"document_id": {"order": "asc"}}]
    if sort == "artifact_type":
        return [{"document_type.keyword": {"order": "asc", "unmapped_type": "keyword"}}, {"document_id": {"order": "asc"}}]
    if sort == "pid":
        return [{"pid": {"order": "asc", "missing": "_last", "unmapped_type": "long"}}, {"process.pid": {"order": "asc", "missing": "_last", "unmapped_type": "long"}}, {"document_id": {"order": "asc"}}]
    if sort == "process_name":
        return [{"process_name.keyword": {"order": "asc", "missing": "_last", "unmapped_type": "keyword"}}, {"process.name": {"order": "asc", "missing": "_last", "unmapped_type": "keyword"}}, {"document_id": {"order": "asc"}}]
    return ["_score", {"document_id": {"order": "asc"}}]


def _aggs() -> dict[str, Any]:
    return {
        "artifact_type": {"terms": {"field": "document_type.keyword", "size": 20}},
        "source_plugin": {"terms": {"field": "source_plugin.keyword", "size": 20}},
        "plugin_name": {"terms": {"field": "plugin_name.keyword", "size": 20}},
        "process_name": {"terms": {"field": "process_name.keyword", "size": 20}},
        "protocol": {"terms": {"field": "protocol.keyword", "size": 20}},
        "network_state": {"terms": {"field": "connection_state.keyword", "size": 20}},
        "has_process": {"filters": {"filters": {"linked": {"exists": {"field": "process_entity_id"}}, "unlinked": {"bool": {"must_not": [{"exists": {"field": "process_entity_id"}}]}}}}},
    }


def _highlight_fields(families: list[str]) -> dict[str, Any]:
    fields: dict[str, Any] = {}
    for family in families:
        for field in FAMILY_SPECS[family].text_fields:
            fields[field] = {}
    return fields


def _facets(aggs: dict[str, Any]) -> dict[str, dict[str, int]]:
    facets: dict[str, dict[str, int]] = {}
    for name, payload in aggs.items():
        if "buckets" in payload and isinstance(payload["buckets"], list):
            facets[name] = {str(bucket.get("key")): int(bucket.get("doc_count") or 0) for bucket in payload["buckets"]}
        elif "buckets" in payload and isinstance(payload["buckets"], dict):
            facets[name] = {key: int(value.get("doc_count") or 0) for key, value in payload["buckets"].items()}
    return facets


def _result_from_hit(hit: dict[str, Any], *, evidence_name: str, families: list[str]) -> dict[str, Any]:
    src = _prepare_artifact_document_for_response(hit.get("_source", {}) | {"document_id": hit.get("_id")})
    doc_type = src.get("document_type") or src.get("memory_artifact_type") or "memory_artifact"
    family = DOC_TYPE_TO_FAMILY.get(doc_type, "memory")
    if doc_type == "memory_process_entity" and families == ["command_lines"]:
        family = "command_lines"
    process = src.get("process") if isinstance(src.get("process"), dict) else {}
    observed = src.get("observed") if isinstance(src.get("observed"), dict) else {}
    pid = src.get("pid", process.get("pid", observed.get("pid")))
    ppid = process.get("ppid", observed.get("ppid"))
    process_name = src.get("process_name") or process.get("name") or observed.get("name")
    entity_id = src.get("process_entity_id")
    timestamp = src.get("create_time") or process.get("create_time") or observed.get("create_time")
    title = _title(family, src, process, observed)
    summary = _summary(family, src, process, observed)
    matched_fields = list((hit.get("highlight") or {}).keys())
    return {
        "result_id": hit.get("_id") or src.get("document_id"),
        "artifact_type": doc_type,
        "artifact_family": family,
        "case_id": src.get("case_id"),
        "evidence_id": src.get("evidence_id"),
        "evidence_name": evidence_name,
        "memory_run_id": src.get("scan_run_id") or src.get("memory_run_id"),
        "plugin_run_id": src.get("plugin_run_id"),
        "profile_id": None,
        "source_plugin": src.get("source_plugin") or src.get("plugin_name") or ",".join(src.get("source_plugins") or []),
        "process_entity_id": entity_id,
        "pid": pid,
        "ppid": ppid,
        "process_name": process_name,
        "timestamp": timestamp,
        "timestamp_source": "create_time" if timestamp else None,
        "title": title,
        "summary": summary,
        "matched_fields": matched_fields,
        "matched_terms": [],
        "provenance": src.get("provenance") or {"document_id": src.get("document_id"), "scan_run_id": src.get("scan_run_id"), "source_plugin": src.get("source_plugin") or src.get("plugin_name")},
        "raw_reference": {"document_id": src.get("document_id"), "source_record_index": src.get("source_record_index"), "plugin_run_id": src.get("plugin_run_id")},
        "navigation_target": _navigation(family, src, entity_id, pid),
        "normalization_warning": src.get("normalization_warning"),
        "raw": _bounded_raw(src),
    }


def _title(family: str, src: dict[str, Any], process: dict[str, Any], observed: dict[str, Any]) -> str:
    if family == "network":
        return f"{src.get('protocol') or 'network'} {src.get('local_address')}:{src.get('local_port')} -> {src.get('remote_address')}:{src.get('remote_port')}"
    if family == "command_lines":
        return f"Command line: {process.get('name') or observed.get('name') or src.get('process_name') or 'process'}"
    for key in ("module_name", "object_name", "driver_name", "privilege", "sid", "variable", "process_name"):
        if src.get(key):
            return str(src[key])[:160]
    if process.get("name") or observed.get("name"):
        return str(process.get("name") or observed.get("name"))
    return str(src.get("document_type") or "Memory artifact")


def _summary(family: str, src: dict[str, Any], process: dict[str, Any], observed: dict[str, Any]) -> str:
    parts = []
    for value in (process.get("command_line"), observed.get("command_line"), src.get("value"), src.get("path"), src.get("object_name"), src.get("description"), src.get("file_object"), src.get("disassembly_preview_bounded"), src.get("hexdump_preview_bounded")):
        if value:
            parts.append(str(value))
    if not parts and family == "network":
        parts.append(str(src.get("connection_state") or src.get("state") or ""))
    return " | ".join(parts)[:512]


def _navigation(family: str, src: dict[str, Any], entity_id: str | None, pid: int | None) -> dict[str, Any]:
    tab = {
        "processes": "processes",
        "command_lines": "history",
        "raw_observations": "raw",
        "network": "artifacts",
        "modules": "artifacts",
        "handles": "artifacts",
        "kernel": "artifacts",
        "drivers": "artifacts",
        "suspicious": "artifacts",
        "vads": "artifacts",
        "environment": "processes",
        "sids": "processes",
        "privileges": "processes",
        "system": "system",
    }.get(family, "artifacts")
    return {"tab": tab, "target_tab": tab, "artifact_family": family, "artifact_type": src.get("document_type"), "artifact_id": src.get("document_id"), "run_id": src.get("scan_run_id"), "evidence_id": src.get("evidence_id"), "process_entity_id": entity_id, "pid": pid}


def _bounded_raw(src: dict[str, Any]) -> dict[str, Any]:
    blocked = {"source_fields", "observations"}
    out: dict[str, Any] = {}
    for key, value in src.items():
        if key in blocked:
            continue
        if isinstance(value, str):
            out[key] = value[:1024]
        elif isinstance(value, (int, float, bool)) or value is None:
            out[key] = value
        elif isinstance(value, dict):
            out[key] = {str(k): (v[:512] if isinstance(v, str) else v) for k, v in list(value.items())[:20]}
        elif isinstance(value, list):
            out[key] = value[:20]
    return out


def _coverage(db: Session, *, case_id: str, evidence_id: str, families: list[str], run_context: dict[str, Any], total: int) -> dict[str, Any]:
    available = []
    not_run = []
    for family in families:
        run = (run_context.get("runs") or {}).get(family)
        if isinstance(run, dict) and run.get("id"):
            available.append(family)
        else:
            not_run.append(family)
    return {"artifact_families_available": available, "families_not_run": not_run, "completed_empty": [], "raw_only_fallback": total == 0 and "raw_observations" in available, "normalization_warnings": [], "raw_only_families": ["raw_observations"] if total == 0 and "raw_observations" in available else [], "rejected_row_counts": {}}
