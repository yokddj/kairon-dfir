from __future__ import annotations

from datetime import datetime, timezone
import hashlib
from typing import Any


MAX_RAW_FIELDS = 80
MAX_RAW_VALUE_LENGTH = 512


def _utc_now() -> datetime:
    return datetime.now(timezone.utc)


def _bounded(value: Any) -> Any:
    if value is None or isinstance(value, (bool, int, float)):
        return value
    if isinstance(value, str):
        return value[:MAX_RAW_VALUE_LENGTH]
    return str(value)[:MAX_RAW_VALUE_LENGTH]


def _first_row(payload: Any) -> dict[str, Any]:
    if isinstance(payload, dict):
        if isinstance(payload.get("rows"), list) and payload["rows"]:
            row = payload["rows"][0]
            return row if isinstance(row, dict) else {}
        if isinstance(payload.get("data"), list) and payload["data"]:
            row = payload["data"][0]
            return row if isinstance(row, dict) else {}
        if isinstance(payload.get("treegrid"), dict):
            columns = payload["treegrid"].get("columns") or []
            rows = payload["treegrid"].get("rows") or []
            if columns and rows:
                first = rows[0]
                values = first.get("values") if isinstance(first, dict) else first
                if isinstance(values, list):
                    return {str(columns[index].get("name") if isinstance(columns[index], dict) else columns[index]): values[index] for index in range(min(len(columns), len(values)))}
        return payload
    if isinstance(payload, list) and payload:
        row = payload[0]
        return row if isinstance(row, dict) else {}
    return {}


def _lookup(row: dict[str, Any], *names: str) -> Any:
    normalized = {str(key).lower().replace(" ", "_").replace("-", "_"): value for key, value in row.items()}
    for name in names:
        key = name.lower().replace(" ", "_").replace("-", "_")
        if key in normalized:
            return normalized[key]
    return None


def _rows(payload: Any) -> list[dict[str, Any]]:
    if isinstance(payload, list):
        return [item for item in payload if isinstance(item, dict)]
    if isinstance(payload, dict):
        for key in ("rows", "data"):
            if isinstance(payload.get(key), list):
                return [item for item in payload[key] if isinstance(item, dict)]
        if isinstance(payload.get("treegrid"), dict):
            columns = payload["treegrid"].get("columns") or []
            rows = payload["treegrid"].get("rows") or []
            result = []
            for row in rows:
                values = row.get("values") if isinstance(row, dict) else row
                if isinstance(values, list):
                    result.append({str(columns[index].get("name") if isinstance(columns[index], dict) else columns[index]): values[index] for index in range(min(len(columns), len(values)))})
            return result
        return [payload]
    return []


def _int_or_none(value: Any) -> int | None:
    if value is None or value == "":
        return None
    try:
        return int(str(value), 0)
    except (TypeError, ValueError):
        return None


def _str_or_none(value: Any, limit: int = 512) -> str | None:
    if value is None:
        return None
    text = str(value).strip()
    return text[:limit] if text else None


def _identity(pid: int | None, offset: str | None, create_time: str | None) -> str:
    seed = f"{pid if pid is not None else 'nopid'}|{offset or 'nooffset'}|{create_time or 'notime'}"
    return hashlib.sha256(seed.encode("utf-8")).hexdigest()[:24]


def _process_from_row(row: dict[str, Any], plugin: str, *, command_limit: int = 16384, raw_limit: int = 65536) -> tuple[dict[str, Any] | None, list[str]]:
    warnings: list[str] = []
    pid = _int_or_none(_lookup(row, "PID", "Pid", "pid"))
    if pid is None:
        warnings.append("missing_or_invalid_pid")
        return None, warnings
    ppid = _int_or_none(_lookup(row, "PPID", "PPid", "ParentPID", "Parent Pid", "InheritedFromUniqueProcessId"))
    name = _str_or_none(_lookup(row, "ImageFileName", "Name", "Process", "Image"), 512)
    create_time = _str_or_none(_lookup(row, "CreateTime", "Create Time", "Created"), 128)
    exit_time = _str_or_none(_lookup(row, "ExitTime", "Exit Time", "Exited"), 128)
    offset = _str_or_none(_lookup(row, "Offset", "Offset(V)", "Offset(P)", "Offset(Virtual)", "Offset(Physical)"), 128)
    command_line = _str_or_none(_lookup(row, "Args", "CommandLine", "Command Line", "CmdLine"), command_limit)
    identity = _identity(pid, offset, create_time)
    return {
        "identity": identity,
        "plugins": [plugin],
        "process": {
            "pid": pid,
            "ppid": ppid,
            "name": name,
            "command_line": command_line,
            "create_time": create_time,
            "exit_time": exit_time,
            "session_id": _int_or_none(_lookup(row, "SessionId", "Session ID")),
            "wow64": _lookup(row, "Wow64", "IsWow64"),
        },
        "memory": {"offset": offset, "virtual_offset": _str_or_none(_lookup(row, "Offset(V)", "Offset(Virtual)"), 128), "physical_offset": _str_or_none(_lookup(row, "Offset(P)", "Offset(Physical)"), 128)},
        "visibility": {"pslist": plugin == "windows.pslist", "psscan": plugin == "windows.psscan", "pstree": plugin == "windows.pstree"},
        "state": {"active_candidate": exit_time is None, "terminated_candidate": exit_time is not None, "hidden_candidate": False},
        "warnings": warnings,
        "raw": {"fields": _raw_subset_limited(row, raw_limit)},
    }, warnings


def _raw_subset_limited(row: dict[str, Any], raw_limit: int) -> dict[str, Any]:
    raw: dict[str, Any] = {}
    total = 0
    for key, value in row.items():
        if len(raw) >= MAX_RAW_FIELDS or total >= raw_limit:
            break
        bounded = _bounded(value)
        total += len(str(bounded))
        raw[str(key)[:128]] = bounded
    return raw


def normalize_windows_pslist(payload: Any, **kwargs: Any) -> dict[str, Any]:
    return _normalize_process_plugin(payload, "windows.pslist", **kwargs)


def normalize_windows_pstree(payload: Any, **kwargs: Any) -> dict[str, Any]:
    normalized = _normalize_process_plugin(payload, "windows.pstree", **kwargs)
    edges = []
    for item in normalized["processes"]:
        ppid = item["process"].get("ppid")
        pid = item["process"].get("pid")
        if ppid is not None and pid is not None:
            edges.append({"parent_pid": ppid, "child_pid": pid, "edge_type": "parent_child", "source_plugin": "windows.pstree", "confidence": "reported_by_plugin", "warnings": []})
    normalized["edges"] = edges
    return normalized


def normalize_windows_psscan(payload: Any, **kwargs: Any) -> dict[str, Any]:
    return _normalize_process_plugin(payload, "windows.psscan", **kwargs)


def normalize_windows_cmdline(payload: Any, **kwargs: Any) -> dict[str, Any]:
    return _normalize_process_plugin(payload, "windows.cmdline", **kwargs)


def _normalize_process_plugin(payload: Any, plugin: str, *, command_limit: int = 16384, raw_limit: int = 65536) -> dict[str, Any]:
    processes = []
    warnings: list[str] = []
    for row in _rows(payload):
        process, row_warnings = _process_from_row(row, plugin, command_limit=command_limit, raw_limit=raw_limit)
        warnings.extend(row_warnings)
        if process:
            processes.append(process)
    return {"plugin": plugin, "processes": processes, "edges": [], "warnings": warnings, "row_count": len(_rows(payload))}


def merge_memory_process_results(results: list[dict[str, Any]], *, case_id: str, evidence_id: str, memory_run_id: str) -> dict[str, Any]:
    merged: dict[str, dict[str, Any]] = {}
    warnings: list[str] = []
    edges = []
    for result in results:
        warnings.extend(result.get("warnings") or [])
        for item in result.get("processes") or []:
            identity = item["identity"]
            current = merged.get(identity)
            if current is None:
                merged[identity] = item
                continue
            for plugin in item.get("plugins") or []:
                if plugin not in current["plugins"]:
                    current["plugins"].append(plugin)
            for section in ("process", "memory"):
                for key, value in item.get(section, {}).items():
                    if current[section].get(key) in (None, "") and value not in (None, ""):
                        current[section][key] = value
                    elif value not in (None, "") and current[section].get(key) not in (None, "", value):
                        current.setdefault("warnings", []).append(f"conflicting_{section}_{key}")
            for key, value in item.get("visibility", {}).items():
                current["visibility"][key] = bool(current["visibility"].get(key) or value)
            current["state"]["terminated_candidate"] = bool(current["state"].get("terminated_candidate") or item["state"].get("terminated_candidate"))
            current["state"]["active_candidate"] = not current["state"]["terminated_candidate"]
        for edge in result.get("edges") or []:
            edges.append(edge)

    parsed_at = _utc_now()
    docs = []
    for identity, item in sorted(merged.items(), key=lambda pair: (pair[1]["process"].get("pid") or -1, pair[0])):
        visibility = item["visibility"]
        if visibility.get("psscan") and not visibility.get("pslist"):
            item.setdefault("warnings", []).append("not_present_in_pslist_result")
        item["state"]["hidden_candidate"] = False
        docs.append({
            "document_id": f"{memory_run_id}:memory_process:{identity}",
            "case_id": case_id,
            "evidence_id": evidence_id,
            "memory_run_id": memory_run_id,
            "source_layer": "memory",
            "memory_artifact_type": "memory_process",
            "backend": "volatility3",
            "plugins": sorted(item.get("plugins") or []),
            "process": item["process"],
            "memory": item["memory"],
            "visibility": visibility,
            "state": item["state"],
            "parsed_at": parsed_at,
            "raw": item.get("raw") or {},
            "warnings": item.get("warnings") or [],
        })
    edge_docs = []
    seen_edges = set()
    for edge in edges:
        key = (edge.get("parent_pid"), edge.get("child_pid"), edge.get("source_plugin"))
        if key in seen_edges:
            continue
        seen_edges.add(key)
        edge_docs.append({
            "document_id": f"{memory_run_id}:memory_process_edge:{key[0]}:{key[1]}:{key[2]}",
            "case_id": case_id,
            "evidence_id": evidence_id,
            "memory_run_id": memory_run_id,
            "source_layer": "memory",
            "memory_artifact_type": "memory_process_edge",
            "parent_pid": edge.get("parent_pid"),
            "child_pid": edge.get("child_pid"),
            "edge_type": edge.get("edge_type") or "parent_child",
            "source_plugin": edge.get("source_plugin") or "reported_ppid",
            "confidence": edge.get("confidence") or "reported_by_plugin",
            "parsed_at": parsed_at,
            "warnings": edge.get("warnings") or [],
        })
    return {"processes": docs, "edges": edge_docs, "warnings": warnings}


def _raw_subset(row: dict[str, Any]) -> dict[str, Any]:
    raw: dict[str, Any] = {}
    for index, (key, value) in enumerate(row.items()):
        if index >= MAX_RAW_FIELDS:
            break
        raw[str(key)[:128]] = _bounded(value)
    return raw


def normalize_windows_info(
    payload: Any,
    *,
    case_id: str,
    evidence_id: str,
    memory_run_id: str,
    memory_plugin_run_id: str,
    backend_version: str | None = None,
) -> dict[str, Any]:
    row = _first_row(payload)
    return {
        "case_id": case_id,
        "evidence_id": evidence_id,
        "memory_run_id": memory_run_id,
        "memory_plugin_run_id": memory_plugin_run_id,
        "source_layer": "memory",
        "memory_artifact_type": "memory_system_info",
        "backend": "volatility3",
        "plugin": "windows.info",
        "host": {"name": _lookup(row, "host_name", "hostname", "computer_name")},
        "os": {
            "family": "windows",
            "kernel_base": _lookup(row, "kernel_base", "kernel base"),
            "kernel_version": _lookup(row, "kernel_version", "nt_build_lab", "major/minor"),
            "nt_major_version": _lookup(row, "nt_major_version", "nt major version"),
            "nt_minor_version": _lookup(row, "nt_minor_version", "nt minor version"),
            "machine_type": _lookup(row, "machine_type", "machine", "architecture"),
        },
        "memory": {
            "layer_name": _lookup(row, "layer_name", "primary", "layer"),
            "dtb": _lookup(row, "dtb", "directory_table_base"),
            "kernel_symbols": _lookup(row, "kernel_symbols", "symbols", "symbol_table"),
            "is_64_bit": _lookup(row, "is_64_bit", "is_64bit"),
            "system_time": _lookup(row, "system_time", "system time"),
        },
        "parsed_at": _utc_now(),
        "raw": {"backend_version": backend_version, "fields": _raw_subset(row)},
    }
