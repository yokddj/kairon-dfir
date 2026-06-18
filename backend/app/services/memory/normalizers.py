from __future__ import annotations

from datetime import datetime, timezone
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
