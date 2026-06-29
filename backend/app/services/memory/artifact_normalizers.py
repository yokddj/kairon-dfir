"""Normalizers for the new core memory artifact profiles.

These normalizers consume the JSON output of a single Volatility plugin
and emit *canonical* documents ready for the ``dfir-memory-{case_id}``
OpenSearch index.  All functions are pure: no I/O, no OpenSearch calls,
no global state.  Materialization is handled by the corresponding
``materialize_*`` helpers in ``app.services.memory.artifact_indexing``.

Design contract
---------------
* Each ``normalize_*`` returns a dict of the form::

      {
        "items": [...],          # canonical documents
        "warnings": [...],       # parser-level warnings
        "raw_count": int,        # rows in the source payload
        "accepted_count": int,   # canonical items emitted
        "dropped_count": int,    # rows discarded
        "conflicts": int,        # multi-source conflicts (e.g. dlllist+ldrmodules)
      }

* Canonical documents never store raw hexdumps, paths under the server
  filesystem, or symbol-cache locations.  Bounded previews are stored as
  small substrings (max 256 bytes by default) when needed for the UI.
* The normalizers are idempotent: re-running with the same input
  produces the same document IDs.
"""
from __future__ import annotations

import hashlib
import re
from typing import Any, Iterable

from app.services.memory.pids import normalize_pid


NORMALIZATION_VERSION = "memory_artifact_canonical_v1"
MAX_PREVIEW_BYTES = 256
MAX_PATH_LENGTH = 1024
MAX_NAME_LENGTH = 256
MAX_OBJECT_NAME_LENGTH = 1024

# Bounded sanitizer: avoid leaking absolute server paths, cache locations,
# or evidence absolute paths in the canonical index.  Volatility output
# can include ``\Device\HarddiskVolume2\...`` style paths, but the
# canonical representation must be path-free on the server side.
_EVIDENCE_PATH_PATTERN = re.compile(r"(/mnt/evidence|/data/evidence|/cases/|/app/data/evidence)[^\s\"']*", re.IGNORECASE)


def _bounded(value: Any, limit: int) -> Any:
    if value is None:
        return None
    if isinstance(value, bool):
        return value
    if isinstance(value, (int, float)):
        return value
    text = str(value)
    if len(text) > limit:
        return text[:limit]
    return text


def _scrub_paths(value: Any) -> Any:
    """Strip server filesystem paths from a string.  The canonical store
    never persists absolute paths to the server or the symbol cache.
    """
    if not isinstance(value, str):
        return value
    return _EVIDENCE_PATH_PATTERN.sub("[evidence]", value)


def _document_id(*, prefix: str, case_id: str, run_id: str, identity: str) -> str:
    return f"{run_id}:{prefix}:{identity}"


def _identity_pid_offset(*parts: Any) -> str:
    seed = "|".join("" if p is None else str(p) for p in parts)
    return hashlib.sha256(seed.encode("utf-8")).hexdigest()[:24]


def _provenance(*, case_id: str, evidence_id: str, scan_run_id: str, plugin_run_id: str, source_plugin: str) -> dict[str, Any]:
    return {
        "case_id": case_id,
        "evidence_id": evidence_id,
        "scan_run_id": scan_run_id,
        "plugin_run_id": plugin_run_id,
        "source_plugin": source_plugin,
        "normalization_version": NORMALIZATION_VERSION,
    }


def _rows(payload: Any) -> list[dict[str, Any]]:
    if isinstance(payload, list):
        return [item for item in payload if isinstance(item, dict)]
    if isinstance(payload, dict):
        for key in ("rows", "data"):
            value = payload.get(key)
            if isinstance(value, list):
                return [item for item in value if isinstance(item, dict)]
        return [payload]
    return []


def _lookup(row: dict[str, Any], *names: str) -> Any:
    if not isinstance(row, dict):
        return None
    normalized = {str(key).lower().replace(" ", "_").replace("-", "_"): value for key, value in row.items()}
    for name in names:
        key = name.lower().replace(" ", "_").replace("-", "_")
        if key in normalized:
            return normalized[key]
    return None


def _int_or_none(value: Any) -> int | None:
    return normalize_pid(value)


def _str_or_none(value: Any, limit: int = MAX_NAME_LENGTH) -> str | None:
    if value is None:
        return None
    text = str(value).strip()
    return text[:limit] if text else None


# ---------------------------------------------------------------------------
# network_basic -> memory_network_connection
# ---------------------------------------------------------------------------


def normalize_windows_netscan(
    payload: Any,
    *,
    case_id: str,
    evidence_id: str,
    scan_run_id: str,
    plugin_run_id: str,
    source_plugin: str = "windows.netscan",
    process_name_resolver: Any | None = None,
    max_records: int = 200000,
) -> dict[str, Any]:
    rows = _rows(payload)
    items: list[dict[str, Any]] = []
    warnings: list[str] = []
    raw_count = len(rows)
    dropped = 0
    conflicts = 0
    accepted = 0
    for row in rows:
        proto = _str_or_none(_lookup(row, "Proto", "Protocol"))
        local_address = _str_or_none(_lookup(row, "LocalAddress", "Local Address"), 128)
        local_port = _int_or_none(_lookup(row, "LocalPort", "Local Port"))
        remote_address = _str_or_none(_lookup(row, "ForeignAddress", "RemoteAddress", "Remote Address"), 128)
        remote_port = _int_or_none(_lookup(row, "ForeignPort", "RemotePort", "Remote Port"))
        state = _str_or_none(_lookup(row, "State", "ConnectionState"), 32)
        pid = _int_or_none(_lookup(row, "PID", "Pid", "pid"))
        owner = _str_or_none(_lookup(row, "Owner", "Process", "CreatedBy"), MAX_NAME_LENGTH)
        create_time = _str_or_none(_lookup(row, "Created", "CreateTime", "Create Time"), 64)
        if pid is None:
            dropped += 1
            warnings.append("netscan_row_missing_pid")
            continue
        if not local_address and not remote_address:
            dropped += 1
            warnings.append("netscan_row_missing_endpoints")
            continue
        identity = _identity_pid_offset(local_address, local_port, remote_address, remote_port, state, pid, proto, create_time or "nopeer")
        doc = {
            "document_id": _document_id(prefix="memory_network_connection", case_id=case_id, run_id=scan_run_id, identity=identity),
            "document_type": "memory_network_connection",
            "case_id": case_id,
            "evidence_id": evidence_id,
            "scan_run_id": scan_run_id,
            "plugin_run_id": plugin_run_id,
            "protocol": proto or "unknown",
            "local_address": local_address,
            "local_port": local_port,
            "remote_address": remote_address,
            "remote_port": remote_port,
            "state": state,
            "pid": pid,
            "process_entity_id": None,
            "process_name": owner or _resolve_process_name(process_name_resolver, pid),
            "create_time": create_time,
            "source_plugin": source_plugin,
            "confidence": "reported_by_plugin",
            "provenance": _provenance(
                case_id=case_id,
                evidence_id=evidence_id,
                scan_run_id=scan_run_id,
                plugin_run_id=plugin_run_id,
                source_plugin=source_plugin,
            ),
            "normalization_version": NORMALIZATION_VERSION,
            "unresolved_process_reference": False,
        }
        items.append(doc)
        accepted += 1
        if accepted >= max_records:
            warnings.append("netscan_max_records_reached")
            break
    return {
        "items": items,
        "warnings": warnings,
        "raw_count": raw_count,
        "accepted_count": accepted,
        "dropped_count": dropped,
        "conflicts": conflicts,
        "normalization_version": NORMALIZATION_VERSION,
    }


def _resolve_process_name(resolver: Any, pid: int) -> str | None:
    if resolver is None or pid is None:
        return None
    try:
        return resolver(pid)
    except Exception:  # noqa: BLE001
        return None


# ---------------------------------------------------------------------------
# modules_basic -> memory_process_module
# ---------------------------------------------------------------------------


def normalize_windows_dlllist(
    payload: Any,
    *,
    case_id: str,
    evidence_id: str,
    scan_run_id: str,
    plugin_run_id: str,
    source_plugin: str = "windows.dlllist",
    process_name_resolver: Any | None = None,
    max_records: int = 200000,
) -> dict[str, Any]:
    return _normalize_module_payload(
        payload,
        case_id=case_id,
        evidence_id=evidence_id,
        scan_run_id=scan_run_id,
        plugin_run_id=plugin_run_id,
        source_plugin=source_plugin,
        process_name_resolver=process_name_resolver,
        max_records=max_records,
        in_load=None,
        in_init=None,
        in_mem=None,
        mapped_path_field="Path",
    )


def normalize_windows_ldrmodules(
    payload: Any,
    *,
    case_id: str,
    evidence_id: str,
    scan_run_id: str,
    plugin_run_id: str,
    source_plugin: str = "windows.ldrmodules",
    process_name_resolver: Any | None = None,
    max_records: int = 200000,
) -> dict[str, Any]:
    return _normalize_module_payload(
        payload,
        case_id=case_id,
        evidence_id=evidence_id,
        scan_run_id=scan_run_id,
        plugin_run_id=plugin_run_id,
        source_plugin=source_plugin,
        process_name_resolver=process_name_resolver,
        max_records=max_records,
        in_load=True,
        in_init=True,
        in_mem=True,
        mapped_path_field="MappedPath",
    )


def _normalize_module_payload(
    payload: Any,
    *,
    case_id: str,
    evidence_id: str,
    scan_run_id: str,
    plugin_run_id: str,
    source_plugin: str,
    process_name_resolver: Any | None,
    max_records: int,
    in_load: bool | None,
    in_init: bool | None,
    in_mem: bool | None,
    mapped_path_field: str,
) -> dict[str, Any]:
    rows = _rows(payload)
    items: list[dict[str, Any]] = []
    warnings: list[str] = []
    raw_count = len(rows)
    dropped = 0
    accepted = 0
    for row in rows:
        pid = _int_or_none(_lookup(row, "PID", "Pid", "pid"))
        if pid is None:
            dropped += 1
            warnings.append("module_row_missing_pid")
            continue
        process_name = _str_or_none(_lookup(row, "Process", "Name", "ImageFileName"), MAX_NAME_LENGTH) or _resolve_process_name(process_name_resolver, pid)
        path_value = _str_or_none(_lookup(row, mapped_path_field, "Path"), MAX_PATH_LENGTH)
        path_value = _scrub_paths(path_value) if path_value else path_value
        # Derive module_name from Name if present; otherwise from the
        # last path component (ldrmodules reports the full mapped
        # path but no separate Name field).
        module_name = _str_or_none(_lookup(row, "Name"), MAX_NAME_LENGTH)
        if not module_name and path_value:
            module_name = _module_name_from_path(path_value)
        base_address = _int_or_none(_lookup(row, "Base", "BaseAddress"))
        size = _int_or_none(_lookup(row, "Size"))
        load_state = _str_or_none(_lookup(row, "LoadState", "State"), 32)
        in_load = _lookup(row, "InLoad")
        in_init = _lookup(row, "InInit")
        in_mem = _lookup(row, "InMem")
        # Module identity: collapse same modules from different plugins
        # (dlllist vs ldrmodules).  The path is normalized so
        # ``\\SystemRoot\\System32\\foo`` and ``\\Windows\\System32\\foo``
        # produce the same identity.
        normalized_path = _normalize_path(path_value) or "nopath"
        identity = _identity_pid_offset(pid, module_name, normalized_path, base_address or 0)
        doc = {
            "document_id": _document_id(prefix="memory_process_module", case_id=case_id, run_id=scan_run_id, identity=identity),
            "document_type": "memory_process_module",
            "case_id": case_id,
            "evidence_id": evidence_id,
            "scan_run_id": scan_run_id,
            "plugin_run_id": plugin_run_id,
            "pid": pid,
            "process_entity_id": None,
            "process_name": process_name,
            "module_name": module_name,
            "path": path_value,
            "base_address": base_address,
            "size": size,
            "load_state": load_state,
            "in_load": _bool_or_none(in_load),
            "in_init": _bool_or_none(in_init),
            "in_memory": _bool_or_none(in_mem),
            "source_plugins": [source_plugin],
            "findings": [],
            "confidence": "reported_by_plugin",
            "provenance": _provenance(
                case_id=case_id,
                evidence_id=evidence_id,
                scan_run_id=scan_run_id,
                plugin_run_id=plugin_run_id,
                source_plugin=source_plugin,
            ),
            "normalization_version": NORMALIZATION_VERSION,
        }
        items.append(doc)
        accepted += 1
        if accepted >= max_records:
            warnings.append("module_max_records_reached")
            break
    return {
        "items": items,
        "warnings": warnings,
        "raw_count": raw_count,
        "accepted_count": accepted,
        "dropped_count": dropped,
        "conflicts": 0,
        "normalization_version": NORMALIZATION_VERSION,
    }


def _bool_or_none(value: Any) -> bool | None:
    if value is None:
        return None
    if isinstance(value, bool):
        return value
    if isinstance(value, (int, float)):
        return bool(value)
    if isinstance(value, str):
        lowered = value.strip().lower()
        if lowered in {"true", "yes", "1"}:
            return True
        if lowered in {"false", "no", "0", ""}:
            return False
    return None


def _module_name_from_path(path: str) -> str | None:
    if not path:
        return None
    # Normalize Windows and POSIX separators.
    cleaned = path.replace("\\", "/").rstrip("/")
    if not cleaned:
        return None
    return cleaned.rsplit("/", 1)[-1][:MAX_NAME_LENGTH] or None


def _normalize_path(path: str | None) -> str | None:
    """Map equivalent Windows path representations to a canonical form
    so that ``dlllist`` and ``ldrmodules`` entries for the same module
    can be merged by identity.  ``\\SystemRoot\\System32\\foo`` and
    ``\\Windows\\System32\\foo`` refer to the same file.
    """
    if not path:
        return path
    cleaned = path.strip().replace("\\", "/").rstrip("/").lower()
    if cleaned.startswith("//?/"):
        cleaned = cleaned[4:]
    if cleaned.startswith("/systemroot/"):
        cleaned = "/windows/" + cleaned[len("/systemroot/"):]
    if cleaned.startswith("systemroot/"):
        cleaned = "windows/" + cleaned[len("systemroot/"):]
    return cleaned


def merge_module_documents(*groups: Iterable[dict[str, Any]]) -> dict[str, Any]:
    """Merge dlllist+ldrmodules into consolidated ``memory_process_module`` docs.

    The merge is keyed on (pid, base_address, module_name, path) and
    combines ``source_plugins`` plus the per-source ``in_load``,
    ``in_init``, ``in_memory`` flags.  Discrepancies between the two
    plugins (e.g. ldrmodules reports a path but dlllist does not)
    produce a non-conflict entry; the combined ``findings`` list carries
    a ``module_list_discrepancy`` marker when the two plugins disagree
    on presence of a record.
    """
    by_id: dict[str, dict[str, Any]] = {}
    conflicts = 0
    raw_count = 0
    accepted_count = 0
    dropped_count = 0
    warnings: list[str] = []
    for group in groups:
        for doc in group.get("items", []):
            raw_count += 1
            identity = doc.get("document_id")
            if not identity:
                dropped_count += 1
                continue
            existing = by_id.get(identity)
            if existing is None:
                by_id[identity] = doc
                accepted_count += 1
                continue
            # Merge: union source plugins, merge booleans, set discrepancy.
            existing["source_plugins"] = sorted(set(existing.get("source_plugins", []) + doc.get("source_plugins", [])))
            for key in ("in_load", "in_init", "in_memory"):
                cur = existing.get(key)
                new = doc.get(key)
                if cur is False and new is True:
                    existing["findings"] = sorted(set(existing.get("findings", []) + ["module_list_discrepancy"]))
                    conflicts += 1
                elif cur is None and new is not None:
                    existing[key] = new
                elif new is not None and cur != new:
                    # Both plugins report a value but disagree: log a
                    # discrepancy so the analyst can review the
                    # inconsistency.
                    existing["findings"] = sorted(set(existing.get("findings", []) + ["module_list_discrepancy"]))
                    conflicts += 1
            if not existing.get("path") and doc.get("path"):
                existing["path"] = doc.get("path")
            elif existing.get("path") and doc.get("path") and existing["path"] != doc["path"]:
                # Prefer the SystemRoot-style path (more canonical),
                # otherwise keep the first non-null one.
                if existing["path"].lower().startswith("\\systemroot\\") and not doc["path"].lower().startswith("\\systemroot\\"):
                    pass  # existing is already preferred
                elif not existing["path"].lower().startswith("\\systemroot\\") and doc["path"].lower().startswith("\\systemroot\\"):
                    existing["path"] = doc["path"]
            if not existing.get("module_name") and doc.get("module_name"):
                existing["module_name"] = doc.get("module_name")
    items = list(by_id.values())
    return {
        "items": items,
        "warnings": warnings,
        "raw_count": raw_count,
        "accepted_count": len(items),
        "dropped_count": dropped_count,
        "conflicts": conflicts,
        "normalization_version": NORMALIZATION_VERSION,
    }


# ---------------------------------------------------------------------------
# handles_basic -> memory_handle
# ---------------------------------------------------------------------------


def normalize_windows_handles(
    payload: Any,
    *,
    case_id: str,
    evidence_id: str,
    scan_run_id: str,
    plugin_run_id: str,
    source_plugin: str = "windows.handles",
    process_name_resolver: Any | None = None,
    max_records: int = 200000,
) -> dict[str, Any]:
    rows = _rows(payload)
    items: list[dict[str, Any]] = []
    warnings: list[str] = []
    raw_count = len(rows)
    dropped = 0
    accepted = 0
    for row in rows:
        pid = _int_or_none(_lookup(row, "PID", "Pid", "pid"))
        if pid is None:
            dropped += 1
            warnings.append("handle_row_missing_pid")
            continue
        process_name = _str_or_none(_lookup(row, "Process"), MAX_NAME_LENGTH) or _resolve_process_name(process_name_resolver, pid)
        handle_value = _int_or_none(_lookup(row, "HandleValue", "Handle"))
        object_type = _str_or_none(_lookup(row, "Type", "ObjectType"), 64)
        object_name = _str_or_none(_lookup(row, "Name", "Object"), MAX_OBJECT_NAME_LENGTH)
        if object_name:
            object_name = _scrub_paths(object_name)
        granted_access = _int_or_none(_lookup(row, "GrantedAccess"))
        identity = _identity_pid_offset(pid, handle_value or 0, object_type or "Unknown", object_name or "no_name", granted_access or 0)
        doc = {
            "document_id": _document_id(prefix="memory_handle", case_id=case_id, run_id=scan_run_id, identity=identity),
            "document_type": "memory_handle",
            "case_id": case_id,
            "evidence_id": evidence_id,
            "scan_run_id": scan_run_id,
            "plugin_run_id": plugin_run_id,
            "pid": pid,
            "process_entity_id": None,
            "process_name": process_name,
            "handle_value": handle_value,
            "object_type": object_type,
            "object_name": object_name,
            "granted_access": granted_access,
            "source_plugin": source_plugin,
            "confidence": "reported_by_plugin",
            "provenance": _provenance(
                case_id=case_id,
                evidence_id=evidence_id,
                scan_run_id=scan_run_id,
                plugin_run_id=plugin_run_id,
                source_plugin=source_plugin,
            ),
            "normalization_version": NORMALIZATION_VERSION,
        }
        items.append(doc)
        accepted += 1
        if accepted >= max_records:
            warnings.append("handle_max_records_reached")
            break
    return {
        "items": items,
        "warnings": warnings,
        "raw_count": raw_count,
        "accepted_count": accepted,
        "dropped_count": dropped,
        "conflicts": 0,
        "normalization_version": NORMALIZATION_VERSION,
    }


# ---------------------------------------------------------------------------
# kernel_basic -> memory_kernel_module + memory_driver
# ---------------------------------------------------------------------------


def normalize_windows_modules(
    payload: Any,
    *,
    case_id: str,
    evidence_id: str,
    scan_run_id: str,
    plugin_run_id: str,
    source_plugin: str = "windows.modules",
    max_records: int = 200000,
) -> dict[str, Any]:
    rows = _rows(payload)
    items: list[dict[str, Any]] = []
    warnings: list[str] = []
    raw_count = len(rows)
    dropped = 0
    accepted = 0
    for row in rows:
        name = _str_or_none(_lookup(row, "Name"), MAX_NAME_LENGTH)
        if not name:
            dropped += 1
            warnings.append("kernel_module_missing_name")
            continue
        path = _str_or_none(_lookup(row, "Path"), MAX_PATH_LENGTH)
        path = _scrub_paths(path) if path else path
        base_address = _int_or_none(_lookup(row, "Base", "BaseAddress"))
        size = _int_or_none(_lookup(row, "Size"))
        identity = _identity_pid_offset(name, path or "nopath", base_address or 0, size or 0)
        doc = {
            "document_id": _document_id(prefix="memory_kernel_module", case_id=case_id, run_id=scan_run_id, identity=identity),
            "document_type": "memory_kernel_module",
            "case_id": case_id,
            "evidence_id": evidence_id,
            "scan_run_id": scan_run_id,
            "plugin_run_id": plugin_run_id,
            "module_name": name,
            "path": path,
            "base_address": base_address,
            "size": size,
            "source_plugin": source_plugin,
            "visibility": {"listed": True, "scan_only": False, "terminated": False, "unknown": False},
            "findings": [],
            "confidence": "reported_by_plugin",
            "provenance": _provenance(
                case_id=case_id,
                evidence_id=evidence_id,
                scan_run_id=scan_run_id,
                plugin_run_id=plugin_run_id,
                source_plugin=source_plugin,
            ),
            "normalization_version": NORMALIZATION_VERSION,
        }
        items.append(doc)
        accepted += 1
        if accepted >= max_records:
            warnings.append("kernel_module_max_records_reached")
            break
    return {
        "items": items,
        "warnings": warnings,
        "raw_count": raw_count,
        "accepted_count": accepted,
        "dropped_count": dropped,
        "conflicts": 0,
        "normalization_version": NORMALIZATION_VERSION,
    }


def normalize_windows_driverscan(
    payload: Any,
    *,
    case_id: str,
    evidence_id: str,
    scan_run_id: str,
    plugin_run_id: str,
    source_plugin: str = "windows.driverscan",
    max_records: int = 200000,
) -> dict[str, Any]:
    rows = _rows(payload)
    items: list[dict[str, Any]] = []
    warnings: list[str] = []
    raw_count = len(rows)
    dropped = 0
    accepted = 0
    for row in rows:
        name = _str_or_none(_lookup(row, "Driver Name", "DriverName", "Name"), MAX_NAME_LENGTH)
        if not name:
            dropped += 1
            warnings.append("driver_missing_name")
            continue
        service_key = _str_or_none(_lookup(row, "Service Key", "ServiceKey"), MAX_PATH_LENGTH)
        if service_key:
            service_key = _scrub_paths(service_key)
        path = _str_or_none(_lookup(row, "Path"), MAX_PATH_LENGTH)
        if path:
            path = _scrub_paths(path)
        start_address = _int_or_none(_lookup(row, "Start", "StartAddress"))
        size = _int_or_none(_lookup(row, "Size"))
        identity = _identity_pid_offset(name, service_key or "nokey", start_address or 0, size or 0)
        doc = {
            "document_id": _document_id(prefix="memory_driver", case_id=case_id, run_id=scan_run_id, identity=identity),
            "document_type": "memory_driver",
            "case_id": case_id,
            "evidence_id": evidence_id,
            "scan_run_id": scan_run_id,
            "plugin_run_id": plugin_run_id,
            "driver_name": name,
            "service_key": service_key,
            "path": path,
            "start_address": start_address,
            "size": size,
            "source_plugin": source_plugin,
            "visibility": {"listed": True, "scan_only": True, "terminated": False, "unknown": False},
            "findings": [],
            "confidence": "reported_by_plugin",
            "provenance": _provenance(
                case_id=case_id,
                evidence_id=evidence_id,
                scan_run_id=scan_run_id,
                plugin_run_id=plugin_run_id,
                source_plugin=source_plugin,
            ),
            "normalization_version": NORMALIZATION_VERSION,
        }
        items.append(doc)
        accepted += 1
        if accepted >= max_records:
            warnings.append("driver_max_records_reached")
            break
    return {
        "items": items,
        "warnings": warnings,
        "raw_count": raw_count,
        "accepted_count": accepted,
        "dropped_count": dropped,
        "conflicts": 0,
        "normalization_version": NORMALIZATION_VERSION,
    }


# ---------------------------------------------------------------------------
# suspicious_memory -> memory_suspicious_region
# ---------------------------------------------------------------------------


def normalize_windows_malfind(
    payload: Any,
    *,
    case_id: str,
    evidence_id: str,
    scan_run_id: str,
    plugin_run_id: str,
    source_plugin: str = "windows.malfind",
    process_name_resolver: Any | None = None,
    max_records: int = 50000,
    max_preview_bytes: int = MAX_PREVIEW_BYTES,
) -> dict[str, Any]:
    rows = _rows(payload)
    items: list[dict[str, Any]] = []
    warnings: list[str] = []
    raw_count = len(rows)
    dropped = 0
    accepted = 0
    for row in rows:
        pid = _int_or_none(_lookup(row, "PID", "Pid", "pid"))
        process_name = _str_or_none(_lookup(row, "Process", "Name"), MAX_NAME_LENGTH) or _resolve_process_name(process_name_resolver, pid)
        start_address = _str_or_none(_lookup(row, "Start", "StartAddress", "Start VPN"), 64)
        end_address = _str_or_none(_lookup(row, "End", "EndAddress", "End VPN"), 64)
        protection = _str_or_none(_lookup(row, "Protection"), 32)
        tag = _str_or_none(_lookup(row, "Tag"), 32)
        commit_charge = _int_or_none(_lookup(row, "CommitCharge"))
        private_memory = _bool_or_none(_lookup(row, "PrivateMemory"))
        hexdump_preview = _bounded_preview(_lookup(row, "Hexdump", "HexDump", "Hex"), max_preview_bytes)
        disasm_preview = _bounded_preview(_lookup(row, "Disassembly", "Disassembled"), max_preview_bytes)
        if pid is None and not (start_address or end_address):
            dropped += 1
            warnings.append("malfind_row_missing_identity")
            continue
        identity = _identity_pid_offset(pid, start_address or "noaddr", end_address or "noaddr", tag or "notag", protection or "noprot")
        findings = ["needs_review"]
        doc = {
            "document_id": _document_id(prefix="memory_suspicious_region", case_id=case_id, run_id=scan_run_id, identity=identity),
            "document_type": "memory_suspicious_region",
            "case_id": case_id,
            "evidence_id": evidence_id,
            "scan_run_id": scan_run_id,
            "plugin_run_id": plugin_run_id,
            "pid": pid,
            "process_entity_id": None,
            "process_name": process_name,
            "start_address": start_address,
            "end_address": end_address,
            "protection": protection,
            "tag": tag,
            "commit_charge": commit_charge,
            "private_memory": private_memory,
            "hexdump_preview_bounded": hexdump_preview,
            "disassembly_preview_bounded": disasm_preview,
            "source_plugin": source_plugin,
            "confidence": "indicator",
            "review_status": "needs_review",
            "findings": findings,
            "provenance": _provenance(
                case_id=case_id,
                evidence_id=evidence_id,
                scan_run_id=scan_run_id,
                plugin_run_id=plugin_run_id,
                source_plugin=source_plugin,
            ),
            "normalization_version": NORMALIZATION_VERSION,
        }
        items.append(doc)
        accepted += 1
        if accepted >= max_records:
            warnings.append("malfind_max_records_reached")
            break
    return {
        "items": items,
        "warnings": warnings,
        "raw_count": raw_count,
        "accepted_count": accepted,
        "dropped_count": dropped,
        "conflicts": 0,
        "normalization_version": NORMALIZATION_VERSION,
    }


def _bounded_preview(value: Any, limit: int) -> str | None:
    if value is None or limit <= 0:
        return None
    if isinstance(value, list):
        value = "\n".join(str(item) for item in value)
    text = str(value).strip()
    if not text:
        return None
    if len(text) > limit:
        return text[:limit]
    return text
