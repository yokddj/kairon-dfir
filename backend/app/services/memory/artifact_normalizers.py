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


def _port_or_none(value: Any) -> int | None:
    port = normalize_pid(value)
    if port is None or port < 0 or port > 65535:
        return None
    return port


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
        local_address = _str_or_none(_lookup(row, "LocalAddress", "Local Address", "LocalAddr", "Local Addr"), 128)
        local_port = _port_or_none(_lookup(row, "LocalPort", "Local Port"))
        remote_address = _str_or_none(_lookup(row, "ForeignAddress", "Foreign Address", "ForeignAddr", "Foreign Addr", "RemoteAddress", "Remote Address", "RemoteAddr", "Remote Addr"), 128)
        remote_port = _port_or_none(_lookup(row, "ForeignPort", "RemotePort", "Remote Port"))
        state = _str_or_none(_lookup(row, "State", "ConnectionState"), 32)
        pid = _int_or_none(_lookup(row, "PID", "Pid", "pid"))
        owner = _str_or_none(_lookup(row, "Owner", "Process", "CreatedBy"), MAX_NAME_LENGTH)
        create_time = _str_or_none(_lookup(row, "Created", "CreateTime", "Create Time"), 64)
        offset = _str_or_none(_lookup(row, "Offset", "Offset(V)", "Offset(P)", "VirtualOffset", "PhysicalOffset"), 64)
        if not local_address and not remote_address:
            dropped += 1
            warnings.append("netscan_row_missing_endpoints")
            continue
        if pid is None:
            warnings.append("netscan_row_missing_pid")
        identity = _identity_pid_offset(local_address, local_port, remote_address, remote_port, state, pid, proto, create_time, offset or "nooffset")
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
            "offset": offset,
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
            "unresolved_process_reference": pid is None,
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


def normalize_linux_sockstat(
    payload: Any,
    *,
    case_id: str,
    evidence_id: str,
    scan_run_id: str,
    plugin_run_id: str,
    source_plugin: str = "linux.sockstat",
    process_name_resolver: Any | None = None,
    max_records: int = 200000,
) -> dict[str, Any]:
    rows = _rows(payload)
    items: list[dict[str, Any]] = []
    warnings: list[str] = []
    raw_count = len(rows)
    dropped = 0
    accepted = 0
    for index, row in enumerate(rows):
        if accepted >= max_records:
            warnings.append("sockstat_max_records_reached")
            dropped += len(rows) - index
            break
        family = _str_or_none(_lookup(row, "Family"), 32)
        sock_type = _str_or_none(_lookup(row, "Type"), 32)
        proto_field = _str_or_none(_lookup(row, "Proto"), 32)
        # linux.sockstat leaves Proto empty for most AF_UNIX sockets; fall
        # back to Family/Type so the connection isn't reduced to "unknown"
        # when the plugin itself reported a real socket family and type.
        protocol = proto_field or (f"{family}/{sock_type}" if family or sock_type else None)
        local_address = _str_or_none(_lookup(row, "Source Addr"), 128)
        remote_address = _str_or_none(_lookup(row, "Destination Addr"), 128)
        # Only AF_INET/AF_INET6 rows carry a real 0-65535 TCP/UDP port in
        # Source/Destination Port. linux.sockstat reuses those same two
        # columns for AF_UNIX (the socket's inode number), AF_NETLINK
        # (a multicast group mask) and similar -- values that routinely
        # exceed 65535. Clamping those to the port range with
        # _port_or_none silently nulled out ~14.5k real identifiers,
        # which then made otherwise-identifiable anonymous sockets look
        # endpoint-less and drop. Only apply the port-range check where
        # the field is actually a port.
        if family in ("AF_INET", "AF_INET6"):
            local_port = _port_or_none(_lookup(row, "Source Port"))
            remote_port = _port_or_none(_lookup(row, "Destination Port"))
        else:
            local_port = _int_or_none(_lookup(row, "Source Port"))
            remote_port = _int_or_none(_lookup(row, "Destination Port"))
        state = _str_or_none(_lookup(row, "State"), 32)
        pid = _int_or_none(_lookup(row, "PID"))
        tid = _int_or_none(_lookup(row, "TID"))
        owner = _str_or_none(_lookup(row, "Process Name"), MAX_NAME_LENGTH)
        fd = _int_or_none(_lookup(row, "FD"))
        offset_raw = _lookup(row, "Sock Offset")
        offset = hex(offset_raw) if isinstance(offset_raw, int) else _str_or_none(offset_raw, 64)
        # Unlike Windows netscan, most AF_UNIX rows have no filesystem
        # path (anonymous socketpair()s -- confirmed against real
        # evidence: systemd's internal IPC, browser-process channels).
        # Their only identity is the paired inode numbers in
        # Source/Destination Port. Checking address alone silently
        # dropped 76% of all real rows; only drop when there is
        # nothing at all to identify the socket by.
        if not local_address and not remote_address and local_port is None and remote_port is None:
            dropped += 1
            warnings.append("sockstat_row_missing_endpoints")
            continue
        if pid is None:
            warnings.append("sockstat_row_missing_pid")
        # FD is part of the identity because a single thread can hold
        # more than one file descriptor open on the same underlying
        # socket (e.g. dup()); omitting it would silently collapse two
        # real, distinct Volatility rows into one document.
        identity = _identity_pid_offset(pid, tid, fd, local_address, local_port, remote_address, remote_port, state, protocol, offset or "nooffset")
        doc = {
            "document_id": _document_id(prefix="memory_network_connection", case_id=case_id, run_id=scan_run_id, identity=identity),
            "document_type": "memory_network_connection",
            "case_id": case_id,
            "evidence_id": evidence_id,
            "scan_run_id": scan_run_id,
            "plugin_run_id": plugin_run_id,
            "platform": "linux",
            "protocol": protocol or "unknown",
            "local_address": local_address,
            "local_port": local_port,
            "remote_address": remote_address,
            "remote_port": remote_port,
            "state": state,
            "pid": pid,
            "tid": tid,
            "fd": fd,
            "process_entity_id": None,
            "process_name": owner or _resolve_process_name(process_name_resolver, pid),
            "create_time": None,
            "offset": offset,
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
            "unresolved_process_reference": pid is None,
        }
        items.append(doc)
        accepted += 1
    return {
        "items": items,
        "warnings": warnings,
        "raw_count": raw_count,
        "accepted_count": accepted,
        "dropped_count": dropped,
        "conflicts": 0,
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
            "confidence": "reported_by_plugin",
            "review_status": "needs_review",
            "findings": [],
            "summary": "Suspicious memory region reported by Volatility.",
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


# ---------------------------------------------------------------------------
# suspicious_memory -> memory_vad (VAD-specific fields)
# ---------------------------------------------------------------------------


def normalize_windows_vadinfo(
    payload: Any,
    *,
    case_id: str,
    evidence_id: str,
    scan_run_id: str,
    plugin_run_id: str,
    source_plugin: str = "windows.vadinfo",
    process_name_resolver: Any | None = None,
    max_records: int = 50000,
) -> dict[str, Any]:
    rows = _rows(payload)
    items: list[dict[str, Any]] = []
    warnings: list[str] = []
    raw_count = len(rows)
    dropped = 0
    accepted = 0
    for index, row in enumerate(rows):
        if accepted >= max_records:
            warnings.append("Max records limit reached; some vadinfo rows dropped.")
            dropped += len(rows) - index
            break
        pid = _int_or_none(_lookup(row, "PID", "Pid", "pid"))
        process_name = _str_or_none(_lookup(row, "Process", "Name"), MAX_NAME_LENGTH) or _resolve_process_name(process_name_resolver, pid)
        start_addr = _str_or_none(_lookup(row, "Start", "StartAddress", "Start VPN"), 64)
        end_addr = _str_or_none(_lookup(row, "End", "EndAddress", "End VPN"), 64)
        protection = _str_or_none(_lookup(row, "Protection"), 32)
        tag = _str_or_none(_lookup(row, "Tag"), 32)
        commit_charge = _int_or_none(_lookup(row, "CommitCharge"))
        private_memory = _bool_or_none(_lookup(row, "PrivateMemory"))
        file_object = _str_or_none(_lookup(row, "FileObject", "File"), 1024)
        parent_id = _int_or_none(_lookup(row, "Parent", "ParentPID"))
        if pid is None and not (start_addr or end_addr):
            dropped += 1
            continue
        items.append({
            "document_type": "memory_vad",
            "memory_artifact_type": "memory_vad",
            "document_id": _doc_id(scan_run_id, plugin_run_id, index),
            "case_id": case_id,
            "evidence_id": evidence_id,
            "scan_run_id": scan_run_id,
            "plugin_run_id": plugin_run_id,
            "pid": pid,
            "process_name": process_name,
            "start_address": start_addr,
            "end_address": end_addr,
            "protection": protection,
            "tag": tag,
            "commit_charge": commit_charge,
            "private_memory": private_memory,
            "file_object": file_object,
            "parent_pid": parent_id,
            "source_plugin": source_plugin,
            "source_record_index": index,
            "provenance": _provenance(
                case_id=case_id,
                evidence_id=evidence_id,
                scan_run_id=scan_run_id,
                plugin_run_id=plugin_run_id,
                source_plugin=source_plugin,
            ),
            "normalization_version": NORMALIZATION_VERSION,
            "review_status": "needs_review",
        })
        accepted += 1
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


# ---------------------------------------------------------------------------
# processes_extended observation normalizers
#   windows.envars  -> memory_environment_variable
#   windows.getsids -> memory_sid
#   windows.privileges -> memory_privilege
# ---------------------------------------------------------------------------


def _doc_id(run_id: str, plugin_run_id: str, index: int) -> str:
    return f"{run_id}:{plugin_run_id}:{index}"


def _resolve_process_name(resolver: Any | None, pid: int | None) -> str | None:
    if resolver is None or pid is None:
        return None
    try:
        return resolver(pid)
    except Exception:
        return None


def normalize_windows_envars(
    payload: Any,
    *,
    case_id: str,
    evidence_id: str,
    scan_run_id: str,
    plugin_run_id: str,
    source_plugin: str = "windows.envars",
    process_name_resolver: Any | None = None,
    max_records: int = 200000,
) -> dict[str, Any]:
    rows = _rows(payload)
    items: list[dict[str, Any]] = []
    warnings: list[str] = []
    raw_count = len(rows)
    dropped = 0
    accepted = 0
    for index, row in enumerate(rows):
        if accepted >= max_records:
            warnings.append("Max records limit reached; some envars rows dropped.")
            dropped += len(rows) - index
            break
        pid = _int_or_none(_lookup(row, "PID", "Pid", "ProcessId"))
        process_name = _str_or_none(_lookup(row, "Process", "Name"), MAX_NAME_LENGTH) or _resolve_process_name(process_name_resolver, pid)
        variable = _str_or_none(_lookup(row, "Variable", "Key", "Name"), 512)
        value = _str_or_none(_lookup(row, "Value", "Data"), 4096)
        if variable is None:
            dropped += 1
            continue
        items.append({
            "document_type": "memory_environment_variable",
            "memory_artifact_type": "memory_environment_variable",
            "document_id": _doc_id(scan_run_id, plugin_run_id, index),
            "pid": pid,
            "process_name": process_name,
            "variable": variable,
            "value": value,
            "source_plugin": source_plugin,
            "source_record_index": index,
            "normalization_version": NORMALIZATION_VERSION,
        })
        accepted += 1
    return {
        "items": items,
        "warnings": warnings,
        "raw_count": raw_count,
        "accepted_count": accepted,
        "dropped_count": dropped,
        "conflicts": 0,
        "normalization_version": NORMALIZATION_VERSION,
    }


def normalize_windows_getsids(
    payload: Any,
    *,
    case_id: str,
    evidence_id: str,
    scan_run_id: str,
    plugin_run_id: str,
    source_plugin: str = "windows.getsids",
    process_name_resolver: Any | None = None,
    max_records: int = 100000,
) -> dict[str, Any]:
    rows = _rows(payload)
    items: list[dict[str, Any]] = []
    warnings: list[str] = []
    raw_count = len(rows)
    dropped = 0
    accepted = 0
    for index, row in enumerate(rows):
        if accepted >= max_records:
            warnings.append("Max records limit reached; some getsids rows dropped.")
            dropped += len(rows) - index
            break
        pid = _int_or_none(_lookup(row, "PID", "Pid", "ProcessId"))
        process_name = _str_or_none(_lookup(row, "Process", "Name"), MAX_NAME_LENGTH) or _resolve_process_name(process_name_resolver, pid)
        sid = _str_or_none(_lookup(row, "SID", "Sid"), 256)
        resolved_name = _str_or_none(_lookup(row, "Name", "Account", "Username"), 512)
        if sid is None:
            dropped += 1
            continue
        items.append({
            "document_type": "memory_sid",
            "memory_artifact_type": "memory_sid",
            "document_id": _doc_id(scan_run_id, plugin_run_id, index),
            "pid": pid,
            "process_name": process_name,
            "sid": sid,
            "resolved_name": resolved_name,
            "source_plugin": source_plugin,
            "source_record_index": index,
            "normalization_version": NORMALIZATION_VERSION,
        })
        accepted += 1
    return {
        "items": items,
        "warnings": warnings,
        "raw_count": raw_count,
        "accepted_count": accepted,
        "dropped_count": dropped,
        "conflicts": 0,
        "normalization_version": NORMALIZATION_VERSION,
    }


def normalize_windows_privileges(
    payload: Any,
    *,
    case_id: str,
    evidence_id: str,
    scan_run_id: str,
    plugin_run_id: str,
    source_plugin: str = "windows.privileges",
    process_name_resolver: Any | None = None,
    max_records: int = 100000,
) -> dict[str, Any]:
    rows = _rows(payload)
    items: list[dict[str, Any]] = []
    warnings: list[str] = []
    raw_count = len(rows)
    dropped = 0
    accepted = 0
    for index, row in enumerate(rows):
        if accepted >= max_records:
            warnings.append("Max records limit reached; some privileges rows dropped.")
            dropped += len(rows) - index
            break
        pid = _int_or_none(_lookup(row, "PID", "Pid", "ProcessId"))
        process_name = _str_or_none(_lookup(row, "Process", "Name"), MAX_NAME_LENGTH) or _resolve_process_name(process_name_resolver, pid)
        privilege_name = _str_or_none(_lookup(row, "Privilege", "Value", "Name"), 256)
        present = _bool_or_none(_lookup(row, "Present"))
        enabled = _bool_or_none(_lookup(row, "Enabled"))
        default_enabled = _bool_or_none(_lookup(row, "Default", "DefaultEnabled"))
        description = _str_or_none(_lookup(row, "Description"), 1024)
        if privilege_name is None:
            dropped += 1
            continue
        items.append({
            "document_type": "memory_privilege",
            "memory_artifact_type": "memory_privilege",
            "document_id": _doc_id(scan_run_id, plugin_run_id, index),
            "pid": pid,
            "process_name": process_name,
            "privilege": privilege_name,
            "present": present,
            "enabled": enabled,
            "default_enabled": default_enabled,
            "description": description,
            "source_plugin": source_plugin,
            "source_record_index": index,
            "normalization_version": NORMALIZATION_VERSION,
        })
        accepted += 1
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
# shell_history -> memory_shell_history
#   linux.bash recovers resident bash history entries scanned out of a
#   process's heap.  PID/Process/CommandTime/Command are the only fields
#   the plugin reports; CommandTime is either a real timestamp or absent
#   (Volatility never emits a sentinel string for it), so it is stored
#   raw and never fabricated.  The schema intentionally has no user,
#   cwd, tty, session, or parent-pid fields: linux.bash does not report
#   them, and none of the other Linux plugins provide a validated way to
#   derive them.  Kept platform-agnostic: normalize_windows_consoles
#   below (the Windows producer, windows.consoles) emits the same
#   document_type with command_time left null for the same reason.
# ---------------------------------------------------------------------------


def normalize_linux_bash(
    payload: Any,
    *,
    case_id: str,
    evidence_id: str,
    scan_run_id: str,
    plugin_run_id: str,
    source_plugin: str = "linux.bash",
    process_name_resolver: Any | None = None,
    max_records: int = 200000,
) -> dict[str, Any]:
    rows = _rows(payload)
    items: list[dict[str, Any]] = []
    warnings: list[str] = []
    raw_count = len(rows)
    dropped = 0
    accepted = 0
    for index, row in enumerate(rows):
        if accepted >= max_records:
            warnings.append("bash_max_records_reached")
            dropped += len(rows) - index
            break
        pid = _int_or_none(_lookup(row, "PID", "Pid", "pid"))
        process_name = _str_or_none(_lookup(row, "Process", "process_name"), MAX_NAME_LENGTH) or _resolve_process_name(process_name_resolver, pid)
        command = _str_or_none(_lookup(row, "Command", "command"), MAX_OBJECT_NAME_LENGTH)
        if command:
            command = _scrub_paths(command)
        command_time = _str_or_none(_lookup(row, "CommandTime", "Command Time", "command_time"), 64)
        if not command:
            dropped += 1
            warnings.append("bash_row_missing_command")
            continue
        if pid is None:
            warnings.append("bash_row_missing_pid")
        identity = _identity_pid_offset(pid, process_name, command, command_time, index)
        doc = {
            "document_id": _document_id(prefix="memory_shell_history", case_id=case_id, run_id=scan_run_id, identity=identity),
            "document_type": "memory_shell_history",
            "case_id": case_id,
            "evidence_id": evidence_id,
            "scan_run_id": scan_run_id,
            "plugin_run_id": plugin_run_id,
            "platform": "linux",
            "pid": pid,
            "process_entity_id": None,
            "process_name": process_name,
            "command": command,
            "command_time": command_time,
            "source_plugin": source_plugin,
            "source_record_index": index,
            "confidence": "reported_by_plugin",
            "provenance": _provenance(
                case_id=case_id,
                evidence_id=evidence_id,
                scan_run_id=scan_run_id,
                plugin_run_id=plugin_run_id,
                source_plugin=source_plugin,
            ),
            "normalization_version": NORMALIZATION_VERSION,
            "unresolved_process_reference": pid is None,
        }
        items.append(doc)
        accepted += 1
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
# shell_history -> memory_shell_history (Windows)
#   windows.consoles walks every conhost.exe process's console buffers and
#   flattens the recovered _CONSOLE_INFORMATION structures into one row
#   per (PID, Property, Data) triple -- there is no one-row-per-command
#   shape the way linux.bash has. Recovered typed commands are the rows
#   whose Property matches
#   "..._HistoryList.CommandHistory_{index}_Command_{cmd_index}"; the
#   application that owned that history buffer (cmd.exe, powershell.exe,
#   ...) is a sibling row, "..._CommandHistory_{index}_Application",
#   which the plugin always emits before its Command_* rows for the same
#   index (verified against volatility3.framework.plugins.windows.
#   consoles.Consoles._generator). This is tracked as "last Application
#   seen for this PID" while scanning rows in order rather than a full
#   index-keyed state machine, since the plugin's own emission order
#   already guarantees Application precedes its Commands.
#   PID/Process here identify conhost.exe itself (the plugin scans only
#   conhost.exe processes), so process_name is deliberately overridden
#   with the recovered Application when available -- that is the actual
#   shell the analyst cares about, not the console host. No timestamp is
#   ever available from this plugin, matching linux.bash's contract:
#   command_time is always None here, never fabricated.
# ---------------------------------------------------------------------------

_CONSOLE_COMMAND_PROPERTY = re.compile(r"_Command_\d+$")
_CONSOLE_APPLICATION_PROPERTY = re.compile(r"_Application$")


def _flatten_console_rows(payload: Any) -> list[dict[str, Any]]:
    """windows.consoles is the one plugin in this registry whose TreeGrid
    uses real ``level`` nesting (PID -> HistoryList -> CommandHistory_N ->
    Command_N) rather than the flat level-0-only rows every other plugin
    here emits.  Volatility's ``-r json`` renderer represents that as a
    ``__children`` list on the parent row instead of sibling flat rows
    (verified against a real evidence run: a CommandHistory_N node's
    Application/Command_* properties arrive nested under its
    "__children", not alongside it) -- so a plain ``_rows()`` walk would
    silently miss every command past the top level.  This walks the tree
    at any depth and returns every node as a flat row; safe to reuse for
    already-flat plugin output too, since a row with no "__children" key
    is simply appended as-is.
    """
    flat: list[dict[str, Any]] = []

    def walk(nodes: list[dict[str, Any]]) -> None:
        for node in nodes:
            if not isinstance(node, dict):
                continue
            children = node.get("__children")
            flat.append({key: value for key, value in node.items() if key != "__children"})
            if isinstance(children, list):
                walk([child for child in children if isinstance(child, dict)])

    walk(_rows(payload))
    return flat


def normalize_windows_consoles(
    payload: Any,
    *,
    case_id: str,
    evidence_id: str,
    scan_run_id: str,
    plugin_run_id: str,
    source_plugin: str = "windows.consoles",
    max_records: int = 200000,
) -> dict[str, Any]:
    rows = _flatten_console_rows(payload)
    items: list[dict[str, Any]] = []
    warnings: list[str] = []
    raw_count = len(rows)
    dropped = 0
    accepted = 0
    last_application_by_pid: dict[int, str] = {}
    for index, row in enumerate(rows):
        if accepted >= max_records:
            warnings.append("consoles_max_records_reached")
            dropped += len(rows) - index
            break
        pid = _int_or_none(_lookup(row, "PID", "Pid", "pid"))
        conhost_process_name = _str_or_none(_lookup(row, "Process", "process_name"), MAX_NAME_LENGTH)
        property_name = _str_or_none(_lookup(row, "Property", "property"), MAX_OBJECT_NAME_LENGTH) or ""
        data = _lookup(row, "Data", "data")
        if pid is not None and _CONSOLE_APPLICATION_PROPERTY.search(property_name):
            application = _str_or_none(data, MAX_NAME_LENGTH)
            if application:
                last_application_by_pid[pid] = application
            continue
        if not _CONSOLE_COMMAND_PROPERTY.search(property_name):
            continue
        command = _str_or_none(data, MAX_OBJECT_NAME_LENGTH)
        if command:
            command = _scrub_paths(command)
        if not command:
            dropped += 1
            warnings.append("consoles_row_missing_command")
            continue
        if pid is None:
            warnings.append("consoles_row_missing_pid")
        process_name = (pid is not None and last_application_by_pid.get(pid)) or conhost_process_name
        identity = _identity_pid_offset(pid, property_name, command, index)
        doc = {
            "document_id": _document_id(prefix="memory_shell_history", case_id=case_id, run_id=scan_run_id, identity=identity),
            "document_type": "memory_shell_history",
            "case_id": case_id,
            "evidence_id": evidence_id,
            "scan_run_id": scan_run_id,
            "plugin_run_id": plugin_run_id,
            "platform": "windows",
            "pid": pid,
            "process_entity_id": None,
            "process_name": process_name,
            "command": command,
            "command_time": None,
            "source_plugin": source_plugin,
            "source_record_index": index,
            "confidence": "reported_by_plugin",
            "provenance": _provenance(
                case_id=case_id,
                evidence_id=evidence_id,
                scan_run_id=scan_run_id,
                plugin_run_id=plugin_run_id,
                source_plugin=source_plugin,
            ),
            "normalization_version": NORMALIZATION_VERSION,
            "unresolved_process_reference": pid is None,
        }
        items.append(doc)
        accepted += 1
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
# files -> memory_file_object
#   windows.filescan walks pool allocations for _FILE_OBJECT structures
#   image-wide and reports only Offset + Name -- unlike windows.consoles,
#   its TreeGrid always renders at level 0 (verified against a real
#   evidence run: 13,191 rows, none nested), so this is a plain flat
#   normalizer like linux.bash, no tree-walk needed. This is the same
#   plugin app.services.memory.file_extraction's on-demand "recover this
#   exact file" action already runs per request and discards everything
#   but one matching row; this normalizer persists the full result as a
#   browsable, searchable list instead. Offset+Name is the identity (no
#   PID exists for a file object), so the same file object reported
#   twice in one run collapses to one document rather than duplicating.
# ---------------------------------------------------------------------------


def normalize_windows_filescan(
    payload: Any,
    *,
    case_id: str,
    evidence_id: str,
    scan_run_id: str,
    plugin_run_id: str,
    source_plugin: str = "windows.filescan",
    max_records: int = 200000,
) -> dict[str, Any]:
    rows = _rows(payload)
    items: list[dict[str, Any]] = []
    warnings: list[str] = []
    raw_count = len(rows)
    dropped = 0
    accepted = 0
    for index, row in enumerate(rows):
        if accepted >= max_records:
            warnings.append("filescan_max_records_reached")
            dropped += len(rows) - index
            break
        name = _str_or_none(_lookup(row, "Name", "name"), MAX_OBJECT_NAME_LENGTH)
        if name:
            name = _scrub_paths(name)
        offset = _str_or_none(_lookup(row, "Offset", "offset"), 32)
        if not name:
            dropped += 1
            warnings.append("filescan_row_missing_name")
            continue
        identity = _identity_pid_offset(offset, name)
        doc = {
            "document_id": _document_id(prefix="memory_file_object", case_id=case_id, run_id=scan_run_id, identity=identity),
            "document_type": "memory_file_object",
            "case_id": case_id,
            "evidence_id": evidence_id,
            "scan_run_id": scan_run_id,
            "plugin_run_id": plugin_run_id,
            "platform": "windows",
            "offset": offset,
            "name": name,
            "process_entity_id": None,
            "source_plugin": source_plugin,
            "source_record_index": index,
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
    return {
        "items": items,
        "warnings": warnings,
        "raw_count": raw_count,
        "accepted_count": accepted,
        "dropped_count": dropped,
        "conflicts": 0,
        "normalization_version": NORMALIZATION_VERSION,
    }
