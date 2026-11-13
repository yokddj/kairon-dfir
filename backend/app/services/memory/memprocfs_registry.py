"""Registry values read from a Windows memory image with MemProcFS.

The registry hives Windows had loaded are in memory, and MemProcFS reads them through its registry
API (``VMMDLL_WinReg_*``) without the kernel's symbols. A memory-only case has no hive files, so
this is where the computer name, its network configuration, its user profiles and the registry
execution artifacts (BAM, UserAssist, ShimCache as loaded at boot) come from.

Two halves:

* :func:`read_registry` runs in MemProcFS's child process (app.services.memory.memprocfs_findevil),
  next to the native library: it reads a fixed list of well-known forensic keys and returns them
  as plain data (values base64-encoded). It imports nothing from the app.
* :func:`normalize_memprocfs_registry` runs in the worker: one document per value, decoded where
  the format is known, plus the host facts the values establish.

A key that is not in memory -- hive not loaded, or its cells paged out -- is reported as
``not_in_memory``, never as absent from the machine.
"""

from __future__ import annotations

import base64
import codecs
import ctypes
import hashlib
import struct
from datetime import UTC, datetime, timedelta
from typing import Any

PLUGIN = "memprocfs.registry"
DOCUMENT_TYPE = "memory_registry_value"
NORMALIZATION_VERSION = "memory_registry_v1"
FILE_NAME = "registry.json"

REG_TYPES = {
    0: "REG_NONE", 1: "REG_SZ", 2: "REG_EXPAND_SZ", 3: "REG_BINARY", 4: "REG_DWORD", 5: "REG_DWORD_BIG_ENDIAN",
    6: "REG_LINK", 7: "REG_MULTI_SZ", 8: "REG_RESOURCE_LIST", 11: "REG_QWORD",
}

# (hive, path, mode, value names to keep or None for all, category)
# mode: "values" -- the key's own values; "subkeys" -- the values of each sub key;
# "subkeys/Count" -- the values of each sub key's Count key (UserAssist).
# {CCS} is the control set Select\Current names.
SYSTEM_TARGETS: tuple[tuple[str, str, tuple[str, ...] | None, str], ...] = (
    ("{CCS}\\Control\\ComputerName\\ComputerName", "values", ("ComputerName",), "computer_name"),
    ("{CCS}\\Control\\TimeZoneInformation", "values", ("TimeZoneKeyName", "StandardName", "Bias", "ActiveTimeBias"), "time_zone"),
    ("{CCS}\\Services\\Tcpip\\Parameters", "values", ("Hostname", "Domain", "NV Hostname", "NV Domain"), "computer_name"),
    ("{CCS}\\Services\\Tcpip\\Parameters\\Interfaces", "subkeys", (
        "IPAddress", "DhcpIPAddress", "SubnetMask", "DhcpSubnetMask", "DefaultGateway", "DhcpDefaultGateway",
        "DhcpServer", "NameServer", "DhcpNameServer", "Domain", "DhcpDomain", "EnableDHCP", "LeaseObtainedTime",
    ), "network_interface"),
    ("{CCS}\\Services\\bam\\State\\UserSettings", "subkeys", None, "bam"),
    ("{CCS}\\Services\\bam\\UserSettings", "subkeys", None, "bam"),
    ("{CCS}\\Control\\Session Manager\\AppCompatCache", "values", ("AppCompatCache",), "shimcache"),
    ("{CCS}\\Services", "subkeys", ("ImagePath", "Start", "Type", "DisplayName"), "service"),
)
SOFTWARE_TARGETS: tuple[tuple[str, str, tuple[str, ...] | None, str], ...] = (
    ("Microsoft\\Windows NT\\CurrentVersion", "values", (
        "ProductName", "DisplayVersion", "CurrentBuild", "EditionID", "InstallDate", "RegisteredOwner", "RegisteredOrganization",
    ), "os_version"),
    ("Microsoft\\Windows NT\\CurrentVersion\\ProfileList", "subkeys", ("ProfileImagePath", "State", "Flags"), "profile"),
    ("Microsoft\\Windows NT\\CurrentVersion\\Winlogon", "values", ("Shell", "Userinit", "DefaultUserName", "DefaultDomainName", "LastUsedUsername", "AutoAdminLogon"), "winlogon"),
    ("Microsoft\\Windows\\CurrentVersion\\Run", "values", None, "autorun"),
    ("Microsoft\\Windows\\CurrentVersion\\RunOnce", "values", None, "autorun"),
    ("WOW6432Node\\Microsoft\\Windows\\CurrentVersion\\Run", "values", None, "autorun"),
    ("WOW6432Node\\Microsoft\\Windows\\CurrentVersion\\RunOnce", "values", None, "autorun"),
)
USER_TARGETS: tuple[tuple[str, str, tuple[str, ...] | None, str], ...] = (
    ("Software\\Microsoft\\Windows\\CurrentVersion\\Run", "values", None, "autorun"),
    ("Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce", "values", None, "autorun"),
    ("Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\UserAssist", "subkeys/Count", None, "userassist"),
    ("Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\RunMRU", "values", None, "run_mru"),
    ("Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\TypedPaths", "values", None, "typed_paths"),
)

# BAM keys' own counters, not programs.
_BAM_BOOKKEEPING = {"version", "sequencenumber"}
_MAX_VALUE_BYTES = 64 * 1024
_MAX_LARGE_VALUE_BYTES = 8 * 1024 * 1024  # AppCompatCache
_MAX_KEYS = 5000
_MAX_VALUES_PER_KEY = 2000


# --------------------------------------------------------------------------
# Reading (MemProcFS child process)
# --------------------------------------------------------------------------

class _FileInfo(ctypes.Structure):
    _fields_ = [("fValid", ctypes.c_int), ("dwHandle", ctypes.c_uint32), ("vaFileObject", ctypes.c_uint64)]


class _HiveInfo(ctypes.Structure):
    # VMMDLL_REGISTRY_HIVE_INFORMATION (vmmdll.h, version 5).
    _fields_ = [
        ("magic", ctypes.c_uint64), ("wVersion", ctypes.c_uint16), ("wSize", ctypes.c_uint16),
        ("_reserved1", ctypes.c_char * 0x34), ("vaCMHIVE", ctypes.c_uint64), ("vaHBASE_BLOCK", ctypes.c_uint64),
        ("cbLength", ctypes.c_uint32), ("uszName", ctypes.c_char * 128), ("uszNameShort", ctypes.c_char * 33),
        ("uszHiveRootPath", ctypes.c_char * 260), ("File", _FileInfo), ("_reserved2", ctypes.c_uint64 * 14),
    ]


def bind(lib: Any) -> bool:
    """Declare the registry functions on the library; False when this MemProcFS lacks them."""
    try:
        lib.VMMDLL_WinReg_HiveList.restype = ctypes.c_int
        lib.VMMDLL_WinReg_HiveList.argtypes = [ctypes.c_void_p, ctypes.c_void_p, ctypes.c_uint32, ctypes.POINTER(ctypes.c_uint32)]
        lib.VMMDLL_WinReg_EnumKeyExU.restype = ctypes.c_int
        lib.VMMDLL_WinReg_EnumKeyExU.argtypes = [ctypes.c_void_p, ctypes.c_char_p, ctypes.c_uint32, ctypes.c_char_p, ctypes.POINTER(ctypes.c_uint32), ctypes.POINTER(ctypes.c_uint64)]
        lib.VMMDLL_WinReg_EnumValueU.restype = ctypes.c_int
        lib.VMMDLL_WinReg_EnumValueU.argtypes = [ctypes.c_void_p, ctypes.c_char_p, ctypes.c_uint32, ctypes.c_char_p, ctypes.POINTER(ctypes.c_uint32), ctypes.POINTER(ctypes.c_uint32), ctypes.c_void_p, ctypes.POINTER(ctypes.c_uint32)]
    except AttributeError:
        return False
    try:
        lib.VMMDLL_WinReg_QueryNameOriginalU.restype = ctypes.c_int
        lib.VMMDLL_WinReg_QueryNameOriginalU.argtypes = [ctypes.c_void_p, ctypes.c_char_p, ctypes.c_int, ctypes.c_char_p, ctypes.POINTER(ctypes.c_uint32)]
    except AttributeError:
        pass  # older MemProcFS: names keep MemProcFS's "_" for "\\"
    return True


class _Reader:
    def __init__(self, lib: Any, handle: int) -> None:
        self.lib = lib
        self.handle = handle
        try:
            self.has_original_names = lib.VMMDLL_WinReg_QueryNameOriginalU.restype is ctypes.c_int
        except AttributeError:
            self.has_original_names = False

    def key(self, path: str) -> tuple[bool, int | None]:
        """Whether the key is readable, and its last write time (FILETIME)."""
        name = ctypes.create_string_buffer(1024)
        size = ctypes.c_uint32(1024)
        written = ctypes.c_uint64(0)
        ok = self.lib.VMMDLL_WinReg_EnumKeyExU(self.handle, path.encode("utf-8"), 0xFFFFFFFF, name, ctypes.byref(size), ctypes.byref(written))
        return bool(ok), (written.value or None) if ok else None

    def subkeys(self, path: str) -> list[tuple[str, int | None]]:
        out = []
        index = 0
        while index < _MAX_KEYS:
            name = ctypes.create_string_buffer(1024)
            size = ctypes.c_uint32(1024)
            written = ctypes.c_uint64(0)
            if not self.lib.VMMDLL_WinReg_EnumKeyExU(self.handle, path.encode("utf-8"), index, name, ctypes.byref(size), ctypes.byref(written)):
                break
            out.append((name.value.decode("utf-8", "replace"), written.value or None))
            index += 1
        return out

    def original_name(self, full_path: str, name: str) -> str:
        """MemProcFS lists names with "\\" replaced by "_" (BAM names a program by its path);
        ask for the name as stored when it may have been changed."""
        if "_" not in name or not self.has_original_names:
            return name
        buffer = ctypes.create_string_buffer(2048)
        size = ctypes.c_uint32(2048)
        try:
            if self.lib.VMMDLL_WinReg_QueryNameOriginalU(self.handle, full_path.encode("utf-8"), 1, buffer, ctypes.byref(size)):
                return buffer.value.decode("utf-8", "replace") or name
        except (AttributeError, ctypes.ArgumentError):
            pass
        return name

    def values(self, path: str, keep: tuple[str, ...] | None) -> list[dict[str, Any]]:
        wanted = {name.lower() for name in keep} if keep else None
        out = []
        index = 0
        while index < _MAX_VALUES_PER_KEY:
            name = ctypes.create_string_buffer(1024)
            name_size = ctypes.c_uint32(1024)
            value_type = ctypes.c_uint32(0)
            limit = _MAX_LARGE_VALUE_BYTES if keep and "appcompatcache" in (wanted or set()) else _MAX_VALUE_BYTES
            data = ctypes.create_string_buffer(limit)
            data_size = ctypes.c_uint32(limit)
            if not self.lib.VMMDLL_WinReg_EnumValueU(self.handle, path.encode("utf-8"), index, name, ctypes.byref(name_size), ctypes.byref(value_type), data, ctypes.byref(data_size)):
                break
            index += 1
            value_name = name.value.decode("utf-8", "replace")
            if wanted is not None and value_name.lower() not in wanted:
                continue
            value_name = self.original_name(f"{path}\\{value_name}", value_name)
            raw = data.raw[: min(data_size.value, limit)]
            out.append({"name": value_name, "type": value_type.value, "size": data_size.value, "data": base64.b64encode(raw).decode("ascii")})
        return out


def _hives(lib: Any, handle: int) -> list[dict[str, Any]]:
    count = ctypes.c_uint32(0)
    if not lib.VMMDLL_WinReg_HiveList(handle, None, 0, ctypes.byref(count)) or not count.value:
        return []
    array = (_HiveInfo * count.value)()
    if not lib.VMMDLL_WinReg_HiveList(handle, array, count.value, ctypes.byref(count)):
        return []
    return [
        {
            "address": int(item.vaCMHIVE),
            "name": item.uszName.decode("utf-8", "replace"),
            "path": item.uszNameShort.decode("utf-8", "replace"),
        }
        for item in array[: count.value]
    ]


def read_registry(lib: Any, handle: int) -> dict[str, Any]:
    """The target keys of every loaded hive, as plain data for registry.json."""
    if not bind(lib):
        return {"available": False, "reason": "This MemProcFS has no registry API.", "keys": [], "missing": []}
    reader = _Reader(lib, handle)
    keys: list[dict[str, Any]] = []
    missing: list[dict[str, Any]] = []

    for hive in ("SYSTEM", "SOFTWARE"):
        if not reader.key(f"HKLM\\{hive}")[0]:
            missing.append({"path": f"HKLM\\{hive}", "category": "hive", "hive": hive, "scope": "hive"})
    control_set = _current_control_set(reader)
    for relative, mode, keep, category in SYSTEM_TARGETS:
        relative = relative.replace("{CCS}", control_set or "ControlSet001")
        _collect(reader, f"HKLM\\SYSTEM\\{relative}", f"HKLM\\SYSTEM\\{relative}", mode, keep, category, {"hive": "SYSTEM"}, keys, missing)
    for relative, mode, keep, category in SOFTWARE_TARGETS:
        _collect(reader, f"HKLM\\SOFTWARE\\{relative}", f"HKLM\\SOFTWARE\\{relative}", mode, keep, category, {"hive": "SOFTWARE"}, keys, missing)

    profiles = {
        _norm_path(_decode_string(_b64(value["data"]), value["type"])): key["subkey"]
        for key in keys if key.get("category") == "profile"
        for value in key["values"] if value["name"].lower() == "profileimagepath"
    }
    hives = _hives(lib, handle)
    for hive in hives:
        if "ntuser" not in hive["name"].lower():
            continue
        sid, profile = _profile_for_hive(hive["path"], profiles)
        base = f"0x{hive['address']:x}\\ROOT"
        owner = f"HKU\\{sid}" if sid else f"HKU\\{hive['path'] or hex(hive['address'])}"
        context = {"hive": "NTUSER.DAT", "hive_file": hive["path"], "user_sid": sid, "profile_path": profile}
        for relative, mode, keep, category in USER_TARGETS:
            _collect(reader, f"{base}\\{relative}", f"{owner}\\{relative}", mode, keep, category, context, keys, missing)
    return {
        "available": True,
        "control_set": control_set,
        "hives": [{"name": h["name"], "path": h["path"]} for h in hives],
        "keys": keys,
        "missing": missing,
    }


def _current_control_set(reader: _Reader) -> str | None:
    for value in reader.values("HKLM\\SYSTEM\\Select", ("Current",)):
        raw = _b64(value["data"])
        if len(raw) >= 4:
            return f"ControlSet{struct.unpack('<I', raw[:4])[0]:03d}"
    return None


def _collect(reader: _Reader, path: str, display: str, mode: str, keep, category: str, context: dict, keys: list, missing: list) -> None:
    if len(keys) >= _MAX_KEYS:
        return
    exists, written = reader.key(path)
    if not exists:
        missing.append({"path": display, "category": category, **{k: v for k, v in context.items() if k in ("hive", "user_sid")}})
        return
    if mode == "values":
        keys.append({"path": display, "category": category, "last_write": written, "values": reader.values(path, keep), **context})
        return
    for name, sub_written in reader.subkeys(path):
        if len(keys) >= _MAX_KEYS:
            return
        sub_path, sub_display = f"{path}\\{name}", f"{display}\\{name}"
        if mode == "subkeys/Count":
            sub_path, sub_display = f"{sub_path}\\Count", f"{sub_display}\\Count"
            _, sub_written = reader.key(sub_path)
        values = reader.values(sub_path, keep)
        if values:
            keys.append({"path": sub_display, "subkey": name, "category": category, "last_write": sub_written, "values": values, **context})


def _profile_for_hive(hive_path: str, profiles: dict[str, str]) -> tuple[str | None, str | None]:
    """Which ProfileList entry an NTUSER.DAT hive belongs to.

    MemProcFS gives the hive's file path, sometimes truncated at its start; it ends with
    <profile path>\\ntuser.dat, so it is matched as a suffix of a profile path.
    """
    tail = _norm_path(hive_path)
    if tail.endswith("\\ntuser.dat"):
        tail = tail[: -len("\\ntuser.dat")]
    if not tail:
        return None, None
    matches = [(path, sid) for path, sid in profiles.items() if path and (path.endswith(tail) or tail.endswith(path))]
    if len(matches) != 1:
        return None, None
    return matches[0][1], matches[0][0]


def _norm_path(value: str | None) -> str:
    return str(value or "").strip().strip("\x00").replace("/", "\\").lower()


# --------------------------------------------------------------------------
# Normalizing (worker)
# --------------------------------------------------------------------------

def normalize_memprocfs_registry(
    payload: Any,
    *,
    case_id: str,
    evidence_id: str,
    scan_run_id: str,
    plugin_run_id: str,
    source_plugin: str = PLUGIN,
) -> dict[str, Any]:
    snapshot = payload[0] if isinstance(payload, list) and payload and isinstance(payload[0], dict) else payload
    snapshot = snapshot if isinstance(snapshot, dict) else {}
    common = {
        "case_id": case_id, "evidence_id": evidence_id, "scan_run_id": scan_run_id,
        "plugin_run_id": plugin_run_id, "source_plugin": source_plugin,
        "normalization_version": NORMALIZATION_VERSION, "document_type": DOCUMENT_TYPE,
        "confidence": "reported_by_tool",
    }
    items: list[dict[str, Any]] = []
    warnings: list[str] = []
    raw_count = 0
    for key in snapshot.get("keys") or []:
        for value in key.get("values") or []:
            raw_count += 1
            if key.get("category") == "bam" and str(value.get("name") or "").lower() in _BAM_BOOKKEEPING:
                continue
            try:
                items.extend(_value_documents(key, value, common))
            except Exception as exc:  # noqa: BLE001 - one odd value must not lose the rest
                warnings.append(f"registry_value_not_decoded:{key.get('category')}:{type(exc).__name__}")
    # Only a whole hive that cannot be read is reported: a missing key is usually one this
    # system never had (no RunOnce entries, no UserAssist for a service account).
    for entry in snapshot.get("missing") or []:
        if entry.get("scope") != "hive":
            continue
        items.append({
            **common,
            "document_id": _document_id(scan_run_id, "missing", entry.get("path")),
            "status": "not_in_memory",
            "category": entry.get("category"),
            "hive": entry.get("hive"),
            "user_sid": entry.get("user_sid"),
            "key_path": entry.get("path"),
            "summary": "Hive not readable from this memory image (not loaded, or its pages not captured): its values are unknown, not absent.",
        })
    if snapshot and not snapshot.get("available", True):
        warnings.append(str(snapshot.get("reason") or "registry_not_available"))
    return {
        "items": items,
        "warnings": warnings,
        "raw_count": raw_count,
        "accepted_count": len(items),
        "dropped_count": 0,
        "conflicts": 0,
        "normalization_version": NORMALIZATION_VERSION,
    }


def _value_documents(key: dict[str, Any], value: dict[str, Any], common: dict[str, Any]) -> list[dict[str, Any]]:
    raw = _b64(value.get("data"))
    value_type = int(value.get("type") or 0)
    category = key.get("category")
    base = {
        **common,
        "status": "read",
        "category": category,
        "hive": key.get("hive"),
        "hive_file": key.get("hive_file"),
        "user_sid": key.get("user_sid") or (key.get("subkey") if category in ("bam", "profile") else None),
        "profile_path": key.get("profile_path"),
        "key_path": key.get("path"),
        "key_last_write": _filetime_iso(key.get("last_write")),
        "value_name": value.get("name"),
        "value_type": REG_TYPES.get(value_type, str(value_type)),
        "value_size": value.get("size"),
    }
    if category == "shimcache" and str(value.get("name") or "").lower() == "appcompatcache":
        return _shimcache_documents(raw, base)
    decoded, timestamp = _decode(category, key, value, raw, value_type)
    text = _value_text(raw, value_type)
    document = {
        **base,
        "document_id": _document_id(common["scan_run_id"], key.get("path"), value.get("name")),
        "value_data": text[:4096] if text is not None else None,
        "decoded": decoded or None,
        "timestamp": timestamp or base["key_last_write"],
        "timestamp_source": ("decoded" if timestamp else "key_last_write") if (timestamp or base["key_last_write"]) else None,
    }
    document["summary"] = _summary(document)
    return [document]


def _decode(category: str | None, key: dict, value: dict, raw: bytes, value_type: int) -> tuple[dict[str, Any], str | None]:
    name = str(value.get("name") or "")
    if category == "bam" and value_type == 3 and len(raw) >= 8 and name.lower() not in ("version", "sequencenumber"):
        when = _filetime_iso(struct.unpack("<Q", raw[:8])[0])
        return {"program": name, "last_execution": when}, when
    if category == "userassist" and value_type == 3:
        program = codecs.decode(name, "rot_13")
        decoded: dict[str, Any] = {"program": program}
        when = None
        if len(raw) >= 68:  # Windows 7 and later
            session, run_count, focus_count, focus_ms = struct.unpack("<IIII", raw[:16])
            when = _filetime_iso(struct.unpack("<Q", raw[60:68])[0])
            decoded.update({"run_count": run_count, "focus_count": focus_count, "focus_seconds": focus_ms // 1000, "last_run": when})
        elif len(raw) >= 16:  # Windows XP
            run_count = max(struct.unpack("<I", raw[4:8])[0] - 5, 0)
            when = _filetime_iso(struct.unpack("<Q", raw[8:16])[0])
            decoded.update({"run_count": run_count, "last_run": when})
        return decoded, when
    if category == "network_interface" and name.lower() in ("leaseobtainedtime",) and len(raw) >= 4:
        seconds = struct.unpack("<I", raw[:4])[0]
        return {"lease_obtained": datetime.fromtimestamp(seconds, UTC).isoformat()}, None
    if category == "os_version" and name.lower() == "installdate" and len(raw) >= 4:
        return {"install_date": datetime.fromtimestamp(struct.unpack("<I", raw[:4])[0], UTC).isoformat()}, None
    return {}, None


def _shimcache_documents(raw: bytes, base: dict[str, Any]) -> list[dict[str, Any]]:
    from app.ingest.raw_parsers.shimcache_parser import _get_shimcache_entries

    try:
        entries = _get_shimcache_entries(raw, partial=True)
    except (ValueError, struct.error):
        entries = []
    out = []
    for position, entry in enumerate(entries):
        path = entry.get("path") or entry.get("file_path")
        modified = entry.get("last_modified") or entry.get("last_modified_time")
        document = {
            **base,
            "document_id": _document_id(base["scan_run_id"], base["key_path"], "AppCompatCache", position, path),
            "value_data": None,
            "decoded": {"path": path, "last_modified": modified, "position": position, "executed": entry.get("executed")},
            "timestamp": modified or None,
            "timestamp_source": "file_last_modified" if modified else None,
        }
        document["summary"] = _summary(document)
        out.append(document)
    return out


def _summary(document: dict[str, Any]) -> str:
    decoded = document.get("decoded") or {}
    category = document.get("category")
    if category == "bam":
        return f"BAM: {decoded.get('program')} last ran {decoded.get('last_execution')}"
    if category == "userassist":
        return f"UserAssist: {decoded.get('program')} ran {decoded.get('run_count')} times, last {decoded.get('last_run')}"
    if category == "shimcache":
        return f"ShimCache (as loaded at boot): {decoded.get('path')}"
    return f"{document.get('value_name')} = {document.get('value_data')}"[:512]


def _value_text(raw: bytes, value_type: int) -> str | None:
    if value_type in (1, 2, 6):
        return _decode_string(raw, value_type)
    if value_type == 7:
        return " | ".join(part for part in _decode_string(raw, value_type).split("\x00") if part)
    if value_type == 4 and len(raw) >= 4:
        return str(struct.unpack("<I", raw[:4])[0])
    if value_type == 5 and len(raw) >= 4:
        return str(struct.unpack(">I", raw[:4])[0])
    if value_type == 11 and len(raw) >= 8:
        return str(struct.unpack("<Q", raw[:8])[0])
    if not raw:
        return None
    return raw[:512].hex()


def _decode_string(raw: bytes, value_type: int) -> str:
    if len(raw) >= 2 and raw[1:2] == b"\x00" or (len(raw) % 2 == 0 and raw.count(0) >= len(raw) // 3):
        text = raw.decode("utf-16le", "replace")
    else:
        text = raw.decode("utf-8", "replace")
    return text if value_type == 7 else text.rstrip("\x00")


def _b64(value: Any) -> bytes:
    try:
        return base64.b64decode(str(value or ""))
    except (ValueError, TypeError):
        return b""


def _filetime_iso(value: Any) -> str | None:
    try:
        ticks = int(value or 0)
    except (TypeError, ValueError):
        return None
    # Before 1980 or after 2100 is not a real time for these artifacts.
    if ticks < 119600064000000000 or ticks > 157469184000000000:
        return None
    return (datetime(1601, 1, 1, tzinfo=UTC) + timedelta(microseconds=ticks // 10)).isoformat()


def _document_id(*parts: Any) -> str:
    digest = hashlib.sha256("|".join(str(part) for part in parts).encode("utf-8")).hexdigest()[:24]
    return f"{parts[0]}:{DOCUMENT_TYPE}:{digest}"


# --------------------------------------------------------------------------
# What the values establish about the host
# --------------------------------------------------------------------------

SOURCE_KIND_COMPUTERNAME = "memory_registry_computername"
SOURCE_KIND_TIMEZONE = "memory_registry_timezone_key_name"
SOURCE_KIND_PROFILE_LIST = "profile_list"


def host_fact_inputs(documents: list[dict[str, Any]], *, run_id: str, plugin_run_id: str) -> list[dict[str, Any]]:
    """Host fact observation documents (hostname, timezone) for app.ingest.host_facts_extraction."""
    from app.ingest.linux.os_info import FACT_HOSTNAME
    from app.ingest.linux.timezone import FACT_TYPE_TIMEZONE

    def first(category: str, *names: str) -> str | None:
        wanted = [name.lower() for name in names]
        for name in wanted:
            for doc in documents:
                if doc.get("status") == "read" and doc.get("category") == category and str(doc.get("value_name") or "").lower() == name:
                    value = str(doc.get("value_data") or "").strip()
                    if value:
                        return value
        return None

    facts: list[dict[str, Any]] = []
    hostname = first("computer_name", "ComputerName", "Hostname")
    if hostname:
        facts.append(_fact(FACT_HOSTNAME, hostname, hostname.upper() if hostname.isascii() else hostname, SOURCE_KIND_COMPUTERNAME, run_id, plugin_run_id))
    timezone = first("time_zone", "TimeZoneKeyName")
    if timezone:
        facts.append(_fact(FACT_TYPE_TIMEZONE, timezone, timezone, SOURCE_KIND_TIMEZONE, run_id, plugin_run_id))
    # Shaped like app.ingest.host_facts_extraction's inline observation documents.
    return [{"host_fact": fact} for fact in facts]


def _fact(fact_type: str, raw: str, normalized: str, kind: str, run_id: str, plugin_run_id: str) -> dict[str, Any]:
    return {
        "fact_type": fact_type,
        "artifact_family": "memory_registry",
        "artifact_type": kind,
        "source_file": f"memory:{PLUGIN}",
        "raw_value": raw,
        "normalized_value": normalized,
        # The machine's own registry configuration, read from the loaded hive: as reliable as the
        # hive file on disk for what it says, ranked just below it (app.services.host_facts).
        "confidence": "high",
        "parse_status": "valid",
        "reason": "",
        "extra_provenance": {"memory_run_id": run_id, "memory_plugin_run_id": plugin_run_id, "plugin": PLUGIN},
    }


def host_user_documents(documents: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """ProfileList entries as Host User Facts, like the SOFTWARE hive parser on disk."""
    profiles: dict[str, dict[str, Any]] = {}
    for doc in documents:
        if doc.get("status") != "read" or doc.get("category") != "profile" or not doc.get("user_sid"):
            continue
        entry = profiles.setdefault(doc["user_sid"], {})
        name = str(doc.get("value_name") or "").lower()
        if name == "profileimagepath":
            entry["home"] = doc.get("value_data")
        elif name == "state":
            entry["state"] = doc.get("value_data")
    out = []
    for sid, entry in sorted(profiles.items()):
        if not entry.get("home"):
            continue
        attributes = {"sid": sid}
        if entry.get("state") is not None:
            attributes["profile_state"] = str(entry["state"])
        out.append({"host_user_fact": {
            "source_kind": SOURCE_KIND_PROFILE_LIST,
            "username": None,
            "home": entry["home"],
            "attributes": attributes,
            "parser": PLUGIN,
            "source_file": f"memory:{PLUGIN}",
        }})
    return out
