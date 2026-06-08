from datetime import UTC, datetime, timedelta
import hashlib
import json
from pathlib import Path, PureWindowsPath
import re

from dateutil import parser as date_parser

from app.analysis.suspicious import detect_suspicious_path, is_suspicious_double_extension, is_windows_unc_path, normalize_windows_path_for_classification
from app.ingest.autoruns.discovery import looks_like_startup_folder_path
from app.ingest.cloud_sync.helpers import detect_cloud_provider_from_path
from app.ingest.identity_extraction import extract_host, extract_user, extract_user_from_path, is_valid_hostname, normalize_hostname
from app.ingest.browser.normalizer import normalize_browser_event
from app.ingest.eztools.lecmd import select_lnk_effective_target, _suffix as lecmd_suffix, _basename as lecmd_basename
from app.ingest.velociraptor.path_utils import normalize_velociraptor_path
from app.ingest.windows_event_mapping import classify_windows_event
from app.ingest.wmi.helpers import classify_wmi_activity_event


def first_value(row: dict, candidates: list[str]) -> str | None:
    candidate_map = {str(key or "").lower(): value for key, value in row.items() if str(key or "").strip()}
    for candidate in candidates:
        value = candidate_map.get(candidate.lower())
        if value not in (None, ""):
            return str(value)
    return None


def _lower_bool(value: str | None) -> bool | None:
    if value is None:
        return None
    normalized = str(value).strip().lower()
    if normalized in {"true", "yes", "1", "in use"}:
        return True
    if normalized in {"false", "no", "0"}:
        return False
    return None


def _suspicious_path(path: str | None) -> bool:
    if not path:
        return False
    lower = path.lower()
    return any(token in lower for token in ["\\temp\\", "\\appdata\\", "\\programdata\\", "\\users\\public\\", "\\windows\\temp\\"])


def _clean_placeholder(value: str | None) -> str | None:
    if value is None:
        return None
    normalized = str(value).strip()
    if normalized in {"", "-", "--", "N/A", "n/a", "null", "None"}:
        return None
    return normalized


def _normalize_windowsish_path(value: str | None) -> str | None:
    cleaned = _clean_placeholder(value)
    if not cleaned:
        return None
    return normalize_windows_path_for_classification(cleaned)


def _parse_iso_timestamp(value: str | None) -> str | None:
    cleaned = _clean_placeholder(value)
    if not cleaned:
        return None
    try:
        parsed = date_parser.parse(cleaned)
        if parsed.tzinfo is None:
            parsed = parsed.replace(tzinfo=UTC)
        return parsed.isoformat()
    except Exception:  # noqa: BLE001
        return None


def _safe_windows_basename(value: str | None) -> str | None:
    path = _normalize_windowsish_path(value) or _clean_placeholder(value)
    if not path:
        return None
    try:
        return PureWindowsPath(path).name or path
    except Exception:  # noqa: BLE001
        return Path(path.replace("\\", "/")).name or path


def _safe_windows_parent(value: str | None) -> str | None:
    path = _normalize_windowsish_path(value) or _clean_placeholder(value)
    if not path:
        return None
    try:
        parent = str(PureWindowsPath(path).parent)
    except Exception:  # noqa: BLE001
        parent = str(Path(path.replace("\\", "/")).parent).replace("/", "\\")
    if parent in {".", ""}:
        return None
    return parent


def _parse_hashes_field(value: str | None) -> dict[str, str | None]:
    result: dict[str, str | None] = {"md5": None, "sha1": None, "sha256": None}
    cleaned = _clean_placeholder(value)
    if not cleaned:
        return result
    for fragment in re.split(r"[;,|]", cleaned):
        if "=" not in fragment:
            continue
        name, raw_value = fragment.split("=", 1)
        key = name.strip().lower()
        normalized = _normalize_hash(raw_value, {32, 40, 64})
        if key in result and normalized:
            result[key] = normalized
    return result


def _compact_dict(value: dict) -> dict:
    return {key: item for key, item in value.items() if item not in (None, "", [], {})}


def _evtx_event_data(row: dict) -> dict:
    payload = row.get("Payload")
    if isinstance(payload, dict):
        return payload
    event_data = row.get("EventData")
    if isinstance(event_data, dict):
        return event_data
    return {}


def _evtx_value(row: dict, names: list[str]) -> str | None:
    event_data = _evtx_event_data(row)
    lowered_event_data = {str(key or "").lower(): value for key, value in event_data.items() if str(key or "").strip()}
    for name in names:
        value = lowered_event_data.get(name.lower())
        if value not in (None, ""):
            return str(value)
    return first_value(row, names)


def _split_windows_user(value: str | None) -> tuple[str | None, str | None]:
    cleaned = _clean_placeholder(value)
    if not cleaned:
        return None, None
    if "\\" in cleaned:
        domain, name = cleaned.split("\\", 1)
        return _clean_placeholder(name), _clean_placeholder(domain)
    if "@" in cleaned:
        name, domain = cleaned.split("@", 1)
        return _clean_placeholder(name), _clean_placeholder(domain)
    return cleaned, None


def _set_nested(document: dict, path: list[str], value: object | None) -> None:
    if value in (None, "", [], {}):
        return
    target = document
    for key in path[:-1]:
        child = target.get(key)
        if not isinstance(child, dict):
            child = {}
            target[key] = child
        target = child
    target[path[-1]] = value


def _update_process_identity(document: dict, *, prefix: str = "process", image: str | None = None, command_line: str | None = None, pid: int | None = None, guid: str | None = None) -> dict:
    path = _normalize_windowsish_path(image)
    name = _safe_windows_basename(path or image)
    payload = _compact_dict(
        {
            "name": name,
            "path": path or _clean_placeholder(image),
            "executable": path or _clean_placeholder(image),
            "command_line": _clean_placeholder(command_line),
            "pid": pid,
            "entity_id": _clean_placeholder(guid),
            "guid": _clean_placeholder(guid),
        }
    )
    if prefix == "process":
        document.setdefault("process", {}).update(payload)
        if path:
            document["process"]["application"] = name
    else:
        _set_nested(document, prefix.split("."), payload)
    return payload


def _apply_sysmon_event_normalization(document: dict, row: dict, event_id: int | None, source_file: str | None) -> dict:
    channel = _evtx_value(row, ["Channel", "LogName"])
    provider = _evtx_value(row, ["Provider", "ProviderName", "SourceName"])
    if "sysmon" not in str(channel or "").lower() and "sysmon" not in str(provider or "").lower():
        return document

    event_data = _evtx_event_data(row)
    if event_data:
        document.setdefault("windows", {})["event_data"] = event_data
        document.setdefault("winlog", {})["event_data"] = event_data

    sysmon_actions = {
        1: ("process", "sysmon_process_created", "Sysmon process created"),
        3: ("network", "sysmon_network_connection", "Sysmon network connection"),
        7: ("library", "sysmon_image_loaded", "Sysmon image loaded"),
        8: ("process", "sysmon_create_remote_thread", "Sysmon remote thread created"),
        10: ("process", "sysmon_process_access", "Sysmon process access"),
        11: ("file", "sysmon_file_created", "Sysmon file created"),
        12: ("registry", "sysmon_registry_key_event", "Sysmon registry key event"),
        13: ("registry", "sysmon_registry_value_set", "Sysmon registry value set"),
        14: ("registry", "sysmon_registry_key_renamed", "Sysmon registry key renamed"),
        15: ("file", "sysmon_file_create_stream_hash", "Sysmon file stream hash"),
        22: ("network", "sysmon_dns_query", "Sysmon DNS query"),
        23: ("file", "sysmon_file_deleted", "Sysmon file deleted"),
        26: ("file", "sysmon_file_deleted", "Sysmon file deleted"),
    }
    category, action, default_message = sysmon_actions.get(event_id or -1, ("windows_event", f"sysmon_event_{event_id}" if event_id else "sysmon_event", f"Sysmon event {event_id or 'unknown'}"))
    document.setdefault("event", {}).update({"category": category, "type": action, "action": action})
    document["event"]["message"] = default_message
    document.setdefault("artifact", {})["type"] = "windows_event"
    document["artifact"]["parser"] = document["artifact"].get("parser") or "evtxecmd_csv"
    document["source_file"] = source_file
    document.setdefault("windows", {}).update({"event_id": event_id, "channel": channel or "Microsoft-Windows-Sysmon/Operational", "provider": provider or "Microsoft-Windows-Sysmon"})

    user_value = _evtx_value(row, ["User"])
    user_name, user_domain = _split_windows_user(user_value)
    if user_name:
        document.setdefault("user", {})["name"] = user_name
    if user_domain:
        document.setdefault("user", {})["domain"] = user_domain

    image = _evtx_value(row, ["Image", "SourceImage"])
    command_line = _evtx_value(row, ["CommandLine"])
    pid = _parse_pidish(_evtx_value(row, ["ProcessId", "SourceProcessId"]))
    guid = _evtx_value(row, ["ProcessGuid", "ProcessGUID", "SourceProcessGuid", "SourceProcessGUID"])
    process_payload = _update_process_identity(document, image=image, command_line=command_line, pid=pid, guid=guid)
    current_directory = _normalize_windowsish_path(_evtx_value(row, ["CurrentDirectory"]))
    if current_directory:
        document["process"]["current_directory"] = current_directory
        document["process"]["working_directory"] = current_directory
    hashes = _parse_hashes_field(_evtx_value(row, ["Hashes"]))
    if any(hashes.values()):
        document["process"]["hashes"] = hashes
        document["process"]["hash"] = hashes
    integrity_level = _evtx_value(row, ["IntegrityLevel"])
    if integrity_level:
        document["process"]["integrity_level"] = integrity_level
        document["integrity_level"] = integrity_level
    logon_id = _evtx_value(row, ["LogonId"])
    if logon_id:
        document["logon"] = {**(document.get("logon") or {}), "id": logon_id}

    parent_image = _evtx_value(row, ["ParentImage"])
    parent_command_line = _evtx_value(row, ["ParentCommandLine"])
    parent_pid = _parse_pidish(_evtx_value(row, ["ParentProcessId"]))
    parent_guid = _evtx_value(row, ["ParentProcessGuid", "ParentProcessGUID"])
    parent_payload = _compact_dict(
        {
            "name": _safe_windows_basename(parent_image),
            "path": _normalize_windowsish_path(parent_image),
            "executable": _normalize_windowsish_path(parent_image),
            "command_line": _clean_placeholder(parent_command_line),
            "pid": parent_pid,
            "entity_id": _clean_placeholder(parent_guid),
            "guid": _clean_placeholder(parent_guid),
        }
    )
    if parent_payload:
        document["process"]["parent"] = {**(document["process"].get("parent") or {}), **parent_payload}
        document.setdefault("parent", {}).setdefault("process", {}).update(parent_payload)
        document["process"]["parent_name"] = parent_payload.get("name")
        document["process"]["parent_path"] = parent_payload.get("path")
        document["process"]["parent_command_line"] = parent_payload.get("command_line")
        document["process"]["ppid"] = parent_pid
        document["process"]["parent_pid"] = parent_pid
        document["process"]["parent_entity_id"] = parent_guid

    if event_id == 1:
        document.setdefault("execution", {}).update({"source": "sysmon_process_creation", "is_execution_confirmed": True, "confidence": "high", "program_name": process_payload.get("name"), "interpretation": "Sysmon Event ID 1 confirms process creation"})
        document["event"]["message"] = f"Sysmon process created: {command_line or process_payload.get('executable') or process_payload.get('name') or 'unknown'}"
        document["key_entity"] = command_line or process_payload.get("executable") or process_payload.get("name")

    if event_id == 3:
        src_ip = _evtx_value(row, ["SourceIp", "SourceAddress"])
        src_port = _parse_pidish(_evtx_value(row, ["SourcePort"]))
        dst_ip = _evtx_value(row, ["DestinationIp", "DestinationAddress"])
        dst_port = _parse_pidish(_evtx_value(row, ["DestinationPort"]))
        dst_host = _evtx_value(row, ["DestinationHostname", "DestinationHostName"])
        protocol = _evtx_value(row, ["Protocol"])
        initiated = _lower_bool(_evtx_value(row, ["Initiated"]))
        document.setdefault("network", {}).update(_compact_dict({"source_ip": src_ip, "source_port": src_port, "destination_ip": dst_ip, "destination_port": dst_port, "domain": dst_host, "protocol": protocol, "direction": "outbound" if initiated is True else "inbound" if initiated is False else None, "initiated": initiated}))
        document.setdefault("source", {}).update(_compact_dict({"ip": src_ip, "port": src_port}))
        document.setdefault("destination", {}).update(_compact_dict({"ip": dst_ip, "port": dst_port, "hostname": dst_host, "domain": dst_host}))
        document["event"]["message"] = f"Sysmon network connection: {src_ip or '?'}:{src_port or '?'} -> {dst_host or dst_ip or '?'}:{dst_port or '?'}"
        document["key_entity"] = f"{dst_host or dst_ip}:{dst_port}" if (dst_host or dst_ip or dst_port) else None

    if event_id == 7:
        loaded_path = _normalize_windowsish_path(_evtx_value(row, ["ImageLoaded"]))
        loaded_hashes = _parse_hashes_field(_evtx_value(row, ["Hashes"]))
        loaded_payload = _compact_dict({"path": loaded_path, "name": _safe_windows_basename(loaded_path), "hash": loaded_hashes if any(loaded_hashes.values()) else None, "signed": _lower_bool(_evtx_value(row, ["Signed"])), "signature": _evtx_value(row, ["Signature"]), "signature_status": _evtx_value(row, ["SignatureStatus"])})
        document["image"] = {**(document.get("image") or {}), "loaded": loaded_payload}
        document.setdefault("module", {}).update(loaded_payload)
        document["event"]["message"] = f"Sysmon image loaded: {loaded_path or 'unknown'}"
        document["key_entity"] = loaded_path

    if event_id in {11, 15, 23, 26}:
        target = _normalize_windowsish_path(_evtx_value(row, ["TargetFilename"]))
        file_hashes = _parse_hashes_field(_evtx_value(row, ["Hashes"]))
        document.setdefault("file", {}).update(_compact_dict({"path": target, "name": _safe_windows_basename(target), "directory": _safe_windows_parent(target), "parent_path": _safe_windows_parent(target), "extension": _appcompat_extension(target), "created": _parse_iso_timestamp(_evtx_value(row, ["CreationUtcTime"])), "hash": file_hashes if any(file_hashes.values()) else None, "md5": file_hashes.get("md5"), "sha1": file_hashes.get("sha1"), "sha256": file_hashes.get("sha256")}))
        document["target"] = {**(document.get("target") or {}), "filename": target}
        document["event"]["message"] = f"{default_message}: {target or 'unknown'}"
        document["key_entity"] = target

    if event_id in {12, 13, 14}:
        target_object = _evtx_value(row, ["TargetObject"])
        details = _evtx_value(row, ["Details"])
        reg_event_type = _evtx_value(row, ["EventType"]) or action
        key_path = _normalize_windowsish_path(target_object)
        value_name = None
        if key_path and "\\" in key_path:
            value_name = PureWindowsPath(key_path).name
        document.setdefault("registry", {}).update(_compact_dict({"path": key_path, "key_path": key_path, "key": _safe_windows_parent(key_path), "value": value_name, "value_name": value_name, "data": details, "value_data": details, "event_type": reg_event_type}))
        document.setdefault("artifact", {})["type"] = "registry_event"
        document.setdefault("artifact", {})["parser"] = document.get("artifact", {}).get("parser") or "sysmon_registry"
        document["event"]["type"] = "registry_value_set" if event_id == 13 else "registry_key_or_value_renamed" if event_id == 14 else "registry_key_created_or_deleted"
        document["event"]["message"] = f"{default_message}: {target_object or 'unknown'}"
        document["key_entity"] = target_object

    if event_id == 22:
        query_name = _evtx_value(row, ["QueryName"])
        query_results = _evtx_value(row, ["QueryResults"])
        answers = [item for item in re.split(r"[;,]\s*", query_results or "") if item]
        document.setdefault("dns", {}).update(_compact_dict({"question": {"name": query_name}, "query": query_name, "name": query_name, "domain": query_name, "answers": answers, "data": query_results, "status": _evtx_value(row, ["QueryStatus"])}))
        document["event"]["message"] = f"Sysmon DNS query: {query_name or 'unknown'}"
        document["key_entity"] = query_name

    if event_id == 10:
        target_image = _evtx_value(row, ["TargetImage"])
        document.setdefault("target", {}).setdefault("process", {}).update(_compact_dict({"guid": _evtx_value(row, ["TargetProcessGuid", "TargetProcessGUID"]), "entity_id": _evtx_value(row, ["TargetProcessGuid", "TargetProcessGUID"]), "pid": _parse_pidish(_evtx_value(row, ["TargetProcessId"])), "executable": _normalize_windowsish_path(target_image), "path": _normalize_windowsish_path(target_image), "name": _safe_windows_basename(target_image)}))
        document.setdefault("source", {}).setdefault("process", {}).update(process_payload)
        document["process"]["granted_access"] = _evtx_value(row, ["GrantedAccess"])
        document["process"]["call_trace"] = _evtx_value(row, ["CallTrace"])
        document["event"]["message"] = f"Sysmon process access: {process_payload.get('name') or 'source'} -> {_safe_windows_basename(target_image) or 'target'}"
        document["key_entity"] = target_image

    if event_id == 8:
        target_image = _evtx_value(row, ["TargetImage"])
        document.setdefault("target", {}).setdefault("process", {}).update(_compact_dict({"guid": _evtx_value(row, ["TargetProcessGuid", "TargetProcessGUID"]), "entity_id": _evtx_value(row, ["TargetProcessGuid", "TargetProcessGUID"]), "pid": _parse_pidish(_evtx_value(row, ["TargetProcessId"])), "executable": _normalize_windowsish_path(target_image), "path": _normalize_windowsish_path(target_image), "name": _safe_windows_basename(target_image)}))
        document.setdefault("source", {}).setdefault("process", {}).update(process_payload)
        document["process"]["start_address"] = _evtx_value(row, ["StartAddress"])
        document["process"]["start_module"] = _evtx_value(row, ["StartModule"])
        document["process"]["start_function"] = _evtx_value(row, ["StartFunction"])
        document["event"]["message"] = f"Sysmon remote thread: {process_payload.get('name') or 'source'} -> {_safe_windows_basename(target_image) or 'target'}"
        document["key_entity"] = target_image

    document["tags"] = sorted(set(document.get("tags", [])) | {"sysmon"})
    return document


def _apply_security_4663_normalization(document: dict, row: dict, event_id: int | None) -> dict:
    if event_id != 4663:
        return document
    provider = _evtx_value(row, ["Provider", "ProviderName", "SourceName"])
    channel = _evtx_value(row, ["Channel", "LogName"])
    if "security" not in str(channel or "").lower() and "microsoft-windows-security-auditing" not in str(provider or "").lower():
        return document

    object_name = _clean_placeholder(_evtx_value(row, ["ObjectName", "Object Name"]))
    object_type = _clean_placeholder(_evtx_value(row, ["ObjectType", "Object Type"]))
    object_server = _clean_placeholder(_evtx_value(row, ["ObjectServer", "Object Server"]))
    access_mask = _clean_placeholder(_evtx_value(row, ["AccessMask"]))
    accesses_raw = _clean_placeholder(_evtx_value(row, ["Accesses"]))
    access_reason = _clean_placeholder(_evtx_value(row, ["AccessReason", "Access Reason"]))
    process_path = _normalize_windowsish_path(_evtx_value(row, ["ProcessName"]))
    object_type_lower = str(object_type or "").lower()
    looks_like_file = bool(object_name and re.match(r"^(?:[a-zA-Z]:\\|\\\\)", object_name)) and "key" not in object_type_lower
    looks_like_registry = bool(object_name) and ("key" in object_type_lower or str(object_name).upper().startswith("\\REGISTRY\\"))
    access_list = [item.strip() for item in re.split(r"[\r\n;|]+", str(accesses_raw or "")) if item.strip()]

    document["event"].update(
        {
            "category": "object_access",
            "type": "object_access",
            "action": "object_access_attempted",
            "message": f"Object access attempted: {object_name or 'unknown object'}",
        }
    )
    document["object"] = {
        "name": object_name,
        "path": object_name,
        "type": object_type,
        "server": object_server,
    }
    document["access"] = {
        "mask": access_mask,
        "list": access_list,
        "accesses": access_list,
        "reason": access_reason,
    }
    if looks_like_file:
        document["file"].update(
            {
                "path": _normalize_windowsish_path(object_name),
                "name": _safe_windows_basename(object_name),
                "extension": _appcompat_extension(object_name),
                "parent_path": _safe_windows_parent(object_name),
            }
        )
    if looks_like_registry:
        document["registry"].update({"path": object_name, "key_path": object_name})
    if process_path:
        document["process"].update({"path": process_path, "executable": process_path, "name": _safe_windows_basename(process_path)})
    subject_user = _clean_placeholder(_evtx_value(row, ["SubjectUserName"]))
    subject_domain = _clean_placeholder(_evtx_value(row, ["SubjectDomainName"]))
    subject_sid = _clean_placeholder(_evtx_value(row, ["SubjectUserSid"]))
    subject_logon_id = _clean_placeholder(_evtx_value(row, ["SubjectLogonId"]))
    if subject_user:
        document["user"]["name"] = subject_user
    if subject_domain:
        document["user"]["domain"] = subject_domain
    if subject_sid:
        document["user"]["sid"] = subject_sid
    document["subject"] = {"user": {"name": subject_user, "domain": subject_domain, "sid": subject_sid}, "logon": {"id": subject_logon_id}}
    if subject_logon_id:
        document["logon"] = {"id": subject_logon_id}
    document["key_entity"] = object_name
    search_parts = [
        document.get("search_text"),
        object_name,
        object_type,
        object_server,
        access_mask,
        accesses_raw,
        process_path,
        subject_user,
        subject_domain,
    ]
    document["search_text"] = " | ".join(str(part) for part in search_parts if part)
    return document


def _parse_pidish(value: str | None) -> int | None:
    cleaned = _clean_placeholder(value)
    if not cleaned:
        return None
    lowered = cleaned.lower()
    try:
        if lowered.startswith("0x"):
            return int(lowered, 16)
        return int(lowered)
    except Exception:  # noqa: BLE001
        return None


def _process_entity_id(document: dict, row: dict, host_name: str | None, process_path: str | None, pid: int | None) -> str | None:
    guid = _clean_placeholder(first_value(row, ["ProcessGuid", "ProcessGUID"]))
    if guid:
        return guid
    timestamp = document.get("@timestamp") or _parse_iso_timestamp(first_value(row, ["UtcTime", "TimeCreated", "Timestamp"]))
    blob = "|".join(
        str(part or "")
        for part in (
            "security",
            document.get("case_id"),
            host_name,
            timestamp,
            pid,
            process_path,
        )
    )
    if not blob.strip("|"):
        return None
    return f"security:{hashlib.sha1(blob.encode('utf-8', errors='ignore')).hexdigest()}"


def _normalize_hash(value: str | None, expected_lengths: set[int]) -> str | None:
    cleaned = _clean_placeholder(value)
    if not cleaned:
        return None
    normalized = re.sub(r"[^0-9a-fA-F]", "", cleaned).lower()
    if len(normalized) in expected_lengths:
        return normalized
    return None


def _safe_int(value: object | None) -> int | None:
    if value in (None, ""):
        return None
    try:
        return int(str(value).strip())
    except Exception:  # noqa: BLE001
        return None


def _lnk_source_location(path: str | None) -> str:
    normalized = (_normalize_windowsish_path(path) or "").lower()
    if "\\microsoft\\windows\\recent\\" in normalized:
        return "recent"
    if "\\microsoft\\office\\recent\\" in normalized:
        return "office_recent"
    if "\\internet explorer\\quick launch\\user pinned\\taskbar\\" in normalized:
        return "taskbar"
    if "\\microsoft\\windows\\start menu\\programs\\startup\\" in normalized or "\\microsoft\\windows\\start menu\\programs\\startup\\" in normalized.replace("startup", "startup"):
        return "startup"
    if "\\microsoft\\windows\\start menu\\" in normalized:
        return "start_menu"
    if "\\desktop\\" in normalized:
        return "desktop"
    if "\\downloads\\" in normalized:
        return "downloads"
    return "other"


def _valid_lnk_machine_id(value: str | None) -> str | None:
    candidate = normalize_hostname(value)
    return candidate if is_valid_hostname(candidate) else None


def _appcompat_basename(path: str | None) -> str | None:
    cleaned = _normalize_windowsish_path(path)
    if not cleaned:
        return None
    try:
        return PureWindowsPath(cleaned).name or cleaned
    except Exception:  # noqa: BLE001
        return Path(cleaned.replace("\\", "/")).name or cleaned


def _appcompat_extension(path: str | None) -> str | None:
    name = _appcompat_basename(path)
    if not name or "." not in name:
        return None
    return "." + name.split(".")[-1].lower()


def _boolish(value: str | None) -> bool | None:
    cleaned = _clean_placeholder(value)
    if not cleaned:
        return None
    lowered = cleaned.lower()
    if lowered in {"true", "yes", "1", "y"}:
        return True
    if lowered in {"false", "no", "0", "n"}:
        return False
    return None


def _select_appcompat_effective_path(row: dict) -> str | None:
    path = _normalize_windowsish_path(first_value(row, ["FullPath", "FilePath", "Path", "LowerCaseLongPath"]))
    if path:
        return path
    name = _clean_placeholder(first_value(row, ["Name", "FileName"]))
    if name and (":\\" in name or name.startswith("\\\\")):
        return _normalize_windowsish_path(name)
    return None


def _path_suspicion_reasons(path: str | None) -> list[str]:
    if not path:
        return []
    reasons = detect_suspicious_path(path)
    mapped: list[str] = []
    lower = path.lower()
    if "\\downloads\\" in lower:
        mapped.append("Executable observed in Downloads")
    if "\\appdata\\" in lower:
        mapped.append("Executable observed in AppData")
    if "\\temp\\" in lower:
        mapped.append("Executable observed in Temp")
    if "\\users\\public\\" in lower:
        mapped.append("Executable observed in Users\\Public")
    if "\\programdata\\" in lower:
        mapped.append("Executable observed in ProgramData")
    if "\\desktop\\" in lower:
        mapped.append("Executable observed on Desktop")
    mapped.extend(str(reason) for reason in reasons if reason)
    return list(dict.fromkeys(mapped))


EXECUTION_ARTIFACT_EXTENSIONS = {".exe", ".dll", ".sys", ".com", ".scr", ".bat", ".cmd", ".ps1", ".vbs", ".js", ".jse", ".wsf", ".hta", ".msi", ".lnk", ".cpl"}
SCRIPT_EXECUTION_ARTIFACT_EXTENSIONS = {".ps1", ".bat", ".cmd", ".vbs", ".js", ".jse", ".wsf", ".hta"}
AMCACHE_EXECUTION_CANDIDATE_EXTENSIONS = {".exe", ".dll", ".sys"}
ARCHIVE_EXTENSIONS = {".zip", ".7z", ".rar", ".tar", ".gz", ".bz2", ".cab", ".iso"}
REMOTE_ACCESS_TOOL_HINTS = {"anydesk", "teamviewer", "ngrok", "rustdesk", "screenconnect", "connectwise", "splashtop", "rclone", "plink"}
LOLBIN_HINTS = {"powershell.exe", "pwsh.exe", "cmd.exe", "rundll32.exe", "regsvr32.exe", "mshta.exe", "wscript.exe", "cscript.exe", "certutil.exe", "bitsadmin.exe", "schtasks.exe"}
SERVICE_LOLBIN_HINTS = LOLBIN_HINTS | {"msiexec.exe"}
PREFETCH_LOLBINS = {
    "powershell.exe",
    "pwsh.exe",
    "cmd.exe",
    "wscript.exe",
    "cscript.exe",
    "mshta.exe",
    "rundll32.exe",
    "regsvr32.exe",
    "certutil.exe",
    "bitsadmin.exe",
    "msiexec.exe",
    "schtasks.exe",
    "net.exe",
    "net1.exe",
    "sc.exe",
    "whoami.exe",
    "nltest.exe",
    "quser.exe",
    "wevtutil.exe",
    "vssadmin.exe",
    "wbadmin.exe",
    "bcdedit.exe",
}
PREFETCH_REMOTE_ADMIN = {"psexec.exe", "psexesvc.exe", "anydesk.exe", "teamviewer.exe", "rustdesk.exe", "screenconnect.exe"}
PREFETCH_FORENSIC_TOOLS = {"ftkimager.exe", "winpmem.exe", "magnet.exe", "kape.exe", "velociraptor.exe", "chainsaw.exe", "hayabusa.exe"}
PREFETCH_BROWSER_NAMES = {"chrome.exe", "msedge.exe", "brave.exe", "firefox.exe", "iexplore.exe", "opera.exe"}
PREFETCH_ARCHIVE_TOOLS = {"7z.exe", "rar.exe", "winrar.exe", "tar.exe"}
PREFETCH_SECURITY_TOOLS = {"procmon.exe", "procexp.exe", "tcpview.exe", "autoruns.exe", "sigcheck.exe"}
SRUM_REMOTE_TOOL_HINTS = {
    "anydesk",
    "teamviewer",
    "chrome remote desktop",
    "rustdesk",
    "rclone",
    "megasync",
    "dropbox",
    "onedrive",
    "googledrive",
    "winscp",
    "filezilla",
    "putty",
    "plink",
    "ngrok",
    "tailscale",
    "zerotier",
    "tor",
    "vpn",
}
SRUM_FILE_TRANSFER_HINTS = {"rclone", "winscp", "filezilla", "megasync", "dropbox", "onedrive", "googledrive"}
SRUM_LOLBIN_NETWORK_HINTS = {"powershell.exe", "pwsh.exe", "cmd.exe", "certutil.exe", "bitsadmin.exe", "mshta.exe", "rundll32.exe", "regsvr32.exe", "wscript.exe", "cscript.exe", "curl.exe", "wget.exe"}
SRUM_HIGH_UPLOAD_THRESHOLD = 100 * 1024 * 1024


def _apply_execution_artifact_suspicion(document: dict, *, artifact_name: str | None, path: str | None) -> None:
    tags = set(document.get("tags", []))
    reasons = set(document.get("suspicious_reasons", []))
    normalized_path = _normalize_windowsish_path(path)
    extension = _appcompat_extension(normalized_path or artifact_name)
    lower_blob = f"{(artifact_name or '').lower()} {(normalized_path or '').lower()}"
    if extension in EXECUTION_ARTIFACT_EXTENSIONS:
        tags.add("executable")
    if extension in SCRIPT_EXECUTION_ARTIFACT_EXTENSIONS:
        tags.add("script")
    if is_windows_unc_path(normalized_path):
        tags.update({"suspicious", "unc_path", "network_path"})
        reasons.add("UNC path observed in AppCompat artifact")
    if is_suspicious_double_extension(artifact_name) or is_suspicious_double_extension(normalized_path):
        tags.update({"suspicious", "double_extension"})
        reasons.add("Double extension executable observed")
    basename = (artifact_name or _appcompat_basename(normalized_path) or "").lower()
    if basename in LOLBIN_HINTS:
        tags.update({"suspicious", "lolbin"})
        reasons.add("Known LOLBin observed")
    if any(token in lower_blob for token in REMOTE_ACCESS_TOOL_HINTS):
        tags.update({"suspicious", "remote_access_tool"})
        reasons.add("Remote access tool observed")
    if normalized_path:
        path_reasons = _path_suspicion_reasons(normalized_path)
        if path_reasons:
            tags.update({"suspicious", "suspicious_path"})
            reasons.update(path_reasons)
    document["tags"] = sorted(tags)
    document["suspicious_reasons"] = sorted(reasons)


def _set_execution_interpretation(document: dict, *, source: str, confidence: str, confirmed: bool | None, interpretation: str) -> None:
    document["execution"].update(
        {
            "source": source,
            "confidence": confidence,
            "is_execution_confirmed": confirmed,
            "interpretation": interpretation,
        }
    )


SERVICE_START_TYPE_MAP = {
    0: "boot",
    1: "system",
    2: "auto",
    3: "manual",
    4: "disabled",
}

SERVICE_TYPE_FLAGS = {
    0x1: "kernel_driver",
    0x2: "file_system_driver",
    0x4: "adapter",
    0x8: "recognizer_driver",
    0x10: "win32_own_process",
    0x20: "win32_share_process",
    0x100: "interactive_process",
}

KNOWN_SERVICE_SIDS = {
    "localsystem": "NT AUTHORITY\\SYSTEM",
    "localservice": "NT AUTHORITY\\LOCAL SERVICE",
    "networkservice": "NT AUTHORITY\\NETWORK SERVICE",
    "nt authority\\system": "NT AUTHORITY\\SYSTEM",
    "nt authority\\local service": "NT AUTHORITY\\LOCAL SERVICE",
    "nt authority\\network service": "NT AUTHORITY\\NETWORK SERVICE",
}


def _expand_service_env(value: str | None) -> str | None:
    cleaned = _clean_placeholder(value)
    if not cleaned:
        return None
    expanded = cleaned
    replacements = {
        "%systemroot%": "C:\\Windows",
        "%windir%": "C:\\Windows",
    }
    lower = expanded.lower()
    for token, replacement in replacements.items():
        if token in lower:
            expanded = re.sub(re.escape(token), lambda _: replacement, expanded, flags=re.IGNORECASE)
            lower = expanded.lower()
    if lower.startswith("\\systemroot\\"):
        expanded = "C:\\Windows\\" + expanded[len("\\SystemRoot\\"):]
    elif lower.startswith("system32\\"):
        expanded = "C:\\Windows\\" + expanded
    elif lower.startswith("\\system32\\"):
        expanded = "C:\\Windows" + expanded
    return _normalize_windowsish_path(expanded) or expanded


def _extract_service_launch_target(image_path: str | None) -> tuple[str | None, str | None]:
    command_line = _expand_service_env(image_path)
    if not command_line:
        return None, None
    patterns = [
        r'^\s*"(?P<binary>[^"]+\.(?:exe|dll|sys|com|scr|bat|cmd|ps1|vbs|js|jse|wsf|msi|cpl))"',
        r"^\s*(?P<binary>(?:[A-Za-z]:\\|\\\\\?\\[A-Za-z]:\\|\\\\\?\\Volume\{[^}]+\}\\|\\SystemRoot\\|System32\\|\\\\[^\\]+\\[^\\]+\\)[^ ]+?\.(?:exe|dll|sys|com|scr|bat|cmd|ps1|vbs|js|jse|wsf|msi|cpl))",
        r"^\s*(?P<binary>[A-Za-z0-9_.-]+\.(?:exe|dll|sys|com|scr|bat|cmd|ps1|vbs|js|jse|wsf|msi|cpl))(?=\s|$)",
    ]
    binary = None
    for pattern in patterns:
        match = re.search(pattern, command_line, flags=re.IGNORECASE)
        if match:
            binary = match.group("binary")
            break
    expanded_binary = _expand_service_env(binary) if binary else None
    return command_line, expanded_binary


def _parse_multi_value(value: str | None) -> list[str]:
    cleaned = _clean_placeholder(value)
    if not cleaned:
        return []
    if "|" in cleaned:
        items = [item.strip() for item in cleaned.split("|")]
    elif "\x00" in cleaned:
        items = [item.strip() for item in cleaned.split("\x00")]
    elif ";" in cleaned:
        items = [item.strip() for item in cleaned.split(";")]
    else:
        items = [cleaned.strip()]
    return [item for item in items if item]


def _resolve_service_identity(value: str | None) -> tuple[str | None, str | None]:
    cleaned = _clean_placeholder(value)
    if not cleaned:
        return None, None
    normalized = KNOWN_SERVICE_SIDS.get(cleaned.lower(), cleaned)
    return cleaned, normalized


def _service_type_strings(raw_value: int | None) -> tuple[str | None, list[str]]:
    if raw_value is None:
        return None, []
    labels = [label for bit, label in SERVICE_TYPE_FLAGS.items() if raw_value & bit]
    return "|".join(labels) if labels else str(raw_value), labels


def _is_known_good_service_path(path: str | None) -> bool:
    lower = str(path or "").lower()
    if not lower:
        return False
    return (
        lower.startswith("c:\\windows\\system32\\")
        or lower.startswith("c:\\windows\\")
        or lower.startswith("c:\\program files\\windows defender\\")
        or lower.startswith("c:\\program files\\microsoft defender\\")
        or lower.startswith("c:\\program files\\windowsapps\\")
        or lower.startswith("c:\\program files\\microsoft")
        or lower.startswith("c:\\program files (x86)\\microsoft")
        or lower.startswith("c:\\programdata\\microsoft\\windows defender\\platform\\")
    )


def normalize_service_row(document: dict, row: dict, artifact_meta: dict) -> dict:
    service_name = _clean_placeholder(first_value(row, ["ServiceName", "Name"])) or "unknown"
    display_name = _clean_placeholder(first_value(row, ["DisplayName"]))
    description = _clean_placeholder(first_value(row, ["Description"]))
    key_path = _clean_placeholder(first_value(row, ["KeyPath"]))
    source_file = _clean_placeholder(first_value(row, ["SourceFile"])) or _clean_placeholder(str(artifact_meta.get("source_path") or ""))
    control_set = _clean_placeholder(first_value(row, ["ControlSet"]))
    image_path = _clean_placeholder(first_value(row, ["ImagePath"]))
    command_line, expanded_binary = _extract_service_launch_target(image_path)
    image_path_expanded = command_line
    service_dll = _clean_placeholder(first_value(row, ["ServiceDll"]))
    service_dll_expanded = _expand_service_env(service_dll)
    start_type_raw = _safe_int(first_value(row, ["StartRaw", "Start"]))
    start_type = SERVICE_START_TYPE_MAP.get(start_type_raw)
    service_type_raw = _safe_int(first_value(row, ["ServiceTypeRaw", "Type"]))
    service_type, service_flags = _service_type_strings(service_type_raw)
    error_control = _clean_placeholder(first_value(row, ["ErrorControl"]))
    object_name_raw = _clean_placeholder(first_value(row, ["ObjectName"]))
    object_sid, object_name = _resolve_service_identity(object_name_raw)
    delayed_auto_start = _boolish(first_value(row, ["DelayedAutoStart"]))
    launch_protected = _clean_placeholder(first_value(row, ["LaunchProtected"]))
    service_sid_type = _clean_placeholder(first_value(row, ["ServiceSidType"]))
    trigger_info = _clean_placeholder(first_value(row, ["TriggerInfo"]))
    failure_actions = _clean_placeholder(first_value(row, ["FailureActions"]))
    required_privileges = _parse_multi_value(first_value(row, ["RequiredPrivileges"]))
    depend_on_service = _parse_multi_value(first_value(row, ["DependOnService"]))
    depend_on_group = _parse_multi_value(first_value(row, ["DependOnGroup"]))
    group = _clean_placeholder(first_value(row, ["Group"]))
    parser_status = _clean_placeholder(first_value(row, ["ParserStatus"])) or "parsed_native"
    processed_at = _parse_iso_timestamp(str(artifact_meta.get("parser_processed_at") or "")) or _clean_placeholder(str(artifact_meta.get("parser_processed_at") or ""))
    last_write = _parse_iso_timestamp(first_value(row, ["LastWrite", "LastWriteTime"]))
    timestamp = last_write or None
    timestamp_precision = "service_key_last_write" if last_write else "unknown"
    executable_path = expanded_binary
    executable_name = _appcompat_basename(executable_path)
    file_extension = _appcompat_extension(executable_path or executable_name)
    lower_command = str(image_path_expanded or image_path or "").lower()
    lower_binary = str(executable_path or "").lower()
    lower_service_dll = str(service_dll_expanded or "").lower()
    microsoft_like_name = bool(re.match(r"^(ms|microsoft|windows)", service_name, flags=re.IGNORECASE))
    trusted_path = (
        lower_binary.startswith("c:\\windows\\")
        or lower_binary.startswith("c:\\program files\\windowsapps\\")
        or lower_binary.startswith("c:\\program files\\microsoft")
        or lower_binary.startswith("c:\\program files (x86)\\microsoft")
    )
    enabled = None if start_type_raw is None else start_type_raw != 4

    document["@timestamp"] = timestamp
    document["timestamp_precision"] = timestamp_precision
    document["timezone"] = "UTC" if timestamp else None
    document["artifact"].update(
        {
            "type": "service",
            "name": f"Windows Service - {service_name}",
            "source_path": source_file,
            "parser": "windows_service_registry",
        }
    )
    document["event"].update(
        {
            "category": "persistence",
            "type": "service",
            "action": "service_observed",
            "severity": "info",
            "message": f"Windows service observed: {service_name}",
            "timeline_include": bool(last_write),
        }
    )
    document["registry"].update(
        {
            "hive": "SYSTEM",
            "key_path": key_path,
            "last_write": last_write,
        }
    )
    document["service"] = {
        "artifact_type": "service",
        "name": service_name,
        "display_name": display_name,
        "description": description,
        "image_path": image_path,
        "image_path_expanded": image_path_expanded,
        "service_dll": service_dll,
        "service_dll_expanded": service_dll_expanded,
        "command_line": image_path_expanded or image_path,
        "executable_path": executable_path,
        "start_type": start_type,
        "start_type_raw": start_type_raw,
        "service_type": service_type,
        "service_type_raw": service_type_raw,
        "error_control": error_control,
        "object_name": object_name,
        "account": object_name,
        "group": group,
        "depend_on_service": depend_on_service,
        "depend_on_group": depend_on_group,
        "dependencies": sorted(dict.fromkeys([*depend_on_service, *depend_on_group])),
        "failure_actions": failure_actions,
        "required_privileges": required_privileges,
        "launch_protected": launch_protected,
        "service_sid_type": service_sid_type,
        "delayed_auto_start": delayed_auto_start,
        "trigger_info": trigger_info,
        "key_path": key_path,
        "control_set": control_set,
        "source_file": source_file,
        "last_write": last_write,
        "key_last_write_time": last_write,
        "parser_status": parser_status,
        "timestamp_interpretation": timestamp_precision,
    }
    persistence_path = executable_path
    if executable_name and executable_name.lower() == "svchost.exe" and service_dll_expanded:
        persistence_path = service_dll_expanded
    document["persistence"].update(
        {
            "mechanism": "windows_service",
            "location": key_path,
            "name": service_name,
            "command": image_path_expanded or image_path or service_dll_expanded or service_dll,
            "path": persistence_path or service_dll_expanded,
            "enabled": enabled,
            "scope": "system",
            "user": object_name,
            "sid": object_sid,
            "confidence": "medium",
            "source": source_file,
        }
    )
    document["process"].update(
        {
            "name": executable_name if file_extension == ".exe" else None,
            "path": executable_path,
            "command_line": image_path_expanded or image_path,
            "application": executable_name if file_extension == ".exe" else None,
        }
    )
    document["file"].update(
        {
            "path": executable_path,
            "name": executable_name,
            "extension": file_extension,
            "source_path": source_file,
        }
    )
    if object_name and not document["user"].get("name"):
        document["user"]["name"] = object_name
    if object_sid and not document["user"].get("sid"):
        document["user"]["sid"] = object_sid
    _set_execution_interpretation(
        document,
        source="service",
        confidence="low",
        confirmed=False,
        interpretation="Windows Service definition indicates configured execution/persistence, not confirmed execution by itself",
    )

    tags = set(document.get("tags", [])) | {"service", "persistence"}
    reasons = set(document.get("suspicious_reasons", []))
    data_quality = set(document.get("data_quality", []))
    if start_type_raw in {0, 1, 2}:
        tags.add("autorun")
    if start_type_raw == 2:
        tags.add("service_autostart")
    if start_type_raw == 4:
        tags.add("disabled_service")
    if any(flag in {"kernel_driver", "file_system_driver", "recognizer_driver"} for flag in service_flags) or file_extension == ".sys":
        tags.add("driver_service")
    if service_dll_expanded:
        tags.add("service_dll")
    command_is_known_good = _is_known_good_service_path(image_path_expanded) or _is_known_good_service_path(executable_path)
    service_dll_is_known_good = _is_known_good_service_path(service_dll_expanded)
    if image_path_expanded:
        for reason in detect_suspicious_path(image_path_expanded):
            if reason != "unc_path" and not command_is_known_good:
                tags.add("suspicious_path")
        if not command_is_known_good and ("\\users\\" in lower_command or "\\appdata\\" in lower_command or "\\temp\\" in lower_command or "\\downloads\\" in lower_command or "\\desktop\\" in lower_command or "\\public\\" in lower_command or "\\programdata\\" in lower_command):
            reasons.add("Service executable path is user-writable")
    if service_dll_expanded and not service_dll_is_known_good and ("\\users\\" in lower_service_dll or "\\appdata\\" in lower_service_dll or "\\temp\\" in lower_service_dll or "\\downloads\\" in lower_service_dll or "\\desktop\\" in lower_service_dll or "\\public\\" in lower_service_dll or "\\programdata\\" in lower_service_dll):
        reasons.add("Service DLL path is suspicious")
        tags.add("suspicious_path")
    if executable_name and executable_name.lower() in SERVICE_LOLBIN_HINTS:
        tags.add("lolbin")
        reasons.add("Service uses LOLBin in ImagePath")
    encoded_tokens = ("-enc", "-encodedcommand", "frombase64string", "downloadstring", "iex", "bypass")
    if any(token in lower_command for token in encoded_tokens):
        reasons.add("Service command contains encoded PowerShell")
        tags.add("powershell")
    if any(token in lower_command for token in ("http://", "https://", "ftp://")):
        reasons.add("Service command contains URL")
    if start_type_raw in {0, 1, 2} and any(reason in reasons for reason in {"Service executable path is user-writable", "Service DLL path is suspicious"}):
        reasons.add("Autostart service uses suspicious path")
    if microsoft_like_name and not trusted_path and executable_path:
        reasons.add("Service name mimics Microsoft but path is not trusted")
    if service_dll_expanded and executable_name and executable_name.lower() == "svchost.exe" and not (
        service_dll_is_known_good
    ):
        reasons.add("Service DLL path is suspicious")
    if is_suspicious_double_extension(executable_name) or is_suspicious_double_extension(executable_path):
        reasons.add("Service executable uses suspicious double extension")
    if file_extension in {".scr", ".js", ".vbs", ".ps1", ".bat", ".cmd", ".com"}:
        reasons.add("Service executable uses uncommon script-like extension")

    risk_score = 0
    if "Service executable path is user-writable" in reasons:
        risk_score += 30
        tags.update({"suspicious", "user_writable_path"})
    if "Service uses LOLBin in ImagePath" in reasons:
        risk_score += 25
    if any(reason in reasons for reason in {"Service command contains encoded PowerShell", "Service command contains URL"}):
        risk_score += 30
    if "Autostart service uses suspicious path" in reasons:
        risk_score += 20
    if "Service DLL path is suspicious" in reasons:
        risk_score += 30
    if "Service name mimics Microsoft but path is not trusted" in reasons:
        risk_score += 25
    risk_score = min(risk_score, 100)
    severity = "high" if risk_score >= 70 else "medium" if risk_score >= 40 else "info"

    if not image_path:
        data_quality.add("missing_command")
    if not timestamp:
        data_quality.add("missing_timestamp")
    data_quality.add("low_confidence_execution")

    document["event"]["severity"] = severity
    timeline_include = bool(last_write) and (
        risk_score > 0
        or not command_is_known_good
        or (bool(service_dll_expanded) and not service_dll_is_known_good)
    )
    document["event"]["timeline_include"] = bool(timeline_include)
    document["risk_score"] = risk_score
    document["tags"] = sorted(tags)
    document["suspicious_reasons"] = sorted(reasons)
    document["data_quality"] = sorted(data_quality)
    document.setdefault("ingest", {})
    document["ingest"]["processed_at"] = processed_at
    document["raw_summary"] = " | ".join(
        part for part in [
            f"ServiceName={service_name}",
            f"DisplayName={display_name}" if display_name else None,
            f"ImagePath={image_path}" if image_path else None,
            f"ServiceDll={service_dll}" if service_dll else None,
            f"StartType={start_type}" if start_type else None,
            f"ServiceType={service_type}" if service_type else None,
            f"ObjectName={object_name}" if object_name else None,
            f"KeyPath={key_path}" if key_path else None,
            f"LastWrite={last_write}" if last_write else None,
        ] if part
    )[:2000]
    document["_preserve_risk_score"] = True
    document["_preserve_timeline_include"] = True
    return document


def _parse_srum_timestamp(value: str | None) -> str | None:
    cleaned = _clean_placeholder(value)
    if not cleaned:
        return None
    if re.fullmatch(r"\d{16,18}", cleaned):
        try:
            epoch_start = date_parser.parse("1601-01-01T00:00:00Z")
            return (epoch_start + timedelta(microseconds=int(cleaned))).isoformat()
        except Exception:  # noqa: BLE001
            return None
    if re.fullmatch(r"\d{13}", cleaned):
        try:
            return datetime.fromtimestamp(int(cleaned) / 1000, tz=UTC).isoformat()
        except Exception:  # noqa: BLE001
            return None
    if re.fullmatch(r"\d{10}", cleaned):
        try:
            return datetime.fromtimestamp(int(cleaned), tz=UTC).isoformat()
        except Exception:  # noqa: BLE001
            return None
    return _parse_iso_timestamp(cleaned)


def _normalize_int_bytes(value: str | None) -> int | None:
    cleaned = _clean_placeholder(value)
    if not cleaned:
        return None
    normalized = re.sub(r"[^0-9-]", "", cleaned)
    if not normalized:
        return None
    try:
        return int(normalized)
    except Exception:  # noqa: BLE001
        return None


def _sum_bytes(*values: int | None) -> int | None:
    present = [value for value in values if value is not None]
    if not present:
        return None
    return sum(present)


def _stable_event_id(*parts: object) -> str:
    blob = "||".join("" if part is None else str(part) for part in parts)
    return hashlib.sha1(blob.encode("utf-8", errors="ignore")).hexdigest()


def _stable_payload_hash(payload: object) -> str:
    try:
        normalized = json.dumps(payload, sort_keys=True, ensure_ascii=True, separators=(",", ":"))
    except Exception:  # noqa: BLE001
        normalized = str(payload)
    return hashlib.sha1(normalized.encode("utf-8", errors="ignore")).hexdigest()


def _parse_prefetch_filename(filename: str | None) -> tuple[str | None, str | None]:
    if not filename:
        return None, None
    match = re.match(r"(?P<exe>.+?)(?:-(?P<hash>[0-9A-Fa-f]{8}))?\.pf$", str(filename), flags=re.IGNORECASE)
    if not match:
        return None, None
    executable_name = str(match.group("exe") or "").strip() or None
    pf_hash = str(match.group("hash") or "").upper() or None
    return executable_name, pf_hash


def _format_bytes_for_summary(value: int | None) -> str:
    if value is None:
        return "0 B"
    units = ["B", "KB", "MB", "GB", "TB"]
    size = float(value)
    unit = units[0]
    for candidate in units:
        unit = candidate
        if size < 1024 or candidate == units[-1]:
            break
        size /= 1024
    if unit == "B":
        return f"{int(size)} {unit}"
    return f"{size:.2f} {unit}"


def _srum_artifact_type(row: dict, artifact_meta: dict) -> str:
    explicit_type = str(first_value(row, ["ArtifactType"]) or "").strip().lower()
    explicit_map = {
        "srum_network_usage": "srum_network_usage",
        "network_usage": "srum_network_usage",
        "srum_network_connectivity": "srum_network_connectivity",
        "network_connectivity": "srum_network_connectivity",
        "srum_app_resource": "srum_app_resource",
        "srum_application_resource": "srum_app_resource",
        "application_resource_usage": "srum_app_resource",
        "srum_energy": "srum_energy",
        "energy_usage": "srum_energy",
    }
    if explicit_type in explicit_map:
        return explicit_map[explicit_type]
    table = str(first_value(row, ["Table", "Provider", "Description"]) or "").lower()
    source_name = str(artifact_meta.get("name") or "").lower()
    blob = f"{table} {source_name}"
    header_blob = " ".join(str(key).lower() for key in row.keys())
    if any(token in blob for token in ["network usage", "networkusage", "network connectivity", "networkconnectivity"]):
        return "srum_network_usage" if "connectivity" not in blob else "srum_network_connectivity"
    if any(token in blob for token in ["applicationresourceusage", "appresource", "resource usage"]):
        return "srum_app_resource"
    if "energy" in blob:
        return "srum_energy"
    if any(token in f"{blob} {header_blob}" for token in ["bytessent", "bytesreceived", "sendbytes", "receivebytes", "foregroundbytessent", "backgroundbytesreceived", "networkprofile", "interfaceprofile"]):
        return "srum_network_usage"
    if any(token in f"{blob} {header_blob}" for token in ["connectedtime", "interfaceguid", "interfaceluid"]) and "duration" in header_blob:
        return "srum_network_connectivity"
    if any(token in f"{blob} {header_blob}" for token in ["energyusage", "cycletime"]):
        return "srum_energy"
    if "duration" in header_blob:
        return "srum_app_resource"
    if any(token in blob for token in ["timeline", "apptimeline"]):
        return "app_timeline"
    return "srum_unknown_table"


def _srum_timestamp_candidates(row: dict) -> list[tuple[str | None, str]]:
    return [
        (_parse_srum_timestamp(first_value(row, ["EndTime"])), "srum_end_time"),
        (_parse_srum_timestamp(first_value(row, ["StartTime"])), "srum_start_time"),
        (_parse_srum_timestamp(first_value(row, ["ConnectedTime"])), "srum_connected_time"),
        (_parse_srum_timestamp(first_value(row, ["Timestamp", "TimeStamp", "EventTimestamp"])), "event_time"),
        (_parse_srum_timestamp(first_value(row, ["Created"])), "srum_created"),
    ]


def _select_srum_application(row: dict) -> dict:
    process_path = _normalize_windowsish_path(first_value(row, ["ExePath", "Path", "AppId", "AppID"]))
    exe_info = _clean_placeholder(first_value(row, ["ExeInfo"]))
    app_name = _clean_placeholder(first_value(row, ["AppName", "Application"]))
    app_id = _clean_placeholder(first_value(row, ["AppId", "AppID"]))
    package_name = _clean_placeholder(first_value(row, ["PackageFullName", "PackageName"]))
    file_name = _clean_placeholder(first_value(row, ["FileName"]))
    if not process_path and exe_info:
        process_path = _normalize_windowsish_path(exe_info if (":\\" in exe_info or exe_info.startswith("\\\\") or "\\device\\" in exe_info.lower()) else None)
    process_name = _appcompat_basename(process_path) or _appcompat_basename(exe_info) or file_name or app_name or app_id or package_name or "unknown"
    display_name = process_name
    if app_name and app_name.lower() != process_name.lower():
        display_name = app_name
    elif app_id and app_id.lower() != process_name.lower():
        display_name = app_id
    elif package_name and package_name.lower() != process_name.lower():
        display_name = package_name
    return {
        "app_id": app_id or process_path or exe_info,
        "app_name": app_name or exe_info or process_name,
        "process_path": process_path,
        "process_name": process_name,
        "package_name": package_name,
        "display_name": display_name or "unknown",
    }


def _srum_direction(bytes_sent: int | None, bytes_received: int | None) -> str:
    sent = int(bytes_sent or 0)
    received = int(bytes_received or 0)
    if sent > 0 and received == 0:
        return "upload"
    if received > 0 and sent == 0:
        return "download"
    if sent > 0 and received > 0:
        return "bidirectional"
    return "unknown"


def _derive_srum_risk_and_reasons(
    *,
    display_name: str,
    process_path: str | None,
    process_name: str | None,
    app_id: str | None,
    app_name: str | None,
    bytes_sent: int | None,
    bytes_received: int | None,
    artifact_type: str,
) -> tuple[set[str], set[str], set[str], int]:
    tags = set()
    reasons = set()
    data_quality = set()
    risk = 0
    blob = " ".join(
        part
        for part in [
            display_name,
            process_name,
            app_name,
            app_id,
            process_path or "",
        ]
        if part
    ).lower()
    candidate_path = process_path or _normalize_windowsish_path(app_id) or _normalize_windowsish_path(app_name)
    basename = (
        _appcompat_basename(candidate_path)
        or _appcompat_basename(app_id)
        or _appcompat_basename(app_name)
        or process_name
        or display_name
        or "unknown"
    )
    basename_lower = str(basename).lower()
    direction = _srum_direction(bytes_sent, bytes_received)
    sent = int(bytes_sent or 0)
    received = int(bytes_received or 0)
    total = sent + received

    if artifact_type == "srum_unknown_table":
        data_quality.add("srum_unknown_table")
    if not display_name or str(display_name).strip().lower() in {"unknown", "unknown application"}:
        data_quality.add("missing_application")
    if bytes_sent is None and bytes_received is None:
        data_quality.add("missing_bytes")
    elif sent == 0 and received == 0:
        data_quality.add("srum_zero_bytes")

    if any(token in blob for token in SRUM_REMOTE_TOOL_HINTS):
        tags.update({"suspicious", "remote_access_tool", "suspicious_process"})
        reasons.add("SRUM network activity by suspicious process")
        risk = max(risk, 45)
    if any(token in blob for token in SRUM_FILE_TRANSFER_HINTS):
        tags.update({"suspicious", "file_transfer_tool"})
        risk = max(risk, 35)
    if basename_lower in {"powershell.exe", "pwsh.exe", "wscript.exe", "cscript.exe"}:
        tags.update({"suspicious", "scripting_process"})
        reasons.add("SRUM network activity by scripting process")
        risk = max(risk, 72 if total > 0 else 50)
    if basename_lower in SRUM_LOLBIN_NETWORK_HINTS:
        tags.update({"suspicious", "lolbin_network"})
        reasons.add("SRUM network activity by LOLBin")
        risk = max(risk, 60 if total > 0 else 45)
    if candidate_path:
        path_reasons = _path_suspicion_reasons(candidate_path)
        if path_reasons:
            tags.update({"suspicious", "suspicious_path", "user_writable_app"})
            reasons.add("SRUM network activity by user-writable application")
            reasons.update(path_reasons)
            risk = max(risk, 65 if total > 0 else 40)
    elif display_name and display_name.lower() not in {"system", "svchost.exe", "chrome.exe", "msedge.exe", "firefox.exe"}:
        tags.update({"suspicious", "unknown_application"})
        reasons.add("SRUM network activity by unknown application")
        risk = max(risk, 35 if total > 0 else 10)

    if sent >= SRUM_HIGH_UPLOAD_THRESHOLD:
        tags.update({"suspicious", "high_upload", "possible_exfiltration"})
        reasons.add("SRUM high outbound bytes")
        risk = max(risk, 85)
    elif sent >= 10 * 1024 * 1024:
        tags.update({"suspicious", "high_upload"})
        reasons.add("SRUM high outbound bytes")
        risk = max(risk, 70)
    if sent > 0 and sent > max(received, 1) * 5 and sent >= 1 * 1024 * 1024:
        tags.update({"suspicious", "upload_heavy"})
        reasons.add("SRUM upload-heavy traffic")
        risk = max(risk, 75)

    if artifact_type == "srum_network_connectivity":
        risk = min(risk, 10)
    elif artifact_type == "srum_app_resource":
        risk = min(max(risk, 0), 20) if risk == 0 else risk
    elif artifact_type == "srum_energy":
        risk = min(max(risk, 0), 10) if risk == 0 else risk
    elif total > 0 and risk == 0:
        risk = 5 if direction != "unknown" else 0

    return tags, reasons, data_quality, min(risk, 100)


def normalize_evtx_row(document: dict, row: dict, artifact_meta: dict) -> dict:
    event_id_value = first_value(row, ["EventID", "EventId", "Id", "EID"])
    event_id = int(event_id_value) if event_id_value and str(event_id_value).isdigit() else None
    classification = classify_windows_event(event_id, row)
    user_name = extract_user(row, artifact_meta, {"event_id": event_id})
    host_name = extract_host(row, artifact_meta)
    channel = first_value(row, ["Channel", "LogName"])
    provider = first_value(row, ["Provider", "ProviderName", "SourceName"])
    record_id = first_value(row, ["RecordID", "EventRecordID", "RecordNumber"])
    level = first_value(row, ["Level", "Severity"])
    opcode = first_value(row, ["Opcode"])
    keywords = first_value(row, ["Keywords"])
    event_data_summary = first_value(row, ["EventDataSummary", "Message"])
    logon_type = first_value(row, ["LogonType"])
    service_name = first_value(row, ["ServiceName"])
    service_path = first_value(row, ["ServiceFileName", "ImagePath"])
    task_name = first_value(row, ["TaskName"])
    task_instance_id = first_value(row, ["TaskInstanceId"])
    task_action_name = first_value(row, ["ActionName"])
    task_result_code = first_value(row, ["ResultCode"])
    task_engine_pid = first_value(row, ["EnginePID", "EngineProcessId"])
    process_name = first_value(row, ["NewProcessName", "ProcessName", "Image"])
    command_line = first_value(row, ["ProcessCommandLine", "CommandLine", "ScriptBlockText", "HostApplication"])
    source_ip = first_value(row, ["IpAddress", "SourceNetworkAddress", "SourceAddress"])
    workstation = first_value(row, ["WorkstationName"])
    lower_channel = str(channel or "").lower()
    lower_provider = str(provider or "").lower()
    source_file = first_value(row, ["SourceFile", "FileName", "EvtxFile"]) or artifact_meta.get("source_path")
    event_payload_hash = _stable_payload_hash(first_value(row, ["Payload", "RawXml"]) or row)

    if "microsoft-windows-wmi-activity" in lower_channel or "microsoft-windows-wmi-activity" in lower_provider:
        wmi_activity = classify_wmi_activity_event(row)
        document["artifact"]["type"] = "windows_event"
        document["artifact"]["parser"] = artifact_meta.get("parser") or "evtx_raw"
        document["source_file"] = source_file
        document["source_tool"] = artifact_meta.get("source_tool") or "evtxecmd"
        document["source_format"] = artifact_meta.get("source_format") or "evtx_csv"
        document["event"].update(
            {
                "category": "wmi",
                "type": str(wmi_activity["event_type"]),
                "action": str(wmi_activity["action"]),
                "severity": str(wmi_activity["severity"]),
                "message": str(wmi_activity["message"]),
            }
        )
        document["host"]["name"] = host_name
        document["host"]["hostname"] = host_name
        document["user"]["name"] = user_name
        document["windows"].update(
            {
                "event_id": event_id,
                "channel": channel,
                "provider": provider,
                "record_id": record_id,
                "record_number": record_id,
                "opcode": opcode,
                "level": level,
                "keywords": keywords,
                "event_data_summary": event_data_summary,
            }
        )
        document["wmi"].update(
            {
                "artifact_type": "wmi_activity_event",
                "namespace": first_value(row, ["NamespaceName"]),
                "query": first_value(row, ["Query"]),
                "consumer_name": first_value(row, ["Consumer"]),
                "creator_user": first_value(row, ["User"]) or user_name,
                "source_file": artifact_meta.get("source_path"),
                "parser_status": "parsed",
            }
        )
        document["process"].update({"pid": first_value(row, ["ClientProcessId", "ProcessId"]), "name": first_value(row, ["ProviderName"])})
        document["tags"] = sorted(set(document.get("tags", [])) | {"wmi"})
        document["event_id"] = _stable_event_id(document.get("case_id"), document.get("evidence_id"), source_file, channel, record_id, event_id, document.get("@timestamp") or event_payload_hash)
        return document

    if classification.source_match and classification.event_type == "logon_success":
        message = f"Successful logon: {user_name or 'unknown user'} (LogonType {logon_type or '?'}) from {source_ip or workstation or 'local host'}"
    elif classification.source_match and classification.event_type == "logon_failed":
        message = f"Failed logon: {user_name or 'unknown user'} (LogonType {logon_type or '?'}) from {source_ip or workstation or 'local host'}"
    elif classification.source_match and classification.event_type == "explicit_credentials_logon":
        target_user = first_value(row, ["TargetUserName"])
        message = f"Explicit credentials used by {user_name or 'unknown user'} for {target_user or 'unknown user'}"
    elif classification.source_match and classification.category == "process":
        parent_hint = _safe_windows_basename(first_value(row, ["ParentProcessName", "CreatorProcessName", "ParentImage"]))
        child_hint = _safe_windows_basename(process_name) or "unknown"
        message = f"Process created: {parent_hint or 'unknown'} -> {child_hint}"
    elif classification.source_match and classification.event_type in {"service_created", "service_installed"}:
        message = f"Service created: {service_name or 'unknown'} -> {service_path or 'unknown'}"
    elif classification.source_match and classification.event_type in {"scheduled_task_created", "scheduled_task_updated", "scheduled_task_registered", "scheduled_task_deleted"}:
        message = f"Scheduled task changed: {task_name or 'unknown'}"
    elif classification.source_match and classification.source_family == "powershell":
        message = "PowerShell script block/module logging event"
    else:
        message = classification.message_hint or f"Windows event {event_id or 'unknown'} from {provider or '?'}"

    normalized_event_type = classification.event_type
    normalized_event_action = classification.action or classification.event_type
    normalized_artifact_type = "windows_event"
    normalized_parser = artifact_meta.get("parser") or document["artifact"].get("parser")
    if classification.source_match and classification.category == "process":
        normalized_event_type = "process_start"
        normalized_event_action = "process_created"
        normalized_artifact_type = "process"
        normalized_parser = "sysmon_evtx" if event_id == 1 and "sysmon" in lower_provider else "security_4688" if event_id == 4688 and lower_channel == "security" else (artifact_meta.get("parser") or document["artifact"].get("parser"))

    document["event"].update(
        {
            "category": classification.category,
            "type": normalized_event_type,
            "action": normalized_event_action,
            "severity": classification.severity,
            "message": message,
        }
    )
    document["artifact"]["type"] = normalized_artifact_type
    document["artifact"]["parser"] = normalized_parser
    document["source_file"] = source_file
    document["host"]["name"] = host_name
    document["host"]["hostname"] = host_name
    document["user"]["name"] = user_name
    process_path = _normalize_windowsish_path(process_name)
    parent_process_path = _normalize_windowsish_path(first_value(row, ["ParentProcessName", "CreatorProcessName", "ParentImage"]))
    pid = _parse_pidish(first_value(row, ["ProcessId", "NewProcessId"]))
    parent_pid = _parse_pidish(first_value(row, ["ParentProcessId", "CreatorProcessId"]))
    process_hashes = _parse_hashes_field(first_value(row, ["Hashes"]))
    process_entity_id = _process_entity_id(document, row, host_name, process_path, pid)
    parent_entity_id = _clean_placeholder(first_value(row, ["ParentProcessGuid", "ParentProcessGUID"]))
    document["process"].update(
        {
            "entity_id": process_entity_id,
            "name": _safe_windows_basename(process_path or process_name),
            "path": process_path or _clean_placeholder(process_name),
            "command_line": command_line,
            "current_directory": _normalize_windowsish_path(first_value(row, ["CurrentDirectory"])),
            "parent_entity_id": parent_entity_id,
            "parent_name": _safe_windows_basename(parent_process_path),
            "parent_path": parent_process_path,
            "parent_command_line": first_value(row, ["ParentCommandLine"]),
            "pid": pid,
            "ppid": parent_pid,
            "parent_pid": parent_pid,
            "integrity_level": first_value(row, ["IntegrityLevel", "MandatoryLabel"]),
            "hashes": process_hashes,
            "application": _safe_windows_basename(process_path or process_name),
        }
    )
    if process_path:
        document["file"].update(
            {
                "path": process_path,
                "name": _safe_windows_basename(process_path),
                "extension": _appcompat_extension(process_path),
                "parent_path": _safe_windows_parent(process_path),
                "source_path": source_file,
            }
        )
    document["network"].update({"source_ip": source_ip, "destination_ip": first_value(row, ["DestinationAddress", "DestinationIp"]), "source_port": first_value(row, ["SourcePort"]), "destination_port": first_value(row, ["DestinationPort"])})
    document["windows"].update(
        {
            "event_id": event_id,
            "channel": channel,
            "provider": provider,
            "logon_type": logon_type,
            "service_name": service_name,
            "task_name": task_name,
            "record_id": record_id,
            "record_number": record_id,
            "opcode": opcode,
            "level": level,
            "keywords": keywords,
            "event_data_summary": event_data_summary,
            "computer": host_name,
            "process_id": first_value(row, ["ProcessId"]),
            "thread_id": first_value(row, ["ThreadId"]),
            "event_data": row.get("Payload") if isinstance(row.get("Payload"), dict) else None,
            "raw_xml": first_value(row, ["RawXml", "Xml"]),
        }
    )
    document = _apply_sysmon_event_normalization(document, row, event_id, source_file)
    document = _apply_security_4663_normalization(document, row, event_id)
    if classification.source_match and classification.category == "process":
        document["execution"].update(
            {
                "source": "process_creation",
                "is_execution_confirmed": True,
                "confidence": "high",
                "interpretation": "Process creation event confirms execution",
            }
        )
        if not first_value(row, ["ProcessGuid", "ProcessGUID"]):
            document["data_quality"] = sorted(set(document.get("data_quality", [])) | {"missing_process_guid"})
        if not parent_entity_id:
            document["data_quality"] = sorted(set(document.get("data_quality", [])) | {"missing_parent_guid"})
    if classification.source_match and classification.source_family == "powershell":
        from app.ingest.powershell.normalizer import normalize_powershell_row

        ps_meta = {
            **artifact_meta,
            "artifact_type": "powershell",
            "parser": "powershell_evtx",
            "source_tool": artifact_meta.get("source_tool") or "native_evtx",
            "source_format": "evtx",
            "powershell_artifact_type": "powershell_evtx",
        }
        document = normalize_powershell_row(document, row, ps_meta)
        document["artifact"]["type"] = "powershell"
        document["artifact"]["parser"] = "powershell_evtx"
        document["source_tool"] = ps_meta["source_tool"]
        document["source_format"] = "evtx"
        document["powershell"]["artifact_type"] = "powershell_evtx"
        document["powershell"]["source_file"] = source_file
        if event_id == 4103:
            document["event"].update(
                {
                    "type": "module_logging",
                    "action": "powershell_module_command_observed",
                    "message": f"PowerShell module logging: {document['powershell'].get('command_preview') or 'command observed'}",
                }
            )
            document["execution"].update(
                {
                    "source": "powershell",
                    "is_execution_confirmed": True if document["powershell"].get("command") or document["powershell"].get("command_preview") else False,
                    "confidence": "high" if document["powershell"].get("command") or document["powershell"].get("command_preview") else "medium",
                    "interpretation": "PowerShell module logging indicates command execution context",
                }
            )
        elif event_id in {400, 403}:
            document["event"].update(
                {
                    "type": "powershell_engine_lifecycle",
                    "action": "powershell_engine_lifecycle_observed",
                    "message": "PowerShell engine lifecycle observed",
                }
            )
            document["execution"].update(
                {
                    "source": "powershell",
                    "is_execution_confirmed": False,
                    "confidence": "low",
                    "interpretation": "PowerShell engine lifecycle indicates session activity, not command execution by itself",
                }
            )
        elif event_id == 600:
            document["event"].update(
                {
                    "type": "provider_lifecycle",
                    "action": "powershell_provider_lifecycle_observed",
                    "message": "PowerShell provider lifecycle observed",
                }
            )
            document["execution"].update(
                {
                    "source": "powershell",
                    "is_execution_confirmed": False,
                    "confidence": "low",
                    "interpretation": "PowerShell provider lifecycle indicates session activity, not command execution by itself",
                }
            )
        elif event_id == 800:
            document["event"].update(
                {
                    "type": "pipeline_execution",
                    "action": "powershell_pipeline_execution_observed",
                    "message": f"PowerShell pipeline execution: {document['powershell'].get('command_preview') or 'pipeline observed'}",
                }
            )
            document["execution"].update(
                {
                    "source": "powershell",
                    "is_execution_confirmed": True,
                    "confidence": "medium",
                    "interpretation": "PowerShell pipeline execution event indicates command or pipeline execution context",
                }
            )
        document["event_id"] = _stable_event_id(document.get("case_id"), document.get("evidence_id"), source_file, channel, record_id or event_id, document.get("@timestamp") or event_payload_hash, provider)
        return document
    if classification.source_match and classification.source_family == "defender":
        from app.ingest.defender.normalizer import normalize_defender_row

        defender_meta = {
            **artifact_meta,
            "artifact_type": "detection",
            "parser": "defender_evtx",
            "source_tool": artifact_meta.get("source_tool") or "native_evtx",
            "source_format": "evtx",
            "defender_artifact_type": "defender_evtx",
        }
        document = normalize_defender_row(document, row, defender_meta)
        document["artifact"]["type"] = "detection"
        document["artifact"]["parser"] = "defender_evtx"
        document["source_tool"] = defender_meta["source_tool"]
        document["source_format"] = "evtx"
        document["source_file"] = source_file
        document["host"]["name"] = host_name
        document["host"]["hostname"] = host_name
        document["user"]["name"] = document.get("user", {}).get("name") or user_name
        document["windows"].update(
            {
                "event_id": event_id,
                "channel": channel,
                "provider": provider,
                "record_id": record_id,
                "record_number": record_id,
                "opcode": opcode,
                "level": level,
                "keywords": keywords,
                "event_data_summary": event_data_summary,
                "computer": host_name,
                "process_id": first_value(row, ["ProcessId"]),
                "thread_id": first_value(row, ["ThreadId"]),
                "event_data": row.get("Payload") if isinstance(row.get("Payload"), dict) else None,
                "raw_xml": first_value(row, ["RawXml", "Xml"]),
            }
        )
        document["event_id"] = _stable_event_id(document.get("case_id"), document.get("evidence_id"), source_file, channel, record_id or event_id, document.get("@timestamp") or event_payload_hash, provider)
        return document
    if classification.source_match and "scheduled_task" in classification.event_type:
        document["task"] = {
            **(document.get("task") or {}),
            "name": task_name,
            "path": task_name,
            "uri": task_name,
            "source_file": source_file,
        }
        document["persistence"].update(
            {
                "mechanism": "scheduled_task",
                "location": task_name,
                "name": task_name,
                "path": None,
                "source": source_file,
            }
        )
        document["execution"].update(
            {
                "source": "task_scheduler_evtx" if classification.event_type in {"scheduled_task_action_started", "scheduled_task_action_completed", "scheduled_task_completed"} else "scheduled_task",
                "program_name": Path(str(task_action_name or process_name or "")).name or None,
                "confidence": "high" if classification.event_type in {"scheduled_task_action_started", "scheduled_task_action_completed", "scheduled_task_completed"} else "low",
                "is_execution_confirmed": classification.event_type in {"scheduled_task_action_started", "scheduled_task_action_completed", "scheduled_task_completed"},
                "interpretation": "Task Scheduler Operational EVTX indicates scheduled task execution" if classification.event_type in {"scheduled_task_action_started", "scheduled_task_action_completed", "scheduled_task_completed"} else "Scheduled task registration/update/delete event indicates persistence metadata, not execution by itself",
            }
        )
        document["task"].update(
            {
                "instance_id": task_instance_id,
                "action_name": task_action_name,
                "engine_pid": task_engine_pid,
                "result_code": task_result_code,
            }
        )
        if first_value(row, ["UserName"]):
            document["user"]["name"] = document["user"].get("name") or first_value(row, ["UserName"])
    if service_path:
        document["file"]["path"] = service_path
    document["tags"] = sorted(set(document.get("tags", [])) | set(classification.tags))
    if not classification.source_match and "source_mismatch" not in document["data_quality"]:
        document["data_quality"] = sorted(set(document.get("data_quality", [])) | {"source_mismatch"})
    summary_parts = [
        f"Provider={provider}" if provider else None,
        f"Channel={channel}" if channel else None,
        f"EventID={event_id}" if event_id is not None else None,
        f"RecordID={record_id}" if record_id else None,
        f"TimeCreated={document.get('@timestamp')}" if document.get("@timestamp") else None,
        f"EventData={str(event_data_summary)[:240]}" if event_data_summary else None,
    ]
    document["raw_summary"] = " | ".join(part for part in summary_parts if part)[:1024]
    if classification.source_match and event_id in {4624, 4625, 4634, 4648, 4672, 4688, 4697, 4698, 4720, 4722, 4723, 4724, 4728, 4732, 7045}:
        document["event_id"] = _stable_event_id(document.get("case_id"), document.get("evidence_id"), source_file, channel, record_id, event_id, document.get("@timestamp"))
    else:
        document["event_id"] = _stable_event_id(document.get("case_id"), document.get("evidence_id"), source_file, channel, record_id or event_id, document.get("@timestamp") or event_payload_hash, provider)
    return document


def normalize_mft_row(document: dict, row: dict, artifact_meta: dict) -> dict:
    file_path = _clean_placeholder(first_value(row, ["FullPath", "FilePath", "Path"]))
    parent_path = _clean_placeholder(first_value(row, ["ParentPath"]))
    file_name = _clean_placeholder(first_value(row, ["FileName", "Name"])) or (Path(file_path).name if file_path else None)
    if not file_path and parent_path and file_name:
        file_path = str(Path(parent_path) / file_name)
        document["data_quality"] = sorted(set(document.get("data_quality", [])) | {"mft_path_reconstructed"})
    if not file_name and file_path:
        file_name = Path(file_path).name
    in_use = _lower_bool(first_value(row, ["InUse"]))
    deleted_flag = _lower_bool(first_value(row, ["Deleted", "IsDeleted"]))
    is_deleted = (in_use is False) or (deleted_flag is True)
    created_si = first_value(row, ["SI_Created", "Created0x10"])
    created_fn = first_value(row, ["FN_Created", "Created0x30"])
    modified_si = first_value(row, ["SI_Modified", "Modified0x10"])
    modified_fn = first_value(row, ["FN_Modified", "Modified0x30"])
    accessed_si = first_value(row, ["SI_Accessed", "LastAccess0x10"])
    accessed_fn = first_value(row, ["FN_Accessed", "LastAccess0x30"])
    changed_si = first_value(row, ["SI_Changed", "LastRecordChange0x10"])
    changed_fn = first_value(row, ["FN_Changed", "LastRecordChange0x30"])
    ads_name = _clean_placeholder(first_value(row, ["AdsName"]))
    ads_size = first_value(row, ["AdsSize"])
    zone_id = _clean_placeholder(first_value(row, ["ZoneId"]))
    has_ads = _lower_bool(first_value(row, ["HasAds"])) or bool(ads_name or zone_id)
    extension = first_value(row, ["Extension"]) or (Path(file_name).suffix if file_name else None)
    lower_path = str(file_path or "").lower()
    lower_name = str(file_name or "").lower()
    suspicious_reasons: list[str] = []
    if extension in {".exe", ".dll", ".msi", ".scr"} and is_deleted:
        suspicious_reasons.append("MFT deleted executable")
    if extension in {".ps1", ".bat", ".cmd", ".vbs", ".js", ".hta"} and is_deleted:
        suspicious_reasons.append("MFT deleted script")
    if extension in {".zip", ".rar", ".7z", ".iso", ".img"} and is_deleted:
        suspicious_reasons.append("MFT deleted archive")
    if extension in {".exe", ".dll", ".msi", ".scr"} and any(token in lower_path for token in ("\\downloads\\", "\\desktop\\", "\\appdata\\", "\\temp\\", "\\users\\public\\")):
        suspicious_reasons.append("MFT executable in user-writable path")
    if extension in {".ps1", ".bat", ".cmd", ".vbs", ".js", ".hta"} and any(token in lower_path for token in ("\\downloads\\", "\\desktop\\", "\\appdata\\", "\\temp\\", "\\users\\public\\")):
        suspicious_reasons.append("MFT script in user-writable path")
    if "\\startup\\" in lower_path:
        suspicious_reasons.append("MFT file in Startup folder")
    if any(token in lower_name for token in ("payload", "invoice", "update", "installer", "setup", "crack", "keygen", "loader", "beacon")):
        suspicious_reasons.append("MFT suspicious filename keyword")
    if extension in {".exe", ".scr"} and (".pdf." in lower_name or ".doc." in lower_name or ".xls." in lower_name):
        suspicious_reasons.append("MFT double extension")
    if has_ads:
        suspicious_reasons.append("MFT alternate data stream observed")
    if zone_id or str(ads_name or "").lower() == "zone.identifier":
        suspicious_reasons.append("MFT Zone.Identifier observed")
    if any(token in lower_path for token in ("\\downloads\\", "\\desktop\\", "\\appdata\\", "\\temp\\", "\\users\\public\\", "\\startup\\")) and is_deleted:
        suspicious_reasons.append("MFT deleted file in suspicious path")
    timestomp = bool(created_si and created_fn and created_si[:10] != created_fn[:10] and extension in {".exe", ".dll", ".msi", ".scr", ".ps1", ".bat", ".cmd", ".js", ".vbs", ".hta"})
    if timestomp:
        suspicious_reasons.extend(["MFT timestamp anomaly", "MFT possible timestomping"])

    activity = "alternate_data_stream" if has_ads else "file_deleted" if is_deleted else "file_observed"
    document["event"].update(
        {
            "category": "file",
            "type": activity,
            "action": "mft_ads_observed" if has_ads else "mft_deleted_entry_observed" if is_deleted else "mft_entry_observed",
            "severity": "high" if suspicious_reasons and any(reason in suspicious_reasons for reason in ("MFT executable in user-writable path", "MFT script in user-writable path", "MFT file in Startup folder", "MFT possible timestomping")) else "medium" if suspicious_reasons else "info",
            "message": f"{'Alternate Data Stream observed' if has_ads else 'Deleted MFT entry observed' if is_deleted else 'MFT entry observed'}: {file_path or file_name or 'unknown'}" + (f":{ads_name}" if has_ads and ads_name else ""),
        }
    )
    document["file"].update(
        {
            "path": file_path,
            "name": file_name,
            "extension": extension,
            "size": first_value(row, ["FileSize", "Size"]),
            "created": created_si or created_fn,
            "modified": modified_si or modified_fn,
            "accessed": accessed_si or accessed_fn,
            "changed": changed_si or changed_fn,
            "deleted": is_deleted,
            "parent_path": parent_path,
            "source_path": artifact_meta.get("source_path"),
        }
    )
    document["mft"] = {
        "entry_number": first_value(row, ["EntryNumber"]),
        "sequence_number": first_value(row, ["SequenceNumber"]),
        "parent_entry_number": first_value(row, ["ParentEntryNumber"]),
        "parent_sequence_number": first_value(row, ["ParentSequenceNumber"]),
        "in_use": in_use,
        "is_deleted": is_deleted,
        "ads": [ads_name or zone_id] if (ads_name or zone_id) else [],
        "si_created": created_si,
        "si_modified": modified_si,
        "si_accessed": accessed_si,
        "si_changed": changed_si,
        "fn_created": created_fn,
        "fn_modified": modified_fn,
        "fn_accessed": accessed_fn,
        "fn_changed": changed_fn,
    }
    document["user"]["name"] = extract_user(row, artifact_meta)
    document["user"]["sid"] = first_value(row, ["OwnerSid", "UserSid"])
    document["volume"]["drive_letter"] = first_value(row, ["DriveLetter"]) or (str(file_path)[:2] if file_path and re.match(r"^[A-Za-z]:", str(file_path)) else None)
    document["volume"]["serial"] = first_value(row, ["VolumeSerial"])
    document["execution"].update(
        {
            "source": "mft",
            "is_execution_confirmed": False,
            "confidence": "low",
            "interpretation": "MFT entries indicate filesystem metadata, not program execution by itself",
        }
    )
    if changed_si:
        document["@timestamp"] = changed_si
        document["timestamp_precision"] = "mft_si_changed"
    elif modified_si:
        document["@timestamp"] = modified_si
        document["timestamp_precision"] = "mft_si_modified"
    elif created_si:
        document["@timestamp"] = created_si
        document["timestamp_precision"] = "mft_si_created"
    elif changed_fn:
        document["@timestamp"] = changed_fn
        document["timestamp_precision"] = "mft_fn_changed"
    elif modified_fn:
        document["@timestamp"] = modified_fn
        document["timestamp_precision"] = "mft_fn_modified"
    elif created_fn:
        document["@timestamp"] = created_fn
        document["timestamp_precision"] = "mft_fn_created"
    if not document["file"]["path"] and file_name:
        document["data_quality"] = sorted(set(document.get("data_quality", [])) | {"missing_path"})
    if is_deleted:
        document["data_quality"] = sorted(set(document.get("data_quality", [])) | {"mft_deleted_entry"})
    if has_ads:
        document["data_quality"] = sorted(set(document.get("data_quality", [])) | {"mft_ads_present"})
    if timestomp:
        document["data_quality"] = sorted(set(document.get("data_quality", [])) | {"mft_timestamp_inconsistency"})
    document["suspicious_reasons"] = sorted(set(document.get("suspicious_reasons", [])) | set(suspicious_reasons))
    score = 5
    if suspicious_reasons:
        score += 20
    if any(reason in suspicious_reasons for reason in ("MFT deleted executable", "MFT deleted script", "MFT deleted archive")):
        score += 18
    if any(reason in suspicious_reasons for reason in ("MFT executable in user-writable path", "MFT script in user-writable path", "MFT file in Startup folder")):
        score += 22
    if "MFT alternate data stream observed" in suspicious_reasons:
        score += 25
    if "MFT Zone.Identifier observed" in suspicious_reasons:
        score += 8
    if "MFT double extension" in suspicious_reasons:
        score += 10
    if "MFT possible timestomping" in suspicious_reasons:
        score += 22
    document["risk_score"] = min(score, 100)
    document["tags"] = sorted(set(document.get("tags", [])) | {"mft", "filesystem"} | ({"deleted"} if is_deleted else set()) | ({"suspicious_path"} if _suspicious_path(file_path) else set()) | ({"ads"} if has_ads else set()))
    return document


def normalize_prefetch_row(document: dict, row: dict, artifact_meta: dict) -> dict:
    executable_name = _clean_placeholder(first_value(row, ["ExecutableName", "Application", "Filename"]))
    source_file = _normalize_windowsish_path(first_value(row, ["SourceFile", "SourceFilename"]))
    if not executable_name and source_file:
        executable_name = _parse_prefetch_filename(Path(source_file).name)[0]
    executable_path = _normalize_windowsish_path(first_value(row, ["ExecutablePath", "Path"]))
    prefetch_hash = _clean_placeholder(first_value(row, ["PrefetchHash", "Hash"]))
    run_count = _safe_int(first_value(row, ["RunCount"]))
    version = _safe_int(first_value(row, ["Version"]))
    signature = _clean_placeholder(first_value(row, ["Signature"]))
    last_run = _parse_iso_timestamp(first_value(row, ["LastRun", "LastRunTime"]))
    last_runs = [
        parsed
        for parsed in (
            _parse_iso_timestamp(value)
            for key, value in row.items()
            if str(key or "").lower().startswith("previousrun") or str(key or "").lower().startswith("lastrun")
        )
        if parsed
    ]
    last_runs = sorted(dict.fromkeys(last_runs))
    latest_last_run = last_run or (last_runs[-1] if last_runs else None)
    source_created = _parse_iso_timestamp(first_value(row, ["SourceCreated"]))
    source_modified = _parse_iso_timestamp(first_value(row, ["SourceModified", "Modified"]))
    source_accessed = _parse_iso_timestamp(first_value(row, ["SourceAccessed"]))
    source_file_mtime = _parse_iso_timestamp(first_value(row, ["SourceFileMtime"]))
    source_file_mtime_confidence = str(first_value(row, ["SourceFileMtimeConfidence"]) or artifact_meta.get("source_file_mtime_confidence") or "").lower()
    referenced_files = [
        _normalize_windowsish_path(item) or item
        for item in re.split(r"[|\n;]+", str(first_value(row, ["ReferencedFiles", "FilesLoaded"]) or ""))
        if str(item).strip()
    ]
    referenced_files = list(dict.fromkeys(filter(None, referenced_files)))
    referenced_directories = [
        _normalize_windowsish_path(item) or item
        for item in re.split(r"[|\n;]+", str(first_value(row, ["ReferencedDirectories", "Directories"]) or ""))
        if str(item).strip()
    ]
    referenced_directories = list(dict.fromkeys(filter(None, referenced_directories)))
    volume_serial = _clean_placeholder(first_value(row, ["VolumeSerialNumber"]))
    volume_device_path = _normalize_windowsish_path(first_value(row, ["VolumeDevicePath"]))
    volume_creation_time = _parse_iso_timestamp(first_value(row, ["VolumeCreationTime"]))
    volume_label = _clean_placeholder(first_value(row, ["VolumeLabel"]))
    parse_warnings = [item.strip() for item in str(first_value(row, ["ParseWarnings"]) or "").split(";") if item.strip()]
    parser_status = _clean_placeholder(first_value(row, ["ParserStatus"])) or ("parsed_native" if not parse_warnings or "unsupported_prefetch_version" not in parse_warnings else "failed")
    processed_at = _parse_iso_timestamp(str(artifact_meta.get("parser_processed_at") or "")) or datetime.now(tz=UTC).isoformat()

    timestamp = latest_last_run or source_modified
    timestamp_precision = (
        "prefetch_last_run" if last_run
        else "prefetch_last_run_array" if last_runs
        else "source_file_mtime" if source_modified and source_file_mtime_confidence == "high"
        else "source_file_mtime_low_confidence" if source_file_mtime or source_modified
        else "unknown"
    )
    if not latest_last_run and not source_modified and source_file_mtime and source_file_mtime_confidence == "high":
        timestamp = source_file_mtime
    elif not latest_last_run and not source_modified and source_file_mtime:
        timestamp = source_file_mtime

    executable_path_name = _appcompat_basename(executable_path)
    process_name = executable_path_name or executable_name
    file_name = executable_path_name or process_name
    file_extension = _appcompat_extension(executable_path or file_name)
    lowered_name = str(process_name or "").lower()

    tags = set(document.get("tags", [])) | {"prefetch", "execution", "program_execution"}
    reasons: set[str] = set(document.get("suspicious_reasons", []))
    data_quality = set(document.get("data_quality", []))

    if executable_path:
        lowered_path = executable_path.lower()
        if any(token in lowered_path for token in ["\\appdata\\", "\\temp\\", "\\downloads\\", "\\desktop\\", "\\users\\public\\"]):
            tags.add("user_writable_path")
            reasons.add("Prefetch indicates execution from user-writable path")
        if "\\$recycle.bin\\" in lowered_path or "\\recycler\\" in lowered_path:
            tags.update({"suspicious", "suspicious_path"})
            reasons.add("Prefetch indicates execution from Recycle Bin")
        if executable_path.startswith("\\\\"):
            tags.update({"suspicious", "suspicious_path", "network_path"})
            reasons.add("Prefetch indicates execution from UNC path")
        if any(provider in lowered_path for provider in ["\\onedrive\\", "\\dropbox\\", "\\google drive\\", "\\googledrive\\", "\\megasync\\", "\\icloud", "\\box\\"]):
            tags.add("cloud_path")
            if file_extension in EXECUTION_ARTIFACT_EXTENSIONS:
                tags.update({"suspicious", "suspicious_path"})
                reasons.add("Prefetch indicates execution from cloud sync folder")
        path_reasons = detect_suspicious_path(executable_path)
        if path_reasons and file_extension in EXECUTION_ARTIFACT_EXTENSIONS:
            tags.update({"suspicious", "suspicious_path"})
            reasons.update(f"Prefetch path indicator: {reason}" for reason in path_reasons)
    else:
        reasons.add("Prefetch executable path could not be resolved")

    if lowered_name in PREFETCH_LOLBINS:
        tags.update({"lolbin", "interesting_execution"})
        reasons.add("Prefetch indicates execution of LOLBin")
    if lowered_name in PREFETCH_REMOTE_ADMIN:
        tags.update({"remote_admin_tool", "suspicious"})
        reasons.add("Prefetch indicates execution of remote administration tool")
    if lowered_name in PREFETCH_FORENSIC_TOOLS:
        tags.add("forensic_tool")
    if lowered_name in PREFETCH_BROWSER_NAMES:
        tags.add("browser")
    if lowered_name in PREFETCH_ARCHIVE_TOOLS:
        tags.add("archive_tool")
    if lowered_name in PREFETCH_SECURITY_TOOLS:
        tags.add("security_tool")
    if lowered_name in {"powershell.exe", "pwsh.exe", "wscript.exe", "cscript.exe", "mshta.exe"}:
        tags.add("script_host")
    if file_extension in EXECUTION_ARTIFACT_EXTENSIONS:
        tags.add("execution_candidate")

    risk_score = 0
    if "remote_admin_tool" in tags:
        risk_score = max(risk_score, 50)
    if "forensic_tool" in tags:
        risk_score = max(risk_score, 25)
    if "lolbin" in tags:
        risk_score = max(risk_score, 30)
    if "user_writable_path" in tags and file_extension in EXECUTION_ARTIFACT_EXTENSIONS:
        risk_score = max(risk_score, 50)
    if any(token in str(executable_path or "").lower() for token in ["\\$recycle.bin\\", "\\recycler\\"]):
        risk_score = max(risk_score, 70)
    if executable_path and executable_path.startswith("\\\\"):
        risk_score = max(risk_score, 60)
    if "browser" in tags or (lowered_name in {"chrome.exe", "explorer.exe", "notepad.exe", "wireshark.exe"}):
        risk_score = min(max(risk_score, 0), 10)
    if executable_path and ":\\program files" in executable_path.lower():
        risk_score = min(max(risk_score, 0), 10) if risk_score == 0 else risk_score

    severity = "info"
    if risk_score >= 70:
        severity = "high"
    elif risk_score >= 45:
        severity = "medium"
    elif risk_score >= 20:
        severity = "low"

    if timestamp_precision == "source_file_mtime_low_confidence":
        data_quality.add("low_confidence_timestamp")
    if not executable_path:
        data_quality.add("content_missing")
    if not timestamp:
        data_quality.add("missing_timestamp")
    if parser_status == "partial" and executable_name and not latest_last_run and run_count in (None, 0):
        data_quality.add("prefetch_filename_only")
        data_quality.add("prefetch_metadata_only")

    document["@timestamp"] = timestamp
    document["timestamp_precision"] = timestamp_precision
    document["timezone"] = "UTC" if timestamp else "unknown"
    document["artifact"].update(
        {
            "type": "prefetch",
            "name": artifact_meta.get("name") or f"Prefetch raw - {Path(source_file or artifact_meta.get('source_path') or '').name}",
            "source_path": source_file or artifact_meta.get("source_path"),
            "parser": artifact_meta.get("parser", "prefetch_raw"),
        }
    )
    partial_prefetch = parser_status == "partial" or (executable_name and not latest_last_run and run_count in (None, 0))
    document["event"].update(
        {
            "category": "execution",
            "type": "prefetch_observed" if partial_prefetch else "process_executed",
            "action": "prefetch_execution_observed",
            "severity": severity,
            "timeline_include": bool(timestamp),
            "message": (
                f"Prefetch file observed but execution metadata could not be parsed: {process_name or 'unknown executable'}"
                if partial_prefetch
                else f"Prefetch execution observed: {process_name or 'unknown executable'} run_count={run_count if run_count is not None else '?'}"
            ),
        }
    )
    document["process"].update(
        {
            "name": process_name,
            "path": executable_path,
            "command_line": None,
            "application": process_name,
        }
    )
    document["file"].update(
        {
            "path": executable_path,
            "name": file_name,
            "extension": file_extension,
            "source_path": source_file,
        }
    )
    document["execution"] = {
        "source": "prefetch",
        "run_count": run_count,
        "first_run": None,
        "last_run": latest_last_run,
        "last_runs": last_runs,
        "program_name": process_name,
        "is_execution_confirmed": None if partial_prefetch else True,
        "confidence": "low" if partial_prefetch else "high",
        "interpretation": (
            "Prefetch file observed but execution metadata could not be parsed reliably"
            if partial_prefetch
            else "Prefetch indicates program execution on Windows when Prefetch is enabled"
        ),
    }
    document["prefetch"] = {
        "artifact_type": artifact_meta.get("prefetch_artifact_type") or ("prefetch_raw" if str(artifact_meta.get("parser") or "").lower() == "prefetch_raw" else "prefetch"),
        "executable_name": process_name,
        "executable_path": executable_path,
        "prefetch_hash": prefetch_hash,
        "run_count": run_count,
        "last_run": latest_last_run,
        "last_runs": last_runs,
        "source_file": source_file,
        "source_created": source_created,
        "source_modified": source_modified or source_file_mtime,
        "source_accessed": source_accessed,
        "version": version,
        "signature": signature,
        "file_size": _safe_int(first_value(row, ["FileSize"])),
        "volume_serial_number": volume_serial,
        "volume_device_path": volume_device_path,
        "volume_creation_time": volume_creation_time,
        "volume_label": volume_label,
        "referenced_files": referenced_files,
        "referenced_directories": referenced_directories,
        "loaded_files_count": _safe_int(first_value(row, ["LoadedFilesCount"])) or len(referenced_files),
        "referenced_files_count": _safe_int(first_value(row, ["ReferencedFilesCount"])) or len(referenced_files),
        "parse_warnings": parse_warnings,
        "parser_status": parser_status,
        "timestamp_interpretation": (
            "Prefetch last run timestamp from raw artifact"
            if latest_last_run
            else "Source file timestamp from inventory metadata; execution time not directly available"
            if timestamp
            else "Prefetch metadata observed without usable timestamp"
        ),
        "source_filename": source_file,
        "hash": prefetch_hash,
        "previous_runs": last_runs,
        "volume_serials": [volume_serial] if volume_serial else [],
        "volume_names": [volume_label] if volume_label else [],
        "volume_created_times": [volume_creation_time] if volume_creation_time else [],
        "directories": referenced_directories,
    }
    document.setdefault("volume", {})
    document["volume"].update(
        {
            "serial": volume_serial,
            "created": volume_creation_time,
            "label": volume_label,
            "device_path": volume_device_path,
        }
    )
    document.setdefault("ingest", {})
    document["ingest"]["processed_at"] = processed_at
    trusted_host = normalize_hostname(
        str(document["host"].get("name") or artifact_meta.get("detected_host") or "")
    )
    document["host"]["name"] = trusted_host
    document["host"]["hostname"] = trusted_host
    document["user"]["name"] = None
    document["risk_score"] = risk_score
    document["tags"] = sorted(tags)
    document["suspicious_reasons"] = sorted(reasons)
    document["data_quality"] = sorted(data_quality)

    raw_parts = [
        f"Executable={process_name}" if process_name else None,
        f"Path={executable_path}" if executable_path else None,
        f"RunCount={run_count}" if run_count is not None else None,
        f"LastRun={latest_last_run}" if latest_last_run else None,
        f"Hash={prefetch_hash}" if prefetch_hash else None,
    ]
    document["raw_summary"] = " | ".join(part for part in raw_parts if part)[:2000]
    return document


def normalize_amcache_row(document: dict, row: dict, artifact_meta: dict) -> dict:
    parser_name = str(artifact_meta.get("parser") or "").lower()
    source_tool = str(artifact_meta.get("source_tool") or "").lower()
    is_native_amcache = parser_name == "amcache_raw" or source_tool == "native_amcache"
    file_path = _select_appcompat_effective_path(row)
    program_name = _clean_placeholder(first_value(row, ["ProgramName", "ProductName", "Name"]))
    publisher = _clean_placeholder(first_value(row, ["Publisher"]))
    product_name = _clean_placeholder(first_value(row, ["ProductName"]))
    product_version = _clean_placeholder(first_value(row, ["ProductVersion", "ProgramVersion"]))
    file_name = _appcompat_basename(file_path) or _clean_placeholder(first_value(row, ["FileName", "Name"])) or program_name
    link_date = _parse_iso_timestamp(first_value(row, ["LinkDate"]))
    compile_time = _parse_iso_timestamp(first_value(row, ["CompileTime", "PECompileTime"]))
    install_date = _parse_iso_timestamp(first_value(row, ["InstallDate"]))
    last_modified = _parse_iso_timestamp(first_value(row, ["LastModified", "LastModifiedTime", "Modified"]))
    key_last_write = _parse_iso_timestamp(first_value(row, ["KeyLastWriteTimestamp", "LastWriteTime", "LastWrite"]))
    uninstall_date = _parse_iso_timestamp(first_value(row, ["UninstallDate"]))
    file_extension = _appcompat_extension(file_path or file_name)
    lower_path = str(file_path or "").lower()
    lower_name = str(file_name or "").lower()
    is_os_component = _boolish(first_value(row, ["IsOsComponent"]))
    is_execution_candidate = file_extension in AMCACHE_EXECUTION_CANDIDATE_EXTENSIONS
    is_installed_program = bool(program_name and install_date and not is_execution_candidate)
    if is_native_amcache:
        timestamp = key_last_write or install_date or link_date or compile_time
        timestamp_precision = (
            "amcache_key_last_write" if key_last_write else
            "amcache_install_date" if install_date else
            "amcache_link_date" if link_date else
            "amcache_compile_time" if compile_time else
            "unknown"
        )
    else:
        timestamp = key_last_write or link_date or compile_time or install_date
        timestamp_precision = (
            "registry_key_last_write" if key_last_write else
            "link_date" if link_date else
            "compile_time" if compile_time else
            "install_date" if install_date else
            "unknown"
        )
    confidence = "low" if is_native_amcache else ("medium" if is_execution_candidate and file_path else "low")
    event_category = "program_inventory" if is_installed_program else "execution" if is_execution_candidate else "file"
    if is_installed_program:
        event_type = "installed_program_observed"
    elif is_execution_candidate and is_native_amcache:
        event_type = "execution_candidate"
    elif is_execution_candidate:
        event_type = "program_observed"
    else:
        event_type = "file_observed"
    if event_type == "execution_candidate":
        event_action = "amcache_execution_candidate_observed"
    elif event_type == "file_observed":
        event_action = "amcache_file_observed"
    else:
        event_action = "amcache_program_observed"
    display_name = file_name or program_name or "unknown"
    if event_type == "installed_program_observed":
        message = f"Amcache installed program observed: {program_name or display_name}"
    elif event_type == "execution_candidate":
        message = f"Amcache executable candidate observed: {display_name}"
    elif event_type == "file_observed":
        message = f"Amcache file observed: {display_name}"
    else:
        message = f"Amcache program observed: {display_name}"
    timeline_include = bool(timestamp)
    if is_native_amcache and timestamp_precision in {"amcache_link_date", "amcache_compile_time"}:
        timeline_include = False

    document["@timestamp"] = timestamp
    document["timestamp_precision"] = timestamp_precision
    document["timezone"] = "UTC" if timestamp else None
    document["artifact"]["type"] = "amcache"
    document["event"].update(
        {
            "category": event_category,
            "type": event_type,
            "action": event_action,
            "severity": "info",
            "timeline_include": timeline_include,
            "message": message,
        }
    )
    document["file"].update(
        {
            "path": file_path,
            "name": file_name,
            "extension": file_extension,
            "source_path": _clean_placeholder(first_value(row, ["SourceFile", "Source"])) or _clean_placeholder(str(artifact_meta.get("source_path") or "")),
            "size": first_value(row, ["Size", "FileSize"]),
            "created": _parse_iso_timestamp(first_value(row, ["Created"])),
            "modified": last_modified,
            "hash_sha1": _normalize_hash(first_value(row, ["SHA1"]), {40}),
            "hash_sha256": _normalize_hash(first_value(row, ["SHA256"]), {64}),
            "sha1": _normalize_hash(first_value(row, ["SHA1"]), {40}),
            "sha256": _normalize_hash(first_value(row, ["SHA256"]), {64}),
            "md5": _normalize_hash(first_value(row, ["MD5"]), {32}),
        }
    )
    document["process"].update(
        {
            "name": file_name if is_execution_candidate else None,
            "path": file_path if is_execution_candidate else None,
            "application": file_name if is_execution_candidate else None,
            "publisher": publisher,
            "product_name": product_name,
            "product_version": product_version,
            "original_file_name": _clean_placeholder(first_value(row, ["OriginalFileName", "FileName"])),
        }
    )
    document["amcache"] = {
        "artifact_type": _clean_placeholder(first_value(row, ["ArtifactType"])) or ("amcache_raw" if is_native_amcache else "amcache"),
        "program_id": _clean_placeholder(first_value(row, ["ProgramId"])),
        "program_name": program_name,
        "program_version": _clean_placeholder(first_value(row, ["ProgramVersion"])),
        "publisher": publisher,
        "product_name": product_name,
        "product_version": product_version,
        "file_id": _clean_placeholder(first_value(row, ["FileId"])),
        "file_name": file_name,
        "file_path": file_path,
        "path_hash": _clean_placeholder(first_value(row, ["LongPathHash"])),
        "link_date": link_date,
        "compile_time": compile_time,
        "install_date": install_date,
        "uninstall_date": uninstall_date,
        "language": _clean_placeholder(first_value(row, ["Language"])),
        "binary_type": _clean_placeholder(first_value(row, ["BinaryType"])),
        "is_os_component": is_os_component,
        "key_path": _clean_placeholder(first_value(row, ["KeyPath"])),
        "key_last_write_time": key_last_write,
        "source_file": _clean_placeholder(first_value(row, ["SourceFile", "Source"])) or _clean_placeholder(str(artifact_meta.get("source_path") or "")),
        "parser_status": _clean_placeholder(first_value(row, ["ParserStatus"])) or ("parsed_native" if is_native_amcache else _clean_placeholder(str(artifact_meta.get("raw_parser_status") or ""))),
    }
    _set_execution_interpretation(
        document,
        source="amcache",
        confidence=confidence,
        confirmed=False,
        interpretation="Amcache indicates program/file presence or inventory, not execution by itself",
    )
    document["execution"].update(
        {
            "program_name": file_name if is_execution_candidate else None,
            "first_seen": install_date,
            "last_seen": key_last_write,
            "last_modified": last_modified,
            "install_date": install_date,
            "link_date": link_date,
            "compile_time": compile_time,
        }
    )
    inferred_user = extract_user_from_path(file_path) if file_path else None
    if inferred_user:
        document["user"]["name"] = document["user"].get("name") or inferred_user

    tags = set(document.get("tags", [])) | {"amcache", "program_inventory"}
    if file_name or file_path:
        tags.add("file_observed")
    if is_execution_candidate:
        tags.add("execution_candidate")
    if file_extension == ".dll":
        tags.add("dll")
    if file_extension == ".sys":
        tags.add("driver")
    if is_os_component is True:
        tags.add("os_component")
    if is_execution_candidate and (is_suspicious_double_extension(file_name) or is_suspicious_double_extension(file_path)):
        tags.add("double_extension")
    if any(token in lower_path for token in ["\\users\\", "\\downloads\\", "\\desktop\\", "\\appdata\\", "\\temp\\", "\\users\\public\\", "\\programdata\\"]):
        tags.add("user_writable_path")
    if is_execution_candidate and any(token in lower_path for token in ["\\downloads\\", "\\desktop\\", "\\appdata\\", "\\temp\\", "\\users\\public\\", "\\programdata\\"]):
        tags.update({"suspicious", "suspicious_path"})
    if lower_name in LOLBIN_HINTS:
        tags.add("lolbin")
    if any(token in f"{lower_name} {lower_path}" for token in REMOTE_ACCESS_TOOL_HINTS):
        tags.add("remote_access_tool")

    reasons = set(document.get("suspicious_reasons", []))
    if "user_writable_path" in tags and is_execution_candidate:
        reasons.add("Amcache observed executable in user-writable path")
    if "suspicious_path" in tags:
        reasons.update(_path_suspicion_reasons(file_path))
    if "double_extension" in tags:
        reasons.add("Double extension executable observed")
    if "lolbin" in tags:
        reasons.add("Known LOLBin observed in Amcache")
    if "remote_access_tool" in tags:
        reasons.add("Remote access tool observed in Amcache")

    risk_score = 0
    if is_os_component is True or "\\windows\\system32\\" in lower_path:
        risk_score = 0
    elif is_execution_candidate and "user_writable_path" in tags:
        risk_score = 15
        if any(token in lower_path for token in ["\\downloads\\", "\\desktop\\", "\\users\\public\\"]):
            risk_score = 20
        if any(token in lower_path for token in ["\\temp\\", "\\appdata\\"]):
            risk_score = 30
        if "double_extension" in tags:
            risk_score = max(risk_score, 35)
        if "double_extension" in tags or "remote_access_tool" in tags:
            risk_score = max(risk_score, 35)
        if "suspicious_path" in tags and not publisher:
            risk_score = max(risk_score, 40)
    elif is_execution_candidate:
        risk_score = 5

    severity = "info"
    if risk_score >= 30:
        severity = "medium"
    elif risk_score >= 10:
        severity = "low"

    data_quality = set(document.get("data_quality", [])) | {"amcache_not_execution_proof"}
    if not timestamp:
        data_quality.add("missing_timestamp")
    if not file_path:
        data_quality.add("missing_file_path")
    if not file_name:
        data_quality.add("missing_file_name")
    if not program_name:
        data_quality.add("missing_program_name")
    if is_execution_candidate:
        data_quality.add("low_confidence_execution")

    document["event"]["severity"] = severity
    document["risk_score"] = risk_score
    document["tags"] = sorted(tags)
    document["suspicious_reasons"] = sorted(reasons)
    document["data_quality"] = sorted(data_quality)
    return document


def normalize_shimcache_row(document: dict, row: dict, artifact_meta: dict) -> dict:
    file_path = _select_appcompat_effective_path(row)
    entry_name = _appcompat_basename(file_path) or _clean_placeholder(first_value(row, ["Name", "FileName"]))
    executed = _boolish(first_value(row, ["Executed", "ExecutionFlag"]))
    last_modified = _parse_iso_timestamp(first_value(row, ["LastModifiedTimeUTC", "LastModifiedTime", "LastModified"]))
    last_update = _parse_iso_timestamp(first_value(row, ["LastUpdate"]))
    last_write = _parse_iso_timestamp(first_value(row, ["LastWriteTime"]))
    timestamp = last_modified or last_update or None
    timestamp_precision = "shimcache_last_modified" if last_modified else "shimcache_last_update" if last_update else "unknown"
    lower_name = str((artifact_meta.get("name") or "")).lower()
    is_recentfilecache = "recentfilecache" in lower_name or "recentfilecache" in " ".join(str(key).lower() for key in row.keys())
    if is_recentfilecache:
        artifact_type = "appcompat"
        document["@timestamp"] = timestamp or last_write
        document["timestamp_precision"] = timestamp_precision if timestamp else "registry_last_write" if last_write else "unknown"
        document["timezone"] = "UTC" if (timestamp or last_write) else None
        document["artifact"]["type"] = artifact_type
        document["event"].update(
            {
                "category": "execution",
                "type": "recentfilecache_entry",
                "action": "program_presence_or_execution_hint",
                "severity": "info",
                "timeline_include": bool(timestamp or last_write),
                "message": f"AppCompat execution candidate observed: {entry_name or 'unknown'}",
            }
        )
        document["file"].update(
            {
                "path": file_path,
                "name": entry_name,
                "extension": _appcompat_extension(file_path or entry_name),
                "size": first_value(row, ["FileSize", "Size"]),
                "modified": last_modified,
                "source_path": artifact_meta.get("source_path"),
            }
        )
        document["process"].update({"name": entry_name, "path": file_path, "application": entry_name})
        document["appcompat"] = {
            "artifact_type": "recentfilecache_entry",
            "path": file_path,
            "name": entry_name,
            "last_modified": last_modified,
            "last_write_time": last_write,
            "entry_number": _clean_placeholder(first_value(row, ["EntryNumber"])),
            "source_file": _clean_placeholder(first_value(row, ["SourceFile", "Source"])),
            "interpretation": "program_presence_or_execution_hint",
        }
        _set_execution_interpretation(
            document,
            source="recentfilecache",
            confidence="low",
            confirmed=False,
            interpretation="RecentFileCache indicates program/file presence or compatibility cache entry, not execution by itself",
        )
        document["execution"].update({"program_name": entry_name, "last_modified": last_modified, "last_seen": last_update or last_write or last_modified})
        document["data_quality"] = sorted(set(document.get("data_quality", [])) | {"low_confidence_execution"})
        document["tags"] = sorted(set(document.get("tags", [])) | {"appcompat", "execution_candidate", "low_confidence_execution"})
        _apply_execution_artifact_suspicion(document, artifact_name=entry_name, path=file_path)
        return document

    file_extension = _appcompat_extension(file_path or entry_name)
    lower_path = str(file_path or "").lower()
    looks_executable = file_extension in EXECUTION_ARTIFACT_EXTENSIONS
    interpretation = "Shimcache/AppCompatCache indicates file presence or compatibility cache entry, not execution by itself"
    control_set = _clean_placeholder(first_value(row, ["ControlSet"]))
    parser_name = str(artifact_meta.get("parser") or "").lower()
    parser_status = _clean_placeholder(first_value(row, ["ParserStatus"])) or ("parsed_native" if parser_name == "shimcache_raw" else "parsed")
    timestamp_interpretation = _clean_placeholder(first_value(row, ["TimestampInterpretation"])) or timestamp_precision

    document["@timestamp"] = timestamp
    document["timestamp_precision"] = timestamp_precision
    document["timezone"] = "UTC" if timestamp else None
    document["artifact"]["type"] = "shimcache"
    document["event"].update(
        {
            "category": "execution",
            "type": "execution_candidate",
            "action": "shimcache_entry_observed",
            "severity": "info",
            "timeline_include": bool(timestamp),
            "message": f"Shimcache execution candidate observed: {entry_name or 'unknown'}",
        }
    )
    document["file"].update(
        {
            "path": file_path,
            "name": entry_name,
            "extension": file_extension,
            "size": first_value(row, ["FileSize", "Size"]),
            "modified": last_modified,
            "source_path": artifact_meta.get("source_path"),
        }
    )
    if looks_executable:
        document["process"].update({"name": entry_name, "path": file_path, "application": entry_name})
    document["shimcache"] = {
        "artifact_type": "shimcache_raw" if parser_name == "shimcache_raw" else "shimcache_parsed",
        "entry_number": _clean_placeholder(first_value(row, ["EntryNumber"])),
        "position": _clean_placeholder(first_value(row, ["CacheEntryPosition", "Position"])),
        "path": file_path,
        "last_modified_time": last_modified,
        "last_update": last_update or last_write,
        "insert_flags": _clean_placeholder(first_value(row, ["InsertFlags"])),
        "shim_flags": _clean_placeholder(first_value(row, ["ShimFlags", "AppCompatFlags"])),
        "executed": executed,
        "control_set": control_set,
        "source_file": _clean_placeholder(first_value(row, ["SourceFile", "Source"])) or artifact_meta.get("source_path"),
        "key_path": _clean_placeholder(first_value(row, ["KeyPath"])),
        "parser_status": parser_status,
        "timestamp_interpretation": timestamp_interpretation,
    }
    document["appcompat"] = {
        "artifact_type": "shimcache_entry",
        "path": file_path,
        "name": entry_name,
        "last_modified": last_modified,
        "last_write_time": last_write,
        "entry_number": _clean_placeholder(first_value(row, ["EntryNumber"])),
        "source_file": _clean_placeholder(first_value(row, ["SourceFile", "Source"])) or artifact_meta.get("source_path"),
        "interpretation": interpretation,
    }
    _set_execution_interpretation(
        document,
        source="shimcache",
        confidence="low",
        confirmed=False,
        interpretation=interpretation,
    )
    document["execution"].update(
        {
            "program_name": entry_name,
            "first_seen": None,
            "last_run": None,
            "last_modified": last_modified,
            "last_seen": None,
            "last_modified_time": last_modified,
        }
    )

    inferred_user = extract_user_from_path(file_path) if file_path else None
    if inferred_user:
        document["user"]["name"] = document["user"].get("name") or inferred_user

    tags = set(document.get("tags", [])) | {"shimcache", "appcompatcache", "execution_candidate", "file_observed", "low_confidence_execution"}
    if lower_path.startswith("c:\\windows\\") or lower_path.startswith("c:\\program files\\") or lower_path.startswith("c:\\program files (x86)\\"):
        tags.add("system_path")
    if any(token in lower_path for token in ["\\users\\", "\\downloads\\", "\\desktop\\", "\\appdata\\", "\\temp\\", "\\users\\public\\", "\\programdata\\"]):
        tags.add("user_writable_path")
    _apply_execution_artifact_suspicion(document, artifact_name=entry_name, path=file_path)
    tags.update(document.get("tags", []))

    reasons = set(document.get("suspicious_reasons", []))
    if "double_extension" in tags:
        reasons.add("Double extension executable observed")
    if executed is True:
        reasons.add("Shimcache executed flag observed, but this is not proof of execution on modern Windows")

    risk_score = 0
    if "system_path" in tags:
        risk_score = 0
    elif "user_writable_path" in tags:
        risk_score = 20
        if any(token in lower_path for token in ["\\temp\\", "\\appdata\\roaming\\", "\\public\\", "\\programdata\\"]):
            risk_score = 30
        if "double_extension" in tags or "remote_access_tool" in tags:
            risk_score = max(risk_score, 35)
        if "lolbin" in tags and "user_writable_path" in tags:
            risk_score = max(risk_score, 40)
    elif looks_executable:
        risk_score = 10

    severity = "info"
    if risk_score >= 30:
        severity = "medium"
    elif risk_score >= 10:
        severity = "low"

    data_quality = set(document.get("data_quality", [])) | {"shimcache_not_execution_proof", "low_confidence_execution"}
    if not timestamp:
        data_quality.add("missing_timestamp")
    if not file_path:
        data_quality.add("missing_file_path")
    if not entry_name:
        data_quality.add("missing_file_name")
    if not control_set:
        data_quality.add("unresolved_control_set")

    document["event"]["severity"] = severity
    document["risk_score"] = risk_score
    document["tags"] = sorted(tags)
    document["suspicious_reasons"] = sorted(reasons)
    document["data_quality"] = sorted(data_quality)
    return document


def normalize_lnk_row(document: dict, row: dict, artifact_meta: dict) -> dict:
    raw_lnk = {
        "source_file": first_value(row, ["SourceFile", "SourceFilename", "LnkFile", "FileName"]),
        "original_source_file": first_value(row, ["OriginalSourceFile"]),
        "normalized_windows_path": first_value(row, ["NormalizedWindowsPath"]),
        "target_path": first_value(row, ["TargetPath"]),
        "target_id_absolute_path": first_value(row, ["TargetIDAbsolutePath"]),
        "local_path": first_value(row, ["LocalPath", "LocalBasePath"]),
        "common_path": first_value(row, ["CommonPath"]),
        "relative_path": first_value(row, ["RelativePath"]),
        "working_directory": first_value(row, ["WorkingDirectory"]),
        "network_path": first_value(row, ["NetworkPath", "NetName", "ShareName"]),
        "environment_target": first_value(row, ["EnvironmentTarget"]),
        "description": first_value(row, ["Description", "NameString"]),
    }
    effective = select_lnk_effective_target(raw_lnk, row)
    target_path = effective.get("effective_path")
    normalized_target = _normalize_windowsish_path(target_path)
    raw_source_candidate = (
        raw_lnk["normalized_windows_path"]
        or artifact_meta.get("velociraptor_normalized_windows_path")
        or raw_lnk["source_file"]
        or artifact_meta.get("source_path")
    )
    source_file = _normalize_windowsish_path(raw_source_candidate)
    if raw_source_candidate and (("%3a" in str(raw_source_candidate).lower()) or str(raw_source_candidate).startswith(("Users/", "ProgramData/", "Windows/"))):
        source_file = _normalize_windowsish_path(normalize_velociraptor_path(str(raw_source_candidate))) or source_file
    working_directory = _normalize_windowsish_path(first_value(row, ["WorkingDirectory"]))
    arguments = _clean_placeholder(first_value(row, ["Arguments"]))
    description = _clean_placeholder(first_value(row, ["Description", "NameString"]))
    icon_location = _clean_placeholder(first_value(row, ["IconLocation"]))
    source_location = _lnk_source_location(source_file)
    target_extension = lecmd_suffix(normalized_target) if normalized_target else None
    lower_target = str(normalized_target or "").lower()
    lower_args = str(arguments or "").lower()
    tags = set(document.get("tags", [])) | {"lnk"}
    reasons = set(document.get("suspicious_reasons", []))
    data_quality = set(document.get("data_quality", []))
    is_network = bool(normalized_target and normalized_target.startswith("\\\\")) or bool(_clean_placeholder(raw_lnk["network_path"]))
    file_attributes = str(first_value(row, ["FileAttributes"]) or "")
    is_folder = bool(
        normalized_target
        and (
            "directory" in file_attributes.lower()
            or (not target_extension and not is_network and str(normalized_target).endswith("\\"))
        )
    )
    executable_exts = {".exe", ".bat", ".cmd", ".ps1", ".vbs", ".js", ".hta", ".scr", ".msi", ".dll"}
    script_exts = {".bat", ".cmd", ".ps1", ".vbs", ".js", ".hta"}
    event_type = "unknown_target"
    drive_type = _clean_placeholder(first_value(row, ["DriveType"]))
    drive_serial_number = _clean_placeholder(first_value(row, ["DriveSerialNumber", "DriveSerial"]))
    provider_from_path, sync_root_from_path, _ = detect_cloud_provider_from_path(normalized_target)
    source_in_startup = looks_like_startup_folder_path(source_file)
    target_in_startup = looks_like_startup_folder_path(normalized_target)
    is_partial_target = bool(effective.get("is_partial_path"))
    if any(token in str(value or "").lower() for value in {source_file, normalized_target, description} for token in ["amcacheparser", "drivebinaries.csv", "amcacheparser_drivebinaries.csv"]):
        tags.add("references_amcache_output")
    if is_network:
        event_type = "network_path_opened"
        tags.add("network_path")
    elif is_folder:
        event_type = "folder_opened"
        tags.add("folder_access")
    elif drive_type and any(token in str(drive_type).lower() for token in {"removable", "usb"}):
        event_type = "removable_media_path_opened"
        tags.update({"removable_media", "file_access"})
    elif target_extension in executable_exts:
        event_type = "script_opened" if target_extension in script_exts else "executable_opened"
        tags.update({"execution_candidate", "file_access"})
    elif normalized_target:
        event_type = "file_opened"
        tags.add("file_access")
    if source_location in {"start_menu", "taskbar"} and not source_in_startup:
        if target_extension in executable_exts:
            event_type = "shortcut_to_executable"
        elif not normalized_target:
            event_type = "shortcut_observed"
    if is_partial_target:
        tags.add("partial_lnk_target")
        data_quality.add("partial_lnk_target")
    in_user_writable_path = any(token in lower_target for token in ["\\appdata\\", "\\temp\\", "\\programdata\\", "\\users\\public\\", "\\downloads\\", "\\desktop\\"])
    if in_user_writable_path:
        tags.add("user_writable_path")
    if target_extension in ARCHIVE_EXTENSIONS:
        tags.add("archive_file")
    suspicious_path_needed = False
    if target_extension in executable_exts and in_user_writable_path:
        suspicious_path_needed = True
    if suspicious_path_needed:
        tags.update({"suspicious", "suspicious_path"})
        reasons.add("LNK target is executable/script in user-writable path")
    if any(token in lower_args for token in ["powershell", "-enc", "encodedcommand", "bypass", "hidden", "mshta", "rundll32", "regsvr32", "wscript", "cscript", "cmd /c", "http://", "https://"]):
        tags.update({"suspicious", "suspicious_arguments", "execution_candidate"})
        reasons.add("LNK arguments contain suspicious execution indicators")
    if is_network:
        if target_extension in executable_exts:
            tags.add("suspicious")
            reasons.add("LNK target uses network path")
    if source_in_startup or target_in_startup:
        tags.update({"startup_folder", "persistence", "suspicious"})
        reasons.add("LNK in Startup folder")
        event_type = "startup_lnk"
    if provider_from_path:
        tags.add("cloud_path")
    if re.match(r"^[a-z]:\\", str(normalized_target or ""), re.IGNORECASE):
        drive_letter = str(normalized_target)[0].lower()
        if drive_letter not in {"c"}:
            tags.add("removable_media")
            if event_type in {"unknown_target", "file_opened", "executable_opened", "script_opened"}:
                event_type = "removable_media_path_opened"
            if target_extension in executable_exts:
                tags.add("suspicious")
                reasons.add("LNK target appears to reference removable media")
    source_modified = _parse_iso_timestamp(first_value(row, ["SourceModified", "SourceModifiedTime", "SourceFileModified"]))
    source_created = _parse_iso_timestamp(first_value(row, ["SourceCreated", "SourceCreatedTime"]))
    source_accessed = _parse_iso_timestamp(first_value(row, ["SourceAccessed", "SourceAccessedTime"]))
    target_created = _parse_iso_timestamp(first_value(row, ["TargetCreated"]))
    target_modified = _parse_iso_timestamp(first_value(row, ["TargetModified"]))
    target_accessed = _parse_iso_timestamp(first_value(row, ["TargetAccessed"]))
    candidate_source_mtime = _parse_iso_timestamp(first_value(row, ["SourceFileMtime"]) or artifact_meta.get("source_file_mtime"))
    candidate_source_mtime_confidence = str(first_value(row, ["SourceFileMtimeConfidence"]) or artifact_meta.get("source_file_mtime_confidence") or "").strip().lower()
    timestamp = target_accessed or source_modified or source_created or target_modified or candidate_source_mtime
    timestamp_precision = (
        "lnk_target_accessed" if target_accessed
        else "lnk_source_modified" if source_modified
        else "lnk_source_created" if source_created
        else "lnk_target_modified" if target_modified
        else "source_file_mtime_low_confidence" if candidate_source_mtime and candidate_source_mtime_confidence == "low"
        else "source_file_mtime" if candidate_source_mtime
        else "unknown"
    )
    document["@timestamp"] = timestamp
    document["timestamp_precision"] = timestamp_precision
    document["timezone"] = "UTC" if timestamp else None
    document.setdefault("ingest", {})
    document["ingest"]["processed_at"] = _parse_iso_timestamp(str(artifact_meta.get("parser_processed_at") or "")) or _clean_placeholder(str(artifact_meta.get("parser_processed_at") or ""))
    trusted_host = normalize_hostname(str(artifact_meta.get("detected_host") or "")) if artifact_meta.get("detected_host") else None
    if not trusted_host:
        trusted_host = _valid_lnk_machine_id(first_value(row, ["MachineID", "MachineId"]))
    document["host"]["name"] = trusted_host
    document["host"]["hostname"] = trusted_host
    message_target = normalized_target or effective.get("display_name") or lecmd_basename(source_file) or "unknown"
    effective_source = str(effective.get("effective_path_source") or "")
    if effective_source == "icon_location_low_confidence":
        data_quality.add("effective_path_from_icon_location")
    if source_in_startup or target_in_startup:
        message = f"Startup shortcut observed: {message_target}"
    elif source_location in {"recent", "office_recent"}:
        message = f"LNK indicates recent access/reference: {message_target}"
    elif source_location == "start_menu":
        if normalized_target and target_extension in executable_exts:
            message = f"Start Menu shortcut to executable: {lecmd_basename(source_file) or message_target} -> {normalized_target}"
        else:
            message = f"Start Menu shortcut observed: {message_target}"
    elif source_location == "taskbar":
        message = f"LNK shortcut observed: {message_target}"
    else:
        message = f"LNK shortcut observed: {message_target}"
    document["event"].update(
        {
            "category": "persistence" if source_in_startup or target_in_startup else "shortcut" if source_location in {"start_menu", "taskbar"} else "file_access",
            "action": "shortcut_observed" if source_location in {"start_menu", "taskbar"} or source_in_startup or target_in_startup else "lnk_target_accessed",
            "type": event_type,
            "severity": "info",
            "timeline_include": bool(timestamp),
            "message": message,
        }
    )
    document["artifact"]["source_path"] = source_file
    document["file"].update(
        {
            "path": normalized_target,
            "name": lecmd_basename(normalized_target) if normalized_target else effective.get("display_name"),
            "extension": target_extension,
            "size": _safe_int(first_value(row, ["FileSize"])),
            "created": target_created,
            "modified": target_modified,
            "accessed": target_accessed,
            "source_path": source_file,
        }
    )
    document["lnk"] = {
        "target_path": _normalize_windowsish_path(raw_lnk["target_path"]),
        "target_id_absolute_path": _normalize_windowsish_path(raw_lnk["target_id_absolute_path"]),
        "local_path": _normalize_windowsish_path(raw_lnk["local_path"]),
        "common_path": _normalize_windowsish_path(raw_lnk["common_path"]),
        "relative_path": _normalize_windowsish_path(raw_lnk["relative_path"]),
        "effective_path": effective.get("effective_path"),
        "effective_path_source": effective.get("effective_path_source"),
        "display_name": effective.get("display_name"),
        "is_partial_target": effective.get("is_partial_path"),
        "is_shell_target": effective.get("is_shell_target"),
        "source_file": source_file,
        "arguments": arguments,
        "working_directory": working_directory,
        "icon_location": icon_location,
        "description": description,
        "environment_target": _normalize_windowsish_path(raw_lnk["environment_target"]),
        "machine_id": first_value(row, ["MachineID", "MachineId"]),
        "drive_serial": first_value(row, ["DriveSerial"]),
        "drive_serial_number": drive_serial_number,
        "drive_type": drive_type,
        "volume_label": first_value(row, ["VolumeLabel"]),
        "network_path": _normalize_windowsish_path(raw_lnk["network_path"]),
        "net_name": first_value(row, ["NetName"]),
        "device_name": first_value(row, ["DeviceName"]),
        "share_name": first_value(row, ["ShareName"]),
        "target_created": target_created,
        "target_modified": target_modified,
        "target_accessed": target_accessed,
        "source_created": source_created,
        "source_modified": source_modified,
        "source_accessed": source_accessed,
        "file_size": _safe_int(first_value(row, ["FileSize"])),
        "file_attributes": first_value(row, ["FileAttributes"]),
        "mft_entry": first_value(row, ["MFTEntry"]),
        "mft_sequence": first_value(row, ["MFTSequence"]),
        "parse_warnings": [warning.strip() for warning in str(first_value(row, ["ParseWarnings"]) or "").split(";") if warning.strip()],
        "timestamp_interpretation": (
            None
            if target_accessed
            else "LNK file timestamp from inventory/collection metadata; not necessarily target access time"
            if timestamp_precision == "source_file_mtime_low_confidence"
            else "LNK file timestamp; not necessarily target access time"
            if timestamp
            else "LNK metadata observed without usable timestamp"
        ),
    }
    document["user"]["name"] = extract_user(row, {"artifact_type": "lnk", **artifact_meta})
    if not document["user"].get("name") and source_file:
        document["user"]["name"] = extract_user_from_path(source_file)
    if provider_from_path:
        document.setdefault("cloud", {})
        document["cloud"]["provider"] = document["cloud"].get("provider") or provider_from_path
        document["cloud"]["sync_root"] = document["cloud"].get("sync_root") or sync_root_from_path
    if raw_lnk["network_path"]:
        document.setdefault("network", {})
        document["network"].update(
            {
                "path": _normalize_windowsish_path(raw_lnk["network_path"]),
                "share_name": _clean_placeholder(first_value(row, ["ShareName"])),
                "device_name": _clean_placeholder(first_value(row, ["DeviceName"])),
                "direction": "accessed",
            }
        )
    if drive_serial_number or drive_type:
        document.setdefault("volume", {})
        document["volume"].update(
            {
                "serial": drive_serial_number,
                "label": _clean_placeholder(first_value(row, ["VolumeLabel"])),
                "drive_type": drive_type,
            }
        )
    if source_in_startup or target_in_startup:
        document.setdefault("persistence", {})
        document["persistence"].update(
            {
                "mechanism": "startup_folder_lnk",
                "location": source_file or normalized_target,
                "name": lecmd_basename(source_file) or artifact_meta.get("name"),
                "command": normalized_target or arguments,
                "path": normalized_target,
                "confidence": "medium",
                "source": artifact_meta.get("parser") or "lnk_raw",
            }
        )
    document["source_file"] = source_file
    if not document["lnk"]["parse_warnings"] and not normalized_target:
        document["lnk"]["parse_warnings"] = ["no_resolved_target_path"]
    if not normalized_target and first_value(row, ["HasLinkTargetIdList"]) in {"True", "true", "1"} and "target_id_list_present_unresolved" not in (document["lnk"]["parse_warnings"] or []):
        document["lnk"]["parse_warnings"].append("target_id_list_present_unresolved")
    if not normalized_target and first_value(row, ["HasKnownFolderDataBlock"]) in {"True", "true", "1"} and "known_folder_unresolved" not in (document["lnk"]["parse_warnings"] or []):
        document["lnk"]["parse_warnings"].append("known_folder_unresolved")
    if not normalized_target and first_value(row, ["HasPropertyStoreDataBlock"]) in {"True", "true", "1"}:
        if "property_store_present_unparsed" not in (document["lnk"]["parse_warnings"] or []):
            document["lnk"]["parse_warnings"].append("property_store_present_unparsed")
        if "property_store_no_target_path" not in (document["lnk"]["parse_warnings"] or []):
            document["lnk"]["parse_warnings"].append("property_store_no_target_path")
    if (
        not normalized_target
        and first_value(row, ["HasLinkInfo"]) in {"True", "true", "1"}
        and not document["lnk"]["local_path"]
        and "linkinfo_parse_failed" not in (document["lnk"]["parse_warnings"] or [])
        and "linkinfo_present_no_local_path" not in (document["lnk"]["parse_warnings"] or [])
    ):
        document["lnk"]["parse_warnings"].append("linkinfo_present_no_local_path")
    if not normalized_target and first_value(row, ["HasLinkInfo"]) not in {"True", "true", "1"} and "linkinfo_absent" not in (document["lnk"]["parse_warnings"] or []):
        document["lnk"]["parse_warnings"].append("linkinfo_absent")
    if not normalized_target:
        data_quality.update({"missing_target_path", "unresolved_lnk_target"})
        tags.add("unresolved_lnk_target")
        reasons.add("LNK target could not be fully resolved")
    elif is_partial_target:
        reasons.add("LNK target could not be fully resolved")
    if effective_source == "icon_location_low_confidence":
        reasons.add("LNK effective path inferred from icon location")
    if timestamp_precision == "source_file_mtime_low_confidence":
        data_quality.add("low_confidence_timestamp")
    if event_type in {"executable_opened", "script_opened"} and source_in_startup:
        reasons.add("LNK in Startup folder")
        document["risk_score"] = max(int(document.get("risk_score") or 0), 70)
    elif "suspicious_arguments" in tags:
        document["risk_score"] = max(int(document.get("risk_score") or 0), 70)
    elif event_type in {"network_path_opened"} and target_extension in executable_exts:
        document["risk_score"] = max(int(document.get("risk_score") or 0), 60)
    elif event_type in {"executable_opened", "script_opened", "shortcut_to_executable"} and "cloud_path" in tags:
        document["risk_score"] = max(int(document.get("risk_score") or 0), 45)
    elif event_type in {"removable_media_path_opened"} and target_extension in executable_exts:
        document["risk_score"] = max(int(document.get("risk_score") or 0), 45)
    elif event_type in {"executable_opened", "script_opened", "shortcut_to_executable"} and "user_writable_path" in tags:
        document["risk_score"] = max(int(document.get("risk_score") or 0), 50)
    elif event_type in {"file_opened", "folder_opened", "shortcut_observed"}:
        document["risk_score"] = max(int(document.get("risk_score") or 0), 5 if normalized_target else 0)
    document["data_quality"] = sorted(data_quality)
    document["tags"] = sorted(tags)
    document["suspicious_reasons"] = sorted(reasons)
    document["event_id"] = _stable_event_id(
        document.get("case_id"),
        document.get("evidence_id"),
        source_file,
        normalized_target,
        target_accessed or source_modified,
        source_modified or source_created or _stable_payload_hash(row),
    )
    return document


def normalize_jumplist_row(document: dict, row: dict, artifact_meta: dict) -> dict:
    from app.ingest.jumplists.helpers import (
        basename_windows,
        classify_jumplist_path,
        infer_jumplist_user,
        normalize_windows_path,
        resolve_app_id_name,
        select_jumplist_effective_path,
        suffix_windows,
    )

    raw_jumplist = {
        "source_file": first_value(row, ["SourceFile", "SourceFilename"]),
        "target_path": first_value(row, ["TargetPath", "Path", "FilePath", "FullPath"]),
        "target_id_absolute_path": first_value(row, ["TargetIDAbsolutePath"]),
        "local_path": first_value(row, ["LocalPath"]),
        "common_path": first_value(row, ["CommonPath"]),
        "relative_path": first_value(row, ["RelativePath"]),
        "working_directory": first_value(row, ["WorkingDirectory"]),
        "network_path": first_value(row, ["NetworkPath", "NetName", "ShareName"]),
        "stream_name": first_value(row, ["StreamName"]),
        "description": first_value(row, ["Description"]),
    }
    effective = select_jumplist_effective_path(row)
    target_path = effective.get("effective_path")
    app_id = _clean_placeholder(first_value(row, ["AppId", "AppID"]))
    app_description = _clean_placeholder(first_value(row, ["AppIdDescription", "AppDescription"]))
    app_name = resolve_app_id_name(app_id, app_description, _clean_placeholder(first_value(row, ["Application", "AppName"])))
    app_id_unresolved = bool(app_id and not app_description and (not app_name or str(app_name).strip().lower() == str(app_id).strip().lower()))
    target_created = _parse_iso_timestamp(first_value(row, ["TargetCreated"]))
    target_modified = _parse_iso_timestamp(first_value(row, ["TargetModified", "LastModified", "ModifiedTime"]))
    target_accessed = _parse_iso_timestamp(first_value(row, ["TargetAccessed", "LastAccessed", "AccessedTime"]))
    tracker_created = _parse_iso_timestamp(first_value(row, ["TrackerCreatedOn"]))
    destlist_last_accessed = _parse_iso_timestamp(first_value(row, ["DestListLastAccessed"]))
    created = _parse_iso_timestamp(first_value(row, ["CreationTime"]))
    modified = _parse_iso_timestamp(first_value(row, ["ModifiedTime", "LastModified"]))
    accessed = _parse_iso_timestamp(first_value(row, ["AccessedTime", "LastAccessed"]))
    source_file_mtime = _parse_iso_timestamp(first_value(row, ["SourceFileMtime"]))
    timestamp = destlist_last_accessed or target_accessed or accessed or target_modified or modified or created or tracker_created or source_file_mtime
    timestamp_precision = (
        "jumplist_destlist_last_accessed" if destlist_last_accessed
        else "jumplist_target_accessed" if target_accessed
        else "jumplist_last_accessed" if accessed
        else "jumplist_target_modified" if target_modified
        else "jumplist_last_modified" if modified
        else "jumplist_created" if created
        else "tracker_created" if tracker_created
        else "source_file_mtime" if source_file_mtime
        else document.get("timestamp_precision") or "unknown"
    )
    normalized_path = normalize_windows_path(str(target_path) if target_path else None)
    classification = classify_jumplist_path(normalized_path, row)
    extension = suffix_windows(normalized_path)
    name = basename_windows(normalized_path) if normalized_path else effective.get("display_name")
    is_directory = bool(normalized_path and not extension and not normalized_path.startswith("\\\\") and normalized_path.endswith("\\"))
    destination_type = (
        "automatic" if str((raw_jumplist["source_file"] or "")).lower().endswith(".automaticdestinations-ms")
        else "custom" if str((raw_jumplist["source_file"] or "")).lower().endswith(".customdestinations-ms")
        else _clean_placeholder(first_value(row, ["DestinationType"]))
    )
    event_type = "jumplist_recent_item"
    if extension in {".exe", ".dll", ".scr", ".ps1", ".bat", ".cmd", ".vbs", ".js", ".jse", ".wsf", ".hta", ".msi"}:
        event_type = "program_or_script_opened"
    elif extension in {".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx", ".pdf", ".txt", ".rtf"}:
        event_type = "document_opened"
    elif is_directory:
        event_type = "folder_opened"
    display_target = normalized_path or effective.get("display_name") or app_name or app_id or "recent item"
    if classification["is_network_path"] and normalized_path:
        message = f"JumpList network item: {normalized_path} via {app_name or app_id or 'unknown app'}"
    elif normalized_path:
        message = f"JumpList recent item: {normalized_path} via {app_name or app_id or 'unknown app'}"
    elif app_name or app_id or raw_jumplist["stream_name"]:
        message = f"JumpList item observed via {app_name or app_id or raw_jumplist['stream_name']}"
    else:
        message = f"JumpList item observed: {display_target}"
    document["@timestamp"] = timestamp or document.get("@timestamp")
    document["timestamp_precision"] = timestamp_precision
    document["timezone"] = "UTC" if timestamp else document.get("timezone", "unknown")
    document["event"].update(
        {
            "category": "file_access",
            "type": event_type,
            "action": "jumplist_item_observed",
            "severity": "medium" if "suspicious" in set(classification["tags"]) else "info",
            "timeline_include": bool(timestamp),
            "message": message,
        }
    )
    document["file"].update(
        {
            "path": normalized_path,
            "name": name,
            "extension": extension,
            "size": _safe_int(_clean_placeholder(first_value(row, ["FileSize"]))),
            "created": target_created or created,
            "modified": target_modified or modified,
            "accessed": target_accessed or accessed,
            "is_directory": is_directory,
        }
    )
    document["jumplist"] = {
        "artifact_type": classification["artifact_type"],
        "app_id": app_id,
        "app_name": app_name,
        "app_id_description": app_description,
        "destination_type": destination_type,
        "entry_number": _clean_placeholder(first_value(row, ["EntryNumber", "EntryId"])),
        "source_file": raw_jumplist["source_file"],
        "target_path": raw_jumplist["target_path"],
        "target_created": target_created,
        "target_modified": target_modified,
        "target_accessed": target_accessed,
        "destlist_last_accessed": destlist_last_accessed,
        "destlist_access_count": _safe_int(_clean_placeholder(first_value(row, ["DestListAccessCount", "InteractionCount"]))),
        "destlist_pin_status": _clean_placeholder(first_value(row, ["DestListPinStatus", "Pinned", "PinStatus"])),
        "effective_path": effective.get("effective_path"),
        "effective_path_source": effective.get("effective_path_source"),
        "display_name": effective.get("display_name"),
        "stream_name": raw_jumplist["stream_name"],
        "local_path": raw_jumplist["local_path"],
        "common_path": raw_jumplist["common_path"],
        "relative_path": raw_jumplist["relative_path"],
        "working_directory": raw_jumplist["working_directory"],
        "arguments": first_value(row, ["Arguments"]),
        "description": raw_jumplist["description"],
        "interaction_count": first_value(row, ["InteractionCount"]),
        "machine_id": first_value(row, ["MachineID"]),
        "machine_mac_address": first_value(row, ["MachineMACAddress"]),
        "drive_serial_number": first_value(row, ["DriveSerialNumber", "VolumeSerialNumber"]),
        "volume_label": first_value(row, ["VolumeLabel", "DriveLabel"]),
        "drive_type": first_value(row, ["DriveType"]),
        "network_path": raw_jumplist["network_path"],
        "share_name": first_value(row, ["ShareName", "NetName"]),
        "device_name": first_value(row, ["DeviceName", "Hostname"]),
        "created": created,
        "modified": modified,
        "accessed": accessed,
        "tracker_created": tracker_created,
        "mft_entry": _clean_placeholder(first_value(row, ["TargetMFTEntryNumber"])),
        "mft_sequence": _clean_placeholder(first_value(row, ["TargetMFTSequenceNumber"])),
        "file_attributes": _clean_placeholder(first_value(row, ["FileAttributes"])),
        "parse_method": _clean_placeholder(first_value(row, ["ParseMethod"])),
        "parse_warnings": [str(item).strip() for item in str(first_value(row, ["ParseWarnings"]) or "").split(" | ") if str(item).strip()] or None,
        "timestamp_interpretation": (
            "JumpList source file modification time; may indicate JumpList update time, not exact item open time"
            if timestamp_precision == "source_file_mtime"
            else None
        ),
    }
    document["network"].update(
        {
            "path": raw_jumplist["network_path"] or (normalized_path if classification["is_network_path"] else None),
            "share_name": classification["share_name"] or first_value(row, ["ShareName", "NetName"]),
            "destination_hostname": classification["destination_hostname"],
            "device_name": classification["device_name"],
        }
    )
    document["volume"].update(
        {
            "serial": first_value(row, ["VolumeSerialNumber", "DriveSerialNumber"]),
            "label": first_value(row, ["VolumeLabel", "DriveLabel"]),
            "drive_type": first_value(row, ["DriveType"]) or ("removable" if classification["is_usb_path"] else None),
        }
    )
    document["lnk"] = {
        "source_file": raw_jumplist["source_file"],
        "target_path": raw_jumplist["target_path"],
        "local_path": raw_jumplist["local_path"],
        "relative_path": raw_jumplist["relative_path"],
        "working_directory": raw_jumplist["working_directory"],
        "arguments": first_value(row, ["Arguments"]),
    }
    document["user"]["name"] = extract_user(row, {"artifact_type": "jumplist", **artifact_meta}) or infer_jumplist_user(raw_jumplist["source_file"])
    if str(artifact_meta.get("source_tool") or "").lower() == "velociraptor_raw":
        source_file_path = raw_jumplist["source_file"] or str(artifact_meta.get("source_path") or "")
        document["velociraptor"].update(
            {
                "original_path": str(artifact_meta.get("velociraptor_original_path") or source_file_path or ""),
                "normalized_windows_path": str(artifact_meta.get("velociraptor_normalized_windows_path") or normalize_windows_path(source_file_path) or ""),
                "artifact_category": "jumplist",
                "parser_status": "parsed",
                "collection_id": artifact_meta.get("velociraptor_collection_id") or document.get("evidence_id"),
            }
        )
    if classification["destination_hostname"]:
        document["destination"]["hostname"] = classification["destination_hostname"]
    if not normalized_path:
        document.setdefault("data_quality", []).append("missing_target_path")
        if effective.get("generic_target_path"):
            document.setdefault("data_quality", []).append("generic_target_path")
            document.setdefault("data_quality", []).append("missing_effective_path")
    if not document.get("@timestamp"):
        document.setdefault("data_quality", []).append("missing_timestamp")
    if app_id_unresolved:
        document.setdefault("data_quality", []).append("unresolved_jumplist_app_id")
    document["tags"] = sorted(set(document.get("tags") or []) | set(classification["tags"]))
    if classification["reasons"]:
        document["suspicious_reasons"] = sorted(set(document.get("suspicious_reasons") or []) | set(classification["reasons"]))
    document["risk_score"] = max(int(document.get("risk_score") or 0), int(classification["risk"]))
    document["event"]["severity"] = "critical" if int(document.get("risk_score") or 0) >= 90 else "high" if int(document.get("risk_score") or 0) >= 70 else "medium" if int(document.get("risk_score") or 0) >= 40 else "low" if int(document.get("risk_score") or 0) >= 20 else "info"
    document["_preserve_risk_score"] = True
    return document


def normalize_shellbags_row(document: dict, row: dict, artifact_meta: dict) -> dict:
    from app.ingest.shellbags.helpers import basename_windows, classify_shellbag_path, infer_user_from_windows_path, normalize_windows_path, parse_shellbags_timestamp

    folder_path = normalize_windows_path(first_value(row, ["AbsolutePath", "Path", "FullPath", "ItemPath", "ShellItemPath", "FolderPath", "Value"]))
    bag_path = normalize_windows_path(first_value(row, ["BagPath"]))
    source_file = _clean_placeholder(first_value(row, ["SourceFile"]))
    hive_path = normalize_windows_path(first_value(row, ["HivePath", "Hive"]))
    key_path = normalize_windows_path(first_value(row, ["KeyPath"]))
    shell_type = _clean_placeholder(first_value(row, ["ShellType", "FriendlyName"]))
    slot = _clean_placeholder(first_value(row, ["Slot"]))
    node_slot = _clean_placeholder(first_value(row, ["NodeSlot"]))
    mru_position = _clean_placeholder(first_value(row, ["MRUPosition", "MRU"]))
    last_write = parse_shellbags_timestamp(first_value(row, ["LastWriteTime", "LastWriteTimestamp"]))
    created = parse_shellbags_timestamp(first_value(row, ["CreatedOn", "CreationTime"]))
    modified = parse_shellbags_timestamp(first_value(row, ["ModifiedOn", "ModifiedTime"]))
    accessed = parse_shellbags_timestamp(first_value(row, ["AccessedOn", "AccessedTime"]))
    first_interacted = parse_shellbags_timestamp(first_value(row, ["FirstInteracted"]))
    last_interacted = parse_shellbags_timestamp(first_value(row, ["LastInteracted"]))
    extension_block = _clean_placeholder(first_value(row, ["ExtensionBlock"]))
    sid = _clean_placeholder(first_value(row, ["SID"]))
    user_name = _clean_placeholder(first_value(row, ["User", "UserName", "HiveOwner"])) or infer_user_from_windows_path(_clean_placeholder(first_value(row, ["ProfilePath"])) or source_file or hive_path or folder_path)
    timestamp = last_interacted or first_interacted or last_write or modified or accessed or created
    timestamp_precision = (
        "shellbag_last_interacted" if last_interacted
        else "shellbag_first_interacted" if first_interacted
        else "registry_key_last_write" if last_write
        else "shell_item_modified" if modified
        else "shell_item_accessed" if accessed
        else "shell_item_created" if created
        else "unknown"
    )
    path_meta = classify_shellbag_path(folder_path, row)
    file_name = basename_windows(folder_path)
    document["@timestamp"] = timestamp or document.get("@timestamp")
    document["timestamp_precision"] = timestamp_precision
    document["timezone"] = "UTC" if timestamp else document.get("timezone", "unknown")
    document["event"].update(
        {
            "category": "file_access",
            "type": "shellbag_folder_access",
            "action": "shellbag_folder_observed",
            "severity": "medium" if "suspicious" in set(path_meta["tags"]) else "info",
            "message": f"Shellbag folder observed: {folder_path or bag_path or 'unknown'}",
        }
    )
    document["file"].update(
        {
            "path": folder_path,
            "name": file_name,
            "extension": None,
            "is_directory": True,
        }
    )
    document["shellbag"].update(
        {
            "artifact_type": path_meta["artifact_type"],
            "path": folder_path,
            "bag_path": bag_path,
            "absolute_path": folder_path,
            "shell_type": shell_type,
            "slot": slot,
            "node_slot": node_slot,
            "mru_position": mru_position,
            "mru": mru_position,
            "last_write_time": last_write,
            "last_write": last_write,
            "created": created,
            "modified": modified,
            "accessed": accessed,
            "first_interacted": first_interacted,
            "last_interacted": last_interacted,
            "mft_entry": _clean_placeholder(first_value(row, ["MFTEntry", "MFTEntryNumber"])),
            "mft_sequence": _clean_placeholder(first_value(row, ["MFTSequenceNumber"])),
            "extension_block": extension_block,
            "source_file": source_file,
            "hive_path": hive_path,
            "key_path": key_path,
            "is_deleted": path_meta["is_deleted"],
            "is_network_path": path_meta["is_network_path"],
            "is_usb_path": path_meta["is_usb_path"],
            "is_control_panel": path_meta["is_control_panel"],
        }
    )
    if path_meta["is_network_path"]:
        document["network"].update(
            {
                "path": folder_path,
                "share_name": path_meta["share_name"],
                "destination_hostname": path_meta["network_host"],
            }
        )
    if path_meta["is_usb_path"] and path_meta["drive_type"]:
        document["volume"]["drive_type"] = path_meta["drive_type"]
    if sid:
        document["user"]["sid"] = sid
    if user_name:
        document["user"]["name"] = user_name
    elif not document["user"].get("name"):
        document["user"]["name"] = extract_user(row, {"artifact_type": "shellbags", **artifact_meta})
    if not folder_path:
        document["data_quality"] = sorted(set(document.get("data_quality", [])) | {"missing_shellbag_path"})
    document["tags"] = sorted(set(document.get("tags", [])) | set(path_meta["tags"]))
    document["suspicious_reasons"] = sorted(set(document.get("suspicious_reasons", [])) | set(path_meta["reasons"]))
    document["risk_score"] = max(int(document.get("risk_score") or 0), int(path_meta["risk"]))
    return document


def normalize_recycle_bin_row(document: dict, row: dict, artifact_meta: dict) -> dict:
    from app.ingest.identity_extraction import normalize_hostname
    from app.ingest.recycle_bin.helpers import basename, extension, infer_drive_letter, is_valid_windows_original_path, normalize_windows_path, suspicious_recycle_markers

    original_path = normalize_windows_path(first_value(row, ["OriginalPath", "Path", "FullPath"]))
    if original_path and not is_valid_windows_original_path(original_path):
        original_path = None
    original_name = first_value(row, ["OriginalFileName", "FileName", "Name"]) or basename(original_path)
    if original_path:
        original_name = basename(original_path) or original_name
    deleted_time = _parse_iso_timestamp(first_value(row, ["DeletedOn", "DeletionTime", "DeletedTime", "$I Created"]))
    size_value = _clean_placeholder(first_value(row, ["OriginalSize", "FileSize", "Size"]))
    sid = _clean_placeholder(first_value(row, ["SID", "Sid"]))
    user_name = _clean_placeholder(first_value(row, ["User"]))
    source_file = _normalize_windowsish_path(first_value(row, ["SourceFile"])) or _clean_placeholder(str(artifact_meta.get("source_path") or ""))
    i_path = _normalize_windowsish_path(first_value(row, ["IPath", "$I"]))
    r_path = _normalize_windowsish_path(first_value(row, ["RPath", "$R"]))
    has_i_file = _boolish(first_value(row, ["HasMetadataFile", "HasIFile"]))
    if has_i_file is None:
        has_i_file = bool(i_path)
    has_r_file = _boolish(first_value(row, ["HasContentFile", "HasRFile"])) if first_value(row, ["HasContentFile", "HasRFile"]) is not None else bool(r_path)
    if has_r_file is None:
        has_r_file = bool(r_path)
    content_status = _clean_placeholder(first_value(row, ["ContentStatus"]))
    recycle_record_type = _clean_placeholder(first_value(row, ["ArtifactType"])) or ("recycle_pair" if has_r_file else "recycle_i_file")
    parser_name = str(artifact_meta.get("parser") or "").lower()
    normalized_parser = (
        "recycle_bin_raw" if parser_name in {"raw_i_file", "raw_r_file", "generic"}
        else "recycle_bin_csv" if parser_name in {"rbcmd", "csv"}
        else "recycle_bin_jsonl" if parser_name == "jsonl"
        else "recycle_bin_json" if parser_name == "json"
        else "recycle_bin_raw" if source_file and any(token in source_file.lower() for token in ["\\$recycle.bin\\", "/$recycle.bin/"])
        else "recycle_bin_csv"
    )
    drive_letter = _clean_placeholder(first_value(row, ["DriveLetter", "Drive"])) or infer_drive_letter(original_path)
    tags, reasons, risk = suspicious_recycle_markers(original_path, bool(has_r_file), file_name=original_name)
    if content_status == "content_missing_confirmed":
        tags.add("content_missing")
    if not original_path:
        reasons = [reason for reason in reasons if "recycled content file is missing" not in reason.lower()]

    document["artifact"].update(
        {
            "type": "recycle_bin",
            "parser": normalized_parser,
            "source_path": source_file or document.get("source_file"),
            "name": f"Recycle Bin - {original_name or 'unknown'}",
        }
    )
    document["@timestamp"] = deleted_time or document.get("@timestamp")
    document["timestamp_precision"] = "recycle_deleted_time" if deleted_time else "unknown"
    document["timezone"] = "UTC" if deleted_time else document.get("timezone", "unknown")
    document["event"].update(
        {
            "category": "file",
            "type": "file_deleted" if original_path else "recycle_metadata_observed",
            "action": "recycle_bin_deleted" if original_path else "recycle_metadata_observed",
            "severity": "medium" if "suspicious" in tags else "info",
            "message": (
                f"Recycle Bin deletion observed: {original_path or original_name or 'unknown'}"
                if original_path
                else "Recycle Bin metadata observed but original path could not be parsed"
            ),
            "timeline_include": True,
        }
    )
    document["file"].update(
        {
            "path": original_path,
            "name": original_name,
            "extension": extension(original_path or original_name),
            "size": int(size_value) if size_value and str(size_value).isdigit() else size_value,
            "deleted_time": deleted_time,
            "deleted": deleted_time,
            "is_directory": _boolish(first_value(row, ["IsDirectory"])),
            "source_path": source_file,
        }
    )
    document["volume"].update({"drive_letter": drive_letter, "drive_type": "removable" if drive_letter else document.get("volume", {}).get("drive_type")})
    document["recycle_bin"] = {
        "original_path": original_path,
        "deleted_time": deleted_time,
        "recovery_name": first_value(row, ["RecoveryName", "DeletedFileName", "$R"]) or basename(r_path),
    }
    document["recycle"] = {
        "artifact_type": "recycle_bin",
        "record_type": recycle_record_type,
        "sid": sid,
        "user": user_name,
        "original_path": original_path,
        "original_file_name": original_name,
        "original_size": int(size_value) if size_value and str(size_value).isdigit() else size_value,
        "deleted_time": deleted_time,
        "i_file_path": i_path,
        "r_file_path": r_path,
        "has_i_file": bool(has_i_file),
        "has_r_file": bool(has_r_file),
        "pair_id": _clean_placeholder(first_value(row, ["PairId"])),
        "version": _clean_placeholder(first_value(row, ["Version"])),
        "drive_letter": drive_letter,
        "source_file": source_file,
        "content_status": content_status,
    }
    if str(artifact_meta.get("source_tool") or "").lower() == "recycle_bin_raw":
        source_file_path = _clean_placeholder(first_value(row, ["SourceFile"])) or str(artifact_meta.get("source_path") or "")
        document["velociraptor"].update(
            {
                "original_path": str(artifact_meta.get("velociraptor_original_path") or source_file_path or ""),
                "normalized_windows_path": str(artifact_meta.get("velociraptor_normalized_windows_path") or source_file_path or ""),
                "artifact_category": "recycle_bin",
                "parser_status": "parsed",
                "collection_id": artifact_meta.get("velociraptor_collection_id") or document.get("evidence_id"),
            }
        )
    if sid:
        document["user"]["sid"] = sid
    if user_name:
        document["user"]["name"] = user_name
    elif original_path and not document["user"].get("name"):
        document["user"]["name"] = extract_user_from_path(original_path)
    data_quality = set(document.get("data_quality", []))
    if sid and not document["user"].get("name"):
        data_quality.add("missing_user")
    if not sid:
        data_quality.add("missing_sid")
    if not deleted_time:
        data_quality.add("missing_timestamp")
    if not original_path:
        data_quality.update({"missing_original_path", "invalid_recycle_original_path"})
    if size_value in (None, ""):
        data_quality.add("missing_original_size")
    if not has_i_file:
        data_quality.update({"recycle_pair_incomplete", "missing_info_file"})
        reasons.append("Recycle Bin pair missing $I metadata")
    if not has_r_file:
        data_quality.update({"recycle_pair_incomplete", "missing_recovery_file"})
    existing_host_name = str((document.get("host") or {}).get("name") or "")
    if not normalize_hostname(existing_host_name):
        document["host"]["name"] = None
        data_quality.add("missing_host")
        if source_file and basename(source_file) and existing_host_name.lower() == str(basename(source_file) or "").lower():
            data_quality.add("host_name_not_inferred_from_filename")
    document["data_quality"] = sorted(data_quality)
    document["tags"] = sorted(set(document.get("tags", [])) | tags)
    document["suspicious_reasons"] = sorted(set(document.get("suspicious_reasons", [])) | set(reasons))
    document["risk_score"] = max(int(document.get("risk_score") or 0), risk)
    document["_preserve_risk_score"] = True
    document["source_file"] = source_file or document.get("source_file")
    document["execution"].update(
        {
            "source": "recycle_bin",
            "is_execution_confirmed": False,
            "confidence": "low",
            "interpretation": "Recycle Bin artifacts indicate deletion to the recycle bin, not execution by itself",
        }
    )
    return document


def normalize_srum_row(document: dict, row: dict, artifact_meta: dict) -> dict:
    from app.ingest.identity_extraction import normalize_hostname

    artifact_type = _srum_artifact_type(row, artifact_meta)
    table_name = _clean_placeholder(first_value(row, ["Table", "Provider", "Description"]))
    application = _select_srum_application(row)
    user_sid = _clean_placeholder(first_value(row, ["UserSid", "UserSID", "SID"]))
    user_name = _clean_placeholder(first_value(row, ["UserName"]))
    process_path = application["process_path"]
    process_name = application["process_name"]
    display_name = application["display_name"] or "unknown application"
    file_name = _appcompat_basename(process_path) or process_name
    file_extension = _appcompat_extension(process_path or file_name)

    foreground_sent = _normalize_int_bytes(first_value(row, ["ForegroundBytesSent"]))
    foreground_received = _normalize_int_bytes(first_value(row, ["ForegroundBytesReceived"]))
    background_sent = _normalize_int_bytes(first_value(row, ["BackgroundBytesSent"]))
    background_received = _normalize_int_bytes(first_value(row, ["BackgroundBytesReceived"]))
    bytes_sent = _normalize_int_bytes(first_value(row, ["BytesSent", "SendBytes"]))
    if bytes_sent is None:
        bytes_sent = _sum_bytes(foreground_sent, background_sent)
    bytes_received = _normalize_int_bytes(first_value(row, ["BytesReceived", "ReceiveBytes"]))
    if bytes_received is None:
        bytes_received = _sum_bytes(foreground_received, background_received)
    bytes_total = _normalize_int_bytes(first_value(row, ["BytesTotal", "TotalBytes"]))
    if bytes_total is None:
        bytes_total = _sum_bytes(bytes_sent, bytes_received)

    timestamp = None
    timestamp_precision = "unknown"
    for candidate, precision in _srum_timestamp_candidates(row):
        if candidate:
            timestamp = candidate
            timestamp_precision = precision
            break

    start_time = _parse_srum_timestamp(first_value(row, ["StartTime"]))
    end_time = _parse_srum_timestamp(first_value(row, ["EndTime"]))
    duration_value = _safe_int(first_value(row, ["Duration"]))
    connected_time = _parse_srum_timestamp(first_value(row, ["ConnectedTime"]))
    energy_usage = _clean_placeholder(first_value(row, ["EnergyUsage"]))
    cycle_time = _clean_placeholder(first_value(row, ["CycleTime"]))
    interface_profile = _clean_placeholder(first_value(row, ["InterfaceProfile"]))
    network_profile = _clean_placeholder(first_value(row, ["NetworkProfile"])) or interface_profile
    interface_guid = _clean_placeholder(first_value(row, ["InterfaceGuid"]))
    interface_luid = _clean_placeholder(first_value(row, ["InterfaceLuid"]))
    package_name = application["package_name"]
    source_file = _normalize_windowsish_path(first_value(row, ["SourceFile"])) or _clean_placeholder(str(artifact_meta.get("source_path") or ""))
    direction = _srum_direction(bytes_sent, bytes_received)
    network_artifact_type = artifact_type if artifact_type in {"srum_network_usage", "srum_network_connectivity"} else "srum_network_usage"

    document["@timestamp"] = timestamp
    document["timestamp_precision"] = timestamp_precision
    document["timezone"] = "UTC" if timestamp else "unknown"
    document["user"]["sid"] = user_sid or document["user"].get("sid")
    if user_name:
        document["user"]["name"] = user_name
    elif process_path and not document["user"].get("name"):
        document["user"]["name"] = extract_user_from_path(process_path)

    existing_host_name = str((document.get("host") or {}).get("name") or "")
    if not normalize_hostname(existing_host_name):
        document["host"]["name"] = None

    document["file"].update(
        {
            "path": process_path,
            "name": file_name,
            "extension": file_extension,
        }
    )
    document["process"].update(
        {
            "name": process_name,
            "path": process_path,
            "application": application["app_name"] or application["app_id"] or package_name,
        }
    )
    document["network"].update(
        {
            "artifact_type": network_artifact_type,
            "bytes_sent": bytes_sent,
            "bytes_received": bytes_received,
            "bytes_total": bytes_total,
            "application": display_name,
            "interface_guid": interface_guid,
            "interface": interface_guid or interface_luid,
            "interface_profile": interface_profile,
            "profile": network_profile,
            "network_profile": network_profile,
            "direction": direction,
        }
    )
    document["srum"].update(
        {
            "artifact_type": artifact_type,
            "table": table_name,
            "application": display_name,
            "app_id": application["app_id"],
            "app_name": application["app_name"],
            "package_name": package_name,
            "user_sid": user_sid,
            "interface_luid": interface_luid,
            "interface_guid": interface_guid,
            "interface_profile": interface_profile,
            "network_profile": network_profile,
            "bytes_sent": bytes_sent,
            "bytes_received": bytes_received,
            "bytes_total": bytes_total,
            "foreground_bytes_sent": foreground_sent,
            "foreground_bytes_received": foreground_received,
            "background_bytes_sent": background_sent,
            "background_bytes_received": background_received,
            "connected_time": connected_time,
            "duration": duration_value,
            "energy_usage": energy_usage,
            "cycle_time": cycle_time,
            "start_time": start_time,
            "end_time": end_time,
            "source_file": source_file,
        }
    )

    if artifact_type == "srum_network_usage":
        document["event"].update(
            {
                "category": "network",
                "type": "network_usage",
                "action": "srum_network_usage_observed",
                "severity": "info",
                "message": f"SRUM network usage observed: {display_name} sent={bytes_sent or 0} received={bytes_received or 0}",
                "timeline_include": True,
            }
        )
    elif artifact_type == "srum_network_connectivity":
        document["event"].update(
            {
                "category": "network",
                "type": "network_connectivity_observed",
                "action": "srum_network_connectivity_observed",
                "severity": "info",
                "message": f"SRUM network connectivity observed: {network_profile or interface_profile or interface_guid or 'unknown profile'}",
                "timeline_include": True,
            }
        )
    elif artifact_type == "srum_app_resource":
        summary = f"SRUM application usage: {display_name}"
        if bytes_total is not None:
            summary = f"{summary} ({_format_bytes_for_summary(bytes_total)})"
        document["event"].update(
            {
                "category": "network",
                "type": "app_resource_usage",
                "action": "srum_app_resource_usage_observed",
                "severity": "info",
                "message": summary,
                "timeline_include": True,
            }
        )
    elif artifact_type == "srum_energy":
        document["event"].update(
            {
                "category": "network",
                "type": "energy_usage",
                "action": "srum_energy_usage_observed",
                "severity": "info",
                "message": f"SRUM energy usage: {display_name}",
                "timeline_include": True,
            }
        )
    else:
        document["event"].update(
            {
                "category": "network",
                "type": "srum_record",
                "action": "srum_observed",
                "severity": "info",
                "message": f"SRUM record: {display_name}",
                "timeline_include": True,
            }
        )
    tags, reasons, derived_quality, risk_score = _derive_srum_risk_and_reasons(
        display_name=display_name,
        process_path=process_path,
        process_name=process_name,
        app_id=application["app_id"],
        app_name=application["app_name"],
        bytes_sent=bytes_sent,
        bytes_received=bytes_received,
        artifact_type=artifact_type,
    )
    data_quality = set(document.get("data_quality", []))
    if not timestamp:
        data_quality.add("missing_timestamp")
    if not display_name or display_name.lower() in {"unknown", "unknown application"}:
        data_quality.add("missing_application")
    if not user_sid and not document["user"].get("name"):
        data_quality.add("missing_user")
    if not interface_guid and not interface_luid and not interface_profile and not network_profile:
        data_quality.add("missing_interface")
    if not normalize_hostname(existing_host_name):
        data_quality.add("missing_host")
        if source_file and _appcompat_basename(source_file) and existing_host_name.lower() == str(_appcompat_basename(source_file) or "").lower():
            data_quality.add("host_name_not_inferred_from_filename")
    data_quality.update(derived_quality)
    document["data_quality"] = sorted(data_quality)
    document["tags"] = sorted(set(document.get("tags", [])) | tags)
    document["suspicious_reasons"] = sorted(set(document.get("suspicious_reasons", [])) | reasons)
    document["risk_score"] = max(int(document.get("risk_score") or 0), risk_score)
    document["_preserve_risk_score"] = True
    document["source_file"] = source_file or document.get("source_file")
    document["execution"].update(
        {
            "source": "srum",
            "is_execution_confirmed": False,
            "confidence": "low",
            "interpretation": "SRUM indicates resource/network usage attributed to an application, not process execution by itself",
        }
    )
    return document


def normalize_browser_row(document: dict, row: dict, artifact_meta: dict) -> dict:
    return normalize_browser_event(document, row, artifact_meta)


def normalize_registry_row(document: dict, row: dict, artifact_meta: dict) -> dict:
    key_path = first_value(row, ["KeyPath", "Path"])
    document["event"].update({"category": "registry", "type": "registry_value", "message": f"Registry entry: {key_path or 'unknown'}"})
    document["registry"] = {
        "hive": first_value(row, ["Hive"]),
        "key_path": key_path,
        "value_name": first_value(row, ["ValueName", "Value"]),
        "value_data": first_value(row, ["ValueData", "Data"]),
        "last_write": first_value(row, ["LastWriteTime", "LastWrite"]),
    }
    return document


def normalize_process_row(document: dict, row: dict, artifact_meta: dict) -> dict:
    process_name = first_value(row, ["Name", "ProcessName", "ImageName"])
    pid = first_value(row, ["Pid", "PID"])
    document["event"].update({"category": "execution", "type": "process_observed", "message": f"Process observed: {process_name or 'unknown'} ({pid or '?'})"})
    document["process"].update({"name": process_name, "pid": pid, "ppid": first_value(row, ["PPid", "ParentPid"]), "command_line": first_value(row, ["CommandLine"]), "path": first_value(row, ["Path", "ImagePath"])})
    return document


def normalize_network_row(document: dict, row: dict, artifact_meta: dict) -> dict:
    src = first_value(row, ["LocalAddress", "SourceIP", "SrcIP"])
    dst = first_value(row, ["RemoteAddress", "DestinationIP", "DstIP"])
    document["event"].update({"category": "network", "type": "network_connection", "message": f"Network connection: {src or '?'} -> {dst or '?'}"})
    document["network"].update({"source_ip": src, "source_port": first_value(row, ["LocalPort", "SourcePort"]), "destination_ip": dst, "destination_port": first_value(row, ["RemotePort", "DestinationPort"]), "protocol": first_value(row, ["Protocol"]), "domain": first_value(row, ["Domain"]), "url": first_value(row, ["URL", "Url"])})
    document["process"].update({"name": first_value(row, ["ProcessName", "Name"]), "pid": first_value(row, ["PID", "Pid"])})
    return document


def normalize_generic_row(document: dict, row: dict, artifact_meta: dict) -> dict:
    document["event"].update({"category": "unknown", "type": "generic_record", "message": first_value(row, ["Message", "Description", "Path", "Name"]) or artifact_meta["name"]})
    return document
