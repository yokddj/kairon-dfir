from __future__ import annotations

from datetime import datetime
import re
from typing import Any


REGISTRY_COMMAND_ARTIFACT_TYPE = "registry_command"
REGISTRY_EVENT_ARTIFACT_TYPE = "registry_event"
REGISTRY_ROOT_RE = re.compile(r"(?i)\b(?:HKLM|HKCU|HKU|HKCR|HKCC|HKEY_LOCAL_MACHINE|HKEY_CURRENT_USER|HKEY_USERS|HKEY_CLASSES_ROOT|HKEY_CURRENT_CONFIG|Registry::HKEY_LOCAL_MACHINE|Registry::HKEY_CURRENT_USER)[:\\][^\r\n\"']+")
REG_ADD_DELETE_RE = re.compile(r"(?i)(?:^|\s)(?:reg(?:\.exe)?\s+)?(add|delete|import|load|unload|save|restore|copy|query)\b")
POWERSHELL_REGISTRY_RE = re.compile(r"(?i)\b(Set-ItemProperty|New-ItemProperty|Remove-ItemProperty|New-Item|Remove-Item|Rename-ItemProperty)\b")


def normalize_registry_modification_event(document: dict[str, Any]) -> dict[str, Any]:
    """Normalize observed registry modification telemetry without fabricating events."""
    windows = _obj(document.get("windows"))
    event_id = _to_int(windows.get("event_id") or document.get("event_id"))
    winlog = _obj(document.get("winlog"))
    provider = str(_obj(document.get("event")).get("provider") or windows.get("provider") or winlog.get("provider_name") or "").lower()
    if event_id in {12, 13, 14} and "sysmon" in provider:
        return _normalize_sysmon_registry_event(document, event_id)
    if event_id == 4657:
        return _normalize_security_4657(document)
    return document


def enrich_registry_command_document(document: dict[str, Any]) -> dict[str, Any]:
    """Expose command evidence as a derived display contract while preserving raw event fields."""
    process = _obj(document.get("process"))
    powershell = _obj(document.get("powershell"))
    candidates = [
        process.get("command_line"),
        powershell.get("command"),
        powershell.get("command_preview"),
        _obj(document.get("event")).get("message"),
        document.get("search_text"),
        document.get("key_entity"),
    ]
    evidence = None
    command = ""
    for candidate in candidates:
        evidence = detect_registry_command(candidate)
        if evidence:
            command = _clean(candidate)
            break
    if not evidence:
        return document
    original_artifact = dict(_obj(document.get("artifact")))
    raw = document.get("raw") if isinstance(document.get("raw"), dict) else {}
    raw.setdefault("original_artifact", original_artifact)
    document["raw"] = raw
    document["artifact"] = {**original_artifact, "type": REGISTRY_COMMAND_ARTIFACT_TYPE, "parser": original_artifact.get("parser") or "runtime_registry_command"}
    document["registry_command"] = evidence
    document["registry"] = {
        **_obj(document.get("registry")),
        "path": evidence.get("registry_path"),
        "key_path": evidence.get("registry_path"),
        "action": evidence.get("operation"),
        "confidence": "command_evidence",
    }
    event = document.setdefault("event", {})
    event["type"] = "registry_command"
    event["action"] = f"registry_command_{evidence.get('operation') or 'unknown'}"
    event["category"] = "registry"
    event["confidence"] = "command_evidence"
    event["message"] = f"Registry command evidence: {evidence.get('operation') or 'unknown'} {evidence.get('registry_path') or ''}".strip()
    event["timeline_include"] = bool(document.get("@timestamp"))
    document["key_entity"] = evidence.get("registry_path") or command
    document["key_entity_type"] = "registry_path"
    document["snippet"] = "Registry command evidence, not a confirmed registry event"
    existing_quality = document.get("data_quality") if isinstance(document.get("data_quality"), list) else []
    document["data_quality"] = sorted(set(existing_quality) | {"registry_command_not_confirmed_without_registry_event"})
    return document


def detect_registry_command(command: Any) -> dict[str, Any] | None:
    text = _clean(command)
    if not text:
        return None
    operation = ""
    match = REG_ADD_DELETE_RE.search(text)
    ps_match = POWERSHELL_REGISTRY_RE.search(text)
    if match:
        operation = _normalize_operation(match.group(1))
    elif ps_match:
        operation = _normalize_powershell_operation(ps_match.group(1))
    else:
        return None
    path = extract_registry_path(text)
    if not path:
        return None
    return {
        "command_line": text,
        "registry_path": path,
        "operation": operation or "unknown",
        "confidence": "command_evidence",
        "confirmed_by_registry_event": False,
        "linked_registry_event_ids": [],
        "key_entity": path or text,
        "snippet": "Possible registry modification command",
    }


def correlate_registry_commands(commands: list[dict[str, Any]], registry_events: list[dict[str, Any]], *, window_seconds: int = 30) -> list[dict[str, Any]]:
    for command in commands:
        evidence = _obj(command.get("registry_command"))
        if not evidence:
            continue
        command_path = _norm_path(evidence.get("registry_path"))
        command_time = _parse_time(command.get("timestamp"))
        command_host = str(command.get("host") or "").lower()
        proc_guid = str(_obj(command.get("process")).get("guid") or "").lower()
        matches: list[str] = []
        for event in registry_events:
            registry = _obj(event.get("registry"))
            event_path = _norm_path(registry.get("target_object") or registry.get("path") or registry.get("key_path"))
            if command_path and event_path and command_path not in event_path and event_path not in command_path:
                continue
            event_host = str(_first(_obj(event.get("host")).get("name"), event.get("host")) or "").lower()
            if command_host and event_host and command_host != event_host:
                continue
            event_guid = str(_obj(event.get("process")).get("guid") or _obj(event.get("process")).get("entity_id") or "").lower()
            if proc_guid and event_guid and proc_guid != event_guid:
                continue
            event_time = _parse_time(event.get("@timestamp") or event.get("timestamp"))
            if command_time and event_time and abs((command_time - event_time).total_seconds()) > window_seconds:
                continue
            event_id = str(event.get("id") or event.get("event_id") or event.get("stable_event_id") or "")
            if event_id:
                matches.append(event_id)
        if matches:
            evidence["confirmed_by_registry_event"] = True
            evidence["linked_registry_event_ids"] = sorted(set(matches))
            command["registry_command"] = evidence
    return commands


def extract_registry_path(text: Any) -> str:
    value = _clean(text)
    value = (
        value.replace("\\REGISTRY\\MACHINE\\", "HKLM\\")
        .replace("\\Registry\\Machine\\", "HKLM\\")
        .replace("\\REGISTRY\\USER\\", "HKU\\")
        .replace("\\Registry\\User\\", "HKU\\")
    )
    match = REGISTRY_ROOT_RE.search(value)
    if not match:
        return ""
    path = match.group(0).strip(" ,;\"'")
    return path.replace("Registry::HKEY_LOCAL_MACHINE", "HKLM").replace("Registry::HKEY_CURRENT_USER", "HKCU").replace("HKEY_LOCAL_MACHINE", "HKLM").replace("HKEY_CURRENT_USER", "HKCU").replace("HKEY_USERS", "HKU").replace("HKEY_CLASSES_ROOT", "HKCR").replace("HKEY_CURRENT_CONFIG", "HKCC")


def _normalize_sysmon_registry_event(document: dict[str, Any], event_id: int) -> dict[str, Any]:
    event_data = _event_data(document)
    target = _first(event_data.get("TargetObject"), _obj(document.get("registry")).get("path"), _obj(document.get("registry")).get("key_path"), document.get("key_entity"))
    details = _first(event_data.get("Details"), _obj(document.get("registry")).get("value_data"), _obj(document.get("registry")).get("data"))
    event_type_raw = str(_first(event_data.get("EventType"), _obj(document.get("registry")).get("event_type")) or "")
    action, event_type = _sysmon_action(event_id, event_type_raw)
    registry = _registry_parts(target)
    registry.update(
        {
            "target_object": target,
            "value_data": details,
            "details": details,
            "action": action,
            "confidence": "observed_event",
            "source": "sysmon",
        }
    )
    document["registry"] = {**_obj(document.get("registry")), **registry}
    artifact = document.setdefault("artifact", {})
    artifact["type"] = REGISTRY_EVENT_ARTIFACT_TYPE
    artifact["parser"] = artifact.get("parser") or "sysmon_registry"
    event = document.setdefault("event", {})
    event["type"] = event_type
    event["action"] = f"registry_{action}"
    event["category"] = "registry"
    event["confidence"] = "observed_event"
    event["message"] = f"Registry modification event ({action}): {target or 'unknown'}"
    event["timeline_include"] = bool(document.get("@timestamp"))
    document["key_entity"] = target or event_type
    document["key_entity_type"] = "registry_path"
    document["snippet"] = f"Observed registry {action}: {target or 'unknown'}"
    return document


def _normalize_security_4657(document: dict[str, Any]) -> dict[str, Any]:
    event_data = _event_data(document)
    object_name = _first(event_data.get("ObjectName"), _obj(document.get("registry")).get("path"), _obj(document.get("registry")).get("key_path"), document.get("key_entity"))
    value_name = _first(event_data.get("ObjectValueName"), _obj(document.get("registry")).get("value_name"))
    target = "\\".join(part for part in [object_name, value_name] if part)
    old_value = _first(event_data.get("OldValue"), event_data.get("OldValueType"))
    new_value = _first(event_data.get("NewValue"), event_data.get("NewValueType"))
    registry = _registry_parts(target or object_name)
    registry.update(
        {
            "target_object": target or object_name,
            "value_name": value_name or registry.get("value_name"),
            "old_value": old_value,
            "new_value": new_value,
            "value_data": new_value,
            "action": "modified",
            "confidence": "observed_event",
            "source": "security",
        }
    )
    document["registry"] = {**_obj(document.get("registry")), **registry}
    artifact = document.setdefault("artifact", {})
    artifact["type"] = REGISTRY_EVENT_ARTIFACT_TYPE
    artifact["parser"] = artifact.get("parser") or "security_registry"
    event = document.setdefault("event", {})
    event["type"] = "registry_value_modified"
    event["action"] = "registry_modified"
    event["category"] = "registry"
    event["confidence"] = "observed_event"
    event["message"] = f"Registry value modified: {target or object_name or 'unknown'}"
    event["timeline_include"] = bool(document.get("@timestamp"))
    document["key_entity"] = target or object_name or "registry_value_modified"
    document["key_entity_type"] = "registry_path"
    document["snippet"] = f"Observed registry value modified: {target or object_name or 'unknown'}"
    return document


def _sysmon_action(event_id: int, event_type: str) -> tuple[str, str]:
    lowered = event_type.lower()
    if event_id == 13:
        return "set", "registry_value_set"
    if event_id == 14:
        return "renamed", "registry_object_renamed"
    if "delete" in lowered:
        return "deleted", "registry_key_deleted"
    if "create" in lowered:
        return "created", "registry_key_created"
    return "unknown", "registry_key_created_or_deleted"


def _registry_parts(path: Any) -> dict[str, Any]:
    text = extract_registry_path(path) or _clean(path)
    root = "unknown"
    remainder = text
    for candidate in ("HKLM", "HKCU", "HKU", "HKCR", "HKCC"):
        if text.upper().startswith(candidate):
            root = candidate
            remainder = text[len(candidate):].lstrip(":\\")
            break
    value_name = ""
    key_path = text
    if "\\" in text:
        key_path, value_name = text.rsplit("\\", 1)
    return {"registry_root": root, "root_key": root, "key_path": key_path, "path": text, "value_name": value_name}


def _event_data(document: dict[str, Any]) -> dict[str, Any]:
    windows = _obj(document.get("windows"))
    event_data = _obj(windows.get("event_data"))
    return event_data or _obj(document.get("winlog")).get("event_data") or {}


def _normalize_operation(value: str) -> str:
    lowered = str(value or "").lower()
    return {"add": "add", "delete": "delete", "import": "import", "load": "load", "unload": "unload", "save": "save", "restore": "restore", "copy": "copy", "query": "query"}.get(lowered, "unknown")


def _normalize_powershell_operation(value: str) -> str:
    lowered = str(value or "").lower()
    if lowered.startswith("set-"):
        return "set"
    if lowered.startswith("new-"):
        return "add"
    if lowered.startswith("remove-"):
        return "delete"
    if lowered.startswith("rename-"):
        return "renamed"
    return "unknown"


def _parse_time(value: Any) -> datetime | None:
    if isinstance(value, datetime):
        return value
    if not value:
        return None
    try:
        text = str(value).replace("Z", "+00:00")
        return datetime.fromisoformat(text)
    except Exception:
        return None


def _norm_path(value: Any) -> str:
    return re.sub(r"[^a-z0-9]+", "", _clean(value).lower())


def _to_int(value: Any) -> int | None:
    try:
        return int(str(value))
    except Exception:
        return None


def _obj(value: Any) -> dict[str, Any]:
    return value if isinstance(value, dict) else {}


def _first(*values: Any) -> str:
    for value in values:
        text = _clean(value)
        if text:
            return text
    return ""


def _clean(value: Any) -> str:
    return str(value or "").strip()
