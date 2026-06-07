from __future__ import annotations

import json
from pathlib import PureWindowsPath
import re
from typing import Any

from app.ingest.powershell.helpers import basename_windows, clean_text, infer_user_from_path


PLACEHOLDER_VALUES = {"", "-", "--", "0x", "0x0", "0x00", "0x00000000", "null", "none", "n/a"}
SYSTEM_SIDS = {"s-1-5-18", "s-1-5-19", "s-1-5-20"}
SYSTEM_USER_NAMES = {"system", "local service", "network service", "nt authority\\system"}
PAYLOAD_LABELS = (
    "UserId",
    "User",
    "UserName",
    "Connected User",
    "ConnectedUser",
    "RunAs User",
    "HostApplication",
    "CommandLine",
    "ScriptBlockText",
    "ScriptName",
    "CommandInvocation",
    "ParameterBinding",
    "EngineVersion",
    "RunspaceId",
    "PipelineId",
    "ProviderName",
    "HostName",
)


def normalize_powershell_entities(document: dict[str, Any]) -> dict[str, Any]:
    artifact = _obj(document.get("artifact"))
    powershell = _obj(document.get("powershell"))
    if str(artifact.get("type") or "").lower() != "powershell":
        return document

    payload_fields = extract_payload_fields(document)
    user_value, user_confidence = extract_user(document, payload_fields)
    user = document.setdefault("user", {})
    if user_value:
        user["name"] = user_value
        user["confidence"] = user_confidence
        powershell["user_confidence"] = user_confidence

    command = extract_command(document, payload_fields)
    if not command and (_looks_like_payload(powershell.get("command")) or _is_bad_value(powershell.get("command"))):
        command = clean_command_value(payload_fields.get("HostApplication")) or clean_command_value(_obj(document.get("process")).get("name"))
    if command:
        powershell["command"] = command
        powershell["command_preview"] = _preview(command)
        process = document.setdefault("process", {})
        if _is_bad_value(process.get("command_line")) or _looks_like_payload(process.get("command_line")):
            process["command_line"] = command

    for source, target in (
        ("ScriptBlockText", "script_block"),
        ("ScriptName", "script_path"),
        ("HostApplication", "host_application"),
        ("ProviderName", "provider_name"),
        ("EngineVersion", "engine_version"),
        ("RunspaceId", "runspace_id"),
        ("PipelineId", "pipeline_id"),
        ("CommandInvocation", "command_invocation"),
        ("ParameterBinding", "parameter_binding"),
    ):
        value = clean_entity_value(payload_fields.get(source))
        if value and _valid_field_value(target, value):
            powershell[target] = value

    raw_payload = extract_raw_payload(document)
    if raw_payload:
        powershell["raw_payload"] = raw_payload

    key_entity, key_entity_type = extract_key_entity(document, payload_fields)
    if key_entity:
        document["key_entity"] = key_entity
        document["key_entity_type"] = key_entity_type

    document["powershell"] = powershell
    return document


def extract_payload_fields(document: dict[str, Any]) -> dict[str, str]:
    fields: dict[str, str] = {}

    def add_field(key: object, value: object) -> None:
        canonical = _canonical_label(str(key))
        if not canonical:
            return
        text = clean_entity_value(value)
        if text:
            fields.setdefault(canonical, text)

    for source in _payload_sources(document):
        if isinstance(source, dict):
            for key, value in source.items():
                if isinstance(value, (dict, list)):
                    for nested_key, nested_value in _flatten_payload(value).items():
                        add_field(nested_key, nested_value)
                    continue
                text = clean_entity_value(value)
                if str(key).lower().startswith("payload") and text:
                    fields.update(_parse_payload_text(text))
                add_field(key, value)
        elif isinstance(source, str):
            fields.update(_parse_payload_text(source))
    return fields


def extract_user(document: dict[str, Any], payload_fields: dict[str, str] | None = None) -> tuple[str | None, str]:
    payload_fields = payload_fields or extract_payload_fields(document)
    user = _obj(document.get("user"))
    powershell = _obj(document.get("powershell"))
    windows = _obj(document.get("windows"))
    event_data = _obj(windows.get("event_data"))
    raw = _obj(document.get("raw"))
    explicit_candidates = [
        user.get("name"),
        user.get("user"),
        powershell.get("username"),
        powershell.get("run_as"),
        powershell.get("user"),
        event_data.get("User"),
        event_data.get("UserName"),
        event_data.get("AccountName"),
        event_data.get("SubjectUserName"),
        event_data.get("SecurityUserID"),
        raw.get("UserName"),
    ]
    for candidate in explicit_candidates:
        value = clean_user_value(candidate)
        if value:
            return value, "explicit"

    context_candidates = [
        payload_fields.get("UserId"),
        payload_fields.get("User"),
        payload_fields.get("UserName"),
        payload_fields.get("ConnectedUser"),
        payload_fields.get("Connected User"),
        payload_fields.get("RunAs User"),
    ]
    for candidate in context_candidates:
        value = clean_user_value(candidate)
        if value:
            return value, "context"

    for candidate in (
        powershell.get("script_path"),
        payload_fields.get("ScriptName"),
        powershell.get("source_file"),
        document.get("source_file"),
        _obj(document.get("file")).get("path"),
        powershell.get("command"),
        _obj(document.get("process")).get("command_line"),
    ):
        value = clean_user_value(infer_user_from_path(str(candidate or "")))
        if value:
            return value, "path_inferred"
    return None, "unknown"


def extract_command(document: dict[str, Any], payload_fields: dict[str, str] | None = None) -> str | None:
    payload_fields = payload_fields or extract_payload_fields(document)
    powershell = _obj(document.get("powershell"))
    process = _obj(document.get("process"))
    event = _obj(document.get("event"))
    candidates = [
        payload_fields.get("CommandLine"),
        payload_fields.get("ScriptBlockText"),
        powershell.get("script_block_text"),
        powershell.get("script_block"),
        payload_fields.get("CommandInvocation"),
        powershell.get("command_invocation"),
        powershell.get("command"),
        powershell.get("command_preview"),
        process.get("command_line"),
        payload_fields.get("HostApplication"),
        powershell.get("host_application"),
        event.get("message"),
    ]
    for candidate in candidates:
        value = clean_command_value(candidate)
        if value:
            return value
    return None


def extract_key_entity(document: dict[str, Any], payload_fields: dict[str, str] | None = None) -> tuple[str | None, str | None]:
    payload_fields = payload_fields or extract_payload_fields(document)
    powershell = _obj(document.get("powershell"))
    event_type = str(_obj(document.get("event")).get("type") or "").lower()
    command = extract_command(document, payload_fields)
    candidates: list[tuple[Any, str]] = []
    if event_type in {"command_observed", "pipeline_execution", "module_logging", "script_block"}:
        candidates.extend(
            [
                (payload_fields.get("ScriptName"), "script_path"),
                (powershell.get("script_path"), "script_path"),
                (command, "command"),
                (payload_fields.get("HostApplication"), "process"),
                (powershell.get("host_application"), "process"),
            ]
        )
    elif event_type in {"provider_lifecycle", "powershell_engine_lifecycle"}:
        candidates.extend(
            [
                (payload_fields.get("ProviderName"), "provider"),
                (powershell.get("provider_name"), "provider"),
                (payload_fields.get("HostApplication"), "process"),
                (powershell.get("host_application"), "process"),
                (payload_fields.get("EngineVersion"), "engine_version"),
                (powershell.get("engine_version"), "engine_version"),
            ]
        )
    candidates.extend(
        [
            (document.get("key_entity"), str(document.get("key_entity_type") or "entity")),
            (command, "command"),
            (_obj(document.get("process")).get("name"), "process"),
            (document.get("source_file"), "source_file"),
            (event_type or "powershell_event", "event_type"),
        ]
    )
    for candidate, entity_type in candidates:
        value = clean_key_entity(candidate)
        if value and entity_type == "script_path" and not _valid_field_value("script_path", value):
            continue
        if value:
            return _short_entity(value), entity_type
    return None, None


def extract_raw_payload(document: dict[str, Any]) -> str | None:
    parts: list[str] = []
    for source in _payload_sources(document):
        if isinstance(source, dict):
            payload = source.get("Payload") or source.get("payload")
            if payload:
                parts.append(str(payload))
            for key, value in source.items():
                if str(key).lower().startswith("payloaddata") and value:
                    parts.append(str(value))
        elif source:
            parts.append(str(source))
    output = "\n".join(dict.fromkeys(part.strip() for part in parts if part and part.strip()))
    return output or None


def clean_user_value(value: Any) -> str | None:
    text = clean_entity_value(value)
    if not text or _looks_like_payload(text) or _is_bad_value(text):
        return None
    lowered = text.lower()
    if lowered in SYSTEM_SIDS:
        return None
    if lowered in SYSTEM_USER_NAMES:
        return text
    if re.fullmatch(r"s-\d-\d+(?:-\d+){1,12}", lowered):
        return None
    if re.fullmatch(r"\{?[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}\}?", lowered):
        return None
    if "\\" in text:
        left, right = text.rsplit("\\", 1)
        if right and left and left.lower() not in {"windows", "microsoft"}:
            return text
    if len(text) > 128 or any(token in lowered for token in ("hostapplication", "scriptblocktext", "eventdata", "commandline=")):
        return None
    return text


def clean_command_value(value: Any) -> str | None:
    text = clean_entity_value(value)
    if not text or _is_bad_value(text) or _looks_like_payload(text):
        return None
    if text.lower().startswith("commandinvocation("):
        match = re.search(r'(?i)CommandInvocation\(([^)]+)\):\s*"?([^"\r\n]+)', text)
        if match:
            text = match.group(2) or match.group(1)
    return re.sub(r"\s+", " ", text).strip() or None


def clean_key_entity(value: Any) -> str | None:
    text = clean_entity_value(value)
    if not text or _is_bad_value(text) or _looks_like_payload(text):
        return None
    if re.fullmatch(r"(?i)[a-z][\w ]{0,32}\s*=", text):
        return None
    return re.sub(r"\s+", " ", text).strip() or None


def clean_entity_value(value: Any) -> str | None:
    if value is None:
        return None
    text = str(value).strip().strip("\x00")
    if len(text) >= 2 and text[0] == text[-1] and text[0] in {'"', "'"}:
        text = text[1:-1].strip()
    return text or None


def _payload_sources(document: dict[str, Any]) -> list[Any]:
    windows = _obj(document.get("windows"))
    event_data = _obj(windows.get("event_data"))
    raw = _obj(document.get("raw"))
    powershell = _obj(document.get("powershell"))
    return [
        event_data,
        event_data.get("payload_columns"),
        windows.get("payload"),
        raw,
        raw.get("Payload"),
        powershell.get("raw_payload"),
        powershell.get("command"),
        powershell.get("command_preview"),
    ]


def _parse_payload_text(value: str) -> dict[str, str]:
    text = value.strip()
    parsed_fields: dict[str, str] = {}
    if text.startswith("{") or text.startswith("["):
        try:
            parsed = json.loads(text)
        except Exception:  # noqa: BLE001
            parsed = None
        if parsed is not None:
            flattened = _flatten_payload(parsed)
            for key, item in flattened.items():
                if isinstance(item, (dict, list)):
                    continue
                clean = clean_entity_value(item)
                if clean:
                    parsed_fields[_canonical_label(key)] = clean
                    if key.lower() in {"data", "eventdata.data"}:
                        parsed_fields.update(_parse_payload_text(clean))
    for label in PAYLOAD_LABELS:
        pattern = rf"(?im)(?:^|[\n,;]\s*){re.escape(label)}\s*=\s*(.*?)(?=(?:\n|,\s*\w[\w ]{{1,32}}\s*=)|$)"
        match = re.search(pattern, text)
        if match:
            value_text = clean_entity_value(match.group(1).strip(" ,;\r"))
            if value_text:
                parsed_fields[_canonical_label(label)] = value_text
    invocation = re.search(r'(?i)CommandInvocation\(([^)]+)\):\s*"?([^"\r\n]+)', text)
    if invocation:
        parsed_fields.setdefault("CommandInvocation", invocation.group(2) or invocation.group(1))
    return parsed_fields


def _flatten_payload(value: Any, prefix: str = "") -> dict[str, Any]:
    output: dict[str, Any] = {}
    if isinstance(value, dict):
        name = value.get("@Name") or value.get("Name") or value.get("name")
        text = value.get("#text")
        if name and text is not None:
            output[str(name)] = text
        for key, item in value.items():
            child_key = f"{prefix}.{key}" if prefix else str(key)
            if key in {"@Name", "Name", "name", "#text"}:
                continue
            if isinstance(item, (dict, list)):
                output.update(_flatten_payload(item, child_key))
            else:
                output[child_key] = item
    elif isinstance(value, list):
        for item in value:
            output.update(_flatten_payload(item, prefix))
    return output


def _canonical_label(label: str) -> str:
    compact = re.sub(r"[^a-z0-9]+", "", label.lower())
    mapping = {
        "userid": "UserId",
        "user": "User",
        "username": "UserName",
        "connecteduser": "ConnectedUser",
        "runasuser": "RunAs User",
        "hostapplication": "HostApplication",
        "commandline": "CommandLine",
        "scriptblocktext": "ScriptBlockText",
        "scriptname": "ScriptName",
        "commandinvocation": "CommandInvocation",
        "parameterbinding": "ParameterBinding",
        "engineversion": "EngineVersion",
        "runspaceid": "RunspaceId",
        "pipelineid": "PipelineId",
        "providername": "ProviderName",
        "hostname": "HostName",
        "eventdatadata": "Data",
        "data": "Data",
    }
    return mapping.get(compact, label.strip())


def _is_bad_value(value: Any) -> bool:
    text = str(value or "").strip().lower()
    return text in PLACEHOLDER_VALUES or bool(re.fullmatch(r"0x[0-9a-f]{1,8}", text))


def _looks_like_payload(value: Any) -> bool:
    text = str(value or "").strip().lower()
    if not text:
        return False
    if "eventdata" in text or "payloaddata" in text or '""@name""' in text or '"@name"' in text:
        return True
    if text.startswith("{") and any(token in text for token in ("eventdata", "payloaddata", "hostapplication", "scriptblocktext")):
        return True
    return len(text) > 180 and any(token in text for token in ("hostapplication", "eventdata", "payloaddata", "scriptblocktext", "commandline="))


def _valid_field_value(field: str, value: str) -> bool:
    if _looks_like_payload(value) or _is_bad_value(value):
        return False
    if field == "script_path":
        return bool(re.search(r"(?i)(?:^|[a-z]:\\|\\\\).+\.(?:ps1|psm1|psd1)$", value.strip()))
    if field == "pipeline_id":
        return bool(re.fullmatch(r"\d+", value.strip()))
    if field == "runspace_id":
        return bool(re.fullmatch(r"\{?[0-9a-fA-F]{8}(?:-[0-9a-fA-F]{4}){3}-[0-9a-fA-F]{12}\}?", value.strip()))
    if field == "engine_version":
        return bool(re.fullmatch(r"\d+(?:\.\d+){1,4}", value.strip()))
    if field in {"command_invocation", "parameter_binding"} and re.search(r"(?i)\b(?:CommandLine|ScriptName|CommandPath|PipelineId)\s*=", value):
        return False
    return True


def _short_entity(value: str) -> str:
    text = value.strip()
    path_match = re.search(r"(?i)([a-z]:\\[^\r\n\"']+\.(?:ps1|psm1|psd1|exe|bat|cmd|js|vbs))", text)
    if path_match:
        return path_match.group(1)
    if len(text) <= 180:
        return text
    first_line = text.splitlines()[0].strip()
    if len(first_line) <= 180:
        return first_line
    try:
        name = PureWindowsPath(text.replace("/", "\\")).name
        if name and len(name) < len(text):
            return name
    except Exception:  # noqa: BLE001
        pass
    return basename_windows(text) or text[:177] + "..."


def _preview(value: str, limit: int = 240) -> str:
    text = re.sub(r"\s+", " ", value).strip()
    return text if len(text) <= limit else text[: limit - 3].rstrip() + "..."


def _obj(value: Any) -> dict[str, Any]:
    return value if isinstance(value, dict) else {}
