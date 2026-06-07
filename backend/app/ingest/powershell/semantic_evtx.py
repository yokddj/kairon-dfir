from __future__ import annotations

import json
from pathlib import PureWindowsPath
import re
from typing import Any

from app.ingest.normalization.field_quality import is_payload_blob, is_placeholder, is_probably_user


POWERSHELL_PROVIDERS = {"microsoft-windows-powershell", "powershell", "windows powershell", "powershellcore"}
IDENTITY_KEYS = {
    "user",
    "userid",
    "user_id",
    "username",
    "accountname",
    "subjectusername",
    "connecteduser",
    "connected user",
    "runasuser",
    "runas user",
    "securityuserid",
}
TECHNICAL_KEYS = {
    "hostapplication": "HostApplication",
    "commandline": "CommandLine",
    "scriptblocktext": "ScriptBlockText",
    "scriptname": "ScriptName",
    "commandpath": "CommandPath",
    "commandname": "CommandName",
    "commandinvocation": "CommandInvocation",
    "modulename": "ModuleName",
    "providername": "ProviderName",
    "engineversion": "EngineVersion",
    "runspaceid": "RunspaceId",
    "pipelineid": "PipelineId",
    "userid": "UserId",
    "user": "User",
    "username": "UserName",
    "connecteduser": "ConnectedUser",
    "runasuser": "RunAsUser",
    "processid": "ProcessId",
    "hostname": "HostName",
}
INVALID_PROFILE_USERS = {"default", "default user", "public", "all users", "systemprofile", "localservice", "networkservice"}
SCRIPT_PATH_RE = re.compile(r"(?i)([a-z]:\\[^\r\n\"'<>|]+\.(?:ps1|psm1|psd1))")
PROCESS_IMAGE_RE = re.compile(r"(?i)([a-z]:\\[^\r\n\"'<>|]+\\(?:powershell|pwsh)(?:_ise)?\.exe|\b(?:powershell|pwsh)(?:_ise)?\.exe\b)")
FILE_ARG_RE = re.compile(r"(?i)(?:^|\s)-(?:file|f)\s+(?:\"([^\"]+\.(?:ps1|psm1|psd1))\"|'([^']+\.(?:ps1|psm1|psd1))'|([^\s\"']+\.(?:ps1|psm1|psd1)))")


def normalize_powershell_evtx_semantics(document: dict[str, Any]) -> dict[str, Any]:
    artifact = _obj(document.get("artifact"))
    if str(artifact.get("type") or "").lower() != "powershell":
        return document
    if str(artifact.get("parser") or "").lower() != "powershell_evtx":
        return document

    fields = _structured_fields(document)
    event_id = _event_id(document)
    provider = _provider(document)
    event_type = _classify_event(event_id, provider, _event_type(document))
    raw_payload = _raw_payload(document)

    user, user_source, user_confidence = _semantic_user(document, fields)
    process_image = _process_image(document, fields)
    host_application = _clean_structured(fields.get("HostApplication")) or process_image or ""
    script_block_text = _clean_structured(fields.get("ScriptBlockText")) or _obj(document.get("powershell")).get("script_block_text") or ""
    command_name = _clean_structured(fields.get("CommandName"))
    command_invocation = _clean_structured(fields.get("CommandInvocation"))
    command = _semantic_command(event_id, fields, document, script_block_text, host_application, command_name, command_invocation)
    script_path = _script_path(fields, command, host_application, document)
    module_name = _clean_structured(fields.get("ModuleName"))
    engine_version = _clean_structured(fields.get("EngineVersion"))
    runspace_id = _clean_structured(fields.get("RunspaceId"))
    pipeline_id = _clean_structured(fields.get("PipelineId"))
    key_entity, key_entity_type = _semantic_key_entity(
        event_type=event_type,
        command=command,
        script_path=script_path,
        script_block_text=script_block_text,
        module_name=module_name,
        command_name=command_name,
        command_invocation=command_invocation,
        process_image=process_image,
        engine_version=engine_version,
        provider=provider,
        source_file=document.get("source_file"),
    )
    snippet = _snippet(event_type, command, script_path, module_name, key_entity)

    model = {
        "event_id": event_id,
        "provider": provider,
        "event_type": event_type,
        "timestamp": document.get("@timestamp") or "",
        "host": (_obj(document.get("host")).get("name") or _obj(document.get("host")).get("hostname") or ""),
        "user": user or "-",
        "user_source": user_source,
        "user_confidence": user_confidence,
        "process_image": process_image,
        "process_id": _clean_structured(fields.get("ProcessId")) or str(_obj(document.get("process")).get("pid") or ""),
        "host_application": host_application,
        "command": command,
        "script_path": script_path,
        "script_block_text": script_block_text,
        "module_name": module_name,
        "pipeline_id": pipeline_id,
        "runspace_id": runspace_id,
        "engine_version": engine_version,
        "key_entity": key_entity,
        "key_entity_type": key_entity_type,
        "snippet": snippet,
        "raw_payload": raw_payload,
        "normalization_warnings": _warnings(user, key_entity, command, raw_payload),
    }
    document["powershell_event_normalized"] = model
    document["display_user"] = user or "-"
    document["display_key_entity"] = key_entity
    document["display_command"] = command
    document["display_snippet"] = snippet

    user_obj = document.setdefault("user", {})
    if user and isinstance(user_obj, dict):
        user_obj["name"] = user
        user_obj["confidence"] = user_confidence
    powershell = document.setdefault("powershell", {})
    if command:
        powershell["command"] = command
        powershell["command_preview"] = _short(command, 240)
    if script_path:
        powershell["script_path"] = script_path
    if host_application:
        powershell["host_application"] = host_application
    if raw_payload:
        powershell["raw_payload"] = raw_payload
    document["key_entity"] = key_entity
    document["key_entity_type"] = key_entity_type
    document["snippet"] = snippet
    return document


def parse_context_info(value: Any) -> dict[str, str]:
    text = _clean_structured(value)
    if not text:
        return {}
    fields: dict[str, str] = {}
    for line in re.split(r"[\r\n]+", text):
        line = line.strip(" \t,;")
        if not line:
            continue
        match = re.match(r"^([A-Za-z][A-Za-z0-9 _-]{1,40})\s*(?:=|:|\t)\s*(.*)$", line)
        if not match:
            continue
        key = _canonical(match.group(1))
        if key not in TECHNICAL_KEYS:
            continue
        value_text = match.group(2).strip(" \t,;\"")
        if value_text:
            fields.setdefault(TECHNICAL_KEYS[key], value_text)
    return fields


def _structured_fields(document: dict[str, Any]) -> dict[str, str]:
    fields: dict[str, str] = {}

    def add(key: Any, value: Any) -> None:
        canonical = _canonical(str(key))
        if canonical in {"contextinfo", "context"}:
            fields.update({k: v for k, v in parse_context_info(value).items() if k not in fields})
            return
        mapped = TECHNICAL_KEYS.get(canonical)
        if not mapped:
            return
        text = _clean_structured(value)
        if text:
            fields.setdefault(mapped, text)
            if mapped in {"HostApplication", "CommandLine", "ScriptBlockText"}:
                fields.update({k: v for k, v in parse_context_info(text).items() if k not in fields})

    for source in _field_sources(document):
        if isinstance(source, dict):
            for key, value in source.items():
                if isinstance(value, (dict, list)):
                    for nested_key, nested_value in _flatten_event_data(value).items():
                        add(nested_key, nested_value)
                    continue
                if str(key).lower().startswith("payload") and value:
                    fields.update(_payload_fields(value))
                add(key, value)
        elif source:
            fields.update(_payload_fields(source))
    return fields


def _field_sources(document: dict[str, Any]) -> list[Any]:
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
        powershell,
        powershell.get("raw_payload"),
    ]


def _payload_fields(value: Any) -> dict[str, str]:
    text = _clean_structured(value)
    if not text:
        return {}
    fields: dict[str, str] = {}
    if text.startswith("{") or text.startswith("["):
        try:
            parsed = json.loads(text)
        except Exception:  # noqa: BLE001
            parsed = None
        if parsed is not None:
            flat = _flatten_event_data(parsed)
            for key, item in flat.items():
                mapped = TECHNICAL_KEYS.get(_canonical(str(key)))
                if mapped and _clean_structured(item):
                    fields.setdefault(mapped, _clean_structured(item))
                if _canonical(str(key)) in {"data", "eventdatadata"}:
                    fields.update(parse_context_info(item))
    fields.update(parse_context_info(text))
    invocation = re.search(r'(?i)\bCommandInvocation\(([^)]+)\):\s*"?([^"\r\n]+)', text)
    if invocation:
        fields.setdefault("CommandInvocation", _clean_structured(invocation.group(2) or invocation.group(1)))
        fields.setdefault("CommandName", _clean_structured(invocation.group(1)))
    return {key: value for key, value in fields.items() if value}


def _flatten_event_data(value: Any, prefix: str = "") -> dict[str, Any]:
    output: dict[str, Any] = {}
    if isinstance(value, dict):
        name = value.get("@Name") or value.get("Name") or value.get("name")
        text = value.get("#text")
        if name and text is not None:
            output[str(name)] = text
        for key, item in value.items():
            if key in {"@Name", "Name", "name", "#text"}:
                continue
            child_key = f"{prefix}.{key}" if prefix else str(key)
            if isinstance(item, (dict, list)):
                output.update(_flatten_event_data(item, child_key))
            else:
                output[child_key] = item
    elif isinstance(value, list):
        for item in value:
            output.update(_flatten_event_data(item, prefix))
    return output


def _semantic_user(document: dict[str, Any], fields: dict[str, str]) -> tuple[str, str, str]:
    windows = _obj(document.get("windows"))
    event_data = _obj(windows.get("event_data"))
    raw = _obj(document.get("raw"))
    user = _obj(document.get("user"))
    candidates = [
        (event_data.get("UserId") or raw.get("UserId") or user.get("sid"), "system_security_userid", "high"),
        (fields.get("User") or fields.get("UserId") or fields.get("UserName") or fields.get("ConnectedUser") or fields.get("RunAsUser"), "eventdata_identity", "high"),
        (user.get("name"), "normalized_user", "high"),
    ]
    for candidate, source, confidence in candidates:
        value = _valid_user(candidate)
        if value:
            return value, source, confidence
    for candidate in (fields.get("ScriptName"), fields.get("HostApplication"), fields.get("CommandLine"), _obj(document.get("powershell")).get("command")):
        value = _user_from_profile_path(candidate)
        if value:
            return value, "profile_path", "medium"
    return "-", "unknown", "unknown"


def _semantic_command(event_id: int | None, fields: dict[str, str], document: dict[str, Any], script_block_text: str, host_application: str, command_name: str, command_invocation: str) -> str:
    if event_id in {4104, 4105, 4106} and script_block_text and not _invalid_display_value(script_block_text, allow_long=True):
        return script_block_text
    for value in (fields.get("CommandLine"), host_application, command_invocation, command_name, _obj(document.get("powershell")).get("command"), _obj(document.get("process")).get("command_line")):
        text = _clean_display(value, allow_long=True)
        if text:
            return text
    return ""


def _script_path(fields: dict[str, str], command: str, host_application: str, document: dict[str, Any]) -> str:
    for value in (fields.get("ScriptName"), fields.get("CommandPath")):
        text = _clean_display(value)
        if text and SCRIPT_PATH_RE.fullmatch(text):
            return text
    for value in (command, host_application, fields.get("CommandLine")):
        text = _clean_structured(value)
        if not text:
            continue
        file_match = FILE_ARG_RE.search(text)
        if file_match:
            return next(group for group in file_match.groups() if group)
        script_match = SCRIPT_PATH_RE.search(text)
        if script_match:
            return script_match.group(1)
    file_path = _obj(document.get("file")).get("path")
    if file_path and not _is_internal_path(file_path) and SCRIPT_PATH_RE.search(str(file_path)):
        return SCRIPT_PATH_RE.search(str(file_path)).group(1)
    return ""


def _process_image(document: dict[str, Any], fields: dict[str, str]) -> str:
    for value in (_obj(document.get("process")).get("path"), fields.get("HostApplication"), fields.get("CommandLine"), _obj(document.get("process")).get("name")):
        text = _clean_structured(value)
        if not text or _is_internal_path(text):
            continue
        match = PROCESS_IMAGE_RE.search(text)
        if match:
            return match.group(1)
    return ""


def _semantic_key_entity(**kwargs: Any) -> tuple[str, str]:
    event_type = str(kwargs.get("event_type") or "")
    script_path = _clean_display(kwargs.get("script_path"))
    command = _clean_display(kwargs.get("command"), allow_long=True)
    script_block_text = _clean_display(kwargs.get("script_block_text"), allow_long=True)
    module_name = _clean_display(kwargs.get("module_name"))
    command_name = _clean_display(kwargs.get("command_name"))
    command_invocation = _clean_display(kwargs.get("command_invocation"))
    process_image = _clean_display(kwargs.get("process_image"))
    engine_version = _clean_display(kwargs.get("engine_version"))
    provider = _clean_display(kwargs.get("provider"))
    source_file = kwargs.get("source_file")
    by_type = {
        "script_block": [(script_path, "script_path"), (_script_summary(script_block_text), "script_block"), ("script_block", "event_type")],
        "module_logging": [(module_name, "module"), (command_name, "command_name"), (command_invocation, "command"), (script_path, "script_path"), ("module_logging", "event_type")],
        "pipeline_execution": [(command_name, "command_name"), (command_invocation, "command"), (script_path, "script_path"), (_command_executable(command), "command"), (process_image, "process"), ("pipeline_execution", "event_type")],
        "powershell_engine_lifecycle": [(process_image, "process"), (engine_version, "engine_version"), ("powershell_engine_lifecycle", "event_type")],
        "provider_lifecycle": [(process_image, "process"), (provider, "provider"), ("provider_lifecycle", "event_type")],
        "command_observed": [(script_path, "script_path"), (_command_executable(command), "command"), (_command_summary(command), "command"), (process_image, "process")],
    }
    candidates = by_type.get(event_type, []) + [(process_image, "process"), (script_path, "script_path"), (_command_executable(command), "command"), (provider or event_type, "event_type"), (_source_basename(source_file), "source_file")]
    for value, entity_type in candidates:
        text = _clean_display(value)
        if text:
            return text, entity_type
    return event_type or "powershell_event", "event_type"


def _snippet(event_type: str, command: str, script_path: str, module_name: str, key_entity: str) -> str:
    context = script_path or module_name or _command_summary(command) or key_entity
    return _short(f"{event_type}: {context}" if context else event_type, 180)


def _classify_event(event_id: int | None, provider: str, fallback: str) -> str:
    if event_id in {400, 403}:
        return "powershell_engine_lifecycle"
    if event_id == 600:
        return "provider_lifecycle"
    if event_id == 800:
        return "pipeline_execution"
    if event_id == 4103:
        return "module_logging"
    if event_id in {4104, 4105, 4106}:
        return "script_block"
    if event_id == 53504:
        return "host_application"
    if fallback:
        return fallback
    return "generic_powershell_event" if _is_powershell_provider(provider) else "event"


def _event_id(document: dict[str, Any]) -> int | None:
    value = _obj(document.get("windows")).get("event_id") or document.get("event_id")
    try:
        return int(value)
    except Exception:
        return None


def _provider(document: dict[str, Any]) -> str:
    return str(_obj(document.get("event")).get("provider") or _obj(document.get("windows")).get("provider") or "")


def _event_type(document: dict[str, Any]) -> str:
    return str(_obj(document.get("event")).get("type") or "")


def _is_powershell_provider(provider: str) -> bool:
    return str(provider or "").strip().lower() in POWERSHELL_PROVIDERS or "powershell" in str(provider or "").lower()


def _raw_payload(document: dict[str, Any]) -> dict[str, Any]:
    output: dict[str, Any] = {}
    for key, value in _obj(document.get("raw")).items():
        if value not in (None, "") and (str(key).lower().startswith("payload") or str(key).lower() in {"message", "contextinfo"}):
            output[str(key)] = value
    event_data = _obj(_obj(document.get("windows")).get("event_data"))
    if event_data:
        output["event_data"] = event_data
    return output


def _valid_user(value: Any) -> str:
    text = _clean_structured(value)
    if not text or is_placeholder(text) or is_payload_blob(text):
        return ""
    if is_probably_user(text):
        return text
    if "\n" in text or len(text) > 80 or text.count("=") > 1 or _looks_like_path_or_command(text):
        return ""
    return ""


def _user_from_profile_path(value: Any) -> str:
    text = _clean_structured(value)
    if not text or _is_internal_path(text):
        return ""
    match = re.search(r"(?i)(?:^|\\)Users\\([^\\]+)\\", text.replace("/", "\\"))
    if not match:
        return ""
    user = match.group(1)
    if user.lower() in INVALID_PROFILE_USERS:
        return ""
    return user if _valid_user(user) else ""


def _invalid_display_value(value: Any, allow_long: bool = False) -> bool:
    text = _clean_structured(value)
    if not text or is_placeholder(text) or _is_internal_path(text):
        return True
    if is_payload_blob(text):
        return True
    if not allow_long and ("\n" in text or len(text) > 220 or text.count("=") > 2):
        return True
    return False


def _clean_display(value: Any, allow_long: bool = False) -> str:
    text = _clean_structured(value)
    if _invalid_display_value(text, allow_long=allow_long):
        return ""
    return _short(text, 512 if allow_long else 220)


def _command_executable(command: str) -> str:
    text = _clean_structured(command)
    if not text:
        return ""
    script = SCRIPT_PATH_RE.search(text)
    if script:
        return script.group(1)
    proc = PROCESS_IMAGE_RE.search(text)
    if proc:
        return proc.group(1)
    token = text.split()[0] if text.split() else ""
    return token.strip('"') if token and not is_placeholder(token) else ""


def _command_summary(command: str) -> str:
    text = _clean_display(command, allow_long=True)
    return _short(text, 160) if text else ""


def _script_summary(script_block_text: str) -> str:
    text = _clean_display(script_block_text, allow_long=True)
    return _short(text, 160) if text else ""


def _source_basename(value: Any) -> str:
    text = _clean_structured(value)
    if not text or _is_internal_path(text):
        return ""
    try:
        return PureWindowsPath(text.replace("/", "\\")).name
    except Exception:
        return text.rsplit("/", 1)[-1].rsplit("\\", 1)[-1]


def _is_internal_path(value: Any) -> bool:
    text = str(value or "").replace("\\", "/").lower()
    return "/app/data/evidence/" in text or "/root/dfir_app/" in text or "/staging/uploads/" in text


def _looks_like_path_or_command(value: str) -> bool:
    lower = value.lower()
    return bool("\\" in value or "/" in value or ".exe" in lower or ".ps1" in lower or " -" in lower)


def _warnings(user: str, key_entity: str, command: str, raw_payload: dict[str, Any]) -> list[str]:
    warnings = []
    if not user or user == "-":
        warnings.append("user_unknown")
    if not key_entity:
        warnings.append("key_entity_fallback")
    if raw_payload and not command:
        warnings.append("raw_payload_preserved_no_command")
    return warnings


def _clean_structured(value: Any) -> str:
    if value is None:
        return ""
    text = str(value).strip().strip("\x00")
    if len(text) >= 2 and text[0] == text[-1] and text[0] in {'"', "'"}:
        text = text[1:-1].strip()
    return text


def _short(value: str, limit: int) -> str:
    text = re.sub(r"\s+", " ", _clean_structured(value)).strip()
    return text if len(text) <= limit else text[: limit - 3].rstrip() + "..."


def _canonical(value: str) -> str:
    return re.sub(r"[^a-z0-9]+", "", value.lower())


def _obj(value: Any) -> dict[str, Any]:
    return value if isinstance(value, dict) else {}
