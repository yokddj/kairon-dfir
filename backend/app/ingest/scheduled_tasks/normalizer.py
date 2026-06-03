import json
from pathlib import PureWindowsPath
import re
from datetime import UTC, datetime, timedelta

from app.analysis.suspicious import detect_suspicious_path, is_windows_unc_path
from app.ingest.identity_extraction import extract_user_from_path
from app.ingest.scheduled_tasks.helpers import (
    TASK_LOLBIN_HINTS,
    TASK_SCRIPT_EXTENSIONS,
    basename_windows,
    clean_text,
    extension_windows,
    is_known_microsoft_task_path,
    normalize_windowsish_path,
    parse_bool,
    parse_isoish_timestamp,
    resolve_known_windows_sid,
    task_name_looks_suspicious,
)


def _first_value(row: dict, candidates: list[str]) -> str | None:
    mapping = {str(key).lower(): value for key, value in row.items()}
    for candidate in candidates:
        value = mapping.get(candidate.lower())
        if value not in (None, ""):
            return str(value)
    return None


def _load_json_list(value: str | None) -> list:
    text = clean_text(value)
    if not text:
        return []
    try:
        parsed = json.loads(text)
        return parsed if isinstance(parsed, list) else []
    except Exception:  # noqa: BLE001
        return []


def _extract_trigger_start_boundary(triggers: list[dict]) -> str | None:
    for trigger in triggers:
        if not isinstance(trigger, dict):
            continue
        value = parse_isoish_timestamp(trigger.get("start_boundary") or trigger.get("StartBoundary"))
        if value:
            return value
    return None


def _safe_task_settings(row: dict) -> dict:
    enabled = parse_bool(_first_value(row, ["Enabled"]))
    hidden = parse_bool(_first_value(row, ["Hidden"]))
    return {
        "enabled": enabled,
        "hidden": hidden,
        "enabled_state": "missing" if enabled is None else "enabled" if enabled else "disabled",
        "hidden_state": "missing" if hidden is None else "hidden" if hidden else "visible",
        "allow_start_on_demand": parse_bool(_first_value(row, ["AllowStartOnDemand"])),
        "disallow_start_if_on_batteries": parse_bool(_first_value(row, ["DisallowStartIfOnBatteries"])),
        "stop_if_going_on_batteries": parse_bool(_first_value(row, ["StopIfGoingOnBatteries"])),
        "multiple_instances_policy": clean_text(_first_value(row, ["MultipleInstancesPolicy"])),
        "run_only_if_network_available": parse_bool(_first_value(row, ["RunOnlyIfNetworkAvailable"])),
        "execution_time_limit": clean_text(_first_value(row, ["ExecutionTimeLimit"])),
        "priority": clean_text(_first_value(row, ["Priority"])),
        "start_when_available": parse_bool(_first_value(row, ["StartWhenAvailable"])),
        "wake_to_run": parse_bool(_first_value(row, ["WakeToRun"])),
    }


def normalize_task_action(command: str | None, arguments: str | None, working_directory: str | None) -> dict:
    command = normalize_windowsish_path(command) or clean_text(command)
    arguments = clean_text(arguments)
    working_directory = normalize_windowsish_path(working_directory) or clean_text(working_directory)
    executable_path = command if command and (":\\" in command or command.startswith("\\\\") or "/" in command) else None
    executable_name = basename_windows(executable_path or command)
    command_line = None
    if command and arguments:
        command_line = f'"{command}" {arguments}' if " " in command and not command.startswith('"') else f"{command} {arguments}"
    else:
        command_line = command or arguments
    action_summary = None
    if command_line:
        action_summary = command_line
    elif command:
        action_summary = command
    return {
        "command": command,
        "arguments": arguments,
        "command_line": command_line,
        "executable_path": executable_path,
        "executable_name": executable_name,
        "working_directory": working_directory,
        "action_summary": action_summary,
    }


def _is_system_scope(run_as: str | None, task_path: str | None, source_file: str | None) -> bool:
    lowered = str(run_as or "").strip().lower()
    if lowered in {"system", "nt authority\\system", "s-1-5-18", "local service", "nt authority\\local service", "network service", "nt authority\\network service"}:
        return True
    blob = f"{task_path or ''} {source_file or ''}".lower()
    return "\\windows\\system32\\tasks\\" in blob or blob.startswith("c:\\windows\\system32\\tasks\\")


def _task_has_startup_trigger(triggers: list[dict]) -> bool:
    return any(str((trigger or {}).get("type") or "") in {"BootTrigger", "RegistrationTrigger"} for trigger in triggers)


def _task_has_logon_trigger(triggers: list[dict]) -> bool:
    return any(str((trigger or {}).get("type") or "") == "LogonTrigger" for trigger in triggers)


_VALID_CLSID_RE = re.compile(r"^\{[0-9a-fA-F]{8}(?:-[0-9a-fA-F]{4}){3}-[0-9a-fA-F]{12}\}$")
_MIN_REASONABLE_TIMESTAMP_YEAR = 1990
_MAX_FUTURE_TIMESTAMP_SKEW = timedelta(days=366)


def _parse_normalized_timestamp(value: str | None) -> datetime | None:
    if not value:
        return None
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=UTC)
    return parsed.astimezone(UTC)


def _validate_forensic_timestamp(value: str | None, source_status: str) -> tuple[str | None, str, str | None]:
    if not value:
        return None, "missing", None
    parsed = _parse_normalized_timestamp(value)
    if parsed is None:
        return None, "invalid", "parse_failed"
    if parsed.year < _MIN_REASONABLE_TIMESTAMP_YEAR:
        return None, "suspicious", "past_out_of_range"
    if parsed > datetime.now(UTC) + _MAX_FUTURE_TIMESTAMP_SKEW:
        return None, "suspicious", "future_out_of_range"
    return value, source_status, None


def _task_risk_and_tags(*, task_name: str | None, task_path: str | None, author: str | None, command: str | None, arguments: str | None, working_directory: str | None, enabled: bool | None, hidden: bool | None, triggers: list[dict], com_handler_class_id: str | None) -> tuple[set[str], set[str], int]:
    tags: set[str] = {"scheduled_task", "persistence", "autorun"}
    reasons: set[str] = set()
    risk = 0
    lower_command = str(command or "").lower()
    lower_args = str(arguments or "").lower()
    lower_blob = f"{lower_command} {lower_args} {working_directory or ''}".lower()
    basename = str(basename_windows(command) or "").lower()
    path_reasons = detect_suspicious_path(command)
    has_com_handler = bool(clean_text(com_handler_class_id))
    is_microsoft_task = is_known_microsoft_task_path(task_path)
    startup_trigger = _task_has_startup_trigger(triggers)
    logon_trigger = _task_has_logon_trigger(triggers)
    command_suspicious = bool(command and path_reasons)
    lolbin_or_script = basename in TASK_LOLBIN_HINTS or (command and extension_windows(command) in TASK_SCRIPT_EXTENSIONS)
    command_content_suspicious = any(token in lower_blob for token in ["-enc", "-encodedcommand", "frombase64string", "http://", "https://"])

    if command:
        tags.add("execution_candidate")
    if hidden is True:
        tags.add("hidden_task")
        risk += 20
        reasons.add("Task is hidden")
    if enabled is False:
        tags.add("disabled")
    if startup_trigger:
        tags.add("startup_trigger")
        if not is_microsoft_task and (hidden is True or command_suspicious or lolbin_or_script or command_content_suspicious or has_com_handler):
            risk += 20
            reasons.add("Startup or registration trigger on suspicious task")
    if logon_trigger:
        tags.add("logon_trigger")
        if not is_microsoft_task and (hidden is True or command_suspicious or lolbin_or_script or command_content_suspicious or has_com_handler):
            risk += 20
            reasons.add("Logon trigger on suspicious task")
    if basename in TASK_LOLBIN_HINTS:
        tags.add("lolbin")
        risk += 20
        reasons.add("Task action uses LOLBin")
    if basename in {"powershell.exe", "pwsh.exe"}:
        tags.add("powershell")
    if any(token in lower_blob for token in ["-enc", "-encodedcommand", "frombase64string"]):
        tags.add("encoded_command")
        risk += 30
        reasons.add("Encoded command in task action")
    if "http://" in lower_blob or "https://" in lower_blob:
        tags.add("network_url")
        risk += 20
        reasons.add("Task action references network URL")
    if is_windows_unc_path(command):
        tags.update({"unc_path", "network_path"})
        reasons.add("Task action uses UNC path")
    if has_com_handler:
        tags.add("com_handler_task")
        clsid = clean_text(com_handler_class_id)
        if clsid and not _VALID_CLSID_RE.fullmatch(clsid):
            risk += 20
            reasons.add("Task uses invalid COM handler CLSID")
        elif not is_microsoft_task and (hidden is True or startup_trigger or logon_trigger):
            risk += 20
            reasons.add("Non-Microsoft COM handler task has persistence-oriented trigger or is hidden")
        elif not is_microsoft_task and author and "microsoft" not in author.lower():
            risk += 10
            reasons.add("Non-Microsoft COM handler task outside trusted Microsoft path")
    if command and any(reason in path_reasons for reason in {"appdata_path", "temp_path", "downloads_path", "desktop_path", "public_path", "programdata_path"}):
        tags.add("user_writable_path")
    if command and path_reasons:
        tags.add("suspicious_path")
        risk += 30
        reasons.add("Task action path is suspicious or user-writable")
        if any(reason == "unc_path" for reason in path_reasons):
            tags.update({"unc_path", "network_path"})
    if lower_command.startswith("c:\\windows\\") or lower_command.startswith("c:\\program files\\") or lower_command.startswith("c:\\program files (x86)\\"):
        tags.add("system_path")
    if task_name_looks_suspicious(task_name, task_path=task_path):
        reasons.add("Task name looks suspicious")
    if enabled is True and command:
        risk += 20
        reasons.add("Enabled task with executable action")
    if command and extension_windows(command) in TASK_SCRIPT_EXTENSIONS:
        tags.add("script_execution")
    if not command and not has_com_handler:
        reasons.add("Task has no executable command")
    return tags, reasons, min(risk, 100)


def _parse_run_as(value: str | None) -> tuple[str | None, str | None]:
    text = clean_text(value)
    if not text:
        return None, None
    if text.startswith("S-1-"):
        return resolve_known_windows_sid(text), text
    if "\\" in text:
        return text.split("\\", 1)[1], None
    return text, None


def normalize_scheduled_task_row(document: dict, row: dict, artifact_meta: dict) -> dict:
    parser = str(artifact_meta.get("parser") or "").lower()
    source_format = str(artifact_meta.get("source_format") or "").lower()
    enabled = parse_bool(_first_value(row, ["Enabled"]))
    hidden = parse_bool(_first_value(row, ["Hidden"]))
    task_name = clean_text(_first_value(row, ["TaskName", "Name"]))
    task_path = normalize_windowsish_path(_first_value(row, ["TaskPath", "URI", "TaskUri"]))
    if task_path and not task_path.startswith("\\"):
        task_path = f"\\{task_path.lstrip('\\')}"
    task_uri = clean_text(_first_value(row, ["URI", "TaskUri"])) or task_path
    author = clean_text(_first_value(row, ["Author"]))
    description = clean_text(_first_value(row, ["Description"]))
    user_id = clean_text(_first_value(row, ["UserId", "Principal", "RunAs"]))
    group_id = clean_text(_first_value(row, ["GroupId"]))
    logon_type = clean_text(_first_value(row, ["LogonType"]))
    run_level = clean_text(_first_value(row, ["RunLevel"]))
    registration_date = parse_isoish_timestamp(_first_value(row, ["Date", "RegistrationDate", "Created"]))
    source_mtime = parse_isoish_timestamp(_first_value(row, ["SourceFileMtime", "LastWriteTime"]))
    command = _first_value(row, ["Command"])
    arguments = _first_value(row, ["Arguments"])
    working_directory = _first_value(row, ["WorkingDirectory"])
    action = normalize_task_action(command, arguments, working_directory)
    process_path = action["executable_path"]
    process_name = action["executable_name"]
    task_actions = _load_json_list(_first_value(row, ["Actions"]))
    task_triggers = _load_json_list(_first_value(row, ["Triggers"]))
    trigger_start_boundary = parse_isoish_timestamp(_first_value(row, ["TriggerStartBoundary", "StartBoundary", "FirstTriggerStartBoundary"])) or _extract_trigger_start_boundary(task_triggers)
    trigger_summary = clean_text(_first_value(row, ["TriggerSummary", "Triggers"]))
    action_summary = action["action_summary"] or clean_text(_first_value(row, ["ActionSummary", "Actions"]))
    com_handler_class_id = clean_text(_first_value(row, ["ComHandlerClassId", "ClassId"]))
    com_handler_data = clean_text(_first_value(row, ["ComHandlerData", "Data"]))
    source_file = clean_text(_first_value(row, ["SourceFile", "OriginalPath"]))
    original_path = clean_text(_first_value(row, ["OriginalPath"])) or source_file
    settings = _safe_task_settings(row)
    run_as_value = clean_text(_first_value(row, ["RunAs"])) or user_id or group_id
    run_as_name, run_as_sid = _parse_run_as(run_as_value)
    resolved_user = run_as_name or resolve_known_windows_sid(user_id) or resolve_known_windows_sid(group_id)

    raw_timestamp = registration_date or trigger_start_boundary
    timestamp_precision = "scheduled_task_registration_date" if registration_date else "trigger_start_boundary" if trigger_start_boundary else "unknown"
    source_timestamp_status = "valid" if registration_date else "derived" if trigger_start_boundary else "missing"
    timestamp_source = "registration_date" if registration_date else "trigger_start_boundary" if trigger_start_boundary else None
    timestamp, timestamp_status, timestamp_warning = _validate_forensic_timestamp(raw_timestamp, source_timestamp_status)
    if timestamp:
        document["@timestamp"] = timestamp
    else:
        document.pop("@timestamp", None)
    if raw_timestamp and raw_timestamp != timestamp:
        document["raw_timestamp"] = raw_timestamp
        document["original_timestamp"] = raw_timestamp
    if timestamp_warning:
        document["timestamp_warning"] = timestamp_warning
    document["timestamp_precision"] = timestamp_precision
    document["timestamp_status"] = timestamp_status
    document["timestamp_source"] = timestamp_source
    document["timezone"] = "UTC" if timestamp else None
    document["artifact"]["type"] = "scheduled_task"
    is_xml = parser in {"xml", "scheduled_task_xml"} or source_format == "xml"
    document["artifact"]["parser"] = "scheduled_task_xml" if is_xml else "scheduled_task_csv"
    document["source_tool"] = "native_scheduled_task" if is_xml else "scheduled_task_parser"
    document["source_format"] = "xml" if is_xml else "csv"

    tags, reasons, risk_score = _task_risk_and_tags(
        task_name=task_name,
        task_path=task_uri or task_path,
        author=author,
        command=action["command"],
        arguments=action["arguments"],
        working_directory=action["working_directory"],
        enabled=enabled,
        hidden=hidden,
        triggers=task_triggers,
        com_handler_class_id=com_handler_class_id,
    )
    severity = "high" if risk_score >= 70 else "medium" if risk_score >= 40 else "low" if risk_score >= 20 else "info"
    timeline_include = bool(timestamp) and bool(
        action["command"]
        or hidden is True
        or enabled is True and (_task_has_startup_trigger(task_triggers) or _task_has_logon_trigger(task_triggers))
        or "suspicious_path" in tags
    )

    document["event"].update(
        {
            "category": "persistence",
            "type": "scheduled_task",
            "action": "scheduled_task_observed",
            "severity": severity,
            "timeline_include": timeline_include,
            "message": f"Scheduled task observed: {task_name or task_uri or task_path or 'unknown'}",
        }
    )
    document["task"] = {
        "name": task_name,
        "path": task_path,
        "uri": task_uri,
        "author": author,
        "description": description,
        "enabled": enabled,
        "hidden": hidden,
        "source_file": source_file,
        "date": registration_date,
        "version": clean_text(_first_value(row, ["Version"])),
        "user_id": user_id,
        "group_id": group_id,
        "run_as": run_as_value,
        "resolved_user": resolved_user,
        "logon_type": logon_type,
        "run_level": run_level,
        "actions": task_actions,
        "triggers": task_triggers,
        "command": action["command"],
        "arguments": action["arguments"],
        "working_directory": action["working_directory"],
        "com_handler_class_id": com_handler_class_id,
        "com_handler_data": com_handler_data,
        "settings": settings,
        "trigger_summary": trigger_summary,
        "action_summary": action_summary,
        "trigger_start_boundary": trigger_start_boundary,
        "source_file_mtime": source_mtime,
        "timestamp_status": timestamp_status,
        "timestamp_source": timestamp_source,
        "timestamp_warning": timestamp_warning,
        "raw_timestamp": raw_timestamp if raw_timestamp and raw_timestamp != timestamp else None,
        "artifact_type": "task_xml" if is_xml else "task_csv",
    }
    document.setdefault("persistence", {})
    document["persistence"].update(
        {
            "mechanism": "scheduled_task",
            "location": task_uri or task_path,
            "name": task_name,
            "command": action["command_line"] or action["command"],
            "path": action["command"],
            "enabled": enabled,
            "scope": "system" if _is_system_scope(run_as_value, task_path, source_file) else "interactive_user" if run_as_sid == "S-1-5-4" else "user" if (resolved_user or extract_user_from_path(action["command"]) or run_as_value) else None,
            "user": resolved_user or run_as_value,
            "sid": run_as_sid,
            "confidence": "high" if enabled is True and action["command"] else "medium",
            "source": source_file,
        }
    )
    document["process"].update(
        {
            "path": process_path or action["command"],
            "name": process_name or basename_windows(action["command"]),
            "command_line": action["command_line"],
            "working_directory": action["working_directory"],
            "application": process_name or basename_windows(action["command"]),
        }
    )
    document["file"].update(
        {
            "path": process_path or action["command"],
            "name": basename_windows(process_path or action["command"]),
            "extension": extension_windows(process_path or action["command"]),
            "source_path": source_file,
        }
    )
    document["execution"].update(
        {
            "source": "scheduled_task",
            "program_name": process_name or basename_windows(action["command"]),
            "is_execution_confirmed": False,
            "confidence": "medium" if action["command"] else "low",
            "interpretation": "Scheduled Task definition indicates configured execution/persistence, not confirmed execution by itself",
            "first_seen": None,
            "last_seen": None,
            "last_run": None,
        }
    )
    if run_as_sid:
        document["user"]["sid"] = document["user"].get("sid") or run_as_sid
    if resolved_user:
        document["user"]["name"] = document["user"].get("name") or resolved_user
    elif process_path and not document["user"].get("name"):
        document["user"]["name"] = extract_user_from_path(process_path)

    if not document["user"].get("name") and not any(value for value in [user_id, group_id, run_as_value]):
        document.setdefault("data_quality", [])
        document["data_quality"] = sorted(set(document.get("data_quality", [])) | {"missing_user"})
    dq = set(document.get("data_quality", []))
    dq.add("low_confidence_execution")
    if not timestamp:
        dq.add("missing_timestamp")
    if enabled is False:
        dq.add("disabled_task")
    if not action["command"]:
        dq.add("missing_command")
    if com_handler_class_id:
        dq.add("com_handler_task")
    document["data_quality"] = sorted(dq | {"low_confidence_execution"})

    tags.update({"powershell"} if str((process_name or "")).lower() in {"powershell.exe", "pwsh.exe"} else set())
    if author and "microsoft" in author.lower() and process_path and process_path.lower().startswith("c:\\windows\\system32\\"):
        risk_score = min(risk_score, 10)
        document["event"]["severity"] = "info"
    document["tags"] = sorted(tags)
    document["suspicious_reasons"] = sorted(reasons)
    document["risk_score"] = risk_score
    document["_preserve_risk_score"] = True
    document["_preserve_timeline_include"] = True
    document["raw"] = {
        **document.get("raw", {}),
        "ScheduledTaskParser": document["artifact"]["parser"],
        "TaskXml": clean_text(_first_value(row, ["TaskXml"])),
        "TaskXmlPreview": clean_text(_first_value(row, ["TaskXmlPreview"])) or (clean_text(_first_value(row, ["TaskXml"]))[:20000] if clean_text(_first_value(row, ["TaskXml"])) else None),
        "TaskXmlEncoding": clean_text(_first_value(row, ["TaskXmlEncoding"])) or "unknown",
        "SourceFile": source_file,
        "OriginalPath": original_path,
        "NormalizedWindowsPath": source_file,
        "TaskFields": {
            "TaskName": task_name,
            "TaskPath": task_path,
            "URI": task_uri,
            "Command": action["command"],
            "Arguments": action["arguments"],
            "RunAs": run_as_value,
        },
    }
    if artifact_meta.get("velociraptor_original_path") or artifact_meta.get("velociraptor_normalized_windows_path"):
        document.setdefault("velociraptor", {})
        document["velociraptor"].update(
            {
                "original_path": artifact_meta.get("velociraptor_original_path"),
                "normalized_windows_path": artifact_meta.get("velociraptor_normalized_windows_path") or source_file,
                "parser_status": artifact_meta.get("velociraptor_parser_status") or "ready",
            }
        )
    return document
