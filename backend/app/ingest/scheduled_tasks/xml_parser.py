from datetime import UTC, datetime
from pathlib import Path
import json
import re
import xml.etree.ElementTree as ET

from app.ingest.scheduled_tasks.helpers import infer_task_identity_from_filesystem_path, normalize_windowsish_path, parse_isoish_timestamp


def _local_name(tag: str) -> str:
    if "}" in tag:
        return tag.split("}", 1)[1]
    return tag


def _child(node: ET.Element | None, name: str) -> ET.Element | None:
    if node is None:
        return None
    for child in list(node):
        if _local_name(child.tag) == name:
            return child
    return None


def _children(node: ET.Element | None, name: str | None = None) -> list[ET.Element]:
    if node is None:
        return []
    if name is None:
        return list(node)
    return [child for child in list(node) if _local_name(child.tag) == name]


def _text(node: ET.Element | None, name: str) -> str | None:
    child = _child(node, name)
    if child is None or child.text is None:
        return None
    value = child.text.strip()
    return value or None


def _node_to_text(node: ET.Element | None) -> str | None:
    if node is None:
        return None
    text = "".join(node.itertext()).strip()
    return text or None


_INVALID_XML_RE = re.compile(r"[\x00-\x08\x0B\x0C\x0E-\x1F]")
_BARE_AMP_RE = re.compile(r"&(?!#\d+;|#x[0-9a-fA-F]+;|amp;|lt;|gt;|quot;|apos;)")


def _sanitize_xml_text(xml_text: str) -> str:
    cleaned = _INVALID_XML_RE.sub("", xml_text)
    cleaned = _BARE_AMP_RE.sub("&amp;", cleaned)
    return cleaned


def _decode_task_xml_bytes(payload: bytes) -> tuple[str, str]:
    if payload.startswith(b"\xff\xfe"):
        return payload.decode("utf-16-le", errors="ignore"), "utf-16-le"
    if payload.startswith(b"\xfe\xff"):
        return payload.decode("utf-16-be", errors="ignore"), "utf-16-be"
    if payload.startswith(b"\xef\xbb\xbf"):
        return payload.decode("utf-8-sig", errors="ignore"), "utf-8"
    if payload:
        even_bytes = payload[0::2]
        odd_bytes = payload[1::2]
        even_nuls = sum(1 for value in even_bytes if value == 0)
        odd_nuls = sum(1 for value in odd_bytes if value == 0)
        if odd_bytes and odd_nuls >= max(2, len(odd_bytes) // 3) and even_nuls <= max(1, len(even_bytes) // 10):
            return payload.decode("utf-16-le", errors="ignore"), "utf-16-le"
        if even_bytes and even_nuls >= max(2, len(even_bytes) // 3) and odd_nuls <= max(1, len(odd_bytes) // 10):
            return payload.decode("utf-16-be", errors="ignore"), "utf-16-be"
    try:
        return payload.decode("utf-8"), "utf-8"
    except UnicodeDecodeError:
        return payload.decode("utf-8", errors="ignore"), "unknown"


def _xml_preview(xml_text: str, limit: int = 4000) -> str:
    return xml_text[:limit]


def _regex_text(xml_text: str, tag: str) -> str | None:
    match = re.search(rf"<(?:\w+:)?{re.escape(tag)}\b[^>]*>(.*?)</(?:\w+:)?{re.escape(tag)}>", xml_text, re.IGNORECASE | re.DOTALL)
    if not match:
        return None
    value = re.sub(r"<[^>]+>", "", match.group(1)).strip()
    return value or None


def _fallback_parse_task_xml(xml_text: str, path: Path, source_path: str | None, *, xml_encoding: str = "unknown") -> tuple[dict, list[str]]:
    task_path, task_name = infer_task_identity_from_filesystem_path(source_path or str(path))
    stat = path.stat()
    command = normalize_windowsish_path(_regex_text(xml_text, "Command")) or _regex_text(xml_text, "Command")
    arguments = _regex_text(xml_text, "Arguments")
    working_directory = normalize_windowsish_path(_regex_text(xml_text, "WorkingDirectory")) or _regex_text(xml_text, "WorkingDirectory")
    class_id = _regex_text(xml_text, "ClassId")
    data = _regex_text(xml_text, "Data")
    trigger_types = re.findall(r"<(?:\w+:)?([A-Za-z]+Trigger)\b", xml_text)
    trigger_summary = " | ".join(dict.fromkeys(trigger_types)) or None
    actions: list[dict] = []
    if command or arguments or working_directory:
        actions.append({"type": "Exec", "command": command, "arguments": arguments, "working_directory": working_directory})
    if class_id or data:
        actions.append({"type": "ComHandler", "class_id": class_id, "data": data})
    action_summary = None
    if command:
        action_summary = f"Exec: {command} {arguments or ''}".strip()
    elif class_id:
        action_summary = f"ComHandler: {class_id}"
    row = {
        "TaskName": task_name,
        "TaskPath": task_path,
        "SourceFile": source_path or str(path),
        "OriginalPath": source_path or str(path),
        "SourceFileMtime": parse_isoish_timestamp(datetime.fromtimestamp(stat.st_mtime, tz=UTC).isoformat()),
        "Author": _regex_text(xml_text, "Author"),
        "Description": _regex_text(xml_text, "Description"),
        "Date": _regex_text(xml_text, "Date"),
        "URI": _regex_text(xml_text, "URI"),
        "Source": _regex_text(xml_text, "Source"),
        "Version": _regex_text(xml_text, "Version"),
        "Documentation": _regex_text(xml_text, "Documentation"),
        "SecurityDescriptor": _regex_text(xml_text, "SecurityDescriptor"),
        "UserId": _regex_text(xml_text, "UserId"),
        "GroupId": _regex_text(xml_text, "GroupId"),
        "LogonType": _regex_text(xml_text, "LogonType"),
        "RunLevel": _regex_text(xml_text, "RunLevel"),
        "DisplayName": _regex_text(xml_text, "DisplayName"),
        "Enabled": _regex_text(xml_text, "Enabled"),
        "Hidden": _regex_text(xml_text, "Hidden"),
        "AllowStartOnDemand": _regex_text(xml_text, "AllowStartOnDemand"),
        "DisallowStartIfOnBatteries": _regex_text(xml_text, "DisallowStartIfOnBatteries"),
        "StopIfGoingOnBatteries": _regex_text(xml_text, "StopIfGoingOnBatteries"),
        "MultipleInstancesPolicy": _regex_text(xml_text, "MultipleInstancesPolicy"),
        "RunOnlyIfNetworkAvailable": _regex_text(xml_text, "RunOnlyIfNetworkAvailable"),
        "ExecutionTimeLimit": _regex_text(xml_text, "ExecutionTimeLimit"),
        "Priority": _regex_text(xml_text, "Priority"),
        "StartWhenAvailable": _regex_text(xml_text, "StartWhenAvailable"),
        "WakeToRun": _regex_text(xml_text, "WakeToRun"),
        "Command": command,
        "Arguments": arguments,
        "WorkingDirectory": working_directory,
        "ComHandlerClassId": class_id,
        "ComHandlerData": data,
        "RunAs": _regex_text(xml_text, "UserId") or _regex_text(xml_text, "GroupId"),
        "Actions": json.dumps(actions, ensure_ascii=False),
        "Triggers": json.dumps([{"type": item} for item in dict.fromkeys(trigger_types)], ensure_ascii=False),
        "ActionSummary": action_summary,
        "TriggerSummary": trigger_summary,
        "TaskXml": xml_text[:20000],
        "TaskXmlPreview": _xml_preview(xml_text),
        "TaskXmlEncoding": xml_encoding,
    }
    warnings = ["Task XML was malformed; parsed with best-effort fallback."]
    if not actions:
        warnings.append("Task contains no actions.")
    if not trigger_types:
        warnings.append("Task contains no triggers.")
    return row, warnings


def parse_scheduled_task_xml(path: Path, *, source_path: str | None = None) -> tuple[dict, list[str]]:
    xml_text, xml_encoding = _decode_task_xml_bytes(path.read_bytes())
    parser = ET.XMLParser()
    warnings: list[str] = []
    try:
        root = ET.fromstring(xml_text, parser=parser)
    except ET.ParseError:
        sanitized_xml_text = _sanitize_xml_text(xml_text)
        try:
            root = ET.fromstring(sanitized_xml_text, parser=ET.XMLParser())
            xml_text = sanitized_xml_text
            warnings.append("Task XML required sanitization before parsing.")
        except ET.ParseError:
            return _fallback_parse_task_xml(sanitized_xml_text, path, source_path, xml_encoding=xml_encoding)

    registration = _child(root, "RegistrationInfo")
    principals = _child(root, "Principals")
    principal = _child(principals, "Principal")
    settings = _child(root, "Settings")
    triggers_node = _child(root, "Triggers")
    actions_node = _child(root, "Actions")

    task_path, task_name = infer_task_identity_from_filesystem_path(source_path or str(path))
    triggers: list[dict] = []
    for trigger in _children(triggers_node):
        trigger_type = _local_name(trigger.tag)
        repetition = _child(trigger, "Repetition")
        triggers.append(
            {
                "type": trigger_type,
                "start_boundary": _text(trigger, "StartBoundary"),
                "end_boundary": _text(trigger, "EndBoundary"),
                "enabled": _text(trigger, "Enabled"),
                "delay": _text(trigger, "Delay"),
                "user_id": _text(trigger, "UserId"),
                "subscription": _node_to_text(_child(trigger, "Subscription")),
                "interval": _text(repetition, "Interval"),
                "duration": _text(repetition, "Duration"),
                "days_interval": _text(trigger, "DaysInterval"),
                "weeks_interval": _text(trigger, "WeeksInterval"),
            }
        )

    actions: list[dict] = []
    exec_command = None
    exec_arguments = None
    working_directory = None
    com_handler_class_id = None
    com_handler_data = None
    for action in _children(actions_node):
        action_type = _local_name(action.tag)
        item = {"type": action_type}
        if action_type == "Exec":
            exec_command = normalize_windowsish_path(_text(action, "Command")) or _text(action, "Command")
            exec_arguments = _text(action, "Arguments")
            working_directory = normalize_windowsish_path(_text(action, "WorkingDirectory")) or _text(action, "WorkingDirectory")
            item.update({"command": exec_command, "arguments": exec_arguments, "working_directory": working_directory})
        elif action_type == "ComHandler":
            com_handler_class_id = _text(action, "ClassId")
            com_handler_data = _node_to_text(_child(action, "Data"))
            item.update({"com_handler_class_id": com_handler_class_id, "com_handler_data": com_handler_data})
        elif action_type == "SendEmail":
            item.update(
                {
                    "server": _text(action, "Server"),
                    "subject": _text(action, "Subject"),
                    "to": _text(action, "To"),
                    "from": _text(action, "From"),
                    "body": _text(action, "Body"),
                }
            )
        elif action_type == "ShowMessage":
            item.update({"title": _text(action, "Title"), "body": _text(action, "Body")})
        else:
            item["content"] = _node_to_text(action)
        actions.append(item)

    stat = path.stat()
    row = {
        "TaskName": task_name,
        "TaskPath": task_path,
        "SourceFile": source_path or str(path),
        "OriginalPath": source_path or str(path),
        "SourceFileMtime": parse_isoish_timestamp(datetime.fromtimestamp(stat.st_mtime, tz=UTC).isoformat()),
        "Author": _text(registration, "Author"),
        "Description": _text(registration, "Description"),
        "Date": _text(registration, "Date"),
        "URI": _text(registration, "URI"),
        "Source": _text(registration, "Source"),
        "Version": _text(registration, "Version"),
        "Documentation": _text(registration, "Documentation"),
        "SecurityDescriptor": _text(registration, "SecurityDescriptor"),
        "UserId": _text(principal, "UserId"),
        "GroupId": _text(principal, "GroupId"),
        "LogonType": _text(principal, "LogonType"),
        "RunLevel": _text(principal, "RunLevel"),
        "DisplayName": _text(principal, "DisplayName"),
        "Enabled": _text(settings, "Enabled"),
        "Hidden": _text(settings, "Hidden"),
        "AllowStartOnDemand": _text(settings, "AllowStartOnDemand"),
        "DisallowStartIfOnBatteries": _text(settings, "DisallowStartIfOnBatteries"),
        "StopIfGoingOnBatteries": _text(settings, "StopIfGoingOnBatteries"),
        "MultipleInstancesPolicy": _text(settings, "MultipleInstancesPolicy"),
        "RunOnlyIfNetworkAvailable": _text(settings, "RunOnlyIfNetworkAvailable"),
        "ExecutionTimeLimit": _text(settings, "ExecutionTimeLimit"),
        "Priority": _text(settings, "Priority"),
        "StartWhenAvailable": _text(settings, "StartWhenAvailable"),
        "WakeToRun": _text(settings, "WakeToRun"),
        "Command": exec_command,
        "Arguments": exec_arguments,
        "WorkingDirectory": working_directory,
        "ComHandlerClassId": com_handler_class_id,
        "ComHandlerData": com_handler_data,
        "RunAs": _text(principal, "UserId") or _text(principal, "GroupId"),
        "Actions": json.dumps(actions, ensure_ascii=False),
        "Triggers": json.dumps(triggers, ensure_ascii=False),
        "ActionSummary": " | ".join(
            (
                f"Exec: {exec_command or '?'} {exec_arguments or ''}".strip()
                if exec_command
                else f"ComHandler: {com_handler_class_id}"
                if com_handler_class_id
                else action.get("type", "Action")
            )
            for action in actions
        )
        or None,
        "TriggerSummary": " | ".join(trigger.get("type", "Trigger") for trigger in triggers) or None,
        "TaskXml": xml_text,
        "TaskXmlPreview": _xml_preview(xml_text),
        "TaskXmlEncoding": xml_encoding,
    }
    if not actions:
        warnings.append("Task contains no actions.")
    if not triggers:
        warnings.append("Task contains no triggers.")
    return row, warnings
