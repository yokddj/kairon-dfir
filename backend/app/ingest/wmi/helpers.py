from __future__ import annotations

import json
import re
from pathlib import Path, PureWindowsPath
from urllib.parse import urlparse


WMI_NAME_HINTS = (
    "wmi",
    "wmiparser",
    "eventfilter",
    "eventconsumer",
    "filtertoconsumerbinding",
    "commandlineeventconsumer",
    "activescripteventconsumer",
)
WMI_HEADER_HINTS = {
    "namespace",
    "class",
    "classname",
    "instancename",
    "name",
    "query",
    "querylanguage",
    "eventnamespace",
    "creatorsid",
    "consumer",
    "filter",
    "commandlinetemplate",
    "executablepath",
    "workingdirectory",
    "scripttext",
    "scriptingengine",
    "path",
    "relpath",
    "class",
    "consumername",
    "filtername",
    "binding",
    "sourcefile",
    "lastwritetime",
    "timestamp",
}
SUSPICIOUS_CONSUMER_TOKENS = {
    "powershell",
    "cmd.exe",
    "wscript",
    "cscript",
    "mshta",
    "rundll32",
    "regsvr32",
    "certutil",
    "bitsadmin",
    "curl",
    "wget",
    "schtasks",
    "reg.exe",
}
SUSPICIOUS_COMMAND_TOKENS = {
    "-enc",
    "encodedcommand",
    "bypass",
    "hidden",
    "downloadstring",
    "invoke-expression",
    "iwr",
    "irm",
    "frombase64string",
    "add-mppreference",
    "set-mppreference",
    "disableantispyware",
    "http://",
    "https://",
    "\\\\",
    "\\appdata\\",
    "\\temp\\",
    "\\programdata\\",
    "\\users\\public\\",
}
SUSPICIOUS_QUERY_TOKENS = {
    "__instancemodificationevent": "registry_trigger",
    "__instancecreationevent": "process_trigger",
    "__timerevent": "timer_trigger",
    "win32_processstarttrace": "process_trigger",
    "registryvaluechangeevent": "registry_trigger",
    "win32_perfformatteddata_perfos_system": "timer_trigger",
}
URL_RE = re.compile(r"https?://[^\s\"'>]+", re.IGNORECASE)
UNC_RE = re.compile(r"\\\\[A-Za-z0-9_.-]+\\[^\s\"'>]+")
PATH_RE = re.compile(r"[A-Za-z]:\\[^\s\"'>]+")


def canonicalize_header(value: object) -> str:
    return re.sub(r"[^a-z0-9]+", "", str(value).strip().lower())


def normalize_windows_path(value: str | None) -> str | None:
    if value in (None, ""):
        return None
    normalized = str(value).strip().strip('"').strip("'")
    if normalized.lower() in {"-", "--", "n/a", "na", "(null)", "null", "none", "unknown"}:
        return None
    return normalized.replace("/", "\\")


def basename_windows(path: str | None) -> str | None:
    normalized = normalize_windows_path(path)
    if not normalized:
        return None
    try:
        return PureWindowsPath(normalized).name or normalized
    except Exception:  # noqa: BLE001
        return Path(normalized.replace("\\", "/")).name or normalized


def suffix_windows(path: str | None) -> str | None:
    normalized = normalize_windows_path(path)
    if not normalized:
        return None
    try:
        suffix = PureWindowsPath(normalized).suffix.lower()
        return suffix or None
    except Exception:  # noqa: BLE001
        suffix = Path(normalized.replace("\\", "/")).suffix.lower()
        return suffix or None


def normalize_wmi_namespace(value: str | None) -> str | None:
    normalized = normalize_windows_path(value)
    if not normalized:
        return None
    return normalized.strip("\\")


def normalize_wmi_class(value: str | None) -> str | None:
    if not value:
        return None
    cleaned = str(value).strip().strip('"').strip("'")
    return cleaned or None


def normalize_wmi_path(value: str | None) -> str | None:
    if not value:
        return None
    cleaned = str(value).strip().strip('"').strip("'")
    return cleaned or None


def looks_like_wmi_artifact(path: Path, headers: list[str] | None = None) -> bool:
    suffix = path.suffix.lower()
    lower_name = path.name.lower()
    if suffix not in {".csv", ".json", ".jsonl"}:
        return False
    if any(token in lower_name for token in WMI_NAME_HINTS):
        return True
    header_set = {canonicalize_header(header) for header in (headers or []) if header}
    return len(header_set & WMI_HEADER_HINTS) >= 4


def infer_wmi_artifact_type(row: dict, artifact_meta: dict) -> str:
    artifact_type_hint = str(first_nonempty(row, "ArtifactType", "Type", "EntryType") or "").strip().lower()
    class_name = normalize_wmi_class(first_nonempty(row, "Class", "ClassName", "__CLASS", "ConsumerType"))
    source_name = str(artifact_meta.get("name") or "").lower()
    blob = " ".join(
        str(part or "")
        for part in [
            class_name,
            first_nonempty(row, "Name", "InstanceName", "FilterName", "ConsumerName"),
            first_nonempty(row, "Binding", "Consumer", "Filter"),
            source_name,
        ]
    ).lower()
    if artifact_type_hint in {"wmi_namespace_observed", "namespace_observed"}:
        return "wmi_namespace_observed"
    if artifact_type_hint in {"wmi_filter_consumer_binding", "wmi_event_binding", "wmi_binding"}:
        return "wmi_filter_to_consumer_binding"
    if artifact_type_hint in {"wmi_event_filter", "event_filter"}:
        return "wmi_event_filter"
    if any(token in blob for token in ["filtertoconsumerbinding", "__filtertoconsumerbinding"]):
        return "wmi_filter_to_consumer_binding"
    if artifact_type_hint in {"wmi_event_consumer", "wmi_consumer", "event_consumer"}:
        if any(token in blob for token in ["commandlineeventconsumer", "command line event consumer"]):
            return "wmi_command_line_consumer"
        if any(token in blob for token in ["activescripteventconsumer", "active script event consumer"]):
            return "wmi_active_script_consumer"
        return "wmi_consumer"
    if any(token in blob for token in ["commandlineeventconsumer", "command line event consumer"]):
        return "wmi_command_line_consumer"
    if any(token in blob for token in ["activescripteventconsumer", "active script event consumer"]):
        return "wmi_active_script_consumer"
    if any(token in blob for token in ["eventfilter", "__eventfilter"]):
        return "wmi_event_filter"
    if "eventconsumer" in blob or "consumer" in blob:
        return "wmi_consumer"
    return "wmi_generic"


def first_nonempty(row: dict, *names: str) -> str | None:
    lowered = {str(key).lower(): value for key, value in row.items()}
    canon = {canonicalize_header(key): value for key, value in row.items()}
    for name in names:
        for candidate in (name, name.lower(), canonicalize_header(name)):
            value = lowered.get(candidate) if candidate in lowered else canon.get(candidate)
            if value not in (None, ""):
                return str(value)
    return None


def extract_wmi_names(row: dict) -> dict[str, str | None]:
    name = first_nonempty(row, "Name", "InstanceName")
    filter_name = first_nonempty(row, "FilterName", "Filter")
    consumer_name = first_nonempty(row, "ConsumerName", "Consumer")
    path = normalize_wmi_path(first_nonempty(row, "__PATH", "Path"))
    relpath = normalize_wmi_path(first_nonempty(row, "__RELPATH", "RelPath"))
    if not filter_name and path and "__eventfilter.name=" in path.lower():
        filter_name = path.split("Name=", 1)[-1].strip('"')
    if not consumer_name and path and "consumer" in path.lower() and ".name=" in path.lower():
        consumer_name = path.split("Name=", 1)[-1].strip('"')
    return {
        "name": name,
        "filter_name": filter_name,
        "consumer_name": consumer_name,
        "path": path,
        "relpath": relpath,
    }


def extract_command_from_consumer(command_line: str | None, executable_path: str | None) -> str | None:
    normalized_cmd = str(command_line or "").strip()
    normalized_path = normalize_windows_path(executable_path)
    if normalized_cmd:
        return normalized_cmd
    if normalized_path:
        return normalized_path
    return None


def extract_script_preview(script_text: str | None, *, limit: int = 240) -> str | None:
    if not script_text:
        return None
    cleaned = " ".join(str(script_text).split())
    if len(cleaned) <= limit:
        return cleaned
    return f"{cleaned[:limit]}..."


def extract_urls_domains_paths(*values: str | None) -> dict[str, list[str]]:
    urls: list[str] = []
    domains: list[str] = []
    paths: list[str] = []
    for value in values:
        if not value:
            continue
        text = str(value)
        for match in URL_RE.findall(text):
            if match not in urls:
                urls.append(match)
            domain = urlparse(match).hostname
            if domain and domain not in domains:
                domains.append(domain)
        for match in UNC_RE.findall(text):
            normalized = normalize_windows_path(match)
            if normalized and normalized not in paths:
                paths.append(normalized)
        for match in PATH_RE.findall(text):
            normalized = normalize_windows_path(match)
            if normalized and normalized not in paths:
                paths.append(normalized)
    return {"urls": urls, "domains": domains, "paths": paths}


def decode_creator_sid_if_possible(value: str | None) -> str | None:
    if not value:
        return None
    cleaned = str(value).strip()
    if cleaned.upper().startswith("S-1-"):
        return cleaned
    try:
        payload = json.loads(cleaned)
        if isinstance(payload, dict):
            sid = payload.get("sid") or payload.get("SID")
            return str(sid).strip() if sid else cleaned
    except Exception:  # noqa: BLE001
        pass
    return cleaned


def classify_wmi_suspicion(
    *,
    consumer_type: str | None,
    command_line_template: str | None,
    executable_path: str | None,
    script_text: str | None,
    query: str | None,
    has_binding: bool,
    creator_sid: str | None,
) -> tuple[set[str], list[str], int]:
    tags = {"wmi"}
    reasons: list[str] = []
    risk = 0
    consumer_blob = f"{consumer_type or ''} {command_line_template or ''} {executable_path or ''}".lower()
    script_blob = str(script_text or "").lower()
    query_blob = str(query or "").lower()

    if has_binding:
        tags.update({"persistence", "wmi_binding", "wmi_persistence_candidate"})
        reasons.append("WMI filter-to-consumer binding observed")
        risk = max(risk, 35)
    if consumer_type and "commandlineeventconsumer" in consumer_type.lower():
        tags.update({"command_line_consumer", "wmi_consumer"})
        reasons.append("WMI CommandLineEventConsumer observed")
        risk = max(risk, 20)
    if consumer_type and "activescripteventconsumer" in consumer_type.lower():
        tags.update({"active_script_consumer", "script_execution"})
        reasons.append("WMI ActiveScriptEventConsumer observed")
        risk = max(risk, 35)
    if any(token in consumer_blob for token in SUSPICIOUS_CONSUMER_TOKENS):
        tags.update({"suspicious_command", "wmi_consumer"})
        if "powershell" in consumer_blob or "pwsh" in consumer_blob:
            reasons.append("WMI consumer executes PowerShell")
        else:
            reasons.append("WMI CommandLineEventConsumer observed")
        risk = max(risk, 65)
    if any(token in consumer_blob for token in SUSPICIOUS_COMMAND_TOKENS) or any(token in script_blob for token in SUSPICIOUS_COMMAND_TOKENS):
        if "-enc" in consumer_blob or "encodedcommand" in consumer_blob:
            tags.add("encoded_powershell")
            reasons.append("WMI consumer executes PowerShell")
            risk = max(risk, 80)
        if "bypass" in consumer_blob:
            reasons.append("WMI consumer uses execution policy bypass")
            risk = max(risk, 75)
        if "hidden" in consumer_blob:
            reasons.append("WMI consumer uses hidden window")
            risk = max(risk, 70)
        if "http://" in consumer_blob or "https://" in consumer_blob or "http://" in script_blob or "https://" in script_blob:
            tags.add("download_command")
            reasons.append("WMI consumer command contains URL")
            risk = max(risk, 70)
        if any(token in consumer_blob or token in script_blob for token in ["\\appdata\\", "\\temp\\", "\\programdata\\", "\\users\\public\\"]):
            reasons.append("WMI consumer command uses user-writable path")
            risk = max(risk, 60)
    if any(token in script_blob for token in ["createobject(\"wscript.shell\")", "createobject('wscript.shell')", "powershell", "cmd.exe", "frombase64string", "downloadstring"]):
        reasons.append("WMI consumer uses suspicious script content")
        risk = max(risk, 70)
    for token, tag in SUSPICIOUS_QUERY_TOKENS.items():
        if token in query_blob:
            tags.add(tag)
            reasons.append("WMI permanent event subscription observed")
            risk = max(risk, 45)
    if re.search(r"\bwithin\s+(?:[1-9]|10)\b", query_blob):
        tags.add("timer_trigger")
        reasons.append("WMI permanent event subscription observed")
        risk = max(risk, 50)
    if creator_sid and not str(creator_sid).upper().startswith("S-1-5-18"):
        risk = max(risk, 20)
    if not has_binding and "__eventfilter" in (consumer_type or "").lower():
        risk = max(risk, 10)
    return tags, list(dict.fromkeys(reasons)), risk


def classify_wmi_activity_event(row: dict) -> dict[str, str | list[str] | int | None]:
    event_id_raw = first_nonempty(row, "EventID", "EventId", "Id")
    event_id = int(event_id_raw) if event_id_raw and str(event_id_raw).isdigit() else None
    channel = first_nonempty(row, "Channel", "LogName")
    provider = first_nonempty(row, "Provider", "ProviderName", "SourceName")
    operation = first_nonempty(row, "Operation")
    query = first_nonempty(row, "Query")
    consumer = first_nonempty(row, "Consumer")
    result_code = first_nonempty(row, "ResultCode")
    possible_cause = first_nonempty(row, "PossibleCause")
    tags = ["wmi"]
    event_type = "wmi_activity"
    message = f"WMI activity observed: event {event_id or 'unknown'}"
    if event_id in {5857, 5858, 5859}:
        event_type = "wmi_query"
        message = f"WMI query observed: {query or operation or 'WMI query'}"
    elif event_id in {5860, 5861}:
        event_type = "wmi_consumer_binding"
        message = f"WMI consumer/binding activity observed: {consumer or operation or 'WMI activity'}"
    if result_code or possible_cause:
        event_type = "wmi_error"
        message = f"WMI activity error: {possible_cause or result_code or operation or 'WMI activity'}"
    return {
        "event_id": event_id,
        "channel": channel,
        "provider": provider,
        "event_type": event_type,
        "action": event_type,
        "severity": "low" if event_type == "wmi_error" else "info",
        "message": message,
        "tags": tags,
    }


__all__ = [
    "basename_windows",
    "canonicalize_header",
    "classify_wmi_activity_event",
    "classify_wmi_suspicion",
    "decode_creator_sid_if_possible",
    "extract_command_from_consumer",
    "extract_script_preview",
    "extract_urls_domains_paths",
    "extract_wmi_names",
    "first_nonempty",
    "infer_wmi_artifact_type",
    "looks_like_wmi_artifact",
    "normalize_windows_path",
    "normalize_wmi_class",
    "normalize_wmi_namespace",
    "normalize_wmi_path",
    "suffix_windows",
]
