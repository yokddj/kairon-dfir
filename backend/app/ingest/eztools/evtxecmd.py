from collections.abc import Iterable
from datetime import UTC
import hashlib
import json
import logging
from pathlib import Path
import re
from uuid import uuid4
from xml.etree import ElementTree as ET

from dateutil import parser as date_parser

from app.analysis.suspicious import detect_suspicious_path, detect_suspicious_powershell
from app.ingest.eztools.base import ArtifactParser, read_delimited_rows
from app.ingest.windows_event_catalog import classify_windows_event as classify_windows_event_catalog
from app.services.host_attribution import classify_host_candidate


logger = logging.getLogger(__name__)
PAYLOAD_PREFIX = "payloaddata"
WINDOWS_EMPTY_VALUES = {"", "-", "n/a", "na", "(null)", "null", "%%", "%%0"}


def _canonicalize_key(value: object) -> str:
    return re.sub(r"[^a-z0-9]+", "", str(value).strip().lower())


def _normalize_row_keys(row: dict) -> tuple[dict[str, object], dict[str, object]]:
    raw = {str(key): value for key, value in row.items()}
    lowered = {_canonicalize_key(key): value for key, value in raw.items()}
    return raw, lowered


def _get(lowered: dict[str, object], *names: str) -> str | None:
    for name in names:
        value = lowered.get(_canonicalize_key(name))
        if value not in (None, ""):
            return str(value)
    return None


def _normalize_windows_value(value: object, *, allow_zero_ip: bool = False) -> object | None:
    if value is None:
        return None
    if isinstance(value, str):
        normalized = value.strip()
        if normalized.lower() in WINDOWS_EMPTY_VALUES:
            return None
        if normalized == "0.0.0.0" and not allow_zero_ip:
            return None
        return normalized
    return value


def _parse_boolish(value: object | None) -> bool | None:
    normalized = _normalize_windows_value(value)
    if normalized is None:
        return None
    lowered = str(normalized).strip().lower()
    if lowered in {"true", "yes", "1", "enabled"}:
        return True
    if lowered in {"false", "no", "0", "disabled"}:
        return False
    return None


def _parse_timestamp(value: str | None) -> tuple[str | None, str]:
    if not value:
        return None, "unknown"
    try:
        parsed = date_parser.parse(value)
        if parsed.tzinfo is None:
            parsed = parsed.replace(tzinfo=UTC)
        return parsed.isoformat(), "exact"
    except Exception:  # noqa: BLE001
        return None, "unknown"


def _basename(path: str | None) -> str | None:
    if not path:
        return None
    return Path(path.replace("\\", "/")).name or None


def _parent_path(path: str | None) -> str | None:
    if not path:
        return None
    current = str(path).replace("/", "\\")
    if "\\" not in current:
        return None
    parent = current.rsplit("\\", 1)[0]
    return parent or None


def _stable_process_entity_id(case_id: str, host_name: str | None, timestamp: str | None, pid: str | None, process_path: str | None) -> str:
    blob = "|".join(str(part or "") for part in (case_id, host_name, timestamp, pid, process_path))
    return f"security:{hashlib.sha1(blob.encode('utf-8', errors='ignore')).hexdigest()}"


def _extract_payload(raw: dict[str, object], lowered: dict[str, object]) -> dict[str, object]:
    payload: dict[str, object] = {}
    for key, value in raw.items():
        if str(key).strip().lower().startswith(PAYLOAD_PREFIX) and value not in (None, ""):
            payload[str(key)] = value
    payload_field = _get(lowered, "Payload")
    if payload_field:
        payload["Payload"] = payload_field
    return payload


def _flatten_payload_item(item: object) -> dict[str, object]:
    extracted: dict[str, object] = {}
    if isinstance(item, list):
        for child in item:
            extracted.update(_flatten_payload_item(child))
        return extracted
    if not isinstance(item, dict):
        return extracted

    name = item.get("@Name") or item.get("Name") or item.get("name")
    text = item.get("#text")
    if name is not None:
        if text is not None:
            extracted[str(name)] = text
        else:
            nested = {key: value for key, value in item.items() if key not in {"@Name", "Name", "name"}}
            extracted[str(name)] = nested or None
    for key, value in item.items():
        if key in {"@Name", "Name", "name", "#text"}:
            continue
        extracted.update(_flatten_payload_item(value))
    return extracted


def parse_evtx_payload_json(payload_text: str | None) -> dict[str, object]:
    if not payload_text:
        return {}
    try:
        parsed = json.loads(payload_text)
    except Exception:  # noqa: BLE001
        return {}
    extracted = _flatten_payload_item(parsed)
    if extracted:
        return extracted
    if isinstance(parsed, dict):
        event_data = parsed.get("EventData")
        if isinstance(event_data, dict):
            extracted.update(_flatten_payload_item(event_data.get("Data")))
        user_data = parsed.get("UserData")
        if user_data is not None:
            extracted.update(_flatten_payload_item(user_data))
            if isinstance(user_data, dict):
                for provider_block in user_data.values():
                    if isinstance(provider_block, dict):
                        for key, value in provider_block.items():
                            if not isinstance(value, (dict, list)):
                                extracted.setdefault(str(key), value)
    return extracted


def _extract_xml_fields(xml_text: str | None) -> dict[str, object]:
    if not xml_text:
        return {}
    try:
        root = ET.fromstring(xml_text)
    except Exception:  # noqa: BLE001
        return {}
    fields: dict[str, object] = {}
    for data_node in root.findall(".//EventData/Data"):
        name = data_node.attrib.get("Name") or data_node.attrib.get("name")
        text = (data_node.text or "").strip()
        if name and text:
            fields[name] = text
    for child in root.findall(".//UserData//*"):
        tag = child.tag.split("}")[-1]
        text = (child.text or "").strip()
        if text:
            fields[tag] = text
        for key, value in child.attrib.items():
            fields[f"{tag}.{key}"] = value
    for parent_path, prefix in [
        (".//System/Execution", ""),
        (".//System/Security", ""),
        (".//System/Correlation", "Correlation."),
    ]:
        node = root.find(parent_path)
        if node is None:
            continue
        for key, value in node.attrib.items():
            fields[f"{prefix}{key}"] = value
    return fields


def _merge_event_data(lowered: dict[str, object], xml_fields: dict[str, object], payload: dict[str, object]) -> dict[str, object]:
    event_data = dict(xml_fields)
    payload_json_fields = parse_evtx_payload_json(str(payload.get("Payload")) if payload.get("Payload") not in (None, "") else None)
    for key, value in payload_json_fields.items():
        event_data.setdefault(key, value)
    explicit_columns = [
        "TargetUserName", "TargetDomainName", "TargetUserSid", "TargetLogonId", "TargetServerName",
        "SubjectUserName", "SubjectDomainName", "SubjectUserSid", "SubjectLogonId",
        "LogonType", "LogonId", "IpAddress", "IpPort", "WorkstationName", "LogonProcessName", "AuthenticationPackageName",
        "ProcessName", "NewProcessName", "Image", "ProcessCommandLine", "CommandLine", "ParentProcessName", "ParentImage", "CreatorProcessName", "ParentCommandLine",
        "ProcessGuid", "ParentProcessGuid", "NewProcessId", "CreatorProcessId", "ParentProcessId", "ProcessId",
        "CurrentDirectory", "TokenElevationType", "MandatoryLabel", "IntegrityLevel", "Hashes",
        "ServiceName", "ServiceFileName", "ImagePath", "ServiceType", "ServiceStartType", "StartType", "AccountName",
        "TaskName", "TaskContent", "ActionName", "UserContext", "WorkingDirectory", "Author", "UserId",
        "MemberName", "TargetSid", "ShareName", "ShareLocalPath", "RelativeTargetName", "AccessMask", "Application",
        "SourceAddress", "SourceIp", "SourcePort", "DestAddress", "DestinationAddress", "DestinationIp", "DestinationHostname", "DestinationHostName", "DestinationPort", "Protocol", "Direction", "Initiated",
        "State", "PreviousStartType", "HostName", "HostApplication", "EngineVersion", "RunspaceId", "CommandInvocation",
        "ParameterBinding", "ContextInfo", "ScriptBlockText", "ScriptBlockId", "Path", "MessageNumber", "MessageTotal",
        "User", "Domain", "Address", "SourceNetworkAddress", "ClientAddress", "ClientName", "SessionName", "SessionID",
        "ThreatName", "ThreatID", "Severity", "Category", "Action", "DetectionUser", "ErrorCode",
        "ClientProcessId", "ClientMachine", "ClientIP", "Namespace", "Query", "Operation", "Consumer", "Filter",
        "ShellId", "CommandId", "ResourceUri", "Plugin", "Reason", "Status", "SubStatus", "FailureReason",
        "TicketEncryptionType", "FailureCode", "Workstation", "ServiceName",
        "TargetFilename", "ImageLoaded", "Signed", "Signature", "SignatureStatus", "CreationUtcTime",
        "TargetObject", "Details", "EventType", "QueryName", "QueryResults", "QueryStatus",
        "TargetImage", "TargetProcessGuid", "TargetProcessId", "GrantedAccess", "CallTrace",
        "StartAddress", "StartModule", "StartFunction",
        "ObjectName", "ObjectType", "ObjectServer", "Accesses", "AccessMask", "AccessReason",
    ]
    for name in explicit_columns:
        value = _get(lowered, name)
        if value and name not in event_data:
            event_data[name] = value
    if payload:
        event_data["payload_columns"] = payload
    return event_data


def _parse_event_id(value: object | None) -> int | None:
    if value is None:
        return None
    text = str(value).strip()
    if not text:
        return None
    if text.isdigit():
        return int(text)
    match = re.search(r"\b(\d+)\b", text)
    if match:
        try:
            return int(match.group(1))
        except ValueError:
            return None
    return None


def _to_intish(value: object | None) -> int | None:
    normalized = _normalize_windows_value(value)
    if normalized is None:
        return None
    text = str(normalized).strip()
    if not text:
        return None
    try:
        if text.lower().startswith("0x"):
            return int(text, 16)
        return int(text, 10)
    except (TypeError, ValueError):
        match = re.search(r"\b(0x[0-9a-fA-F]+|\d+)\b", text)
        if not match:
            return None
        token = match.group(1)
        try:
            if token.lower().startswith("0x"):
                return int(token, 16)
            return int(token, 10)
        except (TypeError, ValueError):
            return None


def _account_display(domain: object | None, user: object | None) -> str:
    normalized_user = _normalize_windows_value(user)
    normalized_domain = _normalize_windows_value(domain)
    if normalized_domain and normalized_user:
        return f"{normalized_domain}\\{normalized_user}"
    if normalized_user:
        return str(normalized_user)
    return "unknown user"


def _logon_source_text(ip_value: object | None) -> str:
    normalized_ip = _normalize_windows_value(ip_value)
    return str(normalized_ip) if normalized_ip else "local host"


def _extract_task_command(task_content: object | None) -> tuple[str | None, str | None]:
    text = str(task_content or "").strip()
    if not text:
        return None, None
    command_match = re.search(r"<Command>(.*?)</Command>", text, flags=re.IGNORECASE | re.DOTALL)
    arguments_match = re.search(r"<Arguments>(.*?)</Arguments>", text, flags=re.IGNORECASE | re.DOTALL)
    command = command_match.group(1).strip() if command_match else None
    arguments = arguments_match.group(1).strip() if arguments_match else None
    return _normalize_windows_value(command), _normalize_windows_value(arguments)


def _normalize_task_xml_fields(event_data: dict[str, object]) -> None:
    command, arguments = _extract_task_command(event_data.get("TaskContent"))
    if command and not event_data.get("Command"):
        event_data["Command"] = command
    if arguments and not event_data.get("Arguments"):
        event_data["Arguments"] = arguments
    text = str(event_data.get("TaskContent") or "").strip()
    if not text:
        return
    extra_tags = {"WorkingDirectory": "WorkingDirectory", "Author": "Author", "UserId": "UserId"}
    for key, tag in extra_tags.items():
        if event_data.get(key):
            continue
        match = re.search(rf"<{tag}>(.*?)</{tag}>", text, flags=re.IGNORECASE | re.DOTALL)
        if match:
            event_data[key] = match.group(1).strip()


def _user_domain(event_data: dict[str, object]) -> tuple[str | None, str | None]:
    if event_data.get("TargetUserName"):
        return _normalize_windows_value(event_data.get("TargetUserName")), _normalize_windows_value(event_data.get("TargetDomainName"))
    if event_data.get("SubjectUserName"):
        return _normalize_windows_value(event_data.get("SubjectUserName")), _normalize_windows_value(event_data.get("SubjectDomainName"))
    if event_data.get("User"):
        return _normalize_windows_value(event_data.get("User")), _normalize_windows_value(event_data.get("Domain"))
    user_id = str(event_data.get("UserId") or "")
    if "\\" in user_id:
        domain, user = user_id.split("\\", 1)
        return user, domain
    return None, None


def _derive_file_info(event_data: dict[str, object]) -> dict[str, str | None]:
    candidate = event_data.get("Path") or event_data.get("ServiceFileName") or event_data.get("ImagePath") or event_data.get("NewProcessName") or event_data.get("ProcessName")
    if not candidate:
        return {"path": None, "name": None, "extension": None}
    path = str(candidate)
    name = _basename(path)
    extension = Path(name).suffix.lower() if name and "." in name else None
    return {"path": path, "name": name, "extension": extension}


def _build_message(event_id: int | None, event_data: dict[str, object], provider: str | None, channel: str | None, map_description: str | None, message: str | None, *, source_match: bool) -> str:
    fallback = map_description or message or f"Windows event {event_id or 'unknown'}"
    if not source_match:
        return fallback or f"Windows event {event_id or 'unknown'} from {provider or channel or '?'}"
    if event_id == 4624:
        return f"Successful logon: {_account_display(event_data.get('TargetDomainName'), event_data.get('TargetUserName'))} (LogonType {event_data.get('LogonType') or '?'}) from {_logon_source_text(event_data.get('IpAddress'))}"
    if event_id == 4625:
        failure = " ".join(str(value) for value in [event_data.get("FailureReason"), event_data.get("Status"), event_data.get("SubStatus")] if value not in (None, ""))
        suffix = f" [{failure}]" if failure else ""
        return f"Failed logon: {_account_display(event_data.get('TargetDomainName'), event_data.get('TargetUserName'))} (LogonType {event_data.get('LogonType') or '?'}) from {_logon_source_text(event_data.get('IpAddress'))}{suffix}"
    if event_id == 4648:
        return f"Explicit credentials logon: {_account_display(event_data.get('SubjectDomainName'), event_data.get('SubjectUserName'))} -> {_account_display(event_data.get('TargetDomainName'), event_data.get('TargetUserName'))} via {event_data.get('ProcessName') or '?'}"
    if event_id == 4688:
        process_name = _basename(str(event_data.get("NewProcessName") or event_data.get("ProcessName") or "")) or "?"
        command = str(event_data.get("ProcessCommandLine") or event_data.get("CommandLine") or "").strip()
        return f"Process created: {process_name} by {_account_display(event_data.get('SubjectDomainName'), event_data.get('SubjectUserName'))}{f' - {command[:220]}' if command else ''}"
    if event_id in {4697, 7045}:
        return f"Service created: {event_data.get('ServiceName') or '?'} -> {event_data.get('ServiceFileName') or event_data.get('ImagePath') or '?'}"
    if event_id in {4698, 4702, 106, 140, 141}:
        command, arguments = _extract_task_command(event_data.get("TaskContent"))
        command_text = " ".join(part for part in [command, arguments] if part) or "task content unavailable"
        return f"Scheduled task changed: {event_data.get('TaskName') or '?'} -> {command_text}"
    if event_id == 4104:
        script = str(event_data.get("ScriptBlockText") or "").strip().replace("\r", " ").replace("\n", " ")
        preview = f"{script[:160]}..." if len(script) > 160 else script
        return f"PowerShell script block {event_data.get('MessageNumber') or '?'}/{event_data.get('MessageTotal') or '?'}: {preview}"
    if event_id == 4103:
        invocation = str(event_data.get("CommandInvocation") or event_data.get("Payload") or "").strip().replace("\r", " ").replace("\n", " ")
        preview = f"{invocation[:160]}..." if len(invocation) > 160 else invocation
        return f"PowerShell module logging: {preview or 'PowerShell activity'}"
    if event_id == 5156:
        destination = event_data.get("DestAddress") or event_data.get("DestinationAddress") or "?"
        return f"Network connection allowed: {event_data.get('Application') or '?'} {event_data.get('SourceAddress') or '?'}->{destination}"
    if event_id == 1116:
        return f"Defender malware detected: {event_data.get('ThreatName') or '?'}"
    return fallback or f"Windows event {event_id or 'unknown'} from {provider or channel or '?'}"


def _severity(level: str | None, fallback_severity: str, suspicious_reasons: list[str], *, source_match: bool) -> str:
    lowered = (level or "").strip().lower()
    if lowered in {"critical", "error", "warning", "information", "informational"}:
        mapping = {"critical": "critical", "error": "high", "warning": "medium", "information": "info", "informational": "info"}
        severity = mapping[lowered]
    else:
        severity = fallback_severity or "info"
    if not source_match and severity not in {"high", "critical"}:
        severity = "info"
    if suspicious_reasons and severity in {"info", "low"}:
        severity = "medium"
    return severity


def _document_base(case_id: str, evidence_id: str, artifact_id: str, source_file: str, raw_row: dict, timestamp: str | None, timestamp_type: str, artifact_meta: dict) -> dict:
    return {
        "event_id": str(uuid4()),
        "case_id": case_id,
        "evidence_id": evidence_id,
        "artifact_id": artifact_id,
        "ingest_run_id": artifact_meta.get("ingest_run_id"),
        "contract_version": artifact_meta.get("contract_version", "v1"),
        "@timestamp": timestamp,
        "timestamp_precision": timestamp_type,
        "timezone": "UTC" if timestamp else "unknown",
        "host": {"name": None, "hostname": None, "ip": [], "os": "Windows"},
        "user": {"name": None, "domain": None, "sid": None, "logon_id": None},
        "source": {"ip": None, "port": None, "hostname": None},
        "destination": {"ip": None, "port": None, "hostname": None},
        "artifact": {
            "type": artifact_meta.get("artifact_type", "evtx"),
            "name": artifact_meta.get("name", source_file),
            "source_path": artifact_meta.get("source_path", source_file),
            "parser": artifact_meta.get("parser", "zimmerman"),
        },
        "event": {
            "category": "windows_event",
            "type": "unknown",
            "action": "evtx_event",
            "provider": None,
            "channel": None,
            "severity": "info",
            "message": artifact_meta.get("name", source_file),
            "timeline_include": False,
        },
        "windows": {
            "event_id": None,
            "provider": None,
            "channel": None,
            "computer": None,
            "record_number": None,
            "process_id": None,
            "thread_id": None,
            "event_data": {},
            "payload": {},
            "raw_xml": None,
            "logon_type": None,
            "service_name": None,
            "task_name": None,
            "authentication_package": None,
            "logon_process": None,
            "status": None,
            "sub_status": None,
            "failure_reason": None,
            "session_id": None,
            "session_name": None,
            "reason": None,
        },
        "process": {
            "entity_id": None,
            "pid": None,
            "name": None,
            "path": None,
            "command_line": None,
            "current_directory": None,
            "parent_entity_id": None,
            "parent_pid": None,
            "ppid": None,
            "parent_name": None,
            "parent_path": None,
            "parent_command_line": None,
            "integrity_level": None,
            "hashes": {"md5": None, "sha1": None, "sha256": None},
            "token_elevation": None,
        },
        "execution": {
            "source": None,
            "run_count": None,
            "first_run": None,
            "last_run": None,
            "last_runs": [],
            "program_name": None,
            "confidence": None,
            "is_execution_confirmed": None,
            "interpretation": None,
            "first_seen": None,
            "last_seen": None,
            "last_modified": None,
            "install_date": None,
            "compile_time": None,
        },
        "file": {"path": None, "name": None, "extension": None, "size": None, "hash_sha1": None, "hash_sha256": None, "sha1": None, "sha256": None, "md5": None},
        "object": {"name": None, "path": None, "type": None, "server": None},
        "access": {"mask": None, "list": [], "accesses": [], "reason": None},
        "registry": {"hive": None, "key": None, "value_name": None, "value_data": None},
        "network": {"protocol": None, "direction": None, "application": None, "bytes_sent": None, "bytes_received": None, "source_ip": None, "source_port": None, "destination_ip": None, "destination_port": None, "share_name": None, "share_local_path": None, "relative_target_name": None},
        "detection": {"threat_name": None, "threat_id": None, "severity": None, "category": None, "action": None, "path": None, "error_code": None},
        "task": {"name": None, "path": None, "command": None, "arguments": None, "author": None, "run_as": None, "trigger": None, "enabled": None, "content": None, "working_directory": None, "action": None},
        "service": {"name": None, "display_name": None, "image_path": None, "start_type": None, "service_type": None, "account": None},
        "powershell": {},
        "winrm": {"shell_id": None, "command_id": None, "resource_uri": None, "plugin": None, "operation": None},
        "tags": [],
        "data_quality": [],
        "risk_score": 0,
        "raw_summary": "",
        "search_text": "",
        "raw": raw_row,
        "suspicious_reasons": [],
        "source_file": source_file,
        "source_tool": "evtxecmd",
        "source_format": "csv",
    }


def _build_search_text(document: dict) -> str:
    values: list[str] = []
    candidates = [
        document.get("event", {}).get("message"),
        document.get("host", {}).get("name"),
        document.get("user", {}).get("name"),
        document.get("artifact", {}).get("name"),
        document.get("artifact", {}).get("type"),
        document.get("artifact", {}).get("source_path"),
        document.get("process", {}).get("name"),
        document.get("process", {}).get("command_line"),
        document.get("process", {}).get("path"),
        document.get("file", {}).get("path"),
        document.get("file", {}).get("name"),
        document.get("file", {}).get("extension"),
        document.get("file", {}).get("sha256"),
        document.get("file", {}).get("sha1"),
        document.get("file", {}).get("md5"),
        document.get("object", {}).get("name"),
        document.get("object", {}).get("path"),
        document.get("object", {}).get("type"),
        document.get("access", {}).get("mask"),
        " | ".join(document.get("access", {}).get("list") or []),
        document.get("access", {}).get("reason"),
        document.get("network", {}).get("source_ip"),
        document.get("network", {}).get("destination_ip"),
        document.get("destination", {}).get("hostname"),
        document.get("destination", {}).get("ip"),
        document.get("dns", {}).get("query") if isinstance(document.get("dns"), dict) else None,
        document.get("dns", {}).get("domain") if isinstance(document.get("dns"), dict) else None,
        document.get("registry", {}).get("path"),
        document.get("registry", {}).get("key_path"),
        document.get("registry", {}).get("value_data"),
        document.get("windows", {}).get("event_id"),
        document.get("windows", {}).get("channel"),
        document.get("windows", {}).get("provider"),
    ]
    for value in candidates:
        if value not in (None, ""):
            values.append(str(value))
    return " | ".join(values)[:8192]


def _compact(value: dict) -> dict:
    return {key: item for key, item in value.items() if item not in (None, "", [], {})}


def _split_domain_user(value: object | None) -> tuple[str | None, str | None]:
    normalized = _normalize_windows_value(value)
    if normalized is None:
        return None, None
    text = str(normalized)
    if "\\" in text:
        domain, name = text.split("\\", 1)
        return _normalize_windows_value(name), _normalize_windows_value(domain)
    if "@" in text:
        name, domain = text.split("@", 1)
        return _normalize_windows_value(name), _normalize_windows_value(domain)
    return text, None


def _parse_hashes(value: object | None, event_data: dict[str, object]) -> dict[str, str | None]:
    hashes = {
        "md5": _normalize_windows_value(event_data.get("MD5")),
        "sha1": _normalize_windows_value(event_data.get("SHA1")),
        "sha256": _normalize_windows_value(event_data.get("SHA256")),
    }
    text = _normalize_windows_value(value)
    if not text:
        return hashes
    for fragment in re.split(r"[;,|]", str(text)):
        if "=" not in fragment:
            continue
        name, raw_hash = fragment.split("=", 1)
        key = name.strip().lower()
        clean_hash = re.sub(r"[^0-9a-fA-F]", "", raw_hash).lower()
        if key in hashes and len(clean_hash) in {32, 40, 64}:
            hashes[key] = clean_hash
    return hashes


def _path_details(path: object | None) -> tuple[str | None, str | None, str | None, str | None]:
    normalized = _normalize_windows_value(path)
    if normalized is None:
        return None, None, None, None
    text = str(normalized)
    name = _basename(text)
    parent = _parent_path(text)
    extension = None
    if name and "." in name:
        extension = "." + name.rsplit(".", 1)[-1].lower()
    return text, name, parent, extension


def _apply_sysmon_normalization(document: dict, event_id: int | None, event_data: dict[str, object], provider: str | None, channel: str | None) -> None:
    if "sysmon" not in str(provider or "").lower() and "sysmon" not in str(channel or "").lower():
        return

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
    document["event"].update({"category": category, "type": action, "action": action, "message": default_message})
    document["artifact"]["type"] = "windows_event"
    document["windows"]["event_data"] = event_data
    document["winlog"] = {"event_data": event_data}
    document["tags"] = sorted(set(document.get("tags", [])) | {"sysmon"})

    user_name, user_domain = _split_domain_user(event_data.get("User"))
    if user_name:
        document["user"]["name"] = user_name
    if user_domain:
        document["user"]["domain"] = user_domain

    image = _normalize_windows_value(event_data.get("Image") or event_data.get("SourceImage"))
    process_path, process_name, _, _ = _path_details(image)
    command_line = _normalize_windows_value(event_data.get("CommandLine"))
    process_hashes = _parse_hashes(event_data.get("Hashes"), event_data)
    document["process"].update(
        _compact(
            {
                "entity_id": _normalize_windows_value(event_data.get("ProcessGuid") or event_data.get("SourceProcessGuid")),
                "guid": _normalize_windows_value(event_data.get("ProcessGuid") or event_data.get("SourceProcessGuid")),
                "pid": _to_intish(event_data.get("ProcessId") or event_data.get("SourceProcessId")),
                "name": process_name,
                "path": process_path,
                "executable": process_path,
                "command_line": command_line,
                "current_directory": _normalize_windows_value(event_data.get("CurrentDirectory")),
                "working_directory": _normalize_windows_value(event_data.get("CurrentDirectory")),
                "integrity_level": _normalize_windows_value(event_data.get("IntegrityLevel")),
                "hashes": process_hashes if any(process_hashes.values()) else None,
                "hash": process_hashes if any(process_hashes.values()) else None,
            }
        )
    )
    if event_data.get("LogonId"):
        document["logon"] = {"id": _normalize_windows_value(event_data.get("LogonId"))}

    parent_image = _normalize_windows_value(event_data.get("ParentImage"))
    parent_path, parent_name, _, _ = _path_details(parent_image)
    parent_payload = _compact(
        {
            "entity_id": _normalize_windows_value(event_data.get("ParentProcessGuid")),
            "guid": _normalize_windows_value(event_data.get("ParentProcessGuid")),
            "pid": _to_intish(event_data.get("ParentProcessId")),
            "name": parent_name,
            "path": parent_path,
            "executable": parent_path,
            "command_line": _normalize_windows_value(event_data.get("ParentCommandLine")),
        }
    )
    if parent_payload:
        document["process"]["parent"] = parent_payload
        document["parent"] = {"process": dict(parent_payload)}
        document["process"].update({"parent_entity_id": parent_payload.get("entity_id"), "parent_pid": parent_payload.get("pid"), "ppid": parent_payload.get("pid"), "parent_name": parent_name, "parent_path": parent_path, "parent_command_line": parent_payload.get("command_line")})

    if event_id == 1:
        document["execution"].update({"source": "sysmon_process_creation", "is_execution_confirmed": True, "confidence": "high", "program_name": process_name, "interpretation": "Sysmon Event ID 1 confirms process creation"})
        document["event"]["message"] = f"Sysmon process created: {command_line or process_path or process_name or 'unknown'}"
        document["key_entity"] = command_line or process_path or process_name

    if event_id == 3:
        source_ip = _normalize_windows_value(event_data.get("SourceIp") or event_data.get("SourceAddress"))
        source_port = _to_intish(event_data.get("SourcePort"))
        destination_ip = _normalize_windows_value(event_data.get("DestinationIp") or event_data.get("DestinationAddress"))
        destination_port = _to_intish(event_data.get("DestinationPort"))
        destination_host = _normalize_windows_value(event_data.get("DestinationHostname") or event_data.get("DestinationHostName"))
        initiated = _parse_boolish(event_data.get("Initiated"))
        document["source"].update(_compact({"ip": source_ip, "port": source_port}))
        document["destination"].update(_compact({"ip": destination_ip, "port": destination_port, "hostname": destination_host, "domain": destination_host}))
        document["network"].update(_compact({"source_ip": source_ip, "source_port": source_port, "destination_ip": destination_ip, "destination_port": destination_port, "domain": destination_host, "protocol": _normalize_windows_value(event_data.get("Protocol")), "direction": "outbound" if initiated is True else "inbound" if initiated is False else None, "initiated": initiated}))
        document["event"]["message"] = f"Sysmon network connection: {source_ip or '?'}:{source_port or '?'} -> {destination_host or destination_ip or '?'}:{destination_port or '?'}"
        document["key_entity"] = f"{destination_host or destination_ip}:{destination_port}" if (destination_host or destination_ip or destination_port) else None

    if event_id == 7:
        loaded_path, loaded_name, _, _ = _path_details(event_data.get("ImageLoaded"))
        loaded_hashes = _parse_hashes(event_data.get("Hashes"), event_data)
        loaded_payload = _compact({"path": loaded_path, "name": loaded_name, "hash": loaded_hashes if any(loaded_hashes.values()) else None, "signed": _parse_boolish(event_data.get("Signed")), "signature": _normalize_windows_value(event_data.get("Signature")), "signature_status": _normalize_windows_value(event_data.get("SignatureStatus"))})
        document["image"] = {"loaded": loaded_payload}
        document["module"] = loaded_payload
        document["event"]["message"] = f"Sysmon image loaded: {loaded_path or 'unknown'}"
        document["key_entity"] = loaded_path

    if event_id in {11, 15, 23, 26}:
        file_path, file_name, file_parent, file_extension = _path_details(event_data.get("TargetFilename"))
        file_hashes = _parse_hashes(event_data.get("Hashes"), event_data)
        file_created, _ = _parse_timestamp(_normalize_windows_value(event_data.get("CreationUtcTime")))
        document["file"].update(_compact({"path": file_path, "name": file_name, "directory": file_parent, "parent_path": file_parent, "extension": file_extension, "created": file_created, "created_original": _normalize_windows_value(event_data.get("CreationUtcTime")) if file_created is None else None, "hash": file_hashes if any(file_hashes.values()) else None, "md5": file_hashes.get("md5"), "sha1": file_hashes.get("sha1"), "sha256": file_hashes.get("sha256")}))
        document["target"] = {"filename": file_path}
        document["event"]["message"] = f"{default_message}: {file_path or 'unknown'}"
        document["key_entity"] = file_path

    if event_id in {12, 13, 14}:
        registry_path = _normalize_windows_value(event_data.get("TargetObject"))
        registry_key = _parent_path(str(registry_path)) if registry_path else None
        registry_value = _basename(str(registry_path)) if registry_path else None
        registry_data = _normalize_windows_value(event_data.get("Details"))
        document["registry"].update(_compact({"path": registry_path, "key_path": registry_path, "key": registry_key, "value": registry_value, "value_name": registry_value, "data": registry_data, "value_data": registry_data, "event_type": _normalize_windows_value(event_data.get("EventType")) or action}))
        document["artifact"]["type"] = "registry_event"
        document["artifact"]["parser"] = document["artifact"].get("parser") or "sysmon_registry"
        document["event"]["type"] = "registry_value_set" if event_id == 13 else "registry_key_or_value_renamed" if event_id == 14 else "registry_key_created_or_deleted"
        document["event"]["message"] = f"{default_message}: {registry_path or 'unknown'}"
        document["key_entity"] = registry_path

    if event_id == 22:
        query_name = _normalize_windows_value(event_data.get("QueryName"))
        query_results = _normalize_windows_value(event_data.get("QueryResults"))
        answers = [item for item in re.split(r"[;,]\s*", str(query_results or "")) if item]
        document["dns"] = _compact({"question": {"name": query_name} if query_name else None, "query": query_name, "name": query_name, "domain": query_name, "answers": answers, "data": query_results, "status": _normalize_windows_value(event_data.get("QueryStatus"))})
        document["event"]["message"] = f"Sysmon DNS query: {query_name or 'unknown'}"
        document["key_entity"] = query_name

    if event_id in {8, 10}:
        target_image = _normalize_windows_value(event_data.get("TargetImage"))
        target_path, target_name, _, _ = _path_details(target_image)
        document["target"] = {"process": _compact({"entity_id": _normalize_windows_value(event_data.get("TargetProcessGuid")), "guid": _normalize_windows_value(event_data.get("TargetProcessGuid")), "pid": _to_intish(event_data.get("TargetProcessId")), "path": target_path, "executable": target_path, "name": target_name})}
        document["source"].setdefault("process", {}).update(_compact({"entity_id": document["process"].get("entity_id"), "pid": document["process"].get("pid"), "path": document["process"].get("path"), "executable": document["process"].get("executable"), "name": document["process"].get("name")}))
        if event_id == 10:
            document["process"]["granted_access"] = _normalize_windows_value(event_data.get("GrantedAccess"))
            document["process"]["call_trace"] = _normalize_windows_value(event_data.get("CallTrace"))
            document["event"]["message"] = f"Sysmon process access: {process_name or 'source'} -> {target_name or 'target'}"
        else:
            document["process"]["start_address"] = _normalize_windows_value(event_data.get("StartAddress"))
            document["process"]["start_module"] = _normalize_windows_value(event_data.get("StartModule"))
            document["process"]["start_function"] = _normalize_windows_value(event_data.get("StartFunction"))
            document["event"]["message"] = f"Sysmon remote thread: {process_name or 'source'} -> {target_name or 'target'}"
        document["key_entity"] = target_path


def _apply_security_4663_normalization(document: dict, event_id: int | None, event_data: dict[str, object], provider: str | None, channel: str | None) -> None:
    if event_id != 4663:
        return
    if "security" not in str(channel or "").lower() and "microsoft-windows-security-auditing" not in str(provider or "").lower():
        return

    object_name = _normalize_windows_value(event_data.get("ObjectName") or event_data.get("Object Name"))
    object_type = _normalize_windows_value(event_data.get("ObjectType") or event_data.get("Object Type"))
    object_server = _normalize_windows_value(event_data.get("ObjectServer") or event_data.get("Object Server"))
    access_mask = _normalize_windows_value(event_data.get("AccessMask"))
    accesses_raw = _normalize_windows_value(event_data.get("Accesses"))
    access_reason = _normalize_windows_value(event_data.get("AccessReason") or event_data.get("Access Reason"))
    process_path, process_name, _, _ = _path_details(event_data.get("ProcessName"))
    subject_user = _normalize_windows_value(event_data.get("SubjectUserName"))
    subject_domain = _normalize_windows_value(event_data.get("SubjectDomainName"))
    subject_sid = _normalize_windows_value(event_data.get("SubjectUserSid"))
    subject_logon_id = _normalize_windows_value(event_data.get("SubjectLogonId"))
    access_list = [item.strip() for item in re.split(r"[\r\n;|]+", str(accesses_raw or "")) if item.strip()]
    object_text = str(object_name or "")
    object_type_lower = str(object_type or "").lower()
    looks_like_file = bool(re.match(r"^(?:[a-zA-Z]:\\|\\\\)", object_text)) and "key" not in object_type_lower
    looks_like_registry = "key" in object_type_lower or object_text.upper().startswith("\\REGISTRY\\")

    document["event"].update(
        {
            "category": "object_access",
            "type": "object_access",
            "action": "object_access_attempted",
            "message": f"Object access attempted: {object_name or 'unknown object'}",
        }
    )
    document["object"] = _compact(
        {
            "name": object_name,
            "path": object_name,
            "type": object_type,
            "server": object_server,
        }
    )
    document["access"] = _compact(
        {
            "mask": access_mask,
            "list": access_list,
            "accesses": access_list,
            "reason": access_reason,
        }
    )
    if looks_like_file:
        file_path, file_name, file_parent, file_extension = _path_details(object_name)
        document["file"].update(_compact({"path": file_path, "name": file_name, "directory": file_parent, "parent_path": file_parent, "extension": file_extension}))
    if looks_like_registry:
        document["registry"].update(_compact({"path": object_name, "key_path": object_name}))
    if process_path or process_name:
        document["process"].update(_compact({"path": process_path, "executable": process_path, "name": process_name}))
    if subject_user:
        document["user"]["name"] = subject_user
    if subject_domain:
        document["user"]["domain"] = subject_domain
    if subject_sid:
        document["user"]["sid"] = subject_sid
    document["subject"] = {"user": _compact({"name": subject_user, "domain": subject_domain, "sid": subject_sid}), "logon": _compact({"id": subject_logon_id})}
    if subject_logon_id:
        document["logon"] = {"id": subject_logon_id}
    document["key_entity"] = object_name


def _apply_event_source(document: dict, provider: object | None, channel: object | None) -> None:
    normalized_provider = _normalize_windows_value(provider)
    normalized_channel = _normalize_windows_value(channel)
    if normalized_provider:
        document.setdefault("event", {})["provider"] = normalized_provider
    if normalized_channel:
        document.setdefault("event", {})["channel"] = normalized_channel


def _normalize_evtx_row(case_id: str, evidence_id: str, artifact_id: str, raw_row: dict, artifact_meta: dict) -> dict:
    raw, lowered = _normalize_row_keys(raw_row)
    source_file = artifact_meta.get("source_path") or artifact_meta.get("name") or "EvtxECmd_Output.csv"
    timestamp, timestamp_type = _parse_timestamp(
        _get(
            lowered,
            "TimeCreatedUtc",
            "TimeCreated UTC",
            "TimeCreated",
            "UtcTime",
            "Timestamp",
            "EventTime",
            "Created",
            "Date",
        )
    )
    event_id = _parse_event_id(_get(lowered, "EventId", "EventID", "Event ID", "EID", "Id"))
    provider = _get(lowered, "Provider", "ProviderName", "SourceName")
    channel = _get(lowered, "Channel", "LogName")
    payload = _extract_payload(raw, lowered)
    xml_text = _get(lowered, "Xml", "RawXml")
    xml_fields = _extract_xml_fields(xml_text)
    event_data = _merge_event_data(lowered, xml_fields, payload)
    _normalize_task_xml_fields(event_data)
    match = classify_windows_event_catalog(event_id, provider, channel)
    source_match = match.source_match

    document = _document_base(case_id, evidence_id, artifact_id, source_file, raw, timestamp, timestamp_type, artifact_meta)
    message = _build_message(event_id, event_data, provider, channel, _get(lowered, "MapDescription"), _get(lowered, "Message"), source_match=source_match)
    user_name, user_domain = _user_domain(event_data)
    host_name = _normalize_windows_value(_get(lowered, "Computer") or event_data.get("Computer"))
    host_classification = classify_host_candidate(host_name, source="evtx_computer", provider=provider, channel=channel) if host_name else None
    trusted_host_name = str(host_classification["normalized"]) if host_classification and host_classification["accepted"] else None
    file_info = _derive_file_info(event_data)
    suspicious_reasons = detect_suspicious_powershell(
        str(
            event_data.get("ScriptBlockText")
            or event_data.get("CommandLine")
            or event_data.get("ProcessCommandLine")
            or event_data.get("CommandInvocation")
            or payload.get("Payload")
            or ""
        )
    ) + detect_suspicious_path(file_info["path"])
    severity = _severity(_get(lowered, "Level", "Severity"), match.severity, suspicious_reasons, source_match=source_match)
    tags = sorted(set(match.tags + (["suspicious"] if suspicious_reasons else [])))
    if match.event_type == "logon_success" and str(event_data.get("LogonType") or "") == "10":
        tags.extend(["rdp", "remote_access"])
    if any(reason == "powershell_encoded" for reason in suspicious_reasons):
        tags.append("powershell_encoded")
    if any(reason == "download" for reason in suspicious_reasons):
        tags.append("download")
    if any(reason == "defender_tamper" for reason in suspicious_reasons):
        tags.append("defender_tamper")

    source_ip = _normalize_windows_value(
        event_data.get("IpAddress")
        or event_data.get("SourceAddress")
        or event_data.get("ClientIP")
        or event_data.get("Address")
        or event_data.get("SourceNetworkAddress")
        or event_data.get("ClientAddress")
    )
    destination_ip = _normalize_windows_value(event_data.get("DestAddress") or event_data.get("DestinationAddress"))
    command_line = _normalize_windows_value(
        event_data.get("ProcessCommandLine")
        or event_data.get("CommandLine")
        or event_data.get("HostApplication")
        or event_data.get("ScriptBlockText")
    )
    process_path = _normalize_windows_value(
        event_data.get("NewProcessName")
        or event_data.get("ProcessName")
        or event_data.get("Image")
        or event_data.get("Application")
        or event_data.get("Path")
    )
    parent_path = _normalize_windows_value(
        event_data.get("ParentProcessName")
        or event_data.get("ParentImage")
        or event_data.get("CreatorProcessName")
    )

    if match.event_type == "logon_success":
        user_name = _normalize_windows_value(event_data.get("TargetUserName"))
        user_domain = _normalize_windows_value(event_data.get("TargetDomainName"))
    elif match.event_type == "logon_failed":
        user_name = _normalize_windows_value(event_data.get("TargetUserName"))
        user_domain = _normalize_windows_value(event_data.get("TargetDomainName"))
    elif match.event_type == "explicit_credentials_logon":
        user_name = _normalize_windows_value(event_data.get("SubjectUserName"))
        user_domain = _normalize_windows_value(event_data.get("SubjectDomainName"))
    elif match.event_type == "process_creation":
        user_name = _normalize_windows_value(event_data.get("SubjectUserName"))
        user_domain = _normalize_windows_value(event_data.get("SubjectDomainName"))
    elif event_id in {1116, 1117, 1118, 1119, 5007, 5013} and not user_name:
        user_name = _normalize_windows_value(event_data.get("DetectionUser"))

    document["host"].update({"name": trusted_host_name, "hostname": trusted_host_name})
    document["user"].update(
        {
            "name": user_name,
            "domain": user_domain,
            "sid": _normalize_windows_value(event_data.get("TargetUserSid") or event_data.get("SubjectUserSid") or event_data.get("SecurityUserId") or event_data.get("UserId")),
            "logon_id": _normalize_windows_value(event_data.get("TargetLogonId") or event_data.get("LogonId") or event_data.get("SubjectLogonId")),
        }
    )
    document["source"].update(
        {
            "ip": source_ip,
            "port": _normalize_windows_value(event_data.get("IpPort") or event_data.get("SourcePort")),
            "hostname": _normalize_windows_value(event_data.get("WorkstationName") or event_data.get("ClientMachine") or event_data.get("ClientName") or event_data.get("Workstation")),
        }
    )
    document["destination"].update(
        {
            "ip": destination_ip,
            "port": _normalize_windows_value(event_data.get("DestinationPort")),
            "hostname": _normalize_windows_value(event_data.get("TargetServerName")),
        }
    )
    process_entity_id = _normalize_windows_value(event_data.get("ProcessGuid"))
    parent_entity_id = _normalize_windows_value(event_data.get("ParentProcessGuid"))
    synthetic_entity_id = _stable_process_entity_id(case_id, host_name if isinstance(host_name, str) else None, timestamp, _to_intish(event_data.get("NewProcessId") or event_data.get("ProcessId")), process_path)
    document["process"].update(
        {
            "entity_id": process_entity_id or synthetic_entity_id,
            "pid": _to_intish(event_data.get("NewProcessId") or event_data.get("ProcessId")),
            "name": _basename(process_path),
            "path": process_path,
            "command_line": command_line,
            "current_directory": _normalize_windows_value(event_data.get("CurrentDirectory")),
            "parent_entity_id": parent_entity_id,
            "parent_pid": _to_intish(event_data.get("CreatorProcessId") or event_data.get("ParentProcessId")),
            "ppid": _to_intish(event_data.get("CreatorProcessId") or event_data.get("ParentProcessId")),
            "parent_name": _basename(parent_path),
            "parent_path": parent_path,
            "parent_command_line": _normalize_windows_value(event_data.get("ParentCommandLine")),
            "integrity_level": _normalize_windows_value(event_data.get("IntegrityLevel") or event_data.get("MandatoryLabel")),
            "hashes": {
                "md5": _normalize_windows_value(event_data.get("MD5")),
                "sha1": _normalize_windows_value(event_data.get("SHA1")),
                "sha256": _normalize_windows_value(event_data.get("SHA256")),
            },
            "token_elevation": _normalize_windows_value(event_data.get("TokenElevationType")),
        }
    )
    document["file"].update(
        {
            **file_info,
            "sha1": _normalize_windows_value(event_data.get("SHA1")),
            "sha256": _normalize_windows_value(event_data.get("SHA256")),
            "md5": _normalize_windows_value(event_data.get("MD5")),
            "parent_path": _parent_path(process_path),
            "source_path": source_file,
        }
    )
    document["registry"].update(
        {
            "hive": _normalize_windows_value(event_data.get("Hive")),
            "key": _normalize_windows_value(event_data.get("KeyPath")),
            "value_name": _normalize_windows_value(event_data.get("ValueName")),
            "value_data": _normalize_windows_value(event_data.get("ValueData")),
        }
    )
    document["network"].update(
        {
            "protocol": _normalize_windows_value(event_data.get("Protocol")),
            "direction": _normalize_windows_value(event_data.get("Direction")),
            "application": _normalize_windows_value(event_data.get("Application")),
            "bytes_sent": _normalize_windows_value(event_data.get("BytesSent")),
            "bytes_received": _normalize_windows_value(event_data.get("BytesReceived")),
            "source_ip": source_ip,
            "source_port": _normalize_windows_value(event_data.get("SourcePort") or event_data.get("IpPort")),
            "destination_ip": destination_ip,
            "destination_port": _normalize_windows_value(event_data.get("DestinationPort")),
            "share_name": _normalize_windows_value(event_data.get("ShareName")),
            "share_local_path": _normalize_windows_value(event_data.get("ShareLocalPath")),
            "relative_target_name": _normalize_windows_value(event_data.get("RelativeTargetName")),
        }
    )
    document["detection"].update(
        {
            "threat_name": _normalize_windows_value(event_data.get("ThreatName")),
            "threat_id": _normalize_windows_value(event_data.get("ThreatID")),
            "severity": _normalize_windows_value(event_data.get("Severity")),
            "category": _normalize_windows_value(event_data.get("Category")),
            "action": _normalize_windows_value(event_data.get("Action")),
            "path": _normalize_windows_value(event_data.get("Path")),
            "error_code": _normalize_windows_value(event_data.get("ErrorCode")),
        }
    )
    document["task"].update(
        {
            "name": _normalize_windows_value(event_data.get("TaskName")),
            "command": _normalize_windows_value(event_data.get("Command")),
            "arguments": _normalize_windows_value(event_data.get("Arguments")),
            "author": _normalize_windows_value(event_data.get("Author")),
            "run_as": _normalize_windows_value(event_data.get("RunAs") or event_data.get("UserId")),
            "trigger": _normalize_windows_value(event_data.get("Trigger")),
            "enabled": _parse_boolish(event_data.get("Enabled")),
            "content": _normalize_windows_value(event_data.get("TaskContent")),
            "working_directory": _normalize_windows_value(event_data.get("WorkingDirectory")),
            "action": _normalize_windows_value(event_data.get("ActionName")),
        }
    )
    document["service"].update(
        {
            "name": _normalize_windows_value(event_data.get("ServiceName")),
            "display_name": _normalize_windows_value(event_data.get("DisplayName")),
            "image_path": _normalize_windows_value(event_data.get("ServiceFileName") or event_data.get("ImagePath")),
            "start_type": _normalize_windows_value(event_data.get("ServiceStartType") or event_data.get("StartType")),
            "service_type": _normalize_windows_value(event_data.get("ServiceType")),
            "account": _normalize_windows_value(event_data.get("AccountName")),
        }
    )
    document["winrm"].update(
        {
            "shell_id": _normalize_windows_value(event_data.get("ShellId")),
            "command_id": _normalize_windows_value(event_data.get("CommandId")),
            "resource_uri": _normalize_windows_value(event_data.get("ResourceUri")),
            "plugin": _normalize_windows_value(event_data.get("Plugin")),
            "operation": _normalize_windows_value(event_data.get("Operation")),
        }
    )
    if document["network"]["application"] and not document["process"]["path"]:
        document["process"]["path"] = document["network"]["application"]
        document["process"]["name"] = _basename(document["network"]["application"])

    document["windows"].update(
        {
            "event_id": event_id,
            "provider": provider,
            "channel": channel,
            "computer": host_name,
            "record_number": _normalize_windows_value(_get(lowered, "EventRecordId", "RecordNumber", "RecordId")),
            "process_id": _normalize_windows_value(_get(lowered, "ProcessId", "ExecutionProcessID")),
            "thread_id": _normalize_windows_value(_get(lowered, "ThreadId", "ExecutionThreadID")),
            "event_data": event_data,
            "payload": payload,
            "raw_xml": xml_text,
            "logon_type": _normalize_windows_value(event_data.get("LogonType")),
            "service_name": _normalize_windows_value(event_data.get("ServiceName")),
            "task_name": _normalize_windows_value(event_data.get("TaskName")),
            "authentication_package": _normalize_windows_value(event_data.get("AuthenticationPackageName")),
            "logon_process": _normalize_windows_value(event_data.get("LogonProcessName")),
            "status": _normalize_windows_value(event_data.get("Status")),
            "sub_status": _normalize_windows_value(event_data.get("SubStatus")),
            "failure_reason": _normalize_windows_value(event_data.get("FailureReason")),
            "session_id": _normalize_windows_value(event_data.get("SessionID")),
            "session_name": _normalize_windows_value(event_data.get("SessionName")),
            "reason": _normalize_windows_value(event_data.get("Reason")),
        }
    )
    _apply_event_source(document, provider, channel)
    if host_classification and not host_classification["accepted"]:
        document["data_quality"] = sorted(
            set(document.get("data_quality", []))
            | {
                "host_low_confidence",
                f"host_rejected_{host_classification['rejected_reason']}",
            }
        )

    powershell: dict[str, object] = {}
    if event_id == 4104:
        powershell.update(
            {
                "script_block_text": _normalize_windows_value(event_data.get("ScriptBlockText")),
                "script_block_id": _normalize_windows_value(event_data.get("ScriptBlockId")),
                "path": _normalize_windows_value(event_data.get("Path")),
                "message_number": _normalize_windows_value(event_data.get("MessageNumber")),
                "message_total": _normalize_windows_value(event_data.get("MessageTotal")),
            }
        )
    if event_id == 4103:
        powershell.update(
            {
                "command_invocation": _normalize_windows_value(event_data.get("CommandInvocation")),
                "parameter_binding": _normalize_windows_value(event_data.get("ParameterBinding")),
                "payload": _normalize_windows_value(event_data.get("Payload")),
                "context_info": _normalize_windows_value(event_data.get("ContextInfo")),
                "user": _normalize_windows_value(event_data.get("User")),
            }
        )
    document["powershell"] = powershell

    if source_match and match.source_family == "powershell":
        from app.ingest.powershell.normalizer import normalize_powershell_row

        ps_row = dict(raw_row)
        for key, value in event_data.items():
            ps_row.setdefault(str(key), value)
        ps_meta = {
            **artifact_meta,
            "artifact_type": "powershell",
            "parser": "powershell_evtx",
            "source_tool": artifact_meta.get("source_tool") or "evtxecmd",
            "source_format": "evtx",
            "powershell_artifact_type": "powershell_evtx",
        }
        document = normalize_powershell_row(document, ps_row, ps_meta)
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
        document["event"]["category"] = "execution"
        document["windows"].update(
            {
                "event_id": event_id,
                "provider": provider,
                "channel": channel,
                "computer": host_name,
                "record_number": _normalize_windows_value(_get(lowered, "EventRecordId", "RecordNumber", "RecordId")),
                "process_id": _normalize_windows_value(_get(lowered, "ProcessId", "ExecutionProcessID")),
                "thread_id": _normalize_windows_value(_get(lowered, "ThreadId", "ExecutionThreadID")),
                "event_data": event_data,
                "payload": payload,
                "raw_xml": xml_text,
            }
        )
        _apply_event_source(document, provider, channel)
        document["raw_summary"] = " | ".join(
            f"{key}={str(value)[:160]}" for key, value in list(raw.items())[:12] if value not in (None, "")
        )[:2000]
        document["search_text"] = _build_search_text(document)
        if not timestamp and "missing_timestamp" not in document["data_quality"]:
            document["data_quality"].append("missing_timestamp")
        if not host_name and "missing_host" not in document["data_quality"]:
            document["data_quality"].append("missing_host")
        if not user_name and "missing_user" not in document["data_quality"]:
            document["data_quality"].append("missing_user")
        if event_id is None and "missing_event_id" not in document["data_quality"]:
            document["data_quality"].append("missing_event_id")
        document["data_quality"] = sorted(set(document["data_quality"]))
        return document

    if source_match and str(match.source_family or "") == "defender":
        from app.ingest.defender.normalizer import normalize_defender_row

        defender_row = dict(raw_row)
        for key, value in event_data.items():
            defender_row.setdefault(str(key), value)
        defender_row.setdefault("EventID", event_id)
        defender_row.setdefault("TimeCreated", timestamp)
        defender_meta = {
            **artifact_meta,
            "artifact_type": "detection",
            "parser": "defender_evtx",
            "source_tool": "native_evtx",
            "source_format": "evtx",
            "defender_artifact_type": "defender_evtx",
        }
        document = normalize_defender_row(document, defender_row, defender_meta)
        document["artifact"]["type"] = "detection"
        document["artifact"]["parser"] = "defender_evtx"
        document["source_tool"] = "native_evtx"
        document["source_format"] = "evtx"
        document["windows"].update(
            {
                "event_id": event_id,
                "provider": provider,
                "channel": channel,
                "computer": host_name,
                "record_number": _normalize_windows_value(_get(lowered, "EventRecordId", "RecordNumber", "RecordId")),
                "process_id": _normalize_windows_value(_get(lowered, "ProcessId", "ExecutionProcessID")),
                "thread_id": _normalize_windows_value(_get(lowered, "ThreadId", "ExecutionThreadID")),
                "event_data": event_data,
                "payload": payload,
                "raw_xml": xml_text,
            }
        )
        _apply_event_source(document, provider, channel)
        document["raw_summary"] = " | ".join(
            f"{key}={str(value)[:160]}" for key, value in list(raw.items())[:12] if value not in (None, "")
        )[:2000]
        document["search_text"] = _build_search_text(document)
        if not timestamp and "missing_timestamp" not in document["data_quality"]:
            document["data_quality"].append("missing_timestamp")
        if not host_name and "missing_host" not in document["data_quality"]:
            document["data_quality"].append("missing_host")
        if event_id is None and "defender_unknown_event_id" not in document["data_quality"]:
            document["data_quality"].append("defender_unknown_event_id")
        document["data_quality"] = sorted(set(document["data_quality"]))
        return document

    document["event"].update(
        {
            "category": match.category,
            "type": match.event_type,
            "action": match.action,
            "severity": severity,
            "message": message,
            "timeline_include": severity in {"medium", "high", "critical"} or bool(suspicious_reasons) or match.category in {"authentication", "powershell", "persistence", "remote_access", "detection", "anti_forensics", "account_management"},
        }
    )
    if match.category == "process":
        document["artifact"]["type"] = "process"
        document["artifact"]["parser"] = "sysmon_evtx" if event_id == 1 and "sysmon" in str(provider or "").lower() else "security_4688" if event_id == 4688 and str(channel or "").lower() == "security" else document["artifact"].get("parser")
        document["event"]["type"] = "process_start"
        document["event"]["action"] = "process_created"
        parent_label = document["process"].get("parent_name") or "unknown"
        child_label = document["process"].get("name") or "unknown"
        document["event"]["message"] = f"Process created: {parent_label} -> {child_label}"
        document["execution"].update(
            {
                "source": "process_creation",
                "is_execution_confirmed": True,
                "confidence": "high",
                "interpretation": "Process creation event confirms execution",
            }
        )
        if not process_entity_id:
            document["data_quality"].append("missing_process_guid")
        if not parent_entity_id:
            document["data_quality"].append("missing_parent_guid")
    document["tags"] = sorted(set(tags))
    _apply_sysmon_normalization(document, event_id, event_data, provider, channel)
    _apply_security_4663_normalization(document, event_id, event_data, provider, channel)
    document["suspicious_reasons"] = sorted(set(reason for reason in suspicious_reasons if reason))
    document["raw_summary"] = " | ".join(f"{key}={str(value)[:160]}" for key, value in list(raw.items())[:12] if value not in (None, ""))[:2000]
    document["search_text"] = _build_search_text(document)
    if not timestamp:
        document["data_quality"].append("missing_timestamp")
    if not host_name:
        document["data_quality"].append("missing_host")
    if not document.get("user", {}).get("name"):
        document["data_quality"].append("missing_user")
    if event_id is None:
        document["data_quality"].append("missing_event_id")
    return document


def _build_ingest_audit(path: Path, documents: list[dict]) -> dict[str, object]:
    event_id_counts: dict[str, int] = {}
    event_type_counts: dict[str, int] = {}
    channel_counts: dict[str, int] = {}
    provider_counts: dict[str, int] = {}
    missing_timestamp = 0
    missing_event_id = 0
    source_mismatch_count = 0
    for document in documents:
        windows = document.get("windows", {}) or {}
        event = document.get("event", {}) or {}
        event_id = windows.get("event_id")
        event_type = str(event.get("type") or "unknown")
        channel = str(windows.get("channel") or "unknown")
        provider = str(windows.get("provider") or "unknown")
        if document.get("@timestamp") is None:
            missing_timestamp += 1
        if event_id is None:
            missing_event_id += 1
        if "source_mismatch" in (document.get("tags") or []):
            source_mismatch_count += 1
        event_id_key = str(event_id) if event_id is not None else "unknown"
        event_id_counts[event_id_key] = event_id_counts.get(event_id_key, 0) + 1
        event_type_counts[event_type] = event_type_counts.get(event_type, 0) + 1
        channel_counts[channel] = channel_counts.get(channel, 0) + 1
        provider_counts[provider] = provider_counts.get(provider, 0) + 1
    return {
        "artifact": path.name,
        "parser": "evtxecmd",
        "records_read": len(documents),
        "records_parsed": len(documents),
        "events_indexed": len(documents),
        "bulk_index_errors": 0,
        "missing_timestamp": missing_timestamp,
        "missing_event_id": missing_event_id,
        "source_mismatch_count": source_mismatch_count,
        "event_id_counts": event_id_counts,
        "event_type_counts": event_type_counts,
        "channel_counts": channel_counts,
        "provider_counts": provider_counts,
        "top_errors": [],
    }


class EvtxECmdParser(ArtifactParser):
    def can_parse(self, path: Path, headers: list[str] | None = None) -> bool:
        lower_name = path.name.lower()
        header_set = {header.strip().lower() for header in (headers or []) if header}
        return "evtxecmd" in lower_name or {"eventid", "provider", "channel"} <= header_set

    def parse(self, path: Path, **kwargs) -> Iterable[dict]:
        case_id = kwargs["case_id"]
        evidence_id = kwargs["evidence_id"]
        artifact_id = kwargs["artifact_id"]
        artifact_meta = kwargs["artifact_meta"]
        rows = read_delimited_rows(path)
        for row in rows:
            yield _normalize_evtx_row(case_id, evidence_id, artifact_id, row, artifact_meta)


def parse_evtxecmd_file(case_id: str, evidence_id: str, artifact_id: str, path: Path, artifact_meta: dict) -> list[dict]:
    parser = EvtxECmdParser()
    documents = list(parser.parse(path, case_id=case_id, evidence_id=evidence_id, artifact_id=artifact_id, artifact_meta=artifact_meta))
    artifact_meta["ingest_audit"] = _build_ingest_audit(path, documents)
    return documents
