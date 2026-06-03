from collections import Counter
from datetime import UTC
from pathlib import Path, PureWindowsPath
import codecs
import re
from uuid import uuid4

from dateutil import parser as date_parser

from app.analysis.suspicious import detect_suspicious_path, detect_suspicious_powershell
from app.ingest.eztools.base import ArtifactParser, read_delimited_rows
from app.ingest.identity_extraction import extract_user_from_path, is_valid_username, normalize_hostname


RECMD_HEADER_HINTS = {
    "sourcefile",
    "hivepath",
    "hive",
    "keypath",
    "valuename",
    "valuetype",
    "valuedata",
    "lastwritetime",
}
WINDOWS_EMPTY_VALUES = {"", "-", "--", "n/a", "na", "(null)", "null"}
SCRIPT_EXTENSIONS = {".ps1", ".bat", ".cmd", ".vbs", ".js", ".jse", ".wsf", ".hta"}
EXECUTABLE_EXTENSIONS = {".exe", ".com", ".dll", ".scr", ".msi"} | SCRIPT_EXTENSIONS
DOCUMENT_EXTENSIONS = {".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx", ".pdf", ".txt", ".rtf", ".csv", ".zip", ".rar", ".7z"}
MACRO_DOCUMENT_EXTENSIONS = {".docm", ".xlsm", ".pptm", ".xlam", ".dotm", ".ppam"}
ARCHIVE_EXTENSIONS = {".zip", ".rar", ".7z", ".iso", ".img"}
USER_WRITABLE_MARKERS = ("\\users\\", "\\downloads\\", "\\desktop\\", "\\appdata\\", "\\temp\\", "\\public\\", "\\startup\\")
SUSPICIOUS_DOCUMENT_EXTENSIONS = MACRO_DOCUMENT_EXTENSIONS | {".js", ".jse", ".vbs", ".vbe", ".wsf", ".hta", ".ps1", ".bat", ".cmd", ".exe", ".scr"}
SUSPICIOUS_COMMAND_PATTERNS = {
    "powershell": "Registry command invokes PowerShell",
    "-enc": "Registry command contains PowerShell encoded command",
    "-encodedcommand": "Registry command contains PowerShell encoded command",
    "cmd /c": "Registry command invokes cmd /c",
    "mshta": "Registry command invokes mshta",
    "rundll32": "Registry command invokes rundll32",
    "regsvr32": "Registry command invokes regsvr32",
    "wscript": "Registry command invokes wscript",
    "cscript": "Registry command invokes cscript",
    "certutil": "Registry command invokes certutil",
    "bitsadmin": "Registry command invokes bitsadmin",
    "schtasks": "Registry command invokes schtasks",
    "net user": "Registry command invokes net user",
    "whoami": "Registry command invokes whoami",
    "ipconfig": "Registry command invokes ipconfig",
    "netstat": "Registry command invokes netstat",
    "nltest": "Registry command invokes nltest",
}
LOLBIN_HINTS = {
    "powershell.exe",
    "pwsh.exe",
    "cmd.exe",
    "mshta.exe",
    "rundll32.exe",
    "regsvr32.exe",
    "wscript.exe",
    "cscript.exe",
    "certutil.exe",
    "bitsadmin.exe",
    "schtasks.exe",
}
HIVE_HINTS = {
    "ntuser.dat": "NTUSER.DAT",
    "usrclass.dat": "UsrClass.dat",
    "system": "SYSTEM",
    "software": "SOFTWARE",
    "sam": "SAM",
    "security": "SECURITY",
    "amcache.hve": "Amcache.hve",
}


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


def _normalize_value(value: object | None) -> str | None:
    if value is None:
        return None
    normalized = str(value).strip()
    if normalized.lower() in WINDOWS_EMPTY_VALUES:
        return None
    return normalized


def _parse_timestamp(value: object | None) -> str | None:
    normalized = _normalize_value(value)
    if not normalized:
        return None
    try:
        parsed = date_parser.parse(normalized)
        if parsed.tzinfo is None:
            parsed = parsed.replace(tzinfo=UTC)
        return parsed.isoformat()
    except Exception:  # noqa: BLE001
        return None


def normalize_registry_timestamp(value: object | None) -> str | None:
    return _parse_timestamp(value)


def _parse_int(value: object | None) -> int | None:
    normalized = _normalize_value(value)
    if not normalized:
        return None
    try:
        return int(normalized)
    except Exception:  # noqa: BLE001
        return None


def _suffix(path: str | None) -> str | None:
    normalized = _normalize_value(path)
    if not normalized:
        return None
    suffix = PureWindowsPath(normalized).suffix.lower()
    return suffix or None


def _basename(path: str | None) -> str | None:
    normalized = _normalize_value(path)
    if not normalized:
        return None
    return PureWindowsPath(normalized.replace("/", "\\")).name or None


def _normalize_text_blob(*values: object | None) -> str:
    return " ".join(str(value).strip().lower() for value in values if value not in (None, ""))


def infer_registry_hive(source_file: str | None, hive_path: str | None, key_path: str | None) -> str | None:
    for candidate in [source_file, hive_path, key_path]:
        normalized = str(candidate or "").lower()
        for token, hive in HIVE_HINTS.items():
            if token in normalized:
                return hive
    if key_path and str(key_path).upper().startswith("HKCU\\"):
        return "NTUSER.DAT"
    if key_path and str(key_path).upper().startswith("HKLM\\SYSTEM\\"):
        return "SYSTEM"
    if key_path and str(key_path).upper().startswith("HKLM\\SOFTWARE\\"):
        return "SOFTWARE"
    return None


def infer_user_from_registry_path(source_file: str | None, key_path: str | None) -> str | None:
    for candidate in [source_file, key_path]:
        inferred = extract_user_from_path(candidate)
        if inferred and is_valid_username(inferred):
            return inferred
    return None


def extract_sid_from_key_path(key_path: str | None) -> str | None:
    normalized = _normalize_value(key_path)
    if not normalized:
        return None
    match = re.search(r"(S-\d-\d+(?:-\d+){1,14})", normalized, flags=re.IGNORECASE)
    return match.group(1) if match else None


def extract_service_name_from_key_path(key_path: str | None) -> str | None:
    normalized = _normalize_value(key_path)
    if not normalized:
        return None
    match = re.search(r"services\\([^\\]+)", normalized, flags=re.IGNORECASE)
    return match.group(1) if match else None


def extract_usb_identifiers_from_key_path(key_path: str | None) -> dict[str, str | None]:
    normalized = _normalize_value(key_path) or ""
    vendor = product = serial = device_id = None
    if "usbstor" in normalized.lower():
        match = re.search(r"USBSTOR\\([^\\]+)\\([^\\]+)", normalized, flags=re.IGNORECASE)
        if match:
            device_id = match.group(1)
            serial = match.group(2)
            ven_match = re.search(r"Ven_([^&\\]+)", device_id, flags=re.IGNORECASE)
            prod_match = re.search(r"Prod_([^&\\]+)", device_id, flags=re.IGNORECASE)
            if ven_match:
                vendor = ven_match.group(1).replace("_", " ")
            if prod_match:
                product = prod_match.group(1).replace("_", " ")
    elif "\\enum\\usb\\" in normalized.lower():
        match = re.search(r"USB\\([^\\]+)\\([^\\]+)", normalized, flags=re.IGNORECASE)
        if match:
            device_id = match.group(1)
            serial = match.group(2)
    return {
        "vendor": vendor,
        "product": product,
        "serial": serial,
        "device_id": device_id,
    }


def decode_userassist_rot13(value: str | None) -> str | None:
    normalized = _normalize_value(value)
    if not normalized:
        return None
    try:
        decoded = codecs.decode(normalized, "rot_13")
    except Exception:  # noqa: BLE001
        return normalized
    decoded_lower = decoded.lower()
    if any(token in decoded_lower for token in [":\\", "\\", ".exe", ".lnk", ".ps1", ".cmd", "explorer", "uemr"]):
        return decoded
    return normalized


def extract_executable_from_command(command_line: str | None) -> str | None:
    normalized = _normalize_value(command_line)
    if not normalized:
        return None
    if normalized.startswith('"'):
        match = re.match(r'"([^"]+)"', normalized)
        if match:
            return match.group(1)
    first_token = normalized.split()[0]
    if re.search(r"\.(?:exe|com|cmd|bat|ps1|vbs|js|jse|wsf|mshta|dll|scr|msi)$", first_token, flags=re.IGNORECASE):
        return first_token
    if "\\" in first_token or "/" in first_token:
        return first_token
    return None


def _extract_path_like_value(*values: str | None) -> str | None:
    for value in values:
        normalized = _normalize_value(value)
        if not normalized:
            continue
        if re.match(r"^[a-zA-Z]:\\", normalized) or normalized.startswith("\\\\") or normalized.startswith("..\\"):
            return normalized
    return None


def _target_from_registry_value(value_name: str | None, value_data: str | None) -> str | None:
    return _extract_path_like_value(value_data, value_name)


def _extract_url(value: str | None) -> str | None:
    normalized = _normalize_value(value)
    if not normalized:
        return None
    match = re.search(r"https?://[^\s|\"']+", normalized, flags=re.IGNORECASE)
    return match.group(0) if match else None


def _extract_mru_target(value_name: str | None, value_data: str | None) -> str | None:
    direct = _target_from_registry_value(value_name, value_data)
    if direct:
        return direct
    url = _extract_url(value_data) or _extract_url(value_name)
    if url:
        return url
    normalized = _normalize_value(value_data)
    if not normalized:
        return None
    star_path_match = re.search(r"\*([A-Za-z]:\\[^*]+)$", normalized)
    if star_path_match:
        return star_path_match.group(1)
    star_url_match = re.search(r"\*(https?://[^*]+)$", normalized, flags=re.IGNORECASE)
    if star_url_match:
        return star_url_match.group(1)
    return None


def _parse_mru_order(value_name: str | None) -> int | None:
    normalized = _normalize_value(value_name)
    if not normalized:
        return None
    lower = normalized.lower()
    if len(lower) == 1 and "a" <= lower <= "z":
        return ord(lower) - ord("a")
    if lower.isdigit():
        try:
            return int(lower)
        except Exception:  # noqa: BLE001
            return None
    return None


def _looks_double_extension(path: str | None) -> bool:
    normalized = _normalize_value(path)
    if not normalized:
        return False
    name = _basename(normalized) or normalized
    parts = name.lower().split(".")
    if len(parts) < 3:
        return False
    return f".{parts[-1]}" in EXECUTABLE_EXTENSIONS | SCRIPT_EXTENSIONS


def _is_user_writable_path(path: str | None) -> bool:
    normalized = str(_normalize_value(path) or "").lower()
    return any(marker in normalized for marker in USER_WRITABLE_MARKERS)


def _risk_document_path(path: str | None) -> tuple[set[str], list[str]]:
    tags: set[str] = set()
    reasons: list[str] = []
    normalized = _normalize_value(path)
    if not normalized:
        return tags, reasons
    extension = _suffix(normalized)
    lower = normalized.lower()
    if extension in MACRO_DOCUMENT_EXTENSIONS:
        tags.update({"suspicious", "macro_document"})
        reasons.append("Macro-enabled Office document observed")
    if extension in EXECUTABLE_EXTENSIONS | SCRIPT_EXTENSIONS:
        tags.update({"suspicious", "executable_document"})
        reasons.append("Executable or script observed in recent user activity")
    if extension in ARCHIVE_EXTENSIONS:
        tags.add("archive")
        reasons.append("Archive observed in recent user activity")
    if _looks_double_extension(normalized):
        tags.update({"suspicious", "double_extension"})
        reasons.append("Double extension file observed")
    if _is_user_writable_path(normalized) and extension in SUSPICIOUS_DOCUMENT_EXTENSIONS | ARCHIVE_EXTENSIONS:
        tags.update({"suspicious", "user_writable_path"})
        reasons.append("Suspicious file observed in user-writable path")
    if normalized.startswith("\\\\"):
        tags.update({"network_path", "unc_path"})
        reasons.append("UNC or remote path observed")
    if re.match(r"^[D-Z]:\\", normalized, flags=re.IGNORECASE):
        tags.add("removable_or_secondary_volume")
        if extension in SUSPICIOUS_DOCUMENT_EXTENSIONS | ARCHIVE_EXTENSIONS:
            reasons.append("Suspicious file observed on non-system volume")
    if any(token in lower for token in ("\\downloads\\", "\\temp\\", "\\appdata\\", "\\desktop\\")) and extension in MACRO_DOCUMENT_EXTENSIONS | EXECUTABLE_EXTENSIONS | SCRIPT_EXTENSIONS:
        tags.update({"suspicious", "staging_path"})
        reasons.append("Suspicious file observed in staging path")
    return tags, sorted(set(reasons))


def _detect_auth_failures(value: str | None) -> tuple[set[str], list[str]]:
    normalized = str(_normalize_value(value) or "").lower()
    tags: set[str] = set()
    reasons: list[str] = []
    if not normalized:
        return tags, reasons
    if "spf=fail" in normalized or "spf fail" in normalized:
        tags.add("spf_fail")
        reasons.append("SPF failure observed")
    if "dkim=fail" in normalized or "dkim fail" in normalized:
        tags.add("dkim_fail")
        reasons.append("DKIM failure observed")
    if "dmarc=fail" in normalized or "dmarc fail" in normalized:
        tags.add("dmarc_fail")
        reasons.append("DMARC failure observed")
    return tags, reasons


def _preview_value(value: str | None, limit: int = 180) -> str | None:
    normalized = _normalize_value(value)
    if not normalized:
        return None
    compact = re.sub(r"\s+", " ", normalized)
    if len(compact) <= limit:
        return compact
    return f"{compact[: limit - 3]}..."


def _extract_registry_execution_path(lowered: dict[str, object], value_name: str | None, value_data: str | None) -> str | None:
    return (
        extract_executable_from_command(value_data)
        or extract_executable_from_command(value_name)
        or _extract_path_like_value(
            value_data,
            value_name,
            _get(lowered, "Path", "Application", "Executable", "Name"),
            _get(lowered, "TargetPath", "ImagePath", "CommandLine"),
        )
    )


def classify_registry_artifact(row: dict | tuple[dict[str, object], dict[str, object]]) -> str:
    if isinstance(row, tuple):
        raw_row, lowered = row
    else:
        raw_row, lowered = _normalize_row_keys(row)
    key_path = _normalize_value(_get(lowered, "KeyPath", "Path")) or ""
    plugin = _normalize_value(_get(lowered, "Plugin")) or ""
    batch = _normalize_value(_get(lowered, "Batch")) or ""
    description = _normalize_value(_get(lowered, "Description")) or ""
    category = _normalize_value(_get(lowered, "Category")) or ""
    source_blob = _normalize_text_blob(key_path, plugin, batch, description, category, raw_row.get("SourceFile"))
    key_lower = key_path.lower()

    if any(fragment in key_lower for fragment in [
        "\\software\\microsoft\\windows\\currentversion\\run",
        "\\software\\microsoft\\windows\\currentversion\\runonce",
        "\\software\\microsoft\\windows\\currentversion\\policies\\explorer\\run",
        "\\wow6432node\\microsoft\\windows\\currentversion\\run",
        "\\wow6432node\\microsoft\\windows\\currentversion\\runonce",
    ]):
        return "run_key"
    if "\\services\\" in key_lower and ("currentcontrolset" in key_lower or "controlset" in key_lower):
        if "\\services\\bam" in key_lower or "\\state\\usersettings\\" in key_lower and "\\bam" in source_blob:
            return "bam"
        if "\\services\\dam" in key_lower or "\\state\\usersettings\\" in key_lower and "\\dam" in source_blob:
            return "dam"
        return "service"
    if "userassist" in key_lower or "userassist" in source_blob:
        return "userassist"
    if "muicache" in key_lower or "muicache" in source_blob:
        return "muicache"
    if "\\enum\\usbstor" in key_lower or "\\enum\\usb\\" in key_lower or "windows portable devices\\devices" in key_lower:
        return "usb_device"
    if "\\system\\mounteddevices" in key_lower:
        return "mounted_devices"
    if "\\software\\microsoft\\windows\\currentversion\\explorer\\typedpaths" in key_lower:
        return "typed_paths"
    if "\\software\\microsoft\\windows\\currentversion\\explorer\\runmru" in key_lower:
        return "run_mru"
    if "\\software\\microsoft\\windows\\currentversion\\explorer\\recentdocs" in key_lower:
        return "recent_docs"
    if "\\software\\microsoft\\windows\\currentversion\\explorer\\comdlg32\\opensavepidlmru" in key_lower:
        return "opensave_mru"
    if "\\software\\microsoft\\windows\\currentversion\\explorer\\comdlg32\\lastvisitedpidlmru" in key_lower:
        return "lastvisited_mru"
    if "\\software\\microsoft\\office\\" in key_lower and "\\filemru" in key_lower:
        return "office_recent_docs"
    if "\\software\\microsoft\\office\\" in key_lower and "\\security\\trusted documents\\trustrecords" in key_lower:
        return "office_trustrecords"
    if "\\software\\microsoft\\windows\\currentversion\\explorer\\featureusage" in key_lower:
        return "featureusage"
    if "\\software\\microsoft\\windows\\currentversion\\search\\recentapps" in key_lower:
        return "recentapps"
    if "\\software\\microsoft\\terminal server client\\default" in key_lower or "\\software\\microsoft\\terminal server client\\servers" in key_lower:
        return "rdp_mru"
    if "shellbag" in source_blob or "\\bagmru" in key_lower or "\\shell\\bags" in key_lower:
        return "shellbags"
    return "registry_generic"


def _infer_timestamp(lowered: dict[str, object]) -> tuple[str | None, str]:
    candidates = [
        ("registry_last_write", _get(lowered, "LastWriteTime", "LastWrite", "LastWriteTimestamp")),
        ("timestamp", _get(lowered, "Timestamp")),
        ("last_run", _get(lowered, "LastRun", "LastExecuted", "LastExecutionTime")),
        ("modified", _get(lowered, "Modified")),
        ("created", _get(lowered, "Created")),
    ]
    for ts_type, value in candidates:
        parsed = _parse_timestamp(value)
        if parsed:
            return parsed, ts_type
    return None, "unknown"


def _base_document(case_id: str, evidence_id: str, artifact_id: str, source_file: str, raw_row: dict, artifact_meta: dict, timestamp: str | None, timestamp_type: str) -> dict:
    return {
        "event_id": str(uuid4()),
        "id": str(uuid4()),
        "case_id": case_id,
        "evidence_id": evidence_id,
        "artifact_id": artifact_id,
        "@timestamp": timestamp,
        "timestamp_precision": timestamp_type,
        "timezone": "UTC" if timestamp else "unknown",
        "host": {"name": artifact_meta.get("detected_host"), "hostname": artifact_meta.get("detected_host"), "ip": [], "os": "Windows"},
        "user": {"name": artifact_meta.get("detected_user"), "domain": None, "sid": None, "logon_id": None},
        "source": {"ip": None, "port": None, "hostname": None},
        "destination": {"ip": None, "port": None, "hostname": None},
        "artifact": {
            "type": "registry",
            "name": artifact_meta.get("name", source_file),
            "source_path": artifact_meta.get("source_path", source_file),
            "parser": artifact_meta.get("parser", "zimmerman"),
        },
        "event": {
            "category": "registry",
            "type": "registry_value",
            "action": "registry_observed",
            "severity": "info",
            "message": artifact_meta.get("name", source_file),
            "timeline_include": True,
        },
        "process": {
            "pid": None,
            "name": None,
            "display_name": None,
            "path": None,
            "command_line": None,
            "parent_pid": None,
            "parent_name": None,
            "parent_path": None,
            "parent_command_line": None,
            "integrity_level": None,
            "token_elevation": None,
        },
        "file": {"path": None, "name": None, "extension": None, "size": None, "hash_sha1": None, "hash_sha256": None, "sha1": None, "sha256": None, "md5": None, "created": None, "modified": None, "accessed": None, "source_path": None},
        "execution": {"source": None, "run_count": None, "first_run": None, "last_run": None, "last_runs": [], "program_name": None, "confidence": None, "focus_time": None},
        "registry": {
            "hive": None,
            "hive_path": None,
            "key_path": None,
            "key_name": None,
            "value_name": None,
            "value_type": None,
            "value_data": None,
            "last_write_time": None,
            "artifact_type": None,
            "plugin": None,
            "batch": None,
        },
        "file_access": {},
        "folder": {"path": None},
        "mru": {"order": None, "list": None},
        "office": {"app": None, "version": None, "trusted_document": None, "macro_trust_possible": None},
        "user_activity": {"kind": None, "application": None, "activity_target": None},
        "service": {"name": None, "display_name": None, "image_path": None, "start_type": None, "service_type": None, "account": None, "service_dll": None, "description": None},
        "usb": {"vendor": None, "product": None, "serial": None, "device_id": None, "friendly_name": None, "container_id": None, "first_install_time": None, "last_connected_time": None, "last_removal_time": None},
        "shellbag": {"path": None, "mru": None, "slot": None, "last_write": None},
        "volume": {"guid": None, "drive_letter": None, "serial": None, "label": None, "drive_type": None, "created": None},
        "network": {"direction": None, "share_name": None, "path": None, "source_ip": None, "source_port": None, "destination_ip": None, "destination_port": None, "protocol": None, "application": None, "domain": None, "url": None, "destination_hostname": None},
        "lnk": {},
        "jumplist": {},
        "windows": {"event_id": None, "channel": None, "provider": None, "computer": None, "record_number": None, "process_id": None, "thread_id": None, "event_data": {}, "payload": {}, "raw_xml": None, "logon_type": None, "service_name": None, "task_name": None},
        "task": {"name": None, "path": None, "command": None, "arguments": None, "author": None, "run_as": None, "trigger": None, "enabled": None, "content": None, "working_directory": None, "action": None},
        "detection": {"threat_name": None, "threat_id": None, "severity": None, "category": None, "action": None, "path": None, "error_code": None},
        "tags": ["registry"],
        "data_quality": [],
        "risk_score": 0,
        "raw_summary": "",
        "search_text": "",
        "raw": raw_row,
        "suspicious_reasons": [],
        "source_file": source_file,
        "source_tool": "recmd",
        "source_format": "csv",
    }


def _classify_target_path(path: str | None) -> tuple[str, set[str]]:
    normalized = _normalize_value(path)
    if not normalized:
        return "file_opened", set()
    extension = _suffix(normalized)
    if extension in EXECUTABLE_EXTENSIONS:
        tags = {"execution_related", "executable"}
        if extension in SCRIPT_EXTENSIONS:
            tags.add("script")
        return "program_or_script_opened", tags
    if extension in DOCUMENT_EXTENSIONS:
        return "document_opened", {"document"}
    return "file_opened", set()


def _detect_registry_suspicious(value_data: str | None, *paths: str | None) -> tuple[set[str], list[str]]:
    tags: set[str] = set()
    reasons: list[str] = []
    normalized_value = str(value_data or "")
    lower_value = normalized_value.lower()
    for token, reason in SUSPICIOUS_COMMAND_PATTERNS.items():
        if token in lower_value:
            tags.add("suspicious")
            if "powershell" in token or token in {"-enc", "-encodedcommand"}:
                tags.add("powershell")
            if token in {"mshta", "rundll32", "regsvr32", "certutil", "bitsadmin"}:
                tags.add("lolbin")
            reasons.append(reason)
    for reason in detect_suspicious_powershell(value_data):
        tags.update({"suspicious", "powershell"})
        reasons.append(f"Registry command suspicious token: {reason}")
    for path_value in paths:
        target_name = str(_basename(path_value) or "").lower()
        target_extension = str(_suffix(path_value) or "").lower()
        if target_name in LOLBIN_HINTS:
            tags.update({"suspicious", "lolbin"})
            reasons.append(f"Registry target is LOLBin: {target_name}")
        if target_extension in SCRIPT_EXTENSIONS:
            tags.update({"suspicious", "script"})
            reasons.append(f"Registry target is a script: {target_extension}")
        elif target_extension in EXECUTABLE_EXTENSIONS:
            tags.update({"suspicious", "executable"})
            reasons.append(f"Registry target is executable: {target_extension}")
        for reason in detect_suspicious_path(path_value):
            tags.update({"suspicious", "suspicious_path"})
            reasons.append(f"Suspicious registry path context: {reason}")
        if _is_user_writable_path(path_value):
            tags.update({"suspicious", "user_writable_path"})
            reasons.append("Registry target is in a user-writable path")
        if str(path_value or "").startswith("\\\\"):
            tags.update({"suspicious", "network_path", "unc_path"})
            reasons.append("Registry target uses UNC path")
    return tags, sorted(set(reasons))


def _severity_and_score(artifact_type: str, tags: set[str], suspicious_reasons: list[str]) -> tuple[int, str]:
    score = 10
    if artifact_type in {"run_key", "service"}:
        score += 25
    elif artifact_type in {"userassist", "bam", "dam", "run_mru", "office_trustrecords"}:
        score += 15
    elif artifact_type in {"rdp_mru", "usb_device", "mounted_devices", "typed_paths", "recent_docs", "shellbags", "opensave_mru", "lastvisited_mru", "office_recent_docs", "featureusage", "recentapps"}:
        score += 8
    elif artifact_type == "muicache":
        score += 5
    if suspicious_reasons:
        score += 20
    if "lolbin" in tags:
        score += 15
    if "network_path" in tags or "unc_path" in tags:
        score += 10
    if "persistence" in tags:
        score += 10
    if "macro_document" in tags or "trusted_document" in tags:
        score += 12
    if "double_extension" in tags:
        score += 18
    if artifact_type == "run_mru":
        if "powershell" in tags:
            score += 15
        if "lolbin" in tags:
            score += 10
        if suspicious_reasons and any(
            "encoded command" in reason.lower() or "hidden" in reason.lower() or "bypass" in reason.lower()
            for reason in suspicious_reasons
        ):
            score += 12
    if artifact_type in {"userassist", "bam", "dam"}:
        if "suspicious_path" in tags:
            score += 15
        if "script" in tags or "executable" in tags:
            score += 10
        if "user_writable_path" in tags:
            score += 10
    if artifact_type == "office_trustrecords":
        if "trusted_document" in tags:
            score += 10
        if "macro_document" in tags:
            score += 12
        if "staging_path" in tags or "user_writable_path" in tags:
            score += 8
    if score >= 65:
        return score, "high"
    if score >= 40:
        return score, "medium"
    if score >= 20:
        return score, "low"
    return score, "info"


def _build_search_text(document: dict) -> str:
    registry = document.get("registry", {}) or {}
    service = document.get("service", {}) or {}
    usb = document.get("usb", {}) or {}
    shellbag = document.get("shellbag", {}) or {}
    volume = document.get("volume", {}) or {}
    folder = document.get("folder", {}) or {}
    office = document.get("office", {}) or {}
    mru = document.get("mru", {}) or {}
    user_activity = document.get("user_activity", {}) or {}
    values = [
        document.get("source_file"),
        (document.get("event") or {}).get("type"),
        registry.get("artifact_type"),
        registry.get("hive"),
        registry.get("key_path"),
        registry.get("value_name"),
        registry.get("value_data"),
        (document.get("process") or {}).get("path"),
        (document.get("process") or {}).get("command_line"),
        (document.get("process") or {}).get("display_name"),
        (document.get("file") or {}).get("path"),
        service.get("name"),
        service.get("image_path"),
        service.get("service_dll"),
        usb.get("vendor"),
        usb.get("product"),
        usb.get("serial"),
        usb.get("friendly_name"),
        volume.get("guid"),
        volume.get("drive_letter"),
        shellbag.get("path"),
        folder.get("path"),
        office.get("app"),
        office.get("version"),
        office.get("trusted_document"),
        office.get("macro_trust_possible"),
        mru.get("order"),
        mru.get("list"),
        user_activity.get("kind"),
        user_activity.get("application"),
        user_activity.get("activity_target"),
        (document.get("destination") or {}).get("hostname"),
        (document.get("user") or {}).get("name"),
        (document.get("user") or {}).get("sid"),
        " ".join(document.get("tags") or []),
        " ".join(document.get("suspicious_reasons") or []),
    ]
    return " | ".join(str(value).strip() for value in values if value not in (None, "", []))[:8192]


def _raw_summary(document: dict) -> str:
    registry = document.get("registry", {}) or {}
    process = document.get("process", {}) or {}
    service = document.get("service", {}) or {}
    file_data = document.get("file", {}) or {}
    usb = document.get("usb", {}) or {}
    folder = document.get("folder", {}) or {}
    office = document.get("office", {}) or {}
    parts = [
        f"Subtype={registry.get('artifact_type')}" if registry.get("artifact_type") else None,
        f"Key={registry.get('key_path')}" if registry.get("key_path") else None,
        f"Value={registry.get('value_name')}" if registry.get("value_name") else None,
        f"Data={registry.get('value_data')}" if registry.get("value_data") else None,
        f"Process={process.get('path') or process.get('command_line')}" if process.get("path") or process.get("command_line") else None,
        f"Service={service.get('name')}" if service.get("name") else None,
        f"ServiceDll={service.get('service_dll')}" if service.get("service_dll") else None,
        f"File={file_data.get('path')}" if file_data.get("path") else None,
        f"Folder={folder.get('path')}" if folder.get("path") else None,
        f"Office={office.get('app')}" if office.get("app") else None,
        f"USB={usb.get('vendor') or usb.get('product') or usb.get('serial')}" if usb.get("vendor") or usb.get("product") or usb.get("serial") else None,
    ]
    return " | ".join(part for part in parts if part)[:2000]


def _apply_service_fields(document: dict, key_path: str | None, value_name: str | None, value_data: str | None) -> None:
    value_lower = str(value_name or "").lower()
    if value_lower == "imagepath":
        document["service"]["image_path"] = value_data
        document["process"]["path"] = value_data
    elif value_lower == "displayname":
        document["service"]["display_name"] = value_data
    elif value_lower == "start":
        document["service"]["start_type"] = value_data
    elif value_lower == "type":
        document["service"]["service_type"] = value_data
    elif value_lower in {"objectname", "accountname"}:
        document["service"]["account"] = value_data
    elif value_lower == "description":
        document["service"]["description"] = value_data
    elif value_lower == "servicedll" or "\\parameters" in str(key_path or "").lower() and value_lower.endswith("dll"):
        document["service"]["service_dll"] = value_data


def _set_destination_from_unc(document: dict, path: str | None) -> None:
    normalized = _normalize_value(path)
    if not normalized or not normalized.startswith("\\\\"):
        return
    parts = normalized.lstrip("\\").split("\\")
    if not parts:
        return
    document["destination"]["hostname"] = normalize_hostname(parts[0])
    document["network"]["path"] = normalized
    if len(parts) > 1:
        document["network"]["share_name"] = parts[1]
    document["network"]["direction"] = "access"


def _set_file_from_path(document: dict, path: str | None) -> None:
    normalized = _normalize_value(path)
    if not normalized:
        return
    document["file"]["path"] = normalized
    document["file"]["name"] = _basename(normalized)
    document["file"]["extension"] = _suffix(normalized)
    _set_destination_from_unc(document, normalized)


def parse_recmd_file(case_id: str, evidence_id: str, artifact_id: str, path: Path, artifact_meta: dict) -> list[dict]:
    rows = read_delimited_rows(path)
    documents: list[dict] = []
    audit = {
        "artifact": path.name,
        "parser": "recmd",
        "records_read": len(rows),
        "records_parsed": 0,
        "events_indexed": 0,
        "missing_timestamp": 0,
        "missing_key_path": 0,
        "suspicious_count": 0,
        "persistence_count": 0,
        "run_key_count": 0,
        "service_count": 0,
        "userassist_count": 0,
        "bam_count": 0,
        "dam_count": 0,
        "muicache_count": 0,
        "usb_device_count": 0,
        "mounted_device_count": 0,
        "recent_docs_count": 0,
        "typed_paths_count": 0,
        "run_mru_count": 0,
        "office_recent_docs_count": 0,
        "opensave_mru_count": 0,
        "lastvisited_mru_count": 0,
        "office_trustrecords_count": 0,
        "featureusage_count": 0,
        "recentapps_count": 0,
        "rdp_mru_count": 0,
        "shellbags_count": 0,
        "user_activity_count": 0,
        "suspicious_command_count": 0,
        "trusted_office_document_count": 0,
        "bam_execution_count": 0,
        "userassist_execution_count": 0,
        "unsupported_raw_hive_count": 0,
        "generic_registry_count": 0,
        "top_registry_artifact_types": {},
        "top_users": {},
        "bulk_index_errors": 0,
        "top_errors": [],
    }
    subtype_counts: Counter[str] = Counter()
    user_counts: Counter[str] = Counter()

    for row in rows:
        raw_row, lowered = _normalize_row_keys(row)
        source_file = _normalize_value(_get(lowered, "SourceFile", "SourceFilename")) or path.name
        key_path = _normalize_value(_get(lowered, "KeyPath", "Path"))
        value_name = _normalize_value(_get(lowered, "ValueName", "Value"))
        value_type = _normalize_value(_get(lowered, "ValueType"))
        value_data = _normalize_value(_get(lowered, "ValueData", "Data"))
        hive_path = _normalize_value(_get(lowered, "HivePath"))
        timestamp, timestamp_type = _infer_timestamp(lowered)
        artifact_type = classify_registry_artifact((raw_row, lowered))
        hive = infer_registry_hive(source_file, hive_path, key_path) or _normalize_value(_get(lowered, "Hive"))
        user_name = _normalize_value(_get(lowered, "UserName", "Username", "User")) or infer_user_from_registry_path(source_file, key_path) or artifact_meta.get("detected_user")
        sid = _normalize_value(_get(lowered, "SID")) or extract_sid_from_key_path(key_path)

        document = _base_document(case_id, evidence_id, artifact_id, source_file, raw_row, artifact_meta, timestamp, timestamp_type)
        document["registry"].update(
            {
                "hive": hive,
                "hive_path": hive_path,
                "key_path": key_path,
                "key_name": _normalize_value(_get(lowered, "KeyName")),
                "value_name": value_name,
                "value_type": value_type,
                "value_data": value_data,
                "last_write_time": _parse_timestamp(_get(lowered, "LastWriteTime", "LastWrite", "LastWriteTimestamp")),
                "artifact_type": artifact_type,
                "plugin": _normalize_value(_get(lowered, "Plugin")),
                "batch": _normalize_value(_get(lowered, "Batch")),
            }
        )
        document["event"]["timeline_include"] = bool(timestamp)
        if user_name and is_valid_username(user_name):
            document["user"]["name"] = user_name
            user_counts[str(user_name)] += 1
        if sid:
            document["user"]["sid"] = sid
        if not document["host"]["name"]:
            host_candidate = _normalize_value(_get(lowered, "MachineID", "HostName", "Hostname"))
            if host_candidate:
                normalized_host = normalize_hostname(host_candidate)
                if normalized_host:
                    document["host"]["name"] = normalized_host
                    document["host"]["hostname"] = normalized_host

        suspicious_tags: set[str] = set()
        suspicious_reasons: list[str] = []
        subtype_counts[artifact_type] += 1
        user_activity_subtypes = {
            "userassist",
            "bam",
            "dam",
            "typed_paths",
            "run_mru",
            "recent_docs",
            "office_recent_docs",
            "opensave_mru",
            "lastvisited_mru",
            "shellbags",
            "office_trustrecords",
            "featureusage",
            "recentapps",
        }
        parser_by_subtype = {
            "userassist": "userassist_registry",
            "bam": "bam_dam_registry",
            "dam": "bam_dam_registry",
            "typed_paths": "typed_paths_registry",
            "run_mru": "run_mru_registry",
            "recent_docs": "recent_docs_registry",
            "office_recent_docs": "office_recent_docs_registry",
            "opensave_mru": "opensave_mru_registry",
            "lastvisited_mru": "lastvisited_mru_registry",
            "shellbags": "shellbags_registry",
            "office_trustrecords": "office_trustrecords_registry",
            "featureusage": "featureusage_registry",
            "recentapps": "recent_apps_registry",
        }
        if artifact_type in user_activity_subtypes:
            document["artifact"]["type"] = "user_activity"
            document["artifact"]["parser"] = parser_by_subtype.get(artifact_type, "user_activity_registry_raw")
            document["event"]["category"] = "user_activity"
            document["tags"] = sorted(set(document["tags"]) | {"user_activity"})
            audit["user_activity_count"] += 1

        if not timestamp:
            audit["missing_timestamp"] += 1
            document["data_quality"].append("missing_timestamp")
        if not key_path:
            audit["missing_key_path"] += 1
            document["data_quality"].append("missing_key_path")

        if artifact_type == "run_key":
            audit["run_key_count"] += 1
            audit["persistence_count"] += 1
            process_path = extract_executable_from_command(value_data) or _extract_path_like_value(value_data)
            _set_file_from_path(document, process_path)
            document["process"]["path"] = process_path
            document["process"]["name"] = _basename(process_path)
            document["process"]["command_line"] = value_data
            suspicious_tags, suspicious_reasons = _detect_registry_suspicious(value_data, process_path)
            document["event"].update(
                {
                    "category": "persistence",
                    "type": "registry_run_key",
                    "action": "registry_persistence",
                    "message": f"Run key persistence: {value_name or 'unknown'} -> {value_data or 'unknown'}",
                }
            )
            document["tags"] = ["registry", "persistence", "run_key"]
        elif artifact_type == "service":
            audit["service_count"] += 1
            audit["persistence_count"] += 1
            service_name = extract_service_name_from_key_path(key_path)
            document["service"]["name"] = service_name
            _apply_service_fields(document, key_path, value_name, value_data)
            service_target = document["service"].get("image_path") or document["service"].get("service_dll")
            if service_target:
                _set_file_from_path(document, str(service_target))
                if not document["process"]["path"]:
                    document["process"]["path"] = str(service_target)
                    document["process"]["name"] = _basename(str(service_target))
            suspicious_tags, suspicious_reasons = _detect_registry_suspicious(value_data, document["service"].get("image_path"), document["service"].get("service_dll"))
            document["event"].update(
                {
                    "category": "persistence",
                    "type": "registry_service",
                    "action": "registry_service_configuration",
                    "message": f"Registry service: {service_name or 'unknown'} -> {service_target or value_data or 'unknown'}",
                }
            )
            document["tags"] = ["registry", "service", "persistence"]
        elif artifact_type == "userassist":
            audit["userassist_count"] += 1
            audit["userassist_execution_count"] += 1
            decoded_value = decode_userassist_rot13(value_name) or decode_userassist_rot13(value_data)
            process_path = _extract_path_like_value(decoded_value, value_data)
            _set_file_from_path(document, process_path)
            document["process"]["path"] = process_path
            document["process"]["name"] = _basename(process_path)
            document["process"]["display_name"] = decoded_value if decoded_value and decoded_value != process_path else None
            document["execution"].update(
                {
                    "source": "userassist",
                    "run_count": _parse_int(_get(lowered, "RunCount")),
                    "focus_time": _parse_int(_get(lowered, "FocusTime")),
                    "last_run": _parse_timestamp(_get(lowered, "LastRun", "LastExecuted", "LastExecutionTime")),
                    "program_name": _basename(process_path),
                    "confidence": "high",
                    "is_execution_confirmed": True,
                }
            )
            suspicious_tags, suspicious_reasons = _detect_registry_suspicious(decoded_value or value_data, process_path)
            document["user_activity"].update({"kind": "recent_program_execution", "application": _basename(process_path), "activity_target": process_path})
            document["event"].update(
                {
                    "category": "user_activity",
                    "type": "user_program_execution_observed",
                    "action": "userassist_program_execution",
                    "message": f"UserAssist execution: {process_path or decoded_value or 'unknown'}",
                }
            )
            document["tags"] = ["registry", "userassist", "execution", "user_activity"]
        elif artifact_type in {"bam", "dam"}:
            audit[f"{artifact_type}_count"] += 1
            audit["bam_execution_count"] += 1 if artifact_type == "bam" else 0
            process_path = _extract_registry_execution_path(lowered, value_name, value_data)
            _set_file_from_path(document, process_path)
            document["process"]["path"] = process_path
            document["process"]["name"] = _basename(process_path)
            document["execution"].update(
                {
                    "source": artifact_type,
                    "last_run": timestamp,
                    "program_name": _basename(process_path),
                    "confidence": "high" if artifact_type == "bam" else "medium",
                    "is_execution_confirmed": True if artifact_type == "bam" else False,
                }
            )
            suspicious_tags, suspicious_reasons = _detect_registry_suspicious(value_data, process_path)
            document["user_activity"].update({"kind": "background_execution", "application": _basename(process_path), "activity_target": process_path})
            document["event"].update(
                {
                    "category": "user_activity",
                    "type": "background_app_execution_observed",
                    "action": f"{artifact_type}_program_execution_observed",
                    "message": f"{artifact_type.upper()} execution: {process_path or _basename(process_path) or value_name or value_data or 'unknown'}",
                }
            )
            document["tags"] = ["registry", artifact_type, "execution"]
        elif artifact_type == "muicache":
            audit["muicache_count"] += 1
            process_path = _extract_path_like_value(value_name, value_data)
            _set_file_from_path(document, process_path)
            document["process"]["path"] = process_path
            document["process"]["name"] = _basename(process_path)
            document["process"]["display_name"] = value_data if value_data and value_data != process_path else None
            suspicious_tags, suspicious_reasons = _detect_registry_suspicious(value_data, process_path)
            document["execution"].update({"source": "muicache", "program_name": _basename(process_path), "confidence": "low"})
            document["event"].update(
                {
                    "category": "execution",
                    "type": "muicache_entry",
                    "action": "program_presence_or_execution_hint",
                    "message": f"MUICache entry: {process_path or 'unknown'} -> {value_data or 'unknown'}",
                }
            )
            document["tags"] = ["registry", "muicache", "execution_hint"]
        elif artifact_type == "usb_device":
            audit["usb_device_count"] += 1
            usb_fields = extract_usb_identifiers_from_key_path(key_path)
            document["usb"].update(
                {
                    **usb_fields,
                    "friendly_name": value_data if value_name and value_name.lower() in {"friendlyname", "devicedesc"} else None,
                    "container_id": value_data if value_name and value_name.lower() == "containerid" else None,
                    "first_install_time": _parse_timestamp(_get(lowered, "FirstInstallTime", "InstallDate")),
                    "last_connected_time": _parse_timestamp(_get(lowered, "LastConnectedTime")),
                    "last_removal_time": _parse_timestamp(_get(lowered, "LastRemovalTime")),
                }
            )
            document["event"].update(
                {
                    "category": "device",
                    "type": "usb_device_seen",
                    "action": "usb_registry_artifact",
                    "message": f"USB device seen: {document['usb'].get('friendly_name') or document['usb'].get('product') or document['usb'].get('serial') or 'unknown device'}",
                }
            )
            document["tags"] = ["registry", "usb", "device", "removable_media"]
        elif artifact_type == "mounted_devices":
            audit["mounted_device_count"] += 1
            drive_letter = None
            guid = None
            if value_name:
                drive_match = re.search(r"DosDevices\\([A-Z]:)", value_name, flags=re.IGNORECASE)
                guid_match = re.search(r"(Volume\{[^}]+\})", value_name, flags=re.IGNORECASE)
                drive_letter = drive_match.group(1) if drive_match else None
                guid = guid_match.group(1) if guid_match else None
            document["volume"].update(
                {
                    "drive_letter": drive_letter,
                    "guid": guid,
                    "serial": _normalize_value(_get(lowered, "VolumeSerialNumber")),
                }
            )
            document["event"].update(
                {
                    "category": "device",
                    "type": "mounted_device",
                    "action": "mounted_device_mapping",
                    "message": f"Mounted device: {drive_letter or guid or value_name or 'unknown'}",
                }
            )
            document["tags"] = ["registry", "mounted_device", "drive_mapping"]
        elif artifact_type == "typed_paths":
            audit["typed_paths_count"] += 1
            _set_file_from_path(document, value_data)
            document["mru"]["order"] = _parse_mru_order(value_name)
            document["mru"]["list"] = "TypedPaths"
            document["folder"]["path"] = _normalize_value(value_data)
            document["user_activity"].update({"kind": "typed_path", "activity_target": _normalize_value(value_data)})
            document["event"].update(
                {
                    "category": "user_activity",
                    "type": "user_typed_path_observed",
                    "action": "explorer_typed_path",
                    "message": f"Explorer typed path: {value_data or 'unknown'}",
                }
            )
            document["tags"] = ["registry", "explorer", "typed_path", "user_activity"]
        elif artifact_type == "run_mru":
            audit["run_mru_count"] += 1
            audit["suspicious_command_count"] += 1 if value_data and ("encodedcommand" in value_data.lower() or "-enc" in value_data.lower()) else 0
            process_path = extract_executable_from_command(value_data) or _extract_path_like_value(value_data)
            _set_file_from_path(document, process_path)
            document["process"]["path"] = process_path
            document["process"]["name"] = _basename(process_path)
            document["process"]["command_line"] = value_data
            document["execution"].update({"source": "run_mru", "program_name": _basename(process_path), "confidence": "medium", "is_execution_confirmed": False})
            document["mru"]["order"] = _parse_mru_order(value_name)
            document["mru"]["list"] = "RunMRU"
            document["user_activity"].update({"kind": "run_dialog", "application": _basename(process_path), "activity_target": value_data})
            suspicious_tags, suspicious_reasons = _detect_registry_suspicious(value_data, process_path)
            document["event"].update(
                {
                    "category": "user_activity",
                    "type": "user_run_command_observed",
                    "action": "run_dialog_command",
                    "message": f"RunMRU command: {value_data or 'unknown'}",
                }
            )
            document["tags"] = ["registry", "run_mru", "execution", "user_activity"]
        elif artifact_type == "recent_docs":
            audit["recent_docs_count"] += 1
            target_path = _target_from_registry_value(value_name, value_data)
            _set_file_from_path(document, target_path)
            if not document["file"]["name"]:
                document["file"]["name"] = _normalize_value(value_data) or _normalize_value(value_name)
            _, extra_tags = _classify_target_path(document["file"]["path"])
            document["mru"]["order"] = _parse_mru_order(value_name)
            document["mru"]["list"] = "RecentDocs"
            document["user_activity"].update({"kind": "recent_document", "activity_target": document["file"].get("path") or document["file"].get("name")})
            path_tags, path_reasons = _risk_document_path(document["file"]["path"] or document["file"]["name"])
            suspicious_tags |= path_tags
            suspicious_reasons = sorted(set(suspicious_reasons + path_reasons))
            document["event"].update(
                {
                    "category": "user_activity",
                    "type": "user_recent_document_observed",
                    "action": "recent_document_entry",
                    "message": f"Recent document: {document['file'].get('path') or document['file'].get('name') or 'unknown'}",
                }
            )
            document["tags"] = ["registry", "recent_docs", "file_access", "user_activity"] + sorted(extra_tags)
        elif artifact_type == "office_recent_docs":
            audit["office_recent_docs_count"] += 1
            target_path = _extract_mru_target(value_name, value_data)
            _set_file_from_path(document, target_path)
            document["mru"]["order"] = _parse_mru_order(value_name)
            document["mru"]["list"] = "Office FileMRU"
            app_match = re.search(r"\\office\\([^\\]+)\\([^\\]+)\\filemru", str(key_path or ""), flags=re.IGNORECASE)
            document["office"]["version"] = app_match.group(1) if app_match else None
            document["office"]["app"] = app_match.group(2) if app_match else None
            document["user_activity"].update({"kind": "recent_document", "application": document["office"]["app"], "activity_target": target_path})
            path_tags, path_reasons = _risk_document_path(target_path)
            suspicious_tags |= path_tags
            suspicious_reasons = sorted(set(suspicious_reasons + path_reasons))
            document["event"].update(
                {
                    "category": "user_activity",
                    "type": "user_recent_document_observed",
                    "action": "office_recent_document_entry",
                    "message": f"Office recent document: {target_path or value_name or 'unknown'}",
                }
            )
            document["tags"] = ["registry", "office_mru", "file_access", "user_activity"]
        elif artifact_type == "opensave_mru":
            audit["opensave_mru_count"] += 1
            target_path = _extract_mru_target(value_name, value_data)
            _set_file_from_path(document, target_path)
            document["mru"]["order"] = _parse_mru_order(value_name)
            document["mru"]["list"] = "OpenSavePidlMRU"
            app_match = re.search(r"\\opensavepidlmru\\([^\\]+)", str(key_path or ""), flags=re.IGNORECASE)
            document["user_activity"].update({"kind": "file_dialog", "application": app_match.group(1) if app_match else None, "activity_target": target_path})
            path_tags, path_reasons = _risk_document_path(target_path)
            suspicious_tags |= path_tags
            suspicious_reasons = sorted(set(suspicious_reasons + path_reasons))
            document["event"].update(
                {
                    "category": "user_activity",
                    "type": "user_file_dialog_observed",
                    "action": "opensave_dialog_entry",
                    "message": f"Open/Save dialog item: {target_path or value_name or 'unknown'}",
                }
            )
            document["tags"] = ["registry", "opensave_mru", "file_access", "user_activity"]
        elif artifact_type == "lastvisited_mru":
            audit["lastvisited_mru_count"] += 1
            target_path = _extract_mru_target(value_name, value_data)
            _set_file_from_path(document, target_path)
            document["mru"]["order"] = _parse_mru_order(value_name)
            document["mru"]["list"] = "LastVisitedPidlMRU"
            document["user_activity"].update({"kind": "file_dialog", "application": _basename(target_path), "activity_target": target_path})
            path_tags, path_reasons = _risk_document_path(target_path)
            suspicious_tags |= path_tags
            suspicious_reasons = sorted(set(suspicious_reasons + path_reasons))
            document["event"].update(
                {
                    "category": "user_activity",
                    "type": "user_file_dialog_observed",
                    "action": "last_visited_dialog_entry",
                    "message": f"Last visited dialog item: {target_path or value_name or 'unknown'}",
                }
            )
            document["tags"] = ["registry", "lastvisited_mru", "file_access", "user_activity"]
        elif artifact_type == "rdp_mru":
            audit["rdp_mru_count"] += 1
            destination = _normalize_value(value_data) or _normalize_value(value_name)
            if destination:
                document["destination"]["hostname"] = destination
            document["event"].update(
                {
                    "category": "remote_access",
                    "type": "rdp_mru",
                    "action": "rdp_client_history",
                    "message": f"RDP MRU: {destination or 'unknown'}",
                }
            )
            document["tags"] = ["registry", "rdp", "remote_access", "mru"]
        elif artifact_type == "shellbags":
            audit["shellbags_count"] += 1
            target_path = _target_from_registry_value(value_data, value_name)
            _set_file_from_path(document, target_path)
            document["folder"]["path"] = target_path
            document["mru"]["order"] = _parse_mru_order(_normalize_value(_get(lowered, "MRU")) or value_name)
            document["mru"]["list"] = "Shellbags"
            document["user_activity"].update({"kind": "folder_access", "activity_target": target_path})
            document["shellbag"].update(
                {
                    "path": target_path,
                    "mru": _normalize_value(_get(lowered, "MRU")),
                    "slot": _normalize_value(_get(lowered, "Slot")),
                    "last_write": _parse_timestamp(_get(lowered, "LastWriteTime", "LastWrite")),
                }
            )
            document["event"].update(
                {
                    "category": "user_activity",
                    "type": "user_folder_access_observed",
                    "action": "shellbag_folder_observed",
                    "message": f"Shellbag folder: {target_path or 'unknown'}",
                }
            )
            document["tags"] = ["registry", "shellbags", "folder_access", "user_activity"]
        elif artifact_type == "office_trustrecords":
            audit["office_trustrecords_count"] += 1
            target_path = _extract_mru_target(value_name, value_data) or _normalize_value(value_name)
            _set_file_from_path(document, target_path)
            document["office"]["trusted_document"] = True
            document["office"]["macro_trust_possible"] = _suffix(target_path) in MACRO_DOCUMENT_EXTENSIONS
            app_match = re.search(r"\\office\\([^\\]+)\\([^\\]+)\\security\\trusted documents\\trustrecords", str(key_path or ""), flags=re.IGNORECASE)
            document["office"]["version"] = app_match.group(1) if app_match else None
            document["office"]["app"] = app_match.group(2) if app_match else None
            document["user_activity"].update({"kind": "office_trust", "application": document["office"]["app"], "activity_target": target_path})
            suspicious_tags |= {"trusted_document"}
            path_tags, path_reasons = _risk_document_path(target_path)
            suspicious_tags |= path_tags
            suspicious_reasons = sorted(set(suspicious_reasons + path_reasons + ["Office trusted document record observed"]))
            if document["office"]["macro_trust_possible"]:
                suspicious_reasons.append("Trusted macro-enabled Office document observed")
            audit["trusted_office_document_count"] += 1
            document["event"].update(
                {
                    "category": "user_activity",
                    "type": "office_document_trusted",
                    "action": "office_trust_record_observed",
                    "message": f"Office trusted document: {target_path or value_name or 'unknown'}",
                }
            )
            document["tags"] = ["registry", "office", "trusted_document", "user_activity"]
        elif artifact_type == "featureusage":
            audit["featureusage_count"] += 1
            application = _basename(_normalize_value(value_name)) or _normalize_value(value_name)
            document["user_activity"].update({"kind": "app_usage", "application": application, "activity_target": _normalize_value(value_name)})
            document["execution"].update({"source": "featureusage", "run_count": _parse_int(value_data), "confidence": "low", "is_execution_confirmed": False})
            document["event"].update(
                {
                    "category": "user_activity",
                    "type": "user_app_usage_observed",
                    "action": "feature_usage_observed",
                    "message": f"FeatureUsage observed: {application or 'unknown application'}",
                }
            )
            document["tags"] = ["registry", "featureusage", "user_activity"]
        elif artifact_type == "recentapps":
            audit["recentapps_count"] += 1
            target_path = _extract_mru_target(value_name, value_data) or _normalize_value(value_data) or _normalize_value(value_name)
            _set_file_from_path(document, target_path)
            document["user_activity"].update({"kind": "recent_app", "application": _basename(target_path) or _normalize_value(value_name), "activity_target": target_path})
            document["execution"].update(
                {
                    "source": "recentapps",
                    "run_count": _parse_int(_get(lowered, "LaunchCount", "Count", "ValueData")) or _parse_int(value_data),
                    "last_run": _parse_timestamp(_get(lowered, "LastAccessTime", "LastAccess", "Timestamp")) or timestamp,
                    "confidence": "medium",
                    "is_execution_confirmed": True,
                }
            )
            path_tags, path_reasons = _risk_document_path(target_path)
            suspicious_tags |= path_tags
            suspicious_reasons = sorted(set(suspicious_reasons + path_reasons))
            document["event"].update(
                {
                    "category": "user_activity",
                    "type": "user_app_usage_observed",
                    "action": "recent_app_usage_observed",
                    "message": f"Recent app observed: {target_path or value_name or 'unknown'}",
                }
            )
            document["tags"] = ["registry", "recentapps", "user_activity"]
        else:
            audit["generic_registry_count"] += 1
            key_display = f"{(key_path or 'unknown')}\\{value_name or ''}".rstrip("\\")
            value_preview = _preview_value(value_data)
            document["event"].update(
                {
                    "category": "registry",
                    "type": "registry_value",
                    "action": "registry_observed",
                    "message": f"Registry value: {key_display}" + (f" = {value_preview}" if value_preview else ""),
                }
            )
            document["tags"] = ["registry"]

        if artifact_type in {"typed_paths", "recent_docs", "shellbags", "office_recent_docs", "opensave_mru", "lastvisited_mru", "office_trustrecords", "recentapps"}:
            suspicious_path_tags, suspicious_path_reasons = _detect_registry_suspicious(value_data, document["file"].get("path"), document.get("folder", {}).get("path"))
            suspicious_tags |= suspicious_path_tags
            suspicious_reasons = sorted(set(suspicious_reasons + suspicious_path_reasons))
        if artifact_type == "rdp_mru" and document["destination"].get("hostname"):
            suspicious_tags.add("remote_access")
        if artifact_type == "usb_device":
            suspicious_tags.add("usb")
        if artifact_type in {"run_key", "service"}:
            suspicious_tags.add("persistence")
        if artifact_type == "office_trustrecords" and document["office"].get("trusted_document"):
            suspicious_tags.add("trusted_document")

        score, severity = _severity_and_score(artifact_type, set(document["tags"]) | suspicious_tags, suspicious_reasons)
        if suspicious_reasons:
            audit["suspicious_count"] += 1
        document["tags"] = sorted(set(document["tags"]) | suspicious_tags)
        document["suspicious_reasons"] = suspicious_reasons
        document["risk_score"] = score
        document["event"]["severity"] = severity
        document["raw_summary"] = _raw_summary(document)
        document["search_text"] = _build_search_text(document)
        documents.append(document)

    audit["records_parsed"] = len(documents)
    audit["events_indexed"] = len(documents)
    audit["top_registry_artifact_types"] = dict(subtype_counts.most_common(15))
    audit["top_users"] = dict(user_counts.most_common(10))
    artifact_meta["ingest_audit"] = audit
    return documents


class RECmdParser(ArtifactParser):
    def can_parse(self, path: Path, headers: list[str] | None = None) -> bool:
        lower_name = path.name.lower()
        if "recmd_output.csv" in lower_name or lower_name.endswith("_recmd_output.csv") or "recmd" in lower_name:
            return True
        normalized_headers = {_canonicalize_key(header) for header in (headers or []) if header}
        required = {"keypath", "valuename"}
        return len(RECMD_HEADER_HINTS & normalized_headers) >= 3 and required <= normalized_headers

    def parse(self, path: Path, **kwargs):
        return parse_recmd_file(
            kwargs["case_id"],
            kwargs["evidence_id"],
            kwargs["artifact_id"],
            path,
            kwargs["artifact_meta"],
        )
