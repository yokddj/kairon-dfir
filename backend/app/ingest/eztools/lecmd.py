from collections import Counter
from datetime import UTC
from pathlib import Path, PureWindowsPath
import re
from uuid import uuid4

from dateutil import parser as date_parser

from app.analysis.suspicious import detect_suspicious_path, detect_suspicious_powershell
from app.ingest.eztools.base import ArtifactParser, read_delimited_rows
from app.ingest.identity_extraction import extract_user_from_path, normalize_hostname


LECMD_HEADER_HINTS = {
    "sourcefile",
    "sourcefilename",
    "targetpath",
    "targetidabsolutepath",
    "localpath",
    "workingdirectory",
    "arguments",
    "machineid",
}
WINDOWS_EMPTY_VALUES = {"", "-", "--", "n/a", "na", "(null)", "null"}
LNK_SHELL_TARGETS = {
    "desktop",
    "internet explorer (homepage)",
    "computer",
    "this pc",
    "control panel",
    "libraries",
    "network",
    "documents",
    "downloads",
    "music",
    "pictures",
    "videos",
    "recycle bin",
}
SCRIPT_EXTENSIONS = {".ps1", ".bat", ".cmd", ".vbs", ".js", ".jse", ".wsf", ".msi"}
EXECUTABLE_EXTENSIONS = {".exe", ".com", ".dll", ".scr"} | SCRIPT_EXTENSIONS
DOCUMENT_EXTENSIONS = {".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx", ".pdf", ".txt", ".rtf"}
ARGUMENT_TOKENS = {
    "powershell": "LNK arguments invoke PowerShell",
    "-enc": "LNK arguments contain PowerShell encoded command",
    "-encodedcommand": "LNK arguments contain PowerShell encoded command",
    "cmd /c": "LNK arguments invoke cmd /c",
    "rundll32": "LNK arguments invoke rundll32",
    "regsvr32": "LNK arguments invoke regsvr32",
    "mshta": "LNK arguments invoke mshta",
    "wscript": "LNK arguments invoke wscript",
    "cscript": "LNK arguments invoke cscript",
    "certutil": "LNK arguments invoke certutil",
    "bitsadmin": "LNK arguments invoke bitsadmin",
}
LOL_BIN_HINTS = {
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
}


def _merge_local_path(local_base: str | None, common_suffix: str | None) -> str | None:
    local = (local_base or "").strip()
    suffix = (common_suffix or "").strip()
    if local and suffix:
        if local.lower().endswith(suffix.lower()):
            return local
        if suffix.startswith("\\") or local.endswith("\\"):
            return f"{local.rstrip('\\')}{suffix}"
        return f"{local.rstrip('\\')}\\{suffix}"
    return local or suffix or None


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


def _clean_icon_location_target(value: str | None) -> str | None:
    normalized = _normalize_value(value)
    if not normalized:
        return None
    candidate = normalized.strip().strip('"')
    if "," in candidate:
        candidate = candidate.split(",", 1)[0].strip()
    candidate = candidate.replace("/", "\\")
    if not candidate:
        return None
    if _suffix(candidate) != ".exe":
        return None
    if candidate.startswith("%") or candidate.startswith("\\\\") or re.match(r"^[a-zA-Z]:\\", candidate):
        return candidate
    return None


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


def _choose_timestamp(lowered: dict[str, object]) -> tuple[str | None, str]:
    candidates = [
        ("target_accessed", _get(lowered, "TargetAccessed")),
        ("target_modified", _get(lowered, "TargetModified")),
        ("lnk_modified", _get(lowered, "SourceModified")),
        ("lnk_created", _get(lowered, "SourceCreated")),
        ("target_created", _get(lowered, "TargetCreated")),
    ]
    for ts_type, value in candidates:
        parsed = _parse_timestamp(value)
        if parsed:
            return parsed, ts_type
    return None, "unknown"


def _target_path(lowered: dict[str, object]) -> str | None:
    return _normalize_value(
        _get(
            lowered,
            "LocalPath",
            "CommonPath",
            "NetworkPath",
            "TargetPath",
            "TargetIDAbsolutePath",
            "RelativePath",
        )
    )


def _basename(path: str | None) -> str | None:
    normalized = _normalize_value(path)
    if not normalized:
        return None
    return PureWindowsPath(normalized).name or None


def _suffix(path: str | None) -> str | None:
    normalized = _normalize_value(path)
    if not normalized:
        return None
    suffix = PureWindowsPath(normalized).suffix.lower()
    return suffix or None


def is_lnk_partial_or_shell_target(value: str | None) -> bool:
    normalized = _normalize_value(value)
    if not normalized:
        return True
    compact = normalized.strip().rstrip("\\/").strip().lower()
    if compact in LNK_SHELL_TARGETS:
        return True
    if normalized.endswith("\\") and compact in LNK_SHELL_TARGETS:
        return True
    if re.fullmatch(r"desktop\\+", normalized, flags=re.IGNORECASE):
        return True
    if normalized.startswith("\\\\"):
        return False
    if re.match(r"^[a-zA-Z]:\\", normalized):
        return False
    if normalized.startswith("..\\") or normalized.startswith("../"):
        return False
    if _suffix(normalized):
        return False
    if "\\" not in normalized and "/" not in normalized:
        return True
    components = [part for part in re.split(r"[\\/]+", normalized) if part and part not in {".", ".."}]
    return len(components) <= 1


def is_lnk_useful_path(value: str | None) -> bool:
    normalized = _normalize_value(value)
    if not normalized:
        return False
    if normalized.startswith("\\\\"):
        return True
    if re.match(r"^[a-zA-Z]:\\", normalized):
        return True
    if normalized.startswith("..\\") or normalized.startswith("../"):
        return True
    if _suffix(normalized):
        return True
    components = [part for part in re.split(r"[\\/]+", normalized) if part and part not in {".", ".."}]
    return len(components) >= 2 and not is_lnk_partial_or_shell_target(normalized)


def resolve_lnk_effective_path(lnk: dict, raw: dict | None = None) -> dict[str, object]:
    raw = raw or {}

    def pick_value(*normalized_keys: str, raw_keys: tuple[str, ...] = ()) -> str | None:
        for key in normalized_keys:
            value = _normalize_value(lnk.get(key))
            if value:
                return value
        for key in raw_keys:
            value = _normalize_value(raw.get(key))
            if value:
                return value
        return None

    local_path = pick_value("local_path", raw_keys=("LocalPath", "LocalBasePath"))
    common_path = pick_value("common_path", raw_keys=("CommonPath", "CommonPathSuffix"))
    target_path = pick_value("target_path", raw_keys=("TargetPath",))
    target_id_absolute_path = pick_value("target_id_absolute_path", raw_keys=("TargetIDAbsolutePath",))
    network_path = pick_value("network_path", raw_keys=("NetworkPath", "NetName", "ShareName"))
    relative_path = pick_value("relative_path", raw_keys=("RelativePath",))
    working_directory = pick_value("working_directory", raw_keys=("WorkingDirectory",))
    environment_target = pick_value("environment_target", raw_keys=("EnvironmentTarget",))
    icon_location = pick_value("icon_location", raw_keys=("IconLocation",))
    description = pick_value("description", "display_name", raw_keys=("Description", "NameString", "DisplayName"))
    relaunch_command = pick_value("appusermodel_relaunch_command", raw_keys=("AppUserModel_RelaunchCommand",))
    property_store_target = pick_value("property_store_target_path", raw_keys=("PropertyStoreTargetParsingPath", "System.Link.TargetParsingPath"))
    combined_relative = None
    merged_local_common = None
    if working_directory and relative_path and not is_lnk_partial_or_shell_target(relative_path):
        combined_relative = _merge_local_path(working_directory, relative_path)
    if local_path and common_path and (is_lnk_partial_or_shell_target(local_path) or not is_lnk_useful_path(local_path)):
        merged_local_common = _merge_local_path(local_path, common_path)
    cleaned_icon_location = _clean_icon_location_target(icon_location)

    candidates: list[tuple[str, str | None, bool]] = [
        ("local_path", local_path, False),
        ("local_path+common_path", merged_local_common, False),
        ("target_path", target_path, False),
        ("environment_target", environment_target, False),
        ("property_store_target_path", property_store_target, False),
        ("appusermodel_relaunch_command", relaunch_command, False),
        ("working_directory+relative_path", combined_relative, False),
        ("target_id_absolute_path", target_id_absolute_path, False),
        ("network_path", network_path, False),
        ("relative_path", relative_path, True),
        ("icon_location_low_confidence", cleaned_icon_location, False),
        ("description", description if is_lnk_useful_path(description) else None, True),
    ]

    for source, value, partial_ok in candidates:
        if not value:
            continue
        partial = is_lnk_partial_or_shell_target(value)
        useful = is_lnk_useful_path(value)
        is_shell = partial and not useful
        if useful or (partial_ok and value):
            display_name = _basename(value) or value.rstrip("\\/") or value
            return {
                "effective_path": value,
                "effective_path_source": source,
                "display_name": display_name,
                "is_partial_path": partial,
                "is_shell_target": is_shell,
            }

    fallback = next((value for _, value, _ in candidates if value), None)
    fallback_source = next((source for source, value, _ in candidates if value), None)
    display_name = _basename(fallback) or (str(fallback).rstrip("\\/") if fallback else None)
    partial = is_lnk_partial_or_shell_target(fallback)
    useful = is_lnk_useful_path(fallback)
    return {
        "effective_path": fallback,
        "effective_path_source": fallback_source,
        "display_name": display_name,
        "is_partial_path": partial,
        "is_shell_target": bool(fallback and partial and not useful),
    }


def select_lnk_effective_target(lnk: dict, raw: dict | None = None) -> dict[str, object]:
    return resolve_lnk_effective_path(lnk, raw)


def _is_unc(path: str | None) -> bool:
    normalized = _normalize_value(path)
    return bool(normalized and normalized.startswith("\\\\"))


def _extract_unc_host(path: str | None) -> str | None:
    normalized = _normalize_value(path)
    if not normalized or not normalized.startswith("\\\\"):
        return None
    parts = normalized.lstrip("\\").split("\\")
    if not parts:
        return None
    return normalize_hostname(parts[0])


def _drive_type_tags(drive_type: str | None) -> set[str]:
    normalized = str(drive_type or "").strip().lower()
    tags: set[str] = set()
    if any(token in normalized for token in {"removable", "usb"}):
        tags.update({"removable_media", "usb_candidate"})
    return tags


def _classify_target(path: str | None, file_attributes: str | None = None) -> tuple[str, set[str]]:
    normalized = _normalize_value(path)
    if not normalized:
        return "file_opened", {"file_access", "lnk"}
    extension = _suffix(normalized)
    tags = {"lnk"}
    if _is_unc(normalized):
        tags.update({"network_path", "unc_path"})
    file_attributes_normalized = str(file_attributes or "").lower()
    if "fileattributedirectory" in file_attributes_normalized:
        tags.update({"file_access", "folder_access"})
        return "folder_opened", tags
    if extension in EXECUTABLE_EXTENSIONS:
        tags.update({"file_access", "execution_related", "executable"})
        if extension in SCRIPT_EXTENSIONS:
            tags.add("script")
        return "program_or_script_opened", tags
    if extension in DOCUMENT_EXTENSIONS:
        tags.update({"file_access", "document"})
        return "document_opened", tags
    if not extension and normalized.endswith("\\"):
        tags.update({"folder_access"})
        return "folder_opened", tags
    return "file_opened", tags | {"file_access"}


def _detect_suspicious_lnk(target_path: str | None, arguments: str | None, working_directory: str | None, icon_location: str | None, network_path: str | None, drive_type: str | None) -> tuple[set[str], list[str]]:
    tags: set[str] = {"lnk"}
    reasons: list[str] = []
    target_name = str(_basename(target_path) or "").lower()
    if target_name in LOL_BIN_HINTS:
        tags.update({"suspicious", "lolbin"})
        reasons.append(f"LNK target is LOLBin: {target_name}")
    for path_value in [target_path, working_directory, icon_location, network_path]:
        for reason in detect_suspicious_path(path_value):
            tags.update({"suspicious", "suspicious_path"})
            reasons.append(f"Suspicious LNK path context: {reason}")
    if _is_unc(target_path) or _is_unc(network_path):
        tags.update({"suspicious", "network_path", "unc_path"})
        reasons.append("LNK target uses UNC path")
    normalized_arguments = str(arguments or "").lower()
    for token, description in ARGUMENT_TOKENS.items():
        if token in normalized_arguments:
            tags.add("suspicious")
            if "powershell" in token or token in {"-enc", "-encodedcommand"}:
                tags.add("powershell")
            if token in {"rundll32", "regsvr32", "mshta", "certutil", "bitsadmin"}:
                tags.add("lolbin")
            reasons.append(description)
    if arguments:
        for reason in detect_suspicious_powershell(arguments):
            tags.update({"suspicious", "powershell"})
            reasons.append(f"LNK arguments suspicious token: {reason}")
    if any(token in (drive_type or "").lower() for token in {"removable", "usb"}):
        tags.update({"suspicious", "removable_media", "usb_candidate"})
        reasons.append("LNK target references removable media")
    return tags, sorted(set(reasons))


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
            "type": "lnk",
            "name": artifact_meta.get("name", source_file),
            "source_path": artifact_meta.get("source_path", source_file),
            "parser": artifact_meta.get("parser", "zimmerman"),
        },
        "event": {
            "category": "file_access",
            "type": "file_opened",
            "action": "lnk_target_accessed",
            "severity": "info",
            "message": artifact_meta.get("name", source_file),
            "timeline_include": True,
        },
        "process": {"pid": None, "name": None, "path": None, "command_line": None, "parent_pid": None, "parent_name": None, "parent_path": None, "parent_command_line": None, "integrity_level": None, "token_elevation": None},
        "file": {"path": None, "name": None, "extension": None, "size": None, "hash_sha1": None, "hash_sha256": None, "sha1": None, "sha256": None, "md5": None, "created": None, "modified": None, "accessed": None, "source_path": None},
        "lnk": {
            "source_file": None,
            "target_path": None,
            "target_id_absolute_path": None,
            "local_path": None,
            "common_path": None,
            "relative_path": None,
            "working_directory": None,
            "arguments": None,
            "icon_location": None,
            "description": None,
            "machine_id": None,
            "drive_type": None,
            "drive_serial_number": None,
            "volume_label": None,
            "volume_created": None,
            "network_path": None,
            "net_name": None,
            "device_name": None,
            "share_name": None,
            "tracker_droid": None,
            "tracker_birth_droid": None,
            "droid": None,
            "birth_droid": None,
            "mac_address": None,
            "target_created": None,
            "target_modified": None,
            "target_accessed": None,
            "source_created": None,
            "source_modified": None,
            "source_accessed": None,
        },
        "volume": {"serial": None, "label": None, "drive_type": None, "created": None},
        "network": {"direction": None, "share_name": None, "path": None, "source_ip": None, "source_port": None, "destination_ip": None, "destination_port": None, "protocol": None, "application": None, "domain": None, "url": None, "destination_hostname": None},
        "tags": ["lnk"],
        "data_quality": [],
        "risk_score": 0,
        "raw_summary": "",
        "search_text": "",
        "raw": raw_row,
        "suspicious_reasons": [],
        "source_file": source_file,
        "source_tool": "lecmd",
        "source_format": "csv",
    }


def _risk_score(tags: set[str], suspicious_reasons: list[str], event_type: str) -> tuple[int, str]:
    score = 10
    if event_type in {"program_or_script_opened", "document_opened"}:
        score += 10
    if suspicious_reasons:
        score += 20
    if "lolbin" in tags:
        score += 15
    if "network_path" in tags or "unc_path" in tags:
        score += 10
    if "removable_media" in tags:
        score += 10
    if score >= 65:
        return score, "high"
    if score >= 40:
        return score, "medium"
    if score >= 20:
        return score, "low"
    return score, "info"


def _build_search_text(document: dict) -> str:
    lnk = document.get("lnk", {}) or {}
    raw = document.get("raw", {}) or {}
    values = [
        document.get("source_file"),
        (document.get("file") or {}).get("path"),
        (document.get("file") or {}).get("name"),
        (document.get("lnk") or {}).get("source_file"),
        lnk.get("effective_path"),
        lnk.get("display_name"),
        lnk.get("local_path"),
        lnk.get("relative_path"),
        lnk.get("working_directory"),
        (document.get("lnk") or {}).get("target_path"),
        (document.get("lnk") or {}).get("arguments"),
        (document.get("lnk") or {}).get("machine_id"),
        (document.get("network") or {}).get("path"),
        (document.get("volume") or {}).get("serial"),
        raw.get("LocalPath"),
        raw.get("RelativePath"),
        raw.get("SourceFile"),
        raw.get("MachineID"),
        raw.get("VolumeSerialNumber"),
        " ".join(document.get("suspicious_reasons") or []),
    ]
    return " | ".join(str(value).strip() for value in values if value not in (None, "", []))[:8192]


def _raw_summary(target_path: str | None, source_file: str | None, arguments: str | None, drive_type: str | None, target_source: str | None) -> str:
    parts = [
        f"Target={target_path}" if target_path else None,
        f"TargetSource={target_source}" if target_source else None,
        f"Source={source_file}" if source_file else None,
        f"Args={arguments}" if arguments else None,
        f"DriveType={drive_type}" if drive_type else None,
    ]
    return " | ".join(item for item in parts if item)[:2000]


def parse_lecmd_file(case_id: str, evidence_id: str, artifact_id: str, path: Path, artifact_meta: dict) -> list[dict]:
    rows = read_delimited_rows(path)
    documents: list[dict] = []
    audit = {
        "artifact": path.name,
        "parser": "lecmd",
        "records_read": len(rows),
        "records_parsed": 0,
        "events_indexed": 0,
        "missing_timestamp": 0,
        "missing_target_path": 0,
        "suspicious_count": 0,
        "network_path_count": 0,
        "removable_media_count": 0,
        "script_target_count": 0,
        "executable_target_count": 0,
        "document_target_count": 0,
        "top_extensions": {},
        "top_users": {},
        "bulk_index_errors": 0,
        "top_errors": [],
    }
    extension_counts: Counter[str] = Counter()
    user_counts: Counter[str] = Counter()

    for row in rows:
        raw_row, lowered = _normalize_row_keys(row)
        timestamp, timestamp_type = _choose_timestamp(lowered)
        source_file = _normalize_value(_get(lowered, "SourceFile", "SourceFilename", "LnkFile", "FileName"))
        raw_target_path = _normalize_value(_get(lowered, "TargetPath"))
        target_id_absolute_path = _normalize_value(_get(lowered, "TargetIDAbsolutePath"))
        local_path = _normalize_value(_get(lowered, "LocalPath", "LocalBasePath"))
        common_path = _normalize_value(_get(lowered, "CommonPath"))
        relative_path = _normalize_value(_get(lowered, "RelativePath"))
        arguments = _normalize_value(_get(lowered, "Arguments"))
        working_directory = _normalize_value(_get(lowered, "WorkingDirectory"))
        network_path = _normalize_value(_get(lowered, "NetworkPath", "NetName", "ShareName"))
        drive_type = _normalize_value(_get(lowered, "DriveType"))
        lnk_fields = {
            "source_file": source_file,
            "target_path": raw_target_path,
            "target_id_absolute_path": target_id_absolute_path,
            "local_path": local_path,
            "common_path": common_path,
            "relative_path": relative_path,
            "working_directory": working_directory,
            "network_path": network_path,
        }
        effective_target = select_lnk_effective_target(lnk_fields, raw_row)
        target_path = _normalize_value(effective_target.get("effective_path"))
        target_path_source = _normalize_value(effective_target.get("effective_path_source"))
        display_name = _normalize_value(effective_target.get("display_name"))
        file_attributes = _normalize_value(_get(lowered, "FileAttributes"))
        event_type, base_tags = _classify_target(target_path, file_attributes)
        suspicious_tags, suspicious_reasons = _detect_suspicious_lnk(target_path, arguments, working_directory, _normalize_value(_get(lowered, "IconLocation")), network_path, drive_type)
        all_tags = set(base_tags) | suspicious_tags | _drive_type_tags(drive_type)
        if event_type == "program_or_script_opened":
            if _suffix(target_path) in SCRIPT_EXTENSIONS:
                all_tags.add("script")
                audit["script_target_count"] += 1
            else:
                audit["executable_target_count"] += 1
        if event_type == "document_opened":
            audit["document_target_count"] += 1
        if "network_path" in all_tags or "unc_path" in all_tags:
            audit["network_path_count"] += 1
        if "removable_media" in all_tags:
            audit["removable_media_count"] += 1
        if suspicious_reasons:
            audit["suspicious_count"] += 1
        if not timestamp:
            audit["missing_timestamp"] += 1
        if not target_path:
            audit["missing_target_path"] += 1

        document = _base_document(case_id, evidence_id, artifact_id, path.name, raw_row, artifact_meta, timestamp, timestamp_type)
        user_name = extract_user_from_path(source_file) or extract_user_from_path(target_path) or artifact_meta.get("detected_user")
        if user_name:
            user_counts[str(user_name)] += 1
        machine_id = _normalize_value(_get(lowered, "MachineID"))
        if machine_id and not document["host"]["name"]:
            document["host"]["name"] = machine_id.lower()
            document["host"]["hostname"] = machine_id.lower()

        target_extension = _suffix(target_path)
        if target_extension:
            extension_counts[target_extension] += 1

        target_name = _basename(target_path) or display_name
        if target_name:
            document["process"]["name"] = target_name if target_extension in EXECUTABLE_EXTENSIONS else None
            document["process"]["path"] = target_path if target_extension in EXECUTABLE_EXTENSIONS else None
            if arguments and target_extension in EXECUTABLE_EXTENSIONS:
                document["process"]["command_line"] = f"{target_path} {arguments}".strip()

        unc_host = _extract_unc_host(target_path or network_path)
        if unc_host:
            document["destination"]["hostname"] = unc_host

        document["event"]["category"] = "file_access"
        document["event"]["type"] = event_type
        document["event"]["action"] = "lnk_target_accessed"
        document["event"]["message"] = f"LNK target accessed: {target_path or display_name or 'unknown target'}"
        document["event"]["timeline_include"] = bool(timestamp)
        document["file"].update(
            {
                "path": target_path,
                "name": target_name,
                "extension": target_extension,
                "created": _parse_timestamp(_get(lowered, "TargetCreated", "TargetBirthCreated")),
                "modified": _parse_timestamp(_get(lowered, "TargetModified", "TargetBirthModified")),
                "accessed": _parse_timestamp(_get(lowered, "TargetAccessed", "TargetBirthAccessed")),
                "source_path": source_file,
            }
        )
        document["lnk"].update(
            {
                "source_file": source_file,
                "target_path": raw_target_path,
                "target_id_absolute_path": target_id_absolute_path,
                "local_path": local_path,
                "common_path": common_path,
                "relative_path": relative_path,
                "working_directory": working_directory,
                "arguments": arguments,
                "icon_location": _normalize_value(_get(lowered, "IconLocation")),
                "description": _normalize_value(_get(lowered, "Description")),
                "machine_id": machine_id,
                "drive_type": drive_type,
                "drive_serial_number": _normalize_value(_get(lowered, "DriveSerialNumber", "VolumeSerialNumber")),
                "volume_label": _normalize_value(_get(lowered, "DriveLabel", "VolumeLabel")),
                "volume_created": _parse_timestamp(_get(lowered, "VolumeCreated")),
                "network_path": network_path,
                "net_name": _normalize_value(_get(lowered, "NetName")),
                "device_name": _normalize_value(_get(lowered, "DeviceName")),
                "share_name": _normalize_value(_get(lowered, "ShareName")),
                "tracker_droid": _normalize_value(_get(lowered, "TrackerDroid")),
                "tracker_birth_droid": _normalize_value(_get(lowered, "TrackerBirthDroid")),
                "droid": _normalize_value(_get(lowered, "Droid")),
                "birth_droid": _normalize_value(_get(lowered, "BirthDroid")),
                "mac_address": _normalize_value(_get(lowered, "MacAddress")),
                "target_created": _parse_timestamp(_get(lowered, "TargetCreated")),
                "target_modified": _parse_timestamp(_get(lowered, "TargetModified")),
                "target_accessed": _parse_timestamp(_get(lowered, "TargetAccessed")),
                "source_created": _parse_timestamp(_get(lowered, "SourceCreated")),
                "source_modified": _parse_timestamp(_get(lowered, "SourceModified")),
                "source_accessed": _parse_timestamp(_get(lowered, "SourceAccessed")),
                "effective_path": target_path,
                "effective_path_source": target_path_source,
                "display_name": display_name,
                "is_partial_target": bool(effective_target.get("is_partial_path")),
                "is_shell_target": bool(effective_target.get("is_shell_target")),
            }
        )
        document["volume"].update(
            {
                "serial": _normalize_value(_get(lowered, "DriveSerialNumber", "VolumeSerialNumber")),
                "label": _normalize_value(_get(lowered, "DriveLabel", "VolumeLabel")),
                "drive_type": drive_type,
                "created": _parse_timestamp(_get(lowered, "VolumeCreated")),
            }
        )
        document["network"].update(
            {
                "direction": "access" if network_path or _is_unc(target_path) else None,
                "share_name": _normalize_value(_get(lowered, "ShareName")),
                "path": network_path or (target_path if _is_unc(target_path) else None),
            }
        )
        if user_name and not document["user"]["name"]:
            document["user"]["name"] = user_name
        document["tags"] = sorted(all_tags)
        document["suspicious_reasons"] = suspicious_reasons
        document["raw_summary"] = _raw_summary(target_path, source_file, arguments, drive_type, target_path_source)
        if not timestamp:
            document["data_quality"].append("missing_timestamp")
        if not target_path:
            document["data_quality"].append("missing_target_path")
        score, severity = _risk_score(all_tags, suspicious_reasons, event_type)
        document["risk_score"] = score
        document["event"]["severity"] = severity
        document["search_text"] = _build_search_text(document)
        documents.append(document)

    audit["records_parsed"] = len(documents)
    audit["events_indexed"] = len(documents)
    audit["top_extensions"] = dict(extension_counts.most_common(10))
    audit["top_users"] = dict(user_counts.most_common(10))
    artifact_meta["ingest_audit"] = audit
    return documents


class LECmdParser(ArtifactParser):
    def can_parse(self, path: Path, headers: list[str] | None = None) -> bool:
        lower_name = path.name.lower()
        if "lecmd_output.csv" in lower_name or lower_name.endswith("_lecmd_output.csv") or "lecmd" in lower_name:
            return True
        normalized_headers = {_canonicalize_key(header) for header in (headers or []) if header}
        return len(LECMD_HEADER_HINTS & normalized_headers) >= 3 and any(header in normalized_headers for header in {"targetpath", "localpath", "sourcefile", "machineid"})

    def parse(self, path: Path, **kwargs):
        return parse_lecmd_file(
            kwargs["case_id"],
            kwargs["evidence_id"],
            kwargs["artifact_id"],
            path,
            kwargs["artifact_meta"],
        )
