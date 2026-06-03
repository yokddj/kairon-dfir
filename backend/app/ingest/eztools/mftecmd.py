from collections import Counter
from datetime import UTC, datetime
from functools import lru_cache
import hashlib
from pathlib import Path, PureWindowsPath
import re
import time
from uuid import uuid4

from dateutil import parser as date_parser

from app.analysis.suspicious import detect_suspicious_path
from app.ingest.eztools.base import ArtifactParser, iter_delimited_rows, read_delimited_rows
from app.ingest.identity_extraction import extract_user_from_path, is_valid_username, normalize_hostname


MFTECMD_HEADER_HINTS = {
    "entrynumber",
    "sequencenumber",
    "parententrynumber",
    "filename",
    "fullpath",
    "sourcefile",
}
USN_HEADER_HINTS = {
    "reason",
    "reasons",
    "usn",
    "filereference",
    "parentfilereference",
    "timestamp",
}
WINDOWS_EMPTY_VALUES = {"", "-", "--", "n/a", "na", "(null)", "null"}
SCRIPT_EXTENSIONS = {".ps1", ".bat", ".cmd", ".vbs", ".js", ".jse", ".wsf", ".hta"}
EXECUTABLE_EXTENSIONS = {".exe", ".com", ".dll", ".scr", ".msi"} | SCRIPT_EXTENSIONS
ARCHIVE_EXTENSIONS = {".zip", ".rar", ".7z", ".iso", ".img"}
SUSPICIOUS_NAME_TOKENS = {
    "password",
    "credentials",
    "cred",
    "secret",
    "token",
    "key",
    "backup",
    "dump",
    "mimikatz",
    "procdump",
    "rclone",
    "anydesk",
    "teamviewer",
    "ngrok",
    "plink",
    "psexec",
}
MFT_MESSAGE_TYPE_MAP = {
    "file_deleted": "Deleted MFT entry observed",
    "alternate_data_stream": "MFT ADS observed",
    "file_observed": "MFT entry observed",
}
_PROFILE = {
    "timestamp_parse_seconds": 0.0,
    "doc_build_seconds": 0.0,
}
MFT_FINGERPRINT_VERSION = "mft-summary-v1"


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


@lru_cache(maxsize=65536)
def _parse_timestamp_cached(normalized: str) -> str | None:
    try:
        fast_value = normalized.replace("Z", "+00:00")
        if re.match(r"^\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}(?:\.\d+)?(?:[+-]\d{2}:\d{2})?$", fast_value):
            date_part, time_part = fast_value.split(" ", 1)
            timezone = ""
            if "+" in time_part:
                time_part, timezone = time_part.rsplit("+", 1)
                timezone = f"+{timezone}"
            elif "-" in time_part[8:]:
                time_part, timezone = time_part.rsplit("-", 1)
                timezone = f"-{timezone}"
            if "." in time_part:
                base, fraction = time_part.split(".", 1)
                time_part = f"{base}.{fraction[:6].ljust(6, '0')}"
            parsed = datetime.fromisoformat(f"{date_part}T{time_part}{timezone}")
        else:
            parsed = date_parser.parse(normalized)
        if parsed.tzinfo is None:
            parsed = parsed.replace(tzinfo=UTC)
        return parsed.isoformat()
    except Exception:  # noqa: BLE001
        return None


def _parse_timestamp(value: object | None) -> str | None:
    normalized = _normalize_value(value)
    if not normalized:
        return None
    started = time.perf_counter()
    parsed = _parse_timestamp_cached(normalized)
    _PROFILE["timestamp_parse_seconds"] += time.perf_counter() - started
    return parsed


def reset_mftecmd_profile() -> None:
    for key in _PROFILE:
        _PROFILE[key] = 0.0


def get_mftecmd_profile() -> dict:
    return {key: round(value, 2) for key, value in _PROFILE.items()}


def _parse_dt(value: object | None) -> datetime | None:
    parsed = _parse_timestamp(value)
    if not parsed:
        return None
    try:
        return datetime.fromisoformat(parsed.replace("Z", "+00:00"))
    except Exception:  # noqa: BLE001
        return None


def _normalize_bool(value: object | None) -> bool | None:
    normalized = str(value or "").strip().lower()
    if normalized in {"true", "yes", "1", "in use"}:
        return True
    if normalized in {"false", "no", "0", "not in use"}:
        return False
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


def _normalize_windows_path(path: str | None) -> str | None:
    normalized = _normalize_value(path)
    if not normalized:
        return None
    if normalized.startswith("\\\\"):
        return normalized.replace("/", "\\")
    return normalized.replace("/", "\\")


def _join_windows_path(parent_path: str | None, file_name: str | None) -> str | None:
    parent = _normalize_windows_path(parent_path)
    name = _normalize_value(file_name)
    if parent and name:
        return f"{parent.rstrip('\\')}\\{name}"
    return parent or name


def _is_usn_record(lowered: dict[str, object], path: Path) -> bool:
    lower_name = path.name.lower()
    if "usn" in lower_name or "usnjrnl" in lower_name or "$j" in lower_name:
        return True
    keys = set(lowered)
    return bool({"reason", "usn", "filereference"} & keys and {"timestamp", "updatetimestamp", "filepath", "fullpath"} & keys)


def _normalize_usn_reason(reason: str | None) -> str | None:
    normalized = _normalize_value(reason)
    if not normalized:
        return None
    return normalized.replace("|", ",").replace(";", ",")


def _bool_tag(value: bool | None, truthy: str, falsy: str | None = None) -> list[str]:
    if value is True:
        return [truthy]
    if value is False and falsy:
        return [falsy]
    return []


def select_filesystem_effective_path(row: dict | tuple[dict[str, object], dict[str, object]]) -> dict[str, str | None]:
    if isinstance(row, tuple):
        raw_row, lowered = row
    else:
        raw_row, lowered = _normalize_row_keys(row)
    full_path = _normalize_windows_path(_get(lowered, "FullPath"))
    file_path = _normalize_windows_path(_get(lowered, "FilePath"))
    path_value = _normalize_windows_path(_get(lowered, "Path"))
    parent_path = _normalize_windows_path(_get(lowered, "ParentPath"))
    file_name = _normalize_value(_get(lowered, "FileName", "Name"))
    source_file = _normalize_windows_path(_get(lowered, "SourceFile", "SourceFilename"))
    combined = _join_windows_path(parent_path, file_name)

    selected_path = full_path or file_path or path_value or combined or file_name or source_file
    path_source = (
        "full_path"
        if full_path
        else "file_path"
        if file_path
        else "path"
        if path_value
        else "parent_plus_name"
        if combined
        else "file_name"
        if file_name
        else "source_file_fallback"
        if source_file
        else None
    )
    name = _basename(selected_path) or file_name
    extension = _suffix(selected_path) or _suffix(file_name)
    return {
        "path": selected_path,
        "path_source": path_source,
        "name": name,
        "extension": extension,
        "parent_path": parent_path,
    }


def _extract_ads_list(raw_ads: str | None) -> list[str]:
    normalized = _normalize_value(raw_ads)
    if not normalized:
        return []
    tokens = re.split(r"[|;\n,]+", normalized)
    return [token.strip() for token in tokens if token.strip()]


def _classify_mft_event(is_directory: bool, in_use: bool | None, ads_list: list[str]) -> tuple[str, str, list[str]]:
    if ads_list:
        return "alternate_data_stream", "mft_ads_observed", ["filesystem", "mft", "ads", "suspicious"]
    if in_use is False:
        return "file_deleted", "mft_deleted_entry_observed", ["filesystem", "mft", "deleted_candidate"]
    tags = ["filesystem", "mft"]
    if is_directory:
        tags.append("folder")
    return "file_observed", "mft_entry_observed", tags


def _classify_usn_event(reason: str | None) -> tuple[str, str, list[str]]:
    normalized = str(reason or "").upper()
    if "FILE_CREATE" in normalized:
        return "file_created", "usn_file_create", ["filesystem", "usn", "file_created"]
    if "FILE_DELETE" in normalized:
        return "file_deleted", "usn_file_delete", ["filesystem", "usn", "file_deleted"]
    if "RENAME_OLD_NAME" in normalized or "FILE_RENAME_OLD_NAME" in normalized:
        return "file_rename_old_name", "usn_rename_old_name", ["filesystem", "usn", "file_renamed"]
    if "RENAME_NEW_NAME" in normalized or "FILE_RENAME_NEW_NAME" in normalized:
        return "file_rename_new_name", "usn_rename_new_name", ["filesystem", "usn", "file_renamed"]
    if any(token in normalized for token in {"DATA_OVERWRITE", "DATA_EXTEND", "DATA_TRUNCATION"}):
        return "file_modified", "usn_file_modified", ["filesystem", "usn", "file_modified"]
    if "BASIC_INFO_CHANGE" in normalized:
        return "file_metadata_changed", "usn_file_metadata_changed", ["filesystem", "usn", "file_modified"]
    return "usn_record", "usn_record_observed", ["filesystem", "usn"]


def _timestamp_diff_suspicious(*pairs: tuple[datetime | None, datetime | None], threshold_seconds: int = 5) -> bool:
    for left, right in pairs:
        if not left or not right:
            continue
        if abs((left - right).total_seconds()) > threshold_seconds:
            return True
    return False


def _base_document(case_id: str, evidence_id: str, artifact_id: str, artifact_meta: dict, source_file: str, raw_row: dict, artifact_type: str, timestamp: str | None, timestamp_type: str) -> dict:
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
            "type": artifact_type,
            "name": artifact_meta.get("name", source_file),
            "source_path": artifact_meta.get("source_path", source_file),
            "parser": artifact_meta.get("parser", "zimmerman"),
        },
        "event": {
            "category": "file",
            "type": "filesystem_generic",
            "action": "filesystem_observed",
            "severity": "info",
            "message": artifact_meta.get("name", source_file),
            "timeline_include": bool(timestamp),
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
        "file": {
            "path": None,
            "name": None,
            "extension": None,
            "parent_path": None,
            "size": None,
            "created": None,
            "modified": None,
            "accessed": None,
            "changed": None,
            "mft_modified": None,
            "deleted": None,
            "in_use": None,
            "is_directory": None,
            "attributes": None,
            "ads": None,
            "has_ads": None,
            "source_path": source_file,
        },
        "filesystem": {
            "artifact_type": None,
            "source": "usn" if artifact_type == "usn" else "mft",
            "activity": None,
            "reason": None,
            "is_deleted": None,
            "is_directory": None,
            "is_ads": None,
            "path_depth": None,
            "suspicious_path": None,
            "timestomp_suspected": None,
        },
        "mft": {
            "entry_number": None,
            "sequence_number": None,
            "reference_number": None,
            "parent_entry_number": None,
            "parent_sequence_number": None,
            "parent_reference_number": None,
            "in_use": None,
            "file_name": None,
            "full_path": None,
            "parent_path": None,
            "extension": None,
            "file_size": None,
            "file_attributes": None,
            "has_ads": None,
            "ads": None,
            "si_created": None,
            "si_modified": None,
            "si_accessed": None,
            "si_mft_modified": None,
            "si_changed": None,
            "fn_created": None,
            "fn_modified": None,
            "fn_accessed": None,
            "fn_mft_modified": None,
            "fn_changed": None,
            "object_id": None,
            "reparse_target": None,
            "zone_id": None,
        },
        "usn": {
            "timestamp": None,
            "file_reference": None,
            "parent_file_reference": None,
            "usn": None,
            "reason": None,
            "reasons": None,
            "source_info": None,
            "security_id": None,
        },
        "volume": {"name": None, "serial": None, "drive_letter": None, "guid": None, "label": None, "drive_type": None, "created": None},
        "tags": ["filesystem", "usn" if artifact_type == "usn" else "mft"],
        "data_quality": [],
        "risk_score": 0,
        "execution": {
            "source": "mft" if artifact_type == "mft" else "usn",
            "run_count": None,
            "first_run": None,
            "last_run": None,
            "last_runs": [],
            "program_name": None,
            "confidence": "low",
            "is_execution_confirmed": False,
            "interpretation": "MFT entries indicate filesystem metadata, not program execution by itself" if artifact_type == "mft" else "USN records indicate filesystem journal activity, not program execution by itself",
            "first_seen": None,
            "last_seen": None,
            "last_modified": None,
            "install_date": None,
            "compile_time": None,
        },
        "raw_summary": "",
        "search_text": "",
        "raw": raw_row,
        "suspicious_reasons": [],
        "source_file": source_file,
        "source_tool": "mftecmd",
        "source_format": "csv",
    }


def _apply_mft_fingerprint(document: dict) -> None:
    mft = document.get("mft") if isinstance(document.get("mft"), dict) else {}
    components = [
        str(document.get("case_id") or ""),
        str(document.get("evidence_id") or ""),
        str(document.get("artifact_id") or ""),
        str(mft.get("record_number") or mft.get("entry_number") or ""),
        str(mft.get("sequence_number") or ""),
        str(document.get("key_entity") or document.get("file", {}).get("path") or ""),
        str(document.get("@timestamp") or ""),
        str(document.get("event", {}).get("action") or ""),
    ]
    digest = hashlib.sha256("|".join(components).encode("utf-8", "ignore")).hexdigest()
    document["stable_event_id"] = digest
    document["event_fingerprint"] = digest
    document["event_fingerprint_version"] = MFT_FINGERPRINT_VERSION


def _infer_timestamp_for_mft(lowered: dict[str, object]) -> tuple[str | None, str]:
    candidates = [
        ("mft_si_changed", _get(lowered, "LastRecordChange0x10", "SiMftModified", "SI_Changed")),
        ("mft_si_modified", _get(lowered, "Modified0x10", "SiModified", "SI_Modified")),
        ("mft_si_created", _get(lowered, "Created0x10", "SiCreated", "SI_Created")),
        ("mft_fn_changed", _get(lowered, "LastRecordChange0x30", "FnMftModified", "FN_Changed")),
        ("mft_fn_modified", _get(lowered, "Modified0x30", "FnModified", "FN_Modified")),
        ("mft_fn_created", _get(lowered, "Created0x30", "FnCreated", "FN_Created")),
        ("mft_si_accessed", _get(lowered, "LastAccess0x10", "SiAccessed", "SI_Accessed")),
        ("mft_fn_accessed", _get(lowered, "LastAccess0x30", "FnAccessed", "FN_Accessed")),
    ]
    for precision, value in candidates:
        parsed = _parse_timestamp(value)
        if parsed:
            return parsed, precision
    return None, "unknown"


def _infer_timestamp_for_usn(lowered: dict[str, object]) -> tuple[str | None, str]:
    parsed = _parse_timestamp(_get(lowered, "Timestamp", "UpdateTimestamp"))
    return (parsed, "usn_timestamp") if parsed else (None, "unknown")


def _message_for_usn(event_type: str, file_path: str | None) -> str:
    target = file_path or "unknown"
    mapping = {
        "file_created": "USN file created",
        "file_deleted": "USN file deleted",
        "file_modified": "USN file modified",
        "file_rename_old_name": "USN rename old name",
        "file_rename_new_name": "USN rename new name",
        "file_metadata_changed": "USN metadata changed",
        "usn_record": "USN record",
    }
    return f"{mapping.get(event_type, 'USN record')}: {target}"


def _search_text(document: dict, candidates: list[str | None]) -> str:
    file_data = document.get("file", {}) or {}
    filesystem = document.get("filesystem", {}) or {}
    mft = document.get("mft", {}) or {}
    usn = document.get("usn", {}) or {}
    values = [
        document.get("source_file"),
        (document.get("event") or {}).get("type"),
        (document.get("event") or {}).get("message"),
        file_data.get("path"),
        file_data.get("name"),
        file_data.get("extension"),
        file_data.get("parent_path"),
        filesystem.get("artifact_type"),
        filesystem.get("reason"),
        mft.get("entry_number"),
        mft.get("reference_number"),
        mft.get("ads"),
        usn.get("reason"),
        usn.get("file_reference"),
        usn.get("parent_file_reference"),
        " ".join(document.get("tags") or []),
        " ".join(document.get("suspicious_reasons") or []),
        *candidates,
    ]
    return " | ".join(str(value).strip() for value in values if value not in (None, "", []))[:8192]


def _raw_summary(document: dict) -> str:
    file_data = document.get("file", {}) or {}
    filesystem = document.get("filesystem", {}) or {}
    mft = document.get("mft", {}) or {}
    usn = document.get("usn", {}) or {}
    parts = [
        f"Path={file_data.get('path')}" if file_data.get("path") else None,
        f"Activity={filesystem.get('activity')}" if filesystem.get("activity") else None,
        f"Reason={filesystem.get('reason')}" if filesystem.get("reason") else None,
        f"Entry={mft.get('entry_number')}" if mft.get("entry_number") else None,
        f"USN={usn.get('usn')}" if usn.get("usn") else None,
        f"InUse={mft.get('in_use')}" if mft.get("in_use") is not None else None,
        f"ADS={mft.get('ads')}" if mft.get("ads") else None,
    ]
    return " | ".join(part for part in parts if part)[:2000]


def _detect_suspicious_filesystem(path_value: str | None, ads_list: list[str]) -> tuple[set[str], list[str]]:
    tags: set[str] = set()
    reasons: list[str] = []
    normalized = _normalize_windows_path(path_value)
    if normalized:
        for reason in detect_suspicious_path(normalized):
            tags.update({"suspicious", "suspicious_path"})
            reasons.append(f"Suspicious filesystem path context: {reason}")
        extension = _suffix(normalized)
        if extension in EXECUTABLE_EXTENSIONS:
            tags.update({"execution_related", "executable"})
            if extension in SCRIPT_EXTENSIONS:
                tags.add("script")
            if "\\downloads\\" in normalized.lower() or "\\desktop\\" in normalized.lower() or "\\appdata\\" in normalized.lower() or "\\temp\\" in normalized.lower() or "\\users\\public\\" in normalized.lower():
                reasons.append("MFT executable in user-writable path")
        if extension in ARCHIVE_EXTENSIONS:
            tags.add("archive")
        if extension in SCRIPT_EXTENSIONS and ("\\downloads\\" in normalized.lower() or "\\desktop\\" in normalized.lower() or "\\appdata\\" in normalized.lower() or "\\temp\\" in normalized.lower() or "\\users\\public\\" in normalized.lower()):
            reasons.append("MFT script in user-writable path")
        if "\\startup\\" in normalized.lower():
            reasons.append("MFT file in Startup folder")
        if "\\downloads\\" in normalized.lower() and any(ext in normalized.lower() for ext in EXECUTABLE_EXTENSIONS | ARCHIVE_EXTENSIONS):
            reasons.append("MFT deleted file in suspicious path")
        lower_name = str(_basename(normalized) or "").lower()
        for token in SUSPICIOUS_NAME_TOKENS:
            if token in lower_name:
                tags.add("suspicious")
                reasons.append("MFT suspicious filename keyword")
        if normalized.startswith("\\\\"):
            tags.update({"network_path", "unc_path"})
            reasons.append("Filesystem path uses UNC path")
        if extension in EXECUTABLE_EXTENSIONS and (".pdf." in lower_name or ".doc." in lower_name or ".xls." in lower_name):
            reasons.append("MFT double extension")
    for ads in ads_list:
        tags.update({"suspicious", "ads"})
        reasons.append("MFT alternate data stream observed")
        if str(ads).lower() == "zone.identifier":
            reasons.append("MFT Zone.Identifier observed")
    return tags, sorted(set(reasons))


def _severity_score(tags: set[str], reasons: list[str], *, deleted_candidate: bool = False, timestomp: bool = False) -> tuple[int, str]:
    score = 5
    if deleted_candidate:
        score += 12
    if timestomp:
        score += 30
    if reasons:
        score += 15
    if "executable" in tags or "script" in tags:
        score += 18
    if "archive" in tags:
        score += 10
    if "ads" in tags:
        score += 25
    if any(reason in reasons for reason in ("MFT file in Startup folder", "MFT executable in user-writable path", "MFT script in user-writable path", "MFT deleted file in suspicious path")):
        score += 15
    if "MFT double extension" in reasons:
        score += 12
    if "MFT Zone.Identifier observed" in reasons:
        score += 8
    if "network_path" in tags:
        score += 8
    score = min(score, 100)
    if score >= 65:
        return score, "high"
    if score >= 40:
        return score, "medium"
    if score >= 20:
        return score, "low"
    return score, "info"


def _build_mft_document(case_id: str, evidence_id: str, artifact_id: str, path: Path, artifact_meta: dict, raw_row: dict, lowered: dict[str, object]) -> dict:
    timestamp, timestamp_type = _infer_timestamp_for_mft(lowered)
    source_file = _normalize_windows_path(_get(lowered, "SourceFile", "SourceFilename")) or path.name
    effective = select_filesystem_effective_path((raw_row, lowered))
    file_path = effective["path"]
    file_name = effective["name"]
    extension = _normalize_value(_get(lowered, "Extension")) or effective["extension"]
    parent_path = effective["parent_path"]
    file_attributes = _normalize_value(_get(lowered, "FileAttributes"))
    is_directory = _normalize_bool(_get(lowered, "IsDirectory")) or ("directory" in str(file_attributes or "").lower())
    in_use = _normalize_bool(_get(lowered, "InUse"))
    ads_list = _extract_ads_list(_get(lowered, "Ads"))
    has_ads = _normalize_bool(_get(lowered, "HasAds")) or bool(ads_list)
    event_type, action, base_tags = _classify_mft_event(bool(is_directory), in_use, ads_list if has_ads else [])
    doc = _base_document(case_id, evidence_id, artifact_id, artifact_meta, source_file, raw_row, "mft", timestamp, timestamp_type)
    doc["event"].update(
        {
            "type": event_type,
            "action": action,
            "message": f"{MFT_MESSAGE_TYPE_MAP.get(event_type, 'MFT file observed')}: {file_path or file_name or 'unknown'}" + (f":{ads_list[0]}" if event_type == "alternate_data_stream" and ads_list else ""),
            "category": "file",
        }
    )
    user_name = extract_user_from_path(file_path) or extract_user_from_path(source_file)
    if user_name and is_valid_username(user_name):
        doc["user"]["name"] = user_name
    host_candidate = _normalize_value(_get(lowered, "MachineID", "Hostname", "HostName"))
    if host_candidate and not doc["host"]["name"]:
        normalized_host = normalize_hostname(host_candidate)
        if normalized_host:
            doc["host"]["name"] = normalized_host
            doc["host"]["hostname"] = normalized_host

    si_created = _parse_timestamp(_get(lowered, "Created0x10", "SiCreated", "SI_Created"))
    si_modified = _parse_timestamp(_get(lowered, "Modified0x10", "SiModified", "SI_Modified"))
    si_accessed = _parse_timestamp(_get(lowered, "LastAccess0x10", "SiAccessed", "SI_Accessed"))
    si_mft_modified = _parse_timestamp(_get(lowered, "LastRecordChange0x10", "SiMftModified", "SI_Changed"))
    fn_created = _parse_timestamp(_get(lowered, "Created0x30", "FnCreated", "FN_Created"))
    fn_modified = _parse_timestamp(_get(lowered, "Modified0x30", "FnModified", "FN_Modified"))
    fn_accessed = _parse_timestamp(_get(lowered, "LastAccess0x30", "FnAccessed", "FN_Accessed"))
    fn_mft_modified = _parse_timestamp(_get(lowered, "LastRecordChange0x30", "FnMftModified", "FN_Changed"))

    timestomp = _timestamp_diff_suspicious(
        (_parse_dt(si_created), _parse_dt(fn_created)),
        (_parse_dt(si_modified), _parse_dt(fn_modified)),
        (_parse_dt(si_accessed), _parse_dt(fn_accessed)),
        (_parse_dt(si_mft_modified), _parse_dt(fn_mft_modified)),
    )
    suspicious_tags, suspicious_reasons = _detect_suspicious_filesystem(file_path, ads_list if has_ads else [])
    if timestomp:
        suspicious_tags.update({"suspicious", "timestomp_suspected"})
        suspicious_reasons.extend(["MFT timestamp anomaly", "MFT possible timestomping"])

    doc["file"].update(
        {
            "path": file_path,
            "name": file_name,
            "extension": extension,
            "directory": parent_path,
            "parent_path": parent_path,
            "size": _normalize_value(_get(lowered, "FileSize")),
            "created": si_created or fn_created,
            "modified": si_modified or fn_modified,
            "accessed": si_accessed or fn_accessed,
            "changed": si_mft_modified or fn_mft_modified,
            "mft_modified": si_mft_modified or fn_mft_modified,
            "deleted": True if in_use is False else False if in_use is True else None,
            "in_use": in_use,
            "is_directory": bool(is_directory),
            "attributes": file_attributes,
            "ads": list(ads_list),
            "has_ads": bool(has_ads),
            "source_path": source_file,
            "owner_user": user_name,
            "profile_user": user_name,
        }
    )
    doc["filesystem"].update(
        {
            "artifact_type": "ads" if has_ads else "file_deleted" if in_use is False else "mft_entry",
            "source": "mft",
            "activity": event_type,
            "is_deleted": in_use is False,
            "is_directory": bool(is_directory),
            "is_ads": bool(has_ads),
            "path_depth": len([part for part in str(file_path or "").split("\\") if part]),
            "suspicious_path": "suspicious_path" in suspicious_tags,
            "timestomp_suspected": timestomp,
        }
    )
    doc["mft"].update(
        {
            "entry_number": _normalize_value(_get(lowered, "EntryNumber")),
            "record_number": _normalize_value(_get(lowered, "EntryNumber")),
            "sequence_number": _normalize_value(_get(lowered, "SequenceNumber")),
            "reference_number": _normalize_value(_get(lowered, "ReferenceNumber")),
            "parent_entry_number": _normalize_value(_get(lowered, "ParentEntryNumber")),
            "parent_record_number": _normalize_value(_get(lowered, "ParentEntryNumber")),
            "parent_sequence_number": _normalize_value(_get(lowered, "ParentSequenceNumber")),
            "parent_reference_number": _normalize_value(_get(lowered, "ParentReferenceNumber")),
            "flags": file_attributes,
            "in_use": in_use,
            "file_name": file_name,
            "full_path": _normalize_windows_path(_get(lowered, "FullPath")),
            "parent_path": parent_path,
            "extension": extension,
            "file_size": _normalize_value(_get(lowered, "FileSize")),
            "file_attributes": file_attributes,
            "has_ads": bool(has_ads),
            "ads": list(ads_list),
            "created_time": si_created,
            "modified_time": si_modified,
            "mft_modified_time": si_mft_modified,
            "accessed_time": si_accessed,
            "si_created": si_created,
            "si_modified": si_modified,
            "si_accessed": si_accessed,
            "si_mft_modified": si_mft_modified,
            "si_changed": si_mft_modified,
            "fn_created_time": fn_created,
            "fn_modified_time": fn_modified,
            "fn_mft_modified_time": fn_mft_modified,
            "fn_accessed_time": fn_accessed,
            "fn_created": fn_created,
            "fn_modified": fn_modified,
            "fn_accessed": fn_accessed,
            "fn_mft_modified": fn_mft_modified,
            "fn_changed": fn_mft_modified,
            "object_id": _normalize_value(_get(lowered, "ObjectId")),
            "reparse_target": _normalize_value(_get(lowered, "ReparseTarget")),
            "zone_id": _normalize_value(_get(lowered, "ZoneId", "MarkOfTheWeb")),
        }
    )
    doc["volume"].update(
        {
            "name": _normalize_value(_get(lowered, "VolumeName")),
            "serial": _normalize_value(_get(lowered, "VolumeSerialNumber")),
            "drive_letter": _normalize_value(_get(lowered, "DriveLetter")),
        }
    )
    if _normalize_value(_get(lowered, "OwnerSid")):
        doc["user"]["sid"] = _normalize_value(_get(lowered, "OwnerSid"))
    score, severity = _severity_score(set(base_tags) | suspicious_tags, suspicious_reasons, deleted_candidate=in_use is False, timestomp=timestomp)
    summary_score = _normalize_value(_get(lowered, "SummaryScore"))
    summary_reasons = [
        item.strip()
        for item in str(_normalize_value(_get(lowered, "SummaryReasons")) or "").split(";")
        if item.strip()
    ]
    doc["event"]["severity"] = severity
    doc["tags"] = sorted(set(doc["tags"]) | set(base_tags) | suspicious_tags)
    doc["suspicious_reasons"] = sorted(set(suspicious_reasons))
    doc["risk_score"] = score
    if summary_score is not None:
        try:
            doc["mft"]["summary_score"] = int(float(summary_score))
        except ValueError:
            doc["mft"]["summary_score"] = summary_score
    if summary_reasons:
        doc["mft"]["summary_reasons"] = summary_reasons
        doc["tags"] = sorted(set(doc["tags"]) | set(summary_reasons))
    doc["raw_summary"] = _raw_summary(doc)
    doc["key_entity"] = file_path or file_name
    doc["summary"] = doc["raw_summary"]
    doc["search_text"] = _search_text(
        doc,
        [
            _normalize_windows_path(_get(lowered, "FullPath")),
            _normalize_windows_path(_get(lowered, "Path")),
            _normalize_windows_path(_get(lowered, "ParentPath")),
            _normalize_value(_get(lowered, "FileName")),
            _normalize_value(_get(lowered, "Ads")),
            _normalize_value(_get(lowered, "ReferenceNumber")),
            " ".join(summary_reasons),
        ],
    )
    if not timestamp:
        doc["data_quality"].append("missing_timestamp")
    if not file_path:
        doc["data_quality"].append("missing_path")
    if in_use is False:
        doc["data_quality"].append("mft_deleted_entry")
    if has_ads:
        doc["data_quality"].append("mft_ads_present")
    if timestomp:
        doc["data_quality"].append("mft_timestamp_inconsistency")
    _apply_mft_fingerprint(doc)
    return doc


def _build_mft_document_fast(case_id: str, evidence_id: str, artifact_id: str, path: Path, artifact_meta: dict, raw_row: dict, lowered: dict[str, object]) -> dict:
    timestamp, timestamp_type = _infer_timestamp_for_mft(lowered)
    source_file = _normalize_windows_path(_get(lowered, "SourceFile", "SourceFilename")) or path.name
    effective = select_filesystem_effective_path((raw_row, lowered))
    file_path = effective["path"]
    file_name = effective["name"]
    extension = _normalize_value(_get(lowered, "Extension")) or effective["extension"]
    parent_path = effective["parent_path"]
    file_attributes = _normalize_value(_get(lowered, "FileAttributes"))
    is_directory = bool(_normalize_bool(_get(lowered, "IsDirectory")) or ("directory" in str(file_attributes or "").lower()))
    in_use = _normalize_bool(_get(lowered, "InUse"))
    ads_list = _extract_ads_list(_get(lowered, "Ads"))
    has_ads = bool(_normalize_bool(_get(lowered, "HasAds")) or ads_list)
    event_type, action, base_tags = _classify_mft_event(is_directory, in_use, ads_list if has_ads else [])

    doc = _base_document(case_id, evidence_id, artifact_id, artifact_meta, source_file, raw_row, "mft", timestamp, timestamp_type)
    doc["event"].update(
        {
            "type": event_type,
            "action": action,
            "message": f"{MFT_MESSAGE_TYPE_MAP.get(event_type, 'MFT file observed')}: {file_path or file_name or 'unknown'}" + (f":{ads_list[0]}" if event_type == "alternate_data_stream" and ads_list else ""),
            "category": "file",
        }
    )

    suspicious_tags, suspicious_reasons = _detect_suspicious_filesystem(file_path, ads_list if has_ads else [])
    user_name = extract_user_from_path(file_path) or extract_user_from_path(source_file)
    if user_name and is_valid_username(user_name):
        doc["user"]["name"] = user_name

    doc["file"].update(
        {
            "path": file_path,
            "name": file_name,
            "extension": extension,
            "directory": parent_path,
            "parent_path": parent_path,
            "size": _normalize_value(_get(lowered, "FileSize")),
            "modified": timestamp if timestamp_type == "mft_si_modified" else None,
            "created": timestamp if timestamp_type == "mft_si_created" else None,
            "accessed": timestamp if timestamp_type == "mft_si_accessed" else None,
            "changed": timestamp if timestamp_type == "mft_si_changed" else None,
            "mft_modified": timestamp if timestamp_type == "mft_si_changed" else None,
            "deleted": True if in_use is False else False if in_use is True else None,
            "in_use": in_use,
            "is_directory": is_directory,
            "attributes": file_attributes,
            "ads": ads_list,
            "has_ads": has_ads,
            "source_path": source_file,
            "owner_user": user_name,
            "profile_user": user_name,
        }
    )
    doc["filesystem"].update(
        {
            "artifact_type": "ads" if has_ads else "file_deleted" if in_use is False else "mft_entry",
            "source": "mft",
            "activity": event_type,
            "is_deleted": in_use is False,
            "is_directory": is_directory,
            "is_ads": has_ads,
            "path_depth": len([part for part in str(file_path or "").split("\\") if part]),
            "suspicious_path": "suspicious_path" in suspicious_tags,
            "timestomp_suspected": False,
        }
    )
    doc["mft"].update(
        {
            "entry_number": _normalize_value(_get(lowered, "EntryNumber")),
            "record_number": _normalize_value(_get(lowered, "EntryNumber")),
            "sequence_number": _normalize_value(_get(lowered, "SequenceNumber")),
            "reference_number": _normalize_value(_get(lowered, "ReferenceNumber")),
            "parent_entry_number": _normalize_value(_get(lowered, "ParentEntryNumber")),
            "parent_record_number": _normalize_value(_get(lowered, "ParentEntryNumber")),
            "parent_sequence_number": _normalize_value(_get(lowered, "ParentSequenceNumber")),
            "parent_reference_number": _normalize_value(_get(lowered, "ParentReferenceNumber")),
            "flags": file_attributes,
            "in_use": in_use,
            "file_name": file_name,
            "full_path": _normalize_windows_path(_get(lowered, "FullPath")),
            "parent_path": parent_path,
            "extension": extension,
            "file_size": _normalize_value(_get(lowered, "FileSize")),
            "file_attributes": file_attributes,
            "has_ads": has_ads,
            "ads": ads_list,
            "created_time": doc["file"]["created"],
            "modified_time": doc["file"]["modified"],
            "mft_modified_time": doc["file"]["mft_modified"],
            "accessed_time": doc["file"]["accessed"],
            "si_created": doc["file"]["created"],
            "si_modified": doc["file"]["modified"],
            "si_accessed": doc["file"]["accessed"],
            "si_mft_modified": doc["file"]["mft_modified"],
            "si_changed": doc["file"]["changed"],
            "fn_created": None,
            "fn_modified": None,
            "fn_accessed": None,
            "fn_mft_modified": None,
            "fn_changed": None,
            "object_id": None,
            "reparse_target": None,
            "zone_id": None,
        }
    )
    doc["volume"].update(
        {
            "name": _normalize_value(_get(lowered, "VolumeName")),
            "serial": _normalize_value(_get(lowered, "VolumeSerialNumber")),
            "drive_letter": _normalize_value(_get(lowered, "DriveLetter")),
        }
    )
    if _normalize_value(_get(lowered, "OwnerSid")):
        doc["user"]["sid"] = _normalize_value(_get(lowered, "OwnerSid"))

    score, severity = _severity_score(set(base_tags) | suspicious_tags, suspicious_reasons, deleted_candidate=in_use is False, timestomp=False)
    summary_score = _normalize_value(_get(lowered, "SummaryScore"))
    summary_reasons = [
        item.strip()
        for item in str(_normalize_value(_get(lowered, "SummaryReasons")) or "").split(";")
        if item.strip()
    ]
    doc["event"]["severity"] = severity
    doc["tags"] = sorted(set(doc["tags"]) | set(base_tags) | suspicious_tags)
    doc["suspicious_reasons"] = sorted(set(suspicious_reasons))
    doc["risk_score"] = score
    if summary_score is not None:
        try:
            doc["mft"]["summary_score"] = int(float(summary_score))
        except ValueError:
            doc["mft"]["summary_score"] = summary_score
    if summary_reasons:
        doc["mft"]["summary_reasons"] = summary_reasons
        doc["tags"] = sorted(set(doc["tags"]) | set(summary_reasons))
    doc["raw_summary"] = _raw_summary(doc)
    doc["key_entity"] = file_path or file_name
    doc["summary"] = doc["raw_summary"]
    doc["search_text"] = _search_text(
        doc,
        [
            _normalize_windows_path(_get(lowered, "FullPath")),
            _normalize_windows_path(_get(lowered, "Path")),
            _normalize_windows_path(_get(lowered, "ParentPath")),
            _normalize_value(_get(lowered, "FileName")),
            _normalize_value(_get(lowered, "ReferenceNumber")),
            " ".join(summary_reasons),
        ],
    )
    if not timestamp:
        doc["data_quality"].append("missing_timestamp")
    if not file_path:
        doc["data_quality"].append("missing_path")
    if in_use is False:
        doc["data_quality"].append("mft_deleted_entry")
    if has_ads:
        doc["data_quality"].append("mft_ads_present")
    _apply_mft_fingerprint(doc)
    return doc


def _build_usn_document(case_id: str, evidence_id: str, artifact_id: str, path: Path, artifact_meta: dict, raw_row: dict, lowered: dict[str, object]) -> dict:
    timestamp, timestamp_type = _infer_timestamp_for_usn(lowered)
    source_file = _normalize_windows_path(_get(lowered, "SourceFile", "SourceFilename")) or path.name
    effective = select_filesystem_effective_path((raw_row, lowered))
    file_path = effective["path"]
    file_name = effective["name"]
    extension = _normalize_value(_get(lowered, "Extension")) or effective["extension"]
    reason = _normalize_usn_reason(_get(lowered, "Reason", "Reasons"))
    event_type, action, base_tags = _classify_usn_event(reason)
    doc = _base_document(case_id, evidence_id, artifact_id, artifact_meta, source_file, raw_row, "usn", timestamp, timestamp_type)
    doc["event"].update(
        {
            "type": event_type,
            "action": action,
            "message": _message_for_usn(event_type, file_path or file_name),
        }
    )
    user_name = extract_user_from_path(file_path) or extract_user_from_path(source_file)
    if user_name and is_valid_username(user_name):
        doc["user"]["name"] = user_name
    suspicious_tags, suspicious_reasons = _detect_suspicious_filesystem(file_path, [])
    doc["file"].update(
        {
            "path": file_path,
            "name": file_name,
            "extension": extension,
            "parent_path": effective["parent_path"],
            "created": timestamp if event_type == "file_created" else None,
            "modified": timestamp if event_type in {"file_modified", "file_metadata_changed"} else None,
            "deleted": "true" if event_type == "file_deleted" else None,
            "is_directory": "directory" in str(_normalize_value(_get(lowered, "FileAttributes")) or "").lower(),
            "attributes": _normalize_value(_get(lowered, "FileAttributes")),
            "source_path": source_file,
        }
    )
    doc["filesystem"].update(
        {
            "artifact_type": event_type if event_type != "usn_record" else "usn_record",
            "source": "usn",
            "activity": event_type,
            "reason": reason,
            "is_deleted": event_type == "file_deleted",
            "is_directory": doc["file"]["is_directory"],
            "is_ads": False,
            "path_depth": len([part for part in str(file_path or "").split("\\") if part]),
            "suspicious_path": "suspicious_path" in suspicious_tags,
            "timestomp_suspected": False,
        }
    )
    doc["usn"].update(
        {
            "timestamp": timestamp,
            "file_reference": _normalize_value(_get(lowered, "FileReference")),
            "parent_file_reference": _normalize_value(_get(lowered, "ParentFileReference")),
            "usn": _normalize_value(_get(lowered, "Usn")),
            "reason": reason,
            "reasons": reason,
            "source_info": _normalize_value(_get(lowered, "SourceInfo")),
            "security_id": _normalize_value(_get(lowered, "SecurityId")),
        }
    )
    doc["volume"].update(
        {
            "name": _normalize_value(_get(lowered, "VolumeName")),
            "serial": _normalize_value(_get(lowered, "VolumeSerialNumber")),
            "drive_letter": _normalize_value(_get(lowered, "DriveLetter")),
        }
    )
    score, severity = _severity_score(set(base_tags) | suspicious_tags, suspicious_reasons, deleted_candidate=event_type == "file_deleted")
    doc["event"]["severity"] = severity
    doc["tags"] = sorted(set(doc["tags"]) | set(base_tags) | suspicious_tags)
    doc["suspicious_reasons"] = sorted(set(suspicious_reasons))
    doc["risk_score"] = score
    doc["raw_summary"] = _raw_summary(doc)
    doc["search_text"] = _search_text(
        doc,
        [
            _normalize_windows_path(_get(lowered, "FullPath")),
            _normalize_windows_path(_get(lowered, "FilePath")),
            _normalize_windows_path(_get(lowered, "Path")),
            _normalize_value(_get(lowered, "Reason", "Reasons")),
            _normalize_value(_get(lowered, "FileReference")),
        ],
    )
    if not timestamp:
        doc["data_quality"].append("missing_timestamp")
    if not file_path:
        doc["data_quality"].append("missing_path")
    return doc


def parse_mftecmd_file(case_id: str, evidence_id: str, artifact_id: str, path: Path, artifact_meta: dict) -> list[dict]:
    rows = read_delimited_rows(path)
    documents: list[dict] = []
    audit = {
        "artifact": path.name,
        "parser": "mftecmd",
        "artifact_type": "usn" if rows and _is_usn_record(_normalize_row_keys(rows[0])[1], path) else "mft",
        "records_read": len(rows),
        "records_parsed": 0,
        "events_indexed": 0,
        "missing_timestamp": 0,
        "missing_path": 0,
        "suspicious_count": 0,
        "ads_count": 0,
        "deleted_candidate_count": 0,
        "file_created_count": 0,
        "file_modified_count": 0,
        "file_deleted_count": 0,
        "file_renamed_count": 0,
        "timestomp_suspected_count": 0,
        "executable_count": 0,
        "script_count": 0,
        "top_extensions": {},
        "top_suspicious_paths": {},
        "bulk_index_errors": 0,
        "top_errors": [],
    }
    extension_counts: Counter[str] = Counter()
    suspicious_path_counts: Counter[str] = Counter()

    for row in rows:
        raw_row, lowered = _normalize_row_keys(row)
        document = _build_usn_document(case_id, evidence_id, artifact_id, path, artifact_meta, raw_row, lowered) if _is_usn_record(lowered, path) else _build_mft_document(case_id, evidence_id, artifact_id, path, artifact_meta, raw_row, lowered)
        documents.append(document)
        audit["records_parsed"] += 1
        audit["events_indexed"] += 1
        if "missing_timestamp" in document.get("data_quality", []):
            audit["missing_timestamp"] += 1
        if "missing_path" in document.get("data_quality", []):
            audit["missing_path"] += 1
        if document.get("suspicious_reasons"):
            audit["suspicious_count"] += 1
        if (document.get("file", {}) or {}).get("has_ads"):
            audit["ads_count"] += 1
        if (document.get("filesystem", {}) or {}).get("is_deleted"):
            audit["deleted_candidate_count"] += 1
        if (document.get("filesystem", {}) or {}).get("timestomp_suspected"):
            audit["timestomp_suspected_count"] += 1
        event_type = str((document.get("event", {}) or {}).get("type") or "")
        if event_type == "file_created":
            audit["file_created_count"] += 1
        if event_type in {"file_modified", "file_metadata_changed"}:
            audit["file_modified_count"] += 1
        if event_type in {"file_deleted", "file_deleted_or_not_in_use"}:
            audit["file_deleted_count"] += 1
        if event_type in {"file_rename_old_name", "file_rename_new_name"}:
            audit["file_renamed_count"] += 1
        extension = str((document.get("file", {}) or {}).get("extension") or "").lower()
        if extension:
            extension_counts[extension] += 1
        tags = set(document.get("tags", []))
        if "executable" in tags:
            audit["executable_count"] += 1
        if "script" in tags:
            audit["script_count"] += 1
        file_path = str((document.get("file", {}) or {}).get("path") or "")
        if "suspicious_path" in tags and file_path:
            suspicious_path_counts[file_path] += 1

    audit["top_extensions"] = dict(extension_counts.most_common(15))
    audit["top_suspicious_paths"] = dict(suspicious_path_counts.most_common(15))
    artifact_meta["ingest_audit"] = audit
    return documents


def iter_mftecmd_batches(case_id: str, evidence_id: str, artifact_id: str, path: Path, artifact_meta: dict, *, batch_size: int = 1000, fast_path: bool = False):
    rows_iter = iter(iter_delimited_rows(path))
    first_row = next(rows_iter, None)
    if first_row is None:
        artifact_meta["ingest_audit"] = {
            "artifact": path.name,
            "parser": "mftecmd",
            "artifact_type": "mft",
            "records_read": 0,
            "records_parsed": 0,
            "events_indexed": 0,
            "missing_timestamp": 0,
            "missing_path": 0,
            "suspicious_count": 0,
            "ads_count": 0,
            "deleted_candidate_count": 0,
            "file_created_count": 0,
            "file_modified_count": 0,
            "file_deleted_count": 0,
            "file_renamed_count": 0,
            "timestomp_suspected_count": 0,
            "executable_count": 0,
            "script_count": 0,
            "top_extensions": {},
            "top_suspicious_paths": {},
            "bulk_index_errors": 0,
            "top_errors": [],
        }
        return

    _, first_lowered = _normalize_row_keys(first_row)
    artifact_kind = "usn" if _is_usn_record(first_lowered, path) else "mft"
    audit = {
        "artifact": path.name,
        "parser": "mftecmd",
        "artifact_type": artifact_kind,
        "records_read": 0,
        "records_parsed": 0,
        "events_indexed": 0,
        "missing_timestamp": 0,
        "missing_path": 0,
        "suspicious_count": 0,
        "ads_count": 0,
        "deleted_candidate_count": 0,
        "file_created_count": 0,
        "file_modified_count": 0,
        "file_deleted_count": 0,
        "file_renamed_count": 0,
        "timestomp_suspected_count": 0,
        "executable_count": 0,
        "script_count": 0,
        "top_extensions": {},
        "top_suspicious_paths": {},
        "bulk_index_errors": 0,
        "top_errors": [],
    }
    extension_counts: Counter[str] = Counter()
    suspicious_path_counts: Counter[str] = Counter()
    batch: list[dict] = []

    def process_row(row: dict) -> dict:
        started = time.perf_counter()
        raw_row, lowered = _normalize_row_keys(row)
        try:
            if artifact_kind == "usn":
                return _build_usn_document(case_id, evidence_id, artifact_id, path, artifact_meta, raw_row, lowered)
            if fast_path:
                return _build_mft_document_fast(case_id, evidence_id, artifact_id, path, artifact_meta, raw_row, lowered)
            return _build_mft_document(case_id, evidence_id, artifact_id, path, artifact_meta, raw_row, lowered)
        finally:
            _PROFILE["doc_build_seconds"] += time.perf_counter() - started

    def update_audit(document: dict) -> None:
        audit["records_read"] += 1
        audit["records_parsed"] += 1
        if "missing_timestamp" in document.get("data_quality", []):
            audit["missing_timestamp"] += 1
        if "missing_path" in document.get("data_quality", []):
            audit["missing_path"] += 1
        if document.get("suspicious_reasons"):
            audit["suspicious_count"] += 1
        if (document.get("file", {}) or {}).get("has_ads"):
            audit["ads_count"] += 1
        if (document.get("filesystem", {}) or {}).get("is_deleted"):
            audit["deleted_candidate_count"] += 1
        if (document.get("filesystem", {}) or {}).get("timestomp_suspected"):
            audit["timestomp_suspected_count"] += 1
        event_type = str((document.get("event", {}) or {}).get("type") or "")
        if event_type == "file_created":
            audit["file_created_count"] += 1
        if event_type in {"file_modified", "file_metadata_changed"}:
            audit["file_modified_count"] += 1
        if event_type in {"file_deleted", "file_deleted_or_not_in_use"}:
            audit["file_deleted_count"] += 1
        if event_type in {"file_rename_old_name", "file_rename_new_name"}:
            audit["file_renamed_count"] += 1
        extension = str((document.get("file", {}) or {}).get("extension") or "").lower()
        if extension:
            extension_counts[extension] += 1
        tags = set(document.get("tags", []))
        if "executable" in tags:
            audit["executable_count"] += 1
        if "script" in tags:
            audit["script_count"] += 1
        file_path = str((document.get("file", {}) or {}).get("path") or "")
        if "suspicious_path" in tags and file_path:
            suspicious_path_counts[file_path] += 1

    row = first_row
    document = process_row(row)
    batch.append(document)
    update_audit(document)
    if len(batch) >= max(1, batch_size):
        artifact_meta["ingest_audit"] = {
            **audit,
            "top_extensions": dict(extension_counts.most_common(15)),
            "top_suspicious_paths": dict(suspicious_path_counts.most_common(15)),
        }
        yield batch
        batch = []

    for row in rows_iter:
        document = process_row(row)
        batch.append(document)
        update_audit(document)
        if len(batch) >= max(1, batch_size):
            artifact_meta["ingest_audit"] = {
                **audit,
                "top_extensions": dict(extension_counts.most_common(15)),
                "top_suspicious_paths": dict(suspicious_path_counts.most_common(15)),
            }
            yield batch
            batch = []

    if batch:
        yield batch

    artifact_meta["ingest_audit"] = {
        **audit,
        "top_extensions": dict(extension_counts.most_common(15)),
        "top_suspicious_paths": dict(suspicious_path_counts.most_common(15)),
    }


class MFTECmdParser(ArtifactParser):
    def can_parse(self, path: Path, headers: list[str] | None = None) -> bool:
        lower_name = path.name.lower()
        if "mftecmd_output.csv" in lower_name or lower_name.endswith("_mftecmd_output.csv") or "mftecmd" in lower_name or "usn" in lower_name:
            return True
        normalized_headers = {_canonicalize_key(header) for header in (headers or []) if header}
        if len(MFTECMD_HEADER_HINTS & normalized_headers) >= 3:
            return True
        return len(USN_HEADER_HINTS & normalized_headers) >= 3 and bool({"filepath", "fullpath", "path"} & normalized_headers)

    def parse(self, path: Path, **kwargs):
        return parse_mftecmd_file(
            kwargs["case_id"],
            kwargs["evidence_id"],
            kwargs["artifact_id"],
            path,
            kwargs["artifact_meta"],
        )
