from collections import Counter
from datetime import UTC
from pathlib import Path
import re
from uuid import uuid4

from dateutil import parser as date_parser

from app.ingest.eztools.base import ArtifactParser, read_delimited_rows
from app.ingest.eztools.lecmd import (
    ARGUMENT_TOKENS,
    DOCUMENT_EXTENSIONS,
    EXECUTABLE_EXTENSIONS,
    SCRIPT_EXTENSIONS,
    _basename,
    _canonicalize_key,
    _classify_target,
    _detect_suspicious_lnk,
    _drive_type_tags,
    _extract_unc_host,
    _get,
    _is_unc,
    _normalize_row_keys,
    _normalize_value,
    _parse_timestamp,
    _risk_score,
    _suffix,
    select_lnk_effective_target,
)
from app.ingest.identity_extraction import extract_user_from_path, normalize_hostname


JLECMD_HEADER_HINTS = {
    "sourcefile",
    "appid",
    "appiddescription",
    "path",
    "targetpath",
    "localpath",
    "interactioncount",
}


def _choose_timestamp(lowered: dict[str, object]) -> tuple[str | None, str]:
    candidates = [
        ("last_accessed", _get(lowered, "LastAccessed")),
        ("last_modified", _get(lowered, "LastModified")),
        ("modified", _get(lowered, "Modified")),
        ("accessed", _get(lowered, "Accessed")),
        ("created", _get(lowered, "Created")),
        ("source_modified", _get(lowered, "SourceModified")),
        ("source_created", _get(lowered, "SourceCreated")),
    ]
    for ts_type, value in candidates:
        parsed = _parse_timestamp(value)
        if parsed:
            return parsed, ts_type
    return None, "unknown"


def _safe_int(value: object | None) -> int | None:
    normalized = _normalize_value(value)
    if not normalized:
        return None
    digits = re.sub(r"[^\d-]", "", normalized)
    if not digits:
        return None
    try:
        return int(digits)
    except ValueError:
        return None


def _infer_app_name(lowered: dict[str, object]) -> str | None:
    for field in ["AppIdDescription", "AppDescription", "Application", "AppName", "AppId", "AppID"]:
        value = _normalize_value(_get(lowered, field))
        if value:
            return value
    return None


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
            "type": "jumplist",
            "name": artifact_meta.get("name", source_file),
            "source_path": artifact_meta.get("source_path", source_file),
            "parser": artifact_meta.get("parser", "zimmerman"),
        },
        "event": {
            "category": "file_access",
            "type": "file_opened",
            "action": "jumplist_entry_accessed",
            "severity": "info",
            "message": artifact_meta.get("name", source_file),
            "timeline_include": True,
        },
        "process": {"pid": None, "name": None, "path": None, "command_line": None, "parent_pid": None, "parent_name": None, "parent_path": None, "parent_command_line": None, "integrity_level": None, "token_elevation": None},
        "file": {"path": None, "name": None, "extension": None, "size": None, "hash_sha1": None, "hash_sha256": None, "sha1": None, "sha256": None, "md5": None, "created": None, "modified": None, "accessed": None, "source_path": None},
        "jumplist": {
            "source_file": None,
            "app_id": None,
            "app_name": None,
            "app_description": None,
            "dest_list_version": None,
            "entry_number": None,
            "entry_id": None,
            "mru": None,
            "pin_status": None,
            "hostname": None,
            "mac_address": None,
            "interaction_count": None,
            "target_path": None,
            "effective_path": None,
            "effective_path_source": None,
            "display_name": None,
            "local_path": None,
            "common_path": None,
            "relative_path": None,
            "working_directory": None,
            "arguments": None,
            "description": None,
            "icon_location": None,
            "last_accessed": None,
            "last_modified": None,
            "created": None,
            "modified": None,
            "accessed": None,
            "birth_created": None,
            "birth_modified": None,
            "birth_accessed": None,
            "drive_type": None,
            "drive_serial_number": None,
            "volume_label": None,
            "network_path": None,
            "net_name": None,
            "device_name": None,
            "share_name": None,
            "machine_id": None,
            "tracker_droid": None,
            "tracker_birth_droid": None,
            "droid": None,
            "birth_droid": None,
        },
        "volume": {"serial": None, "label": None, "drive_type": None, "created": None},
        "network": {"direction": None, "share_name": None, "path": None, "source_ip": None, "source_port": None, "destination_ip": None, "destination_port": None, "protocol": None, "application": None, "domain": None, "url": None, "destination_hostname": None},
        "tags": ["jumplist"],
        "data_quality": [],
        "risk_score": 0,
        "raw_summary": "",
        "search_text": "",
        "raw": raw_row,
        "suspicious_reasons": [],
        "source_file": source_file,
        "source_tool": "jlecmd",
        "source_format": "csv",
    }


def _build_search_text(document: dict) -> str:
    jumplist = document.get("jumplist", {}) or {}
    raw = document.get("raw", {}) or {}
    values = [
        document.get("source_file"),
        (document.get("file") or {}).get("path"),
        (document.get("file") or {}).get("name"),
        jumplist.get("source_file"),
        jumplist.get("effective_path"),
        jumplist.get("display_name"),
        jumplist.get("local_path"),
        jumplist.get("relative_path"),
        jumplist.get("working_directory"),
        jumplist.get("arguments"),
        jumplist.get("app_name"),
        jumplist.get("app_id"),
        jumplist.get("machine_id"),
        jumplist.get("network_path"),
        (document.get("volume") or {}).get("serial"),
        raw.get("LocalPath"),
        raw.get("RelativePath"),
        raw.get("SourceFile"),
        raw.get("MachineID"),
        raw.get("VolumeSerialNumber"),
        " ".join(document.get("suspicious_reasons") or []),
    ]
    return " | ".join(str(value).strip() for value in values if value not in (None, "", []))[:8192]


def _raw_summary(target_path: str | None, source_file: str | None, app_name: str | None, arguments: str | None, drive_type: str | None, target_source: str | None) -> str:
    parts = [
        f"Target={target_path}" if target_path else None,
        f"TargetSource={target_source}" if target_source else None,
        f"App={app_name}" if app_name else None,
        f"Source={source_file}" if source_file else None,
        f"Args={arguments}" if arguments else None,
        f"DriveType={drive_type}" if drive_type else None,
    ]
    return " | ".join(item for item in parts if item)[:2000]


def parse_jlecmd_file(case_id: str, evidence_id: str, artifact_id: str, path: Path, artifact_meta: dict) -> list[dict]:
    rows = read_delimited_rows(path)
    documents: list[dict] = []
    audit = {
        "artifact": path.name,
        "parser": "jlecmd",
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
        "top_app_ids": {},
        "top_applications": {},
        "bulk_index_errors": 0,
        "top_errors": [],
    }
    extension_counts: Counter[str] = Counter()
    user_counts: Counter[str] = Counter()
    app_id_counts: Counter[str] = Counter()
    app_name_counts: Counter[str] = Counter()

    for row in rows:
        raw_row, lowered = _normalize_row_keys(row)
        timestamp, timestamp_type = _choose_timestamp(lowered)
        source_file = _normalize_value(_get(lowered, "SourceFile", "SourceFilename"))
        app_id = _normalize_value(_get(lowered, "AppId", "AppID"))
        app_name = _infer_app_name(lowered)
        target_path = _normalize_value(_get(lowered, "TargetPath", "Path"))
        local_path = _normalize_value(_get(lowered, "LocalPath"))
        common_path = _normalize_value(_get(lowered, "CommonPath"))
        relative_path = _normalize_value(_get(lowered, "RelativePath"))
        working_directory = _normalize_value(_get(lowered, "WorkingDirectory"))
        network_path = _normalize_value(_get(lowered, "NetworkPath", "NetName", "ShareName"))
        drive_type = _normalize_value(_get(lowered, "DriveType"))
        arguments = _normalize_value(_get(lowered, "Arguments"))
        path_candidates = {
            "source_file": source_file,
            "target_path": target_path or _normalize_value(_get(lowered, "Path")),
            "target_id_absolute_path": _normalize_value(_get(lowered, "TargetIDAbsolutePath")),
            "local_path": local_path,
            "common_path": common_path,
            "relative_path": relative_path,
            "working_directory": working_directory,
            "network_path": network_path,
        }
        effective = select_lnk_effective_target(path_candidates, raw_row)
        effective_path = _normalize_value(effective.get("effective_path"))
        effective_source = _normalize_value(effective.get("effective_path_source"))
        display_name = _normalize_value(effective.get("display_name"))
        event_type, base_tags = _classify_target(effective_path)
        suspicious_tags, suspicious_reasons = _detect_suspicious_lnk(
            effective_path,
            arguments,
            working_directory,
            _normalize_value(_get(lowered, "IconLocation")),
            network_path,
            drive_type,
        )
        all_tags = set(base_tags) | suspicious_tags | _drive_type_tags(drive_type) | {"jumplist"}
        if app_name and any(token in app_name.lower() for token in {"powershell", "cmd", "explorer", "winword", "excel", "chrome", "msedge", "7z", "winrar"}):
            all_tags.add("application_context")
        if event_type == "program_or_script_opened":
            if _suffix(effective_path) in SCRIPT_EXTENSIONS:
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
        if not effective_path:
            audit["missing_target_path"] += 1

        document = _base_document(case_id, evidence_id, artifact_id, path.name, raw_row, artifact_meta, timestamp, timestamp_type)
        user_name = extract_user_from_path(source_file) or extract_user_from_path(effective_path) or artifact_meta.get("detected_user")
        if user_name:
            user_counts[str(user_name)] += 1
        if app_id:
            app_id_counts[app_id] += 1
        if app_name:
            app_name_counts[app_name] += 1
        machine_id = _normalize_value(_get(lowered, "MachineID", "Hostname"))
        if machine_id and not document["host"]["name"]:
            document["host"]["name"] = normalize_hostname(machine_id)
            document["host"]["hostname"] = normalize_hostname(machine_id)

        target_extension = _suffix(effective_path)
        if target_extension:
            extension_counts[target_extension] += 1

        target_name = _basename(effective_path) or display_name
        if target_name:
            document["process"]["name"] = target_name if target_extension in EXECUTABLE_EXTENSIONS else None
            document["process"]["path"] = effective_path if target_extension in EXECUTABLE_EXTENSIONS else None
            if arguments and target_extension in EXECUTABLE_EXTENSIONS:
                document["process"]["command_line"] = f"{effective_path} {arguments}".strip()

        unc_host = _extract_unc_host(effective_path or network_path)
        if unc_host:
            document["destination"]["hostname"] = unc_host

        document["event"]["category"] = "file_access"
        document["event"]["type"] = event_type
        document["event"]["action"] = "jumplist_entry_accessed"
        document["event"]["message"] = f"JumpList target accessed: {effective_path or display_name or app_name or 'unknown target'}"
        document["event"]["timeline_include"] = bool(timestamp)

        document["file"].update(
            {
                "path": effective_path,
                "name": target_name,
                "extension": target_extension,
                "created": _parse_timestamp(_get(lowered, "Created", "BirthCreated")),
                "modified": _parse_timestamp(_get(lowered, "Modified", "LastModified", "BirthModified")),
                "accessed": _parse_timestamp(_get(lowered, "Accessed", "LastAccessed", "BirthAccessed")),
                "source_path": source_file,
            }
        )

        document["jumplist"].update(
            {
                "source_file": source_file,
                "app_id": app_id,
                "app_name": app_name,
                "app_description": _normalize_value(_get(lowered, "AppIdDescription", "AppDescription")),
                "dest_list_version": _normalize_value(_get(lowered, "DestListVersion")),
                "entry_number": _normalize_value(_get(lowered, "EntryNumber")),
                "entry_id": _normalize_value(_get(lowered, "EntryId")),
                "mru": _normalize_value(_get(lowered, "MRU")),
                "pin_status": _normalize_value(_get(lowered, "PinStatus")),
                "hostname": _normalize_value(_get(lowered, "Hostname")),
                "mac_address": _normalize_value(_get(lowered, "MacAddress")),
                "interaction_count": _safe_int(_get(lowered, "InteractionCount")),
                "target_path": target_path or _normalize_value(_get(lowered, "Path")),
                "effective_path": effective_path,
                "effective_path_source": effective_source,
                "display_name": display_name,
                "local_path": local_path,
                "common_path": common_path,
                "relative_path": relative_path,
                "working_directory": working_directory,
                "arguments": arguments,
                "description": _normalize_value(_get(lowered, "Description")),
                "icon_location": _normalize_value(_get(lowered, "IconLocation")),
                "last_accessed": _parse_timestamp(_get(lowered, "LastAccessed")),
                "last_modified": _parse_timestamp(_get(lowered, "LastModified")),
                "created": _parse_timestamp(_get(lowered, "Created")),
                "modified": _parse_timestamp(_get(lowered, "Modified")),
                "accessed": _parse_timestamp(_get(lowered, "Accessed")),
                "birth_created": _parse_timestamp(_get(lowered, "BirthCreated")),
                "birth_modified": _parse_timestamp(_get(lowered, "BirthModified")),
                "birth_accessed": _parse_timestamp(_get(lowered, "BirthAccessed")),
                "drive_type": drive_type,
                "drive_serial_number": _normalize_value(_get(lowered, "DriveSerialNumber", "VolumeSerialNumber")),
                "volume_label": _normalize_value(_get(lowered, "DriveLabel", "VolumeLabel")),
                "network_path": network_path,
                "net_name": _normalize_value(_get(lowered, "NetName")),
                "device_name": _normalize_value(_get(lowered, "DeviceName")),
                "share_name": _normalize_value(_get(lowered, "ShareName")),
                "machine_id": machine_id,
                "tracker_droid": _normalize_value(_get(lowered, "TrackerDroid")),
                "tracker_birth_droid": _normalize_value(_get(lowered, "TrackerBirthDroid")),
                "droid": _normalize_value(_get(lowered, "Droid")),
                "birth_droid": _normalize_value(_get(lowered, "BirthDroid")),
            }
        )
        document["volume"].update(
            {
                "serial": _normalize_value(_get(lowered, "DriveSerialNumber", "VolumeSerialNumber")),
                "label": _normalize_value(_get(lowered, "DriveLabel", "VolumeLabel")),
                "drive_type": drive_type,
            }
        )
        document["network"].update(
            {
                "direction": "access" if network_path or _is_unc(effective_path) else None,
                "share_name": _normalize_value(_get(lowered, "ShareName")),
                "path": network_path or (effective_path if _is_unc(effective_path) else None),
            }
        )
        if user_name and not document["user"]["name"]:
            document["user"]["name"] = user_name
        document["tags"] = sorted(all_tags)
        document["suspicious_reasons"] = sorted(set(suspicious_reasons))
        document["raw_summary"] = _raw_summary(effective_path, source_file, app_name, arguments, drive_type, effective_source)
        if not timestamp:
            document["data_quality"].append("missing_timestamp")
        if not effective_path:
            document["data_quality"].append("missing_target_path")
        score, severity = _risk_score(all_tags, suspicious_reasons, event_type)
        if (document["jumplist"].get("interaction_count") or 0) > 0 and score < 40:
            score += 5
        document["risk_score"] = score
        document["event"]["severity"] = severity
        document["search_text"] = _build_search_text(document)
        documents.append(document)

    audit["records_parsed"] = len(documents)
    audit["events_indexed"] = len(documents)
    audit["top_extensions"] = dict(extension_counts.most_common(10))
    audit["top_users"] = dict(user_counts.most_common(10))
    audit["top_app_ids"] = dict(app_id_counts.most_common(10))
    audit["top_applications"] = dict(app_name_counts.most_common(10))
    artifact_meta["ingest_audit"] = audit
    return documents


class JLECmdParser(ArtifactParser):
    def can_parse(self, path: Path, headers: list[str] | None = None) -> bool:
        lower_name = path.name.lower()
        if "jlecmd_output.csv" in lower_name or lower_name.endswith("_jlecmd_output.csv") or "jlecmd" in lower_name:
            return True
        normalized_headers = {_canonicalize_key(header) for header in (headers or []) if header}
        return len(JLECMD_HEADER_HINTS & normalized_headers) >= 3 and any(header in normalized_headers for header in {"appid", "appiddescription", "interactioncount", "targetpath", "path"})

    def parse(self, path: Path, **kwargs):
        return parse_jlecmd_file(
            kwargs["case_id"],
            kwargs["evidence_id"],
            kwargs["artifact_id"],
            path,
            kwargs["artifact_meta"],
        )
