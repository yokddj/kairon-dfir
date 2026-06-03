from __future__ import annotations

import re
from urllib.parse import urlparse

from app.ingest.ntfs.helpers import basename_windows, clean_value, first_nonempty, normalize_windows_path, parent_windows, suffix_windows
from app.ingest.windows_event_mapping import risk_score_to_severity


EXECUTABLE_EXTENSIONS = {".exe", ".scr", ".com", ".msi", ".dll", ".hta", ".jar", ".lnk", ".ps1", ".cmd", ".bat", ".js", ".vbs", ".wsf"}
MACRO_EXTENSIONS = {".docm", ".xlsm", ".pptm", ".xlam", ".dotm"}
ARCHIVE_EXTENSIONS = {".zip", ".rar", ".7z", ".iso", ".cab"}
SUSPICIOUS_DOC_EXTENSIONS = MACRO_EXTENSIONS | EXECUTABLE_EXTENSIONS | ARCHIVE_EXTENSIONS
STAGING_MARKERS = ("\\downloads\\", "\\temp\\", "\\appdata\\", "\\desktop\\", "\\startup\\", "\\public\\", "\\programdata\\")


def _as_bool(value: object | None) -> bool | None:
    if value in (None, ""):
        return None
    if isinstance(value, bool):
        return value
    text = str(value).strip().lower()
    if text in {"1", "true", "yes", "y"}:
        return True
    if text in {"0", "false", "no", "n"}:
        return False
    return None


def _coerce_int(value: object | None) -> int | None:
    cleaned = clean_value(value)
    if cleaned is None:
        return None
    try:
        return int(str(cleaned), 10)
    except Exception:  # noqa: BLE001
        return None


def _is_double_extension(path: str | None) -> bool:
    name = str(basename_windows(path) or "").lower()
    parts = [part for part in name.split(".") if part]
    return len(parts) >= 3 and f".{parts[-1]}" in EXECUTABLE_EXTENSIONS


def _is_user_writable_or_staging(path: str | None) -> bool:
    lowered = str(path or "").replace("/", "\\").lower()
    return "\\users\\" in lowered and any(marker in lowered for marker in STAGING_MARKERS)


def _is_unc_or_removable(path: str | None) -> bool:
    lowered = str(path or "").replace("/", "\\").lower()
    return lowered.startswith("\\\\") or re.match(r"^[defghijklmnopqrstuvwxyz]:\\\\", lowered) is not None


def _domain_from_url(value: str | None) -> str | None:
    cleaned = clean_value(value)
    if not cleaned:
        return None
    try:
        return urlparse(cleaned).hostname
    except Exception:  # noqa: BLE001
        return None


def _zone_name(zone_id: int | None) -> str | None:
    mapping = {0: "My Computer", 1: "Local Intranet", 2: "Trusted Sites", 3: "Internet", 4: "Untrusted"}
    return mapping.get(zone_id)


def _event_from_usn_reason(reason: str | None) -> tuple[str, str]:
    lowered = str(reason or "").upper()
    if "FILE_CREATE" in lowered:
        return "file_created_observed", "created"
    if "FILE_DELETE" in lowered:
        return "file_deleted_observed", "deleted"
    if "RENAME_OLD_NAME" in lowered or "RENAME_NEW_NAME" in lowered:
        return "file_renamed_observed", "renamed"
    if any(token in lowered for token in ("DATA_EXTEND", "DATA_OVERWRITE", "DATA_TRUNCATION")):
        return "file_modified_observed", "modified"
    return "ntfs_metadata_observed", "observed"


def _event_from_logfile(row: dict) -> tuple[str, str]:
    blob = " ".join(str(value) for value in row.values() if value).lower()
    if "delete" in blob:
        return "file_deleted_observed", "deleted"
    if "rename" in blob or "oldname" in blob or "newname" in blob:
        return "file_renamed_observed", "renamed"
    if "create" in blob:
        return "file_created_observed", "created"
    if "move" in blob:
        return "file_moved_observed", "moved"
    if "modify" in blob or "change" in blob:
        return "file_modified_observed", "modified"
    return "ntfs_metadata_observed", "observed"


def _score_ntfs(row: dict, parser_name: str, path: str | None, event_type: str) -> tuple[int, list[str], list[str]]:
    reasons: list[str] = []
    tags: list[str] = ["ntfs"]
    extension = (suffix_windows(path) or "").lower()
    risk = 5

    if parser_name == "ntfs_ads_zone_identifier":
        zone_id = _coerce_int(first_nonempty(row, "ZoneId"))
        host_url = clean_value(first_nonempty(row, "HostUrl"))
        referrer_url = clean_value(first_nonempty(row, "ReferrerUrl"))
        if zone_id in {3, 4}:
            reasons.append(f"Zone.Identifier indicates {_zone_name(zone_id) or zone_id}")
            risk = max(risk, 35 if extension not in SUSPICIOUS_DOC_EXTENSIONS and not _is_double_extension(path) else 70)
        if extension in EXECUTABLE_EXTENSIONS:
            reasons.append("Downloaded executable or script marked with web origin")
            risk = max(risk, 90)
            tags.append("downloaded_executable")
        elif extension in MACRO_EXTENSIONS:
            reasons.append("Downloaded macro-enabled Office document")
            risk = max(risk, 75)
        elif extension in ARCHIVE_EXTENSIONS:
            reasons.append("Downloaded archive marked with web origin")
            risk = max(risk, 65)
        if _is_double_extension(path):
            reasons.append("Downloaded double-extension file")
            risk = max(risk, 95)
        if host_url and re.search(r"https?://(?:\d{1,3}\.){3}\d{1,3}", host_url, re.IGNORECASE):
            reasons.append("Download host URL uses direct IP")
            risk = max(risk, 70)
        if host_url and referrer_url and _domain_from_url(host_url) and _domain_from_url(referrer_url) and _domain_from_url(host_url) != _domain_from_url(referrer_url):
            reasons.append("Referrer URL domain mismatch")
            risk = max(risk, 55)
        if _is_user_writable_or_staging(path):
            reasons.append("Web-origin file stored in user-writable staging path")
            risk = max(risk, 50)
    elif parser_name in {"ntfs_usnjrnl", "ntfs_logfile", "ntfs_i30", "ntfs_mft_enriched"}:
        if extension in SUSPICIOUS_DOC_EXTENSIONS or _is_double_extension(path):
            reasons.append("Suspicious file type observed in NTFS metadata")
            risk = max(risk, 45)
        if event_type in {"file_created_observed", "file_deleted_observed", "file_renamed_observed", "file_moved_observed"} and (extension in SUSPICIOUS_DOC_EXTENSIONS or _is_double_extension(path)):
            reasons.append(f"Suspicious file {event_type.removesuffix('_observed').replace('_', ' ')}")
            risk = max(risk, 70 if event_type != "file_deleted_observed" else 75)
        if _is_user_writable_or_staging(path):
            reasons.append("Suspicious NTFS activity in user-writable path")
            risk = max(risk, 55)
        if _is_unc_or_removable(path):
            reasons.append("NTFS activity on removable drive or UNC path")
            risk = max(risk, 50)
        if parser_name == "ntfs_i30" and (_as_bool(first_nonempty(row, "IsDeleted", "Deleted")) is True or _as_bool(first_nonempty(row, "InUse")) is False):
            reasons.append("Deleted directory entry observed in $I30")
            risk = max(risk, 60 if extension in SUSPICIOUS_DOC_EXTENSIONS or _is_double_extension(path) else 35)
        if parser_name == "ntfs_logfile" and event_type == "ntfs_metadata_observed":
            reasons.append("$LogFile metadata transaction observed")
            risk = max(risk, 20)
    elif parser_name == "ntfs_shadowcopy":
        reasons.append("Shadow copy metadata observed")
        risk = 10
    elif parser_name == "ntfs_generic_raw":
        reasons.append("Raw NTFS artifact inventory only")
        risk = 0

    return risk, list(dict.fromkeys(reasons)), list(dict.fromkeys(tags))


def normalize_ntfs_row(document: dict, row: dict, artifact_meta: dict) -> dict:
    parser_name = str(first_nonempty(row, "NtfsParser") or artifact_meta.get("parser") or "ntfs_generic_raw").lower()
    source_artifact_type = str(artifact_meta.get("artifact_type") or "").strip().lower()
    source_file = normalize_windows_path(str(artifact_meta.get("source_path") or artifact_meta.get("name") or ""))
    file_path = normalize_windows_path(first_nonempty(row, "FilePath", "FullPath", "Path", "FileName")) or source_file
    file_name = basename_windows(file_path)
    folder_path = normalize_windows_path(first_nonempty(row, "ParentPath", "DirectoryPath", "FolderPath")) or parent_windows(file_path)
    event_type = str(first_nonempty(row, "EventType") or "")
    action = "observed"

    if parser_name == "ntfs_ads_zone_identifier":
        event_type = event_type or "file_zone_identifier_observed"
    elif parser_name == "ntfs_usnjrnl":
        event_type, action = _event_from_usn_reason(first_nonempty(row, "Reason"))
    elif parser_name == "ntfs_logfile":
        event_type, action = _event_from_logfile(row)
    elif parser_name == "ntfs_i30":
        event_type = event_type or "directory_entry_observed"
    elif parser_name == "ntfs_shadowcopy":
        event_type = event_type or "shadowcopy_observed"
    elif parser_name == "ntfs_generic_raw":
        event_type = "ntfs_metadata_observed"
        action = "inventory"
    elif parser_name == "ntfs_mft_enriched":
        if str(first_nonempty(row, "IsDeleted") or "").lower() in {"true", "1", "yes"}:
            event_type = "file_deleted_observed"
            action = "deleted"
        else:
            event_type = event_type or "ntfs_metadata_observed"

    risk_score, suspicious_reasons, tags = _score_ntfs(row, parser_name, file_path, event_type)
    zone_id = _coerce_int(first_nonempty(row, "ZoneId"))
    host_url = clean_value(first_nonempty(row, "HostUrl"))
    referrer_url = clean_value(first_nonempty(row, "ReferrerUrl"))
    old_name = normalize_windows_path(first_nonempty(row, "OldName"))
    new_name = normalize_windows_path(first_nonempty(row, "NewName"))

    document["artifact"]["type"] = "mft" if source_artifact_type == "mft" else "ntfs"
    document["artifact"]["parser"] = parser_name
    document["artifact"]["name"] = f"NTFS - {file_name or parser_name}"
    document["event"]["category"] = "file"
    document["event"]["type"] = event_type
    document["event"]["action"] = action
    document["event"]["severity"] = risk_score_to_severity(risk_score)
    document["risk_score"] = risk_score
    document["_preserve_risk_score"] = True
    document["suspicious_reasons"] = suspicious_reasons
    document["tags"] = tags
    document["event"]["message"] = {
        "file_zone_identifier_observed": f"Zone.Identifier observed for {file_name or file_path or '-'}",
        "file_created_observed": f"NTFS file create observed: {file_name or file_path or '-'}",
        "file_modified_observed": f"NTFS file modification observed: {file_name or file_path or '-'}",
        "file_deleted_observed": f"NTFS file delete observed: {file_name or file_path or '-'}",
        "file_renamed_observed": f"NTFS file rename observed: {old_name or file_name or '-'} -> {new_name or file_name or '-'}",
        "file_moved_observed": f"NTFS file move observed: {file_name or file_path or '-'}",
        "directory_entry_observed": f"$I30 directory entry observed: {file_name or file_path or '-'}",
        "shadowcopy_observed": f"Shadow copy observed: {clean_value(first_nonempty(row, 'ShadowId')) or file_name or '-'}",
    }.get(event_type, f"NTFS metadata observed: {file_name or file_path or parser_name}")

    document["file"].update(
        {
            "path": file_path,
            "name": file_name,
            "extension": suffix_windows(file_path),
            "size": _coerce_int(first_nonempty(row, "Size", "FileSize")),
            "parent_path": folder_path,
            "source_path": source_file,
            "created": clean_value(first_nonempty(row, "Created0x10", "Created0x30")),
            "modified": clean_value(first_nonempty(row, "Modified0x10", "Modified0x30")),
            "accessed": clean_value(first_nonempty(row, "Accessed0x10", "Accessed0x30")),
            "changed": clean_value(first_nonempty(row, "Changed0x10", "Changed0x30", "LastRecordChange0x10", "LastRecordChange0x30")),
            "deleted": clean_value(first_nonempty(row, "DeletedTime")),
            "is_deleted": _as_bool(first_nonempty(row, "IsDeleted")),
            "entry_number": first_nonempty(row, "EntryNumber", "FileReference"),
            "sequence_number": first_nonempty(row, "SequenceNumber"),
            "mft_reference": first_nonempty(row, "FileReference"),
        }
    )
    document["folder"]["path"] = folder_path
    document["url"].update({"full": host_url or referrer_url, "domain": _domain_from_url(host_url) or _domain_from_url(referrer_url)})
    document["execution"]["is_execution_confirmed"] = False
    document["execution"]["confidence"] = "low"
    document["ntfs"] = {
        "source": parser_name.removeprefix("ntfs_"),
        "usn": first_nonempty(row, "USN", "UpdateSequenceNumber"),
        "reason": clean_value(first_nonempty(row, "Reason", "Operation")),
        "in_use": _as_bool(first_nonempty(row, "InUse")),
        "old_name": old_name,
        "new_name": new_name,
        "zone_id": zone_id,
        "zone_name": _zone_name(zone_id),
        "host_url": host_url,
        "referrer_url": referrer_url,
        "last_writer_package_family_name": clean_value(first_nonempty(row, "LastWriterPackageFamilyName")),
        "shadow_id": clean_value(first_nonempty(row, "ShadowId")),
        "snapshot_time": clean_value(first_nonempty(row, "SnapshotTime")),
        "timestamp_source": clean_value(first_nonempty(row, "TimestampSource")) or (
            "ads_zone_identifier"
            if parser_name == "ntfs_ads_zone_identifier"
            else "usnjrnl_timestamp"
            if parser_name == "ntfs_usnjrnl"
            else "logfile_timestamp"
            if parser_name == "ntfs_logfile"
            else "i30_entry_timestamp"
            if parser_name == "ntfs_i30"
            else "shadowcopy_snapshot"
            if parser_name == "ntfs_shadowcopy"
            else "source_file"
        ),
    }
    document["data_quality"] = sorted(
        set(document.get("data_quality") or [])
        | (
            {"ntfs_inventory_only"}
            if parser_name == "ntfs_generic_raw"
            else {"logfile_transaction_metadata_only"}
            if parser_name == "ntfs_logfile" and event_type == "ntfs_metadata_observed"
            else set()
        )
    )
    document["related_iocs"] = {
        "urls": sorted({item for item in [host_url, referrer_url] if item}),
        "domains": sorted({item for item in [_domain_from_url(host_url), _domain_from_url(referrer_url)] if item}),
        "files": sorted({item for item in [file_path, old_name, new_name] if item}),
    }
    document["event"]["timeline_include"] = risk_score >= 50 or event_type in {"file_zone_identifier_observed", "file_deleted_observed", "file_renamed_observed"}
    document["_preserve_timeline_include"] = True
    return document
