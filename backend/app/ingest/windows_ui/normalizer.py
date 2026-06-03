from __future__ import annotations

import re
from urllib.parse import urlparse

from app.ingest.email.helpers import redact_secret_like_text
from app.ingest.windows_event_mapping import risk_score_to_severity
from app.ingest.windows_ui.helpers import basename_windows, clean_value, first_nonempty, normalize_windows_path, parent_windows, suffix_windows


EXECUTABLE_EXTENSIONS = {".exe", ".scr", ".com", ".msi", ".dll", ".hta", ".js", ".vbs", ".ps1", ".cmd", ".bat"}
MACRO_EXTENSIONS = {".docm", ".xlsm", ".pptm", ".xlam", ".dotm", ".ppam"}
ARCHIVE_EXTENSIONS = {".zip", ".rar", ".7z", ".iso", ".cab"}
SUSPICIOUS_EXTENSIONS = EXECUTABLE_EXTENSIONS | MACRO_EXTENSIONS | ARCHIVE_EXTENSIONS
STAGING_MARKERS = ("\\downloads\\", "\\temp\\", "\\appdata\\", "\\desktop\\", "\\startup\\", "\\public\\")
SECURITY_NOTIFICATION_HINTS = ("threat", "trojan", "malware", "quarantine", "phishing", "credential", "defender")
OFFICE_SECURITY_HINTS = ("protected view", "enable content", "enable editing", "macro", "security warning", "content disabled")


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


def _body_preview(value: str | None) -> str | None:
    return redact_secret_like_text(clean_value(value), max_len=600)


def _score_windows_ui(parser_name: str, row: dict, file_path: str | None) -> tuple[int, list[str], list[str]]:
    reasons: list[str] = []
    tags: list[str] = ["windows_ui"]
    risk = 5
    extension = (suffix_windows(file_path) or "").lower()
    lower_path = str(file_path or "").lower()

    if parser_name in {"windows_thumbcache", "windows_thumbsdb"}:
        if extension in SUSPICIOUS_EXTENSIONS or _is_double_extension(file_path):
            reasons.append("Thumbnail cache references suspicious file")
            risk = max(risk, 65)
        if _is_user_writable_or_staging(file_path):
            reasons.append("Thumbnail source path in user-writable or staging location")
            risk = max(risk, 45)
        if _is_unc_or_removable(file_path):
            reasons.append("Thumbnail source path on removable drive or network share")
            risk = max(risk, 50)
    elif parser_name == "windows_notifications":
        title = str(first_nonempty(row, "Title", "NotificationTitle") or "").lower()
        body = str(first_nonempty(row, "Body", "BodyPreview", "PayloadPreview") or "").lower()
        app_name = str(first_nonempty(row, "AppName", "AppId", "PackageId") or "").lower()
        blob = f"{title} {body} {app_name}"
        if any(token in blob for token in SECURITY_NOTIFICATION_HINTS):
            reasons.append("Security or threat notification observed")
            risk = max(risk, 80)
            tags.append("security_notification")
        elif "download complete" in blob and (extension in EXECUTABLE_EXTENSIONS or "payload.exe" in blob):
            reasons.append("Notification references suspicious download")
            risk = max(risk, 60)
    elif parser_name == "windows_activitiescache":
        uri = str(first_nonempty(row, "ActivationUri", "WebUrl") or "")
        if extension in MACRO_EXTENSIONS:
            reasons.append("Windows Timeline references macro-enabled Office document")
            risk = max(risk, 70)
        if extension in EXECUTABLE_EXTENSIONS or "powershell" in lower_path or "powershell" in uri.lower():
            reasons.append("Windows Timeline references suspicious executable or script")
            risk = max(risk, 75)
        if uri.lower().startswith("http"):
            reasons.append("Windows Timeline references web activity")
            risk = max(risk, 35)
    elif parser_name == "windows_search_index":
        if extension in EXECUTABLE_EXTENSIONS or _is_double_extension(file_path):
            reasons.append("Windows Search index references suspicious executable or double extension")
            risk = max(risk, 65)
        elif extension in MACRO_EXTENSIONS:
            reasons.append("Windows Search index references macro-enabled document")
            risk = max(risk, 55)
        elif "password" in lower_path:
            reasons.append("Windows Search index references potentially sensitive document")
            risk = max(risk, 40)
    elif parser_name == "windows_eventtranscript":
        text = str(first_nonempty(row, "EventText", "BodyPreview", "Text") or "").lower()
        if any(token in text for token in ("download", "payload", "trojan", "phishing")):
            reasons.append("Event transcript references suspicious UI activity")
            risk = max(risk, 60)
    elif parser_name == "office_oalerts_evtx":
        text = str(first_nonempty(row, "AlertText", "Message", "OfficeAlert") or "").lower()
        if any(token in text for token in OFFICE_SECURITY_HINTS):
            reasons.append("Office security alert observed")
            risk = max(risk, 85 if extension in MACRO_EXTENSIONS or _is_user_writable_or_staging(file_path) else 70)
            tags.append("office_security_alert")
    elif parser_name in {"office_filecache", "office_backstage"}:
        path_or_url = str(first_nonempty(row, "DocumentPath", "DocumentUrl", "IndexedPath", "FilePath") or "")
        if path_or_url.lower().startswith("http"):
            reasons.append("Office cache references remote document")
            risk = max(risk, 55)
        if extension in MACRO_EXTENSIONS:
            reasons.append("Office cache references macro-enabled document")
            risk = max(risk, 65)
    elif parser_name == "windows_ui_generic_raw":
        reasons.append("Raw Windows UI artifact inventory only")
        risk = 0

    return risk, list(dict.fromkeys(reasons)), list(dict.fromkeys(tags))


def normalize_windows_ui_row(document: dict, row: dict, artifact_meta: dict) -> dict:
    parser_name = str(first_nonempty(row, "WindowsUIParser") or artifact_meta.get("parser") or "windows_ui_generic_raw").lower()
    source_file = normalize_windows_path(str(artifact_meta.get("source_path") or artifact_meta.get("name") or ""))
    file_path = normalize_windows_path(first_nonempty(row, "FilePath", "FullPath", "SourcePath", "IndexedPath", "DocumentPath", "ThumbnailPath"))
    file_name = basename_windows(file_path)
    folder_path = normalize_windows_path(first_nonempty(row, "FolderPath", "ParentPath")) or parent_windows(file_path)
    event_type = str(first_nonempty(row, "EventType") or "")
    action = "observed"

    if parser_name in {"windows_thumbcache", "windows_thumbsdb"}:
        event_type = event_type or "thumbnail_observed"
    elif parser_name == "windows_notifications":
        event_type = event_type or "notification_observed"
    elif parser_name == "windows_activitiescache":
        event_type = event_type or "activity_history_observed"
    elif parser_name == "windows_search_index":
        event_type = event_type or "search_index_entry_observed"
    elif parser_name == "windows_eventtranscript":
        event_type = event_type or "event_transcript_observed"
    elif parser_name == "office_oalerts_evtx":
        event_type = event_type or "office_alert_observed"
    elif parser_name in {"office_filecache", "office_backstage"}:
        event_type = event_type or "office_cache_entry_observed"
    else:
        event_type = "ui_artifact_observed"
        action = "inventory"

    risk_score, suspicious_reasons, tags = _score_windows_ui(parser_name, row, file_path)

    notification_title = clean_value(first_nonempty(row, "Title", "NotificationTitle"))
    notification_body = _body_preview(first_nonempty(row, "Body", "BodyPreview", "PayloadPreview", "Payload"))
    activity_display = clean_value(first_nonempty(row, "DisplayText", "DisplayName", "Description"))
    activity_uri = clean_value(first_nonempty(row, "ActivationUri", "WebUrl", "Uri"))
    office_alert_text = _body_preview(first_nonempty(row, "AlertText", "Message", "OfficeAlert"))
    office_doc = normalize_windows_path(first_nonempty(row, "DocumentPath", "DocumentUrl"))
    indexed_path = normalize_windows_path(first_nonempty(row, "IndexedPath")) or file_path
    host_url = clean_value(first_nonempty(row, "HostUrl", "SourceUrl", "DocumentUrl", "WebUrl"))

    document["artifact"]["type"] = "windows_ui"
    document["artifact"]["parser"] = parser_name
    document["artifact"]["name"] = f"Windows UI - {file_name or parser_name}"
    document["event"]["category"] = "user_activity"
    document["event"]["type"] = event_type
    document["event"]["action"] = action
    document["event"]["severity"] = risk_score_to_severity(risk_score)
    document["risk_score"] = risk_score
    document["_preserve_risk_score"] = True
    document["suspicious_reasons"] = suspicious_reasons
    document["tags"] = tags
    document["event"]["message"] = {
        "thumbnail_observed": f"Thumbnail observed for {file_name or file_path or '-'}",
        "notification_observed": f"Notification observed: {notification_title or file_name or '-'}",
        "activity_history_observed": f"Activity history observed: {activity_display or file_name or '-'}",
        "search_index_entry_observed": f"Windows Search indexed entry observed: {file_name or indexed_path or '-'}",
        "event_transcript_observed": f"Event transcript observed: {file_name or activity_display or '-'}",
        "office_alert_observed": f"Office alert observed: {office_alert_text or file_name or '-'}",
        "office_cache_entry_observed": f"Office cache entry observed: {file_name or office_doc or '-'}",
    }.get(event_type, f"Windows UI artifact observed: {file_name or parser_name}")

    document["file"].update(
        {
            "path": file_path or indexed_path or office_doc,
            "name": file_name or basename_windows(indexed_path or office_doc),
            "extension": suffix_windows(file_path or indexed_path or office_doc),
            "size": _coerce_int(first_nonempty(row, "Size", "FileSize")),
            "source_path": source_file,
        }
    )
    document["folder"]["path"] = folder_path
    document["process"]["name"] = clean_value(first_nonempty(row, "ProcessName", "Executable", "Application", "AppName"))
    document["process"]["path"] = normalize_windows_path(first_nonempty(row, "ProcessPath", "ApplicationPath"))
    document["app"] = {
        "name": clean_value(first_nonempty(row, "AppName", "Application", "PackageDisplayName")),
        "id": clean_value(first_nonempty(row, "AppId", "ApplicationId")),
        "package": clean_value(first_nonempty(row, "PackageId", "PackageFamilyName")),
    }
    document["notification"] = {
        "title": notification_title,
        "body_preview": notification_body,
        "app_id": clean_value(first_nonempty(row, "AppId", "PackageId")),
        "created_time": clean_value(first_nonempty(row, "CreatedTime", "Created", "TimeCreated")),
        "expires_time": clean_value(first_nonempty(row, "ExpiresTime", "ExpiryTime")),
    }
    document["activity"] = {
        "activity_id": clean_value(first_nonempty(row, "ActivityId")),
        "app_id": clean_value(first_nonempty(row, "AppId", "ApplicationId")),
        "display_text": activity_display,
        "activation_uri": activity_uri,
        "start_time": clean_value(first_nonempty(row, "StartTime", "CreatedTime")),
        "end_time": clean_value(first_nonempty(row, "EndTime", "LastModified", "ModifiedTime")),
    }
    document["office"] = {
        "app": clean_value(first_nonempty(row, "OfficeApp", "AppName")),
        "alert_id": clean_value(first_nonempty(row, "AlertId")),
        "alert_text": office_alert_text,
        "document_path": office_doc,
        "cache_id": clean_value(first_nonempty(row, "CacheId", "EntryId")),
    }
    document["windows_search"] = {
        "entry_id": clean_value(first_nonempty(row, "EntryId", "DocId")),
        "indexed_path": indexed_path,
        "content_type": clean_value(first_nonempty(row, "ContentType", "MimeType")),
        "last_modified": clean_value(first_nonempty(row, "LastModified", "ModifiedTime")),
    }
    document["thumbnail"] = {
        "cache_id": clean_value(first_nonempty(row, "ThumbnailCacheId", "CacheId")),
        "source_path": normalize_windows_path(first_nonempty(row, "ThumbnailPath", "SourcePath", "FilePath")),
        "width": _coerce_int(first_nonempty(row, "Width")),
        "height": _coerce_int(first_nonempty(row, "Height")),
        "format": clean_value(first_nonempty(row, "Format", "ImageFormat")),
        "entry_hash": clean_value(first_nonempty(row, "CacheEntryHash", "EntryHash")),
    }
    document["url"].update({"full": host_url or activity_uri, "domain": _domain_from_url(host_url or activity_uri)})
    document["execution"]["is_execution_confirmed"] = False
    document["execution"]["confidence"] = "low"
    document["windows_ui"] = {
        "source": parser_name.removeprefix("windows_").removeprefix("office_"),
        "timestamp_source": clean_value(first_nonempty(row, "TimestampSource")) or (
            "notification_created"
            if parser_name == "windows_notifications"
            else "activity_start"
            if parser_name == "windows_activitiescache"
            else "windows_search_last_modified"
            if parser_name == "windows_search_index"
            else "office_alert_event_time"
            if parser_name == "office_oalerts_evtx"
            else "thumbnail_cache_timestamp"
            if parser_name in {"windows_thumbcache", "windows_thumbsdb"}
            else "source_file"
        ),
    }
    document["data_quality"] = sorted(
        set(document.get("data_quality") or [])
        | ({"windows_ui_inventory_only"} if parser_name == "windows_ui_generic_raw" else set())
    )
    document["related_iocs"] = {
        "files": sorted({item for item in [file_path, indexed_path, office_doc, (document.get("thumbnail") or {}).get("source_path")] if item}),
        "urls": sorted({item for item in [host_url, activity_uri] if item and str(item).lower().startswith("http")}),
        "domains": sorted({item for item in [_domain_from_url(host_url), _domain_from_url(activity_uri)] if item}),
    }
    document["event"]["timeline_include"] = risk_score >= 50 or event_type in {"office_alert_observed", "notification_observed"}
    document["_preserve_timeline_include"] = True
    return document
