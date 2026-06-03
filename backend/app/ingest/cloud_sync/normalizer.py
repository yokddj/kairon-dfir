from __future__ import annotations

from app.ingest.identity_extraction import extract_user_from_path
from app.ingest.cloud_sync.helpers import (
    basename_windows,
    classify_cloud_file,
    classify_cloud_item,
    clean_value,
    detect_cloud_provider_from_path,
    first_nonempty,
    normalize_cloud_direction,
    normalize_cloud_provider,
    normalize_windows_path,
    parse_cloud_url,
    redact_cloud_secrets,
    suffix_windows,
)
from app.ingest.windows_event_mapping import risk_score_to_severity


def _as_bool(value: object | None) -> bool | None:
    if value in (None, ""):
        return None
    lowered = str(value).strip().lower()
    if lowered in {"true", "1", "yes"}:
        return True
    if lowered in {"false", "0", "no"}:
        return False
    return None


def normalize_cloud_row(document: dict, row: dict, artifact_meta: dict) -> dict:
    source_file = str(artifact_meta.get("source_path") or artifact_meta.get("name") or "")
    normalized_source_path = normalize_windows_path(str(artifact_meta.get("velociraptor_normalized_windows_path") or source_file or ""))

    provider_raw = clean_value(first_nonempty(row, "Provider")) or artifact_meta.get("cloud_provider")
    account = clean_value(first_nonempty(row, "Account"))
    account_email = redact_cloud_secrets(first_nonempty(row, "AccountEmail", "UserEmail"))
    user_name = clean_value(first_nonempty(row, "User")) or artifact_meta.get("user")
    user_sid = clean_value(first_nonempty(row, "UserSid"))
    sync_root = normalize_windows_path(first_nonempty(row, "SyncRoot")) or normalize_windows_path(str(artifact_meta.get("cloud_sync_root") or artifact_meta.get("sync_root") or ""))
    local_path = normalize_windows_path(first_nonempty(row, "LocalPath", "FilePath")) or normalized_source_path
    remote_path = clean_value(first_nonempty(row, "RemotePath"))
    cloud_path = clean_value(first_nonempty(row, "CloudPath"))
    item_id = redact_cloud_secrets(first_nonempty(row, "ItemId"))
    drive_id = redact_cloud_secrets(first_nonempty(row, "DriveId"))
    resource_id = redact_cloud_secrets(first_nonempty(row, "ResourceId"))
    status = clean_value(first_nonempty(row, "Status"))
    sync_status = clean_value(first_nonempty(row, "SyncStatus"))
    hydration_status = clean_value(first_nonempty(row, "HydrationStatus"))
    pinned = _as_bool(first_nonempty(row, "Pinned"))
    shared = _as_bool(first_nonempty(row, "Shared"))
    created_time = clean_value(first_nonempty(row, "CreatedTime", "Created"))
    modified_time = clean_value(first_nonempty(row, "ModifiedTime", "Modified"))
    accessed_time = clean_value(first_nonempty(row, "AccessedTime", "Accessed"))
    deleted_time = clean_value(first_nonempty(row, "DeletedTime", "Deleted"))
    last_sync_time = clean_value(first_nonempty(row, "LastSyncTime", "LastSync"))
    last_upload_time = clean_value(first_nonempty(row, "LastUploadTime", "LastUpload"))
    last_download_time = clean_value(first_nonempty(row, "LastDownloadTime", "LastDownload"))
    parser_status = clean_value(first_nonempty(row, "ParserStatus")) or ("discovery_only" if str(artifact_meta.get("parser") or "").lower() == "path_inference" else "ready")
    detection_method = clean_value(first_nonempty(row, "DetectionMethod")) or ("path_inference" if str(artifact_meta.get("parser") or "").lower() == "path_inference" else "parsed_output")
    timestamp_interpretation = clean_value(first_nonempty(row, "TimestampInterpretation"))
    computer = clean_value(first_nonempty(row, "Computer"))
    url_value = redact_cloud_secrets(first_nonempty(row, "URL"))

    provider_from_path, sync_root_from_path, _ = detect_cloud_provider_from_path(local_path or sync_root or normalized_source_path)
    provider = normalize_cloud_provider(provider_raw or provider_from_path)
    if provider == "Unknown" and provider_from_path:
        provider = normalize_cloud_provider(provider_from_path)
    sync_root = sync_root or sync_root_from_path
    if not user_name:
        user_name = extract_user_from_path(normalized_source_path or source_file) or extract_user_from_path(local_path) or extract_user_from_path(sync_root)

    direction = normalize_cloud_direction(
        first_nonempty(row, "Direction"),
        deleted_time=deleted_time,
        upload_time=last_upload_time,
        download_time=last_download_time,
        sync_time=last_sync_time,
    )

    explicit_artifact_type = (clean_value(first_nonempty(row, "ArtifactType")) or str(artifact_meta.get("cloud_artifact_type") or "")).lower()
    if direction == "upload":
        event_type = "cloud_upload"
    elif direction == "download":
        event_type = "cloud_download"
    elif direction == "delete":
        event_type = "cloud_deleted"
    else:
        event_type = "cloud_item_observed"

    if "syncroot" in explicit_artifact_type or str(artifact_meta.get("parser") or "").lower() == "path_inference":
        direction = "sync" if direction == "unknown" else direction
        event_type = "cloud_item_observed"

    artifact_subtype = (
        "syncroot" if "syncroot" in explicit_artifact_type
        else "cloud_file" if hydration_status
        else "onedrive_item"
    )

    parsed_url = parse_cloud_url(url_value)
    file_path = local_path
    file_name = basename_windows(file_path)
    file_extension = suffix_windows(file_path)

    tags, reasons, risk = classify_cloud_item(
        provider=provider,
        local_path=local_path,
        remote_path=remote_path,
        cloud_path=cloud_path,
        direction=direction,
        hydration_status=hydration_status,
        shared=shared,
        deleted_time=deleted_time,
    )
    legacy_tags, legacy_reasons, legacy_risk = classify_cloud_file(local_path or sync_root, command_line=remote_path or cloud_path)
    tags |= legacy_tags
    reasons = list(dict.fromkeys([*reasons, *legacy_reasons]))
    risk = max(risk, legacy_risk)
    if sync_root:
        tags.add("cloud_sync")
    if provider == "Unknown":
        document["data_quality"] = sorted(set(document.get("data_quality", [])) | {"cloud_unknown_provider"})
    if direction == "unknown":
        document["data_quality"] = sorted(set(document.get("data_quality", [])) | {"cloud_unknown_direction"})
    if hydration_status and "placeholder" in str(hydration_status).lower() and not local_path:
        document["data_quality"] = sorted(set(document.get("data_quality", [])) | {"cloud_placeholder_without_local_file"})

    sanitized_raw = {}
    for key, value in (document.get("raw") or {}).items():
        sanitized_raw[key] = redact_cloud_secrets(str(value) if value is not None else None) if any(token in str(key).lower() for token in {"token", "password", "secret", "cookie"}) else value
    document["raw"] = sanitized_raw

    document["artifact"]["type"] = "cloud"
    parser_name = str(artifact_meta.get("parser") or "cloud_onedrive_csv")
    if parser_name == "cloud_csv":
        parser_name = "cloud_onedrive_csv"
    elif parser_name == "cloud_json":
        parser_name = "cloud_onedrive_json"
    elif parser_name == "provider_log":
        parser_name = "cloud_raw"
    elif parser_name == "path_inference":
        parser_name = "cloud_syncroot"
    elif parser_name == "cloud_jsonl":
        parser_name = "cloud_onedrive_jsonl"
    document["artifact"]["parser"] = parser_name
    document["artifact"]["name"] = f"Cloud item - {file_path or remote_path or account or provider}"

    document["event"]["category"] = "cloud"
    document["event"]["type"] = event_type
    document["event"]["action"] = {
        "cloud_item_observed": "cloud_item_observed",
        "cloud_upload": "cloud_upload_observed",
        "cloud_download": "cloud_download_observed",
        "cloud_deleted": "cloud_delete_observed",
    }[event_type]
    document["event"]["message"] = (
        f"Cloud upload observed: {local_path or '-'} -> {remote_path or cloud_path or '-'}" if event_type == "cloud_upload"
        else f"Cloud download observed: {remote_path or cloud_path or '-'} -> {local_path or '-'}" if event_type == "cloud_download"
        else f"Cloud deletion observed: {local_path or remote_path or cloud_path or '-'}" if event_type == "cloud_deleted"
        else f"Cloud item observed: {local_path or remote_path or cloud_path or sync_root or account or provider}"
    )
    if parser_status == "ready" and parser_name == "cloud_raw":
        document["event"]["timeline_include"] = False

    document["cloud"].update(
        {
            "artifact_type": artifact_subtype,
            "provider": provider,
            "account": account,
            "account_email": account_email,
            "user": user_name,
            "sync_root": sync_root,
            "local_path": local_path,
            "remote_path": remote_path,
            "cloud_path": cloud_path,
            "item_id": item_id,
            "drive_id": drive_id,
            "resource_id": resource_id,
            "status": status,
            "sync_status": sync_status,
            "hydration_status": hydration_status,
            "pinned": pinned,
            "shared": shared,
            "created_time": created_time,
            "modified_time": modified_time,
            "accessed_time": accessed_time,
            "deleted_time": deleted_time,
            "last_sync_time": last_sync_time,
            "last_upload_time": last_upload_time,
            "last_download_time": last_download_time,
            "direction": direction,
            "confidence": "medium" if event_type in {"cloud_upload", "cloud_download", "cloud_deleted"} else "low",
            "source_file": source_file,
            "parser_status": parser_status,
            "detection_method": detection_method,
            "timestamp_interpretation": timestamp_interpretation,
        }
    )

    document["file"].update(
        {
            "path": file_path,
            "name": file_name,
            "extension": file_extension,
            "created": created_time,
            "modified": modified_time,
            "accessed": accessed_time,
            "deleted": deleted_time,
            "source_path": source_file,
        }
    )
    document["user"]["name"] = document["user"].get("name") or user_name
    document["user"]["sid"] = document["user"].get("sid") or user_sid
    document["network"].update(
        {
            "application": provider,
            "direction": direction if direction != "unknown" else "sync",
            "domain": parsed_url.get("domain"),
        }
    )
    document["url"].update(parsed_url)
    document["host"]["name"] = computer if computer else None

    timestamp_map = [
        ("cloud_deleted_time", deleted_time if event_type == "cloud_deleted" else None),
        ("cloud_last_upload_time", last_upload_time if event_type == "cloud_upload" else None),
        ("cloud_last_download_time", last_download_time if event_type == "cloud_download" else None),
        ("cloud_last_sync_time", last_sync_time),
        ("cloud_modified_time", modified_time),
        ("cloud_created_time", created_time),
        ("source_file_mtime", artifact_meta.get("mtime")),
    ]
    for precision, value in timestamp_map:
        if value:
            document["@timestamp"] = value
            document["timestamp_precision"] = precision
            break
    if not document.get("@timestamp"):
        document["timestamp_precision"] = "unknown"
        document["event"]["timeline_include"] = False
        document["data_quality"] = sorted(set(document.get("data_quality", [])) | {"missing_timestamp"})
    elif document["timestamp_precision"] == "source_file_mtime":
        document["data_quality"] = sorted(set(document.get("data_quality", [])) | {"timestamp_source_file_only"})

    if not local_path:
        document["data_quality"] = sorted(set(document.get("data_quality", [])) | {"missing_local_path"})
    if not remote_path and event_type in {"cloud_upload", "cloud_download", "cloud_deleted"}:
        document["data_quality"] = sorted(set(document.get("data_quality", [])) | {"missing_remote_path"})
    if not account and not account_email:
        document["data_quality"] = sorted(set(document.get("data_quality", [])) | {"missing_account"})
    if not user_name:
        document["data_quality"] = sorted(set(document.get("data_quality", [])) | {"missing_user"})
    if not document["host"].get("name"):
        document["data_quality"] = sorted(set(document.get("data_quality", [])) | {"missing_host"})

    if any(value and "[REDACTED]" in str(value) for value in sanitized_raw.values()) or any(
        token in str(first_nonempty(row, "Raw", "Message", "Details") or "").lower()
        for token in {"token", "password", "secret"}
    ):
        document["data_quality"] = sorted(set(document.get("data_quality", [])) | {"cloud_secret_redacted"})

    document["execution"].update(
        {
            "source": "cloud",
            "is_execution_confirmed": False,
            "confidence": "low",
            "interpretation": "Cloud artifacts indicate synchronization or cloud file state, not program execution by itself",
        }
    )
    document["tags"] = sorted(set(document.get("tags", [])) | tags)
    document["suspicious_reasons"] = sorted(set(document.get("suspicious_reasons", [])) | set(reasons))
    document["risk_score"] = risk
    document["event"]["severity"] = risk_score_to_severity(risk)
    document["raw_summary"] = f"Provider={provider} | Direction={direction} | LocalPath={local_path or '-'} | RemotePath={remote_path or cloud_path or '-'} | Source={source_file}"[:1024]
    document["_preserve_risk_score"] = True
    return document


__all__ = ["normalize_cloud_row"]
