from __future__ import annotations

from app.ingest.artifact_normalizers import first_value
from app.ingest.bits.helpers import (
    basename_windows,
    classify_bits_job,
    extract_bits_notify_process,
    infer_bits_direction,
    infer_bits_user_from_path,
    infer_file_name,
    normalize_bits_download_state,
    normalize_bits_state,
    normalize_bits_type,
    normalize_windows_path,
    parse_bits_url,
    suffix_windows,
)
from app.ingest.identity_extraction import extract_user_from_path


def _coerce_int(value: object) -> int | None:
    if value in (None, ""):
        return None
    try:
        return int(value)
    except Exception:  # noqa: BLE001
        try:
            return int(float(str(value).strip()))
        except Exception:  # noqa: BLE001
            return None


def normalize_bits_row(document: dict, row: dict, artifact_meta: dict) -> dict:
    first = lambda *names: first_value(row, list(names))
    bits = document.setdefault("bits", {})
    file = document.setdefault("file", {})
    process = document.setdefault("process", {})
    url = document.setdefault("url", {})
    download = document.setdefault("download", {})
    network = document.setdefault("network", {})
    persistence = document.setdefault("persistence", {})
    execution = document.setdefault("execution", {})
    user = document.setdefault("user", {})
    velociraptor = document.setdefault("velociraptor", {})
    data_quality = document.setdefault("data_quality", [])

    parser = str(artifact_meta.get("parser") or "").lower()
    source_path = first("SourceFile") or artifact_meta.get("source_path")
    source_format = (
        artifact_meta.get("source_format")
        or ("jsonl" if str(source_path or "").lower().endswith(".jsonl") else "json" if str(source_path or "").lower().endswith(".json") else "txt" if parser == "bitsadmin" else "csv")
    )
    artifact_parser = (
        "bits_jsonl" if source_format == "jsonl"
        else "bits_json" if source_format == "json"
        else "bits_qmgr" if source_format in {"raw_qmgr", "qmgr"}
        else "bits_raw" if source_format == "txt"
        else "bits_csv"
    )
    job_id = first("JobId", "JobID")
    job_guid = first("JobGuid", "JobGUID")
    display_name = first("DisplayName", "JobName", "Name")
    description = first("Description")
    owner = first("Owner", "User")
    owner_sid = first("OwnerSID", "OwnerSid", "SID")
    state = normalize_bits_state(first("State"))
    download_state = normalize_bits_download_state(first("State"))
    job_type = normalize_bits_type(first("Type"))
    remote_url = first("RemoteUrl", "URL", "Url")
    remote_name = first("RemoteName")
    transfer_url = remote_url
    if not transfer_url and str(remote_name or "").lower().startswith(("http://", "https://", "ftp://")):
        transfer_url = remote_name
    local_path = normalize_windows_path(first("LocalPath", "LocalFile", "LocalName", "TargetPath"))
    local_name = first("LocalName") or basename_windows(local_path)
    target_path = local_path or normalize_windows_path(local_name)
    notify_cmd = first("NotifyCmdLine", "NotifyCommandLine")
    notify_executable, notify_arguments = extract_bits_notify_process(notify_cmd)
    parser_status = first("ParserStatus") or artifact_meta.get("velociraptor_parser_status") or "parsed_native"
    url_info = parse_bits_url(transfer_url)
    direction = infer_bits_direction(job_type, transfer_url, target_path)
    file_name = infer_file_name(target_path, transfer_url)
    artifact_subtype = first("ArtifactType") or ("bits_transfer" if remote_url or local_path else "bits_job")

    tags, reasons, risk = classify_bits_job(
        remote_url=remote_url,
        local_path=local_path,
        notify_cmd_line=notify_cmd,
        display_name=display_name,
        description=description,
        owner=owner,
        owner_sid=owner_sid,
        job_type=job_type,
        state=state,
    )

    document["artifact"]["type"] = "bits"
    document["artifact"]["parser"] = artifact_parser
    document["artifact"]["name"] = f"BITS Job - {display_name or job_id or job_guid or file_name or 'job'}"
    document["source_tool"] = artifact_meta.get("source_tool") or "native_bits"
    document["source_format"] = source_format

    timestamp = None
    timestamp_precision = "unknown"
    if first("TransferCompletionTime"):
        timestamp = first("TransferCompletionTime")
        timestamp_precision = "bits_transfer_completion_time"
    elif first("ModificationTime", "LastModificationTime"):
        timestamp = first("ModificationTime", "LastModificationTime")
        timestamp_precision = "bits_modification_time"
    elif first("CreationTime", "JobCreationTime"):
        timestamp = first("CreationTime", "JobCreationTime")
        timestamp_precision = "bits_creation_time"
    document["@timestamp"] = timestamp
    document["timestamp_precision"] = timestamp_precision
    document["timezone"] = "UTC" if timestamp else None

    if direction == "download" and download_state == "complete":
        event_type = "file_downloaded"
        event_action = "bits_transfer_observed"
        event_category = "download"
        message = f"BITS transfer observed: {transfer_url or remote_name or 'unknown'} -> {target_path or local_name or 'unknown'}"
    elif direction == "download" and download_state == "in_progress":
        event_type = "download_started"
        event_action = "bits_transfer_observed"
        event_category = "download"
        message = f"BITS download in progress: {transfer_url or remote_name or 'unknown'} -> {target_path or local_name or 'unknown'}"
    elif direction == "download" and download_state in {"error", "cancelled", "interrupted"}:
        event_type = "download_interrupted"
        event_action = "bits_transfer_observed"
        event_category = "download"
        message = f"BITS transfer interrupted: {transfer_url or remote_name or 'unknown'} -> {target_path or local_name or 'unknown'}"
    else:
        event_type = "bits_job_observed"
        event_action = "bits_transfer_observed"
        event_category = "download"
        message = f"BITS job observed: {display_name or job_id or transfer_url or target_path or 'job'}"
    if notify_cmd:
        message = f"{message} | NotifyCmdLine: {notify_cmd}"

    document["event"].update(
        {
            "category": "network",
            "type": event_type,
            "action": event_action,
            "category": event_category,
            "severity": "high" if risk >= 70 else "medium" if risk >= 40 else "info",
            "timeline_include": True,
            "message": message,
        }
    )

    bits.update(
        {
            "artifact_type": artifact_subtype,
            "job_id": job_id,
            "job_guid": job_guid,
            "display_name": display_name,
            "description": description,
            "owner": owner,
            "owner_sid": owner_sid,
            "state": state,
            "type": job_type,
            "priority": first("Priority"),
            "remote_name": remote_name,
            "remote_url": transfer_url,
            "local_name": local_name,
            "local_path": target_path,
            "file_list": first("FileList"),
            "files_total": _coerce_int(first("FilesTotal")),
            "files_transferred": _coerce_int(first("FilesTransferred")),
            "bytes_total": _coerce_int(first("BytesTotal")),
            "bytes_transferred": _coerce_int(first("BytesTransferred")),
            "creation_time": first("CreationTime", "JobCreationTime"),
            "modification_time": first("ModificationTime", "LastModificationTime"),
            "transfer_completion_time": first("TransferCompletionTime"),
            "expiration_time": first("ExpirationTime"),
            "error_code": first("ErrorCode"),
            "error_description": first("ErrorDescription"),
            "notify_cmd_line": notify_cmd,
            "notify_flags": first("NotifyFlags"),
            "retry_delay": first("RetryDelay"),
            "no_progress_timeout": first("NoProgressTimeout"),
            "minimum_retry_delay": first("MinimumRetryDelay"),
            "source_file": source_path,
            "raw_qmgr_path": first("RawQmgrPath"),
            "parser_status": parser_status,
            "timestamp_interpretation": timestamp_precision,
        }
    )

    url.update(url_info)
    download.update(
        {
            "url": transfer_url,
            "final_url": first("FinalUrl", "FinalURL"),
            "referrer": None,
            "target_path": target_path,
            "file_name": file_name,
            "mime_type": first("MimeType", "ContentType"),
            "total_bytes": _coerce_int(first("BytesTotal")),
            "received_bytes": _coerce_int(first("BytesTransferred")),
            "state": download_state,
        }
    )
    network.update(
        {
            "artifact_type": "bits_job",
            "url": transfer_url,
            "domain": url_info.get("domain"),
            "direction": direction,
            "bytes_sent": _coerce_int(first("BytesTransferred")) if direction == "upload" else None,
            "bytes_received": _coerce_int(first("BytesTransferred")) if direction != "upload" else None,
            "bytes_total": _coerce_int(first("BytesTotal")),
            "application": "bits",
        }
    )
    file.update(
        {
            "path": target_path,
            "name": file_name,
            "extension": suffix_windows(target_path) or suffix_windows(file_name),
            "source_path": source_path,
            "size": _coerce_int(first("BytesTotal")),
        }
    )

    if notify_cmd:
        process.update(
            {
                "name": basename_windows(notify_executable),
                "path": notify_executable,
                "command_line": notify_cmd,
                "application": basename_windows(notify_executable),
            }
        )

    scope = "system" if owner_sid == "S-1-5-18" or str(owner or "").upper() == "SYSTEM" else "user" if owner or owner_sid else "unknown"
    persistence.update(
        {
            "mechanism": "bits_notify_cmd" if notify_cmd else None,
            "location": source_path,
            "name": display_name or job_id or job_guid,
            "command": notify_cmd,
            "path": notify_executable,
            "enabled": None,
            "scope": scope,
            "user": owner,
            "sid": owner_sid,
            "confidence": "high" if notify_cmd else None,
            "source": source_path,
        }
    )
    execution.update(
        {
            "source": "bits",
            "is_execution_confirmed": False,
            "confidence": "low",
            "interpretation": "BITS job indicates configured/background transfer; NotifyCmdLine may indicate deferred execution, but execution is not confirmed by the job alone",
        }
    )

    if owner and not user.get("name"):
        user["name"] = owner
    if owner_sid and not user.get("sid"):
        user["sid"] = owner_sid
    if not user.get("name"):
        user["name"] = (
            infer_bits_user_from_path(local_path)
            or infer_bits_user_from_path(str(source_path or ""))
            or extract_user_from_path(str(source_path or ""))
        )

    if str(artifact_meta.get("source_tool") or "").startswith("velociraptor"):
        velociraptor.update(
            {
                "original_path": artifact_meta.get("velociraptor_original_path") or source_path,
                "normalized_windows_path": artifact_meta.get("velociraptor_normalized_windows_path") or source_path,
                "artifact_category": artifact_meta.get("velociraptor_category") or "bits",
                "parser_status": artifact_meta.get("velociraptor_parser_status") or "parsed",
                "collection_id": artifact_meta.get("velociraptor_collection_id"),
            }
        )

    if not transfer_url and "missing_remote_url" not in data_quality:
        data_quality.append("missing_remote_url")
    if not target_path and "missing_local_path" not in data_quality:
        data_quality.append("missing_local_path")
    if not timestamp and "missing_timestamp" not in data_quality:
        data_quality.append("missing_timestamp")
    if not owner and not owner_sid and "missing_user" not in data_quality:
        data_quality.append("missing_user")
    if "missing_host" not in data_quality:
        data_quality.append("missing_host")
    if "bits_not_execution_proof" not in data_quality:
        data_quality.append("bits_not_execution_proof")
    if "low_confidence_execution" not in data_quality:
        data_quality.append("low_confidence_execution")
    if notify_cmd and "bits_notify_cmd_present" not in data_quality:
        data_quality.append("bits_notify_cmd_present")
    if state == "unknown" and "bits_unknown_state" not in data_quality:
        data_quality.append("bits_unknown_state")
    file_list = bits.get("file_list")
    if isinstance(file_list, str) and any(sep in file_list for sep in ["\n", ";", ","]) and "bits_multiple_files_collapsed" not in data_quality:
        data_quality.append("bits_multiple_files_collapsed")

    document["tags"] = sorted(set(document.get("tags") or []) | tags)
    document["suspicious_reasons"] = sorted(set(document.get("suspicious_reasons") or []) | set(reasons))
    document["risk_score"] = risk
    return document
