from app.ingest.artifact_normalizers import first_value
from app.ingest.powershell.helpers import (
    basename_windows,
    clean_text,
    detect_defender_tampering,
    detect_execution_policy_bypass,
    detect_iex,
    detect_persistence_keywords,
    detect_powershell_download,
    extension_windows,
    extract_domains,
    extract_primary_download_target,
    extract_hashes,
    extract_urls,
    extract_windows_paths,
    infer_user_from_path,
    merge_indicator_text,
    normalize_windows_path,
    parse_powershell_timestamp,
    powershell_suspicion,
    preview_command,
    try_decode_powershell_encoded_command,
)
from app.ingest.normalization.field_quality import normalize_event_fields
from app.ingest.powershell.entity_normalization import normalize_powershell_entities


def normalize_powershell_row(document: dict, row: dict, artifact_meta: dict) -> dict:
    first = lambda *names: first_value(row, list(names))
    powershell = document.setdefault("powershell", {})
    process = document.setdefault("process", {})
    file_data = document.setdefault("file", {})
    user = document.setdefault("user", {})
    url_data = document.setdefault("url", {})
    download = document.setdefault("download", {})
    execution = document.setdefault("execution", {})

    command = clean_text(first("Command", "CommandLine", "ScriptBlockText", "Message", "Payload", "CommandPreview"))
    command_preview = clean_text(first("CommandPreview")) or preview_command(command)
    source_file = clean_text(first("SourceFile")) or artifact_meta.get("source_path")
    file_path = normalize_windows_path(first("FilePath", "Path"))
    parser = str(artifact_meta.get("parser") or "").lower()
    artifact_type = str(artifact_meta.get("powershell_artifact_type") or "").lower()
    if not artifact_type:
        if parser == "psreadline":
            artifact_type = "psreadline_history"
        elif parser == "transcript":
            artifact_type = "powershell_transcript"
        elif parser == "script" or str(artifact_meta.get("source_format") or "").lower() == "ps1":
            artifact_type = "powershell_script"
        else:
            artifact_type = "powershell_command"
    canonical_parser = {
        "psreadline": "powershell_history",
        "powershell_history": "powershell_history",
        "transcript": "powershell_transcript",
        "powershell_transcript": "powershell_transcript",
        "script": "powershell_script",
        "powershell_script": "powershell_script",
        "json": "powershell_json",
        "powershell_json": "powershell_json",
        "jsonl": "powershell_jsonl",
        "powershell_jsonl": "powershell_jsonl",
        "csv": "powershell_csv",
        "powershell_csv": "powershell_csv",
        "evtx": "powershell_evtx",
        "powershell_evtx": "powershell_evtx",
    }.get(parser, "powershell_json" if artifact_type == "powershell_command" else parser or "powershell_json")
    raw_event_id = first("EventID", "EventId")
    try:
        event_id = int(raw_event_id) if raw_event_id not in (None, "") else None
    except Exception:  # noqa: BLE001
        event_id = None
    encoded_command, decoded_preview = try_decode_powershell_encoded_command(command)
    analysis_blob = merge_indicator_text(command, decoded_preview)
    urls = extract_urls(analysis_blob)
    domains = extract_domains(analysis_blob)
    paths = extract_windows_paths(analysis_blob)
    if file_path and file_path not in paths:
        paths.insert(0, file_path)
    tags, reasons, risk = powershell_suspicion(analysis_blob, file_path=file_path, is_script=artifact_type == "powershell_script")
    hashes = extract_hashes(analysis_blob)
    has_download = detect_powershell_download(analysis_blob)
    has_iex = detect_iex(analysis_blob)
    has_execution_policy_bypass = detect_execution_policy_bypass(analysis_blob)
    has_defender_tampering = detect_defender_tampering(analysis_blob)
    has_persistence = detect_persistence_keywords(analysis_blob)

    timestamp = None
    timestamp_precision = "unknown"
    if artifact_type == "powershell_transcript":
        timestamp = (
            parse_powershell_timestamp(first("CommandStartTime"))
            or parse_powershell_timestamp(first("TranscriptStartTime"))
            or parse_powershell_timestamp(first("SourceFileMtime"))
        )
        timestamp_precision = (
            "transcript_command_time" if first("CommandStartTime")
            else "transcript_start_time" if first("TranscriptStartTime")
            else "script_file_mtime" if first("SourceFileMtime")
            else "unknown"
        )
    elif artifact_type == "psreadline_history":
        timestamp = None
        timestamp_precision = "history_line_observed"
    elif artifact_type == "powershell_script":
        timestamp = parse_powershell_timestamp(first("SourceFileMtime"))
        timestamp_precision = "script_file_mtime" if timestamp else "unknown"
    else:
        timestamp = (
            parse_powershell_timestamp(first("TimeCreated"))
            or parse_powershell_timestamp(first("Timestamp"))
            or parse_powershell_timestamp(first("StartTime"))
            or parse_powershell_timestamp(first("SourceFileMtime"))
        )
        timestamp_precision = (
            "event_time" if first("TimeCreated") or first("Timestamp")
            else "transcript_start_time" if first("StartTime")
            else "script_file_mtime" if first("SourceFileMtime")
            else "unknown"
        )
    if timestamp:
        document["@timestamp"] = timestamp
        document["timestamp_precision"] = timestamp_precision
        document["timezone"] = "UTC"

    document["artifact"]["type"] = "powershell"
    document["artifact"]["parser"] = canonical_parser
    document["source_tool"] = artifact_meta.get("source_tool") or "native_powershell"
    document["source_format"] = artifact_meta.get("source_format") or (
        "ps1" if canonical_parser == "powershell_script"
        else "jsonl" if canonical_parser == "powershell_jsonl"
        else "json" if canonical_parser == "powershell_json"
        else "csv" if canonical_parser == "powershell_csv"
        else "evtx" if canonical_parser == "powershell_evtx"
        else "txt"
    )

    is_transcript = artifact_type == "powershell_transcript"
    is_history = artifact_type == "psreadline_history"
    is_script = artifact_type == "powershell_script"
    is_evtx_script_block = event_id == 4104 or canonical_parser == "powershell_evtx" and bool(clean_text(first("ScriptBlockText")))
    message_number = clean_text(first("MessageNumber"))
    message_total = clean_text(first("MessageTotal"))
    if is_evtx_script_block:
        event_type = "script_block"
        event_action = "powershell_script_block_observed"
        message_prefix = "PowerShell script block"
    elif is_transcript:
        event_type = "powershell_transcript"
        event_action = "powershell_transcript_observed"
        message_prefix = "PowerShell transcript command"
    elif is_script:
        event_type = "powershell_script"
        event_action = "powershell_script_file_observed"
        message_prefix = "PowerShell script file observed"
    elif is_history:
        event_type = "powershell_history"
        event_action = "powershell_history_observed"
        message_prefix = "PowerShell history command"
    else:
        event_type = "command_observed"
        event_action = "powershell_command_observed"
        message_prefix = "PowerShell command observed"
    event_message = f"{message_prefix}: {command_preview or 'command observed'}"
    if is_evtx_script_block and (message_number or message_total):
        event_message = f"{message_prefix} {message_number or '?'}/{message_total or '?'}: {command_preview or 'command observed'}"
    document["event"].update(
        {
            "category": "execution",
            "type": event_type,
            "action": event_action,
            "severity": "high" if risk >= 85 else "medium" if risk >= 65 else "low" if risk >= 40 else "info",
            "timeline_include": bool(document.get("@timestamp")) if not is_history else False,
            "message": event_message,
        }
    )

    powershell.update(
        {
            "artifact_type": artifact_type,
            "command": command,
            "command_preview": command_preview,
            "line_number": first("LineNumber"),
            "source_file": source_file,
            "transcript_start_time": parse_powershell_timestamp(first("TranscriptStartTime")),
            "transcript_end_time": parse_powershell_timestamp(first("TranscriptEndTime")),
            "username": clean_text(first("Username")),
            "run_as": clean_text(first("RunAsUser")),
            "machine": clean_text(first("Machine")),
            "host_application": clean_text(first("HostApplication")),
            "process_id": clean_text(first("ProcessId")),
            "ps_version": clean_text(first("PSVersion")),
            "message_number": message_number,
            "message_total": message_total,
            "has_encoded_command": bool(encoded_command),
            "encoded_command": encoded_command,
            "decoded_command_preview": preview_command(decoded_preview, 1024) if decoded_preview else None,
            "has_download": has_download,
            "has_iex": has_iex,
            "has_execution_policy_bypass": has_execution_policy_bypass,
            "has_defender_tampering": has_defender_tampering,
            "has_persistence": has_persistence,
            "urls": urls,
            "domains": domains,
            "paths": paths,
            "indicators": sorted(
                indicator
                for indicator, enabled in {
                    "encoded_command": bool(encoded_command),
                    "download_cradle": has_download,
                    "invoke_expression": has_iex,
                    "execution_policy_bypass": has_execution_policy_bypass,
                    "defender_tampering": has_defender_tampering,
                    "persistence": has_persistence,
                    "recon": "recon" in tags,
                    "credential_access": "credential_access" in tags,
                }.items()
                if enabled
            ),
            "parser_status": "parsed_native",
            "timestamp_interpretation": timestamp_precision,
        }
    )

    inferred_process = None if is_script else ("pwsh.exe" if "pwsh" in (command or "").lower() else "powershell.exe")
    process["name"] = process.get("name") or inferred_process
    process["application"] = "powershell"
    process["command_line"] = command
    if file_path and artifact_type == "powershell_script":
        file_data["path"] = file_path
        file_data["name"] = basename_windows(file_path)
        file_data["extension"] = extension_windows(file_path)
    elif paths:
        process["path"] = process.get("path") or next((path for path in paths if extension_windows(path) in {".exe", ".ps1", ".bat", ".cmd", ".vbs", ".js", ".hta"}), None)
        if process.get("path"):
            file_data["path"] = file_data.get("path") or process["path"]
            file_data["name"] = file_data.get("name") or basename_windows(process["path"])
            file_data["extension"] = file_data.get("extension") or extension_windows(process["path"])
    for field, key in (("md5", "md5"), ("sha1", "sha1"), ("sha256", "sha256"), ("hash_sha1", "sha1"), ("hash_sha256", "sha256")):
        file_data[field] = file_data.get(field) or hashes.get(key)
    if urls:
        first_url = urls[0]
        domain = domains[0] if domains else None
        url_data.update(
            {
                "full": first_url,
                "domain": domain,
                "scheme": first_url.split("://", 1)[0] if "://" in first_url else None,
                "path": "/" + first_url.split("://", 1)[1].split("/", 1)[1] if "://" in first_url and "/" in first_url.split("://", 1)[1] else None,
                "query": first_url.split("?", 1)[1] if "?" in first_url else None,
            }
        )
    download_target = extract_primary_download_target(analysis_blob, paths)
    download_file_name = basename_windows(download_target) or (
        basename_windows(urls[0].split("?", 1)[0]) if urls else None
    )
    if urls or download_target or first("BytesTotal", "BytesTransferred", "State"):
        download.update(
            {
                "url": urls[0] if urls else None,
                "target_path": download_target,
                "file_name": download_file_name,
                "state": clean_text(first("State")),
            }
        )

    if is_transcript or is_evtx_script_block:
        execution_confirmed = True
        execution_confidence = "high"
        execution_interpretation = "PowerShell transcript or Script Block Logging indicates executed/recorded PowerShell activity"
    elif is_history:
        execution_confirmed = False
        execution_confidence = "medium"
        execution_interpretation = "PSReadLine history indicates command was entered or present in user history; execution should be corroborated"
    elif is_script:
        execution_confirmed = False
        execution_confidence = "low"
        execution_interpretation = "PowerShell script file observed; file presence alone does not confirm execution"
    else:
        execution_confirmed = False
        execution_confidence = "medium" if command else "low"
        execution_interpretation = "PowerShell command or event observed; execution confidence depends on source context"
    execution.update(
        {
            "source": "powershell",
            "is_execution_confirmed": execution_confirmed,
            "confidence": execution_confidence,
            "interpretation": execution_interpretation,
        }
    )
    if not user.get("name"):
        user["name"] = clean_text(first("Username")) or infer_user_from_path(source_file) or infer_user_from_path(file_path)
    data_quality = set(document.get("data_quality") or [])
    if not timestamp:
        data_quality.add("missing_timestamp")
    if not user.get("name") and not powershell.get("username") and not powershell.get("run_as"):
        data_quality.add("missing_user")
    if not clean_text(first("Machine")):
        data_quality.add("missing_host")
    if is_history:
        data_quality.update({"powershell_history_not_execution_proof", "low_confidence_execution"})
    elif is_script:
        data_quality.update({"powershell_script_file_not_execution_proof", "low_confidence_execution"})
    elif not execution_confirmed:
        data_quality.add("low_confidence_execution")
    if encoded_command and not decoded_preview:
        data_quality.add("encoded_command_decode_failed")
    if is_script and command and len(command) > 1024:
        data_quality.add("truncated_script_preview")
    document["data_quality"] = sorted(data_quality)
    document["tags"] = sorted(set(document.get("tags") or []) | set(tags) | {"powershell"})
    document["suspicious_reasons"] = sorted(set(document.get("suspicious_reasons") or []) | set(reasons))
    document["risk_score"] = max(int(document.get("risk_score") or 0), risk)
    document["_preserve_risk_score"] = True
    if not timestamp:
        document["timestamp_precision"] = timestamp_precision
    return normalize_event_fields(normalize_powershell_entities(document))
