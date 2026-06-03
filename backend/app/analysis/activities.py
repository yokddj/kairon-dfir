from collections import defaultdict
from datetime import datetime
from pathlib import Path, PureWindowsPath
from uuid import uuid4

from app.analysis.suspicious import detect_suspicious_powershell
from app.ingest.cloud_sync.path_inference import infer_cloud_context
from app.models.forensic_activity import ForensicActivity


def _parse_iso(value: str | None) -> datetime | None:
    if not value:
        return None
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00"))
    except Exception:  # noqa: BLE001
        return None


def _is_powershell_event(event: dict) -> bool:
    process = event.get("process", {}) or {}
    name = str(process.get("name") or "").lower()
    event_type = str((event.get("event", {}) or {}).get("type") or "").lower()
    artifact_type = str((event.get("artifact", {}) or {}).get("type") or "").lower()
    return "powershell" in name or artifact_type == "powershell" or event_type.startswith("powershell_") or event_type in {"script_block", "command_observed"}


def _program_confidence(event: dict) -> float:
    execution = event.get("execution", {}) or {}
    source = str(execution.get("source") or "").lower()
    run_count = execution.get("run_count")
    process_name = (event.get("process", {}) or {}).get("name")
    timestamp = event.get("@timestamp")
    if source == "prefetch":
        if process_name and timestamp and run_count not in (None, "", 0):
            return 0.82
        if process_name and timestamp:
            return 0.72
        return 0.6
    return 0.78


def _execution_artifact_confidence(event: dict) -> float:
    execution = event.get("execution", {}) or {}
    label = str(execution.get("confidence") or "").lower()
    if label == "high":
        return 0.9
    if label == "medium":
        return 0.68
    if label == "low":
        return 0.45
    return 0.52


def _srum_confidence(event: dict) -> float:
    tags = set(event.get("tags") or [])
    if "high_upload" in tags and {"remote_access_tool", "file_transfer_tool", "lolbin_network"} & tags:
        return 0.9
    if "high_upload" in tags or "possible_exfiltration" in tags:
        return 0.76
    if {"remote_access_tool", "file_transfer_tool", "lolbin_network"} & tags:
        return 0.72
    return 0.6


def _defender_confidence(event: dict) -> float:
    detection = event.get("detection", {}) or {}
    severity = str(detection.get("severity") or "").lower()
    action = str(detection.get("action") or "").lower()
    if severity in {"severe", "critical", "high"}:
        return 0.95
    if "quarantine" in action or "removed" in action or "blocked" in action:
        return 0.88
    if "failed" in action:
        return 0.9
    return 0.78


def _normalized_name(value: object | None) -> str:
    if value in (None, ""):
        return ""
    text = str(value).strip().lower()
    return text


def _display_file_target(event: dict) -> str:
    file_data = event.get("file", {}) or {}
    lnk = event.get("lnk", {}) or {}
    jumplist = event.get("jumplist", {}) or {}
    return str(
        file_data.get("path")
        or jumplist.get("effective_path")
        or lnk.get("effective_path")
        or jumplist.get("display_name")
        or lnk.get("display_name")
        or file_data.get("name")
        or "LNK target"
    )


def _display_filesystem_target(event: dict) -> str:
    file_data = event.get("file", {}) or {}
    mft = event.get("mft", {}) or {}
    return str(
        file_data.get("path")
        or mft.get("full_path")
        or file_data.get("name")
        or mft.get("file_name")
        or "Filesystem target"
    )


def _display_browser_target(event: dict) -> str:
    browser = event.get("browser", {}) or {}
    download = event.get("download", {}) or {}
    file_data = event.get("file", {}) or {}
    url = event.get("url", {}) or {}
    return str(
        file_data.get("path")
        or download.get("target_path")
        or browser.get("title")
        or browser.get("search_terms")
        or url.get("full")
        or browser.get("url")
        or "Browser target"
    )


def _extract_drive_letter_from_path(path: str | None) -> str | None:
    if not path:
        return None
    match = __import__("re").search(r"(?<![A-Z])([A-Z]:)(?:\\|$)", str(path), __import__("re").IGNORECASE)
    return match.group(1).upper() if match else None


def _extract_drive_letters_from_text(value: str | None) -> list[str]:
    if not value:
        return []
    return [match.upper() for match in __import__("re").findall(r"([A-Z]:)(?:\\|/)", str(value), __import__("re").IGNORECASE)]


def _normalized_windows_parent(path: str | None) -> str:
    if not path:
        return ""
    try:
        return str(PureWindowsPath(str(path)).parent).replace("/", "\\").lower()
    except Exception:  # noqa: BLE001
        return ""


def _cloud_context_for_values(*values: object, command_line: str | None = None) -> dict | None:
    for value in values:
        if value in (None, ""):
            continue
        context = infer_cloud_context(str(value), command_line=command_line)
        if context.get("provider") and context.get("sync_root"):
            return context
    if command_line:
        context = infer_cloud_context(None, command_line=command_line)
        if context.get("provider") and context.get("sync_root"):
            return context
    return None


def event_to_activity(event: dict) -> list[ForensicActivity]:
    meta = event.get("event", {}) or {}
    event_type = str(meta.get("type") or "unknown")
    timestamp = event.get("@timestamp")
    artifact = event.get("artifact", {}) or {}
    process = event.get("process", {}) or {}
    file = event.get("file", {}) or {}
    network = event.get("network", {}) or {}
    service = event.get("service", {}) or {}
    task = event.get("task", {}) or {}
    detection = event.get("detection", {}) or {}
    recycle = event.get("recycle", {}) or {}
    host = (event.get("host", {}) or {}).get("name")
    user = (event.get("user", {}) or {}).get("name")
    suspicious_reasons = list(event.get("suspicious_reasons") or [])
    activities: list[ForensicActivity] = []
    windows = event.get("windows", {}) or {}
    source = event.get("source", {}) or {}
    registry = event.get("registry", {}) or {}
    volume = event.get("volume", {}) or {}
    usb = event.get("usb", {}) or {}
    shellbag = event.get("shellbag", {}) or {}

    evidence_refs = [
        rendered
        for rendered in [
            f"doc:{event.get('id')}" if event.get("id") else None,
            f"event:{event.get('event_id')}" if event.get("event_id") else None,
            f"evidence:{event.get('evidence_id')}" if event.get("evidence_id") else None,
            f"artifact:{event.get('artifact_id')}" if event.get("artifact_id") else None,
            f"source_file:{event.get('source_file')}" if event.get("source_file") else None,
            f"record:{windows.get('record_number')}" if windows.get("record_number") else None,
            f"windows_event_id:{windows.get('event_id')}" if windows.get("event_id") is not None else None,
            f"channel:{windows.get('channel')}" if windows.get("channel") else None,
            f"provider:{windows.get('provider')}" if windows.get("provider") else None,
        ]
        if rendered
    ]

    def make(activity_type: str, title: str, summary: str, key_fields: dict, confidence: float = 0.75) -> None:
        activities.append(
            ForensicActivity(
                id=str(uuid4()),
                activity_type=activity_type,
                title=title,
                timestamp=timestamp,
                host=host,
                user=user,
                summary=summary,
                severity=str(meta.get("severity") or "info"),
                confidence=confidence,
                tags=list(event.get("tags") or []),
                key_fields=key_fields,
                evidence_refs=evidence_refs,
                related_events=[event.get("event_id")] if event.get("event_id") else [],
                suspicious_reasons=suspicious_reasons,
            )
        )

    if event_type in {"process_start", "process_creation", "program_execution", "process_executed"}:
        execution = event.get("execution", {}) or {}
        base_key_fields = {
            "process_name": process.get("name"),
            "process_path": process.get("path"),
            "command_line": process.get("command_line"),
            "parent_process": process.get("parent_name"),
            "source": execution.get("source"),
            "run_count": execution.get("run_count"),
            "last_run": execution.get("last_run"),
            "previous_runs_count": len(execution.get("last_runs") or []),
            "confidence_label": execution.get("confidence"),
        }
        program_summary = str(process.get("command_line") or process.get("path") or meta.get("message") or "Program execution")
        make(
            "program_execution",
            process.get("name") or "Program execution",
            program_summary,
            base_key_fields,
            confidence=_program_confidence(event),
        )
        cloud_context = _cloud_context_for_values(process.get("path"), file.get("path"), command_line=str(process.get("command_line") or ""))
        if cloud_context and str(process.get("path") or file.get("path") or "").lower().endswith((".exe", ".dll", ".ps1", ".bat", ".cmd", ".js", ".vbs", ".hta", ".msi", ".scr")):
            make(
                "executable_from_cloud",
                process.get("name") or "Executable from cloud",
                "Executable or script path is inside a cloud sync folder.",
                {
                    **base_key_fields,
                    "provider": cloud_context.get("provider"),
                    "sync_root": cloud_context.get("sync_root"),
                },
                confidence=max(_program_confidence(event), 0.82),
            )
        if _is_powershell_event(event):
            script_text = str(
                process.get("command_line")
                or (event.get("powershell", {}) or {}).get("script_block_text")
                or (event.get("windows", {}) or {}).get("event_data", {}).get("ScriptBlockText")
                or meta.get("message")
                or ""
            )
            suspicious = detect_suspicious_powershell(script_text)
            ps_summary = (
                "PowerShell execution observed via Prefetch"
                if str(execution.get("source") or "").lower() == "prefetch"
                else script_text or str(meta.get("message") or "PowerShell activity")
            )
            make(
                "powershell_execution",
                process.get("name") or "PowerShell execution",
                ps_summary,
                {
                    **base_key_fields,
                    "script_block_id": (event.get("powershell", {}) or {}).get("script_block_id"),
                    "host_application": (event.get("windows", {}) or {}).get("event_data", {}).get("HostApplication"),
                },
                confidence=0.9 if suspicious else max(_program_confidence(event), 0.78),
            )
            cloud_context = _cloud_context_for_values(
                *(((event.get("powershell", {}) or {}).get("paths") or [])),
                file.get("path"),
                command_line=script_text,
            )
            if cloud_context and any(token in script_text.lower() for token in ["copy-item", "move-item", "copy ", "xcopy", "robocopy", "compress-archive", "7z", "rar ", " tar "]):
                make(
                    "copied_to_cloud",
                    process.get("name") or "Copy to cloud folder",
                    "PowerShell/copy command references a cloud sync folder.",
                    {
                        **base_key_fields,
                        "provider": cloud_context.get("provider"),
                        "sync_root": cloud_context.get("sync_root"),
                    },
                    confidence=0.86,
                )
    elif event_type in {"powershell_script_block", "powershell_script_block_start", "powershell_script_block_stop", "powershell_module_logging", "powershell_pipeline_execution", "powershell_engine_start", "script_block"}:
        event_data = (event.get("windows", {}) or {}).get("event_data", {}) or {}
        script_text = str(event_data.get("ScriptBlockText") or process.get("command_line") or meta.get("message") or "")
        suspicious = detect_suspicious_powershell(script_text)
        make(
            "powershell_execution",
            "PowerShell activity",
            script_text or str(meta.get("message") or "PowerShell activity"),
            {
                "process_name": process.get("name"),
                "process_path": process.get("path"),
                "command_line": process.get("command_line"),
                "script_block_id": event_data.get("ScriptBlockId"),
                "host_application": event_data.get("HostApplication"),
            },
            confidence=0.9 if suspicious else 0.8,
        )
        cloud_context = _cloud_context_for_values(
            *(((event.get("powershell", {}) or {}).get("paths") or [])),
            command_line=script_text,
        )
        if cloud_context and any(token in script_text.lower() for token in ["copy-item", "move-item", "copy ", "xcopy", "robocopy", "compress-archive", "7z", "rar ", " tar "]):
            make(
                "copied_to_cloud",
                "PowerShell copy to cloud folder",
                "PowerShell command references a cloud sync folder.",
                {
                    "command_line": process.get("command_line"),
                    "provider": cloud_context.get("provider"),
                    "sync_root": cloud_context.get("sync_root"),
                    "source": "powershell",
                },
                confidence=0.86,
            )
    elif event_type in {"powershell_console_history", "powershell_transcript_command", "powershell_script_file_observed", "powershell_history", "powershell_transcript", "powershell_script", "command_observed"}:
        powershell = event.get("powershell", {}) or {}
        artifact = event.get("artifact", {}) or {}
        command = str(powershell.get("command") or process.get("command_line") or meta.get("message") or "")
        key_fields = {
            "process_name": process.get("name"),
            "process_path": process.get("path"),
            "command_line": command,
            "command_preview": powershell.get("command_preview"),
            "decoded_command_preview": powershell.get("decoded_command_preview"),
            "artifact_type": powershell.get("artifact_type"),
            "line_number": powershell.get("line_number"),
            "source": artifact.get("parser") or artifact.get("type"),
            "source_file": powershell.get("source_file") or event.get("source_file"),
            "url": ((powershell.get("urls") or [None])[0]),
            "domain": ((powershell.get("domains") or [None])[0]),
            "paths": powershell.get("paths"),
            "indicators": powershell.get("indicators"),
            "host_application": powershell.get("host_application"),
            "transcript_user": powershell.get("username"),
            "run_as": powershell.get("run_as"),
        }
        base_confidence = (
            0.88 if event_type == "powershell_transcript"
            else 0.7 if event_type == "powershell_transcript_command"
            else 0.6 if event_type in {"powershell_console_history", "powershell_history", "command_observed"}
            else 0.42
        )
        if powershell.get("has_encoded_command") or powershell.get("has_defender_tampering"):
            base_confidence = max(base_confidence, 0.82)
        make(
            "powershell_execution",
            "PowerShell activity",
            str(meta.get("message") or powershell.get("command_preview") or command or "PowerShell activity"),
            key_fields,
            confidence=base_confidence,
        )
        if powershell.get("has_download"):
            make(
                "powershell_download",
                "PowerShell download",
                str(meta.get("message") or powershell.get("command_preview") or command or "PowerShell download"),
                key_fields,
                confidence=max(base_confidence, 0.76),
            )
        if powershell.get("has_encoded_command"):
            make(
                "powershell_encoded_execution",
                "PowerShell encoded command",
                str(meta.get("message") or powershell.get("command_preview") or command or "PowerShell encoded command"),
                key_fields,
                confidence=max(base_confidence, 0.85),
            )
        if powershell.get("has_defender_tampering"):
            make(
                "powershell_defender_tampering",
                "PowerShell Defender tampering",
                str(meta.get("message") or powershell.get("command_preview") or command or "PowerShell Defender tampering"),
                key_fields,
                confidence=max(base_confidence, 0.9),
            )
        if powershell.get("has_persistence"):
            make(
                "powershell_persistence",
                "PowerShell persistence command",
                str(meta.get("message") or powershell.get("command_preview") or command or "PowerShell persistence command"),
                key_fields,
                confidence=max(base_confidence, 0.8),
            )
        if "recon" in set(event.get("tags") or []):
            make(
                "powershell_recon",
                "PowerShell reconnaissance",
                str(meta.get("message") or powershell.get("command_preview") or command or "PowerShell reconnaissance"),
                key_fields,
                confidence=max(base_confidence, 0.62),
            )
        if "credential_access" in set(event.get("tags") or []):
            make(
                "powershell_credential_access",
                "PowerShell credential access",
                str(meta.get("message") or powershell.get("command_preview") or command or "PowerShell credential access"),
                key_fields,
                confidence=max(base_confidence, 0.88),
            )
        cloud_context = _cloud_context_for_values(
            *(((powershell.get("paths") or []))),
            file.get("path"),
            command_line=command,
        )
        if cloud_context and any(token in command.lower() for token in ["copy-item", "move-item", "copy ", "xcopy", "robocopy", "compress-archive", "7z", "rar ", " tar "]):
            make(
                "copied_to_cloud",
                process.get("name") or "Copy to cloud folder",
                "PowerShell/copy command references a cloud sync folder.",
                {
                    **key_fields,
                    "provider": cloud_context.get("provider"),
                    "sync_root": cloud_context.get("sync_root"),
                },
                confidence=0.86,
            )
    elif (
        str((event.get("artifact") or {}).get("type") or "") in {"recycle_bin", "recycle"}
        and (
            event_type in {"file_recycled", "file_deleted", "recycle_metadata_observed"}
            or str(meta.get("action") or "") in {"recycle_bin_deleted", "recycle_metadata_observed"}
            or "recycle_bin" in set(event.get("tags") or [])
        )
    ):
        key_fields = {
            "file_path": recycle.get("original_path") or file.get("path"),
            "file_name": recycle.get("original_file_name") or file.get("name"),
            "file_size": recycle.get("original_size") or file.get("size"),
            "deleted_time": recycle.get("deleted_time") or file.get("deleted_time"),
            "sid": recycle.get("sid"),
            "user": recycle.get("user"),
            "has_content_file": recycle.get("has_r_file"),
            "i_file_path": recycle.get("i_file_path"),
            "r_file_path": recycle.get("r_file_path"),
            "pair_id": recycle.get("pair_id"),
            "artifact_type": recycle.get("artifact_type"),
            "source": "recycle_bin",
        }
        if key_fields["file_path"] or event_type in {"file_recycled", "file_deleted"} or str(meta.get("action") or "") == "recycle_bin_deleted":
            make(
                "file_recycled",
                recycle.get("original_file_name") or file.get("name") or "Recycle Bin item",
                str(meta.get("message") or recycle.get("original_path") or file.get("path") or "File moved to Recycle Bin"),
                key_fields,
                confidence=0.78 if key_fields["deleted_time"] else 0.62,
            )
        cloud_context = _cloud_context_for_values(recycle.get("original_path") or file.get("path"))
        if cloud_context:
            make(
                "deleted_from_cloud",
                recycle.get("original_file_name") or file.get("name") or "Deleted cloud file",
                "File deleted from cloud sync folder after activity.",
                {
                    **key_fields,
                    "provider": cloud_context.get("provider"),
                    "sync_root": cloud_context.get("sync_root"),
                },
                confidence=0.8,
            )
        extension = _normalized_name(file.get("extension"))
        if extension in {".exe", ".dll", ".scr", ".msi"}:
            make(
                "deleted_executable",
                recycle.get("original_file_name") or file.get("name") or "Deleted executable",
                str(meta.get("message") or recycle.get("original_path") or file.get("path") or "Executable moved to Recycle Bin"),
                key_fields,
                confidence=0.82,
            )
        if extension in {".ps1", ".bat", ".cmd", ".vbs", ".js", ".jse", ".wsf", ".hta"}:
            make(
                "deleted_script",
                recycle.get("original_file_name") or file.get("name") or "Deleted script",
                str(meta.get("message") or recycle.get("original_path") or file.get("path") or "Script moved to Recycle Bin"),
                key_fields,
                confidence=0.82,
            )
        if recycle.get("has_r_file") is False:
            make(
                "cleanup_candidate",
                recycle.get("original_file_name") or file.get("name") or "Recycle Bin cleanup candidate",
                str(meta.get("message") or recycle.get("original_path") or file.get("path") or "Recycle metadata observed without recycled content"),
                key_fields,
                confidence=0.72,
            )
    elif event_type == "scheduled_task_created":
        make("scheduled_task_created", task.get("name") or "Scheduled task created", str(meta.get("message") or task.get("command") or "Scheduled task created"), {"task_name": task.get("name"), "command": task.get("command"), "arguments": task.get("arguments")})
    elif event_type == "scheduled_task_updated":
        make("scheduled_task_updated", task.get("name") or "Scheduled task updated", str(meta.get("message") or task.get("command") or "Scheduled task updated"), {"task_name": task.get("name"), "command": task.get("command"), "arguments": task.get("arguments")})
    elif event_type in {"scheduled_task_definition", "scheduled_task_com_handler", "scheduled_task"}:
        key_fields = {
            "task_name": task.get("name"),
            "task_path": task.get("path"),
            "task_uri": task.get("uri"),
            "command": task.get("command"),
            "arguments": task.get("arguments"),
            "working_directory": task.get("working_directory"),
            "author": task.get("author"),
            "run_as": task.get("run_as"),
            "enabled": task.get("enabled"),
            "hidden": task.get("hidden"),
            "trigger_summary": task.get("trigger_summary"),
            "action_summary": task.get("action_summary"),
            "com_handler_class_id": task.get("com_handler_class_id"),
            "source": "scheduled_task",
        }
        make(
            "scheduled_task" if event_type == "scheduled_task" else event_type,
            task.get("name") or "Scheduled task observed",
            str(meta.get("message") or task.get("action_summary") or task.get("command") or "Scheduled task definition observed"),
            key_fields,
            confidence=0.7 if task.get("enabled") else 0.58,
        )
        if "suspicious" in set(event.get("tags") or []):
            make(
                "suspicious_task",
                task.get("name") or "Suspicious scheduled task",
                str(meta.get("message") or task.get("action_summary") or task.get("command") or "Suspicious scheduled task"),
                key_fields,
                confidence=0.86 if {"encoded_command", "unc_path", "com_handler"} & set(event.get("tags") or []) else 0.74,
            )
    elif event_type == "service_created":
        make("service_created", service.get("name") or "Service created", str(meta.get("message") or service.get("image_path") or "Service created"), {"service_name": service.get("name"), "image_path": service.get("image_path"), "account": service.get("account"), "start_type": service.get("start_type")})
    elif event_type == "service_start_type_changed":
        make("service_modified", service.get("name") or "Service modified", str(meta.get("message") or service.get("image_path") or "Service modified"), {"service_name": service.get("name"), "image_path": service.get("image_path"), "account": service.get("account"), "start_type": service.get("start_type")})
    elif event_type == "network_connection_allowed":
        make("network_connection", process.get("name") or "Network connection", str(meta.get("message") or f"{network.get('source_ip')} -> {network.get('destination_ip')}"), {"source_ip": network.get("source_ip"), "source_port": network.get("source_port"), "destination_ip": network.get("destination_ip"), "destination_port": network.get("destination_port"), "protocol": network.get("protocol"), "application": network.get("application")})
    elif event_type in {"network_share_access", "network_share_object_access"}:
        make(
            "network_connection",
            process.get("name") or "Share access",
            str(meta.get("message") or "Share access"),
            {
                "source_ip": source.get("ip"),
                "share_name": network.get("share_name"),
                "share_local_path": network.get("share_local_path"),
                "relative_target_name": network.get("relative_target_name"),
            },
            confidence=0.8,
        )
    elif event_type == "logon_success":
        activity_type = "rdp_logon" if str(windows.get("logon_type") or "") == "10" else "logon_success"
        make(activity_type, user or "Successful logon", str(meta.get("message") or "Logon success"), {"logon_type": windows.get("logon_type"), "source_ip": source.get("ip"), "workstation": windows.get("event_data", {}).get("WorkstationName")})
    elif event_type == "logon_failed":
        make("logon_failed", user or "Failed logon", str(meta.get("message") or "Logon failed"), {"logon_type": windows.get("logon_type"), "source_ip": source.get("ip"), "workstation": windows.get("event_data", {}).get("WorkstationName")})
    elif event_type in {"rdp_authentication_success", "rdp_session_logon", "rdp_session_reconnected"}:
        make("rdp_logon", user or "RDP activity", str(meta.get("message") or "RDP activity"), {"source_ip": source.get("ip"), "session_id": windows.get("session_id"), "session_name": windows.get("session_name")})
    elif event_type in {"rdp_session_disconnected", "rdp_session_logoff", "rdp_session_disconnected_by_session", "rdp_session_reconnection_or_disconnect_reason"}:
        make("rdp_disconnect", user or "RDP disconnect", str(meta.get("message") or "RDP disconnect"), {"source_ip": source.get("ip"), "session_id": windows.get("session_id"), "reason": windows.get("reason")})
    elif event_type in {"defender_malware_detected", "defender_detection", "malware_detected", "security_detection", "suspicious_behavior"}:
        make("defender_detection", detection.get("threat_name") or "Defender detection", str(meta.get("message") or detection.get("path") or "Defender detection"), {"threat_name": detection.get("threat_name"), "path": detection.get("path"), "action": detection.get("action"), "severity": detection.get("severity")}, confidence=0.95)
        cloud_context = _cloud_context_for_values(detection.get("path") or file.get("path"))
        if cloud_context:
            make(
                "defender_detection_in_cloud",
                detection.get("threat_name") or "Defender detection in cloud folder",
                "Defender detection occurred inside a cloud sync folder.",
                {
                    "provider": cloud_context.get("provider"),
                    "sync_root": cloud_context.get("sync_root"),
                    "path": detection.get("path") or file.get("path"),
                    "threat_name": detection.get("threat_name"),
                },
                confidence=0.9,
            )
    elif event_type in {"defender_action_taken", "defender_action_failed", "defender_remediation_critical", "defender_configuration_changed", "defender_log_observed", "remediation", "configuration_change", "tamper_protection"}:
        make("defender_action", detection.get("threat_name") or "Defender action", str(meta.get("message") or detection.get("action") or "Defender action"), {"threat_name": detection.get("threat_name"), "path": detection.get("path"), "action": detection.get("action"), "severity": detection.get("severity")}, confidence=0.9)
    elif event_type in {
        "threat_detected",
        "threat_blocked",
        "threat_quarantined",
        "threat_removed",
        "threat_allowed",
        "remediation_started",
        "remediation_completed",
        "remediation_failed",
        "scan_started",
        "scan_completed",
        "defender_observed",
    }:
        key_fields = {
            "threat_name": detection.get("threat_name"),
            "threat_id": detection.get("threat_id"),
            "path": detection.get("path") or file.get("path"),
            "resource": detection.get("resource"),
            "action": detection.get("action") or meta.get("action"),
            "status": detection.get("status"),
            "severity": detection.get("severity"),
            "category": detection.get("category"),
            "user_sid": detection.get("user_sid") or user.get("sid"),
            "source": "defender",
        }
        activity_type = "defender_detection" if event_type.startswith("threat_") else "defender_action"
        make(
            activity_type,
            detection.get("threat_name") or "Defender event",
            str(meta.get("message") or detection.get("resource") or detection.get("path") or "Defender event"),
            key_fields,
            confidence=_defender_confidence(event),
        )
        cloud_context = _cloud_context_for_values(detection.get("path") or file.get("path"))
        if cloud_context:
            make(
                "defender_detection_in_cloud",
                detection.get("threat_name") or "Defender event in cloud folder",
                "Defender event references a file inside a cloud sync folder.",
                {
                    "provider": cloud_context.get("provider"),
                    "sync_root": cloud_context.get("sync_root"),
                    "path": detection.get("path") or file.get("path"),
                    "threat_name": detection.get("threat_name"),
                },
                confidence=max(_defender_confidence(event), 0.88),
            )
    elif event_type == "audit_log_cleared":
        make("audit_log_cleared", "Audit log cleared", str(meta.get("message") or "Audit log cleared"), {}, confidence=0.95)
    elif event_type == "user_created":
        make("account_created", user or "Account created", str(meta.get("message") or "Account created"), {})
    elif event_type == "user_modified":
        make("account_modified", user or "Account modified", str(meta.get("message") or "Account modified"), {})
    elif event_type == "user_deleted":
        make("account_deleted", user or "Account deleted", str(meta.get("message") or "Account deleted"), {})
    elif event_type == "user_added_to_group":
        make("user_added_to_group", user or "User added to group", str(meta.get("message") or "User added to group"), {})
    elif event_type == "account_locked_out":
        make("account_locked_out", user or "Account locked out", str(meta.get("message") or "Account locked out"), {}, confidence=0.9)
    elif event_type in {"service_state_changed", "service_start_type_changed"}:
        make("service_modified", service.get("name") or "Service updated", str(meta.get("message") or "Service updated"), {"service_name": service.get("name"), "image_path": service.get("image_path"), "start_type": service.get("start_type")})
    elif event_type in {"scheduled_task_registered", "scheduled_task_deleted", "scheduled_task_action_started", "scheduled_task_action_completed", "scheduled_task_launch_failed"}:
        mapped_activity = {
            "scheduled_task_registered": "scheduled_task_created",
            "scheduled_task_deleted": "scheduled_task_deleted",
            "scheduled_task_action_started": "scheduled_task_action_started",
            "scheduled_task_action_completed": "scheduled_task_action_completed",
            "scheduled_task_launch_failed": "scheduled_task_launch_failed",
        }[event_type]
        make(mapped_activity, task.get("name") or "Scheduled task activity", str(meta.get("message") or "Scheduled task activity"), {"task_name": task.get("name"), "command": task.get("command"), "arguments": task.get("arguments")})
    elif event_type == "winrm_activity":
        winrm = event.get("winrm", {}) or {}
        make("rdp_logon", user or "WinRM activity", str(meta.get("message") or "WinRM activity"), {"source_ip": source.get("ip"), "resource_uri": winrm.get("resource_uri"), "operation": winrm.get("operation")}, confidence=0.8)
    elif event_type in {"wmi_persistence_or_consumer", "wmi_persistence_or_filter", "wmi_persistence_or_binding"}:
        make("persistence", "WMI persistence", str(meta.get("message") or "WMI persistence"), {"operation": windows.get("event_data", {}).get("Operation"), "namespace": windows.get("event_data", {}).get("Namespace")}, confidence=0.9)
    elif event_type in {
        "autorun_entry",
        "autorun",
        "run_key_persistence",
        "runonce_persistence",
        "startup_folder_persistence",
        "service_persistence",
        "driver_persistence",
        "scheduled_task_persistence",
        "wmi_persistence",
        "winlogon_persistence",
        "ifeo_debugger_persistence",
        "appinit_dll_persistence",
        "appcert_dll_persistence",
        "lsa_provider_persistence",
        "print_monitor_persistence",
        "shell_extension_persistence",
        "office_addin_persistence",
    }:
        autoruns = event.get("autoruns", {}) or {}
        persistence = event.get("persistence", {}) or {}
        key_fields = {
            "type": persistence.get("mechanism") or autoruns.get("artifact_type"),
            "mechanism": persistence.get("mechanism"),
            "location": persistence.get("location") or autoruns.get("entry_location"),
            "name": persistence.get("name") or autoruns.get("entry"),
            "enabled": persistence.get("enabled") if persistence.get("enabled") is not None else autoruns.get("enabled"),
            "command": persistence.get("command") or autoruns.get("command_line") or process.get("command_line"),
            "path": persistence.get("path") or autoruns.get("image_path") or process.get("path") or file.get("path"),
            "publisher": autoruns.get("publisher"),
            "signer": autoruns.get("signer"),
            "signed": autoruns.get("signed"),
            "verified": autoruns.get("verified"),
            "vt_detection": autoruns.get("vt_detection"),
            "user": persistence.get("user") or autoruns.get("user") or user,
            "profile": autoruns.get("profile"),
            "entry_location": autoruns.get("entry_location"),
            "entry": autoruns.get("entry"),
            "image_path": autoruns.get("image_path"),
            "launch_string": autoruns.get("launch_string"),
            "hash_sha1": autoruns.get("hash_sha1"),
            "hash_sha256": autoruns.get("hash_sha256"),
            "service_name": service.get("name") or autoruns.get("entry"),
            "task_name": task.get("name") or autoruns.get("entry"),
            "consumer_name": (event.get("wmi", {}) or {}).get("consumer_name"),
            "source": event.get("source_tool") or "autoruns",
        }
        confidence = 0.88 if suspicious_reasons else 0.68
        make(
            "autorun_entry",
            str(persistence.get("name") or autoruns.get("entry") or persistence.get("mechanism") or "Autorun entry"),
            str(meta.get("message") or autoruns.get("launch_string") or autoruns.get("image_path") or "Autorun entry observed"),
            key_fields,
            confidence=confidence,
        )
        if suspicious_reasons or any(tag in (event.get("tags") or []) for tag in {"suspicious_autorun", "lolbin", "user_writable_path", "encoded_powershell", "download_command"}):
            make(
                "suspicious_autorun",
                str(persistence.get("name") or autoruns.get("entry") or "Suspicious autorun"),
                str(meta.get("message") or autoruns.get("launch_string") or autoruns.get("image_path") or "Potential persistence abuse"),
                key_fields,
                confidence=max(confidence, 0.82),
            )
        cloud_context = _cloud_context_for_values(persistence.get("path") or autoruns.get("image_path"))
        if cloud_context:
            make(
                "persistence_target_in_cloud",
                str(persistence.get("name") or autoruns.get("entry") or "Persistence target in cloud"),
                "Persistence entry points to a file inside a cloud sync folder.",
                {
                    **key_fields,
                    "provider": cloud_context.get("provider"),
                    "sync_root": cloud_context.get("sync_root"),
                },
                confidence=0.84,
            )
    elif event_type == "registry_run_key":
        make(
            "persistence",
            registry.get("value_name") or "Run key persistence",
            str(meta.get("message") or "Run key persistence"),
            {
                "type": "run_key",
                "name": registry.get("value_name"),
                "key_path": registry.get("key_path"),
                "value_name": registry.get("value_name"),
                "command": process.get("command_line"),
                "path": process.get("path"),
                "source": "recmd",
            },
            confidence=0.9 if suspicious_reasons else 0.78,
        )
    elif event_type in {"registry_service", "service"}:
        make(
            "service_modified",
            service.get("name") or "Registry service",
            str(meta.get("message") or "Registry service"),
            {
                "service_name": service.get("name"),
                "image_path": service.get("image_path"),
                "service_dll": service.get("service_dll"),
                "start_type": service.get("start_type"),
                "account": service.get("account") or service.get("object_name"),
                "key_path": registry.get("key_path"),
                "source": event.get("source_tool") or "recmd",
            },
            confidence=0.88 if suspicious_reasons else 0.76,
        )
    elif event_type in {"userassist_execution", "bam_execution", "dam_execution", "muicache_entry", "run_mru_command"}:
        execution = event.get("execution", {}) or {}
        base_key_fields = {
            "process_name": process.get("name"),
            "process_path": process.get("path"),
            "command_line": process.get("command_line"),
            "source": execution.get("source") or registry.get("artifact_type"),
            "run_count": execution.get("run_count"),
            "last_run": execution.get("last_run"),
            "confidence_label": execution.get("confidence"),
            "registry_key": registry.get("key_path"),
        }
        make(
            "program_execution",
            process.get("name") or registry.get("artifact_type") or "Registry execution",
            str(meta.get("message") or process.get("command_line") or process.get("path") or "Registry execution"),
            base_key_fields,
            confidence=0.72 if event_type == "muicache_entry" else 0.84,
        )
        command_blob = str(process.get("command_line") or process.get("path") or meta.get("message") or "")
        if "powershell" in command_blob.lower() or "pwsh" in command_blob.lower():
            make(
                "powershell_execution",
                process.get("name") or "PowerShell execution",
                str(meta.get("message") or command_blob or "PowerShell activity"),
                base_key_fields,
                confidence=0.88,
            )
    elif event_type in {"typed_path", "recent_document", "shellbag_folder_access"}:
        display_target = str((event.get("file", {}) or {}).get("path") or shellbag.get("path") or registry.get("value_data") or registry.get("value_name") or "Registry target")
        display_name = str((event.get("file", {}) or {}).get("name") or Path(display_target).name or "Registry target")
        base_key_fields = {
            "file_path": (event.get("file", {}) or {}).get("path") or shellbag.get("path"),
            "extension": (event.get("file", {}) or {}).get("extension"),
            "source": "recmd",
            "key_path": registry.get("key_path"),
            "value_name": registry.get("value_name"),
            "network_path": (event.get("network", {}) or {}).get("path"),
            "volume_serial": volume.get("serial"),
            "document_like": event_type == "recent_document",
        }
        title_prefix = {
            "typed_path": "Typed path",
            "recent_document": "Recent document",
            "shellbag_folder_access": "Shellbag folder",
        }[event_type]
        make(
            "opened_file",
            f"{title_prefix}: {display_name}",
            str(meta.get("message") or display_target),
            base_key_fields,
            confidence=0.76 if event.get("@timestamp") else 0.62,
        )
        if event_type == "shellbag_folder_access":
            make(
                "user_activity",
                f"Shellbag: {display_name}",
                str(meta.get("message") or display_target),
                base_key_fields,
                confidence=0.72,
            )
        if "network_path" in set(event.get("tags") or []):
            make(
                "network_path_opened",
                f"Opened network path: {display_name}",
                str(meta.get("message") or display_target),
                base_key_fields,
                confidence=0.78,
            )
        if event_type == "shellbag_folder_access":
            make(
                "folder_accessed",
                f"Shellbag folder observed: {display_name}",
                str(meta.get("message") or display_target),
                {
                    **base_key_fields,
                    "source_file": shellbag.get("source_file"),
                    "hive_path": shellbag.get("hive_path"),
                    "shell_type": shellbag.get("shell_type"),
                    "mru_position": shellbag.get("mru_position") or shellbag.get("mru"),
                    "artifact_type": shellbag.get("artifact_type"),
                },
                confidence=0.78 if event.get("@timestamp") else 0.64,
            )
            if shellbag.get("is_network_path"):
                make(
                    "network_folder_accessed",
                    f"Shellbag network folder: {display_name}",
                    str(meta.get("message") or display_target),
                    {
                        **base_key_fields,
                        "network_host": (event.get("network", {}) or {}).get("destination_hostname"),
                        "share_name": (event.get("network", {}) or {}).get("share_name"),
                    },
                    confidence=0.8,
                )
            if shellbag.get("is_usb_path"):
                make(
                    "usb_folder_accessed",
                    f"Shellbag USB folder: {display_name}",
                    str(meta.get("message") or display_target),
                    {
                        **base_key_fields,
                        "drive_type": (event.get("volume", {}) or {}).get("drive_type"),
                        "volume_serial": (event.get("volume", {}) or {}).get("serial"),
                    },
                    confidence=0.8,
                )
            if "cloud_sync" in set(event.get("tags") or []):
                make(
                    "cloud_folder_accessed",
                    f"Shellbag cloud folder: {display_name}",
                    str(meta.get("message") or display_target),
                    base_key_fields,
                    confidence=0.74,
                )
            if "suspicious" in set(event.get("tags") or []):
                make(
                    "suspicious_folder_accessed",
                    f"Suspicious shellbag folder: {display_name}",
                    str(meta.get("message") or display_target),
                    base_key_fields,
                    confidence=0.82 if suspicious_reasons else 0.7,
                )
            if "deleted_or_missing_candidate" in set(event.get("tags") or []):
                make(
                    "deleted_folder_candidate",
                    f"Deleted or missing folder candidate: {display_name}",
                    str(meta.get("message") or display_target),
                    base_key_fields,
                    confidence=0.68,
                )
    elif event_type in {"usb_device_seen", "mounted_device", "usb_device_install", "volume_mounted", "portable_device_observed", "setupapi_driver_update", "usb_class_generic", "usb_connected", "usb_disconnected", "usb_installed", "usb_observed"}:
        derived_type = (
            "setupapi_driver_update"
            if event_type == "setupapi_driver_update"
            else "usb_class_generic"
            if event_type == "usb_class_generic"
            else "usb_connected"
            if event_type == "usb_connected"
            else "usb_disconnected"
            if event_type == "usb_disconnected"
            else "usb_device_install"
            if event_type in {"usb_device_install", "usb_installed"}
            else "usb_volume_mapping"
            if event_type in {"mounted_device", "volume_mounted"}
            else "portable_device_observed"
            if event_type == "portable_device_observed"
            else event_type
        )
        make(
            derived_type,
            meta.get("message") or event_type.replace("_", " "),
            str(meta.get("message") or event_type.replace("_", " ")),
            {
                "device_instance_id": usb.get("device_instance_id"),
                "vendor": usb.get("vendor"),
                "product": usb.get("product"),
                "serial": usb.get("serial"),
                "friendly_name": usb.get("friendly_name"),
                "drive_letter": volume.get("drive_letter"),
                "volume_guid": volume.get("guid"),
                "volume_serial": volume.get("serial"),
                "device_type": usb.get("device_type"),
                "container_id": usb.get("container_id"),
                "source": event.get("source_tool") or "recmd",
            },
            confidence=0.2 if derived_type in {"setupapi_driver_update", "usb_class_generic"} else 0.8,
        )
    elif event_type in {
        "bits_job",
        "bits_file_transfer",
        "bits_notify_command",
        "background_download",
        "download_started",
        "download_interrupted",
        "bits_job_observed",
    } or (
        artifact.get("type") == "bits" and event_type in {"file_transfer", "file_downloaded", "background_download", "download_started", "download_interrupted", "bits_job_observed"}
    ):
        bits = event.get("bits", {}) or {}
        url_data = event.get("url", {}) or {}
        download = event.get("download", {}) or {}
        file_data = event.get("file", {}) or {}
        activity_type = "bits_notify_persistence" if bits.get("notify_cmd_line") or event.get("persistence", {}).get("mechanism") == "bits_notify_cmd" else "background_download"
        key_fields = {
            "job_id": bits.get("job_id") or bits.get("job_guid"),
            "display_name": bits.get("display_name"),
            "owner": bits.get("owner"),
            "owner_sid": bits.get("owner_sid"),
            "state": bits.get("state"),
            "type": bits.get("type"),
            "remote_url": bits.get("remote_url") or url_data.get("full"),
            "local_path": bits.get("local_path") or file_data.get("path"),
            "file_path": bits.get("local_path") or file_data.get("path"),
            "file_name": file_data.get("name") or download.get("file_name"),
            "bytes_total": bits.get("bytes_total") or download.get("total_bytes"),
            "bytes_transferred": bits.get("bytes_transferred") or download.get("received_bytes"),
            "notify_cmd_line": bits.get("notify_cmd_line"),
            "source": "bits",
            "document_like": str(file_data.get("extension") or "").lower() in {".txt", ".docx", ".xlsx", ".pdf", ".csv", ".log"},
        }
        make(
            activity_type,
            bits.get("display_name") or bits.get("job_id") or "BITS job",
            str(meta.get("message") or bits.get("remote_url") or bits.get("local_path") or "BITS job observed"),
            key_fields,
            confidence=0.86 if bits.get("notify_cmd_line") else 0.72,
        )
        if bits.get("notify_cmd_line"):
            make(
                "possible_persistence",
                bits.get("display_name") or "BITS notify command",
                str(meta.get("message") or bits.get("notify_cmd_line") or "BITS notify command observed"),
                key_fields,
                confidence=0.88,
            )
        if "suspicious_download" in set(event.get("tags") or []) or "possible_bits_abuse" in set(event.get("tags") or []):
            make(
                "suspicious_bits_job",
                bits.get("display_name") or bits.get("job_id") or "Suspicious BITS job",
                str(meta.get("message") or bits.get("remote_url") or bits.get("local_path") or "Possible BITS abuse candidate"),
                key_fields,
                confidence=0.8,
            )
        cloud_context = _cloud_context_for_values(bits.get("local_path") or file_data.get("path"))
        if cloud_context:
            make(
                "downloaded_to_cloud",
                bits.get("display_name") or bits.get("job_id") or "BITS download to cloud",
                "BITS local path is inside a cloud sync folder.",
                {
                    **key_fields,
                    "provider": cloud_context.get("provider"),
                    "sync_root": cloud_context.get("sync_root"),
                },
                confidence=0.82,
            )
    elif event_type in {
        "cloud_sync_root",
        "cloud_file_activity",
        "cloud_staging_candidate",
        "possible_cloud_exfiltration",
        "cloud_item_observed",
        "cloud_upload",
        "cloud_download",
        "cloud_deleted",
    }:
        cloud = event.get("cloud", {}) or {}
        file_data = event.get("file", {}) or {}
        normalized_event_type = event_type
        if event_type == "cloud_item_observed":
            normalized_event_type = "cloud_sync_root" if cloud.get("sync_root") else "cloud_file_activity"
        elif event_type in {"cloud_upload", "cloud_download", "cloud_deleted"}:
            normalized_event_type = "cloud_file_activity"
        key_fields = {
            "provider": cloud.get("provider"),
            "account": cloud.get("account"),
            "account_email": cloud.get("account_email"),
            "sync_root": cloud.get("sync_root"),
            "file_path": cloud.get("local_path") or file_data.get("path"),
            "cloud_path": cloud.get("cloud_path") or cloud.get("remote_path"),
            "status": cloud.get("status"),
            "sync_status": cloud.get("sync_status"),
            "direction": cloud.get("direction"),
            "source": "cloud_sync",
            "document_like": str(file_data.get("extension") or "").lower() in {".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx", ".pdf", ".txt", ".csv"},
        }
        if normalized_event_type == "cloud_sync_root":
            make("cloud_sync_root_observed", f"Cloud sync root: {cloud.get('sync_root') or cloud.get('provider') or 'cloud'}", str(meta.get("message") or cloud.get("sync_root") or "Cloud sync root observed"), key_fields, confidence=0.74)
        elif normalized_event_type == "cloud_file_activity":
            make("cloud_file_activity", f"Cloud file: {file_data.get('name') or cloud.get('local_path') or 'file'}", str(meta.get("message") or cloud.get("local_path") or "Cloud file activity observed"), key_fields, confidence=0.7)
            if "sensitive_file" in set(event.get("tags") or []):
                make("cloud_sensitive_file_observed", f"Sensitive cloud file: {file_data.get('name') or 'file'}", str(meta.get("message") or "Sensitive file observed in cloud sync folder"), key_fields, confidence=0.76)
            if "archive_file" in set(event.get("tags") or []):
                make("cloud_archive_created", f"Cloud archive: {file_data.get('name') or 'archive'}", str(meta.get("message") or "Archive file observed in cloud sync folder"), key_fields, confidence=0.78)
            if "executable_from_cloud" in set(event.get("tags") or []):
                make("executable_from_cloud", f"Executable from cloud: {file_data.get('name') or 'file'}", str(meta.get("message") or "Executable/script observed in cloud sync folder"), key_fields, confidence=0.8)
        elif normalized_event_type == "cloud_staging_candidate":
            make("possible_cloud_staging", f"Cloud staging candidate: {cloud.get('sync_root') or cloud.get('provider') or 'cloud'}", str(meta.get("message") or "Cloud staging candidate"), key_fields, confidence=0.78)
        else:
            make("possible_cloud_exfiltration", f"Possible cloud exfiltration candidate: {cloud.get('sync_root') or cloud.get('provider') or 'cloud'}", str(meta.get("message") or "Possible cloud exfiltration candidate"), key_fields, confidence=0.82)
    elif event_type in {"wlan_profile", "wlan_connection", "wlan_connected", "wlan_disconnection", "wlan_disconnected", "wlan_profile_event", "wlan_error", "wlan_connection_failed", "dns_cache_entry", "dns_query", "dns_query_failed", "dns_config", "hosts_entry", "network_profile", "interface_config", "netstat_connection", "arp_entry", "route_entry"}:
        wlan = event.get("wlan", {}) or {}
        dns = event.get("dns", {}) or {}
        key_fields = {
            "ssid": wlan.get("ssid"),
            "profile_name": wlan.get("profile_name") or network.get("profile_name"),
            "bssid": wlan.get("bssid"),
            "interface_name": network.get("interface_name"),
            "interface_guid": network.get("interface_guid"),
            "domain": dns.get("domain") or dns.get("name") or network.get("domain"),
            "hostname": dns.get("name"),
            "ip": dns.get("ip") or network.get("destination_ip") or network.get("source_ip") or network.get("ip_address"),
            "dns_servers": network.get("dns_servers"),
            "gateway": network.get("gateway"),
            "process_name": network.get("process_name"),
            "process_id": network.get("process_id"),
            "status": dns.get("status") or network.get("state"),
            "source": "network",
        }
        summary = str(meta.get("message") or dns.get("name") or wlan.get("ssid") or network.get("profile_name") or "Network activity observed")
        if event_type == "wlan_profile":
            make("wlan_profile_observed", wlan.get("ssid") or wlan.get("profile_name") or "WLAN profile", summary, key_fields, confidence=0.72)
            if "open_wifi" in set(event.get("tags") or []):
                make("suspicious_network_configuration", wlan.get("ssid") or "Open Wi-Fi profile", "WLAN profile uses open authentication.", key_fields, confidence=0.55)
        elif event_type in {"wlan_connection", "wlan_connected"}:
            make("wlan_connection_observed", wlan.get("ssid") or wlan.get("profile_name") or "WLAN connection", summary, key_fields, confidence=0.78)
        elif event_type == "network_profile":
            make("network_profile_observed", network.get("profile_name") or "Network profile", summary, key_fields, confidence=0.68)
        elif event_type in {"dns_cache_entry", "dns_query", "dns_query_failed", "dns_config", "interface_config"}:
            make("network_indicator_seen", dns.get("name") or network.get("domain") or "Network indicator", summary, key_fields, confidence=0.64 if event_type == "dns_cache_entry" else 0.6)
            if "suspicious_dns_server" in set(event.get("tags") or []):
                make("suspicious_dns_config", "Suspicious DNS configuration", "DNS server configuration may be unusual.", key_fields, confidence=0.58)
        elif event_type == "hosts_entry":
            make("hosts_override_observed", dns.get("name") or "Hosts entry", summary, key_fields, confidence=0.74)
            if "suspicious_hosts_entry" in set(event.get("tags") or []):
                make("suspicious_hosts_override", dns.get("name") or "Suspicious hosts entry", "Hosts file redirects security/vendor domain.", key_fields, confidence=0.9)
        elif event_type == "netstat_connection":
            make("network_indicator_seen", network.get("destination_ip") or "Network connection", summary, key_fields, confidence=0.7)
            if "direct_ip_connection" in set(event.get("tags") or []):
                make("suspicious_network_activity_candidate", network.get("destination_ip") or "Direct IP connection", "Connection to direct public IP by suspicious process.", key_fields, confidence=0.82)
        elif event_type == "arp_entry":
            make("network_indicator_seen", dns.get("ip") or network.get("ip_address") or "ARP entry", summary, key_fields, confidence=0.55)
        elif event_type == "route_entry":
            make("network_indicator_seen", network.get("destination_ip") or "Route entry", summary, key_fields, confidence=0.55)
    elif event_type in {"wmi_event_filter", "wmi_event_consumer", "wmi_filter_consumer_binding", "wmi_command_line_consumer", "wmi_active_script_consumer", "wmi_filter_to_consumer_binding", "wmi_activity", "wmi_query", "wmi_consumer_binding", "wmi_error"}:
        wmi = event.get("wmi", {}) or {}
        key_fields = {
            "namespace": wmi.get("namespace"),
            "class_name": wmi.get("class_name"),
            "name": wmi.get("name"),
            "filter_name": wmi.get("filter_name"),
            "consumer_name": wmi.get("consumer_name"),
            "consumer_type": wmi.get("consumer_type"),
            "query": wmi.get("query"),
            "command_line": wmi.get("command_line_template"),
            "executable_path": wmi.get("executable_path"),
            "script_preview": wmi.get("script_preview"),
            "binding_filter": wmi.get("binding_filter"),
            "binding_consumer": wmi.get("binding_consumer"),
            "creator_sid": wmi.get("creator_sid"),
            "creator_user": wmi.get("creator_user"),
            "source": "wmi",
        }
        if event_type == "wmi_event_filter":
            make("wmi_filter", wmi.get("filter_name") or wmi.get("name") or "WMI filter", str(meta.get("message") or "WMI filter observed"), key_fields, confidence=0.62 if event.get("timestamp_precision") == "source_file_mtime" else 0.74)
        elif event_type in {"wmi_event_consumer", "wmi_command_line_consumer", "wmi_active_script_consumer"}:
            make("wmi_consumer", wmi.get("consumer_name") or wmi.get("name") or "WMI consumer", str(meta.get("message") or "WMI consumer observed"), key_fields, confidence=0.66 if event.get("timestamp_precision") == "source_file_mtime" else 0.8)
        elif event_type in {"wmi_filter_consumer_binding", "wmi_filter_to_consumer_binding"}:
            binding_title = wmi.get("binding_consumer") or wmi.get("consumer_name") or "WMI binding"
            binding_summary = str(meta.get("message") or "WMI binding observed")
            make("wmi_binding", binding_title, binding_summary, key_fields, confidence=0.7)
            make(
                "wmi_persistence_candidate",
                binding_title,
                binding_summary,
                {
                    **key_fields,
                    "binding_status": "complete" if key_fields.get("binding_filter") and key_fields.get("binding_consumer") else "unresolved",
                },
                confidence=0.82 if key_fields.get("binding_filter") and key_fields.get("binding_consumer") else 0.64,
            )
        else:
            make("wmi_activity_query", wmi.get("consumer_name") or wmi.get("name") or "WMI activity", str(meta.get("message") or "WMI activity observed"), key_fields, confidence=0.48)
    elif event_type == "rdp_mru":
        make(
            "rdp_history",
            "RDP MRU",
            str(meta.get("message") or "RDP MRU"),
            {
                "destination_hostname": (event.get("destination", {}) or {}).get("hostname"),
                "registry_key": registry.get("key_path"),
                "value_name": registry.get("value_name"),
                "source": "recmd",
            },
            confidence=0.74,
        )
    elif event_type in {"browser_history", "browser_visit"}:
        browser = event.get("browser", {}) or {}
        url = event.get("url", {}) or {}
        title = str(browser.get("title") or url.get("domain") or url.get("full") or "Browser visit")
        key_fields = {
            "browser": browser.get("name") or browser.get("browser"),
            "profile": browser.get("profile"),
            "url": url.get("full"),
            "domain": url.get("domain"),
            "title": browser.get("title"),
            "visit_count": browser.get("visit_count"),
            "typed_count": browser.get("typed_count"),
            "source": "browser",
        }
        make(
            "browser_history",
            f"Visited: {title}",
            str(meta.get("message") or _display_browser_target(event)),
            key_fields,
            confidence=0.72 if event.get("@timestamp") else 0.58,
        )
    elif event_type == "browser_search":
        browser = event.get("browser", {}) or {}
        url = event.get("url", {}) or {}
        key_fields = {
            "browser": browser.get("name") or browser.get("browser"),
            "profile": browser.get("profile"),
            "search_engine": browser.get("search_engine"),
            "search_terms": browser.get("search_terms"),
            "url": url.get("full"),
            "domain": url.get("domain"),
            "source": "browser",
        }
        make(
            "web_search",
            f"Search: {browser.get('search_terms') or 'unknown'}",
            str(meta.get("message") or _display_browser_target(event)),
            key_fields,
            confidence=0.78 if browser.get("search_terms") else 0.62,
        )
    elif event_type == "file_downloaded":
        browser = event.get("browser", {}) or {}
        download = event.get("download", {}) or {}
        file_data = event.get("file", {}) or {}
        url = event.get("url", {}) or {}
        domain = url.get("domain") or browser.get("domain")
        file_name = str(file_data.get("name") or download.get("file_name") or "downloaded file")
        key_fields = {
            "browser": browser.get("name") or browser.get("browser"),
            "profile": browser.get("profile"),
            "file_path": file_data.get("path") or download.get("target_path"),
            "file_name": file_data.get("name") or download.get("file_name"),
            "extension": file_data.get("extension"),
            "size": file_data.get("size") or download.get("total_bytes"),
            "url": download.get("url") or url.get("full"),
            "final_url": download.get("final_url") or browser.get("final_url"),
            "domain": domain,
            "referrer": download.get("referrer") or browser.get("referrer"),
            "state": download.get("state") or browser.get("download_state"),
            "danger_type": browser.get("danger_type"),
            "source": "browser",
        }
        make(
            "file_download",
            f"Downloaded: {file_name}",
            str(meta.get("message") or _display_browser_target(event)),
            key_fields,
            confidence=0.82 if key_fields.get("file_path") else 0.68,
        )
        cloud_context = _cloud_context_for_values(file_data.get("path"), download.get("target_path"))
        if cloud_context:
            make(
                "downloaded_to_cloud",
                f"Downloaded to cloud: {file_name}",
                "Browser download target is inside a cloud sync folder.",
                {
                    **key_fields,
                    "provider": cloud_context.get("provider"),
                    "sync_root": cloud_context.get("sync_root"),
                },
                confidence=0.84,
            )
    elif event_type in {"srum_network_usage", "srum_application_resource_usage", "srum_energy_usage", "srum_record", "network_usage", "app_resource_usage", "energy_usage", "network_connectivity_observed"}:
        srum = event.get("srum", {}) or {}
        network = event.get("network", {}) or {}
        key_fields = {
            "application": srum.get("app_name") or network.get("application") or process.get("name"),
            "process_name": process.get("name"),
            "process_path": process.get("path"),
            "user_sid": (event.get("user", {}) or {}).get("sid") or srum.get("user_sid"),
            "bytes_sent": network.get("bytes_sent") or srum.get("bytes_sent"),
            "bytes_received": network.get("bytes_received") or srum.get("bytes_received"),
            "bytes_total": network.get("bytes_total") or srum.get("bytes_total"),
            "interface_profile": srum.get("interface_profile"),
            "network_profile": srum.get("network_profile"),
            "table": srum.get("table"),
            "artifact_type": srum.get("artifact_type"),
            "source": "srum",
        }
        make(
            "application_network_usage",
            f"Network usage: {srum.get('app_name') or process.get('name') or 'application'}",
            str(meta.get("message") or process.get("path") or srum.get("app_id") or "SRUM network usage"),
            key_fields,
            confidence=_srum_confidence(event),
        )
        if "high_upload" in set(event.get("tags") or []):
            make(
                "high_upload_activity",
                f"High upload: {srum.get('app_name') or process.get('name') or 'application'}",
                str(meta.get("message") or "High outbound network usage"),
                {**key_fields, "upload_ratio": ((network.get("bytes_sent") or srum.get("bytes_sent") or 0) / max((network.get("bytes_received") or srum.get("bytes_received") or 1), 1))},
                confidence=max(_srum_confidence(event), 0.78),
            )
        if "remote_access_tool" in set(event.get("tags") or []):
            make(
                "remote_access_activity",
                f"Remote access network: {srum.get('app_name') or process.get('name') or 'application'}",
                str(meta.get("message") or "Remote access tool network activity"),
                key_fields,
                confidence=max(_srum_confidence(event), 0.8),
            )
        if "possible_exfiltration" in set(event.get("tags") or []):
            make(
                "possible_exfiltration",
                f"Possible exfiltration candidate: {srum.get('app_name') or process.get('name') or 'application'}",
                str(meta.get("message") or "Possible exfiltration candidate"),
                key_fields,
                confidence=max(_srum_confidence(event), 0.8),
            )
    elif event_type in {"program_observed", "installed_program_observed", "file_observed", "execution_candidate"} and str((event.get("artifact", {}) or {}).get("type") or "") == "amcache":
        amcache = event.get("amcache", {}) or {}
        execution = event.get("execution", {}) or {}
        display_target = str((event.get("file", {}) or {}).get("path") or amcache.get("program_name") or amcache.get("product_name") or "Amcache program")
        key_fields = {
            "file_path": (event.get("file", {}) or {}).get("path"),
            "file_name": (event.get("file", {}) or {}).get("name"),
            "extension": (event.get("file", {}) or {}).get("extension"),
            "publisher": amcache.get("publisher"),
            "product_name": amcache.get("product_name"),
            "version": amcache.get("product_version") or amcache.get("program_version"),
            "hash_sha1": (event.get("file", {}) or {}).get("hash_sha1") or (event.get("file", {}) or {}).get("sha1"),
            "hash_sha256": (event.get("file", {}) or {}).get("hash_sha256") or (event.get("file", {}) or {}).get("sha256"),
            "md5": (event.get("file", {}) or {}).get("md5"),
            "source": "amcache",
            "confidence_label": execution.get("confidence"),
            "interpretation": execution.get("interpretation"),
            "install_date": execution.get("install_date"),
            "compile_time": execution.get("compile_time"),
            "last_modified": execution.get("last_modified"),
            "program_id": amcache.get("program_id"),
        }
        make(
            "program_inventory",
            f"Program observed: {(event.get('file', {}) or {}).get('name') or amcache.get('program_name') or 'program'}",
            str(meta.get("message") or display_target),
            key_fields,
            confidence=_execution_artifact_confidence(event),
        )
        if suspicious_reasons or any(tag in set(event.get("tags") or []) for tag in {"suspicious", "suspicious_path", "lolbin", "remote_access_tool", "double_extension"}):
            make(
                "suspicious_program",
                f"Suspicious program observed: {(event.get('file', {}) or {}).get('name') or amcache.get('program_name') or 'program'}",
                str(meta.get("message") or display_target),
                key_fields,
                confidence=max(_execution_artifact_confidence(event), 0.7),
            )
    elif event_type in {"shimcache_entry", "appcompat_entry", "recentfilecache_entry"} or (
        event_type == "execution_candidate" and str((event.get("artifact", {}) or {}).get("type") or "") in {"shimcache", "appcompat"}
    ):
        appcompat = event.get("appcompat", {}) or {}
        shimcache = event.get("shimcache", {}) or {}
        execution = event.get("execution", {}) or {}
        display_target = str((event.get("file", {}) or {}).get("path") or appcompat.get("path") or shimcache.get("path") or appcompat.get("name") or "AppCompat artifact")
        key_fields = {
            "file_path": (event.get("file", {}) or {}).get("path") or appcompat.get("path") or shimcache.get("path"),
            "file_name": (event.get("file", {}) or {}).get("name") or appcompat.get("name"),
            "extension": (event.get("file", {}) or {}).get("extension"),
            "source": execution.get("source") or ("recentfilecache" if event_type == "recentfilecache_entry" else "shimcache"),
            "confidence_label": execution.get("confidence"),
            "interpretation": execution.get("interpretation") or appcompat.get("interpretation"),
            "executed": shimcache.get("executed"),
            "entry_number": shimcache.get("entry_number") or appcompat.get("entry_number"),
            "position": shimcache.get("position"),
            "last_modified": shimcache.get("last_modified_time") or appcompat.get("last_modified"),
        }
        make(
            "execution_candidate",
            f"Execution candidate: {(event.get('file', {}) or {}).get('name') or appcompat.get('name') or 'program'}",
            str(meta.get("message") or display_target),
            key_fields,
            confidence=_execution_artifact_confidence(event),
        )
        if suspicious_reasons or any(tag in set(event.get("tags") or []) for tag in {"suspicious", "suspicious_path", "lolbin", "remote_access_tool", "double_extension"}):
            make(
                "suspicious_program",
                f"Suspicious execution artifact: {(event.get('file', {}) or {}).get('name') or appcompat.get('name') or 'program'}",
                str(meta.get("message") or display_target),
                key_fields,
                confidence=max(_execution_artifact_confidence(event), 0.68),
            )
    elif event_type in {"file_opened", "document_opened", "program_or_script_opened", "folder_opened", "jumplist_recent_item", "executable_opened", "script_opened", "network_path_opened", "removable_media_path_opened", "startup_lnk"}:
        lnk = event.get("lnk", {}) or {}
        jumplist = event.get("jumplist", {}) or {}
        volume = event.get("volume", {}) or {}
        artifact = event.get("artifact", {}) or {}
        timestamp_precision = str(event.get("timestamp_precision") or "")
        low_temporal_confidence = timestamp_precision == "source_file_mtime"
        source_type = str(artifact.get("type") or lnk.get("source_file") and "lnk" or jumplist.get("source_file") and "jumplist" or "file_access")
        display_target = _display_file_target(event)
        display_name = str((event.get("file", {}) or {}).get("name") or jumplist.get("display_name") or lnk.get("display_name") or "File target")
        title_prefix = {
            "folder_opened": "Opened folder",
            "document_opened": "Opened document",
            "program_or_script_opened": "Opened executable or script",
            "executable_opened": "Opened executable",
            "script_opened": "Opened script",
            "network_path_opened": "Opened network path",
            "removable_media_path_opened": "Opened removable media path",
            "startup_lnk": "Startup LNK reference",
            "file_opened": "Opened file",
            "jumplist_recent_item": "Recent item",
        }.get(event_type, "Opened file")
        base_key_fields = {
            "file_path": (event.get("file", {}) or {}).get("path"),
            "extension": (event.get("file", {}) or {}).get("extension"),
            "source_lnk": lnk.get("source_file"),
            "source_jumplist": jumplist.get("source_file"),
            "arguments": jumplist.get("arguments") or lnk.get("arguments"),
            "app_name": jumplist.get("app_name"),
            "app_id": jumplist.get("app_id"),
            "interaction_count": jumplist.get("interaction_count"),
            "working_directory": jumplist.get("working_directory") or lnk.get("working_directory"),
            "drive_type": volume.get("drive_type") or jumplist.get("drive_type") or lnk.get("drive_type"),
            "network_path": (event.get("network", {}) or {}).get("path") or jumplist.get("network_path") or lnk.get("network_path"),
            "machine_id": jumplist.get("machine_id") or jumplist.get("hostname") or lnk.get("machine_id"),
            "volume_serial": volume.get("serial"),
            "source": "jlecmd" if source_type == "jumplist" else str((event.get("source_tool") or "").lower() or "lecmd"),
            "effective_target_source": jumplist.get("effective_path_source") or lnk.get("effective_path_source"),
            "document_like": event_type == "document_opened",
        }
        make(
            "opened_file",
            f"{title_prefix}: {display_name}",
            str(meta.get("message") or f"LNK target accessed: {display_target}"),
            base_key_fields,
            confidence=0.6 if low_temporal_confidence else 0.72 if event.get("@timestamp") and (event.get("file", {}) or {}).get("path") else 0.58,
        )
        if event_type in {"program_or_script_opened", "executable_opened", "script_opened", "startup_lnk"}:
            make(
                "script_opened",
                f"Opened script or executable: {display_name}",
                str(meta.get("message") or f"Execution-related LNK target: {display_target}"),
                base_key_fields,
                confidence=0.8 if event.get("@timestamp") else 0.62,
            )
        if source_type == "jumplist" and (jumplist.get("app_name") or jumplist.get("app_id")):
            make(
                "application_used",
                str(jumplist.get("app_name") or jumplist.get("app_id") or "JumpList application"),
                str(meta.get("message") or f"JumpList usage via {jumplist.get('app_name') or jumplist.get('app_id') or 'application'}"),
                {
                    "app_name": jumplist.get("app_name"),
                    "app_id": jumplist.get("app_id"),
                    "interaction_count": jumplist.get("interaction_count"),
                    "source_jumplist": jumplist.get("source_file"),
                    "file_path": (event.get("file", {}) or {}).get("path"),
                    "last_seen": timestamp,
                    "source": "jlecmd",
                    "timestamp_precision": timestamp_precision,
                },
                confidence=0.68 if low_temporal_confidence else 0.84 if jumplist.get("interaction_count") not in (None, 0, "0") else 0.7,
            )
        if any(tag in set(event.get("tags") or []) for tag in {"network_path", "unc_path"}):
            make(
                "network_path_opened",
                f"Opened network path: {display_name}",
                str(meta.get("message") or f"UNC or network path opened: {display_target}"),
                base_key_fields,
                confidence=0.7 if low_temporal_confidence else 0.8,
            )
            if source_type == "jumplist":
                make(
                    "network_file_accessed",
                    f"JumpList network item: {display_name}",
                    str(meta.get("message") or f"JumpList network item observed: {display_target}"),
                    base_key_fields,
                    confidence=0.7 if low_temporal_confidence else 0.8,
                )
        if any(tag in set(event.get("tags") or []) for tag in {"removable_media", "usb_candidate"}):
            make(
                "removable_media_access",
                f"Opened removable-media target: {display_name}",
                str(meta.get("message") or f"Removable media access: {display_target}"),
                base_key_fields,
                confidence=0.68 if low_temporal_confidence else 0.78,
            )
            if source_type == "jumplist":
                make(
                    "usb_file_accessed",
                    f"JumpList USB item: {display_name}",
                    str(meta.get("message") or f"JumpList removable item observed: {display_target}"),
                    base_key_fields,
                    confidence=0.68 if low_temporal_confidence else 0.78,
                )
            if source_type == "lnk":
                make(
                    "usb_file_accessed",
                    f"LNK USB item: {display_name}",
                    str(meta.get("message") or f"LNK removable item observed: {display_target}"),
                    base_key_fields,
                    confidence=0.68 if low_temporal_confidence else 0.78,
                )
        if source_type == "jumplist" and "cloud_sync" in set(event.get("tags") or []):
            make(
                "cloud_file_accessed",
                f"JumpList cloud item: {display_name}",
                str(meta.get("message") or f"JumpList cloud item observed: {display_target}"),
                base_key_fields,
                confidence=0.64 if low_temporal_confidence else 0.74,
            )
        if source_type == "jumplist":
            make(
                "recent_file_opened",
                f"JumpList recent item: {display_name}",
                str(meta.get("message") or f"JumpList item observed: {display_target}"),
                base_key_fields,
                confidence=0.62 if low_temporal_confidence else 0.8 if event.get("@timestamp") and (event.get("file", {}) or {}).get("path") else 0.62,
            )
            if "suspicious" in set(event.get("tags") or []):
                make(
                    "suspicious_recent_item",
                    f"Suspicious JumpList item: {display_name}",
                    str(meta.get("message") or f"Suspicious JumpList item observed: {display_target}"),
                    base_key_fields,
                    confidence=0.84 if suspicious_reasons else 0.72,
                )
    elif event_type in {
        "file_observed",
        "folder_observed",
        "alternate_data_stream",
        "file_deleted_or_not_in_use",
        "file_created",
        "file_deleted",
        "file_modified",
        "file_metadata_changed",
        "file_rename_old_name",
        "file_rename_new_name",
        "usn_record",
    } and str((event.get("artifact") or {}).get("type") or "") not in {"recycle_bin", "recycle"}:
        filesystem = event.get("filesystem", {}) or {}
        artifact = event.get("artifact", {}) or {}
        mft = event.get("mft", {}) or {}
        usn = event.get("usn", {}) or {}
        file_data = event.get("file", {}) or {}
        display_target = _display_filesystem_target(event)
        display_name = str(file_data.get("name") or Path(display_target).name or "Filesystem target")
        base_key_fields = {
            "file_path": file_data.get("path"),
            "file_name": file_data.get("name"),
            "extension": file_data.get("extension"),
            "parent_path": file_data.get("parent_path"),
            "size": file_data.get("size"),
            "in_use": file_data.get("in_use"),
            "deleted": file_data.get("deleted"),
            "is_directory": file_data.get("is_directory"),
            "ads": file_data.get("ads"),
            "source": artifact.get("type") or filesystem.get("source"),
            "filesystem_activity": filesystem.get("activity"),
            "filesystem_reason": filesystem.get("reason"),
            "mft_entry": mft.get("entry_number"),
            "mft_sequence": mft.get("sequence_number"),
            "usn_reason": usn.get("reason") or usn.get("reasons"),
            "usn_value": usn.get("usn"),
            "document_like": str(file_data.get("extension") or "").lower() in {".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx", ".pdf", ".txt", ".rtf", ".csv", ".zip", ".rar", ".7z"},
        }
        fs_title_map = {
            "file_observed": "Observed file",
            "folder_observed": "Observed folder",
            "alternate_data_stream": "Alternate data stream",
            "file_deleted_or_not_in_use": "Deleted candidate",
            "file_created": "Created file",
            "file_deleted": "Deleted file",
            "file_modified": "Modified file",
            "file_metadata_changed": "Metadata changed",
            "file_rename_old_name": "Rename old name",
            "file_rename_new_name": "Rename new name",
            "usn_record": "USN record",
        }
        primary_activity = {
            "file_created": "file_created",
            "file_deleted": "file_deleted",
            "file_modified": "file_modified",
            "file_metadata_changed": "file_modified",
            "file_rename_old_name": "file_renamed",
            "file_rename_new_name": "file_renamed",
        }.get(event_type, "opened_file")
        make(
            primary_activity,
            f"{fs_title_map.get(event_type, 'Filesystem event')}: {display_name}",
            str(meta.get("message") or display_target),
            base_key_fields,
            confidence=0.84 if artifact.get("type") == "usn" and event_type in {"file_created", "file_deleted", "file_modified"} else 0.72,
        )
        extension = str(file_data.get("extension") or "").lower()
        if extension in {".ps1", ".bat", ".cmd", ".vbs", ".js", ".jse", ".wsf", ".hta", ".exe", ".com", ".dll", ".scr", ".msi"}:
            make(
                "execution_candidate",
                f"Execution candidate: {display_name}",
                str(meta.get("message") or display_target),
                base_key_fields,
                confidence=0.82 if artifact.get("type") == "usn" and event_type in {"file_created", "file_modified"} else 0.7,
            )
        if any(tag in set(event.get("tags") or []) for tag in {"suspicious", "suspicious_path", "ads", "timestomp_suspected"}):
            make(
                "suspicious_file",
                f"Suspicious file evidence: {display_name}",
                str(meta.get("message") or display_target),
                base_key_fields,
                confidence=0.86 if suspicious_reasons else 0.74,
            )
        cloud_context = _cloud_context_for_values(file_data.get("path"))
        if cloud_context:
            tags = cloud_context.get("tags") or set()
            make(
                "cloud_file_activity",
                f"Cloud file activity: {display_name}",
                str(meta.get("message") or display_target),
                {
                    **base_key_fields,
                    "provider": cloud_context.get("provider"),
                    "sync_root": cloud_context.get("sync_root"),
                },
                confidence=0.76,
            )
            if "sensitive_file" in tags:
                make(
                    "cloud_sensitive_file_observed",
                    f"Sensitive cloud file: {display_name}",
                    "Sensitive file observed inside cloud sync folder",
                    {
                        **base_key_fields,
                        "provider": cloud_context.get("provider"),
                        "sync_root": cloud_context.get("sync_root"),
                    },
                    confidence=0.8,
                )
            if "archive_file" in tags:
                make(
                    "cloud_archive_created",
                    f"Cloud archive: {display_name}",
                    "Archive file created or modified inside cloud sync folder",
                    {
                        **base_key_fields,
                        "provider": cloud_context.get("provider"),
                        "sync_root": cloud_context.get("sync_root"),
                    },
                    confidence=0.82,
                )
            if "executable_from_cloud" in tags:
                make(
                    "executable_from_cloud",
                    f"Executable from cloud: {display_name}",
                    "Executable or script observed inside cloud sync folder",
                    {
                        **base_key_fields,
                        "provider": cloud_context.get("provider"),
                        "sync_root": cloud_context.get("sync_root"),
                    },
                    confidence=0.84,
                )
    elif suspicious_reasons:
        make("suspicious_event", str(process.get("name") or meta.get("type") or "Suspicious event"), str(meta.get("message") or "Suspicious event"), {"process_name": process.get("name"), "path": process.get("path")}, confidence=0.7)

    return activities


def correlate_usb_activity(activities: list[ForensicActivity], *, window_seconds: int = 7200) -> list[ForensicActivity]:
    device_activities = [
        item
        for item in activities
        if item.activity_type in {"usb_device_install", "usb_volume_mapping", "portable_device_observed", "usb_device_seen", "mounted_device"}
    ]
    if not device_activities:
        return activities

    drive_map: dict[str, ForensicActivity] = {}
    serial_map: dict[str, ForensicActivity] = {}
    for item in device_activities:
        drive = _normalized_name(item.key_fields.get("drive_letter"))
        volume_serial = _normalized_name(item.key_fields.get("volume_serial"))
        serial = _normalized_name(item.key_fields.get("serial"))
        if drive:
            drive_map[drive] = item
        if volume_serial:
            serial_map[volume_serial] = item
        if serial and serial not in serial_map:
            serial_map[serial] = item

    new_activities: list[ForensicActivity] = []
    file_like = [
        item
        for item in activities
        if item.activity_type in {"opened_file", "recent_file_opened", "downloaded_file_opened", "file_created", "file_modified", "file_deleted", "file_recycled", "usb_file_accessed", "usb_folder_accessed", "removable_media_access", "powershell_execution", "powershell_download", "file_download"}
    ]
    for item in file_like:
        command_line = str(item.key_fields.get("command_line") or "")
        path = str(item.key_fields.get("file_path") or item.key_fields.get("target_path") or item.key_fields.get("paths") or "")
        candidate_drives = []
        if path:
            drive = _extract_drive_letter_from_path(path)
            if drive:
                candidate_drives.append(drive)
        candidate_drives.extend(_extract_drive_letters_from_text(command_line))
        normalized_drive = _normalized_name(item.key_fields.get("drive_letter"))
        if normalized_drive:
            candidate_drives.append(str(item.key_fields.get("drive_letter")))
        drive_letter = None
        matched = None
        for candidate_drive in candidate_drives:
            candidate_match = drive_map.get(_normalized_name(candidate_drive))
            if candidate_match:
                drive_letter = candidate_drive
                matched = candidate_match
                break
        volume_serial = _normalized_name(item.key_fields.get("volume_serial"))
        matched = matched or (serial_map.get(volume_serial) if volume_serial else None)
        if not matched:
            continue
        item.evidence_refs = sorted(set(item.evidence_refs + matched.evidence_refs))
        item.related_events = sorted(set(item.related_events + matched.related_events))
        item.tags = sorted(set(item.tags + matched.tags + ["usb_correlated"]))
        item.confidence = max(item.confidence, 0.82)

        if item.activity_type in {"opened_file", "recent_file_opened", "downloaded_file_opened", "usb_file_accessed", "removable_media_access"}:
            new_activities.append(
                ForensicActivity(
                    id=str(uuid4()),
                    activity_type="usb_file_access",
                    title=f"USB file activity: {path or item.title}",
                    timestamp=item.timestamp or matched.timestamp,
                    host=item.host,
                    user=item.user,
                    summary=item.summary,
                    severity=item.severity,
                    confidence=max(item.confidence, 0.84),
                    tags=sorted(set(item.tags + matched.tags + ["usb_file_access"])),
                    key_fields={**item.key_fields, "related_usb_device": matched.id, "drive_letter": drive_letter},
                    evidence_refs=sorted(set(item.evidence_refs + matched.evidence_refs)),
                    related_events=sorted(set(item.related_events + matched.related_events)),
                    suspicious_reasons=sorted(set(item.suspicious_reasons + matched.suspicious_reasons)),
                )
            )
        if item.activity_type in {"file_download"} and drive_letter:
            new_activities.append(
                ForensicActivity(
                    id=str(uuid4()),
                    activity_type="usb_download_to_external_drive",
                    title=f"Download to USB: {path or item.title}",
                    timestamp=item.timestamp or matched.timestamp,
                    host=item.host,
                    user=item.user,
                    summary="Browser download targeted a removable drive.",
                    severity="medium",
                    confidence=0.86,
                    tags=sorted(set(item.tags + matched.tags + ["download_to_usb", "possible_usb_exfiltration"])),
                    key_fields={**item.key_fields, "related_usb_device": matched.id},
                    evidence_refs=sorted(set(item.evidence_refs + matched.evidence_refs)),
                    related_events=sorted(set(item.related_events + matched.related_events)),
                    suspicious_reasons=sorted(set(item.suspicious_reasons + ["Browser download target is removable drive"])),
                )
            )
        if item.activity_type in {"powershell_execution", "powershell_download"} and drive_letter:
            summary_blob = f"{item.summary} {item.key_fields.get('command_line') or ''}".lower()
            if any(token in summary_blob for token in ["copy-item", "copy ", "xcopy", "robocopy", "move ", "compress-archive", "7z", "rar", "zip "]):
                new_activities.append(
                    ForensicActivity(
                        id=str(uuid4()),
                        activity_type="possible_usb_exfiltration_candidate",
                        title=f"Possible USB exfiltration candidate: {path or item.title}",
                        timestamp=item.timestamp or matched.timestamp,
                        host=item.host,
                        user=item.user,
                        summary="Command references a removable drive and a copy/archive style action. Treat as hypothesis, not proof.",
                        severity="medium",
                        confidence=0.78,
                        tags=sorted(set(item.tags + matched.tags + ["copy_to_usb", "possible_usb_exfiltration"])),
                        key_fields={**item.key_fields, "related_usb_device": matched.id, "drive_letter": drive_letter},
                        evidence_refs=sorted(set(item.evidence_refs + matched.evidence_refs)),
                        related_events=sorted(set(item.related_events + matched.related_events)),
                        suspicious_reasons=sorted(set(item.suspicious_reasons + ["PowerShell/copy command references removable drive"])),
                    )
                )

    return activities + new_activities


def deduplicate_activities(activities: list[ForensicActivity]) -> list[ForensicActivity]:
    buckets: dict[tuple, ForensicActivity] = {}
    for activity in activities:
        timestamp = _parse_iso(activity.timestamp)
        rounded = timestamp.replace(second=(timestamp.second // 30) * 30, microsecond=0).isoformat() if timestamp else activity.timestamp
        key_hint = (
            activity.key_fields.get("process_path")
            or activity.key_fields.get("command_line")
            or activity.key_fields.get("task_name")
            or activity.key_fields.get("service_name")
            or activity.key_fields.get("threat_name")
            or activity.key_fields.get("destination_ip")
            or activity.summary
        )
        key = (activity.activity_type, rounded, activity.host, activity.user, str(key_hint))
        if key not in buckets:
            buckets[key] = activity
            continue
        existing = buckets[key]
        existing.related_events = sorted(set(existing.related_events + activity.related_events))
        existing.evidence_refs = sorted(set(existing.evidence_refs + activity.evidence_refs))
        existing.tags = sorted(set(existing.tags + activity.tags))
        existing.suspicious_reasons = sorted(set(existing.suspicious_reasons + activity.suspicious_reasons))
        existing.confidence = max(existing.confidence, activity.confidence)
        if activity.summary and len(activity.summary) > len(existing.summary):
            existing.summary = activity.summary
    return sorted(buckets.values(), key=lambda item: item.timestamp or "", reverse=False)


def correlate_program_execution_sources(activities: list[ForensicActivity], *, window_seconds: int = 600) -> list[ForensicActivity]:
    execution_items = [item for item in activities if item.activity_type in {"program_execution", "powershell_execution"}]
    merged_ids: set[str] = set()
    for index, activity in enumerate(execution_items):
        if activity.id in merged_ids:
            continue
        current_ts = _parse_iso(activity.timestamp)
        current_name = str(activity.key_fields.get("process_name") or "").lower()
        current_host = str(activity.host or "")
        current_source = str(activity.key_fields.get("source") or "").lower()
        if not current_ts or not current_name:
            continue
        for candidate in execution_items[index + 1 :]:
            if candidate.id in merged_ids:
                continue
            if candidate.activity_type != activity.activity_type:
                continue
            candidate_ts = _parse_iso(candidate.timestamp)
            candidate_name = str(candidate.key_fields.get("process_name") or "").lower()
            candidate_host = str(candidate.host or "")
            candidate_source = str(candidate.key_fields.get("source") or "").lower()
            if not candidate_ts or not candidate_name:
                continue
            if current_host != candidate_host or current_name != candidate_name:
                continue
            if "prefetch" not in {current_source, candidate_source} or current_source == candidate_source:
                continue
            if abs((candidate_ts - current_ts).total_seconds()) > window_seconds:
                continue
            activity.evidence_refs = sorted(set(activity.evidence_refs + candidate.evidence_refs))
            activity.related_events = sorted(set(activity.related_events + candidate.related_events))
            activity.tags = sorted(set(activity.tags + candidate.tags + ["correlated_execution"]))
            activity.suspicious_reasons = sorted(set(activity.suspicious_reasons + candidate.suspicious_reasons))
            activity.confidence = max(activity.confidence, candidate.confidence, 0.95)
            activity.key_fields["correlated_sources"] = sorted(
                set(
                    [
                        str(activity.key_fields.get("source") or "unknown"),
                        str(candidate.key_fields.get("source") or "unknown"),
                    ]
                )
            )
            if candidate.key_fields.get("run_count") and not activity.key_fields.get("run_count"):
                activity.key_fields["run_count"] = candidate.key_fields.get("run_count")
            if candidate.key_fields.get("last_run") and not activity.key_fields.get("last_run"):
                activity.key_fields["last_run"] = candidate.key_fields.get("last_run")
            merged_ids.add(candidate.id)
    return [item for item in activities if item.id not in merged_ids]


def correlate_lnk_with_execution(activities: list[ForensicActivity], *, window_seconds: int = 1800) -> list[ForensicActivity]:
    execution_items = [item for item in activities if item.activity_type in {"program_execution", "powershell_execution"}]
    lnk_items = [item for item in activities if item.activity_type in {"opened_file", "script_opened"}]
    for execution in execution_items:
        exec_ts = _parse_iso(execution.timestamp)
        exec_host = _normalized_name(execution.host)
        exec_user = _normalized_name(execution.user)
        exec_name = _normalized_name(execution.key_fields.get("process_name"))
        exec_path = _normalized_name(execution.key_fields.get("process_path"))
        exec_cmd = _normalized_name(execution.key_fields.get("command_line"))
        if not exec_ts:
            continue
        for lnk in lnk_items:
            lnk_ts = _parse_iso(lnk.timestamp)
            if not lnk_ts:
                continue
            if abs((exec_ts - lnk_ts).total_seconds()) > window_seconds:
                continue
            lnk_host = _normalized_name(lnk.host)
            if exec_host and lnk_host and exec_host != lnk_host:
                continue
            lnk_user = _normalized_name(lnk.user)
            lnk_path = _normalized_name(lnk.key_fields.get("file_path"))
            lnk_name = _normalized_name(Path(str(lnk_path)).name if lnk_path else None)
            if exec_user and lnk_user and exec_user != lnk_user:
                pass
            path_match = bool(lnk_path and (lnk_path == exec_path or lnk_path in exec_cmd))
            name_match = bool(lnk_name and exec_name and lnk_name == exec_name)
            if not path_match and not name_match:
                continue
            execution.evidence_refs = sorted(set(execution.evidence_refs + lnk.evidence_refs))
            execution.related_events = sorted(set(execution.related_events + lnk.related_events))
            execution.tags = sorted(set(execution.tags + lnk.tags + ["lnk_correlated"]))
            execution.suspicious_reasons = sorted(set(execution.suspicious_reasons + lnk.suspicious_reasons))
            execution.confidence = max(execution.confidence, 0.95 if path_match else 0.88)
            execution.key_fields["lnk_source"] = lnk.key_fields.get("source_lnk")
            execution.key_fields["source_jumplist"] = lnk.key_fields.get("source_jumplist")
            execution.key_fields["lnk_target_path"] = lnk.key_fields.get("file_path")
            execution.key_fields["file_access_target_path"] = lnk.key_fields.get("file_path")
    return activities


def correlate_registry_persistence_sources(activities: list[ForensicActivity], *, window_seconds: int = 1800) -> list[ForensicActivity]:
    persistence_items = [item for item in activities if item.activity_type in {"persistence", "service_modified"}]
    execution_items = [item for item in activities if item.activity_type in {"program_execution", "powershell_execution", "service_created", "service_modified"}]
    for persistence in persistence_items:
        persistence_ts = _parse_iso(persistence.timestamp)
        persistence_host = _normalized_name(persistence.host)
        path_hint = _normalized_name(
            persistence.key_fields.get("path")
            or persistence.key_fields.get("command")
            or persistence.key_fields.get("image_path")
            or persistence.key_fields.get("service_dll")
        )
        service_name = _normalized_name(persistence.key_fields.get("service_name"))
        if not persistence_ts and not path_hint and not service_name:
            continue
        for candidate in execution_items:
            if candidate.id == persistence.id:
                continue
            candidate_ts = _parse_iso(candidate.timestamp)
            candidate_host = _normalized_name(candidate.host)
            if persistence_host and candidate_host and persistence_host != candidate_host:
                continue
            if persistence_ts and candidate_ts and abs((candidate_ts - persistence_ts).total_seconds()) > window_seconds:
                continue
            candidate_path = _normalized_name(
                candidate.key_fields.get("process_path")
                or candidate.key_fields.get("command_line")
                or candidate.key_fields.get("image_path")
            )
            candidate_service = _normalized_name(candidate.key_fields.get("service_name"))
            path_match = bool(path_hint and candidate_path and (path_hint == candidate_path or path_hint in candidate_path or candidate_path in path_hint))
            service_match = bool(service_name and candidate_service and service_name == candidate_service)
            if not path_match and not service_match:
                continue
            persistence.evidence_refs = sorted(set(persistence.evidence_refs + candidate.evidence_refs))
            persistence.related_events = sorted(set(persistence.related_events + candidate.related_events))
            persistence.tags = sorted(set(persistence.tags + candidate.tags + ["registry_correlated"]))
            persistence.suspicious_reasons = sorted(set(persistence.suspicious_reasons + candidate.suspicious_reasons))
            persistence.confidence = max(persistence.confidence, 0.94 if path_match else 0.9)
    return activities


def correlate_file_access_sources(activities: list[ForensicActivity], *, window_seconds: int = 1800) -> list[ForensicActivity]:
    file_access_items = [item for item in activities if item.activity_type in {"opened_file", "script_opened"}]
    merged_ids: set[str] = set()
    for index, activity in enumerate(file_access_items):
        if activity.id in merged_ids:
            continue
        current_ts = _parse_iso(activity.timestamp)
        current_path = _normalized_name(activity.key_fields.get("file_path"))
        current_host = _normalized_name(activity.host)
        current_source = _normalized_name(activity.key_fields.get("source"))
        if not current_ts or not current_path:
            continue
        for candidate in file_access_items[index + 1 :]:
            if candidate.id in merged_ids or candidate.activity_type != activity.activity_type:
                continue
            candidate_ts = _parse_iso(candidate.timestamp)
            candidate_path = _normalized_name(candidate.key_fields.get("file_path"))
            candidate_host = _normalized_name(candidate.host)
            candidate_source = _normalized_name(candidate.key_fields.get("source"))
            if not candidate_ts or not candidate_path or current_path != candidate_path:
                continue
            if current_host and candidate_host and current_host != candidate_host:
                continue
            if current_source == candidate_source:
                continue
            if abs((candidate_ts - current_ts).total_seconds()) > window_seconds:
                continue
            activity.evidence_refs = sorted(set(activity.evidence_refs + candidate.evidence_refs))
            activity.related_events = sorted(set(activity.related_events + candidate.related_events))
            activity.tags = sorted(set(activity.tags + candidate.tags + ["correlated_file_access"]))
            activity.suspicious_reasons = sorted(set(activity.suspicious_reasons + candidate.suspicious_reasons))
            activity.confidence = max(activity.confidence, candidate.confidence, 0.9)
            activity.key_fields["correlated_sources"] = sorted(set([current_source or "unknown", candidate_source or "unknown"]))
            if candidate.key_fields.get("source_lnk") and not activity.key_fields.get("source_lnk"):
                activity.key_fields["source_lnk"] = candidate.key_fields.get("source_lnk")
            if candidate.key_fields.get("source_jumplist") and not activity.key_fields.get("source_jumplist"):
                activity.key_fields["source_jumplist"] = candidate.key_fields.get("source_jumplist")
            merged_ids.add(candidate.id)
    return [item for item in activities if item.id not in merged_ids]


def correlate_browser_downloads(activities: list[ForensicActivity], *, window_seconds: int = 1800) -> list[ForensicActivity]:
    downloads = [item for item in activities if item.activity_type == "file_download"]
    file_creations = [item for item in activities if item.activity_type == "file_created"]
    file_accesses = [item for item in activities if item.activity_type in {"opened_file", "script_opened"}]
    executions = [item for item in activities if item.activity_type in {"program_execution", "powershell_execution", "execution_candidate"}]
    defender = [item for item in activities if item.activity_type in {"defender_detection", "defender_action"}]
    new_activities: list[ForensicActivity] = []

    for download in downloads:
        download_path = _normalized_name(download.key_fields.get("file_path"))
        download_name = _normalized_name(download.key_fields.get("file_name"))
        download_ts = _parse_iso(download.timestamp)
        download_host = _normalized_name(download.host)
        if not download_path and not download_name:
            continue
        matched_creation = None
        matched_execution = None
        for candidate in file_creations:
            candidate_ts = _parse_iso(candidate.timestamp)
            candidate_path = _normalized_name(candidate.key_fields.get("file_path"))
            candidate_name = _normalized_name(candidate.key_fields.get("file_name"))
            candidate_host = _normalized_name(candidate.host)
            if download_host and candidate_host and download_host != candidate_host:
                continue
            if download_ts and candidate_ts and abs((candidate_ts - download_ts).total_seconds()) > window_seconds:
                continue
            if (download_path and candidate_path and download_path == candidate_path) or (download_name and candidate_name and download_name == candidate_name):
                matched_creation = candidate
                break
        for candidate in executions:
            candidate_ts = _parse_iso(candidate.timestamp)
            candidate_host = _normalized_name(candidate.host)
            process_path = _normalized_name(candidate.key_fields.get("process_path"))
            process_name = _normalized_name(candidate.key_fields.get("process_name"))
            command_line = _normalized_name(candidate.key_fields.get("command_line"))
            if download_host and candidate_host and download_host != candidate_host:
                continue
            if download_ts and candidate_ts and abs((candidate_ts - download_ts).total_seconds()) > window_seconds:
                continue
            if (download_path and (download_path == process_path or download_path in command_line)) or (download_name and download_name == process_name):
                matched_execution = candidate
                break
        for candidate in file_accesses:
            candidate_ts = _parse_iso(candidate.timestamp)
            candidate_host = _normalized_name(candidate.host)
            candidate_path = _normalized_name(candidate.key_fields.get("file_path"))
            if download_host and candidate_host and download_host != candidate_host:
                continue
            if download_ts and candidate_ts and abs((candidate_ts - download_ts).total_seconds()) > window_seconds:
                continue
            if download_path and candidate_path and download_path == candidate_path:
                download.evidence_refs = sorted(set(download.evidence_refs + candidate.evidence_refs))
                download.related_events = sorted(set(download.related_events + candidate.related_events))
                download.tags = sorted(set(download.tags + candidate.tags + ["browser_download_opened"]))
                download.confidence = max(download.confidence, 0.86)
        for candidate in defender:
            candidate_path = _normalized_name(candidate.key_fields.get("path"))
            if download_path and candidate_path and download_path == candidate_path:
                download.evidence_refs = sorted(set(download.evidence_refs + candidate.evidence_refs))
                download.related_events = sorted(set(download.related_events + candidate.related_events))
                download.tags = sorted(set(download.tags + candidate.tags + ["defender_correlated"]))
                download.confidence = max(download.confidence, 0.95)
                download.suspicious_reasons = sorted(set(download.suspicious_reasons + ["Downloaded file matched Defender detection"]))
        if matched_creation:
            download.evidence_refs = sorted(set(download.evidence_refs + matched_creation.evidence_refs))
            download.related_events = sorted(set(download.related_events + matched_creation.related_events))
            download.tags = sorted(set(download.tags + matched_creation.tags + ["mft_correlated"]))
            download.confidence = max(download.confidence, 0.88)
        if matched_execution:
            download.evidence_refs = sorted(set(download.evidence_refs + matched_execution.evidence_refs))
            download.related_events = sorted(set(download.related_events + matched_execution.related_events))
            download.tags = sorted(set(download.tags + matched_execution.tags + ["executed_after_download"]))
            download.confidence = max(download.confidence, 0.96)
            new_activities.append(
                ForensicActivity(
                    id=str(uuid4()),
                    activity_type="downloaded_and_executed",
                    title=f"Downloaded and executed: {download.key_fields.get('file_name') or download.key_fields.get('file_path') or 'file'}",
                    timestamp=download.timestamp,
                    host=download.host,
                    user=download.user,
                    summary=download.summary,
                    severity=download.severity,
                    confidence=0.96 if matched_creation else 0.92,
                    tags=sorted(set(download.tags + ["download", "execution_related"])),
                    key_fields={
                        **download.key_fields,
                        "created_file_event": matched_creation.id if matched_creation else None,
                        "executed_event": matched_execution.id,
                    },
                    evidence_refs=sorted(set(download.evidence_refs + matched_execution.evidence_refs + (matched_creation.evidence_refs if matched_creation else []))),
                    related_events=sorted(set(download.related_events + matched_execution.related_events + (matched_creation.related_events if matched_creation else []))),
                    suspicious_reasons=sorted(set(download.suspicious_reasons + matched_execution.suspicious_reasons)),
                )
            )
    return activities + new_activities


def correlate_powershell_usage(activities: list[ForensicActivity], *, window_seconds: int = 7200) -> list[ForensicActivity]:
    powershell_items = [item for item in activities if item.activity_type in {"powershell_execution", "powershell_download", "powershell_encoded_execution", "powershell_defender_tampering", "powershell_persistence", "powershell_recon", "powershell_credential_access"}]
    downloads = [item for item in activities if item.activity_type == "file_download"]
    executions = [item for item in activities if item.activity_type == "program_execution"]
    defender = [item for item in activities if item.activity_type in {"defender_detection", "defender_action"}]
    scheduled_tasks = [item for item in activities if item.activity_type in {"scheduled_task_definition", "scheduled_task_com_handler", "scheduled_task"}]
    srum_items = [item for item in activities if item.activity_type == "application_network_usage"]
    file_items = [item for item in activities if item.activity_type in {"file_created", "file_modified"}]
    new_activities: list[ForensicActivity] = []

    for item in powershell_items:
        item_ts = _parse_iso(item.timestamp)
        item_host = _normalized_name(item.host)
        command = _normalized_name(item.key_fields.get("command_line"))
        item_url = _normalized_name(item.key_fields.get("url"))
        item_domain = _normalized_name(item.key_fields.get("domain"))
        item_paths = [_normalized_name(path) for path in (item.key_fields.get("paths") or []) if path]
        matched_download = None
        matched_execution = None
        matched_defender = None
        matched_task = None
        matched_srum = None
        matched_file = None

        for candidate in downloads:
            candidate_host = _normalized_name(candidate.host)
            candidate_ts = _parse_iso(candidate.timestamp)
            candidate_path = _normalized_name(candidate.key_fields.get("file_path"))
            candidate_url = _normalized_name(candidate.key_fields.get("url"))
            candidate_domain = _normalized_name(candidate.key_fields.get("domain"))
            if item_host and candidate_host and item_host != candidate_host:
                continue
            if item_ts and candidate_ts and abs((candidate_ts - item_ts).total_seconds()) > window_seconds:
                continue
            if (item_url and candidate_url and item_url == candidate_url) or (item_domain and candidate_domain and item_domain == candidate_domain) or any(path and candidate_path and path == candidate_path for path in item_paths):
                matched_download = candidate
                break

        for candidate in executions:
            candidate_host = _normalized_name(candidate.host)
            candidate_ts = _parse_iso(candidate.timestamp)
            candidate_name = _normalized_name(candidate.key_fields.get("process_name"))
            candidate_cmd = _normalized_name(candidate.key_fields.get("command_line"))
            if item_host and candidate_host and item_host != candidate_host:
                continue
            if item_ts and candidate_ts and abs((candidate_ts - item_ts).total_seconds()) > window_seconds:
                continue
            if ("powershell" in candidate_name or "pwsh" in candidate_name) and (not command or (command and (command in candidate_cmd or candidate_cmd in command))):
                matched_execution = candidate
                break

        for candidate in defender:
            candidate_host = _normalized_name(candidate.host)
            candidate_path = _normalized_name(candidate.key_fields.get("path"))
            if item_host and candidate_host and item_host != candidate_host:
                continue
            if any(path and candidate_path and path == candidate_path for path in item_paths):
                matched_defender = candidate
                break

        for candidate in scheduled_tasks:
            candidate_host = _normalized_name(candidate.host)
            run_blob = _normalized_name(" ".join(filter(None, [candidate.key_fields.get("command"), candidate.key_fields.get("arguments")])))
            if item_host and candidate_host and item_host != candidate_host:
                continue
            if command and run_blob and any(token in run_blob for token in [command] + item_paths):
                matched_task = candidate
                break

        for candidate in srum_items:
            candidate_host = _normalized_name(candidate.host)
            candidate_ts = _parse_iso(candidate.timestamp)
            candidate_process = _normalized_name(candidate.key_fields.get("process_name"))
            if item_host and candidate_host and item_host != candidate_host:
                continue
            if item_ts and candidate_ts and abs((candidate_ts - item_ts).total_seconds()) > window_seconds:
                continue
            if candidate_process in {"powershell.exe", "pwsh.exe"}:
                matched_srum = candidate
                break

        for candidate in file_items:
            candidate_host = _normalized_name(candidate.host)
            candidate_path = _normalized_name(candidate.key_fields.get("file_path"))
            if item_host and candidate_host and item_host != candidate_host:
                continue
            if any(path and candidate_path and path == candidate_path for path in item_paths):
                matched_file = candidate
                break

        if matched_download:
            item.evidence_refs = sorted(set(item.evidence_refs + matched_download.evidence_refs))
            item.related_events = sorted(set(item.related_events + matched_download.related_events))
            item.tags = sorted(set(item.tags + matched_download.tags + ["browser_download_correlated"]))
            item.confidence = max(item.confidence, 0.82)
            if item.activity_type == "powershell_download":
                new_activities.append(
                    ForensicActivity(
                        id=str(uuid4()),
                        activity_type="downloaded_and_executed_via_powershell",
                        title="Downloaded via PowerShell",
                        timestamp=item.timestamp or matched_download.timestamp,
                        host=item.host,
                        user=item.user,
                        summary=item.summary,
                        severity=item.severity,
                        confidence=0.84,
                        tags=sorted(set(item.tags + ["download", "powershell"])),
                        key_fields={**item.key_fields, "download_event": matched_download.id, "download_domain": matched_download.key_fields.get("domain")},
                        evidence_refs=sorted(set(item.evidence_refs + matched_download.evidence_refs)),
                        related_events=sorted(set(item.related_events + matched_download.related_events)),
                        suspicious_reasons=sorted(set(item.suspicious_reasons + matched_download.suspicious_reasons)),
                    )
                )
        if matched_execution:
            item.evidence_refs = sorted(set(item.evidence_refs + matched_execution.evidence_refs))
            item.related_events = sorted(set(item.related_events + matched_execution.related_events))
            item.tags = sorted(set(item.tags + matched_execution.tags + ["execution_correlated"]))
            item.confidence = max(item.confidence, 0.92)
        if matched_defender:
            item.evidence_refs = sorted(set(item.evidence_refs + matched_defender.evidence_refs))
            item.related_events = sorted(set(item.related_events + matched_defender.related_events))
            item.tags = sorted(set(item.tags + matched_defender.tags + ["defender_correlated"]))
            item.confidence = max(item.confidence, 0.9)
        if matched_task:
            item.evidence_refs = sorted(set(item.evidence_refs + matched_task.evidence_refs))
            item.related_events = sorted(set(item.related_events + matched_task.related_events))
            item.tags = sorted(set(item.tags + matched_task.tags + ["scheduled_task_correlated"]))
            item.confidence = max(item.confidence, 0.86)
        if matched_srum:
            item.evidence_refs = sorted(set(item.evidence_refs + matched_srum.evidence_refs))
            item.related_events = sorted(set(item.related_events + matched_srum.related_events))
            item.tags = sorted(set(item.tags + matched_srum.tags + ["srum_correlated"]))
            item.confidence = max(item.confidence, 0.8)
        if matched_file:
            item.evidence_refs = sorted(set(item.evidence_refs + matched_file.evidence_refs))
            item.related_events = sorted(set(item.related_events + matched_file.related_events))
            item.tags = sorted(set(item.tags + matched_file.tags + ["filesystem_correlated"]))
            item.confidence = max(item.confidence, 0.78)
    return activities + new_activities


def correlate_execution_artifacts(activities: list[ForensicActivity], *, window_seconds: int = 86400) -> list[ForensicActivity]:
    observed = [item for item in activities if item.activity_type in {"program_inventory", "execution_candidate"}]
    downloads = [item for item in activities if item.activity_type == "file_download"]
    files = [item for item in activities if item.activity_type in {"file_created", "file_modified"}]
    executions = [item for item in activities if item.activity_type in {"program_execution", "powershell_execution"}]
    defender = [item for item in activities if item.activity_type in {"defender_detection", "defender_action"}]
    new_activities: list[ForensicActivity] = []

    for item in observed:
        item_path = _normalized_name(item.key_fields.get("file_path"))
        item_name = _normalized_name(item.key_fields.get("file_name"))
        item_sha1 = _normalized_name(item.key_fields.get("hash_sha1"))
        item_sha256 = _normalized_name(item.key_fields.get("hash_sha256"))
        item_host = _normalized_name(item.host)
        item_ts = _parse_iso(item.timestamp)
        matched_download = None
        matched_execution = None
        matched_file = None
        matched_defender = None

        for candidate in downloads:
            candidate_path = _normalized_name(candidate.key_fields.get("file_path"))
            candidate_name = _normalized_name(candidate.key_fields.get("file_name"))
            candidate_host = _normalized_name(candidate.host)
            candidate_ts = _parse_iso(candidate.timestamp)
            if item_host and candidate_host and item_host != candidate_host:
                continue
            if item_ts and candidate_ts and abs((candidate_ts - item_ts).total_seconds()) > window_seconds:
                continue
            if (item_path and candidate_path and item_path == candidate_path) or (item_name and candidate_name and item_name == candidate_name):
                matched_download = candidate
                break

        for candidate in files:
            candidate_path = _normalized_name(candidate.key_fields.get("file_path"))
            candidate_name = _normalized_name(candidate.key_fields.get("file_name"))
            candidate_host = _normalized_name(candidate.host)
            if item_host and candidate_host and item_host != candidate_host:
                continue
            if (item_path and candidate_path and item_path == candidate_path) or (item_name and candidate_name and item_name == candidate_name):
                matched_file = candidate
                break

        for candidate in executions:
            candidate_path = _normalized_name(candidate.key_fields.get("process_path"))
            candidate_name = _normalized_name(candidate.key_fields.get("process_name"))
            candidate_cmd = _normalized_name(candidate.key_fields.get("command_line"))
            candidate_host = _normalized_name(candidate.host)
            if item_host and candidate_host and item_host != candidate_host:
                continue
            if (item_path and (item_path == candidate_path or item_path in candidate_cmd)) or (item_name and candidate_name and item_name == candidate_name):
                matched_execution = candidate
                break

        for candidate in defender:
            candidate_path = _normalized_name(candidate.key_fields.get("path"))
            candidate_host = _normalized_name(candidate.host)
            if item_host and candidate_host and item_host != candidate_host:
                continue
            if item_path and candidate_path and item_path == candidate_path:
                matched_defender = candidate
                break

        if matched_download:
            item.evidence_refs = sorted(set(item.evidence_refs + matched_download.evidence_refs))
            item.related_events = sorted(set(item.related_events + matched_download.related_events))
            item.tags = sorted(set(item.tags + matched_download.tags + ["browser_download_correlated"]))
            item.confidence = max(item.confidence, 0.7)
            new_activities.append(
                ForensicActivity(
                    id=str(uuid4()),
                    activity_type="downloaded_and_observed_program",
                    title=f"Downloaded and observed: {item.key_fields.get('file_name') or item.key_fields.get('file_path') or 'program'}",
                    timestamp=matched_download.timestamp or item.timestamp,
                    host=item.host,
                    user=item.user,
                    summary=item.summary,
                    severity=item.severity,
                    confidence=0.82 if matched_file else 0.74,
                    tags=sorted(set(item.tags + matched_download.tags + ["download", "execution_artifact"])),
                    key_fields={
                        **item.key_fields,
                        "download_event": matched_download.id,
                        "download_domain": matched_download.key_fields.get("domain"),
                    },
                    evidence_refs=sorted(set(item.evidence_refs + matched_download.evidence_refs + (matched_file.evidence_refs if matched_file else []))),
                    related_events=sorted(set(item.related_events + matched_download.related_events + (matched_file.related_events if matched_file else []))),
                    suspicious_reasons=sorted(set(item.suspicious_reasons + matched_download.suspicious_reasons)),
                )
            )

        if matched_file:
            item.evidence_refs = sorted(set(item.evidence_refs + matched_file.evidence_refs))
            item.related_events = sorted(set(item.related_events + matched_file.related_events))
            item.tags = sorted(set(item.tags + matched_file.tags + ["filesystem_correlated"]))
            item.confidence = max(item.confidence, 0.76)

        if matched_execution:
            item.evidence_refs = sorted(set(item.evidence_refs + matched_execution.evidence_refs))
            item.related_events = sorted(set(item.related_events + matched_execution.related_events))
            item.tags = sorted(set(item.tags + matched_execution.tags + ["execution_correlated"]))
            item.confidence = max(item.confidence, 0.93)
            item.key_fields["executed_event"] = matched_execution.id
            item.key_fields["execution_source"] = matched_execution.key_fields.get("source")

        if matched_defender:
            item.evidence_refs = sorted(set(item.evidence_refs + matched_defender.evidence_refs))
            item.related_events = sorted(set(item.related_events + matched_defender.related_events))
            item.tags = sorted(set(item.tags + matched_defender.tags + ["defender_correlated"]))
            item.confidence = max(item.confidence, 0.95)

    return activities + new_activities


def correlate_srum_usage(activities: list[ForensicActivity], *, window_seconds: int = 7200) -> list[ForensicActivity]:
    srum_items = [item for item in activities if item.activity_type == "application_network_usage"]
    downloads = [item for item in activities if item.activity_type == "file_download"]
    executions = [item for item in activities if item.activity_type in {"program_execution", "powershell_execution"}]
    observed = [item for item in activities if item.activity_type in {"program_inventory", "execution_candidate"}]
    new_activities: list[ForensicActivity] = []

    for item in srum_items:
        process_name = _normalized_name(item.key_fields.get("process_name") or item.key_fields.get("application"))
        process_path = _normalized_name(item.key_fields.get("process_path"))
        item_ts = _parse_iso(item.timestamp)
        item_host = _normalized_name(item.host)
        if not process_name and not process_path:
            continue

        matched_execution = None
        matched_observed = None
        matched_download = None

        for candidate in executions:
            candidate_host = _normalized_name(candidate.host)
            candidate_ts = _parse_iso(candidate.timestamp)
            candidate_name = _normalized_name(candidate.key_fields.get("process_name"))
            candidate_path = _normalized_name(candidate.key_fields.get("process_path"))
            candidate_cmd = _normalized_name(candidate.key_fields.get("command_line"))
            if item_host and candidate_host and item_host != candidate_host:
                continue
            if item_ts and candidate_ts and abs((candidate_ts - item_ts).total_seconds()) > window_seconds:
                continue
            if (process_path and (process_path == candidate_path or process_path in candidate_cmd)) or (process_name and process_name == candidate_name):
                matched_execution = candidate
                break

        for candidate in observed:
            candidate_host = _normalized_name(candidate.host)
            candidate_name = _normalized_name(candidate.key_fields.get("file_name"))
            candidate_path = _normalized_name(candidate.key_fields.get("file_path"))
            if item_host and candidate_host and item_host != candidate_host:
                continue
            if (process_path and process_path == candidate_path) or (process_name and process_name == candidate_name):
                matched_observed = candidate
                break

        for candidate in downloads:
            candidate_host = _normalized_name(candidate.host)
            candidate_ts = _parse_iso(candidate.timestamp)
            candidate_name = _normalized_name(candidate.key_fields.get("file_name"))
            candidate_path = _normalized_name(candidate.key_fields.get("file_path"))
            if item_host and candidate_host and item_host != candidate_host:
                continue
            if item_ts and candidate_ts and abs((candidate_ts - item_ts).total_seconds()) > window_seconds:
                continue
            if (process_path and process_path == candidate_path) or (process_name and process_name == candidate_name):
                matched_download = candidate
                break

        if matched_execution:
            item.evidence_refs = sorted(set(item.evidence_refs + matched_execution.evidence_refs))
            item.related_events = sorted(set(item.related_events + matched_execution.related_events))
            item.tags = sorted(set(item.tags + matched_execution.tags + ["execution_correlated"]))
            item.confidence = max(item.confidence, 0.88)

        if matched_observed:
            item.evidence_refs = sorted(set(item.evidence_refs + matched_observed.evidence_refs))
            item.related_events = sorted(set(item.related_events + matched_observed.related_events))
            item.tags = sorted(set(item.tags + matched_observed.tags + ["execution_artifact_correlated"]))
            item.confidence = max(item.confidence, 0.76)

        if matched_download:
            item.evidence_refs = sorted(set(item.evidence_refs + matched_download.evidence_refs))
            item.related_events = sorted(set(item.related_events + matched_download.related_events))
            item.tags = sorted(set(item.tags + matched_download.tags + ["browser_download_correlated", "downloaded_and_network_active"]))
            item.confidence = max(item.confidence, 0.74)
            new_activities.append(
                ForensicActivity(
                    id=str(uuid4()),
                    activity_type="downloaded_and_network_active_program",
                    title=f"Downloaded and network active: {item.key_fields.get('process_name') or item.key_fields.get('application') or 'program'}",
                    timestamp=item.timestamp or matched_download.timestamp,
                    host=item.host,
                    user=item.user,
                    summary=item.summary,
                    severity=item.severity,
                    confidence=0.84 if matched_execution else 0.75,
                    tags=sorted(set(item.tags + matched_download.tags + ["network", "download"])),
                    key_fields={
                        **item.key_fields,
                        "download_event": matched_download.id,
                        "download_domain": matched_download.key_fields.get("domain"),
                        "execution_event": matched_execution.id if matched_execution else None,
                    },
                    evidence_refs=sorted(set(item.evidence_refs + matched_download.evidence_refs + (matched_execution.evidence_refs if matched_execution else []))),
                    related_events=sorted(set(item.related_events + matched_download.related_events + (matched_execution.related_events if matched_execution else []))),
                    suspicious_reasons=sorted(set(item.suspicious_reasons + matched_download.suspicious_reasons + (matched_execution.suspicious_reasons if matched_execution else []))),
                )
            )

    return activities + new_activities


def correlate_scheduled_tasks(activities: list[ForensicActivity], *, window_seconds: int = 7200) -> list[ForensicActivity]:
    definitions = [item for item in activities if item.activity_type in {"scheduled_task_definition", "scheduled_task_com_handler", "scheduled_task"}]
    task_events = [item for item in activities if item.activity_type in {"scheduled_task_created", "scheduled_task_updated", "scheduled_task_action_started", "scheduled_task_action_completed"}]
    downloads = [item for item in activities if item.activity_type == "file_download"]
    executions = [item for item in activities if item.activity_type in {"program_execution", "powershell_execution"}]
    observed = [item for item in activities if item.activity_type in {"program_inventory", "execution_candidate"}]
    new_activities: list[ForensicActivity] = []

    for item in definitions:
        item_ts = _parse_iso(item.timestamp)
        item_host = _normalized_name(item.host)
        task_name = _normalized_name(item.key_fields.get("task_name"))
        task_path = _normalized_name(item.key_fields.get("task_path"))
        command = _normalized_name(item.key_fields.get("command"))
        arguments = _normalized_name(item.key_fields.get("arguments"))
        run_blob = " ".join(part for part in [command, arguments] if part)
        matched_event = None
        matched_execution = None
        matched_download = None
        matched_observed = None

        for candidate in task_events:
            candidate_host = _normalized_name(candidate.host)
            candidate_ts = _parse_iso(candidate.timestamp)
            candidate_name = _normalized_name(candidate.key_fields.get("task_name"))
            if item_host and candidate_host and item_host != candidate_host:
                continue
            if item_ts and candidate_ts and abs((candidate_ts - item_ts).total_seconds()) > window_seconds:
                continue
            if task_name and candidate_name and task_name == candidate_name:
                matched_event = candidate
                break

        for candidate in executions:
            candidate_host = _normalized_name(candidate.host)
            candidate_ts = _parse_iso(candidate.timestamp)
            candidate_name = _normalized_name(candidate.key_fields.get("process_name"))
            candidate_path = _normalized_name(candidate.key_fields.get("process_path"))
            candidate_cmd = _normalized_name(candidate.key_fields.get("command_line"))
            if item_host and candidate_host and item_host != candidate_host:
                continue
            if item_ts and candidate_ts and abs((candidate_ts - item_ts).total_seconds()) > window_seconds:
                continue
            if (command and (command == candidate_path or command in candidate_cmd)) or (candidate_name and Path(command or "").name.lower() == candidate_name):
                matched_execution = candidate
                break

        for candidate in observed:
            candidate_host = _normalized_name(candidate.host)
            candidate_name = _normalized_name(candidate.key_fields.get("file_name"))
            candidate_path = _normalized_name(candidate.key_fields.get("file_path"))
            if item_host and candidate_host and item_host != candidate_host:
                continue
            if (command and command == candidate_path) or (command and candidate_name and Path(command).name.lower() == candidate_name):
                matched_observed = candidate
                break

        for candidate in downloads:
            candidate_host = _normalized_name(candidate.host)
            candidate_ts = _parse_iso(candidate.timestamp)
            candidate_name = _normalized_name(candidate.key_fields.get("file_name"))
            candidate_path = _normalized_name(candidate.key_fields.get("file_path"))
            if item_host and candidate_host and item_host != candidate_host:
                continue
            if item_ts and candidate_ts and abs((candidate_ts - item_ts).total_seconds()) > 86400:
                continue
            if (command and candidate_path and command == candidate_path) or (run_blob and candidate_path and candidate_path in run_blob) or (command and candidate_name and Path(command).name.lower() == candidate_name):
                matched_download = candidate
                break

        if matched_event:
            item.evidence_refs = sorted(set(item.evidence_refs + matched_event.evidence_refs))
            item.related_events = sorted(set(item.related_events + matched_event.related_events))
            item.tags = sorted(set(item.tags + matched_event.tags + ["task_event_correlated"]))
            item.confidence = max(item.confidence, 0.9)
        if matched_observed:
            item.evidence_refs = sorted(set(item.evidence_refs + matched_observed.evidence_refs))
            item.related_events = sorted(set(item.related_events + matched_observed.related_events))
            item.tags = sorted(set(item.tags + matched_observed.tags + ["execution_artifact_correlated"]))
            item.confidence = max(item.confidence, 0.76)
        if matched_execution:
            item.evidence_refs = sorted(set(item.evidence_refs + matched_execution.evidence_refs))
            item.related_events = sorted(set(item.related_events + matched_execution.related_events))
            item.tags = sorted(set(item.tags + matched_execution.tags + ["task_execution_correlated"]))
            item.confidence = max(item.confidence, 0.95)
            new_activities.append(
                    ForensicActivity(
                        id=str(uuid4()),
                        activity_type="task_execution",
                        title=f"Scheduled task executed: {item.key_fields.get('task_name') or 'task'}",
                        timestamp=matched_execution.timestamp or (matched_event.timestamp if matched_event else None) or item.timestamp,
                    host=item.host,
                    user=item.user,
                    summary=item.summary,
                    severity=item.severity,
                    confidence=0.95,
                    tags=sorted(set(item.tags + matched_execution.tags + ["persistence", "execution_related"])),
                    key_fields={**item.key_fields, "executed_event": matched_execution.id},
                    evidence_refs=sorted(set(item.evidence_refs + matched_execution.evidence_refs)),
                    related_events=sorted(set(item.related_events + matched_execution.related_events)),
                    suspicious_reasons=sorted(set(item.suspicious_reasons + matched_execution.suspicious_reasons)),
                )
            )
        if matched_download:
            item.evidence_refs = sorted(set(item.evidence_refs + matched_download.evidence_refs))
            item.related_events = sorted(set(item.related_events + matched_download.related_events))
            item.tags = sorted(set(item.tags + matched_download.tags + ["browser_download_correlated"]))
            item.confidence = max(item.confidence, 0.82)
            new_activities.append(
                ForensicActivity(
                    id=str(uuid4()),
                    activity_type="downloaded_and_persisted",
                    title=f"Downloaded file persisted via task: {item.key_fields.get('task_name') or 'task'}",
                    timestamp=matched_download.timestamp or item.timestamp,
                    host=item.host,
                    user=item.user,
                    summary=item.summary,
                    severity=item.severity,
                    confidence=0.84 if matched_execution else 0.78,
                    tags=sorted(set(item.tags + matched_download.tags + ["download", "persistence"])),
                    key_fields={**item.key_fields, "download_event": matched_download.id, "download_domain": matched_download.key_fields.get("domain")},
                    evidence_refs=sorted(set(item.evidence_refs + matched_download.evidence_refs)),
                    related_events=sorted(set(item.related_events + matched_download.related_events)),
                    suspicious_reasons=sorted(set(item.suspicious_reasons + matched_download.suspicious_reasons)),
                )
            )

    return activities + new_activities


def correlate_defender_findings(activities: list[ForensicActivity], *, window_seconds: int = 86400) -> list[ForensicActivity]:
    defender_items = [item for item in activities if item.activity_type in {"defender_detection", "defender_action"}]
    downloads = [item for item in activities if item.activity_type == "file_download"]
    executions = [item for item in activities if item.activity_type in {"program_execution", "powershell_execution"}]
    persistence_items = [item for item in activities if item.activity_type in {"scheduled_task_definition", "scheduled_task_com_handler", "scheduled_task", "persistence", "service_modified"}]
    network_items = [item for item in activities if item.activity_type == "application_network_usage"]
    new_activities: list[ForensicActivity] = []

    for item in defender_items:
        item_path = _normalized_name(item.key_fields.get("path"))
        item_name = _normalized_name(Path(item_path).name if item_path else None)
        item_ts = _parse_iso(item.timestamp)
        item_host = _normalized_name(item.host)
        action = _normalized_name(item.key_fields.get("action"))
        status = _normalized_name(item.key_fields.get("status"))
        severity = _normalized_name(item.key_fields.get("severity"))

        matched_download = None
        matched_execution = None
        matched_persistence = None
        matched_network = None

        for candidate in downloads:
            candidate_path = _normalized_name(candidate.key_fields.get("file_path"))
            candidate_name = _normalized_name(candidate.key_fields.get("file_name"))
            candidate_host = _normalized_name(candidate.host)
            candidate_ts = _parse_iso(candidate.timestamp)
            if item_host and candidate_host and item_host != candidate_host:
                continue
            if item_ts and candidate_ts and abs((candidate_ts - item_ts).total_seconds()) > window_seconds:
                continue
            if (item_path and candidate_path and item_path == candidate_path) or (item_name and candidate_name and item_name == candidate_name):
                matched_download = candidate
                break

        for candidate in executions:
            candidate_path = _normalized_name(candidate.key_fields.get("process_path"))
            candidate_name = _normalized_name(candidate.key_fields.get("process_name"))
            candidate_cmd = _normalized_name(candidate.key_fields.get("command_line"))
            candidate_host = _normalized_name(candidate.host)
            candidate_ts = _parse_iso(candidate.timestamp)
            if item_host and candidate_host and item_host != candidate_host:
                continue
            if item_ts and candidate_ts and abs((candidate_ts - item_ts).total_seconds()) > window_seconds:
                continue
            if (item_path and (item_path == candidate_path or item_path in candidate_cmd)) or (item_name and candidate_name and item_name == candidate_name):
                matched_execution = candidate
                break

        for candidate in persistence_items:
            candidate_host = _normalized_name(candidate.host)
            if item_host and candidate_host and item_host != candidate_host:
                continue
            run_blob = _normalized_name(
                candidate.key_fields.get("command")
                or candidate.key_fields.get("path")
                or candidate.key_fields.get("image_path")
                or candidate.key_fields.get("service_dll")
            )
            if (item_path and run_blob and item_path in run_blob) or (item_name and run_blob and item_name in run_blob):
                matched_persistence = candidate
                break

        for candidate in network_items:
            candidate_host = _normalized_name(candidate.host)
            if item_host and candidate_host and item_host != candidate_host:
                continue
            candidate_path = _normalized_name(candidate.key_fields.get("process_path"))
            candidate_name = _normalized_name(candidate.key_fields.get("process_name") or candidate.key_fields.get("application"))
            if (item_path and candidate_path and item_path == candidate_path) or (item_name and candidate_name and item_name == candidate_name):
                matched_network = candidate
                break

        if matched_download:
            item.evidence_refs = sorted(set(item.evidence_refs + matched_download.evidence_refs))
            item.related_events = sorted(set(item.related_events + matched_download.related_events))
            item.tags = sorted(set(item.tags + matched_download.tags + ["browser_download_correlated"]))
            item.confidence = max(item.confidence, 0.9)
            new_activities.append(
                ForensicActivity(
                    id=str(uuid4()),
                    activity_type="detected_downloaded_file",
                    title=f"Detected downloaded file: {item.key_fields.get('threat_name') or item.key_fields.get('path') or 'file'}",
                    timestamp=item.timestamp or matched_download.timestamp,
                    host=item.host,
                    user=item.user,
                    summary=item.summary,
                    severity=item.severity,
                    confidence=0.9,
                    tags=sorted(set(item.tags + matched_download.tags + ["defender_correlated", "download"])),
                    key_fields={**item.key_fields, "download_event": matched_download.id, "download_domain": matched_download.key_fields.get("domain")},
                    evidence_refs=sorted(set(item.evidence_refs + matched_download.evidence_refs)),
                    related_events=sorted(set(item.related_events + matched_download.related_events)),
                    suspicious_reasons=sorted(set(item.suspicious_reasons + matched_download.suspicious_reasons)),
                )
            )

        if matched_execution:
            item.evidence_refs = sorted(set(item.evidence_refs + matched_execution.evidence_refs))
            item.related_events = sorted(set(item.related_events + matched_execution.related_events))
            item.tags = sorted(set(item.tags + matched_execution.tags + ["execution_correlated"]))
            item.confidence = max(item.confidence, 0.96)
            new_activities.append(
                ForensicActivity(
                    id=str(uuid4()),
                    activity_type="detected_executed_file",
                    title=f"Detected executed file: {item.key_fields.get('threat_name') or item.key_fields.get('path') or 'file'}",
                    timestamp=item.timestamp or matched_execution.timestamp,
                    host=item.host,
                    user=item.user,
                    summary=item.summary,
                    severity=item.severity,
                    confidence=0.96,
                    tags=sorted(set(item.tags + matched_execution.tags + ["execution_related", "defender_correlated"])),
                    key_fields={**item.key_fields, "executed_event": matched_execution.id},
                    evidence_refs=sorted(set(item.evidence_refs + matched_execution.evidence_refs)),
                    related_events=sorted(set(item.related_events + matched_execution.related_events)),
                    suspicious_reasons=sorted(set(item.suspicious_reasons + matched_execution.suspicious_reasons)),
                )
            )

        if matched_persistence:
            item.evidence_refs = sorted(set(item.evidence_refs + matched_persistence.evidence_refs))
            item.related_events = sorted(set(item.related_events + matched_persistence.related_events))
            item.tags = sorted(set(item.tags + matched_persistence.tags + ["persistence_correlated"]))
            item.confidence = max(item.confidence, 0.94)
            new_activities.append(
                ForensicActivity(
                    id=str(uuid4()),
                    activity_type="detected_persistent_file",
                    title=f"Detected persistent file: {item.key_fields.get('threat_name') or item.key_fields.get('path') or 'file'}",
                    timestamp=item.timestamp or matched_persistence.timestamp,
                    host=item.host,
                    user=item.user,
                    summary=item.summary,
                    severity=item.severity,
                    confidence=0.94,
                    tags=sorted(set(item.tags + matched_persistence.tags + ["persistence", "defender_correlated"])),
                    key_fields={**item.key_fields, "persistence_event": matched_persistence.id},
                    evidence_refs=sorted(set(item.evidence_refs + matched_persistence.evidence_refs)),
                    related_events=sorted(set(item.related_events + matched_persistence.related_events)),
                    suspicious_reasons=sorted(set(item.suspicious_reasons + matched_persistence.suspicious_reasons)),
                )
            )

        if matched_network:
            item.evidence_refs = sorted(set(item.evidence_refs + matched_network.evidence_refs))
            item.related_events = sorted(set(item.related_events + matched_network.related_events))
            item.tags = sorted(set(item.tags + matched_network.tags + ["network_correlated"]))
            item.confidence = max(item.confidence, 0.84)

        if "quarantine" in action or "quarantined" in action or "quarantine" in status:
            new_activities.append(
                ForensicActivity(
                    id=str(uuid4()),
                    activity_type="defender_quarantined_file",
                    title=f"Defender quarantined: {item.key_fields.get('threat_name') or item.key_fields.get('path') or 'file'}",
                    timestamp=item.timestamp,
                    host=item.host,
                    user=item.user,
                    summary=item.summary,
                    severity=item.severity,
                    confidence=max(item.confidence, 0.9),
                    tags=sorted(set(item.tags + ["quarantined"])),
                    key_fields=dict(item.key_fields),
                    evidence_refs=list(item.evidence_refs),
                    related_events=list(item.related_events),
                    suspicious_reasons=sorted(set(item.suspicious_reasons + ["Threat was quarantined"])),
                )
            )
        if "failed" in action or "failed" in status:
            new_activities.append(
                ForensicActivity(
                    id=str(uuid4()),
                    activity_type="defender_remediation_failed",
                    title=f"Defender remediation failed: {item.key_fields.get('threat_name') or item.key_fields.get('path') or 'file'}",
                    timestamp=item.timestamp,
                    host=item.host,
                    user=item.user,
                    summary=item.summary,
                    severity=item.severity,
                    confidence=max(item.confidence, 0.92),
                    tags=sorted(set(item.tags + ["remediation_failed"])),
                    key_fields=dict(item.key_fields),
                    evidence_refs=list(item.evidence_refs),
                    related_events=list(item.related_events),
                    suspicious_reasons=sorted(set(item.suspicious_reasons + ["Threat remediation failed"])),
                )
            )
        if any(token in action for token in {"removed", "cleaned", "remediated"}) or any(token in status for token in {"removed", "cleaned", "remediated"}):
            new_activities.append(
                ForensicActivity(
                    id=str(uuid4()),
                    activity_type="defender_remediated_threat",
                    title=f"Defender remediated: {item.key_fields.get('threat_name') or item.key_fields.get('path') or 'file'}",
                    timestamp=item.timestamp,
                    host=item.host,
                    user=item.user,
                    summary=item.summary,
                    severity=item.severity,
                    confidence=max(item.confidence, 0.88),
                    tags=sorted(set(item.tags + ["remediated"])),
                    key_fields=dict(item.key_fields),
                    evidence_refs=list(item.evidence_refs),
                    related_events=list(item.related_events),
                    suspicious_reasons=sorted(set(item.suspicious_reasons)),
                )
            )
        if severity in {"high", "severe", "critical"} and matched_network:
            item.tags = sorted(set(item.tags + ["defender_with_network_activity"]))

    return activities + new_activities


def correlate_recycle_bin(activities: list[ForensicActivity], *, window_seconds: int = 604800) -> list[ForensicActivity]:
    recycle_items = [item for item in activities if item.activity_type == "file_recycled"]
    downloads = [item for item in activities if item.activity_type == "file_download"]
    defender = [item for item in activities if item.activity_type in {"defender_detection", "defender_action"}]
    executions = [item for item in activities if item.activity_type in {"program_execution", "powershell_execution", "execution_candidate", "program_inventory"}]
    file_events = [item for item in activities if item.activity_type in {"file_deleted", "file_renamed", "file_modified", "file_created"}]
    persistence = [item for item in activities if item.activity_type in {"scheduled_task_definition", "scheduled_task_com_handler", "scheduled_task", "scheduled_task_created", "scheduled_task_updated", "persistence", "service_modified", "service_created"}]
    new_activities: list[ForensicActivity] = []

    for item in recycle_items:
        item_path = _normalized_name(item.key_fields.get("file_path"))
        item_name = _normalized_name(item.key_fields.get("file_name"))
        item_ts = _parse_iso(item.timestamp)
        item_host = _normalized_name(item.host)
        if not item_path and not item_name:
            continue

        matched_download = None
        matched_defender = None
        matched_execution = None
        matched_file = None
        matched_persistence = None

        for candidate in downloads:
            candidate_host = _normalized_name(candidate.host)
            candidate_ts = _parse_iso(candidate.timestamp)
            candidate_path = _normalized_name(candidate.key_fields.get("file_path"))
            candidate_name = _normalized_name(candidate.key_fields.get("file_name") or Path(str(candidate.key_fields.get("file_path") or "")).name)
            if item_host and candidate_host and item_host != candidate_host:
                continue
            if item_ts and candidate_ts and abs((candidate_ts - item_ts).total_seconds()) > window_seconds:
                continue
            if (item_path and candidate_path and item_path == candidate_path) or (item_name and candidate_name and item_name == candidate_name):
                matched_download = candidate
                break

        for candidate in defender:
            candidate_host = _normalized_name(candidate.host)
            candidate_path = _normalized_name(candidate.key_fields.get("path"))
            if item_host and candidate_host and item_host != candidate_host:
                continue
            if (item_path and candidate_path and item_path == candidate_path) or (item_name and _normalized_name(Path(candidate_path).name) == item_name):
                matched_defender = candidate
                break

        for candidate in executions:
            candidate_host = _normalized_name(candidate.host)
            candidate_ts = _parse_iso(candidate.timestamp)
            candidate_path = _normalized_name(candidate.key_fields.get("process_path") or candidate.key_fields.get("file_path"))
            candidate_name = _normalized_name(candidate.key_fields.get("process_name") or candidate.key_fields.get("file_name"))
            candidate_cmd = _normalized_name(candidate.key_fields.get("command_line"))
            if item_host and candidate_host and item_host != candidate_host:
                continue
            if item_ts and candidate_ts and abs((candidate_ts - item_ts).total_seconds()) > window_seconds:
                continue
            if (item_path and (item_path == candidate_path or item_path in candidate_cmd)) or (item_name and item_name == candidate_name):
                matched_execution = candidate
                break

        for candidate in file_events:
            candidate_host = _normalized_name(candidate.host)
            candidate_ts = _parse_iso(candidate.timestamp)
            candidate_path = _normalized_name(candidate.key_fields.get("file_path"))
            candidate_name = _normalized_name(candidate.key_fields.get("file_name"))
            if item_host and candidate_host and item_host != candidate_host:
                continue
            if item_ts and candidate_ts and abs((candidate_ts - item_ts).total_seconds()) > window_seconds:
                continue
            if (item_path and candidate_path and item_path == candidate_path) or (item_name and item_name == candidate_name):
                matched_file = candidate
                break

        for candidate in persistence:
            candidate_host = _normalized_name(candidate.host)
            candidate_command = _normalized_name(candidate.key_fields.get("command") or candidate.key_fields.get("path") or candidate.key_fields.get("command_line"))
            candidate_name = _normalized_name(candidate.key_fields.get("task_name") or candidate.key_fields.get("service_name"))
            if item_host and candidate_host and item_host != candidate_host:
                continue
            if (item_path and item_path in candidate_command) or (item_name and item_name in candidate_command) or (item_name and item_name == candidate_name):
                matched_persistence = candidate
                break

        if matched_download:
            item.evidence_refs = sorted(set(item.evidence_refs + matched_download.evidence_refs))
            item.related_events = sorted(set(item.related_events + matched_download.related_events))
            item.tags = sorted(set(item.tags + matched_download.tags + ["browser_download_correlated", "deleted_download"]))
            item.confidence = max(item.confidence, 0.9)
            new_activities.append(
                ForensicActivity(
                    id=str(uuid4()),
                    activity_type="deleted_download",
                    title=f"Deleted download: {item.key_fields.get('file_name') or item.key_fields.get('file_path') or 'file'}",
                    timestamp=item.timestamp or matched_download.timestamp,
                    host=item.host,
                    user=item.user,
                    summary=item.summary,
                    severity=item.severity,
                    confidence=0.9 if matched_file else 0.84,
                    tags=sorted(set(item.tags + matched_download.tags + ["recycle_bin", "download"])),
                    key_fields={**item.key_fields, "download_event": matched_download.id},
                    evidence_refs=sorted(set(item.evidence_refs + matched_download.evidence_refs + (matched_file.evidence_refs if matched_file else []))),
                    related_events=sorted(set(item.related_events + matched_download.related_events + (matched_file.related_events if matched_file else []))),
                    suspicious_reasons=sorted(set(item.suspicious_reasons + matched_download.suspicious_reasons)),
                )
            )

        if matched_defender:
            item.evidence_refs = sorted(set(item.evidence_refs + matched_defender.evidence_refs))
            item.related_events = sorted(set(item.related_events + matched_defender.related_events))
            item.tags = sorted(set(item.tags + matched_defender.tags + ["defender_correlated", "deleted_detected_file"]))
            item.confidence = max(item.confidence, 0.94)
            new_activities.append(
                ForensicActivity(
                    id=str(uuid4()),
                    activity_type="deleted_detected_file",
                    title=f"Deleted detected file: {item.key_fields.get('file_name') or item.key_fields.get('file_path') or 'file'}",
                    timestamp=item.timestamp or matched_defender.timestamp,
                    host=item.host,
                    user=item.user,
                    summary=item.summary,
                    severity=item.severity,
                    confidence=0.94,
                    tags=sorted(set(item.tags + matched_defender.tags + ["recycle_bin", "defender_correlated"])),
                    key_fields={**item.key_fields, "defender_event": matched_defender.id},
                    evidence_refs=sorted(set(item.evidence_refs + matched_defender.evidence_refs)),
                    related_events=sorted(set(item.related_events + matched_defender.related_events)),
                    suspicious_reasons=sorted(set(item.suspicious_reasons + matched_defender.suspicious_reasons)),
                )
            )

        if matched_execution:
            item.evidence_refs = sorted(set(item.evidence_refs + matched_execution.evidence_refs))
            item.related_events = sorted(set(item.related_events + matched_execution.related_events))
            item.tags = sorted(set(item.tags + matched_execution.tags + ["execution_correlated"]))
            item.confidence = max(item.confidence, 0.9)

        if matched_file:
            item.evidence_refs = sorted(set(item.evidence_refs + matched_file.evidence_refs))
            item.related_events = sorted(set(item.related_events + matched_file.related_events))
            item.tags = sorted(set(item.tags + matched_file.tags + ["filesystem_correlated"]))
            item.confidence = max(item.confidence, 0.96 if matched_file.activity_type == "file_deleted" else 0.86)

        if matched_persistence:
            item.evidence_refs = sorted(set(item.evidence_refs + matched_persistence.evidence_refs))
            item.related_events = sorted(set(item.related_events + matched_persistence.related_events))
            item.tags = sorted(set(item.tags + matched_persistence.tags + ["persistence_correlated"]))
            item.confidence = max(item.confidence, 0.88)
            new_activities.append(
                ForensicActivity(
                    id=str(uuid4()),
                    activity_type="deleted_persistent_file",
                    title=f"Deleted persistent file: {item.key_fields.get('file_name') or item.key_fields.get('file_path') or 'file'}",
                    timestamp=item.timestamp or matched_persistence.timestamp,
                    host=item.host,
                    user=item.user,
                    summary=item.summary,
                    severity=item.severity,
                    confidence=0.88,
                    tags=sorted(set(item.tags + matched_persistence.tags + ["recycle_bin", "persistence"])),
                    key_fields={**item.key_fields, "persistence_event": matched_persistence.id},
                    evidence_refs=sorted(set(item.evidence_refs + matched_persistence.evidence_refs)),
                    related_events=sorted(set(item.related_events + matched_persistence.related_events)),
                    suspicious_reasons=sorted(set(item.suspicious_reasons + matched_persistence.suspicious_reasons)),
                )
            )

        if item.key_fields.get("has_content_file") is False and "Recycle Bin metadata exists but recycled content file is missing" not in item.suspicious_reasons:
            item.suspicious_reasons = sorted(set(item.suspicious_reasons + ["Recycle Bin metadata exists but recycled content file is missing"]))

    return activities + new_activities


def correlate_shellbags(activities: list[ForensicActivity]) -> list[ForensicActivity]:
    shellbag_items = [item for item in activities if item.activity_type == "folder_accessed"]
    lnk_items = [item for item in activities if item.activity_type in {"opened_file", "script_opened"}]
    recycle_items = [item for item in activities if item.activity_type == "file_recycled"]
    browser_items = [item for item in activities if item.activity_type == "file_download"]
    new_activities: list[ForensicActivity] = []

    for item in shellbag_items:
        folder_path = _normalized_name(item.key_fields.get("file_path"))
        if not folder_path:
            continue
        matched_lnk = next(
            (
                candidate
                for candidate in lnk_items
                if _normalized_name(candidate.host) in {"", _normalized_name(item.host)}
                and (
                    _normalized_name(candidate.key_fields.get("file_path")).startswith(folder_path + "\\")
                    or _normalized_windows_parent(str(candidate.key_fields.get("file_path") or "")) == folder_path
                )
            ),
            None,
        )
        matched_recycle = next(
            (
                candidate
                for candidate in recycle_items
                if _normalized_name(candidate.host) in {"", _normalized_name(item.host)}
                and _normalized_windows_parent(str(candidate.key_fields.get("file_path") or "")) == folder_path
            ),
            None,
        )
        matched_browser = next(
            (
                candidate
                for candidate in browser_items
                if _normalized_name(candidate.host) in {"", _normalized_name(item.host)}
                and _normalized_windows_parent(str(candidate.key_fields.get("file_path") or "")) == folder_path
            ),
            None,
        )

        if matched_lnk:
            item.evidence_refs = sorted(set(item.evidence_refs + matched_lnk.evidence_refs))
            item.related_events = sorted(set(item.related_events + matched_lnk.related_events))
            item.tags = sorted(set(item.tags + matched_lnk.tags + ["lnk_correlated"]))
            item.confidence = max(item.confidence, 0.88)
        if matched_recycle:
            item.evidence_refs = sorted(set(item.evidence_refs + matched_recycle.evidence_refs))
            item.related_events = sorted(set(item.related_events + matched_recycle.related_events))
            item.tags = sorted(set(item.tags + matched_recycle.tags + ["recycle_bin_correlated"]))
            item.confidence = max(item.confidence, 0.86)
        if matched_browser:
            item.evidence_refs = sorted(set(item.evidence_refs + matched_browser.evidence_refs))
            item.related_events = sorted(set(item.related_events + matched_browser.related_events))
            item.tags = sorted(set(item.tags + matched_browser.tags + ["browser_download_correlated"]))
            item.confidence = max(item.confidence, 0.86)
            new_activities.append(
                ForensicActivity(
                    id=str(uuid4()),
                    activity_type="folder_related_to_deleted_download",
                    title=f"Shellbag folder related to download: {item.key_fields.get('file_path') or 'folder'}",
                    timestamp=item.timestamp or matched_browser.timestamp,
                    host=item.host,
                    user=item.user,
                    summary=item.summary,
                    severity=item.severity,
                    confidence=0.84,
                    tags=sorted(set(item.tags + matched_browser.tags + ["shellbags", "download"])),
                    key_fields=dict(item.key_fields),
                    evidence_refs=sorted(set(item.evidence_refs + matched_browser.evidence_refs)),
                    related_events=sorted(set(item.related_events + matched_browser.related_events)),
                    suspicious_reasons=sorted(set(item.suspicious_reasons + matched_browser.suspicious_reasons)),
                )
            )

    return activities + new_activities


def correlate_jumplists(activities: list[ForensicActivity], *, window_seconds: int = 604800) -> list[ForensicActivity]:
    jumplist_items = [item for item in activities if item.activity_type in {"recent_file_opened", "opened_file", "script_opened"} and str(item.key_fields.get("source") or "").lower() == "jlecmd"]
    lnk_items = [item for item in activities if item.activity_type in {"opened_file", "script_opened"} and str(item.key_fields.get("source") or "").lower() in {"lecmd", "native_lnk"}]
    shellbag_items = [item for item in activities if item.activity_type == "folder_accessed"]
    recycle_items = [item for item in activities if item.activity_type == "file_recycled"]
    browser_items = [item for item in activities if item.activity_type == "file_download"]
    new_activities: list[ForensicActivity] = []

    for item in jumplist_items:
        item_path = _normalized_name(item.key_fields.get("file_path"))
        item_name = _normalized_name(Path(str(item_path)).name if item_path else None)
        item_folder = _normalized_name(Path(str(item_path)).parent.as_posix().replace("/", "\\")) if item_path else ""
        item_host = _normalized_name(item.host)
        item_ts = _parse_iso(item.timestamp)
        if not item_path and not item_name:
            continue

        matched_lnk = next(
            (
                candidate
                for candidate in lnk_items
                if _normalized_name(candidate.host) in {"", item_host}
                and (
                    _normalized_name(candidate.key_fields.get("file_path")) == item_path
                    or _normalized_name(Path(str(candidate.key_fields.get("file_path") or "")).name) == item_name
                )
            ),
            None,
        )
        matched_shellbag = next(
            (
                candidate
                for candidate in shellbag_items
                if _normalized_name(candidate.host) in {"", item_host}
                and item_folder
                and _normalized_name(candidate.key_fields.get("file_path")) == item_folder
            ),
            None,
        )
        matched_recycle = next(
            (
                candidate
                for candidate in recycle_items
                if _normalized_name(candidate.host) in {"", item_host}
                and (
                    _normalized_name(candidate.key_fields.get("file_path")) == item_path
                    or (_normalized_name(candidate.key_fields.get("file_name")) and _normalized_name(candidate.key_fields.get("file_name")) == item_name)
                )
            ),
            None,
        )
        matched_browser = next(
            (
                candidate
                for candidate in browser_items
                if _normalized_name(candidate.host) in {"", item_host}
                and (
                    _normalized_name(candidate.key_fields.get("file_path")) == item_path
                    or (_normalized_name(candidate.key_fields.get("file_name")) and _normalized_name(candidate.key_fields.get("file_name")) == item_name)
                )
                and (
                    not item_ts
                    or not _parse_iso(candidate.timestamp)
                    or abs((_parse_iso(candidate.timestamp) - item_ts).total_seconds()) <= window_seconds
                )
            ),
            None,
        )

        if matched_lnk:
            item.evidence_refs = sorted(set(item.evidence_refs + matched_lnk.evidence_refs))
            item.related_events = sorted(set(item.related_events + matched_lnk.related_events))
            item.tags = sorted(set(item.tags + matched_lnk.tags + ["lnk_correlated"]))
            item.confidence = max(item.confidence, 0.9)
        if matched_shellbag:
            item.evidence_refs = sorted(set(item.evidence_refs + matched_shellbag.evidence_refs))
            item.related_events = sorted(set(item.related_events + matched_shellbag.related_events))
            item.tags = sorted(set(item.tags + matched_shellbag.tags + ["shellbag_correlated"]))
            item.confidence = max(item.confidence, 0.88)
        if matched_recycle:
            item.evidence_refs = sorted(set(item.evidence_refs + matched_recycle.evidence_refs))
            item.related_events = sorted(set(item.related_events + matched_recycle.related_events))
            item.tags = sorted(set(item.tags + matched_recycle.tags + ["recycle_bin_correlated"]))
            item.confidence = max(item.confidence, 0.9)
            new_activities.append(
                ForensicActivity(
                    id=str(uuid4()),
                    activity_type="deleted_file_was_opened",
                    title=f"Deleted file was opened: {item.key_fields.get('file_path') or item.key_fields.get('file_name') or 'file'}",
                    timestamp=item.timestamp or matched_recycle.timestamp,
                    host=item.host,
                    user=item.user,
                    summary=item.summary,
                    severity=item.severity,
                    confidence=0.9,
                    tags=sorted(set(item.tags + matched_recycle.tags + ["recycle_bin"])),
                    key_fields={**item.key_fields, "recycle_event": matched_recycle.id},
                    evidence_refs=sorted(set(item.evidence_refs + matched_recycle.evidence_refs)),
                    related_events=sorted(set(item.related_events + matched_recycle.related_events)),
                    suspicious_reasons=sorted(set(item.suspicious_reasons + matched_recycle.suspicious_reasons)),
                )
            )
        if matched_browser:
            item.evidence_refs = sorted(set(item.evidence_refs + matched_browser.evidence_refs))
            item.related_events = sorted(set(item.related_events + matched_browser.related_events))
            item.tags = sorted(set(item.tags + matched_browser.tags + ["browser_download_correlated"]))
            item.confidence = max(item.confidence, 0.9)
            new_activities.append(
                ForensicActivity(
                    id=str(uuid4()),
                    activity_type="downloaded_file_opened",
                    title=f"Downloaded file opened: {item.key_fields.get('file_path') or item.key_fields.get('file_name') or 'file'}",
                    timestamp=item.timestamp or matched_browser.timestamp,
                    host=item.host,
                    user=item.user,
                    summary=item.summary,
                    severity=item.severity,
                    confidence=0.9,
                    tags=sorted(set(item.tags + matched_browser.tags + ["download"])),
                    key_fields={**item.key_fields, "download_event": matched_browser.id, "download_domain": matched_browser.key_fields.get("domain")},
                    evidence_refs=sorted(set(item.evidence_refs + matched_browser.evidence_refs)),
                    related_events=sorted(set(item.related_events + matched_browser.related_events)),
                    suspicious_reasons=sorted(set(item.suspicious_reasons + matched_browser.suspicious_reasons)),
                )
            )

    return activities + new_activities


def section_activities(activities: list[ForensicActivity]) -> dict:
    sections = defaultdict(list)
    for activity in activities:
        sections[activity.activity_type].append(activity.model_dump())
        if activity.activity_type in {"powershell_execution", "powershell_download", "powershell_encoded_execution", "powershell_defender_tampering", "powershell_persistence", "powershell_recon", "powershell_credential_access"}:
            sections["powershell"].append(activity.model_dump())
            sections["powershell_activity"].append(activity.model_dump())
        if activity.activity_type == "powershell_download":
            sections["powershell_downloads"].append(activity.model_dump())
        if activity.activity_type == "powershell_encoded_execution":
            sections["powershell_encoded_commands"].append(activity.model_dump())
        if activity.activity_type == "powershell_defender_tampering":
            sections["powershell_defender_tampering"].append(activity.model_dump())
        if activity.activity_type == "powershell_persistence":
            sections["powershell_persistence"].append(activity.model_dump())
        if activity.activity_type == "powershell_recon":
            sections["powershell_recon"].append(activity.model_dump())
        if activity.activity_type == "powershell_credential_access":
            sections["powershell_credential_access"].append(activity.model_dump())
        if "persistence" in activity.tags or activity.activity_type in {"scheduled_task_created", "scheduled_task_updated", "scheduled_task_definition", "scheduled_task_com_handler", "scheduled_task", "task_execution", "service_created", "service_modified"}:
            sections["persistence"].append(activity.model_dump())
        if activity.activity_type in {"scheduled_task_definition", "scheduled_task_com_handler", "scheduled_task", "scheduled_task_created", "scheduled_task_updated"}:
            sections["scheduled_tasks"].append(activity.model_dump())
        if activity.activity_type == "suspicious_task":
            sections["suspicious_tasks"].append(activity.model_dump())
        if activity.activity_type in {"task_execution", "scheduled_task_action_started", "scheduled_task_action_completed"}:
            sections["task_executions"].append(activity.model_dump())
        if activity.activity_type == "downloaded_and_persisted":
            sections["downloaded_and_persisted"].append(activity.model_dump())
        if activity.activity_type in {"defender_detection", "defender_action", "defender_remediated_threat", "defender_quarantined_file", "defender_remediation_failed"}:
            sections["defender"].append(activity.model_dump())
            sections["defender_detections"].append(activity.model_dump())
        if activity.activity_type == "detected_downloaded_file":
            sections["detected_downloads"].append(activity.model_dump())
            sections["detected_files"].append(activity.model_dump())
        if activity.activity_type == "detected_executed_file":
            sections["detected_executions"].append(activity.model_dump())
            sections["detected_files"].append(activity.model_dump())
        if activity.activity_type == "detected_persistent_file":
            sections["detected_files"].append(activity.model_dump())
        if activity.activity_type == "defender_quarantined_file":
            sections["quarantined_items"].append(activity.model_dump())
        if activity.activity_type == "defender_remediation_failed":
            sections["remediation_failures"].append(activity.model_dump())
        if "user_activity" in activity.tags or activity.activity_type == "user_activity":
            sections["user_activity"].append(activity.model_dump())
        if activity.activity_type in {"account_created", "account_modified", "account_deleted", "user_added_to_group", "account_locked_out"}:
            sections["account_changes"].append(activity.model_dump())
        if activity.activity_type == "audit_log_cleared":
            sections["anti_forensics"].append(activity.model_dump())
        if activity.activity_type == "opened_file":
            sections["opened_files"].append(activity.model_dump())
            sections["file_accesses"].append(activity.model_dump())
            if activity.key_fields.get("document_like"):
                sections["recent_documents"].append(activity.model_dump())
        if activity.activity_type == "file_created":
            sections["file_creations"].append(activity.model_dump())
            if any(token in str((activity.key_fields or {}).get("file_path") or "").lower() for token in ["\\downloads\\", "\\desktop\\", "\\temp\\", "\\appdata\\", "\\users\\public\\", "\\programdata\\"]):
                sections["downloaded_files"].append(activity.model_dump())
        if activity.activity_type == "file_deleted":
            sections["file_deletions"].append(activity.model_dump())
            sections["deleted_files"].append(activity.model_dump())
        if activity.activity_type == "file_recycled":
            sections["recycled_files"].append(activity.model_dump())
            sections["deleted_files"].append(activity.model_dump())
        if activity.activity_type == "deleted_download":
            sections["deleted_downloads"].append(activity.model_dump())
        if activity.activity_type == "deleted_executable":
            sections["deleted_executables"].append(activity.model_dump())
        if activity.activity_type == "deleted_script":
            sections["deleted_scripts"].append(activity.model_dump())
        if activity.activity_type == "deleted_detected_file":
            sections["deleted_detected_files"].append(activity.model_dump())
        if activity.activity_type in {"cleanup_candidate", "deleted_persistent_file"}:
            sections["cleanup_candidates"].append(activity.model_dump())
        if activity.activity_type == "file_modified":
            sections["file_modifications"].append(activity.model_dump())
        if activity.activity_type == "file_renamed":
            sections["file_renames"].append(activity.model_dump())
        if activity.activity_type == "script_opened":
            sections["scripts_opened"].append(activity.model_dump())
        if activity.activity_type == "execution_candidate":
            sections["execution_candidates"].append(activity.model_dump())
        if activity.activity_type == "program_inventory":
            sections["program_inventory"].append(activity.model_dump())
        if activity.activity_type == "downloaded_and_observed_program":
            sections["downloaded_and_observed_programs"].append(activity.model_dump())
        if activity.activity_type == "suspicious_program":
            sections["suspicious_programs"].append(activity.model_dump())
        if activity.activity_type == "application_used":
            sections["applications_used"].append(activity.model_dump())
            sections["application_recent_items"].append(activity.model_dump())
        if activity.activity_type == "browser_history":
            sections["browser_history"].append(activity.model_dump())
            if any(tag in activity.tags for tag in {"cloud_storage", "paste_site", "remote_access_tool"}):
                sections["cloud_activity"].append(activity.model_dump())
        if activity.activity_type == "web_search":
            sections["web_searches"].append(activity.model_dump())
        if activity.activity_type == "file_download":
            sections["downloaded_files"].append(activity.model_dump())
            if any(tag in activity.tags for tag in {"cloud_storage", "paste_site", "remote_access_tool"}):
                sections["cloud_activity"].append(activity.model_dump())
            if any(tag in activity.tags for tag in {"suspicious_download", "executable_download", "archive_download", "script_download"}):
                sections["suspicious_downloads"].append(activity.model_dump())
        if activity.activity_type == "downloaded_and_executed":
            sections["downloaded_and_executed"].append(activity.model_dump())
        if activity.activity_type == "cloud_sync_root_observed":
            sections["cloud_sync"].append(activity.model_dump())
            sections["cloud_sync_roots"].append(activity.model_dump())
            if activity.key_fields.get("account") or activity.key_fields.get("account_email"):
                sections["cloud_accounts"].append(activity.model_dump())
        if activity.activity_type == "cloud_file_activity":
            sections["cloud_file_activity"].append(activity.model_dump())
        if activity.activity_type == "cloud_sensitive_file_observed":
            sections["cloud_sensitive_files"].append(activity.model_dump())
        if activity.activity_type == "cloud_archive_created":
            sections["cloud_archives"].append(activity.model_dump())
        if activity.activity_type == "downloaded_to_cloud":
            sections["downloaded_to_cloud"].append(activity.model_dump())
        if activity.activity_type == "copied_to_cloud":
            sections["copied_to_cloud"].append(activity.model_dump())
        if activity.activity_type == "executable_from_cloud":
            sections["executable_from_cloud"].append(activity.model_dump())
        if activity.activity_type == "defender_detection_in_cloud":
            sections["defender_detection_in_cloud"].append(activity.model_dump())
        if activity.activity_type == "possible_cloud_staging":
            sections["possible_cloud_staging"].append(activity.model_dump())
        if activity.activity_type == "possible_cloud_exfiltration":
            sections["possible_cloud_exfiltration"].append(activity.model_dump())
            sections["suspicious_findings"].append(activity.model_dump())
        if activity.activity_type == "deleted_from_cloud":
            sections["cloud_file_activity"].append(activity.model_dump())
        if activity.activity_type == "persistence_target_in_cloud":
            sections["possible_cloud_exfiltration"].append(activity.model_dump())
            sections["possible_persistence"].append(activity.model_dump())
        if activity.activity_type == "application_network_usage":
            sections["network_activity"].append(activity.model_dump())
            sections["application_network_usage"].append(activity.model_dump())
        if activity.activity_type == "wlan_profile_observed":
            sections["network_overview"].append(activity.model_dump())
            sections["wlan_profiles"].append(activity.model_dump())
        if activity.activity_type == "wlan_connection_observed":
            sections["network_overview"].append(activity.model_dump())
            sections["wlan_connections"].append(activity.model_dump())
        if activity.activity_type == "network_profile_observed":
            sections["network_overview"].append(activity.model_dump())
            sections["network_profiles"].append(activity.model_dump())
        if activity.activity_type == "hosts_override_observed":
            sections["hosts_entries"].append(activity.model_dump())
        if activity.activity_type == "suspicious_hosts_override":
            sections["suspicious_hosts_entries"].append(activity.model_dump())
            sections["suspicious_findings"].append(activity.model_dump())
        if activity.activity_type == "suspicious_dns_config":
            sections["suspicious_dns_config"].append(activity.model_dump())
        if activity.activity_type == "network_indicator_seen":
            sections["network_indicators"].append(activity.model_dump())
            sections["network_correlations"].append(activity.model_dump())
        if activity.activity_type == "suspicious_network_activity_candidate":
            sections["network_correlations"].append(activity.model_dump())
            sections["suspicious_findings"].append(activity.model_dump())
        if activity.activity_type == "high_upload_activity":
            sections["high_upload_activity"].append(activity.model_dump())
        if activity.activity_type == "remote_access_activity":
            sections["remote_access_activity"].append(activity.model_dump())
        if activity.activity_type == "possible_exfiltration":
            sections["possible_exfiltration"].append(activity.model_dump())
        if activity.activity_type == "downloaded_and_network_active_program":
            sections["downloaded_and_network_active_programs"].append(activity.model_dump())
        if activity.activity_type == "network_path_opened":
            sections["network_paths"].append(activity.model_dump())
        if activity.activity_type == "recent_file_opened":
            sections["recent_files"].append(activity.model_dump())
            sections["opened_files"].append(activity.model_dump())
        if activity.activity_type == "downloaded_file_opened":
            sections["downloaded_files_opened"].append(activity.model_dump())
        if activity.activity_type == "deleted_file_was_opened":
            sections["deleted_files_opened"].append(activity.model_dump())
        if activity.activity_type == "network_file_accessed":
            sections["network_file_activity"].append(activity.model_dump())
        if activity.activity_type == "usb_file_accessed":
            sections["usb_file_activity"].append(activity.model_dump())
        if activity.activity_type == "cloud_file_accessed":
            sections["cloud_file_activity"].append(activity.model_dump())
        if activity.activity_type == "suspicious_recent_item":
            sections["suspicious_recent_items"].append(activity.model_dump())
            sections["suspicious_findings"].append(activity.model_dump())
        if activity.activity_type == "folder_accessed":
            sections["folder_activity"].append(activity.model_dump())
            sections["shellbag_folders"].append(activity.model_dump())
        if activity.activity_type == "network_folder_accessed":
            sections["network_share_activity"].append(activity.model_dump())
            sections["folder_activity"].append(activity.model_dump())
        if activity.activity_type == "usb_folder_accessed":
            sections["usb_folder_activity"].append(activity.model_dump())
            sections["folder_activity"].append(activity.model_dump())
        if activity.activity_type == "cloud_folder_accessed":
            sections["cloud_folder_activity"].append(activity.model_dump())
            sections["folder_activity"].append(activity.model_dump())
        if activity.activity_type == "suspicious_folder_accessed":
            sections["suspicious_folder_activity"].append(activity.model_dump())
            sections["suspicious_findings"].append(activity.model_dump())
        if activity.activity_type == "deleted_folder_candidate":
            sections["deleted_or_missing_folders"].append(activity.model_dump())
        if activity.activity_type == "folder_related_to_deleted_download":
            sections["deleted_downloads"].append(activity.model_dump())
        if activity.activity_type == "removable_media_access":
            sections["removable_media"].append(activity.model_dump())
        if activity.activity_type in {"usb_device_seen", "mounted_device", "usb_device_install", "usb_volume_mapping", "portable_device_observed"}:
            sections["usb_devices"].append(activity.model_dump())
        if activity.activity_type == "usb_device_install":
            sections["usb_storage_devices"].append(activity.model_dump())
        if activity.activity_type == "usb_volume_mapping":
            sections["usb_volume_mappings"].append(activity.model_dump())
        if activity.activity_type in {"setupapi_driver_update", "usb_class_generic"}:
            sections["setupapi_driver_activity"].append(activity.model_dump())
        if activity.activity_type == "usb_file_access":
            sections["usb_file_activity"].append(activity.model_dump())
        if activity.activity_type == "usb_folder_accessed":
            sections["usb_folder_activity"].append(activity.model_dump())
        if activity.activity_type == "usb_download_to_external_drive":
            sections["download_to_usb"].append(activity.model_dump())
            sections["possible_usb_exfiltration"].append(activity.model_dump())
        if activity.activity_type == "possible_usb_exfiltration_candidate":
            sections["possible_usb_exfiltration"].append(activity.model_dump())
            sections["suspicious_usb_activity"].append(activity.model_dump())
        if activity.activity_type == "background_download":
            sections["background_downloads"].append(activity.model_dump())
            sections["bits_jobs"].append(activity.model_dump())
            sections["bits_transfers"].append(activity.model_dump())
            sections["downloaded_files"].append(activity.model_dump())
        if activity.activity_type == "suspicious_bits_job":
            sections["suspicious_bits_jobs"].append(activity.model_dump())
            sections["suspicious_findings"].append(activity.model_dump())
        if activity.activity_type == "bits_notify_persistence":
            sections["bits_notify_commands"].append(activity.model_dump())
            sections["possible_persistence"].append(activity.model_dump())
        if activity.activity_type == "bits_download_then_execute":
            sections["downloaded_then_executed"].append(activity.model_dump())
        if activity.activity_type == "bits_download_detected_by_defender":
            sections["downloaded_then_detected"].append(activity.model_dump())
        if activity.activity_type == "autorun_entry":
            sections["autoruns_persistence"].append(activity.model_dump())
            mechanism = str((activity.key_fields or {}).get("mechanism") or "")
            if mechanism in {"run_key", "runonce_key"}:
                sections["run_key_persistence"].append(activity.model_dump())
            if mechanism == "startup_folder":
                sections["startup_folder_persistence"].append(activity.model_dump())
            if mechanism in {"service", "driver"}:
                sections["service_driver_persistence"].append(activity.model_dump())
            if mechanism == "scheduled_task":
                sections["scheduled_task_persistence"].append(activity.model_dump())
            if mechanism == "wmi":
                sections["wmi_persistence"].append(activity.model_dump())
            if mechanism == "ifeo_debugger":
                sections["ifeo_debugger_persistence"].append(activity.model_dump())
            if mechanism in {"winlogon_shell", "winlogon_userinit"}:
                sections["winlogon_persistence"].append(activity.model_dump())
            if mechanism in {"appinit_dll", "appcert_dll"}:
                sections["appinit_appcert_persistence"].append(activity.model_dump())
        if activity.activity_type == "suspicious_autorun":
            sections["suspicious_autoruns"].append(activity.model_dump())
            sections["suspicious_findings"].append(activity.model_dump())
            sections["possible_persistence"].append(activity.model_dump())
        if activity.activity_type == "wmi_filter":
            sections["wmi_filters"].append(activity.model_dump())
        if activity.activity_type == "wmi_consumer":
            sections["wmi_consumers"].append(activity.model_dump())
        if activity.activity_type == "wmi_binding":
            sections["wmi_bindings"].append(activity.model_dump())
            binding_dump = activity.model_dump()
            key_fields = dict(binding_dump.get("key_fields") or {})
            if "binding_status" not in key_fields:
                key_fields["binding_status"] = "complete" if key_fields.get("binding_filter") and key_fields.get("binding_consumer") else "unresolved"
            binding_dump["key_fields"] = key_fields
            sections["wmi_persistence"].append(binding_dump)
            sections["persistence"].append(binding_dump)
            sections["possible_persistence"].append(binding_dump)
        if activity.activity_type == "wmi_persistence_candidate":
            sections["wmi_persistence"].append(activity.model_dump())
            sections["persistence"].append(activity.model_dump())
            sections["possible_persistence"].append(activity.model_dump())
        if activity.activity_type == "wmi_encoded_powershell":
            sections["wmi_encoded_powershell"].append(activity.model_dump())
            sections["suspicious_wmi_consumers"].append(activity.model_dump())
        if activity.activity_type == "wmi_script_consumer":
            sections["suspicious_wmi_consumers"].append(activity.model_dump())
        if activity.activity_type == "wmi_download_command":
            sections["wmi_download_commands"].append(activity.model_dump())
            sections["suspicious_wmi_consumers"].append(activity.model_dump())
        if activity.activity_type == "possible_wmi_execution":
            sections["possible_wmi_execution"].append(activity.model_dump())
            sections["suspicious_wmi_consumers"].append(activity.model_dump())
        if activity.activity_type == "wmi_activity_query":
            sections["wmi_activity"].append(activity.model_dump())
        if activity.activity_type == "rdp_history":
            sections["rdp"].append(activity.model_dump())
        if activity.activity_type == "suspicious_file":
            sections["suspicious_files"].append(activity.model_dump())
        if activity.suspicious_reasons or any(tag in activity.tags for tag in {"suspicious", "suspicious_command", "suspicious_process", "powershell_encoded", "download", "defender_tamper"}):
            sections["suspicious_findings"].append(activity.model_dump())
        sections["timeline"].append(activity.model_dump())
    return dict(sections)
