from datetime import datetime, timezone
from typing import Callable

from app.analysis.activities import (
    correlate_browser_downloads,
    correlate_defender_findings,
    correlate_execution_artifacts,
    correlate_file_access_sources,
    correlate_jumplists,
    correlate_lnk_with_execution,
    correlate_powershell_usage,
    correlate_recycle_bin,
    correlate_shellbags,
    correlate_program_execution_sources,
    correlate_registry_persistence_sources,
    correlate_scheduled_tasks,
    correlate_srum_usage,
    correlate_usb_activity,
    deduplicate_activities,
    event_to_activity,
    section_activities,
)
from app.ingest.bits.correlation import correlate_bits_activity
from app.ingest.autoruns.correlation import correlate_autoruns_activity
from app.ingest.cloud_sync.correlation import correlate_cloud_activity
from app.ingest.network.correlation import correlate_network_activity
from app.ingest.wmi.correlation import correlate_wmi_activity
from app.analysis.timeline import build_global_timeline
from app.core.opensearch import iter_case_events


def _build_time_range_query(time_from: str | None = None, time_to: str | None = None) -> dict | None:
    range_clause: dict[str, str] = {}
    if time_from:
        range_clause["gte"] = time_from
    if time_to:
        range_clause["lte"] = time_to
    if not range_clause:
        return None
    return {"range": {"@timestamp": range_clause}}


def _build_application_usage_section(activities: list) -> list[dict]:
    grouped: dict[tuple[str, str, str], dict] = {}
    for activity in activities:
        if activity.activity_type != "application_used":
            continue
        app_name = str(activity.key_fields.get("app_name") or "")
        app_id = str(activity.key_fields.get("app_id") or "")
        user = str(activity.user or "")
        key = (app_name, app_id, user)
        current = grouped.get(key)
        if current is None:
            current = activity.model_dump()
            current["key_fields"]["count"] = 1
            current["key_fields"]["last_seen"] = activity.timestamp
            grouped[key] = current
            continue
        current["key_fields"]["count"] = int(current["key_fields"].get("count") or 0) + 1
        if activity.timestamp and (not current["key_fields"].get("last_seen") or str(activity.timestamp) > str(current["key_fields"].get("last_seen"))):
            current["key_fields"]["last_seen"] = activity.timestamp
        current["evidence_refs"] = sorted(set(current.get("evidence_refs", []) + activity.evidence_refs))
        current["related_events"] = sorted(set(current.get("related_events", []) + activity.related_events))
        current["tags"] = sorted(set(current.get("tags", []) + activity.tags))
        current["suspicious_reasons"] = sorted(set(current.get("suspicious_reasons", []) + activity.suspicious_reasons))
        current["confidence"] = max(current.get("confidence") or 0, activity.confidence)
    return sorted(grouped.values(), key=lambda item: (-(item.get("key_fields", {}) or {}).get("count", 0), str((item.get("key_fields", {}) or {}).get("last_seen") or "")))


class SemiAutoAnalysisCancelled(RuntimeError):
    pass


def _emit_progress(
    progress_cb: Callable[[str, int, dict | None], None] | None,
    phase: str,
    pct: int,
    extra: dict | None = None,
) -> None:
    if progress_cb:
        progress_cb(phase, pct, extra)


def _ensure_not_cancelled(cancel_cb: Callable[[], bool] | None) -> None:
    if cancel_cb and cancel_cb():
        raise SemiAutoAnalysisCancelled("Semi-automatic analysis cancelled")


def build_case_semi_auto_analysis(
    case_id: str,
    *,
    time_from: str | None = None,
    time_to: str | None = None,
    progress_cb: Callable[[str, int, dict | None], None] | None = None,
    cancel_cb: Callable[[], bool] | None = None,
) -> dict:
    _emit_progress(progress_cb, "fetching_events", 5, {"message": "Loading normalized events"})
    _ensure_not_cancelled(cancel_cb)
    events = list(iter_case_events(case_id, query=_build_time_range_query(time_from, time_to)))
    _emit_progress(progress_cb, "fetched_events", 20, {"total_events": len(events)})
    _ensure_not_cancelled(cancel_cb)
    generated_activities = []
    total_events = max(len(events), 1)
    for index, event in enumerate(events, start=1):
        generated_activities.extend(event_to_activity(event))
        if index == len(events) or index % 250 == 0:
            pct = 20 + int((index / total_events) * 30)
            _emit_progress(progress_cb, "building_activities", pct, {"processed_events": index, "total_events": len(events)})
            _ensure_not_cancelled(cancel_cb)
    activities = deduplicate_activities(generated_activities)
    _emit_progress(progress_cb, "deduplicating", 55, {"total_activities": len(activities)})
    _ensure_not_cancelled(cancel_cb)
    activities = correlate_program_execution_sources(activities)
    _emit_progress(progress_cb, "correlating_execution", 60, None)
    _ensure_not_cancelled(cancel_cb)
    activities = correlate_file_access_sources(activities)
    _emit_progress(progress_cb, "correlating_file_access", 64, None)
    _ensure_not_cancelled(cancel_cb)
    activities = correlate_lnk_with_execution(activities)
    _emit_progress(progress_cb, "correlating_lnk", 68, None)
    _ensure_not_cancelled(cancel_cb)
    activities = correlate_registry_persistence_sources(activities)
    _emit_progress(progress_cb, "correlating_registry", 72, None)
    _ensure_not_cancelled(cancel_cb)
    activities = correlate_browser_downloads(activities)
    _emit_progress(progress_cb, "correlating_browser", 76, None)
    _ensure_not_cancelled(cancel_cb)
    activities = correlate_powershell_usage(activities)
    _emit_progress(progress_cb, "correlating_powershell", 78, None)
    _ensure_not_cancelled(cancel_cb)
    activities = correlate_execution_artifacts(activities)
    _emit_progress(progress_cb, "correlating_execution_artifacts", 82, None)
    _ensure_not_cancelled(cancel_cb)
    activities = correlate_srum_usage(activities)
    _emit_progress(progress_cb, "correlating_srum", 86, None)
    _ensure_not_cancelled(cancel_cb)
    activities = correlate_scheduled_tasks(activities)
    _emit_progress(progress_cb, "correlating_scheduled_tasks", 90, None)
    _ensure_not_cancelled(cancel_cb)
    activities = correlate_recycle_bin(activities)
    _emit_progress(progress_cb, "correlating_recycle_bin", 92, None)
    _ensure_not_cancelled(cancel_cb)
    activities = correlate_shellbags(activities)
    _emit_progress(progress_cb, "correlating_shellbags", 93, None)
    _ensure_not_cancelled(cancel_cb)
    activities = correlate_jumplists(activities)
    _emit_progress(progress_cb, "correlating_jumplists", 94, None)
    _ensure_not_cancelled(cancel_cb)
    activities = correlate_usb_activity(activities)
    _emit_progress(progress_cb, "correlating_usb", 95, None)
    _ensure_not_cancelled(cancel_cb)
    activities = correlate_bits_activity(activities)
    _emit_progress(progress_cb, "correlating_bits", 96, None)
    _ensure_not_cancelled(cancel_cb)
    activities = correlate_wmi_activity(activities)
    _emit_progress(progress_cb, "correlating_wmi", 97, None)
    _ensure_not_cancelled(cancel_cb)
    activities = correlate_autoruns_activity(activities)
    _emit_progress(progress_cb, "correlating_autoruns", 98, None)
    _ensure_not_cancelled(cancel_cb)
    activities = correlate_cloud_activity(activities)
    _emit_progress(progress_cb, "correlating_cloud", 99, None)
    _ensure_not_cancelled(cancel_cb)
    activities = correlate_network_activity(activities)
    _emit_progress(progress_cb, "correlating_network", 99, None)
    _ensure_not_cancelled(cancel_cb)
    activities = correlate_defender_findings(activities)
    _emit_progress(progress_cb, "correlating_defender", 99, None)
    _ensure_not_cancelled(cancel_cb)
    sections = section_activities(activities)
    sections.setdefault("program_executions", [item for item in sections.get("program_execution", [])])
    sections.setdefault("powershell", [item for item in sections.get("powershell_execution", [])])
    sections.setdefault("powershell_activity", sections.get("powershell_activity", []))
    sections.setdefault("powershell_downloads", sections.get("powershell_downloads", []))
    sections.setdefault("powershell_encoded_commands", sections.get("powershell_encoded_commands", []))
    sections.setdefault("powershell_defender_tampering", sections.get("powershell_defender_tampering", []))
    sections.setdefault("powershell_persistence", sections.get("powershell_persistence", []))
    sections.setdefault("powershell_recon", sections.get("powershell_recon", []))
    sections.setdefault("powershell_credential_access", sections.get("powershell_credential_access", []))
    sections.setdefault("downloads", [item for item in sections.get("file_download", [])])
    sections.setdefault("browser_history", sections.get("browser_history", []))
    sections.setdefault("downloaded_files", sections.get("downloaded_files", []))
    sections.setdefault("web_searches", sections.get("web_searches", []))
    sections.setdefault("cloud_activity", sections.get("cloud_activity", []))
    sections.setdefault("cloud_sync", sections.get("cloud_sync", []))
    sections.setdefault("cloud_accounts", sections.get("cloud_accounts", []))
    sections.setdefault("cloud_sync_roots", sections.get("cloud_sync_roots", []))
    sections.setdefault("network_overview", sections.get("network_overview", []))
    sections.setdefault("wlan_profiles", sections.get("wlan_profiles", []))
    sections.setdefault("wlan_connections", sections.get("wlan_connections", []))
    sections.setdefault("network_profiles", sections.get("network_profiles", []))
    sections.setdefault("dns_config", sections.get("dns_config", []))
    sections.setdefault("dns_cache", sections.get("dns_cache", []))
    sections.setdefault("hosts_entries", sections.get("hosts_entries", []))
    sections.setdefault("suspicious_hosts_entries", sections.get("suspicious_hosts_entries", []))
    sections.setdefault("suspicious_dns_config", sections.get("suspicious_dns_config", []))
    sections.setdefault("network_indicators", sections.get("network_indicators", []))
    sections.setdefault("network_correlations", sections.get("network_correlations", []))
    sections.setdefault("suspicious_downloads", sections.get("suspicious_downloads", []))
    sections.setdefault("downloaded_and_executed", sections.get("downloaded_and_executed", []))
    sections.setdefault("file_creations", [item for item in sections.get("file_created", [])])
    sections.setdefault("file_modifications", [item for item in sections.get("file_modified", [])])
    sections.setdefault("file_deletions", [item for item in sections.get("file_deleted", [])])
    sections.setdefault("file_renames", [item for item in sections.get("file_renamed", [])])
    sections.setdefault(
        "scheduled_tasks",
        sections.get("scheduled_tasks", [])
        or (sections.get("scheduled_task", []) + sections.get("scheduled_task_definition", []) + sections.get("scheduled_task_com_handler", []) + sections.get("scheduled_task_created", []) + sections.get("scheduled_task_updated", [])),
    )
    sections.setdefault("suspicious_tasks", sections.get("suspicious_tasks", []))
    sections.setdefault("task_executions", sections.get("task_executions", []))
    sections.setdefault("downloaded_and_persisted", sections.get("downloaded_and_persisted", []))
    sections.setdefault("defender_detections", sections.get("defender_detections", []) or sections.get("defender", []))
    sections.setdefault("detected_files", sections.get("detected_files", []))
    sections.setdefault("detected_downloads", sections.get("detected_downloads", []))
    sections.setdefault("detected_executions", sections.get("detected_executions", []))
    sections.setdefault("quarantined_items", sections.get("quarantined_items", []))
    sections.setdefault("remediation_failures", sections.get("remediation_failures", []))
    sections.setdefault("services", sections.get("service_created", []) + sections.get("service_modified", []))
    sections.setdefault("network_connections", sections.get("network_connection", []))
    sections.setdefault("file_accesses", sections.get("opened_files", []))
    sections.setdefault("opened_files", sections.get("opened_file", []))
    sections.setdefault("recent_files", sections.get("recent_files", []))
    sections.setdefault("application_recent_items", sections.get("application_recent_items", []) or sections.get("applications_used", []))
    sections.setdefault("downloaded_files_opened", sections.get("downloaded_files_opened", []))
    sections.setdefault("deleted_files_opened", sections.get("deleted_files_opened", []))
    sections.setdefault("network_file_activity", sections.get("network_file_activity", []))
    sections.setdefault("usb_file_activity", sections.get("usb_file_activity", []))
    sections.setdefault("cloud_file_activity", sections.get("cloud_file_activity", []))
    sections.setdefault("cloud_sensitive_files", sections.get("cloud_sensitive_files", []))
    sections.setdefault("cloud_archives", sections.get("cloud_archives", []))
    sections.setdefault("downloaded_to_cloud", sections.get("downloaded_to_cloud", []))
    sections.setdefault("copied_to_cloud", sections.get("copied_to_cloud", []))
    sections.setdefault("executable_from_cloud", sections.get("executable_from_cloud", []))
    sections.setdefault("defender_detection_in_cloud", sections.get("defender_detection_in_cloud", []))
    sections.setdefault("possible_cloud_staging", sections.get("possible_cloud_staging", []))
    sections.setdefault("possible_cloud_exfiltration", sections.get("possible_cloud_exfiltration", []))
    sections.setdefault("suspicious_recent_items", sections.get("suspicious_recent_items", []))
    sections.setdefault("recent_documents", [item for item in sections.get("opened_files", []) if (item.get("key_fields", {}) or {}).get("document_like")])
    sections.setdefault("scripts_opened", sections.get("script_opened", []))
    sections.setdefault("applications_used", _build_application_usage_section(activities))
    sections.setdefault("network_paths", sections.get("network_path_opened", []))
    sections.setdefault("removable_media", sections.get("removable_media_access", []))
    sections.setdefault("execution_candidates", sections.get("execution_candidates", []))
    sections.setdefault("program_inventory", sections.get("program_inventory", []))
    sections.setdefault("downloaded_and_observed_programs", sections.get("downloaded_and_observed_programs", []))
    sections.setdefault("suspicious_programs", sections.get("suspicious_programs", []))
    sections.setdefault("network_activity", sections.get("network_activity", []))
    sections.setdefault("application_network_usage", sections.get("application_network_usage", []))
    sections.setdefault("high_upload_activity", sections.get("high_upload_activity", []))
    sections.setdefault("remote_access_activity", sections.get("remote_access_activity", []))
    sections.setdefault("possible_exfiltration", sections.get("possible_exfiltration", []))
    sections.setdefault("downloaded_and_network_active_programs", sections.get("downloaded_and_network_active_programs", []))
    sections.setdefault("recycled_files", sections.get("recycled_files", []))
    sections.setdefault("deleted_files", sections.get("deleted_files", []) or sections.get("file_deletions", []))
    sections.setdefault("deleted_downloads", sections.get("deleted_downloads", []))
    sections.setdefault("deleted_executables", sections.get("deleted_executables", []))
    sections.setdefault("deleted_scripts", sections.get("deleted_scripts", []))
    sections.setdefault("deleted_detected_files", sections.get("deleted_detected_files", []))
    sections.setdefault("cleanup_candidates", sections.get("cleanup_candidates", []))
    sections.setdefault("folder_activity", sections.get("folder_activity", []))
    sections.setdefault("shellbag_folders", sections.get("shellbag_folders", []))
    sections.setdefault("usb_folder_activity", sections.get("usb_folder_activity", []))
    sections.setdefault("network_share_activity", sections.get("network_share_activity", []))
    sections.setdefault("cloud_folder_activity", sections.get("cloud_folder_activity", []))
    sections.setdefault("suspicious_folder_activity", sections.get("suspicious_folder_activity", []))
    sections.setdefault("deleted_or_missing_folders", sections.get("deleted_or_missing_folders", []))
    sections.setdefault("suspicious_files", sections.get("suspicious_files", []))
    sections.setdefault("user_activity", sections.get("user_activity", []))
    sections.setdefault("usb_devices", sections.get("usb_device_seen", []) + sections.get("mounted_device", []))
    sections.setdefault("usb_storage_devices", sections.get("usb_storage_devices", []))
    sections.setdefault("usb_volume_mappings", sections.get("usb_volume_mappings", []))
    sections.setdefault("setupapi_driver_activity", sections.get("setupapi_driver_activity", []))
    sections.setdefault("download_to_usb", sections.get("download_to_usb", []))
    sections.setdefault("possible_usb_exfiltration", sections.get("possible_usb_exfiltration", []))
    sections.setdefault("suspicious_usb_activity", sections.get("suspicious_usb_activity", []))
    sections.setdefault("background_downloads", sections.get("background_downloads", []))
    sections.setdefault("bits_jobs", sections.get("bits_jobs", []))
    sections.setdefault("bits_transfers", sections.get("bits_transfers", []))
    sections.setdefault("suspicious_bits_jobs", sections.get("suspicious_bits_jobs", []))
    sections.setdefault("bits_notify_commands", sections.get("bits_notify_commands", []))
    sections.setdefault("downloaded_then_executed", sections.get("downloaded_then_executed", []))
    sections.setdefault("downloaded_then_detected", sections.get("downloaded_then_detected", []))
    sections.setdefault("possible_persistence", sections.get("possible_persistence", []))
    sections.setdefault("wmi_persistence", sections.get("wmi_persistence", []))
    sections.setdefault("wmi_filters", sections.get("wmi_filters", []))
    sections.setdefault("wmi_consumers", sections.get("wmi_consumers", []))
    sections.setdefault("wmi_bindings", sections.get("wmi_bindings", []))
    sections.setdefault("suspicious_wmi_consumers", sections.get("suspicious_wmi_consumers", []))
    sections.setdefault("wmi_encoded_powershell", sections.get("wmi_encoded_powershell", []))
    sections.setdefault("wmi_download_commands", sections.get("wmi_download_commands", []))
    sections.setdefault("possible_wmi_execution", sections.get("possible_wmi_execution", []))
    sections.setdefault("wmi_activity", sections.get("wmi_activity", []))
    sections.setdefault("autoruns_persistence", sections.get("autoruns_persistence", []))
    sections.setdefault("suspicious_autoruns", sections.get("suspicious_autoruns", []))
    sections.setdefault("run_key_persistence", sections.get("run_key_persistence", []))
    sections.setdefault("startup_folder_persistence", sections.get("startup_folder_persistence", []))
    sections.setdefault("service_driver_persistence", sections.get("service_driver_persistence", []))
    sections.setdefault("scheduled_task_persistence", sections.get("scheduled_task_persistence", []))
    sections.setdefault("ifeo_debugger_persistence", sections.get("ifeo_debugger_persistence", []))
    sections.setdefault("winlogon_persistence", sections.get("winlogon_persistence", []))
    sections.setdefault("appinit_appcert_persistence", sections.get("appinit_appcert_persistence", []))
    sections.setdefault("downloaded_then_persisted", sections.get("downloaded_then_persisted", []))
    sections.setdefault("persisted_then_executed", sections.get("persisted_then_executed", []))
    sections.setdefault("persistence_detected_by_defender", sections.get("persistence_detected_by_defender", []))
    sections.setdefault("logons", sections.get("logon_success", []) + sections.get("logon_failed", []))
    sections.setdefault("rdp", sections.get("rdp_logon", []) + sections.get("rdp_disconnect", []))
    sections.setdefault("defender", sections.get("defender_detection", []) + sections.get("defender_action", []))
    sections.setdefault(
        "account_changes",
        sections.get("account_created", [])
        + sections.get("account_modified", [])
        + sections.get("account_deleted", [])
        + sections.get("user_added_to_group", [])
        + sections.get("account_locked_out", []),
    )
    sections.setdefault("anti_forensics", sections.get("audit_log_cleared", []))
    _emit_progress(progress_cb, "building_timeline", 96, None)
    _ensure_not_cancelled(cancel_cb)
    sections["timeline"] = build_global_timeline(activities)
    summary = {
        "total_events": len(events),
        "total_activities": len(activities),
        "program_executions": len(sections.get("program_execution", [])),
        "powershell_executions": len(sections.get("powershell_execution", [])),
        "powershell_activity": len(sections.get("powershell_activity", [])),
        "powershell_downloads": len(sections.get("powershell_downloads", [])),
        "powershell_encoded_commands": len(sections.get("powershell_encoded_commands", [])),
        "powershell_defender_tampering": len(sections.get("powershell_defender_tampering", [])),
        "powershell_persistence": len(sections.get("powershell_persistence", [])),
        "downloads": len(sections.get("file_download", [])),
        "browser_history": len(sections.get("browser_history", [])),
        "downloaded_files": len(sections.get("downloaded_files", [])),
        "web_searches": len(sections.get("web_searches", [])),
        "program_inventory": len(sections.get("program_inventory", [])),
        "execution_candidates": len(sections.get("execution_candidates", [])),
        "network_activity": len(sections.get("network_activity", [])),
        "high_upload_activity": len(sections.get("high_upload_activity", [])),
        "deleted_files": len(sections.get("deleted_files", [])),
        "recycled_files": len(sections.get("recycled_files", [])),
        "deleted_downloads": len(sections.get("deleted_downloads", [])),
        "deleted_detected_files": len(sections.get("deleted_detected_files", [])),
        "cleanup_candidates": len(sections.get("cleanup_candidates", [])),
        "recent_files": len(sections.get("recent_files", [])),
        "downloaded_files_opened": len(sections.get("downloaded_files_opened", [])),
        "deleted_files_opened": len(sections.get("deleted_files_opened", [])),
        "network_file_activity": len(sections.get("network_file_activity", [])),
        "usb_file_activity": len(sections.get("usb_file_activity", [])),
        "cloud_file_activity": len(sections.get("cloud_file_activity", [])),
        "cloud_sync_roots": len(sections.get("cloud_sync_roots", [])),
        "cloud_accounts": len(sections.get("cloud_accounts", [])),
        "cloud_sensitive_files": len(sections.get("cloud_sensitive_files", [])),
        "cloud_archives": len(sections.get("cloud_archives", [])),
        "downloaded_to_cloud": len(sections.get("downloaded_to_cloud", [])),
        "copied_to_cloud": len(sections.get("copied_to_cloud", [])),
        "possible_cloud_staging": len(sections.get("possible_cloud_staging", [])),
        "possible_cloud_exfiltration": len(sections.get("possible_cloud_exfiltration", [])),
        "usb_storage_devices": len(sections.get("usb_storage_devices", [])),
        "usb_volume_mappings": len(sections.get("usb_volume_mappings", [])),
        "setupapi_driver_activity": len(sections.get("setupapi_driver_activity", [])),
        "download_to_usb": len(sections.get("download_to_usb", [])),
        "possible_usb_exfiltration": len(sections.get("possible_usb_exfiltration", [])),
        "suspicious_usb_activity": len(sections.get("suspicious_usb_activity", [])),
        "background_downloads": len(sections.get("background_downloads", [])),
        "bits_jobs": len(sections.get("bits_jobs", [])),
        "bits_transfers": len(sections.get("bits_transfers", [])),
        "suspicious_bits_jobs": len(sections.get("suspicious_bits_jobs", [])),
        "bits_notify_commands": len(sections.get("bits_notify_commands", [])),
        "downloaded_then_executed": len(sections.get("downloaded_then_executed", [])),
        "downloaded_then_detected": len(sections.get("downloaded_then_detected", [])),
        "wmi_persistence": len(sections.get("wmi_persistence", [])),
        "suspicious_wmi_consumers": len(sections.get("suspicious_wmi_consumers", [])),
        "autoruns_persistence": len(sections.get("autoruns_persistence", [])),
        "suspicious_autoruns": len(sections.get("suspicious_autoruns", [])),
        "ifeo_debugger_persistence": len(sections.get("ifeo_debugger_persistence", [])),
        "winlogon_persistence": len(sections.get("winlogon_persistence", [])),
        "folder_activity": len(sections.get("folder_activity", [])),
        "network_share_activity": len(sections.get("network_share_activity", [])),
        "usb_folder_activity": len(sections.get("usb_folder_activity", [])),
        "cloud_folder_activity": len(sections.get("cloud_folder_activity", [])),
        "services_created": len(sections.get("service_created", [])),
        "scheduled_tasks_created": len(sections.get("scheduled_task_created", [])),
        "scheduled_tasks_observed": len(sections.get("scheduled_tasks", [])),
        "logons": len(sections.get("logon_success", [])) + len(sections.get("logon_failed", [])),
        "rdp_sessions": len(sections.get("rdp_logon", [])) + len(sections.get("rdp_disconnect", [])),
        "defender_detections": len(sections.get("defender_detections", [])),
        "detected_downloads": len(sections.get("detected_downloads", [])),
        "detected_executions": len(sections.get("detected_executions", [])),
        "quarantined_items": len(sections.get("quarantined_items", [])),
        "remediation_failures": len(sections.get("remediation_failures", [])),
        "suspicious_findings": len(sections.get("suspicious_findings", [])),
        "account_changes": len(sections.get("account_changes", [])),
        "anti_forensics": len(sections.get("anti_forensics", [])),
        "usb_devices": len(sections.get("usb_devices", [])),
        "user_activity": len(sections.get("user_activity", [])),
    }
    result = {
        "case_id": case_id,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "time_range": {
            "from": time_from,
            "to": time_to,
        },
        "summary": summary,
        "sections": sections,
    }
    _emit_progress(progress_cb, "completed", 100, {"total_activities": len(activities), "total_events": len(events)})
    return result


def render_case_semi_auto_markdown(analysis: dict, *, case_name: str | None = None) -> str:
    summary = analysis.get("summary", {}) or {}
    sections = analysis.get("sections", {}) or {}
    time_range = analysis.get("time_range", {}) or {}

    lines = [
        f"# Semi-Automatic Analysis Report{f' - {case_name}' if case_name else ''}",
        "",
        f"- Case ID: {analysis.get('case_id', '-')}",
        f"- Generated at: {analysis.get('generated_at', '-')}",
        f"- Time from: {time_range.get('from') or 'not set'}",
        f"- Time to: {time_range.get('to') or 'not set'}",
        "",
        "## Summary",
        "",
        f"- Total events: {summary.get('total_events', 0)}",
        f"- Total activities: {summary.get('total_activities', 0)}",
        f"- Program executions: {summary.get('program_executions', 0)}",
        f"- PowerShell executions: {summary.get('powershell_executions', 0)}",
        f"- Logons: {summary.get('logons', 0)}",
        f"- RDP sessions: {summary.get('rdp_sessions', 0)}",
        f"- Services created: {summary.get('services_created', 0)}",
        f"- Scheduled tasks created: {summary.get('scheduled_tasks_created', 0)}",
        f"- Defender detections: {summary.get('defender_detections', 0)}",
        f"- BITS jobs: {summary.get('bits_jobs', 0)}",
        f"- Suspicious BITS jobs: {summary.get('suspicious_bits_jobs', 0)}",
        f"- WMI persistence candidates: {summary.get('wmi_persistence', 0)}",
        f"- Autoruns persistence entries: {summary.get('autoruns_persistence', 0)}",
        f"- Suspicious autoruns: {summary.get('suspicious_autoruns', 0)}",
        f"- Cloud sync roots: {summary.get('cloud_sync_roots', 0)}",
        f"- Cloud accounts: {summary.get('cloud_accounts', 0)}",
        f"- Possible cloud staging: {summary.get('possible_cloud_staging', 0)}",
        f"- Possible cloud exfiltration: {summary.get('possible_cloud_exfiltration', 0)}",
        f"- Recycled files: {summary.get('recycled_files', 0)}",
        f"- Suspicious findings: {summary.get('suspicious_findings', 0)}",
        "",
    ]

    section_order = [
        ("program_executions", "Programas ejecutados"),
        ("powershell", "PowerShell"),
        ("powershell_activity", "Actividad PowerShell"),
        ("powershell_downloads", "Descargas vía PowerShell"),
        ("powershell_encoded_commands", "PowerShell encoded"),
        ("powershell_defender_tampering", "Defender tampering vía PowerShell"),
        ("powershell_persistence", "Persistencia vía PowerShell"),
        ("powershell_recon", "Reconocimiento vía PowerShell"),
        ("powershell_credential_access", "Credential access vía PowerShell"),
        ("browser_history", "Historial de navegador"),
        ("downloaded_files", "Archivos descargados"),
        ("web_searches", "Búsquedas web"),
        ("cloud_activity", "Actividad cloud / sharing"),
        ("cloud_sync_roots", "Cloud sync roots"),
        ("cloud_accounts", "Cloud accounts"),
        ("cloud_file_activity", "Actividad de archivos cloud"),
        ("cloud_sensitive_files", "Archivos sensibles en cloud"),
        ("cloud_archives", "Archivos comprimidos en cloud"),
        ("downloaded_to_cloud", "Descargas hacia cloud"),
        ("copied_to_cloud", "Copias hacia cloud"),
        ("executable_from_cloud", "Ejecutables en cloud"),
        ("defender_detection_in_cloud", "Detecciones Defender en cloud"),
        ("possible_cloud_staging", "Posible staging en cloud"),
        ("possible_cloud_exfiltration", "Posible exfiltración cloud"),
        ("suspicious_downloads", "Descargas sospechosas"),
        ("downloaded_and_executed", "Descargados y ejecutados"),
        ("program_inventory", "Inventario de programas"),
        ("file_creations", "Archivos creados"),
        ("file_modifications", "Archivos modificados"),
        ("file_deletions", "Archivos borrados"),
        ("recycled_files", "Archivos reciclados"),
        ("deleted_downloads", "Descargas borradas"),
        ("deleted_executables", "Ejecutables borrados"),
        ("deleted_scripts", "Scripts borrados"),
        ("deleted_detected_files", "Archivos detectados y borrados"),
        ("cleanup_candidates", "Posibles limpiezas"),
        ("file_renames", "Renombrados"),
        ("logons", "Logons"),
        ("rdp", "RDP"),
        ("opened_files", "Archivos abiertos"),
        ("recent_documents", "Documentos recientes"),
        ("execution_candidates", "Candidatos a ejecución"),
        ("downloaded_and_observed_programs", "Descargados y observados"),
        ("network_activity", "Actividad de red"),
        ("application_network_usage", "Uso de red por aplicación"),
        ("high_upload_activity", "Alto volumen de subida"),
        ("remote_access_activity", "Acceso remoto con red"),
        ("possible_exfiltration", "Posible exfiltración"),
        ("downloaded_and_network_active_programs", "Descargados con actividad de red"),
        ("suspicious_programs", "Programas sospechosos"),
        ("scheduled_tasks", "Tareas programadas"),
        ("suspicious_tasks", "Tareas sospechosas"),
        ("task_executions", "Ejecuciones de tareas"),
        ("downloaded_and_persisted", "Descargados y persistidos"),
        ("defender_detections", "Detecciones de Defender"),
        ("detected_files", "Archivos detectados"),
        ("detected_downloads", "Descargados detectados"),
        ("detected_executions", "Ejecutados detectados"),
        ("quarantined_items", "Elementos en cuarentena"),
        ("remediation_failures", "Fallos de remediación"),
        ("suspicious_files", "Archivos sospechosos"),
        ("applications_used", "Aplicaciones usadas"),
        ("scripts_opened", "Scripts abiertos"),
        ("network_paths", "Rutas de red"),
        ("removable_media", "USB / removible"),
        ("user_activity", "Actividad de usuario"),
        ("usb_devices", "Dispositivos USB"),
        ("usb_storage_devices", "Dispositivos USB de almacenamiento"),
        ("usb_volume_mappings", "Mapeos de volumen USB"),
        ("setupapi_driver_activity", "Actividad SetupAPI / driver updates"),
        ("usb_file_activity", "Actividad de archivos USB"),
        ("usb_folder_activity", "Actividad de carpetas USB"),
        ("download_to_usb", "Descargas hacia USB"),
        ("possible_usb_exfiltration", "Posible exfiltración a USB"),
        ("suspicious_usb_activity", "Actividad USB sospechosa"),
        ("background_downloads", "Descargas en segundo plano"),
        ("bits_jobs", "Jobs BITS"),
        ("bits_transfers", "Transferencias BITS"),
        ("suspicious_bits_jobs", "Jobs BITS sospechosos"),
        ("bits_notify_commands", "BITS notify commands"),
        ("downloaded_then_executed", "Descargados vía BITS y luego ejecutados"),
        ("downloaded_then_detected", "Descargados vía BITS y luego detectados"),
        ("possible_persistence", "Posible persistencia"),
        ("wmi_persistence", "Persistencia WMI"),
        ("wmi_filters", "WMI filters"),
        ("wmi_consumers", "WMI consumers"),
        ("wmi_bindings", "WMI bindings"),
        ("suspicious_wmi_consumers", "WMI consumers sospechosos"),
        ("wmi_encoded_powershell", "WMI encoded PowerShell"),
        ("wmi_download_commands", "WMI download commands"),
        ("possible_wmi_execution", "Posible ejecución por WMI"),
        ("wmi_activity", "Actividad WMI"),
        ("autoruns_persistence", "Autoruns / persistencia"),
        ("suspicious_autoruns", "Autoruns sospechosos"),
        ("run_key_persistence", "Persistencia por Run Keys"),
        ("startup_folder_persistence", "Persistencia por Startup folder"),
        ("service_driver_persistence", "Persistencia por servicios y drivers"),
        ("scheduled_task_persistence", "Persistencia por tareas"),
        ("ifeo_debugger_persistence", "Persistencia IFEO Debugger"),
        ("winlogon_persistence", "Persistencia Winlogon"),
        ("appinit_appcert_persistence", "Persistencia AppInit / AppCert"),
        ("downloaded_then_persisted", "Descargados y luego persistidos"),
        ("persisted_then_executed", "Persistidos y luego ejecutados"),
        ("persistence_detected_by_defender", "Persistencia detectada por Defender"),
        ("services", "Servicios"),
        ("network_connections", "Conexiones de red"),
        ("defender", "Defender"),
        ("account_changes", "Cambios de cuentas"),
        ("anti_forensics", "Anti-forensics"),
        ("persistence", "Persistencia"),
        ("suspicious_findings", "Hallazgos sospechosos"),
        ("timeline", "Timeline global"),
    ]

    for section_key, section_label in section_order:
        items = sections.get(section_key, []) or []
        lines.extend([f"## {section_label}", ""])
        if not items:
            lines.extend(["_No activity surfaced for this section._", ""])
            continue
        for item in items:
            key_fields = item.get("key_fields", {}) or {}
            lines.append(f"### {item.get('title') or item.get('activity_type') or 'Activity'}")
            lines.append("")
            lines.append(f"- Timestamp: {item.get('timestamp') or '-'}")
            lines.append(f"- Host: {item.get('host') or '-'}")
            lines.append(f"- User: {item.get('user') or '-'}")
            lines.append(f"- Severity: {item.get('severity') or '-'}")
            lines.append(f"- Confidence: {item.get('confidence') if item.get('confidence') is not None else '-'}")
            lines.append(f"- Summary: {item.get('summary') or '-'}")
            if item.get("evidence_refs"):
                lines.append(f"- Evidence refs: {', '.join(item.get('evidence_refs', []))}")
            if item.get("related_events"):
                lines.append(f"- Related events: {', '.join(item.get('related_events', []))}")
            if item.get("suspicious_reasons"):
                lines.append(f"- Suspicious reasons: {', '.join(item.get('suspicious_reasons', []))}")
            if key_fields:
                lines.append("- Key fields:")
                for key, value in key_fields.items():
                    if value in (None, "", [], {}):
                        continue
                    if isinstance(value, list):
                        rendered = ", ".join(str(entry) for entry in value)
                    else:
                        rendered = str(value)
                    lines.append(f"  - {key}: {rendered}")
            lines.append("")

    return "\n".join(lines)


def render_case_semi_auto_text(analysis: dict, *, case_name: str | None = None) -> str:
    summary = analysis.get("summary", {}) or {}
    sections = analysis.get("sections", {}) or {}
    time_range = analysis.get("time_range", {}) or {}

    lines = [
        f"Semi-Automatic Analysis Report{f' - {case_name}' if case_name else ''}",
        "",
        f"Case ID: {analysis.get('case_id', '-')}",
        f"Generated at: {analysis.get('generated_at', '-')}",
        f"Time from: {time_range.get('from') or 'not set'}",
        f"Time to: {time_range.get('to') or 'not set'}",
        "",
        "SUMMARY",
        f"  Total events: {summary.get('total_events', 0)}",
        f"  Total activities: {summary.get('total_activities', 0)}",
        f"  Program executions: {summary.get('program_executions', 0)}",
        f"  PowerShell executions: {summary.get('powershell_executions', 0)}",
        f"  Logons: {summary.get('logons', 0)}",
        f"  RDP sessions: {summary.get('rdp_sessions', 0)}",
        f"  Services created: {summary.get('services_created', 0)}",
        f"  Scheduled tasks created: {summary.get('scheduled_tasks_created', 0)}",
        f"  Defender detections: {summary.get('defender_detections', 0)}",
        f"  BITS jobs: {summary.get('bits_jobs', 0)}",
        f"  Suspicious BITS jobs: {summary.get('suspicious_bits_jobs', 0)}",
        f"  WMI persistence candidates: {summary.get('wmi_persistence', 0)}",
        f"  Autoruns persistence entries: {summary.get('autoruns_persistence', 0)}",
        f"  Suspicious autoruns: {summary.get('suspicious_autoruns', 0)}",
        f"  Cloud sync roots: {summary.get('cloud_sync_roots', 0)}",
        f"  Cloud accounts: {summary.get('cloud_accounts', 0)}",
        f"  Possible cloud staging: {summary.get('possible_cloud_staging', 0)}",
        f"  Possible cloud exfiltration: {summary.get('possible_cloud_exfiltration', 0)}",
        f"  Recycled files: {summary.get('recycled_files', 0)}",
        f"  Suspicious findings: {summary.get('suspicious_findings', 0)}",
        "",
    ]

    section_order = [
        ("program_executions", "Programas ejecutados"),
        ("powershell", "PowerShell"),
        ("powershell_activity", "Actividad PowerShell"),
        ("powershell_downloads", "Descargas vía PowerShell"),
        ("powershell_encoded_commands", "PowerShell encoded"),
        ("powershell_defender_tampering", "Defender tampering vía PowerShell"),
        ("powershell_persistence", "Persistencia vía PowerShell"),
        ("powershell_recon", "Reconocimiento vía PowerShell"),
        ("powershell_credential_access", "Credential access vía PowerShell"),
        ("browser_history", "Historial de navegador"),
        ("downloaded_files", "Archivos descargados"),
        ("web_searches", "Búsquedas web"),
        ("cloud_activity", "Actividad cloud / sharing"),
        ("cloud_sync_roots", "Cloud sync roots"),
        ("cloud_accounts", "Cloud accounts"),
        ("cloud_file_activity", "Actividad de archivos cloud"),
        ("cloud_sensitive_files", "Archivos sensibles en cloud"),
        ("cloud_archives", "Archivos comprimidos en cloud"),
        ("downloaded_to_cloud", "Descargas hacia cloud"),
        ("copied_to_cloud", "Copias hacia cloud"),
        ("executable_from_cloud", "Ejecutables en cloud"),
        ("defender_detection_in_cloud", "Detecciones Defender en cloud"),
        ("possible_cloud_staging", "Posible staging en cloud"),
        ("possible_cloud_exfiltration", "Posible exfiltración cloud"),
        ("suspicious_downloads", "Descargas sospechosas"),
        ("downloaded_and_executed", "Descargados y ejecutados"),
        ("program_inventory", "Inventario de programas"),
        ("file_creations", "Archivos creados"),
        ("file_modifications", "Archivos modificados"),
        ("file_deletions", "Archivos borrados"),
        ("recycled_files", "Archivos reciclados"),
        ("deleted_downloads", "Descargas borradas"),
        ("deleted_executables", "Ejecutables borrados"),
        ("deleted_scripts", "Scripts borrados"),
        ("deleted_detected_files", "Archivos detectados y borrados"),
        ("cleanup_candidates", "Posibles limpiezas"),
        ("file_renames", "Renombrados"),
        ("logons", "Logons"),
        ("rdp", "RDP"),
        ("opened_files", "Archivos abiertos"),
        ("recent_documents", "Documentos recientes"),
        ("execution_candidates", "Candidatos a ejecución"),
        ("downloaded_and_observed_programs", "Descargados y observados"),
        ("suspicious_programs", "Programas sospechosos"),
        ("suspicious_files", "Archivos sospechosos"),
        ("applications_used", "Aplicaciones usadas"),
        ("scripts_opened", "Scripts abiertos"),
        ("network_paths", "Rutas de red"),
        ("removable_media", "USB / removible"),
        ("user_activity", "Actividad de usuario"),
        ("usb_devices", "Dispositivos USB"),
        ("usb_storage_devices", "Dispositivos USB de almacenamiento"),
        ("usb_volume_mappings", "Mapeos de volumen USB"),
        ("setupapi_driver_activity", "Actividad SetupAPI / driver updates"),
        ("usb_file_activity", "Actividad de archivos USB"),
        ("usb_folder_activity", "Actividad de carpetas USB"),
        ("download_to_usb", "Descargas hacia USB"),
        ("possible_usb_exfiltration", "Posible exfiltración a USB"),
        ("suspicious_usb_activity", "Actividad USB sospechosa"),
        ("background_downloads", "Descargas en segundo plano"),
        ("bits_jobs", "Jobs BITS"),
        ("bits_transfers", "Transferencias BITS"),
        ("suspicious_bits_jobs", "Jobs BITS sospechosos"),
        ("bits_notify_commands", "BITS notify commands"),
        ("downloaded_then_executed", "Descargados vía BITS y luego ejecutados"),
        ("downloaded_then_detected", "Descargados vía BITS y luego detectados"),
        ("possible_persistence", "Posible persistencia"),
        ("wmi_persistence", "Persistencia WMI"),
        ("wmi_filters", "WMI filters"),
        ("wmi_consumers", "WMI consumers"),
        ("wmi_bindings", "WMI bindings"),
        ("suspicious_wmi_consumers", "WMI consumers sospechosos"),
        ("wmi_encoded_powershell", "WMI encoded PowerShell"),
        ("wmi_download_commands", "WMI download commands"),
        ("possible_wmi_execution", "Posible ejecución por WMI"),
        ("wmi_activity", "Actividad WMI"),
        ("autoruns_persistence", "Autoruns / persistencia"),
        ("suspicious_autoruns", "Autoruns sospechosos"),
        ("run_key_persistence", "Persistencia por Run Keys"),
        ("startup_folder_persistence", "Persistencia por Startup folder"),
        ("service_driver_persistence", "Persistencia por servicios y drivers"),
        ("scheduled_task_persistence", "Persistencia por tareas"),
        ("ifeo_debugger_persistence", "Persistencia IFEO Debugger"),
        ("winlogon_persistence", "Persistencia Winlogon"),
        ("appinit_appcert_persistence", "Persistencia AppInit / AppCert"),
        ("downloaded_then_persisted", "Descargados y luego persistidos"),
        ("persisted_then_executed", "Persistidos y luego ejecutados"),
        ("persistence_detected_by_defender", "Persistencia detectada por Defender"),
        ("scheduled_tasks", "Tareas programadas"),
        ("services", "Servicios"),
        ("network_connections", "Conexiones de red"),
        ("defender", "Defender"),
        ("account_changes", "Cambios de cuentas"),
        ("anti_forensics", "Anti-forensics"),
        ("persistence", "Persistencia"),
        ("suspicious_findings", "Hallazgos sospechosos"),
        ("timeline", "Timeline global"),
    ]

    for section_key, section_label in section_order:
        items = sections.get(section_key, []) or []
        lines.extend([section_label.upper(), ""])
        if not items:
            lines.extend(["  No activity surfaced for this section.", ""])
            continue
        for item in items:
            key_fields = item.get("key_fields", {}) or {}
            lines.append(f"  - {item.get('title') or item.get('activity_type') or 'Activity'}")
            lines.append(f"    Timestamp: {item.get('timestamp') or '-'}")
            lines.append(f"    Host: {item.get('host') or '-'}")
            lines.append(f"    User: {item.get('user') or '-'}")
            lines.append(f"    Severity: {item.get('severity') or '-'}")
            lines.append(f"    Summary: {item.get('summary') or '-'}")
            if item.get("evidence_refs"):
                lines.append(f"    Evidence refs: {', '.join(item.get('evidence_refs', []))}")
            if item.get("suspicious_reasons"):
                lines.append(f"    Suspicious reasons: {', '.join(item.get('suspicious_reasons', []))}")
            for key, value in key_fields.items():
                if value in (None, "", [], {}):
                    continue
                rendered = ", ".join(str(entry) for entry in value) if isinstance(value, list) else str(value)
                lines.append(f"    {key}: {rendered}")
            lines.append("")

    return "\n".join(lines)
