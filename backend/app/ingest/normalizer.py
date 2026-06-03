import csv
import json
import re
from collections import Counter, defaultdict
from datetime import UTC, datetime
from pathlib import Path
from uuid import uuid4

from dateutil import parser as date_parser

from app.core.rules import load_suspicious_keywords
from app.ingest.browser.detector import looks_like_browser_artifact
from app.ingest.browser.normalizer import normalize_browser_event
from app.ingest.browser.parser import read_browser_records
from app.ingest.browser.sqlite_chromium import parse_chromium_history_sqlite
from app.ingest.browser.sqlite_firefox import parse_firefox_places_sqlite
from app.ingest.autoruns import (
    looks_like_autoruns_artifact,
    normalize_autoruns_row,
    parse_autoruns_csv_file,
    parse_autoruns_tsv_file,
    parse_autoruns_xml_file,
)
from app.ingest.bits import (
    looks_like_bits_artifact,
    normalize_bits_row,
    parse_bits_csv_file,
    parse_bits_json_file,
    parse_bitsadmin_file,
)
from app.ingest.cloud_sync import (
    looks_like_cloud_sync_artifact,
    normalize_cloud_row,
    parse_cloud_csv_file,
    parse_cloud_json_file,
    parse_cloud_log_file,
)
from app.ingest.browser.normalizer import BrowserAudit
from app.ingest.defender import (
    looks_like_defender_artifact,
    looks_like_defender_event_row,
    normalize_defender_row,
    parse_detection_history_file,
    parse_mplog_file,
    read_defender_csv_rows,
    read_defender_json_rows,
)
from app.ingest.email import (
    looks_like_email_artifact,
    normalize_email_row,
    parse_email_artifact_file,
)
from app.ingest.ntfs import (
    looks_like_ntfs_artifact,
    normalize_ntfs_row,
    parse_ntfs_artifact_file,
)
from app.ingest.windows_ui import (
    looks_like_windows_ui_artifact,
    normalize_windows_ui_row,
    parse_windows_ui_artifact_file,
)
from app.ingest.eztools.base import ensure_csv_field_limit
from app.ingest.eztools.amcache import AmcacheParser
from app.ingest.eztools.evtxecmd import parse_evtxecmd_file
from app.ingest.eztools.jlecmd import JLECmdParser, parse_jlecmd_file
from app.ingest.eztools.lecmd import LECmdParser, parse_lecmd_file
from app.ingest.eztools.mftecmd import MFTECmdParser, parse_mftecmd_file
from app.ingest.eztools.pecmd import PECmdParser, parse_pecmd_file
from app.ingest.eztools.recmd import RECmdParser, parse_recmd_file
from app.ingest.eztools.shimcache import ShimCacheParser
from app.ingest.eztools.srumecmd import SrumECmdParser
from app.ingest.scheduled_tasks import (
    looks_like_scheduled_task_csv,
    looks_like_scheduled_task_xml_path,
    normalize_scheduled_task_row,
    parse_scheduled_task_xml,
    read_scheduled_task_csv_rows,
)
from app.ingest.powershell import (
    looks_like_powershell_artifact,
    normalize_powershell_row,
    parse_psreadline_history,
    parse_powershell_script_file,
    parse_powershell_transcript,
    read_powershell_csv_rows,
    read_powershell_json_rows,
)
from app.ingest.jumplists import parse_automatic_destinations_file, parse_custom_destinations_file, read_jumplist_csv_rows
from app.ingest.network import (
    classify_dns_client_event,
    classify_network_registry_row,
    classify_wlan_autoconfig_event,
    looks_like_network_artifact,
    normalize_network_row as normalize_network_artifact_row,
    parse_arp_txt,
    parse_dns_csv_file,
    parse_dns_json_file,
    parse_hosts_file,
    parse_ipconfig_txt,
    parse_netsh_wlan_txt,
    parse_netstat_txt,
    parse_network_csv_file,
    parse_network_json_file,
    parse_wlan_profile_xml,
)
from app.ingest.raw_parsers.router import route_raw_parser
from app.ingest.recycle_bin import (
    looks_like_recycle_bin_artifact,
    parse_recycle_i_file,
    parse_recycle_r_file,
    read_recycle_bin_csv_rows,
    read_recycle_bin_json_rows,
)
from app.ingest.shellbags import (
    looks_like_shellbags_artifact,
    read_shellbags_csv_rows,
)
from app.ingest.usb import (
    looks_like_usb_artifact,
    normalize_usb_row,
    parse_setupapi_dev_log,
    parse_usb_csv_file,
)
from app.ingest.wmi.autoruns_parser import parse_autoruns_wmi_csv_file
from app.ingest.wmi.csv_parser import parse_wmi_csv_file
from app.ingest.wmi.evtx_classifier import classify_wmi_activity_event
from app.ingest.wmi.helpers import looks_like_wmi_artifact
from app.ingest.wmi.json_parser import parse_wmi_json_file
from app.ingest.wmi.normalizer import normalize_wmi_row
from app.ingest.artifact_normalizers import (
    first_value,
    normalize_amcache_row,
    normalize_browser_row,
    normalize_evtx_row,
    normalize_generic_row,
    normalize_jumplist_row,
    normalize_lnk_row,
    normalize_mft_row,
    normalize_prefetch_row,
    normalize_process_row,
    normalize_recycle_bin_row,
    normalize_registry_row,
    normalize_service_row,
    normalize_shellbags_row,
    normalize_shimcache_row,
    normalize_srum_row,
)
from app.ingest.identity_extraction import extract_host, extract_user, is_valid_username
from app.ingest.windows_event_mapping import apply_tag_risk_adjustments, risk_score_to_severity, severity_to_risk_score


SUSPICIOUS_RULES = load_suspicious_keywords()
INVALID_TS_MARKERS = {"", "n/a", "na", "none", "null"}
INVALID_TS_PREFIXES = ("0001-01-01", "1601-01-01", "1970-01-01")
MICROSOFT_DOMAINS = ("microsoft.com", "windowsupdate.com", "update.microsoft.com", "download.windowsupdate.com", "delivery.mp.microsoft.com")
KNOWN_GOOD_WINDOWS_PATH_MARKERS = (
    "\\windows\\system32\\",
    "\\windows\\syswow64\\",
    "\\program files\\microsoft",
    "\\program files (x86)\\microsoft",
    "\\program files\\windowsapps\\",
)
KNOWN_GOOD_UPDATE_PATH_MARKERS = (
    "\\windows\\softwaredistribution\\",
    "\\windows\\servicing\\",
    "\\programdata\\microsoft\\windows\\deliveryoptimization\\",
)
TIMESTAMP_CANDIDATES = [
    "@timestamp",
    "Timestamp",
    "TimeCreated",
    "Time",
    "LastRunTime",
    "LastRun",
    "LastRun0",
    "RunTime",
    "Created0x10",
    "Created0x30",
    "Modified0x10",
    "Modified0x30",
    "LastAccess0x10",
    "LastAccess0x30",
    "LastRecordChange0x10",
    "LastRecordChange0x30",
    "LastModified",
    "LastWriteTime",
    "EventTime",
    "Date",
    "SourceCreated",
    "SourceModified",
]


def _csv_headers(path: Path) -> set[str]:
    try:
        ensure_csv_field_limit()
        with path.open("r", encoding="utf-8-sig", errors="ignore") as handle:
            reader = csv.reader(handle)
            headers = next(reader, [])
    except Exception:  # noqa: BLE001
        return set()
    return {str(header).strip().lower() for header in headers if header}


def _looks_like_evtxecmd(path: Path, artifact_meta: dict) -> bool:
    lower_name = path.name.lower()
    artifact_type = str(artifact_meta.get("artifact_type") or "").lower()
    parser = str(artifact_meta.get("parser") or "").lower()
    if path.suffix.lower() != ".csv":
        return False
    if artifact_type == "evtx" and (parser in {"zimmerman", "hayabusa"} or "evtxecmd" in lower_name):
        return True
    headers = _csv_headers(path)
    return {"eventid", "channel", "provider"} <= headers


def _looks_like_pecmd(path: Path, artifact_meta: dict) -> bool:
    lower_name = path.name.lower()
    artifact_type = str(artifact_meta.get("artifact_type") or "").lower()
    parser = str(artifact_meta.get("parser") or "").lower()
    if path.suffix.lower() != ".csv":
        return False
    if artifact_type == "prefetch" and (parser == "zimmerman" or "pecmd" in lower_name):
        return True
    headers = _csv_headers(path)
    return PECmdParser().can_parse(path, list(headers))


def _looks_like_lecmd(path: Path, artifact_meta: dict) -> bool:
    lower_name = path.name.lower()
    artifact_type = str(artifact_meta.get("artifact_type") or "").lower()
    parser = str(artifact_meta.get("parser") or "").lower()
    if path.suffix.lower() != ".csv":
        return False
    if artifact_type == "lnk" and (parser == "zimmerman" or ("lecmd" in lower_name and "jlecmd" not in lower_name)):
        return True
    headers = _csv_headers(path)
    return LECmdParser().can_parse(path, list(headers))


def _looks_like_jlecmd(path: Path, artifact_meta: dict) -> bool:
    lower_name = path.name.lower()
    artifact_type = str(artifact_meta.get("artifact_type") or "").lower()
    parser = str(artifact_meta.get("parser") or "").lower()
    if path.suffix.lower() != ".csv":
        return False
    if artifact_type == "jumplist" and (parser == "zimmerman" or "jlecmd" in lower_name):
        return True
    headers = _csv_headers(path)
    return JLECmdParser().can_parse(path, list(headers))


def _looks_like_recmd(path: Path, artifact_meta: dict) -> bool:
    lower_name = path.name.lower()
    artifact_type = str(artifact_meta.get("artifact_type") or "").lower()
    parser = str(artifact_meta.get("parser") or "").lower()
    if artifact_type == "usb":
        return False
    if path.suffix.lower() != ".csv":
        return False
    if artifact_type == "registry" and (parser == "zimmerman" or "recmd" in lower_name):
        return True
    headers = _csv_headers(path)
    return RECmdParser().can_parse(path, list(headers))


def _looks_like_mftecmd(path: Path, artifact_meta: dict) -> bool:
    lower_name = path.name.lower()
    artifact_type = str(artifact_meta.get("artifact_type") or "").lower()
    parser = str(artifact_meta.get("parser") or "").lower()
    if path.suffix.lower() != ".csv":
        return False
    if artifact_type in {"mft", "usn"} and (parser == "zimmerman" or "mftecmd" in lower_name or "usn" in lower_name):
        return True
    headers = _csv_headers(path)
    return MFTECmdParser().can_parse(path, list(headers))


def _looks_like_amcache(path: Path, artifact_meta: dict) -> bool:
    lower_name = path.name.lower()
    artifact_type = str(artifact_meta.get("artifact_type") or "").lower()
    parser = str(artifact_meta.get("parser") or "").lower()
    if path.suffix.lower() != ".csv":
        return False
    if artifact_type == "amcache" and (parser in {"zimmerman", "generic_csv"} or "amcache" in lower_name):
        return True
    headers = _csv_headers(path)
    return AmcacheParser().can_parse(path, list(headers))


def _looks_like_shimcache(path: Path, artifact_meta: dict) -> bool:
    lower_name = path.name.lower()
    artifact_type = str(artifact_meta.get("artifact_type") or "").lower()
    parser = str(artifact_meta.get("parser") or "").lower()
    if path.suffix.lower() != ".csv":
        return False
    if artifact_type in {"shimcache", "appcompat"} and (parser in {"zimmerman", "generic_csv"} or any(token in lower_name for token in ["shimcache", "appcompatcache", "recentfilecache"])):
        return True
    headers = _csv_headers(path)
    return ShimCacheParser().can_parse(path, list(headers))


def _looks_like_srum(path: Path, artifact_meta: dict) -> bool:
    lower_name = path.name.lower()
    artifact_type = str(artifact_meta.get("artifact_type") or "").lower()
    parser = str(artifact_meta.get("parser") or "").lower()
    if path.suffix.lower() != ".csv":
        return False
    if artifact_type == "srum" and (parser in {"zimmerman", "generic_csv"} or any(token in lower_name for token in ["srum", "networkusage", "applicationresourceusage", "energyusage", "networkconnectivity"])):
        return True
    headers = _csv_headers(path)
    return SrumECmdParser().can_parse(path, list(headers))


def _looks_like_scheduled_task(path: Path, artifact_meta: dict) -> bool:
    lower_name = path.name.lower()
    artifact_type = str(artifact_meta.get("artifact_type") or "").lower()
    parser = str(artifact_meta.get("parser") or "").lower()
    if artifact_type == "scheduled_task":
        return True
    if parser in {"xml", "scheduled_task_xml"} and looks_like_scheduled_task_xml_path(path):
        return True
    if path.suffix.lower() == ".csv" and (
        "scheduledtask" in lower_name
        or "taskscheduler" in lower_name
        or looks_like_scheduled_task_csv(path, list(_csv_headers(path)))
    ):
        return True
    return False


def _looks_like_powershell(path: Path, artifact_meta: dict) -> bool:
    headers = list(_csv_headers(path)) if path.suffix.lower() == ".csv" else artifact_meta.get("headers") or []
    return looks_like_powershell_artifact(path, headers)


def _looks_like_recycle_bin(path: Path, artifact_meta: dict) -> bool:
    headers = list(_csv_headers(path)) if path.suffix.lower() == ".csv" else artifact_meta.get("headers") or []
    return looks_like_recycle_bin_artifact(path, headers)


def _looks_like_shellbags(path: Path, artifact_meta: dict) -> bool:
    headers = list(_csv_headers(path)) if path.suffix.lower() == ".csv" else artifact_meta.get("headers") or []
    return looks_like_shellbags_artifact(path, headers)


def _looks_like_usb(path: Path, artifact_meta: dict) -> bool:
    headers = list(_csv_headers(path)) if path.suffix.lower() == ".csv" else artifact_meta.get("headers") or []
    return looks_like_usb_artifact(path, headers)


def _looks_like_bits(path: Path, artifact_meta: dict) -> bool:
    headers = list(_csv_headers(path)) if path.suffix.lower() == ".csv" else artifact_meta.get("headers") or []
    return looks_like_bits_artifact(path, headers)


def _looks_like_wmi(path: Path, artifact_meta: dict) -> bool:
    headers = list(_csv_headers(path)) if path.suffix.lower() == ".csv" else artifact_meta.get("headers") or []
    return looks_like_wmi_artifact(path, headers)


def parse_timestamp(value: str | None) -> tuple[str | None, str]:
    if value is None:
        return None, "unknown"
    normalized = str(value).strip()
    if normalized.lower() in INVALID_TS_MARKERS:
        return None, "unknown"
    if normalized.startswith(INVALID_TS_PREFIXES):
        return None, "unknown"
    try:
        parsed = date_parser.parse(normalized)
        if parsed.tzinfo is None:
            parsed = parsed.replace(tzinfo=UTC)
        return parsed.isoformat(), "exact"
    except Exception:  # noqa: BLE001
        return None, "unknown"


def build_raw_summary(row: dict) -> str:
    parts = []
    for key, value in list(row.items())[:10]:
        if value in (None, ""):
            continue
        text_value = str(value)
        if len(text_value) > 220:
            text_value = f"{text_value[:220]}..."
        parts.append(f"{key}={text_value}")
    return " | ".join(parts)[:2000]


def build_search_text(document: dict) -> str:
    prefetch_data = document.get("prefetch", {}) or {}
    referenced_files = list(prefetch_data.get("referenced_files") or [])
    referenced_directories = list(prefetch_data.get("referenced_directories") or [])
    prefetch_search_refs = " | ".join(referenced_files[:8])
    prefetch_search_dirs = " | ".join(referenced_directories[:3])
    email_data = document.get("email", {}) or {}
    email_headers = email_data.get("headers", {}) or {}
    email_attachments = [str(item.get("file_name") or "") for item in (email_data.get("attachments") or []) if isinstance(item, dict)]
    values: list[str] = []
    fields = [
        ((document.get("event", {}) or {}).get("message")),
        ((document.get("host", {}) or {}).get("name")),
        ((document.get("user", {}) or {}).get("name")),
        ((document.get("artifact", {}) or {}).get("name")),
        ((document.get("artifact", {}) or {}).get("type")),
        ((document.get("artifact", {}) or {}).get("source_path")),
        ((document.get("process", {}) or {}).get("name")),
        ((document.get("process", {}) or {}).get("command_line")),
        ((document.get("process", {}) or {}).get("path")),
        ((document.get("file", {}) or {}).get("path")),
        ((document.get("file", {}) or {}).get("name")),
        ((document.get("file", {}) or {}).get("extension")),
        ((document.get("file", {}) or {}).get("sha256")),
        ((document.get("file", {}) or {}).get("sha1")),
        ((document.get("file", {}) or {}).get("md5")),
        ((document.get("browser", {}) or {}).get("url")),
        ((document.get("browser", {}) or {}).get("final_url")),
        ((document.get("browser", {}) or {}).get("domain")),
        ((document.get("browser", {}) or {}).get("title")),
        ((document.get("browser", {}) or {}).get("search_terms")),
        ((document.get("browser", {}) or {}).get("search_engine")),
        ((document.get("browser", {}) or {}).get("source_file")),
        ((document.get("url", {}) or {}).get("full")),
        ((document.get("url", {}) or {}).get("domain")),
        ((document.get("download", {}) or {}).get("url")),
        ((document.get("download", {}) or {}).get("final_url")),
        ((document.get("download", {}) or {}).get("target_path")),
        ((document.get("download", {}) or {}).get("file_name")),
        ((document.get("execution", {}) or {}).get("source")),
        ((document.get("execution", {}) or {}).get("run_count")),
        ((document.get("execution", {}) or {}).get("last_run")),
        ((document.get("execution", {}) or {}).get("program_name")),
        ((document.get("execution", {}) or {}).get("confidence")),
        ((document.get("execution", {}) or {}).get("interpretation")),
        prefetch_data.get("executable_name"),
        prefetch_data.get("executable_path"),
        prefetch_data.get("prefetch_hash"),
        prefetch_data.get("source_file"),
        prefetch_data.get("run_count"),
        prefetch_data.get("last_run"),
        prefetch_data.get("volume_serial_number"),
        prefetch_data.get("volume_device_path"),
        prefetch_search_refs,
        prefetch_search_dirs,
        ((document.get("amcache", {}) or {}).get("program_id")),
        ((document.get("amcache", {}) or {}).get("program_name")),
        ((document.get("amcache", {}) or {}).get("publisher")),
        ((document.get("amcache", {}) or {}).get("product_name")),
        ((document.get("amcache", {}) or {}).get("file_path")),
        ((document.get("shimcache", {}) or {}).get("path")),
        ((document.get("appcompat", {}) or {}).get("path")),
        ((document.get("appcompat", {}) or {}).get("name")),
        ((document.get("srum", {}) or {}).get("app_id")),
        ((document.get("srum", {}) or {}).get("app_name")),
        ((document.get("srum", {}) or {}).get("package_name")),
        ((document.get("srum", {}) or {}).get("user_sid")),
        ((document.get("srum", {}) or {}).get("interface_profile")),
        ((document.get("srum", {}) or {}).get("network_profile")),
        ((document.get("network", {}) or {}).get("application")),
        ((document.get("user", {}) or {}).get("sid")),
        ((document.get("velociraptor", {}) or {}).get("original_path")),
        ((document.get("velociraptor", {}) or {}).get("normalized_windows_path")),
        ((document.get("network", {}) or {}).get("source_ip")),
        ((document.get("network", {}) or {}).get("destination_ip")),
        ((document.get("network", {}) or {}).get("domain")),
        ((document.get("network", {}) or {}).get("url")),
        ((document.get("network", {}) or {}).get("interface_name")),
        ((document.get("network", {}) or {}).get("interface_guid")),
        ((document.get("network", {}) or {}).get("interface_description")),
        ((document.get("network", {}) or {}).get("mac_address")),
        ((document.get("network", {}) or {}).get("ipv4")),
        ((document.get("network", {}) or {}).get("ipv6")),
        ((document.get("network", {}) or {}).get("gateway")),
        " | ".join((document.get("network", {}) or {}).get("dns_servers") or []),
        ((document.get("network", {}) or {}).get("profile_name")),
        ((document.get("dns", {}) or {}).get("name")),
        ((document.get("dns", {}) or {}).get("domain")),
        ((document.get("dns", {}) or {}).get("record_type")),
        ((document.get("dns", {}) or {}).get("ip")),
        ((document.get("wlan", {}) or {}).get("ssid")),
        ((document.get("wlan", {}) or {}).get("profile_name")),
        ((document.get("wlan", {}) or {}).get("bssid")),
        ((document.get("wlan", {}) or {}).get("authentication")),
        ((document.get("wlan", {}) or {}).get("encryption")),
        ((document.get("task", {}) or {}).get("name")),
        ((document.get("task", {}) or {}).get("path")),
        ((document.get("task", {}) or {}).get("uri")),
        ((document.get("task", {}) or {}).get("author")),
        ((document.get("task", {}) or {}).get("run_as")),
        ((document.get("task", {}) or {}).get("command")),
        ((document.get("task", {}) or {}).get("arguments")),
        ((document.get("task", {}) or {}).get("trigger_summary")),
        ((document.get("task", {}) or {}).get("action_summary")),
        ((document.get("service", {}) or {}).get("name")),
        ((document.get("service", {}) or {}).get("display_name")),
        ((document.get("service", {}) or {}).get("description")),
        ((document.get("service", {}) or {}).get("image_path")),
        ((document.get("service", {}) or {}).get("image_path_expanded")),
        ((document.get("service", {}) or {}).get("service_dll")),
        ((document.get("service", {}) or {}).get("service_dll_expanded")),
        ((document.get("service", {}) or {}).get("object_name")),
        ((document.get("service", {}) or {}).get("key_path")),
        ((document.get("wmi", {}) or {}).get("namespace")),
        ((document.get("wmi", {}) or {}).get("filter_name")),
        ((document.get("wmi", {}) or {}).get("consumer_name")),
        ((document.get("wmi", {}) or {}).get("query")),
        ((document.get("wmi", {}) or {}).get("command_line_template")),
        ((document.get("wmi", {}) or {}).get("executable_path")),
        ((document.get("wmi", {}) or {}).get("script_preview")),
        ((document.get("wmi", {}) or {}).get("creator_user")),
        ((document.get("wmi", {}) or {}).get("creator_sid")),
        ((document.get("wmi", {}) or {}).get("source_file")),
        ((document.get("wmi", {}) or {}).get("repository_path")),
        " | ".join(document.get("suspicious_reasons") or []),
        ((document.get("persistence", {}) or {}).get("command")),
        ((document.get("detection", {}) or {}).get("threat_name")),
        ((document.get("detection", {}) or {}).get("threat_id")),
        ((document.get("detection", {}) or {}).get("path")),
        ((document.get("detection", {}) or {}).get("resource")),
        ((document.get("detection", {}) or {}).get("action")),
        ((document.get("detection", {}) or {}).get("status")),
        ((document.get("detection", {}) or {}).get("category")),
        ((document.get("powershell", {}) or {}).get("command")),
        ((document.get("powershell", {}) or {}).get("command_preview")),
        ((document.get("powershell", {}) or {}).get("decoded_command_preview")),
        ((document.get("powershell", {}) or {}).get("source_file")),
        " | ".join((document.get("powershell", {}) or {}).get("urls") or []),
        " | ".join((document.get("powershell", {}) or {}).get("domains") or []),
        " | ".join((document.get("powershell", {}) or {}).get("paths") or []),
        " | ".join((document.get("powershell", {}) or {}).get("indicators") or []),
        ((document.get("windows", {}) or {}).get("event_id")),
        ((document.get("windows", {}) or {}).get("channel")),
        ((document.get("windows", {}) or {}).get("provider")),
        ((document.get("windows", {}) or {}).get("event_data_summary")),
        ((document.get("object", {}) or {}).get("name")),
        ((document.get("object", {}) or {}).get("path")),
        ((document.get("object", {}) or {}).get("type")),
        ((document.get("object", {}) or {}).get("server")),
        ((document.get("access", {}) or {}).get("mask")),
        " | ".join((document.get("access", {}) or {}).get("list") or []),
        ((document.get("access", {}) or {}).get("reason")),
        ((document.get("registry", {}) or {}).get("key_path")),
        ((document.get("registry", {}) or {}).get("value_name")),
        ((document.get("registry", {}) or {}).get("value_data")),
        ((document.get("folder", {}) or {}).get("path")),
        ((document.get("ntfs", {}) or {}).get("reason")),
        ((document.get("ntfs", {}) or {}).get("zone_id")),
        ((document.get("ntfs", {}) or {}).get("zone_name")),
        ((document.get("ntfs", {}) or {}).get("host_url")),
        ((document.get("ntfs", {}) or {}).get("referrer_url")),
        ((document.get("ntfs", {}) or {}).get("old_name")),
        ((document.get("ntfs", {}) or {}).get("new_name")),
        ((document.get("ntfs", {}) or {}).get("shadow_id")),
        ((document.get("ntfs", {}) or {}).get("snapshot_time")),
        ((document.get("lnk", {}) or {}).get("effective_path")),
        ((document.get("lnk", {}) or {}).get("target_path")),
        ((document.get("lnk", {}) or {}).get("local_path")),
        ((document.get("lnk", {}) or {}).get("relative_path")),
        ((document.get("lnk", {}) or {}).get("working_directory")),
        ((document.get("lnk", {}) or {}).get("arguments")),
        ((document.get("lnk", {}) or {}).get("source_file")),
        ((document.get("lnk", {}) or {}).get("machine_id")),
        ((document.get("lnk", {}) or {}).get("drive_serial_number")),
        ((document.get("lnk", {}) or {}).get("display_name")),
        ((document.get("jumplist", {}) or {}).get("effective_path")),
        ((document.get("jumplist", {}) or {}).get("target_path")),
        ((document.get("jumplist", {}) or {}).get("display_name")),
        ((document.get("jumplist", {}) or {}).get("app_name")),
        ((document.get("jumplist", {}) or {}).get("app_id")),
        ((document.get("jumplist", {}) or {}).get("app_id_description")),
        ((document.get("jumplist", {}) or {}).get("arguments")),
        ((document.get("jumplist", {}) or {}).get("working_directory")),
        ((document.get("jumplist", {}) or {}).get("source_file")),
        ((document.get("usb", {}) or {}).get("device_instance_id")),
        ((document.get("usb", {}) or {}).get("raw_instance_id")),
        ((document.get("usb", {}) or {}).get("vendor")),
        ((document.get("usb", {}) or {}).get("product")),
        ((document.get("usb", {}) or {}).get("revision")),
        ((document.get("usb", {}) or {}).get("serial")),
        ((document.get("usb", {}) or {}).get("vid")),
        ((document.get("usb", {}) or {}).get("pid")),
        ((document.get("usb", {}) or {}).get("friendly_name")),
        ((document.get("usb", {}) or {}).get("container_id")),
        ((document.get("usb", {}) or {}).get("parent_device_instance_id")),
        ((document.get("usb", {}) or {}).get("class_guid")),
        ((document.get("usb", {}) or {}).get("class_name")),
        ((document.get("usb", {}) or {}).get("service")),
        ((document.get("usb", {}) or {}).get("driver")),
        ((document.get("usb", {}) or {}).get("driver_provider")),
        ((document.get("usb", {}) or {}).get("driver_version")),
        ((document.get("usb", {}) or {}).get("inf_path")),
        ((document.get("usb", {}) or {}).get("source_file")),
        ((document.get("bits", {}) or {}).get("job_id")),
        ((document.get("bits", {}) or {}).get("job_guid")),
        ((document.get("bits", {}) or {}).get("display_name")),
        ((document.get("bits", {}) or {}).get("description")),
        ((document.get("bits", {}) or {}).get("owner")),
        ((document.get("bits", {}) or {}).get("owner_sid")),
        ((document.get("bits", {}) or {}).get("state")),
        ((document.get("bits", {}) or {}).get("type")),
        ((document.get("bits", {}) or {}).get("remote_url")),
        ((document.get("bits", {}) or {}).get("remote_name")),
        ((document.get("bits", {}) or {}).get("local_path")),
        ((document.get("bits", {}) or {}).get("local_name")),
        ((document.get("bits", {}) or {}).get("notify_cmd_line")),
        ((document.get("bits", {}) or {}).get("source_file")),
        ((document.get("network", {}) or {}).get("domain")),
        ((document.get("download", {}) or {}).get("file_name")),
        ((document.get("cloud", {}) or {}).get("provider")),
        ((document.get("cloud", {}) or {}).get("account")),
        ((document.get("cloud", {}) or {}).get("account_email")),
        ((document.get("cloud", {}) or {}).get("sync_root")),
        ((document.get("cloud", {}) or {}).get("local_path")),
        ((document.get("cloud", {}) or {}).get("remote_path")),
        ((document.get("cloud", {}) or {}).get("cloud_path")),
        ((document.get("cloud", {}) or {}).get("status")),
        ((document.get("cloud", {}) or {}).get("sync_status")),
        ((document.get("cloud", {}) or {}).get("source_file")),
        email_data.get("message_id"),
        email_data.get("subject"),
        ((email_data.get("from", {}) or {}).get("address")),
        ((email_data.get("from", {}) or {}).get("display_name")),
        " | ".join(email_data.get("to") or []),
        " | ".join(email_data.get("cc") or []),
        " | ".join(email_data.get("bcc") or []),
        email_headers.get("reply_to"),
        email_headers.get("return_path"),
        email_headers.get("authentication_results"),
        email_headers.get("received_spf"),
        email_headers.get("x_mailer"),
        email_headers.get("user_agent"),
        email_data.get("body_preview"),
        " | ".join(email_data.get("mailbox_name") and [str(email_data.get("mailbox_name"))] or []),
        " | ".join(email_attachments),
        ((document.get("wmi", {}) or {}).get("namespace")),
        ((document.get("wmi", {}) or {}).get("name")),
        ((document.get("wmi", {}) or {}).get("filter_name")),
        ((document.get("wmi", {}) or {}).get("consumer_name")),
        ((document.get("wmi", {}) or {}).get("query")),
        ((document.get("wmi", {}) or {}).get("command_line_template")),
        ((document.get("wmi", {}) or {}).get("script_preview")),
        ((document.get("wmi", {}) or {}).get("source_file")),
        ((document.get("volume", {}) or {}).get("guid")),
        ((document.get("volume", {}) or {}).get("drive_letter")),
        ((document.get("volume", {}) or {}).get("serial")),
        ((document.get("volume", {}) or {}).get("mounted_device")),
        ((document.get("volume", {}) or {}).get("dos_device")),
        document.get("raw_summary"),
    ]
    for value in fields:
        if value in (None, ""):
            continue
        text = str(value).strip()
        if text:
            values.append(text)
    return " | ".join(values)[:8192]


def base_document(case_id: str, evidence_id: str, artifact_id: str, row: dict, artifact_meta: dict) -> dict:
    timestamp, precision = parse_timestamp(first_value(row, TIMESTAMP_CANDIDATES))
    host_name = extract_host(row, artifact_meta)
    user_name = extract_user(row, artifact_meta)
    os_type = artifact_meta.get("os_type", "windows" if artifact_meta.get("parser") in {"velociraptor", "kape", "zimmerman", "hayabusa", "generic_csv"} else "unknown")
    artifact_type = artifact_meta.get("artifact_type") or "unknown"
    source_path = artifact_meta.get("source_path")
    artifact_name = artifact_meta.get("name") or Path(str(source_path or "")).name or artifact_type
    parser_name = artifact_meta.get("parser")
    ingest_run_id = str(artifact_meta.get("ingest_run_id") or artifact_meta.get("run_id") or "")
    contract_version = str(artifact_meta.get("contract_version") or artifact_meta.get("output_contract_version") or "v1")
    return {
        "event_id": str(uuid4()),
        "case_id": case_id,
        "evidence_id": evidence_id,
        "ingest_run_id": ingest_run_id or None,
        "contract_version": contract_version,
        "artifact_id": artifact_id,
        "source_file": source_path,
        "source_tool": artifact_meta.get("source_tool") or parser_name,
        "source_format": artifact_meta.get("source_format") or Path(str(artifact_name or "")).suffix.lower().lstrip(".") or None,
        "@timestamp": timestamp,
        "timestamp_precision": precision,
        "timezone": "UTC" if timestamp else None,
        "os": {"type": os_type, "version": None},
        "host": {"name": host_name, "hostname": host_name, "ip": [], "os": "Windows" if os_type == "windows" else None},
        "user": {"name": user_name if is_valid_username(user_name) else None, "sid": first_value(row, ["SID", "UserSid"])},
        "artifact": {
            "type": artifact_type,
            "name": artifact_name,
            "source_path": source_path,
            "parser": parser_name,
        },
        "event": {"category": "unknown", "type": "unknown", "action": artifact_type, "severity": "info", "message": artifact_name},
        "process": {
            "entity_id": None,
            "pid": None,
            "ppid": None,
            "parent_pid": None,
            "name": None,
            "path": None,
            "command_line": None,
            "current_directory": None,
            "parent_entity_id": None,
            "parent_name": None,
            "parent_path": None,
            "parent_command_line": None,
            "integrity_level": None,
            "hashes": {"md5": None, "sha1": None, "sha256": None},
            "application": None,
        },
        "destination": {"hostname": None, "ip": None, "port": None},
        "object": {"name": None, "path": None, "type": None, "server": None},
        "access": {"mask": None, "list": [], "accesses": [], "reason": None},
        "file": {
            "path": None,
            "name": None,
            "extension": None,
            "size": None,
            "sha1": None,
            "sha256": None,
            "md5": None,
            "created": None,
            "modified": None,
            "accessed": None,
            "changed": None,
            "deleted": None,
            "parent_path": None,
            "source_path": None,
        },
        "folder": {
            "path": None,
        },
        "mft": {
            "entry_number": None,
            "sequence_number": None,
            "parent_entry_number": None,
            "parent_sequence_number": None,
            "in_use": None,
            "is_deleted": None,
            "ads": None,
            "si_created": None,
            "si_modified": None,
            "si_accessed": None,
            "si_changed": None,
            "fn_created": None,
            "fn_modified": None,
            "fn_accessed": None,
            "fn_changed": None,
        },
        "execution": {
            "source": None,
            "run_count": None,
            "first_run": None,
            "last_run": None,
            "last_runs": [],
            "program_name": None,
            "confidence": None,
            "is_execution_confirmed": None,
            "interpretation": None,
            "first_seen": None,
            "last_seen": None,
            "last_modified": None,
            "install_date": None,
            "compile_time": None,
        },
        "autoruns": {
            "artifact_type": None,
            "category": None,
            "entry_location": None,
            "entry": None,
            "enabled": None,
            "profile": None,
            "description": None,
            "publisher": None,
            "company": None,
            "signer": None,
            "signed": None,
            "verified": None,
            "image_path": None,
            "launch_string": None,
            "command_line": None,
            "arguments": None,
            "working_directory": None,
            "hash_md5": None,
            "hash_sha1": None,
            "hash_sha256": None,
            "pe_sha1": None,
            "pe_sha256": None,
            "virus_total": None,
            "vt_detection": None,
            "vt_link": None,
            "wow64": None,
            "user": None,
            "sid": None,
            "timestamp": None,
            "source_file": None,
            "parser_status": None,
            "timestamp_interpretation": None,
        },
        "persistence": {
            "mechanism": None,
            "location": None,
            "name": None,
            "command": None,
            "path": None,
            "enabled": None,
            "scope": None,
            "user": None,
            "sid": None,
            "confidence": None,
            "source": None,
        },
        "volume": {"guid": None, "drive_letter": None, "serial": None, "label": None, "drive_type": None, "created": None, "mounted_device": None, "dos_device": None},
        "usb": {
            "artifact_type": None,
            "device_instance_id": None,
            "parent_device_instance_id": None,
            "hardware_id": None,
            "compatible_ids": None,
            "vendor": None,
            "product": None,
            "revision": None,
            "serial": None,
            "vid": None,
            "pid": None,
            "device_id": None,
            "friendly_name": None,
            "container_id": None,
            "parent_id_prefix": None,
            "class_guid": None,
            "class_name": None,
            "service": None,
            "driver": None,
            "driver_provider": None,
            "driver_date": None,
            "driver_version": None,
            "inf_path": None,
            "install_status": None,
            "result_code": None,
            "first_install_time": None,
            "install_time": None,
            "last_arrival_time": None,
            "last_connected_time": None,
            "last_removal_time": None,
            "section_start_time": None,
            "section_end_time": None,
            "source_file": None,
            "line_start": None,
            "line_end": None,
            "raw_instance_id": None,
            "device_type": None,
            "parse_warnings": None,
        },
        "bits": {
            "artifact_type": None,
            "job_id": None,
            "job_guid": None,
            "display_name": None,
            "description": None,
            "owner": None,
            "owner_sid": None,
            "state": None,
            "type": None,
            "priority": None,
            "remote_name": None,
            "remote_url": None,
            "local_name": None,
            "local_path": None,
            "file_list": None,
            "files_total": None,
            "files_transferred": None,
            "bytes_total": None,
            "bytes_transferred": None,
            "creation_time": None,
            "modification_time": None,
            "transfer_completion_time": None,
            "expiration_time": None,
            "error_code": None,
            "error_description": None,
            "notify_cmd_line": None,
            "notify_flags": None,
            "retry_delay": None,
            "no_progress_timeout": None,
            "minimum_retry_delay": None,
            "source_file": None,
            "raw_qmgr_path": None,
            "parser_status": None,
            "timestamp_interpretation": None,
        },
        "cloud": {
            "artifact_type": None,
            "provider": None,
            "account": None,
            "account_email": None,
            "user": None,
            "sync_root": None,
            "local_path": None,
            "remote_path": None,
            "cloud_path": None,
            "item_id": None,
            "drive_id": None,
            "resource_id": None,
            "status": None,
            "sync_status": None,
            "hydration_status": None,
            "pinned": None,
            "shared": None,
            "created_time": None,
            "modified_time": None,
            "accessed_time": None,
            "deleted_time": None,
            "last_sync_time": None,
            "last_upload_time": None,
            "last_download_time": None,
            "direction": None,
            "confidence": None,
            "source_file": None,
            "parser_status": None,
            "detection_method": None,
            "timestamp_interpretation": None,
        },
        "wlan": {
            "ssid": None,
            "ssid_hex": None,
            "profile_name": None,
            "profile_type": None,
            "connection_mode": None,
            "authentication": None,
            "encryption": None,
            "key_type": None,
            "key_protected": None,
            "key_material_present": None,
            "auto_switch": None,
            "mac_randomization": None,
            "interface_guid": None,
            "interface_description": None,
            "bssid": None,
            "signal_quality": None,
            "connection_start": None,
            "connection_end": None,
            "reason": None,
            "source_file": None,
        },
        "dns": {
            "name": None,
            "domain": None,
            "record_type": None,
            "data": None,
            "ip": None,
            "ttl": None,
            "status": None,
            "source": None,
            "server": None,
            "interface": None,
            "timestamp": None,
            "source_file": None,
        },
        "wmi": {
            "artifact_type": None,
            "namespace": None,
            "class_name": None,
            "instance_name": None,
            "name": None,
            "path": None,
            "relpath": None,
            "creator_sid": None,
            "creator_user": None,
            "filter_name": None,
            "consumer_name": None,
            "query": None,
            "query_language": None,
            "event_namespace": None,
            "consumer_type": None,
            "command_line_template": None,
            "executable_path": None,
            "working_directory": None,
            "script_text": None,
            "script_preview": None,
            "scripting_engine": None,
            "binding_filter": None,
            "binding_consumer": None,
            "delivery_qos": None,
            "maintain_security_context": None,
            "kill_timeout": None,
            "machine_name": None,
            "max_queue_size": None,
            "last_write_time": None,
            "created_time": None,
            "modified_time": None,
            "source_file": None,
            "repository_path": None,
            "parser_status": None,
            "timestamp_interpretation": None,
        },
        "shellbag": {"path": None, "mru": None, "slot": None, "last_write": None},
        "velociraptor": {
            "collection_id": None,
            "original_path": None,
            "normalized_windows_path": None,
            "artifact_category": None,
            "parser_status": None,
        },
        "browser": {
            "browser": None,
            "name": None,
            "profile": None,
            "profile_path": None,
            "artifact_type": None,
            "url": None,
            "final_url": None,
            "referrer": None,
            "tab_url": None,
            "domain": None,
            "title": None,
            "visit_count": None,
            "typed_count": None,
            "transition": None,
            "search_terms": None,
            "search_engine": None,
            "download_path": None,
            "download_start_time": None,
            "download_end_time": None,
            "download_state": None,
            "danger_type": None,
            "interrupt_reason": None,
            "source_file": None,
        },
        "email": {
            "message_id": None,
            "subject": None,
            "from": {"address": None, "display_name": None},
            "to": [],
            "cc": [],
            "bcc": [],
            "date": None,
            "client_submit_time": None,
            "conversation_index": None,
            "headers": {
                "return_path": None,
                "reply_to": None,
                "x_mailer": None,
                "user_agent": None,
                "authentication_results": None,
                "received_spf": None,
                "x_originating_ip": None,
                "dkim_present": None,
                "spf_result": None,
                "dmarc_result": None,
                "dkim_result": None,
            },
            "attachments": [],
            "body_preview": None,
            "mailbox_name": None,
            "mailbox_type": None,
            "message_index": None,
            "source_kind": None,
            "unsupported_reason": None,
            "parser_status": None,
            "auth_failure": None,
            "suspicious_attachment_count": 0,
        },
        "ntfs": {
            "source": None,
            "usn": None,
            "reason": None,
            "in_use": None,
            "old_name": None,
            "new_name": None,
            "zone_id": None,
            "zone_name": None,
            "host_url": None,
            "referrer_url": None,
            "last_writer_package_family_name": None,
            "shadow_id": None,
            "snapshot_time": None,
            "timestamp_source": None,
        },
        "powershell": {
            "artifact_type": None,
            "command": None,
            "command_preview": None,
            "line_number": None,
            "source_file": None,
            "transcript_start_time": None,
            "transcript_end_time": None,
            "username": None,
            "run_as": None,
            "machine": None,
            "host_application": None,
            "process_id": None,
            "ps_version": None,
            "has_encoded_command": None,
            "encoded_command": None,
            "decoded_command_preview": None,
            "has_download": None,
            "has_iex": None,
            "has_execution_policy_bypass": None,
            "has_defender_tampering": None,
            "has_persistence": None,
            "urls": [],
            "domains": [],
            "paths": [],
            "indicators": [],
            "parser_status": None,
            "timestamp_interpretation": None,
        },
        "url": {"full": None, "domain": None, "scheme": None, "path": None, "query": None},
        "download": {"url": None, "final_url": None, "referrer": None, "target_path": None, "file_name": None, "mime_type": None, "total_bytes": None, "received_bytes": None, "state": None},
        "task": {
            "name": None,
            "path": None,
            "uri": None,
            "author": None,
            "description": None,
            "enabled": None,
            "hidden": None,
            "source_file": None,
            "date": None,
            "version": None,
            "user_id": None,
            "group_id": None,
            "run_as": None,
            "logon_type": None,
            "run_level": None,
            "actions": [],
            "triggers": [],
            "command": None,
            "arguments": None,
            "working_directory": None,
            "com_handler_class_id": None,
            "com_handler_data": None,
            "settings": {},
            "trigger_summary": None,
            "action_summary": None,
            "artifact_type": None,
        },
        "service": {
            "artifact_type": None,
            "name": None,
            "display_name": None,
            "description": None,
            "image_path": None,
            "image_path_expanded": None,
            "service_dll": None,
            "service_dll_expanded": None,
            "start_type": None,
            "start_type_raw": None,
            "service_type": None,
            "service_type_raw": None,
            "error_control": None,
            "object_name": None,
            "account": None,
            "group": None,
            "depend_on_service": [],
            "depend_on_group": [],
            "failure_actions": None,
            "required_privileges": [],
            "launch_protected": None,
            "service_sid_type": None,
            "delayed_auto_start": None,
            "trigger_info": None,
            "key_path": None,
            "control_set": None,
            "source_file": None,
            "last_write": None,
            "parser_status": None,
            "timestamp_interpretation": None,
        },
        "registry": {"hive": None, "key_path": None, "value_name": None, "value_data": None, "last_write": None},
        "amcache": {
            "program_id": None,
            "program_name": None,
            "program_version": None,
            "publisher": None,
            "product_name": None,
            "product_version": None,
            "file_id": None,
            "file_name": None,
            "file_path": None,
            "path_hash": None,
            "link_date": None,
            "compile_time": None,
            "install_date": None,
            "uninstall_date": None,
            "language": None,
            "binary_type": None,
            "is_os_component": None,
            "key_path": None,
            "key_last_write_time": None,
            "source_file": None,
        },
        "shimcache": {
            "entry_number": None,
            "position": None,
            "path": None,
            "last_modified_time": None,
            "last_update": None,
            "insert_flags": None,
            "shim_flags": None,
            "executed": None,
            "control_set": None,
            "source_file": None,
        },
        "appcompat": {
            "artifact_type": None,
            "path": None,
            "name": None,
            "last_modified": None,
            "last_write_time": None,
            "entry_number": None,
            "source_file": None,
            "interpretation": None,
        },
        "lnk": {
            "source_file": None,
            "target_path": None,
            "target_id_absolute_path": None,
            "local_path": None,
            "common_path": None,
            "relative_path": None,
            "effective_path": None,
            "effective_path_source": None,
            "display_name": None,
            "is_partial_target": None,
            "is_shell_target": None,
            "arguments": None,
            "working_directory": None,
            "icon_location": None,
            "description": None,
            "machine_id": None,
            "drive_serial": None,
            "drive_type": None,
            "drive_serial_number": None,
            "volume_label": None,
            "network_path": None,
            "net_name": None,
            "device_name": None,
            "share_name": None,
            "target_created": None,
            "target_modified": None,
            "target_accessed": None,
            "source_created": None,
            "source_modified": None,
            "source_accessed": None,
            "file_size": None,
            "file_attributes": None,
            "mft_entry": None,
            "mft_sequence": None,
            "parse_warnings": [],
            "timestamp_interpretation": None,
        },
        "jumplist": {"app_id": None, "app_name": None, "target_path": None, "effective_path": None, "source_file": None, "timestamp_interpretation": None},
        "recycle_bin": {"original_path": None, "deleted_time": None, "recovery_name": None},
        "recycle": {
            "artifact_type": None,
            "sid": None,
            "user": None,
            "original_path": None,
            "original_file_name": None,
            "original_size": None,
            "deleted_time": None,
            "i_file_path": None,
            "r_file_path": None,
            "has_i_file": None,
            "has_r_file": None,
            "pair_id": None,
            "version": None,
            "drive_letter": None,
            "source_file": None,
        },
        "srum": {
            "artifact_type": None,
            "table": None,
            "application": None,
            "app_id": None,
            "app_name": None,
            "package_name": None,
            "user_sid": None,
            "interface_luid": None,
            "interface_guid": None,
            "interface_profile": None,
            "network_profile": None,
            "bytes_sent": None,
            "bytes_received": None,
            "bytes_total": None,
            "foreground_bytes_sent": None,
            "foreground_bytes_received": None,
            "background_bytes_sent": None,
            "background_bytes_received": None,
            "connected_time": None,
            "duration": None,
            "energy_usage": None,
            "cycle_time": None,
            "start_time": None,
            "end_time": None,
            "source_file": None,
        },
        "network": {
            "artifact_type": None,
            "interface_name": None,
            "interface_guid": None,
            "interface_alias": None,
            "interface_description": None,
            "mac_address": None,
            "ip_address": None,
            "ipv4": None,
            "ipv6": None,
            "subnet": None,
            "gateway": None,
            "dns_servers": [],
            "dhcp_enabled": None,
            "dhcp_server": None,
            "profile_name": None,
            "profile_guid": None,
            "network_category": None,
            "source_ip": None,
            "source_port": None,
            "destination_ip": None,
            "destination_port": None,
            "protocol": None,
            "domain": None,
            "url": None,
            "state": None,
            "process_id": None,
            "process_name": None,
            "bytes_sent": None,
            "bytes_received": None,
            "bytes_total": None,
            "application": None,
            "interface": None,
            "profile": None,
            "direction": None,
            "first_seen": None,
            "last_seen": None,
            "source_file": None,
            "parser_status": None,
            "timestamp_interpretation": None,
        },
        "detection": {
            "artifact_type": None,
            "threat_name": None,
            "threat_id": None,
            "severity": None,
            "category": None,
            "action": None,
            "status": None,
            "remediation_action": None,
            "detection_source": None,
            "product_name": None,
            "engine_version": None,
            "signature_version": None,
            "path": None,
            "resource": None,
            "container_file": None,
            "user": None,
            "user_sid": None,
            "timestamp": None,
            "source_file": None,
            "line_number": None,
            "error_code": None,
        },
        "windows": {
            "event_id": None,
            "channel": None,
            "provider": None,
            "computer": None,
            "record_id": None,
            "record_number": None,
            "process_id": None,
            "thread_id": None,
            "opcode": None,
            "level": None,
            "keywords": None,
            "event_data_summary": None,
            "event_data": None,
            "raw_xml": None,
            "logon_type": None,
            "service_name": None,
            "task_name": None,
        },
        "ingest": {
            "processed_at": None,
        },
        "rule": {"engine": None, "name": None, "namespace": None, "severity": None, "tags": []},
        "memory": {"plugin": None, "process_offset": None, "virtual_address": None},
        "linux": {},
        "macos": {},
        "tags": [],
        "data_quality": [],
        "risk_score": 0,
        "raw_summary": build_raw_summary(row),
        "search_text": "",
        "raw": row,
    }


def _apply_data_quality(document: dict) -> dict:
    warnings: set[str] = set(document.get("data_quality", []))
    file_data = document.get("file", {}) or {}
    artifact_type = str((document.get("artifact", {}) or {}).get("type") or "").lower()
    event_category = str((document.get("event", {}) or {}).get("category") or "").lower()
    browser_type = str((document.get("browser", {}) or {}).get("artifact_type") or "").lower()
    if not document.get("@timestamp"):
        warnings.add("missing_timestamp")
    if document.get("@timestamp") and document.get("timestamp_precision") in {"unknown", "source_file_mtime_low_confidence"}:
        warnings.add("low_confidence_timestamp")
    if not file_data.get("path") and not (
        event_category == "device"
        or (artifact_type == "browser" and browser_type in {"history", "search_term", "browser_generic"})
        or artifact_type == "scheduled_task"
        or artifact_type in {"defender", "detection"}
        or artifact_type == "powershell"
        or artifact_type == "detection"
        or artifact_type == "wmi"
        or artifact_type in {"autoruns", "autorun"}
        or artifact_type == "cloud_sync"
        or artifact_type == "network"
        or artifact_type == "windows_event"
    ):
        warnings.add("missing_file_path")
    if not file_data.get("name") and not (
        event_category == "device"
        or (artifact_type == "browser" and browser_type in {"history", "search_term", "browser_generic"})
        or artifact_type == "scheduled_task"
        or artifact_type in {"defender", "detection"}
        or artifact_type == "powershell"
        or artifact_type == "detection"
        or artifact_type == "wmi"
        or artifact_type in {"autoruns", "autorun"}
        or artifact_type == "cloud_sync"
        or artifact_type == "network"
        or artifact_type == "windows_event"
    ):
        warnings.add("missing_file_name")
    if not (document.get("host", {}) or {}).get("name"):
        warnings.add("missing_host")
    if not (document.get("user", {}) or {}).get("name"):
        warnings.add("missing_user")
    if (document.get("windows", {}) or {}).get("event_id") is None and document.get("artifact", {}).get("type") in {"evtx", "windows_event"}:
        warnings.add("unmapped_event_id")
    document["data_quality"] = sorted(warnings)
    return document


def _apply_suspicious_tags(document: dict) -> dict:
    tags = set(document.get("tags", []))
    suspicious_reasons = set(str(item) for item in (document.get("suspicious_reasons") or []) if item)
    process_name = (document.get("process", {}) or {}).get("name") or ""
    command_line = (document.get("process", {}) or {}).get("command_line") or ""
    file_path = (document.get("file", {}) or {}).get("path") or ""
    windows = document.get("windows", {}) or {}
    event_id = windows.get("event_id")

    for item in SUSPICIOUS_RULES.get("process_names", []):
        if process_name and process_name.lower().endswith(item.lower()) and (
            suspicious_reasons or {"suspicious", "suspicious_command", "encoded_command", "defender_tampering", "download_cradle", "invoke_expression"} & tags
        ):
            tags.add("suspicious_process")
            break
    for pattern in SUSPICIOUS_RULES.get("command_line_patterns", []):
        if re.search(pattern, command_line, flags=re.IGNORECASE):
            tags.add("suspicious_command")
            if "powershell" in command_line.lower():
                tags.add("powershell")
            if "rclone" in command_line.lower():
                tags.add("possible_exfiltration")
    for pattern in SUSPICIOUS_RULES.get("paths", []):
        if file_path and pattern.lower() in file_path.lower():
            tags.add("suspicious_path")

    if event_id in (4697, 7045):
        tags.update({"service_install", "persistence"})
    if event_id in (4698, 4702, 106, 140):
        tags.update({"scheduled_task", "persistence"})
    if event_id in SUSPICIOUS_RULES.get("event_ids", {}).get("rdp", []):
        tags.add("rdp")
    if event_id in SUSPICIOUS_RULES.get("event_ids", {}).get("powershell", []):
        tags.add("powershell")

    document["tags"] = sorted(tags)
    if document.get("_preserve_risk_score"):
        adjusted_score = int(document.get("risk_score") or 0)
        document["risk_score"] = adjusted_score
        document["event"]["severity"] = risk_score_to_severity(adjusted_score)
        return document
    base_score = severity_to_risk_score(document["event"]["severity"])
    adjusted_score = apply_tag_risk_adjustments(base_score, document["tags"])
    document["risk_score"] = adjusted_score
    document["event"]["severity"] = risk_score_to_severity(adjusted_score)
    return document


def _noise_adjustment_state(document: dict) -> dict:
    current = document.get("event", {}) or {}
    existing = current.get("risk_adjustment")
    if isinstance(existing, dict):
        return existing
    state = {
        "base_score": int(document.get("risk_score") or 0),
        "final_score": int(document.get("risk_score") or 0),
        "positive_reasons": list(dict.fromkeys(document.get("suspicious_reasons") or [])),
        "negative_reasons": [],
        "suppressed": False,
        "suppression_reason": None,
    }
    document.setdefault("event", {})["risk_adjustment"] = state
    return state


def _apply_noise_score(document: dict, candidate_score: int, negative_reason: str, *, suppress: bool = False, suppression_reason: str | None = None) -> None:
    adjustment = _noise_adjustment_state(document)
    current_score = int(document.get("risk_score") or 0)
    new_score = min(current_score, max(0, int(candidate_score)))
    if new_score != current_score or negative_reason:
        if negative_reason and negative_reason not in adjustment["negative_reasons"]:
            adjustment["negative_reasons"].append(negative_reason)
        document["risk_score"] = new_score
        document["event"]["severity"] = risk_score_to_severity(new_score)
        adjustment["final_score"] = new_score
        if suppress:
            adjustment["suppressed"] = True
            adjustment["suppression_reason"] = suppression_reason or negative_reason


def _path_lower(value: object | None) -> str:
    return str(value or "").replace("/", "\\").lower()


def _text_lower(value: object | None) -> str:
    return str(value or "").strip().lower()


def _boolish_value(value: object | None) -> bool:
    if isinstance(value, bool):
        return value
    text = str(value or "").strip().lower()
    return text in {"1", "true", "yes", "y"}


def _is_microsoft_signed_verified(document: dict) -> bool:
    autoruns = document.get("autoruns", {}) or {}
    candidates = [
        autoruns.get("publisher"),
        autoruns.get("company"),
        autoruns.get("signer"),
        document.get("service", {}).get("company") if isinstance(document.get("service"), dict) else None,
    ]
    signed = _boolish_value(autoruns.get("signed"))
    verified = _boolish_value(autoruns.get("verified"))
    return signed and verified and any("microsoft" in _text_lower(item) for item in candidates if item)


def _known_good_windows_path(path: str | None) -> bool:
    lowered = _path_lower(path)
    return any(marker in lowered for marker in KNOWN_GOOD_WINDOWS_PATH_MARKERS)


def _is_user_startup_path(path: str | None) -> bool:
    lowered = _path_lower(path)
    return "\\users\\" in lowered and "\\start menu\\programs\\startup\\" in lowered


def _known_good_update_context(document: dict) -> bool:
    remote = _text_lower((document.get("bits", {}) or {}).get("remote_url"))
    local_path = _path_lower((document.get("bits", {}) or {}).get("local_path"))
    domain = _text_lower((document.get("dns", {}) or {}).get("domain") or (document.get("dns", {}) or {}).get("name"))
    srum_app = _text_lower((document.get("srum", {}) or {}).get("application"))
    path = _path_lower((document.get("file", {}) or {}).get("path"))
    return (
        any(host in remote for host in MICROSOFT_DOMAINS)
        or any(host in domain for host in MICROSOFT_DOMAINS)
        or any(marker in local_path for marker in KNOWN_GOOD_UPDATE_PATH_MARKERS)
        or any(marker in path for marker in KNOWN_GOOD_UPDATE_PATH_MARKERS)
        or srum_app in {"svchost.exe", "wuauclt.exe", "usoclient.exe"}
    )


def _command_is_strongly_suspicious(command: str | None) -> bool:
    lowered = _text_lower(command)
    return any(
        token in lowered
        for token in (
            "encodedcommand",
            "-enc ",
            "executionpolicy bypass",
            "-windowstyle hidden",
            " -w hidden",
            "iex(",
            "invoke-expression",
        )
    )


def _apply_false_positive_reduction(document: dict) -> dict:
    tags = set(document.get("tags", []))
    reasons = set(str(item) for item in (document.get("suspicious_reasons") or []) if item)
    data_quality = set(document.get("data_quality", []))
    artifact_type = _text_lower((document.get("artifact", {}) or {}).get("type"))
    event_type = _text_lower((document.get("event", {}) or {}).get("type"))
    path = (
        (document.get("file", {}) or {}).get("path")
        or (document.get("process", {}) or {}).get("path")
        or (document.get("autoruns", {}) or {}).get("image_path")
        or (document.get("persistence", {}) or {}).get("path")
        or (document.get("cloud", {}) or {}).get("local_path")
    )
    lower_path = _path_lower(path)
    command_line = (
        (document.get("process", {}) or {}).get("command_line")
        or (document.get("autoruns", {}) or {}).get("command_line")
        or (document.get("persistence", {}) or {}).get("command")
        or (document.get("service", {}) or {}).get("image_path")
    )
    strong_suspicion = _command_is_strongly_suspicious(command_line) or any(
        reason
        for reason in reasons
        if any(token in reason.lower() for token in ("encoded", "bypass", "hidden", "lolbin", "defender", "tamper", "suspicious domain", "high outbound"))
    )

    if _is_microsoft_signed_verified(document) and _known_good_windows_path(path) and not strong_suspicion:
        tags.update({"benign_microsoft_signed", "known_good_windows_path"})
        reasons = {reason for reason in reasons if "persistence" not in reason.lower()}
        _apply_noise_score(document, 20, "Microsoft signed/verified binary in known-good Windows path")

    if artifact_type in {"bits", "dns", "srum"} and _known_good_update_context(document) and not strong_suspicion:
        tags.add("known_good_windows_update")
        reasons = {
            reason for reason in reasons
            if not any(token in reason.lower() for token in ("downloaded executable", "download over http", "direct ip", "suspicious domain", "dynamic dns"))
        }
        _apply_noise_score(document, 10, "Known-good Windows Update / Microsoft network activity")

    if artifact_type in {"defender", "detection"}:
        status = _text_lower((document.get("detection", {}) or {}).get("status"))
        severity = _text_lower((document.get("detection", {}) or {}).get("severity"))
        threat = _text_lower((document.get("detection", {}) or {}).get("threat_name"))
        action = _text_lower((document.get("detection", {}) or {}).get("action"))
        if (
            not strong_suspicion
            and severity not in {"high", "critical"}
            and not threat
            and any(token in status or token in action for token in ("inform", "success", "update", "healthy", "clean"))
        ):
            _apply_noise_score(document, 5, "Defender maintenance/informational event")
            reasons.clear()

    if artifact_type == "cloud":
        shared = _boolish_value((document.get("cloud", {}) or {}).get("shared"))
        direction = _text_lower((document.get("cloud", {}) or {}).get("direction"))
        filename = _text_lower((document.get("file", {}) or {}).get("name") or path)
        if not shared and not strong_suspicion and not any(keyword in filename for keyword in ("password", "secret", "credential", "token", "wallet", "backup", "dump", "database", "payroll")):
            if direction in {"sync", "download", "unknown"} or event_type == "cloud_item_observed":
                tags.add("normal_onedrive_sync")
                reasons = {reason for reason in reasons if "cloud sync root observed" not in reason.lower()}
                _apply_noise_score(document, 10, "Normal OneDrive/Cloud sync activity")

    if artifact_type == "dns":
        domain = _text_lower((document.get("dns", {}) or {}).get("domain") or (document.get("dns", {}) or {}).get("name"))
        if domain and any(host in domain for host in ("microsoft.com", "windowsupdate.com", "office.com", "office365.com", "githubusercontent.com")) and not strong_suspicion:
            _apply_noise_score(document, 10, "Known-good common DNS resolution")

    if artifact_type == "wlan":
        authentication = _text_lower((document.get("wlan", {}) or {}).get("authentication"))
        encryption = _text_lower((document.get("wlan", {}) or {}).get("encryption"))
        if authentication in {"wpa2psk", "wpa3psk", "wpa2", "wpa3", "wpa2-enterprise", "wpa3-enterprise"} and encryption in {"aes", "ccmp"} and not strong_suspicion:
            _apply_noise_score(document, 5, "Protected WLAN profile or connection")

    if artifact_type == "srum":
        app = _text_lower((document.get("srum", {}) or {}).get("application") or (document.get("process", {}) or {}).get("name"))
        if app in {"chrome.exe", "msedge.exe", "svchost.exe", "system"} and not strong_suspicion:
            _apply_noise_score(document, 10, "Common benign SRUM application activity")

    if artifact_type == "usb":
        device_type = _text_lower((document.get("usb", {}) or {}).get("device_type"))
        allowed_usb_reasons = {
            "USB mass storage device observed",
            "USB drive letter assigned",
            "USB device connected recently",
            "USB device removed recently",
            "USB portable device observed",
            "USB device connected under user context",
        }
        if device_type == "hid":
            _apply_noise_score(document, 0, "USB HID activity is informational", suppress=True, suppression_reason="informational_usb_only")
            tags.add("informational_usb_only")
        elif not strong_suspicion and reasons and all(reason in allowed_usb_reasons for reason in reasons):
            tags.add("informational_usb_only")
            if device_type == "mass_storage":
                reasons = {reason for reason in reasons if reason in {"USB drive letter assigned", "USB device connected recently", "USB device removed recently"}}
            else:
                reasons = {reason for reason in reasons if reason in allowed_usb_reasons}
            _apply_noise_score(document, 10, "USB connection alone is informational")

    if artifact_type in {"autorun", "scheduled_task", "service"} and not strong_suspicion:
        microsoft_path = _known_good_windows_path(path) or "\\microsoft\\windows\\" in lower_path
        if microsoft_path and (
            _is_microsoft_signed_verified(document)
            or "\\microsoft\\windows\\" in lower_path
            or (document.get("task", {}) or {}).get("uri", "").startswith("\\Microsoft\\Windows\\")
        ) and not _is_user_startup_path(path):
            tags.update({"known_good_windows_path", "known_good_microsoft_task"})
            reasons = {
                reason for reason in reasons
                if reason not in {"Run key persistence", "RunOnce persistence", "Startup folder persistence"}
            }
            _apply_noise_score(document, 20, "Known-good Microsoft persistence location")

    if artifact_type in {"amcache", "shimcache", "mft", "recycle_bin", "cloud", "dns", "srum", "wlan"} and not strong_suspicion and int(document.get("risk_score") or 0) <= 20:
        tags.add("weak_single_signal")

    document["tags"] = sorted(tags)
    document["suspicious_reasons"] = sorted(reasons)
    document["data_quality"] = sorted(data_quality)
    return document


def normalize_row(case_id: str, evidence_id: str, artifact_id: str, row: dict, artifact_meta: dict) -> dict:
    document = base_document(case_id, evidence_id, artifact_id, row, artifact_meta)
    artifact_name = str(
        artifact_meta.get("name")
        or artifact_meta.get("display_name")
        or artifact_meta.get("source_path")
        or artifact_meta.get("parser")
        or artifact_meta.get("artifact_type")
        or ""
    )
    artifact_path = Path(artifact_name)
    name = artifact_name.lower()
    artifact_type = str(artifact_meta["artifact_type"]).lower()
    parser = str(artifact_meta.get("parser") or "").lower()
    source_tool = str(artifact_meta.get("source_tool") or "").lower()
    source_format = str(artifact_meta.get("source_format") or "").lower()
    source_path = str(artifact_meta.get("source_path") or "")
    headers = {str(key or "").lower() for key in row.keys() if str(key or "").strip()}
    is_native_lnk_context = artifact_type == "lnk" or parser == "lnk_raw" or source_tool == "native_lnk" or source_format == "lnk"
    is_native_prefetch_context = artifact_type == "prefetch" or parser == "prefetch_raw" or source_tool == "native_prefetch" or source_format == "pf"
    normalized_source_path = source_path.replace("/", "\\").lower()
    is_native_service_context = (
        artifact_type == "service"
        or parser == "windows_service_registry"
        or source_tool == "native_windows_service"
        or "\\currentcontrolset\\services\\" in normalized_source_path
        or ("\\controlset00" in normalized_source_path and "\\services\\" in normalized_source_path)
    )
    is_native_scheduled_task_context = (
        artifact_type == "scheduled_task"
        or parser in {"xml", "scheduled_task_xml", "scheduled_task_csv"}
        or source_tool == "native_scheduled_task"
        or "\\windows\\system32\\tasks\\" in normalized_source_path
        or "\\windows\\tasks\\" in normalized_source_path
    )

    if artifact_type == "mft" or "mftecmd" in name or {"entrynumber", "sequencenumber", "parententrynumber"} <= headers:
        document = normalize_mft_row(document, row, artifact_meta)
    elif is_native_prefetch_context or "pecmd" in name or "prefetch" in name:
        document = normalize_prefetch_row(document, row, artifact_meta)
    elif is_native_service_context:
        artifact_meta = {
            **artifact_meta,
            "artifact_type": "service",
            "parser": "windows_service_registry",
            "source_tool": "native_windows_service",
            "source_format": "registry_hive" if source_format == "registry_hive" or "\\windows\\system32\\config\\system" in normalized_source_path else (artifact_meta.get("source_format") or "registry"),
        }
        document["artifact"]["type"] = "service"
        document["artifact"]["parser"] = "windows_service_registry"
        document["source_tool"] = "native_windows_service"
        document["source_format"] = artifact_meta["source_format"]
        document = normalize_service_row(document, row, artifact_meta)
    elif is_native_scheduled_task_context:
        artifact_meta = {
            **artifact_meta,
            "artifact_type": "scheduled_task",
            "parser": "scheduled_task_xml" if parser in {"xml", "scheduled_task_xml"} or source_tool == "native_scheduled_task" or source_format == "xml" else artifact_meta.get("parser"),
            "source_tool": "native_scheduled_task" if source_tool == "native_scheduled_task" or parser in {"xml", "scheduled_task_xml"} else artifact_meta.get("source_tool"),
            "source_format": "xml" if source_format == "xml" or parser in {"xml", "scheduled_task_xml"} or "\\windows\\system32\\tasks\\" in normalized_source_path else artifact_meta.get("source_format"),
        }
        document["artifact"]["type"] = "scheduled_task"
        if artifact_meta.get("parser"):
            document["artifact"]["parser"] = artifact_meta["parser"]
        if artifact_meta.get("source_tool"):
            document["source_tool"] = artifact_meta["source_tool"]
        if artifact_meta.get("source_format"):
            document["source_format"] = artifact_meta["source_format"]
        document = normalize_scheduled_task_row(document, row, artifact_meta)
    elif artifact_type == "dns" and (parser == "dns_evtx" or str(first_value(row, ["ArtifactType"]) or "").lower() == "dns_evtx"):
        document = normalize_network_artifact_row(document, row, artifact_meta)
    elif artifact_type == "evtx" and looks_like_defender_event_row(row, artifact_meta):
        document = normalize_evtx_row(document, row, artifact_meta)
        document = normalize_defender_row(
            document,
            row,
            {
                **artifact_meta,
                "artifact_type": "defender",
                "parser": "defender_evtx",
                "defender_artifact_type": "defender_evtx",
                "source_tool": artifact_meta.get("source_tool") or "native_evtx",
                "source_format": "evtx",
            },
        )
    elif (
        artifact_type in {"evtx", "windows_event"}
        or "evtxecmd" in name
        or "hayabusa" in name
        or ("eventid" in headers and artifact_type != "powershell" and not _looks_like_powershell(artifact_path, artifact_meta))
    ) and not (artifact_type == "usb" or parser == "usb_evtx"):
        channel = str(first_value(row, ["Channel"]) or "").lower()
        provider = str(first_value(row, ["Provider", "ProviderName", "SourceName"]) or "").lower()
        if (
            "wlan-autoconfig/operational" in channel
            or "microsoft-windows-wlan-autoconfig" in channel
            or "wlan-autoconfig" in provider
        ):
            document = normalize_network_artifact_row(document, classify_wlan_autoconfig_event(row), {**artifact_meta, "artifact_type": "network", "parser": "evtx", "network_artifact_type": "wlan_autoconfig_evtx"})
        else:
            document = normalize_evtx_row(document, row, artifact_meta)
    elif artifact_type == "jumplist" or "jlecmd" in name:
        document = normalize_jumplist_row(document, row, artifact_meta)
    elif is_native_lnk_context or ("lecmd" in name and "jlecmd" not in name):
        document = normalize_lnk_row(document, row, artifact_meta)
    elif artifact_type == "amcache" or _looks_like_amcache(artifact_path, artifact_meta) or "amcache" in name:
        document = normalize_amcache_row(document, row, artifact_meta)
    elif artifact_type in {"shimcache", "appcompat"} or _looks_like_shimcache(artifact_path, artifact_meta) or "shimcache" in name or "appcompatcacheparser" in name or "recentfilecache" in name:
        document = normalize_shimcache_row(document, row, artifact_meta)
    elif artifact_type == "shellbags" or _looks_like_shellbags(artifact_path, artifact_meta):
        document = normalize_shellbags_row(document, row, artifact_meta)
    elif artifact_type == "usb" or _looks_like_usb(artifact_path, artifact_meta):
        document = normalize_usb_row(document, row, artifact_meta)
    elif artifact_type == "bits" or _looks_like_bits(artifact_path, artifact_meta):
        document = normalize_bits_row(document, row, artifact_meta)
    elif artifact_type == "recycle_bin" or _looks_like_recycle_bin(artifact_path, artifact_meta) or "recycle" in name or "rbcmd" in name:
        document = normalize_recycle_bin_row(document, row, artifact_meta)
    elif artifact_type in {"autoruns", "autorun"}:
        document = normalize_autoruns_row(document, row, artifact_meta)
    elif artifact_type in {"cloud_sync", "cloud"} or looks_like_cloud_sync_artifact(artifact_path, list(row.keys())):
        document = normalize_cloud_row(document, row, artifact_meta)
    elif artifact_type == "windows_ui" or looks_like_windows_ui_artifact(artifact_path, list(row.keys())):
        document = normalize_windows_ui_row(document, row, artifact_meta)
    elif artifact_type == "browser" or looks_like_browser_artifact(artifact_path, list(row.keys())) or "browserhistory" in name or {"url", "title"} & headers:
        document = normalize_browser_event(document, row, artifact_meta)
    elif artifact_type == "email" or looks_like_email_artifact(artifact_path, list(row.keys())):
        document = normalize_email_row(document, row, artifact_meta)
    elif artifact_type in {"ntfs", "ntfs_raw"} or looks_like_ntfs_artifact(artifact_path, list(row.keys())):
        document = normalize_ntfs_row(document, row, artifact_meta)
    elif artifact_type == "wmi" or _looks_like_wmi(artifact_path, artifact_meta):
        document = normalize_wmi_row(document, row, artifact_meta)
    elif artifact_type not in {"network", "wlan", "dns"} and (artifact_type in {"defender", "detection"} or looks_like_defender_artifact(artifact_path, list(row.keys()))):
        document = normalize_defender_row(document, row, artifact_meta)
    elif looks_like_autoruns_artifact(artifact_path, list(row.keys())):
        document = normalize_autoruns_row(document, row, artifact_meta)
    elif artifact_type == "srum" or _looks_like_srum(artifact_path, artifact_meta) or "srum" in name or "networkusage" in name or "applicationresourceusage" in name:
        document = normalize_srum_row(document, row, artifact_meta)
    elif artifact_type == "powershell" or _looks_like_powershell(artifact_path, artifact_meta):
        document = normalize_powershell_row(document, row, artifact_meta)
    elif artifact_type == "registry" or "recmd" in name:
        classified_registry_row = classify_network_registry_row(row)
        if classified_registry_row.get("ArtifactType") in {"networklist_registry", "tcpip_interfaces_registry"}:
            document = normalize_network_artifact_row(document, classified_registry_row, {**artifact_meta, "artifact_type": "network", "parser": "registry"})
        else:
            document = normalize_registry_row(document, row, artifact_meta)
    elif artifact_type == "process" or "pslist" in name:
        document = normalize_process_row(document, row, artifact_meta)
    elif artifact_type in {"network", "wlan", "dns"} or "netstat" in name or {"destinationip", "remoteaddress", "queryname", "recordtype"} & headers:
        document = normalize_network_artifact_row(document, row, artifact_meta)
    else:
        document = normalize_generic_row(document, row, artifact_meta)

    file_path = document["file"].get("path")
    if file_path and not document["file"].get("name"):
        document["file"]["name"] = Path(file_path).name
        document["file"]["extension"] = Path(file_path).suffix
    document["host"]["name"] = document["host"]["name"] or extract_host(row, artifact_meta)
    document["host"]["hostname"] = document["host"]["name"]
    if document["host"].get("name"):
        document["observed_host"] = {
            "name": document["host"]["name"],
            "hostname": document["host"].get("hostname") or document["host"]["name"],
        }
    if not document["user"]["name"]:
        document["user"]["name"] = extract_user(row, artifact_meta, {"event_id": document["windows"].get("event_id")})
    document = _apply_suspicious_tags(document)
    if document.pop("_preserve_timeline_include", False):
        timeline_include = bool(document.get("@timestamp")) and bool(document["event"].get("timeline_include"))
    else:
        timeline_include = bool(document.get("@timestamp")) and (
            document["event"].get("severity") in {"medium", "high", "critical"}
            or document["event"].get("type") not in {"file_observed", "generic_record", "process_observed"}
            or any(tag in set(document.get("tags", [])) for tag in {"persistence", "rdp", "powershell", "deleted", "suspicious_process", "suspicious_command"})
        )
    document = _apply_false_positive_reduction(document)
    document["event"]["timeline_include"] = bool(timeline_include)
    document["search_text"] = build_search_text(document)
    document.pop("_preserve_risk_score", None)
    return _apply_data_quality(document)


def read_records(path: Path) -> list[dict]:
    suffix = path.suffix.lower()
    if suffix == ".csv":
        with path.open("r", encoding="utf-8-sig", errors="ignore") as handle:
            return list(csv.DictReader(handle))
    if suffix == ".json":
        data = json.loads(path.read_text(encoding="utf-8", errors="ignore"))
        if isinstance(data, list):
            return [item for item in data if isinstance(item, dict)]
        if isinstance(data, dict):
            if "rows" in data and isinstance(data["rows"], list):
                return [item for item in data["rows"] if isinstance(item, dict)]
            return [data]
    if suffix == ".jsonl":
        rows = []
        with path.open("r", encoding="utf-8", errors="ignore") as handle:
            for line in handle:
                line = line.strip()
                if not line:
                    continue
                item = json.loads(line)
                if isinstance(item, dict):
                    rows.append(item)
        return rows
    if suffix == ".txt":
        return [{"Message": line.rstrip()} for line in path.read_text(encoding="utf-8", errors="ignore").splitlines() if line.strip()]
    return []


def normalize_user_activity_raw_hive(case_id: str, evidence_id: str, artifact_id: str, path: Path, artifact_meta: dict) -> list[dict]:
    source_path = str(artifact_meta.get("source_path") or path)
    host_name = extract_host({}, artifact_meta)
    user_name = extract_user({"SourceFile": source_path}, artifact_meta)
    hive_name = path.name
    timestamp = datetime.fromtimestamp(path.stat().st_mtime, tz=UTC).isoformat() if path.exists() else None
    document = {
        "event_id": str(uuid4()),
        "case_id": case_id,
        "evidence_id": evidence_id,
        "artifact_id": artifact_id,
        "source_file": source_path,
        "source_tool": artifact_meta.get("source_tool") or "native_registry_inventory",
        "source_format": "registry_hive",
        "@timestamp": timestamp,
        "timestamp_precision": "source_file_fallback" if timestamp else "unknown",
        "timezone": "UTC" if timestamp else None,
        "os": {"type": "windows", "version": None},
        "host": {"name": host_name, "hostname": host_name, "ip": [], "os": "Windows"},
        "user": {"name": user_name if is_valid_username(user_name) else None, "sid": None},
        "artifact": {
            "type": "user_activity",
            "name": artifact_meta.get("name") or path.name,
            "source_path": source_path,
            "parser": "user_activity_registry_raw",
        },
        "event": {
            "category": "user_activity",
            "type": "user_activity_registry_hive_observed",
            "action": "registry_hive_inventory",
            "severity": "info",
            "message": f"User activity registry hive observed: {hive_name}",
            "timeline_include": False,
        },
        "registry": {
            "hive": hive_name,
            "hive_path": source_path,
            "key_path": None,
            "key_name": None,
            "value_name": None,
            "value_type": None,
            "value_data": None,
            "last_write_time": timestamp,
            "artifact_type": "user_activity_registry_hive",
            "plugin": None,
            "batch": None,
        },
        "process": {"entity_id": None, "pid": None, "ppid": None, "parent_pid": None, "name": None, "path": None, "command_line": None, "current_directory": None, "parent_entity_id": None, "parent_name": None, "parent_path": None, "parent_command_line": None, "integrity_level": None, "hashes": {"md5": None, "sha1": None, "sha256": None}, "application": None},
        "destination": {"hostname": None, "ip": None, "port": None},
        "file": {"path": source_path, "name": path.name, "extension": path.suffix.lower(), "size": path.stat().st_size if path.exists() else None, "sha1": None, "sha256": None, "md5": None, "created": None, "modified": timestamp, "accessed": None, "changed": None, "deleted": None, "parent_path": str(path.parent) if path.parent else None, "source_path": source_path},
        "folder": {"path": None},
        "mru": {"order": None, "list": None},
        "office": {"app": None, "version": None, "trusted_document": None, "macro_trust_possible": None},
        "user_activity": {"kind": "raw_registry_hive_inventory", "application": None, "activity_target": source_path},
        "execution": {"source": "registry_hive_raw", "run_count": None, "first_run": None, "last_run": None, "last_runs": [], "program_name": None, "confidence": "low", "is_execution_confirmed": False, "interpretation": "inventory_only", "first_seen": None, "last_seen": None, "last_modified": None, "install_date": None, "compile_time": None},
        "tags": ["user_activity", "registry_hive_raw", "inventory_only"],
        "data_quality": ["raw_hive_inventory_only"],
        "risk_score": 0,
        "raw_summary": f"Raw user activity hive observed: {hive_name}",
        "search_text": f"{hive_name} | {source_path} | raw_hive_inventory_only",
        "raw": {},
        "suspicious_reasons": [],
    }
    artifact_meta["ingest_audit"] = {
        "artifact": str(artifact_meta.get("name") or path.name),
        "parser": "user_activity_registry_raw",
        "records_read": 1,
        "records_parsed": 1,
        "records_indexed": 1,
        "unsupported_raw_hive_count": 1,
        "warnings": ["raw_user_activity_hive_inventory_only"],
        "parser_errors": [],
        "parser_status": "detected_not_implemented",
        "bulk_index_errors": 0,
        "sample_records": [{"hive": hive_name, "source_file": source_path, "user": document["user"]["name"]}],
    }
    return [document]


def normalize_file(case_id: str, evidence_id: str, artifact_id: str, path: Path, artifact_meta: dict, progress_cb=None) -> list[dict]:
    parser_name = str(artifact_meta.get("parser") or "").lower()
    artifact_type = str(artifact_meta.get("artifact_type") or "").lower()
    if parser_name in {"unsupported_text", "unsupported_sensitive_artifact"}:
        artifact_meta["ingest_audit"] = {
            "artifact": str(artifact_meta.get("name") or path.name),
            "parser": parser_name,
            "records_read": 0,
            "records_parsed": 0,
            "records_indexed": 0,
            "records_failed": 0,
            "parse_warnings": ["unsupported_text_skipped" if parser_name == "unsupported_text" else "sensitive_artifact_not_parsed"],
            "parser_errors": [],
            "parser_status": "skipped_sensitive" if parser_name == "unsupported_sensitive_artifact" else "skipped_unsupported",
            "bulk_index_errors": 0,
        }
        return []
    if parser_name in {"evtx_raw", "lnk_raw", "prefetch_raw", "amcache_raw", "shimcache_raw", "windows_service_registry"}:
        raw_parser = route_raw_parser(path, parser_name_hint=parser_name)
        if parser_name == "evtx_raw":
            result = raw_parser.parse(
                path,
                case_id=case_id,
                evidence_id=evidence_id,
                artifact_id=artifact_id,
                artifact_meta=artifact_meta,
                progress_cb=progress_cb,
            )
        else:
            result = raw_parser.parse(path, case_id=case_id, evidence_id=evidence_id, artifact_id=artifact_id, artifact_meta=artifact_meta)
        artifact_meta["raw_parser_status"] = result.parser_status
        artifact_meta["raw_parser_warnings"] = list(result.warnings)
        artifact_meta["raw_parser_errors"] = list(result.errors)
        artifact_meta["ingest_audit"] = result.metadata.get("audit") or {
            "parser_name": result.parser_name,
            "source_file": result.source_path,
            "records_read": result.records_read,
            "events_indexed": len(result.events),
            "warnings_count": len(result.warnings),
            "errors_count": len(result.errors),
            "parser_status": result.parser_status,
        }
        return result.events
    if parser_name == "user_activity_registry_raw" or (artifact_type == "user_activity" and path.name.lower() in {"ntuser.dat", "usrclass.dat"}):
        return normalize_user_activity_raw_hive(case_id, evidence_id, artifact_id, path, artifact_meta)
    if _looks_like_mftecmd(path, artifact_meta):
        return parse_mftecmd_file(case_id, evidence_id, artifact_id, path, artifact_meta)
    if parser_name.startswith("ntfs_") or artifact_type in {"ntfs", "ntfs_raw"} or looks_like_ntfs_artifact(path, list(_csv_headers(path)) if path.suffix.lower() == ".csv" else None):
        rows, ntfs_audit = parse_ntfs_artifact_file(path, artifact_meta)
        normalized_artifact_type = "mft" if artifact_type == "mft" else "ntfs"
        documents = [normalize_row(case_id, evidence_id, artifact_id, row, {**artifact_meta, "artifact_type": normalized_artifact_type}) for row in rows]
        by_parser: Counter[str] = Counter()
        by_event_type: Counter[str] = Counter()
        zone_counts: Counter[str] = Counter()
        extension_counts: Counter[str] = Counter()
        for document in documents:
            parser_label = str((document.get("artifact", {}) or {}).get("parser") or "ntfs_generic_raw")
            by_parser[parser_label] += 1
            by_event_type[str((document.get("event", {}) or {}).get("type") or "unknown")] += 1
            zone_value = str(((document.get("ntfs", {}) or {}).get("zone_name") or ((document.get("ntfs", {}) or {}).get("zone_id")) or "")).strip()
            if zone_value:
                zone_counts[zone_value] += 1
            extension = str((document.get("file", {}) or {}).get("extension") or "unknown")
            extension_counts[extension] += 1
        artifact_meta["ingest_audit"] = {
            "artifact": str(artifact_meta.get("name") or path.name),
            "artifact_type": "ntfs",
            "parser": str(artifact_meta.get("parser") or "ntfs_generic_raw"),
            "records_read": int(ntfs_audit.get("records_read") or len(rows)),
            "records_parsed": int(ntfs_audit.get("records_parsed") or len(rows)),
            "records_indexed": len(documents),
            "events_indexed": len(documents),
            "records_failed": int(ntfs_audit.get("records_failed") or 0),
            "by_parser": dict(sorted(by_parser.items())),
            "by_event_type": dict(sorted(by_event_type.items())),
            "zone_identifier_count": sum(1 for doc in documents if str((doc.get("event", {}) or {}).get("type") or "") == "file_zone_identifier_observed"),
            "internet_zone_count": sum(1 for doc in documents if ((doc.get("ntfs", {}) or {}).get("zone_id")) == 3),
            "untrusted_zone_count": sum(1 for doc in documents if ((doc.get("ntfs", {}) or {}).get("zone_id")) == 4),
            "usn_create_count": sum(1 for doc in documents if str((doc.get("event", {}) or {}).get("type") or "") == "file_created_observed"),
            "usn_delete_count": sum(1 for doc in documents if str((doc.get("event", {}) or {}).get("type") or "") == "file_deleted_observed"),
            "usn_rename_count": sum(1 for doc in documents if str((doc.get("event", {}) or {}).get("type") or "") == "file_renamed_observed"),
            "i30_deleted_entry_count": sum(1 for doc in documents if str((doc.get("artifact", {}) or {}).get("parser") or "") == "ntfs_i30" and ((((doc.get("file", {}) or {}).get("is_deleted")) is True) or (((doc.get("ntfs", {}) or {}).get("in_use")) is False))),
            "shadowcopy_count": sum(1 for doc in documents if str((doc.get("event", {}) or {}).get("type") or "") == "shadowcopy_observed"),
            "suspicious_origin_count": sum(1 for doc in documents if "Downloaded executable or script marked with web origin" in set(doc.get("suspicious_reasons") or []) or "Downloaded double-extension file" in set(doc.get("suspicious_reasons") or [])),
            "suspicious_delete_count": sum(1 for doc in documents if str((doc.get("event", {}) or {}).get("type") or "") in {"file_deleted_observed", "file_renamed_observed"} and int(doc.get("risk_score") or 0) >= 60),
            "unsupported_raw_count": sum(1 for doc in documents if str((doc.get("artifact", {}) or {}).get("parser") or "") == "ntfs_generic_raw"),
            "by_extension": dict(sorted(extension_counts.items())),
            "by_zone": dict(sorted(zone_counts.items())),
            "warnings": list(ntfs_audit.get("warnings") or []),
            "parser_errors": list(ntfs_audit.get("parser_errors") or []),
            "bulk_index_errors": 0,
            "sample_records": [
                {
                    "source_file": doc.get("source_file"),
                    "event_type": (doc.get("event", {}) or {}).get("type"),
                    "file_path": (doc.get("file", {}) or {}).get("path"),
                    "reason": (doc.get("ntfs", {}) or {}).get("reason"),
                    "host_url": (doc.get("ntfs", {}) or {}).get("host_url"),
                    "risk_score": doc.get("risk_score"),
                    "suspicious_reasons": list(doc.get("suspicious_reasons") or []),
                }
                for doc in documents[:10]
            ],
        }
        return documents
    if _looks_like_evtxecmd(path, artifact_meta):
        return parse_evtxecmd_file(case_id, evidence_id, artifact_id, path, artifact_meta)
    if _looks_like_pecmd(path, artifact_meta):
        return parse_pecmd_file(case_id, evidence_id, artifact_id, path, artifact_meta)
    if _looks_like_jlecmd(path, artifact_meta):
        return parse_jlecmd_file(case_id, evidence_id, artifact_id, path, artifact_meta)
    if _looks_like_lecmd(path, artifact_meta):
        return parse_lecmd_file(case_id, evidence_id, artifact_id, path, artifact_meta)
    if _looks_like_recmd(path, artifact_meta):
        return parse_recmd_file(case_id, evidence_id, artifact_id, path, artifact_meta)
    if _looks_like_scheduled_task(path, artifact_meta):
        if looks_like_scheduled_task_xml_path(path) or str(artifact_meta.get("parser") or "").lower() in {"xml", "scheduled_task_xml"}:
            row, warnings = parse_scheduled_task_xml(path, source_path=str(artifact_meta.get("source_path") or path))
            document = normalize_row(case_id, evidence_id, artifact_id, row, artifact_meta)
            parser_status = "parsed_native" if str(artifact_meta.get("source_tool") or "").lower() == "native_scheduled_task" else "parsed"
            artifact_meta["ingest_audit"] = {
                "artifact": str(artifact_meta.get("name") or path.name),
                "parser": "scheduled_task_xml",
                "records_read": 1,
                "records_parsed": 1,
                "events_indexed": 1,
                "records_indexed": 1,
                "xml_task_count": 1,
                "csv_task_count": 0,
                "enabled_count": 1 if document.get("task", {}).get("enabled") is True else 0,
                "disabled_count": 1 if document.get("task", {}).get("enabled") is False else 0,
                "hidden_count": 1 if document.get("task", {}).get("hidden") is True else 0,
                "exec_action_count": 1 if document.get("task", {}).get("command") else 0,
                "com_handler_count": 1 if document.get("task", {}).get("com_handler_class_id") else 0,
                "suspicious_count": 1 if "suspicious" in set(document.get("tags") or []) else 0,
                "powershell_count": 1 if "powershell" in set(document.get("tags") or []) else 0,
                "encoded_command_count": 1 if "encoded_command" in set(document.get("tags") or []) else 0,
                "lolbin_count": 1 if "lolbin" in set(document.get("tags") or []) else 0,
                "suspicious_path_count": 1 if "suspicious_path" in set(document.get("tags") or []) else 0,
                "unc_path_count": 1 if "unc_path" in set(document.get("tags") or []) else 0,
                "missing_timestamp": 0 if document.get("@timestamp") else 1,
                "missing_action": 0 if document.get("task", {}).get("command") or document.get("task", {}).get("com_handler_class_id") else 1,
                "top_task_authors": [document.get("task", {}).get("author")] if document.get("task", {}).get("author") else [],
                "top_commands": [document.get("task", {}).get("command")] if document.get("task", {}).get("command") else [],
                "bulk_index_errors": 0,
                "parser_status": parser_status,
                "warnings": warnings,
                "sample_records": [
                    {
                        "source_file": document.get("source_file"),
                        "task_name": (document.get("task", {}) or {}).get("name"),
                        "uri": (document.get("task", {}) or {}).get("uri"),
                        "command": (document.get("task", {}) or {}).get("command"),
                        "arguments": (document.get("task", {}) or {}).get("arguments"),
                        "enabled": (document.get("task", {}) or {}).get("enabled"),
                        "hidden": (document.get("task", {}) or {}).get("hidden"),
                        "triggers": (document.get("task", {}) or {}).get("triggers"),
                        "risk_score": document.get("risk_score"),
                        "tags": list(document.get("tags") or []),
                        "suspicious_reasons": list(document.get("suspicious_reasons") or []),
                        "parser_status": parser_status,
                    }
                ],
            }
            return [document]
        rows = list(read_scheduled_task_csv_rows(path))
        documents = [normalize_row(case_id, evidence_id, artifact_id, row, artifact_meta) for row in rows]
        author_counter: Counter[str] = Counter()
        command_counter: Counter[str] = Counter()
        enabled_count = disabled_count = hidden_count = exec_action_count = com_handler_count = 0
        suspicious_count = powershell_count = encoded_command_count = lolbin_count = suspicious_path_count = unc_path_count = 0
        missing_timestamp = missing_action = 0
        for document in documents:
            task = document.get("task", {}) or {}
            tags = set(document.get("tags") or [])
            if task.get("author"):
                author_counter[str(task.get("author"))] += 1
            if task.get("command"):
                command_counter[str(task.get("command"))] += 1
            if task.get("enabled") is True:
                enabled_count += 1
            elif task.get("enabled") is False:
                disabled_count += 1
            if task.get("hidden") is True:
                hidden_count += 1
            if task.get("command"):
                exec_action_count += 1
            if task.get("com_handler_class_id"):
                com_handler_count += 1
            if not document.get("@timestamp"):
                missing_timestamp += 1
            if not task.get("command") and not task.get("com_handler_class_id"):
                missing_action += 1
            if "suspicious" in tags:
                suspicious_count += 1
            if "powershell" in tags:
                powershell_count += 1
            if "encoded_command" in tags:
                encoded_command_count += 1
            if "lolbin" in tags:
                lolbin_count += 1
            if "suspicious_path" in tags:
                suspicious_path_count += 1
            if "unc_path" in tags:
                unc_path_count += 1
        artifact_meta["ingest_audit"] = {
            "artifact": str(artifact_meta.get("name") or path.name),
            "parser": "scheduled_task_csv",
            "records_read": len(rows),
            "records_parsed": len(documents),
            "events_indexed": len(documents),
            "xml_task_count": 0,
            "csv_task_count": len(documents),
            "enabled_count": enabled_count,
            "disabled_count": disabled_count,
            "hidden_count": hidden_count,
            "exec_action_count": exec_action_count,
            "com_handler_count": com_handler_count,
            "suspicious_count": suspicious_count,
            "powershell_count": powershell_count,
            "encoded_command_count": encoded_command_count,
            "lolbin_count": lolbin_count,
            "suspicious_path_count": suspicious_path_count,
            "unc_path_count": unc_path_count,
            "missing_timestamp": missing_timestamp,
            "missing_action": missing_action,
            "top_task_authors": [name for name, _ in author_counter.most_common(10)],
            "top_commands": [name for name, _ in command_counter.most_common(10)],
            "bulk_index_errors": 0,
        }
        return documents
    if str(artifact_meta.get("artifact_type") or "").lower() == "windows_ui" or looks_like_windows_ui_artifact(path, list(_csv_headers(path)) if path.suffix.lower() == ".csv" else None):
        rows, ui_audit = parse_windows_ui_artifact_file(path, artifact_meta)
        documents = [normalize_row(case_id, evidence_id, artifact_id, row, {**artifact_meta, "artifact_type": "windows_ui"}) for row in rows]
        by_event_type: Counter[str] = Counter()
        by_parser: Counter[str] = Counter()
        warning_counts: Counter[str] = Counter()
        for document in documents:
            by_event_type[str((document.get("event", {}) or {}).get("type") or "unknown")] += 1
            by_parser[str((document.get("artifact", {}) or {}).get("parser") or str(artifact_meta.get("parser") or "windows_ui_generic_raw"))] += 1
        for warning in ui_audit.get("warnings") or []:
            warning_counts[str(warning)] += 1
        artifact_meta["ingest_audit"] = {
            "artifact": str(artifact_meta.get("name") or path.name),
            "artifact_type": "windows_ui",
            "parser": str(artifact_meta.get("parser") or "windows_ui_generic_raw"),
            "records_read": int(ui_audit.get("records_read") or len(rows)),
            "records_parsed": int(ui_audit.get("records_parsed") or len(rows)),
            "records_indexed": len(documents),
            "events_indexed": len(documents),
            "records_failed": int(ui_audit.get("records_failed") or 0),
            "by_parser": dict(sorted(by_parser.items())),
            "by_event_type": dict(sorted(by_event_type.items())),
            "thumbnail_count": sum(1 for doc in documents if str((doc.get("event", {}) or {}).get("type") or "") == "thumbnail_observed"),
            "notification_count": sum(1 for doc in documents if str((doc.get("event", {}) or {}).get("type") or "") == "notification_observed"),
            "activity_history_count": sum(1 for doc in documents if str((doc.get("event", {}) or {}).get("type") or "") == "activity_history_observed"),
            "search_index_count": sum(1 for doc in documents if str((doc.get("event", {}) or {}).get("type") or "") == "search_index_entry_observed"),
            "event_transcript_count": sum(1 for doc in documents if str((doc.get("event", {}) or {}).get("type") or "") == "event_transcript_observed"),
            "office_alert_count": sum(1 for doc in documents if str((doc.get("event", {}) or {}).get("type") or "") == "office_alert_observed"),
            "office_cache_count": sum(1 for doc in documents if str((doc.get("event", {}) or {}).get("type") or "") == "office_cache_entry_observed"),
            "unsupported_raw_count": sum(1 for doc in documents if str((doc.get("artifact", {}) or {}).get("parser") or "") == "windows_ui_generic_raw"),
            "suspicious_ui_file_count": sum(1 for doc in documents if int(doc.get("risk_score") or 0) >= 60 and str((doc.get("event", {}) or {}).get("type") or "") in {"thumbnail_observed", "activity_history_observed", "search_index_entry_observed"}),
            "office_security_alert_count": sum(1 for doc in documents if str((doc.get("event", {}) or {}).get("type") or "") == "office_alert_observed" and int(doc.get("risk_score") or 0) >= 70),
            "security_notification_count": sum(1 for doc in documents if str((doc.get("event", {}) or {}).get("type") or "") == "notification_observed" and int(doc.get("risk_score") or 0) >= 70),
            "warnings": [{"warning": key, "count": value} for key, value in sorted(warning_counts.items())],
            "parser_errors": list(ui_audit.get("parser_errors") or []),
            "parse_warnings": list(ui_audit.get("warnings") or []),
            "sample_records": [
                {
                    "event_type": (doc.get("event", {}) or {}).get("type"),
                    "path": (doc.get("file", {}) or {}).get("path"),
                    "notification_title": (doc.get("notification", {}) or {}).get("title"),
                    "activity_display": (doc.get("activity", {}) or {}).get("display_text"),
                    "indexed_path": (doc.get("windows_search", {}) or {}).get("indexed_path"),
                    "office_alert_text": (doc.get("office", {}) or {}).get("alert_text"),
                    "risk_score": doc.get("risk_score"),
                    "tags": list(doc.get("tags") or []),
                }
                for doc in documents[:10]
            ],
        }
        return documents
    if artifact_meta.get("artifact_type") == "browser" or looks_like_browser_artifact(path, list(_csv_headers(path)) if path.suffix.lower() == ".csv" else None):
        parser = str(artifact_meta.get("parser") or "").lower()
        if parser in {"browser_chromium_history", "sqlite_chromium"} or path.name.lower() == "history":
            rows, sqlite_copies = parse_chromium_history_sqlite(path, source_path=str(artifact_meta.get("source_path") or path))
        elif parser in {"browser_firefox_places", "sqlite_firefox"} or path.name.lower() == "places.sqlite":
            rows, sqlite_copies = parse_firefox_places_sqlite(path, source_path=str(artifact_meta.get("source_path") or path))
        else:
            rows = read_browser_records(path)
            sqlite_copies = []
        documents = [normalize_row(case_id, evidence_id, artifact_id, row, artifact_meta) for row in rows]
        by_browser: Counter[str] = Counter()
        by_artifact_type: Counter[str] = Counter()
        by_event_type: Counter[str] = Counter()
        danger_type_counts: Counter[str] = Counter()
        data_quality_counts: Counter[str] = Counter()
        suspicious_reason_counts: Counter[str] = Counter()
        for document in documents:
            browser = document.get("browser", {}) or {}
            event = document.get("event", {}) or {}
            if browser.get("browser"):
                by_browser[str(browser.get("browser"))] += 1
            if browser.get("artifact_type"):
                by_artifact_type[str(browser.get("artifact_type"))] += 1
            if event.get("type"):
                by_event_type[str(event.get("type"))] += 1
            if browser.get("danger_type"):
                danger_type_counts[str(browser.get("danger_type"))] += 1
            for quality in document.get("data_quality") or []:
                data_quality_counts[str(quality)] += 1
            for reason in document.get("suspicious_reasons") or []:
                suspicious_reason_counts[str(reason)] += 1
        parser_for_audit = documents[0]["artifact"]["parser"] if documents else parser or "browser_csv"
        browser_audit = BrowserAudit(
            records_read=len(rows),
            records_parsed=len(documents),
            history_count=sum(1 for doc in documents if (doc.get("browser", {}) or {}).get("artifact_type") == "history"),
            download_count=sum(1 for doc in documents if (doc.get("browser", {}) or {}).get("artifact_type") == "download"),
            search_count=sum(1 for doc in documents if (doc.get("browser", {}) or {}).get("artifact_type") == "search_term"),
            suspicious_download_count=sum(1 for doc in documents if "suspicious_download" in set(doc.get("tags") or [])),
            executable_download_count=sum(1 for doc in documents if "executable_download" in set(doc.get("tags") or [])),
            archive_download_count=sum(1 for doc in documents if "archive_download" in set(doc.get("tags") or [])),
            missing_timestamp=sum(1 for doc in documents if not doc.get("@timestamp")),
            missing_url=sum(1 for doc in documents if not ((doc.get("url") or {}).get("full"))),
            missing_path=sum(1 for doc in documents if (doc.get("browser", {}) or {}).get("artifact_type") == "download" and not ((doc.get("download") or {}).get("target_path"))),
        )
        audit = browser_audit.as_dict(artifact_name=str(artifact_meta.get("name") or path.name), parser_name=parser_for_audit, bulk_index_errors=0)
        audit["sqlite_copies"] = sqlite_copies
        audit["by_browser"] = dict(sorted(by_browser.items()))
        audit["by_artifact_type"] = dict(sorted(by_artifact_type.items()))
        audit["by_event_type"] = dict(sorted(by_event_type.items()))
        audit["danger_type_counts"] = dict(sorted(danger_type_counts.items()))
        audit["data_quality_counts"] = dict(sorted(data_quality_counts.items()))
        audit["suspicious_reason_counts"] = dict(sorted(suspicious_reason_counts.items()))
        audit["sample_records"] = [
            {
                "source_file": doc.get("source_file"),
                "browser": (doc.get("browser", {}) or {}).get("browser"),
                "profile": (doc.get("browser", {}) or {}).get("profile"),
                "artifact_type": (doc.get("browser", {}) or {}).get("artifact_type"),
                "url": (doc.get("url", {}) or {}).get("full"),
                "download_path": (doc.get("download", {}) or {}).get("target_path"),
                "risk_score": doc.get("risk_score"),
                "tags": list(doc.get("tags") or []),
                "suspicious_reasons": list(doc.get("suspicious_reasons") or []),
            }
            for doc in documents[:10]
        ]
        artifact_meta["ingest_audit"] = audit
        return documents
    if str(artifact_meta.get("artifact_type") or "").lower() == "email" or looks_like_email_artifact(path, list(_csv_headers(path)) if path.suffix.lower() == ".csv" else None):
        rows, email_audit = parse_email_artifact_file(path, artifact_meta)
        documents = [normalize_row(case_id, evidence_id, artifact_id, row, artifact_meta) for row in rows]
        by_event_type: Counter[str] = Counter()
        sender_domain_counter: Counter[str] = Counter()
        attachment_extension_counter: Counter[str] = Counter()
        unsupported_counts: Counter[str] = Counter()
        for document in documents:
            by_event_type[str((document.get("event", {}) or {}).get("type") or "unknown")] += 1
            sender = (((document.get("email", {}) or {}).get("from", {}) or {}).get("address"))
            if sender and "@" in str(sender):
                sender_domain_counter[str(sender).rsplit("@", 1)[-1].lower()] += 1
            for attachment in ((document.get("email", {}) or {}).get("attachments") or []):
                if not isinstance(attachment, dict):
                    continue
                ext = str(attachment.get("extension") or "unknown")
                attachment_extension_counter[ext] += 1
            unsupported_reason = str(((document.get("email", {}) or {}).get("unsupported_reason") or "")).strip()
            if unsupported_reason:
                unsupported_counts[unsupported_reason] += 1
        artifact_meta["ingest_audit"] = {
            "artifact": str(artifact_meta.get("name") or path.name),
            "artifact_type": "email",
            "parser": str(artifact_meta.get("parser") or "email_generic_raw"),
            "records_read": int(email_audit.get("records_read") or len(rows)),
            "records_parsed": int(email_audit.get("records_parsed") or len(rows)),
            "records_indexed": len(documents),
            "events_indexed": len(documents),
            "records_failed": int(email_audit.get("records_failed") or 0),
            "message_count": sum(1 for doc in documents if str((doc.get("event", {}) or {}).get("type") or "") == "email_message"),
            "attachment_count": sum(len(((doc.get("email", {}) or {}).get("attachments") or [])) for doc in documents),
            "mailbox_inventory_count": sum(1 for doc in documents if str((doc.get("event", {}) or {}).get("type") or "") == "email_mailbox_observed"),
            "temp_attachment_count": sum(1 for doc in documents if str((doc.get("event", {}) or {}).get("type") or "") == "email_temp_attachment_observed"),
            "suspicious_attachment_count": sum(int(((doc.get("email", {}) or {}).get("suspicious_attachment_count") or 0)) for doc in documents),
            "auth_failure_count": sum(1 for doc in documents if bool(((doc.get("email", {}) or {}).get("auth_failure")))),
            "by_parser": {str(artifact_meta.get("parser") or "email_generic_raw"): len(documents)},
            "by_event_type": dict(sorted(by_event_type.items())),
            "by_sender_domain": dict(sorted(sender_domain_counter.items())),
            "by_attachment_extension": dict(sorted(attachment_extension_counter.items())),
            "unsupported_counts": dict(sorted(unsupported_counts.items())),
            "warnings": list(email_audit.get("warnings") or []),
            "parser_errors": list(email_audit.get("parser_errors") or []),
            "bulk_index_errors": 0,
            "sample_records": [
                {
                    "source_file": doc.get("source_file"),
                    "event_type": (doc.get("event", {}) or {}).get("type"),
                    "subject": (doc.get("email", {}) or {}).get("subject"),
                    "from": (((doc.get("email", {}) or {}).get("from", {}) or {}).get("address")),
                    "message_id": (doc.get("email", {}) or {}).get("message_id"),
                    "risk_score": doc.get("risk_score"),
                    "tags": list(doc.get("tags") or []),
                    "suspicious_reasons": list(doc.get("suspicious_reasons") or []),
                }
                for doc in documents[:10]
            ],
        }
        return documents
    if str(artifact_meta.get("artifact_type") or "") == "recycle_bin" or _looks_like_recycle_bin(path, artifact_meta):
        parser = str(artifact_meta.get("parser") or "").lower()
        warnings: list[str] = []
        if parser == "raw_i_file" or path.name.lower().startswith("$i"):
            row, warnings = parse_recycle_i_file(
                path,
                source_path=str(artifact_meta.get("source_path") or path),
                paired_r_path=artifact_meta.get("recycle_r_path"),
            )
            rows = [row]
        elif parser == "raw_r_file" or path.name.lower().startswith("$r"):
            row, warnings = parse_recycle_r_file(path, source_path=str(artifact_meta.get("source_path") or path))
            rows = [row]
        elif parser in {"json", "jsonl"} or path.suffix.lower() in {".json", ".jsonl"}:
            rows = list(read_recycle_bin_json_rows(path))
        else:
            rows = list(read_recycle_bin_csv_rows(path))
        documents = [normalize_row(case_id, evidence_id, artifact_id, row, artifact_meta) for row in rows]
        recycle_i_count = recycle_r_count = recycle_pair_count = orphan_i_count = orphan_r_count = content_missing_count = 0
        recycle_i_parsed_ok = recycle_i_invalid_path_count = recycle_i_utf16_fallback_count = content_missing_confirmed_count = content_not_collected_count = 0
        suspicious_count = executable_deleted_count = script_deleted_count = archive_deleted_count = double_extension_count = deleted_download_count = deleted_detected_file_count = 0
        missing_timestamp = missing_original_path = unresolved_sid_count = 0
        for document in documents:
            recycle = document.get("recycle", {}) or {}
            tags = set(document.get("tags") or [])
            artifact_kind = str(recycle.get("record_type") or recycle.get("artifact_type") or "")
            if artifact_kind in {"recycle_i_file", "recycle_pair"}:
                recycle_i_count += 1
                if recycle.get("original_path"):
                    recycle_i_parsed_ok += 1
                else:
                    recycle_i_invalid_path_count += 1
            if artifact_kind in {"recycle_pair", "recycle_orphan_r"}:
                recycle_r_count += 1
            if artifact_kind == "recycle_pair":
                recycle_pair_count += 1
            if artifact_kind == "recycle_i_file" and not recycle.get("has_r_file"):
                orphan_i_count += 1
            if artifact_kind == "recycle_orphan_r":
                orphan_r_count += 1
            if not document.get("@timestamp"):
                missing_timestamp += 1
            if not recycle.get("original_path"):
                missing_original_path += 1
            raw_warning_blob = str((document.get("raw", {}) or {}).get("ParseWarnings") or "")
            if "original_path_extracted_by_utf16_fallback" in raw_warning_blob:
                recycle_i_utf16_fallback_count += 1
            if document.get("user", {}).get("sid") and not document.get("user", {}).get("name"):
                unresolved_sid_count += 1
            if "content_missing" in tags:
                content_missing_count += 1
            if recycle.get("content_status") == "content_missing_confirmed":
                content_missing_confirmed_count += 1
            elif recycle.get("content_status") == "content_not_collected":
                content_not_collected_count += 1
            if "suspicious" in tags:
                suspicious_count += 1
            if "executable_deleted" in tags:
                executable_deleted_count += 1
            if "script_deleted" in tags:
                script_deleted_count += 1
            if "archive_deleted" in tags:
                archive_deleted_count += 1
            if "double_extension" in tags:
                double_extension_count += 1
            if "deleted_download" in tags:
                deleted_download_count += 1
            if "defender_correlated" in tags:
                deleted_detected_file_count += 1
        artifact_meta["ingest_audit"] = {
            "artifact": str(artifact_meta.get("name") or path.name),
            "parser": parser or "recycle_bin",
            "records_read": len(rows),
            "records_parsed": len(documents),
            "events_indexed": len(documents),
            "recycle_i_count": recycle_i_count,
            "recycle_i_parsed_ok": recycle_i_parsed_ok,
            "recycle_i_invalid_path_count": recycle_i_invalid_path_count,
            "recycle_i_utf16_fallback_count": recycle_i_utf16_fallback_count,
            "recycle_r_count": recycle_r_count,
            "recycle_pair_count": recycle_pair_count,
            "orphan_i_count": orphan_i_count,
            "orphan_r_count": orphan_r_count,
            "content_missing_count": content_missing_count,
            "content_missing_confirmed_count": content_missing_confirmed_count,
            "content_not_collected_count": content_not_collected_count,
            "suspicious_count": suspicious_count,
            "executable_deleted_count": executable_deleted_count,
            "script_deleted_count": script_deleted_count,
            "archive_deleted_count": archive_deleted_count,
            "double_extension_count": double_extension_count,
            "deleted_download_count": deleted_download_count,
            "deleted_detected_file_count": deleted_detected_file_count,
            "missing_timestamp_count": missing_timestamp,
            "missing_original_path_count": missing_original_path,
            "unresolved_sid_count": unresolved_sid_count,
            "warnings": warnings,
            "sample_records": [
                {
                    "original_path": (doc.get("recycle", {}) or {}).get("original_path"),
                    "deleted_time": (doc.get("recycle", {}) or {}).get("deleted_time"),
                    "sid": (doc.get("recycle", {}) or {}).get("sid"),
                    "user": (doc.get("user", {}) or {}).get("name"),
                    "risk_score": doc.get("risk_score"),
                    "tags": list(doc.get("tags") or []),
                    "suspicious_reasons": list(doc.get("suspicious_reasons") or []),
                }
                for doc in documents[:10]
            ],
        }
        return documents
    if artifact_meta.get("artifact_type") in {"autoruns", "autorun"} or looks_like_autoruns_artifact(path, list(_csv_headers(path)) if path.suffix.lower() in {".csv", ".tsv"} else None):
        parser = str(artifact_meta.get("parser") or "").lower()
        if parser == "startup_folder":
            startup_source_path = str(artifact_meta.get("source_path") or path)
            rows = [
                {
                    "Category": "Logon",
                    "Entry Location": startup_source_path,
                    "Entry": path.name,
                    "Enabled": "true",
                    "Profile": artifact_meta.get("user"),
                    "Image Path": startup_source_path,
                    "Launch String": startup_source_path,
                    "Time": artifact_meta.get("mtime") or None,
                    "Description": "Startup folder file observed via raw collection",
                }
            ]
        elif parser == "autoruns_jsonl" or path.suffix.lower() == ".jsonl":
            rows = read_records(path)
        elif parser == "autoruns_json" or path.suffix.lower() == ".json":
            payload = json.loads(path.read_text(encoding="utf-8", errors="ignore"))
            if isinstance(payload, list):
                rows = [item for item in payload if isinstance(item, dict)]
            elif isinstance(payload, dict):
                if isinstance(payload.get("items"), list):
                    rows = [item for item in payload["items"] if isinstance(item, dict)]
                elif isinstance(payload.get("entries"), list):
                    rows = [item for item in payload["entries"] if isinstance(item, dict)]
                else:
                    rows = [payload]
            else:
                rows = []
        elif parser == "autoruns_xml" or path.suffix.lower() == ".xml":
            rows = parse_autoruns_xml_file(path)
        elif parser == "autoruns_tsv" or path.suffix.lower() == ".tsv":
            rows = parse_autoruns_tsv_file(path)
        else:
            rows = parse_autoruns_csv_file(path)
        documents = [normalize_row(case_id, evidence_id, artifact_id, row, artifact_meta) for row in rows]
        autoruns_entries_count = enabled_entries_count = disabled_entries_count = run_key_count = runonce_count = startup_folder_count = service_count = driver_count = scheduled_task_count = wmi_count = winlogon_count = ifeo_count = appinit_count = appcert_count = lsa_count = print_monitor_count = suspicious_autoruns_count = unsigned_count = unverified_count = user_writable_path_count = lolbin_count = powershell_count = encoded_powershell_count = download_command_count = vt_detection_count = missing_path_count = missing_timestamp_count = high_risk_count = 0
        for document in documents:
            autoruns = document.get("autoruns", {}) or {}
            persistence = document.get("persistence", {}) or {}
            tags = set(document.get("tags") or [])
            mechanism = str(persistence.get("mechanism") or "")
            autoruns_entries_count += 1
            if autoruns.get("enabled") is True:
                enabled_entries_count += 1
            if autoruns.get("enabled") is False:
                disabled_entries_count += 1
            if mechanism == "run_key":
                run_key_count += 1
            if mechanism == "runonce_key":
                runonce_count += 1
            if mechanism == "startup_folder":
                startup_folder_count += 1
            if mechanism == "service":
                service_count += 1
            if mechanism == "driver":
                driver_count += 1
            if mechanism == "scheduled_task":
                scheduled_task_count += 1
            if mechanism == "wmi":
                wmi_count += 1
            if mechanism in {"winlogon_shell", "winlogon_userinit"}:
                winlogon_count += 1
            if mechanism == "ifeo_debugger":
                ifeo_count += 1
            if mechanism == "appinit_dll":
                appinit_count += 1
            if mechanism == "appcert_dll":
                appcert_count += 1
            if mechanism == "lsa_package":
                lsa_count += 1
            if mechanism == "print_monitor":
                print_monitor_count += 1
            if "suspicious_autorun" in tags or document.get("suspicious_reasons"):
                suspicious_autoruns_count += 1
            if "unsigned" in tags:
                unsigned_count += 1
            if "unverified" in tags:
                unverified_count += 1
            if "user_writable_path" in tags:
                user_writable_path_count += 1
            if "lolbin" in tags:
                lolbin_count += 1
            if "Autorun uses PowerShell" in set(document.get("suspicious_reasons") or []):
                powershell_count += 1
            if "encoded_powershell" in tags:
                encoded_powershell_count += 1
            if "download_command" in tags:
                download_command_count += 1
            if autoruns.get("vt_detection"):
                vt_detection_count += 1
            if "missing_path" in (document.get("data_quality") or []):
                missing_path_count += 1
            if not document.get("@timestamp"):
                missing_timestamp_count += 1
            if int(document.get("risk_score") or 0) >= 80:
                high_risk_count += 1
        artifact_meta["ingest_audit"] = {
            "artifact": str(artifact_meta.get("name") or path.name),
            "artifact_type": "autorun",
            "parser": parser or "autoruns_csv",
            "records_read": len(rows),
            "records_parsed": len(documents),
            "events_indexed": len(documents),
            "autoruns_entries_count": autoruns_entries_count,
            "enabled_entries_count": enabled_entries_count,
            "disabled_entries_count": disabled_entries_count,
            "run_key_count": run_key_count,
            "runonce_count": runonce_count,
            "startup_folder_count": startup_folder_count,
            "service_count": service_count,
            "driver_count": driver_count,
            "scheduled_task_count": scheduled_task_count,
            "wmi_count": wmi_count,
            "winlogon_count": winlogon_count,
            "ifeo_count": ifeo_count,
            "appinit_count": appinit_count,
            "appcert_count": appcert_count,
            "lsa_count": lsa_count,
            "print_monitor_count": print_monitor_count,
            "suspicious_autoruns_count": suspicious_autoruns_count,
            "unsigned_count": unsigned_count,
            "unverified_count": unverified_count,
            "user_writable_path_count": user_writable_path_count,
            "lolbin_count": lolbin_count,
            "powershell_autorun_count": powershell_count,
            "encoded_powershell_count": encoded_powershell_count,
            "download_command_count": download_command_count,
            "vt_detection_count": vt_detection_count,
            "high_risk_count": high_risk_count,
            "missing_path_count": missing_path_count,
            "missing_timestamp_count": missing_timestamp_count,
            "parse_warnings": [],
            "bulk_index_errors": 0,
        }
        return documents
    if artifact_meta.get("artifact_type") in {"cloud_sync", "cloud"} or looks_like_cloud_sync_artifact(path, list(_csv_headers(path)) if path.suffix.lower() == ".csv" else None):
        parser = str(artifact_meta.get("parser") or "").lower()
        if parser == "path_inference":
            inferred_path = str(artifact_meta.get("normalized_windows_path") or artifact_meta.get("source_path") or "")
            rows = [{
                "Provider": artifact_meta.get("cloud_provider") or artifact_meta.get("provider"),
                "SyncRoot": artifact_meta.get("cloud_sync_root") or artifact_meta.get("sync_root") or inferred_path,
                "LocalPath": None,
                "ArtifactType": artifact_meta.get("cloud_artifact_type") or artifact_meta.get("artifact_subtype") or "cloud_syncroot",
                "DetectionMethod": "path_inference",
            }]
        elif parser in {"cloud_json", "cloud_onedrive_json"} or path.suffix.lower() == ".json":
            rows = parse_cloud_json_file(path)
        elif parser in {"provider_log", "cloud_raw"} or path.suffix.lower() in {".log", ".txt", ".ini"}:
            rows = parse_cloud_log_file(path)
        elif parser in {"cloud_onedrive_jsonl"} or path.suffix.lower() == ".jsonl":
            rows = read_records(path)
        else:
            rows = parse_cloud_csv_file(path)
        documents = [normalize_row(case_id, evidence_id, artifact_id, row, artifact_meta) for row in rows]
        providers = sorted({str((doc.get("cloud", {}) or {}).get("provider")) for doc in documents if (doc.get("cloud", {}) or {}).get("provider")})
        sync_roots = sorted({str((doc.get("cloud", {}) or {}).get("sync_root")) for doc in documents if (doc.get("cloud", {}) or {}).get("sync_root")})
        cloud_file_activity_count = sensitive_file_count = archive_file_count = copied_to_cloud_count = downloaded_to_cloud_count = executable_from_cloud_count = possible_cloud_staging_count = possible_cloud_exfiltration_count = missing_timestamp_count = 0
        for document in documents:
            tags = set(document.get("tags") or [])
            event_type = str((document.get("event", {}) or {}).get("type") or "")
            if event_type == "cloud_file_activity":
                cloud_file_activity_count += 1
            if "sensitive_file" in tags:
                sensitive_file_count += 1
            if "archive_file" in tags:
                archive_file_count += 1
            if "copied_to_cloud" in tags:
                copied_to_cloud_count += 1
            if "downloaded_to_cloud" in tags:
                downloaded_to_cloud_count += 1
            if "executable_from_cloud" in tags:
                executable_from_cloud_count += 1
            if event_type == "cloud_staging_candidate":
                possible_cloud_staging_count += 1
            if event_type == "possible_cloud_exfiltration":
                possible_cloud_exfiltration_count += 1
            if not document.get("@timestamp"):
                missing_timestamp_count += 1
        artifact_meta["ingest_audit"] = {
            "artifact": str(artifact_meta.get("name") or path.name),
            "parser": parser or "cloud_csv",
            "records_read": len(rows),
            "records_parsed": len(documents),
            "events_indexed": len(documents),
            "cloud_candidates": len(documents),
            "providers_detected": providers,
            "sync_roots_detected": len(sync_roots),
            "cloud_file_activity_count": cloud_file_activity_count,
            "sensitive_file_count": sensitive_file_count,
            "archive_file_count": archive_file_count,
            "copied_to_cloud_count": copied_to_cloud_count,
            "downloaded_to_cloud_count": downloaded_to_cloud_count,
            "executable_from_cloud_count": executable_from_cloud_count,
            "defender_detection_in_cloud_count": 0,
            "possible_cloud_staging_count": possible_cloud_staging_count,
            "possible_cloud_exfiltration_count": possible_cloud_exfiltration_count,
            "large_cloud_folder_skipped_count": 0,
            "missing_timestamp_count": missing_timestamp_count,
            "parse_warnings": [],
            "bulk_index_errors": 0,
        }
        return documents
    if artifact_meta.get("artifact_type") in {"network", "wlan", "dns"} or looks_like_network_artifact(path, list(_csv_headers(path)) if path.suffix.lower() == ".csv" else None):
        parser = str(artifact_meta.get("parser") or "").lower()
        if parser == "wlan_profile_xml" or path.suffix.lower() == ".xml":
            rows = parse_wlan_profile_xml(path)
        elif parser == "hosts_file" or path.name.lower() == "hosts":
            rows = parse_hosts_file(path)
        elif parser == "dns_csv":
            rows = parse_dns_csv_file(path)
        elif parser in {"network_json", "wlan_json", "dns_json"} or path.suffix.lower() == ".json":
            rows = parse_dns_json_file(path) if "dns" in path.name.lower() else parse_network_json_file(path)
        elif parser in {"wlan_jsonl", "dns_jsonl"} or path.suffix.lower() == ".jsonl":
            rows = read_records(path)
        elif parser == "ipconfig_txt":
            rows = parse_ipconfig_txt(path)
        elif parser in {"netsh_txt", "wlan_raw"}:
            rows = parse_netsh_wlan_txt(path)
        elif parser == "dns_raw":
            rows = read_records(path)
        elif parser == "network_txt":
            lower_name = path.name.lower()
            if "netstat" in lower_name:
                rows = parse_netstat_txt(path)
            elif "arp" in lower_name:
                rows = parse_arp_txt(path)
            else:
                rows = parse_ipconfig_txt(path)
        elif parser in {"evtx", "wlan_evtx", "dns_evtx"}:
            base_rows = parse_network_csv_file(path)
            if parser == "dns_evtx" or "dns-client" in path.name.lower():
                rows = [classify_dns_client_event(item) for item in base_rows]
            else:
                rows = [classify_wlan_autoconfig_event(item) for item in base_rows]
        elif parser in {"registry", "wlan_registry"}:
            rows = [classify_network_registry_row(item) for item in parse_network_csv_file(path)]
        else:
            lower_name = path.name.lower()
            if "dns" in lower_name:
                rows = parse_dns_csv_file(path)
            else:
                rows = parse_network_csv_file(path)
            if any(token in lower_name for token in {"networklist", "tcpip", "interfaces"}):
                rows = [classify_network_registry_row(item) for item in rows]
            if "wlan-autoconfig" in lower_name:
                rows = [classify_wlan_autoconfig_event(item) for item in rows]
            if "dns-client" in lower_name:
                rows = [classify_dns_client_event(item) for item in rows]
        documents = [normalize_row(case_id, evidence_id, artifact_id, row, artifact_meta) for row in rows]
        ingest_counts = Counter()
        for document in documents:
            event_type = str((document.get("event", {}) or {}).get("type") or "")
            tags = set(document.get("tags") or [])
            if event_type == "wlan_profile":
                ingest_counts["wlan_profiles_count"] += 1
            if event_type == "wlan_connected":
                ingest_counts["wlan_connections_count"] += 1
            if event_type == "wlan_disconnected":
                ingest_counts["wlan_disconnections_count"] += 1
            if event_type == "wlan_connection_failed":
                ingest_counts["wlan_failures_count"] += 1
            if event_type == "network_profile":
                ingest_counts["network_profiles_count"] += 1
            if event_type == "dns_cache_entry":
                ingest_counts["dns_cache_count"] += 1
            if event_type == "dns_config":
                ingest_counts["dns_config_count"] += 1
            if event_type == "hosts_entry":
                ingest_counts["hosts_entries_count"] += 1
            if "suspicious_hosts_entry" in tags:
                ingest_counts["suspicious_hosts_entries_count"] += 1
            if "open_wifi" in tags:
                ingest_counts["open_wifi_count"] += 1
            if "suspicious_dns_server" in tags:
                ingest_counts["suspicious_dns_server_count"] += 1
            if event_type == "netstat_connection":
                ingest_counts["netstat_connections_count"] += 1
            if event_type == "arp_entry":
                ingest_counts["arp_entries_count"] += 1
            if event_type == "route_entry":
                ingest_counts["route_entries_count"] += 1
            if not document.get("@timestamp"):
                ingest_counts["missing_timestamp_count"] += 1
        artifact_meta["ingest_audit"] = {
            "artifact": str(artifact_meta.get("name") or path.name),
            "parser": parser or "network_csv",
            "records_read": len(rows),
            "records_parsed": len(documents),
            "events_indexed": len(documents),
            "wlan_profiles_count": ingest_counts["wlan_profiles_count"],
            "wlan_connections_count": ingest_counts["wlan_connections_count"],
            "wlan_disconnections_count": ingest_counts["wlan_disconnections_count"],
            "wlan_failures_count": ingest_counts["wlan_failures_count"],
            "network_profiles_count": ingest_counts["network_profiles_count"],
            "dns_cache_count": ingest_counts["dns_cache_count"],
            "dns_config_count": ingest_counts["dns_config_count"],
            "hosts_entries_count": ingest_counts["hosts_entries_count"],
            "suspicious_hosts_entries_count": ingest_counts["suspicious_hosts_entries_count"],
            "open_wifi_count": ingest_counts["open_wifi_count"],
            "suspicious_dns_server_count": ingest_counts["suspicious_dns_server_count"],
            "netstat_connections_count": ingest_counts["netstat_connections_count"],
            "arp_entries_count": ingest_counts["arp_entries_count"],
            "route_entries_count": ingest_counts["route_entries_count"],
            "missing_timestamp_count": ingest_counts["missing_timestamp_count"],
            "parse_warnings": [],
            "bulk_index_errors": 0,
        }
        return documents
    if _looks_like_powershell(path, artifact_meta):
        parser = str(artifact_meta.get("parser") or "").lower()
        warnings: list[str] = []
        if parser in {"psreadline", "powershell_history"}:
            rows, warnings = parse_psreadline_history(path)
        elif parser in {"transcript", "powershell_transcript"}:
            rows, transcript_audit = parse_powershell_transcript(path)
            warnings = []
        elif parser in {"script", "powershell_script"} or path.suffix.lower() in {".ps1", ".psm1", ".psd1"}:
            rows, warnings = parse_powershell_script_file(path)
        elif parser in {"json", "jsonl", "powershell_json", "powershell_jsonl"} or path.suffix.lower() in {".json", ".jsonl"}:
            rows = read_powershell_json_rows(path)
        elif parser in {"csv", "powershell_csv"} or path.suffix.lower() == ".csv":
            rows = list(read_powershell_csv_rows(path))
        else:
            rows, warnings = parse_psreadline_history(path)
        source_mtime = datetime.fromtimestamp(path.stat().st_mtime, tz=UTC).isoformat()
        for row in rows:
            row.setdefault("SourceFile", str(artifact_meta.get("source_path") or path))
            row.setdefault("SourceFileMtime", source_mtime)
        documents = [normalize_row(case_id, evidence_id, artifact_id, row, artifact_meta) for row in rows]
        missing_timestamp = 0
        suspicious_count = encoded_command_count = decoded_command_count = download_cradle_count = iex_count = defender_tampering_count = persistence_count = recon_count = credential_access_count = source_file_mtime_used_count = 0
        by_ps_artifact_type: dict[str, int] = defaultdict(int)
        by_ps_event_type: dict[str, int] = defaultdict(int)
        for document in documents:
            powershell = document.get("powershell", {}) or {}
            tags = set(document.get("tags") or [])
            by_ps_artifact_type[str(powershell.get("artifact_type") or "powershell")] += 1
            by_ps_event_type[str((document.get("event", {}) or {}).get("type") or "unknown")] += 1
            if not document.get("@timestamp"):
                missing_timestamp += 1
            if document.get("timestamp_precision") == "source_file_mtime":
                source_file_mtime_used_count += 1
            if "suspicious" in tags:
                suspicious_count += 1
            if powershell.get("has_encoded_command"):
                encoded_command_count += 1
            if powershell.get("decoded_command_preview"):
                decoded_command_count += 1
            if powershell.get("has_download"):
                download_cradle_count += 1
            if powershell.get("has_iex"):
                iex_count += 1
            if powershell.get("has_defender_tampering"):
                defender_tampering_count += 1
            if powershell.get("has_persistence"):
                persistence_count += 1
            if "recon" in tags:
                recon_count += 1
            if "credential_access" in tags:
                credential_access_count += 1
        artifact_meta["ingest_audit"] = {
            "artifact": str(artifact_meta.get("name") or path.name),
            "parser": (
                "powershell_history" if parser in {"psreadline", "powershell_history"}
                else "powershell_transcript" if parser in {"transcript", "powershell_transcript"}
                else "powershell_script" if parser in {"script", "powershell_script"}
                else "powershell_jsonl" if parser in {"jsonl", "powershell_jsonl"} or path.suffix.lower() == ".jsonl"
                else "powershell_json" if parser in {"json", "powershell_json"} or path.suffix.lower() == ".json"
                else "powershell_csv" if parser in {"csv", "powershell_csv"} or path.suffix.lower() == ".csv"
                else "powershell_history"
            ),
            "artifact_type": "powershell",
            "source_file": str(artifact_meta.get("source_path") or path),
            "records_read": len(rows),
            "records_parsed": len(documents),
            "events_indexed": len(documents),
            "records_indexed": len(documents),
            "records_failed": 0,
            "psreadline_command_count": sum(1 for item in documents if (item.get("powershell", {}) or {}).get("artifact_type") == "psreadline_history"),
            "transcript_command_count": sum(1 for item in documents if (item.get("powershell", {}) or {}).get("artifact_type") == "powershell_transcript"),
            "script_observed_count": sum(1 for item in documents if (item.get("powershell", {}) or {}).get("artifact_type") == "powershell_script"),
            "suspicious_count": suspicious_count,
            "encoded_command_count": encoded_command_count,
            "decoded_command_count": decoded_command_count,
            "download_cradle_count": download_cradle_count,
            "iex_count": iex_count,
            "defender_tampering_count": defender_tampering_count,
            "persistence_count": persistence_count,
            "recon_count": recon_count,
            "credential_access_count": credential_access_count,
            "by_artifact_type": dict(sorted(by_ps_artifact_type.items())),
            "by_event_type": dict(sorted(by_ps_event_type.items())),
            "missing_timestamp": missing_timestamp,
            "source_file_mtime_used_count": source_file_mtime_used_count,
            "parse_warnings": warnings,
            "bulk_index_errors": 0,
            "sample_records": [
                {
                    "source_file": (item.get("powershell", {}) or {}).get("source_file") or item.get("source_file"),
                    "artifact_type": (item.get("powershell", {}) or {}).get("artifact_type"),
                    "event_type": (item.get("event", {}) or {}).get("type"),
                    "command_preview": (item.get("powershell", {}) or {}).get("command_preview"),
                    "decoded_command_preview": (item.get("powershell", {}) or {}).get("decoded_command_preview"),
                    "urls": list((item.get("powershell", {}) or {}).get("urls") or []),
                    "domains": list((item.get("powershell", {}) or {}).get("domains") or []),
                    "paths": list((item.get("powershell", {}) or {}).get("paths") or []),
                    "risk_score": item.get("risk_score"),
                    "tags": list(item.get("tags") or []),
                    "suspicious_reasons": list(item.get("suspicious_reasons") or []),
                }
                for item in documents[:10]
            ],
        }
        return documents
    if str(artifact_meta.get("artifact_type") or "") == "recycle_bin" or _looks_like_recycle_bin(path, artifact_meta):
        parser = str(artifact_meta.get("parser") or "").lower()
        warnings: list[str] = []
        if parser == "raw_i_file" or path.name.lower().startswith("$i"):
            row, warnings = parse_recycle_i_file(
                path,
                source_path=str(artifact_meta.get("source_path") or path),
                paired_r_path=artifact_meta.get("recycle_r_path"),
            )
            rows = [row]
        elif parser == "raw_r_file" or path.name.lower().startswith("$r"):
            row, warnings = parse_recycle_r_file(path, source_path=str(artifact_meta.get("source_path") or path))
            rows = [row]
        elif parser in {"json", "jsonl"} or path.suffix.lower() in {".json", ".jsonl"}:
            rows = list(read_recycle_bin_json_rows(path))
        else:
            rows = list(read_recycle_bin_csv_rows(path))
        documents = [normalize_row(case_id, evidence_id, artifact_id, row, artifact_meta) for row in rows]
        recycle_i_count = recycle_r_count = recycle_pair_count = orphan_i_count = orphan_r_count = content_missing_count = 0
        recycle_i_parsed_ok = recycle_i_invalid_path_count = recycle_i_utf16_fallback_count = content_missing_confirmed_count = content_not_collected_count = 0
        suspicious_count = executable_deleted_count = script_deleted_count = archive_deleted_count = double_extension_count = deleted_download_count = deleted_detected_file_count = 0
        missing_timestamp = missing_original_path = unresolved_sid_count = 0
        for document in documents:
            recycle = document.get("recycle", {}) or {}
            tags = set(document.get("tags") or [])
            artifact_kind = str(recycle.get("record_type") or recycle.get("artifact_type") or "")
            if artifact_kind in {"recycle_i_file", "recycle_pair"}:
                recycle_i_count += 1
                if recycle.get("original_path"):
                    recycle_i_parsed_ok += 1
                else:
                    recycle_i_invalid_path_count += 1
            if artifact_kind in {"recycle_pair", "recycle_orphan_r"}:
                recycle_r_count += 1
            if artifact_kind == "recycle_pair":
                recycle_pair_count += 1
            if artifact_kind == "recycle_i_file" and not recycle.get("has_r_file"):
                orphan_i_count += 1
            if artifact_kind == "recycle_orphan_r":
                orphan_r_count += 1
            if not document.get("@timestamp"):
                missing_timestamp += 1
            if not recycle.get("original_path"):
                missing_original_path += 1
            raw_warning_blob = str((document.get("raw", {}) or {}).get("ParseWarnings") or "")
            if "original_path_extracted_by_utf16_fallback" in raw_warning_blob:
                recycle_i_utf16_fallback_count += 1
            if document.get("user", {}).get("sid") and not document.get("user", {}).get("name"):
                unresolved_sid_count += 1
            if "content_missing" in tags:
                content_missing_count += 1
            if recycle.get("content_status") == "content_missing_confirmed":
                content_missing_confirmed_count += 1
            elif recycle.get("content_status") == "content_not_collected":
                content_not_collected_count += 1
            if "suspicious" in tags:
                suspicious_count += 1
            if "executable_deleted" in tags:
                executable_deleted_count += 1
            if "script_deleted" in tags:
                script_deleted_count += 1
            if "archive_deleted" in tags:
                archive_deleted_count += 1
            if "double_extension" in tags:
                double_extension_count += 1
            if "deleted_download" in tags:
                deleted_download_count += 1
            if "defender_correlated" in tags:
                deleted_detected_file_count += 1
        artifact_meta["ingest_audit"] = {
            "artifact": str(artifact_meta.get("name") or path.name),
            "parser": parser or "recycle_bin",
            "records_read": len(rows),
            "records_parsed": len(documents),
            "events_indexed": len(documents),
            "recycle_i_count": recycle_i_count,
            "recycle_i_parsed_ok": recycle_i_parsed_ok,
            "recycle_i_invalid_path_count": recycle_i_invalid_path_count,
            "recycle_i_utf16_fallback_count": recycle_i_utf16_fallback_count,
            "recycle_r_count": recycle_r_count,
            "recycle_pair_count": recycle_pair_count,
            "orphan_i_count": orphan_i_count,
            "orphan_r_count": orphan_r_count,
            "content_missing_count": content_missing_count,
            "content_missing_confirmed_count": content_missing_confirmed_count,
            "content_not_collected_count": content_not_collected_count,
            "suspicious_count": suspicious_count,
            "executable_deleted_count": executable_deleted_count,
            "script_deleted_count": script_deleted_count,
            "archive_deleted_count": archive_deleted_count,
            "double_extension_count": double_extension_count,
            "deleted_download_count": deleted_download_count,
            "deleted_detected_file_count": deleted_detected_file_count,
            "missing_timestamp": missing_timestamp,
            "missing_original_path": missing_original_path,
            "unresolved_sid_count": unresolved_sid_count,
            "bulk_index_errors": 0,
            "parse_warnings": warnings,
        }
        return documents
    if artifact_meta.get("artifact_type") == "usb" or _looks_like_usb(path, artifact_meta):
        parser = str(artifact_meta.get("parser") or "").lower()
        parse_warnings: list[str] = []
        raw_audit: dict | None = None
        if parser in {"setupapi", "usb_setupapi"} or path.name.lower() in {"setupapi.dev.log", "setupapi.setup.log"}:
            rows, parse_warnings, raw_audit = parse_setupapi_dev_log(
                path,
                source_path=str(artifact_meta.get("source_path") or artifact_meta.get("velociraptor_original_path") or path),
            )
        elif parser in {"usb_json", "usb_jsonl", "usb_evtx"} or path.suffix.lower() in {".json", ".jsonl"}:
            rows = read_defender_json_rows(path)
        else:
            rows = parse_usb_csv_file(path)
        documents = [normalize_row(case_id, evidence_id, artifact_id, row, artifact_meta) for row in rows]
        setupapi_blocks_read = setupapi_usb_blocks = usb_storage_count = portable_device_count = mounted_device_count = 0
        vendor_product_parsed_count = serial_parsed_count = missing_timestamp = missing_serial = missing_device_instance_id = 0
        by_event_type: Counter[str] = Counter()
        by_device_type: Counter[str] = Counter()
        by_vendor: Counter[str] = Counter()
        by_product: Counter[str] = Counter()
        by_vid_pid: Counter[str] = Counter()
        by_serial_presence: Counter[str] = Counter()
        by_drive_letter: Counter[str] = Counter()
        by_volume_serial: Counter[str] = Counter()
        connected_count = disconnected_count = installed_count = observed_count = 0
        for document in documents:
            usb = document.get("usb", {}) or {}
            volume = document.get("volume", {}) or {}
            event_type = str((document.get("event", {}) or {}).get("type") or "")
            by_event_type[event_type or "unknown"] += 1
            if event_type == "usb_installed":
                setupapi_usb_blocks += 1
                installed_count += 1
            elif event_type == "usb_connected":
                connected_count += 1
            elif event_type == "usb_disconnected":
                disconnected_count += 1
            elif event_type == "usb_observed":
                observed_count += 1
            if event_type == "usb_observed" and volume.get("drive_letter"):
                mounted_device_count += 1
            if usb.get("device_type") in {"mtp", "phone"}:
                portable_device_count += 1
            if usb.get("device_type") == "mass_storage":
                usb_storage_count += 1
            by_device_type[str(usb.get("device_type") or "unknown")] += 1
            if usb.get("vendor"):
                by_vendor[str(usb.get("vendor"))] += 1
            if usb.get("vendor") or usb.get("product"):
                vendor_product_parsed_count += 1
            if usb.get("product"):
                by_product[str(usb.get("product"))] += 1
            if usb.get("serial"):
                serial_parsed_count += 1
                by_serial_presence["present"] += 1
            else:
                missing_serial += 1
                by_serial_presence["missing"] += 1
            if not usb.get("device_instance_id"):
                missing_device_instance_id += 1
            if not document.get("@timestamp"):
                missing_timestamp += 1
            if volume.get("drive_letter"):
                document["tags"] = sorted(set(document.get("tags") or []) | {"drive_letter_observed"})
                by_drive_letter[str(volume.get("drive_letter"))] += 1
            if volume.get("serial"):
                by_volume_serial[str(volume.get("serial"))] += 1
            if usb.get("vid") or usb.get("pid"):
                by_vid_pid[f"{usb.get('vid') or 'unknown'}:{usb.get('pid') or 'unknown'}"] += 1
        artifact_meta["ingest_audit"] = {
            "artifact": str(artifact_meta.get("name") or path.name),
            "parser": parser or "usb_registry",
            "records_read": len(rows),
            "records_parsed": len(documents),
            "events_indexed": len(documents),
            "setupapi_blocks_read": (raw_audit or {}).get("setupapi_blocks_read", 0),
            "setupapi_usb_blocks": (raw_audit or {}).get("setupapi_usb_blocks", 0),
            "usb_storage_count": usb_storage_count,
            "portable_device_count": portable_device_count,
            "mounted_device_count": mounted_device_count,
            "connected_count": connected_count,
            "disconnected_count": disconnected_count,
            "installed_count": installed_count,
            "observed_count": observed_count,
            "device_profiles_count": 0,
            "vendor_product_parsed_count": vendor_product_parsed_count,
            "serial_parsed_count": serial_parsed_count,
            "missing_timestamp": missing_timestamp,
            "missing_serial": missing_serial,
            "missing_device_instance_id": missing_device_instance_id,
            "by_event_type": dict(sorted(by_event_type.items())),
            "by_device_type": dict(sorted(by_device_type.items())),
            "by_vendor": dict(sorted(by_vendor.items())),
            "by_product": dict(sorted(by_product.items())),
            "by_vid_pid": dict(sorted(by_vid_pid.items())),
            "by_serial_presence": dict(sorted(by_serial_presence.items())),
            "by_drive_letter": dict(sorted(by_drive_letter.items())),
            "by_volume_serial": dict(sorted(by_volume_serial.items())),
            "correlation_usb_file_activity_count": 0,
            "possible_usb_exfiltration_count": 0,
            "parse_warnings": parse_warnings,
            "bulk_index_errors": 0,
        }
        return documents
    if artifact_meta.get("artifact_type") == "bits" or _looks_like_bits(path, artifact_meta):
        parser = str(artifact_meta.get("parser") or "").lower()
        parse_warnings: list[str] = []
        if parser in {"raw_qmgr_discovery", "bits_qmgr"} or path.suffix.lower() in {".dat", ".db"}:
            artifact_meta["ingest_audit"] = {
                "artifact": str(artifact_meta.get("name") or path.name),
                "parser_name": "bits_qmgr",
                "parser": "bits_qmgr",
                "source_file": str(artifact_meta.get("source_path") or path),
                "records_read": 0,
                "records_parsed": 0,
                "records_indexed": 0,
                "records_failed": 0,
                "parse_warnings": ["unsupported_bits_qmgr_raw"],
                "parser_errors": [],
                "parser_status": "detected_not_implemented",
                "bulk_index_errors": 0,
            }
            return []
        if parser in {"json", "jsonl", "bits_json", "bits_jsonl"} or path.suffix.lower() in {".json", ".jsonl"}:
            rows = parse_bits_json_file(path)
        elif parser in {"bitsadmin", "bits_raw"} or path.suffix.lower() == ".txt":
            rows = parse_bitsadmin_file(path)
        else:
            rows = parse_bits_csv_file(path)
        documents = [normalize_row(case_id, evidence_id, artifact_id, row, artifact_meta) for row in rows]
        suspicious_bits_jobs_count = notify_command_count = executable_download_count = script_download_count = direct_ip_url_count = cleartext_http_count = microsoft_update_jobs_count = missing_url_count = missing_local_path_count = missing_timestamp_count = 0
        jobs_read = transfers_read = 0
        by_state: dict[str, int] = defaultdict(int)
        by_owner: dict[str, int] = defaultdict(int)
        sample_records: list[dict] = []
        for document in documents:
            bits = document.get("bits", {}) or {}
            tags = set(document.get("tags") or [])
            event_type = str((document.get("event", {}) or {}).get("type") or "")
            if bits.get("state"):
                by_state[str(bits.get("state"))] += 1
            if bits.get("owner"):
                by_owner[str(bits.get("owner"))] += 1
            if bits.get("job_id") or bits.get("job_guid"):
                jobs_read += 1
            if event_type in {"file_downloaded", "download_started", "download_interrupted", "bits_job_observed"}:
                transfers_read += 1
            if not document.get("@timestamp"):
                missing_timestamp_count += 1
            if not bits.get("remote_url"):
                missing_url_count += 1
            if not bits.get("local_path"):
                missing_local_path_count += 1
            if "possible_bits_abuse" in tags or "suspicious_download" in tags:
                suspicious_bits_jobs_count += 1
            if bits.get("notify_cmd_line"):
                notify_command_count += 1
            if "executable_download" in tags:
                executable_download_count += 1
            if "script_download" in tags:
                script_download_count += 1
            if "direct_ip_url" in tags:
                direct_ip_url_count += 1
            if "cleartext_http" in tags:
                cleartext_http_count += 1
            if document.get("risk_score") == 0:
                microsoft_update_jobs_count += 1
            if len(sample_records) < 10:
                sample_records.append(
                    {
                        "source_file": bits.get("source_file"),
                        "job_id": bits.get("job_id"),
                        "job_guid": bits.get("job_guid"),
                        "display_name": bits.get("display_name"),
                        "owner": bits.get("owner"),
                        "state": bits.get("state"),
                        "remote_url": bits.get("remote_url"),
                        "local_path": bits.get("local_path"),
                        "notify_cmd_line": bits.get("notify_cmd_line"),
                        "risk_score": document.get("risk_score"),
                        "tags": list(document.get("tags") or []),
                        "suspicious_reasons": list(document.get("suspicious_reasons") or []),
                        "parser_status": bits.get("parser_status"),
                    }
                )
        artifact_meta["ingest_audit"] = {
            "artifact": str(artifact_meta.get("name") or path.name),
            "parser_name": parser or "bits_csv",
            "parser": parser or "bits_csv",
            "source_file": str(artifact_meta.get("source_path") or path),
            "records_read": len(rows),
            "records_parsed": len(documents),
            "records_indexed": len(documents),
            "records_failed": 0,
            "jobs_read": jobs_read,
            "transfers_read": transfers_read,
            "events_indexed": len(documents),
            "raw_qmgr_candidates": 0,
            "raw_qmgr_not_implemented": 0,
            "bits_evtx_candidates": 0,
            "bits_records_read": len(rows),
            "bits_records_indexed": len(documents),
            "by_state": dict(sorted(by_state.items())),
            "by_owner": dict(sorted(by_owner.items())),
            "by_event_type": dict(sorted(Counter(str((doc.get("event", {}) or {}).get("type") or "unknown") for doc in documents).items())),
            "by_extension": dict(sorted(Counter(str((doc.get("file", {}) or {}).get("extension") or "unknown") for doc in documents if (doc.get("file", {}) or {}).get("extension")).items())),
            "by_domain": dict(sorted(Counter(str((doc.get("network", {}) or {}).get("domain") or "unknown") for doc in documents if (doc.get("network", {}) or {}).get("domain")).items())),
            "suspicious_bits_jobs_count": suspicious_bits_jobs_count,
            "notify_command_count": notify_command_count,
            "executable_download_count": executable_download_count,
            "script_download_count": script_download_count,
            "direct_ip_url_count": direct_ip_url_count,
            "cleartext_http_count": cleartext_http_count,
            "microsoft_update_jobs_count": microsoft_update_jobs_count,
            "missing_url_count": missing_url_count,
            "missing_local_path_count": missing_local_path_count,
            "missing_timestamp_count": missing_timestamp_count,
            "sample_records": sample_records,
            "parse_warnings": parse_warnings,
            "parser_errors": [],
            "bulk_index_errors": 0,
        }
        return documents
    if artifact_meta.get("artifact_type") == "wmi" or _looks_like_wmi(path, artifact_meta):
        parser = str(artifact_meta.get("parser") or "").lower()
        parse_warnings: list[str] = []
        if parser in {"wmi_json", "wmi_jsonl"} or path.suffix.lower() in {".json", ".jsonl"}:
            rows = parse_wmi_json_file(path)
        elif parser == "autoruns":
            rows = parse_autoruns_wmi_csv_file(path)
        else:
            rows = parse_wmi_csv_file(path)
        documents = [normalize_row(case_id, evidence_id, artifact_id, row, artifact_meta) for row in rows]
        filters_read = consumers_read = bindings_read = namespaces_read = wmi_activity_events_read = suspicious_consumers_count = active_script_consumers_count = command_line_consumers_count = complete_persistence_chains_count = unresolved_bindings_count = encoded_powershell_count = download_command_count = missing_timestamp_count = 0
        suspicious_counts: Counter[str] = Counter()
        data_quality_counts: Counter[str] = Counter()
        sample_records: list[dict] = []
        for document in documents:
            wmi = document.get("wmi", {}) or {}
            tags = set(document.get("tags") or [])
            artifact_type = str(wmi.get("artifact_type") or "")
            if artifact_type == "wmi_event_filter":
                filters_read += 1
            elif artifact_type in {"wmi_command_line_consumer", "wmi_active_script_consumer", "wmi_consumer"}:
                consumers_read += 1
            elif artifact_type == "wmi_filter_to_consumer_binding":
                bindings_read += 1
            elif artifact_type == "wmi_namespace_observed":
                namespaces_read += 1
            elif artifact_type == "wmi_activity_event":
                wmi_activity_events_read += 1
            if "active_script_consumer" in tags:
                active_script_consumers_count += 1
            if "command_line_consumer" in tags:
                command_line_consumers_count += 1
            if "encoded_powershell" in tags:
                encoded_powershell_count += 1
            if "download_command" in tags:
                download_command_count += 1
            if "wmi_persistence_candidate" in tags and "wmi_binding" in tags:
                complete_persistence_chains_count += 1
            if "unresolved_binding" in (document.get("data_quality") or []):
                unresolved_bindings_count += 1
            if document.get("suspicious_reasons"):
                suspicious_consumers_count += 1
                for reason in document.get("suspicious_reasons") or []:
                    suspicious_counts[str(reason)] += 1
            for quality in document.get("data_quality") or []:
                data_quality_counts[str(quality)] += 1
            if not document.get("@timestamp"):
                missing_timestamp_count += 1
            if len(sample_records) < 10:
                sample_records.append(
                    {
                        "source_file": wmi.get("source_file"),
                        "artifact_type": artifact_type,
                        "namespace": wmi.get("namespace"),
                        "filter_name": wmi.get("filter_name"),
                        "consumer_name": wmi.get("consumer_name"),
                        "query": wmi.get("query"),
                        "command_line_template": wmi.get("command_line_template"),
                        "executable_path": wmi.get("executable_path"),
                        "script_preview": wmi.get("script_preview"),
                        "risk_score": document.get("risk_score"),
                        "tags": list(document.get("tags") or []),
                        "suspicious_reasons": list(document.get("suspicious_reasons") or []),
                        "parser_status": wmi.get("parser_status"),
                    }
                )
        artifact_meta["ingest_audit"] = {
            "artifact": str(artifact_meta.get("name") or path.name),
            "parser": parser or "wmi",
            "records_read": len(rows),
            "records_parsed": len(documents),
            "filters_read": filters_read,
            "consumers_read": consumers_read,
            "bindings_read": bindings_read,
            "namespaces_read": namespaces_read,
            "wmi_activity_events_read": wmi_activity_events_read,
            "events_indexed": len(documents),
            "records_indexed": len(documents),
            "raw_repository_candidates": 0,
            "raw_repository_not_implemented": 0,
            "suspicious_consumers_count": suspicious_consumers_count,
            "active_script_consumers_count": active_script_consumers_count,
            "command_line_consumers_count": command_line_consumers_count,
            "complete_persistence_chains_count": complete_persistence_chains_count,
            "unresolved_bindings_count": unresolved_bindings_count,
            "encoded_powershell_count": encoded_powershell_count,
            "download_command_count": download_command_count,
            "missing_timestamp_count": missing_timestamp_count,
            "suspicious_counts": dict(sorted(suspicious_counts.items())),
            "data_quality_counts": dict(sorted(data_quality_counts.items())),
            "sample_records": sample_records,
            "parse_warnings": parse_warnings,
            "parser_errors": [],
            "bulk_index_errors": 0,
        }
        return documents
    if artifact_meta.get("artifact_type") == "shellbags" or _looks_like_shellbags(path, artifact_meta):
        rows = list(read_shellbags_csv_rows(path))
        documents = [normalize_row(case_id, evidence_id, artifact_id, row, artifact_meta) for row in rows]
        shellbag_count = network_path_count = usb_path_count = cloud_path_count = control_panel_count = suspicious_count = missing_path_count = missing_timestamp = deleted_or_missing_candidate_count = 0
        user_counter: Counter[str] = Counter()
        root_counter: Counter[str] = Counter()
        network_host_counter: Counter[str] = Counter()
        for document in documents:
            shellbag = document.get("shellbag", {}) or {}
            tags = set(document.get("tags") or [])
            shellbag_count += 1
            if shellbag.get("is_network_path"):
                network_path_count += 1
            if shellbag.get("is_usb_path"):
                usb_path_count += 1
            if "cloud_sync" in tags:
                cloud_path_count += 1
            if shellbag.get("is_control_panel"):
                control_panel_count += 1
            if "suspicious" in tags:
                suspicious_count += 1
            if not shellbag.get("path"):
                missing_path_count += 1
            if not document.get("@timestamp"):
                missing_timestamp += 1
            if "deleted_or_missing_candidate" in tags:
                deleted_or_missing_candidate_count += 1
            if document.get("user", {}).get("name"):
                user_counter[str(document["user"]["name"])] += 1
            file_path = str((document.get("file", {}) or {}).get("path") or "")
            if file_path:
                root_counter[file_path.split("\\", 2)[0]] += 1
            host_name = str((document.get("network", {}) or {}).get("destination_hostname") or "")
            if host_name:
                network_host_counter[host_name] += 1
        artifact_meta["ingest_audit"] = {
            "artifact": str(artifact_meta.get("name") or path.name),
            "parser": "sbecmd",
            "records_read": len(rows),
            "records_parsed": len(documents),
            "events_indexed": len(documents),
            "shellbag_count": shellbag_count,
            "network_path_count": network_path_count,
            "usb_path_count": usb_path_count,
            "cloud_path_count": cloud_path_count,
            "control_panel_count": control_panel_count,
            "suspicious_count": suspicious_count,
            "missing_path_count": missing_path_count,
            "missing_timestamp": missing_timestamp,
            "deleted_or_missing_candidate_count": deleted_or_missing_candidate_count,
            "top_users": [name for name, _ in user_counter.most_common(10)],
            "top_roots": [name for name, _ in root_counter.most_common(10)],
            "top_network_hosts": [name for name, _ in network_host_counter.most_common(10)],
            "bulk_index_errors": 0,
            "parse_warnings": [],
        }
        return documents
    if artifact_meta.get("artifact_type") == "jumplist" or _looks_like_jlecmd(path, artifact_meta):
        parser = str(artifact_meta.get("parser") or "").lower()
        parse_warnings: list[str] = []
        raw_audit: dict | None = None
        if parser == "raw_automatic_destinations" or path.suffix.lower() == ".automaticdestinations-ms":
            rows, parse_warnings, raw_audit = parse_automatic_destinations_file(
                path,
                source_path=str(artifact_meta.get("source_path") or artifact_meta.get("velociraptor_original_path") or path),
                app_id=str(artifact_meta.get("jumplist_app_id") or artifact_meta.get("app_id") or "") or None,
                user=str(artifact_meta.get("user") or "") or None,
            )
        elif parser == "raw_custom_destinations" or path.suffix.lower() == ".customdestinations-ms":
            rows, parse_warnings, raw_audit = parse_custom_destinations_file(
                path,
                source_path=str(artifact_meta.get("source_path") or artifact_meta.get("velociraptor_original_path") or path),
                app_id=str(artifact_meta.get("jumplist_app_id") or artifact_meta.get("app_id") or "") or None,
                user=str(artifact_meta.get("user") or "") or None,
            )
        else:
            rows = list(read_jumplist_csv_rows(path))
        documents = [normalize_row(case_id, evidence_id, artifact_id, row, artifact_meta) for row in rows]
        jumplist_count = automatic_destinations_count = custom_destinations_count = app_id_count = network_path_count = usb_path_count = cloud_path_count = suspicious_count = missing_path_count = missing_timestamp = downloaded_file_opened_count = deleted_file_opened_count = 0
        missing_effective_path_count = source_file_mtime_used_count = app_id_mapped_count = app_id_unknown_count = skipped_low_value_records = 0
        app_id_counter: Counter[str] = Counter()
        app_name_counter: Counter[str] = Counter()
        extension_counter: Counter[str] = Counter()
        for document in documents:
            jumplist = document.get("jumplist", {}) or {}
            tags = set(document.get("tags") or [])
            jumplist_count += 1
            if jumplist.get("destination_type") == "automatic":
                automatic_destinations_count += 1
            if jumplist.get("destination_type") == "custom":
                custom_destinations_count += 1
            if jumplist.get("app_id"):
                app_id_count += 1
                app_id_counter[str(jumplist["app_id"])] += 1
            if jumplist.get("app_name"):
                app_name_counter[str(jumplist["app_name"])] += 1
                if str(jumplist.get("app_name") or "").strip().lower() != str(jumplist.get("app_id") or "").strip().lower():
                    app_id_mapped_count += 1
                else:
                    app_id_unknown_count += 1
            elif jumplist.get("app_id"):
                app_id_unknown_count += 1
            if (document.get("network", {}) or {}).get("path"):
                network_path_count += 1
            if "usb_path" in tags:
                usb_path_count += 1
            if "cloud_sync" in tags:
                cloud_path_count += 1
            if "suspicious" in tags:
                suspicious_count += 1
            if not jumplist.get("effective_path"):
                missing_path_count += 1
                missing_effective_path_count += 1
            if not document.get("@timestamp"):
                missing_timestamp += 1
            if document.get("timestamp_precision") == "source_file_mtime":
                source_file_mtime_used_count += 1
            if "browser_download_correlated" in tags:
                downloaded_file_opened_count += 1
            if "recycle_bin_correlated" in tags:
                deleted_file_opened_count += 1
            if (document.get("file", {}) or {}).get("extension"):
                extension_counter[str(document["file"]["extension"])] += 1
        artifact_meta["ingest_audit"] = {
            "artifact": path.name,
            "parser": parser or "jlecmd",
            "records_read": len(rows),
            "records_parsed": len(documents),
            "events_indexed": len(documents),
            "jumplist_count": jumplist_count,
            "automatic_destinations_count": automatic_destinations_count,
            "custom_destinations_count": custom_destinations_count,
            "app_id_count": app_id_count,
            "network_path_count": network_path_count,
            "usb_path_count": usb_path_count,
            "cloud_path_count": cloud_path_count,
            "suspicious_count": suspicious_count,
            "missing_path_count": missing_path_count,
            "missing_effective_path_count": missing_effective_path_count,
            "missing_timestamp": missing_timestamp,
            "source_file_mtime_used_count": source_file_mtime_used_count,
            "downloaded_file_opened_count": downloaded_file_opened_count,
            "deleted_file_opened_count": deleted_file_opened_count,
            "app_id_mapped_count": app_id_mapped_count,
            "app_id_unknown_count": app_id_unknown_count,
            "top_app_ids": dict(app_id_counter.most_common(10)),
            "top_app_names": dict(app_name_counter.most_common(10)),
            "top_extensions": dict(extension_counter.most_common(10)),
            "bulk_index_errors": 0,
            "parse_warnings": parse_warnings,
        }
        if raw_audit:
            artifact_meta["ingest_audit"].update(raw_audit)
        return documents
    if artifact_meta.get("artifact_type") in {"defender", "detection"} or looks_like_defender_artifact(path):
        parser = str(artifact_meta.get("parser") or "").lower()
        lower_name = path.name.lower()
        rows: list[dict]
        parse_warnings: list[str] = []
        mplog_audit: dict | None = None
        parser_errors: list[str] = []
        delimiter_note: str | None = None
        if parser in {"defender_json", "defender_jsonl", "json"} or path.suffix.lower() in {".json", ".jsonl"}:
            rows = read_defender_json_rows(path)
        elif parser in {"defender_csv", "csv"} or path.suffix.lower() in {".csv", ".tsv", ".txt"}:
            rows, csv_audit = read_defender_csv_rows(path)
            delimiter_note = csv_audit.get("delimiter_note")
            parse_warnings.extend(list(csv_audit.get("warnings") or []))
            parser_errors.extend(list(csv_audit.get("errors") or []))
        elif parser in {"defender_mplog"} or "mplog" in lower_name or path.suffix.lower() == ".log":
            rows, mplog_audit = parse_mplog_file(path)
        elif parser in {"defender_quarantine_metadata"}:
            rows = []
            parse_warnings.append("unsupported_defender_source")
        else:
            rows, parse_warnings = parse_detection_history_file(path)
        documents = [
            normalize_row(
                case_id,
                evidence_id,
                artifact_id,
                row,
                {
                    **artifact_meta,
                    "defender_delimiter_note": delimiter_note,
                    "defender_parse_warnings": parse_warnings,
                },
            )
            for row in rows
        ]
        threat_counter: Counter[str] = Counter()
        action_counter: Counter[str] = Counter()
        path_counter: Counter[str] = Counter()
        event_type_counter: Counter[str] = Counter()
        severity_counter: Counter[str] = Counter()
        category_counter: Counter[str] = Counter()
        status_counter: Counter[str] = Counter()
        remediation_counter: Counter[str] = Counter()
        blocked_count = quarantined_count = removed_count = allowed_count = remediation_failed_count = high_severity_count = pua_count = hacktool_count = 0
        missing_timestamp = missing_threat_name = missing_path = 0
        for document in documents:
            detection = document.get("detection", {}) or {}
            event_action = str((document.get("event", {}) or {}).get("action") or "")
            event_type = str((document.get("event", {}) or {}).get("type") or "")
            threat_name = str(detection.get("threat_name") or "").strip()
            category = str(detection.get("category") or "").strip().lower()
            threat_counter.update([threat_name] if threat_name else [])
            action_counter.update([event_action] if event_action else [])
            path_counter.update([str(detection.get("path"))] if detection.get("path") else [])
            event_type_counter.update([event_type] if event_type else [])
            severity_counter.update([str(detection.get("severity") or "")] if detection.get("severity") else [])
            category_counter.update([category] if category else [])
            status_counter.update([str(detection.get("status") or "")] if detection.get("status") else [])
            remediation_counter.update([str(detection.get("remediation_action") or "")] if detection.get("remediation_action") else [])
            if not document.get("@timestamp"):
                missing_timestamp += 1
            if not threat_name:
                missing_threat_name += 1
            if not detection.get("path"):
                missing_path += 1
            if event_action == "threat_blocked":
                blocked_count += 1
            elif event_action == "threat_quarantined":
                quarantined_count += 1
            elif event_action in {"threat_removed", "remediation_completed"}:
                removed_count += 1
            elif event_action == "threat_allowed":
                allowed_count += 1
            elif event_action == "remediation_failed":
                remediation_failed_count += 1
            if str(detection.get("severity") or "") in {"high", "critical"}:
                high_severity_count += 1
            if "pua" in category:
                pua_count += 1
            if "hacktool" in category or "hacktool" in threat_name.lower():
                hacktool_count += 1
        artifact_meta["ingest_audit"] = {
            "artifact": str(artifact_meta.get("name") or path.name),
            "parser": parser or "defender_detection_history",
            "records_read": len(rows),
            "records_parsed": len(documents),
            "events_indexed": len(documents),
            "detection_count": len(documents),
            "mplog_lines_read": (mplog_audit or {}).get("lines_read", 0),
            "mplog_interesting_lines": (mplog_audit or {}).get("interesting_lines", 0),
            "quarantine_count": quarantined_count,
            "blocked_count": blocked_count,
            "quarantined_count": quarantined_count,
            "removed_count": removed_count,
            "allowed_count": allowed_count,
            "remediation_failed_count": remediation_failed_count,
            "high_severity_count": high_severity_count,
            "pua_count": pua_count,
            "hacktool_count": hacktool_count,
            "missing_timestamp": missing_timestamp,
            "missing_threat_name": missing_threat_name,
            "missing_path": missing_path,
            "by_threat_name": dict(threat_counter.most_common(20)),
            "by_action": dict(action_counter.most_common(20)),
            "by_event_type": dict(event_type_counter.most_common(20)),
            "by_severity": dict(severity_counter.most_common(20)),
            "by_category": dict(category_counter.most_common(20)),
            "by_status": dict(status_counter.most_common(20)),
            "by_remediation_action": dict(remediation_counter.most_common(20)),
            "top_threats": [name for name, _ in threat_counter.most_common(10)],
            "top_actions": [name for name, _ in action_counter.most_common(10)],
            "top_paths": [name for name, _ in path_counter.most_common(10)],
            "delimiter_fallback_count": 1 if delimiter_note == "delimiter_fallback_used" else 0,
            "bulk_index_errors": 0,
            "parse_warnings": parse_warnings,
            "parser_errors": parser_errors,
        }
        return documents
    if _looks_like_srum(path, artifact_meta):
        rows = read_records(path)
        documents = [normalize_row(case_id, evidence_id, artifact_id, row, artifact_meta) for row in rows]
        parser_name = str(artifact_meta.get("parser") or "").strip().lower()
        audit_parser = (
            "srum_jsonl" if path.suffix.lower() == ".jsonl"
            else "srum_json" if path.suffix.lower() == ".json"
            else "srum_csv" if path.suffix.lower() == ".csv"
            else "srum_db" if parser_name == "srum_db"
            else "srum_raw"
        )
        app_counter: Counter[str] = Counter()
        user_counter: Counter[str] = Counter()
        table_counter: Counter[str] = Counter()
        event_type_counter: Counter[str] = Counter()
        direction_counter: Counter[str] = Counter()
        profile_counter: Counter[str] = Counter()
        interface_counter: Counter[str] = Counter()
        total_bytes_sent = 0
        total_bytes_received = 0
        high_upload_count = 0
        upload_heavy_count = 0
        remote_access_tool_count = 0
        lolbin_network_count = 0
        scripting_process_network_count = 0
        user_writable_app_network_count = 0
        suspicious_count = 0
        missing_timestamp = 0
        missing_application = 0
        missing_bytes = 0
        zero_bytes_count = 0
        network_usage_count = 0
        connectivity_count = 0
        application_resource_count = 0
        energy_usage_count = 0
        generic_srum_count = 0
        for document in documents:
            event_type = str((document.get("event", {}) or {}).get("type") or "")
            event_type_counter.update([event_type] if event_type else [])
            srum = document.get("srum", {}) or {}
            table_counter.update([str(srum.get("table") or srum.get("artifact_type") or "unknown")])
            if event_type == "network_usage":
                network_usage_count += 1
            elif event_type == "network_connectivity_observed":
                connectivity_count += 1
            elif event_type == "app_resource_usage":
                application_resource_count += 1
            elif event_type == "energy_usage":
                energy_usage_count += 1
            else:
                generic_srum_count += 1
            app_name = str(
                srum.get("app_name")
                or (document.get("network", {}) or {}).get("application")
                or (document.get("process", {}) or {}).get("name")
                or ""
            ).strip()
            user_sid = str((document.get("user", {}) or {}).get("sid") or srum.get("user_sid") or "").strip()
            if app_name:
                app_counter[app_name] += 1
            else:
                missing_application += 1
            if user_sid:
                user_counter[user_sid] += 1
            network_profile = str(srum.get("network_profile") or "").strip()
            interface_value = str(srum.get("interface_guid") or srum.get("interface_luid") or "").strip()
            direction = str((document.get("network", {}) or {}).get("direction") or "unknown").strip()
            if network_profile:
                profile_counter[network_profile] += 1
            if interface_value:
                interface_counter[interface_value] += 1
            if direction:
                direction_counter[direction] += 1
            bytes_sent = (document.get("network", {}) or {}).get("bytes_sent")
            bytes_received = (document.get("network", {}) or {}).get("bytes_received")
            if bytes_sent is None and bytes_received is None:
                missing_bytes += 1
            elif int(bytes_sent or 0) == 0 and int(bytes_received or 0) == 0:
                zero_bytes_count += 1
            total_bytes_sent += int(bytes_sent or 0)
            total_bytes_received += int(bytes_received or 0)
            tags = set(document.get("tags") or [])
            if not document.get("@timestamp"):
                missing_timestamp += 1
            if {"suspicious", "possible_exfiltration", "high_upload", "remote_access_tool", "file_transfer_tool", "lolbin_network", "scripting_process", "user_writable_app", "upload_heavy"} & tags:
                suspicious_count += 1
            if "high_upload" in tags:
                high_upload_count += 1
            if "upload_heavy" in tags:
                upload_heavy_count += 1
            if "remote_access_tool" in tags:
                remote_access_tool_count += 1
            if "lolbin_network" in tags:
                lolbin_network_count += 1
            if "scripting_process" in tags:
                scripting_process_network_count += 1
            if "user_writable_app" in tags:
                user_writable_app_network_count += 1
        artifact_meta["ingest_audit"] = {
            "artifact": str(artifact_meta.get("name") or path.name),
            "parser": audit_parser,
            "records_read": len(rows),
            "records_parsed": len(documents),
            "events_indexed": len(documents),
            "network_usage_count": network_usage_count,
            "connectivity_count": connectivity_count,
            "application_resource_count": application_resource_count,
            "energy_usage_count": energy_usage_count,
            "generic_srum_count": generic_srum_count,
            "suspicious_count": suspicious_count,
            "high_upload_count": high_upload_count,
            "upload_heavy_count": upload_heavy_count,
            "remote_access_tool_count": remote_access_tool_count,
            "lolbin_network_count": lolbin_network_count,
            "scripting_process_network_count": scripting_process_network_count,
            "user_writable_app_network_count": user_writable_app_network_count,
            "missing_timestamp": missing_timestamp,
            "missing_application": missing_application,
            "missing_bytes": missing_bytes,
            "zero_bytes_count": zero_bytes_count,
            "top_applications": [name for name, _ in app_counter.most_common(10)],
            "top_users": [name for name, _ in user_counter.most_common(10)],
            "by_table": dict(table_counter.most_common(20)),
            "by_event_type": dict(event_type_counter.most_common(20)),
            "by_direction": dict(direction_counter.most_common(20)),
            "by_network_profile": dict(profile_counter.most_common(20)),
            "by_interface": dict(interface_counter.most_common(20)),
            "total_bytes_sent": total_bytes_sent,
            "total_bytes_received": total_bytes_received,
            "total_bytes": total_bytes_sent + total_bytes_received,
            "bulk_index_errors": 0,
        }
        return documents
    if str(artifact_meta.get("artifact_type") or "").lower() == "srum" and str(artifact_meta.get("parser") or "").lower() == "srum_db":
        artifact_meta["ingest_audit"] = {
            "artifact": str(artifact_meta.get("name") or path.name),
            "parser": "srum_db",
            "records_read": 0,
            "records_parsed": 0,
            "events_indexed": 0,
            "parse_warnings": ["unsupported_srum_db_raw"],
            "parser_status": "detected_not_implemented",
            "bulk_index_errors": 0,
        }
        return []
    if _looks_like_amcache(path, artifact_meta) or _looks_like_shimcache(path, artifact_meta) or _looks_like_srum(path, artifact_meta):
        rows = read_records(path)
        return [normalize_row(case_id, evidence_id, artifact_id, row, artifact_meta) for row in rows]
    if artifact_meta.get("artifact_type") == "browser" or looks_like_browser_artifact(path, list(_csv_headers(path))):
        rows = read_browser_records(path)
        audit = BrowserAudit()
        documents = []
        for row in rows:
            document = normalize_browser_event(base_document(case_id, evidence_id, artifact_id, row, artifact_meta), row, artifact_meta, audit)
            document = _apply_suspicious_tags(document)
            document["search_text"] = build_search_text(document)
            documents.append(_apply_data_quality(document))
        artifact_meta["ingest_audit"] = audit.as_dict(artifact_name=str(artifact_meta.get("name") or path.name))
        return documents
    rows = read_records(path)
    return [normalize_row(case_id, evidence_id, artifact_id, row, artifact_meta) for row in rows]
