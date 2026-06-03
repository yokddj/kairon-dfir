from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path, PureWindowsPath
import re

from app.analysis.suspicious import is_suspicious_double_extension
from app.ingest.eztools.lecmd import (
    ARGUMENT_TOKENS,
    DOCUMENT_EXTENSIONS,
    EXECUTABLE_EXTENSIONS,
    SCRIPT_EXTENSIONS,
    _extract_unc_host,
    _normalize_value,
    is_lnk_partial_or_shell_target,
    is_lnk_useful_path,
)
from app.ingest.host_detection import normalize_hostname
from app.ingest.jumplists.appid_map import resolve_app_id_name


JUMPLIST_NAME_HINTS = (
    "jlecmd_output",
    "jlecmd",
    "jumplist",
    "jumplists",
    "automaticdestinations",
    "customdestinations",
    "destinations",
)
JUMPLIST_HEADER_HINTS = {
    "sourcefile",
    "appid",
    "appiddescription",
    "entrynumber",
    "creationtime",
    "lastmodified",
    "lastaccessed",
    "targetcreated",
    "targetmodified",
    "targetaccessed",
    "targetpath",
    "localpath",
    "commonpath",
    "relativepath",
    "arguments",
    "workingdirectory",
    "drivetype",
    "volumeserialnumber",
    "machineid",
}
CLOUD_TOKENS = ("\\onedrive\\", "\\dropbox\\", "\\google drive\\", "\\box\\", "\\mega\\", "\\nextcloud\\")
SUSPICIOUS_TOKENS = ("mimikatz", "rclone", "anydesk", "teamviewer", "ngrok", "payload", "staging", "exfil", "dump", "credentials", "lsass", "runme")
USER_WRITABLE_TOKENS = ("\\downloads\\", "\\desktop\\", "\\documents\\", "\\appdata\\", "\\temp\\", "\\users\\public\\", "\\programdata\\")
HIGH_RISK_USER_WRITABLE_TOKENS = ("\\appdata\\local\\temp\\", "\\appdata\\roaming\\", "\\users\\public\\", "\\programdata\\", "\\$recycle.bin\\")


def canonicalize_header(value: object) -> str:
    return re.sub(r"[^a-z0-9]+", "", str(value).strip().lower())


def looks_like_jumplist_artifact(path: Path, headers: list[str] | None = None) -> bool:
    if path.suffix.lower() != ".csv":
        return False
    lower_name = path.name.lower()
    if "bits" in lower_name or "qmgr" in lower_name:
        return False
    header_set = {canonicalize_header(header) for header in (headers or []) if header}
    if {"jobid", "jobguid", "remoteurl", "localpath", "notifycmdline", "bytestransferred"} & header_set:
        return False
    if any(token in lower_name for token in JUMPLIST_NAME_HINTS):
        return True
    return len(header_set & JUMPLIST_HEADER_HINTS) >= 5


def normalize_windows_path(value: str | None) -> str | None:
    normalized = _normalize_value(value)
    if not normalized:
        return None
    return normalized.replace("/", "\\").strip('"')


def basename_windows(path: str | None) -> str | None:
    normalized = normalize_windows_path(path)
    if not normalized:
        return None
    try:
        return PureWindowsPath(normalized).name or normalized
    except Exception:  # noqa: BLE001
        return Path(normalized.replace("\\", "/")).name or normalized


def suffix_windows(path: str | None) -> str | None:
    normalized = normalize_windows_path(path)
    if not normalized:
        return None
    try:
        suffix = PureWindowsPath(normalized).suffix.lower()
        return suffix or None
    except Exception:  # noqa: BLE001
        suffix = Path(normalized.replace("\\", "/")).suffix.lower()
        return suffix or None


def infer_jumplist_user(path: str | None) -> str | None:
    normalized = normalize_windows_path(path)
    if not normalized:
        return None
    match = re.search(r"\\users\\(?P<user>[^\\]+)\\", normalized, re.IGNORECASE)
    return match.group("user") if match else None


def source_file_mtime_iso(path: Path) -> str | None:
    try:
        return datetime.fromtimestamp(path.stat().st_mtime, tz=UTC).isoformat()
    except Exception:  # noqa: BLE001
        return None


def _compose_unc(network_path: str | None, share_name: str | None, hostname: str | None) -> str | None:
    net = normalize_windows_path(network_path)
    if net and net.startswith("\\\\"):
        return net
    share = _normalize_value(share_name)
    host = _normalize_value(hostname)
    if host and share:
        share_clean = share.lstrip("\\/")
        host_clean = host.strip("\\/")
        return f"\\\\{host_clean}\\{share_clean}"
    return None


def select_jumplist_effective_path(row: dict) -> dict[str, object]:
    raw = {str(key): value for key, value in row.items()}

    def pick(*keys: str) -> str | None:
        for key in keys:
            value = normalize_windows_path(raw.get(key))
            if value:
                return value
        return None

    network_path = _compose_unc(
        pick("NetworkPath", "NetName"),
        pick("ShareName"),
        pick("Hostname", "DeviceName"),
    )
    candidates: list[tuple[str, str | None, bool]] = [
        ("local_path", pick("LocalPath"), False),
        ("target_path", pick("TargetPath"), False),
        ("target_id_absolute_path", pick("TargetIDAbsolutePath"), False),
        ("common_path", pick("CommonPath"), False),
        ("network_path", network_path, False),
        ("relative_path", pick("RelativePath"), True),
        ("path", pick("Path", "FilePath", "FullPath"), False),
    ]
    for source, value, allow_partial in candidates:
        if not value:
            continue
        partial = is_lnk_partial_or_shell_target(value)
        useful = is_lnk_useful_path(value) or value.startswith("\\\\")
        if useful or (allow_partial and not partial):
            return {
                "effective_path": value,
                "effective_path_source": source,
                "display_name": basename_windows(value) or value.rstrip("\\/") or value,
                "is_partial_path": partial,
                "is_shell_target": partial and not useful,
            }

    fallback = next((value for _, value, _ in candidates if value and not is_lnk_partial_or_shell_target(value)), None)
    fallback_source = next((source for source, value, _ in candidates if value and not is_lnk_partial_or_shell_target(value)), None)
    generic_fallback = next((value for _, value, _ in candidates if value), None)
    return {
        "effective_path": fallback,
        "effective_path_source": fallback_source,
        "display_name": basename_windows(fallback or generic_fallback) or (str(fallback or generic_fallback).rstrip("\\/") if (fallback or generic_fallback) else None),
        "is_partial_path": is_lnk_partial_or_shell_target(generic_fallback),
        "is_shell_target": is_lnk_partial_or_shell_target(generic_fallback),
        "generic_target_path": bool(generic_fallback and is_lnk_partial_or_shell_target(generic_fallback)),
    }


def classify_jumplist_path(path: str | None, row: dict) -> dict:
    normalized = normalize_windows_path(path)
    lower_path = (normalized or "").lower()
    args = str(row.get("Arguments") or "").lower()
    drive_type = str(row.get("DriveType") or "").lower()
    tags = {"jumplist", "recent_file", "file_access"}
    reasons: list[str] = []
    risk = 8
    is_network = False
    is_usb = False
    is_cloud = False
    host = None
    share = None
    device_name = _normalize_value(row.get("DeviceName"))
    artifact_type = "jumplist_entry"

    if normalized and normalized.startswith("\\\\"):
        is_network = True
        host = _extract_unc_host(normalized)
        parts = normalized.lstrip("\\").split("\\")
        share = parts[1] if len(parts) > 1 else None
        tags.add("network_path")
        reasons.append("JumpList references network share")
        artifact_type = "jumplist_network_item"
        risk = max(risk, 28)

    if "removable" in drive_type or ("usb" in drive_type):
        is_usb = True
        tags.add("usb_path")
        tags.add("removable_media")
        artifact_type = "jumplist_usb_item"
        reasons.append("JumpList references removable/USB path")
        risk = max(risk, 30)

    if any(token in lower_path for token in CLOUD_TOKENS):
        is_cloud = True
        tags.add("cloud_sync")
        reasons.append("JumpList references cloud sync folder")
        risk = max(risk, 24)

    if any(token in lower_path for token in USER_WRITABLE_TOKENS):
        tags.add("user_writable_path")
    if "\\downloads\\" in lower_path:
        tags.add("downloaded_location")

    ext = suffix_windows(normalized)
    is_script = ext in SCRIPT_EXTENSIONS
    is_executable = ext in EXECUTABLE_EXTENSIONS
    is_document = ext in DOCUMENT_EXTENSIONS
    has_suspicious_keyword = any(token in lower_path for token in SUSPICIOUS_TOKENS)
    high_risk_user_writable = any(token in lower_path for token in HIGH_RISK_USER_WRITABLE_TOKENS)
    if is_script or is_executable:
        tags.update({"suspicious", "suspicious_path"})
        tags.add("file_opened")
        tags.add("script" if is_script else "executable")
        reasons.append("JumpList references executable/script")
        risk = max(risk, 52)
        if high_risk_user_writable:
            reasons.append("JumpList references executable/script in high-risk user-writable path")
            risk = max(risk, 64)
    elif normalized:
        tags.add("recent_file")
    if is_document:
        tags.add("document")
        risk = max(risk, 10 if "downloaded_location" in tags else 8)

    if is_suspicious_double_extension(lower_path):
        tags.update({"suspicious", "suspicious_path", "double_extension"})
        reasons.append("JumpList references double extension file")
        risk = max(risk, 75)

    if has_suspicious_keyword:
        tags.update({"suspicious", "suspicious_path"})
        reasons.append("JumpList references suspicious tool/payload name")
        risk = max(risk, 72)

    suspicious_argument_reason = None
    for token, reason in ARGUMENT_TOKENS.items():
        if token in args:
            suspicious_argument_reason = "JumpList arguments contain suspicious command pattern"
            break
    if suspicious_argument_reason:
        tags.update({"suspicious", "suspicious_command", "suspicious_path"})
        reasons.append(suspicious_argument_reason)
        risk = max(risk, 58)

    return {
        "artifact_type": artifact_type,
        "tags": sorted(tags),
        "reasons": reasons,
        "risk": risk,
        "is_network_path": is_network,
        "is_usb_path": is_usb,
        "is_cloud_path": is_cloud,
        "destination_hostname": normalize_hostname(host) if host else None,
        "share_name": share,
        "device_name": device_name,
    }


__all__ = [
    "basename_windows",
    "classify_jumplist_path",
    "infer_jumplist_user",
    "looks_like_jumplist_artifact",
    "normalize_windows_path",
    "resolve_app_id_name",
    "select_jumplist_effective_path",
    "source_file_mtime_iso",
    "suffix_windows",
]
