from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path, PureWindowsPath
import re

from dateutil import parser as date_parser


SHELLBAGS_NAME_HINTS = (
    "sbecmd_output",
    "sbecmd",
    "shellbags",
    "shellbags",
    "shellbag",
    "shell_bags",
)

SHELLBAGS_HEADER_HINTS = {
    "bagpath",
    "absolutepath",
    "path",
    "fullpath",
    "itempath",
    "shellitempath",
    "folderpath",
    "shelltype",
    "slot",
    "nodeslot",
    "mruposition",
    "lastwritetime",
    "createdon",
    "modifiedon",
    "accessedon",
    "firstinteracted",
    "lastinteracted",
    "mftentry",
    "mftsequencenumber",
    "extensionblock",
    "sourcefile",
    "hivepath",
}

CLOUD_TOKENS = ("\\onedrive\\", "\\dropbox\\", "\\google drive\\", "\\box\\", "\\mega\\", "\\nextcloud\\")
SUSPICIOUS_TOKENS = ("mimikatz", "rclone", "payload", "tools", "exfil", "credentials", "dump", "lsass", "anydesk", "teamviewer", "ngrok", "staging")
USER_WRITABLE_TOKENS = ("\\downloads\\", "\\desktop\\", "\\appdata\\", "\\temp\\", "\\users\\public\\", "\\programdata\\")
CONTROL_PANEL_TOKENS = ("control panel", "this pc", "my computer")
UNC_RE = re.compile(r"^(?:\\\\|//)(?P<host>[^\\/]+)[\\/](?P<share>[^\\/]+)", re.IGNORECASE)
USER_FROM_USERS_RE = re.compile(r"\\users\\(?P<user>[^\\]+)\\", re.IGNORECASE)


def clean_text(value: object | None) -> str | None:
    if value is None:
        return None
    text = str(value).strip().strip("\x00")
    if text in {"", "-", "--", "N/A", "n/a", "null", "None"}:
        return None
    return text


def canonicalize_header(value: object) -> str:
    return re.sub(r"[^a-z0-9]+", "", str(value).strip().lower())


def looks_like_shellbags_artifact(path: Path, headers: list[str] | None = None) -> bool:
    if path.suffix.lower() != ".csv":
        return False
    lower_name = path.name.lower()
    if any(token in lower_name for token in SHELLBAGS_NAME_HINTS):
        return True
    header_set = {canonicalize_header(header) for header in (headers or []) if header}
    return len(header_set & SHELLBAGS_HEADER_HINTS) >= 4


def normalize_windows_path(value: str | None) -> str | None:
    text = clean_text(value)
    if not text:
        return None
    return text.replace("/", "\\").strip('"')


def basename_windows(path: str | None) -> str | None:
    normalized = normalize_windows_path(path)
    if not normalized:
        return None
    try:
        return PureWindowsPath(normalized).name or normalized
    except Exception:  # noqa: BLE001
        return Path(normalized.replace("\\", "/")).name or normalized


def infer_user_from_windows_path(path: str | None) -> str | None:
    normalized = normalize_windows_path(path)
    if not normalized:
        return None
    match = USER_FROM_USERS_RE.search(normalized)
    return match.group("user") if match else None


def parse_shellbags_timestamp(value: object | None) -> str | None:
    text = clean_text(value)
    if not text:
        return None
    try:
        parsed = date_parser.parse(text)
    except Exception:  # noqa: BLE001
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=UTC)
    return parsed.isoformat()


def source_file_mtime_iso(path: Path) -> str:
    return datetime.fromtimestamp(path.stat().st_mtime, tz=UTC).isoformat()


def unc_details(path: str | None) -> tuple[str | None, str | None]:
    normalized = normalize_windows_path(path)
    if not normalized:
        return None, None
    match = UNC_RE.match(normalized)
    if not match:
        return None, None
    return match.group("host"), match.group("share")


def _boolish(value: object | None) -> bool | None:
    text = clean_text(value)
    if not text:
        return None
    lowered = text.lower()
    if lowered in {"true", "yes", "1", "y"}:
        return True
    if lowered in {"false", "no", "0", "n"}:
        return False
    return None


def classify_shellbag_path(path: str | None, row: dict) -> dict:
    normalized = normalize_windows_path(path)
    lower_path = (normalized or "").lower()
    row_blob = " ".join(str(value) for value in row.values() if value not in (None, "")).lower()
    tags = {"shellbags", "folder_access", "folder_observed"}
    reasons: list[str] = []
    artifact_type = "shellbag_folder"
    share_host = None
    share_name = None
    drive_type = None
    is_deleted = _boolish(row.get("IsDeleted"))
    is_network_path = False
    is_usb_path = False
    is_control_panel = False
    risk = 10

    share_host, share_name = unc_details(normalized)
    if share_host and share_name:
        is_network_path = True
        artifact_type = "shellbag_network_folder"
        tags.add("network_path")
        reasons.append("Shellbag references network share")
        risk = max(risk, 30)

    if normalized and normalized.startswith("::") or any(token in lower_path for token in CONTROL_PANEL_TOKENS) or "::{" in lower_path:
        is_control_panel = True
        artifact_type = "shellbag_control_panel"
        tags.add("control_panel")

    removable_tokens = ("removable", "usb", "usbstor")
    if normalized and re.match(r"^[D-Z]:\\", normalized, re.IGNORECASE) and any(token in row_blob for token in removable_tokens):
        is_usb_path = True
    elif any(token in row_blob for token in removable_tokens) and normalized:
        is_usb_path = True
    if is_usb_path:
        artifact_type = "shellbag_usb_folder"
        tags.add("usb_path")
        tags.add("removable_media")
        drive_type = "removable"
        reasons.append("Shellbag references removable/USB path")
        risk = max(risk, 34)

    if any(token in lower_path for token in CLOUD_TOKENS):
        tags.add("cloud_sync")
        reasons.append("Shellbag references cloud sync folder")
        risk = max(risk, 26)

    if any(token in lower_path for token in USER_WRITABLE_TOKENS):
        tags.add("user_writable_path")

    if any(token in lower_path for token in SUSPICIOUS_TOKENS):
        tags.add("suspicious")
        tags.add("suspicious_path")
        reasons.append("Shellbag references suspicious tool/payload folder")
        risk = max(risk, 60)
    elif "user_writable_path" in tags and any(token in lower_path for token in ("payload", "temp", "tools", "dump")):
        tags.add("suspicious")
        tags.add("suspicious_path")
        reasons.append("Shellbag references user-writable suspicious path")
        risk = max(risk, 46)

    if is_deleted or any(token in row_blob for token in ("deleted", "missing", "notfound")):
        tags.add("deleted_or_missing_candidate")
        reasons.append("Shellbag entry appears to reference deleted or missing folder")
        risk = max(risk, 28)

    return {
        "artifact_type": artifact_type,
        "tags": sorted(tags),
        "reasons": reasons,
        "risk": risk,
        "is_network_path": is_network_path,
        "is_usb_path": is_usb_path,
        "is_control_panel": is_control_panel,
        "network_host": share_host,
        "share_name": share_name,
        "drive_type": drive_type,
        "is_deleted": is_deleted,
    }
