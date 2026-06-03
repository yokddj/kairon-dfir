from __future__ import annotations

import json
from pathlib import Path, PureWindowsPath
import re
from urllib.parse import urlparse


CLOUD_NAME_HINTS = (
    "onedrive",
    "googledrive",
    "drivefs",
    "dropbox",
    "megasync",
    "icloud",
    "boxdrive",
    "cloudsync",
    "filesync",
)
CLOUD_HEADER_HINTS = {
    "provider",
    "account",
    "accountemail",
    "useremail",
    "syncroot",
    "localpath",
    "remotepath",
    "cloudpath",
    "filename",
    "filepath",
    "status",
    "syncstatus",
    "hydrationstatus",
    "pinned",
    "shared",
    "itemid",
    "driveid",
    "resourceid",
    "created",
    "modified",
    "accessed",
    "deleted",
    "lastsync",
    "lastupload",
    "lastdownload",
    "url",
    "domain",
    "sourcefile",
    "usersid",
    "direction",
    "deletedtime",
    "lastsynctime",
    "lastuploadtime",
    "lastdownloadtime",
    "timestampinterpretation",
    "parserstatus",
    "detectionmethod",
}
SENSITIVE_CLOUD_FIELD_TOKENS = {
    "password",
    "passwd",
    "secret",
    "token",
    "refresh_token",
    "access_token",
    "clientsecret",
    "authorization",
    "cookie",
}
SENSITIVE_EXTENSIONS = {
    ".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx", ".pdf", ".txt", ".csv",
    ".kdbx", ".rdp", ".ovpn", ".pem", ".key", ".pfx", ".p12", ".ppk", ".config", ".ini", ".env",
    ".ps1", ".bat", ".cmd", ".py", ".js", ".vbs", ".sh",
    ".zip", ".rar", ".7z", ".tar", ".gz",
    ".db", ".sqlite", ".mdb", ".accdb",
}
ARCHIVE_EXTENSIONS = {".zip", ".rar", ".7z", ".tar", ".gz"}
EXECUTABLE_EXTENSIONS = {".exe", ".dll", ".ps1", ".bat", ".cmd", ".vbs", ".js", ".hta", ".msi", ".scr"}
SCRIPT_EXTENSIONS = {".ps1", ".bat", ".cmd", ".vbs", ".js", ".hta"}
SENSITIVE_NAME_TOKENS = {
    "password", "passwords", "credential", "credentials", "secret", "vpn", "backup", "dump",
    "database", "db", "export", "confidential", "private", "wallet", "token", "key", "ssh", "lsass", "payroll", "invoice",
}
COPY_COMMAND_TOKENS = {
    "copy ", "xcopy", "robocopy", "move ", "copy-item", "move-item", "compress-archive", " 7z ", " rar ", " tar ",
}
URL_RE = re.compile(r"https?://[^\s\"'>]+", re.IGNORECASE)

PROVIDER_RULES: list[tuple[str, tuple[str, ...]]] = [
    ("onedrive", ("\\onedrive\\", "\\onedrive - ", "\\appdata\\local\\microsoft\\onedrive\\", "\\programdata\\microsoft\\onedrive\\")),
    ("google_drive", ("\\google drive\\", "\\my drive\\", "\\appdata\\local\\google\\drivefs\\", "\\appdata\\roaming\\google\\drivefs\\", "\\appdata\\local\\google\\drive\\")),
    ("dropbox", ("\\dropbox\\", "\\appdata\\local\\dropbox\\", "\\appdata\\roaming\\dropbox\\")),
    ("mega", ("\\megasync\\", "\\appdata\\local\\mega limited\\megasync\\", "\\appdata\\roaming\\mega limited\\megasync\\")),
    ("icloud", ("\\iclouddrive\\", "\\icloud photos\\", "\\appdata\\local\\packages\\appleinc.icloud", "\\appdata\\roaming\\apple computer\\mobilesync\\")),
    ("box", ("\\box\\", "\\box sync\\", "\\box drive\\", "\\appdata\\local\\box\\", "\\appdata\\roaming\\box\\")),
]


def canonicalize_header(value: object) -> str:
    return re.sub(r"[^a-z0-9]+", "", str(value).strip().lower())


def clean_value(value: str | None) -> str | None:
    if value in (None, ""):
        return None
    cleaned = str(value).strip().strip('"').strip("'")
    if cleaned.lower() in {"-", "--", "n/a", "na", "(null)", "null", "none", "unknown"}:
        return None
    return cleaned


def normalize_windows_path(value: str | None) -> str | None:
    cleaned = clean_value(value)
    if not cleaned:
        return None
    return cleaned.replace("/", "\\")


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


def first_nonempty(row: dict, *names: str) -> str | None:
    lowered = {str(key).lower(): value for key, value in row.items()}
    canon = {canonicalize_header(key): value for key, value in row.items()}
    for name in names:
        for candidate in (name, name.lower(), canonicalize_header(name)):
            value = lowered.get(candidate) if candidate in lowered else canon.get(candidate)
            if value not in (None, ""):
                return str(value)
    return None


def looks_like_cloud_sync_artifact(path: Path, headers: list[str] | None = None) -> bool:
    suffix = path.suffix.lower()
    if suffix not in {".csv", ".json", ".jsonl", ".log", ".txt", ".ini"}:
        return False
    lower_name = path.name.lower()
    if any(token in lower_name for token in CLOUD_NAME_HINTS):
        return True
    header_set = {canonicalize_header(header) for header in (headers or []) if header}
    return len(header_set & CLOUD_HEADER_HINTS) >= 4


def detect_cloud_provider_from_path(path: str | None) -> tuple[str | None, str | None, str | None]:
    normalized = normalize_windows_path(path)
    if not normalized:
        return None, None, None
    lower = normalized.lower()
    for provider, tokens in PROVIDER_RULES:
        if not any(token in lower for token in tokens):
            continue
        if provider == "onedrive":
            match = re.search(r"^[A-Z]:\\Users\\(?P<user>[^\\]+)\\(?P<root>OneDrive(?: - [^\\]+)?)\\", normalized, re.IGNORECASE)
            if match:
                return provider, f"{normalized[:2]}\\Users\\{match.group('user')}\\{match.group('root')}", None
        elif provider == "google_drive":
            match = re.search(r"^[A-Z]:\\Users\\(?P<user>[^\\]+)\\(?P<root>Google Drive|My Drive)\\", normalized, re.IGNORECASE)
            if match:
                return provider, f"{normalized[:2]}\\Users\\{match.group('user')}\\{match.group('root')}", None
            match = re.search(r"^(?P<drive>[A-Z]:)\\My Drive\\", normalized, re.IGNORECASE)
            if match:
                return provider, f"{match.group('drive')}\\My Drive", None
        elif provider == "dropbox":
            match = re.search(r"^[A-Z]:\\Users\\(?P<user>[^\\]+)\\Dropbox\\", normalized, re.IGNORECASE)
            if match:
                return provider, f"{normalized[:2]}\\Users\\{match.group('user')}\\Dropbox", None
        elif provider == "mega":
            match = re.search(r"^[A-Z]:\\Users\\(?P<user>[^\\]+)\\MEGAsync\\", normalized, re.IGNORECASE)
            if match:
                return provider, f"{normalized[:2]}\\Users\\{match.group('user')}\\MEGAsync", None
        elif provider == "icloud":
            match = re.search(r"^[A-Z]:\\Users\\(?P<user>[^\\]+)\\(?P<root>iCloudDrive|iCloud Photos)\\", normalized, re.IGNORECASE)
            if match:
                return provider, f"{normalized[:2]}\\Users\\{match.group('user')}\\{match.group('root')}", None
        elif provider == "box":
            match = re.search(r"^[A-Z]:\\Users\\(?P<user>[^\\]+)\\(?P<root>Box|Box Sync|Box Drive)\\", normalized, re.IGNORECASE)
            if match:
                return provider, f"{normalized[:2]}\\Users\\{match.group('user')}\\{match.group('root')}", None
        return provider, None, None
    return None, None, None


def normalize_cloud_provider(value: str | None) -> str:
    cleaned = (clean_value(value) or "").strip().lower()
    aliases = {
        "onedrive": "OneDrive",
        "sharepoint": "SharePoint",
        "google_drive": "GoogleDrive",
        "googledrive": "GoogleDrive",
        "google drive": "GoogleDrive",
        "dropbox": "Dropbox",
        "mega": "MEGA",
        "megasync": "MEGA",
        "icloud": "iCloud",
        "box": "Box",
    }
    return aliases.get(cleaned, value if value else "Unknown")


def normalize_cloud_direction(value: str | None, *, deleted_time: str | None = None, upload_time: str | None = None, download_time: str | None = None, sync_time: str | None = None) -> str:
    cleaned = (clean_value(value) or "").strip().lower()
    if cleaned in {"upload", "uploaded", "outbound"}:
        return "upload"
    if cleaned in {"download", "downloaded", "inbound"}:
        return "download"
    if cleaned in {"delete", "deleted", "remove", "removed"}:
        return "delete"
    if cleaned in {"sync", "synced", "synchronized", "synchronization"}:
        return "sync"
    if deleted_time:
        return "delete"
    if upload_time:
        return "upload"
    if download_time:
        return "download"
    if sync_time:
        return "sync"
    return "unknown"


def redact_cloud_secrets(value: str | None) -> str | None:
    cleaned = clean_value(value)
    if not cleaned:
        return None
    lowered = cleaned.lower()
    if any(token in lowered for token in SENSITIVE_CLOUD_FIELD_TOKENS):
        return "[REDACTED]"
    return cleaned


def classify_cloud_item(
    *,
    provider: str | None,
    local_path: str | None,
    remote_path: str | None,
    cloud_path: str | None,
    direction: str | None,
    hydration_status: str | None,
    shared: bool | None,
    deleted_time: str | None,
) -> tuple[set[str], list[str], int]:
    normalized = normalize_windows_path(local_path) or ""
    lower = normalized.lower()
    effective_name = (basename_windows(local_path or remote_path or cloud_path) or "").lower()
    ext = suffix_windows(local_path or remote_path or cloud_path)
    tags = {"cloud", "cloud_sync"}
    reasons: list[str] = []
    risk = 5

    if direction == "sync":
        reasons.append("Cloud sync root observed")
        risk = max(risk, 10)
    if hydration_status:
        lowered_hydration = str(hydration_status).lower()
        if "placeholder" in lowered_hydration:
            reasons.append("Cloud item placeholder observed")
            tags.add("cloud_placeholder")
        if any(token in lowered_hydration for token in {"hydrated", "pinned", "alwaysavailable"}):
            reasons.append("Cloud item hydrated locally")
            tags.add("cloud_hydrated")
    if ext in EXECUTABLE_EXTENSIONS and direction == "upload":
        reasons.append("Cloud upload of script" if ext in SCRIPT_EXTENSIONS else "Cloud upload of executable")
        risk = max(risk, 75 if ext in SCRIPT_EXTENSIONS else 80)
    if ext in ARCHIVE_EXTENSIONS and direction == "upload":
        reasons.append("Cloud upload of archive")
        risk = max(risk, 62)
    if any(token in effective_name for token in SENSITIVE_NAME_TOKENS):
        reasons.append("Cloud file name contains sensitive keyword")
        risk = max(risk, 60 if shared else 45)
    if shared and any(token in effective_name for token in SENSITIVE_NAME_TOKENS):
        reasons.append("Cloud shared sensitive item")
        risk = max(risk, 68)
    if direction == "delete" and (ext in EXECUTABLE_EXTENSIONS or ext in ARCHIVE_EXTENSIONS or any(token in effective_name for token in SENSITIVE_NAME_TOKENS)):
        reasons.append("Cloud deleted suspicious item")
        risk = max(risk, 45)
    if any(token in lower for token in ("\\desktop\\", "\\downloads\\", "\\appdata\\", "\\temp\\")) and direction == "upload":
        reasons.append("Cloud upload from user-writable path")
        risk = max(risk, 65)
    if provider and str(provider).lower() == "onedrive":
        tags.add("onedrive")
    return tags, [reason for reason in reasons if reason], risk


def classify_cloud_path_kind(path: str | None) -> tuple[str | None, str]:
    normalized = normalize_windows_path(path)
    if not normalized:
        return None, "unknown"
    lower = normalized.lower()
    if any(token in lower for token in ("\\logs\\", "syncengine-", "filecache", "\\onedrive\\logs\\", "\\dropbox\\logs\\")):
        return "cloud_client_log", "provider_log"
    if any(token in lower for token in ("\\settings\\", "global.db", "instance_db", "host.db", "sync_config", "business", "personal", "drivefs")):
        return "cloud_client_config", "provider_log"
    provider, sync_root, _ = detect_cloud_provider_from_path(normalized)
    if provider and sync_root and lower.startswith(sync_root.lower()):
        return f"{provider}_folder", "path_inference"
    return "cloud_generic", "raw_discovery"


def parse_cloud_url(value: str | None) -> dict[str, str | None]:
    url = str(value or "").strip()
    if not url:
        return {"full": None, "domain": None, "scheme": None, "path": None}
    parsed = urlparse(url)
    return {
        "full": url,
        "domain": parsed.hostname,
        "scheme": parsed.scheme or None,
        "path": parsed.path or None,
    }


def extract_urls(*values: str | None) -> list[str]:
    urls: list[str] = []
    for value in values:
        if not value:
            continue
        for match in URL_RE.findall(str(value)):
            if match not in urls:
                urls.append(match)
    return urls


def classify_cloud_file(path: str | None, *, command_line: str | None = None) -> tuple[set[str], list[str], int]:
    normalized = normalize_windows_path(path) or ""
    lower = normalized.lower()
    name = (basename_windows(normalized) or "").lower()
    ext = suffix_windows(normalized)
    tags = {"cloud", "cloud_sync"}
    reasons: list[str] = []
    risk = 5

    if ext in SENSITIVE_EXTENSIONS or any(token in name for token in SENSITIVE_NAME_TOKENS):
        tags.add("sensitive_file")
        reasons.append("Sensitive file observed inside cloud sync folder")
        risk = max(risk, 45)
    if ext in ARCHIVE_EXTENSIONS:
        tags.add("archive_file")
        reasons.append("Archive file created/modified inside cloud sync folder")
        risk = max(risk, 58)
    if ext in {".kdbx", ".rdp", ".ovpn", ".pem", ".key", ".pfx", ".p12", ".ppk", ".env"}:
        tags.add("credential_file")
        risk = max(risk, 68)
    if ext in EXECUTABLE_EXTENSIONS:
        tags.add("executable_from_cloud")
        reasons.append("Executable/script observed in cloud sync folder")
        risk = max(risk, 65)
    blob = str(command_line or "").lower()
    if any(token in blob for token in COPY_COMMAND_TOKENS):
        tags.add("copied_to_cloud")
        reasons.append("PowerShell/copy command references cloud sync folder")
        risk = max(risk, 72 if "sensitive_file" in tags or "archive_file" in tags else 52)
    return tags, reasons, risk


def read_cloud_json_rows(path: Path) -> list[dict]:
    text = path.read_text(encoding="utf-8", errors="ignore")
    payload = json.loads(text)
    if isinstance(payload, list):
        return [item for item in payload if isinstance(item, dict)]
    if isinstance(payload, dict):
        for key in ("rows", "items", "entries"):
            if isinstance(payload.get(key), list):
                return [item for item in payload[key] if isinstance(item, dict)]
        return [payload]
    return []


__all__ = [
    "ARCHIVE_EXTENSIONS",
    "EXECUTABLE_EXTENSIONS",
    "basename_windows",
    "canonicalize_header",
    "classify_cloud_file",
    "classify_cloud_path_kind",
    "clean_value",
    "detect_cloud_provider_from_path",
    "extract_urls",
    "first_nonempty",
    "looks_like_cloud_sync_artifact",
    "normalize_windows_path",
    "parse_cloud_url",
    "read_cloud_json_rows",
    "suffix_windows",
]
