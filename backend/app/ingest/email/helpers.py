from __future__ import annotations

import re
from pathlib import Path, PureWindowsPath


EMAIL_HEADER_HINTS = {
    "message-id",
    "message-id:",
    "from:",
    "to:",
    "subject:",
    "mime-version:",
    "content-type:",
    "authentication-results:",
    "received-spf:",
}
EMAIL_STRUCTURED_HEADER_HINTS = {
    "messageid",
    "subject",
    "fromaddress",
    "toaddresses",
    "replyto",
    "authenticationresults",
    "receivedspf",
}
THUNDERBIRD_MBOX_NAMES = {
    "inbox",
    "sent",
    "archives",
    "drafts",
    "trash",
    "junk",
    "templates",
}
OUTLOOK_TEMP_PATTERN = re.compile(r"users\\[^\\]+\\appdata\\local\\microsoft\\windows\\inetcache\\content\.outlook\\", re.IGNORECASE)
WINDOWS_MAIL_STORE_PATTERN = re.compile(r"users\\[^\\]+\\appdata\\local\\comms\\(?:unistoredb\\store\.vol|unistore\\data\\)", re.IGNORECASE)
THUNDERBIRD_PROFILE_PATTERN = re.compile(r"users\\[^\\]+\\appdata\\roaming\\thunderbird\\profiles\\", re.IGNORECASE)
OUTLOOK_MAILBOX_PATTERN = re.compile(
    r"users\\[^\\]+\\(?:appdata\\local|local settings\\application data)\\microsoft\\outlook\\",
    re.IGNORECASE,
)
URL_RE = re.compile(r"https?://[^\s\"'<>()]+", re.IGNORECASE)
IPV4_RE = re.compile(r"\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b")


def clean_value(value: object | None) -> str | None:
    if value in (None, ""):
        return None
    text = str(value).strip().strip('"').strip("'")
    if not text or text.lower() in {"-", "--", "n/a", "na", "none", "null", "unknown"}:
        return None
    return text


def canonicalize_header(value: object) -> str:
    return re.sub(r"[^a-z0-9]+", "", str(value).strip().lower())


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


def is_outlook_temp_attachment_path(path: str | None) -> bool:
    normalized = normalize_windows_path(path)
    if not normalized:
        return False
    return bool(OUTLOOK_TEMP_PATTERN.search(normalized))


def is_windows_mail_inventory_path(path: str | None) -> bool:
    normalized = normalize_windows_path(path)
    if not normalized:
        return False
    return bool(WINDOWS_MAIL_STORE_PATTERN.search(normalized))


def is_outlook_mailbox_path(path: str | None) -> bool:
    normalized = normalize_windows_path(path)
    if not normalized:
        return False
    return bool(OUTLOOK_MAILBOX_PATTERN.search(normalized))


def is_thunderbird_profile_path(path: str | None) -> bool:
    normalized = normalize_windows_path(path)
    if not normalized:
        return False
    return bool(THUNDERBIRD_PROFILE_PATTERN.search(normalized))


def _looks_like_mbox_name(path: Path) -> bool:
    lower_name = path.name.lower()
    return lower_name in THUNDERBIRD_MBOX_NAMES or lower_name.endswith(".mbox")


def looks_like_email_artifact(path: Path, headers: list[str] | None = None) -> bool:
    lower_name = path.name.lower()
    suffix = path.suffix.lower()
    normalized_path = normalize_windows_path(str(path)) or str(path).replace("/", "\\")
    header_blob = " ".join(str(header).lower() for header in (headers or []) if header)
    header_set = {canonicalize_header(header) for header in (headers or []) if header}

    if suffix in {".eml", ".pst", ".ost", ".mbox"}:
        return True
    if is_outlook_temp_attachment_path(normalized_path):
        return True
    if is_windows_mail_inventory_path(normalized_path):
        return True
    if is_outlook_mailbox_path(normalized_path) and suffix in {".pst", ".ost"}:
        return True
    if is_thunderbird_profile_path(normalized_path) and _looks_like_mbox_name(path) and suffix not in {".msf", ".sqlite"}:
        return True
    if "content.outlook" in normalized_path.lower():
        return True
    if lower_name == "store.vol" and "comms" in normalized_path.lower():
        return True
    if EMAIL_HEADER_HINTS & set(header_blob.split()):
        return True
    if len(header_set & EMAIL_STRUCTURED_HEADER_HINTS) >= 2:
        return True
    return False


def redact_secret_like_text(value: str | None, *, max_len: int = 600) -> str | None:
    cleaned = clean_value(value)
    if not cleaned:
        return None
    redacted = re.sub(r"(?i)\b(access_token|refresh_token|password|secret|apikey|api_key|authorization)\b\s*[:=]\s*([^\s;]+)", r"\1=[REDACTED]", cleaned)
    redacted = re.sub(r"(?i)\b(bearer\s+)[A-Za-z0-9._\-+/=]{12,}", r"\1[REDACTED]", redacted)
    if len(redacted) > max_len:
        redacted = f"{redacted[:max_len]}..."
    return redacted


def extract_urls(text: str | None) -> list[str]:
    if not text:
        return []
    return list(dict.fromkeys(match.group(0) for match in URL_RE.finditer(text)))[:25]


def extract_ipv4s(text: str | None) -> list[str]:
    if not text:
        return []
    return list(dict.fromkeys(match.group(0) for match in IPV4_RE.finditer(text)))[:25]


def parse_email_domain(address: str | None) -> str | None:
    cleaned = clean_value(address)
    if not cleaned or "@" not in cleaned:
        return None
    return cleaned.rsplit("@", 1)[-1].strip().lower()
