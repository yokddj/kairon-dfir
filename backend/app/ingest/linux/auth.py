"""Auth log parser for /var/log/auth.log and /var/log/secure."""
from __future__ import annotations
import re
from datetime import datetime, timezone
from pathlib import Path

_AUTH_PATTERNS = [
    re.compile(r"(accepted|Accepted)\s+(password|publickey)\s+for\s+(\S+)", re.IGNORECASE),
    re.compile(r"(Failed|failed)\s+password\s+for\s+(\S+)", re.IGNORECASE),
    re.compile(r"(Invalid|invalid)\s+user\s+(\S+)", re.IGNORECASE),
    re.compile(r"(sudo|su)\s*:\s+(\S+)\s*:\s*TTY=", re.IGNORECASE),
    re.compile(r"pam_unix\([^)]+\):\s*session\s+(opened|closed)", re.IGNORECASE),
    re.compile(r"(authentication|Authentication)\s+failure", re.IGNORECASE),
]

_SYSLOG_TIMESTAMP_RE = re.compile(
    r"^(\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+(\S+)\s+(\S+?)(?:\[(\d+)\])?\s*:\s+(.*)$"
)

_IP_RE = re.compile(r"\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b")

_MONTH_MAP = {
    "jan": 1, "feb": 2, "mar": 3, "apr": 4, "may": 5, "jun": 6,
    "jul": 7, "aug": 8, "sep": 9, "oct": 10, "nov": 11, "dec": 12,
}


def _parse_syslog_timestamp(ts_str: str, year: int | None = None) -> str | None:
    ts_str = ts_str.strip()
    if year is None:
        year = datetime.now(tz=timezone.utc).year
    match = re.match(r"^(\w{3})\s+(\d{1,2})\s+(\d{2}):(\d{2}):(\d{2})$", ts_str)
    if not match:
        return None
    month_str, day_str, hour_str, minute_str, second_str = match.groups()
    month = _MONTH_MAP.get(month_str.lower())
    if month is None:
        return None
    try:
        dt = datetime(year, month, int(day_str), int(hour_str), int(minute_str), int(second_str), tzinfo=timezone.utc)
        return dt.isoformat()
    except (ValueError, OverflowError):
        return None


def _extract_username(log_message: str, fallback: str | None = None) -> str | None:
    for pattern in _AUTH_PATTERNS:
        m = pattern.search(log_message)
        if m:
            if pattern.pattern.startswith("(accepted|Accepted)"):
                return m.group(3)
            elif pattern.pattern.startswith("(Failed|failed)"):
                return m.group(2)
            elif pattern.pattern.startswith("(Invalid|invalid)"):
                return m.group(2)
            elif pattern.pattern.startswith("(sudo|su)"):
                return m.group(2)
    if fallback and fallback not in ("", "unknown"):
        return fallback
    user_match = re.search(r"user[= ](\S+)", log_message, re.IGNORECASE)
    if user_match:
        return user_match.group(1).rstrip(";")
    return None


def _extract_event_action(log_message: str) -> str:
    lower = log_message.lower()
    if "accepted" in lower and "password" in lower:
        return "password_accepted"
    if "accepted" in lower and "publickey" in lower:
        return "publickey_accepted"
    if "failed password" in lower:
        return "password_failed"
    if "invalid user" in lower:
        return "invalid_user"
    if lower.startswith("sudo") or "sudo:" in lower:
        if "command" in lower:
            return "sudo_command"
        return "sudo_auth"
    if "su:" in lower:
        return "su_auth"
    if "pam_unix" in lower and "session opened" in lower:
        return "session_opened"
    if "pam_unix" in lower and "session closed" in lower:
        return "session_closed"
    if "authentication failure" in lower:
        return "auth_failure"
    return "unknown"


def _extract_auth_method(log_message: str) -> str | None:
    lower = log_message.lower()
    if "publickey" in lower:
        return "publickey"
    if "password" in lower:
        return "password"
    if "keyboard-interactive" in lower:
        return "keyboard-interactive"
    return None


def parse_auth(
    content: str,
    *,
    source_path: str = "",
    username: str | None = None,
) -> list[dict]:
    results: list[dict] = []
    for line_number, line in enumerate(content.splitlines(), start=1):
        stripped = line.strip()
        if not stripped:
            continue
        raw_excerpt = stripped[:2000]
        timestamp = None
        host = None
        process = None
        pid = None
        message = stripped
        detected_username = None
        source_ip = None

        syslog_match = _SYSLOG_TIMESTAMP_RE.match(stripped)
        if syslog_match:
            ts_str, host, process, pid, message = syslog_match.groups()
            timestamp = _parse_syslog_timestamp(ts_str)
            if process:
                process = process.rstrip(":")
            pid = int(pid) if pid else None
        else:
            host = None
            process = None
            pid = None
            message = stripped

        detected_username = _extract_username(message)
        if detected_username is None:
            detected_username = username

        ip_matches = _IP_RE.findall(message)
        if ip_matches:
            source_ip = ip_matches[0]

        event_action = _extract_event_action(message)
        auth_method = _extract_auth_method(message)

        results.append({
            "artifact_family": "linux_auth",
            "artifact_type": "auth_log",
            "source_file": source_path,
            "line_number": line_number,
            "timestamp": timestamp,
            "detected_host": host,
            "username": detected_username,
            "process": process,
            "pid": pid,
            "source_ip": source_ip,
            "auth_method": auth_method,
            "event_action": event_action,
            "message": message[:2000],
            "raw_excerpt": raw_excerpt,
        })
    return results


def _read_content(path: str | Path) -> str:
    path_obj = Path(path) if isinstance(path, str) else path
    for enc in ("utf-8", "latin-1"):
        try:
            return path_obj.read_text(encoding=enc)
        except (UnicodeDecodeError, UnicodeError):
            continue
    return path_obj.read_text(encoding="utf-8", errors="ignore")
