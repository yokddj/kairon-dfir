"""Auth log parser for /var/log/auth.log and /var/log/secure."""
from __future__ import annotations
import re
import socket
import struct
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

# See app.ingest.linux.syslog's _SYSLOG_RE for why the "<facility.severity>"
# tag (e.g. "<auth.err>") needs to be an optional, skippable group here: BSD
# syslogd (seen on a NetScaler appliance's own auth.log) inserts it between
# the timestamp and hostname on most lines, and without accounting for it
# the whole line falls through to "no match" -- timestamp/host/process all
# None -- for everything except the rare line logged without that tag.
_SYSLOG_TIMESTAMP_RE = re.compile(
    r"^(\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+(?:<[\w.]+>\s+)?(\S+)\s+(\S+?)(?:\[(\d+)\])?\s*:\s+(.*)$"
)

_IP_RE = re.compile(r"\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b")
_SOURCE_PORT_RE = re.compile(r"\bport\s+(\d{1,5})\b", re.IGNORECASE)
_FAILED_INVALID_RE = re.compile(r"Failed\s+(?P<method>\S+)\s+for\s+invalid\s+user\s+(?P<user>\S+)\s+from\s+(?P<ip>\S+)(?:\s+port\s+(?P<port>\d+))?", re.IGNORECASE)
_FAILED_RE = re.compile(r"Failed\s+(?P<method>\S+)\s+for\s+(?P<user>\S+)\s+from\s+(?P<ip>\S+)(?:\s+port\s+(?P<port>\d+))?", re.IGNORECASE)
_ACCEPTED_RE = re.compile(r"Accepted\s+(?P<method>\S+)\s+for\s+(?P<user>\S+)\s+from\s+(?P<ip>\S+)(?:\s+port\s+(?P<port>\d+))?", re.IGNORECASE)
_INVALID_RE = re.compile(r"Invalid\s+user\s+(?P<user>\S+)\s+from\s+(?P<ip>\S+)", re.IGNORECASE)
_PAM_SESSION_RE = re.compile(r"pam_unix\((?P<service>[^:):]+)(?::(?P<context>[^)]+))?\):\s*session\s+(?P<state>opened|closed)\s+for\s+user\s+(?P<user>\S+)", re.IGNORECASE)
_PAM_FAILURE_RE = re.compile(r"pam_unix\((?P<service>[^:):]+)(?::(?P<context>[^)]+))?\):\s*authentication\s+failure", re.IGNORECASE)
_PAM_MORE_RE = re.compile(r"PAM\s+(?P<count>\d+)\s+more\s+authentication\s+failures?", re.IGNORECASE)
_TTY_RE = re.compile(r"\btty=([^\s;]+)", re.IGNORECASE)
_UID_RE = re.compile(r"\buid=(\d+)", re.IGNORECASE)
_RHOST_RE = re.compile(r"\brhost=([^\s;]+)", re.IGNORECASE)
_USER_RE = re.compile(r"\buser=([^\s;]+)", re.IGNORECASE)

_UTMP_STRUCT_SIZE = 384
_UTMP_STRUCT = struct.Struct("hi32s4s32s256shhiii4i20s")
_UTMP_TYPES = {
    1: "runlevel",
    2: "boot_time",
    3: "new_time",
    4: "old_time",
    5: "init_process",
    6: "login_process",
    7: "user_process",
    8: "dead_process",
}

_LASTLOG_STRUCT_SIZE = 292
_LASTLOG_STRUCT = struct.Struct("i32s256s")

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


_SUDO_LINE_RE = re.compile(
    r"^\s*(?P<user>[^\s:]+)\s*:\s*(?:(?P<problem>[^;]*?)\s*;\s*)?TTY=(?P<tty>[^;]*?)\s*;\s*PWD=(?P<pwd>[^;]*?)\s*;\s*USER=(?P<runas>[^;]*?)\s*;(?:[^;]*;)*?\s*COMMAND=(?P<cmd>.*)$"
)
_MAX_ATTEMPTS_RE = re.compile(r"maximum authentication attempts exceeded for (?:invalid user )?(?P<user>\S+) from (?P<ip>[0-9a-fA-F:.]+) port (?P<port>\d+)", re.IGNORECASE)
_CONSOLE_LOGIN_RE = re.compile(r"(?:ROOT LOGIN\s+on '?(?P<tty1>[^'\s]+)'?|LOGIN ON (?P<tty2>\S+) BY (?P<user>\S+))")


def _extract_event_action(log_message: str, process: str | None = None) -> str:
    lower = log_message.lower()
    program = (process or "").lower()
    if "accepted" in lower and "password" in lower:
        return "password_accepted"
    if "accepted" in lower and "publickey" in lower:
        return "publickey_accepted"
    if "failed password" in lower:
        return "password_failed"
    # Before "invalid user": the line may name one ("... for invalid user x from ...").
    if "maximum authentication attempts exceeded" in lower:
        return "max_auth_attempts"
    if "invalid user" in lower:
        return "invalid_user"
    # The program name is split off the message, so "sudo:" is usually not in the text itself.
    if program == "sudo" or lower.startswith("sudo") or "sudo:" in lower:
        if "incorrect password" in lower or "not in the sudoers" in lower or "authentication failure" in lower:
            return "sudo_failed"
        if "command=" in lower:
            return "sudo_command"
        return "sudo_auth"
    if program == "su" or "su:" in lower:
        return "su_auth"
    if "pam_unix" in lower and "session opened" in lower:
        return "session_opened"
    if "pam_unix" in lower and "session closed" in lower:
        return "session_closed"
    if "authentication failure" in lower:
        return "auth_failure"
    if _CONSOLE_LOGIN_RE.search(log_message):
        return "console_login"
    if "connection closed by" in lower and "[preauth]" in lower:
        return "preauth_disconnect"
    if lower.startswith(("received disconnect", "disconnected from")):
        return "ssh_disconnect"
    if lower.startswith("server listening on"):
        return "sshd_listening"
    return "unknown"


def _extract_privilege_and_console(message: str, action: str) -> dict:
    """sudo's user, target account, directory, terminal and command; console and brute-force details."""
    data: dict = {}
    if action in {"sudo_command", "sudo_failed"}:
        match = _SUDO_LINE_RE.match(message)
        if match:
            data.update(username=match.group("user"), run_as=match.group("runas").strip(), cwd=match.group("pwd").strip(),
                        terminal=match.group("tty").strip(), command=match.group("cmd").strip()[:4000])
    elif action == "max_auth_attempts":
        match = _MAX_ATTEMPTS_RE.search(message)
        if match:
            data.update(username=match.group("user"), attempted_username=match.group("user"), source_ip=match.group("ip"), source_port=int(match.group("port")))
    elif action == "console_login":
        match = _CONSOLE_LOGIN_RE.search(message)
        if match:
            data.update(username=match.group("user") or "root", terminal=(match.group("tty1") or match.group("tty2") or "").replace("/dev/", ""))
    return data


def _extract_auth_method(log_message: str) -> str | None:
    lower = log_message.lower()
    if "publickey" in lower:
        return "publickey"
    if "password" in lower:
        return "password"
    if "keyboard-interactive" in lower:
        return "keyboard-interactive"
    return None


def _clean_bytes(value: bytes) -> str:
    return value.split(b"\x00", 1)[0].decode("utf-8", errors="replace").strip()


def _source_host_from_addr(addr_words: tuple[int, int, int, int], host: str) -> str:
    """ut_addr_v6: four 32-bit words in network byte order. IPv4 uses only the first word.

    The words are unpacked as signed ints, so they are packed back the same way to recover the
    raw bytes: an address such as 192.168.x.x has the high bit set and is negative as a signed int.
    """
    words = tuple(addr_words or ())
    if len(words) != 4 or not any(words):
        return host
    try:
        raw = struct.pack("=4i", *words)
        if any(words[1:]):
            return socket.inet_ntop(socket.AF_INET6, raw)
        return socket.inet_ntoa(raw[:4])
    except (OSError, struct.error, ValueError):
        return host


def _auth_type_from_action(action: str) -> tuple[str, str]:
    if action in {"password_accepted", "publickey_accepted"}:
        return "login_success", "success"
    if action == "password_failed":
        return "login_failure", "failure"
    if action == "invalid_user":
        return "invalid_user", "failure"
    if action == "session_opened":
        return "session_open", "success"
    if action == "session_closed":
        return "session_close", "success"
    if action == "auth_failure":
        return "authentication_failure", "failure"
    if action in {"sudo_auth", "su_auth", "sudo_command"}:
        return "privilege_authentication", "success" if action == "sudo_command" else "unknown"
    if action == "sudo_failed":
        return "privilege_authentication", "failure"
    if action == "max_auth_attempts":
        return "login_failure", "failure"
    if action == "console_login":
        return "login_success", "success"
    return "other", "unknown"


def _extract_structured_auth(message: str, process: str | None) -> dict:
    data: dict = {"service": process or ""}
    for regex in (_ACCEPTED_RE, _FAILED_INVALID_RE, _FAILED_RE, _INVALID_RE):
        match = regex.search(message)
        if not match:
            continue
        groups = match.groupdict()
        user = (groups.get("user") or "").rstrip(".,;")
        data["attempted_username"] = user
        if regex is _FAILED_INVALID_RE:
            data["username"] = user
        elif regex is _INVALID_RE:
            data["username"] = user
        else:
            data["username"] = user
        data["source_ip"] = (groups.get("ip") or "").rstrip(".,;")
        if groups.get("port"):
            data["source_port"] = int(groups["port"])
        if groups.get("method"):
            data["auth_method"] = groups["method"]
        return data
    session_match = _PAM_SESSION_RE.search(message)
    if session_match:
        data["service"] = session_match.group("service") or process or ""
        data["username"] = session_match.group("user")
    failure_match = _PAM_FAILURE_RE.search(message)
    if failure_match:
        data["service"] = failure_match.group("service") or process or ""
    more_match = _PAM_MORE_RE.search(message)
    if more_match:
        data["effective_failure_count"] = int(more_match.group("count"))
    for key, regex in (("terminal", _TTY_RE), ("uid", _UID_RE), ("source_ip", _RHOST_RE), ("username", _USER_RE)):
        match = regex.search(message)
        if match:
            value = match.group(1).strip().rstrip(".,;")
            if key == "uid":
                data[key] = int(value)
            elif value:
                data[key] = value
    port_match = _SOURCE_PORT_RE.search(message)
    if port_match:
        data["source_port"] = int(port_match.group(1))
    return data


def parse_wtmp_btmp(content: bytes, *, source_path: str = "") -> list[dict]:
    if not content or len(content) % _UTMP_STRUCT_SIZE != 0:
        return []
    artifact_type = "btmp" if "btmp" in source_path.lower() else "wtmp"
    rows: list[dict] = []
    for offset in range(0, len(content), _UTMP_STRUCT_SIZE):
        chunk = content[offset:offset + _UTMP_STRUCT_SIZE]
        try:
            record = _UTMP_STRUCT.unpack(chunk)
        except struct.error:
            return []
        record_type = int(record[0])
        if record_type not in _UTMP_TYPES:
            continue
        pid = int(record[1])
        terminal = _clean_bytes(record[2])
        username = _clean_bytes(record[4])
        host = _source_host_from_addr(record[11:15], _clean_bytes(record[5]))
        seconds = int(record[9])
        if seconds <= 0 or seconds > 4_102_444_800:
            continue
        timestamp = datetime.fromtimestamp(seconds, tz=timezone.utc).isoformat()
        event_type = "login_success" if record_type == 7 else "logout" if record_type == 8 else "other"
        if artifact_type == "btmp" and record_type in {6, 7}:
            event_type = "login_failure"
        elif record_type == 2:
            event_type = "system_boot"
        elif record_type == 1:
            # RUN_LVL records carry "shutdown" or "runlevel" as the user and the new level in the pid.
            event_type = "system_shutdown" if username == "shutdown" else "runlevel_change"
        elif record_type == 6:
            event_type = "login_prompt"
        elif record_type == 5:
            event_type = "init_process"
        elif record_type in {3, 4}:
            event_type = "clock_change"
        if record_type in {1, 2}:
            message = f"{artifact_type} {event_type.replace('_', ' ')}" + (f" (kernel {host})" if host and record_type == 2 else "")
        else:
            message = f"{artifact_type} {event_type.replace('_', ' ')} user={username or '-'} terminal={terminal or '-'} source={host or '-'}"
        rows.append({
            "artifact_family": "linux_auth",
            "artifact_type": artifact_type,
            "source_file": source_path,
            "timestamp": timestamp,
            "username": username,
            "attempted_username": username,
            "process": "login",
            "service": "login",
            "pid": pid,
            "source_ip": host,
            "terminal": terminal,
            "event_action": event_type,
            "auth_event_type": event_type,
            "authentication_result": "failure" if event_type == "login_failure" else "success" if event_type == "login_success" else "unknown",
            "record_type": _UTMP_TYPES[record_type],
            "record_offset": offset,
            "message": message,
            "raw_excerpt": message,
        })
    return rows


def parse_lastlog(content: bytes, *, source_path: str = "") -> list[dict]:
    from app.ingest.linux.lastlog import parse_lastlog as parse_linux_lastlog

    return parse_linux_lastlog(content, source_path=source_path)


def parse_auth(
    content: str | bytes,
    *,
    source_path: str = "",
    username: str | None = None,
) -> list[dict]:
    if isinstance(content, bytes):
        lowered = source_path.lower()
        if "lastlog" in lowered:
            return parse_lastlog(content, source_path=source_path)
        if "wtmp" in lowered or "btmp" in lowered:
            return parse_wtmp_btmp(content, source_path=source_path)
        content = content.decode("utf-8", errors="replace")
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

        event_action = _extract_event_action(message, process)
        auth_method = _extract_auth_method(message)
        structured = _extract_structured_auth(message, process)
        structured.update({key: value for key, value in _extract_privilege_and_console(message, event_action).items() if value not in (None, "")})
        auth_event_type, authentication_result = _auth_type_from_action(event_action)
        if structured.get("username"):
            detected_username = structured["username"]
        attempted_username = structured.get("attempted_username") or detected_username
        source_ip = structured.get("source_ip") or source_ip
        service = structured.get("service") or process or ""

        results.append({
            "artifact_family": "linux_auth",
            "artifact_type": "auth_log",
            "source_file": source_path,
            "line_number": line_number,
            "timestamp": timestamp,
            "timestamp_status": "assumed_year_utc" if timestamp else "missing",
            "detected_host": host,
            "username": detected_username,
            "attempted_username": attempted_username,
            "process": process,
            "service": service,
            "pid": pid,
            "source_ip": source_ip,
            "source_port": structured.get("source_port"),
            "terminal": structured.get("terminal", ""),
            "uid": structured.get("uid"),
            "auth_method": auth_method,
            "authentication_result": authentication_result,
            "auth_event_type": auth_event_type,
            "effective_failure_count": structured.get("effective_failure_count"),
            "run_as": structured.get("run_as", ""),
            "cwd": structured.get("cwd", ""),
            "command": structured.get("command", ""),
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
