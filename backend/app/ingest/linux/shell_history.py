"""Bash/ZSH history parser."""
from __future__ import annotations
import re
from datetime import datetime, timezone
from pathlib import Path

_ZSH_EXTENDED_RE = re.compile(r"^:\s*(\d+):\d+;(.*)$")

_MONTH_MAP = {
    "jan": 1, "feb": 2, "mar": 3, "apr": 4, "may": 5, "jun": 6,
    "jul": 7, "aug": 8, "sep": 9, "oct": 10, "nov": 11, "dec": 12,
}

# BSD systems (seen on a FreeBSD-based appliance) can audit-log every
# interactive shell command through syslog, writing to a dedicated file
# (bash.log/sh.log) rather than the shell's own ~/.bash_history -- each
# line is a normal BSD-syslogd envelope ("<facility> host process[pid]:
# ...", see app.ingest.linux.syslog._SYSLOG_RE) whose message is this
# specific "<user> on <tty> shell_command=\"<command>\"" shape. Previously
# unrecognized by any filename pattern at all, so these files were
# misclassified as generic_csv and produced zero events -- every command
# run on the box was invisible to search.
_BSD_SHELL_AUDIT_ENVELOPE_RE = re.compile(
    r"^(\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+(?:<([\w.]+)>\s+)?(\S+)\s+(\S+?)(?:\[(\d+)\])?\s*:\s+(.*)$"
)
_BSD_SHELL_AUDIT_MESSAGE_RE = re.compile(r'^(\S+)\s+on\s+(\S+)\s+shell_command="(.*)"\s*$')


def _parse_bsd_syslog_timestamp(ts_str: str) -> str | None:
    match = re.match(r"^(\w{3})\s+(\d{1,2})\s+(\d{2}):(\d{2}):(\d{2})$", ts_str.strip())
    if not match:
        return None
    month_str, day_str, hour_str, minute_str, second_str = match.groups()
    month = _MONTH_MAP.get(month_str.lower())
    if month is None:
        return None
    try:
        year = datetime.now(tz=timezone.utc).year
        return datetime(year, month, int(day_str), int(hour_str), int(minute_str), int(second_str), tzinfo=timezone.utc).isoformat()
    except (ValueError, OverflowError):
        return None


def parse_bsd_shell_audit_log(content: str, *, source_path: str = "") -> list[dict]:
    results: list[dict] = []
    for line_number, line in enumerate(content.splitlines(), start=1):
        stripped = line.strip()
        if not stripped:
            continue
        envelope_match = _BSD_SHELL_AUDIT_ENVELOPE_RE.match(stripped)
        if not envelope_match:
            continue
        ts_str, _facility, host, process_raw, pid_str, message = envelope_match.groups()
        audit_match = _BSD_SHELL_AUDIT_MESSAGE_RE.match(message.strip())
        if not audit_match:
            # Not every line in these files is a command (startup/rotation
            # notices share the file) -- only the shell_command= lines are
            # this artifact's actual content.
            continue
        username, tty, command = audit_match.groups()
        results.append({
            "artifact_family": "linux_shell_history",
            "artifact_type": "bsd_shell_audit",
            "source_file": source_path,
            "line_number": line_number,
            "username": username,
            "process": (process_raw or "").rstrip(":") or None,
            "terminal": tty,
            "hostname": host,
            "pid": int(pid_str) if pid_str else None,
            "command": command[:4000],
            "timestamp": _parse_bsd_syslog_timestamp(ts_str),
            "message": command[:2000],
            "raw_excerpt": stripped[:2000],
        })
    return results


def _infer_username(source_path: str) -> str | None:
    path_str = str(source_path).replace("\\", "/")
    match = re.search(r"/home/([^/]+)/", path_str)
    if match:
        return match.group(1)
    match = re.search(r"/root/", path_str)
    if match:
        return "root"
    return None


def _detect_shell_type(source_path: str) -> str:
    lower = str(source_path).lower()
    if "zsh_history" in lower or ".zsh" in lower:
        return "zsh"
    return "bash"


def parse_shell_history(
    content: str,
    *,
    source_path: str = "",
    username: str | None = None,
) -> list[dict]:
    results: list[dict] = []
    inferred_user = username or _infer_username(source_path)
    shell_type = _detect_shell_type(source_path)
    current_timestamp = None

    for line_number, line in enumerate(content.splitlines(), start=1):
        stripped = line.strip()
        if not stripped:
            current_timestamp = None
            continue

        if shell_type == "zsh":
            zsh_match = _ZSH_EXTENDED_RE.match(stripped)
            if zsh_match:
                epoch_str = zsh_match.group(1)
                command = zsh_match.group(2).strip()
                try:
                    epoch = int(epoch_str)
                    current_timestamp = datetime.fromtimestamp(epoch, tz=timezone.utc).isoformat()
                except (ValueError, OverflowError, OSError):
                    current_timestamp = None
            else:
                if stripped.startswith(":"):
                    current_timestamp = None
                    continue
                command = stripped
        else:
            command = stripped

        if not command:
            continue

        truncated = command[:4000] if len(command) > 4000 else command
        raw_excerpt = truncated[:2000]

        results.append({
            "artifact_family": "linux_shell_history",
            "artifact_type": f"{shell_type}_history",
            "source_file": source_path,
            "line_number": line_number,
            "username": inferred_user,
            "shell_type": shell_type,
            "command": truncated,
            "timestamp": current_timestamp,
            "message": truncated[:2000],
            "raw_excerpt": raw_excerpt,
        })

    return results
