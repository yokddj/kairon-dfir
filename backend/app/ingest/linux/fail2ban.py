"""fail2ban log parser (``/var/log/fail2ban.log``).

fail2ban watches other logs for repeated failures and bans the offending address for a while;
its own log is therefore a ready-made list of who attacked the host, which service they hit
(the *jail*) and when they were banned and released:

    2024-03-01 10:20:30,123 fail2ban.filter         [1234]: INFO    [sshd] Found 203.0.113.9 - 2024-03-01 10:20:29
    2024-03-01 10:20:31,456 fail2ban.actions        [1234]: NOTICE  [sshd] Ban 203.0.113.9
    2024-03-01 10:50:31,456 fail2ban.actions        [1234]: NOTICE  [sshd] Unban 203.0.113.9
"""
from __future__ import annotations

import re
from datetime import datetime, timezone

ARTIFACT_FAMILY = "linux_fail2ban"
ARTIFACT_TYPE = "fail2ban_log"

# The pid is absent in logs from older releases ("fail2ban.actions: WARNING [ssh] Ban ...").
_LINE_RE = re.compile(
    r"^(?P<timestamp>\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}(?:[,.]\d{1,6})?)\s+"
    r"(?P<component>fail2ban(?:\.[\w]+)*)\s*(?:\[(?P<pid>\d+)\])?:\s+"
    r"(?P<level>[A-Z]+)\s+(?P<message>.*)$"
)
_JAIL_RE = re.compile(r"^\[(?P<jail>[^\]]+)\]\s+(?P<rest>.*)$")
_IP_RE = re.compile(r"((?:\d{1,3}\.){3}\d{1,3}|[0-9a-fA-F:]*:[0-9a-fA-F:]+)")
_SEVERITY = {"DEBUG": "debug", "INFO": "info", "NOTICE": "notice", "WARNING": "warning", "ERROR": "error", "CRITICAL": "crit"}

# (regex on the text after "[jail] ", action). Order matters: "Restore Ban" before "Ban".
_JAIL_ACTIONS = (
    (re.compile(r"^Restore Ban\b"), "restore_ban"),
    (re.compile(r"^Unban\b"), "unban"),
    (re.compile(r"^Ban\b"), "ban"),
    (re.compile(r"^Found\b"), "found"),
    (re.compile(r"^(?:\S+ )?already banned\b"), "already_banned"),
    (re.compile(r"^Ignore\b"), "ignore"),
)
_SERVER_ACTIONS = (
    (re.compile(r"^Jail '(?P<jail>[^']+)' started"), "jail_started"),
    (re.compile(r"^Jail '(?P<jail>[^']+)' stopped"), "jail_stopped"),
    (re.compile(r"^Jail '(?P<jail>[^']+)' uses "), "jail_configured"),
)


def _timestamp(value: str) -> str | None:
    text = value.replace(",", ".")
    for fmt in ("%Y-%m-%d %H:%M:%S.%f", "%Y-%m-%d %H:%M:%S"):
        try:
            # fail2ban logs the server's local time without a zone: read as UTC, and say so.
            return datetime.strptime(text, fmt).replace(tzinfo=timezone.utc).isoformat()
        except ValueError:
            continue
    return None


def _valid_ip(value: str) -> str:
    import ipaddress

    try:
        return str(ipaddress.ip_address(value))
    except ValueError:
        return ""


def parse_fail2ban(content: str, *, source_path: str = "") -> list[dict]:
    rows: list[dict] = []
    for line_number, line in enumerate(content.splitlines(), start=1):
        stripped = line.strip()
        if not stripped:
            continue
        match = _LINE_RE.match(stripped)
        row: dict = {
            "artifact_family": ARTIFACT_FAMILY,
            "artifact_type": ARTIFACT_TYPE,
            "source_file": source_path,
            "line_number": line_number,
            "raw_excerpt": stripped[:2000],
            "message": stripped[:2000],
            "timestamp": None,
            "timestamp_status": "missing",
            "process": "fail2ban",
        }
        if not match:
            rows.append(row)
            continue
        groups = match.groupdict()
        message = groups["message"].strip()
        stamp = _timestamp(groups["timestamp"])
        row.update({
            "timestamp": stamp,
            "timestamp_status": "assumed_utc" if stamp else "missing",
            "pid": int(groups["pid"]) if groups.get("pid") else None,
            "severity": _SEVERITY.get(groups["level"], groups["level"].lower()),
            "component": groups["component"],
            "message": message[:2000],
            "event_action": "log",
        })
        jail_match = _JAIL_RE.match(message)
        if jail_match:
            rest = jail_match.group("rest")
            row["jail"] = jail_match.group("jail")
            for pattern, action in _JAIL_ACTIONS:
                if pattern.match(rest):
                    row["event_action"] = action
                    break
            ip_match = _IP_RE.search(rest)
            ip = _valid_ip(ip_match.group(1)) if ip_match else ""
            if ip:
                row["source_ip"] = ip
        else:
            for pattern, action in _SERVER_ACTIONS:
                matched = pattern.match(message)
                if matched:
                    row["event_action"] = action
                    row["jail"] = matched.group("jail")
                    break
        rows.append(row)
    return rows
