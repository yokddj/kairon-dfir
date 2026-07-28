"""Exim MTA main/reject/panic log parser."""
from __future__ import annotations

from datetime import datetime, timezone
import re


_LINE_RE = re.compile(r"^(?P<timestamp>\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2})\s+(?P<body>.*)$")
_QUEUE_RE = re.compile(r"\b(?P<queue_id>[A-Za-z0-9]{5,}-[A-Za-z0-9]{5,}-[A-Za-z0-9]{2})\b")
_ADDR_RE = re.compile(r"[A-Za-z0-9.!#$%&'*+/=?^_`{|}~-]+@[A-Za-z0-9.-]+")
_IP_RE = re.compile(r"\[(?P<ip>[0-9A-Fa-f:.]+)\](?::(?P<port>\d+))?")
_HELO_RE = re.compile(r"\bH=(?P<helo>[^\s\[]+)")
_AUTH_RE = re.compile(r"\bA=(?P<auth>\S+)")
_MSGID_RE = re.compile(r"\bid=(?P<message_id><[^>]+>|[^\s]+)")
_SMTP_STATUS_RE = re.compile(r"\bC=(?P<status>[245]\d\d)\b")
_LOCAL_IP_RE = re.compile(r"\bI=\[(?P<ip>[0-9A-Fa-f:.]+)\](?::(?P<port>\d+))?")
_REJECT_FROM_RE = re.compile(r"\b(?:RCPT|MAIL)\s+from\s+(?P<helo>[^\s\[]+)")


def _exim_type(source_path: str) -> str:
    name = source_path.replace("\\", "/").rsplit("/", 1)[-1].lower()
    if name.startswith("rejectlog"):
        return "exim_reject"
    if name.startswith("paniclog"):
        return "exim_panic"
    return "exim_main"


def _parse_timestamp(value: str) -> str | None:
    try:
        return datetime.strptime(value, "%Y-%m-%d %H:%M:%S").replace(tzinfo=timezone.utc).isoformat()
    except ValueError:
        return None


def _int_or_none(value: str | None) -> int | None:
    if not value:
        return None
    try:
        return int(value)
    except ValueError:
        return None


def _first(pattern: re.Pattern[str], text: str, group: str) -> str:
    match = pattern.search(text)
    return match.group(group) if match else ""


def _smtp_status(body: str) -> str:
    match = _SMTP_STATUS_RE.search(body)
    return match.group("status") if match else ""


def parse_exim(content: str, *, source_path: str = "") -> list[dict]:
    results: list[dict] = []
    artifact_type = _exim_type(source_path)
    for line_number, line in enumerate(content.splitlines(), start=1):
        stripped = line.strip()
        if not stripped:
            continue
        results.append(_parse_line(stripped, source_path, line_number, artifact_type))
    return results


def _parse_line(line: str, source_path: str, line_number: int, artifact_type: str) -> dict:
    timestamp = None
    body = line
    match = _LINE_RE.match(line)
    if match:
        timestamp = _parse_timestamp(match.group("timestamp"))
        body = match.group("body") or ""

    action = _action_from_body(body, artifact_type)
    addresses = _ADDR_RE.findall(body)
    sender = _sender_from_body(body, addresses)
    recipient = _recipient_from_body(body, addresses)
    remote_ip, remote_port = _remote_endpoint(body)
    local_ip, local_port = _local_endpoint(body)
    smtp_status = _smtp_status(body)
    outcome = _outcome(action, smtp_status, artifact_type)
    severity = _severity(action, artifact_type)
    message_id = _first(_MSGID_RE, body, "message_id").strip("<>")
    helo = _first(_HELO_RE, body, "helo") or _first(_REJECT_FROM_RE, body, "helo")

    return {
        "artifact_family": "linux_exim",
        "artifact_type": artifact_type,
        "source_file": source_path,
        "line_number": line_number,
        "timestamp": timestamp,
        "message": body[:2000],
        "raw_excerpt": line[:2000],
        "event_action": action,
        "event_outcome": outcome,
        "event_severity": severity,
        "source_ip": remote_ip,
        "source_port": remote_port,
        "destination_ip": local_ip,
        "destination_port": local_port,
        "sender": sender,
        "recipient": recipient,
        "queue_id": _first(_QUEUE_RE, body, "queue_id"),
        "message_id": message_id,
        "smtp_status": _int_or_none(smtp_status),
        "remote_ip": remote_ip,
        "local_ip": local_ip,
        "helo": helo,
        "authentication": _first(_AUTH_RE, body, "auth"),
    }


def _action_from_body(body: str, artifact_type: str) -> str:
    lower = body.lower()
    if artifact_type == "exim_panic":
        return "panic"
    if "<= " in body:
        return "message_received"
    if "=> " in body or "-> " in body:
        return "message_delivered"
    if "** " in body:
        return "delivery_failed"
    if "== " in body:
        return "delivery_deferred"
    if "completed" in lower:
        return "message_completed"
    if "rejected" in lower or artifact_type == "exim_reject":
        return "message_rejected"
    return artifact_type


def _outcome(action: str, smtp_status: str, artifact_type: str) -> str:
    if artifact_type == "exim_panic" or action in {"delivery_failed", "message_rejected"}:
        return "failure"
    if action == "delivery_deferred" or smtp_status.startswith("4"):
        return "unknown"
    if smtp_status.startswith("5"):
        return "failure"
    if action in {"message_received", "message_delivered", "message_completed"} or smtp_status.startswith("2"):
        return "success"
    return "unknown"


def _severity(action: str, artifact_type: str) -> str:
    if artifact_type == "exim_panic":
        return "high"
    if action in {"delivery_failed", "message_rejected"}:
        return "medium"
    if action == "delivery_deferred":
        return "low"
    return "info"


def _sender_from_body(body: str, addresses: list[str]) -> str:
    if "<= <>" in body:
        return "<>"
    match = re.search(r"\b(?:F=|from\s+|MAIL\s*)<(?P<addr>[^>]+)>", body, re.IGNORECASE)
    if match:
        return match.group("addr")
    if "<= " in body:
        return addresses[0] if addresses else ""
    return ""


def _recipient_from_body(body: str, addresses: list[str]) -> str:
    if any(marker in body for marker in ("=> ", "-> ", "** ", "== ")):
        return addresses[0] if addresses else ""
    match = re.search(r"\bRCPT\s+(?P<addr>[^\s:]+@[^\s:]+)", body, re.IGNORECASE)
    if match:
        return match.group("addr")
    match = re.search(r"\brecipient\b[^:]*:\s*(?P<addr>[^\s]+@[^\s]+)", body, re.IGNORECASE)
    return match.group("addr") if match else ""


def _remote_endpoint(body: str) -> tuple[str, int | None]:
    # Prefer H=... [remote] over I=[local].
    before_local = body.split(" I=[", 1)[0]
    match = _IP_RE.search(before_local)
    if match:
        return match.group("ip"), _int_or_none(match.group("port"))
    return "", None


def _local_endpoint(body: str) -> tuple[str, int | None]:
    match = _LOCAL_IP_RE.search(body)
    if match:
        return match.group("ip"), _int_or_none(match.group("port"))
    return "", None
