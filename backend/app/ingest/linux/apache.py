"""Apache HTTP Server access/error log parser."""
from __future__ import annotations

from datetime import datetime, timezone
import re


_ACCESS_RE = re.compile(
    r'^(?P<remote_host>\S+)\s+(?P<remote_logname>\S+)\s+(?P<remote_user>\S+)\s+'
    r'\[(?P<timestamp>[^\]]+)\]\s+"(?P<request>[^"]*)"\s+(?P<status>\d{3}|-)\s+'
    r'(?P<bytes>\d+|-)(?:\s+"(?P<referrer>[^"]*)"\s+"(?P<user_agent>[^"]*)")?.*$'
)
_REQUEST_RE = re.compile(r"^(?P<method>\S+)\s+(?P<path>\S+)(?:\s+(?P<protocol>HTTP/[^\s]+))?")
_ERROR_RE = re.compile(
    r"^\[(?P<timestamp>[^\]]+)\]\s+\[(?P<module>[^:\]]+)(?::(?P<severity>[^\]]+))?\]"
    r"(?:\s+\[pid\s+(?P<pid>\d+)(?::tid\s+(?P<tid>\d+))?\])?"
    r"(?:\s+\[client\s+(?P<client>[^\]]+)\])?\s*(?P<message>.*)$"
)


def _parse_access_timestamp(value: str) -> str | None:
    try:
        return datetime.strptime(value.strip(), "%d/%b/%Y:%H:%M:%S %z").isoformat()
    except ValueError:
        return None


def _parse_error_timestamp(value: str) -> str | None:
    text = value.strip()
    for fmt in ("%a %b %d %H:%M:%S.%f %Y", "%a %b %d %H:%M:%S %Y"):
        try:
            return datetime.strptime(text, fmt).replace(tzinfo=timezone.utc).isoformat()
        except ValueError:
            continue
    return None


def _int_or_none(value: str | None) -> int | None:
    if not value or value == "-":
        return None
    try:
        return int(value)
    except ValueError:
        return None


def _split_client(value: str | None) -> tuple[str, int | None]:
    if not value:
        return "", None
    text = value.strip()
    if ":" in text and not text.startswith("["):
        host, port = text.rsplit(":", 1)
        return host, _int_or_none(port)
    if text.startswith("[") and "]:" in text:
        host, port = text.rsplit(":", 1)
        return host.strip("[]"), _int_or_none(port)
    return text.strip("[]"), None


def _apache_type(source_path: str) -> str:
    name = source_path.replace("\\", "/").rsplit("/", 1)[-1].lower()
    return "apache_error" if "error" in name else "apache_access"


def parse_apache(content: str, *, source_path: str = "") -> list[dict]:
    results: list[dict] = []
    apache_type = _apache_type(source_path)
    for line_number, line in enumerate(content.splitlines(), start=1):
        stripped = line.strip()
        if not stripped:
            continue
        if apache_type == "apache_error":
            parsed = _parse_error_line(stripped, source_path, line_number)
        else:
            parsed = _parse_access_line(stripped, source_path, line_number)
        results.append(parsed)
    return results


def _parse_access_line(line: str, source_path: str, line_number: int) -> dict:
    match = _ACCESS_RE.match(line)
    if not match:
        return _fallback_row("apache_access", line, source_path, line_number)
    groups = match.groupdict()
    request = groups.get("request") or ""
    request_match = _REQUEST_RE.match(request)
    method = path = protocol = ""
    if request_match:
        method = request_match.group("method") or ""
        path = request_match.group("path") or ""
        protocol = request_match.group("protocol") or ""
    status_code = _int_or_none(groups.get("status"))
    message = f"{method} {path} {status_code or '-'}".strip()
    return {
        "artifact_family": "linux_apache",
        "artifact_type": "apache_access",
        "source_file": source_path,
        "line_number": line_number,
        "timestamp": _parse_access_timestamp(groups.get("timestamp") or ""),
        "message": message,
        "raw_excerpt": line[:2000],
        "source_ip": groups.get("remote_host") or "",
        "username": "" if groups.get("remote_user") == "-" else groups.get("remote_user") or "",
        "http_method": method,
        "url_path": path,
        "http_protocol": protocol,
        "http_status": status_code,
        "bytes_sent": _int_or_none(groups.get("bytes")),
        "http_referrer": "" if groups.get("referrer") == "-" else groups.get("referrer") or "",
        "http_user_agent": "" if groups.get("user_agent") == "-" else groups.get("user_agent") or "",
    }


def _parse_error_line(line: str, source_path: str, line_number: int) -> dict:
    match = _ERROR_RE.match(line)
    if not match:
        return _fallback_row("apache_error", line, source_path, line_number)
    groups = match.groupdict()
    client_ip, client_port = _split_client(groups.get("client"))
    severity = (groups.get("severity") or "error").lower()
    message = groups.get("message") or line
    return {
        "artifact_family": "linux_apache",
        "artifact_type": "apache_error",
        "source_file": source_path,
        "line_number": line_number,
        "timestamp": _parse_error_timestamp(groups.get("timestamp") or ""),
        "message": message[:2000],
        "raw_excerpt": line[:2000],
        "process": groups.get("module") or "apache",
        "pid": _int_or_none(groups.get("pid")),
        "source_ip": client_ip,
        "source_port": client_port,
        "http_severity": severity,
        "apache_module": groups.get("module") or "",
        "thread_id": _int_or_none(groups.get("tid")),
    }


def _fallback_row(artifact_type: str, line: str, source_path: str, line_number: int) -> dict:
    return {
        "artifact_family": "linux_apache",
        "artifact_type": artifact_type,
        "source_file": source_path,
        "line_number": line_number,
        "timestamp": None,
        "message": line[:2000],
        "raw_excerpt": line[:2000],
    }
