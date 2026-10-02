"""Apache HTTP Server and nginx access/error log parser.

The two servers share the NCSA ``combined`` access format, so one parser serves both; nginx
adds its own error-log layout and is often configured to write JSON access lines, both
handled here. ``web_server`` records which one the file came from (decided by its path),
and ``x_forwarded_for`` keeps the real client address when a proxy or load balancer sits in
front, since ``source_ip`` is then the proxy's.
"""
from __future__ import annotations

import base64
import binascii
import ipaddress
import json
from datetime import datetime, timezone
import re
from urllib.parse import unquote


# Generic reverse-shell / web-shell indicator vocabulary -- widely used
# across DFIR and IDS signature sets, not tied to any one CTF's payload.
# Matched against the *decoded* request line, never executed.
_SUSPICIOUS_KEYWORDS = (
    "/bin/sh", "/bin/bash", "bash -i", "sh -i", "nc -e", "ncat ", "netcat ",
    "python -c", "python3 -c", "perl -e", "php -r", "wget ", "curl ",
    "base64_decode", "eval(", "exec(", "system(", "passthru(", "shell_exec(",
    "$_get", "$_post", "$_request", "cmd=", "../../", "..%2f", "%00",
)
_BASE64_CANDIDATE_RE = re.compile(r"[A-Za-z0-9+/]{16,}={0,2}")
_IP_PORT_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b[:\s]+\d{2,5}\b")
_MAX_DECODED_LEN = 4000


def _decode_url_safe(value: str) -> str:
    """Percent-decode a URL path/query passively -- never executes anything,
    just reveals what a payload actually says once URL-encoding is undone."""
    if not value:
        return ""
    try:
        return unquote(value, errors="replace")[:_MAX_DECODED_LEN]
    except Exception:  # noqa: BLE001
        return value[:_MAX_DECODED_LEN]


def _decode_base64_segments(text: str) -> list[str]:
    """Passively decode base64-looking substrings, keeping only results that
    are mostly printable text -- a safe reveal, never an execution."""
    decoded: list[str] = []
    for match in _BASE64_CANDIDATE_RE.finditer(text):
        candidate = match.group(0)
        if len(decoded) >= 5:
            break
        try:
            raw = base64.b64decode(candidate + "=" * (-len(candidate) % 4), validate=False)
        except (binascii.Error, ValueError):
            continue
        try:
            as_text = raw.decode("utf-8")
        except UnicodeDecodeError:
            continue
        printable = sum(1 for ch in as_text if ch.isprintable())
        if as_text and printable / len(as_text) > 0.85:
            decoded.append(as_text[:500])
    return decoded


def _suspicious_indicators(decoded_url: str, base64_decoded: list[str]) -> list[str]:
    haystack = " ".join([decoded_url, *base64_decoded]).lower()
    indicators = [keyword.strip("(") for keyword in _SUSPICIOUS_KEYWORDS if keyword in haystack]
    if base64_decoded:
        indicators.append("embedded_base64")
    if _IP_PORT_RE.search(" ".join([decoded_url, *base64_decoded])):
        indicators.append("ip_port_reference")
    return sorted(set(indicators))


_ACCESS_RE = re.compile(
    r'^(?P<remote_host>\S+)\s+(?P<remote_logname>\S+)\s+(?P<remote_user>\S+)\s+'
    r'\[(?P<timestamp>[^\]]+)\]\s+"(?P<request>[^"]*)"\s+(?P<status>\d{3}|-)\s+'
    r'(?P<bytes>\d+|-)(?:\s+"(?P<referrer>[^"]*)"\s+"(?P<user_agent>[^"]*)")?'
    r'(?:\s+"(?P<forwarded>[^"]*)")?.*$'
)
# nginx error log: "2024/03/01 10:20:30 [error] 7#7: *1 message, client: ..., server: ..."
_NGINX_ERROR_RE = re.compile(
    r"^(?P<timestamp>\d{4}/\d{2}/\d{2} \d{2}:\d{2}:\d{2}) \[(?P<severity>\w+)\] "
    r"(?P<pid>\d+)#(?P<tid>\d+): (?:\*(?P<connection>\d+) )?(?P<message>.*)$"
)
_NGINX_CONTEXT_RE = re.compile(r'(?:^|, )(?P<key>client|server|request|upstream|host|referrer): (?P<value>"[^"]*"|[^,]*)')
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


def _web_server(source_path: str) -> str:
    lowered = source_path.replace("\\", "/").lower()
    if "/nginx/" in lowered or lowered.startswith("nginx/"):
        return "nginx"
    if any(token in lowered for token in ("/apache2/", "/httpd/", "apache2/", "httpd/")):
        return "apache"
    return ""


def _real_client(forwarded: str | None) -> str:
    """The first valid IP of an X-Forwarded-For style value (the original client)."""
    for token in str(forwarded or "").split(","):
        candidate = token.strip().strip("[]")
        try:
            return str(ipaddress.ip_address(candidate))
        except ValueError:
            continue
    return ""


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
        parsed["web_server"] = parsed.get("web_server") or _web_server(source_path)
        results.append(parsed)
    return results


_JSON_TIME_KEYS = ("time_iso8601", "@timestamp", "timestamp", "time", "time_local")
_JSON_IP_KEYS = ("remote_addr", "client_ip", "clientip", "client", "src_ip")


def _json_first(record: dict, keys: tuple[str, ...]) -> str:
    for key in keys:
        value = record.get(key)
        if value not in (None, "", "-"):
            return str(value)
    return ""


def _json_timestamp(value: str) -> str | None:
    if not value:
        return None
    parsed = _parse_access_timestamp(value)
    if parsed:
        return parsed
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00")).astimezone(timezone.utc).isoformat()
    except ValueError:
        return None


def _parse_json_access_line(record: dict, line: str, source_path: str, line_number: int) -> dict:
    request = _json_first(record, ("request",))
    method = _json_first(record, ("request_method", "method"))
    path = _json_first(record, ("request_uri", "uri", "url", "path"))
    if request:
        request_match = _REQUEST_RE.match(request)
        if request_match:
            method = method or (request_match.group("method") or "")
            path = path or (request_match.group("path") or "")
    status = _int_or_none(_json_first(record, ("status", "response_status", "http_status")))
    decoded_path = _decode_url_safe(path)
    base64_decoded = _decode_base64_segments(decoded_path)
    forwarded = _real_client(_json_first(record, ("http_x_forwarded_for", "x_forwarded_for", "xff")))
    return {
        "artifact_family": "linux_apache",
        "artifact_type": "apache_access",
        "source_file": source_path,
        "line_number": line_number,
        "timestamp": _json_timestamp(_json_first(record, _JSON_TIME_KEYS)),
        "message": f"{method} {path} {status or '-'}".strip(),
        "raw_excerpt": line[:2000],
        "source_ip": _json_first(record, _JSON_IP_KEYS),
        "username": _json_first(record, ("remote_user", "user")),
        "http_method": method,
        "url_path": path,
        "url_path_decoded": decoded_path,
        "url_base64_decoded": base64_decoded,
        "suspicious_url_indicators": _suspicious_indicators(decoded_path, base64_decoded),
        "http_protocol": _json_first(record, ("server_protocol", "protocol")),
        "http_status": status,
        "bytes_sent": _int_or_none(_json_first(record, ("body_bytes_sent", "bytes_sent", "bytes"))),
        "http_referrer": _json_first(record, ("http_referer", "http_referrer", "referer", "referrer")),
        "http_user_agent": _json_first(record, ("http_user_agent", "user_agent", "agent")),
        "x_forwarded_for": forwarded,
        "log_format": "json",
    }


def _parse_access_line(line: str, source_path: str, line_number: int) -> dict:
    if line.startswith("{"):
        try:
            record = json.loads(line)
        except ValueError:
            record = None
        if isinstance(record, dict):
            return _parse_json_access_line(record, line, source_path, line_number)
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
    decoded_path = _decode_url_safe(path)
    referrer = "" if groups.get("referrer") == "-" else groups.get("referrer") or ""
    base64_decoded = _decode_base64_segments(decoded_path)
    suspicious = _suspicious_indicators(decoded_path, base64_decoded)
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
        # Passive decoding only -- percent-decoding and, where a segment
        # looks base64-encoded, a best-effort printable-text decode. Never
        # executed, never fetched, never evaluated.
        "url_path_decoded": decoded_path,
        "url_base64_decoded": base64_decoded,
        "suspicious_url_indicators": suspicious,
        "http_protocol": protocol,
        "http_status": status_code,
        "bytes_sent": _int_or_none(groups.get("bytes")),
        "http_referrer": referrer,
        "http_user_agent": "" if groups.get("user_agent") == "-" else groups.get("user_agent") or "",
        "x_forwarded_for": _real_client(groups.get("forwarded")),
    }


def _parse_nginx_error_line(match: re.Match[str], line: str, source_path: str, line_number: int) -> dict:
    groups = match.groupdict()
    context = {m.group("key"): m.group("value").strip().strip('"') for m in _NGINX_CONTEXT_RE.finditer(groups["message"])}
    client_ip, client_port = _split_client(context.get("client"))
    try:
        # nginx writes the server's local time with no zone: read as UTC and say so.
        timestamp = datetime.strptime(groups["timestamp"], "%Y/%m/%d %H:%M:%S").replace(tzinfo=timezone.utc).isoformat()
    except ValueError:
        timestamp = None
    request = context.get("request", "")
    request_match = _REQUEST_RE.match(request) if request else None
    return {
        "artifact_family": "linux_apache",
        "artifact_type": "apache_error",
        "source_file": source_path,
        "line_number": line_number,
        "timestamp": timestamp,
        "timestamp_status": "assumed_utc" if timestamp else "missing",
        "message": groups["message"][:2000],
        "raw_excerpt": line[:2000],
        "process": "nginx",
        "pid": _int_or_none(groups.get("pid")),
        "source_ip": client_ip,
        "source_port": client_port,
        "http_severity": (groups.get("severity") or "error").lower(),
        "thread_id": _int_or_none(groups.get("tid")),
        "web_server": "nginx",
        "http_method": request_match.group("method") if request_match else "",
        "url_path": request_match.group("path") if request_match else "",
        "server_name": context.get("server", ""),
        "upstream": context.get("upstream", ""),
        "http_host": context.get("host", ""),
        "http_referrer": context.get("referrer", ""),
    }


def _parse_error_line(line: str, source_path: str, line_number: int) -> dict:
    nginx_match = _NGINX_ERROR_RE.match(line)
    if nginx_match:
        return _parse_nginx_error_line(nginx_match, line, source_path, line_number)
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
