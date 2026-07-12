"""Audit log parser for auditd."""
from __future__ import annotations
import re

_AUDIT_TYPE_RE = re.compile(r"^type=(\S+)")
_KEY_VALUE_RE = re.compile(r"(\w+)=(?:\"([^\"]*)\"|'([^']*)'|(\S+))")
_AUDIT_TIMESTAMP_RE = re.compile(r"msg=audit\((\d+\.?\d*):(\d+)\)")


def _extract_key_values(line: str) -> dict[str, str]:
    result: dict[str, str] = {}
    for m in _KEY_VALUE_RE.finditer(line):
        key = m.group(1)
        value = m.group(2) or m.group(3) or m.group(4)
        if value:
            result[key] = value
    return result


def parse_audit(
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

        audit_type_match = _AUDIT_TYPE_RE.search(stripped)
        if not audit_type_match:
            continue

        audit_type = audit_type_match.group(1)
        kv = _extract_key_values(stripped)

        timestamp = None
        ts_match = _AUDIT_TIMESTAMP_RE.search(stripped)
        if ts_match:
            try:
                epoch = float(ts_match.group(1))
                from datetime import datetime, timezone
                timestamp = datetime.fromtimestamp(epoch, tz=timezone.utc).isoformat()
            except (ValueError, OverflowError, OSError):
                pass

        uid = kv.get("uid")
        auid = kv.get("auid")
        pid = int(kv["pid"]) if kv.get("pid") and kv["pid"].isdigit() else None
        exe = kv.get("exe")
        cwd = kv.get("cwd")
        command = kv.get("comm")
        success = kv.get("success")

        message_parts = []
        for key in ("res", "op", "name", "acct", "terminal", "exe", "dir", "comm", "cmd"):
            if key in kv:
                message_parts.append(f"{key}={kv[key]}")
        message = "; ".join(message_parts) or stripped

        results.append({
            "artifact_family": "linux_audit",
            "artifact_type": "audit_log",
            "source_file": source_path,
            "line_number": line_number,
            "timestamp": timestamp,
            "audit_type": audit_type,
            "uid": uid,
            "auid": auid,
            "pid": pid,
            "exe": exe,
            "cwd": cwd,
            "command": command,
            "success": success,
            "message": message[:2000],
            "raw_excerpt": raw_excerpt,
        })
    return results
