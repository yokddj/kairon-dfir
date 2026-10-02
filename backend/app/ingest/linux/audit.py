"""Audit log parser for auditd."""
from __future__ import annotations
import re
from datetime import datetime, timezone

_AUDIT_TYPE_RE = re.compile(r"^type=(\S+)")
_KEY_VALUE_RE = re.compile(r"(\w+)=(?:\"([^\"]*)\"|'([^']*)'|(\S+))")
_AUDIT_TIMESTAMP_RE = re.compile(r"msg=audit\((\d+\.?\d*):(\d+)\)")
_QUOTED_MSG_RE = re.compile(r"\bmsg='([^']*)'")
_HEX_RE = re.compile(r"^(?:[0-9A-Fa-f]{2})+$")
_ARG_KEY_RE = re.compile(r"^a(\d+)$")

# auditd writes a string field in double quotes when it is plain text and as an unquoted
# hex dump when it contains anything awkward (spaces, quotes, control characters).
# "(null)" is its placeholder for an absent value.
_NULL = "(null)"
# Fields whose unquoted form is a hex-encoded string. Everything else unquoted (pid=,
# uid=, success=, a0..a3 of a SYSCALL record, which are raw register values) is left alone.
_HEX_STRING_FIELDS = frozenset({"exe", "comm", "cwd", "name", "cmd", "proctitle", "key", "acct"})
MAX_EXECVE_ARGS = 64


def _with_msg_fields(line: str) -> str:
    """Append the body of ``msg='...'`` so its key=value pairs are seen individually.

    User-space records (USER_CMD, USER_AUTH, ...) wrap cmd=, exe=, cwd=, acct= in
    ``msg='...'``; matched as one single-quoted value they were never extracted.
    """
    inner = _QUOTED_MSG_RE.search(line)
    return f"{line} {inner.group(1)}" if inner else line


def _extract_key_values(line: str) -> dict[str, str]:
    result: dict[str, str] = {}
    for m in _KEY_VALUE_RE.finditer(_with_msg_fields(line)):
        key = m.group(1)
        value = m.group(2) or m.group(3) or m.group(4)
        if value:
            result[key] = value
    return result


def _extract_typed_values(line: str) -> dict[str, tuple[str, bool]]:
    """Like ``_extract_key_values`` but remembers whether each value was quoted."""
    result: dict[str, tuple[str, bool]] = {}
    for m in _KEY_VALUE_RE.finditer(_with_msg_fields(line)):
        quoted = m.group(2) is not None or m.group(3) is not None
        value = m.group(2) if m.group(2) is not None else m.group(3) if m.group(3) is not None else m.group(4)
        if value:
            result[m.group(1)] = (value, quoted)
    return result


def _decode_hex(value: str) -> str | None:
    """Decode an auditd hex-encoded string, or None when it is not printable text."""
    if not _HEX_RE.match(value):
        return None
    try:
        text = bytes.fromhex(value).decode("utf-8")
    except (ValueError, UnicodeDecodeError):
        return None
    # proctitle and EXECVE arguments separate argv entries with NUL bytes.
    text = text.replace("\x00", " ").strip()
    return text if text and all(ch.isprintable() or ch in "\t " for ch in text) else None


def _string_field(typed: dict[str, tuple[str, bool]], key: str) -> str | None:
    item = typed.get(key)
    if not item:
        return None
    value, quoted = item
    if value == _NULL:
        return None
    if not quoted and key in _HEX_STRING_FIELDS:
        decoded = _decode_hex(value)
        if decoded is not None:
            return decoded
    return value


def _execve_arguments(typed: dict[str, tuple[str, bool]]) -> list[str]:
    indexed: list[tuple[int, str]] = []
    for key, (value, quoted) in typed.items():
        match = _ARG_KEY_RE.match(key)
        if not match:
            continue
        text = value if quoted else (_decode_hex(value) or value)
        indexed.append((int(match.group(1)), text))
    indexed.sort()
    return [text for _, text in indexed[:MAX_EXECVE_ARGS]]


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
        typed = _extract_typed_values(stripped)

        timestamp = None
        ts_match = _AUDIT_TIMESTAMP_RE.search(stripped)
        if ts_match:
            try:
                epoch = float(ts_match.group(1))
                timestamp = datetime.fromtimestamp(epoch, tz=timezone.utc).isoformat()
            except (ValueError, OverflowError, OSError):
                pass

        uid = kv.get("uid")
        auid = kv.get("auid")
        pid = int(kv["pid"]) if kv.get("pid") and kv["pid"].isdigit() else None
        ppid = int(kv["ppid"]) if kv.get("ppid") and kv["ppid"].isdigit() else None
        exe = _string_field(typed, "exe")
        cwd = _string_field(typed, "cwd")
        comm = _string_field(typed, "comm")
        success = kv.get("success")

        # "command" keeps its historical meaning (the short process name from comm=) except
        # on records that actually carry a command line, where it becomes that line.
        command_line: str | None = None
        arguments: list[str] = []
        if audit_type == "EXECVE":
            arguments = _execve_arguments(typed)
            command_line = " ".join(arguments) or None
        elif audit_type == "USER_CMD":
            command_line = _string_field(typed, "cmd")
        elif audit_type == "PROCTITLE":
            command_line = _string_field(typed, "proctitle")
        command = command_line or comm

        message_parts = []
        for key in ("res", "op", "name", "acct", "terminal", "exe", "dir", "comm", "cmd"):
            if key in kv:
                message_parts.append(f"{key}={kv[key]}")
        if command_line and audit_type == "EXECVE":
            message_parts.append(f"argv={command_line}")
        message = "; ".join(message_parts) or stripped

        row = {
            "artifact_family": "linux_audit",
            "artifact_type": "audit_log",
            "source_file": source_path,
            "line_number": line_number,
            "timestamp": timestamp,
            "audit_type": audit_type,
            "uid": uid,
            "auid": auid,
            "euid": kv.get("euid"),
            "pid": pid,
            "ppid": ppid,
            "exe": exe,
            "cwd": cwd,
            "comm": comm,
            "command": command,
            "command_line": command_line,
            "syscall": kv.get("syscall"),
            "audit_key": _string_field(typed, "key"),
            "audit_name": _string_field(typed, "name"),
            "success": success,
            "message": message[:2000],
            "raw_excerpt": raw_excerpt,
        }
        for index, argument in enumerate(arguments[:8]):
            row[f"audit_a{index}"] = argument[:1024]
        results.append(row)
    return results
