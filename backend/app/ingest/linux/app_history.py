"""Interactive client histories: what was typed into database clients and language REPLs.

Each client keeps its own file in the user's home directory, written by readline, libedit or the
client itself. None of them records when an entry was typed, so the rows are undated; their order
is the order the entries were typed in (``history_index``, 1 = oldest). Every format below was
checked against files written by the real clients:

* ``~/.mysql_history`` (MySQL client) and ``~/.mariadb_history`` (MariaDB 11 client): libedit.
* ``~/.psql_history`` (PostgreSQL psql): readline; the lines of a multi-line query are joined by
  ``\\x01``.
* ``~/.sqlite_history`` (sqlite3): readline, or libedit where sqlite3 is built with it.
* ``~/.python_history`` (Python REPL): readline; Python 3.13's REPL writes the lines of a
  multi-line entry ending in ``\\r\\n``.
* ``~/.node_repl_history`` (Node.js REPL): one entry per line, newest first.

libedit files start with ``_HiStOrY_V2_`` and encode spaces, tabs, newlines and backslashes as
``strvis(3)`` escapes (``\\040``); any client's file in that format is decoded the same way.
SQL statements and REPL input are not process launches, so these rows are kept out of the shell
history family (and out of Sigma's process-creation rules).
"""
from __future__ import annotations

import re
from pathlib import PurePosixPath

ARTIFACT_FAMILY = "linux_app_history"
MAX_COMMAND = 4000
MAX_TEXT = 2000

# Basename -> client.
APP_HISTORY_FILES: dict[str, str] = {
    ".mysql_history": "mysql",
    ".mariadb_history": "mariadb",
    ".psql_history": "psql",
    ".sqlite_history": "sqlite3",
    ".python_history": "python",
    ".node_repl_history": "node",
}

_LIBEDIT_HEADER = "_HiStOrY_V2_"
_PSQL_NEWLINE = "\x01"
_OCTAL_RE = re.compile(r"\\([0-7]{3})")


def app_history_client(source_path: str) -> str | None:
    name = PurePosixPath(str(source_path or "").replace("\\", "/")).name
    return APP_HISTORY_FILES.get(name)


def _unvis(line: str) -> str:
    """Undo libedit's strvis(3) encoding of one history line."""
    out: list[str] = []
    index = 0
    while index < len(line):
        char = line[index]
        if char != "\\" or index + 1 >= len(line):
            out.append(char)
            index += 1
            continue
        octal = _OCTAL_RE.match(line, index)
        if octal:
            out.append(chr(int(octal.group(1), 8)))
            index += 4
            continue
        following = line[index + 1]
        if following == "\\":
            out.append("\\")
            index += 2
        elif following == "^" and index + 2 < len(line):
            # \^X: a control character.
            out.append(chr(ord(line[index + 2]) & 0x1F))
            index += 3
        elif following == "M" and index + 3 < len(line) and line[index + 2] in "-^":
            # \M-x and \M^x: a character with the high bit set.
            base = ord(line[index + 3])
            out.append(chr((base & 0x1F if line[index + 2] == "^" else base) | 0x80))
            index += 4
        elif following == "$":
            # An encoded empty string.
            index += 2
        else:
            out.append(char)
            index += 1
    return "".join(out)


def _entries(content: str, client: str) -> list[tuple[int, str]]:
    """(line number, entry) pairs in the order the entries were typed."""
    lines = content.split("\n")
    if lines and lines[-1] == "":
        lines.pop()
    entries: list[tuple[int, str]] = []
    if lines and lines[0].strip() == _LIBEDIT_HEADER:
        for number, line in enumerate(lines[1:], start=2):
            entries.append((number, _unvis(line.rstrip("\r"))))
    elif client == "python":
        # Python 3.13+ ends the inner lines of a multi-line entry with \r\n.
        start, parts = 0, []
        for number, line in enumerate(lines, start=1):
            if not parts:
                start = number
            if line.endswith("\r"):
                parts.append(line[:-1])
                continue
            parts.append(line)
            # The REPL's auto-indent leaves a blank last line on a block.
            entries.append((start, "\n".join(parts).rstrip()))
            parts = []
        if parts:
            entries.append((start, "\n".join(parts).rstrip()))
    else:
        for number, line in enumerate(lines, start=1):
            entry = line.rstrip("\r")
            if client == "psql":
                entry = entry.replace(_PSQL_NEWLINE, "\n")
            entries.append((number, entry))
    if client == "node":
        entries.reverse()
    return [(number, entry) for number, entry in entries if entry.strip()]


def _infer_username(source_path: str) -> str | None:
    path = "/" + str(source_path or "").replace("\\", "/").lstrip("/")
    match = re.search(r"/home/([^/]+)/", path)
    if match:
        return match.group(1)
    if "/root/" in path:
        return "root"
    return None


def parse_app_history(content: str, *, source_path: str = "", truncated: bool = False) -> list[dict]:
    client = app_history_client(source_path) or "unknown"
    username = _infer_username(source_path)
    results: list[dict] = []
    for index, (line_number, entry) in enumerate(_entries(content, client), start=1):
        command = entry[:MAX_COMMAND]
        results.append({
            "artifact_family": ARTIFACT_FAMILY,
            "artifact_type": f"{client}_history",
            "source_file": source_path,
            "line_number": line_number,
            "history_index": index,
            "app_client": client,
            "username": username,
            "command": command,
            "timestamp": None,
            "timestamp_status": "missing",
            "message": command[:MAX_TEXT],
            "raw_excerpt": command[:MAX_TEXT],
        })
    if truncated and results:
        results[-1]["truncated"] = True
    return results
