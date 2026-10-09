"""PowerShell history files (PSReadLine) recovered from a memory image.

PSReadLine, PowerShell's line editor since Windows 10, appends every command typed at an
interactive prompt to ``%APPDATA%\\Microsoft\\Windows\\PowerShell\\PSReadLine\\<host>_history.txt``
(ConsoleHost_history.txt for powershell.exe and pwsh.exe consoles). The file outlives the
session, so it holds commands from earlier sessions too, which neither conhost's history lists
nor the console screens have. When Windows still has that file cached, windows.filescan finds its
_FILE_OBJECT and windows.dumpfiles recovers the cached pages.

Output rows: {"User", "Path", "Line", "Command", "FileObject"}, one per command, in the order the
file lists them (oldest first). The file has no timestamps, so commands have none either. A file
recovered only in part (pages no longer cached come back as zeros) gives the commands on the
pages that were.
"""

from __future__ import annotations

import json
import re
import time
from collections.abc import Callable
from pathlib import Path
from typing import Any

KAIRON_PSREADLINE_PLUGIN = "kairon.psreadline"
SOURCE_PLUGINS = ("windows.filescan", "windows.dumpfiles")

_HISTORY_FILE = re.compile(r"\\Microsoft\\Windows\\PowerShell\\PSReadLine\\[^\\]*_history\.txt$", re.I)
_USER = re.compile(r"\\Users\\(?P<user>[^\\]+)\\", re.I)
# One user rarely has more than a few history files (console, VS Code, ISE); a bound keeps a
# strange image from fanning out to hundreds of dumps.
MAX_FILE_OBJECTS = 20
_MAX_COMMAND = 8192


def history_file_objects(filescan_rows: list[dict[str, Any]]) -> list[dict[str, str]]:
    """The PSReadLine history files among windows.filescan's rows: {"offset", "path", "user"}."""
    found = []
    for row in filescan_rows:
        name = row.get("Name")
        offset = row.get("Offset")
        if not isinstance(name, str) or offset is None or not _HISTORY_FILE.search(name):
            continue
        user = _USER.search(name)
        found.append({"offset": str(offset), "path": name, "user": user.group("user") if user else ""})
    return found[:MAX_FILE_OBJECTS]


def history_commands(data: bytes) -> list[str]:
    """The commands in a PSReadLine history file's bytes.

    PSReadLine writes UTF-8, one command per line; a command typed over several lines is saved
    with a backtick at the end of every line but its last. Pages Windows no longer had cached
    come back from dumpfiles as runs of zero bytes, which split the text where they were.
    """
    if data.startswith(b"\xff\xfe") or data.startswith(b"\xfe\xff"):
        text = data.decode("utf-16", "replace")
    else:
        text = data.decode("utf-8-sig", "replace")
    commands: list[str] = []
    for chunk in re.split(r"\x00+", text):
        pending: list[str] = []
        for line in chunk.replace("\r\n", "\n").replace("\r", "\n").split("\n"):
            if line.endswith("`"):
                pending.append(line[:-1])
                continue
            command = "\n".join([*pending, line]).strip()
            pending = []
            if command and all(ch.isprintable() or ch in "\n\t" for ch in command):
                commands.append(command[:_MAX_COMMAND])
        if pending:
            command = "\n".join(pending).strip()
            if command:
                commands.append(command[:_MAX_COMMAND])
    return commands


def history_rows(files: list[dict[str, str]], recovered: dict[str, bytes]) -> list[dict[str, Any]]:
    """Rows for the recovered files. Several file objects can stand for the same file; its
    commands are listed once, from the copy that gave the most."""
    best: dict[str, tuple[dict[str, str], list[str]]] = {}
    for item in files:
        data = recovered.get(item["offset"])
        if not data:
            continue
        commands = history_commands(data)
        key = item["path"].lower()
        if commands and len(commands) > len(best.get(key, ({}, []))[1]):
            best[key] = (item, commands)
    rows = []
    for item, commands in best.values():
        for line, command in enumerate(commands, start=1):
            rows.append({"User": item["user"], "Path": item["path"], "Line": line, "Command": command, "FileObject": item["offset"]})
    return rows


def _offset_key(value: Any) -> str:
    try:
        return hex(int(str(value), 0) if isinstance(value, str) else int(value))
    except (TypeError, ValueError):
        return str(value)


def run_kairon_psreadline(
    evidence_path: Path,
    work_dir: Path,
    *,
    timeout_seconds: int,
    max_output_bytes: int,
    plugin_timeout: Callable[[str], int],
    cancellation_check: Callable[[], bool] | None = None,
):
    """Find the history files with windows.filescan and recover them with windows.dumpfiles.

    No history file cached in memory is a normal outcome (PowerShell never used interactively, or
    the pages were evicted), reported as zero rows rather than a failure.
    """
    from app.services.memory.artifact_normalizers import _rows
    from app.services.memory.volatility_runner import VolatilityRunnerError, VolatilityRunResult, run_plugin

    started = time.monotonic()
    deadline = started + max(1, int(timeout_seconds))
    dump_dir = work_dir / "kairon-psreadline"
    try:
        filescan = run_plugin(
            "windows.filescan",
            evidence_path,
            dump_dir,
            timeout_seconds=min(int(deadline - time.monotonic()), plugin_timeout("windows.filescan")),
            max_output_bytes=max_output_bytes * 4,
            cancellation_check=cancellation_check,
        )
        files = history_file_objects(_rows(json.loads(filescan.stdout.decode("utf-8") or "[]")))
    except (ValueError, UnicodeDecodeError) as exc:
        raise VolatilityRunnerError("PLUGIN_FAILED", "windows.filescan ran, but its output could not be read.") from exc
    notes: list[str] = []
    recovered: dict[str, bytes] = {}
    if not files:
        notes.append("No PowerShell history file (PSReadLine) is cached in this image.")
    else:
        remaining = int(deadline - time.monotonic())
        if remaining < 10:
            raise VolatilityRunnerError("PLUGIN_TIMEOUT", "No time left to recover the PowerShell history files windows.filescan found.")
        dumpfiles = run_plugin(
            "windows.dumpfiles",
            evidence_path,
            dump_dir,
            timeout_seconds=min(remaining, plugin_timeout("windows.dumpfiles")),
            max_output_bytes=max_output_bytes,
            cancellation_check=cancellation_check,
            extra_args=["--virtaddr", *[item["offset"] for item in files]],
        )
        try:
            dumped = _rows(json.loads(dumpfiles.stdout.decode("utf-8") or "[]"))
        except (ValueError, UnicodeDecodeError) as exc:
            raise VolatilityRunnerError("PLUGIN_FAILED", "windows.dumpfiles ran, but its output could not be read.") from exc
        by_offset = {_offset_key(item["offset"]): item["offset"] for item in files}
        for row in dumped:
            result = row.get("Result")
            offset = by_offset.get(_offset_key(row.get("FileObject")))
            if not isinstance(result, str) or not offset:
                continue
            path = dump_dir / Path(result).name
            if not path.is_file() or path.stat().st_size == 0:
                continue
            data = path.read_bytes()[: 64 * 1024 * 1024]
            # dumpfiles can write the same file from its data section and its cache map; keep the
            # copy with more text.
            if len(data.replace(b"\x00", b"")) > len(recovered.get(offset, b"").replace(b"\x00", b"")):
                recovered[offset] = data
        if not recovered:
            notes.append(f"Found {len(files)} PowerShell history file object(s), but none of their pages are cached any more.")
    rows = history_rows(files, recovered)
    return VolatilityRunResult(
        argv_display=["kairon-psreadline", *SOURCE_PLUGINS],
        stdout=json.dumps(rows).encode("utf-8"),
        stderr=" ".join(notes).encode("utf-8"),
        duration_ms=int((time.monotonic() - started) * 1000),
    )
