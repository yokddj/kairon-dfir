"""Child process: print the console text MemProcFS recovers from a memory image as JSON.

MemProcFS's console module rebuilds the screen and scrollback text of the consoles a process
hosts (``\\pid\\<pid>\\console\\console.txt``): conhost.exe windows, and the PowerShell and cmd.exe
sessions inside Windows Terminal (WindowsTerminal.exe / OpenConsole.exe), where Volatility's
windows.consoles and windows.cmdscan find nothing on recent Windows 11 builds. The commands are
read from that text by the same prompt parser windows.consoles' screen dumps go through
(app.services.memory.artifact_normalizers.normalize_memprocfs_console).

Started by app.services.memory.memprocfs_runner with ``python -m`` and never imported by the
worker, like memprocfs_findevil: MemProcFS is a native library parsing untrusted memory. No
forensic scan is needed, so this only opens the image (about a minute).

Output on stdout: a JSON list of {"PID", "Process", "Text"}, one per process with console text.
Exit codes: 3 library unavailable, 4 image not opened.
"""

from __future__ import annotations

import argparse
import ctypes
import json
import re
import sys

from app.services.memory.memprocfs_findevil import EXIT_IMAGE_NOT_OPENED, EXIT_LIBRARY_UNAVAILABLE, _die_with_parent, _load, _read

_MAX_PROCESS_LIST_BYTES = 16 * 1024 * 1024
_MAX_CONSOLE_BYTES = 4 * 1024 * 1024
# Processes without a console still answer with a few bytes of noise.
_MIN_TEXT = 16
# "---- WindowsTermina           4876   7828      *   ..." (tree depth, short name, pid, parent pid).
_PROCESS_LINE = re.compile(r"^\s*-+\s+(?P<name>.+?)\s+(?P<pid>\d+)\s+(?P<ppid>\d+)(?:\s|$)")


def process_ids(proc_txt: str) -> list[tuple[int, str]]:
    """(pid, short name) of every process in \\sys\\proc\\proc.txt, in its order, once each."""
    seen: dict[int, str] = {}
    for line in proc_txt.splitlines():
        match = _PROCESS_LINE.match(line)
        if match:
            seen.setdefault(int(match["pid"]), match["name"].strip())
    return list(seen.items())


def console_rows(read) -> list[dict[str, object]]:
    """The console text of every process, with ``read(path, limit) -> bytes | None``."""
    rows = []
    for pid, short_name in process_ids((read("\\sys\\proc\\proc.txt", _MAX_PROCESS_LIST_BYTES) or b"").decode("utf-8", "replace")):
        data = read(f"\\pid\\{pid}\\console\\console.txt", _MAX_CONSOLE_BYTES)
        text = (data or b"").decode("utf-8", "replace").strip()
        if len(text) < _MIN_TEXT:
            continue
        name = (read(f"\\pid\\{pid}\\name-long.txt", 4096) or b"").decode("utf-8", "replace").strip() or short_name
        rows.append({"PID": pid, "Process": name, "Text": text})
    return rows


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--library", required=True)
    parser.add_argument("--evidence", required=True)
    args = parser.parse_args(argv)
    _die_with_parent()
    try:
        lib = _load(args.library)
    except OSError as exc:
        print(f"MemProcFS library could not be loaded: {exc}", file=sys.stderr)
        return EXIT_LIBRARY_UNAVAILABLE
    options = ["", "-device", args.evidence, "-disable-symbolserver", "-disable-python"]
    handle = lib.VMMDLL_Initialize(len(options), (ctypes.c_char_p * len(options))(*[item.encode("utf-8") for item in options]))
    if not handle:
        print("MemProcFS could not open this memory image (not a supported Windows image, or damaged).", file=sys.stderr)
        return EXIT_IMAGE_NOT_OPENED
    try:
        lib.VMMDLL_InitializePlugins(handle)
        rows = console_rows(lambda path, limit: _read(lib, handle, path, limit=limit))
        json.dump(rows, sys.stdout)
        sys.stdout.flush()
        return 0
    finally:
        lib.VMMDLL_Close(handle)


if __name__ == "__main__":
    sys.exit(main())
