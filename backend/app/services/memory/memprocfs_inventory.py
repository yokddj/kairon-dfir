"""Child process: MemProcFS's inventory of a Windows memory image, saved once per evidence.

MemProcFS is Kairon's engine for Windows memory: it walks the kernel's structures with its own
built-in knowledge, without the kernel's symbols (``-disable-symbolserver``), and reads raw
captures whose page tables Volatility cannot find. One forensic scan gives everything the Windows
analyses show; this child saves it to a directory the worker reads back for every analysis of the
evidence (app.services.memory.memprocfs_engine), so the scan runs once:

* ``process.csv``, ``net.csv``, ``modules.csv``, ``handles.csv``, ``drivers.csv``,
  ``unloaded_modules.csv``: MemProcFS's ``\\forensic\\csv`` tables;
* ``environment.json``: each process's environment variables (``\\pid\\<pid>\\win-environment.txt``);
* ``tokens.json``: each process's token, its user, integrity, session, all its SIDs and privileges
  (``\\pid\\<pid>\\token\\``, filled in by the forensic scan);
* ``system.json``: the ``\\sys`` facts (version, computer name, times, architecture).

The directory is written as ``<dir>.partial`` and renamed when complete. Started by
app.services.memory.memprocfs_runner with ``python -m`` and never imported by the worker, like
memprocfs_findevil: MemProcFS is a native library parsing untrusted memory.

``--kind processes|network`` prints that one table as JSON instead (kept for older runs).
Exit codes: 3 library unavailable, 4 image not opened, 5 forensic mode unavailable, 6 a table is
missing, 7 writing failed.
"""

from __future__ import annotations

import argparse
import csv
import ctypes
import io
import json
import os
import shutil
import sys
import time
from pathlib import Path

from app.services.memory.memprocfs_findevil import (
    EXIT_FINDEVIL_MISSING,
    EXIT_FORENSIC_UNAVAILABLE,
    EXIT_IMAGE_NOT_OPENED,
    EXIT_LIBRARY_UNAVAILABLE,
    _die_with_parent,
    _load,
    _read,
    _Watchdog,
)

CSV_FILES = {"processes": "process.csv", "network": "net.csv"}
TABLES = ("process", "net", "modules", "handles", "drivers", "unloaded_modules")
SYSTEM_FILES = ("version", "version-major", "version-minor", "version-build", "computername", "time-boot", "time-current", "timezone", "architecture")
EXIT_WRITE_FAILED = 7
_MAX_CSV_BYTES = 512 * 1024 * 1024
_MAX_TEXT_BYTES = 4 * 1024 * 1024
_STALL_SECONDS = 600


def csv_rows(text: str) -> list[dict[str, str]]:
    return [dict(row) for row in csv.DictReader(io.StringIO(text))]


def environment(text: str) -> dict[str, str]:
    """``NAME=value`` lines of win-environment.txt; the ``=C:=...`` drive entries are left out."""
    variables: dict[str, str] = {}
    for line in text.splitlines():
        if "=" in line and not line.startswith("="):
            name, value = line.split("=", 1)
            variables[name] = value
    return variables


def token_sids(text: str) -> list[dict[str, str]]:
    """sid-all.txt: ``   # Display Name   SID`` table, the SID last on each row."""
    sids = []
    for line in text.splitlines():
        parts = line.split()
        if len(parts) >= 2 and parts[-1].startswith("S-1-") and _is_hex(parts[0]):
            sids.append({"sid": parts[-1], "name": " ".join(parts[1:-1]) or None})
    return sids


def _is_hex(value: str) -> bool:
    try:
        int(value, 16)
    except ValueError:
        return False
    return True


def token_privileges(text: str) -> list[dict[str, object]]:
    """privileges.txt: ``0017  epd  SeChangeNotifyPrivilege`` -- value (hex), flags (e enabled,
    p present, d enabled by default), name."""
    privileges = []
    for line in text.splitlines():
        parts = line.split()
        if len(parts) >= 3 and _is_hex(parts[0]) and parts[2].startswith("Se"):
            flags = parts[1]
            privileges.append({"value": int(parts[0], 16), "name": parts[2], "present": "p" in flags, "enabled": "e" in flags, "default": "d" in flags})
    return privileges


def _text(lib: ctypes.CDLL, handle: int, path: str) -> str:
    return (_read(lib, handle, path, limit=_MAX_TEXT_BYTES) or b"").decode("utf-8", "replace")


def save_inventory(lib: ctypes.CDLL, handle: int, output: Path, *, extra=None, progress=None) -> int:
    """Write the inventory to ``<output>.partial`` and rename it to ``output`` when complete.
    ``extra(partial)`` adds more files before the rename (the full scan: memprocfs_findevil);
    ``progress(label)`` keeps the scan watchdog from taking the writing for a stall."""
    partial = output.with_name(output.name + ".partial")
    shutil.rmtree(partial, ignore_errors=True)
    partial.mkdir(parents=True, mode=0o750)
    pids: list[int] = []
    for table in TABLES:
        data = _read(lib, handle, f"\\forensic\\csv\\{table}.csv", limit=_MAX_CSV_BYTES)
        if data is None:
            if table == "process":
                print("MemProcFS did not write its process table.", file=sys.stderr)
                return EXIT_FINDEVIL_MISSING
            data = b""
        (partial / f"{table}.csv").write_bytes(data)
        if table == "process":
            pids = sorted({int(row["PID"]) for row in csv_rows(data.decode("utf-8", "replace")) if str(row.get("PID") or "").isdigit()})
    envs: dict[str, dict[str, str]] = {}
    tokens: dict[str, dict[str, object]] = {}
    for position, pid in enumerate(pids):
        if progress and position % 25 == 0:
            progress(f"inventory {position}/{len(pids)}")
        env = environment(_text(lib, handle, f"\\pid\\{pid}\\win-environment.txt"))
        if env:
            envs[str(pid)] = env
        sid = _text(lib, handle, f"\\pid\\{pid}\\token\\sid.txt").strip()
        if sid:
            tokens[str(pid)] = {
                "sid": sid,
                "user": _text(lib, handle, f"\\pid\\{pid}\\token\\user.txt").strip() or None,
                "integrity": _text(lib, handle, f"\\pid\\{pid}\\token\\integrity.txt").strip() or None,
                "session": _text(lib, handle, f"\\pid\\{pid}\\token\\session.txt").strip() or None,
                "sids": token_sids(_text(lib, handle, f"\\pid\\{pid}\\token\\sid-all.txt")),
                "privileges": token_privileges(_text(lib, handle, f"\\pid\\{pid}\\token\\privileges.txt")),
            }
    system = {name: _text(lib, handle, f"\\sys\\{name}.txt").strip() for name in SYSTEM_FILES}
    for name, value in (("environment.json", envs), ("tokens.json", tokens), ("system.json", system)):
        (partial / name).write_text(json.dumps(value), encoding="utf-8")
    if extra is not None:
        extra(partial)
    shutil.rmtree(output, ignore_errors=True)
    os.replace(partial, output)
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--library", required=True)
    parser.add_argument("--evidence", required=True)
    parser.add_argument("--kind", choices=sorted(CSV_FILES))
    parser.add_argument("--output-dir")
    parser.add_argument("--scan-timeout", type=int, default=1800)
    args = parser.parse_args(argv)
    if not args.kind and not args.output_dir:
        parser.error("--kind or --output-dir is required")
    _die_with_parent()
    watchdog = _Watchdog(scan_timeout=args.scan_timeout, stall_timeout=_STALL_SECONDS)
    watchdog.start()
    try:
        lib = _load(args.library)
    except OSError as exc:
        print(f"MemProcFS library could not be loaded: {exc}", file=sys.stderr)
        return EXIT_LIBRARY_UNAVAILABLE
    options = ["", "-device", args.evidence, "-forensic", "1", "-disable-symbolserver", "-disable-python"]
    handle = lib.VMMDLL_Initialize(len(options), (ctypes.c_char_p * len(options))(*[item.encode("utf-8") for item in options]))
    if not handle:
        print("MemProcFS could not open this memory image (not a supported Windows image, or damaged).", file=sys.stderr)
        return EXIT_IMAGE_NOT_OPENED
    try:
        if not lib.VMMDLL_InitializePlugins(handle):
            print("MemProcFS plugins could not be initialised.", file=sys.stderr)
            return EXIT_FORENSIC_UNAVAILABLE
        while True:
            raw = _read(lib, handle, "\\forensic\\progress_percent.txt", limit=64)
            if raw is None:
                print("MemProcFS forensic mode is not available for this image.", file=sys.stderr)
                return EXIT_FORENSIC_UNAVAILABLE
            progress = raw.decode("utf-8", "replace").strip()
            watchdog.update(progress)
            if progress.startswith("100"):
                break
            watchdog.check()
            time.sleep(2)
        if args.output_dir:
            try:
                code = save_inventory(lib, handle, Path(args.output_dir))
            except OSError as exc:
                print(f"Writing the MemProcFS inventory failed: {exc.strerror or exc}", file=sys.stderr)
                code = EXIT_WRITE_FAILED
            watchdog.finished(code)
            return code
        data = _read(lib, handle, f"\\forensic\\csv\\{CSV_FILES[args.kind]}", limit=_MAX_CSV_BYTES)
        if data is None:
            print(f"MemProcFS did not write {CSV_FILES[args.kind]}.", file=sys.stderr)
            return EXIT_FINDEVIL_MISSING
        json.dump(csv_rows(data.decode("utf-8", "replace")), sys.stdout)
        sys.stdout.flush()
        watchdog.finished(0)
        return 0
    finally:
        lib.VMMDLL_Close(handle)


if __name__ == "__main__":
    sys.exit(main())
