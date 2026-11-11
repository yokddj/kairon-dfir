"""Child process: MemProcFS's process or network inventory of a Windows memory image, as JSON.

Used when Volatility cannot analyse a Windows image because the kernel's symbols are not in the
cache: MemProcFS walks the kernel's process and network structures with its own built-in
knowledge, without symbols (``-disable-symbolserver``), and its forensic scan writes them as CSV
(``\\forensic\\csv\\process.csv``: PID, PPID, name, user, integrity, create/exit time, EPROCESS,
paths, command line; ``net.csv``: protocol, state, addresses, ports, time, PID, process). The
worker converts the rows to the shape of windows.pslist / windows.netscan
(app.services.memory.normalizers.memprocfs_process_rows,
app.services.memory.artifact_normalizers.memprocfs_net_rows), so the Processes and Network views
show them like Volatility's.

Started by app.services.memory.memprocfs_runner with ``python -m`` and never imported by the
worker, like memprocfs_findevil: MemProcFS is a native library parsing untrusted memory.

Output on stdout: a JSON list of the CSV's rows (column -> text).
Exit codes: 3 library unavailable, 4 image not opened, 5 forensic mode unavailable, 6 the CSV is
missing.
"""

from __future__ import annotations

import argparse
import csv
import ctypes
import io
import json
import sys
import time

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
_MAX_CSV_BYTES = 64 * 1024 * 1024
_STALL_SECONDS = 600


def csv_rows(text: str) -> list[dict[str, str]]:
    return [dict(row) for row in csv.DictReader(io.StringIO(text))]


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--library", required=True)
    parser.add_argument("--evidence", required=True)
    parser.add_argument("--kind", required=True, choices=sorted(CSV_FILES))
    parser.add_argument("--scan-timeout", type=int, default=1800)
    args = parser.parse_args(argv)
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
