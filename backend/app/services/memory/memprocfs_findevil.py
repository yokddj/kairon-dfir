"""Child process: run MemProcFS's forensic scan on one memory image and print FindEvil as JSON.

With ``--timeline-dir`` the same scan also leaves the timelines Volatility has no equivalent for
(NTFS, registry, event logs, web, scheduled tasks, Amcache, Prefetch, kernel objects) there as
MemProcFS's CSV files, for app.services.memory.memprocfs_timeline to index.

Started by app.services.memory.memprocfs_runner with ``python -m``, never imported by the
worker itself: MemProcFS is a native library parsing untrusted memory, so a crash or a hang
stays in this process, which the runner can time out and kill as a group.

MemProcFS is used through its C API (``vmm.so``) with ctypes: the Python bindings shipped in
the Linux builds are compiled against an old Python and do not load in the worker, and the
command-line tool needs FUSE to expose its file system, which the hardened worker does not
have. The scan runs with the Microsoft symbol server disabled (MemProcFS's bundled info.db
covers the kernel structures FindEvil needs), so the worker stays offline.

Output on stdout: a JSON list of {"PID", "Process", "Type", "Address", "Description"} rows,
the columns of MemProcFS's forensic/csv/findevil.csv. Exit codes name the failure for the
runner: 3 library unavailable, 4 image not opened, 5 forensic scan unavailable, 6 FindEvil
result missing.
"""

from __future__ import annotations

import argparse
import csv
import ctypes
import io
import json
import os
import signal
import sys
import threading
import time

EXIT_LIBRARY_UNAVAILABLE = 3
EXIT_IMAGE_NOT_OPENED = 4
EXIT_FORENSIC_UNAVAILABLE = 5
EXIT_FINDEVIL_MISSING = 6

_STATUS_SUCCESS = 0
# The forensic scan reports progress in steps (10-59 % while scanning memory, then 60, 70, 90,
# 95, 100). Past the memory scan it can wait forever on one of its own workers -- seen on a
# Windows 11 24H2 crash dump that stays at 90 % -- so a long time without progress there means
# it will not finish.
_DEFAULT_STALL_SECONDS = 600
_READ_CHUNK = 1024 * 1024
_MAX_CSV_BYTES = 64 * 1024 * 1024
# A busy system's registry or NTFS timeline runs to hundreds of MB; the indexer has its own row cap.
_MAX_TIMELINE_BYTES = 512 * 1024 * 1024
# \forensic\csv\timeline_<name>.csv files worth keeping. Left out, because Volatility already
# gives them or they are noise: process (pslist/psscan), net (netscan) and thread creation.
TIMELINE_FILES = ("ntfs", "registry", "eventlog", "web", "task", "amcache", "prefetch", "kernelobject")


def _load(library: str) -> ctypes.CDLL:
    lib = ctypes.CDLL(library)
    lib.VMMDLL_Initialize.restype = ctypes.c_void_p
    lib.VMMDLL_Initialize.argtypes = [ctypes.c_uint32, ctypes.POINTER(ctypes.c_char_p)]
    lib.VMMDLL_InitializePlugins.restype = ctypes.c_int
    lib.VMMDLL_InitializePlugins.argtypes = [ctypes.c_void_p]
    lib.VMMDLL_VfsReadU.restype = ctypes.c_uint32
    lib.VMMDLL_VfsReadU.argtypes = [ctypes.c_void_p, ctypes.c_char_p, ctypes.c_void_p, ctypes.c_uint32, ctypes.POINTER(ctypes.c_uint32), ctypes.c_uint64]
    lib.VMMDLL_Close.restype = None
    lib.VMMDLL_Close.argtypes = [ctypes.c_void_p]
    return lib


def _read(lib: ctypes.CDLL, handle: int, path: str, *, limit: int) -> bytes | None:
    """Read a whole file of MemProcFS's virtual file system (paths use backslashes)."""
    chunks: list[bytes] = []
    offset = 0
    encoded = path.encode("utf-8")
    while offset < limit:
        buffer = ctypes.create_string_buffer(_READ_CHUNK)
        read = ctypes.c_uint32(0)
        status = lib.VMMDLL_VfsReadU(handle, encoded, buffer, _READ_CHUNK, ctypes.byref(read), offset)
        if status != _STATUS_SUCCESS and not chunks:
            return None
        if read.value == 0:
            break
        chunks.append(buffer.raw[: read.value])
        offset += read.value
        if read.value < _READ_CHUNK:
            break
    return b"".join(chunks)


# After the scan, reading findevil.csv and closing MemProcFS get this long before the child stops.
_FINISH_SECONDS = 120


def _die_with_parent() -> None:
    """Have the kernel kill this process when the worker that started it dies (Linux), so a
    killed or restarted worker never leaves a MemProcFS scan running on its own."""
    try:
        libc = ctypes.CDLL(None, use_errno=True)
        libc.prctl(1, signal.SIGKILL)  # PR_SET_PDEATHSIG
    except (OSError, AttributeError):
        return
    if os.getppid() == 1:  # the parent was already gone before prctl took effect
        os._exit(EXIT_FORENSIC_UNAVAILABLE)


class _Watchdog:
    """Ends the process when the scan stalls or runs out of time.

    The checks also run from a thread of their own: MemProcFS calls can block or spin inside the
    native library and never come back to the loop in main(), and only os._exit() gets out of
    that (closing MemProcFS waits for the stuck scan's workers and never returns either).
    """

    def __init__(self, *, scan_timeout: int, stall_timeout: int) -> None:
        self.started = time.monotonic()
        self.deadline = self.started + max(1, scan_timeout)
        self.stall_timeout = max(30, stall_timeout)
        self.progress = ""
        self.changed_at = self.started
        self.result_code: int | None = None
        self._lock = threading.Lock()

    def start(self) -> None:
        threading.Thread(target=self._run, name="memprocfs-watchdog", daemon=True).start()

    def _run(self) -> None:
        while True:
            self.check()
            time.sleep(5)

    def update(self, progress: str) -> None:
        with self._lock:
            if progress != self.progress:
                self.progress, self.changed_at = progress, time.monotonic()

    def finished(self, result_code: int) -> None:
        """The scan is over and the result is written: allow a short time to close."""
        with self._lock:
            self.result_code = result_code
            self.deadline = time.monotonic() + _FINISH_SECONDS

    def check(self) -> None:
        now = time.monotonic()
        with self._lock:
            result_code, progress = self.result_code, self.progress
            stalled = result_code is None and now - self.changed_at > self.stall_timeout
            expired = now > self.deadline
        if result_code is not None and expired:
            sys.stdout.flush()
            os._exit(result_code)
        if stalled or expired:
            reason = "stopped making progress" if stalled else "did not finish in time"
            print(f"MemProcFS's forensic scan {reason} at {progress or '?'}% and cannot finish on this image, so it produced no FindEvil result. Kairon's own Find Evil checks still ran.", file=sys.stderr)
            sys.stderr.flush()
            os._exit(EXIT_FORENSIC_UNAVAILABLE)


def _save_timelines(lib: ctypes.CDLL, handle: int, directory: str) -> None:
    """Copy the forensic scan's timeline CSVs to ``directory``. Best effort: a timeline that cannot
    be read is left out, and FindEvil is not affected."""
    try:
        os.makedirs(directory, exist_ok=True)
    except OSError as exc:
        print(f"MemProcFS timelines not saved: {exc}", file=sys.stderr)
        return
    for name in TIMELINE_FILES:
        data = _read(lib, handle, f"\\forensic\\csv\\timeline_{name}.csv", limit=_MAX_TIMELINE_BYTES)
        if not data:
            continue
        try:
            with open(os.path.join(directory, f"timeline_{name}.csv"), "wb") as handle_out:
                handle_out.write(data)
        except OSError as exc:
            print(f"MemProcFS timeline {name} not saved: {exc}", file=sys.stderr)


def findevil_rows(csv_text: str) -> list[dict[str, str]]:
    rows = []
    for record in csv.DictReader(io.StringIO(csv_text)):
        rows.append({
            "PID": (record.get("PID") or "").strip(),
            "Process": (record.get("ProcessName") or "").strip(),
            "Type": (record.get("Type") or "").strip(),
            "Address": (record.get("Address") or "").strip(),
            "Description": (record.get("Description") or "").strip(),
        })
    return rows


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--library", required=True)
    parser.add_argument("--evidence", required=True)
    parser.add_argument("--scan-timeout", type=int, default=1500)
    parser.add_argument("--stall-timeout", type=int, default=_DEFAULT_STALL_SECONDS)
    parser.add_argument("--timeline-dir", default=None)
    args = parser.parse_args(argv)
    _die_with_parent()
    watchdog = _Watchdog(scan_timeout=args.scan_timeout, stall_timeout=args.stall_timeout)
    watchdog.start()

    try:
        lib = _load(args.library)
    except OSError as exc:
        print(f"MemProcFS library could not be loaded: {exc}", file=sys.stderr)
        return EXIT_LIBRARY_UNAVAILABLE

    options = ["", "-device", args.evidence, "-forensic", "1", "-disable-symbolserver"]
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
        if args.timeline_dir:
            _save_timelines(lib, handle, args.timeline_dir)
        data = _read(lib, handle, "\\forensic\\csv\\findevil.csv", limit=_MAX_CSV_BYTES)
        if data is None:
            print("MemProcFS produced no FindEvil result for this image (FindEvil needs 64-bit Windows 10 or later).", file=sys.stderr)
            watchdog.finished(EXIT_FINDEVIL_MISSING)
            return EXIT_FINDEVIL_MISSING
        json.dump(findevil_rows(data.decode("utf-8", "replace")), sys.stdout)
        sys.stdout.flush()
        watchdog.finished(0)
        return 0
    finally:
        lib.VMMDLL_Close(handle)


if __name__ == "__main__":
    sys.exit(main())
