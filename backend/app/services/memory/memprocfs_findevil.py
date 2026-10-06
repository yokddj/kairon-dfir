"""Child process: run MemProcFS's forensic scan on one memory image and print FindEvil as JSON.

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
import sys
import time

EXIT_LIBRARY_UNAVAILABLE = 3
EXIT_IMAGE_NOT_OPENED = 4
EXIT_FORENSIC_UNAVAILABLE = 5
EXIT_FINDEVIL_MISSING = 6

_STATUS_SUCCESS = 0
_READ_CHUNK = 1024 * 1024
_MAX_CSV_BYTES = 64 * 1024 * 1024


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
    args = parser.parse_args(argv)

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
        deadline = time.monotonic() + max(1, args.scan_timeout)
        progress = ""
        while time.monotonic() < deadline:
            raw = _read(lib, handle, "\\forensic\\progress_percent.txt", limit=64)
            if raw is None:
                print("MemProcFS forensic mode is not available for this image.", file=sys.stderr)
                return EXIT_FORENSIC_UNAVAILABLE
            progress = raw.decode("utf-8", "replace").strip()
            if progress.startswith("100"):
                break
            time.sleep(2)
        else:
            print(f"MemProcFS forensic scan did not finish (at {progress or '?'}%).", file=sys.stderr)
            return EXIT_FORENSIC_UNAVAILABLE
        data = _read(lib, handle, "\\forensic\\csv\\findevil.csv", limit=_MAX_CSV_BYTES)
        if data is None:
            print("MemProcFS produced no FindEvil result for this image (FindEvil needs 64-bit Windows 10 or later).", file=sys.stderr)
            return EXIT_FINDEVIL_MISSING
        json.dump(findevil_rows(data.decode("utf-8", "replace")), sys.stdout)
        return 0
    finally:
        lib.VMMDLL_Close(handle)


if __name__ == "__main__":
    sys.exit(main())
