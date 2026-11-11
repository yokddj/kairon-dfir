"""Child process: write MemProcFS's crash-dump view of a memory image, for Volatility to read.

Some raw captures cannot be read by Volatility: its page-map scan finds no page tables (DTB), so it
builds no memory layer and every plugin fails, while MemProcFS, which finds the DTB its own way,
reads the same image. MemProcFS presents the memory it reconstructed as a Windows full crash dump
(``\\memory.dmp``), whose header carries the DTB and the kernel's debugger data; Volatility reads
that file directly. This writes it once per evidence (app.services.memory.execution keeps it next
to the evidence's memory outputs and removes it with them).

Started by app.services.memory.memprocfs_runner with ``python -m`` and never imported by the
worker, like the other MemProcFS children: MemProcFS is a native library parsing untrusted memory.

The file is written as ``<output>.partial`` and renamed when complete. Exit codes: 3 library
unavailable, 4 image not opened, 5 no crash-dump view, 7 write failed.
"""

from __future__ import annotations

import argparse
import ctypes
import os
import sys
from pathlib import Path

from app.services.memory.memprocfs_findevil import EXIT_IMAGE_NOT_OPENED, EXIT_LIBRARY_UNAVAILABLE, _die_with_parent, _load

EXIT_NO_CRASH_DUMP = 5
EXIT_WRITE_FAILED = 7
_CHUNK = 16 * 1024 * 1024
_CRASH_DUMP_SIGNATURES = (b"PAGEDU64", b"PAGEDUMP")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--library", required=True)
    parser.add_argument("--evidence", required=True)
    parser.add_argument("--output", required=True)
    args = parser.parse_args(argv)
    _die_with_parent()
    try:
        lib = _load(args.library)
    except OSError as exc:
        print(f"MemProcFS library could not be loaded: {exc}", file=sys.stderr)
        return EXIT_LIBRARY_UNAVAILABLE
    lib.VMMDLL_VfsReadU.argtypes = [ctypes.c_void_p, ctypes.c_char_p, ctypes.c_void_p, ctypes.c_uint32, ctypes.POINTER(ctypes.c_uint32), ctypes.c_uint64]
    options = ["", "-device", args.evidence, "-disable-symbolserver", "-disable-python"]
    handle = lib.VMMDLL_Initialize(len(options), (ctypes.c_char_p * len(options))(*[item.encode("utf-8") for item in options]))
    if not handle:
        print("MemProcFS could not open this memory image (not a supported Windows image, or damaged).", file=sys.stderr)
        return EXIT_IMAGE_NOT_OPENED
    output = Path(args.output)
    partial = output.with_name(output.name + ".partial")
    buffer = ctypes.create_string_buffer(_CHUNK)
    read = ctypes.c_uint32()
    offset = 0
    try:
        lib.VMMDLL_InitializePlugins(handle)
        output.parent.mkdir(parents=True, exist_ok=True, mode=0o750)
        with partial.open("wb") as handle_out:
            while True:
                read.value = 0
                lib.VMMDLL_VfsReadU(handle, b"\\memory.dmp", buffer, _CHUNK, ctypes.byref(read), offset)
                if read.value == 0:
                    break
                chunk = buffer.raw[: read.value]
                if offset == 0 and not chunk.startswith(_CRASH_DUMP_SIGNATURES):
                    print("MemProcFS has no crash-dump view of this image.", file=sys.stderr)
                    return EXIT_NO_CRASH_DUMP
                handle_out.write(chunk)
                offset += read.value
            handle_out.flush()
            os.fsync(handle_out.fileno())
        if offset == 0:
            print("MemProcFS has no crash-dump view of this image.", file=sys.stderr)
            return EXIT_NO_CRASH_DUMP
        os.replace(partial, output)
        print(offset)
        return 0
    except OSError as exc:
        print(f"Writing the crash-dump copy failed: {exc.strerror or exc}", file=sys.stderr)
        return EXIT_WRITE_FAILED
    finally:
        partial.unlink(missing_ok=True)
        lib.VMMDLL_Close(handle)


if __name__ == "__main__":
    sys.exit(main())
