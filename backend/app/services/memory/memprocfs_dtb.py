"""Child process: the kernel page-table base (DTB) MemProcFS found in a Windows memory image.

Volatility finds the DTB by scanning a few physical ranges for a self-referencing page table; on
some captures nothing matches, it builds no memory layer and every plugin fails
(INVALID_MEMORY_LAYER). MemProcFS finds the DTB its own way. It presents the memory as a Windows
crash dump (``\\memory.dmp``) whose header carries that DTB, so the first page of that view is all
that is read here (well under a second, nothing written). app.services.memory.volatility_layer then
gives Volatility a memory layer pinned to it. Volatility itself ignores the DTB in a crash dump's
header, which is why a crash-dump copy alone does not help.

Started by app.services.memory.memprocfs_runner with ``python -m`` and never imported by the
worker, like the other MemProcFS children: MemProcFS is a native library parsing untrusted memory.

Prints ``{"page_map_offset": int, "architecture": "Intel64"|"Intel32", "pae": bool}``. Exit codes:
3 library unavailable, 4 image not opened, 5 no crash-dump view (so no DTB).
"""

from __future__ import annotations

import argparse
import ctypes
import json
import struct
import sys

from app.services.memory.memprocfs_findevil import EXIT_IMAGE_NOT_OPENED, EXIT_LIBRARY_UNAVAILABLE, _die_with_parent, _load

EXIT_NO_CRASH_DUMP = 5
_HEADER_BYTES = 0x1000
# DUMP_HEADER64 / DUMP_HEADER32: Signature, ValidDump, MajorVersion, MinorVersion, then DirectoryTableBase.
_DTB_OFFSET = 0x10
# DUMP_HEADER32.PaeEnabled.
_PAE_OFFSET_32 = 0x5C


def parse_header(header: bytes) -> dict | None:
    """The DTB and paging mode a Windows crash-dump header records, or None."""
    if len(header) < 0x60:
        return None
    if header.startswith(b"PAGEDU64"):
        dtb = struct.unpack_from("<Q", header, _DTB_OFFSET)[0]
        return {"page_map_offset": dtb, "architecture": "Intel64", "pae": False} if dtb else None
    if header.startswith(b"PAGEDUMP"):
        dtb = struct.unpack_from("<I", header, _DTB_OFFSET)[0]
        return {"page_map_offset": dtb, "architecture": "Intel32", "pae": bool(header[_PAE_OFFSET_32])} if dtb else None
    return None


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
    lib.VMMDLL_VfsReadU.argtypes = [ctypes.c_void_p, ctypes.c_char_p, ctypes.c_void_p, ctypes.c_uint32, ctypes.POINTER(ctypes.c_uint32), ctypes.c_uint64]
    options = ["", "-device", args.evidence, "-disable-symbolserver", "-disable-python"]
    handle = lib.VMMDLL_Initialize(len(options), (ctypes.c_char_p * len(options))(*[item.encode("utf-8") for item in options]))
    if not handle:
        print("MemProcFS could not open this memory image (not a supported Windows image, or damaged).", file=sys.stderr)
        return EXIT_IMAGE_NOT_OPENED
    try:
        lib.VMMDLL_InitializePlugins(handle)
        buffer = ctypes.create_string_buffer(_HEADER_BYTES)
        read = ctypes.c_uint32()
        lib.VMMDLL_VfsReadU(handle, b"\\memory.dmp", buffer, _HEADER_BYTES, ctypes.byref(read), 0)
        found = parse_header(buffer.raw[: read.value])
    finally:
        lib.VMMDLL_Close(handle)
    if found is None:
        print("MemProcFS has no crash-dump view of this image, so no page-table base.", file=sys.stderr)
        return EXIT_NO_CRASH_DUMP
    print(json.dumps(found))
    return 0


if __name__ == "__main__":
    sys.exit(main())
