"""Files inside an uploaded archive that are evidence of their own kind.

A collection archive sometimes carries a memory image or a packet capture next
to the triage files (one .zip per host with everything taken from it). The
collection is ingested; those members are not -- a memory image is analysed
only as its own evidence, and packet captures have no parser yet. Each such
member is flagged at extraction so the evidence says what it did not process,
instead of the file disappearing silently. Disk images are not listed: they are
mounted and their files ingested.

Recognition is by content, never by file name: the memory classifier's header
read, and the pcap/pcapng file signatures.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

MAX_LISTED = 50
MIN_MEMORY_IMAGE_BYTES = 64 * 1024 * 1024
_ELF_CORE = 4

KIND_LABELS = {
    "memory_dump": "Memory image",
    "pcap": "Packet capture",
}

# Classic pcap in both byte orders, with microsecond or nanosecond timestamps.
_PCAP_MAGICS = {b"\xd4\xc3\xb2\xa1", b"\xa1\xb2\xc3\xd4", b"\x4d\x3c\xb2\xa1", b"\xa1\xb2\x3c\x4d"}
# pcapng: a Section Header Block, then its byte-order magic at offset 8.
_PCAPNG_BLOCK = b"\x0a\x0d\x0d\x0a"
_PCAPNG_BYTE_ORDER = {b"\x1a\x2b\x3c\x4d", b"\x4d\x3c\x2b\x1a"}


def is_packet_capture(path: Path) -> bool:
    try:
        with path.open("rb") as handle:
            header = handle.read(12)
    except OSError:
        return False
    if header[:4] in _PCAP_MAGICS:
        return True
    return header[:4] == _PCAPNG_BLOCK and header[8:12] in _PCAPNG_BYTE_ORDER


def _is_memory_image(path: Path) -> bool:
    """The classifier's memory verdict, held to what a whole-system image is:
    tens of megabytes at least, and an ELF file only when it is a core dump
    (the header probe accepts any ELF, which would list every binary of a
    Linux collection)."""
    try:
        if path.stat().st_size < MIN_MEMORY_IMAGE_BYTES:
            return False
        with path.open("rb") as handle:
            header = handle.read(20)
    except OSError:
        return False
    if header[:4] == b"\x7fELF":
        little_endian = header[5:6] != b"\x02"
        return int.from_bytes(header[16:18], "little" if little_endian else "big") == _ELF_CORE
    return True


def bundled_kind(category: str | None, path: Path) -> str | None:
    """The kind of separate evidence a member is, from its classification."""
    if category == "memory_dump" and _is_memory_image(path):
        return "memory_dump"
    if is_packet_capture(path):
        return "pcap"
    return None


def bundled_evidence(archive_entries: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """The flagged members of an extraction, for the evidence metadata."""
    listed = []
    for entry in archive_entries:
        kind = entry.get("bundled_evidence")
        if not kind:
            continue
        listed.append({
            "path": entry.get("path"),
            "kind": kind,
            "label": KIND_LABELS.get(kind, kind),
            "size_bytes": entry.get("size"),
        })
    return listed[:MAX_LISTED]
