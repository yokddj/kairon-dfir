"""FSEvents: the file system change journal macOS keeps in each volume's ``.fseventsd`` folder.

Each file in ``.fseventsd`` is gzip-compressed and holds one or more pages. A page starts with a
12-byte header -- a 4-byte signature (``1SLD``, ``2SLD`` or ``3SLD``), 4 reserved bytes and the
page size (header included) as a little-endian 32-bit integer -- followed by records: a
NUL-terminated UTF-8 path relative to the volume root, a 64-bit event id and 32-bit flags; version
2 adds a 64-bit node (inode) id and version 3 four more bytes.

Records carry no time. Event ids only grow, so they give the order; the page file's modification
time is when its page was written, an upper bound for its records' times.

A Mac holds millions of records (17 million on a test Mac), so they are not indexed: they are
searched on demand (see app.services.macos_fsevents). Reading them all takes seconds.

Flag bits: the item type bits were checked on a real Mac -- every record of a path that is a
directory had 0x01000000, every file record 0x00800000 -- and the change bits match the on-disk
order documented by FSEventsParser (0x1 created, 0x2 removed, 0x8 renamed, 0x10 modified, 0x80
folder created...). A bit not in that list is reported by its value, never guessed.
"""
from __future__ import annotations

import gzip
import struct
import zlib
from collections.abc import Iterator
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path

PAGE_HEADER = 12
RECORD_TAIL = {b"1SLD": 12, b"2SLD": 20, b"3SLD": 24}
FLAG_NAMES = {
    0x00000001: "created",
    0x00000002: "removed",
    0x00000004: "inode_metadata_modified",
    0x00000008: "renamed",
    0x00000010: "modified",
    0x00000020: "exchanged",
    0x00000040: "finder_info_modified",
    0x00000080: "folder_created",
    0x00000100: "permissions_changed",
    0x00000200: "extended_attribute_modified",
    0x00000400: "extended_attribute_removed",
}
TYPE_FLAGS = {0x00800000: "file", 0x01000000: "folder"}
# The change kinds an analyst filters on.
CHANGE_KINDS = ("created", "removed", "renamed", "modified", "folder_created", "permissions_changed", "extended_attribute_modified")
_MAX_PAGE_FILE_BYTES = 64 * 1024 * 1024


@dataclass(frozen=True)
class FseventsRecord:
    path: str
    event_id: int
    flags: int
    node_id: int | None
    page_file: str
    page_written: str | None
    version: int

    @property
    def changes(self) -> list[str]:
        return [name for bit, name in FLAG_NAMES.items() if self.flags & bit]

    @property
    def item_type(self) -> str | None:
        for bit, name in TYPE_FLAGS.items():
            if self.flags & bit:
                return name
        return None

    @property
    def unknown_flags(self) -> list[str]:
        known = 0
        for bit in (*FLAG_NAMES, *TYPE_FLAGS):
            known |= bit
        rest = self.flags & ~known
        return [hex(1 << bit) for bit in range(32) if rest >> bit & 1]

    def as_dict(self) -> dict:
        return {
            "path": self.path,
            "event_id": self.event_id,
            "flags": hex(self.flags),
            "changes": self.changes,
            "item_type": self.item_type,
            "unknown_flags": self.unknown_flags,
            "node_id": self.node_id,
            "page_file": self.page_file,
            "page_written": self.page_written,
            "version": self.version,
        }


def page_files(directory: Path) -> list[Path]:
    """The page files of one .fseventsd folder, oldest first (their names are hex event ids)."""
    files = []
    try:
        for item in directory.iterdir():
            if item.is_file() and not item.is_symlink() and all(char in "0123456789abcdefABCDEF" for char in item.name) and item.name:
                files.append(item)
    except OSError:
        return []
    return sorted(files, key=lambda item: int(item.name, 16))


def read_page_file(path: Path) -> bytes | None:
    try:
        if path.stat().st_size > _MAX_PAGE_FILE_BYTES:
            return None
        with gzip.open(path, "rb") as handle:
            return handle.read(_MAX_PAGE_FILE_BYTES * 8)
    except (OSError, EOFError, zlib.error):
        return None


def _written(path: Path) -> str | None:
    try:
        return datetime.fromtimestamp(path.stat().st_mtime, tz=timezone.utc).isoformat()
    except (OSError, OverflowError, ValueError):
        return None


def iter_records(data: bytes, *, page_file: str, page_written: str | None) -> Iterator[FseventsRecord]:
    position = 0
    while position + PAGE_HEADER <= len(data):
        signature = data[position:position + 4]
        tail = RECORD_TAIL.get(signature)
        if tail is None:
            return
        size = struct.unpack_from("<I", data, position + 8)[0]
        end = min(position + size, len(data)) if size > PAGE_HEADER else len(data)
        cursor = position + PAGE_HEADER
        version = int(chr(signature[0]))
        while cursor < end:
            terminator = data.find(b"\0", cursor, end)
            if terminator < 0 or terminator + 1 + tail > end:
                break
            raw_path = data[cursor:terminator]
            cursor = terminator + 1
            event_id, flags = struct.unpack_from("<QI", data, cursor)
            node_id = struct.unpack_from("<Q", data, cursor + 12)[0] if tail >= 20 else None
            cursor += tail
            yield FseventsRecord(
                path=raw_path.decode("utf-8", errors="replace"),
                event_id=event_id,
                flags=flags,
                node_id=node_id,
                page_file=page_file,
                page_written=page_written,
                version=version,
            )
        position = end


def iter_directory(directory: Path, *, needle: bytes | None = None) -> Iterator[FseventsRecord]:
    """Every record of a .fseventsd folder; pages without ``needle`` (lower-case bytes) are skipped."""
    for page in page_files(directory):
        data = read_page_file(page)
        if data is None:
            continue
        if needle and needle not in data.lower():
            continue
        yield from iter_records(data, page_file=page.name, page_written=_written(page))
