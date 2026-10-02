"""Reader for the binary systemd journal format (``*.journal``).

Debian 12+, Fedora, Arch and modern RHEL/SUSE can run with journald only: no ``auth.log`` or
``syslog`` exists, so without this reader those hosts yield almost no Linux log evidence.

The format is documented in systemd's JOURNAL_FILE_FORMAT. This is a forensic reader, not a
database client: it scans objects sequentially from the header to the tail rather than
following the hash tables / entry arrays, so entries the file's own index no longer links
(a rotated-then-damaged file, an unclean shutdown) are still recovered.

Journal files come from evidence and are untrusted: every offset and size is bounds-checked,
decompression is capped, the scan always advances, and a damaged file yields the entries
read before the damage plus a marker rather than an exception.
"""
from __future__ import annotations

import io
import lzma
import mmap
import struct
from collections.abc import Iterator
from pathlib import Path
from typing import Any

SIGNATURE = b"LPKSHHRH"

# Header field offsets (little-endian), identical across format versions.
_OFF_INCOMPATIBLE_FLAGS = 12
_OFF_HEADER_SIZE = 88
_OFF_TAIL_OBJECT_OFFSET = 136
_MIN_HEADER = 144

_INCOMPAT_COMPACT = 0x10

_OBJECT_HEADER = struct.Struct("<BB6xQ")  # type, flags, size
_OBJECT_HEADER_SIZE = 16
_TYPE_DATA = 1
_TYPE_ENTRY = 3
_FLAG_XZ = 0x01
_FLAG_LZ4 = 0x02
_FLAG_ZSTD = 0x04

_DATA_PAYLOAD_OFFSET = 64          # 16 header + six u64
_DATA_PAYLOAD_OFFSET_COMPACT = 72  # + tail_entry_array_offset/n (u32 each)
_ENTRY_FIXED = 64                  # 16 header + seqnum, realtime, monotonic, boot_id, xor_hash
_ENTRY_STRUCT = struct.Struct("<QQQ16sQ")

MAX_ENTRIES = 1_000_000
MAX_FIELDS_PER_ENTRY = 512
MAX_FIELD_BYTES = 1 * 1024 * 1024
MAX_STORED_VALUE_CHARS = 4000
_DATA_CACHE_LIMIT = 200_000


def is_journal_file(path: Path) -> bool:
    try:
        with path.open("rb") as handle:
            return handle.read(len(SIGNATURE)) == SIGNATURE
    except OSError:
        return False


def _decompress(payload: bytes, flags: int) -> bytes | None:
    """Decompress a DATA payload, or None when the algorithm is unavailable or it is invalid."""
    try:
        if flags & _FLAG_ZSTD:
            import zstandard

            with zstandard.ZstdDecompressor().stream_reader(io.BytesIO(payload)) as reader:
                data = reader.read(MAX_FIELD_BYTES + 1)
            return data if len(data) <= MAX_FIELD_BYTES else None
        if flags & _FLAG_XZ:
            data = lzma.LZMADecompressor().decompress(payload, max_length=MAX_FIELD_BYTES + 1)
            return data if len(data) <= MAX_FIELD_BYTES else None
        if flags & _FLAG_LZ4:
            import lz4.block

            if len(payload) < 8:
                return None
            declared = struct.unpack_from("<Q", payload, 0)[0]
            if declared > MAX_FIELD_BYTES:
                return None
            return lz4.block.decompress(payload[8:], uncompressed_size=declared)
    except Exception:  # noqa: BLE001 - corrupt or exotic payloads must not abort the scan
        return None
    return None


class _Journal:
    def __init__(self, buffer: Any) -> None:
        self.buf = buffer
        self.size = len(buffer)
        if self.size < _MIN_HEADER or bytes(buffer[:8]) != SIGNATURE:
            raise ValueError("not a systemd journal file")
        self.compact = bool(struct.unpack_from("<I", buffer, _OFF_INCOMPATIBLE_FLAGS)[0] & _INCOMPAT_COMPACT)
        self.header_size = struct.unpack_from("<Q", buffer, _OFF_HEADER_SIZE)[0]
        self.tail_offset = struct.unpack_from("<Q", buffer, _OFF_TAIL_OBJECT_OFFSET)[0]
        self._cache: dict[int, tuple[str, bytes] | None] = {}
        self.undecodable_fields = 0

    def _object_header(self, offset: int) -> tuple[int, int, int] | None:
        if offset < 0 or offset + _OBJECT_HEADER_SIZE > self.size:
            return None
        otype, flags, osize = _OBJECT_HEADER.unpack_from(self.buf, offset)
        if osize < _OBJECT_HEADER_SIZE or offset + osize > self.size:
            return None
        return otype, flags, osize

    def data_field(self, offset: int) -> tuple[str, bytes] | None:
        """Resolve the ``NAME=value`` data object at ``offset``."""
        if offset in self._cache:
            return self._cache[offset]
        result: tuple[str, bytes] | None = None
        header = self._object_header(offset) if offset % 8 == 0 else None
        if header and header[0] == _TYPE_DATA:
            _, flags, osize = header
            start = offset + (_DATA_PAYLOAD_OFFSET_COMPACT if self.compact else _DATA_PAYLOAD_OFFSET)
            end = offset + osize
            if start <= end:
                payload = bytes(self.buf[start:end])
                if flags & (_FLAG_XZ | _FLAG_LZ4 | _FLAG_ZSTD):
                    decoded = _decompress(payload, flags)
                    if decoded is None:
                        self.undecodable_fields += 1
                    payload = decoded if decoded is not None else b""
                name, separator, value = payload.partition(b"=")
                if separator and name:
                    result = (name.decode("ascii", "replace"), value)
        if len(self._cache) < _DATA_CACHE_LIMIT:
            self._cache[offset] = result
        return result

    def entries(self) -> Iterator[tuple[int, int, bytes, dict[str, bytes]]]:
        """Yield ``(seqnum, realtime_us, boot_id, fields)`` for every ENTRY object."""
        item_size = 4 if self.compact else 16
        position = max(self.header_size, _MIN_HEADER)
        position = (position + 7) & ~7
        last_object = min(self.tail_offset, self.size) if self.tail_offset else self.size
        while position <= last_object and position + _OBJECT_HEADER_SIZE <= self.size:
            header = self._object_header(position)
            if header is None:
                return
            otype, _flags, osize = header
            if otype == 0:
                return
            if otype == _TYPE_ENTRY and osize >= _ENTRY_FIXED:
                seqnum, realtime, _mono, boot_id, _xor = _ENTRY_STRUCT.unpack_from(self.buf, position + 16)
                fields: dict[str, bytes] = {}
                count = (osize - _ENTRY_FIXED) // item_size
                for index in range(min(count, MAX_FIELDS_PER_ENTRY)):
                    at = position + _ENTRY_FIXED + index * item_size
                    target = struct.unpack_from("<I" if self.compact else "<Q", self.buf, at)[0]
                    resolved = self.data_field(target)
                    if resolved and resolved[0] not in fields:
                        fields[resolved[0]] = resolved[1]
                yield seqnum, realtime, boot_id, fields
            position += (osize + 7) & ~7


def read_journal_entries(path: Path) -> tuple[list[tuple[int, int, bytes, dict[str, bytes]]], dict[str, Any]]:
    """Read every entry of a journal file. Returns ``(entries, info)``.

    ``info`` reports ``truncated`` (entry cap reached or the file ended mid-object) and
    ``undecodable_fields`` (compressed fields that could not be decoded).
    """
    info: dict[str, Any] = {"truncated": False, "undecodable_fields": 0}
    if path.stat().st_size == 0:
        return [], info
    entries: list[tuple[int, int, bytes, dict[str, bytes]]] = []
    with path.open("rb") as handle, mmap.mmap(handle.fileno(), 0, access=mmap.ACCESS_READ) as buffer:
        journal = _Journal(buffer)
        try:
            for entry in journal.entries():
                if len(entries) >= MAX_ENTRIES:
                    info["truncated"] = True
                    break
                entries.append(entry)
        except (struct.error, ValueError, IndexError):
            info["truncated"] = True
        info["undecodable_fields"] = journal.undecodable_fields
    return entries, info
