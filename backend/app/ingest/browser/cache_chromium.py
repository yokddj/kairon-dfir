"""Chromium HTTP cache (Chrome, Edge, Brave, Opera): one record per cached resource.

Two on-disk formats, told apart by their files:

* blockfile (``index``, ``data_0``..``data_3``, ``f_*``): Chrome and Edge on Windows.
  ``index`` is a hash table of addresses into the block files; each points to a
  256-byte entry in ``data_1`` holding the key and the addresses of its streams.
* Simple Cache (``<16 hex>_0`` files, ``index-dir/the-real-index``): macOS, Linux,
  Android. Each ``_0`` file holds the key, the body and the response metadata.

Only the key and stream 0 (the pickled ``HttpResponseInfo``: times, status line,
headers, server address) are read. Stream 1 is the body, nearly all of a cache's
size, and is never read.

The key names the resource and, since Chrome 86 split the cache per site, the
top-level site whose page loaded it: ``1/0/_dk_<top-frame site> <frame site> <url>``.
That is what ties a third-party request to the page that caused it.
"""

from __future__ import annotations

import ipaddress
import logging
import re
import struct
from collections.abc import Iterator
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path

logger = logging.getLogger(__name__)

WINDOWS_EPOCH = datetime(1601, 1, 1, tzinfo=UTC)

# --- blockfile (net/disk_cache/blockfile/disk_format.h) ---------------------
INDEX_MAGIC = 0xC103CAC3
BLOCK_MAGIC = 0xC104CAC3
INDEX_HEADER_SIZE = 368
BLOCK_HEADER_SIZE = 8192
ENTRY_STORE_SIZE = 256
ENTRY_KEY_OFFSET = 96
ADDR_INITIALIZED = 0x80000000
# File type (bits 28-30) -> block size. 0 is an external f_ file.
BLOCK_SIZES = {1: 36, 2: 256, 3: 1024, 4: 4096, 5: 8, 6: 104, 7: 48}

# --- Simple Cache (net/disk_cache/simple/simple_entry_format.h) -------------
SIMPLE_INITIAL_MAGIC = 0xFCFB6D1BA7725C30
SIMPLE_FINAL_MAGIC = 0xF4FA6F45970D41D8
SIMPLE_HEADER_SIZE = 24
SIMPLE_EOF_SIZE = 24
SIMPLE_EOF_HAS_KEY_SHA256 = 0x2
SIMPLE_ENTRY_FILE = re.compile(r"^[0-9a-f]{16}_0$")

# A stream 0 larger than this is not response metadata.
MAX_METADATA_BYTES = 1 << 20
# Inline key bytes an entry can hold before Chromium moves the key out.
MAX_KEY_BYTES = 1 << 16

HEADERS_KEPT = ("content-type", "content-length", "server", "date", "last-modified", "location", "referrer-policy")


@dataclass
class CacheRecord:
    key: str
    url: str | None
    top_frame_site: str | None
    frame_site: str | None
    created: datetime | None
    last_used: datetime | None
    request_time: datetime | None
    response_time: datetime | None
    status_line: str | None
    status_code: int | None
    headers: dict[str, str]
    server_ip: str | None
    server_port: int | None
    body_size: int | None
    cache_format: str


def _windows_time(value: int) -> datetime | None:
    """Chromium's internal time: microseconds since 1601-01-01 UTC."""
    if value <= 0:
        return None
    try:
        moment = WINDOWS_EPOCH + timedelta(microseconds=value)
    except OverflowError:
        return None
    return moment if 1990 <= moment.year <= 2100 else None


def parse_cache_key(key: str) -> tuple[str | None, str | None, str | None]:
    """Split a cache key into (top-frame site, frame site, resource URL).

    ``1/0/_dk_https://site.com https://site.com https://cdn.net/a.js`` is a key
    of the split cache; a bare URL is a key from before it, or one Chromium does
    not split. ``_dk_cn_`` marks a credentialless load; the site follows."""
    text = key.strip()
    if not text:
        return None, None, None
    marker = text.find("_dk_")
    if marker < 0:
        return None, None, text.split(" ")[-1] or None
    parts = text[marker + 4:].split(" ")
    if parts and parts[0].startswith("cn_"):
        parts[0] = parts[0][3:]
    url = parts[-1] if len(parts) >= 2 else None
    top_frame = parts[0] if len(parts) >= 2 else None
    frame = parts[1] if len(parts) >= 3 else None
    return top_frame or None, frame or None, url or None


def _read_pickle_string(blob: bytes, offset: int) -> tuple[bytes, int] | None:
    if offset + 4 > len(blob):
        return None
    (length,) = struct.unpack_from("<i", blob, offset)
    if length < 0 or offset + 4 + length > len(blob):
        return None
    start = offset + 4
    return blob[start:start + length], start + ((length + 3) & ~3)


def parse_http_response_info(blob: bytes) -> dict:
    """The fields of a pickled ``HttpResponseInfo`` (net/http/http_response_info.cc)
    an investigator needs. Newer Chrome writes an extra flags word and a third
    time after the first two; the headers are found by their ``HTTP/`` status line
    rather than by a fixed offset, so the layouts of other versions read too."""
    result: dict = {"request_time": None, "response_time": None, "status_line": None, "status_code": None, "headers": {}, "server_ip": None, "server_port": None}
    if len(blob) < 24:
        return result
    offset = 4  # pickle payload size
    (flags,) = struct.unpack_from("<I", blob, offset)
    offset += 4
    if flags & 0x80000000:  # RESPONSE_INFO_HAS_EXTRA_FLAGS
        offset += 4
    if offset + 16 > len(blob):
        return result
    request, response = struct.unpack_from("<qq", blob, offset)
    result["request_time"] = _windows_time(request)
    result["response_time"] = _windows_time(response)
    headers_at = None
    for candidate in range(offset + 16, min(offset + 48, len(blob) - 8) + 1, 8):
        if blob[candidate + 4:candidate + 9] == b"HTTP/":
            headers_at = candidate
            break
    if headers_at is None:
        return result
    read = _read_pickle_string(blob, headers_at)
    if not read:
        return result
    raw_headers, after = read
    lines = [line.decode("latin-1", "replace") for line in raw_headers.split(b"\0") if line]
    if lines:
        result["status_line"] = lines[0]
        status = lines[0].split(" ")
        if len(status) >= 2 and status[1].isdigit():
            result["status_code"] = int(status[1])
        for line in lines[1:]:
            name, sep, value = line.partition(":")
            name = name.strip().lower()
            if sep and name in HEADERS_KEPT and name not in result["headers"]:
                result["headers"][name] = value.strip()
    ip, port = _find_socket_address(blob, after)
    result["server_ip"], result["server_port"] = ip, port
    return result


_ADDRESS_TEXT = re.compile(rb"[0-9a-fA-F:.\[\]]{2,47}")


def _find_socket_address(blob: bytes, start: int) -> tuple[str | None, int | None]:
    """The server address follows the certificate data, whose length depends on
    flags and on the chain. It is a pickled string holding an IP literal,
    followed by a 16-bit port: looked for by that shape rather than by walking
    every optional field before it."""
    for match in _ADDRESS_TEXT.finditer(blob, start):
        text = match.group()
        position = match.start()
        if position < 4 or struct.unpack_from("<i", blob, position - 4)[0] != len(text):
            continue
        try:
            address = ipaddress.ip_address(text.decode("ascii").strip("[]"))
        except ValueError:
            continue
        port_at = position + ((len(text) + 3) & ~3)
        port = struct.unpack_from("<H", blob, port_at)[0] if port_at + 2 <= len(blob) else None
        return str(address), port or None
    return None, None


def _record(key: str, metadata: bytes | None, *, created: datetime | None, last_used: datetime | None, body_size: int | None, cache_format: str) -> CacheRecord:
    top_frame, frame, url = parse_cache_key(key)
    info = parse_http_response_info(metadata) if metadata else {}
    return CacheRecord(
        key=key,
        url=url,
        top_frame_site=top_frame,
        frame_site=frame,
        created=created,
        last_used=last_used,
        request_time=info.get("request_time"),
        response_time=info.get("response_time"),
        status_line=info.get("status_line"),
        status_code=info.get("status_code"),
        headers=info.get("headers") or {},
        server_ip=info.get("server_ip"),
        server_port=info.get("server_port"),
        body_size=body_size,
        cache_format=cache_format,
    )


# --- format detection --------------------------------------------------------


def cache_format(directory: Path) -> str | None:
    index = directory / "index"
    if index.is_file():
        try:
            with index.open("rb") as handle:
                magic = handle.read(4)
        except OSError:
            magic = b""
        if len(magic) == 4 and struct.unpack("<I", magic)[0] == INDEX_MAGIC:
            return "blockfile"
    if (directory / "index-dir").is_dir() or any(SIMPLE_ENTRY_FILE.match(path.name) for path in _safe_iterdir(directory)):
        return "simple"
    return None


def _safe_iterdir(directory: Path) -> Iterator[Path]:
    try:
        yield from directory.iterdir()
    except OSError:
        return


def iter_chromium_cache(directory: Path, *, max_entries: int | None = None) -> Iterator[CacheRecord]:
    kind = cache_format(directory)
    if kind == "blockfile":
        yield from _iter_blockfile(directory, max_entries=max_entries)
    elif kind == "simple":
        yield from _iter_simple(directory, max_entries=max_entries)


# --- Simple Cache --------------------------------------------------------------


def _iter_simple(directory: Path, *, max_entries: int | None) -> Iterator[CacheRecord]:
    count = 0
    for path in sorted(_safe_iterdir(directory)):
        if not SIMPLE_ENTRY_FILE.match(path.name):
            continue
        record = _read_simple_entry(path)
        if record is None:
            continue
        yield record
        count += 1
        if max_entries is not None and count >= max_entries:
            return


def _read_simple_entry(path: Path) -> CacheRecord | None:
    try:
        size = path.stat().st_size
        if size < SIMPLE_HEADER_SIZE + SIMPLE_EOF_SIZE:
            return None
        with path.open("rb") as handle:
            header = handle.read(SIMPLE_HEADER_SIZE)
            magic, _version, key_length, _key_hash = struct.unpack("<QIII", header[:20])
            if magic != SIMPLE_INITIAL_MAGIC or key_length > MAX_KEY_BYTES or SIMPLE_HEADER_SIZE + key_length > size:
                return None
            key = handle.read(key_length).decode("utf-8", "replace")
            handle.seek(size - SIMPLE_EOF_SIZE)
            final_magic, flags, _crc, stream0_size = struct.unpack("<QIII", handle.read(20))
            if final_magic != SIMPLE_FINAL_MAGIC:
                return _record(key, None, created=None, last_used=_mtime(path), body_size=None, cache_format="simple")
            stream0_end = size - SIMPLE_EOF_SIZE - (32 if flags & SIMPLE_EOF_HAS_KEY_SHA256 else 0)
            metadata = None
            if 0 < stream0_size <= min(MAX_METADATA_BYTES, stream0_end):
                handle.seek(stream0_end - stream0_size)
                metadata = handle.read(stream0_size)
            # Body = what lies between the key and stream 0, less stream 1's EOF record.
            body_size = stream0_end - stream0_size - SIMPLE_EOF_SIZE - SIMPLE_HEADER_SIZE - key_length
    except (OSError, struct.error) as exc:
        logger.debug("Unreadable Simple Cache entry %s: %s", path, exc)
        return None
    return _record(key, metadata, created=None, last_used=_mtime(path), body_size=max(body_size, 0), cache_format="simple")


def _mtime(path: Path) -> datetime | None:
    try:
        return datetime.fromtimestamp(path.stat().st_mtime, tz=UTC)
    except OSError:
        return None


# --- blockfile -----------------------------------------------------------------


class _BlockFiles:
    """Reads blocks out of data_N and external f_XXXXXX files, opened once each."""

    def __init__(self, directory: Path) -> None:
        self.directory = directory
        self._handles: dict[str, object] = {}

    def close(self) -> None:
        for handle in self._handles.values():
            handle.close()  # type: ignore[attr-defined]
        self._handles.clear()

    def _handle(self, name: str):
        if name not in self._handles:
            path = self.directory / name
            self._handles[name] = path.open("rb") if path.is_file() else None
        return self._handles[name]

    def read(self, address: int, length: int | None = None) -> bytes | None:
        """The bytes at a CacheAddr: ``length`` of them, or the whole run of blocks."""
        if not address & ADDR_INITIALIZED:
            return None
        file_type = (address >> 28) & 0x7
        if file_type == 0:
            handle = self._handle(f"f_{address & 0x0FFFFFFF:06x}")
            if handle is None:
                return None
            handle.seek(0)
            return handle.read(length if length is not None else MAX_METADATA_BYTES)
        block_size = BLOCK_SIZES.get(file_type)
        if block_size is None:
            return None
        num_blocks = ((address >> 24) & 0x3) + 1
        file_number = (address >> 16) & 0xFF
        start_block = address & 0xFFFF
        handle = self._handle(f"data_{file_number}")
        if handle is None:
            return None
        span = num_blocks * block_size
        handle.seek(BLOCK_HEADER_SIZE + start_block * block_size)
        data = handle.read(span)
        return data[:length] if length is not None else data


def _iter_blockfile(directory: Path, *, max_entries: int | None) -> Iterator[CacheRecord]:
    try:
        index = (directory / "index").read_bytes()
    except OSError:
        return
    if len(index) < INDEX_HEADER_SIZE:
        return
    (table_len,) = struct.unpack_from("<i", index, 28)
    if table_len <= 0 or INDEX_HEADER_SIZE + table_len * 4 > len(index):
        table_len = (len(index) - INDEX_HEADER_SIZE) // 4
    blocks = _BlockFiles(directory)
    seen: set[int] = set()
    count = 0
    try:
        for (address,) in struct.iter_unpack("<I", index[INDEX_HEADER_SIZE:INDEX_HEADER_SIZE + table_len * 4]):
            # Collisions chain through each entry's "next" address.
            while address & ADDR_INITIALIZED and address not in seen:
                seen.add(address)
                entry = blocks.read(address)
                if not entry or len(entry) < ENTRY_STORE_SIZE:
                    break
                record, address = _read_blockfile_entry(entry, blocks)
                if record is not None:
                    yield record
                    count += 1
                    if max_entries is not None and count >= max_entries:
                        return
    finally:
        blocks.close()


def _read_blockfile_entry(entry: bytes, blocks: _BlockFiles) -> tuple[CacheRecord | None, int]:
    (_hash, next_address, rankings, _reuse, _refetch, _state, creation, key_length, long_key) = struct.unpack_from("<IIIiiiQiI", entry, 0)
    data_sizes = struct.unpack_from("<4i", entry, 40)
    data_addresses = struct.unpack_from("<4I", entry, 56)
    if key_length <= 0 or key_length > MAX_KEY_BYTES:
        return None, next_address
    if long_key & ADDR_INITIALIZED:
        raw_key = blocks.read(long_key, key_length) or b""
    else:
        raw_key = entry[ENTRY_KEY_OFFSET:ENTRY_KEY_OFFSET + key_length]
    key = raw_key.split(b"\0", 1)[0].decode("utf-8", "replace")
    metadata = None
    if 0 < data_sizes[0] <= MAX_METADATA_BYTES:
        metadata = blocks.read(data_addresses[0], data_sizes[0])
    last_used = None
    ranking = blocks.read(rankings, 16) if rankings & ADDR_INITIALIZED else None
    if ranking and len(ranking) >= 8:
        last_used = _windows_time(struct.unpack_from("<Q", ranking, 0)[0])
    record = _record(
        key,
        metadata,
        created=_windows_time(creation),
        last_used=last_used,
        body_size=max(data_sizes[1], 0),
        cache_format="blockfile",
    )
    return record, next_address
