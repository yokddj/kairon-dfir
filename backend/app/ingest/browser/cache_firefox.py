"""Firefox HTTP cache (``cache2/entries``): one record per cached resource.

Each entry file holds the body first and the metadata at the end
(netwerk/cache2/CacheFileMetadata.cpp); the last 4 bytes give where the
metadata starts. Only that tail is read:

    uint32 metadata hash, uint16 per 256 KiB chunk of body,
    uint32 version, fetch count, last fetched, last modified, frecency,
           expiration, key size, [flags if version >= 2]   (all big-endian)
    key + NUL, then "name\\0value\\0" elements (response-head, request-method...)

The key is ``[O^<origin attributes>,]<tags>,:<url>``; with network partitioning
the attributes carry ``partitionKey=(https,site.com)``, the top-level site whose
page loaded the resource.
"""

from __future__ import annotations

import logging
import re
import struct
from collections.abc import Iterator
from datetime import UTC, datetime
from pathlib import Path
from urllib.parse import unquote

from app.ingest.browser.cache_chromium import HEADERS_KEPT, CacheRecord

logger = logging.getLogger(__name__)

CHUNK_SIZE = 256 * 1024
MAX_METADATA_BYTES = 1 << 20
ENTRY_FILE = re.compile(r"^[0-9A-F]{40}$")


def parse_firefox_cache_key(key: str) -> tuple[str | None, str | None]:
    """(top-level site, resource URL) of a cache2 key."""
    url = None
    marker = key.find(",:")
    if marker >= 0:
        url = key[marker + 2:]
    elif key.startswith(":"):
        url = key[1:]
    site = None
    match = re.search(r"partitionKey=([^&,]+)", key)
    if match:
        parts = unquote(match.group(1)).strip("()").split(",")
        if len(parts) >= 2 and parts[0] and parts[1]:
            site = f"{parts[0]}://{parts[1]}" + (f":{parts[2]}" if len(parts) >= 3 and parts[2].isdigit() else "")
    return site, url or None


def _epoch(value: int) -> datetime | None:
    if value <= 0:
        return None
    try:
        moment = datetime.fromtimestamp(value, tz=UTC)
    except (OverflowError, OSError, ValueError):
        return None
    return moment if 1990 <= moment.year <= 2100 else None


def read_firefox_cache_entry(path: Path) -> CacheRecord | None:
    try:
        size = path.stat().st_size
        if size < 8:
            return None
        with path.open("rb") as handle:
            handle.seek(size - 4)
            (offset,) = struct.unpack(">I", handle.read(4))
            if offset >= size - 4 or size - offset > MAX_METADATA_BYTES:
                return None
            handle.seek(offset)
            tail = handle.read(size - 4 - offset)
    except OSError as exc:
        logger.debug("Unreadable Firefox cache entry %s: %s", path, exc)
        return None
    chunks = (offset + CHUNK_SIZE - 1) // CHUNK_SIZE
    position = 4 + chunks * 2
    if position + 28 > len(tail):
        return None
    version, _fetch_count, last_fetched, last_modified, _frecency, _expiration, key_size = struct.unpack_from(">7I", tail, position)
    position += 28
    if version >= 2:
        position += 4
    if version > 16 or position + key_size > len(tail):
        return None
    key = tail[position:position + key_size].decode("utf-8", "replace")
    position += key_size + 1
    elements: dict[str, str] = {}
    fields = tail[position:].split(b"\0")
    for name, value in zip(fields[0::2], fields[1::2]):
        if name:
            elements[name.decode("latin-1", "replace")] = value.decode("latin-1", "replace")
    site, url = parse_firefox_cache_key(key)
    status_line, status_code, headers = None, None, {}
    response_head = elements.get("response-head")
    if response_head:
        lines = [line for line in response_head.replace("\r\n", "\n").split("\n") if line]
        if lines:
            status_line = lines[0]
            parts = status_line.split(" ")
            if len(parts) >= 2 and parts[1].isdigit():
                status_code = int(parts[1])
            for line in lines[1:]:
                name, sep, value = line.partition(":")
                name = name.strip().lower()
                if sep and name in HEADERS_KEPT and name not in headers:
                    headers[name] = value.strip()
    return CacheRecord(
        key=key,
        url=url,
        top_frame_site=site,
        frame_site=None,
        created=None,
        last_used=_epoch(last_fetched),
        request_time=None,
        response_time=_epoch(last_modified),
        status_line=status_line,
        status_code=status_code,
        headers=headers,
        server_ip=None,
        server_port=None,
        body_size=offset,
        cache_format="firefox_cache2",
    )


def iter_firefox_cache(entries_dir: Path, *, max_entries: int | None = None) -> Iterator[CacheRecord]:
    count = 0
    try:
        paths = sorted(entries_dir.iterdir())
    except OSError:
        return
    for path in paths:
        if not ENTRY_FILE.match(path.name):
            continue
        record = read_firefox_cache_entry(path)
        if record is None:
            continue
        yield record
        count += 1
        if max_entries is not None and count >= max_entries:
            return
