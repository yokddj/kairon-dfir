"""Browser HTTP caches as browser rows: one per cached resource.

The artifact path is the cache directory (Chromium ``Cache_Data`` or Firefox
``cache2/entries``); the format is recognised from its files.
"""

from __future__ import annotations

from collections.abc import Iterator
from datetime import datetime
from pathlib import Path

from app.ingest.browser.cache_chromium import CacheRecord, cache_format, iter_chromium_cache
from app.ingest.browser.cache_firefox import ENTRY_FILE as FIREFOX_ENTRY_FILE, iter_firefox_cache

CACHE_ARTIFACT_TYPE = "browser_cache"


def _iso(value: datetime | None) -> str | None:
    return value.isoformat() if value else None


def cache_directory_for(path: Path) -> Path:
    """The cache directory an artifact path stands for. Discovery anchors a cache
    on one file: ``Cache_Data/index`` for Chromium (both formats have it),
    ``cache2/index`` for Firefox, whose entries sit in ``cache2/entries``."""
    if path.is_dir():
        return path
    if path.name.lower() == "index" and (path.parent / "entries").is_dir():
        return path.parent / "entries"
    return path.parent


def detect_cache_format(directory: Path) -> str | None:
    kind = cache_format(directory)
    if kind:
        return kind
    try:
        if any(FIREFOX_ENTRY_FILE.match(path.name) for path in directory.iterdir()):
            return "firefox_cache2"
    except OSError:
        return None
    return None


def iter_cache_records(directory: Path, *, max_entries: int | None = None) -> Iterator[CacheRecord]:
    kind = detect_cache_format(directory)
    if kind == "firefox_cache2":
        yield from iter_firefox_cache(directory, max_entries=max_entries)
    elif kind:
        yield from iter_chromium_cache(directory, max_entries=max_entries)


def cache_row(record: CacheRecord, *, source_path: str) -> dict:
    return {
        "ArtifactType": CACHE_ARTIFACT_TYPE,
        "SourceFile": source_path,
        "URL": record.url,
        "Cache Key": record.key,
        "Top Frame Site": record.top_frame_site,
        "Frame Site": record.frame_site,
        "Cache Request Time": _iso(record.request_time),
        "Cache Response Time": _iso(record.response_time),
        "Cache Last Used": _iso(record.last_used),
        "Cache Created": _iso(record.created),
        "HTTP Status": record.status_code,
        "Status Line": record.status_line,
        "Content Type": record.headers.get("content-type"),
        "Content Length": record.headers.get("content-length"),
        "Server": record.headers.get("server"),
        "Location": record.headers.get("location"),
        "Server IP": record.server_ip,
        "Server Port": record.server_port,
        "Body Size": record.body_size,
        "Cache Format": record.cache_format,
    }


def read_browser_cache(path: Path, *, source_path: str, max_entries: int | None = None) -> list[dict]:
    directory = cache_directory_for(path)
    return [cache_row(record, source_path=source_path) for record in iter_cache_records(directory, max_entries=max_entries)]
