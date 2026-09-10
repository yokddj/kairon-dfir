"""Parses WebCacheV01.dat, the ESE (Jet Blue) database where legacy Windows
Internet Explorer / pre-Chromium Edge store browsing history and download
records. Unlike Chrome/Firefox's SQLite stores, this file has no public
schema documentation from Microsoft -- the "Containers" table maps container
IDs to logical stores (History, iedownload, Cookies, Content caches, ...),
and each container's actual entries live in a same-shaped "Container_<id>"
table. We only read the containers that hold real browsing activity
(History / the per-day "MSHist01..." containers, and iedownload); Cookies
and cache-content containers are left untouched, matching how Kairon already
treats Chrome's Cookies/Login Data as sensitive and unparsed.
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import Iterator

from app.ingest.recycle_bin.helpers import parse_windows_filetime

WEBCACHE_FILENAME = "webcachev01.dat"

_MSHIST01_PREFIX = "mshist01"
_MSHIST01_URL_PREFIX_RE = re.compile(r"^:\d{16}:\s*")
_UTF16LE_STRING_RE = re.compile(rb"(?:[\x20-\x7e]\x00){4,}")
_WINDOWS_PATH_RE = re.compile(r"^[A-Za-z]:\\")


def looks_like_webcache_database(path: Path) -> bool:
    return path.name.lower() == WEBCACHE_FILENAME


def _is_history_container(name: str) -> bool:
    lowered = name.lower()
    return lowered == "history" or lowered.startswith(_MSHIST01_PREFIX)


def _decode_history_url(raw_url: str) -> str | None:
    """Real History entries: "Visited: <user>@<url>". The per-day
    "MSHist01..." containers use ":<16-digit date range>: <user>@<url>"
    instead. A small number of entries are host-visit summaries shaped
    "<user>@:Host: <hostname>" rather than a real page visit -- those are
    dropped, not real navigable URLs."""
    value = raw_url
    if value.startswith("Visited: "):
        value = value[len("Visited: ") :]
    else:
        value = _MSHIST01_URL_PREFIX_RE.sub("", value, count=1)
    if "@" not in value:
        return None
    _user, _, url = value.partition("@")
    if not url or url.startswith(":Host:"):
        return None
    if not url.lower().startswith(("http://", "https://", "ftp://", "file://")):
        return None
    return url


def _extract_utf16le_strings(blob: bytes, min_length: int = 4) -> list[str]:
    strings = []
    for match in _UTF16LE_STRING_RE.finditer(blob):
        try:
            text = match.group(0).decode("utf-16-le")
        except UnicodeDecodeError:
            continue
        if len(text) >= min_length:
            strings.append(text)
    return strings


def _decode_download_fields(response_headers: bytes | None) -> tuple[str | None, str | None]:
    """The iedownload container's ResponseHeaders column is an internal,
    version-specific binary blob with no public schema; it embeds the
    source URL and local target path as UTF-16LE strings among fixed
    binary fields whose offsets shift across Windows/Edge versions. Rather
    than hand-decode those offsets, we extract every embedded string and
    classify by shape -- the same heuristic community DFIR tooling uses
    for this artifact."""
    if not response_headers:
        return None, None
    strings = _extract_utf16le_strings(bytes(response_headers))
    urls = [s for s in strings if s.lower().startswith(("http://", "https://"))]
    paths = [s for s in strings if _WINDOWS_PATH_RE.match(s)]
    download_url = urls[-1] if urls else None
    target_path = paths[-1] if paths else None
    return download_url, target_path


def read_webcache_records(path: Path) -> Iterator[dict]:
    from dissect.esedb.esedb import EseDB

    with path.open("rb") as handle:
        db = EseDB(handle)
        try:
            containers_table = db.table("Containers")
        except Exception:  # noqa: BLE001
            return
        container_names: dict[int, str] = {}
        for record in containers_table.records():
            container_id = record.get("ContainerId")
            name = record.get("Name")
            if container_id is not None and name:
                container_names[int(container_id)] = str(name)
        for container_id, name in container_names.items():
            is_history = _is_history_container(name)
            is_download = name.lower() == "iedownload"
            if not is_history and not is_download:
                continue
            try:
                table = db.table(f"Container_{container_id}")
            except Exception:  # noqa: BLE001
                continue
            for record in table.records():
                raw_url = record.get("Url")
                if not raw_url:
                    continue
                accessed_time = parse_windows_filetime(record.get("AccessedTime"))
                if is_history:
                    url = _decode_history_url(str(raw_url))
                    if not url:
                        continue
                    yield {
                        "URL": url,
                        "Visit Time": accessed_time,
                        "Visit Count": record.get("AccessCount"),
                        "Browser": "Internet Explorer / Edge (legacy)",
                        "SourceFile": str(path),
                    }
                else:
                    download_url, target_path = _decode_download_fields(record.get("ResponseHeaders"))
                    if not download_url and not target_path:
                        continue
                    yield {
                        "Download URL": download_url,
                        "Target Path": target_path,
                        "Download End Time": accessed_time,
                        "Browser": "Internet Explorer / Edge (legacy)",
                        "SourceFile": str(path),
                    }
