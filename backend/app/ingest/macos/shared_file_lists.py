"""Shared file lists (``~/Library/Application Support/com.apple.sharedfilelist/*.sfl2|sfl3|sfl4``).

macOS keeps the user's recent documents, recent applications, recent servers, Finder favourites
and, per application, the documents it opened recently
(``com.apple.LSSharedFileList.ApplicationRecentDocuments/<bundle id>.sfl*``). Each file is an
NSKeyedArchiver property list whose ``items`` hold a name and a **bookmark**: Apple's binary
alias format (``book`` header), which keeps the target's path components, its volume and its
creation date.

Items carry no time of their own. Their order is the list's (most recent first in the recent
lists) and the list file's modification time is when the list last changed; it is kept as
``list_modified``, not as the items' time.
"""
from __future__ import annotations

import plistlib
import re
import struct
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

from app.ingest.macos.common import file_mtime_iso, load_plist, original_path, user_from_path

ARTIFACT_FAMILY = "macos_recent_items"
_SFL_RE = re.compile(r"/Library/Application Support/com\.apple\.sharedfilelist/(?P<rest>.+\.sfl[234])$", re.IGNORECASE)
_COCOA_EPOCH = datetime(2001, 1, 1, tzinfo=timezone.utc)
# Bookmark table-of-contents keys (Apple's CFURL bookmark format, as documented by mac_alias).
_KEY_PATH = 0x1004
_KEY_CREATION = 0x1040
_KEY_VOLUME_PATH = 0x2002
_KEY_VOLUME_NAME = 0x2010
_TYPE_STRING = 0x0101
_TYPE_ARRAY = 0x0601
_TYPE_DATE = 0x0400


def is_shared_file_list(original: str) -> bool:
    return bool(_SFL_RE.search(original))


def _list_kind(original: str) -> tuple[str, str]:
    """(list name, application bundle id or "") from the file's place."""
    match = _SFL_RE.search(original)
    rest = match.group("rest") if match else Path(original).name
    parts = rest.split("/")
    if len(parts) >= 2 and parts[0].lower() == "com.apple.lsSharedFileList.ApplicationRecentDocuments".lower():
        return "ApplicationRecentDocuments", re.sub(r"\.sfl[234]$", "", parts[-1], flags=re.IGNORECASE)
    name = re.sub(r"\.sfl[234]$", "", parts[-1], flags=re.IGNORECASE)
    return name.removeprefix("com.apple.LSSharedFileList."), ""


def _resolve(objects: list[Any], value: Any, depth: int = 0) -> Any:
    """Turn an NSKeyedArchiver object graph into plain Python values."""
    if depth > 40:
        return None
    if isinstance(value, plistlib.UID):
        value = objects[value.data] if value.data < len(objects) else None
    if isinstance(value, str) and value == "$null":
        return None
    if isinstance(value, dict):
        if "NS.keys" in value and "NS.objects" in value:
            keys = [_resolve(objects, key, depth + 1) for key in value["NS.keys"]]
            return {str(key): _resolve(objects, item, depth + 1) for key, item in zip(keys, value["NS.objects"])}
        if "NS.objects" in value:
            return [_resolve(objects, item, depth + 1) for item in value["NS.objects"]]
        if "NS.data" in value:
            return value["NS.data"]
        if "NS.string" in value:
            return value["NS.string"]
        if "NS.time" in value:
            return value["NS.time"]
        return {key: _resolve(objects, item, depth + 1) for key, item in value.items() if key != "$class"}
    return value


def parse_bookmark(blob: bytes) -> dict[str, Any]:
    """Path, volume and creation date from a CFURL bookmark (``book`` format); {} when unreadable."""
    if not isinstance(blob, (bytes, bytearray)) or len(blob) < 48 or blob[:4] != b"book":
        return {}
    try:
        header_size = struct.unpack_from("<I", blob, 12)[0]
        base = header_size
        toc_offset = struct.unpack_from("<I", blob, base)[0]
        items: dict[int, int] = {}
        guard = 0
        while toc_offset and guard < 16:
            guard += 1
            start = base + toc_offset
            _size, magic, _toc_id, next_toc, count = struct.unpack_from("<IIIII", blob, start)
            if magic != 0xFFFFFFFE:
                break
            for index in range(count):
                key, offset, _reserved = struct.unpack_from("<III", blob, start + 20 + index * 12)
                items.setdefault(key & 0x7FFFFFFF, offset)
            toc_offset = next_toc

        def item(offset: int) -> tuple[int, bytes]:
            length, kind = struct.unpack_from("<II", blob, base + offset)
            return kind, blob[base + offset + 8: base + offset + 8 + length]

        def text(offset: int) -> str | None:
            kind, payload = item(offset)
            return payload.decode("utf-8", errors="replace") if kind == _TYPE_STRING else None

        result: dict[str, Any] = {}
        if _KEY_PATH in items:
            kind, payload = item(items[_KEY_PATH])
            if kind == _TYPE_ARRAY:
                parts = [text(struct.unpack_from("<I", payload, index * 4)[0]) for index in range(len(payload) // 4)]
                result["path"] = "/" + "/".join(part for part in parts if part)
        if _KEY_VOLUME_PATH in items:
            result["volume_path"] = text(items[_KEY_VOLUME_PATH])
        if _KEY_VOLUME_NAME in items:
            result["volume_name"] = text(items[_KEY_VOLUME_NAME])
        if _KEY_CREATION in items:
            kind, payload = item(items[_KEY_CREATION])
            if kind == _TYPE_DATE and len(payload) >= 8:
                seconds = struct.unpack(">d", payload[:8])[0]
                if -3e9 < seconds < 3e9:
                    result["target_created"] = (_COCOA_EPOCH + timedelta(seconds=seconds)).isoformat()
        return result
    except (struct.error, IndexError, ValueError):
        return {}


def parse_shared_file_list(path: Path, *, source_path: str) -> list[dict[str, Any]]:
    original = original_path(source_path)
    list_name, bundle_id = _list_kind(original)
    archive = load_plist(path)
    if not isinstance(archive, dict) or "$objects" not in archive:
        return []
    objects = archive["$objects"]
    top = archive.get("$top") or {}
    root = _resolve(objects, top.get("root"))
    entries = root.get("items") if isinstance(root, dict) else None
    if not isinstance(entries, list):
        return []
    username = user_from_path(source_path)
    modified = file_mtime_iso(path)
    rows: list[dict[str, Any]] = []
    for position, entry in enumerate(entries):
        if not isinstance(entry, dict):
            continue
        bookmark = parse_bookmark(entry.get("Bookmark")) if isinstance(entry.get("Bookmark"), (bytes, bytearray)) else {}
        name = str(entry.get("Name") or "") or Path(str(bookmark.get("path") or "")).name
        target = bookmark.get("path") or ""
        where = f"{bundle_id} " if bundle_id else ""
        rows.append({
            "artifact_family": ARTIFACT_FAMILY,
            "artifact_type": "recent_item",
            "source_file": source_path,
            "line_number": position + 1,
            "username": username,
            "list_name": list_name,
            "bundle_id": bundle_id,
            "item_name": name,
            "item_path": target,
            "volume_path": bookmark.get("volume_path") or "",
            "volume_name": bookmark.get("volume_name") or "",
            "target_created": bookmark.get("target_created"),
            "list_position": position + 1,
            "list_modified": modified,
            "timestamp": None,
            "timestamp_status": "not_recorded",
            "event_action": "recent_item",
            "message": f"{list_name} {where}#{position + 1}: {target or name}",
        })
    return rows
