"""UAC's bodyfile (``bodyfile/bodyfile.txt``): the file system listing in the mactime format.

One line per file or directory of the collected system: ``MD5|name|inode|mode|UID|GID|size|atime|
mtime|ctime|crtime``, times in Unix seconds (0 when the file system does not record it). It is the
counterpart of an NTFS MFT listing: every file with its four times. A Mac's has millions of lines
(3.1 million, 650 MB on a test Mac), so it is searched on demand (scanning it takes about two
seconds), not indexed. Names can contain "|": the last nine fields are fixed, so a line is read
from the right.
"""
from __future__ import annotations

from collections.abc import Iterator
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

TIME_FIELDS = ("atime", "mtime", "ctime", "crtime")


def _time(value: str) -> str | None:
    try:
        seconds = int(float(value))
    except ValueError:
        return None
    if seconds <= 0 or seconds > 4_102_444_800:
        return None
    return datetime.fromtimestamp(seconds, tz=timezone.utc).isoformat()


def parse_line(line: str) -> dict[str, Any] | None:
    parts = line.rstrip("\r\n").split("|")
    if len(parts) < 11:
        return None
    md5, tail = parts[0], parts[-9:]
    name = "|".join(parts[1:-9])
    inode, mode, uid, gid, size, atime, mtime, ctime, crtime = tail
    target = ""
    if " -> " in name and mode.startswith("l"):
        name, target = name.split(" -> ", 1)
    try:
        size_value = int(size)
    except ValueError:
        size_value = None
    return {
        "path": name,
        "link_target": target or None,
        "md5": md5 if md5 not in {"", "0"} else None,
        "inode": inode,
        "mode": mode,
        "uid": uid,
        "gid": gid,
        "size": size_value,
        "atime": _time(atime),
        "mtime": _time(mtime),
        "ctime": _time(ctime),
        "crtime": _time(crtime),
    }


def iter_matches(path: Path, needle: str) -> Iterator[dict[str, Any]]:
    """Lines whose path contains ``needle`` (case-insensitive); matched on bytes before parsing."""
    wanted = needle.lower().encode("utf-8")
    with path.open("rb") as handle:
        for raw in handle:
            if wanted not in raw.lower():
                continue
            record = parse_line(raw.decode("utf-8", errors="replace"))
            if record is not None and needle.lower() in record["path"].lower():
                yield record
