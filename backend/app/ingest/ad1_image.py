"""AccessData AD1 logical images (FTK Imager "Contents of a Folder" and custom
content images), read with dissect.evidence.

An AD1 holds a file tree, not a filesystem, so Kairon treats it like a
collection archive: the tree is listed for preflight and, at registration, it
is repacked into a ZIP next to the original. Every later step (discovery,
selected extraction, the raw hive/SRUM/$MFT backends that call 7-Zip on the
original archive) then reads that ZIP exactly as it reads an uploaded one. The
.ad1 stays as the hashed original for integrity checks.

Paths are rebased on the source volume: FTK names the image after where it was
taken (``C:\\NONAME [NTFS]\\[root]\\Users\\alice``); the partition label and
``[root]`` are dropped, so entries read ``C/Users/alice/NTUSER.DAT`` like a
KAPE collection.
"""

from __future__ import annotations

from collections.abc import Callable, Iterator
from datetime import datetime, timezone
import json
from pathlib import Path
import re
import shutil
import zipfile

AD1_SUFFIX = ".ad1"
AD1_MAGIC = b"ADSEGMENTEDFILE"
_DRIVE_PART = re.compile(r"^([A-Za-z]):\\?$")
_ROOT_PART = "[root]"
_ZIP_EPOCH = (1980, 1, 1, 0, 0, 0)
_BUFFERED_ENTRY_BYTES = 64 * 1024 * 1024


class AD1ImageError(RuntimeError):
    def __init__(self, code: str, message: str):
        super().__init__(message)
        self.code = code
        self.message = message


def has_ad1_signature(path: Path) -> bool:
    try:
        with Path(path).open("rb") as handle:
            return handle.read(len(AD1_MAGIC)) == AD1_MAGIC
    except OSError:
        return False


def is_ad1_image(path: Path) -> bool:
    path = Path(path)
    return path.is_file() and path.suffix.lower() == AD1_SUFFIX and has_ad1_signature(path)


def open_ad1(path: Path):
    try:
        from dissect.evidence.ad1 import AD1
        from dissect.evidence.ad1.ad1 import SegmentFile
    except ImportError as exc:  # pragma: no cover - dependency is part of the image
        raise AD1ImageError("ad1_reader_unavailable", "The AD1 reader (dissect.evidence) is not installed.") from exc
    path = Path(path)
    with path.open("rb") as handle:
        if handle.read(len(AD1_MAGIC)) != AD1_MAGIC:
            raise AD1ImageError("ad1_invalid", f"{path.name} is not an AD1 image (no ADSEGMENTEDFILE signature).")
        handle.seek(0)
        segment_count = SegmentFile(handle).count
    if segment_count > 1:
        raise AD1ImageError(
            "ad1_multi_segment",
            f"{path.name} is the first of {segment_count} AD1 segments (.ad1, .ad2...). Multi-segment AD1 images are not supported yet; "
            "re-export it from FTK Imager as a single segment.",
        )
    try:
        image = AD1([path])
    except Exception as exc:  # noqa: BLE001
        raise AD1ImageError("ad1_invalid", f"{path.name} could not be read as an AD1 image: {exc}") from exc
    if image.is_adcrypt():
        raise AD1ImageError("ad1_encrypted", f"{path.name} is an encrypted (ADCRYPT) AD1 image. Decrypt it in FTK Imager before uploading.")
    return image


def rebase_parts(parts: list[str]) -> list[str]:
    """Image path parts -> collection-relative parts (see module docstring)."""
    lowered = [part.lower() for part in parts]
    if _ROOT_PART in lowered:
        index = lowered.index(_ROOT_PART)
        drive = next((match.group(1).upper() for part in parts[:index] if (match := _DRIVE_PART.match(part))), None)
        rest = parts[index + 1 :]
        return [drive, *rest] if drive else rest
    rebased = []
    for part in parts:
        match = _DRIVE_PART.match(part)
        rebased.append(match.group(1).upper() if match else part)
    return [part for part in rebased if part not in {"", "\\", "/"}]


def _content_rank(entry) -> tuple[int, int]:
    return (1 if entry.size else 0, entry.size)


def iter_ad1_files(image) -> Iterator[tuple[str, object]]:
    """(relative path, entry) for every live regular file.

    Deleted entries carry no reliable content and reparse points hold link
    data, not the target; both are skipped. FTK also stores NTFS index ($I30)
    entries for some files as a second, empty child of the same name; the one
    with content is kept.
    """

    def walk(entry, parts: list[str]):
        chosen: dict[str, object] = {}
        for child in entry.iterdir():
            if child.type is not None and child.type.name == "Deleted":
                continue
            key = child.name.lower()
            current = chosen.get(key)
            if current is None or (not child.is_dir() and not current.is_dir() and _content_rank(child) > _content_rank(current)):
                chosen[key] = child
        for child in chosen.values():
            child_parts = [*parts, child.name]
            if child.is_dir():
                yield from walk(child, child_parts)
            elif child.is_file() and not child.is_symlink():
                rebased = rebase_parts(child_parts)
                if rebased:
                    yield "/".join(rebased), child

    yield from walk(image.root, [])


def entry_mtime(entry) -> datetime | None:
    try:
        value = entry.mtime
    except Exception:  # noqa: BLE001
        return None
    return value if value.year > 1970 else None


_META_TIMES = {"crtime": "DateCreated", "mtime": "DateModified", "atime": "DateAccessed", "ctime": "MFTDateChanged"}
_META_FLAGS = ("Hidden", "System", "ReadOnly", "Archive", "Encrypted", "Compressed")


def _meta_text(meta: dict, name: str) -> str | None:
    item = next((value for key, value in meta.items() if getattr(key, "name", None) == name), None)
    if item is None:
        return None
    data = item.data
    text = data.decode("utf-8", errors="replace") if isinstance(data, (bytes, bytearray)) else str(data)
    return text.strip("\x00").strip() or None


def _epoch(text: str | None) -> int | None:
    if not text:
        return None
    try:
        value = datetime.strptime(text, "%Y%m%dT%H%M%S.%f" if "." in text else "%Y%m%dT%H%M%S").replace(tzinfo=timezone.utc)
    except ValueError:
        return None
    return int(value.timestamp()) if value.year > 1970 else None


def ad1_file_metadata(entry) -> dict:
    """What FTK recorded for one file when it was acquired: NTFS times,
    the hashes it computed, owner and DOS attributes."""
    try:
        meta = entry.meta
    except Exception:  # noqa: BLE001
        return {}
    record: dict = {key: _epoch(_meta_text(meta, name)) for key, name in _META_TIMES.items()}
    record.update({
        "md5": _meta_text(meta, "MD5"),
        "sha1": _meta_text(meta, "SHA1"),
        "owner": _meta_text(meta, "MFTOwnerName"),
        "owner_sid": _meta_text(meta, "MFTOwnerSid"),
        "short_name": _meta_text(meta, "ShortFilename"),
        "mft_record": _meta_text(meta, "MFTRecordNumber"),
        "attributes": [name.lower() for name in _META_FLAGS if (_meta_text(meta, name) or "").lower() == "true"],
    })
    return {key: value for key, value in record.items() if value not in (None, [], "")}


def write_ad1_metadata(files: list[tuple[str, object]], target: Path) -> None:
    target.parent.mkdir(parents=True, exist_ok=True)
    partial = target.with_name(f"{target.name}.partial")
    partial.write_text(json.dumps({"version": 1, "files": {path: ad1_file_metadata(entry) for path, entry in files}}), encoding="utf-8")
    partial.replace(target)


def convert_ad1_to_zip(source: Path, target: Path, progress_cb: Callable[[dict], None] | None = None, *, metadata_path: Path | None = None) -> dict:
    """Repack the image's live files into ``target`` (written atomically).
    Files whose content cannot be read are listed, not fatal. With
    ``metadata_path``, FTK's per-file metadata is kept there (the ZIP only
    holds a modification time)."""
    image = open_ad1(source)
    files = list(iter_ad1_files(image))
    if metadata_path is not None:
        write_ad1_metadata(files, metadata_path)
    total_bytes = sum(int(entry.size or 0) for _path, entry in files)
    partial = target.with_name(f"{target.name}.partial")
    failed: list[dict] = []
    written = 0
    written_bytes = 0
    seen: set[str] = set()
    try:
        with zipfile.ZipFile(partial, "w", compression=zipfile.ZIP_STORED, allowZip64=True) as archive:
            for index, (relative, entry) in enumerate(files, start=1):
                if relative.lower() in seen:
                    continue
                seen.add(relative.lower())
                mtime = entry_mtime(entry)
                info = zipfile.ZipInfo(relative, date_time=max(mtime.timetuple()[:6], _ZIP_EPOCH) if mtime else _ZIP_EPOCH)
                info.compress_type = zipfile.ZIP_STORED
                info.file_size = int(entry.size or 0)
                try:
                    if info.file_size == 0:
                        archive.writestr(info, b"")
                    elif info.file_size <= _BUFFERED_ENTRY_BYTES:
                        # Read first so a chunk that fails to decompress
                        # leaves no truncated member behind.
                        with entry.open() as src:
                            archive.writestr(info, src.read())
                    else:
                        with entry.open() as src, archive.open(info, "w") as dst:
                            shutil.copyfileobj(src, dst, 1024 * 1024)
                except Exception as exc:  # noqa: BLE001
                    failed.append({"path": relative, "error": f"{type(exc).__name__}: {exc}"[:300]})
                    continue
                written += 1
                written_bytes += info.file_size
                if progress_cb and index % 200 == 0:
                    progress_cb({"processed_files": index, "total_files": len(files), "processed_bytes": written_bytes, "total_bytes": total_bytes, "current_path": relative})
        partial.replace(target)
    except BaseException:
        partial.unlink(missing_ok=True)
        raise
    return {
        "format": "ad1",
        "image_name": image.logical_image.name,
        "files": written,
        "bytes": written_bytes,
        "failed": failed[:50],
        "failed_count": len(failed),
        "container_path": str(target),
    }
