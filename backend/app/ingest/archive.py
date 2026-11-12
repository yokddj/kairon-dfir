import errno
import json
import logging
import os
from datetime import datetime, timezone
import shutil
import struct
import subprocess
import tempfile
import zipfile
import zlib
from collections.abc import Callable
from pathlib import Path

from app.core.config import get_settings
from app.core.storage import ensure_within_directory

settings = get_settings()
logger = logging.getLogger(__name__)
IGNORED_NAMES = {".DS_Store"}
WINDOWS_IGNORED_NAMES = {"desktop.ini", "thumbs.db"}
# What Python's own zipfile can decompress. Anything else in a .zip has to go
# through 7-Zip; Deflate64 (9) is the one that shows up in practice.
_ZIPFILE_SUPPORTED_COMPRESSION = frozenset({
    zipfile.ZIP_STORED,
    zipfile.ZIP_DEFLATED,
    zipfile.ZIP_BZIP2,
    zipfile.ZIP_LZMA,
})

SEVEN_ZIP_ARCHIVE_SUFFIXES: tuple[tuple[str, ...], ...] = (
    (".7z",),
    (".rar",),
    (".tar",),
    (".gz",),
    (".bz2",),
    (".xz",),
    (".tgz",),
    (".tbz2",),
    (".txz",),
    (".tar", ".gz"),
    (".tar", ".bz2"),
    (".tar", ".xz"),
)

class ArchiveExtractionError(RuntimeError):
    """A classified archive extraction failure.

    ``message`` is analyst-facing (no internal paths, commands, or raw
    subprocess output) and is what callers should surface in the API.
    ``detail`` is technical (exit codes, truncated tool output) and is
    for server logs only -- it is never returned to the analyst.
    """

    def __init__(self, code: str, message: str, *, detail: str | None = None):
        self.code = code
        self.message = message
        self.detail = detail
        super().__init__(message)


def _is_disk_space_error(exc: OSError) -> bool:
    return getattr(exc, "errno", None) == errno.ENOSPC


def _decode_process_output(exc: subprocess.CalledProcessError) -> str:
    stderr = exc.stderr if isinstance(exc.stderr, bytes) else (exc.stderr or b"").encode()
    stdout = exc.stdout if isinstance(exc.stdout, bytes) else (exc.stdout or b"").encode()
    return (stderr + b"\n" + stdout).decode("utf-8", "ignore")


def _classify_seven_zip_failure(exc: Exception, source: Path) -> ArchiveExtractionError:
    if isinstance(exc, FileNotFoundError):
        return ArchiveExtractionError(
            "archive_tool_missing",
            "The server is missing the 7z tool required to extract this archive type.",
            detail=str(exc),
        )
    if isinstance(exc, subprocess.TimeoutExpired):
        return ArchiveExtractionError(
            "archive_extraction_timeout",
            f"Extraction of {source.name} took too long and was stopped.",
            detail=str(exc),
        )
    if isinstance(exc, subprocess.CalledProcessError):
        output = _decode_process_output(exc).lower()
        if "wrong password" in output or "enter password" in output:
            return ArchiveExtractionError(
                "archive_password_protected",
                f"{source.name} is password-protected. Provide the password or extract it before uploading.",
                detail=output[:2000],
            )
        if "no space left" in output or "not enough space" in output or "disk full" in output:
            return ArchiveExtractionError(
                "archive_insufficient_disk_space",
                "The server ran out of disk space while extracting this archive.",
                detail=output[:2000],
            )
        if ("cannot open" in output and "as archive" in output) or "is not supported archive" in output or "unsupported method" in output:
            return ArchiveExtractionError(
                "archive_unsupported_format",
                f"{source.name}'s format is not recognized or is not supported.",
                detail=output[:2000],
            )
        if "data error" in output or "crc failed" in output or "headers error" in output or "unexpected end of archive" in output:
            return ArchiveExtractionError(
                "archive_corrupted",
                f"{source.name} appears to be corrupted or incomplete.",
                detail=output[:2000],
            )
        return ArchiveExtractionError(
            "archive_extraction_failed",
            f"The archive extraction tool could not process {source.name}.",
            detail=f"exit_code={exc.returncode} output={output[:2000]!r}",
        )
    if isinstance(exc, OSError) and _is_disk_space_error(exc):
        return ArchiveExtractionError(
            "archive_insufficient_disk_space",
            "The server ran out of disk space while extracting this archive.",
            detail=str(exc),
        )
    return ArchiveExtractionError(
        "archive_extraction_failed",
        f"Extraction of {source.name} failed unexpectedly.",
        detail=f"{type(exc).__name__}: {exc}",
    )


def _classify_zip_failure(exc: Exception, source: Path) -> ArchiveExtractionError:
    if isinstance(exc, zipfile.BadZipFile):
        return ArchiveExtractionError(
            "archive_corrupted",
            f"{source.name} is corrupted or is not a valid ZIP file.",
            detail=str(exc),
        )
    if isinstance(exc, RuntimeError) and "password" in str(exc).lower():
        return ArchiveExtractionError(
            "archive_password_protected",
            f"{source.name} is password-protected. Provide the password or extract it before uploading.",
            detail=str(exc),
        )
    if isinstance(exc, OSError) and _is_disk_space_error(exc):
        return ArchiveExtractionError(
            "archive_insufficient_disk_space",
            "The server ran out of disk space while extracting this archive.",
            detail=str(exc),
        )
    return ArchiveExtractionError(
        "archive_extraction_failed",
        f"Extraction of {source.name} failed unexpectedly.",
        detail=f"{type(exc).__name__}: {exc}",
    )


def should_ignore_path(path: Path, *, size: int | None = None, is_dir: bool = False) -> tuple[bool, str | None]:
    lowered_parts = [part.lower() for part in path.parts]
    if is_dir:
        return True, "ignored_directory"
    if "__macosx" in lowered_parts:
        return True, "ignored_macos_directory"
    if path.name in IGNORED_NAMES:
        return True, "ignored_macos_metadata"
    if path.name.startswith("._") or any(part.startswith("._") for part in path.parts):
        return True, "ignored_appledouble_resource_fork"
    if path.name.lower() in WINDOWS_IGNORED_NAMES:
        return True, "ignored_windows_metadata"
    if size == 0:
        return True, "ignored_zero_size"
    return False, None


_ZIP_UNIX_TIME_EXTRA = 0x5455
_DOS_EPOCH = (1980, 1, 1, 0, 0, 0)


def zip_member_mtime(member: zipfile.ZipInfo) -> float | None:
    """The modification time a ZIP recorded for a member, as epoch seconds.

    The extended-timestamp extra field (Info-ZIP, macOS, 7-Zip) holds it in
    UTC; otherwise the DOS time, which has no zone, is taken as UTC. The DOS
    epoch itself means "not recorded"."""
    extra = member.extra or b""
    offset = 0
    while offset + 4 <= len(extra):
        tag = int.from_bytes(extra[offset:offset + 2], "little")
        size = int.from_bytes(extra[offset + 2:offset + 4], "little")
        body = extra[offset + 4:offset + 4 + size]
        if tag == _ZIP_UNIX_TIME_EXTRA and len(body) >= 5 and body[0] & 1:
            return float(int.from_bytes(body[1:5], "little", signed=True))
        offset += 4 + size
    if tuple(member.date_time) == _DOS_EPOCH:
        return None
    try:
        return datetime(*member.date_time, tzinfo=timezone.utc).timestamp()
    except ValueError:
        return None


def restore_mtime(path: Path, mtime: float | None) -> None:
    """Give an extracted copy the time its archive recorded instead of the
    extraction time: parsers fall back to a file's mtime when the artifact
    has no time of its own, and a copy dated "now" puts it on the timeline
    at the moment of processing."""
    if mtime is None:
        return
    try:
        os.utime(path, (mtime, mtime))
    except (OSError, OverflowError, ValueError):
        pass


def _validate_path(dest_dir: Path, member_name: str) -> Path:
    target = dest_dir / member_name
    if Path(member_name).is_absolute():
        raise ValueError(f"Absolute archive path is not allowed: {member_name}")
    ensure_within_directory(dest_dir, target)
    return target


def _matches_suffix_parts(path: Path, suffix_parts: tuple[str, ...]) -> bool:
    suffixes = tuple(part.lower() for part in path.suffixes)
    return suffixes[-len(suffix_parts):] == suffix_parts


def _is_seven_zip_supported_archive(path: Path) -> bool:
    return any(_matches_suffix_parts(path, suffix_parts) for suffix_parts in SEVEN_ZIP_ARCHIVE_SUFFIXES)


def _enforce_limits(entries: list[dict]) -> None:
    file_count = sum(1 for entry in entries if not entry.get("ignored"))
    total_bytes = sum(entry.get("size", 0) for entry in entries if not entry.get("ignored"))
    if file_count > settings.backend_max_extracted_files:
        raise ValueError(f"Extracted file count limit exceeded: {file_count} > {settings.backend_max_extracted_files}")
    if total_bytes > settings.backend_max_extracted_bytes:
        raise ValueError(f"Extracted byte limit exceeded: {total_bytes} > {settings.backend_max_extracted_bytes}")


def _safe_members_zip(archive: zipfile.ZipFile, dest_dir: Path, progress_cb: Callable[[dict], None] | None = None) -> list[dict]:
    manifest_entries = []
    members = [member for member in archive.infolist() if not member.is_dir()]
    total_files = len(members)
    total_bytes = sum(member.file_size for member in members)
    processed_files = 0
    processed_bytes = 0
    for member in members:
        target = _validate_path(dest_dir, member.filename)
        ignored, reason = should_ignore_path(Path(member.filename), size=member.file_size, is_dir=False)
        processed_files += 1
        processed_bytes += member.file_size
        if ignored:
            manifest_entries.append(
                {
                    "path": member.filename,
                    "ignored": True,
                    "reason": reason,
                    "size": member.file_size,
                    "status": "ignored",
                    "local_path": None,
                }
            )
            if progress_cb:
                progress_cb({"processed_files": processed_files, "total_files": total_files, "processed_bytes": processed_bytes, "total_bytes": total_bytes, "current_path": member.filename})
            continue
        target.parent.mkdir(parents=True, exist_ok=True)
        with archive.open(member) as src, target.open("wb") as dst:
            shutil.copyfileobj(src, dst)
        restore_mtime(target, zip_member_mtime(member))
        manifest_entries.append(
            {
                "path": member.filename,
                "ignored": False,
                "reason": None,
                "size": member.file_size,
                "status": "extracted",
                "local_path": str(target),
            }
        )
        if progress_cb:
            progress_cb({"processed_files": processed_files, "total_files": total_files, "processed_bytes": processed_bytes, "total_bytes": total_bytes, "current_path": member.filename})
    _enforce_limits(manifest_entries)
    return manifest_entries


def _raise_classified(classified: ArchiveExtractionError, source: Path, from_exc: Exception) -> None:
    # The classified .message is what reaches the analyst; .detail (and the
    # chained original exception, preserved via `from`) stays in the log so
    # administrators keep full technical diagnostics.
    logger.error(
        "archive extraction failed source=%s code=%s detail=%s",
        source.name, classified.code, classified.detail,
    )
    raise classified from from_exc


def _classify_limit_exceeded(exc: ValueError, source: Path) -> ArchiveExtractionError | None:
    if "limit exceeded" not in str(exc).lower():
        return None
    return ArchiveExtractionError(
        "archive_extraction_limit_exceeded",
        f"{source.name} extracts to more files or bytes than the configured safety limit allows.",
        detail=str(exc),
    )


_LOCAL_HEADER = b"PK\x03\x04"
_DATA_DESCRIPTOR = b"PK\x07\x08"
_ZIP64_EXTRA = 0x0001
_SALVAGE_CHUNK = 1024 * 1024
TRUNCATED_STATUS = "truncated"


class _EntryCut(Exception):
    """The archive ends, or its data stops making sense, inside this entry."""


def _starts_with_local_header(source: Path) -> bool:
    try:
        with source.open("rb") as handle:
            return handle.read(4) == _LOCAL_HEADER
    except OSError:
        return False


def _zip64_sizes(extra: bytes, csize: int, usize: int) -> tuple[int, int, bool]:
    """Sizes from a local header's ZIP64 extra field, which holds only the ones set to 0xFFFFFFFF."""
    pos = 0
    while pos + 4 <= len(extra):
        tag, length = struct.unpack_from("<HH", extra, pos)
        body = extra[pos + 4: pos + 4 + length]
        if tag == _ZIP64_EXTRA:
            values = [struct.unpack_from("<Q", body, offset)[0] for offset in range(0, len(body) - 7, 8)]
            if usize == 0xFFFFFFFF and values:
                usize = values.pop(0)
            if csize == 0xFFFFFFFF and values:
                csize = values.pop(0)
            return csize, usize, True
        pos += 4 + length
    return csize, usize, False


def _salvage_entry_data(handle, target: Path, method: int, csize: int, sized: bool) -> tuple[int, int, int]:
    """Copy one entry's data from ``handle`` (at its first data byte) into ``target``.

    Returns (crc32, uncompressed size, compressed size); raises _EntryCut when the file ends first.
    Deflate streams mark their own end, so entries whose sizes only come after the data (a data
    descriptor, as streaming writers such as Velociraptor's emit) are still delimited."""
    crc = 0
    written = 0
    consumed = 0
    with target.open("wb") as out:
        if method == zipfile.ZIP_STORED:
            if not sized:
                raise _EntryCut("stored entry without its size")
            remaining = csize
            while remaining:
                chunk = handle.read(min(_SALVAGE_CHUNK, remaining))
                if not chunk:
                    raise _EntryCut("data ends early")
                out.write(chunk)
                crc = zlib.crc32(chunk, crc)
                remaining -= len(chunk)
            return crc, csize, csize
        decompressor = zlib.decompressobj(-15)
        while not decompressor.eof:
            chunk = handle.read(_SALVAGE_CHUNK)
            if not chunk:
                raise _EntryCut("data ends early")
            try:
                data = decompressor.decompress(chunk)
            except zlib.error as exc:
                raise _EntryCut(f"deflate stream broken: {exc}") from exc
            out.write(data)
            crc = zlib.crc32(data, crc)
            written += len(data)
            consumed += len(chunk) - len(decompressor.unused_data)
        handle.seek(-len(decompressor.unused_data), os.SEEK_CUR)
    return crc, written, consumed


def _salvage_truncated_zip(source: Path, dest_dir: Path, progress_cb: Callable[[dict], None] | None) -> list[dict]:
    """Extract the complete entries of a ZIP whose end (the central directory) is missing.

    A ZIP is read from its central directory, written last; an archive cut short -- an interrupted
    copy or download, a collector stopped before it finished -- has none, and zipfile refuses it.
    Every entry also starts with a local header, so the entries are walked from the start, as
    ``zip -FF`` and 7-Zip do: each one is kept only when its data is complete and its CRC matches;
    the walk stops at the first entry that is cut off or unreadable. The manifest ends with an entry
    of status ``truncated`` saying where."""
    manifest_entries: list[dict] = []
    archive_size = source.stat().st_size
    processed_files = 0
    cut: dict | None = None
    with source.open("rb") as handle:
        while True:
            offset = handle.tell()
            header = handle.read(30)
            if len(header) < 30 or header[:4] != _LOCAL_HEADER:
                if header:
                    cut = {"path": None, "offset": offset, "reason": "no further entry header"}
                break
            flags, method, mod_time, mod_date, header_crc, csize, usize, name_len, extra_len = struct.unpack_from("<HHHHIIIHH", header, 6)
            raw_name = handle.read(name_len)
            extra = handle.read(extra_len)
            if len(raw_name) < name_len or len(extra) < extra_len:
                cut = {"path": None, "offset": offset, "reason": "entry header cut off"}
                break
            name = raw_name.decode("utf-8" if flags & 0x800 else "cp437", errors="replace")
            csize, usize, zip64 = _zip64_sizes(extra, csize, usize)
            described_later = bool(flags & 0x08)
            if flags & 0x01 or method not in (zipfile.ZIP_STORED, zipfile.ZIP_DEFLATED):
                cut = {"path": name, "offset": offset, "reason": "encrypted entry or unsupported compression"}
                break
            info = zipfile.ZipInfo(name, date_time=((mod_date >> 9) + 1980, (mod_date >> 5) & 0xF or 1, mod_date & 0x1F or 1, mod_time >> 11, (mod_time >> 5) & 0x3F, (mod_time & 0x1F) * 2))
            is_dir = name.endswith("/")
            target = None if is_dir else _validate_path(dest_dir, name)
            ignored, reason = (True, "directory") if is_dir else should_ignore_path(Path(name), size=usize if not described_later else None, is_dir=False)
            partial = (target.with_name(target.name + ".kairon-partial") if target is not None else dest_dir / ".kairon-salvage-skip")
            partial.parent.mkdir(parents=True, exist_ok=True)
            try:
                crc, written, consumed = _salvage_entry_data(handle, partial, method, csize, not described_later or method == zipfile.ZIP_STORED and csize > 0)
                if described_later:
                    signature = handle.read(4)
                    if signature != _DATA_DESCRIPTOR:
                        handle.seek(-len(signature), os.SEEK_CUR)
                    wide = zip64 or written >= 0xFFFFFFFF or consumed >= 0xFFFFFFFF
                    descriptor = handle.read(20 if wide else 12)
                    if len(descriptor) < (20 if wide else 12):
                        raise _EntryCut("data descriptor cut off")
                    header_crc = struct.unpack_from("<I", descriptor, 0)[0]
                if crc != header_crc:
                    raise _EntryCut("CRC mismatch")
            except _EntryCut as exc:
                partial.unlink(missing_ok=True)
                cut = {"path": name, "offset": offset, "reason": str(exc)}
                break
            processed_files += 1
            if is_dir:
                partial.unlink(missing_ok=True)
                continue
            if ignored:
                partial.unlink(missing_ok=True)
                manifest_entries.append({"path": name, "ignored": True, "reason": reason, "size": written, "status": "ignored", "local_path": None})
            else:
                os.replace(partial, target)
                restore_mtime(target, zip_member_mtime(info))
                manifest_entries.append({"path": name, "ignored": False, "reason": None, "size": written, "status": "extracted", "local_path": str(target)})
            if progress_cb:
                progress_cb({"processed_files": processed_files, "total_files": processed_files, "processed_bytes": handle.tell(), "total_bytes": archive_size, "current_path": name})
    (dest_dir / ".kairon-salvage-skip").unlink(missing_ok=True)
    if cut is None:
        cut = {"path": None, "offset": archive_size, "reason": "archive ends without its central directory"}
    recovered = sum(1 for entry in manifest_entries if entry["status"] == "extracted")
    manifest_entries.append({
        "path": cut["path"] or "(end of archive)",
        "ignored": True,
        "reason": "archive_truncated",
        "size": 0,
        "status": TRUNCATED_STATUS,
        "local_path": None,
        "truncation": {"offset": cut["offset"], "archive_size": archive_size, "recovered_files": recovered, "detail": cut["reason"]},
    })
    _enforce_limits(manifest_entries)
    return manifest_entries


def archive_truncation(manifest_entries: list[dict]) -> dict | None:
    """What a salvaged (truncated) archive lost, from its manifest; None for a complete archive."""
    for entry in manifest_entries:
        if entry.get("status") == TRUNCATED_STATUS:
            path = entry.get("path")
            return {"first_missing_path": None if path in (None, "", "(end of archive)") else path, **(entry.get("truncation") or {})}
    return None


def _extract_zip(source: Path, dest_dir: Path, progress_cb: Callable[[dict], None] | None) -> tuple[list[str], list[dict]]:
    try:
        archive_handle = zipfile.ZipFile(source)
    except zipfile.BadZipFile as exc:
        if not _starts_with_local_header(source):
            _raise_classified(_classify_zip_failure(exc, source), source, exc)
        logger.warning("ZIP without central directory, recovering complete entries source=%s detail=%s", source.name, exc)
        try:
            manifest_entries = _salvage_truncated_zip(source, dest_dir, progress_cb)
        except ValueError as salvage_exc:
            classified = _classify_limit_exceeded(salvage_exc, source) or _classify_zip_failure(salvage_exc, source)
            _raise_classified(classified, source, salvage_exc)
        except OSError as salvage_exc:
            _raise_classified(_classify_zip_failure(salvage_exc, source), source, salvage_exc)
        if not any(entry["status"] == "extracted" for entry in manifest_entries):
            _raise_classified(
                ArchiveExtractionError(
                    "archive_truncated",
                    f"{source.name} is incomplete: the file was cut off before its first file could be read. Upload a complete copy.",
                    detail=str(exc),
                ),
                source,
                exc,
            )
        extracted = [entry["path"] for entry in manifest_entries if entry["status"] == "extracted"]
        return extracted, manifest_entries
    except Exception as exc:  # noqa: BLE001
        _raise_classified(_classify_zip_failure(exc, source), source, exc)
    try:
        with archive_handle as archive:
            manifest_entries = _safe_members_zip(archive, dest_dir, progress_cb=progress_cb)
            extracted = [entry["path"] for entry in manifest_entries if not entry["ignored"]]
            return extracted, manifest_entries
    except ArchiveExtractionError:
        raise
    except ValueError as exc:
        classified = _classify_limit_exceeded(exc, source) or _classify_zip_failure(exc, source)
        _raise_classified(classified, source, exc)
    except Exception as exc:  # noqa: BLE001
        _raise_classified(_classify_zip_failure(exc, source), source, exc)


def _extract_seven_zip(source: Path, dest_dir: Path, progress_cb: Callable[[dict], None] | None) -> tuple[list[str], list[dict]]:
    manifest_entries: list[dict] = []
    try:
        with tempfile.TemporaryDirectory(dir=settings.backend_temp_dir) as tmp_dir:
            temp_extract_dir = Path(tmp_dir)
            subprocess.run(
                ["7z", "x", str(source), f"-o{temp_extract_dir}", "-y"],
                check=True,
                capture_output=True,
                timeout=settings.archive_extraction_timeout_seconds,
            )
            paths = [path for path in temp_extract_dir.rglob("*") if path.is_file()]
            total_files = len(paths)
            total_bytes = sum(path.stat().st_size for path in paths)
            processed_files = 0
            processed_bytes = 0
            for path in paths:
                ensure_within_directory(temp_extract_dir, path)
                relative = path.relative_to(temp_extract_dir)
                size = path.stat().st_size
                ignored, reason = should_ignore_path(relative, size=size, is_dir=False)
                manifest_entries.append(
                    {
                        "path": str(relative),
                        "ignored": ignored,
                        "reason": reason,
                        "size": size,
                        "status": "ignored" if ignored else "extracted",
                        "local_path": None if ignored else str(dest_dir / relative),
                    }
                )
                processed_files += 1
                processed_bytes += size
                if ignored:
                    if progress_cb:
                        progress_cb({"processed_files": processed_files, "total_files": total_files, "processed_bytes": processed_bytes, "total_bytes": total_bytes, "current_path": str(relative)})
                    continue
                target = _validate_path(dest_dir, str(relative))
                target.parent.mkdir(parents=True, exist_ok=True)
                # Moved, not copied: the temporary tree is discarded anyway, and a copy would write
                # every byte twice (tens of gigabytes for a memory capture) and need twice the space.
                shutil.move(path, target)
                if progress_cb:
                    progress_cb({"processed_files": processed_files, "total_files": total_files, "processed_bytes": processed_bytes, "total_bytes": total_bytes, "current_path": str(relative)})
            _enforce_limits(manifest_entries)
            extracted = [entry["path"] for entry in manifest_entries if not entry["ignored"]]
            return extracted, manifest_entries
    except ArchiveExtractionError:
        raise
    except ValueError as exc:
        classified = _classify_limit_exceeded(exc, source) or _classify_seven_zip_failure(exc, source)
        _raise_classified(classified, source, exc)
    except Exception as exc:  # noqa: BLE001
        _raise_classified(_classify_seven_zip_failure(exc, source), source, exc)


def _zip_needs_seven_zip(source: Path) -> bool:
    """Whether this .zip uses a compression method Python cannot read.

    Python's zipfile supports stored/deflate/bzip2/lzma and nothing else, so a
    Deflate64 member -- what Windows and several collection tools emit once the
    content gets large -- makes it raise NotImplementedError halfway through.
    7-Zip reads those, and is already a dependency for the other archive
    formats, so the entry is worth checking before committing to zipfile.
    """
    try:
        with zipfile.ZipFile(source) as archive:
            return any(entry.compress_type not in _ZIPFILE_SUPPORTED_COMPRESSION for entry in archive.infolist())
    except Exception:  # noqa: BLE001
        # Unreadable central directory is a different failure; let the normal
        # zip path classify and report it rather than silently rerouting.
        return False


def _extract_ad1(source: Path, dest_dir: Path, progress_cb: Callable[[dict], None] | None) -> tuple[list[str], list[dict]]:
    """An AD1 logical image nested in a collection (e.g. a ZIP holding one
    .ad1): its live files are written out like an archive's members."""
    from app.ingest.ad1_image import AD1ImageError, entry_mtime, iter_ad1_files, open_ad1

    def _ad1_mtime(entry) -> float | None:
        value = entry_mtime(entry)
        return value.timestamp() if value else None

    try:
        files = list(iter_ad1_files(open_ad1(source)))
    except AD1ImageError as exc:
        _raise_classified(ArchiveExtractionError(exc.code, exc.message), source, exc)
    total_files = len(files)
    total_bytes = sum(int(entry.size or 0) for _path, entry in files)
    manifest_entries: list[dict] = []
    processed_bytes = 0
    for index, (relative, entry) in enumerate(files, start=1):
        size = int(entry.size or 0)
        processed_bytes += size
        ignored, reason = should_ignore_path(Path(relative), size=size, is_dir=False)
        record = {"path": relative, "ignored": ignored, "reason": reason, "size": size, "status": "ignored" if ignored else "extracted", "local_path": None}
        if not ignored:
            target = _validate_path(dest_dir, relative)
            target.parent.mkdir(parents=True, exist_ok=True)
            try:
                with entry.open() as src, target.open("wb") as dst:
                    shutil.copyfileobj(src, dst, 1024 * 1024)
                restore_mtime(target, _ad1_mtime(entry))
                record["local_path"] = str(target)
            except OSError as exc:
                if _is_disk_space_error(exc):
                    _raise_classified(_classify_zip_failure(exc, source), source, exc)
                target.unlink(missing_ok=True)
                record.update({"status": "failed", "reason": f"{type(exc).__name__}: {exc}"[:300]})
            except Exception as exc:  # noqa: BLE001
                target.unlink(missing_ok=True)
                record.update({"status": "failed", "reason": f"{type(exc).__name__}: {exc}"[:300]})
        manifest_entries.append(record)
        if progress_cb:
            progress_cb({"processed_files": index, "total_files": total_files, "processed_bytes": processed_bytes, "total_bytes": total_bytes, "current_path": relative})
    try:
        _enforce_limits(manifest_entries)
    except ValueError as exc:
        _raise_classified(_classify_limit_exceeded(exc, source), source, exc)
    extracted = [entry["path"] for entry in manifest_entries if entry["status"] == "extracted"]
    return extracted, manifest_entries


def extract_archive(source: Path, dest_dir: Path, progress_cb: Callable[[dict], None] | None = None) -> tuple[list[str], list[dict]]:
    dest_dir.mkdir(parents=True, exist_ok=True)
    suffix = source.suffix.lower()
    if suffix == ".ad1":
        extracted, manifest_entries = _extract_ad1(source, dest_dir, progress_cb)
    elif suffix == ".zip" and _zip_needs_seven_zip(source):
        extracted, manifest_entries = _extract_seven_zip(source, dest_dir, progress_cb)
    elif suffix == ".zip":
        extracted, manifest_entries = _extract_zip(source, dest_dir, progress_cb)
    elif _is_seven_zip_supported_archive(source):
        extracted, manifest_entries = _extract_seven_zip(source, dest_dir, progress_cb)
    else:
        raise ArchiveExtractionError(
            "archive_unsupported_format",
            f"{source.name}'s file type is not a supported archive format.",
            detail=f"suffix={''.join(source.suffixes) or source.suffix!r}",
        )
    return extracted, manifest_entries


def copy_folder(source: Path, dest_dir: Path, progress_cb: Callable[[dict], None] | None = None) -> tuple[list[str], list[dict]]:
    if dest_dir.exists():
        shutil.rmtree(dest_dir)
    dest_dir.mkdir(parents=True, exist_ok=True)
    entries = []
    extracted = []
    files = [path for path in source.rglob("*") if path.is_file()]
    total_files = len(files)
    total_bytes = sum(path.stat().st_size for path in files)
    processed_files = 0
    processed_bytes = 0
    for path in files:
        relative = path.relative_to(source)
        size = path.stat().st_size
        ignored, reason = should_ignore_path(relative, size=size, is_dir=False)
        entries.append({"path": str(relative), "ignored": ignored, "reason": reason, "size": size})
        processed_files += 1
        processed_bytes += size
        if ignored:
            if progress_cb:
                progress_cb({"processed_files": processed_files, "total_files": total_files, "processed_bytes": processed_bytes, "total_bytes": total_bytes, "current_path": str(relative)})
            continue
        target = dest_dir / relative
        ensure_within_directory(dest_dir, target)
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(path, target)
        extracted.append(str(relative))
        if progress_cb:
            progress_cb({"processed_files": processed_files, "total_files": total_files, "processed_bytes": processed_bytes, "total_bytes": total_bytes, "current_path": str(relative)})
    _enforce_limits(entries)
    return extracted, entries


def inventory_folder(source: Path, progress_cb: Callable[[dict], None] | None = None) -> tuple[list[str], list[dict]]:
    entries = []
    extracted = []
    files = [path for path in source.rglob("*") if path.is_file()]
    total_files = len(files)
    total_bytes = sum(path.stat().st_size for path in files)
    processed_files = 0
    processed_bytes = 0
    for path in files:
        relative = path.relative_to(source)
        size = path.stat().st_size
        ignored, reason = should_ignore_path(relative, size=size, is_dir=False)
        entries.append({"path": str(relative), "ignored": ignored, "reason": reason, "size": size, "status": "extracted" if not ignored else "ignored", "local_path": str(path)})
        processed_files += 1
        processed_bytes += size
        if not ignored:
            extracted.append(str(relative))
        if progress_cb:
            progress_cb({"processed_files": processed_files, "total_files": total_files, "processed_bytes": processed_bytes, "total_bytes": total_bytes, "current_path": str(relative)})
    _enforce_limits(entries)
    return extracted, entries


def write_tree_metadata(dest_path: Path, files: list[str]) -> None:
    dest_path.write_text(json.dumps({"files": sorted(files)}, indent=2), encoding="utf-8")
