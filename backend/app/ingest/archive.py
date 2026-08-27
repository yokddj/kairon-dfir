import errno
import json
import logging
import shutil
import subprocess
import tempfile
import zipfile
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


def _extract_zip(source: Path, dest_dir: Path, progress_cb: Callable[[dict], None] | None) -> tuple[list[str], list[dict]]:
    try:
        with zipfile.ZipFile(source) as archive:
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
                shutil.copy2(path, target)
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


def extract_archive(source: Path, dest_dir: Path, progress_cb: Callable[[dict], None] | None = None) -> tuple[list[str], list[dict]]:
    dest_dir.mkdir(parents=True, exist_ok=True)
    suffix = source.suffix.lower()
    if suffix == ".zip" and _zip_needs_seven_zip(source):
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
