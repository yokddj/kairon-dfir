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


def extract_archive(source: Path, dest_dir: Path, progress_cb: Callable[[dict], None] | None = None) -> tuple[list[str], list[dict]]:
    dest_dir.mkdir(parents=True, exist_ok=True)
    extracted: list[str] = []
    manifest_entries: list[dict] = []
    suffix = source.suffix.lower()
    if suffix == ".zip":
        with zipfile.ZipFile(source) as archive:
            manifest_entries = _safe_members_zip(archive, dest_dir, progress_cb=progress_cb)
            extracted = [entry["path"] for entry in manifest_entries if not entry["ignored"]]
    elif _is_seven_zip_supported_archive(source):
        with tempfile.TemporaryDirectory(dir=settings.backend_temp_dir) as tmp_dir:
            temp_extract_dir = Path(tmp_dir)
            subprocess.run(["7z", "x", str(source), f"-o{temp_extract_dir}", "-y"], check=True, capture_output=True)
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
    else:
        raise ValueError(f"Unsupported archive type: {''.join(source.suffixes) or source.suffix}")
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
