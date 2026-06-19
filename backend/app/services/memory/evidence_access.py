from __future__ import annotations

import os
import stat
from dataclasses import dataclass
from pathlib import Path

from app.core.config import get_settings
from app.models.evidence import Evidence, EvidenceStorageMode


PERMISSION_MESSAGE = "The memory worker cannot read the uploaded evidence. An administrator must correct the evidence storage permissions."
OUTPUT_PERMISSION_MESSAGE = "The memory worker cannot write isolated analysis output. An administrator must correct the memory output storage permissions."


class MemoryStorageAccessError(RuntimeError):
    def __init__(self, code: str, message: str):
        super().__init__(message)
        self.code = code
        self.message = message


@dataclass(frozen=True)
class MemoryEvidenceAccess:
    path: Path
    exists: bool
    regular_file: bool
    readable: bool
    size_matches: bool


def _within(root: Path, candidate: Path) -> bool:
    try:
        candidate.relative_to(root)
        return True
    except ValueError:
        return False


def resolve_memory_evidence_path(evidence: Evidence, *, settings=None) -> Path:
    settings = settings or get_settings()
    managed_root = (settings.backend_data_dir / "evidence").resolve()
    metadata = evidence.ingest_source or {}
    relative_value = str(metadata.get("canonical_relative_path") or "").strip()
    if relative_value:
        relative = Path(relative_value)
        if relative.is_absolute() or ".." in relative.parts:
            raise MemoryStorageAccessError("UNSAFE_EVIDENCE_PATH", "Memory evidence path is outside approved evidence storage roots.")
        candidate = settings.backend_data_dir / relative
    else:
        raw = str(evidence.stored_path or "").strip()
        if not raw:
            raise MemoryStorageAccessError("EVIDENCE_PATH_MISSING", "Evidence storage path is missing.")
        candidate = Path(raw)
        if not candidate.is_absolute():
            candidate = settings.backend_data_dir / candidate

    try:
        resolved = candidate.resolve(strict=True)
    except (FileNotFoundError, PermissionError, OSError):
        raise MemoryStorageAccessError("EVIDENCE_FILE_NOT_FOUND", "Memory evidence file was not found.") from None
    approved_roots = [managed_root]
    if evidence.storage_mode in {EvidenceStorageMode.mounted_path, EvidenceStorageMode.shared_path}:
        approved_roots.extend(root.resolve() for root in settings.allowed_evidence_roots)
    if not any(_within(root, resolved) for root in approved_roots):
        raise MemoryStorageAccessError("UNSAFE_EVIDENCE_PATH", "Memory evidence path is outside approved evidence storage roots.")
    if candidate.is_symlink() or resolved.is_symlink():
        raise MemoryStorageAccessError("UNSAFE_EVIDENCE_FILE", "Memory evidence file must not be a symlink.")
    return resolved


def validate_current_process_evidence_access(evidence: Evidence, *, settings=None) -> MemoryEvidenceAccess:
    path = resolve_memory_evidence_path(evidence, settings=settings)
    try:
        metadata = path.lstat()
        regular = stat.S_ISREG(metadata.st_mode)
        if not regular:
            raise MemoryStorageAccessError("UNSAFE_EVIDENCE_FILE", "Memory evidence path must be a regular file.")
        flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
        descriptor = os.open(path, flags)
        try:
            opened_metadata = os.fstat(descriptor)
            if not stat.S_ISREG(opened_metadata.st_mode) or opened_metadata.st_size != metadata.st_size:
                raise MemoryStorageAccessError("UNSAFE_EVIDENCE_FILE", "Memory evidence path must be a stable regular file.")
        finally:
            os.close(descriptor)
    except PermissionError:
        raise MemoryStorageAccessError("MEMORY_EVIDENCE_PERMISSION_DENIED", PERMISSION_MESSAGE) from None
    expected = int(evidence.size_bytes or 0)
    size_matches = expected <= 0 or metadata.st_size == expected
    if not size_matches:
        raise MemoryStorageAccessError("EVIDENCE_SIZE_MISMATCH", "Memory evidence size does not match its registration metadata.")
    return MemoryEvidenceAccess(path=path, exists=True, regular_file=True, readable=True, size_matches=True)


def validate_current_process_output_access() -> Path:
    settings = get_settings()
    root = settings.memory_output_root
    if root is None:
        return settings.backend_data_dir / "evidence"
    try:
        resolved = root.resolve(strict=True)
        if not resolved.is_dir() or not os.access(resolved, os.W_OK | os.X_OK):
            raise PermissionError
    except (FileNotFoundError, PermissionError, OSError):
        raise MemoryStorageAccessError("MEMORY_OUTPUT_PERMISSION_DENIED", OUTPUT_PERMISSION_MESSAGE) from None
    return resolved


def _has_permission(metadata: os.stat_result, uid: int, gids: set[int], owner_bit: int, group_bit: int, other_bit: int) -> bool:
    mode = stat.S_IMODE(metadata.st_mode)
    if uid == metadata.st_uid:
        return bool(mode & owner_bit)
    if metadata.st_gid in gids:
        return bool(mode & group_bit)
    return bool(mode & other_bit)


def _worker_can_traverse(path: Path, uid: int, gids: set[int]) -> bool:
    for parent in [path.anchor and Path(path.anchor), *path.parents[::-1]]:
        if not parent:
            continue
        try:
            metadata = parent.stat()
        except OSError:
            return False
        if not _has_permission(metadata, uid, gids, stat.S_IXUSR, stat.S_IXGRP, stat.S_IXOTH):
            return False
    return True


def evidence_readiness(evidence: Evidence, *, settings=None) -> dict[str, object]:
    settings = settings or get_settings()
    uid = int(settings.memory_worker_uid)
    gids = {int(settings.memory_evidence_shared_gid), int(settings.memory_worker_gid)}
    exists = regular = readable = size_matches = False
    error_code: str | None = None
    message = "Memory evidence is available to the dedicated memory worker."
    try:
        path = resolve_memory_evidence_path(evidence, settings=settings)
        metadata = path.lstat()
        exists = True
        regular = stat.S_ISREG(metadata.st_mode) and not path.is_symlink()
        size_matches = regular and metadata.st_size == int(evidence.size_bytes or 0)
        readable = regular and _worker_can_traverse(path, uid, gids) and _has_permission(metadata, uid, gids, stat.S_IRUSR, stat.S_IRGRP, stat.S_IROTH)
        if not readable:
            error_code, message = "MEMORY_EVIDENCE_PERMISSION_DENIED", PERMISSION_MESSAGE
        elif not size_matches:
            error_code, message = "EVIDENCE_SIZE_MISMATCH", "Memory evidence size does not match its registration metadata."
    except MemoryStorageAccessError as exc:
        error_code, message = exc.code, exc.message

    output_writable = False
    output_root = settings.memory_output_root
    if output_root is not None:
        try:
            output_metadata = output_root.resolve(strict=True).stat()
            output_path = output_root.resolve(strict=True)
            output_writable = _worker_can_traverse(output_path, uid, gids) and _has_permission(output_metadata, uid, gids, stat.S_IWUSR, stat.S_IWGRP, stat.S_IWOTH) and _has_permission(output_metadata, uid, gids, stat.S_IXUSR, stat.S_IXGRP, stat.S_IXOTH)
        except OSError:
            output_writable = False
    else:
        output_writable = True
    if readable and size_matches and not output_writable:
        error_code, message = "MEMORY_OUTPUT_PERMISSION_DENIED", OUTPUT_PERMISSION_MESSAGE
    can_analyze = bool(exists and regular and readable and size_matches and output_writable)
    return {
        "exists": exists,
        "regular_file": regular,
        "readable_by_memory_worker": readable,
        "size_matches": size_matches,
        "output_writable_by_memory_worker": output_writable,
        "can_analyze": can_analyze,
        "error_code": error_code,
        "sanitized_message": message,
    }


def secure_uploaded_memory_permissions(path: Path, *, settings=None) -> None:
    settings = settings or get_settings()
    managed_root = (settings.backend_data_dir / "evidence").resolve()
    resolved = path.resolve(strict=True)
    if not _within(managed_root, resolved) or path.is_symlink() or not resolved.is_file():
        raise MemoryStorageAccessError("UNSAFE_EVIDENCE_FILE", "Canonical memory evidence validation failed.")
    gid = int(settings.memory_evidence_shared_gid)
    for directory in (managed_root, resolved.parents[2], resolved.parents[1], resolved.parent):
        os.chown(directory, -1, gid)
        os.chmod(directory, 0o2750)
    os.chown(resolved, -1, gid)
    os.chmod(resolved, 0o640)
