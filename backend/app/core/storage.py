import hashlib
import logging
import os
import re
import shutil
from pathlib import Path
from uuid import uuid4

from fastapi import UploadFile

from app.core.config import get_settings
from app.services.memory.upload_capacity import (
    MemoryCapacityError,
    MemoryUploadSlot,
    assert_memory_upload_capacity,
)


settings = get_settings()
logger = logging.getLogger(__name__)
_MEMORY_TEMP_NAME = re.compile(r"^[0-9a-f-]{36}-[0-9a-f-]{36}\.memory-upload\.part$")


class MemoryUploadError(ValueError):
    def __init__(self, code: str, message: str):
        super().__init__(message)
        self.code = code
        self.message = message


def case_storage_root(case_id: str) -> Path:
    return settings.backend_data_dir / "evidence" / case_id


def build_evidence_root(case_id: str, evidence_id: str) -> Path:
    root = case_storage_root(case_id) / evidence_id
    root.mkdir(parents=True, exist_ok=True)
    return root


def save_upload(case_id: str, upload: UploadFile) -> tuple[str, Path, int]:
    evidence_id = str(uuid4())
    root = build_evidence_root(case_id, evidence_id)
    original_dir = root / "original"
    original_dir.mkdir(parents=True, exist_ok=True)
    filename = Path(upload.filename or "upload.bin").name
    stored_path = original_dir / filename
    size = 0
    with stored_path.open("wb") as buffer:
        while chunk := upload.file.read(1024 * 1024):
            size += len(chunk)
            buffer.write(chunk)
    return evidence_id, stored_path, size


def safe_display_filename(filename: str | None) -> str:
    name = Path((filename or "memory-image").replace("\\", "/")).name.strip()
    name = "".join(ch if ch.isalnum() or ch in "._- " else "_" for ch in name).strip(" .")
    return name[:180] or "memory-image"


def is_memory_upload_filename(filename: str | None) -> bool:
    suffix = Path(filename or "").suffix.lower()
    return bool(suffix and suffix in settings.memory_upload_extensions)


def save_memory_upload(case_id: str, upload: UploadFile) -> tuple[str, Path, int, str, str]:
    suffix = Path(upload.filename or "").suffix.lower()
    if suffix not in settings.memory_upload_extensions:
        raise MemoryUploadError("rejected_type", "This memory image extension is not enabled for browser upload.")
    chunk_size = max(65536, int(settings.memory_upload_chunk_size_bytes or 4194304))
    max_bytes = max(1, int(settings.memory_upload_max_bytes or settings.memory_max_upload_size or 1))
    evidence_id = str(uuid4())
    root = build_evidence_root(case_id, evidence_id)
    original_dir = root / "original"
    staging_root = settings.memory_upload_staging_path
    staging_root.mkdir(parents=True, exist_ok=True)
    original_dir.mkdir(parents=True, exist_ok=True)
    temp_path = staging_root / f"{case_id}-{evidence_id}.memory-upload.part"
    final_path = original_dir / f"memory-image{suffix}"
    digest = hashlib.sha256()
    size = 0
    safe_name = safe_display_filename(upload.filename)
    request_id = str(uuid4())
    strategy = "unknown"
    try:
        hinted_size = getattr(upload, "size", None)
        expected_size = int(hinted_size) if isinstance(hinted_size, int) and hinted_size > 0 else max_bytes
        if expected_size > max_bytes:
            raise MemoryUploadError("rejected_size", f"Memory image exceeds configured upload limit of {max_bytes} bytes.")
        try:
            with MemoryUploadSlot(request_id=request_id) as slot:
                decision = assert_memory_upload_capacity(expected_size, phase="pre_upload")
                strategy = decision.finalization_strategy
                logger.info(
                    "memory upload capacity decision request_id=%s case_id=%s selected_size_bytes=%s phase=pre_upload accepted=true strategy=%s same_filesystem=%s bytes_written=0",
                    request_id,
                    case_id,
                    expected_size,
                    strategy,
                    decision.staging_and_final_same_filesystem,
                )
                with temp_path.open("xb") as buffer:
                    while True:
                        chunk = upload.file.read(chunk_size)
                        if not chunk:
                            break
                        next_size = size + len(chunk)
                        if next_size > max_bytes or (isinstance(hinted_size, int) and hinted_size > 0 and next_size > hinted_size):
                            raise MemoryUploadError("rejected_size", f"Memory image exceeds configured upload limit of {max_bytes} bytes.")
                        assert_memory_upload_capacity(expected_size, phase="streaming", bytes_already_staged=size)
                        digest.update(chunk)
                        buffer.write(chunk)
                        size = next_size
                        slot.refresh()
                    buffer.flush()
                    os.fsync(buffer.fileno())
                if size <= 0:
                    raise MemoryUploadError("rejected_empty", "Empty memory image uploads are not accepted.")
                if isinstance(hinted_size, int) and hinted_size > 0 and size != hinted_size:
                    raise MemoryUploadError("size_mismatch", "Transferred memory image size did not match the declared size.")
                decision = assert_memory_upload_capacity(size, phase="finalization", bytes_already_staged=size)
                strategy = decision.finalization_strategy
                if strategy == "atomic_rename":
                    os.replace(temp_path, final_path)
                else:
                    _copy_memory_upload_to_final(temp_path, final_path, expected_size=size, expected_sha256=digest.hexdigest(), chunk_size=chunk_size)
                    _safe_unlink_memory_staging(temp_path, staging_root=staging_root, expected_name=temp_path.name)
                slot.refresh(force=True)
        except MemoryCapacityError as exc:
            public_message = (
                "Another memory image upload is currently in progress."
                if exc.category == "upload_in_progress"
                else "Server storage capacity is below the safe threshold for this memory image."
            )
            raise MemoryUploadError(exc.category, public_message) from exc
        dir_fd = os.open(str(final_path.parent), os.O_DIRECTORY)
        try:
            os.fsync(dir_fd)
        finally:
            os.close(dir_fd)
        return evidence_id, final_path, size, digest.hexdigest(), safe_name
    except Exception as exc:
        cleaned = _safe_unlink_memory_staging(temp_path, staging_root=staging_root, expected_name=temp_path.name)
        if final_path.exists() and not final_path.is_symlink():
            final_path.unlink()
        safe_remove(root)
        logger.warning(
            "memory upload failed request_id=%s case_id=%s selected_size_bytes=%s phase=upload_or_finalization strategy=%s bytes_written=%s failure_category=%s staging_cleaned=%s",
            request_id,
            case_id,
            getattr(upload, "size", None),
            strategy,
            size,
            getattr(exc, "code", getattr(exc, "category", type(exc).__name__)),
            cleaned,
        )
        raise


def _safe_unlink_memory_staging(path: Path, *, staging_root: Path, expected_name: str) -> bool:
    if path.name != expected_name or not _MEMORY_TEMP_NAME.fullmatch(path.name):
        return False
    try:
        root = staging_root.resolve(strict=True)
        candidate = path.resolve(strict=True)
        candidate.relative_to(root)
        stat = path.lstat()
    except (FileNotFoundError, OSError, ValueError):
        return False
    if path.is_symlink() or not path.is_file() or stat.st_nlink < 1:
        return False
    path.unlink()
    return True


def _copy_memory_upload_to_final(
    staging_path: Path,
    final_path: Path,
    *,
    expected_size: int,
    expected_sha256: str,
    chunk_size: int,
) -> None:
    destination_temp = final_path.with_name(f".{final_path.name}.{uuid4()}.part")
    copied_size = 0
    copied_digest = hashlib.sha256()
    try:
        with staging_path.open("rb") as source, destination_temp.open("xb") as target:
            while chunk := source.read(chunk_size):
                target.write(chunk)
                copied_digest.update(chunk)
                copied_size += len(chunk)
            target.flush()
            os.fsync(target.fileno())
        if copied_size != expected_size or copied_digest.hexdigest() != expected_sha256:
            raise MemoryUploadError("copy_integrity_failed", "Memory image integrity verification failed during finalization.")
        os.replace(destination_temp, final_path)
    finally:
        if destination_temp.exists() and not destination_temp.is_symlink():
            destination_temp.unlink()


def import_existing_path(case_id: str, source_path: Path) -> tuple[str, Path, int]:
    evidence_id = str(uuid4())
    root = build_evidence_root(case_id, evidence_id)
    if source_path.is_dir():
        target = root / "original_folder"
        shutil.copytree(source_path, target, dirs_exist_ok=True)
        size = sum(path.stat().st_size for path in target.rglob("*") if path.is_file())
    else:
        original_dir = root / "original"
        original_dir.mkdir(parents=True, exist_ok=True)
        target = original_dir / source_path.name
        shutil.copy2(source_path, target)
        size = target.stat().st_size
    return evidence_id, target, size


def sanitize_relative_path(raw_path: str) -> Path:
    normalized = raw_path.replace("\\", "/")
    path = Path(normalized)
    if path.is_absolute() or path.anchor:
        raise ValueError(f"Absolute path is not allowed: {raw_path}")
    if any(part == ".." for part in path.parts):
        raise ValueError(f"Parent path traversal is not allowed: {raw_path}")
    parts = [part for part in path.parts if part not in ("", ".")]
    sanitized = Path(*parts) if parts else Path("file.bin")
    if sanitized.is_absolute():
        raise ValueError(f"Absolute path is not allowed after sanitization: {raw_path}")
    return sanitized


def save_folder_uploads(case_id: str, uploads: list[UploadFile]) -> tuple[str, Path, int, str, list[dict], str]:
    evidence_id = str(uuid4())
    root = build_evidence_root(case_id, evidence_id)
    original_dir = root / "original_folder"
    original_dir.mkdir(parents=True, exist_ok=True)
    total_size = 0
    manifest_files: list[dict] = []
    folder_label = "uploaded-folder"
    for upload in uploads:
        filename = upload.filename or "upload.bin"
        try:
            sanitized = sanitize_relative_path(filename)
        except ValueError as exc:
            manifest_files.append({"path": filename, "ignored": True, "reason": str(exc)})
            continue
        if folder_label == "uploaded-folder" and len(sanitized.parts) > 1:
            folder_label = sanitized.parts[0]
        if any(part == "__MACOSX" for part in sanitized.parts) or sanitized.name in {".DS_Store"} or sanitized.name.startswith("._"):
            manifest_files.append({"path": str(sanitized), "ignored": True, "reason": "ignored_macos_artifact"})
            continue
        stored_path = original_dir / sanitized
        stored_path.parent.mkdir(parents=True, exist_ok=True)
        size = 0
        with stored_path.open("wb") as buffer:
            while chunk := upload.file.read(1024 * 1024):
                size += len(chunk)
                total_size += len(chunk)
                buffer.write(chunk)
        manifest_files.append({"path": str(sanitized), "ignored": False, "reason": None, "sha256": sha256_file(stored_path), "size": size})
    combined = hashlib.sha256()
    for entry in sorted(manifest_files, key=lambda item: item["path"]):
        combined.update(entry["path"].encode("utf-8"))
        combined.update(str(entry.get("sha256", "")).encode("utf-8"))
    return (
        evidence_id,
        original_dir,
        total_size,
        combined.hexdigest(),
        [{"path": item["path"], "ignored": item["ignored"], "reason": item["reason"]} for item in manifest_files],
        folder_label,
    )


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def evidence_extract_dir(case_id: str, evidence_id: str) -> Path:
    path = build_evidence_root(case_id, evidence_id) / "extracted"
    path.mkdir(parents=True, exist_ok=True)
    return path


def evidence_staging_dir(case_id: str, evidence_id: str) -> Path:
    path = build_evidence_root(case_id, evidence_id) / "staging"
    path.mkdir(parents=True, exist_ok=True)
    return path


def evidence_manifest_path(case_id: str, evidence_id: str) -> Path:
    return build_evidence_root(case_id, evidence_id) / "manifest.json"


def evidence_metadata_path(case_id: str, evidence_id: str) -> Path:
    return build_evidence_root(case_id, evidence_id) / "metadata.json"


def safe_remove(path: Path) -> None:
    if path.exists():
        if path.is_dir():
            shutil.rmtree(path)
        else:
            path.unlink()


def reset_extracted_dir(case_id: str, evidence_id: str) -> Path:
    path = build_evidence_root(case_id, evidence_id) / "extracted"
    safe_remove(path)
    path.mkdir(parents=True, exist_ok=True)
    return path


def reset_staging_dir(case_id: str, evidence_id: str) -> Path:
    path = build_evidence_root(case_id, evidence_id) / "staging"
    safe_remove(path)
    path.mkdir(parents=True, exist_ok=True)
    return path


def ensure_within_directory(base_dir: Path, candidate: Path) -> None:
    base = base_dir.resolve()
    target = candidate.resolve()
    if os.path.commonpath([str(base), str(target)]) != str(base):
        raise ValueError(f"Unsafe extraction path detected: {candidate}")
