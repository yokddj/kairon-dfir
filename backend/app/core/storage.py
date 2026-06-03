import hashlib
import os
import shutil
from pathlib import Path
from uuid import uuid4

from fastapi import UploadFile

from app.core.config import get_settings


settings = get_settings()


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
