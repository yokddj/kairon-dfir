from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path

from sqlalchemy.orm import Session

from app.core.config import get_settings
from app.models.evidence import Evidence, EvidenceStorageMode, EvidenceType


class MemoryExecutionValidationError(RuntimeError):
    def __init__(self, code: str, message: str):
        super().__init__(message)
        self.code = code
        self.message = message


@dataclass(frozen=True)
class ValidatedMemoryEvidence:
    evidence: Evidence
    path: Path
    size_bytes: int


def _is_within(base: Path, candidate: Path) -> bool:
    try:
        return os.path.commonpath([str(base.resolve()), str(candidate.resolve())]) == str(base.resolve())
    except OSError:
        return False


def _approved_roots_for(evidence: Evidence) -> list[Path]:
    settings = get_settings()
    roots = [settings.backend_data_dir / "evidence"]
    if evidence.storage_mode in {EvidenceStorageMode.mounted_path, EvidenceStorageMode.shared_path}:
        roots.extend(settings.allowed_evidence_roots)
    return roots


def validate_memory_execution_request(db: Session, evidence_id: str) -> ValidatedMemoryEvidence:
    settings = get_settings()
    evidence = db.get(Evidence, evidence_id)
    if evidence is None:
        raise MemoryExecutionValidationError("EVIDENCE_NOT_FOUND", "Evidence not found.")
    if evidence.evidence_type != EvidenceType.memory_dump:
        raise MemoryExecutionValidationError("INVALID_EVIDENCE_TYPE", "Metadata analysis is only supported for memory_dump evidence.")

    raw_path = str(evidence.stored_path or "").strip()
    if not raw_path:
        raise MemoryExecutionValidationError("EVIDENCE_PATH_MISSING", "Evidence storage path is missing.")
    candidate = Path(raw_path)
    if not candidate.is_absolute():
        candidate = settings.backend_data_dir / candidate

    try:
        resolved = candidate.resolve(strict=True)
    except OSError:
        raise MemoryExecutionValidationError("EVIDENCE_FILE_NOT_FOUND", "Memory evidence file was not found.") from None

    if candidate.is_symlink() or resolved.is_symlink():
        raise MemoryExecutionValidationError("UNSAFE_EVIDENCE_FILE", "Memory evidence file must not be a symlink.")
    if not resolved.is_file():
        raise MemoryExecutionValidationError("UNSAFE_EVIDENCE_FILE", "Memory evidence path must be a regular file.")
    if not any(_is_within(root, resolved) for root in _approved_roots_for(evidence)):
        raise MemoryExecutionValidationError("UNSAFE_EVIDENCE_PATH", "Memory evidence path is outside approved evidence storage roots.")

    stat_result = resolved.stat()
    if stat_result.st_size <= 0:
        raise MemoryExecutionValidationError("EMPTY_EVIDENCE_FILE", "Memory evidence file is empty.")
    max_size = int(getattr(settings, "memory_upload_max_bytes", None) or settings.memory_max_upload_size)
    if stat_result.st_size > max_size:
        raise MemoryExecutionValidationError("EVIDENCE_TOO_LARGE", "Memory evidence exceeds the configured memory evidence size limit.")
    return ValidatedMemoryEvidence(evidence=evidence, path=resolved, size_bytes=stat_result.st_size)
