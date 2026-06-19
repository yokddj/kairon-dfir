from __future__ import annotations

import os
import stat
from pathlib import Path
from types import SimpleNamespace

import pytest

from app.models.evidence import EvidenceStorageMode
from app.services.memory import evidence_access


def _settings(tmp_path: Path) -> SimpleNamespace:
    return SimpleNamespace(
        backend_data_dir=tmp_path / "data",
        memory_output_root=tmp_path / "memory-output",
        memory_worker_uid=10001,
        memory_worker_gid=os.getgid(),
        memory_evidence_shared_gid=os.getgid(),
        allowed_evidence_roots=[],
    )


def _evidence(settings: SimpleNamespace, *, mode: int = 0o640):
    settings.backend_data_dir.parent.chmod(0o755)
    path = settings.backend_data_dir / "evidence" / "case" / "evidence" / "original" / "memory.dmp"
    path.parent.mkdir(parents=True)
    for directory in (settings.backend_data_dir, settings.backend_data_dir / "evidence", path.parents[2], path.parents[1], path.parent):
        directory.chmod(0o750)
    path.write_bytes(b"synthetic")
    path.chmod(mode)
    return SimpleNamespace(
        stored_path=str(path),
        ingest_source={"canonical_relative_path": "evidence/case/evidence/original/memory.dmp"},
        storage_mode=EvidenceStorageMode.uploaded,
        size_bytes=len(b"synthetic"),
    ), path


def test_mode_0600_rejects_different_worker_uid(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    settings = _settings(tmp_path)
    settings.memory_output_root.mkdir(mode=0o770)
    settings.memory_output_root.chmod(0o770)
    evidence, _path = _evidence(settings, mode=0o600)
    monkeypatch.setattr(evidence_access, "_worker_can_traverse", lambda *_args: True)

    result = evidence_access.evidence_readiness(evidence, settings=settings)

    assert result["can_analyze"] is False
    assert result["error_code"] == "MEMORY_EVIDENCE_PERMISSION_DENIED"
    assert "path" not in result["sanitized_message"].lower()


def test_mode_0640_with_shared_group_is_readable(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    settings = _settings(tmp_path)
    settings.memory_output_root.mkdir(mode=0o770)
    settings.memory_output_root.chmod(0o770)
    evidence, _path = _evidence(settings, mode=0o640)
    monkeypatch.setattr(evidence_access, "_worker_can_traverse", lambda *_args: True)

    result = evidence_access.evidence_readiness(evidence, settings=settings)

    assert result["readable_by_memory_worker"] is True
    assert result["can_analyze"] is True


def test_parent_without_group_execute_is_rejected(tmp_path: Path) -> None:
    settings = _settings(tmp_path)
    settings.memory_output_root.mkdir(mode=0o770)
    settings.memory_output_root.chmod(0o770)
    evidence, path = _evidence(settings, mode=0o640)
    path.parents[1].chmod(0o700)

    result = evidence_access.evidence_readiness(evidence, settings=settings)

    assert result["error_code"] == "MEMORY_EVIDENCE_PERMISSION_DENIED"


def test_secure_permissions_are_group_readable_not_world_readable(tmp_path: Path) -> None:
    settings = _settings(tmp_path)
    _evidence_item, path = _evidence(settings, mode=0o666)

    evidence_access.secure_uploaded_memory_permissions(path, settings=settings)

    assert stat.S_IMODE(path.stat().st_mode) == 0o640
    assert stat.S_IMODE(path.parent.stat().st_mode) == 0o2750
    assert path.stat().st_size == len(b"synthetic")


def test_sanitizer_placeholder_is_never_used_as_real_path(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    settings = _settings(tmp_path)
    evidence, path = _evidence(settings)
    opened: list[Path] = []

    def denied(candidate, _flags):
        opened.append(Path(candidate))
        raise PermissionError

    monkeypatch.setattr(evidence_access.os, "open", denied)
    with pytest.raises(evidence_access.MemoryStorageAccessError) as exc_info:
        evidence_access.validate_current_process_evidence_access(evidence, settings=settings)

    assert opened == [path.resolve()]
    assert opened[0].name != "[path]"
    assert exc_info.value.code == "MEMORY_EVIDENCE_PERMISSION_DENIED"
    assert str(path) not in exc_info.value.message
