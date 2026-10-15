from __future__ import annotations

import json
import os
import stat
from pathlib import Path
from types import SimpleNamespace

import pytest

from app.models.evidence import EvidenceStorageMode
from app.services.memory import evidence_access, worker_access_probe


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
        id="ev-1",
        stored_path=str(path),
        ingest_source={"canonical_relative_path": "evidence/case/evidence/original/memory.dmp"},
        storage_mode=EvidenceStorageMode.uploaded,
        size_bytes=len(b"synthetic"),
    ), path


class _FakeRedis:
    """Just the commands the access probe uses."""

    def __init__(self) -> None:
        self.values: dict[str, str] = {}
        self.lists: dict[str, list[str]] = {}

    def get(self, key):
        return self.values.get(key)

    def set(self, key, value, nx=False, ex=None):
        if nx and key in self.values:
            return False
        self.values[key] = value
        return True

    def setex(self, key, _ttl, value):
        self.values[key] = value

    def delete(self, key):
        self.values.pop(key, None)

    def rpush(self, key, value):
        self.lists.setdefault(key, []).append(value)


@pytest.fixture(autouse=True)
def _no_probe_wait(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(worker_access_probe, "DEFAULT_WAIT_SECONDS", 0.0)


def _store_verdict(redis: _FakeRedis, evidence_id: str, **verdict) -> None:
    redis.setex(f"{worker_access_probe.RESULT_PREFIX}{evidence_id}", 60, json.dumps(verdict))


def test_owner_and_mode_bits_alone_never_block_analysis(tmp_path: Path) -> None:
    # Some storages report owner/mode bits they do not enforce (a bind mount
    # showing root:root 0600 that the worker reads fine). Without the worker's
    # own answer, access is unverified -- not denied.
    settings = _settings(tmp_path)
    evidence, _path = _evidence(settings, mode=0o600)

    result = evidence_access.evidence_readiness(evidence, settings=settings, redis_conn=_FakeRedis())

    assert result["access_verified"] is False
    assert result["readable_by_memory_worker"] is None
    assert result["can_analyze"] is True
    assert result["error_code"] is None


def test_unverified_access_asks_the_worker_once(tmp_path: Path) -> None:
    settings = _settings(tmp_path)
    evidence, _path = _evidence(settings)
    redis = _FakeRedis()

    evidence_access.evidence_readiness(evidence, settings=settings, redis_conn=redis)
    evidence_access.evidence_readiness(evidence, settings=settings, redis_conn=redis)

    assert redis.lists[worker_access_probe.REQUEST_LIST] == ["ev-1"]


def test_worker_denial_blocks_with_the_workers_reason(tmp_path: Path) -> None:
    settings = _settings(tmp_path)
    evidence, path = _evidence(settings)
    redis = _FakeRedis()
    _store_verdict(
        redis, "ev-1", readable=False, output_writable=False, identity=None,
        error_code="MEMORY_EVIDENCE_PERMISSION_DENIED", message=evidence_access.PERMISSION_MESSAGE,
    )

    result = evidence_access.evidence_readiness(evidence, settings=settings, redis_conn=redis)

    assert result["access_verified"] is True
    assert result["can_analyze"] is False
    assert result["error_code"] == "MEMORY_EVIDENCE_PERMISSION_DENIED"
    assert "path" not in result["sanitized_message"].lower()


def test_worker_confirmation_is_reported(tmp_path: Path) -> None:
    settings = _settings(tmp_path)
    evidence, path = _evidence(settings)
    redis = _FakeRedis()
    identity = worker_access_probe.file_identity(path.lstat())
    _store_verdict(redis, "ev-1", readable=True, output_writable=True, identity=identity, error_code=None, message=None)

    result = evidence_access.evidence_readiness(evidence, settings=settings, redis_conn=redis)

    assert result["readable_by_memory_worker"] is True
    assert result["output_writable_by_memory_worker"] is True
    assert result["can_analyze"] is True


def test_verdict_for_an_older_version_of_the_file_is_not_trusted(tmp_path: Path) -> None:
    settings = _settings(tmp_path)
    evidence, path = _evidence(settings)
    redis = _FakeRedis()
    _store_verdict(redis, "ev-1", readable=True, output_writable=False, identity="1:2:3", error_code="MEMORY_OUTPUT_PERMISSION_DENIED", message="x")

    result = evidence_access.evidence_readiness(evidence, settings=settings, redis_conn=redis)

    assert result["access_verified"] is False
    assert result["can_analyze"] is True
    assert redis.lists[worker_access_probe.REQUEST_LIST] == ["ev-1"]


def test_size_mismatch_is_reported_without_asking_the_worker(tmp_path: Path) -> None:
    settings = _settings(tmp_path)
    evidence, _path = _evidence(settings)
    evidence.size_bytes += 1
    redis = _FakeRedis()

    result = evidence_access.evidence_readiness(evidence, settings=settings, redis_conn=redis)

    assert result["error_code"] == "EVIDENCE_SIZE_MISMATCH"
    assert result["can_analyze"] is False
    assert worker_access_probe.REQUEST_LIST not in redis.lists


def test_probe_reads_the_file_like_an_analysis_does(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    settings = _settings(tmp_path)
    evidence, path = _evidence(settings)
    monkeypatch.setattr(evidence_access, "validate_current_process_output_access", lambda: tmp_path)

    result = worker_access_probe.probe_evidence_access(evidence, settings=settings)

    assert result["readable"] is True
    assert result["output_writable"] is True
    assert result["identity"] == worker_access_probe.file_identity(path.lstat())


@pytest.mark.skipif(hasattr(os, "geteuid") and os.geteuid() == 0, reason="root reads any file")
def test_probe_reports_a_file_the_process_really_cannot_read(tmp_path: Path) -> None:
    settings = _settings(tmp_path)
    evidence, path = _evidence(settings, mode=0o000)
    try:
        result = worker_access_probe.probe_evidence_access(evidence, settings=settings)
    finally:
        path.chmod(0o640)

    assert result["readable"] is False
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


def test_canonical_relative_path_wins_over_stale_stored_path(tmp_path: Path) -> None:
    settings = _settings(tmp_path)
    settings.memory_output_root.mkdir(mode=0o770)
    evidence, canonical_path = _evidence(settings)
    evidence.stored_path = "/app/data/tmp/stale-upload-session/memory.dmp"

    access = evidence_access.validate_current_process_evidence_access(evidence, settings=settings)

    assert access.path == canonical_path.resolve()
    assert access.readable is True


def test_missing_canonical_storage_reports_storage_failure_without_path(tmp_path: Path) -> None:
    settings = _settings(tmp_path)
    evidence, canonical_path = _evidence(settings)
    canonical_path.unlink()

    with pytest.raises(evidence_access.MemoryStorageAccessError) as exc_info:
        evidence_access.validate_current_process_evidence_access(evidence, settings=settings)

    assert exc_info.value.code == "EVIDENCE_FILE_NOT_FOUND"
    assert str(canonical_path) not in exc_info.value.message
