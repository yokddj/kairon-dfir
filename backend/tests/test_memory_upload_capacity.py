from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace

import pytest

from app.core import storage
from app.services.memory import upload_capacity


GIB = 1024 * 1024 * 1024


def _settings(tmp_path: Path) -> SimpleNamespace:
    return SimpleNamespace(
        backend_data_dir=tmp_path / "data",
        memory_upload_staging_path=tmp_path / "staging",
        memory_output_root=tmp_path / "output",
        memory_plugin_output_max_bytes=10 * 1024 * 1024,
        redis_url="redis://unused",
        memory_upload_request_timeout_seconds=0,
        memory_upload_cleanup_age_seconds=3600,
    )


def test_same_filesystem_preflight_and_finalization_do_not_double_count_staging(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    settings = _settings(tmp_path)
    monkeypatch.setattr(upload_capacity, "get_settings", lambda: settings)
    available = {"value": 8 * GIB}
    monkeypatch.setattr(upload_capacity, "_snapshot", lambda _path: upload_capacity.FilesystemSnapshot(device=7, available_bytes=available["value"]))

    preflight = upload_capacity.evaluate_memory_upload_capacity(4 * GIB, phase="pre_upload")
    available["value"] -= 4 * GIB
    finalization = upload_capacity.evaluate_memory_upload_capacity(4 * GIB, phase="finalization", bytes_already_staged=4 * GIB)

    assert preflight.accepted is True
    assert preflight.required_additional_bytes == 4 * GIB + upload_capacity.SAFETY_MARGIN_BYTES + upload_capacity.MIN_OUTPUT_ALLOWANCE_BYTES
    assert finalization.accepted is True
    assert finalization.finalization_strategy == "atomic_rename"
    assert finalization.required_additional_bytes == upload_capacity.SAFETY_MARGIN_BYTES + upload_capacity.MIN_OUTPUT_ALLOWANCE_BYTES


def test_cross_filesystem_checks_destination_independently(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    settings = _settings(tmp_path)
    monkeypatch.setattr(upload_capacity, "get_settings", lambda: settings)

    def snapshot(path: Path) -> upload_capacity.FilesystemSnapshot:
        if path == settings.memory_upload_staging_path:
            return upload_capacity.FilesystemSnapshot(device=1, available_bytes=8 * GIB)
        if path == settings.backend_data_dir / "evidence":
            return upload_capacity.FilesystemSnapshot(device=2, available_bytes=5 * GIB)
        return upload_capacity.FilesystemSnapshot(device=2, available_bytes=5 * GIB)

    monkeypatch.setattr(upload_capacity, "_snapshot", snapshot)
    decision = upload_capacity.evaluate_memory_upload_capacity(4 * GIB, phase="finalization", bytes_already_staged=4 * GIB)

    assert decision.finalization_strategy == "staged_copy"
    assert decision.accepted is False
    assert decision.shortfall_bytes == GIB + upload_capacity.MIN_OUTPUT_ALLOWANCE_BYTES


class _RedisStub:
    def __init__(self):
        self.value = None
        self.expired = False

    def set(self, _key, value, *, nx, ex):
        assert nx is True and ex >= 300
        if self.value is not None and not self.expired:
            return False
        self.value = value
        self.expired = False
        return True

    def eval(self, script, _keys, _key, token, *_args):
        if self.value != token or self.expired:
            return 0
        if "expire" in script:
            return 1
        self.value = None
        return 1


def test_distributed_upload_slot_blocks_concurrency_and_releases(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(upload_capacity, "get_settings", lambda: _settings(tmp_path))
    redis = _RedisStub()
    first = upload_capacity.MemoryUploadSlot(request_id="first", redis_conn=redis)
    second = upload_capacity.MemoryUploadSlot(request_id="second", redis_conn=redis)

    first.acquire()
    with pytest.raises(upload_capacity.MemoryCapacityError, match="currently in progress"):
        second.acquire()
    first.release()
    second.acquire()
    second.release()


def test_upload_slot_expiry_can_be_reacquired_and_lost_owner_cannot_release(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(upload_capacity, "get_settings", lambda: _settings(tmp_path))
    redis = _RedisStub()
    first = upload_capacity.MemoryUploadSlot(request_id="first", redis_conn=redis)
    first.acquire()
    redis.expired = True
    second = upload_capacity.MemoryUploadSlot(request_id="second", redis_conn=redis)
    second.acquire()
    first.release()
    assert redis.value == second._token
    second.release()


def test_controlled_staging_cleanup_rejects_symlink_and_unrelated_file(tmp_path: Path) -> None:
    root = tmp_path / "staging"
    root.mkdir()
    expected = root / "aaaaaaaa-1111-4111-8111-111111111111-bbbbbbbb-2222-4222-8222-222222222222.memory-upload.part"
    expected.write_bytes(b"partial")
    unrelated = root / "unrelated.part"
    unrelated.write_bytes(b"keep")

    assert storage._safe_unlink_memory_staging(expected, staging_root=root, expected_name=expected.name) is True
    assert unrelated.read_bytes() == b"keep"

    outside = tmp_path / "outside"
    outside.write_bytes(b"keep")
    symlink = root / "aaaaaaaa-1111-4111-8111-111111111111-cccccccc-3333-4333-8333-333333333333.memory-upload.part"
    symlink.symlink_to(outside)
    assert storage._safe_unlink_memory_staging(symlink, staging_root=root, expected_name=symlink.name) is False
    assert outside.read_bytes() == b"keep"
