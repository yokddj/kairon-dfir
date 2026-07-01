from __future__ import annotations

import asyncio
import os
from pathlib import Path
from types import SimpleNamespace

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from app.core.database import Base
from app.models.case import Case
from app.services.memory import upload_sessions


CASE_ID = "aaaaaaaa-1111-4111-8111-111111111111"


@pytest.fixture()
def db_session():
    engine = create_engine("sqlite:///:memory:", future=True)
    Base.metadata.create_all(bind=engine)
    Session = sessionmaker(bind=engine, autoflush=False, autocommit=False, future=True)
    db = Session()
    db.add(Case(id=CASE_ID, name="Upload hardening"))
    db.commit()
    try:
        yield db
    finally:
        db.close()
        engine.dispose()


def _settings(tmp_path: Path, **overrides):
    data = tmp_path / "data"
    values = {
        "backend_data_dir": data,
        "backend_temp_dir": data / "tmp",
        "memory_upload_enabled": True,
        "memory_upload_max_bytes": 32 * 1024 * 1024 * 1024,
        "memory_max_upload_size": 32 * 1024 * 1024 * 1024,
        "memory_upload_chunk_size_bytes": 64 * 1024 * 1024,
        "memory_upload_chunk_size_min_bytes": 1024 * 1024,
        "memory_upload_chunk_size_max_bytes": 256 * 1024 * 1024,
        "memory_upload_extensions": {".dmp", ".mem"},
        "memory_upload_staging_path": data / "tmp" / "memory-uploads",
        "memory_upload_session_ttl_seconds": 3600,
        "memory_upload_session_ttl_hours": 24,
        "memory_upload_min_free_space_bytes": 0,
        "memory_upload_case_quota_bytes": 128 * 1024 * 1024 * 1024,
        "memory_upload_direct_threshold_bytes": 1024,
        "memory_upload_default_concurrency": 2,
        "memory_upload_max_concurrency": 4,
        "memory_upload_max_parallel_chunks": 2,
        "memory_plugin_output_max_bytes": 1024,
        "memory_output_root": data / "memory-output",
        "redis_url": "redis://127.0.0.1:1/0",
        "memory_evidence_shared_gid": os.getgid(),
    }
    values.update(overrides)
    return SimpleNamespace(**values)


def _capacity(_db, expected_bytes, exclude_upload_id=None):
    return {
        "staging_available_bytes": 10**12,
        "canonical_storage_available_bytes": 10**12,
        "memory_output_available_bytes": 10**12,
        "required_capacity_bytes": expected_bytes,
        "finalization_strategy": "atomic_move",
        "can_accept_selected_size": True,
    }


async def _chunks(data: bytes):
    yield data[: max(1, len(data) // 2)]
    yield data[max(1, len(data) // 2) :]


def _create(db, **kwargs):
    return upload_sessions.create_memory_upload_session(
        db,
        case_id=CASE_ID,
        filename=kwargs.pop("filename", "memory.dmp"),
        expected_size_bytes=kwargs.pop("expected_size_bytes", 16),
        provided_host="WS01",
        authorization_acknowledged=True,
        **kwargs,
    )


def test_direct_mode_requested_under_threshold(db_session, tmp_path, monkeypatch):
    monkeypatch.setattr(upload_sessions, "get_settings", lambda: _settings(tmp_path))
    monkeypatch.setattr(upload_sessions, "_capacity_snapshot", _capacity)
    item = _create(db_session, expected_size_bytes=512, upload_mode="direct")
    status = upload_sessions.upload_status_with_chunks(item, db=db_session)
    assert status["upload_mode"] == "direct"
    assert status["chunk_size_bytes"] == 512
    assert status["total_chunks"] == 1


def test_direct_mode_over_threshold_rejected(db_session, tmp_path, monkeypatch):
    monkeypatch.setattr(upload_sessions, "get_settings", lambda: _settings(tmp_path, memory_upload_direct_threshold_bytes=128))
    monkeypatch.setattr(upload_sessions, "_capacity_snapshot", _capacity)
    with pytest.raises(upload_sessions.MemoryUploadSessionError) as exc:
        _create(db_session, expected_size_bytes=129, upload_mode="direct")
    assert exc.value.code == "MEMORY_UPLOAD_DIRECT_TOO_LARGE"


def test_new_resumable_session_uses_64_mib_and_concurrency(db_session, tmp_path, monkeypatch):
    monkeypatch.setattr(upload_sessions, "get_settings", lambda: _settings(tmp_path))
    monkeypatch.setattr(upload_sessions, "_capacity_snapshot", _capacity)
    item = _create(db_session, expected_size_bytes=10 * 1024 * 1024 * 1024, upload_mode="resumable")
    status = upload_sessions.upload_status_with_chunks(item, db=db_session)
    assert status["chunk_size_bytes"] == 64 * 1024 * 1024
    assert status["total_chunks"] == 160
    assert status["default_concurrency"] == 2
    assert status["max_concurrency"] == 4


def test_existing_session_preserves_chunk_size(db_session, tmp_path, monkeypatch):
    monkeypatch.setattr(upload_sessions, "get_settings", lambda: _settings(tmp_path, memory_upload_chunk_size_bytes=8 * 1024 * 1024))
    monkeypatch.setattr(upload_sessions, "_capacity_snapshot", _capacity)
    item = _create(db_session, expected_size_bytes=24 * 1024 * 1024, upload_mode="resumable")
    monkeypatch.setattr(upload_sessions, "get_settings", lambda: _settings(tmp_path, memory_upload_chunk_size_bytes=64 * 1024 * 1024))
    db_session.refresh(item)
    assert upload_sessions.upload_status_with_chunks(item, db=db_session)["chunk_size_bytes"] == 8 * 1024 * 1024


def test_same_chunk_upload_is_idempotent(db_session, tmp_path, monkeypatch):
    monkeypatch.setattr(upload_sessions, "get_settings", lambda: _settings(tmp_path, memory_upload_chunk_size_bytes=8, memory_upload_chunk_size_min_bytes=8))
    monkeypatch.setattr(upload_sessions, "_capacity_snapshot", _capacity)
    item = _create(db_session, expected_size_bytes=8, upload_mode="resumable")
    headers = {"content-length": "8"}
    asyncio.run(upload_sessions.store_memory_upload_chunk_stream(db_session, case_id=CASE_ID, upload_id=item.id, chunk_index=0, chunks=_chunks(b"12345678"), headers=headers, content_length_is_payload=True))
    again = asyncio.run(upload_sessions.store_memory_upload_chunk_stream(db_session, case_id=CASE_ID, upload_id=item.id, chunk_index=0, chunks=_chunks(b"12345678"), headers=headers, content_length_is_payload=True))
    assert again.received_chunk_count == 1
    assert again.bytes_received == 8


def test_mode_mismatch_rejected(db_session, tmp_path, monkeypatch):
    monkeypatch.setattr(upload_sessions, "get_settings", lambda: _settings(tmp_path))
    monkeypatch.setattr(upload_sessions, "_capacity_snapshot", _capacity)
    item = _create(db_session, expected_size_bytes=8, upload_mode="direct")
    with pytest.raises(upload_sessions.MemoryUploadSessionError) as exc:
        asyncio.run(upload_sessions.store_memory_upload_chunk_stream(db_session, case_id=CASE_ID, upload_id=item.id, chunk_index=0, chunks=_chunks(b"12345678"), headers={}, content_length_is_payload=False, expected_mode="resumable"))
    assert exc.value.code == "MEMORY_UPLOAD_MODE_CONFLICT"


def test_finalize_rejects_active_chunk(db_session, tmp_path, monkeypatch):
    monkeypatch.setattr(upload_sessions, "get_settings", lambda: _settings(tmp_path))
    monkeypatch.setattr(upload_sessions, "_capacity_snapshot", _capacity)
    item = _create(db_session, expected_size_bytes=8, upload_mode="resumable")
    metadata = dict(item.metadata_json)
    metadata["active_chunks"] = [0]
    item.metadata_json = metadata
    db_session.commit()
    with pytest.raises(upload_sessions.MemoryUploadSessionError) as exc:
        upload_sessions.finalize_memory_upload_session(db_session, case_id=CASE_ID, upload_id=item.id)
    assert exc.value.code == "MEMORY_UPLOAD_CHUNKS_ACTIVE"


def test_cleanup_skips_active_session(db_session, tmp_path, monkeypatch):
    monkeypatch.setattr(upload_sessions, "get_settings", lambda: _settings(tmp_path))
    monkeypatch.setattr(upload_sessions, "_capacity_snapshot", _capacity)
    item = _create(db_session, expected_size_bytes=8, upload_mode="resumable")
    report = upload_sessions.cleanup_memory_upload_staging(db_session, dry_run=True)
    assert report["skipped_active_sessions"] == 1
    assert report["bytes_removed"] == 0


def test_reconciliation_detects_orphan_staging(db_session, tmp_path, monkeypatch):
    settings = _settings(tmp_path)
    monkeypatch.setattr(upload_sessions, "get_settings", lambda: settings)
    monkeypatch.setattr(upload_sessions, "_capacity_snapshot", _capacity)
    (settings.memory_upload_staging_path / "orphan").mkdir(parents=True)
    report = upload_sessions.reconcile_memory_upload_storage(db_session)
    assert any(item["classification"] == "staging_exists_db_session_missing" for item in report["findings"])


def test_fallback_state_is_reported(db_session, tmp_path, monkeypatch):
    monkeypatch.setattr(upload_sessions, "get_settings", lambda: _settings(tmp_path))
    monkeypatch.setattr(upload_sessions, "_capacity_snapshot", _capacity)
    item = _create(db_session, expected_size_bytes=8, upload_mode="resumable")
    metadata = dict(item.metadata_json)
    metadata["fallback_to_sequential"] = True
    item.metadata_json = metadata
    db_session.commit()
    assert upload_sessions.upload_status_with_chunks(item, db=db_session)["fallback_to_sequential"] is True


def test_orphaned_chunk_file_with_matching_content_reconciles_db(db_session, tmp_path, monkeypatch):
    settings = _settings(tmp_path, memory_upload_chunk_size_bytes=8, memory_upload_chunk_size_min_bytes=8)
    monkeypatch.setattr(upload_sessions, "get_settings", lambda: settings)
    monkeypatch.setattr(upload_sessions, "_capacity_snapshot", _capacity)
    item = _create(db_session, expected_size_bytes=8, upload_mode="resumable")
    chunk_data = b"\x01" * 8
    headers = {"content-length": "8"}

    async def _run_store():
        return await upload_sessions.store_memory_upload_chunk_stream(
            db_session,
            case_id=CASE_ID,
            upload_id=item.id,
            chunk_index=0,
            chunks=_chunks(chunk_data),
            headers=headers,
            content_length_is_payload=True,
            expected_mode="resumable",
        )

    result = asyncio.run(_run_store())
    assert result.received_chunk_count == 1
    assert result.bytes_received == 8

    received_before = upload_sessions._received_chunks(result)
    upload_sessions._set_received_chunks(result, {})
    result.received_chunk_count = 0
    result.bytes_received = 0
    db_session.commit()

    chunk_path = upload_sessions._chunk_path(item, 0)
    assert chunk_path.exists()

    result2 = asyncio.run(_run_store())
    assert result2.received_chunk_count == 1
    assert result2.bytes_received == 8
    received_after = upload_sessions._received_chunks(result2)
    assert "0" in received_after, "orphaned chunk file should be reconciled into DB"


def test_orphaned_chunk_file_with_mismatched_content_raises_409(db_session, tmp_path, monkeypatch):
    settings = _settings(tmp_path, memory_upload_chunk_size_bytes=8, memory_upload_chunk_size_min_bytes=8)
    monkeypatch.setattr(upload_sessions, "get_settings", lambda: settings)
    monkeypatch.setattr(upload_sessions, "_capacity_snapshot", _capacity)
    item = _create(db_session, expected_size_bytes=8, upload_mode="resumable")
    headers = {"content-length": "8"}

    async def _run_store(data: bytes):
        return await upload_sessions.store_memory_upload_chunk_stream(
            db_session,
            case_id=CASE_ID,
            upload_id=item.id,
            chunk_index=0,
            chunks=_chunks(data),
            headers=headers,
            content_length_is_payload=True,
            expected_mode="resumable",
        )

    result = asyncio.run(_run_store(b"\x01" * 8))
    received_before = upload_sessions._received_chunks(result)
    upload_sessions._set_received_chunks(result, {})
    result.received_chunk_count = 0
    result.bytes_received = 0
    db_session.commit()

    with pytest.raises(upload_sessions.MemoryUploadSessionError) as exc:
        asyncio.run(_run_store(b"\x02" * 8))
    assert exc.value.code == "MEMORY_UPLOAD_CHUNK_CONTENT_MISMATCH"
    detail = exc.value.detail or {}
    assert detail.get("chunk_index") == 0
    assert detail.get("expected_size") == 8


def test_completed_upload_with_removed_staging_is_healthy(db_session, tmp_path, monkeypatch):
    settings = _settings(tmp_path)
    monkeypatch.setattr(upload_sessions, "get_settings", lambda: settings)
    monkeypatch.setattr(upload_sessions, "_capacity_snapshot", _capacity)
    item = _create(db_session, expected_size_bytes=8, upload_mode="resumable")
    item.status = "completed"
    item.evidence_id = "evidence-abc-123"
    db_session.commit()
    import shutil
    session_root = upload_sessions._session_root(item)
    if session_root.exists():
        shutil.rmtree(session_root)
    payload = upload_sessions.upload_status_with_chunks(item, db=db_session)
    assert payload.get("failure_code") is None
    assert payload.get("failure_message") is None
    assert payload.get("integrity_status") is None


def test_file_fingerprint_stored_in_status_response(db_session, tmp_path, monkeypatch):
    monkeypatch.setattr(upload_sessions, "get_settings", lambda: _settings(tmp_path))
    monkeypatch.setattr(upload_sessions, "_capacity_snapshot", _capacity)
    fp = "a" * 64
    item = _create(
        db_session,
        expected_size_bytes=8,
        upload_mode="resumable",
        file_fingerprint=fp,
    )
    payload = upload_sessions.upload_status_with_chunks(item, db=db_session)
    assert payload.get("file_fingerprint") == fp


def test_conflicting_session_includes_fingerprint(db_session, tmp_path, monkeypatch):
    monkeypatch.setattr(upload_sessions, "get_settings", lambda: _settings(tmp_path))
    monkeypatch.setattr(upload_sessions, "_capacity_snapshot", _capacity)
    existing_fp = "b" * 64
    item = _create(
        db_session,
        expected_size_bytes=8,
        upload_mode="resumable",
        file_fingerprint=existing_fp,
    )
    with pytest.raises(upload_sessions.MemoryUploadSessionError) as exc:
        upload_sessions.create_memory_upload_session(
            db_session,
            case_id=CASE_ID,
            filename=item.display_name,
            expected_size_bytes=int(item.expected_bytes),
            provided_host="other-host",
            authorization_acknowledged=True,
            upload_mode="resumable",
            file_fingerprint="c" * 64,
        )
    assert exc.value.code == "MEMORY_UPLOAD_ACTIVE_SESSION_EXISTS"
    detail = exc.value.detail or {}
    assert detail.get("file_fingerprint") == existing_fp
