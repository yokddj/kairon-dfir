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


def test_concurrent_chunk_writes_across_independent_sessions_do_not_clobber_each_other(tmp_path, monkeypatch):
    """Regression for the extra_chunks_on_disk lost-update race.

    Each HTTP request gets its own SQLAlchemy Session (Depends(get_db)), so
    two chunk-index uploads in flight at once -- exactly what
    default_concurrency/max_concurrency exist to allow -- are handled by two
    independent Session objects against the same MemoryUpload row. Before
    the fix, the received_chunks merge read state once per request and
    committed a stale in-memory copy at the end; whichever request's slow
    disk write finished last would silently overwrite the other's already-
    committed chunk record even though both chunks were correctly on disk.
    _record_chunk_received now refreshes from the DB immediately before
    merging, inside a lock scoped to the whole upload (not one chunk index),
    so this can no longer happen regardless of which Session issues the
    write or how the two requests interleave.
    """
    from sqlalchemy.pool import StaticPool

    engine = create_engine(
        "sqlite://",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
        future=True,
    )
    Base.metadata.create_all(bind=engine)
    Session = sessionmaker(bind=engine, autoflush=False, autocommit=False, future=True)
    db_a = Session()
    db_b = Session()
    db_a.add(Case(id=CASE_ID, name="Concurrent chunk case"))
    db_a.commit()

    settings = _settings(tmp_path, memory_upload_chunk_size_bytes=8, memory_upload_chunk_size_min_bytes=8)
    monkeypatch.setattr(upload_sessions, "get_settings", lambda: settings)
    monkeypatch.setattr(upload_sessions, "_capacity_snapshot", _capacity)

    item = _create(db_a, expected_size_bytes=24, upload_mode="resumable")
    upload_id = item.id

    # Two independent sessions, each fetching their own copy of the row --
    # this is the realistic shape of two concurrent requests, not two
    # in-process references to the same Python object.
    item_a = db_a.get(upload_sessions.MemoryUpload, upload_id)
    item_b = db_b.get(upload_sessions.MemoryUpload, upload_id)

    item_a = upload_sessions._record_chunk_received(
        db_a, item_a, upload_id=upload_id, chunk_index=0, size=8, sha256="a" * 64,
    )
    # item_b's session never saw chunk 0 land -- exactly the stale-snapshot
    # shape that used to cause the clobber -- but _record_chunk_received
    # refreshes from the DB itself before merging, so chunk 0 survives.
    item_b = upload_sessions._record_chunk_received(
        db_b, item_b, upload_id=upload_id, chunk_index=2, size=8, sha256="c" * 64,
    )

    db_a.refresh(item_a)
    final_chunks = upload_sessions._received_chunks(item_a)
    assert set(final_chunks.keys()) == {"0", "2"}, "chunk 0 must not be lost when chunk 2 commits from a different session"
    assert item_a.received_chunk_count == 2
    assert item_a.bytes_received == 16

    db_a.close()
    db_b.close()
    engine.dispose()


def test_chunk_write_racing_a_concurrent_cancel_raises_clean_terminal_error_not_500(db_session, tmp_path, monkeypatch):
    """Regression: cancel deletes the whole staging directory as soon as it
    commits status=cancelled, with no lock against chunk uploads that already
    passed the terminal-status check earlier in this same request. Before the
    fix, a chunk mid-write whose staging directory disappeared underneath it
    hit an unhandled FileNotFoundError from os.replace() -- a raw 500 instead
    of the same clean, structured "session is terminal" error the top-of-
    function check produces when the timing goes the other way. Reproduced
    live against production: 4 concurrent chunk uploads all 500'd when a
    cancel landed mid-transfer.
    """
    settings = _settings(tmp_path, memory_upload_chunk_size_bytes=8, memory_upload_chunk_size_min_bytes=8)
    monkeypatch.setattr(upload_sessions, "get_settings", lambda: settings)
    monkeypatch.setattr(upload_sessions, "_capacity_snapshot", _capacity)
    item = _create(db_session, expected_size_bytes=8, upload_mode="resumable")
    headers = {"content-length": "8"}

    real_replace = os.replace

    def _replace_racing_a_cancel(src, dst):
        # Simulate a cancel landing on a different session concurrently,
        # between this chunk's terminal-status check and its os.replace:
        # it commits status=cancelled and deletes the whole staging dir.
        item.status = "cancelled"
        db_session.add(item)
        db_session.commit()
        import shutil
        shutil.rmtree(upload_sessions._chunk_dir(item), ignore_errors=True)
        return real_replace(src, dst)

    monkeypatch.setattr(os, "replace", _replace_racing_a_cancel)

    async def _run_store():
        return await upload_sessions.store_memory_upload_chunk_stream(
            db_session,
            case_id=CASE_ID,
            upload_id=item.id,
            chunk_index=0,
            chunks=_chunks(b"\x01" * 8),
            headers=headers,
            content_length_is_payload=True,
            expected_mode="resumable",
        )

    with pytest.raises(upload_sessions.MemoryUploadSessionError) as exc:
        asyncio.run(_run_store())
    assert exc.value.code == "MEMORY_UPLOAD_TERMINAL"
