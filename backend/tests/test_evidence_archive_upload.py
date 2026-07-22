"""Coverage for the unified chunk-index Evidence Wizard single-file archive
path (UNIFIED_UPLOAD_EVIDENCE_ARCHIVE) -- the third category migrated onto
the shared backend proven by memory_dump/disk_image (see
test_evidence_unified_upload.py, test_evidence_disk_image_upload.py). These
tests focus on what is genuinely archive-specific (supported-extension
validation, evidence_id re-pointing since upload_evidence() mints its own,
reuse of the real upload_evidence() classification/registration path); the
transport/discovery/reconciliation/cancel machinery is exercised generically
in test_evidence_unified_upload.py and is not re-tested here.
"""
from __future__ import annotations

import asyncio
import hashlib
import io
import zipfile

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from app.core.config import get_settings
from app.core.database import Base
from app.models.case import Case
from app.models.case_host import CaseHost
from app.models.evidence_upload_session import EvidenceUploadSession
from app.models.memory import MemoryUpload
from app.services.evidence_archive_workflow import register_archive_evidence
from app.services.evidence_unified_upload import (
    UNIFIED_UPLOAD_KINDS,
    create_unified_upload_session,
    is_unified_session,
    sync_unified_session,
    unified_upload_info,
)
from app.services.evidence_upload_session import UploadSessionError, append_resumable_upload_chunk_stream, finalize_resumable_upload_session, get_upload_session
from app.services.memory.upload_sessions import MemoryUploadSessionError, finalize_memory_upload_session, store_memory_upload_chunk_stream
from app.services.upload_shared.workflow import get_workflow_handler, registered_workflows

settings = get_settings()
CASE_ID = "eeeeeeee-2222-4222-8222-eeeeeeeeeeee"


def _db():
    engine = create_engine("sqlite:///:memory:", connect_args={"check_same_thread": False}, poolclass=StaticPool, future=True)
    Base.metadata.create_all(engine)
    return sessionmaker(bind=engine, future=True)()


def _case(db, *, case_id=CASE_ID):
    item = Case(id=case_id, name="Archive Upload Case", description="", status="active", priority="medium", management_tags=[])
    db.add(item)
    db.commit()
    return item


def _configure(monkeypatch, tmp_path):
    monkeypatch.setattr(settings, "backend_temp_dir", tmp_path / "tmp")
    monkeypatch.setattr(settings, "backend_data_dir", tmp_path / "data")
    monkeypatch.setattr(settings, "backend_max_upload_size", 64 * 1024 * 1024)
    monkeypatch.setattr(settings, "memory_upload_chunk_size_bytes", 16)
    monkeypatch.setattr(settings, "memory_upload_chunk_size_min_bytes", 16)
    monkeypatch.setattr(settings, "unified_upload_evidence_archive", True)
    monkeypatch.setattr("app.services.memory.upload_sessions._capacity_snapshot", lambda *args, **kwargs: {"can_accept_selected_size": True})
    # register_archive_evidence calls upload_evidence(), which -- unlike
    # the disk_image workflow's own deferred `from app.workers.tasks import
    # enqueue_ingest` -- resolves against routes_evidence.py's own
    # MODULE-LEVEL `from app.workers.tasks import enqueue_ingest` (routes_evidence.py:132).
    # That binds its own reference the first time routes_evidence gets
    # imported by anything in the whole test session (not necessarily this
    # test), so patching app.workers.tasks.enqueue_ingest is unreliable
    # across full-suite runs; patch the actual call site directly instead,
    # same as the legacy upload_evidence tests already do.
    from app.api import routes_evidence
    monkeypatch.setattr(routes_evidence, "enqueue_ingest", lambda evidence_id: None)


def _real_zip_bytes() -> bytes:
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w") as archive:
        archive.writestr("readme.txt", "kairon test archive")
        archive.writestr("logs/sample.log", "2026-01-01 example log line")
    return buffer.getvalue()


async def _bytes_stream(payload: bytes):
    yield payload


def _create_archive_session(db, *, filename="evidence.zip", expected_size_bytes, host_id=None, provided_host="WIN-ARCHIVE01"):
    kind_config = UNIFIED_UPLOAD_KINDS["archive"]
    return create_unified_upload_session(
        db,
        CASE_ID,
        kind="archive",
        workflow=kind_config.workflow,
        evidence_type=kind_config.evidence_type,
        filename=filename,
        expected_size_bytes=expected_size_bytes,
        declared_platform=None,
        client_sha256=None,
        host_id=host_id,
        provided_host=provided_host,
        authorization_acknowledged=False,  # archive has no such concept -- must not be required
        notes=None,
        current_user=None,
    )


def _upload_all_chunks(db, memory_upload_id: str, payload: bytes, chunk_size: int) -> None:
    total_chunks = max(1, -(-len(payload) // chunk_size))
    for index in range(total_chunks):
        start = index * chunk_size
        chunk = payload[start:start + chunk_size]
        asyncio.run(
            store_memory_upload_chunk_stream(
                db, case_id=CASE_ID, upload_id=memory_upload_id, chunk_index=index,
                chunks=_bytes_stream(chunk), headers={"content-length": str(len(chunk))},
                content_length_is_payload=True, expected_mode="resumable",
            )
        )


def test_registered_workflows_include_archive():
    assert "archive" in registered_workflows()
    assert get_workflow_handler("archive") is register_archive_evidence


def test_archive_session_does_not_require_authorization_acknowledgement(tmp_path, monkeypatch):
    _configure(monkeypatch, tmp_path)
    db = _db()
    _case(db)
    session, info = _create_archive_session(db, expected_size_bytes=64)
    assert is_unified_session(session, kind="archive")
    memory_upload = db.get(MemoryUpload, info.memory_upload_id)
    assert memory_upload.metadata_json["workflow"] == "archive"


def test_archive_upload_rejects_the_legacy_byte_offset_endpoints(tmp_path, monkeypatch):
    """Part of the single-file unified-upload invariant: an archive session
    created under the unified backend must never be advanceable through the
    legacy PUT .../bytes?offset= / finalize endpoints, only through the
    memory-upload chunk-index endpoints."""
    _configure(monkeypatch, tmp_path)
    db = _db()
    _case(db)
    session, _info = _create_archive_session(db, expected_size_bytes=16)
    fresh = get_upload_session(db, CASE_ID, session.id)

    with pytest.raises(UploadSessionError) as exc_info:
        asyncio.run(append_resumable_upload_chunk_stream(db, fresh, offset=0, chunks=_bytes_stream(b"x" * 16)))
    assert exc_info.value.code == "unified_session_wrong_endpoint"

    with pytest.raises(UploadSessionError) as exc_info:
        finalize_resumable_upload_session(db, fresh)
    assert exc_info.value.code == "unified_session_wrong_endpoint"


def test_archive_session_uses_original_filename_as_canonical_name(tmp_path, monkeypatch):
    _configure(monkeypatch, tmp_path)
    db = _db()
    _case(db)
    session, info = _create_archive_session(db, filename="Case-Collection.tar.gz", expected_size_bytes=64)
    memory_upload = db.get(MemoryUpload, info.memory_upload_id)
    assert memory_upload.canonical_relative_path.endswith("/original/Case-Collection.tar.gz")


@pytest.mark.parametrize("filename", ["evidence.zip", "evidence.7z", "evidence.tar", "evidence.tar.gz", "evidence.gz", "evidence.xz"])
def test_archive_session_accepts_every_supported_extension(tmp_path, monkeypatch, filename):
    _configure(monkeypatch, tmp_path)
    db = _db()
    _case(db)
    session, info = _create_archive_session(db, filename=filename, expected_size_bytes=64)
    assert is_unified_session(session, kind="archive")


def test_archive_session_rejects_unsupported_extension(tmp_path, monkeypatch):
    _configure(monkeypatch, tmp_path)
    db = _db()
    _case(db)
    with pytest.raises(MemoryUploadSessionError) as exc_info:
        _create_archive_session(db, filename="evidence.rar", expected_size_bytes=64)
    assert exc_info.value.code == "MEMORY_UPLOAD_INVALID_EXTENSION"


def test_archive_upload_registers_evidence_via_upload_evidence_and_repoints_evidence_id(tmp_path, monkeypatch):
    _configure(monkeypatch, tmp_path)
    db = _db()
    _case(db)
    host = CaseHost(id="ffffffff-1111-4111-8111-ffffffffffff", case_id=CASE_ID, canonical_name="WIN-ARCHIVE02", display_name="WIN-ARCHIVE02", confidence="manual", source="manual")
    db.add(host)
    db.commit()

    payload = _real_zip_bytes()
    known_hash = hashlib.sha256(payload).hexdigest()
    session, info = _create_archive_session(db, filename="collection.zip", expected_size_bytes=len(payload), host_id=host.id, provided_host=None)
    reserved_evidence_id = db.get(MemoryUpload, info.memory_upload_id).evidence_id

    _upload_all_chunks(db, info.memory_upload_id, payload, info.chunk_size_bytes)
    finalized_upload, evidence = finalize_memory_upload_session(db, case_id=CASE_ID, upload_id=info.memory_upload_id, expected_sha256=known_hash)

    assert finalized_upload.status == "completed"
    assert evidence is not None
    assert evidence.sha256 == known_hash
    assert evidence.size_bytes == len(payload)
    assert evidence.host_id == host.id
    assert evidence.original_filename == "collection.zip"
    assert evidence.ingest_status.value == "pending"
    # upload_evidence()'s own save_upload() mints a fresh evidence_id distinct
    # from the one the unified session pre-reserved -- the handler must have
    # re-pointed MemoryUpload.evidence_id at the real one for reconciliation
    # and idempotency to keep working.
    assert evidence.id != reserved_evidence_id
    assert finalized_upload.evidence_id == evidence.id

    synced = sync_unified_session(db, db.get(EvidenceUploadSession, session.id))
    assert synced.status == "promoted"
    assert synced.promoted_evidence_id == evidence.id


def test_archive_upload_is_idempotent_on_repeated_handler_invocation(tmp_path, monkeypatch):
    _configure(monkeypatch, tmp_path)
    db = _db()
    _case(db)
    payload = _real_zip_bytes()
    known_hash = hashlib.sha256(payload).hexdigest()
    session, info = _create_archive_session(db, filename="repeat.zip", expected_size_bytes=len(payload))
    _upload_all_chunks(db, info.memory_upload_id, payload, info.chunk_size_bytes)
    _finalized_upload, evidence = finalize_memory_upload_session(db, case_id=CASE_ID, upload_id=info.memory_upload_id, expected_sha256=known_hash)

    again = register_archive_evidence(info.memory_upload_id, db)
    assert again.id == evidence.id


def test_archive_and_disk_image_ownership_never_cross(tmp_path, monkeypatch):
    """Two sessions created under different kinds must resolve to their
    own workflow handler even when both flags are enabled simultaneously."""
    _configure(monkeypatch, tmp_path)
    monkeypatch.setattr(settings, "disk_image_ingest_enabled", True)
    monkeypatch.setattr(settings, "unified_upload_evidence_disk_image", True)
    db = _db()
    _case(db)

    archive_session, archive_info = _create_archive_session(db, filename="a.zip", expected_size_bytes=64)

    from app.services.evidence_unified_upload import UNIFIED_UPLOAD_KINDS as kinds
    disk_kind = kinds["disk_image"]
    disk_session, disk_info = create_unified_upload_session(
        db, CASE_ID, kind="disk_image", workflow=disk_kind.workflow, evidence_type=disk_kind.evidence_type,
        filename="b.raw", expected_size_bytes=64, declared_platform=None, client_sha256=None,
        host_id=None, provided_host="WIN-DISK", authorization_acknowledged=False, notes=None, current_user=None,
    )

    archive_upload = db.get(MemoryUpload, archive_info.memory_upload_id)
    disk_upload = db.get(MemoryUpload, disk_info.memory_upload_id)
    assert archive_upload.metadata_json["workflow"] == "archive"
    assert disk_upload.metadata_json["workflow"] == "disk_image"
    assert is_unified_session(archive_session, kind="archive")
    assert not is_unified_session(archive_session, kind="disk_image")
    assert is_unified_session(disk_session, kind="disk_image")
    assert not is_unified_session(disk_session, kind="archive")
