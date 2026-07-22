"""Coverage for the unified chunk-index Evidence Wizard disk_image path
(UNIFIED_UPLOAD_EVIDENCE_DISK_IMAGE) -- the second category migrated onto
the shared backend proven by memory_dump (see
test_evidence_unified_upload.py). These tests focus on what is genuinely
disk_image-specific (format detection/validation, canonical filename,
Evidence field shape, single-file-only scope); the transport/discovery/
reconciliation/cancel machinery is exercised generically there and is not
re-tested here since nothing about it is category-specific.
"""
from __future__ import annotations

import asyncio
import hashlib

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
from app.services.evidence_disk_image_workflow import register_disk_image_evidence
from app.services.evidence_unified_upload import (
    UNIFIED_UPLOAD_KINDS,
    create_unified_upload_session,
    is_unified_session,
    sync_unified_session,
    unified_upload_info,
)
from app.services.memory.upload_sessions import MemoryUploadSessionError, finalize_memory_upload_session, store_memory_upload_chunk_stream
from app.services.upload_shared.workflow import get_workflow_handler, registered_workflows

settings = get_settings()
CASE_ID = "dddddddd-1111-4111-8111-dddddddddddd"


def _db():
    engine = create_engine("sqlite:///:memory:", connect_args={"check_same_thread": False}, poolclass=StaticPool, future=True)
    Base.metadata.create_all(engine)
    return sessionmaker(bind=engine, future=True)()


def _case(db, *, case_id=CASE_ID):
    item = Case(id=case_id, name="Disk Image Upload Case", description="", status="active", priority="medium", management_tags=[])
    db.add(item)
    db.commit()
    return item


def _configure(monkeypatch, tmp_path):
    monkeypatch.setattr(settings, "backend_temp_dir", tmp_path / "tmp")
    monkeypatch.setattr(settings, "backend_data_dir", tmp_path / "data")
    monkeypatch.setattr(settings, "disk_image_ingest_enabled", True)
    monkeypatch.setattr(settings, "backend_max_upload_size", 64 * 1024 * 1024)
    monkeypatch.setattr(settings, "memory_upload_chunk_size_bytes", 16)
    monkeypatch.setattr(settings, "memory_upload_chunk_size_min_bytes", 16)
    monkeypatch.setattr(settings, "unified_upload_evidence_disk_image", True)
    monkeypatch.setattr("app.services.memory.upload_sessions._capacity_snapshot", lambda *args, **kwargs: {"can_accept_selected_size": True})


async def _bytes_stream(payload: bytes):
    yield payload


def _create_disk_image_session(db, *, filename="disk.raw", expected_size_bytes, host_id=None, provided_host="WIN-DISK01"):
    kind_config = UNIFIED_UPLOAD_KINDS["disk_image"]
    return create_unified_upload_session(
        db,
        CASE_ID,
        kind="disk_image",
        workflow=kind_config.workflow,
        evidence_type=kind_config.evidence_type,
        filename=filename,
        expected_size_bytes=expected_size_bytes,
        declared_platform=None,
        client_sha256=None,
        host_id=host_id,
        provided_host=provided_host,
        authorization_acknowledged=False,  # disk_image has no such concept -- must not be required
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


def test_registered_workflows_include_disk_image():
    assert "disk_image" in registered_workflows()
    assert get_workflow_handler("disk_image") is register_disk_image_evidence


def test_disk_image_session_does_not_require_authorization_acknowledgement(tmp_path, monkeypatch):
    """Unlike memory_dump, disk_image has no "I am authorized to handle
    this RAM evidence" concept -- the policy must not require it."""
    _configure(monkeypatch, tmp_path)
    db = _db()
    _case(db)
    session, info = _create_disk_image_session(db, expected_size_bytes=64)
    assert is_unified_session(session, kind="disk_image")
    memory_upload = db.get(MemoryUpload, info.memory_upload_id)
    assert memory_upload.metadata_json["workflow"] == "disk_image"


def test_disk_image_session_uses_original_filename_as_canonical_name(tmp_path, monkeypatch):
    """The one generalization create_memory_upload() needed: memory_dump
    always canonicalizes to "memory-image{ext}"; disk_image must preserve
    the real original filename in canonical storage."""
    _configure(monkeypatch, tmp_path)
    db = _db()
    _case(db)
    session, info = _create_disk_image_session(db, filename="DC02-forensic-image.raw", expected_size_bytes=64)
    memory_upload = db.get(MemoryUpload, info.memory_upload_id)
    assert memory_upload.canonical_relative_path.endswith("/original/DC02-forensic-image.raw")
    assert "memory-image" not in memory_upload.canonical_relative_path


def test_disk_image_upload_registers_evidence_with_format_and_host(tmp_path, monkeypatch):
    _configure(monkeypatch, tmp_path)
    # enqueue_ingest (real volume/OS discovery, run async by a worker in
    # production) opens its own SessionLocal() against the configured
    # database rather than this test's in-memory SQLite session -- stub it
    # out the same way the legacy upload_disk_image route's own tests do.
    enqueued: list[str] = []
    monkeypatch.setattr("app.workers.tasks.enqueue_ingest", lambda evidence_id: enqueued.append(evidence_id))
    db = _db()
    _case(db)
    host = CaseHost(id="eeeeeeee-1111-4111-8111-eeeeeeeeeeee", case_id=CASE_ID, canonical_name="WIN-DISK02", display_name="WIN-DISK02", confidence="manual", source="manual")
    db.add(host)
    db.commit()

    # RawImageAdapter falls back to matching the ".raw"/".img"/".dd"
    # extension when no MBR/GPT/filesystem signature is present, so
    # arbitrary bytes with a ".raw" name are enough to prove format
    # detection ran, without needing a real disk image fixture.
    payload = b"NOT-A-REAL-DISK-IMAGE-BUT-HAS-THE-RIGHT-EXTENSION"
    known_hash = hashlib.sha256(payload).hexdigest()
    session, info = _create_disk_image_session(db, filename="evidence.raw", expected_size_bytes=len(payload), host_id=host.id, provided_host=None)

    _upload_all_chunks(db, info.memory_upload_id, payload, info.chunk_size_bytes)
    finalized_upload, evidence = finalize_memory_upload_session(db, case_id=CASE_ID, upload_id=info.memory_upload_id, expected_sha256=known_hash)

    assert finalized_upload.status == "completed"
    assert evidence is not None
    assert evidence.evidence_type.value == "disk_image"
    assert evidence.sha256 == known_hash
    assert evidence.size_bytes == len(payload)
    assert evidence.host_id == host.id
    assert evidence.source_tool == "disk_image"
    assert evidence.original_filename == "evidence.raw"
    assert evidence.metadata_json["disk_image"]["format_probe"]["format"] == "raw"
    assert evidence.ingest_status.value == "pending"  # real registration (volume/OS discovery) happens async via enqueue_ingest, matching the legacy route

    synced = sync_unified_session(db, db.get(EvidenceUploadSession, session.id))
    assert synced.status == "promoted"
    assert synced.promoted_evidence_id == evidence.id


def test_disk_image_upload_rejects_unsupported_format(tmp_path, monkeypatch):
    _configure(monkeypatch, tmp_path)
    db = _db()
    _case(db)
    # No recognizable signature and no matching extension -> format
    # detection returns None -> "unknown_format", mirroring
    # routes_evidence.upload_disk_image's same rejection.
    payload = b"plain bytes, unrecognizable, no special extension"
    known_hash = hashlib.sha256(payload).hexdigest()
    session, info = _create_disk_image_session(db, filename="mystery.bin", expected_size_bytes=len(payload))
    _upload_all_chunks(db, info.memory_upload_id, payload, info.chunk_size_bytes)

    with pytest.raises(MemoryUploadSessionError) as exc_info:
        finalize_memory_upload_session(db, case_id=CASE_ID, upload_id=info.memory_upload_id, expected_sha256=known_hash)
    assert exc_info.value.code == "unknown_format"


def test_disk_image_and_memory_dump_ownership_never_cross(tmp_path, monkeypatch):
    """Two sessions created under different kinds must resolve to their
    own workflow handler even when both flags are enabled simultaneously."""
    _configure(monkeypatch, tmp_path)
    monkeypatch.setattr(settings, "memory_upload_enabled", True)
    monkeypatch.setattr(settings, "memory_upload_max_bytes", 64 * 1024 * 1024)
    monkeypatch.setattr(settings, "memory_max_upload_size", 64 * 1024 * 1024)
    monkeypatch.setattr(settings, "memory_upload_case_quota_bytes", 256 * 1024 * 1024)
    monkeypatch.setattr(settings, "unified_upload_evidence_memory_dump", True)
    db = _db()
    _case(db)

    disk_session, disk_info = _create_disk_image_session(db, filename="a.raw", expected_size_bytes=64)

    from app.services.evidence_unified_upload import UNIFIED_UPLOAD_KINDS as kinds
    mem_kind = kinds["memory_dump"]
    mem_session, mem_info = create_unified_upload_session(
        db, CASE_ID, kind="memory_dump", workflow=mem_kind.workflow, evidence_type=mem_kind.evidence_type,
        filename="b.mem", expected_size_bytes=64, declared_platform=None, client_sha256=None,
        host_id=None, provided_host="WIN-RAM", authorization_acknowledged=True, notes=None, current_user=None,
    )

    disk_upload = db.get(MemoryUpload, disk_info.memory_upload_id)
    mem_upload = db.get(MemoryUpload, mem_info.memory_upload_id)
    assert disk_upload.metadata_json["workflow"] == "disk_image"
    assert mem_upload.metadata_json["workflow"] == "evidence_memory_dump"
    assert is_unified_session(disk_session, kind="disk_image")
    assert not is_unified_session(disk_session, kind="memory_dump")
    assert is_unified_session(mem_session, kind="memory_dump")
    assert not is_unified_session(mem_session, kind="disk_image")
