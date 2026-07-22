"""Coverage for the unified chunk-index Evidence Wizard memory_dump path
(UNIFIED_UPLOAD_EVIDENCE_MEMORY_DUMP).

Exercises app.services.evidence_unified_memory (session creation, status
projection onto EvidenceUploadSession/Activity Center, cancel) and
app.services.evidence_memory_workflow (the "evidence_memory_dump" workflow
handler), plus the ownership-fixing contract in
app.services.memory.upload_sessions.finalize_memory_upload_session: a
session's registration workflow is decided once, at creation, and never
changes afterward regardless of later feature-flag state.
"""
from __future__ import annotations

import asyncio
import hashlib
from pathlib import Path

import uuid
from datetime import datetime, timedelta, timezone

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from app.api import routes_evidence_preflight
from app.core.config import get_settings
from app.core.database import Base, get_db, utc_now
from app.models.case_access import CaseAccess
from app.models.session import Session as AuthSession
from app.models.user import User
from app.services.auth_utils import hash_token
from app.models.case import Case
from app.models.case_host import CaseHost
from app.models.evidence_upload_session import EvidenceUploadSession, EvidenceUploadSessionStatus
from app.models.memory import MemoryUpload
from app.services.evidence_memory_workflow import register_evidence_memory_dump
from app.services.evidence_operations import ALLOWED_OPERATION_TRANSITIONS
from app.services.evidence_unified_memory import (
    cancel_unified_memory_dump_session,
    create_unified_memory_dump_session,
    is_unified_memory_dump_session,
    sync_unified_session_from_memory_upload,
    unified_upload_info,
)
from app.services.evidence_upload_session import UploadSessionError, append_resumable_upload_chunk_stream, finalize_resumable_upload_session, get_upload_session
from app.services.memory.upload_sessions import (
    MemoryUploadSessionError,
    cancel_memory_upload_session,
    finalize_memory_upload_session,
    store_memory_upload_chunk_stream,
)
from app.services.upload_shared.workflow import get_workflow_handler, registered_workflows

settings = get_settings()
CASE_ID = "cccccccc-1111-4111-8111-cccccccccccc"


def _db():
    engine = create_engine("sqlite:///:memory:", connect_args={"check_same_thread": False}, poolclass=StaticPool, future=True)
    Base.metadata.create_all(engine)
    return sessionmaker(bind=engine, future=True)()


def _client(db):
    test_app = FastAPI()
    test_app.include_router(routes_evidence_preflight.router)
    test_app.dependency_overrides[get_db] = lambda: db
    return TestClient(test_app)


def _login(db, client, *, case_id=CASE_ID, is_admin=False, grant_case_access=True):
    user = User(id=str(uuid.uuid4()), username=f"analyst-{uuid.uuid4().hex[:8]}", password_hash="x", is_admin=is_admin)
    db.add(user)
    db.commit()
    if grant_case_access and not is_admin:
        db.add(CaseAccess(id=str(uuid.uuid4()), case_id=case_id, user_id=user.id, role="analyst"))
        db.commit()
    token = f"test-token-{user.id}"
    db.add(AuthSession(id=str(uuid.uuid4()), user_id=user.id, token_hash=hash_token(token), expires_at=(datetime.now(timezone.utc) + timedelta(hours=1)).isoformat()))
    db.commit()
    client.cookies.set("kairon_session", token)
    return user


def _case(db, *, case_id=CASE_ID):
    item = Case(id=case_id, name="Unified Upload Case", description="", status="active", priority="medium", management_tags=[])
    db.add(item)
    db.commit()
    return item


def _configure(monkeypatch, tmp_path):
    monkeypatch.setattr(settings, "backend_temp_dir", tmp_path / "tmp")
    monkeypatch.setattr(settings, "backend_data_dir", tmp_path / "data")
    monkeypatch.setattr(settings, "memory_upload_enabled", True)
    monkeypatch.setattr(settings, "memory_upload_max_bytes", 64 * 1024 * 1024)
    monkeypatch.setattr(settings, "memory_max_upload_size", 64 * 1024 * 1024)
    monkeypatch.setattr(settings, "memory_upload_case_quota_bytes", 256 * 1024 * 1024)
    monkeypatch.setattr(settings, "memory_upload_chunk_size_bytes", 16)
    monkeypatch.setattr(settings, "memory_upload_chunk_size_min_bytes", 16)
    monkeypatch.setattr(settings, "unified_upload_evidence_memory_dump", True)
    monkeypatch.setattr("app.services.memory.upload_sessions._capacity_snapshot", lambda *args, **kwargs: {"can_accept_selected_size": True})


async def _bytes_stream(payload: bytes):
    yield payload


def _upload_all_chunks(db, memory_upload_id: str, payload: bytes, chunk_size: int) -> None:
    total_chunks = max(1, -(-len(payload) // chunk_size))
    for index in range(total_chunks):
        start = index * chunk_size
        chunk = payload[start:start + chunk_size]
        asyncio.run(
            store_memory_upload_chunk_stream(
                db,
                case_id=CASE_ID,
                upload_id=memory_upload_id,
                chunk_index=index,
                chunks=_bytes_stream(chunk),
                headers={"content-length": str(len(chunk))},
                content_length_is_payload=True,
                expected_mode="resumable",
            )
        )


def test_registered_workflows_include_evidence_memory_dump():
    assert "evidence_memory_dump" in registered_workflows()
    assert get_workflow_handler("evidence_memory_dump") is register_evidence_memory_dump


def test_create_unified_session_fixes_ownership_at_creation(tmp_path, monkeypatch):
    _configure(monkeypatch, tmp_path)
    db = _db()
    _case(db)
    session, info = create_unified_memory_dump_session(
        db,
        CASE_ID,
        filename="capture.mem",
        expected_size_bytes=64,
        declared_platform=None,
        client_sha256=None,
        host_id=None,
        provided_host="WIN-RAM01",
        memory_authorization_acknowledged=True,
        notes="found on WS-01",
        current_user=None,
    )
    assert is_unified_memory_dump_session(session)
    assert session.metadata_json["backend"] == "unified"
    assert session.metadata_json["memory_upload_id"] == info.memory_upload_id
    memory_upload = db.get(MemoryUpload, info.memory_upload_id)
    assert memory_upload.metadata_json["workflow"] == "evidence_memory_dump"
    assert memory_upload.metadata_json["wizard_notes"] == "found on WS-01"

    # Flipping the flag off after creation must not change this session's
    # backend -- ownership was decided once, at creation.
    monkeypatch.setattr(settings, "unified_upload_evidence_memory_dump", False)
    db.refresh(memory_upload)
    assert memory_upload.metadata_json["workflow"] == "evidence_memory_dump"


def test_legacy_memory_upload_session_has_no_workflow_key_and_defaults_to_memory(tmp_path, monkeypatch):
    _configure(monkeypatch, tmp_path)
    db = _db()
    _case(db)
    from app.services.memory.upload_sessions import create_memory_upload_session

    legacy = create_memory_upload_session(
        db,
        case_id=CASE_ID,
        filename="capture.mem",
        expected_size_bytes=16,
        provided_host="WIN-RAM01",
        authorization_acknowledged=True,
        upload_mode="direct",
    )
    assert "workflow" not in legacy.metadata_json
    payload = b"A" * 16
    monkeypatch.setattr(legacy, "expected_sha256", None)
    asyncio.run(
        store_memory_upload_chunk_stream(
            db,
            case_id=CASE_ID,
            upload_id=legacy.id,
            chunk_index=0,
            chunks=_bytes_stream(payload),
            headers={"content-length": "16"},
            content_length_is_payload=True,
            expected_mode="direct",
        )
    )
    _, evidence = finalize_memory_upload_session(db, case_id=CASE_ID, upload_id=legacy.id)
    assert evidence is not None
    assert evidence.evidence_type.value == "memory_dump"


def test_unified_single_chunk_upload_registers_evidence_with_wizard_metadata(tmp_path, monkeypatch):
    _configure(monkeypatch, tmp_path)
    db = _db()
    _case(db)
    host = CaseHost(id="dddddddd-1111-4111-8111-dddddddddddd", case_id=CASE_ID, canonical_name="WIN-RAM02", display_name="WIN-RAM02", confidence="manual", source="manual")
    db.add(host)
    db.commit()

    payload = b"KAIRON-UNIFIED-MEMORY-DUMP-BYTES"
    known_hash = hashlib.sha256(payload).hexdigest()
    session, info = create_unified_memory_dump_session(
        db,
        CASE_ID,
        filename="capture.mem",
        expected_size_bytes=len(payload),
        declared_platform="windows",
        client_sha256=known_hash,
        host_id=host.id,
        provided_host=None,
        memory_authorization_acknowledged=True,
        notes="Collected during triage",
        current_user=None,
    )
    assert info.total_chunks >= 2  # chunk size forced to 16 bytes in _configure

    _upload_all_chunks(db, info.memory_upload_id, payload, info.chunk_size_bytes)

    finalized_upload, evidence = finalize_memory_upload_session(db, case_id=CASE_ID, upload_id=info.memory_upload_id, expected_sha256=known_hash)
    assert finalized_upload.status == "completed"
    assert evidence is not None
    assert evidence.evidence_type.value == "memory_dump"
    assert evidence.sha256 == known_hash
    assert evidence.notes == "Collected during triage"
    assert evidence.host_id == host.id
    assert evidence.host_assignment_method == "upload_assignment"

    synced = sync_unified_session_from_memory_upload(db, db.get(EvidenceUploadSession, session.id))
    assert synced.status == EvidenceUploadSessionStatus.promoted.value
    assert synced.promoted_evidence_id == evidence.id
    assert synced.bytes_received == len(payload)


def test_unified_upload_supports_out_of_order_chunks_and_resume(tmp_path, monkeypatch):
    _configure(monkeypatch, tmp_path)
    db = _db()
    _case(db)
    payload = b"0123456789ABCDEF" * 3  # 48 bytes -> 3 chunks of 16
    known_hash = hashlib.sha256(payload).hexdigest()
    session, info = create_unified_memory_dump_session(
        db,
        CASE_ID,
        filename="capture.mem",
        expected_size_bytes=len(payload),
        declared_platform=None,
        client_sha256=known_hash,
        host_id=None,
        provided_host="WIN-RAM03",
        memory_authorization_acknowledged=True,
        notes=None,
        current_user=None,
    )
    assert info.total_chunks == 3
    chunk_size = info.chunk_size_bytes
    order = [2, 0, 1]  # out of order, simulating parallel completion
    for index in order:
        start = index * chunk_size
        chunk = payload[start:start + chunk_size]
        asyncio.run(
            store_memory_upload_chunk_stream(
                db,
                case_id=CASE_ID,
                upload_id=info.memory_upload_id,
                chunk_index=index,
                chunks=_bytes_stream(chunk),
                headers={"content-length": str(len(chunk))},
                content_length_is_payload=True,
                expected_mode="resumable",
            )
        )
    finalized_upload, evidence = finalize_memory_upload_session(db, case_id=CASE_ID, upload_id=info.memory_upload_id, expected_sha256=known_hash)
    assert evidence is not None
    assert evidence.sha256 == known_hash
    assert Path(evidence.stored_path).read_bytes() == payload


def test_cancel_unified_session_cancels_backing_memory_upload(tmp_path, monkeypatch):
    _configure(monkeypatch, tmp_path)
    db = _db()
    _case(db)
    session, info = create_unified_memory_dump_session(
        db,
        CASE_ID,
        filename="capture.mem",
        expected_size_bytes=64,
        declared_platform=None,
        client_sha256=None,
        host_id=None,
        provided_host="WIN-RAM04",
        memory_authorization_acknowledged=True,
        notes=None,
        current_user=None,
    )
    cancelled = cancel_unified_memory_dump_session(db, session)
    assert cancelled.status == EvidenceUploadSessionStatus.cancelled.value
    memory_upload = db.get(MemoryUpload, info.memory_upload_id)
    assert memory_upload.status == "cancelled"


def test_legacy_byte_offset_endpoints_reject_unified_sessions(tmp_path, monkeypatch):
    _configure(monkeypatch, tmp_path)
    db = _db()
    _case(db)
    session, _info = create_unified_memory_dump_session(
        db,
        CASE_ID,
        filename="capture.mem",
        expected_size_bytes=16,
        declared_platform=None,
        client_sha256=None,
        host_id=None,
        provided_host="WIN-RAM05",
        memory_authorization_acknowledged=True,
        notes=None,
        current_user=None,
    )
    fresh = get_upload_session(db, CASE_ID, session.id)
    with pytest.raises(UploadSessionError) as exc_info:
        asyncio.run(append_resumable_upload_chunk_stream(db, fresh, offset=0, chunks=_bytes_stream(b"x" * 16)))
    assert exc_info.value.code == "unified_session_wrong_endpoint"

    with pytest.raises(UploadSessionError) as exc_info:
        finalize_resumable_upload_session(db, fresh)
    assert exc_info.value.code == "unified_session_wrong_endpoint"


def test_unified_status_projection_maps_onto_evidence_operation_state_machine(tmp_path, monkeypatch):
    """Every status app.services.evidence_unified_memory can project must be
    a valid node in evidence_operations.ALLOWED_OPERATION_TRANSITIONS, or
    Activity Center's sync_upload_operation raises on the next poll."""
    from app.services.evidence_unified_memory import _UNIFIED_STATUS_TO_SESSION_STATUS
    from app.services.evidence_operations import _operation_status

    valid_operation_statuses = set(ALLOWED_OPERATION_TRANSITIONS.keys())
    for memory_status, session_status in _UNIFIED_STATUS_TO_SESSION_STATUS.items():
        operation_status = _operation_status(session_status)
        assert operation_status in valid_operation_statuses, (memory_status, session_status, operation_status)


def test_duplicate_active_session_conflict_surfaces_as_upload_session_error(tmp_path, monkeypatch):
    _configure(monkeypatch, tmp_path)
    db = _db()
    _case(db)
    create_unified_memory_dump_session(
        db, CASE_ID, filename="dup.mem", expected_size_bytes=64, declared_platform=None, client_sha256=None,
        host_id=None, provided_host="WIN-RAM06", memory_authorization_acknowledged=True, notes=None, current_user=None,
    )
    # MemoryUploadSessionError propagates unwrapped (not repackaged as
    # UploadSessionError) so the route layer's dedicated handler keeps this
    # code's correct 409 status, instead of falling back to a generic 400.
    with pytest.raises(MemoryUploadSessionError) as exc_info:
        create_unified_memory_dump_session(
            db, CASE_ID, filename="dup.mem", expected_size_bytes=64, declared_platform=None, client_sha256=None,
            host_id=None, provided_host="WIN-RAM06", memory_authorization_acknowledged=True, notes=None, current_user=None,
        )
    assert exc_info.value.code == "MEMORY_UPLOAD_ACTIVE_SESSION_EXISTS"


def test_http_init_falls_back_to_legacy_when_flag_disabled(tmp_path, monkeypatch):
    _configure(monkeypatch, tmp_path)
    monkeypatch.setattr(settings, "unified_upload_evidence_memory_dump", False)
    db = _db()
    _case(db)
    client = _client(db)
    response = client.post(
        f"/api/cases/{CASE_ID}/evidence-uploads/resumable",
        json={"filename": "capture.mem", "expected_size_bytes": 64, "intake_category": "memory_dump", "provided_host": "WIN-RAM07", "memory_authorization_acknowledged": True},
    )
    assert response.status_code == 200, response.text
    body = response.json()
    assert body["unified"] is None
    session = db.get(EvidenceUploadSession, body["session"]["id"])
    assert not is_unified_memory_dump_session(session)


def test_http_init_routes_memory_dump_intake_to_unified_backend_when_flag_enabled(tmp_path, monkeypatch):
    _configure(monkeypatch, tmp_path)
    db = _db()
    _case(db)
    client = _client(db)
    response = client.post(
        f"/api/cases/{CASE_ID}/evidence-uploads/resumable",
        json={"filename": "capture.mem", "expected_size_bytes": 64, "intake_category": "memory_dump", "provided_host": "WIN-RAM08", "memory_authorization_acknowledged": True},
    )
    assert response.status_code == 200, response.text
    body = response.json()
    assert body["unified"] is not None
    assert body["unified"]["total_chunks"] >= 1
    session = db.get(EvidenceUploadSession, body["session"]["id"])
    assert is_unified_memory_dump_session(session)

    # Other intake categories are untouched by the flag: no intake_category
    # (or a non-memory_dump one) always takes the legacy path.
    generic_response = client.post(
        f"/api/cases/{CASE_ID}/evidence-uploads/resumable",
        json={"filename": "collection.zip", "expected_size_bytes": 64},
    )
    assert generic_response.status_code == 200, generic_response.text
    assert generic_response.json()["unified"] is None


def test_http_duplicate_active_session_returns_409(tmp_path, monkeypatch):
    _configure(monkeypatch, tmp_path)
    db = _db()
    _case(db)
    client = _client(db)
    payload = {"filename": "dup.mem", "expected_size_bytes": 64, "intake_category": "memory_dump", "provided_host": "WIN-RAM09", "memory_authorization_acknowledged": True}
    first = client.post(f"/api/cases/{CASE_ID}/evidence-uploads/resumable", json=payload)
    assert first.status_code == 200, first.text
    second = client.post(f"/api/cases/{CASE_ID}/evidence-uploads/resumable", json=payload)
    assert second.status_code == 409, second.text


# ---------------------------------------------------------------------------
# Resumable session discovery (GET /{case_id}/evidence-uploads)
# ---------------------------------------------------------------------------

def test_resumable_discovery_requires_authentication(tmp_path, monkeypatch):
    _configure(monkeypatch, tmp_path)
    db = _db()
    _case(db)
    client = _client(db)
    response = client.get(f"/api/cases/{CASE_ID}/evidence-uploads")
    assert response.status_code == 401


def test_resumable_discovery_denies_user_without_case_access(tmp_path, monkeypatch):
    _configure(monkeypatch, tmp_path)
    db = _db()
    _case(db)
    client = _client(db)
    _login(db, client, grant_case_access=False)
    response = client.get(f"/api/cases/{CASE_ID}/evidence-uploads")
    assert response.status_code == 403


def test_resumable_discovery_isolated_across_cases(tmp_path, monkeypatch):
    _configure(monkeypatch, tmp_path)
    db = _db()
    other_case_id = "eeeeeeee-1111-4111-8111-eeeeeeeeeeee"
    _case(db)
    _case(db, case_id=other_case_id)
    create_unified_memory_dump_session(
        db, CASE_ID, filename="in-case.mem", expected_size_bytes=64, declared_platform=None, client_sha256=None,
        host_id=None, provided_host="WIN-A", memory_authorization_acknowledged=True, notes=None, current_user=None,
    )
    client = _client(db)
    # A user with access to a DIFFERENT case must not see this case's sessions.
    _login(db, client, case_id=other_case_id)
    response = client.get(f"/api/cases/{CASE_ID}/evidence-uploads")
    assert response.status_code == 403


def test_resumable_discovery_lists_unified_session_with_chunk_bitmap(tmp_path, monkeypatch):
    _configure(monkeypatch, tmp_path)
    db = _db()
    _case(db)
    payload = b"0123456789ABCDEF" * 3  # 48 bytes -> 3 chunks of 16
    session, info = create_unified_memory_dump_session(
        db, CASE_ID, filename="capture.mem", expected_size_bytes=len(payload), declared_platform=None, client_sha256=None,
        host_id=None, provided_host="WIN-RAM10", memory_authorization_acknowledged=True, notes=None, current_user=None,
    )
    asyncio.run(
        store_memory_upload_chunk_stream(
            db, case_id=CASE_ID, upload_id=info.memory_upload_id, chunk_index=0,
            chunks=_bytes_stream(payload[0:16]), headers={"content-length": "16"}, content_length_is_payload=True, expected_mode="resumable",
        )
    )
    client = _client(db)
    _login(db, client)
    response = client.get(f"/api/cases/{CASE_ID}/evidence-uploads")
    assert response.status_code == 200, response.text
    body = response.json()
    entries = [s for s in body["sessions"] if s["id"] == session.id]
    assert len(entries) == 1
    entry = entries[0]
    assert entry["backend"] == "unified"
    assert entry["category"] == "memory_dump"
    assert entry["status"] == "uploading"
    assert entry["resumable"] is True
    assert entry["cancellable"] is True
    assert entry["unified"]["memory_upload_id"] == info.memory_upload_id
    assert entry["unified"]["received_chunks"] == [0]
    assert entry["unified"]["missing_chunks"] == [1, 2]
    assert entry["unified"]["verification_chunk_index"] == 0
    assert entry["unified"]["verification_chunk_sha256"] == hashlib.sha256(payload[0:16]).hexdigest()


def test_resumable_discovery_excludes_cancelled_and_expired(tmp_path, monkeypatch):
    _configure(monkeypatch, tmp_path)
    db = _db()
    _case(db)
    cancelled_session, _ = create_unified_memory_dump_session(
        db, CASE_ID, filename="cancelled.mem", expected_size_bytes=64, declared_platform=None, client_sha256=None,
        host_id=None, provided_host="WIN-RAM11", memory_authorization_acknowledged=True, notes=None, current_user=None,
    )
    cancel_unified_memory_dump_session(db, cancelled_session)

    from app.models.evidence_upload_session import EvidenceUploadSessionStatus
    expired_session, _ = create_unified_memory_dump_session(
        db, CASE_ID, filename="expired.mem", expected_size_bytes=64, declared_platform=None, client_sha256=None,
        host_id=None, provided_host="WIN-RAM12", memory_authorization_acknowledged=True, notes=None, current_user=None,
    )
    expired_session.expires_at = utc_now() - timedelta(days=1)
    expired_session.status = EvidenceUploadSessionStatus.expired.value
    db.add(expired_session)
    db.commit()

    client = _client(db)
    _login(db, client)
    response = client.get(f"/api/cases/{CASE_ID}/evidence-uploads")
    ids = {s["id"] for s in response.json()["sessions"]}
    assert cancelled_session.id not in ids
    assert expired_session.id not in ids


def test_resumable_discovery_surfaces_recently_promoted_session_for_redirect(tmp_path, monkeypatch):
    _configure(monkeypatch, tmp_path)
    db = _db()
    _case(db)
    payload = b"A" * 16
    session, info = create_unified_memory_dump_session(
        db, CASE_ID, filename="capture.mem", expected_size_bytes=len(payload), declared_platform=None, client_sha256=hashlib.sha256(payload).hexdigest(),
        host_id=None, provided_host="WIN-RAM13", memory_authorization_acknowledged=True, notes=None, current_user=None,
    )
    asyncio.run(
        store_memory_upload_chunk_stream(
            db, case_id=CASE_ID, upload_id=info.memory_upload_id, chunk_index=0,
            chunks=_bytes_stream(payload), headers={"content-length": "16"}, content_length_is_payload=True, expected_mode="resumable",
        )
    )
    _, evidence = finalize_memory_upload_session(db, case_id=CASE_ID, upload_id=info.memory_upload_id, expected_sha256=hashlib.sha256(payload).hexdigest())

    client = _client(db)
    _login(db, client)
    response = client.get(f"/api/cases/{CASE_ID}/evidence-uploads")
    entries = [s for s in response.json()["sessions"] if s["id"] == session.id]
    assert len(entries) == 1
    assert entries[0]["status"] == "promoted"
    assert entries[0]["promoted_evidence_id"] == evidence.id
    assert entries[0]["resumable"] is False


def test_resumable_discovery_reconciles_missing_backing_memory_upload(tmp_path, monkeypatch):
    _configure(monkeypatch, tmp_path)
    db = _db()
    _case(db)
    session, info = create_unified_memory_dump_session(
        db, CASE_ID, filename="orphan.mem", expected_size_bytes=64, declared_platform=None, client_sha256=None,
        host_id=None, provided_host="WIN-RAM14", memory_authorization_acknowledged=True, notes=None, current_user=None,
    )
    memory_upload = db.get(MemoryUpload, info.memory_upload_id)
    db.delete(memory_upload)
    db.commit()

    client = _client(db)
    _login(db, client)
    response = client.get(f"/api/cases/{CASE_ID}/evidence-uploads")
    entries = [s for s in response.json()["sessions"] if s["id"] == session.id]
    # Ownership-mismatch / missing-backing-session reconciliation marks the
    # session failed with a clear message instead of leaving it silently
    # stuck showing "uploading" forever, and a non-retryable failure isn't
    # offered for resume.
    if entries:
        assert entries[0]["status"] == "failed"
        assert entries[0]["resumable"] is False
    refreshed = db.get(EvidenceUploadSession, session.id)
    assert refreshed.status == "failed"
    assert "no longer available" in (refreshed.failure_message or "")


def test_resumable_discovery_includes_legacy_session(tmp_path, monkeypatch):
    _configure(monkeypatch, tmp_path)
    db = _db()
    _case(db)
    from app.services.evidence_upload_session import create_resumable_upload_session

    legacy_session = create_resumable_upload_session(db, CASE_ID, filename="disk.E01", expected_size_bytes=1024, declared_platform=None, client_sha256=None)
    client = _client(db)
    _login(db, client)
    response = client.get(f"/api/cases/{CASE_ID}/evidence-uploads")
    entries = [s for s in response.json()["sessions"] if s["id"] == legacy_session.id]
    assert len(entries) == 1
    assert entries[0]["backend"] == "legacy"
    assert entries[0]["resumable"] is True
    assert entries[0]["unified"] is None
