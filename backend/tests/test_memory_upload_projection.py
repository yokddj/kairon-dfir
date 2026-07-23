"""Coverage for the architecture-consolidation phase's Workstream A: Memory
Overview's own upload-session-creation endpoint (POST /memory/uploads) now
also projects into the same EvidenceUploadSession/EvidenceOperation surface
the Wizard's unified sessions use, via the same create_unified_upload_session
-- not a second projection mechanism. Workflow stays "memory" (the plain
register_memory_evidence_from_upload handler this page has always used),
never "evidence_memory_dump" (the Wizard-only handler) -- see
evidence_memory_workflow.py's docstring for why these are a proven superset
relationship, not equivalence, and must not be merged.

These tests exercise the route directly (HTTP-level, matching the existing
pattern in test_memory_analysis.py) since the behavior under test IS the
route's session-creation plumbing, not the underlying chunk engine (already
covered exhaustively by test_evidence_unified_upload.py).
"""
from __future__ import annotations

from fastapi import FastAPI
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from app.api import routes_memory
from app.core.config import get_settings
from app.core.database import Base, get_db
from app.models.case import Case
from app.models.evidence import Evidence
from app.models.evidence_upload_session import EvidenceUploadSession
from app.models.memory import MemoryUpload
from app.services.evidence_operations import get_upload_operation
from app.services.evidence_unified_upload import find_unified_session_for_memory_upload, is_unified_session
from app.services.memory import upload_sessions as memory_upload_sessions
from app.services.memory.upload_lifecycle import get_memory_upload

settings = get_settings()
CASE_ID = "ffffffff-3333-4333-8333-ffffffffffff"


def _db():
    engine = create_engine("sqlite:///:memory:", connect_args={"check_same_thread": False}, poolclass=StaticPool, future=True)
    Base.metadata.create_all(engine)
    return sessionmaker(bind=engine, future=True)()


def _case(db, *, case_id=CASE_ID):
    item = Case(id=case_id, name="Memory Projection Case", description="", status="active", priority="medium", management_tags=[])
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
    monkeypatch.setattr("app.services.memory.upload_sessions._capacity_snapshot", lambda *args, **kwargs: {"can_accept_selected_size": True})


def _client(db):
    app = FastAPI()
    app.include_router(routes_memory.router)
    app.dependency_overrides[get_db] = lambda: db
    return TestClient(app)


def test_memory_overview_session_creation_produces_the_shared_projection(tmp_path, monkeypatch):
    _configure(monkeypatch, tmp_path)
    db = _db()
    _case(db)
    client = _client(db)

    response = client.post(
        f"/api/cases/{CASE_ID}/memory/uploads",
        json={"filename": "capture.mem", "expected_size_bytes": 32, "provided_host": "WS-MEM01", "authorization_acknowledged": True},
    )
    assert response.status_code == 201
    body = response.json()
    upload_id = body["upload_id"]

    memory_upload = db.get(MemoryUpload, upload_id)
    assert memory_upload is not None
    assert memory_upload.metadata_json["workflow"] == "memory"  # NOT "evidence_memory_dump" -- see module docstring

    projected = find_unified_session_for_memory_upload(db, case_id=CASE_ID, memory_upload_id=upload_id)
    assert projected is not None
    assert is_unified_session(projected, kind="memory_dump")


def test_activity_center_receives_the_projected_memory_upload(tmp_path, monkeypatch):
    _configure(monkeypatch, tmp_path)
    db = _db()
    _case(db)
    client = _client(db)

    response = client.post(
        f"/api/cases/{CASE_ID}/memory/uploads",
        json={"filename": "capture.mem", "expected_size_bytes": 32, "provided_host": "WS-MEM02", "authorization_acknowledged": True},
    )
    upload_id = response.json()["upload_id"]

    session = find_unified_session_for_memory_upload(db, case_id=CASE_ID, memory_upload_id=upload_id)
    assert session is not None
    operation = get_upload_operation(db, session)
    assert operation is not None
    assert operation.case_id == CASE_ID


def test_cancel_from_memory_overview_syncs_the_shared_projection(tmp_path, monkeypatch):
    _configure(monkeypatch, tmp_path)
    db = _db()
    _case(db)
    client = _client(db)

    created = client.post(
        f"/api/cases/{CASE_ID}/memory/uploads",
        json={"filename": "capture.mem", "expected_size_bytes": 32, "provided_host": "WS-MEM03", "authorization_acknowledged": True},
    ).json()
    upload_id = created["upload_id"]

    cancel_response = client.post(f"/api/cases/{CASE_ID}/memory/uploads/{upload_id}/cancel", json={})
    assert cancel_response.status_code == 200
    assert cancel_response.json()["status"] == "cancelled"

    session = find_unified_session_for_memory_upload(db, case_id=CASE_ID, memory_upload_id=upload_id)
    assert session is not None
    db.refresh(session)
    assert session.status == "cancelled"


def test_projection_registers_no_duplicate_evidence_on_completion(tmp_path, monkeypatch):
    """The projection is purely observational -- registration still runs
    exactly once, through the same "memory" workflow handler, exactly as
    before this change."""
    import asyncio

    _configure(monkeypatch, tmp_path)
    monkeypatch.setattr(routes_memory, "settings", settings)
    db = _db()
    _case(db)
    client = _client(db)

    payload = b"0123456789ABCDEF" * 2  # 32 bytes, 2 chunks of 16
    created = client.post(
        f"/api/cases/{CASE_ID}/memory/uploads",
        json={"filename": "capture.mem", "expected_size_bytes": len(payload), "provided_host": "WS-MEM04", "authorization_acknowledged": True},
    ).json()
    upload_id = created["upload_id"]

    import hashlib

    for index in range(2):
        chunk = payload[index * 16:(index + 1) * 16]
        resp = client.post(
            f"/api/cases/{CASE_ID}/memory/uploads/{upload_id}/chunks/{index}",
            files={"chunk": (f"chunk-{index}.bin", chunk, "application/octet-stream")},
            headers={"X-Kairon-Chunk-SHA256": hashlib.sha256(chunk).hexdigest()},
        )
        assert resp.status_code == 204

    finalize_resp = client.post(f"/api/cases/{CASE_ID}/memory/uploads/{upload_id}/finalize", json={})
    assert finalize_resp.status_code == 200
    evidence_id = finalize_resp.json()["evidence_id"]
    assert evidence_id is not None
    assert db.query(Evidence).filter(Evidence.case_id == CASE_ID).count() == 1

    # Re-finalizing (e.g. a client retry) must not create a second Evidence.
    finalize_again = client.post(f"/api/cases/{CASE_ID}/memory/uploads/{upload_id}/finalize", json={})
    assert finalize_again.status_code == 200
    assert finalize_again.json()["evidence_id"] == evidence_id
    assert db.query(Evidence).filter(Evidence.case_id == CASE_ID).count() == 1


def test_pre_existing_active_session_has_no_projection_and_stays_served_by_the_direct_api(tmp_path, monkeypatch):
    """Explicit non-migration compatibility strategy: a MemoryUpload created
    the OLD way (direct create_memory_upload_session call, bypassing the
    route entirely -- simulating a session that existed before this
    deployment) gets no retroactive EvidenceUploadSession. It must keep
    working exactly as before via the existing direct MemoryUpload-table
    endpoints, and must never be silently double-registered."""
    _configure(monkeypatch, tmp_path)
    db = _db()
    _case(db)
    client = _client(db)

    pre_existing = memory_upload_sessions.create_memory_upload_session(
        db, case_id=CASE_ID, filename="pre-existing.mem", expected_size_bytes=16,
        provided_host="WS-OLD", authorization_acknowledged=True,
    )
    assert pre_existing.metadata_json.get("workflow") in (None, "memory")

    # No projection exists for it.
    assert find_unified_session_for_memory_upload(db, case_id=CASE_ID, memory_upload_id=pre_existing.id) is None

    # The existing direct discovery/status API still serves it, unaffected.
    active_response = client.get(f"/api/cases/{CASE_ID}/memory/uploads/active")
    assert active_response.status_code == 200
    assert active_response.json()["upload_id"] == pre_existing.id

    status_response = client.get(f"/api/cases/{CASE_ID}/memory/uploads/{pre_existing.id}")
    assert status_response.status_code == 200
    assert status_response.json()["upload_id"] == pre_existing.id

    # Cancelling it must not error just because there's no projection to sync.
    cancel_response = client.post(f"/api/cases/{CASE_ID}/memory/uploads/{pre_existing.id}/cancel", json={})
    assert cancel_response.status_code == 200
    assert cancel_response.json()["status"] == "cancelled"


def test_memory_and_evidence_memory_dump_workflows_are_not_merged(tmp_path, monkeypatch):
    """Direct proof that Memory Overview sessions keep the plain "memory"
    workflow -- switching to "evidence_memory_dump" was considered and
    explicitly rejected (see the architecture-consolidation review) because
    that handler layers Wizard-only concepts (explicit host override,
    notes) this page has no UI to populate correctly."""
    _configure(monkeypatch, tmp_path)
    db = _db()
    _case(db)
    client = _client(db)

    response = client.post(
        f"/api/cases/{CASE_ID}/memory/uploads",
        json={"filename": "capture.mem", "expected_size_bytes": 32, "provided_host": "WS-MEM05", "authorization_acknowledged": True},
    )
    upload_id = response.json()["upload_id"]
    memory_upload = get_memory_upload(db, CASE_ID, upload_id)
    assert memory_upload.metadata_json["workflow"] == "memory"
    # "memory" is registered as a thin lambda adapter around
    # register_memory_evidence (memory/upload_sessions.py:54, needed only
    # because register_memory_evidence's `db` param is keyword-only while
    # the workflow registry calls positionally) -- not "evidence_memory_dump".
    from app.services.upload_shared.workflow import get_workflow_handler

    assert get_workflow_handler("memory") is not get_workflow_handler("evidence_memory_dump")
