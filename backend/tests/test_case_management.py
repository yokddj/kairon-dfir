from fastapi import FastAPI
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from app.api import routes_cases
from app.core.database import Base, get_db
from app.main import app, settings
from app.models.activity import AppActivityEvent
from app.models.case import Case
from app.models.evidence import Evidence, EvidenceStorageMode, EvidenceType, IngestStatus


CASE_ID = "aaaaaaaa-1111-4111-8111-aaaaaaaaaaaa"
EVIDENCE_ID = "bbbbbbbb-2222-4222-8222-bbbbbbbbbbbb"


def _db():
    engine = create_engine("sqlite:///:memory:", connect_args={"check_same_thread": False}, poolclass=StaticPool, future=True)
    Base.metadata.create_all(engine)
    return sessionmaker(bind=engine, future=True)()


def _client(db):
    test_app = FastAPI()
    test_app.include_router(routes_cases.router)
    test_app.dependency_overrides[get_db] = lambda: db
    return TestClient(test_app)


def _case(db, *, case_id=CASE_ID, name="Case", status="active", priority="medium", tags=None, description=""):
    item = Case(id=case_id, name=name, description=description, status=status, priority=priority, management_tags=tags or [])
    db.add(item)
    db.commit()
    return item


def _evidence(db):
    item = Evidence(
        id=EVIDENCE_ID,
        case_id=CASE_ID,
        original_filename="evidence.zip",
        stored_path="/tmp/evidence.zip",
        storage_mode=EvidenceStorageMode.uploaded,
        is_external=False,
        copy_to_storage=True,
        evidence_type=EvidenceType.velociraptor_zip,
        size_bytes=128,
        ingest_status=IngestStatus.completed,
        path_validation={},
        ingest_source={},
        metadata_json={},
        error_log={},
    )
    db.add(item)
    db.commit()
    return item


def test_new_case_defaults_to_active_medium():
    db = _db()
    client = _client(db)

    response = client.post("/api/cases", json={"name": "New Case"})

    assert response.status_code == 201
    payload = response.json()
    assert payload["status"] == "active"
    assert payload["priority"] == "medium"
    assert payload["tags"] == []


def test_patch_updates_priority_status_tags_description_and_notes():
    db = _db()
    _case(db)
    client = _client(db)

    response = client.patch(
        f"/api/cases/{CASE_ID}",
        json={"status": "closed", "priority": "high", "tags": [" CTF ", "Memory"], "description": "Updated", "case_notes": "Long notes"},
    )

    assert response.status_code == 200
    payload = response.json()
    assert payload["status"] == "closed"
    assert payload["priority"] == "high"
    assert payload["tags"] == ["ctf", "memory"]
    assert payload["description"] == "Updated"
    assert payload["case_notes"] == "Long notes"


def test_tags_are_normalized_and_deduplicated():
    db = _db()
    client = _client(db)

    response = client.post("/api/cases", json={"name": "Tags", "tags": [" CTF ", "ctf", "Memory Dump", ""]})

    assert response.status_code == 201
    assert response.json()["tags"] == ["ctf", "memory-dump"]


def test_invalid_status_and_priority_fail():
    db = _db()
    _case(db)
    client = _client(db)

    assert client.patch(f"/api/cases/{CASE_ID}", json={"status": "deleted"}).status_code == 422
    assert client.patch(f"/api/cases/{CASE_ID}", json={"priority": "urgent"}).status_code == 422


def test_archive_hidden_by_default_and_include_archived_shows_it():
    db = _db()
    _case(db, case_id="aaaaaaaa-1111-4111-8111-aaaaaaaaaaa1", name="Active")
    _case(db, case_id="bbbbbbbb-2222-4222-8222-bbbbbbbbbbb2", name="Archived", status="archived")
    client = _client(db)

    default = client.get("/api/cases")
    included = client.get("/api/cases?include_archived=true")

    assert [item["name"] for item in default.json()] == ["Active"]
    assert {item["name"] for item in included.json()} == {"Active", "Archived"}


def test_close_reopen_archive_unarchive_actions():
    db = _db()
    _case(db)
    client = _client(db)

    assert client.post(f"/api/cases/{CASE_ID}/close").json()["status"] == "closed"
    assert client.post(f"/api/cases/{CASE_ID}/reopen").json()["status"] == "active"
    assert client.post(f"/api/cases/{CASE_ID}/archive").json()["status"] == "archived"
    assert client.post(f"/api/cases/{CASE_ID}/unarchive").json()["status"] == "active"


def test_filters_by_text_status_priority_and_tag():
    db = _db()
    _case(db, case_id="cccccccc-3333-4333-8333-ccccccccccc3", name="Memory Lab", priority="critical", tags=["ctf", "memory"], description="RAM image")
    _case(db, case_id="dddddddd-4444-4444-8444-ddddddddddd4", name="Ransomware", status="closed", priority="high", tags=["windows"])
    client = _client(db)

    assert [item["name"] for item in client.get("/api/cases?q=ram").json()] == ["Memory Lab"]
    assert [item["name"] for item in client.get("/api/cases?status=closed").json()] == ["Ransomware"]
    assert [item["name"] for item in client.get("/api/cases?priority=critical").json()] == ["Memory Lab"]
    assert [item["name"] for item in client.get("/api/cases?tag=memory").json()] == ["Memory Lab"]


def test_archive_does_not_delete_evidence():
    db = _db()
    _case(db)
    _evidence(db)
    client = _client(db)

    response = client.post(f"/api/cases/{CASE_ID}/archive")

    assert response.status_code == 200
    assert db.get(Evidence, EVIDENCE_ID) is not None
    assert response.json()["evidence_count"] == 1


def test_case_management_events_are_recorded():
    db = _db()
    _case(db)
    client = _client(db)

    client.patch(f"/api/cases/{CASE_ID}", json={"priority": "critical", "tags": ["ctf"]})
    client.post(f"/api/cases/{CASE_ID}/archive")

    event_types = {event.activity_type for event in db.query(AppActivityEvent).all()}
    assert {"case_priority_changed", "case_tags_changed", "case_updated", "case_archived"}.issubset(event_types)


def test_unauthenticated_user_cannot_access_cases(monkeypatch):
    monkeypatch.setattr(settings, "auth_enabled", True)
    response = TestClient(app).get("/api/cases")
    monkeypatch.setattr(settings, "auth_enabled", False)

    assert response.status_code == 401
