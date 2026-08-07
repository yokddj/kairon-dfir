from fastapi import FastAPI
from fastapi.testclient import TestClient
from sqlalchemy import create_engine, event
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from app.api import routes_evidence, routes_hosts
from app.core.database import Base, get_db
from app.models.assignment_history import AssignmentHistory
from app.models.case import Case
from app.models.case_host import CaseHost
from app.models.case_host_alias import CaseHostAlias
from app.models.evidence import Evidence, EvidenceCustodyEvent, EvidenceStorageMode, EvidenceType, IngestStatus
from app.services.memory.overview import list_memory_evidences

CASE_ID = "aaaaaaaa-1111-4111-8111-aaaaaaaaaaaa"
OTHER_CASE_ID = "ffffffff-1111-4111-8111-ffffffffffff"
EVIDENCE_ID = "bbbbbbbb-2222-4222-8222-bbbbbbbbbbbb"
SECOND_EVIDENCE_ID = "cccccccc-3333-4333-8333-cccccccccccc"
HOST_WS01_ID = "dddddddd-1111-4111-8111-dddddddddddd"
HOST_WS02_ID = "eeeeeeee-2222-4222-8222-eeeeeeeeeeee"


def _db():
    engine = create_engine("sqlite:///:memory:", connect_args={"check_same_thread": False}, poolclass=StaticPool, future=True)
    Base.metadata.create_all(engine)
    return sessionmaker(bind=engine, future=True)()


def _client(db):
    app = FastAPI()
    app.include_router(routes_hosts.router)
    app.include_router(routes_evidence.router)
    app.dependency_overrides[get_db] = lambda: db
    return TestClient(app)


def _case(db, case_id=CASE_ID):
    db.add(Case(id=case_id, name="Case", description=None))
    db.commit()


def _host(db, host_id=HOST_WS01_ID, name="WS-01", case_id=CASE_ID):
    host = CaseHost(id=host_id, case_id=case_id, canonical_name=name.lower(), display_name=name, confidence="manual", source="manual")
    db.add(host)
    db.add(CaseHostAlias(case_host_id=host_id, case_id=case_id, alias=name, normalized_alias=name.lower(), source="manual", confidence="manual", is_primary=True))
    db.commit()
    return host


def _evidence(db, evidence_id=EVIDENCE_ID, *, detected_host="WIN-ABC123", host_id=None, evidence_type=EvidenceType.memory_dump):
    item = Evidence(
        id=evidence_id,
        case_id=CASE_ID,
        original_filename="memdump01.raw",
        stored_path="/tmp/memdump01.raw",
        original_path="/tmp/memdump01.raw",
        storage_mode=EvidenceStorageMode.uploaded,
        is_external=False,
        copy_to_storage=True,
        evidence_type=evidence_type,
        sha256="0" * 64,
        size_bytes=128,
        ingest_status=IngestStatus.completed,
        detected_host=detected_host,
        host_id=host_id,
        path_validation={},
        ingest_source={},
        metadata_json={},
        error_log={},
    )
    db.add(item)
    db.commit()
    return item


def test_list_and_create_case_host_reuses_case_insensitive_duplicate():
    db = _db()
    _case(db)
    client = _client(db)

    created = client.post(f"/api/cases/{CASE_ID}/hosts", json={"host_name": "WS-01"})
    duplicate = client.post(f"/api/cases/{CASE_ID}/hosts", json={"host_name": "ws-01"})
    listed = client.get(f"/api/cases/{CASE_ID}/hosts")

    assert created.status_code == 200
    assert created.json()["created"] is True
    assert duplicate.status_code == 200
    assert duplicate.json()["created"] is False
    assert len([host for host in listed.json()["hosts"] if host["canonical_name"] == "ws-01"]) == 1


def test_assign_existing_create_new_and_unassign_records_custody():
    db = _db()
    _case(db)
    _host(db)
    _evidence(db)
    client = _client(db)

    assigned = client.patch(f"/api/cases/{CASE_ID}/evidence/{EVIDENCE_ID}/host", json={"host_id": HOST_WS01_ID})
    created = client.patch(f"/api/cases/{CASE_ID}/evidence/{EVIDENCE_ID}/host", json={"host_name": "WS-02"})
    unassigned = client.patch(f"/api/cases/{CASE_ID}/evidence/{EVIDENCE_ID}/host", json={"host_id": None})

    assert assigned.status_code == 200
    assert assigned.json()["host_id"] == HOST_WS01_ID
    assert created.status_code == 200
    assert created.json()["host_id"] != HOST_WS01_ID
    assert unassigned.status_code == 200
    assert unassigned.json()["host_id"] is None
    event_types = {getattr(row.event_type, "value", row.event_type) for row in db.query(EvidenceCustodyEvent).all()}
    assert {"host_assigned", "host_created", "host_assignment_changed", "host_unassigned"}.issubset(event_types)


def test_cannot_assign_host_from_another_case():
    db = _db()
    _case(db)
    _case(db, OTHER_CASE_ID)
    _host(db, host_id=HOST_WS02_ID, name="WS-02", case_id=OTHER_CASE_ID)
    _evidence(db)
    client = _client(db)

    response = client.patch(f"/api/cases/{CASE_ID}/evidence/{EVIDENCE_ID}/host", json={"host_id": HOST_WS02_ID})

    assert response.status_code == 400


def test_memory_filter_prefers_assigned_host_and_falls_back_to_detected_host():
    db = _db()
    _case(db)
    _host(db, HOST_WS01_ID, "WS-01")
    _host(db, HOST_WS02_ID, "WS-02")
    _evidence(db, EVIDENCE_ID, detected_host="WIN-ABC123", host_id=HOST_WS01_ID)
    _evidence(db, SECOND_EVIDENCE_ID, detected_host="WS-02.local", host_id=None)

    assert [item.id for item in list_memory_evidences(db, CASE_ID, host_id=HOST_WS01_ID, host="WS-01")] == [EVIDENCE_ID]
    assert [item.id for item in list_memory_evidences(db, CASE_ID, host_id=HOST_WS02_ID, host="WS-02")] == [SECOND_EVIDENCE_ID]
    assert [item.id for item in list_memory_evidences(db, CASE_ID, host_id=HOST_WS02_ID, host="WS-02")] != [EVIDENCE_ID]


def test_unassigned_evidence_without_detected_host_does_not_break_memory_listing():
    db = _db()
    _case(db)
    _evidence(db, detected_host=None, host_id=None)

    assert [item.id for item in list_memory_evidences(db, CASE_ID)] == [EVIDENCE_ID]
    assert list_memory_evidences(db, CASE_ID, host="WS-01") == []


def test_delete_host_without_evidence_succeeds_immediately():
    db = _db()
    _case(db)
    _host(db)
    client = _client(db)

    preview = client.get(f"/api/cases/{CASE_ID}/hosts/{HOST_WS01_ID}/deletion-preview")
    assert preview.status_code == 200
    assert preview.json()["evidence_count"] == 0
    assert preview.json()["requires_reassignment"] is False

    response = client.delete(f"/api/cases/{CASE_ID}/hosts/{HOST_WS01_ID}")

    assert response.status_code == 200
    assert response.json()["moved_evidence_count"] == 0
    listed = client.get(f"/api/cases/{CASE_ID}/hosts")
    assert HOST_WS01_ID not in {host["id"] for host in listed.json()["hosts"]}


def test_delete_host_with_evidence_requires_target_host():
    db = _db()
    _case(db)
    _host(db)
    _evidence(db, host_id=HOST_WS01_ID)
    client = _client(db)

    preview = client.get(f"/api/cases/{CASE_ID}/hosts/{HOST_WS01_ID}/deletion-preview")
    assert preview.status_code == 200
    assert preview.json()["evidence_count"] == 1
    assert preview.json()["requires_reassignment"] is True
    assert preview.json()["eligible_target_hosts"] == []
    assert preview.json()["can_delete"] is False

    response = client.delete(f"/api/cases/{CASE_ID}/hosts/{HOST_WS01_ID}")

    assert response.status_code == 400
    # Nothing changed: host and evidence assignment are untouched.
    listed = client.get(f"/api/cases/{CASE_ID}/hosts")
    assert HOST_WS01_ID in {host["id"] for host in listed.json()["hosts"]}
    evidence = db.get(Evidence, EVIDENCE_ID)
    assert evidence.host_id == HOST_WS01_ID


def test_delete_host_moves_evidence_to_target_and_preserves_audit():
    db = _db()
    _case(db)
    _host(db, HOST_WS01_ID, "WS-01")
    _host(db, HOST_WS02_ID, "WS-02")
    _evidence(db, host_id=HOST_WS01_ID)
    client = _client(db)

    preview = client.get(f"/api/cases/{CASE_ID}/hosts/{HOST_WS01_ID}/deletion-preview")
    assert preview.json()["eligible_target_hosts"] == [{"id": HOST_WS02_ID, "display_name": "WS-02"}]

    response = client.request(
        "DELETE",
        f"/api/cases/{CASE_ID}/hosts/{HOST_WS01_ID}",
        json={"target_host_id": HOST_WS02_ID, "reason": "duplicate host", "analyst": "tester"},
    )

    assert response.status_code == 200
    body = response.json()
    assert body["moved_evidence_count"] == 1
    assert body["target_host_id"] == HOST_WS02_ID

    evidence = db.get(Evidence, EVIDENCE_ID)
    assert evidence.host_id == HOST_WS02_ID

    listed = client.get(f"/api/cases/{CASE_ID}/hosts")
    host_ids = {host["id"] for host in listed.json()["hosts"]}
    assert HOST_WS01_ID not in host_ids
    assert HOST_WS02_ID in host_ids

    # The deletion itself, and the host's prior identity history, survive as
    # case-level audit entries instead of being cascade-deleted with the host.
    audit = client.get(f"/api/cases/{CASE_ID}/hosts/audit")
    actions = [item["action"] for item in audit.json()["items"]]
    assert "host_deleted" in actions


def test_delete_host_rejects_target_from_another_case():
    db = _db()
    _case(db)
    _case(db, OTHER_CASE_ID)
    _host(db, HOST_WS01_ID, "WS-01")
    _host(db, HOST_WS02_ID, "WS-02", case_id=OTHER_CASE_ID)
    _evidence(db, host_id=HOST_WS01_ID)
    client = _client(db)

    response = client.request(
        "DELETE",
        f"/api/cases/{CASE_ID}/hosts/{HOST_WS01_ID}",
        json={"target_host_id": HOST_WS02_ID},
    )

    assert response.status_code == 400


def _db_with_foreign_keys():
    # Plain SQLite (used by _db() above) does not enforce foreign keys by
    # default, which is why the AssignmentHistory regression below was not
    # caught by earlier tests -- production runs on Postgres, which does
    # enforce them. Enabling the pragma here makes this engine behave like
    # Postgres for FK purposes.
    engine = create_engine("sqlite:///:memory:", connect_args={"check_same_thread": False}, poolclass=StaticPool, future=True)
    event.listen(engine, "connect", lambda dbapi_conn, _: dbapi_conn.execute("PRAGMA foreign_keys=ON"))
    Base.metadata.create_all(engine)
    return sessionmaker(bind=engine, future=True)()


def test_delete_host_with_prior_reassignment_history_does_not_violate_foreign_keys():
    """Regression test: AssignmentHistory.previous_host_id/new_host_id
    reference case_hosts.id with no ON DELETE clause. A host that had ever
    been the source or target of an evidence reassignment (including the
    reassignment delete_case_host itself performs) could not be deleted on
    Postgres -- it failed with a ForeignKeyViolation that plain in-memory
    SQLite (no FK enforcement) let slip through undetected."""
    db = _db_with_foreign_keys()
    _case(db)
    _host(db, HOST_WS01_ID, "WS-01")
    _host(db, HOST_WS02_ID, "WS-02")
    _evidence(db, host_id=HOST_WS01_ID)
    client = _client(db)

    # Reassign the evidence onto WS-01 once before the delete, so WS-01 is
    # referenced as assignment_history.new_host_id even before deletion
    # starts moving it elsewhere.
    reassigned = client.patch(f"/api/cases/{CASE_ID}/evidence/{EVIDENCE_ID}/host", json={"host_id": HOST_WS01_ID})
    assert reassigned.status_code == 200
    assert db.query(AssignmentHistory).filter(AssignmentHistory.new_host_id == HOST_WS01_ID).count() >= 1

    response = client.request(
        "DELETE",
        f"/api/cases/{CASE_ID}/hosts/{HOST_WS01_ID}",
        json={"target_host_id": HOST_WS02_ID},
    )

    assert response.status_code == 200
    evidence = db.get(Evidence, EVIDENCE_ID)
    assert evidence.host_id == HOST_WS02_ID
    # The history rows survive deletion; only the pointer to the removed
    # host is cleared, matching the identity-audit detach pattern.
    assert db.query(AssignmentHistory).filter(AssignmentHistory.new_host_id == HOST_WS01_ID).count() == 0
    assert db.query(AssignmentHistory).filter(AssignmentHistory.previous_host_id == HOST_WS01_ID).count() == 0
