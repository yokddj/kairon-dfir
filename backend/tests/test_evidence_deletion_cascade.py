"""Reproduces the bug where DELETE /api/evidences/{id} left an orphaned
Evidence row behind: OpenSearch events and on-disk files were already deleted
by the time db.delete(item) hit a ForeignKeyViolation from assignment_history
rows referencing the evidence without ON DELETE CASCADE.

SQLite does not enforce foreign keys unless PRAGMA foreign_keys=ON is set on
each connection, so it's enabled explicitly here to faithfully reproduce the
Postgres constraint behavior this fix targets.
"""
from sqlalchemy import create_engine, event
from sqlalchemy.orm import sessionmaker

from app.api.routes_evidence import delete_evidence
from app.core.database import Base
from app.models.assignment_history import AssignmentHistory
from app.models.case import Case, CaseStatus
from app.models.evidence import Evidence, EvidenceStorageMode, EvidenceType, IngestStatus


def _make_db():
    engine = create_engine("sqlite:///:memory:", future=True)

    @event.listens_for(engine, "connect")
    def _enable_fk(dbapi_connection, _record):
        cursor = dbapi_connection.cursor()
        cursor.execute("PRAGMA foreign_keys=ON")
        cursor.close()

    Base.metadata.create_all(bind=engine)
    Session = sessionmaker(bind=engine, autoflush=False, autocommit=False, expire_on_commit=False, future=True)
    return Session()


def test_delete_evidence_cascades_assignment_history(monkeypatch):
    db = _make_db()
    case = Case(id="11111111-1111-4111-a111-111111111111", name="Deletion cascade", status=CaseStatus.open)
    evidence = Evidence(
        id="22222222-2222-4222-a222-222222222222",
        case_id=case.id,
        original_filename="host-assigned.zip",
        stored_path="/tmp/host-assigned.zip",
        original_path="/tmp/host-assigned.zip",
        evidence_type=EvidenceType.velociraptor_zip,
        sha256="abc",
        size_bytes=1,
        file_count=1,
        ingest_status=IngestStatus.completed,
        storage_mode=EvidenceStorageMode.uploaded,
        metadata_json={},
        error_log={},
    )
    db.add(case)
    db.add(evidence)
    db.commit()
    db.add(
        AssignmentHistory(
            id="33333333-3333-4333-a333-333333333333",
            evidence_id=evidence.id,
            case_id=case.id,
            new_status="assigned",
            method="manual",
            actor="analyst",
        )
    )
    db.commit()

    monkeypatch.setattr("app.api.routes_evidence.delete_events_by_evidence", lambda *_args, **_kwargs: None)
    monkeypatch.setattr("app.api.routes_evidence.safe_remove", lambda *_args, **_kwargs: None)
    monkeypatch.setattr("app.api.routes_evidence.evidence_manifest_path", lambda *_args, **_kwargs: __import__("pathlib").Path("/tmp/does-not-exist"))
    monkeypatch.setattr("app.api.routes_evidence.log_activity", lambda *_args, **_kwargs: None)

    delete_evidence(evidence.id, db=db)

    assert db.get(Evidence, evidence.id) is None
    assert db.query(AssignmentHistory).filter(AssignmentHistory.evidence_id == evidence.id).count() == 0
