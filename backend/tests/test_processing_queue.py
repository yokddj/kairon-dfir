from datetime import datetime, timedelta

from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import Session, sessionmaker

from app.core.database import Base
from app.main import app, settings
from app.models.artifact import Artifact
from app.models.case import Case
from app.models.evidence import Evidence, EvidenceStorageMode, EvidenceType, IngestStatus
from app.models.memory import MemoryPluginRun, MemoryScanRun
from app.services.processing_queue import get_evidence_processing, get_evidence_processing_run, list_case_processing

CASE_ID = "aaaaaaaa-1111-4111-8111-aaaaaaaaaaaa"
EVIDENCE_ID = "bbbbbbbb-2222-4222-8222-bbbbbbbbbbbb"
SECOND_EVIDENCE_ID = "cccccccc-3333-4333-8333-cccccccccccc"


def _db() -> Session:
    engine = create_engine("sqlite:///:memory:", future=True)
    Base.metadata.create_all(engine)
    return sessionmaker(bind=engine, future=True)()


def _case(db: Session) -> Case:
    case = Case(id=CASE_ID, name="Queue Case", description=None)
    db.add(case)
    db.commit()
    return case


def _evidence(db: Session, *, evidence_id: str = EVIDENCE_ID, filename: str = "triage.zip", status: IngestStatus = IngestStatus.pending, metadata: dict | None = None, error_log: dict | None = None, evidence_type: EvidenceType = EvidenceType.velociraptor_zip) -> Evidence:
    evidence = Evidence(
        id=evidence_id,
        case_id=CASE_ID,
        original_filename=filename,
        stored_path="/internal/storage/triage.zip",
        original_path="/internal/source/triage.zip",
        storage_mode=EvidenceStorageMode.uploaded,
        is_external=False,
        copy_to_storage=True,
        evidence_type=evidence_type,
        sha256="0" * 64,
        size_bytes=128,
        ingest_status=status,
        detected_host="WS-01",
        path_validation={},
        ingest_source={},
        metadata_json=metadata or {},
        error_log=error_log or {},
    )
    db.add(evidence)
    db.commit()
    db.refresh(evidence)
    return evidence


def test_list_processing_status_of_case_with_multiple_evidences():
    db = _db()
    _case(db)
    _evidence(db, status=IngestStatus.completed, metadata={"ingest_runs": [{"run_id": "run-ok", "run_type": "ingest", "status": "completed", "started_at": "2026-01-01T00:00:00", "finished_at": "2026-01-01T00:01:00", "selected_by_parser": {"evtx": 1}}]})
    _evidence(db, evidence_id=SECOND_EVIDENCE_ID, filename="memory.raw", status=IngestStatus.processing, evidence_type=EvidenceType.memory_dump, metadata={"provided_host": "WS-02", "ingest_runs": [{"run_id": "run-active", "run_type": "ingest", "status": "running", "started_at": "2026-01-01T00:02:00"}]})
    db.add(Artifact(case_id=CASE_ID, evidence_id=EVIDENCE_ID, name="Security.evtx", artifact_type="windows_event", source_path="/internal/Security.evtx", parser="evtx", record_count=10, status="parsed"))
    db.commit()

    result = list_case_processing(db, CASE_ID)

    assert len(result["items"]) == 2
    assert result["summary"]["completed"] == 1
    assert result["summary"]["running"] == 1
    assert {item["host"] for item in result["items"]} == {"WS-01", "WS-02"}


def test_list_runs_of_evidence():
    db = _db()
    _case(db)
    _evidence(db, status=IngestStatus.completed, metadata={"ingest_runs": [{"run_id": "run-1", "run_type": "ingest", "status": "completed", "started_at": "2026-01-01T00:00:00", "finished_at": "2026-01-01T00:00:05"}]})

    result = get_evidence_processing(db, CASE_ID, EVIDENCE_ID)

    assert result is not None
    assert result["runs"][0]["run_id"] == "run-1"
    assert get_evidence_processing_run(db, CASE_ID, EVIDENCE_ID, "run-1")["duration"] == 5


def test_evidence_without_runs_returns_clear_pending_state():
    db = _db()
    _case(db)
    _evidence(db)

    result = get_evidence_processing(db, CASE_ID, EVIDENCE_ID)

    assert result is not None
    assert result["processing_status"] == "pending"
    assert result["runs"] == []
    assert result["last_error"] is None


def test_failed_run_shows_sanitized_error():
    db = _db()
    _case(db)
    _evidence(
        db,
        status=IngestStatus.failed,
        metadata={"ingest_runs": [{"run_id": "run-failed", "run_type": "ingest", "status": "failed", "last_error": "Parser failed at /root/kairon/private.evtx"}]},
        error_log={"errors": [{"parser": "evtx", "error": "Cannot parse /root/kairon/private.evtx", "source_path": "/root/kairon/private.evtx"}]},
    )

    result = get_evidence_processing(db, CASE_ID, EVIDENCE_ID)

    assert result is not None
    assert result["processing_status"] == "failed"
    assert result["failed_parser_count"] == 1
    assert "private.evtx" not in str(result)
    assert "source_path" not in str(result)


def test_partial_runs_show_warnings():
    db = _db()
    _case(db)
    _evidence(db, status=IngestStatus.completed_with_errors, metadata={"warnings": ["slow parser"], "ingest_runs": [{"run_id": "run-warn", "run_type": "ingest", "status": "completed_with_errors", "warnings": ["slow parser"], "artifacts_failed": 1}]}, error_log={"errors": [{"parser": "mft", "error": "timeout"}]})
    db.add(Artifact(case_id=CASE_ID, evidence_id=EVIDENCE_ID, name="Amcache", artifact_type="amcache", source_path="/internal/Amcache.hve", parser="amcache", record_count=3, status="parsed"))
    db.commit()

    result = get_evidence_processing(db, CASE_ID, EVIDENCE_ID)

    assert result is not None
    assert result["processing_status"] == "completed_with_warnings"
    assert result["warning_count"] >= 1
    assert result["successful_parser_count"] == 1
    assert result["failed_parser_count"] == 1


def test_memory_runs_are_reported_as_parser_level_status():
    db = _db()
    _case(db)
    _evidence(db, status=IngestStatus.completed, evidence_type=EvidenceType.memory_dump)
    now = datetime.utcnow()
    run = MemoryScanRun(id="dddddddd-4444-4444-8444-dddddddddddd", case_id=CASE_ID, evidence_id=EVIDENCE_ID, profile="metadata_only", status="completed_with_errors", started_at=now, completed_at=now + timedelta(seconds=4), duration_ms=4000, error_log={})
    db.add(run)
    db.add(MemoryPluginRun(case_id=CASE_ID, evidence_id=EVIDENCE_ID, memory_scan_run_id=run.id, plugin="windows.pslist", status="completed", row_count=12))
    db.add(MemoryPluginRun(case_id=CASE_ID, evidence_id=EVIDENCE_ID, memory_scan_run_id=run.id, plugin="windows.dlllist", status="failed", error_message="Volatility parser failed at /tmp/output.json"))
    db.commit()

    result = get_evidence_processing(db, CASE_ID, EVIDENCE_ID)

    assert result is not None
    assert result["processing_status"] == "completed_with_warnings"
    assert result["artifact_count"] == 12
    assert "windows.dlllist" in str(result["parser_runs"])
    assert "/tmp/output.json" not in str(result)


def test_missing_evidence_returns_none():
    db = _db()
    _case(db)

    assert get_evidence_processing(db, CASE_ID, EVIDENCE_ID) is None


def test_unauthenticated_user_cannot_access_processing_endpoint(monkeypatch):
    monkeypatch.setattr(settings, "auth_enabled", True)
    response = TestClient(app).get(f"/api/cases/{CASE_ID}/processing")
    monkeypatch.setattr(settings, "auth_enabled", False)

    assert response.status_code == 401
