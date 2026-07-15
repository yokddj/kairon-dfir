"""Case Deletion v1 — backend coverage.

Exercises DELETE /api/cases/{case_id} (backend/app/api/routes_cases.py) and
the underlying reusable service (backend/app/services/case_deletion.py)
against every case-scoped table, plus the safety gate, rollback behavior,
and storage/OpenSearch cleanup.
"""
from datetime import datetime, timedelta, timezone

from fastapi import FastAPI
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from app.api import routes_cases
from app.core.database import Base, get_db
from app.models.activity import AppActivityEvent
from app.models.artifact import Artifact
from app.models.assignment_history import AssignmentHistory
from app.models.audit_event import AuditEvent
from app.models.case import Case
from app.models.case_access import CaseAccess
from app.models.case_analysis_job import CaseAnalysisJob, CaseAnalysisJobStatus
from app.models.case_host import CaseHost
from app.models.case_host_alias import CaseHostAlias
from app.models.case_host_identity_audit import CaseHostIdentityAudit
from app.models.case_report import CaseReport
from app.models.detection_result import DetectionResult
from app.models.disk_image import DiskImage, DiskVolume, OSInstallation
from app.models.event_marking import EventMarking
from app.models.evidence import Evidence, EvidenceStorageMode, EvidenceType, IngestStatus
from app.models.finding import Finding
from app.models.incident_timeline_draft import IncidentTimelineDraft
from app.models.memory import (
    MemoryAnalysisBatch,
    MemoryArtifactSummary,
    MemoryCachedSymbol,
    MemoryEvidenceSymbolLink,
    MemoryNativeProbe,
    MemoryPluginRun,
    MemoryScanRun,
    MemorySymbolAcquisition,
    MemorySymbolAcquisitionRequest,
    MemorySymbolApproval,
    MemorySymbolPendingAnalysis,
    MemorySymbolPreparation,
    MemorySymbolRecoveryAttempt,
    MemorySymbolRequirement,
    MemoryUpload,
)
from app.models.rule import Rule, RuleEngine
from app.models.rule_run import RuleRun
from app.models.rule_set import RuleSet
from app.models.tag import Tag
from app.models.timeline_bookmark import TimelineBookmark
from app.services import case_deletion


CASE_ID = "aaaaaaaa-1111-4111-8111-aaaaaaaaaaaa"
OTHER_CASE_ID = "9a999999-1111-4111-8111-999999999999"
EVIDENCE_ID = "bbbbbbbb-2222-4222-8222-bbbbbbbbbbbb"
HOST_ID = "cccccccc-3333-4333-8333-ccccccccccc3"


def _db():
    engine = create_engine("sqlite:///:memory:", connect_args={"check_same_thread": False}, poolclass=StaticPool, future=True)
    Base.metadata.create_all(engine)
    return sessionmaker(bind=engine, future=True)()


def _client(db):
    test_app = FastAPI()
    test_app.include_router(routes_cases.router)
    test_app.dependency_overrides[get_db] = lambda: db
    return TestClient(test_app)


def _case(db, *, case_id=CASE_ID, name="Case", status="active"):
    item = Case(id=case_id, name=name, description="", status=status, priority="medium", management_tags=[])
    db.add(item)
    db.commit()
    return item


def _evidence(db, *, evidence_id=EVIDENCE_ID, case_id=CASE_ID, ingest_status=IngestStatus.completed):
    item = Evidence(
        id=evidence_id,
        case_id=case_id,
        original_filename="evidence.zip",
        stored_path="/tmp/evidence.zip",
        storage_mode=EvidenceStorageMode.uploaded,
        is_external=False,
        copy_to_storage=True,
        evidence_type=EvidenceType.velociraptor_zip,
        size_bytes=128,
        ingest_status=ingest_status,
        path_validation={},
        ingest_source={},
        metadata_json={},
        error_log={},
    )
    db.add(item)
    db.commit()
    return item


def _populate_core(db, *, case_id=CASE_ID, evidence_id=EVIDENCE_ID):
    """One row in every directly-case-scoped table that's cheap to construct."""
    db.add(Artifact(id="1a000000-0000-4000-8000-000000000001", case_id=case_id, evidence_id=evidence_id, name="artifact.csv", artifact_type="evtx", source_path="/tmp/artifact.csv", parser="evtxecmd"))
    db.add(Finding(id="1a000000-0000-4000-8000-000000000002", case_id=case_id, title="Suspicious logon"))
    db.add(DetectionResult(id="1a000000-0000-4000-8000-000000000003", case_id=case_id, engine="sigma", rule_name="rule-a"))
    rule_set = RuleSet(id="1a000000-0000-4000-8000-000000000004", case_id=case_id, name="Set", engine=RuleEngine.sigma, content="[]")
    db.add(rule_set)
    rule = Rule(id="1a000000-0000-4000-8000-000000000005", case_id=case_id, name="Rule", engine=RuleEngine.sigma, content="title: x")
    db.add(rule)
    db.add(RuleRun(id="1a000000-0000-4000-8000-000000000006", case_id=case_id, engine="sigma"))
    db.add(Tag(id="1a000000-0000-4000-8000-000000000007", case_id=case_id, name="ctf"))
    db.add(CaseAccess(id="1a000000-0000-4000-8000-000000000008", case_id=case_id, user_id="some-user-id"))
    db.add(AppActivityEvent(id="1a000000-0000-4000-8000-000000000009", case_id=case_id, activity_type="note", title="t", message="m"))
    db.add(EventMarking(id="1a000000-0000-4000-8000-00000000000a", case_id=case_id, evidence_id=evidence_id, event_id="evt-1"))
    db.add(TimelineBookmark(id="1a000000-0000-4000-8000-00000000000b", case_id=case_id, event_id="evt-1", title="Bookmark"))
    db.add(IncidentTimelineDraft(id="1a000000-0000-4000-8000-00000000000c", case_id=case_id, option_key="full", cache_key=f"{case_id}-full", data_fingerprint="fp"))
    db.add(CaseAnalysisJob(id="1a000000-0000-4000-8000-00000000000d", case_id=case_id, status=CaseAnalysisJobStatus.completed))
    db.add(AssignmentHistory(id="1a000000-0000-4000-8000-00000000000e", evidence_id=evidence_id, case_id=case_id))
    db.commit()


def _populate_hosts(db, *, case_id=CASE_ID, host_id=HOST_ID):
    db.add(CaseHost(id=host_id, case_id=case_id, canonical_name="ws01", display_name="WS01"))
    db.add(CaseHostAlias(id="2a000000-0000-4000-8000-000000000001", case_host_id=host_id, case_id=case_id, alias="WS01.local", normalized_alias="ws01.local"))
    db.add(CaseHostIdentityAudit(id="2a000000-0000-4000-8000-000000000002", case_id=case_id, case_host_id=host_id, action="merge"))
    db.commit()


def _populate_reports(db, tmp_path, *, case_id=CASE_ID):
    from app.core.config import get_settings

    settings = get_settings()
    report_id = "3a000000-0000-4000-8000-000000000001"
    db.add(CaseReport(id=report_id, case_id=case_id, title="Investigation Report"))
    db.commit()
    report_dir = settings.backend_data_dir / "reports" / report_id
    report_dir.mkdir(parents=True, exist_ok=True)
    (report_dir / "report.md").write_text("# Report", encoding="utf-8")
    return report_dir


def _populate_disk_image(db, *, evidence_id=EVIDENCE_ID):
    image_id = "4a000000-0000-4000-8000-000000000001"
    volume_id = "4a000000-0000-4000-8000-000000000002"
    db.add(DiskImage(id=image_id, evidence_id=evidence_id, original_filename="disk.E01", format="ewf"))
    db.add(DiskVolume(id=volume_id, disk_image_id=image_id, partition_index=0))
    db.add(OSInstallation(id="4a000000-0000-4000-8000-000000000003", disk_volume_id=volume_id, platform="windows"))
    db.commit()


def _populate_memory(db, *, case_id=CASE_ID, evidence_id=EVIDENCE_ID, batch_status="completed"):
    db.add(MemoryUpload(
        id="5a000000-0000-4000-8000-000000000001", case_id=case_id, evidence_id=evidence_id, expected_bytes=1024,
        display_name="mem.raw", source_host="ws01", extension="raw", staging_name="stg.raw", canonical_relative_path="mem/stg.raw",
    ))
    scan_run_id = "5a000000-0000-4000-8000-000000000002"
    db.add(MemoryScanRun(id=scan_run_id, case_id=case_id, evidence_id=evidence_id))
    db.add(MemoryPluginRun(id="5a000000-0000-4000-8000-000000000003", memory_scan_run_id=scan_run_id, case_id=case_id, evidence_id=evidence_id, plugin="windows.pslist"))
    db.add(MemoryArtifactSummary(id="5a000000-0000-4000-8000-000000000004", case_id=case_id, evidence_id=evidence_id, memory_artifact_type="process"))
    requirement_id = "5a000000-0000-4000-8000-000000000005"
    db.add(MemorySymbolRequirement(
        id=requirement_id, case_id=case_id, evidence_id=evidence_id, pdb_name="ntkrnlmp.pdb", pdb_guid="ABC123",
        pdb_age=1, architecture="x64", symbol_key="ntkrnlmp.pdb-ABC123-1",
    ))
    db.add(MemoryEvidenceSymbolLink(id="5a000000-0000-4000-8000-000000000006", case_id=case_id, evidence_id=evidence_id, requirement_id=requirement_id))
    db.add(MemorySymbolPreparation(id="5a000000-0000-4000-8000-000000000007", case_id=case_id, evidence_id=evidence_id))
    db.add(MemorySymbolPendingAnalysis(id="5a000000-0000-4000-8000-000000000008", case_id=case_id, evidence_id=evidence_id, kind="single_profile"))
    db.add(MemorySymbolAcquisition(id="5a000000-0000-4000-8000-000000000009", requirement_id=requirement_id))
    acquisition_request_id = "5a000000-0000-4000-8000-00000000000a"
    db.add(MemorySymbolAcquisitionRequest(
        id=acquisition_request_id, requirement_id=requirement_id, case_id=case_id, evidence_id=evidence_id,
        requirement_fingerprint="fp-1",
    ))
    db.add(MemorySymbolApproval(
        id="5a000000-0000-4000-8000-00000000000b", request_id=acquisition_request_id, requirement_fingerprint="fp-1",
        expires_at=datetime.now(timezone.utc).replace(tzinfo=None) + timedelta(hours=1),
    ))
    db.add(MemoryAnalysisBatch(id="5a000000-0000-4000-8000-00000000000c", case_id=case_id, evidence_id=evidence_id, status=batch_status))
    db.add(MemorySymbolRecoveryAttempt(
        id="5a000000-0000-4000-8000-00000000000d", requirement_id=requirement_id, case_id=case_id, evidence_id=evidence_id,
        source_type="microsoft_public", source_label="Microsoft public", status="pending",
    ))
    db.add(MemoryNativeProbe(id="5a000000-0000-4000-8000-00000000000e", case_id=case_id, evidence_id=evidence_id, requirement_id=requirement_id))
    db.commit()


# ---------------------------------------------------------------------------
# Deletion scope
# ---------------------------------------------------------------------------

def test_delete_empty_case(monkeypatch):
    monkeypatch.setattr(case_deletion, "delete_case_index", lambda case_id: True)
    monkeypatch.setattr(case_deletion, "delete_case_memory_indices", lambda case_id: {"memory": True, "memory_experimental": True})
    db = _db()
    _case(db)
    client = _client(db)

    response = client.delete(f"/api/cases/{CASE_ID}")

    assert response.status_code == 200
    payload = response.json()
    assert payload["status"] == "deleted"
    assert payload["case_id"] == CASE_ID
    assert db.get(Case, CASE_ID) is None


def test_delete_populated_case_removes_core_tables(monkeypatch):
    monkeypatch.setattr(case_deletion, "delete_case_index", lambda case_id: True)
    monkeypatch.setattr(case_deletion, "delete_case_memory_indices", lambda case_id: {"memory": True, "memory_experimental": True})
    db = _db()
    _case(db)
    _evidence(db)
    _populate_core(db)
    client = _client(db)

    response = client.delete(f"/api/cases/{CASE_ID}")

    assert response.status_code == 200
    assert db.get(Case, CASE_ID) is None
    for model in (Artifact, Finding, DetectionResult, RuleSet, Rule, RuleRun, Tag, CaseAccess,
                  AppActivityEvent, EventMarking, TimelineBookmark, IncidentTimelineDraft,
                  CaseAnalysisJob, AssignmentHistory):
        assert db.query(model).filter(model.case_id == CASE_ID).count() == 0, f"orphan rows in {model.__tablename__}"


def test_delete_case_with_hosts_removes_hosts_aliases_and_audit(monkeypatch):
    monkeypatch.setattr(case_deletion, "delete_case_index", lambda case_id: True)
    monkeypatch.setattr(case_deletion, "delete_case_memory_indices", lambda case_id: {"memory": True, "memory_experimental": True})
    db = _db()
    _case(db)
    _populate_hosts(db)
    client = _client(db)

    response = client.delete(f"/api/cases/{CASE_ID}")

    assert response.status_code == 200
    assert db.query(CaseHost).filter(CaseHost.case_id == CASE_ID).count() == 0
    assert db.query(CaseHostAlias).filter(CaseHostAlias.case_id == CASE_ID).count() == 0
    assert db.query(CaseHostIdentityAudit).filter(CaseHostIdentityAudit.case_id == CASE_ID).count() == 0


def test_delete_case_with_evidence_and_disk_images(monkeypatch):
    monkeypatch.setattr(case_deletion, "delete_case_index", lambda case_id: True)
    monkeypatch.setattr(case_deletion, "delete_case_memory_indices", lambda case_id: {"memory": True, "memory_experimental": True})
    db = _db()
    _case(db)
    _evidence(db)
    _populate_disk_image(db)
    client = _client(db)

    response = client.delete(f"/api/cases/{CASE_ID}")

    assert response.status_code == 200
    assert db.get(Evidence, EVIDENCE_ID) is None
    assert db.query(DiskImage).count() == 0
    assert db.query(DiskVolume).count() == 0
    assert db.query(OSInstallation).count() == 0


def test_delete_case_with_memory_removes_case_scoped_memory_but_keeps_global_cache(monkeypatch):
    monkeypatch.setattr(case_deletion, "delete_case_index", lambda case_id: True)
    monkeypatch.setattr(case_deletion, "delete_case_memory_indices", lambda case_id: {"memory": True, "memory_experimental": True})
    db = _db()
    _case(db)
    _evidence(db)
    _populate_memory(db)
    cached_symbol = MemoryCachedSymbol(
        id="6a000000-0000-4000-8000-000000000001", symbol_key="global-key", pdb_name="ntkrnlmp.pdb", pdb_guid="ABC123",
        pdb_age=1, architecture="x64", pdb_relative_path="p", isf_relative_path="i", pdb_sha256="a" * 64, isf_sha256="b" * 64,
        pdb_size_bytes=1, isf_size_bytes=1,
    )
    db.add(cached_symbol)
    db.commit()
    client = _client(db)

    response = client.delete(f"/api/cases/{CASE_ID}")

    assert response.status_code == 200
    for model in (MemoryUpload, MemoryScanRun, MemoryPluginRun, MemoryArtifactSummary, MemoryEvidenceSymbolLink,
                  MemorySymbolPreparation, MemorySymbolPendingAnalysis, MemorySymbolRequirement,
                  MemorySymbolAcquisitionRequest, MemoryAnalysisBatch, MemoryNativeProbe):
        assert db.query(model).filter(model.case_id == CASE_ID).count() == 0, f"orphan rows in {model.__tablename__}"
    assert db.query(MemorySymbolAcquisition).count() == 0
    assert db.query(MemorySymbolApproval).count() == 0
    assert db.query(MemorySymbolRecoveryAttempt).count() == 0
    # The global symbol cache is never touched by case deletion.
    assert db.get(MemoryCachedSymbol, cached_symbol.id) is not None


def test_delete_case_with_findings(monkeypatch):
    monkeypatch.setattr(case_deletion, "delete_case_index", lambda case_id: True)
    monkeypatch.setattr(case_deletion, "delete_case_memory_indices", lambda case_id: {"memory": True, "memory_experimental": True})
    db = _db()
    _case(db)
    db.add(Finding(id="7a000000-0000-4000-8000-000000000001", case_id=CASE_ID, title="Lateral movement"))
    db.commit()
    client = _client(db)

    response = client.delete(f"/api/cases/{CASE_ID}")

    assert response.status_code == 200
    assert db.query(Finding).filter(Finding.case_id == CASE_ID).count() == 0


def test_delete_case_with_reports_removes_db_row_and_files(monkeypatch, tmp_path):
    from app.core.config import get_settings

    monkeypatch.setattr(case_deletion, "delete_case_index", lambda case_id: True)
    monkeypatch.setattr(case_deletion, "delete_case_memory_indices", lambda case_id: {"memory": True, "memory_experimental": True})
    settings = get_settings()
    monkeypatch.setattr(settings, "backend_data_dir", tmp_path)
    db = _db()
    _case(db)
    report_dir = _populate_reports(db, tmp_path)
    assert report_dir.exists()
    client = _client(db)

    response = client.delete(f"/api/cases/{CASE_ID}")

    assert response.status_code == 200
    payload = response.json()
    assert payload["cleanup"]["reports_removed"] == 1
    assert db.query(CaseReport).filter(CaseReport.case_id == CASE_ID).count() == 0
    assert not report_dir.exists(), "report directory must be removed, not just the DB row"


def test_delete_case_with_staged_upload_session_removes_row_and_staged_file(monkeypatch, tmp_path):
    from app.core.config import get_settings
    from app.models.evidence_upload_session import EvidenceUploadSession

    monkeypatch.setattr(case_deletion, "delete_case_index", lambda case_id: True)
    monkeypatch.setattr(case_deletion, "delete_case_memory_indices", lambda case_id: {"memory": True, "memory_experimental": True})
    settings = get_settings()
    monkeypatch.setattr(settings, "backend_data_dir", tmp_path)
    db = _db()
    _case(db)
    staged_dir = tmp_path / "evidence-upload-sessions" / "session-1"
    staged_dir.mkdir(parents=True)
    staged_file = staged_dir / "collection.zip"
    staged_file.write_bytes(b"fake zip bytes")
    from datetime import datetime, timedelta, timezone
    db.add(EvidenceUploadSession(
        id="90000000-0000-4000-8000-000000000099", case_id=CASE_ID, status="staged",
        original_filename="collection.zip", staged_path=str(staged_file), is_folder=False, is_server_path=False,
        size_bytes=14, sha256="a" * 64, expires_at=datetime.now(timezone.utc) + timedelta(hours=1),
    ))
    db.commit()
    assert staged_file.exists()
    client = _client(db)

    response = client.delete(f"/api/cases/{CASE_ID}")

    assert response.status_code == 200
    assert db.query(EvidenceUploadSession).filter(EvidenceUploadSession.case_id == CASE_ID).count() == 0
    assert not staged_file.exists(), "staged upload bytes must be cleaned up, not just the DB row"


def test_delete_case_with_artifacts(monkeypatch):
    monkeypatch.setattr(case_deletion, "delete_case_index", lambda case_id: True)
    monkeypatch.setattr(case_deletion, "delete_case_memory_indices", lambda case_id: {"memory": True, "memory_experimental": True})
    db = _db()
    _case(db)
    _evidence(db)
    db.add(Artifact(id="8a000000-0000-4000-8000-000000000001", case_id=CASE_ID, evidence_id=EVIDENCE_ID, name="a.csv", artifact_type="evtx", source_path="/tmp/a.csv", parser="evtxecmd"))
    db.commit()
    client = _client(db)

    response = client.delete(f"/api/cases/{CASE_ID}")

    assert response.status_code == 200
    assert db.query(Artifact).filter(Artifact.case_id == CASE_ID).count() == 0


def test_delete_case_with_search_documents_deletes_all_three_index_patterns(monkeypatch):
    deleted_indices = []
    monkeypatch.setattr(case_deletion, "delete_case_index", lambda case_id: deleted_indices.append(("events", case_id)) or True)
    monkeypatch.setattr(
        case_deletion,
        "delete_case_memory_indices",
        lambda case_id: (deleted_indices.append(("memory", case_id)) or deleted_indices.append(("memory_experimental", case_id)) or {"memory": True, "memory_experimental": True}),
    )
    db = _db()
    _case(db)
    client = _client(db)

    response = client.delete(f"/api/cases/{CASE_ID}")

    assert response.status_code == 200
    payload = response.json()
    assert payload["cleanup"]["index_deleted"] == {"events": True, "memory": True, "memory_experimental": True}
    assert ("events", CASE_ID) in deleted_indices
    assert ("memory", CASE_ID) in deleted_indices
    assert ("memory_experimental", CASE_ID) in deleted_indices


# ---------------------------------------------------------------------------
# Safety and transactional behavior
# ---------------------------------------------------------------------------

def test_delete_blocked_while_evidence_processing(monkeypatch):
    monkeypatch.setattr(case_deletion, "delete_case_index", lambda case_id: True)
    monkeypatch.setattr(case_deletion, "delete_case_memory_indices", lambda case_id: {"memory": True, "memory_experimental": True})
    db = _db()
    _case(db)
    _evidence(db, ingest_status=IngestStatus.processing)
    client = _client(db)

    response = client.delete(f"/api/cases/{CASE_ID}")

    assert response.status_code == 409
    assert response.json()["detail"] == "Case cannot be deleted while processing is active."
    assert db.get(Case, CASE_ID) is not None


def test_delete_blocked_while_case_analysis_job_running(monkeypatch):
    monkeypatch.setattr(case_deletion, "delete_case_index", lambda case_id: True)
    monkeypatch.setattr(case_deletion, "delete_case_memory_indices", lambda case_id: {"memory": True, "memory_experimental": True})
    db = _db()
    _case(db)
    db.add(CaseAnalysisJob(id="9a000000-0000-4000-8000-000000000001", case_id=CASE_ID, status=CaseAnalysisJobStatus.running))
    db.commit()
    client = _client(db)

    response = client.delete(f"/api/cases/{CASE_ID}")

    assert response.status_code == 409
    assert db.get(Case, CASE_ID) is not None


def test_delete_blocked_while_memory_batch_running(monkeypatch):
    monkeypatch.setattr(case_deletion, "delete_case_index", lambda case_id: True)
    monkeypatch.setattr(case_deletion, "delete_case_memory_indices", lambda case_id: {"memory": True, "memory_experimental": True})
    db = _db()
    _case(db)
    _evidence(db)
    db.add(MemoryAnalysisBatch(id="9a000000-0000-4000-8000-000000000002", case_id=CASE_ID, evidence_id=EVIDENCE_ID, status="running"))
    db.commit()
    client = _client(db)

    response = client.delete(f"/api/cases/{CASE_ID}")

    assert response.status_code == 409
    assert db.get(Case, CASE_ID) is not None


def test_delete_not_blocked_by_completed_or_failed_activity(monkeypatch):
    monkeypatch.setattr(case_deletion, "delete_case_index", lambda case_id: True)
    monkeypatch.setattr(case_deletion, "delete_case_memory_indices", lambda case_id: {"memory": True, "memory_experimental": True})
    db = _db()
    _case(db)
    _evidence(db, ingest_status=IngestStatus.failed)
    db.add(CaseAnalysisJob(id="9a000000-0000-4000-8000-000000000003", case_id=CASE_ID, status=CaseAnalysisJobStatus.failed))
    db.add(MemoryAnalysisBatch(id="9a000000-0000-4000-8000-000000000004", case_id=CASE_ID, evidence_id=EVIDENCE_ID, status="failed"))
    db.commit()
    client = _client(db)

    response = client.delete(f"/api/cases/{CASE_ID}")

    assert response.status_code == 200
    assert db.get(Case, CASE_ID) is None


def test_delete_missing_case_returns_404():
    db = _db()
    client = _client(db)

    response = client.delete(f"/api/cases/{CASE_ID}")

    assert response.status_code == 404


def test_rollback_on_failure_leaves_case_and_children_intact(monkeypatch):
    db = _db()
    _case(db)
    _evidence(db)
    _populate_core(db)

    def failing_commit():
        raise case_deletion.SQLAlchemyError("simulated commit failure")

    monkeypatch.setattr(db, "commit", failing_commit)
    client = _client(db)

    response = client.delete(f"/api/cases/{CASE_ID}")

    assert response.status_code == 500
    assert db.get(Case, CASE_ID) is not None
    assert db.get(Evidence, EVIDENCE_ID) is not None
    assert db.query(Artifact).filter(Artifact.case_id == CASE_ID).count() == 1


def test_audit_trail_survives_case_deletion(monkeypatch):
    """AuditEvent rows are the security/access audit log, not investigation
    data, and are deliberately NOT deleted so the record of the deletion
    itself (and everything else done on the case) remains intact."""
    monkeypatch.setattr(case_deletion, "delete_case_index", lambda case_id: True)
    monkeypatch.setattr(case_deletion, "delete_case_memory_indices", lambda case_id: {"memory": True, "memory_experimental": True})
    db = _db()
    _case(db)
    db.add(AuditEvent(id="a0000000-0000-4000-8000-000000000001", action="case_viewed", case_id=CASE_ID))
    db.commit()
    client = _client(db)

    response = client.delete(f"/api/cases/{CASE_ID}")

    assert response.status_code == 200
    assert db.query(AuditEvent).filter(AuditEvent.case_id == CASE_ID).count() == 1


def test_other_cases_are_not_affected(monkeypatch):
    monkeypatch.setattr(case_deletion, "delete_case_index", lambda case_id: True)
    monkeypatch.setattr(case_deletion, "delete_case_memory_indices", lambda case_id: {"memory": True, "memory_experimental": True})
    db = _db()
    _case(db)
    _case(db, case_id=OTHER_CASE_ID, name="Other")
    db.add(Finding(id="b0000000-0000-4000-8000-000000000001", case_id=OTHER_CASE_ID, title="Untouched"))
    db.commit()
    client = _client(db)

    response = client.delete(f"/api/cases/{CASE_ID}")

    assert response.status_code == 200
    assert db.get(Case, OTHER_CASE_ID) is not None
    assert db.query(Finding).filter(Finding.case_id == OTHER_CASE_ID).count() == 1


def test_no_orphan_rows_across_every_case_scoped_table(monkeypatch, tmp_path):
    """Kitchen-sink coverage: populate every category from the deletion scope
    (hosts, evidence, disk images, memory, findings, reports, artifacts,
    rules/detections, timeline, activity) and assert zero rows remain
    anywhere that references the deleted case_id."""
    from app.core.config import get_settings

    monkeypatch.setattr(case_deletion, "delete_case_index", lambda case_id: True)
    monkeypatch.setattr(case_deletion, "delete_case_memory_indices", lambda case_id: {"memory": True, "memory_experimental": True})
    settings = get_settings()
    monkeypatch.setattr(settings, "backend_data_dir", tmp_path)

    db = _db()
    _case(db)
    _evidence(db)
    _populate_core(db)
    _populate_hosts(db)
    _populate_disk_image(db)
    _populate_memory(db)
    report_dir = _populate_reports(db, tmp_path)
    client = _client(db)

    response = client.delete(f"/api/cases/{CASE_ID}")

    assert response.status_code == 200
    assert db.get(Case, CASE_ID) is None
    assert not report_dir.exists()

    case_scoped_models = [
        Artifact, Finding, DetectionResult, RuleSet, Rule, RuleRun, Tag, CaseAccess,
        AppActivityEvent, EventMarking, TimelineBookmark, IncidentTimelineDraft, CaseAnalysisJob,
        AssignmentHistory, CaseHost, CaseHostAlias, CaseHostIdentityAudit, CaseReport,
        MemoryUpload, MemoryScanRun, MemoryPluginRun, MemoryArtifactSummary, MemoryEvidenceSymbolLink,
        MemorySymbolPreparation, MemorySymbolPendingAnalysis, MemorySymbolRequirement,
        MemorySymbolAcquisitionRequest, MemoryAnalysisBatch, MemoryNativeProbe,
    ]
    for model in case_scoped_models:
        assert db.query(model).filter(model.case_id == CASE_ID).count() == 0, f"orphan rows in {model.__tablename__}"

    assert db.query(Evidence).filter(Evidence.case_id == CASE_ID).count() == 0
    assert db.query(DiskImage).count() == 0
    assert db.query(DiskVolume).count() == 0
    assert db.query(OSInstallation).count() == 0
    assert db.query(MemorySymbolAcquisition).count() == 0
    assert db.query(MemorySymbolApproval).count() == 0
    assert db.query(MemorySymbolRecoveryAttempt).count() == 0
