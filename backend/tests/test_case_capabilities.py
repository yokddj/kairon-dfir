from fastapi import FastAPI
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from app.api import routes_cases
from app.core.database import Base, get_db
from app.models.artifact import Artifact
from app.models.case import Case
from app.models.case_host import CaseHost
from app.models.evidence import Evidence, EvidenceStorageMode, EvidenceType, IngestStatus
from app.models.memory import MemoryArtifactSummary, MemoryPluginRun, MemoryScanRun


CASE_ID = "aaaaaaaa-1111-4111-8111-aaaaaaaaaaaa"
HOST_ID = "bbbbbbbb-2222-4222-8222-bbbbbbbbbbbb"
LINUX_EVIDENCE_ID = "cccccccc-3333-4333-8333-cccccccccccc"
MEMORY_EVIDENCE_ID = "dddddddd-4444-4444-8444-dddddddddddd"


def _db():
    engine = create_engine("sqlite:///:memory:", connect_args={"check_same_thread": False}, poolclass=StaticPool, future=True)
    Base.metadata.create_all(engine)
    return sessionmaker(bind=engine, future=True)()


def _client(db):
    app = FastAPI()
    app.include_router(routes_cases.router)
    app.dependency_overrides[get_db] = lambda: db
    return TestClient(app)


def _case(db):
    db.add(Case(id=CASE_ID, name="Capability Case", description=None))
    db.add(CaseHost(id=HOST_ID, case_id=CASE_ID, canonical_name="web-01", display_name="WEB-01", confidence="manual", source="manual"))
    db.commit()


def _evidence(db, evidence_id, filename, evidence_type, platform, *, metadata=None):
    item = Evidence(
        id=evidence_id,
        case_id=CASE_ID,
        original_filename=filename,
        stored_path=f"/tmp/{filename}",
        original_path=f"/tmp/{filename}",
        storage_mode=EvidenceStorageMode.uploaded,
        is_external=False,
        copy_to_storage=True,
        evidence_type=evidence_type,
        sha256="0" * 64,
        size_bytes=128,
        ingest_status=IngestStatus.completed,
        provided_platform="auto",
        detected_platform=platform,
        effective_platform=platform,
        detected_host="WEB-01",
        host_id=HOST_ID,
        path_validation={},
        ingest_source={},
        metadata_json=metadata or {},
        error_log={},
    )
    db.add(item)
    db.commit()
    return item


def test_case_capabilities_exposes_linux_scope_and_counts():
    db = _db()
    _case(db)
    _evidence(db, LINUX_EVIDENCE_ID, "triage.tgz", EvidenceType.linux_triage, "linux")
    db.add(Artifact(case_id=CASE_ID, evidence_id=LINUX_EVIDENCE_ID, name="auth.log", artifact_type="linux_auth", source_path="/var/log/auth.log", parser="linux_auth", record_count=42, status="parsed"))
    db.commit()

    response = _client(db).get(f"/api/cases/{CASE_ID}/capabilities")

    assert response.status_code == 200
    body = response.json()
    assert body["registry_version"]
    assert body["platforms"] == [{"id": "linux", "label": "Linux", "evidence_count": 1, "shipped": True}]
    linux_auth = next(item for item in body["capabilities"] if item["id"] == "linux.access.authentication")
    assert linux_auth["readiness"] == "has_data"
    assert linux_auth["visible"] is True
    assert linux_auth["record_count"] == 42
    windows_command_history = next(item for item in body["capabilities"] if item["id"] == "windows.execution.command_history")
    assert windows_command_history["visible"] is False
    assert windows_command_history["readiness"] == "not_applicable"


def test_case_capabilities_separates_memory_domain_from_os_platform():
    db = _db()
    _case(db)
    _evidence(db, MEMORY_EVIDENCE_ID, "mem.raw", EvidenceType.memory_dump, "memory", metadata={"probable_os": "windows"})
    run = MemoryScanRun(id="eeeeeeee-5555-4555-8555-eeeeeeeeeeee", case_id=CASE_ID, evidence_id=MEMORY_EVIDENCE_ID, status="completed", profile="quick")
    db.add(run)
    db.add(MemoryPluginRun(memory_scan_run_id=run.id, case_id=CASE_ID, evidence_id=MEMORY_EVIDENCE_ID, plugin="windows.pslist", status="completed", row_count=8))
    db.add(MemoryArtifactSummary(case_id=CASE_ID, evidence_id=MEMORY_EVIDENCE_ID, memory_run_id=run.id, memory_artifact_type="processes", count=8, metadata_json={}))
    db.commit()

    response = _client(db).get(f"/api/cases/{CASE_ID}/capabilities")

    assert response.status_code == 200
    body = response.json()
    assert body["platforms"] == [{"id": "windows", "label": "Windows", "evidence_count": 1, "shipped": True}]
    assert body["evidence_domains"] == [{"id": "memory", "label": "Memory", "evidence_count": 1}]
    assert body["evidence"][0]["legacy_effective_platform"] == "memory"
    assert body["evidence"][0]["platform"] == "windows"
    assert body["evidence"][0]["evidence_domain"] == "memory"
    memory_processes = next(item for item in body["capabilities"] if item["id"] == "memory.processes")
    assert memory_processes["visible"] is True
    assert memory_processes["readiness"] == "has_data"
    assert memory_processes["record_count"] == 8


def test_case_capabilities_returns_404_for_unknown_case():
    db = _db()

    response = _client(db).get("/api/cases/ffffffff-1111-4111-8111-ffffffffffff/capabilities")

    assert response.status_code == 404
