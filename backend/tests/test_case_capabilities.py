from pathlib import Path

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
from app.services.case_capabilities import CAPABILITY_REGISTRY


CASE_ID = "aaaaaaaa-1111-4111-8111-aaaaaaaaaaaa"
HOST_ID = "bbbbbbbb-2222-4222-8222-bbbbbbbbbbbb"
LINUX_EVIDENCE_ID = "cccccccc-3333-4333-8333-cccccccccccc"
MEMORY_EVIDENCE_ID = "dddddddd-4444-4444-8444-dddddddddddd"
APP_TSX = Path(__file__).resolve().parents[2] / "frontend" / "src" / "App.tsx"


def _route_path(route: str) -> str:
    return route.split("?", 1)[0]


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
    assert linux_auth["route"] == "/cases/:caseId/l/access/authentication"
    assert linux_auth["overview"]["featured"] is True
    linux = next(item for item in body["workbenches"] if item["id"] == "linux")
    assert linux["overview_route"] == f"/cases/{CASE_ID}/l"
    assert linux["overview"]["coverage"]["status_counts"]["has_data"] >= 1
    assert linux["overview"]["quick_actions"][0]["route"] == f"/cases/{CASE_ID}/l/access/authentication"
    windows_command_history = next(item for item in body["capabilities"] if item["id"] == "windows.execution.command_history")
    assert windows_command_history["route"] == "/cases/:caseId/w/execution/command-history"
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
    assert memory_processes["route"] == "/cases/:caseId/m/:evidenceId/processes"
    memory = next(item for item in body["workbenches"] if item["id"] == "memory")
    assert memory["overview_route"] == f"/cases/{CASE_ID}/m"
    assert memory["overview"]["memory_images"][0]["route"] == f"/cases/{CASE_ID}/m/{MEMORY_EVIDENCE_ID}/overview"
    assert memory["overview"]["quick_actions"][0]["route"] == f"/cases/{CASE_ID}/m"
    assert any(action["route"] == f"/cases/{CASE_ID}/m/{MEMORY_EVIDENCE_ID}/processes" for action in memory["overview"]["quick_actions"])


def test_case_capabilities_aggregates_workbench_warnings():
    db = _db()
    _case(db)
    _evidence(db, LINUX_EVIDENCE_ID, "triage.tgz", EvidenceType.linux_triage, "linux")
    db.add(Artifact(case_id=CASE_ID, evidence_id=LINUX_EVIDENCE_ID, name="auth.log", artifact_type="linux_auth", source_path="/var/log/auth.log", parser="linux_auth", record_count=1, status="completed_with_errors"))
    db.commit()

    response = _client(db).get(f"/api/cases/{CASE_ID}/capabilities")

    assert response.status_code == 200
    linux = next(item for item in response.json()["workbenches"] if item["id"] == "linux")
    assert any(warning["id"] == "linux.access.authentication.degraded" for warning in linux["overview"]["warnings"])


def test_case_capabilities_returns_404_for_unknown_case():
    db = _db()

    response = _client(db).get("/api/cases/ffffffff-1111-4111-8111-ffffffffffff/capabilities")

    assert response.status_code == 404


def test_registry_canonical_routes_are_registered_in_app_router():
    app_source = APP_TSX.read_text()
    registered_paths = set()
    for line in app_source.splitlines():
        marker = '<Route path="'
        if marker not in line:
            continue
        registered_paths.add(line.split(marker, 1)[1].split('"', 1)[0])

    for capability in CAPABILITY_REGISTRY:
        route = _route_path(capability["route"])
        assert route in registered_paths, f"{capability['id']} route {route} is not registered in App.tsx"


def test_legacy_redirect_targets_are_single_hop_terminal_routes():
    app_source = APP_TSX.read_text()
    legacy_redirects = {
        "/cases/:caseId/linux-authentication": "/cases/:caseId/l/access/authentication",
        "/cases/:caseId/command-history": "/cases/:caseId/l/execution/command-history",
        "/cases/:caseId/process-graph": "/cases/:caseId/w/execution/stories",
        "/cases/:caseId/process-tree": "/cases/:caseId/w/execution/stories",
        "/cases/:caseId/artifact-search": "/cases/:caseId/artifacts",
        "/cases/:caseId/memory": "/cases/:caseId/m",
        "/cases/:caseId/memory/landing": "/cases/:caseId/m",
        "/cases/:caseId/memory/upload": "/cases/:caseId",
        "/cases/:caseId/memory/:evidenceId/:memoryTab": "/cases/:caseId/m/:evidenceId/:memoryTab",
        "/cases/:caseId/memory/:evidenceId": "/cases/:caseId/m/:evidenceId/overview",
        "/process-tree": "/cases/:caseId/w/execution/stories",
        "/command-history": "/cases/:caseId/l/execution/command-history",
        "/dashboard": "/cases/:caseId/overview",
        "/analysis/semi-auto": "/cases/:caseId/findings",
        "/semi-auto": "/cases/:caseId/findings",
    }
    legacy_sources = set(legacy_redirects)

    for source, target in legacy_redirects.items():
        assert source in app_source, f"Legacy route {source} is not registered"
        assert source != target, f"Legacy route {source} redirects to itself"
        assert target not in legacy_sources, f"Legacy route {source} redirects to another legacy route {target}"

    for capability in CAPABILITY_REGISTRY:
        route = _route_path(capability["route"])
        assert route not in legacy_sources, f"Registry route {route} uses a legacy alias"
