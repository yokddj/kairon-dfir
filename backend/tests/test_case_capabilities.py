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
from app.services.case_capabilities import CAPABILITY_REGISTRY, SURFACE_REGISTRY, surface_route_prefix


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


def _registered_routes() -> set[str]:
    app_source = APP_TSX.read_text()
    registered_paths = set()
    for line in app_source.splitlines():
        marker = '<Route path="'
        if marker in line:
            registered_paths.add(line.split(marker, 1)[1].split('"', 1)[0])
    return registered_paths


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


def test_registry_static_architecture_consistency():
    capability_ids = [item["id"] for item in CAPABILITY_REGISTRY]
    assert len(capability_ids) == len(set(capability_ids))

    # Full routes (path + query) must be unique -- two capabilities are never
    # literally indistinguishable. The canonical *path* alone may repeat
    # when capabilities legitimately share one query-param-driven page (e.g.
    # ArtifactExplorer at /cases/:caseId/artifacts, selected via
    # ?artifact_type=...), same as linux.software.packages and
    # windows.persistence.overview both do.
    full_routes = [item["route"] for item in CAPABILITY_REGISTRY]
    assert len(full_routes) == len(set(full_routes))

    for capability in CAPABILITY_REGISTRY:
        assert capability["platform"]
        assert capability["domain"]
        assert capability["evidence_domain"] in {"filesystem", "memory"}
        assert capability["availability"] == "shipped"
        assert capability["readiness_source"] in {"artifact_counts", "memory_artifact_counts"}
        assert capability["nav"]["parent"].startswith(f"{capability['platform']}/")
        assert capability["nav"]["order"] > 0
        overview = capability.get("overview")
        assert overview, f"{capability['id']} has no overview metadata"
        assert isinstance(overview.get("priority"), int)
        assert isinstance(overview.get("featured"), bool)
        if overview["featured"]:
            assert overview.get("quick_action"), f"{capability['id']} featured without quick action"
        search = capability.get("search")
        assert search, f"{capability['id']} has no search metadata"
        assert isinstance(search.get("priority"), int)
        assert search.get("group")
        assert isinstance(search.get("default_filters"), dict)
        assert search.get("presets"), f"{capability['id']} has no registry search presets"
        if capability["evidence_domain"] == "memory":
            assert capability["platform"] == "memory"
            assert capability["route"].startswith("/cases/:caseId/m")
        else:
            assert capability["platform"] in {"windows", "linux"}


def test_surface_registry_consistency():
    surface_ids = [entry["id"] for entry in SURFACE_REGISTRY]
    assert len(surface_ids) == len(set(surface_ids))

    route_prefixes = [entry["route_prefix"] for entry in SURFACE_REGISTRY]
    assert len(route_prefixes) == len(set(route_prefixes))

    for entry in SURFACE_REGISTRY:
        assert entry["label"]
        assert entry["kind"] in {"platform", "evidence_domain"}
        assert entry["icon"]
        assert entry["nav"]["order"] > 0

    # Every workbench a capability can resolve to (platform, or "memory" for
    # evidence_domain == "memory") must have a registered surface, so the
    # sidebar/overview never falls back to derived label/kind/icon defaults
    # for a surface that is actually shipped today.
    reachable_surface_ids = {
        "memory" if capability["evidence_domain"] == "memory" else capability["platform"]
        for capability in CAPABILITY_REGISTRY
    }
    assert reachable_surface_ids.issubset(set(surface_ids))


def test_surface_route_prefix_matches_registry():
    assert surface_route_prefix("windows") == "w"
    assert surface_route_prefix("linux") == "l"
    assert surface_route_prefix("memory") == "m"
    # Unregistered surface falls back to its first letter rather than raising,
    # so a new platform value in CAPABILITY_REGISTRY never breaks capability
    # navigation while SURFACE_REGISTRY catches up.
    assert surface_route_prefix("cloud") == "c"


def test_workbench_payload_contract_is_unchanged_except_for_icon():
    """Pins the exact pre-SURFACE_REGISTRY workbench payload shape and values.

    SURFACE_REGISTRY must only add the new `icon` field to each workbench --
    every other key and value already covered by existing tests must be
    byte-for-byte identical to what build_case_capabilities() produced before
    this registry existed.
    """
    db = _db()
    _case(db)
    _evidence(db, LINUX_EVIDENCE_ID, "triage.tgz", EvidenceType.linux_triage, "linux")
    db.add(Artifact(case_id=CASE_ID, evidence_id=LINUX_EVIDENCE_ID, name="auth.log", artifact_type="linux_auth", source_path="/var/log/auth.log", parser="linux_auth", record_count=42, status="parsed"))
    db.commit()

    response = _client(db).get(f"/api/cases/{CASE_ID}/capabilities")

    assert response.status_code == 200
    linux = next(item for item in response.json()["workbenches"] if item["id"] == "linux")

    pre_registry_keys = {"id", "label", "kind", "capability_ids", "domains", "overview_route", "overview"}
    assert set(linux.keys()) == pre_registry_keys | {"icon"}

    assert linux["id"] == "linux"
    assert linux["label"] == "Linux"
    assert linux["kind"] == "platform"
    assert linux["capability_ids"] == ["linux.access.authentication", "linux.execution.command_history", "linux.software.packages"]
    assert linux["overview_route"] == f"/cases/{CASE_ID}/l"
    assert linux["icon"] == "shield-check"


def test_workbench_overview_routes_are_registered():
    registered_paths = _registered_routes()
    expected = {"/cases/:caseId/w", "/cases/:caseId/l", "/cases/:caseId/m"}
    assert expected.issubset(registered_paths)


def test_case_capabilities_returns_404_for_unknown_case():
    db = _db()

    response = _client(db).get("/api/cases/ffffffff-1111-4111-8111-ffffffffffff/capabilities")

    assert response.status_code == 404


def test_registry_canonical_routes_are_registered_in_app_router():
    registered_paths = _registered_routes()

    for capability in CAPABILITY_REGISTRY:
        route = _route_path(capability["route"])
        assert route in registered_paths, f"{capability['id']} route {route} is not registered in App.tsx"


def test_generated_workbench_summaries_have_no_orphan_routes_or_capabilities():
    db = _db()
    _case(db)
    _evidence(db, "eeeeeeee-1111-4111-8111-eeeeeeeeeeee", "win.zip", EvidenceType.raw_collection, "windows")
    _evidence(db, LINUX_EVIDENCE_ID, "triage.tgz", EvidenceType.linux_triage, "linux")
    _evidence(db, MEMORY_EVIDENCE_ID, "mem.raw", EvidenceType.memory_dump, "memory", metadata={"probable_os": "windows"})

    response = _client(db).get(f"/api/cases/{CASE_ID}/capabilities")

    assert response.status_code == 200
    body = response.json()
    capability_ids = {capability["id"] for capability in body["capabilities"]}
    for workbench in body["workbenches"]:
        assert workbench["overview_route"].startswith(f"/cases/{CASE_ID}/")
        assert ":" not in workbench["overview_route"]
        domain_memberships: list[str] = []
        for domain in workbench["domains"]:
            assert domain["capability_ids"]
            for capability_id in domain["capability_ids"]:
                assert capability_id in capability_ids
                domain_memberships.append(capability_id)
        assert sorted(domain_memberships) == sorted(workbench["capability_ids"])
        assert len(domain_memberships) == len(set(domain_memberships))
        for action in workbench["overview"]["quick_actions"]:
            assert action["id"] in capability_ids
            assert action["route"].startswith(f"/cases/{CASE_ID}/")
            assert ":" not in action["route"]


def test_case_capabilities_exposes_registry_driven_search_metadata():
    db = _db()
    _case(db)
    _evidence(db, "eeeeeeee-1111-4111-8111-eeeeeeeeeeee", "win.zip", EvidenceType.raw_collection, "windows")
    _evidence(db, LINUX_EVIDENCE_ID, "triage.tgz", EvidenceType.linux_triage, "linux")
    _evidence(db, MEMORY_EVIDENCE_ID, "mem.raw", EvidenceType.memory_dump, "memory", metadata={"probable_os": "windows"})
    db.add(Artifact(case_id=CASE_ID, evidence_id=LINUX_EVIDENCE_ID, name="auth.log", artifact_type="linux_auth", source_path="/var/log/auth.log", parser="linux_auth", record_count=42, status="parsed"))
    db.add(MemoryArtifactSummary(case_id=CASE_ID, evidence_id=MEMORY_EVIDENCE_ID, memory_run_id="ffffffff-5555-4555-8555-ffffffffffff", memory_artifact_type="processes", count=8, metadata_json={}))
    db.commit()

    response = _client(db).get(f"/api/cases/{CASE_ID}/capabilities")

    assert response.status_code == 200
    search = response.json()["search"]
    assert {item["id"] for item in search["facets"]["workbench"]} >= {"windows", "linux", "memory"}
    assert any(item["workbench"] == "linux" and item["id"] == "access" for item in search["facets"]["domain"])
    assert any(item["id"] == "linux.access.authentication" for item in search["facets"]["capability"])
    assert any(preset["capability_id"] == "linux.access.authentication" and preset["state"]["platform"] == "linux" for preset in search["presets"])


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
