from __future__ import annotations

from pathlib import Path
from uuid import uuid4

import pytest
from fastapi import HTTPException
from sqlalchemy import create_engine
from sqlalchemy.orm import Session, sessionmaker

from app.core.database import Base
from app.models.case import Case
from app.models.evidence import Evidence, EvidenceStorageMode, EvidenceType, IngestStatus
from app.models.memory import MemoryPluginRun, MemoryScanRun
from app.schemas.memory import MemoryStartScanRequest
from app.services.memory import execution as execution_module
from app.services.memory import profile_planning
from app.services.memory.profile_planning import plan_profile_capability
from app.services.memory.validation import ValidatedMemoryEvidence
from app.services.memory.volatility_runner import VolatilityRunResult


def _settings(*, enabled_plugins: str | None = None):
    from app.core.config import Settings

    base = Settings()
    object.__setattr__(base, "memory_analysis_enabled", True)
    object.__setattr__(base, "memory_allow_external_tool_execution", True)
    object.__setattr__(base, "memory_process_profile_enabled", True)
    object.__setattr__(base, "memory_allowed_profiles", "metadata_only,processes_basic,processes_extended,network_basic,modules_basic,handles_basic,kernel_basic,suspicious_memory")
    object.__setattr__(
        base,
        "memory_allowed_plugins",
        enabled_plugins
        or "windows.info,windows.pslist,windows.pstree,windows.psscan,windows.cmdline,windows.envars,windows.getsids,windows.privileges,windows.netscan,windows.netstat,windows.dlllist,windows.ldrmodules,windows.handles,windows.modules,windows.driverscan,windows.malfind,windows.vadinfo",
    )
    return base


@pytest.fixture()
def db(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> tuple[Session, Evidence, Path]:
    engine = create_engine("sqlite:///:memory:", connect_args={"check_same_thread": False})
    Base.metadata.create_all(bind=engine)
    session = sessionmaker(bind=engine)()
    case = Case(id=str(uuid4()), name="case", description="", status="open", mode="investigation")
    evidence_path = tmp_path / "memory.dmp"
    evidence_path.write_bytes(b"memory")
    ev = Evidence(
        id=str(uuid4()),
        case_id=case.id,
        original_filename="memory.dmp",
        stored_path=str(evidence_path),
        storage_mode=EvidenceStorageMode.uploaded,
        evidence_type=EvidenceType.memory_dump,
        size_bytes=evidence_path.stat().st_size,
        ingest_status=IngestStatus.completed,
        sha256="0" * 64,
        metadata_json={},
        detection_status="confirmed_memory",
        detection_confidence="high",
        detected_format="windows_crash_dump",
    )
    session.add_all([case, ev])
    session.commit()

    monkeypatch.setattr(profile_planning, "get_settings", _settings)
    monkeypatch.setattr(execution_module.backend_readiness, "get_settings", _settings)
    return session, ev, evidence_path


def _patch_direct_scan(monkeypatch: pytest.MonkeyPatch, db: Session, ev: Evidence, evidence_path: Path, *, settings_obj=None, ready: bool = True) -> None:
    from app.api import routes_memory

    settings_obj = settings_obj or _settings()
    monkeypatch.setattr(routes_memory, "settings", settings_obj)
    monkeypatch.setattr(profile_planning, "get_settings", lambda: settings_obj)
    monkeypatch.setattr(execution_module.backend_readiness, "get_settings", lambda: settings_obj)
    monkeypatch.setattr(
        routes_memory,
        "get_memory_backend_overview",
        lambda: {"backends": [{"backend": "volatility3", "ready": ready, "message": "worker ready" if ready else "worker down"}]},
    )

    def validate(session: Session, evidence_id: str):
        return ValidatedMemoryEvidence(evidence=session.get(Evidence, evidence_id), path=evidence_path, size_bytes=evidence_path.stat().st_size)

    monkeypatch.setattr(routes_memory, "validate_memory_execution_request", validate)
    monkeypatch.setattr(execution_module, "validate_memory_execution_request", validate)
    monkeypatch.setattr(routes_memory, "enqueue_memory_metadata_scan", lambda run_id: f"job-{run_id}")


def test_direct_network_basic_succeeds_when_api_process_lacks_volatility_and_capability_unknown(db, monkeypatch: pytest.MonkeyPatch) -> None:
    from app.api.routes_memory import start_memory_scan
    from app.services.memory import volatility_runner

    session, ev, evidence_path = db
    _patch_direct_scan(monkeypatch, session, ev, evidence_path)
    monkeypatch.setattr(profile_planning, "_current_worker_capability", lambda: None)
    monkeypatch.setattr(volatility_runner, "network_basic_available", lambda: (_ for _ in ()).throw(AssertionError("API-local probe must not run")))

    response = start_memory_scan(
        ev.id,
        MemoryStartScanRequest(profile="network_basic", authorization_acknowledged=True),
        case_id=ev.case_id,
        db=session,
    )

    assert response.accepted is True
    run = session.get(MemoryScanRun, response.run_id)
    assert run.status == "queued"
    assert [item.plugin for item in run.plugin_runs] == ["windows.netscan", "windows.netstat"]


def test_direct_network_basic_succeeds_with_fresh_worker_capability_available(db, monkeypatch: pytest.MonkeyPatch) -> None:
    from app.api.routes_memory import start_memory_scan

    session, ev, evidence_path = db
    _patch_direct_scan(monkeypatch, session, ev, evidence_path)
    monkeypatch.setattr(
        profile_planning,
        "_current_worker_capability",
        lambda: {"healthy": True, "queue": "memory", "plugins": {"windows.netscan": {"state": "available"}, "windows.netstat": {"state": "available"}}},
    )

    response = start_memory_scan(
        ev.id,
        MemoryStartScanRequest(profile="network_basic", authorization_acknowledged=True),
        case_id=ev.case_id,
        db=session,
    )

    run = session.get(MemoryScanRun, response.run_id)
    assert run.plugin_count == 2
    assert [item.plugin for item in run.plugin_runs] == ["windows.netscan", "windows.netstat"]


def test_direct_scan_all_plugins_disabled_returns_no_enabled_plugins(db, monkeypatch: pytest.MonkeyPatch) -> None:
    from app.api.routes_memory import start_memory_scan

    session, ev, evidence_path = db
    settings_obj = _settings(enabled_plugins="windows.info,windows.pslist,windows.pstree,windows.cmdline")
    _patch_direct_scan(monkeypatch, session, ev, evidence_path, settings_obj=settings_obj)

    with pytest.raises(HTTPException) as exc:
        start_memory_scan(
            ev.id,
            MemoryStartScanRequest(profile="network_basic", authorization_acknowledged=True),
            case_id=ev.case_id,
            db=session,
        )

    assert exc.value.status_code == 400
    assert exc.value.detail["error_code"] == "MEMORY_PROFILE_NO_ENABLED_PLUGINS"
    assert session.query(MemoryScanRun).count() == 0


def test_worker_unavailable_still_blocks_direct_scan(db, monkeypatch: pytest.MonkeyPatch) -> None:
    from app.api.routes_memory import start_memory_scan

    session, ev, evidence_path = db
    _patch_direct_scan(monkeypatch, session, ev, evidence_path, ready=False)

    with pytest.raises(HTTPException) as exc:
        start_memory_scan(
            ev.id,
            MemoryStartScanRequest(profile="network_basic", authorization_acknowledged=True),
            case_id=ev.case_id,
            db=session,
        )

    assert exc.value.status_code == 503
    assert session.query(MemoryScanRun).count() == 0


def test_shared_planner_treats_stale_or_missing_capability_as_unknown_not_unavailable(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(profile_planning, "get_settings", _settings)
    monkeypatch.setattr(profile_planning, "_current_worker_capability", lambda: None)

    plan = plan_profile_capability("network_basic")

    assert plan["has_enabled_plugins"] is True
    assert [item["state"] for item in plan["plugins"]] == ["unknown", "unknown"]
    assert plan["available_plugin_count"] == 2


def test_shared_planner_reports_known_unavailable_without_blocking_remaining_plugins(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(profile_planning, "get_settings", _settings)
    plan = plan_profile_capability(
        "network_basic",
        worker_capability={
            "healthy": True,
            "plugins": {
                "windows.netscan": {"state": "available"},
                "windows.netstat": {"state": "unavailable", "reason": "missing class"},
            },
        },
    )

    assert plan["has_enabled_plugins"] is True
    assert [item["state"] for item in plan["plugins"]] == ["available", "unavailable"]
    assert [item["plugin"] for item in plan["runnable_plugins"]] == ["windows.netscan"]


def test_worker_authoritative_check_creates_skipped_unsupported(db, monkeypatch: pytest.MonkeyPatch) -> None:
    session, ev, evidence_path = db

    def validate(session_: Session, evidence_id: str):
        return ValidatedMemoryEvidence(evidence=session_.get(Evidence, evidence_id), path=evidence_path, size_bytes=evidence_path.stat().st_size)

    monkeypatch.setattr(execution_module, "validate_memory_execution_request", validate)
    monkeypatch.setattr(execution_module.backend_readiness, "check_volatility3_backend", lambda: {"ready": True, "version": "2.28.0"})
    monkeypatch.setattr(execution_module, "validate_current_process_output_access", lambda: None)
    monkeypatch.setattr(execution_module, "_advance_batch_after_run", lambda run: None)
    monkeypatch.setattr(execution_module.volatility_runner, "probe_volatility_plugin", lambda plugin: plugin == "windows.netscan")
    monkeypatch.setattr(execution_module, "run_plugin", lambda *args, **kwargs: VolatilityRunResult(argv_display=["vol", "-f", "[evidence]", "-r", "json"], stdout=b"[]", stderr=b"", duration_ms=1))
    monkeypatch.setattr(execution_module, "index_artifact_documents", lambda case_id, documents: {"indexed": len(documents), "errors": 0})
    monkeypatch.setattr(execution_module, "link_process_entities", lambda *args, **kwargs: None)

    class _SessionCtx:
        def __enter__(self):
            return session

        def __exit__(self, *args):
            return False

    monkeypatch.setattr(execution_module, "SessionLocal", lambda: _SessionCtx())
    run = execution_module.create_memory_metadata_run(session, ev.id, "network_basic")
    run.status = "queued"
    session.commit()

    execution_module.run_memory_metadata_scan(run.id)

    refreshed = session.get(MemoryScanRun, run.id)
    assert refreshed.status == "completed_with_errors"
    assert {item.plugin: item.status for item in refreshed.plugin_runs} == {
        "windows.netscan": "completed",
        "windows.netstat": "skipped_unsupported",
    }


def test_processes_extended_and_suspicious_memory_plugin_definitions_unchanged() -> None:
    from app.services.memory.execution import PROFILE_PLUGINS

    assert PROFILE_PLUGINS["processes_extended"] == ["windows.psscan", "windows.envars", "windows.getsids", "windows.privileges"]
    assert PROFILE_PLUGINS["network_basic"] == ["windows.netscan", "windows.netstat"]
    assert PROFILE_PLUGINS["suspicious_memory"] == ["windows.malfind", "windows.vadinfo"]


def test_normal_volatility_command_has_no_offline_flag() -> None:
    from app.services.memory.volatility_runner import build_plugin_argv

    command = build_plugin_argv(["vol"], Path("/tmp/memory.dmp"), "windows.netscan")
    assert "--offline" not in command
