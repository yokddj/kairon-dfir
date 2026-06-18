from types import SimpleNamespace

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from app.api import routes_memory
from app.core.database import Base
from app.models.artifact import Artifact
from app.models.case import Case
from app.models.evidence import Evidence, EvidenceType, IngestStatus
from app.models.memory import MemoryArtifactSummary, MemoryScanRun
from app.services.memory import backend_readiness
from app.services.memory import overview as memory_overview


@pytest.fixture()
def db_session():
    engine = create_engine("sqlite:///:memory:", future=True)
    Base.metadata.create_all(bind=engine)
    Session = sessionmaker(bind=engine, autoflush=False, autocommit=False, future=True)
    db = Session()
    try:
        yield db
    finally:
        db.close()


CASE_ID = "aaaaaaaa-1111-4111-8111-111111111111"
MEMORY_EVIDENCE_ID = "bbbbbbbb-2222-4222-8222-222222222222"
DISK_EVIDENCE_ID = "cccccccc-3333-4333-8333-333333333333"


def _case(db, case_id: str = CASE_ID) -> Case:
    item = Case(id=case_id, name="Memory Case")
    db.add(item)
    db.commit()
    return item


def _evidence(db, case_id: str = CASE_ID, evidence_id: str = MEMORY_EVIDENCE_ID, evidence_type=EvidenceType.memory_dump) -> Evidence:
    item = Evidence(
        id=evidence_id,
        case_id=case_id,
        original_filename="memory.mem" if evidence_type == EvidenceType.memory_dump else "disk.evtx",
        stored_path="/tmp/evidence",
        original_path="/tmp/evidence",
        evidence_type=evidence_type,
        sha256="0" * 64,
        size_bytes=1024,
        ingest_status=IngestStatus.completed,
        metadata_json={},
        error_log={},
    )
    db.add(item)
    db.commit()
    return item


def _set_disk_count(monkeypatch: pytest.MonkeyPatch, count: int) -> None:
    monkeypatch.setattr(memory_overview, "count_documents", lambda _index: {"count": count})


def test_memory_overview_empty_case(db_session, monkeypatch: pytest.MonkeyPatch) -> None:
    _case(db_session)
    _set_disk_count(monkeypatch, 0)

    overview = memory_overview.get_case_memory_overview(db_session, CASE_ID)

    assert overview["mode"] == "empty"
    assert overview["has_memory_evidence"] is False
    assert overview["has_disk_events"] is False


def test_memory_overview_disk_only_case(db_session, monkeypatch: pytest.MonkeyPatch) -> None:
    _case(db_session)
    _set_disk_count(monkeypatch, 12)

    overview = memory_overview.get_case_memory_overview(db_session, CASE_ID)

    assert overview["mode"] == "disk_only"
    assert overview["has_disk_events"] is True


def test_memory_overview_memory_only_case(db_session, monkeypatch: pytest.MonkeyPatch) -> None:
    _case(db_session)
    _evidence(db_session)
    _set_disk_count(monkeypatch, 0)

    overview = memory_overview.get_case_memory_overview(db_session, CASE_ID)

    assert overview["mode"] == "memory_only"
    assert overview["has_memory_evidence"] is True


def test_memory_overview_hybrid_case(db_session, monkeypatch: pytest.MonkeyPatch) -> None:
    _case(db_session)
    _evidence(db_session)
    _set_disk_count(monkeypatch, 4)

    overview = memory_overview.get_case_memory_overview(db_session, CASE_ID)

    assert overview["mode"] == "hybrid"
    assert overview["has_disk_events"] is True
    assert overview["has_memory_evidence"] is True


def test_memory_scan_disabled_by_default(db_session, monkeypatch: pytest.MonkeyPatch) -> None:
    _case(db_session)
    evidence = _evidence(db_session)
    monkeypatch.setattr(routes_memory, "settings", SimpleNamespace(memory_analysis_enabled=False))

    response = routes_memory.start_memory_scan(evidence.id, None, db_session)

    assert response.status == "disabled"
    assert response.accepted is False
    assert db_session.query(MemoryScanRun).count() == 0


def test_memory_scan_rejects_non_memory_evidence(db_session, monkeypatch: pytest.MonkeyPatch) -> None:
    _case(db_session)
    evidence = _evidence(db_session, evidence_id=DISK_EVIDENCE_ID, evidence_type=EvidenceType.evtx)
    monkeypatch.setattr(routes_memory, "settings", SimpleNamespace(memory_analysis_enabled=True))

    with pytest.raises(Exception) as exc_info:
        routes_memory.start_memory_scan(evidence.id, None, db_session)

    assert getattr(exc_info.value, "status_code", None) == 400


def test_memory_scan_registers_metadata_only_when_enabled(db_session, monkeypatch: pytest.MonkeyPatch) -> None:
    _case(db_session)
    evidence = _evidence(db_session)
    monkeypatch.setattr(routes_memory, "settings", SimpleNamespace(memory_analysis_enabled=True))

    response = routes_memory.start_memory_scan(evidence.id, None, db_session)
    run = db_session.query(MemoryScanRun).one()

    assert response.accepted is True
    assert response.status == "ready"
    assert run.profile == "metadata_only"
    assert run.plugin_count == 0
    assert "External analysis is not enabled" in response.message


def test_memory_evidence_does_not_create_normalized_events(db_session, monkeypatch: pytest.MonkeyPatch) -> None:
    _case(db_session)
    evidence = _evidence(db_session)
    monkeypatch.setattr(routes_memory, "settings", SimpleNamespace(memory_analysis_enabled=True))

    routes_memory.start_memory_scan(evidence.id, None, db_session)

    assert db_session.query(Artifact).filter(Artifact.evidence_id == evidence.id).count() == 0
    assert db_session.query(MemoryArtifactSummary).filter(MemoryArtifactSummary.evidence_id == evidence.id).count() == 0


def test_memory_evidence_does_not_write_to_existing_events_index(db_session, monkeypatch: pytest.MonkeyPatch) -> None:
    _case(db_session)
    evidence = _evidence(db_session)
    monkeypatch.setattr(routes_memory, "settings", SimpleNamespace(memory_analysis_enabled=True))
    monkeypatch.setattr(memory_overview, "count_documents", lambda _index: {"count": 0})

    routes_memory.start_memory_scan(evidence.id, None, db_session)
    overview = memory_overview.get_case_memory_overview(db_session, CASE_ID)

    assert overview["has_disk_events"] is False
    assert overview["has_memory_results"] is False


def _backend_settings(**overrides) -> SimpleNamespace:
    values = {
        "memory_analysis_enabled": False,
        "memory_allow_external_tool_execution": False,
        "memory_backend_check_timeout_seconds": 10,
        "memory_backend_status_cache_seconds": 60,
        "preferred_memory_backend": "volatility3",
        "volatility3_command": "vol",
        "memprocfs_command": "memprocfs",
    }
    values.update(overrides)
    return SimpleNamespace(**values)


def _completed(stdout: str = "Volatility 3 Framework 2.8.0\n", stderr: str = "", returncode: int = 0) -> SimpleNamespace:
    return SimpleNamespace(stdout=stdout, stderr=stderr, returncode=returncode)


def test_backend_readiness_memory_feature_disabled(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(backend_readiness, "get_settings", lambda: _backend_settings(memory_analysis_enabled=False))
    monkeypatch.setattr(backend_readiness.shutil, "which", lambda _command: "/usr/bin/vol")
    monkeypatch.setattr(backend_readiness.subprocess, "run", lambda *_args, **_kwargs: _completed())

    status = backend_readiness.check_volatility3_backend()

    assert status["status"] == "disabled"
    assert status["available"] is True
    assert status["ready"] is False


def test_backend_readiness_external_execution_disabled(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(backend_readiness, "get_settings", lambda: _backend_settings(memory_analysis_enabled=True, memory_allow_external_tool_execution=False))
    monkeypatch.setattr(backend_readiness.shutil, "which", lambda _command: "/usr/bin/vol")
    monkeypatch.setattr(backend_readiness.subprocess, "run", lambda *_args, **_kwargs: _completed())

    status = backend_readiness.check_volatility3_backend()

    assert status["status"] == "blocked"
    assert status["available"] is True
    assert status["ready"] is False
    assert "disabled" in status["message"]


def test_backend_readiness_command_not_configured(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(backend_readiness, "get_settings", lambda: _backend_settings(volatility3_command=""))

    status = backend_readiness.check_volatility3_backend()

    assert status["configured"] is False
    assert status["status"] == "not_configured"
    assert status["error_code"] == "not_configured"


def test_backend_readiness_executable_not_found(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(backend_readiness, "get_settings", lambda: _backend_settings(volatility3_command="vol"))
    monkeypatch.setattr(backend_readiness.shutil, "which", lambda _command: None)

    status = backend_readiness.check_volatility3_backend()

    assert status["configured"] is True
    assert status["executable_found"] is False
    assert status["status"] == "not_found"


def test_backend_readiness_executable_found_and_ready(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(backend_readiness, "get_settings", lambda: _backend_settings(memory_analysis_enabled=True, memory_allow_external_tool_execution=True))
    monkeypatch.setattr(backend_readiness.shutil, "which", lambda _command: "/usr/bin/vol")
    monkeypatch.setattr(backend_readiness.subprocess, "run", lambda args, **kwargs: _completed("Volatility 3 Framework 2.8.0\n"))

    status = backend_readiness.check_volatility3_backend()

    assert status["executable_found"] is True
    assert status["available"] is True
    assert status["ready"] is True
    assert status["status"] == "available"
    assert status["version"] == "Volatility 3 Framework 2.8.0"
    assert status["command_display"] == "vol"


def test_backend_readiness_harmless_check_timeout(monkeypatch: pytest.MonkeyPatch) -> None:
    def raise_timeout(*_args, **_kwargs):
        raise backend_readiness.subprocess.TimeoutExpired(cmd=["vol", "--help"], timeout=1)

    monkeypatch.setattr(backend_readiness, "get_settings", lambda: _backend_settings())
    monkeypatch.setattr(backend_readiness.shutil, "which", lambda _command: "/usr/bin/vol")
    monkeypatch.setattr(backend_readiness.subprocess, "run", raise_timeout)

    status = backend_readiness.check_volatility3_backend()

    assert status["status"] == "check_failed"
    assert status["error_code"] == "check_timeout"


def test_backend_readiness_harmless_check_failure(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(backend_readiness, "get_settings", lambda: _backend_settings())
    monkeypatch.setattr(backend_readiness.shutil, "which", lambda _command: "/usr/bin/vol")
    monkeypatch.setattr(backend_readiness.subprocess, "run", lambda *_args, **_kwargs: _completed(stderr="/secret/path failure", returncode=2))

    status = backend_readiness.check_volatility3_backend()

    assert status["status"] == "check_failed"
    assert status["version"] is None


def test_backend_readiness_sanitizes_error_output() -> None:
    assert "/home/alex/secret" not in backend_readiness.sanitize_backend_error("failed at /home/alex/secret/tool")


@pytest.mark.parametrize("command", ["vol --help", "vol;id", "vol|id", "vol && id", "./vol"])
def test_backend_readiness_rejects_suspicious_configured_commands(command: str) -> None:
    configured, executable, display, error = backend_readiness.resolve_configured_executable(command)

    assert configured is False
    assert executable is None
    assert display is not None
    assert error == "invalid_command"


def test_backend_readiness_cache_prevents_repeated_subprocess_calls(monkeypatch: pytest.MonkeyPatch) -> None:
    backend_readiness.clear_memory_backend_readiness_cache()
    calls = {"count": 0}

    def fake_run(*_args, **_kwargs):
        calls["count"] += 1
        return _completed()

    monkeypatch.setattr(backend_readiness, "get_settings", lambda: _backend_settings())
    monkeypatch.setattr(backend_readiness.shutil, "which", lambda command: f"/usr/bin/{command}")
    monkeypatch.setattr(backend_readiness.subprocess, "run", fake_run)
    monkeypatch.setattr(backend_readiness.time, "monotonic", lambda: 100.0)

    first = backend_readiness.get_memory_backend_overview()
    second = backend_readiness.get_memory_backend_overview()

    assert first is second
    assert calls["count"] == 2


def test_backend_readiness_cache_expires(monkeypatch: pytest.MonkeyPatch) -> None:
    backend_readiness.clear_memory_backend_readiness_cache()
    calls = {"count": 0}
    now = {"value": 100.0}

    def fake_run(*_args, **_kwargs):
        calls["count"] += 1
        return _completed()

    monkeypatch.setattr(backend_readiness, "get_settings", lambda: _backend_settings(memory_backend_status_cache_seconds=1))
    monkeypatch.setattr(backend_readiness.shutil, "which", lambda command: f"/usr/bin/{command}")
    monkeypatch.setattr(backend_readiness.subprocess, "run", fake_run)
    monkeypatch.setattr(backend_readiness.time, "monotonic", lambda: now["value"])

    backend_readiness.get_memory_backend_overview()
    now["value"] = 102.0
    backend_readiness.get_memory_backend_overview()

    assert calls["count"] == 4


def test_backend_readiness_endpoint_does_not_create_runs_or_write_indexes(db_session, monkeypatch: pytest.MonkeyPatch) -> None:
    backend_readiness.clear_memory_backend_readiness_cache()
    monkeypatch.setattr(backend_readiness, "get_settings", lambda: _backend_settings())
    monkeypatch.setattr(backend_readiness.shutil, "which", lambda _command: None)

    response = routes_memory.get_memory_backends()

    assert response["ready_backend_count"] == 0
    assert db_session.query(MemoryScanRun).count() == 0


def test_backend_readiness_response_does_not_expose_full_sensitive_paths(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(backend_readiness, "get_settings", lambda: _backend_settings(volatility3_command="/opt/private/tools/vol"))
    monkeypatch.setattr(backend_readiness.Path, "is_file", lambda _self: True)
    monkeypatch.setattr(backend_readiness.subprocess, "run", lambda *_args, **_kwargs: _completed())

    status = backend_readiness.check_volatility3_backend()

    assert status["command_display"] == "vol"
    assert "/opt/private" not in str(status)
