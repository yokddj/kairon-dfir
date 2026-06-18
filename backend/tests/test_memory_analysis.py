import subprocess
from io import BytesIO
from pathlib import Path
from types import SimpleNamespace

import pytest
from fastapi import UploadFile
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from app.api import routes_evidence
from app.api import routes_memory
from app.core.database import Base
from app.models.artifact import Artifact
from app.models.case import Case
from app.models.evidence import Evidence, EvidenceType, IngestStatus
from app.models.memory import MemoryArtifactSummary, MemoryPluginRun, MemoryScanRun
from app.services.memory import backend_readiness
from app.services.memory import execution as memory_execution
from app.services.memory import indexing as memory_indexing
from app.services.memory import normalizers as memory_normalizers
from app.services.memory import overview as memory_overview
from app.services.memory import storage as memory_storage
from app.services.memory import validation as memory_validation
from app.services.memory import volatility_runner
from app.services.memory import worker_capability
from app.core import storage as core_storage
from app.schemas.memory import MemoryStartScanRequest


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


def _evidence(db, case_id: str = CASE_ID, evidence_id: str = MEMORY_EVIDENCE_ID, evidence_type=EvidenceType.memory_dump, stored_path: str = "/tmp/evidence") -> Evidence:
    item = Evidence(
        id=evidence_id,
        case_id=case_id,
        original_filename="memory.mem" if evidence_type == EvidenceType.memory_dump else "disk.evtx",
        stored_path=stored_path,
        original_path=stored_path,
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


def test_standard_memory_upload_streams_to_canonical_storage(db_session, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    _case(db_session)
    data = b"abc" * 4096
    upload = UploadFile(filename="../authorized.raw", file=BytesIO(data))
    settings = SimpleNamespace(
        backend_data_dir=tmp_path / "data",
        backend_temp_dir=tmp_path / "data" / "tmp",
        memory_upload_enabled=True,
        memory_upload_max_bytes=len(data) + 10,
        memory_upload_chunk_size_bytes=1024,
        memory_upload_extensions={".raw", ".mem", ".vmem", ".dmp", ".lime"},
        memory_upload_staging_path=tmp_path / "data" / "tmp" / "memory-uploads",
    )
    monkeypatch.setattr(core_storage, "settings", settings)
    monkeypatch.setattr(routes_evidence, "settings", settings)
    enqueue_calls: list[str] = []
    monkeypatch.setattr(routes_evidence, "enqueue_ingest", lambda evidence_id: enqueue_calls.append(evidence_id))

    evidence = routes_evidence.upload_evidence(CASE_ID, upload, folder_upload=False, folder_name=None, evidence_intent=None, packaging=None, ingest_mode=None, provided_host="HOSTA", evtx_profile=None, db=db_session)

    assert evidence.evidence_type == EvidenceType.memory_dump
    assert evidence.ingest_status == IngestStatus.completed
    assert evidence.sha256 == core_storage.hashlib.sha256(data).hexdigest()
    assert evidence.size_bytes == len(data)
    assert evidence.original_filename == "authorized.raw"
    assert evidence.stored_path.endswith(f"/evidence/{CASE_ID}/{evidence.id}/original/memory-image.raw")
    assert Path(evidence.stored_path).read_bytes() == data
    assert not list(settings.memory_upload_staging_path.glob("*.part"))
    assert enqueue_calls == []


def test_memory_upload_rejects_oversized_file_without_evidence(db_session, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    _case(db_session)
    upload = UploadFile(filename="too-large.mem", file=BytesIO(b"123456789"))
    settings = SimpleNamespace(
        backend_data_dir=tmp_path / "data",
        backend_temp_dir=tmp_path / "data" / "tmp",
        memory_upload_enabled=True,
        memory_upload_max_bytes=4,
        memory_upload_chunk_size_bytes=3,
        memory_upload_extensions={".raw", ".mem", ".vmem", ".dmp", ".lime"},
        memory_upload_staging_path=tmp_path / "data" / "tmp" / "memory-uploads",
    )
    monkeypatch.setattr(core_storage, "settings", settings)
    monkeypatch.setattr(routes_evidence, "settings", settings)

    with pytest.raises(Exception) as exc_info:
        routes_evidence.upload_evidence(CASE_ID, upload, folder_upload=False, folder_name=None, evidence_intent=None, packaging=None, ingest_mode=None, provided_host="HOSTA", evtx_profile=None, db=db_session)

    assert getattr(exc_info.value, "status_code", None) == 413
    assert db_session.query(Evidence).count() == 0
    assert not list((settings.backend_data_dir / "evidence").rglob("*.mem"))


def test_memory_upload_disabled_rejects_memory_extension(db_session, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    _case(db_session)
    upload = UploadFile(filename="memory.mem", file=BytesIO(b"data"))
    settings = SimpleNamespace(
        backend_data_dir=tmp_path / "data",
        backend_temp_dir=tmp_path / "data" / "tmp",
        memory_upload_enabled=False,
        memory_upload_extensions={".raw", ".mem", ".vmem", ".dmp", ".lime"},
    )
    monkeypatch.setattr(core_storage, "settings", settings)
    monkeypatch.setattr(routes_evidence, "settings", settings)

    with pytest.raises(Exception) as exc_info:
        routes_evidence.upload_evidence(CASE_ID, upload, folder_upload=False, folder_name=None, evidence_intent=None, packaging=None, ingest_mode=None, provided_host="HOSTA", evtx_profile=None, db=db_session)

    assert getattr(exc_info.value, "status_code", None) == 403
    assert db_session.query(Evidence).count() == 0


def test_memory_scan_requires_authorization_acknowledgement_when_enabled(db_session, monkeypatch: pytest.MonkeyPatch) -> None:
    _case(db_session)
    evidence = _evidence(db_session)
    monkeypatch.setattr(routes_memory, "settings", SimpleNamespace(memory_analysis_enabled=True, memory_allow_external_tool_execution=True))

    with pytest.raises(Exception) as exc_info:
        routes_memory.start_memory_scan(evidence.id, MemoryStartScanRequest(profile="metadata_only"), db_session)

    assert getattr(exc_info.value, "status_code", None) == 400
    assert "Authorization acknowledgement" in str(getattr(exc_info.value, "detail", ""))
    assert db_session.query(MemoryScanRun).count() == 0


def test_memory_scan_disabled_by_default(db_session, monkeypatch: pytest.MonkeyPatch) -> None:
    _case(db_session)
    evidence = _evidence(db_session)
    monkeypatch.setattr(routes_memory, "settings", SimpleNamespace(memory_analysis_enabled=False))

    response = routes_memory.start_memory_scan(evidence.id, MemoryStartScanRequest(authorization_acknowledged=True), db_session)

    assert response.status == "disabled"
    assert response.accepted is False
    assert db_session.query(MemoryScanRun).count() == 0


def test_memory_scan_rejects_non_memory_evidence(db_session, monkeypatch: pytest.MonkeyPatch) -> None:
    _case(db_session)
    evidence = _evidence(db_session, evidence_id=DISK_EVIDENCE_ID, evidence_type=EvidenceType.evtx)
    monkeypatch.setattr(routes_memory, "settings", SimpleNamespace(memory_analysis_enabled=True))

    with pytest.raises(Exception) as exc_info:
        routes_memory.start_memory_scan(evidence.id, MemoryStartScanRequest(authorization_acknowledged=True), db_session)

    assert getattr(exc_info.value, "status_code", None) == 400


def test_memory_scan_external_execution_disabled_rejects_without_run(db_session, monkeypatch: pytest.MonkeyPatch) -> None:
    _case(db_session)
    evidence = _evidence(db_session)
    monkeypatch.setattr(routes_memory, "settings", SimpleNamespace(memory_analysis_enabled=True, memory_allow_external_tool_execution=False))

    with pytest.raises(Exception) as exc_info:
        routes_memory.start_memory_scan(evidence.id, MemoryStartScanRequest(authorization_acknowledged=True), db_session)

    assert getattr(exc_info.value, "status_code", None) == 403
    assert db_session.query(MemoryScanRun).count() == 0


def test_memory_scan_queues_metadata_only_when_enabled(db_session, monkeypatch: pytest.MonkeyPatch) -> None:
    _case(db_session)
    evidence = _evidence(db_session)
    monkeypatch.setattr(routes_memory, "settings", SimpleNamespace(memory_analysis_enabled=True, memory_allow_external_tool_execution=True))
    monkeypatch.setattr(routes_memory, "get_memory_backend_overview", lambda: {"backends": [{"backend": "volatility3", "ready": True}]})
    monkeypatch.setattr(routes_memory, "validate_memory_execution_request", lambda _db, _evidence_id: object())
    monkeypatch.setattr(memory_execution, "validate_memory_execution_request", lambda _db, _evidence_id: SimpleNamespace(evidence=evidence))
    monkeypatch.setattr(routes_memory, "enqueue_memory_metadata_scan", lambda _run_id: "job-1")

    response = routes_memory.start_memory_scan(evidence.id, MemoryStartScanRequest(authorization_acknowledged=True), db_session)
    run = db_session.query(MemoryScanRun).one()
    plugin_run = db_session.query(MemoryPluginRun).one()

    assert response.accepted is True
    assert response.status == "queued"
    assert run.profile == "metadata_only"
    assert run.backend == "volatility3"
    assert run.plugin_count == 1
    assert run.worker_task_id == "job-1"
    assert plugin_run.plugin == "windows.info"


def test_memory_profiles_resolve_server_side(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(memory_execution.backend_readiness, "get_settings", lambda: _backend_settings(memory_process_profile_enabled=True))

    assert memory_execution.resolve_profile_plugins("metadata_only") == ["windows.info"]
    assert memory_execution.resolve_profile_plugins("processes_basic") == ["windows.info", "windows.pslist", "windows.pstree", "windows.cmdline"]
    assert memory_execution.resolve_profile_plugins("processes_extended") == ["windows.info", "windows.pslist", "windows.pstree", "windows.psscan", "windows.cmdline"]


def test_process_profile_disabled_by_default(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(memory_execution.backend_readiness, "get_settings", lambda: _backend_settings(memory_process_profile_enabled=False))

    with pytest.raises(memory_validation.MemoryExecutionValidationError) as exc_info:
        memory_execution.resolve_profile_plugins("processes_basic")

    assert exc_info.value.code == "PROCESS_PROFILE_DISABLED"


def test_unknown_memory_profile_rejected(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(memory_execution.backend_readiness, "get_settings", lambda: _backend_settings(memory_process_profile_enabled=True))

    with pytest.raises(memory_validation.MemoryExecutionValidationError) as exc_info:
        memory_execution.resolve_profile_plugins("windows.netscan")

    assert exc_info.value.code == "UNKNOWN_PROFILE"


def test_memory_evidence_does_not_create_normalized_events(db_session, monkeypatch: pytest.MonkeyPatch) -> None:
    _case(db_session)
    evidence = _evidence(db_session)
    monkeypatch.setattr(routes_memory, "settings", SimpleNamespace(memory_analysis_enabled=False))

    routes_memory.start_memory_scan(evidence.id, None, db_session)

    assert db_session.query(Artifact).filter(Artifact.evidence_id == evidence.id).count() == 0
    assert db_session.query(MemoryArtifactSummary).filter(MemoryArtifactSummary.evidence_id == evidence.id).count() == 0


def test_memory_evidence_does_not_write_to_existing_events_index(db_session, monkeypatch: pytest.MonkeyPatch) -> None:
    _case(db_session)
    evidence = _evidence(db_session)
    monkeypatch.setattr(routes_memory, "settings", SimpleNamespace(memory_analysis_enabled=False))
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
        "allowed_memory_profiles": ["metadata_only", "processes_basic", "processes_extended"],
        "allowed_memory_plugins": ["windows.info", "windows.pslist", "windows.pstree", "windows.psscan", "windows.cmdline"],
        "default_memory_profile": "metadata_only",
        "memory_process_profile_enabled": False,
        "memory_max_process_rows": 100000,
        "memory_max_command_line_length": 16384,
        "memory_max_raw_field_length": 65536,
        "memory_execution_mode": "external_command",
        "memory_queue_name": "memory",
        "memory_require_dedicated_worker": True,
        "memory_symbol_network_access_enabled": False,
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


def test_memory_validation_rejects_non_regular_file(db_session, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    _case(db_session)
    evidence_dir = tmp_path / "data" / "evidence" / CASE_ID / MEMORY_EVIDENCE_ID
    evidence_dir.mkdir(parents=True)
    evidence = _evidence(db_session, stored_path=str(evidence_dir))
    monkeypatch.setattr(memory_validation, "get_settings", lambda: SimpleNamespace(backend_data_dir=tmp_path / "data", allowed_evidence_roots=[] , memory_max_upload_size=10_000))

    with pytest.raises(memory_validation.MemoryExecutionValidationError) as exc_info:
        memory_validation.validate_memory_execution_request(db_session, evidence.id)

    assert exc_info.value.code == "UNSAFE_EVIDENCE_FILE"


def test_memory_validation_accepts_regular_uploaded_file(db_session, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    _case(db_session)
    evidence_file = tmp_path / "data" / "evidence" / CASE_ID / MEMORY_EVIDENCE_ID / "original" / "memory.mem"
    evidence_file.parent.mkdir(parents=True)
    evidence_file.write_bytes(b"synthetic")
    evidence = _evidence(db_session, stored_path=str(evidence_file))
    monkeypatch.setattr(memory_validation, "get_settings", lambda: SimpleNamespace(backend_data_dir=tmp_path / "data", allowed_evidence_roots=[] , memory_max_upload_size=10_000))

    validated = memory_validation.validate_memory_execution_request(db_session, evidence.id)

    assert validated.path == evidence_file.resolve()


def test_memory_scan_prevents_duplicate_active_run(db_session, monkeypatch: pytest.MonkeyPatch) -> None:
    _case(db_session)
    evidence = _evidence(db_session)
    db_session.add(MemoryScanRun(case_id=CASE_ID, evidence_id=evidence.id, profile="metadata_only", status="running"))
    db_session.commit()
    monkeypatch.setattr(routes_memory, "settings", SimpleNamespace(memory_analysis_enabled=True, memory_allow_external_tool_execution=True))
    monkeypatch.setattr(routes_memory, "get_memory_backend_overview", lambda: {"backends": [{"backend": "volatility3", "ready": True}]})
    monkeypatch.setattr(routes_memory, "validate_memory_execution_request", lambda _db, _evidence_id: object())

    with pytest.raises(Exception) as exc_info:
        routes_memory.start_memory_scan(evidence.id, MemoryStartScanRequest(authorization_acknowledged=True), db_session)

    assert getattr(exc_info.value, "status_code", None) == 409


def test_volatility_runner_uses_fixed_argv_and_shell_false(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    evidence_path = tmp_path / "memory.mem"
    evidence_path.write_bytes(b"synthetic")
    calls: dict = {}

    class FakeProcess:
        pid = 12345
        returncode = 0

        def communicate(self, timeout):
            calls["timeout"] = timeout
            return b'{"Kernel Base":"0xf8000000"}', b""

    def fake_popen(args, **kwargs):
        calls["args"] = args
        calls["kwargs"] = kwargs
        return FakeProcess()

    monkeypatch.setattr(volatility_runner, "get_settings", lambda: SimpleNamespace(volatility3_command="vol", memory_plugin_timeout_seconds=5, memory_plugin_output_max_bytes=10_000))
    monkeypatch.setattr(volatility_runner, "resolve_configured_executable", lambda _command: (True, "/usr/bin/vol", "vol", None))
    monkeypatch.setattr(volatility_runner.subprocess, "Popen", fake_popen)

    result = volatility_runner.run_windows_info(evidence_path, tmp_path)

    assert calls["args"] == ["/usr/bin/vol", "-f", str(evidence_path), "-r", "json", "windows.info"]
    assert calls["kwargs"]["shell"] is False
    assert result.argv_display == ["vol", "-f", "[evidence]", "-r", "json", "windows.info"]


def test_volatility_runner_uses_fixed_process_plugin_argv(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    evidence_path = tmp_path / "memory.mem"
    evidence_path.write_bytes(b"synthetic")
    calls: dict = {}

    class FakeProcess:
        pid = 12345
        returncode = 0

        def communicate(self, timeout):
            return b"[]", b""

    monkeypatch.setattr(volatility_runner, "get_settings", lambda: SimpleNamespace(volatility3_command="vol", memory_plugin_timeout_seconds=5, memory_plugin_output_max_bytes=10_000))
    monkeypatch.setattr(volatility_runner, "resolve_configured_executable", lambda _command: (True, "/usr/bin/vol", "vol", None))
    monkeypatch.setattr(volatility_runner.subprocess, "Popen", lambda args, **kwargs: calls.update({"args": args, "kwargs": kwargs}) or FakeProcess())

    volatility_runner.run_plugin("windows.pslist", evidence_path, tmp_path)

    assert calls["args"] == ["/usr/bin/vol", "-f", str(evidence_path), "-r", "json", "windows.pslist"]
    assert calls["kwargs"]["shell"] is False


def test_volatility_runner_rejects_unallowed_plugin(tmp_path: Path) -> None:
    with pytest.raises(volatility_runner.VolatilityRunnerError) as exc_info:
        volatility_runner.build_plugin_argv("/usr/bin/vol", tmp_path / "memory.mem", "windows.netscan")

    assert exc_info.value.code == "PLUGIN_NOT_ALLOWED"


def test_volatility_runner_timeout_terminates_process_group(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    evidence_path = tmp_path / "memory.mem"
    evidence_path.write_bytes(b"synthetic")
    signals: list[int] = []

    class FakeProcess:
        pid = 12345
        returncode = None

        def communicate(self, timeout):
            raise subprocess.TimeoutExpired(cmd=["vol"], timeout=timeout)

        def wait(self, timeout):
            raise TimeoutError()

        def kill(self):
            signals.append(9)

    monkeypatch.setattr(volatility_runner, "get_settings", lambda: SimpleNamespace(volatility3_command="vol", memory_plugin_timeout_seconds=1, memory_plugin_output_max_bytes=10_000))
    monkeypatch.setattr(volatility_runner, "resolve_configured_executable", lambda _command: (True, "/usr/bin/vol", "vol", None))
    monkeypatch.setattr(volatility_runner.subprocess, "Popen", lambda *_args, **_kwargs: FakeProcess())
    monkeypatch.setattr(volatility_runner.os, "killpg", lambda _pid, sig: signals.append(sig))

    with pytest.raises(volatility_runner.VolatilityRunnerError) as exc_info:
        volatility_runner.run_windows_info(evidence_path, tmp_path)

    assert exc_info.value.code == "PLUGIN_TIMEOUT"
    assert signals


def test_volatility_runner_output_size_enforced(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    evidence_path = tmp_path / "memory.mem"
    evidence_path.write_bytes(b"synthetic")

    class FakeProcess:
        pid = 12345
        returncode = 0

        def communicate(self, timeout):
            return b"x" * 20, b""

    monkeypatch.setattr(volatility_runner, "get_settings", lambda: SimpleNamespace(volatility3_command="vol", memory_plugin_timeout_seconds=1, memory_plugin_output_max_bytes=10))
    monkeypatch.setattr(volatility_runner, "resolve_configured_executable", lambda _command: (True, "/usr/bin/vol", "vol", None))
    monkeypatch.setattr(volatility_runner.subprocess, "Popen", lambda *_args, **_kwargs: FakeProcess())

    with pytest.raises(volatility_runner.VolatilityRunnerError) as exc_info:
        volatility_runner.run_windows_info(evidence_path, tmp_path)

    assert exc_info.value.code == "OUTPUT_TOO_LARGE"


def test_windows_info_normalizer_handles_missing_fields() -> None:
    document = memory_normalizers.normalize_windows_info(
        {"Kernel Base": "0xf8000000", "Machine": "x64"},
        case_id=CASE_ID,
        evidence_id=MEMORY_EVIDENCE_ID,
        memory_run_id="run-1",
        memory_plugin_run_id="plugin-1",
        backend_version="Volatility 3 Framework 2.8.0",
    )

    assert document["memory_artifact_type"] == "memory_system_info"
    assert document["plugin"] == "windows.info"
    assert document["os"]["kernel_base"] == "0xf8000000"
    assert document["os"]["machine_type"] == "x64"
    assert document["memory"]["dtb"] is None


def test_process_normalizers_merge_pslist_pstree_psscan_cmdline() -> None:
    pslist = memory_normalizers.normalize_windows_pslist([
        {"PID": 4, "PPID": 0, "ImageFileName": "System", "Offset(V)": "0x1000"},
        {"PID": 1000, "PPID": 4, "ImageFileName": "sample-app.exe", "Offset(V)": "0x2000", "CreateTime": "2026-06-16T00:00:00Z"},
    ])
    pstree = memory_normalizers.normalize_windows_pstree([
        {"PID": 1000, "PPID": 4, "Name": "sample-app.exe", "Offset(V)": "0x2000", "CreateTime": "2026-06-16T00:00:00Z"},
    ])
    psscan = memory_normalizers.normalize_windows_psscan([
        {"PID": 2000, "PPID": 1000, "ImageFileName": "finished-task.exe", "Offset(P)": "0x3000", "ExitTime": "2026-06-16T00:05:00Z"},
    ])
    cmdline = memory_normalizers.normalize_windows_cmdline([
        {"PID": 1000, "Args": "C:\\\\Program Files\\\\Example\\\\sample-app.exe --safe-mode", "Offset(V)": "0x2000", "CreateTime": "2026-06-16T00:00:00Z"},
    ])

    merged = memory_normalizers.merge_memory_process_results([pslist, pstree, psscan, cmdline], case_id=CASE_ID, evidence_id=MEMORY_EVIDENCE_ID, memory_run_id="run-1")

    assert len(merged["processes"]) == 3
    sample = next(item for item in merged["processes"] if item["process"]["pid"] == 1000)
    assert sample["process"]["command_line"].endswith("--safe-mode")
    assert sample["visibility"]["pslist"] is True
    assert sample["visibility"]["pstree"] is True
    scanned_only = next(item for item in merged["processes"] if item["process"]["pid"] == 2000)
    assert scanned_only["visibility"]["psscan"] is True
    assert scanned_only["state"]["hidden_candidate"] is False
    assert "not_present_in_pslist_result" in scanned_only["warnings"]
    assert len(merged["edges"]) == 1


def test_process_normalizer_invalid_pid_warns() -> None:
    normalized = memory_normalizers.normalize_windows_pslist([{"PID": "not-a-pid", "ImageFileName": "example.exe"}])

    assert normalized["processes"] == []
    assert "missing_or_invalid_pid" in normalized["warnings"]


def test_execution_indexing_failure_retains_raw_output(db_session, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    _case(db_session)
    evidence_file = tmp_path / "data" / "evidence" / CASE_ID / MEMORY_EVIDENCE_ID / "original" / "memory.mem"
    evidence_file.parent.mkdir(parents=True)
    evidence_file.write_bytes(b"synthetic")
    evidence = _evidence(db_session, stored_path=str(evidence_file))
    run = MemoryScanRun(case_id=CASE_ID, evidence_id=evidence.id, backend="volatility3", profile="metadata_only", status="queued", requested_plugin_count=1, plugin_count=1)
    db_session.add(run)
    db_session.commit()
    db_session.add(MemoryPluginRun(memory_scan_run_id=run.id, case_id=CASE_ID, evidence_id=evidence.id, plugin="windows.info", status="pending"))
    db_session.commit()

    class SessionContext:
        def __enter__(self):
            return db_session

        def __exit__(self, *_args):
            return False

    monkeypatch.setattr(memory_execution, "SessionLocal", lambda: SessionContext())
    monkeypatch.setattr(memory_execution, "validate_memory_execution_request", lambda _db, _evidence_id: SimpleNamespace(evidence=evidence, path=evidence_file, size_bytes=evidence_file.stat().st_size))
    monkeypatch.setattr(memory_execution.backend_readiness, "check_volatility3_backend", lambda: {"ready": True, "version": "Volatility 3 Framework 2.8.0"})
    monkeypatch.setattr(memory_execution, "run_plugin", lambda _plugin, _path, _work_dir: SimpleNamespace(argv_display=["vol", "-f", "[evidence]", "-r", "json", "windows.info"], stdout=b'{"Kernel Base":"0xf8000000"}', stderr=b"", duration_ms=7))
    monkeypatch.setattr(memory_execution, "index_memory_system_info", lambda _case_id, _document: (_ for _ in ()).throw(RuntimeError("/secret/index failed")))
    monkeypatch.setattr(memory_execution, "memory_run_dir", lambda _case_id, _evidence_id, run_id: tmp_path / "data" / "evidence" / CASE_ID / MEMORY_EVIDENCE_ID / "memory" / "runs" / run_id)
    monkeypatch.setattr(memory_execution, "relative_to_data_dir", lambda path: str(path.relative_to(tmp_path / "data")))
    monkeypatch.setattr(memory_execution, "write_atomic_bytes", lambda path, data: {"path": str(path.relative_to(tmp_path / "data")), "sha256": "a" * 64, "size": len(data)})
    monkeypatch.setattr(memory_execution, "write_atomic_json", lambda path, payload: {"path": str(path.relative_to(tmp_path / "data")), "sha256": "b" * 64, "size": 12})

    memory_execution.run_memory_metadata_scan(run.id)
    db_session.refresh(run)
    plugin_run = db_session.query(MemoryPluginRun).filter(MemoryPluginRun.memory_scan_run_id == run.id).one()

    assert run.status == "completed_with_errors"
    assert run.error_log["code"] == "INDEXING_FAILED"
    assert plugin_run.status == "completed"
    assert plugin_run.output_sha256
    assert "/secret" not in run.error_log["message"]


def test_indexing_uses_memory_index_only(monkeypatch: pytest.MonkeyPatch) -> None:
    calls = {}

    class Indices:
        def exists(self, index):
            calls["exists"] = index
            return True

    class Client:
        indices = Indices()

        def index(self, index, id, body, refresh):
            calls["index"] = index
            calls["id"] = id
            calls["body"] = body
            return {"_id": id, "result": "created"}

    monkeypatch.setattr(memory_indexing, "get_opensearch_client", lambda: Client())

    memory_indexing.index_memory_system_info(CASE_ID, {"memory_plugin_run_id": "plugin-1", "memory_run_id": "run-1"})

    assert calls["index"] == f"dfir-memory-{CASE_ID}"


def test_dedicated_worker_readiness_does_not_require_backend_vol(monkeypatch: pytest.MonkeyPatch) -> None:
    class RedisStub:
        @classmethod
        def from_url(cls, _url):
            return cls()

        def ping(self):
            return True

    capability = {
        "healthy": True,
        "queue": "memory",
        "volatility_version": "Volatility 3 Framework 2.28.0",
        "supported_profiles": ["metadata_only", "processes_basic", "processes_extended"],
        "supported_plugins": ["windows.info", "windows.pslist", "windows.pstree", "windows.psscan", "windows.cmdline"],
        "symbol_network_enabled": False,
    }
    monkeypatch.setattr(backend_readiness, "get_settings", lambda: _backend_settings(memory_execution_mode="dedicated_worker", memory_analysis_enabled=True, memory_allow_external_tool_execution=True, memory_process_profile_enabled=True, redis_url="redis://redis:6379/0"))
    monkeypatch.setattr(backend_readiness, "Redis", RedisStub)
    monkeypatch.setattr(backend_readiness, "list_memory_worker_capabilities", lambda _redis: [capability])
    monkeypatch.setattr(backend_readiness.shutil, "which", lambda _command: None)

    status = backend_readiness.check_volatility3_backend()

    assert status["ready"] is True
    assert status["execution_mode"] == "dedicated_worker"
    assert status["dedicated_worker_online"] is True
    assert status["backend_version"] == "Volatility 3 Framework 2.28.0"


def test_dedicated_worker_offline_is_not_ready(monkeypatch: pytest.MonkeyPatch) -> None:
    class RedisStub:
        @classmethod
        def from_url(cls, _url):
            return cls()

        def ping(self):
            return True

    monkeypatch.setattr(backend_readiness, "get_settings", lambda: _backend_settings(memory_execution_mode="dedicated_worker", memory_analysis_enabled=True, memory_allow_external_tool_execution=True, redis_url="redis://redis:6379/0"))
    monkeypatch.setattr(backend_readiness, "Redis", RedisStub)
    monkeypatch.setattr(backend_readiness, "list_memory_worker_capabilities", lambda _redis: [])

    status = backend_readiness.check_volatility3_backend()

    assert status["ready"] is False
    assert status["dedicated_worker_online"] is False
    assert status["error_code"] == "memory_worker_offline"


def test_external_mode_observes_optional_memory_worker(monkeypatch: pytest.MonkeyPatch) -> None:
    class RedisStub:
        @classmethod
        def from_url(cls, _url):
            return cls()

        def ping(self):
            return True

    capability = {
        "healthy": True,
        "queue": "memory",
        "volatility_version": "Volatility 3 Framework 2.28.0",
        "supported_profiles": ["metadata_only"],
        "supported_plugins": ["windows.info"],
        "symbol_network_enabled": False,
    }
    monkeypatch.setattr(backend_readiness, "get_settings", lambda: _backend_settings(memory_execution_mode="external_command", memory_analysis_enabled=False, redis_url="redis://redis:6379/0"))
    monkeypatch.setattr(backend_readiness, "Redis", RedisStub)
    monkeypatch.setattr(backend_readiness, "list_memory_worker_capabilities", lambda _redis: [capability])
    monkeypatch.setattr(backend_readiness.shutil, "which", lambda _command: None)

    status = backend_readiness.check_volatility3_backend()

    assert status["ready"] is False
    assert status["status"] == "not_found"
    assert status["dedicated_worker_online"] is True
    assert status["backend_version"] == "Volatility 3 Framework 2.28.0"


def test_memory_worker_capability_prefers_installed_package_version(monkeypatch: pytest.MonkeyPatch) -> None:
    class Result:
        returncode = 0
        stdout = "Change the default path (/volatility-cache)\n"
        stderr = ""

    monkeypatch.setattr(worker_capability, "get_settings", lambda: _backend_settings(volatility3_command="vol"))
    monkeypatch.setattr(worker_capability.shutil, "which", lambda _command: "/usr/local/bin/vol")
    monkeypatch.setattr(worker_capability.subprocess, "run", lambda *_args, **_kwargs: Result())
    monkeypatch.setattr(worker_capability.metadata, "version", lambda package: "2.28.0" if package == "volatility3" else None)

    capability = worker_capability.build_memory_worker_capability()

    assert capability["healthy"] is True
    assert capability["volatility_version"] == "Volatility 3 Framework 2.28.0"


def test_memory_enqueue_uses_dedicated_queue(monkeypatch: pytest.MonkeyPatch) -> None:
    from app.workers import tasks as worker_tasks

    calls = []

    class QueueStub:
        def __init__(self, name):
            self.name = name

        def enqueue(self, func_name, run_id, job_timeout):
            calls.append((self.name, func_name, run_id, job_timeout))
            return SimpleNamespace(id=f"{self.name}-job")

    monkeypatch.setattr(worker_tasks, "settings", SimpleNamespace(memory_execution_mode="dedicated_worker", memory_job_timeout_seconds=900))
    monkeypatch.setattr(worker_tasks, "memory_queue", QueueStub("memory"))
    monkeypatch.setattr(worker_tasks, "analysis_queue", QueueStub("dfir-analysis"))

    job_id = worker_tasks.enqueue_memory_metadata_scan("run-1")

    assert job_id == "memory-job"
    assert calls == [("memory", "app.workers.tasks.run_memory_metadata_scan", "run-1", 900)]


def test_memory_output_dir_relative_path(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    output_root = tmp_path / "memory-output"
    monkeypatch.setattr(memory_storage, "get_settings", lambda: SimpleNamespace(backend_data_dir=tmp_path / "data", memory_output_root=output_root, memory_plugin_output_max_bytes=1024))

    run_dir = memory_storage.memory_run_dir(CASE_ID, MEMORY_EVIDENCE_ID, "run-1")
    info = memory_storage.write_atomic_bytes(run_dir / "windows.info.json", b"{}")

    assert info["path"] == f"memory-output/evidence/{CASE_ID}/{MEMORY_EVIDENCE_ID}/memory/runs/run-1/windows.info.json"
