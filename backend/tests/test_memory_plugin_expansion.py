from __future__ import annotations

from pathlib import Path
from uuid import uuid4

from sqlalchemy import create_engine
from sqlalchemy.orm import Session, sessionmaker

from app.core.database import Base
from app.models.case import Case
from app.models.evidence import Evidence, EvidenceStorageMode, EvidenceType, IngestStatus
from app.models.memory import MemoryPluginRun, MemoryScanRun
from app.services.memory import execution as execution_module
from app.services.memory.execution import PROFILE_PLUGINS, create_memory_metadata_run, run_memory_metadata_scan
from app.services.memory.validation import ValidatedMemoryEvidence
from app.services.memory.volatility_runner import VolatilityRunResult, VolatilityRunnerError


def _settings():
    from app.core.config import Settings

    base = Settings()
    object.__setattr__(base, "memory_process_profile_enabled", True)
    object.__setattr__(base, "memory_allowed_profiles", "metadata_only,processes_basic,processes_extended,network_basic,modules_basic,handles_basic,kernel_basic,suspicious_memory")
    object.__setattr__(base, "memory_allowed_plugins", "windows.info,windows.pslist,windows.pstree,windows.psscan,windows.cmdline,windows.envars,windows.getsids,windows.privileges,windows.netscan,windows.netstat,windows.dlllist,windows.ldrmodules,windows.handles,windows.modules,windows.driverscan,windows.malfind,windows.vadinfo")
    return base


def _db(tmp_path, monkeypatch) -> tuple[Session, Evidence]:
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

    def validate(db, evidence_id):
        return ValidatedMemoryEvidence(evidence=db.get(Evidence, evidence_id), path=evidence_path, size_bytes=evidence_path.stat().st_size)

    monkeypatch.setattr(execution_module, "validate_memory_execution_request", validate)
    monkeypatch.setattr(execution_module.backend_readiness, "get_settings", _settings)
    monkeypatch.setattr(execution_module.backend_readiness, "check_volatility3_backend", lambda: {"ready": True, "version": "2.28.0"})
    monkeypatch.setattr(execution_module, "validate_current_process_output_access", lambda: None)
    monkeypatch.setattr(execution_module, "_advance_batch_after_run", lambda run: None)
    monkeypatch.setattr(execution_module, "index_memory_documents", lambda case_id, documents: {"index": "memory", "indexed": len(documents), "errors": 0})
    monkeypatch.setattr(execution_module, "index_artifact_documents", lambda case_id, documents: {"index": "artifact", "indexed": len(documents), "errors": 0})
    monkeypatch.setattr(execution_module, "link_process_entities", lambda *args, **kwargs: None)

    class _SessionCtx:
        def __enter__(self):
            return session

        def __exit__(self, *args):
            return False

    monkeypatch.setattr(execution_module, "SessionLocal", lambda: _SessionCtx())
    return session, ev


def _result(payload: bytes = b"[]") -> VolatilityRunResult:
    return VolatilityRunResult(argv_display=["vol", "-f", "[evidence]", "-r", "json"], stdout=payload, stderr=b"", duration_ms=5)


def test_expanded_profiles_have_deterministic_plugin_order() -> None:
    assert PROFILE_PLUGINS["processes_extended"] == ["windows.psscan", "windows.envars", "windows.getsids", "windows.privileges"]
    assert PROFILE_PLUGINS["network_basic"] == ["windows.netscan", "windows.netstat"]
    assert PROFILE_PLUGINS["suspicious_memory"] == ["windows.malfind", "windows.vadinfo"]


def test_create_run_creates_one_plugin_run_per_profile_plugin(tmp_path, monkeypatch) -> None:
    db, ev = _db(tmp_path, monkeypatch)
    run = create_memory_metadata_run(db, ev.id, "network_basic")
    assert run.plugin_count == 2
    assert [item.plugin for item in run.plugin_runs] == ["windows.netscan", "windows.netstat"]


def test_unavailable_plugin_is_skipped_without_blocking_available_plugin(tmp_path, monkeypatch) -> None:
    db, ev = _db(tmp_path, monkeypatch)
    monkeypatch.setattr(execution_module.volatility_runner, "probe_volatility_plugin", lambda plugin: plugin != "windows.netstat")
    monkeypatch.setattr(execution_module, "run_plugin", lambda *args, **kwargs: _result())
    run = create_memory_metadata_run(db, ev.id, "network_basic")
    run.status = "queued"
    db.commit()
    run_memory_metadata_scan(run.id)
    refreshed = db.get(MemoryScanRun, run.id)
    assert refreshed.status == "completed_with_errors"
    states = {item.plugin: item.status for item in refreshed.plugin_runs}
    assert states == {"windows.netscan": "completed", "windows.netstat": "skipped_unsupported"}


def test_partial_plugin_failure_continues_later_plugins(tmp_path, monkeypatch) -> None:
    db, ev = _db(tmp_path, monkeypatch)
    monkeypatch.setattr(execution_module.volatility_runner, "probe_volatility_plugin", lambda plugin: True)

    def fake_run(plugin, *args, **kwargs):
        if plugin == "windows.malfind":
            raise VolatilityRunnerError("execution_error", "malfind failed", stderr=b"boom", return_code=1)
        return _result()

    monkeypatch.setattr(execution_module, "run_plugin", fake_run)
    run = create_memory_metadata_run(db, ev.id, "suspicious_memory")
    run.status = "queued"
    db.commit()
    run_memory_metadata_scan(run.id)
    refreshed = db.get(MemoryScanRun, run.id)
    assert refreshed.status == "completed_with_errors"
    assert {item.plugin: item.status for item in refreshed.plugin_runs} == {"windows.malfind": "failed", "windows.vadinfo": "completed"}


def test_empty_json_is_success_and_invalid_json_is_plugin_failure(tmp_path, monkeypatch) -> None:
    db, ev = _db(tmp_path, monkeypatch)
    monkeypatch.setattr(execution_module.volatility_runner, "probe_volatility_plugin", lambda plugin: True)
    monkeypatch.setattr(execution_module, "run_plugin", lambda *args, **kwargs: _result(b"[]"))
    empty_run = create_memory_metadata_run(db, ev.id, "network_basic")
    empty_run.status = "queued"
    db.commit()
    run_memory_metadata_scan(empty_run.id)
    assert db.get(MemoryScanRun, empty_run.id).status == "completed"

    monkeypatch.setattr(execution_module, "run_plugin", lambda *args, **kwargs: _result(b"not-json"))
    bad_run = create_memory_metadata_run(db, ev.id, "network_basic")
    bad_run.status = "queued"
    db.commit()
    run_memory_metadata_scan(bad_run.id)
    assert db.get(MemoryScanRun, bad_run.id).status == "completed_with_errors"
    assert db.query(MemoryPluginRun).filter(MemoryPluginRun.memory_scan_run_id == bad_run.id, MemoryPluginRun.status == "failed").count() == 2


def test_expanded_plugins_pass_per_plugin_timeout_overrides(tmp_path, monkeypatch) -> None:
    db, ev = _db(tmp_path, monkeypatch)
    monkeypatch.setattr(execution_module.volatility_runner, "probe_volatility_plugin", lambda plugin: True)
    calls: list[tuple[str, int | None, int | None]] = []

    def fake_run(plugin, *args, timeout_seconds=None, max_output_bytes=None, **kwargs):
        calls.append((plugin, timeout_seconds, max_output_bytes))
        return _result()

    monkeypatch.setattr(execution_module, "run_plugin", fake_run)
    run = create_memory_metadata_run(db, ev.id, "suspicious_memory")
    run.status = "queued"
    db.commit()
    run_memory_metadata_scan(run.id)
    assert calls == [
        ("windows.malfind", 1800, 32 * 1024 * 1024),
        ("windows.vadinfo", 1800, 32 * 1024 * 1024),
    ]


def test_process_observation_pid_values_are_normalized() -> None:
    docs = execution_module._normalize_process_observation_payload(
        "windows.envars",
        [{"PID": 999999999999, "Variable": "Path", "Value": "C:\\Windows"}],
        case_id="case",
        evidence_id="ev",
        scan_run_id="run",
        plugin_run_id="plugin-run",
    )
    assert docs[0]["process"]["pid"] is None
    assert docs[0]["observed"]["pid"] is None
    assert docs[0]["source_fields"]["Variable"] == "Path"
