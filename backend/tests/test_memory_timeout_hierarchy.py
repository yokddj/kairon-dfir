from __future__ import annotations

from pathlib import Path
from uuid import uuid4

import pytest
import subprocess
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from app.core.database import Base
from app.models.case import Case
from app.models.evidence import Evidence, EvidenceStorageMode, EvidenceType, IngestStatus
from app.models.memory import MemoryPluginRun, MemoryScanRun
from app.services.memory import execution
from app.services.memory import volatility_runner


def _settings(*, enabled_plugins: str | None = None):
    from app.core.config import Settings

    settings = Settings()
    object.__setattr__(settings, "memory_analysis_enabled", True)
    object.__setattr__(settings, "memory_allow_external_tool_execution", True)
    object.__setattr__(settings, "memory_process_profile_enabled", True)
    object.__setattr__(settings, "memory_profile_timeout_overhead_seconds", 300)
    object.__setattr__(settings, "memory_job_timeout_cleanup_margin_seconds", 300)
    object.__setattr__(settings, "memory_plugin_timeout_seconds", 600)
    object.__setattr__(
        settings,
        "memory_allowed_plugins",
        enabled_plugins
        or "windows.info,windows.pslist,windows.pstree,windows.psscan,windows.cmdline,windows.envars,windows.getsids,windows.privileges,windows.netscan,windows.netstat,windows.dlllist,windows.ldrmodules,windows.handles,windows.modules,windows.driverscan,windows.malfind,windows.vadinfo",
    )
    return settings


@pytest.fixture(autouse=True)
def settings(monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setattr(execution, "get_settings", _settings)
    monkeypatch.setattr(execution.backend_readiness, "get_settings", _settings)


def test_profile_timeout_values_are_derived_from_plugin_timeouts() -> None:
    expected = {
        "metadata_only": (600 + 300, 600 + 300 + 300),
        "processes_basic": (600 * 4 + 300, 600 * 4 + 600),
        "processes_extended": (900 * 4 + 300, 900 * 4 + 600),
        "network_basic": (300 + 1200 + 300, 300 + 1200 + 600),
        "suspicious_memory": (1800 + 1800 + 300, 1800 + 1800 + 600),
    }
    for profile, (profile_timeout, job_timeout) in expected.items():
        plan = execution.derive_memory_timeout_plan(profile)
        assert plan["profile_timeout_seconds"] == profile_timeout
        assert plan["job_timeout_seconds"] == job_timeout
        assert plan["job_timeout_seconds"] > plan["profile_timeout_seconds"]
        assert plan["profile_timeout_seconds"] > max(item["timeout_seconds"] for item in plan["included_plugins"])
    assert execution.derive_memory_timeout_plan("suspicious_memory")["job_timeout_seconds"] == 4200


def test_disabled_known_unavailable_and_unknown_plugins_are_handled(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(execution, "get_settings", lambda: _settings(enabled_plugins="windows.netscan,windows.netstat"))
    plan = execution.derive_memory_timeout_plan("network_basic", plugin_states={"windows.netstat": "unavailable"})
    assert [item["plugin"] for item in plan["included_plugins"]] == ["windows.netscan"]
    assert [item["plugin"] for item in plan["excluded_plugins"]] == ["windows.netstat"]
    assert plan["profile_timeout_seconds"] == 300 + 300

    unknown = execution.derive_memory_timeout_plan("network_basic", plugin_states={})
    assert [item["plugin"] for item in unknown["included_plugins"]] == ["windows.netscan", "windows.netstat"]
    assert unknown["profile_timeout_seconds"] == 300 + 1200 + 300


def test_enqueue_uses_derived_job_timeout_and_persists_policy(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    from app.workers import tasks

    engine = create_engine("sqlite:///:memory:", connect_args={"check_same_thread": False})
    Base.metadata.create_all(bind=engine)
    SessionLocal = sessionmaker(bind=engine)
    session = SessionLocal()
    case = Case(id=str(uuid4()), name="case", description="", status="open", mode="investigation")
    evidence_path = tmp_path / "memory.dmp"
    evidence_path.write_bytes(b"memory")
    evidence = Evidence(
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
    run = MemoryScanRun(
        id=str(uuid4()),
        case_id=case.id,
        evidence_id=evidence.id,
        backend="volatility3",
        profile="suspicious_memory",
        status="pending",
        requested_plugin_count=2,
        plugin_count=2,
        metadata_json={"plugins": ["windows.malfind", "windows.vadinfo"], "profile": "suspicious_memory"},
    )
    session.add_all([case, evidence, run])
    session.commit()
    run_id = run.id
    session.close()

    captured: dict[str, int] = {}

    class QueueStub:
        def enqueue(self, *args, **kwargs):
            captured["job_timeout"] = kwargs["job_timeout"]
            return type("Job", (), {"id": "job-1"})()

    monkeypatch.setattr(tasks, "SessionLocal", SessionLocal)
    monkeypatch.setattr(tasks, "memory_queue", QueueStub())
    object.__setattr__(tasks.settings, "memory_worker_mode", "dedicated_worker")
    object.__setattr__(tasks.settings, "memory_job_timeout_seconds", 900)
    monkeypatch.setattr(execution, "get_settings", _settings)

    assert tasks.enqueue_memory_metadata_scan(run_id) == "job-1"
    assert captured["job_timeout"] == 4200

    with SessionLocal() as verify:
        persisted = verify.get(MemoryScanRun, run_id)
        assert persisted.metadata_json["timeout_policy"]["job_timeout_seconds"] == 4200
        assert persisted.metadata_json["timeout_policy"]["profile_timeout_seconds"] == 3900


def test_profile_timeout_marks_pending_plugins_explicitly(tmp_path: Path) -> None:
    # Direct unit coverage for terminal-state accounting without invoking RQ.
    engine = create_engine("sqlite:///:memory:", connect_args={"check_same_thread": False})
    Base.metadata.create_all(bind=engine)
    SessionLocal = sessionmaker(bind=engine)
    with SessionLocal() as session:
        case = Case(id=str(uuid4()), name="case", description="", status="open", mode="investigation")
        evidence_path = tmp_path / "memory.dmp"
        evidence_path.write_bytes(b"memory")
        evidence = Evidence(
            id=str(uuid4()),
            case_id=case.id,
            original_filename="memory.dmp",
            stored_path=str(evidence_path),
            storage_mode=EvidenceStorageMode.uploaded,
            evidence_type=EvidenceType.memory_dump,
            size_bytes=1,
            ingest_status=IngestStatus.completed,
            sha256="0" * 64,
            metadata_json={},
            detection_status="confirmed_memory",
            detection_confidence="high",
            detected_format="windows_crash_dump",
        )
        session.add_all([case, evidence])
        session.commit()
        run = MemoryScanRun(
            id=str(uuid4()),
            case_id=case.id,
            evidence_id=evidence.id,
            backend="volatility3",
            profile="suspicious_memory",
            status="running",
            requested_plugin_count=2,
            plugin_count=2,
            metadata_json={"plugins": ["windows.malfind", "windows.vadinfo"], "profile": "suspicious_memory"},
        )
        first = MemoryPluginRun(id=str(uuid4()), memory_scan_run_id=run.id, case_id=case.id, evidence_id=evidence.id, plugin="windows.malfind", status="completed")
        second = MemoryPluginRun(id=str(uuid4()), memory_scan_run_id=run.id, case_id=case.id, evidence_id=evidence.id, plugin="windows.vadinfo", status="pending")
        session.add_all([run, first, second])
        session.commit()
        session.refresh(run)
        first.status = "completed"
        first.completed_at = execution.utc_now_naive()
        run.plugins_completed = 1
        session.commit()

        execution._mark_profile_timeout_pending(session, run, ["windows.malfind", "windows.vadinfo"], active_plugin=None, profile_timeout_seconds=3900)

        session.refresh(run)
        assert run.status == "completed_with_errors"
        assert run.plugins_completed == 1
        assert run.plugins_failed == 0
        assert second.status == "skipped_dependency"
        assert second.error_code == "not_started_due_to_profile_timeout"


def test_runner_cancellation_terminates_process_group(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    signals: list[int] = []
    evidence_path = tmp_path / "memory.mem"
    evidence_path.write_bytes(b"memory")

    class FakeProcess:
        pid = 12345
        returncode = None

        def communicate(self, timeout):
            if timeout == 1:
                raise subprocess.TimeoutExpired(cmd=["vol"], timeout=timeout)
            return b"", b"cancelled"

    settings = _settings()
    object.__setattr__(settings, "volatility3_command", "vol")
    object.__setattr__(settings, "memory_plugin_termination_grace_seconds", 2)
    monkeypatch.setattr(volatility_runner, "get_settings", lambda: settings)
    monkeypatch.setattr(volatility_runner, "resolve_configured_executable", lambda _command: (True, "/usr/bin/vol", "vol", None))
    monkeypatch.setattr(volatility_runner.subprocess, "Popen", lambda *_args, **_kwargs: FakeProcess())
    monkeypatch.setattr(volatility_runner.os, "killpg", lambda _pid, sig: signals.append(sig))

    with pytest.raises(volatility_runner.VolatilityRunnerError) as exc_info:
        volatility_runner.run_plugin(
            "windows.info",
            evidence_path,
            tmp_path,
            timeout_seconds=60,
            cancellation_check=lambda: True,
        )

    assert exc_info.value.code == "PLUGIN_CANCELLED"
    assert signals == [15]
