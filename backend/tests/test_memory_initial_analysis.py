"""Regression coverage for Memory Preparation Phase 3A ("initial analysis").

This phase adds no backend code: it reuses ``POST /evidences/{id}/memory/scan``
(``start_memory_scan``) with ``profile="processes_basic"`` exactly as
``MemoryEvidencePage``'s existing Run Analysis flow already does. These
tests exist only to pin down, as regressions, the specific guarantees the
frontend design in the Phase 3A audit depends on:

* ``metadata_only`` is unconditionally ineligible for Linux evidence (no
  ``IDENTIFICATION`` capability entry exists for Linux in
  ``app.services.memory.capability_registry``) -- the new wizard action
  must never use it, and this pins the exact rejection so a future change
  can't silently make it "work" and hide the platform-inconsistency bug.
* ``processes_basic`` never resolves to ``linux.sockstat`` on Linux --
  the profile's capability (``PROCESSES``) is simply not ``NETWORK``, so
  this is structural, not a runtime probe result.
* ``active_run_for_evidence`` -- the same double-submit guard
  ``start_memory_scan`` calls -- blocks a second concurrent
  ``processes_basic`` run and allows a fresh one once the prior run
  reached a terminal (e.g. ``failed``) status.
* ``processes_basic`` resolves real Windows plugins through the same
  capability registry, for the same profile name, with no
  platform-specific branching required by the caller.

See ``app/services/memory/execution.py`` (``resolve_profile_plugins``,
``create_memory_metadata_run``, ``active_run_for_evidence``) and
``app/services/memory/capability_registry.py`` for the code under test.
"""
from __future__ import annotations

import os
import uuid
from pathlib import Path

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import Session, sessionmaker

from app.core.database import Base
from app.models.case import Case
from app.models.evidence import Evidence, EvidenceStorageMode, EvidenceType, IngestStatus
from app.services.memory.analysis_plan import build_memory_analysis_plan
from app.services.memory.execution import (
    ACTIVE_STATUSES,
    MemoryExecutionValidationError,
    active_run_for_evidence,
    create_memory_metadata_run,
    resolve_profile_plugins,
)
from app.services.memory.platform import PlatformFamily


@pytest.fixture
def db() -> Session:
    engine = create_engine("sqlite:///:memory:", connect_args={"check_same_thread": False})
    Base.metadata.create_all(bind=engine)
    Session_ = sessionmaker(bind=engine)
    session = Session_()
    try:
        yield session
    finally:
        session.close()
        engine.dispose()


@pytest.fixture(autouse=True)
def _enable_process_profiles(monkeypatch: pytest.MonkeyPatch) -> None:
    """``processes_basic`` is gated by ``memory_process_profile_enabled``
    (default off) -- every test here exercises that profile, so enable it
    globally rather than repeating the same monkeypatch per test, mirroring
    ``test_memory_platform_routing.py``'s own pattern for the same gate."""
    from app.core.config import Settings
    from app.services.memory import backend_readiness

    enabled_settings = Settings()
    object.__setattr__(enabled_settings, "memory_process_profile_enabled", True)
    monkeypatch.setattr(backend_readiness, "get_settings", lambda: enabled_settings)


def _make_case(db: Session, case_id: str = "eeeeeeee-1111-4111-8111-eeeeeeeeeeee") -> Case:
    case = Case(id=case_id, name="Initial analysis case")
    db.add(case)
    db.commit()
    return case


def _make_evidence(db: Session, case_id: str, *, content: bytes, detected_format: str | None) -> Evidence:
    # create_memory_metadata_run -> validate_memory_execution_request ->
    # resolve_memory_evidence_path only accepts a stored_path inside the
    # managed evidence root (settings.backend_data_dir / "evidence") for
    # storage_mode=uploaded evidence -- an arbitrary tempfile path (fine
    # for build_memory_analysis_plan, which only probes bytes) is rejected
    # as UNSAFE_EVIDENCE_PATH here, so the file must live under that root.
    from app.core.config import get_settings

    evidence_id = str(uuid.uuid4())
    root = get_settings().backend_data_dir / "evidence"
    root.mkdir(parents=True, exist_ok=True)
    path = root / f"{evidence_id}.img"
    path.write_bytes(content)
    ev = Evidence(
        id=evidence_id,
        case_id=case_id,
        original_filename="mem.img",
        stored_path=str(path),
        original_path=str(path),
        evidence_type=EvidenceType.memory_dump,
        storage_mode=EvidenceStorageMode.uploaded,
        is_external=False,
        copy_to_storage=True,
        sha256="0" * 64,
        size_bytes=os.path.getsize(path),
        ingest_status=IngestStatus.completed,
        path_validation={},
        ingest_source={},
        metadata_json={},
        error_log={},
        detection_status="confirmed_memory",
        detected_format=detected_format,
    )
    db.add(ev)
    db.commit()
    return ev


def _linux_plan(db: Session, case_id: str):
    evidence = _make_evidence(db, case_id, content=b"\x7fELF" + b"\x00" * 4092, detected_format="elf_core")
    plan = build_memory_analysis_plan(evidence, canonical_path=Path(evidence.stored_path))
    assert plan.detected_platform == PlatformFamily.LINUX
    return evidence, plan


def _windows_plan(db: Session, case_id: str):
    evidence = _make_evidence(db, case_id, content=b"PAGEDU64" + b"\x00" * 4088, detected_format=None)
    plan = build_memory_analysis_plan(evidence, canonical_path=Path(evidence.stored_path))
    assert plan.detected_platform == PlatformFamily.WINDOWS
    return evidence, plan


# ---------------------------------------------------------------------------
# metadata_only is unconditionally ineligible for Linux (Phase 3A audit §3.2)
# ---------------------------------------------------------------------------


def test_metadata_only_is_rejected_for_linux_evidence(db: Session) -> None:
    """Never let the new golden-path action regress to metadata_only on
    Linux -- there is no IDENTIFICATION capability entry for Linux at
    all, so this must fail even when everything else about the evidence
    is otherwise perfectly ready."""
    case = _make_case(db)
    _evidence, plan = _linux_plan(db, case.id)

    with pytest.raises(MemoryExecutionValidationError) as exc_info:
        resolve_profile_plugins("metadata_only", plan=plan)

    assert exc_info.value.code == "PROFILE_CAPABILITY_UNAVAILABLE"


def test_processes_basic_is_accepted_for_linux_evidence(db: Session) -> None:
    case = _make_case(db)
    _evidence, plan = _linux_plan(db, case.id)

    plugins = resolve_profile_plugins("processes_basic", plan=plan)

    assert plugins == ["linux.pslist", "linux.pstree"]


# ---------------------------------------------------------------------------
# processes_basic never touches linux.sockstat (the plugin that hit the
# 600s timeout on real evidence) -- structural, not just an observed result.
# ---------------------------------------------------------------------------


def test_processes_basic_never_selects_linux_sockstat(db: Session) -> None:
    case = _make_case(db)
    _evidence, plan = _linux_plan(db, case.id)

    plugins = resolve_profile_plugins("processes_basic", plan=plan)

    assert "linux.sockstat" not in plugins
    assert "linux.bash" not in plugins


# ---------------------------------------------------------------------------
# Windows uses the exact same profile name and endpoint -- no
# platform branching required by any caller.
# ---------------------------------------------------------------------------


def test_processes_basic_resolves_windows_plugins_via_the_same_profile_name(db: Session) -> None:
    case = _make_case(db)
    _evidence, plan = _windows_plan(db, case.id)

    plugins = resolve_profile_plugins("processes_basic", plan=plan)

    assert plugins == ["windows.info", "windows.pslist", "windows.pstree", "windows.cmdline"]


# ---------------------------------------------------------------------------
# active_run_for_evidence: the exact double-submit guard start_memory_scan
# calls -- blocks a concurrent run, allows a fresh one after a terminal one.
# ---------------------------------------------------------------------------


def test_active_run_for_evidence_blocks_a_second_concurrent_processes_basic_run(db: Session) -> None:
    case = _make_case(db)
    evidence, plan = _linux_plan(db, case.id)

    assert active_run_for_evidence(db, evidence.id, "processes_basic") is None

    run = create_memory_metadata_run(db, evidence.id, "processes_basic", plan=plan)

    assert run.status in ACTIVE_STATUSES
    existing = active_run_for_evidence(db, evidence.id, "processes_basic")
    assert existing is not None
    assert existing.id == run.id


def test_active_run_for_evidence_allows_a_fresh_run_after_the_prior_one_failed(db: Session) -> None:
    """Mirrors what app.services.memory.execution._fail_run does to
    MemoryScanRun.status on failure -- once terminal, the evidence must be
    retryable immediately, with no separate "reset" step required."""
    case = _make_case(db)
    evidence, plan = _linux_plan(db, case.id)
    run = create_memory_metadata_run(db, evidence.id, "processes_basic", plan=plan)

    run.status = "failed"
    db.commit()

    assert active_run_for_evidence(db, evidence.id, "processes_basic") is None

    retried = create_memory_metadata_run(db, evidence.id, "processes_basic", plan=plan)
    assert retried.id != run.id
    assert active_run_for_evidence(db, evidence.id, "processes_basic").id == retried.id
