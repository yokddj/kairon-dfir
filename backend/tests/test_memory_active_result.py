"""Tests for the central active-result resolver and evidence scoping.

The active-result resolver is the single source of truth for "which
``MemoryScanRun`` is the analyst currently looking at for this
evidence + family?"  The per-family selection rules must be stable:

* system_info:      latest completed metadata_only
* processes:        latest completed processes_extended, else processes_basic
* network:          latest completed network_basic
* modules/handles/kernel/drivers/suspicious: latest completed profile

The "latest attempt failed" rule: a failed run NEVER replaces the
last successful run.  The function returns the last successful run
and flags ``using_fallback=True``.

The "evidence cross-isolation" rule: a run for evidence A must
never be the active result for evidence B.
"""
from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Any
from uuid import uuid4

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import Session, sessionmaker

from app.core.database import Base
from app.models.case import Case
from app.models.evidence import Evidence, EvidenceStorageMode, EvidenceType, IngestStatus
from app.models.memory import MemoryArtifactSummary, MemoryScanRun
from app.services.memory.active_result import FAMILY_RESOLUTION, list_families, resolve_active_memory_result
from app.services.memory.catalogue import build_analysis_catalogue
from app.services.memory.overview import get_evidence_landing


@pytest.fixture()
def db() -> Session:
    engine = create_engine("sqlite:///:memory:", connect_args={"check_same_thread": False})
    Base.metadata.create_all(bind=engine)
    Session_ = sessionmaker(bind=engine)
    session = Session_()
    yield session
    session.close()


def _utc(year: int, month: int, day: int, hour: int = 0, minute: int = 0) -> datetime:
    return datetime(year, month, day, hour, minute, tzinfo=timezone.utc)


def _make_case(db: Session) -> Case:
    case = Case(
        id=str(uuid4()),
        name="Test",
        description="",
        status="open",
        mode="investigation",
        timezone="UTC",
    )
    db.add(case)
    db.commit()
    return case


def _make_evidence(db: Session, case_id: str, filename: str = "a.dmp") -> Evidence:
    evidence = Evidence(
        id=str(uuid4()),
        case_id=case_id,
        original_filename=filename,
        stored_path=f"/tmp/{filename}",
        evidence_type=EvidenceType.memory_dump,
        storage_mode=EvidenceStorageMode.uploaded,
        is_external=False,
        copy_to_storage=True,
        sha256=str(uuid4()),
        size_bytes=1024 * 1024,
        ingest_status=IngestStatus.completed,
        metadata_json={},
        path_validation={},
        ingest_source={},
        error_log={},
        created_at=_utc(2026, 6, 15),
    )
    db.add(evidence)
    db.commit()
    return evidence


def _make_run(
    db: Session,
    case_id: str,
    evidence_id: str,
    profile: str,
    status: str,
    started_at: datetime,
    completed_at: datetime | None = None,
    plugins_completed: int = 4,
    plugin_count: int = 4,
) -> MemoryScanRun:
    run = MemoryScanRun(
        id=str(uuid4()),
        case_id=case_id,
        evidence_id=evidence_id,
        backend="volatility3",
        profile=profile,
        status=status,
        requested_plugin_count=plugin_count,
        plugin_count=plugin_count,
        plugins_completed=plugins_completed,
        plugins_failed=plugin_count - plugins_completed,
        started_at=started_at,
        completed_at=completed_at,
        duration_ms=int(((completed_at or started_at) - started_at).total_seconds() * 1000),
        metadata_json={},
        error_log={},
        created_at=started_at,
    )
    db.add(run)
    db.commit()
    return run


def test_list_families_returns_all_supported_families() -> None:
    families = list_families()
    for required in ("system_info", "processes", "network", "modules", "handles", "kernel_modules", "drivers", "suspicious_regions"):
        assert required in families, families


def test_resolve_active_result_unknown_family_returns_structured_response(db: Session) -> None:
    case = _make_case(db)
    ev = _make_evidence(db, case.id, "a.dmp")
    result = resolve_active_memory_result(db, case_id=case.id, evidence_id=ev.id, family="not_a_real_family")
    assert result["analysis_state"] == "unknown_family"
    assert result["active_run"] is None


def test_resolve_active_result_requires_evidence_id(db: Session) -> None:
    case = _make_case(db)
    result = resolve_active_memory_result(db, case_id=case.id, evidence_id="", family="processes")
    assert result["analysis_state"] == "evidence_scope_required"


def test_resolve_active_result_not_analyzed_when_no_runs_exist(db: Session) -> None:
    case = _make_case(db)
    ev = _make_evidence(db, case.id, "a.dmp")
    result = resolve_active_memory_result(db, case_id=case.id, evidence_id=ev.id, family="processes")
    assert result["analysis_state"] == "not_analyzed"
    assert result["active_run"] is None


def test_resolve_active_result_picks_latest_metadata_only_for_system_info(db: Session) -> None:
    case = _make_case(db)
    ev = _make_evidence(db, case.id, "a.dmp")
    r1 = _make_run(db, case.id, ev.id, "metadata_only", "completed", _utc(2026, 6, 15), _utc(2026, 6, 15, 0, 1))
    r2 = _make_run(db, case.id, ev.id, "metadata_only", "completed", _utc(2026, 6, 16), _utc(2026, 6, 16, 0, 1))
    result = resolve_active_memory_result(db, case_id=case.id, evidence_id=ev.id, family="system_info")
    assert result["active_run"] is not None
    assert result["active_run"]["id"] == r2.id
    assert result["analysis_state"] == "completed"


def test_resolve_active_result_prefers_extended_over_basic_for_processes(db: Session) -> None:
    case = _make_case(db)
    ev = _make_evidence(db, case.id, "a.dmp")
    r_basic = _make_run(db, case.id, ev.id, "processes_basic", "completed", _utc(2026, 6, 16), _utc(2026, 6, 16, 0, 2))
    r_ext = _make_run(db, case.id, ev.id, "processes_extended", "completed", _utc(2026, 6, 15), _utc(2026, 6, 15, 0, 5))
    result = resolve_active_memory_result(db, case_id=case.id, evidence_id=ev.id, family="processes")
    assert result["active_run"] is not None
    assert result["active_run"]["id"] == r_ext.id


def test_resolve_active_result_falls_back_to_processes_basic_when_no_extended(db: Session) -> None:
    case = _make_case(db)
    ev = _make_evidence(db, case.id, "a.dmp")
    r_basic = _make_run(db, case.id, ev.id, "processes_basic", "completed", _utc(2026, 6, 16), _utc(2026, 6, 16, 0, 2))
    result = resolve_active_memory_result(db, case_id=case.id, evidence_id=ev.id, family="processes")
    assert result["active_run"] is not None
    assert result["active_run"]["id"] == r_basic.id


def test_resolve_active_result_latest_attempt_failed_does_not_replace_successful(db: Session) -> None:
    case = _make_case(db)
    ev = _make_evidence(db, case.id, "a.dmp")
    r_ok = _make_run(db, case.id, ev.id, "handles_basic", "completed", _utc(2026, 6, 15), _utc(2026, 6, 15, 0, 1))
    r_fail = _make_run(db, case.id, ev.id, "handles_basic", "failed", _utc(2026, 6, 16), _utc(2026, 6, 16, 0, 1))
    result = resolve_active_memory_result(db, case_id=case.id, evidence_id=ev.id, family="handles")
    assert result["active_run"] is not None
    assert result["active_run"]["id"] == r_ok.id
    assert result["using_fallback"] is True
    assert result["selection_reason"] == "latest_attempt_failed_kept_last_success"
    assert result["latest_attempt"]["id"] == r_fail.id


def test_resolve_active_result_evidence_cross_isolation(db: Session) -> None:
    """A run for evidence A must NEVER appear as the active result
    for evidence B.
    """
    case = _make_case(db)
    ev_a = _make_evidence(db, case.id, "a.dmp")
    ev_b = _make_evidence(db, case.id, "b.dmp")
    r_A = _make_run(db, case.id, ev_a.id, "metadata_only", "completed", _utc(2026, 6, 15), _utc(2026, 6, 15, 0, 1))
    r_B = _make_run(db, case.id, ev_b.id, "metadata_only", "completed", _utc(2026, 6, 16), _utc(2026, 6, 16, 0, 1))
    result_a = resolve_active_memory_result(db, case_id=case.id, evidence_id=ev_a.id, family="system_info")
    result_b = resolve_active_memory_result(db, case_id=case.id, evidence_id=ev_b.id, family="system_info")
    assert result_a["active_run"]["id"] == r_A.id
    assert result_b["active_run"]["id"] == r_B.id


def test_resolve_active_result_historical_override_returns_requested_run(db: Session) -> None:
    case = _make_case(db)
    ev = _make_evidence(db, case.id, "a.dmp")
    r_old = _make_run(db, case.id, ev.id, "processes_basic", "completed", _utc(2026, 6, 10), _utc(2026, 6, 10, 0, 1))
    r_new = _make_run(db, case.id, ev.id, "processes_extended", "completed", _utc(2026, 6, 16), _utc(2026, 6, 16, 0, 1))
    result = resolve_active_memory_result(
        db, case_id=case.id, evidence_id=ev.id, family="processes", preferred_run_id=r_old.id,
    )
    assert result["active_run"]["id"] == r_old.id
    assert result["historical_override"] is True
    assert result["selection_reason"] == "historical_override"


def test_resolve_active_result_historical_override_rejected_when_run_belongs_to_other_evidence(db: Session) -> None:
    case = _make_case(db)
    ev_a = _make_evidence(db, case.id, "a.dmp")
    ev_b = _make_evidence(db, case.id, "b.dmp")
    r_B = _make_run(db, case.id, ev_b.id, "processes_basic", "completed", _utc(2026, 6, 16), _utc(2026, 6, 16, 0, 1))
    result = resolve_active_memory_result(
        db, case_id=case.id, evidence_id=ev_a.id, family="processes", preferred_run_id=r_B.id,
    )
    assert result["historical_override"] is True
    assert result["selection_reason"] == "historical_override_rejected"
    assert result["active_run"] is None


def test_resolve_active_result_network_returns_unavailable_when_no_run(db: Session) -> None:
    case = _make_case(db)
    ev = _make_evidence(db, case.id, "a.dmp")
    result = resolve_active_memory_result(db, case_id=case.id, evidence_id=ev.id, family="network")
    assert result["analysis_state"] == "not_analyzed"


def test_resolve_active_result_kernel_modules_and_drivers_share_kernel_basic_run(db: Session) -> None:
    case = _make_case(db)
    ev = _make_evidence(db, case.id, "a.dmp")
    r_kernel = _make_run(db, case.id, ev.id, "kernel_basic", "completed", _utc(2026, 6, 16), _utc(2026, 6, 16, 0, 2))
    km = resolve_active_memory_result(db, case_id=case.id, evidence_id=ev.id, family="kernel_modules")
    drv = resolve_active_memory_result(db, case_id=case.id, evidence_id=ev.id, family="drivers")
    assert km["active_run"]["id"] == r_kernel.id
    assert drv["active_run"]["id"] == r_kernel.id


def test_resolve_active_result_idempotence(db: Session) -> None:
    case = _make_case(db)
    ev = _make_evidence(db, case.id, "a.dmp")
    _make_run(db, case.id, ev.id, "metadata_only", "completed", _utc(2026, 6, 15), _utc(2026, 6, 15, 0, 1))
    a = resolve_active_memory_result(db, case_id=case.id, evidence_id=ev.id, family="system_info")
    b = resolve_active_memory_result(db, case_id=case.id, evidence_id=ev.id, family="system_info")
    assert a == b


def test_get_evidence_landing_returns_per_family_status(db: Session) -> None:
    case = _make_case(db)
    ev_a = _make_evidence(db, case.id, "a.dmp")
    ev_b = _make_evidence(db, case.id, "b.dmp")
    _make_run(db, case.id, ev_a.id, "metadata_only", "completed", _utc(2026, 6, 15), _utc(2026, 6, 15, 0, 1))
    items = get_evidence_landing(db, case.id)
    assert len(items) == 2
    a_sys = next(f for f in items[0]["families"] if f["family"] == "system_info")
    b_sys = next(f for f in items[1]["families"] if f["family"] == "system_info")
    a_done = a_sys["state"] == "completed"
    b_done = b_sys["state"] == "completed"
    assert a_done != b_done  # one of them is completed and the other is not


def test_catalogue_returns_eight_profiles_with_network_unavailable(db: Session) -> None:
    case = _make_case(db)
    ev = _make_evidence(db, case.id, "a.dmp")
    _make_run(db, case.id, ev.id, "metadata_only", "completed", _utc(2026, 6, 15), _utc(2026, 6, 15, 0, 1))
    catalogue = build_analysis_catalogue(db, case_id=case.id, evidence_id=ev.id)
    assert len(catalogue) == 8
    profiles = [item["profile"] for item in catalogue]
    assert "metadata_only" in profiles
    assert "processes_extended" in profiles
    assert "network_basic" in profiles
    network = next(item for item in catalogue if item["profile"] == "network_basic")
    # In the unit test runtime the network plugin is not installed,
    # so the catalogue must mark it as Unavailable with a reason.
    assert network["available"] is False
    assert network["availability_reason"] is not None
    assert "network plugin" in network["availability_reason"].lower()


def test_catalogue_returns_count_from_artifact_summaries(db: Session) -> None:
    case = _make_case(db)
    ev = _make_evidence(db, case.id, "a.dmp")
    run = _make_run(db, case.id, ev.id, "modules_basic", "completed", _utc(2026, 6, 15), _utc(2026, 6, 15, 0, 1))
    summary = MemoryArtifactSummary(
        case_id=case.id,
        evidence_id=ev.id,
        memory_run_id=run.id,
        memory_artifact_type="memory_process_module",
        count=21339,
        metadata_json={"raw_count": 22000, "accepted_count": 21339},
    )
    db.add(summary)
    db.commit()
    catalogue = build_analysis_catalogue(db, case_id=case.id, evidence_id=ev.id)
    modules = next(item for item in catalogue if item["profile"] == "modules_basic")
    assert modules["last_count"] == 21339
    assert modules["last_run"]["id"] == run.id


def test_resolve_active_result_handles_and_modules_resolve_separately(db: Session) -> None:
    case = _make_case(db)
    ev = _make_evidence(db, case.id, "a.dmp")
    r_h = _make_run(db, case.id, ev.id, "handles_basic", "completed", _utc(2026, 6, 16), _utc(2026, 6, 16, 0, 30))
    r_m = _make_run(db, case.id, ev.id, "modules_basic", "completed", _utc(2026, 6, 15), _utc(2026, 6, 15, 0, 2))
    h = resolve_active_memory_result(db, case_id=case.id, evidence_id=ev.id, family="handles")
    m = resolve_active_memory_result(db, case_id=case.id, evidence_id=ev.id, family="modules")
    assert h["active_run"]["id"] == r_h.id
    assert m["active_run"]["id"] == r_m.id


def test_resolve_active_result_zero_processes_extended_in_progress_uses_basic_fallback(db: Session) -> None:
    case = _make_case(db)
    ev = _make_evidence(db, case.id, "a.dmp")
    _make_run(db, case.id, ev.id, "processes_extended", "running", _utc(2026, 6, 16), None, plugins_completed=1)
    r_basic = _make_run(db, case.id, ev.id, "processes_basic", "completed", _utc(2026, 6, 15), _utc(2026, 6, 15, 0, 1))
    result = resolve_active_memory_result(db, case_id=case.id, evidence_id=ev.id, family="processes")
    # The extended run is still running, so the resolver falls back to basic
    assert result["active_run"]["id"] == r_basic.id


def test_resolve_active_result_no_successful_result_returns_latest_attempt_for_banner(db: Session) -> None:
    case = _make_case(db)
    ev = _make_evidence(db, case.id, "a.dmp")
    r_fail = _make_run(db, case.id, ev.id, "metadata_only", "failed", _utc(2026, 6, 16), _utc(2026, 6, 16, 0, 1))
    result = resolve_active_memory_result(db, case_id=case.id, evidence_id=ev.id, family="system_info")
    assert result["active_run"] is None
    assert result["latest_attempt"] is not None
    assert result["latest_attempt"]["id"] == r_fail.id
    assert result["analysis_state"] == "latest_attempt_failed"


def test_resolve_active_result_suspicious_regions_falls_back_when_no_suspicious_memory(db: Session) -> None:
    case = _make_case(db)
    ev = _make_evidence(db, case.id, "a.dmp")
    result = resolve_active_memory_result(db, case_id=case.id, evidence_id=ev.id, family="suspicious_regions")
    assert result["analysis_state"] == "not_analyzed"


def test_resolve_active_result_does_not_mutate_database(db: Session) -> None:
    case = _make_case(db)
    ev = _make_evidence(db, case.id, "a.dmp")
    _make_run(db, case.id, ev.id, "metadata_only", "completed", _utc(2026, 6, 15), _utc(2026, 6, 15, 0, 1))
    before = db.query(MemoryScanRun).count()
    resolve_active_memory_result(db, case_id=case.id, evidence_id=ev.id, family="system_info")
    resolve_active_memory_result(db, case_id=case.id, evidence_id=ev.id, family="processes")
    after = db.query(MemoryScanRun).count()
    assert before == after


def test_family_resolution_includes_evidence_id_required_for_all_families() -> None:
    """All families must require an evidence_id.  A case-level read
    without evidence_id is a scope violation and must be rejected.
    """
    for family, rules in FAMILY_RESOLUTION.items():
        assert rules.get("evidence_id_required") is True, f"family {family} does not require evidence_id"


def test_resolve_active_result_returns_completed_with_errors_as_success(db: Session) -> None:
    """A run with status ``completed_with_errors`` is still considered
    a successful result for active-result purposes.  The function
    must NOT fall back to an earlier run when the latest is
    completed_with_errors.
    """
    case = _make_case(db)
    ev = _make_evidence(db, case.id, "a.dmp")
    r_old = _make_run(db, case.id, ev.id, "modules_basic", "completed", _utc(2026, 6, 15), _utc(2026, 6, 15, 0, 1))
    r_new = _make_run(db, case.id, ev.id, "modules_basic", "completed_with_errors", _utc(2026, 6, 16), _utc(2026, 6, 16, 0, 2))
    result = resolve_active_memory_result(db, case_id=case.id, evidence_id=ev.id, family="modules")
    assert result["active_run"] is not None
    assert result["active_run"]["id"] == r_new.id
    assert result["using_fallback"] is False


def test_catalogue_includes_runs_for_all_profiles_with_correct_count(db: Session) -> None:
    case = _make_case(db)
    ev = _make_evidence(db, case.id, "a.dmp")
    _make_run(db, case.id, ev.id, "metadata_only", "completed", _utc(2026, 6, 15), _utc(2026, 6, 15, 0, 1))
    _make_run(db, case.id, ev.id, "processes_extended", "completed", _utc(2026, 6, 16), _utc(2026, 6, 16, 0, 4))
    _make_run(db, case.id, ev.id, "modules_basic", "completed", _utc(2026, 6, 16), _utc(2026, 6, 16, 0, 2))
    catalogue = build_analysis_catalogue(db, case_id=case.id, evidence_id=ev.id)
    by_profile = {item["profile"]: item for item in catalogue}
    assert by_profile["metadata_only"]["last_status"] == "completed"
    assert by_profile["processes_extended"]["last_status"] == "completed"
    assert by_profile["modules_basic"]["last_status"] == "completed"
    assert by_profile["suspicious_memory"]["last_status"] is None
    assert by_profile["suspicious_memory"]["last_run"] is None


def test_get_evidence_landing_isolates_evidence_runs(db: Session) -> None:
    """The landing page must not show runs from another evidence in
    the same case.
    """
    case = _make_case(db)
    ev_a = _make_evidence(db, case.id, "a.dmp")
    ev_b = _make_evidence(db, case.id, "b.dmp")
    _make_run(db, case.id, ev_a.id, "metadata_only", "completed", _utc(2026, 6, 16), _utc(2026, 6, 16, 0, 1))
    _make_run(db, case.id, ev_b.id, "metadata_only", "failed", _utc(2026, 6, 15), _utc(2026, 6, 15, 0, 1))
    items = get_evidence_landing(db, case.id)
    a_item = next(item for item in items if item["evidence_id"] == ev_a.id)
    b_item = next(item for item in items if item["evidence_id"] == ev_b.id)
    a_sys = next(f for f in a_item["families"] if f["family"] == "system_info")
    b_sys = next(f for f in b_item["families"] if f["family"] == "system_info")
    assert a_sys["state"] == "completed"
    assert b_sys["state"] == "latest_attempt_failed"
    # Per-evidence run counts must reflect the local evidence only
    assert a_item["run_count"] == 1
    assert b_item["run_count"] == 1
