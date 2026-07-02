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
from unittest.mock import patch
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
    assert result["analysis_state"] in {"completed", "analyzed_empty", "analyzed_with_results", "partial"}


def test_resolve_active_result_prefers_extended_over_basic_for_processes(db: Session) -> None:
    case = _make_case(db)
    ev = _make_evidence(db, case.id, "a.dmp")
    r_basic = _make_run(db, case.id, ev.id, "processes_basic", "completed", _utc(2026, 6, 16), _utc(2026, 6, 16, 0, 2))
    r_basic.canonical_materialization_status = "completed"
    r_basic.canonical_entity_count = 100
    r_ext = _make_run(db, case.id, ev.id, "processes_extended", "completed", _utc(2026, 6, 15), _utc(2026, 6, 15, 0, 5))
    r_ext.canonical_materialization_status = "completed"
    r_ext.canonical_entity_count = 200
    db.commit()
    result = resolve_active_memory_result(db, case_id=case.id, evidence_id=ev.id, family="processes")
    assert result["active_run"] is not None
    assert result["active_run"]["id"] == r_ext.id


def test_resolve_active_result_falls_back_to_processes_basic_when_no_extended(db: Session) -> None:
    case = _make_case(db)
    ev = _make_evidence(db, case.id, "a.dmp")
    r_basic = _make_run(db, case.id, ev.id, "processes_basic", "completed", _utc(2026, 6, 16), _utc(2026, 6, 16, 0, 2))
    r_basic.canonical_materialization_status = "completed"
    r_basic.canonical_entity_count = 100
    db.commit()
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
    completed_states = {"completed", "analyzed_with_results", "analyzed_empty", "partial"}
    a_done = a_sys["state"] in completed_states
    b_done = b_sys["state"] in completed_states
    assert a_done != b_done  # one of them is completed and the other is not


def test_catalogue_returns_eight_profiles_with_network_plugin_availability(db: Session) -> None:
    case = _make_case(db)
    ev = _make_evidence(db, case.id, "a.dmp")
    _make_run(db, case.id, ev.id, "metadata_only", "completed", _utc(2026, 6, 15), _utc(2026, 6, 15, 0, 1))
    with patch("app.services.memory.counts.get_memory_family_count", return_value={"total": 0}):
        catalogue = build_analysis_catalogue(db, case_id=case.id, evidence_id=ev.id)
    assert len(catalogue) == 8
    profiles = [item["profile"] for item in catalogue]
    assert "metadata_only" in profiles
    assert "processes_extended" in profiles
    assert "network_basic" in profiles
    network = next(item for item in catalogue if item["profile"] == "network_basic")
    assert network["available"] is True
    assert network["plugins"] == ["windows.netscan", "windows.netstat"]
    assert network["plugin_count"] == 2
    assert network["available_plugin_count"] >= 1


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
    r_basic.canonical_materialization_status = "completed"
    r_basic.canonical_entity_count = 100
    db.commit()
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
    assert result["analysis_state"] == "failed"


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
    completed_states = {"completed", "analyzed_with_results", "analyzed_empty", "partial"}
    assert a_sys["state"] in completed_states
    assert b_sys["state"] == "failed"
    # Per-evidence run counts must reflect the local evidence only
    assert a_item["run_count"] == 1
    assert b_item["run_count"] == 1


# ---------------------------------------------------------------------------
# Per-family run resolution (the bug from the operator report)
# ---------------------------------------------------------------------------


def _mock_family_count(monkeypatch, *, total: int, count_source: str = "summary") -> None:
    """Patch get_memory_family_count so tests can run without OpenSearch."""
    from app.services.memory import active_result

    def fake_count(*, case_id, evidence_id, family, active_run_id, db=None):
        return {
            "family": family,
            "document_type": active_result.FAMILY_TO_DOCUMENT_TYPE.__class__.__name__ if False else family,
            "active_run_id": active_run_id,
            "total": total,
            "count_source": count_source,
            "calculated_at": "2026-06-24T00:00:00Z",
        }

    monkeypatch.setattr(
        active_result,
        "_family_count",
        lambda *, case_id, evidence_id, family, active_run: {
            "family": family,
            "document_type": family,
            "active_run_id": str(active_run.id),
            "total": total,
            "count_source": count_source,
            "calculated_at": "2026-06-24T00:00:00Z",
        },
    )
    monkeypatch.setattr(
        active_result,
        "_family_items",
        lambda *, case_id, evidence_id, family, active_run, page, page_size, filters: ([], "summary_fallback"),
    )


def test_modules_resolves_modules_basic_not_processes(db: Session, monkeypatch) -> None:
    """Goal A test 1: Modules must use modules_basic, not the global
    processes_extended default.
    """
    _mock_family_count(monkeypatch, total=21339)
    case = _make_case(db)
    ev = _make_evidence(db, case.id, "a.dmp")
    r_processes = _make_run(db, case.id, ev.id, "processes_extended", "completed", _utc(2026, 6, 16), _utc(2026, 6, 16, 0, 4))
    r_processes.canonical_materialization_status = "completed"
    r_processes.canonical_entity_count = 255
    r_modules = _make_run(db, case.id, ev.id, "modules_basic", "completed", _utc(2026, 6, 15), _utc(2026, 6, 15, 0, 2))
    db.commit()
    result = resolve_active_memory_result(
        db, case_id=case.id, evidence_id=ev.id, family="modules",
    )
    assert result["active_run"] is not None
    assert result["active_run"]["id"] == r_modules.id
    assert result["active_run"]["profile"] == "modules_basic"


def test_handles_resolves_handles_basic(db: Session, monkeypatch) -> None:
    """Goal A test 2: Handles must resolve to handles_basic, not the
    global default process run.
    """
    _mock_family_count(monkeypatch, total=97087)
    case = _make_case(db)
    ev = _make_evidence(db, case.id, "a.dmp")
    r_processes = _make_run(db, case.id, ev.id, "processes_extended", "completed", _utc(2026, 6, 16), _utc(2026, 6, 16, 0, 4))
    r_processes.canonical_materialization_status = "completed"
    r_processes.canonical_entity_count = 255
    r_handles = _make_run(db, case.id, ev.id, "handles_basic", "completed", _utc(2026, 6, 15), _utc(2026, 6, 15, 0, 2))
    db.commit()
    result = resolve_active_memory_result(
        db, case_id=case.id, evidence_id=ev.id, family="handles",
    )
    assert result["active_run"] is not None
    assert result["active_run"]["id"] == r_handles.id
    assert result["active_run"]["profile"] == "handles_basic"
    assert result["total"] == 97087


def test_drivers_resolves_kernel_basic(db: Session, monkeypatch) -> None:
    """Goal A test 3: Drivers must resolve to kernel_basic, not the
    global default process run.
    """
    _mock_family_count(monkeypatch, total=135)
    case = _make_case(db)
    ev = _make_evidence(db, case.id, "a.dmp")
    r_processes = _make_run(db, case.id, ev.id, "processes_extended", "completed", _utc(2026, 6, 16), _utc(2026, 6, 16, 0, 4))
    r_processes.canonical_materialization_status = "completed"
    r_processes.canonical_entity_count = 255
    r_kernel = _make_run(db, case.id, ev.id, "kernel_basic", "completed", _utc(2026, 6, 15), _utc(2026, 6, 15, 0, 2))
    db.commit()
    result = resolve_active_memory_result(
        db, case_id=case.id, evidence_id=ev.id, family="drivers",
    )
    assert result["active_run"] is not None
    assert result["active_run"]["id"] == r_kernel.id
    assert result["active_run"]["profile"] == "kernel_basic"


def test_kernel_modules_resolves_kernel_basic(db: Session, monkeypatch) -> None:
    """Goal A test 4: Kernel modules must resolve to kernel_basic, not
    the global default process run.
    """
    _mock_family_count(monkeypatch, total=169)
    case = _make_case(db)
    ev = _make_evidence(db, case.id, "a.dmp")
    r_processes = _make_run(db, case.id, ev.id, "processes_extended", "completed", _utc(2026, 6, 16), _utc(2026, 6, 16, 0, 4))
    r_processes.canonical_materialization_status = "completed"
    r_processes.canonical_entity_count = 255
    r_kernel = _make_run(db, case.id, ev.id, "kernel_basic", "completed", _utc(2026, 6, 15), _utc(2026, 6, 15, 0, 2))
    db.commit()
    result = resolve_active_memory_result(
        db, case_id=case.id, evidence_id=ev.id, family="kernel_modules",
    )
    assert result["active_run"] is not None
    assert result["active_run"]["id"] == r_kernel.id
    assert result["active_run"]["profile"] == "kernel_basic"


def test_suspicious_regions_resolves_suspicious_memory(db: Session, monkeypatch) -> None:
    """Goal A test 5: Suspicious regions must resolve to
    suspicious_memory, not the global default process run.
    """
    _mock_family_count(monkeypatch, total=19)
    case = _make_case(db)
    ev = _make_evidence(db, case.id, "a.dmp")
    r_processes = _make_run(db, case.id, ev.id, "processes_extended", "completed", _utc(2026, 6, 16), _utc(2026, 6, 16, 0, 4))
    r_processes.canonical_materialization_status = "completed"
    r_processes.canonical_entity_count = 255
    r_suspicious = _make_run(db, case.id, ev.id, "suspicious_memory", "completed", _utc(2026, 6, 15), _utc(2026, 6, 15, 0, 2))
    db.commit()
    result = resolve_active_memory_result(
        db, case_id=case.id, evidence_id=ev.id, family="suspicious_regions",
    )
    assert result["active_run"] is not None
    assert result["active_run"]["id"] == r_suspicious.id
    assert result["active_run"]["profile"] == "suspicious_memory"


def test_family_response_returns_real_total_and_items(db: Session, monkeypatch) -> None:
    """Goal A test 6: The family response must return the real total
    and items, not hardcoded 0 and [].
    """
    from app.services.memory import active_result

    def fake_count(*, case_id, evidence_id, family, active_run):
        return {
            "family": family,
            "document_type": family,
            "active_run_id": str(active_run.id),
            "total": 1234,
            "count_source": "opensearch",
            "calculated_at": "2026-06-24T00:00:00Z",
        }

    def fake_items(*, case_id, evidence_id, family, active_run, page, page_size, filters):
        return ([{"document_id": "doc-1"}, {"document_id": "doc-2"}], "opensearch")

    monkeypatch.setattr(active_result, "_family_count", fake_count)
    monkeypatch.setattr(active_result, "_family_items", fake_items)
    case = _make_case(db)
    ev = _make_evidence(db, case.id, "a.dmp")
    _make_run(db, case.id, ev.id, "handles_basic", "completed", _utc(2026, 6, 15), _utc(2026, 6, 15, 0, 1))
    result = resolve_active_memory_result(
        db, case_id=case.id, evidence_id=ev.id, family="handles",
    )
    assert result["total"] == 1234
    assert len(result["items"]) == 2
    assert result["items"][0]["document_id"] == "doc-1"
    assert result["count_source"] == "opensearch"
    assert result["page"] == 1
    assert result["page_size"] == 50


def test_pagination_for_large_handles_results(db: Session, monkeypatch) -> None:
    """Goal A test 7: Pagination must respect page and page_size for
    large families (e.g. 97k handles).
    """
    from app.services.memory import active_result

    def fake_count(*, case_id, evidence_id, family, active_run):
        return {
            "family": family,
            "document_type": family,
            "active_run_id": str(active_run.id),
            "total": 97087,
            "count_source": "opensearch",
            "calculated_at": "2026-06-24T00:00:00Z",
        }

    captured = {}

    def fake_items(*, case_id, evidence_id, family, active_run, page, page_size, filters):
        captured["page"] = page
        captured["page_size"] = page_size
        return ([{"document_id": f"doc-{page}-{i}"} for i in range(page_size)], "opensearch")

    monkeypatch.setattr(active_result, "_family_count", fake_count)
    monkeypatch.setattr(active_result, "_family_items", fake_items)
    case = _make_case(db)
    ev = _make_evidence(db, case.id, "a.dmp")
    _make_run(db, case.id, ev.id, "handles_basic", "completed", _utc(2026, 6, 15), _utc(2026, 6, 15, 0, 1))
    result = resolve_active_memory_result(
        db, case_id=case.id, evidence_id=ev.id, family="handles", page=2, page_size=50,
    )
    assert captured["page"] == 2
    assert captured["page_size"] == 50
    assert result["page"] == 2
    assert result["page_size"] == 50
    assert result["total"] == 97087
    assert len(result["items"]) == 50


def test_completed_zero_row_run_returns_analyzed_empty(db: Session, monkeypatch) -> None:
    """Goal A test 8: A successful run with zero rows must return
    analyzed_empty (NOT not_analyzed).
    """
    from app.services.memory import active_result

    monkeypatch.setattr(
        active_result,
        "_family_count",
        lambda *, case_id, evidence_id, family, active_run: {
            "family": family,
            "document_type": family,
            "active_run_id": str(active_run.id),
            "total": 0,
            "count_source": "opensearch",
            "calculated_at": "2026-06-24T00:00:00Z",
        },
    )
    monkeypatch.setattr(
        active_result,
        "_family_items",
        lambda *, case_id, evidence_id, family, active_run, page, page_size, filters: ([], "opensearch"),
    )
    case = _make_case(db)
    ev = _make_evidence(db, case.id, "a.dmp")
    _make_run(db, case.id, ev.id, "network_basic", "completed", _utc(2026, 6, 15), _utc(2026, 6, 15, 0, 1))
    result = resolve_active_memory_result(
        db, case_id=case.id, evidence_id=ev.id, family="network",
    )
    assert result["active_run"] is not None
    assert result["total"] == 0
    assert result["analysis_state"] == "analyzed_empty"
    assert result["items"] == []


def test_missing_compatible_run_returns_not_analyzed(db: Session) -> None:
    """Goal A test 9: When no compatible run exists, the family must
    return not_analyzed.
    """
    case = _make_case(db)
    ev = _make_evidence(db, case.id, "a.dmp")
    result = resolve_active_memory_result(
        db, case_id=case.id, evidence_id=ev.id, family="suspicious_regions",
    )
    assert result["active_run"] is None
    assert result["total"] == 0
    assert result["items"] == []
    assert result["analysis_state"] == "not_analyzed"


def test_failed_compatible_run_is_not_reported_as_not_analyzed(db: Session) -> None:
    """Goal A test 10: A failed compatible run is reported as failed,
    not as not_analyzed.
    """
    case = _make_case(db)
    ev = _make_evidence(db, case.id, "a.dmp")
    _make_run(db, case.id, ev.id, "suspicious_memory", "failed", _utc(2026, 6, 15), _utc(2026, 6, 15, 0, 1))
    result = resolve_active_memory_result(
        db, case_id=case.id, evidence_id=ev.id, family="suspicious_regions",
    )
    assert result["active_run"] is None
    assert result["latest_attempt"] is not None
    assert result["analysis_state"] == "failed"
    assert result["total"] == 0
    assert result["items"] == []


def test_active_result_response_carries_count_source(db: Session, monkeypatch) -> None:
    """The response should expose a count_source so the UI can tell
    the analyst whether the count came from OpenSearch or the DB
    fallback.
    """
    from app.services.memory import active_result

    monkeypatch.setattr(
        active_result,
        "_family_count",
        lambda *, case_id, evidence_id, family, active_run: {
            "family": family,
            "document_type": family,
            "active_run_id": str(active_run.id),
            "total": 100,
            "count_source": "summary",
            "calculated_at": "2026-06-24T00:00:00Z",
        },
    )
    monkeypatch.setattr(
        active_result,
        "_family_items",
        lambda *, case_id, evidence_id, family, active_run, page, page_size, filters: ([], "summary_fallback"),
    )
    case = _make_case(db)
    ev = _make_evidence(db, case.id, "a.dmp")
    _make_run(db, case.id, ev.id, "handles_basic", "completed", _utc(2026, 6, 15), _utc(2026, 6, 15, 0, 1))
    result = resolve_active_memory_result(
        db, case_id=case.id, evidence_id=ev.id, family="handles",
    )
    # When both count and items fall back to the DB summary, the
    # response surfaces the combined ``summary_fallback`` source.
    assert result["count_source"] in {"summary", "summary_fallback"}
    assert result["total"] == 100


def test_active_result_handles_pagination_when_run_missing(db: Session) -> None:
    """The function must still return pagination metadata when the
    active run is missing (the UI uses page_size to render an empty
    state consistently).
    """
    case = _make_case(db)
    ev = _make_evidence(db, case.id, "a.dmp")
    result = resolve_active_memory_result(
        db, case_id=case.id, evidence_id=ev.id, family="handles",
        page=3, page_size=25,
    )
    assert result["active_run"] is None
    assert result["page"] == 3
    assert result["page_size"] == 25


def test_active_result_analysis_state_partial_when_plugins_failed(db: Session, monkeypatch) -> None:
    """A run that finished with plugin failures is partial: the
    family is analysable but the analyst should know.
    """
    from app.services.memory import active_result

    monkeypatch.setattr(
        active_result,
        "_family_count",
        lambda *, case_id, evidence_id, family, active_run: {
            "family": family,
            "document_type": family,
            "active_run_id": str(active_run.id),
            "total": 10,
            "count_source": "opensearch",
            "calculated_at": "2026-06-24T00:00:00Z",
        },
    )
    monkeypatch.setattr(
        active_result,
        "_family_items",
        lambda *, case_id, evidence_id, family, active_run, page, page_size, filters: ([], "opensearch"),
    )
    case = _make_case(db)
    ev = _make_evidence(db, case.id, "a.dmp")
    r = _make_run(
        db, case.id, ev.id, "handles_basic", "completed_with_errors",
        _utc(2026, 6, 15), _utc(2026, 6, 15, 0, 1),
        plugin_count=3, plugins_completed=2,
    )
    db.commit()
    result = resolve_active_memory_result(
        db, case_id=case.id, evidence_id=ev.id, family="handles",
    )
    assert result["active_run"] is not None
    assert result["active_run"]["id"] == r.id
    assert result["analysis_state"] == "partial"
    assert result["total"] == 10


def test_active_result_does_not_mutate_database(db: Session, monkeypatch) -> None:
    """Resolving the active result for a family must NEVER mutate
    the database (the function is read-only).
    """
    from app.services.memory import active_result

    monkeypatch.setattr(
        active_result,
        "_family_count",
        lambda *, case_id, evidence_id, family, active_run: {
            "family": family,
            "document_type": family,
            "active_run_id": str(active_run.id),
            "total": 5,
            "count_source": "summary",
            "calculated_at": "2026-06-24T00:00:00Z",
        },
    )
    monkeypatch.setattr(
        active_result,
        "_family_items",
        lambda *, case_id, evidence_id, family, active_run, page, page_size, filters: ([], "summary_fallback"),
    )
    case = _make_case(db)
    ev = _make_evidence(db, case.id, "a.dmp")
    _make_run(db, case.id, ev.id, "handles_basic", "completed", _utc(2026, 6, 15), _utc(2026, 6, 15, 0, 1))
    before = db.query(MemoryScanRun).count()
    resolve_active_memory_result(
        db, case_id=case.id, evidence_id=ev.id, family="handles", page=2, page_size=10,
    )
    after = db.query(MemoryScanRun).count()
    assert before == after


# ---------------------------------------------------------------------------
# evidence_id field query fix
#
# In the deployed OpenSearch mapping ``evidence_id`` is a plain ``keyword``
# field (no ``.keyword`` sub-field).  The old code used
# ``{"term": {"evidence_id.keyword": evidence_id}}`` which matched zero
# documents.  The fix uses ``{"term": {"evidence_id": evidence_id}}``.
# The following tests prove the fix and the full item-returning path.
# ---------------------------------------------------------------------------


class _CaptureSearchClient:
    """Fake OpenSearch client that captures the last search body and
    returns caller-specified items and total."""

    def __init__(self, items: list[dict[str, Any]], total: int = 5) -> None:
        self.items = items
        self.total = total
        self.last_index: str | None = None
        self.last_body: dict[str, Any] | None = None
        self.last_params: dict[str, Any] | None = None
        self.calls: list[tuple[str, dict[str, Any]]] = []

    def search(self, index: str, body: dict[str, Any], params: dict[str, Any] | None = None) -> dict[str, Any]:
        self.last_index = index
        self.last_body = body
        self.last_params = params
        self.calls.append(("search", body))
        return {
            "hits": {
                "total": {"value": self.total, "relation": "eq"},
                "hits": [
                    {"_id": item.get("document_id", str(i)), "_source": item}
                    for i, item in enumerate(self.items)
                ],
            }
        }

    def count(self, index: str, body: dict[str, Any], params: dict[str, Any] | None = None) -> dict[str, Any]:
        self.calls.append(("count", body))
        return {"count": self.total}


class TestEvidenceIdFieldQuery:
    """Prove ``search_artifact_documents`` and the active-result pipeline
    use ``evidence_id`` directly (no ``.keyword`` suffix)."""

    # ------------------------------------------------------------------
    # Unit: the query body structure
    # ------------------------------------------------------------------

    @staticmethod
    def _patch_client(fake: _CaptureSearchClient):
        """Patch both the artifact-indexing module (module-level
        import) and the core module (lazy import used by count functions)."""
        return patch.multiple(
            "app.services.memory.artifact_indexing",
            get_opensearch_client=lambda: fake,
        ), patch.multiple(
            "app.core.opensearch",
            get_opensearch_client=lambda: fake,
        )

    def test_search_artifact_documents_uses_evidence_id_not_keyword(self) -> None:
        from app.services.memory.artifact_indexing import search_artifact_documents

        fake = _CaptureSearchClient(items=[{"document_id": "a", "evidence_id": "ev-1"}], total=1)
        p1, p2 = self._patch_client(fake)
        with p1, p2:
            result = search_artifact_documents(
                case_id="case-1",
                document_type="memory_handle",
                run_id="run-1",
                evidence_id="ev-1",
            )
        assert result["total"] == 1
        assert len(result["items"]) == 1
        assert fake.last_body is not None
        filters = fake.last_body["query"]["bool"]["filter"]
        evidence_filter = [f for f in filters if "evidence_id" in str(f)]
        assert len(evidence_filter) == 1, f"evidence_id filter not found in {filters}"
        ev_filter = evidence_filter[0]
        assert "evidence_id" in ev_filter["term"]
        assert ".keyword" not in ev_filter["term"]["evidence_id"], (
            f"evidence_id filter should NOT use .keyword: {ev_filter}"
        )

    def test_search_artifact_documents_still_uses_scan_run_id_keyword(self) -> None:
        """scan_run_id is text with keyword sub-field — .keyword is correct."""
        from app.services.memory.artifact_indexing import search_artifact_documents

        fake = _CaptureSearchClient(items=[], total=0)
        p1, p2 = self._patch_client(fake)
        with p1, p2:
            search_artifact_documents(
                case_id="case-1",
                document_type="memory_handle",
                run_id="run-1",
                evidence_id="ev-1",
            )
        assert fake.last_body is not None
        filters = fake.last_body["query"]["bool"]["filter"]
        run_filters = [f for f in filters if "scan_run_id" in str(f)]
        assert len(run_filters) >= 1
        run_filter = run_filters[0]
        assert "scan_run_id.keyword" in run_filter["term"]

    def test_search_artifact_documents_uses_exact_network_filter_fields(self) -> None:
        from app.services.memory.artifact_indexing import search_artifact_documents

        fake = _CaptureSearchClient(items=[], total=0)
        p1, p2 = self._patch_client(fake)
        with p1, p2:
            search_artifact_documents(
                case_id="case-1",
                document_type="memory_network_connection",
                run_id="run-1",
                evidence_id="ev-1",
                filters={"protocol": "TCPv4", "local_address": "192.168.20.41", "process_name": "svchost.exe"},
            )
        assert fake.last_body is not None
        filters = fake.last_body["query"]["bool"]["filter"]
        assert {"term": {"protocol": "TCPv4"}} in filters
        assert {"term": {"local_address": "192.168.20.41"}} in filters
        assert {"term": {"process_name": "svchost.exe"}} in filters

    # ------------------------------------------------------------------
    # Integration: full active-result pipeline returns items
    # ------------------------------------------------------------------

    @staticmethod
    def _make_fake_client(family: str) -> _CaptureSearchClient:
        items = [
            {"document_id": f"{family}-{i}", "evidence_id": "ev-1", "family": family}
            for i in range(3)
        ]
        return _CaptureSearchClient(items=items, total=5)

    @pytest.mark.parametrize("family,profile,doc_type", [
        ("handles", "handles_basic", "memory_handle"),
        ("modules", "modules_basic", "memory_process_module"),
        ("drivers", "kernel_basic", "memory_driver"),
        ("kernel_modules", "kernel_basic", "memory_kernel_module"),
        ("suspicious_regions", "suspicious_memory", "memory_suspicious_region"),
    ])
    def test_family_active_result_returns_items(
        self, db: Session, family: str, profile: str, doc_type: str,
    ) -> None:
        case = _make_case(db)
        ev = _make_evidence(db, case.id, "a.dmp")
        _make_run(db, case.id, ev.id, profile, "completed", _utc(2026, 6, 15), _utc(2026, 6, 15, 0, 1))
        fake = self._make_fake_client(family)
        p1, p2 = self._patch_client(fake)
        with p1, p2:
            result = resolve_active_memory_result(db, case_id=case.id, evidence_id=ev.id, family=family)
        assert result["total"] == 5, family
        assert len(result["items"]) == 3, family
        assert result["count_source"] == "opensearch", family
        assert result["analysis_state"] == "analyzed_with_results", family
        assert result["items"][0]["document_id"] == f"{family}-0", family

    # ------------------------------------------------------------------
    # Isolation
    # ------------------------------------------------------------------

    def test_evidence_isolation_enforced(self, db: Session) -> None:
        case = _make_case(db)
        ev_a = _make_evidence(db, case.id, "a.dmp")
        _make_evidence(db, case.id, "b.dmp")
        _make_run(db, case.id, ev_a.id, "handles_basic", "completed", _utc(2026, 6, 15), _utc(2026, 6, 15, 0, 1))

        fake = _CaptureSearchClient(items=[{"document_id": "h-1"}], total=1)
        p1, p2 = self._patch_client(fake)
        with p1, p2:
            resolve_active_memory_result(db, case_id=case.id, evidence_id=ev_a.id, family="handles")

        assert fake.last_body is not None
        filters = fake.last_body["query"]["bool"]["filter"]
        ev_filters = [f for f in filters if "evidence_id" in str(f)]
        assert len(ev_filters) >= 1
        assert "evidence_id" in ev_filters[0]["term"]
        assert ev_filters[0]["term"]["evidence_id"] == ev_a.id

    def test_run_isolation_enforced(self, db: Session) -> None:
        case = _make_case(db)
        ev = _make_evidence(db, case.id, "a.dmp")
        run = _make_run(db, case.id, ev.id, "handles_basic", "completed", _utc(2026, 6, 15), _utc(2026, 6, 15, 0, 1))

        fake = _CaptureSearchClient(items=[{"document_id": "h-1"}], total=1)
        p1, p2 = self._patch_client(fake)
        with p1, p2:
            resolve_active_memory_result(db, case_id=case.id, evidence_id=ev.id, family="handles")

        assert fake.last_body is not None
        filters = fake.last_body["query"]["bool"]["filter"]
        run_filters = [f for f in filters if "scan_run_id" in str(f)]
        assert len(run_filters) >= 1
        run_filter = run_filters[0]
        assert "scan_run_id.keyword" in run_filter["term"]
        assert run_filter["term"]["scan_run_id.keyword"] == run.id

    # ------------------------------------------------------------------
    # Pagination
    # ------------------------------------------------------------------

    def test_pagination_returns_different_records(self, db: Session) -> None:
        case = _make_case(db)
        ev = _make_evidence(db, case.id, "a.dmp")
        _make_run(db, case.id, ev.id, "handles_basic", "completed", _utc(2026, 6, 15), _utc(2026, 6, 15, 0, 1))

        page1_items = [{"document_id": f"h-{i}", "evidence_id": ev.id, "family": "handles"} for i in range(2)]
        page2_items = [{"document_id": f"h-{i+10}", "evidence_id": ev.id, "family": "handles"} for i in range(2)]
        fake1 = _CaptureSearchClient(items=page1_items, total=50)
        fake2 = _CaptureSearchClient(items=page2_items, total=50)

        # Each resolve_active_memory_result calls count -> search.
        # Use side_effect to return a fresh fake for each resolve call.
        with patch("app.services.memory.artifact_indexing.get_opensearch_client") as oa_patcher, \
             patch("app.core.opensearch.get_opensearch_client") as oc_patcher:
            fakes_iter = iter([fake1, fake1, fake2, fake2])
            oa_patcher.side_effect = lambda: next(fakes_iter)
            oc_patcher.side_effect = lambda: next(fakes_iter)
            result1 = resolve_active_memory_result(
                db, case_id=case.id, evidence_id=ev.id, family="handles", page=1, page_size=2,
            )
            result2 = resolve_active_memory_result(
                db, case_id=case.id, evidence_id=ev.id, family="handles", page=2, page_size=2,
            )

        assert len(result1["items"]) == 2
        assert len(result2["items"]) == 2
        ids1 = {it["document_id"] for it in result1["items"]}
        ids2 = {it["document_id"] for it in result2["items"]}
        assert ids1 & ids2 == set(), "page 1 and page 2 must return different records"

    def test_pagination_forwards_page_metadata(self, db: Session) -> None:
        case = _make_case(db)
        ev = _make_evidence(db, case.id, "a.dmp")
        _make_run(db, case.id, ev.id, "handles_basic", "completed", _utc(2026, 6, 15), _utc(2026, 6, 15, 0, 1))

        fake = _CaptureSearchClient(items=[], total=97087)
        p1, p2 = self._patch_client(fake)
        with p1, p2:
            result = resolve_active_memory_result(
                db, case_id=case.id, evidence_id=ev.id, family="handles", page=2, page_size=50,
            )
        assert result["total"] == 97087
        assert result["page"] == 2
        assert result["page_size"] == 50

    # ------------------------------------------------------------------
    # Total unchanged while items become populated
    # ------------------------------------------------------------------

    def test_total_unchanged_while_items_populated(self, db: Session) -> None:
        case = _make_case(db)
        ev = _make_evidence(db, case.id, "a.dmp")
        _make_run(db, case.id, ev.id, "handles_basic", "completed", _utc(2026, 6, 15), _utc(2026, 6, 15, 0, 1))

        fake = _CaptureSearchClient(items=[{"document_id": "h-1"}], total=97087)
        p1, p2 = self._patch_client(fake)
        with p1, p2:
            result = resolve_active_memory_result(db, case_id=case.id, evidence_id=ev.id, family="handles")
        assert result["total"] == 97087
        assert len(result["items"]) == 1
        assert result["count_source"] == "opensearch"

    # ------------------------------------------------------------------
    # No reindex operation
    # ------------------------------------------------------------------

    def test_no_reindex_operation_performed(self, db: Session) -> None:
        case = _make_case(db)
        ev = _make_evidence(db, case.id, "a.dmp")
        _make_run(db, case.id, ev.id, "handles_basic", "completed", _utc(2026, 6, 15), _utc(2026, 6, 15, 0, 1))

        fake = _CaptureSearchClient(items=[{"document_id": "h-1"}], total=1)
        p1, p2 = self._patch_client(fake)
        with p1, p2:
            resolve_active_memory_result(db, case_id=case.id, evidence_id=ev.id, family="handles")
        call_names = {c[0] for c in fake.calls}
        assert "search" in call_names
        assert "count" in call_names
        assert "put_mapping" not in call_names
        assert "reindex" not in call_names
        assert "update_by_query" not in call_names
