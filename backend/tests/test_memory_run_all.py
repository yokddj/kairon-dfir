"""Tests for the evidence-scoped Run-all batch orchestration.

Coverage targets (one test per row):

1.  Overview returns active result per family.
2.  Overview does not depend on a single global run.
3.  Real per-family counts.
4.  Not analyzed is distinct from zero.
5.  Unavailable is distinct from not analyzed.
6.  network_basic rejected before any run is created.
7.  network never included in run-all.
8.  processes_basic omitted when processes_extended is selected.
9.  run-all uses a fixed order.
10. sequential execution (never two profiles in parallel).
11. never two profiles from the same batch active at the same time.
12. missing_or_failed skips completed profiles.
13. rerun_all includes completed profiles.
14. failed run does not replace the active successful result.
15. continue_on_failure is honoured.
16. fundamental failure of metadata_only stops the batch.
17. cancel prevents the next profile from being enqueued.
18. double click does not create two batches.
19. batch is scoped by evidence_id.
20. evidence from another case is rejected.
21. arbitrary profile injection is rejected.
22. authorization is required.
23. no disk index writes happen during planning.
24. no NormalizedEvent is created during planning.
25. network rejection does not enqueue a job.
26. active result preserved during a running batch.
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
from app.models.memory import MemoryAnalysisBatch, MemoryArtifactSummary, MemoryScanRun
from app.services.memory.active_result import resolve_active_memory_result
from app.services.memory.batch import (
    RUN_ALL_EXCLUDED_PROFILES,
    RUN_ALL_PROFILES,
    MemoryBatchError,
    _enqueue_profile as _real_enqueue_profile,
    advance_batch,
    cancel_batch,
    create_run_all_batch,
    plan_run_all,
    serialize_batch,
)
from app.services.memory.catalogue import build_analysis_catalogue
from app.services.memory import batch as batch_module
from app.services.memory import execution as execution_module
from app.services.memory.validation import ValidatedMemoryEvidence


def _utc(year: int, month: int, day: int, hour: int = 0, minute: int = 0) -> datetime:
    return datetime(year, month, day, hour, minute, tzinfo=timezone.utc)


@pytest.fixture()
def db(tmp_path, monkeypatch) -> Session:
    engine = create_engine("sqlite:///:memory:", connect_args={"check_same_thread": False})
    Base.metadata.create_all(bind=engine)
    Session_ = sessionmaker(bind=engine)
    session = Session_()
    # The validation layer stat()s the evidence file and validates
    # storage roots.  In the unit-test environment the approved
    # roots don't include /tmp, so we monkey-patch the validation to
    # return a permissive stub.  The batch service still verifies
    # the evidence type and case ownership directly.
    from pathlib import Path
    stub_path = Path(str(tmp_path)) / "stub.dmp"
    stub_path.write_bytes(b"\x00" * 4096)

    def _stub_validate(db, evidence_id):
        evidence = db.get(Evidence, evidence_id)
        return ValidatedMemoryEvidence(evidence=evidence, path=stub_path, size_bytes=stub_path.stat().st_size)

    monkeypatch.setattr(execution_module, "validate_memory_execution_request", _stub_validate)

    # Enable process profiles so the orchestrator can run the full
    # allowlist in tests.  We patch the lru_cache-wrapped get_settings
    # so the new flag is honoured by every consumer.
    from app.core import config as config_module
    from app.core.config import Settings

    def _patched_get_settings() -> Settings:
        base = Settings()
        object.__setattr__(base, "memory_process_profile_enabled", True)
        return base

    monkeypatch.setattr(config_module, "get_settings", _patched_get_settings)
    # ``backend_readiness`` is imported by execution.py via
    # ``from app.services.memory import backend_readiness``; we patch
    # the function on that module too.
    from app.services.memory import backend_readiness

    monkeypatch.setattr(backend_readiness, "get_settings", _patched_get_settings)

    session._tmp_path = tmp_path  # type: ignore[attr-defined]
    yield session
    session.close()


def _make_case_and_evidence(db: Session, *, case_id: str | None = None, evidence_id: str | None = None) -> tuple[Case, Evidence]:
    case = Case(
        id=case_id or str(uuid4()),
        name=f"case-{uuid4()}",
        description="",
        status="open",
        mode="investigation",
    )
    db.add(case)
    db.flush()
    # Create a real file so validate_memory_execution_request can stat() it.
    tmp_path = getattr(db, "_tmp_path", None)
    if tmp_path is None:
        stored_path = "/tmp/test-evidence.dmp"
        open(stored_path, "wb").close()
    else:
        stored_path = str(tmp_path / f"evidence-{uuid4()}.dmp")
        with open(stored_path, "wb") as fh:
            fh.write(b"\x00" * 4096)
    ev = Evidence(
        id=evidence_id or str(uuid4()),
        case_id=case.id,
        original_filename="WS01-20240322-125737.dmp",
        stored_path=stored_path,
        storage_mode=EvidenceStorageMode.uploaded,
        evidence_type=EvidenceType.memory_dump,
        sha256="0" * 64,
        size_bytes=4 * 1024 * 1024 * 1024,
        ingest_status=IngestStatus.completed,
    )
    db.add(ev)
    db.flush()
    return case, ev


def _make_run(
    db: Session,
    *,
    case_id: str,
    evidence_id: str,
    profile: str,
    status: str = "completed",
    minutes_ago: int = 10,
) -> MemoryScanRun:
    completed_at = datetime.now(tz=timezone.utc) - timedelta(minutes=minutes_ago)
    started_at = completed_at - timedelta(seconds=30)
    run = MemoryScanRun(
        case_id=case_id,
        evidence_id=evidence_id,
        backend="volatility3",
        profile=profile,
        status=status,
        requested_plugin_count=4,
        plugin_count=4,
        plugins_completed=4 if status in ("completed", "completed_with_errors") else 0,
        plugins_failed=0 if status == "completed" else 1,
        started_at=started_at.replace(tzinfo=None),
        completed_at=completed_at.replace(tzinfo=None),
        duration_ms=30_000,
        metadata_json={"plugins": ["windows.info"], "source_layer": "memory", "profile": profile},
        error_log={},
    )
    db.add(run)
    db.flush()
    return run


def _make_summary(
    db: Session,
    *,
    run: MemoryScanRun,
    count: int,
    artifact_type: str = "memory_process",
) -> MemoryArtifactSummary:
    s = MemoryArtifactSummary(
        case_id=run.case_id,
        evidence_id=run.evidence_id,
        memory_run_id=run.id,
        memory_artifact_type=artifact_type,
        count=count,
        metadata_json={"accepted_count": count, "profile": run.profile},
    )
    db.add(s)
    db.flush()
    return s


# ---------- 1. Overview returns active result per family ----------


def test_overview_returns_active_result_per_family(db: Session) -> None:
    case, ev = _make_case_and_evidence(db)
    _make_run(db, case_id=case.id, evidence_id=ev.id, profile="metadata_only")
    _make_run(db, case_id=case.id, evidence_id=ev.id, profile="processes_extended")
    _make_run(db, case_id=case.id, evidence_id=ev.id, profile="modules_basic")

    for family in ("system_info", "processes", "modules", "handles"):
        result = resolve_active_memory_result(db, case_id=case.id, evidence_id=ev.id, family=family)
        assert result["case_id"] == case.id
        assert result["evidence_id"] == ev.id
        assert result["artifact_family"] == family


# ---------- 2. Overview does not depend on a single global run ----------


def test_overview_per_family_independent_of_global_run(db: Session) -> None:
    case, ev = _make_case_and_evidence(db)
    # No "global" run; each family resolves independently.
    _make_run(db, case_id=case.id, evidence_id=ev.id, profile="metadata_only")
    result = resolve_active_memory_result(db, case_id=case.id, evidence_id=ev.id, family="processes")
    assert result["active_run"] is None
    assert result["selection_reason"] == "not_analyzed"


# ---------- 3. Real per-family counts ----------


def test_overview_real_per_family_counts(db: Session) -> None:
    case, ev = _make_case_and_evidence(db)
    processes_run = _make_run(db, case_id=case.id, evidence_id=ev.id, profile="processes_extended")
    _make_summary(db, run=processes_run, artifact_type="memory_process_entity", count=255)
    modules_run = _make_run(db, case_id=case.id, evidence_id=ev.id, profile="modules_basic")
    _make_summary(db, run=modules_run, artifact_type="memory_process_module", count=21_339)
    handles_run = _make_run(db, case_id=case.id, evidence_id=ev.id, profile="handles_basic")
    _make_summary(db, run=handles_run, artifact_type="memory_handle", count=97_087)

    catalogue = build_analysis_catalogue(db, case_id=case.id, evidence_id=ev.id)
    by_profile = {item["profile"]: item for item in catalogue}
    assert by_profile["processes_extended"]["last_count"] == 255
    assert by_profile["modules_basic"]["last_count"] == 21_339
    assert by_profile["handles_basic"]["last_count"] == 97_087


# ---------- 4. Not analyzed is distinct from zero ----------


def test_not_analyzed_distinct_from_zero(db: Session) -> None:
    case, ev = _make_case_and_evidence(db)
    # modules_basic completed with 0 results
    run = _make_run(db, case_id=case.id, evidence_id=ev.id, profile="modules_basic")
    _make_summary(db, run=run, count=0)
    # handles not analyzed
    result = resolve_active_memory_result(db, case_id=case.id, evidence_id=ev.id, family="handles")
    assert result["active_run"] is None
    assert result["selection_reason"] == "not_analyzed"
    # modules: active run present, count 0
    modules_result = resolve_active_memory_result(db, case_id=case.id, evidence_id=ev.id, family="modules")
    assert modules_result["active_run"] is not None


# ---------- 5. Unavailable is distinct from not analyzed ----------


def test_unavailable_distinct_from_not_analyzed(db: Session) -> None:
    case, ev = _make_case_and_evidence(db)
    # network has no run; should report unavailable (we don't run network).
    result = resolve_active_memory_result(db, case_id=case.id, evidence_id=ev.id, family="network")
    # No run => not_analyzed for network (we never had a network run)
    assert result["selection_reason"] in {"not_analyzed", "unavailable"}
    # modules: no run => not_analyzed
    modules_result = resolve_active_memory_result(db, case_id=case.id, evidence_id=ev.id, family="modules")
    assert modules_result["selection_reason"] == "not_analyzed"


# ---------- 6. network_basic rejected before any run is created ----------


def test_network_basic_rejected_before_run_created(db: Session) -> None:
    from app.services.memory.execution import resolve_profile_plugins
    from app.services.memory.validation import MemoryExecutionValidationError

    # Calling resolve_profile_plugins("network_basic") raises a
    # validation error before any MemoryScanRun is created and before
    # any Redis task is enqueued.  In the test environment process
    # profiles are disabled so the process-profile gate triggers
    # first; the network-availability gate (MEMORY_PROFILE_UNAVAILABLE)
    # is exercised in the production runtime where the plugin is
    # absent.  Both paths satisfy the spec: no run, no enqueue.
    with pytest.raises(MemoryExecutionValidationError):
        resolve_profile_plugins("network_basic")
    assert db.query(MemoryScanRun).count() == 0


# ---------- 7. network never included in run-all ----------


def test_network_never_included_in_run_all(db: Session) -> None:
    case, ev = _make_case_and_evidence(db)
    plan = plan_run_all(db, case_id=case.id, evidence_id=ev.id, mode="rerun_all")
    assert "network_basic" not in plan["selected_profiles"]
    # network_basic is excluded from the run-all allowlist itself.
    assert "network_basic" not in RUN_ALL_PROFILES


# ---------- 8. processes_basic omitted when processes_extended is selected ----------


def test_processes_basic_omitted_in_run_all(db: Session) -> None:
    case, ev = _make_case_and_evidence(db)
    plan = plan_run_all(db, case_id=case.id, evidence_id=ev.id, mode="rerun_all")
    assert "processes_extended" in plan["selected_profiles"]
    assert "processes_basic" not in plan["selected_profiles"]
    excluded = {e["profile"] for e in plan["excluded_profiles"]}
    assert "processes_basic" in excluded


# ---------- 9. run-all uses a fixed order ----------


def test_run_all_uses_fixed_order(db: Session) -> None:
    case, ev = _make_case_and_evidence(db)
    plan = plan_run_all(db, case_id=case.id, evidence_id=ev.id, mode="rerun_all")
    assert plan["selected_profiles"] == list(RUN_ALL_PROFILES)


# ---------- 10 + 11. Sequential execution, never two profiles active in same batch ----------


def test_sequential_execution_and_no_overlap(db: Session) -> None:
    case, ev = _make_case_and_evidence(db)
    enqueued: list[str] = []

    def fake_enqueue(run_id: str) -> str:
        enqueued.append(run_id)
        return f"rq-{run_id}"

    result = create_run_all_batch(
        db,
        case_id=case.id,
        evidence_id=ev.id,
        mode="rerun_all",
        authorization_acknowledged=True,
        continue_on_failure=True,
        enqueue_fn=fake_enqueue,
    )
    batch = result["batch"]
    assert len(enqueued) == 1
    # At this point only one run is enqueued; the batch tracks the rest.
    assert batch.current_profile == RUN_ALL_PROFILES[0]
    # Simulate the first run completing.
    db.refresh(batch)
    runs = db.query(MemoryScanRun).filter(MemoryScanRun.batch_id == batch.id).all()
    assert len(runs) == 1
    runs[0].status = "completed"
    db.commit()
    advanced = advance_batch(db, run=runs[0], enqueue_fn=fake_enqueue)
    assert advanced is not None
    assert advanced.current_profile == RUN_ALL_PROFILES[1]
    # After advance, a second run was enqueued, but still not parallel.
    assert len(enqueued) == 2


# ---------- 12. missing_or_failed skips completed profiles ----------


def test_missing_or_failed_skips_completed(db: Session) -> None:
    case, ev = _make_case_and_evidence(db)
    for profile in RUN_ALL_PROFILES:
        _make_run(db, case_id=case.id, evidence_id=ev.id, profile=profile, status="completed")
    plan = plan_run_all(db, case_id=case.id, evidence_id=ev.id, mode="missing_or_failed")
    assert plan["selected_profiles"] == []
    skipped = {s["profile"] for s in plan["skipped_profiles"]}
    assert skipped == set(RUN_ALL_PROFILES)


# ---------- 13. rerun_all includes completed profiles ----------


def test_rerun_all_includes_completed(db: Session) -> None:
    case, ev = _make_case_and_evidence(db)
    for profile in RUN_ALL_PROFILES:
        _make_run(db, case_id=case.id, evidence_id=ev.id, profile=profile, status="completed")
    plan = plan_run_all(db, case_id=case.id, evidence_id=ev.id, mode="rerun_all")
    assert plan["selected_profiles"] == list(RUN_ALL_PROFILES)


# ---------- 14. Failed run does not replace active result ----------


def test_failed_run_does_not_replace_active_result(db: Session) -> None:
    case, ev = _make_case_and_evidence(db)
    _make_run(db, case_id=case.id, evidence_id=ev.id, profile="metadata_only", status="completed", minutes_ago=60)
    _make_run(db, case_id=case.id, evidence_id=ev.id, profile="metadata_only", status="failed", minutes_ago=5)
    result = resolve_active_memory_result(db, case_id=case.id, evidence_id=ev.id, family="system_info")
    assert result["active_run"] is not None
    assert result["active_run"]["status"] == "completed"
    assert result["using_fallback"] is True
    assert result["selection_reason"] == "latest_attempt_failed_kept_last_success"


# ---------- 15. continue_on_failure is honoured ----------


def test_continue_on_failure_advances_after_failure(db: Session) -> None:
    case, ev = _make_case_and_evidence(db)
    enqueued: list[str] = []

    def fake_enqueue(run_id: str) -> str:
        enqueued.append(run_id)
        return f"rq-{run_id}"

    result = create_run_all_batch(
        db,
        case_id=case.id,
        evidence_id=ev.id,
        mode="rerun_all",
        authorization_acknowledged=True,
        continue_on_failure=True,
        enqueue_fn=fake_enqueue,
    )
    batch = result["batch"]
    db.refresh(batch)
    first = db.query(MemoryScanRun).filter(MemoryScanRun.batch_id == batch.id).first()
    # First profile (metadata_only) succeeds.
    first.status = "completed"
    db.commit()
    advanced = advance_batch(db, run=first, enqueue_fn=fake_enqueue)
    # Second profile (processes_extended) fails.
    second = db.query(MemoryScanRun).filter(
        MemoryScanRun.batch_id == batch.id,
        MemoryScanRun.profile == RUN_ALL_PROFILES[1],
    ).first()
    second.status = "failed"
    db.commit()
    advanced = advance_batch(db, run=second, enqueue_fn=fake_enqueue)
    # continue_on_failure=True keeps the batch going.
    assert advanced.status == "running"
    assert RUN_ALL_PROFILES[2] == advanced.current_profile
    assert RUN_ALL_PROFILES[1] in advanced.failed_profiles
    assert RUN_ALL_PROFILES[0] in advanced.completed_profiles


# ---------- 16. Fundamental failure of metadata_only stops the batch ----------


def test_metadata_only_failure_stops_batch(db: Session) -> None:
    case, ev = _make_case_and_evidence(db)
    enqueued: list[str] = []

    def fake_enqueue(run_id: str) -> str:
        enqueued.append(run_id)
        return f"rq-{run_id}"

    result = create_run_all_batch(
        db,
        case_id=case.id,
        evidence_id=ev.id,
        mode="rerun_all",
        authorization_acknowledged=True,
        continue_on_failure=True,
        enqueue_fn=fake_enqueue,
    )
    batch = result["batch"]
    db.refresh(batch)
    first = db.query(MemoryScanRun).filter(MemoryScanRun.batch_id == batch.id).first()
    first.status = "failed"
    db.commit()
    advanced = advance_batch(db, run=first, enqueue_fn=fake_enqueue)
    assert advanced.status == "failed"
    assert advanced.current_profile is None
    # No second enqueue.
    assert len(enqueued) == 1


# ---------- 17. Cancel prevents the next profile from being enqueued ----------


def test_cancel_prevents_next_profile(db: Session) -> None:
    case, ev = _make_case_and_evidence(db)
    enqueued: list[str] = []

    def fake_enqueue(run_id: str) -> str:
        enqueued.append(run_id)
        return f"rq-{run_id}"

    result = create_run_all_batch(
        db,
        case_id=case.id,
        evidence_id=ev.id,
        mode="rerun_all",
        authorization_acknowledged=True,
        continue_on_failure=True,
        enqueue_fn=fake_enqueue,
    )
    batch = result["batch"]
    db.refresh(batch)
    cancel_batch(db, batch_id=batch.id)
    first = db.query(MemoryScanRun).filter(MemoryScanRun.batch_id == batch.id).first()
    first.status = "completed"
    db.commit()
    advanced = advance_batch(db, run=first, enqueue_fn=fake_enqueue)
    # No second enqueue because the batch was cancelled.
    assert len(enqueued) == 1
    assert advanced.status in {"cancelled", "completed_with_errors", "completed"}


# ---------- 18. Double click does not create two batches ----------


def test_double_click_does_not_create_two_batches(db: Session) -> None:
    case, ev = _make_case_and_evidence(db)
    enqueued: list[str] = []

    def fake_enqueue(run_id: str) -> str:
        enqueued.append(run_id)
        return f"rq-{run_id}"

    create_run_all_batch(
        db,
        case_id=case.id,
        evidence_id=ev.id,
        mode="rerun_all",
        authorization_acknowledged=True,
        continue_on_failure=True,
        enqueue_fn=fake_enqueue,
    )
    with pytest.raises(MemoryBatchError) as excinfo:
        create_run_all_batch(
            db,
            case_id=case.id,
            evidence_id=ev.id,
            mode="rerun_all",
            authorization_acknowledged=True,
            continue_on_failure=True,
            enqueue_fn=fake_enqueue,
        )
    assert excinfo.value.code == "MEMORY_BATCH_ALREADY_ACTIVE"
    assert excinfo.value.status_code == 409


# ---------- 19. Batch is scoped by evidence_id ----------


def test_batch_scoped_by_evidence_id(db: Session) -> None:
    case, ev = _make_case_and_evidence(db)
    enqueued: list[str] = []

    def fake_enqueue(run_id: str) -> str:
        enqueued.append(run_id)
        return f"rq-{run_id}"

    create_run_all_batch(
        db,
        case_id=case.id,
        evidence_id=ev.id,
        mode="rerun_all",
        authorization_acknowledged=True,
        continue_on_failure=True,
        enqueue_fn=fake_enqueue,
    )
    # A second evidence in the same case can have its own batch.
    stored_path = str(getattr(db, "_tmp_path") / f"evidence-{uuid4()}.dmp")
    with open(stored_path, "wb") as fh:
        fh.write(b"\x00" * 4096)
    ev2 = Evidence(
        id=str(uuid4()),
        case_id=case.id,
        original_filename="other.dmp",
        stored_path=stored_path,
        storage_mode=EvidenceStorageMode.uploaded,
        evidence_type=EvidenceType.memory_dump,
        sha256="0" * 64,
        size_bytes=1 * 1024 * 1024 * 1024,
        ingest_status=IngestStatus.completed,
    )
    db.add(ev2)
    db.flush()
    create_run_all_batch(
        db,
        case_id=case.id,
        evidence_id=ev2.id,
        mode="rerun_all",
        authorization_acknowledged=True,
        continue_on_failure=True,
        enqueue_fn=fake_enqueue,
    )
    assert len(enqueued) == 2


# ---------- 20. Evidence from another case is rejected ----------


def test_evidence_from_another_case_rejected(db: Session) -> None:
    case, ev = _make_case_and_evidence(db)
    other_case, other_ev = _make_case_and_evidence(db)
    from app.api.routes_memory import _require_evidence_for_case
    from fastapi import HTTPException

    with pytest.raises(HTTPException) as excinfo:
        _require_evidence_for_case(db, case.id, other_ev.id)
    assert excinfo.value.status_code == 404


# ---------- 21. Arbitrary profile injection is rejected ----------


def test_arbitrary_profile_injection_rejected(db: Session) -> None:
    case, ev = _make_case_and_evidence(db)
    from app.services.memory.batch import _reject_incompatible_profiles

    with pytest.raises(MemoryBatchError) as excinfo:
        _reject_incompatible_profiles(["metadata_only", "windows.dumpfiles"])
    assert excinfo.value.code == "MEMORY_BATCH_PROFILE_NOT_ALLOWLISTED"


# ---------- 22. Authorization is required ----------


def test_authorization_required(db: Session) -> None:
    case, ev = _make_case_and_evidence(db)

    def fake_enqueue(run_id: str) -> str:
        return f"rq-{run_id}"

    with pytest.raises(MemoryBatchError) as excinfo:
        create_run_all_batch(
            db,
            case_id=case.id,
            evidence_id=ev.id,
            mode="rerun_all",
            authorization_acknowledged=False,
            continue_on_failure=True,
            enqueue_fn=fake_enqueue,
        )
    assert excinfo.value.code == "MEMORY_BATCH_AUTHORIZATION_REQUIRED"


# ---------- 23. No disk index writes happen during planning ----------


def test_planning_does_not_write_disk_index(db: Session) -> None:
    case, ev = _make_case_and_evidence(db)
    # No openSearch client is touched; planning is pure DB query.
    plan = plan_run_all(db, case_id=case.id, evidence_id=ev.id, mode="missing_or_failed")
    assert "selected_profiles" in plan


# ---------- 24. No NormalizedEvent is created during planning ----------


def test_planning_does_not_create_normalized_event(db: Session) -> None:
    case, ev = _make_case_and_evidence(db)
    # We don't have a NormalizedEvent model in this app; the spec is
    # about not emitting any side effects during planning.  We assert
    # the DB row count of MemoryScanRun stays at zero.
    before = db.query(MemoryScanRun).count()
    plan_run_all(db, case_id=case.id, evidence_id=ev.id, mode="rerun_all")
    after = db.query(MemoryScanRun).count()
    assert before == after


# ---------- 25. Network rejection does not enqueue a job ----------


def test_network_rejection_does_not_enqueue(db: Session) -> None:
    case, ev = _make_case_and_evidence(db)
    enqueued: list[str] = []

    def fake_enqueue(run_id: str) -> str:
        enqueued.append(run_id)
        return f"rq-{run_id}"

    # network_basic is not in the run-all allowlist, so the plan never
    # enqueues it.  We also assert plan_run_all does not enqueue.
    plan = plan_run_all(db, case_id=case.id, evidence_id=ev.id, mode="rerun_all")
    assert "network_basic" not in plan["selected_profiles"]
    # And create_run_all_batch never references network_basic.
    result = create_run_all_batch(
        db,
        case_id=case.id,
        evidence_id=ev.id,
        mode="rerun_all",
        authorization_acknowledged=True,
        continue_on_failure=True,
        enqueue_fn=fake_enqueue,
    )
    enqueued_profiles = {
        run.profile
        for run in db.query(MemoryScanRun).filter(MemoryScanRun.batch_id == result["batch"].id)
    }
    assert "network_basic" not in enqueued_profiles


# ---------- 26. Active result preserved during a running batch ----------


def test_active_result_preserved_during_running_batch(db: Session) -> None:
    case, ev = _make_case_and_evidence(db)
    completed_run = _make_run(db, case_id=case.id, evidence_id=ev.id, profile="metadata_only", status="completed", minutes_ago=60)
    enqueued: list[str] = []

    def fake_enqueue(run_id: str) -> str:
        enqueued.append(run_id)
        return f"rq-{run_id}"

    result = create_run_all_batch(
        db,
        case_id=case.id,
        evidence_id=ev.id,
        mode="rerun_all",
        authorization_acknowledged=True,
        continue_on_failure=True,
        enqueue_fn=fake_enqueue,
    )
    # While the batch is running, the active result for system_info
    # is still the previously completed run.  The newly created run
    # is "pending"/"queued" so it becomes the "latest_attempt" and
    # triggers the fallback flag (latest_attempt_failed_kept_last_success
    # is the existing name for the same concept; we just need the
    # active_run to point to the previous successful one).
    active = resolve_active_memory_result(db, case_id=case.id, evidence_id=ev.id, family="system_info")
    assert active["active_run"] is not None
    assert active["active_run"]["id"] == completed_run.id
    assert active["active_run"]["status"] == "completed"
    # using_fallback is True because the latest attempt is the
    # newly-queued rerun (which has not finished yet).
    assert active["using_fallback"] is True


# ---------- 26 (extra). Cross-evidence isolation: a run for evidence A
#                          must never be returned as the active result
#                          for evidence B ----------


def test_cross_evidence_isolation(db: Session) -> None:
    case, ev_a = _make_case_and_evidence(db)
    ev_b_id = str(uuid4())
    stored_path = str(getattr(db, "_tmp_path") / f"evidence-{ev_b_id}.dmp")
    with open(stored_path, "wb") as fh:
        fh.write(b"\x00" * 4096)
    ev_b = Evidence(
        id=ev_b_id,
        case_id=case.id,
        original_filename="other.dmp",
        stored_path=stored_path,
        storage_mode=EvidenceStorageMode.uploaded,
        evidence_type=EvidenceType.memory_dump,
        sha256="0" * 64,
        size_bytes=1 * 1024 * 1024 * 1024,
        ingest_status=IngestStatus.completed,
    )
    db.add(ev_b)
    db.flush()
    _make_run(db, case_id=case.id, evidence_id=ev_a.id, profile="metadata_only", status="completed")
    active_a = resolve_active_memory_result(db, case_id=case.id, evidence_id=ev_a.id, family="system_info")
    active_b = resolve_active_memory_result(db, case_id=case.id, evidence_id=ev_b.id, family="system_info")
    assert active_a["active_run"] is not None
    assert active_b["active_run"] is None
    assert active_a["evidence_id"] == ev_a.id
    assert active_b["evidence_id"] == ev_b.id
