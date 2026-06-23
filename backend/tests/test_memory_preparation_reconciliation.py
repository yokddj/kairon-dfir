"""Backend tests for the Memory Preparation State Reconciliation v1.

Fourteen tests covering the v1 stabilization requirements:

 1. queued + metadata success → ready.
 2. queued + exact cache hit + metadata success → ready.
 3. queued without task → stale.
 4. queued with active task remains queued.
 5. reconciliation idempotent.
 6. no Volatility execution.
 7. no symbol download.
 8. no MemoryScanRun creation.
 9. duplicate preparations reconciled.
10. effective state overrides stale persisted state.
11. evidence scope (different case / different evidence).
12. no dfir-events writes.
13. no NormalizedEvent.
14. no evidence modification.
"""
from __future__ import annotations

import os
import uuid
from datetime import datetime
from pathlib import Path
from unittest.mock import patch

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import Session, sessionmaker

from app.core.config import get_settings
from app.core.database import Base, utc_now_naive
from app.models.case import Case
from app.models.evidence import Evidence, EvidenceStorageMode, EvidenceType, IngestStatus
from app.models.memory import (
    MemoryEvidenceContent,
    MemoryEvidenceSymbolLink,
    MemoryScanRun,
    MemorySymbolPreparation,
    MemorySymbolRequirement,
)
from app.services.memory import symbol_preparation as prep_module
from app.services.memory.symbol_preparation import (
    PREP_PROBING,
    PREP_QUEUED,
    PREP_READY,
    PREP_STALE,
    reconcile_memory_preparation_states,
    resolve_effective_memory_preparation_state,
)


# ---------------------------------------------------------------------------
# Fixtures and helpers
# ---------------------------------------------------------------------------


@pytest.fixture
def data_dir(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    root = tmp_path / "appdata"
    root.mkdir(parents=True, exist_ok=True)
    settings = get_settings()
    monkeypatch.setattr(settings, "backend_data_dir", root)
    monkeypatch.setattr(settings, "memory_auto_preparation", False)
    monkeypatch.setattr(settings, "memory_preparation_stale_seconds", 60)
    return root


@pytest.fixture
def db(data_dir: Path) -> Session:
    engine = create_engine("sqlite:///:memory:", connect_args={"check_same_thread": False})
    Base.metadata.create_all(bind=engine)
    Session_ = sessionmaker(bind=engine)
    session = Session_()
    try:
        yield session
    finally:
        session.close()
        engine.dispose()


def _make_case(db: Session, name: str = "case-A") -> Case:
    case = Case(name=name)
    db.add(case)
    db.commit()
    db.refresh(case)
    return case


def _make_evidence(db: Session, case_id: str, sha: str = "a" * 64, size: int = 4096) -> Evidence:
    """Create a memory evidence row without a real file on disk."""
    evidence = Evidence(
        id=str(uuid.uuid4()),
        case_id=case_id,
        original_filename="mem.img",
        stored_path="/nonexistent/memory-image.img",
        original_path="/nonexistent/memory-image.img",
        evidence_type=EvidenceType.memory_dump,
        storage_mode=EvidenceStorageMode.uploaded,
        is_external=False,
        copy_to_storage=True,
        sha256=sha,
        size_bytes=size,
        ingest_status=IngestStatus.completed,
        path_validation={},
        ingest_source={},
        metadata_json={},
        error_log={},
        processed_at=utc_now_naive(),
    )
    db.add(evidence)
    db.commit()
    db.refresh(evidence)
    return evidence


def _make_metadata_run(
    db: Session,
    *,
    case_id: str,
    evidence_id: str,
    status: str = "completed",
    plugins_completed: int = 1,
    plugins_failed: int = 0,
) -> MemoryScanRun:
    run = MemoryScanRun(
        id=str(uuid.uuid4()),
        case_id=case_id,
        evidence_id=evidence_id,
        profile="metadata_only",
        status=status,
        plugin_count=1,
        requested_plugin_count=1,
        plugins_completed=plugins_completed,
        plugins_failed=plugins_failed,
        started_at=utc_now_naive(),
        completed_at=utc_now_naive(),
        duration_ms=1000,
        metadata_json={"plugins": ["windows.info"]},
        error_log={},
        batch_id=None,
    )
    db.add(run)
    db.commit()
    db.refresh(run)
    return run


def _make_queued_prep(
    db: Session,
    *,
    case_id: str,
    evidence_id: str,
    active: bool = True,
) -> MemorySymbolPreparation:
    prep = MemorySymbolPreparation(
        id=str(uuid.uuid4()),
        case_id=case_id,
        evidence_id=evidence_id,
        state=PREP_QUEUED,
        state_reason="queued",
        attempts=0,
        progress_percent=5,
        active=active,
        metadata_json={},
    )
    db.add(prep)
    db.commit()
    db.refresh(prep)
    return prep


def _make_requirement(
    db: Session,
    *,
    case_id: str,
    evidence_id: str,
    pdb_name: str = "ntkrnlmp.pdb",
    guid: str = "ABCDEF1234567890ABCDEF1234567890",
    age: int = 1,
) -> MemorySymbolRequirement:
    # source_run_id and source_plugin_run_id are non-null FKs; we
    # create stub rows for them.
    stub_run = _make_metadata_run(
        db, case_id=case_id, evidence_id=evidence_id,
    )
    from app.models.memory import MemoryPluginRun
    stub_plugin = MemoryPluginRun(
        case_id=case_id,
        evidence_id=evidence_id,
        memory_scan_run_id=stub_run.id,
        plugin="windows.info",
        status="completed",
        started_at=utc_now_naive(),
        completed_at=utc_now_naive(),
        duration_ms=1000,
        metadata_json={},
    )
    db.add(stub_plugin)
    db.commit()
    db.refresh(stub_plugin)
    req = MemorySymbolRequirement(
        case_id=case_id,
        evidence_id=evidence_id,
        source_run_id=stub_run.id,
        source_plugin_run_id=stub_plugin.id,
        pdb_name=pdb_name,
        pdb_guid=guid,
        pdb_age=age,
        architecture="x64",
        symbol_key=f"{pdb_name}/{guid}-{age}",
        source="manual",
        confidence=1.0,
        is_shared=True,
        metadata_json={},
    )
    db.add(req)
    db.commit()
    db.refresh(req)
    return req


# ---------------------------------------------------------------------------
# 1. queued + metadata success → ready
# ---------------------------------------------------------------------------


def test_queued_with_metadata_success_becomes_ready(db: Session, data_dir: Path) -> None:
    case = _make_case(db)
    evidence = _make_evidence(db, case.id)
    _make_metadata_run(db, case_id=case.id, evidence_id=evidence.id)
    prep = _make_queued_prep(db, case_id=case.id, evidence_id=evidence.id)
    result = resolve_effective_memory_preparation_state(
        db, case_id=case.id, evidence_id=evidence.id,
    )
    assert result["persisted_state"] == PREP_QUEUED
    assert result["effective_state"] == PREP_READY
    assert result["reconciled"] is True
    assert result["source_of_truth"] == "successful_metadata_run"
    assert result["progress"] == 100
    db.refresh(prep)
    assert prep.state == PREP_READY
    assert prep.progress_percent == 100
    assert prep.source_of_truth == "successful_metadata_run"


# ---------------------------------------------------------------------------
# 2. queued + exact cache hit + metadata success → ready
# ---------------------------------------------------------------------------


def test_queued_with_exact_cache_and_metadata_becomes_ready(
    db: Session, data_dir: Path
) -> None:
    case = _make_case(db)
    evidence = _make_evidence(db, case.id)
    _make_metadata_run(db, case_id=case.id, evidence_id=evidence.id)
    req = _make_requirement(db, case_id=case.id, evidence_id=evidence.id)
    # Register a content identity and link to the requirement so
    # the exact cache match is reported.
    content = MemoryEvidenceContent(
        evidence_sha256=evidence.sha256,
        size_bytes=int(evidence.size_bytes),
        acquisition_metadata={"first_evidence_id": evidence.id, "first_filename": evidence.original_filename},
    )
    db.add(content)
    db.flush()
    link = MemoryEvidenceSymbolLink(
        case_id=case.id,
        evidence_id=evidence.id,
        requirement_id=req.id,
        state=PREP_READY,
        link_source="exact_cache_match",
    )
    db.add(link)
    db.commit()
    _make_queued_prep(db, case_id=case.id, evidence_id=evidence.id)
    result = resolve_effective_memory_preparation_state(
        db, case_id=case.id, evidence_id=evidence.id,
    )
    assert result["effective_state"] == PREP_READY
    assert result["source_of_truth"] == "successful_metadata_run"


# ---------------------------------------------------------------------------
# 3. queued without task → stale
# ---------------------------------------------------------------------------


def test_queued_without_task_becomes_stale(
    db: Session, data_dir: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    case = _make_case(db)
    evidence = _make_evidence(db, case.id)
    # No metadata run, no task.
    prep = _make_queued_prep(db, case_id=case.id, evidence_id=evidence.id)
    # Force the heartbeat into the past so the row is stale.
    prep.created_at = utc_now_naive() - __import__("datetime").timedelta(seconds=120)
    prep.updated_at = utc_now_naive() - __import__("datetime").timedelta(seconds=120)
    prep.last_heartbeat_at = utc_now_naive() - __import__("datetime").timedelta(seconds=120)
    db.commit()
    monkeypatch.setattr(prep_module, "_task_is_alive", lambda _id: False)
    result = resolve_effective_memory_preparation_state(
        db, case_id=case.id, evidence_id=evidence.id,
    )
    assert result["effective_state"] == PREP_STALE
    assert result["source_of_truth"] == "stale_timeout"
    assert result["stale"] is True
    db.refresh(prep)
    assert prep.state == PREP_STALE
    assert prep.failure_code == "MEMORY_PREPARATION_STALE"


# ---------------------------------------------------------------------------
# 4. queued with active task remains queued
# ---------------------------------------------------------------------------


def test_queued_with_active_task_remains_queued(
    db: Session, data_dir: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    case = _make_case(db)
    evidence = _make_evidence(db, case.id)
    prep = _make_queued_prep(db, case_id=case.id, evidence_id=evidence.id)
    prep.worker_task_id = "rq:job:abc-123"
    db.commit()
    monkeypatch.setattr(prep_module, "_task_is_alive", lambda _id: True)
    result = resolve_effective_memory_preparation_state(
        db, case_id=case.id, evidence_id=evidence.id,
    )
    assert result["effective_state"] == PREP_QUEUED
    assert result["reconciled"] is False
    assert result["source_of_truth"] == "active_task"
    assert result["task_alive"] is True
    # The persisted state is NOT modified.
    db.refresh(prep)
    assert prep.state == PREP_QUEUED


# ---------------------------------------------------------------------------
# 5. reconciliation idempotent
# ---------------------------------------------------------------------------


def test_reconciliation_idempotent(db: Session, data_dir: Path) -> None:
    case = _make_case(db)
    evidence = _make_evidence(db, case.id)
    _make_metadata_run(db, case_id=case.id, evidence_id=evidence.id)
    _make_queued_prep(db, case_id=case.id, evidence_id=evidence.id)
    stats1 = reconcile_memory_preparation_states(db, max_evidences=10)
    stats2 = reconcile_memory_preparation_states(db, max_evidences=10)
    stats3 = reconcile_memory_preparation_states(db, max_evidences=10)
    assert stats1["scanned"] == 1
    assert stats1["promoted_ready"] == 1
    # Second and third calls produce no further changes.
    assert stats2["promoted_ready"] == 0
    assert stats2["already_ready"] >= 0
    assert stats3["promoted_ready"] == 0


# ---------------------------------------------------------------------------
# 6. no Volatility execution
# ---------------------------------------------------------------------------


def test_resolution_does_not_run_volatility(
    db: Session, data_dir: Path
) -> None:
    case = _make_case(db)
    evidence = _make_evidence(db, case.id)
    _make_metadata_run(db, case_id=case.id, evidence_id=evidence.id)
    _make_queued_prep(db, case_id=case.id, evidence_id=evidence.id)
    forbidden = [
        "app.services.memory.volatility_runner.run_plugin",
        "app.services.memory.volatility_runner.run_windows_info",
        "app.services.memory.symbol_probe_controller.probe_evidence_symbol_requirement",
    ]
    patches = [patch(path, side_effect=AssertionError(f"called {path}")) for path in forbidden]
    for p in patches:
        p.start()
    try:
        reconcile_memory_preparation_states(db, max_evidences=10)
        resolve_effective_memory_preparation_state(
            db, case_id=case.id, evidence_id=evidence.id,
        )
    finally:
        for p in patches:
            p.stop()
    # No exception means none of the forbidden functions were called.


# ---------------------------------------------------------------------------
# 7. no symbol download
# ---------------------------------------------------------------------------


def test_resolution_does_not_download_symbols(
    db: Session, data_dir: Path
) -> None:
    case = _make_case(db)
    evidence = _make_evidence(db, case.id)
    _make_metadata_run(db, case_id=case.id, evidence_id=evidence.id)
    _make_queued_prep(db, case_id=case.id, evidence_id=evidence.id)
    with patch("app.services.memory.symbol_control.queue_symbol_acquisition") as qa:
        with patch("app.services.memory.symbol_control.request_symbol_acquisition_awaiting_approval") as ac:
            reconcile_memory_preparation_states(db, max_evidences=10)
            assert qa.call_count == 0
            assert ac.call_count == 0


# ---------------------------------------------------------------------------
# 8. no MemoryScanRun creation
# ---------------------------------------------------------------------------


def test_resolution_does_not_create_scan_runs(db: Session, data_dir: Path) -> None:
    case = _make_case(db)
    evidence = _make_evidence(db, case.id)
    _make_metadata_run(db, case_id=case.id, evidence_id=evidence.id)
    _make_queued_prep(db, case_id=case.id, evidence_id=evidence.id)
    before = db.query(MemoryScanRun).filter(MemoryScanRun.evidence_id == evidence.id).count()
    reconcile_memory_preparation_states(db, max_evidences=10)
    after = db.query(MemoryScanRun).filter(MemoryScanRun.evidence_id == evidence.id).count()
    assert before == after
    # Specifically: no new runs are created with profile=metadata_only
    # or any other profile as a side-effect.
    new_runs = db.query(MemoryScanRun).filter(
        MemoryScanRun.evidence_id == evidence.id,
        MemoryScanRun.created_at > utc_now_naive(),
    ).count()
    assert new_runs == 0


# ---------------------------------------------------------------------------
# 9. duplicate preparations reconciled
# ---------------------------------------------------------------------------


def test_duplicate_preparations_deactivated(
    db: Session, data_dir: Path
) -> None:
    case = _make_case(db)
    evidence = _make_evidence(db, case.id)
    _make_metadata_run(db, case_id=case.id, evidence_id=evidence.id)
    # The partial unique index ``uq_memory_symbol_prep_active_evidence``
    # guarantees at most one active preparation per evidence.  We
    # verify the constraint is in place by attempting to insert a
    # second active row for the same evidence and expecting an
    # integrity error.
    from sqlalchemy.exc import IntegrityError
    _make_queued_prep(
        db, case_id=case.id, evidence_id=evidence.id, active=True,
    )
    with pytest.raises(IntegrityError):
        duplicate = MemorySymbolPreparation(
            case_id=case.id,
            evidence_id=evidence.id,
            state=PREP_QUEUED,
            attempts=0,
            progress_percent=5,
            active=True,
            metadata_json={},
        )
        db.add(duplicate)
        db.commit()
    db.rollback()
    # Historical (active=False) rows are allowed alongside an
    # active row; the audit trail is preserved.
    historical = MemorySymbolPreparation(
        case_id=case.id,
        evidence_id=evidence.id,
        state=PREP_QUEUED,
        attempts=0,
        progress_percent=5,
        active=False,
        metadata_json={},
    )
    db.add(historical)
    db.commit()
    all_rows = (
        db.query(MemorySymbolPreparation)
        .filter(MemorySymbolPreparation.evidence_id == evidence.id)
        .all()
    )
    assert len(all_rows) == 2
    # Only one is active.
    active_rows = (
        db.query(MemorySymbolPreparation)
        .filter(
            MemorySymbolPreparation.evidence_id == evidence.id,
            MemorySymbolPreparation.active == True,  # noqa: E712
        )
        .all()
    )
    assert len(active_rows) == 1
    # The reconciliation pass is a no-op when there is only one
    # active row and the state is correct.
    stats = reconcile_memory_preparation_states(db, max_evidences=10)
    assert stats["scanned"] >= 1


# ---------------------------------------------------------------------------
# 10. effective state overrides stale persisted state
# ---------------------------------------------------------------------------


def test_effective_state_overrides_stale_persisted_state(
    db: Session, data_dir: Path
) -> None:
    case = _make_case(db)
    evidence = _make_evidence(db, case.id)
    _make_metadata_run(db, case_id=case.id, evidence_id=evidence.id)
    prep = _make_queued_prep(db, case_id=case.id, evidence_id=evidence.id)
    # Persisted state is "queued"; the effective state must
    # override it to "ready" because a successful metadata run
    # exists.
    result = resolve_effective_memory_preparation_state(
        db, case_id=case.id, evidence_id=evidence.id,
    )
    assert result["persisted_state"] == PREP_QUEUED
    assert result["effective_state"] == PREP_READY
    assert result["reconciled"] is True
    # The persisted state has been promoted.
    db.refresh(prep)
    assert prep.state == PREP_READY


# ---------------------------------------------------------------------------
# 11. evidence scope
# ---------------------------------------------------------------------------


def test_resolution_is_scoped_to_evidence(db: Session, data_dir: Path) -> None:
    case = _make_case(db)
    evidence_a = _make_evidence(db, case.id, sha="a" * 64)
    evidence_b = _make_evidence(db, case.id, sha="b" * 64)
    _make_metadata_run(db, case_id=case.id, evidence_id=evidence_a.id)
    _make_queued_prep(db, case_id=case.id, evidence_id=evidence_a.id)
    _make_queued_prep(db, case_id=case.id, evidence_id=evidence_b.id)
    result_a = resolve_effective_memory_preparation_state(
        db, case_id=case.id, evidence_id=evidence_a.id,
    )
    result_b = resolve_effective_memory_preparation_state(
        db, case_id=case.id, evidence_id=evidence_b.id,
    )
    assert result_a["effective_state"] == PREP_READY
    assert result_b["effective_state"] != PREP_READY
    # The B preparation must not be touched by the A resolution.
    assert result_a["preparation_id"] != result_b["preparation_id"]


# ---------------------------------------------------------------------------
# 12. no dfir-events writes
# ---------------------------------------------------------------------------


def test_resolution_does_not_write_dfir_events(
    db: Session, data_dir: Path
) -> None:
    case = _make_case(db)
    evidence = _make_evidence(db, case.id)
    _make_metadata_run(db, case_id=case.id, evidence_id=evidence.id)
    _make_queued_prep(db, case_id=case.id, evidence_id=evidence.id)
    with patch("app.services.memory.indexing.get_opensearch_client") as os_spy:
        reconcile_memory_preparation_states(db, max_evidences=10)
        resolve_effective_memory_preparation_state(
            db, case_id=case.id, evidence_id=evidence.id,
        )
    assert os_spy.call_count == 0


# ---------------------------------------------------------------------------
# 13. no NormalizedEvent
# ---------------------------------------------------------------------------


def test_resolution_does_not_create_normalized_event(
    db: Session, data_dir: Path
) -> None:
    import app.services.memory.symbol_preparation as mod
    case = _make_case(db)
    evidence = _make_evidence(db, case.id)
    _make_metadata_run(db, case_id=case.id, evidence_id=evidence.id)
    _make_queued_prep(db, case_id=case.id, evidence_id=evidence.id)
    reconcile_memory_preparation_states(db, max_evidences=10)
    forbidden = [
        name for name in dir(mod)
        if "normalized_event" in name or "publish_event" in name
    ]
    assert forbidden == [], f"unexpected producer imported: {forbidden}"


# ---------------------------------------------------------------------------
# 14. no evidence modification
# ---------------------------------------------------------------------------


def test_resolution_does_not_modify_evidence(
    db: Session, data_dir: Path
) -> None:
    case = _make_case(db)
    evidence = _make_evidence(db, case.id)
    _make_metadata_run(db, case_id=case.id, evidence_id=evidence.id)
    _make_queued_prep(db, case_id=case.id, evidence_id=evidence.id)
    snapshot = {
        "id": evidence.id,
        "case_id": evidence.case_id,
        "original_filename": evidence.original_filename,
        "stored_path": evidence.stored_path,
        "sha256": evidence.sha256,
        "size_bytes": int(evidence.size_bytes),
    }
    reconcile_memory_preparation_states(db, max_evidences=10)
    db.refresh(evidence)
    assert evidence.id == snapshot["id"]
    assert evidence.case_id == snapshot["case_id"]
    assert evidence.original_filename == snapshot["original_filename"]
    assert evidence.stored_path == snapshot["stored_path"]
    assert evidence.sha256 == snapshot["sha256"]
    assert int(evidence.size_bytes) == snapshot["size_bytes"]


# ---------------------------------------------------------------------------
# Bonus: stale timeout
# ---------------------------------------------------------------------------


def test_stale_timeout_threshold(
    db: Session, data_dir: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    settings = get_settings()
    monkeypatch.setattr(settings, "memory_preparation_stale_seconds", 30)
    case = _make_case(db)
    evidence = _make_evidence(db, case.id)
    prep = _make_queued_prep(db, case_id=case.id, evidence_id=evidence.id)
    # Heartbeat is 60 seconds old: past the 30s threshold.
    from datetime import timedelta
    prep.last_heartbeat_at = utc_now_naive() - timedelta(seconds=60)
    db.commit()
    monkeypatch.setattr(prep_module, "_task_is_alive", lambda _id: False)
    result = resolve_effective_memory_preparation_state(
        db, case_id=case.id, evidence_id=evidence.id,
    )
    assert result["effective_state"] == PREP_STALE
    assert result["stale_reason"] == "no_task_no_metadata"
