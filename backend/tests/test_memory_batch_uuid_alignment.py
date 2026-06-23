"""Tests for sprint: Memory Batch UUID Schema Alignment & Live Run-All Closure v1.

The schema mismatch between the SQLAlchemy model
(``last_advanced_run_id`` declared as ``String(64)``) and the
live PostgreSQL column (``uuid``) caused every ``INSERT`` into
``memory_analysis_batches`` to fail with::

    column "last_advanced_run_id" is of type uuid but
    expression is of type character varying

This test module asserts the post-sprint behaviour:

1. The model declares ``last_advanced_run_id`` as a native
   ``UUID`` (as_uuid=False for string round-trip).
2. A new batch can be created with ``last_advanced_run_id=None``
   and round-trips through the database.
3. ``advance_batch`` stores a UUID string and dedupes duplicate
   callbacks.
4. The structured error handler converts SQLAlchemy
   ``DataError``/``IntegrityError``/``ProgrammingError`` into
   ``MEMORY_BATCH_DB_SCHEMA_ERROR`` with a migration hint.
5. The ``serialize_batch`` payload returns a string.
6. The migration v11 logic is idempotent and converts VARCHAR
   to UUID where applicable.
7. Comparison with ``run.id`` works without manual casts.
8. Cancellation works.
9. Reconciliation handles a non-UUID legacy value safely.
10. The runtime_validation mode completes the batch without
    touching heavy profiles.
"""
from __future__ import annotations

import os
import uuid as _uuid
from datetime import datetime
from unittest.mock import MagicMock

import pytest
import sqlalchemy as sa
from sqlalchemy import create_engine
from sqlalchemy.exc import DataError, IntegrityError, ProgrammingError
from sqlalchemy.orm import Session, sessionmaker

from app.core.database import Base, UUIDMixin
from app.models.case import Case, CaseStatus
from app.models.evidence import (
    Evidence, EvidenceStorageMode, EvidenceType, IngestStatus,
)
from app.models.memory import MemoryAnalysisBatch, MemoryScanRun
from app.services.memory import batch as batch_mod


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def db(tmp_path) -> Session:
    engine = create_engine("sqlite:///:memory:", connect_args={"check_same_thread": False})
    Base.metadata.create_all(bind=engine)
    Session_ = sessionmaker(bind=engine)
    session = Session_()
    try:
        yield session
    finally:
        session.close()
        engine.dispose()


def _make_case(db: Session) -> Case:
    case = Case(
        id=str(_uuid.uuid4()),
        name="uuid-test-case",
        mode="investigation",
        status=CaseStatus.open,
    )
    db.add(case)
    db.commit()
    db.refresh(case)
    return case


def _make_evidence(db: Session, case_id: str) -> Evidence:
    ev = Evidence(
        id=str(_uuid.uuid4()),
        case_id=case_id,
        original_filename="WS01-20240322-125737.dmp",
        stored_path="/tmp/WS01.dmp",
        original_path="/tmp/WS01.dmp",
        evidence_type=EvidenceType.memory_dump,
        storage_mode=EvidenceStorageMode.uploaded,
        is_external=False,
        copy_to_storage=True,
        sha256="0" * 64,
        size_bytes=4_255_346_688,
        ingest_status=IngestStatus.completed,
        path_validation={},
        ingest_source={"detected_host": "WS01"},
        metadata_json={},
        error_log={},
        detection_status="windows_memory",
    )
    db.add(ev)
    db.commit()
    db.refresh(ev)
    return ev


# ---------------------------------------------------------------------------
# 1. Model type alignment
# ---------------------------------------------------------------------------


def test_1_last_advanced_run_id_declared_as_uuid() -> None:
    """The model declares ``last_advanced_run_id`` as a native UUID."""
    col = MemoryAnalysisBatch.__table__.columns["last_advanced_run_id"]
    # The underlying SQLAlchemy type class is the postgresql UUID.
    assert "UUID" in type(col.type).__name__.upper()
    # The column is nullable: a brand new batch has not advanced yet.
    assert col.nullable is True


def test_2_batch_id_fk_on_runs_is_uuid() -> None:
    """``memory_scan_runs.batch_id`` is also a native UUID."""
    col = MemoryScanRun.__table__.columns["batch_id"]
    assert "UUID" in type(col.type).__name__.upper()
    assert col.nullable is True


# ---------------------------------------------------------------------------
# 2. Round-trip: create batch with last_advanced_run_id=NULL
# ---------------------------------------------------------------------------


def test_3_create_batch_with_null_last_advanced_run_id(db: Session) -> None:
    """A brand new batch starts with ``last_advanced_run_id=None``."""
    case = _make_case(db)
    ev = _make_evidence(db, case.id)
    batch = MemoryAnalysisBatch(
        case_id=case.id,
        evidence_id=ev.id,
        mode="runtime_validation",
        status="queued",
        requested_profiles=["metadata_only"],
        skipped_profiles=[],
        completed_profiles=[],
        failed_profiles=[],
        continue_on_failure=True,
        authorization_acknowledged=True,
    )
    db.add(batch)
    db.commit()
    db.refresh(batch)
    assert batch.last_advanced_run_id is None
    assert batch.id == str(_uuid.UUID(str(batch.id)))  # round-trip as UUID


def test_4_last_advanced_run_id_accepts_uuid_string(db: Session) -> None:
    """A UUID-format string is accepted (and matches run.id semantics)."""
    case = _make_case(db)
    ev = _make_evidence(db, case.id)
    run_id = str(_uuid.uuid4())
    batch = MemoryAnalysisBatch(
        case_id=case.id,
        evidence_id=ev.id,
        mode="runtime_validation",
        status="running",
        requested_profiles=["metadata_only"],
        skipped_profiles=[],
        completed_profiles=[],
        failed_profiles=[],
        continue_on_failure=True,
        authorization_acknowledged=True,
        last_advanced_run_id=run_id,
    )
    db.add(batch)
    db.commit()
    db.refresh(batch)
    assert batch.last_advanced_run_id == run_id


# ---------------------------------------------------------------------------
# 3. advance_batch and idempotent dedup
# ---------------------------------------------------------------------------


def _make_run(db: Session, *, batch_id: str, profile: str = "metadata_only") -> MemoryScanRun:
    """Insert a run that the advance can reference."""
    # Find the evidence via batch.
    batch = db.get(MemoryAnalysisBatch, batch_id)
    case_id = batch.case_id
    evidence_id = batch.evidence_id
    run = MemoryScanRun(
        id=str(_uuid.uuid4()),
        case_id=case_id,
        evidence_id=evidence_id,
        profile=profile,
        status="pending",
    )
    run.batch_id = batch_id
    db.add(run)
    db.commit()
    db.refresh(run)
    return run


def test_5_advance_batch_sets_last_advanced_run_id(db: Session, monkeypatch) -> None:
    """The first advance stores the run id; a second advance is a no-op."""
    case = _make_case(db)
    ev = _make_evidence(db, case.id)
    batch = MemoryAnalysisBatch(
        case_id=case.id,
        evidence_id=ev.id,
        mode="runtime_validation",
        status="running",
        requested_profiles=["metadata_only"],
        skipped_profiles=[],
        completed_profiles=[],
        failed_profiles=[],
        continue_on_failure=True,
        authorization_acknowledged=True,
    )
    db.add(batch)
    db.commit()
    db.refresh(batch)
    run = _make_run(db, batch_id=batch.id, profile="metadata_only")
    run.status = "completed"
    db.commit()
    db.refresh(run)

    # Bypass the evidence file access check in the unit test.
    def _fake_enqueue(db, *, batch, profile, position, enqueue_fn):
        return None
    monkeypatch.setattr(batch_mod, "_enqueue_profile", _fake_enqueue)

    # The advance dedupe guard fires before any worker call when
    # last_advanced_run_id is None, so the first advance should
    # mutate the batch and the second should be a no-op.
    noop_enq = MagicMock(return_value="task-1")
    result_1 = batch_mod.advance_batch(db, run=run, enqueue_fn=noop_enq)
    db.refresh(batch)
    assert result_1 is batch
    assert batch.last_advanced_run_id == run.id
    assert batch.status == "completed"
    assert batch.completed_profiles == ["metadata_only"]
    # Second call: no further enqueue, no state change.
    noop_enq_2 = MagicMock(return_value="task-2")
    result_2 = batch_mod.advance_batch(db, run=run, enqueue_fn=noop_enq_2)
    db.refresh(batch)
    assert result_2 is batch
    assert batch.last_advanced_run_id == run.id
    noop_enq_2.assert_not_called()


def test_6_compare_uses_str_eq_with_run_id(db: Session) -> None:
    """``last_advanced_run_id == run.id`` works without manual cast."""
    case = _make_case(db)
    ev = _make_evidence(db, case.id)
    run = MemoryScanRun(
        id=str(_uuid.uuid4()),
        case_id=case.id,
        evidence_id=ev.id,
        profile="metadata_only",
        status="pending",
    )
    db.add(run)
    db.commit()
    db.refresh(run)
    batch = MemoryAnalysisBatch(
        case_id=case.id,
        evidence_id=ev.id,
        mode="runtime_validation",
        status="running",
        requested_profiles=["metadata_only"],
        skipped_profiles=[],
        completed_profiles=[],
        failed_profiles=[],
        continue_on_failure=True,
        authorization_acknowledged=True,
        last_advanced_run_id=run.id,
    )
    db.add(batch)
    db.commit()
    db.refresh(batch)
    # String equality is the contract.
    assert batch.last_advanced_run_id == run.id
    # The reverse is also true.
    assert run.id == batch.last_advanced_run_id


def test_7_advance_batch_progresses_to_next_profile(db: Session, monkeypatch) -> None:
    """Completing the first profile moves to the next profile and enqueues it."""
    case = _make_case(db)
    ev = _make_evidence(db, case.id)
    batch = MemoryAnalysisBatch(
        case_id=case.id,
        evidence_id=ev.id,
        mode="runtime_validation",
        status="running",
        requested_profiles=["metadata_only", "processes_extended"],
        skipped_profiles=[],
        completed_profiles=[],
        failed_profiles=[],
        continue_on_failure=True,
        authorization_acknowledged=True,
        current_profile="metadata_only",
    )
    db.add(batch)
    db.commit()
    db.refresh(batch)
    run = _make_run(db, batch_id=batch.id, profile="metadata_only")
    run.status = "completed"
    db.commit()
    db.refresh(run)
    # Bypass the evidence file access check in the unit test by
    # stubbing ``_enqueue_profile`` to a no-op factory.
    def _fake_enqueue(db, *, batch, profile, position, enqueue_fn):
        new_run = MemoryScanRun(
            id=str(_uuid.uuid4()),
            case_id=batch.case_id,
            evidence_id=batch.evidence_id,
            profile=profile,
            status="queued",
            batch_id=batch.id,
            batch_position=position,
            batch_total=len(batch.requested_profiles),
        )
        db.add(new_run)
        db.flush()
        enqueue_fn(new_run.id)
        return new_run
    monkeypatch.setattr(batch_mod, "_enqueue_profile", _fake_enqueue)
    enq = MagicMock(return_value="task-1")
    batch_mod.advance_batch(db, run=run, enqueue_fn=enq)
    db.refresh(batch)
    assert batch.last_advanced_run_id == run.id
    # The next run was enqueued.
    enq.assert_called_once()
    # The batch is still running, now on the second profile.
    assert batch.current_profile == "processes_extended"
    assert batch.status == "running"


# ---------------------------------------------------------------------------
# 4. Cancellation
# ---------------------------------------------------------------------------


def test_8_cancel_marks_batch_as_cancellation_requested(db: Session) -> None:
    """Cancellation sets the flag and is reflected on the batch."""
    case = _make_case(db)
    ev = _make_evidence(db, case.id)
    batch = MemoryAnalysisBatch(
        case_id=case.id,
        evidence_id=ev.id,
        mode="runtime_validation",
        status="running",
        requested_profiles=["metadata_only"],
        skipped_profiles=[],
        completed_profiles=[],
        failed_profiles=[],
        continue_on_failure=True,
        authorization_acknowledged=True,
    )
    db.add(batch)
    db.commit()
    db.refresh(batch)
    batch_mod.cancel_batch(db, batch_id=batch.id)
    db.refresh(batch)
    assert batch.cancellation_requested is True
    assert batch.cancellation_reason == "operator_requested"


# ---------------------------------------------------------------------------
# 5. Structured error handling
# ---------------------------------------------------------------------------


def test_9_structured_error_for_db_schema_mismatch() -> None:
    """A DB schema error is converted to a structured HTTPException."""
    from fastapi import HTTPException
    from app.api.routes_memory import _structured_db_error

    # Build a DataError that looks like the live deployment's
    # original error.
    fake_orig = DataError("statement", {}, Exception("column mismatch"))
    exc = _structured_db_error(
        fake_orig,
        case_id="c1",
        evidence_id="e1",
        mode="missing_or_failed",
    )
    assert isinstance(exc, HTTPException)
    assert exc.status_code == 500
    assert exc.detail["error_code"] == "MEMORY_BATCH_DB_SCHEMA_ERROR"
    assert "migration" in exc.detail["message"].lower()
    assert exc.detail["expected_migration_version"] == 11


def test_10_structured_error_for_integrity_error() -> None:
    """An IntegrityError is also converted to a structured error."""
    from fastapi import HTTPException
    from app.api.routes_memory import _structured_db_error
    fake = IntegrityError("statement", {}, Exception("fk violation"))
    exc = _structured_db_error(fake, case_id="c1", evidence_id="e1", mode="missing_or_failed")
    assert isinstance(exc, HTTPException)
    assert exc.status_code == 500
    assert exc.detail["error_code"] == "MEMORY_BATCH_DB_SCHEMA_ERROR"


def test_11_structured_error_for_programming_error() -> None:
    """A ProgrammingError (datatype mismatch) is also caught."""
    from fastapi import HTTPException
    from app.api.routes_memory import _structured_db_error
    fake = ProgrammingError("statement", {}, Exception("datatype mismatch"))
    exc = _structured_db_error(fake, case_id="c1", evidence_id="e1", mode="missing_or_failed")
    assert isinstance(exc, HTTPException)
    assert exc.status_code == 500
    assert exc.detail["error_code"] == "MEMORY_BATCH_DB_SCHEMA_ERROR"


# ---------------------------------------------------------------------------
# 6. Serialization
# ---------------------------------------------------------------------------


def test_12_serialize_batch_returns_string_ids(db: Session) -> None:
    """``serialize_batch`` returns the UUID as a string at the API boundary."""
    case = _make_case(db)
    ev = _make_evidence(db, case.id)
    run_id = str(_uuid.uuid4())
    batch = MemoryAnalysisBatch(
        case_id=case.id,
        evidence_id=ev.id,
        mode="runtime_validation",
        status="running",
        requested_profiles=["metadata_only"],
        skipped_profiles=[],
        completed_profiles=[],
        failed_profiles=[],
        continue_on_failure=True,
        authorization_acknowledged=True,
        last_advanced_run_id=run_id,
    )
    db.add(batch)
    db.commit()
    db.refresh(batch)
    payload = batch_mod.serialize_batch(batch)
    # The id is a string at the API boundary.
    assert isinstance(payload["id"], str)
    assert payload["last_advanced_run_id"] == run_id
    # Timestamps are ISO strings.
    assert payload["created_at"] is None or isinstance(payload["created_at"], str)


# ---------------------------------------------------------------------------
# 7. Reconciliation
# ---------------------------------------------------------------------------


def test_13_reconcile_no_active_batches(db: Session) -> None:
    """Reconciliation with no active batches is a no-op."""
    summary = batch_mod.reconcile_memory_batches(db, enqueue_fn=MagicMock())
    assert summary["enqueued_first_profile"] == 0
    assert summary["advanced"] == 0
    assert summary["cancelled_after_cancel_request"] == 0
    assert summary["errors"] == 0


def test_14_reconcile_enqueues_missing_first_run(db: Session, monkeypatch) -> None:
    """A queued batch with no first run is enqueued by reconciliation."""
    case = _make_case(db)
    ev = _make_evidence(db, case.id)
    batch = MemoryAnalysisBatch(
        case_id=case.id,
        evidence_id=ev.id,
        mode="runtime_validation",
        status="queued",
        requested_profiles=["metadata_only"],
        skipped_profiles=[],
        completed_profiles=[],
        failed_profiles=[],
        continue_on_failure=True,
        authorization_acknowledged=True,
    )
    db.add(batch)
    db.commit()
    db.refresh(batch)
    # Bypass the evidence file access check.
    def _fake_enqueue(db, *, batch, profile, position, enqueue_fn):
        new_run = MemoryScanRun(
            id=str(_uuid.uuid4()),
            case_id=batch.case_id,
            evidence_id=batch.evidence_id,
            profile=profile,
            status="queued",
            batch_id=batch.id,
            batch_position=position,
            batch_total=len(batch.requested_profiles),
        )
        db.add(new_run)
        db.flush()
        enqueue_fn(new_run.id)
        return new_run
    monkeypatch.setattr(batch_mod, "_enqueue_profile", _fake_enqueue)
    enq = MagicMock(return_value="task-1")
    summary = batch_mod.reconcile_memory_batches(db, enqueue_fn=enq)
    db.refresh(batch)
    assert summary["enqueued_first_profile"] == 1
    assert batch.status == "running"
    assert batch.current_profile == "metadata_only"
    enq.assert_called_once()


# ---------------------------------------------------------------------------
# 8. Migration v11 idempotency (logic test, no PostgreSQL needed)
# ---------------------------------------------------------------------------


def test_15_migration_v11_no_op_when_column_already_uuid() -> None:
    """The migration is a no-op when the column is already a UUID on PostgreSQL."""
    from app.core.migrations import _v11_batches_last_advanced_run_id_uuid

    # Build a fake inspector that says: column exists, type is UUID, nullable.
    fake_inspector = MagicMock()
    fake_inspector.get_table_names.return_value = ["memory_analysis_batches"]
    fake_inspector.get_columns.return_value = [
        {"name": "last_advanced_run_id", "type": "UUID", "nullable": True},
    ]
    fake_conn = MagicMock()
    fake_conn.dialect.name = "postgresql"
    # Patch the inspector factory to return our fake.
    import app.core.migrations as mig
    monkey = pytest.MonkeyPatch()
    monkey.setattr(mig, "_inspector_for", lambda c: fake_inspector)
    try:
        _v11_batches_last_advanced_run_id_uuid(fake_conn)
    finally:
        monkey.undo()
    # No ALTER should have been issued.
    def _call_text(call) -> str:
        if not call.args:
            return ""
        arg = call.args[0]
        return getattr(arg, "text", str(arg))

    alter_calls = [
        call for call in fake_conn.execute.call_args_list
        if "ALTER" in _call_text(call)
    ]
    assert alter_calls == []


def test_16_migration_v11_converts_varchar_to_uuid() -> None:
    """The migration converts a VARCHAR(64) column to UUID on PostgreSQL."""
    from app.core.migrations import _v11_batches_last_advanced_run_id_uuid

    fake_inspector = MagicMock()
    fake_inspector.get_table_names.return_value = ["memory_analysis_batches"]
    # First call (memory_analysis_batches.last_advanced_run_id)
    # returns VARCHAR.  Second call (memory_scan_runs.batch_id)
    # returns the same.  The third call (nullable check) returns
    # True.  Subsequent calls would scan memory_scan_runs and that
    # table is not in get_table_names() — so the migration skips
    # the batch_id fix.
    def fake_get_columns(table, *args, **kwargs):
        if table == "memory_analysis_batches":
            return [{"name": "last_advanced_run_id", "type": "VARCHAR(64)", "nullable": True}]
        if table == "memory_scan_runs":
            return [{"name": "batch_id", "type": "VARCHAR(64)", "nullable": True}]
        return []
    fake_inspector.get_columns.side_effect = fake_get_columns
    fake_inspector.get_table_names.return_value = ["memory_analysis_batches", "memory_scan_runs"]
    fake_conn = MagicMock()
    fake_conn.dialect.name = "postgresql"
    # First execute() call: SELECT to detect invalid UUIDs.  The
    # magic mock returns an empty list so no invalid UUIDs are
    # reported.
    fake_conn.execute.return_value.fetchall.return_value = []
    import app.core.migrations as mig
    monkey = pytest.MonkeyPatch()
    monkey.setattr(mig, "_inspector_for", lambda c: fake_inspector)
    try:
        _v11_batches_last_advanced_run_id_uuid(fake_conn)
    finally:
        monkey.undo()
    # The migration must issue an ALTER COLUMN TYPE statement.
    def _call_text(call) -> str:
        if not call.args:
            return ""
        arg = call.args[0]
        return getattr(arg, "text", str(arg))

    alter_calls = [
        call for call in fake_conn.execute.call_args_list
        if "ALTER COLUMN" in _call_text(call) and "TYPE UUID" in _call_text(call)
    ]
    assert alter_calls, "expected at least one ALTER COLUMN TYPE statement"


# ---------------------------------------------------------------------------
# 9. Cross-check: model accepts both representations
# ---------------------------------------------------------------------------


def test_17_run_id_and_last_advanced_run_id_are_equivalent_strings(db: Session) -> None:
    """``run.id`` and ``last_advanced_run_id`` use the same Python type (str)."""
    case = _make_case(db)
    ev = _make_evidence(db, case.id)
    run = MemoryScanRun(
        id=str(_uuid.uuid4()),
        case_id=case.id,
        evidence_id=ev.id,
        profile="metadata_only",
        status="pending",
    )
    db.add(run)
    db.commit()
    db.refresh(run)
    assert isinstance(run.id, str)
    # Use the same string to set the FK and the dedupe column.
    batch = MemoryAnalysisBatch(
        case_id=case.id,
        evidence_id=ev.id,
        mode="runtime_validation",
        status="running",
        requested_profiles=["metadata_only"],
        skipped_profiles=[],
        completed_profiles=[],
        failed_profiles=[],
        continue_on_failure=True,
        authorization_acknowledged=True,
        last_advanced_run_id=run.id,
    )
    db.add(batch)
    db.commit()
    db.refresh(batch)
    # Update the run's batch_id to point at the new batch.
    run.batch_id = batch.id
    db.commit()
    db.refresh(run)
    # Both ends of the relationship are strings.
    assert isinstance(run.batch_id, str)
    assert isinstance(batch.last_advanced_run_id, str)
    assert run.batch_id == batch.id
    assert batch.last_advanced_run_id == run.id


# ---------------------------------------------------------------------------
# 10. End-to-end plan + create batch in runtime_validation mode
# ---------------------------------------------------------------------------


def test_18_plan_runtime_validation_only_picks_two_profiles(db: Session) -> None:
    """The ``runtime_validation`` plan only picks the first two profiles."""
    case = _make_case(db)
    ev = _make_evidence(db, case.id)
    plan = batch_mod.plan_run_all(
        db,
        case_id=case.id,
        evidence_id=ev.id,
        mode="runtime_validation",
    )
    assert plan["selected_profiles"] == ["metadata_only", "processes_extended"]


def test_19_create_run_all_batch_runtime_validation_creates_batch(db: Session, monkeypatch) -> None:
    """``runtime_validation`` mode creates a batch with no heavy profiles."""
    case = _make_case(db)
    ev = _make_evidence(db, case.id)

    # Bypass the symbol preflight (no preparation has been
    # recorded in the test DB).
    from app.services.memory import symbol_preparation as sp
    from app.services.memory import symbol_state as ss
    from app.services.memory.symbol_preparation import UI_STATE_READY
    fake_readiness = MagicMock()
    fake_readiness.ui_state = UI_STATE_READY
    monkeypatch.setattr(sp, "compute_memory_readiness", lambda db, evidence: fake_readiness)
    monkeypatch.setattr(ss, "evidence_symbol_state", lambda *a, **k: MagicMock(state="not_required", requirement=None, blocker=None, acquisition_supported=False))
    monkeypatch.setattr(batch_mod, "evidence_symbol_state", ss.evidence_symbol_state, raising=False)

    # Bypass the evidence file access check in the unit test by
    # stubbing ``_enqueue_profile`` to a no-op factory.
    def _fake_enqueue(db, *, batch, profile, position, enqueue_fn):
        new_run = MemoryScanRun(
            id=str(_uuid.uuid4()),
            case_id=batch.case_id,
            evidence_id=batch.evidence_id,
            profile=profile,
            status="queued",
            batch_id=batch.id,
            batch_position=position,
            batch_total=len(batch.requested_profiles),
        )
        db.add(new_run)
        db.flush()
        enqueue_fn(new_run.id)
        return new_run
    monkeypatch.setattr(batch_mod, "_enqueue_profile", _fake_enqueue)

    enq = MagicMock(return_value="task-1")
    result = batch_mod.create_run_all_batch(
        db,
        case_id=case.id,
        evidence_id=ev.id,
        mode="runtime_validation",
        authorization_acknowledged=True,
        continue_on_failure=True,
        enqueue_fn=enq,
    )
    batch = result["batch"]
    assert batch.mode == "runtime_validation"
    assert "metadata_only" in batch.requested_profiles
    assert "processes_extended" in batch.requested_profiles
    # No heavy profiles were scheduled.
    for heavy in (
        "modules_basic",
        "handles_basic",
        "kernel_basic",
        "suspicious_memory",
    ):
        assert heavy not in batch.requested_profiles
    assert batch.last_advanced_run_id is None
    # First run was enqueued.
    enq.assert_called_once()
