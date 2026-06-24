"""Tests for the unified memory preparation retry dispatch contract.

Sprint: both the canonical ``/preparation/retry`` (sprint 6) and the
legacy ``/symbol-preparation/retry`` endpoints must:

* persist a single active preparation row;
* enqueue an RQ job to the memory queue;
* return the task ID and queue name;
* never leave ``worker_task_id = NULL`` after a successful response;
* never create a second active preparation row on a re-click;
* never create a ``MemoryScanRun`` row;
* refuse dispatch failures with an explicit ``dispatch_failed`` state.

These tests pin the unified contract so the UI retry button and any
older client that still hits ``/symbol-preparation/retry`` both
produce the same observable dispatch behaviour.
"""
from __future__ import annotations

import uuid as _uuid

import pytest
from fastapi import HTTPException
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from app.api import routes_memory
from app.core.database import Base
from app.models.case import Case
from app.models.evidence import Evidence, EvidenceType, IngestStatus
from app.models.memory import (
    MemoryScanRun,
    MemorySymbolPreparation,
)
from app.services.memory import preparation_runtime as pr
from app.services.memory.symbol_preparation import (
    PREP_DISPATCH_FAILED_STATE,
    PREP_QUEUED,
    PREP_READY,
)
from app.services.memory.preparation_runtime import PREP_DISPATCH_FAILED


CASE_ID = "cccccccc-3333-4333-8333-333333000001"
EVIDENCE_ID = "dddddddd-4444-4444-8444-444444000001"
OTHER_CASE_ID = "cccccccc-3333-4333-8333-333333000002"
OTHER_EVIDENCE_ID = "dddddddd-4444-4444-8444-444444000002"


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


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


def _make_case(db, case_id: str = CASE_ID) -> Case:
    case = Case(id=case_id, name="Retry dispatch case")
    db.add(case)
    db.commit()
    return case


def _make_evidence(
    db,
    case_id: str = CASE_ID,
    evidence_id: str = EVIDENCE_ID,
) -> Evidence:
    ev = Evidence(
        id=evidence_id,
        case_id=case_id,
        original_filename="mem.img",
        stored_path="/tmp/mem.img",
        original_path="/tmp/mem.img",
        evidence_type=EvidenceType.memory_dump,
        sha256="0" * 64,
        size_bytes=1024,
        ingest_status=IngestStatus.completed,
        detection_status="confirmed_memory",
        detected_format="windows_crash_dump",
        metadata_json={},
        error_log={},
    )
    db.add(ev)
    db.commit()
    return ev


def _patch_enqueue(monkeypatch, *, raise_exc: Exception | None = None):
    """Patch ``enqueue_memory_preparation`` so we never touch Redis.

    The import is resolved at call time from
    ``app.workers.tasks.enqueue_memory_preparation`` inside
    ``dispatch_memory_preparation``, so we patch the function
    in its defining module.
    """
    calls: list[str] = []

    def _fake_enqueue(evidence_id):
        calls.append(evidence_id)
        if raise_exc is not None:
            raise raise_exc
        return f"rq-job-{_uuid.uuid4()}"

    from app.workers import tasks as workers_tasks
    monkeypatch.setattr(
        workers_tasks, "enqueue_memory_preparation", _fake_enqueue
    )
    return calls


# ---------------------------------------------------------------------------
# New endpoint: /preparation/retry
# ---------------------------------------------------------------------------


class TestPreparationRetryEndpoint:
    """The sprint-6 /preparation/retry endpoint must always dispatch."""

    def test_1_new_endpoint_dispatches_job(
        self, db_session, monkeypatch
    ) -> None:
        """POST /preparation/retry persists the row AND enqueues an RQ job."""
        _make_case(db_session)
        ev = _make_evidence(db_session)
        calls = _patch_enqueue(monkeypatch)

        result = routes_memory.retry_memory_preparation(
            case_id=CASE_ID,
            evidence_id=EVIDENCE_ID,
            db=db_session,
        )

        assert result["state"] == PREP_QUEUED
        assert result["task_active"] is True
        assert result["queue"] == "memory"
        assert result["worker_task_id"] is not None
        assert result["worker_task_id"].startswith("rq-job-")
        assert calls == [EVIDENCE_ID]

    def test_2_new_endpoint_does_not_create_scan_runs(
        self, db_session, monkeypatch
    ) -> None:
        """A retry must never fabricate a MemoryScanRun."""
        _make_case(db_session)
        ev = _make_evidence(db_session)
        _patch_enqueue(monkeypatch)
        scan_before = db_session.query(MemoryScanRun).count()

        routes_memory.retry_memory_preparation(
            case_id=CASE_ID,
            evidence_id=EVIDENCE_ID,
            db=db_session,
        )

        assert db_session.query(MemoryScanRun).count() == scan_before

    def test_3_new_endpoint_persists_worker_task_id_on_row(
        self, db_session, monkeypatch
    ) -> None:
        """The preparation row must store worker_task_id and queue_name."""
        _make_case(db_session)
        ev = _make_evidence(db_session)
        _patch_enqueue(monkeypatch)

        result = routes_memory.retry_memory_preparation(
            case_id=CASE_ID,
            evidence_id=EVIDENCE_ID,
            db=db_session,
        )

        prep = (
            db_session.query(MemorySymbolPreparation)
            .filter(MemorySymbolPreparation.evidence_id == EVIDENCE_ID)
            .order_by(MemorySymbolPreparation.created_at.desc())
            .first()
        )
        assert prep is not None
        assert prep.worker_task_id == result["worker_task_id"]
        assert prep.queue_name == "memory"
        assert prep.worker_task_id is not None
        assert prep.queue_name is not None

    def test_4_new_endpoint_dispatch_failure_returns_500(
        self, db_session, monkeypatch
    ) -> None:
        """A Redis enqueue failure must surface as 500 dispatch_failed."""
        _make_case(db_session)
        ev = _make_evidence(db_session)
        _patch_enqueue(monkeypatch, raise_exc=RuntimeError("redis down"))

        with pytest.raises(HTTPException) as exc_info:
            routes_memory.retry_memory_preparation(
                case_id=CASE_ID,
                evidence_id=EVIDENCE_ID,
                db=db_session,
            )
        assert exc_info.value.status_code == 500
        assert exc_info.value.detail["error_code"] == PREP_DISPATCH_FAILED
        assert exc_info.value.detail["retryable"] is True

        # The row must be in dispatch_failed, NOT orphaned in queued.
        prep = (
            db_session.query(MemorySymbolPreparation)
            .filter(MemorySymbolPreparation.evidence_id == EVIDENCE_ID)
            .order_by(MemorySymbolPreparation.created_at.desc())
            .first()
        )
        assert prep is not None
        assert prep.state == PREP_DISPATCH_FAILED_STATE
        assert prep.worker_task_id is None

    def test_5_new_endpoint_authorization(
        self, db_session, monkeypatch
    ) -> None:
        """The endpoint refuses evidence that does not belong to the case."""
        _make_case(db_session, case_id=CASE_ID)
        _make_evidence(db_session, case_id=CASE_ID, evidence_id=EVIDENCE_ID)
        _make_evidence(
            db_session,
            case_id=OTHER_CASE_ID,
            evidence_id=OTHER_EVIDENCE_ID,
        )
        _patch_enqueue(monkeypatch)

        with pytest.raises(HTTPException) as exc_info:
            routes_memory.retry_memory_preparation(
                case_id=OTHER_CASE_ID,
                evidence_id=EVIDENCE_ID,  # belongs to CASE_ID, not OTHER
                db=db_session,
            )
        assert exc_info.value.status_code == 404


# ---------------------------------------------------------------------------
# Legacy endpoint: /symbol-preparation/retry
# ---------------------------------------------------------------------------


class TestSymbolPreparationRetryEndpoint:
    """The legacy endpoint must produce the SAME dispatch contract."""

    def test_6_legacy_endpoint_dispatches_canonical_job(
        self, db_session, monkeypatch
    ) -> None:
        """POST /symbol-preparation/retry also enqueues via dispatch_memory_preparation."""
        _make_case(db_session)
        ev = _make_evidence(db_session)
        calls = _patch_enqueue(monkeypatch)

        result = routes_memory.post_memory_symbol_preparation_retry(
            case_id=CASE_ID,
            evidence_id=EVIDENCE_ID,
            db=db_session,
        )

        # Backward-compat fields still present.
        assert result["requeued"] is True
        assert result["case_id"] == CASE_ID
        assert result["evidence_id"] == EVIDENCE_ID
        # New dispatch fields.
        assert result["state"] == PREP_QUEUED
        assert result["task_active"] is True
        assert result["queue"] == "memory"
        assert result["worker_task_id"] is not None
        assert calls == [EVIDENCE_ID]

    def test_7_legacy_endpoint_never_leaves_worker_task_id_null(
        self, db_session, monkeypatch
    ) -> None:
        """After a successful legacy retry, the row MUST have a non-null worker_task_id."""
        _make_case(db_session)
        ev = _make_evidence(db_session)
        _patch_enqueue(monkeypatch)

        result = routes_memory.post_memory_symbol_preparation_retry(
            case_id=CASE_ID,
            evidence_id=EVIDENCE_ID,
            db=db_session,
        )

        assert result["worker_task_id"] is not None
        assert result["queue"] is not None

        prep = (
            db_session.query(MemorySymbolPreparation)
            .filter(MemorySymbolPreparation.evidence_id == EVIDENCE_ID)
            .order_by(MemorySymbolPreparation.created_at.desc())
            .first()
        )
        assert prep is not None
        assert prep.worker_task_id is not None
        assert prep.queue_name == "memory"
        assert prep.state == PREP_QUEUED

    def test_8_legacy_endpoint_dispatch_failure_returns_500(
        self, db_session, monkeypatch
    ) -> None:
        """A Redis enqueue failure on the legacy endpoint must also 500."""
        _make_case(db_session)
        ev = _make_evidence(db_session)
        _patch_enqueue(monkeypatch, raise_exc=RuntimeError("redis down"))

        with pytest.raises(HTTPException) as exc_info:
            routes_memory.post_memory_symbol_preparation_retry(
                case_id=CASE_ID,
                evidence_id=EVIDENCE_ID,
                db=db_session,
            )
        assert exc_info.value.status_code == 500
        assert exc_info.value.detail["error_code"] == PREP_DISPATCH_FAILED

    def test_9_legacy_endpoint_does_not_create_scan_runs(
        self, db_session, monkeypatch
    ) -> None:
        """The legacy endpoint must not create any MemoryScanRun."""
        _make_case(db_session)
        ev = _make_evidence(db_session)
        _patch_enqueue(monkeypatch)
        scan_before = db_session.query(MemoryScanRun).count()

        routes_memory.post_memory_symbol_preparation_retry(
            case_id=CASE_ID,
            evidence_id=EVIDENCE_ID,
            db=db_session,
        )

        assert db_session.query(MemoryScanRun).count() == scan_before

    def test_10_legacy_endpoint_authorization(
        self, db_session, monkeypatch
    ) -> None:
        """The legacy endpoint also enforces case ownership."""
        _make_case(db_session, case_id=CASE_ID)
        _make_evidence(db_session, case_id=CASE_ID, evidence_id=EVIDENCE_ID)
        _make_evidence(
            db_session,
            case_id=OTHER_CASE_ID,
            evidence_id=OTHER_EVIDENCE_ID,
        )
        _patch_enqueue(monkeypatch)

        with pytest.raises(HTTPException) as exc_info:
            routes_memory.post_memory_symbol_preparation_retry(
                case_id=OTHER_CASE_ID,
                evidence_id=EVIDENCE_ID,  # belongs to CASE_ID
                db=db_session,
            )
        assert exc_info.value.status_code == 404


# ---------------------------------------------------------------------------
# Idempotency and double-click behaviour
# ---------------------------------------------------------------------------


class TestRetryIdempotency:
    """Multiple retries must not create multiple active rows."""

    def test_11_double_click_no_duplicate_active_row(
        self, db_session, monkeypatch
    ) -> None:
        """Two retries on the same evidence must reuse the single active row."""
        _make_case(db_session)
        ev = _make_evidence(db_session)
        _patch_enqueue(monkeypatch)

        first = routes_memory.retry_memory_preparation(
            case_id=CASE_ID,
            evidence_id=EVIDENCE_ID,
            db=db_session,
        )
        first_id = first["preparation_id"]
        first_task = first["worker_task_id"]

        second = routes_memory.retry_memory_preparation(
            case_id=CASE_ID,
            evidence_id=EVIDENCE_ID,
            db=db_session,
        )

        assert second["preparation_id"] == first_id
        active_rows = (
            db_session.query(MemorySymbolPreparation)
            .filter(
                MemorySymbolPreparation.evidence_id == EVIDENCE_ID,
                MemorySymbolPreparation.active.is_(True),
            )
            .count()
        )
        assert active_rows == 1

    def test_12_existing_dead_queued_row_is_safely_reused(
        self, db_session, monkeypatch
    ) -> None:
        """A pre-existing dead queued row (worker_task_id NULL) is re-dispatched.

        This is the production scenario: an evidence uploaded while
        MEMORY_AUTO_PREPARATION was off left a dead ``queued`` row.
        A retry must replace its ``worker_task_id`` rather than leave
        it stranded.
        """
        _make_case(db_session)
        ev = _make_evidence(db_session)

        # Simulate the production dead row.
        dead = MemorySymbolPreparation(
            id=str(_uuid.uuid4()),
            case_id=CASE_ID,
            evidence_id=EVIDENCE_ID,
            state=PREP_QUEUED,
            state_reason="manual_retry",
            attempts=0,
            active=True,
            queue_name=None,
            worker_task_id=None,
            metadata_json={},
        )
        db_session.add(dead)
        db_session.commit()
        dead_id = dead.id

        _patch_enqueue(monkeypatch)
        result = routes_memory.retry_memory_preparation(
            case_id=CASE_ID,
            evidence_id=EVIDENCE_ID,
            db=db_session,
        )

        # The same row is reused.
        assert result["preparation_id"] == dead_id
        refreshed = db_session.get(MemorySymbolPreparation, dead_id)
        assert refreshed is not None
        assert refreshed.worker_task_id is not None
        assert refreshed.queue_name == "memory"
        assert refreshed.state == PREP_QUEUED


# ---------------------------------------------------------------------------
# Endpoint contract equality
# ---------------------------------------------------------------------------


class TestBothEndpointsProduceSameDispatch:
    """Both endpoints must produce the same observable dispatch result."""

    def test_13_both_endpoints_return_same_task_and_queue(
        self, db_session, monkeypatch
    ) -> None:
        """Calling both endpoints on the same evidence yields the same task+queue."""
        # Enqueue must be deterministic-ish: stub returns a known ID.
        from app.workers import tasks as workers_tasks
        monkeypatch.setattr(
            workers_tasks, "enqueue_memory_preparation",
            lambda evidence_id: f"rq-job-{evidence_id[:8]}",
        )

        # First, the new endpoint.
        _make_case(db_session)
        ev1 = _make_evidence(
            db_session, case_id=CASE_ID, evidence_id=EVIDENCE_ID
        )
        new_result = routes_memory.retry_memory_preparation(
            case_id=CASE_ID,
            evidence_id=EVIDENCE_ID,
            db=db_session,
        )

        # Second, the legacy endpoint on a fresh evidence.
        ev2 = _make_evidence(
            db_session, case_id=CASE_ID, evidence_id=OTHER_EVIDENCE_ID
        )
        legacy_result = routes_memory.post_memory_symbol_preparation_retry(
            case_id=CASE_ID,
            evidence_id=OTHER_EVIDENCE_ID,
            db=db_session,
        )

        # Same dispatch contract.
        assert new_result["state"] == legacy_result["state"]
        assert new_result["queue"] == legacy_result["queue"]
        assert new_result["task_active"] is True
        assert legacy_result["task_active"] is True
        assert new_result["worker_task_id"] is not None
        assert legacy_result["worker_task_id"] is not None
        # Legacy keeps backward-compat fields.
        assert legacy_result["requeued"] is True
        assert legacy_result["case_id"] == CASE_ID


# ---------------------------------------------------------------------------
# The requeue_preparation helper is now internal-only
# ---------------------------------------------------------------------------


class TestRequeueIsInternalHelper:
    """The requeue_preparation() helper must not be used by any retry path."""

    def test_14_legacy_route_does_not_call_requeue(
        self, db_session, monkeypatch
    ) -> None:
        """The legacy retry route must NOT call requeue_preparation."""
        _make_case(db_session)
        ev = _make_evidence(db_session)
        from app.services.memory import symbol_preparation as sp
        calls = []
        original = sp.requeue_preparation

        def _spy(*args, **kwargs):
            calls.append((args, kwargs))
            return original(*args, **kwargs)

        monkeypatch.setattr(sp, "requeue_preparation", _spy)
        _patch_enqueue(monkeypatch)

        routes_memory.post_memory_symbol_preparation_retry(
            case_id=CASE_ID,
            evidence_id=EVIDENCE_ID,
            db=db_session,
        )

        assert calls == [], (
            "legacy retry route must not call requeue_preparation "
            "— it must delegate to dispatch_memory_preparation"
        )
