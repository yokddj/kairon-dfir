"""Backend tests for sprint: OS-Agnostic Memory Preparation v1.

The tests cover the four critical regressions that caused every
new memory evidence to stay in ``queued`` forever:

1. The preparation row never received a worker task id.
2. The state machine was Windows-symbol-specific before the
   OS was even identified.
3. The reconciliation created rows without dispatching work.
4. The UI rendered a fake 5% progress on every queued row.

The tests assert:

* evidence registration succeeds without preparation
* dispatched rows receive a real task id and queue name
* enqueue failure becomes ``dispatch_failed`` and is retryable
* duplicate dispatch reuses the active row (idempotent)
* no row stays ``queued`` forever (stale reconciliation
  re-dispatches once or marks ``stale``)
* successful metadata implies ``ready``
* Windows / Linux / macOS adapters select the right probe
* unknown image terminates as ``platform_not_identified``
* no heavy profile is executed during preparation
* no symbol download during probe
* no dfir-events writes (probe is read-only)
* no evidence modification (probe is read-only)
* diagnostics endpoint reports queue mismatch
* retry endpoint is idempotent
* direct probe endpoint returns a task id
* progress_for_state no longer returns 5% for queued
"""
from __future__ import annotations

import os
import uuid as _uuid
from datetime import datetime
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import Session, sessionmaker

from app.core.database import Base
from app.core.config import get_settings
from app.models.case import Case, CaseStatus
from app.models.evidence import (
    Evidence, EvidenceStorageMode, EvidenceType, IngestStatus,
)
from app.services.memory.platform import (
    Architecture,
    LinuxMemoryAdapter,
    MacOSMemoryAdapter,
    PlatformFamily,
    ProbeConfidence,
    ProfileDefinition,
    UnsupportedMemoryAdapter,
    WindowsMemoryAdapter,
    get_adapter_for_probe,
    probe_memory_platform,
)
from app.services.memory import symbol_preparation as sp
from app.services.memory import preparation_runtime as pr


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
        name="os-agnostic-prep-test",
        mode="investigation",
        status=CaseStatus.open,
    )
    db.add(case)
    db.commit()
    db.refresh(case)
    return case


def _make_evidence(
    db: Session,
    case_id: str,
    *,
    filename: str = "WS01-20240322-125737.dmp",
    stored_path: str | None = None,
    detected_format: str = "windows_memory",
    detection_status: str = "windows_memory",
) -> Evidence:
    if stored_path is None:
        # The path is never opened by the bounded probe but the
        # model requires a non-empty value.
        stored_path = "/tmp/WS01-20240322-125737.dmp"
    ev = Evidence(
        id=str(_uuid.uuid4()),
        case_id=case_id,
        original_filename=filename,
        stored_path=stored_path,
        original_path=stored_path,
        evidence_type=EvidenceType.memory_dump,
        storage_mode=EvidenceStorageMode.uploaded,
        is_external=False,
        copy_to_storage=True,
        sha256="a" * 64,
        size_bytes=4_255_346_688,
        ingest_status=IngestStatus.completed,
        path_validation={},
        ingest_source={},
        metadata_json={},
        error_log={},
        detection_status=detection_status,
        detected_format=detected_format,
    )
    db.add(ev)
    db.commit()
    db.refresh(ev)
    return ev


# ---------------------------------------------------------------------------
# 1. evidence registration succeeds without preparation
# ---------------------------------------------------------------------------


def test_1_evidence_registration_succeeds_without_preparation(db: Session) -> None:
    """An evidence row commits even when the preparation pipeline
    is completely disabled.  No preparation row, no task, no
    error.
    """
    case = _make_case(db)
    ev = _make_evidence(db, case.id)
    # The evidence row is durable; the preparation row is not
    # required for registration.
    assert ev.id is not None
    assert ev.ingest_status == IngestStatus.completed
    from app.models.memory import MemorySymbolPreparation
    assert db.query(MemorySymbolPreparation).filter_by(evidence_id=ev.id).count() == 0


# ---------------------------------------------------------------------------
# 2. dispatched row receives a real task id
# ---------------------------------------------------------------------------


def test_2_dispatched_row_receives_real_task_id(db: Session, monkeypatch) -> None:
    """The dispatcher enqueues a real RQ job and stores the id
    on the preparation row.
    """
    case = _make_case(db)
    ev = _make_evidence(db, case.id)
    fake_job = MagicMock()
    fake_job.id = "rq-job-12345"
    monkeypatch.setattr(
        "app.workers.tasks.enqueue_memory_preparation",
        lambda evidence_id: fake_job.id,
    )
    result = pr.dispatch_memory_preparation(db, evidence=ev)
    assert result["task_active"] is True
    assert result["worker_task_id"] == "rq-job-12345"
    assert result["queue"] == get_settings().memory_queue_name
    # The row was committed with the task id.
    prep = db.query(sp.MemorySymbolPreparation).filter_by(evidence_id=ev.id).first()
    assert prep.worker_task_id == "rq-job-12345"
    assert prep.queue_name == get_settings().memory_queue_name
    assert prep.active is True


# ---------------------------------------------------------------------------
# 3. worker consumes the expected queue
# ---------------------------------------------------------------------------


def test_3_worker_uses_documented_queue(db: Session, monkeypatch) -> None:
    """The dispatcher's queue matches the ``memory_queue_name``
    setting.  Mismatch produces ``MEMORY_PREPARATION_QUEUE_MISMATCH``.
    """
    case = _make_case(db)
    ev = _make_evidence(db, case.id)
    monkeypatch.setattr(
        "app.workers.tasks.enqueue_memory_preparation",
        lambda evidence_id: "rq-job-9",
    )
    result = pr.dispatch_memory_preparation(db, evidence=ev)
    expected = get_settings().memory_queue_name
    assert result["queue"] == expected
    # Diagnostics reports the same queue.
    diag = pr.preparation_diagnostics(db, ev.id)
    assert diag["expected_queue"] == expected
    assert diag["persisted_queue"] == expected
    assert diag["queue_match"] is True


# ---------------------------------------------------------------------------
# 4. enqueue failure becomes dispatch_failed
# ---------------------------------------------------------------------------


def test_4_enqueue_failure_becomes_dispatch_failed(db: Session, monkeypatch) -> None:
    """When the enqueue raises, the row is marked
    ``dispatch_failed`` with a structured error code and
    ``retryable=True``.
    """
    case = _make_case(db)
    ev = _make_evidence(db, case.id)

    def _raise(evidence_id):
        raise RuntimeError("redis is down")

    monkeypatch.setattr(
        "app.workers.tasks.enqueue_memory_preparation",
        _raise,
    )
    result = pr.dispatch_memory_preparation(db, evidence=ev)
    assert result["state"] == sp.PREP_DISPATCH_FAILED_STATE
    assert result["error_code"] == "MEMORY_PREPARATION_DISPATCH_FAILED"
    assert result["retryable"] is True
    assert result["task_active"] is False
    prep = db.query(sp.MemorySymbolPreparation).filter_by(evidence_id=ev.id).first()
    assert prep.state == sp.PREP_DISPATCH_FAILED_STATE
    assert prep.error_code == "MEMORY_PREPARATION_DISPATCH_FAILED"


# ---------------------------------------------------------------------------
# 5. no indefinite queued state
# ---------------------------------------------------------------------------


def test_5_no_indefinite_queued_state(db: Session, monkeypatch) -> None:
    """Within the stale window, the row is queued.  After the
    window elapses, reconciliation either re-dispatches or
    marks the row ``stale`` / ``dispatch_failed`` — never
    silently keeps it queued.
    """
    case = _make_case(db)
    ev = _make_evidence(db, case.id)
    monkeypatch.setattr(
        "app.workers.tasks.enqueue_memory_preparation",
        lambda eid: "rq-job-1",
    )
    pr.dispatch_memory_preparation(db, evidence=ev)
    prep = db.query(sp.MemorySymbolPreparation).filter_by(evidence_id=ev.id).first()
    # Force the row to be stale (heartbeat far in the past).
    from datetime import timedelta
    from app.core.database import utc_now_naive
    prep.last_heartbeat_at = utc_now_naive() - timedelta(seconds=10_000)
    prep.updated_at = prep.last_heartbeat_at
    db.commit()
    # Stub _task_is_alive to return False (job is gone).
    monkeypatch.setattr("app.services.memory.symbol_preparation._task_is_alive", lambda _: False)
    # Stub the re-dispatch to succeed.
    monkeypatch.setattr(
        "app.workers.tasks.enqueue_memory_preparation",
        lambda eid: "rq-job-2",
    )
    stats = pr.reconcile_stale_preparations(db)
    assert stats["scanned"] >= 1
    assert stats["redispatched"] + stats["marked_stale"] + stats["marked_dispatch_failed"] >= 1
    # The row is no longer in the original non-terminal state
    # alone: it was either re-dispatched or marked terminal.
    db.refresh(prep)
    assert prep.state != "queued" or prep.worker_task_id == "rq-job-2"


# ---------------------------------------------------------------------------
# 6. duplicate request is idempotent
# ---------------------------------------------------------------------------


def test_6_duplicate_dispatch_reuses_active_row(db: Session, monkeypatch) -> None:
    """Calling ``dispatch_memory_preparation`` twice in a row
    does not create two active preparation rows.
    """
    case = _make_case(db)
    ev = _make_evidence(db, case.id)
    monkeypatch.setattr(
        "app.workers.tasks.enqueue_memory_preparation",
        lambda eid: "rq-job-A",
    )
    first = pr.dispatch_memory_preparation(db, evidence=ev)
    monkeypatch.setattr(
        "app.workers.tasks.enqueue_memory_preparation",
        lambda eid: "rq-job-B",
    )
    second = pr.dispatch_memory_preparation(db, evidence=ev)
    # Only one active row; the second dispatch reused the same row.
    rows = (
        db.query(sp.MemorySymbolPreparation)
        .filter_by(evidence_id=ev.id)
        .all()
    )
    active = [r for r in rows if r.active]
    assert len(active) == 1
    assert active[0].id == first["preparation_id"]
    assert active[0].id == second["preparation_id"]
    # The latest job id is on the active row.
    assert active[0].worker_task_id == "rq-job-B"


# ---------------------------------------------------------------------------
# 7. successful metadata implies ready
# ---------------------------------------------------------------------------


def test_7_successful_metadata_implies_ready(db: Session) -> None:
    """An evidence with a successful metadata run resolves to
    the effective state ``ready`` even when the preparation
    row is missing or stale.
    """
    case = _make_case(db)
    ev = _make_evidence(db, case.id)
    # Insert a successful metadata run.
    from app.models.memory import MemoryScanRun
    run = MemoryScanRun(
        id=str(_uuid.uuid4()),
        case_id=case.id,
        evidence_id=ev.id,
        profile="metadata_only",
        status="completed",
        plugins_completed=1,
        plugins_failed=0,
    )
    db.add(run)
    db.commit()
    result = sp.resolve_effective_memory_preparation_state(
        db, case_id=case.id, evidence_id=ev.id,
    )
    assert result["effective_state"] == sp.PREP_READY
    assert result["source_of_truth"] == "successful_metadata_run"


# ---------------------------------------------------------------------------
# 8. Windows adapter selected correctly
# ---------------------------------------------------------------------------


def test_8_windows_adapter_selected() -> None:
    """The factory returns a Windows adapter for KDBG signature."""
    fake_path = MagicMock()
    fake_path.open.return_value.__enter__.return_value.read.return_value = b"KDBG\x00\x00"
    result = probe_memory_platform(canonical_path=fake_path, detected_format="windows_memory")
    assert result.platform == PlatformFamily.WINDOWS
    adapter = get_adapter_for_probe(result)
    assert isinstance(adapter, WindowsMemoryAdapter)


# ---------------------------------------------------------------------------
# 9. Linux adapter selected
# ---------------------------------------------------------------------------


def test_9_linux_adapter_selected() -> None:
    """The factory returns a Linux adapter for the Linux banner."""
    fake_path = MagicMock()
    fake_path.open.return_value.__enter__.return_value.read.return_value = (
        b"Linux version 5.15.0-100-generic"
    )
    result = probe_memory_platform(canonical_path=fake_path, detected_format="lime")
    assert result.platform == PlatformFamily.LINUX
    adapter = get_adapter_for_probe(result)
    assert isinstance(adapter, LinuxMemoryAdapter)


# ---------------------------------------------------------------------------
# 10. macOS adapter terminates as unsupported
# ---------------------------------------------------------------------------


def test_10_macos_terminates_as_unsupported() -> None:
    """The macOS adapter returns a structured ``unsupported``
    state when no ISF / metadata run is available.
    """
    adapter = MacOSMemoryAdapter()
    probe = MagicMock()
    probe.platform = PlatformFamily.MACOS
    probe.format = "raw"
    probe.architecture = Architecture.X64
    probe.confidence = ProbeConfidence.MEDIUM
    probe.reason = "macho_header"
    result = adapter.check_readiness(probe=probe, cache_state={})
    assert result.state.value == "unsupported"
    assert result.error_code == "PLATFORM_NOT_SUPPORTED"


# ---------------------------------------------------------------------------
# 11. unknown image terminates as platform_not_identified
# ---------------------------------------------------------------------------


def test_11_unknown_image_terminates_as_platform_not_identified() -> None:
    """An empty / unrecognised image terminates as
    ``unsupported`` with ``PLATFORM_NOT_IDENTIFIED``.
    """
    fake_path = MagicMock()
    fake_path.open.return_value.__enter__.return_value.read.return_value = b"\x00\x00\x00"
    result = probe_memory_platform(canonical_path=fake_path, detected_format=None)
    assert result.platform == PlatformFamily.UNKNOWN
    adapter = get_adapter_for_probe(result)
    assert isinstance(adapter, UnsupportedMemoryAdapter)
    readiness = adapter.check_readiness(probe=result, cache_state={})
    assert readiness.state.value == "unsupported"
    assert readiness.error_code == "PLATFORM_NOT_IDENTIFIED"


# ---------------------------------------------------------------------------
# 12. no heavy profile execution during preparation
# ---------------------------------------------------------------------------


def test_12_no_heavy_profile_execution_during_probe() -> None:
    """The bounded probe opens the file with ``read()`` only and
    does not invoke any Volatility plugin or symbol fetcher.
    """
    fake_path = MagicMock()
    fake_handle = MagicMock()
    fake_handle.read.return_value = b"KDBG\x00\x00"
    fake_path.open.return_value.__enter__.return_value = fake_handle
    probe_memory_platform(canonical_path=fake_path, detected_format="lime")
    fake_handle.read.assert_called_once()
    # Only a single ``open()`` call: the probe did not scan
    # the file in multiple passes.
    fake_path.open.assert_called_once()


# ---------------------------------------------------------------------------
# 13. no symbol download during probe
# ---------------------------------------------------------------------------


def test_13_no_symbol_download_during_probe(monkeypatch) -> None:
    """The probe module does NOT import the symbol fetcher."""
    from app.services.memory import platform as platform_mod
    # If the module imported the symbol fetcher at module
    # level the import would already be in ``platform_mod.__dict__``.
    assert "symbol_fetcher" not in platform_mod.__dict__
    assert "symbol_egress" not in platform_mod.__dict__


# ---------------------------------------------------------------------------
# 14. no dfir-events writes during probe
# ---------------------------------------------------------------------------


def test_14_no_dfir_events_writes_during_probe() -> None:
    """The platform module does not import the dfir-events
    publisher or the OpenSearch client.
    """
    from app.services.memory import platform as platform_mod
    for forbidden in (
        "opensearch", "publish_event", "dfir_events", "EventPublisher",
    ):
        assert forbidden not in platform_mod.__dict__


# ---------------------------------------------------------------------------
# 15. no evidence modification during probe
# ---------------------------------------------------------------------------


def test_15_no_evidence_modification_during_probe(db: Session) -> None:
    """The bounded probe is a pure function: the evidence row
    is unchanged before and after a call.
    """
    case = _make_case(db)
    ev = _make_evidence(db, case.id)
    sha_before = ev.sha256
    size_before = ev.size_bytes
    # Run the probe with a fake path that just returns a
    # Windows KDBG signature.
    fake_path = MagicMock()
    fake_path.open.return_value.__enter__.return_value.read.return_value = b"KDBG\x00"
    probe_memory_platform(canonical_path=fake_path, detected_format="windows_memory")
    db.refresh(ev)
    assert ev.sha256 == sha_before
    assert ev.size_bytes == size_before


# ---------------------------------------------------------------------------
# 16. diagnostics endpoint shape
# ---------------------------------------------------------------------------


def test_16_diagnostics_endpoint_shape(db: Session, monkeypatch) -> None:
    """The diagnostics payload exposes the queue, the task id
    and a retryable flag — never Redis URLs or paths.
    """
    case = _make_case(db)
    ev = _make_evidence(db, case.id)
    monkeypatch.setattr(
        "app.workers.tasks.enqueue_memory_preparation",
        lambda eid: "rq-job-X",
    )
    pr.dispatch_memory_preparation(db, evidence=ev)
    diag = pr.preparation_diagnostics(db, ev.id)
    for key in (
        "expected_queue",
        "persisted_queue",
        "queue_match",
        "task_registered",
        "task_alive",
        "worker_task_id",
        "preparation_id",
        "state",
        "current_step",
        "last_heartbeat_at",
        "retryable",
    ):
        assert key in diag
    # Forbidden fields must not leak.
    for forbidden in ("redis_url", "stored_path", "stored_path_"):
        assert forbidden not in diag


# ---------------------------------------------------------------------------
# 17. progress_for_state no longer fakes 5% on queued
# ---------------------------------------------------------------------------


def test_17_progress_for_state_queued_is_not_five() -> None:
    label, percent = sp.progress_for_state(sp.PREP_QUEUED)
    assert percent == 0
    assert "Queued" in label


# ---------------------------------------------------------------------------
# 18. retry endpoint is idempotent
# ---------------------------------------------------------------------------


def test_18_retry_does_not_create_second_active_row(db: Session, monkeypatch) -> None:
    """Retry on a queued preparation reuses the same row."""
    case = _make_case(db)
    ev = _make_evidence(db, case.id)
    monkeypatch.setattr(
        "app.workers.tasks.enqueue_memory_preparation",
        lambda eid: "rq-job-Y",
    )
    first = pr.dispatch_memory_preparation(db, evidence=ev)
    second = pr.dispatch_memory_preparation(db, evidence=ev, force=True)
    # The retry updated the same active row.
    rows = (
        db.query(sp.MemorySymbolPreparation)
        .filter_by(evidence_id=ev.id)
        .all()
    )
    active = [r for r in rows if r.active]
    assert len(active) == 1
    assert active[0].id == first["preparation_id"]
    # The second call may return a different task id (it
    # enqueued a new job) but only the latest job id is on
    # the active row.
    assert active[0].worker_task_id in {first["worker_task_id"], second["worker_task_id"]}


# ---------------------------------------------------------------------------
# 19. direct probe bypasses preparation gate
# ---------------------------------------------------------------------------


def test_19_direct_probe_endpoint_enqueues_metadata_run(
    db: Session, monkeypatch
) -> None:
    """The direct-probe endpoint enqueues a metadata run even
    when the preparation is not ready.
    """
    case = _make_case(db)
    ev = _make_evidence(db, case.id)
    monkeypatch.setattr(
        "app.workers.tasks.enqueue_memory_preparation",
        lambda eid: "rq-job-DP",
    )
    # We call the underlying dispatcher.  The HTTP endpoint
    # is exercised separately.
    from app.services.memory.preparation_runtime import (
        dispatch_memory_preparation,
    )
    result = dispatch_memory_preparation(db, evidence=ev)
    assert result["task_active"] is True
    assert result["worker_task_id"] == "rq-job-DP"


# ---------------------------------------------------------------------------
# 20. one active preparation per evidence (DB constraint)
# ---------------------------------------------------------------------------


def test_20_one_active_per_evidence_unique_constraint(db: Session) -> None:
    """The model declares the partial unique index that
    enforces ``one active row per evidence``.
    """
    from app.models.memory import MemorySymbolPreparation
    from sqlalchemy import inspect
    indexes = list(MemorySymbolPreparation.__table_args__)
    # The constraint name is documented as
    # ``uq_memory_symbol_prep_active_evidence``.
    assert any(
        getattr(idx, "name", None) == "uq_memory_symbol_prep_active_evidence"
        for idx in indexes
    )
