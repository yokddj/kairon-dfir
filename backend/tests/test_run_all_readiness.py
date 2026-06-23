"""Tests for the run-all readiness gate added in sprint 3.

The ``post_run_all_batch`` endpoint must reject requests with
``MEMORY_PREPARATION_NOT_READY`` (HTTP 409) when the evidence's
effective preparation state is not "ready".  The flag
``memory_run_all_enabled`` is also checked; when False, the
endpoint must reject with ``MEMORY_RUN_ALL_DISABLED`` (HTTP 409).
"""
from __future__ import annotations

import pytest
from fastapi import HTTPException
from sqlalchemy import create_engine
from sqlalchemy.orm import Session, sessionmaker

from app.core.config import get_settings
from app.core.database import Base
from app.services.memory import symbol_preparation as sp

settings = get_settings()


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


def _make_case(db: Session):
    from app.models.case import Case
    case = Case(name="readiness-case", description="readiness test")
    db.add(case)
    db.commit()
    db.refresh(case)
    return case


def _make_evidence(db: Session, case_id: str, **kwargs):
    import uuid
    from datetime import datetime
    from app.models.evidence import (
        Evidence, EvidenceStorageMode, EvidenceType, IngestStatus,
    )
    ev = Evidence(
        id=str(uuid.uuid4()),
        case_id=case_id,
        original_filename=kwargs.get("filename", "WS01-20240322-125737.dmp"),
        stored_path=kwargs.get("stored_path", "/tmp/WS01.dmp"),
        original_path=kwargs.get("stored_path", "/tmp/WS01.dmp"),
        evidence_type=EvidenceType.memory_dump,
        storage_mode=EvidenceStorageMode.uploaded,
        is_external=False,
        copy_to_storage=True,
        sha256="0" * 64,
        size_bytes=kwargs.get("size_bytes", 4_255_346_688),
        ingest_status=IngestStatus.completed,
        path_validation={},
        ingest_source={"detected_host": kwargs.get("detected_host", "WS01")},
        metadata_json={},
        error_log={},
        processed_at=datetime.utcnow(),
        detection_status=kwargs.get("detection_status", "windows_memory"),
    )
    db.add(ev)
    db.commit()
    db.refresh(ev)
    return ev


def _restore_flag():
    """Restore the memory_run_all_enabled flag after a test mutates it."""
    yield
    settings.memory_run_all_enabled = True


def test_1_run_all_rejected_when_flag_disabled(db: Session) -> None:
    """When memory_run_all_enabled=False, the endpoint returns MEMORY_RUN_ALL_DISABLED."""
    from app.api.routes_memory import post_run_all_batch
    case = _make_case(db)
    ev = _make_evidence(db, case.id)
    settings.memory_run_all_enabled = False
    try:
        with pytest.raises(HTTPException) as exc:
            post_run_all_batch(
                case_id=case.id,
                evidence_id=ev.id,
                payload={
                    "mode": "missing_or_failed",
                    "authorization_acknowledged": True,
                },
                db=db,
            )
        assert exc.value.status_code == 409
        assert exc.value.detail["error_code"] == "MEMORY_RUN_ALL_DISABLED"
    finally:
        settings.memory_run_all_enabled = True


def test_2_run_all_rejected_when_preparation_not_ready(db: Session, monkeypatch) -> None:
    """When the effective state is not 'ready', returns MEMORY_PREPARATION_NOT_READY."""
    from app.api.routes_memory import post_run_all_batch
    case = _make_case(db)
    ev = _make_evidence(db, case.id)

    # Force the effective state to be 'verifying' (i.e. not ready).
    monkeypatch.setattr(
        sp,
        "resolve_effective_memory_preparation_state",
        lambda db, *, case_id, evidence_id: {
            "effective_state": "verifying",
            "preparation_id": None,
            "source_of_truth": "stub",
        },
    )
    with pytest.raises(HTTPException) as exc:
        post_run_all_batch(
            case_id=case.id,
            evidence_id=ev.id,
            payload={
                "mode": "missing_or_failed",
                "authorization_acknowledged": True,
            },
            db=db,
        )
    assert exc.value.status_code == 409
    assert exc.value.detail["error_code"] == "MEMORY_PREPARATION_NOT_READY"
    assert exc.value.detail["effective_state"] == "verifying"


def test_3_run_all_authorization_required_even_when_ready(db: Session, monkeypatch) -> None:
    """Even when preparation is ready, authorization_acknowledged is still required."""
    from app.api.routes_memory import post_run_all_batch
    case = _make_case(db)
    ev = _make_evidence(db, case.id)

    monkeypatch.setattr(
        sp,
        "resolve_effective_memory_preparation_state",
        lambda db, *, case_id, evidence_id: {
            "effective_state": "ready",
            "preparation_id": "prep-1",
            "source_of_truth": "stub",
        },
    )
    with pytest.raises(HTTPException) as exc:
        post_run_all_batch(
            case_id=case.id,
            evidence_id=ev.id,
            payload={"mode": "missing_or_failed"},
            db=db,
        )
    assert exc.value.status_code == 400
    assert exc.value.detail["error_code"] == "MEMORY_BATCH_AUTHORIZATION_REQUIRED"


def test_4_run_all_proceeds_when_flag_enabled_and_preparation_ready(
    db: Session, monkeypatch
) -> None:
    """When both the flag is enabled and the preparation is ready, the batch starts."""
    from app.api.routes_memory import post_run_all_batch
    from app.services.memory import batch as batch_mod
    case = _make_case(db)
    ev = _make_evidence(db, case.id)

    monkeypatch.setattr(
        sp,
        "resolve_effective_memory_preparation_state",
        lambda db, *, case_id, evidence_id: {
            "effective_state": "ready",
            "preparation_id": "prep-1",
            "source_of_truth": "stub",
        },
    )
    # Stub the downstream batch builder + worker enqueue so the
    # test does not need a real scan run / Celery / memory worker.
    monkeypatch.setattr(
        batch_mod,
        "plan_run_all",
        lambda **kwargs: {
            "selected_profiles": ["metadata_only", "processes_extended"],
            "skipped_profiles": [],
            "estimated_duration_seconds": 100,
        },
    )
    monkeypatch.setattr(
        batch_mod,
        "create_run_all_batch",
        lambda db, **kwargs: {
            "batch": {
                "batch_id": "b-test",
                "case_id": case.id,
                "evidence_id": ev.id,
                "state": "queued",
                "total_profiles": 2,
                "queued_profiles": 2,
                "selected_profiles": ["metadata_only", "processes_extended"],
            },
            "first_run": None,
            "plan": {
                "selected_profiles": ["metadata_only", "processes_extended"],
                "skipped_profiles": [],
            },
        },
    )
    monkeypatch.setattr(
        batch_mod,
        "serialize_batch",
        lambda batch: {
            "batch_id": batch.get("batch_id"),
            "case_id": batch.get("case_id"),
            "evidence_id": batch.get("evidence_id"),
            "state": batch.get("state"),
            "total_profiles": batch.get("total_profiles"),
            "queued_profiles": batch.get("queued_profiles"),
        },
    )
    monkeypatch.setattr(
        "app.workers.tasks.enqueue_memory_metadata_scan",
        lambda **kwargs: None,
    )
    result = post_run_all_batch(
        case_id=case.id,
        evidence_id=ev.id,
        payload={
            "mode": "missing_or_failed",
            "authorization_acknowledged": True,
            "continue_on_failure": True,
        },
        db=db,
    )
    assert result["state"] == "queued"
    assert result["total_profiles"] == 2


def test_5_run_all_rejects_preparation_state_registering(db: Session, monkeypatch) -> None:
    """The 'registering' state is also not-ready."""
    from app.api.routes_memory import post_run_all_batch
    case = _make_case(db)
    ev = _make_evidence(db, case.id)

    monkeypatch.setattr(
        sp,
        "resolve_effective_memory_preparation_state",
        lambda db, *, case_id, evidence_id: {
            "effective_state": "registering",
            "preparation_id": None,
            "source_of_truth": "stub",
        },
    )
    with pytest.raises(HTTPException) as exc:
        post_run_all_batch(
            case_id=case.id,
            evidence_id=ev.id,
            payload={"mode": "missing_or_failed", "authorization_acknowledged": True},
            db=db,
        )
    assert exc.value.status_code == 409
    assert exc.value.detail["error_code"] == "MEMORY_PREPARATION_NOT_READY"
    assert exc.value.detail["effective_state"] == "registering"


def test_6_run_all_rejects_preparation_state_failed(db: Session, monkeypatch) -> None:
    """The 'failed' state is also not-ready."""
    from app.api.routes_memory import post_run_all_batch
    case = _make_case(db)
    ev = _make_evidence(db, case.id)

    monkeypatch.setattr(
        sp,
        "resolve_effective_memory_preparation_state",
        lambda db, *, case_id, evidence_id: {
            "effective_state": "failed",
            "preparation_id": "prep-failed",
            "source_of_truth": "stub",
        },
    )
    with pytest.raises(HTTPException) as exc:
        post_run_all_batch(
            case_id=case.id,
            evidence_id=ev.id,
            payload={"mode": "missing_or_failed", "authorization_acknowledged": True},
            db=db,
        )
    assert exc.value.status_code == 409
    assert exc.value.detail["error_code"] == "MEMORY_PREPARATION_NOT_READY"
    assert exc.value.detail["preparation_id"] == "prep-failed"


def test_7_run_all_flag_default_is_true() -> None:
    """The memory_run_all_enabled flag defaults to True after sprint 1 reset."""
    # The flag was set to False in sprint 1, then reactivated in
    # sprint 3 when the preparation state machine was added.
    assert settings.memory_run_all_enabled is True


def test_8_run_all_returns_409_not_400_when_not_ready(db: Session, monkeypatch) -> None:
    """The not-ready state is 409 (state), not 400 (input)."""
    from app.api.routes_memory import post_run_all_batch
    case = _make_case(db)
    ev = _make_evidence(db, case.id)

    monkeypatch.setattr(
        sp,
        "resolve_effective_memory_preparation_state",
        lambda db, *, case_id, evidence_id: {
            "effective_state": "pending",
            "preparation_id": None,
            "source_of_truth": "stub",
        },
    )
    with pytest.raises(HTTPException) as exc:
        post_run_all_batch(
            case_id=case.id,
            evidence_id=ev.id,
            payload={"mode": "missing_or_failed", "authorization_acknowledged": True},
            db=db,
        )
    # 409 means the resource is in a state that prevents the
    # action, which is what we want for "preparation not ready".
    assert exc.value.status_code == 409
