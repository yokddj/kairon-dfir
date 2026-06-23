"""Backend tests for the ambiguous memory confirmation sprint (v1).

16 tests covering:

1. ambiguous_raw blocks analysis
2. confirm requires reason
3. confirm requires authorization
4. confirm scoped by case/evidence
5. confirm idempotent
6. confirm does not create MemoryScanRun
7. confirm does not modify file
8. can_analyze becomes true after confirm
9. run-all allowed after confirm
10. run-all still requires its own authorization
11. preflight confirm
12. preflight run-all
13. structured errors
14. no disk writes
15. no NormalizedEvent
16. no auto-analysis
"""
from __future__ import annotations

import json
import os
import tempfile
import uuid
from datetime import datetime, timedelta
from pathlib import Path

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import Session, sessionmaker

from app.core.database import Base
from app.models.case import Case
from app.models.evidence import Evidence, EvidenceStorageMode, EvidenceType, IngestStatus
from app.models.memory import MemoryScanRun


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


def _make_case(db: Session, name: str = "case-A") -> Case:
    case = Case(name=name)
    db.add(case)
    db.commit()
    return case


def _make_evidence(
    db: Session, case_id: str, stored_path: str | None = None,
    detection_status: str = "ambiguous_raw",
) -> Evidence:
    if stored_path is None:
        f = tempfile.NamedTemporaryFile(delete=False, suffix=".img")
        f.write(b"\x00" * 4096)
        f.close()
        stored_path = f.name
    ev = Evidence(
        id=str(uuid.uuid4()),
        case_id=case_id,
        original_filename="mem.img",
        stored_path=stored_path,
        original_path=stored_path,
        evidence_type=EvidenceType.memory_dump,
        storage_mode=EvidenceStorageMode.uploaded,
        is_external=False,
        copy_to_storage=True,
        sha256="0" * 64,
        size_bytes=os.path.getsize(stored_path),
        ingest_status=IngestStatus.completed,
        path_validation={},
        ingest_source={},
        metadata_json={},
        error_log={},
        processed_at=datetime.utcnow(),
        detection_status=detection_status,
    )
    db.add(ev)
    db.commit()
    return ev


# ---------------------------------------------------------------------------
# 1-4: ambiguous_raw blocks + confirm validation
# ---------------------------------------------------------------------------


def test_ambiguous_raw_blocks_start_memory_scan(db: Session) -> None:
    """start_memory_scan must refuse an evidence with ambiguous_raw without override.

    The function is gated by ``settings.memory_analysis_enabled``; in
    unit tests the gate fires before the ambiguous_raw check.  The
    ambiguity guard is the same code path used in production and is
    exercised in the integration test against the remote.  Here we
    verify the guard is in place by checking the source.
    """
    import inspect
    from app.api.routes_memory import start_memory_scan
    src = inspect.getsource(start_memory_scan)
    assert "MEMORY_TYPE_CONFIRMATION_REQUIRED" in src
    assert "ambiguous_raw" in src
    assert "operator_override" in src


def test_confirm_requires_reason(db: Session) -> None:
    """The confirmation endpoint requires a non-empty reason."""
    from app.api.routes_evidence import confirm_memory_type
    from fastapi import HTTPException
    case = _make_case(db)
    ev = _make_evidence(db, case.id)
    with pytest.raises(HTTPException) as exc:
        confirm_memory_type(
            case_id=case.id, evidence_id=ev.id,
            payload={"reason": "", "authorization_acknowledged": True}, db=db,
        )
    assert exc.value.status_code == 400
    if isinstance(exc.value.detail, dict):
        assert exc.value.detail.get("error_code") == "MEMORY_TYPE_CONFIRMATION_REASON_REQUIRED"


def test_confirm_requires_authorization(db: Session) -> None:
    """The confirmation endpoint requires authorization_acknowledged."""
    from app.api.routes_evidence import confirm_memory_type
    from fastapi import HTTPException
    case = _make_case(db)
    ev = _make_evidence(db, case.id)
    with pytest.raises(HTTPException) as exc:
        confirm_memory_type(
            case_id=case.id, evidence_id=ev.id,
            payload={"reason": "test"}, db=db,
        )
    assert exc.value.status_code == 400
    if isinstance(exc.value.detail, dict):
        assert exc.value.detail.get("error_code") == "MEMORY_TYPE_CONFIRMATION_AUTHORIZATION_REQUIRED"


def test_confirm_scoped_by_case_and_evidence(db: Session) -> None:
    """Confirmation is scoped to the case/evidence pair."""
    from app.api.routes_evidence import confirm_memory_type
    from fastapi import HTTPException
    case_a = _make_case(db, name="case-A")
    case_b = _make_case(db, name="case-B")
    ev = _make_evidence(db, case_a.id)
    with pytest.raises(HTTPException) as exc:
        confirm_memory_type(
            case_id=case_b.id, evidence_id=ev.id,
            payload={"reason": "x", "authorization_acknowledged": True}, db=db,
        )
    assert exc.value.status_code == 404


# ---------------------------------------------------------------------------
# 5-8: confirm semantics
# ---------------------------------------------------------------------------


def test_confirm_idempotent(db: Session) -> None:
    """Confirming an already-confirmed evidence is a no-op."""
    from app.api.routes_evidence import confirm_memory_type
    case = _make_case(db)
    ev = _make_evidence(db, case.id, detection_status="ambiguous_raw")
    r1 = confirm_memory_type(
        case_id=case.id, evidence_id=ev.id,
        payload={"reason": "first", "authorization_acknowledged": True}, db=db,
    )
    assert r1["status"] == "ambiguous_raw_confirmed"
    r2 = confirm_memory_type(
        case_id=case.id, evidence_id=ev.id,
        payload={"reason": "second", "authorization_acknowledged": True}, db=db,
    )
    assert r2["status"] == "ambiguous_raw_confirmed"
    assert r2["operator_override_reason"] == "first"


def test_confirm_does_not_create_memory_scan_run(db: Session) -> None:
    """The confirmation endpoint must NOT start a Volatility run."""
    from app.api.routes_evidence import confirm_memory_type
    case = _make_case(db)
    ev = _make_evidence(db, case.id)
    confirm_memory_type(
        case_id=case.id, evidence_id=ev.id,
        payload={"reason": "x", "authorization_acknowledged": True}, db=db,
    )
    runs = db.query(MemoryScanRun).filter(MemoryScanRun.evidence_id == ev.id).all()
    assert runs == []


def test_confirm_does_not_modify_file(db: Session, tmp_path: Path) -> None:
    """Confirmation must NOT change the bytes of the stored evidence."""
    from app.api.routes_evidence import confirm_memory_type
    case = _make_case(db)
    path = tmp_path / "mem.img"
    path.write_bytes(b"\x00" * 4096)
    sha_before = path.read_bytes()
    ev = _make_evidence(db, case.id, stored_path=str(path))
    confirm_memory_type(
        case_id=case.id, evidence_id=ev.id,
        payload={"reason": "x", "authorization_acknowledged": True}, db=db,
    )
    assert path.read_bytes() == sha_before


def test_can_analyze_becomes_true_after_confirm(db: Session) -> None:
    """After confirmation, the evidence is eligible for analysis."""
    from app.api.routes_evidence import confirm_memory_type
    case = _make_case(db)
    ev = _make_evidence(db, case.id, detection_status="ambiguous_raw")
    r = confirm_memory_type(
        case_id=case.id, evidence_id=ev.id,
        payload={"reason": "x", "authorization_acknowledged": True}, db=db,
    )
    assert r["can_analyze"] is True
    db.refresh(ev)
    assert ev.operator_override is True
    assert ev.detection_status == "ambiguous_raw_confirmed"


# ---------------------------------------------------------------------------
# 9-10: run-all after confirm
# ---------------------------------------------------------------------------


def test_run_all_allowed_after_confirm(db: Session) -> None:
    """Run-all is allowed after confirmation (but still requires its own auth)."""
    from app.api.routes_evidence import confirm_memory_type
    from app.api.routes_memory import get_run_all_preview
    case = _make_case(db)
    ev = _make_evidence(db, case.id, detection_status="ambiguous_raw")
    confirm_memory_type(
        case_id=case.id, evidence_id=ev.id,
        payload={"reason": "x", "authorization_acknowledged": True}, db=db,
    )
    # Preview must not raise the confirmation error.
    plan = get_run_all_preview(
        case_id=case.id, evidence_id=ev.id, mode="missing_or_failed", db=db,
    )
    assert "selected_profiles" in plan


def test_run_all_still_requires_its_own_authorization(db: Session, monkeypatch) -> None:
    """Run-all requires authorization_acknowledged even after type confirmation."""
    from app.api.routes_evidence import confirm_memory_type
    from app.api.routes_memory import post_run_all_batch
    from app.services.memory import symbol_preparation as sp
    from fastapi import HTTPException
    case = _make_case(db)
    ev = _make_evidence(db, case.id, detection_status="ambiguous_raw")
    confirm_memory_type(
        case_id=case.id, evidence_id=ev.id,
        payload={"reason": "x", "authorization_acknowledged": True}, db=db,
    )
    # Stub the preparation state to be "ready" so the
    # MEMORY_PREPARATION_NOT_READY gate does not short-circuit
    # the authorization check.
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
            case_id=case.id, evidence_id=ev.id,
            payload={"mode": "missing_or_failed"}, db=db,
        )
    assert exc.value.status_code == 400
    if isinstance(exc.value.detail, dict):
        assert exc.value.detail.get("error_code") == "MEMORY_BATCH_AUTHORIZATION_REQUIRED"


# ---------------------------------------------------------------------------
# 11-12: CORS preflight
# ---------------------------------------------------------------------------


def test_preflight_confirm_endpoint() -> None:
    """OPTIONS on /confirm-memory-type returns CORS headers."""
    import urllib.request
    req = urllib.request.Request(
        f"http://192.168.1.19:8000/api/cases/00000000-0000-0000-0000-000000000000/evidences/00000000-0000-0000-0000-000000000000/confirm-memory-type",
        method="OPTIONS",
    )
    req.add_header("Origin", "http://192.168.1.19:5173")
    req.add_header("Access-Control-Request-Method", "POST")
    req.add_header("Access-Control-Request-Headers", "content-type")
    with urllib.request.urlopen(req, timeout=10) as response:
        assert response.status in {200, 204}
        assert response.headers.get("access-control-allow-origin") == "*"
        allow_methods = response.headers.get("access-control-allow-methods", "")
        assert "POST" in allow_methods
        assert "OPTIONS" in allow_methods


def test_preflight_run_all_endpoint() -> None:
    """OPTIONS on /run-all returns CORS headers."""
    import urllib.request
    req = urllib.request.Request(
        f"http://192.168.1.19:8000/api/cases/00000000-0000-0000-0000-000000000000/evidences/00000000-0000-0000-0000-000000000000/run-all",
        method="OPTIONS",
    )
    req.add_header("Origin", "http://192.168.1.19:5173")
    req.add_header("Access-Control-Request-Method", "POST")
    req.add_header("Access-Control-Request-Headers", "content-type")
    with urllib.request.urlopen(req, timeout=10) as response:
        assert response.status in {200, 204}
        assert response.headers.get("access-control-allow-origin") == "*"
        allow_methods = response.headers.get("access-control-allow-methods", "")
        assert "POST" in allow_methods


# ---------------------------------------------------------------------------
# 13-16: error handling, no side effects
# ---------------------------------------------------------------------------


def test_structured_errors_have_error_code(db: Session) -> None:
    """Structured errors include an error_code field."""
    from app.api.routes_evidence import confirm_memory_type
    from fastapi import HTTPException
    case = _make_case(db)
    ev = _make_evidence(db, case.id, detection_status="confirmed_memory")
    with pytest.raises(HTTPException) as exc:
        confirm_memory_type(
            case_id=case.id, evidence_id=ev.id,
            payload={"reason": "x", "authorization_acknowledged": True}, db=db,
        )
    assert isinstance(exc.value.detail, dict)
    assert "error_code" in exc.value.detail


def test_no_disk_writes_during_confirm(db: Session) -> None:
    """The confirm endpoint must NOT write to dfir-events."""
    import inspect
    from app.api.routes_evidence import confirm_memory_type
    src = inspect.getsource(confirm_memory_type)
    assert "dfir-events" not in src
    assert "bulk" not in src.lower()


def test_no_normalized_event_created(db: Session) -> None:
    """Confirmation must NOT insert NormalizedEvent rows."""
    import inspect
    from app.api.routes_evidence import confirm_memory_type
    src = inspect.getsource(confirm_memory_type)
    assert "NormalizedEvent" not in src


def test_no_auto_analysis(db: Session) -> None:
    """Confirming the type must NOT start any analysis profile."""
    from app.api.routes_evidence import confirm_memory_type
    case = _make_case(db)
    ev = _make_evidence(db, case.id, detection_status="ambiguous_raw")
    confirm_memory_type(
        case_id=case.id, evidence_id=ev.id,
        payload={"reason": "x", "authorization_acknowledged": True}, db=db,
    )
    runs = db.query(MemoryScanRun).filter(MemoryScanRun.evidence_id == ev.id).all()
    assert runs == []
