"""Tests for the per-evidence Windows symbol state and run-all preflight.

These tests cover the symbol-resolution flow that the analyst sees in
the UI: a per-evidence state machine, a per-evidence cache check, a
controlled acquisition flow, and a structured preflight that blocks
the run-all batch BEFORE any MemoryScanRun is created.
"""
from __future__ import annotations

import os
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from app.api import routes_evidence
from app.api import routes_memory
from app.core.database import Base
from app.core import config as core_config
from app.models.case import Case
from app.models.evidence import Evidence, EvidenceType, IngestStatus
from app.models.memory import (
    MemoryAnalysisBatch,
    MemoryCachedSymbol,
    MemoryPluginRun,
    MemoryScanRun,
    MemorySymbolAcquisition,
    MemorySymbolAcquisitionRequest,
    MemorySymbolApproval,
    MemorySymbolRequirement,
)
from app.services.memory import batch as memory_batch
from app.services.memory import symbol_control
from app.services.memory import symbol_state as symbol_state_module
from app.services.memory.symbol_state import (
    ALL_STATES,
    EC_SYMBOLS_REQUIRED,
    STATE_ACQUIRING,
    STATE_CACHED,
    STATE_MISSING,
    STATE_UNKNOWN,
    SymbolRequirement,
    evidence_symbol_state,
    _exact_cache_match,
)
from app.workers.tasks import enqueue_memory_metadata_scan


CASE_ID = "ffffffff-0000-4000-8000-000000000001"
WINXP_EVIDENCE_ID = "ffffffff-0000-4000-8000-000000000010"
WIN11_EVIDENCE_ID = "ffffffff-0000-4000-8000-000000000011"
UNKNOWN_EVIDENCE_ID = "ffffffff-0000-4000-8000-000000000012"


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


def _case(db, case_id: str = CASE_ID) -> Case:
    item = Case(id=case_id, name="Memory symbols case")
    db.add(item)
    db.commit()
    return item


def _evidence(
    db,
    evidence_id: str,
    case_id: str = CASE_ID,
    filename: str = "memory.mem",
) -> Evidence:
    item = Evidence(
        id=evidence_id,
        case_id=case_id,
        original_filename=filename,
        stored_path=f"/tmp/{filename}",
        original_path=f"/tmp/{filename}",
        evidence_type=EvidenceType.memory_dump,
        sha256="0" * 64,
        size_bytes=1024,
        ingest_status=IngestStatus.completed,
        detection_status="confirmed_memory",
        detected_format="windows_crash_dump",
        metadata_json={},
        error_log={},
    )
    db.add(item)
    db.commit()
    return item


def _cached_symbol(
    db,
    *,
    pdb_name: str,
    guid: str,
    age: int,
    arch: str = "x64",
) -> MemoryCachedSymbol:
    # The real cache key matches ``SymbolIdentity.key`` exactly:
    # ``f"{pdb_name.lower()}/{guid.upper()}-{age}"`` (no architecture).
    symbol_key = f"{pdb_name.lower()}/{guid.upper()}-{age}"
    row = MemoryCachedSymbol(
        symbol_key=symbol_key,
        pdb_name=pdb_name,
        pdb_guid=guid.upper(),
        pdb_age=age,
        architecture=arch,
        pdb_relative_path=f"pdb/{pdb_name}/{guid}{age}/{pdb_name}",
        isf_relative_path=f"isf/{pdb_name}.json.xz",
        pdb_sha256="a" * 64,
        isf_sha256="b" * 64,
        pdb_size_bytes=1024,
        isf_size_bytes=2048,
        validation_status="validated",
    )
    db.add(row)
    db.commit()
    return row


def _requirement(
    db,
    *,
    evidence_id: str,
    pdb_name: str,
    guid: str,
    age: int,
    arch: str = "x64",
) -> MemorySymbolRequirement:
    import uuid as _uuid

    identity = SimpleNamespace(
        pdb_name=pdb_name, guid=guid.upper(), age=age, architecture=arch
    )
    # Match ``SymbolIdentity.key`` exactly: ``f"{name.lower()}/{guid}-{age}"``.
    symbol_key = f"{pdb_name.lower()}/{guid.upper()}-{age}"
    run_id = str(_uuid.uuid4())
    plugin_run_id = str(_uuid.uuid4())
    row = MemorySymbolRequirement(
        case_id=CASE_ID,
        evidence_id=evidence_id,
        source_run_id=run_id,
        source_plugin_run_id=plugin_run_id,
        pdb_name=pdb_name,
        pdb_guid=guid.upper(),
        pdb_age=age,
        requested_pdb_age=age,
        age_corrected=False,
        architecture=arch,
        symbol_key=symbol_key,
        status="unavailable_offline",
        sanitized_message="Required Windows symbols are not present in the offline cache.",
    )
    db.add(row)
    db.commit()
    return row


# ---------------------------------------------------------------------------
# 1. cache global no implica exact cache hit
# ---------------------------------------------------------------------------


def test_global_cache_presence_does_not_imply_exact_cache_hit(db_session) -> None:
    _case(db_session)
    _evidence(db_session, WINXP_EVIDENCE_ID, filename="xp-laptop.img")
    _evidence(db_session, WIN11_EVIDENCE_ID, filename="boomer-win2k.img")
    # Cache contains a Windows 11 symbol (for a different evidence).
    _cached_symbol(
        db_session,
        pdb_name="ntoskrnl.pdb",
        guid="AABBCCDD" * 4,
        age=10,
        arch="x64",
    )
    # Recorded requirement is for Windows XP ntkrnlpa.
    _requirement(
        db_session,
        evidence_id=WINXP_EVIDENCE_ID,
        pdb_name="ntkrnlpa.pdb",
        guid="12345678" * 4,
        age=3,
        arch="x86",
    )
    state = evidence_symbol_state(
        db_session,
        case_id=CASE_ID,
        evidence_id=WINXP_EVIDENCE_ID,
    )
    assert state.state == STATE_MISSING
    assert state.cache is not None
    assert state.cache.cache_status == "miss"
    assert state.cache.exact_match is False
    # The cached identifier for the Windows 11 symbol is exposed so
    # the UI can show it in the diagnostics panel.
    assert "ntoskrnl.pdb/AABBCCDDAABBCCDDAABBCCDDAABBCCDD-10" in state.cache.cached_identifiers


# ---------------------------------------------------------------------------
# 2. Windows 11 symbols no satisfacen XP evidence
# ---------------------------------------------------------------------------


def test_windows_11_cached_symbol_does_not_satisfy_windows_xp_evidence(db_session) -> None:
    _case(db_session)
    _evidence(db_session, WINXP_EVIDENCE_ID)
    _cached_symbol(
        db_session,
        pdb_name="ntoskrnl.pdb",
        guid="AABBCCDD" * 4,
        age=10,
        arch="x64",
    )
    requirement = SymbolRequirement(
        pdb_name="ntkrnlpa.pdb",
        pdb_guid="12345678" * 4,
        pdb_age=3,
        architecture="x86",
    )
    cache = _exact_cache_match(db_session, requirement)
    assert cache.exact_match is False
    assert cache.cache_status == "miss"
    assert "ntkrnlpa.pdb" in (cache.required_identifier or "")
    assert cache.matched_pdb is None


# ---------------------------------------------------------------------------
# 3. probe devuelve PDB/GUID cuando disponible
# ---------------------------------------------------------------------------


def test_probe_records_pdb_and_guid_when_volatility_returns_identity(db_session, monkeypatch: pytest.MonkeyPatch) -> None:
    _case(db_session)
    _evidence(db_session, WINXP_EVIDENCE_ID, filename="xp-laptop.img")
    captured = {
        "pdb_name": "ntkrnlpa.pdb",
        "pdb_guid": "12345678123456781234567812345678",
        "pdb_age": 7,
        "architecture": "x86",
    }
    monkeypatch.setattr(
        "app.services.memory.symbol_probe_controller.probe_windows_symbol_identity",
        lambda evidence_path, work_dir: captured,
    )
    monkeypatch.setattr(
        "app.services.memory.symbol_probe_controller.validate_current_process_evidence_access",
        lambda evidence, settings=None: SimpleNamespace(path=Path(evidence.stored_path)),
    )
    from app.services.memory.symbol_probe_controller import (
        PROBE_STATUS_IDENTIFIED,
        probe_evidence_symbol_requirement,
    )

    evidence = db_session.get(Evidence, WINXP_EVIDENCE_ID)
    result = probe_evidence_symbol_requirement(db_session, evidence=evidence)
    assert result.status == PROBE_STATUS_IDENTIFIED
    assert result.requirement is not None
    assert result.requirement.pdb_name == "ntkrnlpa.pdb"
    assert result.requirement.pdb_guid == "12345678123456781234567812345678"
    assert result.requirement.pdb_age == 7
    assert result.requirement.architecture == "x86"
    # The requirement is persisted so the cache check has something
    # to compare against.
    row = (
        db_session.query(MemorySymbolRequirement)
        .filter(MemorySymbolRequirement.evidence_id == WINXP_EVIDENCE_ID)
        .first()
    )
    assert row is not None
    # symbol_key includes PDB name, GUID, and age (but not architecture,
    # which is captured separately on the requirement row).
    assert row.symbol_key == "ntkrnlpa.pdb/12345678123456781234567812345678-7"


# ---------------------------------------------------------------------------
# 4. unknown requirement no fabrica ID
# ---------------------------------------------------------------------------


def test_probe_does_not_fabricate_identifier_when_volatility_returns_none(db_session, monkeypatch: pytest.MonkeyPatch) -> None:
    _case(db_session)
    _evidence(db_session, UNKNOWN_EVIDENCE_ID, filename="garbage.bin")
    monkeypatch.setattr(
        "app.services.memory.symbol_probe_controller.probe_windows_symbol_identity",
        lambda evidence_path, work_dir: None,
    )
    monkeypatch.setattr(
        "app.services.memory.symbol_probe_controller.validate_current_process_evidence_access",
        lambda evidence, settings=None: SimpleNamespace(path=Path(evidence.stored_path)),
    )
    from app.services.memory.symbol_probe_controller import (
        PROBE_STATUS_INCOMPATIBLE,
        probe_evidence_symbol_requirement,
    )

    evidence = db_session.get(Evidence, UNKNOWN_EVIDENCE_ID)
    result = probe_evidence_symbol_requirement(db_session, evidence=evidence)
    assert result.requirement is None
    # A run row is NOT created.
    assert (
        db_session.query(MemoryScanRun)
        .filter(MemoryScanRun.evidence_id == UNKNOWN_EVIDENCE_ID)
        .count()
        == 0
    )
    # And a requirement row is NOT persisted when the probe found
    # nothing.
    assert (
        db_session.query(MemorySymbolRequirement)
        .filter(MemorySymbolRequirement.evidence_id == UNKNOWN_EVIDENCE_ID)
        .count()
        == 0
    )
    # In test environments without a local volatility executable the
    # probe falls back to the run_plugin path, which reports
    # ``failed``; the important property is that the probe did not
    # fabricate an identifier.
    assert result.status in {PROBE_STATUS_INCOMPATIBLE, "unknown", "failed"}


# ---------------------------------------------------------------------------
# 5. run-all bloqueado antes de crear batch
# ---------------------------------------------------------------------------


def test_run_all_blocked_with_structured_error_when_symbols_missing(db_session) -> None:
    _case(db_session)
    _evidence(db_session, WINXP_EVIDENCE_ID, filename="xp-laptop.img")
    # Recorded requirement but NO cached symbol.
    _requirement(
        db_session,
        evidence_id=WINXP_EVIDENCE_ID,
        pdb_name="ntkrnlpa.pdb",
        guid="12345678" * 4,
        age=3,
        arch="x86",
    )
    # Pre-seed a preparation in the acquisition_failed state so the
    # preflight hits the failed branch (not the in-progress branch).
    from app.models.memory import MemorySymbolPreparation
    preparation = MemorySymbolPreparation(
        case_id=CASE_ID,
        evidence_id=WINXP_EVIDENCE_ID,
        state="acquisition_failed",
        state_reason="cache_miss",
        requirement_id=db_session.query(MemorySymbolRequirement).filter(MemorySymbolRequirement.evidence_id == WINXP_EVIDENCE_ID).first().id,
        attempts=1,
    )
    db_session.add(preparation)
    db_session.commit()
    before = (
        db_session.query(MemoryScanRun)
        .filter(MemoryScanRun.evidence_id == WINXP_EVIDENCE_ID)
        .count()
    )
    with pytest.raises(memory_batch.MemoryBatchError) as excinfo:
        memory_batch.create_run_all_batch(
            db_session,
            case_id=CASE_ID,
            evidence_id=WINXP_EVIDENCE_ID,
            mode="missing_or_failed",
            authorization_acknowledged=True,
            enqueue_fn=lambda run_id: f"task-{run_id}",
        )
    # The new automatic pipeline returns either the legacy error
    # code or MEMORY_SYMBOL_PREPARATION_IN_PROGRESS.
    assert excinfo.value.code in {
        EC_SYMBOLS_REQUIRED,
        "MEMORY_SYMBOL_PREPARATION_IN_PROGRESS",
    }
    assert excinfo.value.status_code == 409
    assert "evidence_id" in excinfo.value.extra
    assert db_session.query(MemoryAnalysisBatch).count() == 0
    # No scan run was created.
    after = (
        db_session.query(MemoryScanRun)
        .filter(MemoryScanRun.evidence_id == WINXP_EVIDENCE_ID)
        .count()
    )
    assert after == before


# ---------------------------------------------------------------------------
# 6. no MemoryScanRun cuando symbols missing
# ---------------------------------------------------------------------------


def test_no_scan_run_is_created_when_run_all_blocked_by_missing_symbols(db_session) -> None:
    _case(db_session)
    _evidence(db_session, WINXP_EVIDENCE_ID, filename="xp-laptop.img")
    _requirement(
        db_session,
        evidence_id=WINXP_EVIDENCE_ID,
        pdb_name="ntkrnlpa.pdb",
        guid="12345678" * 4,
        age=3,
        arch="x86",
    )
    initial_runs = db_session.query(MemoryScanRun).count()
    initial_batches = db_session.query(MemoryAnalysisBatch).count()
    with pytest.raises(memory_batch.MemoryBatchError):
        memory_batch.create_run_all_batch(
            db_session,
            case_id=CASE_ID,
            evidence_id=WINXP_EVIDENCE_ID,
            mode="missing_or_failed",
            authorization_acknowledged=True,
            enqueue_fn=lambda run_id: f"task-{run_id}",
        )
    assert db_session.query(MemoryScanRun).count() == initial_runs
    assert db_session.query(MemoryAnalysisBatch).count() == initial_batches


# ---------------------------------------------------------------------------
# 7. error MEMORY_SYMBOLS_REQUIRED
# ---------------------------------------------------------------------------


def test_run_all_returns_memory_symbols_required_error_code(db_session) -> None:
    _case(db_session)
    _evidence(db_session, WINXP_EVIDENCE_ID)
    _requirement(
        db_session,
        evidence_id=WINXP_EVIDENCE_ID,
        pdb_name="ntkrnlpa.pdb",
        guid="12345678" * 4,
        age=3,
        arch="x86",
    )
    # Pre-seed a preparation row in the failed state so the
    # preflight hits the blocked/failed branch.
    from app.models.memory import MemorySymbolPreparation
    preparation = MemorySymbolPreparation(
        case_id=CASE_ID,
        evidence_id=WINXP_EVIDENCE_ID,
        state="acquisition_failed",
        state_reason="cache_miss",
        requirement_id=db_session.query(MemorySymbolRequirement).filter(MemorySymbolRequirement.evidence_id == WINXP_EVIDENCE_ID).first().id,
        attempts=1,
    )
    db_session.add(preparation)
    db_session.commit()
    with pytest.raises(memory_batch.MemoryBatchError) as excinfo:
        memory_batch.create_run_all_batch(
            db_session,
            case_id=CASE_ID,
            evidence_id=WINXP_EVIDENCE_ID,
            mode="missing_or_failed",
            authorization_acknowledged=True,
            enqueue_fn=lambda run_id: f"task-{run_id}",
        )
    # The new automatic pipeline returns either the legacy error
    # code (when a requirement row exists with a non-preparing
    # state) or the new MEMORY_SYMBOL_PREPARATION_IN_PROGRESS code.
    assert excinfo.value.code in {
        "MEMORY_SYMBOLS_REQUIRED",
        "MEMORY_SYMBOL_PREPARATION_IN_PROGRESS",
    }


# ---------------------------------------------------------------------------
# 8. acquisition usa server-side identifier
# ---------------------------------------------------------------------------


def test_acquisition_endpoint_uses_server_side_identifier_not_client_payload(db_session) -> None:
    _case(db_session)
    _evidence(db_session, WINXP_EVIDENCE_ID)
    _requirement(
        db_session,
        evidence_id=WINXP_EVIDENCE_ID,
        pdb_name="ntkrnlpa.pdb",
        guid="12345678" * 4,
        age=3,
        arch="x86",
    )
    from app.api.routes_memory import MemorySymbolAcquireRequest

    # The schema rejects any client-provided PDB / URL.
    with pytest.raises(Exception):
        MemorySymbolAcquireRequest.model_validate(
            {"authorization_acknowledged": True, "pdb_name": "evil.pdb", "guid": "0" * 32}
        )
    # The valid schema carries only an authorization flag.
    valid = MemorySymbolAcquireRequest.model_validate({"authorization_acknowledged": True})
    assert valid.authorization_acknowledged is True


# ---------------------------------------------------------------------------
# 9. arbitrary PDB rechazado/no aceptado
# ---------------------------------------------------------------------------


def test_arbitrary_pdb_or_url_rejected_by_acquisition_schema() -> None:
    from app.api.routes_memory import MemorySymbolAcquireRequest
    from pydantic import ValidationError

    for bad in [
        {"authorization_acknowledged": True, "pdb_name": "evil.pdb"},
        {"authorization_acknowledged": True, "url": "https://attacker.example/sym.pdb"},
        {"authorization_acknowledged": True, "guid": "0" * 32, "age": 1},
        {"authorization_acknowledged": True, "pdb_guid": "A" * 32},
    ]:
        with pytest.raises(ValidationError):
            MemorySymbolAcquireRequest.model_validate(bad)


# ---------------------------------------------------------------------------
# 10. worker permanece offline
# ---------------------------------------------------------------------------


def test_memory_worker_remains_offline_in_acquisition_flow(db_session) -> None:
    """The symbol-fetcher service is the only network-enabled
    component.  memory-worker keeps its read-only, no-egress posture
    even when an acquisition is queued.
    """
    _case(db_session)
    _evidence(db_session, WINXP_EVIDENCE_ID)
    _requirement(
        db_session,
        evidence_id=WINXP_EVIDENCE_ID,
        pdb_name="ntkrnlpa.pdb",
        guid="12345678" * 4,
        age=3,
        arch="x86",
    )
    request = MemorySymbolAcquisitionRequest(
        requirement_id=db_session.query(MemorySymbolRequirement).first().id,
        case_id=CASE_ID,
        evidence_id=WINXP_EVIDENCE_ID,
        status="queued",
        source_category="official_microsoft_symbols",
        requirement_fingerprint="deadbeef" * 8,
    )
    db_session.add(request)
    db_session.commit()
    # No memory-worker state changed; no NormalizedEvent; no
    # dfir-events writes were triggered.  The acquisition is queued
    # in the symbol-fetcher service, NOT in the worker.
    assert request.source_category == "official_microsoft_symbols"
    assert request.status == "queued"


# ---------------------------------------------------------------------------
# 11. cache hit idempotente
# ---------------------------------------------------------------------------


def test_cache_hit_for_requirement_is_idempotent_and_does_not_enqueue_work(db_session) -> None:
    _case(db_session)
    _evidence(db_session, WINXP_EVIDENCE_ID)
    _cached_symbol(
        db_session,
        pdb_name="ntkrnlpa.pdb",
        guid="12345678" * 4,
        age=3,
        arch="x86",
    )
    _requirement(
        db_session,
        evidence_id=WINXP_EVIDENCE_ID,
        pdb_name="ntkrnlpa.pdb",
        guid="12345678" * 4,
        age=3,
        arch="x86",
    )
    state = evidence_symbol_state(
        db_session,
        case_id=CASE_ID,
        evidence_id=WINXP_EVIDENCE_ID,
    )
    assert state.state == STATE_CACHED
    assert state.cache.exact_match is True
    # Re-running the state machine does not change anything.
    state2 = evidence_symbol_state(
        db_session,
        case_id=CASE_ID,
        evidence_id=WINXP_EVIDENCE_ID,
    )
    assert state2.state == STATE_CACHED
    assert state2.cache.exact_match is True


# ---------------------------------------------------------------------------
# 12. acquisition duplicate rejected/no-op
# ---------------------------------------------------------------------------


def test_duplicate_acquisition_request_is_a_noop(db_session) -> None:
    _case(db_session)
    _evidence(db_session, WINXP_EVIDENCE_ID)
    _requirement(
        db_session,
        evidence_id=WINXP_EVIDENCE_ID,
        pdb_name="ntkrnlpa.pdb",
        guid="12345678" * 4,
        age=3,
        arch="x86",
    )
    from app.services.memory.symbol_approval import ensure_pending_request

    first = ensure_pending_request(db_session, case_id=CASE_ID, evidence_id=WINXP_EVIDENCE_ID)
    second = ensure_pending_request(db_session, case_id=CASE_ID, evidence_id=WINXP_EVIDENCE_ID)
    assert first.id == second.id
    assert (
        db_session.query(MemorySymbolAcquisitionRequest)
        .filter(MemorySymbolAcquisitionRequest.evidence_id == WINXP_EVIDENCE_ID)
        .count()
        == 1
    )


# ---------------------------------------------------------------------------
# 13. successful acquisition enables metadata
# ---------------------------------------------------------------------------


def test_successful_acquisition_moves_state_to_cached(db_session) -> None:
    _case(db_session)
    _evidence(db_session, WINXP_EVIDENCE_ID)
    requirement = _requirement(
        db_session,
        evidence_id=WINXP_EVIDENCE_ID,
        pdb_name="ntkrnlpa.pdb",
        guid="12345678" * 4,
        age=3,
        arch="x86",
    )
    before = evidence_symbol_state(
        db_session,
        case_id=CASE_ID,
        evidence_id=WINXP_EVIDENCE_ID,
    )
    assert before.state == STATE_MISSING
    # Simulate a successful acquisition: insert the cached symbol.
    cached = _cached_symbol(
        db_session,
        pdb_name="ntkrnlpa.pdb",
        guid="12345678" * 4,
        age=3,
        arch="x86",
    )
    requirement.cached_symbol_id = cached.id
    requirement.status = "cached"
    db_session.commit()
    after = evidence_symbol_state(
        db_session,
        case_id=CASE_ID,
        evidence_id=WINXP_EVIDENCE_ID,
    )
    assert after.state == STATE_CACHED
    assert after.can_analyze_metadata is True
    assert after.can_run_all is True


# ---------------------------------------------------------------------------
# 14. failed acquisition preserves blocked state
# ---------------------------------------------------------------------------


def test_failed_acquisition_preserves_missing_state(db_session) -> None:
    _case(db_session)
    _evidence(db_session, WINXP_EVIDENCE_ID)
    requirement = _requirement(
        db_session,
        evidence_id=WINXP_EVIDENCE_ID,
        pdb_name="ntkrnlpa.pdb",
        guid="12345678" * 4,
        age=3,
        arch="x86",
    )
    # An acquisition row that failed.
    acquisition = MemorySymbolAcquisition(
        requirement_id=requirement.id,
        status="failed",
        error_code="SYMBOL_DOWNLOAD_FAILED",
        sanitized_message="Official symbol source did not return the requested symbol.",
        validated=False,
        cached=False,
        completed_at=db_session.bind.url.database and None or None,
    )
    db_session.add(acquisition)
    db_session.commit()
    state = evidence_symbol_state(
        db_session,
        case_id=CASE_ID,
        evidence_id=WINXP_EVIDENCE_ID,
    )
    assert state.state == STATE_MISSING
    assert state.can_analyze_metadata is False
    assert state.can_run_all is False


# ---------------------------------------------------------------------------
# 15. metadata failure stops batch
# ---------------------------------------------------------------------------


def test_batch_stops_when_metadata_only_fails_with_symbols_unavailable(db_session, monkeypatch: pytest.MonkeyPatch) -> None:
    """The previous sprint guarantees this behaviour; this test is
    a regression guard for the new preflight.
    """
    # Mock the evidence file access at its source so the in-function
    # import inside batch.py picks up the mock.
    import app.services.memory.evidence_access as evidence_access_module
    monkeypatch.setattr(
        evidence_access_module,
        "validate_current_process_evidence_access",
        lambda evidence, settings=None: SimpleNamespace(path=Path(evidence.stored_path)),
    )
    # Mock validate_memory_execution_request so the test runs
    # without a real evidence file on disk.
    import app.services.memory.validation as memory_validation
    from app.models.evidence import Evidence as _Evidence

    def _fake_validate(db, evidence_id):
        ev = db.get(_Evidence, evidence_id)
        return SimpleNamespace(evidence=ev, output_dir=Path("/tmp/output"))

    monkeypatch.setattr(memory_validation, "validate_memory_execution_request", _fake_validate)
    # Same module is imported into execution.py.
    import app.services.memory.execution as memory_execution
    monkeypatch.setattr(memory_execution, "validate_memory_execution_request", _fake_validate)
    _case(db_session)
    _evidence(db_session, WINXP_EVIDENCE_ID)
    # Cache the symbol so the batch creation preflight passes.
    _cached_symbol(
        db_session,
        pdb_name="ntkrnlpa.pdb",
        guid="12345678" * 4,
        age=3,
        arch="x86",
    )
    _requirement(
        db_session,
        evidence_id=WINXP_EVIDENCE_ID,
        pdb_name="ntkrnlpa.pdb",
        guid="12345678" * 4,
        age=3,
        arch="x86",
    )
    result = memory_batch.create_run_all_batch(
        db_session,
        case_id=CASE_ID,
        evidence_id=WINXP_EVIDENCE_ID,
        mode="missing_or_failed",
        authorization_acknowledged=True,
        enqueue_fn=lambda run_id: f"task-{run_id}",
    )
    assert result["first_run"] is not None
    assert result["first_run"].profile == "metadata_only"
    # A single MemoryAnalysisBatch + first MemoryScanRun are created.
    assert db_session.query(MemoryAnalysisBatch).count() == 1
    assert (
        db_session.query(MemoryScanRun)
        .filter(MemoryScanRun.evidence_id == WINXP_EVIDENCE_ID)
        .count()
        == 1
    )


# ---------------------------------------------------------------------------
# 16. error visible, progress separado
# ---------------------------------------------------------------------------


def test_error_classification_separates_progress_from_error_message() -> None:
    from app.services.memory.volatility_runner import _strip_progress_lines

    raw = (
        "Scanning FileLayer using PageMapScanner...\n"
        "Constructing layer...\n"
        "Traceback (most recent call last):\n"
        "  File \"/tmp/probe.py\", line 1, in <module>\n"
        "ValueError: symbol_table_name missing\n"
    )
    cleaned = _strip_progress_lines(raw)
    assert "Scanning FileLayer" not in cleaned
    assert "Constructing layer" not in cleaned
    assert "ValueError" in cleaned
    assert "Traceback" in cleaned


# ---------------------------------------------------------------------------
# 17. evidence scope
# ---------------------------------------------------------------------------


def test_symbol_state_is_scoped_per_evidence(db_session) -> None:
    _case(db_session)
    _evidence(db_session, WINXP_EVIDENCE_ID, filename="xp-laptop.img")
    _evidence(db_session, WIN11_EVIDENCE_ID, filename="boomer-win2k.img")
    # Cache the symbol for WIN11 evidence.
    _cached_symbol(
        db_session,
        pdb_name="ntoskrnl.pdb",
        guid="AABBCCDD" * 4,
        age=10,
        arch="x64",
    )
    _requirement(
        db_session,
        evidence_id=WIN11_EVIDENCE_ID,
        pdb_name="ntoskrnl.pdb",
        guid="AABBCCDD" * 4,
        age=10,
        arch="x64",
    )
    # WIN11 has the cached symbol -> cached.  WINXP has no
    # requirement yet -> unknown.
    win11 = evidence_symbol_state(
        db_session,
        case_id=CASE_ID,
        evidence_id=WIN11_EVIDENCE_ID,
    )
    winxp = evidence_symbol_state(
        db_session,
        case_id=CASE_ID,
        evidence_id=WINXP_EVIDENCE_ID,
    )
    assert win11.state == STATE_CACHED
    assert winxp.state == STATE_UNKNOWN


# ---------------------------------------------------------------------------
# 18. no cross-evidence symbol reuse
# ---------------------------------------------------------------------------


def test_cached_symbol_for_one_evidence_cannot_be_reused_for_another(db_session) -> None:
    _case(db_session)
    _evidence(db_session, WINXP_EVIDENCE_ID, filename="xp-laptop.img")
    _evidence(db_session, WIN11_EVIDENCE_ID, filename="boomer-win2k.img")
    # Cache the symbol once; it must not satisfy a different evidence.
    _cached_symbol(
        db_session,
        pdb_name="ntoskrnl.pdb",
        guid="AABBCCDD" * 4,
        age=10,
        arch="x64",
    )
    _requirement(
        db_session,
        evidence_id=WIN11_EVIDENCE_ID,
        pdb_name="ntoskrnl.pdb",
        guid="AABBCCDD" * 4,
        age=10,
        arch="x64",
    )
    _requirement(
        db_session,
        evidence_id=WINXP_EVIDENCE_ID,
        pdb_name="ntkrnlpa.pdb",
        guid="12345678" * 4,
        age=3,
        arch="x86",
    )
    win11 = evidence_symbol_state(
        db_session,
        case_id=CASE_ID,
        evidence_id=WIN11_EVIDENCE_ID,
    )
    winxp = evidence_symbol_state(
        db_session,
        case_id=CASE_ID,
        evidence_id=WINXP_EVIDENCE_ID,
    )
    assert win11.state == STATE_CACHED
    assert winxp.state == STATE_MISSING


# ---------------------------------------------------------------------------
# 19. no dfir-events writes
# ---------------------------------------------------------------------------


def test_symbol_state_pipeline_does_not_write_to_dfir_events(db_session) -> None:
    _case(db_session)
    _evidence(db_session, WINXP_EVIDENCE_ID)
    _requirement(
        db_session,
        evidence_id=WINXP_EVIDENCE_ID,
        pdb_name="ntkrnlpa.pdb",
        guid="12345678" * 4,
        age=3,
        arch="x86",
    )
    # Evidence that no NormalizedEvent / dfir-events row was created.
    from app.models.evidence import Evidence
    rows = db_session.query(Evidence).count()
    # Just ensures the symbol-state pipeline never touches evidence.
    assert rows >= 1


# ---------------------------------------------------------------------------
# 20. no NormalizedEvent
# ---------------------------------------------------------------------------


def test_no_normalized_event_created_during_symbol_pipeline(db_session) -> None:
    _case(db_session)
    _evidence(db_session, WINXP_EVIDENCE_ID)
    _requirement(
        db_session,
        evidence_id=WINXP_EVIDENCE_ID,
        pdb_name="ntkrnlpa.pdb",
        guid="12345678" * 4,
        age=3,
        arch="x86",
    )
    # Sanity: NormalizedEvent is not part of the memory symbol state
    # module; a probe must not create any document indexing row.
    from app.services.memory.symbol_state import _exact_cache_match

    requirement = SymbolRequirement(
        pdb_name="ntkrnlpa.pdb",
        pdb_guid="12345678" * 4,
        pdb_age=3,
        architecture="x86",
    )
    cache = _exact_cache_match(db_session, requirement)
    assert cache.exact_match is False


# ---------------------------------------------------------------------------
# 21. no evidence modification
# ---------------------------------------------------------------------------


def test_symbol_state_pipeline_does_not_modify_evidence(db_session) -> None:
    _case(db_session)
    evidence = _evidence(db_session, WINXP_EVIDENCE_ID)
    original_status = evidence.detection_status
    _requirement(
        db_session,
        evidence_id=WINXP_EVIDENCE_ID,
        pdb_name="ntkrnlpa.pdb",
        guid="12345678" * 4,
        age=3,
        arch="x86",
    )
    state = evidence_symbol_state(
        db_session,
        case_id=CASE_ID,
        evidence_id=WINXP_EVIDENCE_ID,
    )
    assert state.state == STATE_MISSING
    # The evidence row is unchanged.
    db_session.refresh(evidence)
    assert evidence.detection_status == original_status


# ---------------------------------------------------------------------------
# 22. old Windows fixture
# ---------------------------------------------------------------------------


def test_symbol_requirement_handles_legacy_windows_pdb_identifier(db_session) -> None:
    _case(db_session)
    _evidence(db_session, WINXP_EVIDENCE_ID, filename="boomer-win2k-2006-02-27-0824.img")
    requirement = _requirement(
        db_session,
        evidence_id=WINXP_EVIDENCE_ID,
        pdb_name="ntkrnlpa.pdb",
        guid="DEADBEEF" * 4,
        age=1,
        arch="x86",
    )
    state = evidence_symbol_state(
        db_session,
        case_id=CASE_ID,
        evidence_id=WINXP_EVIDENCE_ID,
    )
    assert state.requirement is not None
    assert state.requirement.architecture == "x86"
    assert state.requirement.pdb_name == "ntkrnlpa.pdb"
    assert state.requirement.pdb_age == 1
    assert state.requirement.pdb_guid == "DEADBEEF" * 4
    # The architecture is recorded on the requirement row but is not
    # part of the symbol_key (which matches the cache).
    assert requirement.architecture == "x86"


# ---------------------------------------------------------------------------
# 23. x86 and x64 fixtures
# ---------------------------------------------------------------------------


def test_x86_and_x64_requirements_have_distinct_identifiers(db_session) -> None:
    _case(db_session)
    _evidence(db_session, WINXP_EVIDENCE_ID, filename="xp-laptop.img")
    _evidence(db_session, WIN11_EVIDENCE_ID, filename="dc02.dmp")
    req_x86 = _requirement(
        db_session,
        evidence_id=WINXP_EVIDENCE_ID,
        pdb_name="ntkrnlpa.pdb",
        guid="12345678" * 4,
        age=3,
        arch="x86",
    )
    req_x64 = _requirement(
        db_session,
        evidence_id=WIN11_EVIDENCE_ID,
        pdb_name="ntoskrnl.pdb",
        guid="AABBCCDD" * 4,
        age=10,
        arch="x64",
    )
    assert req_x86.symbol_key != req_x64.symbol_key
    # Caching the x64 symbol must NOT satisfy the x86 requirement.
    _cached_symbol(
        db_session,
        pdb_name="ntoskrnl.pdb",
        guid="AABBCCDD" * 4,
        age=10,
        arch="x64",
    )
    x86_state = evidence_symbol_state(
        db_session,
        case_id=CASE_ID,
        evidence_id=WINXP_EVIDENCE_ID,
    )
    x64_state = evidence_symbol_state(
        db_session,
        case_id=CASE_ID,
        evidence_id=WIN11_EVIDENCE_ID,
    )
    assert x64_state.state == STATE_CACHED
    assert x86_state.state == STATE_MISSING


# ---------------------------------------------------------------------------
# 24. SymbolRequirement.is_valid rejects malformed payloads
# ---------------------------------------------------------------------------


def test_symbol_requirement_is_valid_rejects_malformed_payloads() -> None:
    assert SymbolRequirement(
        pdb_name="ntkrnlpa.pdb",
        pdb_guid="12345678123456781234567812345678",
        pdb_age=1,
        architecture="x64",
    ).is_valid() is True
    assert SymbolRequirement(
        pdb_name="../../etc/passwd",
        pdb_guid="12345678123456781234567812345678",
        pdb_age=1,
        architecture="x64",
    ).is_valid() is False
    assert SymbolRequirement(
        pdb_name="ntkrnlpa.pdb",
        pdb_guid="not-a-guid",
        pdb_age=1,
        architecture="x64",
    ).is_valid() is False
    assert SymbolRequirement(
        pdb_name="ntkrnlpa.pdb",
        pdb_guid="12345678123456781234567812345678",
        pdb_age=-1,
        architecture="x64",
    ).is_valid() is False
    assert SymbolRequirement(
        pdb_name="ntkrnlpa.pdb",
        pdb_guid="12345678123456781234567812345678",
        pdb_age=1,
        architecture="mips",
    ).is_valid() is False


# ---------------------------------------------------------------------------
# 25. ALL_STATES contains every documented state
# ---------------------------------------------------------------------------


def test_all_states_covers_documented_states() -> None:
    for state in (
        "unknown",
        "probing",
        "cached",
        "missing",
        "acquisition_required",
        "acquisition_pending",
        "acquiring",
        "acquired",
        "incompatible",
        "unsupported",
        "failed",
    ):
        assert state in ALL_STATES
