"""Test the worker's catch clauses for structured acquisition failures.

The worker's ``acquire_windows_symbol`` function runs a single
managed acquisition.  It has two catch clauses:

* ``except SymbolFetchError`` (the canonical structured
  acquisition exception) — preserves the original error code
  (e.g. ``SYMBOL_PDB_IDENTITY_MISMATCH``,
  ``SYMBOL_EGRESS_TIMEOUT``);
* ``except Exception`` (the generic fallback) — maps unexpected
  failures to ``SYMBOL_ACQUISITION_FAILED``.

These tests pin the contract: a ``SymbolFetchError`` raised by the
in-fetcher ``validate_pdb`` (the canonical
``SYMBOL_PDB_IDENTITY_MISMATCH`` path) MUST be caught by the
structured clause and persisted verbatim.  A truly unexpected
exception falls through to the generic clause.
"""
from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path
from uuid import uuid4

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from app.core.database import Base
from app.models.case import Case
from app.models.evidence import Evidence, EvidenceStorageMode, EvidenceType, IngestStatus
from app.models.memory import (
    MemorySymbolAcquisition,
    MemorySymbolAcquisitionRequest,
    MemorySymbolRequirement,
)


def _utc() -> datetime:
    return datetime.now(timezone.utc).replace(tzinfo=None)


@pytest.fixture()
def db():
    engine = create_engine("sqlite:///:memory:", connect_args={"check_same_thread": False})
    Base.metadata.create_all(bind=engine)
    Session_ = sessionmaker(bind=engine)
    session = Session_()
    yield session
    session.close()


def _make_case(db, name="test") -> Case:
    case = Case(
        id=str(uuid4()),
        name=name,
        description="",
        status="open",
        mode="investigation",
        timezone="UTC",
    )
    db.add(case)
    db.commit()
    return case


def _make_evidence(db, case_id: str, filename: str = "a.dmp") -> Evidence:
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
        created_at=_utc(),
    )
    db.add(evidence)
    db.commit()
    return evidence


def _seed_requirement_and_acquisition(
    db,
    *,
    case_id: str,
    evidence_id: str,
    requirement_id: str,
    acquisition_id: str,
    request_id: str,
) -> tuple[MemorySymbolRequirement, MemorySymbolAcquisition, MemorySymbolAcquisitionRequest]:
    requirement = MemorySymbolRequirement(
        id=requirement_id,
        case_id=case_id,
        evidence_id=evidence_id,
        pdb_name="ntkrnlmp.pdb",
        pdb_guid="D801A9AFC0FB7761380800F708633DEA",
        pdb_age=1,
        architecture="x64",
        symbol_key="ntkrnlmp.pdb/D801A9AFC0FB7761380800F708633DEA-1",
        status="acquiring",
        source="bounded_discovery",
        confidence="high",
        requested_pdb_age=1,
        age_corrected=False,
        backfill_version="v1",
        metadata_json={},
        is_shared=False,
    )
    acquisition = MemorySymbolAcquisition(
        id=acquisition_id,
        requirement_id=requirement_id,
        status="downloading",
        source_category="official_microsoft_symbols",
        downloaded_bytes=0,
        validated=False,
        cached=False,
        retryable=False,
        metadata_json={},
    )
    # Pin the fingerprint to the value the worker computes from
    # the seeded requirement, so the fingerprint-drift guard
    # accepts the request.
    from app.services.memory.symbol_approval import (
        requirement_fingerprint,
    )
    fingerprint = requirement_fingerprint(requirement)
    request = MemorySymbolAcquisitionRequest(
        id=request_id,
        case_id=case_id,
        evidence_id=evidence_id,
        requirement_id=requirement_id,
        source_category="official_microsoft_symbols",
        status="downloading",
        requirement_fingerprint=fingerprint,
        error_code=None,
        sanitized_message=None,
        metadata_json={},
    )
    db.add_all([requirement, acquisition, request])
    db.commit()
    return requirement, acquisition, request


def test_pdb_identity_mismatch_caught_by_structured_clause(
    tmp_path: Path, monkeypatch, db
) -> None:
    """A ``SymbolFetchError`` raised by ``validate_pdb`` with
    ``code=SYMBOL_PDB_IDENTITY_MISMATCH`` MUST be caught by the
    structured ``except SymbolFetchError`` clause and persisted
    with the original code.  The previous bug dropped the
    exception into the generic ``except Exception`` and persisted
    the generic ``SYMBOL_ACQUISITION_FAILED`` code.
    """
    from app.services.memory import symbol_fetcher
    from app.workers import symbol_tasks

    case = _make_case(db)
    evidence = _make_evidence(db, case.id)
    requirement_id = str(uuid4())
    acquisition_id = str(uuid4())
    request_id = str(uuid4())
    _seed_requirement_and_acquisition(
        db,
        case_id=case.id,
        evidence_id=evidence.id,
        requirement_id=requirement_id,
        acquisition_id=acquisition_id,
        request_id=request_id,
    )
    # Stub settings so the worker passes its gate checks.
    from app.core import config as config_module

    def _settings():
        s = type("S", (), {})()
        s.memory_symbol_managed_download_enabled = True
        s.memory_symbol_network_isolation_ready = True
        s.memory_symbol_egress_gateway_secret = "secret"
        s.memory_symbol_cache_path = tmp_path
        s.memory_symbol_download_max_bytes = 1024 * 1024 * 1024
        s.memory_symbol_cache_max_bytes = 10 * 1024 * 1024 * 1024
        s.memory_symbol_egress_gateway_url = "http://symbol-egress-gateway:8443"
        s.memory_symbol_egress_gateway_timeout_seconds = 60
        s.memory_symbol_egress_max_response_bytes = 50 * 1024 * 1024
        s.memory_symbol_isf_max_bytes = 50 * 1024 * 1024
        return s

    monkeypatch.setattr(config_module, "get_settings", _settings)
    monkeypatch.setattr(symbol_tasks, "get_settings", _settings)
    monkeypatch.setattr(symbol_tasks, "SessionLocal", lambda: db)
    # Stub fetch_pdb_via_egress to return a fake result.
    from app.services.memory import symbol_egress_client

    fake_result = type("R", (), {})()
    fake_result.bytes_received = 1024
    fake_result.sha256 = "abc"
    fake_result.redirect_count = 0
    fake_result.duration_ms = 100
    monkeypatch.setattr(symbol_egress_client, "fetch_pdb_via_egress", lambda **kw: fake_result)
    monkeypatch.setattr(symbol_tasks, "fetch_pdb_via_egress", lambda **kw: fake_result)
    # Stub validate_pdb to raise the canonical identity mismatch.
    def fake_validate_pdb(*args, **kwargs):
        raise symbol_fetcher.SymbolFetchError(
            "SYMBOL_PDB_IDENTITY_MISMATCH",
            "expected age=1, observed age=5",
        )

    monkeypatch.setattr(symbol_tasks, "validate_pdb", fake_validate_pdb)
    # Stub the gateway reachability check by patching SessionLocal.
    from app.core import database

    monkeypatch.setattr(database, "SessionLocal", lambda: db)
    # Make a partial PDB file (the worker would have written it via
    # fetch_pdb_via_egress, but we stubbed that to a no-op).
    cache_root = (tmp_path / "tmp").resolve()
    cache_root.mkdir(parents=True, exist_ok=True)
    partial = cache_root / f"{acquisition_id}.pdb.partial"
    partial.write_bytes(b"fake-pdb-content")

    # Invoke the worker.
    symbol_tasks.acquire_windows_symbol(acquisition_id, request_id)

    # Verify the acquisition row was updated with the canonical code.
    db.expire_all()
    acq = db.get(MemorySymbolAcquisition, acquisition_id)
    assert acq is not None
    assert acq.status == "failed"
    assert acq.error_code == "SYMBOL_PDB_IDENTITY_MISMATCH", (
        f"expected the canonical code to be preserved, got {acq.error_code!r}"
    )
    assert "age=1" in (acq.sanitized_message or "")
    assert "age=5" in (acq.sanitized_message or "")


def test_truly_unexpected_exception_maps_to_generic_code(
    tmp_path: Path, monkeypatch, db
) -> None:
    """A truly unexpected exception (NOT a ``SymbolFetchError``) must
    be caught by the generic ``except Exception`` clause and mapped
    to ``SYMBOL_ACQUISITION_FAILED``.
    """
    from app.services.memory import symbol_egress_client
    from app.workers import symbol_tasks
    from app.core import config as config_module
    from app.core import database

    case = _make_case(db)
    evidence = _make_evidence(db, case.id)
    requirement_id = str(uuid4())
    acquisition_id = str(uuid4())
    request_id = str(uuid4())
    _seed_requirement_and_acquisition(
        db,
        case_id=case.id,
        evidence_id=evidence.id,
        requirement_id=requirement_id,
        acquisition_id=acquisition_id,
        request_id=request_id,
    )

    def _settings():
        s = type("S", (), {})()
        s.memory_symbol_managed_download_enabled = True
        s.memory_symbol_network_isolation_ready = True
        s.memory_symbol_egress_gateway_secret = "secret"
        s.memory_symbol_cache_path = tmp_path
        s.memory_symbol_download_max_bytes = 1024 * 1024 * 1024
        s.memory_symbol_cache_max_bytes = 10 * 1024 * 1024 * 1024
        s.memory_symbol_egress_gateway_url = "http://symbol-egress-gateway:8443"
        s.memory_symbol_egress_gateway_timeout_seconds = 60
        s.memory_symbol_egress_max_response_bytes = 50 * 1024 * 1024
        s.memory_symbol_isf_max_bytes = 50 * 1024 * 1024
        return s

    monkeypatch.setattr(config_module, "get_settings", _settings)
    monkeypatch.setattr(symbol_tasks, "get_settings", _settings)
    monkeypatch.setattr(symbol_tasks, "SessionLocal", lambda: db)

    def fake_fetch(**kw):
        raise RuntimeError("totally unexpected network failure")

    monkeypatch.setattr(symbol_egress_client, "fetch_pdb_via_egress", fake_fetch)
    monkeypatch.setattr(symbol_tasks, "fetch_pdb_via_egress", fake_fetch)

    symbol_tasks.acquire_windows_symbol(acquisition_id, request_id)
    db.expire_all()
    acq = db.get(MemorySymbolAcquisition, acquisition_id)
    assert acq is not None
    assert acq.status == "failed"
    assert acq.error_code == "SYMBOL_ACQUISITION_FAILED", (
        f"expected the generic code for unexpected exceptions, got {acq.error_code!r}"
    )
    assert "totally unexpected network failure" in (acq.sanitized_message or "")
