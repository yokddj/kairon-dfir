"""Tests for the local-operator approval workflow."""
from __future__ import annotations

import os
from datetime import timedelta

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from app.core.database import Base
from app.core.config import get_settings
from app.models.case import Case
from app.models.evidence import Evidence, EvidenceType, IngestStatus
from app.models.memory import (
    MemoryScanRun,
    MemorySymbolApproval,
    MemorySymbolRequirement,
    MemorySymbolAcquisitionRequest,
)
from app.services.memory import symbol_approval, symbol_control


def _db():
    engine = create_engine("sqlite:///:memory:", future=True)
    Base.metadata.create_all(engine)
    return sessionmaker(bind=engine, future=True)()


def _setup(monkeypatch, *, local_approval: bool = True, isolation_ready: bool = True, managed: bool = True):
    monkeypatch.setenv("MEMORY_SYMBOL_LOCAL_APPROVAL_ENABLED", "true" if local_approval else "false")
    monkeypatch.setenv("MEMORY_SYMBOL_NETWORK_ISOLATION_READY", "true" if isolation_ready else "false")
    monkeypatch.setenv("MEMORY_SYMBOL_MANAGED_DOWNLOAD_ENABLED", "true" if managed else "false")
    monkeypatch.setenv("MEMORY_SYMBOL_MODE", "managed_download")
    monkeypatch.setenv("MEMORY_SYMBOL_INITIAL_HOST", "msdl.microsoft.com")
    monkeypatch.setenv("MEMORY_SYMBOL_REDIRECT_SUFFIXES", ".blob.core.windows.net")
    monkeypatch.setenv("MEMORY_SYMBOL_ADMIN_AUTHORIZATION_REQUIRED", "true")
    monkeypatch.setenv("MEMORY_SYMBOL_APPROVAL_TTL_SECONDS", "60")
    get_settings.cache_clear()


def _make_case_evidence_requirement(db) -> tuple[str, str, str]:
    case = Case(id="aaaaaaaa-1111-4111-8111-111111111111", name="Lab")
    evidence = Evidence(
        id="bbbbbbbb-2222-4222-8222-222222222222",
        case_id=case.id,
        original_filename="crash.mem",
        stored_path="relative",
        original_path="relative",
        evidence_type=EvidenceType.memory_dump,
        sha256="0" * 64,
        size_bytes=1,
        ingest_status=IngestStatus.completed,
        metadata_json={},
        error_log={},
    )
    db.add_all([case, evidence])
    db.commit()
    run = MemoryScanRun(case_id=case.id, evidence_id=evidence.id, profile="metadata_only", status="failed", error_log={"code": "SYMBOLS_UNAVAILABLE"})
    db.add(run)
    db.commit()
    requirement = MemorySymbolRequirement(
        case_id=case.id,
        evidence_id=evidence.id,
        source_run_id=run.id,
        source_plugin_run_id=run.id,
        pdb_name="ntkrnlmp.pdb",
        pdb_guid="9DC3FC69B1CA4B34707EBC57FD1D6126",
        pdb_age=1,
        architecture="x64",
        symbol_key="ntkrnlmp.pdb/9DC3FC69B1CA4B34707EBC57FD1D6126-1",
        status="unavailable_offline",
    )
    db.add(requirement)
    db.commit()
    return case.id, evidence.id, requirement.id


def test_request_starts_awaiting_when_isolation_not_ready(monkeypatch) -> None:
    _setup(monkeypatch, isolation_ready=False)
    db = _db()
    case_id, evidence_id, _ = _make_case_evidence_requirement(db)
    request = symbol_approval.ensure_pending_request(db, case_id=case_id, evidence_id=evidence_id)
    assert request.status == "awaiting_network_isolation"
    db.close()


def test_request_moves_to_awaiting_operator_approval(monkeypatch) -> None:
    _setup(monkeypatch)
    db = _db()
    case_id, evidence_id, _ = _make_case_evidence_requirement(db)
    request = symbol_approval.ensure_pending_request(db, case_id=case_id, evidence_id=evidence_id)
    assert request.status == "awaiting_operator_approval"
    db.close()


def test_approve_requires_explicit_confirmation(monkeypatch) -> None:
    _setup(monkeypatch)
    db = _db()
    case_id, evidence_id, _ = _make_case_evidence_requirement(db)
    request = symbol_approval.ensure_pending_request(db, case_id=case_id, evidence_id=evidence_id)
    with pytest.raises(symbol_approval.ApprovalError) as exc:
        symbol_approval.approve_request(db, request_id=request.id, confirm=False, yes=False)
    assert exc.value.code == "SYMBOL_APPROVAL_CONFIRMATION_REQUIRED"
    db.close()


def test_approve_then_revoke(monkeypatch) -> None:
    _setup(monkeypatch)
    db = _db()
    case_id, evidence_id, _ = _make_case_evidence_requirement(db)
    request = symbol_approval.ensure_pending_request(db, case_id=case_id, evidence_id=evidence_id)
    approval = symbol_approval.approve_request(db, request_id=request.id, confirm=True, yes=True)
    assert approval.status == "active"
    assert symbol_approval.active_approval_for_request(db, request.id) is not None
    symbol_approval.revoke_approval(db, request_id=request.id)
    assert symbol_approval.active_approval_for_request(db, request.id) is None
    db.close()


def test_approve_rejected_when_already_approved(monkeypatch) -> None:
    _setup(monkeypatch)
    db = _db()
    case_id, evidence_id, _ = _make_case_evidence_requirement(db)
    request = symbol_approval.ensure_pending_request(db, case_id=case_id, evidence_id=evidence_id)
    symbol_approval.approve_request(db, request_id=request.id, confirm=True, yes=True)
    with pytest.raises(symbol_approval.ApprovalError) as exc:
        symbol_approval.approve_request(db, request_id=request.id, confirm=True, yes=True)
    assert exc.value.code == "SYMBOL_APPROVAL_ALREADY_ACTIVE"
    db.close()


def test_consume_is_single_use(monkeypatch) -> None:
    _setup(monkeypatch)
    db = _db()
    case_id, evidence_id, requirement_id = _make_case_evidence_requirement(db)
    request = symbol_approval.ensure_pending_request(db, case_id=case_id, evidence_id=evidence_id)
    symbol_approval.approve_request(db, request_id=request.id, confirm=True, yes=True)
    fingerprint = symbol_approval.requirement_fingerprint(db.get(MemorySymbolRequirement, requirement_id))
    symbol_approval.consume_approval(db, request_id=request.id, requirement_fingerprint_value=fingerprint)
    with pytest.raises(symbol_approval.ApprovalError):
        symbol_approval.consume_approval(db, request_id=request.id, requirement_fingerprint_value=fingerprint)
    db.close()


def test_consume_rejects_fingerprint_mismatch(monkeypatch) -> None:
    _setup(monkeypatch)
    db = _db()
    case_id, evidence_id, _ = _make_case_evidence_requirement(db)
    request = symbol_approval.ensure_pending_request(db, case_id=case_id, evidence_id=evidence_id)
    symbol_approval.approve_request(db, request_id=request.id, confirm=True, yes=True)
    with pytest.raises(symbol_approval.ApprovalError) as exc:
        symbol_approval.consume_approval(db, request_id=request.id, requirement_fingerprint_value="ff" * 32)
    assert exc.value.code == "SYMBOL_APPROVAL_FINGERPRINT_MISMATCH"
    db.close()


def test_expired_approval_cannot_be_consumed(monkeypatch) -> None:
    _setup(monkeypatch)
    db = _db()
    case_id, evidence_id, requirement_id = _make_case_evidence_requirement(db)
    request = symbol_approval.ensure_pending_request(db, case_id=case_id, evidence_id=evidence_id)
    approval = symbol_approval.approve_request(db, request_id=request.id, confirm=True, yes=True)
    # Force expiry by moving the expires_at into the past.
    from app.core.database import utc_now_naive
    approval.expires_at = utc_now_naive() - timedelta(seconds=1)
    db.commit()
    fingerprint = symbol_approval.requirement_fingerprint(db.get(MemorySymbolRequirement, requirement_id))
    with pytest.raises(symbol_approval.ApprovalError) as exc:
        symbol_approval.consume_approval(db, request_id=request.id, requirement_fingerprint_value=fingerprint)
    assert exc.value.code == "SYMBOL_APPROVAL_EXPIRED"
    db.close()


def test_revoked_approval_cannot_be_consumed(monkeypatch) -> None:
    _setup(monkeypatch)
    db = _db()
    case_id, evidence_id, requirement_id = _make_case_evidence_requirement(db)
    request = symbol_approval.ensure_pending_request(db, case_id=case_id, evidence_id=evidence_id)
    symbol_approval.approve_request(db, request_id=request.id, confirm=True, yes=True)
    symbol_approval.revoke_approval(db, request_id=request.id)
    fingerprint = symbol_approval.requirement_fingerprint(db.get(MemorySymbolRequirement, requirement_id))
    with pytest.raises(symbol_approval.ApprovalError):
        symbol_approval.consume_approval(db, request_id=request.id, requirement_fingerprint_value=fingerprint)
    db.close()


def test_list_pending_filters_awaiting_states(monkeypatch) -> None:
    _setup(monkeypatch)
    db = _db()
    case_id, evidence_id, _ = _make_case_evidence_requirement(db)
    symbol_approval.ensure_pending_request(db, case_id=case_id, evidence_id=evidence_id)
    pending = symbol_approval.list_pending_requests(db)
    assert len(pending) == 1
    assert pending[0]["status"] == "awaiting_operator_approval"
    db.close()


def test_show_request_does_not_leak_paths(monkeypatch) -> None:
    _setup(monkeypatch)
    db = _db()
    case_id, evidence_id, _ = _make_case_evidence_requirement(db)
    request = symbol_approval.ensure_pending_request(db, case_id=case_id, evidence_id=evidence_id)
    data = symbol_approval.show_request(db, request.id)
    serialized = str(data)
    # No filesystem paths, evidence bytes, or RAM content.
    assert "/mnt/" not in serialized
    assert "/data/" not in serialized
    assert "evidence_path" not in serialized
    assert "stored_path" not in serialized
    assert "memory-output" not in serialized
    assert "url" not in serialized
    db.close()


def test_summarize_includes_no_ram_transmitted_marker(monkeypatch) -> None:
    _setup(monkeypatch)
    db = _db()
    case_id, evidence_id, _ = _make_case_evidence_requirement(db)
    request = symbol_approval.ensure_pending_request(db, case_id=case_id, evidence_id=evidence_id)
    summary = symbol_approval.summarize_pending_for_operator(db, request.id)
    assert summary["no_ram_transmitted"] is True
    assert "pdb_name" in summary["transmitted_metadata"]
    assert "guid" in summary["transmitted_metadata"]
    assert "age" in summary["transmitted_metadata"]
    db.close()


def test_local_approval_disabled_blocks_approve(monkeypatch) -> None:
    _setup(monkeypatch, local_approval=False)
    db = _db()
    case_id, evidence_id, _ = _make_case_evidence_requirement(db)
    request = symbol_approval.ensure_pending_request(db, case_id=case_id, evidence_id=evidence_id)
    with pytest.raises(symbol_approval.ApprovalError) as exc:
        symbol_approval.approve_request(db, request_id=request.id, confirm=True, yes=True)
    assert exc.value.code == "SYMBOL_LOCAL_APPROVAL_DISABLED"
    db.close()
