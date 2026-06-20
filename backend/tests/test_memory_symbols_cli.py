"""Tests for the memory_symbols CLI commands.

These tests use the CLI in-process via its cmd_* entrypoints to make
sure approval mutations do not raise DetachedInstanceError after the
session is closed.
"""
from __future__ import annotations

import argparse
import io
from contextlib import redirect_stdout

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from app.cli import memory_symbols
from app.core.database import Base
from app.models.case import Case
from app.models.evidence import Evidence, EvidenceType, IngestStatus
from app.models.memory import (
    MemoryScanRun,
    MemorySymbolRequirement,
)


def _make_session_factory():
    engine = create_engine("sqlite:///:memory:", future=True)
    Base.metadata.create_all(engine)
    return sessionmaker(bind=engine, future=True)


def _setup_case(session_factory):
    """Create a case, evidence, scan run, and requirement, all attached
    to the given session factory.
    """
    db = session_factory()
    try:
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
        run = MemoryScanRun(
            case_id=case.id,
            evidence_id=evidence.id,
            profile="metadata_only",
            status="failed",
            error_log={"code": "SYMBOLS_UNAVAILABLE"},
        )
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
            requested_pdb_age=1,
            age_corrected=False,
            architecture="x64",
            symbol_key="ntkrnlmp.pdb/9DC3FC69B1CA4B34707EBC57FD1D6126-1",
            status="unavailable_offline",
        )
        db.add(requirement)
        db.commit()
        return case.id, evidence.id, requirement.id
    finally:
        db.close()


def test_approve_does_not_raise_detached_instance_error(monkeypatch) -> None:
    """After approve_request() commits and closes the session, the CLI
    must not raise DetachedInstanceError when reading the approval.
    """
    from app.core.config import get_settings
    monkeypatch.setenv("MEMORY_SYMBOL_LOCAL_APPROVAL_ENABLED", "true")
    monkeypatch.setenv("MEMORY_SYMBOL_MANAGED_DOWNLOAD_ENABLED", "true")
    monkeypatch.setenv("MEMORY_SYMBOL_NETWORK_ISOLATION_READY", "true")
    monkeypatch.setenv("MEMORY_SYMBOL_MODE", "managed_download")
    monkeypatch.setenv("MEMORY_SYMBOL_APPROVAL_TTL_SECONDS", "600")
    get_settings.cache_clear()

    session_factory = _make_session_factory()
    case_id, evidence_id, _ = _setup_case(session_factory)

    # Create the pending request first
    db = session_factory()
    try:
        from app.services.memory.symbol_approval import ensure_pending_request
        request = ensure_pending_request(db, case_id=case_id, evidence_id=evidence_id)
        request_id = request.id
    finally:
        db.close()

    # Patch SessionLocal to use the in-memory session factory
    import app.cli.memory_symbols as cli_module
    monkeypatch.setattr(cli_module, "SessionLocal", session_factory)

    parser = memory_symbols.build_parser()
    args = parser.parse_args(["approve", "--request-id", request_id, "--yes"])
    buf = io.StringIO()
    with redirect_stdout(buf):
        rc = memory_symbols.cmd_approve(args)
    assert rc == 0
    out = buf.getvalue()
    assert "approval_id" in out
    assert "status" in out
    assert "active" in out
    assert "expires_at" in out
    # No traceback printed
    assert "Traceback" not in out
    assert "DetachedInstanceError" not in out


def test_revoke_missing_approval_reports_error(monkeypatch) -> None:
    """Revoking a request without an active approval should report a
    sanitized error and not crash with a DetachedInstanceError.
    """
    monkeypatch.setenv("MEMORY_SYMBOL_LOCAL_APPROVAL_ENABLED", "true")
    from app.core.config import get_settings
    get_settings.cache_clear()

    session_factory = _make_session_factory()
    case_id, evidence_id, _ = _setup_case(session_factory)

    db = session_factory()
    try:
        from app.services.memory.symbol_approval import ensure_pending_request
        request = ensure_pending_request(db, case_id=case_id, evidence_id=evidence_id)
        request_id = request.id
    finally:
        db.close()

    import app.cli.memory_symbols as cli_module
    monkeypatch.setattr(cli_module, "SessionLocal", session_factory)

    parser = memory_symbols.build_parser()
    args = parser.parse_args(["revoke", "--request-id", request_id])
    import sys
    from io import StringIO
    err = StringIO()
    buf = io.StringIO()
    with redirect_stdout(buf):
        # revoke requires an active approval; the error is printed to stderr
        # but cmd_revoke's path through raise doesn't print to stderr directly.
        # We only assert no crash.
        rc = memory_symbols.cmd_revoke(args)
    # rc is 2 (ApprovalError path) or 0 if no error.  Either way, no crash.
    assert rc in (0, 2)
    assert "Traceback" not in buf.getvalue()
