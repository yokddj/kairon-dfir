"""Tests for the experimental CLI subcommands.

The CLI exposes two subcommands:

* ``register-experimental-candidate`` — registers a cache
  row as an experimental candidate.  Refused when the
  feature flag is off.
* ``status-experimental`` — returns the trust state.

The tests cover the flag gate and the happy paths.
"""
from __future__ import annotations

import os
import sys

import pytest


os.environ.setdefault("DATABASE_URL", "sqlite:///:memory:")
os.environ.setdefault("REDIS_URL", "redis://localhost:6379/0")
os.environ.setdefault("MEMORY_SYMBOL_EXPERIMENTAL_MISMATCH_ENABLED", "true")


@pytest.fixture
def db_session():
    from sqlalchemy import create_engine
    from sqlalchemy.orm import sessionmaker
    from app.core.database import Base
    import app.models  # noqa: F401

    engine = create_engine("sqlite:///:memory:", future=True)
    Base.metadata.create_all(bind=engine)
    SessionLocal = sessionmaker(
        bind=engine, autoflush=False, autocommit=False, future=True
    )
    import app.core.database as database_module

    original_session = database_module.SessionLocal
    original_engine = database_module.engine
    database_module.SessionLocal = SessionLocal
    database_module.engine = engine
    session = SessionLocal()
    try:
        yield session
    finally:
        session.close()
        database_module.SessionLocal = original_session
        database_module.engine = original_engine
        engine.dispose()


@pytest.fixture
def cli_test_env():
    """Import the CLI module so the tests have a parser."""
    from app.cli import memory_symbols

    return memory_symbols


class TestExperimentalCli:
    def test_register_experimental_candidate_happy_path(
        self, db_session, cli_test_env, monkeypatch
    ):
        from app.models.case import Case
        from app.models.evidence import Evidence, EvidenceType
        from app.models.memory import (
            MemoryCachedSymbol,
            MemorySymbolRequirement,
        )
        from app.services.memory import experimental_lifecycle
        from app.cli import memory_symbols
        import uuid

        case = Case(id=str(uuid.uuid4()), name="t", description="t")
        db_session.add(case)
        db_session.flush()
        evidence = Evidence(
            id=str(uuid.uuid4()),
            case_id=case.id,
            original_filename="t.raw",
            stored_path="staging/t.raw",
            sha256="0" * 64,
            size_bytes=1,
            evidence_type=EvidenceType.memory_dump,
            detection_status="memory",
        )
        db_session.add(evidence)
        db_session.commit()
        requirement = MemorySymbolRequirement(
            id=str(uuid.uuid4()),
            case_id=case.id,
            evidence_id=evidence.id,
            pdb_name="ntkrnlmp.pdb",
            pdb_guid="D801A9AFC0FB7761380800F708633DEA",
            pdb_age=1,
            requested_pdb_age=1,
            age_corrected=False,
            architecture="x64",
            symbol_key="ntkrnlmp.pdb/D801A9AFC0FB7761380800F708633DEA-1",
            status="blocked_symbols",
        )
        cache = MemoryCachedSymbol(
            id=str(uuid.uuid4()),
            symbol_key="ntkrnlmp.pdb/D801A9AFC0FB7761380800F708633DEA-5",
            pdb_name="ntkrnlmp.pdb",
            pdb_guid="D801A9AFC0FB7761380800F708633DEA",
            pdb_age=5,
            architecture="x64",
            pdb_relative_path="cache/x.pdb",
            isf_relative_path="cache/x.json",
            pdb_sha256="0" * 64,
            isf_sha256="0" * 64,
            pdb_size_bytes=1,
            isf_size_bytes=1,
            validation_status="validated",
            source_category="official_microsoft_symbols",
            provenance_source_type="operator_cli_pdb",
            provenance_source_name="Operator CLI",
            provenance_actor="server-operator",
            cache_classification="experimental_candidate",
        )
        db_session.add_all([requirement, cache])
        db_session.commit()
        candidate = experimental_lifecycle.record_cli_candidate(
            db_session,
            case_id=case.id,
            evidence_id=evidence.id,
            cached_symbol_id=cache.id,
            source_host_path="/host/cache/ntkrnlmp.pdb",
            actor="operator",
        )
        assert candidate.required_pdb_age == 1
        assert candidate.observed_pdb_age == 5

    def test_register_experimental_candidate_refused_when_disabled(
        self, monkeypatch, cli_test_env
    ):
        from app.cli import memory_symbols

        monkeypatch.setenv("MEMORY_SYMBOL_EXPERIMENTAL_MISMATCH_ENABLED", "false")
        from app.core.config import get_settings
        get_settings.cache_clear()
        args = memory_symbols.build_parser().parse_args(
            ["register-experimental-candidate", "--case-id", "x", "--evidence-id", "y", "--cached-symbol-id", "z"]
        )
        rc = args.func(args)
        assert rc == 2
        get_settings.cache_clear()

    def test_status_experimental_returns_trust_state(
        self, db_session, cli_test_env
    ):
        from app.models.case import Case
        from app.models.evidence import Evidence, EvidenceType
        from app.cli import memory_symbols
        import uuid

        case = Case(id=str(uuid.uuid4()), name="t", description="t")
        db_session.add(case)
        db_session.flush()
        evidence = Evidence(
            id=str(uuid.uuid4()),
            case_id=case.id,
            original_filename="t.raw",
            stored_path="staging/t.raw",
            sha256="0" * 64,
            size_bytes=1,
            evidence_type=EvidenceType.memory_dump,
            detection_status="memory",
        )
        db_session.add(evidence)
        db_session.commit()
        # The CLI opens its own SessionLocal.  Patch the
        # module-level binding so it uses the test engine.
        from sqlalchemy.orm import sessionmaker
        from app.core.database import engine as test_engine
        TestSessionLocal = sessionmaker(
            bind=test_engine, autoflush=False, autocommit=False, future=True
        )
        original = memory_symbols.SessionLocal
        memory_symbols.SessionLocal = TestSessionLocal
        try:
            args = memory_symbols.build_parser().parse_args(
                ["status-experimental", "--case-id", case.id, "--evidence-id", evidence.id, "--json"]
            )
            rc = args.func(args)
            assert rc == 0
        finally:
            memory_symbols.SessionLocal = original
