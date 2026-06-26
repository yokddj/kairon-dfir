"""Tests for the experimental active-result resolver.

The validated active-result resolver never returns experimental
runs.  The experimental active-result resolver never returns
validated runs.  These tests pin the trust filter on both
sides.
"""
from __future__ import annotations

import os

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


def _make_case_evidence(session):
    from app.models.case import Case
    from app.models.evidence import Evidence, EvidenceType
    import uuid

    case = Case(id=str(uuid.uuid4()), name="t", description="t")
    session.add(case)
    session.flush()
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
    session.add(evidence)
    session.commit()
    return case, evidence


class TestActiveResultTrustFilter:
    """The validated resolver must NEVER return experimental runs."""

    def test_validated_resolver_excludes_experimental_runs(self, db_session):
        from app.models.memory import MemoryScanRun
        from app.services.memory.active_result import (
            resolve_active_memory_result,
        )
        import uuid

        case, evidence = _make_case_evidence(db_session)
        experimental = MemoryScanRun(
            id=str(uuid.uuid4()),
            case_id=case.id,
            evidence_id=evidence.id,
            backend="volatility3",
            profile="processes_extended",
            status="completed",
            analysis_mode="experimental",
            trust_level="untrusted",
            symbol_match_type="guid_only_age_mismatch",
        )
        db_session.add(experimental)
        db_session.commit()
        result = resolve_active_memory_result(
            db_session,
            case_id=case.id,
            evidence_id=evidence.id,
            family="processes",
        )
        # The experimental run must not surface in the validated
        # view.
        assert result["active_run"] is None
        assert result["analysis_state"] in {
            "no_runs",
            "no_successful_runs",
            "no_canonical_run",
            "processes_no_canonical_materialization",
            "not_analyzed",
        }

    def test_validated_resolver_returns_validated_runs(self, db_session):
        from app.models.memory import MemoryScanRun
        from app.services.memory.active_result import (
            resolve_active_memory_result,
        )
        import uuid

        case, evidence = _make_case_evidence(db_session)
        validated = MemoryScanRun(
            id=str(uuid.uuid4()),
            case_id=case.id,
            evidence_id=evidence.id,
            backend="volatility3",
            profile="metadata_only",
            status="completed",
            analysis_mode="validated",
            trust_level="validated",
            symbol_match_type="exact",
        )
        db_session.add(validated)
        db_session.commit()
        result = resolve_active_memory_result(
            db_session,
            case_id=case.id,
            evidence_id=evidence.id,
            family="system_info",
        )
        assert result["active_run"] is not None
        assert result["active_run"]["id"] == validated.id

    def test_experimental_resolver_excludes_validated_runs(self, db_session):
        from app.models.memory import MemoryScanRun
        from app.services.memory.experimental_active_result import (
            resolve_experimental_active_result,
        )
        import uuid

        case, evidence = _make_case_evidence(db_session)
        validated = MemoryScanRun(
            id=str(uuid.uuid4()),
            case_id=case.id,
            evidence_id=evidence.id,
            backend="volatility3",
            profile="metadata_only",
            status="completed",
            analysis_mode="validated",
            trust_level="validated",
            symbol_match_type="exact",
        )
        db_session.add(validated)
        db_session.commit()
        # The experimental resolver must refuse to surface the
        # validated run.
        run_id = str(uuid.uuid4())
        result = resolve_experimental_active_result(
            db_session,
            case_id=case.id,
            evidence_id=evidence.id,
            experimental_run_id=run_id,
            family="system_info",
        )
        assert result["active_run"] is None

    def test_experimental_resolver_returns_experimental_runs(self, db_session):
        from app.models.memory import MemoryScanRun
        from app.services.memory.experimental_active_result import (
            resolve_experimental_active_result,
        )
        import uuid

        case, evidence = _make_case_evidence(db_session)
        experimental_run_id = str(uuid.uuid4())
        experimental = MemoryScanRun(
            id=str(uuid.uuid4()),
            case_id=case.id,
            evidence_id=evidence.id,
            backend="volatility3",
            profile="experimental_metadata",
            status="completed",
            analysis_mode="experimental",
            trust_level="untrusted",
            symbol_match_type="guid_only_age_mismatch",
            experimental_run_id=experimental_run_id,
        )
        db_session.add(experimental)
        db_session.commit()
        result = resolve_experimental_active_result(
            db_session,
            case_id=case.id,
            evidence_id=evidence.id,
            experimental_run_id=experimental_run_id,
            family="system_info",
        )
        assert result["active_run"] is not None
        assert result["active_run"]["id"] == experimental.id
        assert result["trust_level"] == "untrusted"

    def test_experimental_resolver_rejects_empty_run_id(self, db_session):
        from app.services.memory.experimental_active_result import (
            resolve_experimental_active_result,
        )

        case, evidence = _make_case_evidence(db_session)
        result = resolve_experimental_active_result(
            db_session,
            case_id=case.id,
            evidence_id=evidence.id,
            experimental_run_id="",
            family="system_info",
        )
        assert result["active_run"] is None
        assert result["analysis_state"] == "experimental_run_id_required"

    def test_filter_cannot_be_overridden(self, db_session):
        from app.services.memory.experimental_active_result import (
            assert_experimental_view_filters,
        )

        # The function refuses client-supplied trust filters.
        with pytest.raises(ValueError):
            assert_experimental_view_filters({"trust_level": "validated"})
        with pytest.raises(ValueError):
            assert_experimental_view_filters({"analysis_mode": "experimental"})
        with pytest.raises(ValueError):
            assert_experimental_view_filters({"experimental_run_id": "x"})
        # None / empty filters pass.
        assert_experimental_view_filters(None)
        assert_experimental_view_filters({})


class TestValidatedAndExperimentalCountsSeparate:
    """Validated and experimental counts must be independent."""

    def test_counts_remain_separate(self, db_session):
        from app.models.memory import MemoryScanRun
        from app.services.memory.active_result import (
            resolve_active_memory_result,
        )
        from app.services.memory.experimental_active_result import (
            resolve_experimental_active_result,
        )
        import uuid

        case, evidence = _make_case_evidence(db_session)
        run_id = str(uuid.uuid4())
        # One validated and one experimental.
        validated = MemoryScanRun(
            id=str(uuid.uuid4()),
            case_id=case.id,
            evidence_id=evidence.id,
            backend="volatility3",
            profile="metadata_only",
            status="completed",
            analysis_mode="validated",
            trust_level="validated",
        )
        experimental = MemoryScanRun(
            id=str(uuid.uuid4()),
            case_id=case.id,
            evidence_id=evidence.id,
            backend="volatility3",
            profile="experimental_metadata",
            status="completed",
            analysis_mode="experimental",
            trust_level="untrusted",
            experimental_run_id=run_id,
        )
        db_session.add_all([validated, experimental])
        db_session.commit()
        validated_result = resolve_active_memory_result(
            db_session,
            case_id=case.id,
            evidence_id=evidence.id,
            family="system_info",
        )
        experimental_result = resolve_experimental_active_result(
            db_session,
            case_id=case.id,
            evidence_id=evidence.id,
            experimental_run_id=run_id,
            family="system_info",
        )
        # Each resolver sees only its own trust domain.
        assert validated_result["active_run"]["id"] == validated.id
        assert experimental_result["active_run"]["id"] == experimental.id
