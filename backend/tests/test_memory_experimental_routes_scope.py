from __future__ import annotations

import os
import sys
import uuid

import pytest

os.environ.setdefault("DATABASE_URL", "sqlite:///:memory:")
os.environ.setdefault("REDIS_URL", "redis://localhost:6379/0")

_BACKEND = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if _BACKEND not in sys.path:
    sys.path.insert(0, _BACKEND)


@pytest.fixture
def db_session(monkeypatch):
    from sqlalchemy import create_engine
    from sqlalchemy.orm import sessionmaker
    from app.core.database import Base
    import app.models  # noqa: F401
    import app.core.database as database_module

    engine = create_engine("sqlite:///:memory:", future=True)
    Base.metadata.create_all(bind=engine)
    SessionLocal = sessionmaker(bind=engine, autoflush=False, autocommit=False, future=True)
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


def test_warning_and_catalogue_require_valid_case_and_evidence(db_session, monkeypatch):
    from fastapi import HTTPException
    from app.models.case import Case
    from app.models.evidence import Evidence, EvidenceType
    from app.api.routes_memory_experimental import get_experimental_profile_catalogue, get_experimental_warning

    monkeypatch.setenv("MEMORY_SYMBOL_EXPERIMENTAL_MISMATCH_ENABLED", "true")
    from app.core.config import get_settings

    get_settings.cache_clear()
    case = Case(id=str(uuid.uuid4()), name="c", description="d")
    db_session.add(case)
    db_session.flush()
    evidence = Evidence(
        id=str(uuid.uuid4()),
        case_id=case.id,
        original_filename="e.raw",
        stored_path="staging/e.raw",
        sha256="0" * 64,
        size_bytes=10,
        evidence_type=EvidenceType.memory_dump,
        detection_status="memory",
    )
    db_session.add(evidence)
    db_session.commit()

    get_experimental_warning(case.id, evidence.id, db_session)
    get_experimental_profile_catalogue(case.id, evidence.id, db_session)
    with pytest.raises(HTTPException):
        get_experimental_warning(case.id, str(uuid.uuid4()), db_session)
    with pytest.raises(HTTPException):
        get_experimental_profile_catalogue(case.id, str(uuid.uuid4()), db_session)
    get_settings.cache_clear()
