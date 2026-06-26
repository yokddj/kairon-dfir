from __future__ import annotations

import json
import lzma
import os
import sys
import uuid
from pathlib import Path

import pytest

os.environ.setdefault("DATABASE_URL", "sqlite:///:memory:")
os.environ.setdefault("REDIS_URL", "redis://localhost:6379/0")
os.environ.setdefault("MEMORY_SYMBOL_EXPERIMENTAL_MISMATCH_ENABLED", "true")

_BACKEND = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if _BACKEND not in sys.path:
    sys.path.insert(0, _BACKEND)


@pytest.fixture
def db_session(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    from sqlalchemy import create_engine
    from sqlalchemy.orm import sessionmaker
    from app.core.database import Base
    import app.models  # noqa: F401
    import app.core.database as database_module

    monkeypatch.setenv("KAIRON_CLI_OPERATOR_ROOTS", str(tmp_path))
    monkeypatch.setenv("MEMORY_SYMBOL_EXPERIMENTAL_MISMATCH_ENABLED", "true")
    monkeypatch.setenv("BACKEND_DATA_DIR", str(tmp_path / "data"))
    monkeypatch.setenv("BACKEND_TEMP_DIR", str(tmp_path / "tmp"))
    from app.core.config import get_settings

    get_settings.cache_clear()
    engine = create_engine("sqlite:///:memory:", future=True)
    Base.metadata.create_all(bind=engine)
    SessionLocal = sessionmaker(bind=engine, autoflush=False, autocommit=False, future=True)
    original_session = database_module.SessionLocal
    original_engine = database_module.engine
    database_module.SessionLocal = SessionLocal
    database_module.engine = engine
    session = SessionLocal()
    try:
        yield session, tmp_path
    finally:
        session.close()
        database_module.SessionLocal = original_session
        database_module.engine = original_engine
        engine.dispose()
        get_settings.cache_clear()


def _make_case_evidence_requirement(db_session):
    from app.models.case import Case
    from app.models.evidence import Evidence, EvidenceType
    from app.models.memory import MemorySymbolRequirement

    db, _ = db_session
    case = Case(id=str(uuid.uuid4()), name="t", description="t")
    db.add(case)
    db.flush()
    evidence = Evidence(
        id=str(uuid.uuid4()),
        case_id=case.id,
        original_filename="e.raw",
        stored_path="staging/e.raw",
        sha256="0" * 64,
        size_bytes=1024,
        evidence_type=EvidenceType.memory_dump,
        detection_status="memory",
    )
    db.add(evidence)
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
    db.add(requirement)
    db.commit()
    return case, evidence, requirement


def test_experimental_pdb_import_creates_candidate_and_usable_isf(db_session, monkeypatch: pytest.MonkeyPatch):
    from app.services.memory.experimental_import import cli_import_experimental_pdb_for_requirement, verify_candidate_integrity

    db, tmp_path = db_session
    _, _, requirement = _make_case_evidence_requirement(db_session)
    pdb_path = tmp_path / "ntkrnlmp.pdb"
    pdb_path.write_bytes(b"MSF7")

    monkeypatch.setattr(
        "app.services.memory.experimental_import.read_pdb_identity",
        lambda path: ("D801A9AFC0FB7761380800F708633DEA", 5),
    )

    def _fake_generate_isf(pdb_path, output_path, identity, *, max_bytes):
        payload = {
            "metadata": {"windows": {"pdb": {"GUID": identity.guid, "age": identity.age, "database": identity.pdb_name}, "arch": identity.architecture}},
            "symbols": {},
            "user_types": {},
        }
        output_path.parent.mkdir(parents=True, exist_ok=True)
        with lzma.open(output_path, "wb") as handle:
            handle.write(json.dumps(payload).encode("utf-8"))
        return {"bytes": output_path.stat().st_size, "sha256": "x" * 64}

    monkeypatch.setattr("app.services.memory.experimental_import.generate_isf", _fake_generate_isf)
    result = cli_import_experimental_pdb_for_requirement(
        db,
        requirement_id=requirement.id,
        file_path=pdb_path,
        operator_label="ops@example.com",
        dry_run=False,
    )
    assert result["status"] == "ready"
    candidate = db.get(__import__("app.models.memory", fromlist=["MemoryExperimentalSymbolCandidate"]).MemoryExperimentalSymbolCandidate, result["candidate_id"])
    cache, _, isf_path = verify_candidate_integrity(db, candidate=candidate)
    assert cache.cache_classification == "experimental_candidate"
    assert cache.validation_status == "usable"
    assert isf_path.exists()
    assert candidate.required_pdb_age == 1
    assert candidate.observed_pdb_age == 5


def test_candidate_integrity_rejects_missing_or_changed_files(db_session, monkeypatch: pytest.MonkeyPatch):
    from app.models.memory import MemoryCachedSymbol, MemoryExperimentalSymbolCandidate
    from app.services.memory.experimental_import import ExperimentalImportError, experimental_cache_root, verify_candidate_integrity

    db, tmp_path = db_session
    case, evidence, requirement = _make_case_evidence_requirement(db_session)
    root = experimental_cache_root()
    pdb_rel = Path("pdb") / "ntkrnlmp.pdb" / "GUID-5" / "ntkrnlmp.pdb"
    isf_rel = Path("symbols") / "windows" / "ntkrnlmp.pdb" / "GUID-5.json.xz"
    (root / pdb_rel).parent.mkdir(parents=True, exist_ok=True)
    (root / isf_rel).parent.mkdir(parents=True, exist_ok=True)
    (root / pdb_rel).write_bytes(b"a")
    (root / isf_rel).write_bytes(b"b")
    from app.services.memory.symbol_recovery import hash_file

    cache = MemoryCachedSymbol(
        id=str(uuid.uuid4()),
        symbol_key="ntkrnlmp.pdb/D801A9AFC0FB7761380800F708633DEA-5",
        pdb_name="ntkrnlmp.pdb",
        pdb_guid="D801A9AFC0FB7761380800F708633DEA",
        pdb_age=5,
        architecture="x64",
        pdb_relative_path=str(pdb_rel),
        isf_relative_path=str(isf_rel),
        pdb_sha256=hash_file(root / pdb_rel, max_bytes=1000),
        isf_sha256=hash_file(root / isf_rel, max_bytes=1000),
        pdb_size_bytes=1,
        isf_size_bytes=1,
        validation_status="usable",
        source_category="experimental_operator_import",
        provenance_source_type="operator_cli_experimental_pdb",
        provenance_source_name="Operator CLI experimental PDB import",
        provenance_actor="operator_cli:test",
        cache_classification="experimental_candidate",
        required_pdb_name=requirement.pdb_name,
        required_pdb_guid=requirement.pdb_guid,
        required_pdb_age=requirement.pdb_age,
        required_architecture=requirement.architecture,
    )
    db.add(cache)
    db.flush()
    candidate = MemoryExperimentalSymbolCandidate(
        id=str(uuid.uuid4()),
        case_id=case.id,
        evidence_id=evidence.id,
        requirement_id=requirement.id,
        cached_symbol_id=cache.id,
        required_pdb_name=requirement.pdb_name,
        required_pdb_guid=requirement.pdb_guid,
        required_pdb_age=requirement.pdb_age,
        required_architecture=requirement.architecture,
        observed_pdb_name=cache.pdb_name,
        observed_pdb_guid=cache.pdb_guid,
        observed_pdb_age=cache.pdb_age,
        observed_architecture=cache.architecture,
        symbol_match_type="guid_only_age_mismatch",
        symbol_warning="mismatch",
        provenance_source_type="operator_cli_experimental_pdb",
        provenance_source_name="Operator CLI experimental PDB import",
        provenance_actor="operator_cli:test",
        pdb_sha256=cache.pdb_sha256,
        isf_sha256=cache.isf_sha256,
        isf_validation_status="usable",
        metadata_json={},
    )
    db.add(candidate)
    db.commit()
    verify_candidate_integrity(db, candidate=candidate)
    (root / isf_rel).unlink()
    with pytest.raises(ExperimentalImportError):
        verify_candidate_integrity(db, candidate=candidate)


def test_experimental_import_rejects_exact_age_and_guid_mismatch(db_session, monkeypatch: pytest.MonkeyPatch):
    from app.services.memory.experimental_import import ExperimentalImportError, cli_import_experimental_pdb_for_requirement

    db, tmp_path = db_session
    _, _, requirement = _make_case_evidence_requirement(db_session)
    pdb_path = tmp_path / "ntkrnlmp.pdb"
    pdb_path.write_bytes(b"MSF7")
    monkeypatch.setattr(
        "app.services.memory.experimental_import.read_pdb_identity",
        lambda path: ("D801A9AFC0FB7761380800F708633DEA", 1),
    )
    with pytest.raises(ExperimentalImportError):
        cli_import_experimental_pdb_for_requirement(
            db,
            requirement_id=requirement.id,
            file_path=pdb_path,
            operator_label="ops@example.com",
            dry_run=True,
        )
    monkeypatch.setattr(
        "app.services.memory.experimental_import.read_pdb_identity",
        lambda path: ("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", 5),
    )
    with pytest.raises(ExperimentalImportError):
        cli_import_experimental_pdb_for_requirement(
            db,
            requirement_id=requirement.id,
            file_path=pdb_path,
            operator_label="ops@example.com",
            dry_run=True,
        )


def test_experimental_candidate_never_satisfies_exact_cache_lookup(db_session, monkeypatch: pytest.MonkeyPatch):
    from app.services.memory.experimental_import import cli_import_experimental_pdb_for_requirement
    from app.services.memory.symbol_resolver import symbol_identifier

    db, tmp_path = db_session
    _, _, requirement = _make_case_evidence_requirement(db_session)
    pdb_path = tmp_path / "ntkrnlmp.pdb"
    pdb_path.write_bytes(b"MSF7")
    monkeypatch.setattr(
        "app.services.memory.experimental_import.read_pdb_identity",
        lambda path: ("D801A9AFC0FB7761380800F708633DEA", 5),
    )
    def _fake_generate_isf(pdb_path, output_path, identity, *, max_bytes):
        output_path.write_bytes(
            lzma.compress(
                json.dumps(
                    {
                        "metadata": {"windows": {"pdb": {"GUID": identity.guid, "age": identity.age}}},
                        "symbols": {},
                        "user_types": {},
                    }
                ).encode("utf-8")
            )
        )
        return {"bytes": 1, "sha256": "x" * 64}

    monkeypatch.setattr("app.services.memory.experimental_import.generate_isf", _fake_generate_isf)
    cli_import_experimental_pdb_for_requirement(db, requirement_id=requirement.id, file_path=pdb_path, operator_label="ops", dry_run=False)
    exact = db.query(__import__("app.models.memory", fromlist=["MemoryCachedSymbol"]).MemoryCachedSymbol).filter_by(symbol_key=requirement.symbol_key).first()
    assert exact is None
    observed = db.query(__import__("app.models.memory", fromlist=["MemoryCachedSymbol"]).MemoryCachedSymbol).filter_by(symbol_key=symbol_identifier(requirement.pdb_name, requirement.pdb_guid, 5)).first()
    assert observed is not None
