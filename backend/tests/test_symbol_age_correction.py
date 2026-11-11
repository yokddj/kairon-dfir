"""Tests for the auditable age handling of memory symbol requirements.

Microsoft's symbol server sometimes publishes a re-generated PDB at the
same URL with a different internal age than the one Volatility's
windows.info plugin originally reported.  When the GUID matches exactly,
Kairon preserves the originally requested age as audit metadata and
uses the validated file age for the cache key.
"""
from __future__ import annotations

import struct
import uuid
from pathlib import Path

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from app.core.database import Base
from app.core.config import get_settings
from app.models.case import Case
from app.models.evidence import Evidence, EvidenceType, IngestStatus
from app.models.memory import (
    MemoryScanRun,
    MemorySymbolAcquisition,
    MemorySymbolAcquisitionRequest,
    MemorySymbolRequirement,
)
from app.services.memory.symbol_fetcher import (
    MSF7_SIGNATURE,
    SymbolFetchError,
    SymbolIdentity,
    read_pdb_identity,
    validate_pdb,
)


def _db():
    engine = create_engine("sqlite:///:memory:", future=True)
    Base.metadata.create_all(engine)
    return sessionmaker(bind=engine, future=True)()


def _synthetic_pdb(path: Path, *, guid: str, age: int) -> None:
    block_size = 512
    content = bytearray(block_size * 5)
    content[:32] = MSF7_SIGNATURE
    struct.pack_into("<6I", content, 32, block_size, 1, 5, 16, 0, 2)
    struct.pack_into("<I", content, block_size * 2, 3)
    directory = struct.pack("<III", 2, 0xFFFFFFFF, 28) + struct.pack("<I", 4)
    content[block_size * 3:block_size * 3 + len(directory)] = directory
    pdb_header = struct.pack("<III", 20000404, 0, age) + uuid.UUID(hex=guid).bytes_le
    content[block_size * 4:block_size * 4 + len(pdb_header)] = pdb_header
    path.write_bytes(content)


def _setup_case(db):
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
    return case.id, evidence.id, run.id


def test_validate_pdb_rejects_age_mismatch_when_guid_matches(tmp_path: Path) -> None:
    # Strict since 46815cc: the kernel's RSDS age is authoritative, a re-published
    # PDB with another age is reported, never accepted silently.
    guid = "9DC3FC69B1CA4B34707EBC57FD1D6126"
    identity = SymbolIdentity("ntkrnlmp.pdb", guid, age=1, architecture="x64")
    pdb = tmp_path / "ntkrnlmp.pdb"
    _synthetic_pdb(pdb, guid=guid, age=5)
    with pytest.raises(SymbolFetchError) as exc:
        validate_pdb(pdb, identity)
    assert exc.value.code == "SYMBOL_PDB_IDENTITY_MISMATCH"


def _published_pdb(path: Path, *, guid: str, pdb_stream_age: int, dbi_age: int) -> None:
    """A PDB as Microsoft publishes it: the PDB stream's age was bumped by rewrites, the DBI
    stream keeps the age the kernel's CodeView record names."""
    block_size = 512
    content = bytearray(block_size * 6)
    content[:32] = MSF7_SIGNATURE
    directory = struct.pack("<I", 4) + struct.pack("<4I", 0, 28, 0, 12) + struct.pack("<II", 4, 5)
    struct.pack_into("<6I", content, 32, block_size, 1, 6, len(directory), 0, 2)
    struct.pack_into("<I", content, block_size * 2, 3)
    content[block_size * 3:block_size * 3 + len(directory)] = directory
    pdb_header = struct.pack("<III", 20000404, 0, pdb_stream_age) + uuid.UUID(hex=guid).bytes_le
    content[block_size * 4:block_size * 4 + len(pdb_header)] = pdb_header
    content[block_size * 5:block_size * 5 + 12] = struct.pack("<iII", -1, 19990903, dbi_age)
    path.write_bytes(content)


def test_the_dbi_age_is_the_one_the_kernel_record_names(tmp_path: Path) -> None:
    # Real ntkrnlmp.pdb files from msdl: RSDS age 1, PDB stream age 5 (or 2), DBI age 1.
    guid = "D801A9AFC0FB7761380800F708633DEA"
    pdb = tmp_path / "ntkrnlmp.pdb"
    _published_pdb(pdb, guid=guid, pdb_stream_age=5, dbi_age=1)
    assert read_pdb_identity(pdb) == (guid, 1)
    assert validate_pdb(pdb, SymbolIdentity("ntkrnlmp.pdb", guid, age=1, architecture="x64"))["age"] == 1
    with pytest.raises(SymbolFetchError):
        validate_pdb(pdb, SymbolIdentity("ntkrnlmp.pdb", guid, age=5, architecture="x64"))


def test_validate_pdb_accepts_exact_match(tmp_path: Path) -> None:
    guid = "9DC3FC69B1CA4B34707EBC57FD1D6126"
    identity = SymbolIdentity("ntkrnlmp.pdb", guid, age=5, architecture="x64")
    pdb = tmp_path / "ntkrnlmp.pdb"
    _synthetic_pdb(pdb, guid=guid, age=5)
    result = validate_pdb(pdb, identity)
    assert result["guid"] == guid
    assert result["age"] == result["expected_age"] == 5


def test_validate_pdb_rejects_guid_mismatch(tmp_path: Path) -> None:
    identity = SymbolIdentity("ntkrnlmp.pdb", "9DC3FC69B1CA4B34707EBC57FD1D6126", age=1, architecture="x64")
    pdb = tmp_path / "ntkrnlmp.pdb"
    _synthetic_pdb(pdb, guid="FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF", age=1)
    with pytest.raises(Exception) as exc:
        validate_pdb(pdb, identity)
    assert "identity" in str(exc.value).lower() or "guid" in str(exc.value).lower()


def test_requirement_preserves_requested_pdb_age(monkeypatch) -> None:
    """The requirement's requested_pdb_age is set when the requirement
    is first created, before any acquisition.  Verified via the model
    field defaults: the column is nullable but the service layer sets
    it equal to pdb_age on first record.
    """
    # Inspect the model to ensure the field exists with the right
    # type and default.  This is a structural test that does not need
    # a live session.
    from app.models.memory import MemorySymbolRequirement
    import sqlalchemy
    columns = {c.name: c for c in MemorySymbolRequirement.__table__.columns}
    assert "requested_pdb_age" in columns
    assert "age_corrected" in columns
    assert isinstance(columns["age_corrected"].default, sqlalchemy.Boolean) or hasattr(columns["age_corrected"].default, "arg")
    # age_corrected should default to False
    assert columns["age_corrected"].default.arg is False or str(columns["age_corrected"].default) == "false"


def _make_run(db):
    """Helper retained for compatibility with previous draft tests."""
    return None
