from __future__ import annotations

import hashlib
import os
import shutil
from pathlib import Path
from types import SimpleNamespace

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient
from sqlalchemy import create_engine, inspect, text
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from app.api import routes_evidence_companions
from app.core.database import Base, get_db
from app.core.migrations import run_migrations
from app.models.case import Case
from app.models.evidence import Evidence, EvidenceCompanionFile, EvidenceCustodyEvent, EvidenceCustodyEventType, EvidenceType, IngestStatus
from app.services.memory.companion_files import (
    EvidenceCompanionError,
    StagedCompanionUpload,
    VMWARE_COMPANION_PRECEDENCE,
    attach_vmware_companion,
    companion_target_path,
    delete_evidence_companion,
    get_evidence_companion_status,
    list_evidence_companions,
)


CASE_ID = "aaaaaaaa-1111-4111-8111-111111111111"
EVIDENCE_ID = "bbbbbbbb-2222-4222-8222-222222222222"
OTHER_CASE_ID = "cccccccc-3333-4333-8333-333333333333"
OTHER_EVIDENCE_ID = "dddddddd-4444-4444-8444-444444444444"


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
    item = Case(id=case_id, name="Companion Test Case")
    db.add(item)
    db.commit()
    return item


def _memory_evidence(db, tmp_path: Path, *, case_id: str = CASE_ID, evidence_id: str = EVIDENCE_ID, filename: str = "memory-image.vmem", sha256: str = "a" * 64) -> Evidence:
    original_dir = tmp_path / "evidence" / case_id / evidence_id / "original"
    original_dir.mkdir(parents=True, exist_ok=True)
    primary = original_dir / filename
    primary.write_bytes(b"VMWARE-VMEM-FIXTURE" + os.urandom(64))
    item = Evidence(
        id=evidence_id,
        case_id=case_id,
        original_filename="memory.vmem",
        stored_path=str(primary),
        original_path=str(primary),
        evidence_type=EvidenceType.memory_dump,
        sha256=sha256,
        size_bytes=primary.stat().st_size,
        ingest_status=IngestStatus.completed,
        metadata_json={},
        error_log={},
    )
    db.add(item)
    db.commit()
    return item


def _settings(tmp_path: Path, **overrides) -> SimpleNamespace:
    values = {
        "backend_data_dir": tmp_path,
        "memory_upload_max_bytes": 50 * 1024 * 1024,
        "memory_max_upload_size": 50 * 1024 * 1024,
        "memory_upload_min_free_space_bytes": 0,
        "memory_evidence_shared_gid": os.getgid(),
    }
    values.update(overrides)
    return SimpleNamespace(**values)


def _stage(tmp_path: Path, name: str, content: bytes) -> Path:
    staging = tmp_path / "staging"
    staging.mkdir(parents=True, exist_ok=True)
    path = staging / name
    path.write_bytes(content)
    return path


# --------------------------------------------------------------------------
# Model / migration
# --------------------------------------------------------------------------


def test_evidence_companion_files_table_registered_on_fresh_db(db_session) -> None:
    inspector = inspect(db_session.get_bind())
    assert "evidence_companion_files" in inspector.get_table_names()
    columns = {c["name"] for c in inspector.get_columns("evidence_companion_files")}
    assert {
        "id", "case_id", "evidence_id", "companion_type", "original_filename",
        "internal_filename", "relative_path", "sha256", "size_bytes",
        "source_method", "uploaded_by_user_id", "created_at", "updated_at",
    } <= columns


def test_migration_creates_table_on_existing_db() -> None:
    """Simulates upgrading a real, already-provisioned database (every
    table through migration 38 already exists) by the versioned migration
    runner alone -- not ``Base.metadata.create_all()``, which would just
    create the new table from the current model shape and prove nothing
    about the migration function itself.

    Every migration EXCEPT 39/40 is pre-marked as applied (matching a real
    existing deployment already at every other schema version, including
    ones added after this phase) rather than replayed from a blank
    database: several older migrations contain raw Postgres-only DDL
    (e.g. ``'{}'::jsonb``) that was always meant to run only against a
    database already at that schema version, on Postgres -- replaying
    them against a bare SQLite engine is not a scenario that occurs in
    production and is not what this test is exercising.
    """
    from app.core.migrations import MIGRATIONS, ensure_migrations_table

    engine = create_engine("sqlite:///:memory:", future=True)
    Base.metadata.create_all(bind=engine)
    with engine.begin() as connection:
        connection.execute(text("DROP TABLE evidence_companion_files"))
        ensure_migrations_table(connection)
        for migration in MIGRATIONS:
            if migration.version not in (39, 40):
                connection.execute(
                    text("INSERT INTO schema_migrations (version, name) VALUES (:v, :n)"),
                    {"v": migration.version, "n": migration.name},
                )

    inspector = inspect(engine)
    assert "evidence_companion_files" not in inspector.get_table_names()

    applied_first = run_migrations(engine)
    assert applied_first == [39, 40]
    inspector = inspect(engine)
    assert "evidence_companion_files" in inspector.get_table_names()
    columns = {c["name"] for c in inspector.get_columns("evidence_companion_files")}
    assert {"evidence_id", "companion_type", "internal_filename", "relative_path", "sha256"} <= columns

    # Re-running is a no-op (idempotent), matching every other migration.
    applied_second = run_migrations(engine)
    assert applied_second == []


def test_volatility_precedence_is_vmss_before_vmsn() -> None:
    """Documents (and pins) the precedence verified against the real
    installed volatility3 source (VmwareStacker.stack()): .vmss is tried
    before .vmsn. Phase 1 only ever keeps one active companion, so this
    precedence does not create ambiguity, but the constant must stay
    correct for anyone reading it later."""
    assert VMWARE_COMPANION_PRECEDENCE == ("vmware_vmss", "vmware_vmsn")


# --------------------------------------------------------------------------
# Attach: happy paths
# --------------------------------------------------------------------------


def test_attach_valid_vmsn(db_session, tmp_path: Path) -> None:
    evidence = _memory_evidence(db_session, tmp_path)
    settings = _settings(tmp_path)
    content = b"VMSN-CONTENT" + os.urandom(128)
    staged = _stage(tmp_path, "snapshot.vmsn", content)

    row = attach_vmware_companion(
        db_session,
        evidence,
        StagedCompanionUpload(path=staged, original_filename="snapshot.vmsn"),
        actor_user_id="user-1",
        settings=settings,
    )

    assert row.companion_type == "vmware_vmsn"
    assert row.sha256 == hashlib.sha256(content).hexdigest()
    assert row.size_bytes == len(content)
    target = tmp_path / "evidence" / CASE_ID / EVIDENCE_ID / "original" / "memory-image.vmsn"
    assert target.is_file()
    assert target.read_bytes() == content


def test_attach_valid_vmss(db_session, tmp_path: Path) -> None:
    evidence = _memory_evidence(db_session, tmp_path)
    settings = _settings(tmp_path)
    content = b"VMSS-CONTENT" + os.urandom(128)
    staged = _stage(tmp_path, "snapshot.vmss", content)

    row = attach_vmware_companion(
        db_session,
        evidence,
        StagedCompanionUpload(path=staged, original_filename="snapshot.vmss"),
        settings=settings,
    )

    assert row.companion_type == "vmware_vmss"
    target = tmp_path / "evidence" / CASE_ID / EVIDENCE_ID / "original" / "memory-image.vmss"
    assert target.is_file()


def test_internal_filename_is_exact_basename_swap(db_session, tmp_path: Path) -> None:
    """The single highest-risk regression identified during design review:
    Volatility only discovers a companion whose basename is the primary's
    OWN canonical basename with the extension swapped. Storing it under
    any other name fails silently (exit 0, 0 rows, same warning) with no
    visible error."""
    evidence = _memory_evidence(db_session, tmp_path, filename="memory-image.vmem")
    settings = _settings(tmp_path)
    staged = _stage(tmp_path, "totally-different-name.vmsn", b"content")

    row = attach_vmware_companion(
        db_session,
        evidence,
        StagedCompanionUpload(path=staged, original_filename="totally-different-name.vmsn"),
        settings=settings,
    )

    assert row.internal_filename == "memory-image.vmsn"
    assert row.original_filename != row.internal_filename
    assert row.original_filename == "totally-different-name.vmsn"
    expected = companion_target_path(tmp_path / "evidence" / CASE_ID / EVIDENCE_ID / "original" / "memory-image.vmem", "vmware_vmsn")
    assert Path(settings.backend_data_dir / row.relative_path) == expected


def test_companion_target_path_matches_volatility_suffix_swap() -> None:
    primary = Path("/data/evidence/case/ev/original/memory-image.vmem")
    assert companion_target_path(primary, "vmware_vmss") == Path("/data/evidence/case/ev/original/memory-image.vmss")
    assert companion_target_path(primary, "vmware_vmsn") == Path("/data/evidence/case/ev/original/memory-image.vmsn")


# --------------------------------------------------------------------------
# Attach: rejections
# --------------------------------------------------------------------------


def test_non_memory_evidence_rejected(db_session, tmp_path: Path) -> None:
    evtx_dir = tmp_path / "evidence" / CASE_ID / EVIDENCE_ID / "original"
    evtx_dir.mkdir(parents=True, exist_ok=True)
    evtx_path = evtx_dir / "System.evtx"
    evtx_path.write_bytes(b"evtx")
    _case(db_session)
    evidence = Evidence(
        id=EVIDENCE_ID, case_id=CASE_ID, original_filename="System.evtx",
        stored_path=str(evtx_path), original_path=str(evtx_path),
        evidence_type=EvidenceType.evtx, sha256="b" * 64, size_bytes=4,
        ingest_status=IngestStatus.completed, metadata_json={}, error_log={},
    )
    db_session.add(evidence)
    db_session.commit()
    settings = _settings(tmp_path)
    staged = _stage(tmp_path, "x.vmsn", b"content")

    with pytest.raises(EvidenceCompanionError) as excinfo:
        attach_vmware_companion(db_session, evidence, StagedCompanionUpload(path=staged, original_filename="x.vmsn"), settings=settings)
    assert excinfo.value.code == "EVIDENCE_NOT_MEMORY_DUMP"


def test_primary_not_vmem_rejected(db_session, tmp_path: Path) -> None:
    evidence = _memory_evidence(db_session, tmp_path, filename="memory-image.raw")
    settings = _settings(tmp_path)
    staged = _stage(tmp_path, "x.vmsn", b"content")

    with pytest.raises(EvidenceCompanionError) as excinfo:
        attach_vmware_companion(db_session, evidence, StagedCompanionUpload(path=staged, original_filename="x.vmsn"), settings=settings)
    assert excinfo.value.code == "PRIMARY_NOT_VMEM"


def test_invalid_extension_rejected(db_session, tmp_path: Path) -> None:
    evidence = _memory_evidence(db_session, tmp_path)
    settings = _settings(tmp_path)
    staged = _stage(tmp_path, "notes.txt", b"content")

    with pytest.raises(EvidenceCompanionError) as excinfo:
        attach_vmware_companion(db_session, evidence, StagedCompanionUpload(path=staged, original_filename="notes.txt"), settings=settings)
    assert excinfo.value.code == "UNSUPPORTED_COMPANION_TYPE"


def test_symlink_upload_rejected(db_session, tmp_path: Path) -> None:
    evidence = _memory_evidence(db_session, tmp_path)
    settings = _settings(tmp_path)
    real_target = tmp_path / "outside.vmsn"
    real_target.write_bytes(b"content")
    staging = tmp_path / "staging"
    staging.mkdir(parents=True, exist_ok=True)
    link = staging / "link.vmsn"
    os.symlink(real_target, link)

    with pytest.raises(EvidenceCompanionError) as excinfo:
        attach_vmware_companion(db_session, evidence, StagedCompanionUpload(path=link, original_filename="link.vmsn"), settings=settings)
    assert excinfo.value.code == "COMPANION_UPLOAD_REJECTED"


def test_original_filename_never_used_as_path_component(db_session, tmp_path: Path) -> None:
    """Path traversal regression: a malicious original_filename must never
    influence the on-disk write location -- only the extension is read
    from it, and only for display is it sanitized/stored."""
    evidence = _memory_evidence(db_session, tmp_path)
    settings = _settings(tmp_path)
    staged = _stage(tmp_path, "evil.vmsn", b"content")
    malicious_name = "../../../../etc/passwd.vmsn"

    row = attach_vmware_companion(db_session, evidence, StagedCompanionUpload(path=staged, original_filename=malicious_name), settings=settings)

    assert row.internal_filename == "memory-image.vmsn"
    assert ".." not in row.relative_path
    assert Path(row.relative_path).is_absolute() is False
    target = tmp_path / "evidence" / CASE_ID / EVIDENCE_ID / "original" / "memory-image.vmsn"
    assert target.is_file()
    assert not (tmp_path / "etc").exists()


def test_max_size_rejected(db_session, tmp_path: Path) -> None:
    evidence = _memory_evidence(db_session, tmp_path)
    settings = _settings(tmp_path, memory_upload_max_bytes=8)
    staged = _stage(tmp_path, "big.vmsn", b"0123456789ABCDEF")

    with pytest.raises(EvidenceCompanionError) as excinfo:
        attach_vmware_companion(db_session, evidence, StagedCompanionUpload(path=staged, original_filename="big.vmsn"), settings=settings)
    assert excinfo.value.code == "COMPANION_UPLOAD_TOO_LARGE"


def test_insufficient_disk_space_rejected(db_session, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    evidence = _memory_evidence(db_session, tmp_path)
    settings = _settings(tmp_path, memory_upload_min_free_space_bytes=999_999_999_999)
    staged = _stage(tmp_path, "x.vmsn", b"content")

    with pytest.raises(EvidenceCompanionError) as excinfo:
        attach_vmware_companion(db_session, evidence, StagedCompanionUpload(path=staged, original_filename="x.vmsn"), settings=settings)
    assert excinfo.value.code == "INSUFFICIENT_STORAGE"


def test_companion_matching_primary_hash_rejected(db_session, tmp_path: Path) -> None:
    primary_sha = hashlib.sha256(b"same-bytes").hexdigest()
    evidence = _memory_evidence(db_session, tmp_path, sha256=primary_sha)
    settings = _settings(tmp_path)
    staged = _stage(tmp_path, "same.vmsn", b"same-bytes")

    with pytest.raises(EvidenceCompanionError) as excinfo:
        attach_vmware_companion(db_session, evidence, StagedCompanionUpload(path=staged, original_filename="same.vmsn"), settings=settings)
    assert excinfo.value.code == "COMPANION_MATCHES_PRIMARY"


def test_empty_upload_rejected(db_session, tmp_path: Path) -> None:
    evidence = _memory_evidence(db_session, tmp_path)
    settings = _settings(tmp_path)
    staged = _stage(tmp_path, "empty.vmsn", b"")

    with pytest.raises(EvidenceCompanionError) as excinfo:
        attach_vmware_companion(db_session, evidence, StagedCompanionUpload(path=staged, original_filename="empty.vmsn"), settings=settings)
    assert excinfo.value.code == "COMPANION_UPLOAD_REJECTED"


# --------------------------------------------------------------------------
# Replacement semantics
# --------------------------------------------------------------------------


def test_replace_same_type_overwrites_in_place(db_session, tmp_path: Path) -> None:
    evidence = _memory_evidence(db_session, tmp_path)
    settings = _settings(tmp_path)
    first = attach_vmware_companion(db_session, evidence, StagedCompanionUpload(path=_stage(tmp_path, "a.vmsn", b"first"), original_filename="a.vmsn"), settings=settings)
    second = attach_vmware_companion(db_session, evidence, StagedCompanionUpload(path=_stage(tmp_path, "b.vmsn", b"second-content"), original_filename="b.vmsn"), settings=settings)

    assert first.id == second.id
    assert db_session.query(EvidenceCompanionFile).filter_by(evidence_id=EVIDENCE_ID).count() == 1
    target = tmp_path / "evidence" / CASE_ID / EVIDENCE_ID / "original" / "memory-image.vmsn"
    assert target.read_bytes() == b"second-content"


def test_replace_different_type_removes_stale_higher_precedence_file(db_session, tmp_path: Path) -> None:
    """Safety-critical: replacing a .vmss with a .vmsn MUST delete the old
    .vmss file, or Volatility would keep silently preferring the stale
    .vmss over the newly attached .vmsn forever."""
    evidence = _memory_evidence(db_session, tmp_path)
    settings = _settings(tmp_path)
    attach_vmware_companion(db_session, evidence, StagedCompanionUpload(path=_stage(tmp_path, "a.vmss", b"vmss-bytes"), original_filename="a.vmss"), settings=settings)
    vmss_path = tmp_path / "evidence" / CASE_ID / EVIDENCE_ID / "original" / "memory-image.vmss"
    assert vmss_path.is_file()

    attach_vmware_companion(db_session, evidence, StagedCompanionUpload(path=_stage(tmp_path, "a.vmsn", b"vmsn-bytes"), original_filename="a.vmsn"), settings=settings)

    vmsn_path = tmp_path / "evidence" / CASE_ID / EVIDENCE_ID / "original" / "memory-image.vmsn"
    assert vmsn_path.is_file()
    assert not vmss_path.exists(), "stale .vmss must be removed -- it would otherwise keep winning over the new .vmsn"
    assert db_session.query(EvidenceCompanionFile).filter_by(evidence_id=EVIDENCE_ID).count() == 1
    row = db_session.query(EvidenceCompanionFile).filter_by(evidence_id=EVIDENCE_ID).one()
    assert row.companion_type == "vmware_vmsn"


# --------------------------------------------------------------------------
# Cleanup on failure
# --------------------------------------------------------------------------


def test_cleanup_after_filesystem_error_leaves_no_orphan(db_session, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    evidence = _memory_evidence(db_session, tmp_path)
    settings = _settings(tmp_path)
    staged = _stage(tmp_path, "x.vmsn", b"content")
    original_dir = tmp_path / "evidence" / CASE_ID / EVIDENCE_ID / "original"

    def _boom(*_args, **_kwargs):
        raise OSError("simulated disk failure")

    monkeypatch.setattr(shutil, "copyfileobj", _boom)

    with pytest.raises(OSError):
        attach_vmware_companion(db_session, evidence, StagedCompanionUpload(path=staged, original_filename="x.vmsn"), settings=settings)

    assert db_session.query(EvidenceCompanionFile).count() == 0
    leftovers = [p for p in original_dir.iterdir() if p.name != "memory-image.vmem"]
    assert leftovers == []


def test_cleanup_after_db_error_removes_new_row_file(db_session, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    evidence = _memory_evidence(db_session, tmp_path)
    settings = _settings(tmp_path)
    staged = _stage(tmp_path, "x.vmsn", b"content")

    def _boom(*_args, **_kwargs):
        raise RuntimeError("simulated db failure")

    from app.services.memory import companion_files as companion_module
    monkeypatch.setattr(companion_module, "record_evidence_event", _boom)

    with pytest.raises(RuntimeError):
        attach_vmware_companion(db_session, evidence, StagedCompanionUpload(path=staged, original_filename="x.vmsn"), settings=settings)

    assert db_session.query(EvidenceCompanionFile).count() == 0
    target = tmp_path / "evidence" / CASE_ID / EVIDENCE_ID / "original" / "memory-image.vmsn"
    assert not target.exists()


def test_cleanup_after_db_error_on_replace_restores_previous_bytes(db_session, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """The trickier case: replacing a companion of the SAME type writes
    over the only copy of the previous file's bytes. A DB failure during
    that replace must restore the previous bytes, not just delete the
    file (which would silently destroy the still-DB-recorded companion)."""
    evidence = _memory_evidence(db_session, tmp_path)
    settings = _settings(tmp_path)
    attach_vmware_companion(db_session, evidence, StagedCompanionUpload(path=_stage(tmp_path, "a.vmsn", b"original-bytes"), original_filename="a.vmsn"), settings=settings)
    target = tmp_path / "evidence" / CASE_ID / EVIDENCE_ID / "original" / "memory-image.vmsn"
    assert target.read_bytes() == b"original-bytes"
    original_row = db_session.query(EvidenceCompanionFile).filter_by(evidence_id=EVIDENCE_ID).one()
    original_sha256 = original_row.sha256

    from app.services.memory import companion_files as companion_module

    def _boom(*_args, **_kwargs):
        raise RuntimeError("simulated db failure")

    monkeypatch.setattr(companion_module, "record_evidence_event", _boom)

    with pytest.raises(RuntimeError):
        attach_vmware_companion(db_session, evidence, StagedCompanionUpload(path=_stage(tmp_path, "b.vmsn", b"new-bytes-that-should-not-stick"), original_filename="b.vmsn"), settings=settings)

    db_session.rollback()
    assert target.read_bytes() == b"original-bytes"
    row = db_session.query(EvidenceCompanionFile).filter_by(evidence_id=EVIDENCE_ID).one()
    assert row.sha256 == original_sha256


# --------------------------------------------------------------------------
# Delete
# --------------------------------------------------------------------------


def test_delete_companion_removes_file_row_and_records_custody(db_session, tmp_path: Path) -> None:
    evidence = _memory_evidence(db_session, tmp_path)
    settings = _settings(tmp_path)
    row = attach_vmware_companion(db_session, evidence, StagedCompanionUpload(path=_stage(tmp_path, "a.vmsn", b"content"), original_filename="a.vmsn"), settings=settings)
    target = tmp_path / "evidence" / CASE_ID / EVIDENCE_ID / "original" / "memory-image.vmsn"
    assert target.is_file()

    delete_evidence_companion(db_session, evidence, row.id, actor_user_id="user-1", settings=settings)

    assert not target.exists()
    assert db_session.query(EvidenceCompanionFile).filter_by(id=row.id).one_or_none() is None
    events = db_session.query(EvidenceCustodyEvent).filter_by(evidence_id=EVIDENCE_ID, event_type=EvidenceCustodyEventType.companion_removed).all()
    assert len(events) == 1

    primary = tmp_path / "evidence" / CASE_ID / EVIDENCE_ID / "original" / "memory-image.vmem"
    assert primary.is_file()


def test_delete_unknown_companion_id_raises(db_session, tmp_path: Path) -> None:
    evidence = _memory_evidence(db_session, tmp_path)
    settings = _settings(tmp_path)
    with pytest.raises(EvidenceCompanionError) as excinfo:
        delete_evidence_companion(db_session, evidence, "does-not-exist", settings=settings)
    assert excinfo.value.code == "COMPANION_NOT_FOUND"


def test_delete_never_removes_primary_even_if_row_is_corrupted(db_session, tmp_path: Path) -> None:
    """Defense in depth: even if a companion row's relative_path were
    (through some future bug or direct DB manipulation) made to point at
    the primary evidence file, deletion must refuse rather than delete
    the primary dump."""
    evidence = _memory_evidence(db_session, tmp_path)
    settings = _settings(tmp_path)
    row = attach_vmware_companion(db_session, evidence, StagedCompanionUpload(path=_stage(tmp_path, "a.vmsn", b"content"), original_filename="a.vmsn"), settings=settings)
    row.relative_path = str(Path(evidence.stored_path).relative_to(tmp_path))
    db_session.commit()

    with pytest.raises(EvidenceCompanionError) as excinfo:
        delete_evidence_companion(db_session, evidence, row.id, settings=settings)
    assert excinfo.value.code == "REFUSED_PRIMARY_DELETE"
    assert Path(evidence.stored_path).is_file()


def test_companion_scoped_to_its_own_evidence(db_session, tmp_path: Path) -> None:
    """A companion belonging to evidence A must not be deletable through
    evidence B's scope."""
    _case(db_session, case_id=OTHER_CASE_ID)
    evidence_a = _memory_evidence(db_session, tmp_path, case_id=CASE_ID, evidence_id=EVIDENCE_ID)
    evidence_b = _memory_evidence(db_session, tmp_path, case_id=OTHER_CASE_ID, evidence_id=OTHER_EVIDENCE_ID)
    settings = _settings(tmp_path)
    row = attach_vmware_companion(db_session, evidence_a, StagedCompanionUpload(path=_stage(tmp_path, "a.vmsn", b"content"), original_filename="a.vmsn"), settings=settings)

    with pytest.raises(EvidenceCompanionError) as excinfo:
        delete_evidence_companion(db_session, evidence_b, row.id, settings=settings)
    assert excinfo.value.code == "COMPANION_NOT_FOUND"
    assert db_session.query(EvidenceCompanionFile).filter_by(id=row.id).one_or_none() is not None


# --------------------------------------------------------------------------
# Status service (Phase 2 read surface)
# --------------------------------------------------------------------------


def test_status_reports_no_companion_by_default(db_session, tmp_path: Path) -> None:
    _memory_evidence(db_session, tmp_path)
    status = get_evidence_companion_status(db_session, EVIDENCE_ID)
    assert status == {
        "has_vmware_companion": False,
        "companion_id": None,
        "companion_type": None,
        "original_filename": None,
        "sha256": None,
        "size_bytes": None,
    }


def test_status_reports_attached_companion(db_session, tmp_path: Path) -> None:
    evidence = _memory_evidence(db_session, tmp_path)
    settings = _settings(tmp_path)
    attach_vmware_companion(db_session, evidence, StagedCompanionUpload(path=_stage(tmp_path, "a.vmsn", b"content"), original_filename="a.vmsn"), settings=settings)

    status = get_evidence_companion_status(db_session, EVIDENCE_ID)
    assert status["has_vmware_companion"] is True
    assert status["companion_id"]
    assert status["companion_type"] == "vmware_vmsn"
    assert status["sha256"] == hashlib.sha256(b"content").hexdigest()
    assert status["size_bytes"] == len(b"content")


def test_list_evidence_companions(db_session, tmp_path: Path) -> None:
    evidence = _memory_evidence(db_session, tmp_path)
    settings = _settings(tmp_path)
    assert list_evidence_companions(db_session, EVIDENCE_ID) == []
    attach_vmware_companion(db_session, evidence, StagedCompanionUpload(path=_stage(tmp_path, "a.vmsn", b"content"), original_filename="a.vmsn"), settings=settings)
    companions = list_evidence_companions(db_session, EVIDENCE_ID)
    assert len(companions) == 1
    assert companions[0].companion_type == "vmware_vmsn"


# --------------------------------------------------------------------------
# Provenance
# --------------------------------------------------------------------------


def test_provenance_fields_recorded(db_session, tmp_path: Path) -> None:
    evidence = _memory_evidence(db_session, tmp_path)
    settings = _settings(tmp_path)
    content = b"provenance-content"
    row = attach_vmware_companion(
        db_session,
        evidence,
        StagedCompanionUpload(path=_stage(tmp_path, "operator-supplied-name.vmsn", content), original_filename="operator-supplied-name.vmsn"),
        actor_user_id="analyst-42",
        settings=settings,
    )

    assert row.case_id == CASE_ID
    assert row.evidence_id == EVIDENCE_ID
    assert row.original_filename == "operator-supplied-name.vmsn"
    assert row.internal_filename == "memory-image.vmsn"
    assert row.sha256 == hashlib.sha256(content).hexdigest()
    assert row.size_bytes == len(content)
    assert row.source_method == "manual_upload"
    assert row.uploaded_by_user_id == "analyst-42"
    assert row.created_at is not None

    event = db_session.query(EvidenceCustodyEvent).filter_by(evidence_id=EVIDENCE_ID, event_type=EvidenceCustodyEventType.companion_attached).one()
    assert event.actor_user_id == "analyst-42"
    assert event.details_json["companion_type"] == "vmware_vmsn"
    assert event.details_json["sha256"] == row.sha256


# --------------------------------------------------------------------------
# Restart / persistence (across a fresh DB session against the same DB)
# --------------------------------------------------------------------------


def test_companion_persists_across_new_db_session(tmp_path: Path) -> None:
    engine = create_engine(f"sqlite:///{tmp_path}/persist.db", future=True)
    Base.metadata.create_all(bind=engine)
    Session = sessionmaker(bind=engine, autoflush=False, autocommit=False, future=True)

    settings = _settings(tmp_path)
    db1 = Session()
    try:
        evidence = _memory_evidence(db1, tmp_path)
        attach_vmware_companion(db1, evidence, StagedCompanionUpload(path=_stage(tmp_path, "a.vmsn", b"content"), original_filename="a.vmsn"), settings=settings)
    finally:
        db1.close()

    # Simulates a backend restart: brand new session/connection against
    # the same on-disk database and evidence storage.
    db2 = Session()
    try:
        status = get_evidence_companion_status(db2, EVIDENCE_ID)
        assert status["has_vmware_companion"] is True
        target = tmp_path / "evidence" / CASE_ID / EVIDENCE_ID / "original" / "memory-image.vmsn"
        assert target.is_file()
    finally:
        db2.close()


# --------------------------------------------------------------------------
# API-level scoping (auth + case/evidence ownership)
# --------------------------------------------------------------------------


class _User:
    def __init__(self, user_id: str, is_admin: bool = True) -> None:
        self.id = user_id
        self.is_admin = is_admin


def _api_session():
    """A dedicated StaticPool sqlite engine/session, matching the pattern
    ``test_memory_analysis.py`` already uses for TestClient-backed routes:
    the ASGI transport runs the app in a worker thread, so a plain
    ``sqlite:///:memory:`` session (thread-affine by default) would raise
    "SQLite objects created in a thread can only be used in that same
    thread" the moment a request comes in.
    """
    engine = create_engine(
        "sqlite:///:memory:",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
        future=True,
    )
    Base.metadata.create_all(bind=engine)
    Session = sessionmaker(bind=engine, autoflush=False, autocommit=False, future=True)
    return Session()


def _client(db_session) -> TestClient:
    app = FastAPI()
    app.include_router(routes_evidence_companions.router)
    app.dependency_overrides[get_db] = lambda: db_session
    return TestClient(app)


def test_api_requires_authentication(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """Companion routes require login, matching every other route in the
    app -- Kairon has no per-case access control yet (see docs/roadmap.md),
    so a logged-in user is not additionally scoped to specific cases here."""
    db_session = _api_session()
    _memory_evidence(db_session, tmp_path)

    def _deny(request, db):
        from fastapi import HTTPException
        raise HTTPException(status_code=401, detail="Not authenticated")

    monkeypatch.setattr(routes_evidence_companions, "get_current_user", _deny)
    with _client(db_session) as client:
        response = client.get(f"/api/cases/{CASE_ID}/evidences/{EVIDENCE_ID}/companions")
    assert response.status_code == 401


def test_api_upload_and_list_round_trip(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    db_session = _api_session()
    _case(db_session)
    _memory_evidence(db_session, tmp_path)
    settings = _settings(tmp_path)

    def _allow(request, db):
        return _User("user-1")

    route_staging = tmp_path / "route-staging"
    route_staging.mkdir(parents=True, exist_ok=True)
    monkeypatch.setattr(routes_evidence_companions, "get_current_user", _allow)
    monkeypatch.setattr(routes_evidence_companions, "settings", settings)
    monkeypatch.setattr(routes_evidence_companions, "evidence_staging_dir", lambda case_id, evidence_id: route_staging)
    from app.services.memory import companion_files as companion_module
    monkeypatch.setattr(companion_module, "get_settings", lambda: settings)

    with _client(db_session) as client:
        response = client.post(
            f"/api/cases/{CASE_ID}/evidences/{EVIDENCE_ID}/companions/vmware",
            files={"file": ("snapshot.vmsn", b"api-content", "application/octet-stream")},
        )
        assert response.status_code == 201, response.text
        body = response.json()
        assert body["companion_type"] == "vmware_vmsn"
        assert body["internal_filename"] == "memory-image.vmsn"

        listing = client.get(f"/api/cases/{CASE_ID}/evidences/{EVIDENCE_ID}/companions")
        assert listing.status_code == 200
        assert len(listing.json()) == 1

        delete_response = client.delete(f"/api/cases/{CASE_ID}/evidences/{EVIDENCE_ID}/companions/{body['id']}")
        assert delete_response.status_code == 204
        assert client.get(f"/api/cases/{CASE_ID}/evidences/{EVIDENCE_ID}/companions").json() == []


def test_api_rejects_unsupported_extension_before_touching_service(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    db_session = _api_session()
    _case(db_session)
    _memory_evidence(db_session, tmp_path)

    def _allow(request, db):
        return _User("user-1")

    monkeypatch.setattr(routes_evidence_companions, "get_current_user", _allow)
    with _client(db_session) as client:
        response = client.post(
            f"/api/cases/{CASE_ID}/evidences/{EVIDENCE_ID}/companions/vmware",
            files={"file": ("notes.txt", b"nope", "text/plain")},
        )
    assert response.status_code == 400
    assert response.json()["detail"]["error_code"] == "UNSUPPORTED_COMPANION_TYPE"


def test_api_evidence_not_found_for_wrong_case(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    db_session = _api_session()
    _case(db_session, case_id=OTHER_CASE_ID)
    _memory_evidence(db_session, tmp_path, case_id=CASE_ID, evidence_id=EVIDENCE_ID)

    def _allow(request, db):
        return _User("user-1")

    monkeypatch.setattr(routes_evidence_companions, "get_current_user", _allow)
    with _client(db_session) as client:
        response = client.get(f"/api/cases/{OTHER_CASE_ID}/evidences/{EVIDENCE_ID}/companions")
    assert response.status_code == 404
