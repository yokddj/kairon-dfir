from __future__ import annotations

import json
import os
import uuid
from pathlib import Path
from types import SimpleNamespace

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from app.cli import memory_upload_maintenance as cli
from app.core.database import Base, utc_now_naive
from app.models.case import Case
from app.models.evidence import Evidence, EvidenceStorageMode, EvidenceType, IngestStatus
from app.models.memory import MemoryUpload
from app.services.memory import upload_sessions


CASE_ID = "aaaaaaaa-2222-4222-8222-222222222222"
OTHER_CASE_ID = "bbbbbbbb-2222-4222-8222-222222222222"


@pytest.fixture()
def db_session():
    engine = create_engine("sqlite:///:memory:", future=True)
    Base.metadata.create_all(bind=engine)
    Session = sessionmaker(bind=engine, autoflush=False, autocommit=False, future=True)
    db = Session()
    db.add(Case(id=CASE_ID, name="Upload maintenance"))
    db.add(Case(id=OTHER_CASE_ID, name="Other"))
    db.commit()
    try:
        yield db
    finally:
        db.close()
        engine.dispose()


@pytest.fixture()
def maintenance_env(tmp_path: Path, db_session, monkeypatch):
    settings = SimpleNamespace(
        backend_data_dir=tmp_path / "data",
        backend_temp_dir=tmp_path / "data" / "tmp",
        memory_upload_staging_path=tmp_path / "data" / "tmp" / "memory-uploads",
        memory_upload_default_concurrency=2,
        memory_upload_max_concurrency=4,
        memory_upload_stale_timeout_seconds=900,
        memory_evidence_shared_gid=os.getgid(),
    )
    settings.memory_upload_staging_path.mkdir(parents=True)
    monkeypatch.setattr(upload_sessions, "get_settings", lambda: settings)
    monkeypatch.setattr(cli, "SessionLocal", lambda: db_session)
    return settings


def _upload(db, *, case_id=CASE_ID, status="cancelled", staging_name: str | None = None, evidence_id: str | None = None, updated_at=None) -> MemoryUpload:
    evidence_id = evidence_id or str(uuid.uuid4())
    item = MemoryUpload(
        id=str(uuid.uuid4()),
        case_id=case_id,
        evidence_id=evidence_id,
        status=status,
        bytes_received=0,
        expected_bytes=16,
        display_name="memory.dmp",
        source_host="WS01",
        extension=".dmp",
        staging_name=staging_name or str(uuid.uuid4()),
        canonical_relative_path=f"evidence/{case_id}/{evidence_id}/original/memory-image.dmp",
        chunk_size_bytes=8,
        total_chunks=2,
        received_chunk_count=0,
        retryable=status not in {"completed", "cancelled"},
        metadata_json={"received_chunks": {}, "active_chunks": [], "upload_mode": "resumable"},
        progress_at=updated_at or utc_now_naive(),
        updated_at=updated_at or utc_now_naive(),
    )
    db.add(item)
    db.commit()
    return item


def _staging(settings, name: str, size: int = 10) -> Path:
    root = settings.memory_upload_staging_path / name
    root.mkdir(parents=True, exist_ok=True)
    (root / "payload.bin").write_bytes(b"x" * size)
    return root


def _completed_evidence(db, upload: MemoryUpload, path: Path) -> Evidence:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(b"evidence")
    ev = Evidence(
        id=upload.evidence_id,
        case_id=upload.case_id,
        original_filename=upload.display_name,
        stored_path=str(path),
        original_path=str(path),
        evidence_type=EvidenceType.memory_dump,
        storage_mode=EvidenceStorageMode.uploaded,
        is_external=False,
        copy_to_storage=True,
        sha256="0" * 64,
        size_bytes=path.stat().st_size,
        ingest_status=IngestStatus.completed,
        metadata_json={},
        path_validation={},
        ingest_source={},
        error_log={},
    )
    db.add(ev)
    db.commit()
    return ev


def test_cleanup_dry_run_performs_no_deletion(db_session, maintenance_env):
    upload = _upload(db_session, status="cancelled")
    root = _staging(maintenance_env, upload.staging_name, size=12)
    code = cli.main(["cleanup", "--dry-run", "--json"])
    assert code == 0
    assert root.exists()


def test_cleanup_apply_deletes_only_eligible_orphan_staging(db_session, maintenance_env):
    orphan = _staging(maintenance_env, "orphan", size=7)
    active = _upload(db_session, status="uploading")
    active_root = _staging(maintenance_env, active.staging_name, size=9)
    code = cli.main(["cleanup", "--apply", "--json"])
    assert code == 0
    assert not orphan.exists()
    assert active_root.exists()


def test_active_locked_upload_is_skipped(db_session, maintenance_env, capsys):
    upload = _upload(db_session, status="uploading")
    upload.metadata_json = {**upload.metadata_json, "active_chunks": [0]}
    db_session.commit()
    _staging(maintenance_env, upload.staging_name, size=5)
    assert cli.main(["cleanup", "--dry-run", "--json"]) == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload["active_sessions_skipped"] == 1


def test_completed_evidence_is_preserved(db_session, maintenance_env):
    upload = _upload(db_session, status="completed")
    root = _staging(maintenance_env, upload.staging_name, size=5)
    evidence_path = maintenance_env.backend_data_dir / upload.canonical_relative_path
    _completed_evidence(db_session, upload, evidence_path)
    assert cli.main(["cleanup", "--apply", "--json"]) == 0
    assert not root.exists()
    assert evidence_path.exists()
    assert db_session.get(Evidence, upload.evidence_id) is not None


def test_reconcile_reports_missing_staging(db_session, maintenance_env, capsys):
    _upload(db_session, status="cancelled")
    assert cli.main(["reconcile", "--dry-run", "--json"]) == 0
    payload = json.loads(capsys.readouterr().out)
    assert any(item["classification"] == "db_session_staging_missing" for item in payload["reconciliation_findings"])


def test_reconcile_reports_db_less_orphan_directory(db_session, maintenance_env, capsys):
    _staging(maintenance_env, "orphan", size=3)
    assert cli.main(["reconcile", "--dry-run", "--json"]) == 0
    payload = json.loads(capsys.readouterr().out)
    assert any(item["classification"] == "staging_exists_db_session_missing" for item in payload["reconciliation_findings"])


def test_cleanup_reports_completed_upload_with_leftover_staging(db_session, maintenance_env, capsys):
    upload = _upload(db_session, status="completed")
    _staging(maintenance_env, upload.staging_name, size=5)
    _completed_evidence(db_session, upload, maintenance_env.backend_data_dir / upload.canonical_relative_path)
    assert cli.main(["cleanup", "--dry-run", "--json"]) == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload["completed_with_staging"] == 1


def test_case_and_upload_filters_work(db_session, maintenance_env, capsys):
    keep = _upload(db_session, case_id=OTHER_CASE_ID, status="cancelled")
    target = _upload(db_session, case_id=CASE_ID, status="cancelled")
    _staging(maintenance_env, keep.staging_name, size=5)
    _staging(maintenance_env, target.staging_name, size=5)
    assert cli.main(["cleanup", "--dry-run", "--case-id", CASE_ID, "--upload-id", target.id, "--json"]) == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload["sessions_inspected"] == 1
    assert payload["bytes_reclaimable"] == 5


def test_older_than_threshold_works(db_session, maintenance_env, capsys):
    old_time = utc_now_naive().replace(year=2020)
    old = _upload(db_session, status="cancelled", updated_at=old_time)
    new = _upload(db_session, status="cancelled")
    _staging(maintenance_env, old.staging_name, size=4)
    _staging(maintenance_env, new.staging_name, size=8)
    assert cli.main(["cleanup", "--dry-run", "--older-than-hours", "24", "--json"]) == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload["bytes_reclaimable"] == 4


def test_repeated_apply_is_idempotent(db_session, maintenance_env, capsys):
    orphan = _staging(maintenance_env, "orphan", size=6)
    assert cli.main(["cleanup", "--apply", "--json"]) == 0
    assert not orphan.exists()
    capsys.readouterr()
    assert cli.main(["cleanup", "--apply", "--json"]) == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload["bytes_removed"] == 0


def test_operational_failure_returns_non_zero(monkeypatch, capsys):
    monkeypatch.setattr(cli, "SessionLocal", lambda: (_ for _ in ()).throw(RuntimeError("db unavailable")))
    assert cli.main(["cleanup", "--dry-run", "--json"]) == 2
    payload = json.loads(capsys.readouterr().out)
    assert payload["errors"]


def test_ambiguous_reconciliation_is_not_auto_repaired(db_session, maintenance_env):
    upload = _upload(db_session, status="cancelled")
    root = _staging(maintenance_env, upload.staging_name, size=5)
    assert cli.main(["reconcile", "--dry-run", "--json"]) == 0
    assert root.exists()


def test_bytes_reclaimable_and_removed_are_correct(db_session, maintenance_env, capsys):
    _staging(maintenance_env, "orphan-a", size=11)
    _staging(maintenance_env, "orphan-b", size=13)
    assert cli.main(["cleanup", "--apply", "--json"]) == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload["bytes_reclaimable"] == 24
    assert payload["bytes_removed"] == 24
