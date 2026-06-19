from __future__ import annotations

import hashlib
from datetime import timedelta
from pathlib import Path
from types import SimpleNamespace

import pytest
from sqlalchemy import create_engine
from sqlalchemy import BigInteger
from sqlalchemy.orm import sessionmaker

from app.core.database import Base, utc_now_naive
from app.models.case import Case
from app.models.evidence import Evidence, EvidenceType
from app.models.memory import MemoryScanRun, MemoryUpload
from app.services.memory import upload_lifecycle


CASE_ID = "aaaaaaaa-1111-4111-8111-111111111111"
UPLOAD_ID = "bbbbbbbb-2222-4222-8222-222222222222"


def test_evidence_size_uses_bigint() -> None:
    assert isinstance(Evidence.__table__.c.size_bytes.type, BigInteger)


@pytest.fixture()
def lifecycle(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    engine = create_engine(f"sqlite:///{tmp_path / 'lifecycle.sqlite'}", future=True)
    Base.metadata.create_all(bind=engine)
    Session = sessionmaker(bind=engine, autoflush=False, autocommit=False, future=True)
    settings = SimpleNamespace(
        backend_data_dir=tmp_path / "data",
        backend_temp_dir=tmp_path / "data" / "tmp",
        memory_upload_staging_path=tmp_path / "data" / "tmp" / "memory-uploads",
        memory_upload_stale_timeout_seconds=60,
        memory_plugin_output_max_bytes=10 * 1024 * 1024,
        memory_output_root=None,
        redis_url="redis://unused",
    )
    settings.memory_upload_staging_path.mkdir(parents=True)
    (settings.backend_data_dir / "evidence").mkdir(parents=True)
    monkeypatch.setattr(upload_lifecycle, "SessionLocal", Session)
    monkeypatch.setattr(upload_lifecycle, "get_settings", lambda: settings)
    with Session() as db:
        db.add(Case(id=CASE_ID, name="Memory lifecycle"))
        db.commit()
    return Session, settings


def _upload(Session, *, status: str = "failed", sha256: str | None = None) -> MemoryUpload:
    with Session() as db:
        return upload_lifecycle.create_memory_upload(
            upload_id=UPLOAD_ID,
            case_id=CASE_ID,
            expected_bytes=6,
            display_name="authorized.mem",
            source_host="HOSTA",
            extension=".mem",
            metadata={"authorization_acknowledged": True, "evidence_intent": "raw", "packaging": "single_file"},
            db=db,
        )


def _paths(settings, item: MemoryUpload) -> tuple[Path, Path]:
    return settings.memory_upload_staging_path / item.staging_name, settings.backend_data_dir / item.canonical_relative_path


def test_canonical_exists_without_evidence_reconciles_once_without_second_hash(lifecycle, monkeypatch: pytest.MonkeyPatch) -> None:
    Session, settings = lifecycle
    item = _upload(Session)
    staging, canonical = _paths(settings, item)
    canonical.parent.mkdir(parents=True)
    canonical.write_bytes(b"memory")
    digest = hashlib.sha256(b"memory").hexdigest()
    with Session() as db:
        state = db.get(MemoryUpload, UPLOAD_ID)
        state.status = "failed"
        state.sha256 = digest
        state.bytes_received = 6
        state.retryable = True
        db.commit()
    monkeypatch.setattr(upload_lifecycle, "sha256_file", lambda _path: (_ for _ in ()).throw(AssertionError("must not hash canonical twice")))

    result = upload_lifecycle.reconcile_memory_upload(CASE_ID, UPLOAD_ID)
    again = upload_lifecycle.reconcile_memory_upload(CASE_ID, UPLOAD_ID)

    assert result.status == "completed"
    assert again.status == "completed"
    with Session() as db:
        evidence = db.get(Evidence, item.evidence_id)
        assert evidence is not None and evidence.evidence_type == EvidenceType.memory_dump
        assert db.query(Evidence).count() == 1
        assert db.query(MemoryScanRun).count() == 0
    assert not staging.exists()


def test_complete_staging_finalizes_and_registers_once(lifecycle, monkeypatch: pytest.MonkeyPatch) -> None:
    Session, settings = lifecycle
    item = _upload(Session)
    staging, canonical = _paths(settings, item)
    staging.write_bytes(b"memory")
    with Session() as db:
        state = db.get(MemoryUpload, UPLOAD_ID)
        state.status = "failed"
        state.sha256 = hashlib.sha256(b"memory").hexdigest()
        state.bytes_received = 6
        state.retryable = True
        db.commit()
    monkeypatch.setattr(upload_lifecycle, "assert_memory_upload_capacity", lambda *_args, **_kwargs: None)

    upload_lifecycle.reconcile_memory_upload(CASE_ID, UPLOAD_ID)
    upload_lifecycle.reconcile_memory_upload(CASE_ID, UPLOAD_ID)

    assert not staging.exists()
    assert canonical.read_bytes() == b"memory"
    with Session() as db:
        assert db.query(Evidence).count() == 1


def test_neither_file_marks_upload_lost_and_releases_only_stale_owner(lifecycle, monkeypatch: pytest.MonkeyPatch) -> None:
    Session, _settings = lifecycle
    _upload(Session)
    released: list[str] = []
    monkeypatch.setattr(upload_lifecycle, "release_memory_upload_slot_if_owner", lambda upload_id: released.append(upload_id) or True)
    with Session() as db:
        state = db.get(MemoryUpload, UPLOAD_ID)
        state.status = "finalizing"
        state.progress_at = utc_now_naive() - timedelta(minutes=5)
        db.commit()

    result = upload_lifecycle.reconcile_memory_upload(CASE_ID, UPLOAD_ID)

    assert result.status == "failed"
    assert result.failure_code == "upload_bytes_lost"
    assert result.retryable is False
    assert released == [UPLOAD_ID]


def test_recent_active_upload_is_not_stolen(lifecycle, monkeypatch: pytest.MonkeyPatch) -> None:
    Session, _settings = lifecycle
    _upload(Session)
    monkeypatch.setattr(upload_lifecycle, "release_memory_upload_slot_if_owner", lambda _upload_id: (_ for _ in ()).throw(AssertionError("active owner must not be released")))
    with Session() as db:
        state = db.get(MemoryUpload, UPLOAD_ID)
        state.status = "uploading"
        state.progress_at = utc_now_naive()
        db.commit()

    result = upload_lifecycle.reconcile_memory_upload(CASE_ID, UPLOAD_ID)

    assert result.status == "uploading"


def test_public_status_never_exposes_storage_paths(lifecycle) -> None:
    Session, settings = lifecycle
    _upload(Session)
    with Session() as db:
        payload = upload_lifecycle.public_memory_upload_status(db.get(MemoryUpload, UPLOAD_ID))

    rendered = str(payload)
    assert str(settings.backend_data_dir) not in rendered
    assert "staging_name" not in rendered
    assert "canonical_relative_path" not in rendered
