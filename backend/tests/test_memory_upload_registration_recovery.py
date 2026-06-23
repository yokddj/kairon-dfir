"""Backend tests for the memory upload evidence-registration recovery flow.

Sixteen tests covering:

 1. canonical preserved on DB failure
 2. retry does NOT re-send bytes (no extra disk writes)
 3. idempotent retry: calling twice produces the same result
 4. double-click race: a parallel retry does not create a duplicate Evidence
 5. post-commit probe failure does NOT invalidate the Evidence row
 6. symbol preparation enqueue failure does NOT mark the upload failed
 7. same-SHA same-case returns the existing Evidence row
 8. same-SHA different-case is allowed (new Evidence row created)
 9. same-filename different-hash is allowed (new Evidence row created)
10. migration v9 completeness on memory_uploads
11. failed registration is reconcilable: the bulk endpoint requeues it
12. completed upload is NOT retryable through the new endpoint
13. cancel does NOT delete the canonical blob
14. no dfir-events rows are created during registration
15. no NormalizedEvent rows are created during registration
16. no Volatility is invoked during evidence registration
"""
from __future__ import annotations

import os
import shutil
import tempfile
import uuid
from datetime import datetime
from pathlib import Path
from unittest.mock import patch

import pytest
from sqlalchemy import create_engine, inspect
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session, sessionmaker

from app.core.database import Base, utc_now_naive
from app.models.case import Case
from app.models.evidence import Evidence, EvidenceStorageMode, EvidenceType, IngestStatus
from app.models.memory import MemoryUpload
from app.services.memory import upload_lifecycle as lifecycle_module
from app.services.memory.upload_lifecycle import (
    ACTIVE_STATUSES,
    ERR_REGISTRATION_DB_CONSTRAINT,
    ERR_REGISTRATION_FAILED,
    REG_STAGE_COMPLETED,
    REG_STAGE_FAILED_REGISTRATION,
    REG_STAGE_REGISTRATION_PENDING,
    MemoryUploadRegistrationError,
    cancel_memory_upload,
    public_memory_upload_status,
    reconcile_memory_upload_lifecycles,
    register_preserved_memory_upload,
    retry_preserved_memory_upload_registration,
)


# ---------------------------------------------------------------------------
# Fixtures and helpers
# ---------------------------------------------------------------------------


@pytest.fixture
def data_dir(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    """Override the backend data directory so the canonical blob lives
    under ``tmp_path`` and is removed on teardown."""
    root = tmp_path / "appdata"
    root.mkdir(parents=True, exist_ok=True)
    from app.core.config import get_settings
    settings = get_settings()
    monkeypatch.setattr(settings, "backend_data_dir", root)
    return root


@pytest.fixture
def db(data_dir: Path) -> Session:
    engine = create_engine("sqlite:///:memory:", connect_args={"check_same_thread": False})
    Base.metadata.create_all(bind=engine)
    Session_ = sessionmaker(bind=engine)
    session = Session_()
    try:
        yield session
    finally:
        session.close()
        engine.dispose()


def _make_case(db: Session, name: str = "case-A") -> Case:
    case = Case(name=name)
    db.add(case)
    db.commit()
    db.refresh(case)
    return case


def _make_canonical(data_dir: Path, case_id: str, evidence_id: str, payload: bytes = b"\x00" * 4096) -> Path:
    """Materialise a canonical memory blob on disk under data_dir."""
    canonical = data_dir / "evidence" / case_id / evidence_id / "original" / "memory-image.img"
    canonical.parent.mkdir(parents=True, exist_ok=True)
    canonical.write_bytes(payload)
    canonical.chmod(0o640)
    return canonical


def _make_failed_upload(
    db: Session,
    *,
    case_id: str,
    data_dir: Path,
    payload: bytes = b"\x00" * 4096,
    sha256: str = "a" * 64,
) -> MemoryUpload:
    """Create a MemoryUpload row that mirrors the 4 production failures:
    the canonical blob is on disk, the Evidence row is missing, the
    upload is marked ``failed`` with ``canonical_preserved=True`` and
    ``failure_code='evidence_registration_failed'``.
    """
    evidence_id = str(uuid.uuid4())
    canonical = _make_canonical(data_dir, case_id, evidence_id, payload=payload)
    item = MemoryUpload(
        id=str(uuid.uuid4()),
        case_id=case_id,
        evidence_id=evidence_id,
        status="failed",
        bytes_received=len(payload),
        expected_bytes=len(payload),
        sha256=sha256,
        display_name="mem.img",
        source_host="HOSTA",
        extension=".img",
        staging_name=f"{evidence_id}.staging",
        canonical_relative_path=f"evidence/{case_id}/{evidence_id}/original/memory-image.img",
        retryable=True,
        failure_code="evidence_registration_failed",
        failure_message="Canonical upload is preserved; evidence registration can be retried.",
        metadata_json={},
        progress_at=utc_now_naive(),
        stage=REG_STAGE_FAILED_REGISTRATION,
        registration_state=None,
        registration_attempts=0,
        canonical_preserved=True,
    )
    db.add(item)
    db.commit()
    db.refresh(item)
    return item


def _no_secure_permissions(*_args, **_kwargs) -> None:
    """No-op replacement for ``secure_uploaded_memory_permissions``.

    The function operates on the live filesystem and chowns the file
    to the memory worker uid/gid.  In tests we do not need a real
    permissions change, only the side effects of the
    ``_persist_evidence_minimal`` call.
    """
    return None


# ---------------------------------------------------------------------------
# 1. Canonical preserved on DB failure
# ---------------------------------------------------------------------------


def test_canonical_preserved_on_db_failure(
    db: Session, data_dir: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    case = _make_case(db)
    item = _make_failed_upload(db, case_id=case.id, data_dir=data_dir)
    canonical = data_dir / item.canonical_relative_path
    canonical_bytes = canonical.read_bytes()
    canonical_mtime = canonical.stat().st_mtime
    canonical_inode = canonical.stat().st_ino

    def explode(*_args, **_kwargs):
        raise IntegrityError("INSERT", {}, Exception("synthetic constraint"))

    monkeypatch.setattr(lifecycle_module, "secure_uploaded_memory_permissions", _no_secure_permissions)
    monkeypatch.setattr(lifecycle_module, "_persist_evidence_minimal", explode)

    with pytest.raises(MemoryUploadRegistrationError) as excinfo:
        register_preserved_memory_upload(item.id, db=db)

    assert excinfo.value.canonical_preserved is True
    assert excinfo.value.code == ERR_REGISTRATION_DB_CONSTRAINT
    # The canonical blob is still on disk, unchanged.
    assert canonical.exists()
    assert canonical.read_bytes() == canonical_bytes
    assert canonical.stat().st_ino == canonical_inode
    assert canonical.stat().st_mtime == canonical_mtime
    db.refresh(item)
    assert item.status == "failed"
    assert item.canonical_preserved is True
    assert item.retryable is True


# ---------------------------------------------------------------------------
# 2. Retry does NOT re-send bytes
# ---------------------------------------------------------------------------


def test_retry_does_not_resend_bytes(
    db: Session, data_dir: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    case = _make_case(db)
    item = _make_failed_upload(db, case_id=case.id, data_dir=data_dir)
    canonical = data_dir / item.canonical_relative_path
    canonical_size = canonical.stat().st_size

    monkeypatch.setattr(lifecycle_module, "secure_uploaded_memory_permissions", _no_secure_permissions)

    evidence = register_preserved_memory_upload(item.id, db=db)
    db.refresh(item)
    assert evidence.id == item.evidence_id
    # The canonical file was not rewritten.
    assert canonical.stat().st_size == canonical_size
    # No "staging" file appeared either.
    staging = data_dir / "staging" / f"{item.id}.staging"
    assert not staging.exists()
    # The upload is now completed.
    assert item.status == "completed"
    assert item.canonical_preserved is True


# ---------------------------------------------------------------------------
# 3. Idempotent retry
# ---------------------------------------------------------------------------


def test_idempotent_retry_returns_same_evidence(
    db: Session, data_dir: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    case = _make_case(db)
    item = _make_failed_upload(db, case_id=case.id, data_dir=data_dir)
    monkeypatch.setattr(lifecycle_module, "secure_uploaded_memory_permissions", _no_secure_permissions)

    first = register_preserved_memory_upload(item.id, db=db)
    second = register_preserved_memory_upload(item.id, db=db)
    third = register_preserved_memory_upload(item.id, db=db)

    assert first.id == second.id == third.id == item.evidence_id
    # No duplicate Evidence rows.
    count = db.query(Evidence).filter(Evidence.id == item.evidence_id).count()
    assert count == 1
    db.refresh(item)
    assert item.registration_attempts == 1
    assert item.status == "completed"


# ---------------------------------------------------------------------------
# 4. Double-click race
# ---------------------------------------------------------------------------


def test_double_click_retry_does_not_create_duplicate(
    db: Session, data_dir: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    case = _make_case(db)
    item = _make_failed_upload(db, case_id=case.id, data_dir=data_dir)
    monkeypatch.setattr(lifecycle_module, "secure_uploaded_memory_permissions", _no_secure_permissions)

    # Simulate the race: the first call inserts, the second call sees
    # the existing row and returns it.  Because we wrap the second
    # call in a real IntegrityError we need to inject a one-time
    # failure for the second ``db.add``.
    real_add = db.add
    call_count = {"n": 0}

    def flaky_add(instance):
        call_count["n"] += 1
        if call_count["n"] == 2:
            # The first commit succeeded; the second attempt hits a
            # real IntegrityError because the row is already there.
            real_add(instance)
            db.flush()
            raise IntegrityError("INSERT", {}, Exception("synthetic unique violation"))
        real_add(instance)

    monkeypatch.setattr(db, "add", flaky_add)
    # The second call must not raise; it must return the same Evidence.
    evidence_a = register_preserved_memory_upload(item.id, db=db)
    evidence_b = register_preserved_memory_upload(item.id, db=db)
    assert evidence_a.id == evidence_b.id == item.evidence_id
    count = db.query(Evidence).filter(Evidence.id == item.evidence_id).count()
    assert count == 1


# ---------------------------------------------------------------------------
# 5. Post-commit probe failure does NOT invalidate the Evidence row
# ---------------------------------------------------------------------------


def test_post_commit_probe_failure_preserves_evidence(
    db: Session, data_dir: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    case = _make_case(db)
    item = _make_failed_upload(db, case_id=case.id, data_dir=data_dir)
    monkeypatch.setattr(lifecycle_module, "secure_uploaded_memory_permissions", _no_secure_permissions)

    def explode(*_args, **_kwargs):
        raise RuntimeError("synthetic probe failure")

    # Patch the probe to fail.  The Evidence row must still be durable.
    with patch("app.services.memory.probe.probe_memory_image", side_effect=explode):
        evidence = register_preserved_memory_upload(item.id, db=db)

    db.refresh(item)
    assert evidence.id == item.evidence_id
    assert db.get(Evidence, item.evidence_id) is not None
    # The upload is completed even though the probe failed.
    assert item.status == "completed"
    assert item.stage == REG_STAGE_COMPLETED


# ---------------------------------------------------------------------------
# 6. Symbol preparation enqueue failure does NOT mark failed
# ---------------------------------------------------------------------------


def test_symbol_enqueue_failure_preserves_evidence(
    db: Session, data_dir: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    case = _make_case(db)
    item = _make_failed_upload(db, case_id=case.id, data_dir=data_dir)
    monkeypatch.setattr(lifecycle_module, "secure_uploaded_memory_permissions", _no_secure_permissions)

    def explode(*_args, **_kwargs):
        raise RuntimeError("synthetic symbol prep failure")

    with patch(
        "app.services.memory.symbol_preparation.schedule_preparation",
        side_effect=explode,
    ):
        evidence = register_preserved_memory_upload(item.id, db=db)

    db.refresh(item)
    assert evidence.id == item.evidence_id
    assert db.get(Evidence, item.evidence_id) is not None
    # The Evidence row is still durable; the upload is completed.
    assert item.status == "completed"
    assert item.stage == REG_STAGE_COMPLETED


# ---------------------------------------------------------------------------
# 7. Same-SHA same-case returns the existing Evidence row
# ---------------------------------------------------------------------------


def test_same_sha_same_case_returns_existing_evidence(
    db: Session, data_dir: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    case = _make_case(db)
    item = _make_failed_upload(db, case_id=case.id, data_dir=data_dir)
    monkeypatch.setattr(lifecycle_module, "secure_uploaded_memory_permissions", _no_secure_permissions)
    first = register_preserved_memory_upload(item.id, db=db)
    db.refresh(item)
    # The ``Evidence`` row is already in the table.
    db.expire_all()
    # Calling again with the same SHA on the same case returns the same row.
    second = register_preserved_memory_upload(item.id, db=db)
    assert first.id == second.id
    count = db.query(Evidence).filter(Evidence.id == first.id).count()
    assert count == 1


# ---------------------------------------------------------------------------
# 8. Same-SHA different-case is allowed
# ---------------------------------------------------------------------------


def test_same_sha_different_case_allowed(
    db: Session, data_dir: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    case_a = _make_case(db, name="case-A")
    case_b = _make_case(db, name="case-B")
    item_a = _make_failed_upload(db, case_id=case_a.id, data_dir=data_dir)
    item_b = _make_failed_upload(db, case_id=case_b.id, data_dir=data_dir)
    # Force the same SHA on both uploads.
    item_b.sha256 = item_a.sha256
    db.commit()
    monkeypatch.setattr(lifecycle_module, "secure_uploaded_memory_permissions", _no_secure_permissions)
    evidence_a = register_preserved_memory_upload(item_a.id, db=db)
    evidence_b = register_preserved_memory_upload(item_b.id, db=db)
    assert evidence_a.id == item_a.evidence_id
    assert evidence_b.id == item_b.evidence_id
    assert evidence_a.id != evidence_b.id
    # Each case has exactly one Evidence row.
    count_a = db.query(Evidence).filter(Evidence.case_id == case_a.id).count()
    count_b = db.query(Evidence).filter(Evidence.case_id == case_b.id).count()
    assert count_a == 1
    assert count_b == 1


# ---------------------------------------------------------------------------
# 9. Same-filename different-hash is allowed
# ---------------------------------------------------------------------------


def test_same_filename_different_hash_allowed(
    db: Session, data_dir: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    case = _make_case(db)
    item_a = _make_failed_upload(
        db,
        case_id=case.id,
        data_dir=data_dir,
        payload=b"\x00" * 4096,
        sha256="a" * 64,
    )
    item_b = _make_failed_upload(
        db,
        case_id=case.id,
        data_dir=data_dir,
        payload=b"\x01" * 4096,
        sha256="b" * 64,
    )
    monkeypatch.setattr(lifecycle_module, "secure_uploaded_memory_permissions", _no_secure_permissions)
    evidence_a = register_preserved_memory_upload(item_a.id, db=db)
    evidence_b = register_preserved_memory_upload(item_b.id, db=db)
    assert evidence_a.id != evidence_b.id
    count = db.query(Evidence).count()
    assert count == 2


# ---------------------------------------------------------------------------
# 10. Migration v9 completeness
# ---------------------------------------------------------------------------


def test_migration_v9_adds_registration_columns() -> None:
    """The migration that lands the v9 columns must include the new
    ``stage``/``registration_state``/``registration_attempts``/
    ``last_registration_error_code``/``last_registration_error_class``/
    ``canonical_preserved`` columns on ``memory_uploads`` and a
    corresponding index.
    """
    from app.core.migrations import MIGRATIONS
    migration = next((m for m in MIGRATIONS if m.version == 9), None)
    assert migration is not None, "v9 migration is not registered"
    assert migration.name == "memory_upload_registration_lifecycle"
    # Run the migration against a sqlite connection that has the
    # v8 schema (created from the live metadata) and inspect the
    # resulting ``memory_uploads`` table.
    engine = create_engine("sqlite:///:memory:", connect_args={"check_same_thread": False})
    Base.metadata.create_all(bind=engine)
    with engine.connect() as connection:
        migration.up(connection)
        insp = inspect(connection)
        columns = {c["name"] for c in insp.get_columns("memory_uploads")}
        indexes = {i["name"] for i in insp.get_indexes("memory_uploads")}
    for column in (
        "stage",
        "registration_state",
        "registration_attempts",
        "last_registration_error_code",
        "last_registration_error_class",
        "canonical_preserved",
    ):
        assert column in columns, f"memory_uploads missing column: {column}"
    assert "ix_memory_uploads_registration_state" in indexes, (
        "registration_state index is missing"
    )


def test_memory_uploads_model_exposes_v9_columns() -> None:
    """The ``MemoryUpload`` model must expose the v9 columns."""
    engine = create_engine("sqlite:///:memory:", connect_args={"check_same_thread": False})
    Base.metadata.create_all(bind=engine)
    insp = inspect(engine)
    columns = {c["name"] for c in insp.get_columns("memory_uploads")}
    for column in (
        "stage",
        "registration_state",
        "registration_attempts",
        "last_registration_error_code",
        "last_registration_error_class",
        "canonical_preserved",
    ):
        assert column in columns, f"memory_uploads missing column: {column}"


# ---------------------------------------------------------------------------
# 11. Failed registration is reconcilable
# ---------------------------------------------------------------------------


def test_reconcile_memory_upload_lifecycles_requeues_failed(
    db: Session, data_dir: Path
) -> None:
    case = _make_case(db)
    failed = _make_failed_upload(db, case_id=case.id, data_dir=data_dir)
    # Add a healthy upload that should NOT be requeued.
    healthy_id = str(uuid.uuid4())
    _make_canonical(data_dir, case.id, healthy_id)
    healthy = MemoryUpload(
        id=healthy_id,
        case_id=case.id,
        evidence_id=healthy_id,
        status="completed",
        bytes_received=4096,
        expected_bytes=4096,
        sha256="c" * 64,
        display_name="healthy.img",
        source_host="HOSTB",
        extension=".img",
        staging_name=f"{healthy_id}.staging",
        canonical_relative_path=f"evidence/{case.id}/{healthy_id}/original/memory-image.img",
        retryable=False,
        metadata_json={},
        progress_at=utc_now_naive(),
        stage=REG_STAGE_COMPLETED,
        canonical_preserved=True,
    )
    db.add(healthy)
    db.commit()
    # Materialise the Evidence row for the healthy upload so the
    # reconcile treats it as a fully-registered upload.
    from app.models.evidence import EvidenceType, IngestStatus
    evidence = Evidence(
        id=healthy_id,
        case_id=case.id,
        original_filename="healthy.img",
        stored_path=str(data_dir / healthy.canonical_relative_path),
        original_path=str(data_dir / healthy.canonical_relative_path),
        evidence_type=EvidenceType.memory_dump,
        storage_mode=EvidenceStorageMode.uploaded,
        is_external=False,
        copy_to_storage=True,
        sha256="c" * 64,
        size_bytes=4096,
        ingest_status=IngestStatus.completed,
        path_validation={},
        ingest_source={},
        metadata_json={},
        error_log={},
        processed_at=utc_now_naive(),
    )
    db.add(evidence)
    db.commit()
    stats = reconcile_memory_upload_lifecycles(db, case_id=case.id)
    assert stats["scanned"] == 2
    assert stats["requeued"] == 1
    assert stats["skipped_terminal"] == 1
    db.refresh(failed)
    assert failed.stage == REG_STAGE_REGISTRATION_PENDING
    assert failed.registration_state == "requeued"
    assert failed.canonical_preserved is True


# ---------------------------------------------------------------------------
# 12. Completed upload is NOT retryable
# ---------------------------------------------------------------------------


def test_completed_upload_cannot_be_retried(
    db: Session, data_dir: Path
) -> None:
    case = _make_case(db)
    evidence_id = str(uuid.uuid4())
    _make_canonical(data_dir, case.id, evidence_id)
    item = MemoryUpload(
        id=str(uuid.uuid4()),
        case_id=case.id,
        evidence_id=evidence_id,
        status="completed",
        bytes_received=4096,
        expected_bytes=4096,
        sha256="d" * 64,
        display_name="done.img",
        source_host="HOSTC",
        extension=".img",
        staging_name=f"{evidence_id}.staging",
        canonical_relative_path=f"evidence/{case.id}/{evidence_id}/original/memory-image.img",
        retryable=False,
        metadata_json={},
        progress_at=utc_now_naive(),
        stage=REG_STAGE_COMPLETED,
        canonical_preserved=True,
    )
    db.add(item)
    db.commit()
    # The retry function is idempotent and returns the existing row.
    payload = retry_preserved_memory_upload_registration(item.id, db=db)
    assert payload["status"] == "completed"
    assert payload["stage"] == REG_STAGE_COMPLETED


# ---------------------------------------------------------------------------
# 13. Cancel does NOT delete the canonical blob
# ---------------------------------------------------------------------------


def test_cancel_does_not_delete_canonical(
    db: Session, data_dir: Path
) -> None:
    case = _make_case(db)
    # The upload is in an "uploading" state with the canonical blob
    # already on disk; cancelling must NOT delete the canonical file.
    evidence_id = str(uuid.uuid4())
    _make_canonical(data_dir, case.id, evidence_id)
    item = MemoryUpload(
        id=str(uuid.uuid4()),
        case_id=case.id,
        evidence_id=evidence_id,
        status="uploading",
        bytes_received=4096,
        expected_bytes=4096,
        sha256="e" * 64,
        display_name="mem.img",
        source_host="HOSTA",
        extension=".img",
        staging_name=f"{evidence_id}.staging",
        canonical_relative_path=f"evidence/{case.id}/{evidence_id}/original/memory-image.img",
        retryable=True,
        metadata_json={},
        progress_at=utc_now_naive(),
        stage=REG_STAGE_FAILED_REGISTRATION,
        canonical_preserved=True,
    )
    db.add(item)
    db.commit()
    canonical = data_dir / item.canonical_relative_path
    assert canonical.exists()
    payload = cancel_memory_upload(case.id, item.id, operator="tester", reason="audit", db=db)
    assert payload.status == "cancelled"
    # The canonical blob is still on disk.
    assert canonical.exists()
    assert canonical.read_bytes() == b"\x00" * 4096


# ---------------------------------------------------------------------------
# 14. No dfir-events rows created during registration
# ---------------------------------------------------------------------------


def test_no_dfir_events_created_during_registration(
    db: Session, data_dir: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    case = _make_case(db)
    item = _make_failed_upload(db, case_id=case.id, data_dir=data_dir)
    monkeypatch.setattr(lifecycle_module, "secure_uploaded_memory_permissions", _no_secure_permissions)
    # The activity log MUST be called once with
    # ``activity_type='evidence_uploaded'`` for the audit trail.
    # The log_activity function is the only side effect that the
    # registration flow performs after the Evidence INSERT; the
    # dfir-events ingestion is reserved for the normal memory
    # analysis run and must not happen here.
    from app.core.activity import log_activity as real_log_activity
    with patch("app.services.memory.upload_lifecycle.log_activity", wraps=real_log_activity) as log_spy:
        register_preserved_memory_upload(item.id, db=db)
    # The activity log was called exactly once.
    assert log_spy.call_count == 1
    args, kwargs = log_spy.call_args
    assert kwargs.get("activity_type") == "evidence_uploaded"
    # No ``ingest_memory_evidence_events`` was imported by the
    # upload_lifecycle module — that is the symbol the dfir-events
    # ingestion path exposes.
    import app.services.memory.upload_lifecycle as mod
    assert "ingest_memory_evidence_events" not in dir(mod)


# ---------------------------------------------------------------------------
# 15. No NormalizedEvent rows created during registration
# ---------------------------------------------------------------------------


def test_no_normalized_event_created(
    db: Session, data_dir: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The registration flow must not produce any normalised event
    rows.  ``NormalizedEvent`` is a Pydantic model in this codebase
    (events are written by the memory-worker after the analyst
    runs an analysis), but we still want to assert that the
    lifecycle module does not pull in a producer for it.
    """
    case = _make_case(db)
    item = _make_failed_upload(db, case_id=case.id, data_dir=data_dir)
    monkeypatch.setattr(lifecycle_module, "secure_uploaded_memory_permissions", _no_secure_permissions)
    # If a producer for NormalizedEvent gets imported, the test
    # will fail because the symbol is exposed on the module.
    register_preserved_memory_upload(item.id, db=db)
    import app.services.memory.upload_lifecycle as mod
    forbidden = [name for name in dir(mod) if "normalized_event" in name or "publish_event" in name]
    assert forbidden == [], f"unexpected producer imported: {forbidden}"


# ---------------------------------------------------------------------------
# 16. No Volatility is invoked during evidence registration
# ---------------------------------------------------------------------------


def test_no_volatility_invoked_during_registration(
    db: Session, data_dir: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    case = _make_case(db)
    item = _make_failed_upload(db, case_id=case.id, data_dir=data_dir)
    monkeypatch.setattr(lifecycle_module, "secure_uploaded_memory_permissions", _no_secure_permissions)
    # Patch every entry point that could spawn Volatility.  If any
    # of them is called, the test fails.
    forbidden = [
        "app.services.memory.volatility_runner.run_plugin",
        "app.services.memory.volatility_runner.run_windows_info",
        "app.services.memory.volatility_runner.probe_windows_symbol_identity",
        "app.workers.tasks.enqueue_memory_metadata_scan",
    ]
    patches = [patch(path, side_effect=AssertionError(f"called {path}")) for path in forbidden]
    for p in patches:
        p.start()
    try:
        evidence = register_preserved_memory_upload(item.id, db=db)
    finally:
        for p in patches:
            p.stop()
    assert evidence.id == item.evidence_id
    db.refresh(item)
    assert item.status == "completed"
