"""Tests for case-scoped, content-based duplicate evidence detection.

The ingestion pipeline review found that general evidence uploads had no
duplicate detection at all, unlike Memory uploads (MEMORY_EVIDENCE_DUPLICATE)
and the unified disk-image workflow. This covers the shared helper
(app.services.evidence_integrity.find_duplicate_evidence) as wired into the
general upload/registration paths in routes_evidence.py.
"""
from __future__ import annotations

from types import SimpleNamespace
from uuid import uuid4

import pytest
from fastapi import HTTPException, UploadFile
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from app.api import routes_evidence
from app.api.routes_evidence import RegisterPathRequest
from app.core.database import Base
from app.models.case import Case
from app.models.evidence import Evidence


CASE_ID = "aaaaaaaa-1111-4111-8111-aaaaaaaaaaaa"
OTHER_CASE_ID = "bbbbbbbb-2222-4222-8222-bbbbbbbbbbbb"

SHA_A = "a" * 64
SHA_B = "b" * 64


def _db():
    engine = create_engine("sqlite:///:memory:", connect_args={"check_same_thread": False}, poolclass=StaticPool, future=True)
    Base.metadata.create_all(engine)
    return sessionmaker(bind=engine, future=True)()


def _case(db, case_id=CASE_ID):
    item = Case(id=case_id, name="Case", description="", status="active", priority="medium", management_tags=[])
    db.add(item)
    db.commit()
    return item


def _configure(monkeypatch, tmp_path, enqueue_calls: list):
    counter = {"n": 0}

    def _fake_save_upload(case_id, file):
        counter["n"] += 1
        stored_path = tmp_path / f"upload-{counter['n']}.bin"
        stored_path.write_bytes(b"placeholder")
        return str(uuid4()), stored_path, stored_path.stat().st_size, file._fake_sha256

    monkeypatch.setattr(routes_evidence, "save_upload", _fake_save_upload)
    monkeypatch.setattr(routes_evidence, "log_activity", lambda *a, **k: None)
    monkeypatch.setattr(routes_evidence, "enqueue_ingest", lambda evidence_id: enqueue_calls.append(evidence_id))


def _upload(db, *, case_id=CASE_ID, sha256=SHA_A, filename="evidence.zip"):
    upload = UploadFile(filename=filename, file=SimpleNamespace())
    upload._fake_sha256 = sha256  # read by the _fake_save_upload monkeypatch above
    return routes_evidence.upload_evidence(
        case_id=case_id,
        file=upload,
        folder_upload=False,
        folder_name=None,
        evidence_intent="raw",
        packaging=None,
        ingest_mode=None,
        provided_host=None,
        provided_platform=None,
        host_id=None,
        evtx_profile=None,
        memory_authorization_acknowledged=False,
        memory_upload_id=None,
        db=db,
        current_user=None,
    )


def test_first_upload_succeeds(tmp_path, monkeypatch):
    enqueue_calls: list = []
    _configure(monkeypatch, tmp_path, enqueue_calls)
    db = _db()
    _case(db)

    evidence = _upload(db, sha256=SHA_A)

    assert evidence.sha256 == SHA_A
    assert evidence.case_id == CASE_ID
    assert enqueue_calls == [evidence.id]


def test_second_upload_of_identical_evidence_in_same_case_is_detected(tmp_path, monkeypatch):
    enqueue_calls: list = []
    _configure(monkeypatch, tmp_path, enqueue_calls)
    db = _db()
    _case(db)

    first = _upload(db, sha256=SHA_A, filename="evidence.zip")

    with pytest.raises(HTTPException) as exc_info:
        _upload(db, sha256=SHA_A, filename="a-completely-different-name.zip")

    assert exc_info.value.status_code == 409
    detail = exc_info.value.detail
    assert detail["error_code"] == "EVIDENCE_DUPLICATE"
    assert detail["duplicate"] is True
    assert detail["existing_evidence_id"] == first.id
    assert detail["existing_filename"] == first.original_filename

    # No second Evidence row, and the worker was only ever enqueued once.
    assert db.query(Evidence).filter(Evidence.case_id == CASE_ID).count() == 1
    assert enqueue_calls == [first.id]


def test_identical_filename_but_different_content_is_accepted(tmp_path, monkeypatch):
    enqueue_calls: list = []
    _configure(monkeypatch, tmp_path, enqueue_calls)
    db = _db()
    _case(db)

    first = _upload(db, sha256=SHA_A, filename="evidence.zip")
    second = _upload(db, sha256=SHA_B, filename="evidence.zip")

    assert first.id != second.id
    assert db.query(Evidence).filter(Evidence.case_id == CASE_ID).count() == 2
    assert enqueue_calls == [first.id, second.id]


def test_identical_content_in_a_different_case_is_accepted(tmp_path, monkeypatch):
    enqueue_calls: list = []
    _configure(monkeypatch, tmp_path, enqueue_calls)
    db = _db()
    _case(db, case_id=CASE_ID)
    _case(db, case_id=OTHER_CASE_ID)

    first = _upload(db, case_id=CASE_ID, sha256=SHA_A)
    second = _upload(db, case_id=OTHER_CASE_ID, sha256=SHA_A)

    assert first.id != second.id
    assert first.case_id == CASE_ID
    assert second.case_id == OTHER_CASE_ID
    assert enqueue_calls == [first.id, second.id]


def test_extraction_is_not_started_for_a_duplicate(tmp_path, monkeypatch):
    """No archive inspection happens for a duplicate: is_supported_archive_container
    is only reached after the duplicate check, so it must never be called."""
    enqueue_calls: list = []
    _configure(monkeypatch, tmp_path, enqueue_calls)
    container_calls: list = []
    monkeypatch.setattr(routes_evidence, "is_supported_archive_container", lambda path: container_calls.append(path) or False)
    db = _db()
    _case(db)

    _upload(db, sha256=SHA_A)
    container_calls.clear()  # only care about calls made during the second (duplicate) attempt

    with pytest.raises(HTTPException):
        _upload(db, sha256=SHA_A, filename="renamed.zip")

    assert container_calls == []


def test_register_path_duplicate_detection_reuses_the_same_helper(tmp_path, monkeypatch):
    """A second general-evidence-creation site (register_evidence_path) uses
    the identical shared helper, not a second framework."""
    db = _db()
    _case(db)
    monkeypatch.setattr(routes_evidence, "log_activity", lambda *a, **k: None)
    monkeypatch.setattr(routes_evidence, "enqueue_ingest", lambda evidence_id: None)

    file_a = tmp_path / "case_file_a.bin"
    file_a.write_bytes(b"identical evidence bytes")
    file_b = tmp_path / "case_file_b.bin"
    file_b.write_bytes(b"identical evidence bytes")  # same content, different path/name

    def _validate_ok(path, *, scan_limit=5000):
        return {"valid": True, "resolved_path": path}

    monkeypatch.setattr(routes_evidence, "validate_external_path", _validate_ok)
    monkeypatch.setattr(routes_evidence, "load_runtime_settings", lambda db: {})

    payload_a = RegisterPathRequest(path=str(file_a), copy_to_storage=False)
    evidence_a = routes_evidence.register_evidence_path(CASE_ID, payload_a, db=db, current_user=None)

    payload_b = RegisterPathRequest(path=str(file_b), copy_to_storage=False)
    with pytest.raises(HTTPException) as exc_info:
        routes_evidence.register_evidence_path(CASE_ID, payload_b, db=db, current_user=None)

    assert exc_info.value.status_code == 409
    assert exc_info.value.detail["error_code"] == "EVIDENCE_DUPLICATE"
    assert exc_info.value.detail["existing_evidence_id"] == evidence_a.id


def test_velociraptor_discover_zip_duplicate_detection_reuses_the_same_helper(tmp_path, monkeypatch):
    """The dedicated Velociraptor upload routes are a separate,
    still-active evidence-creation surface (no shared code path with
    upload_evidence) and must not have been missed.

    Only the duplicate-rejection behavior is exercised here (the check
    fires before archive discovery/inspection); the full successful
    Velociraptor discovery flow needs a real zip and has its own
    dedicated review, out of scope for this sprint.
    """
    from app.api import routes_velociraptor
    from app.models.evidence import EvidenceStorageMode, EvidenceType, IngestStatus

    db = _db()
    _case(db)
    existing = Evidence(
        id=str(uuid4()),
        case_id=CASE_ID,
        original_filename="collection.zip",
        stored_path=str(tmp_path / "collection.zip"),
        evidence_type=EvidenceType.velociraptor_zip,
        storage_mode=EvidenceStorageMode.uploaded,
        is_external=False,
        copy_to_storage=True,
        sha256=SHA_A,
        size_bytes=11,
        ingest_status=IngestStatus.completed,
        path_validation={},
        ingest_source={},
        metadata_json={},
        error_log={},
    )
    db.add(existing)
    db.commit()

    def _fake_save_upload(case_id, file):
        stored_path = tmp_path / "velo-duplicate-attempt.zip"
        stored_path.write_bytes(b"placeholder")
        return str(uuid4()), stored_path, stored_path.stat().st_size, file._fake_sha256

    monkeypatch.setattr(routes_velociraptor, "save_upload", _fake_save_upload)

    upload = UploadFile(filename="different-name.zip", file=SimpleNamespace())
    upload._fake_sha256 = SHA_A
    with pytest.raises(HTTPException) as exc_info:
        routes_velociraptor.discover_velociraptor_zip(
            CASE_ID, upload, ingest_mode=None, provided_host="TESTHOST01", provided_platform=None, evtx_profile=None, db=db, current_user=None,
        )

    assert exc_info.value.status_code == 409
    assert exc_info.value.detail["error_code"] == "EVIDENCE_DUPLICATE"
    assert exc_info.value.detail["existing_evidence_id"] == existing.id
