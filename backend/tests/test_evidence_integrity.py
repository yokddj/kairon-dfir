import hashlib
from pathlib import Path

from fastapi import UploadFile
from sqlalchemy import create_engine
from sqlalchemy.orm import Session, sessionmaker

from app.core.database import Base
from app.core.storage import save_upload
from app.models.case import Case
from app.models.evidence import Evidence, EvidenceCustodyEvent, EvidenceIntegrityStatus, EvidenceStorageMode, EvidenceType, IngestStatus
from app.models.user import User
from app.services.evidence_integrity import build_evidence_manifest, record_evidence_event, verify_evidence_integrity

CASE_ID = "aaaaaaaa-1111-4111-8111-aaaaaaaaaaaa"
EVIDENCE_ID = "bbbbbbbb-2222-4222-8222-bbbbbbbbbbbb"
USER_ID = "user-1"


def _db() -> Session:
    engine = create_engine("sqlite:///:memory:", future=True)
    Base.metadata.create_all(engine)
    return sessionmaker(bind=engine, future=True)()


def _evidence(db: Session, path: Path, *, sha256: str, size_bytes: int | None = None) -> Evidence:
    case = Case(id=CASE_ID, name="Case", description=None)
    user = User(id=USER_ID, username="analyst", display_name="Analyst", password_hash="x")
    evidence = Evidence(
        id=EVIDENCE_ID,
        case_id=case.id,
        original_filename="sample.bin",
        stored_path=str(path),
        original_path=str(path),
        storage_mode=EvidenceStorageMode.uploaded,
        is_external=False,
        copy_to_storage=True,
        evidence_type=EvidenceType.unknown,
        sha256=sha256,
        size_bytes=size_bytes if size_bytes is not None else path.stat().st_size,
        uploaded_by_user_id=user.id,
        ingest_status=IngestStatus.pending,
        path_validation={},
        ingest_source={},
        metadata_json={},
        error_log={},
    )
    db.add(case)
    db.add(user)
    db.add(evidence)
    db.commit()
    db.refresh(evidence)
    return evidence


def test_save_upload_calculates_sha256_and_size(tmp_path, monkeypatch):
    monkeypatch.setattr("app.core.storage.settings.backend_data_dir", tmp_path)
    source = tmp_path / "upload.bin"
    source.write_bytes(b"kairon-integrity")
    with source.open("rb") as handle:
        upload = UploadFile(filename="upload.bin", file=handle)
        evidence_id, stored_path, size, sha256 = save_upload("case-1", upload)

    assert evidence_id
    assert stored_path.exists()
    assert size == len(b"kairon-integrity")
    assert sha256 == hashlib.sha256(b"kairon-integrity").hexdigest()


def test_verify_integrity_with_matching_hash_records_event(tmp_path):
    path = tmp_path / "sample.bin"
    path.write_bytes(b"known-good")
    db = _db()
    evidence = _evidence(db, path, sha256=hashlib.sha256(b"known-good").hexdigest())

    result = verify_evidence_integrity(db, evidence, actor_user_id=USER_ID)
    db.commit()

    assert result["integrity_status"] == EvidenceIntegrityStatus.verified.value
    assert db.query(EvidenceCustodyEvent).filter(EvidenceCustodyEvent.event_type == "integrity_checked").count() == 1


def test_verify_integrity_detects_mismatch(tmp_path):
    path = tmp_path / "sample.bin"
    path.write_bytes(b"changed")
    db = _db()
    evidence = _evidence(db, path, sha256="0" * 64)

    result = verify_evidence_integrity(db, evidence)
    db.commit()

    assert result["integrity_status"] == EvidenceIntegrityStatus.mismatch.value
    assert evidence.integrity_status == EvidenceIntegrityStatus.mismatch


def test_verify_integrity_detects_missing_file(tmp_path):
    path = tmp_path / "missing.bin"
    db = _db()
    evidence = _evidence(db, path, sha256="0" * 64, size_bytes=10)

    result = verify_evidence_integrity(db, evidence)
    db.commit()

    assert result["integrity_status"] == EvidenceIntegrityStatus.missing_file.value
    assert evidence.integrity_status == EvidenceIntegrityStatus.missing_file


def test_manifest_excludes_internal_paths(tmp_path):
    path = tmp_path / "sample.bin"
    path.write_bytes(b"manifest")
    db = _db()
    evidence = _evidence(db, path, sha256="0" * 64)
    record_evidence_event(db, evidence, "uploaded", "Evidence uploaded.", actor_user_id=USER_ID, details={"stored_path": str(path), "sha256": evidence.sha256})
    db.commit()

    manifest = build_evidence_manifest(evidence, db.query(EvidenceCustodyEvent).all())
    serialized = str(manifest)

    assert "stored_path" not in serialized
    assert str(path) not in serialized
    assert manifest["uploaded_by"] == "Analyst"
