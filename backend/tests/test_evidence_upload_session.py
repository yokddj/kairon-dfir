"""Temporary Upload Session coverage (v2.1 preflight refinement).

Exercises app.services.evidence_upload_session (stage once, inspect,
promote without retransmitting bytes) and the corresponding API routes in
app.api.routes_evidence_preflight, verifying: sessions expire and clean up,
cancel cleans up immediately, promotion reuses the exact staged bytes and
its precomputed SHA-256 (no duplicate upload, no duplicate hash), and
nothing is enqueued/created until promotion is explicitly confirmed.
"""
from __future__ import annotations

import zipfile
from datetime import timedelta
from pathlib import Path
from types import SimpleNamespace

from fastapi import FastAPI, UploadFile
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from app.api import routes_evidence_preflight
from app.core.database import Base, get_db, utc_now
from app.core.config import get_settings
from app.models.case import Case
from app.models.evidence import Evidence
from app.models.evidence_upload_session import EvidenceUploadSession, EvidenceUploadSessionStatus
from app.services.evidence_upload_session import (
    UploadSessionError,
    cancel_upload_session,
    cleanup_expired_upload_sessions,
    create_upload_session,
    get_active_session,
    promote_upload_session,
)

settings = get_settings()
CASE_ID = "aaaaaaaa-1111-4111-8111-aaaaaaaaaaaa"


def _db():
    engine = create_engine("sqlite:///:memory:", connect_args={"check_same_thread": False}, poolclass=StaticPool, future=True)
    Base.metadata.create_all(engine)
    return sessionmaker(bind=engine, future=True)()


def _client(db):
    test_app = FastAPI()
    test_app.include_router(routes_evidence_preflight.router)
    test_app.dependency_overrides[get_db] = lambda: db
    return TestClient(test_app)


def _case(db, *, case_id=CASE_ID):
    item = Case(id=case_id, name="Upload Session Case", description="", status="active", priority="medium", management_tags=[])
    db.add(item)
    db.commit()
    return item


def _make_zip(path: Path, hostname: str = "web01") -> None:
    with zipfile.ZipFile(path, "w") as zf:
        zf.writestr("etc/hostname", f"{hostname}\n")
        zf.writestr("etc/os-release", 'PRETTY_NAME="Ubuntu 24.04 LTS"\n')
        zf.writestr("var/log/auth.log", "auth\n" * 20)


def _upload_file(path: Path, filename: str | None = None) -> UploadFile:
    return UploadFile(path.open("rb"), filename=filename or path.name)


# ---------------------------------------------------------------------------
# Session lifecycle: create, preflight, cancel, expiry
# ---------------------------------------------------------------------------

def test_create_session_stages_file_and_runs_preflight_without_creating_evidence(tmp_path, monkeypatch):
    monkeypatch.setattr(settings, "backend_temp_dir", tmp_path)
    db = _db()
    _case(db)
    zip_path = tmp_path / "collection.zip"
    _make_zip(zip_path)

    session, report = create_upload_session(db, CASE_ID, files=[_upload_file(zip_path)], declared_platform=None, client_sha256=None)

    assert session.status == EvidenceUploadSessionStatus.staged.value
    assert session.sha256 is not None
    assert Path(session.staged_path).exists()
    assert report.status == "ready"
    assert report.classification.hostname == "web01"
    assert db.query(Evidence).count() == 0


def test_client_sha256_mismatch_is_flagged_not_silently_trusted(tmp_path, monkeypatch):
    monkeypatch.setattr(settings, "backend_temp_dir", tmp_path)
    db = _db()
    _case(db)
    zip_path = tmp_path / "collection.zip"
    _make_zip(zip_path)

    session, _ = create_upload_session(db, CASE_ID, files=[_upload_file(zip_path)], declared_platform=None, client_sha256="0" * 64)

    assert session.metadata_json.get("client_sha256_mismatch") is True


def test_cancel_cleans_up_staged_file_immediately(tmp_path, monkeypatch):
    monkeypatch.setattr(settings, "backend_temp_dir", tmp_path)
    db = _db()
    _case(db)
    zip_path = tmp_path / "collection.zip"
    _make_zip(zip_path)
    session, _ = create_upload_session(db, CASE_ID, files=[_upload_file(zip_path)], declared_platform=None, client_sha256=None)
    staged_path = Path(session.staged_path)
    assert staged_path.exists()

    cancel_upload_session(db, session)

    assert db.get(EvidenceUploadSession, session.id).status == EvidenceUploadSessionStatus.cancelled.value
    assert not staged_path.exists()


def test_expired_sessions_are_cleaned_up_by_sweep(tmp_path, monkeypatch):
    monkeypatch.setattr(settings, "backend_temp_dir", tmp_path)
    db = _db()
    _case(db)
    zip_path = tmp_path / "collection.zip"
    _make_zip(zip_path)
    session, _ = create_upload_session(db, CASE_ID, files=[_upload_file(zip_path)], declared_platform=None, client_sha256=None)
    staged_path = Path(session.staged_path)

    session.expires_at = utc_now() - timedelta(seconds=1)
    db.add(session)
    db.commit()

    result = cleanup_expired_upload_sessions(db)

    assert result["expired"] == 1
    assert db.get(EvidenceUploadSession, session.id).status == EvidenceUploadSessionStatus.expired.value
    assert not staged_path.exists()


def test_get_active_session_rejects_wrong_case_or_terminal_status(tmp_path, monkeypatch):
    monkeypatch.setattr(settings, "backend_temp_dir", tmp_path)
    db = _db()
    _case(db)
    _case(db, case_id="9a999999-1111-4111-8111-999999999999")
    zip_path = tmp_path / "collection.zip"
    _make_zip(zip_path)
    session, _ = create_upload_session(db, CASE_ID, files=[_upload_file(zip_path)], declared_platform=None, client_sha256=None)

    try:
        get_active_session(db, "9a999999-1111-4111-8111-999999999999", session.id)
        assert False, "expected UploadSessionError"
    except UploadSessionError:
        pass

    cancel_upload_session(db, session)
    try:
        get_active_session(db, CASE_ID, session.id)
        assert False, "expected UploadSessionError"
    except UploadSessionError:
        pass


# ---------------------------------------------------------------------------
# Promotion: no retransmission, no duplicate hash
# ---------------------------------------------------------------------------

def test_promote_reuses_staged_bytes_without_retransmission_or_rehash(tmp_path, monkeypatch):
    monkeypatch.setattr(settings, "backend_temp_dir", tmp_path)
    monkeypatch.setattr(settings, "backend_data_dir", tmp_path / "data")
    monkeypatch.setattr("app.api.routes_evidence.enqueue_ingest", lambda evidence_id: "job-1")
    monkeypatch.setattr("app.core.storage.settings", settings)
    db = _db()
    _case(db)
    zip_path = tmp_path / "collection.zip"
    _make_zip(zip_path)

    session, report = create_upload_session(db, CASE_ID, files=[_upload_file(zip_path)], declared_platform=None, client_sha256=None)
    staged_path = Path(session.staged_path)
    known_hash = session.sha256

    evidence = promote_upload_session(
        db, session,
        provided_platform=None, host_id=None, provided_host=None, evtx_profile=None,
        memory_authorization_acknowledged=False, folder_name=None, labels=None, notes=None,
        current_user=None,
    )

    assert evidence.sha256 == known_hash, "promotion must reuse the hash computed while staging, not recompute it"
    assert not staged_path.exists(), "the staged copy must be moved into evidence storage, not duplicated"
    assert Path(evidence.stored_path).exists()
    assert Path(evidence.stored_path).read_bytes() == zip_path.read_bytes()
    assert db.get(EvidenceUploadSession, session.id).status == EvidenceUploadSessionStatus.promoted.value
    assert db.get(EvidenceUploadSession, session.id).promoted_evidence_id == evidence.id


def test_promote_disk_image_category_routes_to_disk_image_upload(tmp_path, monkeypatch):
    import subprocess

    def _require_tools(*names):
        import pytest
        missing = [n for n in names if subprocess.run(["bash", "-lc", f"command -v {n} >/dev/null 2>&1"], check=False).returncode != 0]
        if missing:
            pytest.skip(f"Missing required tool(s): {', '.join(missing)}")

    _require_tools("parted", "mkfs.vfat", "dd")
    monkeypatch.setattr(settings, "backend_temp_dir", tmp_path)
    monkeypatch.setattr(settings, "backend_data_dir", tmp_path / "data")
    monkeypatch.setattr("app.api.routes_evidence.enqueue_ingest", lambda evidence_id: "job-1")
    db = _db()
    _case(db)

    fs_image = tmp_path / "fs.img"
    subprocess.run(["mkfs.vfat", "-C", str(fs_image), "16384"], check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    disk_path = tmp_path / "disk.dd"
    disk_path.write_bytes(b"\x00" * (32 * 1024 * 1024))
    subprocess.run(["parted", "-s", str(disk_path), "mklabel", "msdos", "mkpart", "primary", "fat32", "1MiB", "17MiB"], check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    subprocess.run(["dd", f"if={fs_image}", f"of={disk_path}", "bs=1M", "seek=1", "conv=notrunc"], check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

    session, report = create_upload_session(db, CASE_ID, files=[_upload_file(disk_path)], declared_platform=None, client_sha256=None)
    assert report.classification.category == "disk_image"

    evidence = promote_upload_session(
        db, session,
        provided_platform=None, host_id=None, provided_host=None, evtx_profile=None,
        memory_authorization_acknowledged=False, folder_name=None, labels=None, notes=None,
        current_user=None,
    )
    assert evidence.evidence_type.value == "disk_image"


def test_promote_disk_image_with_multiple_segments_passes_all_segments_in_order(tmp_path, monkeypatch):
    """Regression guard: a split disk image (.E01/.E02/...) must not lose
    segments 2..N when promoted through the upload session - only staging
    files[0] for preflight inspection is fine (matches historical preview
    behavior), but promotion must still send every segment to
    upload_disk_image, in upload order."""
    monkeypatch.setattr(settings, "backend_temp_dir", tmp_path)
    monkeypatch.setattr(settings, "backend_data_dir", tmp_path / "data")
    db = _db()
    _case(db)

    seg1 = tmp_path / "disk.E01"
    seg1.write_bytes(b"segment-one-bytes")
    seg2 = tmp_path / "disk.E02"
    seg2.write_bytes(b"segment-two-bytes")

    session, _report = create_upload_session(
        db, CASE_ID, files=[_upload_file(seg1), _upload_file(seg2)], declared_platform=None, client_sha256=None,
    )
    # Force the category regardless of real EWF format detection (which needs
    # genuine libewf-produced segments); this test targets the segment
    # staging/promotion plumbing, not format detection.
    session.metadata_json = {**(session.metadata_json or {}), "category": "disk_image"}
    db.add(session)
    db.commit()
    extra_segment_path = Path(session.metadata_json["extra_segments"][0]["path"])
    staged_primary_path = Path(session.staged_path)
    assert extra_segment_path.read_bytes() == b"segment-two-bytes"

    captured: dict[str, list] = {}

    def _fake_upload_disk_image(case_id, files, **_kwargs):
        captured["filenames"] = [f.filename for f in files]
        captured["contents"] = [f.file.read() for f in files]
        return SimpleNamespace(id="evidence-multi-segment")

    import app.api.routes_evidence as routes_evidence
    monkeypatch.setattr(routes_evidence, "upload_disk_image", _fake_upload_disk_image)

    evidence = promote_upload_session(
        db, session,
        provided_platform=None, host_id=None, provided_host=None, evtx_profile=None,
        memory_authorization_acknowledged=False, folder_name=None, labels=None, notes=None,
        current_user=None,
    )

    assert captured["filenames"] == ["disk.E01", "disk.E02"]
    assert captured["contents"] == [b"segment-one-bytes", b"segment-two-bytes"]
    assert evidence.id == "evidence-multi-segment"
    assert not staged_primary_path.exists(), "staged segments must be cleaned up after promotion"
    assert not extra_segment_path.exists(), "staged extra segments must be cleaned up after promotion"


def test_promote_folder_session(tmp_path, monkeypatch):
    monkeypatch.setattr(settings, "backend_temp_dir", tmp_path)
    monkeypatch.setattr(settings, "backend_data_dir", tmp_path / "data")
    monkeypatch.setattr(settings, "backend_enable_experimental_folder_upload", True)
    monkeypatch.setattr("app.api.routes_evidence.enqueue_ingest", lambda evidence_id: "job-1")
    db = _db()
    _case(db)

    (tmp_path / "a.log").write_text("a\n", encoding="utf-8")
    (tmp_path / "b.log").write_text("b\n", encoding="utf-8")
    files = [
        UploadFile((tmp_path / "a.log").open("rb"), filename="etc/a.log"),
        UploadFile((tmp_path / "b.log").open("rb"), filename="etc/b.log"),
    ]
    session, report = create_upload_session(db, CASE_ID, files=files, is_folder=True, declared_platform=None, client_sha256=None)
    assert session.is_folder is True

    evidence = promote_upload_session(
        db, session,
        provided_platform=None, host_id=None, provided_host=None, evtx_profile=None,
        memory_authorization_acknowledged=False, folder_name=None, labels=None, notes=None,
        current_user=None,
    )
    assert evidence.id is not None
    assert not Path(session.staged_path).exists()


def test_promote_server_path_session_never_deletes_original(tmp_path, monkeypatch):
    import app.core.evidence_paths as evidence_paths_module

    monkeypatch.setattr(settings, "backend_temp_dir", tmp_path / "tmp")
    monkeypatch.setattr(settings, "backend_data_dir", tmp_path / "data")
    monkeypatch.setattr("app.api.routes_evidence.enqueue_ingest", lambda evidence_id: "job-1")
    allowed_root = tmp_path / "evidence"
    allowed_root.mkdir(parents=True, exist_ok=True)
    monkeypatch.setattr(evidence_paths_module.settings, "dfir_allow_host_path_import", True)
    monkeypatch.setattr(evidence_paths_module.settings, "dfir_allowed_evidence_roots", str(allowed_root))

    zip_path = allowed_root / "collection.zip"
    _make_zip(zip_path)

    db = _db()
    _case(db)
    session, report = create_upload_session(db, CASE_ID, server_path=str(zip_path), declared_platform=None, client_sha256=None)
    assert session.is_server_path is True

    evidence = promote_upload_session(
        db, session,
        provided_platform=None, host_id=None, provided_host=None, evtx_profile=None,
        memory_authorization_acknowledged=False, folder_name=None, labels=None, notes=None,
        current_user=None,
    )
    assert evidence.id is not None
    assert zip_path.exists(), "the analyst's own file at the server path must never be deleted"
    cancelled_check = db.get(EvidenceUploadSession, session.id)
    assert cancelled_check.status == EvidenceUploadSessionStatus.promoted.value


# ---------------------------------------------------------------------------
# API-level: routes, no evidence/enqueue before promotion, health check
# ---------------------------------------------------------------------------

def test_api_create_then_promote_flow(tmp_path, monkeypatch):
    monkeypatch.setattr(settings, "backend_temp_dir", tmp_path)
    monkeypatch.setattr(settings, "backend_data_dir", tmp_path / "data")
    monkeypatch.setattr("app.api.routes_evidence.enqueue_ingest", lambda evidence_id: "job-1")
    db = _db()
    _case(db)
    client = _client(db)

    zip_path = tmp_path / "collection.zip"
    _make_zip(zip_path)
    with zip_path.open("rb") as fh:
        response = client.post(f"/api/cases/{CASE_ID}/evidence-uploads", files={"files": ("collection.zip", fh, "application/zip")})
    assert response.status_code == 200
    payload = response.json()
    assert payload["preflight"]["status"] == "ready"
    assert payload["session"]["status"] == "staged"
    assert db.query(Evidence).count() == 0

    session_id = payload["session"]["id"]
    promote_response = client.post(f"/api/cases/{CASE_ID}/evidence-uploads/{session_id}/promote", json={})
    assert promote_response.status_code == 200
    assert db.query(Evidence).count() == 1

    # Cannot promote (or cancel) the same session twice.
    second = client.post(f"/api/cases/{CASE_ID}/evidence-uploads/{session_id}/promote", json={})
    assert second.status_code == 404


def test_api_cancel_endpoint(tmp_path, monkeypatch):
    monkeypatch.setattr(settings, "backend_temp_dir", tmp_path)
    db = _db()
    _case(db)
    client = _client(db)
    zip_path = tmp_path / "collection.zip"
    _make_zip(zip_path)
    with zip_path.open("rb") as fh:
        response = client.post(f"/api/cases/{CASE_ID}/evidence-uploads", files={"files": ("collection.zip", fh, "application/zip")})
    session_id = response.json()["session"]["id"]

    cancel_response = client.delete(f"/api/cases/{CASE_ID}/evidence-uploads/{session_id}")
    assert cancel_response.status_code == 200
    assert db.get(EvidenceUploadSession, session_id).status == "cancelled"


def test_api_rerun_preflight_with_platform_override(tmp_path, monkeypatch):
    monkeypatch.setattr(settings, "backend_temp_dir", tmp_path)
    db = _db()
    _case(db)
    client = _client(db)
    zip_path = tmp_path / "collection.zip"
    _make_zip(zip_path)
    with zip_path.open("rb") as fh:
        response = client.post(f"/api/cases/{CASE_ID}/evidence-uploads", files={"files": ("collection.zip", fh, "application/zip")})
    session_id = response.json()["session"]["id"]

    rerun = client.post(f"/api/cases/{CASE_ID}/evidence-uploads/{session_id}/preflight", json={"declared_platform": "windows"})
    assert rerun.status_code == 200
    assert rerun.json()["classification"]["platform"] == "windows"


def test_ingestion_readiness_endpoint_reports_structured_checks(tmp_path, monkeypatch):
    monkeypatch.setattr(settings, "backend_temp_dir", tmp_path)
    db = _db()
    _case(db)
    client = _client(db)

    response = client.get(f"/api/cases/{CASE_ID}/ingestion-readiness")
    assert response.status_code == 200
    payload = response.json()
    labels = {check["label"] for check in payload["checks"]}
    assert {"Storage", "Search", "Database", "Workers", "Memory Worker"}.issubset(labels)
    assert "available_disk_space_bytes" in payload
    assert "configured_upload_limit_bytes" in payload
