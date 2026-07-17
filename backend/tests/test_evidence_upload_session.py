"""Temporary Upload Session coverage (v2.1 preflight refinement).

Exercises app.services.evidence_upload_session (stage once, inspect,
promote without retransmitting bytes) and the corresponding API routes in
app.api.routes_evidence_preflight, verifying: sessions expire and clean up,
cancel cleans up immediately, promotion reuses the exact staged bytes and
its precomputed SHA-256 (no duplicate upload, no duplicate hash), and
nothing is enqueued/created until promotion is explicitly confirmed.
"""
from __future__ import annotations

import asyncio
import hashlib
import zipfile
from datetime import timedelta
from pathlib import Path
from types import SimpleNamespace

import pytest
from fastapi import FastAPI, UploadFile
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool
from starlette.requests import ClientDisconnect

from app.api import routes_evidence_preflight
from app.core.database import Base, get_db, utc_now
from app.core.config import get_settings
from app.models.case import Case
from app.models.case_host import CaseHost
from app.models.evidence import Evidence
from app.models.evidence_upload_session import EvidenceUploadSession, EvidenceUploadSessionStatus
from app.models.memory import MemoryUpload
from app.services.memory.upload_sessions import (
    create_memory_upload_session,
    finalize_memory_upload_session,
    store_memory_upload_chunk_stream,
)
from app.services.evidence_upload_session import (
    UploadSessionError,
    _stage_streamed_file,
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


class _StreamRequest:
    def __init__(self, chunks):
        self.chunks = list(chunks)
        self.disconnect_checks = 0

    async def is_disconnected(self):
        self.disconnect_checks += 1
        raise AssertionError("is_disconnected must not be polled while request.stream() is active")

    async def stream(self):
        for chunk in self.chunks:
            if isinstance(chunk, BaseException):
                raise chunk
            yield chunk


async def _bytes_stream(payload: bytes):
    yield payload


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


def test_streaming_upload_stages_file_before_preflight(tmp_path, monkeypatch):
    monkeypatch.setattr(settings, "backend_temp_dir", tmp_path)
    monkeypatch.setattr(settings, "backend_max_upload_size", 32 * 1024 * 1024)
    db = _db()
    _case(db)
    client = _client(db)
    body = b"PK\x03\x04" + (b"A" * (5 * 1024 * 1024))

    response = client.post(
        f"/api/cases/{CASE_ID}/evidence-uploads/stream?filename=large.zip",
        content=body,
        headers={"Content-Type": "application/octet-stream", "X-Kairon-File-Size": str(len(body))},
    )

    assert response.status_code == 200
    payload = response.json()
    assert "preflight" not in payload
    session = db.get(EvidenceUploadSession, payload["session"]["id"])
    assert session is not None
    assert session.size_bytes == len(body)
    assert Path(session.staged_path).stat().st_size == len(body)

    preflight = client.post(f"/api/cases/{CASE_ID}/evidence-uploads/{session.id}/preflight", json={"declared_platform": None})
    assert preflight.status_code == 200
    db.refresh(session)
    assert (session.metadata_json or {}).get("category")


@pytest.mark.anyio
async def test_streaming_upload_preserves_repeated_chunks_without_disconnect_polling(tmp_path, monkeypatch):
    monkeypatch.setattr(settings, "backend_temp_dir", tmp_path)
    monkeypatch.setattr(settings, "backend_max_upload_size", 32 * 1024 * 1024)
    chunks = [bytes([i % 251]) * (80 * 1024) for i in range(80)]
    expected = b"".join(chunks)
    request = _StreamRequest(chunks)

    staged = await _stage_streamed_file(request, session_id="high-water-regression", filename="large.data", expected_bytes=len(expected))

    assert request.disconnect_checks == 0
    assert staged.size_bytes == len(expected)
    assert staged.sha256 == hashlib.sha256(expected).hexdigest()
    assert staged.path.read_bytes() == expected


@pytest.mark.anyio
async def test_streaming_upload_client_disconnect_becomes_structured_error_and_cleans_up(tmp_path, monkeypatch):
    monkeypatch.setattr(settings, "backend_temp_dir", tmp_path)
    monkeypatch.setattr(settings, "backend_max_upload_size", 32 * 1024 * 1024)
    request = _StreamRequest([b"partial", ClientDisconnect()])

    with pytest.raises(UploadSessionError) as exc:
        await _stage_streamed_file(request, session_id="disconnect-test", filename="large.data", expected_bytes=1024)

    assert exc.value.code == "client_disconnected"
    assert exc.value.details["received_bytes"] == len(b"partial")
    assert exc.value.details["expected_bytes"] == 1024
    assert not (tmp_path / "evidence-upload-sessions" / "disconnect-test" / "large.data").exists()


@pytest.mark.anyio
async def test_streaming_upload_incomplete_transfer_fails_size_validation_and_cleans_up(tmp_path, monkeypatch):
    monkeypatch.setattr(settings, "backend_temp_dir", tmp_path)
    monkeypatch.setattr(settings, "backend_max_upload_size", 32 * 1024 * 1024)
    request = _StreamRequest([b"short"])

    with pytest.raises(UploadSessionError) as exc:
        await _stage_streamed_file(request, session_id="incomplete-test", filename="large.data", expected_bytes=1024)

    assert exc.value.code == "staging_failed"
    assert exc.value.details["received_bytes"] == len(b"short")
    assert exc.value.details["expected_bytes"] == 1024
    assert not (tmp_path / "evidence-upload-sessions" / "incomplete-test" / "large.data").exists()


def test_backend_dockerfile_does_not_patch_uvicorn_flow_control():
    dockerfile = Path(__file__).resolve().parents[1] / "Dockerfile"
    text = dockerfile.read_text(encoding="utf-8")

    assert "uvicorn/protocols/http/flow_control.py" not in text
    assert "HIGH_WATER_LIMIT" not in text


def test_streaming_upload_rejects_insufficient_storage_before_reading(tmp_path, monkeypatch):
    monkeypatch.setattr(settings, "backend_temp_dir", tmp_path)
    monkeypatch.setattr(settings, "backend_max_upload_size", 32 * 1024 * 1024)
    monkeypatch.setattr("app.services.evidence_upload_session.shutil.disk_usage", lambda _path: type("Usage", (), {"free": 10})())
    db = _db()
    _case(db)
    client = _client(db)

    response = client.post(
        f"/api/cases/{CASE_ID}/evidence-uploads/stream?filename=too-large.zip",
        content=b"abc",
        headers={"Content-Type": "application/octet-stream", "X-Kairon-File-Size": str(1024)},
    )

    assert response.status_code == 413
    detail = response.json()["detail"]
    assert detail["code"] == "insufficient_storage"
    assert detail["configuration_key"] == "BACKEND_TEMP_DIR"


@pytest.mark.anyio
async def test_streaming_upload_idle_timeout_cleans_partial_file(tmp_path, monkeypatch):
    monkeypatch.setattr(settings, "backend_temp_dir", tmp_path)
    monkeypatch.setattr(settings, "backend_upload_idle_timeout_seconds", 1)

    class SlowRequest:
        async def is_disconnected(self):
            return False

        async def stream(self):
            yield b"abc"
            await asyncio.sleep(2)
            yield b"def"

    with pytest.raises(UploadSessionError) as exc:
        await _stage_streamed_file(SlowRequest(), session_id="idle-test", filename="large.zip", expected_bytes=6)

    assert exc.value.code == "upload_idle_timeout"
    assert not (tmp_path / "evidence-upload-sessions" / "idle-test" / "large.zip").exists()


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


def test_promote_memory_session_uses_memory_upload_lifecycle_not_generic_ingest(tmp_path, monkeypatch):
    monkeypatch.setattr(settings, "backend_temp_dir", tmp_path / "tmp")
    monkeypatch.setattr(settings, "backend_data_dir", tmp_path / "data")
    monkeypatch.setattr(settings, "memory_upload_enabled", True)
    monkeypatch.setattr(settings, "memory_upload_max_bytes", 64 * 1024 * 1024)
    monkeypatch.setattr(settings, "memory_max_upload_size", 64 * 1024 * 1024)
    monkeypatch.setattr(settings, "memory_upload_case_quota_bytes", 256 * 1024 * 1024)
    monkeypatch.setattr(settings, "memory_auto_preparation", False)
    monkeypatch.setattr(settings, "memory_auto_symbol_probe", False)
    monkeypatch.setattr("app.services.memory.upload_sessions._capacity_snapshot", lambda *args, **kwargs: {"can_accept_selected_size": True})
    monkeypatch.setattr("app.api.routes_evidence.enqueue_ingest", lambda _evidence_id: (_ for _ in ()).throw(AssertionError("memory wizard must not enqueue generic ingest")))
    monkeypatch.setattr("app.api.routes_evidence.upload_evidence", lambda *args, **kwargs: (_ for _ in ()).throw(AssertionError("memory wizard must not call generic upload_evidence")))
    monkeypatch.setattr("app.api.routes_evidence.upload_disk_image", lambda *args, **kwargs: (_ for _ in ()).throw(AssertionError("memory wizard must not call disk image upload")))
    db = _db()
    _case(db)
    host = CaseHost(id="bbbbbbbb-1111-4111-8111-bbbbbbbbbbbb", case_id=CASE_ID, canonical_name="WIN-RAM01", display_name="WIN-RAM01", confidence="manual", source="manual")
    db.add(host)
    db.commit()
    ram_path = tmp_path / "capture.mem"
    ram_bytes = b"RAM" * 4096
    ram_path.write_bytes(ram_bytes)

    session, report = create_upload_session(db, CASE_ID, files=[_upload_file(ram_path)], declared_platform=None, client_sha256=None)
    assert report.classification.category == "memory_dump"
    staged_path = Path(session.staged_path)
    known_hash = hashlib.sha256(ram_bytes).hexdigest()

    evidence = promote_upload_session(
        db,
        session,
        provided_platform="windows",
        host_id=host.id,
        provided_host=None,
        evtx_profile=None,
        memory_authorization_acknowledged=True,
        folder_name=None,
        labels=None,
        notes=None,
        current_user=None,
    )

    assert evidence.evidence_type.value == "memory_dump"
    assert evidence.sha256 == known_hash
    assert evidence.size_bytes == len(ram_bytes)
    assert evidence.ingest_status.value == "completed"
    assert evidence.host_id == host.id
    assert evidence.metadata_json["memory_analysis"]["status"] == "registered"
    assert evidence.ingest_source["memory_upload"] is True
    assert Path(evidence.stored_path).name == "memory-image.mem"
    assert Path(evidence.stored_path).read_bytes() == ram_bytes
    upload = db.query(MemoryUpload).filter(MemoryUpload.evidence_id == evidence.id).one()
    assert upload.status == "completed"
    assert upload.sha256 == known_hash
    assert upload.metadata_json["source_upload_session_kind"] == "unified_evidence_wizard"
    assert db.get(EvidenceUploadSession, session.id).status == EvidenceUploadSessionStatus.promoted.value
    assert db.get(EvidenceUploadSession, session.id).promoted_evidence_id == evidence.id
    assert not staged_path.exists()


def test_memory_wizard_and_legacy_upload_register_equivalent_canonical_evidence(tmp_path, monkeypatch):
    monkeypatch.setattr(settings, "backend_temp_dir", tmp_path / "tmp")
    monkeypatch.setattr(settings, "backend_data_dir", tmp_path / "data")
    monkeypatch.setattr(settings, "memory_upload_enabled", True)
    monkeypatch.setattr(settings, "memory_upload_max_bytes", 64 * 1024 * 1024)
    monkeypatch.setattr(settings, "memory_max_upload_size", 64 * 1024 * 1024)
    monkeypatch.setattr(settings, "memory_upload_case_quota_bytes", 256 * 1024 * 1024)
    monkeypatch.setattr(settings, "memory_auto_preparation", False)
    monkeypatch.setattr(settings, "memory_auto_symbol_probe", False)
    monkeypatch.setattr("app.services.memory.upload_sessions._capacity_snapshot", lambda *args, **kwargs: {"can_accept_selected_size": True})
    db = _db()
    legacy_case_id = CASE_ID
    wizard_case_id = "aaaaaaaa-2222-4222-8222-aaaaaaaaaaaa"
    _case(db, case_id=legacy_case_id)
    _case(db, case_id=wizard_case_id)
    ram_bytes = b"Kairon RAM parity\x00" * 4096
    known_hash = hashlib.sha256(ram_bytes).hexdigest()

    legacy_upload = create_memory_upload_session(
        db,
        case_id=legacy_case_id,
        filename="capture.mem",
        expected_size_bytes=len(ram_bytes),
        provided_host="WIN-RAM01",
        authorization_acknowledged=True,
        expected_sha256=known_hash,
        upload_mode="direct",
    )
    asyncio.run(
        store_memory_upload_chunk_stream(
            db,
            case_id=legacy_case_id,
            upload_id=legacy_upload.id,
            chunk_index=0,
            chunks=_bytes_stream(ram_bytes),
            headers={"content-length": str(len(ram_bytes)), "x-kairon-chunk-sha256": known_hash},
            content_length_is_payload=True,
            expected_mode="direct",
        )
    )
    _, legacy_evidence = finalize_memory_upload_session(db, case_id=legacy_case_id, upload_id=legacy_upload.id, expected_sha256=known_hash)

    ram_path = tmp_path / "capture.mem"
    ram_path.write_bytes(ram_bytes)
    wizard_session, report = create_upload_session(db, wizard_case_id, files=[_upload_file(ram_path)], declared_platform=None, client_sha256=known_hash)
    assert report.classification.category == "memory_dump"
    wizard_evidence = promote_upload_session(
        db,
        wizard_session,
        provided_platform="windows",
        host_id=None,
        provided_host="WIN-RAM01",
        evtx_profile=None,
        memory_authorization_acknowledged=True,
        folder_name=None,
        labels=None,
        notes=None,
        current_user=None,
    )

    assert legacy_evidence is not None
    legacy_upload = db.query(MemoryUpload).filter(MemoryUpload.evidence_id == legacy_evidence.id).one()
    wizard_upload = db.query(MemoryUpload).filter(MemoryUpload.evidence_id == wizard_evidence.id).one()
    for evidence in (legacy_evidence, wizard_evidence):
        assert evidence.evidence_type.value == "memory_dump"
        assert evidence.sha256 == known_hash
        assert evidence.size_bytes == len(ram_bytes)
        assert evidence.ingest_status.value == "completed"
        assert evidence.metadata_json["memory_analysis"]["status"] == "registered"
        assert evidence.ingest_source["memory_upload"] is True
        assert Path(evidence.stored_path).name == "memory-image.mem"
        assert Path(evidence.stored_path).read_bytes() == ram_bytes
    for upload in (legacy_upload, wizard_upload):
        assert upload.status == "completed"
        assert upload.sha256 == known_hash
        assert upload.bytes_received == len(ram_bytes)
        assert upload.received_chunk_count == 1
    assert wizard_upload.metadata_json["source_upload_session_kind"] == "unified_evidence_wizard"


def test_legacy_memory_upload_without_explicit_host_is_rejected(tmp_path, monkeypatch):
    monkeypatch.setattr(settings, "backend_temp_dir", tmp_path / "tmp")
    monkeypatch.setattr(settings, "backend_data_dir", tmp_path / "data")
    monkeypatch.setattr(settings, "memory_upload_enabled", True)
    monkeypatch.setattr(settings, "memory_upload_max_bytes", 64 * 1024 * 1024)
    monkeypatch.setattr(settings, "memory_max_upload_size", 64 * 1024 * 1024)
    monkeypatch.setattr(settings, "memory_upload_case_quota_bytes", 256 * 1024 * 1024)
    monkeypatch.setattr("app.services.memory.upload_sessions._capacity_snapshot", lambda *args, **kwargs: {"can_accept_selected_size": True})
    db = _db()
    _case(db)

    with pytest.raises(Exception) as exc:
        create_memory_upload_session(
            db,
            case_id=CASE_ID,
            filename="capture.mem",
            expected_size_bytes=4096,
            provided_host="",
            authorization_acknowledged=True,
            upload_mode="direct",
        )

    assert getattr(exc.value, "code", None) == "MEMORY_UPLOAD_HOST_REQUIRED"
    assert db.query(Evidence).count() == 0
    assert db.query(MemoryUpload).count() == 0


def test_promote_memory_session_requires_authorization_acknowledgement(tmp_path, monkeypatch):
    monkeypatch.setattr(settings, "backend_temp_dir", tmp_path / "tmp")
    monkeypatch.setattr(settings, "backend_data_dir", tmp_path / "data")
    monkeypatch.setattr(settings, "memory_upload_enabled", True)
    monkeypatch.setattr(settings, "memory_upload_max_bytes", 64 * 1024 * 1024)
    monkeypatch.setattr(settings, "memory_max_upload_size", 64 * 1024 * 1024)
    monkeypatch.setattr(settings, "memory_upload_case_quota_bytes", 256 * 1024 * 1024)
    monkeypatch.setattr("app.services.memory.upload_sessions._capacity_snapshot", lambda *args, **kwargs: {"can_accept_selected_size": True})
    db = _db()
    _case(db)
    ram_path = tmp_path / "capture.mem"
    ram_path.write_bytes(b"RAM" * 1024)
    session, report = create_upload_session(db, CASE_ID, files=[_upload_file(ram_path)], declared_platform=None, client_sha256=None)
    assert report.classification.category == "memory_dump"

    with pytest.raises(Exception) as exc:
        promote_upload_session(
            db,
            session,
            provided_platform=None,
            host_id=None,
            provided_host="WIN-RAM01",
            evtx_profile=None,
            memory_authorization_acknowledged=False,
            folder_name=None,
            labels=None,
            notes=None,
            current_user=None,
        )

    assert getattr(exc.value, "code", None) == "MEMORY_UPLOAD_AUTHORIZATION_REQUIRED"
    assert db.query(Evidence).count() == 0


def test_promote_memory_session_requires_explicit_source_host_like_legacy(tmp_path, monkeypatch):
    monkeypatch.setattr(settings, "backend_temp_dir", tmp_path / "tmp")
    monkeypatch.setattr(settings, "backend_data_dir", tmp_path / "data")
    monkeypatch.setattr(settings, "memory_upload_enabled", True)
    monkeypatch.setattr(settings, "memory_upload_max_bytes", 64 * 1024 * 1024)
    monkeypatch.setattr(settings, "memory_max_upload_size", 64 * 1024 * 1024)
    monkeypatch.setattr(settings, "memory_upload_case_quota_bytes", 256 * 1024 * 1024)
    monkeypatch.setattr("app.services.memory.upload_sessions._capacity_snapshot", lambda *args, **kwargs: {"can_accept_selected_size": True})
    db = _db()
    _case(db)
    ram_path = tmp_path / "capture.mem"
    ram_path.write_bytes(b"RAM" * 1024)
    session, report = create_upload_session(db, CASE_ID, files=[_upload_file(ram_path)], declared_platform=None, client_sha256=None)
    assert report.classification.category == "memory_dump"

    with pytest.raises(Exception) as exc:
        promote_upload_session(
            db,
            session,
            provided_platform=None,
            host_id=None,
            provided_host=None,
            evtx_profile=None,
            memory_authorization_acknowledged=True,
            folder_name=None,
            labels=None,
            notes=None,
            current_user=None,
        )

    assert getattr(exc.value, "code", None) == "MEMORY_UPLOAD_HOST_REQUIRED"
    assert db.query(Evidence).count() == 0
    assert db.query(MemoryUpload).count() == 0


def test_promote_memory_session_without_host_returns_structured_api_error(tmp_path, monkeypatch):
    monkeypatch.setattr(settings, "backend_temp_dir", tmp_path / "tmp")
    monkeypatch.setattr(settings, "backend_data_dir", tmp_path / "data")
    monkeypatch.setattr(settings, "memory_upload_enabled", True)
    monkeypatch.setattr(settings, "memory_upload_max_bytes", 64 * 1024 * 1024)
    monkeypatch.setattr(settings, "memory_max_upload_size", 64 * 1024 * 1024)
    monkeypatch.setattr(settings, "memory_upload_case_quota_bytes", 256 * 1024 * 1024)
    monkeypatch.setattr("app.services.memory.upload_sessions._capacity_snapshot", lambda *args, **kwargs: {"can_accept_selected_size": True})
    db = _db()
    _case(db)
    client = _client(db)
    ram_path = tmp_path / "capture.mem"
    ram_path.write_bytes(b"RAM" * 1024)
    session, report = create_upload_session(db, CASE_ID, files=[_upload_file(ram_path)], declared_platform=None, client_sha256=None)
    assert report.classification.category == "memory_dump"

    response = client.post(
        f"/api/cases/{CASE_ID}/evidence-uploads/{session.id}/promote",
        json={"provided_platform": None, "host_id": None, "memory_authorization_acknowledged": True},
    )

    assert response.status_code == 400
    assert response.json()["detail"] == {
        "error_code": "MEMORY_UPLOAD_HOST_REQUIRED",
        "code": "MEMORY_UPLOAD_HOST_REQUIRED",
        "message": "Source host is required for memory evidence registration.",
    }
    assert db.query(Evidence).count() == 0
    assert db.query(MemoryUpload).count() == 0


def test_promote_memory_session_rejects_host_from_another_case(tmp_path, monkeypatch):
    monkeypatch.setattr(settings, "backend_temp_dir", tmp_path / "tmp")
    monkeypatch.setattr(settings, "backend_data_dir", tmp_path / "data")
    monkeypatch.setattr(settings, "memory_upload_enabled", True)
    monkeypatch.setattr(settings, "memory_upload_max_bytes", 64 * 1024 * 1024)
    monkeypatch.setattr(settings, "memory_max_upload_size", 64 * 1024 * 1024)
    monkeypatch.setattr(settings, "memory_upload_case_quota_bytes", 256 * 1024 * 1024)
    monkeypatch.setattr("app.services.memory.upload_sessions._capacity_snapshot", lambda *args, **kwargs: {"can_accept_selected_size": True})
    db = _db()
    _case(db)
    other_case_id = "aaaaaaaa-3333-4333-8333-aaaaaaaaaaaa"
    _case(db, case_id=other_case_id)
    other_host = CaseHost(id="bbbbbbbb-3333-4333-8333-bbbbbbbbbbbb", case_id=other_case_id, canonical_name="OTHER-HOST", display_name="OTHER-HOST", confidence="manual", source="manual")
    db.add(other_host)
    db.commit()
    ram_path = tmp_path / "capture.mem"
    ram_path.write_bytes(b"RAM" * 1024)
    session, report = create_upload_session(db, CASE_ID, files=[_upload_file(ram_path)], declared_platform=None, client_sha256=None)
    assert report.classification.category == "memory_dump"

    with pytest.raises(Exception) as exc:
        promote_upload_session(
            db,
            session,
            provided_platform=None,
            host_id=other_host.id,
            provided_host=None,
            evtx_profile=None,
            memory_authorization_acknowledged=True,
            folder_name=None,
            labels=None,
            notes=None,
            current_user=None,
        )

    assert getattr(exc.value, "code", None) == "MEMORY_UPLOAD_HOST_REQUIRED"
    assert db.query(Evidence).count() == 0
    assert db.query(MemoryUpload).count() == 0


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
