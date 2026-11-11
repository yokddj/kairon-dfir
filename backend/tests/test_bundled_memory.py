"""A memory image inside a collection: found even without a header or firmware tables, and
registered as its own memory evidence from the extracted file, without uploading it again."""

from __future__ import annotations

import os
import struct
import uuid
from pathlib import Path
from types import SimpleNamespace

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from app.api import routes_bundled_memory
from app.core.config import get_settings
from app.core.database import Base, get_db
from app.core.storage import build_evidence_root
from app.ingest import bundled_evidence as bundled
from app.models.case import Case
from app.models.evidence import Evidence
from app.models.evidence_upload_session import EvidenceUploadSession
from app.services import bundled_memory
from app.services.memory import probe as probe_module
from app.workers import tasks

settings = get_settings()
CASE_ID = "dddddddd-4444-4444-8444-dddddddddddd"
EV_COLLECTION = "eeeeeeee-5555-4555-8555-eeeeeeeeeeee"
EV_MEMORY = "ffffffff-6666-4666-8666-ffffffffffff"
MIB = 1024 * 1024
WINDOWS_KERNEL = b"RSDS" + uuid.UUID("11D7FE79-CC24-5612-0555-03EE86BB0E3E").bytes_le + struct.pack("<I", 1) + b"ntkrnlmp.pdb\x00"


def _sparse(path: Path, size: int, writes: dict[int, bytes]) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("wb") as handle:
        for offset, data in writes.items():
            handle.seek(offset)
            handle.write(data)
        handle.truncate(size)
    return path


@pytest.fixture(autouse=True)
def _fresh_scan_cache():
    probe_module._cached_kernel_scan.cache_clear()
    yield
    probe_module._cached_kernel_scan.cache_clear()


# --- finding it ------------------------------------------------------------------------------


def _dispatch(extract_dir: Path, rel_paths: list[str]) -> list[dict]:
    entries = [{"path": rel, "status": "extracted", "size": (extract_dir / rel).stat().st_size} for rel in rel_paths]
    _files, result_entries, _mat = tasks._classify_and_dispatch_extracted(
        db=None, evidence=SimpleNamespace(id="ev-1", case_id=CASE_ID), extract_dir=extract_dir, extracted_files=list(rel_paths), archive_entries=entries
    )
    return result_entries


def test_a_headerless_windows_capture_without_firmware_tables_is_found_in_a_collection(tmp_path):
    rel = "host02/ram/2026-11-01/host02-capture.dd"
    _sparse(tmp_path / rel, 300 * MIB, {150 * MIB: WINDOWS_KERNEL, 180 * MIB: WINDOWS_KERNEL})
    (tmp_path / "host02/logs").mkdir(parents=True)
    (tmp_path / "host02/logs/notes.txt").write_text("triage notes")
    flagged = {entry["path"]: entry.get("bundled_evidence") for entry in _dispatch(tmp_path, [rel, "host02/logs/notes.txt"])}
    assert flagged[rel] == "memory_dump"
    assert flagged["host02/logs/notes.txt"] is None


def test_windows_paging_files_are_never_memory_images(tmp_path):
    rel = "C/pagefile.sys"
    _sparse(tmp_path / rel, 300 * MIB, {150 * MIB: WINDOWS_KERNEL, 180 * MIB: WINDOWS_KERNEL})
    assert not bundled.wants_kernel_scan(tmp_path / rel)
    assert [entry.get("bundled_evidence") for entry in _dispatch(tmp_path, [rel])] == [None]


def test_small_unidentified_files_are_not_searched(tmp_path):
    assert not bundled.wants_kernel_scan(_sparse(tmp_path / "blob.bin", 10 * MIB, {}))


# --- registering it ----------------------------------------------------------------------------


@pytest.fixture()
def env(tmp_path, monkeypatch):
    engine = create_engine("sqlite:///:memory:", connect_args={"check_same_thread": False}, poolclass=StaticPool, future=True)
    Base.metadata.create_all(engine)
    make_session = sessionmaker(bind=engine, future=True)
    db = make_session()
    monkeypatch.setattr(settings, "backend_data_dir", tmp_path / "data")
    monkeypatch.setattr(settings, "backend_temp_dir", tmp_path / "tmp")
    monkeypatch.setattr(settings, "backend_max_upload_size", 64 * 1024 * MIB)
    monkeypatch.setattr(settings, "auth_enabled", False)
    db.add(Case(id=CASE_ID, name="Collection case", description="", status="active", priority="medium", management_tags=[]))
    evidence = Evidence(id=EV_COLLECTION, case_id=CASE_ID, original_filename="hosts.zip", stored_path=str(tmp_path / "hosts.zip"), evidence_type="unknown", ingest_status="completed", size_bytes=4096)
    member = "host02/ram/host02-capture.dd"
    evidence.metadata_json = {"bundled_evidence": [{"path": member, "kind": "memory_dump", "label": "Memory image", "size_bytes": 4096}, {"path": "cap.pcap", "kind": "pcap", "label": "Packet capture"}]}
    db.add(evidence)
    db.commit()
    source = build_evidence_root(CASE_ID, evidence.id) / "extracted" / member
    source.parent.mkdir(parents=True, exist_ok=True)
    source.write_bytes(b"\0" * 4096)
    queued: list[str] = []
    monkeypatch.setattr("app.workers.tasks.enqueue_bundled_memory_registration", lambda session_id: queued.append(session_id) or "job-1")
    monkeypatch.setattr("app.services.evidence_operations.sync_upload_operation", lambda *a, **k: None)
    monkeypatch.setattr(routes_bundled_memory, "log_audit", lambda *a, **k: None)
    monkeypatch.setattr("app.core.database.SessionLocal", make_session)
    app = FastAPI()
    app.include_router(routes_bundled_memory.router)
    app.dependency_overrides[get_db] = lambda: db
    return {"db": db, "client": TestClient(app), "queued": queued, "member": member, "source": source, "make_session": make_session}


def _post(env, **body):
    return env["client"].post(f"/api/cases/{CASE_ID}/evidences/{EV_COLLECTION}/bundled-memory", json={"path": env["member"], "provided_host": "HOST02", **body})


def test_registration_links_the_extracted_file_into_a_new_upload_session(env):
    response = _post(env)
    assert response.status_code == 202, response.text
    session_id = response.json()["upload_session_id"]
    assert env["queued"] == [session_id]
    session = env["db"].get(EvidenceUploadSession, session_id)
    staged = Path(session.staged_path)
    assert staged.read_bytes() == env["source"].read_bytes()
    assert os.stat(staged).st_ino == os.stat(env["source"]).st_ino  # hard link: nothing copied
    assert session.metadata_json["upload_mode"] == "bundled_member"
    assert session.metadata_json["bundled_source"] == {"evidence_id": EV_COLLECTION, "path": env["member"], "placement": "hardlink"}
    listed = env["db"].get(Evidence, EV_COLLECTION).metadata_json["bundled_evidence"][0]
    assert listed["registration_status"] == "queued" and listed["registration_session_id"] == session_id
    assert _post(env).status_code == 400  # already being registered


@pytest.mark.parametrize(
    "body, message",
    [
        ({"path": "cap.pcap"}, "Only a memory image"),
        ({"path": "not/listed.dd"}, "not listed"),
        ({"provided_host": ""}, "Choose the host"),
    ],
)
def test_registration_refuses_what_it_cannot_register(env, body, message):
    response = _post(env, **body)
    assert response.status_code == 400 and message in response.json()["detail"]


def test_a_listed_path_cannot_escape_the_extraction_directory(env):
    evidence = env["db"].get(Evidence, EV_COLLECTION)
    with pytest.raises(bundled_memory.BundledMemoryError):
        bundled_memory.member_file(evidence, "../../../../etc/passwd")


def test_another_cases_evidence_is_not_found(env):
    response = env["client"].post(f"/api/cases/other-case/evidences/{EV_COLLECTION}/bundled-memory", json={"path": env["member"], "provided_host": "H"})
    assert response.status_code == 404


def test_the_worker_preflights_then_registers_it_as_memory_and_records_both_ends(env, monkeypatch):
    session_id = _post(env).json()["upload_session_id"]
    promoted: dict = {}

    def fake_preflight(sid):
        with env["make_session"]() as db:
            session = db.get(EvidenceUploadSession, sid)
            session.status = "staged"
            session.metadata_json = {**session.metadata_json, "category": "memory_dump"}
            db.commit()
        return {"status": "completed"}

    def fake_promote(db, session, **kwargs):
        promoted.update(kwargs)
        evidence = Evidence(id=EV_MEMORY, case_id=CASE_ID, original_filename=session.original_filename, stored_path=session.staged_path, evidence_type="memory_dump", ingest_status="pending", size_bytes=4096)
        db.add(evidence)
        db.commit()
        return evidence

    monkeypatch.setattr("app.workers.tasks.run_evidence_upload_preflight", fake_preflight)
    monkeypatch.setattr("app.services.evidence_upload_session.promote_upload_session", fake_promote)
    assert bundled_memory.run_registration(session_id) == {"status": "registered", "upload_session_id": session_id, "evidence_id": EV_MEMORY}
    assert promoted["provided_host"] == "HOST02" and promoted["memory_authorization_acknowledged"] is True
    assert env["member"] in promoted["notes"] and "hosts.zip" in promoted["notes"]
    with env["make_session"]() as db:
        listed = db.get(Evidence, EV_COLLECTION).metadata_json["bundled_evidence"][0]
        assert listed["registration_status"] == "registered" and listed["registered_evidence_id"] == EV_MEMORY
        assert db.get(Evidence, EV_MEMORY).metadata_json["bundled_source"] == {"evidence_id": EV_COLLECTION, "path": env["member"]}


def test_a_member_the_inspection_does_not_confirm_as_memory_is_not_registered(env, monkeypatch):
    session_id = _post(env).json()["upload_session_id"]

    def fake_preflight(sid):
        with env["make_session"]() as db:
            session = db.get(EvidenceUploadSession, sid)
            session.status = "staged"
            session.metadata_json = {**session.metadata_json, "category": "unknown"}
            db.commit()
        return {"status": "completed"}

    monkeypatch.setattr("app.workers.tasks.run_evidence_upload_preflight", fake_preflight)
    monkeypatch.setattr("app.services.evidence_upload_session.promote_upload_session", lambda *a, **k: pytest.fail("must not register"))
    result = bundled_memory.run_registration(session_id)
    assert result["status"] == "failed" and "did not confirm a memory image" in result["error"]
    with env["make_session"]() as db:
        listed = db.get(Evidence, EV_COLLECTION).metadata_json["bundled_evidence"][0]
        assert listed["registration_status"] == "failed" and "did not confirm" in listed["registration_error"]
