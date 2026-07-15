"""Preflight Inspection coverage.

Exercises app.services.evidence_preflight.run_preflight() directly (unit
level) and POST /api/cases/{case_id}/evidence-preflight (API level),
verifying: no worker job is started, no Artifact/Evidence/processing-queue
row is created, classification and resource estimation are correct, and
configuration-aware diagnostics are produced for each blocking condition.
"""
from __future__ import annotations

import subprocess
import zipfile
from pathlib import Path

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from app.api import routes_evidence_preflight
from app.core.database import Base, get_db
from app.core.config import get_settings
from app.models.artifact import Artifact
from app.models.case import Case
from app.models.evidence import Evidence
from app.services.evidence_preflight import run_preflight

settings = get_settings()

CASE_ID = "aaaaaaaa-1111-4111-8111-aaaaaaaaaaaa"


def _require_tools(*names: str) -> None:
    missing = [name for name in names if subprocess.run(["bash", "-lc", f"command -v {name} >/dev/null 2>&1"], check=False).returncode != 0]
    if missing:
        pytest.skip(f"Missing required tool(s): {', '.join(missing)}")


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
    item = Case(id=case_id, name="Preflight Case", description="", status="active", priority="medium", management_tags=[])
    db.add(item)
    db.commit()
    return item


def _make_linux_zip(path: Path) -> None:
    with zipfile.ZipFile(path, "w") as zf:
        zf.writestr("etc/hostname", "web01\n")
        zf.writestr("etc/os-release", 'PRETTY_NAME="Ubuntu 24.04 LTS"\nID=ubuntu\nVERSION_ID="24.04"\n')
        zf.writestr("var/log/auth.log", "auth log content\n" * 50)
        zf.writestr("etc/cron.d/mycron", "* * * * * root echo hi\n")
        zf.writestr("etc/ssh/sshd_config", "PermitRootLogin no\n")


# ---------------------------------------------------------------------------
# Unit-level: run_preflight()
# ---------------------------------------------------------------------------

def test_archive_classification_and_expected_parsers(tmp_path):
    zip_path = tmp_path / "collection.zip"
    _make_linux_zip(zip_path)

    report = run_preflight(zip_path, token="t1", original_filename="collection.zip", declared_platform=None, tmp_dir=tmp_path / "scratch")

    assert report.classification.category == "archive"
    assert report.classification.platform == "linux"
    assert report.classification.hostname == "web01"
    assert report.classification.distro == "Ubuntu 24.04 LTS"
    assert "linux auth" in report.classification.expected_parsers
    assert "linux cron" in report.classification.expected_parsers
    assert "linux ssh" in report.classification.expected_parsers
    assert report.pipeline_preview[0] == "Archive"
    assert report.pipeline_preview[-1] == "Timeline"
    assert report.status == "ready"
    assert report.diagnostics == []


def test_memory_dump_classification_by_extension(tmp_path):
    mem_path = tmp_path / "capture.mem"
    mem_path.write_bytes(b"\x00" * 4096)

    report = run_preflight(mem_path, token="t2", original_filename="capture.mem", declared_platform=None, tmp_dir=tmp_path / "scratch")

    assert report.classification.category == "memory_dump"
    assert "Memory Dump" in report.pipeline_preview
    assert report.resource_check.file_size_bytes == 4096


def test_unknown_evidence_is_low_confidence_and_not_blocking_alone(tmp_path):
    unknown_path = tmp_path / "notes.txt"
    unknown_path.write_text("just some notes, not evidence", encoding="utf-8")

    report = run_preflight(unknown_path, token="t3", original_filename="notes.txt", declared_platform=None, tmp_dir=tmp_path / "scratch")

    assert report.classification.category == "unknown"
    assert report.status == "blocked"
    assert any(check.label == "Supported" and not check.ok for check in report.status_checks)
    assert any(d.problem == "Low confidence classification" for d in report.diagnostics)


def test_nested_archive_depth_exceeded(tmp_path, monkeypatch):
    monkeypatch.setattr(settings, "max_archive_depth", 1)
    inner = tmp_path / "inner.zip"
    with zipfile.ZipFile(inner, "w") as zf:
        zf.writestr("etc/hostname", "inner-host\n")
    outer = tmp_path / "outer.zip"
    with zipfile.ZipFile(outer, "w") as zf:
        zf.write(inner, "inner.zip")

    report = run_preflight(outer, token="t4", original_filename="outer.zip", declared_platform=None, tmp_dir=tmp_path / "scratch")

    assert report.resource_check.detected_archive_depth is not None
    assert report.resource_check.detected_archive_depth >= 2
    assert report.status == "blocked"
    diag = next(d for d in report.diagnostics if d.problem == "Nested archives too deep")
    assert diag.configuration_key == "MAX_ARCHIVE_DEPTH"
    assert diag.configuration_file == "backend/.env"
    assert diag.how_to_fix


def test_upload_limit_exceeded_diagnostic(tmp_path, monkeypatch):
    monkeypatch.setattr(settings, "backend_max_upload_size", 100)
    zip_path = tmp_path / "collection.zip"
    _make_linux_zip(zip_path)

    report = run_preflight(zip_path, token="t5", original_filename="collection.zip", declared_platform=None, tmp_dir=tmp_path / "scratch")

    assert report.status == "blocked"
    check = next(c for c in report.status_checks if c.label == "Within upload limit")
    assert not check.ok
    diag = next(d for d in report.diagnostics if d.problem == "Upload limit exceeded")
    assert diag.configuration_key == "BACKEND_MAX_UPLOAD_SIZE"
    assert diag.configuration_file == "backend/.env"
    assert any("upgrade.sh" in step for step in diag.how_to_fix)


def test_extraction_limit_exceeded_diagnostic(tmp_path, monkeypatch):
    monkeypatch.setattr(settings, "backend_max_extracted_bytes", 10)
    zip_path = tmp_path / "collection.zip"
    _make_linux_zip(zip_path)

    report = run_preflight(zip_path, token="t6", original_filename="collection.zip", declared_platform=None, tmp_dir=tmp_path / "scratch")

    assert report.status == "blocked"
    diag = next(d for d in report.diagnostics if d.problem == "Extraction size exceeded")
    assert diag.configuration_key == "BACKEND_MAX_EXTRACTED_BYTES"


def test_insufficient_storage_diagnostic(tmp_path, monkeypatch):
    zip_path = tmp_path / "collection.zip"
    _make_linux_zip(zip_path)

    import app.services.evidence_preflight as preflight_module

    fake_usage = type("Usage", (), {"free": 10})()
    monkeypatch.setattr(preflight_module.shutil, "disk_usage", lambda _path: fake_usage)

    report = run_preflight(zip_path, token="t7", original_filename="collection.zip", declared_platform=None, tmp_dir=tmp_path / "scratch")

    assert report.status == "blocked"
    diag = next(d for d in report.diagnostics if d.problem == "Temporary storage too low")
    assert diag.configuration_key == "BACKEND_TEMP_DIR"


def test_folder_is_inspected_like_an_archive(tmp_path):
    folder = tmp_path / "collection"
    (folder / "etc").mkdir(parents=True)
    (folder / "etc" / "hostname").write_text("folder-host\n", encoding="utf-8")
    (folder / "var" / "log").mkdir(parents=True)
    (folder / "var" / "log" / "auth.log").write_text("auth\n" * 10, encoding="utf-8")

    report = run_preflight(folder, token="t8", original_filename="collection", declared_platform=None, tmp_dir=tmp_path / "scratch")

    assert report.classification.platform == "linux"
    assert report.classification.hostname == "folder-host"
    assert report.pipeline_preview[0] == "Folder"


def test_disk_image_volume_discovery(tmp_path):
    _require_tools("parted", "mkfs.vfat", "mcopy", "mmd", "dd")
    fs_image = tmp_path / "fs.img"
    subprocess.run(["mkfs.vfat", "-C", str(fs_image), "16384"], check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    disk_path = tmp_path / "disk.dd"
    disk_path.write_bytes(b"\x00" * (32 * 1024 * 1024))
    subprocess.run(["parted", "-s", str(disk_path), "mklabel", "msdos", "mkpart", "primary", "fat32", "1MiB", "17MiB"], check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    subprocess.run(["dd", f"if={fs_image}", f"of={disk_path}", "bs=1M", "seek=1", "conv=notrunc"], check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

    report = run_preflight(disk_path, token="t9", original_filename="disk.dd", declared_platform=None, tmp_dir=tmp_path / "scratch")

    assert report.classification.category == "disk_image"
    assert report.classification.format_key == "raw"
    assert report.classification.volumes == 1
    assert report.resource_check.estimated_extracted_bytes and report.resource_check.estimated_extracted_bytes > 0


# ---------------------------------------------------------------------------
# API-level: no side effects, correct HTTP behavior
# ---------------------------------------------------------------------------

def test_preflight_endpoint_creates_no_evidence_artifact_or_queue_entry(monkeypatch, tmp_path):
    monkeypatch.setattr(settings, "backend_temp_dir", tmp_path)
    enqueue_calls = []
    monkeypatch.setattr("app.workers.tasks.enqueue_ingest", lambda *args, **kwargs: enqueue_calls.append((args, kwargs)))

    db = _db()
    _case(db)
    client = _client(db)

    zip_path = tmp_path / "upload.zip"
    _make_linux_zip(zip_path)
    with zip_path.open("rb") as fh:
        response = client.post(f"/api/cases/{CASE_ID}/evidence-preflight", files={"files": ("upload.zip", fh, "application/zip")})

    assert response.status_code == 200
    payload = response.json()
    assert payload["status"] == "ready"
    assert payload["classification"]["hostname"] == "web01"
    assert db.query(Evidence).count() == 0
    assert db.query(Artifact).count() == 0
    assert enqueue_calls == []
    # The staged upload must be cleaned up, not left behind.
    assert not (tmp_path / "preflight").exists() or not any((tmp_path / "preflight").iterdir())


def test_preflight_endpoint_missing_case_returns_404(tmp_path, monkeypatch):
    monkeypatch.setattr(settings, "backend_temp_dir", tmp_path)
    db = _db()
    client = _client(db)
    zip_path = tmp_path / "upload.zip"
    _make_linux_zip(zip_path)
    with zip_path.open("rb") as fh:
        response = client.post(f"/api/cases/{CASE_ID}/evidence-preflight", files={"files": ("upload.zip", fh, "application/zip")})
    assert response.status_code == 404


def test_preflight_endpoint_requires_a_file_or_path(tmp_path, monkeypatch):
    monkeypatch.setattr(settings, "backend_temp_dir", tmp_path)
    db = _db()
    _case(db)
    client = _client(db)
    response = client.post(f"/api/cases/{CASE_ID}/evidence-preflight", data={})
    assert response.status_code == 400


def test_preflight_endpoint_server_path(monkeypatch, tmp_path):
    import app.core.evidence_paths as evidence_paths_module

    monkeypatch.setattr(settings, "backend_temp_dir", tmp_path / "tmp")
    allowed_root = tmp_path / "evidence"
    allowed_root.mkdir(parents=True, exist_ok=True)
    monkeypatch.setattr(evidence_paths_module.settings, "dfir_allow_host_path_import", True)
    monkeypatch.setattr(evidence_paths_module.settings, "dfir_allowed_evidence_roots", str(allowed_root))

    zip_path = allowed_root / "collection.zip"
    _make_linux_zip(zip_path)

    db = _db()
    _case(db)
    client = _client(db)

    response = client.post(f"/api/cases/{CASE_ID}/evidence-preflight", data={"server_path": str(zip_path)})

    assert response.status_code == 200
    payload = response.json()
    assert payload["classification"]["hostname"] == "web01"
    assert db.query(Evidence).count() == 0
