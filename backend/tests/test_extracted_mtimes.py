from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path
import struct
import zipfile

from app.ingest.archive import extract_archive, zip_member_mtime
from app.ingest.velociraptor.zip_inventory import ZipEvidenceContainer

RECORDED = datetime(2019, 12, 7, 9, 12, 46, tzinfo=UTC).timestamp()


def _zip(path: Path) -> Path:
    with zipfile.ZipFile(path, "w") as archive:
        info = zipfile.ZipInfo("challenge/Windows/profile.ps1", date_time=(2019, 12, 7, 9, 12, 46))
        archive.writestr(info, b"Write-Host hi")
        # Extended timestamp (UTC) wins over the zone-less DOS time.
        info = zipfile.ZipInfo("challenge/notes.txt", date_time=(2001, 1, 1, 0, 0, 0))
        info.extra = struct.pack("<HHBi", 0x5455, 5, 1, int(RECORDED) + 3600)
        archive.writestr(info, b"hello")
        archive.writestr(zipfile.ZipInfo("challenge/undated.txt", date_time=(1980, 1, 1, 0, 0, 0)), b"x")
    return path


def test_member_mtime_prefers_the_utc_extra_field(tmp_path):
    with zipfile.ZipFile(_zip(tmp_path / "c.zip")) as archive:
        assert zip_member_mtime(archive.getinfo("challenge/Windows/profile.ps1")) == RECORDED
        assert zip_member_mtime(archive.getinfo("challenge/notes.txt")) == RECORDED + 3600
        assert zip_member_mtime(archive.getinfo("challenge/undated.txt")) is None


def test_extracted_copies_keep_the_recorded_time(tmp_path):
    archive = _zip(tmp_path / "c.zip")
    results = ZipEvidenceContainer(archive).extract_entries(["challenge/Windows/profile.ps1", "challenge/notes.txt"], tmp_path / "selected")
    assert [item["status"] for item in results] == ["extracted", "extracted"]
    assert (tmp_path / "selected/challenge/Windows/profile.ps1").stat().st_mtime == RECORDED
    single = ZipEvidenceContainer(archive).extract_entry("challenge/Windows/profile.ps1", tmp_path / "single")
    assert single.stat().st_mtime == RECORDED

    extract_archive(archive, tmp_path / "full")
    assert (tmp_path / "full/challenge/notes.txt").stat().st_mtime == RECORDED + 3600
