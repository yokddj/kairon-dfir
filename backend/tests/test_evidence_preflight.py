"""Preflight Inspection coverage.

Exercises app.services.evidence_preflight.run_preflight() directly: no
worker job is started (it never enqueues anything), no Artifact/Evidence
row is created (it never imports a DB Session), classification and
resource estimation are correct, and configuration-aware diagnostics are
produced for each blocking condition.

API-level coverage (creating an upload session, promoting it, cancelling
it, the health check endpoint) lives in test_evidence_upload_session.py,
which exercises the current app.api.routes_evidence_preflight endpoints -
the old ephemeral-only POST .../evidence-preflight endpoint this file used
to test was superseded by the session-based endpoints in v2.1.
"""
from __future__ import annotations

import subprocess
import zipfile
from pathlib import Path

import pytest

from app.core.config import get_settings
from app.services.evidence_preflight import run_preflight

settings = get_settings()


def _require_tools(*names: str) -> None:
    missing = [name for name in names if subprocess.run(["bash", "-lc", f"command -v {name} >/dev/null 2>&1"], check=False).returncode != 0]
    if missing:
        pytest.skip(f"Missing required tool(s): {', '.join(missing)}")


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


def test_memory_dump_is_not_subject_to_extraction_limit(tmp_path, monkeypatch):
    # Memory dumps are staged as-is - nothing is ever extracted from them
    # (app.ingest.archive._enforce_limits is never invoked for this
    # category) - so a memory image larger than the configured extraction
    # limit must not be blocked by the "Within extraction limit" check.
    # Regression test for the evidence-wizard memory_dump intake
    # incorrectly reusing estimated_extracted_bytes=file_size.
    monkeypatch.setattr(settings, "backend_max_extracted_bytes", 100)
    mem_path = tmp_path / "capture.mem"
    mem_path.write_bytes(b"\x00" * 4096)

    report = run_preflight(mem_path, token="t2b", original_filename="capture.mem", declared_platform=None, tmp_dir=tmp_path / "scratch")

    assert report.resource_check.estimated_extracted_bytes is None
    assert not any(d.problem == "Extraction size exceeded" for d in report.diagnostics)
    assert not any(c.label == "Within extraction limit" for c in report.status_checks)


def _make_minimal_mbr_disk_image(path: Path, *, partition_bytes: int) -> None:
    """Hand-crafted MBR with one allocated partition -- avoids depending on
    parted/mkfs.vfat (not installed in every environment) purely to get
    pytsk3.Volume_Info to recognize a partition table with a known,
    controllable declared size. The partition's filesystem is deliberately
    left unrecognizable (all zero bytes): this only needs the volume to be
    *discovered* (and its declared length counted), not readable --
    matching the real-world case this fix targets (e.g. an LVM physical
    volume Kairon's OS discovery cannot parse, so no installation is found
    but the volume and its size are still reported)."""
    sector_size = 512
    start_lba = 2048
    num_sectors = partition_bytes // sector_size
    mbr = bytearray(512)
    entry_offset = 446
    mbr[entry_offset + 0] = 0x00
    mbr[entry_offset + 4] = 0x83  # Linux partition type
    mbr[entry_offset + 8:entry_offset + 12] = start_lba.to_bytes(4, "little")
    mbr[entry_offset + 12:entry_offset + 16] = num_sectors.to_bytes(4, "little")
    mbr[510] = 0x55
    mbr[511] = 0xAA
    total_size = (start_lba + num_sectors) * sector_size
    with path.open("wb") as fh:
        fh.write(bytes(mbr))
        fh.seek(total_size - 1)
        fh.write(b"\x00")


def test_disk_image_is_not_subject_to_extraction_limit(tmp_path, monkeypatch):
    # BACKEND_MAX_EXTRACTED_BYTES guards app.ingest.archive's real
    # decompression-bomb risk -- a risk that does not exist for disk
    # images (you cannot extract more bytes than the image physically
    # contains), which are already bounded by their own dedicated settings
    # (disk_image_max_bytes_per_volume, disk_image_virtual_size_max_bytes).
    # A tiny configured limit here proves the check is skipped entirely
    # for this category, not merely satisfied because the estimate happens
    # to be small -- the discovered volume is deliberately made to exceed
    # it by a wide margin.
    monkeypatch.setattr(settings, "backend_max_extracted_bytes", 100)
    disk_path = tmp_path / "disk.dd"
    _make_minimal_mbr_disk_image(disk_path, partition_bytes=8 * 1024 * 1024)

    report = run_preflight(disk_path, token="t14", original_filename="disk.dd", declared_platform=None, tmp_dir=tmp_path / "scratch")

    assert report.classification.category == "disk_image"
    assert report.classification.volumes == 1
    assert report.classification.installations == 0  # unreadable filesystem, matching the LVM real-world case
    assert report.resource_check.estimated_extracted_bytes is not None
    assert report.resource_check.estimated_extracted_bytes > 100
    assert not any(c.label == "Within extraction limit" for c in report.status_checks)
    assert not any(d.problem == "Extraction size exceeded" for d in report.diagnostics)
    assert report.status != "blocked"


def test_archive_still_blocked_by_extraction_limit_disk_image_is_not(tmp_path, monkeypatch):
    # Same tiny limit applied to both categories in one test: proves the
    # fix is scoped precisely to disk images, not a blanket disable of the
    # archive decompression-bomb guard.
    monkeypatch.setattr(settings, "backend_max_extracted_bytes", 10)

    zip_path = tmp_path / "collection.zip"
    _make_linux_zip(zip_path)
    archive_report = run_preflight(zip_path, token="t15a", original_filename="collection.zip", declared_platform=None, tmp_dir=tmp_path / "scratch_archive")
    assert archive_report.status == "blocked"
    assert any(c.label == "Within extraction limit" and not c.ok for c in archive_report.status_checks)

    disk_path = tmp_path / "disk.dd"
    _make_minimal_mbr_disk_image(disk_path, partition_bytes=8 * 1024 * 1024)
    disk_report = run_preflight(disk_path, token="t15b", original_filename="disk.dd", declared_platform=None, tmp_dir=tmp_path / "scratch_disk")
    assert not any(c.label == "Within extraction limit" for c in disk_report.status_checks)


def test_memory_dump_upload_limit_matches_dedicated_memory_pipeline(tmp_path, monkeypatch):
    # The evidence wizard's memory_dump intake must enforce the same
    # upload-size limit as the dedicated Memory Overview pipeline
    # (memory_upload_max_bytes), not the legacy memory_max_upload_size
    # fallback - otherwise a memory image that uploads fine via Memory
    # Overview can be rejected by preflight when routed through the
    # wizard instead.
    monkeypatch.setattr(settings, "memory_upload_max_bytes", 5000)
    monkeypatch.setattr(settings, "memory_max_upload_size", 100)
    mem_path = tmp_path / "capture.mem"
    mem_path.write_bytes(b"\x00" * 4096)

    report = run_preflight(mem_path, token="t2c", original_filename="capture.mem", declared_platform=None, tmp_dir=tmp_path / "scratch")

    assert report.resource_check.configured_upload_limit_bytes == 5000
    check = next(c for c in report.status_checks if c.label == "Within upload limit")
    assert check.ok


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
    assert report.classification.partitions == 1
    assert report.classification.container == "RAW disk image"
    assert report.classification.contained_object and "volume" in report.classification.contained_object
    assert len(report.classification.filesystems) == 1
    assert report.resource_check.estimated_extracted_bytes and report.resource_check.estimated_extracted_bytes > 0


# ---------------------------------------------------------------------------
# v2.1 refinement: richer report fields (container, contained object,
# duration bucket, warning/diagnostic severity)
# ---------------------------------------------------------------------------

def test_archive_report_has_container_and_contained_object(tmp_path):
    zip_path = tmp_path / "collection.zip"
    _make_linux_zip(zip_path)

    report = run_preflight(zip_path, token="t10", original_filename="collection.zip", declared_platform=None, tmp_dir=tmp_path / "scratch")

    assert report.classification.container == "ZIP archive"
    assert report.classification.contained_object is not None
    assert "artifact collection" in report.classification.contained_object
    assert report.resource_check.estimated_duration_bucket == "fast"


def test_low_confidence_diagnostic_has_recommendation_severity(tmp_path):
    unknown_path = tmp_path / "notes.txt"
    unknown_path.write_text("just some notes, not evidence", encoding="utf-8")

    report = run_preflight(unknown_path, token="t11", original_filename="notes.txt", declared_platform=None, tmp_dir=tmp_path / "scratch")

    diag = next(d for d in report.diagnostics if d.problem == "Low confidence classification")
    assert diag.severity == "recommendation"


def test_upload_limit_diagnostic_is_blocking_severity(tmp_path, monkeypatch):
    monkeypatch.setattr(settings, "backend_max_upload_size", 100)
    zip_path = tmp_path / "collection.zip"
    _make_linux_zip(zip_path)

    report = run_preflight(zip_path, token="t12", original_filename="collection.zip", declared_platform=None, tmp_dir=tmp_path / "scratch")

    diag = next(d for d in report.diagnostics if d.problem == "Upload limit exceeded")
    assert diag.severity == "blocking"


def test_warnings_are_classified_by_severity(tmp_path, monkeypatch):
    import app.services.evidence_preflight as preflight_module

    monkeypatch.setattr(preflight_module, "open_evidence_container", lambda *_a, **_k: (_ for _ in ()).throw(RuntimeError("boom")))
    zip_path = tmp_path / "collection.zip"
    _make_linux_zip(zip_path)

    report = run_preflight(zip_path, token="t13", original_filename="collection.zip", declared_platform=None, tmp_dir=tmp_path / "scratch")

    assert report.classification.warnings
    warning = report.classification.warnings[0]
    assert warning.severity == "recommendation"
    assert "could not" in warning.message.lower()


def test_duration_bucket_thresholds():
    from app.services.evidence_preflight import _duration_bucket

    assert _duration_bucket(None) is None
    assert _duration_bucket(30) == "fast"
    assert _duration_bucket(119) == "fast"
    assert _duration_bucket(600) == "medium"
    assert _duration_bucket(3600) == "long"
    assert _duration_bucket(10800) == "very_long"
