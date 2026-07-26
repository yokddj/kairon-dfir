"""Regression coverage for the ingest-watchdog heartbeat gap discovered
while validating PR3 (LVM integration) against real evidence: a Logical
Volume's own root filesystem can now be walked and have files extracted
from it -- something that never happened before PR3 (an LVM Physical
Volume was always immediately "unreadable"). For a real, large Linux
installation, that walk can run long enough to exceed
job_watchdog.py's STALE_INGEST_HEARTBEAT_SECONDS (600s), because
materialize_disk_image_sources previously only touched progress_cb (which
refreshes the ingest heartbeat) at coarse phase boundaries -- never during
the walk itself.

_materialize_volume_installation now calls progress_cb periodically
(time-based, not file-count-based -- see its own comment for why) during
that walk. This is a general fix (it benefits any large filesystem, not
LVM-specific), verified here directly against a real pytsk3.FS_Info over a
small FAT filesystem, with time.monotonic patched so the test does not
need to wait out a real 5-second interval.
"""

from __future__ import annotations

import shutil
import subprocess
from pathlib import Path
from types import SimpleNamespace

import pytest
import pytsk3

from app.disk_images import service as disk_image_service


def _require_tools(*names: str) -> None:
    missing = [name for name in names if shutil.which(name) is None]
    if missing:
        pytest.skip(f"Missing required tool(s): {', '.join(missing)}")


def _build_fat_filesystem(tmp_path: Path, files: dict[str, str], *, size_kib: int = 1408) -> Path:
    _require_tools("mkfs.vfat", "mcopy", "mmd")
    fs_image = tmp_path / "fs.img"
    subprocess.run(["mkfs.vfat", "-C", str(fs_image), str(size_kib)], check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    directories: set[str] = set()
    for relative_path, contents in files.items():
        source = tmp_path / "src" / relative_path
        source.parent.mkdir(parents=True, exist_ok=True)
        source.write_text(contents, encoding="utf-8")
        current = Path(relative_path).parent
        while str(current) not in {"", "."}:
            directories.add(str(current).replace("\\", "/"))
            current = current.parent
    for directory in sorted(directories, key=lambda item: (item.count("/"), item)):
        subprocess.run(["mmd", "-i", str(fs_image), f"::/{directory}"], check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    for relative_path in files:
        source = tmp_path / "src" / relative_path
        subprocess.run(["mcopy", "-i", str(fs_image), str(source), f"::/{relative_path}"], check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    return fs_image


def test_materialize_volume_installation_emits_heartbeat_progress_during_walk(tmp_path, monkeypatch):
    fs_image = _build_fat_filesystem(
        tmp_path,
        {
            "etc/os-release": 'PRETTY_NAME="Test"\n',
            "etc/passwd": "root:x:0:0:root:/root:/bin/bash\n",
            "var/log/auth.log": "Accepted password for root\n",
            "home/user/.bash_history": "whoami\n",
        },
    )
    img = pytsk3.Img_Info(str(fs_image))
    fs_info = pytsk3.FS_Info(img)

    # Force the very first time.monotonic() read inside the walk to already
    # be past the interval threshold, and every subsequent read to advance
    # by another full interval -- deterministic, no real sleep needed.
    fake_clock = {"value": 0.0}

    def fake_monotonic() -> float:
        fake_clock["value"] += disk_image_service._MATERIALIZE_PROGRESS_INTERVAL_SECONDS
        return fake_clock["value"]

    monkeypatch.setattr(disk_image_service.time, "monotonic", fake_monotonic)

    progress_calls: list[dict] = []

    def progress_cb(extra: dict) -> None:
        progress_calls.append(extra)

    install = SimpleNamespace(id="install-1", platform="linux", root_path="/")
    disk_image = SimpleNamespace(id="disk-image-1")
    volume = SimpleNamespace(id="volume-1", partition_index=1)

    extracted_files, manifest_entries, source_map, warnings = disk_image_service._materialize_volume_installation(
        fs_info=fs_info,
        install=install,
        disk_image=disk_image,
        volume=volume,
        destination_root=tmp_path / "extract",
        progress_cb=progress_cb,
    )

    assert len(extracted_files) == 4  # the walk itself is unaffected
    assert progress_calls, "progress_cb must be invoked during the walk, not only at coarse phase boundaries"
    assert all(call["current_action"] == "materializing_disk_image_files" for call in progress_calls)


def test_materialize_volume_installation_works_without_a_progress_cb(tmp_path):
    # progress_cb is optional -- a caller that doesn't pass one (e.g.
    # existing direct callers/tests) must be completely unaffected.
    fs_image = _build_fat_filesystem(tmp_path, {"etc/os-release": 'PRETTY_NAME="Test"\n'})
    img = pytsk3.Img_Info(str(fs_image))
    fs_info = pytsk3.FS_Info(img)

    install = SimpleNamespace(id="install-1", platform="linux", root_path="/")
    disk_image = SimpleNamespace(id="disk-image-1")
    volume = SimpleNamespace(id="volume-1", partition_index=1)

    extracted_files, manifest_entries, source_map, warnings = disk_image_service._materialize_volume_installation(
        fs_info=fs_info,
        install=install,
        disk_image=disk_image,
        volume=volume,
        destination_root=tmp_path / "extract",
    )

    assert len(extracted_files) == 1
