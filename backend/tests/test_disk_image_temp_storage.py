"""A thin virtual disk needs room for its real data, not its full virtual size, to be converted."""
from __future__ import annotations

import json
import subprocess
from pathlib import Path
from types import SimpleNamespace

import pytest

from app.disk_images import qemu as qemu_module
from app.services import evidence_preflight as preflight_module
from app.services.evidence_preflight import run_preflight
from tests.test_evidence_preflight import _make_minimal_mbr_disk_image, _require_tools

MIB = 1024 * 1024


@pytest.fixture()
def thin_vmdk(tmp_path: Path) -> Path:
    """A VMDK whose 64 MiB partition holds no data: tiny on disk, 64+ MiB virtual."""
    _require_tools("qemu-img")
    raw = tmp_path / "disk.dd"
    _make_minimal_mbr_disk_image(raw, partition_bytes=64 * MIB)
    vmdk = tmp_path / "disk.vmdk"
    subprocess.run(["qemu-img", "convert", "-f", "raw", "-O", "vmdk", str(raw), str(vmdk)], check=True)
    raw.unlink()
    return vmdk


def test_the_real_data_of_a_thin_disk_is_measured(thin_vmdk):
    data = qemu_module.allocated_data_bytes(thin_vmdk)
    assert data is not None and data < 8 * MIB


def _preflight(path: Path, tmp_path: Path, monkeypatch, free: int):
    monkeypatch.setattr(preflight_module.shutil, "disk_usage", lambda _path: SimpleNamespace(free=free))
    return run_preflight(path, token="t-thin", original_filename=path.name, declared_platform=None, tmp_dir=tmp_path / "scratch")


def test_enough_room_for_the_data_is_not_blocked_but_noted(thin_vmdk, tmp_path, monkeypatch):
    report = _preflight(thin_vmdk, tmp_path, monkeypatch, free=32 * MIB)   # well above the data, below the virtual size
    assert report.resource_check.estimated_temp_storage_bytes >= 64 * MIB
    assert not any(d.problem == "Temporary storage too low" for d in report.diagnostics)
    tight = next(d for d in report.diagnostics if d.problem == "Temporary storage is tight")
    assert tight.severity == "recommendation" and "sparse" in tight.reason
    storage = next(check for check in report.status_checks if check.label == "Enough storage")
    assert storage.ok and "worst case" in storage.detail


def test_no_room_even_for_the_data_is_blocked(thin_vmdk, tmp_path, monkeypatch):
    report = _preflight(thin_vmdk, tmp_path, monkeypatch, free=10)
    assert report.status == "blocked"
    assert any(d.problem == "Temporary storage too low" for d in report.diagnostics)


def test_unmeasurable_data_falls_back_to_the_virtual_size(thin_vmdk, tmp_path, monkeypatch):
    monkeypatch.setattr(preflight_module, "allocated_data_bytes", lambda _path: None)
    report = _preflight(thin_vmdk, tmp_path, monkeypatch, free=32 * MIB)
    assert report.status == "blocked"


def test_the_conversion_step_checks_the_same_figure(thin_vmdk, tmp_path):
    check = qemu_module._check_space_before_convert(64 * 1024 * MIB, tmp_path / "ws", thin_vmdk)
    assert check["data_bytes"] is not None and check["data_bytes"] < 8 * MIB
    assert check["needed_bytes"] == 256 * MIB   # the floor, far below the 64 GiB virtual size given


def test_map_output_is_summed_over_data_extents(monkeypatch, tmp_path):
    extents = [{"start": 0, "length": 4096, "data": True, "zero": False}, {"start": 4096, "length": 8192, "data": False, "zero": True},
               {"start": 12288, "length": 1000, "data": True, "zero": True}, {"start": 13288, "length": 50, "data": True, "zero": False}]
    monkeypatch.setattr(qemu_module, "_qemu_img_exists", lambda: True)
    monkeypatch.setattr(qemu_module.subprocess, "run", lambda *a, **k: SimpleNamespace(returncode=0, stdout=json.dumps(extents)))
    assert qemu_module.allocated_data_bytes(tmp_path / "x.vmdk") == 4146
    monkeypatch.setattr(qemu_module.subprocess, "run", lambda *a, **k: SimpleNamespace(returncode=1, stdout=""))
    assert qemu_module.allocated_data_bytes(tmp_path / "x.vmdk") is None


def test_docker_deployments_are_told_how_to_move_the_temp_folder(monkeypatch):
    real_exists = Path.exists
    monkeypatch.setattr(Path, "exists", lambda self: True if str(self) == "/.dockerenv" else real_exists(self))
    fixes = " ".join(preflight_module._temp_storage_fixes())
    assert "docker-compose.override.yml" in fixes and "/app/data/tmp" in fixes and "docker builder prune" in fixes
