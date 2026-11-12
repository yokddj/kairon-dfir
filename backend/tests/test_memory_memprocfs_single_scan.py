"""One MemProcFS scan per Windows image, saved and read by every analysis; a new one on request."""

from __future__ import annotations

import json
import zipfile
from pathlib import Path
from types import SimpleNamespace

import pytest

from app.core.config import get_settings
from app.services.memory import memprocfs_engine, memprocfs_findevil, memprocfs_scan
from tests.memprocfs_scan_fakes import install_fake_scan


def test_the_scan_is_made_once_and_again_only_on_request(tmp_path, monkeypatch):
    calls: list[str] = []
    scan = install_fake_scan(monkeypatch, tmp_path, [{"Type": "PRIVATE_RWX"}], calls=calls)
    image = tmp_path / "image.raw"
    for _ in range(2):
        assert memprocfs_engine.ensure_scan("c", "e", image, tmp_path, timeout_seconds=60) == scan
    assert calls == ["image.raw"]
    assert memprocfs_engine.ensure_inventory("c", "e", image, tmp_path, timeout_seconds=60) == scan
    assert calls == ["image.raw"]
    memprocfs_engine.ensure_scan("c", "e", image, tmp_path, timeout_seconds=60, force=True)
    assert calls == ["image.raw", "image.raw"]
    assert memprocfs_engine.findevil_rows(scan) == [{"Type": "PRIVATE_RWX"}]


def test_an_inventory_from_an_older_version_serves_inventories_but_findevil_scans(tmp_path, monkeypatch):
    calls: list[str] = []
    scan = install_fake_scan(monkeypatch, tmp_path, [], calls=calls)
    scan.mkdir(parents=True)
    (scan / "system.json").write_text("{}")
    (scan / "process.csv").write_text("PID\n")
    memprocfs_engine.ensure_inventory("c", "e", tmp_path / "image.raw", tmp_path, timeout_seconds=60)
    assert calls == []
    memprocfs_engine.ensure_scan("c", "e", tmp_path / "image.raw", tmp_path, timeout_seconds=60)
    assert calls == ["image.raw"] and memprocfs_engine.scan_complete(scan)


def test_findevil_on_an_image_it_does_not_cover_still_saves_the_inventory(tmp_path, monkeypatch):
    scan = install_fake_scan(monkeypatch, tmp_path, None)
    memprocfs_engine.ensure_scan("c", "e", tmp_path / "image.raw", tmp_path, timeout_seconds=60)
    assert memprocfs_engine.inventory_ready(scan) and memprocfs_engine.findevil_rows(scan) is None


def test_the_child_saves_the_whole_scan(tmp_path, monkeypatch):
    """--scan-dir: inventory, then FindEvil's rows, the forensic files and scan.json, renamed in place at the end."""
    from app.services.memory import memprocfs_inventory

    def fake_inventory(lib, handle, output, *, extra=None, progress=None):
        partial = output.with_name(output.name + ".partial")
        partial.mkdir(parents=True)
        (partial / "process.csv").write_text("PID\n")
        (partial / "system.json").write_text("{}")
        extra(partial)
        partial.rename(output)
        return 0

    saved: list[str] = []
    monkeypatch.setattr(memprocfs_inventory, "save_inventory", fake_inventory)
    monkeypatch.setattr(memprocfs_findevil, "_save_timelines", lambda lib, handle, directory, progress=None: saved.append(directory) or Path(directory).mkdir(parents=True))
    args = SimpleNamespace(library=str(tmp_path / "vmm.so"), accept_elastic_license=True)
    (tmp_path / "KAIRON_RESOLVED_VERSION.txt").write_text("5.19.3\n")
    watchdog = SimpleNamespace(update=lambda _label: None)
    output = tmp_path / "scan"
    assert memprocfs_findevil._save_scan(None, 0, output, [{"Type": "YR_TROJAN"}], args, watchdog) == 0
    assert saved == [str(tmp_path / "scan.partial" / "forensic")]
    info = json.loads((output / "scan.json").read_text())
    assert info["yara_rules"] is True and info["memprocfs_version"] == "5.19.3" and info["findevil"] is True and info["findevil_rows"] == 1
    assert json.loads((output / "findevil.json").read_text()) == [{"Type": "YR_TROJAN"}]


def _evidence(tmp_path, monkeypatch, scan_dir: Path, **info):
    monkeypatch.setattr(get_settings(), "backend_data_dir", tmp_path)
    monkeypatch.setattr(get_settings(), "backend_temp_dir", tmp_path / "tmp")
    return SimpleNamespace(id="e", case_id="c", metadata_json={"memprocfs_scan": {"path": str(scan_dir.relative_to(tmp_path)), **info}})


def _scan_dir(tmp_path: Path) -> Path:
    scan = tmp_path / "memory-output" / "evidence" / "c" / "e" / "memory" / "memprocfs-inventory"
    (scan / "forensic" / "evtx").mkdir(parents=True)
    (scan / "process.csv").write_text("PID\n4\n")
    (scan / "forensic" / "timeline_ntfs.csv").write_text("Time,Path\n1,C:\\\\x\n")
    (scan / "forensic" / "evtx" / "System.evtx").write_bytes(b"ElfFile\x00")
    (tmp_path / "secret.txt").write_text("outside")
    return scan


def test_status_lists_the_files_and_warns_when_yara_rules_came_later(tmp_path, monkeypatch):
    scan = _scan_dir(tmp_path)
    evidence = _evidence(tmp_path, monkeypatch, scan, scanned_at="2026-11-12T10:00:00Z", yara_rules=False)
    monkeypatch.setattr(get_settings(), "memprocfs_yara_accept_elastic_license", True)
    state = memprocfs_scan.status(evidence)
    assert state["exists"] and state["notices"] == ["yara_rules_missing"]
    assert {item["path"] for item in state["files"]} == {"process.csv", "forensic/timeline_ntfs.csv", "forensic/evtx/System.evtx"}
    assert next(item for item in state["files"] if item["path"] == "forensic/timeline_ntfs.csv")["source_path"] == "memprocfs/forensic/timeline_ntfs.csv"
    monkeypatch.setattr(get_settings(), "memprocfs_yara_accept_elastic_license", False)
    assert memprocfs_scan.status(evidence)["notices"] == []


def test_files_are_served_only_from_inside_the_scan(tmp_path, monkeypatch):
    scan = _scan_dir(tmp_path)
    evidence = _evidence(tmp_path, monkeypatch, scan)
    assert memprocfs_scan.resolve_file(evidence, "forensic/evtx/System.evtx") == scan / "forensic" / "evtx" / "System.evtx"
    for bad in ("../../../../../secret.txt", "/etc/passwd", "forensic/../../../../../../secret.txt", ""):
        assert memprocfs_scan.resolve_file(evidence, bad) is None
    archive = memprocfs_scan.build_archive(evidence)
    with zipfile.ZipFile(archive) as opened:
        assert sorted(opened.namelist()) == ["forensic/evtx/System.evtx", "forensic/timeline_ntfs.csv", "process.csv"]
    assert archive.parent == tmp_path / "tmp"


def test_source_tables_open_the_scans_csvs(tmp_path, monkeypatch):
    from app.services.source_tables import resolve_source_file

    scan = _scan_dir(tmp_path)
    evidence = _evidence(tmp_path, monkeypatch, scan)
    evidence.stored_path = str(tmp_path / "image.raw")
    assert resolve_source_file(evidence, "memprocfs/forensic/timeline_ntfs.csv") == scan / "forensic" / "timeline_ntfs.csv"
    assert resolve_source_file(evidence, "memprocfs/../secret.txt") is None


def test_no_scan_means_nothing_to_show(tmp_path, monkeypatch):
    monkeypatch.setattr(get_settings(), "backend_data_dir", tmp_path)
    evidence = SimpleNamespace(id="e", case_id="c", metadata_json={})
    assert memprocfs_scan.status(evidence)["exists"] is False and memprocfs_scan.build_archive(evidence) is None


def test_a_rescan_request_is_taken_once_per_run():
    from app.services.memory import execution

    class _Db:
        def commit(self):
            pass

    run = SimpleNamespace(metadata_json={"memprocfs_rescan": True})
    assert execution._take_memprocfs_rescan(_Db(), run) is True
    assert execution._take_memprocfs_rescan(_Db(), run) is False
    assert execution._take_memprocfs_rescan(_Db(), SimpleNamespace(metadata_json={})) is False


def test_the_timeline_is_indexed_once_per_scan(tmp_path, monkeypatch):
    from app.services.memory import execution

    scan = tmp_path / "scan"
    (scan / "forensic").mkdir(parents=True)
    monkeypatch.setattr(memprocfs_engine, "inventory_dir", lambda *_a: scan)
    indexed: list[Path] = []
    monkeypatch.setattr(execution, "_index_memprocfs_timeline", lambda db, run, directory: indexed.append(directory) or {"indexed": 3})
    evidence = SimpleNamespace(metadata_json={"memprocfs_scan": {"scanned_at": "T1", "path": "x"}})

    class _Db:
        def get(self, _model, _id):
            return evidence

        def commit(self):
            pass

    run = SimpleNamespace(case_id="c", evidence_id="e", id="r")
    monkeypatch.setattr(execution, "flag_modified", lambda *_a: None)
    assert execution._index_scan_timeline(_Db(), run) == {"indexed": 3}
    assert execution._index_scan_timeline(_Db(), run)["skipped"] == "already indexed for this scan"
    evidence.metadata_json["memprocfs_scan"]["scanned_at"] = "T2"
    assert execution._index_scan_timeline(_Db(), run) == {"indexed": 3}
    assert indexed == [scan / "forensic", scan / "forensic"]
