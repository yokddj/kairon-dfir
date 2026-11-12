"""A stand-in for MemProcFS's full scan (memprocfs_findevil --scan-dir) in worker tests."""

from __future__ import annotations

import json
from pathlib import Path

from app.services.memory import memprocfs_engine, memprocfs_runner
from app.services.memory.volatility_runner import VolatilityRunResult


def install_fake_scan(monkeypatch, tmp_path: Path, rows: list[dict] | None, *, calls: list[str] | None = None, yara_rules: bool = False) -> Path:
    """Make the evidence's scan directory ``tmp_path/memprocfs-scan`` and have every scan write it
    with ``rows`` as FindEvil's result (None: FindEvil does not cover the image)."""
    scan = tmp_path / "memprocfs-scan"
    made: list[int] = []
    monkeypatch.setattr(memprocfs_engine, "inventory_dir", lambda *_args: scan)

    def fake_scan(evidence_path, work_dir, *, scan_dir=None, **_kwargs):
        assert scan_dir == scan, "the full scan must be written to the evidence's scan directory"
        made.append(1)
        if calls is not None:
            calls.append(Path(evidence_path).name)
        (scan_dir / "forensic").mkdir(parents=True, exist_ok=True)
        (scan_dir / "system.json").write_text("{}", encoding="utf-8")
        (scan_dir / "process.csv").write_text("PID,Name\n4,System\n", encoding="utf-8")
        (scan_dir / "forensic" / "tasks.csv").write_text("TaskName\nUpdater\n", encoding="utf-8")
        if rows is not None:
            (scan_dir / "findevil.json").write_text(json.dumps(rows), encoding="utf-8")
        else:
            (scan_dir / "findevil.json").unlink(missing_ok=True)
        (scan_dir / "scan.json").write_text(json.dumps({"scanned_at": f"2026-11-12T10:00:{len(made):02d}Z", "memprocfs_version": "5.19.3", "yara_rules": yara_rules, "findevil": rows is not None}), encoding="utf-8")
        return VolatilityRunResult(argv_display=["memprocfs"], stdout=b"", stderr=b"", duration_ms=5)

    monkeypatch.setattr(memprocfs_runner, "run_findevil", fake_scan)
    return scan
