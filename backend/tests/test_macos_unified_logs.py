"""Unified Logs: logarchive layout, streaming filter and folding, with a stand-in for the tool."""
from __future__ import annotations

import json
import stat
import sys
from pathlib import Path

import pytest

from app.ingest.macos import unified_logs
from app.ingest.macos.helpers import list_macos_artifacts

ENTRIES = [
    {"timestamp": "2026-01-05T10:00:01Z", "subsystem": "com.apple.loginwindow.logging", "category": "Standard", "process": "/System/Library/CoreServices/loginwindow.app/Contents/MacOS/loginwindow", "pid": 100, "euid": 0, "message": "User alice logged in", "log_type": "Default", "event_type": "Log", "evidence": "/x/Persist/0000000000000001.tracev3"},
    {"timestamp": "2026-01-05T10:00:02Z", "subsystem": "com.apple.TCC", "category": "access", "process": "/usr/libexec/tccd", "pid": 200, "message": "noise", "log_type": "Default", "event_type": "Log"},
    {"timestamp": "2026-01-05T10:00:03Z", "subsystem": "", "category": "", "process": "/usr/bin/sudo", "pid": 301, "euid": 0, "message": "alice : TTY=ttys001 ; COMMAND=/usr/bin/id", "log_type": "Error", "event_type": "Log"},
    {"timestamp": "2026-01-05T10:00:04Z", "subsystem": "", "category": "", "process": "/usr/bin/sudo", "pid": 302, "euid": 0, "message": "alice : TTY=ttys001 ; COMMAND=/usr/bin/id", "log_type": "Error", "event_type": "Log"},
    {"timestamp": "2026-01-05T10:00:04Z", "subsystem": "com.apple.CFNetwork", "category": "Default", "process": "/usr/libexec/syspolicyd", "pid": 400, "message": "a forensic process's library noise", "log_type": "Default", "event_type": "Log"},
    {"timestamp": "2026-01-05T10:00:05Z", "subsystem": "com.apple.syspolicy.exec", "category": "default", "process": "/usr/libexec/syspolicyd", "pid": 400, "message": "Gatekeeper evaluating tool.app", "log_type": "Fault", "event_type": "Log"},
]


@pytest.fixture()
def collection(tmp_path: Path) -> Path:
    root = tmp_path / "c"
    db = root / "[root]/private/var/db"
    (db / "diagnostics/Persist").mkdir(parents=True)
    (db / "diagnostics/Persist/0000000000000001.tracev3").write_bytes(b"\0" * 8)
    (db / "diagnostics/timesync").mkdir()
    (db / "diagnostics/timesync/0000000000000001.timesync").write_bytes(b"\0")
    (db / "uuidtext/AB").mkdir(parents=True)
    (db / "uuidtext/AB/CDEF").write_bytes(b"\0")
    (db / "uuidtext/dsc").mkdir()
    return root


@pytest.fixture()
def fake_tool(tmp_path: Path, monkeypatch) -> Path:
    """Checks it got a logarchive with diagnostics and uuidtext merged, then prints the entries."""
    script = tmp_path / "fake_iterator"
    script.write_text(
        f"#!{sys.executable}\n"
        "import json, sys, pathlib\n"
        "archive = pathlib.Path(sys.argv[sys.argv.index('--input') + 1])\n"
        "assert (archive / 'Persist').is_dir() and (archive / 'timesync').is_dir() and (archive / 'AB' / 'CDEF').is_file() and (archive / 'dsc').is_dir()\n"
        "print('[WARN] not json')\n"
        f"for entry in json.loads({json.dumps(json.dumps(ENTRIES))}):\n"
        "    print(json.dumps(entry))\n"
    )
    script.chmod(script.stat().st_mode | stat.S_IEXEC)
    monkeypatch.setenv("UNIFIEDLOG_ITERATOR", str(script))
    monkeypatch.delenv("MACOS_UNIFIED_LOGS_MODE", raising=False)
    return script


def test_listing_keeps_one_artifact_for_the_logs(collection: Path) -> None:
    artifacts, stats = list_macos_artifacts(collection)
    assert [item["parser"] for item in artifacts] == ["macos_unified_logs_raw"]
    assert artifacts[0]["name"] == "Unified Logs"
    assert stats["files_seen"] == 0


def test_forensic_entries_are_kept_and_folded(collection: Path, fake_tool: Path) -> None:
    marker = collection / "[root]/private/var/db/diagnostics/Persist/0000000000000001.tracev3"
    rows = unified_logs.parse_unified_logs(marker, source_path="[root]/private/var/db/diagnostics/Persist/0000000000000001.tracev3")
    assert [row["process"] for row in rows] == ["loginwindow", "sudo", "syspolicyd"]
    assert rows[1]["repeat_count"] == 2
    assert rows[0]["subsystem"] == "com.apple.loginwindow.logging" and rows[0]["tracev3_file"] == "0000000000000001.tracev3"
    assert rows[2]["log_type"] == "Fault"


def test_every_entry_with_mode_all(collection: Path, fake_tool: Path, monkeypatch) -> None:
    monkeypatch.setenv("MACOS_UNIFIED_LOGS_MODE", "all")
    marker = collection / "[root]/private/var/db/diagnostics/Persist/0000000000000001.tracev3"
    rows = unified_logs.parse_unified_logs(marker, source_path="x")
    assert "tccd" in [row["process"] for row in rows]


def test_missing_tool_is_reported(collection: Path, monkeypatch) -> None:
    monkeypatch.setenv("UNIFIEDLOG_ITERATOR", "/nonexistent")
    monkeypatch.setattr(unified_logs.shutil, "which", lambda name: None)
    with pytest.raises(RuntimeError, match="not installed"):
        unified_logs.parse_unified_logs(collection / "[root]/private/var/db/diagnostics/Persist/0000000000000001.tracev3", source_path="x")
