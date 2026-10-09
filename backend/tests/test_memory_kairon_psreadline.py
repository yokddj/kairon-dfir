"""PowerShell history files (PSReadLine) recovered from memory (app.services.memory.kairon_psreadline).

No test image has the file cached, so the Volatility side is simulated with filescan/dumpfiles
output in the shape the real plugins print (see file_extraction.py, which drives the same pair).
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from app.services.memory import kairon_psreadline
from app.services.memory.artifact_normalizers import normalize_psreadline_history
from app.services.memory.kairon_psreadline import history_commands, history_file_objects, history_rows, run_kairon_psreadline
from app.services.memory.volatility_runner import VolatilityRunResult

HISTORY_PATH = "\\Users\\bob\\AppData\\Roaming\\Microsoft\\Windows\\PowerShell\\PSReadLine\\ConsoleHost_history.txt"
FILESCAN = [
    {"Offset": 0xE0001, "Name": "\\Windows\\System32\\cmd.exe"},
    {"Offset": 0xE0002, "Name": HISTORY_PATH},
    {"Offset": 0xE0003, "Name": HISTORY_PATH},
    {"Offset": 0xE0004, "Name": "\\Users\\alice\\AppData\\Roaming\\Microsoft\\Windows\\PowerShell\\PSReadLine\\Visual Studio Code Host_history.txt"},
    {"Offset": 0xE0005, "Name": "\\Users\\bob\\Documents\\ConsoleHost_history.txt"},
]


def test_finds_every_psreadline_history_file_and_its_user() -> None:
    files = history_file_objects(FILESCAN)
    assert [item["offset"] for item in files] == [str(0xE0002), str(0xE0003), str(0xE0004)]
    assert [item["user"] for item in files] == ["bob", "bob", "alice"]


def test_commands_keep_file_order_and_join_multiline_commands() -> None:
    data = "whoami\r\nGet-Process |`\r\n  Where-Object CPU -gt 10\r\n\r\nInvoke-WebRequest http://x/a.ps1 -OutFile a.ps1\r\n".encode()
    assert history_commands(data) == ["whoami", "Get-Process |\n  Where-Object CPU -gt 10", "Invoke-WebRequest http://x/a.ps1 -OutFile a.ps1"]


def test_pages_no_longer_cached_split_the_text_without_inventing_commands() -> None:
    data = b"ipconfig /all\n" + b"\x00" * 4096 + b"net user\nhostname\n"
    assert history_commands(data) == ["ipconfig /all", "net user", "hostname"]


def test_utf8_bom_and_utf16_are_read() -> None:
    assert history_commands("﻿dir\n".encode("utf-8")) == ["dir"]
    assert history_commands("dir\r\ncls\r\n".encode("utf-16")) == ["dir", "cls"]


def test_one_file_seen_through_several_file_objects_is_listed_once() -> None:
    files = history_file_objects(FILESCAN)
    rows = history_rows(files, {str(0xE0002): b"whoami\n", str(0xE0003): b"whoami\nhostname\n"})
    assert [(row["User"], row["Line"], row["Command"]) for row in rows] == [("bob", 1, "whoami"), ("bob", 2, "hostname")]
    assert rows[0]["FileObject"] == str(0xE0003)


def _fake_volatility(tmp_path: Path, filescan_rows, dumps: dict[int, bytes]):
    calls: list[tuple[str, list[str] | None]] = []

    def fake_run_plugin(plugin, evidence_path, work_dir, *, timeout_seconds, max_output_bytes=None, cancellation_check=None, extra_args=None):
        calls.append((plugin, extra_args))
        if plugin == "windows.filescan":
            return VolatilityRunResult(argv_display=[plugin], stdout=json.dumps(filescan_rows).encode(), stderr=b"", duration_ms=1)
        work_dir.mkdir(parents=True, exist_ok=True)
        rows = []
        for offset, data in dumps.items():
            name = f"file.{offset:#x}.0xdead.DataSectionObject.ConsoleHost_history.txt.dat"
            (work_dir / name).write_bytes(data)
            rows.append({"Cache": "DataSectionObject", "FileObject": offset, "FileName": "ConsoleHost_history.txt", "Result": name})
        return VolatilityRunResult(argv_display=[plugin], stdout=json.dumps(rows).encode(), stderr=b"", duration_ms=1)

    return calls, fake_run_plugin


def test_run_recovers_the_cached_file(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    from app.services.memory import volatility_runner

    calls, fake = _fake_volatility(tmp_path, FILESCAN, {0xE0002: b"whoami\nGet-LocalUser\n"})
    monkeypatch.setattr(volatility_runner, "run_plugin", fake)
    result = run_kairon_psreadline(tmp_path / "image.dmp", tmp_path, timeout_seconds=600, max_output_bytes=1 << 20, plugin_timeout=lambda plugin: 300)
    rows = json.loads(result.stdout)
    assert [row["Command"] for row in rows] == ["whoami", "Get-LocalUser"]
    assert calls[1] == ("windows.dumpfiles", ["--virtaddr", str(0xE0002), str(0xE0003), str(0xE0004)])


def test_no_cached_history_file_is_zero_rows_not_a_failure(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    from app.services.memory import volatility_runner

    calls, fake = _fake_volatility(tmp_path, FILESCAN[:1], {})
    monkeypatch.setattr(volatility_runner, "run_plugin", fake)
    result = run_kairon_psreadline(tmp_path / "image.dmp", tmp_path, timeout_seconds=600, max_output_bytes=1 << 20, plugin_timeout=lambda plugin: 300)
    assert json.loads(result.stdout) == []
    assert b"No PowerShell history file" in result.stderr
    assert [plugin for plugin, _ in calls] == ["windows.filescan"]


def test_found_but_evicted_file_is_explained(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    from app.services.memory import volatility_runner

    _, fake = _fake_volatility(tmp_path, FILESCAN, {})
    monkeypatch.setattr(volatility_runner, "run_plugin", fake)
    result = run_kairon_psreadline(tmp_path / "image.dmp", tmp_path, timeout_seconds=600, max_output_bytes=1 << 20, plugin_timeout=lambda plugin: 300)
    assert json.loads(result.stdout) == [] and b"none of their pages are cached" in result.stderr


def test_rows_become_shell_history_documents() -> None:
    rows = history_rows(history_file_objects(FILESCAN), {str(0xE0002): b"whoami\nhostname\n"})
    result = normalize_psreadline_history(rows, case_id="c", evidence_id="e", scan_run_id="r", plugin_run_id="p")
    assert result["accepted_count"] == 2
    first = result["items"][0]
    assert first["document_type"] == "memory_shell_history" and first["recovered_from"] == "psreadline_history"
    assert first["command"] == "whoami" and first["user"] == "bob" and first["history_file"] == HISTORY_PATH
    assert first["pid"] is None and first["command_time"] is None and first["process_name"] == "powershell.exe"
    assert first["source_plugin"] == "kairon.psreadline"
    assert len({item["document_id"] for item in result["items"]}) == 2


def test_execution_routes_the_plugin_and_its_documents() -> None:
    from app.services.memory import execution

    assert execution.ARTIFACT_PLUGIN_NORMALIZER["kairon.psreadline"] == "memory_shell_history"
    assert kairon_psreadline.KAIRON_PSREADLINE_PLUGIN in execution.ARTIFACT_PLUGIN_LIMITS
    result = execution._normalize_artifact_payload("kairon.psreadline", [{"User": "bob", "Path": HISTORY_PATH, "Line": 1, "Command": "dir"}], case_id="c", evidence_id="e", scan_run_id="r", plugin_run_id="p")
    assert result["items"][0]["command"] == "dir"
