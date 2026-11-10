"""MemProcFS console text as Shell History (app.services.memory.memprocfs_console).

The samples are MemProcFS 5.19's own output (\\sys\\proc\\proc.txt, \\pid\\<pid>\\console\\console.txt)
from a Windows 11 24H2 image, where the PowerShell session ran inside Windows Terminal.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from app.services.memory import memprocfs_console, memprocfs_runner
from app.services.memory.artifact_normalizers import normalize_memprocfs_console

PROC_TXT = """  Process                      Pid Parent   Flag User             Create Time              Exit Time
------------------------------------------------------------------------------------------------------------------
- System                         4      0                                             ***                      ***
---- WindowsTermina           4876   7828      *                                      ***                      ***
----- OpenConsole.ex          9096   4876      *                                      ***                      ***
----- powershell.exe         11512   4876                                             ***                      ***
---- svchost.exe               820    640    32  U                                     ***                      ***
"""
CONSOLE_TXT = """ 
Windows PowerShell
Copyright (C) Microsoft Corporation. Todos los derechos reservados.

PS C:\\Users\\dfir> cd .\\Downloads\\
PS C:\\Users\\dfir\\Downloads> .\\winpmem_mini_x86.exe memoria.raw
WinPmem64
Extracting driver to C:\\Users\\dfir\\AppData\\Local\\Temp\\pme8C38.tmp
PS C:\\Users\\dfir\\Downloads> ping example.org
"""


def test_every_process_of_the_tree_is_listed_once() -> None:
    assert memprocfs_console.process_ids(PROC_TXT + "---- svchost.exe               820    640\n") == [(4, "System"), (4876, "WindowsTermina"), (9096, "OpenConsole.ex"), (11512, "powershell.exe"), (820, "svchost.exe")]


def test_only_processes_with_console_text_are_returned_with_their_full_name() -> None:
    files = {
        "\\sys\\proc\\proc.txt": PROC_TXT.encode(),
        "\\pid\\4876\\console\\console.txt": CONSOLE_TXT.encode(),
        "\\pid\\4876\\name-long.txt": b"WindowsTerminal.exe",
        # What processes without a console answer: a few bytes of noise.
        "\\pid\\820\\console\\console.txt": " 䙔".encode(),
    }
    rows = memprocfs_console.console_rows(lambda path, limit: files.get(path))
    assert [(row["PID"], row["Process"]) for row in rows] == [(4876, "WindowsTerminal.exe")]
    assert "winpmem_mini_x86.exe" in rows[0]["Text"]


def test_console_text_becomes_the_typed_commands() -> None:
    result = normalize_memprocfs_console([{"PID": 4876, "Process": "WindowsTerminal.exe", "Text": CONSOLE_TXT}], case_id="c", evidence_id="e", scan_run_id="r", plugin_run_id="p")
    items = result["items"]
    assert [item["command"] for item in items] == ["cd .\\Downloads\\", ".\\winpmem_mini_x86.exe memoria.raw", "ping example.org"]
    first = items[1]
    assert first["working_directory"] == "C:\\Users\\dfir\\Downloads" and first["process_name"] == "powershell.exe"
    assert first["pid"] == 4876 and first["console_host"] == "WindowsTerminal.exe"
    assert first["recovered_from"] == "memprocfs_console" and first["source_plugin"] == "memprocfs.console"
    assert first["document_type"] == "memory_shell_history" and first["command_time"] is None
    again = normalize_memprocfs_console([{"PID": 4876, "Process": "WindowsTerminal.exe", "Text": CONSOLE_TXT}], case_id="c", evidence_id="e", scan_run_id="r", plugin_run_id="p")
    assert [item["document_id"] for item in again["items"]] == [item["document_id"] for item in items]


def test_text_without_a_prompt_gives_no_commands() -> None:
    result = normalize_memprocfs_console([{"PID": 8500, "Process": "conhost.exe", "Text": "DumpIt 3.6\n--> Proceed with the acquisition ? [y/n] y"}], case_id="c", evidence_id="e", scan_run_id="r", plugin_run_id="p")
    assert result["items"] == [] and result["raw_count"] == 1


def test_the_same_command_from_volatility_and_memprocfs_is_one_grouped_row() -> None:
    from app.services.memory.artifact_indexing import group_duplicate_commands

    memprocfs = normalize_memprocfs_console([{"PID": 4876, "Process": "WindowsTerminal.exe", "Text": CONSOLE_TXT}], case_id="c", evidence_id="e", scan_run_id="r", plugin_run_id="p")["items"]
    volatility = {**memprocfs[1], "document_id": "x", "recovered_from": "screen", "source_plugin": "windows.consoles", "pid": 9096}
    groups = group_duplicate_commands([*memprocfs, volatility])
    assert len(groups) == 3
    grouped = next(group for group in groups if group["command"] == volatility["command"])
    assert grouped["occurrences"] == 2 and grouped["sources"] == ["memprocfs_console", "screen"]


def test_runner_starts_the_console_child_and_names_its_failures(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    library = tmp_path / "vmm.so"
    library.write_bytes(b"")
    monkeypatch.setattr(memprocfs_runner, "memprocfs_library", lambda: library)
    calls = {}

    def fake_run(argv, **kwargs):
        calls["argv"] = argv
        return json.dumps([]).encode(), b"", 0, 10

    monkeypatch.setattr(memprocfs_runner, "run_isolated_process", fake_run)
    result = memprocfs_runner.run_console(tmp_path / "image.raw", tmp_path, timeout_seconds=600, max_output_bytes=4096)
    assert "app.services.memory.memprocfs_console" in calls["argv"] and "-forensic" not in result.argv_display
    monkeypatch.setattr(memprocfs_runner, "run_isolated_process", lambda argv, **kwargs: (b"", b"", 4, 10))
    with pytest.raises(memprocfs_runner.VolatilityRunnerError) as error:
        memprocfs_runner.run_console(tmp_path / "image.raw", tmp_path, timeout_seconds=600, max_output_bytes=4096)
    assert error.value.code == "UNSUPPORTED_MEMORY_IMAGE"


def test_console_text_is_a_shell_history_source_on_windows() -> None:
    from app.core.config import Settings
    from app.services.memory import execution
    from app.services.memory.capability_registry import MemoryCapability, PlatformFamily, plugins_for_capability

    assert "memprocfs.console" in [spec.plugin for spec in plugins_for_capability(PlatformFamily.WINDOWS, MemoryCapability.SHELL_HISTORY)]
    assert execution.ARTIFACT_PLUGIN_NORMALIZER["memprocfs.console"] == "memory_shell_history"
    assert "memprocfs.console" in Settings().allowed_memory_plugins
