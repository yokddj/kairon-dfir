"""MemProcFS as the Windows engine: the saved inventory read into each analysis's rows, in the
columns of the Volatility plugin it stands in for, and which engine a run uses."""

from __future__ import annotations

import json
from types import SimpleNamespace

import pytest

from app.services.memory import memprocfs_engine as engine
from app.services.memory.artifact_normalizers import normalize_windows_dlllist, normalize_windows_handles, normalize_windows_privileges
from app.services.memory.execution import resolve_run_engine
from app.services.memory.memprocfs_inventory import environment, token_privileges, token_sids
from app.services.memory.normalizers import normalize_windows_info
from app.services.memory.validation import MemoryExecutionValidationError

# Shapes of MemProcFS 5.19's forensic CSVs and token files.
SID_ALL = """   # Display Name                                                     SID
-------------------------------------------------------------------------
0000 DOMAIN\\DOMAIN_USER_RID_ADMIN                                     S-1-5-21-1-2-3-500
0001 Everyone                                                         S-1-1-0
"""
PRIVILEGES = """   # Flags Privilege Name
-------------------------
0002  -p-  SeCreateTokenPrivilege
000a  epd  SeLoadDriverPrivilege
"""


@pytest.fixture()
def inventory(tmp_path):
    d = tmp_path / "memprocfs-inventory"
    d.mkdir()
    (d / "process.csv").write_text('PID,PPID,State,ShortName,Name,User,CreateTime,ExitTime,Wow64,EPROCESS,CommandLine\n4,0,0,System,System,SYSTEM,"2024-02-29 09:25:57",,0,0xffff1,""\n7432,6120,0,powershell.exe,powershell.exe,analyst,"2024-03-22 12:40:01",,0,0xffff2,"powershell.exe -nop"\n')
    (d / "modules.csv").write_text('PID,Process,Name,Wow64,Size,Start,End,Path,KernelPath\n4,System,ntoskrnl.exe,0,0x1000,0xfffff80157e00000,0xfffff80157e00fff,\\SystemRoot\\system32\\ntoskrnl.exe,\n7432,powershell.exe,ntdll.dll,0,0x200000,0x7ffd00000000,0x7ffd001fffff,C:\\Windows\\SYSTEM32\\ntdll.dll,\n')
    (d / "handles.csv").write_text('PID,Handle,Object,Access,Type,Tag,HandleCount,Device,Description\n7432,0x10,0xffffaa0e81ea13c0,1f0001,Mutant,Muta,0x1,,BcdSyncMutant\n')
    (d / "drivers.csv").write_text('Name,ObjectAddress,Size,Start,End,ServiceKey,DriverName,DriverPath\nPEAUTH,0xffffaa0e849e9d00,0xce000,0xfffff80152000000,0xfffff801520cdfff,PEAUTH,\\Driver\\PEAUTH,\\SystemRoot\\system32\\drivers\\peauth.sys\n')
    (d / "net.csv").write_text("Proto,State,SrcAddr,SrcPort,DstAddr,DstPort,Time,Object,PID,Process,ProcessPath\n")
    (d / "environment.json").write_text(json.dumps({"7432": environment("=C:=C:\\\nPath=C:\\Windows\nUSERNAME=analyst\n")}))
    (d / "tokens.json").write_text(json.dumps({"7432": {"sid": "S-1-5-21-1-2-3-500", "user": "analyst", "integrity": "High", "session": "1", "sids": token_sids(SID_ALL), "privileges": token_privileges(PRIVILEGES)}}))
    (d / "system.json").write_text(json.dumps({"version": "10.0.20348", "version-major": "10", "version-minor": "0", "version-build": "20348", "computername": "DC02", "time-boot": "2024-02-29 09:25:25 UTC", "time-current": "2024-03-22 12:59:18 UTC", "timezone": "Romance Standard Time", "architecture": "X64"}))
    return d


def test_token_and_environment_files_are_parsed():
    assert token_sids(SID_ALL) == [{"sid": "S-1-5-21-1-2-3-500", "name": "DOMAIN\\DOMAIN_USER_RID_ADMIN"}, {"sid": "S-1-1-0", "name": "Everyone"}]
    assert token_privileges(PRIVILEGES)[1] == {"value": 10, "name": "SeLoadDriverPrivilege", "present": True, "enabled": True, "default": True}
    assert environment("=C:=C:\\\nPath=C:\\Windows\n") == {"Path": "C:\\Windows"}


def test_system_info_reads_like_windows_info(inventory):
    doc = normalize_windows_info(engine.rows("memprocfs.sysinfo", inventory), case_id="c", evidence_id="e", memory_run_id="r", memory_plugin_run_id="p")
    assert doc["host"]["name"] == "DC02"
    assert doc["os"]["windows_build"] in ("20348", 20348) and doc["os"]["nt_major_version"] == 10
    assert doc["memory"]["is_64_bit"] is True and doc["memory"]["system_time"].startswith("2024-03-22 12:59:18")


def test_modules_split_into_process_dlls_and_kernel_modules(inventory):
    dlls = engine.rows("memprocfs.dlllist", inventory)
    kernel = engine.rows("memprocfs.modules", inventory)
    assert [(m["PID"], m["Name"], m["Base"]) for m in dlls] == [(7432, "ntdll.dll", 0x7ffd00000000)]
    assert [m["Name"] for m in kernel] == ["ntoskrnl.exe"] and "PID" not in kernel[0]
    result = normalize_windows_dlllist(dlls, case_id="c", evidence_id="e", scan_run_id="r", plugin_run_id="p", source_plugin="memprocfs.dlllist")
    assert result["accepted_count"] == 1


def test_handles_drivers_envars_sids_and_privileges(inventory):
    handles = engine.rows("memprocfs.handles", inventory)
    assert handles == [{"PID": 7432, "Process": "powershell.exe", "Offset": 0xffffaa0e81ea13c0, "HandleValue": 0x10, "Type": "Mutant", "GrantedAccess": 0x1f0001, "Name": "BcdSyncMutant"}]
    assert normalize_windows_handles(handles, case_id="c", evidence_id="e", scan_run_id="r", plugin_run_id="p", source_plugin="memprocfs.handles")["accepted_count"] == 1
    assert engine.rows("memprocfs.driverscan", inventory)[0]["Name"] == "\\Driver\\PEAUTH"
    assert {(r["Variable"], r["Value"]) for r in engine.rows("memprocfs.envars", inventory)} == {("Path", "C:\\Windows"), ("USERNAME", "analyst")}
    assert [r["SID"] for r in engine.rows("memprocfs.getsids", inventory)] == ["S-1-5-21-1-2-3-500", "S-1-1-0"]
    privileges = engine.rows("memprocfs.privileges", inventory)
    assert privileges[1] == {"PID": 7432, "Process": "powershell.exe", "Value": 10, "Privilege": "SeLoadDriverPrivilege", "Attributes": "Present,Enabled,Default", "Description": None}
    assert normalize_windows_privileges(privileges, case_id="c", evidence_id="e", scan_run_id="r", plugin_run_id="p", source_plugin="memprocfs.privileges")["accepted_count"] == 2


def _plan(platform):
    return SimpleNamespace(detected_platform=SimpleNamespace(value=platform))


@pytest.fixture()
def memprocfs_default(monkeypatch):
    from app.services.memory import backend_readiness

    monkeypatch.setattr(backend_readiness.get_settings(), "memory_windows_default_engine", "memprocfs")


def test_windows_runs_on_memprocfs_and_volatility_only_on_request(memprocfs_default):
    assert resolve_run_engine("processes_basic", _plan("windows"), None) == "memprocfs"
    assert resolve_run_engine("processes_basic", _plan("windows"), "volatility") == "volatility"
    with pytest.raises(MemoryExecutionValidationError) as exc:
        resolve_run_engine("suspicious_memory", _plan("windows"), None)
    assert exc.value.code == "VOLATILITY_REQUIRED"
    assert resolve_run_engine("suspicious_memory", _plan("windows"), "volatility") == "volatility"
    assert resolve_run_engine("processes_basic", _plan("linux"), None) == "volatility"
    with pytest.raises(MemoryExecutionValidationError):
        resolve_run_engine("processes_basic", _plan("linux"), "memprocfs")


def test_every_windows_profile_maps_to_memprocfs_or_is_volatility_only():
    from app.core.config import Settings

    profiles = set(Settings().allowed_memory_profiles)
    assert profiles == set(engine.PROFILE_PLUGINS) | engine.VOLATILITY_ONLY_PROFILES
    assert all(plugin in engine.INVENTORY_PLUGINS or plugin in ("memprocfs.console", "memprocfs.findevil") for plugins in engine.PROFILE_PLUGINS.values() for plugin in plugins)
