"""MemProcFS's process and network inventory, standing in for Volatility without symbols."""

from __future__ import annotations

from app.services.memory.artifact_normalizers import memprocfs_net_rows, normalize_windows_netscan
from app.services.memory.memprocfs_inventory import csv_rows
from app.services.memory.normalizers import merge_memory_process_results, normalize_memprocfs_processes

# Header and row shapes of MemProcFS 5.x \forensic\csv\process.csv and net.csv.
PROCESS_CSV = (
    "PID,PPID,State,ShortName,Name,IntegrityLevel,User,CreateTime,ExitTime,Wow64,EPROCESS,PEB,PEB32,DTB,UserDTB,UserPath,KernelPath,CommandLine,Flag\n"
    '4,0,0,System,System,System,SYSTEM,"2024-02-29 09:25:57",,0,0xffffaa0e81ed5180,0x0,0x0,0x1ae000,0x101600000,"",System,"",-\n'
    '7432,6120,0,powershell.exe,powershell.exe,Medium,analyst,"2024-03-22 12:40:01",,0,0xffffaa0e8a128080,0x1,0x0,0x1,0x1,'
    '"C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe","","powershell.exe -nop -w hidden -enc AAAA",-\n'
    '812,6120,0,old.exe,old.exe,Medium,analyst,"2024-03-22 12:00:00","2024-03-22 12:05:00",1,0xffffaa0e8a000000,0x1,0x1,0x1,0x1,"","","",-\n'
)
NET_CSV = (
    "Proto,State,SrcAddr,SrcPort,DstAddr,DstPort,Time,Object,PID,Process,ProcessPath\n"
    'TCP4,ESTABLISHED,192.0.2.10,49733,203.0.113.5,443,"2024-03-22 12:46:16 UTC",0xffffaa0e86bcd7b0,7432,"powershell.exe",""\n'
    'TCP6,LISTENING,::,445,***,0,"",0xffffaa0e86bcd000,4,"System",""\n'
)


def test_processes_keep_parent_command_line_user_and_times():
    result = normalize_memprocfs_processes(csv_rows(PROCESS_CSV))
    by_pid = {item["process"]["pid"]: item for item in result["processes"]}
    ps = by_pid[7432]["process"]
    assert ps["name"] == "powershell.exe" and ps["ppid"] == 6120
    assert ps["command_line"] == "powershell.exe -nop -w hidden -enc AAAA"
    assert ps["user"] == "analyst"
    assert ps["create_time"] == "2024-03-22T12:40:01+00:00" and ps["exit_time"] is None
    assert by_pid[7432]["visibility"]["pslist"] is True
    assert by_pid[812]["state"]["terminated_candidate"] is True and by_pid[812]["process"]["wow64"] is True
    assert {"parent_pid": 6120, "child_pid": 7432} in [{"parent_pid": e["parent_pid"], "child_pid": e["child_pid"]} for e in result["edges"]]


def test_merged_documents_say_they_come_from_memprocfs_on_windows():
    merged = merge_memory_process_results([normalize_memprocfs_processes(csv_rows(PROCESS_CSV))], case_id="c", evidence_id="e", memory_run_id="r")
    doc = next(d for d in merged["processes"] if d["process"]["pid"] == 7432)
    assert doc["backend"] == "memprocfs" and doc["os"]["family"] == "windows"
    assert doc["plugins"] == ["memprocfs.pslist"]


def test_network_rows_read_like_netscan():
    result = normalize_windows_netscan(memprocfs_net_rows(csv_rows(NET_CSV)), case_id="c", evidence_id="e", scan_run_id="r", plugin_run_id="p", source_plugin="memprocfs.network")
    established, listening = result["items"]
    assert (established["protocol"], established["state"]) == ("TCPv4", "ESTABLISHED")
    assert (established["local_address"], established["local_port"], established["remote_address"], established["remote_port"]) == ("192.0.2.10", 49733, "203.0.113.5", 443)
    assert established["pid"] == 7432 and established["process_name"] == "powershell.exe"
    assert established["create_time"] == "2024-03-22T12:46:16+00:00"
    assert established["source_plugin"] == "memprocfs.network"
    assert listening["remote_address"] is None and listening["local_port"] == 445 and listening["protocol"] == "TCPv6"
