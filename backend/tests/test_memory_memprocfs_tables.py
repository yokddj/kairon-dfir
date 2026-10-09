"""MemProcFS's forensic inventories as tables (app.services.memory.memprocfs_tables) and the
scheduled tasks and services they add to the case's Persistence view."""

from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace

import pytest

from app.services.memory import memprocfs_tables
from app.services.memory.memprocfs_findevil import TABLE_FILES
from app.services.memory.memprocfs_tables import TABLES, memprocfs_table, readable_dns_row

TASKS = (
    "GUID,TaskName,TaskPath,User,TimeMostRecent,CommandLine,Parameters,TimeReg,TimeCreate,TimeLastRun,TimeCompleted\n"
    '{15C0A147},MicrosoftEdgeUpdateTaskMachineCore,\\MicrosoftEdgeUpdateTaskMachineCore,Author,"2025-03-07 19:35:30","C:\\Program Files (x86)\\Microsoft\\EdgeUpdate\\MicrosoftEdgeUpdate.exe",/c,"2025-03-03 22:23:16","2025-03-03 22:23:16","2025-03-07 19:35:16","2025-03-07 19:35:30"\n'
    '{AAAA0001},Updater,\\Updater,bob,"2025-03-07 19:40:00",powershell.exe,"-nop -w hidden -enc SQBFAFgA","2025-03-07 19:39:00","2025-03-07 19:39:00",,\n'
)
NETDNS = (
    "Address,Type,Flags,TTL,Name,Data\n"
    '1bcab858500,A,0x2009,364,"",23.221.212.196\n'
    "1bcab858580,CNAME,0x3009,364,?ild᳭ⴌrd.f.tlu.dl.delivery.mp.microsoft.com.edgesuite.net,wpad.nullsec.link\n"
    "1bcab858600,A,0x2009,364,wpad.nullsec.link,10.0.2.15\n"
)


@pytest.fixture
def saved(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    directory = tmp_path / "memprocfs-timeline"
    directory.mkdir()
    (directory / "tasks.csv").write_text(TASKS, encoding="utf-8")
    (directory / "netdns.csv").write_text(NETDNS, encoding="utf-8")
    (directory / "services.csv").write_text("PID,Ordinal,ServiceName,DisplayName,User,StartType,State,Type1,Type2,ObjectAddress,ImagePath,DriverpathOrCmdline\n", encoding="utf-8")
    monkeypatch.setattr(memprocfs_tables, "active_find_evil_run", lambda db, case_id, evidence_id: ({"id": "run-fe"}, directory))
    return directory


def test_every_table_is_saved_by_the_child() -> None:
    assert {table.file for table in TABLES} == {f"{name}.csv" for name in TABLE_FILES}


def test_dns_rows_read_from_garbage_memory_are_hidden() -> None:
    assert readable_dns_row({"Name": "wpad.nullsec.link", "Data": "10.0.2.15"})
    assert not readable_dns_row({"Name": "", "Data": "23.221.212.196"})
    assert not readable_dns_row({"Name": "?ild᳭ⴌrd.f.tlu.dl.delivery.mp.microsoft.com", "Data": "x"})
    assert not readable_dns_row({"Name": "ok.example", "Data": "?119緘锫75F"})


def test_table_lists_rows_counts_and_curated_columns(saved: Path) -> None:
    result = memprocfs_table(None, case_id="c", evidence_id="e", table="tasks")
    assert result["available"] and result["total"] == 2 and result["run"] == {"id": "run-fe"}
    assert [column["key"] for column in result["columns"]][:2] == ["TaskName", "CommandLine"]
    counts = {item["key"]: item["count"] for item in result["tables"]}
    assert counts["tasks"] == 2 and counts["netdns"] == 1 and counts["services"] == 0 and counts["drivers"] == 0
    dns = memprocfs_table(None, case_id="c", evidence_id="e", table="netdns")
    assert [row["Name"] for row in dns["items"]] == ["wpad.nullsec.link"] and dns["hidden"] == 2


def test_table_filter_and_paging(saved: Path) -> None:
    result = memprocfs_table(None, case_id="c", evidence_id="e", table="tasks", q="-ENC")
    assert [row["TaskName"] for row in result["items"]] == ["Updater"]
    second = memprocfs_table(None, case_id="c", evidence_id="e", table="tasks", page=2, page_size=1)
    assert [row["TaskName"] for row in second["items"]] == ["Updater"] and second["total"] == 2


def test_no_find_evil_run_is_unavailable(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(memprocfs_tables, "active_find_evil_run", lambda *a: (None, None))
    result = memprocfs_table(None, case_id="c", evidence_id="e", table="tasks")
    assert not result["available"] and result["items"] == [] and result["run"] is None


def test_run_directory_is_found_under_the_data_dir(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    from app.core import config

    (tmp_path / "memory-output" / "run-1" / "memprocfs-timeline").mkdir(parents=True)
    monkeypatch.setattr(config, "get_settings", lambda: SimpleNamespace(backend_data_dir=tmp_path, memory_output_root=None))
    assert memprocfs_tables._run_directory("memory-output/run-1") == tmp_path / "memory-output" / "run-1" / "memprocfs-timeline"
    assert memprocfs_tables._run_directory("memory-output/missing") is None


def test_persistence_lists_memory_tasks_with_their_risk(saved: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    from app.services import investigation_memory, startup_persistence

    monkeypatch.setattr(investigation_memory, "memory_evidences", lambda db, case_id, evidence_id=None: [SimpleNamespace(id="ev-mem")])
    monkeypatch.setattr(investigation_memory, "_evidence_host_name", lambda db, evidence: "DESKTOP-1")
    items = startup_persistence._memory_inventory_items(None, "c", [], "")
    by_name = {item["name"]: item for item in items}
    suspicious = by_name["Updater"]
    assert suspicious["type"] == "scheduled_task" and suspicious["source_artifact"] == "memory_memprocfs"
    assert suspicious["command_or_target"] == "powershell.exe -nop -w hidden -enc SQBFAFgA"
    assert suspicious["user"] == "bob" and suspicious["host"] == "desktop-1" and suspicious["first_seen"] == "2025-03-07T19:39:00Z"
    assert suspicious["risk_score"] > by_name["MicrosoftEdgeUpdateTaskMachineCore"]["risk_score"]
    assert startup_persistence._memory_inventory_items(None, "c", ["other-host"], "") == []
    assert [item["name"] for item in startup_persistence._memory_inventory_items(None, "c", [], "edgeupdate")] == ["MicrosoftEdgeUpdateTaskMachineCore"]


def test_memory_is_a_default_persistence_source() -> None:
    from app.services import startup_persistence

    assert "memory" in startup_persistence._active_source_names("", set(), set())
    assert "memory" in startup_persistence._active_source_names("", set(), {"scheduled_task"})
