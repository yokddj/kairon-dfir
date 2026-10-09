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
        assert document["event"]["message"] and document["search_text"] == document["event"]["message"]
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
    assert document["event"]["type"] == "event_id_4688"
    assert document["process"] == {"pid": "5152"}


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
    assert saved == sorted(f"timeline_{name}.csv" for name in memprocfs_findevil.TIMELINE_FILES if name != "prefetch")
    assert not any(name in " ".join(read_paths) for name in ("timeline_process", "timeline_net", "timeline_thread"))
    assert set(memprocfs_findevil.TIMELINE_FILES) == set(memprocfs_timeline.TIMELINES)


def test_execution_indexes_saved_timelines_without_failing_the_run(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    from types import SimpleNamespace

    from app.services.memory import execution

    run = SimpleNamespace(id="run-1", case_id="case-1", evidence_id="ev-1")
    monkeypatch.setattr(execution, "index_memprocfs_timeline", lambda directory, **kwargs: {"indexed": 3, "directory": directory.name, **kwargs})
    assert execution._index_memprocfs_timeline(run, tmp_path)["indexed"] == 3

    def broken(*_a, **_k):
        raise RuntimeError("opensearch down")

    monkeypatch.setattr(execution, "index_memprocfs_timeline", broken)
    report = execution._index_memprocfs_timeline(run, tmp_path)
    assert report["indexed"] == 0 and "opensearch down" in report["error"]


def test_timeline_quick_filter_selects_every_memprocfs_timeline() -> None:
    from app.services import search_service, timeline_service

    quick = next(item for item in timeline_service.TIMELINE_QUICK_FILTERS if item["id"] == "memory_memprocfs")
    assert set(memprocfs_timeline.ARTIFACT_TYPES) <= set(search_service._artifact_type_values(quick["params"]["artifact_type"]))
