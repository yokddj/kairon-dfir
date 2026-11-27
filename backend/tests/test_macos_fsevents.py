"""FSEvents pages (synthetic) and the on-demand search."""
from __future__ import annotations

import gzip
import struct
from pathlib import Path
from types import SimpleNamespace

from app.ingest.macos.fsevents import iter_directory, iter_records
from app.ingest.macos.helpers import list_macos_artifacts
from app.services import macos_fsevents

FILE, FOLDER = 0x00800000, 0x01000000


def _page(version: int, records: list[tuple[str, int, int]]) -> bytes:
    tail = {1: b"", 2: struct.pack("<Q", 7), 3: struct.pack("<Q", 7) + b"\0\0\0\0"}[version]
    body = b"".join(path.encode() + b"\0" + struct.pack("<QI", event_id, flags) + tail for path, event_id, flags in records)
    return f"{version}SLD".encode() + b"\0\0\0\0" + struct.pack("<I", 12 + len(body)) + body


def _journal(root: Path) -> Path:
    directory = root / "[root]/System/Volumes/Data/.fseventsd"
    directory.mkdir(parents=True)
    (directory / "fseventsd-uuid").write_text("uuid")
    (directory / "0000000000000010").write_bytes(gzip.compress(_page(1, [("Users/alice/old.txt", 16, FILE | 0x1)])))
    (directory / "0000000000000400").write_bytes(gzip.compress(
        _page(3, [
            ("Users/alice/Downloads/tool.dmg", 1000, FILE | 0x1 | 0x10),
            ("Users/alice/Downloads", 1001, FOLDER | 0x80),
            ("Users/alice/Downloads/tool.dmg", 1002, FILE | 0x2 | 0x4000),
        ]) + _page(2, [("private/tmp/x", 1003, FILE | 0x8)])
    ))
    return directory


def test_pages_of_every_version(tmp_path: Path) -> None:
    records = list(iter_directory(_journal(tmp_path)))
    assert [record.event_id for record in records] == [16, 1000, 1001, 1002, 1003]
    assert records[0].version == 1 and records[0].node_id is None
    assert records[1].changes == ["created", "modified"] and records[1].item_type == "file"
    assert records[2].changes == ["folder_created"] and records[2].item_type == "folder"
    # A bit not confirmed is reported by value, never named.
    assert records[3].changes == ["removed"] and records[3].unknown_flags == ["0x4000"]
    assert records[4].version == 2 and records[4].node_id == 7


def test_truncated_page_stops_cleanly() -> None:
    data = _page(3, [("a/b", 1, FILE)])[:-5]
    assert list(iter_records(data, page_file="p", page_written=None)) == []


def test_search_on_demand(tmp_path: Path, monkeypatch) -> None:
    _journal(tmp_path)
    monkeypatch.setattr(macos_fsevents, "evidence_extract_dir", lambda case_id, evidence_id: tmp_path)
    evidence = SimpleNamespace(id="e", case_id="c", stored_path=None)
    found = macos_fsevents.search(evidence, path_contains="DOWNLOADS/tool")
    assert [record["event_id"] for record in found["records"]] == [1002, 1000]
    assert found["records"][0]["volume"] == "/System/Volumes/Data"
    removed = macos_fsevents.search(evidence, path_contains="tool.dmg", changes=["removed"])
    assert [record["event_id"] for record in removed["records"]] == [1002]
    folders = macos_fsevents.search(evidence, path_contains="downloads", item_type="folder")
    assert [record["path"] for record in folders["records"]] == ["Users/alice/Downloads"]
    limited = macos_fsevents.search(evidence, path_contains="Users/", limit=1)
    assert limited["truncated"] and limited["total_matches"] == 4 and limited["records"][0]["event_id"] == 1002
    assert macos_fsevents.summarize(evidence)["volumes"] == [{"volume": "/System/Volumes/Data", "page_files": 2}]


def test_listing_keeps_one_row_for_the_journal(tmp_path: Path) -> None:
    root = tmp_path / "collection"
    _journal(root)
    artifacts, stats = list_macos_artifacts(root)
    journal = [item for item in artifacts if item["artifact_type"] == "macos_fsevents"]
    assert len(journal) == 1 and journal[0]["parser"] == "not_implemented" and journal[0]["status"] == "detected_not_parsed"
    # Its pages are neither listed nor counted as unparsed files.
    assert stats["files_seen"] == 0
