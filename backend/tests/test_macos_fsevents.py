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


# -- shared file lists ---------------------------------------------------------------------------

import plistlib  # noqa: E402

from app.ingest.macos.shared_file_lists import parse_bookmark, parse_shared_file_list  # noqa: E402


def _bookmark(parts: list[str], created: float) -> bytes:
    """A minimal CFURL bookmark: header, data items, one table of contents."""
    data = bytearray(b"\0\0\0\0")  # first TOC offset, patched below
    offsets = []
    for part in parts:
        offsets.append(len(data))
        raw = part.encode()
        data += struct.pack("<II", len(raw), 0x0101) + raw + b"\0" * (-len(raw) % 4)
    array_offset = len(data)
    data += struct.pack("<II", 4 * len(offsets), 0x0601) + b"".join(struct.pack("<I", item) for item in offsets)
    date_offset = len(data)
    data += struct.pack("<II", 8, 0x0400) + struct.pack(">d", created)
    toc_offset = len(data)
    entries = [(0x1004, array_offset), (0x1040, date_offset)]
    data += struct.pack("<IIIII", 0, 0xFFFFFFFE, 1, 0, len(entries)) + b"".join(struct.pack("<III", key, offset, 0) for key, offset in entries)
    struct.pack_into("<I", data, 0, toc_offset)
    header = b"book" + struct.pack("<III", 48 + len(data), 0x10040000, 48) + b"\0" * 32
    return header + bytes(data)


def _archive(items: list[dict]) -> bytes:
    objects: list = ["$null"]

    def add(value) -> plistlib.UID:
        objects.append(value)
        return plistlib.UID(len(objects) - 1)

    item_uids = []
    for item in items:
        keys = [add(key) for key in item]
        values = [add(value) for value in item.values()]
        item_uids.append(add({"NS.keys": keys, "NS.objects": values}))
    items_uid = add({"NS.objects": item_uids})
    root = add({"NS.keys": [add("items")], "NS.objects": [items_uid]})
    return plistlib.dumps({"$version": 100000, "$archiver": "NSKeyedArchiver", "$top": {"root": root}, "$objects": objects}, fmt=plistlib.FMT_BINARY)


def test_bookmark_path_and_creation() -> None:
    parsed = parse_bookmark(_bookmark(["Users", "alice", "Documents", "plan.pages"], 789_000_000.0))
    assert parsed["path"] == "/Users/alice/Documents/plan.pages"
    assert parsed["target_created"].startswith("2026-")
    assert parse_bookmark(b"not a bookmark") == {}


def test_application_recent_documents(tmp_path: Path) -> None:
    rel = "[root]/Users/alice/Library/Application Support/com.apple.sharedfilelist/com.apple.LSSharedFileList.ApplicationRecentDocuments/com.example.editor.sfl4"
    target = tmp_path / rel
    target.parent.mkdir(parents=True)
    target.write_bytes(_archive([
        {"Name": "plan.pages", "Bookmark": _bookmark(["Users", "alice", "Documents", "plan.pages"], 789_000_000.0)},
        {"Name": "server", "uuid": "x"},
    ]))
    rows = parse_shared_file_list(target, source_path=rel)
    assert [row["item_path"] for row in rows] == ["/Users/alice/Documents/plan.pages", ""]
    assert rows[0]["list_name"] == "ApplicationRecentDocuments" and rows[0]["bundle_id"] == "com.example.editor"
    assert rows[0]["username"] == "alice" and rows[0]["list_position"] == 1 and rows[0]["timestamp"] is None
    artifacts, _ = list_macos_artifacts(tmp_path)
    assert [item["parser"] for item in artifacts] == ["macos_recent_items_raw"]
