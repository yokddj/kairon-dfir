from __future__ import annotations

import json
from pathlib import Path
from types import SimpleNamespace
import zipfile

import pytest

from app.core.config import get_settings
from app.services import collection_file_explorer as explorer
from app.services.evidence_container_prep import ad1_metadata_path


@pytest.fixture(autouse=True)
def _fresh_caches():
    explorer.clear_caches()
    yield
    explorer.clear_caches()


def _evidence(tmp_path: Path, monkeypatch, *, ad1: bool = False):
    monkeypatch.setattr(get_settings(), "backend_data_dir", tmp_path / "data")
    from app.core.storage import build_evidence_root

    root = build_evidence_root("case-1", "ev-1")
    original = root / "original"
    original.mkdir(parents=True, exist_ok=True)
    archive = original / "alice.zip"
    with zipfile.ZipFile(archive, "w") as handle:
        handle.writestr("C/Users/alice/NTUSER.DAT", b"regf-data")
        handle.writestr("C/Users/alice/Desktop/notes.txt", b"hello")
        handle.writestr("C/Users/alice/Desktop/tool.exe", b"MZ")
        handle.writestr("C/Users/alice/Desktop/desktop.ini", b"")
    metadata = {}
    if ad1:
        source = root / "source" / "alice.ad1"
        source.parent.mkdir(parents=True)
        source.write_bytes(b"ADSEGMENTEDFILE")
        sidecar = ad1_metadata_path(root)
        sidecar.parent.mkdir(parents=True)
        sidecar.write_text(json.dumps({"version": 1, "files": {
            "C/Users/alice/Desktop/notes.txt": {"crtime": 1700000000, "mtime": 1700000100, "atime": 1700000200, "ctime": 1700000300,
                                                "md5": "5d41402abc4b2a76b9719d911017c592", "owner": "alice", "attributes": ["hidden"]},
        }}))
        metadata = {"repacked_from": {"path": str(source), "steps": [{"format": "ad1"}]}}
    return SimpleNamespace(id="ev-1", case_id="case-1", stored_path=str(archive), original_filename="alice.ad1" if ad1 else "alice.zip", sha256="00", metadata_json=metadata)


def test_collection_is_one_volume_with_its_folder_tree(tmp_path, monkeypatch):
    evidence = _evidence(tmp_path, monkeypatch)
    volumes = explorer.list_volumes(evidence, "infected")
    assert volumes["kind"] == "collection"
    assert [(item["id"], item["filesystem_type"], item["file_count"]) for item in volumes["volumes"]] == [("collection", "ZIP collection", 4)]

    root = explorer.list_directory(evidence, "collection", path="/", max_entries=100)
    assert [(item["name"], item["kind"]) for item in root["entries"]] == [("C", "dir")]
    desktop = explorer.list_directory(evidence, "collection", path="/C/Users/alice/Desktop", max_entries=100)
    # Listed although ingestion skips it (empty desktop.ini).
    assert [item["name"] for item in desktop["entries"]] == ["desktop.ini", "notes.txt", "tool.exe"]
    alice = explorer.list_directory(evidence, "collection", path="/C/Users/alice", max_entries=100)
    assert [(item["name"], item["kind"]) for item in alice["entries"]] == [("Desktop", "dir"), ("NTUSER.DAT", "file")]
    with pytest.raises(explorer.CollectionExplorerError):
        explorer.list_directory(evidence, "collection", path="/nope", max_entries=100)


def test_ad1_collection_shows_what_ftk_recorded(tmp_path, monkeypatch):
    evidence = _evidence(tmp_path, monkeypatch, ad1=True)
    assert explorer.list_volumes(evidence, "infected")["volumes"][0]["filesystem_type"] == "AD1 logical image"
    notes = next(item for item in explorer.list_directory(evidence, "collection", path="/C/Users/alice/Desktop", max_entries=100)["entries"] if item["name"] == "notes.txt")
    assert (notes["crtime"], notes["mtime"], notes["atime"], notes["ctime"]) == (1700000000, 1700000100, 1700000200, 1700000300)
    assert notes["owner"] == "alice"
    assert notes["attributes"] == ["hidden"]


def test_find_and_export(tmp_path, monkeypatch):
    evidence = _evidence(tmp_path, monkeypatch, ad1=True)
    found = explorer.find_files(evidence, "collection", pattern="*.exe", path="/")
    assert [item["path"] for item in found["results"]] == ["/C/Users/alice/Desktop/tool.exe"]

    out = tmp_path / "out"
    response = explorer.export_into(evidence, "collection", items=[{"path": "/C/Users/alice/Desktop"}], output_dir=out, max_bytes=10_000, max_files=10)
    by_path = {item["path"]: item for item in response["manifest"]}
    assert set(by_path) == {"/C/Users/alice/Desktop/desktop.ini", "/C/Users/alice/Desktop/notes.txt", "/C/Users/alice/Desktop/tool.exe"}
    assert (out / "files/C/Users/alice/Desktop/notes.txt").read_bytes() == b"hello"
    # The MD5 FTK recorded matches the bytes exported.
    assert by_path["/C/Users/alice/Desktop/notes.txt"]["md5_computed"] == "5d41402abc4b2a76b9719d911017c592"
    assert by_path["/C/Users/alice/Desktop/notes.txt"]["reason"] == ""


def test_disk_explorer_answers_for_a_collection(tmp_path, monkeypatch):
    from app.services import disk_file_explorer

    evidence = _evidence(tmp_path, monkeypatch)

    class _Query:
        def filter(self, *args):
            return self

        def first(self):
            return None

    db = SimpleNamespace(query=lambda *args: _Query())
    assert disk_file_explorer.list_volumes(db, evidence)["kind"] == "collection"
    listing = disk_file_explorer.list_directory(db, evidence, "collection", path="C/Users", inode=None)
    assert [item["name"] for item in listing["entries"]] == ["alice"]
