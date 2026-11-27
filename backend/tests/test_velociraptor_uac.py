"""A UAC collection run by Velociraptor is read as an archive holding a UAC collection, not through
Velociraptor's (Windows) artifact discovery. Synthetic collections only."""

from __future__ import annotations

import io
import json
import tarfile
import zipfile
from pathlib import Path

import pytest

from app.api.routes_evidence import _should_route_to_raw_collection_discovery
from app.ingest.uac.velociraptor import tar_stream_is_uac, uac_archives_in_velociraptor_collection, velociraptor_files_beside_uac
from app.ingest.velociraptor.zip_inventory import open_evidence_container

UAC_LOG = "2026-01-02 03:04:05 +0000 INF Unix-like Artifacts Collector 3.4.0\n2026-01-02 03:04:05 +0000 INF Operating system: linux\n"
ARCHIVE = "uploads/file/uac-testhost-linux-20260102030405.tar.gz"


def _tar_gz(members: dict[str, str]) -> bytes:
    buffer = io.BytesIO()
    with tarfile.open(fileobj=buffer, mode="w:gz") as archive:
        for name, text in members.items():
            data = text.encode()
            info = tarfile.TarInfo(name)
            info.size = len(data)
            archive.addfile(info, io.BytesIO(data))
    return buffer.getvalue()


UAC_TAR = {"uac.log": UAC_LOG, "live_response/process/ps.txt": "PID CMD\n1 init\n", "[root]/etc/hostname": "testhost\n"}


def _collection(path: Path, *, tar_members: dict[str, str] = UAC_TAR, extra: dict[str, bytes] | None = None) -> Path:
    with zipfile.ZipFile(path, "w") as archive:
        archive.writestr(ARCHIVE, _tar_gz(tar_members))
        archive.writestr(ARCHIVE.replace(".tar.gz", ".log"), UAC_LOG)
        archive.writestr("results/Generic.Collection.UAC.json", json.dumps({"Stdout": "collecting", "ReturnCode": 0}) + "\n")
        archive.writestr("log.json", json.dumps({"level": "INFO", "message": "started"}) + "\n")
        archive.writestr("uploads.json", json.dumps({"vfs_path": "/tmp/uac.tar.gz"}) + "\n")
        archive.writestr("client_info.json", json.dumps({"client_id": "C.test", "hostname": "testhost"}))
        archive.writestr("collection_context.json", json.dumps({"artifacts": ["Generic.Collection.UAC"]}))
        for name, data in (extra or {}).items():
            archive.writestr(name, data)
    return path


def _entries(path: Path) -> list[str]:
    return [entry.path for entry in open_evidence_container(path).list_entries() if not entry.is_dir]


def test_a_tar_is_uac_by_its_first_members() -> None:
    assert tar_stream_is_uac(io.BytesIO(_tar_gz(UAC_TAR)))
    assert tar_stream_is_uac(io.BytesIO(_tar_gz({f"uac-out/{name}": text for name, text in UAC_TAR.items()})))
    # A uac.log without UAC's output beside it, or output without the log, is not.
    assert not tar_stream_is_uac(io.BytesIO(_tar_gz({"uac.log": UAC_LOG, "notes/readme.txt": "x"})))
    assert not tar_stream_is_uac(io.BytesIO(_tar_gz({"live_response/ps.txt": "x"})))
    assert not tar_stream_is_uac(io.BytesIO(b"not a tar"))


def test_a_collection_that_only_ran_uac_is_not_sent_to_discovery(tmp_path: Path) -> None:
    path = _collection(tmp_path / "Collection-testhost.zip")
    entries = _entries(path)
    assert uac_archives_in_velociraptor_collection(open_evidence_container(path), entries) == [ARCHIVE]
    assert _should_route_to_raw_collection_discovery(path, entries) is False


@pytest.mark.parametrize(
    "case",
    ["other_artifact", "not_uac"],
)
def test_other_velociraptor_collections_keep_discovery(tmp_path: Path, case: str) -> None:
    if case == "other_artifact":
        path = _collection(tmp_path / "c.zip", extra={"uploads/auto/C%3A/Windows/System32/winevt/Logs/Security.evtx": b"ElfFile\x00"})
    else:
        path = _collection(tmp_path / "c.zip", tar_members={"data/file.txt": "x"})
    entries = _entries(path)
    assert uac_archives_in_velociraptor_collection(open_evidence_container(path), entries) == []
    assert _should_route_to_raw_collection_discovery(path, entries) is True


def test_velociraptor_files_beside_the_extracted_uac_are_left_out(tmp_path: Path) -> None:
    extract = tmp_path / "extracted"
    for name in ("client_info.json", "collection_context.json", "log.json", "uploads.json", "results/Generic.Collection.UAC.json", ARCHIVE, ARCHIVE.replace(".tar.gz", ".log"), "uploads/file/notes.log"):
        (extract / name).parent.mkdir(parents=True, exist_ok=True)
        (extract / name).write_text("x")
    root = extract / "_nested_0_uac-testhost-linux-20260102030405.tar"
    (root / "live_response").mkdir(parents=True)
    (root / "uac.log").write_text(UAC_LOG)
    (root / "results.json").write_text("{}")  # inside the UAC output: kept

    dropped = velociraptor_files_beside_uac(extract, root)
    assert dropped == sorted(
        ["client_info.json", "collection_context.json", "log.json", "results/Generic.Collection.UAC.json", "uploads.json", ARCHIVE.replace(".tar.gz", ".log")]
    )
    # Without Velociraptor's files, or with the UAC output at the top, nothing is left out.
    assert velociraptor_files_beside_uac(root, root) == []


def test_the_log_beside_an_archive_already_expanded_is_left_out(tmp_path: Path) -> None:
    extract = tmp_path / "extracted"
    log = extract / ARCHIVE.replace(".tar.gz", ".log")
    log.parent.mkdir(parents=True)
    log.write_text("x")
    (extract / "client_info.json").write_text("{}")
    # The ingest removed the .tar.gz after expanding it into _nested_0_<name>.tar.
    root = extract / "_nested_0_uac-testhost-linux-20260102030405.tar"
    (root / "live_response").mkdir(parents=True)
    (root / "uac.log").write_text(UAC_LOG)
    assert velociraptor_files_beside_uac(extract, root) == ["client_info.json", ARCHIVE.replace(".tar.gz", ".log")]

