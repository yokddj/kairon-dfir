"""Extraction reports 7-Zip's percentage while it unpacks a large archive, and an archive already
expanded into the managed copy is removed (its contents are there; the original evidence keeps it)."""

from __future__ import annotations

import io
import os
import subprocess
import tarfile
from pathlib import Path
from types import SimpleNamespace

import pytest

from app.ingest import archive as archive_module
from app.workers import tasks

FAKE_7Z = """#!/usr/bin/env bash
printf '\\n7-Zip fake\\n'
printf '  0%% - a.tar'; printf '\\b\\b\\b\\b\\b\\b\\b\\b\\b\\b\\b'
printf ' 37%% 12 - a.tar'; printf '\\b\\b\\b\\b\\b\\b\\b\\b\\b\\b\\b\\b\\b\\b'
printf '100%% - a.tar\\n'
if [[ "${FAKE_7Z_FAIL:-}" == 1 ]]; then
  printf 'ERROR: Dangerous link path was ignored : link : ../../etc\\n'
  exit 2
fi
printf 'Everything is Ok\\n'
"""


@pytest.fixture()
def fake_7z(tmp_path, monkeypatch):
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    (bin_dir / "7z").write_text(FAKE_7Z)
    (bin_dir / "7z").chmod(0o755)
    monkeypatch.setenv("PATH", f"{bin_dir}{os.pathsep}{os.environ['PATH']}")


def test_seven_zip_percentage_is_reported(fake_7z) -> None:
    seen: list[int] = []
    archive_module._run_seven_zip_with_progress(["7z", "x", "a.tar"], timeout=30, on_percent=seen.append)
    assert seen == [0, 37, 100]


def test_seven_zip_errors_keep_their_text_without_the_progress(fake_7z, monkeypatch) -> None:
    monkeypatch.setenv("FAKE_7Z_FAIL", "1")
    with pytest.raises(subprocess.CalledProcessError) as exc_info:
        archive_module._run_seven_zip_with_progress(["7z", "x", "a.tar"], timeout=30, on_percent=lambda percent: None)
    output = archive_module._decode_process_output(exc_info.value)
    assert "Dangerous link path was ignored : link : ../../etc" in output and "%" not in output
    # The existing rule still reads it as "complete minus refused links".
    assert archive_module.skipped_dangerous_links(exc_info.value) == ["link"]


def test_the_percentage_moves_the_extraction_bar() -> None:
    pct, phase, indeterminate = tasks._compute_extraction_progress(is_selected_velociraptor=False, streaming_materialization_enabled=False, current_action="extracting_archive", total_files=0, processed_files=0, archive_percent=50)
    assert (pct, phase, indeterminate) == (11, "extracting", False)
    assert tasks._compute_extraction_progress(is_selected_velociraptor=False, streaming_materialization_enabled=False, current_action="extracting_archive", total_files=0, processed_files=0, archive_percent=100)[0] == 18


def _tar_gz(path: Path) -> None:
    with tarfile.open(path, "w:gz") as archive:
        for name, text in (("collection/a.txt", "a"), ("collection/b/c.txt", "c")):
            data = text.encode()
            info = tarfile.TarInfo(name)
            info.size = len(data)
            archive.addfile(info, io.BytesIO(data))


@pytest.mark.parametrize("remove", [True, False])
def test_an_expanded_archive_is_removed_from_the_managed_copy(tmp_path, remove) -> None:
    extract = tmp_path / "extracted"
    (extract / "uploads").mkdir(parents=True)
    source = extract / "uploads" / "collection.tar.gz"
    _tar_gz(source)
    entries = [{"path": "uploads/collection.tar.gz", "ignored": False, "status": "extracted", "size": source.stat().st_size, "local_path": str(source)}]
    files, result, _ = tasks._classify_and_dispatch_extracted(
        db=None,
        evidence=SimpleNamespace(id="e", case_id="c"),
        extract_dir=extract,
        extracted_files=["uploads/collection.tar.gz"],
        archive_entries=entries,
        remove_expanded_archives=remove,
    )
    assert any(path.endswith("collection/b/c.txt") for path in files)
    assert next(Path(extract / path).read_text() for path in files if path.endswith("collection/a.txt")) == "a"
    assert source.exists() is (not remove)
    expanded = [entry for entry in result if entry["path"] == "uploads/collection.tar.gz"]
    if remove:
        assert [entry["status"] for entry in expanded] == ["expanded"]
        assert "uploads/collection.tar.gz" not in files
        # No intermediate .tar left behind either.
        assert not [path for path in extract.rglob("*.tar") if path.is_file()]
