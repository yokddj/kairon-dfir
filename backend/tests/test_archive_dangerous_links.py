"""A tar whose only 7-Zip errors are refused links ("Dangerous link path was ignored") is a complete
extraction minus those links, not a corrupt archive. Collections of Unix systems (UAC's tar of a
Mac) hold hundreds of such relative links.
"""
from __future__ import annotations

import subprocess
from pathlib import Path

import pytest

from app.ingest.archive import extract_archive, skipped_dangerous_links


def _error(output: str, code: int = 2) -> subprocess.CalledProcessError:
    return subprocess.CalledProcessError(code, ["7z"], output=output.encode(), stderr=b"")


def test_only_dangerous_links_is_not_a_failure() -> None:
    output = (
        "Extracting archive: t.tar\n"
        "ERROR: Dangerous link path was ignored : ./[root]/a/b/link.plist : ../../x/target.plist\n"
        "ERROR: Dangerous link path was ignored : ./[root]/c/other : ../../../y\n"
        "Sub items Errors: 2\n\nArchives with Errors: 1\n"
    )
    assert skipped_dangerous_links(_error(output)) == ["./[root]/a/b/link.plist", "./[root]/c/other"]


@pytest.mark.parametrize("output, code", [
    ("ERROR: Dangerous link path was ignored : a : ../b\nERROR: Data Error : big.bin\n", 2),
    ("ERROR: Dangerous link path was ignored : a : ../b\n", 7),
    ("ERROR: t.tar\nUnexpected end of archive\n", 2),
])
def test_any_other_error_still_fails(output: str, code: int) -> None:
    assert skipped_dangerous_links(_error(output, code)) is None


def test_extraction_keeps_everything_but_the_refused_links(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """What 7-Zip 25 on Linux does (the worker's): the files are written, an empty file stands
    where the refused link was, and it exits with 2 naming each link."""
    from app.ingest import archive as archive_module

    def fake_run(command, **kwargs):
        out = Path(next(part for part in command if part.startswith("-o"))[2:])
        (out / "[root]/a/b").mkdir(parents=True)
        (out / "[root]/a/b/real.txt").write_text("hello", encoding="utf-8")
        (out / "[root]/a/b/link.plist").write_bytes(b"")
        raise _error("ERROR: Dangerous link path was ignored : ./[root]/a/b/link.plist : ../../../x/target.plist\nSub items Errors: 1\n")

    monkeypatch.setattr(archive_module.subprocess, "run", fake_run)
    archive = tmp_path / "collection.tar"
    archive.write_bytes(b"")
    extracted, entries = extract_archive(archive, tmp_path / "out")
    assert extracted == ["[root]/a/b/real.txt"]
    assert not (tmp_path / "out/[root]/a/b/link.plist").exists()
    skipped = [entry for entry in entries if entry.get("reason") == "unsafe_link_not_followed"]
    assert [entry["path"] for entry in skipped] == ["[root]/a/b/link.plist"]
