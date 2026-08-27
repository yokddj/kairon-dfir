from __future__ import annotations

import subprocess
import zipfile
from pathlib import Path

import pytest

from app.ingest import archive


def _make_plain_zip(path: Path) -> Path:
    with zipfile.ZipFile(path, "w", compression=zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("collected/notes.txt", "hello" * 100)
    return path


def test_a_normal_zip_still_goes_through_python(tmp_path: Path) -> None:
    source = _make_plain_zip(tmp_path / "plain.zip")
    assert archive._zip_needs_seven_zip(source) is False


def test_a_deflate64_member_is_routed_to_seven_zip(tmp_path: Path) -> None:
    """Python's zipfile raises NotImplementedError on Deflate64.

    Windows and several collection tools emit Deflate64 once the content gets
    large, so a perfectly valid triage archive failed with an opaque
    "Extraction failed unexpectedly" halfway through extraction.
    """
    source = tmp_path / "deflate64.zip"
    _make_plain_zip(source)
    # Rewrite the member's compression method to Deflate64 (9) in the central
    # directory, which is what zipfile inspects before deciding it cannot cope.
    with zipfile.ZipFile(source) as zf:
        infos = zf.infolist()
    assert infos
    raw = source.read_bytes()
    # ZIP_DEFLATED is 8; flip the two on-disk occurrences (local header and
    # central directory) to 9 so infolist() reports Deflate64.
    patched = raw.replace(b"\x08\x00", b"\x09\x00", 2)
    source.write_bytes(patched)

    assert archive._zip_needs_seven_zip(source) is True


def test_python_really_cannot_read_deflate64(tmp_path: Path) -> None:
    """Pins the premise: if zipfile ever gains Deflate64 this test tells us."""
    assert 9 not in archive._ZIPFILE_SUPPORTED_COMPRESSION


def test_unreadable_zip_is_not_silently_rerouted(tmp_path: Path) -> None:
    """A corrupt central directory is a different failure and must keep its
    own classification instead of being handed to 7-Zip."""
    source = tmp_path / "broken.zip"
    source.write_bytes(b"PK\x03\x04 not really a zip")
    assert archive._zip_needs_seven_zip(source) is False


@pytest.mark.skipif(subprocess.run(["which", "7z"], capture_output=True).returncode != 0, reason="7z not installed")
def test_seven_zip_is_available_for_the_fallback() -> None:
    assert subprocess.run(["7z"], capture_output=True).returncode in (0, 1, 2)
