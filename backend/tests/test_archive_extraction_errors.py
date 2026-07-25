"""Tests for classified archive-extraction errors (ZIP / 7z family).

The ingestion pipeline review found that archive extraction failures for
the 7z family surfaced raw subprocess exceptions to analysts instead of a
clean diagnosis. This verifies every classified error code produces a
stable code and an analyst-facing message with no raw command/exception
text, while the technical detail is still preserved (for logs) on the
exception object.
"""
from __future__ import annotations

import errno
import subprocess
import zipfile
from pathlib import Path

import pytest

from app.ingest import archive as archive_module
from app.ingest.archive import (
    ArchiveExtractionError,
    _classify_seven_zip_failure,
    _classify_zip_failure,
    extract_archive,
)

PLACEHOLDER_SOURCE = Path("evidence.zip")


def _write_real_zip(path: Path, *, entries: dict[str, bytes] | None = None) -> None:
    entries = entries or {"readme.txt": b"hello"}
    with zipfile.ZipFile(path, "w") as zf:
        for name, data in entries.items():
            zf.writestr(name, data)


def _assert_message_is_clean(message: str) -> None:
    """No raw exception class names, tracebacks, or subprocess command
    reprs should ever reach the analyst-facing message."""
    lowered = message.lower()
    for leak_marker in ("traceback", "calledprocesserror", "filenotfounderror", "timeoutexpired", "badzipfile", "['7z'", "exit status"):
        assert leak_marker not in lowered, f"leaked internal detail {leak_marker!r} in message: {message}"


# ---------------------------------------------------------------------------
# ZIP family
# ---------------------------------------------------------------------------


def test_corrupted_zip_is_classified(tmp_path):
    source = tmp_path / "broken.zip"
    source.write_bytes(b"this is not a real zip file" * 10)
    dest = tmp_path / "out"

    with pytest.raises(ArchiveExtractionError) as exc_info:
        extract_archive(source, dest)

    err = exc_info.value
    assert err.code == "archive_corrupted"
    assert "corrupt" in err.message.lower()
    _assert_message_is_clean(err.message)
    assert err.detail  # technical detail preserved for logs


def test_zip_password_protected_is_classified():
    err = _classify_zip_failure(RuntimeError("Bad password for file 'secret.txt'"), PLACEHOLDER_SOURCE)
    assert err.code == "archive_password_protected"
    assert "password" in err.message.lower()
    _assert_message_is_clean(err.message)


def test_zip_disk_space_error_is_classified():
    exc = OSError("no space left on device")
    exc.errno = errno.ENOSPC
    err = _classify_zip_failure(exc, PLACEHOLDER_SOURCE)
    assert err.code == "archive_insufficient_disk_space"
    _assert_message_is_clean(err.message)


def test_zip_extraction_limit_exceeded_is_classified(tmp_path, monkeypatch):
    source = tmp_path / "big.zip"
    _write_real_zip(source, entries={"a.txt": b"x" * 500, "b.txt": b"y" * 500})
    dest = tmp_path / "out"
    monkeypatch.setattr(archive_module.settings, "backend_max_extracted_bytes", 10)

    with pytest.raises(ArchiveExtractionError) as exc_info:
        extract_archive(source, dest)

    assert exc_info.value.code == "archive_extraction_limit_exceeded"
    _assert_message_is_clean(exc_info.value.message)


def test_zip_unknown_failure_falls_back_to_generic(tmp_path, monkeypatch):
    source = tmp_path / "weird.zip"
    _write_real_zip(source)
    dest = tmp_path / "out"

    def _boom(*args, **kwargs):
        raise MemoryError("simulated allocation failure")

    monkeypatch.setattr(archive_module, "_safe_members_zip", _boom)

    with pytest.raises(ArchiveExtractionError) as exc_info:
        extract_archive(source, dest)

    err = exc_info.value
    assert err.code == "archive_extraction_failed"
    assert "MemoryError" not in err.message
    assert "MemoryError" in (err.detail or "")


# ---------------------------------------------------------------------------
# 7z family (RAR/TAR/GZ/BZ2/XZ all share this backend)
# ---------------------------------------------------------------------------


def _seven_zip_source(tmp_path: Path, name: str = "evidence.7z") -> Path:
    source = tmp_path / name
    source.write_bytes(b"placeholder 7z-family bytes")
    return source


def _patch_subprocess_run(monkeypatch, side_effect):
    def _run(*args, **kwargs):
        raise side_effect

    monkeypatch.setattr(archive_module.subprocess, "run", _run)


def test_seven_zip_tool_missing_is_classified(tmp_path, monkeypatch):
    source = _seven_zip_source(tmp_path)
    _patch_subprocess_run(monkeypatch, FileNotFoundError(2, "No such file or directory: '7z'"))

    with pytest.raises(ArchiveExtractionError) as exc_info:
        extract_archive(source, tmp_path / "out")

    err = exc_info.value
    assert err.code == "archive_tool_missing"
    _assert_message_is_clean(err.message)


def test_seven_zip_extraction_timeout_is_classified(tmp_path, monkeypatch):
    source = _seven_zip_source(tmp_path)
    _patch_subprocess_run(monkeypatch, subprocess.TimeoutExpired(cmd=["7z", "x"], timeout=1800))

    with pytest.raises(ArchiveExtractionError) as exc_info:
        extract_archive(source, tmp_path / "out")

    err = exc_info.value
    assert err.code == "archive_extraction_timeout"
    _assert_message_is_clean(err.message)


@pytest.mark.parametrize(
    "stderr_text,expected_code",
    [
        (b"ERROR: Wrong password?", "archive_password_protected"),
        (b"Enter password (will not be echoed):", "archive_password_protected"),
        (b"No space left on device", "archive_insufficient_disk_space"),
        (b"Cannot open the file as archive", "archive_unsupported_format"),
        (b"Is not supported archive", "archive_unsupported_format"),
        (b"Data Error in encrypted file", "archive_corrupted"),
        (b"CRC Failed", "archive_corrupted"),
        (b"some completely unrecognized 7z output", "archive_extraction_failed"),
    ],
)
def test_seven_zip_stderr_patterns_are_classified(tmp_path, monkeypatch, stderr_text, expected_code):
    source = _seven_zip_source(tmp_path)
    _patch_subprocess_run(
        monkeypatch,
        subprocess.CalledProcessError(returncode=2, cmd=["7z", "x", str(source)], stderr=stderr_text, output=b""),
    )

    with pytest.raises(ArchiveExtractionError) as exc_info:
        extract_archive(source, tmp_path / "out")

    err = exc_info.value
    assert err.code == expected_code
    _assert_message_is_clean(err.message)
    # Raw tool output must still be available for administrators, just not
    # in the analyst-facing message.
    assert stderr_text.decode().lower() in (err.detail or "").lower()


def test_seven_zip_disk_space_error_during_copy_is_classified():
    exc = OSError("no space left on device")
    exc.errno = errno.ENOSPC
    err = _classify_seven_zip_failure(exc, PLACEHOLDER_SOURCE)
    assert err.code == "archive_insufficient_disk_space"
    _assert_message_is_clean(err.message)


# ---------------------------------------------------------------------------
# Unsupported extension (no 7z/zipfile involvement at all)
# ---------------------------------------------------------------------------


def test_unsupported_extension_is_classified(tmp_path):
    source = tmp_path / "evidence.unknownext"
    source.write_bytes(b"whatever")

    with pytest.raises(ArchiveExtractionError) as exc_info:
        extract_archive(source, tmp_path / "out")

    assert exc_info.value.code == "archive_unsupported_format"
    _assert_message_is_clean(exc_info.value.message)


# ---------------------------------------------------------------------------
# Diagnostics are not reduced: full detail reaches the logger
# ---------------------------------------------------------------------------


def test_classified_error_is_logged_with_technical_detail(tmp_path, monkeypatch, caplog):
    import logging

    source = _seven_zip_source(tmp_path)
    _patch_subprocess_run(
        monkeypatch,
        subprocess.CalledProcessError(returncode=2, cmd=["7z", "x", str(source)], stderr=b"Data Error", output=b""),
    )

    with caplog.at_level(logging.ERROR, logger="app.ingest.archive"):
        with pytest.raises(ArchiveExtractionError):
            extract_archive(source, tmp_path / "out")

    assert any("archive_corrupted" in record.message for record in caplog.records)
