"""A ZIP cut short (no central directory) yields its complete files and says what is missing."""

from __future__ import annotations

import io
import os
import zipfile
from pathlib import Path

import pytest

from app.ingest.archive import ArchiveExtractionError, archive_truncation, extract_archive


class _Unseekable(io.RawIOBase):
    """zipfile writes data descriptors when it cannot seek back, as streaming collectors do."""

    def __init__(self) -> None:
        self.buffer = bytearray()

    def writable(self) -> bool:
        return True

    def write(self, data) -> int:
        self.buffer.extend(data)
        return len(data)


FILES = {
    "results/Generic.System.Pstree.json": b'{"Pid": 4}\n' * 2000,
    "uploads/auto/C%3A/Windows/System32/winevt/Logs/Security.evtx": os.urandom(300_000),
    "uploads/ntfs/%5C%5C.%5CC%3A/$MFT": b"FILE0" * 100_000,
    "log.json": b"{}\n",
}


def _streamed_zip(method: int = zipfile.ZIP_DEFLATED) -> tuple[bytes, list[int]]:
    """The archive bytes and each entry's starting offset."""
    sink = _Unseekable()
    offsets = []
    with zipfile.ZipFile(sink, "w", compression=method) as archive:
        for name, data in FILES.items():
            offsets.append(len(sink.buffer))
            archive.writestr(name, data)
    return bytes(sink.buffer), offsets


def _seekable_zip(method: int) -> tuple[bytes, list[int]]:
    buffer = io.BytesIO()
    offsets = []
    with zipfile.ZipFile(buffer, "w", compression=method) as archive:
        for name, payload in FILES.items():
            offsets.append(buffer.tell())
            archive.writestr(name, payload)
    return buffer.getvalue(), offsets


def _write(tmp_path: Path, data: bytes) -> Path:
    source = tmp_path / "collection.zip"
    source.write_bytes(data)
    return source


@pytest.mark.parametrize("method", [zipfile.ZIP_DEFLATED, zipfile.ZIP_STORED])
def test_an_archive_cut_inside_an_entry_keeps_the_complete_ones(tmp_path, method):
    # Deflate: streamed with data descriptors, like Velociraptor; stored entries carry their sizes.
    data, offsets = _streamed_zip(method) if method == zipfile.ZIP_DEFLATED else _seekable_zip(method)
    cut = offsets[3] - 20  # inside the third entry's data
    source = _write(tmp_path, data[:cut])
    extracted, entries = extract_archive(source, tmp_path / "out")
    names = list(FILES)
    assert extracted == names[:2]
    for name in names[:2]:
        assert (tmp_path / "out" / name).read_bytes() == FILES[name]
    assert not list((tmp_path / "out").rglob("*.kairon-partial"))
    truncation = archive_truncation(entries)
    assert truncation["first_missing_path"] == names[2]
    assert truncation["recovered_files"] == 2 and truncation["offset"] == offsets[2]
    assert truncation["archive_size"] == cut


def test_an_archive_cut_in_its_central_directory_keeps_every_file(tmp_path):
    data, _offsets = _streamed_zip()
    end_of_entries = data.rfind(b"PK\x01\x02", 0, data.rfind(b"PK\x05\x06"))
    central = data.find(b"PK\x01\x02")
    assert central <= end_of_entries
    extracted, entries = extract_archive(_write(tmp_path, data[: central + 10]), tmp_path / "out")
    assert extracted == list(FILES)
    truncation = archive_truncation(entries)
    assert truncation["first_missing_path"] is None and truncation["recovered_files"] == len(FILES)


def test_a_complete_archive_is_read_as_before(tmp_path):
    data, _offsets = _streamed_zip()
    extracted, entries = extract_archive(_write(tmp_path, data), tmp_path / "out")
    assert extracted == list(FILES) and archive_truncation(entries) is None


def test_a_damaged_entry_stops_the_recovery_there(tmp_path):
    data, offsets = _seekable_zip(zipfile.ZIP_STORED)
    damaged = bytearray(data[: offsets[3]])
    damaged[offsets[1] + 200] ^= 0xFF  # inside the second entry's data
    extracted, entries = extract_archive(_write(tmp_path, bytes(damaged)), tmp_path / "out")
    assert extracted == [list(FILES)[0]]
    assert archive_truncation(entries)["first_missing_path"] == list(FILES)[1]


def test_nothing_recoverable_is_reported_as_incomplete(tmp_path):
    data, _offsets = _streamed_zip()
    with pytest.raises(ArchiveExtractionError) as exc_info:
        extract_archive(_write(tmp_path, data[:40]), tmp_path / "out")
    assert exc_info.value.code == "archive_truncated"
    assert "incomplete" in exc_info.value.message and "/" not in exc_info.value.message.split("is incomplete")[0].replace("collection.zip", "")


def test_unsafe_paths_are_refused_while_recovering(tmp_path):
    sink = _Unseekable()
    with zipfile.ZipFile(sink, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        archive.writestr("../escape.txt", b"x" * 100)
    with pytest.raises(Exception):
        extract_archive(_write(tmp_path, bytes(sink.buffer)[:60]), tmp_path / "out")
    assert not (tmp_path / "escape.txt").exists()
