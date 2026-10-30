"""Members of an uploaded archive that are evidence of their own kind are
listed on the evidence instead of disappearing silently."""

from __future__ import annotations

from pathlib import Path

from app.ingest import bundled_evidence as bundled


def _write(path: Path, header: bytes, size: int = 4096) -> Path:
    with path.open("wb") as handle:
        handle.write(header)
        handle.truncate(size)
    return path


def test_packet_captures_are_recognised_by_signature(tmp_path: Path) -> None:
    assert bundled.is_packet_capture(_write(tmp_path / "a.bin", b"\xd4\xc3\xb2\xa1"))
    assert bundled.is_packet_capture(_write(tmp_path / "b", b"\xa1\xb2\x3c\x4d"))
    assert bundled.is_packet_capture(_write(tmp_path / "c.pcapng", b"\x0a\x0d\x0d\x0a" + b"\x1c\x00\x00\x00" + b"\x4d\x3c\x2b\x1a"))
    # The name decides nothing, and a bare pcapng block type is not enough.
    assert not bundled.is_packet_capture(_write(tmp_path / "d.pcap", b"PK\x03\x04"))
    assert not bundled.is_packet_capture(_write(tmp_path / "e", b"\x0a\x0d\x0d\x0a" + b"\x00" * 8))


def test_memory_verdict_needs_an_image_sized_file_and_an_elf_core(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setattr(bundled, "MIN_MEMORY_IMAGE_BYTES", 8192)
    crash = _write(tmp_path / "host.dmp", b"PAGEDU64", 16384)
    small = _write(tmp_path / "app.dmp", b"PAGEDU64", 4096)
    core = _write(tmp_path / "vmcore", b"\x7fELF\x02\x01\x01" + b"\x00" * 9 + b"\x04\x00", 16384)
    binary = _write(tmp_path / "ls", b"\x7fELF\x02\x01\x01" + b"\x00" * 9 + b"\x03\x00", 16384)
    assert bundled.bundled_kind("memory_dump", crash) == "memory_dump"
    assert bundled.bundled_kind("memory_dump", small) is None
    assert bundled.bundled_kind("memory_dump", core) == "memory_dump"
    assert bundled.bundled_kind("memory_dump", binary) is None
    assert bundled.bundled_kind("unknown", crash) is None


def test_flagged_entries_are_listed_with_their_kind() -> None:
    entries = [
        {"path": "_nested_0_HOST/C/Windows/System32/config/SYSTEM", "size": 10},
        {"path": "HOST-memory.dmp", "size": 4_000_000_000, "bundled_evidence": "memory_dump"},
        {"path": "HOST-capture.pcap", "size": 20_000_000, "bundled_evidence": "pcap"},
    ]
    assert bundled.bundled_evidence(entries) == [
        {"path": "HOST-memory.dmp", "kind": "memory_dump", "label": "Memory image", "size_bytes": 4_000_000_000},
        {"path": "HOST-capture.pcap", "kind": "pcap", "label": "Packet capture", "size_bytes": 20_000_000},
    ]
