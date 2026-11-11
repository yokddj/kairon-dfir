"""Raw memory images named like disk images (.dd/.img/.raw), and memory images above 16 GiB.

Sparse files stand in for the large images: only the bytes the probe looks at are written."""

from __future__ import annotations

from pathlib import Path

import pytest

from app.ingest.evidence_classifier import EvidenceCategory, get_evidence_classifier
from app.services.memory import probe as probe_module
from app.services.memory.kernel_signatures import scan_kernel_signatures
from app.services.memory.probe import STATUS_CONFIRMED_MEMORY, STATUS_PROBABLE_MEMORY, firmware_tables, kernel_scan_seconds, probe_memory_image

GIB = 1024**3
LINUX_BANNER = b"Linux version 6.8.0-45-generic (buildd@lcy02-amd64-075) (x86_64-linux-gnu-gcc-13 (Ubuntu 13.2.0-23ubuntu4) 13.2.0) #45-Ubuntu SMP\0"


def _sparse(path: Path, size: int, writes: dict[int, bytes]) -> Path:
    with path.open("wb") as handle:
        for offset, data in writes.items():
            handle.seek(offset)
            handle.write(data)
        handle.truncate(size)
    return path


def _with_checksum(block: bytearray, checksum_at: int, length: int) -> bytes:
    block[checksum_at] = 0
    block[checksum_at] = (-sum(block[:length])) % 256
    return bytes(block)


def _rsdp() -> bytes:
    block = bytearray(b"RSD PTR " + b"\0" + b"OEMID " + b"\0" + b"\0\0\0\0")  # 20-byte ACPI 1.0 RSDP
    return _with_checksum(block, 8, 20)


def _smbios() -> bytes:
    block = bytearray(31)
    block[0:4] = b"_SM_"
    block[5] = 0x1F
    block[16:21] = b"_DMI_"
    return _with_checksum(block, 4, 0x1F)


@pytest.fixture(autouse=True)
def _fresh_scan_cache():
    probe_module._cached_kernel_scan.cache_clear()
    yield
    probe_module._cached_kernel_scan.cache_clear()


def test_a_crash_dump_above_16_gib_is_still_memory(tmp_path):
    path = _sparse(tmp_path / "capture.dd", 20 * GIB, {0: b"PAGEDU64" + b"\0" * 8})
    assert probe_memory_image(path).status == STATUS_CONFIRMED_MEMORY
    assert get_evidence_classifier().classify(path).category == EvidenceCategory.MEMORY_DUMP


def test_a_raw_dd_above_16_gib_with_a_kernel_is_memory_not_disk(tmp_path):
    path = _sparse(tmp_path / "capture.dd", 20 * GIB, {5 * GIB: LINUX_BANNER})
    deep = get_evidence_classifier().classify(path, deep=True)
    assert deep.category == EvidenceCategory.MEMORY_DUMP and "Linux kernel 6.8.0-45-generic" in deep.reason
    # Without the kernel scan nothing proves either: never a disk image on its extension alone.
    assert get_evidence_classifier().classify(path).category == EvidenceCategory.UNKNOWN


@pytest.mark.parametrize("suffix", [".dd", ".img", ".raw"])
def test_a_raw_extension_without_disk_structure_is_never_a_disk_image(tmp_path, suffix):
    path = _sparse(tmp_path / f"unknown{suffix}", 128 * 1024 * 1024, {})
    assert get_evidence_classifier().classify(path).category == EvidenceCategory.UNKNOWN


def test_firmware_tables_at_their_physical_address_mean_memory_without_a_kernel_scan(tmp_path):
    path = _sparse(tmp_path / "capture.dd", 256 * 1024 * 1024, {0xF6A00: _rsdp(), 0xF69B0: _smbios()})
    assert firmware_tables(path, path.stat().st_size) == ["smbios", "acpi_rsdp"]
    result = probe_memory_image(path)
    assert result.status == STATUS_PROBABLE_MEMORY and result.detected_format == "raw_physical_memory"
    assert get_evidence_classifier().classify(path).category == EvidenceCategory.MEMORY_DUMP


def test_firmware_signatures_without_a_valid_checksum_say_nothing(tmp_path):
    broken = bytearray(_rsdp())
    broken[8] ^= 0x55
    path = _sparse(tmp_path / "capture.dd", 256 * 1024 * 1024, {0xF6A00: bytes(broken), 0xE0004: b"_SM_"})
    assert firmware_tables(path, path.stat().st_size) == []
    assert get_evidence_classifier().classify(path).category == EvidenceCategory.UNKNOWN


def test_the_kernel_scan_budget_grows_with_the_image_within_bounds():
    assert kernel_scan_seconds(2 * GIB) == 30.0
    assert 30.0 < kernel_scan_seconds(16 * GIB) < 120.0
    assert kernel_scan_seconds(256 * GIB) == 120.0


def test_the_scan_stops_soon_after_the_kernel_is_found(tmp_path):
    path = _sparse(tmp_path / "capture.dd", 2 * GIB, {64 * 1024 * 1024: LINUX_BANNER})
    scan = scan_kernel_signatures(path, max_seconds=60, max_signatures=8, settle_seconds=0)
    assert scan.signatures and scan.bytes_scanned < 2 * GIB and not scan.complete
