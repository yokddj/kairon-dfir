"""Raw memory images identified by their kernel's own name string, with no header or symbols
(app.services.memory.kernel_signatures and its use in the upload and platform probes)."""

from __future__ import annotations

import uuid
from pathlib import Path

import pytest

from app.services.memory import kernel_signatures, probe
from app.services.memory.kernel_signatures import LINUX, MACOS, WINDOWS, identify_kernel, scan_kernel_signatures

GUID = uuid.UUID("11d7fe79-cc24-5612-0555-03ee86bb0e3e")


def _windows_record(name: bytes = b"ntkrnlmp.pdb", guid: uuid.UUID = GUID, age: int = 1) -> bytes:
    return b"RSDS" + guid.bytes_le + age.to_bytes(4, "little") + name + b"\x00"


LINUX_BANNER = b"Linux version 6.5.0-41-generic (buildd@lcy02-amd64-079) (x86_64-linux-gnu-gcc-12 (Ubuntu 12.3.0-1ubuntu1~22.04) 12.3.0) #41~22.04.2-Ubuntu SMP\x00"
DARWIN_BANNER = b"Darwin Kernel Version 23.4.0: Fri Mar 15 00:10:42 PDT 2024; root:xnu-10063.101.17~1/RELEASE_ARM64_T6000\x00"


def _image(tmp_path: Path, *parts: tuple[int, bytes], size: int = 3 * 1024 * 1024, name: str = "memory.raw") -> Path:
    data = bytearray(size)
    for offset, payload in parts:
        data[offset : offset + len(payload)] = payload
    path = tmp_path / name
    path.write_bytes(bytes(data))
    return path


def test_finds_the_windows_kernel_pdb_with_guid_and_age(tmp_path: Path) -> None:
    image = _image(tmp_path, (0x1F000, _windows_record()))
    scan = scan_kernel_signatures(image, max_seconds=10)
    assert scan.complete
    kernel = identify_kernel(scan.signatures)
    assert kernel.platform == WINDOWS and kernel.name == "ntkrnlmp.pdb"
    assert kernel.pdb_guid == str(GUID).upper() and kernel.pdb_age == 1 and kernel.offset == 0x1F000


def test_finds_linux_and_macos_banners(tmp_path: Path) -> None:
    linux = identify_kernel(scan_kernel_signatures(_image(tmp_path, (4096, LINUX_BANNER), name="l.raw"), max_seconds=10).signatures)
    assert linux.platform == LINUX and linux.release == "6.5.0-41-generic" and "x86_64" in linux.banner
    darwin = identify_kernel(scan_kernel_signatures(_image(tmp_path, (4096, DARWIN_BANNER), name="m.raw"), max_seconds=10).signatures)
    assert darwin.platform == MACOS and darwin.release == "23.4.0"


def test_a_signature_split_across_chunks_is_found_once(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(kernel_signatures, "_CHUNK_BYTES", 1024 * 1024)
    image = _image(tmp_path, (1024 * 1024 - 10, _windows_record()))
    signatures = scan_kernel_signatures(image, max_seconds=10).signatures
    assert len(signatures) == 1 and signatures[0].offset == 1024 * 1024 - 10


def test_the_running_kernel_wins_over_other_kernels_in_cached_files(tmp_path: Path) -> None:
    other = uuid.UUID("f8ae879c-b3d8-49ee-b50d-11c0c6882663")
    image = _image(tmp_path, (0x1000, _windows_record()), (0x40000, _windows_record(b"ntoskrnl.pdb", other)), (0x80000, _windows_record()), (0x100000, LINUX_BANNER))
    kernel = identify_kernel(scan_kernel_signatures(image, max_seconds=10).signatures)
    assert kernel.platform == WINDOWS and kernel.pdb_guid == str(GUID).upper()


def test_a_close_call_between_systems_is_left_undecided(tmp_path: Path) -> None:
    image = _image(tmp_path, (0x1000, _windows_record()), (0x100000, LINUX_BANNER))
    assert identify_kernel(scan_kernel_signatures(image, max_seconds=10).signatures) is None


def test_no_kernel_and_unreadable_files_identify_nothing(tmp_path: Path) -> None:
    assert identify_kernel(scan_kernel_signatures(_image(tmp_path), max_seconds=10).signatures) is None
    scan = scan_kernel_signatures(tmp_path / "missing.raw", max_seconds=10)
    assert scan.signatures == [] and not scan.complete


def test_the_scan_stops_at_its_time_bound(tmp_path: Path) -> None:
    scan = scan_kernel_signatures(_image(tmp_path, (0x200000, _windows_record())), max_seconds=-1)
    assert not scan.complete and scan.signatures == []


@pytest.fixture
def small_images_scanned(monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setattr(probe, "_KERNEL_SCAN_MIN_BYTES", 1024)
    probe._cached_kernel_scan.cache_clear()
    yield
    probe._cached_kernel_scan.cache_clear()


def test_upload_probe_recognises_a_headerless_windows_memory_image(tmp_path: Path, small_images_scanned) -> None:
    result = probe.probe_memory_image(scan_kernel=True, path=_image(tmp_path, (0x200000, _windows_record()), name="memoria.raw"))
    assert result.status == probe.STATUS_PROBABLE_MEMORY and result.can_analyze and not result.requires_confirmation
    assert result.detected_format == "windows_kernel_scan"
    assert "ntkrnlmp.pdb" in result.reason and result.details["kernel_pdb_guid"] == str(GUID).upper()


def test_upload_probe_recognises_linux_memory_as_linux_banner_scan(tmp_path: Path, small_images_scanned) -> None:
    result = probe.probe_memory_image(scan_kernel=True, path=_image(tmp_path, (0x200000, LINUX_BANNER), name="dump.bin"))
    assert result.status == probe.STATUS_PROBABLE_MEMORY and result.detected_format == "linux_banner_scan"


def test_upload_probe_still_asks_when_no_kernel_is_found(tmp_path: Path, small_images_scanned) -> None:
    result = probe.probe_memory_image(scan_kernel=True, path=_image(tmp_path, name="unknown.raw"))
    assert result.status == probe.STATUS_AMBIGUOUS_RAW and result.requires_confirmation


def test_upload_probe_leaves_disk_images_alone(tmp_path: Path, small_images_scanned) -> None:
    mbr = bytearray(512)
    mbr[446:462] = bytes([0x80, 1, 1, 0, 0x07, 0xFE, 0xFF, 0xFF, 0x3F, 0, 0, 0, 0x00, 0x10, 0, 0])
    mbr[510:512] = b"\x55\xaa"
    result = probe.probe_memory_image(scan_kernel=True, path=_image(tmp_path, (0, bytes(mbr)), (0x200000, _windows_record()), name="disk.raw"))
    assert result.status != probe.STATUS_PROBABLE_MEMORY


def test_platform_probe_identifies_windows_from_the_kernel_record(tmp_path: Path) -> None:
    from app.services.memory.platform import PLATFORM_RESOLVING_FORMATS, Architecture, PlatformFamily, kernel_signature_probe, probe_memory_platform

    image = _image(tmp_path, (0x200000, _windows_record()))
    result = kernel_signature_probe(image)
    assert result.platform is PlatformFamily.WINDOWS and result.format == "windows_kernel_scan" and result.architecture is Architecture.X64
    assert f"{str(GUID).upper()}:1" in result.reason
    # Persisted, the format resolves the platform again without rescanning.
    assert PLATFORM_RESOLVING_FORMATS["windows_kernel_scan"][0] is PlatformFamily.WINDOWS
    resolved = probe_memory_platform(canonical_path=image, detected_format="windows_kernel_scan")
    assert resolved.platform is PlatformFamily.WINDOWS


def test_platform_probe_tries_the_kernel_scan_before_volatility(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    from app.services.memory import platform

    monkeypatch.setattr(platform, "_bounded_volatility_fallback", lambda path: pytest.fail("Volatility must not run when the kernel was found"))
    result = platform.probe_memory_platform(canonical_path=_image(tmp_path, (0x200000, _windows_record())), detected_format="raw_candidate", use_volatility_fallback=True)
    assert result.platform is platform.PlatformFamily.WINDOWS


def test_32_bit_pae_kernels_do_not_claim_x64(tmp_path: Path) -> None:
    from app.services.memory.platform import Architecture, kernel_signature_probe

    result = kernel_signature_probe(_image(tmp_path, (0x2000, _windows_record(b"ntkrpamp.pdb"))))
    assert result.architecture is Architecture.UNKNOWN


def test_without_scan_kernel_the_probe_stays_a_bounded_header_read(tmp_path: Path, small_images_scanned) -> None:
    result = probe.probe_memory_image(_image(tmp_path, (0x200000, _windows_record()), name="memoria.raw"))
    assert result.status == probe.STATUS_AMBIGUOUS_RAW


def test_the_upload_classifier_uses_the_deep_probe(tmp_path: Path, small_images_scanned) -> None:
    from app.ingest.evidence_classifier import EvidenceCategory, get_evidence_classifier

    image = _image(tmp_path, (0x200000, _windows_record()), name="memoria.raw")
    assert get_evidence_classifier().classify(image, deep=True).category == EvidenceCategory.MEMORY_DUMP
    assert get_evidence_classifier().classify(image).category != EvidenceCategory.MEMORY_DUMP
