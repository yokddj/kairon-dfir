from __future__ import annotations

import zipfile
from pathlib import Path

from app.ingest.detector import detect_evidence_type
from app.ingest.evidence_classifier import EvidenceCategory, get_evidence_classifier
from app.models.evidence import EvidenceType
from app.services.evidence_preflight import run_preflight
from app.services.memory.probe import STATUS_PROBABLE_DISK, probe_memory_image


def _mbr_image() -> bytes:
    data = bytearray(4096)
    data[446 + 4] = 0x83
    data[446 + 8:446 + 12] = (1).to_bytes(4, "little")
    data[446 + 12:446 + 16] = (7).to_bytes(4, "little")
    data[510:512] = b"\x55\xaa"
    return bytes(data)


def _ext_filesystem_image() -> bytes:
    data = bytearray(4096)
    superblock = 1024
    data[superblock:superblock + 4] = (1024).to_bytes(4, "little")
    data[superblock + 4:superblock + 8] = (8192).to_bytes(4, "little")
    data[superblock + 24:superblock + 28] = (0).to_bytes(4, "little")
    data[superblock + 56:superblock + 58] = b"\x53\xef"
    return bytes(data)


def _write(path: Path, payload: bytes) -> Path:
    path.write_bytes(payload)
    return path


def test_raw_disk_image_with_partition_table_is_disk(tmp_path: Path) -> None:
    path = _write(tmp_path / "memory-looking.raw", _mbr_image())

    result = get_evidence_classifier().classify(path)

    assert result.category == EvidenceCategory.DISK_IMAGE
    assert result.confidence == "mbr"
    assert detect_evidence_type(path) == EvidenceType.disk_image


def test_raw_filesystem_image_without_partition_table_is_disk(tmp_path: Path) -> None:
    path = _write(tmp_path / "victoria-v8.sda1.img", _ext_filesystem_image())

    result = get_evidence_classifier().classify(path)

    probe = probe_memory_image(path)

    assert probe.status == STATUS_PROBABLE_DISK
    assert result.category == EvidenceCategory.DISK_IMAGE
    assert result.confidence in {"filesystem", "high"}
    assert detect_evidence_type(path) == EvidenceType.disk_image


def test_linux_proc_kcore_style_memory_evidence_is_memory_despite_img(tmp_path: Path) -> None:
    path = _write(tmp_path / "victoria-v8.kcore.img", b"\x7fELF" + b"\x00" * 4096)

    result = get_evidence_classifier().classify(path)

    assert result.category == EvidenceCategory.MEMORY_DUMP
    assert result.format_key == "elf_core"
    assert result.confidence == "high"
    assert detect_evidence_type(path) == EvidenceType.memory_dump


def test_linux_memdump_style_memory_evidence_uses_name_only_after_no_disk_structure(tmp_path: Path) -> None:
    path = _write(tmp_path / "victoria-v8.memdump.img", b"\x00" * (2 * 1024 * 1024))

    result = get_evidence_classifier().classify(path)

    assert result.category == EvidenceCategory.MEMORY_DUMP
    assert result.confidence == "medium"
    assert "no coherent disk structure" in result.reason.lower()
    assert "raw_extension" in result.metadata.get("conflicts", [])
    assert detect_evidence_type(path) == EvidenceType.memory_dump


def test_misleading_img_extension_alone_is_unknown(tmp_path: Path) -> None:
    path = _write(tmp_path / "ambiguous.img", b"\x00" * (2 * 1024 * 1024))

    result = get_evidence_classifier().classify(path)
    assert result.category == EvidenceCategory.UNKNOWN
    assert result.confidence == "low"
    assert detect_evidence_type(path) == EvidenceType.unknown


def test_misleading_raw_extension_with_memory_signature_is_memory(tmp_path: Path) -> None:
    path = _write(tmp_path / "capture.raw", b"\x7fELF" + b"\x00" * 4096)

    assert get_evidence_classifier().classify(path).category == EvidenceCategory.MEMORY_DUMP
    assert detect_evidence_type(path) == EvidenceType.memory_dump


def test_volatility_profile_zip_is_auxiliary_not_archive_capture(tmp_path: Path) -> None:
    path = tmp_path / "Debian5_26.zip"
    with zipfile.ZipFile(path, "w") as zf:
        zf.writestr("volatility-master/tools/linux/module.dwarf", b"dwarf")
        zf.writestr("boot/System.map-2.6.26-2-686", b"symbols")

    result = get_evidence_classifier().classify(path)
    report = run_preflight(path, token="aux", original_filename=path.name, declared_platform=None, tmp_dir=tmp_path / "scratch")

    assert result.category == EvidenceCategory.AUXILIARY
    assert detect_evidence_type(path) == EvidenceType.unknown
    assert report.classification.category == "auxiliary"
    assert report.status == "blocked"
    assert any(check.label == "Supported" and not check.ok for check in report.status_checks)


def test_corrupt_or_ambiguous_image_is_unknown(tmp_path: Path) -> None:
    path = _write(tmp_path / "image.raw", b"not a disk or memory" * 200)

    result = get_evidence_classifier().classify(path)
    assert result.category == EvidenceCategory.UNKNOWN
    assert detect_evidence_type(path) == EvidenceType.unknown


def test_conflicting_weak_extension_loses_to_strong_disk_signal(tmp_path: Path) -> None:
    path = _write(tmp_path / "memdump.img", _mbr_image())

    result = get_evidence_classifier().classify(path)
    assert result.category == EvidenceCategory.DISK_IMAGE
    assert detect_evidence_type(path) == EvidenceType.disk_image


def test_bounded_read_behavior(tmp_path: Path, monkeypatch) -> None:
    path = tmp_path / "large.memdump.img"
    with path.open("wb") as handle:
        handle.seek((128 * 1024 * 1024) - 1)
        handle.write(b"\x00")
    read_sizes: list[int] = []
    real_open = Path.open

    class CountingFile:
        def __init__(self, wrapped):
            self._wrapped = wrapped

        def __enter__(self):
            self._wrapped.__enter__()
            return self

        def __exit__(self, *args):
            return self._wrapped.__exit__(*args)

        def __getattr__(self, name):
            return getattr(self._wrapped, name)

        def read(self, size=-1):
            read_sizes.append(size)
            return self._wrapped.read(size)

    def counted_open(self, *args, **kwargs):
        return CountingFile(real_open(self, *args, **kwargs))

    monkeypatch.setattr(Path, "open", counted_open)

    result = get_evidence_classifier().classify(path)

    assert result.category == EvidenceCategory.MEMORY_DUMP
    assert max(read_sizes) <= 1024 * 1024
    assert sum(size for size in read_sizes if size > 0) < 2 * 1024 * 1024


def test_routing_based_on_evidence_kind(tmp_path: Path) -> None:
    disk = _write(tmp_path / "disk.img", _ext_filesystem_image())
    memory = _write(tmp_path / "memory.img", b"\x7fELF" + b"\x00" * 4096)

    assert detect_evidence_type(disk) == EvidenceType.disk_image
    assert detect_evidence_type(memory) == EvidenceType.memory_dump


def test_no_cross_file_classification_state_leakage(tmp_path: Path) -> None:
    first = _write(tmp_path / "victoria-v8.kcore.img", b"\x7fELF" + b"\x00" * 4096)
    second = _write(tmp_path / "ambiguous.img", b"\x00" * (2 * 1024 * 1024))

    assert get_evidence_classifier().classify(first).category == EvidenceCategory.MEMORY_DUMP
    assert get_evidence_classifier().classify(second).category == EvidenceCategory.UNKNOWN
