"""Integration tests for PR3: wiring app.disk_images.lvm's parser (PR1) and
reader (PR2) into the disk-image discovery/materialization pipeline
(app.disk_images.service._discover_raw_volumes and
materialize_disk_image_sources).

Reuses test_lvm_parser.py's exact byte-level fixture-building technique
(build_synthetic_pv, render_metadata_text) to construct a real, valid,
on-disk LVM2 Physical Volume -- no lvm2 userspace tools, no loop devices,
no privileged access. That PV is embedded inside a hand-crafted MBR
partition, the same way test_evidence_preflight.py's
_make_minimal_mbr_disk_image already does for non-LVM volume-discovery
tests.

Tests that additionally need a *real* filesystem inside a logical volume
(to prove _detect_installations and materialization actually work end to
end, not just that a pytsk3.FS_Info could be constructed) use mkfs.vfat/
mcopy and skip when those tools are not installed -- same convention as
tests/test_disk_image_ingestion.py.
"""

from __future__ import annotations

import hashlib
import shutil
import struct
import subprocess
from pathlib import Path

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from app.core.database import Base
from app.disk_images.service import _discover_raw_volumes, materialize_disk_image_sources
from app.models.case import Case
from app.models.evidence import Evidence, EvidenceStorageMode, EvidenceType, IngestStatus
from tests.test_lvm_parser import DEFAULT_PV_UUID_FORMATTED, build_synthetic_pv, render_metadata_text

SECTOR = 512
_START_LBA = 2048


def _require_tools(*names: str) -> None:
    missing = [name for name in names if shutil.which(name) is None]
    if missing:
        pytest.skip(f"Missing required tool(s): {', '.join(missing)}")


@pytest.fixture
def sqlite_session():
    engine = create_engine("sqlite:///:memory:", future=True)
    Base.metadata.create_all(bind=engine)
    Session = sessionmaker(bind=engine, autoflush=False, autocommit=False, expire_on_commit=False, future=True)
    db = Session()
    try:
        yield db
    finally:
        db.close()


def _make_case_and_evidence(db, path: Path) -> Evidence:
    case = Case(id="case-1", name="LVM Integration Case")
    evidence = Evidence(
        id="evidence-1",
        case_id=case.id,
        original_filename=path.name,
        stored_path=str(path),
        original_path=str(path),
        storage_mode=EvidenceStorageMode.uploaded,
        is_external=False,
        copy_to_storage=True,
        evidence_type=EvidenceType.disk_image,
        sha256=hashlib.sha256(path.read_bytes()).hexdigest() if path.is_file() else None,
        size_bytes=path.stat().st_size if path.exists() else 0,
        ingest_status=IngestStatus.pending,
        path_validation={},
        ingest_source={},
        metadata_json={},
        error_log={},
    )
    db.add(case)
    db.add(evidence)
    db.flush()
    return evidence


def _mbr_bytes(*, num_sectors: int, partition_type: int = 0x8E) -> bytes:
    """0x8E is the well-known MBR partition-type byte for "Linux LVM" --
    cosmetic only (pytsk3.Volume_Info's own filtering is on flags/len, not
    this byte), kept for realism."""
    mbr = bytearray(512)
    entry_offset = 446
    mbr[entry_offset + 0] = 0x00
    mbr[entry_offset + 4] = partition_type
    mbr[entry_offset + 8 : entry_offset + 12] = _START_LBA.to_bytes(4, "little")
    mbr[entry_offset + 12 : entry_offset + 16] = num_sectors.to_bytes(4, "little")
    mbr[510] = 0x55
    mbr[511] = 0xAA
    return bytes(mbr)


def _lv_segment(*, start_extent: int, extent_count: int, pv_name: str = "pv0", start_pe: int = 0) -> dict:
    return {"start_extent": start_extent, "extent_count": extent_count, "type": "striped", "stripe_count": 1, "stripes": [pv_name, start_pe]}


def _single_pv_metadata_text(*, extent_size_sectors: int, pe_start_sectors: int, pe_count: int, logical_volumes: list[dict]) -> str:
    # dev_size is not cross-checked against anything else in this fixture
    # (parser.py only validates it is a positive int; LogicalVolumeReader
    # never reads PhysicalVolume.device_size_bytes at all) -- a generous
    # fixed sentinel is fine.
    return render_metadata_text(
        extent_size=extent_size_sectors,
        physical_volumes=[{"name": "pv0", "id": DEFAULT_PV_UUID_FORMATTED, "dev_size": 999_999, "pe_start": pe_start_sectors, "pe_count": pe_count}],
        logical_volumes=logical_volumes,
    )


def _write_disk_with_lvm_partition(path: Path, pv_bytes: bytes) -> None:
    num_sectors = len(pv_bytes) // SECTOR + 1
    total_size = (_START_LBA + num_sectors) * SECTOR
    with path.open("wb") as fh:
        fh.write(_mbr_bytes(num_sectors=num_sectors))
        fh.seek(total_size - 1)
        fh.write(b"\x00")
        fh.seek(_START_LBA * SECTOR)
        fh.write(pv_bytes)


# ---------------------------------------------------------------------------
# Discovery-level tests (_discover_raw_volumes directly) -- no external tools
# ---------------------------------------------------------------------------


def test_lvm_signature_without_valid_metadata_leaves_todays_diagnostic_unchanged(tmp_path):
    # Same real-world case as
    # test_evidence_preflight.test_volume_diagnostics_detect_lvm_signature_without_parsing_lvm:
    # only the "LABELONE" magic is present, no valid PV header/metadata
    # area follows it. parse_physical_volume_metadata must fail, and PR3
    # must add nothing -- exactly today's diagnostic.
    disk_path = tmp_path / "disk.dd"
    garbage_pv = b"\x00" * 512 + b"LABELONE" + b"\x00" * 4096
    _write_disk_with_lvm_partition(disk_path, garbage_pv)

    volumes, installs, warnings = _discover_raw_volumes(disk_path)

    assert len(volumes) == 1
    assert volumes[0]["status"] == "unreadable_volume"
    assert volumes[0]["metadata"].get("container_signature") == "lvm2_physical_volume"
    assert installs == []


def test_valid_single_lv_metadata_adds_readable_lv_entry_when_no_filesystem_recognized(tmp_path):
    # Metadata parses fully (a genuinely supported case), but the logical
    # volume's own bytes are all zero -- pytsk3 cannot recognize a
    # filesystem there, so this one logical volume is independently
    # unreadable. The parent PV's own diagnostic must be unchanged.
    extent_size_sectors = 8  # 4096 bytes/extent
    pe_start_sectors = 2048
    extent_count = 10
    metadata_text = _single_pv_metadata_text(
        extent_size_sectors=extent_size_sectors,
        pe_start_sectors=pe_start_sectors,
        pe_count=extent_count + 50,
        logical_volumes=[{"name": "root", "id": "LLLLLL-MMMM-NNNN-OOOO-PPPP-QQQQ-000001", "segments": [_lv_segment(start_extent=0, extent_count=extent_count)]}],
    )
    header_bytes = build_synthetic_pv(metadata_text=metadata_text, pe_start_sectors=pe_start_sectors)
    pe_start_bytes = pe_start_sectors * SECTOR
    total = max(len(header_bytes), pe_start_bytes + extent_count * extent_size_sectors * SECTOR)
    pv_bytes = bytearray(total)
    pv_bytes[: len(header_bytes)] = header_bytes

    disk_path = tmp_path / "disk.dd"
    _write_disk_with_lvm_partition(disk_path, bytes(pv_bytes))

    volumes, installs, warnings = _discover_raw_volumes(disk_path)

    assert len(volumes) == 2
    parent, lv = volumes
    assert parent["status"] == "unreadable_volume"
    assert parent["metadata"]["container_signature"] == "lvm2_physical_volume"
    assert lv["partition_type"] == "lvm2_logical_volume"
    assert lv["status"] == "unreadable_volume"  # no recognizable filesystem in the zero-filled LV
    assert lv["metadata"]["lvm"]["logical_volume"] == "root"
    assert lv["metadata"]["lvm"]["volume_group"] == "test-vg"
    # The logical volume's own synthetic index must never collide with any
    # real partition-table index.
    assert lv["partition_index"] != parent["partition_index"]
    assert lv["partition_index"] > 1_000_000


def test_multiple_logical_volumes_are_each_attempted_independently(tmp_path):
    extent_size_sectors = 8
    pe_start_sectors = 2048
    metadata_text = _single_pv_metadata_text(
        extent_size_sectors=extent_size_sectors,
        pe_start_sectors=pe_start_sectors,
        pe_count=200,
        logical_volumes=[
            {"name": "root", "id": "LLLLLL-MMMM-NNNN-OOOO-PPPP-QQQQ-000001", "segments": [_lv_segment(start_extent=0, extent_count=10, start_pe=0)]},
            # Each logical volume has its own extent numbering starting at 0
            # -- what makes "var" occupy a distinct physical region is its
            # start_pe (physical extent on pv0), not start_extent.
            {"name": "var", "id": "LLLLLL-MMMM-NNNN-OOOO-PPPP-QQQQ-000002", "segments": [_lv_segment(start_extent=0, extent_count=10, start_pe=10)]},
        ],
    )
    header_bytes = build_synthetic_pv(metadata_text=metadata_text, pe_start_sectors=pe_start_sectors)
    pe_start_bytes = pe_start_sectors * SECTOR
    total = max(len(header_bytes), pe_start_bytes + 20 * extent_size_sectors * SECTOR)
    pv_bytes = bytearray(total)
    pv_bytes[: len(header_bytes)] = header_bytes

    disk_path = tmp_path / "disk.dd"
    _write_disk_with_lvm_partition(disk_path, bytes(pv_bytes))

    volumes, installs, warnings = _discover_raw_volumes(disk_path)

    lv_volumes = [v for v in volumes if v["partition_type"] == "lvm2_logical_volume"]
    assert len(lv_volumes) == 2
    names = {v["metadata"]["lvm"]["logical_volume"] for v in lv_volumes}
    assert names == {"root", "var"}
    indices = {v["partition_index"] for v in lv_volumes}
    assert len(indices) == 2  # distinct, collision-free indices


def test_multi_pv_volume_group_is_treated_as_unsupported(tmp_path):
    # Multi-PV logical-volume reading is explicitly out of scope for V1 --
    # a Volume Group declaring more than one Physical Volume must add no
    # logical-volume entries at all, leaving today's diagnostic unchanged,
    # even though the metadata itself parses without error.
    extent_size_sectors = 8
    pe_start_sectors = 2048
    metadata_text = render_metadata_text(
        extent_size=extent_size_sectors,
        physical_volumes=[
            {"name": "pv0", "id": DEFAULT_PV_UUID_FORMATTED, "dev_size": 204800, "pe_start": pe_start_sectors, "pe_count": 200},
            {"name": "pv1", "id": "ZZZZZZ-ZZZZ-ZZZZ-ZZZZ-ZZZZ-ZZZZ-000099", "dev_size": 204800, "pe_start": pe_start_sectors, "pe_count": 200},
        ],
        logical_volumes=[{"name": "root", "id": "LLLLLL-MMMM-NNNN-OOOO-PPPP-QQQQ-000001", "segments": [_lv_segment(start_extent=0, extent_count=10)]}],
    )
    header_bytes = build_synthetic_pv(metadata_text=metadata_text, pe_start_sectors=pe_start_sectors)
    pe_start_bytes = pe_start_sectors * SECTOR
    total = max(len(header_bytes), pe_start_bytes + 10 * extent_size_sectors * SECTOR)
    pv_bytes = bytearray(total)
    pv_bytes[: len(header_bytes)] = header_bytes

    disk_path = tmp_path / "disk.dd"
    _write_disk_with_lvm_partition(disk_path, bytes(pv_bytes))

    volumes, installs, warnings = _discover_raw_volumes(disk_path)

    assert len(volumes) == 1  # only the parent PV's own (unchanged) diagnostic
    assert volumes[0]["status"] == "unreadable_volume"
    assert volumes[0]["metadata"]["container_signature"] == "lvm2_physical_volume"


def test_normal_partition_discovery_is_unaffected_by_lvm_integration(tmp_path):
    # A plain, non-LVM MBR disk with an unreadable (but not LVM-signed)
    # partition must behave exactly as before: no logical-volume entries,
    # single unreadable_volume diagnostic, no container_signature.
    disk_path = tmp_path / "disk.dd"
    plain_partition = b"\x00" * (4 * 1024 * 1024)
    _write_disk_with_lvm_partition(disk_path, plain_partition)

    volumes, installs, warnings = _discover_raw_volumes(disk_path)

    assert len(volumes) == 1
    assert volumes[0]["status"] == "unreadable_volume"
    assert "container_signature" not in volumes[0]["metadata"]


# ---------------------------------------------------------------------------
# Full round-trip: materialize_disk_image_sources with a real filesystem
# inside the logical volume (requires mkfs.vfat/mcopy; skips otherwise)
# ---------------------------------------------------------------------------


def _build_fat_image_bytes(tmp_path: Path, files: dict[str, str], *, size_kib: int) -> bytes:
    _require_tools("mkfs.vfat", "mcopy")
    fs_image = tmp_path / "lv-fs.img"
    subprocess.run(["mkfs.vfat", "-C", str(fs_image), str(size_kib)], check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    for relative_path, contents in files.items():
        source = tmp_path / "src" / relative_path
        source.parent.mkdir(parents=True, exist_ok=True)
        source.write_text(contents, encoding="utf-8")
        directory = Path(relative_path).parent
        if str(directory) not in {"", "."}:
            subprocess.run(["mmd", "-i", str(fs_image), f"::/{directory}"], check=False, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        subprocess.run(["mcopy", "-i", str(fs_image), str(source), f"::/{relative_path}"], check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    return fs_image.read_bytes()


def test_materialize_extracts_files_from_a_logical_volume(sqlite_session, tmp_path):
    extent_size_sectors = 8  # 4096 bytes/extent
    pe_start_sectors = 2048
    fat_bytes = _build_fat_image_bytes(
        tmp_path,
        {
            "etc/os-release": 'PRETTY_NAME="Ubuntu 24.04 LTS"\n',
            "etc/passwd": "root:x:0:0:root:/root:/bin/bash\n",
            "var/log/syslog": "kernel: booted\n",
        },
        size_kib=1408,  # 1,441,792 bytes = exactly 352 * 4096
    )
    extent_count = len(fat_bytes) // (extent_size_sectors * SECTOR)
    assert extent_count * extent_size_sectors * SECTOR == len(fat_bytes)

    metadata_text = _single_pv_metadata_text(
        extent_size_sectors=extent_size_sectors,
        pe_start_sectors=pe_start_sectors,
        pe_count=extent_count + 50,
        logical_volumes=[{"name": "root", "id": "LLLLLL-MMMM-NNNN-OOOO-PPPP-QQQQ-000001", "segments": [_lv_segment(start_extent=0, extent_count=extent_count)]}],
    )
    header_bytes = build_synthetic_pv(metadata_text=metadata_text, pe_start_sectors=pe_start_sectors)
    pe_start_bytes = pe_start_sectors * SECTOR
    total = max(len(header_bytes), pe_start_bytes + len(fat_bytes))
    pv_bytes = bytearray(total)
    pv_bytes[: len(header_bytes)] = header_bytes
    pv_bytes[pe_start_bytes : pe_start_bytes + len(fat_bytes)] = fat_bytes

    disk_path = tmp_path / "disk.dd"
    _write_disk_with_lvm_partition(disk_path, bytes(pv_bytes))
    evidence = _make_case_and_evidence(sqlite_session, disk_path)

    result = materialize_disk_image_sources(sqlite_session, evidence, extract_dir=tmp_path / "extract")

    lv_volumes = [v for v in result.volumes if v.partition_type == "lvm2_logical_volume"]
    assert len(lv_volumes) == 1
    assert lv_volumes[0].readable is True
    assert lv_volumes[0].filesystem_type is not None
    assert any(install.platform == "linux" for install in result.installations)
    assert any("os-release" in path or "passwd" in path for path in result.extracted_files)
