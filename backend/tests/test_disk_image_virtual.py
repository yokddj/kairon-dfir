from __future__ import annotations

import hashlib
import json
from pathlib import Path
import subprocess

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from app.core.database import Base
from app.disk_images.qemu import (
    _format_from_info,
    _format_size,
    _parse_vmdk_descriptor,
    _validate_backing_file,
    _validate_vmdk_extents,
    qemu_img_check,
    qemu_img_convert_to_raw,
    qemu_img_info,
)
from app.disk_images.registry import get_image_format_registry
from app.disk_images.service import detect_disk_image_format
from app.disk_images.vmdk import VmdkImageAdapter
from app.disk_images.vhd import VhdImageAdapter
from app.disk_images.qcow import QcowImageAdapter
from app.disk_images.vdi import VdiImageAdapter


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


def _require_qemu() -> None:
    missing = subprocess.run(["bash", "-lc", "command -v qemu-img >/dev/null 2>&1"], check=False).returncode != 0
    if missing:
        pytest.skip("qemu-img not available")


def _mkfat_image(target: Path, files: dict[str, str], size_kib: int = 16384) -> None:
    _require_tools("mkfs.vfat", "mcopy", "mmd")
    src = target.parent / f"{target.stem}-src"
    src.mkdir(parents=True, exist_ok=True)
    _write_tree(src, files)
    subprocess.run(["mkfs.vfat", "-C", str(target), str(size_kib)], check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    directories: set[str] = set()
    for rel in files:
        current = Path(rel).parent
        while str(current) not in {"", "."}:
            directories.add(str(current).replace("\\", "/"))
            current = current.parent
    for directory in sorted(directories, key=lambda item: (item.count("/"), item)):
        subprocess.run(["mmd", "-i", str(target), f"::/{directory}"], check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    for rel in files:
        normalized = rel.replace("\\", "/")
        subprocess.run(["mcopy", "-i", str(target), str(src / rel), f"::/{normalized}"], check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)


def _write_tree(root: Path, files: dict[str, str]) -> None:
    for rel, content in files.items():
        target = root / rel
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(content, encoding="utf-8")


def _require_tools(*names: str) -> None:
    missing = []
    for name in names:
        if subprocess.run(["bash", "-lc", f"command -v {name} >/dev/null 2>&1"], check=False).returncode != 0:
            missing.append(name)
    if missing:
        pytest.skip(f"Missing required tool(s): {', '.join(missing)}")


def test_vmdk_detect_by_magic_and_extension(tmp_path: Path) -> None:
    _require_qemu()
    adapter = VmdkImageAdapter()
    fake = tmp_path / "test.vmdk"
    fake.write_bytes(b"KDMV" + (b"\x00" * 65536))
    result = adapter.detect(fake, [])
    assert result is not None
    assert result["format"] == "vmdk"
    assert result["confidence"] == "magic"


def test_vmdk_descriptor_parse(tmp_path: Path) -> None:
    descriptor = tmp_path / "image.vmdk"
    descriptor.write_text(
        """# Disk DescriptorFile
version=1
RW 8388608 FLAT "image-flat.vmdk" 0
RDONLY 4194304 SPARSE "delta.vmdk"
RW 1024 ZERO
""",
        encoding="utf-8",
    )
    result = _parse_vmdk_descriptor(descriptor)
    assert result["valid"] is True
    extents = result["extents"]
    assert len(extents) == 2
    assert "image-flat.vmdk" in extents


def test_vmdk_descriptor_rejects_absolute_paths(tmp_path: Path) -> None:
    descriptor = tmp_path / "abs.vmdk"
    descriptor.write_text(
        """# Disk DescriptorFile
RW 8388608 FLAT "/tmp/malicious.img" 0
RW 4194304 FLAT "safe.vmdk"
""",
        encoding="utf-8",
    )
    result = _parse_vmdk_descriptor(descriptor)
    assert len(result["extents"]) == 1
    assert "safe.vmdk" in result["extents"]


def test_vmdk_descriptor_rejects_path_traversal(tmp_path: Path) -> None:
    descriptor = tmp_path / "traversal.vmdk"
    descriptor.write_text(
        """# Disk DescriptorFile
RW 8388608 FLAT "../../outside.vmdk" 0
""",
        encoding="utf-8",
    )
    result = _parse_vmdk_descriptor(descriptor)
    assert len(result["extents"]) == 0
    assert any("path_traversal" in err for err in result["errors"])


def test_vmdk_extent_validation_missing(tmp_path: Path) -> None:
    validation = _validate_vmdk_extents(tmp_path, ["missing-flat.vmdk"])
    assert validation["valid"] is False
    assert "missing-flat.vmdk" in validation["missing"]


def test_vmdk_extent_validation_present(tmp_path: Path) -> None:
    (tmp_path / "flat.vmdk").write_bytes(b"\x00" * 1024)
    validation = _validate_vmdk_extents(tmp_path, ["flat.vmdk"])
    assert validation["valid"] is True


def test_vhd_detect_by_magic_and_extension(tmp_path: Path) -> None:
    _require_qemu()
    adapter = VhdImageAdapter()
    fake = tmp_path / "test.vhd"
    fake.write_bytes(b"conectix" + (b"\x00" * 65536))
    result = adapter.detect(fake, [])
    assert result is not None
    assert result["format"] == "vhd"


def test_qcow2_detect_by_magic_and_extension(tmp_path: Path) -> None:
    _require_qemu()
    adapter = QcowImageAdapter()
    fake = tmp_path / "test.qcow2"
    fake.write_bytes(b"QFI\xfb" + (b"\x00" * 65536))
    result = adapter.detect(fake, [])
    assert result is not None
    assert result["format"] == "qcow2"


def test_vdi_detect_by_magic_and_extension(tmp_path: Path) -> None:
    _require_qemu()
    adapter = VdiImageAdapter()
    fake = tmp_path / "test.vdi"
    fake.write_bytes(b"<<< Oracle VM VirtualBox Disk Image >>>" + (b"\x00" * 65536))
    result = adapter.detect(fake, [])
    assert result is not None
    assert result["format"] == "vdi"


def test_registry_exposes_all_virtual_formats() -> None:
    registry = get_image_format_registry()
    capabilities = registry.list_capabilities()
    keys = {item["key"] for item in capabilities}
    for expected in ("vmdk", "vhd", "qcow2", "vdi", "raw", "ewf"):
        assert expected in keys


@pytest.mark.skipif(subprocess.run(["bash", "-lc", "command -v qemu-img >/dev/null 2>&1"], check=False).returncode != 0, reason="needs qemu-img")
def test_vmdk_convert_and_detect_through_registry(tmp_path: Path) -> None:
    fs_image = tmp_path / "linux.img"
    _mkfat_image(fs_image, {
        "etc/os-release": 'PRETTY_NAME="Ubuntu 24.04 LTS"\n',
        "etc/passwd": "root:x:0:0:root:/root:/bin/bash\n",
        "var/log/auth.log": "Accepted password for root from 10.0.0.5\n",
    })
    vmdk = tmp_path / "test.vmdk"
    subprocess.run(["qemu-img", "convert", "-O", "vmdk", str(fs_image), str(vmdk)], check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    assert vmdk.exists()
    detection = detect_disk_image_format(vmdk)
    assert detection is not None
    assert detection["format"] == "vmdk"


@pytest.mark.skipif(subprocess.run(["bash", "-lc", "command -v qemu-img >/dev/null 2>&1"], check=False).returncode != 0, reason="needs qemu-img")
def test_qcow2_convert_and_detect(tmp_path: Path) -> None:
    fs_image = tmp_path / "base.img"
    _mkfat_image(fs_image, {"etc/passwd": "root:x:0:0:root:/root:/bin/bash\n"})
    qcow2 = tmp_path / "test.qcow2"
    subprocess.run(["qemu-img", "convert", "-O", "qcow2", str(fs_image), str(qcow2)], check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    detection = detect_disk_image_format(qcow2)
    assert detection is not None
    assert detection["format"] == "qcow2"


@pytest.mark.skipif(subprocess.run(["bash", "-lc", "command -v qemu-img >/dev/null 2>&1"], check=False).returncode != 0, reason="needs qemu-img")
def test_vhd_convert_and_detect(tmp_path: Path) -> None:
    fs_image = tmp_path / "base.img"
    _mkfat_image(fs_image, {"etc/passwd": "root:x:0:0:root:/root:/bin/bash\n"})
    vhd = tmp_path / "test.vhd"
    subprocess.run(["qemu-img", "convert", "-O", "vpc", str(fs_image), str(vhd)], check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    detection = detect_disk_image_format(vhd)
    assert detection is not None
    assert detection["format"] == "vhd"


@pytest.mark.skipif(subprocess.run(["bash", "-lc", "command -v qemu-img >/dev/null 2>&1"], check=False).returncode != 0, reason="needs qemu-img")
def test_vdi_convert_and_detect(tmp_path: Path) -> None:
    fs_image = tmp_path / "base.img"
    _mkfat_image(fs_image, {"etc/passwd": "root:x:0:0:root:/root:/bin/bash\n"})
    vdi = tmp_path / "test.vdi"
    subprocess.run(["qemu-img", "convert", "-O", "vdi", str(fs_image), str(vdi)], check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    detection = detect_disk_image_format(vdi)
    assert detection is not None
    assert detection["format"] == "vdi"


@pytest.mark.skipif(subprocess.run(["bash", "-lc", "command -v qemu-img >/dev/null 2>&1"], check=False).returncode != 0, reason="needs qemu-img")
def test_vmdk_materialize_and_index_linux(sqlite_session, tmp_path: Path) -> None:
    import hashlib

    from app.core.database import utc_now_naive
    from app.disk_images.service import materialize_disk_image_sources
    from app.ingest.kape import list_kape_artifacts
    from app.models.case import Case
    from app.models.evidence import Evidence, EvidenceIntegrityStatus, EvidenceStorageMode, EvidenceType, IngestStatus

    fs_image = tmp_path / "linux.img"
    _mkfat_image(fs_image, {
        "etc/os-release": 'PRETTY_NAME="Ubuntu 24.04 LTS"\n',
        "etc/passwd": "root:x:0:0:root:/root:/bin/bash\n",
        "var/log/auth.log": "Accepted password for root from 10.0.0.5\n",
    })
    vmdk = tmp_path / "test.vmdk"
    subprocess.run(["qemu-img", "convert", "-O", "vmdk", str(fs_image), str(vmdk)], check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    vmdk_path = vmdk
    evidence = Evidence(
        case_id="case-1",
        original_filename=vmdk.name,
        stored_path=str(vmdk_path),
        original_path=str(vmdk_path.parent),
        storage_mode=EvidenceStorageMode.uploaded,
        is_external=False,
        copy_to_storage=True,
        evidence_type=EvidenceType.disk_image,
        sha256=hashlib.sha256(vmdk_path.read_bytes()).hexdigest(),
        size_bytes=vmdk_path.stat().st_size,
        ingest_status=IngestStatus.pending,
        integrity_status=EvidenceIntegrityStatus.unknown,
        path_validation={},
        ingest_source={"mode": "uploaded", "disk_image": True},
        metadata_json={},
        error_log={},
        uploaded_at=utc_now_naive(),
        first_seen_at=utc_now_naive(),
    )
    case = Case(id="case-1", name="VDMK Test")
    sqlite_session.add(case)
    sqlite_session.add(evidence)
    sqlite_session.commit()
    extract_dir = tmp_path / "extract-vmdk"

    result = materialize_disk_image_sources(sqlite_session, evidence, extract_dir=extract_dir)
    artifacts = list_kape_artifacts(result.extract_dir)

    assert result.disk_image.format == "vmdk"
    assert len(result.volumes) == 1
    assert result.volumes[0].readable is True
    assert any(install.platform == "linux" for install in result.installations)
    assert any(item["artifact_type"] == "linux_auth" for item in artifacts)

    assert not (tmp_path.parent / f"disk-image-{evidence.id}").exists()


def test_qemu_check_cleanup_sets_status_on_image_with_absent_qemu() -> None:
    """Adapter status reflects unavailable dependency rather than failing silently."""
    adapter = VmdkImageAdapter()
    readiness = adapter.readiness()
    if readiness["ready"]:
        pytest.skip("qemu-img is available in this environment")
    assert readiness["ready"] is False
    assert "qemu-img" in readiness.get("reason", "")


def test_qcow2_backing_file_external_rejected(tmp_path: Path) -> None:
    backing_info = {"full-backing-filename": "/etc/passwd"}
    result = _validate_backing_file(backing_info, tmp_path)
    assert result["valid"] is False
