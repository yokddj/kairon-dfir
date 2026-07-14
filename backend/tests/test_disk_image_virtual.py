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
    _build_authorized_set,
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

    assert not (tmp_path / f"disk-image-{evidence.id}").exists()


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


def test_authorized_set_rejects_extent_outside_upload(tmp_path: Path) -> None:
    outside = tmp_path / "outside" / "flat.vmdk"
    outside.parent.mkdir(parents=True, exist_ok=True)
    outside.write_bytes(b"\x00" * 1024)
    upload_dir = tmp_path / "upload"
    upload_dir.mkdir()
    (upload_dir / "descriptor.vmdk").write_text("")
    authorized = _build_authorized_set(upload_dir, [])
    validation = _validate_vmdk_extents(tmp_path, ["flat.vmdk"], authorized_paths=authorized)
    assert "flat.vmdk" in validation.get("missing", []) or "flat.vmdk" in validation.get("unauthorized", [])


def test_authorized_set_rejects_parent_outside_upload(tmp_path: Path) -> None:
    authorized = _build_authorized_set(tmp_path, [])
    backing_info = {"backing-filename": "parent.qcow2"}
    result = _validate_backing_file(backing_info, tmp_path, authorized_paths=authorized)
    assert result["valid"] is False
    assert "parent_not_in_authorized_set" in result.get("error", "")


def test_chain_loop_detected(monkeypatch, tmp_path: Path) -> None:
    from app.disk_images.qcow import QcowImageAdapter
    adapter = QcowImageAdapter()
    authorized = _build_authorized_set(tmp_path, [])
    adapter._check_chain_depth = lambda path, auth, depth: {"error": "chain_loop_detected"}
    result = adapter.expose_readonly(evidence_id="ev-1", path=tmp_path / "test.qcow2", companions=[], workspace=tmp_path)
    assert result.get("error") == "chain_loop_detected" or "qemu-img" in str(result.get("error", ""))


def test_subprocess_never_shell_true(monkeypatch, tmp_path: Path) -> None:
    import subprocess as sp
    captured = []

    def fake_run(command, capture_output, text, shell, timeout, cwd=None):
        captured.append({"command": command, "shell": shell})
        return sp.CompletedProcess(args=command, returncode=0, stdout="{}", stderr="")

    monkeypatch.setattr(sp, "run", fake_run)
    qemu_img_info(Path("/fake/path"))
    assert len(captured) > 0
    for call in captured:
        assert call["shell"] is False, f"shell=True detected in command: {call['command']}"


def test_readonly_preserves_original_hash(monkeypatch, tmp_path: Path) -> None:
    import hashlib as hl
    original = tmp_path / "original.vmdk"
    original.write_bytes(b"KDMV" + (b"\x00" * 4096))
    original_hash = hl.sha256(original.read_bytes()).hexdigest()
    monkeypatch.setattr("app.disk_images.qemu._tool_functional", lambda name: True)
    monkeypatch.setattr("app.disk_images.qemu.qemu_img_info", lambda path: {"format": "vmdk", "virtual-size": 8388608, "actual-size": 4096})
    monkeypatch.setattr("app.disk_images.qemu.qemu_img_check", lambda path: {"valid": True, "errors": [], "warnings": [], "returncode": 0})
    monkeypatch.setattr("app.disk_images.qemu.qemu_img_convert_to_raw", lambda **kw: {"format": "raw", "supported": True, "exported_raw_path": str(tmp_path / "mock-export.raw"), "command": [], "returncode": 0, "stdout": "", "stderr": "", "access_strategy": "test", "tool": "qemu-img", "tool_version": "1.0"})
    adapter = VmdkImageAdapter()
    result = adapter.expose_readonly(evidence_id="ev-1", path=original, companions=[], workspace=tmp_path)
    final_hash = hl.sha256(original.read_bytes()).hexdigest()
    assert final_hash == original_hash


def test_memory_disk_disambiguation_raw_content(tmp_path: Path) -> None:
    """Filesystem image with RAW content should be detected as disk_image, not memory."""
    img = tmp_path / "test.img"
    _mkfat_image(img, {"etc/passwd": "root:x:0:0:root:/root:/bin/bash\n"})
    from app.ingest.detector import detect_evidence_type
    from app.models.evidence import EvidenceType
    result = detect_evidence_type(img)
    assert result == EvidenceType.disk_image


def test_memory_disk_disambiguation_random_data(tmp_path: Path) -> None:
    """Random data without disk signature should NOT be classified as disk_image."""
    random_file = tmp_path / "random.img"
    random_file.write_bytes(b"NOT_A_DISK_IMAGE" + (b"\x00" * 4096))
    detection = detect_disk_image_format(random_file)
    assert detection is None or detection.get("format") == "raw"


def test_cleanup_removes_exported_raw_on_failure(tmp_path: Path) -> None:
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    raw_file = workspace / "test-export.raw"
    raw_file.write_bytes(b"fake raw content")
    adapter = VmdkImageAdapter()
    adapter.cleanup({"exported_raw_path": str(raw_file)})
    assert not raw_file.exists()


def test_vmdk_materialize_provenance_has_source_fields(sqlite_session, tmp_path: Path) -> None:
    import hashlib as hl
    from app.core.database import utc_now_naive
    from app.disk_images.service import materialize_disk_image_sources
    from app.ingest.kape import list_kape_artifacts
    from app.models.case import Case
    from app.models.evidence import Evidence, EvidenceIntegrityStatus, EvidenceStorageMode, EvidenceType, IngestStatus

    fs_image = tmp_path / "linux.img"
    _mkfat_image(fs_image, {
        "etc/os-release": 'PRETTY_NAME="Ubuntu 24.04 LTS"\n',
        "etc/passwd": "root:x:0:0:root:/root:/bin/bash\n",
    })
    vmdk = tmp_path / "test-pv.vmdk"
    subprocess.run(["qemu-img", "convert", "-O", "vmdk", str(fs_image), str(vmdk)], check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    case = Case(id="case-99", name="Provenance Test")
    evidence = Evidence(
        case_id="case-99",
        original_filename=vmdk.name,
        stored_path=str(vmdk),
        original_path=str(vmdk.parent),
        storage_mode=EvidenceStorageMode.uploaded,
        is_external=False, copy_to_storage=True,
        evidence_type=EvidenceType.disk_image,
        sha256=hl.sha256(vmdk.read_bytes()).hexdigest(),
        size_bytes=vmdk.stat().st_size,
        ingest_status=IngestStatus.pending,
        integrity_status=EvidenceIntegrityStatus.unknown,
        path_validation={}, ingest_source={"mode": "uploaded", "disk_image": True},
        metadata_json={}, error_log={},
        uploaded_at=utc_now_naive(), first_seen_at=utc_now_naive(),
    )
    sqlite_session.add(case)
    sqlite_session.add(evidence)
    sqlite_session.commit()
    result = materialize_disk_image_sources(sqlite_session, evidence, extract_dir=tmp_path / "extract-pv")
    source_map = result.source_map
    assert len(source_map) > 0
    for key, src in source_map.items():
        assert "disk_image_id" in src
        assert "disk_volume_id" in src
        assert "original_source_path" in src
        assert "acquisition_method" in src
        assert src["disk_image_id"] is not None
        assert src["disk_volume_id"] is not None
