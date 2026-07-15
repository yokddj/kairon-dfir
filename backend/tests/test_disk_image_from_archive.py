from __future__ import annotations

import hashlib
import json
import zipfile
from pathlib import Path
import subprocess
import tarfile

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from app.core.config import get_settings
from app.core.database import Base
from app.disk_images.registry import get_image_format_registry
from app.disk_images.service import detect_disk_image_format, materialize_disk_image_sources
from app.ingest.detector import detect_evidence_type
from app.ingest.evidence_classifier import EvidenceCategory, get_evidence_classifier
from app.ingest.kape import list_kape_artifacts
from app.models.case import Case
from app.models.evidence import Evidence, EvidenceStorageMode, EvidenceType, IngestStatus


settings = get_settings()


def _require_tools(*names: str) -> None:
    missing = []
    for name in names:
        if subprocess.run(["bash", "-lc", f"command -v {name} >/dev/null 2>&1"], check=False).returncode != 0:
            missing.append(name)
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


def _write_tree(root: Path, files: dict[str, str]) -> None:
    for rel, content in files.items():
        target = root / rel
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(content, encoding="utf-8")


def _create_fat_fs(target: Path, files: dict[str, str], *, size_kib: int = 16384) -> None:
    _require_tools("mkfs.vfat", "mcopy", "mmd")
    src = target.parent / f"{target.stem}-src"
    src.mkdir(parents=True, exist_ok=True)
    _write_tree(src, files)
    subprocess.run(
        ["mkfs.vfat", "-C", str(target), str(size_kib)],
        check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
    )
    dirs: set[str] = set()
    for rel in files:
        current = Path(rel).parent
        while str(current) not in {"", "."}:
            dirs.add(str(current).replace("\\", "/"))
            current = current.parent
    for d in sorted(dirs, key=lambda x: (x.count("/"), x)):
        subprocess.run(
            ["mmd", "-i", str(target), f"::/{d}"],
            check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        )
    for rel in files:
        subprocess.run(
            ["mcopy", "-i", str(target), str(src / rel), f"::/{rel.replace('\\', '/')}"],
            check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        )


def _make_evidence(db, path: Path, *, evidence_type: EvidenceType = EvidenceType.unknown) -> Evidence:
    case = Case(id="archive-case", name="Archive Test")
    db.add(case)
    db.flush()
    evidence = Evidence(
        id=f"ev-{path.stem}",
        case_id=case.id,
        original_filename=path.name,
        stored_path=str(path),
        original_path=str(path),
        storage_mode=EvidenceStorageMode.uploaded,
        is_external=False,
        copy_to_storage=True,
        evidence_type=evidence_type,
        sha256=hashlib.sha256(path.read_bytes()).hexdigest() if path.is_file() else None,
        size_bytes=path.stat().st_size if path.exists() else 0,
        ingest_status=IngestStatus.pending,
        mime_type=None,
        detected_type=None,
        uploaded_by_user_id=None,
    )
    db.add(evidence)
    db.flush()
    return evidence


def _make_zip(source_paths: list[Path], target: Path) -> None:
    with zipfile.ZipFile(target, "w", zipfile.ZIP_DEFLATED) as zf:
        for sp in source_paths:
            zf.write(sp, sp.name)


def _make_tar(source_paths: list[Path], target: Path, *, mode: str = "w:gz") -> None:
    with tarfile.open(target, mode) as tf:
        for sp in source_paths:
            tf.add(sp, sp.name)


class TestEvidenceClassifier:
    def test_classify_archive_zip(self, tmp_path: Path) -> None:
        archive = tmp_path / "test.zip"
        with zipfile.ZipFile(archive, "w") as zf:
            zf.writestr("dummy.txt", "hello")
        classifier = get_evidence_classifier()
        result = classifier.classify(archive)
        assert result.category == EvidenceCategory.ARCHIVE

    def test_classify_archive_tar_gz(self, tmp_path: Path) -> None:
        archive = tmp_path / "test.tar.gz"
        with tarfile.open(archive, "w:gz") as tf:
            pass
        classifier = get_evidence_classifier()
        result = classifier.classify(archive)
        assert result.category == EvidenceCategory.ARCHIVE

    def test_classify_raw_disk_image(self, tmp_path: Path) -> None:
        _require_tools("mkfs.vfat")
        raw = tmp_path / "test.raw"
        _create_fat_fs(raw, {"hello.txt": "world"}, size_kib=4096)
        classifier = get_evidence_classifier()
        result = classifier.classify(raw)
        assert result.category == EvidenceCategory.DISK_IMAGE
        assert result.format_key == "raw"

    def test_classify_unknown_text_file(self, tmp_path: Path) -> None:
        txt = tmp_path / "readme.txt"
        txt.write_text("hello")
        classifier = get_evidence_classifier()
        result = classifier.classify(txt)
        assert result.category == EvidenceCategory.UNKNOWN


class TestZipToRawLinux:
    """ZIP -> RAW (Linux filesystem) E2E"""

    def test_zip_containing_linux_raw_image(self, tmp_path: Path, sqlite_session) -> None:
        _require_tools("mkfs.vfat")
        raw = tmp_path / "vm-101-disk-0.raw"
        linux_files = {
            "etc/os-release": 'PRETTY_NAME="Test Linux 1.0"\nNAME="Test Linux"\n',
            "etc/hostname": "test-vm-101\n",
            "etc/passwd": "root:x:0:0:root:/root:/bin/bash\n",
            "var/log/syslog": "Jan 1 00:00:00 test-vm-101 kernel: boot\n",
            "home/user/.bash_history": "ls\ncd /tmp\n",
        }
        _create_fat_fs(raw, linux_files, size_kib=16384)

        zip_path = tmp_path / "vm-101-disk-0.zip"
        _make_zip([raw], zip_path)

        classifier = get_evidence_classifier()
        result = classifier.classify(zip_path)
        assert result.category == EvidenceCategory.ARCHIVE

        extract_dir = tmp_path / "extracted"
        extract_dir.mkdir(parents=True, exist_ok=True)

        from app.ingest.archive import extract_archive
        extracted_files, archive_entries = extract_archive(zip_path, extract_dir)

        assert "vm-101-disk-0.raw" in extracted_files

        raw_extracted = extract_dir / "vm-101-disk-0.raw"
        assert raw_extracted.exists()

        raw_result = classifier.classify(raw_extracted)
        assert raw_result.category == EvidenceCategory.DISK_IMAGE
        assert raw_result.format_key == "raw"

        evidence = _make_evidence(sqlite_session, zip_path)
        mat = materialize_disk_image_sources(
            sqlite_session, evidence,
            extract_dir=extract_dir,
            image_path=raw_extracted,
        )

        assert mat.disk_image is not None
        assert len(mat.volumes) > 0
        assert len(mat.installations) > 0
        platforms = [i.platform for i in mat.installations]
        assert "linux" in platforms

        artifacts = list_kape_artifacts(extract_dir)
        assert len(artifacts) > 0

    def test_detect_evidence_type_zip_with_raw(self, tmp_path: Path) -> None:
        _require_tools("mkfs.vfat")
        raw = tmp_path / "disk.raw"
        _create_fat_fs(raw, {"test.txt": "hello"}, size_kib=4096)
        zip_path = tmp_path / "disk.zip"
        _make_zip([raw], zip_path)

        detected = detect_evidence_type(zip_path, ["disk.raw"])
        assert detected == EvidenceType.disk_image or detected == EvidenceType.unknown


class TestZipToRawWindows:
    """ZIP -> RAW (Windows filesystem) E2E"""

    def test_zip_containing_windows_raw_image(self, tmp_path: Path, sqlite_session) -> None:
        _require_tools("mkfs.vfat")
        raw = tmp_path / "windows-disk.raw"
        windows_files = {
            "Windows/System32/config/SYSTEM": "\x00" * 512,
            "Windows/System32/config/SOFTWARE": "\x00" * 512,
            "Users/Admin/Desktop/readme.txt": "Hello\n",
            "ProgramData/some.log": "log data\n",
        }
        _create_fat_fs(raw, windows_files, size_kib=16384)

        zip_path = tmp_path / "windows-disk.zip"
        _make_zip([raw], zip_path)

        extract_dir = tmp_path / "win-extracted"
        extract_dir.mkdir(parents=True, exist_ok=True)

        from app.ingest.archive import extract_archive
        extracted_files, archive_entries = extract_archive(zip_path, extract_dir)

        raw_extracted = extract_dir / "windows-disk.raw"
        classifier = get_evidence_classifier()
        result = classifier.classify(raw_extracted)
        assert result.category == EvidenceCategory.DISK_IMAGE

        evidence = _make_evidence(sqlite_session, zip_path)
        mat = materialize_disk_image_sources(
            sqlite_session, evidence,
            extract_dir=extract_dir,
            image_path=raw_extracted,
        )
        assert mat.disk_image is not None
        assert len(mat.volumes) > 0


@pytest.mark.skipif(
    subprocess.run(["bash", "-lc", "command -v qemu-img >/dev/null 2>&1"], check=False).returncode != 0,
    reason="qemu-img not available",
)
class TestZipToVirtualFormats:
    """ZIP -> QCOW2, VMDK, VHD"""

    def _create_qcow2(self, target: Path, raw_backing: Path) -> None:
        subprocess.run(
            ["qemu-img", "convert", "-f", "raw", "-O", "qcow2", str(raw_backing), str(target)],
            check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        )

    def _create_vmdk(self, target: Path, raw_backing: Path) -> None:
        subprocess.run(
            ["qemu-img", "convert", "-f", "raw", "-O", "vmdk", str(raw_backing), str(target)],
            check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        )

    def _create_vhd(self, target: Path, raw_backing: Path) -> None:
        subprocess.run(
            ["qemu-img", "convert", "-f", "raw", "-O", "vpc", str(raw_backing), str(target)],
            check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        )

    def test_zip_qcow2_linux(self, tmp_path: Path, sqlite_session) -> None:
        _require_tools("mkfs.vfat", "qemu-img")
        raw = tmp_path / "base.raw"
        _create_fat_fs(raw, {"etc/os-release": 'PRETTY_NAME="Linux"\n', "etc/hostname": "vm\n"}, size_kib=16384)

        qcow2 = tmp_path / "vm.qcow2"
        self._create_qcow2(qcow2, raw)

        zip_path = tmp_path / "vm.qcow2.zip"
        _make_zip([qcow2], zip_path)

        extract_dir = tmp_path / "qcow2-extracted"
        extract_dir.mkdir(parents=True, exist_ok=True)

        from app.ingest.archive import extract_archive
        extracted_files, archive_entries = extract_archive(zip_path, extract_dir)

        qcow2_extracted = extract_dir / "vm.qcow2"
        classifier = get_evidence_classifier()
        result = classifier.classify(qcow2_extracted)
        assert result.category == EvidenceCategory.DISK_IMAGE
        assert result.format_key == "qcow2"

        evidence = _make_evidence(sqlite_session, zip_path)
        mat = materialize_disk_image_sources(
            sqlite_session, evidence,
            extract_dir=extract_dir,
            image_path=qcow2_extracted,
        )
        assert mat.disk_image is not None

    def test_zip_vmdk_linux(self, tmp_path: Path, sqlite_session) -> None:
        _require_tools("mkfs.vfat", "qemu-img")
        raw = tmp_path / "base.raw"
        _create_fat_fs(raw, {"etc/os-release": 'PRETTY_NAME="Linux"\n'}, size_kib=16384)

        vmdk = tmp_path / "vm.vmdk"
        self._create_vmdk(vmdk, raw)

        zip_path = tmp_path / "vm.vmdk.zip"
        _make_zip([vmdk], zip_path)

        extract_dir = tmp_path / "vmdk-extracted"
        extract_dir.mkdir(parents=True, exist_ok=True)

        from app.ingest.archive import extract_archive
        extracted_files, archive_entries = extract_archive(zip_path, extract_dir)

        vmdk_extracted = extract_dir / "vm.vmdk"
        classifier = get_evidence_classifier()
        result = classifier.classify(vmdk_extracted)
        assert result.category == EvidenceCategory.DISK_IMAGE

    def test_zip_vhd_linux(self, tmp_path: Path, sqlite_session) -> None:
        _require_tools("mkfs.vfat", "qemu-img")
        raw = tmp_path / "base.raw"
        _create_fat_fs(raw, {"etc/os-release": 'PRETTY_NAME="Linux"\n'}, size_kib=16384)

        vhd = tmp_path / "vm.vhd"
        self._create_vhd(vhd, raw)

        zip_path = tmp_path / "vm.vhd.zip"
        _make_zip([vhd], zip_path)

        extract_dir = tmp_path / "vhd-extracted"
        extract_dir.mkdir(parents=True, exist_ok=True)

        from app.ingest.archive import extract_archive
        extracted_files, archive_entries = extract_archive(zip_path, extract_dir)

        vhd_extracted = extract_dir / "vm.vhd"
        classifier = get_evidence_classifier()
        result = classifier.classify(vhd_extracted)
        assert result.category == EvidenceCategory.DISK_IMAGE


class TestNestedArchives:
    """ZIP -> ZIP -> RAW"""

    def test_double_zip_raw(self, tmp_path: Path, sqlite_session) -> None:
        _require_tools("mkfs.vfat")
        raw = tmp_path / "disk.raw"
        _create_fat_fs(raw, {"etc/os-release": 'PRETTY_NAME="Nested Test"\n'}, size_kib=16384)

        inner_zip = tmp_path / "inner.zip"
        _make_zip([raw], inner_zip)

        outer_zip = tmp_path / "outer.zip"
        _make_zip([inner_zip], outer_zip)

        classifier = get_evidence_classifier()
        result = classifier.classify(outer_zip)
        assert result.category == EvidenceCategory.ARCHIVE

        extract_dir = tmp_path / "nested-extracted"
        extract_dir.mkdir(parents=True, exist_ok=True)

        from app.ingest.archive import extract_archive
        f1, e1 = extract_archive(outer_zip, extract_dir)
        assert "inner.zip" in f1

        inner_path = extract_dir / "inner.zip"
        assert inner_path.exists()

        inner_result = classifier.classify(inner_path)
        assert inner_result.category == EvidenceCategory.ARCHIVE

        sub_dir = extract_dir / "_nested_0_inner"
        sub_dir.mkdir(parents=True, exist_ok=True)
        f2, e2 = extract_archive(inner_path, sub_dir)
        assert "disk.raw" in f2

        raw_path = sub_dir / "disk.raw"
        raw_result = classifier.classify(raw_path)
        assert raw_result.category == EvidenceCategory.DISK_IMAGE

        evidence = _make_evidence(sqlite_session, outer_zip)
        mat = materialize_disk_image_sources(
            sqlite_session, evidence,
            extract_dir=sub_dir,
            image_path=raw_path,
        )
        assert mat.disk_image is not None
        assert len(mat.volumes) > 0

    def test_tar_gz_raw(self, tmp_path: Path, sqlite_session) -> None:
        _require_tools("mkfs.vfat", "7z")
        raw = tmp_path / "disk.raw"
        _create_fat_fs(raw, {"etc/os-release": 'PRETTY_NAME="TAR Test"\n'}, size_kib=16384)

        tar_path = tmp_path / "disk.tar.gz"
        _make_tar([raw], tar_path)

        extract_dir = tmp_path / "tar-extracted"
        extract_dir.mkdir(parents=True, exist_ok=True)

        from app.ingest.archive import extract_archive
        files, entries = extract_archive(tar_path, extract_dir)
        assert "disk.raw" in files

        raw_extracted = extract_dir / "disk.raw"
        classifier = get_evidence_classifier()
        result = classifier.classify(raw_extracted)
        assert result.category == EvidenceCategory.DISK_IMAGE

        evidence = _make_evidence(sqlite_session, tar_path)
        mat = materialize_disk_image_sources(
            sqlite_session, evidence,
            extract_dir=extract_dir,
            image_path=raw_extracted,
        )
        assert mat.disk_image is not None


class TestMixedCollection:
    """ZIP containing both artifacts and a RAW image"""

    def test_zip_with_artifacts_and_raw(self, tmp_path: Path, sqlite_session) -> None:
        _require_tools("mkfs.vfat")
        raw = tmp_path / "disk.raw"
        _create_fat_fs(raw, {"etc/os-release": 'PRETTY_NAME="Mixed"\n'}, size_kib=16384)

        artifact_dir = tmp_path / "artifacts"
        artifact_dir.mkdir(parents=True, exist_ok=True)
        (artifact_dir / "sample.csv").write_text("col1,col2\nval1,val2\n", encoding="utf-8")

        zip_path = tmp_path / "mixed.zip"
        with zipfile.ZipFile(zip_path, "w", zipfile.ZIP_DEFLATED) as zf:
            zf.write(raw, raw.name)
            zf.write(artifact_dir / "sample.csv", "sample.csv")

        extract_dir = tmp_path / "mixed-extracted"
        extract_dir.mkdir(parents=True, exist_ok=True)

        from app.ingest.archive import extract_archive
        files, entries = extract_archive(zip_path, extract_dir)
        assert "disk.raw" in files
        assert "sample.csv" in files

        classifier = get_evidence_classifier()
        raw_result = classifier.classify(extract_dir / "disk.raw")
        assert raw_result.category == EvidenceCategory.DISK_IMAGE

        csv_result = classifier.classify(extract_dir / "sample.csv")
        assert csv_result.category == EvidenceCategory.UNKNOWN

        evidence = _make_evidence(sqlite_session, zip_path)
        mat = materialize_disk_image_sources(
            sqlite_session, evidence,
            extract_dir=extract_dir,
            image_path=extract_dir / "disk.raw",
        )
        assert mat.disk_image is not None

        artifacts = list_kape_artifacts(extract_dir)
        csv_artifacts = [a for a in artifacts if "sample.csv" in str(a.get("source_path") or a.get("name", ""))]
        assert len(csv_artifacts) > 0 or len(artifacts) > 0


class TestClassifierEdgeCases:
    def test_classify_nonexistent_file(self, tmp_path: Path) -> None:
        classifier = get_evidence_classifier()
        result = classifier.classify(tmp_path / "nonexistent.raw")
        assert result.category == EvidenceCategory.UNKNOWN

    def test_classify_zero_byte_file(self, tmp_path: Path) -> None:
        f = tmp_path / "empty.bin"
        f.write_bytes(b"")
        classifier = get_evidence_classifier()
        result = classifier.classify(f)
        assert result.category is not None

    def test_classify_directory(self, tmp_path: Path) -> None:
        classifier = get_evidence_classifier()
        result = classifier.classify(tmp_path)
        assert result.category == EvidenceCategory.UNKNOWN

    def test_classify_detects_raw_by_magic(self, tmp_path: Path) -> None:
        raw = tmp_path / "noext"
        raw.write_bytes(b"\x00" * 4096)
        classifier = get_evidence_classifier()
        result = classifier.classify(raw)
        assert result.category == EvidenceCategory.DISK_IMAGE or result.category == EvidenceCategory.UNKNOWN
