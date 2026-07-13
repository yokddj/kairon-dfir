from __future__ import annotations

import hashlib
from pathlib import Path
import subprocess

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from app.core.database import Base
from app.disk_images.ewf import EwfImageAdapter
from app.disk_images.registry import get_image_format_registry
from app.disk_images.service import detect_disk_image_format, materialize_disk_image_sources
from app.ingest.detector import detect_evidence_type
from app.ingest.kape import list_kape_artifacts
from app.models.case import Case
from app.models.evidence import Evidence, EvidenceStorageMode, EvidenceType, IngestStatus


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
    for relative_path, contents in files.items():
        target = root / relative_path
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(contents, encoding="utf-8")


def _create_fat_filesystem_image(target: Path, files: dict[str, str], *, size_kib: int = 16384) -> None:
    _require_tools("mkfs.vfat", "mcopy", "mmd")
    source_root = target.parent / f"{target.stem}-src"
    source_root.mkdir(parents=True, exist_ok=True)
    _write_tree(source_root, files)
    subprocess.run(["mkfs.vfat", "-C", str(target), str(size_kib)], check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    directories: set[str] = set()
    for path in files:
        current = Path(path).parent
        while str(current) not in {"", "."}:
            directories.add(str(current).replace("\\", "/"))
            current = current.parent
    for directory in sorted(directories, key=lambda item: (item.count("/"), item)):
        subprocess.run(["mmd", "-i", str(target), f"::/{directory}"], check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    for relative_path in files:
        subprocess.run(["mcopy", "-i", str(target), str(source_root / relative_path), f"::/{relative_path.replace('\\', '/')}"], check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)


def _create_partitioned_image(target: Path, fs_image: Path, *, label: str) -> None:
    _require_tools("parted")
    target.write_bytes(b"\x00" * (32 * 1024 * 1024))
    subprocess.run(["parted", "-s", str(target), "mklabel", label, "mkpart", "primary", "fat32", "1MiB", "17MiB"], check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    subprocess.run(["dd", f"if={fs_image}", f"of={target}", "bs=1M", "seek=1", "conv=notrunc"], check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)


def _create_dual_partition_image(target: Path, first_fs_image: Path, second_fs_image: Path) -> None:
    _require_tools("parted")
    target.write_bytes(b"\x00" * (48 * 1024 * 1024))
    subprocess.run(["parted", "-s", str(target), "mklabel", "msdos", "mkpart", "primary", "fat32", "1MiB", "17MiB", "mkpart", "primary", "fat32", "18MiB", "34MiB"], check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    subprocess.run(["dd", f"if={first_fs_image}", f"of={target}", "bs=1M", "seek=1", "conv=notrunc"], check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    subprocess.run(["dd", f"if={second_fs_image}", f"of={target}", "bs=1M", "seek=18", "conv=notrunc"], check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)


def _create_segmented_ewf(raw_image: Path, target_prefix: Path) -> list[Path]:
    _require_tools("ewfacquire")
    subprocess.run(["ewfacquire", "-u", "-q", "-S", str(1024 * 1024), "-t", str(target_prefix), str(raw_image)], check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    return sorted(target_prefix.parent.glob(f"{target_prefix.name}.E*"))


def _make_case_and_evidence(db, path: Path, *, evidence_type: EvidenceType = EvidenceType.disk_image) -> Evidence:
    case = Case(id="case-1", name="Disk Image Case")
    evidence = Evidence(
        id="evidence-1",
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
        path_validation={},
        ingest_source={},
        metadata_json={},
        error_log={},
    )
    db.add(case)
    db.add(evidence)
    db.commit()
    return evidence


def test_detect_raw_disk_image_by_extension_and_content(tmp_path: Path) -> None:
    image = tmp_path / "linux.img"
    _create_fat_filesystem_image(image, {"etc/passwd": "root:x:0:0:root:/root:/bin/bash\n"})
    no_extension = tmp_path / "linux-sample"
    no_extension.write_bytes(image.read_bytes())

    assert detect_disk_image_format(image)["format"] == "raw"
    assert detect_disk_image_format(no_extension)["format"] == "raw"
    assert detect_evidence_type(image) == EvidenceType.disk_image


def test_materialize_raw_filesystem_image_linux_without_partition_table(sqlite_session, tmp_path: Path) -> None:
    image = tmp_path / "linux.raw"
    _create_fat_filesystem_image(
        image,
        {
            "etc/passwd": "root:x:0:0:root:/root:/bin/bash\n",
            "etc/group": "root:x:0:\n",
            "var/log/auth.log": "Accepted password for root from 10.0.0.5\n",
            "logs/journal.export": "__REALTIME_TIMESTAMP=1710000000000000\n_HOSTNAME=ubuntu-lab\nMESSAGE=Started ssh.service\n\n",
            "home/ubuntu/.bash_history": "whoami\nid\n",
        },
    )
    evidence = _make_case_and_evidence(sqlite_session, image)
    extract_dir = tmp_path / "extract-linux"
    original_hash = hashlib.sha256(image.read_bytes()).hexdigest()

    result = materialize_disk_image_sources(sqlite_session, evidence, extract_dir=extract_dir)
    artifacts = list_kape_artifacts(result.extract_dir)

    assert result.disk_image.format == "raw"
    assert len(result.volumes) == 1
    assert result.volumes[0].readable is True
    assert any(install.platform == "linux" for install in result.installations)
    assert any(item["artifact_type"] == "linux_auth" for item in artifacts)
    assert any(item["artifact_type"] == "linux_journal" for item in artifacts)
    assert any(item["artifact_type"] == "linux_shell_history" for item in artifacts)
    assert hashlib.sha256(image.read_bytes()).hexdigest() == original_hash


def test_materialize_raw_mbr_windows_partition(sqlite_session, tmp_path: Path) -> None:
    fs_image = tmp_path / "windows-fs.img"
    _create_fat_filesystem_image(
        fs_image,
        {
            "Windows/System32/config/SYSTEM": "SYSTEM",
            "Windows/System32/config/SOFTWARE": "SOFTWARE",
            "Users/alex/AppData/Roaming/Microsoft/Windows/PowerShell/PSReadLine/ConsoleHost_history.txt": "Get-Process\n",
            "ProgramData/marker.txt": "marker\n",
        },
    )
    disk = tmp_path / "windows-mbr.dd"
    _create_partitioned_image(disk, fs_image, label="msdos")
    evidence = _make_case_and_evidence(sqlite_session, disk)

    result = materialize_disk_image_sources(sqlite_session, evidence, extract_dir=tmp_path / "extract-windows")
    artifacts = list_kape_artifacts(result.extract_dir)

    assert len(result.volumes) == 1
    assert result.volumes[0].partition_type is not None
    assert any(install.platform == "windows" for install in result.installations)
    assert any(item["artifact_type"] == "powershell" for item in artifacts)


def test_materialize_raw_gpt_linux_partition(sqlite_session, tmp_path: Path) -> None:
    fs_image = tmp_path / "linux-fs.img"
    _create_fat_filesystem_image(
        fs_image,
        {
            "etc/os-release": 'PRETTY_NAME="Ubuntu 24.04 LTS"\n',
            "etc/passwd": "root:x:0:0:root:/root:/bin/bash\n",
            "var/log/syslog": "kernel: booted\n",
        },
    )
    disk = tmp_path / "linux-gpt.img"
    _create_partitioned_image(disk, fs_image, label="gpt")
    evidence = _make_case_and_evidence(sqlite_session, disk)

    result = materialize_disk_image_sources(sqlite_session, evidence, extract_dir=tmp_path / "extract-gpt")

    assert len(result.volumes) == 1
    assert any(install.platform == "linux" for install in result.installations)


def test_materialize_raw_dual_boot_mixed_installations(sqlite_session, tmp_path: Path) -> None:
    windows_fs = tmp_path / "windows-fs.img"
    linux_fs = tmp_path / "linux-fs.img"
    _create_fat_filesystem_image(windows_fs, {"Windows/System32/config/SYSTEM": "SYSTEM", "Windows/System32/config/SOFTWARE": "SOFTWARE", "Users/alex/AppData/Roaming/Microsoft/Windows/PowerShell/PSReadLine/ConsoleHost_history.txt": "Get-Process\n", "ProgramData/marker.txt": "marker\n"})
    _create_fat_filesystem_image(linux_fs, {"etc/os-release": 'PRETTY_NAME="Ubuntu 24.04 LTS"\n', "etc/passwd": "root:x:0:0:root:/root:/bin/bash\n", "var/log/syslog": "kernel: booted\n"})
    disk = tmp_path / "dual-boot.dd"
    _create_dual_partition_image(disk, windows_fs, linux_fs)
    evidence = _make_case_and_evidence(sqlite_session, disk)

    result = materialize_disk_image_sources(sqlite_session, evidence, extract_dir=tmp_path / "extract-mixed")

    assert len(result.volumes) == 2
    assert {install.platform for install in result.installations} == {"windows", "linux"}


def test_ewf_segment_validation_missing_and_duplicate(tmp_path: Path) -> None:
    adapter = EwfImageAdapter()
    good = tmp_path / "case.E01"
    missing = tmp_path / "case.E03"
    duplicate = tmp_path / "case.E02"
    for path in [good, missing, duplicate]:
        path.write_bytes(b"EVF\t\r\n\xff\x00")

    result_missing = adapter.validate_segments(good, [good, missing])
    result_duplicate = adapter.validate_segments(good, [good, duplicate, duplicate])

    assert result_missing["error"] == "missing_segment"
    assert result_duplicate["error"] == "duplicate_segment"


def test_materialize_ewf_segmented_image_linux(sqlite_session, tmp_path: Path) -> None:
    raw_image = tmp_path / "ewf-source.raw"
    _create_fat_filesystem_image(raw_image, {"etc/os-release": 'PRETTY_NAME="Ubuntu 24.04 LTS"\n', "etc/passwd": "root:x:0:0:root:/root:/bin/bash\n", "var/log/auth.log": "Accepted password for root from 10.0.0.5\n"})
    segments = _create_segmented_ewf(raw_image, tmp_path / "case-ewf")
    evidence = _make_case_and_evidence(sqlite_session, segments[0])
    evidence.original_path = str(segments[0].parent)
    sqlite_session.commit()

    result = materialize_disk_image_sources(sqlite_session, evidence, extract_dir=tmp_path / "extract-ewf")
    artifacts = list_kape_artifacts(result.extract_dir)

    assert result.disk_image.format == "ewf"
    assert result.disk_image.segment_count >= 2
    assert any(install.platform == "linux" for install in result.installations)
    assert any(item["artifact_type"] == "linux_auth" for item in artifacts)


def test_encrypted_volume_detected(sqlite_session, tmp_path: Path) -> None:
    image = tmp_path / "encrypted.img"
    image.write_bytes(b"LUKS\xba\xbe" + (b"\x00" * 8192))
    evidence = _make_case_and_evidence(sqlite_session, image)

    result = materialize_disk_image_sources(sqlite_session, evidence, extract_dir=tmp_path / "extract-encrypted")

    assert result.volumes[0].encrypted is True
    assert result.volumes[0].readable is False
    assert result.volumes[0].status == "encrypted_volume"


def test_ewf_adapter_uses_subprocess_without_shell(monkeypatch, tmp_path: Path) -> None:
    adapter = EwfImageAdapter()
    source = tmp_path / "case.E01"
    source.write_bytes(b"EVF\t\r\n\xff\x00")
    captured: dict[str, Any] = {}

    class Completed:
        returncode = 0
        stdout = "ok"
        stderr = ""

    def fake_run(command, capture_output, text, shell, timeout, cwd=None):
        captured["command"] = command
        captured["shell"] = shell
        (tmp_path / "ev-1-ewf-export.raw").write_bytes(b"raw")
        return Completed()

    monkeypatch.setattr(subprocess, "run", fake_run)
    monkeypatch.setattr(adapter, "readiness", lambda: {"key": "ewf", "ready": True, "supported": True, "reason": None})

    result = adapter.expose_readonly(evidence_id="ev-1", path=source, companions=[source], workspace=tmp_path)

    assert captured["shell"] is False
    assert result["access_strategy"] == "ewfexport_to_temporary_raw_readonly"


def test_cleanup_on_exception_removes_workspace(monkeypatch, sqlite_session, tmp_path: Path) -> None:
    image = tmp_path / "linux.raw"
    _create_fat_filesystem_image(image, {"etc/passwd": "root:x:0:0:root:/root:/bin/bash\n"})
    evidence = _make_case_and_evidence(sqlite_session, image)
    workspace = tmp_path / "disk-image-evidence-1"

    from app import disk_images as _di  # noqa: F401
    from app.disk_images import service as service_module

    monkeypatch.setattr(service_module, "_discover_raw_volumes", lambda raw_path: (_ for _ in ()).throw(RuntimeError("boom")))

    with pytest.raises(RuntimeError):
        materialize_disk_image_sources(sqlite_session, evidence, extract_dir=tmp_path / "extract-fail")

    assert not workspace.exists()
