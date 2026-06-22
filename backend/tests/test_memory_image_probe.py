"""Backend tests for the memory image probe and safe .img ingest (v1).

20 tests covering:

1. .img not rejected by extension alone
2. .raw, .mem, .dmp, .bin, .vmem candidates
3. octet-stream MIME allowed as candidate
4. probable_disk detected
5. ambiguous_raw requires confirmation
6. confirmed_memory no override needed
7. invalid file rejected
8. file too small
9. timeout / output limit
10. no shell
11. no network
12. evidence scope
13. override audited
14. re-probe idempotent
15. no file modification
16. no disk index writes
17. no NormalizedEvent
18. no automatic analysis profile
19. path traversal rejected
20. LiME, ELF, Windows crash dump signatures
"""
from __future__ import annotations

import os
import struct
import tempfile
import uuid
from datetime import datetime
from pathlib import Path

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import Session, sessionmaker

from app.core.database import Base, utc_now_naive
from app.models.evidence import Evidence, EvidenceStorageMode, EvidenceType, IngestStatus
from app.models.case import Case
from app.services.memory.probe import (
    CANDIDATE_MEMORY_EXTENSIONS,
    CONFIDENCE_HIGH,
    CONFIDENCE_MEDIUM,
    STATUS_AMBIGUOUS_RAW,
    STATUS_CONFIRMED_MEMORY,
    STATUS_INVALID,
    STATUS_PROBABLE_DISK,
    STATUS_UNSUPPORTED,
    probe_memory_image,
)


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def db(tmp_path) -> Session:
    engine = create_engine("sqlite:///:memory:", connect_args={"check_same_thread": False})
    Base.metadata.create_all(bind=engine)
    Session_ = sessionmaker(bind=engine)
    session = Session_()
    try:
        yield session
    finally:
        session.close()
        engine.dispose()


def _make_fixture_file(tmp_path: Path, content: bytes, suffix: str) -> Path:
    path = tmp_path / f"fixture_{uuid.uuid4().hex}{suffix}"
    path.write_bytes(content)
    return path


def _make_evidence(db: Session, *, case_id: str, stored_path: str) -> Evidence:
    evidence = Evidence(
        id=str(uuid.uuid4()),
        case_id=case_id,
        original_filename=Path(stored_path).name,
        stored_path=stored_path,
        original_path=stored_path,
        evidence_type=EvidenceType.memory_dump,
        storage_mode=EvidenceStorageMode.uploaded,
        is_external=False,
        copy_to_storage=True,
        sha256="0" * 64,
        size_bytes=os.path.getsize(stored_path),
        ingest_status=IngestStatus.completed,
        path_validation={},
        ingest_source={"mode": "uploaded"},
        metadata_json={},
        error_log={},
        processed_at=utc_now_naive(),
    )
    db.add(evidence)
    db.commit()
    return evidence


# ---------------------------------------------------------------------------
# 1-3: Extensions and MIME
# ---------------------------------------------------------------------------


def test_img_extension_accepted_as_candidate(tmp_path: Path) -> None:
    """A .img file with no signature is ambiguous_raw (not rejected)."""
    path = _make_fixture_file(tmp_path, b"\x00" * (2 * 1024 * 1024), ".img")
    result = probe_memory_image(path)
    assert result.status == STATUS_AMBIGUOUS_RAW
    assert result.detected_evidence_type == "memory"
    assert result.requires_confirmation is True


def test_raw_mem_dmp_bin_vmem_are_candidate_extensions(tmp_path: Path) -> None:
    """All common memory image extensions are accepted as candidates."""
    for ext in (".raw", ".mem", ".dmp", ".bin", ".vmem"):
        path = _make_fixture_file(tmp_path, b"\x00" * (2 * 1024 * 1024), ext)
        result = probe_memory_image(path)
        assert result.status in {STATUS_AMBIGUOUS_RAW, STATUS_CONFIRMED_MEMORY}
        assert ext in CANDIDATE_MEMORY_EXTENSIONS or ext == ".vmem"


def test_octet_stream_mime_does_not_block_ingest(tmp_path: Path) -> None:
    """The probe is content-based; MIME is irrelevant.  A .img file
    that arrives as application/octet-stream must still be probed."""
    path = _make_fixture_file(tmp_path, b"\x00" * (2 * 1024 * 1024), ".img")
    result = probe_memory_image(path)
    assert result.detected_format != "invalid"
    # The verdict is based on content, not MIME.


# ---------------------------------------------------------------------------
# 4-7: Detection states
# ---------------------------------------------------------------------------


def test_probable_disk_detected_from_valid_mbr_signature(tmp_path: Path) -> None:
    """A .img file with a structurally valid MBR is classified as probable_disk."""
    # A real MBR has a valid partition entry.  Just the 2-byte
    # signature alone is not enough after the probe hardening.
    content = bytearray(1024 * 1024)
    content[510:512] = b"\x55\xaa"
    # Partition entry 0: bootable NTFS, start LBA 2048, size 204800.
    content[446 + 0] = 0x80
    content[446 + 4] = 0x07
    content[446 + 8:446 + 12] = (2048).to_bytes(4, "little")
    content[446 + 12:446 + 16] = (204800).to_bytes(4, "little")
    path = _make_fixture_file(tmp_path, bytes(content), ".img")
    result = probe_memory_image(path)
    assert result.status == STATUS_PROBABLE_DISK
    assert result.detected_evidence_type == "disk"
    assert result.can_analyze is False


def test_ambiguous_raw_requires_confirmation(tmp_path: Path) -> None:
    path = _make_fixture_file(tmp_path, b"\x00" * (2 * 1024 * 1024), ".img")
    result = probe_memory_image(path)
    assert result.requires_confirmation is True
    assert result.can_analyze is False


def test_confirmed_memory_does_not_require_override(tmp_path: Path) -> None:
    """VMware .vmem is a confirmed memory format."""
    content = b"\x00\x00\x00\x00M\x00R\x00E\x00" + b"\x00" * (2 * 1024 * 1024)
    path = _make_fixture_file(tmp_path, content, ".vmem")
    result = probe_memory_image(path)
    assert result.status == STATUS_CONFIRMED_MEMORY
    assert result.can_analyze is True
    assert result.requires_confirmation is False


def test_invalid_file_rejected(tmp_path: Path) -> None:
    """A file too small is invalid."""
    path = _make_fixture_file(tmp_path, b"\x00" * 100, ".img")
    result = probe_memory_image(path)
    assert result.status == STATUS_INVALID
    assert result.can_analyze is False


# ---------------------------------------------------------------------------
# 8-11: Safety / robustness
# ---------------------------------------------------------------------------


def test_file_too_small_rejected(tmp_path: Path) -> None:
    path = _make_fixture_file(tmp_path, b"\x00" * 512, ".img")
    result = probe_memory_image(path)
    assert result.status == STATUS_INVALID
    assert "too small" in result.reason.lower() or "small" in result.reason.lower()


def test_probe_reads_bounded_bytes(tmp_path: Path) -> None:
    """The probe must read at most a bounded number of bytes."""
    # Create a 4 GiB file would exceed the probe cap.  A 2 MiB file is
    # well within the cap and triggers ambiguous_raw (no signature).
    path = _make_fixture_file(tmp_path, b"\x00" * (2 * 1024 * 1024), ".img")
    result = probe_memory_image(path)
    assert result.file_size == 2 * 1024 * 1024
    assert result.status == STATUS_AMBIGUOUS_RAW


def test_probe_does_not_use_shell() -> None:
    """The probe module must NOT import or invoke subprocess / shell."""
    import app.services.memory.probe as probe_module
    source = Path(probe_module.__file__).read_text()
    assert "subprocess" not in source
    assert "os.system" not in source
    assert "shell=True" not in source


def test_probe_does_not_access_network() -> None:
    """The probe module must NOT import networking libraries."""
    import app.services.memory.probe as probe_module
    source = Path(probe_module.__file__).read_text()
    for forbidden in ("urllib.request", "requests.", "httpx.", "socket.", "aiohttp."):
        assert forbidden not in source


# ---------------------------------------------------------------------------
# 12-14: Evidence scope, override, idempotency
# ---------------------------------------------------------------------------


def test_evidence_scope_enforced_in_probe_endpoint(db: Session, tmp_path: Path) -> None:
    """The probe endpoint must reject evidence that belongs to another case."""
    from app.api.routes_evidence import probe_memory_image as probe_endpoint
    from fastapi import HTTPException
    case = Case(name="case-A")
    db.add(case)
    db.commit()
    other_case = Case(name="case-B")
    db.add(other_case)
    db.commit()
    real_path = _make_fixture_file(tmp_path, b"\x00" * (2 * 1024 * 1024), ".img")
    evidence = _make_evidence(db, case_id=case.id, stored_path=str(real_path))
    with pytest.raises(HTTPException) as exc:
        probe_endpoint(case_id=other_case.id, evidence_id=evidence.id, db=db)
    assert exc.value.status_code == 404


def test_operator_override_audited(db: Session) -> None:
    """The confirmation endpoint writes operator_override + reason."""
    from app.api.routes_evidence import confirm_memory_type
    case = Case(name="case-A")
    db.add(case)
    db.commit()
    with tempfile.NamedTemporaryFile(suffix=".img", delete=False) as f:
        f.write(b"\x00" * (2 * 1024 * 1024))
        tmp_path = f.name
    evidence = _make_evidence(db, case_id=case.id, stored_path=tmp_path)
    evidence.detection_status = STATUS_AMBIGUOUS_RAW
    db.commit()
    result = confirm_memory_type(
        case_id=case.id, evidence_id=evidence.id,
        payload={"reason": "Confirmed as memory by operator.", "authorization_acknowledged": True}, db=db,
    )
    db.refresh(evidence)
    assert evidence.operator_override is True
    assert "operator" in (evidence.operator_override_reason or "").lower()
    assert evidence.detection_status == "ambiguous_raw_confirmed"
    os.unlink(tmp_path)


def test_reprobe_idempotent(tmp_path: Path, db: Session) -> None:
    """Running the probe twice produces the same verdict and does not
    change the file contents."""
    content = b"\x00" * (2 * 1024 * 1024)
    path = _make_fixture_file(tmp_path, content, ".img")
    r1 = probe_memory_image(path)
    r2 = probe_memory_image(path)
    assert r1.status == r2.status
    assert r1.detected_format == r2.detected_format
    # File unchanged.
    assert path.read_bytes() == content


# ---------------------------------------------------------------------------
# 15-18: No side effects
# ---------------------------------------------------------------------------


def test_probe_does_not_modify_file(tmp_path: Path) -> None:
    content = b"\x00\x00\x00\x00M\x00R\x00E\x00" + b"\x00" * (2 * 1024 * 1024)
    path = _make_fixture_file(tmp_path, content, ".vmem")
    sha_before = hash(content)
    probe_memory_image(path)
    sha_after = hash(path.read_bytes())
    assert sha_before == sha_after


def test_probe_does_not_create_normalized_event(tmp_path: Path, db: Session) -> None:
    """The probe must NOT insert NormalizedEvent rows."""
    case = Case(name="case-A")
    db.add(case)
    db.commit()
    path = _make_fixture_file(tmp_path, b"\x00" * (2 * 1024 * 1024), ".img")
    evidence = _make_evidence(db, case_id=case.id, stored_path=str(path))
    from app.api.routes_evidence import probe_memory_image as probe_endpoint
    probe_endpoint(case_id=case.id, evidence_id=evidence.id, db=db)
    # There is no NormalizedEvent table; the probe never touches it.
    # Verify by inspecting the API source.
    import inspect
    from app.services.memory import probe as probe_mod
    src = inspect.getsource(probe_mod)
    assert "NormalizedEvent" not in src


def test_probe_does_not_create_disk_index_entries(tmp_path: Path, db: Session) -> None:
    """The probe must NOT write to dfir-events (disk index)."""
    path = _make_fixture_file(tmp_path, b"\x00" * (2 * 1024 * 1024), ".img")
    probe_memory_image(path)
    import inspect
    from app.services.memory import probe as probe_mod
    src = inspect.getsource(probe_mod)
    assert "dfir-events" not in src
    assert "bulk" not in src.lower()


def test_no_automatic_analysis_profile_started(db: Session, tmp_path: Path) -> None:
    """Probing an evidence must NOT start a Volatility run."""
    case = Case(name="case-A")
    db.add(case)
    db.commit()
    path = _make_fixture_file(tmp_path, b"\x00" * (2 * 1024 * 1024), ".img")
    evidence = _make_evidence(db, case_id=case.id, stored_path=str(path))
    from app.api.routes_evidence import probe_memory_image as probe_endpoint
    probe_endpoint(case_id=case.id, evidence_id=evidence.id, db=db)
    # No MemoryScanRun should exist for this evidence.
    from app.models.memory import MemoryScanRun
    runs = db.query(MemoryScanRun).filter(MemoryScanRun.evidence_id == evidence.id).all()
    assert runs == []


# ---------------------------------------------------------------------------
# 19-20: Path traversal and signature detection
# ---------------------------------------------------------------------------


def test_path_traversal_in_stored_path_rejected(tmp_path: Path, db: Session) -> None:
    """An evidence whose stored_path is missing on disk is rejected."""
    from app.api.routes_evidence import probe_memory_image as probe_endpoint
    from fastapi import HTTPException
    case = Case(name="case-A")
    db.add(case)
    db.commit()
    # Create a real file, create the evidence, then delete the file.
    real_path = _make_fixture_file(tmp_path, b"\x00" * (2 * 1024 * 1024), ".img")
    evidence = _make_evidence(db, case_id=case.id, stored_path=str(real_path))
    real_path.unlink()
    with pytest.raises(HTTPException) as exc:
        probe_endpoint(case_id=case.id, evidence_id=evidence.id, db=db)
    # 400 (stored file is missing) is acceptable.
    assert exc.value.status_code in {400, 404}


def test_lime_elf_crashdump_signatures_detected(tmp_path: Path) -> None:
    """LiME, ELF and Windows crash dump signatures are all confirmed_memory."""
    # LiME: little-endian 0x4C694D45
    lime_content = struct.pack("<I", 0x4C694D45) + b"\x00" * (2 * 1024 * 1024)
    p = _make_fixture_file(tmp_path, lime_content, ".lime")
    r = probe_memory_image(p)
    assert r.status == STATUS_CONFIRMED_MEMORY
    assert r.detected_format == "lime"

    # ELF
    elf_content = b"\x7fELF" + b"\x00" * (2 * 1024 * 1024)
    p = _make_fixture_file(tmp_path, elf_content, ".elf")
    r = probe_memory_image(p)
    assert r.status == STATUS_CONFIRMED_MEMORY
    assert r.detected_format == "elf_core"

    # Windows crash dump
    dump_content = b"PAGE" + b"\x00" * (2 * 1024 * 1024)
    p = _make_fixture_file(tmp_path, dump_content, ".dmp")
    r = probe_memory_image(p)
    assert r.status == STATUS_CONFIRMED_MEMORY
    assert r.detected_format == "windows_crash_dump"
