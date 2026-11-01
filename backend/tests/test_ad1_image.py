from __future__ import annotations

from datetime import UTC, datetime
import hashlib
import io
from pathlib import Path
from types import SimpleNamespace
import zipfile

import pytest

from app.ingest import ad1_image
from app.ingest.ad1_image import AD1ImageError, convert_ad1_to_zip, iter_ad1_files, open_ad1, rebase_parts
from app.ingest.velociraptor.zip_inventory import AD1EvidenceContainer, is_supported_archive_container, open_evidence_container


class _Entry:
    def __init__(self, name: str, *, children=None, data: bytes = b"", kind: str = "File", symlink: bool = False, broken: bool = False, mtime=None):
        self.name = name
        self._children = children
        self.data = data
        self.size = len(data)
        self.type = SimpleNamespace(name="Directory" if children is not None else kind)
        self._symlink = symlink
        self._broken = broken
        self.mtime = mtime or datetime(2025, 2, 15, 22, 0, 0, tzinfo=UTC)

    def is_dir(self) -> bool:
        return self._children is not None

    def is_file(self) -> bool:
        return self._children is None and self.type.name in {"File", "Unknown_File"}

    def is_symlink(self) -> bool:
        return self._symlink

    def iterdir(self):
        return iter(self._children or [])

    def open(self):
        if self._broken:
            raise ValueError("chunk table unreadable")
        return io.BytesIO(self.data)


def _image(name: str, *children):
    """A tree shaped like dissect's: the logical image name becomes root parts."""
    parts = [part for part in name.replace("\\", "/").split("/") if part]
    node = _Entry(parts[-1], children=list(children))
    for part in reversed(parts[:-1]):
        node = _Entry(part, children=[node])
    return SimpleNamespace(root=_Entry("/", children=[node]), logical_image=SimpleNamespace(name=name))


def _sample_image():
    return _image(
        "C:\\NONAME [NTFS]\\[root]\\Users\\alice",
        _Entry("NTUSER.DAT", data=b"regf" + b"\0" * 60),
        # FTK keeps an empty $I30 twin next to some files: the one with content wins.
        _Entry("ntuser.dat.LOG1", data=b""),
        _Entry("ntuser.dat.LOG1", data=b"log-bytes"),
        _Entry("old.txt", data=b"gone", kind="Deleted"),
        _Entry("link", data=b"reparse", symlink=True),
        _Entry("AppData", children=[_Entry("Local", children=[_Entry("broken.db", data=b"x" * 10, broken=True), _Entry("ok.db", data=b"sqlite")])]),
    )


@pytest.mark.parametrize(
    ("parts", "expected"),
    [
        (["C:", "NONAME [NTFS]", "[root]", "Users", "alice", "NTUSER.DAT"], ["C", "Users", "alice", "NTUSER.DAT"]),
        (["\\\\.\\PHYSICALDRIVE0", "Partition 2 [476GB]", "NONAME [NTFS]", "[root]", "Windows", "System32"], ["Windows", "System32"]),
        (["C:", "Users", "alice", "file.txt"], ["C", "Users", "alice", "file.txt"]),
        (["evidence", "notes.txt"], ["evidence", "notes.txt"]),
    ],
)
def test_rebase_parts_drops_the_volume_descriptor(parts, expected):
    assert rebase_parts(parts) == expected


def test_iter_ad1_files_skips_deleted_and_links_and_keeps_content_twin():
    files = dict(iter_ad1_files(_sample_image()))
    assert set(files) == {
        "C/Users/alice/NTUSER.DAT",
        "C/Users/alice/ntuser.dat.LOG1",
        "C/Users/alice/AppData/Local/broken.db",
        "C/Users/alice/AppData/Local/ok.db",
    }
    assert files["C/Users/alice/ntuser.dat.LOG1"].data == b"log-bytes"


def test_convert_ad1_to_zip_repacks_live_files_and_lists_unreadable_ones(tmp_path, monkeypatch):
    monkeypatch.setattr(ad1_image, "open_ad1", lambda path, **kwargs: _sample_image())
    target = tmp_path / "alice.zip"
    summary = convert_ad1_to_zip(tmp_path / "alice.ad1", target)
    with zipfile.ZipFile(target) as archive:
        names = set(archive.namelist())
        assert archive.read("C/Users/alice/ntuser.dat.LOG1") == b"log-bytes"
        assert archive.getinfo("C/Users/alice/AppData/Local/ok.db").date_time == (2025, 2, 15, 22, 0, 0)
    # A file whose content cannot be read leaves no truncated member behind.
    assert names == {"C/Users/alice/NTUSER.DAT", "C/Users/alice/ntuser.dat.LOG1", "C/Users/alice/AppData/Local/ok.db"}
    assert summary["files"] == 3
    assert summary["failed_count"] == 1
    assert summary["failed"][0]["path"] == "C/Users/alice/AppData/Local/broken.db"
    assert not (tmp_path / "alice.zip.partial").exists()


def test_convert_ad1_to_zip_passes_extra_segments_through_to_open_ad1(tmp_path, monkeypatch):
    seen = {}

    def fake_open_ad1(path, *, extra_segments=None, password=None):
        seen["path"] = path
        seen["extra_segments"] = extra_segments
        seen["password"] = password
        return _sample_image()

    monkeypatch.setattr(ad1_image, "open_ad1", fake_open_ad1)
    extras = [tmp_path / "alice.ad2", tmp_path / "alice.ad3"]
    convert_ad1_to_zip(tmp_path / "alice.ad1", tmp_path / "alice.zip", extra_segments=extras, password="secret")
    assert seen["extra_segments"] == extras
    assert seen["password"] == "secret"


def test_prepare_upload_container_moves_every_ad1_segment_to_source(tmp_path, monkeypatch):
    from app.ingest.ad1_image import convert_ad1_to_zip as real_convert
    from app.services.evidence_container_prep import prepare_upload_container

    original = tmp_path / "case" / "evidence" / "original"
    original.mkdir(parents=True)
    primary = original / "alice.ad1"
    primary.write_bytes(b"ADSEGMENTEDFILE primary bytes")
    extras = []
    for suffix in ("ad2", "ad3"):
        segment = original / f"alice.{suffix}"
        segment.write_bytes(f"{suffix} bytes".encode())
        extras.append(segment)

    seen = {}

    def fake_convert(source, target, progress_cb=None, *, metadata_path=None, password=None, extra_segments=None):
        seen["extra_segments"] = extra_segments
        with zipfile.ZipFile(target, "w") as handle:
            handle.writestr("C/Users/alice/NTUSER.DAT", b"regf")
        return {"format": "ad1", "image_name": "test", "files": 1, "bytes": 4, "failed": [], "failed_count": 0, "container_path": str(target)}

    monkeypatch.setattr("app.services.evidence_container_prep.convert_ad1_to_zip", fake_convert)
    working, repacked = prepare_upload_container(primary, "00", extra_segment_paths=extras)

    source_dir = original.parent / "source"
    assert (source_dir / "alice.ad1").read_bytes() == b"ADSEGMENTEDFILE primary bytes"
    assert (source_dir / "alice.ad2").read_bytes() == b"ad2 bytes"
    assert (source_dir / "alice.ad3").read_bytes() == b"ad3 bytes"
    # Original directory holds only the repacked working ZIP: segments do
    # not linger beside it once moved.
    assert sorted(path.name for path in original.iterdir()) == ["alice.zip"]
    assert seen["extra_segments"] == [source_dir / "alice.ad2", source_dir / "alice.ad3"]
    assert repacked["extra_segment_paths"] == [str(source_dir / "alice.ad2"), str(source_dir / "alice.ad3")]
    assert working == original / "alice.zip"


def test_ad1_is_an_archive_container(tmp_path, monkeypatch):
    image = tmp_path / "alice.ad1"
    image.write_bytes(b"ADSEGMENTEDFILE\0")
    assert is_supported_archive_container(image)
    container = open_evidence_container(image)
    assert isinstance(container, AD1EvidenceContainer)
    monkeypatch.setattr("app.ingest.velociraptor.zip_inventory.open_ad1", lambda path, **kwargs: _sample_image())
    entries = {entry.path: entry for entry in container.list_entries()}
    assert entries["C/Users/alice/AppData/Local/ok.db"].container_type == "ad1"
    with container.open_entry("C/Users/alice/AppData/Local/ok.db") as handle:
        assert handle.read() == b"sqlite"
    extracted = container.extract_entries(["C/Users/alice/NTUSER.DAT"], tmp_path / "out")
    assert extracted[0]["status"] == "extracted"
    assert Path(extracted[0]["local_path"]).read_bytes().startswith(b"regf")


def test_open_ad1_rejects_a_file_without_the_signature(tmp_path):
    fake = tmp_path / "renamed.ad1"
    fake.write_bytes(b"PK\x03\x04 not an ad1")
    with pytest.raises(AD1ImageError) as exc_info:
        open_ad1(fake)
    assert exc_info.value.code == "ad1_invalid"


def _segment_header(*, segment_number: int = 1, segment_count: int = 1) -> bytes:
    """A real ADSEGMENTEDFILE segment header (dissect.evidence's own
    cstruct), the only part of a segment open_ad1 reads itself before
    handing the path(s) to AD1 -- not a hand-reconstructed format guess."""
    from dissect.evidence.ad1.c_ad1 import c_ad1

    return c_ad1.SegmentedFileHeader(
        magic=b"ADSEGMENTEDFILE",
        unk1=1,
        unk2=2,
        segment_number=segment_number,
        segment_count=segment_count,
        segment_size=512,
        logical_image_offset=0,
        padding=b"\x00" * 468,
    ).dumps()


def test_open_ad1_without_enough_segments_names_how_many_are_missing(tmp_path):
    (tmp_path / "alice.ad1").write_bytes(_segment_header(segment_number=1, segment_count=3))
    with pytest.raises(AD1ImageError) as exc_info:
        open_ad1(tmp_path / "alice.ad1")
    assert exc_info.value.code == "ad1_multi_segment"
    assert "first of 3 AD1 segments" in exc_info.value.message
    assert "only 1 were uploaded" in exc_info.value.message


def test_open_ad1_with_every_segment_reaches_ad1(tmp_path, monkeypatch):
    (tmp_path / "alice.ad1").write_bytes(_segment_header(segment_number=1, segment_count=2))
    (tmp_path / "alice.ad2").write_bytes(_segment_header(segment_number=2, segment_count=2))
    seen = {}

    def fake_ad1(segments):
        seen["segments"] = segments
        return SimpleNamespace(is_adcrypt=lambda: False)

    monkeypatch.setattr("dissect.evidence.ad1.AD1", fake_ad1)
    image = open_ad1(tmp_path / "alice.ad1", extra_segments=[tmp_path / "alice.ad2"])
    assert seen["segments"] == [tmp_path / "alice.ad1", tmp_path / "alice.ad2"]
    assert image.is_adcrypt() is False


def _adcrypt_header() -> bytes:
    return b"ADCRYPT\x00" + b"\x00" * (512 - 8)


class _FakeAdcrypt:
    def __init__(self, *, correct_password: str):
        self._correct_password = correct_password
        self._unlocked = False

    def unlock(self, *, passphrase=None, private_key=None):
        if passphrase != self._correct_password:
            raise ValueError("Unable to unlock: HMAC verification of passphrase failed")
        self._unlocked = True


class _FakeSegment:
    def __init__(self, segment_count: int):
        self.header = SimpleNamespace(segment_count=segment_count)


class _FakeAdcryptAd1:
    """Stands in for dissect.evidence.ad1.AD1 wrapping an ADCRYPT container:
    enough of its surface for open_ad1's ADCRYPT branch (is_adcrypt,
    .adcrypt.unlock, .segment(0).header.segment_count, ._open_ad1)."""

    def __init__(self, segments, *, total_segment_count: int, correct_password: str):
        self.fh = segments
        self.adcrypt = _FakeAdcrypt(correct_password=correct_password)
        self._total_segment_count = total_segment_count
        self._segments = {}
        self._segment_lru = []
        self.opened = False

    def is_adcrypt(self):
        return True

    def segment(self, _idx):
        return _FakeSegment(self._total_segment_count)

    def _open_ad1(self):
        self.opened = True


def test_open_ad1_adcrypt_requires_a_password(tmp_path, monkeypatch):
    (tmp_path / "enc.ad1").write_bytes(_adcrypt_header())
    monkeypatch.setattr(
        "dissect.evidence.ad1.AD1",
        lambda segments: _FakeAdcryptAd1(segments, total_segment_count=1, correct_password="secret"),
    )
    with pytest.raises(AD1ImageError) as exc_info:
        open_ad1(tmp_path / "enc.ad1")
    assert exc_info.value.code == "ad1_password_required"
    assert "ADCRYPT" in exc_info.value.message


def test_open_ad1_adcrypt_rejects_a_wrong_password(tmp_path, monkeypatch):
    (tmp_path / "enc.ad1").write_bytes(_adcrypt_header())
    monkeypatch.setattr(
        "dissect.evidence.ad1.AD1",
        lambda segments: _FakeAdcryptAd1(segments, total_segment_count=1, correct_password="secret"),
    )
    with pytest.raises(AD1ImageError) as exc_info:
        open_ad1(tmp_path / "enc.ad1", password="wrong")
    assert exc_info.value.code == "ad1_password_invalid"


def test_open_ad1_adcrypt_with_the_right_password_but_missing_segments(tmp_path, monkeypatch):
    # A correct password unlocks the container (reads only the first
    # segment's header), but the image itself is split across more segments
    # than were uploaded -- this must read as ad1_multi_segment, not crash
    # trying to read past the end of the one segment present.
    (tmp_path / "enc.ad1").write_bytes(_adcrypt_header())
    monkeypatch.setattr(
        "dissect.evidence.ad1.AD1",
        lambda segments: _FakeAdcryptAd1(segments, total_segment_count=13, correct_password="secret"),
    )
    with pytest.raises(AD1ImageError) as exc_info:
        open_ad1(tmp_path / "enc.ad1", password="secret")
    assert exc_info.value.code == "ad1_multi_segment"
    assert "first of 13 AD1 segments" in exc_info.value.message


def test_open_ad1_adcrypt_with_every_segment_unlocks_and_opens(tmp_path, monkeypatch):
    (tmp_path / "enc.ad1").write_bytes(_adcrypt_header())
    fake_holder = {}

    def make_fake(segments):
        fake = _FakeAdcryptAd1(segments, total_segment_count=2, correct_password="secret")
        fake_holder["instance"] = fake
        return fake

    monkeypatch.setattr("dissect.evidence.ad1.AD1", make_fake)
    image = open_ad1(tmp_path / "enc.ad1", extra_segments=[tmp_path / "enc.ad2"], password="secret")
    assert image.opened is True
    assert fake_holder["instance"].adcrypt._unlocked is True


def test_is_encrypted_ad1_detects_the_adcrypt_magic(tmp_path):
    from app.ingest.ad1_image import is_encrypted_ad1

    plain = tmp_path / "plain.ad1"
    plain.write_bytes(_segment_header())
    assert is_encrypted_ad1(plain) is False

    encrypted = tmp_path / "enc.ad1"
    encrypted.write_bytes(_adcrypt_header())
    assert is_encrypted_ad1(encrypted) is True

    # Not an AD1 at all (wrong extension): never flagged, regardless of content.
    wrong_suffix = tmp_path / "enc.bin"
    wrong_suffix.write_bytes(_adcrypt_header())
    assert is_encrypted_ad1(wrong_suffix) is False


def test_has_ad1_signature_recognizes_both_plain_and_adcrypt_headers(tmp_path):
    from app.ingest.ad1_image import has_ad1_signature

    plain = tmp_path / "plain.ad1"
    plain.write_bytes(_segment_header())
    assert has_ad1_signature(plain) is True

    encrypted = tmp_path / "enc.ad1"
    encrypted.write_bytes(_adcrypt_header())
    assert has_ad1_signature(encrypted) is True


def test_find_ad1_segments_orders_by_suffix_number(tmp_path):
    from app.ingest.ad1_image import find_ad1_segments

    (tmp_path / "image.ad1").write_bytes(b"1")
    (tmp_path / "image.ad10").write_bytes(b"2")
    (tmp_path / "image.ad2").write_bytes(b"3")
    (tmp_path / "image.ad1.txt").write_bytes(b"not a segment")
    (tmp_path / "other.ad1").write_bytes(b"not the same image")

    segments = find_ad1_segments(tmp_path / "image.ad1")
    assert [path.name for path in segments] == ["image.ad1", "image.ad2", "image.ad10"]


def test_integrity_check_hashes_the_ad1_not_the_repack(tmp_path):
    from sqlalchemy import create_engine
    from sqlalchemy.orm import sessionmaker

    from app.core.database import Base
    from app.models.case import Case
    from app.models.evidence import Evidence, EvidenceIntegrityStatus, EvidenceStorageMode, EvidenceType, IngestStatus
    from app.services.evidence_integrity import verify_evidence_integrity

    image = tmp_path / "alice.ad1"
    image.write_bytes(b"ADSEGMENTEDFILE original bytes")
    repack = tmp_path / "alice.zip"
    repack.write_bytes(b"PK repacked")
    engine = create_engine("sqlite:///:memory:", future=True)
    Base.metadata.create_all(engine)
    db = sessionmaker(bind=engine, future=True)()
    db.add(Case(id="aaaaaaaa-1111-4111-8111-aaaaaaaaaaaa", name="Case", description=None))
    evidence = Evidence(
        id="bbbbbbbb-2222-4222-8222-bbbbbbbbbbbb",
        case_id="aaaaaaaa-1111-4111-8111-aaaaaaaaaaaa",
        original_filename="alice.ad1",
        stored_path=str(repack),
        original_path=str(image),
        storage_mode=EvidenceStorageMode.uploaded,
        is_external=False,
        copy_to_storage=True,
        evidence_type=EvidenceType.velociraptor_zip,
        sha256=hashlib.sha256(image.read_bytes()).hexdigest(),
        size_bytes=image.stat().st_size,
        ingest_status=IngestStatus.pending,
        path_validation={},
        ingest_source={},
        metadata_json={"repacked_from": {"path": str(image)}},
        error_log={},
    )
    db.add(evidence)
    db.commit()
    verify_evidence_integrity(db, evidence)
    assert evidence.integrity_status == EvidenceIntegrityStatus.verified


class _FakeSession:
    def __init__(self, case):
        self.case = case
        self.evidence = None

    def get(self, model, key):
        from app.models.case import Case

        return self.case if model is Case and key == self.case.id else None

    def add(self, value):
        self.evidence = value

    def commit(self):
        return None

    def refresh(self, _value):
        return None


def _upload_ad1(monkeypatch, tmp_path, opener):
    from fastapi import UploadFile

    from app.api import routes_evidence
    from app.core.config import get_settings
    from app.core.storage import build_evidence_root
    from app.models.case import Case

    monkeypatch.setattr(get_settings(), "backend_data_dir", tmp_path / "data")
    stored = build_evidence_root("case-1", "ev-1") / "original" / "alice.ad1"
    stored.parent.mkdir(parents=True, exist_ok=True)
    stored.write_bytes(b"ADSEGMENTEDFILE image bytes")
    monkeypatch.setattr(ad1_image, "open_ad1", opener)
    monkeypatch.setattr(routes_evidence, "save_upload", lambda case_id, file: ("ev-1", stored, stored.stat().st_size, "ab" * 32))
    monkeypatch.setattr(routes_evidence, "find_duplicate_evidence", lambda *args, **kwargs: None)
    monkeypatch.setattr(routes_evidence, "log_activity", lambda *args, **kwargs: None)
    monkeypatch.setattr(routes_evidence, "enqueue_ingest", lambda *_args, **_kwargs: None)
    db = _FakeSession(Case(id="case-1", name="Case 1"))
    upload = UploadFile(filename="alice.ad1", file=SimpleNamespace())
    return stored, routes_evidence._upload_evidence_impl("case-1", upload, False, None, "raw", "single_file", db)


def test_ad1_upload_registers_the_zip_repack_as_a_raw_collection(monkeypatch, tmp_path):
    from app.models.evidence import EvidenceType

    stored, evidence = _upload_ad1(monkeypatch, tmp_path, lambda path, **kwargs: _sample_image())
    source = stored.parent.parent / "source" / "alice.ad1"
    assert evidence.original_path == str(source)
    assert source.read_bytes().startswith(b"ADSEGMENTEDFILE")
    assert evidence.stored_path == str(stored.with_name("alice.zip"))
    assert evidence.sha256 == "ab" * 32
    assert evidence.evidence_type == EvidenceType.velociraptor_zip
    assert evidence.metadata_json["repacked_from"]["path"] == str(source)
    assert evidence.metadata_json["repacked_from"]["steps"][-1]["files"] == 3
    assert "C/Users/alice/NTUSER.DAT" in {entry["path"] for entry in evidence.metadata_json["folder_entries"]}


def test_unreadable_ad1_upload_is_rejected_with_its_reason(monkeypatch, tmp_path):
    from fastapi import HTTPException

    def encrypted(_path, **_kwargs):
        raise AD1ImageError("ad1_encrypted", "alice.ad1 is an encrypted (ADCRYPT) AD1 image.")

    with pytest.raises(HTTPException) as exc_info:
        _upload_ad1(monkeypatch, tmp_path, encrypted)
    assert exc_info.value.status_code == 400
    assert exc_info.value.detail["code"] == "ad1_encrypted"
    assert not (tmp_path / "data" / "case-1").exists() or not any((tmp_path / "data" / "case-1").rglob("*.ad1"))


def test_preflight_flags_a_password_protected_adcrypt_ad1(tmp_path):
    from app.services.evidence_preflight import run_preflight

    archive = tmp_path / "encrypted.ad1"
    archive.write_bytes(_adcrypt_header())
    (tmp_path / "scratch").mkdir()
    report = run_preflight(archive, token="t", original_filename="encrypted.ad1", declared_platform=None, tmp_dir=tmp_path / "scratch")
    assert report.classification.password_protected is True


def test_preflight_does_not_flag_a_plain_ad1_as_password_protected(tmp_path):
    from app.services.evidence_preflight import run_preflight

    archive = tmp_path / "plain.ad1"
    archive.write_bytes(_segment_header())
    (tmp_path / "scratch").mkdir()
    report = run_preflight(archive, token="t", original_filename="plain.ad1", declared_platform=None, tmp_dir=tmp_path / "scratch")
    assert report.classification.password_protected is False
