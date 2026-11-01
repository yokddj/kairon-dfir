from __future__ import annotations

from pathlib import Path
import shutil
import subprocess
import zipfile

import pytest

from app.ingest.encrypted_archive import ArchivePasswordError, check_archive_password, check_zip_password, is_encrypted_archive, is_encrypted_zip
from app.services.evidence_container_prep import ContainerPrepError, hashed_source_path, prepare_upload_container, single_ad1_member

HAS_7Z = shutil.which("7z") is not None
HAS_UNAR = shutil.which("unar") is not None and shutil.which("lsar") is not None

pytestmark = pytest.mark.skipif(not HAS_7Z, reason="7-Zip is required to write encrypted ZIPs and 7z archives")

FIXTURES = Path(__file__).parent / "fixtures" / "encrypted_archives"


def _layout(tmp_path: Path, name: str) -> Path:
    original = tmp_path / "case" / "evidence" / "original"
    original.mkdir(parents=True)
    return original / name


def _encrypted_zip(target: Path, password: str, *, aes: bool = False, files: dict[str, bytes] | None = None) -> Path:
    staging = target.parent.parent / "staging"
    for name, data in (files or {"challenge/C/Users/alice/NTUSER.DAT": b"regf" + b"\0" * 60, "challenge/notes.txt": b"hello"}).items():
        path = staging / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(data)
    args = ["7z", "a", "-tzip", f"-p{password}", str(target), "."]
    if aes:
        args.insert(3, "-mem=AES256")
    subprocess.run(args, cwd=staging, check=True, capture_output=True)
    shutil.rmtree(staging)
    return target


def _encrypted_seven_zip(target: Path, password: str, *, encrypted_header: bool = False, files: dict[str, bytes] | None = None) -> Path:
    staging = target.parent.parent / "staging"
    for name, data in (files or {"challenge/C/Users/alice/NTUSER.DAT": b"regf" + b"\0" * 60, "challenge/notes.txt": b"hello"}).items():
        path = staging / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(data)
    args = ["7z", "a", "-t7z", f"-p{password}"]
    if encrypted_header:
        args.append("-mhe=on")
    args += [str(target), "."]
    subprocess.run(args, cwd=staging, check=True, capture_output=True)
    shutil.rmtree(staging)
    return target


def _rar_fixture(tmp_path: Path, name: str, target_name: str) -> Path:
    """A real encrypted RAR fixture (see fixtures/encrypted_archives/README.txt),
    copied into the layout prepare_upload_container expects. Password is
    always "password"; members are stest1.txt and stest2.txt (2048 bytes
    each, plain text repeated)."""
    target = _layout(tmp_path, target_name)
    shutil.copy(FIXTURES / name, target)
    return target


@pytest.mark.parametrize("aes", [False, True])
def test_password_checks(tmp_path, aes):
    archive = _encrypted_zip(_layout(tmp_path, "challenge.zip"), "infected", aes=aes)
    assert is_encrypted_zip(archive)
    assert is_encrypted_archive(archive)
    with pytest.raises(ArchivePasswordError) as missing:
        check_zip_password(archive, None)
    assert missing.value.code == "archive_password_required"
    with pytest.raises(ArchivePasswordError) as wrong:
        check_zip_password(archive, "nope")
    assert wrong.value.code == "archive_password_invalid"
    check_zip_password(archive, "infected")


@pytest.mark.parametrize("encrypted_header", [False, True])
def test_seven_zip_password_checks(tmp_path, encrypted_header):
    archive = _encrypted_seven_zip(_layout(tmp_path, "challenge.7z"), "infected", encrypted_header=encrypted_header)
    assert is_encrypted_archive(archive)
    with pytest.raises(ArchivePasswordError) as missing:
        check_archive_password(archive, None)
    assert missing.value.code == "archive_password_required"
    with pytest.raises(ArchivePasswordError) as wrong:
        check_archive_password(archive, "nope")
    assert wrong.value.code == "archive_password_invalid"
    check_archive_password(archive, "infected")


@pytest.mark.skipif(not HAS_UNAR, reason="unar is required to decrypt RAR archives")
@pytest.mark.parametrize("fixture_name", ["rar5-psw.rar", "rar5-hpsw.rar"])
def test_rar_password_checks(tmp_path, fixture_name):
    archive = _rar_fixture(tmp_path, fixture_name, "challenge.rar")
    assert is_encrypted_archive(archive)
    with pytest.raises(ArchivePasswordError) as missing:
        check_archive_password(archive, None)
    assert missing.value.code == "archive_password_required"
    with pytest.raises(ArchivePasswordError) as wrong:
        check_archive_password(archive, "nope")
    assert wrong.value.code == "archive_password_invalid"
    check_archive_password(archive, "password")


def test_plain_zip_is_processed_as_it_is(tmp_path):
    archive = _layout(tmp_path, "plain.zip")
    with zipfile.ZipFile(archive, "w") as handle:
        handle.writestr("C/Users/alice/NTUSER.DAT", b"regf")
    assert not is_encrypted_zip(archive)
    assert not is_encrypted_archive(archive)
    assert prepare_upload_container(archive, "00") == (archive, None)


def test_plain_seven_zip_is_not_flagged_encrypted(tmp_path):
    archive = _layout(tmp_path, "plain.7z")
    (archive.parent / "y.txt").write_bytes(b"hi")
    subprocess.run(["7z", "a", "-t7z", str(archive), str(archive.parent / "y.txt")], check=True, capture_output=True)
    assert not is_encrypted_archive(archive)


def test_encrypted_zip_is_decrypted_into_the_working_container(tmp_path):
    archive = _encrypted_zip(_layout(tmp_path, "challenge.zip"), "infected", aes=True)
    working, repacked = prepare_upload_container(archive, "ab" * 32, archive_password="infected")
    source = archive.parent.parent / "source" / "challenge.zip"
    assert working == archive
    assert repacked == {"path": str(source), "extra_segment_paths": [], "sha256": "ab" * 32, "steps": [{"format": "encrypted_zip", "files": 2, "bytes": 69}]}
    assert is_encrypted_zip(source)
    assert not is_encrypted_zip(working)
    with zipfile.ZipFile(working) as handle:
        assert handle.read("challenge/notes.txt") == b"hello"
    assert "infected" not in str(repacked)
    assert hashed_source_path(type("E", (), {"metadata_json": {"repacked_from": repacked}, "stored_path": str(working)})()) == source


def test_encrypted_seven_zip_is_decrypted_into_the_working_container(tmp_path):
    archive = _encrypted_seven_zip(_layout(tmp_path, "challenge.7z"), "infected")
    working, repacked = prepare_upload_container(archive, "ab" * 32, archive_password="infected")
    source = archive.parent.parent / "source" / "challenge.7z"
    # The working container is renamed to .zip: later steps (discovery,
    # extraction) only expect a plain ZIP, never an original-format file.
    assert working == archive.parent / "challenge.zip"
    assert repacked == {"path": str(source), "extra_segment_paths": [], "sha256": "ab" * 32, "steps": [{"format": "encrypted_7z", "files": 2, "bytes": 69}]}
    assert not is_encrypted_archive(working)
    with zipfile.ZipFile(working) as handle:
        assert handle.read("challenge/notes.txt") == b"hello"
    assert "infected" not in str(repacked)


@pytest.mark.skipif(not HAS_UNAR, reason="unar is required to decrypt RAR archives")
def test_encrypted_rar_is_decrypted_into_the_working_container(tmp_path):
    archive = _rar_fixture(tmp_path, "rar5-psw.rar", "challenge.rar")
    working, repacked = prepare_upload_container(archive, "ab" * 32, archive_password="password")
    source = archive.parent.parent / "source" / "challenge.rar"
    assert working == archive.parent / "challenge.zip"
    assert repacked["path"] == str(source)
    assert repacked["steps"] == [{"format": "encrypted_rar", "files": 2, "bytes": 4096}]
    assert not is_encrypted_archive(working)
    with zipfile.ZipFile(working) as handle:
        assert sorted(handle.namelist()) == ["stest1.txt", "stest2.txt"]
    assert "password" not in str(repacked)


def test_encrypted_zip_without_password_is_refused(tmp_path):
    archive = _encrypted_zip(_layout(tmp_path, "challenge.zip"), "infected")
    with pytest.raises(ContainerPrepError) as exc_info:
        prepare_upload_container(archive, "00")
    assert exc_info.value.code == "archive_password_required"


@pytest.mark.skipif(not HAS_UNAR, reason="unar is required to decrypt RAR archives")
def test_encrypted_rar_with_wrong_password_is_refused(tmp_path):
    archive = _rar_fixture(tmp_path, "rar5-psw.rar", "challenge.rar")
    with pytest.raises(ContainerPrepError) as exc_info:
        prepare_upload_container(archive, "00", archive_password="wrong")
    assert exc_info.value.code == "archive_password_invalid"


@pytest.mark.parametrize("encrypted", [False, True])
def test_zip_holding_one_ad1_is_unwrapped_and_repacked(tmp_path, monkeypatch, encrypted):
    files = {"Evidence/alice.ad1": b"ADSEGMENTEDFILE image", "__MACOSX/Evidence/._alice.ad1": b"meta"}
    target = _layout(tmp_path, "challenge.zip")
    if encrypted:
        archive = _encrypted_zip(target, "infected", files=files)
    else:
        archive = target
        with zipfile.ZipFile(archive, "w") as handle:
            for name, data in files.items():
                handle.writestr(name, data)
    assert single_ad1_member(archive) == "Evidence/alice.ad1"
    seen = {}

    def fake_convert(image, zip_target, progress_cb=None, metadata_path=None, password=None, extra_segments=None):
        seen["image"] = image.read_bytes()
        with zipfile.ZipFile(zip_target, "w") as handle:
            handle.writestr("C/Users/alice/NTUSER.DAT", b"regf")
        return {"format": "ad1", "files": 1, "bytes": 4}

    monkeypatch.setattr("app.services.evidence_container_prep.convert_ad1_to_zip", fake_convert)
    working, repacked = prepare_upload_container(archive, "00", archive_password="infected" if encrypted else None)
    original = archive.parent
    assert seen["image"] == b"ADSEGMENTEDFILE image"
    assert working == original / "alice.zip"
    # Only the working ZIP is left where the raw backends look for archives.
    assert sorted(path.name for path in original.iterdir()) == ["alice.zip"]
    assert repacked["path"] == str(original.parent / "source" / "challenge.zip")
    assert [step["format"] for step in repacked["steps"]] == (["encrypted_zip"] if encrypted else []) + ["zip_member", "ad1"]


def test_preflight_flags_a_password_protected_zip(tmp_path):
    from app.services.evidence_preflight import run_preflight

    archive = _encrypted_zip(_layout(tmp_path, "challenge.zip"), "infected")
    (tmp_path / "scratch").mkdir()
    report = run_preflight(archive, token="t", original_filename="challenge.zip", declared_platform=None, tmp_dir=tmp_path / "scratch")
    assert report.classification.password_protected is True
    assert any("password" in warning.message.lower() for warning in report.classification.warnings)


def test_preflight_flags_a_password_protected_seven_zip(tmp_path):
    from app.services.evidence_preflight import run_preflight

    archive = _encrypted_seven_zip(_layout(tmp_path, "challenge.7z"), "infected")
    (tmp_path / "scratch").mkdir()
    report = run_preflight(archive, token="t", original_filename="challenge.7z", declared_platform=None, tmp_dir=tmp_path / "scratch")
    assert report.classification.password_protected is True


@pytest.mark.skipif(not HAS_UNAR, reason="unar is required to decrypt RAR archives")
def test_preflight_flags_a_password_protected_rar(tmp_path):
    from app.services.evidence_preflight import run_preflight

    archive = _rar_fixture(tmp_path, "rar5-hpsw.rar", "challenge.rar")
    (tmp_path / "scratch").mkdir()
    report = run_preflight(archive, token="t", original_filename="challenge.rar", declared_platform=None, tmp_dir=tmp_path / "scratch")
    assert report.classification.password_protected is True
