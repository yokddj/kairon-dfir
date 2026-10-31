from __future__ import annotations

from pathlib import Path
import shutil
import subprocess
import zipfile

import pytest

from app.ingest import ad1_image
from app.ingest.encrypted_archive import ArchivePasswordError, check_zip_password, is_encrypted_zip
from app.services.evidence_container_prep import ContainerPrepError, hashed_source_path, prepare_upload_container, single_ad1_member

pytestmark = pytest.mark.skipif(shutil.which("7z") is None, reason="7-Zip is required to write encrypted ZIPs")


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


@pytest.mark.parametrize("aes", [False, True])
def test_password_checks(tmp_path, aes):
    archive = _encrypted_zip(_layout(tmp_path, "challenge.zip"), "infected", aes=aes)
    assert is_encrypted_zip(archive)
    with pytest.raises(ArchivePasswordError) as missing:
        check_zip_password(archive, None)
    assert missing.value.code == "archive_password_required"
    with pytest.raises(ArchivePasswordError) as wrong:
        check_zip_password(archive, "nope")
    assert wrong.value.code == "archive_password_invalid"
    check_zip_password(archive, "infected")


def test_plain_zip_is_processed_as_it_is(tmp_path):
    archive = _layout(tmp_path, "plain.zip")
    with zipfile.ZipFile(archive, "w") as handle:
        handle.writestr("C/Users/alice/NTUSER.DAT", b"regf")
    assert not is_encrypted_zip(archive)
    assert prepare_upload_container(archive, "00") == (archive, None)


def test_encrypted_zip_is_decrypted_into_the_working_container(tmp_path):
    archive = _encrypted_zip(_layout(tmp_path, "challenge.zip"), "infected", aes=True)
    working, repacked = prepare_upload_container(archive, "ab" * 32, archive_password="infected")
    source = archive.parent.parent / "source" / "challenge.zip"
    assert working == archive
    assert repacked == {"path": str(source), "sha256": "ab" * 32, "steps": [{"format": "encrypted_zip", "files": 2, "bytes": 69}]}
    assert is_encrypted_zip(source)
    assert not is_encrypted_zip(working)
    with zipfile.ZipFile(working) as handle:
        assert handle.read("challenge/notes.txt") == b"hello"
    assert "infected" not in str(repacked)
    assert hashed_source_path(type("E", (), {"metadata_json": {"repacked_from": repacked}, "stored_path": str(working)})()) == source


def test_encrypted_zip_without_password_is_refused(tmp_path):
    archive = _encrypted_zip(_layout(tmp_path, "challenge.zip"), "infected")
    with pytest.raises(ContainerPrepError) as exc_info:
        prepare_upload_container(archive, "00")
    assert exc_info.value.code == "archive_password_required"


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

    def fake_convert(image, zip_target, progress_cb=None, metadata_path=None):
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
