"""Turn an uploaded file into the container Kairon processes.

Most uploads are processed as they are. Three are rewritten once, at
registration, into a plain ZIP in ``original/`` that every later step
(discovery, selected extraction, the raw backends that call 7-Zip on the
original archive) reads like any uploaded collection:

- a password-protected ZIP, decrypted with the password the analyst gave;
- a ZIP whose only file is an AD1 image (how CTF and training images are
  usually shipped), unwrapped;
- an AD1 logical image, repacked (app.ingest.ad1_image).

The uploaded file is moved to ``source/`` beside ``original/``: it keeps the
evidence hash, the integrity check verifies it, and nothing scans it for
artifacts (an encrypted copy there would make 7-Zip fail on every member).
``metadata_json.repacked_from`` records it and each step taken.
"""

from __future__ import annotations

from pathlib import Path
import shutil
import tempfile

from app.core.config import get_settings
from app.ingest.ad1_image import AD1_SUFFIX, AD1ImageError, convert_ad1_to_zip, has_ad1_signature
from app.ingest.encrypted_archive import ArchivePasswordError, decrypt_zip, is_encrypted_zip, move_aside, password_required_message

SOURCE_DIR_NAME = "source"


def ad1_metadata_path(evidence_root: Path) -> Path:
    """FTK's per-file metadata for an AD1 upload (app.ingest.ad1_image.write_ad1_metadata)."""
    return Path(evidence_root) / "derived" / "ad1_metadata.json"


class ContainerPrepError(RuntimeError):
    def __init__(self, code: str, message: str):
        super().__init__(message)
        self.code = code
        self.message = message


def single_ad1_member(zip_path: Path) -> str | None:
    """The member name when a ZIP holds exactly one file and it is an AD1
    (macOS and Windows metadata entries do not count)."""
    from app.ingest.velociraptor.zip_inventory import ZipEvidenceContainer

    if Path(zip_path).suffix.lower() != ".zip":
        return None
    try:
        entries = [entry for entry in ZipEvidenceContainer(zip_path).list_entries() if not entry.is_dir and not entry.ignored]
    except Exception:  # noqa: BLE001
        return None
    if len(entries) == 1 and Path(entries[0].path).suffix.lower() == AD1_SUFFIX:
        return entries[0].path
    return None


def needs_preparation(path: Path) -> bool:
    path = Path(path)
    if path.suffix.lower() == AD1_SUFFIX:
        return has_ad1_signature(path)
    return is_encrypted_zip(path) or single_ad1_member(path) is not None


def prepare_upload_container(stored_path: Path, sha256: str | None, *, archive_password: str | None = None) -> tuple[Path, dict | None]:
    """Returns the working container and the ``repacked_from`` record, or
    ``(stored_path, None)`` when the upload is processed as it is."""
    stored_path = Path(stored_path)
    if not needs_preparation(stored_path):
        return stored_path, None
    original_dir = stored_path.parent
    source_dir = original_dir.parent / SOURCE_DIR_NAME
    source = move_aside(stored_path, source_dir)
    working = source
    steps: list[dict] = []
    try:
        if is_encrypted_zip(working):
            if not archive_password:
                raise ContainerPrepError("archive_password_required", password_required_message(source.name))
            decrypted = original_dir / source.name
            steps.append(decrypt_zip(working, archive_password, decrypted))
            working = decrypted
        member = single_ad1_member(working)
        if member:
            working = _unwrap_member(working, member, original_dir, discard_container=working != source)
            steps.append({"format": "zip_member", "member": member})
        if working.suffix.lower() == AD1_SUFFIX and has_ad1_signature(working):
            image = working
            working = original_dir / f"{image.stem}.zip"
            summary = convert_ad1_to_zip(image, working, metadata_path=ad1_metadata_path(original_dir.parent))
            if image != source:
                image.unlink(missing_ok=True)
            if not summary["files"]:
                raise ContainerPrepError("ad1_empty", f"{image.name} contains no readable files.")
            steps.append(summary)
    except ArchivePasswordError as exc:
        raise ContainerPrepError(exc.code, exc.message) from exc
    except AD1ImageError as exc:
        raise ContainerPrepError(exc.code, exc.message) from exc
    return working, {"path": str(source), "sha256": sha256, "steps": steps}


def _unwrap_member(container: Path, member: str, original_dir: Path, *, discard_container: bool) -> Path:
    from app.ingest.velociraptor.zip_inventory import ZipEvidenceContainer

    with tempfile.TemporaryDirectory(dir=get_settings().backend_temp_dir) as scratch:
        extracted = ZipEvidenceContainer(container).extract_entry(member, Path(scratch))
        target = original_dir / Path(member).name
        shutil.move(str(extracted), target)
    if discard_container:
        container.unlink(missing_ok=True)
    return target


def hashed_source_path(evidence) -> Path:
    """The file the evidence hash belongs to: the upload itself, or the
    original a repack was made from."""
    repacked = (getattr(evidence, "metadata_json", None) or {}).get("repacked_from") or {}
    return Path(str(repacked["path"])) if repacked.get("path") else Path(evidence.stored_path)
