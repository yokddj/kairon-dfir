"""VMware companion files (.vmsn / .vmss) for memory Evidence.

Volatility 3's VMware layer stacker (``volatility3/framework/layers/
vmware.py``, ``VmwareStacker.stack()``) discovers snapshot metadata purely
by string manipulation on the primary ``.vmem``'s own resolved location:
strip the trailing ``.vmem`` and try ``.vmss`` first, then ``.vmsn`` --
same directory, same basename, no CLI flag, no argv change. Confirmed
against the installed volatility3 package source, not assumed. Because
Kairon renames every uploaded memory dump to a fixed canonical basename
(``memory-image<ext>``, see ``app.core.storage.save_memory_upload``), a
companion is only discoverable if it is materialized under that SAME
canonical basename with the extension swapped -- never under the
filename the operator originally uploaded.

The memory-worker's evidence mount is read-only (``docker-compose.yml``,
``/app/data/evidence:ro``) with a read-only rootfs, so this module is only
ever exercised by the backend API process, which mounts evidence storage
read-write. The worker only ever *reads* what this module writes.
"""
from __future__ import annotations

import hashlib
import os
import shutil
from dataclasses import dataclass
from pathlib import Path
from typing import Any
from uuid import uuid4

from sqlalchemy.orm import Session

from app.core.config import get_settings
from app.core.database import utc_now_naive
from app.core.storage import safe_display_filename
from app.models.evidence import Evidence, EvidenceCompanionFile, EvidenceCustodyEventType, EvidenceType
from app.services.evidence_integrity import record_evidence_event
from app.services.memory.evidence_access import MemoryStorageAccessError, resolve_memory_evidence_path, secure_uploaded_memory_permissions


# Volatility tries ``.vmss`` before ``.vmsn`` -- see this module's
# docstring. Kept here (not just in prose) so a future caller that needs
# the precedence order programmatically does not have to re-derive it.
VMWARE_COMPANION_PRECEDENCE: tuple[str, ...] = ("vmware_vmss", "vmware_vmsn")

COMPANION_TYPE_BY_EXTENSION: dict[str, str] = {
    ".vmsn": "vmware_vmsn",
    ".vmss": "vmware_vmss",
}

_FREE_SPACE_CHUNK_SIZE = 1024 * 1024


class EvidenceCompanionError(ValueError):
    """Structured validation/operational error for companion attach/delete."""

    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code
        self.message = message


@dataclass(frozen=True)
class StagedCompanionUpload:
    """A companion file already streamed to a private staging path.

    Callers (the API route) are responsible for producing this -- this
    module never reads directly from an ``UploadFile``/network stream, so
    the validation and materialization logic below has no framework
    dependency and no partial-read state to reason about.
    """

    path: Path
    original_filename: str


def primary_memory_image_path(evidence: Evidence, *, settings: Any | None = None) -> Path:
    """Resolve the canonical, security-validated path of the primary
    memory dump this evidence's companion must sit beside.

    Reuses ``resolve_memory_evidence_path`` -- the same symlink-rejecting,
    storage-root-containing resolver the analysis pipeline itself uses --
    rather than re-deriving the path, so a companion can never be attached
    to a path the rest of the system would refuse to treat as evidence.
    """
    settings = settings or get_settings()
    if evidence.evidence_type != EvidenceType.memory_dump:
        raise EvidenceCompanionError(
            "EVIDENCE_NOT_MEMORY_DUMP",
            "VMware companion files can only be attached to memory_dump evidence.",
        )
    try:
        primary_path = resolve_memory_evidence_path(evidence, settings=settings)
    except MemoryStorageAccessError as exc:
        raise EvidenceCompanionError(exc.code, exc.message) from exc
    if primary_path.suffix.lower() != ".vmem":
        raise EvidenceCompanionError(
            "PRIMARY_NOT_VMEM",
            "This evidence's primary file is not a .vmem image. Volatility's VMware "
            "layer stacker only looks for a snapshot companion next to a .vmem file "
            "(it matches purely on the '.vmem' suffix of the primary file's own path), "
            "so a companion attached here would never be discovered.",
        )
    return primary_path


def companion_target_path(primary_path: Path, companion_type: str) -> Path:
    """The exact on-disk path Volatility will look for.

    ``VmwareStacker`` strips ``.vmem`` and appends ``.vmss``/``.vmsn`` to
    the primary's own resolved path -- same directory, same basename.
    ``Path.with_suffix`` performs the identical basename-preserving
    extension swap.
    """
    extension = {"vmware_vmss": ".vmss", "vmware_vmsn": ".vmsn"}.get(companion_type)
    if extension is None:
        raise EvidenceCompanionError("UNSUPPORTED_COMPANION_TYPE", f"Unsupported companion type: {companion_type!r}")
    return primary_path.with_suffix(extension)


def get_evidence_companion_status(db: Session, evidence_id: str) -> dict[str, Any]:
    """Read-only status summary for a wizard/UI to consume in a later phase.

    No UI/formatting logic here -- callers decide how to present this.
    """
    row = _active_companion(db, evidence_id)
    if row is None:
        return {
            "has_vmware_companion": False,
            "companion_id": None,
            "companion_type": None,
            "original_filename": None,
            "sha256": None,
            "size_bytes": None,
        }
    return {
        "has_vmware_companion": True,
        "companion_id": row.id,
        "companion_type": row.companion_type,
        "original_filename": row.original_filename,
        "sha256": row.sha256,
        "size_bytes": row.size_bytes,
    }


def list_evidence_companions(db: Session, evidence_id: str) -> list[EvidenceCompanionFile]:
    return (
        db.query(EvidenceCompanionFile)
        .filter(EvidenceCompanionFile.evidence_id == evidence_id)
        .order_by(EvidenceCompanionFile.created_at.desc())
        .all()
    )


def attach_vmware_companion(
    db: Session,
    evidence: Evidence,
    staged: StagedCompanionUpload,
    *,
    source_method: str = "manual_upload",
    actor_user_id: str | None = None,
    settings: Any | None = None,
) -> EvidenceCompanionFile:
    """Validate and materialize a VMware companion for ``evidence``.

    Order (see module docstring for why): validate primary + type ->
    validate upload (symlink/size/not-empty) -> hash -> reject if it is a
    byte-for-byte copy of the primary -> derive the canonical internal
    path from the primary's own canonical path -> write atomically
    (temp file in the same directory, fsync, ``os.replace``) -> harden
    permissions for the read-only worker -> upsert the DB row and record
    a custody event in the same transaction -> only once that commits,
    remove a stale file left behind by a type change (e.g. replacing a
    .vmss with a .vmsn). If the DB step fails, the just-written file is
    removed so no orphaned file is left claiming a companion that was
    never actually persisted.
    """
    settings = settings or get_settings()
    primary_path = primary_memory_image_path(evidence, settings=settings)

    original_extension = Path(staged.original_filename).suffix.lower()
    companion_type = COMPANION_TYPE_BY_EXTENSION.get(original_extension)
    if companion_type is None:
        raise EvidenceCompanionError(
            "UNSUPPORTED_COMPANION_TYPE",
            "Only .vmsn and .vmss files are accepted as VMware companions.",
        )

    _validate_staged_upload(staged.path, settings=settings)
    sha256, size_bytes = _hash_file(staged.path)
    if evidence.sha256 and sha256 == evidence.sha256:
        raise EvidenceCompanionError(
            "COMPANION_MATCHES_PRIMARY",
            "The uploaded file is byte-for-byte identical to the primary evidence file "
            "and was rejected -- a companion must never replace the primary dump.",
        )

    target_path = companion_target_path(primary_path, companion_type)
    if target_path.resolve() == primary_path.resolve():
        # Cannot happen given the extension allow-list above (.vmem never
        # maps to a companion type), but this is exactly the kind of
        # "never substitute the primary dump" invariant worth asserting
        # explicitly rather than trusting the allow-list alone.
        raise EvidenceCompanionError("REFUSED_PRIMARY_OVERWRITE", "Refusing to write a companion over the primary evidence file.")

    _assert_free_space(target_path.parent, size_bytes, settings=settings)

    existing = _active_companion(db, evidence.id)
    stale_path_to_remove: Path | None = None
    same_path_overwrite = False
    if existing is not None:
        existing_abs = settings.backend_data_dir / existing.relative_path
        if existing_abs.resolve() == target_path.resolve():
            same_path_overwrite = True
        else:
            stale_path_to_remove = existing_abs

    # In-place replacement (same type re-uploaded) overwrites the only
    # copy of the previous companion's bytes. Keep a same-directory
    # backup until the DB commit below actually succeeds, so a late DB
    # failure can restore the previous file instead of leaving disk (new
    # bytes) and DB (rolled back to the old row) describing different
    # content for the same path.
    backup_path: Path | None = None
    if same_path_overwrite:
        backup_path = target_path.parent / f".{uuid4().hex}.companion.bak"
        shutil.copyfile(target_path, backup_path, follow_symlinks=False)

    def _undo_write() -> None:
        if backup_path is not None:
            os.replace(backup_path, target_path)
        else:
            # Either a brand-new companion or a type change: the file
            # just written is not (yet) reflected by any committed DB
            # row, and any previous companion (a different path) was
            # never touched, so simply removing it restores the
            # pre-call state exactly.
            target_path.unlink(missing_ok=True)

    tmp_path = target_path.parent / f".{uuid4().hex}.companion.tmp"
    try:
        with staged.path.open("rb") as source, tmp_path.open("xb") as destination:
            shutil.copyfileobj(source, destination, length=1024 * 1024)
            destination.flush()
            os.fsync(destination.fileno())
        os.replace(tmp_path, target_path)
    except Exception:
        tmp_path.unlink(missing_ok=True)
        if backup_path is not None:
            backup_path.unlink(missing_ok=True)
        raise

    try:
        secure_uploaded_memory_permissions(target_path, settings=settings)
    except (MemoryStorageAccessError, OSError) as exc:
        _undo_write()
        if backup_path is not None:
            backup_path.unlink(missing_ok=True)
        raise EvidenceCompanionError(
            "COMPANION_PERMISSION_FAILED",
            "The companion was written but secure worker-readable permissions could not be applied.",
        ) from exc

    relative_path = str(target_path.relative_to(settings.backend_data_dir))
    safe_original = safe_display_filename(staged.original_filename)
    try:
        if existing is not None:
            existing.companion_type = companion_type
            existing.original_filename = safe_original
            existing.internal_filename = target_path.name
            existing.relative_path = relative_path
            existing.sha256 = sha256
            existing.size_bytes = size_bytes
            existing.source_method = source_method
            existing.uploaded_by_user_id = actor_user_id
            existing.updated_at = utc_now_naive()
            row = existing
        else:
            row = EvidenceCompanionFile(
                id=str(uuid4()),
                case_id=evidence.case_id,
                evidence_id=evidence.id,
                companion_type=companion_type,
                original_filename=safe_original,
                internal_filename=target_path.name,
                relative_path=relative_path,
                sha256=sha256,
                size_bytes=size_bytes,
                source_method=source_method,
                uploaded_by_user_id=actor_user_id,
                created_at=utc_now_naive(),
                updated_at=utc_now_naive(),
            )
            db.add(row)
        record_evidence_event(
            db,
            evidence,
            EvidenceCustodyEventType.companion_attached,
            f"VMware companion attached ({companion_type}).",
            actor_user_id=actor_user_id,
            details={
                "companion_type": companion_type,
                "original_filename": safe_original,
                "internal_filename": target_path.name,
                "sha256": sha256,
                "size_bytes": size_bytes,
                "source_method": source_method,
                "replaced_existing": existing is not None,
            },
        )
        db.commit()
    except Exception:
        db.rollback()
        _undo_write()
        if backup_path is not None:
            backup_path.unlink(missing_ok=True)
        raise

    if backup_path is not None:
        backup_path.unlink(missing_ok=True)
    if stale_path_to_remove is not None:
        # A type change (e.g. .vmss -> .vmsn) leaves the old file under a
        # DIFFERENT basename. It must be removed now that the DB reflects
        # only the new one: Volatility always prefers .vmss over .vmsn, so
        # a stale .vmss left behind after "replacing" it with a .vmsn
        # would keep silently winning.
        stale_path_to_remove.unlink(missing_ok=True)

    db.refresh(row)
    return row


def delete_evidence_companion(
    db: Session,
    evidence: Evidence,
    companion_id: str,
    *,
    actor_user_id: str | None = None,
    settings: Any | None = None,
) -> None:
    settings = settings or get_settings()
    row = (
        db.query(EvidenceCompanionFile)
        .filter(EvidenceCompanionFile.id == companion_id, EvidenceCompanionFile.evidence_id == evidence.id)
        .one_or_none()
    )
    if row is None:
        raise EvidenceCompanionError("COMPANION_NOT_FOUND", "VMware companion was not found for this evidence.")

    # Derived directly from the injected ``settings`` (not
    # ``app.core.storage.build_evidence_root``, which is hardwired to that
    # module's own global settings instance) so this stays correctly
    # testable and never resolves against the wrong storage root.
    evidence_root = (settings.backend_data_dir / "evidence" / evidence.case_id / evidence.id).resolve()
    target_path = (settings.backend_data_dir / row.relative_path).resolve()
    try:
        target_path.relative_to(evidence_root)
    except ValueError:
        raise EvidenceCompanionError("UNSAFE_COMPANION_PATH", "Companion path is outside this evidence's storage root.") from None
    try:
        primary_path = resolve_memory_evidence_path(evidence, settings=settings)
        if target_path == primary_path.resolve():
            raise EvidenceCompanionError("REFUSED_PRIMARY_DELETE", "Refusing to delete the primary evidence file.")
    except MemoryStorageAccessError:
        # Primary is unreadable/missing for unrelated reasons -- still
        # safe to proceed with deleting the companion itself below, since
        # the containment check above already proved this path cannot be
        # anything shared/critical outside this evidence's own directory.
        pass

    # Delete the file BEFORE the DB row: if the row disappeared first and
    # the file removal then failed or crashed, the file would keep
    # existing on disk -- undetected by Kairon, but still fully
    # discoverable by Volatility's VmwareStacker. Deleting the file first
    # means a failure here aborts before touching the DB, leaving state
    # consistent (the row still correctly describes an existing file).
    try:
        if target_path.exists() or target_path.is_symlink():
            target_path.unlink()
    except FileNotFoundError:
        pass
    except OSError as exc:
        raise EvidenceCompanionError("COMPANION_DELETE_FAILED", "Could not remove the companion file from storage.") from exc

    record_evidence_event(
        db,
        evidence,
        EvidenceCustodyEventType.companion_removed,
        f"VMware companion removed ({row.companion_type}).",
        actor_user_id=actor_user_id,
        details={
            "companion_type": row.companion_type,
            "original_filename": row.original_filename,
            "sha256": row.sha256,
            "size_bytes": row.size_bytes,
        },
    )
    db.delete(row)
    db.commit()


def _active_companion(db: Session, evidence_id: str) -> EvidenceCompanionFile | None:
    return (
        db.query(EvidenceCompanionFile)
        .filter(EvidenceCompanionFile.evidence_id == evidence_id)
        .one_or_none()
    )


def _validate_staged_upload(path: Path, *, settings: Any) -> None:
    try:
        stat = path.lstat()
    except OSError as exc:
        raise EvidenceCompanionError("COMPANION_UPLOAD_NOT_FOUND", "Staged companion upload was not found.") from exc
    if path.is_symlink() or not path.is_file():
        raise EvidenceCompanionError("COMPANION_UPLOAD_REJECTED", "Uploaded companion must be a regular file.")
    if stat.st_size <= 0:
        raise EvidenceCompanionError("COMPANION_UPLOAD_REJECTED", "Uploaded companion is empty.")
    max_bytes = int(getattr(settings, "memory_upload_max_bytes", None) or getattr(settings, "memory_max_upload_size", 2147483648))
    if stat.st_size > max_bytes:
        raise EvidenceCompanionError("COMPANION_UPLOAD_TOO_LARGE", "Uploaded companion exceeds the configured evidence upload size limit.")


def _assert_free_space(directory: Path, size_bytes: int, *, settings: Any) -> None:
    min_free = int(getattr(settings, "memory_upload_min_free_space_bytes", 0) or 0)
    try:
        usage = shutil.disk_usage(directory)
    except OSError:
        return
    if usage.free - size_bytes < min_free:
        raise EvidenceCompanionError(
            "INSUFFICIENT_STORAGE",
            "Not enough free disk space to store this VMware companion file.",
        )


def _hash_file(path: Path) -> tuple[str, int]:
    digest = hashlib.sha256()
    size = 0
    with path.open("rb") as handle:
        while chunk := handle.read(1024 * 1024):
            digest.update(chunk)
            size += len(chunk)
    return digest.hexdigest(), size
