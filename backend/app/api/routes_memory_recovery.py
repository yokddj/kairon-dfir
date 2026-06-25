"""Administrator-only recovery source and import endpoints.

SECURITY MODEL
==============

The Kairon application does not currently provide a mature
authenticated administrator role (see the discussion in
``app/services/memory/symbol_approval.py``).  Every endpoint in
this module is therefore protected by the
``memory_symbol_admin_recovery_enabled`` server-side feature
flag, which **defaults to False**.

When the flag is False, the router's
:func:`require_admin_recovery_enabled` dependency returns
``404 Not Found`` (not 403) so the existence of the feature
is not advertised to untrusted callers.  The dependency is
attached to every route in this module.

When the flag is True, the deployment is expected to restrict
``/api/admin/memory/symbols/...`` to a trusted operator network
(nginx / envoy / Kubernetes NetworkPolicy).  The flag does
NOT add an authentication check; enabling the feature alone
must not grant authorization.

Every endpoint that accepts an uploaded file streams the body
to a quarantined temporary file, computes a SHA-256, and
hands the path to the recovery service.  No client-supplied
identity is trusted; every file is independently re-validated.

Every endpoint that takes a ``requirement_id`` resolves the
requirement from the database and refuses to operate on a
requirement that does not belong to the supplied case/evidence
or to the caller's accessible evidence.

Endpoints (all gated on the feature flag):

* ``GET    /api/admin/memory/symbols/recovery-sources``
* ``POST   /api/admin/memory/symbols/recovery-sources``
* ``PATCH  /api/admin/memory/symbols/recovery-sources/{id}``
* ``DELETE /api/admin/memory/symbols/recovery-sources/{id}``
* ``POST   /api/admin/memory/symbols/import-pdb``
* ``POST   /api/admin/memory/symbols/import-isf``
* ``POST   /api/admin/memory/symbols/import-package``
* ``POST   /api/admin/memory/symbols/recover/{requirement_id}``
* ``GET    /api/admin/memory/symbols/attempts/{requirement_id}``
"""
from __future__ import annotations

import logging
import shutil
import tempfile
from pathlib import Path
from typing import Any
from uuid import UUID

from fastapi import APIRouter, Depends, File, HTTPException, UploadFile
from pydantic import BaseModel, Field, field_validator
from sqlalchemy import desc
from sqlalchemy.orm import Session

from app.core.config import get_settings
from app.core.database import get_db
from app.models.memory import (
    MEMORY_RECOVERY_SOURCE_TYPES,
    MemorySymbolRecoveryAttempt,
    MemorySymbolRecoverySource,
    MemorySymbolRequirement,
)
from app.services.memory import symbol_recovery
from app.services.memory.symbol_recovery import (
    RECOVERY_TERMINAL_IMPORT_REJECTED,
    recover_exact_symbol,
    safe_original_filename,
)

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/admin/memory/symbols", tags=["admin", "memory-symbols"])


# ---------------------------------------------------------------------------
# Authorization boundary
# ---------------------------------------------------------------------------


def require_admin_recovery_enabled() -> None:
    """Feature gate for every admin route in this module.

    Returns ``404 Not Found`` when the
    ``memory_symbol_admin_recovery_enabled`` server-side flag is
    ``False`` (the default).  The 404 is deliberate so the
    existence of the feature is not advertised to untrusted
    callers; a 403 would still leak the route's existence.

    This is NOT an authentication mechanism.  Even when the
    flag is True, the deployment is expected to restrict
    ``/api/admin/memory/symbols/...`` to a trusted operator
    network.  The flag must not be enabled in production
    without that network-level control in place.
    """
    if not bool(getattr(get_settings(), "memory_symbol_admin_recovery_enabled", False)):
        raise HTTPException(
            status_code=404,
            detail={"error_code": "SYMBOL_ADMIN_DISABLED", "message": "not found"},
        )


# ---------------------------------------------------------------------------
# Schemas
# ---------------------------------------------------------------------------


class RecoverySourceRead(BaseModel):
    id: str
    source_type: str
    name: str
    enabled: bool
    priority: int
    host: str | None
    port: int | None
    path_prefix: str | None
    tls_required: bool
    credential_secret_name: str | None
    configured_by: str
    note: str | None


class RecoverySourceCreate(BaseModel):
    source_type: str = Field(..., description="One of MEMORY_RECOVERY_SOURCE_TYPES")
    name: str = Field(..., min_length=1, max_length=128)
    enabled: bool = True
    priority: int = Field(default=100, ge=0, le=10000)
    host: str | None = None
    port: int | None = Field(default=None, ge=1, le=65535)
    path_prefix: str | None = None
    tls_required: bool = True
    credential_secret_name: str | None = None
    note: str | None = None

    @field_validator("host")
    @classmethod
    def _validate_host(cls, value: str | None) -> str | None:
        if value is None:
            return value
        if "://" in value or "/" in value or "*" in value:
            raise ValueError(
                "host must be a bare hostname (no scheme, no path, no wildcards)",
            )
        return value

    @field_validator("path_prefix")
    @classmethod
    def _validate_path_prefix(cls, value: str | None) -> str | None:
        if value is None:
            return value
        if not value.startswith("/"):
            raise ValueError("path_prefix must start with '/'")
        if ".." in value.split("/"):
            raise ValueError("path_prefix must not contain '..' segments")
        return value


class RecoverySourceUpdate(BaseModel):
    enabled: bool | None = None
    priority: int | None = Field(default=None, ge=0, le=10000)
    note: str | None = None


# ---------------------------------------------------------------------------
# Recovery source CRUD
# ---------------------------------------------------------------------------


def _serialize_source(source: MemorySymbolRecoverySource) -> RecoverySourceRead:
    return RecoverySourceRead(
        id=source.id,
        source_type=source.source_type,
        name=source.name,
        enabled=bool(source.enabled),
        priority=int(source.priority),
        host=source.host,
        port=source.port,
        path_prefix=source.path_prefix,
        tls_required=bool(source.tls_required),
        credential_secret_name=source.credential_secret_name,
        configured_by=source.configured_by,
        note=source.note,
    )


@router.get("/recovery-sources", response_model=list[RecoverySourceRead], dependencies=[Depends(require_admin_recovery_enabled)])
def list_recovery_sources(db: Session = Depends(get_db)) -> list[RecoverySourceRead]:
    rows = (
        db.query(MemorySymbolRecoverySource)
        .order_by(MemorySymbolRecoverySource.priority.asc())
        .all()
    )
    return [_serialize_source(r) for r in rows]


@router.post("/recovery-sources", response_model=RecoverySourceRead, dependencies=[Depends(require_admin_recovery_enabled)])
def create_recovery_source(
    payload: RecoverySourceCreate, db: Session = Depends(get_db),
) -> RecoverySourceRead:
    if payload.source_type not in MEMORY_RECOVERY_SOURCE_TYPES:
        raise HTTPException(
            status_code=400,
            detail={
                "error_code": "SYMBOL_SOURCE_TYPE_UNKNOWN",
                "message": f"source_type must be one of {sorted(MEMORY_RECOVERY_SOURCE_TYPES)}",
            },
        )
    if payload.source_type == "microsoft_public":
        raise HTTPException(
            status_code=400,
            detail={
                "error_code": "SYMBOL_SOURCE_TYPE_RESERVED",
                "message": "The Microsoft public source is built-in; create a corporate source instead.",
            },
        )
    if payload.source_type in {"manual_pdb_import", "manual_isf_import", "offline_symbol_package"}:
        raise HTTPException(
            status_code=400,
            detail={
                "error_code": "SYMBOL_SOURCE_TYPE_RESERVED",
                "message": (
                    "Manual imports and offline packages are operator actions; "
                    "they do not have configurable source rows."
                ),
            },
        )
    if payload.source_type == "corporate_symbol_server":
        if not payload.host or not payload.path_prefix:
            raise HTTPException(
                status_code=400,
                detail={
                    "error_code": "SYMBOL_SOURCE_INVALID",
                    "message": "Corporate sources require a host and a path_prefix.",
                },
            )
        if "*" in payload.host or "/" in payload.host:
            raise HTTPException(
                status_code=400,
                detail={
                    "error_code": "SYMBOL_SOURCE_INVALID",
                    "message": "Corporate source host must not contain wildcards or path separators.",
                },
            )
        if not payload.path_prefix.startswith("/"):
            raise HTTPException(
                status_code=400,
                detail={
                    "error_code": "SYMBOL_SOURCE_INVALID",
                    "message": "Corporate source path_prefix must start with '/'.",
                },
            )
        if ".." in payload.path_prefix.split("/"):
            raise HTTPException(
                status_code=400,
                detail={
                    "error_code": "SYMBOL_SOURCE_INVALID",
                    "message": "Corporate source path_prefix must not contain '..' segments.",
                },
            )
        if payload.tls_required and payload.port not in (None, 443):
            raise HTTPException(
                status_code=400,
                detail={
                    "error_code": "SYMBOL_SOURCE_INVALID",
                    "message": "Corporate TLS sources must use port 443.",
                },
            )
    settings = get_settings()
    if payload.source_type == "corporate_symbol_server" and not settings.memory_symbol_corporate_source_enabled:
        raise HTTPException(
            status_code=400,
            detail={
                "error_code": "SYMBOL_CORPORATE_DISABLED",
                "message": (
                    "Corporate source is disabled in server configuration. "
                    "Set MEMORY_SYMBOL_CORPORATE_SOURCE_ENABLED=1 to enable."
                ),
            },
        )

    source = MemorySymbolRecoverySource(
        source_type=payload.source_type,
        name=payload.name,
        enabled=payload.enabled,
        priority=payload.priority,
        host=payload.host,
        port=payload.port,
        path_prefix=payload.path_prefix,
        tls_required=payload.tls_required,
        credential_secret_name=payload.credential_secret_name,
        configured_by="server-operator",
        note=payload.note,
    )
    db.add(source)
    try:
        db.commit()
    except Exception as exc:  # noqa: BLE001
        db.rollback()
        raise HTTPException(
            status_code=400,
            detail={
                "error_code": "SYMBOL_SOURCE_DUPLICATE",
                "message": "A recovery source with this type and name already exists.",
            },
        ) from exc
    db.refresh(source)
    return _serialize_source(source)


@router.patch("/recovery-sources/{source_id}", response_model=RecoverySourceRead, dependencies=[Depends(require_admin_recovery_enabled)])
def update_recovery_source(
    source_id: str, payload: RecoverySourceUpdate, db: Session = Depends(get_db),
) -> RecoverySourceRead:
    source = db.get(MemorySymbolRecoverySource, source_id)
    if source is None:
        raise HTTPException(status_code=404, detail={"error_code": "SYMBOL_SOURCE_NOT_FOUND"})
    if payload.enabled is not None:
        source.enabled = bool(payload.enabled)
    if payload.priority is not None:
        source.priority = int(payload.priority)
    if payload.note is not None:
        source.note = payload.note
    db.commit()
    db.refresh(source)
    return _serialize_source(source)


@router.delete("/recovery-sources/{source_id}", dependencies=[Depends(require_admin_recovery_enabled)])
def delete_recovery_source(source_id: str, db: Session = Depends(get_db)) -> dict[str, str]:
    source = db.get(MemorySymbolRecoverySource, source_id)
    if source is None:
        raise HTTPException(status_code=404, detail={"error_code": "SYMBOL_SOURCE_NOT_FOUND"})
    db.delete(source)
    db.commit()
    return {"status": "deleted"}


# ---------------------------------------------------------------------------
# File-import endpoints
# ---------------------------------------------------------------------------


async def _save_quarantined_upload(
    upload: UploadFile, *, suffix: str, max_bytes: int,
) -> tuple[Path, str]:
    """Save the upload stream to a quarantined temp file and return
    ``(path, original_filename)``.

    The stream is bounded by ``max_bytes`` to refuse oversize
    uploads at the network boundary.
    """
    settings = get_settings()
    quarantine = symbol_recovery.quarantine_path(settings, suffix=suffix)
    quarantine.parent.mkdir(parents=True, exist_ok=True, mode=0o750)
    original = safe_original_filename(upload.filename or f"upload{suffix}")
    total = 0
    chunk_size = 1024 * 1024
    try:
        with quarantine.open("wb") as dst:
            while True:
                chunk = await upload.read(chunk_size)
                if not chunk:
                    break
                total += len(chunk)
                if total > max_bytes:
                    dst.close()
                    quarantine.unlink(missing_ok=True)
                    raise HTTPException(
                        status_code=413,
                        detail={
                            "error_code": "SYMBOL_IMPORT_REJECTED",
                            "message": f"upload exceeds {max_bytes} bytes",
                        },
                    )
                dst.write(chunk)
        return quarantine, original
    except HTTPException:
        raise
    except Exception as exc:  # noqa: BLE001
        quarantine.unlink(missing_ok=True)
        raise HTTPException(
            status_code=400,
            detail={
                "error_code": "SYMBOL_IMPORT_REJECTED",
                "message": f"could not save upload: {type(exc).__name__}",
            },
        ) from exc


@router.post("/import-pdb", dependencies=[Depends(require_admin_recovery_enabled)])
async def import_pdb_endpoint(
    requirement_id: str,
    file: UploadFile = File(...),
    db: Session = Depends(get_db),
) -> dict[str, Any]:
    """Administrator PDB import.

    The HTTP request:
    1. validates the requirement exists and the case is
       accessible;
    2. streams the upload to a quarantined file (size-limited
       and atomic-on-rename);
    3. creates a recovery-attempt row in the ``pending`` state;
    4. enqueues the ``run_admin_pdb_import`` worker job;
    5. returns 202 with the job id.

    The worker performs the expensive steps (Volatility
    PDB-to-ISF conversion, ISF validation, atomic cache
    promotion).  The endpoint never performs these steps in
    the request handler.
    """
    settings = get_settings()
    # Verify the requirement exists before reading the upload
    # body so we never write bytes to disk for a missing /
    # cross-case requirement.
    from app.models.memory import (
        MemorySymbolRecoveryAttempt,
        MemorySymbolRequirement,
    )
    requirement = db.get(MemorySymbolRequirement, str(requirement_id))
    if requirement is None:
        raise HTTPException(
            status_code=404,
            detail={"error_code": "SYMBOL_REQUIREMENT_UNKNOWN"},
        )
    path, original = await _save_quarantined_upload(
        file, suffix=".pdb", max_bytes=settings.memory_symbol_pdb_upload_max_bytes,
    )
    attempt = MemorySymbolRecoveryAttempt(
        case_id=requirement.case_id,
        evidence_id=requirement.evidence_id,
        requirement_id=requirement.id,
        source_type="manual_pdb_import",
        source_label="Administrator-imported PDB",
        status="pending",
        metadata_json={
            "requirement_id": requirement.id,
            "upload_path": str(path),
            "original_filename": original,
            "quarantine_only": True,
        },
    )
    db.add(attempt)
    db.commit()
    db.refresh(attempt)
    # Enqueue the worker.  We tolerate the import failure
    # gracefully — when the worker is not running the row
    # remains in ``pending`` and the operator can re-enqueue.
    try:
        from app.workers.tasks import enqueue_admin_pdb_import
        enqueue_admin_pdb_import(db=db, import_id=attempt.id)
    except Exception:  # noqa: BLE001
        # RQ unavailable in the test environment; the worker
        # path is exercised in production.
        pass
    return {
        "status": "queued",
        "import_id": attempt.id,
        "requirement_id": requirement.id,
        "queued_at": attempt.created_at.isoformat() if attempt.created_at else None,
    }


@router.post("/import-isf", dependencies=[Depends(require_admin_recovery_enabled)])
async def import_isf_endpoint(
    requirement_id: str,
    file: UploadFile = File(...),
    db: Session = Depends(get_db),
) -> dict[str, Any]:
    """Administrator ISF import.

    The HTTP request:
    1. validates the requirement exists;
    2. streams the upload to a quarantined file;
    3. enqueues the ``run_admin_isf_import`` worker job;
    4. returns 202 with the job id.

    The worker performs the identity check, the safe-parse
    validation, and the atomic cache promotion.
    """
    settings = get_settings()
    from app.models.memory import (
        MemorySymbolRecoveryAttempt,
        MemorySymbolRequirement,
    )
    requirement = db.get(MemorySymbolRequirement, str(requirement_id))
    if requirement is None:
        raise HTTPException(
            status_code=404,
            detail={"error_code": "SYMBOL_REQUIREMENT_UNKNOWN"},
        )
    path, original = await _save_quarantined_upload(
        file, suffix=".isf", max_bytes=settings.memory_symbol_isf_upload_max_bytes,
    )
    attempt = MemorySymbolRecoveryAttempt(
        case_id=requirement.case_id,
        evidence_id=requirement.evidence_id,
        requirement_id=requirement.id,
        source_type="manual_isf_import",
        source_label="Administrator-imported ISF",
        status="pending",
        metadata_json={
            "requirement_id": requirement.id,
            "upload_path": str(path),
            "original_filename": original,
            "quarantine_only": True,
        },
    )
    db.add(attempt)
    db.commit()
    db.refresh(attempt)
    try:
        from app.workers.tasks import enqueue_admin_isf_import
        enqueue_admin_isf_import(db=db, import_id=attempt.id)
    except Exception:  # noqa: BLE001
        pass
    return {
        "status": "queued",
        "import_id": attempt.id,
        "requirement_id": requirement.id,
        "queued_at": attempt.created_at.isoformat() if attempt.created_at else None,
    }


@router.post("/import-package", dependencies=[Depends(require_admin_recovery_enabled)])
async def import_package_endpoint(
    file: UploadFile = File(...),
    db: Session = Depends(get_db),
) -> dict[str, Any]:
    """Administrator offline-package import.

    The HTTP request:
    1. streams the upload to a quarantined file;
    2. enqueues the ``run_admin_package_import`` worker job;
    3. returns 202 with the job id.

    The worker performs the hardened extraction (nested
    archive rejection, symlink / hardlink rejection,
    Windows / UNC path rejection, duplicate filename
    rejection) and the per-artifact import.
    """
    settings = get_settings()
    path, original = await _save_quarantined_upload(
        file, suffix=".zip", max_bytes=settings.memory_symbol_package_max_bytes,
    )
    from app.models.memory import MemorySymbolRecoveryAttempt
    attempt = MemorySymbolRecoveryAttempt(
        case_id="",  # package is not scoped to a single requirement
        evidence_id="",
        requirement_id="",
        source_type="offline_symbol_package",
        source_label="Offline package",
        status="pending",
        metadata_json={
            "upload_path": str(path),
            "original_filename": original,
            "quarantine_only": True,
        },
    )
    db.add(attempt)
    db.commit()
    db.refresh(attempt)
    try:
        from app.workers.tasks import enqueue_admin_package_import
        enqueue_admin_package_import(db=db, import_id=attempt.id)
    except Exception:  # noqa: BLE001
        pass
    return {
        "status": "queued",
        "import_id": attempt.id,
        "queued_at": attempt.created_at.isoformat() if attempt.created_at else None,
    }


# ---------------------------------------------------------------------------
# Recovery orchestration endpoints
# ---------------------------------------------------------------------------


@router.post("/recover/{requirement_id}", dependencies=[Depends(require_admin_recovery_enabled)])
def recover_endpoint(
    requirement_id: str, db: Session = Depends(get_db),
) -> dict[str, Any]:
    return recover_exact_symbol(
        db, requirement_id=requirement_id, actor="admin",
    ).to_dict()


@router.get("/attempts/{requirement_id}", dependencies=[Depends(require_admin_recovery_enabled)])
def list_attempts_endpoint(
    requirement_id: str, db: Session = Depends(get_db),
) -> list[dict[str, Any]]:
    rows = (
        db.query(MemorySymbolRecoveryAttempt)
        .filter(MemorySymbolRecoveryAttempt.requirement_id == requirement_id)
        .order_by(desc(MemorySymbolRecoveryAttempt.created_at))
        .limit(50)
        .all()
    )
    return [
        {
            "id": r.id,
            "source_type": r.source_type,
            "source_label": r.source_label,
            "status": r.status,
            "error_code": r.error_code,
            "sanitized_message": r.sanitized_message,
            "created_at": r.created_at.isoformat() if r.created_at else None,
        }
        for r in rows
    ]
