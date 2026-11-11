"""Evidence from Azure Blob Storage: the instance's storage account configuration (admin) and, per
case, browsing a container and importing one blob as evidence (app.services.azure_blob_source).
The same shape as routes_s3."""

from __future__ import annotations

from typing import Literal

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from app.core.config import get_settings
from app.core.database import get_db
from app.models.case import Case
from app.models.user import User
from app.services import azure_blob_source
from app.services.ai.crypto import CredentialCryptoError
from app.services.audit import log_audit
from app.services.auth_dependencies import get_current_user, get_effective_case_role, get_optional_user

router = APIRouter(tags=["azure-blob"])


class AzureBlobConfigUpdate(BaseModel):
    account_url: str | None = Field(default=None, max_length=512)
    auth_method: Literal["account_key", "sas_token", "service_principal"] | None = None
    account_name: str | None = Field(default=None, max_length=64)
    tenant_id: str | None = Field(default=None, max_length=128)
    client_id: str | None = Field(default=None, max_length=128)
    # The account key, SAS token or client secret, per auth_method.
    # None keeps the stored secret, "" clears it, anything else replaces it.
    secret: str | None = Field(default=None, max_length=4096)
    default_container: str | None = Field(default=None, max_length=63)

    model_config = {"extra": "forbid"}


class AzureBlobTestRequest(AzureBlobConfigUpdate):
    container: str | None = Field(default=None, max_length=63)


class AzureBlobImportRequest(BaseModel):
    container: str | None = Field(default=None, max_length=63)
    blob: str = Field(min_length=1, max_length=1024)
    declared_platform: str | None = Field(default=None, max_length=32)

    model_config = {"extra": "forbid"}


def require_azure_blob_admin(request: Request, db: Session = Depends(get_db)) -> User | None:
    """Admin-only, and a no-op when authentication is disabled (tests, dev)."""
    if not get_settings().auth_enabled:
        return None
    user = get_current_user(request, db)
    if not user.is_admin:
        raise HTTPException(status_code=403, detail="Admin required")
    return user


def _case(db: Session, case_id: str, user: User | None) -> None:
    if db.get(Case, case_id) is None:
        raise HTTPException(status_code=404, detail="Case not found")
    if user is not None and get_effective_case_role(user, case_id, db) is None:
        raise HTTPException(status_code=403, detail="Access denied to this case")


def _usable_config(db: Session) -> dict:
    try:
        azure_blob_source.require_enabled()
    except azure_blob_source.AzureBlobSourceError as exc:
        raise HTTPException(status_code=403, detail=str(exc)) from exc
    return azure_blob_source.load_config(db)


@router.get("/api/azure-blob/config")
def get_azure_blob_config(db: Session = Depends(get_db), _admin: User | None = Depends(require_azure_blob_admin)) -> dict:
    return azure_blob_source.public_config(azure_blob_source.load_config(db))


@router.put("/api/azure-blob/config")
def put_azure_blob_config(payload: AzureBlobConfigUpdate, db: Session = Depends(get_db), admin: User | None = Depends(require_azure_blob_admin)) -> dict:
    try:
        stored = azure_blob_source.save_config(db, payload.model_dump(exclude_unset=True))
    except (azure_blob_source.AzureBlobSourceError, CredentialCryptoError) as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    log_audit(
        "azure_blob_source_configured",
        actor_user_id=getattr(admin, "id", None),
        resource_type="app_setting",
        resource_id=azure_blob_source.AZURE_BLOB_SETTING_KEY,
        metadata={"account_url": stored.get("account_url"), "auth_method": stored.get("auth_method"), "default_container": stored.get("default_container"), "secret_changed": payload.secret is not None},
    )
    return azure_blob_source.public_config(stored)


@router.post("/api/azure-blob/test")
def test_azure_blob_config(payload: AzureBlobTestRequest | None = None, db: Session = Depends(get_db), _admin: User | None = Depends(require_azure_blob_admin)) -> dict:
    """Try the stored settings, with any unsaved values from the form laid over them."""
    updates = payload.model_dump(exclude_unset=True, exclude={"container"}) if payload else {}
    try:
        config = azure_blob_source._apply(azure_blob_source.load_config(db), updates)  # noqa: SLF001 -- probe, not persisted
    except (azure_blob_source.AzureBlobSourceError, CredentialCryptoError) as exc:
        return {"ok": False, "error": str(exc)}
    return azure_blob_source.test_connection(config, payload.container if payload else None)


@router.get("/api/cases/{case_id}/azure-blob/status")
def azure_blob_status(case_id: str, db: Session = Depends(get_db), user: User | None = Depends(get_optional_user)) -> dict:
    """Whether the wizard should offer Azure Blob, without any of the configuration's secrets."""
    _case(db, case_id, user)
    config = azure_blob_source.load_config(db)
    enabled = bool(get_settings().azure_blob_source_enabled)
    return {
        "enabled": enabled,
        "configured": enabled and azure_blob_source.is_configured(config),
        "default_container": (config.get("default_container") or "") if enabled else "",
        "account_name": (azure_blob_source.derived_account_name(config) or "") if enabled else "",
    }


@router.get("/api/cases/{case_id}/azure-blob/objects")
def list_azure_blobs(
    case_id: str,
    container: str | None = Query(default=None, max_length=63),
    prefix: str = Query(default="", max_length=1024),
    token: str | None = Query(default=None, max_length=4096),
    db: Session = Depends(get_db),
    user: User | None = Depends(get_optional_user),
) -> dict:
    _case(db, case_id, user)
    config = _usable_config(db)
    try:
        return azure_blob_source.list_blobs(config, container=container, prefix=prefix, token=token)
    except (azure_blob_source.AzureBlobSourceError, CredentialCryptoError) as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@router.post("/api/cases/{case_id}/azure-blob/import")
def import_azure_blob(case_id: str, payload: AzureBlobImportRequest, db: Session = Depends(get_db), user: User | None = Depends(get_optional_user)) -> dict:
    """Start downloading one blob into a new upload session; the wizard follows that session
    (GET .../evidence-uploads/{id}) until its preflight is ready, like a browser upload."""
    from app.api.routes_evidence_preflight import _session_to_read
    from app.services.evidence_upload_session import UploadSessionError

    _case(db, case_id, user)
    _usable_config(db)
    declared = payload.declared_platform if payload.declared_platform and payload.declared_platform != "auto" else None
    try:
        session = azure_blob_source.start_import(db, case_id, container=payload.container, blob=payload.blob, declared_platform=declared)
    except (azure_blob_source.AzureBlobSourceError, CredentialCryptoError) as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    except UploadSessionError as exc:
        raise HTTPException(status_code=413 if "space" in exc.code or "size" in exc.code else 400, detail={"code": exc.code, "message": exc.message}) from exc
    source = (session.metadata_json or {}).get("azure_blob_source") or {}
    log_audit(
        "azure_blob_evidence_import_started",
        actor_user_id=getattr(user, "id", None),
        case_id=case_id,
        resource_type="evidence_upload_session",
        resource_id=session.id,
        metadata={"account_url": source.get("account_url"), "container": source.get("container"), "blob": source.get("blob"), "size": source.get("size")},
    )
    return {"session": _session_to_read(db, session).model_dump(mode="json")}
