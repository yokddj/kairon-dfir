"""Evidence from an S3 bucket: the instance's bucket configuration (admin) and, per case, browsing
the bucket and importing one object as evidence (app.services.s3_source)."""

from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from app.core.config import get_settings
from app.core.database import get_db
from app.models.case import Case
from app.models.user import User
from app.services import s3_source
from app.services.ai.crypto import CredentialCryptoError
from app.services.audit import log_audit
from app.services.auth_dependencies import get_current_user, get_effective_case_role, get_optional_user

router = APIRouter(tags=["s3"])


class S3ConfigUpdate(BaseModel):
    endpoint_url: str | None = Field(default=None, max_length=512)
    region: str | None = Field(default=None, max_length=64)
    access_key_id: str | None = Field(default=None, max_length=256)
    # None keeps the stored secret, "" clears it, anything else replaces it.
    secret_access_key: str | None = Field(default=None, max_length=512)
    default_bucket: str | None = Field(default=None, max_length=255)
    path_style: bool | None = None

    model_config = {"extra": "forbid"}


class S3TestRequest(S3ConfigUpdate):
    bucket: str | None = Field(default=None, max_length=255)


class S3ImportRequest(BaseModel):
    bucket: str | None = Field(default=None, max_length=255)
    key: str = Field(min_length=1, max_length=1024)
    declared_platform: str | None = Field(default=None, max_length=32)

    model_config = {"extra": "forbid"}


def require_s3_admin(request: Request, db: Session = Depends(get_db)) -> User | None:
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
        s3_source.require_enabled()
    except s3_source.S3SourceError as exc:
        raise HTTPException(status_code=403, detail=str(exc)) from exc
    return s3_source.load_config(db)


@router.get("/api/s3/config")
def get_s3_config(db: Session = Depends(get_db), _admin: User | None = Depends(require_s3_admin)) -> dict:
    return s3_source.public_config(s3_source.load_config(db))


@router.put("/api/s3/config")
def put_s3_config(payload: S3ConfigUpdate, db: Session = Depends(get_db), admin: User | None = Depends(require_s3_admin)) -> dict:
    try:
        stored = s3_source.save_config(db, payload.model_dump(exclude_unset=True))
    except (s3_source.S3SourceError, CredentialCryptoError) as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    log_audit("s3_source_configured", actor_user_id=getattr(admin, "id", None), resource_type="app_setting", resource_id=s3_source.S3_SETTING_KEY, metadata={"endpoint_url": stored.get("endpoint_url"), "default_bucket": stored.get("default_bucket"), "secret_changed": payload.secret_access_key is not None})
    return s3_source.public_config(stored)


@router.post("/api/s3/test")
def test_s3_config(payload: S3TestRequest | None = None, db: Session = Depends(get_db), _admin: User | None = Depends(require_s3_admin)) -> dict:
    """Try the stored settings, with any unsaved values from the form laid over them."""
    updates = payload.model_dump(exclude_unset=True, exclude={"bucket"}) if payload else {}
    try:
        config = s3_source._apply(s3_source.load_config(db), updates)  # noqa: SLF001 -- probe, not persisted
    except (s3_source.S3SourceError, CredentialCryptoError) as exc:
        return {"ok": False, "error": str(exc)}
    return s3_source.test_connection(config, payload.bucket if payload else None)


@router.get("/api/cases/{case_id}/s3/status")
def s3_status(case_id: str, db: Session = Depends(get_db), user: User | None = Depends(get_optional_user)) -> dict:
    """Whether the wizard should offer S3, without any of the configuration's secrets."""
    _case(db, case_id, user)
    config = s3_source.load_config(db)
    enabled = bool(get_settings().s3_source_enabled)
    return {"enabled": enabled, "configured": enabled and s3_source._is_configured(config), "default_bucket": (config.get("default_bucket") or "") if enabled else ""}  # noqa: SLF001


@router.get("/api/cases/{case_id}/s3/buckets")
def list_s3_buckets(case_id: str, db: Session = Depends(get_db), user: User | None = Depends(get_optional_user)) -> dict:
    _case(db, case_id, user)
    config = _usable_config(db)
    try:
        return s3_source.list_buckets(config)
    except (s3_source.S3SourceError, CredentialCryptoError) as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@router.get("/api/cases/{case_id}/s3/objects")
def list_s3_objects(
    case_id: str,
    bucket: str | None = Query(default=None, max_length=255),
    prefix: str = Query(default="", max_length=1024),
    token: str | None = Query(default=None, max_length=2048),
    db: Session = Depends(get_db),
    user: User | None = Depends(get_optional_user),
) -> dict:
    _case(db, case_id, user)
    config = _usable_config(db)
    try:
        return s3_source.list_objects(config, bucket=bucket, prefix=prefix, token=token)
    except (s3_source.S3SourceError, CredentialCryptoError) as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@router.post("/api/cases/{case_id}/s3/import")
def import_s3_object(case_id: str, payload: S3ImportRequest, db: Session = Depends(get_db), user: User | None = Depends(get_optional_user)) -> dict:
    """Start downloading one object into a new upload session; the wizard follows that session
    (GET .../evidence-uploads/{id}) until its preflight is ready, like a browser upload."""
    from app.api.routes_evidence_preflight import _session_to_read
    from app.services.evidence_upload_session import UploadSessionError

    _case(db, case_id, user)
    _usable_config(db)
    declared = payload.declared_platform if payload.declared_platform and payload.declared_platform != "auto" else None
    try:
        session = s3_source.start_import(db, case_id, bucket=payload.bucket, key=payload.key, declared_platform=declared)
    except (s3_source.S3SourceError, CredentialCryptoError) as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    except UploadSessionError as exc:
        raise HTTPException(status_code=413 if "space" in exc.code or "size" in exc.code else 400, detail={"code": exc.code, "message": exc.message}) from exc
    source = (session.metadata_json or {}).get("s3_source") or {}
    log_audit("s3_evidence_import_started", actor_user_id=getattr(user, "id", None), case_id=case_id, resource_type="evidence_upload_session", resource_id=session.id, metadata={"bucket": source.get("bucket"), "key": source.get("key"), "size": source.get("size")})
    return {"session": _session_to_read(db, session).model_dump(mode="json")}
