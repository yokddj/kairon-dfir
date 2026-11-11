"""Importing evidence from an S3 bucket.

The operator configures one bucket source for the instance (endpoint, region, access key and the
secret, sealed like the AI provider keys -- see app.services.ai.crypto). An analyst browses it from
the evidence wizard and picks one object; a worker job downloads it into a normal resumable upload
session (create_resumable_upload_session) and then runs the same preflight a browser upload gets
(run_evidence_upload_preflight). From there it is an ordinary staged upload: the wizard shows the
preflight report and registers it, so hashing, classification, registration and ingest are the
same code paths as any other evidence.

S3-compatible stores (MinIO, Ceph, Wasabi...) work through ``endpoint_url``. Downloading reaches
outside the lab, so the whole feature is off unless S3_SOURCE_ENABLED=true.
"""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Any

from sqlalchemy.orm import Session

from app.core.app_settings import get_setting, set_setting
from app.core.config import get_settings
from app.services.ai.crypto import is_sealed, mask, open_sealed, seal
from app.services.remote_evidence_import import RemoteImportError, download_into_session, read_chunks

logger = logging.getLogger(__name__)

S3_SETTING_KEY = "S3_SOURCE"
_CREDENTIAL_INFO = b"kairon-s3-source-credentials-v1"
LIST_PAGE_SIZE = 200
_DOWNLOAD_CHUNK = 8 * 1024 * 1024


class S3SourceError(RemoteImportError):
    """A problem the operator or analyst can act on; the message is safe to show."""


def default_config() -> dict[str, Any]:
    return {"endpoint_url": None, "region": None, "access_key_id": None, "secret_access_key": None, "default_bucket": None, "path_style": False}


def _text(value: Any) -> str | None:
    cleaned = str(value).strip() if value is not None else ""
    return cleaned or None


def _coerce(raw: object) -> dict[str, Any]:
    config = default_config()
    if not isinstance(raw, dict):
        return config
    for key in ("endpoint_url", "region", "access_key_id", "default_bucket"):
        config[key] = _text(raw.get(key))
    if config["endpoint_url"]:
        config["endpoint_url"] = config["endpoint_url"].rstrip("/")
    config["path_style"] = bool(raw.get("path_style", False))
    secret = raw.get("secret_access_key")
    config["secret_access_key"] = secret if is_sealed(secret) else None
    return config


def load_config(db: Session) -> dict[str, Any]:
    """Raw configuration, sealed secret included. Never return this to a client."""
    return _coerce(get_setting(db, S3_SETTING_KEY, default_config()))


def public_config(config: dict[str, Any]) -> dict[str, Any]:
    """What the browser may see: the secret only as a presence flag and a mask."""
    secret = None
    if config.get("secret_access_key"):
        try:
            secret = mask(open_sealed(config["secret_access_key"], info=_CREDENTIAL_INFO))
        except Exception:  # noqa: BLE001 -- shown as stored but unreadable
            secret = None
    return {
        "enabled": bool(get_settings().s3_source_enabled),
        "endpoint_url": config.get("endpoint_url") or "",
        "region": config.get("region") or "",
        "access_key_id": config.get("access_key_id") or "",
        "default_bucket": config.get("default_bucket") or "",
        "path_style": bool(config.get("path_style")),
        "has_secret_access_key": bool(config.get("secret_access_key")),
        "secret_access_key_masked": secret,
        "configured": _is_configured(config),
    }


def _is_configured(config: dict[str, Any]) -> bool:
    return bool(config.get("access_key_id") and config.get("secret_access_key"))


def _apply(config: dict[str, Any], updates: dict[str, Any]) -> dict[str, Any]:
    """``updates`` over ``config``. The secret follows three states, since the browser never gets it
    back: absent or None leaves it, "" clears it, anything else replaces it."""
    merged = dict(config)
    for key in ("endpoint_url", "region", "access_key_id", "default_bucket"):
        if updates.get(key) is not None:
            merged[key] = _text(updates[key])
    if merged.get("endpoint_url"):
        endpoint = merged["endpoint_url"].rstrip("/")
        if not endpoint.lower().startswith(("https://", "http://")):
            raise S3SourceError("The endpoint URL must start with https:// (or http:// for a store inside the lab).")
        merged["endpoint_url"] = endpoint
    if updates.get("path_style") is not None:
        merged["path_style"] = bool(updates["path_style"])
    secret = updates.get("secret_access_key")
    if secret is not None:
        merged["secret_access_key"] = seal(secret.strip(), info=_CREDENTIAL_INFO) if secret.strip() else None
    return merged


def save_config(db: Session, updates: dict[str, Any]) -> dict[str, Any]:
    stored = _coerce(_apply(load_config(db), updates))
    set_setting(db, S3_SETTING_KEY, stored)
    return stored


def require_enabled() -> None:
    if not get_settings().s3_source_enabled:
        raise S3SourceError("Importing evidence from S3 is disabled on this instance (S3_SOURCE_ENABLED=false).")


def build_client(config: dict[str, Any]):
    """A boto3 S3 client for ``config`` (raw, sealed secret)."""
    if not _is_configured(config):
        raise S3SourceError("S3 is not configured yet: an administrator has to set the access key and secret.")
    import boto3
    from botocore.config import Config

    return boto3.client(
        "s3",
        endpoint_url=config.get("endpoint_url") or None,
        region_name=config.get("region") or None,
        aws_access_key_id=config["access_key_id"],
        aws_secret_access_key=open_sealed(config["secret_access_key"], info=_CREDENTIAL_INFO),
        config=Config(
            signature_version="s3v4",
            s3={"addressing_style": "path" if config.get("path_style") else "auto"},
            retries={"max_attempts": 5, "mode": "standard"},
            connect_timeout=15,
            read_timeout=120,
        ),
    )


def _client_error(exc: Exception) -> S3SourceError:
    """An S3/botocore failure as a message without credentials or internals."""
    code = None
    response = getattr(exc, "response", None)
    if isinstance(response, dict):
        code = (response.get("Error") or {}).get("Code")
    known = {
        "AccessDenied": "Access denied: the configured key has no permission for this bucket or object.",
        "403": "Access denied: the configured key has no permission for this bucket or object.",
        "NoSuchBucket": "The bucket does not exist.",
        "NoSuchKey": "The object no longer exists in the bucket.",
        "404": "The bucket or object was not found.",
        "InvalidAccessKeyId": "The access key ID is not valid for this endpoint.",
        "SignatureDoesNotMatch": "The secret access key does not match the access key ID.",
        "InvalidObjectState": "The object is archived (Glacier/Deep Archive): restore it in S3 before importing.",
    }
    if code in known:
        return S3SourceError(known[code])
    name = exc.__class__.__name__
    if name in {"NoCredentialsError", "PartialCredentialsError"}:
        return S3SourceError("S3 credentials are incomplete.")
    if name in {"EndpointConnectionError", "ConnectTimeoutError", "ReadTimeoutError"}:
        return S3SourceError("The S3 endpoint could not be reached from the server.")
    return S3SourceError(f"S3 request failed ({code or name}).")


def test_connection(config: dict[str, Any], bucket: str | None) -> dict[str, Any]:
    target = _text(bucket) or config.get("default_bucket")
    try:
        client = build_client(config)
        if target:
            client.head_bucket(Bucket=target)
            return {"ok": True, "message": f"Connected; bucket {target} is reachable."}
        buckets = client.list_buckets().get("Buckets") or []
        return {"ok": True, "message": f"Connected; {len(buckets)} bucket(s) visible."}
    except S3SourceError as exc:
        return {"ok": False, "error": str(exc)}
    except Exception as exc:  # noqa: BLE001
        return {"ok": False, "error": str(_client_error(exc))}


def list_objects(config: dict[str, Any], *, bucket: str | None, prefix: str = "", token: str | None = None) -> dict[str, Any]:
    """One page of a bucket "folder": the sub-prefixes and the objects directly under ``prefix``."""
    target = _text(bucket) or config.get("default_bucket")
    if not target:
        raise S3SourceError("Name the bucket to browse.")
    kwargs: dict[str, Any] = {"Bucket": target, "Prefix": prefix or "", "Delimiter": "/", "MaxKeys": LIST_PAGE_SIZE}
    if token:
        kwargs["ContinuationToken"] = token
    try:
        page = build_client(config).list_objects_v2(**kwargs)
    except S3SourceError:
        raise
    except Exception as exc:  # noqa: BLE001
        raise _client_error(exc) from exc
    objects = [
        {
            "key": item["Key"],
            "name": item["Key"][len(prefix or ""):],
            "size": int(item.get("Size") or 0),
            "last_modified": item["LastModified"].isoformat() if item.get("LastModified") else None,
            "storage_class": item.get("StorageClass"),
        }
        for item in page.get("Contents") or []
        if not item["Key"].endswith("/")
    ]
    return {
        "bucket": target,
        "prefix": prefix or "",
        "prefixes": [item["Prefix"] for item in page.get("CommonPrefixes") or []],
        "objects": objects,
        "next_token": page.get("NextContinuationToken") if page.get("IsTruncated") else None,
    }


def start_import(db: Session, case_id: str, *, bucket: str | None, key: str, declared_platform: str | None = None) -> Any:
    """Create the upload session the object is downloaded into, and queue the download."""
    from app.services.evidence_operations import sync_upload_operation
    from app.services.evidence_upload_session import create_resumable_upload_session
    from app.workers.tasks import enqueue_s3_import

    require_enabled()
    config = load_config(db)
    target = _text(bucket) or config.get("default_bucket")
    key = (key or "").strip()
    if not target or not key or key.endswith("/"):
        raise S3SourceError("Pick one object (not a folder) to import.")
    filename = Path(key).name
    if not filename or filename in {".", ".."}:
        raise S3SourceError("The object key does not end in a file name.")
    try:
        head = build_client(config).head_object(Bucket=target, Key=key)
    except S3SourceError:
        raise
    except Exception as exc:  # noqa: BLE001
        raise _client_error(exc) from exc
    if head.get("StorageClass") in {"GLACIER", "DEEP_ARCHIVE"} and 'ongoing-request="false"' not in str(head.get("Restore") or ""):
        raise S3SourceError("The object is archived (Glacier/Deep Archive): restore it in S3 before importing.")
    size = int(head.get("ContentLength") or 0)
    if size <= 0:
        raise S3SourceError("The object is empty.")
    session = create_resumable_upload_session(db, case_id, filename=filename, expected_size_bytes=size, declared_platform=declared_platform, reuse_existing=False)
    source = {"bucket": target, "key": key, "endpoint_url": config.get("endpoint_url"), "etag": (head.get("ETag") or "").strip('"') or None, "version_id": head.get("VersionId"), "size": size}
    session.metadata_json = {**(session.metadata_json or {}), "upload_mode": "s3", "s3_source": source}
    db.add(session)
    db.commit()
    db.refresh(session)
    sync_upload_operation(db, session)
    enqueue_s3_import(session.id)
    return session


def _open_object(db: Session, source: dict[str, Any]):
    request: dict[str, Any] = {"Bucket": source["bucket"], "Key": source["key"]}
    # The exact object that was picked, even if the key is overwritten meanwhile.
    if source.get("version_id"):
        request["VersionId"] = source["version_id"]
    elif source.get("etag"):
        request["IfMatch"] = f'"{source["etag"]}"'
    body = build_client(load_config(db)).get_object(**request)["Body"]
    return read_chunks(body, _DOWNLOAD_CHUNK)


def run_import(upload_session_id: str) -> dict[str, Any]:
    """Worker side: download the object into the session's staged file, then preflight it."""
    return download_into_session(
        upload_session_id,
        source_key="s3_source",
        label="S3",
        require_enabled=require_enabled,
        open_stream=_open_object,
        describe_error=_client_error,
    )
