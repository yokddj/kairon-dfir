"""Importing evidence from Azure Blob Storage.

The same flow as the S3 source (app.services.s3_source): the operator configures one storage
account for the instance, an analyst browses a container from the evidence wizard and picks one
blob, and a worker job downloads it into a normal resumable upload session and runs the same
preflight a browser upload gets (app.services.remote_evidence_import).

Three ways to authenticate, as Azure offers them to an incident responder:

- ``account_key``: the storage account's name and one of its access keys.
- ``sas_token``: a shared access signature, account- or container-scoped (needs read + list).
- ``service_principal``: a Microsoft Entra ID application (tenant, client id and a client secret)
  holding a data role such as *Storage Blob Data Reader* on the account or container.

Whichever it is, the secret (key, SAS or client secret) is sealed at rest like the S3 secret and
the AI provider keys, and never returned to the browser. ``account_url`` also takes an
emulator/sovereign-cloud endpoint (Azurite, ``*.blob.core.usgovcloudapi.net``...). Any blob type
can be imported: block blobs, append blobs and page blobs (an exported VM disk is a page blob VHD).
Downloading reaches outside the lab, so the feature is off unless AZURE_BLOB_SOURCE_ENABLED=true.
"""

from __future__ import annotations

import logging
from pathlib import PurePosixPath
from typing import Any
from urllib.parse import urlparse

from sqlalchemy.orm import Session

from app.core.app_settings import get_setting, set_setting
from app.core.config import get_settings
from app.services.ai.crypto import is_sealed, mask, open_sealed, seal
from app.services.remote_evidence_import import RemoteImportError, download_into_session

logger = logging.getLogger(__name__)

AZURE_BLOB_SETTING_KEY = "AZURE_BLOB_SOURCE"
_CREDENTIAL_INFO = b"kairon-azure-blob-source-credentials-v1"
AUTH_METHODS = ("account_key", "sas_token", "service_principal")
LIST_PAGE_SIZE = 200
_DOWNLOAD_CHUNK = 8 * 1024 * 1024
_TEXT_FIELDS = ("account_url", "account_name", "tenant_id", "client_id", "default_container")


class AzureBlobSourceError(RemoteImportError):
    """A problem the operator or analyst can act on; the message is safe to show."""


def default_config() -> dict[str, Any]:
    return {"account_url": None, "auth_method": "account_key", "account_name": None, "tenant_id": None, "client_id": None, "secret": None, "default_container": None}


def _text(value: Any) -> str | None:
    cleaned = str(value).strip() if value is not None else ""
    return cleaned or None


def _coerce(raw: object) -> dict[str, Any]:
    config = default_config()
    if not isinstance(raw, dict):
        return config
    for key in _TEXT_FIELDS:
        config[key] = _text(raw.get(key))
    if config["account_url"]:
        config["account_url"] = config["account_url"].rstrip("/")
    method = str(raw.get("auth_method") or "account_key")
    config["auth_method"] = method if method in AUTH_METHODS else "account_key"
    secret = raw.get("secret")
    config["secret"] = secret if is_sealed(secret) else None
    return config


def load_config(db: Session) -> dict[str, Any]:
    """Raw configuration, sealed secret included. Never return this to a client."""
    return _coerce(get_setting(db, AZURE_BLOB_SETTING_KEY, default_config()))


def derived_account_name(config: dict[str, Any]) -> str | None:
    """The account name given, or the one in the URL (``<name>.blob.core...`` or an emulator's
    ``http://host:10000/<name>``)."""
    if config.get("account_name"):
        return config["account_name"]
    url = config.get("account_url") or ""
    parsed = urlparse(url)
    host = parsed.hostname or ""
    if ".blob." in host:
        return host.split(".", 1)[0] or None
    path = parsed.path.strip("/")
    return path.split("/", 1)[0] if path else None


def public_config(config: dict[str, Any]) -> dict[str, Any]:
    """What the browser may see: the secret only as a presence flag and a mask."""
    masked = None
    if config.get("secret"):
        try:
            masked = mask(open_sealed(config["secret"], info=_CREDENTIAL_INFO))
        except Exception:  # noqa: BLE001 -- shown as stored but unreadable
            masked = None
    return {
        "enabled": bool(get_settings().azure_blob_source_enabled),
        "account_url": config.get("account_url") or "",
        "auth_method": config.get("auth_method") or "account_key",
        "account_name": config.get("account_name") or "",
        "tenant_id": config.get("tenant_id") or "",
        "client_id": config.get("client_id") or "",
        "default_container": config.get("default_container") or "",
        "has_secret": bool(config.get("secret")),
        "secret_masked": masked,
        "configured": is_configured(config),
    }


def is_configured(config: dict[str, Any]) -> bool:
    if not config.get("account_url") or not config.get("secret"):
        return False
    method = config.get("auth_method")
    if method == "account_key":
        return bool(derived_account_name(config))
    if method == "service_principal":
        return bool(config.get("tenant_id") and config.get("client_id"))
    return method == "sas_token"


def _apply(config: dict[str, Any], updates: dict[str, Any]) -> dict[str, Any]:
    """``updates`` over ``config``. The secret follows three states, since the browser never gets it
    back: absent or None leaves it, "" clears it, anything else replaces it. Switching the
    authentication method drops a stored secret of the other kind unless a new one is given."""
    merged = dict(config)
    for key in _TEXT_FIELDS:
        if updates.get(key) is not None:
            merged[key] = _text(updates[key])
    if merged.get("account_url"):
        url = merged["account_url"].rstrip("/")
        if not url.lower().startswith(("https://", "http://")) or not urlparse(url).hostname:
            raise AzureBlobSourceError("The account URL must look like https://<account>.blob.core.windows.net (or http:// for an emulator inside the lab).")
        merged["account_url"] = url
    method = updates.get("auth_method")
    if method is not None:
        if method not in AUTH_METHODS:
            raise AzureBlobSourceError(f"Unknown authentication method: {method}.")
        if method != config.get("auth_method") and updates.get("secret") is None:
            merged["secret"] = None
        merged["auth_method"] = method
    secret = updates.get("secret")
    if secret is not None:
        value = secret.strip()
        if merged.get("auth_method") == "sas_token":
            value = value.lstrip("?")
        merged["secret"] = seal(value, info=_CREDENTIAL_INFO) if value else None
    return merged


def save_config(db: Session, updates: dict[str, Any]) -> dict[str, Any]:
    stored = _coerce(_apply(load_config(db), updates))
    set_setting(db, AZURE_BLOB_SETTING_KEY, stored)
    return stored


def require_enabled() -> None:
    if not get_settings().azure_blob_source_enabled:
        raise AzureBlobSourceError("Importing evidence from Azure Blob Storage is disabled on this instance (AZURE_BLOB_SOURCE_ENABLED=false).")


def build_service_client(config: dict[str, Any]):
    """A BlobServiceClient for ``config`` (raw, sealed secret)."""
    if not is_configured(config):
        raise AzureBlobSourceError("Azure Blob Storage is not configured yet: an administrator has to set the account URL and credentials.")
    from azure.storage.blob import BlobServiceClient

    secret = open_sealed(config["secret"], info=_CREDENTIAL_INFO)
    method = config["auth_method"]
    if method == "account_key":
        credential: Any = {"account_name": derived_account_name(config), "account_key": secret}
    elif method == "sas_token":
        credential = secret
    else:
        from azure.identity import ClientSecretCredential

        credential = ClientSecretCredential(config["tenant_id"], config["client_id"], secret)
    return BlobServiceClient(config["account_url"], credential=credential, connection_timeout=15, read_timeout=120, max_chunk_get_size=_DOWNLOAD_CHUNK)


_KNOWN_ERROR_CODES = {
    "ContainerNotFound": "The container does not exist.",
    "BlobNotFound": "The blob no longer exists in the container.",
    "ResourceNotFound": "The container or blob was not found.",
    "AuthenticationFailed": "Authentication failed: check the account key or SAS token (a SAS may have expired).",
    "AuthorizationFailure": "Access denied: the credential has no permission for this container or blob.",
    "AuthorizationPermissionMismatch": "Access denied: the credential lacks the read/list permission this needs.",
    "AuthorizationResourceTypeMismatch": "Access denied: the SAS does not cover this kind of resource (it needs container and object access).",
    "AuthorizationServiceMismatch": "Access denied: the SAS is not valid for the Blob service.",
    "ConditionNotMet": "The blob changed after it was picked; pick it again.",
    "BlobArchived": "The blob is in the Archive tier: rehydrate it in Azure before importing.",
    "InvalidAuthenticationInfo": "The credentials are not valid for this account.",
}


def _client_error(exc: Exception) -> AzureBlobSourceError:
    """An Azure SDK failure as a message without credentials or internals."""
    code = getattr(exc, "error_code", None)
    code = getattr(code, "value", code)
    if code in _KNOWN_ERROR_CODES:
        return AzureBlobSourceError(_KNOWN_ERROR_CODES[code])
    name = exc.__class__.__name__
    status = getattr(exc, "status_code", None)
    if name == "ResourceModifiedError" or status == 412:
        return AzureBlobSourceError(_KNOWN_ERROR_CODES["ConditionNotMet"])
    if name == "ResourceNotFoundError" or status == 404:
        return AzureBlobSourceError(_KNOWN_ERROR_CODES["ResourceNotFound"])
    if name in {"ClientAuthenticationError", "CredentialUnavailableError"} or status in (401, 403):
        if (getattr(exc, "response", None) is None) and name == "ClientAuthenticationError":
            return AzureBlobSourceError("Signing in to Microsoft Entra ID failed: check the tenant, client id and client secret.")
        return AzureBlobSourceError("Access denied: the credential has no permission for this container or blob.")
    if name in {"ServiceRequestError", "ServiceRequestTimeoutError", "ServiceResponseTimeoutError"}:
        return AzureBlobSourceError("The storage account could not be reached from the server.")
    return AzureBlobSourceError(f"Azure Blob request failed ({code or name}).")


def test_connection(config: dict[str, Any], container: str | None) -> dict[str, Any]:
    target = _text(container) or config.get("default_container")
    try:
        service = build_service_client(config)
        if target:
            # Listing is what browsing needs, and all a container-scoped SAS (read + list) allows:
            # Get Container Properties would be refused for it although imports work.
            next(iter(service.get_container_client(target).walk_blobs(results_per_page=1).by_page()), None)
            return {"ok": True, "message": f"Connected; container {target} can be listed."}
        containers = list(service.list_containers(results_per_page=50).by_page().__next__())
        return {"ok": True, "message": f"Connected; {len(containers)} container(s) visible."}
    except AzureBlobSourceError as exc:
        return {"ok": False, "error": str(exc)}
    except Exception as exc:  # noqa: BLE001
        return {"ok": False, "error": str(_client_error(exc))}


def _is_archived(tier: Any) -> bool:
    # Still "Archive" while a rehydration is pending: not readable until it completes.
    return str(getattr(tier, "value", tier) or "").lower() == "archive"


def list_blobs(config: dict[str, Any], *, container: str | None, prefix: str = "", token: str | None = None) -> dict[str, Any]:
    """One page of a container "folder": the virtual sub-folders and the blobs directly under ``prefix``."""
    target = _text(container) or config.get("default_container")
    if not target:
        raise AzureBlobSourceError("Name the container to browse.")
    try:
        container_client = build_service_client(config).get_container_client(target)
        pages = container_client.walk_blobs(name_starts_with=prefix or None, delimiter="/", results_per_page=LIST_PAGE_SIZE).by_page(continuation_token=token)
        page = list(next(pages, []))
        next_token = getattr(pages, "continuation_token", None)
    except AzureBlobSourceError:
        raise
    except Exception as exc:  # noqa: BLE001
        raise _client_error(exc) from exc
    prefixes, blobs = [], []
    for item in page:
        name = item.name
        if name.endswith("/") and not hasattr(item, "size"):
            prefixes.append(name)
            continue
        if name.endswith("/"):
            continue
        tier = getattr(item, "blob_tier", None)
        blobs.append(
            {
                "key": name,
                "name": name[len(prefix or ""):],
                "size": int(getattr(item, "size", 0) or 0),
                "last_modified": item.last_modified.isoformat() if getattr(item, "last_modified", None) else None,
                "storage_class": str(getattr(tier, "value", tier)) if tier else None,
                "blob_type": str(getattr(getattr(item, "blob_type", None), "value", getattr(item, "blob_type", None)) or "") or None,
                "archived": _is_archived(tier),
            }
        )
    return {"container": target, "prefix": prefix or "", "prefixes": prefixes, "objects": blobs, "next_token": next_token or None}


def start_import(db: Session, case_id: str, *, container: str | None, blob: str, declared_platform: str | None = None) -> Any:
    """Create the upload session the blob is downloaded into, and queue the download."""
    from app.services.evidence_operations import sync_upload_operation
    from app.services.evidence_upload_session import create_resumable_upload_session
    from app.workers.tasks import enqueue_azure_blob_import

    require_enabled()
    config = load_config(db)
    target = _text(container) or config.get("default_container")
    blob = (blob or "").strip()
    if not target or not blob or blob.endswith("/"):
        raise AzureBlobSourceError("Pick one blob (not a folder) to import.")
    filename = PurePosixPath(blob).name
    if not filename or filename in {".", ".."}:
        raise AzureBlobSourceError("The blob name does not end in a file name.")
    try:
        props = build_service_client(config).get_blob_client(target, blob).get_blob_properties()
    except AzureBlobSourceError:
        raise
    except Exception as exc:  # noqa: BLE001
        raise _client_error(exc) from exc
    if _is_archived(getattr(props, "blob_tier", None)):
        raise AzureBlobSourceError(_KNOWN_ERROR_CODES["BlobArchived"])
    size = int(getattr(props, "size", 0) or 0)
    if size <= 0:
        raise AzureBlobSourceError("The blob is empty.")
    session = create_resumable_upload_session(db, case_id, filename=filename, expected_size_bytes=size, declared_platform=declared_platform, reuse_existing=False)
    blob_type = getattr(props, "blob_type", None)
    source = {
        "account_url": config.get("account_url"),
        "container": target,
        "blob": blob,
        "etag": str(getattr(props, "etag", "") or "").strip('"') or None,
        "version_id": getattr(props, "version_id", None),
        "blob_type": str(getattr(blob_type, "value", blob_type) or "") or None,
        "size": size,
    }
    session.metadata_json = {**(session.metadata_json or {}), "upload_mode": "azure_blob", "azure_blob_source": source}
    db.add(session)
    db.commit()
    db.refresh(session)
    sync_upload_operation(db, session)
    enqueue_azure_blob_import(session.id)
    return session


def _open_blob(db: Session, source: dict[str, Any]):
    from azure.core import MatchConditions

    service = build_service_client(load_config(db))
    # The exact blob that was picked, even if it is overwritten meanwhile: its version when the
    # account keeps versions, otherwise its ETag (a 412 if it changed).
    client = service.get_container_client(source["container"]).get_blob_client(source["blob"], version_id=source.get("version_id"))
    kwargs: dict[str, Any] = {"max_concurrency": 1}
    if not source.get("version_id") and source.get("etag"):
        kwargs.update(etag=f'"{source["etag"]}"', match_condition=MatchConditions.IfNotModified)
    return client.download_blob(**kwargs).chunks()


def run_import(upload_session_id: str) -> dict[str, Any]:
    """Worker side: download the blob into the session's staged file, then preflight it."""
    return download_into_session(
        upload_session_id,
        source_key="azure_blob_source",
        label="Azure Blob",
        require_enabled=require_enabled,
        open_stream=_open_blob,
        describe_error=_client_error,
    )
