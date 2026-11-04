"""Service tokens: long-lived, read-only credentials for non-interactive
clients calling the API directly (an MCP server, a script, another internal
tool), instead of a browser session cookie.

There is a single scope today: every case, read-only, forever unless it is
given an expiry or revoked. A narrower scope can be added later (the model
has a ``scope`` column for that) without another migration. Granting access
case by case, the way human users get it through ``CaseAccess``, would make
an automated integration tedious to operate -- a new case would need a new
grant before an integration could see it -- so a service token instead sees
every case, the same way an admin user does, and nothing else.

The token is never stored in the clear: only its SHA-256 hash, exactly like
a session token (see ``auth_utils.hash_token``). It is returned to the
caller once, at creation.
"""
from __future__ import annotations

from datetime import datetime, timedelta, timezone

from sqlalchemy.orm import Session

from app.models.service_token import ServiceToken
from app.services.auth_utils import create_service_token, hash_token, service_token_display_prefix

SERVICE_TOKEN_HEADER_PREFIX = "Bearer "
READ_ONLY_ALL_CASES = "read_only_all_cases"


def create_token(
    db: Session,
    *,
    name: str,
    created_by: str | None,
    expires_in_days: int | None = None,
) -> tuple[ServiceToken, str]:
    """Create a new service token. Returns the row and the plaintext value,
    which the caller must show to the operator now -- it cannot be
    recovered afterwards."""
    plaintext = create_service_token()
    expires_at = None
    if expires_in_days is not None:
        expires_at = (datetime.now(timezone.utc) + timedelta(days=expires_in_days)).isoformat()
    row = ServiceToken(
        name=name,
        token_hash=hash_token(plaintext),
        token_prefix=service_token_display_prefix(plaintext),
        scope=READ_ONLY_ALL_CASES,
        created_by=created_by,
        expires_at=expires_at,
    )
    db.add(row)
    db.commit()
    db.refresh(row)
    return row, plaintext


def revoke_token(db: Session, token_id: str) -> ServiceToken | None:
    row = db.get(ServiceToken, token_id)
    if row is None or row.revoked_at is not None:
        return row
    row.revoked_at = datetime.now(timezone.utc).isoformat()
    db.commit()
    return row


def authenticate(db: Session, authorization_header: str | None) -> ServiceToken | None:
    """The service token a request carries, if its ``Authorization`` header
    names one that is valid: known, not expired, not revoked. Never raises;
    a malformed or absent header is simply "no token", same as an absent
    cookie elsewhere in this module's session counterpart."""
    if not authorization_header or not authorization_header.startswith(SERVICE_TOKEN_HEADER_PREFIX):
        return None
    candidate = authorization_header[len(SERVICE_TOKEN_HEADER_PREFIX):].strip()
    if not candidate:
        return None
    token_hash = hash_token(candidate)
    row = db.query(ServiceToken).filter(
        ServiceToken.token_hash == token_hash,
        ServiceToken.revoked_at == None,  # noqa: E711 - SQLAlchemy idiom
    ).first()
    if row is None:
        return None
    if row.expires_at is not None and row.expires_at < datetime.now(timezone.utc).isoformat():
        return None
    return row


def touch_last_used(db: Session, row: ServiceToken) -> None:
    """Best-effort bookkeeping so an operator can tell a token is actually
    in use. Never raises: a failure here must not break the request it is
    piggy-backing on."""
    try:
        row.last_used_at = datetime.now(timezone.utc).isoformat()
        db.commit()
    except Exception:  # noqa: BLE001
        db.rollback()


def serialize(row: ServiceToken) -> dict:
    return {
        "id": row.id,
        "name": row.name,
        "token_prefix": row.token_prefix,
        "scope": row.scope,
        "created_at": row.created_at,
        "created_by": row.created_by,
        "expires_at": row.expires_at,
        "revoked_at": row.revoked_at,
        "last_used_at": row.last_used_at,
    }
