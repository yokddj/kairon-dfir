from __future__ import annotations
import hashlib
import secrets

import bcrypt

SESSION_EXPIRY_HOURS = 24


def hash_password(password: str) -> str:
    return bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt()).decode("utf-8")


def verify_password(password: str, hash: str) -> bool:
    return bcrypt.checkpw(password.encode("utf-8"), hash.encode("utf-8"))


def create_session_token() -> str:
    return secrets.token_urlsafe(32)


def hash_token(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


SERVICE_TOKEN_PREFIX = "kairon_svc_"


def create_service_token() -> str:
    """A long-lived credential for non-interactive clients.

    The ``kairon_svc_`` prefix makes the token's purpose recognisable at a
    glance (in logs, in a pasted config) and lets a future secret scanner
    rule match it specifically, the same way GitHub's own tokens are
    prefixed. Only the holder ever sees the full value; the server keeps
    its hash, exactly like a session token.
    """
    return f"{SERVICE_TOKEN_PREFIX}{secrets.token_urlsafe(32)}"


def service_token_display_prefix(token: str) -> str:
    """The short, non-secret fragment shown in listings to tell tokens apart."""
    body = token[len(SERVICE_TOKEN_PREFIX):] if token.startswith(SERVICE_TOKEN_PREFIX) else token
    return f"{SERVICE_TOKEN_PREFIX}{body[:6]}"
