from __future__ import annotations
import uuid
from sqlalchemy import Column, String
from app.core.database import Base
from datetime import datetime, timezone


class ServiceToken(Base):
    """A long-lived, read-only credential for non-interactive clients.

    Unlike a user :class:`~app.models.session.Session`, this is not tied to a
    cookie or a browser: it is meant for a service calling the API directly
    (an MCP server, a script, another internal tool) with an
    ``Authorization: Bearer`` header. There is a single scope today,
    ``read_only_all_cases``: every case, no writes, ever. The field exists so
    a narrower scope can be added later without a schema change.

    The token itself is shown once, at creation; only its SHA-256 hash is
    stored, exactly like a session token (see ``auth_utils.hash_token``).
    """

    __tablename__ = "service_tokens"
    id = Column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
    name = Column(String, nullable=False)
    token_hash = Column(String, unique=True, nullable=False, index=True)
    token_prefix = Column(String, nullable=False)  # first chars shown in listings, to tell tokens apart
    scope = Column(String, nullable=False, default="read_only_all_cases")
    created_at = Column(String, default=lambda: datetime.now(timezone.utc).isoformat())
    created_by = Column(String, nullable=True)
    expires_at = Column(String, nullable=True)  # null = does not expire
    revoked_at = Column(String, nullable=True)
    last_used_at = Column(String, nullable=True)
