from __future__ import annotations
import uuid
from sqlalchemy import Boolean, Column, String, DateTime, ForeignKey
from app.core.database import Base
from datetime import datetime, timezone

class Session(Base):
    __tablename__ = "sessions"
    id = Column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
    user_id = Column(String, ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True)
    token_hash = Column(String, unique=True, nullable=False, index=True)
    created_at = Column(String, default=lambda: datetime.now(timezone.utc).isoformat())
    expires_at = Column(String, nullable=False)
    revoked_at = Column(String, nullable=True)
    ip_address = Column(String, nullable=True)
    user_agent = Column(String, nullable=True)
