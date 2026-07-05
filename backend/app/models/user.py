from __future__ import annotations
import uuid
from sqlalchemy import Boolean, Column, String, DateTime
from app.core.database import Base
from datetime import datetime, timezone

def _new_uuid():
    return str(uuid.uuid4())

class User(Base):
    __tablename__ = "users"
    id = Column(String, primary_key=True, default=_new_uuid)
    username = Column(String, unique=True, nullable=False, index=True)
    email = Column(String, nullable=True)
    display_name = Column(String, nullable=True)
    password_hash = Column(String, nullable=False)
    is_active = Column(Boolean, default=True, nullable=False)
    is_admin = Column(Boolean, default=False, nullable=False)
    created_at = Column(String, default=lambda: datetime.now(timezone.utc).isoformat())
    updated_at = Column(String, nullable=True)
    last_login_at = Column(String, nullable=True)
    password_changed_at = Column(String, nullable=True)
