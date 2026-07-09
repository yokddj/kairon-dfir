from __future__ import annotations
import uuid
from sqlalchemy import Column, String, ForeignKey
from app.core.database import Base

class CaseAccess(Base):
    __tablename__ = "case_access"
    id = Column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
    case_id = Column(String, nullable=False, index=True)
    user_id = Column(String, ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True)
    role = Column(String, nullable=False, default="user")  # Reserved for future per-case role enforcement; not active in beta
    granted_by = Column(String, nullable=True)
    created_at = Column(String, nullable=True)
