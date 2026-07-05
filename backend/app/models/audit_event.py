from __future__ import annotations
import uuid
from sqlalchemy import Column, String, JSON
from app.core.database import Base
from datetime import datetime, timezone

class AuditEvent(Base):
    __tablename__ = "audit_events"
    id = Column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
    occurred_at = Column(String, default=lambda: datetime.now(timezone.utc).isoformat(), index=True)
    actor_user_id = Column(String, nullable=True, index=True)
    action = Column(String, nullable=False, index=True)
    resource_type = Column(String, nullable=True)
    resource_id = Column(String, nullable=True)
    case_id = Column(String, nullable=True, index=True)
    result = Column(String, nullable=True)  # success, failure, denied
    ip_address = Column(String, nullable=True)
    user_agent = Column(String, nullable=True)
    metadata_json = Column(JSON, nullable=True, default=dict)
