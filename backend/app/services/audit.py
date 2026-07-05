from __future__ import annotations
from app.models.audit_event import AuditEvent
from app.core.database import SessionLocal
from datetime import datetime, timezone

def log_audit(
    action: str,
    *,
    actor_user_id: str | None = None,
    case_id: str | None = None,
    resource_type: str | None = None,
    resource_id: str | None = None,
    result: str = "success",
    ip_address: str | None = None,
    user_agent: str | None = None,
    metadata: dict | None = None,
) -> None:
    db = SessionLocal()
    try:
        event = AuditEvent(
            occurred_at=datetime.now(timezone.utc).isoformat(),
            actor_user_id=actor_user_id,
            action=action,
            resource_type=resource_type,
            resource_id=resource_id,
            case_id=case_id,
            result=result,
            ip_address=ip_address,
            user_agent=user_agent,
            metadata_json=metadata or {},
        )
        db.add(event)
        db.commit()
    except Exception:
        db.rollback()
    finally:
        db.close()
