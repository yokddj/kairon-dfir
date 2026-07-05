from __future__ import annotations

from app.core.config import settings
from app.core.database import SessionLocal
from app.models.user import User
from app.models.case_access import CaseAccess
from app.models.case import Case
from app.services.auth_utils import hash_password
from sqlalchemy.orm import Session


def bootstrap_admin(db: Session | None = None) -> bool:
    """Create initial admin user from env vars if no users exist. Returns True if created."""
    should_close = db is None
    if db is None:
        db = SessionLocal()
    try:
        if db.query(User).count() > 0:
            return False
        username = settings.bootstrap_admin_username.strip()
        password = settings.bootstrap_admin_password.strip()
        email = settings.bootstrap_admin_email.strip() or None
        if not username or not password:
            return False
        if password == "CHANGE_ME_BOOTSTRAP_ADMIN_PASSWORD":
            raise ValueError("Bootstrap admin password is still the default placeholder")

        user = User(
            username=username,
            email=email,
            display_name=username,
            password_hash=hash_password(password),
            is_admin=True,
            is_active=True,
        )
        db.add(user)
        db.flush()

        for case in db.query(Case).all():
            db.add(CaseAccess(
                case_id=case.id,
                user_id=user.id,
                role="owner",
                granted_by="bootstrap",
            ))

        db.commit()
        return True
    finally:
        if should_close and db is not None:
            db.close()
