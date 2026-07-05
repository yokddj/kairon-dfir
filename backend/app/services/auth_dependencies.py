from __future__ import annotations

from fastapi import Depends, HTTPException, Request
from sqlalchemy.orm import Session

from app.core.database import get_db
from app.models.user import User
from app.models.case_access import CaseAccess
from app.models.session import Session as UserSession
from app.services.auth_utils import hash_token
from datetime import datetime, timezone


def _get_session_user_dep(request: Request, db: Session) -> User | None:
    token = request.cookies.get("kairon_session")
    if not token:
        return None
    token_h = hash_token(token)
    session = db.query(UserSession).filter(
        UserSession.token_hash == token_h,
        UserSession.revoked_at == None,
    ).first()
    if not session:
        return None
    if session.expires_at < datetime.now(timezone.utc).isoformat():
        session.revoked_at = datetime.now(timezone.utc).isoformat()
        db.commit()
        return None
    user = db.get(User, session.user_id)
    if not user or not user.is_active:
        return None
    return user


def get_current_user(request: Request, db: Session = Depends(get_db)) -> User:
    user = _get_session_user_dep(request, db)
    if not user:
        raise HTTPException(status_code=401, detail="Not authenticated")
    return user


def require_admin(user: User = Depends(get_current_user)) -> User:
    if not user.is_admin:
        raise HTTPException(status_code=403, detail="Admin required")
    return user


def require_case_access(case_id: str):
    def _check(request: Request, db: Session = Depends(get_db)) -> User:
        user = get_current_user(request, db)
        if user.is_admin:
            return user
        access = db.query(CaseAccess).filter(
            CaseAccess.case_id == case_id,
            CaseAccess.user_id == user.id,
        ).first()
        if not access:
            raise HTTPException(status_code=403, detail="Access denied to this case")
        return user
    return _check


def get_optional_user(request: Request, db: Session = Depends(get_db)) -> User | None:
    return _get_session_user_dep(request, db)


def get_effective_case_role(user: User, case_id: str, db: Session) -> str | None:
    if user.is_admin:
        return "admin"
    access = db.query(CaseAccess).filter(
        CaseAccess.case_id == case_id,
        CaseAccess.user_id == user.id,
    ).first()
    if not access:
        return None
    return access.role
