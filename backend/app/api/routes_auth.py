from __future__ import annotations

import time

from fastapi import APIRouter, Depends, HTTPException, Request, Response
from sqlalchemy.orm import Session
from sqlalchemy import text
from pydantic import BaseModel, Field
from datetime import datetime, timedelta, timezone

from app.core.client_ip import client_ip
from app.core.database import get_db
from app.models.user import User
from app.models.session import Session as UserSession
from app.services.auth_utils import (
    hash_password, verify_password, create_session_token,
    hash_token, SESSION_EXPIRY_HOURS,
)
from app.services.audit import log_audit

# Failed sign-ins per (address, username). Only failures count and a successful sign-in clears
# its pair, so guessing one account's password from one address is slowed down while nobody else,
# including the account's owner from another address, is ever refused.
_failed_logins: dict[tuple[str, str], list[float]] = {}
_LOGIN_FAILURE_LIMIT = 10
_LOGIN_FAILURE_WINDOW = 300
_MAX_TRACKED_PAIRS = 10_000


def _login_key(ip: str, username: str) -> tuple[str, str]:
    return ip, username.strip().lower()


def _login_wait_seconds(key: tuple[str, str]) -> int:
    """Seconds this pair must wait before trying again; 0 when it may try now."""
    now = time.time()
    recent = [t for t in _failed_logins.get(key, []) if t > now - _LOGIN_FAILURE_WINDOW]
    if recent:
        _failed_logins[key] = recent
    else:
        _failed_logins.pop(key, None)
    if len(recent) < _LOGIN_FAILURE_LIMIT:
        return 0
    return max(1, int(recent[0] + _LOGIN_FAILURE_WINDOW - now) + 1)


def _record_login_failure(key: tuple[str, str]) -> None:
    if len(_failed_logins) >= _MAX_TRACKED_PAIRS:
        cutoff = time.time() - _LOGIN_FAILURE_WINDOW
        for stale in [k for k, times in _failed_logins.items() if not times or times[-1] <= cutoff]:
            del _failed_logins[stale]
    _failed_logins.setdefault(key, []).append(time.time())


router = APIRouter(tags=["auth"])


class LoginRequest(BaseModel):
    username: str
    password: str


class ChangePasswordRequest(BaseModel):
    current_password: str
    new_password: str


def _set_session_cookie(response: Response, session_token: str) -> None:
    response.set_cookie(
        key="kairon_session",
        value=session_token,
        httponly=True,
        secure=False,
        samesite="lax",
        max_age=SESSION_EXPIRY_HOURS * 3600,
        path="/",
    )


def _delete_session_cookie(response: Response) -> None:
    response.delete_cookie(key="kairon_session", path="/")


def _get_session_user(db: Session, request: Request) -> User | None:
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
    user.last_login_at = datetime.now(timezone.utc).isoformat()
    db.commit()
    return user


@router.post("/api/auth/login")
def login(payload: LoginRequest, request: Request, response: Response, db: Session = Depends(get_db)):
    ip = client_ip(request)
    key = _login_key(ip, payload.username)
    wait = _login_wait_seconds(key)
    if wait:
        log_audit("login_failure", actor_user_id=None, result="failure",
                  ip_address=ip, user_agent=request.headers.get("user-agent"))
        minutes = max(1, round(wait / 60))
        raise HTTPException(
            status_code=429,
            detail=f"Too many failed sign-in attempts for this account from this address. Try again in {minutes} minute{'s' if minutes != 1 else ''}.",
            headers={"Retry-After": str(wait)},
        )

    user = db.query(User).filter(User.username == payload.username).first()
    if not user or not verify_password(payload.password, user.password_hash):
        _record_login_failure(key)
        log_audit("login_failure", actor_user_id=None, result="failure",
                  ip_address=ip, user_agent=request.headers.get("user-agent"))
        raise HTTPException(status_code=401, detail="Invalid credentials")
    _failed_logins.pop(key, None)
    if not user.is_active:
        log_audit("login_failure", actor_user_id=user.id, result="failure",
                  ip_address=ip, user_agent=request.headers.get("user-agent"))
        raise HTTPException(status_code=401, detail="Account disabled")

    token = create_session_token()
    token_h = hash_token(token)
    session = UserSession(
        user_id=user.id,
        token_hash=token_h,
        created_at=datetime.now(timezone.utc).isoformat(),
        expires_at=(datetime.now(timezone.utc) + timedelta(hours=SESSION_EXPIRY_HOURS)).isoformat(),
        ip_address=ip,
        user_agent=request.headers.get("user-agent"),
    )
    db.add(session)
    user.last_login_at = datetime.now(timezone.utc).isoformat()
    db.commit()

    log_audit("login_success", actor_user_id=user.id, result="success",
              ip_address=ip, user_agent=request.headers.get("user-agent"))

    _set_session_cookie(response, token)
    return {
        "user_id": user.id,
        "username": user.username,
        "display_name": user.display_name,
        "email": user.email,
        "is_admin": user.is_admin,
    }


@router.post("/api/auth/logout")
def logout(request: Request, response: Response, db: Session = Depends(get_db)):
    token = request.cookies.get("kairon_session")
    if token:
        token_h = hash_token(token)
        session = db.query(UserSession).filter(
            UserSession.token_hash == token_h,
            UserSession.revoked_at == None,
        ).first()
        if session:
            session.revoked_at = datetime.now(timezone.utc).isoformat()
            db.commit()
    _delete_session_cookie(response)
    return {"status": "logged_out"}


@router.get("/api/auth/me")
def get_current_user_info(request: Request, db: Session = Depends(get_db)):
    user = _get_session_user(db, request)
    if not user:
        raise HTTPException(status_code=401, detail="Not authenticated")
    return {
        "user_id": user.id,
        "username": user.username,
        "display_name": user.display_name,
        "email": user.email,
        "is_admin": user.is_admin,
        "is_active": user.is_active,
        "created_at": user.created_at,
        "last_login_at": user.last_login_at,
    }


@router.post("/api/auth/change-password")
def change_password(payload: ChangePasswordRequest, request: Request, db: Session = Depends(get_db)):
    user = _get_session_user(db, request)
    if not user:
        raise HTTPException(status_code=401, detail="Not authenticated")
    if not verify_password(payload.current_password, user.password_hash):
        raise HTTPException(status_code=400, detail="Current password is incorrect")
    if len(payload.new_password) < 12:
        raise HTTPException(status_code=400, detail="Password must be at least 12 characters")
    user.password_hash = hash_password(payload.new_password)
    user.password_changed_at = datetime.now(timezone.utc).isoformat()
    db.query(UserSession).filter(
        UserSession.user_id == user.id,
        UserSession.revoked_at == None,
    ).update({"revoked_at": datetime.now(timezone.utc).isoformat()})
    db.commit()
    log_audit("password_change", actor_user_id=user.id, result="success")
    return {"status": "password_changed"}


class SetupRequest(BaseModel):
    username: str
    email: str | None = None
    display_name: str | None = None
    password: str


@router.get("/api/auth/needs-setup")
def needs_setup(request: Request, response: Response, db: Session = Depends(get_db)):
    # No cache
    response.headers["Cache-Control"] = "no-store"
    response.headers["Pragma"] = "no-cache"
    user_count = db.query(User).count()
    return {"needs_setup": user_count == 0}


@router.post("/api/auth/setup")
def create_first_admin(payload: SetupRequest, response: Response, request: Request, db: Session = Depends(get_db)):
    # Race protection: use PostgreSQL advisory lock to serialize first-admin creation.
    # Hash the endpoint name to a stable lock id so concurrent requests block each other.
    db.execute(text("SELECT pg_advisory_xact_lock(974123)"))
    existing = db.query(User).count()
    if existing > 0:
        raise HTTPException(status_code=403, detail="Setup already completed")
    if len(payload.password) < 12:
        raise HTTPException(status_code=400, detail="Password must be at least 12 characters")
    if not payload.username.strip():
        raise HTTPException(status_code=400, detail="Username is required")

    user = User(
        username=payload.username.strip(),
        email=payload.email,
        display_name=payload.display_name or payload.username.strip(),
        password_hash=hash_password(payload.password),
        is_admin=True,
        is_active=True,
    )
    db.add(user)
    db.commit()

    # Grant access to all existing cases
    from app.models.case_access import CaseAccess
    from app.models.case import Case
    for case in db.query(Case).all():
        db.add(CaseAccess(case_id=case.id, user_id=user.id, role="owner", granted_by="setup_wizard"))
    db.commit()

    # Auto-login
    token = create_session_token()
    token_h = hash_token(token)
    session = UserSession(
        user_id=user.id,
        token_hash=token_h,
        created_at=datetime.now(timezone.utc).isoformat(),
        expires_at=(datetime.now(timezone.utc) + timedelta(hours=SESSION_EXPIRY_HOURS)).isoformat(),
        ip_address=client_ip(request),
        user_agent=request.headers.get("user-agent"),
    )
    db.add(session)
    db.commit()

    _set_session_cookie(response, token)
    log_audit("setup_first_admin", actor_user_id=user.id, result="success")
    return {
        "user_id": user.id,
        "username": user.username,
        "is_admin": True,
        "status": "setup_complete",
    }
