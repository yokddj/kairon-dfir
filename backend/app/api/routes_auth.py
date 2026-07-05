from __future__ import annotations

from collections import defaultdict
import time

from fastapi import APIRouter, Depends, HTTPException, Request, Response
from sqlalchemy.orm import Session
from sqlalchemy import text
from pydantic import BaseModel, Field
from datetime import datetime, timedelta, timezone

from app.core.database import get_db
from app.models.user import User
from app.models.session import Session as UserSession
from app.services.auth_utils import (
    hash_password, verify_password, create_session_token,
    hash_token, SESSION_EXPIRY_HOURS,
)
from app.services.audit import log_audit

_login_attempts: dict[str, list[float]] = defaultdict(list)
_LOGIN_RATE_LIMIT = 5
_LOGIN_RATE_WINDOW = 300


def _check_login_rate(ip: str) -> bool:
    now = time.time()
    window_start = now - _LOGIN_RATE_WINDOW
    _login_attempts[ip] = [t for t in _login_attempts[ip] if t > window_start]
    _login_attempts[ip].append(now)
    return len(_login_attempts[ip]) <= _LOGIN_RATE_LIMIT


_setup_attempts: dict[str, list[float]] = defaultdict(list)
_SETUP_RATE_LIMIT = 10
_SETUP_RATE_WINDOW = 60


def _check_setup_rate(ip: str) -> bool:
    now = time.time()
    window_start = now - _SETUP_RATE_WINDOW
    _setup_attempts[ip] = [t for t in _setup_attempts[ip] if t > window_start]
    _setup_attempts[ip].append(now)
    return len(_setup_attempts[ip]) <= _SETUP_RATE_LIMIT

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
    client_ip = request.client.host if request.client else "unknown"
    if not _check_login_rate(client_ip):
        log_audit("login_failure", actor_user_id=None, result="failure",
                  ip_address=client_ip, user_agent=request.headers.get("user-agent"))
        raise HTTPException(status_code=429, detail="Too many login attempts")

    user = db.query(User).filter(User.username == payload.username).first()
    if not user or not verify_password(payload.password, user.password_hash):
        log_audit("login_failure", actor_user_id=None, result="failure",
                  ip_address=client_ip, user_agent=request.headers.get("user-agent"))
        raise HTTPException(status_code=401, detail="Invalid credentials")
    if not user.is_active:
        log_audit("login_failure", actor_user_id=user.id, result="failure",
                  ip_address=client_ip, user_agent=request.headers.get("user-agent"))
        raise HTTPException(status_code=401, detail="Account disabled")

    token = create_session_token()
    token_h = hash_token(token)
    session = UserSession(
        user_id=user.id,
        token_hash=token_h,
        created_at=datetime.now(timezone.utc).isoformat(),
        expires_at=(datetime.now(timezone.utc) + timedelta(hours=SESSION_EXPIRY_HOURS)).isoformat(),
        ip_address=client_ip,
        user_agent=request.headers.get("user-agent"),
    )
    db.add(session)
    user.last_login_at = datetime.now(timezone.utc).isoformat()
    db.commit()

    log_audit("login_success", actor_user_id=user.id, result="success",
              ip_address=client_ip, user_agent=request.headers.get("user-agent"))

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
    # Rate limit
    client_ip = request.client.host if request.client else "unknown"
    if not _check_setup_rate(client_ip):
        raise HTTPException(status_code=429, detail="Too many requests")
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
        ip_address=request.client.host if request.client else None,
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
