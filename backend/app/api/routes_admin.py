from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Request
from sqlalchemy.orm import Session
from pydantic import BaseModel
from datetime import datetime, timezone

from app.core.database import get_db
from app.models.user import User
from app.models.session import Session as UserSession
from app.services.auth_utils import hash_password
from app.services.auth_dependencies import get_current_user, require_admin
from app.services.audit import log_audit

router = APIRouter(tags=["admin"], prefix="/api/admin")

class CreateUserRequest(BaseModel):
    username: str
    password: str
    email: str | None = None
    display_name: str | None = None
    is_admin: bool = False

class DisableUserRequest(BaseModel):
    disabled: bool = True

class ResetPasswordRequest(BaseModel):
    new_password: str

class UpdateUserRequest(BaseModel):
    email: str | None = None
    display_name: str | None = None
    is_admin: bool | None = None

class CaseAccessRequest(BaseModel):
    user_id: str
    role: str = "user"  # user or admin effective; legacy analyst/viewer normalized to user

@router.get("/users")
def list_users(db: Session = Depends(get_db), _admin: User = Depends(require_admin)):
    users = db.query(User).order_by(User.username).all()
    return [
        {
            "id": u.id, "username": u.username, "email": u.email,
            "display_name": u.display_name, "is_admin": u.is_admin,
            "is_active": u.is_active, "created_at": u.created_at,
            "last_login_at": u.last_login_at, "password_changed_at": u.password_changed_at,
        }
        for u in users
    ]

@router.post("/users")
def create_user(payload: CreateUserRequest, request: Request, db: Session = Depends(get_db), admin_user: User = Depends(require_admin)):
    if db.query(User).filter(User.username == payload.username).first():
        raise HTTPException(status_code=400, detail="Username already exists")
    if len(payload.password) < 12:
        raise HTTPException(status_code=400, detail="Password must be at least 12 characters")
    user = User(
        username=payload.username,
        email=payload.email,
        display_name=payload.display_name or payload.username,
        password_hash=hash_password(payload.password),
        is_admin=payload.is_admin,
        is_active=True,
    )
    db.add(user)
    db.commit()
    db.refresh(user)
    log_audit("user_create", actor_user_id=admin_user.id, result="success", resource_type="user", resource_id=user.id,
              ip_address=request.client.host if request.client else None,
              user_agent=request.headers.get("user-agent"))
    return {"id": user.id, "username": user.username, "is_admin": user.is_admin}

@router.patch("/users/{user_id}")
def update_user(user_id: str, payload: UpdateUserRequest, db: Session = Depends(get_db), admin_user: User = Depends(require_admin)):
    user = db.get(User, user_id)
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    
    if payload.is_admin is False and user.is_admin:
        active_admins = db.query(User).filter(User.is_admin == True, User.is_active == True, User.id != user.id).count()
        if active_admins == 0:
            raise HTTPException(status_code=409, detail="Cannot remove the last active administrator")
    
    if payload.email is not None:
        user.email = payload.email
    if payload.display_name is not None:
        user.display_name = payload.display_name
    if payload.is_admin is not None:
        user.is_admin = payload.is_admin
    
    user.updated_at = datetime.now(timezone.utc).isoformat()
    db.commit()
    
    log_audit("user_update", actor_user_id=admin_user.id, resource_type="user", resource_id=user.id,
              metadata={"username": user.username, "is_admin": user.is_admin})
    return {"id": user.id, "username": user.username, "is_admin": user.is_admin}

@router.post("/users/{user_id}/disable")
def disable_user(user_id: str, payload: DisableUserRequest | None = None, request: Request = None, db: Session = Depends(get_db), admin_user: User = Depends(require_admin)):
    disabled = payload.disabled if payload else True
    user = db.get(User, user_id)
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    if user.id == admin_user.id and disabled:
        raise HTTPException(status_code=400, detail="Cannot disable yourself")
    if disabled and user.is_admin:
        active_admins = db.query(User).filter(User.is_admin == True, User.is_active == True, User.id != user.id).count()
        if active_admins == 0:
            raise HTTPException(status_code=400, detail="Cannot disable the last active admin")
    user.is_active = not disabled
    user.updated_at = datetime.now(timezone.utc).isoformat()
    if disabled:
        db.query(UserSession).filter(UserSession.user_id == user_id, UserSession.revoked_at == None).update(
            {"revoked_at": datetime.now(timezone.utc).isoformat()}
        )
    db.commit()
    log_audit("user_disable", actor_user_id=admin_user.id, result="success", resource_type="user", resource_id=user.id,
              ip_address=request.client.host if request and request.client else None,
              user_agent=request.headers.get("user-agent") if request else None)
    return {"id": user.id, "is_active": user.is_active}

@router.post("/users/{user_id}/enable")
def enable_user(user_id: str, db: Session = Depends(get_db), _admin: User = Depends(require_admin)):
    user = db.get(User, user_id)
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    user.is_active = True
    user.updated_at = datetime.now(timezone.utc).isoformat()
    db.commit()
    log_audit("user_enable", actor_user_id=_admin.id, resource_type="user", resource_id=user_id,
              metadata={"username": user.username})
    return {"id": user.id, "is_active": True}

@router.post("/users/{user_id}/reset-password")
def reset_password(user_id: str, payload: ResetPasswordRequest, request: Request, db: Session = Depends(get_db), admin_user: User = Depends(require_admin)):
    user = db.get(User, user_id)
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    if len(payload.new_password) < 12:
        raise HTTPException(status_code=400, detail="Password must be at least 12 characters")
    user.password_hash = hash_password(payload.new_password)
    user.password_changed_at = datetime.now(timezone.utc).isoformat()
    user.updated_at = datetime.now(timezone.utc).isoformat()
    db.query(UserSession).filter(UserSession.user_id == user_id, UserSession.revoked_at == None).update(
        {"revoked_at": datetime.now(timezone.utc).isoformat()}
    )
    db.commit()
    log_audit("admin_password_reset", actor_user_id=admin_user.id, result="success", resource_type="user", resource_id=user.id,
              ip_address=request.client.host if request.client else None,
              user_agent=request.headers.get("user-agent"))
    return {"id": user.id, "status": "password_reset"}

@router.post("/users/{user_id}/revoke-sessions")
def revoke_user_sessions(user_id: str, db: Session = Depends(get_db), admin_user: User = Depends(require_admin)):
    user = db.get(User, user_id)
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    
    revoked = db.query(UserSession).filter(
        UserSession.user_id == user_id,
        UserSession.revoked_at == None,
    ).update({"revoked_at": datetime.now(timezone.utc).isoformat()})
    db.commit()
    
    log_audit("user_sessions_revoked", actor_user_id=admin_user.id, resource_type="user", resource_id=user_id,
              metadata={"username": user.username, "sessions_revoked": revoked})
    return {"id": user_id, "sessions_revoked": revoked}

@router.get("/cases/{case_id}/access")
def list_case_access(case_id: str, db: Session = Depends(get_db), user: User = Depends(get_current_user)):
    from app.models.case_access import CaseAccess
    if not user.is_admin:
        access = db.query(CaseAccess).filter(CaseAccess.case_id == case_id, CaseAccess.user_id == user.id, CaseAccess.role == "owner").first()
        if not access:
            raise HTTPException(status_code=403, detail="Access denied")

    accesses = db.query(CaseAccess).filter(CaseAccess.case_id == case_id).all()
    return [{"id": a.id, "case_id": a.case_id, "user_id": a.user_id, "role": a.role, "granted_by": a.granted_by, "created_at": a.created_at} for a in accesses]

@router.post("/cases/{case_id}/access")
def grant_case_access(case_id: str, payload: CaseAccessRequest, db: Session = Depends(get_db), admin_user: User = Depends(require_admin)):
    from app.models.case_access import CaseAccess
    existing = db.query(CaseAccess).filter(CaseAccess.case_id == case_id, CaseAccess.user_id == payload.user_id).first()
    if existing:
        existing.role = payload.role
        existing.granted_by = admin_user.id
    else:
        db.add(CaseAccess(case_id=case_id, user_id=payload.user_id, role=payload.role, granted_by=admin_user.id))
    db.commit()
    log_audit("case_access_grant", actor_user_id=admin_user.id, case_id=case_id,
              resource_type="case_access", resource_id=payload.user_id,
              metadata={"role": payload.role})
    return {"status": "granted", "case_id": case_id, "user_id": payload.user_id, "role": payload.role}

@router.delete("/cases/{case_id}/access/{user_id}")
def revoke_case_access(case_id: str, user_id: str, db: Session = Depends(get_db), _admin: User = Depends(require_admin)):
    from app.models.case_access import CaseAccess
    access = db.query(CaseAccess).filter(CaseAccess.case_id == case_id, CaseAccess.user_id == user_id).first()
    if access:
        if access.role == "owner":
            other_owners = db.query(CaseAccess).filter(CaseAccess.case_id == case_id, CaseAccess.role == "owner", CaseAccess.id != access.id).count()
            if other_owners == 0:
                raise HTTPException(status_code=400, detail="Cannot revoke the last owner of a case")
        db.delete(access)
        db.commit()
        log_audit("case_access_revoke", actor_user_id=_admin.id, case_id=case_id,
                  resource_type="case_access", resource_id=user_id)
    return {"status": "revoked", "case_id": case_id, "user_id": user_id}
