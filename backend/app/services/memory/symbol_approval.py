"""Local-operator approval workflow for symbol acquisition.

The Kairon application does not currently provide a mature authenticated
administrator role.  The interim control is a server-side CLI that
records an explicit human authorization, scoped to a single acquisition
request and a specific symbol identity.  The approval is:

* short-lived (TTL, default 600 seconds)
* single-use (consumed atomically when the request is queued)
* request-specific (cannot be reused for another request)
* identity-specific (the requirement fingerprint is bound)
* revocable before consumption

The security boundary is the operator's authorized access to the
deployment host; this is NOT a replacement for future application RBAC.
"""
from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from datetime import timedelta
from typing import Any

from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app.core.config import get_settings
from app.core.database import utc_now_naive
from app.models.memory import (
    MemorySymbolAcquisition,
    MemorySymbolAcquisitionRequest,
    MemorySymbolApproval,
    MemorySymbolRequirement,
)


class ApprovalError(RuntimeError):
    def __init__(self, code: str, message: str):
        super().__init__(message)
        self.code = code
        self.message = message


# ---------------------------------------------------------------------------
# Fingerprint and helpers
# ---------------------------------------------------------------------------

def requirement_fingerprint(requirement: MemorySymbolRequirement) -> str:
    payload = f"{requirement.pdb_name.lower()}|{requirement.pdb_guid.upper()}|{int(requirement.pdb_age)}|{requirement.architecture.lower()}"
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def _coerce_status(value: str | None, default: str) -> str:
    if not value:
        return default
    return str(value).strip().lower()


# ---------------------------------------------------------------------------
# Pending-request lifecycle
# ---------------------------------------------------------------------------

def ensure_pending_request(
    db: Session,
    *,
    case_id: str,
    evidence_id: str,
) -> MemorySymbolAcquisitionRequest:
    """Return the existing pending request for the latest requirement or create one.

    The pending request is created in ``awaiting_network_isolation`` or
    ``awaiting_operator_approval`` depending on the deployment state.
    Re-running this function is safe and idempotent.
    """
    settings = get_settings()
    requirement = (
        db.query(MemorySymbolRequirement)
        .filter(MemorySymbolRequirement.case_id == case_id, MemorySymbolRequirement.evidence_id == evidence_id)
        .order_by(MemorySymbolRequirement.created_at.desc())
        .first()
    )
    if requirement is None:
        raise ApprovalError("SYMBOL_REQUIREMENT_MISSING", "No symbol requirement is recorded for this evidence.")
    fingerprint = requirement_fingerprint(requirement)
    existing = (
        db.query(MemorySymbolAcquisitionRequest)
        .filter(
            MemorySymbolAcquisitionRequest.requirement_id == requirement.id,
            MemorySymbolAcquisitionRequest.status.in_(
                [
                    "awaiting_network_isolation",
                    "awaiting_operator_approval",
                    "approved",
                    "queued",
                    "resolving",
                    "downloading",
                    "validating_pdb",
                    "generating_isf",
                    "validating_isf",
                    "caching",
                ]
            ),
        )
        .order_by(MemorySymbolAcquisitionRequest.created_at.desc())
        .first()
    )
    if existing:
        return existing
    if not settings.memory_symbol_managed_download_enabled or settings.memory_symbol_execution_mode != "managed_download":
        status = "awaiting_network_isolation"
        message = "Managed symbol acquisition is disabled. Offline-only mode remains active."
    elif not settings.memory_symbol_network_isolation_ready:
        status = "awaiting_network_isolation"
        message = "Managed acquisition is unavailable until restricted network egress is configured."
    elif not settings.memory_symbol_local_approval_enabled:
        status = "awaiting_network_isolation"
        message = "Managed acquisition is unavailable until local-operator approval is enabled."
    else:
        status = "awaiting_operator_approval"
        message = "A server administrator must approve managed symbol acquisition."
    request = MemorySymbolAcquisitionRequest(
        requirement_id=requirement.id,
        case_id=case_id,
        evidence_id=evidence_id,
        status=status,
        source_category="official_microsoft_symbols",
        requirement_fingerprint=fingerprint,
        sanitized_message=message,
    )
    db.add(request)
    try:
        db.commit()
    except IntegrityError:
        db.rollback()
        existing = (
            db.query(MemorySymbolAcquisitionRequest)
            .filter(MemorySymbolAcquisitionRequest.requirement_id == requirement.id)
            .order_by(MemorySymbolAcquisitionRequest.created_at.desc())
            .first()
        )
        if existing is None:
            raise ApprovalError("SYMBOL_REQUEST_PERSISTENCE_FAILED", "Could not persist the symbol acquisition request.")
        return existing
    return request


def list_pending_requests(db: Session) -> list[dict[str, Any]]:
    rows = (
        db.query(MemorySymbolAcquisitionRequest, MemorySymbolRequirement)
        .join(MemorySymbolRequirement, MemorySymbolRequirement.id == MemorySymbolAcquisitionRequest.requirement_id)
        .filter(MemorySymbolAcquisitionRequest.status.in_(["awaiting_network_isolation", "awaiting_operator_approval"]))
        .order_by(MemorySymbolAcquisitionRequest.created_at.asc())
        .all()
    )
    results: list[dict[str, Any]] = []
    for request, requirement in rows:
        results.append(
            {
                "request_id": request.id,
                "case_id": request.case_id,
                "evidence_id": request.evidence_id,
                "status": request.status,
                "source_category": request.source_category,
                "pdb_name": requirement.pdb_name,
                "pdb_guid": requirement.pdb_guid,
                "pdb_age": requirement.pdb_age,
                "architecture": requirement.architecture,
                "requirement_fingerprint": request.requirement_fingerprint,
                "created_at": request.created_at,
                "updated_at": request.updated_at,
            }
        )
    return results


def show_request(db: Session, request_id: str) -> dict[str, Any]:
    request = db.get(MemorySymbolAcquisitionRequest, request_id)
    if request is None:
        raise ApprovalError("SYMBOL_REQUEST_NOT_FOUND", "The symbol acquisition request was not found.")
    requirement = db.get(MemorySymbolRequirement, request.requirement_id)
    approval = (
        db.query(MemorySymbolApproval)
        .filter(MemorySymbolApproval.request_id == request.id)
        .order_by(MemorySymbolApproval.created_at.desc())
        .first()
    )
    return {
        "request": {
            "id": request.id,
            "case_id": request.case_id,
            "evidence_id": request.evidence_id,
            "status": request.status,
            "source_category": request.source_category,
            "requirement_fingerprint": request.requirement_fingerprint,
            "created_at": request.created_at,
            "updated_at": request.updated_at,
            "approved_at": request.approved_at,
            "approval_expires_at": request.approval_expires_at,
            "approval_consumed_at": request.approval_consumed_at,
            "queued_at": request.queued_at,
            "started_at": request.started_at,
            "completed_at": request.completed_at,
            "downloaded_bytes": request.downloaded_bytes,
            "redirect_count": request.redirect_count,
            "error_code": request.error_code,
            "sanitized_message": request.sanitized_message,
        },
        "requirement": {
            "pdb_name": requirement.pdb_name,
            "pdb_guid": requirement.pdb_guid,
            "pdb_age": requirement.pdb_age,
            "architecture": requirement.architecture,
            "symbol_key": requirement.symbol_key,
        }
        if requirement is not None
        else None,
        "approval": {
            "id": approval.id,
            "status": approval.status,
            "actor_category": approval.actor_category,
            "actor_label": approval.actor_label,
            "created_at": approval.created_at,
            "expires_at": approval.expires_at,
            "consumed_at": approval.consumed_at,
            "revoked_at": approval.revoked_at,
        }
        if approval is not None
        else None,
    }


# ---------------------------------------------------------------------------
# Approval mutations
# ---------------------------------------------------------------------------

def approve_request(
    db: Session,
    *,
    request_id: str,
    actor_label: str = "server-operator",
    confirm: bool = False,
    yes: bool = False,
) -> MemorySymbolApproval:
    settings = get_settings()
    if not settings.memory_symbol_local_approval_enabled:
        raise ApprovalError("SYMBOL_LOCAL_APPROVAL_DISABLED", "Local-operator approval is disabled in this deployment.")
    if not yes and not confirm:
        raise ApprovalError("SYMBOL_APPROVAL_CONFIRMATION_REQUIRED", "Explicit confirmation is required to approve a symbol acquisition request.")
    request = db.get(MemorySymbolAcquisitionRequest, request_id)
    if request is None:
        raise ApprovalError("SYMBOL_REQUEST_NOT_FOUND", "The symbol acquisition request was not found.")
    if request.status not in {"awaiting_operator_approval", "approved", "queued"}:
        raise ApprovalError(
            "SYMBOL_REQUEST_NOT_PENDING",
            f"The symbol acquisition request is not awaiting approval (current status: {request.status}).",
        )
    # Reject if an active approval already exists.
    existing = (
        db.query(MemorySymbolApproval)
        .filter(MemorySymbolApproval.request_id == request.id, MemorySymbolApproval.status == "active")
        .first()
    )
    if existing:
        raise ApprovalError("SYMBOL_APPROVAL_ALREADY_ACTIVE", "An active approval already exists for this request.")
    now = utc_now_naive()
    expires_at = now + timedelta(seconds=int(settings.memory_symbol_approval_ttl_seconds))
    approval = MemorySymbolApproval(
        request_id=request.id,
        requirement_fingerprint=request.requirement_fingerprint,
        status="active",
        actor_category="local_operator",
        actor_label=actor_label,
        created_at=now,
        expires_at=expires_at,
        audit_metadata_json={"ttl_seconds": int(settings.memory_symbol_approval_ttl_seconds), "single_use": bool(settings.memory_symbol_approval_single_use)},
    )
    request.status = "approved"
    request.approved_at = now
    request.approval_expires_at = expires_at
    request.sanitized_message = "An administrator approved this acquisition locally. The acquisition may now be queued."
    db.add(approval)
    db.commit()
    return approval


def revoke_approval(db: Session, *, request_id: str) -> MemorySymbolApproval:
    approval = (
        db.query(MemorySymbolApproval)
        .filter(MemorySymbolApproval.request_id == request_id, MemorySymbolApproval.status == "active")
        .first()
    )
    if approval is None:
        raise ApprovalError("SYMBOL_APPROVAL_NOT_ACTIVE", "No active approval exists for this request.")
    now = utc_now_naive()
    approval.status = "revoked"
    approval.revoked_at = now
    request = db.get(MemorySymbolAcquisitionRequest, request_id)
    if request is not None and request.status in {"approved", "awaiting_operator_approval"}:
        request.status = "revoked"
        request.sanitized_message = "The acquisition approval was revoked before queueing."
    db.commit()
    return approval


# ---------------------------------------------------------------------------
# Consumption (used by symbol_control when queuing)
# ---------------------------------------------------------------------------

def consume_approval(db: Session, *, request_id: str, requirement_fingerprint_value: str) -> MemorySymbolApproval:
    """Atomically mark the active approval as consumed.

    Uses SELECT ... FOR UPDATE on Postgres; on SQLite (tests) we use a
    transaction-scoped read with an immediate status update.
    """
    now = utc_now_naive()
    query = (
        select(MemorySymbolApproval)
        .where(MemorySymbolApproval.request_id == request_id, MemorySymbolApproval.status == "active")
        .order_by(MemorySymbolApproval.created_at.desc())
    )
    bind = db.get_bind()
    if bind is not None and bind.dialect.name == "postgresql":
        query = query.with_for_update()
    approval = db.execute(query).scalars().first()
    if approval is None:
        raise ApprovalError("SYMBOL_APPROVAL_NOT_ACTIVE", "No active approval exists for this request.")
    if approval.expires_at <= now:
        approval.status = "expired"
        request = db.get(MemorySymbolAcquisitionRequest, request_id)
        if request is not None:
            request.status = "expired"
            request.sanitized_message = "The acquisition approval expired before queueing."
        db.commit()
        raise ApprovalError("SYMBOL_APPROVAL_EXPIRED", "The active approval has expired.")
    if approval.requirement_fingerprint != requirement_fingerprint_value:
        raise ApprovalError("SYMBOL_APPROVAL_FINGERPRINT_MISMATCH", "The approval is bound to a different symbol identity.")
    approval.status = "consumed"
    approval.consumed_at = now
    request = db.get(MemorySymbolAcquisitionRequest, request_id)
    if request is not None:
        request.approval_consumed_at = now
    db.commit()
    return approval


def active_approval_for_request(db: Session, request_id: str) -> MemorySymbolApproval | None:
    now = utc_now_naive()
    return (
        db.query(MemorySymbolApproval)
        .filter(
            MemorySymbolApproval.request_id == request_id,
            MemorySymbolApproval.status == "active",
            MemorySymbolApproval.expires_at > now,
        )
        .first()
    )


def summarize_pending_for_operator(db: Session, request_id: str) -> dict[str, Any]:
    """Sanitized summary shown by the CLI before approval.

    Does not include paths, evidence bytes, or any user-supplied data.
    """
    data = show_request(db, request_id)
    requirement = data["requirement"] or {}
    request = data["request"]
    return {
        "request_id": request["id"],
        "case_id": request["case_id"],
        "evidence_id": request["evidence_id"],
        "pdb_name": requirement.get("pdb_name"),
        "pdb_guid": requirement.get("pdb_guid"),
        "pdb_age": requirement.get("pdb_age"),
        "architecture": requirement.get("architecture"),
        "official_source_category": request["source_category"],
        "transmitted_metadata": ["pdb_name", "guid", "age"],
        "no_ram_transmitted": True,
        "third_party_cache": True,
        "current_status": request["status"],
    }
