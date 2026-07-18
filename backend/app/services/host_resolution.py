from __future__ import annotations

from dataclasses import dataclass
import re
from typing import Any, Iterable

from fastapi import HTTPException
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app.core.database import utc_now
from app.models.assignment_history import AssignmentHistory
from app.models.case_host import CaseHost
from app.models.case_host_alias import CaseHostAlias
from app.models.evidence import Evidence, EvidenceCustodyEventType, EvidenceType
from app.services.evidence_integrity import record_evidence_event
from app.services.host_identity import create_manual_case_host, is_invalid_host_value, normalize_host_alias
from app.services.reassignment import backfill_evidence_documents, invalidate_host_caches


OUTCOME_RESOLVED = "resolved"
OUTCOME_CREATED = "created"
OUTCOME_UNASSIGNED = "unassigned"
OUTCOME_AMBIGUOUS = "ambiguous"
OUTCOME_REQUIRED = "required"
OUTCOME_CONFLICT = "conflict"

HOST_REQUIRED = "required"
HOST_OPTIONAL = "optional"
HOST_ERROR_REQUIRED = "HOST_REQUIRED"
HOST_ERROR_AMBIGUOUS = "HOST_AMBIGUOUS"
HOST_ERROR_INVALID = "HOST_INVALID"
HOST_ERROR_NOT_FOUND = "HOST_NOT_FOUND"

_HOST_LABEL_PATTERN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_-]{0,62}$")


@dataclass(frozen=True)
class HostPolicy:
    key: str
    explicit_host_required: bool = False
    provided_host_allowed: bool = True
    detected_hostname_allowed: bool = True
    host_creation_allowed: bool = True
    auto_assign_allowed: bool = False
    case_singleton_auto_assign_allowed: bool = False
    unassigned_allowed: bool = True
    archive_policy_inheritance: bool = False
    platform_conflict_behavior: str = "record_conflict"


EVIDENCE_HOST_POLICIES: dict[str, HostPolicy] = {
    EvidenceType.memory_dump.value: HostPolicy(
        key=EvidenceType.memory_dump.value,
        explicit_host_required=True,
        detected_hostname_allowed=False,
        auto_assign_allowed=False,
        unassigned_allowed=False,
    ),
    EvidenceType.disk_image.value: HostPolicy(key=EvidenceType.disk_image.value, auto_assign_allowed=True),
    EvidenceType.velociraptor_zip.value: HostPolicy(key=EvidenceType.velociraptor_zip.value, auto_assign_allowed=True),
    EvidenceType.raw_collection.value: HostPolicy(key=EvidenceType.raw_collection.value, auto_assign_allowed=True),
    EvidenceType.kape_archive.value: HostPolicy(key=EvidenceType.kape_archive.value, auto_assign_allowed=True, archive_policy_inheritance=True),
    EvidenceType.parsed_folder.value: HostPolicy(key=EvidenceType.parsed_folder.value, auto_assign_allowed=True),
    EvidenceType.evtx.value: HostPolicy(key=EvidenceType.evtx.value, auto_assign_allowed=True),
    EvidenceType.csv.value: HostPolicy(key=EvidenceType.csv.value),
    EvidenceType.json.value: HostPolicy(key=EvidenceType.json.value),
    EvidenceType.jsonl.value: HostPolicy(key=EvidenceType.jsonl.value),
    EvidenceType.linux_triage.value: HostPolicy(key=EvidenceType.linux_triage.value, auto_assign_allowed=True),
    EvidenceType.macos_triage.value: HostPolicy(key=EvidenceType.macos_triage.value, auto_assign_allowed=True),
    EvidenceType.unknown.value: HostPolicy(key=EvidenceType.unknown.value),
    "windows_collection": HostPolicy(key="windows_collection", auto_assign_allowed=True),
    "linux_collection": HostPolicy(key="linux_collection", auto_assign_allowed=True),
    "artifact_collection": HostPolicy(key="artifact_collection", auto_assign_allowed=True),
    "generic_archive": HostPolicy(key="generic_archive", auto_assign_allowed=True, archive_policy_inheritance=True),
    "promoted_archive_content": HostPolicy(key="promoted_archive_content", auto_assign_allowed=True, archive_policy_inheritance=True),
}


@dataclass(frozen=True)
class HostResolution:
    host: CaseHost | None
    host_id: str | None
    provided_host: str | None
    detected_hostname: str | None
    resolution_method: str
    outcome: str
    confidence: str | None = None
    reason: str | None = None
    created: bool = False
    evidence_type: str | None = None
    normalized_candidate: str | None = None
    auto_assign: bool = False
    platform_decision: dict[str, Any] | None = None

    @property
    def display_name(self) -> str | None:
        return self.host.display_name if self.host is not None else self.provided_host or self.detected_hostname

    def assignment_fields(self, *, actor: str, reason: str | None = None, method: str | None = None) -> dict[str, Any]:
        if not self.host_id:
            return {
                "host_id": None,
                "host_assignment_status": None,
                "host_assignment_method": None,
                "host_assignment_confidence": None,
                "host_assignment_reason": None,
                "host_assignment_updated_at": None,
                "host_assignment_updated_by": None,
            }
        return {
            "host_id": self.host_id,
            "host_assignment_status": "confirmed",
            "host_assignment_method": method or self.resolution_method,
            "host_assignment_confidence": self.confidence or "high",
            "host_assignment_reason": reason or self.reason,
            "host_assignment_updated_at": utc_now().isoformat(),
            "host_assignment_updated_by": actor,
        }

    def provenance(self) -> dict[str, Any]:
        return {
            "host_id": self.host_id,
            "provided_host": self.provided_host,
            "detected_hostname": self.detected_hostname,
            "resolution_method": self.resolution_method,
            "outcome": self.outcome,
            "confidence": self.confidence,
            "created": self.created,
            "reason": self.reason,
            "evidence_type": self.evidence_type,
            "normalized_candidate": self.normalized_candidate,
            "auto_assign": self.auto_assign,
            "platform_decision": self.platform_decision or {},
        }


def evidence_type_key(value: EvidenceType | str | None) -> str | None:
    if isinstance(value, EvidenceType):
        return value.value
    text = str(value or "").strip()
    return text or None


def host_policy_for(evidence_type: EvidenceType | str | None) -> HostPolicy:
    key = evidence_type_key(evidence_type) or EvidenceType.unknown.value
    return EVIDENCE_HOST_POLICIES.get(key, EVIDENCE_HOST_POLICIES[EvidenceType.unknown.value])


def _structured_error(status_code: int, error_code: str, message: str, **details: Any) -> HTTPException:
    return HTTPException(status_code=status_code, detail={"error_code": error_code, "code": error_code, "message": message, **details})


def normalize_hostname(value: str | None) -> str | None:
    text = str(value or "").strip().strip('"').strip("'").rstrip(".")
    if not text:
        return None
    if any(ord(ch) < 32 or ord(ch) == 127 for ch in text):
        return None
    if any(separator in text for separator in ("/", "\\", ":", "@")):
        return None
    text = ".".join(part for part in text.split(".") if part)
    if len(text) > 255 or is_invalid_host_value(text):
        return None
    labels = text.split(".")
    if any(not _HOST_LABEL_PATTERN.match(label) for label in labels):
        return None
    return text or None


def normalize_provided_host(value: str | None) -> str | None:
    return normalize_hostname(value)


def require_provided_host(value: str | None, *, message: str = "Host name is required for evidence indexing.") -> str:
    normalized = normalize_provided_host(value)
    if not normalized:
        raise HTTPException(status_code=400, detail=message)
    return normalized


def validate_case_host(db: Session, case_id: str, host_id: str | None) -> CaseHost | None:
    value = str(host_id or "").strip() or None
    if not value:
        return None
    host = db.get(CaseHost, value)
    if not host or host.case_id != case_id:
        raise _structured_error(400, HOST_ERROR_NOT_FOUND, "Host not found in this case")
    return host


def validate_case_host_id(db: Session, case_id: str, host_id: str | None) -> str | None:
    host = validate_case_host(db, case_id, host_id)
    return host.id if host else None


def _hostname_candidates(*values: str | None, candidates: Iterable[str] | None = None) -> list[str]:
    ordered: list[str] = []
    for value in [*values, *(list(candidates or []))]:
        normalized = normalize_hostname(value)
        if normalized and normalized not in ordered:
            ordered.append(normalized)
    return ordered


def _find_host_by_name(db: Session, case_id: str, hostname: str) -> CaseHost | None:
    normalized = normalize_host_alias(hostname)
    if not normalized:
        return None
    query = db.query(CaseHost).filter(CaseHost.case_id == case_id, CaseHost.canonical_name == normalized)
    if not hasattr(query, "first"):
        return None
    host = query.first()
    if host:
        return host
    alias_query = db.query(CaseHostAlias).filter(CaseHostAlias.case_id == case_id, CaseHostAlias.normalized_alias == normalized)
    if not hasattr(alias_query, "first"):
        return None
    alias = alias_query.first()
    if alias:
        return db.get(CaseHost, alias.case_host_id)
    return None


def _all_case_hosts(db: Session, case_id: str) -> list[CaseHost]:
    return db.query(CaseHost).filter(CaseHost.case_id == case_id).order_by(CaseHost.created_at.asc(), CaseHost.id.asc()).all()


def _platform_decision(
    *,
    existing_platform: str | None = None,
    detected_platform: str | None = None,
    platform_confidence: str | None = None,
) -> dict[str, Any]:
    existing = str(existing_platform or "unknown").strip().lower() or "unknown"
    candidate = str(detected_platform or "unknown").strip().lower() or "unknown"
    confidence = str(platform_confidence or "unknown").strip().lower() or "unknown"
    strong = confidence in {"high", "confirmed", "explicit"}
    if candidate in {"", "unknown", "auto", "none"}:
        decision = "preserve"
        reason = "No platform candidate was supplied."
    elif existing in {"", "unknown", "auto", "none"}:
        decision = "set_candidate"
        reason = "Host platform is unknown and evidence platform is usable."
    elif existing == candidate:
        decision = "preserve"
        reason = "Evidence platform matches existing host platform."
    elif strong:
        decision = OUTCOME_CONFLICT
        reason = "High-confidence evidence platform conflicts with existing host platform."
    else:
        decision = "preserve"
        reason = "Weak evidence platform does not overwrite existing host platform."
    return {"existing_platform": existing, "candidate_platform": candidate, "confidence": confidence, "decision": decision, "reason": reason}


def _resolution(
    *,
    host: CaseHost | None,
    provided_host: str | None,
    detected_hostname: str | None,
    resolution_method: str,
    outcome: str,
    evidence_type: EvidenceType | str | None,
    normalized_candidate: str | None = None,
    confidence: str | None = None,
    reason: str | None = None,
    created: bool = False,
    auto_assign: bool = False,
    platform_decision: dict[str, Any] | None = None,
) -> HostResolution:
    return HostResolution(
        host=host,
        host_id=host.id if host else None,
        provided_host=provided_host,
        detected_hostname=detected_hostname,
        resolution_method=resolution_method,
        outcome=outcome,
        confidence=confidence,
        reason=reason,
        created=created,
        evidence_type=evidence_type_key(evidence_type),
        normalized_candidate=normalized_candidate,
        auto_assign=auto_assign,
        platform_decision=platform_decision or _platform_decision(),
    )


def _can_create_case_host(db: Session) -> bool:
    try:
        return hasattr(db.query(CaseHostAlias), "options")
    except Exception:  # noqa: BLE001
        return False


def _get_or_create_host(db: Session, case_id: str, hostname: str, *, source: str, confidence: str) -> tuple[CaseHost | None, bool]:
    existing = _find_host_by_name(db, case_id, hostname)
    if existing:
        return existing, False
    if not _can_create_case_host(db):
        return None, False
    try:
        serialized_host, created = create_manual_case_host(db, case_id, hostname, analyst="host_resolution", reason=f"Resolved from {source}")
        host = db.get(CaseHost, str(serialized_host.get("id") or ""))
        if host is None:
            raise ValueError("Created host could not be loaded")
        if created:
            host.source = source
            host.confidence = confidence
            db.add(host)
            db.flush()
        return host, created
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    except IntegrityError:
        db.rollback()
        existing = _find_host_by_name(db, case_id, hostname)
        if existing:
            return existing, False
        raise


def resolve_host(
    db: Session,
    *,
    case_id: str,
    evidence_type: EvidenceType | str | None,
    host_id: str | None = None,
    provided_host: str | None = None,
    detected_hostname: str | None = None,
    hostname_candidates: Iterable[str] | None = None,
    allow_create: bool = True,
    auto_assign: bool = True,
    require_host: bool | None = None,
    detected_platform: str | None = None,
    platform_confidence: str | None = None,
    existing_host_platform: str | None = None,
) -> HostResolution:
    policy = host_policy_for(evidence_type)
    must_have_host = policy.explicit_host_required if require_host is None else bool(require_host)
    can_create = bool(allow_create and policy.host_creation_allowed)
    platform = _platform_decision(existing_platform=existing_host_platform, detected_platform=detected_platform, platform_confidence=platform_confidence)

    explicit_host = validate_case_host(db, case_id, host_id)
    if explicit_host is not None:
        return _resolution(
            host=explicit_host,
            provided_host=normalize_provided_host(provided_host) or explicit_host.display_name,
            detected_hostname=normalize_hostname(detected_hostname),
            resolution_method="existing_host",
            outcome=OUTCOME_RESOLVED,
            confidence="high",
            reason="Explicit host selected",
            evidence_type=evidence_type,
            normalized_candidate=explicit_host.canonical_name,
            platform_decision=platform,
        )

    normalized_provided = normalize_provided_host(provided_host)
    if provided_host and not normalized_provided:
        raise _structured_error(400, HOST_ERROR_INVALID, "Host name is invalid.")
    if normalized_provided and policy.provided_host_allowed:
        host, created = _get_or_create_host(db, case_id, normalized_provided, source="provided_host", confidence="high") if can_create else (_find_host_by_name(db, case_id, normalized_provided), False)
        if host:
            return _resolution(host=host, provided_host=normalized_provided, detected_hostname=normalize_hostname(detected_hostname), resolution_method="provided_host", outcome=OUTCOME_CREATED if created else OUTCOME_RESOLVED, confidence="high", reason="Provided host resolved", created=created, evidence_type=evidence_type, normalized_candidate=normalize_host_alias(normalized_provided), platform_decision=platform)

    candidates = _hostname_candidates(detected_hostname if policy.detected_hostname_allowed else None, candidates=hostname_candidates if policy.detected_hostname_allowed else None)
    for candidate in candidates:
        host, created = _get_or_create_host(db, case_id, candidate, source="detected_hostname", confidence="medium") if can_create else (_find_host_by_name(db, case_id, candidate), False)
        if host:
            return _resolution(host=host, provided_host=None, detected_hostname=candidate, resolution_method="detected_hostname", outcome=OUTCOME_CREATED if created else OUTCOME_RESOLVED, confidence="medium", reason="Detected hostname resolved", created=created, evidence_type=evidence_type, normalized_candidate=normalize_host_alias(candidate), platform_decision=platform)

    if auto_assign and policy.auto_assign_allowed:
        unique_candidates = [candidate for candidate in candidates if candidate]
        if len(unique_candidates) == 1:
            host = _find_host_by_name(db, case_id, unique_candidates[0])
            if host:
                return _resolution(host=host, provided_host=None, detected_hostname=unique_candidates[0], resolution_method="auto_assign_detected_hostname", outcome=OUTCOME_RESOLVED, confidence="medium", reason="Auto Assign resolved one unambiguous host candidate", evidence_type=evidence_type, normalized_candidate=normalize_host_alias(unique_candidates[0]), auto_assign=True, platform_decision=platform)
        elif len(unique_candidates) > 1:
            if must_have_host:
                raise _structured_error(400, HOST_ERROR_AMBIGUOUS, "Multiple plausible host candidates were found.", candidates=unique_candidates)
            return _resolution(host=None, provided_host=None, detected_hostname=None, resolution_method="auto_assign_ambiguous", outcome=OUTCOME_AMBIGUOUS, confidence=None, reason="Multiple plausible host candidates were found", evidence_type=evidence_type, auto_assign=True, platform_decision=platform)
        if policy.case_singleton_auto_assign_allowed:
            hosts = _all_case_hosts(db, case_id)
            if len(hosts) == 1:
                return _resolution(host=hosts[0], provided_host=None, detected_hostname=None, resolution_method="auto_assign_case_singleton", outcome=OUTCOME_RESOLVED, confidence="low", reason="Auto Assign used the only eligible case host", evidence_type=evidence_type, normalized_candidate=hosts[0].canonical_name, auto_assign=True, platform_decision=platform)
            if len(hosts) > 1:
                if must_have_host:
                    raise _structured_error(400, HOST_ERROR_AMBIGUOUS, "Case has multiple eligible hosts.")
                return _resolution(host=None, provided_host=None, detected_hostname=None, resolution_method="auto_assign_ambiguous", outcome=OUTCOME_AMBIGUOUS, reason="Case has multiple eligible hosts", evidence_type=evidence_type, auto_assign=True, platform_decision=platform)

    if must_have_host:
        raise _structured_error(400, HOST_ERROR_REQUIRED, "Host is required for this evidence type.")
    return _resolution(host=None, provided_host=normalized_provided, detected_hostname=candidates[0] if candidates else None, resolution_method="unassigned", outcome=OUTCOME_UNASSIGNED, confidence=None, reason="No host resolved", evidence_type=evidence_type, normalized_candidate=normalize_host_alias(normalized_provided or (candidates[0] if candidates else None)), platform_decision=platform)


def host_display_name(db: Session, host_id: str | None) -> str | None:
    if not host_id:
        return None
    item = db.get(CaseHost, host_id)
    return item.display_name if item else None


def record_host_assignment_event(
    db: Session,
    evidence: Evidence,
    *,
    previous_host_id: str | None,
    new_host_id: str | None,
    actor_user_id: str | None,
    actor: str,
    reason: str | None,
    method: str,
    host_created: bool = False,
) -> None:
    if previous_host_id and new_host_id and previous_host_id != new_host_id:
        event_type = EvidenceCustodyEventType.host_assignment_changed
    elif new_host_id:
        event_type = EvidenceCustodyEventType.host_assigned
    else:
        event_type = EvidenceCustodyEventType.host_unassigned
    previous_name = host_display_name(db, previous_host_id)
    new_name = host_display_name(db, new_host_id)
    summary = f"Evidence assigned to host {new_name}." if new_name else "Evidence host assignment cleared."
    record_evidence_event(
        db,
        evidence,
        event_type,
        summary,
        actor_user_id=actor_user_id,
        details={
            "previous_host_id": previous_host_id,
            "previous_host_name": previous_name,
            "new_host_id": new_host_id,
            "new_host_name": new_name,
            "detected_host": evidence.detected_host,
            "actor_user_id": actor_user_id,
            "actor": actor,
            "reason": reason,
            "method": method,
            "host_created": host_created,
        },
    )
    if host_created and new_host_id:
        record_evidence_event(
            db,
            evidence,
            EvidenceCustodyEventType.host_created,
            f"Host {new_name or new_host_id} created from evidence assignment.",
            actor_user_id=actor_user_id,
            details={"new_host_id": new_host_id, "new_host_name": new_name, "detected_host": evidence.detected_host, "actor_user_id": actor_user_id},
        )


def assign_evidence_host(
    db: Session,
    evidence: Evidence,
    *,
    host_id: str | None,
    actor_user_id: str | None,
    actor: str,
    reason: str | None = None,
    method: str = "analyst_assigned",
    confidence: str = "high",
    host_created: bool = False,
) -> Evidence:
    previous_host_id = evidence.host_id
    previous_status = evidence.host_assignment_status
    if previous_host_id == host_id and previous_status == ("confirmed" if host_id else "unassigned"):
        return evidence
    if host_id:
        validate_case_host(db, evidence.case_id, host_id)
    evidence.host_id = host_id
    evidence.host_assignment_status = "confirmed" if host_id else "unassigned"
    evidence.host_assignment_method = method if host_id else "analyst_unassigned"
    evidence.host_assignment_confidence = confidence if host_id else None
    evidence.host_assignment_reason = reason
    evidence.host_assignment_updated_at = utc_now().isoformat()
    evidence.host_assignment_updated_by = actor
    db.add(
        AssignmentHistory(
            evidence_id=evidence.id,
            case_id=evidence.case_id,
            previous_host_id=previous_host_id,
            new_host_id=host_id,
            previous_status=previous_status,
            new_status=evidence.host_assignment_status,
            method=evidence.host_assignment_method,
            confidence=evidence.host_assignment_confidence,
            actor=actor,
            reason=reason,
            created_at_str=utc_now().isoformat(),
        )
    )
    record_host_assignment_event(
        db,
        evidence,
        previous_host_id=previous_host_id,
        new_host_id=host_id,
        actor_user_id=actor_user_id,
        actor=actor,
        reason=reason,
        method=evidence.host_assignment_method or method,
        host_created=host_created,
    )
    db.commit()
    db.refresh(evidence)
    try:
        backfill_evidence_documents(db, evidence.id)
    except Exception:
        import logging

        logging.getLogger(__name__).exception("host assignment backfill failed for evidence %s", evidence.id)
    invalidate_host_caches(evidence.id, host_id or previous_host_id or "")
    return evidence


def preferred_artifact_host(metadata: dict[str, Any] | None, detected_host: str | None) -> tuple[str | None, str | None]:
    meta = metadata or {}
    provided = normalize_provided_host(str(meta.get("provided_host") or ""))
    detected = normalize_hostname(detected_host)
    return provided or detected, provided
