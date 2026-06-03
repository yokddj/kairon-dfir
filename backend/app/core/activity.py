from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app.models.activity import ActivitySeverity, AppActivityEvent
from app.models.evidence import Evidence


def log_activity(
    db: Session,
    *,
    activity_type: str,
    title: str,
    message: str,
    severity: str = "info",
    case_id: str | None = None,
    evidence_id: str | None = None,
    actor: str | None = "system",
    metadata: dict | None = None,
    commit: bool = True,
) -> AppActivityEvent:
    normalized_evidence_id = evidence_id
    if normalized_evidence_id and db.get(Evidence, normalized_evidence_id) is None:
        normalized_evidence_id = None

    event = AppActivityEvent(
        case_id=case_id,
        evidence_id=normalized_evidence_id,
        actor=actor,
        activity_type=activity_type,
        severity=ActivitySeverity(severity),
        title=title,
        message=message,
        metadata_json=metadata or {},
    )
    db.add(event)
    if commit:
        try:
            db.commit()
        except IntegrityError as exc:
            db.rollback()
            detail = str(exc)
            if evidence_id and "app_activity_events_evidence_id_fkey" in detail:
                retry_event = AppActivityEvent(
                    case_id=case_id,
                    evidence_id=None,
                    actor=actor,
                    activity_type=activity_type,
                    severity=ActivitySeverity(severity),
                    title=title,
                    message=message,
                    metadata_json=metadata or {},
                )
                db.add(retry_event)
                db.commit()
                return retry_event
            raise
    return event
