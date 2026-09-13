"""DetectionResult.status was always a bare String(32) with zero
validation anywhere -- any string could be PATCHed onto it, including
"stale"/"stale_event_link"/"promoted_to_finding", which are meant to be
set only by backend automation (reprocess cleanup, reconciliation, and the
dedicated promote-to-finding endpoint respectively). validate_detection_transition
(app/models/detection_result.py) closes that gap without inventing a staged
pipeline detections aren't actually worked through in practice."""

from __future__ import annotations

from datetime import UTC, datetime

import pytest
from fastapi import HTTPException
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from app.api.routes_rules import update_detection
from app.core.database import Base
from app.models.case import Case
from app.models.detection_result import DetectionResult, validate_detection_transition
from app.schemas.rule import DetectionUpdate

CASE_ID = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"


def _session():
    engine = create_engine("sqlite:///:memory:", future=True)
    Base.metadata.create_all(bind=engine)
    Session = sessionmaker(bind=engine, autoflush=False, autocommit=False, expire_on_commit=False, future=True)
    return Session()


def _detection(db, *, status: str = "new", detection_id: str = "eeeeeeee-eeee-4eee-8eee-eeeeeeeeeee1"):
    db.add(Case(id=CASE_ID, name="Case"))
    item = DetectionResult(id=detection_id, case_id=CASE_ID, engine="sigma", rule_name="Sigma A", status=status, target_type="event")
    db.add(item)
    db.commit()
    return item


@pytest.mark.parametrize(
    "current,target",
    [
        ("new", "reviewed"),
        ("reviewed", "confirmed"),
        ("confirmed", "dismissed"),
        ("dismissed", "new"),
        ("archived", "reviewed"),
        ("stale", "new"),
    ],
)
def test_free_movement_among_human_statuses(current, target):
    """Detections aren't worked through a staged pipeline the way Findings
    are -- an analyst moves freely in either direction, and the live bulk
    endpoint already applies mark_reviewed/mark_dismissed/mark_new
    unconditionally from any prior status. This must not regress that."""
    validate_detection_transition(current, target)  # must not raise


@pytest.mark.parametrize("automated_status", ["stale", "stale_event_link", "promoted_to_finding"])
def test_rejects_setting_an_automated_only_status_directly(automated_status):
    with pytest.raises(ValueError, match="is set automatically and cannot be assigned directly"):
        validate_detection_transition("new", automated_status)


def test_rejects_an_unrecognized_status_string():
    with pytest.raises(ValueError, match="Unknown detection status"):
        validate_detection_transition("new", "not_a_real_status")


def test_update_detection_returns_400_not_a_silent_success_for_an_automated_status():
    db = _session()
    item = _detection(db)

    with pytest.raises(HTTPException) as exc_info:
        update_detection(item.id, DetectionUpdate(status="promoted_to_finding"), db=db)

    assert exc_info.value.status_code == 400
    assert db.get(DetectionResult, item.id).status == "new"


def test_update_detection_clears_archived_at_when_leaving_archived():
    db = _session()
    item = _detection(db, status="archived")
    item.archived_at = datetime.now(UTC)
    db.commit()

    updated = update_detection(item.id, DetectionUpdate(status="reviewed"), db=db)

    assert updated.status == "reviewed"
    assert updated.archived_at is None


def test_update_detection_sets_archived_at_when_archiving():
    db = _session()
    item = _detection(db, status="new")

    updated = update_detection(item.id, DetectionUpdate(status="archived"), db=db)

    assert updated.status == "archived"
    assert updated.archived_at is not None
