"""Regression coverage for the /api/cases/{case_id}/activity path collision:
routes_activity.py's per-case activity-log route and
routes_evidence_preflight.py's Activity Center route were registered at the
identical path -- whichever router main.py included first silently won every
request, making the Activity Center (the upload/evidence operations list
ActivityPage.tsx depends on) completely unreachable. Fixed by moving the
plain activity-log route to /api/cases/{case_id}/activity-log; this test
builds both routers in the same relative order production uses (routes_activity
before routes_evidence_preflight) to catch any future re-collision.
"""
from __future__ import annotations

from fastapi import FastAPI
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from app.api import routes_activity, routes_evidence_preflight
from app.core.database import Base, get_db
from app.models.case import Case

CASE_ID = "cccccccc-4444-4444-8444-cccccccccccc"


def _db():
    engine = create_engine("sqlite:///:memory:", connect_args={"check_same_thread": False}, poolclass=StaticPool, future=True)
    Base.metadata.create_all(engine)
    return sessionmaker(bind=engine, future=True)()


def _case(db):
    item = Case(id=CASE_ID, name="Activity Route Case", description="", status="active", priority="medium", management_tags=[])
    db.add(item)
    db.commit()
    return item


def _client(db):
    app = FastAPI()
    # Same relative order as app.main (routes_activity included before
    # routes_evidence_preflight there too) so a future re-collision on this
    # path is caught the same way this one was found.
    app.include_router(routes_activity.router)
    app.include_router(routes_evidence_preflight.router)
    app.dependency_overrides[get_db] = lambda: db
    return TestClient(app)


def test_case_activity_path_resolves_to_activity_center_not_the_plain_log():
    db = _db()
    _case(db)
    client = _client(db)

    response = client.get(f"/api/cases/{CASE_ID}/activity")
    assert response.status_code == 200
    body = response.json()
    assert isinstance(body, dict), (
        "GET /api/cases/{case_id}/activity returned a bare list -- the plain "
        "activity-log route is shadowing the Activity Center route again."
    )
    assert set(body.keys()) >= {"case_id", "summary", "operations"}


def test_case_activity_log_still_reachable_at_its_own_path():
    db = _db()
    _case(db)
    client = _client(db)

    response = client.get(f"/api/cases/{CASE_ID}/activity-log")
    assert response.status_code == 200
    assert isinstance(response.json(), list)
