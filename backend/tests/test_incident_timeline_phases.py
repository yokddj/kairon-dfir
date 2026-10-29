"""Incident phases come from the finding's own classification (type, MITRE)
before keywords; analysts can correct a phase and their edits survive a rebuild."""

from __future__ import annotations

from types import SimpleNamespace

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from app.core.database import Base
from app.models.incident_timeline_draft import IncidentTimelineDraft
from app.services import timeline_service
from app.services.mitre_tactics import primary_tactic, technique_ids


def _finding(**kwargs):
    values = {"id": "f-1", "title": "", "description": "", "finding_type": None, "mitre": [], "tags": []}
    values.update(kwargs)
    return SimpleNamespace(**values)


def test_primary_tactic_follows_the_main_technique() -> None:
    assert technique_ids(["T1059.001", "t1003", "T1059"]) == ["T1059", "T1003"]
    assert primary_tactic(["T1566", "T1059.001", "T1204.002"]) == "initial_access"
    assert primary_tactic(["T1486", "T1059.001"]) == "impact"
    # Multi-tactic main technique: the tactic the others support wins.
    assert primary_tactic(["T1078.002", "T1021.001", "T1136.002"]) == "persistence"
    assert primary_tactic(["T1053.005"]) == "execution"
    assert primary_tactic(["T9999", "not a technique"]) is None


def test_finding_phase_prefers_type_then_mitre_then_keywords() -> None:
    ransomware = _finding(title="Ransomware ran", description="PowerShell script encrypted the share", mitre=["T1486", "T1059.001"])
    assert timeline_service._finding_incident_phase(ransomware, "PowerShell script encrypted the share") == ("impact", "high")
    typed = _finding(finding_type="lateral_movement", mitre=["T1059"])
    assert timeline_service._finding_incident_phase(typed, "") == ("lateral_movement", "high")
    c2 = _finding(mitre=["T1071.001"])
    assert timeline_service._finding_incident_phase(c2, "")[0] == "command_and_control"
    linux = _finding(title="New cron entry", description="crontab -l; echo '* * * * * /tmp/x' | crontab -")
    assert timeline_service._finding_incident_phase(linux, linux.description)[0] == "persistence"


def test_marked_event_inherits_the_phase_of_its_finding() -> None:
    known = {"f-1": ("credential_access", "high")}
    assert timeline_service._linked_finding_phase(None, "f-1", known) == ("credential_access", "high")
    assert timeline_service._linked_finding_phase(None, None, known) is None


def test_phase_edit_is_stored_and_survives_a_rebuild() -> None:
    engine = create_engine("sqlite:///:memory:", future=True)
    Base.metadata.create_all(bind=engine)
    db = sessionmaker(bind=engine, future=True)()
    draft = IncidentTimelineDraft(
        case_id="case-1", option_key="opt", cache_key="cache", builder_version="v-test", data_fingerprint="fp",
        payload={"items": [{"id": "marked_event:evt-1:WS01:unknown", "title": "Logon", "status": "accepted", "phase": "unknown", "source": "marked_event", "source_type": "marked_event"}]},
    )
    db.add(draft)
    db.commit()
    db.refresh(draft)

    response = timeline_service.update_incident_timeline_item_status(db, "case-1", draft.id, "marked_event:evt-1:WS01:unknown", {"phase": "lateral_movement"})
    assert response["item"]["phase"] == "lateral_movement"
    assert response["item"]["phase_confidence"] == "analyst"
    assert response["item"]["status"] == "accepted"  # untouched when only the phase changes

    # A rebuild infers the phase again; the analyst's correction is re-applied.
    rebuilt = [{"id": "marked_event:evt-1:WS01:discovery", "title": "Logon", "status": "accepted", "phase": "discovery", "source": "marked_event", "source_type": "marked_event"}]
    carried = timeline_service._carry_over_analyst_edits(db, "case-1", rebuilt)
    assert carried[0]["phase"] == "lateral_movement"


def test_invalid_phase_is_rejected() -> None:
    import pytest
    from fastapi import HTTPException

    with pytest.raises(HTTPException):
        timeline_service.update_incident_timeline_item_status(None, "case-1", "t", "i", {"phase": "not_a_phase"})
