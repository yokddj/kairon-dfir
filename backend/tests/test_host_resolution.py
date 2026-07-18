from __future__ import annotations

from fastapi import HTTPException
import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from app.core.database import Base
from app.models.case import Case
from app.models.case_host import CaseHost
from app.models.case_host_alias import CaseHostAlias
from app.models.evidence import Evidence, EvidenceCustodyEvent, EvidenceCustodyEventType, EvidenceIntegrityStatus, EvidenceType, IngestStatus
from app.services import host_resolution
from app.services.host_resolution import (
    HOST_ERROR_AMBIGUOUS,
    HOST_ERROR_INVALID,
    HOST_ERROR_NOT_FOUND,
    HOST_ERROR_REQUIRED,
    OUTCOME_AMBIGUOUS,
    OUTCOME_CREATED,
    OUTCOME_RESOLVED,
    OUTCOME_UNASSIGNED,
    assign_evidence_host,
    host_policy_for,
    normalize_hostname,
    resolve_host,
    validate_case_host_id,
)


CASE_ID = "aaaaaaaa-1111-4111-8111-aaaaaaaaaaaa"
OTHER_CASE_ID = "aaaaaaaa-2222-4222-8222-aaaaaaaaaaaa"


@pytest.fixture()
def db(monkeypatch):
    engine = create_engine("sqlite:///:memory:", connect_args={"check_same_thread": False}, poolclass=StaticPool, future=True)
    Base.metadata.create_all(engine)
    session = sessionmaker(bind=engine, future=True)()
    session.add(Case(id=CASE_ID, name="Host Resolution Case", description="", status="active", priority="medium", management_tags=[]))
    session.add(Case(id=OTHER_CASE_ID, name="Other Case", description="", status="active", priority="medium", management_tags=[]))
    session.commit()
    monkeypatch.setattr(host_resolution, "backfill_evidence_documents", lambda *_args, **_kwargs: {})
    monkeypatch.setattr(host_resolution, "invalidate_host_caches", lambda *_args, **_kwargs: None)
    try:
        yield session
    finally:
        session.close()


def _host(db, name: str = "VM-101", *, case_id: str = CASE_ID) -> CaseHost:
    canonical = normalize_hostname(name).lower()
    host = CaseHost(case_id=case_id, canonical_name=canonical, display_name=name.strip().rstrip("."), confidence="manual", source="manual")
    db.add(host)
    db.flush()
    db.add(CaseHostAlias(case_host_id=host.id, case_id=case_id, alias=host.display_name, normalized_alias=canonical, source="manual", confidence="manual", is_primary=True))
    db.commit()
    db.refresh(host)
    return host


def _evidence(db, *, host_id: str | None = None, evidence_type: EvidenceType = EvidenceType.disk_image) -> Evidence:
    item = Evidence(
        case_id=CASE_ID,
        original_filename="evidence.bin",
        stored_path="/tmp/evidence.bin",
        evidence_type=evidence_type,
        sha256="abc",
        size_bytes=1,
        detected_type=evidence_type.value,
        integrity_status=EvidenceIntegrityStatus.unknown,
        ingest_status=IngestStatus.pending,
        host_id=host_id,
        metadata_json={},
        ingest_source={},
        path_validation={},
        error_log={},
    )
    db.add(item)
    db.commit()
    db.refresh(item)
    return item


def _error_code(exc: HTTPException) -> str | None:
    detail = exc.detail
    if isinstance(detail, dict):
        return detail.get("error_code") or detail.get("code")
    return None


def test_valid_explicit_host_id_wins_over_other_inputs(db):
    explicit = _host(db, "EXPLICIT")
    other = _host(db, "OTHER")
    result = resolve_host(db, case_id=CASE_ID, evidence_type=EvidenceType.disk_image, host_id=explicit.id, provided_host=other.display_name, detected_hostname="DETECTED")
    assert result.host_id == explicit.id
    assert result.resolution_method == "existing_host"
    assert result.outcome == OUTCOME_RESOLVED


def test_host_id_from_another_case_is_rejected(db):
    other = _host(db, "OTHER", case_id=OTHER_CASE_ID)
    with pytest.raises(HTTPException) as exc:
        validate_case_host_id(db, CASE_ID, other.id)
    assert _error_code(exc.value) == HOST_ERROR_NOT_FOUND


def test_missing_host_id_returns_none(db):
    assert validate_case_host_id(db, CASE_ID, None) is None


def test_provided_host_matches_existing_and_wins_over_detected(db):
    provided = _host(db, "Provided-Host")
    result = resolve_host(db, case_id=CASE_ID, evidence_type=EvidenceType.disk_image, provided_host=" provided-host ", detected_hostname="detected-host")
    assert result.host_id == provided.id
    assert result.resolution_method == "provided_host"
    assert result.outcome == OUTCOME_RESOLVED
    assert result.normalized_candidate == "provided-host"


def test_provided_host_creates_host_when_policy_permits(db):
    result = resolve_host(db, case_id=CASE_ID, evidence_type=EvidenceType.disk_image, provided_host="NEW-HOST")
    assert result.outcome == OUTCOME_CREATED
    assert result.created is True
    assert db.get(CaseHost, result.host_id).canonical_name == "new-host"


def test_detected_hostname_matches_existing_host(db):
    host = _host(db, "LINUX01")
    result = resolve_host(db, case_id=CASE_ID, evidence_type=EvidenceType.linux_triage, detected_hostname="linux01")
    assert result.host_id == host.id
    assert result.resolution_method == "detected_hostname"


def test_detected_hostname_creates_host_when_policy_permits(db):
    result = resolve_host(db, case_id=CASE_ID, evidence_type=EvidenceType.linux_triage, detected_hostname="linux-new")
    assert result.created is True
    assert result.resolution_method == "detected_hostname"


@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        (" VM-101 ", "VM-101"),
        ("vm-101.", "vm-101"),
        ("vm-101..example.local.", "vm-101.example.local"),
        ("NETBIOS_01", "NETBIOS_01"),
    ],
)
def test_hostname_normalization(raw, expected):
    assert normalize_hostname(raw) == expected


@pytest.mark.parametrize("raw", ["", "  ", "unknown", "bad/name", "bad\\name", "bad:name", "bad@name", "bad\x00name", "-bad"])
def test_invalid_hostname_rejected(raw):
    assert normalize_hostname(raw) is None


def test_fqdn_does_not_match_short_name_without_alias(db):
    short = _host(db, "vm-101")
    result = resolve_host(db, case_id=CASE_ID, evidence_type=EvidenceType.disk_image, provided_host="vm-101.example.local")
    assert result.host_id != short.id
    assert db.query(CaseHost).filter(CaseHost.case_id == CASE_ID).count() == 2


def test_fqdn_matches_when_explicit_alias_exists(db):
    host = _host(db, "vm-101")
    db.add(CaseHostAlias(case_host_id=host.id, case_id=CASE_ID, alias="vm-101.example.local", normalized_alias="vm-101.example.local", source="manual", confidence="manual", is_primary=False))
    db.commit()
    result = resolve_host(db, case_id=CASE_ID, evidence_type=EvidenceType.disk_image, provided_host="VM-101.EXAMPLE.LOCAL")
    assert result.host_id == host.id


def test_repeated_equivalent_names_do_not_create_duplicates(db):
    first = resolve_host(db, case_id=CASE_ID, evidence_type=EvidenceType.disk_image, provided_host="VM-101")
    second = resolve_host(db, case_id=CASE_ID, evidence_type=EvidenceType.disk_image, provided_host="vm-101")
    third = resolve_host(db, case_id=CASE_ID, evidence_type=EvidenceType.disk_image, provided_host="vm-101.")
    assert {first.host_id, second.host_id, third.host_id} == {first.host_id}
    assert db.query(CaseHost).filter(CaseHost.case_id == CASE_ID).count() == 1


def test_memory_policy_requires_explicit_source_host(db):
    with pytest.raises(HTTPException) as exc:
        resolve_host(db, case_id=CASE_ID, evidence_type=EvidenceType.memory_dump)
    assert _error_code(exc.value) == HOST_ERROR_REQUIRED


@pytest.mark.parametrize("evidence_type", [EvidenceType.disk_image, EvidenceType.velociraptor_zip, EvidenceType.raw_collection, EvidenceType.kape_archive, EvidenceType.linux_triage, "windows_collection", "linux_collection", "artifact_collection", "generic_archive"])
def test_optional_evidence_policies_allow_unassigned(db, evidence_type):
    result = resolve_host(db, case_id=CASE_ID, evidence_type=evidence_type, auto_assign=False)
    assert result.outcome == OUTCOME_UNASSIGNED
    assert result.host_id is None
    assert host_policy_for(evidence_type).unassigned_allowed is True


def test_auto_assign_allowed_uses_unique_existing_candidate(db):
    host = _host(db, "AUTO-01")
    result = resolve_host(db, case_id=CASE_ID, evidence_type=EvidenceType.disk_image, hostname_candidates=["auto-01"], allow_create=False, auto_assign=True)
    assert result.host_id == host.id
    assert result.auto_assign is False or result.resolution_method in {"detected_hostname", "auto_assign_detected_hostname"}


def test_auto_assign_prohibited_for_memory(db):
    _host(db, "AUTO-01")
    with pytest.raises(HTTPException) as exc:
        resolve_host(db, case_id=CASE_ID, evidence_type=EvidenceType.memory_dump, hostname_candidates=["auto-01"], auto_assign=True)
    assert _error_code(exc.value) == HOST_ERROR_REQUIRED


def test_auto_assign_ambiguous_returns_ambiguous_for_optional_policy(db):
    result = resolve_host(db, case_id=CASE_ID, evidence_type=EvidenceType.disk_image, hostname_candidates=["one", "two"], allow_create=False, auto_assign=True)
    assert result.outcome == OUTCOME_AMBIGUOUS
    assert result.host_id is None


def test_auto_assign_zero_candidate_returns_unassigned_for_optional_policy(db):
    result = resolve_host(db, case_id=CASE_ID, evidence_type=EvidenceType.disk_image, hostname_candidates=[], allow_create=False, auto_assign=True)
    assert result.outcome == OUTCOME_UNASSIGNED


def test_auto_assign_ambiguous_required_policy_raises(db):
    with pytest.raises(HTTPException) as exc:
        resolve_host(db, case_id=CASE_ID, evidence_type=EvidenceType.memory_dump, hostname_candidates=["one", "two"], require_host=True, auto_assign=True)
    assert _error_code(exc.value) == HOST_ERROR_REQUIRED


def test_platform_unknown_host_accepts_high_confidence_candidate(db):
    result = resolve_host(db, case_id=CASE_ID, evidence_type=EvidenceType.disk_image, detected_platform="windows", platform_confidence="high", existing_host_platform="unknown")
    assert result.platform_decision["decision"] == "set_candidate"


def test_platform_high_confidence_conflict_is_recorded_not_overwritten(db):
    result = resolve_host(db, case_id=CASE_ID, evidence_type=EvidenceType.disk_image, detected_platform="linux", platform_confidence="high", existing_host_platform="windows")
    assert result.platform_decision["decision"] == "conflict"


def test_low_confidence_platform_does_not_overwrite_stronger_host_data(db):
    result = resolve_host(db, case_id=CASE_ID, evidence_type=EvidenceType.disk_image, detected_platform="linux", platform_confidence="low", existing_host_platform="windows")
    assert result.platform_decision["decision"] == "preserve"


def test_resolution_provenance_for_created_and_existing_host(db):
    created = resolve_host(db, case_id=CASE_ID, evidence_type=EvidenceType.disk_image, provided_host="PROV-01")
    existing = resolve_host(db, case_id=CASE_ID, evidence_type=EvidenceType.disk_image, provided_host="prov-01")
    assert created.provenance()["created"] is True
    assert created.provenance()["outcome"] == OUTCOME_CREATED
    assert existing.provenance()["created"] is False
    assert existing.provenance()["outcome"] == OUTCOME_RESOLVED
    assert existing.provenance()["resolution_method"] == "provided_host"


def test_evidence_assignment_records_single_custody_event_and_history(db):
    host = _host(db, "ASSIGN-01")
    evidence = _evidence(db)
    assigned = assign_evidence_host(db, evidence, host_id=host.id, actor_user_id=None, actor="analyst", reason="test", method="upload_assignment")
    assert assigned.host_id == host.id
    events = db.query(EvidenceCustodyEvent).filter(EvidenceCustodyEvent.evidence_id == evidence.id).all()
    assert len(events) == 1
    assert events[0].event_type == EvidenceCustodyEventType.host_assigned
    assert events[0].details_json["new_host_id"] == host.id


def test_idempotent_retry_does_not_duplicate_custody_event(db):
    host = _host(db, "ASSIGN-01")
    evidence = _evidence(db)
    assign_evidence_host(db, evidence, host_id=host.id, actor_user_id=None, actor="analyst", reason="test", method="upload_assignment")
    assign_evidence_host(db, evidence, host_id=host.id, actor_user_id=None, actor="analyst", reason="test", method="upload_assignment")
    assert db.query(EvidenceCustodyEvent).filter(EvidenceCustodyEvent.evidence_id == evidence.id).count() == 1


def test_reassignment_records_previous_and_new_host(db):
    old = _host(db, "OLD")
    new = _host(db, "NEW")
    evidence = _evidence(db, host_id=old.id)
    evidence.host_assignment_status = "confirmed"
    db.commit()
    assign_evidence_host(db, evidence, host_id=new.id, actor_user_id=None, actor="analyst", reason="move", method="analyst_assigned")
    event = db.query(EvidenceCustodyEvent).filter(EvidenceCustodyEvent.evidence_id == evidence.id).one()
    assert event.event_type == EvidenceCustodyEventType.host_assignment_changed
    assert event.details_json["previous_host_id"] == old.id
    assert event.details_json["new_host_id"] == new.id


def test_authorization_and_case_isolation_on_assignment(db):
    other = _host(db, "OTHER", case_id=OTHER_CASE_ID)
    evidence = _evidence(db)
    with pytest.raises(HTTPException) as exc:
        assign_evidence_host(db, evidence, host_id=other.id, actor_user_id=None, actor="analyst")
    assert _error_code(exc.value) == HOST_ERROR_NOT_FOUND


def test_invalid_provided_host_raises_structured_error(db):
    with pytest.raises(HTTPException) as exc:
        resolve_host(db, case_id=CASE_ID, evidence_type=EvidenceType.disk_image, provided_host="bad/name")
    assert _error_code(exc.value) == HOST_ERROR_INVALID
