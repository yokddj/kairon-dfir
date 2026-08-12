"""Host Facts: aggregation, conflict resolution, provenance, dedup and API.

Host Facts is a generic layer (see app.services.host_facts) whose first and
only current consumer is host.timezone, produced by
app.ingest.linux.timezone + app.ingest.normalizer.normalize_row. These
tests build normalized documents the same way the real ingest pipeline
does, then exercise the aggregation/resolution/API layer on top of them.
"""
from fastapi import FastAPI
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from app.api import routes_host_facts
from app.core.database import Base, get_db
from app.ingest.linux.timezone import parse_timezone
from app.ingest.normalizer import normalize_row
from app.models.case import Case
from app.models.case_host import CaseHost
from app.models.evidence import Evidence, EvidenceStorageMode, EvidenceType, IngestStatus
from app.models.host_fact import HostFact
from app.services.host_facts import (
    build_host_fact_fingerprint,
    create_host_fact_observations,
    delete_host_facts_for_evidence,
    normalize_host_fact_value,
    resolve_host_facts,
)

CASE_ID = "aaaaaaaa-1111-4111-8111-aaaaaaaaaaaa"
HOST_ID = "dddddddd-1111-4111-8111-dddddddddddd"
EVIDENCE_ID = "bbbbbbbb-2222-4222-8222-bbbbbbbbbbbb"
SECOND_EVIDENCE_ID = "cccccccc-3333-4333-8333-cccccccccccc"
# Deliberately hex-lettered (not all-digit): an all-decimal-digit UUID string
# trips a SQLite type-affinity quirk where a column compiled from the
# postgresql.UUID type falls back to NUMERIC affinity, silently truncating
# an all-digit id to a float. Real uuid4() values essentially never hit
# this (need all 32 hex chars to land on 0-9), but a hand-picked fixture
# easily can -- so these use the same letter-mixed style as every other id
# in this file.
ART1_ID = "11111111-1111-4111-8111-1111111111af"
ART2_ID = "22222222-2222-4222-8222-2222222222bf"


def _db():
    engine = create_engine("sqlite:///:memory:", connect_args={"check_same_thread": False}, poolclass=StaticPool, future=True)
    Base.metadata.create_all(engine)
    return sessionmaker(bind=engine, future=True)()


def _client(db):
    app = FastAPI()
    app.include_router(routes_host_facts.router)
    app.dependency_overrides[get_db] = lambda: db
    return TestClient(app)


def _case(db, case_id=CASE_ID):
    db.add(Case(id=case_id, name="Case", description=None))
    db.commit()


def _host(db, host_id=HOST_ID, case_id=CASE_ID):
    host = CaseHost(id=host_id, case_id=case_id, canonical_name="host-01", display_name="HOST-01", confidence="manual", source="manual")
    db.add(host)
    db.commit()
    return host


def _evidence(db, evidence_id=EVIDENCE_ID, *, host_id=None, case_id=CASE_ID, filename="disk.E01"):
    item = Evidence(
        id=evidence_id, case_id=case_id, original_filename=filename, stored_path=f"/tmp/{filename}",
        original_path=f"/tmp/{filename}", storage_mode=EvidenceStorageMode.uploaded, is_external=False,
        copy_to_storage=True, evidence_type=EvidenceType.disk_image, sha256="0" * 64, size_bytes=128,
        ingest_status=IngestStatus.completed, detected_host=None, host_id=host_id,
        path_validation={}, ingest_source={}, metadata_json={}, error_log={},
    )
    db.add(item)
    db.commit()
    return item


def _doc(raw: str, source_path: str = "etc/timezone") -> dict:
    rows = parse_timezone(raw, source_path=source_path)
    return normalize_row("case-1", "ev-1", ART1_ID, rows[0], {
        "artifact_family": "linux_timezone",
        "artifact_type": rows[0]["artifact_type"],
        "parser": "linux_timezone_raw",
        "name": source_path.rsplit("/", 1)[-1],
        "source_path": source_path,
    })


class TestFingerprint:
    def test_deterministic(self):
        a = build_host_fact_fingerprint("case", "ev", "art", "host.timezone", "etc_timezone", "Europe/Madrid")
        b = build_host_fact_fingerprint("case", "ev", "art", "host.timezone", "etc_timezone", "Europe/Madrid")
        assert a == b

    def test_changes_with_raw_value(self):
        a = build_host_fact_fingerprint("case", "ev", "art", "host.timezone", "etc_timezone", "Europe/Madrid")
        b = build_host_fact_fingerprint("case", "ev", "art", "host.timezone", "etc_timezone", "UTC")
        assert a != b


class TestNormalizeHostFactValue:
    """Direct contract tests for the comparison key used by both
    _recompute_group_status (write-time, persisted row.status) and
    _resolve_group (read-time, resolve_host_facts' response) -- the only
    two places host fact observations are grouped/deduplicated."""

    def test_hostname_is_case_insensitive(self):
        assert normalize_host_fact_value("host.hostname", "WS01") == normalize_host_fact_value("host.hostname", "ws01")

    def test_fqdn_is_case_insensitive(self):
        assert normalize_host_fact_value("host.fqdn", "WS01.megacorp.local") == normalize_host_fact_value("host.fqdn", "ws01.megacorp.local")

    def test_whitespace_is_trimmed(self):
        assert normalize_host_fact_value("host.hostname", "  WS01  ") == normalize_host_fact_value("host.hostname", "ws01")

    def test_genuinely_different_hostnames_stay_distinct(self):
        assert normalize_host_fact_value("host.hostname", "WS01") != normalize_host_fact_value("host.hostname", "WS02")

    def test_other_fact_types_stay_case_sensitive(self):
        # The case-insensitive contract is scoped to host.hostname/host.fqdn
        # only -- every other fact_type compares by exact (trimmed) value,
        # so a real casing difference there is never silently folded away.
        for fact_type in ("host.timezone", "host.distribution", "host.distribution_version", "host.kernel", "host.architecture"):
            assert normalize_host_fact_value(fact_type, "Europe/Madrid") != normalize_host_fact_value(fact_type, "europe/madrid")

    def test_other_fact_types_still_trim_whitespace(self):
        assert normalize_host_fact_value("host.timezone", "  Europe/Madrid  ") == normalize_host_fact_value("host.timezone", "Europe/Madrid")


class TestSingleObservation:
    def test_single_valid_source_is_observed_not_confirmed(self):
        db = _db()
        _case(db)
        _evidence(db)
        created = create_host_fact_observations(
            db, case_id=CASE_ID, evidence_id=EVIDENCE_ID, artifact_id=ART1_ID, host_id=None,
            observed_at=None, documents=[_doc("Europe/Madrid\n")],
        )
        assert len(created) == 1
        row = db.query(HostFact).one()
        assert row.status == "observed"
        assert row.normalized_value == "Europe/Madrid"
        assert row.fact_type == "host.timezone"

    def test_invalid_source_is_marked_invalid(self):
        db = _db()
        _case(db)
        _evidence(db)
        create_host_fact_observations(
            db, case_id=CASE_ID, evidence_id=EVIDENCE_ID, artifact_id=ART1_ID, host_id=None,
            observed_at=None, documents=[_doc("Not/AZone\n")],
        )
        row = db.query(HostFact).one()
        assert row.status == "invalid"
        assert row.normalized_value is None

    def test_provenance_preserved(self):
        db = _db()
        _case(db)
        _evidence(db)
        create_host_fact_observations(
            db, case_id=CASE_ID, evidence_id=EVIDENCE_ID, artifact_id=ART1_ID, host_id=None,
            observed_at=None, documents=[_doc("Not/AZone\n")],
        )
        row = db.query(HostFact).one()
        assert row.provenance["reason"] == "not_a_known_iana_zone"
        assert row.provenance["parse_status"] == "invalid"
        assert row.source_path == "etc/timezone"
        assert row.parser == "linux_timezone_raw"

    def test_non_timezone_documents_are_ignored(self):
        db = _db()
        _case(db)
        _evidence(db)
        plain_doc = {"linux": {}, "artifact": {"parser": "linux_auth_raw"}, "event_id": "e1"}
        created = create_host_fact_observations(
            db, case_id=CASE_ID, evidence_id=EVIDENCE_ID, artifact_id=ART1_ID, host_id=None,
            observed_at=None, documents=[plain_doc],
        )
        assert created == []
        assert db.query(HostFact).count() == 0


class TestDuplicatePrevention:
    def test_calling_twice_does_not_duplicate(self):
        db = _db()
        _case(db)
        _evidence(db)
        docs = [_doc("Europe/Madrid\n")]
        create_host_fact_observations(db, case_id=CASE_ID, evidence_id=EVIDENCE_ID, artifact_id=ART1_ID, host_id=None, observed_at=None, documents=docs)
        create_host_fact_observations(db, case_id=CASE_ID, evidence_id=EVIDENCE_ID, artifact_id=ART1_ID, host_id=None, observed_at=None, documents=docs)
        assert db.query(HostFact).count() == 1

    def test_different_source_kind_is_not_a_duplicate(self):
        db = _db()
        _case(db)
        _evidence(db)
        create_host_fact_observations(
            db, case_id=CASE_ID, evidence_id=EVIDENCE_ID, artifact_id=ART1_ID, host_id=None, observed_at=None,
            documents=[_doc("Europe/Madrid\n", "etc/timezone")],
        )
        create_host_fact_observations(
            db, case_id=CASE_ID, evidence_id=EVIDENCE_ID, artifact_id=ART2_ID, host_id=None, observed_at=None,
            documents=[_doc('ZONE="Europe/Madrid"\n', "etc/sysconfig/clock")],
        )
        assert db.query(HostFact).count() == 2


class TestConflictResolution:
    def test_agreeing_sources_are_confirmed(self):
        db = _db()
        _case(db)
        _evidence(db)
        create_host_fact_observations(
            db, case_id=CASE_ID, evidence_id=EVIDENCE_ID, artifact_id=ART1_ID, host_id=None, observed_at=None,
            documents=[_doc("Europe/Madrid\n", "etc/timezone")],
        )
        create_host_fact_observations(
            db, case_id=CASE_ID, evidence_id=EVIDENCE_ID, artifact_id=ART2_ID, host_id=None, observed_at=None,
            documents=[_doc("Time zone: Europe/Madrid (CEST, +0200)\n", "timedatectl.txt")],
        )
        rows = db.query(HostFact).all()
        assert {row.status for row in rows} == {"confirmed"}

        resolved = resolve_host_facts(db, case_id=CASE_ID, evidence_id=EVIDENCE_ID)
        assert len(resolved) == 1
        assert resolved[0]["status"] == "confirmed"
        assert resolved[0]["preferred_value"] == "Europe/Madrid"
        assert len(resolved[0]["supporting"]) == 2
        assert resolved[0]["conflicting"] == []

    def test_disagreeing_sources_are_conflicting_and_both_surfaced(self):
        db = _db()
        _case(db)
        _evidence(db)
        create_host_fact_observations(
            db, case_id=CASE_ID, evidence_id=EVIDENCE_ID, artifact_id=ART1_ID, host_id=None, observed_at=None,
            documents=[_doc("Europe/Madrid\n", "etc/timezone")],
        )
        create_host_fact_observations(
            db, case_id=CASE_ID, evidence_id=EVIDENCE_ID, artifact_id=ART2_ID, host_id=None, observed_at=None,
            documents=[_doc("/usr/share/zoneinfo/Etc/UTC", "etc/localtime")],
        )
        rows = db.query(HostFact).all()
        assert {row.status for row in rows} == {"conflicting"}

        resolved = resolve_host_facts(db, case_id=CASE_ID, evidence_id=EVIDENCE_ID)
        assert resolved[0]["status"] == "conflicting"
        # etc_timezone outranks etc_localtime_symlink in the tie-break order.
        assert resolved[0]["preferred_value"] == "Europe/Madrid"
        assert len(resolved[0]["conflicting"]) == 1
        assert resolved[0]["conflicting"][0]["normalized_value"] == "Etc/UTC"

    def test_invalid_rows_never_participate_in_agreement(self):
        db = _db()
        _case(db)
        _evidence(db)
        create_host_fact_observations(
            db, case_id=CASE_ID, evidence_id=EVIDENCE_ID, artifact_id=ART1_ID, host_id=None, observed_at=None,
            documents=[_doc("Europe/Madrid\n", "etc/timezone")],
        )
        create_host_fact_observations(
            db, case_id=CASE_ID, evidence_id=EVIDENCE_ID, artifact_id=ART2_ID, host_id=None, observed_at=None,
            documents=[_doc('ZONE="Not/AZone"\n', "etc/sysconfig/clock")],
        )
        resolved = resolve_host_facts(db, case_id=CASE_ID, evidence_id=EVIDENCE_ID)
        assert resolved[0]["status"] == "observed"  # single valid source, one invalid source alongside
        assert resolved[0]["preferred_value"] == "Europe/Madrid"
        assert len(resolved[0]["invalid"]) == 1

    def test_missing_status_when_fact_type_never_observed(self):
        db = _db()
        _case(db)
        _evidence(db)
        resolved = resolve_host_facts(db, case_id=CASE_ID, evidence_id=EVIDENCE_ID, fact_type="host.timezone")
        assert resolved == [{"fact_type": "host.timezone", "status": "missing", "preferred_value": None, "supporting": [], "conflicting": [], "invalid": [], "observations": []}]

    def test_host_scope_crosses_evidence_items(self):
        db = _db()
        _case(db)
        _host(db)
        _evidence(db, EVIDENCE_ID, host_id=HOST_ID, filename="disk.E01")
        _evidence(db, SECOND_EVIDENCE_ID, host_id=HOST_ID, filename="mem.raw")
        create_host_fact_observations(
            db, case_id=CASE_ID, evidence_id=EVIDENCE_ID, artifact_id=ART1_ID, host_id=HOST_ID, observed_at=None,
            documents=[_doc("Europe/Madrid\n", "etc/timezone")],
        )
        create_host_fact_observations(
            db, case_id=CASE_ID, evidence_id=SECOND_EVIDENCE_ID, artifact_id=ART2_ID, host_id=HOST_ID, observed_at=None,
            documents=[_doc("Time zone: Europe/Madrid (CEST, +0200)\n", "timedatectl.txt")],
        )
        resolved = resolve_host_facts(db, case_id=CASE_ID, host_id=HOST_ID)
        assert resolved[0]["status"] == "confirmed"
        assert len(resolved[0]["supporting"]) == 2
        assert {obs["evidence_id"] for obs in resolved[0]["supporting"]} == {EVIDENCE_ID, SECOND_EVIDENCE_ID}

    def test_evidence_without_host_never_leaks_into_another_evidence(self):
        db = _db()
        _case(db)
        _evidence(db, EVIDENCE_ID, host_id=None, filename="disk.E01")
        _evidence(db, SECOND_EVIDENCE_ID, host_id=None, filename="mem.raw")
        create_host_fact_observations(
            db, case_id=CASE_ID, evidence_id=EVIDENCE_ID, artifact_id=ART1_ID, host_id=None, observed_at=None,
            documents=[_doc("Europe/Madrid\n", "etc/timezone")],
        )
        create_host_fact_observations(
            db, case_id=CASE_ID, evidence_id=SECOND_EVIDENCE_ID, artifact_id=ART2_ID, host_id=None, observed_at=None,
            documents=[_doc("/usr/share/zoneinfo/Etc/UTC", "etc/localtime")],
        )
        first = resolve_host_facts(db, case_id=CASE_ID, evidence_id=EVIDENCE_ID)
        second = resolve_host_facts(db, case_id=CASE_ID, evidence_id=SECOND_EVIDENCE_ID)
        assert first[0]["status"] == "observed"
        assert first[0]["preferred_value"] == "Europe/Madrid"
        assert second[0]["status"] == "observed"
        assert second[0]["preferred_value"] == "Etc/UTC"


class TestReprocessCleanup:
    def test_delete_host_facts_for_evidence(self):
        db = _db()
        _case(db)
        _evidence(db)
        create_host_fact_observations(
            db, case_id=CASE_ID, evidence_id=EVIDENCE_ID, artifact_id=ART1_ID, host_id=None, observed_at=None,
            documents=[_doc("Europe/Madrid\n")],
        )
        assert db.query(HostFact).count() == 1
        deleted = delete_host_facts_for_evidence(db, EVIDENCE_ID)
        db.commit()
        assert deleted == 1
        assert db.query(HostFact).count() == 0


class TestApi:
    def test_case_not_found(self):
        db = _db()
        client = _client(db)
        response = client.get(f"/api/cases/{CASE_ID}/host-facts", params={"evidence_id": EVIDENCE_ID})
        assert response.status_code == 404

    def test_requires_scope(self):
        db = _db()
        _case(db)
        client = _client(db)
        response = client.get(f"/api/cases/{CASE_ID}/host-facts")
        assert response.status_code == 422

    def test_rejects_both_scopes(self):
        db = _db()
        _case(db)
        client = _client(db)
        response = client.get(f"/api/cases/{CASE_ID}/host-facts", params={"evidence_id": EVIDENCE_ID, "host_id": HOST_ID})
        assert response.status_code == 422

    def test_returns_resolved_facts_for_evidence(self):
        db = _db()
        _case(db)
        _evidence(db)
        create_host_fact_observations(
            db, case_id=CASE_ID, evidence_id=EVIDENCE_ID, artifact_id=ART1_ID, host_id=None, observed_at=None,
            documents=[_doc("Europe/Madrid\n")],
        )
        client = _client(db)
        response = client.get(f"/api/cases/{CASE_ID}/host-facts", params={"evidence_id": EVIDENCE_ID})
        assert response.status_code == 200
        body = response.json()
        assert body["scope"] == "evidence"
        assert body["evidence_id"] == EVIDENCE_ID
        assert body["facts"][0]["fact_type"] == "host.timezone"
        assert body["facts"][0]["preferred_value"] == "Europe/Madrid"

    def test_returns_resolved_facts_for_host(self):
        db = _db()
        _case(db)
        _host(db)
        _evidence(db, host_id=HOST_ID)
        create_host_fact_observations(
            db, case_id=CASE_ID, evidence_id=EVIDENCE_ID, artifact_id=ART1_ID, host_id=HOST_ID, observed_at=None,
            documents=[_doc("Europe/Madrid\n")],
        )
        client = _client(db)
        response = client.get(f"/api/cases/{CASE_ID}/host-facts", params={"host_id": HOST_ID})
        assert response.status_code == 200
        body = response.json()
        assert body["scope"] == "host"
        assert body["facts"][0]["preferred_value"] == "Europe/Madrid"
