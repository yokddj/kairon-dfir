"""Windows Host Facts: hostname/fqdn derived from the EVTX Computer field.

Mirrors the structure of tests/test_host_facts.py and
tests/test_linux_host_identity.py (same fixtures, same DB helpers) but
exercises the Windows side of the platform-agnostic pipeline:

    normalize_evtx_row (real normalizer, not a hand-built dict)
        -> app.ingest.host_facts_extraction.extract_host_fact_documents
        -> app.services.host_facts.create_host_fact_observations
        -> resolve_host_facts / the host-facts API route

The point of building documents via the real normalizer (see _evtx_doc
below, same helper shape as tests/test_evtx_backend.py) rather than
constructing {"host_fact": {...}} dicts directly is that these tests fail
if the wiring between normalize_evtx_row's new "computer_field" and the
Windows extractor ever drifts apart -- a hand-built fixture could not
catch that.
"""
from fastapi import FastAPI
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from app.api import routes_host_facts
from app.core.database import Base, get_db
from app.ingest.artifact_normalizers import normalize_evtx_row
from app.ingest.host_facts_extraction import extract_host_fact_documents
from app.ingest.normalizer import base_document
from app.ingest.windows.host_facts import extract_windows_host_identity
from app.models.case import Case
from app.models.evidence import Evidence, EvidenceStorageMode, EvidenceType, IngestStatus
from app.models.host_fact import HostFact
from app.services.host_facts import create_host_fact_observations, delete_host_facts_for_evidence, resolve_host_facts

CASE_ID = "eeeeeeee-1111-4111-8111-eeeeeeeeeeee"
HOST_ID = "ffffffff-1111-4111-8111-ffffffffffff"
# Deliberately hex-lettered (not all-digit): an all-decimal-digit UUID
# string trips a SQLite type-affinity quirk where a column compiled from
# the postgresql.UUID type falls back to NUMERIC affinity, silently
# truncating an all-digit id to a float (see tests/test_host_facts.py).
EVIDENCE_ID = "1a1a1a1a-2222-4222-8222-1a1a1a1a1a1a"
ART_ID = "2b2b2b2b-3333-4333-8333-2b2b2b2b2baf"


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


def _evidence(db, evidence_id=EVIDENCE_ID, *, host_id=None, case_id=CASE_ID, filename="WS01.zip"):
    item = Evidence(
        id=evidence_id, case_id=case_id, original_filename=filename, stored_path=f"/tmp/{filename}",
        original_path=f"/tmp/{filename}", storage_mode=EvidenceStorageMode.uploaded, is_external=False,
        copy_to_storage=True, evidence_type=EvidenceType.raw_collection, sha256="0" * 64, size_bytes=128,
        ingest_status=IngestStatus.completed, detected_host=None, host_id=host_id,
        path_validation={}, ingest_source={}, metadata_json={}, error_log={},
    )
    db.add(item)
    db.commit()
    return item


def _evtx_doc(row: dict, *, source_path: str = "C/Windows/System32/winevt/Logs/Microsoft-Windows-Sysmon%4Operational.evtx") -> dict:
    """Builds a document exactly the way real EVTX ingest does -- through
    the real normalize_evtx_row(), not a hand-built {"host_fact": ...}
    dict -- so these tests catch any drift in the normalizer <-> extractor
    wiring, not just the extractor in isolation."""
    artifact_meta = {
        "artifact_type": "windows_event",
        "parser": "evtxecmd_csv",
        "source_tool": "evtxecmd",
        "source_format": "evtx_csv",
        "source_path": source_path,
        "ingest_run_id": "run-1",
    }
    document = base_document(CASE_ID, EVIDENCE_ID, ART_ID, row, artifact_meta)
    return normalize_evtx_row(document, row, artifact_meta)


def _sysmon_row(computer: str = "WS01.megacorp.local", **overrides) -> dict:
    row = {
        "EventID": "1",
        "Channel": "Microsoft-Windows-Sysmon/Operational",
        "Provider": "Microsoft-Windows-Sysmon",
        "Computer": computer,
        "ProcessId": "1234",
        "NewProcessName": "C:\\Windows\\System32\\cmd.exe",
        "UtcTime": "2024-03-22 12:21:24.171",
    }
    row.update(overrides)
    return row


class TestExtractWindowsHostIdentity:
    def test_hostname_and_fqdn_from_real_normalized_evtx_document(self):
        docs = [_evtx_doc(_sysmon_row())]
        result = extract_windows_host_identity(docs)
        by_type = {r["host_fact"]["fact_type"]: r["host_fact"] for r in result}
        assert set(by_type) == {"host.hostname", "host.fqdn"}
        assert by_type["host.hostname"]["normalized_value"] == "WS01"
        assert by_type["host.fqdn"]["normalized_value"] == "WS01.megacorp.local"
        assert by_type["host.hostname"]["artifact_family"] == "windows_host_identity"
        assert by_type["host.hostname"]["confidence"] == "high"

    def test_bare_hostname_never_promoted_to_a_fake_fqdn(self):
        docs = [_evtx_doc(_sysmon_row(computer="WS01"))]
        result = extract_windows_host_identity(docs)
        fact_types = {r["host_fact"]["fact_type"] for r in result}
        assert fact_types == {"host.hostname"}

    def test_missing_computer_field_produces_no_fact(self):
        row = _sysmon_row()
        del row["Computer"]
        docs = [_evtx_doc(row)]
        assert extract_windows_host_identity(docs) == []

    def test_placeholder_values_are_rejected(self):
        for junk in ["", "unknown", "N/A", "localhost", "LOCALHOST", "127.0.0.1"]:
            docs = [_evtx_doc(_sysmon_row(computer=junk))]
            assert extract_windows_host_identity(docs) == [], f"{junk!r} should not become a Host Fact"

    def test_one_observation_per_batch_not_per_event(self):
        # The exact bug this has to avoid: a real EVTX artifact carries
        # thousands of events, every one of them repeating the same
        # Computer field. This must never turn into thousands of rows or
        # thousands of per-row DB dedup queries.
        docs = [_evtx_doc(_sysmon_row(), source_path="C/.../Sysmon.evtx") for _ in range(200)]
        result = extract_windows_host_identity(docs)
        assert len(result) == 2  # exactly one hostname + one fqdn

    def test_never_reads_the_fallback_inclusive_computer_field(self):
        # "computer" (as opposed to "computer_field") is extract_host()'s
        # broader field, which falls back to evidence-level detected_host
        # metadata -- a genuine per-artifact Computer element must never be
        # required to also match that broader field for the extractor to
        # work, and a document that only has the broader field (no genuine
        # per-record Computer) must never be treated as a real observation.
        doc = {"windows": {"computer": "ws01"}}  # no "computer_field" at all
        assert extract_windows_host_identity([doc]) == []


class TestGenericDispatcher:
    def test_combines_inline_linux_and_derived_windows_facts(self):
        from app.ingest.linux.timezone import parse_timezone
        from app.ingest.normalizer import normalize_row

        linux_rows = parse_timezone("Europe/Madrid\n", source_path="etc/timezone")
        linux_doc = normalize_row("case-1", "ev-1", ART_ID, linux_rows[0], {
            "artifact_family": "linux_timezone", "artifact_type": linux_rows[0]["artifact_type"],
            "parser": "linux_timezone_raw", "name": "timezone", "source_path": "etc/timezone",
        })
        windows_doc = _evtx_doc(_sysmon_row())
        result = extract_host_fact_documents([linux_doc, windows_doc])
        fact_types = sorted(r["host_fact"]["fact_type"] for r in result)
        assert fact_types == ["host.fqdn", "host.hostname", "host.timezone"]

    def test_empty_documents_produce_nothing(self):
        assert extract_host_fact_documents([]) == []

    def test_unrelated_documents_produce_nothing(self):
        assert extract_host_fact_documents([{"process": {"name": "cmd.exe"}}]) == []


class TestEndToEndPersistence:
    def test_windows_evidence_produces_hostname_and_fqdn_host_facts(self):
        db = _db()
        _case(db)
        _evidence(db)
        documents = extract_host_fact_documents([_evtx_doc(_sysmon_row())])
        created = create_host_fact_observations(
            db, case_id=CASE_ID, evidence_id=EVIDENCE_ID, artifact_id=ART_ID, host_id=None,
            observed_at=None, documents=documents,
        )
        assert len(created) == 2
        rows = {row.fact_type: row for row in db.query(HostFact).all()}
        assert rows["host.hostname"].normalized_value == "WS01"
        assert rows["host.hostname"].status == "observed"
        assert rows["host.hostname"].source_kind == "evtx_computer_field"
        assert rows["host.fqdn"].normalized_value == "WS01.megacorp.local"

    def test_a_full_artifact_of_repeated_events_still_yields_exactly_two_rows(self):
        # Full pipeline version of TestExtractWindowsHostIdentity's
        # per-batch (not per-event) guarantee -- confirms it holds all the
        # way through persistence, not just extraction.
        db = _db()
        _case(db)
        _evidence(db)
        raw_documents = [_evtx_doc(_sysmon_row()) for _ in range(500)]
        documents = extract_host_fact_documents(raw_documents)
        create_host_fact_observations(
            db, case_id=CASE_ID, evidence_id=EVIDENCE_ID, artifact_id=ART_ID, host_id=None,
            observed_at=None, documents=documents,
        )
        assert db.query(HostFact).count() == 2

    def test_evidence_with_no_valid_computer_field_produces_no_host_facts(self):
        db = _db()
        _case(db)
        _evidence(db)
        row = _sysmon_row()
        del row["Computer"]
        documents = extract_host_fact_documents([_evtx_doc(row)])
        created = create_host_fact_observations(
            db, case_id=CASE_ID, evidence_id=EVIDENCE_ID, artifact_id=ART_ID, host_id=None,
            observed_at=None, documents=documents,
        )
        assert created == []
        assert db.query(HostFact).count() == 0

    def test_resolve_host_facts_returns_windows_hostname(self):
        db = _db()
        _case(db)
        _evidence(db)
        documents = extract_host_fact_documents([_evtx_doc(_sysmon_row())])
        create_host_fact_observations(
            db, case_id=CASE_ID, evidence_id=EVIDENCE_ID, artifact_id=ART_ID, host_id=None,
            observed_at=None, documents=documents,
        )
        resolved = resolve_host_facts(db, case_id=CASE_ID, evidence_id=EVIDENCE_ID, fact_type="host.hostname")
        assert resolved[0]["status"] == "observed"
        assert resolved[0]["preferred_value"] == "WS01"
        assert resolved[0]["supporting"][0]["source_kind"] == "evtx_computer_field"

    def test_api_returns_windows_host_facts(self):
        db = _db()
        _case(db)
        _evidence(db, host_id=HOST_ID)
        documents = extract_host_fact_documents([_evtx_doc(_sysmon_row())])
        create_host_fact_observations(
            db, case_id=CASE_ID, evidence_id=EVIDENCE_ID, artifact_id=ART_ID, host_id=HOST_ID,
            observed_at=None, documents=documents,
        )
        client = _client(db)
        response = client.get(f"/api/cases/{CASE_ID}/host-facts", params={"host_id": HOST_ID})
        assert response.status_code == 200
        body = response.json()
        fact_types = {f["fact_type"] for f in body["facts"]}
        assert {"host.hostname", "host.fqdn"} <= fact_types

    def test_two_different_hosts_never_mix_windows_facts(self):
        db = _db()
        _case(db)
        other_host_id = "abababab-4444-4444-8444-abababababab"
        other_evidence_id = "cdcdcdcd-5555-4555-8555-cdcdcdcdcdcd"
        _evidence(db, EVIDENCE_ID, host_id=HOST_ID, filename="WS01.zip")
        _evidence(db, other_evidence_id, host_id=other_host_id, filename="DC01.zip")
        create_host_fact_observations(
            db, case_id=CASE_ID, evidence_id=EVIDENCE_ID, artifact_id=ART_ID, host_id=HOST_ID, observed_at=None,
            documents=extract_host_fact_documents([_evtx_doc(_sysmon_row(computer="WS01.megacorp.local"))]),
        )
        create_host_fact_observations(
            db, case_id=CASE_ID, evidence_id=other_evidence_id, artifact_id=ART_ID, host_id=other_host_id, observed_at=None,
            documents=extract_host_fact_documents([_evtx_doc(_sysmon_row(computer="DC01.megacorp.local"))]),
        )
        ws01_facts = resolve_host_facts(db, case_id=CASE_ID, host_id=HOST_ID, fact_type="host.hostname")
        dc01_facts = resolve_host_facts(db, case_id=CASE_ID, host_id=other_host_id, fact_type="host.hostname")
        assert ws01_facts[0]["preferred_value"] == "WS01"
        assert dc01_facts[0]["preferred_value"] == "DC01"

    def test_casing_variants_of_the_same_host_resolve_as_one_identity(self):
        # Contract (app.services.host_facts.normalize_host_fact_value):
        # host.hostname/host.fqdn compare case-insensitively, so two EVTX
        # channels observing the same real machine with different
        # System/Computer casing ("WS01.megacorp.local" vs
        # "ws01.megacorp.local") resolve as "confirmed", not "conflicting".
        # Both raw, originally-cased values still persist untouched (see
        # the per-observation assertions below) -- only the comparison used
        # to group/deduplicate is case-insensitive, never the stored value.
        db = _db()
        _case(db)
        _evidence(db)
        other_artifact_id = "3c3c3c3c-4444-4444-8444-3c3c3c3c3c3c"
        create_host_fact_observations(
            db, case_id=CASE_ID, evidence_id=EVIDENCE_ID, artifact_id=ART_ID, host_id=HOST_ID, observed_at=None,
            documents=extract_host_fact_documents([_evtx_doc(_sysmon_row(computer="WS01.megacorp.local"))]),
        )
        create_host_fact_observations(
            db, case_id=CASE_ID, evidence_id=EVIDENCE_ID, artifact_id=other_artifact_id, host_id=HOST_ID, observed_at=None,
            documents=extract_host_fact_documents([_evtx_doc(_sysmon_row(computer="ws01.megacorp.local"), source_path="C/Windows/System32/winevt/Logs/Security.evtx")]),
        )
        resolved = resolve_host_facts(db, case_id=CASE_ID, host_id=HOST_ID, fact_type="host.hostname")[0]
        assert resolved["status"] == "confirmed"
        assert resolved["preferred_value"] in {"WS01", "ws01"}
        assert resolved["conflicting"] == []
        assert len(resolved["supporting"]) == 2
        # Original casing survives untouched per observation -- the
        # case-insensitive comparison never mutates stored values.
        observed_values = {row["normalized_value"] for row in resolved["observations"]}
        assert observed_values == {"WS01", "ws01"}

    def test_genuinely_different_hostnames_still_conflict_regardless_of_casing(self):
        # The case-insensitive contract must not blur a real conflict: two
        # different machine names, even both partly uppercase/lowercase,
        # are never folded into the same identity.
        db = _db()
        _case(db)
        _evidence(db)
        other_artifact_id = "4d4d4d4d-4444-4444-8444-4d4d4d4d4d4d"
        create_host_fact_observations(
            db, case_id=CASE_ID, evidence_id=EVIDENCE_ID, artifact_id=ART_ID, host_id=HOST_ID, observed_at=None,
            documents=extract_host_fact_documents([_evtx_doc(_sysmon_row(computer="WS01.megacorp.local"))]),
        )
        create_host_fact_observations(
            db, case_id=CASE_ID, evidence_id=EVIDENCE_ID, artifact_id=other_artifact_id, host_id=HOST_ID, observed_at=None,
            documents=extract_host_fact_documents([_evtx_doc(_sysmon_row(computer="ws02.megacorp.local"), source_path="C/Windows/System32/winevt/Logs/Security.evtx")]),
        )
        resolved = resolve_host_facts(db, case_id=CASE_ID, host_id=HOST_ID, fact_type="host.hostname")[0]
        assert resolved["status"] == "conflicting"
        assert resolved["supporting"] and resolved["conflicting"]
        observed_values = {row["normalized_value"] for row in resolved["observations"]}
        assert observed_values == {"WS01", "ws02"}

    def test_idempotent_across_reprocess_with_mixed_casing(self):
        # Simulates the real reprocess flow (app.workers.tasks.ingest_evidence
        # deletes an evidence's Host Facts via delete_host_facts_for_evidence
        # before recreating them) with two artifacts whose Computer field
        # differs only in casing -- confirms row count, fingerprints,
        # preferred_value and support count are all stable across repeats,
        # and that the fingerprint-dedup path (no delete in between) also
        # never grows the row count.
        db = _db()
        _case(db)
        _evidence(db, host_id=HOST_ID)
        other_artifact_id = "5e5e5e5e-4444-4444-8444-5e5e5e5e5e5e"

        def _ingest():
            create_host_fact_observations(
                db, case_id=CASE_ID, evidence_id=EVIDENCE_ID, artifact_id=ART_ID, host_id=HOST_ID, observed_at=None,
                documents=extract_host_fact_documents([_evtx_doc(_sysmon_row(computer="WS01.megacorp.local"))]),
            )
            create_host_fact_observations(
                db, case_id=CASE_ID, evidence_id=EVIDENCE_ID, artifact_id=other_artifact_id, host_id=HOST_ID, observed_at=None,
                documents=extract_host_fact_documents([_evtx_doc(_sysmon_row(computer="ws01.megacorp.local"), source_path="C/Windows/System32/winevt/Logs/Security.evtx")]),
            )

        _ingest()
        first_resolved = resolve_host_facts(db, case_id=CASE_ID, host_id=HOST_ID, fact_type="host.hostname")[0]
        first_fingerprints = sorted(row.fingerprint for row in db.query(HostFact).all())
        first_count = db.query(HostFact).count()
        assert first_resolved["status"] == "confirmed"
        assert len(first_resolved["supporting"]) == 2

        # Real reprocess: delete this evidence's rows, then re-run
        # extraction+persistence exactly as tasks.py does on "Re-index evidence".
        delete_host_facts_for_evidence(db, EVIDENCE_ID)
        db.commit()
        _ingest()

        second_resolved = resolve_host_facts(db, case_id=CASE_ID, host_id=HOST_ID, fact_type="host.hostname")[0]
        second_fingerprints = sorted(row.fingerprint for row in db.query(HostFact).all())
        second_count = db.query(HostFact).count()

        assert second_count == first_count
        assert second_fingerprints == first_fingerprints
        assert second_resolved["status"] == "confirmed"
        assert second_resolved["preferred_value"] == first_resolved["preferred_value"]
        assert len(second_resolved["supporting"]) == 2
        assert second_resolved["conflicting"] == []

        # Calling again WITHOUT a delete in between (the fingerprint-dedup
        # path) must not grow the row count either.
        _ingest()
        assert db.query(HostFact).count() == second_count
