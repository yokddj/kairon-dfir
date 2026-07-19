from __future__ import annotations

import pytest
from fastapi import HTTPException
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from app.api import routes_evidence
from app.core.database import Base
from app.models.case import Case
from app.models.case_host import CaseHost
from app.models.evidence import Evidence, EvidenceStorageMode, EvidenceType, IngestStatus


CASE_ID = "aaaaaaaa-1111-4111-8111-aaaaaaaaaaaa"
OTHER_CASE_ID = "ffffffff-1111-4111-8111-ffffffffffff"
EVIDENCE_ID = "bbbbbbbb-2222-4222-8222-bbbbbbbbbbbb"
HOST_ID = "cccccccc-3333-4333-8333-cccccccccccc"
OTHER_HOST_ID = "dddddddd-4444-4444-8444-dddddddddddd"
MISSING_HOST_ID = "eeeeeeee-5555-4555-8555-eeeeeeeeeeee"


def _db():
    engine = create_engine("sqlite:///:memory:", connect_args={"check_same_thread": False}, poolclass=StaticPool, future=True)
    Base.metadata.create_all(engine)
    return sessionmaker(bind=engine, future=True)()


def _case(db, case_id: str = CASE_ID) -> Case:
    item = Case(id=case_id, name=f"Case {case_id[-4:]}", description=None)
    db.add(item)
    db.commit()
    return item


def _host(db, *, host_id: str = HOST_ID, case_id: str = CASE_ID, canonical_name: str = "win-assigned-01") -> CaseHost:
    item = CaseHost(id=host_id, case_id=case_id, canonical_name=canonical_name, display_name=canonical_name.upper(), confidence="manual", source="manual")
    db.add(item)
    db.commit()
    return item


def _metadata(**overrides) -> dict:
    data = {
        "source_type": "raw_collection",
        "current_phase": "waiting_selection",
        "velociraptor_discovery": {
            "candidates": [
                {"id": "evtx-1", "supported": True, "category": "event_logs", "original_path": "Windows/System32/winevt/Logs/Security.evtx"}
            ]
        },
    }
    data.update(overrides)
    return data


def _evidence(db, *, host_id: str | None = None, metadata: dict | None = None, ingest_source: dict | None = None) -> Evidence:
    item = Evidence(
        id=EVIDENCE_ID,
        case_id=CASE_ID,
        original_filename="collection.zip",
        stored_path="/tmp/collection.zip",
        original_path="/tmp/collection.zip",
        storage_mode=EvidenceStorageMode.uploaded,
        is_external=False,
        copy_to_storage=True,
        evidence_type=EvidenceType.velociraptor_zip,
        sha256="0" * 64,
        size_bytes=128,
        ingest_status=IngestStatus.pending,
        detected_host=None,
        host_id=host_id,
        path_validation={},
        ingest_source=ingest_source or {},
        metadata_json=metadata or _metadata(),
        error_log={},
    )
    db.add(item)
    db.commit()
    return item


@pytest.fixture(autouse=True)
def _isolate_indexing_side_effects(monkeypatch):
    monkeypatch.setattr(routes_evidence, "_count_evidence_indexed_docs", lambda item: 0)
    monkeypatch.setattr(routes_evidence, "enqueue_ingest", lambda evidence_id: "queued-run-1")

    def apply_selection(evidence, existing_metadata, selected_candidate_ids, mode, parser_options=None):
        data = dict(existing_metadata)
        data["velociraptor_selected_candidate_ids"] = list(selected_candidate_ids)
        data["velociraptor_selected_categories"] = ["event_logs"]
        data["ingest_plan"] = {"selected_candidates": [{"candidate_id": selected_candidate_ids[0]}] if selected_candidate_ids else []}
        return data

    monkeypatch.setattr(routes_evidence, "_apply_reprocess_selection_metadata", apply_selection)


def _run(db, item: Evidence) -> dict:
    return routes_evidence._queue_recommended_raw_discovery_ingest(item, dict(item.metadata_json or {}), profile="recommended", force=False, db=db)


def test_recommended_indexing_uses_assigned_host_when_metadata_empty():
    db = _db()
    _case(db)
    _host(db, canonical_name="win-assigned-01")
    item = _evidence(db, host_id=HOST_ID, metadata=_metadata())

    result = _run(db, item)
    db.refresh(item)

    assert result and result["accepted"] is True
    assert item.host_id == HOST_ID
    assert item.metadata_json.get("provided_host") is None
    assert item.ingest_source.get("provided_host") is None


def test_recommended_indexing_assigned_host_wins_over_different_metadata_hostname():
    db = _db()
    _case(db)
    _host(db, canonical_name="win-assigned-01")
    item = _evidence(db, host_id=HOST_ID, metadata=_metadata(provided_host="legacy-host"), ingest_source={"provided_host": "legacy-source"})

    hostname, from_assignment = routes_evidence._resolve_indexing_hostname(db, item, dict(item.metadata_json or {}))

    assert hostname == "win-assigned-01"
    assert from_assignment is True


def test_recommended_indexing_uses_metadata_provided_host_without_host_id():
    db = _db()
    _case(db)
    item = _evidence(db, metadata=_metadata(provided_host="legacy-host"))

    result = _run(db, item)
    db.refresh(item)

    assert result and result["accepted"] is True
    assert item.metadata_json["provided_host"] == "legacy-host"


def test_recommended_indexing_uses_ingest_source_provided_host_without_host_id():
    db = _db()
    _case(db)
    item = _evidence(db, metadata=_metadata(), ingest_source={"provided_host": "source-host"})

    result = _run(db, item)
    db.refresh(item)

    assert result and result["accepted"] is True
    assert item.ingest_source["provided_host"] == "source-host"


def test_recommended_indexing_preserves_legacy_400_when_no_hostname_sources():
    db = _db()
    _case(db)
    item = _evidence(db, metadata=_metadata(), ingest_source={})

    with pytest.raises(HTTPException) as exc:
        _run(db, item)

    assert exc.value.status_code == 400
    assert exc.value.detail == "Host name is required for evidence indexing."


def test_recommended_indexing_rejects_host_from_another_case():
    db = _db()
    _case(db)
    _case(db, OTHER_CASE_ID)
    _host(db, host_id=OTHER_HOST_ID, case_id=OTHER_CASE_ID, canonical_name="other-host")
    item = _evidence(db, host_id=OTHER_HOST_ID, metadata=_metadata())

    with pytest.raises(HTTPException) as exc:
        _run(db, item)

    assert exc.value.status_code == 400
    assert exc.value.detail == "Assigned host does not belong to this case."


def test_recommended_indexing_rejects_missing_assigned_host():
    db = _db()
    _case(db)
    item = _evidence(db, host_id=MISSING_HOST_ID, metadata=_metadata())

    with pytest.raises(HTTPException) as exc:
        _run(db, item)

    assert exc.value.status_code == 400
    assert exc.value.detail == "Assigned host was not found for evidence indexing."


def test_recommended_indexing_rejects_empty_assigned_host_canonical_name():
    db = _db()
    _case(db)
    _host(db, canonical_name="")
    item = _evidence(db, host_id=HOST_ID, metadata=_metadata())

    with pytest.raises(HTTPException) as exc:
        _run(db, item)

    assert exc.value.status_code == 400
    assert exc.value.detail == "Assigned host canonical name is required for evidence indexing."
