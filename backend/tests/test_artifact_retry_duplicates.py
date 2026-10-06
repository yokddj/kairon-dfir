"""A retried EVTX keeps one copy of its events, whichever run got further."""

from __future__ import annotations

import pytest

from app.workers import tasks

EVIDENCE = "ev-1"
ORIGINAL = "art-original"
EARLIER_RETRY = "art-retry-1"
RETRY = "art-retry-2"


class _FakeIndex:
    """Just enough of OpenSearch: documents carry evidence_id and artifact_id."""

    def __init__(self, docs_per_artifact: dict[str, int]):
        self.docs = [{"evidence_id": EVIDENCE, "artifact_id": artifact_id} for artifact_id, count in docs_per_artifact.items() for _ in range(count)]
        self.docs.append({"evidence_id": "other-evidence", "artifact_id": ORIGINAL})
        self.indices = self
        self.refreshed = False

    def refresh(self, index):  # noqa: ANN001
        self.refreshed = True

    def _matches(self, doc: dict, query: dict) -> bool:
        for clause in query["bool"]["filter"]:
            if "term" in clause:
                (field, value), = clause["term"].items()
                if doc.get(field) != value:
                    return False
            if "terms" in clause:
                (field, values), = clause["terms"].items()
                if doc.get(field) not in values:
                    return False
        return True

    def count(self, index, body):  # noqa: ANN001
        return {"count": sum(1 for doc in self.docs if self._matches(doc, body["query"]))}

    def delete_by_query(self, index, body, conflicts, refresh):  # noqa: ANN001
        before = len(self.docs)
        self.docs = [doc for doc in self.docs if not self._matches(doc, body["query"])]
        return {"deleted": before - len(self.docs)}

    def by_artifact(self) -> dict[str, int]:
        counts: dict[str, int] = {}
        for doc in self.docs:
            if doc["evidence_id"] == EVIDENCE:
                counts[doc["artifact_id"]] = counts.get(doc["artifact_id"], 0) + 1
        return counts


@pytest.fixture
def index(monkeypatch):
    holder = {}

    def _install(docs_per_artifact: dict[str, int]) -> _FakeIndex:
        holder["index"] = _FakeIndex(docs_per_artifact)
        monkeypatch.setattr(tasks, "get_opensearch_client", lambda **_kwargs: holder["index"])
        monkeypatch.setattr(tasks, "get_events_index", lambda case_id: f"dfir-events-{case_id}")
        return holder["index"]

    return _install


def _reconcile(previous: list[str]) -> dict:
    return tasks._reconcile_retried_artifact_documents(case_id="case-1", evidence_id=EVIDENCE, previous_artifact_ids=previous, retry_artifact_id=RETRY)


def test_a_retry_that_gets_further_replaces_the_earlier_partial_run(index):
    fake = index({ORIGINAL: 1910, RETRY: 5000})
    outcome = _reconcile([ORIGINAL])
    assert outcome == {"kept": "retry", "previous_docs": 1910, "retry_docs": 5000, "removed_docs": 1910}
    assert fake.by_artifact() == {RETRY: 5000}
    assert fake.refreshed
    # Other evidence is never touched.
    assert {"evidence_id": "other-evidence", "artifact_id": ORIGINAL} in fake.docs


def test_a_retry_that_stops_sooner_is_dropped_and_the_earlier_run_kept(index):
    fake = index({ORIGINAL: 1910, RETRY: 300})
    outcome = _reconcile([ORIGINAL])
    assert outcome["kept"] == "previous"
    assert outcome["removed_docs"] == 300
    assert fake.by_artifact() == {ORIGINAL: 1910}


def test_every_earlier_run_of_the_same_file_is_replaced(index):
    fake = index({ORIGINAL: 1910, EARLIER_RETRY: 2500, RETRY: 5000})
    _reconcile([ORIGINAL, EARLIER_RETRY])
    assert fake.by_artifact() == {RETRY: 5000}


def test_nothing_is_deleted_when_there_is_nothing_to_compare(index):
    fake = index({RETRY: 40})
    assert _reconcile([ORIGINAL])["removed_docs"] == 0
    assert fake.by_artifact() == {RETRY: 40}
    fake = index({ORIGINAL: 1910})
    assert _reconcile([ORIGINAL]) == {"kept": "previous", "previous_docs": 1910, "retry_docs": 0, "removed_docs": 0}
    assert fake.by_artifact() == {ORIGINAL: 1910}


def test_the_retry_id_is_never_treated_as_an_earlier_run(index):
    fake = index({ORIGINAL: 10, RETRY: 20})
    _reconcile([ORIGINAL, RETRY])
    assert fake.by_artifact() == {RETRY: 20}


def test_artifact_rows_follow_the_documents_that_were_kept(index, monkeypatch):
    updates: list[tuple[str, dict]] = []
    monkeypatch.setattr(tasks, "_update_artifact_row_isolated", lambda artifact_id, **fields: updates.append((artifact_id, fields)) or True)

    index({ORIGINAL: 1910, RETRY: 5000})
    kept = tasks._keep_one_copy_of_retried_artifact(case_id="case-1", evidence_id=EVIDENCE, previous_artifact_ids=[ORIGINAL], retry_artifact_id=RETRY, docs_processed=5000)
    assert kept == 5000
    assert updates == [(ORIGINAL, {"record_count": 0})]

    updates.clear()
    index({ORIGINAL: 1910, RETRY: 300})
    kept = tasks._keep_one_copy_of_retried_artifact(case_id="case-1", evidence_id=EVIDENCE, previous_artifact_ids=[ORIGINAL], retry_artifact_id=RETRY, docs_processed=300)
    assert kept == 0
    assert updates == []


def test_an_unreachable_index_leaves_everything_as_it_was(monkeypatch):
    def _broken(**_kwargs):
        raise ConnectionError("opensearch down")

    monkeypatch.setattr(tasks, "get_opensearch_client", _broken)
    kept = tasks._keep_one_copy_of_retried_artifact(case_id="case-1", evidence_id=EVIDENCE, previous_artifact_ids=[ORIGINAL], retry_artifact_id=RETRY, docs_processed=123)
    assert kept == 123


# --- the retry job end to end, with the parser and the index simulated -------------------------

from pathlib import Path
from types import SimpleNamespace

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from app.core.database import Base
from app.models.artifact import Artifact
from app.models.case import Case
from app.models.evidence import Evidence, EvidenceStorageMode, EvidenceType, IngestStatus

CASE_UUID = "00000000-0000-4000-8000-0000000000c1"
EVIDENCE_UUID = "00000000-0000-4000-8000-0000000000e1"
ORIGINAL_UUID = "00000000-0000-4000-8000-0000000000a1"
SOURCE = "Windows/System32/winevt/Logs/Security.evtx"


class _IndexByArtifact(_FakeIndex):
    def __init__(self):
        super().__init__({})
        self.docs = []

    def add(self, documents: list[dict]) -> None:
        self.docs.extend({"evidence_id": doc["evidence_id"], "artifact_id": doc["artifact_id"]} for doc in documents)

    def per_artifact(self) -> dict[str, int]:
        counts: dict[str, int] = {}
        for doc in self.docs:
            counts[doc["artifact_id"]] = counts.get(doc["artifact_id"], 0) + 1
        return counts


def _run_retry(tmp_path: Path, monkeypatch, *, already_indexed: int, retry_records: int, fail_after: int | None = None):
    engine = create_engine(f"sqlite:///{tmp_path / 'retry.sqlite'}", future=True)
    Base.metadata.create_all(bind=engine)
    Session = sessionmaker(bind=engine, autoflush=False, autocommit=False, expire_on_commit=False, future=True)
    with Session() as db:
        db.add(Case(id=CASE_UUID, name="retry", status="open"))
        db.add(Evidence(
            id=EVIDENCE_UUID, case_id=CASE_UUID, original_filename="collection.zip", stored_path="/tmp/collection.zip",
            storage_mode=EvidenceStorageMode.uploaded, evidence_type=EvidenceType.velociraptor_zip, sha256="00", size_bytes=1,
            ingest_status=IngestStatus.completed_with_errors, error_log={},
            metadata_json={"velociraptor_discovery": {"candidates": [{"original_path": SOURCE, "parser": "evtx_raw"}]}},
        ))
        db.add(Artifact(id=ORIGINAL_UUID, case_id=CASE_UUID, evidence_id=EVIDENCE_UUID, name="Security.evtx", artifact_type="windows_event",
                        source_path=SOURCE, parser="evtx_raw", status="failed_aborted", record_count=already_indexed))
        db.commit()

    index = _IndexByArtifact()
    index.add([{"evidence_id": EVIDENCE_UUID, "artifact_id": ORIGINAL_UUID}] * already_indexed)

    class _Parser:
        def iter_batches(self, path, *, artifact_id, batch_size, **_kwargs):  # noqa: ANN001
            for start in range(0, retry_records, batch_size):
                if fail_after is not None and start >= fail_after:
                    raise TimeoutError("stalled again")
                count = min(batch_size, retry_records - start)
                yield SimpleNamespace(events=[{"evidence_id": EVIDENCE_UUID, "artifact_id": artifact_id}] * count, records_read=start + count)

    monkeypatch.setattr(tasks, "SessionLocal", Session)
    monkeypatch.setattr(tasks, "get_current_job", lambda *a, **k: None)
    monkeypatch.setattr(tasks, "get_opensearch_client", lambda **_kwargs: index)
    monkeypatch.setattr(tasks, "get_events_index", lambda case_id: "dfir-events-test")
    monkeypatch.setattr(tasks, "bulk_index_events_with_report", lambda case_id, documents, **_kwargs: index.add(documents))
    monkeypatch.setattr(tasks, "_manifest_for_evidence", lambda evidence: {})
    monkeypatch.setattr(tasks, "build_problematic_artifacts_report", lambda *a, **k: {"items": [{"artifact_id": ORIGINAL_UUID, "source_path": SOURCE, "parser": "evtx_raw"}], "summary": {}})
    monkeypatch.setattr(tasks, "problematic_artifacts_require_error_status", lambda report: False)
    monkeypatch.setattr(tasks, "_prepare_velociraptor_selected_staging_from_candidates", lambda evidence, candidates: (tmp_path, candidates, [], {}))
    monkeypatch.setattr(tasks, "list_velociraptor_artifacts", lambda staging, candidates: [{"source_path": SOURCE, "parser": "evtx_raw", "name": "Security.evtx", "artifact_type": "windows_event", "path": tmp_path / "Security.evtx"}])
    monkeypatch.setattr(tasks, "_resolve_retry_profile", lambda mode, timeout: {"retry_mode": "deep_safe_mode", "bulk_batch_size": 100, "max_artifact_seconds": 0, "effective_timeouts": {}, "detections_enabled": False})
    monkeypatch.setattr(tasks, "EvtxRawParser", _Parser)
    monkeypatch.setattr(tasks, "_update_artifact_retry_run_metadata", lambda *a, **k: None)
    monkeypatch.setattr(tasks, "write_manifest", lambda *a, **k: None)
    monkeypatch.setattr(tasks, "evidence_manifest_path", lambda *a, **k: tmp_path / "manifest.json")

    tasks.retry_problematic_artifacts(EVIDENCE_UUID, [ORIGINAL_UUID], mode="deep_safe_mode")
    with Session() as db:
        rows = {row.id: row for row in db.query(Artifact).all()}
    engine.dispose()
    return index, rows


def test_retry_job_leaves_one_copy_when_the_retry_completes(tmp_path, monkeypatch):
    index, rows = _run_retry(tmp_path, monkeypatch, already_indexed=190, retry_records=500)
    retry_id = next(artifact_id for artifact_id in rows if artifact_id != ORIGINAL_UUID)
    assert index.per_artifact() == {retry_id: 500}
    assert rows[retry_id].record_count == 500
    assert rows[ORIGINAL_UUID].record_count == 0


def test_retry_job_that_stalls_earlier_keeps_the_original_events(tmp_path, monkeypatch):
    index, rows = _run_retry(tmp_path, monkeypatch, already_indexed=190, retry_records=500, fail_after=100)
    retry_id = next(artifact_id for artifact_id in rows if artifact_id != ORIGINAL_UUID)
    assert index.per_artifact() == {ORIGINAL_UUID: 190}
    assert rows[retry_id].record_count == 0
    assert rows[ORIGINAL_UUID].record_count == 190


def test_retry_job_that_stalls_later_keeps_its_own_events(tmp_path, monkeypatch):
    index, rows = _run_retry(tmp_path, monkeypatch, already_indexed=190, retry_records=500, fail_after=300)
    retry_id = next(artifact_id for artifact_id in rows if artifact_id != ORIGINAL_UUID)
    assert index.per_artifact() == {retry_id: 300}
    assert rows[retry_id].record_count == 300
    assert rows[ORIGINAL_UUID].record_count == 0
