"""Full-column CSV tables (Source tables view): reading, requesting, building, querying."""

from __future__ import annotations

import codecs
from pathlib import Path

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from app.api import routes_source_tables
from app.core.config import get_settings
from app.core.database import Base, get_db
from app.models.artifact import Artifact
from app.models.case import Case
from app.models.evidence import Evidence, IngestStatus
from app.models.source_table import SourceTable
from app.services import source_tables as service

CASE_ID = "aaaaaaaa-1111-4111-8111-aaaaaaaaaaaa"
EVIDENCE_ID = "bbbbbbbb-2222-4222-8222-bbbbbbbbbbbb"


def _db():
    engine = create_engine("sqlite:///:memory:", connect_args={"check_same_thread": False}, poolclass=StaticPool, future=True)
    Base.metadata.create_all(engine)
    return sessionmaker(bind=engine, future=True)()


def _seed(db, *, status=IngestStatus.completed, stored_path="/nonexistent/upload.zip"):
    db.add(Case(id=CASE_ID, name="Tables", description="", status="active", priority="medium", management_tags=[]))
    evidence = Evidence(id=EVIDENCE_ID, case_id=CASE_ID, original_filename="upload.zip", stored_path=stored_path, size_bytes=1, ingest_status=status)
    db.add(evidence)
    db.commit()
    return evidence


def _artifact(db, source_path: str, artifact_type: str = "generic_csv") -> None:
    db.add(Artifact(case_id=CASE_ID, evidence_id=EVIDENCE_ID, name=Path(source_path).name, artifact_type=artifact_type, source_path=source_path, parser="csv"))
    db.commit()


class FakeIndices:
    def __init__(self):
        self.created: dict[str, dict] = {}
        self.deleted: list[str] = []

    def create(self, index, body):
        self.created[index] = body

    def delete(self, index, params=None):
        self.deleted.append(index)
        self.created.pop(index, None)

    def refresh(self, index):
        return None

    def exists(self, index):
        return index in self.created


class FakeClient:
    def __init__(self):
        self.indices = FakeIndices()
        self.docs: list[dict] = []
        self.searches: list[dict] = []

    def search(self, index, body):
        self.searches.append(body)
        return {"hits": {"total": {"value": 0}, "hits": []}}


@pytest.fixture()
def fake_client(monkeypatch):
    client = FakeClient()
    monkeypatch.setattr(service, "get_opensearch_client", lambda **_: client)
    monkeypatch.setattr(service, "index_exists", lambda c, index: c.indices.exists(index))

    def fake_bulk(c, actions, **_):
        count = 0
        for action in actions:
            c.docs.append(action["_source"])
            count += 1
        return count, []

    monkeypatch.setattr(service.helpers, "bulk", fake_bulk)
    return client


@pytest.fixture()
def evidence_root(monkeypatch, tmp_path):
    monkeypatch.setattr(service, "build_evidence_root", lambda case_id, evidence_id: tmp_path)
    (tmp_path / "extracted").mkdir()
    return tmp_path


# --- reading ---------------------------------------------------------------


def test_reads_semicolon_csv_with_blank_headers_and_blank_lines(tmp_path):
    path = tmp_path / "out.csv"
    path.write_text("Time;;Path\n2024-01-01;x;C:\\a.exe\n\n2024-01-02;y;C:\\b.exe\n", encoding="utf-8")
    headers, rows = service.read_table(path)
    assert headers == ["Time", "Column2", "Path"]
    assert list(rows) == [["2024-01-01", "x", "C:\\a.exe"], ["2024-01-02", "y", "C:\\b.exe"]]


def test_reads_tsv_and_utf16_with_bom(tmp_path):
    tsv = tmp_path / "out.tsv"
    tsv.write_text("A\tB\n1\t2\n", encoding="utf-8")
    assert service.read_table(tsv)[0] == ["A", "B"]
    utf16 = tmp_path / "ps.csv"
    utf16.write_bytes(codecs.BOM_UTF16_LE + '"Name","Value"\r\n"á","1"\r\n'.encode("utf-16-le"))
    headers, rows = service.read_table(utf16)
    assert headers == ["Name", "Value"]
    assert list(rows) == [["á", "1"]]


def test_table_index_never_matches_the_events_index_pattern():
    settings = get_settings()
    # Search queries "<events prefix>-*"; a table index under it would show every value twice.
    assert not service.table_index_name(CASE_ID, "t").startswith(f"{settings.opensearch_index_prefix}-")


# --- requesting --------------------------------------------------------------


def test_all_csv_request_waits_for_the_ingest_and_then_expands_to_csv_artifacts_only(fake_client, evidence_root):
    db = _db()
    evidence = _seed(db, status=IngestStatus.processing)
    tables, queued = service.schedule_source_tables(db, evidence, None)
    assert not queued
    assert [table.source_path for table in tables] == [service.ALL_SOURCES]

    _artifact(db, "EvtxECmd/out.csv")
    _artifact(db, "logs/app.json", artifact_type="generic_json")
    (evidence_root / "extracted" / "EvtxECmd").mkdir()
    (evidence_root / "extracted" / "EvtxECmd" / "out.csv").write_text("A,B\n1,x\n", encoding="utf-8")

    assert service.build_pending_source_tables(db, EVIDENCE_ID) == 0  # still processing
    evidence.ingest_status = IngestStatus.completed
    db.commit()
    assert service.build_pending_source_tables(db, EVIDENCE_ID) == 1

    rows = db.query(SourceTable).all()
    assert [(row.source_path, row.status) for row in rows] == [("EvtxECmd/out.csv", "ready")]


def test_request_after_ingest_queues_the_build_and_rejects_non_csv(monkeypatch):
    db = _db()
    evidence = _seed(db)
    _artifact(db, "out.csv")
    queued_for: list[str] = []
    import app.workers.tasks as tasks

    monkeypatch.setattr(tasks, "enqueue_source_tables_build", lambda evidence_id: queued_for.append(evidence_id) or "job")
    app = FastAPI()
    app.include_router(routes_source_tables.router)
    app.dependency_overrides[get_db] = lambda: db
    client = TestClient(app)

    response = client.post(f"/api/cases/{CASE_ID}/evidence/{EVIDENCE_ID}/source-tables", json={"source_paths": ["out.csv"]})
    assert response.status_code == 200
    assert response.json()["queued"] is True
    assert queued_for == [EVIDENCE_ID]
    assert response.json()["items"][0]["name"] == "out.csv"

    response = client.post(f"/api/cases/{CASE_ID}/evidence/{EVIDENCE_ID}/source-tables", json={"source_paths": ["Security.evtx"]})
    assert response.status_code == 400


# --- building ------------------------------------------------------------------


def test_build_keeps_every_column_positionally_and_detects_numeric_columns(fake_client, evidence_root):
    db = _db()
    evidence = _seed(db)
    (evidence_root / "extracted" / "out.csv").write_text(
        "Time,Size,Path.With.Dots,Path.With.Dots\n2024-01-01,10,a,b\n2024-01-02,9,c,d,EXTRA\n",
        encoding="utf-8",
    )
    service.request_source_tables(db, evidence, ["out.csv"])
    service.build_pending_source_tables(db, EVIDENCE_ID)

    table = db.query(SourceTable).one()
    assert table.status == "ready"
    assert table.row_count == 2
    assert [column["name"] for column in table.columns] == ["Time", "Size", "Path.With.Dots", "Path.With.Dots", "Column5"]
    assert [column["numeric"] for column in table.columns] == [False, True, False, False, False]
    assert [column["empty"] for column in table.columns] == [False, False, False, False, False]
    assert fake_client.docs[1]["c4"] == "EXTRA"
    assert fake_client.docs[0]["n1"] == 10.0
    mapping = fake_client.indices.created[table.index_name]["mappings"]
    assert mapping["dynamic"] is False
    assert "Path.With.Dots" not in mapping["properties"]


def test_missing_source_file_is_reported_as_unavailable(fake_client, evidence_root):
    db = _db()
    evidence = _seed(db)
    service.request_source_tables(db, evidence, ["gone.csv"])
    service.build_pending_source_tables(db, EVIDENCE_ID)
    table = db.query(SourceTable).one()
    assert table.status == "unavailable"
    assert fake_client.indices.created == {}


# --- querying ------------------------------------------------------------------


def _ready_table() -> SourceTable:
    return SourceTable(
        id="t1",
        case_id=CASE_ID,
        evidence_id=EVIDENCE_ID,
        source_path="out.csv",
        name="out.csv",
        status="ready",
        index_name="dfir-tables-x",
        columns=[{"index": 0, "name": "Path", "numeric": False}, {"index": 1, "name": "Size", "numeric": True}],
    )


def test_filters_escape_wildcards_and_sort_numeric_columns_numerically(fake_client):
    table = _ready_table()
    service.query_table_rows(
        table,
        q="mimikatz",
        filters=[{"column": 0, "op": "contains", "value": "a*b"}, {"column": 1, "op": "empty"}],
        sort_column=1,
        sort_order="desc",
    )
    body = fake_client.searches[-1]
    must = body["query"]["bool"]["must"]
    assert must[0]["simple_query_string"]["fields"] == ["row_text"]
    assert must[1]["wildcard"]["c0"] == {"value": "*a\\*b*", "case_insensitive": True}
    assert body["query"]["bool"]["must_not"] == [{"exists": {"field": "c1"}}]
    assert body["sort"] == [{"n1": {"order": "desc", "missing": "_last"}}, {"row": {"order": "asc"}}]


def test_unknown_column_is_rejected():
    with pytest.raises(service.SourceTableError):
        service.build_table_query(_ready_table(), None, [{"column": 7, "op": "equals", "value": "x"}])


def test_empty_columns_are_flagged_when_building(fake_client, evidence_root):
    db = _db()
    evidence = _seed(db)
    (evidence_root / "extracted" / "out.csv").write_text("Time,PayloadData5,User\n2024-01-01,,alice\n2024-01-02,,\n", encoding="utf-8")
    service.request_source_tables(db, evidence, ["out.csv"])
    service.build_pending_source_tables(db, EVIDENCE_ID)
    table = db.query(SourceTable).one()
    assert {column["name"]: column["empty"] for column in table.columns} == {"Time": False, "PayloadData5": True, "User": False}


def test_tables_built_before_the_flag_get_it_once(fake_client):
    db = _db()
    _seed(db)
    table = _ready_table()
    table.id = "cccccccc-3333-4333-8333-cccccccccccc"
    db.add(table)
    db.commit()
    fake_client.search = lambda index, body: {"aggregations": {"c0": {"doc_count": 3}, "c1": {"doc_count": 0}}}
    service.ensure_column_emptiness(db, table)
    assert [column["empty"] for column in table.columns] == [False, True]
    fake_client.search = lambda index, body: pytest.fail("computed twice")
    service.ensure_column_emptiness(db, table)
