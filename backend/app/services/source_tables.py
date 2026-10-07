"""Full-column tables for CSV/TSV sources (a Timeline Explorer style view).

The case events index keeps a normalized, strictly mapped document per row
and stores the original row in ``raw`` without indexing it. When an analyst
wants to explore a CSV with its own columns (sort and filter by any of them),
the file is indexed again, whole, into a dedicated per-file index. Columns
are stored positionally (``c0``, ``c1``...) so arbitrary headers -- dots,
spaces, duplicates, empty names -- never reach the mapping; the ordered
header list lives in Postgres.

The table index prefix differs from the events prefix on purpose: Search,
Timeline, Find Evil and detections query ``<events prefix>-*`` and must never
see these rows, or every value would show up twice.
"""

from __future__ import annotations

import base64
import codecs
import csv
import io
import logging
import math
import sys
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import orjson
from opensearchpy import helpers
from sqlalchemy.orm import Session

from app.core.config import get_settings
from app.core.opensearch import get_opensearch_client, index_exists
from app.core.storage import build_evidence_root, sanitize_relative_path
from app.models.artifact import Artifact
from app.models.evidence import Evidence, IngestStatus
from app.models.source_table import SourceTable

logger = logging.getLogger(__name__)
settings = get_settings()

TABULAR_SUFFIXES = {".csv", ".tsv"}
ALL_SOURCES = "*"
TERMINAL_INGEST_STATUSES = {IngestStatus.completed, IngestStatus.completed_with_errors, IngestStatus.failed}
# Values longer than this are kept in _source (shown and exported) but not
# indexed, so they cannot be sorted or matched by an exact/contains filter.
KEYWORD_IGNORE_ABOVE = 8191
MAX_ROW_TEXT_CHARS = 32_000
BULK_CHUNK_ROWS = 1000
MAX_PAGE_SIZE = 1000
EXPORT_BATCH = 2000
FILTER_OPS = {"contains", "not_contains", "equals", "not_equals", "empty", "not_empty"}

csv.field_size_limit(min(sys.maxsize, 2**31 - 1))


class SourceTableError(Exception):
    pass


def is_tabular_source(source_path: str | None) -> bool:
    return Path(str(source_path or "")).suffix.lower() in TABULAR_SUFFIXES


def table_index_name(case_id: str, table_id: str) -> str:
    return f"{settings.opensearch_table_index_prefix}-{case_id}-{table_id}".lower()


def serialize_table(table: SourceTable) -> dict[str, Any]:
    return {
        "id": table.id,
        "case_id": table.case_id,
        "evidence_id": table.evidence_id,
        "source_path": table.source_path,
        "name": table.name,
        "artifact_type": table.artifact_type,
        "status": table.status,
        "columns": list(table.columns or []),
        "row_count": table.row_count,
        "error": table.error,
        "created_at": table.created_at.isoformat() if table.created_at else None,
        "updated_at": table.updated_at.isoformat() if table.updated_at else None,
    }


# ---------------------------------------------------------------------------
# Requests
# ---------------------------------------------------------------------------


def _tabular_artifacts(db: Session, evidence_id: str) -> dict[str, Artifact]:
    by_path: dict[str, Artifact] = {}
    for artifact in db.query(Artifact).filter(Artifact.evidence_id == evidence_id).order_by(Artifact.created_at.asc()).all():
        if is_tabular_source(artifact.source_path):
            by_path.setdefault(artifact.source_path, artifact)
    return by_path


def request_source_tables(db: Session, evidence: Evidence, source_paths: list[str] | None) -> list[SourceTable]:
    """Record which CSVs of an evidence get a full table.

    ``source_paths=None`` means every CSV/TSV of the evidence, including the
    ones a still-running ingest has not discovered yet.
    """
    existing = {row.source_path: row for row in db.query(SourceTable).filter(SourceTable.evidence_id == evidence.id).all()}
    touched: list[SourceTable] = []
    if source_paths is None:
        row = existing.get(ALL_SOURCES)
        if row is None:
            row = SourceTable(case_id=evidence.case_id, evidence_id=evidence.id, source_path=ALL_SOURCES, name="All CSV files", status="pending", columns=[])
            db.add(row)
        touched.append(row)
    else:
        artifacts = _tabular_artifacts(db, evidence.id)
        for source_path in dict.fromkeys(source_paths):
            if not is_tabular_source(source_path):
                raise SourceTableError(f"Not a CSV/TSV source: {source_path}")
            row = existing.get(source_path)
            if row is None:
                artifact = artifacts.get(source_path)
                row = SourceTable(
                    case_id=evidence.case_id,
                    evidence_id=evidence.id,
                    source_path=source_path,
                    name=(artifact.name if artifact else None) or Path(source_path.replace("\\", "/")).name,
                    artifact_type=artifact.artifact_type if artifact else None,
                    status="pending",
                    columns=[],
                )
                db.add(row)
            elif row.status in {"failed", "unavailable"}:
                row.status = "pending"
                row.error = None
            touched.append(row)
    db.commit()
    for row in touched:
        db.refresh(row)
    return touched


def schedule_source_tables(db: Session, evidence: Evidence, source_paths: list[str] | None) -> tuple[list[SourceTable], bool]:
    """Record the request and build it now if the ingest already finished.

    The request is committed before the ingest status is read, and the ingest
    sets its final status before it looks for pending tables, so one of the
    two sides always sees the other and no request is left behind.
    """
    tables = request_source_tables(db, evidence, source_paths)
    db.refresh(evidence)
    if not ingest_is_finished(evidence) or not any(table.status == "pending" for table in tables):
        return tables, False
    from app.workers.tasks import enqueue_source_tables_build

    enqueue_source_tables_build(evidence.id)
    return tables, True


def has_pending_tables(db: Session, evidence_id: str) -> bool:
    return db.query(SourceTable.id).filter(SourceTable.evidence_id == evidence_id, SourceTable.status == "pending").first() is not None


def ingest_is_finished(evidence: Evidence) -> bool:
    status = evidence.ingest_status
    if not isinstance(status, IngestStatus):
        try:
            status = IngestStatus(str(status))
        except ValueError:
            return False
    return status in TERMINAL_INGEST_STATUSES


def _expand_all_sources_request(db: Session, evidence: Evidence) -> None:
    wildcard = db.query(SourceTable).filter(SourceTable.evidence_id == evidence.id, SourceTable.source_path == ALL_SOURCES).first()
    if wildcard is None or wildcard.status != "pending":
        return
    paths = list(_tabular_artifacts(db, evidence.id))
    db.delete(wildcard)
    db.commit()
    if paths:
        request_source_tables(db, evidence, paths)


# ---------------------------------------------------------------------------
# Reading the source file
# ---------------------------------------------------------------------------


def resolve_source_file(evidence: Evidence, source_path: str) -> Path | None:
    try:
        relative = sanitize_relative_path(source_path)
    except ValueError:
        return None
    root = build_evidence_root(evidence.case_id, evidence.id)
    bases = [root / "extracted", root / "staging", root / "original_folder", root / "original"]
    stored = Path(evidence.stored_path or "")
    if evidence.stored_path and stored.is_dir():
        bases.append(stored)
    for base in bases:
        candidate = base / relative
        if candidate.is_file():
            return candidate
    for base in bases[:2]:
        candidate = base / relative.name
        if candidate.is_file():
            return candidate
    return None


def _detect_encoding(head: bytes) -> str:
    if head.startswith(codecs.BOM_UTF16_LE) or head.startswith(codecs.BOM_UTF16_BE):
        return "utf-16"
    return "utf-8-sig"


def _detect_delimiter(path: Path, sample: str) -> str:
    if path.suffix.lower() == ".tsv":
        return "\t"
    try:
        return csv.Sniffer().sniff(sample, delimiters=",;\t|").delimiter
    except csv.Error:
        return ","


def read_table(path: Path) -> tuple[list[str], Iterator[list[str]]]:
    """Return the header row and an iterator over the data rows of a CSV/TSV."""
    with path.open("rb") as handle:
        head = handle.read(65536)
    encoding = _detect_encoding(head)
    sample = head.decode(encoding, errors="replace")
    delimiter = _detect_delimiter(path, sample)

    handle = path.open("r", encoding=encoding, errors="replace", newline="")
    reader = csv.reader(handle, delimiter=delimiter)
    try:
        headers = next(reader)
    except StopIteration:
        handle.close()
        return [], iter(())
    headers = [str(name or "").strip() or f"Column{index + 1}" for index, name in enumerate(headers)]

    def rows() -> Iterator[list[str]]:
        try:
            for row in reader:
                if not row or not any(cell.strip() for cell in row):
                    continue
                yield row
        finally:
            handle.close()

    return headers, rows()


def _as_number(value: str) -> float | None:
    text = value.strip()
    if not text or len(text) > 40:
        return None
    try:
        number = float(text)
    except ValueError:
        return None
    return number if math.isfinite(number) else None


# ---------------------------------------------------------------------------
# Building
# ---------------------------------------------------------------------------


def _index_body(column_count: int) -> dict[str, Any]:
    properties: dict[str, Any] = {"row": {"type": "long"}, "row_text": {"type": "text"}}
    for index in range(column_count):
        properties[f"c{index}"] = {"type": "keyword", "ignore_above": KEYWORD_IGNORE_ABOVE}
        properties[f"n{index}"] = {"type": "double"}
    return {
        "settings": {
            "number_of_shards": 1,
            "number_of_replicas": 0,
            "index.mapping.total_fields.limit": max(1000, column_count * 2 + 50),
        },
        "mappings": {"dynamic": False, "properties": properties},
    }


def _first_pass_width(path: Path, header_width: int) -> int:
    """Widest row in the file, so ragged rows still get a column."""
    _, rows = read_table(path)
    width = header_width
    for row in rows:
        if len(row) > width:
            width = len(row)
    return width


def build_source_table(db: Session, table: SourceTable, evidence: Evidence) -> None:
    path = resolve_source_file(evidence, table.source_path)
    if path is None:
        table.status = "unavailable"
        table.error = "The source file is no longer in the evidence storage. Reprocess the evidence to restore it."
        db.commit()
        return

    headers, _ = read_table(path)
    width = _first_pass_width(path, len(headers))
    headers = headers + [f"Column{index + 1}" for index in range(len(headers), width)]
    numeric = [True] * width
    seen_value = [False] * width

    client = get_opensearch_client(timeout_seconds=120)
    index = table_index_name(table.case_id, table.id)
    if index_exists(client, index):
        client.indices.delete(index=index, params={"ignore_unavailable": "true"})
    client.indices.create(index=index, body=_index_body(width))

    _, rows = read_table(path)

    def actions() -> Iterator[dict[str, Any]]:
        for row_number, row in enumerate(rows, start=1):
            doc: dict[str, Any] = {"row": row_number}
            parts: list[str] = []
            for position, value in enumerate(row[:width]):
                if value == "":
                    continue
                doc[f"c{position}"] = value
                parts.append(value)
                seen_value[position] = True
                number = _as_number(value)
                if number is None:
                    numeric[position] = False
                else:
                    doc[f"n{position}"] = number
            doc["row_text"] = " | ".join(parts)[:MAX_ROW_TEXT_CHARS]
            yield {"_index": index, "_id": str(row_number), "_source": doc}

    indexed, errors = helpers.bulk(client, actions(), chunk_size=BULK_CHUNK_ROWS, max_chunk_bytes=10 * 1024 * 1024, raise_on_error=False, request_timeout=120)
    client.indices.refresh(index=index)
    failed = len(errors) if isinstance(errors, list) else int(errors or 0)

    table.columns = [
        {"index": position, "name": name, "numeric": bool(numeric[position] and seen_value[position])}
        for position, name in enumerate(headers)
    ]
    table.row_count = int(indexed)
    table.index_name = index
    table.status = "ready"
    table.error = f"{failed} rows could not be indexed" if failed else None
    db.commit()
    logger.info("Built source table %s (%s rows, %s columns) from %s", table.id, indexed, width, path)


def build_pending_source_tables(db: Session, evidence_id: str) -> int:
    evidence = db.get(Evidence, evidence_id)
    if evidence is None or not ingest_is_finished(evidence):
        # The end of the ingest enqueues this job again.
        return 0
    _expand_all_sources_request(db, evidence)
    built = 0
    pending_ids = [row.id for row in db.query(SourceTable.id).filter(SourceTable.evidence_id == evidence_id, SourceTable.status == "pending").all()]
    for table_id in pending_ids:
        claimed = db.query(SourceTable).filter(SourceTable.id == table_id, SourceTable.status == "pending").update({"status": "building"}, synchronize_session=False)
        db.commit()
        if not claimed:
            continue
        table = db.get(SourceTable, table_id)
        try:
            build_source_table(db, table, evidence)
            built += 1
        except Exception as exc:  # noqa: BLE001
            logger.exception("Could not build source table %s", table_id)
            db.rollback()
            table = db.get(SourceTable, table_id)
            if table is not None:
                table.status = "failed"
                table.error = str(exc)[:2000]
                db.commit()
    return built


# ---------------------------------------------------------------------------
# Deleting
# ---------------------------------------------------------------------------


def delete_source_table(db: Session, table: SourceTable) -> None:
    client = get_opensearch_client()
    index = table.index_name or table_index_name(table.case_id, table.id)
    if index_exists(client, index):
        client.indices.delete(index=index, params={"ignore_unavailable": "true"})
    db.delete(table)
    db.commit()


def delete_source_table_indices_for_evidence(db: Session, evidence_id: str) -> int:
    client = get_opensearch_client()
    deleted = 0
    for table in db.query(SourceTable).filter(SourceTable.evidence_id == evidence_id).all():
        index = table.index_name or table_index_name(table.case_id, table.id)
        try:
            if index_exists(client, index):
                client.indices.delete(index=index, params={"ignore_unavailable": "true"})
                deleted += 1
        except Exception as exc:  # noqa: BLE001
            logger.warning("Could not delete source table index %s: %s", index, exc)
    return deleted


def delete_case_source_table_indices(case_id: str) -> int:
    client = get_opensearch_client()
    pattern = f"{settings.opensearch_table_index_prefix}-{case_id}-*".lower()
    try:
        names = list(client.indices.get(index=pattern, params={"allow_no_indices": "true", "ignore_unavailable": "true"}) or {})
    except Exception as exc:  # noqa: BLE001
        logger.warning("Could not list source table indices for case %s: %s", case_id, exc)
        return 0
    for name in names:
        try:
            client.indices.delete(index=name, params={"ignore_unavailable": "true"})
        except Exception as exc:  # noqa: BLE001
            logger.warning("Could not delete source table index %s: %s", name, exc)
    return len(names)


# ---------------------------------------------------------------------------
# Querying
# ---------------------------------------------------------------------------


def _column_count(table: SourceTable) -> int:
    return len(table.columns or [])


def _check_column(table: SourceTable, column: Any) -> int:
    try:
        position = int(column)
    except (TypeError, ValueError) as exc:
        raise SourceTableError(f"Unknown column: {column}") from exc
    if position < 0 or position >= _column_count(table):
        raise SourceTableError(f"Unknown column: {column}")
    return position


def _escape_wildcard(value: str) -> str:
    return value.replace("\\", "\\\\").replace("*", "\\*").replace("?", "\\?")


def build_table_query(table: SourceTable, q: str | None, filters: list[dict] | None) -> dict[str, Any]:
    must: list[dict] = []
    must_not: list[dict] = []
    text = str(q or "").strip()
    if text:
        must.append({"simple_query_string": {"query": text, "fields": ["row_text"], "default_operator": "and"}})
    for item in filters or []:
        field = f"c{_check_column(table, item.get('column'))}"
        op = str(item.get("op") or "contains")
        if op not in FILTER_OPS:
            raise SourceTableError(f"Unknown filter operator: {op}")
        value = str(item.get("value") if item.get("value") is not None else "")
        if op in {"contains", "not_contains"}:
            if not value:
                continue
            clause = {"wildcard": {field: {"value": f"*{_escape_wildcard(value)}*", "case_insensitive": True}}}
            (must if op == "contains" else must_not).append(clause)
        elif op in {"equals", "not_equals"}:
            clause = {"term": {field: value}} if value else {"bool": {"must_not": {"exists": {"field": field}}}}
            (must if op == "equals" else must_not).append(clause)
        elif op == "empty":
            must_not.append({"exists": {"field": field}})
        else:
            must.append({"exists": {"field": field}})
    if not must and not must_not:
        return {"match_all": {}}
    return {"bool": {"must": must, "must_not": must_not}}


def _sort_clause(table: SourceTable, sort_column: Any, order: str) -> list[dict]:
    direction = "desc" if str(order).lower() == "desc" else "asc"
    if sort_column is None or sort_column == "" or sort_column == "row":
        return [{"row": {"order": direction}}]
    position = _check_column(table, sort_column)
    column = (table.columns or [])[position]
    field = f"n{position}" if column.get("numeric") else f"c{position}"
    return [{field: {"order": direction, "missing": "_last"}}, {"row": {"order": "asc"}}]


def _encode_cursor(values: list[Any]) -> str:
    return base64.urlsafe_b64encode(orjson.dumps(values)).decode("ascii")


def _decode_cursor(cursor: str) -> list[Any]:
    try:
        values = orjson.loads(base64.urlsafe_b64decode(cursor.encode("ascii")))
    except Exception as exc:  # noqa: BLE001
        raise SourceTableError("Invalid cursor") from exc
    if not isinstance(values, list):
        raise SourceTableError("Invalid cursor")
    return values


def _hit_values(source: dict, width: int) -> list[str]:
    return [str(source.get(f"c{position}", "")) for position in range(width)]


def query_table_rows(
    table: SourceTable,
    *,
    q: str | None = None,
    filters: list[dict] | None = None,
    sort_column: Any = None,
    sort_order: str = "asc",
    cursor: str | None = None,
    size: int = 200,
) -> dict[str, Any]:
    if table.status != "ready" or not table.index_name:
        raise SourceTableError("Table is not ready")
    size = max(1, min(int(size or 200), MAX_PAGE_SIZE))
    width = _column_count(table)
    body: dict[str, Any] = {
        "query": build_table_query(table, q, filters),
        "sort": _sort_clause(table, sort_column, sort_order),
        "size": size,
        "track_total_hits": True,
    }
    if cursor:
        body["search_after"] = _decode_cursor(cursor)
    response = get_opensearch_client().search(index=table.index_name, body=body)
    hits = response.get("hits", {}).get("hits", [])
    total = response.get("hits", {}).get("total", {})
    rows = [{"row": hit["_source"].get("row"), "values": _hit_values(hit["_source"], width)} for hit in hits]
    next_cursor = _encode_cursor(hits[-1]["sort"]) if len(hits) == size and hits[-1].get("sort") else None
    return {
        "total": int(total.get("value", 0)) if isinstance(total, dict) else int(total or 0),
        "rows": rows,
        "next_cursor": next_cursor,
    }


def column_values(table: SourceTable, column: Any, *, q: str | None = None, filters: list[dict] | None = None, size: int = 50) -> list[dict]:
    """Most frequent values of one column under the current filters."""
    if table.status != "ready" or not table.index_name:
        raise SourceTableError("Table is not ready")
    position = _check_column(table, column)
    body = {
        "size": 0,
        "query": build_table_query(table, q, filters),
        "aggs": {"values": {"terms": {"field": f"c{position}", "size": max(1, min(int(size), 200)), "missing": ""}}},
    }
    response = get_opensearch_client().search(index=table.index_name, body=body)
    buckets = response.get("aggregations", {}).get("values", {}).get("buckets", [])
    return [{"value": str(bucket.get("key", "")), "count": int(bucket.get("doc_count", 0))} for bucket in buckets]


def export_table_csv(
    table: SourceTable,
    *,
    q: str | None = None,
    filters: list[dict] | None = None,
    sort_column: Any = None,
    sort_order: str = "asc",
    visible_columns: list[int] | None = None,
) -> Iterator[str]:
    """Stream the filtered, sorted table as CSV, in batches."""
    width = _column_count(table)
    positions = [_check_column(table, value) for value in visible_columns] if visible_columns else list(range(width))
    names = [str((table.columns or [])[position].get("name") or "") for position in positions]
    buffer = io.StringIO()
    writer = csv.writer(buffer)
    writer.writerow(names)
    yield buffer.getvalue()
    cursor: str | None = None
    while True:
        page = query_table_rows(table, q=q, filters=filters, sort_column=sort_column, sort_order=sort_order, cursor=cursor, size=EXPORT_BATCH)
        buffer = io.StringIO()
        writer = csv.writer(buffer)
        for row in page["rows"]:
            writer.writerow([row["values"][position] for position in positions])
        yield buffer.getvalue()
        cursor = page["next_cursor"]
        if not cursor:
            break
