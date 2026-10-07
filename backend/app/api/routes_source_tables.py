from __future__ import annotations

from typing import Literal

from fastapi import APIRouter, Depends, HTTPException, Query
from fastapi.responses import StreamingResponse
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from app.core.database import get_db
from app.models.evidence import Evidence
from app.models.source_table import SourceTable
from app.services.source_tables import (
    SourceTableError,
    column_values,
    delete_source_table,
    ensure_column_emptiness,
    export_table_csv,
    query_table_rows,
    schedule_source_tables,
    serialize_table,
)

router = APIRouter(tags=["source-tables"])


class SourceTableRequest(BaseModel):
    # None: every CSV/TSV of the evidence.
    source_paths: list[str] | None = None


class SourceTableFilter(BaseModel):
    column: int
    op: Literal["contains", "not_contains", "equals", "not_equals", "empty", "not_empty"] = "contains"
    value: str | None = None


class SourceTableQuery(BaseModel):
    q: str | None = None
    filters: list[SourceTableFilter] = Field(default_factory=list)
    sort_column: int | None = None
    sort_order: Literal["asc", "desc"] = "asc"
    cursor: str | None = None
    size: int = Field(default=200, ge=1, le=1000)


class SourceTableValuesQuery(BaseModel):
    column: int
    q: str | None = None
    filters: list[SourceTableFilter] = Field(default_factory=list)
    size: int = Field(default=50, ge=1, le=200)


class SourceTableExport(BaseModel):
    q: str | None = None
    filters: list[SourceTableFilter] = Field(default_factory=list)
    sort_column: int | None = None
    sort_order: Literal["asc", "desc"] = "asc"
    columns: list[int] | None = None


def _get_table(db: Session, case_id: str, table_id: str) -> SourceTable:
    table = db.get(SourceTable, table_id)
    if table is None or table.case_id != case_id:
        raise HTTPException(status_code=404, detail="Source table not found")
    return table


def _filters(items: list[SourceTableFilter]) -> list[dict]:
    return [item.model_dump() for item in items]


@router.get("/api/cases/{case_id}/source-tables")
def list_source_tables(case_id: str, evidence_id: str | None = Query(default=None), db: Session = Depends(get_db)) -> dict:
    query = db.query(SourceTable).filter(SourceTable.case_id == case_id)
    if evidence_id:
        query = query.filter(SourceTable.evidence_id == evidence_id)
    tables = query.order_by(SourceTable.created_at.desc()).all()
    return {"items": [serialize_table(table) for table in tables]}


@router.post("/api/cases/{case_id}/evidence/{evidence_id}/source-tables")
def create_source_tables(case_id: str, evidence_id: str, payload: SourceTableRequest, db: Session = Depends(get_db)) -> dict:
    evidence = db.get(Evidence, evidence_id)
    if evidence is None or evidence.case_id != case_id:
        raise HTTPException(status_code=404, detail="Evidence not found")
    try:
        tables, queued = schedule_source_tables(db, evidence, payload.source_paths)
    except SourceTableError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    return {"items": [serialize_table(table) for table in tables], "queued": queued}


@router.get("/api/cases/{case_id}/source-tables/{table_id}")
def get_source_table(case_id: str, table_id: str, db: Session = Depends(get_db)) -> dict:
    table = _get_table(db, case_id, table_id)
    try:
        ensure_column_emptiness(db, table)
    except Exception:  # noqa: BLE001 - the table is still usable without it
        db.rollback()
    return serialize_table(table)


@router.delete("/api/cases/{case_id}/source-tables/{table_id}")
def remove_source_table(case_id: str, table_id: str, db: Session = Depends(get_db)) -> dict:
    table = _get_table(db, case_id, table_id)
    if table.status == "building":
        raise HTTPException(status_code=409, detail="The table is being built")
    delete_source_table(db, table)
    return {"deleted": True}


@router.post("/api/cases/{case_id}/source-tables/{table_id}/rows")
def source_table_rows(case_id: str, table_id: str, payload: SourceTableQuery, db: Session = Depends(get_db)) -> dict:
    table = _get_table(db, case_id, table_id)
    try:
        return query_table_rows(
            table,
            q=payload.q,
            filters=_filters(payload.filters),
            sort_column=payload.sort_column,
            sort_order=payload.sort_order,
            cursor=payload.cursor,
            size=payload.size,
        )
    except SourceTableError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@router.post("/api/cases/{case_id}/source-tables/{table_id}/values")
def source_table_values(case_id: str, table_id: str, payload: SourceTableValuesQuery, db: Session = Depends(get_db)) -> dict:
    table = _get_table(db, case_id, table_id)
    try:
        return {"items": column_values(table, payload.column, q=payload.q, filters=_filters(payload.filters), size=payload.size)}
    except SourceTableError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@router.post("/api/cases/{case_id}/source-tables/{table_id}/export")
def source_table_export(case_id: str, table_id: str, payload: SourceTableExport, db: Session = Depends(get_db)) -> StreamingResponse:
    table = _get_table(db, case_id, table_id)
    if table.status != "ready":
        raise HTTPException(status_code=400, detail="Table is not ready")
    try:
        stream = export_table_csv(
            table,
            q=payload.q,
            filters=_filters(payload.filters),
            sort_column=payload.sort_column,
            sort_order=payload.sort_order,
            visible_columns=payload.columns,
        )
        first = next(stream)
    except SourceTableError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc

    def body():
        yield first
        yield from stream

    stem = table.name.rsplit(".", 1)[0] or "table"
    safe_stem = "".join(char if char.isalnum() or char in "-_." else "_" for char in stem)[:120]
    return StreamingResponse(body(), media_type="text/csv", headers={"Content-Disposition": f'attachment; filename="{safe_stem}-filtered.csv"'})
