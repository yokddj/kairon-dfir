from __future__ import annotations

from fastapi import APIRouter, Depends, Query, Response
from sqlalchemy.orm import Session

from app.core.database import get_db
from app.services.report_service import (
    build_case_report_preview,
    create_case_report_draft,
    download_report_by_id,
    export_case_report,
    generate_evidence_summary_report,
    get_case_report,
    get_report_by_id,
    list_evidence_reports,
    list_case_reports,
    list_report_templates,
    update_case_report,
)


router = APIRouter(tags=["reports"])


@router.get("/api/cases/{case_id}/reports/templates")
def get_case_report_templates(case_id: str) -> dict:
    return {"case_id": case_id, "items": list_report_templates()}


@router.get("/api/cases/{case_id}/reports")
def get_case_reports(case_id: str, db: Session = Depends(get_db)) -> list[dict]:
    return list_case_reports(db, case_id)


@router.post("/api/cases/{case_id}/reports/draft", status_code=201)
def create_report_draft(case_id: str, payload: dict, db: Session = Depends(get_db)) -> dict:
    return create_case_report_draft(db, case_id, payload)


@router.get("/api/cases/{case_id}/reports/{report_id}")
def read_case_report(case_id: str, report_id: str, db: Session = Depends(get_db)) -> dict:
    return get_case_report(db, case_id, report_id)


@router.patch("/api/cases/{case_id}/reports/{report_id}")
def patch_case_report(case_id: str, report_id: str, payload: dict, db: Session = Depends(get_db)) -> dict:
    return update_case_report(db, case_id, report_id, payload)


@router.get("/api/cases/{case_id}/reports/{report_id}/preview")
def preview_case_report(case_id: str, report_id: str, db: Session = Depends(get_db)) -> dict:
    return build_case_report_preview(db, case_id, report_id)


@router.get("/api/cases/{case_id}/reports/{report_id}/export")
def export_report(case_id: str, report_id: str, format: str = Query(default="markdown"), db: Session = Depends(get_db)) -> Response:
    content, filename, media_type = export_case_report(db, case_id, report_id, format=format)
    return Response(
        content=content,
        media_type=media_type,
        headers={
            "Content-Disposition": f'attachment; filename="{filename}"',
            "Access-Control-Expose-Headers": "Content-Disposition",
        },
    )


@router.post("/api/evidences/{evidence_id}/reports/generate", status_code=201)
def generate_evidence_report(evidence_id: str, payload: dict, db: Session = Depends(get_db)) -> dict:
    return generate_evidence_summary_report(db, evidence_id, payload)


@router.get("/api/evidences/{evidence_id}/reports")
def get_evidence_reports(evidence_id: str, db: Session = Depends(get_db)) -> list[dict]:
    return list_evidence_reports(db, evidence_id)


@router.get("/api/reports/{report_id}")
def read_report(report_id: str, db: Session = Depends(get_db)) -> dict:
    return get_report_by_id(db, report_id)


@router.get("/api/reports/{report_id}/download")
def download_report(report_id: str, format: str | None = Query(default=None), db: Session = Depends(get_db)) -> Response:
    content, filename, media_type = download_report_by_id(db, report_id, format=format)
    return Response(
        content=content,
        media_type=media_type,
        headers={
            "Content-Disposition": f'attachment; filename="{filename}"',
            "Access-Control-Expose-Headers": "Content-Disposition",
        },
    )
