from __future__ import annotations

from collections import Counter
from datetime import UTC, datetime
from io import BytesIO
import json
from pathlib import Path
import re
from typing import Any
from xml.sax.saxutils import escape

from fastapi import HTTPException
from reportlab.lib import colors
from reportlab.lib.enums import TA_CENTER, TA_LEFT
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import mm
from reportlab.platypus import Image, ListFlowable, ListItem, PageBreak, Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle
from reportlab.pdfgen import canvas
from sqlalchemy import func
from sqlalchemy.orm import Session

from app.api.routes_cases import _build_case_context
from app.core.app_settings import get_setting
from app.core.config import get_settings
from app.core.manifest import default_manifest
from app.core.opensearch import count_documents, fetch_event_by_id, get_events_index, get_opensearch_client, resolve_aggregatable_field, search_documents
from app.core.storage import evidence_manifest_path
from app.models.case import Case
from app.models.case_report import CaseReport, CaseReportStatus
from app.models.detection_result import DetectionResult
from app.models.event_marking import EventMarking
from app.models.evidence import Evidence
from app.models.finding import Finding
from app.models.timeline_bookmark import TimelineBookmark
from app.services.command_history import get_command_history
from app.services.debug_export import build_execution_story
from app.services.email_artifacts import build_email_artifacts_report_context, render_email_artifacts_markdown
from app.services.parser_registry import (
    SEARCHABLE_CONTRACT_VERSION,
    build_indexed_field_coverage_by_artifact_type,
    build_non_searchable_artifacts_report,
    build_parser_registry_report,
    build_searchable_contract_report,
)
from app.services.problematic_artifacts import build_problematic_artifacts_report
from app.services.search_service import search_events_v2
from app.services.motw import build_motw_report_context, render_motw_markdown
from app.services.startup_persistence import build_startup_persistence_report_context, render_startup_persistence_markdown
from app.services.timeline_service import build_incident_timeline_draft, export_incident_timeline_markdown
from app.services.validation_matrix import get_validation_matrix, render_validation_matrix_markdown, should_show_validation_matrix


REPORT_TEMPLATES = [
    {
        "id": "standard_investigation",
        "name": "Standard Investigation Report",
        "description": "Executive summary, findings, timeline, IOCs and recommendations",
        "sections": [
            "executive_summary",
            "scope",
            "evidence",
            "hosts",
            "findings",
            "timeline",
            "incident_timeline",
            "ground_truth_coverage",
            "process_chains",
            "command_history",
            "defender",
            "email",
            "motw",
            "srum",
            "iocs",
            "persistence",
            "network_cloud_usb",
            "recommendations",
            "appendix",
        ],
    }
]

DEFAULT_SECTIONS_ENABLED = {section: True for section in REPORT_TEMPLATES[0]["sections"]}
DEFAULT_ANALYST_NOTES = {
    "executive_summary": "",
    "recommendations": "",
    "limitations": "",
}
DEFAULT_FILTERS = {
    "host": None,
    "evidence_id": None,
    "include_statuses": ["confirmed", "reviewed", "new"],
    "min_severity": "medium",
    "time_from": None,
    "time_to": None,
    "risk_min": None,
    "risk_max": None,
    "include_findings": True,
    "include_detections": True,
    "include_marked_events": True,
    "include_timeline_events": True,
    "include_incident_timeline": True,
    "include_ground_truth_coverage": False,
    "include_command_history": True,
    "include_defender": True,
    "include_email": True,
    "include_srum": True,
    "command_only_suspicious": True,
    "command_shell": None,
    "command_family": None,
    "command_launcher": None,
    "command_source_type": None,
    "command_risk_min": None,
    "command_risk_max": None,
    "command_has_supporting_events": False,
    "command_query": None,
    "command_marking_status": None,
    "include_execution_stories": True,
    "max_commands": 50,
    "max_execution_stories": 10,
    "max_defender_events": 25,
    "max_email_items": 25,
    "max_srum_events": 25,
    "max_incident_timeline_items": 60,
    "detection_statuses": ["new", "reviewed", "confirmed"],
    "detection_severities": ["medium", "high", "critical"],
    "marking_statuses": ["suspicious", "important"],
    "artifact_type": None,
    "parser": None,
    "source_file": None,
    "rule_name": None,
}


def _default_report_filters_for_case(case: Case) -> dict[str, Any]:
    filters = dict(DEFAULT_FILTERS)
    filters["include_ground_truth_coverage"] = should_show_validation_matrix(
        case.id,
        getattr(case, "mode", None),
        validation_mode_enabled=get_settings().validation_features_enabled,
    )
    return filters
SEVERITY_ORDER = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}
_SECRET_INLINE = re.compile(r"(?i)\b(password|secret|token|access_token|refresh_token|apikey|api_key|authorization|bearer|keymaterial)\b\s*[:=]\s*([^\s|,;]+)")
_BEARER_TOKEN = re.compile(r"(?i)\bbearer\s+[A-Za-z0-9._~+/=-]{20,}\b")
_INLINE_CODE = re.compile(r"`([^`]+)`")
_MARKDOWN_LINK = re.compile(r"\[([^\]]+)\]\(([^)]+)\)")
_MARKDOWN_EMPHASIS = re.compile(r"(\*\*|__)(.*?)\1")

settings = get_settings()
ON_DEMAND_REPORT_FORMATS = {"json", "markdown", "html"}
ACTIVE_REPORT_STATUSES = {CaseReportStatus.queued, CaseReportStatus.running}


def list_report_templates() -> list[dict[str, Any]]:
    return REPORT_TEMPLATES


def list_case_reports(db: Session, case_id: str) -> list[dict[str, Any]]:
    _get_case_or_404(db, case_id)
    rows = db.query(CaseReport).filter(CaseReport.case_id == case_id).order_by(CaseReport.updated_at.desc()).all()
    return [_serialize_report(row) for row in rows]


def create_case_report_draft(db: Session, case_id: str, payload: dict[str, Any]) -> dict[str, Any]:
    case = _get_case_or_404(db, case_id)
    template = str(payload.get("template") or "standard_investigation")
    if template not in {item["id"] for item in REPORT_TEMPLATES}:
        raise HTTPException(status_code=400, detail="Unknown report template")
    filters = {**_default_report_filters_for_case(case), **dict(payload.get("filters") or {})}
    time_range = dict(payload.get("time_range") or {})
    sections_enabled = {**DEFAULT_SECTIONS_ENABLED, **dict(payload.get("sections_enabled") or {})}
    analyst_notes = {**DEFAULT_ANALYST_NOTES, **dict(payload.get("analyst_notes") or {})}
    auto_select = bool(payload.get("auto_select", True))

    selected_finding_ids: list[str] = list(payload.get("selected_finding_ids") or [])
    selected_key_event_ids: list[str] = list(payload.get("selected_key_event_ids") or [])
    selected_process_chain_ids: list[str] = list(payload.get("selected_process_chain_ids") or [])

    findings = _filtered_findings(db, case_id, filters)
    bookmarks = _filtered_bookmarks(db, case_id, filters)
    if auto_select:
        selected_finding_ids = _auto_select_finding_ids(findings)
        selected_key_event_ids = [bookmark.id for bookmark in bookmarks if bookmark.include_in_report]
        selected_process_chain_ids = _auto_select_process_chain_ids(findings)

    case_name = str(case.name or "").strip()
    report_case_label = case_name or f"Case {str(case.id)[:8]}"
    report = CaseReport(
        case_id=case_id,
        title=str(payload.get("title") or f"Kairon DFIR Investigation Report - {report_case_label}"),
        status=CaseReportStatus.draft,
        template=template,
        author=str(payload.get("author") or "").strip() or None,
        time_range=time_range,
        filters=filters,
        sections_enabled=sections_enabled,
        analyst_notes=analyst_notes,
        selected_finding_ids=_dedupe(selected_finding_ids),
        selected_key_event_ids=_dedupe(selected_key_event_ids),
        selected_process_chain_ids=_dedupe(selected_process_chain_ids),
        include_raw_appendix=bool(payload.get("include_raw_appendix", False)),
        include_debug_metadata=bool(payload.get("include_debug_metadata", False)),
    )
    db.add(report)
    db.commit()
    db.refresh(report)
    return _serialize_report(report)


def get_case_report(db: Session, case_id: str, report_id: str) -> dict[str, Any]:
    report = _get_report_or_404(db, case_id, report_id)
    return _serialize_report(report)


def update_case_report(db: Session, case_id: str, report_id: str, payload: dict[str, Any]) -> dict[str, Any]:
    report = _get_report_or_404(db, case_id, report_id)
    if "title" in payload:
        report.title = str(payload.get("title") or report.title)
    if "status" in payload and payload.get("status"):
        report.status = CaseReportStatus(str(payload["status"]))
    if "template" in payload and payload.get("template"):
        report.template = str(payload["template"])
    if "author" in payload:
        report.author = str(payload.get("author") or "").strip() or None
    if "time_range" in payload:
        report.time_range = dict(payload.get("time_range") or {})
    if "filters" in payload:
        case = _get_case_or_404(db, case_id)
        report.filters = {**_default_report_filters_for_case(case), **dict(payload.get("filters") or {})}
    if "sections_enabled" in payload:
        report.sections_enabled = {**DEFAULT_SECTIONS_ENABLED, **dict(payload.get("sections_enabled") or {})}
    if "analyst_notes" in payload:
        report.analyst_notes = {**DEFAULT_ANALYST_NOTES, **dict(payload.get("analyst_notes") or {})}
    if "selected_finding_ids" in payload:
        report.selected_finding_ids = _dedupe(payload.get("selected_finding_ids") or [])
    if "selected_key_event_ids" in payload:
        report.selected_key_event_ids = _dedupe(payload.get("selected_key_event_ids") or [])
    if "selected_process_chain_ids" in payload:
        report.selected_process_chain_ids = _dedupe(payload.get("selected_process_chain_ids") or [])
    if "include_raw_appendix" in payload:
        report.include_raw_appendix = bool(payload.get("include_raw_appendix"))
    if "include_debug_metadata" in payload:
        report.include_debug_metadata = bool(payload.get("include_debug_metadata"))
    db.add(report)
    db.commit()
    db.refresh(report)
    return _serialize_report(report)


def build_case_report_preview(db: Session, case_id: str, report_id: str) -> dict[str, Any]:
    report = _get_report_or_404(db, case_id, report_id)
    case = _get_case_or_404(db, case_id)
    context = _build_case_context(db, case_id)
    filters = {**_default_report_filters_for_case(case), **dict(report.filters or {})}
    sections_enabled = {**DEFAULT_SECTIONS_ENABLED, **dict(report.sections_enabled or {})}
    findings = _filtered_findings(db, case_id, filters)
    detections = _filtered_detections(db, case_id, filters)
    marked_events = _filtered_markings(db, case_id, filters)
    command_report = _build_command_history_report_context(db, case, case_id, filters)
    defender_report = _build_defender_report_context(db, case_id, filters)
    email_report = build_email_artifacts_report_context(db, case_id, filters)
    srum_report = _build_srum_report_context(db, case_id, filters)
    motw_report = build_motw_report_context(db, case_id, filters)
    incident_timeline_report = _build_incident_timeline_report_context(db, case_id, filters)
    persistence_report = build_startup_persistence_report_context(db, case_id, filters)
    findings_by_id = {finding.id: finding for finding in findings}
    selected_finding_ids = list(report.selected_finding_ids or [])
    selected_key_event_ids = list(report.selected_key_event_ids or [])
    selected_process_chain_ids = list(report.selected_process_chain_ids or [])
    selected_findings = [findings_by_id[finding_id] for finding_id in selected_finding_ids if finding_id in findings_by_id] if filters.get("include_findings", True) else []
    bookmarks = _filtered_bookmarks(db, case_id, filters)
    bookmarks_by_id = {bookmark.id: bookmark for bookmark in bookmarks}
    selected_bookmarks = [bookmarks_by_id[bookmark_id] for bookmark_id in selected_key_event_ids if bookmark_id in bookmarks_by_id] if filters.get("include_timeline_events", True) else []
    selected_chain_findings = [findings_by_id[finding_id] for finding_id in selected_process_chain_ids if finding_id in findings_by_id]
    if not selected_findings and findings:
        selected_findings = [_auto_select_findings(findings)[0]] if _auto_select_findings(findings) else []
    if not selected_bookmarks and bookmarks:
        selected_bookmarks = [bookmark for bookmark in bookmarks if bookmark.include_in_report]

    timeline_entries, timeline_auto_selected = _build_timeline_entries(selected_bookmarks, selected_findings)
    if filters.get("include_marked_events", True):
        timeline_entries.extend(_build_marked_event_entries(marked_events))
        timeline_entries.sort(key=lambda item: _safe_dt(item.get("timestamp")))
    ioc_rows = _extract_iocs(case_id, selected_findings, selected_bookmarks)
    sections = []
    warnings: list[str] = []
    ground_truth_visible = should_show_validation_matrix(
        case_id,
        getattr(case, "mode", None),
        validation_mode_enabled=get_settings().validation_features_enabled,
    )
    stats = {
        "findings_matched": len(findings),
        "detections_matched": len(detections),
        "marked_events_matched": len(marked_events),
        "timeline_events_matched": len(bookmarks),
        "command_history_matched": int(command_report["counts"]["command_history_matched"]),
        "suspicious_commands_matched": int(command_report["counts"]["suspicious_commands_matched"]),
        "marked_commands_matched": int(command_report["counts"]["marked_commands_matched"]),
        "execution_stories_available": int(command_report["counts"]["execution_stories_available"]),
        "commands_included": len(command_report["commands"]),
        "execution_stories_included": len(command_report["stories"]),
        "defender_events_matched": int(defender_report["counts"]["defender_events_matched"]),
        "defender_events_included": len(defender_report["events"]),
        "defender_high_severity": int(defender_report["counts"]["defender_high_severity"]),
        "defender_failed_actions": int(defender_report["counts"]["defender_failed_actions"]),
        "email_artifacts": int(email_report["counts"].get("total") or 0),
        "email_stores": int(email_report["counts"].get("stores") or 0),
        "srum_events_matched": int(srum_report["counts"]["srum_events_matched"]),
        "srum_events_included": len(srum_report["events"]),
        "srum_network_usage": int(srum_report["counts"]["srum_network_usage"]),
        "srum_total_bytes": int(srum_report["counts"]["srum_total_bytes"]),
        "motw_items": int(motw_report["counts"].get("total") or 0),
        "motw_suspicious": int(motw_report["counts"].get("suspicious") or 0),
        "incident_timeline_items": int(incident_timeline_report["counts"]["incident_timeline_items"]),
        "startup_persistence_items": int(persistence_report["counts"].get("total") or 0),
        "startup_persistence_suspicious": int(persistence_report["counts"].get("suspicious") or 0),
        "ground_truth_total_expected": int(get_validation_matrix(case_id)["summary"].get("total_expected") or 0) if ground_truth_visible else 0,
        "commands_by_shell": command_report["counts"]["commands_by_shell"],
        "commands_by_family": command_report["counts"].get("commands_by_family", command_report["counts"]["commands_by_shell"]),
        "commands_by_launcher": command_report["counts"].get("commands_by_launcher", {}),
        "commands_by_source_type": command_report["counts"]["commands_by_source_type"],
        "selected_findings": len(selected_findings),
        "selected_key_events": len(selected_bookmarks),
        "selected_process_chains": len(selected_chain_findings),
        "ioc_count": len(ioc_rows),
    }
    filters_applied = _report_filters_applied(filters, report.time_range or {})

    if sections_enabled.get("executive_summary", True):
        sections.append({"id": "executive_summary", "title": "Executive Summary", "markdown": _render_executive_summary(case, context, selected_findings, report), "warnings": []})
    if sections_enabled.get("scope", True):
        sections.append({"id": "scope", "title": "Scope", "markdown": _render_scope(case, context, report), "warnings": []})
    if sections_enabled.get("evidence", True):
        sections.append({"id": "evidence", "title": "Evidence Processed", "markdown": _render_evidence(context), "warnings": []})
    if sections_enabled.get("hosts", True):
        sections.append({"id": "hosts", "title": "Hosts", "markdown": _render_hosts(context), "warnings": []})
    if sections_enabled.get("findings", True):
        sections.append({"id": "findings", "title": "Findings", "markdown": _render_findings(selected_findings), "warnings": [] if selected_findings else ["No findings selected for the report."]})
    if sections_enabled.get("findings", True) and filters.get("include_detections", True):
        sections.append({"id": "detections", "title": "Detections", "markdown": _render_detections(detections), "warnings": [] if detections else ["No detections matched the report filters."]})
    if sections_enabled.get("timeline", True):
        timeline_warnings = ["Timeline was auto-selected because no key events were selected."] if timeline_auto_selected else []
        sections.append({"id": "timeline", "title": "Investigation Timeline", "markdown": _render_timeline(timeline_entries), "warnings": timeline_warnings})
    if sections_enabled.get("incident_timeline", True) and filters.get("include_incident_timeline", True):
        sections.append(
            {
                "id": "incident_timeline",
                "title": "Incident Timeline",
                "markdown": _render_incident_timeline_section(case_id, incident_timeline_report["items"]),
                "warnings": incident_timeline_report["warnings"] or ([] if incident_timeline_report["items"] else ["No incident timeline items were generated."]),
            }
        )
    if sections_enabled.get("ground_truth_coverage", True) and filters.get("include_ground_truth_coverage", False) and ground_truth_visible:
        matrix = get_validation_matrix(case_id)
        sections.append(
            {
                "id": "ground_truth_coverage",
                "title": "Ground Truth Coverage",
                "markdown": render_validation_matrix_markdown(matrix),
                "warnings": matrix.get("warnings") or ([] if matrix.get("items") else ["No validation matrix is available for this case."]),
            }
        )
    if sections_enabled.get("process_chains", True):
        sections.append({"id": "process_chains", "title": "Process Chains", "markdown": _render_process_chains(selected_chain_findings), "warnings": [] if selected_chain_findings else ["No process chains selected or available."]})
    if sections_enabled.get("command_history", True) and filters.get("include_command_history", True):
        sections.append(
            {
                "id": "command_history",
                "title": "Suspicious Command History",
                "markdown": _render_command_history_section(command_report["commands"], command_report["stories"]),
                "warnings": command_report["warnings"] or ([] if command_report["commands"] else ["No command history matched current filters."]),
            }
        )
    if sections_enabled.get("defender", True) and filters.get("include_defender", True):
        sections.append(
            {
                "id": "defender",
                "title": "Microsoft Defender",
                "markdown": _render_defender_section(defender_report["events"]),
                "warnings": defender_report["warnings"] or ([] if defender_report["events"] else ["No Defender events matched current filters."]),
            }
        )
    if sections_enabled.get("email", True) and filters.get("include_email", True):
        sections.append(
            {
                "id": "email",
                "title": "Email Artifacts",
                "markdown": render_email_artifacts_markdown(email_report["items"]),
                "warnings": email_report["warnings"] or email_report["limitations"] or ([] if email_report["items"] else ["No email artifacts matched current filters."]),
            }
        )
    if sections_enabled.get("motw", True):
        sections.append(
            {
                "id": "motw",
                "title": "MOTW / Downloaded Files",
                "markdown": render_motw_markdown(motw_report["items"]),
                "warnings": motw_report["warnings"] or ([] if motw_report["items"] else ["No MOTW / Zone.Identifier items matched current filters."]),
            }
        )
    if sections_enabled.get("srum", True) and filters.get("include_srum", True):
        sections.append(
            {
                "id": "srum",
                "title": "SRUM Application and Network Usage",
                "markdown": _render_srum_section(srum_report["events"]),
                "warnings": srum_report["warnings"] or ([] if srum_report["events"] else ["No SRUM records matched current filters."]),
            }
        )
    if sections_enabled.get("iocs", True):
        sections.append({"id": "iocs", "title": "IOCs", "markdown": _render_iocs(ioc_rows), "warnings": []})
    if sections_enabled.get("persistence", True):
        persistence_markdown = render_startup_persistence_markdown(persistence_report["items"])
        if not persistence_report["items"]:
            persistence_markdown = _render_persistence(selected_findings)
        sections.append({"id": "persistence", "title": "Startup & Persistence", "markdown": persistence_markdown, "warnings": persistence_report["warnings"] or []})
    if sections_enabled.get("network_cloud_usb", True):
        sections.append({"id": "network_cloud_usb", "title": "Network / Cloud / USB", "markdown": _render_network_cloud_usb(selected_findings), "warnings": []})
    if sections_enabled.get("recommendations", True):
        sections.append({"id": "recommendations", "title": "Recommendations", "markdown": _render_recommendations(selected_findings, report), "warnings": []})
    if sections_enabled.get("appendix", True):
        sections.append({"id": "appendix", "title": "Appendix", "markdown": _render_appendix(report, timeline_entries, selected_findings), "warnings": []})

    if context["summary"]["warnings"]:
        warnings.extend(context["summary"]["warnings"])
    if command_report["warnings"]:
        warnings.extend(command_report["warnings"])
    if defender_report["warnings"]:
        warnings.extend(defender_report["warnings"])
    if email_report["warnings"]:
        warnings.extend(email_report["warnings"])
    if srum_report["warnings"]:
        warnings.extend(srum_report["warnings"])
    if motw_report["warnings"]:
        warnings.extend(motw_report["warnings"])
    if incident_timeline_report["warnings"]:
        warnings.extend(incident_timeline_report["warnings"])
    if not any([len(findings), len(detections), len(marked_events), len(bookmarks), len(command_report["commands"]), len(defender_report["events"]), len(srum_report["events"])]):
        warnings.append("No data matched the selected report filters.")
    return {
        "title": report.title,
        "sections": sections,
        "warnings": warnings,
        "stats": stats,
        "counts": stats,
        "filters_applied": filters_applied,
    }


def export_case_report(db: Session, case_id: str, report_id: str, *, format: str) -> tuple[str | bytes, str, str]:
    report = _get_report_or_404(db, case_id, report_id)
    if format not in {"markdown", "pdf"}:
        raise HTTPException(status_code=400, detail="Unsupported export format")
    preview = build_case_report_preview(db, case_id, report_id)
    case = _get_case_or_404(db, case_id)
    if format == "markdown":
        content: str | bytes = _render_markdown_document(preview["title"], preview["sections"])
        filename = _slugify_filename(report.title or f"case-report-{case_id}") + ".md"
        media_type = "text/markdown; charset=utf-8"
    else:
        context = _build_case_context(db, case_id)
        try:
            content = _render_pdf_document(report, case, context, preview, _load_report_branding(db))
        except ImportError as exc:  # pragma: no cover - import errors are environment specific
            raise HTTPException(status_code=503, detail="PDF renderer is unavailable in the current backend image.") from exc
        except PdfRendererUnavailableError as exc:
            raise HTTPException(status_code=503, detail=str(exc)) from exc
        filename = _slugify_filename(report.title or f"case-report-{case_id}") + ".pdf"
        media_type = "application/pdf"
    report.generated_at = datetime.now(UTC)
    report.status = CaseReportStatus.generated
    db.add(report)
    db.commit()
    return content, filename, media_type


def list_evidence_reports(db: Session, evidence_id: str) -> list[dict[str, Any]]:
    evidence = _get_evidence_or_404(db, evidence_id)
    rows = (
        db.query(CaseReport)
        .filter(CaseReport.evidence_id == evidence.id)
        .order_by(CaseReport.updated_at.desc(), CaseReport.created_at.desc())
        .all()
    )
    return [_serialize_report(row) for row in rows]


def get_report_by_id(db: Session, report_id: str) -> dict[str, Any]:
    report = db.get(CaseReport, report_id)
    if not report:
        raise HTTPException(status_code=404, detail="Report not found")
    return _serialize_report(report)


def generate_evidence_summary_report(db: Session, evidence_id: str, payload: dict[str, Any]) -> dict[str, Any]:
    evidence = _get_evidence_or_404(db, evidence_id)
    format_name = str(payload.get("format") or "markdown").strip().lower()
    if format_name not in ON_DEMAND_REPORT_FORMATS:
        raise HTTPException(status_code=400, detail="Unsupported report format")
    report_type = str(payload.get("report_type") or "summary").strip().lower()
    if report_type != "summary":
        raise HTTPException(status_code=400, detail="Unsupported report_type")
    indexed_docs = _count_evidence_indexed_docs(evidence)
    detections_count = int(
        db.query(func.count(DetectionResult.id)).filter(DetectionResult.evidence_id == evidence.id).scalar() or 0
    )
    manifest = _load_evidence_manifest(evidence)
    problematic_preview = build_problematic_artifacts_report(evidence, manifest, artifact_rows=list(evidence.artifacts or []))
    problematic_count = int((problematic_preview.get("summary") or {}).get("problematic_count") or 0)
    if indexed_docs <= 0 and detections_count <= 0 and problematic_count <= 0:
        raise HTTPException(status_code=400, detail="No indexed data or detections are available for this evidence yet.")
    force = bool(payload.get("force"))
    if not force:
        active = (
            db.query(CaseReport)
            .filter(
                CaseReport.evidence_id == evidence.id,
                CaseReport.report_type == report_type,
                CaseReport.mode == "on_demand",
                CaseReport.status.in_(list(ACTIVE_REPORT_STATUSES)),
            )
            .first()
        )
        if active:
            raise HTTPException(status_code=409, detail="An active on-demand summary report already exists for this evidence.")
    included_sections = {
        "ingest_summary": True,
        "search_summary": bool(payload.get("include_search_summary", True)),
        "parser_contract": bool(payload.get("include_parser_contract", True)),
        "detections": bool(payload.get("include_detections", True)),
        "problematic_artifacts": bool(payload.get("include_problematic_artifacts", True)),
        "links": True,
    }
    report = CaseReport(
        case_id=evidence.case_id,
        evidence_id=evidence.id,
        title=str(payload.get("title") or f"Evidence Summary Report - {evidence.original_filename}"),
        status=CaseReportStatus.queued,
        template="evidence_summary",
        report_type=report_type,
        format=format_name,
        mode="on_demand",
        source_ingest_run_id=str((evidence.metadata_json or {}).get("latest_ingest_run_id") or "") or None,
        metadata_json={
            "scope": "evidence",
            "requested_by": "manual",
            "requested_via": "evidence_on_demand",
            "mode": "on_demand",
            "report_type": report_type,
            "format": format_name,
            "included_sections": included_sections,
            "indexed_events_input_count": indexed_docs,
        },
    )
    db.add(report)
    db.commit()
    db.refresh(report)

    report.status = CaseReportStatus.running
    report.metadata_json = {**dict(report.metadata_json or {}), "started_at": datetime.now(UTC).isoformat()}
    db.add(report)
    db.commit()
    db.refresh(report)

    try:
        summary = _build_evidence_summary_payload(
            db,
            evidence,
            include_detections=included_sections["detections"],
            include_problematic_artifacts=included_sections["problematic_artifacts"],
            include_search_summary=included_sections["search_summary"],
            include_parser_contract=included_sections["parser_contract"],
        )
        json_content = json.dumps(summary, indent=2, ensure_ascii=True)
        markdown_content = _render_evidence_summary_markdown(summary)
        html_content = _render_evidence_summary_html(summary)
        report_dir = _report_output_dir(report.id)
        report_dir.mkdir(parents=True, exist_ok=True)
        json_path = report_dir / "summary.json"
        markdown_path = report_dir / "summary.md"
        html_path = report_dir / "summary.html"
        json_path.write_text(json_content, encoding="utf-8")
        markdown_path.write_text(markdown_content, encoding="utf-8")
        html_path.write_text(html_content, encoding="utf-8")
        chosen_path = {"json": json_path, "markdown": markdown_path, "html": html_path}[format_name]
        warnings = list(summary.get("warnings") or [])
        report.status = CaseReportStatus.completed_with_warnings if warnings else CaseReportStatus.completed
        report.generated_at = datetime.now(UTC)
        report.output_path = str(chosen_path)
        report.size_bytes = chosen_path.stat().st_size
        report.metadata_json = {
            **dict(report.metadata_json or {}),
            "finished_at": datetime.now(UTC).isoformat(),
            "errors": [],
            "warnings": warnings,
            "size_bytes": report.size_bytes,
            "output_files": {
                "json": str(json_path),
                "markdown": str(markdown_path),
                "html": str(html_path),
            },
            "summary": summary,
        }
        db.add(report)
        db.commit()
        db.refresh(report)
        return _serialize_report(report)
    except HTTPException:
        report.status = CaseReportStatus.failed
        report.metadata_json = {
            **dict(report.metadata_json or {}),
            "finished_at": datetime.now(UTC).isoformat(),
        }
        db.add(report)
        db.commit()
        raise
    except Exception as exc:
        report.status = CaseReportStatus.failed
        report.metadata_json = {
            **dict(report.metadata_json or {}),
            "finished_at": datetime.now(UTC).isoformat(),
            "errors": [str(exc)],
        }
        db.add(report)
        db.commit()
        raise HTTPException(status_code=500, detail=f"Report generation failed: {exc}") from exc


def download_report_by_id(db: Session, report_id: str, *, format: str | None = None) -> tuple[str | bytes, str, str]:
    report = db.get(CaseReport, report_id)
    if not report:
        raise HTTPException(status_code=404, detail="Report not found")
    requested_format = str(format or report.format or "markdown").strip().lower()
    if requested_format not in ON_DEMAND_REPORT_FORMATS:
        raise HTTPException(status_code=400, detail="Unsupported report format")
    if report.mode != "on_demand" or report.report_type != "summary":
        if requested_format == "markdown":
            return export_case_report(db, report.case_id, report.id, format="markdown")
        raise HTTPException(status_code=400, detail="Only markdown export is available for legacy reports through this endpoint.")
    output_files = dict((report.metadata_json or {}).get("output_files") or {})
    target_path = output_files.get(requested_format) or report.output_path
    if not target_path:
        raise HTTPException(status_code=404, detail="Report output is not available.")
    path = Path(str(target_path))
    if not path.exists() or not path.is_file():
        raise HTTPException(status_code=404, detail="Report output is not available.")
    content = path.read_bytes()
    extension = "json" if requested_format == "json" else "html" if requested_format == "html" else "md"
    media_type = "application/json" if requested_format == "json" else "text/html; charset=utf-8" if requested_format == "html" else "text/markdown; charset=utf-8"
    filename = _slugify_filename(report.title or f"report-{report.id}") + f".{extension}"
    return content, filename, media_type


class PdfRendererUnavailableError(RuntimeError):
    pass


def _load_report_branding(db: Session) -> dict[str, Any]:
    brand_name = str(get_setting(db, "REPORT_BRAND_NAME", settings.report_brand_name) or settings.report_brand_name).strip() or settings.report_brand_name
    subtitle = str(get_setting(db, "REPORT_BRAND_SUBTITLE", settings.report_brand_subtitle) or settings.report_brand_subtitle).strip()
    primary = str(get_setting(db, "REPORT_BRAND_PRIMARY_COLOR", settings.report_brand_primary_color) or settings.report_brand_primary_color).strip() or settings.report_brand_primary_color
    include_logo = bool(get_setting(db, "REPORT_INCLUDE_LOGO", settings.report_include_logo))
    logo_path = str(get_setting(db, "REPORT_LOGO_PATH", settings.report_logo_path) or "").strip()
    return {
        "brand_name": _sanitize_text(brand_name),
        "subtitle": _sanitize_text(subtitle),
        "primary_color": _normalize_hex_color(primary),
        "include_logo": include_logo,
        "logo_path": logo_path,
    }


def _render_pdf_document(report: CaseReport, case: Case, context: dict[str, Any], preview: dict[str, Any], branding: dict[str, Any]) -> bytes:
    palette = _pdf_palette(branding["primary_color"])
    styles = _build_pdf_styles(palette)
    buffer = BytesIO()
    doc = SimpleDocTemplate(
        buffer,
        pagesize=A4,
        leftMargin=18 * mm,
        rightMargin=18 * mm,
        topMargin=18 * mm,
        bottomMargin=16 * mm,
        title=preview["title"],
        author=report.author or branding["brand_name"],
    )
    story: list[Any] = []
    generated_at = datetime.now(UTC)

    _append_cover_page(story, report, case, context, preview, branding, palette, styles, generated_at)
    story.append(PageBreak())

    if preview.get("warnings"):
        story.append(Paragraph("Report warnings", styles["section_heading"]))
        story.append(_build_warning_table([str(item) for item in preview["warnings"]], styles, palette))
        story.append(Spacer(1, 8))

    for index, section in enumerate(preview.get("sections") or []):
        story.append(Paragraph(_pdf_inline(section.get("title") or "Section"), styles["section_heading"]))
        if section.get("warnings"):
            story.append(_build_warning_table([str(item) for item in section["warnings"]], styles, palette))
            story.append(Spacer(1, 5))
        _append_markdown_to_story(story, str(section.get("markdown") or ""), styles, palette)
        if index < len(preview.get("sections") or []) - 1:
            story.append(PageBreak())

    def canvas_maker(*args: Any, **kwargs: Any) -> canvas.Canvas:
        kwargs["pageCompression"] = 0
        pdf = canvas.Canvas(*args, **kwargs)
        build = settings.build_identity
        pdf.setCreator(f"Kairon DFIR {build['app_version']}")
        pdf.setProducer(build["build_fingerprint"])
        pdf.setSubject(build["notice"])
        pdf.setKeywords(",".join([build["vendor_id"], build["build_channel"], build["build_fingerprint"]]))
        return pdf

    def on_page(pdf_canvas: canvas.Canvas, _doc: SimpleDocTemplate) -> None:
        _draw_pdf_footer(pdf_canvas, doc, report, branding, generated_at, palette)

    try:
        doc.build(story, onFirstPage=on_page, onLaterPages=on_page, canvasmaker=canvas_maker)
    except Exception as exc:  # noqa: BLE001
        raise PdfRendererUnavailableError(f"PDF export failed: {exc}") from exc
    return buffer.getvalue()


def _append_cover_page(
    story: list[Any],
    report: CaseReport,
    case: Case,
    context: dict[str, Any],
    preview: dict[str, Any],
    branding: dict[str, Any],
    palette: dict[str, colors.Color],
    styles: dict[str, ParagraphStyle],
    generated_at: datetime,
) -> None:
    logo = _load_logo_image(branding)
    if logo is not None:
        story.append(logo)
        story.append(Spacer(1, 8))
    story.append(Paragraph(_pdf_inline(branding["brand_name"]), styles["cover_brand"]))
    if branding.get("subtitle"):
        story.append(Paragraph(_pdf_inline(branding["subtitle"]), styles["cover_subtitle"]))
    story.append(Spacer(1, 14))
    story.append(Paragraph(_pdf_inline(preview["title"]), styles["cover_title"]))
    story.append(Spacer(1, 10))
    story.append(
        Paragraph(
            _pdf_inline("Internal / Investigation Report"),
            ParagraphStyle(
                "classification",
                parent=styles["body"],
                alignment=TA_CENTER,
                textColor=palette["primary"],
                backColor=palette["primary_soft"],
                borderPadding=6,
                borderRadius=8,
            ),
        )
    )
    story.append(Spacer(1, 16))

    case_rows = [
        ["Case name", case.name],
        ["Case ID", case.id],
        ["Generated at", _iso(generated_at) or "-"],
        ["Timezone", str(case.timezone or "UTC")],
        ["Author", report.author or "Analyst"],
    ]
    story.append(_build_key_value_table(case_rows, palette, styles, col_widths=(38 * mm, 130 * mm)))
    story.append(Spacer(1, 12))

    summary = context.get("summary") or {}
    cover_stats = [
        ["Evidences", str(len(context.get("evidences") or []))],
        ["Events", str(summary.get("events_indexed") or 0)],
        ["Findings", str(summary.get("findings_total") or 0)],
        ["High findings", str(summary.get("findings_high") or 0)],
        ["Hosts", str(len(context.get("hosts") or []))],
        ["Selected indicators", str((preview.get("stats") or {}).get("ioc_count") or 0)],
    ]
    story.append(Paragraph("Executive Summary", styles["section_heading"]))
    story.append(_build_stats_table(cover_stats, palette, styles))


def _build_pdf_styles(palette: dict[str, colors.Color]) -> dict[str, ParagraphStyle]:
    base = getSampleStyleSheet()
    return {
        "cover_brand": ParagraphStyle("cover_brand", parent=base["Title"], fontName="Helvetica-Bold", fontSize=18, leading=22, textColor=palette["primary"], alignment=TA_CENTER),
        "cover_subtitle": ParagraphStyle("cover_subtitle", parent=base["BodyText"], fontName="Helvetica", fontSize=10, leading=13, textColor=palette["muted"], alignment=TA_CENTER),
        "cover_title": ParagraphStyle("cover_title", parent=base["Title"], fontName="Helvetica-Bold", fontSize=24, leading=28, textColor=colors.black, alignment=TA_CENTER, spaceAfter=8),
        "section_heading": ParagraphStyle("section_heading", parent=base["Heading1"], fontName="Helvetica-Bold", fontSize=16, leading=20, textColor=palette["primary"], spaceBefore=0, spaceAfter=8),
        "subheading": ParagraphStyle("subheading", parent=base["Heading2"], fontName="Helvetica-Bold", fontSize=12, leading=15, textColor=colors.black, spaceBefore=6, spaceAfter=4),
        "body": ParagraphStyle("body", parent=base["BodyText"], fontName="Helvetica", fontSize=9.5, leading=13, textColor=colors.black, spaceAfter=5, wordWrap="CJK", alignment=TA_LEFT),
        "body_small": ParagraphStyle("body_small", parent=base["BodyText"], fontName="Helvetica", fontSize=8.2, leading=11, textColor=colors.black, wordWrap="CJK"),
        "code": ParagraphStyle("code", parent=base["Code"], fontName="Courier", fontSize=8.2, leading=11, textColor=colors.black, backColor=colors.whitesmoke, borderPadding=5, wordWrap="CJK", spaceAfter=5),
        "bullet": ParagraphStyle("bullet", parent=base["BodyText"], fontName="Helvetica", fontSize=9.3, leading=13, leftIndent=10, firstLineIndent=0, bulletIndent=0, spaceAfter=2, wordWrap="CJK"),
    }


def _append_markdown_to_story(story: list[Any], markdown: str, styles: dict[str, ParagraphStyle], palette: dict[str, colors.Color]) -> None:
    lines = markdown.splitlines()
    index = 0
    while index < len(lines):
        line = lines[index].rstrip()
        stripped = line.strip()
        if not stripped:
            index += 1
            continue
        if stripped.startswith("|"):
            table_lines: list[str] = []
            while index < len(lines) and lines[index].strip().startswith("|"):
                table_lines.append(lines[index].strip())
                index += 1
            table = _parse_markdown_table(table_lines)
            if table:
                story.append(_build_markdown_table(table, styles, palette))
                story.append(Spacer(1, 6))
            continue
        if stripped.startswith("## "):
            story.append(Paragraph(_pdf_inline(stripped.removeprefix("## ").strip()), styles["subheading"]))
            index += 1
            continue
        if stripped.startswith("- "):
            bullet_lines: list[str] = []
            while index < len(lines) and lines[index].strip().startswith("- "):
                bullet_lines.append(lines[index].strip()[2:])
                index += 1
            story.append(
                ListFlowable(
                    [ListItem(Paragraph(_pdf_inline(item), styles["bullet"])) for item in bullet_lines],
                    bulletType="bullet",
                    leftIndent=10,
                )
            )
            story.append(Spacer(1, 4))
            continue
        if stripped.endswith(":") and index + 1 < len(lines) and lines[index + 1].strip().startswith("- "):
            story.append(Paragraph(_pdf_inline(stripped), styles["body"]))
            index += 1
            continue
        paragraph_lines = [stripped]
        index += 1
        while index < len(lines):
            candidate = lines[index].strip()
            if not candidate or candidate.startswith("|") or candidate.startswith("- ") or candidate.startswith("## "):
                break
            paragraph_lines.append(candidate)
            index += 1
        paragraph_text = " ".join(paragraph_lines)
        style = styles["code"] if _should_render_as_code(paragraph_text) else styles["body"]
        story.append(Paragraph(_pdf_inline(paragraph_text), style))
    if markdown.strip():
        story.append(Spacer(1, 4))


def _parse_markdown_table(lines: list[str]) -> list[list[str]]:
    rows: list[list[str]] = []
    for raw in lines:
        candidate = raw.strip().strip("|")
        if not candidate:
            continue
        parts = [_unescape_md_table_cell(part.strip()) for part in candidate.split("|")]
        if parts and all(set(cell) <= {"-", ":"} for cell in parts):
            continue
        rows.append(parts)
    if len(rows) < 1:
        return []
    width = max(len(row) for row in rows)
    for row in rows:
        if len(row) < width:
            row.extend([""] * (width - len(row)))
    return rows


def _build_markdown_table(rows: list[list[str]], styles: dict[str, ParagraphStyle], palette: dict[str, colors.Color]) -> Table:
    paragraph_rows = []
    for row_index, row in enumerate(rows):
        style = styles["body_small"] if row_index else ParagraphStyle("table_header", parent=styles["body_small"], fontName="Helvetica-Bold", textColor=palette["primary"])
        paragraph_rows.append([Paragraph(_pdf_inline(cell or "-"), style) for cell in row])
    column_width = (A4[0] - 36 * mm) / max(len(rows[0]), 1)
    table = Table(paragraph_rows, colWidths=[column_width] * len(rows[0]), repeatRows=1)
    table.setStyle(
        TableStyle(
            [
                ("BACKGROUND", (0, 0), (-1, 0), palette["header_fill"]),
                ("TEXTCOLOR", (0, 0), (-1, 0), palette["primary"]),
                ("GRID", (0, 0), (-1, -1), 0.4, palette["border"]),
                ("VALIGN", (0, 0), (-1, -1), "TOP"),
                ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, palette["zebra"]]),
                ("LEFTPADDING", (0, 0), (-1, -1), 5),
                ("RIGHTPADDING", (0, 0), (-1, -1), 5),
                ("TOPPADDING", (0, 0), (-1, -1), 4),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
            ]
        )
    )
    return table


def _build_warning_table(items: list[str], styles: dict[str, ParagraphStyle], palette: dict[str, colors.Color]) -> Table:
    table = Table([[Paragraph(_pdf_inline(item), styles["body_small"])] for item in items], colWidths=[A4[0] - 36 * mm])
    table.setStyle(
        TableStyle(
            [
                ("BACKGROUND", (0, 0), (-1, -1), palette["warning_fill"]),
                ("TEXTCOLOR", (0, 0), (-1, -1), palette["warning_text"]),
                ("BOX", (0, 0), (-1, -1), 0.6, palette["warning_border"]),
                ("INNERGRID", (0, 0), (-1, -1), 0.2, palette["warning_border"]),
                ("LEFTPADDING", (0, 0), (-1, -1), 6),
                ("RIGHTPADDING", (0, 0), (-1, -1), 6),
                ("TOPPADDING", (0, 0), (-1, -1), 5),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
            ]
        )
    )
    return table


def _build_key_value_table(rows: list[list[str]], palette: dict[str, colors.Color], styles: dict[str, ParagraphStyle], *, col_widths: tuple[float, float]) -> Table:
    data = [[Paragraph(_pdf_inline(label), ParagraphStyle("kv_label", parent=styles["body_small"], fontName="Helvetica-Bold", textColor=palette["primary"])), Paragraph(_pdf_inline(value), styles["body_small"])] for label, value in rows]
    table = Table(data, colWidths=list(col_widths))
    table.setStyle(
        TableStyle(
            [
                ("GRID", (0, 0), (-1, -1), 0.4, palette["border"]),
                ("BACKGROUND", (0, 0), (0, -1), palette["header_fill"]),
                ("VALIGN", (0, 0), (-1, -1), "TOP"),
                ("LEFTPADDING", (0, 0), (-1, -1), 6),
                ("RIGHTPADDING", (0, 0), (-1, -1), 6),
                ("TOPPADDING", (0, 0), (-1, -1), 5),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
            ]
        )
    )
    return table


def _build_stats_table(rows: list[list[str]], palette: dict[str, colors.Color], styles: dict[str, ParagraphStyle]) -> Table:
    value_style = ParagraphStyle("stats_value", parent=styles["section_heading"], fontSize=18, leading=22, alignment=TA_CENTER, textColor=palette["primary"])
    label_style = ParagraphStyle("stats_label", parent=styles["body_small"], alignment=TA_CENTER, textColor=palette["muted"])
    cells = [Paragraph(f"{_pdf_inline(value)}<br/><font size='8'>{_pdf_inline(label)}</font>", value_style) for label, value in rows]
    grid: list[list[Any]] = []
    for offset in range(0, len(cells), 3):
        row = cells[offset : offset + 3]
        if len(row) < 3:
            row.extend([Paragraph("", label_style)] * (3 - len(row)))
        grid.append(row)
    table = Table(grid, colWidths=[55 * mm, 55 * mm, 55 * mm])
    table.setStyle(
        TableStyle(
            [
                ("BOX", (0, 0), (-1, -1), 0.4, palette["border"]),
                ("ROWBACKGROUNDS", (0, 0), (-1, -1), [colors.white, palette["zebra"]]),
                ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
                ("ALIGN", (0, 0), (-1, -1), "CENTER"),
                ("INNERGRID", (0, 0), (-1, -1), 0.3, palette["border"]),
                ("TOPPADDING", (0, 0), (-1, -1), 6),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
            ]
        )
    )
    return table


def _draw_pdf_footer(
    pdf_canvas: canvas.Canvas,
    doc: SimpleDocTemplate,
    report: CaseReport,
    branding: dict[str, Any],
    generated_at: datetime,
    palette: dict[str, colors.Color],
) -> None:
    pdf_canvas.saveState()
    pdf_canvas.setStrokeColor(palette["border"])
    pdf_canvas.setLineWidth(0.4)
    pdf_canvas.line(doc.leftMargin, 11 * mm, A4[0] - doc.rightMargin, 11 * mm)
    pdf_canvas.setFont("Helvetica", 8)
    pdf_canvas.setFillColor(palette["muted"])
    pdf_canvas.drawString(doc.leftMargin, 7 * mm, f"{branding['brand_name']} · {report.id}")
    pdf_canvas.drawRightString(A4[0] - doc.rightMargin, 7 * mm, f"Generated {_iso(generated_at) or ''} · Page {pdf_canvas.getPageNumber()}")
    pdf_canvas.restoreState()


def _load_logo_image(branding: dict[str, Any]) -> Image | None:
    if not branding.get("include_logo") or not branding.get("logo_path"):
        return None
    path = Path(str(branding["logo_path"])).expanduser()
    allowed_roots = [settings.backend_data_dir.resolve()]
    assets_root = Path("/app/static/assets")
    if assets_root.exists():
        allowed_roots.append(assets_root.resolve())
    try:
        resolved = path.resolve(strict=True)
    except FileNotFoundError:
        return None
    if not any(root == resolved or root in resolved.parents for root in allowed_roots):
        return None
    try:
        image = Image(str(resolved))
        image._restrictSize(42 * mm, 18 * mm)
        image.hAlign = "CENTER"
        return image
    except Exception:  # noqa: BLE001
        return None


def _normalize_hex_color(value: str) -> str:
    candidate = value.strip()
    if re.fullmatch(r"#[0-9a-fA-F]{6}", candidate):
        return candidate.lower()
    return settings.report_brand_primary_color


def _pdf_palette(primary_hex: str) -> dict[str, colors.Color]:
    primary = colors.HexColor(primary_hex)
    return {
        "primary": primary,
        "primary_soft": colors.HexColor("#e2e8f0"),
        "muted": colors.HexColor("#475569"),
        "border": colors.HexColor("#cbd5e1"),
        "header_fill": colors.HexColor("#f8fafc"),
        "zebra": colors.HexColor("#f9fbfd"),
        "warning_fill": colors.HexColor("#fef3c7"),
        "warning_border": colors.HexColor("#f59e0b"),
        "warning_text": colors.HexColor("#92400e"),
    }


def _pdf_inline(value: str) -> str:
    text = escape(_sanitize_text(value))
    text = _MARKDOWN_LINK.sub(lambda match: escape(_sanitize_text(match.group(1))), text)
    text = _INLINE_CODE.sub(lambda match: f"<font name='Courier'>{escape(_sanitize_text(match.group(1)))}</font>", text)
    text = _MARKDOWN_EMPHASIS.sub(lambda match: f"<b>{escape(_sanitize_text(match.group(2)))}</b>", text)
    return text.replace("\n", "<br/>")


def _should_render_as_code(value: str) -> bool:
    return "\\" in value or value.count(":\\") >= 1 or len(value) > 180 or value.startswith("Filters:")


def _unescape_md_table_cell(value: str) -> str:
    return value.replace("\\|", "|")


def _get_case_or_404(db: Session, case_id: str) -> Case:
    case = db.get(Case, case_id)
    if not case:
        raise HTTPException(status_code=404, detail="Case not found")
    return case


def _get_evidence_or_404(db: Session, evidence_id: str) -> Evidence:
    evidence = db.get(Evidence, evidence_id)
    if not evidence:
        raise HTTPException(status_code=404, detail="Evidence not found")
    return evidence


def _get_report_or_404(db: Session, case_id: str, report_id: str) -> CaseReport:
    report = db.get(CaseReport, report_id)
    if not report or report.case_id != case_id:
        raise HTTPException(status_code=404, detail="Report not found")
    return report


def _serialize_report(report: CaseReport) -> dict[str, Any]:
    return {
        "id": report.id,
        "case_id": report.case_id,
        "evidence_id": report.evidence_id,
        "title": report.title,
        "status": report.status.value,
        "template": report.template,
        "report_type": report.report_type,
        "format": report.format,
        "mode": report.mode,
        "created_at": _iso(report.created_at),
        "updated_at": _iso(report.updated_at),
        "generated_at": _iso(report.generated_at),
        "author": report.author,
        "source_ingest_run_id": report.source_ingest_run_id,
        "size_bytes": report.size_bytes,
        "time_range": dict(report.time_range or {}),
        "filters": dict(report.filters or {}),
        "sections_enabled": dict(report.sections_enabled or {}),
        "analyst_notes": dict(report.analyst_notes or {}),
        "selected_finding_ids": list(report.selected_finding_ids or []),
        "selected_key_event_ids": list(report.selected_key_event_ids or []),
        "selected_process_chain_ids": list(report.selected_process_chain_ids or []),
        "include_raw_appendix": bool(report.include_raw_appendix),
        "include_debug_metadata": bool(report.include_debug_metadata),
        "metadata_json": dict(report.metadata_json or {}),
    }


def _load_evidence_manifest(evidence: Evidence) -> dict[str, Any]:
    manifest_path = evidence_manifest_path(evidence.case_id, evidence.id)
    if manifest_path.exists():
        try:
            return json.loads(manifest_path.read_text(encoding="utf-8"))
        except Exception:
            return default_manifest(evidence)
    return default_manifest(evidence)


def _fetch_evidence_sample_events(evidence: Evidence, *, size: int = 200) -> list[dict[str, Any]]:
    index = get_events_index(evidence.case_id)
    result = search_documents(
        index,
        {
            "size": size,
            "sort": [{"@timestamp": {"order": "desc", "missing": "_last"}}],
            "query": {"term": {"evidence_id": evidence.id}},
        },
    )
    hits = list((result.get("hits") or {}).get("hits") or [])
    return [dict(hit.get("_source") or {}) for hit in hits if isinstance(hit, dict)]


def _build_evidence_search_summary(evidence: Evidence) -> dict[str, Any]:
    index = get_events_index(evidence.case_id)
    query = {"term": {"evidence_id": evidence.id}}
    total = int((count_documents(index, query).get("count") or 0))
    client = get_opensearch_client()
    source_file_field = resolve_aggregatable_field(client, index, "source_file") or "source_file.keyword"
    host_field = resolve_aggregatable_field(client, index, "host.name") or "host.name"
    user_field = resolve_aggregatable_field(client, index, "user.name") or "user.name"
    aggregation_result = search_documents(
        index,
        {
            "size": 0,
            "query": query,
            "aggs": {
                "artifact_type": {"terms": {"field": "artifact.type", "size": 25}},
                "parser": {"terms": {"field": "artifact.parser", "size": 25}},
                "source_file": {"terms": {"field": source_file_field, "size": 15}},
                "host": {"terms": {"field": host_field, "size": 15}},
                "user": {"terms": {"field": user_field, "size": 15}},
            },
        },
    )
    aggregations = dict(aggregation_result.get("aggregations") or {})

    def _bucket_map(name: str) -> dict[str, int]:
        buckets = list((aggregations.get(name) or {}).get("buckets") or [])
        output: dict[str, int] = {}
        for bucket in buckets:
            key = str(bucket.get("key") or "").strip()
            if not key:
                continue
            output[key] = int(bucket.get("doc_count") or 0)
        return output

    return {
        "evidence_id": evidence.id,
        "case_id": evidence.case_id,
        "ingest_status": evidence.ingest_status.value if hasattr(evidence.ingest_status, "value") else str(evidence.ingest_status or ""),
        "latest_ingest_run_id": str((evidence.metadata_json or {}).get("latest_ingest_run_id") or ""),
        "total_indexed_docs": total,
        "artifact_type_counts": _bucket_map("artifact_type"),
        "parser_counts": _bucket_map("parser"),
        "source_file_counts": _bucket_map("source_file"),
        "host_counts": _bucket_map("host"),
        "user_counts": _bucket_map("user"),
    }


def _count_evidence_indexed_docs(evidence: Evidence) -> int:
    index = get_events_index(evidence.case_id)
    query = {"term": {"evidence_id": evidence.id}}
    return int((count_documents(index, query).get("count") or 0))


def _report_output_dir(report_id: str) -> Path:
    return settings.backend_data_dir / "reports" / report_id


def _build_evidence_summary_payload(
    db: Session,
    evidence: Evidence,
    *,
    include_detections: bool,
    include_problematic_artifacts: bool,
    include_search_summary: bool,
    include_parser_contract: bool,
) -> dict[str, Any]:
    manifest = _load_evidence_manifest(evidence)
    artifacts = [dict(item) for item in (manifest.get("artifacts") or []) if isinstance(item, dict)]
    sampled_events = _fetch_evidence_sample_events(evidence)
    search_summary = _build_evidence_search_summary(evidence) if include_search_summary else {}
    parser_registry = build_parser_registry_report(
        artifact_types=sorted({str(item.get("artifact_type") or "").strip().lower() for item in artifacts if item.get("artifact_type")}) or None
    )
    searchable_contract = (
        build_searchable_contract_report(artifacts=artifacts, sampled_events=sampled_events) if include_parser_contract else {}
    )
    indexed_field_coverage = (
        build_indexed_field_coverage_by_artifact_type(sampled_events) if include_parser_contract else {}
    )
    non_searchable_artifacts = build_non_searchable_artifacts_report(artifacts)
    total_detections = (
        int(db.query(func.count(DetectionResult.id)).filter(DetectionResult.evidence_id == evidence.id).scalar() or 0)
        if include_detections
        else 0
    )
    detection_rows = (
        db.query(DetectionResult)
        .filter(DetectionResult.evidence_id == evidence.id)
        .order_by(DetectionResult.created_at.desc())
        .limit(100)
        .all()
        if include_detections
        else []
    )
    detections_summary = {
        "total_detections": total_detections,
        "by_severity": dict(
            sorted(Counter(str(item.severity or "unknown").strip().lower() or "unknown" for item in detection_rows).items())
        ),
        "by_rule": dict(sorted(Counter(str(item.rule_name or "unknown").strip() or "unknown" for item in detection_rows).most_common(10))),
        "latest_rule_run_ids": [
            run_id
            for run_id in dict.fromkeys(str((item.raw or {}).get("rule_run_id") or "").strip() for item in detection_rows)
            if run_id
        ][:10],
        "top_detections": [
            {
                "id": item.id,
                "rule_name": item.rule_name,
                "rule_title": item.rule_title,
                "severity": item.severity,
                "status": item.status,
                "matched_at": item.matched_at,
                "message": item.message,
                "source_file": item.target_path,
                "rule_run_id": str((item.raw or {}).get("rule_run_id") or "") or None,
            }
            for item in detection_rows[:10]
        ],
    }
    problematic_artifacts = (
        build_problematic_artifacts_report(evidence, manifest, artifact_rows=list(evidence.artifacts or []))
        if include_problematic_artifacts
        else {"summary": {"problematic_count": 0}, "items": []}
    )
    latest_run = str((evidence.metadata_json or {}).get("latest_ingest_run_id") or "")
    ingest_summary = {
        "latest_ingest_run_id": latest_run,
        "ingest_mode": str((evidence.metadata_json or {}).get("ingest_mode") or ""),
        "final_status": evidence.ingest_status.value if hasattr(evidence.ingest_status, "value") else str(evidence.ingest_status or ""),
        "artifacts_total": len(artifacts),
        "artifacts_done": sum(1 for artifact in artifacts if str(artifact.get("status") or "").lower() == "completed"),
        "artifacts_failed": sum(1 for artifact in artifacts if str(artifact.get("status") or "").lower().startswith("failed")),
        "events_indexed": int((evidence.metadata_json or {}).get("events_indexed") or search_summary.get("total_indexed_docs") or 0),
        "records_read": int((evidence.metadata_json or {}).get("records_read") or 0),
        "skipped_features": list((evidence.metadata_json or {}).get("skipped_features") or []),
    }
    warnings: list[str] = []
    if int((problematic_artifacts.get("summary") or {}).get("problematic_count") or 0) > 0:
        warnings.append("Problematic or deferred artifacts remain for this evidence.")
    contract_summary = dict((searchable_contract.get("summary") or {}))
    if int(contract_summary.get("partial") or 0) > 0 or int(contract_summary.get("fail") or 0) > 0:
        warnings.append("Some artifact types only partially satisfy the searchable document contract.")
    return {
        "header": {
            "case_id": evidence.case_id,
            "evidence_id": evidence.id,
            "evidence_name": evidence.original_filename,
            "generated_at": datetime.now(UTC).isoformat(),
            "report_type": "summary",
            "mode": "on_demand",
        },
        "ingest_summary": ingest_summary,
        "search_summary": search_summary,
        "parser_contract_summary": {
            "contract_version": SEARCHABLE_CONTRACT_VERSION,
            "parser_registry": parser_registry,
            "summary": contract_summary,
            "field_coverage": indexed_field_coverage,
            "non_searchable_artifacts": non_searchable_artifacts,
        },
        "detections_summary": detections_summary,
        "problematic_artifacts": problematic_artifacts,
        "links": {
            "search_this_evidence": f"/cases/{evidence.case_id}/search?evidence_id={evidence.id}&tab=results",
            "timeline": f"/cases/{evidence.case_id}/timeline?evidence_id={evidence.id}",
            "detections": f"/cases/{evidence.case_id}/detections?evidence_id={evidence.id}",
            "debug_export": f"/evidences/{evidence.id}#debug-export",
        },
        "warnings": warnings,
    }


def _render_evidence_summary_markdown(summary: dict[str, Any]) -> str:
    header = dict(summary.get("header") or {})
    ingest = dict(summary.get("ingest_summary") or {})
    search = dict(summary.get("search_summary") or {})
    contract = dict((summary.get("parser_contract_summary") or {}).get("summary") or {})
    detections = dict(summary.get("detections_summary") or {})
    problematic = dict(summary.get("problematic_artifacts") or {})
    links = dict(summary.get("links") or {})
    lines = [
        f"# Evidence Summary Report - {header.get('evidence_name') or header.get('evidence_id')}",
        "",
        f"- Case ID: `{header.get('case_id')}`",
        f"- Evidence ID: `{header.get('evidence_id')}`",
        f"- Generated at: `{header.get('generated_at')}`",
        f"- Mode: `{header.get('mode')}`",
        "",
        "## Ingest summary",
        f"- Latest ingest run: `{ingest.get('latest_ingest_run_id') or '-'}`",
        f"- Ingest mode: `{ingest.get('ingest_mode') or '-'}`",
        f"- Final status: `{ingest.get('final_status') or '-'}`",
        f"- Artifacts total: `{ingest.get('artifacts_total') or 0}`",
        f"- Artifacts done: `{ingest.get('artifacts_done') or 0}`",
        f"- Artifacts failed: `{ingest.get('artifacts_failed') or 0}`",
        f"- Events/docs indexed: `{search.get('total_indexed_docs') or ingest.get('events_indexed') or 0}`",
        f"- Skipped features: `{', '.join(ingest.get('skipped_features') or []) or '-'}`",
        "",
        "## Search summary",
        f"- Total indexed docs: `{search.get('total_indexed_docs') or 0}`",
        f"- Artifact types: `{', '.join(f'{key}:{value}' for key, value in (search.get('artifact_type_counts') or {}).items()) or '-'}`",
        f"- Parsers: `{', '.join(f'{key}:{value}' for key, value in (search.get('parser_counts') or {}).items()) or '-'}`",
        "",
        "## Searchable contract summary",
        f"- Contract version: `{(summary.get('parser_contract_summary') or {}).get('contract_version') or SEARCHABLE_CONTRACT_VERSION}`",
        f"- Pass: `{contract.get('pass') or 0}`",
        f"- Partial: `{contract.get('partial') or 0}`",
        f"- Fail: `{contract.get('fail') or 0}`",
        "",
        "## Detections summary",
        f"- Total detections: `{detections.get('total_detections') or 0}`",
        f"- By severity: `{', '.join(f'{key}:{value}' for key, value in (detections.get('by_severity') or {}).items()) or '-'}`",
        f"- Latest rules runs: `{', '.join(detections.get('latest_rule_run_ids') or []) or '-'}`",
        "",
        "## Problematic/deferred artifacts",
        f"- Count: `{((problematic.get('summary') or {}).get('problematic_count') or 0)}`",
        "",
        "## Links",
        f"- Search this evidence: `{links.get('search_this_evidence') or '-'}`",
        f"- Timeline: `{links.get('timeline') or '-'}`",
        f"- Detections: `{links.get('detections') or '-'}`",
        f"- Debug export: `{links.get('debug_export') or '-'}`",
    ]
    warnings = list(summary.get("warnings") or [])
    if warnings:
        lines.extend(["", "## Warnings"])
        lines.extend([f"- {warning}" for warning in warnings])
    return "\n".join(lines) + "\n"


def _render_evidence_summary_html(summary: dict[str, Any]) -> str:
    markdown = _render_evidence_summary_markdown(summary)
    escaped = escape(markdown)
    return f"""<!doctype html>
<html lang="en">
  <head>
    <meta charset="utf-8" />
    <title>{escape(str((summary.get("header") or {}).get("evidence_name") or "Evidence Summary Report"))}</title>
    <style>
      body {{ font-family: ui-monospace, SFMono-Regular, Menlo, monospace; margin: 2rem; background: #0b1020; color: #e5e7eb; }}
      pre {{ white-space: pre-wrap; line-height: 1.5; }}
    </style>
  </head>
  <body>
    <pre>{escaped}</pre>
  </body>
</html>
"""


def _filtered_findings(db: Session, case_id: str, filters: dict[str, Any]) -> list[Finding]:
    query = db.query(Finding).filter(Finding.case_id == case_id)
    evidence_id = str(filters.get("evidence_id") or "").strip()
    host = str(filters.get("host") or "").strip().lower()
    expanded_hosts = _expanded_report_hosts(db, case_id, host) if host else set()
    statuses = {str(item).strip().lower() for item in (filters.get("include_statuses") or []) if str(item).strip()}
    min_severity = str(filters.get("min_severity") or "medium").strip().lower()
    min_severity_rank = SEVERITY_ORDER.get(min_severity, 2)
    risk_min = _optional_int(filters.get("risk_min"))
    risk_max = _optional_int(filters.get("risk_max"))
    time_from = str(filters.get("time_from") or "").strip()
    time_to = str(filters.get("time_to") or "").strip()
    findings = query.all()
    output = []
    for finding in findings:
        if evidence_id and str(finding.evidence_id or "") != evidence_id:
            continue
        if statuses and str(finding.status.value if hasattr(finding.status, "value") else finding.status).lower() not in statuses:
            continue
        severity_name = str(finding.severity.value if hasattr(finding.severity, "value") else finding.severity).lower()
        if SEVERITY_ORDER.get(severity_name, 0) < min_severity_rank:
            continue
        if risk_min is not None and int(finding.risk_score or 0) < risk_min:
            continue
        if risk_max is not None and int(finding.risk_score or 0) > risk_max:
            continue
        finding_time = _iso(finding.time_start or finding.created_at) or ""
        if time_from and finding_time and finding_time < time_from:
            continue
        if time_to and finding_time and finding_time > time_to:
            continue
        if expanded_hosts:
            related_hosts = [str(item).strip() for item in (finding.related_hosts or []) if str(item).strip()]
            if related_hosts and not any(_host_matches_report_filter(item, expanded_hosts) for item in related_hosts):
                continue
        output.append(finding)
    return sorted(
        output,
        key=lambda item: (
            -(SEVERITY_ORDER.get(str(item.severity.value if hasattr(item.severity, "value") else item.severity).lower(), 0)),
            0 if str(item.status.value if hasattr(item.status, "value") else item.status).lower() in {"confirmed", "reviewed"} else 1,
            -(int(item.risk_score or 0)),
            _safe_dt(item.time_start or item.created_at),
        ),
    )


def _filtered_bookmarks(db: Session, case_id: str, filters: dict[str, Any]) -> list[TimelineBookmark]:
    evidence_id = str(filters.get("evidence_id") or "").strip()
    host = str(filters.get("host") or "").strip().lower()
    time_from = str(filters.get("time_from") or "").strip()
    time_to = str(filters.get("time_to") or "").strip()
    bookmarks = (
        db.query(TimelineBookmark)
        .filter(TimelineBookmark.case_id == case_id, TimelineBookmark.include_in_report.is_(True))
        .order_by(TimelineBookmark.order_index.asc(), TimelineBookmark.timestamp.asc(), TimelineBookmark.created_at.asc())
        .all()
    )
    if not evidence_id and not host and not time_from and not time_to:
        return bookmarks
    filtered = []
    for bookmark in bookmarks:
        bookmark_time = _iso(bookmark.timestamp) or ""
        if time_from and bookmark_time and bookmark_time < time_from:
            continue
        if time_to and bookmark_time and bookmark_time > time_to:
            continue
        event = fetch_event_by_id(case_id, bookmark.event_id, event_index=None, opensearch_id=bookmark.event_id) or fetch_event_by_id(case_id, bookmark.event_id, event_index=None, opensearch_id=None) or {}
        if evidence_id and str(event.get("evidence_id") or "") != evidence_id:
            continue
        if host and not event_matches_host_filter(db, case_id, event, host):
            continue
        filtered.append(bookmark)
    return filtered


def _filtered_detections(db: Session, case_id: str, filters: dict[str, Any]) -> list[DetectionResult]:
    if not filters.get("include_detections", True):
        return []
    evidence_id = str(filters.get("evidence_id") or "").strip()
    host = str(filters.get("host") or "").strip().lower()
    expanded_hosts = _expanded_report_hosts(db, case_id, host) if host else set()
    statuses = {str(item).strip().lower() for item in (filters.get("detection_statuses") or []) if str(item).strip()}
    severities = {str(item).strip().lower() for item in (filters.get("detection_severities") or []) if str(item).strip()}
    risk_min = _optional_int(filters.get("risk_min"))
    risk_max = _optional_int(filters.get("risk_max"))
    rule_name = str(filters.get("rule_name") or "").strip().lower()
    time_from = str(filters.get("time_from") or "").strip()
    time_to = str(filters.get("time_to") or "").strip()
    query = db.query(DetectionResult).filter(DetectionResult.case_id == case_id, DetectionResult.deleted_at.is_(None), DetectionResult.archived_at.is_(None))
    if evidence_id:
        query = query.filter(DetectionResult.evidence_id == evidence_id)
    rows = query.order_by(DetectionResult.created_at.desc()).all()
    output: list[DetectionResult] = []
    for row in rows:
        status = str(row.status or "").lower()
        if statuses and status not in statuses:
            continue
        if status in {"dismissed", "false_positive", "deleted"} and not statuses:
            continue
        severity = str(row.severity or row.rule_level or "").lower()
        if severities and severity not in severities:
            continue
        if risk_min is not None and int(row.risk_score or 0) < risk_min:
            continue
        if risk_max is not None and int(row.risk_score or 0) > risk_max:
            continue
        if rule_name and rule_name not in str(row.rule_name or row.rule_title or "").lower():
            continue
        if expanded_hosts:
            row_host = str(row.host_name or "").strip()
            if row_host and not _host_matches_report_filter(row_host, expanded_hosts):
                continue
        matched_at = str(row.matched_at or _iso(row.created_at) or "")
        if time_from and matched_at and matched_at < time_from:
            continue
        if time_to and matched_at and matched_at > time_to:
            continue
        output.append(row)
    return output[:500]


def _filtered_markings(db: Session, case_id: str, filters: dict[str, Any]) -> list[EventMarking]:
    if not filters.get("include_marked_events", True):
        return []
    evidence_id = str(filters.get("evidence_id") or "").strip()
    host = str(filters.get("host") or "").strip().lower()
    expanded_hosts = _expanded_report_hosts(db, case_id, host) if host else set()
    statuses = {str(item).strip().lower() for item in (filters.get("marking_statuses") or []) if str(item).strip()}
    time_from = str(filters.get("time_from") or "").strip()
    time_to = str(filters.get("time_to") or "").strip()
    query = db.query(EventMarking).filter(EventMarking.case_id == case_id)
    if evidence_id:
        query = query.filter(EventMarking.evidence_id == evidence_id)
    rows = query.order_by(EventMarking.timestamp.asc().nullslast(), EventMarking.updated_at.desc()).all()
    output: list[EventMarking] = []
    for row in rows:
        status = str(row.status or "").lower()
        if statuses and status not in statuses:
            continue
        if status == "false_positive" and not statuses:
            continue
        if expanded_hosts:
            row_host = str(row.host or "").strip()
            if row_host and not _host_matches_report_filter(row_host, expanded_hosts):
                continue
        row_time = _iso(row.timestamp) or ""
        if time_from and row_time and row_time < time_from:
            continue
        if time_to and row_time and row_time > time_to:
            continue
        output.append(row)
    return output[:500]


def _auto_select_findings(findings: list[Finding]) -> list[Finding]:
    selected = [
        finding
        for finding in findings
        if str(finding.status.value if hasattr(finding.status, "value") else finding.status).lower() in {"confirmed", "reviewed"}
        or SEVERITY_ORDER.get(str(finding.severity.value if hasattr(finding.severity, "value") else finding.severity).lower(), 0) >= SEVERITY_ORDER["high"]
    ]
    if selected:
        return selected[:12]
    return findings[:8]


def _auto_select_finding_ids(findings: list[Finding]) -> list[str]:
    return [finding.id for finding in _auto_select_findings(findings)]


def _auto_select_process_chain_ids(findings: list[Finding]) -> list[str]:
    selected: list[str] = []
    for finding in findings:
        if (finding.finding_type in {"suspicious_process_chain", "office_powershell", "powershell_network", "download_execute_detect", "persistence_execution"}) and list(finding.related_process_node_ids or []):
            selected.append(finding.id)
    return _dedupe(selected[:8])


def _build_timeline_entries(bookmarks: list[TimelineBookmark], findings: list[Finding]) -> tuple[list[dict[str, Any]], bool]:
    if bookmarks:
        entries = [
            {
                "timestamp": bookmark.timestamp,
                "category": bookmark.category.value,
                "importance": bookmark.importance.value,
                "title": bookmark.title,
                "summary": bookmark.summary or "",
                "note": bookmark.note or "",
                "related_finding": bookmark.finding_id,
                "event_id": bookmark.event_id,
            }
            for bookmark in bookmarks
        ]
        return entries, False
    entries = []
    for finding in findings[:10]:
        timeline_items = list(finding.timeline or [])
        if timeline_items:
            for item in timeline_items[:3]:
                entries.append(
                    {
                        "timestamp": item.get("timestamp") or finding.time_start or finding.created_at,
                        "category": finding.finding_type or "finding",
                        "importance": str(finding.severity.value if hasattr(finding.severity, "value") else finding.severity),
                        "title": finding.title,
                        "summary": item.get("summary") or finding.description or "",
                        "note": "",
                        "related_finding": finding.id,
                        "event_id": item.get("event_id"),
                    }
                )
        else:
            entries.append(
                {
                    "timestamp": finding.time_start or finding.created_at,
                    "category": finding.finding_type or "finding",
                    "importance": str(finding.severity.value if hasattr(finding.severity, "value") else finding.severity),
                    "title": finding.title,
                    "summary": finding.description or "",
                    "note": "",
                    "related_finding": finding.id,
                    "event_id": (finding.related_event_ids or [None])[0],
                }
            )
    entries.sort(key=lambda item: _safe_dt(item.get("timestamp")))
    return entries, True


def _build_marked_event_entries(markings: list[EventMarking]) -> list[dict[str, Any]]:
    entries: list[dict[str, Any]] = []
    for marking in markings:
        labels = ", ".join(str(item) for item in (marking.labels or []) if str(item).strip())
        entries.append(
            {
                "timestamp": marking.timestamp,
                "category": "marked_event",
                "importance": marking.status,
                "title": f"Marked event: {marking.status}",
                "summary": marking.note or labels or "Analyst-marked event",
                "note": marking.note or "",
                "related_finding": marking.finding_id,
                "event_id": marking.event_id,
            }
        )
    return entries


def _build_command_history_report_context(db: Session, case: Case, case_id: str, filters: dict[str, Any]) -> dict[str, Any]:
    if not filters.get("include_command_history", True):
        return {
            "commands": [],
            "stories": [],
            "warnings": [],
            "counts": {
                "command_history_matched": 0,
                "suspicious_commands_matched": 0,
                "marked_commands_matched": 0,
                "execution_stories_available": 0,
                "commands_by_shell": {},
                "commands_by_family": {},
                "commands_by_launcher": {},
                "commands_by_source_type": {},
            },
        }

    max_commands = min(max(_optional_int(filters.get("max_commands")) or 50, 1), 200)
    max_stories = min(max(_optional_int(filters.get("max_execution_stories")) or 10, 0), 50)
    params = {
        "evidence_id": filters.get("evidence_id") or None,
        "host": filters.get("host") or None,
        "time_from": filters.get("time_from") or None,
        "time_to": filters.get("time_to") or None,
        "family": filters.get("command_family") or filters.get("command_shell") or None,
        "launcher": filters.get("command_launcher") or None,
        "source_type": filters.get("command_source_type") or None,
        "q": filters.get("command_query") or None,
        "risk_min": filters.get("command_risk_min") if filters.get("command_risk_min") not in {None, ""} else filters.get("risk_min"),
        "risk_max": filters.get("command_risk_max") if filters.get("command_risk_max") not in {None, ""} else filters.get("risk_max"),
        "has_supporting_sources": filters.get("command_has_supporting_events") or False,
        "page": 1,
        "page_size": 500,
        "sort": "timestamp_asc",
    }
    command_marking_status = str(filters.get("command_marking_status") or "").strip().lower()
    only_suspicious = bool(filters.get("command_only_suspicious", True))
    if only_suspicious and not command_marking_status:
        params["only_suspicious"] = True
    result = get_command_history(case_id, params)
    all_commands = list(result.get("items") or [])
    marking_map = _command_marking_map(db, case_id, filters)
    selected: list[dict[str, Any]] = []
    marked_total = 0
    suspicious_total = 0
    for command in all_commands:
        annotated = dict(command)
        markings = _markings_for_command(command, marking_map)
        if markings:
            annotated["markings"] = markings
            marked_total += 1
        statuses = {str(item.get("status") or "").strip().lower() for item in markings}
        if "false_positive" in statuses and not command_marking_status:
            continue
        if command_marking_status and command_marking_status not in statuses:
            continue
        is_suspicious = int(command.get("risk_score") or 0) >= 50
        if is_suspicious:
            suspicious_total += 1
        is_marked_for_report = bool(statuses & {"suspicious", "important"})
        if only_suspicious and not is_suspicious and not is_marked_for_report:
            continue
        selected.append(annotated)
    selected.sort(key=lambda item: (_safe_dt(item.get("timestamp")), -int(item.get("risk_score") or 0), str(item.get("command") or "")))
    included = selected[:max_commands]
    stories, story_warnings = _build_command_execution_stories(db, case, case_id, included, filters, max_stories=max_stories)
    facets = dict(result.get("facets") or {})
    return {
        "commands": included,
        "stories": stories,
        "warnings": story_warnings,
        "counts": {
            "command_history_matched": int(result.get("total") or len(all_commands)),
            "suspicious_commands_matched": suspicious_total,
            "marked_commands_matched": marked_total,
            "execution_stories_available": len(stories),
            "commands_by_shell": dict(facets.get("shell") or {}),
            "commands_by_family": dict(facets.get("family") or facets.get("shell") or {}),
            "commands_by_launcher": dict(facets.get("launcher") or {}),
            "commands_by_source_type": dict(facets.get("source_type") or {}),
        },
    }


def _build_defender_report_context(db: Session, case_id: str, filters: dict[str, Any]) -> dict[str, Any]:
    if not filters.get("include_defender", True):
        return {
            "events": [],
            "warnings": [],
            "counts": {
                "defender_events_matched": 0,
                "defender_high_severity": 0,
                "defender_failed_actions": 0,
            },
        }
    max_events = min(max(_optional_int(filters.get("max_defender_events")) or 25, 1), 100)
    params = {
        "scope": "events",
        "evidence_id": filters.get("evidence_id") or None,
        "host": filters.get("host") or None,
        "time_from": filters.get("time_from") or None,
        "time_to": filters.get("time_to") or None,
        "artifact_type": ["defender"],
        "risk_min": filters.get("risk_min"),
        "risk_max": filters.get("risk_max"),
        "page": 1,
        "page_size": max_events,
        "sort": "risk_desc",
        "include_facets": False,
    }
    total, rows, warnings, _facets = search_events_v2(case_id, params, db=db)
    high_severity = 0
    failed_actions = 0
    for row in rows:
        raw = row.get("raw") if isinstance(row.get("raw"), dict) else {}
        event = raw.get("event") if isinstance(raw.get("event"), dict) else {}
        defender = raw.get("defender") if isinstance(raw.get("defender"), dict) else {}
        severity = str(defender.get("severity") or event.get("severity") or row.get("severity") or "").lower()
        action_blob = " ".join(str(defender.get(key) or "") for key in ("action", "action_result", "status", "error_code")).lower()
        if severity in {"high", "critical", "severe"}:
            high_severity += 1
        if "fail" in action_blob:
            failed_actions += 1
    return {
        "events": rows,
        "warnings": warnings,
        "counts": {
            "defender_events_matched": int(total),
            "defender_high_severity": high_severity,
            "defender_failed_actions": failed_actions,
        },
    }


def _build_srum_report_context(db: Session, case_id: str, filters: dict[str, Any]) -> dict[str, Any]:
    if not filters.get("include_srum", True):
        return {
            "events": [],
            "warnings": [],
            "counts": {
                "srum_events_matched": 0,
                "srum_network_usage": 0,
                "srum_total_bytes": 0,
            },
        }
    max_events = min(max(_optional_int(filters.get("max_srum_events")) or 25, 1), 100)
    params = {
        "scope": "events",
        "evidence_id": filters.get("evidence_id") or None,
        "host": filters.get("host") or None,
        "time_from": filters.get("time_from") or None,
        "time_to": filters.get("time_to") or None,
        "artifact_type": ["srum"],
        "risk_min": filters.get("risk_min"),
        "risk_max": filters.get("risk_max"),
        "page": 1,
        "page_size": max_events,
        "sort": "risk_desc",
        "include_facets": False,
    }
    total, rows, warnings, _facets = search_events_v2(case_id, params, db=db)
    network_usage = 0
    total_bytes = 0
    for row in rows:
        raw = row.get("raw") if isinstance(row.get("raw"), dict) else {}
        event = raw.get("event") if isinstance(raw.get("event"), dict) else {}
        network = raw.get("network") if isinstance(raw.get("network"), dict) else {}
        srum = raw.get("srum") if isinstance(raw.get("srum"), dict) else {}
        event_type = str(event.get("type") or "").lower()
        if event_type in {"network_usage", "network_connectivity_observed"} or "network" in str(srum.get("artifact_type") or "").lower():
            network_usage += 1
        total_bytes += int(network.get("bytes_total") or srum.get("bytes_total") or 0)
    return {
        "events": rows,
        "warnings": warnings,
        "counts": {
            "srum_events_matched": int(total),
            "srum_network_usage": network_usage,
            "srum_total_bytes": total_bytes,
        },
    }


def _build_incident_timeline_report_context(db: Session, case_id: str, filters: dict[str, Any]) -> dict[str, Any]:
    if not filters.get("include_incident_timeline", True):
        return {"items": [], "warnings": [], "counts": {"incident_timeline_items": 0}}
    try:
        draft = build_incident_timeline_draft(
            db,
            case_id,
            {
                "max_items": min(max(_optional_int(filters.get("max_incident_timeline_items")) or 60, 1), 120),
                "host": [filters["host"]] if filters.get("host") else None,
            },
        )
    except Exception as exc:  # noqa: BLE001
        return {"items": [], "warnings": [f"Incident timeline could not be generated: {exc}"], "counts": {"incident_timeline_items": 0}}
    items = [dict(item) for item in draft.get("items") or [] if isinstance(item, dict)]
    return {
        "items": items,
        "warnings": list(draft.get("warnings") or []),
        "counts": {"incident_timeline_items": len(items)},
    }


def _command_marking_map(db: Session, case_id: str, filters: dict[str, Any]) -> dict[str, list[dict[str, Any]]]:
    evidence_id = str(filters.get("evidence_id") or "").strip()
    host = str(filters.get("host") or "").strip().lower()
    expanded_hosts = _expanded_report_hosts(db, case_id, host) if host else set()
    time_from = str(filters.get("time_from") or "").strip()
    time_to = str(filters.get("time_to") or "").strip()
    rows = db.query(EventMarking).filter(EventMarking.case_id == case_id).order_by(EventMarking.updated_at.desc()).all()
    output: dict[str, list[dict[str, Any]]] = {}
    for row in rows:
        if evidence_id and str(row.evidence_id or "") != evidence_id:
            continue
        if expanded_hosts and row.host and not _host_matches_report_filter(row.host, expanded_hosts):
            continue
        row_time = _iso(row.timestamp) or ""
        if time_from and row_time and row_time < time_from:
            continue
        if time_to and row_time and row_time > time_to:
            continue
        serialized = {
            "id": row.id,
            "event_id": row.event_id,
            "search_doc_id": row.search_doc_id,
            "status": row.status,
            "labels": list(row.labels or []),
            "note": row.note or "",
        }
        for key in {str(row.event_id or ""), str(row.search_doc_id or "")}:
            if key:
                output.setdefault(key, []).append(serialized)
    return output


def _markings_for_command(command: dict[str, Any], marking_map: dict[str, list[dict[str, Any]]]) -> list[dict[str, Any]]:
    keys: set[str] = set()
    if command.get("id"):
        keys.add(str(command.get("id")))
    for event in command.get("supporting_events") or []:
        if not isinstance(event, dict):
            continue
        for key in (event.get("event_id"), event.get("stable_event_id")):
            if key:
                keys.add(str(key))
    output: list[dict[str, Any]] = []
    seen: set[str] = set()
    for key in keys:
        for item in marking_map.get(key, []):
            item_id = str(item.get("id") or "")
            if item_id and item_id not in seen:
                seen.add(item_id)
                output.append(item)
    return output


def _build_command_execution_stories(db: Session, case: Case, case_id: str, commands: list[dict[str, Any]], filters: dict[str, Any], *, max_stories: int) -> tuple[list[dict[str, Any]], list[str]]:
    if not filters.get("include_execution_stories", True) or max_stories <= 0:
        return [], []
    max_stories = min(max_stories, 3)
    candidates = [
        command
        for command in commands
        if int(command.get("risk_score") or 0) >= 50 or any(str(marking.get("status") or "").lower() in {"suspicious", "important"} for marking in command.get("markings") or [])
    ][:max_stories]
    if not candidates:
        return [], []
    stories: list[dict[str, Any]] = []
    warnings: list[str] = []
    for command in candidates:
        try:
            source_event = _primary_command_source_event(command)
            story = _build_lightweight_command_story(command, source_event)
            stories.append({"command_id": command.get("id"), "source_event_id": source_event, "story": story})
        except Exception as exc:  # noqa: BLE001
            warnings.append(f"Execution story unavailable for command {command.get('id')}: {exc}")
    return stories, warnings


def _build_lightweight_command_story(command: dict[str, Any], source_event: str | None) -> dict[str, Any]:
    process = command.get("process") if isinstance(command.get("process"), dict) else {}
    parent = command.get("parent_process") if isinstance(command.get("parent_process"), dict) else {}
    process_name = str(process.get("name") or process.get("executable") or command.get("launcher") or "process")
    process_pid = process.get("pid")
    parent_name = str(parent.get("name") or parent.get("executable") or "").strip()
    parent_pid = parent.get("pid")
    if parent_name:
        parent_sentence = f"{process_name} PID {process_pid or '-'} was launched by {parent_name} PID {parent_pid or '-'}."
    else:
        parent_sentence = "Parent process could not be linked from available command history fields."
    risk_reasons = [str(item) for item in (command.get("risk_reasons") or []) if str(item).strip()]
    risk_sentence = "; ".join(risk_reasons[:5]) if risk_reasons else "No explicit risk reason attached."
    return {
        "target": {
            "name": process_name,
            "pid": process_pid,
            "command_line": process.get("command_line") or command.get("command"),
            "source_event_id": source_event,
        },
        "story": {
            "parent_sentence": parent_sentence,
            "children_sentence": "Open the linked Execution Story to inspect direct children and pivots.",
            "activity_sentence": "Open the linked Execution Story to inspect grouped file, registry, network and DNS activity.",
            "risk_sentence": risk_sentence,
        },
        "activity_groups": {"items": [], "omitted_counts": {}},
        "source_events": [source_event] if source_event else [],
    }


def _primary_command_source_event(command: dict[str, Any]) -> str | None:
    for event in command.get("supporting_events") or []:
        if isinstance(event, dict) and event.get("event_id"):
            return str(event.get("event_id"))
    return None


def _extract_iocs(case_id: str, findings: list[Finding], bookmarks: list[TimelineBookmark]) -> list[dict[str, Any]]:
    rows: dict[tuple[str, str], dict[str, Any]] = {}

    def remember(ioc_type: str, value: Any, *, source: str, timestamp: Any = None, notes: str | None = None) -> None:
        normalized = _sanitize_text(str(value or "").strip())
        if not normalized:
            return
        key = (ioc_type, normalized)
        entry = rows.setdefault(
            key,
            {
                "type": ioc_type,
                "value": normalized,
                "source": source,
                "first_seen": _iso(timestamp) if timestamp else None,
                "last_seen": _iso(timestamp) if timestamp else None,
                "notes": _sanitize_text(notes or ""),
            },
        )
        seen = _iso(timestamp) if timestamp else None
        if seen and (entry["first_seen"] is None or seen < entry["first_seen"]):
            entry["first_seen"] = seen
        if seen and (entry["last_seen"] is None or seen > entry["last_seen"]):
            entry["last_seen"] = seen

    for finding in findings:
        source = f"finding:{finding.title}"
        for value in finding.related_files or []:
            remember("file", value, source=source, timestamp=finding.time_start or finding.created_at)
        for value in finding.related_domains or []:
            remember("domain", value, source=source, timestamp=finding.time_start or finding.created_at)
        for value in finding.related_ips or []:
            remember("ip", value, source=source, timestamp=finding.time_start or finding.created_at)
        for value in finding.related_users or []:
            remember("user", value, source=source, timestamp=finding.time_start or finding.created_at)
        for value in finding.related_hosts or []:
            remember("host", value, source=source, timestamp=finding.time_start or finding.created_at)
        for item in finding.timeline or []:
            if item.get("event_id"):
                remember("event_id", item["event_id"], source=source, timestamp=item.get("timestamp"))

    for bookmark in bookmarks:
        source = f"bookmark:{bookmark.title}"
        remember("event_id", bookmark.event_id, source=source, timestamp=bookmark.timestamp, notes=bookmark.note)
        event = fetch_event_by_id(case_id, bookmark.event_id, event_index=None, opensearch_id=bookmark.event_id) or fetch_event_by_id(case_id, bookmark.event_id, event_index=None, opensearch_id=None) or {}
        _extract_iocs_from_event(event, remember, source, bookmark.timestamp)

    result = list(rows.values())
    result.sort(key=lambda item: (item["type"], item["value"]))
    return result


def _extract_iocs_from_event(event: dict[str, Any], remember, source: str, timestamp: Any) -> None:
    file_data = event.get("file") or {}
    if isinstance(file_data, dict):
        for key in ("path", "sha1", "sha256", "md5"):
            if file_data.get(key):
                remember("hash" if key in {"sha1", "sha256", "md5"} else "file", file_data.get(key), source=source, timestamp=timestamp)
    process_data = event.get("process") or {}
    if isinstance(process_data, dict):
        for key in ("path", "command_line", "name"):
            if process_data.get(key):
                remember("process", process_data.get(key), source=source, timestamp=timestamp)
    dns_data = event.get("dns") or {}
    if isinstance(dns_data, dict):
        if dns_data.get("domain"):
            remember("domain", dns_data.get("domain"), source=source, timestamp=timestamp)
        if dns_data.get("ip"):
            remember("ip", dns_data.get("ip"), source=source, timestamp=timestamp)
    url_data = event.get("url") or {}
    if isinstance(url_data, dict) and url_data.get("full"):
        remember("url", url_data.get("full"), source=source, timestamp=timestamp)
    download_data = event.get("download") or {}
    if isinstance(download_data, dict):
        if download_data.get("url"):
            remember("url", download_data.get("url"), source=source, timestamp=timestamp)
        if download_data.get("target_path"):
            remember("file", download_data.get("target_path"), source=source, timestamp=timestamp)
    network_data = event.get("network") or {}
    if isinstance(network_data, dict):
        for key in ("source_ip", "destination_ip"):
            if network_data.get(key):
                remember("ip", network_data.get(key), source=source, timestamp=timestamp)
        if network_data.get("domain"):
            remember("domain", network_data.get("domain"), source=source, timestamp=timestamp)
    registry = event.get("registry") or {}
    if isinstance(registry, dict) and registry.get("key_path"):
        remember("registry", registry.get("key_path"), source=source, timestamp=timestamp)


def _render_executive_summary(case: Case, context: dict[str, Any], findings: list[Finding], report: CaseReport) -> str:
    highest = findings[:3]
    note = _sanitize_text((report.analyst_notes or {}).get("executive_summary") or "")
    lines = [
        f"The case **{_escape_md(case.name)}** contains **{len(context['evidences'])}** evidences, **{context['summary']['events_indexed']}** indexed events and **{context['summary']['findings_total']}** findings.",
        f"The highest severity findings included in this report are **{sum(1 for finding in findings if _sev(finding) in {'high', 'critical'})}** high/critical findings.",
    ]
    if highest:
        lines.append("")
        lines.append("Top findings:")
        for finding in highest:
            lines.append(f"- **{_escape_md(finding.title)}** ({_sev(finding)}, risk {int(finding.risk_score or 0)})")
    if note:
        lines.extend(["", "Analyst note:", "", note])
    return "\n".join(lines).strip()


def _render_scope(case: Case, context: dict[str, Any], report: CaseReport) -> str:
    filters = report.filters or {}
    lines = [
        f"- Case ID: `{case.id}`",
        f"- Case name: {_escape_md(case.name)}",
        f"- Time range: `{_escape_md(str((report.time_range or {}).get('from') or 'beginning'))}` → `{_escape_md(str((report.time_range or {}).get('to') or 'latest'))}`",
        f"- Host filter: `{_escape_md(str(filters.get('host') or 'all hosts'))}`",
        f"- Evidence filter: `{_escape_md(str(filters.get('evidence_id') or 'all evidence'))}`",
        f"- Timezone: `{_escape_md(case.timezone or 'UTC')}`",
        f"- Data sources: `{', '.join(sorted({str(item['storage_mode']) for item in context['evidences']})) or 'unknown'}`",
    ]
    return "\n".join(lines)


def _render_evidence(context: dict[str, Any]) -> str:
    rows = [["Evidence", "Status", "Storage", "External", "Host", "Events", "Parser errors"]]
    for evidence in context["evidences"]:
        rows.append(
            [
                evidence["name"],
                evidence["status"],
                evidence["storage_mode"],
                "yes" if evidence["is_external"] else "no",
                evidence.get("detected_host") or "unknown",
                str(evidence["events_indexed"]),
                str(evidence["parser_errors"]),
            ]
        )
    return _markdown_table(rows)


def _render_hosts(context: dict[str, Any]) -> str:
    rows = [["Host", "Role", "Events", "Findings", "High risk", "First seen", "Last seen"]]
    for host in context["hosts"]:
        host_name = host.get("host") or host.get("display_name") or host.get("canonical_name") or "unknown"
        events_count = host.get("events_count", host.get("event_count", 0))
        rows.append([
            host_name,
            "primary" if host.get("is_primary") else "alias" if host.get("is_alias") else "host",
            str(events_count),
            str(host.get("findings_count", 0)),
            str(host.get("high_risk_count", 0)),
            str(host.get("first_seen") or "-"),
            str(host.get("last_seen") or "-"),
        ])
    body = _markdown_table(rows)
    candidates = context.get("host_candidates") or []
    if candidates:
        body += "\n\nPossible aliases / historical hostnames:\n"
        for item in candidates[:10]:
            body += f"\n- `{_escape_md(str(item.get('value') or 'unknown'))}` · source=`{_escape_md(str(item.get('source') or 'unknown'))}` · confidence=`{_escape_md(str(item.get('confidence') or 'low'))}`"
    return body


def _render_findings(findings: list[Finding]) -> str:
    if not findings:
        return "No findings selected for this report."
    lines: list[str] = []
    for finding in findings:
        lines.extend(
            [
                f"## {_escape_md(finding.title)}",
                "",
                f"- Severity: `{_sev(finding)}`",
                f"- Confidence: `{_escape_md(str(finding.confidence or 'unknown'))}`",
                f"- Status: `{_escape_md(str(finding.status.value if hasattr(finding.status, 'value') else finding.status))}`",
                f"- Risk score: `{int(finding.risk_score or 0)}`",
            ]
        )
        if finding.description:
            lines.extend(["", _sanitize_text(finding.description)])
        if finding.reasons:
            lines.extend(["", "Reasons:"])
            for reason in finding.reasons[:8]:
                lines.append(f"- {_sanitize_text(reason)}")
        if finding.recommended_triage:
            lines.extend(["", "Recommended triage:"])
            for item in finding.recommended_triage[:6]:
                lines.append(f"- {_sanitize_text(item)}")
        related = []
        if finding.related_files:
            related.append(f"files: {', '.join(_sanitize_text(str(item)) for item in finding.related_files[:3])}")
        if finding.related_domains:
            related.append(f"domains: {', '.join(_sanitize_text(str(item)) for item in finding.related_domains[:3])}")
        if finding.related_ips:
            related.append(f"ips: {', '.join(_sanitize_text(str(item)) for item in finding.related_ips[:3])}")
        if related:
            lines.extend(["", "- Related entities: " + " · ".join(related)])
        if finding.timeline:
            lines.extend(["", "Timeline:"])
            for item in finding.timeline[:4]:
                lines.append(
                    f"- `{_sanitize_text(str(item.get('timestamp') or 'unknown'))}` · `{_sanitize_text(str(item.get('event_type') or 'event'))}` · {_sanitize_text(str(item.get('summary') or ''))}"
                )
        lines.append("")
    return "\n".join(lines).strip()


def _render_detections(detections: list[DetectionResult]) -> str:
    if not detections:
        return "No detections matched the report filters."
    by_rule: Counter[str] = Counter()
    by_severity: Counter[str] = Counter()
    by_status: Counter[str] = Counter()
    by_host: Counter[str] = Counter()
    for detection in detections:
        by_rule[str(detection.rule_title or detection.rule_name or "unknown")] += 1
        by_severity[str(detection.severity or detection.rule_level or "unknown")] += 1
        by_status[str(detection.status or "unknown")] += 1
        if detection.host_name:
            by_host[str(detection.host_name)] += 1
    lines = [
        f"- Detections matched: `{len(detections)}`",
        f"- Severity breakdown: `{dict(by_severity)}`",
        f"- Status breakdown: `{dict(by_status)}`",
        "",
        "Top rules:",
    ]
    for rule, count in by_rule.most_common(10):
        lines.append(f"- `{count}` · {_sanitize_text(rule)}")
    if by_host:
        lines.extend(["", "Affected hosts:"])
        for host, count in by_host.most_common(10):
            lines.append(f"- `{_sanitize_text(host)}` · {count}")
    lines.extend(["", "Sample detections:"])
    for detection in detections[:15]:
        lines.append(
            f"- `{_sanitize_text(str(detection.matched_at or _iso(detection.created_at) or 'unknown'))}` · "
            f"`{_sanitize_text(str(detection.severity or detection.rule_level or 'unknown'))}` · "
            f"`{_sanitize_text(str(detection.status or 'unknown'))}` · "
            f"{_sanitize_text(str(detection.rule_title or detection.rule_name))}"
        )
    return "\n".join(lines).strip()


def _render_timeline(entries: list[dict[str, Any]]) -> str:
    if not entries:
        return "No key events selected for the report."
    rows = [["Timestamp", "Category", "Importance", "Title", "Note", "Related finding", "Event ID"]]
    for entry in entries:
        rows.append(
            [
                str(_iso(entry.get("timestamp")) or "unknown"),
                str(entry.get("category") or "other"),
                str(entry.get("importance") or "medium"),
                str(entry.get("title") or ""),
                str(entry.get("note") or entry.get("summary") or ""),
                str(entry.get("related_finding") or "-"),
                str(entry.get("event_id") or "-"),
            ]
        )
    return _markdown_table(rows)


def _render_incident_timeline_section(case_id: str, items: list[dict[str, Any]]) -> str:
    if not items:
        return "No incident timeline items were generated."
    return export_incident_timeline_markdown(case_id, {"items": items, "title": "Incident Timeline", "group_by": "phase"})


def _render_process_chains(findings: list[Finding]) -> str:
    if not findings:
        return "No process chains selected or available."
    lines = []
    for finding in findings:
        lines.extend(
            [
                f"## {_escape_md(finding.title)}",
                "",
                f"- Risk: `{int(finding.risk_score or 0)}`",
                f"- Process node ids: `{', '.join(str(item) for item in (finding.related_process_node_ids or []))}`",
            ]
        )
        if finding.reasons:
            lines.append("- Reasons: " + "; ".join(_sanitize_text(str(item)) for item in finding.reasons[:6]))
        if finding.timeline:
            for item in finding.timeline[:3]:
                lines.append(f"- `{_sanitize_text(str(item.get('timestamp') or 'unknown'))}` · {_sanitize_text(str(item.get('summary') or ''))}")
        lines.append("")
    return "\n".join(lines).strip()


def _render_command_history_section(commands: list[dict[str, Any]], stories: list[dict[str, Any]]) -> str:
    if not commands:
        return "No command history matched current filters."
    story_by_command_id = {str(item.get("command_id") or ""): dict(item.get("story") or {}) for item in stories}
    lines = [
        f"- Commands included: `{len(commands)}`",
        f"- Execution story summaries: `{len(stories)}`",
        "",
    ]
    for command in commands:
        command_id = str(command.get("id") or "")
        process = command.get("process") if isinstance(command.get("process"), dict) else {}
        parent = command.get("parent_process") if isinstance(command.get("parent_process"), dict) else {}
        markings = [item for item in (command.get("markings") or []) if isinstance(item, dict)]
        supporting = [item for item in (command.get("supporting_events") or []) if isinstance(item, dict)]
        status_label = ", ".join(str(item.get("status") or "") for item in markings if item.get("status")) or "-"
        notes = "; ".join(str(item.get("note") or "") for item in markings if item.get("note")) or "-"
        reasons = "; ".join(_sanitize_text(str(item)) for item in (command.get("risk_reasons") or [])[:6]) or "-"
        source_types = ", ".join(sorted({str(item.get("source_type") or command.get("source_type") or "unknown") for item in supporting})) or str(command.get("source_type") or "unknown")
        family = str(command.get("shell_family") or command.get("shell") or "unknown")
        launcher = str(command.get("launcher") or (process.get("name") or process.get("executable") or "unknown"))
        classification_confidence = str(command.get("classification_confidence") or command.get("confidence") or "unknown")
        search_url = str(command.get("linked_search_url") or "")
        story_url = _execution_story_url_for_command(command)
        lines.extend(
            [
                f"### {_escape_md(family)} · {_escape_md(str(command.get('timestamp') or 'unknown'))}",
                "",
                f"- Host/user: `{_escape_md(str(command.get('host') or '-'))}` · `{_escape_md(str(command.get('user') or '-'))}`",
                f"- Family: `{_escape_md(family)}`",
                f"- Launcher: `{_escape_md(launcher)}`",
                f"- Command: `{_escape_md(str(command.get('command') or '-'))}`",
                f"- Parent: `{_escape_md(str(parent.get('name') or parent.get('executable') or 'unknown'))}` PID `{_escape_md(str(parent.get('pid') or '-'))}`",
                f"- Process: `{_escape_md(str(process.get('name') or process.get('executable') or 'unknown'))}` PID `{_escape_md(str(process.get('pid') or '-'))}`",
                f"- Source: `{_escape_md(source_types)}` · classification `{_escape_md(classification_confidence)}` · supporting events `{len(supporting)}`",
                f"- Risk: `{int(command.get('risk_score') or 0)}`",
                f"- Reasons: {_escape_md(reasons)}",
                f"- Analyst marking: `{_escape_md(status_label)}`",
                f"- Analyst notes: {_escape_md(notes)}",
                f"- Search link: `{_escape_md(search_url or '-')}`",
                f"- Execution Story link: `{_escape_md(story_url or '-')}`",
            ]
        )
        if supporting:
            lines.append("- Source event IDs: `" + ", ".join(_escape_md(str(item.get("event_id") or item.get("stable_event_id") or "-")) for item in supporting[:8]) + "`")
        story = story_by_command_id.get(command_id)
        if story:
            lines.extend(["", _render_execution_story_summary(command, story)])
        lines.append("")
    return "\n".join(lines).strip()


def _render_defender_section(events: list[dict[str, Any]]) -> str:
    if not events:
        return "No Defender events matched current filters."
    rows = [["Timestamp", "Threat", "Severity", "Action/result", "Path", "User", "Event ID", "Source event"]]
    for event in events[:100]:
        raw = event.get("raw") if isinstance(event.get("raw"), dict) else {}
        defender = raw.get("defender") if isinstance(raw.get("defender"), dict) else {}
        threat = raw.get("threat") if isinstance(raw.get("threat"), dict) else {}
        file_data = raw.get("file") if isinstance(raw.get("file"), dict) else {}
        user = raw.get("user") if isinstance(raw.get("user"), dict) else {}
        windows = raw.get("windows") if isinstance(raw.get("windows"), dict) else {}
        related = raw.get("related") if isinstance(raw.get("related"), dict) else {}
        action_parts = [
            str(defender.get("action") or "").strip(),
            str(defender.get("action_result") or "").strip(),
        ]
        rows.append(
            [
                _escape_md(str(event.get("timestamp") or raw.get("@timestamp") or "-")),
                _escape_md(str(threat.get("name") or defender.get("threat_name") or event.get("key_entity") or "-")),
                _escape_md(str(threat.get("severity") or defender.get("severity") or (raw.get("event") or {}).get("severity") or "-")),
                _escape_md(" / ".join(item for item in action_parts if item) or "-"),
                _escape_md(str(defender.get("path") or file_data.get("path") or "-")),
                _escape_md(str(user.get("name") or "-")),
                _escape_md(str(defender.get("event_id") or windows.get("event_id") or "-")),
                _escape_md(str(related.get("source_event_id") or event.get("id") or "-")),
            ]
        )
    return _markdown_table(rows)


def _render_srum_section(events: list[dict[str, Any]]) -> str:
    if not events:
        return "No SRUM records matched current filters."
    rows = [["Timestamp", "Application", "User/SID", "Type/table", "Bytes sent", "Bytes received", "Total bytes", "Source event"]]
    for event in events[:100]:
        raw = event.get("raw") if isinstance(event.get("raw"), dict) else {}
        srum = raw.get("srum") if isinstance(raw.get("srum"), dict) else {}
        network = raw.get("network") if isinstance(raw.get("network"), dict) else {}
        process = raw.get("process") if isinstance(raw.get("process"), dict) else {}
        user = raw.get("user") if isinstance(raw.get("user"), dict) else {}
        event_data = raw.get("event") if isinstance(raw.get("event"), dict) else {}
        app_name = srum.get("app_name") or srum.get("application") or network.get("application") or process.get("name") or "-"
        type_label = srum.get("artifact_type") or event_data.get("type") or srum.get("table") or "-"
        rows.append(
            [
                _escape_md(str(event.get("timestamp") or raw.get("@timestamp") or "-")),
                _escape_md(str(app_name)),
                _escape_md(str(user.get("name") or user.get("sid") or srum.get("user_sid") or "-")),
                _escape_md(str(type_label)),
                _escape_md(str(network.get("bytes_sent") or srum.get("bytes_sent") or 0)),
                _escape_md(str(network.get("bytes_received") or srum.get("bytes_received") or 0)),
                _escape_md(str(network.get("bytes_total") or srum.get("bytes_total") or 0)),
                _escape_md(str(event.get("id") or raw.get("event_id") or "-")),
            ]
        )
    return _markdown_table(rows)


def _render_execution_story_summary(command: dict[str, Any], story: dict[str, Any]) -> str:
    target = story.get("target") if isinstance(story.get("target"), dict) else {}
    story_text = story.get("story") if isinstance(story.get("story"), dict) else {}
    groups = story.get("activity_groups") if isinstance(story.get("activity_groups"), dict) else {}
    activity_items = [item for item in (groups.get("items") or []) if isinstance(item, dict)]
    omitted_counts = groups.get("omitted_counts") if isinstance(groups.get("omitted_counts"), dict) else {}
    activity_counts: Counter[str] = Counter()
    for item in activity_items:
        activity_counts[str(item.get("group") or "activity")] += int(item.get("count") or 0)
    for key, value in (omitted_counts or {}).items():
        activity_counts[str(key)] += int(value or 0)
    source_events = ", ".join(_escape_md(str(item)) for item in (story.get("source_events") or [])[:8]) or _escape_md(str(_primary_command_source_event(command) or "-"))
    lines = [
        f"#### Execution Story: {_escape_md(str(target.get('name') or (command.get('process') or {}).get('name') or 'process'))} PID {_escape_md(str(target.get('pid') or (command.get('process') or {}).get('pid') or '-'))}",
        f"- Parent: {_escape_md(str(story_text.get('parent_sentence') or 'Parent process could not be linked from available events.'))}",
        f"- Children: {_escape_md(str(story_text.get('children_sentence') or 'No child processes were observed for this process.'))}",
        f"- Activity: {_escape_md(str(story_text.get('activity_sentence') or 'No file, registry, network or DNS activity was linked to this process.'))}",
        f"- Suspicious because: {_escape_md(str(story_text.get('risk_sentence') or 'No explicit risk reason attached.'))}",
        f"- Activity group counts: `{dict(activity_counts) if activity_counts else '-'}`",
        f"- Source events: `{source_events}`",
    ]
    return "\n".join(lines)


def _execution_story_url_for_command(command: dict[str, Any]) -> str:
    case_id = str(command.get("case_id") or "")
    if not case_id:
        return ""
    params = [("mode", "execution_story")]
    if command.get("evidence_id"):
        params.append(("evidence_id", str(command.get("evidence_id"))))
    if command.get("host"):
        params.append(("host", str(command.get("host"))))
    source_event = _primary_command_source_event(command)
    if source_event:
        params.append(("source_event_id", source_event))
        params.append(("story_event_id", source_event))
    process = command.get("process") if isinstance(command.get("process"), dict) else {}
    if process.get("guid"):
        params.append(("process_guid", str(process.get("guid"))))
    if process.get("pid") is not None:
        params.append(("pid", str(process.get("pid"))))
    if command.get("timestamp"):
        params.append(("timestamp", str(command.get("timestamp"))))
    return f"/cases/{case_id}/process-graph?" + "&".join(f"{key}={value}" for key, value in params)


def _render_iocs(rows: list[dict[str, Any]]) -> str:
    if not rows:
        return "No IOCs extracted from the selected findings and key events."
    table = [["Type", "Value", "Source", "First seen", "Last seen", "Notes"]]
    for row in rows:
        table.append([row["type"], row["value"], row["source"], row["first_seen"] or "-", row["last_seen"] or "-", row["notes"] or "-"])
    return _markdown_table(table)


def _render_persistence(findings: list[Finding]) -> str:
    persistence = [finding for finding in findings if (finding.finding_type or "") in {"persistence_execution", "office_powershell"} or any("persist" in str(reason).lower() for reason in (finding.reasons or []))]
    if not persistence:
        return "No persistence-related findings selected."
    rows = [["Mechanism", "Finding", "Risk", "Path / Command"]]
    for finding in persistence:
        path_or_command = next(iter(finding.related_files or []), "") or _sanitize_text(finding.description or "")
        rows.append([finding.finding_type or "persistence", finding.title, str(int(finding.risk_score or 0)), path_or_command])
    return _markdown_table(rows)


def _render_network_cloud_usb(findings: list[Finding]) -> str:
    selected = [finding for finding in findings if (finding.finding_type or "") in {"powershell_network", "download_execute_detect", "cloud_exfil_candidate", "usb_exfil_candidate", "execution_cleanup"}]
    if not selected:
        return "No network/cloud/USB findings selected."
    rows = [["Type", "Finding", "Risk", "Related domains / IPs / files"]]
    for finding in selected:
        entities = ", ".join([*(str(item) for item in (finding.related_domains or [])[:2]), *(str(item) for item in (finding.related_ips or [])[:2]), *(str(item) for item in (finding.related_files or [])[:1])]) or "-"
        rows.append([finding.finding_type or "finding", finding.title, str(int(finding.risk_score or 0)), _sanitize_text(entities)])
    return _markdown_table(rows)


def _render_recommendations(findings: list[Finding], report: CaseReport) -> str:
    manual = _sanitize_text((report.analyst_notes or {}).get("recommendations") or "")
    recommendations: list[str] = []
    finding_types = {finding.finding_type or "" for finding in findings}
    if {"download_execute_detect", "office_powershell", "suspicious_process_chain"} & finding_types:
        recommendations.append("Isolate affected hosts and preserve volatile evidence if the case is still active.")
        recommendations.append("Review process trees and persistence mechanisms related to the suspicious execution chain.")
    if {"powershell_network", "cloud_exfil_candidate", "usb_exfil_candidate"} & finding_types:
        recommendations.append("Review outbound network, cloud access and removable media activity around the suspicious timeline.")
    if {"persistence_execution"} & finding_types:
        recommendations.append("Review and remove confirmed persistence only after preserving the relevant artifacts and event references.")
    if findings:
        recommendations.append("Block or monitor the extracted IOCs in downstream detection and containment tooling.")
    recommendations.append("Preserve the collected evidence and investigation exports to keep the case narrative reproducible.")
    deduped = _dedupe(recommendations)
    if manual:
        deduped.insert(0, manual)
    return "\n".join(f"- {_sanitize_text(item)}" for item in deduped)


def _render_appendix(report: CaseReport, timeline_entries: list[dict[str, Any]], findings: list[Finding]) -> str:
    lines = [
        "## Report generation metadata",
        "",
        f"- Filters: `{_sanitize_text(str(report.filters or {}))}`",
        f"- Selected findings: `{len(findings)}`",
        f"- Selected key events: `{len(timeline_entries)}`",
    ]
    if report.include_debug_metadata:
        lines.extend(["", f"- Draft ID: `{report.id}`", f"- Generated at: `{_iso(datetime.now(UTC))}`"])
    if report.include_raw_appendix:
        lines.extend(["", "## Event references", ""])
        for entry in timeline_entries[:15]:
            lines.append(f"- `{_sanitize_text(str(entry.get('event_id') or '-'))}` · {_sanitize_text(str(entry.get('title') or ''))}")
    limitations = _sanitize_text((report.analyst_notes or {}).get("limitations") or "")
    if limitations:
        lines.extend(["", "## Limitations", "", limitations])
    return "\n".join(lines).strip()


def _optional_int(value: Any) -> int | None:
    if value in {None, ""}:
        return None
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def _expanded_report_hosts(db: Session, case_id: str, host: str | None) -> set[str]:
    normalized = normalize_host_alias(host)
    if not normalized:
        return set()
    expanded = {normalize_host_alias(value) for value in expand_host_filter(db, case_id, normalized)}
    expanded.add(normalized)
    if "." in normalized:
        expanded.add(normalized.split(".", 1)[0])
    return {value for value in expanded if value}


def _host_matches_report_filter(candidate: str | None, expanded_hosts: set[str]) -> bool:
    normalized = normalize_host_alias(candidate)
    if not normalized:
        return False
    return normalized in expanded_hosts or normalized.split(".", 1)[0] in expanded_hosts


def _report_filters_applied(filters: dict[str, Any], time_range: dict[str, Any]) -> dict[str, Any]:
    applied: dict[str, Any] = {}
    for key in (
        "evidence_id",
        "host",
        "user",
        "time_from",
        "time_to",
        "min_severity",
        "risk_min",
        "risk_max",
        "include_findings",
        "include_detections",
        "include_marked_events",
        "include_command_history",
        "include_defender",
        "include_srum",
        "command_only_suspicious",
        "command_shell",
        "command_family",
        "command_launcher",
        "command_source_type",
        "command_risk_min",
        "command_risk_max",
        "command_has_supporting_events",
        "command_query",
        "command_marking_status",
        "include_execution_stories",
        "max_commands",
        "max_execution_stories",
        "max_defender_events",
        "max_srum_events",
        "detection_statuses",
        "detection_severities",
        "marking_statuses",
        "artifact_type",
        "parser",
        "source_file",
        "rule_name",
    ):
        value = filters.get(key)
        if value is not None and value != "" and value is not False:
            applied[key] = value
    if time_range:
        applied["time_range"] = time_range
    return applied


def _render_markdown_document(title: str, sections: list[dict[str, Any]]) -> str:
    lines = [f"# {_escape_md(title)}", "", f"_Generated at {_iso(datetime.now(UTC))}_", ""]
    for section in sections:
        lines.append(f"## {_escape_md(section['title'])}")
        lines.append("")
        lines.append(section["markdown"].strip())
        lines.append("")
    return "\n".join(lines).strip() + "\n"


def _markdown_table(rows: list[list[str]]) -> str:
    sanitized_rows = [[_sanitize_text(cell).replace("\n", " ").replace("|", "\\|") for cell in row] for row in rows]
    header = f"| {' | '.join(sanitized_rows[0])} |"
    divider = f"| {' | '.join(['---'] * len(sanitized_rows[0]))} |"
    body = [f"| {' | '.join(row)} |" for row in sanitized_rows[1:]]
    return "\n".join([header, divider, *body])


def _sanitize_text(value: str) -> str:
    text = value.strip()
    if not text:
        return ""
    text = _SECRET_INLINE.sub(lambda match: f"{match.group(1)}=[REDACTED]", text)
    text = _BEARER_TOKEN.sub("Bearer [REDACTED]", text)
    return text[:1200]


def _escape_md(value: str) -> str:
    return _sanitize_text(value).replace("*", "\\*").replace("_", "\\_").replace("`", "\\`")


def _slugify_filename(value: str) -> str:
    slug = re.sub(r"[^a-zA-Z0-9._-]+", "-", value).strip("-").lower()
    return slug or "case-report"


def _sev(finding: Finding) -> str:
    return str(finding.severity.value if hasattr(finding.severity, "value") else finding.severity)


def _safe_dt(value: Any) -> str:
    iso = _iso(value)
    return iso or ""


def _iso(value: Any) -> str | None:
    if value is None:
        return None
    if isinstance(value, str):
        return value
    if isinstance(value, datetime):
        dt = value if value.tzinfo else value.replace(tzinfo=UTC)
        return dt.astimezone(UTC).isoformat().replace("+00:00", "Z")
    return str(value)


def _dedupe(values: list[Any]) -> list[str]:
    seen: set[str] = set()
    output: list[str] = []
    for value in values:
        normalized = str(value or "").strip()
        if not normalized or normalized in seen:
            continue
        seen.add(normalized)
        output.append(normalized)
    return output
from app.services.host_identity import event_matches_host_filter, expand_host_filter, get_case_hosts, normalize_host_alias
