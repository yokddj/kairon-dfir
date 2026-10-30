from __future__ import annotations

from collections import Counter
from datetime import UTC, datetime
from io import BytesIO
import json
import logging
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
from reportlab.pdfbase.pdfmetrics import stringWidth
from reportlab.platypus import (
    BaseDocTemplate,
    CondPageBreak,
    Frame,
    HRFlowable,
    Image,
    ListFlowable,
    ListItem,
    NextPageTemplate,
    PageBreak,
    PageTemplate,
    Paragraph,
    Spacer,
    Table,
    TableStyle,
)
from reportlab.platypus.tableofcontents import TableOfContents
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
from app.services.report_i18n import current_language, normalize_language, report_language, tr
from app.services.mitre_tactics import TACTIC_ORDER, tactic_for, tagged_techniques, technique_label
from app.services.timeline_service import _finding_incident_phase, build_incident_timeline_draft, export_incident_timeline_markdown


logger = logging.getLogger(__name__)

REPORT_TEMPLATES = [
    {
        "id": "standard_investigation",
        "name": "Standard Investigation Report",
        "description": "Executive summary, findings, timeline, IOCs and recommendations",
        "sections": [
            "executive_summary",
            "narrative",
            "scope",
            "evidence",
            "hosts",
            "findings",
            "mitre",
            "timeline",
            "incident_timeline",
            "process_chains",
            "lateral_movement",
            "command_history",
            "defender",
            "email",
            "motw",
            "srum",
            "memory",
            "iocs",
            "persistence",
            "network_cloud_usb",
            "recommendations",
            "appendix",
        ],
    }
]

# How many detection/marking rows a single report will carry. The cap exists to
# keep a report readable; what it must never do is masquerade as the number of
# rows that actually matched.
REPORT_SOURCE_LIMIT = 500

DEFAULT_SECTIONS_ENABLED = {section: True for section in REPORT_TEMPLATES[0]["sections"]}
# Sections every exported report keeps even without data: a report must say
# plainly that it has no findings. Any other section with nothing to show is
# left out of the export and listed once in the appendix instead.
CORE_REPORT_SECTIONS = {"executive_summary", "scope", "evidence", "hosts", "findings", "recommendations", "appendix"}
DEFAULT_ANALYST_NOTES = {
    "executive_summary": "",
    "attack_narrative": "",
    "recommendations": "",
    "limitations": "",
}
DEFAULT_FILTERS = {
    "host": None,
    "evidence_id": None,
    # Only statuses an analyst has actually vetted -- "new" is whatever the
    # correlation engine produced unreviewed, and "reviewed" is a retired
    # status no longer reachable through the finding status transitions.
    "include_statuses": ["confirmed", "resolved"],
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
    return dict(DEFAULT_FILTERS)
SEVERITY_ORDER = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}
# Binaries under these folders are the operating system's own; seeing one in a
# key event (svchost.exe, net.exe) is activity, not an indicator to block.
BENIGN_SYSTEM_PATH = re.compile(r"^[a-z]:\\windows\\(?:system32|syswow64|winsxs)\\[^\s]+\.(?:exe|dll)$", re.IGNORECASE)
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
        metadata_json={"language": normalize_language(payload.get("language"))},
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
    if "language" in payload:
        report.metadata_json = {**dict(report.metadata_json or {}), "language": normalize_language(payload.get("language"))}
    if "ai_provenance" in payload:
        provenance = payload.get("ai_provenance")
        metadata = dict(report.metadata_json or {})
        if isinstance(provenance, dict) and provenance:
            metadata["ai_provenance"] = {key: str(provenance.get(key) or "") for key in ("provider", "model", "hosting", "generated_at", "prompt_version")}
        else:
            metadata.pop("ai_provenance", None)
        report.metadata_json = metadata
    db.add(report)
    db.commit()
    db.refresh(report)
    return _serialize_report(report)


def build_case_report_preview(db: Session, case_id: str, report_id: str, *, collect_ai_context: bool = False) -> dict[str, Any]:
    report = _get_report_or_404(db, case_id, report_id)
    with report_language(_report_language(report)):
        return _build_case_report_preview(db, case_id, report_id, report, collect_ai_context=collect_ai_context)


def _report_language(report: CaseReport) -> str:
    return normalize_language((report.metadata_json or {}).get("language"))


def _build_case_report_preview(db: Session, case_id: str, report_id: str, report: CaseReport, *, collect_ai_context: bool = False) -> dict[str, Any]:
    case = _get_case_or_404(db, case_id)
    context = _build_case_context(db, case_id)
    filters = {**_default_report_filters_for_case(case), **dict(report.filters or {})}
    sections_enabled = {**DEFAULT_SECTIONS_ENABLED, **dict(report.sections_enabled or {})}
    findings = _filtered_findings(db, case_id, filters)
    detections, detections_total = _filtered_detections(db, case_id, filters)
    detection_event_times = _resolve_detection_event_times(case_id, detections)
    marked_events, marked_events_total = _filtered_markings(db, case_id, filters)
    command_report = _build_command_history_report_context(db, case, case_id, filters)
    defender_report = _build_defender_report_context(db, case_id, filters)
    email_report = build_email_artifacts_report_context(db, case_id, filters)
    srum_report = _build_srum_report_context(db, case_id, filters)
    motw_report = build_motw_report_context(db, case_id, filters)
    incident_timeline_report = _build_incident_timeline_report_context(db, case_id, filters)
    persistence_report = build_startup_persistence_report_context(db, case_id, filters)
    memory_report = _build_memory_report_context(db, case_id, filters) if sections_enabled.get("memory", True) else []
    lateral_report = _build_lateral_movement_report_context(db, case_id, filters) if sections_enabled.get("lateral_movement", True) else {"edges": [], "routine": 0}
    findings_by_id = {finding.id: finding for finding in findings}
    selected_finding_ids = list(report.selected_finding_ids or [])
    selected_key_event_ids = list(report.selected_key_event_ids or [])
    selected_process_chain_ids = list(report.selected_process_chain_ids or [])
    selected_findings = [findings_by_id[finding_id] for finding_id in selected_finding_ids if finding_id in findings_by_id] if filters.get("include_findings", True) else []
    bookmarks = _filtered_bookmarks(db, case_id, filters)
    bookmarks_by_id = {bookmark.id: bookmark for bookmark in bookmarks}
    selected_bookmarks = [bookmarks_by_id[bookmark_id] for bookmark_id in selected_key_event_ids if bookmark_id in bookmarks_by_id] if filters.get("include_timeline_events", True) else []
    selected_chain_findings = [findings_by_id[finding_id] for finding_id in selected_process_chain_ids if finding_id in findings_by_id]
    execution_trees = _execution_trees(db, case, selected_chain_findings) if sections_enabled.get("process_chains", True) else {}
    if not selected_findings and findings:
        selected_findings = [_auto_select_findings(findings)[0]] if _auto_select_findings(findings) else []
    if not selected_bookmarks and bookmarks:
        selected_bookmarks = [bookmark for bookmark in bookmarks if bookmark.include_in_report]

    timeline_entries, timeline_auto_selected = _build_timeline_entries(selected_bookmarks, selected_findings)
    if filters.get("include_marked_events", True):
        bookmarked_event_ids = {str(bookmark.event_id) for bookmark in selected_bookmarks}
        timeline_entries.extend(
            entry
            for entry in _build_marked_event_entries(marked_events)
            # A key event already carries the analyst's title and note, and a
            # mark with no time (a memory process) has no place on a timeline;
            # it is reported in its own section (Memory Analysis).
            if entry["timestamp"] and str(entry["event_id"]) not in bookmarked_event_ids
        )
        timeline_entries.sort(key=lambda item: _safe_dt(item.get("timestamp")))
    # One timeline in the report: key events, marked events and the accepted
    # Incident Timeline items, instead of two overlapping sections.
    merge_incident_timeline = bool(
        sections_enabled.get("timeline", True) and sections_enabled.get("incident_timeline", True) and filters.get("include_incident_timeline", True)
    )
    if merge_incident_timeline:
        timeline_entries = _merge_incident_items(timeline_entries, incident_timeline_report["items"])
    ioc_rows = _extract_iocs(case_id, selected_findings, selected_bookmarks)
    evidence_rows = _case_evidence_rows(db, case_id)
    pending_review = _count_findings_pending_review(db, case_id, filters, findings)
    sections: list[dict[str, Any]] = []
    warnings: list[str] = []
    coverage_notes: list[str] = []
    if detections_total > len(detections):
        warnings.append(
            f"detections: showing the {len(detections)} most recent of {detections_total} matched; "
            "narrow by host, severity or time range to review the rest"
        )
        coverage_notes.append(f"Detections: the {len(detections):,} most recent of {detections_total:,} matches are summarised.")
    if marked_events_total > len(marked_events):
        warnings.append(
            f"marked events: showing the {len(marked_events)} most recent of {marked_events_total} matched; "
            "narrow by host or time range to review the rest"
        )
        coverage_notes.append(f"Marked events: the {len(marked_events):,} most recent of {marked_events_total:,} are included.")
    coverage_notes.extend(_COVERAGE_NOTE_TEXT[code] for code in context["summary"]["warnings"] if code in _COVERAGE_NOTE_TEXT)
    coverage_notes.extend(_host_coverage_notes(db, case_id))
    stats = {
        "findings_matched": len(findings),
        "findings_pending_review": pending_review,
        "detections_matched": detections_total,
        "detections_included": len(detections),
        "marked_events_matched": marked_events_total,
        "marked_events_included": len(marked_events),
        # Counts the analyst's key-event bookmarks. The timeline section is also
        # fed by findings and marked events, so it can be populated while this
        # is zero -- timeline_entries_included is what the section actually has.
        "timeline_events_matched": len(bookmarks),
        "timeline_entries_included": len(timeline_entries),
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
        # total describes every persistence entry found; suspicious is how many
        # of them cleared the risk bar; included is how many the report carries.
        "startup_persistence_items": int(persistence_report["counts"].get("total") or 0),
        "startup_persistence_suspicious": int(persistence_report["counts"].get("suspicious") or 0),
        "startup_persistence_included": len(persistence_report.get("items") or []),
        "commands_by_shell": command_report["counts"]["commands_by_shell"],
        "commands_by_family": command_report["counts"].get("commands_by_family", command_report["counts"]["commands_by_shell"]),
        "commands_by_launcher": command_report["counts"].get("commands_by_launcher", {}),
        "commands_by_source_type": command_report["counts"]["commands_by_source_type"],
        "selected_findings": len(selected_findings),
        "selected_key_events": len(selected_bookmarks),
        "selected_process_chains": len(selected_chain_findings),
        "ioc_count": len([row for row in ioc_rows if row["type"] != "event_id"]),
    }
    filters_applied = _report_filters_applied(filters, report.time_range or {})

    def add(section_id: str, title: str, markdown: str, *, empty: bool = False, notes: list[str] | None = None, diagrams: dict[str, Any] | None = None) -> None:
        # An empty section's body already says there is nothing to show, so it
        # carries no warning: repeating "no data" in a warning box is noise.
        section = {"id": section_id, "title": tr(title), "markdown": markdown, "warnings": [] if empty else list(notes or []), "empty": empty}
        if diagrams:
            section["diagrams"] = diagrams
        sections.append(section)

    if sections_enabled.get("executive_summary", True):
        add("executive_summary", "Executive Summary", _render_executive_summary(case, context, selected_findings, report, pending_review=pending_review))
    if sections_enabled.get("narrative", True):
        narrative = _narrative((report.analyst_notes or {}).get("attack_narrative"))
        add("narrative", "Attack Narrative", narrative, empty=not narrative)
    if sections_enabled.get("scope", True):
        add("scope", "Scope", _render_scope(case, context, report, evidence_names={item["id"]: item["name"] for item in context["evidences"]}, coverage_notes=coverage_notes))
    if sections_enabled.get("evidence", True):
        add("evidence", "Evidence Processed", _render_evidence(context, evidence_rows), empty=not context["evidences"])
    if sections_enabled.get("hosts", True):
        add("hosts", "Hosts", _render_hosts(context, selected_findings), empty=not context["hosts"])
    if sections_enabled.get("findings", True):
        add("findings", "Findings", _render_findings(selected_findings), empty=not selected_findings)
    if sections_enabled.get("mitre", True):
        mitre_markdown = _render_mitre(selected_findings)
        add("mitre", "MITRE ATT&CK", mitre_markdown, empty=not mitre_markdown)
    if sections_enabled.get("findings", True) and filters.get("include_detections", True):
        add("detections", "Detections", _render_detections(detections, detections_total, event_times=detection_event_times), empty=not detections)
    if sections_enabled.get("timeline", True):
        timeline_notes = ["No key events were bookmarked for the report; this timeline is built from the selected findings."] if timeline_auto_selected else []
        if merge_incident_timeline:
            timeline_notes.extend(_incident_timeline_report_notes(incident_timeline_report["warnings"]))
        add("timeline", "Investigation Timeline", _render_timeline(timeline_entries), empty=not timeline_entries, notes=timeline_notes)
    if sections_enabled.get("incident_timeline", True) and filters.get("include_incident_timeline", True) and not merge_incident_timeline:
        incident_markdown = _render_incident_timeline_section(case_id, incident_timeline_report["items"])
        add("incident_timeline", "Incident Timeline", incident_markdown, empty=incident_markdown == "No incident timeline items were generated.", notes=_incident_timeline_report_notes(incident_timeline_report["warnings"]))
    if sections_enabled.get("process_chains", True):
        add("process_chains", "Process Chains", _render_process_chains(selected_chain_findings, execution_trees), empty=not selected_chain_findings,
            diagrams={finding_id: tree for finding_id, tree in execution_trees.items() if tree})
    if sections_enabled.get("lateral_movement", True):
        add("lateral_movement", "Lateral Movement", _render_lateral_movement_section(lateral_report), empty=not lateral_report["edges"], notes=lateral_report.get("warnings") or [])
    if sections_enabled.get("command_history", True) and filters.get("include_command_history", True):
        add("command_history", "Suspicious Command History", _render_command_history_section(command_report["commands"], command_report["stories"]), empty=not command_report["commands"], notes=command_report["warnings"])
    if sections_enabled.get("defender", True) and filters.get("include_defender", True):
        add("defender", "Microsoft Defender", _render_defender_section(defender_report["events"]), empty=not defender_report["events"], notes=defender_report["warnings"])
    if sections_enabled.get("email", True) and filters.get("include_email", True):
        email_markdown = _humanize_table_columns(_collapse_duplicate_table_rows(render_email_artifacts_markdown(email_report["items"])), {"Type", "Client"})
        add("email", "Email Artifacts", email_markdown, empty=not email_report["items"], notes=_summarize_source_cap_warnings(email_report["warnings"], "Email Artifacts"))
    if sections_enabled.get("motw", True):
        add("motw", "MOTW / Downloaded Files", _humanize_table_columns(_collapse_duplicate_table_rows(render_motw_markdown(motw_report["items"])), {"Source"}), empty=not motw_report["items"], notes=motw_report["warnings"])
    if sections_enabled.get("srum", True) and filters.get("include_srum", True):
        add("srum", "SRUM Application and Network Usage", _render_srum_section(srum_report["events"]), empty=not srum_report["events"], notes=srum_report["warnings"])
    if memory_report:
        # Only when the case has memory images: no empty section for disk-only cases.
        add("memory", "Memory Analysis", _render_memory_section(memory_report))
    if sections_enabled.get("iocs", True):
        iocs_markdown = _render_iocs(ioc_rows)
        add("iocs", "IOCs", iocs_markdown, empty=not stats["ioc_count"])
    if sections_enabled.get("persistence", True):
        persistence_markdown = _humanize_table_columns(_collapse_duplicate_table_rows(render_startup_persistence_markdown(persistence_report["items"])), {"Type", "Evidence"})
        persistence_empty = False
        if not persistence_report["items"]:
            persistence_markdown = _render_persistence(selected_findings)
            persistence_empty = persistence_markdown == "No persistence-related findings selected."
        add("persistence", "Startup & Persistence", persistence_markdown, empty=persistence_empty, notes=_summarize_source_cap_warnings(persistence_report["warnings"]))
    if sections_enabled.get("network_cloud_usb", True):
        network_markdown = _render_network_cloud_usb(selected_findings)
        add("network_cloud_usb", "Network / Cloud / USB", network_markdown, empty=network_markdown == "No network/cloud/USB findings selected.")
    if sections_enabled.get("recommendations", True):
        add("recommendations", "Recommendations", _render_recommendations(selected_findings, report))
    if sections_enabled.get("appendix", True):
        omitted = [section["title"] for section in sections if section["empty"] and section["id"] not in CORE_REPORT_SECTIONS]
        add("appendix", "Appendix", _render_appendix(report, timeline_entries, selected_findings, omitted_sections=omitted))

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
    ai_context = (
        _report_ai_context(case, context, report, selected_findings, timeline_entries, ioc_rows, coverage_notes, memory_report, detections, detections_total, lateral_report["edges"])
        if collect_ai_context else None
    )
    return {
        **({"ai_context": ai_context} if ai_context is not None else {}),
        "title": report.title,
        "sections": sections,
        "warnings": warnings,
        "coverage_notes": coverage_notes,
        "stats": stats,
        "counts": stats,
        "filters_applied": filters_applied,
    }


def export_case_report(db: Session, case_id: str, report_id: str, *, format: str) -> tuple[str | bytes, str, str]:
    report = _get_report_or_404(db, case_id, report_id)
    with report_language(_report_language(report)):
        return _export_case_report(db, case_id, report_id, report, format=format)


def _export_case_report(db: Session, case_id: str, report_id: str, report: CaseReport, *, format: str) -> tuple[str | bytes, str, str]:
    if format not in {"markdown", "pdf"}:
        raise HTTPException(status_code=400, detail="Unsupported export format")
    preview = build_case_report_preview(db, case_id, report_id)
    case = _get_case_or_404(db, case_id)
    if format == "markdown":
        content: str | bytes = _render_markdown_document(preview["title"], _exported_sections(preview), author=report.author)
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


def _exported_sections(preview: dict[str, Any]) -> list[dict[str, Any]]:
    return [section for section in preview.get("sections") or [] if not (section.get("empty") and section.get("id") not in CORE_REPORT_SECTIONS)]


class _ReportDocTemplate(BaseDocTemplate):
    """Two page templates (cover, content) plus table-of-contents and PDF
    outline entries for every flowable tagged with a `toc_level`."""

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        super().__init__(*args, **kwargs)
        frame = Frame(self.leftMargin, self.bottomMargin, self.width, self.height, id="content", leftPadding=0, rightPadding=0, topPadding=0, bottomPadding=0)
        self.addPageTemplates([PageTemplate(id="cover", frames=[frame]), PageTemplate(id="content", frames=[frame])])
        self._outline_keys = 0

    def beforeDocument(self) -> None:  # noqa: N802 - reportlab API
        # multiBuild re-runs the story until the TOC is stable; keys must be
        # identical on every pass or the entries never converge.
        self._outline_keys = 0

    def afterFlowable(self, flowable: Any) -> None:
        level = getattr(flowable, "toc_level", None)
        if level is None:
            return
        text = getattr(flowable, "toc_text", "") or flowable.getPlainText()
        self._outline_keys += 1
        key = f"section-{self._outline_keys}"
        self.canv.bookmarkPage(key)
        self.canv.addOutlineEntry(text, key, level=level, closed=level > 0)
        self.notify("TOCEntry", (level, text, self.page, key))


def _render_pdf_document(report: CaseReport, case: Case, context: dict[str, Any], preview: dict[str, Any], branding: dict[str, Any]) -> bytes:
    palette = _pdf_palette(branding["primary_color"])
    styles = _build_pdf_styles(palette)
    buffer = BytesIO()
    doc = _ReportDocTemplate(
        buffer,
        pagesize=A4,
        leftMargin=18 * mm,
        rightMargin=18 * mm,
        topMargin=22 * mm,
        bottomMargin=18 * mm,
        title=preview["title"],
        author=report.author or branding["brand_name"],
    )
    story: list[Any] = []
    generated_at = datetime.now(UTC)
    sections = _exported_sections(preview)

    _append_cover_page(story, report, case, preview, branding, palette, styles, generated_at)
    story.append(NextPageTemplate("content"))
    story.append(PageBreak())

    story.append(Paragraph(tr("Contents"), styles["toc_title"]))
    toc = TableOfContents()
    toc.levelStyles = [styles["toc_1"], styles["toc_2"]]
    toc.dotsMinLevel = 0
    story.append(toc)
    story.append(PageBreak())

    for number, section in enumerate(sections, start=1):
        title = str(section.get("title") or "Section")
        if section.get("id") == "appendix" and number > 1:
            story.append(PageBreak())
        else:
            story.append(CondPageBreak(55 * mm))
        heading = Paragraph(f"<font color='{palette['muted'].hexval().replace('0x', '#')}'>{number}</font>&nbsp;&nbsp;{_pdf_inline(title)}", styles["section_heading"])
        heading.toc_level = 0  # type: ignore[attr-defined]
        heading.toc_text = f"{number}. {title}"  # type: ignore[attr-defined]
        story.append(heading)
        story.append(HRFlowable(width="100%", thickness=1.2, color=palette["primary"], spaceBefore=0, spaceAfter=8))
        if section.get("id") == "executive_summary":
            story.append(_build_stats_table(_executive_tiles(context, preview), palette, styles))
            story.append(Spacer(1, 10))
        if section.get("warnings"):
            story.append(_build_warning_table([str(item) for item in section["warnings"]], styles, palette))
            story.append(Spacer(1, 6))
        _append_markdown_to_story(story, str(section.get("markdown") or ""), styles, palette, diagrams=section.get("diagrams"), width=doc.width)
        story.append(Spacer(1, 10))

    case_label = _sanitize_text(str(case.name or case.id))

    def chrome(pdf_canvas: canvas.Canvas, page_number: int, page_count: int) -> None:
        if page_number == 1:
            return
        _draw_pdf_page_chrome(pdf_canvas, doc, branding, case_label, generated_at, palette, page_number, page_count)

    build = settings.build_identity

    class NumberedCanvas(canvas.Canvas):
        # Pages are buffered so the footer can say "Page X of Y".
        def __init__(self, *args: Any, **kwargs: Any) -> None:
            kwargs["pageCompression"] = 0
            super().__init__(*args, **kwargs)
            self._saved_page_states: list[dict[str, Any]] = []
            self.setCreator(f"Kairon DFIR {build['app_version']}")
            self.setProducer(build["build_fingerprint"])
            self.setSubject(build["notice"])
            self.setKeywords(",".join([build["vendor_id"], build["build_channel"], build["build_fingerprint"]]))

        def showPage(self) -> None:  # noqa: N802 - reportlab API
            self._saved_page_states.append(dict(self.__dict__))
            self._startPage()

        def save(self) -> None:
            page_count = len(self._saved_page_states)
            for state in self._saved_page_states:
                self.__dict__.update(state)
                chrome(self, self._pageNumber, page_count)
                super().showPage()
            super().save()

    try:
        doc.multiBuild(story, canvasmaker=NumberedCanvas)
    except Exception as exc:  # noqa: BLE001
        raise PdfRendererUnavailableError(f"PDF export failed: {exc}") from exc
    return buffer.getvalue()


def _executive_tiles(context: dict[str, Any], preview: dict[str, Any]) -> list[list[str]]:
    stats = preview.get("stats") or {}
    hosts = [host for host in context.get("hosts") or [] if _context_host_name(host) != "unknown"]
    return [
        [tr("Evidence items"), f"{len(context.get('evidences') or []):,}"],
        [tr("Hosts"), f"{len(hosts):,}"],
        [tr("Events indexed"), f"{int((context.get('summary') or {}).get('events_indexed') or 0):,}"],
        [tr("Findings reported"), f"{int(stats.get('selected_findings') or 0):,}"],
        [tr("Rule matches"), f"{int(stats.get('detections_matched') or 0):,}"],
        [tr("Indicators"), f"{int(stats.get('ioc_count') or 0):,}"],
    ]


def _append_cover_page(
    story: list[Any],
    report: CaseReport,
    case: Case,
    preview: dict[str, Any],
    branding: dict[str, Any],
    palette: dict[str, colors.Color],
    styles: dict[str, ParagraphStyle],
    generated_at: datetime,
) -> None:
    logo = _load_logo_image(branding)
    if logo is not None:
        logo.hAlign = "LEFT"
        story.append(logo)
        story.append(Spacer(1, 6))
    story.append(Paragraph(_pdf_inline(branding["brand_name"]), styles["cover_brand"]))
    if branding.get("subtitle"):
        story.append(Paragraph(_pdf_inline(branding["subtitle"]), styles["cover_subtitle"]))
    story.append(Spacer(1, 60 * mm))
    story.append(Paragraph(tr("DIGITAL FORENSIC INVESTIGATION REPORT"), styles["cover_kicker"]))
    story.append(Spacer(1, 4))
    story.append(Paragraph(_pdf_inline(preview["title"]), styles["cover_title"]))
    story.append(HRFlowable(width="35%", thickness=3, color=palette["primary"], hAlign="LEFT", spaceBefore=4, spaceAfter=14))
    story.append(Paragraph(_pdf_inline(tr("Case: {case}", case=case.name or case.id)), styles["cover_case"]))
    story.append(Spacer(1, 26 * mm))
    case_rows = [
        [tr("Case ID"), str(case.id)],
        [tr("Prepared by"), report.author or tr("Not specified")],
        [tr("Report date"), f"{_fmt_ts(generated_at)} UTC"],
        [tr("Timezone"), tr("All times in UTC") if (case.timezone or "UTC") == "UTC" else f"{case.timezone} → UTC"],
        [tr("Report reference"), str(report.id)[:8].upper()],
    ]
    story.append(_build_key_value_table(case_rows, palette, styles, col_widths=(38 * mm, 136 * mm)))
    story.append(Spacer(1, 10))
    story.append(Paragraph(
        _pdf_inline(tr("This report contains information from a forensic investigation. Handle it according to your organisation's classification policy and share it only with authorised recipients.")),
        styles["cover_notice"],
    ))


def _build_pdf_styles(palette: dict[str, colors.Color]) -> dict[str, ParagraphStyle]:
    base = getSampleStyleSheet()
    body = ParagraphStyle("body", parent=base["BodyText"], fontName="Helvetica", fontSize=9.5, leading=13.5, textColor=palette["ink"], spaceAfter=5, wordWrap="CJK", alignment=TA_LEFT)
    return {
        "cover_brand": ParagraphStyle("cover_brand", parent=body, fontName="Helvetica-Bold", fontSize=13, leading=16, textColor=palette["primary"]),
        "cover_subtitle": ParagraphStyle("cover_subtitle", parent=body, fontSize=9, leading=12, textColor=palette["muted"]),
        "cover_kicker": ParagraphStyle("cover_kicker", parent=body, fontName="Helvetica-Bold", fontSize=9, leading=12, textColor=palette["muted"]),
        "cover_title": ParagraphStyle("cover_title", parent=body, fontName="Helvetica-Bold", fontSize=26, leading=31, textColor=palette["ink"], spaceAfter=4),
        "cover_case": ParagraphStyle("cover_case", parent=body, fontSize=13, leading=17, textColor=palette["muted"]),
        "cover_notice": ParagraphStyle("cover_notice", parent=body, fontSize=8, leading=11, textColor=palette["muted"]),
        "toc_title": ParagraphStyle("toc_title", parent=body, fontName="Helvetica-Bold", fontSize=18, leading=22, textColor=palette["ink"], spaceAfter=14),
        "toc_1": ParagraphStyle("toc_1", parent=body, fontSize=10.5, leading=17, leftIndent=0),
        "toc_2": ParagraphStyle("toc_2", parent=body, fontSize=9, leading=13, leftIndent=14, textColor=palette["muted"]),
        "section_heading": ParagraphStyle("section_heading", parent=body, fontName="Helvetica-Bold", fontSize=16, leading=20, textColor=palette["ink"], spaceBefore=4, spaceAfter=4, keepWithNext=1),
        "subheading": ParagraphStyle("subheading", parent=body, fontName="Helvetica-Bold", fontSize=12, leading=15, textColor=palette["primary"], spaceBefore=8, spaceAfter=4, keepWithNext=1),
        "minor_heading": ParagraphStyle("minor_heading", parent=body, fontName="Helvetica-Bold", fontSize=10, leading=13, textColor=palette["ink"], spaceBefore=6, spaceAfter=3, keepWithNext=1),
        "label": ParagraphStyle("label", parent=body, fontName="Helvetica-Bold", fontSize=9, leading=12, textColor=palette["muted"], spaceBefore=4, spaceAfter=2, keepWithNext=1),
        "body": body,
        "body_small": ParagraphStyle("body_small", parent=body, fontSize=8, leading=10.5, spaceAfter=0),
        "note": ParagraphStyle("note", parent=body, fontSize=8.5, leading=12, textColor=palette["muted"], backColor=palette["header_fill"], borderColor=palette["border"], borderWidth=0.5, borderPadding=6, spaceBefore=4, spaceAfter=8),
        "code": ParagraphStyle("code", parent=body, fontName="Courier", fontSize=8, leading=10.5, backColor=palette["header_fill"], borderPadding=5, spaceAfter=6),
        "bullet": ParagraphStyle("bullet", parent=body, fontSize=9.3, leading=13, leftIndent=0, spaceAfter=1.5),
    }


_HEADING_STYLES = {2: "subheading", 3: "subheading", 4: "minor_heading", 5: "minor_heading", 6: "minor_heading"}


def _append_markdown_to_story(
    story: list[Any],
    markdown: str,
    styles: dict[str, ParagraphStyle],
    palette: dict[str, colors.Color],
    *,
    diagrams: dict[str, Any] | None = None,
    width: float = 174 * mm,
) -> None:
    lines = markdown.splitlines()
    index = 0
    pending_diagram: str | None = None
    while index < len(lines):
        line = lines[index].rstrip()
        stripped = line.strip()
        if not stripped:
            index += 1
            continue
        marker = re.match(r"^<!--\s*execution-diagram:(\S+)\s*-->$", stripped)
        if marker or stripped.startswith("<!--"):
            # Comments are not shown; a diagram marker replaces the text tree after it.
            pending_diagram = marker.group(1) if marker else None
            index += 1
            continue
        if stripped.startswith("```"):
            code_lines: list[str] = []
            index += 1
            while index < len(lines) and not lines[index].strip().startswith("```"):
                code_lines.append(lines[index])
                index += 1
            index += 1
            tree = (diagrams or {}).get(pending_diagram or "")
            pending_diagram = None
            if tree:
                from app.services.report_execution_diagram import execution_tree_drawing

                story.append(execution_tree_drawing(tree, width, palette))
                story.append(Spacer(1, 6))
                continue
            story.append(Paragraph(escape(_sanitize_text("\n".join(code_lines))).replace("\n", "<br/>"), styles["code"]))
            continue
        if stripped.startswith("|"):
            table_lines: list[str] = []
            while index < len(lines) and lines[index].strip().startswith("|"):
                table_lines.append(lines[index].strip())
                index += 1
            table = _parse_markdown_table(table_lines)
            if table:
                story.append(_build_markdown_table(table, styles, palette))
                story.append(Spacer(1, 7))
            continue
        heading = re.match(r"^(#{2,6})\s+(.*)$", stripped)
        if heading:
            story.append(Paragraph(_pdf_inline(heading.group(2).strip()), styles[_HEADING_STYLES[len(heading.group(1))]]))
            index += 1
            continue
        if stripped.startswith("> "):
            quote_lines: list[str] = []
            while index < len(lines) and lines[index].strip().startswith(">"):
                quote_lines.append(lines[index].strip().lstrip(">").strip())
                index += 1
            story.append(Paragraph(_pdf_inline(" ".join(quote_lines)), styles["note"]))
            continue
        if stripped.startswith("- "):
            bullet_lines: list[str] = []
            while index < len(lines) and lines[index].strip().startswith("- "):
                bullet_lines.append(lines[index].strip()[2:])
                index += 1
            story.append(
                ListFlowable(
                    [ListItem(Paragraph(_pdf_inline(item), styles["bullet"]), value="•") for item in bullet_lines],
                    bulletType="bullet",
                    start="•",
                    leftIndent=12,
                    bulletFontSize=8,
                    bulletColor=palette["primary"],
                )
            )
            story.append(Spacer(1, 4))
            continue
        if stripped.endswith(":") and len(stripped) <= 80 and index + 1 < len(lines) and lines[index + 1].strip().startswith(("- ", "|")):
            story.append(Paragraph(_pdf_inline(stripped), styles["label"]))
            index += 1
            continue
        paragraph_lines = [stripped]
        index += 1
        while index < len(lines):
            candidate = lines[index].strip()
            if not candidate or candidate.startswith(("|", "- ", "#", "> ", "```")):
                break
            paragraph_lines.append(candidate)
            index += 1
        story.append(Paragraph(_pdf_inline(" ".join(paragraph_lines)), styles["body"]))


def _parse_markdown_table(lines: list[str]) -> list[list[str]]:
    rows: list[list[str]] = []
    for raw in lines:
        candidate = raw.strip().strip("|")
        if not candidate:
            continue
        parts = [_unescape_md_table_cell(part.strip()) for part in re.split(r"(?<!\\)\|", candidate)]
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


_SEVERITY_CELL_COLORS = {"critical": "#b91c1c", "high": "#c2410c", "medium": "#a16207", "low": "#0f766e", "info": "#475569"}


def _cell_text_width(cell: str) -> float:
    code = "".join(_INLINE_CODE.findall(cell))
    text = _INLINE_CODE.sub("", cell)
    return stringWidth(text, "Helvetica", 8) + stringWidth(code, "Courier", 7.8)


def _table_column_widths(rows: list[list[str]], total_width: float) -> list[float]:
    """Size columns by measured text: narrow columns (time, risk, PID) get
    their natural width, free text shares what is left. A header word is never
    split across lines."""
    padding = 9
    columns = len(rows[0])
    natural: list[float] = []
    minimum: list[float] = []
    for index in range(columns):
        widths = sorted(_cell_text_width(str(row[index] if index < len(row) else "")) + padding for row in rows[1:]) or [padding]
        header_words = str(rows[0][index]).split() or [""]
        header_min = max(stringWidth(word, "Helvetica-Bold", 8) for word in header_words) + padding
        natural.append(max(widths[min(len(widths) - 1, int(len(widths) * 0.9))], header_min))
        minimum.append(max(header_min, 12 * mm))
    if sum(natural) <= total_width:
        extra = total_width - sum(natural)
        return [width + extra * width / sum(natural) for width in natural]
    # Water-fill: columns that fit in an equal share keep their natural width.
    widths = [0.0] * columns
    flexible = set(range(columns))
    remaining = total_width
    changed = True
    while changed and flexible:
        changed = False
        share = remaining / len(flexible)
        for index in sorted(flexible):
            if natural[index] <= share:
                widths[index] = natural[index]
                remaining -= natural[index]
                flexible.discard(index)
                changed = True
    for index in flexible:
        widths[index] = max(remaining / len(flexible), minimum[index])
    scale = total_width / sum(widths)
    return [width * scale for width in widths]


def _build_markdown_table(rows: list[list[str]], styles: dict[str, ParagraphStyle], palette: dict[str, colors.Color]) -> Table:
    header_style = ParagraphStyle("table_header", parent=styles["body_small"], fontName="Helvetica-Bold", textColor=palette["primary"])
    paragraph_rows = []
    for row_index, row in enumerate(rows):
        cells = []
        for cell in row:
            text = _pdf_inline(cell or "-")
            if row_index and str(cell).strip().lower() in _SEVERITY_CELL_COLORS:
                text = f"<font color='{_SEVERITY_CELL_COLORS[str(cell).strip().lower()]}'><b>{text}</b></font>"
            cells.append(Paragraph(text, header_style if row_index == 0 else styles["body_small"]))
        paragraph_rows.append(cells)
    total_width = A4[0] - 36 * mm
    table = Table(paragraph_rows, colWidths=_table_column_widths(rows, total_width), repeatRows=1, hAlign="LEFT")
    table.setStyle(
        TableStyle(
            [
                ("BACKGROUND", (0, 0), (-1, 0), palette["header_fill"]),
                ("LINEBELOW", (0, 0), (-1, 0), 0.9, palette["primary"]),
                ("LINEBELOW", (0, 1), (-1, -1), 0.3, palette["border"]),
                ("VALIGN", (0, 0), (-1, -1), "TOP"),
                ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, palette["zebra"]]),
                ("LEFTPADDING", (0, 0), (-1, -1), 4),
                ("RIGHTPADDING", (0, 0), (-1, -1), 4),
                ("TOPPADDING", (0, 0), (-1, -1), 3.5),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 3.5),
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
                ("LINEBEFORE", (0, 0), (0, -1), 2.5, palette["warning_border"]),
                ("LEFTPADDING", (0, 0), (-1, -1), 8),
                ("RIGHTPADDING", (0, 0), (-1, -1), 6),
                ("TOPPADDING", (0, 0), (-1, -1), 4),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
            ]
        )
    )
    return table


def _build_key_value_table(rows: list[list[str]], palette: dict[str, colors.Color], styles: dict[str, ParagraphStyle], *, col_widths: tuple[float, float]) -> Table:
    label_style = ParagraphStyle("kv_label", parent=styles["body_small"], fontName="Helvetica-Bold", textColor=palette["muted"])
    data = [[Paragraph(_pdf_inline(label), label_style), Paragraph(_pdf_inline(value), styles["body_small"])] for label, value in rows]
    table = Table(data, colWidths=list(col_widths), hAlign="LEFT")
    table.setStyle(
        TableStyle(
            [
                ("LINEABOVE", (0, 0), (-1, 0), 0.8, palette["primary"]),
                ("LINEBELOW", (0, 0), (-1, -1), 0.3, palette["border"]),
                ("VALIGN", (0, 0), (-1, -1), "TOP"),
                ("LEFTPADDING", (0, 0), (-1, -1), 2),
                ("RIGHTPADDING", (0, 0), (-1, -1), 6),
                ("TOPPADDING", (0, 0), (-1, -1), 5),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
            ]
        )
    )
    return table


def _build_stats_table(rows: list[list[str]], palette: dict[str, colors.Color], styles: dict[str, ParagraphStyle]) -> Table:
    value_style = ParagraphStyle("stats_value", parent=styles["body"], fontName="Helvetica-Bold", fontSize=17, leading=20, alignment=TA_CENTER, textColor=palette["primary"], spaceAfter=0)
    label_style = ParagraphStyle("stats_label", parent=styles["body_small"], alignment=TA_CENTER, textColor=palette["muted"])
    cells = [[Paragraph(_pdf_inline(value), value_style), Paragraph(_pdf_inline(label), label_style)] for label, value in rows]
    columns = 3
    grid: list[list[Any]] = []
    for offset in range(0, len(cells), columns):
        row = cells[offset : offset + columns]
        row.extend([[Paragraph("", label_style)]] * (columns - len(row)))
        grid.append(row)
    width = (A4[0] - 36 * mm) / columns
    table = Table(grid, colWidths=[width] * columns, hAlign="LEFT")
    table.setStyle(
        TableStyle(
            [
                ("BACKGROUND", (0, 0), (-1, -1), palette["header_fill"]),
                ("LINEBELOW", (0, 0), (-1, -1), 2, colors.white),
                ("LINEAFTER", (0, 0), (-2, -1), 2, colors.white),
                ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
                ("TOPPADDING", (0, 0), (-1, -1), 8),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 8),
            ]
        )
    )
    return table


def _draw_pdf_page_chrome(
    pdf_canvas: canvas.Canvas,
    doc: BaseDocTemplate,
    branding: dict[str, Any],
    case_label: str,
    generated_at: datetime,
    palette: dict[str, colors.Color],
    page_number: int,
    page_count: int,
) -> None:
    left, right = doc.leftMargin, A4[0] - doc.rightMargin
    top = A4[1] - 12 * mm
    pdf_canvas.saveState()
    pdf_canvas.setFont("Helvetica-Bold", 7.5)
    pdf_canvas.setFillColor(palette["primary"])
    pdf_canvas.drawString(left, top, branding["brand_name"].upper())
    pdf_canvas.setFont("Helvetica", 7.5)
    pdf_canvas.setFillColor(palette["muted"])
    pdf_canvas.drawRightString(right, top, _clip(tr("Case {case} · Investigation report", case=case_label), 90))
    pdf_canvas.setStrokeColor(palette["border"])
    pdf_canvas.setLineWidth(0.4)
    pdf_canvas.line(left, top - 2.5 * mm, right, top - 2.5 * mm)
    pdf_canvas.line(left, 12 * mm, right, 12 * mm)
    pdf_canvas.drawString(left, 8 * mm, tr("Generated {when} UTC · Confidential", when=_fmt_ts(generated_at)))
    pdf_canvas.drawRightString(right, 8 * mm, tr("Page {page} of {pages}", page=page_number, pages=page_count))
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
        "ink": colors.HexColor("#0f172a"),
        "muted": colors.HexColor("#64748b"),
        "border": colors.HexColor("#e2e8f0"),
        "header_fill": colors.HexColor("#f1f5f9"),
        "zebra": colors.HexColor("#f8fafc"),
        "warning_fill": colors.HexColor("#fffbeb"),
        "warning_border": colors.HexColor("#f59e0b"),
        "warning_text": colors.HexColor("#92400e"),
    }


# Renderers escape * _ ` | for markdown, never backslashes: a doubled
# backslash in text is a UNC path (\\server\share) and must stay as written.
_MARKDOWN_ESCAPE = re.compile(r"\\([*_`|])")


def _pdf_inline(value: str) -> str:
    """Markdown inline -> ReportLab markup. Code spans are kept verbatim; the
    rest has markdown escapes removed so `\\_` prints as `_`."""
    source = _sanitize_text(value)
    parts: list[str] = []
    position = 0
    for match in _INLINE_CODE.finditer(source):
        parts.append(_pdf_inline_text(source[position : match.start()]))
        parts.append(f"<font name='Courier' size='7.8'>{escape(match.group(1))}</font>")
        position = match.end()
    parts.append(_pdf_inline_text(source[position:]))
    return "".join(parts).replace("\n", "<br/>")


def _pdf_inline_text(text: str) -> str:
    text = _MARKDOWN_LINK.sub(lambda match: match.group(1), text)
    placeholders: list[str] = []

    def bold(match: re.Match[str]) -> str:
        placeholders.append(match.group(2))
        return f"\x00{len(placeholders) - 1}\x00"

    text = _MARKDOWN_EMPHASIS.sub(bold, text)
    text = escape(_MARKDOWN_ESCAPE.sub(r"\1", text))
    return re.sub(r"\x00(\d+)\x00", lambda match: "<b>" + escape(_MARKDOWN_ESCAPE.sub(r"\1", placeholders[int(match.group(1))])) + "</b>", text)


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
        "language": normalize_language((report.metadata_json or {}).get("language")),
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
    # detection_rows is a capped sample kept only for the "top detections"
    # listing below. The breakdowns must NOT be derived from it: presenting a
    # by_severity that sums to the sample size next to a true total_detections
    # produces a report whose own numbers contradict each other, which in a
    # forensic deliverable is worse than omitting the breakdown. Aggregate
    # those over every row in the database instead.
    detection_rows = (
        db.query(DetectionResult)
        .filter(DetectionResult.evidence_id == evidence.id)
        .order_by(DetectionResult.created_at.desc())
        .limit(100)
        .all()
        if include_detections
        else []
    )
    severity_counts: dict[str, int] = {}
    rule_counts: dict[str, int] = {}
    if include_detections:
        for severity, count in (
            db.query(DetectionResult.severity, func.count(DetectionResult.id))
            .filter(DetectionResult.evidence_id == evidence.id)
            .group_by(DetectionResult.severity)
            .all()
        ):
            key = str(severity or "unknown").strip().lower() or "unknown"
            severity_counts[key] = severity_counts.get(key, 0) + int(count or 0)
        for rule_name, count in (
            db.query(DetectionResult.rule_name, func.count(DetectionResult.id))
            .filter(DetectionResult.evidence_id == evidence.id)
            .group_by(DetectionResult.rule_name)
            .order_by(func.count(DetectionResult.id).desc())
            .limit(10)
            .all()
        ):
            rule_counts[str(rule_name or "unknown").strip() or "unknown"] = int(count or 0)
    detections_summary = {
        "total_detections": total_detections,
        "by_severity": dict(sorted(severity_counts.items())),
        "by_rule": rule_counts,
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


_FINDING_STATUSES_AWAITING_REVIEW = {"draft", "review", "new", "triaged", "investigating"}


def _count_findings_pending_review(db: Session, case_id: str, filters: dict[str, Any], included: list[Finding]) -> int:
    """Findings that would enter the report once reviewed: same filters except
    status, and a status that is still open (not dismissed or closed)."""
    open_filters = {**filters, "include_statuses": sorted(_FINDING_STATUSES_AWAITING_REVIEW)}
    included_ids = {finding.id for finding in included}
    return sum(1 for finding in _filtered_findings(db, case_id, open_filters) if finding.id not in included_ids)


def _case_evidence_rows(db: Session, case_id: str) -> dict[str, Evidence]:
    rows = db.query(Evidence).filter(Evidence.case_id == case_id).all()
    return {str(row.id): row for row in rows if getattr(row, "id", None)}


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


def _filtered_detections(db: Session, case_id: str, filters: dict[str, Any]) -> tuple[list[DetectionResult], int]:
    if not filters.get("include_detections", True):
        return [], 0
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
    # Rows are ordered newest-first, so the cap keeps the most recent ones.
    # The caller needs the real match count too: reporting the capped length as
    # "detections matched" puts a number in a forensic deliverable that is
    # indistinguishable from the true one and silently understates the case.
    return output[:REPORT_SOURCE_LIMIT], len(output)


def _filtered_markings(db: Session, case_id: str, filters: dict[str, Any]) -> tuple[list[EventMarking], int]:
    if not filters.get("include_marked_events", True):
        return [], 0
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
    matched_total = len(output)
    if matched_total > REPORT_SOURCE_LIMIT:
        # Rows arrive oldest-first, so slicing here would keep the oldest
        # markings and drop everything the analyst marked most recently.
        output = output[-REPORT_SOURCE_LIMIT:]
    return output, matched_total


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
                "title": f"{_humanize(marking.artifact_type or 'event')} marked {marking.status}" + (f" on {marking.host}" if marking.host else ""),
                "host": marking.host,
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
    result = get_command_history(case_id, params, db=db)
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
    # get_command_history caps its own candidate scan and says so in its
    # warnings. Returning only the story warnings dropped that on the floor, so
    # the report published a command count with no hint that the underlying
    # scan had been truncated.
    source_warnings = [str(item) for item in (result.get("warnings") or []) if str(item).strip()]
    facets = dict(result.get("facets") or {})
    return {
        "commands": included,
        "stories": stories,
        "warnings": [*source_warnings, *story_warnings],
        "counts": {
            "command_history_matched": int(result.get("total") or len(all_commands)),
            # Counted over the commands actually scanned, which get_command_history
            # may have capped -- see the propagated warnings above.
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
        # Fetch the widest page: health and housekeeping records are dropped
        # below, and the report should still fill max_events with real ones.
        "page_size": 100,
        "sort": "risk_desc",
        "include_facets": False,
    }
    total, rows, warnings, _facets = search_events_v2(case_id, params, db=db)
    reportable = [row for row in rows if _is_reportable_defender_event(row)]
    rows = reportable[:max_events]
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
            # Reportable records among the 100 highest-risk Defender events.
            "defender_events_matched": len(reportable),
            "defender_high_severity": high_severity,
            "defender_failed_actions": failed_actions,
        },
    }


# Defender records that say something about the incident: detections and
# remediation, and changes to the protection itself. Health reports (1150/1151),
# history clean-up (1013) and signature updates (2000-2002) are routine.
_DEFENDER_REPORTABLE_EVENT_IDS = {
    "1006", "1007", "1008", "1015", "1116", "1117", "1118", "1119", "1120",
    "5001", "5004", "5007", "5008", "5010", "5011", "5012", "5013",
}


def _is_reportable_defender_event(row: dict[str, Any]) -> bool:
    raw = row.get("raw") if isinstance(row.get("raw"), dict) else {}
    defender = raw.get("defender") if isinstance(raw.get("defender"), dict) else {}
    threat = raw.get("threat") if isinstance(raw.get("threat"), dict) else {}
    if threat.get("name") or defender.get("threat_name"):
        return True
    windows = raw.get("windows") if isinstance(raw.get("windows"), dict) else {}
    event_id = str(defender.get("event_id") or windows.get("event_id") or "").strip()
    return event_id in _DEFENDER_REPORTABLE_EVENT_IDS


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
    # A saved draft can predate the analyst dismissing a finding; the report
    # must not present a false positive as part of the incident story.
    dismissed = {
        finding.id
        for finding in db.query(Finding).filter(Finding.case_id == case_id).all()
        if str(finding.status.value if hasattr(finding.status, "value") else finding.status).lower() in {"false_positive", "archived", "suppressed"}
    }
    items = [item for item in items if not item.get("finding_id") or str(item.get("finding_id")) not in dismissed]
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
        for item in finding.timeline or []:
            if item.get("event_id"):
                remember("event_id", item["event_id"], source=source, timestamp=item.get("timestamp"))

    # The events each finding rests on carry the hard indicators (hashes,
    # binaries, destinations) the finding's summary fields often leave out.
    finding_events: dict[str, Finding] = {}
    for finding in findings:
        event_ids = [*(finding.related_event_ids or []), *(str(item.get("event_id") or "") for item in finding.timeline or [])]
        for event_id in event_ids:
            if event_id and not str(event_id).startswith("memory:") and len(finding_events) < _IOC_EVENT_LIMIT:
                finding_events.setdefault(str(event_id), finding)
    for event_id, event in _fetch_events_by_ids(case_id, list(finding_events)).items():
        finding = finding_events[event_id]
        _extract_iocs_from_event(event, remember, f"finding:{finding.title}", event.get("@timestamp") or finding.time_start)

    for bookmark in bookmarks:
        source = f"bookmark:{bookmark.title}"
        remember("event_id", bookmark.event_id, source=source, timestamp=bookmark.timestamp, notes=bookmark.note)
        event = fetch_event_by_id(case_id, bookmark.event_id, event_index=None, opensearch_id=bookmark.event_id) or fetch_event_by_id(case_id, bookmark.event_id, event_index=None, opensearch_id=None) or {}
        _extract_iocs_from_event(event, remember, source, bookmark.timestamp)

    result = list(rows.values())
    result.sort(key=lambda item: (item["type"], item["value"]))
    return result


_IOC_EVENT_LIMIT = 300
_HASH_PAIR = re.compile(r"(MD5|SHA1|SHA256)=([0-9A-Fa-f]{32,64})")


def _fetch_events_by_ids(case_id: str, event_ids: list[str]) -> dict[str, dict[str, Any]]:
    """Events by id in one query; empty when the index cannot be reached."""
    if not event_ids:
        return {}
    try:
        result = search_documents(get_events_index(case_id), {"size": len(event_ids), "query": {"ids": {"values": event_ids}}})
    except Exception:  # noqa: BLE001
        return {}
    events: dict[str, dict[str, Any]] = {}
    for hit in (result.get("hits") or {}).get("hits") or []:
        events[str(hit.get("_id"))] = dict(hit.get("_source") or {})
    return events


def _event_hashes(event: dict[str, Any]) -> list[tuple[str, str]]:
    """(algorithm, value) pairs the event records for its file or image."""
    pairs: list[tuple[str, str]] = []
    process = event.get("process") if isinstance(event.get("process"), dict) else {}
    for source in (process.get("hashes"), event.get("hash")):
        if isinstance(source, dict):
            pairs.extend((algorithm.upper(), str(value)) for algorithm, value in source.items() if algorithm.lower() in {"md5", "sha1", "sha256"} and value)
    event_data = ((event.get("windows") or {}).get("event_data") or {}) if isinstance(event.get("windows"), dict) else {}
    for key in ("Hashes", "Hash"):
        pairs.extend((algorithm.upper(), value) for algorithm, value in _HASH_PAIR.findall(str(event_data.get(key) or "")))
    seen: set[str] = set()
    return [(algorithm, value.lower()) for algorithm, value in pairs if not (value.lower() in seen or seen.add(value.lower()))]


def _extract_iocs_from_event(event: dict[str, Any], remember, source: str, timestamp: Any) -> None:
    file_data = event.get("file") or {}
    if isinstance(file_data, dict):
        for key in ("path", "sha1", "sha256", "md5"):
            value = file_data.get(key)
            if not value or (key == "path" and BENIGN_SYSTEM_PATH.search(str(value))):
                continue
            remember("hash" if key in {"sha1", "sha256", "md5"} else "file", value, source=source, timestamp=timestamp)
    process_data = event.get("process") or {}
    hashed_path = ""
    if isinstance(process_data, dict):
        path = str(process_data.get("executable") or process_data.get("path") or "")
        if path and not BENIGN_SYSTEM_PATH.search(path):
            remember("file", path, source=source, timestamp=timestamp)
            hashed_path = path
    event_data = ((event.get("windows") or {}).get("event_data") or {}) if isinstance(event.get("windows"), dict) else {}
    hashed_path = hashed_path or str(event_data.get("TargetFilename") or "")
    # A hash names a binary; one of a system binary is not an indicator.
    if hashed_path and not BENIGN_SYSTEM_PATH.search(hashed_path):
        for algorithm, value in _event_hashes(event):
            remember("hash", value, source=source, timestamp=timestamp, notes=f"{algorithm} of {hashed_path}")
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
        # Events indexed before the PowerShell parser fix can carry a script
        # argument as target_path with no URL; only a real download counts.
        if download_data.get("target_path") and download_data.get("url"):
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


def _render_executive_summary(
    case: Case,
    context: dict[str, Any],
    findings: list[Finding],
    report: CaseReport,
    *,
    pending_review: int = 0,
) -> str:
    note = _narrative((report.analyst_notes or {}).get("executive_summary"))
    evidences = context.get("evidences") or []
    host_names = _dedupe([_context_host_name(host) for host in context.get("hosts") or []])
    host_names = [name for name in host_names if name and name != "unknown"]
    lines: list[str] = []
    if note:
        lines.extend([note, ""])
    hosts_clause = ""
    if host_names:
        shown = ", ".join(f"**{_escape_md(name)}**" for name in host_names[:5])
        more = f" +{len(host_names) - 5}" if len(host_names) > 5 else ""
        template = " from {count} host ({names})" if len(host_names) == 1 else " from {count} hosts ({names})"
        hosts_clause = tr(template, count=len(host_names), names=f"{shown}{more}")
    evidence_text = tr("{count} evidence item" if len(evidences) == 1 else "{count} evidence items", count=f"{len(evidences):,}")
    lines.append(tr(
        "This report covers case **{case}**. {evidence}{hosts} {verb} processed and {events} events were indexed.",
        case=_escape_md(case.name), evidence=evidence_text, hosts=hosts_clause, verb="was" if len(evidences) == 1 else "were",
        events=f"{int(context['summary']['events_indexed']):,}",
    ))
    lines.append("")
    if findings:
        by_severity = Counter(_sev(finding) for finding in findings)
        breakdown = ", ".join(f"{by_severity[level]} {tr(level)}" for level in ("critical", "high", "medium", "low", "info") if by_severity.get(level))
        template = "**{count} finding** is reported ({breakdown})." if len(findings) == 1 else "**{count} findings** are reported ({breakdown})."
        lines.append(tr(template, count=len(findings), breakdown=breakdown))
    else:
        lines.append(tr("No findings are included in this report."))
    if pending_review:
        lines.append(tr(
            "{count} further finding is still awaiting analyst review and not included; confirm or dismiss it in Findings before issuing the report."
            if pending_review == 1 else
            "{count} further findings are still awaiting analyst review and not included; confirm or dismiss them in Findings before issuing the report.",
            count=pending_review,
        ))
    if findings:
        lines.extend(["", tr("Key findings:")])
        for finding in findings[:5]:
            lines.append(f"- **{_escape_md(finding.title)}**: " + tr("{severity} severity, risk {risk}", severity=tr(_sev(finding)), risk=int(finding.risk_score or 0)))
    return "\n".join(lines).strip()


def _render_scope(
    case: Case,
    context: dict[str, Any],
    report: CaseReport,
    *,
    evidence_names: dict[str, str] | None = None,
    coverage_notes: list[str] | None = None,
) -> str:
    filters = report.filters or {}
    time_range = report.time_range or {}
    period_from = time_range.get("from") or filters.get("time_from")
    period_to = time_range.get("to") or filters.get("time_to")
    if period_from or period_to:
        period = f"{_fmt_ts(period_from) or 'beginning'} to {_fmt_ts(period_to) or 'latest'} UTC"
    else:
        period = tr("All available data")
    evidence_filter = str(filters.get("evidence_id") or "").strip()
    statuses = ", ".join(str(item) for item in (filters.get("include_statuses") or [])) or "any status"
    rows = [
        ["Item", "Value"],
        [tr("Case"), str(case.name or "-")],
        [tr("Case ID"), _code(case.id)],
        [tr("Period"), period],
        [tr("Hosts"), str(filters.get("host") or tr("All hosts"))],
        [tr("Evidence"), (evidence_names or {}).get(evidence_filter, evidence_filter) if evidence_filter else tr("All evidence")],
        [tr("Timezone"), str(case.timezone or "UTC")],
        [tr("Findings included"), tr("{status}; minimum severity {severity}", status=statuses, severity=tr(str(filters.get("min_severity") or "medium")))],
    ]
    body = _markdown_table(rows)
    if coverage_notes:
        body += "\n\n" + tr("Coverage notes:") + "\n" + "\n".join(f"- {_sanitize_text(note)}" for note in coverage_notes)
    return body


_MEMORY_ANALYSIS_TITLES = {
    "find_evil": "Find Evil",
    "processes": "Processes",
    "shell_history": "Shell history",
    "modules": "Process modules",
    "handles": "Process handles",
    "kernel_modules": "Kernel modules",
    "drivers": "Drivers",
    "suspicious_regions": "Suspicious memory regions",
    "network": "Network connections",
    "files": "Files",
}
_MEMORY_STATE_LABELS = {
    "analyzed_with_results": "completed",
    "analyzed_empty": "completed, nothing found",
    "partial": "partly completed",
    "failed": "failed",
    "latest_attempt_failed": "latest run failed",
    "running": "running",
    "queued": "queued",
}


def _build_memory_report_context(db: Session, case_id: str, filters: dict[str, Any]) -> list[dict[str, Any]]:
    if not settings.memory_enabled:
        return []
    from app.services.memory.report_section import build_memory_report_context

    host = str(filters.get("host") or "").strip()
    expanded_hosts = _expanded_report_hosts(db, case_id, host) if host else set()
    return build_memory_report_context(
        db,
        case_id,
        evidence_id=str(filters.get("evidence_id") or "").strip() or None,
        host_matches=(lambda candidate: _host_matches_report_filter(candidate, expanded_hosts)) if expanded_hosts else None,
    )


LATERAL_REPORT_ROWS = 60


def _build_lateral_movement_report_context(db: Session, case_id: str, filters: dict[str, Any]) -> dict[str, Any]:
    """Remote logons between machines for the report: the Lateral Movement
    view without routine traffic (machine, anonymous and built-in accounts),
    limited to the report's host filter when one is set."""
    from app.services.lateral_movement import get_lateral_movement

    try:
        edges = get_lateral_movement(db, case_id).get("edges") or []
    except Exception:  # noqa: BLE001 -- the report renders without this section
        logger.warning("report: lateral movement unavailable", exc_info=True)
        return {"edges": [], "routine": 0, "warnings": ["Lateral movement could not be read; this section is incomplete."]}
    host = str(filters.get("host") or "").strip()
    if host:
        expanded_hosts = _expanded_report_hosts(db, case_id, host)
        edges = [
            edge for edge in edges
            if any(_host_matches_report_filter(name, expanded_hosts) for name in [edge.get("target_host"), *(edge.get("source_hosts") or [])])
        ]
    routine = [edge for edge in edges if edge.get("routine_reason")]
    return {"edges": [edge for edge in edges if not edge.get("routine_reason")], "routine": len(routine), "warnings": []}


def _lateral_account(edge: dict[str, Any]) -> str:
    user = str(edge.get("user") or "").strip()
    domain = str(edge.get("domain") or "").strip()
    return f"{domain}\\{user}" if domain and user else user or "-"


def _render_lateral_movement_section(report: dict[str, Any]) -> str:
    edges = report.get("edges") or []
    if not edges:
        return tr("No remote logons between machines were found in the authentication logs.")
    parts = [tr(
        "Remote logons between machines, from the authentication logs of every host, in the order they began. "
        "A source is named as a case host only when its address was observed on that host. "
        "These are authentications, not proof of intent: read them with the findings and the timeline."
    )]
    if report.get("routine"):
        parts.append(tr("{count} routine connections (machine, anonymous and built-in accounts) are left out.", count=report["routine"]))
    rows = [["First seen (UTC)", "Last seen (UTC)", "From", "To", "Account", "Method", "Result"]]
    for edge in edges[:LATERAL_REPORT_ROWS]:
        source = " / ".join(edge.get("source_hosts") or []) or tr("not a case host")
        source = f"{source} ({edge.get('source_ip')})"
        notes = []
        if edge.get("workstation_mismatch"):
            notes.append(tr("workstation name: {names}", names=", ".join(edge.get("source_workstations") or [])))
        if edge.get("source_ambiguous"):
            notes.append(tr("address seen on several hosts"))
        if notes:
            source += f" [{'; '.join(notes)}]"
        result = []
        if edge.get("successes"):
            result.append(tr("{count} succeeded", count=edge["successes"]))
        if edge.get("failures"):
            result.append(tr("{count} failed", count=edge["failures"]))
        last = _fmt_ts(edge.get("last_seen"))
        rows.append([
            _fmt_ts(edge.get("first_seen")) or "-",
            last if last and last != _fmt_ts(edge.get("first_seen")) else "-",
            source,
            str(edge.get("target_host") or "-"),
            _lateral_account(edge),
            tr(str(edge.get("method") or "-")),
            ", ".join(result) or "-",
        ])
    parts.append(_markdown_table(rows))
    if len(edges) > LATERAL_REPORT_ROWS:
        parts.append(tr("{shown} of {total} connections are shown; the Lateral Movement view lists them all.", shown=LATERAL_REPORT_ROWS, total=len(edges)))
    return "\n\n".join(parts)


def _clip(value: str, limit: int) -> str:
    return value if len(value) <= limit else f"{value[:limit - 1]}…"


def _render_memory_section(entries: list[dict[str, Any]]) -> str:
    parts: list[str] = []
    for entry in entries:
        parts.append(f"### {_escape_md(str(entry.get('filename') or entry['evidence_id']))}")
        details = [["Field", "Value"], [tr("Host"), str(entry.get("host") or "unknown")]]
        if entry.get("system"):
            details.append([tr("System"), " ".join(str(part) for part in (entry["system"], f"({entry['architecture']})" if entry.get("architecture") else "") if part)])
        if entry.get("captured_at"):
            details.append([tr("Captured at (system time in the image, UTC)"), _fmt_ts(entry["captured_at"]) or str(entry["captured_at"])])
        if entry.get("format"):
            details.append([tr("Format"), _humanize(str(entry["format"]))])
        if entry.get("size_bytes"):
            details.append([tr("Size"), _human_bytes(int(entry["size_bytes"]))])
        details.append([tr("Findings linked to this image"), str(entry.get("findings_count") or 0)])
        parts.append(_markdown_table(details))
        analyses = [item for item in entry.get("analyses") or [] if item.get("family") not in {"system_info", "raw_observations"}]
        if analyses:
            rows = [["Analysis", "Result", "Items"]]
            for item in analyses:
                rows.append([
                    _MEMORY_ANALYSIS_TITLES.get(str(item.get("family")), item["title"]),
                    _MEMORY_STATE_LABELS.get(str(item["state"]), str(item["state"]).replace("_", " ")),
                    str(item.get("count") or 0),
                ])
            parts.append(_markdown_table(rows))
        else:
            parts.append("No analysis has been run on this image.")
        find_evil = entry.get("find_evil")
        if find_evil and find_evil.get("available"):
            counts = find_evil.get("indicator_counts") or {}
            parts.append(
                f"**Find Evil**: {sum(counts.values())} indicators in {find_evil['process_count']} processes "
                f"({counts.get('high', 0)} high, {counts.get('medium', 0)} medium, {counts.get('low', 0)} low priority). "
                f"Triage: {len(find_evil['marked_processes'])} marked suspicious or important, {find_evil['settled_count']} reviewed or not relevant, "
                f"{find_evil['unreviewed_count']} not reviewed. Indicators are leads for review, not verdicts."
            )
            if find_evil["marked_processes"]:
                rows = [["Process", "PID", "Mark", "Top priority", "Indicators", "Types", "Note"]]
                for process in find_evil["marked_processes"]:
                    rows.append([
                        str(process.get("process") or "not tied to a process"),
                        "-" if process.get("pid") is None else str(process["pid"]),
                        str(process["mark"]),
                        str(process.get("top_priority") or "-"),
                        str(process.get("indicator_count") or 0),
                        _clip(", ".join(process.get("indicator_types") or []), 160),
                        _clip(str(process.get("note") or "-"), 200),
                    ])
                parts.append(_markdown_table(rows))
            detections = find_evil.get("antivirus_detections") or []
            if detections:
                parts.append(tr("**Antivirus detections still in memory** ({count}): what the antivirus detected and when, recovered from the image even if the event logs were cleared.", count=len(detections)))
                rows = [[tr("Time (UTC)"), tr("Threat"), tr("Detected by"), tr("Target")]]
                for item in detections[:40]:
                    rows.append([
                        _fmt_ts(item.get("first_seen")) or "-",
                        str(item.get("threat") or "-"),
                        ", ".join(tr(source) for source in item.get("sources") or []) or "-",
                        f"{item.get('target_kind') or ''}: " + _clip(str(item.get("target") or ""), 220),
                    ])
                parts.append(_markdown_table(rows))
    return "\n\n".join(parts)


def _render_evidence(context: dict[str, Any], evidence_rows: dict[str, Evidence] | None = None) -> str:
    rows = [["Evidence", "Type", "Size", "SHA-256", "Host", "Events", "Parser errors", "Status"]]
    for evidence in context["evidences"]:
        row = (evidence_rows or {}).get(str(evidence.get("id") or ""))
        evidence_type = getattr(getattr(row, "evidence_type", None), "value", None) if row is not None else None
        size_bytes = getattr(row, "size_bytes", None) if row is not None else None
        sha256 = str(getattr(row, "sha256", "") or "") if row is not None else ""
        rows.append(
            [
                evidence["name"],
                _humanize(evidence_type) if evidence_type and evidence_type != "unknown" else _archive_label(str(evidence["name"])),
                _human_bytes(int(size_bytes)) if size_bytes else "-",
                _code(sha256) if sha256 else "-",
                evidence.get("detected_host") or "-",
                f"{int(evidence['events_indexed'] or 0):,}",
                str(evidence["parser_errors"]),
                _humanize(str(evidence["status"])),
            ]
        )
    return _markdown_table(_drop_empty_columns(rows, zero_is_empty={"Parser errors"}))


def _archive_label(name: str) -> str:
    # An archive whose content did not match one collection type (a bundle of
    # a collection, a memory image and a capture, say) is still an archive.
    lower = name.lower()
    for suffix in (".zip", ".7z", ".tar.gz", ".tgz", ".tar", ".rar"):
        if lower.endswith(suffix):
            return f"Archive ({suffix.lstrip('.')})"
    return "-"


def _context_host_name(host: dict[str, Any]) -> str:
    return str(host.get("host") or host.get("display_name") or host.get("canonical_name") or "unknown")


def _render_hosts(context: dict[str, Any], findings: list[Finding] | None = None) -> str:
    # Count the findings this report carries per host (by related_hosts), so the
    # table agrees with the Findings section instead of the host index counters.
    reported: Counter[str] = Counter()
    reported_high: Counter[str] = Counter()
    for finding in findings or []:
        for related in {normalize_host_alias(str(item)) for item in (finding.related_hosts or []) if str(item).strip()}:
            reported[related] += 1
            if _sev(finding) in {"high", "critical"}:
                reported_high[related] += 1
    rows = [[tr("Host"), "Role", "Events", "Findings", "High/critical", "First seen (UTC)", "Last seen (UTC)"]]
    for host in context["hosts"]:
        events_count = host.get("events_count", host.get("event_count", 0))
        name = _context_host_name(host)
        key = normalize_host_alias(name)
        rows.append([
            name,
            "primary" if host.get("is_primary") else "alias" if host.get("is_alias") else "host",
            f"{int(events_count or 0):,}",
            str(reported[key] if findings is not None else host.get("findings_count", 0)),
            str(reported_high[key] if findings is not None else host.get("high_risk_count", 0)),
            _fmt_ts(host.get("first_seen")) or "-",
            _fmt_ts(host.get("last_seen")) or "-",
        ])
    if len(rows) == 1:
        return "No hosts were attributed to the processed evidence."
    if all(row[1] == "host" for row in rows[1:]):
        rows = [[cell for index, cell in enumerate(row) if index != 1] for row in rows]
    body = _markdown_table(_drop_empty_columns(rows))
    candidates = context.get("host_candidates") or []
    if candidates:
        body += "\n\nPossible aliases / historical hostnames:\n"
        for item in candidates[:10]:
            body += f"\n- {_code(str(item.get('value') or 'unknown'))} · source {_code(str(item.get('source') or 'unknown'))} · confidence {_escape_md(str(item.get('confidence') or 'low'))}"
    return body


def _render_findings(findings: list[Finding]) -> str:
    if not findings:
        return "No findings selected for this report."
    lines: list[str] = []
    for index, finding in enumerate(findings, start=1):
        status = str(finding.status.value if hasattr(finding.status, "value") else finding.status)
        period = _fmt_ts(finding.time_start)
        if period and finding.time_end and _fmt_ts(finding.time_end) != period:
            period = f"{period} to {_fmt_ts(finding.time_end)}"
        lines.extend([f"### F{index}. {_escape_md(finding.title)}", ""])
        summary_rows = [
            ["Severity", "Risk", "Confidence", "Status", "Observed (UTC)"],
            [_sev(finding), str(int(finding.risk_score or 0)), _humanize(str(finding.confidence or "unknown")), _humanize(status), period or "-"],
        ]
        lines.append(_markdown_table(summary_rows))
        if finding.description:
            lines.extend(["", _narrative(finding.description)])
        if finding.reasons:
            lines.extend(["", tr("Why it matters:")])
            for reason in finding.reasons[:8]:
                lines.append(f"- {_sanitize_text(reason)}")
        related = []
        if finding.related_hosts:
            related.append([tr("Hosts"), ", ".join(_sanitize_text(str(item)) for item in finding.related_hosts[:5])])
        if finding.related_users:
            related.append([tr("Users"), ", ".join(_sanitize_text(str(item)) for item in finding.related_users[:5])])
        if finding.related_files:
            related.append([tr("Files"), ", ".join(_code(str(item)) for item in finding.related_files[:5])])
        if finding.related_domains:
            related.append([tr("Domains"), ", ".join(_code(str(item)) for item in finding.related_domains[:5])])
        if finding.related_ips:
            related.append([tr("IP addresses"), ", ".join(_code(str(item)) for item in finding.related_ips[:5])])
        if related:
            lines.extend(["", _markdown_table([["Related", "Values"], *related])])
        if finding.timeline:
            lines.extend(["", tr("Supporting events:")])
            for item in finding.timeline[:6]:
                lines.append(
                    f"- {_fmt_ts(item.get('timestamp')) or 'unknown time'} · {_humanize(str(item.get('event_type') or 'event'))} · {_sanitize_text(str(item.get('summary') or ''))}"
                )
        if finding.recommended_triage:
            lines.extend(["", tr("Recommended next steps:")])
            for item in finding.recommended_triage[:6]:
                lines.append(f"- {_sanitize_text(item)}")
        lines.append("")
    return "\n".join(lines).strip()


def _resolve_detection_event_times(case_id: str, detections: list[DetectionResult]) -> dict[str, str]:
    """Event time of detections that did not record it (built-in detections
    created before they stored matched_at), read from the matched events in
    one query. Read-only; on any search failure the times stay unknown."""
    missing = _dedupe([row.opensearch_id or row.event_id for row in detections if not row.matched_at and (row.opensearch_id or row.event_id)])
    if not missing:
        return {}
    try:
        result = search_documents(
            get_events_index(case_id),
            {"size": len(missing), "_source": ["@timestamp", "timestamp"], "query": {"ids": {"values": missing}}},
        )
    except Exception:  # noqa: BLE001
        return {}
    times = {}
    for hit in (result.get("hits") or {}).get("hits") or []:
        source = hit.get("_source") or {}
        value = source.get("@timestamp") or source.get("timestamp")
        if value:
            times[str(hit.get("_id"))] = str(value)
    return times


def _render_mitre(findings: list[Finding]) -> str:
    """Techniques of the reported findings, filed by tactic in kill-chain order,
    each pointing back to its findings (F1, F2... as numbered in Findings)."""
    rows: dict[tuple[str, str], list[str]] = {}
    for index, finding in enumerate(findings, start=1):
        techniques = tagged_techniques([*(finding.mitre or []), *(finding.tags or [])])
        if not techniques:
            continue
        phase, _confidence = _finding_incident_phase(finding, f"{finding.title} {finding.description or ''}")
        for technique in techniques:
            tactic = tactic_for(technique, phase) or "other"
            rows.setdefault((tactic, technique), []).append(f"F{index}")
    if not rows:
        return ""
    order = {tactic: position for position, tactic in enumerate(TACTIC_ORDER)}
    table = [["Tactic", "Technique", "Findings"]]
    previous = None
    for (tactic, technique), refs in sorted(rows.items(), key=lambda item: (order.get(item[0][0], len(order)), item[0][1])):
        table.append([tr(_humanize(tactic)) if tactic != previous else "", technique_label(technique), ", ".join(refs)])
        previous = tactic
    tactics = len({tactic for tactic, _ in rows})
    techniques_text = _plural(len(rows), "technique") if current_language() == "en" else f"{len(rows)} técnica{'s' if len(rows) != 1 else ''}"
    tactics_text = _plural(tactics, "tactic") if current_language() == "en" else f"{tactics} táctica{'s' if tactics != 1 else ''}"
    return tr("{techniques} across {tactics}, from the MITRE tags of the reported findings.", techniques=techniques_text, tactics=tactics_text) + "\n\n" + _markdown_table(table)


def _render_detections(detections: list[DetectionResult], total: int | None = None, *, event_times: dict[str, str] | None = None) -> str:
    if not detections:
        return "No detections matched the report filters."
    total = max(int(total or 0), len(detections))
    by_severity: Counter[str] = Counter()
    unreviewed = 0
    rules: dict[str, dict[str, Any]] = {}
    for detection in detections:
        severity = str(detection.severity or detection.rule_level or "unknown").lower()
        by_severity[severity] += 1
        if str(detection.status or "").lower() in {"", "new"}:
            unreviewed += 1
        name = str(detection.rule_title or detection.rule_name or "unknown")
        # matched_at is the matched event's own time. created_at is when the
        # rule ran, which is not evidence time, so it is never substituted.
        when = _iso(detection.matched_at) or (event_times or {}).get(str(detection.opensearch_id or detection.event_id or "")) or ""
        entry = rules.setdefault(name, {"count": 0, "severity": severity, "hosts": set(), "first": when, "last": when})
        entry["count"] += 1
        if SEVERITY_ORDER.get(severity, 0) > SEVERITY_ORDER.get(entry["severity"], 0):
            entry["severity"] = severity
        if detection.host_name:
            entry["hosts"].add(str(detection.host_name))
        if when and (not entry["first"] or when < entry["first"]):
            entry["first"] = when
        if when and when > entry["last"]:
            entry["last"] = when
    breakdown = ", ".join(f"{by_severity[level]} {level}" for level in ("critical", "high", "medium", "low", "info", "unknown") if by_severity.get(level))
    scope = f"{total:,} rule matches" if total == len(detections) else f"{total:,} rule matches; the {len(detections):,} most recent are summarised"
    lines = [f"{scope} ({breakdown})."]
    if unreviewed:
        lines.append(tr(
            "These are automated rule matches; {count} of them have not been reviewed by an analyst and should be read as leads, not conclusions.",
            count=f"{unreviewed:,}",
        ))
    table = [["Rule", "Severity", "Matches", "Hosts", "First event (UTC)", "Last event (UTC)"]]
    ordered = sorted(rules.items(), key=lambda item: (-SEVERITY_ORDER.get(item[1]["severity"], 0), -item[1]["count"], item[0]))
    for name, entry in ordered[:20]:
        hosts = sorted(entry["hosts"])
        table.append([
            _sanitize_text(name),
            entry["severity"],
            f"{entry['count']:,}",
            ", ".join(hosts[:3]) + (f" +{len(hosts) - 3}" if len(hosts) > 3 else "") if hosts else "-",
            _fmt_ts(entry["first"]) or "-",
            _fmt_ts(entry["last"]) or "-",
        ])
    lines.extend(["", _markdown_table(_drop_empty_columns(table))])
    if len(ordered) > 20:
        lines.extend(["", f"{len(ordered) - 20} further rules with fewer matches are not listed."])
    return "\n".join(lines).strip()


def _render_timeline(entries: list[dict[str, Any]]) -> str:
    if not entries:
        return "No key events selected for the report."
    rows = [["Time (UTC)", "Host", "Phase", "Event", "Details", "Importance"]]
    for entry in entries:
        rows.append(
            [
                _fmt_ts(entry.get("timestamp")) or "unknown",
                str(entry.get("host") or "-"),
                tr(_humanize(str(entry.get("phase") or "-"))) if entry.get("phase") not in {None, "", "unknown"} else "-",
                str(entry.get("title") or ""),
                _clip(str(entry.get("note") or entry.get("summary") or "-"), 400),
                str(entry.get("importance") or "-"),
            ]
        )
    return _markdown_table(_drop_empty_columns(rows))


def _merge_incident_items(entries: list[dict[str, Any]], incident_items: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Fold the accepted Incident Timeline into the report timeline.

    Rows already in the timeline (key events, marked events) take the item's
    host and phase. Accepted items of other sources (a command, a memory
    observation the analyst accepted) are added. Finding rows are left out:
    every finding has its own block in Findings.
    """
    accepted = [item for item in incident_items if str(item.get("status") or "accepted") == "accepted"]
    by_event = {str(item.get("event_id")): item for item in accepted if item.get("event_id")}
    merged = []
    seen_events: set[str] = set()
    for entry in entries:
        item = by_event.get(str(entry.get("event_id") or ""))
        enriched = dict(entry)
        if item:
            enriched.setdefault("host", item.get("host"))
            enriched["host"] = enriched.get("host") or item.get("host")
            enriched["phase"] = item.get("phase")
        merged.append(enriched)
        if entry.get("event_id"):
            seen_events.add(str(entry["event_id"]))
    for item in accepted:
        if item.get("source") in {"finding", "marked_event"} or str(item.get("event_id") or "") in seen_events:
            continue
        merged.append({
            "timestamp": item.get("timestamp"),
            "host": item.get("host"),
            "phase": item.get("phase"),
            "category": item.get("source") or "incident_timeline",
            "importance": item.get("severity") or "-",
            "title": item.get("title") or "Timeline item",
            "summary": item.get("summary") or "",
            "note": item.get("notes") or "",
            "event_id": item.get("event_id"),
        })
    merged.sort(key=lambda item: _safe_dt(item.get("timestamp")) or "~")
    return merged


def _render_incident_timeline_section(case_id: str, items: list[dict[str, Any]]) -> str:
    accepted = [item for item in items if str(item.get("status") or "accepted") == "accepted"]
    if not accepted:
        return "No incident timeline items were generated."
    accepted.sort(key=lambda item: (_safe_dt(item.get("timestamp")) or "~", str(item.get("host") or "")))
    rows = [["Time (UTC)", "Host", "Phase", "Event", "Source"]]
    for item in accepted:
        title = str(item.get("title") or "Timeline item")
        summary = str(item.get("summary") or "").strip()
        event = f"{title}: {summary}" if summary and summary not in title else title
        rows.append([
            _fmt_ts(item.get("timestamp")) or "unknown",
            str(item.get("host") or "-"),
            tr(_humanize(str(item.get("phase") or "unknown"))),
            _clip(event, 300),
            str(item.get("provenance_badge") or _humanize(str(item.get("source") or "-"))),
        ])
    return _markdown_table(_drop_empty_columns(rows))


def _execution_trees(db: Session, case: Case, findings: list[Finding]) -> dict[str, dict[str, Any] | None]:
    """The process tree behind each finding picked for Process Chains."""
    if not findings:
        return {}
    from app.services.report_execution_diagram import build_execution_tree

    evidences = db.query(Evidence).filter(Evidence.case_id == case.id).all()
    trees: dict[str, dict[str, Any] | None] = {}
    for finding in findings:
        try:
            trees[str(finding.id)] = build_execution_tree(db, case, evidences, finding)
        except Exception:  # noqa: BLE001 -- the section keeps its text without the diagram
            logger.warning("report: execution diagram for finding %s failed", finding.id, exc_info=True)
            trees[str(finding.id)] = None
    return trees


def _render_process_chains(findings: list[Finding], trees: dict[str, dict[str, Any] | None] | None = None) -> str:
    from app.services.report_execution_diagram import MARKER, render_tree_text

    if not findings:
        return "No process chains selected or available."
    lines = []
    for finding in findings:
        lines.extend([f"### {_escape_md(finding.title)}", "", f"- Risk: {int(finding.risk_score or 0)}"])
        if finding.reasons:
            lines.append("- Why it matters: " + "; ".join(_sanitize_text(str(item)) for item in finding.reasons[:6]))
        tree = (trees or {}).get(str(finding.id))
        if tree:
            lines.extend(["", tr("Execution tree: the process this finding points to, what started it and what it started."), ""])
            lines.extend([MARKER.format(key=finding.id), "```text", render_tree_text(tree), "```"])
            if tree.get("truncated"):
                lines.append(tr("The tree is cut at {count} processes or three levels; Execution Stories shows the rest.", count=len(tree["nodes"])))
            if not tree.get("exact"):
                lines.append(tr("Some parent/child links are inferred (PID and time), not recorded identifiers."))
        else:
            if trees is not None:
                lines.append("- " + tr("No process-creation record was found for this finding's events, so no execution tree is drawn."))
            for item in (finding.timeline or [])[:4]:
                lines.append(f"- {_fmt_ts(item.get('timestamp')) or 'unknown time'} · {_sanitize_text(str(item.get('summary') or ''))}")
        lines.append("")
    return "\n".join(lines).strip()


def _command_dedupe_key(command: dict[str, Any]) -> tuple[str, str, str]:
    text = re.sub(r"\s+", " ", str(command.get("command") or "")).strip().strip('"').lower()
    return (str(command.get("host") or "").lower(), (_iso(command.get("timestamp")) or "")[:19], text)


def _merge_duplicate_commands(commands: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Collapse one execution seen by several sources (Sysmon, 4688, memory...)
    into a single entry that lists every source, keeping the richest record."""
    merged: dict[tuple[str, str, str], dict[str, Any]] = {}
    order: list[tuple[str, str, str]] = []
    for command in commands:
        key = _command_dedupe_key(command)
        sources = _command_sources(command)
        if key not in merged:
            entry = dict(command)
            entry["_sources"] = sources
            merged[key] = entry
            order.append(key)
            continue
        entry = merged[key]
        entry["_sources"] = _dedupe([*entry["_sources"], *sources])
        if _command_richness(command) > _command_richness(entry):
            keep_sources, keep_markings = entry["_sources"], entry.get("markings") or []
            entry.clear()
            entry.update(command)
            entry["_sources"] = keep_sources
            entry["markings"] = keep_markings
        entry["markings"] = _dedupe_dicts([*(entry.get("markings") or []), *(command.get("markings") or [])])
        entry["risk_score"] = max(int(entry.get("risk_score") or 0), int(command.get("risk_score") or 0))
        entry["risk_reasons"] = _dedupe([*(entry.get("risk_reasons") or []), *(command.get("risk_reasons") or [])])
    return [merged[key] for key in order]


def _command_sources(command: dict[str, Any]) -> list[str]:
    supporting = [item for item in (command.get("supporting_events") or []) if isinstance(item, dict)]
    return _dedupe([str(item.get("source_type") or "") for item in supporting] or [str(command.get("source_type") or "unknown")])


def _command_richness(command: dict[str, Any]) -> int:
    process = command.get("process") if isinstance(command.get("process"), dict) else {}
    parent = command.get("parent_process") if isinstance(command.get("parent_process"), dict) else {}
    return sum(1 for value in (process.get("pid"), process.get("name"), parent.get("pid"), parent.get("name"), command.get("user"), command.get("supporting_events")) if value)


def _dedupe_dicts(items: list[Any]) -> list[dict[str, Any]]:
    seen: set[str] = set()
    output: list[dict[str, Any]] = []
    for item in items:
        if not isinstance(item, dict):
            continue
        key = str(item.get("id") or json.dumps(item, sort_keys=True, default=str))
        if key not in seen:
            seen.add(key)
            output.append(item)
    return output


def _process_label(process: dict[str, Any]) -> str:
    name = str(process.get("name") or process.get("executable") or "").strip()
    pid = process.get("pid")
    if not name and pid in {None, ""}:
        return ""
    return f"{name or 'unknown'} (PID {pid})" if pid not in {None, ""} else name


def _render_command_history_section(commands: list[dict[str, Any]], stories: list[dict[str, Any]]) -> str:
    if not commands:
        return "No command history matched current filters."
    story_by_command_id = {str(item.get("command_id") or ""): dict(item.get("story") or {}) for item in stories}
    merged = _merge_duplicate_commands(commands)
    lines = []
    if len(merged) < len(commands):
        lines.append(
            f"{_plural(len(merged), 'distinct command')} ({len(commands)} records; executions seen by several sources are merged)."
        )
    else:
        lines.append(f"{_plural(len(merged), 'command')} included.")
    overview = [["Time (UTC)", "Host", "User", "Process", "Command", "Risk"]]
    for command in merged:
        process = command.get("process") if isinstance(command.get("process"), dict) else {}
        overview.append([
            _fmt_ts(command.get("timestamp")) or "unknown",
            str(command.get("host") or "-"),
            str(command.get("user") or "-"),
            _process_label(process) or str(command.get("launcher") or "-"),
            _code(_clip(str(command.get("command") or "-"), 220)),
            str(int(command.get("risk_score") or 0)),
        ])
    lines.extend(["", _markdown_table(_drop_empty_columns(overview)), "", "#### " + tr("Command details"), ""])
    for command in merged:
        process = command.get("process") if isinstance(command.get("process"), dict) else {}
        parent = command.get("parent_process") if isinstance(command.get("parent_process"), dict) else {}
        markings = [item for item in (command.get("markings") or []) if isinstance(item, dict)]
        status_label = ", ".join(_dedupe([str(item.get("status") or "") for item in markings]))
        notes = "; ".join(_dedupe([str(item.get("note") or "") for item in markings]))
        reasons = "; ".join(_sanitize_text(str(item)) for item in (command.get("risk_reasons") or [])[:6])
        family = str(command.get("shell_family") or command.get("shell") or "unknown")
        launcher = str(command.get("launcher") or (process.get("name") or process.get("executable") or "unknown"))
        chain = " → ".join(label for label in (_process_label(parent), _process_label(process)) if label)
        heading_process = _process_label(process) or launcher
        lines.extend([f"##### {_fmt_ts(command.get('timestamp')) or 'unknown time'} UTC · {_escape_md(str(command.get('host') or '-'))} · {_escape_md(heading_process)}", ""])
        lines.append(f"- {tr('Command')}: {_code(_clip(str(command.get('command') or '-'), 600))}")
        if parent and chain:
            lines.append(f"- {tr('Process chain')}: {_escape_md(chain)}")
        if command.get("script"):
            lines.append(f"- {tr('Script')}: {_code(command['script'])}")
        if command.get("user"):
            lines.append(f"- {tr('User')}: {_code(str(command.get('user')))}")
        lines.append(f"- {tr('Family')}: {_code(family)} · {tr('Launcher')}: {_code(launcher)}")
        lines.append(f"- {tr('Seen in')}: {', '.join(_humanize(source) for source in command.get('_sources') or ['unknown'])} · risk {int(command.get('risk_score') or 0)}")
        if reasons:
            lines.append(f"- {tr('Why it is suspicious')}: {_escape_md(reasons)}")
        if status_label:
            lines.append(f"- {tr('Analyst marking')}: {_escape_md(status_label)}" + (f" ({_escape_md(notes)})" if notes else ""))
        elif notes:
            lines.append(f"- {tr('Analyst notes')}: {_escape_md(notes)}")
        story = story_by_command_id.get(str(command.get("id") or ""))
        # The lightweight story only adds the parent link; without one it would
        # print a "could not be linked" placeholder for every command.
        if story and (parent.get("name") or parent.get("executable")):
            target = story.get("target") if isinstance(story.get("target"), dict) else {}
            story_text = story.get("story") if isinstance(story.get("story"), dict) else {}
            lines.append(
                f"- Execution Story: {_escape_md(str(target.get('name') or process.get('name') or 'process'))} PID {_escape_md(str(target.get('pid') or process.get('pid') or '-'))}"
                + (f": {_escape_md(str(story_text.get('parent_sentence')))}" if story_text.get("parent_sentence") else "")
            )
        lines.append("")
    return "\n".join(lines).strip()


def _render_defender_section(events: list[dict[str, Any]]) -> str:
    if not events:
        return "No Defender events matched current filters."
    rows = [["Time (UTC)", "Threat", "Severity", "Action / result", "Path", "User", "Event ID"]]
    for event in events[:100]:
        raw = event.get("raw") if isinstance(event.get("raw"), dict) else {}
        defender = raw.get("defender") if isinstance(raw.get("defender"), dict) else {}
        threat = raw.get("threat") if isinstance(raw.get("threat"), dict) else {}
        file_data = raw.get("file") if isinstance(raw.get("file"), dict) else {}
        user = raw.get("user") if isinstance(raw.get("user"), dict) else {}
        windows = raw.get("windows") if isinstance(raw.get("windows"), dict) else {}
        action_parts = [
            str(defender.get("action") or "").strip(),
            str(defender.get("action_result") or "").strip(),
        ]
        rows.append(
            [
                _fmt_ts(event.get("timestamp") or raw.get("@timestamp")) or "-",
                _escape_md(str(threat.get("name") or defender.get("threat_name") or event.get("key_entity") or "-")),
                _escape_md(str(threat.get("severity") or defender.get("severity") or (raw.get("event") or {}).get("severity") or "-")),
                _escape_md(" / ".join(item for item in action_parts if item) or "-"),
                _code(str(defender.get("path") or file_data.get("path") or "-")),
                _escape_md(str(user.get("name") or "-")),
                _escape_md(str(defender.get("event_id") or windows.get("event_id") or "-")),
            ]
        )
    return _markdown_table(_drop_empty_columns(rows))


def _render_srum_section(events: list[dict[str, Any]]) -> str:
    if not events:
        return "No SRUM records matched current filters."
    rows = [["Time (UTC)", "Application", "User / SID", "Type", "Sent", "Received", "Total"]]
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
                _fmt_ts(event.get("timestamp") or raw.get("@timestamp")) or "-",
                _escape_md(str(app_name)),
                _escape_md(str(user.get("name") or user.get("sid") or srum.get("user_sid") or "-")),
                _humanize(str(type_label)),
                _human_bytes(int(network.get("bytes_sent") or srum.get("bytes_sent") or 0)),
                _human_bytes(int(network.get("bytes_received") or srum.get("bytes_received") or 0)),
                _human_bytes(int(network.get("bytes_total") or srum.get("bytes_total") or 0)),
            ]
        )
    return _markdown_table(rows)


_IOC_TYPE_LABELS = {"ip": "IP address", "url": "URL", "hash": "Hash", "user": "Account"}


def _render_iocs(rows: list[dict[str, Any]]) -> str:
    rows = [row for row in rows if row["type"] != "event_id"]
    if not rows:
        return "No IOCs extracted from the selected findings and key events."
    table = [["Type", "Value", "Source", "First seen (UTC)", "Last seen (UTC)", "Notes"]]
    for row in rows:
        source = str(row["source"])
        if source.startswith("finding:"):
            source = f"Finding: {source.removeprefix('finding:')}"
        elif source.startswith("bookmark:"):
            source = f"Key event: {source.removeprefix('bookmark:')}"
        table.append([
            tr(_IOC_TYPE_LABELS.get(row["type"], _humanize(row["type"]))),
            _code(row["value"]),
            source,
            _fmt_ts(row["first_seen"]) or "-",
            _fmt_ts(row["last_seen"]) or "-",
            row["notes"] or "-",
        ])
    return _markdown_table(_drop_empty_columns(table))


def _render_persistence(findings: list[Finding]) -> str:
    persistence = [finding for finding in findings if (finding.finding_type or "") in {"persistence_execution", "office_powershell"} or any("persist" in str(reason).lower() for reason in (finding.reasons or []))]
    if not persistence:
        return "No persistence-related findings selected."
    rows = [["Mechanism", "Finding", "Risk", "Path / Command"]]
    for finding in persistence:
        path_or_command = next(iter(finding.related_files or []), "") or _sanitize_text(finding.description or "")
        rows.append([_humanize(finding.finding_type or "persistence"), finding.title, str(int(finding.risk_score or 0)), path_or_command])
    return _markdown_table(rows)


def _render_network_cloud_usb(findings: list[Finding]) -> str:
    selected = [finding for finding in findings if (finding.finding_type or "") in {"powershell_network", "download_execute_detect", "cloud_exfil_candidate", "usb_exfil_candidate", "execution_cleanup"}]
    if not selected:
        return "No network/cloud/USB findings selected."
    rows = [["Type", "Finding", "Risk", "Related domains / IPs / files"]]
    for finding in selected:
        entities = ", ".join([*(str(item) for item in (finding.related_domains or [])[:2]), *(str(item) for item in (finding.related_ips or [])[:2]), *(str(item) for item in (finding.related_files or [])[:1])]) or "-"
        rows.append([_humanize(finding.finding_type or "finding"), finding.title, str(int(finding.risk_score or 0)), _sanitize_text(entities)])
    return _markdown_table(rows)


def _render_recommendations(findings: list[Finding], report: CaseReport) -> str:
    manual = _narrative((report.analyst_notes or {}).get("recommendations"))
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
    body = "\n".join(f"- {_sanitize_text(item)}" for item in _dedupe(recommendations))
    if manual:
        return f"{manual}\n\n{tr('Additional general recommendations:')}\n{body}"
    return body


def _render_appendix(
    report: CaseReport,
    timeline_entries: list[dict[str, Any]],
    findings: list[Finding],
    *,
    omitted_sections: list[str] | None = None,
) -> str:
    filters = {**DEFAULT_FILTERS, **dict(report.filters or {})}

    def joined(key: str) -> str:
        return ", ".join(str(item) for item in (filters.get(key) or [])) or "any"

    parameters = [
        ["Parameter", "Value"],
        ["Findings", f"status {joined('include_statuses')}; minimum severity {filters.get('min_severity') or 'medium'}; {len(findings)} included"],
        ["Detections", f"status {joined('detection_statuses')}; severity {joined('detection_severities')}" if filters.get("include_detections", True) else "not included"],
        ["Marked events", f"marked {joined('marking_statuses')}" if filters.get("include_marked_events", True) else "not included"],
        ["Command history", ("suspicious or analyst-marked only" if filters.get("command_only_suspicious", True) else "all commands") + f"; up to {filters.get('max_commands') or 50}" if filters.get("include_command_history", True) else "not included"],
        ["Key events", f"{len(timeline_entries)} timeline entries"],
    ]
    for key, label in (("risk_min", "Minimum risk"), ("risk_max", "Maximum risk"), ("rule_name", "Rule name contains"), ("command_query", "Command text contains")):
        if filters.get(key) not in {None, ""}:
            parameters.append([label, str(filters[key])])
    parameters = [parameters[0], *([tr(label), value] for label, value in parameters[1:])]
    lines = ["### " + tr("Report parameters"), "", _markdown_table(parameters)]
    if omitted_sections:
        lines.extend([
            "",
            "### " + tr("Sections without matching data"),
            "",
            tr("These sections were checked and had no matching data for this case and these parameters, so they are left out of the exported report: {sections}.", sections=", ".join(omitted_sections)),
        ])
    provenance = (report.metadata_json or {}).get("ai_provenance") or {}
    if provenance:
        lines.extend(["", "### " + tr("Use of AI"), "", tr(
            "The executive summary, attack narrative, recommendations and limitations were drafted with AI ({provider}, model {model}, {when} UTC) from the curated findings and timeline of this report, then reviewed and edited by {author}.",
            provider=provenance.get("provider") or "-", model=provenance.get("model") or "-",
            when=_fmt_ts(provenance.get("generated_at")) or "-", author=report.author or tr("the analyst"),
        )])
    limitations = _narrative((report.analyst_notes or {}).get("limitations"))
    if limitations:
        lines.extend(["", "### " + tr("Limitations"), "", limitations])
    if report.include_raw_appendix:
        references = [entry for entry in timeline_entries if entry.get("event_id")][:50]
        if references:
            lines.extend(["", "### " + tr("Event references"), ""])
            rows = [["Time (UTC)", "Event", "Event ID"]]
            for entry in references:
                rows.append([_fmt_ts(entry.get("timestamp")) or "-", str(entry.get("title") or ""), _code(str(entry.get("event_id")))])
            lines.append(_markdown_table(rows))
    if report.include_debug_metadata:
        lines.extend(["", "### " + tr("Report metadata"), "", f"- Report ID: {_code(report.id)}", f"- Generated at: {_fmt_ts(datetime.now(UTC))} UTC"])
    return "\n".join(lines).strip()


def _host_coverage_notes(db: Session, case_id: str) -> list[str]:
    """Hosts missing a critical source their peers have (filesystem, event
    logs, process creation or logon records): what the report cannot say about
    them should be stated, not left for the reader to discover."""
    try:
        from app.services.host_coverage import build_case_host_coverage

        return list(build_case_host_coverage(db, case_id).get("warnings") or [])
    except Exception:  # noqa: BLE001 - coverage must never break the report
        return []


_AI_CONTEXT_LIMITS = {"findings": 25, "timeline": 80, "iocs": 60, "lateral_movement": 30, "text": 1500}


def _report_ai_context(
    case: Case,
    context: dict[str, Any],
    report: CaseReport,
    findings: list[Finding],
    timeline_entries: list[dict[str, Any]],
    ioc_rows: list[dict[str, Any]],
    coverage_notes: list[str],
    memory_report: list[dict[str, Any]],
    detections: list[DetectionResult],
    detections_total: int,
    lateral_edges: list[dict[str, Any]] | None = None,
) -> dict[str, Any]:
    """The curated material a narrative may be drafted from: what the analyst
    confirmed, bookmarked, marked and accepted -- never the raw index. Findings
    keep the F-numbers the report gives them so citations line up."""
    limit = _AI_CONTEXT_LIMITS["text"]
    rule_counts = Counter(str(row.rule_title or row.rule_name or "") for row in detections)
    return {
        "case": str(case.name or ""),
        "language": _report_language(report),
        "hosts": [_context_host_name(host) for host in context.get("hosts") or []],
        "evidence": [{"name": item.get("name"), "host": item.get("detected_host"), "status": item.get("status")} for item in context.get("evidences") or []],
        "findings": [
            {
                "ref": f"F{index}",
                "title": finding.title,
                "severity": _sev(finding),
                "risk": int(finding.risk_score or 0),
                "status": str(getattr(finding.status, "value", finding.status)),
                "observed_utc": " to ".join(value for value in (_fmt_ts(finding.time_start), _fmt_ts(finding.time_end)) if value),
                "description": _sanitize_text(str(finding.description or ""), limit),
                "why": [_sanitize_text(str(item)) for item in (finding.reasons or [])[:8]],
                "mitre": list(finding.mitre or []),
                "hosts": list(finding.related_hosts or []),
                "users": list(finding.related_users or []),
                "files": [_sanitize_text(str(item)) for item in (finding.related_files or [])[:8]],
                "domains": list(finding.related_domains or []),
                "ips": list(finding.related_ips or []),
                "supporting_events": [
                    {"time_utc": _fmt_ts(item.get("timestamp")), "summary": _sanitize_text(str(item.get("summary") or ""))}
                    for item in (finding.timeline or [])[:8]
                ],
                "next_steps": [_sanitize_text(str(item)) for item in (finding.recommended_triage or [])[:6]],
            }
            for index, finding in enumerate(findings[: _AI_CONTEXT_LIMITS["findings"]], start=1)
        ],
        "timeline": [
            {
                "time_utc": _fmt_ts(entry.get("timestamp")),
                "host": entry.get("host"),
                "phase": entry.get("phase"),
                "event": _sanitize_text(str(entry.get("title") or "")),
                "details": _sanitize_text(str(entry.get("note") or entry.get("summary") or ""), 400),
            }
            for entry in timeline_entries[: _AI_CONTEXT_LIMITS["timeline"]]
            if entry.get("timestamp")
        ],
        "iocs": [{"type": row["type"], "value": row["value"], "notes": row.get("notes") or ""} for row in ioc_rows if row["type"] != "event_id"][: _AI_CONTEXT_LIMITS["iocs"]],
        "coverage_notes": list(coverage_notes),
        "memory": [
            {
                "image": entry.get("filename"),
                "host": entry.get("host"),
                "marked_processes": [
                    {"process": item.get("process"), "pid": item.get("pid"), "mark": item.get("mark"), "note": item.get("note")}
                    for item in ((entry.get("find_evil") or {}).get("marked_processes") or [])
                ],
                "antivirus_detections": [
                    {"time_utc": _fmt_ts(item.get("first_seen")), "threat": item.get("threat"), "target": _sanitize_text(str(item.get("target") or ""), 300)}
                    for item in ((entry.get("find_evil") or {}).get("antivirus_detections") or [])[:20]
                ],
            }
            for entry in memory_report or []
        ],
        "lateral_movement": [
            {
                "time_utc": _fmt_ts(edge.get("first_seen")),
                "last_utc": _fmt_ts(edge.get("last_seen")),
                "from_hosts": edge.get("source_hosts") or [],
                "from_ip": edge.get("source_ip"),
                "to_host": edge.get("target_host"),
                "account": _lateral_account(edge),
                "method": edge.get("method"),
                "succeeded": edge.get("successes"),
                "failed": edge.get("failures"),
            }
            for edge in (lateral_edges or [])[: _AI_CONTEXT_LIMITS["lateral_movement"]]
        ],
        "automated_detections": {"total": detections_total, "top_rules": [{"rule": name, "matches": count} for name, count in rule_counts.most_common(8)]},
        "analyst_notes": {key: _narrative(value) for key, value in (report.analyst_notes or {}).items() if value},
    }


_COVERAGE_NOTE_TEXT = {
    "failed_evidence_present": "At least one evidence item failed to process; its data is missing from this report.",
    "parser_errors_present": "Some artifacts produced parser errors; records from those artifacts may be incomplete.",
}


def _plural(count: int, noun: str) -> str:
    return f"{count:,} {noun}{'' if count == 1 else 's'}"


def _humanize(value: str | None) -> str:
    text = str(value or "").strip()
    if not text or text == "-":
        return text or "-"
    if any(char.isupper() for char in text) or " " in text:
        return text
    text = text.replace("_", " ")
    return text[:1].upper() + text[1:]


def _human_bytes(value: int) -> str:
    size = float(max(int(value or 0), 0))
    for unit in ("bytes", "KB", "MB", "GB", "TB"):
        if size < 1024 or unit == "TB":
            return f"{int(size):,} bytes" if unit == "bytes" else f"{size:,.1f} {unit}"
        size /= 1024
    return f"{int(value):,} bytes"


def _fmt_ts(value: Any) -> str:
    """Report timestamps as `YYYY-MM-DD HH:MM:SS` in UTC (seconds precision).
    The zone is stated once (cover, column headers), not on every cell."""
    if value in {None, ""}:
        return ""
    if isinstance(value, datetime):
        parsed = value
    else:
        text = str(value).strip()
        try:
            parsed = datetime.fromisoformat(text.replace("Z", "+00:00"))
        except ValueError:
            return text
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=UTC)
    return parsed.astimezone(UTC).strftime("%Y-%m-%d %H:%M:%S")


def _code(value: Any) -> str:
    """Inline code span. Its content is literal, so it is redacted but not
    markdown-escaped (escaping inside backticks prints the backslashes)."""
    # A code span is one line: a multi-line script would break it open.
    text = re.sub(r"\s*[\r\n]+\s*", " ", _sanitize_text(str(value or ""))).replace("`", "'")
    return f"`{text}`" if text and text != "-" else "-"


def _drop_empty_columns(rows: list[list[str]], *, zero_is_empty: set[str] | None = None) -> list[list[str]]:
    """Remove columns whose every body cell is empty, so tables do not carry
    a column of dashes. Columns named in zero_is_empty also drop when all 0."""
    if len(rows) < 2:
        return rows
    empty_values = {"", "-", "unknown"}
    keep = []
    for index, header in enumerate(rows[0]):
        values = {str(row[index]).strip() for row in rows[1:] if index < len(row)}
        blank = values <= empty_values or (header in (zero_is_empty or set()) and values <= {*empty_values, "0"})
        keep.append(not blank)
    if not any(keep):
        return rows
    return [[cell for index, cell in enumerate(row) if index < len(keep) and keep[index]] for row in rows]


_SOURCE_CAP_WARNING = re.compile(r"showing first (\d+) of (\d+) source matches")


def _summarize_source_cap_warnings(warnings: list[str], review_in: str = "Startup & Persistence") -> list[str]:
    """Per-source "showing first N of M" caps read as noise one by one; the
    reader only needs to know the list is a sample and how big the pool was."""
    capped = [match for match in (_SOURCE_CAP_WARNING.search(str(item)) for item in warnings) if match]
    other = [str(item) for item in warnings if not _SOURCE_CAP_WARNING.search(str(item))]
    if capped:
        total = sum(int(match.group(2)) for match in capped)
        other.append(
            f"{len(capped)} sources had more matching entries than the report lists ({total:,} in total); "
            f"the highest-risk entries are shown. Review {review_in} for the full list."
        )
    return other


def _incident_timeline_report_notes(warnings: list[str]) -> list[str]:
    notes: list[str] = []
    for warning in warnings:
        text = str(warning)
        if "outdated" in text.lower():
            notes.append("The incident timeline was curated before the latest case changes; regenerate it in Incident Timeline to include them.")
        elif "timeline candidates" in text:
            # Concerns unreviewed candidates; the report only carries accepted items.
            continue
        else:
            notes.append(text)
    return _dedupe(notes)


def _humanize_table_columns(markdown: str, columns: set[str]) -> str:
    """Turn snake_case codes (scheduled_task, sysmon_15) into words in the named
    columns of every markdown table; other columns keep their literal values."""
    output: list[str] = []
    header: list[str] | None = None
    for line in markdown.splitlines():
        stripped = line.strip()
        if not stripped.startswith("|"):
            header = None
            output.append(line)
            continue
        cells = [cell.strip() for cell in re.split(r"(?<!\\)\|", stripped.strip("|"))]
        if header is None:
            header = cells
            output.append(line)
            continue
        if all(set(cell) <= {"-", ":"} for cell in cells):
            output.append(line)
            continue
        cells = [
            _humanize(cell) if index < len(header) and header[index] in columns and re.fullmatch(r"[a-z0-9]+(_[a-z0-9]+)+|[a-z]+", cell) else cell
            for index, cell in enumerate(cells)
        ]
        output.append("| " + " | ".join(cells) + " |")
    return "\n".join(output)


def _collapse_duplicate_table_rows(markdown: str) -> str:
    """Merge identical body rows of markdown tables into one row marked `(xN)`."""
    output: list[str] = []
    lines = markdown.splitlines()
    index = 0
    while index < len(lines):
        if not lines[index].lstrip().startswith("|"):
            output.append(lines[index])
            index += 1
            continue
        block: list[str] = []
        while index < len(lines) and lines[index].lstrip().startswith("|"):
            block.append(lines[index])
            index += 1
        head, body = block[:2], block[2:]
        counts: Counter[str] = Counter(body)
        seen: set[str] = set()
        output.extend(head)
        for row in body:
            if row in seen:
                continue
            seen.add(row)
            if counts[row] > 1:
                cells = row.strip().strip("|").split(" | ")
                cells[0] = f"{cells[0].strip()} (×{counts[row]})"
                row = "| " + " | ".join(cell.strip() for cell in cells) + " |"
            output.append(row)
    return "\n".join(output)


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


def _render_markdown_document(title: str, sections: list[dict[str, Any]], *, author: str | None = None) -> str:
    byline = tr("Generated {when} UTC · all times UTC", when=_fmt_ts(datetime.now(UTC))) + (tr(" · Prepared by {author}", author=_sanitize_text(author)) if author else "")
    lines = [f"# {_escape_md(title)}", "", f"_{byline}_", ""]
    for number, section in enumerate(sections, start=1):
        lines.append(f"## {number}. {_escape_md(section['title'])}")
        lines.append("")
        for warning in section.get("warnings") or []:
            lines.append(f"> {_sanitize_text(str(warning))}")
        if section.get("warnings"):
            lines.append("")
        lines.append(section["markdown"].strip())
        lines.append("")
    return "\n".join(lines).strip() + "\n"


def _markdown_table(rows: list[list[str]]) -> str:
    rows = [[tr(cell) for cell in rows[0]], *rows[1:]]
    sanitized_rows = [[_sanitize_text(cell).replace("\n", " ").replace("|", "\\|") for cell in row] for row in rows]
    header = f"| {' | '.join(sanitized_rows[0])} |"
    divider = f"| {' | '.join(['---'] * len(sanitized_rows[0]))} |"
    body = [f"| {' | '.join(row)} |" for row in sanitized_rows[1:]]
    return "\n".join([header, divider, *body])


def _sanitize_text(value: str, limit: int = 1200) -> str:
    text = value.strip()
    if not text:
        return ""
    text = _SECRET_INLINE.sub(lambda match: f"{match.group(1)}=[REDACTED]", text)
    text = _BEARER_TOKEN.sub("Bearer [REDACTED]", text)
    return text[:limit]


# Analyst narrative (executive summary, recommendations, limitations, finding
# descriptions) is written for the reader and must not be cut mid-sentence;
# the 1200-character cap is meant for single values carried into tables.
_NARRATIVE_LIMIT = 20000


def _narrative(value: Any) -> str:
    return _sanitize_text(str(value or ""), _NARRATIVE_LIMIT)


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
