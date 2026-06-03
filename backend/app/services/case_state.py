from __future__ import annotations

from typing import Any


CASE_STATES = {
    "empty_case",
    "evidence_uploaded_not_indexed",
    "indexing_in_progress",
    "investigation_ready",
    "investigation_in_progress",
    "report_ready",
}


def derive_case_investigation_state(
    *,
    evidence_count: int,
    investigation_ready_evidence_count: int = 0,
    indexed_docs: int = 0,
    active_jobs: list[dict[str, Any]] | None = None,
    findings_count: int = 0,
    official_timeline_count: int = 0,
    candidate_timeline_count: int = 0,
    marked_events_count: int = 0,
    parser_errors: int = 0,
    warnings: list[str] | None = None,
) -> dict[str, Any]:
    active_job_rows = [dict(item) for item in (active_jobs or []) if isinstance(item, dict)]
    ready = investigation_ready_evidence_count > 0 or indexed_docs > 0
    if evidence_count <= 0:
        state = "empty_case"
    elif active_job_rows:
        state = "indexing_in_progress"
    elif indexed_docs <= 0 and not ready:
        state = "evidence_uploaded_not_indexed"
    elif findings_count > 0 or official_timeline_count > 0:
        state = "report_ready"
    elif ready and (candidate_timeline_count > 0 or marked_events_count > 0):
        state = "investigation_in_progress"
    else:
        state = "investigation_ready"

    return {
        "state": state,
        "evidence_count": max(int(evidence_count or 0), 0),
        "investigation_ready_evidence_count": max(int(investigation_ready_evidence_count or 0), 0),
        "indexed_docs": max(int(indexed_docs or 0), 0),
        "active_jobs": active_job_rows,
        "active_job_count": len(active_job_rows),
        "findings_count": max(int(findings_count or 0), 0),
        "official_timeline_count": max(int(official_timeline_count or 0), 0),
        "candidate_timeline_count": max(int(candidate_timeline_count or 0), 0),
        "marked_events_count": max(int(marked_events_count or 0), 0),
        "parser_errors": max(int(parser_errors or 0), 0),
        "warnings": list(warnings or []),
    }


def _action(
    action_id: str,
    label: str,
    href: str,
    *,
    priority: str = "secondary",
    enabled: bool = True,
    reason: str | None = None,
) -> dict[str, Any]:
    return {
        "id": action_id,
        "label": label,
        "href": href,
        "priority": priority,
        "enabled": bool(enabled),
        "reason": reason or "",
    }


def build_case_next_actions(
    case_id: str,
    state_payload: dict[str, Any],
    *,
    demo_metadata_enabled: bool = False,
    first_evidence_id: str | None = None,
    defender_docs_count: int = 0,
) -> dict[str, list[dict[str, Any]]]:
    state = str(state_payload.get("state") or "empty_case")
    upload_href = f"/cases/{case_id}/evidence"
    evidence_href = f"/evidences/{first_evidence_id}" if first_evidence_id else upload_href
    primary: list[dict[str, Any]] = []
    secondary: list[dict[str, Any]] = []
    unavailable: list[dict[str, Any]] = []

    if state == "empty_case":
        primary.append(_action("add_evidence", "Add evidence", upload_href, priority="primary"))
        secondary.append(_action("read_upload_guide", "Read upload guide", "/docs/ingestion"))
        if demo_metadata_enabled:
            secondary.append(_action("import_demo_metadata", "Import demo/training case metadata", "/docs/generic-demo-guide"))
        unavailable.extend(
            [
                _action("search_suspicious_commands", "Search suspicious commands", f"/cases/{case_id}/search?q=powershell%20-ep%20bypass", enabled=False, reason="Add and index evidence before searching."),
                _action("review_command_history", "Review Command History", f"/cases/{case_id}/command-history", enabled=False, reason="Command History will appear after command-capable artifacts are indexed."),
                _action("review_defender", "Review Defender detections", f"/cases/{case_id}/artifacts?artifact_type=defender", enabled=False, reason="No Defender artifacts indexed in this case."),
                _action("generate_report", "Generate Report", f"/cases/{case_id}/reports", enabled=False, reason="Create findings or timeline items before generating a useful report."),
            ]
        )
    elif state == "evidence_uploaded_not_indexed":
        primary.append(_action("index_evidence", "Index evidence for investigation", evidence_href, priority="primary"))
        secondary.extend(
            [
                _action("add_more_evidence", "Add more evidence", upload_href),
                _action("view_evidence_details", "View evidence details", evidence_href),
            ]
        )
        unavailable.extend(
            [
                _action("search_suspicious_commands", "Search suspicious commands", f"/cases/{case_id}/search?q=powershell%20-ep%20bypass", enabled=False, reason="Index evidence before searching."),
                _action("review_command_history", "Review Command History", f"/cases/{case_id}/command-history", enabled=False, reason="Command History will appear after command-capable artifacts are indexed."),
                _action("generate_report", "Generate Report", f"/cases/{case_id}/reports", enabled=False, reason="Create findings or timeline items before generating a useful report."),
            ]
        )
    elif state == "indexing_in_progress":
        primary.append(_action("view_indexing_progress", "View indexing progress", evidence_href, priority="primary"))
        secondary.extend(
            [
                _action("add_more_evidence", "Add more evidence", upload_href),
                _action("jobs_activity", "Jobs & Activity", "/activity"),
            ]
        )
        unavailable.append(_action("search_suspicious_commands", "Search suspicious commands", f"/cases/{case_id}/search?q=powershell%20-ep%20bypass", enabled=False, reason="Search becomes useful after indexing has produced documents."))
    elif state == "report_ready":
        primary.extend(
            [
                _action("generate_report", "Generate Report", f"/cases/{case_id}/reports", priority="primary"),
                _action("review_findings", "Review Findings", f"/cases/{case_id}/findings", priority="primary"),
            ]
        )
        if int(state_payload.get("official_timeline_count") or 0) > 0:
            primary.append(_action("export_timeline", "Export timeline", f"/cases/{case_id}/incident-timeline", priority="primary"))
        secondary.extend(_ready_investigation_actions(case_id, upload_href, defender_docs_count=defender_docs_count, include_report=False))
    elif state == "investigation_in_progress":
        primary.extend(
            [
                _action("continue_incident_timeline", "Continue Incident Timeline", f"/cases/{case_id}/incident-timeline", priority="primary"),
                _action("review_findings", "Review Findings", f"/cases/{case_id}/findings", priority="primary"),
                _action("generate_report", "Generate Report", f"/cases/{case_id}/reports", priority="primary"),
            ]
        )
        secondary.extend(_ready_investigation_actions(case_id, upload_href, defender_docs_count=defender_docs_count, include_report=False))
    else:
        primary.extend(_ready_investigation_actions(case_id, upload_href, defender_docs_count=defender_docs_count, include_add_evidence=False, include_report=False))
        secondary.append(_action("add_more_evidence", "Add more evidence", upload_href))
        unavailable.append(_action("generate_report", "Generate Report", f"/cases/{case_id}/reports", enabled=False, reason="Create findings or timeline items before generating a useful report."))
        if defender_docs_count <= 0:
            unavailable.append(_action("review_defender", "Review Defender detections", f"/cases/{case_id}/artifacts?artifact_type=defender", enabled=False, reason="No Defender artifacts indexed in this case."))

    if state not in {"empty_case", "evidence_uploaded_not_indexed", "indexing_in_progress"} and not any(item["id"] in {"add_evidence", "add_more_evidence"} for item in [*primary, *secondary]):
        secondary.insert(0, _action("add_more_evidence", "Add more evidence", upload_href))

    return {"primary": primary, "secondary": secondary, "unavailable": unavailable}


def _ready_investigation_actions(
    case_id: str,
    upload_href: str,
    *,
    defender_docs_count: int = 0,
    include_add_evidence: bool = True,
    include_report: bool = True,
) -> list[dict[str, Any]]:
    actions = [
        _action("search_suspicious_commands", "Search suspicious commands", f"/cases/{case_id}/search?q=powershell%20-ep%20bypass", priority="primary"),
        _action("review_command_history", "Review Command History", f"/cases/{case_id}/command-history", priority="primary"),
        _action("review_artifacts", "Review Artifacts", f"/cases/{case_id}/artifacts", priority="primary"),
        _action("review_startup_persistence", "Review Startup & Persistence", f"/cases/{case_id}/artifacts?artifact_type=startup_persistence&suspicious_only=true", priority="primary"),
        _action("build_incident_timeline", "Build Incident Timeline", f"/cases/{case_id}/incident-timeline", priority="primary"),
    ]
    if defender_docs_count > 0:
        actions.insert(4, _action("review_defender", "Review Defender detections", f"/cases/{case_id}/artifacts?artifact_type=defender", priority="primary"))
    if include_report:
        actions.append(_action("generate_report", "Generate Report", f"/cases/{case_id}/reports", priority="primary"))
    if include_add_evidence:
        actions.append(_action("add_more_evidence", "Add more evidence", upload_href))
    return actions
