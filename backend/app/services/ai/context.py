"""The case briefing sent to the model with every question.

This is deliberately a summary, not evidence. A case holds millions of events;
what the model gets is the shape of the case — hosts, evidence, findings — so it
can ask the analyst the right follow-up and reason about scope. Retrieval of
actual events is a separate capability and is not part of this briefing.
"""

from __future__ import annotations

from sqlalchemy.orm import Session

from app.models.artifact import Artifact
from app.models.case import Case
from app.models.case_host import CaseHost
from app.models.evidence import Evidence
from app.models.finding import Finding


MAX_HOSTS = 25
MAX_EVIDENCE = 25
MAX_FINDINGS = 25


def build_case_context(db: Session, case_id: str) -> str:
    case = db.get(Case, case_id)
    if case is None:
        return "No case is currently open."

    lines: list[str] = ["## Case briefing", ""]
    lines.append(f"- Name: {case.name}")
    lines.append(f"- Status: {_enum_value(case.status)} / priority {_enum_value(case.priority)}")
    if case.timezone:
        lines.append(f"- Case timezone: {case.timezone}")
    if case.description:
        lines.append(f"- Description: {_clip(case.description, 500)}")
    if case.case_notes:
        lines.append(f"- Analyst notes: {_clip(case.case_notes, 800)}")

    lines += ["", "### Hosts"]
    host_query = db.query(CaseHost).filter(CaseHost.case_id == case_id)
    host_total = host_query.count()
    hosts = host_query.order_by(CaseHost.event_count.desc()).limit(MAX_HOSTS).all()
    if hosts:
        for host in hosts:
            lines.append(
                f"- {host.display_name} (events: {host.event_count}, "
                f"evidence items: {host.evidence_count}, first seen: {host.first_seen or 'unknown'}, "
                f"last seen: {host.last_seen or 'unknown'})"
            )
        if host_total > len(hosts):
            lines.append(_truncation_note(len(hosts), host_total, "hosts", "by event count"))
    else:
        lines.append("- No hosts identified yet.")

    lines += ["", "### Evidence"]
    evidence_query = db.query(Evidence).filter(Evidence.case_id == case_id)
    evidence_total = evidence_query.count()
    evidences = evidence_query.limit(MAX_EVIDENCE).all()
    if evidences:
        for item in evidences:
            lines.append(
                f"- {item.original_filename} "
                f"[type: {_enum_value(item.evidence_type)}, ingest: {_enum_value(item.ingest_status)}]"
            )
        if evidence_total > len(evidences):
            lines.append(_truncation_note(len(evidences), evidence_total, "evidence items", None))
    else:
        lines.append("- No evidence uploaded yet.")

    artifact_count = db.query(Artifact).filter(Artifact.case_id == case_id).count()
    lines.append(f"- Parsed artifacts in this case: {artifact_count}")

    lines += ["", "### Findings"]
    finding_query = db.query(Finding).filter(Finding.case_id == case_id)
    finding_total = finding_query.count()
    findings = finding_query.order_by(Finding.created_at.desc()).limit(MAX_FINDINGS).all()
    if findings:
        for finding in findings:
            lines.append(
                f"- [{_enum_value(finding.severity)}/{_enum_value(finding.status)}] {finding.title}"
                + (f" — {_clip(finding.description, 200)}" if finding.description else "")
            )
        if finding_total > len(findings):
            lines.append(_truncation_note(len(findings), finding_total, "findings", "most recent"))
    else:
        lines.append("- No findings recorded yet.")

    return "\n".join(lines)


def _truncation_note(shown: int, total: int, noun: str, ordering: str | None) -> str:
    # The model must not present this briefing as complete case coverage when it
    # isn't -- it should say so, and prefer a targeted tool call (e.g. searching
    # for a specific host by name) over assuming an item absent from this list
    # doesn't exist.
    basis = f" ({ordering})" if ordering else ""
    return f"- Note: showing {shown} of {total} {noun}{basis}. Others exist but are not listed here — ask about a specific one by name/id rather than assuming absence."


def _enum_value(value: object) -> str:
    return str(getattr(value, "value", value) or "unknown")


def _clip(text: str, limit: int) -> str:
    text = " ".join(str(text).split())
    return text if len(text) <= limit else text[: limit - 1] + "…"
