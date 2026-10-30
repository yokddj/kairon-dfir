"""Suggest findings with the configured AI provider, for the analyst to confirm.

The model sees the case's open leads -- rule detections no finding covers yet,
suspicious commands, antivirus detections still in memory, processes the
analyst marked in Find Evil, and remote logons between machines -- each with a
reference (L1, L2...), plus the titles of the findings that already exist. It
proposes findings that group leads describing one activity, with severity and
MITRE techniques, citing the leads it used.

Nothing is created here. Each suggestion is checked before the analyst sees
it: a suggestion without a valid lead is dropped, unknown citations and any IP
address, time or number not in its leads are reported, and techniques must be
ATT&CK IDs. The event, detection, host, address and account links of an
accepted suggestion come from its leads, never from the model's text.
"""

from __future__ import annotations

import json
import logging
import re
from dataclasses import replace
from datetime import UTC, datetime
from typing import Any

from sqlalchemy.orm import Session

from app.models.detection_result import DetectionResult
from app.models.finding import Finding, FindingSeverity
from app.services.ai.config import AIConfigError, resolve_provider
from app.services.ai.report_draft import (
    DRAFT_MIN_TOKENS,
    ReportDraftUnavailable,
    ai_draft_status,
    complete,
    corpus_numbers,
    parse_json_reply,
    unsupported_facts,
)
from app.services.mitre_tactics import primary_tactic, tagged_techniques

logger = logging.getLogger(__name__)

PROMPT_VERSION = "finding-suggestions-v1"
MAX_LEADS = {"detection": 40, "command": 40, "antivirus": 30, "memory_process": 20, "lateral": 30}
MAX_DETECTION_ROWS = 5000
MAX_SUGGESTIONS = 12
MAX_EVENT_IDS = 50
MAX_DETECTION_IDS = 50
MAX_EXISTING_FINDINGS = 80
MAX_TEXT = 400
# Beyond this, a time range describes the data (default dates of built-in
# items, clock errors), not when one activity happened.
MAX_TIME_RANGE_DAYS = 365

# Detections an analyst closed, or that automation retired, are not leads.
_CLOSED_DETECTION_STATUSES = ("dismissed", "false_positive", "archived", "stale", "stale_event_link", "promoted_to_finding")
_DISMISSED_FINDING_STATUSES = {"false_positive", "archived", "suppressed"}
_SEVERITY_RANK = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0, "informational": 0}
_CONFIDENCE = {"low", "medium", "high"}
_ISO_TIME = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}")
_LEAD_REF = re.compile(r"\bL\d+\b")
# Models cite runs of leads as [L25-L27] or [L25–27].
_LEAD_RANGE = re.compile(r"\bL(\d+)\s*[-\u2013]\s*L?(\d+)\b")
MAX_RANGE = 50

SYSTEM_PROMPT = """You are a senior DFIR analyst triaging a case. You are given its OPEN LEADS as JSON -- automated rule detections, suspicious commands, antivirus detections found in memory, memory processes the analyst marked, and remote logons between machines -- each with a reference (L1, L2...), and the titles of the findings the analyst already has.

Propose findings: each one groups the leads that describe ONE activity (for example a tool run and the logon that preceded it), states what happened and why it matters.

Rules:
- Use ONLY facts present in the leads. Do not add hosts, accounts, IP addresses, times, tools, counts or techniques that are not in them.
- Cite the leads you used in the description as [L3]. Every suggestion lists its leads.
- Automated detections and risk scores are leads, not proof: if the leads only suggest something, say so and use confidence "low".
- Do not propose a finding that duplicates an existing one. Skip leads that look benign or routine; you do not have to use every lead.
- Severity is one of info, low, medium, high, critical. MITRE techniques as ATT&CK IDs (T1059.001), only when the leads support them.
- At most {max} suggestions, most important first. Write in English.

Reply with ONLY a JSON object:
{"suggestions": [{"title": "short, specific", "severity": "high", "confidence": "medium", "mitre": ["T1558.003"], "leads": ["L3", "L7"], "description": "2-5 sentences citing [L3] [L7]"}]}"""


class FindingSuggestionsUnavailable(ReportDraftUnavailable):
    """AI is not configured, or the case has no open leads to suggest from."""


def _clip(value: Any, limit: int = MAX_TEXT) -> str | None:
    text = re.sub(r"\s+", " ", str(value or "")).strip()
    if not text:
        return None
    return text[:limit] + ("..." if len(text) > limit else "")


def _iso(value: Any) -> str | None:
    text = str(value or "").strip()
    return text if _ISO_TIME.match(text) else None


def _status(item: Any) -> str:
    status = getattr(item, "status", None)
    return str(getattr(status, "value", status) or "").lower()


def _open_findings(db: Session, case_id: str) -> list[Finding]:
    return [
        finding for finding in db.query(Finding).filter(Finding.case_id == case_id, Finding.archived_at.is_(None)).all()
        if _status(finding) not in _DISMISSED_FINDING_STATUSES
    ]


def _lead(kind: str, *, time: Any, host: Any, label: str, details: dict[str, Any], last: Any = None, **backing: Any) -> dict[str, Any]:
    return {
        "kind": kind,
        "time_utc": _iso(time),
        "last_utc": _iso(last) if last and last != time else None,
        "host": _clip(host, 255),
        "label": label,
        "details": {key: value for key, value in details.items() if value not in (None, "", [], {})},
        "backing": backing,
    }


def _detection_leads(db: Session, case_id: str, covered: set[str]) -> list[dict[str, Any]]:
    rows = (
        db.query(DetectionResult)
        .filter(
            DetectionResult.case_id == case_id,
            DetectionResult.deleted_at.is_(None),
            DetectionResult.archived_at.is_(None),
            DetectionResult.status.notin_(_CLOSED_DETECTION_STATUSES),
        )
        .order_by(DetectionResult.created_at.desc())
        .limit(MAX_DETECTION_ROWS)
        .all()
    )
    groups: dict[tuple[str, str], dict[str, Any]] = {}
    for row in rows:
        if row.related_finding_ids or (row.event_id and row.event_id in covered):
            continue
        group = groups.setdefault((row.rule_name, row.host_name or ""), {"rows": [], "severity": 0})
        group["rows"].append(row)
        group["severity"] = max(group["severity"], _SEVERITY_RANK.get(str(row.severity or row.rule_level or "").lower(), 0))
    ranked = sorted(groups.items(), key=lambda item: (-item[1]["severity"], -len(item[1]["rows"])))
    leads = []
    for (rule, host), group in ranked[: MAX_LEADS["detection"]]:
        members = group["rows"]
        times = sorted(time for time in (_iso(row.matched_at) for row in members) if time)
        sample = members[0]
        severity = next((name for name, rank in _SEVERITY_RANK.items() if rank == group["severity"]), "info")
        leads.append(_lead(
            "detection",
            time=times[0] if times else None,
            last=times[-1] if times else None,
            host=host,
            label=f"Rule {rule} ({len(members)} match{'es' if len(members) != 1 else ''})",
            details={
                "rule": sample.rule_title or rule,
                "severity": severity,
                "matches": len(members),
                "sample": _clip(sample.message or sample.target_path),
                "mitre": tagged_techniques([*(sample.mitre or []), *(sample.tags or [])]),
            },
            detection_ids=[row.id for row in members],
            hosts=[host] if host else [],
        ))
    return leads


def _command_leads(db: Session, case_id: str, covered: set[str]) -> list[dict[str, Any]]:
    """The riskiest suspicious commands, one lead per command and host: a
    script run line by line repeats the same command many times."""
    from app.services.command_history import get_command_history

    result = get_command_history(case_id, {"only_suspicious": True, "page": 1, "page_size": 500}, db=db)
    groups: dict[tuple[str, str], list[dict[str, Any]]] = {}
    for item in result.get("items") or []:
        if str(item.get("source_event_id") or "") in covered:
            continue
        key = (str(item.get("host") or ""), re.sub(r"\s+", " ", str(item.get("command") or "")).strip().lower())
        groups.setdefault(key, []).append(item)
    ranked = sorted(groups.values(), key=lambda members: -max(int(item.get("risk_score") or 0) for item in members))
    leads = []
    for members in ranked[: MAX_LEADS["command"]]:
        item = max(members, key=lambda member: int(member.get("risk_score") or 0))
        times = sorted(time for time in (_iso(member.get("timestamp")) for member in members) if time)
        # A command recovered from memory has no document to link to.
        event_ids = [str(member["source_event_id"]) for member in members if member.get("source_event_id") and str(member.get("source_type") or "") != "memory"]
        leads.append(_lead(
            "command",
            time=times[0] if times else None,
            last=times[-1] if times else None,
            host=item.get("host"),
            label=f"Command (risk {int(item.get('risk_score') or 0)}): {_clip(item.get('command'), 120)}",
            details={
                "user": item.get("user"),
                "command": _clip(item.get("command")),
                "runs": len(members) if len(members) > 1 else None,
                "shell": item.get("shell_family"),
                "risk": item.get("risk_score"),
                "reasons": (item.get("risk_reasons") or [])[:4],
                "source": item.get("source_type"),
            },
            event_ids=event_ids[:MAX_EVENT_IDS],
            evidence_ids=_dedupe([member.get("evidence_id") for member in members]),
            hosts=[item["host"]] if item.get("host") else [],
            users=_dedupe([member.get("user") for member in members]),
        ))
    return leads


def _memory_leads(db: Session, case_id: str) -> list[dict[str, Any]]:
    from app.services.memory.report_section import build_memory_report_context

    antivirus: list[dict[str, Any]] = []
    processes: list[dict[str, Any]] = []
    for image in build_memory_report_context(db, case_id):
        find_evil = image.get("find_evil") or {}
        backing = {"evidence_ids": [image["evidence_id"]], "hosts": [image["host"]] if image.get("host") else []}
        for detection in find_evil.get("antivirus_detections") or []:
            antivirus.append(_lead(
                "antivirus",
                time=detection.get("first_seen"),
                last=detection.get("last_seen"),
                host=image.get("host"),
                label=f"Antivirus detection in memory: {detection.get('threat')}",
                details={
                    "threat": detection.get("threat"),
                    "engine": detection.get("engine"),
                    "detected_by": detection.get("sources"),
                    "target": _clip(detection.get("target")),
                    "image": image.get("filename"),
                },
                **backing,
            ))
        for process in find_evil.get("marked_processes") or []:
            processes.append(_lead(
                "memory_process",
                time=None,
                host=image.get("host"),
                label=f"Memory process marked {process.get('mark')}: {process.get('process')} (PID {process.get('pid')})",
                details={
                    "process": process.get("process"),
                    "pid": process.get("pid"),
                    "analyst_mark": process.get("mark"),
                    "analyst_note": _clip(process.get("note")),
                    "find_evil_indicators": process.get("indicator_types"),
                    "image": image.get("filename"),
                },
                **backing,
            ))
    return antivirus[: MAX_LEADS["antivirus"]] + processes[: MAX_LEADS["memory_process"]]


def _lateral_leads(db: Session, case_id: str) -> list[dict[str, Any]]:
    from app.services.lateral_movement import get_lateral_movement

    edges = [edge for edge in get_lateral_movement(db, case_id).get("edges") or [] if not edge.get("routine_reason")]
    # Rows that carry a lead of their own first, then in time order.
    edges.sort(key=lambda edge: (not (edge.get("failures") or edge.get("workstation_mismatch") or edge.get("source_ambiguous")), edge.get("first_seen") or ""))
    leads = []
    for edge in edges[: MAX_LEADS["lateral"]]:
        account = f"{edge['domain']}\\{edge['user']}" if edge.get("domain") and edge.get("user") else edge.get("user")
        source = " or ".join(edge.get("source_hosts") or []) or "an address that is not a case host"
        notes = []
        if edge.get("workstation_mismatch"):
            notes.append("the workstation name is not the host holding the address")
        if edge.get("source_ambiguous"):
            notes.append("the address was seen on several hosts")
        leads.append(_lead(
            "lateral",
            time=edge.get("first_seen"),
            last=edge.get("last_seen"),
            host=edge.get("target_host"),
            label=f"Remote logon {source} ({edge.get('source_ip')}) -> {edge.get('target_host')} as {account or '-'}",
            details={
                "from_hosts": edge.get("source_hosts"),
                "from_ip": edge.get("source_ip"),
                "workstation_name": edge.get("source_workstations"),
                "to_host": edge.get("target_host"),
                "account": account,
                "method": edge.get("method"),
                "succeeded": edge.get("successes"),
                "failed": edge.get("failures"),
                "notes": notes,
            },
            hosts=[edge["target_host"], *(edge.get("source_hosts") or [])],
            ips=[edge["source_ip"]],
            users=[edge["user"]] if edge.get("user") else [],
        ))
    return leads


def collect_leads(db: Session, case_id: str) -> tuple[list[dict[str, Any]], list[Finding], list[str]]:
    """Open leads in time order with references, the open findings, and the
    lead sources that could not be read."""
    findings = _open_findings(db, case_id)
    covered = {str(event_id) for finding in findings for event_id in [*(finding.event_ids or []), *(finding.related_event_ids or [])]}
    sources = (
        ("rule detections", lambda: _detection_leads(db, case_id, covered)),
        ("command history", lambda: _command_leads(db, case_id, covered)),
        ("memory", lambda: _memory_leads(db, case_id)),
        ("lateral movement", lambda: _lateral_leads(db, case_id)),
    )
    leads: list[dict[str, Any]] = []
    unavailable: list[str] = []
    for name, collect in sources:
        try:
            leads.extend(collect())
        except Exception:  # noqa: BLE001 -- suggest from the other sources
            logger.warning("finding suggestions: %s unavailable", name, exc_info=True)
            unavailable.append(name)
    leads.sort(key=lambda lead: (lead["time_utc"] is None, lead["time_utc"] or ""))
    for number, lead in enumerate(leads, start=1):
        lead["ref"] = f"L{number}"
    return leads, findings, unavailable


def _model_view(lead: dict[str, Any]) -> dict[str, Any]:
    return {key: lead[key] for key in ("ref", "kind", "time_utc", "last_utc", "host", "details") if lead.get(key) not in (None, {}, [])}


def suggest_findings(db: Session, case_id: str) -> dict[str, Any]:
    status = ai_draft_status(db)
    if not status.get("enabled"):
        raise FindingSuggestionsUnavailable("The AI assistant is not enabled. Configure a provider in AI settings to get suggestions.")
    leads, findings, unavailable = collect_leads(db, case_id)
    if not leads:
        raise FindingSuggestionsUnavailable(
            "There are no open leads to suggest from: no rule detections, suspicious commands, antivirus detections in memory, "
            "marked memory processes or remote logons outside the existing findings."
        )
    try:
        credentials = resolve_provider(db)
    except AIConfigError as exc:
        raise FindingSuggestionsUnavailable(str(exc)) from exc
    credentials = replace(credentials, max_tokens=max(credentials.max_tokens, DRAFT_MIN_TOKENS))
    material = {
        "leads": [_model_view(lead) for lead in leads],
        "existing_findings": [
            {"title": finding.title, "severity": _status_value(finding.severity), "mitre": tagged_techniques(finding.mitre or [])}
            for finding in findings[:MAX_EXISTING_FINDINGS]
        ],
    }
    system = SYSTEM_PROMPT.replace("{max}", str(MAX_SUGGESTIONS))
    # The model can take minutes: hold no transaction (and no lock) meanwhile.
    db.commit()
    text = complete(credentials, system=system, user="Open leads (JSON):\n" + json.dumps(material, ensure_ascii=False, default=str), what="suggestions")
    reply = parse_json_reply(text, "suggestions")
    provenance = {
        "provider": status["label"],
        "model": credentials.model,
        "hosting": status["hosting"],
        "generated_at": datetime.now(UTC).isoformat(),
        "prompt_version": PROMPT_VERSION,
    }
    suggestions, dropped = build_suggestions(reply.get("suggestions"), leads, provenance)
    counts: dict[str, int] = {}
    for lead in leads:
        counts[lead["kind"]] = counts.get(lead["kind"], 0) + 1
    return {
        "suggestions": suggestions,
        "dropped": dropped,
        "lead_counts": counts,
        "unavailable_sources": unavailable,
        "provenance": provenance,
    }


def _status_value(value: Any) -> str:
    return str(getattr(value, "value", value) or "")


def _dedupe(values: list[Any], limit: int | None = None) -> list[str]:
    output: list[str] = []
    for value in values:
        text = str(value or "").strip()
        if text and text not in output:
            output.append(text)
    return output[:limit] if limit else output


def _lead_refs(text: str) -> list[str]:
    """Lead references in ``text``, with ranges expanded."""
    refs: list[str] = []
    for match in _LEAD_RANGE.finditer(text):
        first, last = int(match.group(1)), int(match.group(2))
        if first <= last <= first + MAX_RANGE:
            refs.extend(f"L{number}" for number in range(first, last + 1))
    refs.extend(_LEAD_REF.findall(_LEAD_RANGE.sub(" ", text)))
    return refs


def _activity_range(times: list[str]) -> list[str]:
    """First and last time of the leads, or nothing when they span more than a
    year: each lead still shows its own times."""
    if not times:
        return []
    try:
        first = datetime.fromisoformat(times[0].replace("Z", "+00:00"))
        last = datetime.fromisoformat(times[-1].replace("Z", "+00:00"))
    except ValueError:
        return []
    return [times[0], times[-1]] if (last - first).days <= MAX_TIME_RANGE_DAYS else []


def build_suggestions(raw: Any, leads: list[dict[str, Any]], provenance: dict[str, Any]) -> tuple[list[dict[str, Any]], int]:
    """Checked suggestions with their links resolved from the cited leads, and
    how many the model proposed without a valid lead (dropped)."""
    by_ref = {lead["ref"]: lead for lead in leads}
    suggestions: list[dict[str, Any]] = []
    dropped = 0
    for item in (raw if isinstance(raw, list) else [])[:MAX_SUGGESTIONS]:
        if not isinstance(item, dict):
            dropped += 1
            continue
        title = _clip(item.get("title"), 200)
        description = str(item.get("description") or "").strip()[:4000]
        listed = [ref for value in (item.get("leads") if isinstance(item.get("leads"), list) else []) for ref in _lead_refs(str(value))]
        refs = _dedupe([*listed, *_lead_refs(description)])
        valid = [ref for ref in refs if ref in by_ref]
        if not title or not valid:
            dropped += 1
            continue
        used = [by_ref[ref] for ref in valid]
        issues = [{"kind": "unknown_citation", "value": ref} for ref in refs if ref not in by_ref]
        corpus = json.dumps([_model_view(lead) for lead in used], ensure_ascii=False, default=str)
        issues += [{"kind": "unsupported_fact", "value": value} for value in unsupported_facts(_LEAD_REF.sub(" ", _LEAD_RANGE.sub(" ", f"{title} {description}")), corpus, corpus_numbers(corpus))]
        severity = str(item.get("severity") or "").strip().lower()
        severity = severity if severity in FindingSeverity.__members__ else "medium"
        confidence = str(item.get("confidence") or "").strip().lower()
        confidence = confidence if confidence in _CONFIDENCE else None
        mitre = tagged_techniques([str(value) for value in item.get("mitre") or []] if isinstance(item.get("mitre"), list) else [str(item.get("mitre") or "")])
        backing = lambda key: [value for lead in used for value in lead["backing"].get(key) or []]  # noqa: E731
        evidence_ids = _dedupe(backing("evidence_ids"))
        times = _activity_range(sorted(time for lead in used for time in (lead["time_utc"], lead["last_utc"]) if time))
        suggestions.append({
            "title": title,
            "severity": severity,
            "confidence": confidence,
            "description": description,
            "mitre": mitre,
            "phase": primary_tactic(mitre),
            "leads": [{"ref": lead["ref"], "kind": lead["kind"], "time_utc": lead["time_utc"], "host": lead["host"], "label": lead["label"]} for lead in used],
            "issues": issues,
            "finding": {
                "title": title,
                "description": description,
                "severity": severity,
                "status": "new",
                "confidence": confidence,
                "mitre": mitre,
                "event_ids": _dedupe(backing("event_ids"), MAX_EVENT_IDS),
                "detection_ids": _dedupe(backing("detection_ids"), MAX_DETECTION_IDS),
                "related_hosts": _dedupe(backing("hosts")),
                "related_ips": _dedupe(backing("ips")),
                "related_users": _dedupe(backing("users")),
                "related_evidence_ids": evidence_ids,
                "linked_evidence_id": evidence_ids[0] if len(evidence_ids) == 1 else None,
                "time_start": times[0] if times else None,
                "time_end": times[-1] if times else None,
                "source": "ai_suggestion",
                "source_view": "ai_finding_suggestions",
                "source_label": f"Suggested by {provenance['provider']} ({provenance['model']})",
                "source_summary": "Leads: " + "; ".join(lead["label"] for lead in used)[:3900],
                "tags": ["ai-suggested"],
            },
        })
    return suggestions, dropped
