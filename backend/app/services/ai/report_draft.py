"""Draft a report's narrative with the configured AI provider.

The model only sees the curated material the report itself is built from
(confirmed findings, key and marked events, accepted Incident Timeline items,
IOCs, coverage notes, memory triage) -- never the raw index. It must cite every
fact: [F3] for a finding, [12:07:21] for a timeline event. The draft is checked
before the analyst sees it: citations must exist, and every IP address, time
and number in the text must appear in the material. Nothing is saved here; the
analyst reviews, edits and accepts the draft in the report builder.
"""

from __future__ import annotations

import json
import re
from datetime import UTC, datetime
from typing import Any

from sqlalchemy.orm import Session

from app.services.ai.config import PROVIDERS, AIConfigError, load_config, resolve_provider
from app.services.ai.providers import ProviderError, build_provider

PROMPT_VERSION = "report-draft-v1"
DRAFT_FIELDS = ("executive_summary", "attack_narrative", "recommendations", "limitations")

_LANGUAGE_NAMES = {"en": "English", "es": "Spanish (Spain)"}

SYSTEM_PROMPT = """You are a senior DFIR analyst writing the narrative parts of an incident report.
You are given the CURATED material of one case as JSON: findings an analyst confirmed (each with a reference F1, F2...), the analyst's timeline, indicators, coverage notes and memory triage.

Rules:
- Use ONLY facts present in the material. Do not add hosts, accounts, IP addresses, times, tools, counts or techniques that are not in it. If something is unknown, say it is not established.
- Cite every factual sentence: [F3] for a finding, or the timeline time as [HH:MM:SS] exactly as given in time_utc (time part only). A sentence may carry several citations.
- Times are UTC. Write times as HH:MM or HH:MM:SS exactly as they appear in the material.
- Automated detections are leads, not conclusions; do not present them as confirmed.
- Coverage notes and limitations must be reflected honestly; do not overstate certainty.
- Write in {language}. Plain prose, no headings. Markdown bold is allowed sparingly. Recommendations as a bulleted list ("- ") grouped by contain / credentials / eradicate / recover / harden where it applies.

Reply with ONLY a JSON object with these string fields:
"executive_summary": 2-3 short paragraphs for a non-technical reader: what happened, impact, current risk.
"attack_narrative": the attack in chronological order, phase by phase, for a technical reader.
"recommendations": bulleted list of actions derived from the findings.
"limitations": bulleted list of what the evidence does not establish (from coverage notes, gaps, unknowns)."""


class ReportDraftUnavailable(RuntimeError):
    """AI is not enabled or not configured."""


def ai_draft_status(db: Session) -> dict[str, Any]:
    config = load_config(db)
    active = config.get("active_provider")
    if not config.get("enabled") or not active or active not in PROVIDERS:
        return {"enabled": False}
    entry = config["providers"].get(active, {})
    return {
        "enabled": True,
        "provider": active,
        "label": PROVIDERS[active]["label"],
        "model": entry.get("model") or PROVIDERS[active]["default_model"],
        "hosting": PROVIDERS[active]["hosting"],
    }


def draft_report_narrative(db: Session, case_id: str, report_id: str) -> dict[str, Any]:
    from app.services.report_service import build_case_report_preview

    status = ai_draft_status(db)
    if not status.get("enabled"):
        raise ReportDraftUnavailable("The AI assistant is not enabled. Configure a provider in AI settings to draft with AI.")
    preview = build_case_report_preview(db, case_id, report_id, collect_ai_context=True)
    material = preview.get("ai_context") or {}
    if not material.get("findings") and not material.get("timeline"):
        raise ReportDraftUnavailable("There are no confirmed findings or timeline entries in this report to draft from.")
    try:
        credentials = resolve_provider(db)
    except AIConfigError as exc:
        raise ReportDraftUnavailable(str(exc)) from exc
    language = _LANGUAGE_NAMES.get(str(material.get("language") or "en"), "English")
    system = SYSTEM_PROMPT.replace("{language}", language)
    user = "Case material (JSON):\n" + json.dumps(material, ensure_ascii=False, default=str)
    text = ""
    for event in build_provider(credentials).stream_chat(system=system, messages=[{"role": "user", "content": user}], tools=None):
        if event.type == "text":
            text += event.text
        elif event.type == "error":
            raise ProviderError(event.text or "The AI provider returned an error.")
    draft = parse_draft(text)
    return {
        "draft": draft,
        "validation": validate_draft(draft, material),
        "provenance": {
            "provider": status["label"],
            "model": credentials.model,
            "hosting": status["hosting"],
            "generated_at": datetime.now(UTC).isoformat(),
            "prompt_version": PROMPT_VERSION,
        },
    }


def parse_draft(text: str) -> dict[str, str]:
    """The JSON object in the reply; tolerant of code fences or stray prose."""
    candidate = text.strip()
    fenced = re.search(r"```(?:json)?\s*(\{.*\})\s*```", candidate, re.DOTALL)
    if fenced:
        candidate = fenced.group(1)
    else:
        start, end = candidate.find("{"), candidate.rfind("}")
        if start != -1 and end > start:
            candidate = candidate[start : end + 1]
    try:
        data = json.loads(candidate)
    except json.JSONDecodeError as exc:
        raise ProviderError("The AI reply was not the expected JSON draft; try again.") from exc
    if not isinstance(data, dict):
        raise ProviderError("The AI reply was not the expected JSON draft; try again.")
    return {field: _as_text(data.get(field)) for field in DRAFT_FIELDS}


def _as_text(value: Any) -> str:
    if isinstance(value, list):
        return "\n".join(f"- {str(item).lstrip('- ').strip()}" for item in value if str(item).strip())
    return str(value or "").strip()


_CITATION = re.compile(r"\[([^\]\n]{1,40})\]")
_IPV4 = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
_TIME = re.compile(r"\b([01]\d|2[0-3]):[0-5]\d(?::[0-5]\d)?\b")
_NUMBER = re.compile(r"(?<![\w.:/\\-])\d{2,}(?:[.,]\d+)?(?![\w.:/\\-])")
_SENTENCE_BREAK = re.compile(r"(?<=[.!?])\s+|\n+")


def validate_draft(draft: dict[str, str], material: dict[str, Any]) -> dict[str, Any]:
    """Check citations and that concrete facts (IPs, times, numbers) appear in
    the material. Findings are leads for the analyst to fix, not errors."""
    corpus = json.dumps(material, ensure_ascii=False, default=str)
    corpus_numbers = set(_NUMBER.findall(corpus))
    finding_refs = {str(item.get("ref")) for item in material.get("findings") or []}
    event_times = {str(item.get("time_utc") or "")[11:19] for item in material.get("timeline") or [] if item.get("time_utc")}
    event_times |= {time[:5] for time in event_times}
    issues: list[dict[str, str]] = []
    for field, text in draft.items():
        if not text:
            continue
        for citation in _CITATION.findall(text):
            for ref in (part.strip() for part in re.split(r"[,;]", citation)):
                if re.fullmatch(r"F\d+", ref) and ref not in finding_refs:
                    issues.append({"field": field, "kind": "unknown_citation", "value": ref})
                elif _TIME.fullmatch(ref) and ref not in event_times:
                    issues.append({"field": field, "kind": "unknown_citation", "value": ref})
        uncited_text = _CITATION.sub(" ", text)
        for ip in sorted(set(_IPV4.findall(uncited_text))):
            if ip not in corpus:
                issues.append({"field": field, "kind": "unsupported_fact", "value": ip})
        for match in sorted({match.group(0) for match in _TIME.finditer(uncited_text)}):
            if match not in corpus:
                issues.append({"field": field, "kind": "unsupported_fact", "value": match})
        for number in sorted(set(_NUMBER.findall(uncited_text))):
            if number not in corpus_numbers and number.replace(",", "") not in corpus_numbers:
                issues.append({"field": field, "kind": "unsupported_fact", "value": number})
        if field in {"executive_summary", "attack_narrative"}:
            for sentence in _SENTENCE_BREAK.split(text):
                stripped = sentence.strip()
                if len(stripped) > 40 and not _CITATION.search(stripped):
                    issues.append({"field": field, "kind": "uncited_sentence", "value": stripped[:160]})
    return {"issues": issues, "ok": not any(issue["kind"] != "uncited_sentence" for issue in issues)}
