"""Translate a plain-language question into the query syntax Search's own box accepts.

Deliberately a single completion, not the agentic tool loop chat.py runs: the analyst
lands back in the normal Search page with an editable, rerunnable query -- not a prose
answer -- so there is no need for the model to look anything up itself. Grounded with
describe_case's real per-case facets so it doesn't invent a field value that was never
collected in this case.
"""

from __future__ import annotations

from sqlalchemy.orm import Session

from app.services.ai.config import resolve_provider
from app.services.ai.providers import build_provider
from app.services.ai.tools import QUERY_HELP, tool_describe_case

NL_QUERY_SYSTEM_PROMPT = (
    "You translate an analyst's question, asked in whatever language they used -- "
    "English, Spanish, or any other language -- into a single search query for "
    "Kairon's event search box. The query syntax itself (field names, operators) is "
    "always in English regardless of the question's language; only the field VALUES "
    "should reflect what the analyst actually typed (translated/transliterated only "
    "if needed to match a real value from the case, e.g. a host name). Reply with "
    "ONLY the query string on one line -- no explanation, no markdown formatting, no "
    "surrounding quotes. If the question is not actually a request to find specific "
    "data, reply with an empty string.\n\n"
    f"{QUERY_HELP}\n\n"
    "Ground field values in what this case actually contains, listed below -- do not "
    "invent an artifact.type or host.name absent from that list."
)


def translate_natural_language_query(db: Session, case_id: str, question: str, *, provider: str | None = None) -> str:
    question = str(question or "").strip()
    if not question:
        return ""

    described = tool_describe_case(db, case_id, {})
    system = f"{NL_QUERY_SYSTEM_PROMPT}\n\nThis case contains:\n{_facet_summary(described)}"

    credentials = resolve_provider(db, provider)
    client = build_provider(credentials)

    text = ""
    for event in client.stream_chat(system=system, messages=[{"role": "user", "content": question}], tools=None):
        if event.type == "text":
            text += event.text
    return _clean_query(text)


def _facet_summary(described: dict) -> str:
    if not described.get("indexed"):
        return "No events are indexed yet."
    lines = []
    for key in ("artifact_types", "hosts", "event_types"):
        values = described.get(key) or {}
        if values:
            lines.append(f"- {key}: {', '.join(sorted(values)[:20])}")
    return "\n".join(lines) if lines else "No facet data available."


def _clean_query(text: str) -> str:
    stripped = text.strip()
    if not stripped:
        return ""
    # Take the first line before stripping wrapper characters -- a stray
    # explanation line the model was told not to add otherwise ends up
    # trailing the real query instead of being discarded with it.
    first_line = stripped.splitlines()[0].strip().strip("`").strip()
    if len(first_line) > 1 and first_line[0] == first_line[-1] and first_line[0] in "\"'":
        first_line = first_line[1:-1].strip()
    return first_line
