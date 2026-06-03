from __future__ import annotations

from collections import Counter
from datetime import UTC, datetime
from typing import Any
from urllib.parse import urlencode


VALIDATION_RESULTS = [
    "found",
    "partial",
    "not_found",
    "memory_only",
    "not_present_in_evidence",
    "parser_gap",
    "ux_gap",
]

VALIDATION_CASE_MODES = {"demo", "training", "validation"}


def _summary(items: list[dict[str, Any]]) -> dict[str, Any]:
    by_result = Counter(str(item.get("result") or "unknown") for item in items)
    by_phase = Counter(str(item.get("phase") or "unknown") for item in items)
    by_host = Counter(str(item.get("host") or "unknown") for item in items)
    return {
        "total_expected": len(items),
        "found": by_result.get("found", 0),
        "partial": by_result.get("partial", 0),
        "not_found": by_result.get("not_found", 0),
        "memory_only": by_result.get("memory_only", 0),
        "not_present_in_evidence": by_result.get("not_present_in_evidence", 0),
        "parser_gap": by_result.get("parser_gap", 0),
        "ux_gap": by_result.get("ux_gap", 0),
        "by_result": dict(sorted(by_result.items())),
        "by_phase": dict(sorted(by_phase.items())),
        "by_host": dict(sorted(by_host.items())),
    }


def _search_url(case_id: str, item: dict[str, Any]) -> str | None:
    indicators = [str(value).strip() for value in item.get("expected_indicators") or [] if str(value).strip()]
    if not indicators:
        return None
    host = str(item.get("host") or "").strip()
    query: dict[str, str] = {"q": indicators[0]}
    if host and "->" not in host and host != "multi-host":
        query["host"] = host
    return f"/cases/{case_id}/search?{urlencode(query)}"


def _timeline_url(case_id: str, item: dict[str, Any]) -> str:
    query: dict[str, str] = {"phase": str(item.get("phase") or "")}
    host = str(item.get("host") or "").strip()
    if host and "->" not in host and host != "multi-host":
        query["host"] = host
    return f"/cases/{case_id}/incident-timeline?{urlencode({k: v for k, v in query.items() if v})}"


def _with_links(case_id: str, item: dict[str, Any]) -> dict[str, Any]:
    row = dict(item)
    row["case_id"] = case_id
    row["search_url"] = _search_url(case_id, row)
    row["timeline_url"] = _timeline_url(case_id, row)
    row.setdefault("docs_url", None)
    row.setdefault("created_at", datetime.now(UTC).isoformat())
    row.setdefault("updated_at", datetime.now(UTC).isoformat())
    return row


def _load_validation_items(case_id: str) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    # Main intentionally ships no concrete validation dataset. Demo/training datasets
    # can be imported or provided by deployment-specific packages.
    metadata = {
        "validation_id": None,
        "source_name": None,
        "source_urls": {},
        "source_parts": [],
    }
    return metadata, []


def get_validation_matrix(
    case_id: str,
    *,
    host: str | None = None,
    phase: str | None = None,
    result: str | None = None,
    source_part: str | None = None,
    memory_required: bool | None = None,
) -> dict[str, Any]:
    metadata, all_items_raw = _load_validation_items(case_id)
    all_items = [_with_links(case_id, item) for item in all_items_raw]
    items = list(all_items)
    if host:
        normalized = host.strip().lower()
        items = [item for item in items if normalized in str(item.get("host") or "").lower()]
    if phase:
        items = [item for item in items if str(item.get("phase") or "") == phase]
    if result:
        items = [item for item in items if str(item.get("result") or "") == result]
    if source_part:
        part = source_part.strip().upper()
        items = [item for item in items if part in {str(value).upper() for value in item.get("source_part") or []}]
    if memory_required is not None:
        items = [item for item in items if bool(item.get("memory_required")) is memory_required]
    warnings = [] if all_items else ["No validation dataset is bundled with this repository. Import a validation matrix for demo/training/QA workflows."]
    return {
        "case_id": case_id,
        "validation_id": metadata.get("validation_id"),
        "source_name": metadata.get("source_name"),
        "source_urls": metadata.get("source_urls") or {},
        "source_parts": metadata.get("source_parts") or [],
        "items": items,
        "summary": _summary(all_items),
        "filtered_summary": _summary(items),
        "filters": {
            "hosts": sorted({str(item.get("host") or "") for item in all_items}),
            "phases": sorted({str(item.get("phase") or "") for item in all_items}),
            "results": VALIDATION_RESULTS,
            "source_parts": metadata.get("source_parts") or [],
        },
        "generated_at": datetime.now(UTC).isoformat(),
        "warnings": warnings,
    }


def render_validation_matrix_markdown(matrix: dict[str, Any]) -> str:
    summary = matrix.get("summary") or {}
    lines = [
        "## Ground Truth Coverage",
        "",
        f"- Validation source: {matrix.get('source_name') or 'not available'}",
        f"- Total expected: {summary.get('total_expected', 0)}",
        f"- Found: {summary.get('found', 0)}",
        f"- Partial: {summary.get('partial', 0)}",
        f"- Memory-only: {summary.get('memory_only', 0)}",
        f"- Not present in evidence: {summary.get('not_present_in_evidence', 0)}",
        f"- Parser gaps: {summary.get('parser_gap', 0)}",
        "",
        "| ID | Phase | Host | Result | Title |",
        "|---|---|---|---|---|",
    ]
    for item in matrix.get("items") or []:
        lines.append(
            "| {finding_id} | {phase} | {host} | {result} | {title} |".format(
                finding_id=str(item.get("finding_id") or ""),
                phase=str(item.get("phase") or ""),
                host=str(item.get("host") or ""),
                result=str(item.get("result") or ""),
                title=str(item.get("title") or "").replace("|", "\\|"),
            )
        )
    gap_items = [item for item in matrix.get("items") or [] if item.get("result") in {"memory_only", "not_present_in_evidence", "parser_gap", "ux_gap"}]
    if gap_items:
        lines.extend(["", "### Gaps and Limits", ""])
        for item in gap_items:
            lines.append(f"- **{item.get('finding_id')}** `{item.get('result')}`: {item.get('notes') or item.get('description')}")
    return "\n".join(lines).strip() + "\n"


def effective_case_mode(case_id: str, stored_mode: str | None = None) -> str:
    mode = str(getattr(stored_mode, "value", stored_mode) or "investigation").strip().lower() or "investigation"
    if mode in {"investigation", "demo", "training", "validation"}:
        return mode
    return "investigation"


def case_has_validation_matrix(case_id: str) -> bool:
    _, items = _load_validation_items(case_id)
    return bool(items)


def should_show_validation_matrix(case_id: str, stored_mode: str | None = None, *, validation_mode_enabled: bool = False) -> bool:
    mode = effective_case_mode(case_id, stored_mode)
    return bool(validation_mode_enabled and mode in VALIDATION_CASE_MODES)


def validation_matrix_visibility(
    case_id: str,
    stored_mode: str | None = None,
    *,
    validation_mode_enabled: bool = False,
    demo_cases_enabled: bool = False,
) -> dict[str, Any]:
    mode = effective_case_mode(case_id, stored_mode)
    has_matrix = case_has_validation_matrix(case_id)
    visible = should_show_validation_matrix(case_id, stored_mode, validation_mode_enabled=validation_mode_enabled)
    reason = "validation_features_disabled"
    if visible and has_matrix:
        reason = "validation_matrix_available"
    elif visible:
        reason = "case_mode_enabled_without_matrix"
    elif mode not in VALIDATION_CASE_MODES:
        reason = "investigation_mode"
    return {
        "case_id": case_id,
        "mode": mode,
        "has_validation_matrix": has_matrix,
        "show_validation_matrix": visible,
        "demo_cases_enabled": bool(demo_cases_enabled),
        "validation_features_enabled": bool(validation_mode_enabled),
        "label": "Demo/training ground truth enabled" if visible else "Investigation case",
        "reason": reason,
    }
