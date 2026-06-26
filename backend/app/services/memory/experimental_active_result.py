"""Active-result resolver for the experimental trust domain.

This module is the experimental counterpart of
``app/services/memory/active_result.py``.  The two resolvers
are intentionally separate: the validated resolver never
returns experimental runs, and the experimental resolver
never returns validated runs.  The two trust domains never
share a result.

The module is read-only: it never mutates any row.
"""
from __future__ import annotations

import logging
from typing import Any

from sqlalchemy import desc, func
from sqlalchemy.orm import Session

from app.models.memory import MemoryScanRun


logger = logging.getLogger(__name__)


# Statuses that count as a successful experimental outcome.
EXPERIMENTAL_TERMINAL_SUCCESS_STATUSES = {"completed", "completed_with_errors"}


def resolve_experimental_active_result(
    db: Session,
    *,
    case_id: str,
    evidence_id: str,
    experimental_run_id: str,
    family: str,
    page: int = 1,
    page_size: int = 50,
) -> dict[str, Any]:
    """Return the latest successful experimental run for a given
    ``(case, evidence, experimental_run_id, family)`` tuple.

    The function refuses to run when the trust filter cannot be
    applied.  The function never returns a validated run and
    never returns a run for a different case, evidence, or
    experimental run.
    """
    if not experimental_run_id:
        return {
            "case_id": case_id,
            "evidence_id": evidence_id,
            "artifact_family": family,
            "experimental_run_id": None,
            "active_run": None,
            "latest_attempt": None,
            "total": 0,
            "items": [],
            "page": page,
            "page_size": max(1, min(int(page_size or 50), 200)),
            "trust_level": "untrusted",
            "analysis_state": "experimental_run_id_required",
        }
    base_query = (
        db.query(MemoryScanRun)
        .filter(MemoryScanRun.case_id == case_id)
        .filter(MemoryScanRun.evidence_id == evidence_id)
        .filter(MemoryScanRun.experimental_run_id == experimental_run_id)
        # Trust boundary: the experimental resolver NEVER returns
        # validated runs.  Even if a row is mis-labelled the
        # function refuses to surface it.
        .filter(MemoryScanRun.trust_level == "untrusted")
        .filter(MemoryScanRun.analysis_mode == "experimental")
    )
    latest_attempt = (
        base_query.order_by(
            desc(MemoryScanRun.completed_at.is_(None)),
            desc(func.coalesce(MemoryScanRun.completed_at, MemoryScanRun.created_at)),
            desc(MemoryScanRun.created_at),
        )
        .first()
    )
    active_run = (
        base_query.filter(
            MemoryScanRun.status.in_(list(EXPERIMENTAL_TERMINAL_SUCCESS_STATUSES)),
        )
        .order_by(
            desc(func.coalesce(MemoryScanRun.completed_at, MemoryScanRun.created_at)),
            desc(MemoryScanRun.created_at),
        )
        .first()
    )
    if active_run is None:
        return {
            "case_id": case_id,
            "evidence_id": evidence_id,
            "artifact_family": family,
            "experimental_run_id": experimental_run_id,
            "active_run": None,
            "latest_attempt": _serialise(latest_attempt),
            "total": 0,
            "items": [],
            "page": page,
            "page_size": max(1, min(int(page_size or 50), 200)),
            "trust_level": "untrusted",
            "analysis_state": "no_experimental_active_run",
        }
    return {
        "case_id": case_id,
        "evidence_id": evidence_id,
        "artifact_family": family,
        "experimental_run_id": experimental_run_id,
        "active_run": _serialise(active_run),
        "latest_attempt": _serialise(latest_attempt),
        "total": 0,
        "items": [],
        "page": page,
        "page_size": max(1, min(int(page_size or 50), 200)),
        "trust_level": "untrusted",
        "analysis_state": "experimental_run_resolved",
    }


def _serialise(run: MemoryScanRun | None) -> dict[str, Any] | None:
    if run is None:
        return None
    return {
        "id": run.id,
        "profile": run.profile,
        "status": run.status,
        "trust_level": run.trust_level,
        "analysis_mode": run.analysis_mode,
        "symbol_match_type": getattr(run, "symbol_match_type", None),
        "started_at": run.started_at.isoformat() if run.started_at else None,
        "completed_at": run.completed_at.isoformat() if run.completed_at else None,
        "duration_ms": int(run.duration_ms or 0),
        "plugin_count": int(run.plugin_count or 0),
        "plugins_completed": int(run.plugins_completed or 0),
        "plugins_failed": int(run.plugins_failed or 0),
        "experimental_run_id": getattr(run, "experimental_run_id", None),
    }


def assert_experimental_view_filters(filters: dict[str, Any] | None) -> None:
    """Assert that the client filters cannot bypass the trust filter.

    The function is a defense-in-depth check.  Even if the
    caller tries to add ``trust_level = "validated"`` to the
    filters, the function rejects the request.  Routes that
    consume experimental data should call this function.
    """
    if not filters:
        return
    for forbidden in ("trust_level", "analysis_mode", "experimental_run_id"):
        if forbidden in filters:
            raise ValueError(
                f"experimental view forbids overriding the {forbidden!r} filter"
            )


__all__ = [
    "EXPERIMENTAL_TERMINAL_SUCCESS_STATUSES",
    "assert_experimental_view_filters",
    "resolve_experimental_active_result",
]
