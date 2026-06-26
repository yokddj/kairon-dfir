"""Canary phase for the experimental analysis flow.

The canary runs a minimal bounded set of Volatility plugins and
records per-check results onto the ``MemoryExperimentalRun``
row.  The canary is the gate that decides whether a full
experimental run may proceed.

Design rules:

* The canary NEVER mutates the exact symbol cache, the
  requirement, the validated runs, or the validated OpenSearch
  index.
* Every check returns a dict with ``name``, ``status``,
  ``detail`` and (optionally) ``value``; the canary status is
  derived from the aggregate of the checks.
* The status of the canary is one of ``pending``, ``running``,
  ``passed``, ``degraded``, ``failed``, ``inconclusive`` or
  ``skipped``.  The status ``passed`` does NOT mean "symbol
  compatibility proven"; it only means "the bounded checks
  produce structurally plausible output".

The actual plugin execution is delegated to the worker (the
canary shares the existing Volatility execution path) and the
canary is *read* by this module.
"""
from __future__ import annotations

import logging
import re
from datetime import datetime
from typing import Any

from sqlalchemy.orm import Session

from app.core.database import utc_now_naive
from app.models.memory import (
    MemoryExperimentalRun,
    MemoryScanRun,
)
from app.services.memory.experimental_trust import (
    CANARY_STATUS_DEGRADED,
    CANARY_STATUS_FAILED,
    CANARY_STATUS_INCONCLUSIVE,
    CANARY_STATUS_PASSED,
    CANARY_STATUS_PENDING,
    CANARY_STATUS_RUNNING,
)


logger = logging.getLogger(__name__)


# Canary check names.  Each check is implemented by a callable
# that takes the normalized plugin output (a list of dicts) and
# returns ``(status, detail, value)``.  ``status`` is one of
# ``passed``, ``degraded``, ``failed``, ``inconclusive``.
def _check_layer_construction(rows: list[dict[str, Any]]) -> tuple[str, str, Any]:
    if not rows:
        return "failed", "windows.info produced no output", None
    return "passed", "windows.info produced at least one row", len(rows)


def _check_kernel_base(rows: list[dict[str, Any]]) -> tuple[str, str, Any]:
    if not rows:
        return "failed", "no rows to read kernel base from", None
    kernel_base = rows[0].get("kernel_base") or rows[0].get("ntoskrnl_base")
    if not kernel_base:
        return "inconclusive", "kernel base is not present in the output", None
    return "passed", "kernel base is present", str(kernel_base)


def _check_pid_4_system(rows: list[dict[str, Any]]) -> tuple[str, str, Any]:
    if not rows:
        return "inconclusive", "no rows to check PID 4", None
    has_pid_4 = any(
        int(row.get("pid", -1)) == 4 for row in rows
    )
    if not has_pid_4:
        return "degraded", "PID 4 / System is not in the output", None
    return "passed", "PID 4 / System is present", True


def _check_printable_process_names(rows: list[dict[str, Any]]) -> tuple[str, str, Any]:
    if not rows:
        return "inconclusive", "no rows to inspect", None
    printable = re.compile(r"^[\x20-\x7e]+$")
    bad = [row for row in rows if not printable.match(str(row.get("name", "")))]
    ratio = len(bad) / len(rows) if rows else 0.0
    if ratio > 0.10:
        return "failed", f"{ratio:.0%} of process names are unprintable", ratio
    if ratio > 0.02:
        return "degraded", f"{ratio:.0%} of process names are unprintable", ratio
    return "passed", "process names are printable", ratio


def _check_pid_ranges(rows: list[dict[str, Any]]) -> tuple[str, str, Any]:
    if not rows:
        return "inconclusive", "no rows to inspect", None
    pids = [int(row.get("pid", -1)) for row in rows if row.get("pid") is not None]
    if not pids:
        return "inconclusive", "no PID column in output", None
    out_of_range = [pid for pid in pids if pid < 0 or pid > 100000]
    if out_of_range:
        return "degraded", f"{len(out_of_range)} PID(s) out of plausible range", len(out_of_range)
    return "passed", "PID ranges are plausible", len(pids)


def _check_timestamps(rows: list[dict[str, Any]]) -> tuple[str, str, Any]:
    if not rows:
        return "inconclusive", "no rows to inspect", None
    sample = 0
    parseable = 0
    for row in rows[:50]:
        ts = row.get("create_time") or row.get("created")
        if ts is None:
            continue
        sample += 1
        try:
            if isinstance(ts, str):
                datetime.fromisoformat(ts.replace("Z", "+00:00"))
            parseable += 1
        except (ValueError, AttributeError):
            continue
    if sample == 0:
        return "inconclusive", "no timestamp column in output", None
    ratio = parseable / sample
    if ratio < 0.5:
        return "failed", f"{ratio:.0%} of timestamps are unparseable", ratio
    return "passed", f"{parseable}/{sample} timestamps are parseable", ratio


def _check_malformed_ratio(rows: list[dict[str, Any]]) -> tuple[str, str, Any]:
    if not rows:
        return "inconclusive", "no rows to inspect", None
    # A row is considered malformed when one of the "must-have"
    # columns is missing or empty.
    required = ("pid", "name")
    bad = [
        row for row in rows
        if any(not str(row.get(key, "")).strip() for key in required)
    ]
    ratio = len(bad) / len(rows)
    if ratio > 0.30:
        return "failed", f"{ratio:.0%} of rows are malformed", ratio
    if ratio > 0.05:
        return "degraded", f"{ratio:.0%} of rows are malformed", ratio
    return "passed", "rows are structurally plausible", ratio


def _check_offsets_in_range(rows: list[dict[str, Any]]) -> tuple[str, str, Any]:
    if not rows:
        return "inconclusive", "no rows to inspect", None
    out_of_range = []
    for row in rows:
        addr = row.get("base_address") or row.get("offset")
        if addr is None:
            continue
        try:
            value = int(addr, 0) if isinstance(addr, str) else int(addr)
        except (TypeError, ValueError):
            out_of_range.append(addr)
            continue
        if not (0xFFFF000000000000 <= value <= 0xFFFFFFFFFFFFFFFF):
            out_of_range.append(value)
    if not out_of_range:
        return "passed", "addresses are within plausible memory-layer range", None
    return "degraded", f"{len(out_of_range)} address(es) out of plausible range", len(out_of_range)


CANARY_CHECKS: list[tuple[str, Any]] = [
    ("layer_construction", _check_layer_construction),
    ("kernel_base_present", _check_kernel_base),
    ("pid_4_system", _check_pid_4_system),
    ("printable_process_names", _check_printable_process_names),
    ("pid_ranges", _check_pid_ranges),
    ("timestamps_parseable", _check_timestamps),
    ("malformed_ratio", _check_malformed_ratio),
    ("offsets_in_range", _check_offsets_in_range),
]


def _coerce_rows(plugin_rows: dict[str, list[dict[str, Any]]] | None, plugin: str, fallback: list[dict[str, Any]]) -> list[dict[str, Any]]:
    if plugin_rows and plugin in plugin_rows:
        return [item for item in plugin_rows[plugin] if isinstance(item, dict)]
    return [item for item in fallback if isinstance(item, dict)]


def _check_cross_plugin_overlap(plugin_rows: dict[str, list[dict[str, Any]]]) -> tuple[str, str, Any]:
    pslist_rows = _coerce_rows(plugin_rows, "windows.pslist", [])
    psscan_rows = _coerce_rows(plugin_rows, "windows.psscan", [])
    pslist = {int(row.get("pid", -1)) for row in pslist_rows if row.get("pid") is not None}
    psscan = {int(row.get("pid", -1)) for row in psscan_rows if row.get("pid") is not None}
    if not pslist or not psscan:
        return "inconclusive", "pslist/psscan overlap could not be evaluated", None
    overlap = len(pslist & psscan) / max(1, len(pslist | psscan))
    if overlap < 0.20:
        return "failed", f"cross-plugin process overlap too low ({overlap:.0%})", overlap
    if overlap < 0.50:
        return "degraded", f"cross-plugin process overlap is limited ({overlap:.0%})", overlap
    return "passed", "cross-plugin process overlap is plausible", overlap


def _check_plugin_failure_ratio(plugin_results: dict[str, dict[str, Any]]) -> tuple[str, str, Any]:
    if not plugin_results:
        return "inconclusive", "no plugin execution results recorded", None
    total = len(plugin_results)
    failures = sum(1 for item in plugin_results.values() if item.get("status") not in {"completed"})
    ratio = failures / total
    if ratio >= 0.5:
        return "failed", f"{failures}/{total} canary plugins failed", ratio
    if ratio > 0:
        return "degraded", f"{failures}/{total} canary plugins failed", ratio
    return "passed", "all canary plugins executed successfully", ratio


def evaluate_canary(
    *,
    rows: list[dict[str, Any]],
    plugin_rows: dict[str, list[dict[str, Any]]] | None = None,
    plugin_results: dict[str, dict[str, Any]] | None = None,
    now: datetime | None = None,
) -> dict[str, Any]:
    """Return a dict with the canary aggregate and per-check details.

    The returned dict is what gets persisted on
    ``MemoryExperimentalRun.canary_checks`` and
    ``MemoryExperimentalRun.canary_summary``.
    """
    now = now or utc_now_naive()
    checks: list[dict[str, Any]] = []
    for name, fn in CANARY_CHECKS:
        try:
            local_rows = rows
            if plugin_rows:
                if name == "layer_construction":
                    local_rows = _coerce_rows(plugin_rows, "windows.info", rows)
                elif name in {"pid_4_system", "printable_process_names", "pid_ranges", "timestamps_parseable", "malformed_ratio"}:
                    local_rows = _coerce_rows(plugin_rows, "windows.pslist", rows)
                elif name == "offsets_in_range":
                    local_rows = _coerce_rows(plugin_rows, "windows.modules", rows)
            status, detail, value = fn(local_rows)
        except Exception as exc:  # noqa: BLE001
            status = "inconclusive"
            detail = f"check raised {type(exc).__name__}: {exc}"
            value = None
        checks.append(
            {
                "name": name,
                "status": status,
                "detail": detail,
                "value": value,
            }
        )
    if plugin_rows:
        for name, status, detail, value in [
            ("cross_plugin_process_overlap", *_check_cross_plugin_overlap(plugin_rows)),
            ("plugin_failure_ratio", *_check_plugin_failure_ratio(plugin_results or {})),
        ]:
            checks.append({"name": name, "status": status, "detail": detail, "value": value})
    aggregate = _aggregate_status(checks)
    score = _score(checks)
    summary = {
        "aggregate_status": aggregate,
        "score": score,
        "checks_total": len(checks),
        "checks_passed": sum(1 for c in checks if c["status"] == "passed"),
        "checks_degraded": sum(1 for c in checks if c["status"] == "degraded"),
        "checks_failed": sum(1 for c in checks if c["status"] == "failed"),
        "checks_inconclusive": sum(1 for c in checks if c["status"] == "inconclusive"),
        "evaluated_at": now.isoformat(),
    }
    return {
        "checks": checks,
        "summary": summary,
        "status": aggregate,
        "score": score,
    }


def _aggregate_status(checks: list[dict[str, Any]]) -> str:
    statuses = {c["status"] for c in checks}
    if "failed" in statuses:
        return CANARY_STATUS_FAILED
    if statuses == {"passed"}:
        return CANARY_STATUS_PASSED
    if "inconclusive" in statuses and "passed" not in statuses and "degraded" not in statuses:
        return CANARY_STATUS_INCONCLUSIVE
    return CANARY_STATUS_DEGRADED


def _score(checks: list[dict[str, Any]]) -> float:
    weights = {"passed": 1.0, "degraded": 0.5, "inconclusive": 0.25, "failed": 0.0}
    if not checks:
        return 0.0
    total = sum(weights.get(c["status"], 0.0) for c in checks)
    return round(total / len(checks), 4)


def persist_canary_result(
    db: Session,
    run: MemoryExperimentalRun,
    result: dict[str, Any],
) -> MemoryExperimentalRun:
    """Persist a canary result onto a run row.

    The function updates ``canary_status``, ``canary_score``,
    ``canary_checks``, ``canary_summary``, ``canary_completed_at``
    and the related flags.  It does NOT change the run
    ``status``; the lifecycle controller decides whether the
    canary outcome promotes the run to a full profile.
    """
    run.canary_status = result["status"]
    run.canary_score = result["score"]
    run.canary_checks = list(result["checks"])
    run.canary_summary = dict(result["summary"])
    run.canary_completed_at = utc_now_naive()
    # Canary override requirement: the operator must explicitly
    # accept a degraded or inconclusive canary before a full
    # run may proceed.  The endpoint that consumes the override
    # writes ``canary_override_at``.
    if result["status"] in {CANARY_STATUS_DEGRADED, CANARY_STATUS_INCONCLUSIVE}:
        run.canary_override_required = True
    else:
        run.canary_override_required = False
        run.canary_override_at = utc_now_naive()
        run.canary_override_actor = "system"
        run.canary_override_reason = (
            "not_required" if result["status"] == CANARY_STATUS_PASSED else "n/a"
        )
    db.add(run)
    db.commit()
    db.refresh(run)
    return run


def latest_canary_status(run: MemoryExperimentalRun) -> str:
    """Return the most recent canary status of a run."""
    return str(getattr(run, "canary_status", CANARY_STATUS_PENDING) or CANARY_STATUS_PENDING)


def assert_canary_runnable(run: MemoryExperimentalRun) -> None:
    """Raise ``ValueError`` when the run is not in a state that
    allows a canary to be enqueued.

    The function is the single guard for "may we enqueue a
    canary" callers.
    """
    if run.status not in {
        "acknowledgement_required",
        "canary_queued",
        "canary_running",
    }:
        raise ValueError(
            f"Run is in status {run.status!r}; the canary can only be enqueued "
            "for a freshly created run."
        )


def is_run_passed_canary(run: MemoryExperimentalRun) -> bool:
    return run.canary_status == CANARY_STATUS_PASSED


def is_run_degraded_canary(run: MemoryExperimentalRun) -> bool:
    return run.canary_status == CANARY_STATUS_DEGRADED


def is_run_failed_canary(run: MemoryExperimentalRun) -> bool:
    return run.canary_status in {CANARY_STATUS_FAILED, CANARY_STATUS_INCONCLUSIVE}


__all__ = [
    "CANARY_CHECKS",
    "assert_canary_runnable",
    "evaluate_canary",
    "is_run_degraded_canary",
    "is_run_failed_canary",
    "is_run_passed_canary",
    "latest_canary_status",
    "persist_canary_result",
]
