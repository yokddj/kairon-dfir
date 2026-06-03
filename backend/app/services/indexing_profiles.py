from __future__ import annotations

from datetime import UTC, datetime
from typing import Any
from uuid import uuid4

INDEXING_PROFILES = {"recommended", "fast", "advanced_custom"}
ACTIVE_STATUSES = {"queued", "running", "processing", "pending"}


def normalize_indexing_profile(value: object | None) -> str:
    profile = str(value or "recommended").strip().lower()
    return profile if profile in INDEXING_PROFILES else "recommended"


def _status(metadata: dict[str, Any], *keys: str) -> str:
    for key in keys:
        value = str(metadata.get(key) or "").strip().lower()
        if value:
            return value
    return ""


def evidence_has_active_indexing(metadata: dict[str, Any] | None, ingest_status: object | None = None) -> tuple[bool, dict[str, Any] | None]:
    metadata = dict(metadata or {})
    ingest_value = str(getattr(ingest_status, "value", ingest_status) or "").strip().lower()
    if ingest_value in {"pending", "processing"}:
        return True, {
            "step": "core_ingest",
            "run_id": str(metadata.get("current_ingest_run_id") or metadata.get("latest_ingest_run_id") or ""),
            "status": ingest_value,
        }
    checks = [
        ("full_mft", _status(metadata, "mft_full_status", "mft_status")),
        ("user_activity", _status(metadata, "registry_user_activity_status")),
        ("defender", _status(metadata, "defender_evtx_status")),
        ("srum", _status(metadata, "srum_status")),
    ]
    current_plan = dict(metadata.get("indexing_plan_run") or {})
    if str(current_plan.get("status") or "").lower() in ACTIVE_STATUSES:
        return True, {
            "step": "indexing_plan",
            "run_id": str(current_plan.get("run_id") or ""),
            "status": str(current_plan.get("status") or ""),
        }
    for step, status in checks:
        if status in ACTIVE_STATUSES:
            return True, {"step": step, "run_id": "", "status": status}
    return False, None


def _step(
    step_id: str,
    name: str,
    *,
    category: str,
    status: str,
    reason: str = "",
    heavy: bool = False,
    endpoint: str | None = None,
) -> dict[str, Any]:
    return {
        "id": step_id,
        "name": name,
        "category": category,
        "status": status,
        "reason": reason,
        "heavy": heavy,
        "endpoint": endpoint,
    }


def build_indexing_plan(
    *,
    profile: object | None,
    metadata: dict[str, Any] | None,
    mft_diagnostic: dict[str, Any] | None = None,
    indexed_docs: int = 0,
    active: bool = False,
    active_job: dict[str, Any] | None = None,
) -> dict[str, Any]:
    metadata = dict(metadata or {})
    profile_name = normalize_indexing_profile(profile)
    mft = dict(mft_diagnostic or {})
    steps: list[dict[str, Any]] = []
    excluded: list[dict[str, str]] = []

    core_status = "completed" if indexed_docs > 0 or metadata.get("investigation_ready") else "ready"
    steps.append(_step("core_artifacts", "Core artifacts", category="core", status=core_status, reason="EVTX, browser, prefetch, scheduled tasks, services, LNK/Jumplist, Amcache/Shimcache default and normalized searchable events."))
    steps.append(_step("event_logs", "Event logs", category="core", status=core_status, reason="Sysmon, Security and PowerShell are normalized during core ingest."))
    steps.append(_step("command_history", "Command History", category="derived", status="completed" if indexed_docs > 0 else "ready", reason="Derived from indexed command/process/event evidence."))

    include_full_mft = profile_name == "recommended"
    if profile_name == "fast":
        if mft.get("mft_present_in_evidence"):
            steps.append(_step("mft_summary", "MFT summary", category="filesystem", status="ready", reason="Fast indexing avoids full filesystem expansion.", heavy=False, endpoint="mft-summary-index"))
        excluded.append({"name": "Full MFT", "reason": "Fast indexing skips full filesystem expansion."})
    elif include_full_mft:
        if not mft.get("mft_present_in_evidence"):
            steps.append(_step("mft_full", "Full MFT", category="filesystem", status="skipped_not_present", reason="No MFT source detected."))
        elif not mft.get("mft_backend_available", True):
            steps.append(_step("mft_full", "Full MFT", category="filesystem", status="skipped_tooling_missing", reason="MFTECmd backend is unavailable."))
        elif int(mft.get("mft_full_records_indexed") or 0) > 0 or str(mft.get("mft_coverage_status") or "").lower() == "full":
            steps.append(_step("mft_full", "Full MFT", category="filesystem", status="completed", reason="Full MFT is already indexed."))
        else:
            steps.append(_step("mft_full", "Full MFT", category="filesystem", status="ready", reason="Indexes all MFTECmd records so any file/path can be searched.", heavy=True, endpoint="mft-full-index"))

    user_activity_status = _status(metadata, "registry_user_activity_status")
    user_activity_count = int(metadata.get("registry_user_activity_records_indexed") or 0)
    steps.append(
        _step(
            "user_activity",
            "User Activity",
            category="user_activity",
            status="completed" if user_activity_count > 0 else user_activity_status if user_activity_status in ACTIVE_STATUSES else "ready",
            reason="RECmd selected artifacts: UserAssist, RecentDocs, RunMRU and OpenSaveMRU when hives are present.",
            endpoint="recmd-user-activity-index",
        )
    )

    defender_status = _status(metadata, "defender_evtx_status")
    defender_count = int(metadata.get("defender_evtx_docs_indexed") or 0)
    steps.append(
        _step(
            "defender",
            "Defender",
            category="defender",
            status="completed" if defender_count > 0 else defender_status if defender_status in ACTIVE_STATUSES else "ready",
            reason="Defender detections, remediation and configuration changes are indexed as a dedicated artifact.",
            endpoint="defender-evtx-index",
        )
    )

    steps.append(_step("motw", "MOTW / Zone.Identifier", category="downloaded_files", status="derived", reason="Derived from indexed MFT ADS and Sysmon Event ID 15; no separate parser run is required."))
    steps.append(_step("startup_persistence", "Startup & Persistence", category="derived", status="derived", reason="Derived view from scheduled tasks, services, registry events, Defender config and command evidence."))

    excluded.append({"name": "SRUM", "reason": "Requires Windows parser worker / Windows ESE libraries."})
    excluded.extend(
        [
            {"name": "Sigma rules", "reason": "Run selected rules or Sigma Smoke after indexing."},
            {"name": "Reports", "reason": "Generate after findings and reviewed evidence exist."},
            {"name": "EZ advanced rebuilds", "reason": "Advanced comparison backends; not default indexing."},
        ]
    )

    if profile_name == "advanced_custom":
        for item in steps:
            if item["id"] in {"mft_full", "user_activity", "defender"}:
                item["status"] = "advanced_available" if item["status"] == "ready" else item["status"]
        excluded = [{"name": "Automatic execution", "reason": "Advanced custom exposes individual actions instead of running a bundle."}]

    runnable_steps = [item for item in steps if item.get("status") == "ready" and item.get("endpoint")]
    return {
        "profile": profile_name,
        "label": {
            "recommended": "Recommended indexing",
            "fast": "Fast indexing",
            "advanced_custom": "Advanced custom",
        }[profile_name],
        "primary_cta": "Index evidence for investigation",
        "subcopy": "Recommended: indexes event logs, filesystem, user activity, Defender, downloaded-file evidence and core artifacts. Rules and reports are run later.",
        "steps": steps,
        "excluded": excluded,
        "runnable_steps": runnable_steps,
        "active": active,
        "active_job": active_job,
        "can_run": not active and profile_name != "advanced_custom" and bool(runnable_steps),
    }


def create_indexing_plan_run(plan: dict[str, Any], queued_jobs: list[dict[str, Any]]) -> dict[str, Any]:
    now = datetime.now(UTC).isoformat()
    run_id = str(uuid4())
    queued_by_step = {str(item.get("step_id")): item for item in queued_jobs}
    steps: list[dict[str, Any]] = []
    for step in list(plan.get("steps") or []):
        item = dict(step)
        queued = queued_by_step.get(str(item.get("id")))
        if queued:
            item["status"] = "queued"
            item["run_id"] = queued.get("run_id")
        steps.append(item)
    terminal = not queued_jobs
    return {
        "run_id": run_id,
        "profile": plan.get("profile"),
        "status": "completed" if terminal else "queued",
        "created_at": now,
        "updated_at": now,
        "steps": steps,
        "excluded": list(plan.get("excluded") or []),
        "queued_jobs": queued_jobs,
    }
