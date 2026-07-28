from __future__ import annotations

from collections import Counter, defaultdict
from datetime import timezone
from typing import Any

from sqlalchemy import func
from sqlalchemy.orm import Session

from app.core.database import utc_now_naive
from app.models.artifact import Artifact
from app.models.case import Case
from app.models.case_host import CaseHost
from app.models.detection_result import DetectionResult
from app.models.evidence import Evidence, EvidenceType
from app.models.finding import Finding
from app.models.memory import MemoryArtifactSummary, MemoryPluginRun, MemoryScanRun


REGISTRY_VERSION = "2026.07.phase3"
OS_PLATFORMS = {"windows", "linux", "macos", "unknown"}
SHIPPED_PLATFORMS = {"windows", "linux"}


CAPABILITY_REGISTRY: list[dict[str, Any]] = [
    {
        "id": "windows.execution.command_history",
        "platform": "windows",
        "evidence_domain": "filesystem",
        "domain": "execution",
        "title": "Command History",
        "route": "/cases/:caseId/w/execution/command-history",
        "artifact_families": ["powershell_activity", "powershell_execution", "process_execution", "windows_event"],
        "nav": {"parent": "windows/execution", "order": 10},
        "overview": {"priority": 20, "featured": True, "quick_action": "Open Command History"},
        "search": {"priority": 20, "group": "Execution", "tags": ["commands", "process"], "action_tags": ["command_history"], "default_filters": {"platform": "windows", "artifact_type": ["powershell_activity", "powershell_execution", "process_execution", "windows_event"]}, "preferred_sort": "timestamp_desc", "filters": [], "presets": [{"title": "Windows command activity", "state": {"platform": "windows", "artifact_type": ["powershell_activity", "powershell_execution", "process_execution", "windows_event"]}}]},
        "availability": "shipped",
        "readiness_source": "artifact_counts",
    },
    {
        "id": "windows.execution.stories",
        "platform": "windows",
        "evidence_domain": "filesystem",
        "domain": "execution",
        "title": "Execution Stories",
        "route": "/cases/:caseId/w/execution/stories",
        "artifact_families": ["program_executions", "execution_candidates", "windows_event", "prefetch"],
        "nav": {"parent": "windows/execution", "order": 20},
        "overview": {"priority": 10, "featured": True, "quick_action": "Open Execution Stories"},
        "search": {"priority": 10, "group": "Execution", "tags": ["process", "execution_story"], "action_tags": ["execution_story"], "default_filters": {"platform": "windows", "artifact_type": ["program_executions", "execution_candidates", "windows_event", "prefetch"]}, "preferred_sort": "timestamp_desc", "filters": [], "presets": [{"title": "Windows execution stories", "state": {"platform": "windows", "artifact_type": ["program_executions", "execution_candidates", "windows_event", "prefetch"]}}]},
        "availability": "shipped",
        "readiness_source": "artifact_counts",
    },
    {
        "id": "windows.persistence.overview",
        "platform": "windows",
        "evidence_domain": "filesystem",
        "domain": "persistence",
        "title": "Persistence",
        "route": "/cases/:caseId/findings?preset=persistence",
        "artifact_families": ["scheduled_task", "service", "registry_run_key", "autoruns"],
        "nav": {"parent": "windows/persistence", "order": 10},
        "overview": {"priority": 30, "featured": True, "quick_action": "Review Persistence"},
        "search": {"priority": 30, "group": "Persistence", "tags": ["persistence", "registry"], "default_filters": {"platform": "windows", "artifact_type": ["scheduled_task", "service", "registry_run_key", "autoruns"]}, "preferred_sort": "risk_desc", "filters": [], "presets": [{"title": "Windows persistence", "state": {"platform": "windows", "artifact_type": ["scheduled_task", "service", "registry_run_key", "autoruns"]}}]},
        "availability": "shipped",
        "readiness_source": "artifact_counts",
    },
    {
        "id": "linux.access.authentication",
        "platform": "linux",
        "evidence_domain": "filesystem",
        "domain": "access",
        "title": "Authentication",
        "route": "/cases/:caseId/l/access/authentication",
        "artifact_families": ["linux_auth"],
        "nav": {"parent": "linux/access", "order": 10},
        "overview": {"priority": 10, "featured": True, "quick_action": "Open Authentication"},
        "search": {
            "priority": 10,
            "group": "Access",
            "tags": ["authentication", "ssh", "login"],
            "default_filters": {"platform": "linux", "artifact_type": ["linux_auth"]},
            "preferred_sort": "timestamp_desc",
            "filters": [
                {"key": "auth.outcome", "type": "enum", "values": ["success", "failure"]},
                {"key": "auth.remote_ip", "type": "ip"},
            ],
            "presets": [{"title": "Failed SSH logins", "state": {"platform": "linux", "artifact_type": ["linux_auth"], "q": "Failed password"}}],
        },
        "availability": "shipped",
        "readiness_source": "artifact_counts",
    },
    {
        "id": "linux.execution.command_history",
        "platform": "linux",
        "evidence_domain": "filesystem",
        "domain": "execution",
        "title": "Command History",
        "route": "/cases/:caseId/l/execution/command-history",
        "artifact_families": ["linux_shell_history"],
        "nav": {"parent": "linux/execution", "order": 10},
        "overview": {"priority": 20, "featured": True, "quick_action": "Open Command History"},
        "search": {"priority": 20, "group": "Execution", "tags": ["commands", "shell"], "action_tags": ["command_history"], "default_filters": {"platform": "linux", "artifact_type": ["linux_shell_history"]}, "preferred_sort": "timestamp_desc", "filters": [], "presets": [{"title": "Linux shell commands", "state": {"platform": "linux", "artifact_type": ["linux_shell_history"]}}]},
        "availability": "shipped",
        "readiness_source": "artifact_counts",
    },
    {
        "id": "linux.software.packages",
        "platform": "linux",
        "evidence_domain": "filesystem",
        "domain": "software",
        "title": "Packages",
        "route": "/cases/:caseId/artifacts?artifact_type=linux_packages",
        "artifact_families": ["linux_packages"],
        "nav": {"parent": "linux/software", "order": 10},
        "overview": {"priority": 50, "featured": False, "quick_action": "Review Packages"},
        "search": {"priority": 50, "group": "Software", "tags": ["packages", "software"], "default_filters": {"platform": "linux", "artifact_type": ["linux_packages"]}, "preferred_sort": "timestamp_desc", "filters": [], "presets": [{"title": "Linux packages", "state": {"platform": "linux", "artifact_type": ["linux_packages"]}}]},
        "availability": "shipped",
        "readiness_source": "artifact_counts",
    },
    {
        "id": "memory.overview",
        "platform": "memory",
        "evidence_domain": "memory",
        "domain": "execution",
        "title": "Overview",
        "route": "/cases/:caseId/m",
        "artifact_families": ["processes", "network", "modules", "handles", "vads"],
        "nav": {"parent": "memory/overview", "order": 5},
        "overview": {"priority": 5, "featured": True, "quick_action": "Open Memory Images"},
        "search": {"priority": 5, "group": "Memory", "tags": ["memory", "overview"], "default_filters": {"source_category": "Memory", "artifact_type": ["processes", "network", "modules", "handles", "vads"]}, "preferred_sort": "timestamp_desc", "filters": [], "presets": [{"title": "Memory evidence", "state": {"source_category": "Memory", "artifact_type": ["processes", "network", "modules", "handles", "vads"]}}]},
        "availability": "shipped",
        "readiness_source": "memory_artifact_counts",
    },
    {
        "id": "memory.processes",
        "platform": "memory",
        "evidence_domain": "memory",
        "domain": "execution",
        "title": "Processes",
        "route": "/cases/:caseId/m/:evidenceId/processes",
        "artifact_families": ["processes"],
        "nav": {"parent": "memory/execution", "order": 10},
        "overview": {"priority": 10, "featured": True, "quick_action": "Open Processes"},
        "search": {"priority": 10, "group": "Execution", "tags": ["memory", "process"], "default_filters": {"source_category": "Memory", "artifact_type": ["processes"]}, "preferred_sort": "timestamp_desc", "filters": [], "presets": [{"title": "Memory processes", "state": {"source_category": "Memory", "artifact_type": ["processes"]}}]},
        "availability": "shipped",
        "readiness_source": "memory_artifact_counts",
    },
    {
        "id": "memory.network",
        "platform": "memory",
        "evidence_domain": "memory",
        "domain": "network",
        "title": "Network",
        "route": "/cases/:caseId/m/:evidenceId/network",
        "artifact_families": ["network"],
        "nav": {"parent": "memory/network", "order": 10},
        "overview": {"priority": 30, "featured": True, "quick_action": "Open Network"},
        "search": {"priority": 30, "group": "Network", "tags": ["memory", "network"], "default_filters": {"source_category": "Memory", "artifact_type": ["network"]}, "preferred_sort": "timestamp_desc", "filters": [], "presets": [{"title": "Memory network", "state": {"source_category": "Memory", "artifact_type": ["network"]}}]},
        "availability": "shipped",
        "readiness_source": "memory_artifact_counts",
    },
]


def capability_route(capability_id: str, case_id: str, *, evidence_id: str | None = None) -> str:
    for capability in CAPABILITY_REGISTRY:
        if capability["id"] != capability_id:
            continue
        route = str(capability["route"]).replace(":caseId", case_id)
        if evidence_id is not None:
            route = route.replace(":evidenceId", evidence_id)
        if ":evidenceId" in route:
            raise ValueError(f"Capability route {capability_id} requires evidence_id")
        return route
    raise KeyError(f"Unknown capability route: {capability_id}")


def _processing_state(status_counts: Counter[str]) -> str:
    if any(status_counts.get(status, 0) for status in ("failed", "completed_with_errors")):
        return "failed"
    if any(status_counts.get(status, 0) for status in ("processing", "pending")):
        return "processing"
    if status_counts:
        return "ready"
    return "empty"


def _overview_route(workbench_id: str, case_id: str) -> str:
    return f"/cases/{case_id}/{'m' if workbench_id == 'memory' else workbench_id[0]}"


def _route_for_capability(capability: dict[str, Any], case_id: str, evidence_id: str | None = None) -> str:
    route = str(capability["route"]).replace(":caseId", case_id)
    if evidence_id:
        route = route.replace(":evidenceId", evidence_id)
    if ":evidenceId" in route:
        return f"/cases/{case_id}/m"
    return route


def _activity_row(kind: str, title: str, route: str, timestamp: Any = None) -> dict[str, Any]:
    return {"kind": kind, "title": title, "route": route, "timestamp": _iso(timestamp)}


def _workbench_evidence(evidence_payloads: list[dict[str, Any]], workbench_id: str) -> list[dict[str, Any]]:
    return [
        item
        for item in evidence_payloads
        if (item["evidence_domain"] == "memory" if workbench_id == "memory" else item["platform"] == workbench_id and item["evidence_domain"] != "memory")
    ]


def _build_quick_actions(visible_capabilities: list[dict[str, Any]], case_id: str, workbench_evidence: list[dict[str, Any]]) -> list[dict[str, Any]]:
    actions = []
    first_memory_evidence = next((item["id"] for item in workbench_evidence if item["evidence_domain"] == "memory"), None)
    for capability in sorted(visible_capabilities, key=lambda item: (item.get("overview") or {}).get("priority", item.get("nav", {}).get("order", 999))):
        overview = capability.get("overview") or {}
        if not overview.get("featured"):
            continue
        actions.append(
            {
                "id": capability["id"],
                "label": overview.get("quick_action") or capability["title"],
                "route": _route_for_capability(capability, case_id, first_memory_evidence),
                "priority": overview.get("priority", capability.get("nav", {}).get("order", 999)),
            }
        )
    return actions


def _build_warnings(workbench_id: str, status_counts: Counter[str], visible_capabilities: list[dict[str, Any]], workbench_evidence: list[dict[str, Any]], memory_plugin_statuses: dict[str, int]) -> list[dict[str, Any]]:
    warnings = []
    for status in ("failed", "completed_with_errors"):
        count = status_counts.get(status, 0)
        if count:
            warnings.append({"id": f"{workbench_id}.evidence.{status}", "severity": "critical" if status == "failed" else "warning", "title": "Evidence processing needs attention", "detail": f"{count} evidence item(s) are {status.replace('_', ' ')}."})
    for capability in visible_capabilities:
        if capability["readiness"] == "degraded":
            warnings.append({"id": f"{capability['id']}.degraded", "severity": "warning", "title": f"{capability['title']} is degraded", "detail": "Some parser or plugin results are incomplete."})
        if capability["readiness"] == "failed":
            warnings.append({"id": f"{capability['id']}.failed", "severity": "critical", "title": f"{capability['title']} failed", "detail": "Processing failed for this capability."})
    if workbench_id == "memory":
        unassigned = sum(1 for item in workbench_evidence if not item.get("host_id"))
        if unassigned:
            warnings.append({"id": "memory.host_unresolved", "severity": "warning", "title": "Memory host association missing", "detail": f"{unassigned} memory image(s) are not assigned to a host."})
        failed_plugins = memory_plugin_statuses.get("failed", 0) + memory_plugin_statuses.get("timed_out", 0)
        if failed_plugins:
            warnings.append({"id": "memory.plugin_failures", "severity": "warning", "title": "Memory plugin failures", "detail": f"{failed_plugins} plugin run(s) failed or timed out."})
    return warnings


def _recent_activity_for_workbench(case_id: str, workbench_evidence_ids: set[str], recent_detections: list[DetectionResult], recent_findings: list[Finding]) -> list[dict[str, Any]]:
    activity = []
    for detection in recent_detections:
        if detection.evidence_id and detection.evidence_id not in workbench_evidence_ids:
            continue
        activity.append(_activity_row("detection", detection.rule_title or detection.rule_name, f"/cases/{case_id}/detections?detection_id={detection.id}", detection.created_at))
    for finding in recent_findings:
        related_ids = {value for value in [finding.evidence_id, finding.linked_evidence_id] if value}
        if related_ids and not related_ids.intersection(workbench_evidence_ids):
            continue
        activity.append(_activity_row("finding", finding.title, f"/cases/{case_id}/findings?finding_id={finding.id}", finding.updated_at))
    return sorted(activity, key=lambda item: item.get("timestamp") or "", reverse=True)[:6]


def _memory_images_for_workbench(db: Session, case_id: str, workbench_evidence: list[dict[str, Any]], evidence_models: dict[str, Evidence]) -> list[dict[str, Any]]:
    summaries_by_evidence: dict[str, int] = defaultdict(int)
    for summary in db.query(MemoryArtifactSummary.evidence_id, func.coalesce(func.sum(MemoryArtifactSummary.count), 0)).filter(MemoryArtifactSummary.case_id == case_id).group_by(MemoryArtifactSummary.evidence_id).all():
        summaries_by_evidence[str(summary[0])] = int(summary[1] or 0)
    run_status_by_evidence: dict[str, Counter[str]] = defaultdict(Counter)
    for evidence_id, status, count in db.query(MemoryScanRun.evidence_id, MemoryScanRun.status, func.count(MemoryScanRun.id)).filter(MemoryScanRun.case_id == case_id).group_by(MemoryScanRun.evidence_id, MemoryScanRun.status).all():
        run_status_by_evidence[str(evidence_id)][_status(status)] = int(count or 0)
    images = []
    for item in workbench_evidence:
        metadata = _json_dict(evidence_models[item["id"]].metadata_json if item["id"] in evidence_models else {})
        images.append({
            "id": item["id"],
            "name": item["name"],
            "host_id": item.get("host_id"),
            "detected_host": item.get("detected_host"),
            "detected_os": item.get("platform"),
            "preparation_state": item.get("ingest_status"),
            "symbol_state": metadata.get("symbol_state") or metadata.get("symbol_readiness") or "unknown",
            "plugin_record_count": summaries_by_evidence.get(item["id"], 0),
            "run_status_counts": dict(run_status_by_evidence.get(item["id"], Counter())),
            "route": f"/cases/{case_id}/m/{item['id']}/overview",
        })
    return images


def _search_state_items(value: Any) -> list[str]:
    if isinstance(value, list):
        return [str(item) for item in value if str(item)]
    if value:
        return [str(value)]
    return []


def _build_search_metadata(capabilities: list[dict[str, Any]], workbenches: list[dict[str, Any]]) -> dict[str, Any]:
    visible_capabilities = [capability for capability in capabilities if capability.get("visible")]
    capability_lookup = {capability["id"]: capability for capability in visible_capabilities}
    facets = {
        "workbench": [],
        "domain": [],
        "capability": [],
        "platform": [],
        "source_category": [],
        "artifact_type": [],
    }
    platform_counts: Counter[str] = Counter()
    source_counts: Counter[str] = Counter()
    artifact_counts: Counter[str] = Counter()
    domain_counts: Counter[tuple[str, str]] = Counter()
    presets = []

    for workbench in workbenches:
        workbench_capabilities = [capability_lookup[capability_id] for capability_id in workbench["capability_ids"] if capability_id in capability_lookup]
        facets["workbench"].append({"id": workbench["id"], "label": workbench["label"], "count": sum(capability.get("record_count", 0) for capability in workbench_capabilities)})
        for domain in workbench["domains"]:
            domain_capabilities = [capability_lookup[capability_id] for capability_id in domain["capability_ids"] if capability_id in capability_lookup]
            domain_counts[(workbench["id"], domain["id"])] += sum(capability.get("record_count", 0) for capability in domain_capabilities)

    for capability in visible_capabilities:
        search = capability.get("search") or {}
        default_filters = search.get("default_filters") or {}
        platform_counts.update(_search_state_items(default_filters.get("platform")))
        source_counts.update(_search_state_items(default_filters.get("source_category")))
        artifact_counts.update(_search_state_items(default_filters.get("artifact_type")))
        facets["capability"].append({"id": capability["id"], "label": capability["title"], "workbench": "memory" if capability["evidence_domain"] == "memory" else capability["platform"], "domain": capability["domain"], "count": capability.get("record_count", 0)})
        for preset in search.get("presets") or []:
            presets.append({"id": f"{capability['id']}:{preset.get('title', capability['title'])}", "label": preset.get("title") or capability["title"], "capability_id": capability["id"], "workbench": "memory" if capability["evidence_domain"] == "memory" else capability["platform"], "domain": capability["domain"], "state": preset.get("state") or {}})

    facets["domain"] = [{"id": domain_id, "label": domain_id.replace("_", " ").title(), "workbench": workbench_id, "count": count} for (workbench_id, domain_id), count in sorted(domain_counts.items())]
    facets["platform"] = [{"id": key, "label": key.title(), "count": count} for key, count in sorted(platform_counts.items())]
    facets["source_category"] = [{"id": key, "label": key, "count": count} for key, count in sorted(source_counts.items())]
    facets["artifact_type"] = [{"id": key, "label": key.replace("_", " ").title(), "count": count} for key, count in sorted(artifact_counts.items())]
    presets.sort(key=lambda item: (item["workbench"], item["domain"], item["label"]))
    return {"facets": facets, "presets": presets}


def _value(value: Any) -> str:
    return str(getattr(value, "value", value or ""))


def _json_dict(value: Any) -> dict[str, Any]:
    return value if isinstance(value, dict) else {}


def _evidence_domain(evidence: Evidence) -> str:
    if _value(evidence.evidence_type) == EvidenceType.memory_dump.value:
        return "memory"
    if _value(evidence.effective_platform) == "memory":
        return "memory"
    return "filesystem"


def _metadata_platform(evidence: Evidence) -> str | None:
    metadata = _json_dict(getattr(evidence, "metadata_json", None))
    for key in ("platform", "os", "probable_os", "detected_os"):
        candidate = str(metadata.get(key) or "").lower()
        if candidate in {"windows", "linux", "macos"}:
            return candidate
    return None


def _os_platform(evidence: Evidence) -> str:
    for raw in (evidence.effective_platform, evidence.detected_platform, evidence.provided_platform):
        value = _value(raw).lower()
        if value in {"windows", "linux", "macos"}:
            return value
    if _evidence_domain(evidence) == "memory":
        return _metadata_platform(evidence) or "unknown"
    return "unknown"


def _iso(value: Any) -> str | None:
    if value is None:
        return None
    if getattr(value, "tzinfo", None) is None:
        value = value.replace(tzinfo=timezone.utc)
    return value.isoformat().replace("+00:00", "Z")


def _status(value: Any) -> str:
    return _value(value) or "unknown"


def _case_exists(db: Session, case_id: str) -> Case | None:
    return db.get(Case, case_id)


def build_case_capabilities(db: Session, case_id: str) -> dict[str, Any] | None:
    case = _case_exists(db, case_id)
    if not case:
        return None

    evidences = db.query(Evidence).filter(Evidence.case_id == case_id).all()
    hosts = db.query(CaseHost).filter(CaseHost.case_id == case_id).all()
    artifact_rows = (
        db.query(Artifact.artifact_type, func.count(Artifact.id), func.coalesce(func.sum(Artifact.record_count), 0))
        .filter(Artifact.case_id == case_id)
        .group_by(Artifact.artifact_type)
        .all()
    )
    artifact_status_rows = (
        db.query(Artifact.artifact_type, Artifact.status, func.count(Artifact.id))
        .filter(Artifact.case_id == case_id)
        .group_by(Artifact.artifact_type, Artifact.status)
        .all()
    )
    memory_summary_rows = (
        db.query(MemoryArtifactSummary.memory_artifact_type, func.coalesce(func.sum(MemoryArtifactSummary.count), 0))
        .filter(MemoryArtifactSummary.case_id == case_id)
        .group_by(MemoryArtifactSummary.memory_artifact_type)
        .all()
    )
    memory_run_rows = db.query(MemoryScanRun.status, func.count(MemoryScanRun.id)).filter(MemoryScanRun.case_id == case_id).group_by(MemoryScanRun.status).all()
    memory_plugin_rows = db.query(MemoryPluginRun.status, func.count(MemoryPluginRun.id)).filter(MemoryPluginRun.case_id == case_id).group_by(MemoryPluginRun.status).all()
    recent_detections = (
        db.query(DetectionResult)
        .filter(DetectionResult.case_id == case_id, DetectionResult.deleted_at.is_(None), DetectionResult.archived_at.is_(None))
        .order_by(DetectionResult.created_at.desc())
        .limit(20)
        .all()
    )
    recent_findings = (
        db.query(Finding)
        .filter(Finding.case_id == case_id, Finding.archived_at.is_(None))
        .order_by(Finding.updated_at.desc())
        .limit(20)
        .all()
    )

    artifact_counts = {str(kind): {"artifacts": int(count or 0), "records": int(records or 0)} for kind, count, records in artifact_rows}
    artifact_statuses: dict[str, dict[str, int]] = defaultdict(dict)
    for artifact_type, status, count in artifact_status_rows:
        artifact_statuses[str(artifact_type)][_status(status)] = int(count or 0)
    memory_counts = {str(kind): int(count or 0) for kind, count in memory_summary_rows}
    memory_run_statuses = {_status(status): int(count or 0) for status, count in memory_run_rows}
    memory_plugin_statuses = {_status(status): int(count or 0) for status, count in memory_plugin_rows}

    evidence_payloads = []
    evidence_by_host: dict[str | None, list[dict[str, Any]]] = defaultdict(list)
    evidence_lookup: dict[str, dict[str, Any]] = {}
    evidence_models: dict[str, Evidence] = {}
    case_platforms: Counter[str] = Counter()
    case_domains: Counter[str] = Counter()
    evidence_status_by_workbench: dict[str, Counter[str]] = defaultdict(Counter)
    for evidence in evidences:
        domain = _evidence_domain(evidence)
        platform = _os_platform(evidence)
        case_platforms[platform] += 1
        case_domains[domain] += 1
        payload = {
            "id": evidence.id,
            "name": evidence.original_filename,
            "evidence_type": _value(evidence.evidence_type),
            "evidence_domain": domain,
            "platform": platform,
            "legacy_effective_platform": _value(evidence.effective_platform),
            "ingest_status": _status(evidence.ingest_status),
            "host_id": evidence.host_id,
            "detected_host": evidence.detected_host,
        }
        evidence_payloads.append(payload)
        evidence_lookup[evidence.id] = payload
        evidence_models[evidence.id] = evidence
        evidence_by_host[evidence.host_id].append(payload)
        workbench_keys = ["memory"] if domain == "memory" else [platform]
        for workbench_key in workbench_keys:
            evidence_status_by_workbench[workbench_key][_status(evidence.ingest_status)] += 1

    platform_payloads = []
    for platform in sorted(case_platforms):
        platform_payloads.append({"id": platform, "label": platform.title(), "evidence_count": case_platforms[platform], "shipped": platform in SHIPPED_PLATFORMS or platform == "unknown"})
    domain_payloads = []
    for domain in sorted(case_domains):
        domain_payloads.append({"id": domain, "label": domain.title(), "evidence_count": case_domains[domain]})

    capability_payloads = []
    workbench_map: dict[str, dict[str, Any]] = {}
    for entry in CAPABILITY_REGISTRY:
        source = entry["readiness_source"]
        families = list(entry["artifact_families"])
        if source == "memory_artifact_counts":
            record_count = sum(memory_counts.get(family, 0) for family in families)
            artifact_count = sum(1 for family in families if memory_counts.get(family, 0) > 0)
            status_counts = {"runs": memory_run_statuses, "plugins": memory_plugin_statuses}
            in_scope = case_domains.get("memory", 0) > 0
        else:
            record_count = sum(artifact_counts.get(family, {}).get("records", 0) for family in families)
            artifact_count = sum(artifact_counts.get(family, {}).get("artifacts", 0) for family in families)
            status_counts = {family: artifact_statuses.get(family, {}) for family in families if family in artifact_statuses}
            in_scope = case_platforms.get(entry["platform"], 0) > 0
        if not in_scope:
            readiness = "not_applicable"
        elif record_count > 0:
            readiness = "has_data"
        elif artifact_count > 0:
            readiness = "empty"
        else:
            readiness = "not_collected"
        if any(status in {"failed", "completed_with_errors", "timed_out"} for counts in status_counts.values() if isinstance(counts, dict) for status, count in counts.items() if count):
            readiness = "degraded" if readiness in {"has_data", "empty"} else readiness

        visible = entry["availability"] == "shipped" and in_scope
        capability = {
            **entry,
            "artifact_count": artifact_count,
            "record_count": record_count,
            "status_counts": status_counts,
            "readiness": readiness,
            "visible": visible,
        }
        capability_payloads.append(capability)
        if visible:
            workbench_key = "memory" if entry["evidence_domain"] == "memory" else entry["platform"]
            workbench = workbench_map.setdefault(
                workbench_key,
                {
                    "id": workbench_key,
                    "label": workbench_key.title(),
                    "kind": "evidence_domain" if workbench_key == "memory" else "platform",
                    "capability_ids": [],
                    "domains": {},
                    "overview_route": _overview_route(workbench_key, case_id),
                },
            )
            workbench["capability_ids"].append(entry["id"])
            domain = workbench["domains"].setdefault(entry["domain"], {"id": entry["domain"], "capability_ids": [], "record_count": 0})
            domain["capability_ids"].append(entry["id"])
            domain["record_count"] += record_count

    capabilities_by_id = {item["id"]: item for item in capability_payloads}
    workbenches = []
    for workbench in workbench_map.values():
        workbench_id = workbench["id"]
        workbench_evidence = _workbench_evidence(evidence_payloads, workbench_id)
        workbench_evidence_ids = {item["id"] for item in workbench_evidence}
        status_counts = evidence_status_by_workbench.get(workbench_id, Counter())
        visible_capabilities = [capabilities_by_id[capability_id] for capability_id in workbench["capability_ids"] if capability_id in capabilities_by_id]
        quick_actions = _build_quick_actions(visible_capabilities, case_id, workbench_evidence)
        warnings = _build_warnings(workbench_id, status_counts, visible_capabilities, workbench_evidence, memory_plugin_statuses)
        recent_activity = _recent_activity_for_workbench(case_id, workbench_evidence_ids, recent_detections, recent_findings)
        memory_images = _memory_images_for_workbench(db, case_id, workbench_evidence, evidence_models) if workbench_id == "memory" else []
        workbench_hosts = {item.get("host_id") or item.get("detected_host") for item in workbench_evidence if item.get("host_id") or item.get("detected_host")}
        workbenches.append(
            {
                **workbench,
                "domains": list(workbench["domains"].values()),
                "overview": {
                    "host_count": len(workbench_hosts),
                    "evidence_count": len(workbench_evidence),
                    "processing_state": _processing_state(status_counts),
                    "coverage": {"capability_count": len(visible_capabilities), "status_counts": dict(Counter(capability["readiness"] for capability in visible_capabilities))},
                    "quick_actions": quick_actions,
                    "warnings": warnings,
                    "recent_activity": recent_activity,
                    "memory_images": memory_images,
                },
            }
        )
    workbenches.sort(key=lambda item: {"windows": 10, "linux": 20, "macos": 30, "memory": 40}.get(item["id"], 99))

    host_payloads = []
    for host in hosts:
        host_evidences = evidence_by_host.get(host.id, [])
        host_payloads.append(
            {
                "id": host.id,
                "canonical_name": host.canonical_name,
                "display_name": host.display_name,
                "platforms": sorted({item["platform"] for item in host_evidences}),
                "evidence_domains": sorted({item["evidence_domain"] for item in host_evidences}),
                "evidence_count": len(host_evidences),
            }
        )

    search_metadata = _build_search_metadata(capability_payloads, workbenches)

    return {
        "registry_version": REGISTRY_VERSION,
        "generated_at": _iso(utc_now_naive()),
        "case": {"id": case.id, "name": case.name, "status": _status(case.status)},
        "platforms": platform_payloads,
        "evidence_domains": domain_payloads,
        "workbenches": workbenches,
        "capabilities": capability_payloads,
        "search": search_metadata,
        "hosts": host_payloads,
        "evidence": evidence_payloads,
    }
