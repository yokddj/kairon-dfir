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
from app.models.evidence import Evidence, EvidenceType
from app.models.memory import MemoryArtifactSummary, MemoryPluginRun, MemoryScanRun


REGISTRY_VERSION = "2026.07.phase0"
OS_PLATFORMS = {"windows", "linux", "macos", "unknown"}
SHIPPED_PLATFORMS = {"windows", "linux"}


CAPABILITY_REGISTRY: list[dict[str, Any]] = [
    {
        "id": "windows.execution.command_history",
        "platform": "windows",
        "evidence_domain": "filesystem",
        "domain": "execution",
        "title": "Command History",
        "route": "/cases/:caseId/command-history",
        "artifact_families": ["powershell_activity", "powershell_execution", "process_execution", "windows_event"],
        "nav": {"parent": "windows/execution", "order": 10},
        "search": {"filters": [], "presets": []},
        "availability": "shipped",
        "readiness_source": "artifact_counts",
    },
    {
        "id": "windows.execution.stories",
        "platform": "windows",
        "evidence_domain": "filesystem",
        "domain": "execution",
        "title": "Execution Stories",
        "route": "/cases/:caseId/execution-stories",
        "artifact_families": ["program_executions", "execution_candidates", "windows_event", "prefetch"],
        "nav": {"parent": "windows/execution", "order": 20},
        "search": {"filters": [], "presets": []},
        "availability": "shipped",
        "readiness_source": "artifact_counts",
    },
    {
        "id": "windows.persistence.overview",
        "platform": "windows",
        "evidence_domain": "filesystem",
        "domain": "persistence",
        "title": "Persistence",
        "route": "/cases/:caseId/semi-auto?preset=persistence",
        "artifact_families": ["scheduled_task", "service", "registry_run_key", "autoruns"],
        "nav": {"parent": "windows/persistence", "order": 10},
        "search": {"filters": [], "presets": []},
        "availability": "shipped",
        "readiness_source": "artifact_counts",
    },
    {
        "id": "linux.access.authentication",
        "platform": "linux",
        "evidence_domain": "filesystem",
        "domain": "access",
        "title": "Authentication",
        "route": "/cases/:caseId/linux-authentication",
        "artifact_families": ["linux_auth"],
        "nav": {"parent": "linux/access", "order": 10},
        "search": {
            "filters": [
                {"key": "auth.outcome", "type": "enum", "values": ["success", "failure"]},
                {"key": "auth.remote_ip", "type": "ip"},
            ],
            "presets": [{"title": "Failed SSH logins", "state": {"artifact_family": "linux_auth", "q": "Failed password"}}],
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
        "route": "/cases/:caseId/command-history",
        "artifact_families": ["linux_shell_history"],
        "nav": {"parent": "linux/execution", "order": 10},
        "search": {"filters": [], "presets": []},
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
        "search": {"filters": [], "presets": []},
        "availability": "shipped",
        "readiness_source": "artifact_counts",
    },
    {
        "id": "memory.overview",
        "platform": "memory",
        "evidence_domain": "memory",
        "domain": "execution",
        "title": "Overview",
        "route": "/cases/:caseId/memory?tab=overview",
        "artifact_families": ["processes", "network", "modules", "handles", "vads"],
        "nav": {"parent": "memory/overview", "order": 5},
        "search": {"filters": [], "presets": []},
        "availability": "shipped",
        "readiness_source": "memory_artifact_counts",
    },
    {
        "id": "memory.processes",
        "platform": "memory",
        "evidence_domain": "memory",
        "domain": "execution",
        "title": "Processes",
        "route": "/cases/:caseId/memory?tab=processes",
        "artifact_families": ["processes"],
        "nav": {"parent": "memory/execution", "order": 10},
        "search": {"filters": [], "presets": []},
        "availability": "shipped",
        "readiness_source": "memory_artifact_counts",
    },
    {
        "id": "memory.network",
        "platform": "memory",
        "evidence_domain": "memory",
        "domain": "network",
        "title": "Network",
        "route": "/cases/:caseId/memory?tab=network",
        "artifact_families": ["network"],
        "nav": {"parent": "memory/network", "order": 10},
        "search": {"filters": [], "presets": []},
        "availability": "shipped",
        "readiness_source": "memory_artifact_counts",
    },
]


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

    artifact_counts = {str(kind): {"artifacts": int(count or 0), "records": int(records or 0)} for kind, count, records in artifact_rows}
    artifact_statuses: dict[str, dict[str, int]] = defaultdict(dict)
    for artifact_type, status, count in artifact_status_rows:
        artifact_statuses[str(artifact_type)][_status(status)] = int(count or 0)
    memory_counts = {str(kind): int(count or 0) for kind, count in memory_summary_rows}
    memory_run_statuses = {_status(status): int(count or 0) for status, count in memory_run_rows}
    memory_plugin_statuses = {_status(status): int(count or 0) for status, count in memory_plugin_rows}

    evidence_payloads = []
    evidence_by_host: dict[str | None, list[dict[str, Any]]] = defaultdict(list)
    case_platforms: Counter[str] = Counter()
    case_domains: Counter[str] = Counter()
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
        evidence_by_host[evidence.host_id].append(payload)

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
                {"id": workbench_key, "label": workbench_key.title(), "kind": "evidence_domain" if workbench_key == "memory" else "platform", "capability_ids": [], "domains": {}},
            )
            workbench["capability_ids"].append(entry["id"])
            domain = workbench["domains"].setdefault(entry["domain"], {"id": entry["domain"], "capability_ids": [], "record_count": 0})
            domain["capability_ids"].append(entry["id"])
            domain["record_count"] += record_count

    workbenches = []
    for workbench in workbench_map.values():
        workbenches.append({**workbench, "domains": list(workbench["domains"].values())})
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

    return {
        "registry_version": REGISTRY_VERSION,
        "generated_at": _iso(utc_now_naive()),
        "case": {"id": case.id, "name": case.name, "status": _status(case.status)},
        "platforms": platform_payloads,
        "evidence_domains": domain_payloads,
        "workbenches": workbenches,
        "capabilities": capability_payloads,
        "hosts": host_payloads,
        "evidence": evidence_payloads,
    }
