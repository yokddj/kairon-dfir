"""Canonical memory process entity model.

The legacy normalizer produced one document per plugin-row, keyed by
``pid|offset|create_time``.  Each plugin therefore contributed a
duplicate ``memory_process`` document per process identity.  The
frontend had to merge them visually and the process tree was unusable.

This module implements a *canonical entity + observation* model:

* A ``MemoryProcessEntity`` represents a single process identity, with
  one row in the UI.
* A ``MemoryProcessObservation`` is the raw per-plugin row.  Multiple
  observations can belong to the same entity.
* A ``MemoryProcessEdge`` is the parent/child relationship between
  canonical entities.

Identity rules (applied in this order):

1. ``(case_id, evidence_id, pid, create_time)`` — preferred identity.
2. ``(case_id, evidence_id, pid, process_name)`` — fallback when no
   ``create_time`` is available.  Same PID with a different
   ``process_name`` is treated as a *provisional* identity and may be
   reconciled later if a ``create_time`` becomes available.
3. ``(case_id, evidence_id, pid)`` only is the *weakest* identity and
   is only used to bridge until stronger evidence arrives.  Windows
   recycles PIDs, so this identity MUST be reconciled before being
   shown to the analyst.

Field merge precedence (highest first):

* name: pslist > psscan > pstree > cmdline basename > "unknown"
* ppid:  pstree > pslist > psscan > others
* create_time: pslist > psscan > pstree > others (a present value is
  never replaced by a null)
* command_line: cmdline (deduplicated, all variants preserved as
  observations)

Visibility classification (per entity):

* ``listed`` — observed in pslist
* ``scan_only`` — observed in psscan only (pslist not present)
* ``terminated`` — only when an explicit ``exit_time`` is recorded
* ``unknown`` — insufficient data, identity is provisional

Tree semantics:

* ``root`` — PPID == 0 and PPID is well known (or 0 is itself a real
  PID 0 entity)
* ``orphan`` — PPID points to a PID that does not exist as an entity
* ``unknown_parent`` — PPID is null
* ``cycle`` — entity points to itself or an ancestor that points back
* ``self_parent`` — pid == ppid
* PID 0 and PID 4 are special-cased only to the extent that they are
  deduplicated, never artificially filtered.

The module exposes a *dry-run* that returns a deterministic summary
of the merge result without writing to OpenSearch, and an *apply* that
is fully idempotent (re-running the same input produces the same
documents with the same IDs).
"""
from __future__ import annotations

import hashlib
import logging
from collections import defaultdict
from datetime import datetime, timezone
from typing import Any, Iterable

from app.core.opensearch import get_memory_index, get_opensearch_client
from app.services.memory.pids import normalize_pid


logger = logging.getLogger(__name__)


NORMALIZATION_VERSION = "memory_process_canonical_v1"

# Plugin precedence (lower index = higher priority).
NAME_PRECEDENCE = ("windows.pslist", "windows.psscan", "windows.pstree")
PPID_PRECEDENCE = ("windows.pstree", "windows.pslist", "windows.psscan")
CREATE_TIME_PRECEDENCE = ("windows.pslist", "windows.psscan", "windows.pstree")
EXIT_TIME_PRECEDENCE = ("windows.psscan", "windows.pslist", "windows.pstree")

CMDLINE_PLUGIN = "windows.cmdline"
PSLIST_PLUGIN = "windows.pslist"
PSSCAN_PLUGIN = "windows.psscan"
PSTREE_PLUGIN = "windows.pstree"


# OpenSearch mapping additions for the canonical model.  The legacy
# mapping already accepts all of these as dynamic fields, but we
# declare them explicitly to ensure the index has correct types for
# filtering, sorting and aggregations.
CANONICAL_MAPPING_ADDITIONS = {
    "memory_process_entity": {
        "document_id": {"type": "keyword"},
        "document_type": {"type": "keyword"},
        "case_id": {"type": "keyword"},
        "evidence_id": {"type": "keyword"},
        "scan_run_id": {"type": "keyword"},
        "host_id": {"type": "keyword"},
        "process_entity_id": {"type": "keyword"},
        "process": {
            "properties": {
                "pid": {"type": "integer"},
                "ppid": {"type": "integer"},
                "name": {"type": "keyword", "fields": {"text": {"type": "text"}}},
                "executable_name": {"type": "keyword"},
                "command_line": {"type": "text"},
                "create_time": {"type": "date", "ignore_malformed": True},
                "exit_time": {"type": "date", "ignore_malformed": True},
                "session_id": {"type": "integer"},
                "wow64": {"type": "boolean"},
            }
        },
        "visibility": {
            "properties": {
                "listed": {"type": "boolean"},
                "scan_only": {"type": "boolean"},
                "terminated": {"type": "boolean"},
                "unknown": {"type": "boolean"},
                "hidden_candidate": {"type": "boolean"},
            }
        },
        "sources": {"type": "keyword"},
        "source_plugins": {"type": "keyword"},
        "observation_count": {"type": "integer"},
        "observation_summary": {
            "properties": {
                "has_pslist": {"type": "boolean"},
                "has_psscan": {"type": "boolean"},
                "has_pstree": {"type": "boolean"},
                "has_cmdline": {"type": "boolean"},
            }
        },
        "confidence": {"type": "keyword"},
        "first_seen_run_id": {"type": "keyword"},
        "latest_run_id": {"type": "keyword"},
        "parent_entity_id": {"type": "keyword"},
        "child_count": {"type": "integer"},
        "tree": {
            "properties": {
                "is_root": {"type": "boolean"},
                "is_orphan": {"type": "boolean"},
                "is_unknown_parent": {"type": "boolean"},
                "is_cycle": {"type": "boolean"},
                "is_self_parent": {"type": "boolean"},
                "is_pid_zero": {"type": "boolean"},
            }
        },
        "observations": {"type": "object", "enabled": False},
        "findings": {"type": "keyword"},
        "findings_summary": {"type": "keyword"},
        "normalization_version": {"type": "keyword"},
        "materialized_from_run_id": {"type": "keyword"},
        "indexed_at": {"type": "date"},
    },
    "memory_process_observation": {
        "document_id": {"type": "keyword"},
        "document_type": {"type": "keyword"},
        "case_id": {"type": "keyword"},
        "evidence_id": {"type": "keyword"},
        "scan_run_id": {"type": "keyword"},
        "process_entity_id": {"type": "keyword"},
        "plugin_run_id": {"type": "keyword"},
        "plugin_name": {"type": "keyword"},
        "source_record_id": {"type": "keyword"},
        "observed": {
            "properties": {
                "pid": {"type": "integer"},
                "ppid": {"type": "integer"},
                "name": {"type": "keyword"},
                "command_line": {"type": "text"},
                "create_time": {"type": "date", "ignore_malformed": True},
                "exit_time": {"type": "date", "ignore_malformed": True},
            }
        },
        "raw_status": {"type": "keyword"},
        "source_fields": {"type": "object", "enabled": False},
        "confidence": {"type": "keyword"},
        "indexed_at": {"type": "date"},
    },
    "memory_process_edge": {
        "document_id": {"type": "keyword"},
        "document_type": {"type": "keyword"},
        "case_id": {"type": "keyword"},
        "evidence_id": {"type": "keyword"},
        "scan_run_id": {"type": "keyword"},
        "parent_entity_id": {"type": "keyword"},
        "child_entity_id": {"type": "keyword"},
        "edge_type": {"type": "keyword"},
        "source_plugin": {"type": "keyword"},
        "confidence": {"type": "keyword"},
        "parent_pid": {"type": "integer"},
        "child_pid": {"type": "integer"},
        "indexed_at": {"type": "date"},
    },
}


# ---------------------------------------------------------------------------
# Identity helpers
# ---------------------------------------------------------------------------


def _stable_hash(payload: str) -> str:
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()[:24]


def _to_int(value: Any) -> int | None:
    return normalize_pid(value)


def _to_str(value: Any, limit: int = 512) -> str | None:
    if value is None:
        return None
    text = str(value).strip()
    if not text:
        return None
    return text[:limit]


def _normalize_create_time(value: Any) -> str | None:
    """Return a canonical ISO 8601 timestamp or ``None`` if missing.

    The legacy documents store ``CreateTime`` as a string already in
    ISO 8601 (Volatility default).  We do not parse and reformat: any
    malformed value is left as a string and the OpenSearch ``date``
    mapping with ``ignore_malformed`` will keep it from breaking the
    index.  The contract is that the value is a stable string per
    (case_id, evidence_id, pid, plugin).
    """
    return _to_str(value, limit=128)


def strong_identity(*, case_id: str, evidence_id: str, pid: int, create_time: str | None) -> str:
    seed = f"strong|{case_id}|{evidence_id}|{pid}|{create_time or 'notime'}"
    return _stable_hash(seed)


def name_identity(*, case_id: str, evidence_id: str, pid: int, process_name: str | None) -> str:
    seed = f"name|{case_id}|{evidence_id}|{pid}|{process_name or 'noname'}"
    return _stable_hash(seed)


def weak_identity(*, case_id: str, evidence_id: str, pid: int) -> str:
    seed = f"weak|{case_id}|{evidence_id}|{pid}"
    return _stable_hash(seed)


# ---------------------------------------------------------------------------
# Observation extraction
# ---------------------------------------------------------------------------


def _extract_observation(
    document: dict[str, Any],
    *,
    case_id: str,
    evidence_id: str,
    run_id: str,
) -> dict[str, Any] | None:
    """Convert a legacy per-plugin document into an observation.

    Returns ``None`` if the document does not carry a recognizable PID
    (which is the only universally-required identifier in any plugin
    row).
    """
    pid = _to_int(document.get("process", {}).get("pid"))
    if pid is None:
        return None
    ppid = _to_int(document.get("process", {}).get("ppid"))
    name = _to_str(document.get("process", {}).get("name"))
    create_time = _normalize_create_time(document.get("process", {}).get("create_time"))
    exit_time = _normalize_create_time(document.get("process", {}).get("exit_time"))
    command_line = _to_str(document.get("process", {}).get("command_line"), limit=16384)
    plugins = list(document.get("plugins") or [])
    plugin = plugins[0] if plugins else "unknown"
    raw_status = "ok"
    if not plugins:
        raw_status = "missing_plugin"
    return {
        "observation_id": _stable_hash(
            f"obs|{case_id}|{evidence_id}|{run_id}|{document.get('document_id', '')}|{plugin}|{pid}"
        ),
        "case_id": case_id,
        "evidence_id": evidence_id,
        "scan_run_id": run_id,
        "plugin_run_id": document.get("memory_plugin_run_id") or document.get("plugin_run_id") or "",
        "plugin_name": plugin,
        "source_record_id": document.get("document_id", ""),
        "observed": {
            "pid": pid,
            "ppid": ppid,
            "name": name,
            "command_line": command_line,
            "create_time": create_time,
            "exit_time": exit_time,
        },
        "raw_status": raw_status,
        "source_fields": _bounded_raw(document.get("raw")),
    }


def _bounded_raw(raw: Any) -> dict[str, Any]:
    if not isinstance(raw, dict):
        return {}
    bounded: dict[str, Any] = {}
    total = 0
    for key, value in raw.items():
        if len(bounded) >= 40:
            break
        if isinstance(value, str):
            v = value[:512]
        elif isinstance(value, (int, float, bool)) or value is None:
            v = value
        else:
            v = str(value)[:512]
        total += len(str(v))
        if total > 16384:
            break
        bounded[str(key)[:128]] = v
    return bounded


# ---------------------------------------------------------------------------
# Entity reconciliation
# ---------------------------------------------------------------------------


def _bucket_key(pid: int, create_time: str | None) -> tuple:
    return (pid, create_time or None)


def _reconcile_entities(observations: list[dict[str, Any]], *, case_id: str, evidence_id: str) -> list[dict[str, Any]]:
    """Reconcile observations into canonical entities.

    The algorithm is deterministic and idempotent:

    1. Group observations by ``(pid, create_time)``.  The same
       ``create_time`` (or both-missing) groups together.
    2. Within a group, observations belong to the same entity.
    3. Cross-group links (same PID, different ``create_time``) are
       kept as separate entities — this is the PID-reuse case.
    4. For groups where ``create_time`` is missing, fall back to
       grouping by ``(pid, process_name)`` if the name is reported.
    5. If neither ``create_time`` nor ``process_name`` is reported, use
       a weak PID-only identity and mark confidence as ``low`` so the
       UI can flag it.
    6. **Reconciliation**: any name-only group whose ``(pid, name)``
       matches a strong group is merged into the strong group.  This
       is how a ``cmdline`` observation that has no ``create_time``
       joins the canonical ``pslist`` entity for the same PID.
    """
    # Phase 1: bucket by strong identity
    by_strong: dict[tuple[int, str | None], list[dict[str, Any]]] = defaultdict(list)
    by_name: dict[tuple[int, str | None], list[dict[str, Any]]] = defaultdict(list)
    for obs in observations:
        pid = obs["observed"]["pid"]
        create_time = obs["observed"]["create_time"]
        if create_time:
            by_strong[_bucket_key(pid, create_time)] = by_strong.get(_bucket_key(pid, create_time), []) + [obs]
        else:
            name = obs["observed"]["name"]
            by_name[(pid, name)] = by_name.get((pid, name), []) + [obs]

    # Phase 2: build strong entities first.
    entities: list[dict[str, Any]] = []
    seen_observation_ids: set[str] = set()
    pid_to_strong_index: dict[int, int] = {}

    def _build_entity(obs_list: list[dict[str, Any]], *, has_create_time: bool) -> dict[str, Any]:
        obs_list = [o for o in obs_list if o["observation_id"] not in seen_observation_ids]
        for o in obs_list:
            seen_observation_ids.add(o["observation_id"])
        if not obs_list:
            return None  # type: ignore[return-value]
        pid = obs_list[0]["observed"]["pid"]
        create_time = next((o["observed"]["create_time"] for o in obs_list if o["observed"]["create_time"]), None)
        entity_id = (
            strong_identity(case_id=case_id, evidence_id=evidence_id, pid=pid, create_time=create_time)
            if has_create_time and create_time
            else name_identity(
                case_id=case_id,
                evidence_id=evidence_id,
                pid=pid,
                process_name=next((o["observed"]["name"] for o in obs_list if o["observed"]["name"]), None),
            )
        )
        sources: set[str] = set()
        for o in obs_list:
            plugin = o["plugin_name"]
            if plugin:
                sources.add(plugin)
        return {
            "process_entity_id": entity_id,
            "case_id": case_id,
            "evidence_id": evidence_id,
            "pid": pid,
            "create_time": create_time,
            "has_create_time": has_create_time,
            "observations": obs_list,
            "sources": sorted(sources),
        }

    for key, obs_list in by_strong.items():
        ent = _build_entity(obs_list, has_create_time=True)
        if ent is None:
            continue
        entities.append(ent)
        pid_to_strong_index[ent["pid"]] = len(entities) - 1

    # Phase 3: process name-only groups; reconcile into strong when possible
    for key, obs_list in by_name.items():
        pid = key[0]
        if pid in pid_to_strong_index:
            # Reconcile: attach these observations to the strong entity
            strong = entities[pid_to_strong_index[pid]]
            for o in obs_list:
                if o["observation_id"] in seen_observation_ids:
                    continue
                seen_observation_ids.add(o["observation_id"])
                strong["observations"].append(o)
                plugin = o["plugin_name"]
                if plugin and plugin not in strong["sources"]:
                    strong["sources"].append(plugin)
                    strong["sources"] = sorted(strong["sources"])
            continue
        ent = _build_entity(obs_list, has_create_time=False)
        if ent is None:
            continue
        entities.append(ent)

    # Deterministic ordering: by pid, then by entity_id
    entities.sort(key=lambda e: (e["pid"], e["process_entity_id"]))
    return entities


def _select_preferred(values: dict[str, Any], precedence: tuple[str, ...]) -> Any:
    """Pick the highest-precedence non-empty value from a per-plugin mapping."""
    for plugin in precedence:
        v = values.get(plugin)
        if v not in (None, ""):
            return v
    # Fall back to any non-empty
    for v in values.values():
        if v not in (None, ""):
            return v
    return None


def _collect_by_plugin(observations: list[dict[str, Any]], field: str) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for o in observations:
        value = o["observed"].get(field)
        if value in (None, ""):
            continue
        plugin = o["plugin_name"]
        # Keep the first non-empty value per plugin (sorted by plugin to be deterministic)
        result.setdefault(plugin, value)
    return result


def _merge_observations(observations: list[dict[str, Any]]) -> dict[str, Any]:
    """Compute merged canonical fields from observations."""
    name_by_plugin = _collect_by_plugin(observations, "name")
    ppid_by_plugin = _collect_by_plugin(observations, "ppid")
    create_time_by_plugin = _collect_by_plugin(observations, "create_time")
    exit_time_by_plugin = _collect_by_plugin(observations, "exit_time")
    command_lines: list[str] = []
    for o in observations:
        cl = o["observed"].get("command_line")
        if cl and cl not in command_lines:
            command_lines.append(cl)
    return {
        "name": _select_preferred(name_by_plugin, NAME_PRECEDENCE),
        "ppid": _select_preferred(ppid_by_plugin, PPID_PRECEDENCE),
        "create_time": _select_preferred(create_time_by_plugin, CREATE_TIME_PRECEDENCE),
        "exit_time": _select_preferred(exit_time_by_plugin, EXIT_TIME_PRECEDENCE),
        "command_lines": command_lines,
        "command_line": command_lines[0] if command_lines else None,
        "executable_name": _executable_name(name_by_plugin, command_lines),
        "session_id": _select_session_id(observations),
    }


def _executable_name(name_by_plugin: dict[str, Any], command_lines: list[str]) -> str | None:
    for plugin in NAME_PRECEDENCE:
        n = name_by_plugin.get(plugin)
        if n:
            return n
    if command_lines:
        first = command_lines[0].strip()
        if first:
            token = first.split()[0]
            if "\\" in token or "/" in token:
                token = token.rsplit("\\", 1)[-1].rsplit("/", 1)[-1]
            return token[:256] or None
    return None


def _select_session_id(observations: list[dict[str, Any]]) -> int | None:
    for o in observations:
        # Sessions aren't in observations yet; reserved for future.
        pass
    return None


def _classify_visibility(observations: list[dict[str, Any]], merged: dict[str, Any]) -> dict[str, bool]:
    sources = {o["plugin_name"] for o in observations}
    has_pslist = PSLIST_PLUGIN in sources
    has_psscan = PSSCAN_PLUGIN in sources
    has_pstree = PSTREE_PLUGIN in sources
    has_cmdline = CMDLINE_PLUGIN in sources
    explicit_exit = any(o["observed"].get("exit_time") for o in observations)
    listed = has_pslist
    scan_only = has_psscan and not has_pslist
    terminated = bool(explicit_exit)
    unknown = not (has_pslist or has_psscan or has_pstree or has_cmdline) or (
        not merged.get("name") and not merged.get("create_time")
    )
    hidden_candidate = bool(scan_only) and not terminated
    return {
        "listed": listed,
        "scan_only": scan_only,
        "terminated": terminated,
        "unknown": unknown,
        "hidden_candidate": hidden_candidate,
    }


def _confidence(observations: list[dict[str, Any]], has_create_time: bool) -> str:
    sources = {o["plugin_name"] for o in observations}
    if has_create_time:
        if {PSLIST_PLUGIN, CMDLINE_PLUGIN}.issubset(sources):
            return "high"
        if len(sources) >= 2:
            return "medium"
        return "medium"
    if not sources:
        return "low"
    return "low"


def _findings(merged: dict[str, Any], visibility: dict[str, bool], observations: list[dict[str, Any]]) -> list[str]:
    findings: list[str] = []
    if visibility["scan_only"]:
        findings.append("scan_only")
    if visibility["hidden_candidate"]:
        findings.append("hidden_candidate")
    if visibility["terminated"]:
        findings.append("terminated")
    if visibility["unknown"]:
        findings.append("identity_provisional")
    sources = {o["plugin_name"] for o in observations}
    if merged.get("ppid") is None and {PSLIST_PLUGIN, PSTREE_PLUGIN} & sources:
        # pslist/pstree did not report a PPID — cmdline alone cannot fill it
        findings.append("missing_parent_in_pslist_or_pstree")
    # Name conflict detection: pslist vs psscan/pstree disagree
    names = {o["observed"].get("name") for o in observations if o["observed"].get("name")}
    if len(names) > 1:
        findings.append("name_conflict")
    if visibility["listed"] and CMDLINE_PLUGIN not in sources:
        findings.append("command_line_missing")
    return findings


def _build_canonical_entity(
    entity: dict[str, Any],
    *,
    run_id: str,
) -> dict[str, Any]:
    observations = entity["observations"]
    merged = _merge_observations(observations)
    visibility = _classify_visibility(observations, merged)
    confidence = _confidence(observations, entity["has_create_time"])
    findings = _findings(merged, visibility, observations)
    sources = sorted({o["plugin_name"] for o in observations if o["plugin_name"]})
    return {
        "process_entity_id": entity["process_entity_id"],
        "case_id": entity["case_id"],
        "evidence_id": entity["evidence_id"],
        "scan_run_id": run_id,
        "host_id": None,
        "process": {
            "pid": entity["pid"],
            "ppid": merged.get("ppid"),
            "name": merged.get("name"),
            "executable_name": merged.get("executable_name"),
            "command_line": merged.get("command_line"),
            "create_time": merged.get("create_time"),
            "exit_time": merged.get("exit_time"),
            "session_id": merged.get("session_id"),
            "wow64": None,
        },
        "visibility": visibility,
        "sources": sources,
        "source_plugins": sources,
        "observation_count": len(observations),
        "observation_summary": {
            "has_pslist": PSLIST_PLUGIN in sources,
            "has_psscan": PSSCAN_PLUGIN in sources,
            "has_pstree": PSTREE_PLUGIN in sources,
            "has_cmdline": CMDLINE_PLUGIN in sources,
        },
        "confidence": confidence,
        "first_seen_run_id": run_id,
        "latest_run_id": run_id,
        "findings": findings,
        "findings_summary": findings,
        "normalization_version": NORMALIZATION_VERSION,
        "materialized_from_run_id": run_id,
        "memory_run_id": run_id,
        "memory_artifact_type": "memory_process_entity",
        "indexed_at": _utc_now(),
        "document_type": "memory_process_entity",
        "document_id": _entity_document_id(entity["process_entity_id"], run_id),
        "observations": observations,
    }


def _entity_document_id(entity_id: str, run_id: str) -> str:
    return f"{run_id}:memory_process_entity:{entity_id}"


def _observation_document_id(observation_id: str) -> str:
    return f"observation:{observation_id}"


def _edge_document_id(parent_entity_id: str, child_entity_id: str, run_id: str) -> str:
    return f"{run_id}:memory_process_edge:{parent_entity_id}:{child_entity_id}"


def _utc_now() -> datetime:
    return datetime.now(timezone.utc)


# ---------------------------------------------------------------------------
# Tree semantics
# ---------------------------------------------------------------------------


def _is_pid_zero(pid: int | None) -> bool:
    return pid == 0


def build_tree_metrics(entities: list[dict[str, Any]]) -> dict[str, Any]:
    """Annotate entities with tree metrics.

    Each entity receives:

    * ``parent_entity_id`` — the canonical parent (or ``None``)
    * ``tree.is_root`` / ``tree.is_orphan`` / ``tree.is_unknown_parent`` / ``tree.is_cycle`` / ``tree.is_self_parent`` / ``tree.is_pid_zero``
    * ``child_count`` — number of direct children in this entity set

    Tree rules:

    * PID 0 is a real entity if it appears in the data; we do not
      treat it as a magic root.  It is annotated as ``is_pid_zero``
      and removed from the ``root`` count if its PPID is 0 (it
      self-references, which is the OS convention).
    * PID 4 (System) deduplicates automatically: the identity algorithm
      collapses every observation with the same PID and create_time
      into a single entity, so a single System process appears once
      per identity.
    * A node whose parent PID points to a process that exists in the
      set is a *child*.
    * A node whose parent PID is 0 AND the parent is present is a
      *child of the System* ancestor; we still report it as ``root``
      of its own sub-tree for analyst clarity.
    * A node whose parent PID points to a PID NOT in the entity set is
      an ``orphan``.
    * A node whose parent PID is ``None`` has ``unknown_parent``.
    * Cycles and self-parentage are detected and flagged but do not
      prevent rendering.
    """
    by_pid: dict[int, list[dict[str, Any]]] = defaultdict(list)
    for ent in entities:
        by_pid[ent["process"]["pid"]].append(ent)

    # Choose parent for each entity deterministically
    parent_map: dict[str, str | None] = {}
    parent_pid_map: dict[str, int | None] = {}
    pid_to_main_entity: dict[int, str] = {}
    for ent in entities:
        pid = ent["process"]["pid"]
        # Pick the lowest entity_id per pid for "main" pid alias
        existing = pid_to_main_entity.get(pid)
        if existing is None or ent["process_entity_id"] < existing:
            pid_to_main_entity[pid] = ent["process_entity_id"]

    for ent in entities:
        ppid = ent["process"]["ppid"]
        is_zero = _is_pid_zero(ent["process"]["pid"])
        is_self = ppid is not None and ppid == ent["process"]["pid"]
        if is_self:
            parent_map[ent["process_entity_id"]] = None
            parent_pid_map[ent["process_entity_id"]] = ppid
            ent["tree"] = {
                "is_root": False,
                "is_orphan": False,
                "is_unknown_parent": False,
                "is_cycle": False,
                "is_self_parent": True,
                "is_pid_zero": is_zero,
            }
            continue
        if ppid is None:
            parent_map[ent["process_entity_id"]] = None
            parent_pid_map[ent["process_entity_id"]] = None
            ent["tree"] = {
                "is_root": False,
                "is_orphan": False,
                "is_unknown_parent": True,
                "is_cycle": False,
                "is_self_parent": False,
                "is_pid_zero": is_zero,
            }
            continue
        # Try to find the parent entity
        candidates = by_pid.get(ppid, [])
        if candidates:
            parent_entity_id = candidates[0]["process_entity_id"]
            parent_map[ent["process_entity_id"]] = parent_entity_id
            parent_pid_map[ent["process_entity_id"]] = ppid
            ent["tree"] = {
                "is_root": False,
                "is_orphan": False,
                "is_unknown_parent": False,
                "is_cycle": False,
                "is_self_parent": False,
                "is_pid_zero": is_zero,
            }
        else:
            parent_map[ent["process_entity_id"]] = None
            parent_pid_map[ent["process_entity_id"]] = ppid
            ent["tree"] = {
                "is_root": False,
                "is_orphan": True,
                "is_unknown_parent": False,
                "is_cycle": False,
                "is_self_parent": False,
                "is_pid_zero": is_zero,
            }

    # Compute root classification: a node is a "root" of the visible
    # graph if either:
    #   * it has no parent_entity_id (i.e. PPID not in the set,
    #     not flagged as orphan, not unknown_parent, not
    #     self_parent, not the special PID 0), OR
    #   * its parent is the PID 0 self-referencing entity (System
    #     is conventionally the top of the analyst's tree).
    pid_zero_ids = {e["process_entity_id"] for e in entities if e["process"]["pid"] == 0}
    for ent in entities:
        tree = ent["tree"]
        if tree["is_self_parent"] or tree["is_unknown_parent"] or tree["is_orphan"] or tree["is_pid_zero"]:
            continue
        parent_id = parent_map.get(ent["process_entity_id"])
        if parent_id is None:
            tree["is_root"] = True
        elif parent_id in pid_zero_ids:
            tree["is_root"] = True

    # Cycle detection: if any path from A to its parent eventually
    # returns to A.
    for ent in entities:
        visited: set[str] = set()
        cur = ent["process_entity_id"]
        cycle = False
        while cur in parent_map and parent_map[cur] is not None:
            if cur in visited:
                cycle = True
                break
            visited.add(cur)
            cur = parent_map[cur]
            if cur == ent["process_entity_id"]:
                cycle = True
                break
        ent["tree"]["is_cycle"] = cycle

    # Child counts
    child_counts: dict[str, int] = defaultdict(int)
    for child_id, parent_id in parent_map.items():
        if parent_id is not None:
            child_counts[parent_id] += 1
    for ent in entities:
        ent["child_count"] = child_counts.get(ent["process_entity_id"], 0)
        ent["parent_entity_id"] = parent_map.get(ent["process_entity_id"])

    # Aggregate metrics
    metrics = {
        "total_nodes": len(entities),
        "roots": sum(1 for e in entities if e["tree"]["is_root"]),
        "orphans": sum(1 for e in entities if e["tree"]["is_orphan"]),
        "unknown_parent": sum(1 for e in entities if e["tree"]["is_unknown_parent"]),
        "cycles": sum(1 for e in entities if e["tree"]["is_cycle"]),
        "self_parent": sum(1 for e in entities if e["tree"]["is_self_parent"]),
        "hidden_candidates": sum(1 for e in entities if e["visibility"].get("hidden_candidate")),
        "scan_only": sum(1 for e in entities if e["visibility"].get("scan_only")),
        "terminated": sum(1 for e in entities if e["visibility"].get("terminated")),
        "pid_zero_count": sum(1 for e in entities if e["tree"]["is_pid_zero"]),
        "pid_4_count": sum(1 for e in entities if e["process"]["pid"] == 4),
    }
    return metrics


# ---------------------------------------------------------------------------
# Dry-run and apply
# ---------------------------------------------------------------------------


def renormalize_documents(
    raw_documents: list[dict[str, Any]],
    *,
    case_id: str,
    evidence_id: str,
    run_id: str,
    materialize: bool = False,
) -> dict[str, Any]:
    """Reconcile a list of legacy per-plugin documents into canonical entities.

    The function is *pure* when ``materialize=False`` (returns a summary
    suitable for a dry-run) and *side-effecting* when ``materialize=True``
    (writes the canonical entities, observations and edges to OpenSearch).

    Idempotency: re-running with the same inputs produces the same
    document IDs.  OpenSearch ``index`` with explicit ``id`` is an
    upsert.
    """
    observations: list[dict[str, Any]] = []
    skipped: list[dict[str, Any]] = []
    for document in raw_documents:
        if document.get("memory_artifact_type") != "memory_process":
            continue
        obs = _extract_observation(
            document,
            case_id=case_id,
            evidence_id=evidence_id,
            run_id=run_id,
        )
        if obs is None:
            skipped.append({"document_id": document.get("document_id"), "reason": "missing_pid"})
            continue
        observations.append(obs)

    raw_groups = _reconcile_entities(observations, case_id=case_id, evidence_id=evidence_id)
    canonical_entities = [_build_canonical_entity(eg, run_id=run_id) for eg in raw_groups]
    tree_metrics = build_tree_metrics(canonical_entities)

    edges: list[dict[str, Any]] = []
    for ent in canonical_entities:
        parent_id = ent.get("parent_entity_id")
        if parent_id is None:
            continue
        edges.append(
            {
                "document_id": _edge_document_id(parent_id, ent["process_entity_id"], run_id),
                "document_type": "memory_process_edge",
                "case_id": case_id,
                "evidence_id": evidence_id,
                "scan_run_id": run_id,
                "parent_entity_id": parent_id,
                "child_entity_id": ent["process_entity_id"],
                "edge_type": "parent_child",
                "source_plugin": "windows.pstree" if PSTREE_PLUGIN in ent["sources"] else "windows.pslist",
                "confidence": "high" if PSTREE_PLUGIN in ent["sources"] else "medium",
                "parent_pid": ent["process"]["ppid"],
                "child_pid": ent["process"]["pid"],
                "indexed_at": _utc_now(),
            }
        )

    # Source document count: number of legacy documents that fed the
    # renormalization.
    source_documents = len(raw_documents)
    duplicate_groups = max(0, source_documents - len(canonical_entities))
    candidate_entities = len(canonical_entities)
    observation_count = sum(e["observation_count"] for e in canonical_entities)
    invalid_records = len(skipped)
    ambiguous_pid_groups = sum(
        1
        for ent in canonical_entities
        if not ent["process"].get("create_time") and len(ent["observations"]) > 1
    )
    summary = {
        "case_id": case_id,
        "evidence_id": evidence_id,
        "run_id": run_id,
        "source_documents": source_documents,
        "candidate_entities": candidate_entities,
        "observation_count": observation_count,
        "duplicate_groups_collapsed": duplicate_groups,
        "invalid_records": invalid_records,
        "ambiguous_pid_groups": ambiguous_pid_groups,
        "expected_edges": len(edges),
        "tree_metrics": tree_metrics,
        "normalization_version": NORMALIZATION_VERSION,
    }

    if not materialize:
        return {
            "summary": summary,
            "entities": canonical_entities,
            "observations": observations,
            "edges": edges,
            "skipped": skipped,
        }

    # Materialize
    materialize_to_opensearch(
        case_id=case_id,
        entities=canonical_entities,
        observations=observations,
        edges=edges,
    )
    summary["materialization_status"] = "applied"
    return {
        "summary": summary,
        "entities": canonical_entities,
        "observations": observations,
        "edges": edges,
        "skipped": skipped,
    }


def materialize_to_opensearch(
    *,
    case_id: str,
    entities: list[dict[str, Any]],
    observations: list[dict[str, Any]],
    edges: list[dict[str, Any]],
) -> None:
    index = get_memory_index(case_id)
    client = get_opensearch_client()
    if not client.indices.exists(index=index):
        # Index will be created on the fly by dynamic mapping; the
        # canonical types are documented in the dynamic mapping.
        client.indices.create(index=index, body={"mappings": {"dynamic": True}})

    bulk_body: list[dict[str, Any]] = []
    for ent in entities:
        bulk_body.append({"index": {"_index": index, "_id": ent["document_id"]}})
        bulk_body.append(ent)
    for obs in observations:
        doc = {
            "document_id": _observation_document_id(obs["observation_id"]),
            "document_type": "memory_process_observation",
            "case_id": obs["case_id"],
            "evidence_id": obs["evidence_id"],
            "scan_run_id": obs["scan_run_id"],
            "process_entity_id": _resolve_entity_id_for_observation(obs, entities),
            "plugin_run_id": obs["plugin_run_id"],
            "plugin_name": obs["plugin_name"],
            "source_record_id": obs["source_record_id"],
            "observed": obs["observed"],
            "raw_status": obs["raw_status"],
            "source_fields": obs["source_fields"],
            "confidence": "high" if obs["observed"].get("create_time") else "low",
            "indexed_at": _utc_now(),
        }
        bulk_body.append({"index": {"_index": index, "_id": doc["document_id"]}})
        bulk_body.append(doc)
    for edge in edges:
        bulk_body.append({"index": {"_index": index, "_id": edge["document_id"]}})
        bulk_body.append(edge)
    if not bulk_body:
        return
    # bulk uses newline-delimited JSON
    response = client.bulk(body=bulk_body, refresh=False)
    if response.get("errors"):
        # Log and continue; idempotency is preserved by the explicit ids.
        for item in response.get("items", []):
            err = item.get("index", {}).get("error")
            if err:
                logger.warning("canonical materialization item error: %s", err)
    client.indices.refresh(index=index)


def _resolve_entity_id_for_observation(obs: dict[str, Any], entities: list[dict[str, Any]]) -> str:
    """Find the canonical entity that an observation was merged into."""
    pid = obs["observed"]["pid"]
    create_time = obs["observed"].get("create_time")
    name = obs["observed"].get("name")
    for ent in entities:
        if ent["process"]["pid"] != pid:
            continue
        ent_create_time = ent["process"].get("create_time")
        if create_time and ent_create_time == create_time:
            return ent["process_entity_id"]
        if not create_time and not ent_create_time:
            if name and ent["process"].get("name") == name:
                return ent["process_entity_id"]
            if not name and not ent["process"].get("name"):
                return ent["process_entity_id"]
    # Fallback: first entity with same pid
    for ent in entities:
        if ent["process"]["pid"] == pid:
            return ent["process_entity_id"]
    return ""


# ---------------------------------------------------------------------------
# Querying canonical entities
# ---------------------------------------------------------------------------


def fetch_legacy_process_documents(case_id: str, *, run_id: str) -> list[dict[str, Any]]:
    """Pull all legacy ``memory_process`` documents for a given run."""
    client = get_opensearch_client()
    body = {
        "query": {
            "bool": {
                "filter": [
                    {"term": {"memory_artifact_type": "memory_process"}},
                    {"term": {"memory_run_id": run_id}},
                ]
            }
        },
        "size": 5000,
        "sort": [{"process.pid": {"order": "asc", "missing": "_last", "unmapped_type": "long"}}],
    }
    response = client.search(
        index=get_memory_index(case_id),
        body=body,
        params={"ignore_unavailable": "true"},
    )
    return [
        hit.get("_source", {}) | {"document_id": hit.get("_id")}
        for hit in response.get("hits", {}).get("hits", [])
    ]


def fetch_canonical_entities(
    case_id: str,
    *,
    run_id: str,
    evidence_id: str | None = None,
    visibility: str | None = None,
    source_plugin: str | None = None,
    process_name: str | None = None,
    pid: int | None = None,
    ppid: int | None = None,
    has_command_line: bool | None = None,
    interesting_only: bool | None = None,
    page: int = 1,
    page_size: int = 50,
) -> dict[str, Any]:
    page_size = min(max(int(page_size), 1), 200)
    page = max(int(page), 1)
    filters: list[dict[str, Any]] = [
        {"term": {"document_type.keyword": "memory_process_entity"}},
        {"term": {"scan_run_id.keyword": run_id}},
    ]
    if evidence_id:
        filters.append({"term": {"evidence_id.keyword": evidence_id}})
    if visibility:
        filters.append({"term": {f"visibility.{visibility}": True}})
    if source_plugin:
        filters.append({"term": {"source_plugins.keyword": source_plugin}})
    if pid is not None:
        filters.append({"term": {"process.pid": pid}})
    if ppid is not None:
        filters.append({"term": {"process.ppid": ppid}})
    if has_command_line is True:
        filters.append({"exists": {"field": "process.command_line"}})
    elif has_command_line is False:
        filters.append({"bool": {"must_not": [{"exists": {"field": "process.command_line"}}]}})
    if interesting_only:
        filters.append({"exists": {"field": "findings"}})
    must: list[dict[str, Any]] = []
    if process_name:
        safe_name = str(process_name).strip()[:128]
        if safe_name:
            must.append({"match_phrase_prefix": {"process.name.text": safe_name}})
    body = {
        "query": {"bool": {"filter": filters, "must": must}},
        "sort": [
            {"process.pid": {"order": "asc", "missing": "_last"}},
            {"document_id": {"order": "asc"}},
        ],
        "from": (page - 1) * page_size,
        "size": page_size,
        "timeout": "5s",
    }
    client = get_opensearch_client()
    response = client.search(
        index=get_memory_index(case_id),
        body=body,
        params={"ignore_unavailable": "true"},
    )
    hits = response.get("hits", {})
    total = hits.get("total", {})
    total_value = total.get("value", 0) if isinstance(total, dict) else int(total or 0)
    return {
        "items": [hit.get("_source", {}) | {"document_id": hit.get("_id")} for hit in hits.get("hits", [])],
        "total": total_value,
        "page": page,
        "page_size": page_size,
    }


def fetch_canonical_entity(case_id: str, *, run_id: str, entity_id: str) -> dict[str, Any] | None:
    client = get_opensearch_client()
    document_id = _entity_document_id(entity_id, run_id)
    try:
        response = client.get(index=get_memory_index(case_id), id=document_id)
    except Exception:  # noqa: BLE001
        return None
    source = response.get("_source")
    if isinstance(source, dict):
        source["document_id"] = response.get("_id")
    return source


def fetch_canonical_observations(case_id: str, *, run_id: str, entity_id: str) -> list[dict[str, Any]]:
    client = get_opensearch_client()
    body = {
        "query": {
            "bool": {
                "filter": [
                    {"term": {"document_type.keyword": "memory_process_observation"}},
                    {"term": {"scan_run_id.keyword": run_id}},
                    {"term": {"process_entity_id.keyword": entity_id}},
                ]
            }
        },
        "size": 100,
        "sort": [{"plugin_name.keyword": "asc"}],
    }
    response = client.search(
        index=get_memory_index(case_id),
        body=body,
        params={"ignore_unavailable": "true"},
    )
    return [
        hit.get("_source", {}) | {"document_id": hit.get("_id")}
        for hit in response.get("hits", {}).get("hits", [])
    ]


def fetch_canonical_edges(case_id: str, *, run_id: str) -> list[dict[str, Any]]:
    client = get_opensearch_client()
    body = {
        "query": {
            "bool": {
                "filter": [
                    {"term": {"document_type.keyword": "memory_process_edge"}},
                    {"term": {"scan_run_id.keyword": run_id}},
                ]
            }
        },
        "size": 10000,
    }
    response = client.search(
        index=get_memory_index(case_id),
        body=body,
        params={"ignore_unavailable": "true"},
    )
    return [
        hit.get("_source", {}) | {"document_id": hit.get("_id")}
        for hit in response.get("hits", {}).get("hits", [])
    ]


def fetch_canonical_tree(
    case_id: str,
    *,
    run_id: str,
    root_pid: int | None = None,
    root_entity_id: str | None = None,
    depth: int = 3,
    max_nodes: int | None = None,
    visibility: str | None = None,
    interesting_only: bool | None = None,
    include_ancestors: bool = False,
    orphans_only: bool = False,
    search: str | None = None,
) -> dict[str, Any]:
    """Build a tree-shaped response from canonical entities.

    Parameters:

    * ``root_pid`` / ``root_entity_id`` — scope the visible tree to a
      particular sub-tree.
    * ``depth`` — limit how deep we expand from each root.
    * ``max_nodes`` — global cap on returned nodes (truncated flag).
    * ``visibility`` — filter the set (e.g. ``"scan_only"``).
    * ``interesting_only`` — keep only entities with at least one
      finding.
    * ``include_ancestors`` — for a scoped root, also include the
      ancestor chain up to System.
    * ``orphans_only`` — return only orphan entities (separate view).
    * ``search`` — find an entity by exact PID or partial name; when
      set, ``include_ancestors`` is implied.
    """
    page_size = 200
    page = 1
    all_entities: list[dict[str, Any]] = []
    while True:
        result = fetch_canonical_entities(
            case_id,
            run_id=run_id,
            visibility=visibility,
            interesting_only=interesting_only,
            page=page,
            page_size=page_size,
        )
        items = result["items"]
        all_entities.extend(items)
        if len(items) < page_size:
            break
        page += 1
    metrics = build_tree_metrics(all_entities)

    # Search handling
    if search:
        needle = str(search).strip().lower()
        if needle:
            matches: list[dict[str, Any]] = []
            exact_match_ids: list[str] = []
            for e in all_entities:
                pid = e.get("process", {}).get("pid")
                name = (e.get("process", {}).get("name") or "").lower()
                cmdline = (e.get("process", {}).get("command_line") or "").lower()
                if needle.isdigit() and pid is not None and str(pid) == needle:
                    matches.append(e)
                    exact_match_ids.append(e["process_entity_id"])
                elif not needle.isdigit() and (needle in name or needle in cmdline):
                    matches.append(e)
            search_result_ids = [m["process_entity_id"] for m in matches]
            if not matches:
                empty_metrics = dict(metrics)
                empty_metrics.update(
                    {
                        "case_roots": metrics["roots"],
                        "current_view_roots": 0,
                        "visible_processes": 0,
                        "context_ancestors": 0,
                        "collapsed_branches": 0,
                        "processes_not_loaded": metrics["total_nodes"],
                        "search_results": [],
                    }
                )
                return {
                    "run_id": run_id,
                    "roots": [],
                    "orphans": [],
                    "top_level_nodes": [],
                    "nodes": [],
                    "edges": [],
                    "metrics": empty_metrics,
                    "total_entities": len(all_entities),
                    "omitted_count": len(all_entities),
                    "truncation_reason": "search_no_match",
                    "search_results": [],
                }
            # Build ancestor + descendant sub-trees for each match.
            by_id = {e["process_entity_id"]: e for e in all_entities}
            children_map: dict[str, list[dict[str, Any]]] = defaultdict(list)
            for e in all_entities:
                parent_id = e.get("parent_entity_id")
                if parent_id and parent_id in by_id:
                    children_map[parent_id].append(e)
            scope_ids: set[str] = set()
            search_result_ids: list[str] = []
            for match in matches:
                search_result_ids.append(match["process_entity_id"])
                # Ancestors
                cursor = match.get("parent_entity_id")
                if include_ancestors or True:
                    while cursor and cursor in by_id and cursor not in scope_ids:
                        scope_ids.add(cursor)
                        cursor = by_id[cursor].get("parent_entity_id")
                # Match itself
                scope_ids.add(match["process_entity_id"])
            # BFS descendants
            queue = [m["process_entity_id"] for m in matches]
            while queue:
                cur = queue.pop(0)
                for child in children_map.get(cur, []):
                    if child["process_entity_id"] not in scope_ids:
                        scope_ids.add(child["process_entity_id"])
                        queue.append(child["process_entity_id"])
            all_entities = [e for e in all_entities if e["process_entity_id"] in scope_ids]
            metrics = build_tree_metrics(all_entities)
            return _build_tree_response(
                all_entities=all_entities,
                run_id=run_id,
                depth=depth,
                max_nodes=max_nodes,
                search_results=search_result_ids,
                exact_match_ids=exact_match_ids,
            )

    if orphans_only:
        all_entities = [e for e in all_entities if e.get("tree", {}).get("is_orphan")]
        metrics = build_tree_metrics(all_entities)

    return _build_tree_response(
        all_entities=all_entities,
        run_id=run_id,
        depth=depth,
        max_nodes=max_nodes,
        root_pid=root_pid,
        root_entity_id=root_entity_id,
        include_ancestors=include_ancestors,
    )


def _build_tree_response(
    *,
    all_entities: list[dict[str, Any]],
    run_id: str,
    depth: int,
    max_nodes: int | None,
    root_pid: int | None = None,
    root_entity_id: str | None = None,
    include_ancestors: bool = False,
    search_results: list[str] | None = None,
    exact_match_ids: list[str] | None = None,
) -> dict[str, Any]:
    by_id = {e["process_entity_id"]: e for e in all_entities}
    children_map: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for e in all_entities:
        parent_id = e.get("parent_entity_id")
        if parent_id and parent_id in by_id:
            children_map[parent_id].append(e)

    # Determine the visible roots
    # The tree response separates:
    #   * roots  — entities flagged as is_root=True (a real root, e.g. System)
    #   * orphans — entities whose expected parent is missing in the set
    #   * top_level_nodes — presentational union (roots + orphans) used
    #     by the frontend "Orphans" block; orphans are *never* added to
    #     the roots list.
    if root_entity_id and root_entity_id in by_id:
        roots = [by_id[root_entity_id]]
        orphans: list[dict[str, Any]] = []
    elif root_pid is not None:
        roots = [e for e in all_entities if e["process"]["pid"] == root_pid]
        orphans = []
    else:
        # Strict: roots are exactly the is_root entities.  PID 0 (Idle)
        # is a technical entity that never replaces System as the user-
        # visible root; if it is flagged as is_root (which it should not
        # be after the canonical normalizer), we still drop it.
        pid_zero_ids = {e["process_entity_id"] for e in all_entities if e["process"]["pid"] == 0}
        roots = [
            e
            for e in all_entities
            if e.get("tree", {}).get("is_root") and e["process_entity_id"] not in pid_zero_ids
        ]
        # Orphans are entities with no parent in the set, AND that are
        # not already counted as a root.
        root_ids = {r["process_entity_id"] for r in roots}
        orphans = [
            e
            for e in all_entities
            if e.get("parent_entity_id") is None
            and e["process_entity_id"] not in root_ids
            and e["process_entity_id"] not in pid_zero_ids
        ]

    # Ancestor expansion
    if include_ancestors and roots and not root_entity_id and root_pid is None:
        # Already anchored at roots; no extra work.
        pass

    def _walk(ent: dict[str, Any], level: int, visited: set[str], remaining: list[int]) -> dict[str, Any]:
        eid = ent["process_entity_id"]
        if eid in visited or level > depth or remaining[0] <= 0:
            return {
                "process_entity_id": eid,
                "pid": ent["process"]["pid"],
                "name": ent["process"].get("name"),
                "truncated": True,
                "children": [],
                "omitted_children": 0,
            }
        visited = visited | {eid}
        remaining[0] -= 1
        children = []
        for child in sorted(children_map.get(eid, []), key=lambda c: c["process"]["pid"]):
            if remaining[0] <= 0:
                children.append({
                    "process_entity_id": child["process_entity_id"],
                    "pid": child["process"]["pid"],
                    "name": child["process"].get("name"),
                    "truncated": True,
                    "children": [],
                    "omitted_children": 0,
                })
                continue
            children.append(_walk(child, level + 1, visited, remaining))
        total_child_count = ent.get("child_count", len(children_map.get(eid, [])))
        omitted = max(0, total_child_count - len(children))
        return {
            "process_entity_id": eid,
            "pid": ent["process"]["pid"],
            "ppid": ent["process"].get("ppid"),
            "name": ent["process"].get("name"),
            "command_line": ent["process"].get("command_line"),
            "sources": ent.get("sources", []),
            "visibility": ent.get("visibility", {}),
            "findings": ent.get("findings", []),
            "child_count": total_child_count,
            "confidence": ent.get("confidence", "low"),
            "create_time": ent.get("process", {}).get("create_time"),
            "exit_time": ent.get("process", {}).get("exit_time"),
            "tree": ent.get("tree", {}),
            "children": children,
            "omitted_children": omitted,
        }

    cap = [max_nodes] if max_nodes else [10**9]
    nodes = [_walk(r, 0, set(), cap) for r in sorted(roots, key=lambda e: e["process"]["pid"])]
    included_count = sum(1 + _count_subtree(n) for n in nodes)
    omitted_count = max(0, len(all_entities) - included_count)
    truncation_reason = None
    if cap[0] <= 0:
        truncation_reason = "max_nodes_reached"
    elif omitted_count > 0:
        truncation_reason = "depth_or_root_scope"

    # Top-level nodes are the presentational union of roots and orphans.
    # Orphans are rendered flat (no children) to keep the
    # "Parent process is not present in the selected run" panel honest.
    orphan_nodes: list[dict[str, Any]] = []
    for orph in sorted(orphans, key=lambda e: e["process"]["pid"]):
        orphan_nodes.append(
            {
                "process_entity_id": orph["process_entity_id"],
                "pid": orph["process"]["pid"],
                "ppid": orph["process"].get("ppid"),
                "name": orph["process"].get("name"),
                "command_line": orph["process"].get("command_line"),
                "sources": orph.get("sources", []),
                "visibility": orph.get("visibility", {}),
                "findings": orph.get("findings", []),
                "child_count": orph.get("child_count", 0),
                "confidence": orph.get("confidence", "low"),
                "create_time": orph.get("process", {}).get("create_time"),
                "exit_time": orph.get("process", {}).get("exit_time"),
                "tree": orph.get("tree", {}),
                "children": [],
                "omitted_children": 0,
            }
        )
    top_level_nodes = nodes + orphan_nodes
    return {
        "run_id": run_id,
        "roots": [_root_summary(r) for r in sorted(roots, key=lambda e: e["process"]["pid"])],
        "orphans": [_orphan_summary(o) for o in sorted(orphans, key=lambda e: e["process"]["pid"])],
        "top_level_nodes": top_level_nodes,
        "nodes": top_level_nodes,
        "edges": [],
        "metrics": _build_metrics_for_visible(
            all_entities,
            nodes,
            orphan_nodes=orphan_nodes,
            roots=roots,
            orphans=orphans,
            search_results=search_results,
        ),
        "total_entities": len(all_entities),
        "omitted_count": omitted_count,
        "truncation_reason": truncation_reason,
        "search_results": search_results or [],
        "exact_match_ids": exact_match_ids or [],
    }


def _root_summary(entity: dict[str, Any]) -> dict[str, Any]:
    return {
        "process_entity_id": entity["process_entity_id"],
        "pid": entity["process"]["pid"],
        "name": entity["process"].get("name"),
        "command_line": entity["process"].get("command_line"),
        "sources": entity.get("sources", []),
        "visibility": entity.get("visibility", {}),
        "findings": entity.get("findings", []),
        "confidence": entity.get("confidence", "low"),
        "create_time": entity.get("process", {}).get("create_time"),
        "exit_time": entity.get("process", {}).get("exit_time"),
        "tree": entity.get("tree", {}),
    }


def _orphan_summary(entity: dict[str, Any]) -> dict[str, Any]:
    return _root_summary(entity)


def _build_metrics_for_visible(
    all_entities: list[dict[str, Any]],
    nodes: list[dict[str, Any]],
    *,
    orphan_nodes: list[dict[str, Any]] | None = None,
    roots: list[dict[str, Any]] | None = None,
    orphans: list[dict[str, Any]] | None = None,
    search_results: list[str] | None = None,
) -> dict[str, Any]:
    """Single source of truth for tree metrics.

    ``case_roots`` and ``orphans`` describe the *underlying* canonical
    set for the run (independent of the visible sub-tree), while
    ``visible_processes`` / ``current_view_roots`` describe the
    *current* filter scope.  ``search_results`` carries the matching
    entity ids so the UI can show "matching" without a second query.
    """
    base = build_tree_metrics(all_entities)
    visible_ids: set[str] = set()

    def _collect(n: dict[str, Any]) -> None:
        visible_ids.add(n["process_entity_id"])
        for c in n.get("children", []) or []:
            _collect(c)

    for n in nodes:
        _collect(n)
    for n in orphan_nodes or []:
        _collect(n)

    collapsed_branches = sum(1 for n in nodes if n.get("truncated"))
    processes_not_loaded = base["total_nodes"] - len(visible_ids)
    return {
        **base,
        # Single source of truth (renamed for clarity in the UI):
        "case_roots": base["roots"],
        "current_view_roots": len(roots or []),
        "visible_processes": len(visible_ids),
        "context_ancestors": 0,  # populated by the include_ancestors flow at the caller
        "collapsed_branches": collapsed_branches,
        "processes_not_loaded": processes_not_loaded,
        "search_results": search_results or [],
    }


def _count_subtree(node: dict[str, Any]) -> int:
    if not node.get("children"):
        return 0
    return sum(1 + _count_subtree(c) for c in node["children"])


def fetch_canonical_summary(case_id: str, *, run_id: str) -> dict[str, Any]:
    """Aggregate counts for a renormalized run."""
    client = get_opensearch_client()
    body = {
        "size": 0,
        "query": {
            "bool": {
                "filter": [
                    {"term": {"document_type.keyword": "memory_process_entity"}},
                    {"term": {"scan_run_id.keyword": run_id}},
                ]
            }
        },
        "aggs": {
            "listed": {"filter": {"term": {"visibility.listed": True}}},
            "scan_only": {"filter": {"term": {"visibility.scan_only": True}}},
            "terminated": {"filter": {"term": {"visibility.terminated": True}}},
            "unknown": {"filter": {"term": {"visibility.unknown": True}}},
            "hidden_candidate": {"filter": {"term": {"visibility.hidden_candidate": True}}},
            "root": {"filter": {"term": {"tree.is_root": True}}},
            "orphan": {"filter": {"term": {"tree.is_orphan": True}}},
            "unknown_parent": {"filter": {"term": {"tree.is_unknown_parent": True}}},
            "cycle": {"filter": {"term": {"tree.is_cycle": True}}},
            "self_parent": {"filter": {"term": {"tree.is_self_parent": True}}},
            "pid_zero": {"filter": {"term": {"tree.is_pid_zero": True}}},
            "pid_4": {"filter": {"term": {"process.pid": 4}}},
        },
    }
    response = client.search(
        index=get_memory_index(case_id),
        body=body,
        params={"ignore_unavailable": "true"},
    )
    aggs = response.get("aggregations", {})
    total = response.get("hits", {}).get("total", {})
    total_value = total.get("value", 0) if isinstance(total, dict) else int(total or 0)
    return {
        "run_id": run_id,
        "total_entities": total_value,
        "listed": aggs.get("listed", {}).get("doc_count", 0),
        "scan_only": aggs.get("scan_only", {}).get("doc_count", 0),
        "terminated": aggs.get("terminated", {}).get("doc_count", 0),
        "unknown": aggs.get("unknown", {}).get("doc_count", 0),
        "hidden_candidate": aggs.get("hidden_candidate", {}).get("doc_count", 0),
        "roots": aggs.get("root", {}).get("doc_count", 0),
        "orphans": aggs.get("orphan", {}).get("doc_count", 0),
        "unknown_parent": aggs.get("unknown_parent", {}).get("doc_count", 0),
        "cycles": aggs.get("cycle", {}).get("doc_count", 0),
        "self_parent": aggs.get("self_parent", {}).get("doc_count", 0),
        "pid_zero": aggs.get("pid_zero", {}).get("doc_count", 0),
        "pid_4": aggs.get("pid_4", {}).get("doc_count", 0),
        "normalization_version": NORMALIZATION_VERSION,
    }
