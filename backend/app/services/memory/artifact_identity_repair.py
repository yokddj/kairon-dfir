"""Give envars/getsids/privileges documents the ids every memory view filters on.

Until 2026-10-20 those three normalizers indexed their rows without
case_id, evidence_id, scan_run_id and plugin_run_id, so the SIDs,
environment variables and privileges of a run were in the memory index
but no view, count or lookup could find them. Each document id is
"<scan run>:<plugin run>:<row>", so the plugin run identifies them; the
pass is idempotent and only touches documents still missing evidence_id.
"""

from __future__ import annotations

import logging

from sqlalchemy.orm import Session

from app.core.opensearch import get_memory_index, get_opensearch_client
from app.models.memory import MemoryPluginRun

logger = logging.getLogger(__name__)

REPAIRED_PLUGINS = {
    "windows.envars": "memory_environment_variable",
    "windows.getsids": "memory_sid",
    "windows.privileges": "memory_privilege",
}

_SCRIPT = (
    "ctx._source.case_id = params.case_id; ctx._source.evidence_id = params.evidence_id; "
    "ctx._source.scan_run_id = params.scan_run_id; ctx._source.plugin_run_id = params.plugin_run_id;"
)


def repair_memory_artifact_identity(db: Session) -> int:
    client = get_opensearch_client()
    repaired = 0
    plugin_runs = db.query(MemoryPluginRun).filter(MemoryPluginRun.plugin.in_(list(REPAIRED_PLUGINS))).all()
    for plugin_run in plugin_runs:
        index = get_memory_index(plugin_run.case_id)
        if not client.indices.exists(index=index):
            continue
        scan_run_id = str(plugin_run.memory_scan_run_id)
        body = {
            "query": {
                "bool": {
                    "filter": [
                        {"bool": {"should": [{"term": {field: REPAIRED_PLUGINS[plugin_run.plugin]}} for field in ("document_type", "document_type.keyword")], "minimum_should_match": 1}},
                        {"prefix": {"document_id": f"{scan_run_id}:{plugin_run.id}:"}},
                    ],
                    "must_not": [{"exists": {"field": "evidence_id"}}],
                }
            },
            "script": {
                "source": _SCRIPT,
                "lang": "painless",
                "params": {
                    "case_id": str(plugin_run.case_id),
                    "evidence_id": str(plugin_run.evidence_id),
                    "scan_run_id": scan_run_id,
                    "plugin_run_id": str(plugin_run.id),
                },
            },
        }
        result = client.update_by_query(index=index, body=body, params={"conflicts": "proceed", "refresh": "true"})
        repaired += int(result.get("updated") or 0)
    return repaired
