from __future__ import annotations

import logging
from typing import Any

from app.core.opensearch import get_memory_index, get_opensearch_client


logger = logging.getLogger(__name__)


MEMORY_SYSTEM_INFO_MAPPING = {
    "mappings": {
        "dynamic": True,
        "properties": {
            "case_id": {"type": "keyword"},
            "evidence_id": {"type": "keyword"},
            "memory_run_id": {"type": "keyword"},
            "memory_plugin_run_id": {"type": "keyword"},
            "source_layer": {"type": "keyword"},
            "memory_artifact_type": {"type": "keyword"},
            "backend": {"type": "keyword"},
            "plugin": {"type": "keyword"},
            "os": {
                "properties": {
                    "family": {"type": "keyword"},
                    "kernel_version": {"type": "keyword"},
                    "machine_type": {"type": "keyword"},
                }
            },
            "memory": {"properties": {"system_time": {"type": "date", "ignore_malformed": True}}},
            "parsed_at": {"type": "date"},
        },
    }
}


def ensure_memory_index(case_id: str) -> str:
    client = get_opensearch_client()
    index = get_memory_index(case_id)
    if not client.indices.exists(index=index):
        client.indices.create(index=index, body=MEMORY_SYSTEM_INFO_MAPPING)
    return index


def index_memory_system_info(case_id: str, document: dict[str, Any]) -> dict[str, Any]:
    index = ensure_memory_index(case_id)
    client = get_opensearch_client()
    response = client.index(index=index, id=f"{document['memory_plugin_run_id']}:memory_system_info", body=document, refresh=True)
    logger.info("memory system info indexed", extra={"case_id": case_id, "run_id": document.get("memory_run_id"), "index": index})
    return {"index": index, "id": response.get("_id"), "result": response.get("result")}
