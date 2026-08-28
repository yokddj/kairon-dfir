"""Make newly-mapped fields searchable on an already-indexed case.

ensure_case_index sends new fields to existing indices, but a mapping only
governs documents indexed after it exists: values already sitting in _source
stay invisible until the documents are rewritten. This rewrites them in place.

Needed after an upgrade that adds fields -- the linux block, or the Sysmon keys
promoted out of windows.event_data -- on a case that was ingested before it.
A fresh install never needs this; a fresh ingest into an upgraded install does
not either.

Nothing is recomputed and no document changes content: this only re-runs the
existing _source through the current mapping.
"""
import json
import sys
import time

sys.path.insert(0, "/app")
from app.core.opensearch import ensure_case_index, get_events_index, get_opensearch_client  # noqa: E402

CASE_ID = sys.argv[1] if len(sys.argv) > 1 else ""
if not CASE_ID:
    raise SystemExit("usage: reindex_case_for_new_mappings.py <case_id>")

client = get_opensearch_client()
# Push the current mapping first, or the rewrite has nothing new to index into.
ensure_case_index(CASE_ID)
index = get_events_index(CASE_ID)

submitted = client.update_by_query(
    index=index,
    body={"query": {"match_all": {}}},
    params={"conflicts": "proceed", "refresh": "true", "wait_for_completion": "false"},
)
task_id = submitted.get("task")
print(f"task: {task_id}", flush=True)
while True:
    status = client.tasks.get(task_id=task_id)
    if status.get("completed"):
        response = status.get("response") or {}
        print(json.dumps({k: response.get(k) for k in ("total", "updated", "version_conflicts", "failures")}, indent=2))
        break
    st = (status.get("task") or {}).get("status") or {}
    print(f"  progreso: {st.get('updated', 0)} de {st.get('total', 0)}", flush=True)
    time.sleep(10)
