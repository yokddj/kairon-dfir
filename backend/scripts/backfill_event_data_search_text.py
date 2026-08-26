"""Backfill: fold windows.event_data values into search_text for already
indexed events.

Mirrors _windows_event_data_search_values() in app/ingest/normalizer.py. New
ingests get this for free; this exists so existing cases do not stay
unsearchable until someone re-ingests hundreds of gigabytes of evidence.

Idempotent: documents that already contain the marker are skipped, so it can be
re-run safely.
"""
import json
import sys

sys.path.insert(0, "/app")
from app.core.opensearch import get_opensearch_client  # noqa: E402

CASE_ID = sys.argv[1] if len(sys.argv) > 1 else "cc7ac525-479a-44e9-b04b-f998aacb99c5"
INDEX = f"dfir-events-{CASE_ID}"

SKIP_KEYS = ["raw_xml", "payload_columns", "event_data_summary"]
PLACEHOLDERS = ["-", "--", "0x0", "0", "n/a", "null", "none", "%%1833", "%%1843"]

SCRIPT = """
def w = ctx._source.windows;
if (w == null || !(w instanceof Map)) { ctx.op = 'noop'; return; }
def ed = w.event_data;
if (ed == null || !(ed instanceof Map)) { ctx.op = 'noop'; return; }
def existing = ctx._source.search_text;
if (existing == null) { existing = ''; }
def added = new ArrayList();
def seen = new HashSet();
for (entry in ed.entrySet()) {
  if (added.size() >= params.max_values) { break; }
  def k = entry.getKey().toString().toLowerCase();
  if (params.skip_keys.contains(k)) { continue; }
  def v = entry.getValue();
  if (v == null || v instanceof Map || v instanceof List) { continue; }
  def text = v.toString().trim();
  if (text.length() == 0 || text.length() > params.max_chars) { continue; }
  def lowered = text.toLowerCase();
  if (params.placeholders.contains(lowered)) { continue; }
  if (seen.contains(lowered)) { continue; }
  if (existing.toLowerCase().contains(lowered)) { continue; }
  seen.add(lowered);
  added.add(text);
}
if (added.size() == 0) { ctx.op = 'noop'; return; }
def joined = String.join(' | ', added);
def merged = existing.length() > 0 ? existing + ' | ' + joined : joined;
if (merged.length() > 8192) { merged = merged.substring(0, 8192); }
ctx._source.search_text = merged;
"""

client = get_opensearch_client(timeout_seconds=1800)
body = {
    "query": {"bool": {"filter": [{"term": {"case_id": CASE_ID}}, {"exists": {"field": "windows.event_id"}}]}},
    "script": {
        "source": SCRIPT,
        "lang": "painless",
        "params": {
            "skip_keys": SKIP_KEYS,
            "placeholders": PLACEHOLDERS,
            "max_chars": 512,
            "max_values": 60,
        },
    },
}
# Run asynchronously and poll: a synchronous update_by_query over a large index
# keeps the connection alive with periodic headers and trips Python's 100-header
# limit before the work finishes.
import time  # noqa: E402

submitted = client.update_by_query(
    index=INDEX,
    body=body,
    params={"conflicts": "proceed", "refresh": "true", "wait_for_completion": "false"},
)
task_id = submitted.get("task")
print(f"task: {task_id}", flush=True)
while True:
    status = client.tasks.get(task_id=task_id)
    if status.get("completed"):
        response = status.get("response") or {}
        print(json.dumps({k: response.get(k) for k in ("total", "updated", "noops", "version_conflicts", "failures")}, indent=2))
        break
    st = (status.get("task") or {}).get("status") or {}
    print(f"  progreso: {st.get('updated', 0)} actualizados de {st.get('total', 0)}", flush=True)
    time.sleep(15)
