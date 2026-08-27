"""Backfill: promote high-value windows.event_data keys into fields of their own.

Mirrors _PROMOTED_EVENT_DATA_FIELDS in app/ingest/normalizer.py. New ingests get
these for free; this exists so an existing case does not have to be re-ingested
before Sigma rules that key on them can be evaluated -- on a real SigmaHQ pack
OriginalFileName alone was blocking 559 rules.

Idempotent: a document whose target field is already set is left alone, so a
value a dedicated parser established is never overwritten and re-runs are safe.
"""
import json
import sys
import time

sys.path.insert(0, "/app")
from app.core.opensearch import get_opensearch_client  # noqa: E402

CASE_ID = sys.argv[1] if len(sys.argv) > 1 else ""
if not CASE_ID:
    raise SystemExit("usage: backfill_promoted_event_data_fields.py <case_id>")
INDEX = f"dfir-events-{CASE_ID}"

# event_data key -> (document section, field name). Kept identical to the
# normalizer's allow-list; if they drift, freshly ingested and backfilled
# documents stop agreeing, which is worse than either alone.
PROMOTIONS = {
    "OriginalFileName": ["process", "original_file_name"],
    "IntegrityLevel": ["process", "integrity_level_name"],
    "Description": ["process", "description"],
    "Product": ["process", "product"],
    "Company": ["process", "company"],
}
PLACEHOLDERS = ["-", "--", "0x0", "0", "n/a", "null", "none"]

SCRIPT = """
def w = ctx._source.windows;
if (w == null || !(w instanceof Map)) { ctx.op = 'noop'; return; }
def ed = w.event_data;
if (ed == null || !(ed instanceof Map)) { ctx.op = 'noop'; return; }
boolean changed = false;
for (entry in params.promotions.entrySet()) {
  def raw = ed.get(entry.getKey());
  if (raw == null) { continue; }
  def text = raw.toString().trim();
  if (text.length() == 0 || params.placeholders.contains(text.toLowerCase())) { continue; }
  def target = entry.getValue();
  def section = target.get(0);
  def field = target.get(1);
  if (ctx._source[section] == null) { ctx._source[section] = new HashMap(); }
  def block = ctx._source[section];
  if (!(block instanceof Map)) { continue; }
  def current = block.get(field);
  if (current != null && current.toString().length() > 0) { continue; }
  block.put(field, text);
  changed = true;
}
if (!changed) { ctx.op = 'noop'; }
"""

client = get_opensearch_client()
body = {
    "query": {"bool": {"filter": [{"term": {"case_id": CASE_ID}}, {"exists": {"field": "windows.event_id"}}]}},
    "script": {
        "source": SCRIPT,
        "lang": "painless",
        "params": {"promotions": PROMOTIONS, "placeholders": PLACEHOLDERS},
    },
}
# Asynchronous with polling: a synchronous update_by_query over a large index
# keeps the connection alive with periodic headers and trips Python's 100-header
# limit before the work finishes.
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
    time.sleep(10)
