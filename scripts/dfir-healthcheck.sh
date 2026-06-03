#!/usr/bin/env sh
set -eu

BASE_URL="${DFIR_BACKEND_URL:-http://127.0.0.1:8000}"
FRONTEND_URL="${DFIR_FRONTEND_URL:-http://127.0.0.1:5173}"

http_code() {
  url="$1"
  curl -fsS -o /dev/null -w "%{http_code}" "$url" 2>/dev/null || printf "000"
}

echo "DFIR health check"
echo "backend_url=${BASE_URL}"
echo "frontend_url=${FRONTEND_URL}"

frontend_code="$(http_code "$FRONTEND_URL")"
docs_code="$(http_code "$BASE_URL/docs")"
health_body="$(curl -fsS "$BASE_URL/health" 2>/dev/null || true)"
status_body="$(curl -fsS "$BASE_URL/api/system/status" 2>/dev/null || true)"
task_body="$(curl -fsS "$BASE_URL/api/system/task-health" 2>/dev/null || true)"

python3 - "$frontend_code" "$docs_code" "$health_body" "$status_body" "$task_body" <<'PY'
import json
import sys

frontend_code, docs_code, health_body, status_body, task_body = sys.argv[1:6]

def parse_json(value):
    try:
        return json.loads(value) if value else {}
    except Exception:
        return {}

health = parse_json(health_body)
status = parse_json(status_body)
tasks = parse_json(task_body)

checks = []
checks.append(("frontend", frontend_code == "200", f"http={frontend_code}"))
checks.append(("backend_docs", docs_code == "200", f"http={docs_code}"))
checks.append(("backend_health", health.get("status") == "ok", f"status={health.get('status', 'unavailable')}"))

opensearch = status.get("opensearch") or {}
checks.append(("opensearch", bool(opensearch.get("available")) and str(opensearch.get("cluster_status", "")).lower() in {"green", "yellow"}, f"status={opensearch.get('cluster_status', 'unknown')} available={opensearch.get('available')}"))

queues = status.get("queues") or {}
queue_bad = []
queue_failed_history = []
for name, payload in queues.items():
    queued = int((payload or {}).get("queued") or 0)
    failed = int((payload or {}).get("failed") or 0)
    started = int((payload or {}).get("started") or 0)
    if queued or started:
        queue_bad.append(f"{name}:queued={queued},started={started}")
    if failed:
        queue_failed_history.append(f"{name}:failed={failed}")
checks.append(("queues", not queue_bad, ", ".join(queue_bad) or "clean"))
checks.append(("queue_failed_history", True, ", ".join(queue_failed_history) or "none"))

workers = status.get("workers") or {}
checks.append(("worker", int(workers.get("active") or 0) > 0, f"active={workers.get('active', 0)}"))

disk = status.get("disk") or {}
disk_percent = float(disk.get("data_dir_percent") or 0)
checks.append(("disk", disk_percent < 85, f"data_dir_percent={disk_percent:.1f}"))

ez = status.get("ez_parser_tools") or {}
available_tools = sorted(name for name, info in ez.items() if isinstance(info, dict) and info.get("available"))
checks.append(("parser_tools", bool(available_tools), f"available={','.join(available_tools[:8]) or 'none'}"))

task_warnings = (tasks.get("warnings") or []) if isinstance(tasks, dict) else []
checks.append(("task_health", not task_warnings, f"warnings={len(task_warnings)}"))

overall = "healthy"
if any(not ok for _, ok, _ in checks):
    overall = "degraded"

print(f"overall={overall}")
for name, ok, detail in checks:
    print(f"{name}={'ok' if ok else 'degraded'} {detail}")

sys.exit(0 if overall == "healthy" else 1)
PY
