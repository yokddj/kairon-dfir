#!/usr/bin/env bash
set -euo pipefail
# Kairon fresh clone smoke test (reduced)
# Run: bash scripts/fresh-clone-smoke-test.sh

echo "=== Kairon Fresh Clone Smoke Test ==="
WAIT_SEC=5

check_http() {
    local url="$1"
    local desc="$2"
    for i in $(seq 1 12); do
        if curl -fsS -o /dev/null "$url" 2>/dev/null; then
            echo "  OK  $desc -> $url"
            return 0
        fi
        sleep $WAIT_SEC
    done
    echo "  FAIL $desc -> $url"
    exit 1
}

echo "--- Health ---"
check_http "http://localhost:8000/api/system/version" "version endpoint"
check_http "http://localhost:8000/api/cases" "cases API"
check_http "http://localhost:5173/" "frontend root"

echo "--- Docker ---"
docker compose ps --format "table {{.Service}}\t{{.Status}}" 2>/dev/null || echo "  WARN docker not available"

echo "--- Version ---"
curl -sS http://localhost:8000/api/system/version | python3 -m json.tool 2>/dev/null || echo "version check skipped"

echo ""
echo "PASS: Smoke test completed"
echo "  Verified: version endpoint, cases API, frontend root"
echo "  Next: create case, upload evidence, search, rules, findings"
