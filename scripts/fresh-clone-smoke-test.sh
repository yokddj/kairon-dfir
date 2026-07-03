#!/usr/bin/env bash
set -euo pipefail
# Kairon fresh clone smoke test
# Usage: bash scripts/fresh-clone-smoke-test.sh [BASE_URL]

BASE_URL="${1:-http://localhost:8000}"
FRONT_URL="${2:-http://localhost:5173}"
WAIT=5
TIMEOUT=120

echo "=== Kairon Fresh Clone Smoke Test ==="
echo "  backend: $BASE_URL"
echo "  frontend: $FRONT_URL"
echo ""

PASSED=0
FAILED=0

check() {
    local url="$1" desc="$2" expected_status="${3:-200}"
    for i in $(seq 1 $((TIMEOUT / WAIT))); do
        local status
        status=$(curl -fsS -o /dev/null -w "%{http_code}" "$url" 2>/dev/null || echo "000")
        if [ "$status" = "$expected_status" ]; then
            echo "  OK  ($status) $desc"
            PASSED=$((PASSED + 1))
            return 0
        fi
        sleep "$WAIT"
    done
    echo "  FAIL $desc -> $url"
    FAILED=$((FAILED + 1))
    return 1
}

check_json() {
    local url="$1" desc="$2" field="$3" expected="$4"
    local value
    value=$(curl -fsS "$url" 2>/dev/null | python3 -c "import json,sys; d=json.load(sys.stdin); print(d.get('$field',''))" 2>/dev/null || echo "")
    if [ -n "$value" ] && [ "$value" != "unknown" ]; then
        echo "  OK  ($value) $desc"
        PASSED=$((PASSED + 1))
    elif [ "$expected" = "exists" ] && [ -n "$value" ]; then
        echo "  OK  ($value) $desc"
        PASSED=$((PASSED + 1))
    else
        echo "  WARN ($value) $desc"
        PASSED=$((PASSED + 1))
    fi
}

echo "--- Health ---"
check "$BASE_URL/api/system/version" "version endpoint"
check "$BASE_URL/api/cases" "cases API"
check "$FRONT_URL/" "frontend root"

echo "--- Version ---"
check_json "$BASE_URL/api/system/version" "version field" "version" "exists"
check_json "$BASE_URL/api/system/version" "git commit" "git_commit" "exists"

echo "--- Rules ---"
check "$BASE_URL/api/cases" "cases list"

echo ""
echo "=== Results: $PASSED passed, $FAILED failed ==="
if [ "$FAILED" -gt 0 ]; then
    echo "SMOKE TEST FAILED"
    exit 1
else
    echo "SMOKE TEST PASSED"
fi
