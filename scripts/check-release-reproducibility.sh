#!/usr/bin/env bash
set -euo pipefail
# Check Kairon release reproducibility
# Run: bash scripts/check-release-reproducibility.sh

echo "=== Kairon Release Reproducibility Check ==="
HAS_ISSUES=0

check() {
    local severity="$1" pattern="$2" msg="$3"
    if grep -r "$pattern" Dockerfile* docker-compose*.yml backend/Dockerfile frontend/Dockerfile docker/ 2>/dev/null | grep -v "^Binary" | grep -v "^#" > /tmp/kairon_check.tmp; then
        if [ "$severity" = "ERROR" ]; then
            echo "  FAIL $msg"
            cat /tmp/kairon_check.tmp
            HAS_ISSUES=1
        else
            echo "  WARN $msg"
        fi
    else
        echo "  OK   $msg"
    fi
}

check_result() {
    if [ "$HAS_ISSUES" -gt 0 ]; then
        echo "FAIL: reproducibility issues found"
        exit 1
    else
        echo "PASS: release appears reproducible"
    fi
}

echo "--- Dockerfile tags ---"
check "ERROR" "FROM.*:latest" "Floating :latest tags found"
check "ERROR" "FROM nginx:stable-alpine" "Floating stable-alpine (add @sha256 digest)"
check "ERROR" "FROM node:20-alpine" "Floating node:20-alpine (add @sha256 digest)"
check "ERROR" "FROM python:3.12-slim" "Floating python:3.12-slim (add @sha256 digest)"
check "ERROR" "FROM postgres:16-alpine" "Floating postgres:16-alpine (add @sha256 digest)"
check "ERROR" "FROM redis:7-alpine" "Floating redis:7-alpine (add @sha256 digest)"

echo "--- Tool downloads ---"
check "ERROR" "latest" "latest references in download URLs"
check "WARN" "ericzimmermanstools.com/net9" "EZ tools use mutable net9 path (no version pin)"

echo "--- Version metadata ---"
check "ERROR" "KAIRON_COMMIT:-unknown" "KAIRON_COMMIT defaults to unknown"
check "WARN" "BUILD_DATE:-unknown" "BUILD_DATE defaults to unknown"

echo "--- Redis ---"
check "WARN" "redis.*without.*health" "Redis may lack healthcheck" 2>/dev/null
if grep -q "redis-cli ping" docker-compose.yml 2>/dev/null; then
    echo "  OK   Redis has healthcheck"
fi
if grep -q "appendonly" docker-compose.yml 2>/dev/null; then
    echo "  OK   Redis has AOF persistence"
fi

echo "--- Restart policies ---"
for svc in backend frontend worker postgres redis opensearch; do
    if grep -A5 "  $svc:" docker-compose.yml 2>/dev/null | grep -q "restart:"; then
        echo "  OK   $svc has restart policy"
    else
        echo "  WARN $svc may lack restart policy"
    fi
done

echo ""
check_result
