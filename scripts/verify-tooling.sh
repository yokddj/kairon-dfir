#!/usr/bin/env bash
set -euo pipefail

# Kairon tool verification script
# Checks that all required external tools are present and executable
# Run: bash scripts/verify-tooling.sh

echo "=== Kairon Tooling Verification ==="

MISSING=0

check_tool() {
    local name="$1"
    local path="${2:-}"
    local required="${3:-true}"
    if [ -z "$path" ]; then
        path=$(which "$name" 2>/dev/null || echo "")
    fi
    if [ -n "$path" ] && [ -e "$path" ]; then
        echo "  OK  $name -> $path"
    elif [ "$required" = "true" ]; then
        echo "  FAIL $name (not found)"
        MISSING=$((MISSING + 1))
    else
        echo "  WARN $name (not found, optional)"
    fi
}

echo "--- Python Tools ---"
check_tool "python3" "$(which python3 || echo '')" "true"
check_tool "vol" "$(which vol 2>/dev/null || echo '')" "false"
check_tool "dotnet" "/usr/local/bin/dotnet" "false"

echo "--- Eric Zimmerman Tools ---"
for tool in EvtxECmd.dll LECmd.dll JLECmd.dll PECmd.dll AmcacheParser.dll AppCompatCacheParser.dll RECmd.dll MFTECmd.dll SrumECmd.dll; do
    base="/opt/eztools/${tool%.dll}/${tool}"
    if [ -f "$base" ]; then
        echo "  OK  $tool -> $base"
    elif [ -f "/opt/evtxecmd/$tool" ]; then
        echo "  OK  $tool -> /opt/evtxecmd/$tool"
    else
        echo "  WARN $tool (not found; optional unless parsing that artifact type)"
    fi
done

echo "--- System ---"
check_tool "curl" "" "true"
check_tool "p7zip" "$(which 7z 2>/dev/null || which p7zip 2>/dev/null || echo '')" "true"

echo ""
if [ "$MISSING" -gt 0 ]; then
    echo "FAIL: $MISSING required tools missing"
    exit 1
else
    echo "PASS: All required tools present"
fi
