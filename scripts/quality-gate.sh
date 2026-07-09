#!/usr/bin/env bash
# Kairon DFIR local quality gate — replicates CI checks locally.
# Usage:
#   ./scripts/quality-gate.sh           run all available checks
#   ./scripts/quality-gate.sh --fast    skip expensive checks (build, tests)
#   ./scripts/quality-gate.sh --full    run everything including docker compose
#   ./scripts/quality-gate.sh --no-docker  skip docker-dependent checks
#   ./scripts/quality-gate.sh --help    show this message

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"

FAST=false
FULL=false
NO_DOCKER=false
FAILURES=0

usage() {
  cat <<'EOF' >&2
Kairon DFIR quality gate — run CI checks locally.

Usage: bash scripts/quality-gate.sh [OPTIONS]

Options:
  --fast        Skip slow checks (build, backend tests)
  --full        Run all checks including docker compose
  --no-docker   Skip docker-dependent checks
  --help        Show this message
EOF
  exit 0
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --fast) FAST=true; shift ;;
    --full) FULL=true; shift ;;
    --no-docker) NO_DOCKER=true; shift ;;
    -h|--help) usage ;;
    *) echo "Unknown: $1" >&2; usage; exit 2 ;;
  esac
done

pass()  { echo "  PASS: $1"; }
fail()  { echo "  FAIL: $1"; FAILURES=$((FAILURES + 1)); }
warn()  { echo "  WARN: $1"; }
check() { if eval "$2" 2>/dev/null; then pass "$1"; else fail "$1 ($2)"; fi; }

cd "$ROOT_DIR"

echo "=== Kairon DFIR Quality Gate ==="
echo ""

# ---- Always run ----
echo "--- Repository sanity ---"
check "README exists"       "test -f README.md"
check ".env.example exists" "test -f .env.example"
check "docker-compose.yml"  "test -f docker-compose.yml"
check "setup.sh exists"     "test -f scripts/setup.sh"
check "no em-dash in flags" "! grep -rPn '\xe2\x80\x93' --include='*.sh' --include='*.md' scripts/ README.md docs/ .github/ 2>/dev/null | grep -q ."

# ---- Bash syntax ----
echo ""
echo "--- Shell scripts ---"
for f in scripts/*.sh; do
  name=$(basename "$f")
  if bash -n "$f" 2>/dev/null; then
    pass "bash -n $name"
  else
    fail "bash -n $name"
  fi
done

if command -v shellcheck >/dev/null 2>&1; then
  if shellcheck scripts/*.sh 2>/dev/null; then
    pass "shellcheck"
  else
    warn "shellcheck found issues (advisory)"
  fi
fi

# ---- Setup smoke ----
echo ""
echo "--- Setup smoke ---"
check "setup.sh --help" "bash scripts/setup.sh --help 2>&1 | grep -q Usage"
check "double-dash flags" "grep -q -- '--non-interactive' scripts/setup.sh"
check "no down -v in setup" "! grep -q 'docker compose down -v' scripts/setup.sh scripts/upgrade.sh"
check "no secrets exposed" "! grep -E 'echo.*SECRET=|echo.*PASSWORD=' scripts/setup.sh | grep -v '\*\*\*\*\*\*' | grep -v sed | grep -q ."

# ---- Docs checks ----
echo ""
echo "--- Documentation ---"
check "no IP 192.168.1.19" "! grep -rPn '192\.168\.1\.19' --include='*.md' --include='*.yml' README.md .env.example config/ docs/first-run.md docs/roles-and-permissions.md docs/deployment-modes.md docs/windows-wsl.md 2>/dev/null | grep -q ."
check "no 'assigned cases only'" "! grep -rPi 'assigned cases only|read.only role' README.md docs/ 2>/dev/null | grep -q ."
check "no 'default password'" "! grep -rPin 'default password' README.md docs/ 2>/dev/null | grep -q ."
check "no PowerShell as supported" "! grep -rPin 'Native PowerShell (deployment|is supported|CMD.*supported)' README.md docs/ 2>/dev/null | grep -v 'not supported' | grep -q ."
check "setup.sh in README" "grep -q './scripts/setup.sh' README.md"

# ---- Frontend (skip in --fast) ----
if [[ "$FAST" != true ]]; then
  echo ""
  echo "--- Frontend ---"
  if [[ -f frontend/package.json ]]; then
    (cd frontend && npm ci --silent 2>/dev/null) || warn "npm ci failed (deps may be stale)"
    check "TypeScript" "(cd frontend && npx tsc --noEmit) 2>/dev/null"
    if [[ "$FULL" == true ]]; then
      check "Frontend build" "(cd frontend && npm run build) >/dev/null 2>&1"
    fi
  else
    warn "frontend/package.json not found"
  fi
fi

# ---- Backend tests (skip in --fast) ----
if [[ "$FAST" != true ]] && [[ "$FULL" == true ]]; then
  echo ""
  echo "--- Backend tests ---"
  if [[ -f backend/pyproject.toml ]]; then
    check "Backend tests" "(cd backend && python -m pytest tests/test_correlation_metadata.py tests/test_host_assignment.py -x -q) 2>/dev/null"
  else
    warn "backend/pyproject.toml not found"
  fi
fi

# ---- Docker compose (skip in --no-docker or --fast) ----
if [[ "$NO_DOCKER" != true ]] && [[ "$FAST" != true ]]; then
  echo ""
  echo "--- Docker Compose ---"
  if command -v docker >/dev/null 2>&1; then
    check "docker compose config" "docker compose config -q 2>/dev/null"
  else
    warn "Docker not available, skipping compose checks"
  fi
fi

# ---- Security ----
echo ""
echo "--- Security ---"
check "no private keys" "! grep -rP 'BEGIN (RSA |EC |DSA |OPENSSH )PRIVATE KEY' --include='*.py' --include='*.sh' --include='*.yml' --include='*.json' --include='*.md' backend/ scripts/ config/ .github/ 2>/dev/null | grep -q ."
check "no .env tracked" "! git ls-files 2>/dev/null | grep -qx '^.env$'"
check "no CHANGE_ME in defaults" "! grep -q CHANGE_ME config/defaults.env 2>/dev/null"

# ---- Summary ----
echo ""
echo "============================================"
if [[ $FAILURES -eq 0 ]]; then
  echo "  Quality gate: PASSED"
else
  echo "  Quality gate: $FAILURES FAILURE(S)"
fi
echo "============================================"
exit $FAILURES
