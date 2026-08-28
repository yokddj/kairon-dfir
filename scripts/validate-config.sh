#!/usr/bin/env bash
set -euo pipefail

# Kairon DFIR configuration validator.
# Usage: bash scripts/validate-config.sh [.env path]

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
DOTENV="${1:-$ROOT_DIR/.env}"

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
NC='\033[0m'

errors=0
warnings=0

pass() {
  echo -e "  ${GREEN}PASS${NC} $1"
}

warn() {
  echo -e "  ${YELLOW}WARN${NC} $1"
  warnings=$((warnings + 1))
}

fail() {
  echo -e "  ${RED}FAIL${NC} $1"
  errors=$((errors + 1))
}

get() {
  local key="$1"
  grep -E "^${key}=" "$DOTENV" 2>/dev/null | head -1 | sed "s/^${key}=//"
}

has() {
  local key="$1"
  grep -qE "^${key}=" "$DOTENV" 2>/dev/null
}

nonempty() {
  local key="$1"
  local val
  val="$(get "$key")"
  if [[ -z "$val" ]]; then
    fail "$key is empty or unset"
  else
    pass "$key is set"
  fi
}

no_change_me() {
  local key="$1"
  local val
  val="$(get "$key")"
  if [[ "$val" == *"CHANGE_ME"* ]]; then
    fail "$key contains CHANGE_ME placeholder"
  else
    pass "$key has no CHANGE_ME placeholder"
  fi
}

echo "=== Kairon DFIR Config Validation ==="
echo "  Target: $DOTENV"
echo ""

# 1. .env exists
if [[ ! -f "$DOTENV" ]]; then
  echo -e "${RED}FAIL: $DOTENV does not exist.${NC}"
  echo "  Run: bash scripts/setup.sh"
  exit 1
fi
pass "$DOTENV exists"

echo ""
echo "--- Required variables ---"
for var in KAIRON_DEPLOYMENT_MODE KAIRON_PUBLIC_URL KAIRON_AUTH_ENABLED; do
  if has "$var"; then
    pass "$var is declared"
  else
    fail "$var is missing"
  fi
done

echo ""
echo "--- Critical secrets ---"
auth_enabled="$(get "KAIRON_AUTH_ENABLED")"
if [[ "$auth_enabled" != "false" ]]; then
  for var in KAIRON_SESSION_SECRET KAIRON_CSRF_SECRET POSTGRES_PASSWORD OPENSEARCH_INITIAL_ADMIN_PASSWORD; do
    no_change_me "$var"
  done
  for var in KAIRON_SESSION_SECRET KAIRON_CSRF_SECRET POSTGRES_PASSWORD OPENSEARCH_INITIAL_ADMIN_PASSWORD; do
    nonempty "$var"
  done
else
  warn "Authentication is disabled; skipping secret validation"
fi

echo ""
echo "--- CORS validation ---"
cors_val="$(get "KAIRON_ALLOWED_ORIGINS" 2>/dev/null || echo "")"
if [[ -z "$cors_val" ]]; then
  # Check backend default
  if has "BACKEND_CORS_ORIGINS"; then
    cors_val="$(get "BACKEND_CORS_ORIGINS")"
  fi
fi
if [[ "$cors_val" == "*" ]]; then
  if [[ "$auth_enabled" == "true" ]]; then
    fail "CORS origins is '*' but credentials are enabled (auth is on). Use specific origins."
  else
    warn "CORS origins is '*'. This is acceptable only with auth disabled."
  fi
elif [[ -n "$cors_val" ]]; then
  pass "CORS origins are explicitly set"
fi

echo ""
echo "--- Deployment mode checks ---"
dep_mode="$(get "KAIRON_DEPLOYMENT_MODE")"
public_url="$(get "KAIRON_PUBLIC_URL")"

case "$dep_mode" in
  https)
    if [[ "$public_url" != https://* ]]; then
      fail "KAIRON_DEPLOYMENT_MODE=https but KAIRON_PUBLIC_URL does not start with https://"
    else
      pass "HTTPS mode: public URL uses https://"
    fi
    ;;
  localhost|lan)
    pass "Deployment mode is $dep_mode"
    ;;
  *)
    warn "Unknown deployment mode: $dep_mode"
    ;;
esac

echo ""
echo "--- Bootstrap admin consistency ---"
if has "KAIRON_BOOTSTRAP_ADMIN_USERNAME"; then
  admin_user="$(get "KAIRON_BOOTSTRAP_ADMIN_USERNAME")"
  admin_pass="$(get "KAIRON_BOOTSTRAP_ADMIN_PASSWORD")"

  if [[ -n "$admin_user" ]]; then
    if [[ -z "$admin_pass" ]]; then
      warn "KAIRON_BOOTSTRAP_ADMIN_USERNAME is set but KAIRON_BOOTSTRAP_ADMIN_PASSWORD is empty. Admin will not be created on startup."
      warn "  Create admin manually: docker compose run --rm backend python -m app.cli create-admin"
    else
      pass "Bootstrap admin username and password are both set"
    fi
    if [[ -n "$admin_pass" ]] && [[ "$admin_pass" == *"CHANGE_ME"* ]]; then
      fail "KAIRON_BOOTSTRAP_ADMIN_PASSWORD contains CHANGE_ME"
    fi
  else
    pass "No bootstrap admin configured (use CLI instead)"
  fi
fi

echo ""
echo "--- Memory feature consistency ---"
if has "KAIRON_ENABLE_MEMORY"; then
  mem_enabled="$(get "KAIRON_ENABLE_MEMORY")"
  if [[ "$mem_enabled" == "true" ]]; then
    if has "MEMORY_ANALYSIS_ENABLED" && [[ "$(get "MEMORY_ANALYSIS_ENABLED")" != "true" ]]; then
      warn "KAIRON_ENABLE_MEMORY=true but MEMORY_ANALYSIS_ENABLED is not true"
    fi
  fi
  pass "Memory feature config is present"
fi

echo ""
echo "--- File permissions ---"
perms="$(stat -c '%a' "$DOTENV" 2>/dev/null || echo "")"
if [[ "$perms" == "600" ]]; then
  pass ".env has secure permissions (600)"
elif [[ "$perms" == "640" ]]; then
  warn ".env permissions are 640 (consider chmod 600)"
else
  warn ".env permissions are $perms (recommend chmod 600)"
fi

echo ""
echo "=== Validation complete ==="
echo "  Errors:   $errors"
echo "  Warnings: $warnings"

if [[ "$errors" -gt 0 ]]; then
  echo ""
  echo "Fix the errors above before starting Kairon."
  exit 1
fi

if [[ "$warnings" -gt 0 ]]; then
  echo ""
  echo "Review the warnings above. Kairon may still start correctly."
  exit 0
fi

echo ""
echo "Configuration looks good. You should be ready to start Kairon."
echo "  docker compose up -d"
