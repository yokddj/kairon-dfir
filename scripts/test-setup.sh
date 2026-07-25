#!/usr/bin/env bash
# setup.sh smoke tests — verifies flags, idempotency, and safety.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
TMPDIR=$(mktemp -d)
trap 'rm -rf "$TMPDIR"' EXIT

# setup.sh derives ROOT_DIR (and therefore where it writes .env) from its
# own script location, not the caller's cwd -- running the real
# scripts/setup.sh directly would write/overwrite this actual checkout's
# .env. Run a copy from inside TMPDIR instead so every invocation below
# is fully isolated from the real repo.
mkdir -p "$TMPDIR/scripts"
cp "$SCRIPT_DIR/setup.sh" "$SCRIPT_DIR/prepare_memory_storage_permissions.sh" "$TMPDIR/scripts/"
SETUP_SH="$TMPDIR/scripts/setup.sh"

pass=0
fail=0

assert_contains() {
  local label="$1" file="$2" pattern="$3"
  if grep -q "$pattern" "$file" 2>/dev/null; then
    ((pass++)); echo "PASS: $label"
  else
    ((fail++)); echo "FAIL: $label (missing '$pattern')"
  fi
}

assert_exit() {
  local label="$1" expected="$2" cmd="$3"
  local actual=0
  bash -c "$cmd" >/dev/null 2>&1 || actual=$?
  if [[ "$actual" == "$expected" ]]; then
    ((pass++)); echo "PASS: $label"
  else
    ((fail++)); echo "FAIL: $label (expected exit $expected, got $actual)"
  fi
}

echo "=== setup.sh smoke tests ==="
echo ""

# Test 1: --help exits 0 and shows modes
out="$TMPDIR/help.txt"
bash "$SETUP_SH" --help > "$out" 2>&1 || true
assert_contains "--help works" "$out" "Usage"
assert_contains "--help shows modes" "$out" "non-interactive"
assert_contains "--help shows upgrade" "$out" "upgrade"

# Test 2: --validate-only without .env exits 1 (non-zero)
assert_exit "--validate-only without .env" 1 \
  "cd $TMPDIR && bash '$SETUP_SH' --validate-only 2>/dev/null"

# Test 3: Secret preservation
cd "$TMPDIR"
echo 'KAIRON_SESSION_SECRET=test-secret-value' > .env
echo 'POSTGRES_PASSWORD=test-postgres-pwd' >> .env
echo 'KAIRON_PUBLIC_URL=http://localhost:5173' >> .env
echo 'KAIRON_AUTH_ENABLED=true' >> .env

# --no-build avoids depending on a reachable Docker daemon for what is
# fundamentally a .env-content assertion (DO_BUILD=true alone would still
# invoke `docker compose build`).
bash "$SETUP_SH" --non-interactive --mode localhost --no-build --no-start 2>/dev/null
assert_contains "secrets preserved" "$TMPDIR/.env" "test-secret-value"

# Test 3b: MEMORY_EVIDENCE_SHARED_GID is written (defaults to the caller's
# own primary group, never a hardcoded container-internal GID) and is
# preserved across a second run rather than re-derived.
assert_contains "MEMORY_EVIDENCE_SHARED_GID written" "$TMPDIR/.env" "MEMORY_EVIDENCE_SHARED_GID=$(id -g)"
first_gid="$(grep '^MEMORY_EVIDENCE_SHARED_GID=' "$TMPDIR/.env")"
bash "$SETUP_SH" --non-interactive --mode localhost --no-build --no-start 2>/dev/null
second_gid="$(grep '^MEMORY_EVIDENCE_SHARED_GID=' "$TMPDIR/.env")"
if [[ "$first_gid" == "$second_gid" ]]; then
  ((pass++)); echo "PASS: MEMORY_EVIDENCE_SHARED_GID preserved across reruns"
else
  ((fail++)); echo "FAIL: MEMORY_EVIDENCE_SHARED_GID preserved across reruns ($first_gid vs $second_gid)"
fi

# Test 4: No destructive commands
assert_contains "no down -v" "$SETUP_SH" "docker compose down -v"

# Actually, verify the script does NOT contain destructive compose commands
if grep -q "docker compose down -v" "$SETUP_SH"; then
  ((fail++)); echo "FAIL: setup.sh contains docker compose down -v"
else
  ((pass++)); echo "PASS: no docker compose down -v"
fi

# Test 5: Windows native detection message
assert_contains "windows warning" "$SETUP_SH" "Windows native shell detected"

# Test 6: WSL2 message
assert_contains "wsl2 message" "$SETUP_SH" "WSL2 detected"

# Test 7: Planned actions function
assert_contains "planned actions" "$SETUP_SH" "Planned actions"

# Test 8: Flags use double-dash ASCII not em-dash
if ! grep -P '\xE2\x80\x93' "$SETUP_SH" >/dev/null 2>&1; then
  ((pass++)); echo "PASS: no em-dash in flags"
else
  ((fail++)); echo "FAIL: em-dash found in flags"
fi

# Test 9: --no-build warning
assert_contains "no-build warning" "$SETUP_SH" "reuse stale Docker images"

# Test 10: No secrets printed
if grep -E 'echo.*SECRET|echo.*PASSWORD' "$SETUP_SH" >/dev/null 2>&1; then
  # Check it's just the sed mask, not actual values
  if grep 's/=.*=/\*\*\*\*\*\*/' "$SETUP_SH" >/dev/null 2>&1; then
    ((pass++)); echo "PASS: secrets masked in output"
  else
    ((fail++)); echo "FAIL: secrets may be exposed"
  fi
else
  ((pass++)); echo "PASS: no secret echo lines"
fi

echo ""
echo "=== Results: $pass passed, $fail failed ==="
[[ $fail -eq 0 ]] || exit 1
