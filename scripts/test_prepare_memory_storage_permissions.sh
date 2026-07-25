#!/usr/bin/env bash
# Tests for scripts/prepare_memory_storage_permissions.sh -- the host-side
# preparation of Memory's bind-mounted directories (data/evidence,
# data/memory-output). Covers the macOS bind-mount ownership bug: a
# host-side chown of the mount source to the container's UID (10001)
# breaks Docker Desktop's own bind-mount management and requires root,
# so this script must only ever chgrp/chmod, never chown a directory's
# owner away from the calling user.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
TARGET="$SCRIPT_DIR/prepare_memory_storage_permissions.sh"
TMPDIR=$(mktemp -d)
trap 'rm -rf "$TMPDIR"' EXIT

pass=0
fail=0

ok() { ((pass++)); echo "PASS: $1"; }
bad() { ((fail++)); echo "FAIL: $1"; }

echo "=== prepare_memory_storage_permissions.sh tests ==="
echo ""

# --- 1. Directory does not exist: created, group-owned by caller's GID,
#        setgid + group-writable, owner unchanged. ---------------------
case_dir="$TMPDIR/case1"
mkdir -p "$case_dir"
MEMORY_EVIDENCE_HOST_ROOT="$case_dir/evidence" MEMORY_OUTPUT_HOST_ROOT="$case_dir/memory-output" \
  sh "$TARGET" >/dev/null 2>&1
if [[ -d "$case_dir/memory-output" ]] && [[ -O "$case_dir/memory-output" ]]; then
  ok "missing directory is created and owned by the current user"
else
  bad "missing directory is created and owned by the current user"
fi
mode="$(ls -ld "$case_dir/memory-output" | cut -c1-10)"
if [[ "$mode" == "drwxrws---" ]]; then
  ok "memory-output ends up setgid + group-writable (2770), no other access"
else
  bad "memory-output ends up setgid + group-writable (2770), no other access ($mode)"
fi

# --- 2. Idempotent repeated run. ---------------------------------------
if MEMORY_EVIDENCE_HOST_ROOT="$case_dir/evidence" MEMORY_OUTPUT_HOST_ROOT="$case_dir/memory-output" \
  sh "$TARGET" >/dev/null 2>&1; then
  ok "repeated run on an already-prepared directory succeeds (idempotent)"
else
  bad "repeated run on an already-prepared directory succeeds (idempotent)"
fi

# --- 3. Existing directory already owned by the host user: succeeds. --
case_dir2="$TMPDIR/case2"
mkdir -p "$case_dir2/memory-output" "$case_dir2/evidence"
if MEMORY_EVIDENCE_HOST_ROOT="$case_dir2/evidence" MEMORY_OUTPUT_HOST_ROOT="$case_dir2/memory-output" \
  sh "$TARGET" >/dev/null 2>&1; then
  ok "pre-existing, host-user-owned directory is accepted"
else
  bad "pre-existing, host-user-owned directory is accepted"
fi

# --- 4. Memory disabled: this script is simply never invoked by
#        setup.sh's build_and_start() -- verified statically here since
#        that's the actual guard (no separate runtime mode in this
#        script itself). -------------------------------------------------
if grep -q 'if \[\[ "\$ENABLE_MEMORY" == true \]\]; then' "$SCRIPT_DIR/setup.sh" \
  && grep -A10 'Preparing memory storage permissions' "$SCRIPT_DIR/setup.sh" | grep -q 'prepare_memory_storage_permissions.sh'; then
  ok "setup.sh only calls prepare_memory_storage_permissions.sh when Memory is enabled"
else
  bad "setup.sh only calls prepare_memory_storage_permissions.sh when Memory is enabled"
fi

# --- 5. Known UID 10001 ownership conflict: detected, clear error, no
#        silent continuation. Simulated via function override (sourcing
#        in test mode) since reproducing a second real UID would need
#        root. --------------------------------------------------------
case_dir3="$TMPDIR/case3"
mkdir -p "$case_dir3/memory-output"
conflict_output="$TMPDIR/conflict.out"
set +e
PREPARE_MEMORY_STORAGE_PERMISSIONS_TEST=1 bash -c '
  . "'"$TARGET"'"
  _is_owned_by_current_user() { return 1; }
  _owner_name() { echo "10001"; }
  prepare_shared_dir "'"$case_dir3"'/memory-output" 2770
' >"$conflict_output" 2>&1
conflict_exit=$?
set -e
if [[ "$conflict_exit" -eq 3 ]]; then
  ok "UID 10001 ownership conflict is detected and exits non-zero (3)"
else
  bad "UID 10001 ownership conflict is detected and exits non-zero (3) (got $conflict_exit)"
fi
if grep -q "Current owner: 10001" "$conflict_output" \
  && grep -q "sudo chown -R" "$conflict_output" \
  && grep -q "memory-output" "$conflict_output"; then
  ok "conflict error names the directory, current owner, and an exact recovery command"
else
  bad "conflict error names the directory, current owner, and an exact recovery command"
fi
if grep -qi "permission denied" "$conflict_output"; then
  bad "conflict error is a concise diagnosis, not a generic permission-denied passthrough"
else
  ok "conflict error is a concise diagnosis, not a generic permission-denied passthrough"
fi

# --- 6. Clear failure when repair is not permitted (chgrp target the
#        caller does not belong to). ------------------------------------
case_dir4="$TMPDIR/case4"
mkdir -p "$case_dir4"
gid_output="$TMPDIR/gid.out"
set +e
MEMORY_EVIDENCE_SHARED_GID=65534 \
  MEMORY_EVIDENCE_HOST_ROOT="$case_dir4/evidence" MEMORY_OUTPUT_HOST_ROOT="$case_dir4/memory-output" \
  sh "$TARGET" >"$gid_output" 2>&1
gid_exit=$?
set -e
if [[ "$gid_exit" -eq 3 ]] && grep -q "Recovery command" "$gid_output"; then
  ok "unrepairable group-permission failure stops with a clear, actionable error (no silent continue)"
else
  bad "unrepairable group-permission failure stops with a clear, actionable error (no silent continue)"
fi

# --- 7. Regression: no startup script performs an unrestricted
#        recursive chown against the memory-output mount. ---------------
if grep -rEn 'chown[[:space:]]+-[a-zA-Z]*R[a-zA-Z]*[[:space:]].*memory-output' \
  "$SCRIPT_DIR"/*.sh "$SCRIPT_DIR/../docker" "$SCRIPT_DIR/../docker-compose.yml" 2>/dev/null | grep -q .; then
  bad "no script/Dockerfile performs an unrestricted recursive chown on memory-output"
else
  ok "no script/Dockerfile performs an unrestricted recursive chown on memory-output"
fi
if grep -n 'chown' "$TARGET" | grep -v 'echo' | grep -vE ':[[:space:]]*#' | grep -q .; then
  bad "prepare_memory_storage_permissions.sh never invokes chown (chgrp-only by design; mentions of it are comments/recovery-command text)"
else
  ok "prepare_memory_storage_permissions.sh never invokes chown (chgrp-only by design; mentions of it are comments/recovery-command text)"
fi

echo ""
echo "=== Results: $pass passed, $fail failed ==="
[[ $fail -eq 0 ]] || exit 1
