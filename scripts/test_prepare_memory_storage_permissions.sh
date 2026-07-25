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
  _is_owned_by_expected_user() { return 1; }
  _dir_owner_name() { echo "10001"; }
  _dir_owner_uid() { echo "10001"; }
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
# The only legitimate chown left is the root-plus-sudo repair path,
# which always targets the dynamically-resolved expected identity
# ($(_expected_uid):$(_expected_gid)) -- never a hardcoded UID like the
# container's 10001, which was the actual bug.
if grep -n 'chown' "$TARGET" | grep -v 'echo' | grep -vE ':[[:space:]]*#' | grep -v '_expected_uid' | grep -q .; then
  bad "any chown in prepare_memory_storage_permissions.sh targets only the dynamic expected identity, never a hardcoded UID"
else
  ok "any chown in prepare_memory_storage_permissions.sh targets only the dynamic expected identity, never a hardcoded UID"
fi
if grep -v '^[[:space:]]*#' "$TARGET" | grep -E 'chown.*10001' | grep -q .; then
  bad "no chown call hardcodes the container UID (10001)"
else
  ok "no chown call hardcodes the container UID (10001)"
fi

# --- 8. Regression (the exact bug just reported): running under sudo
#        (root process, but a directory ALREADY correctly owned by the
#        real invoking user) must be accepted silently -- no error, no
#        "repair" noise, nothing chowned. ------------------------------
case_dir5="$TMPDIR/case5"
mkdir -p "$case_dir5/memory-output"
real_uid="$(id -u)"
real_gid="$(id -g)"
sudo_output="$TMPDIR/sudo_ok.out"
set +e
PREPARE_MEMORY_STORAGE_PERMISSIONS_TEST=1 SUDO_UID="$real_uid" SUDO_GID="$real_gid" bash -c '
  . "'"$TARGET"'"
  _running_as_root() { return 0; }
  prepare_shared_dir "'"$case_dir5"'/memory-output" 2770
' >"$sudo_output" 2>&1
sudo_exit=$?
set -e
if [[ "$sudo_exit" -eq 0 ]]; then
  ok "sudo + directory already owned by the real invoking user succeeds"
else
  bad "sudo + directory already owned by the real invoking user succeeds (exit $sudo_exit): $(cat "$sudo_output")"
fi
if grep -q "NOTE:" "$sudo_output"; then
  bad "no spurious 'restoring ownership' NOTE when nothing was actually broken"
else
  ok "no spurious 'restoring ownership' NOTE when nothing was actually broken"
fi
if grep -qi "ERROR" "$sudo_output"; then
  bad "no error printed when the directory is already correctly owned under sudo"
else
  ok "no error printed when the directory is already correctly owned under sudo"
fi

# --- 9. sudo + directory left owned by a stale UID (e.g. a previous
#        broken run's 10001): auto-repaired to the real invoking user,
#        then succeeds. --------------------------------------------------
case_dir6="$TMPDIR/case6"
mkdir -p "$case_dir6/memory-output"
repair_output="$TMPDIR/sudo_repair.out"
set +e
PREPARE_MEMORY_STORAGE_PERMISSIONS_TEST=1 SUDO_UID="$real_uid" SUDO_GID="$real_gid" bash -c '
  . "'"$TARGET"'"
  _running_as_root() { return 0; }
  _is_owned_by_expected_user() { return 1; }
  _dir_owner_uid() { echo "10001"; }
  _dir_owner_name() { echo "10001"; }
  prepare_shared_dir "'"$case_dir6"'/memory-output" 2770
' >"$repair_output" 2>&1
repair_exit=$?
set -e
if [[ "$repair_exit" -eq 0 ]] && grep -q "NOTE:.*restoring ownership" "$repair_output"; then
  ok "sudo + stale-UID directory is auto-repaired to the real invoking user and succeeds"
else
  bad "sudo + stale-UID directory is auto-repaired to the real invoking user and succeeds (exit $repair_exit): $(cat "$repair_output")"
fi

# --- 10. Error message reports the real expected owner, never a raw
#         "root" label caused by comparing against the elevated
#         process identity instead of the expected operator. -----------
normal_user_output="$TMPDIR/normal_conflict.out"
case_dir7="$TMPDIR/case7"
mkdir -p "$case_dir7/memory-output"
set +e
PREPARE_MEMORY_STORAGE_PERMISSIONS_TEST=1 bash -c '
  . "'"$TARGET"'"
  _running_as_root() { return 1; }
  _is_owned_by_expected_user() { return 1; }
  _dir_owner_uid() { echo "10001"; }
  _dir_owner_name() { echo "10001"; }
  prepare_shared_dir "'"$case_dir7"'/memory-output" 2770
' >"$normal_user_output" 2>&1
normal_user_exit=$?
set -e
if [[ "$normal_user_exit" -eq 3 ]] && grep -q "Expected owner: $(id -un)" "$normal_user_output"; then
  ok "non-root conflict reports the real expected owner (not root, not a raw \$(id -un) of an elevated process)"
else
  bad "non-root conflict reports the real expected owner (got): $(cat "$normal_user_output")"
fi

echo ""
echo "=== Results: $pass passed, $fail failed ==="
[[ $fail -eq 0 ]] || exit 1
