#!/bin/sh
set -eu

# Prepares the host directories that Memory-capability containers
# (memory-worker, experimental-worker) bind-mount and must be able to
# write into as UID 10001 (see docker-compose.yml's `user: "10001:10001"`
# and `group_add:`).
#
# The container's primary UID/GID stay fixed at 10001:10001 (baked into
# docker/memory-worker/Dockerfile); write access to the host-owned bind
# mount is granted through a *supplementary group* on the host directory
# instead of changing its owner. This script never chowns a host
# directory's owner away from the calling user:
#   - a host-side chown to UID 10001 breaks Docker Desktop's own
#     bind-mount management on macOS (the reported bug this script
#     exists to fix) because ownership no longer matches any real host
#     account;
#   - it would also require this script (and therefore all of
#     scripts/setup.sh) to run as root, which is not required for a
#     normal setup.
#
# Ownership/group checks below are always evaluated against the
# *expected operator identity* -- the sudo-invoking user (SUDO_UID/
# SUDO_GID) if running under sudo, otherwise the process's own real
# UID/GID -- never the raw, possibly-elevated process identity.
# Comparing against the raw process identity is the exact bug this file
# previously had: under sudo, the process's own UID is 0 (root), so a
# directory correctly owned by the real operator was reported as owned
# by the "wrong" user, with a confusing "expected owner: root" message.
#
# MEMORY_EVIDENCE_SHARED_GID should be set by the caller (scripts/setup.sh
# resolves it once -- an existing value from a prior run, or the expected
# operator's own primary GID -- and writes it into .env so
# docker-compose's `group_add:` uses the exact same GID).
evidence_root="${MEMORY_EVIDENCE_HOST_ROOT:-data/evidence}"
output_root="${MEMORY_OUTPUT_HOST_ROOT:-data/memory-output}"
relative_evidence="${1:-}"

# --- identity helpers ---------------------------------------------------

_running_as_root() {
  [ "$(id -u)" = "0" ]
}

# The operator this script should treat as "the owner": the sudo-invoking
# user when running under sudo (sudo always sets SUDO_UID/SUDO_GID for
# the command it runs), otherwise whoever is actually running the
# script. This is deliberately NOT just `id -u`/`id -g`, which under
# sudo reflect root -- an artifact of the elevation mechanism, not the
# operator's real identity.
_expected_uid() {
  echo "${SUDO_UID:-$(id -u)}"
}

_expected_gid() {
  echo "${SUDO_GID:-$(id -g)}"
}

_expected_user_label() {
  uid="$(_expected_uid)"
  id -un "$uid" 2>/dev/null || echo "uid $uid"
}

shared_gid="${MEMORY_EVIDENCE_SHARED_GID:-$(_expected_gid)}"

# Portable numeric owner/group lookup (avoids GNU-only `stat -c` and
# BSD-only `stat -f`, which differ between Linux and macOS): `ls -n`
# prints numeric uid/gid and is specified by POSIX on both.
_dir_owner_uid() {
  ls -ldn "$1" | awk '{print $3}'
}

_dir_owner_name() {
  ls -ld "$1" | awk '{print $3}'
}

# Isolated so tests can override it without needing a second real UID.
_is_owned_by_expected_user() {
  [ "$(_dir_owner_uid "$1")" = "$(_expected_uid)" ]
}

# Ensures $1 exists and is group-owned by $shared_gid with the requested
# mode, without ever changing its owner away from the expected operator
# identity -- unless running as root via sudo, in which case a directory
# left with the wrong owner (e.g. a leftover container UID from a
# previous broken run) is restored to that same expected identity rather
# than staying broken or ending up owned by root itself. Exits 3 with a
# concise, actionable message (naming the directory, its current owner,
# and the exact recovery command) only when the mismatch cannot be fixed
# safely -- it never silently falls through to a Docker Compose failure.
prepare_shared_dir() {
  dir="$1"
  mode="$2"

  mkdir -p "$dir"

  if ! _is_owned_by_expected_user "$dir"; then
    if _running_as_root && [ -n "${SUDO_UID:-}" ] && [ -n "${SUDO_GID:-}" ]; then
      # Root has unconditional privilege to fix this; repair ownership
      # to the expected (real, sudo-invoking) operator instead of
      # leaving it broken or making it root-owned.
      echo "NOTE: '$dir' was owned by $(_dir_owner_name "$dir"); restoring ownership to $(_expected_user_label) (uid=$(_expected_uid) gid=$(_expected_gid))." >&2
      chown "$(_expected_uid):$(_expected_gid)" "$dir"
    elif _running_as_root; then
      # Real root login, no sudo context: there is no known "correct"
      # human owner to restore to, but root's chgrp below works
      # regardless of current ownership, so there is nothing unsafe
      # left to gate here.
      :
    else
      echo "ERROR: Kairon Memory setup cannot use '$dir'." >&2
      echo "  Current owner: $(_dir_owner_name "$dir")" >&2
      echo "  Expected owner: $(_expected_user_label)" >&2
      echo "  This usually happens after a previous setup run left it owned by the container UID (10001)." >&2
      echo "  Recovery command: sudo chown -R \"$(_expected_uid):$(_expected_gid)\" \"$dir\"" >&2
      echo "  Re-run setup after that command completes." >&2
      exit 3
    fi
  fi

  # An unprivileged owner may always chgrp their own file to a group they
  # belong to (POSIX), and root may chgrp to any group regardless of
  # membership -- this is never a chown of the owner and never requires
  # sudo for the default (the expected operator's own primary GID).
  if ! chgrp "$shared_gid" "$dir" 2>/dev/null; then
    echo "ERROR: Kairon Memory setup could not set group $shared_gid on '$dir'." >&2
    echo "  Current owner: $(_dir_owner_name "$dir")" >&2
    echo "  Expected: $(_expected_user_label) must belong to group $shared_gid." >&2
    echo "  Recovery command: sudo chgrp -R \"$shared_gid\" \"$dir\"" >&2
    echo "  Or re-run setup without overriding MEMORY_EVIDENCE_SHARED_GID so it defaults to your own group." >&2
    exit 3
  fi
  chmod "$mode" "$dir"
}

main() {
  prepare_shared_dir "$evidence_root" 2750
  prepare_shared_dir "$output_root" 2770

  if [ ! -w "$output_root" ]; then
    echo "ERROR: '$output_root' is still not writable after setup." >&2
    echo "  Current owner: $(_dir_owner_name "$output_root")" >&2
    echo "  Recovery command: sudo chown -R \"$(_expected_uid):$(_expected_gid)\" \"$output_root\"" >&2
    exit 3
  fi

  if [ -z "$relative_evidence" ]; then
    return 0
  fi

  case "$relative_evidence" in
    /*|*..*)
      echo "Refusing unsafe evidence-relative path" >&2
      exit 2
      ;;
  esac

  candidate="$evidence_root/$relative_evidence"
  canonical_root="$(realpath "$evidence_root")"
  canonical_file="$(realpath "$candidate")"
  case "$canonical_file" in
    "$canonical_root"/*) ;;
    *)
      echo "Refusing evidence path outside managed root" >&2
      exit 2
      ;;
  esac

  if [ -L "$candidate" ] || [ ! -f "$candidate" ]; then
    echo "Refusing non-regular or symlink evidence" >&2
    exit 2
  fi

  current="$(dirname "$candidate")"
  while [ "$current" != "$evidence_root" ]; do
    chgrp "$shared_gid" "$current"
    chmod 2750 "$current"
    current="$(dirname "$current")"
  done
  chgrp "$shared_gid" "$candidate"
  chmod 0640 "$candidate"
}

# Allow tests to `. prepare_memory_storage_permissions.sh` for just the
# function definitions (e.g. to exercise prepare_shared_dir directly
# against a temp directory, or to override _is_owned_by_expected_user to
# simulate an ownership conflict without a second real UID) without
# running main's side effects.
if [ "${PREPARE_MEMORY_STORAGE_PERMISSIONS_TEST:-0}" != "1" ]; then
  main
fi
