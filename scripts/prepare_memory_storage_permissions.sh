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
# MEMORY_EVIDENCE_SHARED_GID should be set by the caller (scripts/setup.sh
# resolves it once -- an existing value from a prior run, or the calling
# user's own primary GID via `id -g` -- and writes it into .env so
# docker-compose's `group_add:` uses the exact same GID). If invoked
# directly without that, it defaults to the caller's own primary group,
# which is always safe to `chgrp` to without any elevated privilege.
shared_gid="${MEMORY_EVIDENCE_SHARED_GID:-$(id -g)}"
evidence_root="${MEMORY_EVIDENCE_HOST_ROOT:-data/evidence}"
output_root="${MEMORY_OUTPUT_HOST_ROOT:-data/memory-output}"
relative_evidence="${1:-}"

_owner_name() {
  ls -ld "$1" | awk '{print $3}'
}

# Isolated so tests can override it without needing a second real UID.
_is_owned_by_current_user() {
  [ -O "$1" ]
}

# Ensures $1 exists and is group-owned by $shared_gid with the requested
# mode, without ever changing its owner. Exits 3 with a concise,
# actionable message (naming the directory, its current owner, and the
# exact recovery command) if that cannot be done safely -- it never
# silently falls through to a Docker Compose failure.
prepare_shared_dir() {
  dir="$1"
  mode="$2"

  mkdir -p "$dir"

  if ! _is_owned_by_current_user "$dir"; then
    owner="$(_owner_name "$dir")"
    echo "ERROR: Kairon Memory setup cannot use '$dir'." >&2
    echo "  Current owner: $owner" >&2
    echo "  Expected: it must be owned by the current user ($(id -un)) so setup can prepare it without root." >&2
    echo "  This usually happens after a previous setup run left it owned by the container UID (10001)." >&2
    echo "  Recovery command: sudo chown -R \"\$(id -u):\$(id -g)\" \"$dir\"" >&2
    echo "  Re-run setup after that command completes." >&2
    exit 3
  fi

  # An unprivileged owner may always chgrp their own file to a group they
  # belong to (POSIX) -- this is never a chown and never requires sudo
  # when $shared_gid is the caller's own primary group, which is the
  # default.
  if ! chgrp "$shared_gid" "$dir" 2>/dev/null; then
    echo "ERROR: Kairon Memory setup could not set group $shared_gid on '$dir'." >&2
    echo "  Current owner: $(_owner_name "$dir")" >&2
    echo "  Expected: the current user must belong to group $shared_gid." >&2
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
    echo "  Current owner: $(_owner_name "$output_root")" >&2
    echo "  Recovery command: sudo chown -R \"\$(id -u):\$(id -g)\" \"$output_root\"" >&2
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
# against a temp directory, or to override _is_owned_by_current_user to
# simulate an ownership conflict without a second real UID) without
# running main's side effects.
if [ "${PREPARE_MEMORY_STORAGE_PERMISSIONS_TEST:-0}" != "1" ]; then
  main
fi
