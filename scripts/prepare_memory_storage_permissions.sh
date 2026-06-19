#!/bin/sh
set -eu

shared_gid="${MEMORY_EVIDENCE_SHARED_GID:-10001}"
worker_uid="${MEMORY_WORKER_UID:-10001}"
evidence_root="${MEMORY_EVIDENCE_HOST_ROOT:-data/evidence}"
output_root="${MEMORY_OUTPUT_HOST_ROOT:-data/memory-output}"
relative_evidence="${1:-}"

mkdir -p "$evidence_root" "$output_root"
chown "$worker_uid:$shared_gid" "$output_root"
chmod 0750 "$output_root"
chgrp "$shared_gid" "$evidence_root"
chmod 2750 "$evidence_root"

if [ -z "$relative_evidence" ]; then
  exit 0
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
