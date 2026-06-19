#!/usr/bin/env bash
set -euo pipefail

REMOTE_HOST="${REMOTE_HOST:-dfir-server}"
REMOTE_DIR="${REMOTE_DIR:-/root/DFIR_APP}"
SERVICES="${SERVICES:-backend frontend}"
DRY_RUN=0
ALLOW_DIRTY=0
DEPLOY_FILES=()

usage() {
  cat <<'EOF'
Usage: scripts/deploy_remote.sh [--host HOST] [--dir REMOTE_DIR] [--services "backend frontend"] [--file PATH ...] [--dry-run] [--allow-dirty]

Deploys selected committed source files to the remote Kairon host with relative paths preserved.
When one or more --file options are supplied, only those tracked files are synchronized.
This helper never uses --delete, never copies secrets, and never touches Docker volumes.
EOF
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --host) REMOTE_HOST="$2"; shift 2 ;;
    --dir) REMOTE_DIR="$2"; shift 2 ;;
    --services) SERVICES="$2"; shift 2 ;;
    --file) DEPLOY_FILES+=("$2"); shift 2 ;;
    --dry-run) DRY_RUN=1; shift ;;
    --allow-dirty) ALLOW_DIRTY=1; shift ;;
    -h|--help) usage; exit 0 ;;
    *) echo "Unknown argument: $1" >&2; usage; exit 2 ;;
  esac
done

commit="$(git rev-parse HEAD)"
branch="$(git rev-parse --abbrev-ref HEAD)"
if [[ "$ALLOW_DIRTY" -ne 1 ]] && [[ -n "$(git status --porcelain)" ]]; then
  echo "Refusing deployment from a dirty working tree. Commit first or pass --allow-dirty." >&2
  exit 1
fi

echo "Deploying commit: $commit"
echo "Branch: $branch"
echo "Remote: $REMOTE_HOST:$REMOTE_DIR"
echo "Services: $SERVICES"

file_list="$(mktemp)"
trap 'rm -f "$file_list"' EXIT
if [[ "${#DEPLOY_FILES[@]}" -gt 0 ]]; then
  for path in "${DEPLOY_FILES[@]}"; do
    if ! git ls-files --error-unmatch -- "$path" >/dev/null 2>&1; then
      echo "Refusing untracked deployment path: $path" >&2
      exit 1
    fi
    printf '%s\0' "$path" >> "$file_list"
  done
  echo "Files: ${DEPLOY_FILES[*]}"
else
  git ls-files -z > "$file_list"
fi

rsync_args=(-avzcR --from0 --files-from="$file_list" --exclude='.env')
if [[ "$DRY_RUN" -eq 1 ]]; then
  rsync_args+=(--dry-run)
fi

rsync "${rsync_args[@]}" ./ "$REMOTE_HOST:$REMOTE_DIR/"

if [[ "$DRY_RUN" -eq 1 ]]; then
  echo "Dry run complete; no remote build performed."
  exit 0
fi

ssh "$REMOTE_HOST" "cd '$REMOTE_DIR' && git rev-parse HEAD && docker compose build $SERVICES && docker compose up -d $SERVICES && docker compose ps && curl -fsS http://127.0.0.1:8000/docs >/dev/null && curl -I -fsS http://127.0.0.1:5173/ | head -n 1"
