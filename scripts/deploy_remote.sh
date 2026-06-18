#!/usr/bin/env bash
set -euo pipefail

REMOTE_HOST="${REMOTE_HOST:-dfir-server}"
REMOTE_DIR="${REMOTE_DIR:-/root/DFIR_APP}"
SERVICES="${SERVICES:-backend frontend}"
DRY_RUN=0
ALLOW_DIRTY=0

usage() {
  cat <<'EOF'
Usage: scripts/deploy_remote.sh [--host HOST] [--dir REMOTE_DIR] [--services "backend frontend"] [--dry-run] [--allow-dirty]

Deploys selected committed source files to the remote Kairon host with relative paths preserved.
This helper never uses --delete, never copies secrets, and never touches Docker volumes.
EOF
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --host) REMOTE_HOST="$2"; shift 2 ;;
    --dir) REMOTE_DIR="$2"; shift 2 ;;
    --services) SERVICES="$2"; shift 2 ;;
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

rsync_args=(-avzcR --exclude='.git/' --exclude='.env' --exclude='data/' --exclude='node_modules/' --exclude='dist/' --exclude='*.tsbuildinfo')
if [[ "$DRY_RUN" -eq 1 ]]; then
  rsync_args+=(--dry-run)
fi

rsync "${rsync_args[@]}" ./ "$REMOTE_HOST:$REMOTE_DIR/"

if [[ "$DRY_RUN" -eq 1 ]]; then
  echo "Dry run complete; no remote build performed."
  exit 0
fi

ssh "$REMOTE_HOST" "cd '$REMOTE_DIR' && git rev-parse HEAD && docker compose build $SERVICES && docker compose up -d $SERVICES && docker compose ps && curl -fsS http://127.0.0.1:8000/docs >/dev/null && curl -I -fsS http://127.0.0.1:5173/ | head -n 1"
