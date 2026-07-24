#!/usr/bin/env bash
set -euo pipefail

# REMOTE_HOST must include whatever SSH user is appropriate for your
# deployment target, e.g. "deploy-user@your-server" or an ~/.ssh/config
# alias -- there is intentionally no default here, real deployment hosts
# must never be hardcoded in a tracked file.
: "${REMOTE_HOST:?REMOTE_HOST must be set, e.g. REMOTE_HOST=user@host ./deploy.sh}"
REMOTE_DIR="${REMOTE_DIR:-/root/kairon-dfir}"
COMMIT_MESSAGE="${1:-Update Kairon}"

cd "$(dirname "$0")"

git add -A

if ! git diff --cached --quiet; then
  git commit -m "$COMMIT_MESSAGE"
fi

git push origin main

ssh "$REMOTE_HOST" "cd '$REMOTE_DIR' && git pull --ff-only && docker compose build backend frontend memory-worker && docker compose up -d --no-deps backend frontend memory-worker && docker compose ps"
