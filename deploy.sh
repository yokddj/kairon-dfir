#!/usr/bin/env bash
set -euo pipefail

REMOTE_HOST="root@192.168.1.19"
REMOTE_DIR="/root/DFIR_APP"
COMMIT_MESSAGE="${1:-Update Kairon}"

cd /root/kairon

git add -A

if ! git diff --cached --quiet; then
  git commit -m "$COMMIT_MESSAGE"
fi

git push origin main

ssh "$REMOTE_HOST" <<'EOF'
set -euo pipefail

cd /root/DFIR_APP
git pull --ff-only

docker compose build backend frontend memory-worker
docker compose up -d --no-deps backend frontend memory-worker

docker compose ps
EOF
