#!/usr/bin/env bash
set -euo pipefail

REMOTE_HOST="root@192.168.1.19"
# /root/kairon-dfir is the real, currently-running production checkout
# (compose project "kairon-dfir"). /root/DFIR_APP (compose project
# "dfir_app") is an older location that still hosts the separate,
# unmigrated symbol-egress-gateway container as of 2026-07-22 -- it is not
# safe to assume dead. Override REMOTE_DIR if you specifically mean to
# deploy something that still lives there.
REMOTE_DIR="/root/kairon-dfir"
COMMIT_MESSAGE="${1:-Update Kairon}"

cd /root/kairon

git add -A

if ! git diff --cached --quiet; then
  git commit -m "$COMMIT_MESSAGE"
fi

git push origin main

ssh "$REMOTE_HOST" "cd '$REMOTE_DIR' && git pull --ff-only && docker compose build backend frontend memory-worker && docker compose up -d --no-deps backend frontend memory-worker && docker compose ps"
