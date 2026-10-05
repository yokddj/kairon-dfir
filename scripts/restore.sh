#!/usr/bin/env bash
# Kairon DFIR restore. Destructive: replaces the database (and ./data and .env when the
# backup has them) with the contents of a backup made by scripts/dfir-backup.sh.
# Try it on a test machine before you need it.

set -euo pipefail

if [ $# -lt 1 ]; then
  echo "Usage: $0 <backup-directory>"
  echo "  Restores the database, and the application data and configuration when present,"
  echo "  from a directory written by scripts/dfir-backup.sh (--run or --db-only)."
  exit 1
fi

BACKUP_DIR="$(cd "$1" && pwd)"
APP_DIR="${APP_DIR:-$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)}"
POSTGRES_USER="${POSTGRES_USER:-dfir}"
POSTGRES_DB="${POSTGRES_DB:-dfir}"

first_existing() {
  for name in "$@"; do
    if [ -f "$BACKUP_DIR/$name" ]; then
      echo "$BACKUP_DIR/$name"
      return 0
    fi
  done
  return 1
}

DUMP="$BACKUP_DIR/postgres.sql"
DATA_ARCHIVE="$(first_existing app-data.tgz data.tar.gz || true)"
ENV_BACKUP="$(first_existing env.backup .env.backup || true)"

if [ ! -s "$DUMP" ]; then
  echo "ERROR: $DUMP not found or empty" >&2
  exit 1
fi

echo "=== Kairon restore from $BACKUP_DIR into $APP_DIR ==="
echo "Database:      replaced"
echo "Data (./data): ${DATA_ARCHIVE:+replaced from $(basename "$DATA_ARCHIVE")}${DATA_ARCHIVE:-kept (not in this backup)}"
echo "Configuration: ${ENV_BACKUP:+replaced from $(basename "$ENV_BACKUP")}${ENV_BACKUP:-kept (not in this backup)}"
echo "Press Ctrl+C within 10 seconds to cancel..."
sleep 10

cd "$APP_DIR"

echo "[1/5] Stopping the application services..."
docker compose stop frontend backend worker memory-worker 2>/dev/null || true

if [ -n "$ENV_BACKUP" ]; then
  echo "[2/5] Restoring configuration..."
  if [ -f .env ]; then
    cp .env ".env.before-restore-$(date -u +%Y%m%dT%H%M%SZ)"
  fi
  cp "$ENV_BACKUP" .env
  chmod 600 .env
else
  echo "[2/5] No configuration in this backup, keeping .env"
fi

if [ -n "$DATA_ARCHIVE" ]; then
  echo "[3/5] Restoring application data..."
  tar -xzf "$DATA_ARCHIVE" -C "$APP_DIR"
else
  echo "[3/5] No application data in this backup, keeping ./data"
fi

echo "[4/5] Restoring the database..."
docker compose up -d postgres
for _ in $(seq 1 30); do
  if docker compose exec -T postgres pg_isready -U "$POSTGRES_USER" -d "$POSTGRES_DB" >/dev/null 2>&1; then
    break
  fi
  sleep 2
done
# A plain pg_dump only loads into an empty schema; over existing tables it fails part-way.
docker compose exec -T postgres psql -q -v ON_ERROR_STOP=1 -U "$POSTGRES_USER" -d "$POSTGRES_DB" \
  -c "DROP SCHEMA public CASCADE; CREATE SCHEMA public;"
docker compose exec -T postgres psql -q -v ON_ERROR_STOP=1 -U "$POSTGRES_USER" -d "$POSTGRES_DB" < "$DUMP" >/dev/null

echo "[5/5] Done."
echo ""
echo "Start the stack:  docker compose up -d"
echo "Then check:       ./scripts/dfir-healthcheck.sh"
echo "Search data lives in OpenSearch and is not in this backup; if it was lost, reprocess the evidence."
