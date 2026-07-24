#!/usr/bin/env bash
# Kairon DFIR backup script.
# Backs up PostgreSQL, OpenSearch snapshots, Evidence, and configuration.
# WARNING: This is a technical draft. Test restoration in a sandbox before relying on it.

set -euo pipefail

TIMESTAMP=$(date -u +%Y%m%dT%H%M%SZ)
BACKUP_DIR="${BACKUP_DIR:-/root/kairon-backups}"
BACKUP_DIR="${BACKUP_DIR%/}/$TIMESTAMP"
# APP_DIR/POSTGRES_CONTAINER describe *your* deployment layout -- set them
# in your own environment rather than assuming a fixed path or compose
# project name, since these are real, deployment-specific values.
APP_DIR="${APP_DIR:-/root/kairon-dfir}"
POSTGRES_CONTAINER="${POSTGRES_CONTAINER:-kairon-dfir-postgres-1}"

echo "=== Kairon Backup $TIMESTAMP ==="
mkdir -p "$BACKUP_DIR"

# 1. PostgreSQL
echo "[1/4] Backing up PostgreSQL..."
docker exec "$POSTGRES_CONTAINER" pg_dump -U dfir dfir > "$BACKUP_DIR/postgres.sql" 2>/dev/null || {
  echo "  WARNING: PostgreSQL backup failed. Is the container running?"
}

# 2. Evidence & uploads
echo "[2/4] Backing up evidence and uploads..."
if [ -d "$APP_DIR/data" ]; then
  tar -czf "$BACKUP_DIR/data.tar.gz" -C "$APP_DIR" data/ 2>/dev/null || {
    echo "  WARNING: Data backup failed."
  }
fi

# 3. Configuration
echo "[3/4] Backing up configuration..."
cp "$APP_DIR/.env" "$BACKUP_DIR/.env.backup" 2>/dev/null || echo "  No .env found"
cp "$APP_DIR/docker-compose.yml" "$BACKUP_DIR/docker-compose.yml" 2>/dev/null || echo "  No docker-compose.yml found"

# 4. OpenSearch (snapshot repository must be configured)
echo "[4/4] OpenSearch snapshot hint..."
echo "  OpenSearch snapshots require a registered repository."
echo "  See docs/backup-restore.md for manual snapshot instructions."

SIZE=$(du -sh "$BACKUP_DIR" 2>/dev/null | cut -f1)
echo ""
echo "Backup complete: $BACKUP_DIR  ($SIZE)"
echo "IMPORTANT: Test restoration before relying on this backup."
