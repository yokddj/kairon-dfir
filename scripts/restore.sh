#!/usr/bin/env bash
# Kairon DFIR restore script.
# WARNING: This is a technical draft. Destructive operation.
# ALWAYS test restoration in a sandbox first.
# Do NOT run on production without a verified backup.

set -euo pipefail

if [ $# -lt 1 ]; then
  echo "Usage: $0 <backup-directory>"
  echo "  Restores PostgreSQL, evidence, and configuration from a backup directory."
  exit 1
fi

BACKUP_DIR="$1"

if [ ! -d "$BACKUP_DIR" ]; then
  echo "ERROR: Backup directory not found: $BACKUP_DIR"
  exit 1
fi

echo "=== Kairon Restore from $BACKUP_DIR ==="
echo "WARNING: This will overwrite existing data."
echo "Ensure all Kairon services are stopped before proceeding."
echo "Press Ctrl+C within 10 seconds to cancel..."
sleep 10

# 1. Stop services
echo "[1/4] Stopping services..."
cd /root/DFIR_APP
docker compose stop backend worker memory-worker 2>/dev/null || true

# 2. Restore PostgreSQL
if [ -f "$BACKUP_DIR/postgres.sql" ]; then
  echo "[2/4] Restoring PostgreSQL..."
  docker compose up -d postgres 2>/dev/null
  sleep 5
  docker exec -i dfir_app-postgres-1 psql -U dfir dfir < "$BACKUP_DIR/postgres.sql" 2>/dev/null || {
    echo "  WARNING: PostgreSQL restore failed."
  }
fi

# 3. Restore evidence
if [ -f "$BACKUP_DIR/data.tar.gz" ]; then
  echo "[3/4] Restoring evidence..."
  tar -xzf "$BACKUP_DIR/data.tar.gz" -C /root/DFIR_APP 2>/dev/null || {
    echo "  WARNING: Data restore failed."
  }
fi

# 4. Restore configuration
if [ -f "$BACKUP_DIR/.env.backup" ]; then
  echo "[4/4] Restoring configuration..."
  cp "$BACKUP_DIR/.env.backup" /root/DFIR_APP/.env 2>/dev/null || true
fi

echo ""
echo "Restore complete. Start services with: cd /root/DFIR_APP && docker compose up -d"
echo "IMPORTANT: Verify data integrity before using the system."
