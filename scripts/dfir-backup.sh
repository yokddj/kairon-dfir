#!/usr/bin/env sh
set -eu

MODE="${1:---dry-run}"
COMPOSE="${DFIR_COMPOSE:-docker compose}"
BACKUP_ROOT="${DFIR_BACKUP_ROOT:-./backups}"
STAMP="$(date -u +%Y%m%dT%H%M%SZ)"
OUT_DIR="${BACKUP_ROOT}/${STAMP}"

echo "DFIR backup"
echo "mode=${MODE}"
echo "output=${OUT_DIR}"

if [ "$MODE" = "--dry-run" ]; then
  echo "Would create:"
  echo "- ${OUT_DIR}/postgres.sql"
  echo "- ${OUT_DIR}/app-data.tgz"
  echo "- ${OUT_DIR}/opensearch-indices.json"
  echo "- ${OUT_DIR}/manifest.json"
  echo
  echo "Would run:"
  echo "- docker compose exec -T postgres pg_dump -U <redacted> -d <redacted>"
  echo "- tar selected app data directories"
  echo "- curl OpenSearch _cat/indices metadata"
  exit 0
fi

if [ "$MODE" != "--run" ] && [ "$MODE" != "--db-only" ]; then
  echo "Usage: $0 [--dry-run|--run|--db-only]" >&2
  echo "  --run      database, application data (evidence included) and index inventory" >&2
  echo "  --db-only  database, configuration and index inventory only: seconds and megabytes," >&2
  echo "             enough before an upgrade, which changes the database but not the evidence" >&2
  exit 2
fi

mkdir -p "$OUT_DIR"

# A backup that stops halfway (Docker not running, disk full) would leave a folder that looks
# like a backup but holds an empty or truncated dump. Remove it unless the backup finished.
COMPLETED=0
cleanup_incomplete() {
  if [ "$COMPLETED" -ne 1 ]; then
    rm -rf "$OUT_DIR"
    echo "ERROR: backup did not complete; removed ${OUT_DIR}" >&2
  fi
}
trap cleanup_incomplete EXIT

POSTGRES_USER="${POSTGRES_USER:-dfir}"
POSTGRES_DB="${POSTGRES_DB:-dfir}"

${COMPOSE} exec -T postgres pg_dump -U "$POSTGRES_USER" -d "$POSTGRES_DB" > "${OUT_DIR}/postgres.sql"

DATA_NOTE="application data directory excluding tmp/local mounts"
if [ "$MODE" = "--run" ]; then
  # tar exits 1 when a file changed while it was read (a log being written, a worker's scratch
  # file): the archive is still usable, so that is a warning; anything above 1 is a real failure.
  set +e
  tar \
    --exclude="./data/tmp" \
    --exclude="./data/local-mounts" \
    -czf "${OUT_DIR}/app-data.tgz" \
    ./data
  TAR_STATUS=$?
  set -e
  if [ "$TAR_STATUS" -gt 1 ]; then
    echo "ERROR: archiving ./data failed (tar exit ${TAR_STATUS})" >&2
    exit "$TAR_STATUS"
  fi
  if [ "$TAR_STATUS" -eq 1 ]; then
    echo "WARNING: some files changed while ./data was archived; the archive is usable" >&2
    DATA_NOTE="application data directory excluding tmp/local mounts (some files changed during the copy)"
  fi
else
  DATA_NOTE=""
fi

DB_ONLY_EXCLUDES=""
if [ "$MODE" = "--db-only" ]; then
  DB_ONLY_EXCLUDES="
    \"application data and uploaded evidence (use --run)\","
fi
DATA_LINE=""
if [ -n "$DATA_NOTE" ]; then
  DATA_LINE="
    \"${DATA_NOTE}\","
fi

# The configuration holds the secrets that encrypt stored provider keys and sign sessions; a
# restored database is of little use without them. Kept in the local backup folder only.
if [ -f ./.env ]; then
  cp ./.env "${OUT_DIR}/env.backup"
  chmod 600 "${OUT_DIR}/env.backup"
fi

# OpenSearch's port is intentionally not published to the host in the
# default deployment (see docs/deployment/deployment.md) -- curl it through
# the container network instead of 127.0.0.1, and let a real failure abort
# the backup (set -e) rather than silently writing an empty inventory that
# manifest.json would otherwise claim as complete.
${COMPOSE} exec -T opensearch curl -fsS "http://localhost:9200/_cat/indices?format=json" > "${OUT_DIR}/opensearch-indices.json"

cat > "${OUT_DIR}/manifest.json" <<EOF
{
  "created_at": "${STAMP}",
  "mode": "${MODE#--}",
  "includes": [
    "postgres logical dump",
    "configuration (.env)",${DATA_LINE}
    "opensearch index inventory"
  ],
  "does_not_include": [
    "docker images",${DB_ONLY_EXCLUDES}
    "external read-only evidence mounts",
    "OpenSearch physical shard snapshot"
  ]
}
EOF

COMPLETED=1
echo "Backup completed at ${OUT_DIR}"
