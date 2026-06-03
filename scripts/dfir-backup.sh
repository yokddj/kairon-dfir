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

if [ "$MODE" != "--run" ]; then
  echo "Usage: $0 [--dry-run|--run]" >&2
  exit 2
fi

mkdir -p "$OUT_DIR"

POSTGRES_USER="${POSTGRES_USER:-dfir}"
POSTGRES_DB="${POSTGRES_DB:-dfir}"

${COMPOSE} exec -T postgres pg_dump -U "$POSTGRES_USER" -d "$POSTGRES_DB" > "${OUT_DIR}/postgres.sql"

tar \
  --exclude="./data/tmp" \
  --exclude="./data/local-mounts" \
  -czf "${OUT_DIR}/app-data.tgz" \
  ./data

curl -fsS "http://127.0.0.1:9200/_cat/indices?format=json" > "${OUT_DIR}/opensearch-indices.json" 2>/dev/null || printf '[]\n' > "${OUT_DIR}/opensearch-indices.json"

cat > "${OUT_DIR}/manifest.json" <<EOF
{
  "created_at": "${STAMP}",
  "includes": [
    "postgres logical dump",
    "application data directory excluding tmp/local mounts",
    "opensearch index inventory"
  ],
  "does_not_include": [
    "docker images",
    "external read-only evidence mounts",
    "OpenSearch physical shard snapshot"
  ]
}
EOF

echo "Backup completed at ${OUT_DIR}"
