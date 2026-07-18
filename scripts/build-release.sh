#!/usr/bin/env bash
set -euo pipefail
# Kairon Release Build Script
# Usage: bash scripts/build-release.sh [VERSION]

VERSION="${1:-0.9.0-beta}"
KAIRON_COMMIT="$(git rev-parse HEAD)"
KAIRON_VERSION="$VERSION"
SOURCE_DATE_EPOCH="$(git show -s --format=%ct HEAD)"
BUILD_DATE="$(date -u -d "@$SOURCE_DATE_EPOCH" +%Y-%m-%dT%H:%M:%SZ)"

echo "=== Kairon Release Build ==="
echo "  version:  $KAIRON_VERSION"
echo "  commit:   $KAIRON_COMMIT"
echo "  date:     $BUILD_DATE"
echo "  epoch:    $SOURCE_DATE_EPOCH"
echo ""

export KAIRON_COMMIT KAIRON_VERSION BUILD_DATE SOURCE_DATE_EPOCH
export APP_VERSION="$KAIRON_VERSION"

echo "--- Building images ---"
docker compose build \
    --build-arg KAIRON_COMMIT="$KAIRON_COMMIT" \
    --build-arg BUILD_DATE="$BUILD_DATE" \
    --build-arg KAIRON_VERSION="$KAIRON_VERSION" \
    backend frontend worker

echo ""
echo "--- Image metadata ---"
docker image inspect dfir_app-backend:latest --format '  version: {{index .Config.Labels "org.opencontainers.image.version"}}' 2>/dev/null || true
docker image inspect dfir_app-backend:latest --format '  revision: {{index .Config.Labels "org.opencontainers.image.revision"}}' 2>/dev/null || true

echo ""
echo "=== Release build complete ==="
echo "  Tag with: git tag -a v$KAIRON_VERSION -m 'Release $KAIRON_VERSION'"
echo "  Commit: $KAIRON_COMMIT"
