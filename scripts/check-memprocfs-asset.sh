#!/usr/bin/env bash
set -euo pipefail
# Check that the MemProcFS release asset pinned in docker/memory-worker/Dockerfile
# still exists upstream.
#
# Why this exists: MemProcFS (github.com/ufrisk/MemProcFS) does not cut a new
# tag for every build. It re-publishes binaries under the *same* release tag
# (e.g. "v5.19") and deletes the previous build's assets. Kairon pins an exact
# build date + SHA-256 for integrity, so when upstream replaces the assets,
# every new `docker compose build memory-worker` (first install or
# scripts/upgrade.sh) starts getting a 404 until someone repins. This has
# already happened twice (see PROJECT_CONTEXT.md, 2026-10-15 and 2026-11-03).
#
# This script lets CI catch that *before* a user hits it: run it on a weekly
# schedule and open an issue automatically if it fails (see
# .github/workflows/dependency-watch.yml). It can also be run locally.
#
# Run: bash scripts/check-memprocfs-asset.sh

DOCKERFILE="docker/memory-worker/Dockerfile"

if [ ! -f "$DOCKERFILE" ]; then
    echo "ERROR: $DOCKERFILE not found (run from repo root)"
    exit 2
fi

get_arg() {
    sed -n "s/^ARG ${1}=\(.*\)$/\1/p" "$DOCKERFILE" | head -1
}

VERSION=$(get_arg MEMPROCFS_VERSION)
TAG=$(get_arg MEMPROCFS_TAG)
BUILD=$(get_arg MEMPROCFS_BUILD)

if [ -z "$VERSION" ] || [ -z "$TAG" ] || [ -z "$BUILD" ]; then
    echo "ERROR: could not parse MEMPROCFS_VERSION/MEMPROCFS_TAG/MEMPROCFS_BUILD from $DOCKERFILE"
    exit 2
fi

echo "=== Checking pinned MemProcFS asset ==="
echo "  Version: $VERSION"
echo "  Tag:     $TAG"
echo "  Build:   $BUILD"
echo ""

FAIL=0
for asset in linux_x64 linux_aarch64; do
    url="https://github.com/ufrisk/MemProcFS/releases/download/${TAG}/MemProcFS_files_and_binaries_v${VERSION}-${asset}-${BUILD}.tar.gz"
    code=$(curl -s -o /dev/null -w "%{http_code}" -L "$url")
    if [ "$code" = "200" ]; then
        echo "  OK   ($code) $asset"
    else
        echo "  FAIL ($code) $asset"
        echo "       $url"
        FAIL=1
    fi
done

echo ""
if [ "$FAIL" -ne 0 ]; then
    cat <<'EOF'
FAIL: pinned MemProcFS asset is missing upstream.

Upstream likely replaced the build under the same release tag. To fix:
  1. curl -s https://api.github.com/repos/ufrisk/MemProcFS/releases/tags/v5.19
     (or check https://github.com/ufrisk/MemProcFS/releases/tag/v5.19 for the
     current asset names and build date)
  2. Download the linux_x64 and linux_aarch64 assets for that build and
     compute their SHA-256 (sha256sum).
  3. Update MEMPROCFS_VERSION / MEMPROCFS_BUILD / MEMPROCFS_SHA256_AMD64 /
     MEMPROCFS_SHA256_ARM64 in docker/memory-worker/Dockerfile.
  4. Update the version/hashes/date in
     docker/memory-worker/THIRD_PARTY_NOTICES.md.
  5. docker compose build memory-worker (verify it completes) before merging.
EOF
    exit 1
fi

echo "PASS: pinned MemProcFS asset is reachable for both architectures"
