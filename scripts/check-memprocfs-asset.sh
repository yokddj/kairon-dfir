#!/usr/bin/env bash
set -euo pipefail
# Check that the MemProcFS release asset pinned in docker/memory-worker/Dockerfile
# still exists upstream.
#
# Context: docker/memory-worker/Dockerfile no longer depends on this pin for a
# normal build -- fetch_memprocfs.py resolves the current build for the pinned
# release *tag* from the GitHub Releases API at build time (and verifies the
# SHA-256 GitHub itself reports for that asset), so a build keeps working even
# if the values below go stale, which they will: upstream republishes
# binaries under the same tag instead of cutting a new one per build, and
# deletes the previous build's assets (this has broken a hardcoded pin three
# times, see PROJECT_CONTEXT.md).
#
# This script instead guards the *fallback* path: the one case where these
# values still matter is a build where the GitHub API is unreachable (e.g. an
# offline/air-gapped build, or the API is rate-limited/down). If this check
# fails, the primary (online, API-resolved) build path still works fine --
# only that degraded fallback path is stale. Repin when convenient, no need to
# treat it as an emergency.
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
FAIL: the fallback-pinned MemProcFS asset is missing upstream.

This only affects builds where the GitHub API is unreachable (offline
builds, API rate-limited/down); a normal online build still resolves the
current asset automatically via fetch_memprocfs.py and is unaffected. To
refresh the fallback pin anyway:
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

echo "PASS: fallback-pinned MemProcFS asset is reachable for both architectures"
