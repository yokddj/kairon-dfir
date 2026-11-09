"""Resolve and fetch the current MemProcFS Linux release binaries at build time.

Why this exists: MemProcFS (github.com/ufrisk/MemProcFS) does not cut a new
release tag for every build. It re-publishes binaries under the *same* tag
(e.g. "v5.19") and deletes the previous build's assets. A Dockerfile that
hardcodes an exact build date + SHA-256 breaks (HTTP 404) every time upstream
publishes a new build under that tag -- this has happened three times to
Kairon (see PROJECT_CONTEXT.md), including on a brand new install.

Instead of hardcoding the build date, this script asks the GitHub Releases
API what the current asset for the pinned *tag* actually is, downloads it,
and verifies it against the SHA-256 that GitHub itself reports for that
asset (the "digest" field), so integrity is still checked -- it is just
checked against a value fetched at build time instead of one typed into the
Dockerfile by a human. We already fully trust this upstream project (it is
the tool being installed), so trusting GitHub's own metadata about its own
hosted asset is not a larger leap.

If the GitHub API is unreachable (offline build, rate limited, etc.), this
falls back to the last known-good version/build/SHA-256 baked into the
Dockerfile as ARGs, preserving the previous (fully offline-capable) behavior.

The release *tag* itself (e.g. "v5.19") is still a human-controlled pin: this
script never jumps to a newer MemProcFS release line on its own, only to a
newer build within the pinned line.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
import tarfile
import urllib.error
import urllib.request
from pathlib import Path

API_URL = "https://api.github.com/repos/ufrisk/MemProcFS/releases/tags/{tag}"
DOWNLOAD_URL = (
    "https://github.com/ufrisk/MemProcFS/releases/download/{tag}/"
    "MemProcFS_files_and_binaries_v{version}-{arch}-{build}.tar.gz"
)
ASSET_RE_TEMPLATE = (
    r"^MemProcFS_files_and_binaries_v(?P<version>[0-9.]+)-{arch}-(?P<build>[0-9]+)\.tar\.gz$"
)
ARCH_MAP = {"amd64": "linux_x64", "arm64": "linux_aarch64"}
REQUEST_TIMEOUT = 15
USER_AGENT = "kairon-dfir-memprocfs-fetch"


def log(msg: str) -> None:
    print(f"[fetch_memprocfs] {msg}", file=sys.stderr, flush=True)


def http_get_json(url: str) -> dict:
    req = urllib.request.Request(
        url,
        headers={
            "User-Agent": USER_AGENT,
            "Accept": "application/vnd.github+json",
        },
    )
    with urllib.request.urlopen(req, timeout=REQUEST_TIMEOUT) as resp:
        return json.load(resp)


def resolve_from_api(tag: str, arch: str) -> tuple[str, str, str, str] | None:
    """Return (version, build, url, sha256) for the current asset under `tag`, or None."""
    try:
        data = http_get_json(API_URL.format(tag=tag))
    except (urllib.error.URLError, urllib.error.HTTPError, TimeoutError, ValueError) as exc:
        log(f"GitHub API lookup failed ({exc}); will use fallback pin")
        return None

    pattern = re.compile(ASSET_RE_TEMPLATE.format(arch=re.escape(arch)))
    candidates = []
    for asset in data.get("assets", []):
        m = pattern.match(asset.get("name", ""))
        if not m:
            continue
        digest = asset.get("digest") or ""
        if not digest.startswith("sha256:"):
            log(f"asset {asset['name']} has no usable sha256 digest from the API; skipping")
            continue
        candidates.append(
            (
                m.group("version"),
                m.group("build"),
                asset.get("browser_download_url", ""),
                digest.split(":", 1)[1],
            )
        )

    if not candidates:
        log(f"no matching '{arch}' asset with a sha256 digest found under tag {tag}; will use fallback pin")
        return None

    # Pick the asset with the highest build number (most recent).
    candidates.sort(key=lambda c: int(c[1]))
    version, build, url, sha256 = candidates[-1]
    log(f"resolved via GitHub API: version={version} build={build}")
    return version, build, url, sha256


def download(url: str, dest: Path) -> str:
    log(f"downloading {url}")
    req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
    hasher = hashlib.sha256()
    with urllib.request.urlopen(req, timeout=60) as resp, open(dest, "wb") as fh:
        while True:
            chunk = resp.read(1024 * 1024)
            if not chunk:
                break
            fh.write(chunk)
            hasher.update(chunk)
    return hasher.hexdigest()


def resolve_both_archs(tag: str) -> dict:
    """Return {"amd64": {"version", "build", "sha256"}, "arm64": {...}} for `tag`.

    Used by --resolve-only (the dependency-watch workflow) to check/refresh
    the fallback pin, independently of the arch-specific download path used
    during an actual image build.
    """
    data = http_get_json(API_URL.format(tag=tag))
    result = {}
    for docker_arch, asset_arch in ARCH_MAP.items():
        pattern = re.compile(ASSET_RE_TEMPLATE.format(arch=re.escape(asset_arch)))
        candidates = []
        for asset in data.get("assets", []):
            m = pattern.match(asset.get("name", ""))
            if not m:
                continue
            digest = asset.get("digest") or ""
            if not digest.startswith("sha256:"):
                continue
            candidates.append((m.group("version"), m.group("build"), digest.split(":", 1)[1]))
        if not candidates:
            raise RuntimeError(f"no matching asset with a sha256 digest for {asset_arch} under tag {tag}")
        candidates.sort(key=lambda c: int(c[1]))
        version, build, sha256 = candidates[-1]
        result[docker_arch] = {"version": version, "build": build, "sha256": sha256}

    if result["amd64"]["version"] != result["arm64"]["version"] or result["amd64"]["build"] != result["arm64"]["build"]:
        raise RuntimeError(f"architectures disagree on version/build: {result}")

    return result


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--tag", required=True, help="Pinned MemProcFS release tag, e.g. v5.19")
    parser.add_argument("--target-arch", choices=sorted(ARCH_MAP), help="Docker TARGETARCH")
    parser.add_argument("--dest-dir", type=Path, help="Directory to extract into")
    parser.add_argument("--fallback-version")
    parser.add_argument("--fallback-build")
    parser.add_argument("--fallback-sha256")
    parser.add_argument(
        "--force-fallback",
        action="store_true",
        help=(
            "Skip the GitHub API lookup and use the fallback pin directly. "
            "For genuinely offline/air-gapped builds, or for CI to verify "
            "the fallback pin on its own without needing to simulate an "
            "API outage."
        ),
    )
    parser.add_argument(
        "--resolve-only",
        action="store_true",
        help=(
            "Print the current build for both architectures as JSON to "
            "stdout and exit, without downloading or extracting anything. "
            "Used by the dependency-watch workflow to check/refresh the "
            "fallback pin."
        ),
    )
    args = parser.parse_args()

    if args.resolve_only:
        print(json.dumps(resolve_both_archs(args.tag)))
        return 0

    missing = [
        name
        for name, val in (
            ("--target-arch", args.target_arch),
            ("--dest-dir", args.dest_dir),
            ("--fallback-version", args.fallback_version),
            ("--fallback-build", args.fallback_build),
            ("--fallback-sha256", args.fallback_sha256),
        )
        if val is None
    ]
    if missing:
        parser.error(f"the following arguments are required unless --resolve-only: {', '.join(missing)}")

    arch = ARCH_MAP[args.target_arch]

    resolved = None if args.force_fallback else resolve_from_api(args.tag, arch)
    if resolved is not None:
        version, build, url, expected_sha256 = resolved
        source = "github-api"
    else:
        version, build = args.fallback_version, args.fallback_build
        url = DOWNLOAD_URL.format(tag=args.tag, version=version, arch=arch, build=build)
        expected_sha256 = args.fallback_sha256
        source = "fallback-pin"
        log(f"using fallback pin: version={version} build={build}")

    tmp_path = Path("/tmp/memprocfs.tgz")
    try:
        actual_sha256 = download(url, tmp_path)
    except (urllib.error.URLError, urllib.error.HTTPError) as exc:
        if source == "github-api":
            log(f"download of API-resolved asset failed ({exc}); retrying with fallback pin")
            version, build = args.fallback_version, args.fallback_build
            url = DOWNLOAD_URL.format(tag=args.tag, version=version, arch=arch, build=build)
            expected_sha256 = args.fallback_sha256
            source = "fallback-pin-after-api-download-failure"
            actual_sha256 = download(url, tmp_path)
        else:
            log(f"download failed and there is no further fallback: {exc}")
            return 1

    if actual_sha256 != expected_sha256:
        log(
            "SHA-256 mismatch: "
            f"expected {expected_sha256} got {actual_sha256} (source={source}, url={url})"
        )
        return 1

    args.dest_dir.mkdir(parents=True, exist_ok=True)
    with tarfile.open(tmp_path, "r:gz") as tar:
        tar.extractall(args.dest_dir, filter="data")
    tmp_path.unlink()

    (args.dest_dir / "KAIRON_RESOLVED_VERSION.txt").write_text(
        f"version={version}\nbuild={build}\ntag={args.tag}\narch={arch}\nsource={source}\nsha256={actual_sha256}\n",
        encoding="utf-8",
    )
    log(f"OK: version={version} build={build} source={source} sha256={actual_sha256}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
