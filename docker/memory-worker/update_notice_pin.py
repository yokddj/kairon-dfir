"""Update the fallback-pin version/build/SHA-256 line in THIRD_PARTY_NOTICES.md.

Used by .github/workflows/dependency-watch.yml after refreshing the
MEMPROCFS_* fallback ARGs in the Dockerfile, to keep the notice in sync.

Usage: update_notice_pin.py <notice_path> <version> <build> <sha256_amd64> <sha256_arm64>
"""

from __future__ import annotations

import re
import sys

PATTERN = re.compile(
    r"As of this writing that resolves to version `[0-9.]+`, build `[0-9]+` "
    r"\(SHA-256 `[0-9a-f]+` for `linux_x64`, `[0-9a-f]+` for `linux_aarch64`\)"
)


def main() -> int:
    if len(sys.argv) != 6:
        print(__doc__, file=sys.stderr)
        return 2

    path, version, build, sha_amd64, sha_arm64 = sys.argv[1:6]
    text = open(path, encoding="utf-8").read()
    replacement = (
        f"As of this writing that resolves to version `{version}`, build `{build}` "
        f"(SHA-256 `{sha_amd64}` for `linux_x64`, `{sha_arm64}` for `linux_aarch64`)"
    )
    new_text, count = PATTERN.subn(replacement, text)
    if count == 0:
        print(f"WARNING: pattern not found in {path}, notice left unchanged", file=sys.stderr)
        return 1

    open(path, "w", encoding="utf-8").write(new_text)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
