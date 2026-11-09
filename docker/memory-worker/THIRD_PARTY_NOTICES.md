# Memory Worker Third-Party Notices

This optional image installs Volatility 3 from the official PyPI package during an operator-initiated Docker build.

- Package: `volatility3`
- Version: `2.28.0`
- Source: `https://pypi.org/project/volatility3/2.28.0/`
- Wheel SHA-256: `68ea2257d25d2ab6160bb29203ce9bf3e91a8a852a420cb819ebb4c4115eaa68`
- Author: Volatility Foundation
- License: Volatility Software License 1.0

Kairon does not vendor, mirror, modify, or redistribute Volatility source code or wheels in this repository. The locally built image contains the dependency installed from PyPI and preserves package metadata and license files under `/licenses/volatility3/`.

Public redistribution of a prebuilt image containing Volatility 3 is out of scope for this release and requires a separate license review. This notice is not legal advice.

## MemProcFS

The image also installs MemProcFS's Linux release binaries, used for the FindEvil memory analysis profile, during the same operator-initiated build.

- Project: MemProcFS by Ulf Frisk, `https://github.com/ufrisk/MemProcFS`
- Pinned release tag: `v5.19`. The exact build within that tag is resolved automatically at image build time from the GitHub Releases API (`docker/memory-worker/fetch_memprocfs.py`), verified against the SHA-256 GitHub itself reports for that asset, and recorded in `/licenses/memprocfs/KAIRON_RESOLVED_VERSION.txt` inside the built image. As of this writing that resolves to version `9.9.9`, build `99999999` (SHA-256 `aaaa` for `linux_x64`, `bbbb` for `linux_aarch64`), also kept as a fallback pin in `docker/memory-worker/Dockerfile` used only if the GitHub API is unreachable at build time.
- Why: upstream republishes binaries under the same release tag instead of cutting a new tag per build, and deletes the previous build's assets -- a hardcoded build date + SHA-256 repeatedly 404'd (including on brand-new installs) whenever upstream published a new build. Resolving the current build at image build time removes the need for a human to notice and repin.
- License: GNU Affero General Public License v3.0; bundled components keep their own licenses (listed in `license_info_all.txt`). All are copied to `/licenses/memprocfs/`.

The release's unmodified `vmm.so` is used as-is. Until v5.19.1, Kairon rebuilt `vmm.so` from source with a patch for a loop that never ended while locating the DNS cache on Windows 11+ (an inner loop reused the outer loop's index), which kept the forensic scan at 90 % and FindEvil from finishing; upstream fixed the same bug its own way in v5.19.1 (`search all heaps in VmmNetDns_LookupHashTable`), so the patch and the rebuild step were dropped -- building `vmm.so` from a different source checkout than the `leechcore.so` it links against risked an ABI mismatch between the two, which is suspected to have caused `memprocfs.findevil` to crash silently (no stderr, no recognized exit code) on a Windows 11 24H2 crash dump right after pinning v5.19.1.

Kairon does not vendor MemProcFS source in this repository; the library is loaded at run time in a separate process.
