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
- Version: `5.19.1` (release `v5.19`, build `20261102`)
- Archives: `MemProcFS_files_and_binaries_v5.19.1-linux_x64-20261102.tar.gz` (SHA-256 `087d787bb2830541bc42fa07185a0a3c34c81fdff7e26afe0764f902f3cd55e3`) and `…-linux_aarch64-20261102.tar.gz` (SHA-256 `ef168b014a8153de9519dc966820817f11e6dcdab8fac1f55494c16f294f0eca`), from the project's GitHub release; the build checks the hash before unpacking.
- License: GNU Affero General Public License v3.0; bundled components keep their own licenses (listed in `license_info_all.txt`). All are copied to `/licenses/memprocfs/`.

The release's unmodified `vmm.so` is used as-is. Until v5.19.1, Kairon rebuilt `vmm.so` from source with a patch for a loop that never ended while locating the DNS cache on Windows 11+ (an inner loop reused the outer loop's index), which kept the forensic scan at 90 % and FindEvil from finishing; upstream fixed the same bug its own way in v5.19.1 (`search all heaps in VmmNetDns_LookupHashTable`), so the patch and the rebuild step were dropped -- building `vmm.so` from a different source checkout than the `leechcore.so` it links against risked an ABI mismatch between the two, which is suspected to have caused `memprocfs.findevil` to crash silently (no stderr, no recognized exit code) on a Windows 11 24H2 crash dump right after pinning v5.19.1.

Kairon does not vendor MemProcFS source in this repository; the library is loaded at run time in a separate process.
