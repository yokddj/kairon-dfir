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
- Version: `5.19.0` (release `v5.19`, build `20261005`)
- Archives: `MemProcFS_files_and_binaries_v5.19.0-linux_x64-20261005.tar.gz` (SHA-256 `2ec75bba2a243525a16be22d1ea6863c9fcd4de694c07e4896d4029017c43ea5`) and `…-linux_aarch64-20261005.tar.gz` (SHA-256 `03554471c1702d73f2b83c22e2483b0e110b04399fc399c07fc4f7a47827c3a5`), from the project's GitHub release; the build checks the hash before unpacking.
- License: GNU Affero General Public License v3.0; bundled components keep their own licenses (listed in `license_info_all.txt`). All are copied to `/licenses/memprocfs/`.

- Modified file: `vmm.so` is rebuilt from the source of that release (commit `2e85ff7edc3772e24bce28bdc4cccb744a8b2456`, archive SHA-256 `8916c442d1a7de667aebaa6c34e69a43325e474e003da89a6881f3961a4b2048`) with the patches in `docker/memory-worker/patches/` applied: `memprocfs-netdns-lookup-loop.patch` fixes a loop that never ends while locating the DNS cache on Windows 11+ (an inner loop reused the outer loop's index), which kept the forensic scan at 90 % and FindEvil from finishing. The patches are the complete source of the changes, under the same AGPL-3.0 license. Every other file is the unmodified release.

Kairon does not vendor MemProcFS source in this repository; the library is loaded at run time in a separate process.
