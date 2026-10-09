"""Identify the operating system of a raw memory image from its kernel, with no symbols.

A raw physical-memory acquisition (DumpIt/WinPmem ``.raw``, ``dd`` of ``/dev/mem``, a VM's
``.vmem``) has no header, so nothing at offset 0 says what it is. Every running kernel, though,
leaves a string in physical memory that names it, and finding it needs no symbols:

* **Windows**: the kernel image's CodeView debug record, ``RSDS`` + PDB GUID + age +
  ``ntkrnlmp.pdb`` (or ``ntoskrnl``/``ntkrpamp``/``ntkpamp``). The GUID and age are exactly what
  Windows symbol lookup needs.
* **Linux**: the ``linux_banner`` string, ``Linux version <release> (...)``, what ``uname -a``
  prints.
* **macOS**: the kernel version string, ``Darwin Kernel Version <version>: ...``.

The scan reads the image in chunks under a wall-clock bound. A Windows file cached in a Linux
machine's memory (or the reverse) can carry the other system's string, so when both appear the
one seen clearly more often wins; a close call is left undecided.
"""

from __future__ import annotations

import re
import time
import uuid
from collections import Counter
from dataclasses import dataclass, field
from pathlib import Path

WINDOWS = "windows"
LINUX = "linux"
MACOS = "macos"

_WINDOWS_KERNEL_PDB = re.compile(rb"RSDS(.{16})(.{4})(nt(?:krnlmp|oskrnl|krpamp|kpamp)\.pdb)\x00", re.S)
_LINUX_BANNER = re.compile(rb"Linux version (\d[\w.+~-]*) \([^\x00-\x08\x0e-\x1f\x7f]{0,220}")
_DARWIN_BANNER = re.compile(rb"Darwin Kernel Version (\d[\w.]*)[^\x00-\x08\x0e-\x1f\x7f]{0,200}")
_CHUNK_BYTES = 64 * 1024 * 1024
_OVERLAP_BYTES = 512


@dataclass(frozen=True)
class KernelSignature:
    platform: str
    offset: int
    # Windows: the kernel PDB (``ntkrnlmp.pdb``) with its GUID and age; Linux/macOS: the release.
    name: str
    pdb_guid: str | None = None
    pdb_age: int | None = None
    release: str | None = None
    banner: str | None = None

    @property
    def description(self) -> str:
        if self.platform == WINDOWS:
            return f"Windows kernel {self.name} ({self.pdb_guid}/{self.pdb_age})"
        if self.platform == LINUX:
            return f"Linux kernel {self.release}"
        return f"macOS kernel (Darwin {self.release})"


@dataclass
class KernelScan:
    signatures: list[KernelSignature] = field(default_factory=list)
    bytes_scanned: int = 0
    complete: bool = False


def _matches(haystack: bytes, base: int) -> list[KernelSignature]:
    found: list[KernelSignature] = []
    for match in _WINDOWS_KERNEL_PDB.finditer(haystack):
        found.append(KernelSignature(
            platform=WINDOWS,
            offset=base + match.start(),
            name=match.group(3).decode("ascii"),
            pdb_guid=str(uuid.UUID(bytes_le=match.group(1))).upper(),
            pdb_age=int.from_bytes(match.group(2), "little"),
        ))
    for match in _LINUX_BANNER.finditer(haystack):
        found.append(KernelSignature(
            platform=LINUX,
            offset=base + match.start(),
            name="linux_banner",
            release=match.group(1).decode("ascii", "replace"),
            banner=match.group(0).decode("ascii", "replace").strip(),
        ))
    for match in _DARWIN_BANNER.finditer(haystack):
        found.append(KernelSignature(
            platform=MACOS,
            offset=base + match.start(),
            name="darwin_banner",
            release=match.group(1).decode("ascii", "replace"),
            banner=match.group(0).decode("ascii", "replace").strip(),
        ))
    return found


def scan_kernel_signatures(path: Path, *, max_seconds: float, stop_at_first: bool = False, max_signatures: int = 64) -> KernelScan:
    """Every kernel signature in the image, read in chunks for at most ``max_seconds``.

    Never raises: an unreadable file is an empty, incomplete scan.
    """
    result = KernelScan()
    started = time.monotonic()
    seen: set[int] = set()
    try:
        with Path(path).open("rb") as handle:
            tail = b""
            offset = 0
            while time.monotonic() - started <= max_seconds:
                chunk = handle.read(_CHUNK_BYTES)
                if not chunk:
                    result.complete = True
                    break
                base = offset - len(tail)
                for signature in _matches(tail + chunk, base):
                    if signature.offset in seen:
                        continue  # found again in the overlap
                    seen.add(signature.offset)
                    result.signatures.append(signature)
                    if stop_at_first or len(result.signatures) >= max_signatures:
                        result.bytes_scanned = offset + len(chunk)
                        return result
                offset += len(chunk)
                tail = chunk[-_OVERLAP_BYTES:]
            result.bytes_scanned = offset
    except OSError:
        return result
    return result


def identify_kernel(signatures: list[KernelSignature]) -> KernelSignature | None:
    """The kernel the image belongs to, or None when nothing (or nothing clear) was found.

    The most frequent signature of the winning platform is returned: a Windows image can hold
    other kernels' PDB records in cached files, but the running kernel is mapped more often.
    """
    if not signatures:
        return None
    by_platform = Counter(signature.platform for signature in signatures)
    ranked = by_platform.most_common()
    if len(ranked) > 1 and ranked[0][1] < 2 * ranked[1][1]:
        return None
    platform = ranked[0][0]
    own = [signature for signature in signatures if signature.platform == platform]
    key_counts = Counter((signature.name, signature.pdb_guid, signature.release) for signature in own)
    best_key = key_counts.most_common(1)[0][0]
    return next(signature for signature in own if (signature.name, signature.pdb_guid, signature.release) == best_key)
