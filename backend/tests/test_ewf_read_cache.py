"""Tests for EwfImgInfo's bounded read cache (disk-image materialization
performance sprint).

Profiling a real ~63GiB Linux E01's filesystem walk found 97.7% of
pytsk3's read(offset, size) calls were exact repeats of an (offset, size)
pair already read moments earlier -- pytsk3's own ext4 driver re-fetches
the same inode-table/directory blocks many times per walk. EwfImgInfo now
caches those results, since the underlying EWF is opened read-only and
never mutated for the lifetime of one EwfImgInfo instance, so an exact
(offset, size) match can never go stale.
"""
from __future__ import annotations

import hashlib
import subprocess
from pathlib import Path

import pytest

from app.disk_images.ewf_img_info import EwfImgInfo, _READ_CACHE_MAX_ENTRIES


def _require_tools(*names: str) -> None:
    missing = [name for name in names if subprocess.run(["bash", "-lc", f"command -v {name} >/dev/null 2>&1"], check=False).returncode != 0]
    if missing:
        pytest.skip(f"Missing required tool(s): {', '.join(missing)}")


def _create_segmented_ewf(raw_image: Path, target_prefix: Path) -> list[Path]:
    _require_tools("ewfacquire")
    subprocess.run(["ewfacquire", "-u", "-q", "-S", str(1024 * 1024), "-t", str(target_prefix), str(raw_image)], check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    return sorted(target_prefix.parent.glob(f"{target_prefix.name}.E*"))


@pytest.fixture
def ewf_fixture(tmp_path: Path) -> tuple[list[Path], bytes]:
    raw_image = tmp_path / "source.raw"
    rng_bytes = bytes((i * 2654435761 + 17) % 256 for i in range(2 * 1024 * 1024))
    raw_image.write_bytes(rng_bytes)
    segments = _create_segmented_ewf(raw_image, tmp_path / "case-ewf")
    return segments, rng_bytes


def test_cached_read_is_byte_identical_to_uncached_read(ewf_fixture) -> None:
    segments, source_bytes = ewf_fixture
    img = EwfImgInfo(segments)
    try:
        first = img.read(4096, 8192)
        second = img.read(4096, 8192)  # cache hit
        assert first == second == source_bytes[4096:4096 + 8192]
    finally:
        img.close()


def test_repeated_read_does_not_reinvoke_underlying_handle(ewf_fixture) -> None:
    segments, _ = ewf_fixture
    img = EwfImgInfo(segments)
    try:
        call_count = {"n": 0}
        real_handle = img._handle

        class _CountingHandleProxy:
            def seek(self, offset):
                return real_handle.seek(offset)

            def read(self, size):
                call_count["n"] += 1
                return real_handle.read(size)

        img._handle = _CountingHandleProxy()

        img.read(0, 1024)
        assert call_count["n"] == 1
        img.read(0, 1024)  # exact repeat -- must be served from cache
        assert call_count["n"] == 1
        img.read(0, 2048)  # different size at same offset -- distinct key, real miss
        assert call_count["n"] == 2
    finally:
        img._handle = real_handle
        img.close()


def test_whole_file_hash_matches_source_with_repeated_overlapping_reads(ewf_fixture) -> None:
    """Reproduces the real walk's pattern (many overlapping/repeated
    reads over the same region) and confirms the final assembled bytes
    are still an exact match -- the cache must never corrupt or return
    stale data across a busy access pattern."""
    segments, source_bytes = ewf_fixture
    img = EwfImgInfo(segments)
    try:
        assembled = bytearray(len(source_bytes))
        block = 4096
        for _ in range(3):  # walk the whole image 3 times, like repeated directory visits
            for offset in range(0, len(source_bytes), block):
                data = img.read(offset, block)
                assembled[offset:offset + block] = data
        assert bytes(assembled) == source_bytes
        assert hashlib.sha256(bytes(assembled)).hexdigest() == hashlib.sha256(source_bytes).hexdigest()
    finally:
        img.close()


def test_cache_is_bounded_and_evicts_oldest_entries(ewf_fixture) -> None:
    segments, source_bytes = ewf_fixture
    img = EwfImgInfo(segments)
    try:
        block = 512
        total_distinct_reads = _READ_CACHE_MAX_ENTRIES + 500
        for i in range(total_distinct_reads):
            offset = (i * block) % (len(source_bytes) - block)
            img.read(offset, block)
        assert len(img._read_cache) <= _READ_CACHE_MAX_ENTRIES
    finally:
        img.close()


def test_cache_scoped_per_instance_not_shared_globally(ewf_fixture) -> None:
    segments, _ = ewf_fixture
    img1 = EwfImgInfo(segments)
    img2 = EwfImgInfo(segments)
    try:
        img1.read(0, 1024)
        assert len(img1._read_cache) == 1
        assert len(img2._read_cache) == 0
    finally:
        img1.close()
        img2.close()
