"""Binary systemd journal reader.

The fixtures are REAL journal files written by ``systemd-journal-remote`` from three systemd
generations (Ubuntu 22.04: regular layout; Debian 12 and Ubuntu 24.04: compact layout), all
ZSTD-compressed. Their content is synthetic: invented host, users and documentation IPs.
"""
from __future__ import annotations

import bz2  # noqa: F401  (kept out of the way of the compression tests below)
import gzip
import lzma
import random
import struct
import time
from datetime import datetime, timezone
from pathlib import Path

import pytest
import yaml

from app.ingest.linux import journal_binary
from app.ingest.linux.discovery import build_linux_inventory
from app.ingest.linux.dispatch import parse_linux_artifact_file
from app.ingest.linux.helpers import looks_like_linux_artifact
from app.ingest.linux.journal import parse_journal_binary_file
from app.ingest.linux.journal_binary import _decompress, is_journal_file, read_journal_entries

FIXTURES = Path(__file__).parent / "fixtures" / "journal"
FIXTURE_NAMES = ["ubuntu_22_04", "debian_12", "ubuntu_24_04"]
BASE = datetime(2024, 3, 1, 10, 20, 30, 123456, tzinfo=timezone.utc)


def _unpack(tmp_path: Path, name: str, filename: str | None = None) -> Path:
    target = tmp_path / (filename or f"{name}.journal")
    target.write_bytes(gzip.decompress((FIXTURES / f"{name}.journal.gz").read_bytes()))
    return target


@pytest.fixture(params=FIXTURE_NAMES)
def journal(request, tmp_path) -> Path:
    return _unpack(tmp_path, request.param)


# ------------------------------------------------------------------- real files

def test_fixture_is_recognised_by_magic_bytes(journal):
    assert is_journal_file(journal)


def test_reads_every_entry_in_order(journal):
    entries, info = read_journal_entries(journal)
    assert [e[0] for e in entries] == [1, 2, 3, 4, 5, 6]
    assert info == {"truncated": False, "undecodable_fields": 0}


def test_timestamps_keep_microseconds(journal):
    rows = parse_journal_binary_file(journal, source_path="var/log/journal/abc/system.journal")
    assert rows[0]["timestamp"] == BASE.isoformat()
    assert rows[1]["timestamp"] == (BASE.replace(second=35)).isoformat()


def test_row_fields_from_a_real_entry(journal):
    row = parse_journal_binary_file(journal, source_path="var/log/journal/abc/system.journal")[0]
    assert row["message"] == "Failed password for invalid user mallory from 203.0.113.9 port 51234 ssh2"
    assert row["hostname"] == "web01"
    assert row["process"] == "sshd" and row["pid"] == "411"
    assert row["exe"] == "/usr/sbin/sshd"
    assert row["unit"] == "ssh.service" and row["event_action"] == "ssh.service"
    assert row["transport"] == "syslog"
    assert row["severity"] == "6"
    assert row["uid"] == "0" and row["seqnum"] == 1
    assert row["boot_id"] == "0123456789abcdef0123456789abcdef"
    assert row["artifact_family"] == "linux_journal"
    assert row["source_path"] == "var/log/journal/abc/system.journal"


def test_entry_without_a_unit_or_pid_still_parses(journal):
    kernel = parse_journal_binary_file(journal)[3]
    assert kernel["message"].startswith("Out of memory: Killed process 4242")
    assert kernel["process"] == "kernel" and kernel["transport"] == "kernel"
    assert "unit" not in kernel and not kernel["pid"]


def test_a_compressed_field_is_decoded(journal):
    """The 1.3 KB message is stored as a ZSTD-compressed data object."""
    long_row = parse_journal_binary_file(journal)[4]
    assert long_row["message"].startswith("long-field ") and long_row["message"].endswith(" end-marker")
    assert len(long_row["message"]) == len("long-field ") + 16 * 80 + len(" end-marker")


def test_multiline_message_is_kept_whole(journal):
    row = parse_journal_binary_file(journal)[5]
    assert row["message"] == 'Traceback (most recent call last):\n  File "x.py", line 1\nValueError: boom'


def test_file_is_read_even_though_it_is_shorter_than_its_declared_arena(journal):
    """The fixtures are trimmed after the last object, as a copied-off live journal can be."""
    assert journal.stat().st_size < 4_000_000
    assert len(read_journal_entries(journal)[0]) == 6


# ------------------------------------------------------------- detection/dispatch

@pytest.mark.parametrize(
    "path",
    [
        "var/log/journal/0123456789abcdef0123456789abcdef/system.journal",
        "var/log/journal/0123456789abcdef0123456789abcdef/user-1000.journal",
        "var/log/journal/0123456789abcdef0123456789abcdef/system@aaaa-bbbb.journal",
        "var/log/journal/0123456789abcdef0123456789abcdef/system@aaaa-bbbb.journal~",
        "run/log/journal/0123456789abcdef0123456789abcdef/system.journal",
        "evidence/host1/var/log/journal/abc/system.journal",
    ],
)
def test_binary_journal_paths_are_detected(path):
    assert looks_like_linux_artifact(path) == ("linux_journal", "journal_binary", "linux_journal_raw")


@pytest.mark.parametrize("path", ["var/log/journal/notes.txt", "home/u/system.journal.bak", "usr/share/doc/system.journal"])
def test_other_paths_are_not_binary_journals(path):
    assert looks_like_linux_artifact(path) is None or looks_like_linux_artifact(path)[1] != "journal_binary"


def test_dispatch_parses_a_binary_journal(journal):
    rows = parse_linux_artifact_file(journal, parser="linux_journal_raw", artifact_type="journal_binary", source_path="var/log/journal/abc/system.journal")
    assert len(rows) == 6 and rows[0]["process"] == "sshd"


def test_dispatch_recognises_a_renamed_journal_by_its_magic_bytes(tmp_path):
    renamed = _unpack(tmp_path, "debian_12", filename="mystery.bin")
    rows = parse_linux_artifact_file(renamed, parser="linux_journal_raw", artifact_type="journal_binary", source_path="x/mystery.bin")
    assert len(rows) == 6


def test_text_exports_still_parse_as_before(tmp_path):
    export = tmp_path / "journal.export"
    export.write_text("__REALTIME_TIMESTAMP=1709288430123456\nMESSAGE=hello\nSYSLOG_IDENTIFIER=app\n\n")
    rows = parse_linux_artifact_file(export, parser="linux_journal_raw", artifact_type="journal_export", source_path="journal.export")
    assert len(rows) == 1 and rows[0]["message"] == "hello" and rows[0]["process"] == "app"


def test_binary_journal_is_listed_as_supported_not_unsupported():
    inventory = build_linux_inventory(Path("."), ["var/log/journal/abc/system.journal", "etc/hostname"])
    assert inventory is not None
    journal_items = [item for item in inventory["detected_artifacts"] if item["key"] == "journal"]
    assert len(journal_items) == 1 and journal_items[0]["artifact_type"] == "journal_binary"
    assert inventory["unsupported"] == []


# --------------------------------------------------------------------- robustness

def test_empty_file_yields_nothing(tmp_path):
    empty = tmp_path / "empty.journal"
    empty.write_bytes(b"")
    assert read_journal_entries(empty) == ([], {"truncated": False, "undecodable_fields": 0})


def test_non_journal_content_is_rejected_cleanly(tmp_path):
    bogus = tmp_path / "bogus.journal"
    bogus.write_bytes(b"not a journal at all" * 50)
    with pytest.raises(ValueError):
        read_journal_entries(bogus)
    assert not is_journal_file(bogus)


def test_dispatch_does_not_treat_a_non_journal_as_one(tmp_path):
    text = tmp_path / "system.journal"
    text.write_text("MESSAGE=plain text pretending\n\n")
    rows = parse_linux_artifact_file(text, parser="linux_journal_raw", artifact_type="journal_binary", source_path="x/system.journal")
    assert [r["message"] for r in rows] == ["plain text pretending"]


def test_truncated_file_keeps_the_entries_read_before_the_cut(tmp_path):
    full = _unpack(tmp_path, "ubuntu_24_04").read_bytes()
    cut = tmp_path / "cut.journal"
    cut.write_bytes(full[: len(full) - 1500])
    rows = parse_journal_binary_file(cut)
    assert 0 < len([r for r in rows if r["message"]]) <= 6


def test_header_only_file_yields_no_entries(tmp_path):
    full = _unpack(tmp_path, "debian_12").read_bytes()
    only = tmp_path / "head.journal"
    only.write_bytes(full[:272])
    assert read_journal_entries(only)[0] == []


def test_the_reader_survives_random_corruption(tmp_path):
    """Untrusted input: mutated copies must never raise (other than the not-a-journal check)
    nor loop; they return whatever was readable."""
    original = _unpack(tmp_path, "ubuntu_22_04").read_bytes()
    rng = random.Random(20240301)
    started = time.monotonic()
    for index in range(300):
        data = bytearray(original)
        for _ in range(rng.randint(1, 40)):
            position = rng.randrange(len(data) if index % 3 else 600)
            data[position] = rng.randrange(256)
        target = tmp_path / f"fuzz{index % 3}.journal"
        target.write_bytes(bytes(data))
        try:
            entries, _info = read_journal_entries(target)
        except ValueError:
            continue
        assert len(entries) <= 6 + 5
    assert time.monotonic() - started < 60


def test_absurd_object_sizes_do_not_loop_or_allocate(tmp_path):
    data = bytearray(_unpack(tmp_path, "debian_12").read_bytes())
    # Point the first object after the header at a gigantic size.
    first = struct.unpack_from("<Q", data, 88)[0]
    struct.pack_into("<Q", data, first + 8, 2**62)
    target = tmp_path / "huge.journal"
    target.write_bytes(bytes(data))
    assert read_journal_entries(target)[0] == []


def test_entry_cap_adds_a_truncation_marker(journal, monkeypatch):
    monkeypatch.setattr(journal_binary, "MAX_ENTRIES", 2)
    rows = parse_journal_binary_file(journal)
    assert len(rows) == 3
    assert "incomplete" in rows[-1]["message"] and rows[-1]["timestamp"] is None


def test_oversized_compressed_field_is_reported_not_trusted(journal, monkeypatch):
    monkeypatch.setattr(journal_binary, "MAX_FIELD_BYTES", 500)
    rows = parse_journal_binary_file(journal)
    assert "could not be decoded" in rows[-1]["message"]
    assert len(rows) == 7  # six entries plus the marker


# ------------------------------------------------------------------ compression

PAYLOAD = b"MESSAGE=" + b"compress me " * 100


def test_xz_payload():
    assert _decompress(lzma.compress(PAYLOAD), journal_binary._FLAG_XZ) == PAYLOAD


def test_zstd_payload():
    import zstandard

    assert _decompress(zstandard.ZstdCompressor().compress(PAYLOAD), journal_binary._FLAG_ZSTD) == PAYLOAD


def test_lz4_payload_with_the_journal_size_prefix():
    import lz4.block

    blob = struct.pack("<Q", len(PAYLOAD)) + lz4.block.compress(PAYLOAD, store_size=False)
    assert _decompress(blob, journal_binary._FLAG_LZ4) == PAYLOAD


def test_lz4_declaring_a_huge_size_is_refused():
    assert _decompress(struct.pack("<Q", 2**40) + b"\x00" * 20, journal_binary._FLAG_LZ4) is None


@pytest.mark.parametrize("flag", [journal_binary._FLAG_XZ, journal_binary._FLAG_LZ4, journal_binary._FLAG_ZSTD])
def test_garbage_compressed_payload_returns_none(flag):
    assert _decompress(b"\xff\x00garbage" * 4, flag) is None


def test_decompression_is_capped(monkeypatch):
    import zstandard

    monkeypatch.setattr(journal_binary, "MAX_FIELD_BYTES", 1000)
    bomb = zstandard.ZstdCompressor().compress(b"A" * 10_000_000)
    assert _decompress(bomb, journal_binary._FLAG_ZSTD) is None
    assert _decompress(lzma.compress(b"A" * 10_000_000), journal_binary._FLAG_XZ) is None


# ------------------------------------------------------------ downstream pipeline

def test_binary_journal_rows_normalize_and_feed_sigma(journal):
    """Binary journal -> normalizer -> Sigma keyword rule for service sshd."""
    from app.ingest.artifact_normalizers import normalize_linux_row
    from app.ingest.normalizer import base_document
    from app.rules_engine.sigma import compile_sigma_rule, evaluate_compiled_sigma_rule

    rows = parse_journal_binary_file(journal, source_path="var/log/journal/abc/system.journal")
    docs = []
    for row in rows:
        base = base_document("case-1", "ev-1", "art-1", row, {"artifact_type": "linux_journal"})
        docs.append(normalize_linux_row(base, row, source_path=row["source_path"], artifact_type="linux_journal"))
    assert docs[0]["linux"]["exe"] == "/usr/sbin/sshd"
    assert docs[0]["@timestamp"].startswith("2024-03-01T10:20:30")

    rule = yaml.safe_load("""
title: SSH failed login
logsource: {product: linux, service: sshd}
detection:
  keywords:
    - 'Failed password'
  condition: keywords
""")
    compiled = compile_sigma_rule(rule)
    assert compiled["compile_status"] == "compiled"
    assert [evaluate_compiled_sigma_rule(compiled, d)["matched"] for d in docs[:3]] == [True, False, False]
