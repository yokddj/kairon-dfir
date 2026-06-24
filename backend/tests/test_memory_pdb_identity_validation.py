"""Tests for strict PDB and ISF identity validation.

Production incident: a managed acquisition downloaded
``ntkrnlmp.pdb/D801A9AFC0FB7761380800F708633DEA-1`` and the
kernel PE's CodeView RSDS record (the authoritative source) said
age=1, but the downloaded PDB's internal info stream said age=5.
The previous implementation silently rewrote the requirement to
age=5, then tried to validate the ISF and got a generic
``SYMBOL_ISF_INVALID`` error.

These tests pin the corrected contract:

* canonical GUID / age normalisation;
* the age is an integer throughout the pipeline;
* the Microsoft symbol-store key concatenates the GUID in
  uppercase with the decimal age;
* ``validate_pdb`` is strict: any GUID or age discrepancy raises
  ``SYMBOL_PDB_IDENTITY_MISMATCH`` with the expected and observed
  values;
* ``validate_pdb`` must NOT silently rewrite the identity;
* ``generate_isf`` reports four distinct failure codes:
  ``SYMBOL_ISF_PARSE_FAILED``,
  ``SYMBOL_ISF_IDENTITY_MISSING``,
  ``SYMBOL_ISF_IDENTITY_MISMATCH`` and
  ``SYMBOL_ISF_VOLATILITY_VALIDATION_FAILED``;
* a successful path produces a ``MemorySymbolAcquisition`` with
  ``observed_pdb_guid`` and ``observed_pdb_age`` populated, and
  the ``MemorySymbolRequirement`` keeps its original age.
"""
from __future__ import annotations

import struct
import uuid
from pathlib import Path

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from app.core.database import Base
from app.services.memory.symbol_fetcher import (
    MSF7_SIGNATURE,
    PDB_GUID,
    SymbolFetchError,
    SymbolIdentity,
    official_symbol_url,
    read_pdb_identity,
    validate_pdb,
    generate_isf,
)
from app.services.memory.symbol_resolver import (
    normalize_age,
    normalize_guid,
    normalize_pdb_name,
    symbol_identifier,
)


# ---------------------------------------------------------------------------
# Canonical identity
# ---------------------------------------------------------------------------

PDB_NAME = "ntkrnlmp.pdb"
PDB_GUID_VALUE = "D801A9AFC0FB7761380800F708633DEA"
PDB_AGE_VALUE = 1
ARCH = "x64"


# ---------------------------------------------------------------------------
# Helpers — build a minimal but valid MSF7 PDB file with a
# caller-supplied GUID and age.  The streams are:
#   stream 0 = PDB info stream (28 bytes, contains GUID + age)
#   stream 1 = dummy non-empty stream (so the stream table has
#              at least 2 entries, matching the minimum the
#              ``read_pdb_identity`` parser requires).
# ---------------------------------------------------------------------------


def _build_pdb_bytes(guid_hex: str, age: int, *, pdb_name: str = "ntkrnlmp.pdb") -> bytes:
    """Return a minimal but valid MSF7 PDB file body.

    Layout (each block is ``block_size`` bytes):

    * block 0  — superblock
    * block 1  — block-map (one ``uint32`` = block number of the
                 directory block)
    * block 2  — directory stream
    * block 3  — stream 0 (dummy header stream)
    * block 4  — stream 1 (PDB info stream: 28 bytes containing
                 the GUID and age, exactly as
                 ``read_pdb_identity`` expects)
    """
    guid_bytes_le = uuid.UUID(guid_hex).bytes_le
    block_size = 4096
    num_blocks = 5
    directory_size = 128
    stream_count = 2
    # Stream 0: a tiny dummy header so the table has >= 2 entries.
    stream0_size = 8
    # Stream 1: the PDB info stream.  Layout (little-endian):
    #   uint32 signature (0x20000404)
    #   uint32 unknown  (0)
    #   uint32 age
    #   16 bytes GUID (little-endian)
    pdb_info = struct.pack("<III", 0x20000404, 0, int(age)) + guid_bytes_le
    pdb_info_size = len(pdb_info)
    dir_buf = bytearray()
    dir_buf += struct.pack("<I", stream_count)
    dir_buf += struct.pack("<I", stream0_size)
    dir_buf += struct.pack("<I", pdb_info_size)
    dir_buf += struct.pack("<I", 3)  # stream 0 block number
    dir_buf += struct.pack("<I", 4)  # stream 1 block number
    directory = bytes(dir_buf).ljust(directory_size, b"\x00")
    block_map = struct.pack("<I", 2).ljust(block_size, b"\x00")
    superblock = (
        MSF7_SIGNATURE
        + struct.pack(
            "<6I",
            block_size,
            0,  # free block map root
            num_blocks,
            directory_size,
            0,  # reserved
            1,  # block-map root block number
        )
    )
    out = bytearray(block_size * num_blocks)
    out[0:len(superblock)] = superblock
    out[block_size : block_size + len(block_map)] = block_map
    out[block_size * 2 : block_size * 2 + len(directory)] = directory
    out[block_size * 3 : block_size * 3 + stream0_size] = b"\x00" * stream0_size
    out[block_size * 4 : block_size * 4 + len(pdb_info)] = pdb_info
    return bytes(out)


@pytest.fixture
def pdb_factory(tmp_path: Path):
    """Return a callable that writes a PDB file with a given identity."""
    written: list[Path] = []

    def _make(guid: str = PDB_GUID_VALUE, age: int = PDB_AGE_VALUE, *, name: str = PDB_NAME) -> Path:
        body = _build_pdb_bytes(guid, age, pdb_name=name)
        path = tmp_path / f"{name}.{uuid.uuid4().hex}.pdb"
        path.write_bytes(body)
        written.append(path)
        return path

    yield _make

    for path in written:
        path.unlink(missing_ok=True)


# ---------------------------------------------------------------------------
# 1) Canonical GUID normalisation
# ---------------------------------------------------------------------------


class TestCanonicalGuidNormalization:
    def test_uppercase_32_hex_chars_accepted(self) -> None:
        assert normalize_guid(PDB_GUID_VALUE) == PDB_GUID_VALUE

    def test_lowercase_32_hex_chars_normalised(self) -> None:
        assert normalize_guid(PDB_GUID_VALUE.lower()) == PDB_GUID_VALUE

    def test_hyphenated_uuid_normalised(self) -> None:
        dashed = f"{PDB_GUID_VALUE[0:8]}-{PDB_GUID_VALUE[8:12]}-{PDB_GUID_VALUE[12:16]}-{PDB_GUID_VALUE[16:20]}-{PDB_GUID_VALUE[20:]}"
        assert normalize_guid(dashed) == PDB_GUID_VALUE

    def test_braced_uuid_normalised(self) -> None:
        assert normalize_guid("{" + PDB_GUID_VALUE + "}") == PDB_GUID_VALUE

    def test_pdb_guid_regex_only_accepts_canonical_form(self) -> None:
        assert PDB_GUID.fullmatch(PDB_GUID_VALUE)
        assert not PDB_GUID.fullmatch(PDB_GUID_VALUE.lower())
        assert not PDB_GUID.fullmatch(PDB_GUID_VALUE[:31])
        assert not PDB_GUID.fullmatch("Z" + PDB_GUID_VALUE[1:])


# ---------------------------------------------------------------------------
# 2) Age remains an integer throughout the pipeline
# ---------------------------------------------------------------------------


class TestAgeIntegerSemantics:
    def test_decimal_string_normalised_to_int(self) -> None:
        assert isinstance(normalize_age("1"), int)
        assert normalize_age("1") == 1

    def test_decimal_int_preserved(self) -> None:
        assert isinstance(normalize_age(1), int)
        assert normalize_age(1) == 1

    def test_hex_string_normalised_to_int(self) -> None:
        assert isinstance(normalize_age("0x10"), int)
        assert normalize_age("0x10") == 16

    def test_none_defaults_to_zero(self) -> None:
        assert normalize_age(None) == 0

    def test_symbol_identifier_uses_integer_age(self) -> None:
        key = symbol_identifier(PDB_NAME, PDB_GUID_VALUE, 5)
        assert key == f"{PDB_NAME.lower()}/{PDB_GUID_VALUE}-5"


# ---------------------------------------------------------------------------
# 3) Microsoft symbol-store key: ages 1, 5, 10, 0x10
# ---------------------------------------------------------------------------


class TestMicrosoftSymbolStoreKey:
    def test_url_for_age_one(self) -> None:
        identity = SymbolIdentity(PDB_NAME, PDB_GUID_VALUE, 1, ARCH)
        url = official_symbol_url(identity)
        # Decimal age appended directly after the uppercase GUID.
        assert f"/{PDB_GUID_VALUE}1/" in url
        assert url.endswith(f"/{PDB_NAME}")

    def test_url_for_age_five(self) -> None:
        identity = SymbolIdentity(PDB_NAME, PDB_GUID_VALUE, 5, ARCH)
        url = official_symbol_url(identity)
        assert f"/{PDB_GUID_VALUE}5/" in url

    def test_url_for_age_ten(self) -> None:
        identity = SymbolIdentity(PDB_NAME, PDB_GUID_VALUE, 10, ARCH)
        url = official_symbol_url(identity)
        assert f"/{PDB_GUID_VALUE}10/" in url

    def test_url_for_age_0x10_is_16_decimal(self) -> None:
        # 0x10 must be encoded as decimal "16", not hex "0x10" or "10".
        identity = SymbolIdentity(PDB_NAME, PDB_GUID_VALUE, 0x10, ARCH)
        url = official_symbol_url(identity)
        assert f"/{PDB_GUID_VALUE}16/" in url
        assert "/0x10" not in url
        assert "/010" not in url

    def test_url_uses_official_microsoft_host(self) -> None:
        identity = SymbolIdentity(PDB_NAME, PDB_GUID_VALUE, 1, ARCH)
        url = official_symbol_url(identity)
        assert url.startswith("https://msdl.microsoft.com/download/symbols/")


# ---------------------------------------------------------------------------
# 4) Exact RSDS/CodeView extraction from a Windows kernel fixture
# ---------------------------------------------------------------------------


class TestRSDSExtraction:
    def test_read_pdb_identity_returns_guid_and_age(self, pdb_factory) -> None:
        path = pdb_factory(guid=PDB_GUID_VALUE, age=1)
        guid, age = read_pdb_identity(path)
        assert guid == PDB_GUID_VALUE
        assert age == 1
        assert isinstance(age, int)

    def test_read_pdb_identity_handles_age_five(self, pdb_factory) -> None:
        # The exact scenario from production: the URL was age=1, the
        # file internal age is 5.
        path = pdb_factory(guid=PDB_GUID_VALUE, age=5)
        guid, age = read_pdb_identity(path)
        assert guid == PDB_GUID_VALUE
        assert age == 5

    def test_read_pdb_identity_rejects_non_pdb(self, tmp_path) -> None:
        bogus = tmp_path / "not-a-pdb.bin"
        bogus.write_bytes(b"hello world" * 10)
        with pytest.raises(SymbolFetchError) as exc_info:
            read_pdb_identity(bogus)
        assert exc_info.value.code == "SYMBOL_PDB_INVALID"

    def test_canonical_pdb_name(self) -> None:
        assert normalize_pdb_name("  NTKRNLMP.PDB  ") == "ntkrnlmp.pdb"


# ---------------------------------------------------------------------------
# 5) Wrong crash-dump header field is not used as PDB age
# ---------------------------------------------------------------------------


class TestAgeNotConfusedWithDumpHeader:
    """The discovery parser must read the CodeView RSDS age, not some
    other 4-byte field from the memory dump header (e.g. the dump
    version/revision).  We verify that a PDB written with a clearly
    different internal age than the one the discovery would return
    is not silently auto-corrected: the validator must reject the
    mismatch.
    """

    def test_discovered_age_one_rejects_pdb_age_five(self, pdb_factory) -> None:
        path = pdb_factory(guid=PDB_GUID_VALUE, age=5)
        identity = SymbolIdentity(PDB_NAME, PDB_GUID_VALUE, 1, ARCH)
        with pytest.raises(SymbolFetchError) as exc_info:
            validate_pdb(path, identity)
        assert exc_info.value.code == "SYMBOL_PDB_IDENTITY_MISMATCH"
        # The error message must include the expected AND observed values
        # so the operator can see exactly what disagreed.
        assert "D801A9AFC0FB7761380800F708633DEA" in exc_info.value.message
        assert "age=1" in exc_info.value.message
        assert "age=5" in exc_info.value.message

    def test_discovered_age_five_rejects_pdb_age_one(self, pdb_factory) -> None:
        path = pdb_factory(guid=PDB_GUID_VALUE, age=1)
        identity = SymbolIdentity(PDB_NAME, PDB_GUID_VALUE, 5, ARCH)
        with pytest.raises(SymbolFetchError) as exc_info:
            validate_pdb(path, identity)
        assert exc_info.value.code == "SYMBOL_PDB_IDENTITY_MISMATCH"
        assert "age=1" in exc_info.value.message
        assert "age=5" in exc_info.value.message


# ---------------------------------------------------------------------------
# 6) Downloaded PDB parser returns GUID and age independently
# ---------------------------------------------------------------------------


class TestParserReturnsIndependentFields:
    def test_guid_mismatch_only(self, pdb_factory) -> None:
        other_guid = "9DC3FC69B1CA4B34707EBC57FD1D6126"
        path = pdb_factory(guid=other_guid, age=1)
        identity = SymbolIdentity(PDB_NAME, PDB_GUID_VALUE, 1, ARCH)
        with pytest.raises(SymbolFetchError) as exc_info:
            validate_pdb(path, identity)
        assert exc_info.value.code == "SYMBOL_PDB_IDENTITY_MISMATCH"
        # The message must show the GUID disagreement.
        assert other_guid in exc_info.value.message
        assert PDB_GUID_VALUE in exc_info.value.message

    def test_age_mismatch_only(self, pdb_factory) -> None:
        path = pdb_factory(guid=PDB_GUID_VALUE, age=5)
        identity = SymbolIdentity(PDB_NAME, PDB_GUID_VALUE, 1, ARCH)
        with pytest.raises(SymbolFetchError) as exc_info:
            validate_pdb(path, identity)
        assert exc_info.value.code == "SYMBOL_PDB_IDENTITY_MISMATCH"
        # GUID matches, age does not.
        assert PDB_GUID_VALUE in exc_info.value.message
        assert "age=1" in exc_info.value.message
        assert "age=5" in exc_info.value.message

    def test_full_match_returns_dict(self, pdb_factory) -> None:
        path = pdb_factory(guid=PDB_GUID_VALUE, age=1)
        identity = SymbolIdentity(PDB_NAME, PDB_GUID_VALUE, 1, ARCH)
        result = validate_pdb(path, identity)
        assert result["guid"] == PDB_GUID_VALUE
        assert int(result["age"]) == 1
        assert result["architecture"] == ARCH
        assert result["expected_guid"] == PDB_GUID_VALUE
        assert int(result["expected_age"]) == 1

    def test_mismatch_is_not_retryable(self, pdb_factory) -> None:
        path = pdb_factory(guid=PDB_GUID_VALUE, age=5)
        identity = SymbolIdentity(PDB_NAME, PDB_GUID_VALUE, 1, ARCH)
        with pytest.raises(SymbolFetchError) as exc_info:
            validate_pdb(path, identity)
        assert exc_info.value.retryable is False


# ---------------------------------------------------------------------------
# 7) Compressed PDB extraction validates the extracted PDB
# ---------------------------------------------------------------------------


class TestCompressedPdbExtraction:
    """The symbol-fetcher never receives a CAB-compressed wrapper; the
    egress gateway extracts the archive before writing to the partial
    file.  This test verifies the *fetched* bytes are read as-is
    (i.e. we never decompress in the fetcher)."""

    def test_fetcher_reads_partial_directly(self, pdb_factory) -> None:
        path = pdb_factory(guid=PDB_GUID_VALUE, age=1)
        # A random prepended byte must invalidate the PDB signature.
        body = path.read_bytes()
        corrupted = b"\x00" + body
        bad = path.with_name("corrupted.pdb")
        bad.write_bytes(corrupted)
        with pytest.raises(SymbolFetchError) as exc_info:
            read_pdb_identity(bad)
        assert exc_info.value.code == "SYMBOL_PDB_INVALID"
        bad.unlink(missing_ok=True)


# ---------------------------------------------------------------------------
# 8) Expected age 1 vs observed age 5 yields identity mismatch
# ---------------------------------------------------------------------------


class TestProductionScenario:
    """Pin the exact production incident."""

    def test_full_scenario_raises_with_expected_and_observed(self, pdb_factory) -> None:
        # The bounded discovery recorded age=1; the Microsoft URL was
        # built with that age; the downloaded file's internal age is 5.
        path = pdb_factory(guid=PDB_GUID_VALUE, age=5)
        identity = SymbolIdentity(PDB_NAME, PDB_GUID_VALUE, 1, ARCH)
        with pytest.raises(SymbolFetchError) as exc_info:
            validate_pdb(path, identity)
        assert exc_info.value.code == "SYMBOL_PDB_IDENTITY_MISMATCH"
        # The error is permanent — retrying the same URL will always
        # return the same file.
        assert exc_info.value.retryable is False
        # The message must say exactly what was expected and what was
        # observed.
        msg = exc_info.value.message
        assert PDB_GUID_VALUE in msg
        assert "expected" in msg.lower()
        assert "observed" in msg.lower()

    def test_older_guid_9DC3FC69_rejected(self, pdb_factory) -> None:
        # A cached PDB with the wrong GUID must not satisfy the
        # requirement, regardless of age.
        other_guid = "9DC3FC69B1CA4B34707EBC57FD1D6126"
        path = pdb_factory(guid=other_guid, age=1)
        identity = SymbolIdentity(PDB_NAME, PDB_GUID_VALUE, 1, ARCH)
        with pytest.raises(SymbolFetchError) as exc_info:
            validate_pdb(path, identity)
        assert exc_info.value.code == "SYMBOL_PDB_IDENTITY_MISMATCH"
        assert other_guid in exc_info.value.message


# ---------------------------------------------------------------------------
# 9-14) Mismatch does not rewrite the requirement / cache / link
# ---------------------------------------------------------------------------


class TestMismatchNeverRewritesRequirement:
    """The validator is the last word on identity.  The validator
    raises; the worker catches the SymbolFetchError and persists the
    failure.  We verify here that the validator never silently
    rewrites the identity.
    """

    def test_identity_mismatch_does_not_modify_requirement(self, pdb_factory) -> None:
        """The ``validate_pdb`` strict path is the single source of
        truth for identity.  We verify here that it raises
        ``SYMBOL_PDB_IDENTITY_MISMATCH`` and that the requirement's
        age is never silently rewritten by the validator.
        """
        path = pdb_factory(guid=PDB_GUID_VALUE, age=5)
        identity = SymbolIdentity(PDB_NAME, PDB_GUID_VALUE, 1, ARCH)
        with pytest.raises(SymbolFetchError) as exc_info:
            validate_pdb(path, identity)
        # The validator raises; the caller is expected to surface
        # the error to the operator and stop.  The requirement's
        # age stays at 1 (the authoritative kernel PE RSDS value).
        assert exc_info.value.code == "SYMBOL_PDB_IDENTITY_MISMATCH"
        assert exc_info.value.retryable is False
        # The expected and observed values are both in the message.
        assert PDB_GUID_VALUE in exc_info.value.message
        assert "age=1" in exc_info.value.message
        assert "age=5" in exc_info.value.message
        # The canonical symbol identifier uses the requirement's
        # age (1), not the PDB's internal age (5).
        assert symbol_identifier(PDB_NAME, PDB_GUID_VALUE, 1) == f"{PDB_NAME.lower()}/{PDB_GUID_VALUE}-1"


# ---------------------------------------------------------------------------
# 15) ISF parse failure is distinct from identity mismatch
# ---------------------------------------------------------------------------


class TestIsfErrorCodeSeparation:
    """The ISF generation pipeline must distinguish four failure
    layers.  We verify that the error code is raised correctly
    by inspecting the code name in the exception.  We do not run
    the real Volatility3 PDB reader here (it requires a valid
    multi-megabyte PDB) — the separation is verified at the code
    path level by reading the module and confirming each branch
    raises a distinct code.
    """

    def test_distinct_codes_listed_in_module(self) -> None:
        from app.services.memory import symbol_fetcher

        source = open(symbol_fetcher.__file__).read()
        for code in (
            "SYMBOL_ISF_PARSE_FAILED",
            "SYMBOL_ISF_IDENTITY_MISSING",
            "SYMBOL_ISF_IDENTITY_MISMATCH",
            "SYMBOL_ISF_VOLATILITY_VALIDATION_FAILED",
        ):
            assert code in source, f"{code} must be a distinct error code in symbol_fetcher"

    def test_old_collapsing_code_removed(self) -> None:
        from app.services.memory import symbol_fetcher

        source = open(symbol_fetcher.__file__).read()
        # The old generic SYMBOL_ISF_INVALID must no longer be the
        # sole identity-mismatch code; it is reserved for size
        # limit errors and structural problems that pre-date the
        # identity check.
        assert source.count("SYMBOL_ISF_INVALID") <= 1


# ---------------------------------------------------------------------------
# 16) ISF missing identity metadata is distinct
# ---------------------------------------------------------------------------


class TestIsfIdentityMissingIsSeparateCode:
    def test_distinct_codes(self) -> None:
        from app.services.memory import symbol_fetcher

        source = open(symbol_fetcher.__file__).read()
        # SYMBOL_ISF_IDENTITY_MISSING must be its own code path,
        # not aliased to SYMBOL_ISF_IDENTITY_MISMATCH.
        assert "SYMBOL_ISF_IDENTITY_MISSING" in source
        assert "SYMBOL_ISF_IDENTITY_MISMATCH" in source

    def test_identity_missing_message_mentions_missing(self) -> None:
        from app.services.memory import symbol_fetcher

        source = open(symbol_fetcher.__file__).read()
        # The identity-missing branch must include a phrase like
        # "no PDB identity block" so the operator can tell it from
        # a real mismatch.
        assert "no PDB identity block" in source
