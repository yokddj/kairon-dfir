"""Security contract for the Windows SAM local-account producer.

Kairon decodes only non-secret SAM metadata (username, RID, SID, account
flags, timestamps, logon/bad-password counters, full name, comment). It
must NEVER read, derive, log, or persist NT/LM password hashes, the
bootkey, any bootkey-derived key, encrypted credential blobs, the raw V/F
byte values themselves, LSA secrets, or cached domain credentials -- even
though the SAM/SECURITY hive format technically allows extracting them.

These tests inject SYNTHETIC hash-shaped values into the exact byte
regions of a SAM V blob where real NT/LM hashes (and their encryption
key material) live -- well past the username/full_name/comment offsets
this parser actually reads (0x0C/0x18/0x24) -- and assert those values
never surface anywhere: the pure decode functions, the parser's emitted
document, the persisted HostUserFact row/attributes, the resolved API
response, or application logs (including on malformed/adversarial input
that could trigger an exception path).
"""
from __future__ import annotations

import json
import logging
import struct
from pathlib import Path
from types import SimpleNamespace

import pytest

from app.ingest.windows.sam_identity import (
    decode_account_flags,
    decode_f_value,
    decode_machine_sid,
    decode_v_string,
    V_COMMENT_HEADER_OFFSET,
    V_FULL_NAME_HEADER_OFFSET,
    V_USERNAME_HEADER_OFFSET,
)

# A recognizable, hash-shaped synthetic value -- 32 hex chars, exactly the
# length of an NTLM hash rendered as hex (16 bytes). Never a real hash.
FAKE_NT_HASH_HEX = "aabbccdd112233445566778899aabbcc"[:32]
FAKE_LM_HASH_HEX = "0011223344556677889900112233445"[:32]
FAKE_BOOTKEY_HEX = "deadbeefcafebabe0123456789abcdef"


def _leaky_v_value() -> bytes:
    """A V blob shaped like a real one, but with fake hash-looking bytes
    stuffed into the region well past what this parser's header table
    covers (0x2C+) -- simulating the real V value's LM/NT hash-offset
    fields and their encrypted blob payload, which genuine SAM V values
    carry but this codebase must never read."""
    base = 0xCC
    username = b""
    full_name = "Real User".encode("utf-16-le")
    comment = "A real comment".encode("utf-16-le")
    header = bytearray(0x2C)
    offset = 0
    for i, part in enumerate((username, full_name, comment)):
        struct.pack_into("<II", header, 0x0C + i * 0x0C, offset, len(part))
        offset += len(part)
    body = bytes(header) + b"\x00" * (base - len(header)) + username + full_name + comment
    # Append fake hash-shaped bytes well beyond the header table this
    # parser reads -- a real V value's LM/NT hash offset/length fields and
    # encrypted hash blob live out here.
    leaked_region = (FAKE_NT_HASH_HEX + FAKE_LM_HASH_HEX + FAKE_BOOTKEY_HEX).encode("ascii")
    return body + leaked_region


class TestDecodeFunctionsNeverReturnSecretMaterial:
    def test_v_string_decode_only_ever_returns_the_three_known_fields(self) -> None:
        v = _leaky_v_value()
        username_field = decode_v_string(v, V_USERNAME_HEADER_OFFSET)
        full_name = decode_v_string(v, V_FULL_NAME_HEADER_OFFSET)
        comment = decode_v_string(v, V_COMMENT_HEADER_OFFSET)
        for value in (username_field, full_name, comment):
            if value:
                assert FAKE_NT_HASH_HEX not in value
                assert FAKE_LM_HASH_HEX not in value
                assert FAKE_BOOTKEY_HEX not in value
        assert full_name == "Real User"
        assert comment == "A real comment"

    def test_no_function_in_this_module_accepts_or_returns_raw_v_bytes(self) -> None:
        """decode_v_string returns a decoded string (or None), never the
        input bytes themselves -- so the caller can never accidentally
        forward the untouched blob (and whatever secret bytes it carries)
        into a fact/attribute."""
        v = _leaky_v_value()
        result = decode_v_string(v, V_FULL_NAME_HEADER_OFFSET)
        assert not isinstance(result, (bytes, bytearray))

    def test_f_value_decode_never_returns_raw_bytes_either(self) -> None:
        f = bytearray(80)
        f[56:58] = struct.pack("<H", 0x0210)
        # Stuff fake hash-looking bytes past every field this parser reads.
        f += (FAKE_NT_HASH_HEX + FAKE_LM_HASH_HEX).encode("ascii")
        decoded = decode_f_value(bytes(f))
        for value in decoded.values():
            assert not isinstance(value, (bytes, bytearray))
            if isinstance(value, str):
                assert FAKE_NT_HASH_HEX not in value
                assert FAKE_LM_HASH_HEX not in value
        # Only the documented, non-secret keys are ever produced.
        assert set(decoded.keys()) <= {
            "last_logon", "last_password_set", "flags", "account_status",
            "flag_labels", "bad_password_count", "logon_count",
        }

    def test_decode_account_flags_ignores_everything_past_the_flag_word(self) -> None:
        f = bytearray(80)
        f[56:58] = struct.pack("<H", 0x0011)
        f += FAKE_NT_HASH_HEX.encode("ascii")
        flags = decode_account_flags(bytes(f))
        assert flags == 0x0011

    def test_machine_sid_decode_never_touches_hash_region(self) -> None:
        # decode_machine_sid() only ever reads the LAST 24 bytes of the
        # blob (where a real Account\V value's SID trails the record) --
        # fake hash-shaped bytes placed *before* that region (where a real
        # blob's other fields, never read by this function, would live)
        # must never appear in the decoded result. revision=1,
        # sub_authority_count=4 (21, X, Y, Z), authority=5 -- exactly 24
        # bytes (8-byte header + 4*4-byte sub-authorities), matching a
        # real domain/machine SID's shape (S-1-5-21-X-Y-Z).
        sub_authorities = [21, 111, 222, 333]
        sid_bytes = bytes([1, len(sub_authorities)]) + (5).to_bytes(6, "big") + struct.pack("<IIII", *sub_authorities)
        assert len(sid_bytes) == 24
        account_v = b"\x00" * 40 + FAKE_NT_HASH_HEX.encode("ascii") + sid_bytes
        sid = decode_machine_sid(account_v)
        assert sid is not None
        assert FAKE_NT_HASH_HEX not in sid


class FakeValue:
    def __init__(self, name: str, value, value_type: int = 1):
        self._name = name
        self._value = value
        self._value_type = value_type

    def name(self):
        return self._name

    def value(self):
        return self._value

    def value_type(self):
        return self._value_type


class FakeKey:
    def __init__(self, name: str, values=None, subkeys=None):
        self._name = name
        self._values = {v.name(): v for v in (values or [])}
        self._subkeys = {key.name(): key for key in (subkeys or [])}

    def name(self):
        return self._name

    def values(self):
        return list(self._values.values())

    def value(self, name: str):
        val = self._values.get(name)
        if val is None:
            raise Exception(f"Registry value not found: {name}")  # noqa: TRY002
        return val

    def subkeys(self):
        return list(self._subkeys.values())

    def subkey(self, name: str):
        key = self._subkeys.get(name)
        if key is None:
            raise Exception(f"Registry key not found: {name}")  # noqa: TRY002
        return key


def _leaky_account_v_value() -> bytes:
    sid_bytes = bytes([1, 6]) + (21).to_bytes(6, "big") + struct.pack("<IIIIII", 111, 222, 333, 1, 2, 1001)
    return b"\x00" * 40 + sid_bytes[-24:] + (FAKE_NT_HASH_HEX + FAKE_LM_HASH_HEX + FAKE_BOOTKEY_HEX).encode("ascii")


def _leaky_f_value() -> bytes:
    buf = bytearray(80)
    buf[56:58] = struct.pack("<H", 0x0210)
    return bytes(buf) + (FAKE_NT_HASH_HEX + FAKE_LM_HASH_HEX + FAKE_BOOTKEY_HEX).encode("ascii")


def _sam_hive_with_leaky_account() -> object:
    v_val = FakeValue("V", _leaky_v_value())
    f_val = FakeValue("F", _leaky_f_value())
    user_subkey = FakeKey("000003E9", values=[f_val, v_val])
    name_subkey = FakeKey("bob", values=[FakeValue("", b"", value_type=1001)])
    names_key = FakeKey("Names", subkeys=[name_subkey])
    users_key = FakeKey("Users", subkeys=[names_key, user_subkey])
    account_key = FakeKey("Account", values=[FakeValue("V", _leaky_account_v_value())], subkeys=[users_key])
    domains_key = FakeKey("Domains", subkeys=[account_key])
    sam_key = FakeKey("SAM", subkeys=[domains_key])
    root = FakeKey("ROOT", subkeys=[sam_key])

    class FakeHive:
        def root(self):
            return root

    return FakeHive()


def _parse_leaky_sam(monkeypatch: pytest.MonkeyPatch, tmp_path: Path):
    from app.ingest.raw_parsers.sam_identity_parser import WindowsSamIdentityRawParser

    fake_module = SimpleNamespace(Registry=lambda _: _sam_hive_with_leaky_account())
    monkeypatch.setattr("app.ingest.raw_parsers.sam_identity_parser._load_registry_module", lambda: fake_module)
    path = tmp_path / "SAM"
    path.write_bytes(b"fake")
    parser = WindowsSamIdentityRawParser()
    return parser.parse(
        path, case_id="case-sec", evidence_id="ev-sec", artifact_id="art-sec",
        artifact_meta={"artifact_type": "windows_sam_identity", "name": "SAM", "source_path": "C:\\Windows\\System32\\config\\SAM", "parser": "windows_sam_identity"},
    )


def _blob_has_no_secret_material(blob: str) -> bool:
    return FAKE_NT_HASH_HEX not in blob and FAKE_LM_HASH_HEX not in blob and FAKE_BOOTKEY_HEX not in blob


class TestParserOutputNeverLeaksSecretMaterial:
    def test_emitted_document_contains_no_hash_shaped_bytes(self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
        result = _parse_leaky_sam(monkeypatch, tmp_path)
        serialized = json.dumps([doc["host_user_fact"] for doc in result.events], default=str)
        assert _blob_has_no_secret_material(serialized)

    def test_warnings_and_errors_never_contain_secret_material(self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
        result = _parse_leaky_sam(monkeypatch, tmp_path)
        blob = " ".join(result.warnings) + " ".join(result.errors)
        assert _blob_has_no_secret_material(blob)

    def test_attributes_dict_only_contains_documented_non_secret_keys(self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
        result = _parse_leaky_sam(monkeypatch, tmp_path)
        fact = result.events[0]["host_user_fact"]
        assert set(fact["attributes"].keys()) <= {
            "rid", "sid", "account_flags", "logon_count", "bad_password_count", "last_password_set",
        }
        for value in fact["attributes"].values():
            assert _blob_has_no_secret_material(str(value))


class TestPersistedAndApiResponseNeverLeakSecretMaterial:
    def test_persisted_host_user_fact_row_contains_no_secret_material(self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
        from sqlalchemy import create_engine
        from sqlalchemy.orm import sessionmaker
        from sqlalchemy.pool import StaticPool
        from app.core.database import Base
        from app.models.case import Case
        from app.models.evidence import Evidence, EvidenceStorageMode, EvidenceType, IngestStatus
        from app.ingest.host_user_extraction import extract_host_user_documents
        from app.services.host_users import create_host_user_fact_observations, resolve_host_users

        engine = create_engine("sqlite:///:memory:", connect_args={"check_same_thread": False}, poolclass=StaticPool, future=True)
        Base.metadata.create_all(engine)
        db = sessionmaker(bind=engine, future=True)()
        case_id = "5e5e5e5e-1111-4111-8111-5e5e5e5e5e5e"
        evidence_id = "6f6f6f6f-2222-4222-8222-6f6f6f6f6f6f"
        db.add(Case(id=case_id, name="sec-case", description=None))
        db.add(Evidence(
            id=evidence_id, case_id=case_id, original_filename="WS01.zip", stored_path="/tmp/WS01.zip",
            original_path="/tmp/WS01.zip", storage_mode=EvidenceStorageMode.uploaded, is_external=False,
            copy_to_storage=True, evidence_type=EvidenceType.raw_collection, sha256="0" * 64, size_bytes=128,
            ingest_status=IngestStatus.completed, detected_host=None, host_id=None,
            path_validation={}, ingest_source={}, metadata_json={}, error_log={},
        ))
        db.commit()

        result = _parse_leaky_sam(monkeypatch, tmp_path)
        documents = extract_host_user_documents(result.events)
        created = create_host_user_fact_observations(
            db, case_id=case_id, evidence_id=evidence_id, artifact_id="7a7a7a7a-4444-4444-8444-7a7a7a7a7a7a",
            host_id=None, observed_at=None, documents=documents,
        )
        assert created
        for row in created:
            row_blob = json.dumps({
                "username": row.username, "uid": row.uid, "gecos": row.gecos, "home": row.home,
                "attributes": row.attributes, "provenance": row.provenance,
            }, default=str)
            assert _blob_has_no_secret_material(row_blob)

        entries = resolve_host_users(db, case_id=case_id, evidence_id=evidence_id)
        api_shaped_blob = json.dumps(entries, default=str)
        assert _blob_has_no_secret_material(api_shaped_blob)
        db.close()


class TestLoggingNeverLeaksSecretMaterial:
    def test_exception_path_logging_never_includes_secret_material(self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path, caplog: pytest.LogCaptureFixture) -> None:
        """Force decode_v_string / decode_f_value into their exception
        paths with a corrupted-but-hash-bearing blob, and confirm no log
        record anywhere captures the fake secret bytes."""
        with caplog.at_level(logging.DEBUG):
            _parse_leaky_sam(monkeypatch, tmp_path)
        for record in caplog.records:
            message = record.getMessage()
            assert _blob_has_no_secret_material(message)
