"""Windows local account inventory from the SAM registry hive (and
ProfileList corroboration from the SOFTWARE hive).

Follows the same FakeKey/FakeValue/FakeHive test-double pattern already
established for WindowsSystemHiveIdentityRawParser in
tests/test_windows_system_hive_facts.py -- self-contained, not
cross-imported (confirmed broken in this environment for `from tests.X
import ...`).
"""
from __future__ import annotations

import struct
from datetime import datetime, timezone
from pathlib import Path
from types import SimpleNamespace

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from app.core.database import Base
from app.ingest.host_user_extraction import extract_host_user_documents
from app.ingest.raw_parsers.profile_list_parser import WindowsProfileListRawParser
from app.ingest.raw_parsers.sam_identity_parser import WindowsSamIdentityRawParser
from app.models.case import Case
from app.models.evidence import Evidence, EvidenceStorageMode, EvidenceType, IngestStatus
from app.models.host_user_fact import HostUserFact
from app.services.host_users import create_host_user_fact_observations, resolve_host_users, resolve_unverified_host_profiles

CASE_ID = "7a7a7a7a-1111-4111-8111-7a7a7a7a7a7a"
HOST_ID = "8b8b8b8b-1111-4111-8111-8b8b8b8b8b8b"
EVIDENCE_ID = "9c9c9c9c-2222-4222-8222-9c9c9c9c9c9c"


def _db():
    engine = create_engine("sqlite:///:memory:", connect_args={"check_same_thread": False}, poolclass=StaticPool, future=True)
    Base.metadata.create_all(engine)
    return sessionmaker(bind=engine, future=True)()


def _case(db):
    db.add(Case(id=CASE_ID, name="Case", description=None))
    db.commit()


def _evidence(db, evidence_id=EVIDENCE_ID, host_id=HOST_ID):
    db.add(
        Evidence(
            id=evidence_id, case_id=CASE_ID, original_filename="WS01.zip", stored_path="/tmp/WS01.zip",
            original_path="/tmp/WS01.zip", storage_mode=EvidenceStorageMode.uploaded, is_external=False,
            copy_to_storage=True, evidence_type=EvidenceType.raw_collection, sha256="0" * 64, size_bytes=128,
            ingest_status=IngestStatus.completed, detected_host=None, host_id=host_id,
            path_validation={}, ingest_source={}, metadata_json={}, error_log={},
        )
    )
    db.commit()


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


def _filetime_bytes(dt: datetime | None) -> bytes:
    if dt is None:
        return b"\x00" * 8
    delta = dt - datetime(1601, 1, 1, tzinfo=timezone.utc)
    return struct.pack("<Q", int(delta.total_seconds() * 10_000_000))


def _f_value(*, flags: int, last_logon: datetime | None = None, logon_count: int = 0) -> bytes:
    buf = bytearray(80)
    buf[8:16] = _filetime_bytes(last_logon)
    buf[56:58] = struct.pack("<H", flags)
    buf[66:68] = struct.pack("<H", logon_count)
    return bytes(buf)


def _v_value(*, full_name: str = "", comment: str = "") -> bytes:
    base = 0xCC
    username_part = b""  # never actually read by the parser (username comes from the Names subkey)
    fullname_part = full_name.encode("utf-16-le")
    comment_part = comment.encode("utf-16-le")
    header = bytearray(0x2C)
    offset = 0
    for i, part in enumerate((username_part, fullname_part, comment_part)):
        struct.pack_into("<II", header, 0x0C + i * 0x0C, offset, len(part))
        offset += len(part)
    return bytes(header) + b"\x00" * (base - len(header)) + username_part + fullname_part + comment_part


MACHINE_SID = "S-1-5-21-3104471185-970636935-942730776"


def _account_v_value(sid: str = MACHINE_SID) -> bytes:
    parts = sid.split("-")
    revision, authority = int(parts[1]), int(parts[2])
    subs = [int(p) for p in parts[3:]]
    return b"\x00" * 40 + bytes([revision, len(subs)]) + authority.to_bytes(6, "big") + struct.pack("<" + "I" * len(subs), *subs)


def _sam_hive(*, users: dict[str, dict]) -> object:
    """users: {username: {"rid": int, "flags": int, "last_logon": dt|None, "full_name": str, "comment": str}}"""
    user_subkeys = []
    name_subkeys = []
    for username, spec in users.items():
        rid = spec["rid"]
        rid_hex = format(rid, "08X")
        f_val = FakeValue("F", _f_value(flags=spec.get("flags", 0x0210), last_logon=spec.get("last_logon"), logon_count=spec.get("logon_count", 0)))
        v_val = FakeValue("V", _v_value(full_name=spec.get("full_name", ""), comment=spec.get("comment", "")))
        user_subkeys.append(FakeKey(rid_hex, values=[f_val, v_val]))
        # SAM\...\Users\Names\<username> is a SUBKEY named after the
        # account, holding one (unnamed) value whose *type* field carries
        # the RID -- the real SAM quirk this test double must reproduce.
        name_subkeys.append(FakeKey(username, values=[FakeValue("", b"", value_type=rid)]))

    names_key = FakeKey("Names", subkeys=name_subkeys)
    users_key = FakeKey("Users", subkeys=[names_key, *user_subkeys])
    account_key = FakeKey("Account", values=[FakeValue("V", _account_v_value())], subkeys=[users_key])
    domains_key = FakeKey("Domains", subkeys=[account_key])
    sam_key = FakeKey("SAM", subkeys=[domains_key])
    root = FakeKey("ROOT", subkeys=[sam_key])

    class FakeHive:
        def root(self):
            return root

    return FakeHive()


def _software_hive(*, profiles: dict[str, tuple[str, int]]) -> object:
    """profiles: {sid: (profile_image_path, state)}"""
    sid_subkeys = []
    for sid, (path, state) in profiles.items():
        sid_subkeys.append(FakeKey(sid, values=[FakeValue("ProfileImagePath", path), FakeValue("State", state)]))
    profile_list_key = FakeKey("ProfileList", subkeys=sid_subkeys)
    current_version_key = FakeKey("CurrentVersion", subkeys=[profile_list_key])
    windows_nt_key = FakeKey("Windows NT", subkeys=[current_version_key])
    microsoft_key = FakeKey("Microsoft", subkeys=[windows_nt_key])
    root = FakeKey("ROOT", subkeys=[microsoft_key])

    class FakeHive:
        def root(self):
            return root

    return FakeHive()


def _parse_sam(monkeypatch: pytest.MonkeyPatch, tmp_path: Path, hive) -> object:
    fake_module = SimpleNamespace(Registry=lambda _: hive)
    monkeypatch.setattr("app.ingest.raw_parsers.sam_identity_parser._load_registry_module", lambda: fake_module)
    path = tmp_path / "SAM"
    path.write_bytes(b"fake")
    parser = WindowsSamIdentityRawParser()
    return parser.parse(
        path, case_id=CASE_ID, evidence_id=EVIDENCE_ID, artifact_id="aaaaaaaa-4444-4444-8444-aaaaaaaaaaaa",
        artifact_meta={"artifact_type": "windows_sam_identity", "name": "SAM", "source_path": "C:\\Windows\\System32\\config\\SAM", "parser": "windows_sam_identity"},
    )


def _parse_profile_list(monkeypatch: pytest.MonkeyPatch, tmp_path: Path, hive) -> object:
    fake_module = SimpleNamespace(Registry=lambda _: hive)
    monkeypatch.setattr("app.ingest.raw_parsers.profile_list_parser._load_registry_module", lambda: fake_module)
    path = tmp_path / "SOFTWARE"
    path.write_bytes(b"fake")
    parser = WindowsProfileListRawParser()
    return parser.parse(
        path, case_id=CASE_ID, evidence_id=EVIDENCE_ID, artifact_id="bbbbbbbb-5555-4555-8555-bbbbbbbbbbbb",
        artifact_meta={"artifact_type": "windows_profile_list", "name": "SOFTWARE", "source_path": "C:\\Windows\\System32\\config\\SOFTWARE", "parser": "windows_profile_list"},
    )


def _facts_by_username(result) -> dict[str, dict]:
    return {doc["host_user_fact"]["username"]: doc["host_user_fact"] for doc in result.events}


def _users_by_username(result) -> dict[str, dict]:
    return {doc["host_user_fact"]["username"]: doc["user"] for doc in result.events}


class TestSamExtraction:
    def test_real_shaped_hive_decodes_five_builtin_and_custom_accounts(self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
        # Mirrors the real ws01 SAM hive decoded during the sprint audit.
        result = _parse_sam(monkeypatch, tmp_path, _sam_hive(users={
            "Administrator": {"rid": 500, "flags": 0x0211, "comment": "Built-in account for administering the computer/domain"},
            "Guest": {"rid": 501, "flags": 0x0215},
            "DefaultAccount": {"rid": 503, "flags": 0x0215},
            "WDAGUtilityAccount": {"rid": 504, "flags": 0x0011},
            "bob": {"rid": 1001, "flags": 0x0214, "last_logon": datetime(2024, 3, 22, 10, 57, 33, tzinfo=timezone.utc), "logon_count": 8},
        }))
        assert result.parser_status == "parsed_native"
        facts = _facts_by_username(result)
        assert set(facts.keys()) == {"Administrator", "Guest", "DefaultAccount", "WDAGUtilityAccount", "bob"}
        assert facts["Administrator"]["account_status"] == "disabled"
        assert facts["Administrator"]["gecos"] == "Built-in account for administering the computer/domain"
        assert facts["bob"]["account_status"] == "active"
        assert facts["bob"]["uid"] == "1001"
        assert facts["bob"]["id_kind"] == "rid"
        assert facts["bob"]["last_login_at"] is not None
        assert facts["bob"]["attributes"]["logon_count"] == "8"
        assert facts["bob"]["attributes"]["sid"] == f"{MACHINE_SID}-1001"

    def test_account_username_and_sid_propagate_to_the_canonical_user_field(self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
        # Regression: base_document() derives user.name/user.sid from the raw
        # parser row, which is empty for this parser, so every SAM account
        # document rendered "-" in the User column (Search and Artifact
        # Views both read doc["user"]["name"]) even though the decoded
        # account name was already sitting in host_user_fact.username. The
        # canonical user.name/user.sid fields must carry it, not a new field.
        result = _parse_sam(monkeypatch, tmp_path, _sam_hive(users={
            "Administrator": {"rid": 500, "flags": 0x0211},
            "Guest": {"rid": 501, "flags": 0x0215},
            "DefaultAccount": {"rid": 503, "flags": 0x0215},
            "WDAGUtilityAccount": {"rid": 504, "flags": 0x0011},
            "bob": {"rid": 1001, "flags": 0x0214},
        }))
        users = _users_by_username(result)
        assert users["Administrator"]["name"] == "Administrator"
        assert users["Administrator"]["sid"] == f"{MACHINE_SID}-500"
        assert users["bob"]["name"] == "bob"
        assert users["bob"]["sid"] == f"{MACHINE_SID}-1001"
        for username in ("Guest", "DefaultAccount", "WDAGUtilityAccount"):
            assert users[username]["name"] == username
            assert users[username]["sid"], f"{username} missing sid"

    def test_locked_account_status(self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
        result = _parse_sam(monkeypatch, tmp_path, _sam_hive(users={"alice": {"rid": 1002, "flags": (1 << 10)}}))
        facts = _facts_by_username(result)
        assert facts["alice"]["account_status"] == "locked"

    def test_never_decodes_a_password_hash(self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
        result = _parse_sam(monkeypatch, tmp_path, _sam_hive(users={"bob": {"rid": 1001, "flags": 0x0210}}))
        fact = _facts_by_username(result)["bob"]
        assert "hash" not in fact
        assert "password" not in {k.lower() for k in fact.get("attributes", {})}

    def test_empty_names_key_produces_no_accounts_not_an_error(self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
        result = _parse_sam(monkeypatch, tmp_path, _sam_hive(users={}))
        assert result.parser_status == "parsed_empty"
        assert result.events == []


class TestSamRobustness:
    def test_hive_open_failure_fails_unsupported_not_a_crash(self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
        def _raise(_path):
            raise OSError("corrupt hive header")
        fake_module = SimpleNamespace(Registry=_raise)
        monkeypatch.setattr("app.ingest.raw_parsers.sam_identity_parser._load_registry_module", lambda: fake_module)
        path = tmp_path / "SAM"
        path.write_bytes(b"not a real hive")
        parser = WindowsSamIdentityRawParser()
        result = parser.parse(
            path, case_id=CASE_ID, evidence_id=EVIDENCE_ID, artifact_id="aaaaaaaa-4444-4444-8444-aaaaaaaaaaaa",
            artifact_meta={"artifact_type": "windows_sam_identity", "name": "SAM", "source_path": "C:\\Windows\\System32\\config\\SAM", "parser": "windows_sam_identity"},
        )
        assert result.parser_status == "failed_unsupported"
        assert result.events == []
        assert any("sam_hive_dependency_or_open_failed" in e for e in result.errors)

    def test_sam_key_missing_produces_no_accounts_with_warning(self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
        # A hive that opens fine but has no SAM\Domains\Account subtree at
        # all (e.g. the wrong hive was uploaded under this name).
        root = FakeKey("ROOT", subkeys=[])
        hive = SimpleNamespace(root=lambda: root)
        result = _parse_sam(monkeypatch, tmp_path, hive)
        assert result.parser_status == "parsed_empty"
        assert result.events == []
        assert any("sam_account_key_not_found" in w for w in result.warnings)

    def test_names_key_missing_produces_no_accounts_with_warning(self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
        users_key = FakeKey("Users", subkeys=[])  # no "Names" subkey
        account_key = FakeKey("Account", values=[FakeValue("V", _account_v_value())], subkeys=[users_key])
        domains_key = FakeKey("Domains", subkeys=[account_key])
        sam_key = FakeKey("SAM", subkeys=[domains_key])
        root = FakeKey("ROOT", subkeys=[sam_key])
        hive = SimpleNamespace(root=lambda: root)
        result = _parse_sam(monkeypatch, tmp_path, hive)
        assert result.parser_status == "parsed_empty"
        assert result.events == []
        assert any("sam_names_key_not_found" in w for w in result.warnings)

    def test_username_subkey_with_no_rid_value_is_skipped_not_fatal(self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
        name_subkey = FakeKey("orphan", values=[])  # no RID-carrying value at all
        good_name_subkey = FakeKey("bob", values=[FakeValue("", b"", value_type=1001)])
        f_val = FakeValue("F", _f_value(flags=0x0210))
        v_val = FakeValue("V", _v_value())
        user_subkey = FakeKey("000003E9", values=[f_val, v_val])
        names_key = FakeKey("Names", subkeys=[name_subkey, good_name_subkey])
        users_key = FakeKey("Users", subkeys=[names_key, user_subkey])
        account_key = FakeKey("Account", values=[FakeValue("V", _account_v_value())], subkeys=[users_key])
        domains_key = FakeKey("Domains", subkeys=[account_key])
        sam_key = FakeKey("SAM", subkeys=[domains_key])
        root = FakeKey("ROOT", subkeys=[sam_key])
        hive = SimpleNamespace(root=lambda: root)
        result = _parse_sam(monkeypatch, tmp_path, hive)
        # The orphan entry is skipped, but bob is still recovered --
        # one malformed account never discards the rest.
        facts = _facts_by_username(result)
        assert set(facts.keys()) == {"bob"}
        assert any("sam_name_entry_missing_rid_value" in w for w in result.warnings)

    def test_rid_with_no_matching_user_subkey_is_skipped_not_fatal(self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
        # Names\ghost claims RID 9999, but no Users\00002707 subkey exists
        # (a genuinely inconsistent/corrupt hive) -- alongside a real,
        # fully-formed bob account that must still come through.
        ghost_name_subkey = FakeKey("ghost", values=[FakeValue("", b"", value_type=9999)])
        bob_name_subkey = FakeKey("bob", values=[FakeValue("", b"", value_type=1001)])
        f_val = FakeValue("F", _f_value(flags=0x0210))
        v_val = FakeValue("V", _v_value())
        bob_user_subkey = FakeKey("000003E9", values=[f_val, v_val])
        names_key = FakeKey("Names", subkeys=[ghost_name_subkey, bob_name_subkey])
        users_key = FakeKey("Users", subkeys=[names_key, bob_user_subkey])  # no 0000270F subkey for "ghost"
        account_key = FakeKey("Account", values=[FakeValue("V", _account_v_value())], subkeys=[users_key])
        domains_key = FakeKey("Domains", subkeys=[account_key])
        sam_key = FakeKey("SAM", subkeys=[domains_key])
        root = FakeKey("ROOT", subkeys=[sam_key])
        hive = SimpleNamespace(root=lambda: root)
        result = _parse_sam(monkeypatch, tmp_path, hive)
        facts = _facts_by_username(result)
        assert set(facts.keys()) == {"bob"}
        assert any("sam_user_key_not_found" in w for w in result.warnings)

    def test_truncated_f_value_skips_account_status_but_keeps_the_account(self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
        f_val = FakeValue("F", b"\x00\x00\x00\x00")  # far too short to read any field from
        v_val = FakeValue("V", _v_value(full_name="Still Decodable"))
        user_subkey = FakeKey("000003E9", values=[f_val, v_val])
        name_subkey = FakeKey("bob", values=[FakeValue("", b"", value_type=1001)])
        names_key = FakeKey("Names", subkeys=[name_subkey])
        users_key = FakeKey("Users", subkeys=[names_key, user_subkey])
        account_key = FakeKey("Account", values=[FakeValue("V", _account_v_value())], subkeys=[users_key])
        domains_key = FakeKey("Domains", subkeys=[account_key])
        sam_key = FakeKey("SAM", subkeys=[domains_key])
        root = FakeKey("ROOT", subkeys=[sam_key])
        hive = SimpleNamespace(root=lambda: root)
        result = _parse_sam(monkeypatch, tmp_path, hive)
        facts = _facts_by_username(result)
        assert "bob" in facts
        assert facts["bob"]["account_status"] is None  # honestly missing, never guessed
        assert facts["bob"]["gecos"] == "Still Decodable"  # V still decoded independently

    def test_truncated_v_value_skips_name_fields_but_keeps_the_account(self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
        f_val = FakeValue("F", _f_value(flags=0x0210))
        v_val = FakeValue("V", b"\x00\x00")  # far too short
        user_subkey = FakeKey("000003E9", values=[f_val, v_val])
        name_subkey = FakeKey("bob", values=[FakeValue("", b"", value_type=1001)])
        names_key = FakeKey("Names", subkeys=[name_subkey])
        users_key = FakeKey("Users", subkeys=[names_key, user_subkey])
        account_key = FakeKey("Account", values=[FakeValue("V", _account_v_value())], subkeys=[users_key])
        domains_key = FakeKey("Domains", subkeys=[account_key])
        sam_key = FakeKey("SAM", subkeys=[domains_key])
        root = FakeKey("ROOT", subkeys=[sam_key])
        hive = SimpleNamespace(root=lambda: root)
        result = _parse_sam(monkeypatch, tmp_path, hive)
        facts = _facts_by_username(result)
        assert "bob" in facts
        assert facts["bob"]["gecos"] is None  # honestly missing, never guessed
        assert facts["bob"]["account_status"] == "active"  # F still decoded independently

    def test_duplicate_rid_across_two_usernames_keeps_both_as_separate_observations(self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
        # Two Names entries both claiming RID 1001 -- a genuinely
        # inconsistent hive (or a deliberately tampered one). Both must
        # surface as independent observations; neither silently wins.
        f_val = FakeValue("F", _f_value(flags=0x0210))
        v_val = FakeValue("V", _v_value())
        user_subkey = FakeKey("000003E9", values=[f_val, v_val])
        name_subkey_1 = FakeKey("bob", values=[FakeValue("", b"", value_type=1001)])
        name_subkey_2 = FakeKey("bob2", values=[FakeValue("", b"", value_type=1001)])
        names_key = FakeKey("Names", subkeys=[name_subkey_1, name_subkey_2])
        users_key = FakeKey("Users", subkeys=[names_key, user_subkey])
        account_key = FakeKey("Account", values=[FakeValue("V", _account_v_value())], subkeys=[users_key])
        domains_key = FakeKey("Domains", subkeys=[account_key])
        sam_key = FakeKey("SAM", subkeys=[domains_key])
        root = FakeKey("ROOT", subkeys=[sam_key])
        hive = SimpleNamespace(root=lambda: root)
        result = _parse_sam(monkeypatch, tmp_path, hive)
        facts = _facts_by_username(result)
        assert set(facts.keys()) == {"bob", "bob2"}
        assert facts["bob"]["uid"] == facts["bob2"]["uid"] == "1001"


class TestProfileListExtraction:
    def test_extracts_profile_paths_keyed_by_sid(self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
        result = _parse_profile_list(monkeypatch, tmp_path, _software_hive(profiles={
            f"{MACHINE_SID}-1001": (r"C:\Users\bob", 0),
            "S-1-5-21-2346594845-3239972734-3293769256-1603": (r"C:\Users\mshutter", 0),
        }))
        assert result.parser_status == "parsed_native"
        by_sid = {doc["host_user_fact"]["attributes"]["sid"]: doc["host_user_fact"] for doc in result.events}
        assert by_sid[f"{MACHINE_SID}-1001"]["home"] == r"C:\Users\bob"
        # ProfileList never sets a username -- that only happens at
        # resolution time, and only for a SID that matches a SAM account.
        assert all(doc["host_user_fact"]["username"] is None for doc in result.events)

    def test_service_sids_are_never_surfaced(self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
        result = _parse_profile_list(monkeypatch, tmp_path, _software_hive(profiles={
            "S-1-5-18": (r"C:\Windows\system32\config\systemprofile", 0),
            f"{MACHINE_SID}-1001": (r"C:\Users\bob", 0),
        }))
        sids = {doc["host_user_fact"]["attributes"]["sid"] for doc in result.events}
        assert "S-1-5-18" not in sids


class TestSamDispatcherIntegration:
    def test_sam_documents_flow_through_the_generic_dispatcher_unchanged(self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
        result = _parse_sam(monkeypatch, tmp_path, _sam_hive(users={"bob": {"rid": 1001, "flags": 0x0210}}))
        dispatched = extract_host_user_documents(result.events)
        assert {doc["host_user_fact"]["username"] for doc in dispatched} == {"bob"}


class TestEndToEndPersistenceAndResolution:
    def test_sam_account_becomes_a_resolved_local_account_entry(self, db_session=None) -> None:
        db = _db()
        _case(db)
        _evidence(db)
        docs = [{
            "host_user_fact": {
                "source_kind": "sam_account", "username": "bob", "uid": "1001", "id_kind": "rid",
                "account_status": "active", "attributes": {"rid": "1001", "sid": f"{MACHINE_SID}-1001"},
                "parser": "windows_sam_identity", "source_file": "C:\\Windows\\System32\\config\\SAM",
            },
        }]
        create_host_user_fact_observations(db, case_id=CASE_ID, evidence_id=EVIDENCE_ID, artifact_id="aaaaaaaa-4444-4444-8444-aaaaaaaaaaaa", host_id=HOST_ID, observed_at=None, documents=docs)
        entries = {e["username"]: e for e in resolve_host_users(db, case_id=CASE_ID, host_id=HOST_ID)}
        assert "bob" in entries
        assert entries["bob"]["identity"]["uid"]["preferred_value"] == "1001"
        assert entries["bob"]["identity"]["id_kind"]["preferred_value"] == "rid"
        assert entries["bob"]["account_status"]["preferred_value"] == "active"
        assert entries["bob"]["attributes"]["rid"]["preferred_value"] == "1001"

    def test_profile_list_matching_machine_sid_attaches_as_home(self) -> None:
        db = _db()
        _case(db)
        _evidence(db)
        sam_doc = {"host_user_fact": {
            "source_kind": "sam_account", "username": "bob", "uid": "1001", "id_kind": "rid",
            "account_status": "active", "attributes": {"rid": "1001", "sid": f"{MACHINE_SID}-1001"},
            "parser": "windows_sam_identity", "source_file": "SAM",
        }}
        profile_doc = {"host_user_fact": {
            "source_kind": "profile_list", "username": None, "home": r"C:\Users\bob",
            "attributes": {"sid": f"{MACHINE_SID}-1001"}, "parser": "windows_profile_list", "source_file": "SOFTWARE",
        }}
        create_host_user_fact_observations(db, case_id=CASE_ID, evidence_id=EVIDENCE_ID, artifact_id="aaaaaaaa-4444-4444-8444-aaaaaaaaaaaa", host_id=HOST_ID, observed_at=None, documents=[sam_doc])
        create_host_user_fact_observations(db, case_id=CASE_ID, evidence_id=EVIDENCE_ID, artifact_id="bbbbbbbb-5555-4555-8555-bbbbbbbbbbbb", host_id=HOST_ID, observed_at=None, documents=[profile_doc])
        entries = {e["username"]: e for e in resolve_host_users(db, case_id=CASE_ID, host_id=HOST_ID)}
        assert entries["bob"]["identity"]["home"]["preferred_value"] == r"C:\Users\bob"

    def test_profile_list_with_mismatched_authority_never_creates_or_enriches_an_account(self) -> None:
        # The exact real-world scenario found during the sprint audit: a
        # ProfileList SID from a DIFFERENT domain authority than this
        # machine's own SAM SID must never be treated as a local account,
        # nor attach to one.
        db = _db()
        _case(db)
        _evidence(db)
        sam_doc = {"host_user_fact": {
            "source_kind": "sam_account", "username": "bob", "uid": "1001", "id_kind": "rid",
            "account_status": "active", "attributes": {"rid": "1001", "sid": f"{MACHINE_SID}-1001"},
            "parser": "windows_sam_identity", "source_file": "SAM",
        }}
        domain_profile_doc = {"host_user_fact": {
            "source_kind": "profile_list", "username": None, "home": r"C:\Users\mshutter",
            "attributes": {"sid": "S-1-5-21-2346594845-3239972734-3293769256-1603"},
            "parser": "windows_profile_list", "source_file": "SOFTWARE",
        }}
        create_host_user_fact_observations(db, case_id=CASE_ID, evidence_id=EVIDENCE_ID, artifact_id="aaaaaaaa-4444-4444-8444-aaaaaaaaaaaa", host_id=HOST_ID, observed_at=None, documents=[sam_doc])
        create_host_user_fact_observations(db, case_id=CASE_ID, evidence_id=EVIDENCE_ID, artifact_id="bbbbbbbb-5555-4555-8555-bbbbbbbbbbbb", host_id=HOST_ID, observed_at=None, documents=[domain_profile_doc])
        entries = {e["username"]: e for e in resolve_host_users(db, case_id=CASE_ID, host_id=HOST_ID)}
        assert set(entries.keys()) == {"bob"}  # "mshutter" is never invented
        assert entries["bob"]["identity"]["home"]["status"] == "missing"  # never enriched by the mismatched profile

    def test_orphan_profile_with_no_matching_sam_account_never_appears(self) -> None:
        # A ProfileList entry whose SID matches no SAM account at all
        # (this machine's own authority or otherwise) -- must never
        # surface as a Local Account, orphaned or synthetic.
        db = _db()
        _case(db)
        _evidence(db)
        orphan_profile_doc = {"host_user_fact": {
            "source_kind": "profile_list", "username": None, "home": r"C:\Users\ghost",
            "attributes": {"sid": f"{MACHINE_SID}-9999"},
            "parser": "windows_profile_list", "source_file": "SOFTWARE",
        }}
        create_host_user_fact_observations(db, case_id=CASE_ID, evidence_id=EVIDENCE_ID, artifact_id="bbbbbbbb-5555-4555-8555-bbbbbbbbbbbb", host_id=HOST_ID, observed_at=None, documents=[orphan_profile_doc])
        entries = resolve_host_users(db, case_id=CASE_ID, host_id=HOST_ID)
        assert entries == []  # never invents "ghost" as a local account

    def test_profile_list_never_derives_username_from_the_path(self) -> None:
        # Even when SAM and ProfileList agree on the SID, the resolved
        # username must come only from SAM's own Names entry -- never
        # parsed out of "C:\Users\<name>".
        db = _db()
        _case(db)
        _evidence(db)
        sam_doc = {"host_user_fact": {
            "source_kind": "sam_account", "username": "bob", "uid": "1001", "id_kind": "rid",
            "account_status": "active", "attributes": {"rid": "1001", "sid": f"{MACHINE_SID}-1001"},
            "parser": "windows_sam_identity", "source_file": "SAM",
        }}
        # Deliberately mismatched trailing path component vs. the real
        # SAM username, to prove the path text is never used as identity.
        profile_doc = {"host_user_fact": {
            "source_kind": "profile_list", "username": None, "home": r"C:\Users\completely_different_name",
            "attributes": {"sid": f"{MACHINE_SID}-1001"},
            "parser": "windows_profile_list", "source_file": "SOFTWARE",
        }}
        create_host_user_fact_observations(db, case_id=CASE_ID, evidence_id=EVIDENCE_ID, artifact_id="aaaaaaaa-4444-4444-8444-aaaaaaaaaaaa", host_id=HOST_ID, observed_at=None, documents=[sam_doc])
        create_host_user_fact_observations(db, case_id=CASE_ID, evidence_id=EVIDENCE_ID, artifact_id="bbbbbbbb-5555-4555-8555-bbbbbbbbbbbb", host_id=HOST_ID, observed_at=None, documents=[profile_doc])
        entries = {e["username"]: e for e in resolve_host_users(db, case_id=CASE_ID, host_id=HOST_ID)}
        assert set(entries.keys()) == {"bob"}  # never "completely_different_name"
        assert entries["bob"]["identity"]["home"]["preferred_value"] == r"C:\Users\completely_different_name"

    def test_sid_matching_is_exact_case_sensitive_never_loosened(self) -> None:
        # Real Windows registry SID subkey names are always canonical
        # (leading "S", decimal fields) -- SID correlation intentionally
        # requires an exact string match rather than case-folding, so a
        # genuinely different-looking SID string is never speculatively
        # treated as "close enough" to match.
        db = _db()
        _case(db)
        _evidence(db)
        sam_doc = {"host_user_fact": {
            "source_kind": "sam_account", "username": "bob", "uid": "1001", "id_kind": "rid",
            "account_status": "active", "attributes": {"rid": "1001", "sid": f"{MACHINE_SID}-1001"},
            "parser": "windows_sam_identity", "source_file": "SAM",
        }}
        lowercase_profile_doc = {"host_user_fact": {
            "source_kind": "profile_list", "username": None, "home": r"C:\Users\bob",
            "attributes": {"sid": f"{MACHINE_SID}-1001".lower()},
            "parser": "windows_profile_list", "source_file": "SOFTWARE",
        }}
        create_host_user_fact_observations(db, case_id=CASE_ID, evidence_id=EVIDENCE_ID, artifact_id="aaaaaaaa-4444-4444-8444-aaaaaaaaaaaa", host_id=HOST_ID, observed_at=None, documents=[sam_doc])
        create_host_user_fact_observations(db, case_id=CASE_ID, evidence_id=EVIDENCE_ID, artifact_id="bbbbbbbb-5555-4555-8555-bbbbbbbbbbbb", host_id=HOST_ID, observed_at=None, documents=[lowercase_profile_doc])
        entries = {e["username"]: e for e in resolve_host_users(db, case_id=CASE_ID, host_id=HOST_ID)}
        assert set(entries.keys()) == {"bob"}
        # Exact-match contract: a differently-cased SID string does not
        # correlate -- home stays missing rather than guessed via a loose match.
        assert entries["bob"]["identity"]["home"]["status"] == "missing"

    def test_idempotent_across_repeated_ingest(self) -> None:
        db = _db()
        _case(db)
        _evidence(db)
        docs = [{"host_user_fact": {
            "source_kind": "sam_account", "username": "bob", "uid": "1001", "id_kind": "rid",
            "account_status": "active", "attributes": {"rid": "1001"},
            "parser": "windows_sam_identity", "source_file": "SAM",
        }}]
        create_host_user_fact_observations(db, case_id=CASE_ID, evidence_id=EVIDENCE_ID, artifact_id="aaaaaaaa-4444-4444-8444-aaaaaaaaaaaa", host_id=HOST_ID, observed_at=None, documents=docs)
        first = db.query(HostUserFact).count()
        create_host_user_fact_observations(db, case_id=CASE_ID, evidence_id=EVIDENCE_ID, artifact_id="aaaaaaaa-4444-4444-8444-aaaaaaaaaaaa", host_id=HOST_ID, observed_at=None, documents=docs)
        second = db.query(HostUserFact).count()
        assert first == second == 1

    def test_two_hosts_never_mix_sam_accounts(self) -> None:
        db = _db()
        _case(db)
        other_evidence_id = "aeaeaeae-3333-4333-8333-aeaeaeaeaeae"
        other_host_id = "bfbfbfbf-3333-4333-8333-bfbfbfbfbfbf"
        _evidence(db, evidence_id=EVIDENCE_ID, host_id=HOST_ID)
        _evidence(db, evidence_id=other_evidence_id, host_id=other_host_id)
        doc_a = [{"host_user_fact": {"source_kind": "sam_account", "username": "bob", "uid": "1001", "id_kind": "rid", "attributes": {}, "parser": "windows_sam_identity", "source_file": "SAM"}}]
        doc_b = [{"host_user_fact": {"source_kind": "sam_account", "username": "carol", "uid": "1002", "id_kind": "rid", "attributes": {}, "parser": "windows_sam_identity", "source_file": "SAM"}}]
        create_host_user_fact_observations(db, case_id=CASE_ID, evidence_id=EVIDENCE_ID, artifact_id="cccccccc-6666-4666-8666-cccccccccccc", host_id=HOST_ID, observed_at=None, documents=doc_a)
        create_host_user_fact_observations(db, case_id=CASE_ID, evidence_id=other_evidence_id, artifact_id="dddddddd-7777-4777-8777-dddddddddddd", host_id=other_host_id, observed_at=None, documents=doc_b)
        entries_a = {e["username"] for e in resolve_host_users(db, case_id=CASE_ID, host_id=HOST_ID)}
        entries_b = {e["username"] for e in resolve_host_users(db, case_id=CASE_ID, host_id=other_host_id)}
        assert entries_a == {"bob"}
        assert entries_b == {"carol"}


class TestUnverifiedHostProfiles:
    """resolve_unverified_host_profiles() -- deliberately separate from
    resolve_host_users()/"Users": exposes ProfileList SIDs with no matching
    SAM account (e.g. a domain account's cached profile from an
    interactive logon) without ever implying local-account membership.
    """

    def test_orphan_profile_surfaces_here_but_never_in_host_users(self) -> None:
        db = _db()
        _case(db)
        _evidence(db)
        domain_profile_doc = {"host_user_fact": {
            "source_kind": "profile_list", "username": None, "home": r"C:\Users\mshunter",
            "attributes": {"sid": "S-1-5-21-9999999999-8888888888-7777777777-1105"},
            "parser": "windows_profile_list", "source_file": "SOFTWARE",
        }}
        create_host_user_fact_observations(db, case_id=CASE_ID, evidence_id=EVIDENCE_ID, artifact_id="bbbbbbbb-5555-4555-8555-bbbbbbbbbbbb", host_id=HOST_ID, observed_at=None, documents=[domain_profile_doc])

        profiles = resolve_unverified_host_profiles(db, case_id=CASE_ID, host_id=HOST_ID)
        assert len(profiles) == 1
        assert profiles[0]["label"] == "mshunter"
        assert profiles[0]["sid"] == "S-1-5-21-9999999999-8888888888-7777777777-1105"
        assert profiles[0]["home"]["preferred_value"] == r"C:\Users\mshunter"

        # Same fixtures, the audited-contract endpoint: must stay untouched.
        assert resolve_host_users(db, case_id=CASE_ID, host_id=HOST_ID) == []

    def test_profile_matching_a_sam_account_is_excluded_here(self) -> None:
        db = _db()
        _case(db)
        _evidence(db)
        sam_doc = {"host_user_fact": {
            "source_kind": "sam_account", "username": "bob", "uid": "1001", "id_kind": "rid",
            "account_status": "active", "attributes": {"rid": "1001", "sid": f"{MACHINE_SID}-1001"},
            "parser": "windows_sam_identity", "source_file": "SAM",
        }}
        matching_profile_doc = {"host_user_fact": {
            "source_kind": "profile_list", "username": None, "home": r"C:\Users\bob",
            "attributes": {"sid": f"{MACHINE_SID}-1001"}, "parser": "windows_profile_list", "source_file": "SOFTWARE",
        }}
        create_host_user_fact_observations(db, case_id=CASE_ID, evidence_id=EVIDENCE_ID, artifact_id="aaaaaaaa-4444-4444-8444-aaaaaaaaaaaa", host_id=HOST_ID, observed_at=None, documents=[sam_doc])
        create_host_user_fact_observations(db, case_id=CASE_ID, evidence_id=EVIDENCE_ID, artifact_id="bbbbbbbb-5555-4555-8555-bbbbbbbbbbbb", host_id=HOST_ID, observed_at=None, documents=[matching_profile_doc])

        assert resolve_unverified_host_profiles(db, case_id=CASE_ID, host_id=HOST_ID) == []

    def test_two_unclaimed_sids_produce_two_distinct_entries(self) -> None:
        db = _db()
        _case(db)
        _evidence(db)
        docs = [
            {"host_user_fact": {"source_kind": "profile_list", "username": None, "home": r"C:\Users\mshunter", "attributes": {"sid": "S-1-5-21-1-1-1-1105"}, "parser": "windows_profile_list", "source_file": "SOFTWARE"}},
            {"host_user_fact": {"source_kind": "profile_list", "username": None, "home": r"C:\Users\jdoe", "attributes": {"sid": "S-1-5-21-1-1-1-1106"}, "parser": "windows_profile_list", "source_file": "SOFTWARE"}},
        ]
        create_host_user_fact_observations(db, case_id=CASE_ID, evidence_id=EVIDENCE_ID, artifact_id="bbbbbbbb-5555-4555-8555-bbbbbbbbbbbb", host_id=HOST_ID, observed_at=None, documents=docs)

        labels = {item["label"] for item in resolve_unverified_host_profiles(db, case_id=CASE_ID, host_id=HOST_ID)}
        assert labels == {"mshunter", "jdoe"}
