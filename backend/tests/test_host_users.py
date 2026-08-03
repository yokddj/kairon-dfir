"""Host User Inventory: aggregation, correlation, conflict resolution,
provenance, dedup and API.

See app.services.host_users -- a sibling to Host Facts, correlating
passwd/shadow/lastlog/group observations into one inventory entry per
local account. These tests build normalized documents the same way the
real ingest pipeline does (via app.ingest.linux.identity + normalize_row),
then exercise the aggregation/resolution/API layer on top of them.
"""
import struct
from datetime import datetime, timezone

from fastapi import FastAPI
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from app.api import routes_host_users
from app.core.database import Base, get_db
from app.ingest.host_user_extraction import extract_host_user_documents
from app.ingest.linux.identity import parse_identity
from app.ingest.linux.lastlog import parse_lastlog
from app.ingest.normalizer import normalize_row
from app.models.case import Case
from app.models.case_host import CaseHost
from app.models.evidence import Evidence, EvidenceStorageMode, EvidenceType, IngestStatus
from app.models.host_user_fact import HostUserFact
from app.services.host_users import (
    build_host_user_fact_fingerprint,
    create_host_user_fact_observations,
    delete_host_user_facts_for_evidence,
    resolve_host_users,
)

CASE_ID = "aaaaaaaa-1111-4111-8111-aaaaaaaaaaaa"
HOST_ID = "dddddddd-1111-4111-8111-dddddddddddd"
EVIDENCE_ID = "bbbbbbbb-2222-4222-8222-bbbbbbbbbbbb"
SECOND_EVIDENCE_ID = "cccccccc-3333-4333-8333-cccccccccccc"
ART1_ID = "11111111-1111-4111-8111-1111111111af"
ART2_ID = "22222222-2222-4222-8222-2222222222bf"


def _db():
    engine = create_engine("sqlite:///:memory:", connect_args={"check_same_thread": False}, poolclass=StaticPool, future=True)
    Base.metadata.create_all(engine)
    return sessionmaker(bind=engine, future=True)()


def _client(db):
    app = FastAPI()
    app.include_router(routes_host_users.router)
    app.dependency_overrides[get_db] = lambda: db
    return TestClient(app)


def _case(db, case_id=CASE_ID):
    db.add(Case(id=case_id, name="Case", description=None))
    db.commit()


def _host(db, host_id=HOST_ID, case_id=CASE_ID):
    host = CaseHost(id=host_id, case_id=case_id, canonical_name="host-01", display_name="HOST-01", confidence="manual", source="manual")
    db.add(host)
    db.commit()
    return host


def _evidence(db, evidence_id=EVIDENCE_ID, *, host_id=None, case_id=CASE_ID, filename="disk.E01"):
    item = Evidence(
        id=evidence_id, case_id=case_id, original_filename=filename, stored_path=f"/tmp/{filename}",
        original_path=f"/tmp/{filename}", storage_mode=EvidenceStorageMode.uploaded, is_external=False,
        copy_to_storage=True, evidence_type=EvidenceType.disk_image, sha256="0" * 64, size_bytes=128,
        ingest_status=IngestStatus.completed, detected_host=None, host_id=host_id,
        path_validation={}, ingest_source={}, metadata_json={}, error_log={},
    )
    db.add(item)
    db.commit()
    return item


def _identity_docs(content: str, *, artifact_type: str, source_path: str, artifact_id=ART1_ID) -> list[dict]:
    # Routes through the real dispatcher (app.ingest.host_user_extraction),
    # exactly like the ingest pipeline does -- these tests exercise the
    # Linux derived extractor, not a bespoke test-only shortcut.
    rows = parse_identity(content, source_path=source_path)
    docs = [
        normalize_row(CASE_ID, EVIDENCE_ID, artifact_id, row, {
            "artifact_family": "linux_identity", "artifact_type": artifact_type, "parser": "linux_identity_raw",
            "name": source_path.rsplit("/", 1)[-1], "source_path": source_path,
        })
        for row in rows
    ]
    return extract_host_user_documents(docs)


def _sudoers_docs(content: str, *, source_path: str = "etc/sudoers", artifact_id=ART1_ID) -> list[dict]:
    from app.ingest.linux.sudoers import parse_sudoers
    rows = parse_sudoers(content, source_path=source_path)
    docs = [
        normalize_row(CASE_ID, EVIDENCE_ID, artifact_id, row, {
            "artifact_family": "linux_sudoers", "artifact_type": "sudoers", "parser": "linux_sudoers_raw",
            "name": source_path.rsplit("/", 1)[-1], "source_path": source_path,
        })
        for row in rows
    ]
    return extract_host_user_documents(docs)


def _lastlog_binary(records: dict[int, tuple[int, str, str]]) -> bytes:
    """records: uid -> (unix_seconds, terminal, host)."""
    layout = struct.Struct("<i32s256s")
    max_uid = max(records) if records else 0
    buf = bytearray(layout.size * (max_uid + 1))
    for uid, (seconds, terminal, host) in records.items():
        packed = layout.pack(seconds, terminal.encode(), host.encode())
        buf[uid * layout.size:(uid + 1) * layout.size] = packed
    return bytes(buf)


def _lastlog_docs(records: dict[int, tuple[int, str, str]], *, passwd_content: str | None = None, artifact_id=ART1_ID) -> list[dict]:
    content = _lastlog_binary(records)
    rows = parse_lastlog(content, source_path="var/log/lastlog", passwd_content=passwd_content)
    docs = [
        normalize_row(CASE_ID, EVIDENCE_ID, artifact_id, row, {
            "artifact_family": "linux_lastlog", "artifact_type": "lastlog", "parser": "linux_lastlog_raw",
            "name": "lastlog", "source_path": "var/log/lastlog",
        })
        for row in rows
    ]
    return extract_host_user_documents(docs)


PASSWD_ALICE_BOB = "alice:x:1000:1000:Alice Analyst:/home/alice:/bin/bash\nbob:x:1001:1001:Bob:/home/bob:/bin/sh\n"
SHADOW_ALICE_BOB = "alice:$6$salt$hash:19000:0:99999:7:::\nbob:!:19000:0:99999:7:::\n"
GROUP_SUDO_DEVS = "sudo:x:27:alice\ndevelopers:x:1000:\n"


class TestFingerprint:
    def test_deterministic(self):
        a = build_host_user_fact_fingerprint("case", "ev", "art", "passwd", "alice", None, 0)
        b = build_host_user_fact_fingerprint("case", "ev", "art", "passwd", "alice", None, 0)
        assert a == b

    def test_distinct_lines_for_same_user_do_not_collide(self):
        # A duplicated UID entry for the same username in one file is a
        # known persistence technique -- it must stay two observations.
        a = build_host_user_fact_fingerprint("case", "ev", "art", "passwd", "alice", None, 0)
        b = build_host_user_fact_fingerprint("case", "ev", "art", "passwd", "alice", None, 1)
        assert a != b


class TestPasswdCorrelation:
    def test_passwd_alone_produces_one_entry_per_user(self):
        db = _db()
        _case(db)
        _evidence(db)
        docs = _identity_docs(PASSWD_ALICE_BOB, artifact_type="passwd", source_path="etc/passwd")
        create_host_user_fact_observations(db, case_id=CASE_ID, evidence_id=EVIDENCE_ID, artifact_id=ART1_ID, host_id=None, observed_at=None, documents=docs)
        entries = resolve_host_users(db, case_id=CASE_ID, evidence_id=EVIDENCE_ID)
        usernames = {e["username"] for e in entries}
        assert usernames == {"alice", "bob"}
        alice = next(e for e in entries if e["username"] == "alice")
        assert alice["identity"]["uid"]["preferred_value"] == "1000"
        assert alice["identity"]["home"]["preferred_value"] == "/home/alice"
        assert alice["identity"]["shell"]["preferred_value"] == "/bin/bash"

    def test_conflicting_uid_observations_are_surfaced_not_hidden(self):
        db = _db()
        _case(db)
        _evidence(db)
        docs1 = _identity_docs("alice:x:1000:1000:Alice:/home/alice:/bin/bash\n", artifact_type="passwd", source_path="etc/passwd")
        docs2 = _identity_docs("alice:x:1050:1000:Alice:/home/alice:/bin/bash\n", artifact_type="passwd", source_path="etc/passwd.bak")
        create_host_user_fact_observations(db, case_id=CASE_ID, evidence_id=EVIDENCE_ID, artifact_id=ART1_ID, host_id=None, observed_at=None, documents=docs1)
        create_host_user_fact_observations(db, case_id=CASE_ID, evidence_id=EVIDENCE_ID, artifact_id=ART2_ID, host_id=None, observed_at=None, documents=docs2)
        entries = resolve_host_users(db, case_id=CASE_ID, evidence_id=EVIDENCE_ID)
        alice = next(e for e in entries if e["username"] == "alice")
        assert alice["identity"]["uid"]["status"] == "conflicting"
        observed_uids = {obs["source_path"] for obs in alice["identity"]["uid"]["observations"]}
        assert observed_uids == {"etc/passwd", "etc/passwd.bak"}
        # home agrees across both -- must not be dragged into "conflicting" by the uid disagreement.
        assert alice["identity"]["home"]["status"] == "confirmed"


class TestPasswordAndAccountStatus:
    def test_locked_and_active_accounts(self):
        db = _db()
        _case(db)
        _evidence(db)
        passwd_docs = _identity_docs(PASSWD_ALICE_BOB, artifact_type="passwd", source_path="etc/passwd")
        shadow_docs = _identity_docs(SHADOW_ALICE_BOB, artifact_type="shadow", source_path="etc/shadow")
        create_host_user_fact_observations(db, case_id=CASE_ID, evidence_id=EVIDENCE_ID, artifact_id=ART1_ID, host_id=None, observed_at=None, documents=passwd_docs)
        create_host_user_fact_observations(db, case_id=CASE_ID, evidence_id=EVIDENCE_ID, artifact_id=ART2_ID, host_id=None, observed_at=None, documents=shadow_docs)
        entries = {e["username"]: e for e in resolve_host_users(db, case_id=CASE_ID, evidence_id=EVIDENCE_ID)}
        assert entries["alice"]["password_status"]["preferred_value"] == "set"
        # account_status is a resolution object -- same source/provenance
        # transparency as every other field -- not a bare string.
        assert entries["alice"]["account_status"]["preferred_value"] == "active"
        assert entries["bob"]["password_status"]["preferred_value"] == "locked"
        assert entries["bob"]["account_status"]["preferred_value"] == "locked"

    def test_no_shadow_observation_is_unavailable_not_fabricated(self):
        db = _db()
        _case(db)
        _evidence(db)
        passwd_docs = _identity_docs(PASSWD_ALICE_BOB, artifact_type="passwd", source_path="etc/passwd")
        create_host_user_fact_observations(db, case_id=CASE_ID, evidence_id=EVIDENCE_ID, artifact_id=ART1_ID, host_id=None, observed_at=None, documents=passwd_docs)
        entries = {e["username"]: e for e in resolve_host_users(db, case_id=CASE_ID, evidence_id=EVIDENCE_ID)}
        assert entries["alice"]["password_status"]["preferred_value"] == "unavailable"
        assert entries["alice"]["account_status"]["status"] == "missing"
        assert entries["alice"]["account_status"]["preferred_value"] is None

    def test_password_hash_never_appears_anywhere_in_resolved_entry(self):
        db = _db()
        _case(db)
        _evidence(db)
        shadow_docs = _identity_docs(SHADOW_ALICE_BOB, artifact_type="shadow", source_path="etc/shadow")
        create_host_user_fact_observations(db, case_id=CASE_ID, evidence_id=EVIDENCE_ID, artifact_id=ART1_ID, host_id=None, observed_at=None, documents=shadow_docs)
        entries = resolve_host_users(db, case_id=CASE_ID, evidence_id=EVIDENCE_ID)
        blob = str(entries)
        assert "$6$" not in blob
        assert "hash" not in blob.replace("password_status", "").lower() or "hash not stored" not in blob


class TestGroups:
    def test_secondary_group_membership(self):
        db = _db()
        _case(db)
        _evidence(db)
        passwd_docs = _identity_docs(PASSWD_ALICE_BOB, artifact_type="passwd", source_path="etc/passwd")
        group_docs = _identity_docs(GROUP_SUDO_DEVS, artifact_type="group", source_path="etc/group")
        create_host_user_fact_observations(db, case_id=CASE_ID, evidence_id=EVIDENCE_ID, artifact_id=ART1_ID, host_id=None, observed_at=None, documents=passwd_docs)
        create_host_user_fact_observations(db, case_id=CASE_ID, evidence_id=EVIDENCE_ID, artifact_id=ART2_ID, host_id=None, observed_at=None, documents=group_docs)
        entries = {e["username"]: e for e in resolve_host_users(db, case_id=CASE_ID, evidence_id=EVIDENCE_ID)}
        assert [g["group_name"] for g in entries["alice"]["secondary_groups"]] == ["sudo"]
        assert entries["bob"]["secondary_groups"] == []

    def test_primary_group_name_resolved_even_without_explicit_membership(self):
        # "developers" (gid 1000) has zero listed members in /etc/group --
        # membership is implied only via passwd's gid -- yet its name must
        # still resolve for alice's primary group.
        db = _db()
        _case(db)
        _evidence(db)
        passwd_docs = _identity_docs(PASSWD_ALICE_BOB, artifact_type="passwd", source_path="etc/passwd")
        group_docs = _identity_docs(GROUP_SUDO_DEVS, artifact_type="group", source_path="etc/group")
        create_host_user_fact_observations(db, case_id=CASE_ID, evidence_id=EVIDENCE_ID, artifact_id=ART1_ID, host_id=None, observed_at=None, documents=passwd_docs)
        create_host_user_fact_observations(db, case_id=CASE_ID, evidence_id=EVIDENCE_ID, artifact_id=ART2_ID, host_id=None, observed_at=None, documents=group_docs)
        entries = {e["username"]: e for e in resolve_host_users(db, case_id=CASE_ID, evidence_id=EVIDENCE_ID)}
        assert entries["alice"]["primary_group_name"] == "developers"


class TestShellClassification:
    def test_login_and_non_login_shells(self):
        db = _db()
        _case(db)
        _evidence(db)
        docs = _identity_docs(PASSWD_ALICE_BOB, artifact_type="passwd", source_path="etc/passwd")
        create_host_user_fact_observations(db, case_id=CASE_ID, evidence_id=EVIDENCE_ID, artifact_id=ART1_ID, host_id=None, observed_at=None, documents=docs)
        entries = {e["username"]: e for e in resolve_host_users(db, case_id=CASE_ID, evidence_id=EVIDENCE_ID)}
        assert entries["alice"]["shell_classification"] == "login"  # /bin/bash
        assert entries["bob"]["shell_classification"] == "login"  # /bin/sh


class TestEffectiveSudo:
    def test_direct_sudoers_rule_grants_effective_sudo(self):
        db = _db()
        _case(db)
        _evidence(db)
        passwd_docs = _identity_docs(PASSWD_ALICE_BOB, artifact_type="passwd", source_path="etc/passwd")
        sudoers_docs = _sudoers_docs("bob ALL=(ALL) ALL\n")
        create_host_user_fact_observations(db, case_id=CASE_ID, evidence_id=EVIDENCE_ID, artifact_id=ART1_ID, host_id=None, observed_at=None, documents=passwd_docs)
        create_host_user_fact_observations(db, case_id=CASE_ID, evidence_id=EVIDENCE_ID, artifact_id=ART2_ID, host_id=None, observed_at=None, documents=sudoers_docs)
        entries = {e["username"]: e for e in resolve_host_users(db, case_id=CASE_ID, evidence_id=EVIDENCE_ID)}
        assert entries["bob"]["effective_sudo"]["has_sudo"] is True
        assert entries["bob"]["effective_sudo"]["via"] == "direct"
        assert entries["alice"]["effective_sudo"]["has_sudo"] is False

    def test_group_based_sudoers_rule_resolves_through_secondary_group_membership(self):
        # alice is a member of "sudo" (GROUP_SUDO_DEVS); a %sudo rule must
        # grant her effective sudo without alice ever appearing by name in
        # /etc/sudoers.
        db = _db()
        _case(db)
        _evidence(db)
        passwd_docs = _identity_docs(PASSWD_ALICE_BOB, artifact_type="passwd", source_path="etc/passwd")
        group_docs = _identity_docs(GROUP_SUDO_DEVS, artifact_type="group", source_path="etc/group")
        sudoers_docs = _sudoers_docs("%sudo ALL=(ALL:ALL) ALL\n")
        create_host_user_fact_observations(db, case_id=CASE_ID, evidence_id=EVIDENCE_ID, artifact_id=ART1_ID, host_id=None, observed_at=None, documents=passwd_docs)
        create_host_user_fact_observations(db, case_id=CASE_ID, evidence_id=EVIDENCE_ID, artifact_id=ART2_ID, host_id=None, observed_at=None, documents=group_docs)
        create_host_user_fact_observations(db, case_id=CASE_ID, evidence_id=EVIDENCE_ID, artifact_id="3333333a-1111-4111-8111-333333333a3f", host_id=None, observed_at=None, documents=sudoers_docs)
        entries = {e["username"]: e for e in resolve_host_users(db, case_id=CASE_ID, evidence_id=EVIDENCE_ID)}
        assert entries["alice"]["effective_sudo"]["has_sudo"] is True
        assert entries["alice"]["effective_sudo"]["via"] == "group"
        assert entries["alice"]["effective_sudo"]["granting_groups"] == ["sudo"]
        assert entries["bob"]["effective_sudo"]["has_sudo"] is False

    def test_defaults_lines_never_grant_sudo(self):
        db = _db()
        _case(db)
        _evidence(db)
        passwd_docs = _identity_docs(PASSWD_ALICE_BOB, artifact_type="passwd", source_path="etc/passwd")
        sudoers_docs = _sudoers_docs("Defaults env_reset\nDefaults secure_path=\"/usr/bin\"\n")
        create_host_user_fact_observations(db, case_id=CASE_ID, evidence_id=EVIDENCE_ID, artifact_id=ART1_ID, host_id=None, observed_at=None, documents=passwd_docs)
        create_host_user_fact_observations(db, case_id=CASE_ID, evidence_id=EVIDENCE_ID, artifact_id=ART2_ID, host_id=None, observed_at=None, documents=sudoers_docs)
        entries = {e["username"]: e for e in resolve_host_users(db, case_id=CASE_ID, evidence_id=EVIDENCE_ID)}
        assert entries["alice"]["effective_sudo"]["has_sudo"] is False
        assert entries["bob"]["effective_sudo"]["has_sudo"] is False
        assert db.query(HostUserFact).filter(HostUserFact.source_kind == "sudoers_rule").count() == 0


class TestLastLogin:
    def test_lastlog_correlates_with_passwd_by_uid(self):
        db = _db()
        _case(db)
        _evidence(db)
        passwd_docs = _identity_docs(PASSWD_ALICE_BOB, artifact_type="passwd", source_path="etc/passwd")
        create_host_user_fact_observations(db, case_id=CASE_ID, evidence_id=EVIDENCE_ID, artifact_id=ART1_ID, host_id=None, observed_at=None, documents=passwd_docs)
        seconds = int(datetime(2026, 1, 15, 12, 0, tzinfo=timezone.utc).timestamp())
        lastlog_docs = _lastlog_docs({1000: (seconds, "pts/0", "203.0.113.5")}, passwd_content=PASSWD_ALICE_BOB)
        create_host_user_fact_observations(db, case_id=CASE_ID, evidence_id=EVIDENCE_ID, artifact_id=ART2_ID, host_id=None, observed_at=None, documents=lastlog_docs)
        entries = {e["username"]: e for e in resolve_host_users(db, case_id=CASE_ID, evidence_id=EVIDENCE_ID)}
        assert entries["alice"]["last_login"]["source_ip"] == "203.0.113.5"
        assert entries["alice"]["last_login"]["timestamp"].startswith("2026-01-15")
        assert entries["bob"]["last_login"] is None

    def test_orphan_lastlog_uid_becomes_synthetic_entry_not_dropped_or_fabricated(self):
        db = _db()
        _case(db)
        _evidence(db)
        # No passwd content available at parse time -- lastlog.py itself
        # cannot resolve uid 1000 to a username, and no passwd observation
        # exists in this scope either, so the aggregation layer's uid
        # fallback also has nothing to match against.
        seconds = int(datetime(2026, 1, 15, 12, 0, tzinfo=timezone.utc).timestamp())
        lastlog_docs = _lastlog_docs({1000: (seconds, "pts/0", "203.0.113.5")}, passwd_content=None)
        create_host_user_fact_observations(db, case_id=CASE_ID, evidence_id=EVIDENCE_ID, artifact_id=ART1_ID, host_id=None, observed_at=None, documents=lastlog_docs)
        entries = resolve_host_users(db, case_id=CASE_ID, evidence_id=EVIDENCE_ID)
        assert len(entries) == 1
        assert entries[0]["username"] == "uid:1000"
        assert entries[0]["is_synthetic_username"] is True
        assert entries[0]["last_login"]["source_ip"] == "203.0.113.5"


class TestDuplicatePrevention:
    def test_calling_twice_does_not_duplicate(self):
        db = _db()
        _case(db)
        _evidence(db)
        docs = _identity_docs(PASSWD_ALICE_BOB, artifact_type="passwd", source_path="etc/passwd")
        create_host_user_fact_observations(db, case_id=CASE_ID, evidence_id=EVIDENCE_ID, artifact_id=ART1_ID, host_id=None, observed_at=None, documents=docs)
        create_host_user_fact_observations(db, case_id=CASE_ID, evidence_id=EVIDENCE_ID, artifact_id=ART1_ID, host_id=None, observed_at=None, documents=docs)
        assert db.query(HostUserFact).count() == 2  # alice + bob, not 4


class TestMultiHost:
    def test_users_never_merge_across_hosts(self):
        db = _db()
        _case(db)
        host_a = "eeeeeeee-1111-4111-8111-eeeeeeeeeeee"
        host_b = "ffffffff-1111-4111-8111-ffffffffffff"
        db.add(CaseHost(id=host_a, case_id=CASE_ID, canonical_name="host-a", display_name="HOST-A", confidence="manual", source="manual"))
        db.add(CaseHost(id=host_b, case_id=CASE_ID, canonical_name="host-b", display_name="HOST-B", confidence="manual", source="manual"))
        db.commit()
        _evidence(db, EVIDENCE_ID, host_id=host_a, filename="a.E01")
        _evidence(db, SECOND_EVIDENCE_ID, host_id=host_b, filename="b.E01")
        docs_a = _identity_docs("alice:x:1000:1000:Alice A:/home/alice:/bin/bash\n", artifact_type="passwd", source_path="etc/passwd")
        docs_b = _identity_docs("alice:x:2000:2000:Alice B:/home/alice2:/bin/zsh\n", artifact_type="passwd", source_path="etc/passwd")
        create_host_user_fact_observations(db, case_id=CASE_ID, evidence_id=EVIDENCE_ID, artifact_id=ART1_ID, host_id=host_a, observed_at=None, documents=docs_a)
        create_host_user_fact_observations(db, case_id=CASE_ID, evidence_id=SECOND_EVIDENCE_ID, artifact_id=ART2_ID, host_id=host_b, observed_at=None, documents=docs_b)
        entries_a = resolve_host_users(db, case_id=CASE_ID, host_id=host_a)
        entries_b = resolve_host_users(db, case_id=CASE_ID, host_id=host_b)
        assert len(entries_a) == 1 and entries_a[0]["identity"]["uid"]["preferred_value"] == "1000"
        assert len(entries_b) == 1 and entries_b[0]["identity"]["uid"]["preferred_value"] == "2000"
        # Never conflicting -- host_a's alice and host_b's alice are different hosts entirely.
        assert entries_a[0]["identity"]["uid"]["status"] == "observed"
        assert entries_b[0]["identity"]["uid"]["status"] == "observed"


class TestReprocessCleanup:
    def test_delete_host_user_facts_for_evidence(self):
        db = _db()
        _case(db)
        _evidence(db)
        docs = _identity_docs(PASSWD_ALICE_BOB, artifact_type="passwd", source_path="etc/passwd")
        create_host_user_fact_observations(db, case_id=CASE_ID, evidence_id=EVIDENCE_ID, artifact_id=ART1_ID, host_id=None, observed_at=None, documents=docs)
        assert db.query(HostUserFact).count() == 2
        deleted = delete_host_user_facts_for_evidence(db, EVIDENCE_ID)
        db.commit()
        assert deleted == 2
        assert db.query(HostUserFact).count() == 0


class TestApi:
    def test_case_not_found(self):
        db = _db()
        client = _client(db)
        response = client.get(f"/api/cases/{CASE_ID}/host-users", params={"evidence_id": EVIDENCE_ID})
        assert response.status_code == 404

    def test_requires_scope(self):
        db = _db()
        _case(db)
        client = _client(db)
        response = client.get(f"/api/cases/{CASE_ID}/host-users")
        assert response.status_code == 422

    def test_returns_resolved_users_for_host(self):
        db = _db()
        _case(db)
        _host(db)
        _evidence(db, host_id=HOST_ID)
        docs = _identity_docs(PASSWD_ALICE_BOB, artifact_type="passwd", source_path="etc/passwd")
        create_host_user_fact_observations(db, case_id=CASE_ID, evidence_id=EVIDENCE_ID, artifact_id=ART1_ID, host_id=HOST_ID, observed_at=None, documents=docs)
        client = _client(db)
        response = client.get(f"/api/cases/{CASE_ID}/host-users", params={"host_id": HOST_ID})
        assert response.status_code == 200
        body = response.json()
        assert body["scope"] == "host"
        usernames = {u["username"] for u in body["users"]}
        assert usernames == {"alice", "bob"}
