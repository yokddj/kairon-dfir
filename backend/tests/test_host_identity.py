from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from types import SimpleNamespace

from sqlalchemy import create_engine
from sqlalchemy.dialects import postgresql
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import sessionmaker

from app.core.database import Base
from app.core.opensearch import bulk_index_events_with_report
from app.ingest.fingerprints import compute_event_fingerprint
from app.models.case import Case
from app.models.case_host import CaseHost
from app.models.case_host_alias import CaseHostAlias
from app.services import host_identity


CASE_ID = "a1111111-1111-4111-8111-111111111111"


def _session(database_url: str = "sqlite:///:memory:"):
    engine = create_engine(database_url, future=True, connect_args={"check_same_thread": False})
    Base.metadata.create_all(bind=engine)
    Session = sessionmaker(bind=engine, autoflush=False, autocommit=False, expire_on_commit=False, future=True)
    db = Session()
    db.add(Case(id=CASE_ID, name="Case Alpha"))
    db.commit()
    return db


def _session_factory(db_path: Path):
    engine = create_engine(f"sqlite:///{db_path}", future=True, connect_args={"check_same_thread": False})
    Base.metadata.create_all(bind=engine)
    Session = sessionmaker(bind=engine, autoflush=False, autocommit=False, expire_on_commit=False, future=True)
    with Session() as db:
        db.add(Case(id=CASE_ID, name="Case Alpha"))
        db.commit()
    return Session


def _observed_counts(host_name: str) -> dict[str, dict]:
    return {
        host_name: {
            "event_count": 10,
            "findings_count": 1,
            "high_risk_count": 1,
            "evidence_ids": ["ev-1"],
            "first_seen": "2026-05-20T08:00:00Z",
            "last_seen": "2026-05-20T08:05:00Z",
        }
    }


def test_normalize_host_alias_lowercases_and_strips_trailing_dot() -> None:
    assert host_identity.normalize_host_alias("HOSTA.EXAMPLE.LOCAL.") == "hosta.example.local"


def test_merge_hosts_creates_canonical_host_and_alias_expansion(monkeypatch) -> None:
    db = _session()
    monkeypatch.setattr(
        host_identity,
        "_observed_host_counts",
        lambda _db, _case_id: {
            "hosta": {"event_count": 10, "findings_count": 1, "high_risk_count": 1, "evidence_ids": ["ev-1"], "first_seen": "2026-05-20T08:00:00Z", "last_seen": "2026-05-20T08:05:00Z"},
            "desktop-old01": {"event_count": 5, "findings_count": 0, "high_risk_count": 0, "evidence_ids": ["ev-1"], "first_seen": "2026-05-20T08:10:00Z", "last_seen": "2026-05-20T08:12:00Z"},
        },
    )

    hosts = host_identity.get_case_hosts(db, CASE_ID)
    canonical_id = next(item["id"] for item in hosts if item["canonical_name"] == "hosta")
    merged = host_identity.merge_hosts(db, CASE_ID, canonical_id, ["desktop-old01"], reason="same endpoint")

    assert merged["canonical_name"] == "hosta"
    assert "desktop-old01" in merged["aliases"]
    assert host_identity.expand_host_filter(db, CASE_ID, "hosta") == ["desktop-old01", "hosta"]


def test_split_alias_removes_alias_from_canonical_filter(monkeypatch) -> None:
    db = _session()
    monkeypatch.setattr(
        host_identity,
        "_observed_host_counts",
        lambda _db, _case_id: {
            "hosta": {"event_count": 10, "findings_count": 1, "high_risk_count": 1, "evidence_ids": ["ev-1"], "first_seen": None, "last_seen": None},
            "desktop-old01": {"event_count": 5, "findings_count": 0, "high_risk_count": 0, "evidence_ids": ["ev-1"], "first_seen": None, "last_seen": None},
        },
    )
    hosts = host_identity.get_case_hosts(db, CASE_ID)
    canonical_id = next(item["id"] for item in hosts if item["canonical_name"] == "hosta")
    host_identity.merge_hosts(db, CASE_ID, canonical_id, ["desktop-old01"], reason="same endpoint")
    merged = next(item for item in host_identity.get_case_hosts(db, CASE_ID) if item["canonical_name"] == "hosta")
    alias_id = next(item["id"] for item in merged["alias_rows"] if item["alias"] == "desktop-old01")

    host_identity.split_alias(db, CASE_ID, alias_id, reason="not the same endpoint")

    assert host_identity.expand_host_filter(db, CASE_ID, "hosta") == ["hosta"]


def test_stable_event_id_uses_observed_host_not_mutable_canonical_name() -> None:
    event = {
        "case_id": CASE_ID,
        "evidence_id": "ev-1",
        "@timestamp": "2026-05-20T08:00:00Z",
        "artifact": {"type": "evtx_raw", "parser": "native_evtx"},
        "event": {"type": "process_start"},
        "windows": {"provider_name": "Microsoft-Windows-Security-Auditing", "event_id": 4688, "event_record_id": 101},
        "host": {"name": "hosta"},
        "observed_host": {"name": "DESKTOP-OLD01"},
    }
    original = compute_event_fingerprint(event).stable_event_id
    event["host"]["name"] = "renamed-hosta"
    renamed = compute_event_fingerprint(event).stable_event_id

    assert original == renamed


def test_concurrent_get_or_create_same_case_and_canonical_name_returns_one_host(tmp_path: Path, monkeypatch) -> None:
    Session = _session_factory(tmp_path / "host-identity-concurrency.sqlite")
    monkeypatch.setattr(host_identity, "_observed_host_counts", lambda _db, _case_id: _observed_counts("pc02.example.corp"))

    def _worker() -> str:
        with Session() as db:
            hosts = host_identity.get_case_hosts(db, CASE_ID)
            return next(item["id"] for item in hosts if item["canonical_name"] == "pc02.example.corp")

    with ThreadPoolExecutor(max_workers=2) as executor:
        results = list(executor.map(lambda _: _worker(), range(2)))

    with Session() as db:
        assert len(set(results)) == 1
        assert db.query(CaseHost).filter(CaseHost.case_id == CASE_ID, CaseHost.canonical_name == "pc02.example.corp").count() == 1
        assert db.query(CaseHostAlias).filter(CaseHostAlias.case_id == CASE_ID, CaseHostAlias.normalized_alias == "pc02.example.corp").count() == 1


def test_duplicate_insert_race_recovers_existing_host_after_integrity_error(tmp_path: Path) -> None:
    Session = _session_factory(tmp_path / "host-identity-race.sqlite")
    with Session() as db:
        original_flush = db.flush
        state = {"raised": False}

        class _FakeSavepoint:
            def commit(self) -> None:
                return None

            def rollback(self) -> None:
                return None

        def _racing_flush(*args, **kwargs):  # noqa: ANN002, ANN003
            if not state["raised"]:
                state["raised"] = True
                with Session() as competing_db:
                    competing_db.add(
                        CaseHost(
                            case_id=CASE_ID,
                            canonical_name="pc01",
                            display_name="pc01",
                            confidence="high",
                            source="observed",
                        )
                    )
                    competing_db.commit()
                raise IntegrityError("INSERT INTO case_hosts", {}, Exception("duplicate key"))
            return original_flush(*args, **kwargs)

        db.begin_nested = lambda: _FakeSavepoint()  # type: ignore[method-assign]
        db.flush = _racing_flush  # type: ignore[method-assign]
        host_id = host_identity._fallback_case_host_upsert(db, host_identity._case_host_upsert_values(CASE_ID, "pc01", _observed_counts("pc01")["pc01"]))
        stats = host_identity.get_host_identity_runtime_stats(db)

        assert host_id
        assert stats["conflicts_recovered"] == 1
        assert stats["host_identity_conflict_retries"] == 1
        assert "host_identity_upsert_conflict_recovered" in stats["warnings"]


def test_postgresql_upsert_statement_uses_on_conflict() -> None:
    captured: dict[str, str] = {}

    class _FakeResult:
        def scalar_one(self) -> str:
            return "host-1"

    class _FakeSession:
        def execute(self, stmt):  # noqa: ANN001
            captured["sql"] = str(stmt.compile(dialect=postgresql.dialect()))
            return _FakeResult()

    host_id = host_identity._postgresql_case_host_upsert(
        _FakeSession(),
        host_identity._case_host_upsert_values(CASE_ID, "pc01", _observed_counts("pc01")["pc01"]),
    )

    assert host_id == "host-1"
    assert "ON CONFLICT" in captured["sql"]
    assert "uq_case_hosts_case_canonical_name" in captured["sql"]


def test_sqlite_fallback_upsert_creates_host_and_primary_alias(monkeypatch) -> None:
    db = _session()
    monkeypatch.setattr(host_identity, "_observed_host_counts", lambda _db, _case_id: _observed_counts("pc01"))

    hosts = host_identity.get_case_hosts(db, CASE_ID)

    assert len(hosts) == 1
    assert hosts[0]["canonical_name"] == "pc01"
    assert hosts[0]["all_names"] == ["pc01"]


def test_parallel_bulk_ingest_same_host_does_not_fail(tmp_path: Path, monkeypatch) -> None:
    from app.core import opensearch as opensearch_module

    Session = _session_factory(tmp_path / "host-identity-bulk.sqlite")
    monkeypatch.setattr(opensearch_module, "SessionLocal", Session)
    monkeypatch.setattr(opensearch_module, "load_runtime_settings", lambda _db: {"OPENSEARCH_BULK_DOCS": 1000, "OPENSEARCH_BULK_BYTES": 1024 * 1024})
    monkeypatch.setattr(opensearch_module, "ensure_case_index", lambda _case_id: "dfir-events-test")
    monkeypatch.setattr(host_identity, "_observed_host_counts", lambda _db, _case_id: _observed_counts("pc01"))

    class _FakeClient:
        def bulk(self, **_kwargs):
            return {"items": []}

    monkeypatch.setattr(opensearch_module, "get_opensearch_client", lambda **_kwargs: _FakeClient())

    def _document(host_name: str) -> dict:
        return {
            "case_id": CASE_ID,
            "evidence_id": "ev-1",
            "event_id": f"evt-{host_name}",
            "@timestamp": "2026-05-20T08:00:00Z",
            "artifact": {"type": "evtx_raw", "parser": "evtx_raw"},
            "event": {"type": "process_start"},
            "host": {"name": host_name},
            "observed_host": {"name": host_name},
        }

    with ThreadPoolExecutor(max_workers=2) as executor:
        reports = list(
            executor.map(
                lambda docs: bulk_index_events_with_report(CASE_ID, docs, index="dfir-events-test", refresh=False, max_bulk_docs=1000, max_bulk_bytes=1024 * 1024),
                [[_document("pc01")], [_document("pc01")]],
            )
        )

    assert all(report["success"] for report in reports)
    with Session() as db:
        assert db.query(CaseHost).filter(CaseHost.case_id == CASE_ID, CaseHost.canonical_name == "pc01").count() == 1


def test_apply_case_host_identity_preserves_observed_name_and_aliases(monkeypatch) -> None:
    db = _session()
    monkeypatch.setattr(
        host_identity,
        "_observed_host_counts",
        lambda _db, _case_id: {
            "hosta": {"event_count": 10, "findings_count": 1, "high_risk_count": 1, "evidence_ids": ["ev-1"], "first_seen": None, "last_seen": None},
            "desktop-old01": {"event_count": 5, "findings_count": 0, "high_risk_count": 0, "evidence_ids": ["ev-1"], "first_seen": None, "last_seen": None},
        },
    )
    hosts = host_identity.get_case_hosts(db, CASE_ID)
    canonical_id = next(item["id"] for item in hosts if item["canonical_name"] == "hosta")
    host_identity.merge_hosts(db, CASE_ID, canonical_id, ["desktop-old01"], reason="same endpoint")

    event = {
        "host": {"name": "desktop-old01"},
        "observed_host": {"name": "desktop-old01"},
    }
    hydrated = host_identity.apply_case_host_identity(db, CASE_ID, event)

    assert hydrated["host"]["name"] == "hosta"
    assert "desktop-old01" in hydrated["host"]["aliases"]
    assert hydrated["observed_host"]["name"] == "desktop-old01"


def test_event_matches_host_filter_uses_alias_expansion(monkeypatch) -> None:
    db = _session()
    monkeypatch.setattr(
        host_identity,
        "_observed_host_counts",
        lambda _db, _case_id: {
            "pc02.example.corp": {"event_count": 8, "findings_count": 0, "high_risk_count": 0, "evidence_ids": ["ev-1"], "first_seen": None, "last_seen": None},
            "pc02": {"event_count": 3, "findings_count": 0, "high_risk_count": 0, "evidence_ids": ["ev-1"], "first_seen": None, "last_seen": None},
        },
    )
    hosts = host_identity.get_case_hosts(db, CASE_ID)
    canonical_id = next(item["id"] for item in hosts if item["canonical_name"] == "pc02.example.corp")
    host_identity.merge_hosts(db, CASE_ID, canonical_id, ["pc02"], reason="fqdn and short host")

    event = {"host": {"name": "pc02.example.corp"}, "observed_host": {"name": "pc02"}}

    assert host_identity.event_matches_host_filter(db, CASE_ID, event, "pc02.example.corp") is True
    assert host_identity.event_matches_host_filter(db, CASE_ID, event, "pc02") is True
    assert host_identity.event_matches_host_filter(db, CASE_ID, event, "other-host") is False
