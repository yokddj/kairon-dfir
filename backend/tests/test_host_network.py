"""Host Network Observations: classification, per-source extraction, and
cross-source merge (see app.services.host_network).

Every source-extraction test feeds the module a FakeOpenSearchClient whose
canned responses mirror the exact real response shapes captured live
against the ctf/ws01 (Windows Sysmon + memory netscan) and
39eabacb.../VulnOSv2 (Linux dhclient) cases during development -- these
are not invented shapes.
"""
from __future__ import annotations

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from app.core.database import Base
from app.models.case import Case
from app.models.case_host import CaseHost
from app.models.evidence import Evidence, EvidenceStorageMode, EvidenceType, IngestStatus
from app.services import host_network
from app.services.host_network import (
    SOURCE_LINUX_DHCLIENT,
    SOURCE_MEMORY_NETSCAN,
    SOURCE_SYSMON_NETWORK_CONNECTION,
    classify_ip,
    get_host_network_observations,
)

CASE_ID = "aaaaaaaa-1111-4111-8111-aaaaaaaaaaaa"
OTHER_CASE_ID = "eeeeeeee-1111-4111-8111-eeeeeeeeeeee"
HOST_ID = "dddddddd-1111-4111-8111-dddddddddddd"
OTHER_HOST_ID = "ffffffff-1111-4111-8111-ffffffffffff"
EVIDENCE_ID = "bbbbbbbb-2222-4222-8222-bbbbbbbbbbbb"
OTHER_HOST_EVIDENCE_ID = "cccccccc-3333-4333-8333-cccccccccccc"


def _db():
    engine = create_engine("sqlite:///:memory:", connect_args={"check_same_thread": False}, poolclass=StaticPool, future=True)
    Base.metadata.create_all(engine)
    return sessionmaker(bind=engine, future=True)()


def _case(db, case_id=CASE_ID):
    db.add(Case(id=case_id, name="Case", description=None))
    db.commit()


def _host(db, host_id=HOST_ID, case_id=CASE_ID, canonical_name="ws01"):
    host = CaseHost(id=host_id, case_id=case_id, canonical_name=canonical_name, display_name=canonical_name.upper(), confidence="manual", source="manual")
    db.add(host)
    db.commit()
    return host


def _evidence(db, evidence_id, *, host_id, case_id=CASE_ID, filename="evidence.dmp"):
    item = Evidence(
        id=evidence_id, case_id=case_id, original_filename=filename, stored_path=f"/tmp/{filename}",
        original_path=f"/tmp/{filename}", storage_mode=EvidenceStorageMode.uploaded, is_external=False,
        copy_to_storage=True, evidence_type=EvidenceType.memory_dump, sha256="0" * 64, size_bytes=128,
        ingest_status=IngestStatus.completed, detected_host=None, host_id=host_id,
        path_validation={}, ingest_source={}, metadata_json={}, error_log={},
    )
    db.add(item)
    db.commit()
    return item


class _FakeSearch:
    """Records every query body it receives and returns a canned response
    chosen by matching a simple marker against the query -- good enough to
    route the three distinct source queries this module issues without
    needing a real OpenSearch.
    """

    def __init__(self, responses: dict[str, dict], *, exists: set[str] | None = None):
        self._responses = responses
        self._exists = exists if exists is not None else {"events", "memory"}
        self.calls: list[dict] = []

    def _kind_for_index(self, index: str) -> str:
        return "memory" if "memory" in index else "events"

    def search(self, *, index: str, body: dict) -> dict:
        self.calls.append({"index": index, "body": body})
        query_str = str(body)
        if "sysmon_network_connection" in query_str:
            return self._responses.get("sysmon", _EMPTY_TERMS)
        if "linux_syslog" in query_str:
            return self._responses.get("dhclient", _EMPTY_HITS)
        if "memory_network_connection" in query_str:
            return self._responses.get("memory", _EMPTY_TERMS)
        return _EMPTY_TERMS


_EMPTY_TERMS = {"aggregations": {"ips": {"buckets": []}, "by_evidence": {"buckets": []}}}
_EMPTY_HITS = {"hits": {"hits": []}}


def _patch_opensearch(monkeypatch, fake_search: _FakeSearch, *, events_index="dfir-events-case", memory_index="dfir-memory-case"):
    monkeypatch.setattr(host_network, "get_opensearch_client", lambda: fake_search)
    monkeypatch.setattr(host_network, "get_events_index", lambda case_id: events_index)
    monkeypatch.setattr(host_network, "get_memory_index", lambda case_id: memory_index)
    monkeypatch.setattr(host_network, "index_exists", lambda client, index: True)
    monkeypatch.setattr(host_network, "is_index_queryable", lambda client, index: True)
    monkeypatch.setattr(
        host_network,
        "resolve_aggregatable_field",
        lambda client, index, field: field,
    )
    monkeypatch.setattr(host_network, "expand_host_filter", lambda db, case_id, name: [name] if name else [])


def _sysmon_response(buckets: list[dict]) -> dict:
    return {"aggregations": {"ips": {"buckets": buckets}}}


def _sysmon_bucket(ip: str, count: int, first: str, last: str, *, evidence_id=EVIDENCE_ID, artifact_id="art-1") -> dict:
    return {
        "key": ip,
        "doc_count": count,
        "first_seen": {"value_as_string": first},
        "last_seen": {"value_as_string": last},
        "sample": {"hits": {"hits": [{"_source": {"evidence_id": evidence_id, "artifact_id": artifact_id}}]}},
    }


def _dhclient_hits(messages: list[tuple[str, str | None]], *, evidence_id=EVIDENCE_ID) -> dict:
    return {
        "hits": {
            "hits": [
                {"_source": {"@timestamp": ts, "event": {"message": message}, "evidence_id": evidence_id, "artifact_id": None}}
                for message, ts in messages
            ]
        }
    }


def _memory_response(evidence_id: str, addresses: list[tuple[str, int, str | None]]) -> dict:
    return {
        "aggregations": {
            "by_evidence": {
                "buckets": [
                    {
                        "key": evidence_id,
                        "addresses": {
                            "buckets": [
                                {"key": addr, "doc_count": count, "latest_create_time": {"value_as_string": create_time}}
                                for addr, count, create_time in addresses
                            ]
                        },
                    }
                ]
            }
        }
    }


class TestClassifyIp:
    def test_ipv4_private(self):
        result = classify_ip("192.168.20.41")
        assert result["classification"] == "private"
        assert result["ip_version"] == 4
        assert result["is_public"] is False

    def test_ipv4_public(self):
        result = classify_ip("104.90.205.80")
        assert result["classification"] == "public"
        assert result["is_public"] is True

    def test_ipv4_loopback_is_not_private(self):
        result = classify_ip("127.0.0.1")
        assert result["classification"] == "loopback"
        assert result["is_private"] is False

    def test_ipv6_loopback(self):
        result = classify_ip("::1")
        assert result["classification"] == "loopback"
        assert result["ip_version"] == 6

    def test_ipv6_link_local_is_not_primary_private(self):
        result = classify_ip("fe80::35fe:fb89:feab:10ae")
        assert result["classification"] == "link-local"

    def test_ipv6_canonical_equivalence(self):
        # Two different textual representations of the same address must
        # collapse to the same canonical string -- required for dedup.
        expanded = classify_ip("0000:0000:0000:0000:0000:0000:0000:0001")
        short = classify_ip("::1")
        assert expanded["ip"] == short["ip"]

    def test_invalid_value_returns_none(self):
        assert classify_ip("not-an-ip") is None
        assert classify_ip("") is None
        assert classify_ip(None) is None

    def test_wildcard_is_unspecified_not_private_or_public(self):
        # classify_ip() itself never excludes wildcards -- that filtering
        # happens in the memory query before classify_ip is even called
        # (0.0.0.0/:: mean "every interface", not a real observation).
        # This just confirms the label is honest if it ever reaches here.
        result = classify_ip("0.0.0.0")
        assert result["classification"] == "unspecified"


class TestSysmonSource:
    def test_single_source_ip_dominant_with_one_outlier(self, monkeypatch):
        db = _db()
        _case(db)
        _host(db)
        fake = _FakeSearch({
            "sysmon": _sysmon_response([
                _sysmon_bucket("192.168.20.41", 1611, "2024-03-22T11:21:41Z", "2024-03-22T19:48:41Z"),
                _sysmon_bucket("10.0.8.25", 1, "2024-03-22T19:47:22Z", "2024-03-22T19:47:22Z"),
            ]),
        })
        _patch_opensearch(monkeypatch, fake)
        result = get_host_network_observations(db, case_id=CASE_ID, host_id=HOST_ID)
        by_ip = {entry["ip"]: entry for entry in result["addresses"]}
        assert by_ip["192.168.20.41"]["observation_count"] == 1611
        assert by_ip["192.168.20.41"]["sources"][0]["source_kind"] == SOURCE_SYSMON_NETWORK_CONNECTION
        assert by_ip["10.0.8.25"]["observation_count"] == 1

    def test_query_never_reads_destination_ip(self, monkeypatch):
        # Regression: the query must be built against network.source_ip
        # only. A field name typo that swapped in destination_ip (the
        # remote peer) would silently attribute remote hosts to this
        # machine -- this asserts the actual field name sent to OpenSearch.
        db = _db()
        _case(db)
        _host(db)
        fake = _FakeSearch({"sysmon": _sysmon_response([_sysmon_bucket("192.168.20.41", 1, "2024-01-01T00:00:00Z", "2024-01-01T00:00:00Z")])})
        _patch_opensearch(monkeypatch, fake)
        get_host_network_observations(db, case_id=CASE_ID, host_id=HOST_ID)
        sysmon_calls = [call for call in fake.calls if "sysmon_network_connection" in str(call["body"])]
        assert len(sysmon_calls) == 1
        agg_field = sysmon_calls[0]["body"]["aggs"]["ips"]["terms"]["field"]
        assert agg_field == "network.source_ip"
        assert "destination_ip" not in str(sysmon_calls[0]["body"])


class TestLinuxDhclientSource:
    def test_bound_to_line_extracts_ip_and_aggregates_first_last_seen(self, monkeypatch):
        db = _db()
        _case(db)
        _host(db, canonical_name="vulnosv2")
        fake = _FakeSearch({
            "dhclient": _dhclient_hits([
                ("bound to 192.168.56.102 -- renewal in 471 seconds.", "2026-04-16T15:12:17+00:00"),
                ("bound to 192.168.56.102 -- renewal in 469 seconds.", "2026-04-16T15:20:08+00:00"),
                ("bound to 10.0.2.15 -- renewal in 39344 seconds.", "2026-04-16T15:28:39+00:00"),
            ])
        })
        _patch_opensearch(monkeypatch, fake)
        result = get_host_network_observations(db, case_id=CASE_ID, host_id=HOST_ID)
        by_ip = {entry["ip"]: entry for entry in result["addresses"]}
        assert by_ip["192.168.56.102"]["observation_count"] == 2
        assert by_ip["192.168.56.102"]["first_seen"] == "2026-04-16T15:12:17+00:00"
        assert by_ip["192.168.56.102"]["last_seen"] == "2026-04-16T15:20:08+00:00"
        assert by_ip["10.0.2.15"]["observation_count"] == 1
        assert by_ip["192.168.56.102"]["sources"][0]["source_kind"] == SOURCE_LINUX_DHCLIENT

    def test_handles_line_with_unstripped_syslog_prefix(self, monkeypatch):
        # Real carved/raw syslog content sometimes keeps the leading
        # "MMM D HH:MM:SS dhclient: " prefix -- the regex must still find
        # the IP via search(), not an anchored match().
        db = _db()
        _case(db)
        _host(db, canonical_name="vulnosv2")
        fake = _FakeSearch({
            "dhclient": _dhclient_hits([
                ("Apr  3 16:03:37 dhclient: bound to 10.0.2.15 -- renewal in 39557 seconds.", "2026-04-03T18:15:15+00:00"),
            ])
        })
        _patch_opensearch(monkeypatch, fake)
        result = get_host_network_observations(db, case_id=CASE_ID, host_id=HOST_ID)
        assert any(entry["ip"] == "10.0.2.15" for entry in result["addresses"])

    def test_message_without_timestamp_is_skipped_not_guessed(self, monkeypatch):
        db = _db()
        _case(db)
        _host(db, canonical_name="vulnosv2")
        fake = _FakeSearch({"dhclient": _dhclient_hits([("bound to 192.168.56.102 -- renewal in 471 seconds.", None)])})
        _patch_opensearch(monkeypatch, fake)
        result = get_host_network_observations(db, case_id=CASE_ID, host_id=HOST_ID)
        assert result["addresses"] == []

    def test_dhcpack_lines_are_never_parsed(self, monkeypatch):
        # DHCPACK names the *server's* address -- must never be mistaken
        # for the host's own address just because it appears in a dhclient
        # log line.
        db = _db()
        _case(db)
        _host(db, canonical_name="vulnosv2")
        fake = _FakeSearch({"dhclient": _dhclient_hits([("DHCPACK from 192.168.56.1", "2026-04-16T15:12:17+00:00")])})
        _patch_opensearch(monkeypatch, fake)
        result = get_host_network_observations(db, case_id=CASE_ID, host_id=HOST_ID)
        assert result["addresses"] == []


class TestMemorySource:
    def test_wildcard_addresses_excluded(self, monkeypatch):
        db = _db()
        _case(db)
        _host(db)
        _evidence(db, EVIDENCE_ID, host_id=HOST_ID)
        fake = _FakeSearch({
            "memory": _memory_response(EVIDENCE_ID, [
                ("192.168.20.41", 79, "2024-03-22T10:55:21Z"),
                ("0.0.0.0", 76, "2024-03-22T12:58:41Z"),
                ("::", 42, "2024-03-22T12:58:41Z"),
            ])
        })
        _patch_opensearch(monkeypatch, fake)
        result = get_host_network_observations(db, case_id=CASE_ID, host_id=HOST_ID)
        ips = {entry["ip"] for entry in result["addresses"]}
        assert ips == {"192.168.20.41"}

    def test_loopback_and_link_local_are_kept_and_classified(self, monkeypatch):
        db = _db()
        _case(db)
        _host(db)
        _evidence(db, EVIDENCE_ID, host_id=HOST_ID)
        fake = _FakeSearch({
            "memory": _memory_response(EVIDENCE_ID, [
                ("127.0.0.1", 10, "2024-03-22T12:52:24Z"),
                ("fe80::35fe:fb89:feab:10ae", 2, "2024-03-22T10:55:21Z"),
            ])
        })
        _patch_opensearch(monkeypatch, fake)
        result = get_host_network_observations(db, case_id=CASE_ID, host_id=HOST_ID)
        by_ip = {entry["ip"]: entry for entry in result["addresses"]}
        assert by_ip["127.0.0.1"]["classification"] == "loopback"
        assert by_ip["fe80::35fe:fb89:feab:10ae"]["classification"] == "link-local"

    def test_missing_create_time_falls_back_to_evidence_acquisition_time(self, monkeypatch):
        db = _db()
        _case(db)
        _host(db)
        _evidence(db, EVIDENCE_ID, host_id=HOST_ID)
        fake = _FakeSearch({"memory": _memory_response(EVIDENCE_ID, [("192.168.20.41", 1, None)])})
        _patch_opensearch(monkeypatch, fake)
        result = get_host_network_observations(db, case_id=CASE_ID, host_id=HOST_ID)
        entry = next(entry for entry in result["addresses"] if entry["ip"] == "192.168.20.41")
        assert entry["first_seen"] is not None
        assert entry["sources"][0]["source_kind"] == SOURCE_MEMORY_NETSCAN

    def test_local_address_never_mixes_with_remote_address(self, monkeypatch):
        # The memory query only ever aggregates on local_address; a memory
        # dump full of high-count remote_address values (e.g. a scanned
        # host, or a CDN hit thousands of times) must never leak into the
        # host's own address list just because it's numerous.
        db = _db()
        _case(db)
        _host(db)
        _evidence(db, EVIDENCE_ID, host_id=HOST_ID)
        fake = _FakeSearch({"memory": _memory_response(EVIDENCE_ID, [("192.168.20.41", 5, "2024-03-22T10:55:21Z")])})
        _patch_opensearch(monkeypatch, fake)
        get_host_network_observations(db, case_id=CASE_ID, host_id=HOST_ID)
        memory_calls = [call for call in fake.calls if "memory_network_connection" in str(call["body"])]
        assert len(memory_calls) == 1
        addr_field = memory_calls[0]["body"]["aggs"]["by_evidence"]["aggs"]["addresses"]["terms"]["field"]
        assert addr_field == "local_address"
        assert "remote_address" not in str(memory_calls[0]["body"])

    def test_evidence_belonging_to_a_different_host_never_leaks_in(self, monkeypatch):
        db = _db()
        _case(db)
        _host(db, host_id=HOST_ID, canonical_name="ws01")
        _host(db, host_id=OTHER_HOST_ID, canonical_name="ws02")
        _evidence(db, EVIDENCE_ID, host_id=HOST_ID)
        _evidence(db, OTHER_HOST_EVIDENCE_ID, host_id=OTHER_HOST_ID)
        fake = _FakeSearch({"memory": _memory_response(EVIDENCE_ID, [("192.168.20.41", 1, "2024-03-22T10:55:21Z")])})
        _patch_opensearch(monkeypatch, fake)
        get_host_network_observations(db, case_id=CASE_ID, host_id=HOST_ID)
        memory_calls = [call for call in fake.calls if "memory_network_connection" in str(call["body"])]
        queried_evidence_ids = memory_calls[0]["body"]["query"]["bool"]["filter"][1]["terms"]["evidence_id"]
        assert queried_evidence_ids == [EVIDENCE_ID]
        assert OTHER_HOST_EVIDENCE_ID not in queried_evidence_ids


class TestMerge:
    def test_multiple_sources_confirming_same_ip_are_merged_not_duplicated(self, monkeypatch):
        db = _db()
        _case(db)
        _host(db)
        _evidence(db, EVIDENCE_ID, host_id=HOST_ID)
        fake = _FakeSearch({
            "sysmon": _sysmon_response([_sysmon_bucket("192.168.20.41", 1611, "2024-03-22T11:21:41Z", "2024-03-22T19:48:41Z")]),
            "memory": _memory_response(EVIDENCE_ID, [("192.168.20.41", 79, "2024-03-22T10:55:21Z")]),
        })
        _patch_opensearch(monkeypatch, fake)
        result = get_host_network_observations(db, case_id=CASE_ID, host_id=HOST_ID)
        assert len(result["addresses"]) == 1
        entry = result["addresses"][0]
        assert entry["ip"] == "192.168.20.41"
        assert entry["observation_count"] == 1611 + 79
        assert {source["source_kind"] for source in entry["sources"]} == {SOURCE_SYSMON_NETWORK_CONNECTION, SOURCE_MEMORY_NETSCAN}
        # first_seen takes the earliest across sources, last_seen the latest.
        assert entry["first_seen"] == "2024-03-22T10:55:21Z"
        assert entry["last_seen"] == "2024-03-22T19:48:41Z"

    def test_sorted_most_recently_seen_first(self, monkeypatch):
        db = _db()
        _case(db)
        _host(db)
        fake = _FakeSearch({
            "sysmon": _sysmon_response([
                _sysmon_bucket("192.168.20.41", 100, "2024-01-01T00:00:00Z", "2024-01-01T00:00:00Z"),
                _sysmon_bucket("192.168.20.99", 5, "2024-06-01T00:00:00Z", "2024-06-01T00:00:00Z"),
            ]),
        })
        _patch_opensearch(monkeypatch, fake)
        result = get_host_network_observations(db, case_id=CASE_ID, host_id=HOST_ID)
        assert [entry["ip"] for entry in result["addresses"]] == ["192.168.20.99", "192.168.20.41"]

    def test_host_with_no_network_evidence_returns_empty_list_not_error(self, monkeypatch):
        db = _db()
        _case(db)
        _host(db)
        fake = _FakeSearch({})
        _patch_opensearch(monkeypatch, fake)
        result = get_host_network_observations(db, case_id=CASE_ID, host_id=HOST_ID)
        assert result == {"case_id": CASE_ID, "host_id": HOST_ID, "addresses": []}

    def test_unknown_host_id_returns_empty_list_not_error(self, monkeypatch):
        db = _db()
        _case(db)
        fake = _FakeSearch({})
        _patch_opensearch(monkeypatch, fake)
        result = get_host_network_observations(db, case_id=CASE_ID, host_id="does-not-exist")
        assert result["addresses"] == []

    def test_host_id_from_a_different_case_is_rejected(self, monkeypatch):
        # A host_id that is real but belongs to another case must not leak
        # that other case's observations into this response.
        db = _db()
        _case(db, case_id=CASE_ID)
        _case(db, case_id=OTHER_CASE_ID)
        _host(db, host_id=OTHER_HOST_ID, case_id=OTHER_CASE_ID)
        fake = _FakeSearch({"sysmon": _sysmon_response([_sysmon_bucket("10.0.0.5", 1, "2024-01-01T00:00:00Z", "2024-01-01T00:00:00Z")])})
        _patch_opensearch(monkeypatch, fake)
        result = get_host_network_observations(db, case_id=CASE_ID, host_id=OTHER_HOST_ID)
        assert result["addresses"] == []

    def test_case_id_is_always_included_in_the_query_scope(self, monkeypatch):
        db = _db()
        _case(db)
        _host(db)
        fake = _FakeSearch({"sysmon": _sysmon_response([_sysmon_bucket("192.168.20.41", 1, "2024-01-01T00:00:00Z", "2024-01-01T00:00:00Z")])})
        _patch_opensearch(monkeypatch, fake)
        get_host_network_observations(db, case_id=CASE_ID, host_id=HOST_ID)
        sysmon_calls = [call for call in fake.calls if "sysmon_network_connection" in str(call["body"])]
        assert {"term": {"case_id": CASE_ID}} in sysmon_calls[0]["body"]["query"]["bool"]["filter"]
