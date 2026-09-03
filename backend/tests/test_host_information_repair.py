"""Deriving Host Information on every ingest path, and repairing old cases."""

from __future__ import annotations

import pytest

from app.services import host_information_repair as repair
from app.workers import tasks


# --------------------------------------------------------------------------
# The ingest paths must not be able to diverge again. Three of the four used
# to harvest Host Facts and silently drop Host User Facts, so whether a
# machine's user inventory appeared depended on which path an artifact took.
# --------------------------------------------------------------------------


def test_no_ingest_path_calls_the_primitives_directly():
    """Every path goes through the combined helper, so none can forget a layer."""
    source = (tasks.__file__ or "").replace(".pyc", ".py")
    with open(source, encoding="utf-8") as handle:
        lines = handle.readlines()

    offenders = []
    for number, line in enumerate(lines, start=1):
        stripped = line.strip()
        if not stripped.startswith(("_safe_create_host_facts_isolated(", "_safe_create_host_user_facts_isolated(")):
            continue
        if stripped.startswith("def "):
            continue
        # Only the combined helper is allowed to call them.
        context = "".join(lines[max(0, number - 60):number])
        if "def _safe_create_derived_host_data_isolated" not in context:
            offenders.append(number)

    assert offenders == [], (
        f"Lines {offenders} call a Host Information primitive directly. "
        "Use _safe_create_derived_host_data_isolated so both layers stay in step."
    )


def test_the_combined_helper_derives_both_layers(monkeypatch):
    calls = []
    monkeypatch.setattr(tasks, "extract_host_fact_documents", lambda docs: [{"host_fact": {}}])
    monkeypatch.setattr(tasks, "extract_host_user_documents", lambda docs: [{"host_user_fact": {}}])
    monkeypatch.setattr(
        tasks, "_safe_create_host_facts_isolated", lambda **kw: calls.append("facts") or None
    )
    monkeypatch.setattr(
        tasks, "_safe_create_host_user_facts_isolated", lambda **kw: calls.append("users") or None
    )

    warnings = tasks._safe_create_derived_host_data_isolated(
        case_id="c", evidence_id="e", artifact_id="a",
        host_id="h", artifact_name="SAM", documents=[{"x": 1}],
    )

    assert calls == ["facts", "users"]
    assert warnings == []


def test_a_failure_in_one_layer_does_not_stop_the_other(monkeypatch):
    """Host Facts failing must not cost the case its user inventory."""
    monkeypatch.setattr(tasks, "extract_host_fact_documents", lambda docs: [{"host_fact": {}}])
    monkeypatch.setattr(tasks, "extract_host_user_documents", lambda docs: [{"host_user_fact": {}}])
    monkeypatch.setattr(tasks, "_safe_create_host_facts_isolated", lambda **kw: "disk full")
    created = []
    monkeypatch.setattr(
        tasks, "_safe_create_host_user_facts_isolated", lambda **kw: created.append(1) or None
    )

    warnings = tasks._safe_create_derived_host_data_isolated(
        case_id="c", evidence_id="e", artifact_id="a",
        host_id="h", artifact_name="SAM", documents=[{"x": 1}],
    )

    assert created == [1]
    assert warnings == ["host_facts: disk full"]


def test_an_empty_batch_does_no_work(monkeypatch):
    monkeypatch.setattr(tasks, "extract_host_fact_documents", lambda docs: pytest.fail("called"))

    assert tasks._safe_create_derived_host_data_isolated(
        case_id="c", evidence_id="e", artifact_id="a",
        host_id="h", artifact_name="SAM", documents=[],
    ) == []


# --------------------------------------------------------------------------
# Repairing a case that was ingested before the fix.
# --------------------------------------------------------------------------


class FakeClient:
    def __init__(self, pages):
        self.pages = list(pages)
        self.bodies = []

    def search(self, index=None, body=None, params=None, **kwargs):
        self.bodies.append(body)
        if not self.pages:
            return {"hits": {"hits": []}}
        return {"hits": {"hits": self.pages.pop(0)}}


def _hit(doc, sort_key):
    return {"_source": doc, "sort": [sort_key]}


class FakeDb:
    def __init__(self):
        self.commits = 0
        self.rollbacks = 0

    def query(self, *_a, **_k):
        return self

    def filter(self, *_a, **_k):
        return self

    def limit(self, *_a, **_k):
        return self

    def all(self):
        return []

    def commit(self):
        self.commits += 1

    def rollback(self):
        self.rollbacks += 1


def _patch(monkeypatch, client):
    monkeypatch.setattr(repair, "get_opensearch_client", lambda **kw: client)
    monkeypatch.setattr(repair, "get_events_index", lambda case_id=None: "idx")
    monkeypatch.setattr(repair, "index_exists", lambda c, i: True)


def test_rebuild_recreates_both_layers_from_indexed_events(monkeypatch):
    docs = [
        {"evidence_id": "ev1", "artifact": {"id": "a1"}, "host_user_fact": {"username": "tycos"}},
    ]
    _patch(monkeypatch, FakeClient([[_hit(docs[0], "1")]]))
    monkeypatch.setattr(repair, "extract_host_fact_documents", lambda d: [{"host_fact": {}}])
    monkeypatch.setattr(repair, "extract_host_user_documents", lambda d: [{"host_user_fact": {}}])
    monkeypatch.setattr(repair, "create_host_fact_observations", lambda db, **kw: ["f1", "f2"])
    monkeypatch.setattr(repair, "create_host_user_fact_observations", lambda db, **kw: ["u1"])

    result = repair.rebuild_host_information(FakeDb(), "case-1")

    assert result["scanned_events"] == 1
    assert result["host_facts_created"] == 2
    assert result["host_user_facts_created"] == 1
    assert result["warnings"] == []


def test_rebuild_groups_documents_per_artifact(monkeypatch):
    """Extractors run per artifact during ingest, so the repair must match."""
    page = [
        _hit({"evidence_id": "ev1", "artifact": {"id": "a1"}}, "1"),
        _hit({"evidence_id": "ev1", "artifact": {"id": "a2"}}, "2"),
    ]
    _patch(monkeypatch, FakeClient([page]))
    seen = []
    monkeypatch.setattr(repair, "extract_host_fact_documents", lambda d: seen.append(len(d)) or [])
    monkeypatch.setattr(repair, "extract_host_user_documents", lambda d: [])

    repair.rebuild_host_information(FakeDb(), "case-1")

    assert seen == [1, 1], "two artifacts must be extracted separately, not merged"


def test_one_bad_artifact_does_not_discard_the_rest(monkeypatch):
    _patch(monkeypatch, FakeClient([[_hit({"evidence_id": "ev1", "artifact": {"id": "a1"}}, "1")]]))
    monkeypatch.setattr(repair, "extract_host_fact_documents", lambda d: [{"host_fact": {}}])
    monkeypatch.setattr(repair, "extract_host_user_documents", lambda d: [{"host_user_fact": {}}])

    def explode(db, **kw):
        raise RuntimeError("bad document")

    monkeypatch.setattr(repair, "create_host_fact_observations", explode)
    monkeypatch.setattr(repair, "create_host_user_fact_observations", lambda db, **kw: ["u1"])
    db = FakeDb()

    result = repair.rebuild_host_information(db, "case-1")

    assert result["host_user_facts_created"] == 1, "the good layer must still be written"
    assert any("bad document" in w for w in result["warnings"])
    assert db.rollbacks == 1


def test_rebuild_on_an_unindexed_case_says_so(monkeypatch):
    monkeypatch.setattr(repair, "get_opensearch_client", lambda **kw: FakeClient([]))
    monkeypatch.setattr(repair, "get_events_index", lambda case_id=None: "idx")
    monkeypatch.setattr(repair, "index_exists", lambda c, i: False)

    result = repair.rebuild_host_information(FakeDb(), "case-1")

    assert result["scanned_events"] == 0
    assert "nothing to rebuild" in result["warnings"][0]


def test_rebuild_reads_only_candidate_events(monkeypatch):
    """A case can hold millions of events; the scan must be filtered."""
    client = FakeClient([])
    _patch(monkeypatch, client)

    repair.rebuild_host_information(FakeDb(), "case-1")

    query = client.bodies[0]["query"]["bool"]
    assert {"term": {"case_id": "case-1"}} in query["filter"]
    assert query["minimum_should_match"] == 1
    assert any("host_user_fact" in str(clause) for clause in query["should"])


def test_a_failing_scan_returns_rather_than_raising(monkeypatch):
    class Broken:
        def search(self, **kwargs):
            raise RuntimeError("cluster down")

    _patch(monkeypatch, Broken())

    result = repair.rebuild_host_information(FakeDb(), "case-1")

    assert result["scanned_events"] == 0


class HostRow:
    def __init__(self, host_id, display_name):
        self.id = host_id
        self.display_name = display_name
        self.canonical_name = display_name


class DbWithHosts(FakeDb):
    """Answers the evidence query and the host query separately."""

    def __init__(self, hosts):
        super().__init__()
        self._hosts = hosts
        self._wants_hosts = False

    def query(self, model=None, *_a, **_k):
        self._wants_hosts = getattr(model, "__name__", "") == "CaseHost"
        return self

    def all(self):
        return self._hosts if self._wants_hosts else []


class CoverageClient(FakeClient):
    def __init__(self, coverage_buckets):
        super().__init__([])
        self.coverage = coverage_buckets

    def search(self, index=None, body=None, params=None, **kwargs):
        self.bodies.append(body)
        if "aggs" in (body or {}):
            return {"hits": {"hits": []}, "aggregations": {"by_host": {"buckets": self.coverage}}}
        return {"hits": {"hits": []}}


def test_rebuild_reports_which_hosts_can_never_list_users(monkeypatch):
    """Pressing the button on such a host must not look like it did nothing."""
    client = CoverageClient([
        {"key": "DC02", "by_type": {"buckets": [{"key": "windows_sam_identity", "doc_count": 4}]}},
    ])
    _patch(monkeypatch, client)
    db = DbWithHosts([HostRow("h1", "WS01"), HostRow("h2", "DC02")])

    coverage = {row["host"]: row for row in repair.rebuild_host_information(db, "case-1")["hosts"]}

    assert coverage["WS01"]["has_identity_source"] is False
    assert coverage["WS01"]["identity_sources"] == {}
    assert coverage["DC02"]["has_identity_source"] is True
    assert coverage["DC02"]["identity_sources"]["windows_sam_identity"] == 4


def test_host_coverage_matching_ignores_case(monkeypatch):
    client = CoverageClient([
        {"key": "ws01", "by_type": {"buckets": [{"key": "windows_sam_identity", "doc_count": 1}]}},
    ])
    _patch(monkeypatch, client)
    db = DbWithHosts([HostRow("h1", "WS01")])

    coverage = repair.rebuild_host_information(db, "case-1")["hosts"]

    assert coverage[0]["has_identity_source"] is True


def test_a_failing_coverage_lookup_does_not_fail_the_rebuild(monkeypatch):
    class PartlyBroken(FakeClient):
        def search(self, index=None, body=None, params=None, **kwargs):
            if "aggs" in (body or {}):
                raise RuntimeError("aggregation unavailable")
            return {"hits": {"hits": []}}

    _patch(monkeypatch, PartlyBroken([]))
    db = DbWithHosts([HostRow("h1", "WS01")])

    result = repair.rebuild_host_information(db, "case-1")

    assert result["hosts"][0]["has_identity_source"] is False
