from __future__ import annotations

from types import SimpleNamespace

import pytest

from app.services import search_service


class _FakeClient:
    def __init__(self, hits=None):
        self.hits = hits or []
        self.last_kwargs = None

    def search(self, **kwargs):  # noqa: ANN003
        self.last_kwargs = kwargs
        return {"hits": {"total": {"value": len(self.hits)}, "hits": self.hits}}


class _FakeFindingQuery:
    def __init__(self, findings):
        self.findings = findings

    def filter(self, *args, **kwargs):
        return self

    def all(self):
        return list(self.findings)


class _FakeDb:
    def __init__(self, findings=None):
        self.findings = findings or []

    def query(self, model):  # noqa: ANN001
        return _FakeFindingQuery(self.findings)


def _finding(**overrides):
    finding = SimpleNamespace(
        id="finding-1",
        case_id="case-1",
        evidence_id="ev-1",
        finding_type="office_powershell",
        title="Office spawned PowerShell",
        description="EncodedCommand observed for powershell.exe",
        severity=SimpleNamespace(value="high"),
        status=SimpleNamespace(value="new"),
        confidence="high",
        source="sigma",
        risk_score=91,
        time_start=None,
        time_end=None,
        created_at=None,
        related_hosts=["TEST-WIN10-01"],
        related_users=["user01"],
        related_files=[r"C:\Users\user01\Downloads\invoice.docm"],
        related_domains=["suspicious.example"],
        related_ips=["203.0.113.10"],
        reasons=["Encoded PowerShell"],
        tags=["powershell"],
        related_event_ids=[],
        event_ids=[],
        related_process_node_ids=[],
        recommended_triage=[],
        data_quality=[],
    )
    for key, value in overrides.items():
        setattr(finding, key, value)
    return finding


def _event_hit(event_id: str, source: dict):
    return {"_id": event_id, "_source": source}


def test_advanced_field_query_builds_term_filter(monkeypatch: pytest.MonkeyPatch):
    client = _FakeClient([_event_hit("evt-1", {"event": {"type": "file_deleted_observed"}, "artifact": {"type": "ntfs"}, "risk_score": 80, "host": {"name": "TEST-WIN10-01"}})])
    monkeypatch.setattr(search_service, "get_opensearch_client", lambda: client)
    monkeypatch.setattr(search_service, "index_exists", lambda client, index: True)
    monkeypatch.setattr(search_service, "get_events_index", lambda case_id: "dfir-events-case-1")

    total, rows, warnings, _ = search_service.search_events_v2("case-1", search_service.build_search_v2_params(q="artifact.type:ntfs", page_size=10))

    assert total == 1
    assert rows[0]["artifact_type"] == "ntfs"
    query = client.last_kwargs["body"]["query"]["bool"]["must"][0]
    assert query["term"]["artifact.type"] == "ntfs"


def test_mixed_query_returns_metadata(monkeypatch: pytest.MonkeyPatch):
    client = _FakeClient([])
    monkeypatch.setattr(search_service, "get_opensearch_client", lambda: client)
    monkeypatch.setattr(search_service, "index_exists", lambda client, index: True)
    monkeypatch.setattr(search_service, "get_events_index", lambda case_id: "dfir-events-case-1")

    response = search_service.search_case_v2(_FakeDb(), "case-1", search_service.build_search_v2_params(scope="events", q="artifact.type:user_activity EncodedCommand", page_size=10))

    assert response["query_syntax"]["mode"] == "mixed"
    assert response["query_syntax"]["applied_filters"] == [{"field": "artifact.type", "operator": ":", "value": "user_activity"}]
    body = client.last_kwargs["body"]
    assert {"term": {"case_id": "case-1"}} in body["query"]["bool"]["filter"]


def test_numeric_and_boolean_query(monkeypatch: pytest.MonkeyPatch):
    client = _FakeClient([])
    monkeypatch.setattr(search_service, "get_opensearch_client", lambda: client)
    monkeypatch.setattr(search_service, "index_exists", lambda client, index: True)
    monkeypatch.setattr(search_service, "get_events_index", lambda case_id: "dfir-events-case-1")

    search_service.search_events_v2("case-1", search_service.build_search_v2_params(q="artifact.type:ntfs AND risk_score>=70", page_size=10))
    must = client.last_kwargs["body"]["query"]["bool"]["must"][0]["bool"]["must"]
    assert must[0] == {"term": {"artifact.type": "ntfs"}}
    assert must[1] == {"range": {"risk_score": {"gte": 70}}}


def test_or_query_builds_should(monkeypatch: pytest.MonkeyPatch):
    client = _FakeClient([])
    monkeypatch.setattr(search_service, "get_opensearch_client", lambda: client)
    monkeypatch.setattr(search_service, "index_exists", lambda client, index: True)
    monkeypatch.setattr(search_service, "get_events_index", lambda case_id: "dfir-events-case-1")

    search_service.search_events_v2("case-1", search_service.build_search_v2_params(q="process.name:powershell.exe OR process.name:cmd.exe", page_size=10))
    query = client.last_kwargs["body"]["query"]["bool"]["must"][0]["bool"]
    assert query["minimum_should_match"] == 1
    assert len(query["should"]) == 2


def test_not_query_builds_must_not(monkeypatch: pytest.MonkeyPatch):
    client = _FakeClient([])
    monkeypatch.setattr(search_service, "get_opensearch_client", lambda: client)
    monkeypatch.setattr(search_service, "index_exists", lambda client, index: True)
    monkeypatch.setattr(search_service, "get_events_index", lambda case_id: "dfir-events-case-1")

    search_service.search_events_v2("case-1", search_service.build_search_v2_params(q="artifact.type:ntfs NOT file.extension:.pdf", page_size=10))
    query = client.last_kwargs["body"]["query"]["bool"]["must"][0]["bool"]["must"][1]
    assert query["bool"]["must_not"][0] == {"term": {"file.extension": ".pdf"}}


def test_alias_and_wildcard_query(monkeypatch: pytest.MonkeyPatch):
    client = _FakeClient([])
    monkeypatch.setattr(search_service, "get_opensearch_client", lambda: client)
    monkeypatch.setattr(search_service, "index_exists", lambda client, index: True)
    monkeypatch.setattr(search_service, "get_events_index", lambda case_id: "dfir-events-case-1")

    search_service.search_events_v2("case-1", search_service.build_search_v2_params(q="artifact:windows_ui AND file.name:*.exe AND risk>=70", page_size=10))
    must = client.last_kwargs["body"]["query"]["bool"]["must"][0]["bool"]["must"]
    assert must[0] == {"term": {"artifact.type": "windows_ui"}}
    assert must[1]["wildcard"]["file.name"]["value"] == "*.exe"
    assert must[2] == {"range": {"risk_score": {"gte": 70}}}


def test_stable_event_id_query_is_supported(monkeypatch: pytest.MonkeyPatch):
    client = _FakeClient([])
    monkeypatch.setattr(search_service, "get_opensearch_client", lambda: client)
    monkeypatch.setattr(search_service, "index_exists", lambda client, index: True)
    monkeypatch.setattr(search_service, "get_events_index", lambda case_id: "dfir-events-case-1")

    search_service.search_events_v2("case-1", search_service.build_search_v2_params(q="stable_event_id:abc123", page_size=10))
    query = client.last_kwargs["body"]["query"]["bool"]["must"][0]
    assert query == {"term": {"stable_event_id": "abc123"}}


def test_has_field_query(monkeypatch: pytest.MonkeyPatch):
    client = _FakeClient([])
    monkeypatch.setattr(search_service, "get_opensearch_client", lambda: client)
    monkeypatch.setattr(search_service, "index_exists", lambda client, index: True)
    monkeypatch.setattr(search_service, "get_events_index", lambda case_id: "dfir-events-case-1")

    search_service.search_events_v2("case-1", search_service.build_search_v2_params(q="has:file.path", page_size=10))
    query = client.last_kwargs["body"]["query"]["bool"]["must"][0]
    assert query == {"exists": {"field": "file.path"}}


def test_invalid_field_returns_http_400(monkeypatch: pytest.MonkeyPatch):
    client = _FakeClient([])
    monkeypatch.setattr(search_service, "get_opensearch_client", lambda: client)
    monkeypatch.setattr(search_service, "index_exists", lambda client, index: True)
    monkeypatch.setattr(search_service, "get_events_index", lambda case_id: "dfir-events-case-1")

    with pytest.raises(Exception) as exc:
        search_service.search_events_v2("case-1", search_service.build_search_v2_params(q="unknown.field:value", page_size=10))
    assert "Invalid search query" in str(exc.value.detail)


def test_unclosed_quote_returns_http_400(monkeypatch: pytest.MonkeyPatch):
    client = _FakeClient([])
    monkeypatch.setattr(search_service, "get_opensearch_client", lambda: client)
    monkeypatch.setattr(search_service, "index_exists", lambda client, index: True)
    monkeypatch.setattr(search_service, "get_events_index", lambda case_id: "dfir-events-case-1")

    with pytest.raises(Exception) as exc:
        search_service.search_events_v2("case-1", search_service.build_search_v2_params(q='file.name:"invoice.docm', page_size=10))
    assert "unclosed quote" in str(exc.value.detail).lower()


def test_findings_scope_respects_advanced_query():
    response = search_service.search_case_v2(
        _FakeDb([_finding(), _finding(id="finding-2", related_hosts=["OTHER"], risk_score=20, title="Benign", description="notepad.exe", related_files=[r"C:\Temp\readme.txt"])]),
        "case-1",
        search_service.build_search_v2_params(scope="findings", q='host.name:"TEST-WIN10-01" risk_score>=70'),
    )
    assert response["total"] == 1
    assert response["results"][0]["id"] == "finding-1"
