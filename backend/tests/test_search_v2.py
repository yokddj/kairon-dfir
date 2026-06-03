from __future__ import annotations

from datetime import UTC, datetime
from types import SimpleNamespace

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from app.core.database import Base
from app.models.case import Case
from app.models.detection_result import DetectionResult
from app.models.evidence import Evidence, EvidenceType
from app.api import routes_search
from app.services import search_service
from app.services import host_identity


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

    def get(self, model, identifier):  # noqa: ANN001
        for item in self.findings:
            if getattr(item, "id", None) == identifier:
                return item
        return None


def _finding(**overrides):
    base = SimpleNamespace(
        id="finding-1",
        case_id="case-1",
        evidence_id="ev-1",
        finding_type="download_execute_detect",
        title="payload.exe executed",
        description="Downloaded file later executed and detected.",
        severity=SimpleNamespace(value="high"),
        status=SimpleNamespace(value="new"),
        confidence="high",
        source="correlation_engine",
        risk_score=90,
        time_start=datetime(2026, 5, 15, 10, 0, tzinfo=UTC),
        time_end=datetime(2026, 5, 15, 10, 10, tzinfo=UTC),
        related_event_ids=["evt-1", "evt-2"],
        event_ids=["evt-1", "evt-2"],
        related_files=["C:\\Users\\dfir\\Downloads\\payload.exe"],
        related_domains=["raw.githubusercontent.com"],
        related_ips=["185.10.10.10"],
        related_users=["dfir"],
        related_hosts=["desktop-1"],
        reasons=["Downloaded file later executed"],
        tags=["download"],
        recommended_triage=["review process tree"],
        data_quality=[],
        created_at=datetime(2026, 5, 16, 9, 0, tzinfo=UTC),
    )
    for key, value in overrides.items():
        setattr(base, key, value)
    return base


def test_detect_ioc_hash():
    assert search_service.detect_ioc_type("a" * 64) == "sha256"


def test_detect_ioc_ipv4():
    assert search_service.detect_ioc_type("185.10.10.10") == "ipv4"


def test_detect_ioc_domain():
    assert search_service.detect_ioc_type("raw.githubusercontent.com") == "domain"


def test_detect_ioc_windows_path():
    assert search_service.detect_ioc_type(r"C:\Users\dfir\Downloads\payload.exe") == "windows_path"


def test_search_findings_scope_filters_status_and_severity():
    db = _FakeDb(
        [
          _finding(id="high-new", status=SimpleNamespace(value="new"), severity=SimpleNamespace(value="high")),
          _finding(id="medium-confirmed", status=SimpleNamespace(value="confirmed"), severity=SimpleNamespace(value="medium")),
        ]
    )
    result = search_service.search_case_v2(db, "case-1", search_service.build_search_v2_params(scope="findings", severity=["high"], status=["new"], page_size=50))
    assert result["total"] == 1
    assert result["results"][0]["id"] == "high-new"


def test_search_related_to_finding_not_found():
    with pytest.raises(Exception):
        search_service.search_related_to_finding(_FakeDb([]), "case-1", "missing")


def test_query_safety_truncates_and_sanitizes():
    normalized, warnings = search_service.normalize_search_value("*" * 20 + "A" * 600)
    assert normalized
    assert "query_truncated" in warnings
    assert "wildcards_sanitized" in warnings


def test_search_events_uses_numeric_request_timeout(monkeypatch: pytest.MonkeyPatch):
    captured: dict[str, object] = {}

    class _FakeClient:
        def search(self, **kwargs):  # noqa: ANN003
            captured.update(kwargs)
            return {"hits": {"total": {"value": 0}, "hits": []}}

    monkeypatch.setattr(search_service, "get_opensearch_client", lambda: _FakeClient())
    monkeypatch.setattr(search_service, "index_exists", lambda client, index: True)
    monkeypatch.setattr(search_service, "get_events_index", lambda case_id: "dfir-events-case-1")

    result_total, result_rows, result_warnings, result_facets = search_service.search_events_v2(
        "case-1",
        search_service.build_search_v2_params(q="payload.exe", page_size=10),
    )

    assert result_total == 0
    assert result_rows == []
    assert result_warnings == []
    assert result_facets["artifact_type"] == {}
    assert captured["request_timeout"] == search_service.SEARCH_REQUEST_TIMEOUT_SECONDS
    assert captured["params"] == {"ignore_unavailable": "true"}


def test_build_event_filters_expands_host_aliases(monkeypatch: pytest.MonkeyPatch):
    engine = create_engine("sqlite:///:memory:", future=True, connect_args={"check_same_thread": False})
    Base.metadata.create_all(bind=engine)
    Session = sessionmaker(bind=engine, autoflush=False, autocommit=False, expire_on_commit=False, future=True)
    db = Session()
    db.add(Case(id="a1111111-1111-4111-8111-111111111111", name="Case 1"))
    db.commit()
    monkeypatch.setattr(
        host_identity,
        "_observed_host_counts",
        lambda _db, _case_id: {
            "pc02.example.corp": {"event_count": 8, "findings_count": 0, "high_risk_count": 0, "evidence_ids": ["ev-1"], "first_seen": None, "last_seen": None},
            "pc02": {"event_count": 3, "findings_count": 0, "high_risk_count": 0, "evidence_ids": ["ev-1"], "first_seen": None, "last_seen": None},
        },
    )
    hosts = host_identity.get_case_hosts(db, "a1111111-1111-4111-8111-111111111111")
    canonical_id = next(item["id"] for item in hosts if item["canonical_name"] == "pc02.example.corp")
    host_identity.merge_hosts(db, "a1111111-1111-4111-8111-111111111111", canonical_id, ["pc02"], reason="fqdn and short host")

    filters = search_service._build_event_filters("a1111111-1111-4111-8111-111111111111", {"host": "pc02.example.corp"}, db)
    host_filter = next(item for item in filters if "bool" in item and "should" in item["bool"])
    expanded = host_filter["bool"]["should"][0]["terms"]["host.name"]

    assert expanded == ["pc02", "pc02.example.corp"]


def test_build_event_filters_uses_evidence_host_fallback() -> None:
    engine = create_engine("sqlite:///:memory:", future=True, connect_args={"check_same_thread": False})
    Base.metadata.create_all(bind=engine)
    Session = sessionmaker(bind=engine, autoflush=False, autocommit=False, expire_on_commit=False, future=True)
    db = Session()
    db.add(Case(id="b1111111-1111-4111-8111-111111111111", name="Case 1"))
    db.add(
        Evidence(
            id="b2222222-2222-4222-8222-222222222222",
            case_id="b1111111-1111-4111-8111-111111111111",
            original_filename="evidence.zip",
            stored_path="/tmp/evidence.zip",
            evidence_type=EvidenceType.raw_collection,
            sha256="a" * 64,
            size_bytes=1,
            detected_host="hosta.examplecorp.local",
            metadata_json={"provided_host": "HOSTA"},
        )
    )
    db.commit()

    filters = search_service._build_event_filters("b1111111-1111-4111-8111-111111111111", {"host": "HOSTA"}, db)
    host_filter = next(item for item in filters if "bool" in item and "should" in item["bool"])

    terms = next(item["terms"]["host.name"] for item in host_filter["bool"]["should"] if item.get("terms", {}).get("host.name"))
    assert "hosta" in terms
    assert "hosta.examplecorp.local" in terms
    assert any(item.get("bool", {}).get("filter") == [{"terms": {"evidence_id": ["b2222222-2222-4222-8222-222222222222"]}}] for item in host_filter["bool"]["should"])


def test_format_event_result_uses_provided_host_for_missing_artifact_host() -> None:
    engine = create_engine("sqlite:///:memory:", future=True, connect_args={"check_same_thread": False})
    Base.metadata.create_all(bind=engine)
    Session = sessionmaker(bind=engine, autoflush=False, autocommit=False, expire_on_commit=False, future=True)
    db = Session()
    db.add(Case(id="c1111111-1111-4111-8111-111111111111", name="Case 1"))
    db.add(
        Evidence(
            id="c2222222-2222-4222-8222-222222222222",
            case_id="c1111111-1111-4111-8111-111111111111",
            original_filename="evidence.zip",
            stored_path="/tmp/evidence.zip",
            evidence_type=EvidenceType.raw_collection,
            sha256="b" * 64,
            size_bytes=1,
            metadata_json={"provided_host": "HOSTA"},
        )
    )
    db.commit()

    result = search_service._format_event_result(
        {
            "_id": "event-1",
            "_source": {
                "case_id": "c1111111-1111-4111-8111-111111111111",
                "evidence_id": "c2222222-2222-4222-8222-222222222222",
                "host": {"name": "-"},
                "artifact": {"type": "prefetch", "parser": "prefetch_internal"},
                "event": {"type": "execution", "message": "App executed"},
            },
        },
        case_id="c1111111-1111-4111-8111-111111111111",
        db=db,
    )

    assert result["host"] == "HOSTA"
    assert result["raw"]["host"]["source"] == "provided_host"
    assert result["raw"]["host"]["confidence"] == "evidence_scope"
    assert result["raw"]["host"]["original_value"] == "-"


def test_format_event_result_groups_fqdn_alias_to_provided_host() -> None:
    engine = create_engine("sqlite:///:memory:", future=True, connect_args={"check_same_thread": False})
    Base.metadata.create_all(bind=engine)
    Session = sessionmaker(bind=engine, autoflush=False, autocommit=False, expire_on_commit=False, future=True)
    db = Session()
    db.add(Case(id="e1111111-1111-4111-8111-111111111111", name="Case 1"))
    db.add(
        Evidence(
            id="e2222222-2222-4222-8222-222222222222",
            case_id="e1111111-1111-4111-8111-111111111111",
            original_filename="evidence.zip",
            stored_path="/tmp/evidence.zip",
            evidence_type=EvidenceType.raw_collection,
            sha256="e" * 64,
            size_bytes=1,
            detected_host="hosta.examplecorp.local",
            metadata_json={"provided_host": "HOSTA"},
        )
    )
    db.commit()

    result = search_service._format_event_result(
        {
            "_id": "event-1",
            "_source": {
                "case_id": "e1111111-1111-4111-8111-111111111111",
                "evidence_id": "e2222222-2222-4222-8222-222222222222",
                "host": {"name": "hosta.examplecorp.local"},
                "artifact": {"type": "windows_event", "parser": "evtxecmd_csv"},
                "event": {"type": "process_start", "message": "Process created"},
            },
        },
        case_id="e1111111-1111-4111-8111-111111111111",
        db=db,
    )

    assert result["host"] == "HOSTA"
    assert result["raw"]["host"]["canonical"] == "HOSTA"
    assert result["raw"]["host"]["original_value"] == "hosta.examplecorp.local"


def test_host_canonicalization_preserves_template_as_original() -> None:
    result = host_identity.canonicalize_host(provided_host="HOSTA", artifact_host="template")

    assert result["canonical"] == "HOSTA"
    assert result["original"] == "template"
    assert result["source"] == "provided_host"
    assert result["confidence"] == "evidence_scope"
    assert result["conflict"] is False
    assert "hosta" in result["aliases"]
    assert "template" not in result["aliases"]


def test_apply_case_host_identity_uses_provided_host_as_canonical() -> None:
    engine = create_engine("sqlite:///:memory:", future=True, connect_args={"check_same_thread": False})
    Base.metadata.create_all(bind=engine)
    Session = sessionmaker(bind=engine, autoflush=False, autocommit=False, expire_on_commit=False, future=True)
    db = Session()
    db.add(Case(id="d1111111-1111-4111-8111-111111111111", name="Case 1"))
    db.add(
        Evidence(
            id="d2222222-2222-4222-8222-222222222222",
            case_id="d1111111-1111-4111-8111-111111111111",
            original_filename="evidence.zip",
            stored_path="/tmp/evidence.zip",
            evidence_type=EvidenceType.raw_collection,
            sha256="d" * 64,
            size_bytes=1,
            detected_host="HOSTA.examplecorp.local",
            metadata_json={"provided_host": "HOSTA"},
        )
    )
    db.commit()

    event = {
        "case_id": "d1111111-1111-4111-8111-111111111111",
        "evidence_id": "d2222222-2222-4222-8222-222222222222",
        "host": {"name": "OTHERHOST"},
    }

    host_identity.apply_case_host_identity(db, "d1111111-1111-4111-8111-111111111111", event)

    assert event["host"]["name"] == "HOSTA"
    assert event["host"]["canonical"] == "HOSTA"
    assert event["host"]["original"] == "OTHERHOST"
    assert event["host"]["conflict"] is True
    assert "hosta.examplecorp.local" in event["host"]["aliases"]
    assert "otherhost" in event["host"]["aliases"]


def test_build_event_filters_keeps_suspicious_timestamps_searchable() -> None:
    filters = search_service._build_event_filters("case-1", {}, _FakeDb())
    assert not any(
        item.get("bool", {}).get("must_not")
        and item["bool"]["must_not"][0].get("terms", {}).get("timestamp_status") == ["invalid", "suspicious"]
        for item in filters
    )


def test_build_event_filters_excludes_suspicious_timestamps_for_timeline_only() -> None:
    filters = search_service._build_event_filters("case-1", {"timeline_only": True}, _FakeDb())
    sanity_filter = next(
        item
        for item in filters
        if item.get("range", {}).get("@timestamp")
    )
    timestamp_range = sanity_filter["range"]["@timestamp"]
    assert "lte" in timestamp_range
    status_filter = next(item for item in filters if item.get("bool", {}).get("must_not") and "terms" in item["bool"]["must_not"][0])
    assert status_filter["bool"]["must_not"][0]["terms"]["timestamp_status"] == ["invalid", "suspicious"]


def test_format_event_result_preserves_but_sanitizes_suspicious_timestamp() -> None:
    result = search_service._format_event_result(
        {
            "_id": "event-1",
            "_source": {
                "case_id": "case-1",
                "@timestamp": "2124-01-01T00:00:00Z",
                "artifact": {"type": "scheduled_task", "parser": "scheduled_task_csv"},
                "event": {"message": "Impossible Future Task", "type": "task"},
                "source_file": "C:\\Windows\\System32\\Tasks\\Impossible Future Task",
            },
        }
    )

    assert result["timestamp"] is None
    assert result["raw"]["timestamp_original"] == "2124-01-01T00:00:00Z"
    assert result["raw"]["raw_timestamp"] == "2124-01-01T00:00:00Z"
    assert result["raw"]["timestamp_status"] == "suspicious"
    assert result["raw"]["timestamp_warning"] == "future_out_of_range"
    assert "@timestamp" not in result["raw"]


def test_empty_search_facets_include_ui_aliases() -> None:
    facets = routes_search._empty_search_facets()
    assert "artifact.type" in facets
    assert "artifact_type" in facets
    assert "artifact.parser" in facets
    assert "parser" in facets
    assert facets["artifact_type"] == {}


def test_build_search_v2_params_keeps_parser_and_source_file() -> None:
    params = search_service.build_search_v2_params(
        artifact_type=["browser"],
        parser=["browser_chromium_history", "browser_chromium_history"],
        exclude_artifact_type=["mft", "mft"],
        exclude_parser=["evtx_raw_python"],
        source_file="History",
    )
    assert params["artifact_type"] == ["browser"]
    assert params["parser"] == ["browser_chromium_history"]
    assert params["exclude_artifact_type"] == ["mft"]
    assert params["exclude_parser"] == ["evtx_raw_python"]
    assert params["source_file"] == "History"


def test_build_event_filters_supports_parser_and_source_file() -> None:
    filters = search_service._build_event_filters(
        "case-1",
        {
            "artifact_type": ["browser"],
            "parser": ["browser_chromium_history"],
            "source_file": "History",
        },
        None,
    )
    assert {"terms": {"artifact.type": ["browser"]}} in filters
    assert {"terms": {"artifact.parser": ["browser_chromium_history"]}} in filters
    source_filter = next(item for item in filters if item.get("bool", {}).get("should") and {"term": {"source_file": "History"}} in item["bool"]["should"])
    assert {"wildcard": {"source_file": {"value": "*History*", "case_insensitive": True}}} in source_filter["bool"]["should"]


def test_build_event_filters_excludes_advanced_backend_by_default() -> None:
    filters = search_service._build_event_filters("case-1", {"artifact_type": ["amcache"]}, None)
    assert {"bool": {"must_not": [{"term": {"artifact.backend_variant": "advanced"}}]}} in filters


def test_build_event_filters_can_select_advanced_backend() -> None:
    filters = search_service._build_event_filters(
        "case-1",
        {"artifact_type": ["amcache"], "backend_variant": ["advanced"], "parser_backend": ["amcacheparser_csv"]},
        None,
    )
    assert {"terms": {"artifact.backend_variant": ["advanced"]}} in filters
    assert {"terms": {"artifact.parser_backend": ["amcacheparser_csv"]}} in filters
    assert {"bool": {"must_not": [{"term": {"artifact.backend_variant": "advanced"}}]}} not in filters


def test_build_event_filters_can_compare_all_backends() -> None:
    filters = search_service._build_event_filters("case-1", {"artifact_type": ["amcache"], "backend_variant": ["all"]}, None)
    assert {"terms": {"artifact.backend_variant": ["all"]}} not in filters
    assert {"bool": {"must_not": [{"term": {"artifact.backend_variant": "advanced"}}]}} not in filters


def test_build_event_filters_source_file_accepts_basename_substring() -> None:
    filters = search_service._build_event_filters("case-1", {"source_file": "Security.evtx"}, None)
    source_filter = next(item for item in filters if item.get("bool", {}).get("should") and {"term": {"source_file": "Security.evtx"}} in item["bool"]["should"])
    assert {"wildcard": {"source_file": {"value": "*Security.evtx*", "case_insensitive": True}}} in source_filter["bool"]["should"]


def test_build_event_exclusions_supports_negative_filters() -> None:
    exclusions = search_service._build_event_exclusions(
        "case-1",
        {
            "exclude_artifact_type": ["mft"],
            "exclude_parser": ["evtx_raw_python"],
            "exclude_source_file": "Security.evtx",
            "exclude_host": "desktop-1",
            "exclude_user": "svc",
            "exclude_q": "defender",
        },
        None,
    )
    assert {"terms": {"artifact.type": ["mft"]}} in exclusions
    assert {"terms": {"artifact.parser": ["evtx_raw_python"]}} in exclusions
    assert {"term": {"user.name": "svc"}} in exclusions
    assert any(item.get("bool", {}).get("should") and {"term": {"source_file": "Security.evtx"}} in item["bool"]["should"] for item in exclusions)
    assert any(item.get("bool", {}).get("should") and {"terms": {"host.name": ["desktop-1"]}} in item["bool"]["should"] for item in exclusions)
    assert any("simple_query_string" in item or item.get("bool") for item in exclusions)


def test_filter_builder_include_artifact_type() -> None:
    filters = search_service._build_event_filters(
        "case-1",
        {"filters": '[{"field":"artifact.type","operator":"is","value":"windows_event"}]'},
        None,
    )
    assert {"terms": {"artifact.type": ["windows_event"]}} in filters


def test_filter_builder_exclude_artifact_type() -> None:
    exclusions = search_service._build_event_exclusions(
        "case-1",
        {"filters": '[{"field":"artifact.type","operator":"is","value":"mft","negate":true}]'},
        None,
    )
    assert {"terms": {"artifact.type": ["mft"]}} in exclusions


def test_filter_builder_contains_process_command_line() -> None:
    filters = search_service._build_event_filters(
        "case-1",
        {"filters": '[{"field":"process.command_line","operator":"contains","value":"powershell"}]'},
        None,
    )
    assert {"bool": {"should": [{"wildcard": {"process.command_line": {"value": "*powershell*", "case_insensitive": True}}}], "minimum_should_match": 1}} in filters


def _wildcard_values(query: dict) -> list[str]:
    values: list[str] = []

    def walk(value):  # noqa: ANN001
        if isinstance(value, dict):
            wildcard = value.get("wildcard")
            if isinstance(wildcard, dict):
                for clause in wildcard.values():
                    if isinstance(clause, dict) and "value" in clause:
                        values.append(str(clause["value"]))
            for child in value.values():
                walk(child)
        elif isinstance(value, list):
            for child in value:
                walk(child)

    walk(query)
    return values


def test_search_command_phrase_treats_hyphen_flags_as_text() -> None:
    query = search_service._build_text_query("powershell -ep bypass")
    values = _wildcard_values(query)

    assert "*powershell -ep bypass*" in values
    assert "*ep*" not in values
    assert not any("simple_query_string" in str(item) for item in [query])


def test_search_command_phrase_expands_windows_path_basename() -> None:
    query = search_service._build_text_query(r"/c C:\Users\public\psexec.exe")
    values = _wildcard_values(query)

    assert any("psexec.exe" in value for value in values)
    assert any("/c c:" in value or r"\\c:" in value for value in values)


def test_filter_builder_supports_object_access_fields() -> None:
    filters = search_service._build_event_filters(
        "case-1",
        {
            "filters": (
                '[{"field":"object.name","operator":"contains","value":"secret.txt"},'
                '{"field":"access.list","operator":"contains","value":"ReadData"}]'
            )
        },
        None,
    )

    assert {
        "bool": {
            "should": [
                {"wildcard": {"object.name": {"value": "*secret.txt*", "case_insensitive": True}}},
                {"wildcard": {"object.path": {"value": "*secret.txt*", "case_insensitive": True}}},
            ],
            "minimum_should_match": 1,
        }
    } in filters
    assert {
        "bool": {
            "should": [
                {"wildcard": {"access.list": {"value": "*ReadData*", "case_insensitive": True}}},
                {"wildcard": {"access.accesses": {"value": "*ReadData*", "case_insensitive": True}}},
            ],
            "minimum_should_match": 1,
        }
    } in filters


def test_filter_builder_message_does_not_contain() -> None:
    exclusions = search_service._build_event_exclusions(
        "case-1",
        {"filters": '[{"field":"message","operator":"does not contain","value":"defender"}]'},
        None,
    )
    assert any(item.get("bool", {}).get("should") for item in exclusions)


def test_filter_builder_windows_event_id_number() -> None:
    filters = search_service._build_event_filters(
        "case-1",
        {"filters": '[{"field":"windows.event_id","operator":"is","value":"4688"}]'},
        None,
    )
    assert {"term": {"windows.event_id": 4688}} in filters


def test_filter_builder_exists_and_does_not_exist() -> None:
    filters = search_service._build_event_filters("case-1", {"filters": '[{"field":"host.name","operator":"exists","value":""}]'}, None)
    exclusions = search_service._build_event_exclusions("case-1", {"filters": '[{"field":"user.name","operator":"does not exist","value":""}]'}, None)
    assert {"bool": {"should": [{"exists": {"field": "host.name"}}], "minimum_should_match": 1}} in filters
    assert {"bool": {"should": [{"exists": {"field": "user.name"}}], "minimum_should_match": 1}} in exclusions


def test_search_events_v2_applies_must_not(monkeypatch: pytest.MonkeyPatch) -> None:
    captured: dict[str, object] = {}

    class _FakeClient:
        def search(self, **kwargs):  # noqa: ANN003
            captured.update(kwargs)
            return {"hits": {"total": {"value": 0}, "hits": []}}

    monkeypatch.setattr(search_service, "get_opensearch_client", lambda: _FakeClient())
    monkeypatch.setattr(search_service, "index_exists", lambda client, index: True)
    monkeypatch.setattr(search_service, "get_events_index", lambda case_id: "dfir-events-case-1")

    search_service.search_events_v2(
        "case-1",
        search_service.build_search_v2_params(
            artifact_type=["windows_event"],
            exclude_artifact_type=["mft"],
            exclude_source_file="Security.evtx",
            q="powershell",
            exclude_q="defender",
            time_from="2026-05-15T10:00:00Z",
            time_to="2026-05-15T11:00:00Z",
            page_size=10,
        ),
    )

    bool_query = captured["body"]["query"]["bool"]
    assert {"terms": {"artifact.type": ["windows_event"]}} in bool_query["filter"]
    assert {"range": {"@timestamp": {"gte": "2026-05-15T10:00:00+00:00", "lte": "2026-05-15T11:00:00+00:00"}}} in bool_query["filter"]
    assert {"terms": {"artifact.type": ["mft"]}} in bool_query["must_not"]
    assert any(item.get("bool", {}).get("should") and {"term": {"source_file": "Security.evtx"}} in item["bool"]["should"] for item in bool_query["must_not"])


def test_search_events_v2_uses_global_backend_sort_and_full_total(monkeypatch: pytest.MonkeyPatch) -> None:
    captured: dict[str, object] = {}

    class _FakeClient:
        def search(self, **kwargs):  # noqa: ANN003
            captured.update(kwargs)
            return {"hits": {"total": {"value": 25000, "relation": "eq"}, "hits": []}}

    monkeypatch.setattr(search_service, "get_opensearch_client", lambda: _FakeClient())
    monkeypatch.setattr(search_service, "index_exists", lambda client, index: True)
    monkeypatch.setattr(search_service, "get_events_index", lambda case_id: "dfir-events-case-1")

    total, _, _, _ = search_service.search_events_v2(
        "case-1",
        search_service.build_search_v2_params(sort="timestamp_asc", page=2, page_size=10),
    )

    body = captured["body"]
    assert total == 25000
    assert body["from"] == 10
    assert body["track_total_hits"] is True
    assert body["sort"] == search_service.EVENT_SORTS["timestamp_asc"]


def test_search_all_scope_page_two_fetches_enough_events_for_offset(monkeypatch: pytest.MonkeyPatch) -> None:
    captured_bodies: list[dict[str, object]] = []

    class _FakeClient:
        def search(self, **kwargs):  # noqa: ANN003
            body = kwargs["body"]
            captured_bodies.append(body)
            size = int(body["size"])
            hits = [
                {
                    "_id": f"evt-{index}",
                    "_source": {
                        "case_id": "case-1",
                        "event_id": f"evt-{index}",
                        "@timestamp": f"2024-03-22T11:{21 + (index // 60):02d}:{index % 60:02d}+00:00",
                        "artifact": {"type": "windows_event", "parser": "evtxecmd_csv"},
                        "event": {"type": "process_start", "severity": "low", "message": f"event {index}"},
                        "host": {"name": "hosta"},
                        "source_file": "Security.evtx",
                    },
                }
                for index in range(size)
            ]
            return {"hits": {"total": {"value": 2684, "relation": "eq"}, "hits": hits}}

    monkeypatch.setattr(search_service, "get_opensearch_client", lambda: _FakeClient())
    monkeypatch.setattr(search_service, "index_exists", lambda client, index: True)
    monkeypatch.setattr(search_service, "get_events_index", lambda case_id: "dfir-events-case-1")

    result = search_service.search_case_v2(
        _FakeDb(),
        "case-1",
        search_service.build_search_v2_params(
            scope="all",
            evidence_id="ev-1",
            sort="timestamp_asc",
            time_from="2024-03-22T11:21:00Z",
            time_to="2024-03-22T11:31:00Z",
            page=2,
            page_size=200,
        ),
    )

    assert captured_bodies[0]["from"] == 0
    assert captured_bodies[0]["size"] == 400
    assert result["total"] == 2684
    assert result["page"] == 2
    assert result["page_size"] == 200
    assert result["items_count"] == 200
    assert len(result["results"]) == 200
    assert result["debug_pagination"]["from"] == 200
    assert result["debug_pagination"]["search_after_used"] is False
    assert result["pagination_mode"] == "offset"
    assert result["results"][0]["id"] == "evt-200"


def test_event_context_returns_available_fields_and_linked_counts(monkeypatch: pytest.MonkeyPatch) -> None:
    engine = create_engine("sqlite:///:memory:", future=True, connect_args={"check_same_thread": False})
    Base.metadata.create_all(bind=engine)
    Session = sessionmaker(bind=engine, autoflush=False, autocommit=False, expire_on_commit=False, future=True)
    db = Session()
    case_id = "d1111111-1111-4111-8111-111111111111"
    db.add(Case(id=case_id, name="Case 1"))
    db.add(
        DetectionResult(
            id="d2222222-2222-4222-8222-222222222222",
            case_id=case_id,
            evidence_id=None,
            engine="sigma",
            rule_name="Suspicious PowerShell",
            event_id="evt-1",
            opensearch_id="evt-1",
            target_type="event",
            status="new",
            matched_fields={},
            matched_strings=[],
            false_positives=[],
            references=[],
            tags=[],
            mitre=[],
            related_event_ids=[],
            related_finding_ids=[],
            related_iocs={},
            data_quality=[],
            raw={},
        )
    )
    db.add(
        search_service.Finding(
            id="d3333333-3333-4333-8333-333333333333",
            case_id=case_id,
            title="PowerShell finding",
            severity=search_service.FindingSeverity.high,
            status=search_service.FindingStatus.new,
            event_ids=["evt-1"],
            related_event_ids=["evt-1"],
        )
    )
    db.commit()
    monkeypatch.setattr(
        search_service,
        "fetch_event_by_id",
        lambda *args, **kwargs: {
            "event_id": "evt-1",
            "@timestamp": "2026-05-15T10:00:00Z",
            "evidence_id": "ev-1",
            "artifact": {"type": "windows_event", "parser": "evtxecmd_csv"},
            "host": {"name": "HOSTA"},
            "user": {"name": "usera"},
            "process": {"name": "powershell.exe", "pid": 4242, "command_line": "powershell.exe -enc AAAA", "parent_name": "explorer.exe"},
            "source_file": "Security.evtx",
            "windows": {"event_id": 4688},
        },
    )

    context = search_service.event_context(db, case_id, "evt-1")

    assert context["available_context"]["timestamp"] is True
    assert context["available_context"]["host"] == "HOSTA"
    assert context["available_context"]["process"] == "powershell.exe"
    assert context["counts"]["related_detections"] == 1
    assert context["counts"]["related_findings"] == 1
    assert context["related_detections"][0]["rule_name"] == "Suspicious PowerShell"


def test_search_findings_respects_negative_text_and_artifact_type() -> None:
    db = _FakeDb([_finding(id="finding-1", title="Defender hit"), _finding(id="finding-2", title="PowerShell activity")])

    result = search_service.search_case_v2(db, "case-1", search_service.build_search_v2_params(scope="findings", exclude_q="defender", page_size=50))
    assert result["total"] == 1
    assert result["results"][0]["id"] == "finding-2"

    excluded = search_service.search_case_v2(db, "case-1", search_service.build_search_v2_params(scope="findings", exclude_artifact_type=["finding"], page_size=50))
    assert excluded["total"] == 0


def test_facet_counts_include_parser_and_source_file() -> None:
    facets = search_service._facet_counts(
        [
            {
                "artifact_type": "browser",
                "source_file": "History",
                "raw": {"artifact": {"parser": "browser_chromium_history"}},
            }
        ]
    )
    assert facets["artifact_type"]["browser"] == 1
    assert facets["parser"]["browser_chromium_history"] == 1
    assert facets["source_file"]["History"] == 1


def test_search_facets_supports_evidence_scope_with_counts(monkeypatch: pytest.MonkeyPatch) -> None:
    captured: dict[str, object] = {}

    class _FakeClient:
        def search(self, **kwargs):  # noqa: ANN003
            captured.setdefault("calls", []).append(kwargs)
            agg_name = next(iter((kwargs.get("body") or {}).get("aggs", {}).keys()))
            return {"aggregations": {agg_name: {"buckets": [{"key": "browser", "doc_count": 53}]}}}

    monkeypatch.setattr(routes_search, "get_opensearch_client", lambda: _FakeClient())
    monkeypatch.setattr(routes_search, "_resolve_index", lambda case_id: "dfir-events-case-1")
    monkeypatch.setattr(routes_search, "_index_available", lambda index: True)
    monkeypatch.setattr(routes_search, "is_index_queryable", lambda client, index: True)
    monkeypatch.setattr(routes_search, "resolve_aggregatable_field", lambda client, index, field: field)
    monkeypatch.setattr(routes_search, "_cache_get", lambda *args, **kwargs: None)
    monkeypatch.setattr(routes_search, "_cache_put", lambda _cache, _key, _ttl, value: value)

    facets = routes_search.search_facets(case_id="case-1", evidence_id="ev-1")

    assert facets["artifact.type"]["browser"] == 53
    first_body = captured["calls"][0]["body"]
    assert {"term": {"case_id": "case-1"}} in first_body["query"]["bool"]["filter"]
    assert {"term": {"evidence_id": "ev-1"}} in first_body["query"]["bool"]["filter"]
