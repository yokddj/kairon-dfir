from app.services import command_history, search_service, timeline_service


def test_global_search_memory_source_uses_memory_adapter(monkeypatch):
    def fake_memory_search(_db, case_id, params):
        return {
            "total": 1,
            "page": 1,
            "page_size": params["page_size"],
            "results": [{"id": "memory:doc-1", "source_category": "Memory", "source_plugin_or_parser": "windows.pslist", "raw": {"evidence_id": "ev-1"}}],
            "facets": {"source_category": {"Memory": 1}},
            "warnings": [],
        }

    monkeypatch.setattr(search_service, "memory_search_results", fake_memory_search)
    result = search_service.search_case_v2(None, "case-1", {"source_category": "Memory", "page_size": 100})
    assert result["total"] == 1
    assert result["results"][0]["source_category"] == "Memory"
    assert result["results"][0]["source_plugin_or_parser"] == "windows.pslist"
    assert result["facets"]["source_category"]["Memory"] == 1


def test_global_search_default_merges_memory_without_cross_case(monkeypatch):
    monkeypatch.setattr(search_service, "search_events_v2", lambda *args, **kwargs: (0, [], [], {}))
    monkeypatch.setattr(search_service, "search_findings_v2", lambda *args, **kwargs: (0, [], [], []))

    def fake_memory_search(_db, case_id, params):
        assert case_id == "case-1"
        assert params.get("evidence_id") == "ev-1"
        return {"results": [{"id": "memory:doc-1", "source_category": "Memory", "artifact_type": "memory_process_entity", "raw": {"evidence_id": "ev-1"}}], "warnings": []}

    monkeypatch.setattr(search_service, "memory_search_results", fake_memory_search)
    result = search_service.search_case_v2(None, "case-1", {"evidence_id": "ev-1", "page": 1, "page_size": 100})
    assert result["total"] == 1
    assert result["results"][0]["id"] == "memory:doc-1"


def test_global_timeline_memory_source_preserves_undated_count(monkeypatch):
    def fake_memory_timeline(_db, case_id, params):
        assert case_id == "case-1"
        return {
            "case_id": case_id,
            "mode": "full",
            "total": 1,
            "page": 1,
            "page_size": params["page_size"],
            "next_cursor": None,
            "items": [{"id": "memory-timeline:e1", "timestamp": "2026-01-01T00:00:00Z", "source_category": "Memory", "raw": {"timestamp_semantics": "process creation"}}],
            "groups": [],
            "facets": {"source_category": {"Memory": 1}},
            "undated_count": 7,
            "warnings": [],
        }

    monkeypatch.setattr(timeline_service, "memory_timeline_items", fake_memory_timeline)
    result = timeline_service.build_timeline_response(None, "case-1", {"source_category": "Memory", "page_size": 100})
    assert result["items"][0]["source_category"] == "Memory"
    assert result["undated_count"] == 7


def test_global_command_history_memory_source_uses_memory_adapter(monkeypatch):
    def fake_memory_commands(_db, case_id, params):
        return {
            "total": 1,
            "page": 1,
            "page_size": params["page_size"],
            "sort": "timestamp_desc",
            "sort_by": "timestamp",
            "sort_order": "desc",
            "items": [{"id": "memory-command:1", "command": "cmd.exe /c whoami", "timestamp": None, "source_category": "Memory", "source_plugin_or_parser": "windows.cmdline", "supporting_events": [], "risk_score": 0, "risk_reasons": []}],
            "facets": {"source_category": {"Memory": 1}},
            "summary": {"commands_total": 1, "suspicious_total": 0, "high_confidence": 0, "with_command_line": 1, "with_supporting_events": 0},
        }

    monkeypatch.setattr(command_history, "memory_command_history", fake_memory_commands)
    result = command_history.get_command_history("case-1", {"source_category": "Memory", "page_size": 100})
    assert result["items"][0]["timestamp"] is None
    assert result["items"][0]["source_category"] == "Memory"
    assert result["items"][0]["source_plugin_or_parser"] == "windows.cmdline"
