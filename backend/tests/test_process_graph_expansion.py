from types import SimpleNamespace
from app.services import debug_export


def _process_event(
    event_id: str,
    *,
    ts: str,
    name: str,
    pid: int,
    entity_id: str,
    parent_entity_id: str | None = None,
    parent_pid: int | None = None,
    parent_name: str | None = None,
) -> dict:
    return {
        "id": event_id,
        "@timestamp": ts,
        "event": {"type": "sysmon_process_creation"},
        "artifact": {"type": "windows_event"},
        "host": {"name": "HOSTA"},
        "process": {
            "entity_id": entity_id,
            "pid": pid,
            "name": name,
            "path": f"C:\\Windows\\System32\\{name}",
            "command_line": name,
            "parent_entity_id": parent_entity_id,
            "parent_pid": parent_pid,
            "parent_name": parent_name,
        },
    }


def _activity_event(event_id: str, *, ts: str, pid: int, entity_id: str, event_type: str, path: str | None = None) -> dict:
    payload = {
        "id": event_id,
        "@timestamp": ts,
        "event": {"type": event_type},
        "artifact": {"type": "windows_event"},
        "host": {"name": "HOSTA"},
        "process": {"entity_id": entity_id, "pid": pid, "name": "powershell.exe"},
    }
    if path:
        payload["file"] = {"path": path}
    return payload


def test_expand_children_returns_child_nodes(monkeypatch) -> None:
    parent = _process_event("evt-ps", ts="2024-03-22T11:00:00Z", name="powershell.exe", pid=100, entity_id="guid-ps")
    child = _process_event(
        "evt-cmd",
        ts="2024-03-22T11:00:05Z",
        name="cmd.exe",
        pid=200,
        entity_id="guid-cmd",
        parent_entity_id="guid-ps",
        parent_pid=100,
        parent_name="powershell.exe",
    )
    responses = [[parent], [child], [parent, child]]

    def fake_search(*_args, **_kwargs):
        return responses.pop(0), 0, {}

    monkeypatch.setattr(debug_export, "_search_scope_events", fake_search)
    result = debug_export.build_process_tree_expansion(
        SimpleNamespace(id="case-1"),
        [],
        scope="evidence",
        evidence_id="ev-1",
        host="HOSTA",
        node_id="guid-ps",
        process_guid="guid-ps",
        process_pid=100,
        process_name="powershell.exe",
        expansion_type="children",
    )

    assert any(node["id"] == "guid-cmd" for node in result["added_nodes"])
    assert any(edge["source"] == "guid-ps" and edge["target"] == "guid-cmd" for edge in result["added_edges"])


def test_expand_siblings_returns_processes_with_shared_parent(monkeypatch) -> None:
    selected = _process_event(
        "evt-cmd",
        ts="2024-03-22T11:00:05Z",
        name="cmd.exe",
        pid=200,
        entity_id="guid-cmd",
        parent_entity_id="guid-ps",
        parent_pid=100,
        parent_name="powershell.exe",
    )
    sibling = _process_event(
        "evt-whoami",
        ts="2024-03-22T11:00:06Z",
        name="whoami.exe",
        pid=201,
        entity_id="guid-whoami",
        parent_entity_id="guid-ps",
        parent_pid=100,
        parent_name="powershell.exe",
    )
    parent = _process_event("evt-ps", ts="2024-03-22T11:00:00Z", name="powershell.exe", pid=100, entity_id="guid-ps")
    responses = [[selected], [selected, sibling], [parent, selected, sibling]]

    def fake_search(*_args, **_kwargs):
        return responses.pop(0), 0, {}

    monkeypatch.setattr(debug_export, "_search_scope_events", fake_search)
    result = debug_export.build_process_tree_expansion(
        SimpleNamespace(id="case-1"),
        [],
        scope="evidence",
        evidence_id="ev-1",
        node_id="guid-cmd",
        process_guid="guid-cmd",
        process_pid=200,
        process_name="cmd.exe",
        expansion_type="siblings",
    )

    assert any(node["id"] == "guid-whoami" for node in result["added_nodes"])
    assert any(edge["source"] == "guid-ps" and edge["target"] == "guid-whoami" for edge in result["added_edges"])


def test_expand_activity_returns_grouped_activity(monkeypatch) -> None:
    process = _process_event("evt-ps", ts="2024-03-22T11:00:00Z", name="powershell.exe", pid=100, entity_id="guid-ps")
    file_event = _activity_event("evt-file", ts="2024-03-22T11:00:08Z", pid=100, entity_id="guid-ps", event_type="sysmon_file_created", path="C:\\Temp\\maintenance.ps1")
    responses = [[process], [file_event]]

    def fake_search(*_args, **_kwargs):
        return responses.pop(0), 0, {}

    monkeypatch.setattr(debug_export, "_search_scope_events", fake_search)
    result = debug_export.build_process_tree_expansion(
        SimpleNamespace(id="case-1"),
        [],
        scope="evidence",
        evidence_id="ev-1",
        node_id="guid-ps",
        process_guid="guid-ps",
        process_pid=100,
        process_name="powershell.exe",
        expansion_type="activity",
    )

    assert result["omitted_counts"]["file"] == 1
    assert result["activity_groups"][0]["group"] == "file"


def test_focused_tree_by_pid_returns_parent_child_sibling_context(monkeypatch) -> None:
    parent = {
        "id": "guid-parent",
        "pid": 11784,
        "name": "powershell.exe",
        "command_line": "powershell.exe",
        "host": "HOSTA",
        "first_seen": "2024-03-22T11:26:00Z",
        "last_seen": "2024-03-22T11:26:00Z",
        "source_events": ["evt-parent"],
        "risk_score": 20,
        "risk_reasons": [],
        "badges": [],
        "data_quality": [],
        "confidence": "high",
    }
    focus = {
        "id": "guid-ps",
        "pid": 12720,
        "name": "powershell.exe",
        "command_line": "powershell.exe -ep bypass",
        "host": "HOSTA",
        "first_seen": "2024-03-22T11:27:00Z",
        "last_seen": "2024-03-22T11:27:00Z",
        "source_events": ["evt-ps"],
        "risk_score": 75,
        "risk_reasons": ["PowerShell execution policy bypass"],
        "badges": ["powershell"],
        "data_quality": [],
        "confidence": "high",
        "parent_name": "powershell.exe",
        "parent_pid": 11784,
        "parent_link_status": "linked",
        "parent_link_reason": "Linked exactly by Sysmon ProcessGuid / ParentProcessGuid.",
        "parent_link_confidence": "high",
    }
    child = {
        **focus,
        "id": "guid-cmd",
        "pid": 13492,
        "name": "cmd.exe",
        "command_line": "cmd.exe /c psexec.exe",
        "source_events": ["evt-cmd"],
        "parent_name": "powershell.exe",
        "parent_pid": 12720,
    }

    def fake_bundle(*_args, **_kwargs):
        return {
            "graph": {
                "nodes": [focus],
                "edges": [],
                "groups": [],
                "omitted_counts": {},
                "summary": {},
            },
            "report": {},
            "sample_chains": [],
        }

    def fake_expansion(*_args, **kwargs):
        expansion_type = kwargs.get("expansion_type")
        if expansion_type == "parents":
            return {"added_nodes": [parent], "added_edges": [{"source": "guid-parent", "target": "guid-ps", "type": "spawned", "confidence": "high", "reason": "test"}], "activity_groups": [], "omitted_counts": {}, "warnings": []}
        if expansion_type == "children":
            return {"added_nodes": [child], "added_edges": [{"source": "guid-ps", "target": "guid-cmd", "type": "spawned", "confidence": "high", "reason": "test"}], "activity_groups": [], "omitted_counts": {}, "warnings": []}
        return {"added_nodes": [], "added_edges": [], "activity_groups": [], "omitted_counts": {}, "warnings": []}

    monkeypatch.setattr(debug_export, "build_process_tree_bundle", fake_bundle)
    monkeypatch.setattr(debug_export, "build_process_tree_expansion", fake_expansion)

    result = debug_export.build_process_tree_focused(
        SimpleNamespace(id="case-1"),
        [],
        scope="evidence",
        evidence_id="ev-1",
        host="HOSTA",
        pid=12720,
        timestamp="2024-03-22T11:27:00Z",
    )

    assert result["focus_node"]["id"] == "guid-ps"
    assert result["parents"][0]["id"] == "guid-parent"
    assert result["children"][0]["id"] == "guid-cmd"
    assert result["identity_resolution"]["method"] == "pid_timestamp_host"
    assert "was launched by powershell.exe PID 11784" in result["identity_resolution"]["parent_explanation"]


def test_focused_tree_pid_only_reports_ambiguity(monkeypatch) -> None:
    first = {"id": "guid-a", "pid": 4444, "name": "cmd.exe", "host": "HOSTA", "source_events": [], "risk_score": 0, "risk_reasons": [], "badges": [], "data_quality": [], "confidence": "medium"}
    second = {"id": "guid-b", "pid": 4444, "name": "cmd.exe", "host": "HOSTA", "source_events": [], "risk_score": 0, "risk_reasons": [], "badges": [], "data_quality": [], "confidence": "medium"}
    monkeypatch.setattr(
        debug_export,
        "build_process_tree_bundle",
        lambda *_args, **_kwargs: {"graph": {"nodes": [first, second], "edges": [], "groups": [], "omitted_counts": {}, "summary": {}}, "report": {}, "sample_chains": []},
    )
    monkeypatch.setattr(debug_export, "build_process_tree_expansion", lambda *_args, **_kwargs: {"added_nodes": [], "added_edges": [], "activity_groups": [], "omitted_counts": {}, "warnings": []})

    result = debug_export.build_process_tree_focused(SimpleNamespace(id="case-1"), [], scope="case", pid=4444)

    assert result["identity_resolution"]["method"] == "pid_only"
    assert result["identity_resolution"]["ambiguous_candidates"]
    assert any("PID-only focus matched multiple candidates" in warning for warning in result["warnings"])


def test_execution_story_returns_narrative_and_visual_tree(monkeypatch) -> None:
    parent = {"id": "guid-parent", "pid": 11784, "name": "powershell.exe", "host": "HOSTA", "source_events": ["evt-parent"], "risk_score": 20, "risk_reasons": [], "badges": [], "data_quality": [], "confidence": "high"}
    focus = {
        "id": "guid-ps",
        "pid": 12720,
        "name": "powershell.exe",
        "command_line": "powershell.exe -ep bypass",
        "host": "HOSTA",
        "source_events": ["evt-ps"],
        "risk_score": 75,
        "risk_reasons": ["PowerShell execution policy bypass"],
        "badges": ["powershell"],
        "data_quality": [],
        "confidence": "high",
        "parent_name": "powershell.exe",
        "parent_pid": 11784,
        "parent_link_status": "linked",
        "parent_link_confidence": "high",
    }
    child = {
        **focus,
        "id": "guid-cmd",
        "pid": 13492,
        "name": "cmd.exe",
        "command_line": "cmd.exe /c psexec.exe",
        "source_events": ["evt-cmd"],
        "risk_score": 70,
        "risk_reasons": ["cmd.exe launched psexec.exe"],
        "parent_name": "powershell.exe",
        "parent_pid": 12720,
    }

    def fake_focused(*_args, **_kwargs):
        return {
            "focus_node": focus,
            "parents": [parent],
            "children": [child],
            "siblings": [],
            "activity_groups": [{"id": "activity:guid-ps:file", "source": "guid-ps", "group": "file", "count": 3}],
            "nodes": [parent, focus, child],
            "edges": [
                {"source": "guid-parent", "target": "guid-ps", "type": "parent_child", "confidence": "high", "reason": "test"},
                {"source": "guid-ps", "target": "guid-cmd", "type": "parent_child", "confidence": "high", "reason": "test"},
            ],
            "omitted_counts": {},
            "warnings": [],
            "identity_resolution": {
                "method": "pid_timestamp_host",
                "confidence": "high",
                "ambiguous_candidates": [],
                "parent_explanation": "This powershell.exe PID 12720 was launched by powershell.exe PID 11784.",
            },
        }

    monkeypatch.setattr(debug_export, "build_process_tree_focused", fake_focused)

    result = debug_export.build_execution_story(SimpleNamespace(id="case-1"), [], scope="evidence", evidence_id="ev-1", host="HOSTA", pid=12720)

    assert result["target"]["id"] == "guid-ps"
    assert "was launched by powershell.exe PID 11784" in result["story"]["parent_sentence"]
    assert "cmd.exe PID 13492" in result["story"]["children_sentence"]
    assert "3 file events" in result["story"]["activity_sentence"]
    assert result["visual_tree"]["nodes"][1]["id"] == "guid-ps"
    assert result["quality"]["confidence"] == "high"


def test_execution_story_source_event_id_wins_over_similar_text(monkeypatch) -> None:
    selected = _process_event(
        "evt-a",
        ts="2024-03-22T11:24:00Z",
        name="powershell.exe",
        pid=12720,
        entity_id="guid-a",
    )
    selected["search_doc_id"] = "search-doc-a"
    selected["process"]["command_line"] = r'powershell.exe -ep bypass -nop -w hidden -NoExit .\f\script.ps1'
    similar = _process_event(
        "evt-b",
        ts="2024-03-22T11:26:00Z",
        name="cmd.exe",
        pid=13492,
        entity_id="guid-b",
    )
    similar["search_doc_id"] = "search-doc-b"
    similar["process"]["command_line"] = r"/c C:\Users\public\psexec.exe \\HOSTB -accepteula powershell -ep bypass -NoExit C:\maintenance.ps1"

    def fake_search(*_args, **_kwargs):
        return [selected], 1, {}

    def fake_bundle(*_args, **_kwargs):
        return {
            "graph": {
                "nodes": [
                    {
                        "id": "guid-b",
                        "pid": 13492,
                        "name": "cmd.exe",
                        "command_line": similar["process"]["command_line"],
                        "host": "HOSTA",
                        "first_seen": similar["@timestamp"],
                        "source_event_id": "search-doc-b",
                        "source_events": ["search-doc-b", "evt-b"],
                        "risk_score": 75,
                        "risk_reasons": [],
                        "badges": [],
                        "data_quality": [],
                        "confidence": "high",
                    },
                    {
                        "id": "guid-a",
                        "pid": 12720,
                        "name": "powershell.exe",
                        "command_line": selected["process"]["command_line"],
                        "host": "HOSTA",
                        "first_seen": selected["@timestamp"],
                        "source_event_id": "search-doc-a",
                        "source_events": ["search-doc-a", "evt-a"],
                        "risk_score": 80,
                        "risk_reasons": ["PowerShell execution policy bypass"],
                        "badges": ["powershell"],
                        "data_quality": [],
                        "confidence": "high",
                    },
                ],
                "edges": [],
                "groups": [],
                "omitted_counts": {},
                "summary": {},
            },
            "report": {},
            "sample_chains": [],
        }

    monkeypatch.setattr(debug_export, "_search_scope_events", fake_search)
    monkeypatch.setattr(debug_export, "build_process_tree_bundle", fake_bundle)
    monkeypatch.setattr(debug_export, "build_process_tree_expansion", lambda *_args, **_kwargs: {"added_nodes": [], "added_edges": [], "activity_groups": [], "omitted_counts": {}, "warnings": []})

    result = debug_export.build_execution_story(
        SimpleNamespace(id="case-1"),
        [],
        scope="evidence",
        evidence_id="ev-1",
        host="HOSTA",
        source_event_id="search-doc-a",
        q="powershell",
    )

    assert result["target"]["id"] == "guid-a"
    assert result["target"]["source_event_id"] == "search-doc-a"
    assert r".\f\script.ps1" in result["target"]["command_line"]
    assert "psexec.exe" not in result["target"]["command_line"]
    assert any(node["id"] == "guid-a" for node in result["visual_tree"]["nodes"])
    assert result["quality"]["identity_resolution"]["method"] == "source_event_id"
    assert result["quality"]["identity_resolution"]["target_identity_matches"] is True


def test_execution_story_exact_identity_does_not_fallback_to_similar_node(monkeypatch) -> None:
    similar = _process_event(
        "evt-b",
        ts="2024-03-22T11:26:00Z",
        name="cmd.exe",
        pid=13492,
        entity_id="guid-b",
    )
    similar["search_doc_id"] = "search-doc-b"
    similar["process"]["command_line"] = r"/c C:\Users\public\psexec.exe \\HOSTB -accepteula powershell -ep bypass -NoExit C:\maintenance.ps1"

    def fake_search(*_args, **_kwargs):
        return [], 0, {}

    def fake_bundle(*_args, **_kwargs):
        return {
            "graph": {
                "nodes": [
                    {
                        "id": "guid-b",
                        "pid": 13492,
                        "name": "cmd.exe",
                        "command_line": similar["process"]["command_line"],
                        "host": "HOSTA",
                        "first_seen": similar["@timestamp"],
                        "source_event_id": "search-doc-b",
                        "source_events": ["search-doc-b", "evt-b"],
                        "risk_score": 75,
                        "risk_reasons": [],
                        "badges": [],
                        "data_quality": [],
                        "confidence": "high",
                    },
                ],
                "edges": [],
                "groups": [],
                "omitted_counts": {},
                "summary": {},
            },
            "report": {},
            "sample_chains": [],
        }

    monkeypatch.setattr(debug_export, "_search_scope_events", fake_search)
    monkeypatch.setattr(debug_export, "build_process_tree_bundle", fake_bundle)

    result = debug_export.build_execution_story(
        SimpleNamespace(id="case-1"),
        [],
        scope="evidence",
        evidence_id="ev-1",
        host="HOSTA",
        source_event_id="search-doc-a",
        q="powershell",
    )

    assert result["target"] is None
    assert result["quality"]["identity_resolution"]["method"] == "source_event_id"
    assert result["quality"]["identity_resolution"]["target_identity_matches"] is False
    assert any("source_event_id" in warning for warning in result["quality"]["warnings"])


def test_execution_story_power_shell_operational_returns_light_candidates(monkeypatch) -> None:
    debug_export._EXECUTION_STORY_LIGHT_CACHE.clear()
    source = {
        "id": "evt-psop",
        "@timestamp": "2024-03-22T11:26:45Z",
        "event": {"provider": "Microsoft-Windows-PowerShell", "type": "powershell_module", "message": "PowerShell module logging"},
        "windows": {"event_id": 4103},
        "artifact": {"type": "powershell"},
        "host": {"name": "HOSTA"},
        "user": {"name": "usera"},
        "process": {"pid": 6996, "name": "powershell.exe"},
    }
    candidate = _process_event(
        "evt-proc",
        ts="2024-03-22T11:26:39Z",
        name="powershell.exe",
        pid=6996,
        entity_id="guid-ps",
    )
    candidate["process"]["command_line"] = r"powershell.exe -ep bypass -nop -w hidden -NoExit .\f\script.ps1"

    responses = [[source], [candidate]]

    def fake_search(*_args, **_kwargs):
        return responses.pop(0), 0, {}

    monkeypatch.setattr(debug_export, "_search_scope_events", fake_search)

    result = debug_export.build_execution_story(
        SimpleNamespace(id="case-1"),
        [],
        scope="evidence",
        evidence_id="ev-1",
        host="HOSTA",
        source_event_id="evt-psop",
    )

    assert result["target"] is None
    assert result["quality"]["target_quality"] == "related"
    assert result["quality"]["response_mode"] == "lightweight"
    assert result["quality"]["activity_lazy"] is True
    assert result["candidate_processes"][0]["pid"] == 6996
    assert result["activity_groups"]["items"] == []


def test_execution_story_light_cache_hit(monkeypatch) -> None:
    debug_export._EXECUTION_STORY_LIGHT_CACHE.clear()
    source = {
        "id": "evt-generic",
        "@timestamp": "2024-03-22T11:26:45Z",
        "event": {"provider": "Microsoft-Windows-PowerShell", "message": "PowerShell operational event"},
        "windows": {"event_id": 4103},
        "artifact": {"type": "powershell"},
        "host": {"name": "HOSTA"},
    }
    calls = {"count": 0}

    def fake_search(*_args, **_kwargs):
        calls["count"] += 1
        return ([source] if calls["count"] == 1 else []), 0, {}

    monkeypatch.setattr(debug_export, "_search_scope_events", fake_search)
    first = debug_export.build_execution_story(SimpleNamespace(id="case-1"), [], scope="evidence", evidence_id="ev-1", source_event_id="evt-generic")
    second = debug_export.build_execution_story(SimpleNamespace(id="case-1"), [], scope="evidence", evidence_id="ev-1", source_event_id="evt-generic")

    assert first["quality"]["cache"]["hit"] is False
    assert second["quality"]["cache"]["hit"] is True
    assert calls["count"] == 2
