from app.services.debug_export import _compact_process_graph


def _graph():
    return {
        "nodes": [
            {"id": "parent", "name": "cmd.exe", "risk_score": 10, "source_events": ["e1"], "badges": []},
            {"id": "child", "name": "powershell.exe", "risk_score": 90, "source_events": ["e2"], "badges": ["powershell"]},
            {"id": "activity:file1", "name": "C:\\Temp\\a.txt", "node_type": "activity", "risk_score": 0, "source_events": ["f1"]},
            {"id": "activity:dns1", "name": "example-control.test", "node_type": "activity", "risk_score": 0, "source_events": ["d1"]},
        ],
        "edges": [
            {"source": "parent", "target": "child", "type": "spawned", "confidence": "high", "reason": "sysmon_parent_process_guid"},
            {"id": "activity:child->file1", "source": "child", "target": "activity:file1", "type": "file_activity", "confidence": "high", "reason": "sysmon_file_created"},
            {"id": "activity:child->dns1", "source": "child", "target": "activity:dns1", "type": "dns_activity", "confidence": "high", "reason": "sysmon_dns_query"},
        ],
        "summary": {"warnings": []},
    }


def test_default_process_graph_collapses_activity_edges() -> None:
    compact = _compact_process_graph(_graph(), include_activity=False, max_nodes=50)

    assert [edge["type"] for edge in compact["edges"]] == ["parent_child"]
    assert {node["id"] for node in compact["nodes"]} == {"parent", "child"}
    assert compact["summary"]["activity_collapsed"] is True
    assert compact["omitted_counts"] == {"file": 1, "dns": 1}
    assert len(compact["groups"]) == 2


def test_include_activity_returns_activity_with_per_process_cap() -> None:
    compact = _compact_process_graph(_graph(), include_activity=True, max_nodes=50, max_activity_per_process=1)

    assert {edge["type"] for edge in compact["edges"]} == {"parent_child", "file_activity"}
    assert compact["omitted_counts"] == {"dns": 1}
    assert any(node["id"] == "activity:file1" for node in compact["nodes"])


def test_edge_type_filter_can_request_dns_activity() -> None:
    compact = _compact_process_graph(_graph(), edge_types=["parent_child", "dns_activity"], max_nodes=50)

    assert {edge["type"] for edge in compact["edges"]} == {"parent_child", "dns_activity"}
    assert any(node["id"] == "activity:dns1" for node in compact["nodes"])


def test_max_nodes_is_enforced() -> None:
    compact = _compact_process_graph(_graph(), include_activity=True, max_nodes=1)

    assert compact["truncated"] is True
    assert len(compact["nodes"]) == 1
    assert compact["summary"]["node_cap"] == 1
