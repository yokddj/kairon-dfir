from app.services.debug_export import _build_process_graph


def _process_event(
    event_id: str,
    *,
    ts: str,
    name: str,
    pid: int,
    entity_id: str | None = None,
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
            "entity_id": entity_id or event_id,
            "pid": pid,
            "name": name,
            "command_line": name,
            "parent_entity_id": parent_entity_id,
            "parent_pid": parent_pid,
            "parent_name": parent_name,
        },
    }


def _node(graph: dict, node_id: str) -> dict:
    return next(node for node in graph["nodes"] if node["id"] == node_id)


def test_sysmon_guid_parent_links_exactly() -> None:
    graph = _build_process_graph(
        [
            _process_event("e-parent", ts="2024-03-22T11:00:00Z", name="cmd.exe", pid=100, entity_id="guid-parent"),
            _process_event(
                "e-child",
                ts="2024-03-22T11:00:01Z",
                name="psexec.exe",
                pid=200,
                entity_id="guid-child",
                parent_entity_id="guid-parent",
                parent_pid=100,
                parent_name="cmd.exe",
            ),
        ],
        "case-1",
        "evidence-1",
        "evidence",
    )

    assert any(edge["source"] == "guid-parent" and edge["target"] == "guid-child" for edge in graph["edges"])
    child = _node(graph, "guid-child")
    assert child["parent_link_status"] == "linked"
    assert child["parent_link_confidence"] == "high"


def test_security_4688_pid_time_parent_links_when_guid_missing() -> None:
    graph = _build_process_graph(
        [
            _process_event("parent", ts="2024-03-22T11:00:00Z", name="cmd.exe", pid=100, entity_id=None),
            _process_event(
                "child",
                ts="2024-03-22T11:00:05Z",
                name="psexec.exe",
                pid=200,
                entity_id=None,
                parent_pid=100,
                parent_name="cmd.exe",
            ),
        ],
        "case-1",
        "evidence-1",
        "evidence",
    )

    child = _node(graph, "child")
    assert child["parent_link_status"] == "linked"
    assert child["parent_link_confidence"] == "medium"
    assert child["parent_fields"]["parent_pid"] == 100


def test_missing_parent_fields_are_classified() -> None:
    graph = _build_process_graph(
        [_process_event("child", ts="2024-03-22T11:00:05Z", name="cmd.exe", pid=200, entity_id=None)],
        "case-1",
        "evidence-1",
        "evidence",
    )

    child = _node(graph, "child")
    assert child["parent_link_status"] == "parent_fields_missing"
    assert "parent_fields_missing" in child["data_quality"]
    assert graph["summary"]["orphan_diagnostics"][0]["parent_link_status"] == "parent_fields_missing"


def test_ambiguous_pid_reuse_is_classified() -> None:
    graph = _build_process_graph(
        [
            _process_event("parent-1", ts="2024-03-22T11:00:00Z", name="cmd.exe", pid=100, entity_id=None),
            _process_event("parent-2", ts="2024-03-22T11:00:02Z", name="cmd.exe", pid=100, entity_id=None),
            _process_event(
                "child",
                ts="2024-03-22T11:00:05Z",
                name="psexec.exe",
                pid=200,
                entity_id=None,
                parent_pid=100,
                parent_name="cmd.exe",
            ),
        ],
        "case-1",
        "evidence-1",
        "evidence",
    )

    child = _node(graph, "child")
    assert child["parent_link_status"] == "parent_pid_reused_ambiguous"
    assert "possible_pid_reuse" in child["data_quality"]
