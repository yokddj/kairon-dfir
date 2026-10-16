"""Typed-command duplicates, the dated filter and the executed time range."""
from __future__ import annotations

from typing import Any

from app.services.memory import artifact_indexing, command_history


def test_duplicates_from_several_shells_are_one_row() -> None:
    docs = [
        {"command": "sudo apt update", "command_time": "2024-07-03T19:40:49Z", "pid": 4453, "process_name": "bash", "source_plugin": "linux.bash"},
        {"command": "exit", "command_time": "2024-07-03T19:40:49Z", "pid": 4453, "process_name": "bash", "source_plugin": "linux.bash"},
        {"command": "sudo apt update", "command_time": "2024-07-03T19:40:49Z", "pid": 4954, "process_name": "bash", "source_plugin": "linux.bash"},
        # Typed again later: a different entry, kept apart.
        {"command": "sudo apt update", "command_time": "2024-07-03T19:47:23Z", "pid": 4954, "process_name": "bash", "source_plugin": "linux.bash"},
        # A console keeps a command in its history and on screen.
        {"command": "whoami", "command_time": None, "pid": 900, "process_name": "conhost.exe", "recovered_from": "command_history"},
        {"command": "whoami", "command_time": None, "pid": 900, "process_name": "conhost.exe", "recovered_from": "screen"},
    ]
    rows = artifact_indexing.group_duplicate_commands(docs)
    assert [(r["command"], r["occurrences"]) for r in rows] == [("sudo apt update", 2), ("exit", 1), ("sudo apt update", 1), ("whoami", 2)]
    assert rows[0]["pids"] == [4453, 4954]
    assert rows[3]["sources"] == ["command_history", "screen"]


class _Client:
    def __init__(self) -> None:
        self.body: dict[str, Any] | None = None

    def search(self, index: str, body: dict, params: dict | None = None) -> dict:
        self.body = body
        return {"hits": {"total": {"value": 0}, "hits": []}}


def test_dated_filter_selects_commands_with_or_without_time(monkeypatch) -> None:
    client = _Client()
    monkeypatch.setattr(artifact_indexing, "get_opensearch_client", lambda: client)
    artifact_indexing.search_artifact_documents("case-1", document_type="memory_shell_history", filters={"dated": "undated"})
    assert {"bool": {"must_not": [{"exists": {"field": "command_time"}}]}} in client.body["query"]["bool"]["filter"]
    artifact_indexing.search_artifact_documents("case-1", document_type="memory_shell_history", filters={"dated": "dated"})
    assert {"exists": {"field": "command_time"}} in client.body["query"]["bool"]["filter"]


class _Session:
    def query(self, *_args):
        return self

    def filter(self, *_args):
        return self

    def first(self):
        return None

    def close(self) -> None:
        pass


def test_time_range_keeps_only_processes_known_to_start_inside_it(monkeypatch) -> None:
    def entity(pid: int, create_time: str | None) -> dict:
        return {"process_entity_id": f"e{pid}", "process": {"pid": pid, "ppid": 4, "name": "x.exe", "command_line": f"x.exe {pid}", "create_time": create_time}, "visibility": {"listed": True}}

    entities = [entity(1, "2025-03-07T19:30:00+00:00"), entity(2, "2025-03-07T19:41:23+00:00"), entity(3, None)]
    monkeypatch.setattr(command_history, "fetch_canonical_entities", lambda *a, **k: {"items": entities})
    monkeypatch.setattr(command_history, "SessionLocal", _Session)
    result = command_history.build_command_line_history(
        case_id="case-1", evidence_id="ev-1", run_id="run-1", time_from="2025-03-07T19:40", time_to="2025-03-07T19:45:59"
    )
    assert [item["pid"] for item in result["items"]] == [2]
