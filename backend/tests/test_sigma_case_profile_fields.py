from __future__ import annotations

from app.workers import tasks


class _FakeIndices:
    def __init__(self, mapping: dict) -> None:
        self._mapping = mapping

    def get_mapping(self, index: str, params: dict | None = None) -> dict:
        return self._mapping


class _FakeClient:
    def __init__(self, mapping: dict) -> None:
        self.indices = _FakeIndices(mapping)


MAPPING = {
    "dfir-events-case-1": {
        "mappings": {
            "properties": {
                "case_id": {"type": "keyword"},
                "windows": {"properties": {"event_id": {"type": "long"}, "channel": {"type": "keyword"}}},
                "process": {
                    "properties": {
                        "command_line": {"type": "text"},
                        "parent": {"properties": {"command_line": {"type": "text"}}},
                    }
                },
            }
        }
    }
}


def test_available_fields_come_from_the_mapping_not_a_sample(monkeypatch) -> None:
    """Which fields exist is a property of the index, not of a document sample.

    Deriving it from an unsorted sample of a thousand documents meant a case
    whose sample happened to hold no Windows events reported windows.event_id
    as absent, and every rule keying on it was skipped as "missing_fields" --
    silently, with the run still reporting success. Re-indexing a case changed
    which documents came back first and took a run from 271 detections to zero.
    """
    monkeypatch.setattr(tasks, "get_opensearch_client", lambda: _FakeClient(MAPPING))

    fields = tasks._indexed_field_names("case-1")

    assert "windows.event_id" in fields
    assert "process.command_line" in fields


def test_nested_objects_are_flattened_to_dotted_paths(monkeypatch) -> None:
    monkeypatch.setattr(tasks, "get_opensearch_client", lambda: _FakeClient(MAPPING))

    fields = tasks._indexed_field_names("case-1")

    assert "process.parent.command_line" in fields
    # The container itself is not a queryable leaf.
    assert "process.parent" not in fields
    assert "process" not in fields


def test_an_unreachable_index_yields_nothing_rather_than_raising(monkeypatch) -> None:
    """A profile that cannot be built must not take the whole run down; the
    sample-derived fields still stand on their own."""

    def _boom():
        raise RuntimeError("opensearch down")

    monkeypatch.setattr(tasks, "get_opensearch_client", _boom)

    assert tasks._indexed_field_names("case-1") == set()
