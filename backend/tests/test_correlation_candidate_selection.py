from __future__ import annotations

from typing import Any

from app.services.memory import timeline


class _CapturingClient:
    def __init__(self) -> None:
        self.bodies: list[dict[str, Any]] = []

    def search(self, index: str, body: dict[str, Any], params: dict[str, Any] | None = None) -> dict[str, Any]:
        self.bodies.append(body)
        return {"hits": {"hits": []}}


def test_disk_correlation_candidates_are_taken_newest_first(monkeypatch) -> None:
    """Oldest-first plus a size cap made correlation structurally impossible.

    A memory image is captured at the newest point of an investigation. Drawing
    the disk candidates from the oldest end meant the two sets never overlapped
    in time, every pair was rejected as "incompatible timestamps", and the
    engine returned zero correlations however much work it did.
    """
    client = _CapturingClient()
    monkeypatch.setattr(timeline, "get_opensearch_client", lambda: client)

    timeline._fetch_disk_docs("case-1")

    sort = client.bodies[0]["sort"]
    assert sort == [{"@timestamp": {"order": "desc", "missing": "_last"}}]
    assert client.bodies[0]["size"] == timeline.DISK_CANDIDATE_LIMIT


def test_memprocfs_events_are_not_disk_correlation_candidates(monkeypatch) -> None:
    """MemProcFS timeline events sit in the events index but come from the memory image itself;
    taken as disk events they were listed twice in the Timeline and correlated with themselves."""
    client = _CapturingClient()
    monkeypatch.setattr(timeline, "get_opensearch_client", lambda: client)

    timeline._fetch_disk_docs("case-1")

    assert {"term": {"artifact.parser": "memprocfs"}} in client.bodies[0]["query"]["bool"]["must_not"]
