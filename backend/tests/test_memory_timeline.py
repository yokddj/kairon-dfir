from __future__ import annotations

from types import SimpleNamespace
from typing import Any

import pytest

from app.services.memory import timeline


class FakeDb:
    def get(self, model, ident):  # noqa: ANN001
        if ident == "ev-1":
            return SimpleNamespace(id="ev-1", case_id="case-1", filename="mem.raw")
        return SimpleNamespace(id=ident, case_id="case-1", evidence_id="ev-1", profile="processes", status="completed")


class FakeClient:
    def __init__(self, memory_docs: list[dict[str, Any]], disk_docs: list[dict[str, Any]] | None = None) -> None:
        self.memory_docs = memory_docs
        self.disk_docs = disk_docs or []
        self.search_bodies: list[dict[str, Any]] = []
        self.bulk_calls: list[list[dict[str, Any]]] = []

    def search(self, index: str, body: dict[str, Any], params: dict[str, Any] | None = None) -> dict[str, Any]:
        self.search_bodies.append(body)
        docs = self.disk_docs if index == "events" else self.memory_docs
        if index != "events":
            text = str(body)
            docs = [doc for doc in docs if doc.get("document_type") in text]
        return {"hits": {"total": {"value": len(docs)}, "hits": [{"_id": doc.get("document_id") or doc.get("stable_event_id") or str(i), "_source": doc} for i, doc in enumerate(docs)]}}

    def bulk(self, body: list[dict[str, Any]], refresh: bool = False) -> dict[str, Any]:
        self.bulk_calls.append(body)
        return {"errors": False, "items": []}


def mem_process(**extra: Any) -> dict[str, Any]:
    doc = {"document_id": "proc-1", "document_type": "memory_process_entity", "case_id": "case-1", "evidence_id": "ev-1", "scan_run_id": "run-1", "process_entity_id": "ent-1", "process": {"pid": 6996, "ppid": 9132, "name": "powershell.exe", "command_line": "powershell.exe -NoP", "create_time": "2024-03-22T12:00:00Z", "exit_time": "2024-03-22T12:05:00Z"}, "source_plugins": ["windows.pslist"]}
    doc.update(extra)
    return doc


def mem_observation(command_line: str | None = "powershell.exe -NoP", create_time: str | None = "2024-03-22T12:00:00Z") -> dict[str, Any]:
    return {"document_id": "obs-1", "document_type": "memory_process_observation", "case_id": "case-1", "evidence_id": "ev-1", "scan_run_id": "run-1", "plugin_run_id": "plug-1", "process_entity_id": "ent-1", "plugin_name": "windows.cmdline", "observed": {"pid": 6996, "ppid": 9132, "name": "powershell.exe", "command_line": command_line, "create_time": create_time}}


def mem_network(create_time: str | None = "2024-03-22T12:00:02Z") -> dict[str, Any]:
    return {"document_id": "net-1", "document_type": "memory_network_connection", "case_id": "case-1", "evidence_id": "ev-1", "scan_run_id": "run-1", "plugin_run_id": "plug-net", "pid": 6996, "process_entity_id": "ent-1", "process_name": "powershell.exe", "protocol": "TCPv4", "local_address": "192.168.1.10", "local_port": 49722, "remote_address": "13.107.42.14", "remote_port": 443, "connection_state": "ESTABLISHED", "create_time": create_time, "source_plugin": "windows.netscan"}


def disk_4688(**extra: Any) -> dict[str, Any]:
    doc = {"stable_event_id": "evt-4688", "case_id": "case-1", "evidence_id": "disk-1", "@timestamp": "2024-03-22T12:00:02Z", "artifact": {"type": "windows_event", "parser": "evtx"}, "windows": {"event_id": 4688}, "process": {"pid": 6996, "name": "powershell.exe", "path": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe", "command_line": "powershell.exe -NoP", "parent": {"pid": 9132, "name": "explorer.exe"}}, "user": {"sid": "S-1-5-21-1"}}
    doc.update(extra)
    return doc


def disk_prefetch() -> dict[str, Any]:
    return {"stable_event_id": "pf-1", "case_id": "case-1", "@timestamp": "2024-03-22T12:00:10Z", "artifact": {"type": "prefetch", "parser": "prefetch"}, "file": {"name": "POWERSHELL.EXE", "path": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\POWERSHELL.EXE"}}


def patch_client(monkeypatch: pytest.MonkeyPatch, client: FakeClient) -> None:
    monkeypatch.setattr(timeline, "get_opensearch_client", lambda: client)
    monkeypatch.setattr(timeline, "get_memory_index", lambda case_id: f"memory-{case_id}")
    monkeypatch.setattr(timeline, "get_events_index", lambda: "events")
    monkeypatch.setattr(timeline, "resolve_active_memory_result", lambda *a, **k: {"active_run": {"id": "run-1"}})


def get_timeline(monkeypatch: pytest.MonkeyPatch, memory_docs: list[dict[str, Any]], disk_docs: list[dict[str, Any]] | None = None, **kwargs: Any) -> dict[str, Any]:
    client = FakeClient(memory_docs, disk_docs)
    patch_client(monkeypatch, client)
    result = timeline.get_memory_timeline(FakeDb(), case_id="case-1", evidence_id="ev-1", **kwargs)
    result["client"] = client
    return result


def test_process_start_and_exit_are_separate(monkeypatch: pytest.MonkeyPatch) -> None:
    result = get_timeline(monkeypatch, [mem_process()])
    kinds = {item["event_kind"] for item in result["items"]}
    assert {"process_start", "process_exit"} <= kinds


def test_null_exit_time_is_not_still_running(monkeypatch: pytest.MonkeyPatch) -> None:
    process = mem_process()
    process["process"]["exit_time"] = None
    result = get_timeline(monkeypatch, [process])
    assert "process_exit" not in {item["event_kind"] for item in result["items"]}


def test_command_line_with_timestamp_enters_timeline(monkeypatch: pytest.MonkeyPatch) -> None:
    result = get_timeline(monkeypatch, [mem_observation()])
    assert result["items"][0]["event_kind"] == "command_line"


def test_command_line_without_timestamp_is_undated(monkeypatch: pytest.MonkeyPatch) -> None:
    result = get_timeline(monkeypatch, [mem_observation(create_time=None)], include_undated=True)
    assert result["items"][0]["is_undated"] is True
    assert result["undated_count"] == 1


def test_network_timestamped_and_undated_split(monkeypatch: pytest.MonkeyPatch) -> None:
    result = get_timeline(monkeypatch, [mem_network(), mem_network(create_time=None)], include_undated=True)
    assert any(item["event_kind"] == "network_connection" and not item["is_undated"] for item in result["items"])
    assert any(item["event_kind"] == "network_connection" and item["is_undated"] for item in result["items"])


def test_plugin_completion_time_is_not_used(monkeypatch: pytest.MonkeyPatch) -> None:
    doc = mem_network(create_time=None) | {"completed_at": "2024-03-22T13:00:00Z", "indexed_at": "2024-03-22T13:00:00Z"}
    result = get_timeline(monkeypatch, [doc], include_undated=True)
    assert result["items"][0]["occurred_at"] is None


def test_timestamp_precision_and_utc_normalization(monkeypatch: pytest.MonkeyPatch) -> None:
    result = get_timeline(monkeypatch, [mem_network("2024-03-22T14:00:00+02:00")])
    assert result["items"][0]["occurred_at"] == "2024-03-22T12:00:00Z"
    assert result["items"][0]["timestamp_precision"] == "second"


def test_unknown_timezone_is_labelled(monkeypatch: pytest.MonkeyPatch) -> None:
    result = get_timeline(monkeypatch, [mem_network("2024-03-22 12:00:00")])
    assert result["items"][0]["timestamp_timezone"] == "source_timezone_unknown"


def test_event_ids_are_deterministic(monkeypatch: pytest.MonkeyPatch) -> None:
    a = get_timeline(monkeypatch, [mem_process()])["items"]
    b = get_timeline(monkeypatch, [mem_process()])["items"]
    assert [x["event_id"] for x in a] == [x["event_id"] for x in b]


def test_scoping_filters_are_sent(monkeypatch: pytest.MonkeyPatch) -> None:
    result = get_timeline(monkeypatch, [mem_process()], process_entity_id="ent-1", pid=6996, process_name="powershell.exe")
    assert "ev-1" in str(result["client"].search_bodies[0])
    assert "ent-1" in str(result["client"].search_bodies[0])
    assert "ev-2" not in str(result["client"].search_bodies[0])


def test_pid_only_correlation_is_rejected(monkeypatch: pytest.MonkeyPatch) -> None:
    disk = disk_4688(process={"pid": 6996, "name": "cmd.exe"})
    result = get_timeline(monkeypatch, [mem_process()], [disk], has_correlations=True)
    assert result["total"] == 0


def test_4688_correlation_requires_identity_and_time(monkeypatch: pytest.MonkeyPatch) -> None:
    result = get_timeline(monkeypatch, [mem_process()], [disk_4688()], has_correlations=True)
    corr = result["items"][0]["correlations"][0]
    assert corr["confidence"] in {"exact", "high"}
    assert "pid" in corr["matched_fields"]
    assert "process.name" in corr["matched_fields"]


def test_pid_reuse_time_mismatch_blocks_false_link(monkeypatch: pytest.MonkeyPatch) -> None:
    result = get_timeline(monkeypatch, [mem_process()], [disk_4688(**{"@timestamp": "2024-03-23T12:00:00Z"})], has_correlations=True)
    assert result["total"] == 0


def test_path_mismatch_blocks_correlation(monkeypatch: pytest.MonkeyPatch) -> None:
    result = get_timeline(monkeypatch, [mem_process(process={"pid": 6996, "name": "powershell.exe", "command_line": "C:\\Bad\\powershell.exe", "create_time": "2024-03-22T12:00:00Z"})], [disk_4688()], has_correlations=True)
    assert result["total"] == 0


def test_prefetch_is_executable_level_not_instance_proof(monkeypatch: pytest.MonkeyPatch) -> None:
    result = get_timeline(monkeypatch, [mem_process()], [disk_prefetch()], has_correlations=True)
    corr = result["items"][0]["correlations"][0]
    assert corr["correlation_type"] == "memory_process_to_prefetch_executable"
    assert any("executable-level" in reason for reason in corr["reasons"])


def test_shimcache_semantics_do_not_claim_execution(monkeypatch: pytest.MonkeyPatch) -> None:
    event = timeline._disk_events("case-1", [{"stable_event_id": "shim", "@timestamp": "2024-03-22", "artifact": {"type": "shimcache"}, "shimcache": {"path": "C:\\x.exe"}}])[0]
    assert "not execution proof" in event["timestamp_semantics"]


def test_powershell_service_task_registry_and_network_classification() -> None:
    docs = [
        {"stable_event_id": "ps", "@timestamp": "2024-03-22T12:00:00Z", "powershell": {"command": "Get-Process"}},
        {"stable_event_id": "svc", "@timestamp": "2024-03-22T12:00:00Z", "service": {"image_path": "C:\\svc.exe"}},
        {"stable_event_id": "task", "@timestamp": "2024-03-22T12:00:00Z", "task": {"command": "cmd.exe"}},
        {"stable_event_id": "reg", "@timestamp": "2024-03-22T12:00:00Z", "registry": {"value_data": "run.exe"}},
        {"stable_event_id": "net", "@timestamp": "2024-03-22T12:00:00Z", "network": {"destination_ip": "1.1.1.1"}},
    ]
    kinds = {event["event_kind"] for event in timeline._disk_events("case-1", docs)}
    assert {"powershell_execution", "service_execution", "scheduled_task_execution", "registry_persistence", "network_log_event"} <= kinds


def test_low_confidence_hidden_by_default(monkeypatch: pytest.MonkeyPatch) -> None:
    disk = disk_4688(**{"@timestamp": "2024-03-22T12:00:40Z"})
    result = get_timeline(monkeypatch, [mem_process()], [disk], has_correlations=True)
    assert result["total"] == 0


def test_correlation_detail_contains_reasons_and_artifacts(monkeypatch: pytest.MonkeyPatch) -> None:
    result = get_timeline(monkeypatch, [mem_process()], [disk_4688()], has_correlations=True)
    corr = result["items"][0]["correlations"][0]
    assert corr["reasons"]
    assert corr["navigation_targets"]
    assert corr["source_provenance"]


def test_facets_counts_and_pagination(monkeypatch: pytest.MonkeyPatch) -> None:
    docs = [mem_process(document_id=f"proc-{i}", process_entity_id=f"ent-{i}", process={"pid": i, "name": "p.exe", "create_time": f"2024-03-22T12:00:{i:02d}Z"}) for i in range(3)]
    result = get_timeline(monkeypatch, docs, page=1, page_size=50)
    assert result["page"] == 1
    assert result["total_pages"] == 1
    assert result["event_kind_counts"]["process_start"] == 3


def test_process_scoped_timeline(monkeypatch: pytest.MonkeyPatch) -> None:
    result = get_timeline(monkeypatch, [mem_process()], process_entity_id="ent-1")
    assert all(item.get("process_entity_id") == "ent-1" for item in result["items"])


def test_materialization_dry_run_writes_nothing(monkeypatch: pytest.MonkeyPatch) -> None:
    client = FakeClient([mem_process()], [disk_4688()])
    patch_client(monkeypatch, client)
    report = timeline.materialize_timeline(FakeDb(), case_id="case-1", evidence_id="ev-1", apply=False)
    assert report["dry_run"] is True
    assert client.bulk_calls == []


def test_materialization_apply_is_idempotent(monkeypatch: pytest.MonkeyPatch) -> None:
    client = FakeClient([mem_process()], [disk_4688()])
    patch_client(monkeypatch, client)
    first = timeline.materialize_timeline(FakeDb(), case_id="case-1", evidence_id="ev-1", apply=True)
    second = timeline.materialize_timeline(FakeDb(), case_id="case-1", evidence_id="ev-1", apply=True)
    assert first["would_create_or_update"] == second["would_create_or_update"]
    assert len(client.bulk_calls) == 2


def test_historical_docs_and_raw_references_remain_readable(monkeypatch: pytest.MonkeyPatch) -> None:
    result = get_timeline(monkeypatch, [mem_network(None)], include_undated=True)
    item = result["items"][0]
    assert item["raw_reference"]["document_id"] == "net-1"
    assert item["is_undated"] is True
