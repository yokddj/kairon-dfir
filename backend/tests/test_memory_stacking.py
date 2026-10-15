"""Stacking: records grouped by value, rarest (fewest processes) first."""
from __future__ import annotations

from types import SimpleNamespace
from typing import Any

from app.services.memory import stacking


class _Client:
    def __init__(self, buckets: list[dict[str, Any]], run_processes: int = 150, other: int = 0) -> None:
        self.buckets = buckets
        self.run_processes = run_processes
        self.other = other
        self.indices = SimpleNamespace(get_field_mapping=lambda **_: {})

    def search(self, index: str, body: dict[str, Any], params: Any = None) -> dict[str, Any]:
        self.body = body
        return {"aggregations": {
            "values": {"buckets": self.buckets, "sum_other_doc_count": self.other},
            "run_processes": {"scoped": {"n": {"value": self.run_processes}}},
        }}


def _bucket(value: str, processes: int, occurrences: int, group: str | None = None) -> dict[str, Any]:
    bucket = {"key": value, "doc_count": occurrences, "processes": {"value": processes}, "names": {"buckets": [{"key": "p.exe"}]}}
    if group:
        bucket["groups"] = {"buckets": [{"key": group}]}
    return bucket


def _stack(monkeypatch, client, **kwargs):
    monkeypatch.setattr(stacking, "get_opensearch_client", lambda: client)
    return stacking.stack_family("case-1", run_id="run-1", evidence_id="ev-1", **kwargs)


def test_orders_values_by_how_few_processes_have_them(monkeypatch) -> None:
    client = _Client([
        _bucket(r"\Windows\System32\ntdll.dll", 149, 149),
        _bucket(r"C:\Users\x\AppData\Local\Temp\a.dll", 1, 1),
        _bucket(r"\Windows\System32\uxtheme.dll", 40, 40),
        _bucket("", 3, 3),
    ])
    result = _stack(monkeypatch, client, family="modules")

    assert [item["value"] for item in result["items"]] == [r"C:\Users\x\AppData\Local\Temp\a.dll", r"\Windows\System32\uxtheme.dll", r"\Windows\System32\ntdll.dll"]
    assert result["total_values"] == 3  # empty values are not stacked
    assert result["run_process_count"] == 150
    assert result["truncated"] is False

    common = _stack(monkeypatch, client, family="modules", order="common")
    assert common["items"][0]["value"] == r"\Windows\System32\ntdll.dll"


def test_handles_carry_their_object_type_and_filter_by_it(monkeypatch) -> None:
    client = _Client([_bucket("Global\\SomeMutex", 1, 1, group="Mutant")], other=5)
    result = _stack(monkeypatch, client, family="handles", group_value="Mutant", q="mutex")

    assert result["items"][0]["group"] == "Mutant"
    assert result["truncated"] is True
    filters = client.body["query"]["bool"]["filter"]
    assert {"term": {"object_type": "Mutant"}} in filters
    assert {"wildcard": {"object_name": {"value": "*mutex*", "case_insensitive": True}}} in filters
    assert {"term": {"scan_run_id.keyword": "run-1"}} in filters


def test_identical_command_lines_collapse_rarest_first() -> None:
    from app.services.memory.command_history import group_identical_command_lines

    def item(pid: int, cmd: str, start: str | None) -> dict[str, Any]:
        return {"pid": pid, "process_name": cmd.split()[0], "command_line": cmd, "create_time": start}

    groups = group_identical_command_lines([
        item(10, r"C:\Windows\system32\svchost.exe -k netsvcs", "2026-01-01T00:00:02"),
        item(11, r"c:\windows\system32\svchost.exe  -k netsvcs", "2026-01-01T00:00:01"),
        item(12, r"C:\Windows\system32\svchost.exe -k netsvcs", None),
        item(99, r"powershell -enc AAAA", "2026-01-01T00:05:00"),
    ])

    assert [g["command_line"] for g in groups] == [r"powershell -enc AAAA", r"C:\Windows\system32\svchost.exe -k netsvcs"]
    svchost = groups[1]
    assert svchost["count"] == 3
    assert svchost["pids"] == [10, 11, 12]
    assert svchost["first_start"] == "2026-01-01T00:00:01"
    assert svchost["last_start"] == "2026-01-01T00:00:02"


def test_command_lines_differing_only_in_numbers_are_variants_of_one_row() -> None:
    from app.services.memory.command_history import group_identical_command_lines

    groups = group_identical_command_lines([
        {"pid": 21, "process_name": "kworker/0:1", "command_line": "[kworker/0:1]", "create_time": None},
        {"pid": 22, "process_name": "kworker/1:2", "command_line": "[kworker/1:2]", "create_time": None},
        {"pid": 23, "process_name": "kworker/1:2", "command_line": "[kworker/1:2]", "create_time": None},
        {"pid": 1, "process_name": "init", "command_line": "/sbin/init splash", "create_time": None},
    ])

    kworker = next(g for g in groups if g["command_line"].startswith("[kworker"))
    assert kworker["count"] == 3
    assert kworker["variants"] == 2
    assert groups[0]["command_line"] == "/sbin/init splash"
