from __future__ import annotations

from typing import Any

from app.services.memory import timeline


def _memory_event(**extra: Any) -> dict[str, Any]:
    event = {
        "event_id": "mem-1",
        "is_undated": False,
        "occurred_at": "2024-03-22T12:00:00+00:00",
        "pid": 4242,
        "process_name": "powershell.exe",
        "executable_path": "C:\\Windows\\System32\\powershell.exe",
        "command_line_summary": "powershell.exe  -NoProfile",
        "artifact_type": "memory_process_entity",
        "artifact_family": "processes",
        "event_kind": "process_start",
    }
    event.update(extra)
    return event


def _disk_event(**extra: Any) -> dict[str, Any]:
    event = {
        "event_id": "disk-1",
        "is_undated": False,
        "occurred_at": "2024-03-22T12:00:02+00:00",
        "pid": 4242,
        "process_name": "powershell.exe",
        "executable_path": "C:\\Windows\\System32\\powershell.exe",
        "command_line_summary": "powershell.exe -NoProfile",
        "artifact_type": "windows_event_4688",
        "artifact_family": "windows_event_4688",
        "event_kind": "process_creation",
    }
    event.update(extra)
    return event


def test_precomputed_keys_match_inline_derivation() -> None:
    """The fast path must decide exactly what the naive per-pair path decides."""
    memory_events = [
        _memory_event(),
        _memory_event(event_id="mem-2", pid=17, process_name="cmd.exe", executable_path="C:\\Windows\\System32\\cmd.exe", command_line_summary=None),
        _memory_event(event_id="mem-3", occurred_at="2019-01-01T00:00:00+00:00"),
        _memory_event(event_id="mem-4", executable_path=None, command_line_summary='"C:\\Temp\\tool.exe" --run'),
    ]
    disk_events = [
        _disk_event(),
        _disk_event(event_id="disk-2", pid=99, process_name="cmd.exe", executable_path="D:\\other\\cmd.exe"),
        _disk_event(event_id="disk-3", process_name=None, executable_path=None, command_line_summary=None, title="powershell.exe"),
        _disk_event(event_id="disk-4", executable_path="C:\\Temp\\tool.exe", command_line_summary=None),
    ]

    for mem in memory_events:
        for disk in disk_events:
            precomputed = timeline._correlate_pair(
                mem,
                disk,
                timeline._correlation_key(mem, side="memory"),
                timeline._correlation_key(disk, side="disk"),
            )
            # Passing no keys makes _correlate_pair derive them itself, which is
            # the same work the pre-optimisation code did on every single pair.
            inline = timeline._correlate_pair(mem, disk)
            assert precomputed == inline, f"{mem['event_id']} x {disk['event_id']}"


def test_correlation_is_still_produced_for_a_matching_pair() -> None:
    """Guards against an optimisation that is fast because it matches nothing."""
    correlations = timeline._build_correlations([_memory_event()], [_disk_event()])
    assert len(correlations) == 1
    correlation = correlations[0]
    assert "same PID" in correlation["reasons"]
    assert "same normalized process name" in correlation["reasons"]
    assert correlation["time_delta_seconds"] == 2.0


def test_undated_events_never_correlate() -> None:
    assert timeline._build_correlations([_memory_event(is_undated=True)], [_disk_event()]) == []
    assert timeline._build_correlations([_memory_event()], [_disk_event(is_undated=True)]) == []


def test_mismatched_path_is_rejected() -> None:
    memory = _memory_event()
    disk = _disk_event(executable_path="D:\\elsewhere\\powershell.exe", pid=None)
    assert timeline._build_correlations([memory], [disk]) == []
