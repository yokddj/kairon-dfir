from __future__ import annotations

from pathlib import Path

import pytest

from app.ingest.detector import classify_artifact


@pytest.mark.parametrize(
    "filename",
    [
        "Microsoft-Windows-PowerShell%4Operational.evtx",
        "Microsoft-Windows-PowerShell%4Admin.evtx",
        "Windows PowerShell.evtx",
        "Microsoft-Windows-TaskScheduler%4Operational.evtx",
        "Microsoft-Windows-TaskScheduler%4Maintenance.evtx",
        "Microsoft-Windows-Windows Defender%4Operational.evtx",
        "Microsoft-Windows-DNS-Client%4Operational.evtx",
        "Security.evtx",
    ],
)
def test_event_logs_are_parsed_as_event_logs_whatever_the_channel_is_called(filename: str) -> None:
    """An .evtx is a binary event log however its channel is named.

    The name-based branches ran first and claimed these by channel: the
    PowerShell logs went to a JSON parser and the Task Scheduler ones to a CSV
    parser, both of which choke on a binary and reported "Expecting value:
    line 1 column 1" / "Dict key must be str". The EVTX parser had already
    ingested the same files correctly, so no events were lost -- but every
    collection finished completed_with_errors pointing at healthy artefacts.
    """
    result = classify_artifact(Path("/collection/C/Windows/System32/winevt/Logs") / filename)

    assert result["artifact_type"] == "windows_event", result
    assert result["parser"] == "evtx_raw", result


def test_oalerts_keeps_its_windows_ui_handling() -> None:
    """A deliberate exception that predates this rule and must survive it."""
    result = classify_artifact(Path("/collection/oalerts.evtx"))
    assert result["artifact_type"] == "windows_ui"


@pytest.mark.parametrize(
    ("filename", "expected_parser"),
    [
        ("powershell_events.json", "powershell_json"),
        ("powershell_events.jsonl", "powershell_jsonl"),
        ("ConsoleHost_history.txt", "powershell_history"),
    ],
)
def test_textual_powershell_artifacts_are_untouched(filename: str, expected_parser: str) -> None:
    """Only the binary logs move; EvtxECmd exports and history files do not."""
    result = classify_artifact(Path("/collection") / filename)
    assert result["parser"] == expected_parser, result
