from __future__ import annotations

from app.ingest.normalizer import build_search_text


def _doc(event_data: dict) -> dict:
    return {
        "event": {"message": "Successful logon"},
        "host": {"name": "DC02"},
        "user": {"name": "attacker01"},
        "windows": {"event_id": 4624, "event_data": event_data},
    }


def test_event_data_values_are_searchable() -> None:
    """windows.event_data is mapped "enabled": false to avoid a field
    explosion, so nothing inside it is indexed. WorkstationName and friends
    were therefore visible in the detail panel yet unfindable by search, which
    reads as "that value does not exist in this case" -- the exact failure that
    hid an attacker's machine name during a real investigation.
    """
    text = build_search_text(_doc({"WorkstationName": "ubuntu", "TargetUserName": "attacker01", "IpAddress": "10.10.10.42"}))
    assert "ubuntu" in text
    assert "10.10.10.42" in text


def test_placeholder_values_are_not_folded_in() -> None:
    """Windows writes "-" and "0x0" in most unused fields. Keeping them would
    add thousands of useless tokens to every event."""
    text = build_search_text(_doc({"WorkstationName": "-", "Status": "0x0", "SubjectUserName": "DC02$"}))
    assert "DC02$" in text
    assert " | - | " not in f" | {text} | "


def test_huge_and_structured_values_are_skipped() -> None:
    """raw_xml and payload_columns duplicate the whole event; folding them in
    would blow the 8192-char search_text budget and evict real values."""
    text = build_search_text(
        _doc({"raw_xml": "<Event>" + "x" * 5000 + "</Event>", "payload_columns": {"PayloadData1": "noise"}, "ServiceName": "SRV01$"})
    )
    assert "ServiceName" not in text or "SRV01$" in text
    assert "xxxxxxxxxx" not in text
    assert "noise" not in text


def test_search_text_stays_within_budget() -> None:
    text = build_search_text(_doc({f"Field{i}": f"value-{i}" for i in range(200)}))
    assert len(text) <= 8192


def test_existing_fields_still_present() -> None:
    """Regression guard: folding event_data in must not displace what
    search_text already carried."""
    text = build_search_text(_doc({"WorkstationName": "ubuntu"}))
    assert "DC02" in text and "attacker01" in text and "Successful logon" in text


def test_command_lines_are_long_enough_to_survive() -> None:
    """Service ImagePaths and process command lines routinely exceed 160 chars.
    The first version capped there and silently dropped exactly the content an
    analyst greps for -- e.g. the CrackMapExec service command line that names
    its LSASS dump file."""
    command = (
        "%COMSPEC% /Q /c CMD.Exe /Q /c for /f \"tokens=1,2 delims= \" ^%A in "
        "('\"tasklist /fi \"Imagename eq lsass.exe\" | find \"lsass\"\"') do "
        "rundll32.exe C:\\windows\\System32\\comsvcs.dll, #+0000^24 ^%B \\Windows\\Temp\\JuyTiUv5g.ico full"
    )
    assert len(command) > 160
    text = build_search_text(_doc({"ServiceName": "abjtTGiR", "ImagePath": command}))
    assert "JuyTiUv5g" in text
    assert "abjtTGiR" in text
