"""Routine system activity: only process starts whose name, image directory
and parent all match the platform baseline are hidden, and only on request."""

from __future__ import annotations

import json

from app.services import search_service
from app.services.routine_activity import ROUTINE_PROCESSES, is_routine_process, routine_process_clause


def test_a_process_is_routine_only_with_the_expected_image_and_parent() -> None:
    assert is_routine_process("svchost.exe", r"C:\Windows\System32\svchost.exe", "services.exe")
    assert is_routine_process("SVCHOST.EXE", r"\Device\HarddiskVolume3\Windows\SysWOW64\svchost.exe", "SERVICES.EXE")
    # Masquerading: wrong directory or wrong parent stays visible.
    assert not is_routine_process("svchost.exe", r"C:\Users\Public\svchost.exe", "services.exe")
    assert not is_routine_process("svchost.exe", r"C:\Windows\System32\svchost.exe", "cmd.exe")
    # Missing facts cannot be shown to match.
    assert not is_routine_process("svchost.exe", None, "services.exe")
    assert not is_routine_process("svchost.exe", r"C:\Windows\System32\svchost.exe", None)
    # Any parent for the console host, only from System32.
    assert is_routine_process("conhost.exe", r"C:\Windows\System32\conhost.exe", "evil.exe")
    assert not is_routine_process("conhost.exe", r"C:\Temp\conhost.exe", "cmd.exe")
    assert is_routine_process("mscorsvw.exe", r"C:\Windows\Microsoft.NET\Framework64\v4.0.30319\mscorsvw.exe", "ngen.exe")
    assert is_routine_process("systemd-journald", "/usr/lib/systemd/systemd-journald", "systemd")
    assert not is_routine_process("systemd-journald", "/tmp/systemd-journald", "systemd")


def test_tools_an_attacker_also_uses_are_never_routine() -> None:
    for name in ("wevtutil.exe", "schtasks.exe", "rundll32.exe", "powershell.exe", "cmd.exe", "regsvr32.exe", "mshta.exe", "wmic.exe", "sshd", "bash"):
        assert name not in ROUTINE_PROCESSES
    assert not is_routine_process("wevtutil.exe", r"C:\Windows\System32\wevtutil.exe", "svchost.exe")


def test_clause_needs_name_path_and_parent_and_escapes_backslashes() -> None:
    clause = routine_process_clause()
    entry = next(item for item in clause["bool"]["should"] if item["bool"]["filter"][0]["term"]["process.name"]["value"] == "svchost.exe")
    name, paths, parents = entry["bool"]["filter"]
    assert name["term"]["process.name"]["case_insensitive"] is True
    values = {list(item["wildcard"].values())[0]["value"] for item in paths["bool"]["should"]}
    assert "*\\\\windows\\\\system32\\\\svchost.exe" in values
    assert {list(item["term"].values())[0]["value"] for item in parents["bool"]["should"]} == {"services.exe"}
    conhost = next(item for item in clause["bool"]["should"] if item["bool"]["filter"][0]["term"]["process.name"]["value"] == "conhost.exe")
    assert len(conhost["bool"]["filter"]) == 2


def test_search_hides_routine_only_when_asked() -> None:
    assert routine_process_clause() not in search_service._build_event_exclusions("case-1", {}, None)
    for value in (True, "true", "1"):
        assert routine_process_clause() in search_service._build_event_exclusions("case-1", {"hide_routine": value}, None)
    # Memory results stay: their process rows carry no parent to match.
    assert "hide_routine" not in search_service.memory_unsupported_filters({"hide_routine": True})
    json.dumps(routine_process_clause())
