"""Sigma rules only judge the records they were written for: map-list selections, Windows service
channels, Sysmon categories and Linux rules against Windows records."""

from __future__ import annotations

from app.rules_engine.sigma import (
    build_sigma_rule_prefilter,
    channel_matches_service,
    compile_sigma_rule,
    evaluate_compiled_sigma_rule,
    evaluate_sigma_rule,
    parse_sigma_rule,
)

PSEXEC = r"""
title: PsExec Service Installation
logsource: {product: windows, service: system}
detection:
  selection_eid:
    Provider_Name: Service Control Manager
    EventID: 7045
  selection_service:
  - ServiceName: PSEXESVC
  - ImagePath|endswith: \PSEXESVC.exe
  condition: all of selection_*
"""


def _record(event_id: int, channel: str, provider: str = "", **extra) -> dict:
    return {"artifact": {"type": "windows_event"}, "windows": {"event_id": event_id, "channel": channel, "provider": provider}, **extra}


def _both(rule_text: str, document: dict) -> tuple[bool, bool]:
    rule = parse_sigma_rule(rule_text)[0]
    return evaluate_sigma_rule(rule, document)["matched"], evaluate_compiled_sigma_rule(compile_sigma_rule(rule), document)["matched"]


def test_a_list_of_maps_is_an_or_that_must_still_hold() -> None:
    vmware = _record(7045, "System", "Service Control Manager", service={"name": "VMware Tools", "image_path": "C:\\VMware\\vmtoolsd.exe"})
    assert _both(PSEXEC, vmware) == (False, False)
    by_name = _record(7045, "System", "Service Control Manager", service={"name": "PSEXESVC", "image_path": "x"})
    by_path = _record(7045, "System", "Service Control Manager", service={"name": "x", "image_path": "C:\\Windows\\PSEXESVC.exe"})
    assert _both(PSEXEC, by_name) == (True, True) and _both(PSEXEC, by_path) == (True, True)


def test_service_rules_only_run_on_their_channels() -> None:
    applocker = """
title: AppLocker
logsource: {product: windows, service: applocker}
detection:
  selection: {EventID: [8004, 8025]}
  condition: selection
"""
    assert _both(applocker, _record(8025, "Microsoft-Windows-HelloForBusiness/Operational")) == (False, False)
    assert _both(applocker, _record(8025, "Microsoft-Windows-AppLocker/MSI and Script")) == (True, True)
    defender = """
title: Defender
logsource: {product: windows, service: windefend}
detection:
  selection: {EventID: 1006}
  condition: selection
"""
    assert _both(defender, _record(1006, "Microsoft-Windows-Kernel-Boot/Operational")) == (False, False)
    assert _both(defender, _record(1006, "Microsoft-Windows-Windows Defender/Operational")) == (True, True)


def test_system_is_the_system_log_not_any_channel_naming_it() -> None:
    assert channel_matches_service("System", "system")
    assert not channel_matches_service("Microsoft-Windows-SystemDataArchiver/Diagnostic", "system")
    # A service Kairon does not know keeps running everywhere.
    assert channel_matches_service("Anything", "some-new-service")


def test_sysmon_categories_need_sysmon_records() -> None:
    wmi = """
title: WMI Event Subscription
logsource: {product: windows, category: wmi_event}
detection:
  selection: {EventID: [19, 20, 21]}
  condition: selection
"""
    assert _both(wmi, _record(20, "System")) == (False, False)
    assert _both(wmi, _record(20, "Microsoft-Windows-Sysmon/Operational")) == (True, True)


def test_linux_rules_do_not_run_on_windows_records() -> None:
    crontab = """
title: Modifying Crontab
logsource: {product: linux, service: cron}
detection:
  keywords: [REPLACE]
  condition: keywords
"""
    windows = {**_record(4688, "Security"), "message": "REPLACE INTO x", "search_text": "REPLACE INTO x"}
    assert _both(crontab, windows) == (False, False)


def test_candidate_channels_use_the_service_channels() -> None:
    rule = parse_sigma_rule(PSEXEC)[0]
    prefilter = build_sigma_rule_prefilter(rule, {"channels_present": {"System": 5, "Microsoft-Windows-SystemDataArchiver/Diagnostic": 3}})
    assert prefilter["channels"] == ["System"]


def test_contains_all_needs_every_value() -> None:
    rule = """
title: WindowStyle
logsource: {product: windows, category: ps_script}
detection:
  selection:
    ScriptBlockText|contains|all: [powershell, WindowStyle, Hidden]
  condition: selection
"""
    channel = "Microsoft-Windows-PowerShell/Operational"
    assert _both(rule, _record(4104, channel, powershell={"script_block_text": "powershell provider started"})) == (False, False)
    assert _both(rule, _record(4104, channel, powershell={"script_block_text": "powershell -WindowStyle Hidden -c x"})) == (True, True)


def test_script_block_rules_do_not_run_on_the_classic_powershell_log() -> None:
    rule = """
title: Script block
logsource: {product: windows, category: ps_script}
detection:
  selection:
    ScriptBlockText|contains: Invoke-Mimikatz
  condition: selection
"""
    assert _both(rule, _record(600, "Windows PowerShell", search_text="Invoke-Mimikatz", powershell={"script_block_text": "Invoke-Mimikatz"})) == (False, False)
