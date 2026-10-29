"""Find Evil AV_DETECT lines parsed into time, threat, source and target, and
the records of one detection grouped."""

from __future__ import annotations

from app.services.memory.antivirus_detections import group_detections, parse_av_detect

CMDLINE_EVENT = (
    "AV:[Windows Defender] EVENT:[2026-01-10T09:15:02.100Z DETECTIONEVENT MPSOURCE_SYSTEM Trojan:Win32/Example.A!ml "
    "CmdLine:C:\\Users\\Public\\tool.exe dump /target:SRV/svc.example.local:1433;internalCmdLine:i n AQAAAAeU]"
)
CMDLINE_ADD = (
    "AV:[Windows Defender] EVENT:[2026-01-10T09:15:02.110Z DETECTION_ADD#2 Trojan:Win32/Example.A!ml "
    "CmdLine:C:\\Users\\Public\\tool.exe dump /target:SRV/svc.example.local:1433 PropBag [length: 0, data: (null)]]"
)
CMDLINE_INTERNAL = "AV:[Windows Defender] EVENT:[2026-01-10T09:15:02.110Z DETECTION_ADD#2 Trojan:Win32/Example.A!ml internalCmdLine:i n AQAAAAeUBYD"
FILE_EVENT = "AV:[Windows Defender] EVENT:[2026-01-10T09:01:00.000Z DETECTIONEVENT MPSOURCE_REALTIME HackTool:Win32/Sample.B file:\\\\tsclient\\share\\sample.exe;]"
AMSI_EVENT = "AV:[Windows Defender] EVENT:[2026-01-10T09:20:00.000Z DETECTIONEVENT MPSOURCE_AMSI HackTool:Win32/Sample.B amsi:\\Device\\HarddiskVolume3\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe;internalamsi:7B89]"
CMDLINE_LATER = CMDLINE_EVENT.replace("09:15:02.100Z", "09:25:40.000Z")


def test_av_detect_line_is_parsed_into_fields() -> None:
    parsed = parse_av_detect(CMDLINE_EVENT)
    assert parsed is not None
    assert parsed["engine"] == "Windows Defender"
    assert parsed["time"] == "2026-01-10T09:15:02.100Z"
    assert parsed["source"] == "MPSOURCE_SYSTEM" and parsed["source_label"] == "system scan"
    assert parsed["threat"] == "Trojan:Win32/Example.A!ml"
    assert parsed["target_kind"] == "cmdline"
    assert parsed["target"] == "C:\\Users\\Public\\tool.exe dump /target:SRV/svc.example.local:1433"
    assert parse_av_detect(CMDLINE_ADD)["target"] == parsed["target"]
    assert parse_av_detect(FILE_EVENT)["target"] == "\\\\tsclient\\share\\sample.exe"
    assert parse_av_detect(AMSI_EVENT)["target_kind"] == "amsi"
    # Only opaque internal data: parsed, but nothing to show as a target.
    assert parse_av_detect(CMDLINE_INTERNAL)["target"] is None
    assert parse_av_detect(CMDLINE_INTERNAL + " PropBag [length: 0, data: (null)]]")["target"] is None
    assert parse_av_detect("Some other Find Evil text") is None
    assert parse_av_detect(None) is None


def test_records_of_one_detection_are_grouped_in_time_order() -> None:
    groups = group_detections([CMDLINE_EVENT, CMDLINE_ADD, CMDLINE_INTERNAL, CMDLINE_LATER, AMSI_EVENT, FILE_EVENT, "garbage"])
    assert [group["threat"] for group in groups] == ["HackTool:Win32/Sample.B", "Trojan:Win32/Example.A!ml", "HackTool:Win32/Sample.B"]
    command = groups[1]
    assert command["records"] == 3
    assert command["first_seen"] == "2026-01-10T09:15:02.100Z" and command["last_seen"] == "2026-01-10T09:25:40.000Z"
    assert command["sources"] == ["system scan"]
    assert groups[0]["target_kind"] == "file" and groups[0]["sources"] == ["real-time protection"]
