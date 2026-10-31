from __future__ import annotations

import csv
from pathlib import Path
import struct

import pytest

from app.ingest.normalizer import normalize_file, normalize_row
from app.ingest.raw_parsers import srum_esedb
from app.ingest.raw_parsers.srum_esedb import describe_app, filetime_timestamp, ole_timestamp, sid_from_bytes, timespan, write_srum_csvs
from app.ingest.shellbags.helpers import filesystem_path_from_shell_path


def _ole_bits(days: float) -> int:
    return struct.unpack("<q", struct.pack("<d", days))[0]


def _sid_blob(revision: int, authority: int, *subs: int) -> bytes:
    return bytes([revision, len(subs)]) + authority.to_bytes(6, "big") + struct.pack(f"<{len(subs)}I", *subs)


class _Record:
    def __init__(self, values: dict) -> None:
        self._values = values

    def get(self, column: str):
        if column not in self._values:
            raise KeyError(column)
        return self._values[column]


class _Table:
    def __init__(self, rows: list[dict]) -> None:
        self._rows = rows

    def records(self):
        return (_Record(row) for row in self._rows)


class _FakeEseDB:
    tables: dict[str, list[dict]] = {}

    def __init__(self, handle) -> None:
        self.handle = handle

    def table(self, name: str) -> _Table:
        if name not in self.tables:
            raise KeyError(name)
        return _Table(self.tables[name])


# 2026-03-28 11:57:00 UTC as an OLE automation date, and FILETIMEs around it.
_TIMESTAMP = _ole_bits(46109.497916666667)
_START = 134191725602128455  # 2026-03-28 11:56:00 UTC
_END = _START + 59 * 10_000_000


def test_srum_time_and_sid_decoding() -> None:
    assert ole_timestamp(_TIMESTAMP) == "2026-03-28 11:57:00"
    assert ole_timestamp(None) == ""
    assert filetime_timestamp(_START) == "2026-03-28 11:56:00"
    assert filetime_timestamp(0) == ""
    assert timespan(36_600_023_936) == "01:01:00.0023936"
    assert timespan(864_000_000_000 + 10_000_000) == "1.00:00:01"
    assert sid_from_bytes(_sid_blob(1, 5, 18)) == "S-1-5-18"
    assert sid_from_bytes(_sid_blob(1, 5, 21, 1, 2, 3, 1001)) == "S-1-5-21-1-2-3-1001"
    assert sid_from_bytes(b"\x01") == ""


def test_srum_app_identity_forms() -> None:
    assert describe_app("!!svchost.exe!2028/05/11:16:56:05!15113f![netsvcs] [Schedule]") == ("svchost.exe", "[netsvcs] [Schedule]", "2028-05-11 16:56:05")
    name, description, stamp = describe_app("Contoso.App_1.0_neutral__abc!app!RuntimeBroker.exe!2004/10/20:01:28:53!2c0b2!")
    assert (name, stamp) == ("RuntimeBroker.exe", "2004-10-20 01:28:53")
    assert description == "Contoso.App_1.0_neutral__abc"
    assert describe_app("\\Device\\HarddiskVolume3\\Windows\\System32\\smss.exe") == ("\\Device\\HarddiskVolume3\\Windows\\System32\\smss.exe", "", "")
    assert describe_app("AppXSvc") == ("AppXSvc", "", "")


def test_write_srum_csvs_matches_srumecmd_columns(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    import dissect.esedb.esedb as esedb_module

    _FakeEseDB.tables = {
        "SruDbIdMapTable": [
            {"IdType": 3, "IdIndex": 6, "IdBlob": _sid_blob(1, 5, 18)},
            {"IdType": 3, "IdIndex": 7, "IdBlob": _sid_blob(1, 5, 21, 1, 2, 3, 1001)},
            {"IdType": 0, "IdIndex": 91, "IdBlob": "\\device\\harddiskvolume3\\users\\alice\\downloads\\rclone.exe".encode("utf-16-le") + b"\x00\x00"},
            {"IdType": 0, "IdIndex": 92, "IdBlob": "!!svchost.exe!2028/05/11:16:56:05!15113f![netsvcs] [Schedule]".encode("utf-16-le")},
            {"IdType": 0, "IdIndex": 1, "IdBlob": None},
        ],
        "{973F5D5C-1D90-4944-BE8E-24B94231A174}": [
            {"AutoIncId": 1, "TimeStamp": _TIMESTAMP, "AppId": 91, "UserId": 7, "InterfaceLuid": 1689399632855040, "L2ProfileId": 0, "L2ProfileFlags": 0, "BytesSent": 300 * 1024 * 1024, "BytesRecvd": 4096},
        ],
        "{DD6636C4-8929-4683-974E-22C046A43763}": [
            {"AutoIncId": 1, "TimeStamp": _TIMESTAMP, "AppId": 1, "UserId": 6, "InterfaceLuid": 71 << 48, "L2ProfileId": 3, "ConnectedTime": 59, "ConnectStartTime": _START, "L2ProfileFlags": 0},
        ],
        "{5C8CF1C7-7257-4F13-B223-970EF5939312}": [
            {"AutoIncId": 9, "TimeStamp": _TIMESTAMP, "AppId": 92, "UserId": 6, "EndTime": _END, "DurationMS": 59000},
        ],
        # An energy table from a build without the long-term columns.
        "{FEE4E14F-02A9-4550-B5CE-5FA2DA202E37}": [
            {"AutoIncId": 1, "TimeStamp": _TIMESTAMP, "AppId": 1, "UserId": 6, "EventTimestamp": _START, "StateTransition": 256, "ChargeLevel": 0, "CycleCount": 0, "DesignedCapacity": 0, "FullChargedCapacity": 0, "ConfigurationHash": 0},
        ],
    }
    monkeypatch.setattr(esedb_module, "EseDB", _FakeEseDB)
    database = tmp_path / "SRUDB.dat"
    database.write_bytes(b"ese")

    result = write_srum_csvs(database, tmp_path / "out")

    assert result["errors"] == []
    assert result["tables"] == {"NetworkUsages": 1, "NetworkConnections": 1, "AppTimelineProvider": 1, "EnergyUsage": 1}
    usage = list(csv.DictReader((tmp_path / "out" / "SRUM_NetworkUsages.csv").open(encoding="utf-8")))[0]
    assert usage["Timestamp"] == "2026-03-28 11:57:00"
    assert usage["ExeInfo"].endswith("\\downloads\\rclone.exe")
    assert usage["Sid"] == "S-1-5-21-1-2-3-1001"
    assert usage["SidType"] == "UnknownOrUserSid"
    assert usage["BytesSent"] == str(300 * 1024 * 1024)
    assert usage["BytesReceived"] == "4096"
    assert usage["InterfaceType"] == "IF_TYPE_ETHERNET_CSMACD"
    connection = list(csv.DictReader((tmp_path / "out" / "SRUM_NetworkConnections.csv").open(encoding="utf-8")))[0]
    assert connection["ConnectStartTime"] == "2026-03-28 11:56:00"
    assert connection["ConnectedTime"] == "59"
    assert connection["InterfaceType"] == "IF_TYPE_IEEE80211"
    assert connection["UserName"] == "SYSTEM"
    timeline = list(csv.DictReader((tmp_path / "out" / "SRUM_AppTimelineProvider.csv").open(encoding="utf-8")))[0]
    assert (timeline["ExeInfo"], timeline["ExeInfoDescription"]) == ("svchost.exe", "[netsvcs] [Schedule]")
    assert timeline["EndTime"] == "2026-03-28 11:56:59"
    energy = list(csv.DictReader((tmp_path / "out" / "SRUM_EnergyUsage.csv").open(encoding="utf-8")))[0]
    assert energy["IsLt"] == "False"
    assert energy["ActiveAcTime"] == ""


def test_write_srum_csvs_names_users_from_software_profile_list(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    import dissect.esedb.esedb as esedb_module

    _FakeEseDB.tables = {
        "SruDbIdMapTable": [{"IdType": 3, "IdIndex": 7, "IdBlob": _sid_blob(1, 5, 21, 1, 2, 3, 1001)}],
        "{973F5D5C-1D90-4944-BE8E-24B94231A174}": [{"AutoIncId": 1, "TimeStamp": _TIMESTAMP, "AppId": 5, "UserId": 7, "InterfaceLuid": 0, "BytesSent": 1, "BytesRecvd": 1}],
    }
    monkeypatch.setattr(esedb_module, "EseDB", _FakeEseDB)
    monkeypatch.setattr(srum_esedb, "read_profile_names", lambda hive: {"S-1-5-21-1-2-3-1001": "alice"} if hive else {})
    database = tmp_path / "SRUDB.dat"
    database.write_bytes(b"ese")

    write_srum_csvs(database, tmp_path / "out", software_hive=tmp_path / "SOFTWARE")

    row = list(csv.DictReader((tmp_path / "out" / "SRUM_NetworkUsages.csv").open(encoding="utf-8")))[0]
    assert row["UserName"] == "alice"


SRUM_META = {"artifact_type": "srum", "source_path": "C:\\Windows\\System32\\sru\\SRUDB.dat", "parser": "srum_esedb"}


def _srum_doc(row: dict, table: str) -> dict:
    return normalize_row("case-1", "ev-1", "art-1", row, {**SRUM_META, "name": f"SRUM - SRUM_{table}"})


def _base_row(**overrides) -> dict:
    row = {"Id": "1", "Timestamp": "2026-03-28 11:57:00", "ExeInfoDescription": "", "ExeTimestamp": "", "SidType": "UnknownOrUserSid", "Sid": "S-1-5-21-1-2-3-1001", "UserName": "alice", "UserId": "7", "AppId": "94"}
    row.update(overrides)
    return row


def test_srumecmd_numeric_app_id_is_not_the_application() -> None:
    doc = _srum_doc(_base_row(ExeInfo="\\Device\\HarddiskVolume3\\Windows\\System32\\certutil.exe", BytesSent="1024", BytesReceived="2048"), "NetworkUsages")
    assert doc["process"]["name"] == "certutil.exe"
    assert doc["srum"]["app_id"] != "94"
    assert doc["srum"]["artifact_type"] == "srum_network_usage"
    assert doc["user"]["sid"] == "S-1-5-21-1-2-3-1001"
    assert "SRUM network activity by LOLBin" in doc["suspicious_reasons"]


def test_srumecmd_network_connection_uses_start_time_and_seconds() -> None:
    doc = _srum_doc(_base_row(ExeInfo="", ConnectedTime="3615", ConnectStartTime="2026-03-28 11:57:44", InterfaceType="IF_TYPE_ETHERNET_CSMACD"), "NetworkConnections")
    assert doc["srum"]["artifact_type"] == "srum_network_connectivity"
    assert doc["@timestamp"].startswith("2026-03-28T11:57:44")
    assert doc["timestamp_precision"] == "srum_connect_start_time"
    assert doc["srum"]["duration"] == 3615
    assert "connected 3615 s" in doc["event"]["message"]


def test_srumecmd_timeline_rows_are_not_network_leads() -> None:
    doc = _srum_doc(_base_row(ExeInfo="powershell.exe", EndTime="2026-03-28 11:57:00", DurationMs="668468"), "AppTimelineProvider")
    assert doc["srum"]["artifact_type"] == "srum_app_timeline"
    assert doc["srum"]["duration"] == 668
    assert doc["risk_score"] == 0
    assert not doc["suspicious_reasons"]


def test_srumecmd_vfu_duration_timespan() -> None:
    doc = _srum_doc(_base_row(ExeInfo="U", StartTime="2026-03-28 11:57:00", EndTime="2026-03-28 12:58:00", Duration="01:01:00.0023936"), "vfuprov")
    assert doc["srum"]["artifact_type"] == "srum_vfu"
    assert doc["srum"]["duration"] == 3660


def test_srum_svchost_service_group_in_message_not_in_application() -> None:
    doc = _srum_doc(_base_row(ExeInfo="svchost.exe", ExeInfoDescription="[netsvcs] [Schedule]", BytesSent="10", BytesReceived="20"), "NetworkUsages")
    assert doc["srum"]["application"] == "svchost.exe"
    assert doc["srum"]["exe_description"] == "[netsvcs] [Schedule]"
    assert "svchost.exe [netsvcs] [Schedule]" in doc["event"]["message"]


@pytest.mark.parametrize(
    "exe_info",
    [
        "\\Device\\HarddiskVolume3\\Windows\\System32\\AggregatorHost.exe",  # "tor" inside a word
        "InventorySvc",
        "\\device\\harddiskvolume3\\users\\alice\\appdata\\local\\microsoft\\onedrive\\onedrive.exe",
        "\\Device\\HarddiskVolume3\\ProgramData\\Microsoft\\Windows Defender\\Platform\\4.18.1-0\\MsMpEng.exe",
        "AppXSvc",
    ],
)
def test_srum_routine_applications_are_not_suspicious(exe_info: str) -> None:
    doc = _srum_doc(_base_row(ExeInfo=exe_info, BytesSent="5000", BytesReceived="90000"), "NetworkUsages")
    assert "suspicious" not in doc["tags"]
    assert doc["risk_score"] < 40


def test_srum_tool_names_still_match() -> None:
    tor = _srum_doc(_base_row(ExeInfo="\\Device\\HarddiskVolume3\\Users\\alice\\Desktop\\Tor Browser\\Browser\\tor.exe", BytesSent="5000", BytesReceived="90000"), "NetworkUsages")
    rclone = _srum_doc(_base_row(ExeInfo="\\Device\\HarddiskVolume3\\Users\\alice\\Downloads\\rclone.exe", BytesSent=str(200 * 1024 * 1024), BytesReceived="1000"), "NetworkUsages")
    assert "remote_access_tool" in tor["tags"]
    assert {"file_transfer_tool", "possible_exfiltration", "suspicious_path"} <= set(rclone["tags"])


def test_srum_unattributed_rows_raise_no_volume_lead() -> None:
    doc = _srum_doc(_base_row(ExeInfo="", BytesSent=str(50 * 1024 * 1024), BytesReceived="100"), "NetworkUsages")
    assert "missing_application" in doc["data_quality"]
    assert "high_upload" not in doc["tags"]


def test_srum_delivery_optimization_upload_is_not_a_lead() -> None:
    doc = _srum_doc(_base_row(ExeInfo="DoSvc", BytesSent=str(300 * 1024 * 1024), BytesReceived="1000"), "NetworkUsages")
    assert "high_upload" not in doc["tags"]
    assert doc["risk_score"] < 40


def test_srum_push_notifications_stay_srum(tmp_path: Path) -> None:
    path = tmp_path / "SRUM_PushNotifications.csv"
    path.write_text("Id,Timestamp,ExeInfo,ExeInfoDescription,ExeTimestamp,SidType,Sid,UserName,UserId,AppId,NetworkType,NotificationType,PayloadSize\n1,2026-03-28 11:57:00,Contoso.App,,,UnknownOrUserSid,,,2,1,0,1,120\n", encoding="utf-8")
    docs = normalize_file("case-1", "ev-1", "art-1", path, {**SRUM_META, "name": "SRUM - SRUM_PushNotifications"})
    assert docs[0]["artifact"]["type"] == "srum"
    assert docs[0]["srum"]["artifact_type"] == "srum_push_notification"


@pytest.mark.parametrize(
    ("shell_path", "expected"),
    [
        ("Desktop\\This PC\\C:\\Users\\alice", "C:\\Users\\alice"),
        ("Desktop\\My Computer\\C:", "C:\\"),
        ("Desktop\\E:\\\\factura", "E:\\factura"),
        ("Desktop\\Computers and Devices\\srv01\\srv01\\share\\Startup_scripts", "\\\\srv01\\share\\Startup_scripts"),
        ("Desktop\\Computers and Devices\\srv01", "\\\\srv01"),
        ("\\\\srv01\\files", "\\\\srv01\\files"),
        ("Desktop\\Downloads\\Sysmon", None),
        ("Desktop\\Unmapped GUID: 60a9b097-020e-49da-acc9-f877308c59be\\proxmox", None),
    ],
)
def test_shellbag_filesystem_path_from_shell_namespace(shell_path: str, expected: str | None) -> None:
    assert filesystem_path_from_shell_path(shell_path) == expected


SBECMD_HEADER = "BagPath,Slot,NodeSlot,MRUPosition,AbsolutePath,ShellType,Value,ChildBags,CreatedOn,ModifiedOn,AccessedOn,LastWriteTime,MFTEntry,MFTSequenceNumber,ExtensionBlockCount,FirstInteracted,LastInteracted,HasExplored,Miscellaneous"


def _sbecmd_docs(tmp_path: Path, *rows: str) -> list[dict]:
    path = tmp_path / "UsrClass.csv"
    path.write_text("\n".join([SBECMD_HEADER, *rows]) + "\n", encoding="utf-8")
    meta = {"artifact_type": "shellbags", "name": "SBECmd Shellbags", "parser": "sbecmd_csv", "source_path": "uploads/auto/C%3A/Users/alice/AppData/Local/Microsoft/Windows/UsrClass.dat"}
    return normalize_file("case-1", "ev-1", "art-1", path, meta)


def test_sbecmd_drive_folders_are_not_control_panel_items(tmp_path: Path) -> None:
    docs = _sbecmd_docs(
        tmp_path,
        "BagMRU\\3\\0,0,8,0,Desktop\\This PC\\C:\\Users\\alice,Directory,alice,0,,,,2026-03-28 16:06:24,225089,3,1,2026-03-28 16:06:24,2026-03-28 16:06:24,True,NTFS file system",
        "BagMRU\\0,0,2,0,Desktop\\ControlPanelHome\\Network and Internet,Control Panel Category,Network and Internet,0,,,,2026-03-28 16:06:24,,,0,,,False,",
    )
    folder, control_panel = docs
    assert folder["file"]["path"] == "C:\\Users\\alice"
    assert folder["shellbag"]["absolute_path"] == "Desktop\\This PC\\C:\\Users\\alice"
    assert folder["shellbag"]["is_control_panel"] is False
    assert folder["user"]["name"] == "alice"
    assert control_panel["shellbag"]["is_control_panel"] is True


def test_sbecmd_network_locations_and_rdp_client_drive(tmp_path: Path) -> None:
    share, tsclient = _sbecmd_docs(
        tmp_path,
        "BagMRU\\0\\0,0,0,0,Desktop\\Computers and Devices\\srv01\\srv01\\files\\passwords,Directory,passwords,0,,,,2024-01-16 17:44:05,,,1,,2024-01-16 17:44:05,True,",
        "BagMRU\\1\\0,0,3,0,Desktop\\Computers and Devices\\tsclient\\tsclient\\_home_user_tools,Network location,\\\\tsclient\\_home_user_tools,0,,,,2024-03-22 12:56:24,,,0,,2024-03-22 12:56:24,False,",
    )
    assert share["file"]["path"] == "\\\\srv01\\files\\passwords"
    assert share["shellbag"]["is_network_path"] is True
    assert share["network"]["destination_hostname"] == "srv01"
    assert share["network"]["share_name"] == "files"
    assert "rdp_client_drive" in tsclient["tags"]
    assert any("RDP client" in reason for reason in tsclient["suspicious_reasons"])


def test_sbecmd_stage_copies_transaction_logs(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    from app.ingest.raw_parsers import sbecmd_backend

    profile = tmp_path / "Users" / "alice" / "AppData" / "Local" / "Microsoft" / "Windows"
    profile.mkdir(parents=True)
    (profile / "UsrClass.dat").write_bytes(b"regf")
    (profile / "UsrClass.dat.LOG1").write_bytes(b"log1")
    (profile / "UsrClass.dat.LOG2").write_bytes(b"log2")
    (profile / "UsrClass.dat.idx").write_bytes(b"velociraptor index")
    monkeypatch.setattr(sbecmd_backend, "build_evidence_root", lambda case_id, evidence_id: tmp_path / "evidence")

    stage = sbecmd_backend._stage_hive("case-1", "ev-1", "Users/alice/AppData/Local/Microsoft/Windows/UsrClass.dat", profile / "UsrClass.dat", tmp_path / "stage")

    assert sorted(path.name for path in stage.iterdir()) == ["UsrClass.dat", "UsrClass.dat.LOG1", "UsrClass.dat.LOG2"]
