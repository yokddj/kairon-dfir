"""Reads a raw SRUDB.dat (System Resource Usage Monitor, an ESE database) with
dissect.esedb and writes one CSV per provider table using SrumECmd's column
names, so the existing SrumECmd CSV normalizer indexes it unchanged.

SrumECmd itself refuses to run outside Windows (it loads esent.dll), which
left raw SRUM as tooling_missing on the Linux worker. The provider tables,
the SruDbIdMapTable lookups and the time encodings below follow the public
SRUM documentation and SrumECmd's own output; the CSV names deliberately do
not claim SrumECmd produced them.
"""

from __future__ import annotations

import csv
from datetime import UTC, datetime, timedelta
from pathlib import Path
import re
import struct

SRUM_ESEDB_BACKEND = "srum_esedb"

ID_MAP_TABLE = "SruDbIdMapTable"
ID_TYPE_SID = 3

# Provider GUID -> (output name, kind). Same seven outputs SrumECmd writes.
SRUM_TABLES: dict[str, tuple[str, str]] = {
    "{973F5D5C-1D90-4944-BE8E-24B94231A174}": ("NetworkUsages", "network_usage"),
    "{DD6636C4-8929-4683-974E-22C046A43763}": ("NetworkConnections", "network_connections"),
    "{D10CA2FE-6FCF-4F6D-848E-B2E99266FA89}": ("AppResourceUseInfo", "app_resource"),
    "{5C8CF1C7-7257-4F13-B223-970EF5939312}": ("AppTimelineProvider", "app_timeline"),
    "{FEE4E14F-02A9-4550-B5CE-5FA2DA202E37}": ("EnergyUsage", "energy"),
    "{FEE4E14F-02A9-4550-B5CE-5FA2DA202E37}LT": ("EnergyUsage", "energy_lt"),
    "{D10CA2FE-6FCF-4F6D-848E-B2E99266FA86}": ("PushNotifications", "push_notifications"),
    "{7ACBBAA3-D029-4BE4-9A7A-0885927F1D8F}": ("vfuprov", "vfuprov"),
}

COMMON_COLUMNS = ["Id", "Timestamp", "ExeInfo", "ExeInfoDescription", "ExeTimestamp", "SidType", "Sid", "UserName", "UserId", "AppId"]
APP_RESOURCE_COLUMNS = [
    "BackgroundBytesRead",
    "BackgroundBytesWritten",
    "BackgroundContextSwitches",
    "BackgroundCycleTime",
    "BackgroundNumberOfFlushes",
    "BackgroundNumReadOperations",
    "BackgroundNumWriteOperations",
    "FaceTime",
    "ForegroundBytesRead",
    "ForegroundBytesWritten",
    "ForegroundContextSwitches",
    "ForegroundCycleTime",
    "ForegroundNumberOfFlushes",
    "ForegroundNumReadOperations",
    "ForegroundNumWriteOperations",
]
ENERGY_LT_COLUMNS = ["ActiveAcTime", "ActiveDcTime", "ActiveDischargeTime", "ActiveEnergy", "CsAcTime", "CsDcTime", "CsDischargeTime", "CsEnergy"]
OUTPUT_COLUMNS: dict[str, list[str]] = {
    "NetworkUsages": COMMON_COLUMNS + ["BytesReceived", "BytesSent", "InterfaceLuid", "InterfaceType", "L2ProfileFlags", "L2ProfileId", "ProfileName"],
    "NetworkConnections": COMMON_COLUMNS + ["ConnectedTime", "ConnectStartTime", "InterfaceLuid", "InterfaceType", "L2ProfileFlags", "L2ProfileId", "ProfileName"],
    "AppResourceUseInfo": COMMON_COLUMNS + APP_RESOURCE_COLUMNS,
    "AppTimelineProvider": COMMON_COLUMNS + ["EndTime", "DurationMs"],
    "EnergyUsage": COMMON_COLUMNS
    + ["IsLt", "ConfigurationHash", "EventTimestamp", "StateTransition", "ChargeLevel", "CycleCount", "DesignedCapacity", "FullChargedCapacity"]
    + ENERGY_LT_COLUMNS,
    "PushNotifications": COMMON_COLUMNS + ["NetworkType", "NotificationType", "PayloadSize"],
    "vfuprov": COMMON_COLUMNS + ["StartTime", "EndTime", "Flags", "Duration"],
}

WELL_KNOWN_SIDS = {
    "S-1-5-18": ("LocalSystem", "SYSTEM"),
    "S-1-5-19": ("LocalService", "LOCAL SERVICE"),
    "S-1-5-20": ("NetworkService", "NETWORK SERVICE"),
}

# IANA ifType values; SRUM keeps the type in the top 16 bits of the interface LUID.
INTERFACE_TYPES = {
    1: "IF_TYPE_OTHER",
    6: "IF_TYPE_ETHERNET_CSMACD",
    23: "IF_TYPE_PPP",
    24: "IF_TYPE_SOFTWARE_LOOPBACK",
    53: "IF_TYPE_PROP_VIRTUAL",
    71: "IF_TYPE_IEEE80211",
    131: "IF_TYPE_TUNNEL",
    144: "IF_TYPE_IEEE1394",
    243: "IF_TYPE_WWANPP",
    244: "IF_TYPE_WWANPP2",
}

_OLE_EPOCH = datetime(1899, 12, 30, tzinfo=UTC)
_FILETIME_EPOCH = datetime(1601, 1, 1, tzinfo=UTC)
_TIME_FORMAT = "%Y-%m-%d %H:%M:%S"


def ole_timestamp(value: object) -> str:
    """SRUM's TimeStamp column is a JET DateTime: an OLE automation date
    (days since 1899-12-30 as a double). dissect hands back its raw 8 bytes
    as a signed integer."""
    if value is None:
        return ""
    if isinstance(value, datetime):
        moment = value if value.tzinfo else value.replace(tzinfo=UTC)
        return moment.astimezone(UTC).strftime(_TIME_FORMAT)
    try:
        days = struct.unpack("<d", struct.pack("<q", value))[0] if isinstance(value, int) else float(value)  # type: ignore[arg-type]
        if not days or days != days:
            return ""
        return (_OLE_EPOCH + timedelta(days=days)).strftime(_TIME_FORMAT)
    except (OverflowError, ValueError, TypeError, struct.error):
        return ""


def filetime_timestamp(value: object) -> str:
    try:
        ticks = int(value)  # type: ignore[arg-type]
    except (TypeError, ValueError):
        return ""
    if ticks <= 0:
        return ""
    try:
        return (_FILETIME_EPOCH + timedelta(microseconds=ticks // 10)).strftime(_TIME_FORMAT)
    except OverflowError:
        return ""


def timespan(ticks: int) -> str:
    """.NET TimeSpan text ([d.]hh:mm:ss.fffffff), as SrumECmd prints durations."""
    sign = "-" if ticks < 0 else ""
    ticks = abs(ticks)
    days, remainder = divmod(ticks, 864_000_000_000)
    hours, remainder = divmod(remainder, 36_000_000_000)
    minutes, remainder = divmod(remainder, 600_000_000)
    seconds, fraction = divmod(remainder, 10_000_000)
    text = f"{hours:02d}:{minutes:02d}:{seconds:02d}"
    if fraction:
        text = f"{text}.{fraction:07d}"
    return f"{sign}{days}.{text}" if days else f"{sign}{text}"


def sid_from_bytes(blob: bytes) -> str:
    if len(blob) < 8:
        return ""
    revision = blob[0]
    count = blob[1]
    authority = int.from_bytes(blob[2:8], "big")
    if len(blob) < 8 + 4 * count:
        return ""
    subs = struct.unpack(f"<{count}I", blob[8 : 8 + 4 * count]) if count else ()
    return "-".join(["S", str(revision), str(authority), *(str(item) for item in subs)])


def _utf16(blob: bytes) -> str:
    return blob.decode("utf-16-le", errors="ignore").split("\x00", 1)[0].strip()


_APP_STAMP_RE = re.compile(r"^(?P<head>.*?)!(?P<stamp>\d{4}/\d{2}/\d{2}:\d{2}:\d{2}:\d{2})!(?P<hash>[0-9A-Fa-f]*)!(?P<tail>.*)$")


def describe_app(value: str) -> tuple[str, str, str]:
    """Split SRUM's image identities into (name, description, timestamp):
    "!!svchost.exe!2028/05/11:16:56:05!15113f![Group] [Svc]" names a service
    host and its groups; "<package>!<app>!RuntimeBroker.exe!<stamp>!<hash>!"
    names a packaged app's executable. Anything else is the name itself."""
    match = _APP_STAMP_RE.match(value)
    if not match:
        return value, "", ""
    head = [part for part in match.group("head").split("!") if part]
    if not head:
        return value, "", ""
    try:
        stamp = datetime.strptime(match.group("stamp"), "%Y/%m/%d:%H:%M:%S").strftime(_TIME_FORMAT)
    except ValueError:
        stamp = ""
    description = " ".join(part for part in [match.group("tail").strip(), head[0] if len(head) > 1 else ""] if part)
    return head[-1], description, stamp


def read_id_map(db) -> tuple[dict[int, str], dict[int, str]]:
    apps: dict[int, str] = {}
    sids: dict[int, str] = {}
    for record in db.table(ID_MAP_TABLE).records():
        index = record.get("IdIndex")
        if index is None:
            continue
        blob = bytes(record.get("IdBlob") or b"")
        if record.get("IdType") == ID_TYPE_SID:
            sids[int(index)] = sid_from_bytes(blob)
        else:
            apps[int(index)] = _utf16(blob)
    return apps, sids


def read_profile_names(software_hive: Path | None) -> dict[str, str]:
    """SID -> profile folder name from the SOFTWARE hive's ProfileList."""
    if not software_hive or not software_hive.is_file():
        return {}
    try:
        from Registry import Registry

        key = Registry.Registry(str(software_hive)).open("Microsoft\\Windows NT\\CurrentVersion\\ProfileList")
    except Exception:  # noqa: BLE001
        return {}
    names: dict[str, str] = {}
    for subkey in key.subkeys():
        try:
            image_path = str(subkey.value("ProfileImagePath").value() or "")
        except Exception:  # noqa: BLE001
            continue
        leaf = image_path.replace("/", "\\").rstrip("\\").rsplit("\\", 1)[-1]
        if leaf:
            names[subkey.name().upper()] = leaf
    return names


def _interface_type(luid: object) -> str:
    try:
        number = int(luid) >> 48  # type: ignore[arg-type]
    except (TypeError, ValueError):
        return ""
    return INTERFACE_TYPES.get(number, str(number))


def _text(value: object) -> str:
    return "" if value is None else str(value)


def _value(record, column: str) -> object:
    """Columns vary between Windows builds; a missing one reads as empty."""
    try:
        return record.get(column)
    except Exception:  # noqa: BLE001
        return None


def _common(record, apps: dict[int, str], sids: dict[int, str], profiles: dict[str, str]) -> dict[str, str]:
    app_id = _value(record, "AppId")
    user_id = _value(record, "UserId")
    name, description, stamp = describe_app(apps.get(int(app_id), "") if app_id is not None else "")
    sid = sids.get(int(user_id), "") if user_id is not None else ""
    sid_type, user_name = WELL_KNOWN_SIDS.get(sid, ("UnknownOrUserSid", profiles.get(sid.upper(), "")))
    return {
        "Id": _text(_value(record, "AutoIncId")),
        "Timestamp": ole_timestamp(_value(record, "TimeStamp")),
        "ExeInfo": name,
        "ExeInfoDescription": description,
        "ExeTimestamp": stamp,
        "SidType": sid_type,
        "Sid": sid,
        "UserName": user_name,
        "UserId": _text(user_id),
        "AppId": _text(app_id),
    }


def _row(kind: str, record, common: dict[str, str]) -> dict[str, str]:
    row = dict(common)
    if kind in {"network_usage", "network_connections"}:
        luid = _value(record, "InterfaceLuid")
        row.update(
            {
                "InterfaceLuid": _text(luid),
                "InterfaceType": _interface_type(luid),
                "L2ProfileFlags": _text(_value(record, "L2ProfileFlags")),
                "L2ProfileId": _text(_value(record, "L2ProfileId")),
                "ProfileName": "",
            }
        )
        if kind == "network_usage":
            row["BytesReceived"] = _text(_value(record, "BytesRecvd"))
            row["BytesSent"] = _text(_value(record, "BytesSent"))
        else:
            row["ConnectedTime"] = _text(_value(record, "ConnectedTime"))
            row["ConnectStartTime"] = filetime_timestamp(_value(record, "ConnectStartTime"))
    elif kind == "app_resource":
        row.update({column: _text(_value(record, column)) for column in APP_RESOURCE_COLUMNS})
    elif kind == "app_timeline":
        row["EndTime"] = filetime_timestamp(_value(record, "EndTime"))
        row["DurationMs"] = _text(_value(record, "DurationMS"))
    elif kind in {"energy", "energy_lt"}:
        row.update(
            {
                "IsLt": "True" if kind == "energy_lt" else "False",
                "ConfigurationHash": _text(_value(record, "ConfigurationHash")),
                "EventTimestamp": filetime_timestamp(_value(record, "EventTimestamp")) if kind == "energy" else "",
                "StateTransition": _text(_value(record, "StateTransition")),
                "ChargeLevel": _text(_value(record, "ChargeLevel")),
                "CycleCount": _text(_value(record, "CycleCount")),
                "DesignedCapacity": _text(_value(record, "DesignedCapacity")),
                "FullChargedCapacity": _text(_value(record, "FullChargedCapacity")),
            }
        )
        row.update({column: _text(_value(record, column)) for column in ENERGY_LT_COLUMNS})
    elif kind == "push_notifications":
        row.update({column: _text(_value(record, column)) for column in ("NetworkType", "NotificationType", "PayloadSize")})
    elif kind == "vfuprov":
        start = _value(record, "StartTime")
        end = _value(record, "EndTime")
        row.update(
            {
                "StartTime": filetime_timestamp(start),
                "EndTime": filetime_timestamp(end),
                "Flags": _text(_value(record, "Flags")),
                "Duration": timespan(int(end) - int(start)) if isinstance(start, int) and isinstance(end, int) and start > 0 and end > 0 else "",
            }
        )
    return row


def write_srum_csvs(srum_path: Path, output_dir: Path, *, software_hive: Path | None = None) -> dict:
    """Write SRUM_<Table>.csv files into output_dir. Returns per-output row
    counts and per-table errors; a damaged table does not stop the others."""
    from dissect.esedb.esedb import EseDB

    output_dir.mkdir(parents=True, exist_ok=True)
    counts: dict[str, int] = {}
    errors: list[dict] = []
    profiles = read_profile_names(software_hive)
    with srum_path.open("rb") as handle:
        db = EseDB(handle)
        apps, sids = read_id_map(db)
        writers: dict[str, tuple[object, csv.DictWriter]] = {}
        try:
            for table_name, (output, kind) in SRUM_TABLES.items():
                try:
                    table = db.table(table_name)
                except Exception:  # noqa: BLE001
                    continue
                if output not in writers:
                    stream = (output_dir / f"SRUM_{output}.csv").open("w", encoding="utf-8", newline="")
                    writer = csv.DictWriter(stream, fieldnames=OUTPUT_COLUMNS[output], extrasaction="ignore")
                    writer.writeheader()
                    writers[output] = (stream, writer)
                    counts.setdefault(output, 0)
                writer = writers[output][1]
                try:
                    for record in table.records():
                        writer.writerow(_row(kind, record, _common(record, apps, sids, profiles)))
                        counts[output] += 1
                except Exception as exc:  # noqa: BLE001
                    errors.append({"table": table_name, "error": str(exc)[:500]})
        finally:
            for stream, _ in writers.values():
                stream.close()  # type: ignore[attr-defined]
    return {"tables": counts, "errors": errors, "users_resolved": len(profiles)}
