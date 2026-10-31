from __future__ import annotations

from pathlib import Path
import shutil
import sqlite3

from app.ingest.normalizer import normalize_file
from app.ingest.velociraptor.path_utils import normalize_velociraptor_path
from app.ingest.windows_ui.wpndatabase import filetime_iso, parse_wpndatabase, payload_content

FIREWALL_TOAST = (
    '<toast launch="windowsdefender://enable"><visual><binding template="ToastGeneric">'
    '<text id="1">Turn on Windows Firewall</text><text id="2">Windows Firewall is turned off.</text>'
    "</binding></visual></toast>"
)
CALENDAR_TILE = (
    '<tile><visual hint-lockDetailedStatus1="Board meeting" hint-lockDetailedStatus2="Room 4">'
    '<binding template="TileSmall"><text>Mon</text></binding><binding template="TileWide"><text>Mon</text><text>Board meeting</text></binding>'
    "</visual></tile>"
)
FILETIME = 133841314776938639  # 2025-02-15T22:17:57Z


def _database(folder: Path) -> tuple[Path, sqlite3.Connection]:
    folder.mkdir(parents=True, exist_ok=True)
    path = folder / "wpndatabase.db"
    connection = sqlite3.connect(path)
    connection.execute("PRAGMA journal_mode=WAL")
    connection.execute("PRAGMA wal_autocheckpoint=0")
    connection.execute("CREATE TABLE NotificationHandler (RecordId INTEGER PRIMARY KEY, PrimaryId TEXT, HandlerType TEXT, CreatedTime TEXT, ModifiedTime TEXT)")
    connection.execute('CREATE TABLE Notification ("Order" INTEGER, Id INTEGER, HandlerId INTEGER, Type TEXT, Payload BLOB, Tag TEXT, "Group" TEXT, ExpiryTime INTEGER, ArrivalTime INTEGER, PayloadType TEXT)')
    connection.executemany("INSERT INTO NotificationHandler VALUES (?, ?, ?, ?, ?)", [
        (1, "Windows.Defender.SecurityCenter", "app:desktop", "2025-02-04 19:11:26", "2025-02-04 19:11:26"),
        (2, "Microsoft.Windows.ParentalControls", "app:system", "2025-02-04 19:11:26", "2025-02-04 19:11:26"),
        (3, "microsoft.windowslive.calendar", "app:immersive", "2025-02-05 08:00:00", "2025-02-05 08:00:00"),
    ])
    connection.commit()
    return path, connection


def _notify(connection: sqlite3.Connection, *rows) -> None:
    connection.executemany('INSERT INTO Notification VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)', rows)
    connection.commit()


def test_payloads_give_title_and_lines():
    toast = payload_content("toast", FIREWALL_TOAST)
    assert (toast["title"], toast["lines"], toast["launch"]) == ("Turn on Windows Firewall", ["Windows Firewall is turned off."], "windowsdefender://enable")
    tile = payload_content("tile", CALENDAR_TILE)
    assert tile["title"] == "Mon" and tile["lines"] == ["Board meeting"] and tile["status"] == ["Board meeting", "Room 4"]
    assert payload_content("badge", '<badge value="3"/>')["title"] == "Badge 3"
    assert filetime_iso(FILETIME).startswith("2025-02-15T22:17:57")


def test_rows_still_in_the_wal_are_read_without_touching_the_evidence(tmp_path):
    path, connection = _database(tmp_path / "live")
    _notify(connection, (1, 76, 1, "toast", FIREWALL_TOAST.encode(), None, None, FILETIME + 10**12, FILETIME, "Xml"))
    evidence = tmp_path / "evidence"
    evidence.mkdir()
    for name in ("wpndatabase.db", "wpndatabase.db-wal", "wpndatabase.db-shm"):
        shutil.copy2(tmp_path / "live" / name, evidence / name)
    connection.close()
    before = {item.name: item.read_bytes() for item in evidence.iterdir()}

    rows, audit = parse_wpndatabase(evidence / "wpndatabase.db", source_path="C:/Users/alice/wpndatabase.db")

    assert {item.name: item.read_bytes() for item in evidence.iterdir()} == before
    notes = [row for row in rows if row["EventType"] == "notification_observed"]
    assert [(row["Title"], row["Body"], row["AppId"]) for row in notes] == [("Turn on Windows Firewall", "Windows Firewall is turned off.", "Windows.Defender.SecurityCenter")]
    registered = sorted(row["AppId"] for row in rows if row["EventType"] == "notification_app_registered")
    # Windows' own (app:system) handlers are left out.
    assert registered == ["Windows.Defender.SecurityCenter", "microsoft.windowslive.calendar"]
    assert audit["records_failed"] == 0


def test_notifications_become_windows_ui_events(tmp_path):
    path, connection = _database(tmp_path / "db")
    _notify(connection,
            (1, 76, 1, "toast", FIREWALL_TOAST.encode(), None, None, None, FILETIME, "Xml"),
            (2, 77, 3, "tile", CALENDAR_TILE.encode(), None, None, None, FILETIME + 10**7, "Xml"))
    connection.execute("PRAGMA wal_checkpoint(TRUNCATE)")
    connection.close()
    documents = normalize_file("case", "ev", "art", path, {"artifact_type": "windows_ui", "parser": "windows_notifications", "source_path": "C:/Users/alice/wpndatabase.db"})
    notes = {doc["notification"]["title"]: doc for doc in documents if doc["event"]["type"] == "notification_observed"}
    firewall = notes["Turn on Windows Firewall"]
    assert firewall["@timestamp"].startswith("2025-02-15T22:17:57")
    assert firewall["risk_score"] >= 70
    assert firewall["event"]["timeline_include"] is True
    assert notes["Mon"]["notification"]["body_preview"] == "Board meeting | Room 4"


def test_collection_paths_find_the_windows_volume():
    assert normalize_velociraptor_path("C/Users/alice/AppData/Local/x.db") == "C:\\Users\\alice\\AppData\\Local\\x.db"
    assert normalize_velociraptor_path("challenge/Users/bob/NTUSER.DAT") == "C:\\Users\\bob\\NTUSER.DAT"
    assert normalize_velociraptor_path("E/Windows/Prefetch/A.pf") == "E:\\Windows\\Prefetch\\A.pf"
    assert normalize_velociraptor_path("random/Users/notes.txt") == "random\\Users\\notes.txt"
