"""A small synthetic Velociraptor collection for the ingest integration test.

Laid out the way a Velociraptor offline collector writes it (``uploads/auto/C%3A/...``), with
files Kairon parses itself, without external tools: a Prefetch file (format version 30, as
Windows 10/11 write it once decompressed) and a scheduled task definition. Names and paths are
made up.
"""

from __future__ import annotations

import struct
import zipfile
from datetime import UTC, datetime
from pathlib import Path

ROOT = "uploads/auto/C%3A"
TASK_XML = """<?xml version="1.0" encoding="UTF-16"?>
<Task version="1.2" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
  <RegistrationInfo><Date>2024-03-03T10:15:00</Date><Author>WS01\\alice</Author><URI>\\Updater</URI></RegistrationInfo>
  <Principals><Principal id="Author"><UserId>S-1-5-21-1111111111-2222222222-3333333333-1001</UserId><LogonType>InteractiveToken</LogonType></Principal></Principals>
  <Triggers><LogonTrigger><Enabled>true</Enabled></LogonTrigger></Triggers>
  <Settings><Enabled>true</Enabled><Hidden>true</Hidden></Settings>
  <Actions Context="Author"><Exec><Command>C:\\Users\\Public\\updater.exe</Command><Arguments>-silent</Arguments></Exec></Actions>
</Task>
"""


def _filetime(value: datetime) -> bytes:
    return int((value - datetime(1601, 1, 1, tzinfo=UTC)).total_seconds() * 10_000_000).to_bytes(8, "little")


def prefetch(executable: str, path: str, last_run: datetime, run_count: int) -> bytes:
    """An uncompressed version-30 Prefetch file with one volume and two referenced files."""
    blob = bytearray(1024)
    struct.pack_into("<I", blob, 0, 30)
    blob[4:8] = b"SCCA"
    name = executable.encode("utf-16le")[:58]
    blob[16:16 + len(name)] = name
    info, volumes, strings_at = 84, 240, 420
    strings = (path + "\x00C:\\Windows\\System32\\KERNEL32.DLL\x00").encode("utf-16le")
    struct.pack_into("<IIII", blob, info + 16, strings_at, len(strings), volumes, 1)
    blob[info + 44:info + 52] = _filetime(last_run)
    struct.pack_into("<I", blob, info + 116, run_count)
    device, directory = "C:\\", path.rsplit("\\", 1)[0]
    struct.pack_into("<II", blob, volumes, 104, len(device))
    blob[volumes + 8:volumes + 16] = _filetime(datetime(2024, 1, 1, tzinfo=UTC))
    struct.pack_into("<I", blob, volumes + 16, 0x1234ABCD)
    struct.pack_into("<II", blob, volumes + 28, 140, 1)
    blob[volumes + 104:volumes + 104 + 2 * len(device)] = device.encode("utf-16le")
    struct.pack_into("<H", blob, volumes + 140, len(directory))
    blob[volumes + 142:volumes + 142 + 2 * len(directory)] = directory.encode("utf-16le")
    blob[strings_at:strings_at + len(strings)] = strings
    struct.pack_into("<I", blob, 12, len(blob))
    return bytes(blob)


def build(path: Path) -> dict:
    """Write the collection to ``path``; return how many events each artifact type should give."""
    files = {
        f"{ROOT}/Windows/Prefetch/UPDATER.EXE-1A2B3C4D.pf": prefetch("UPDATER.EXE", "C:\\Users\\Public\\updater.exe", datetime(2024, 3, 3, 10, 20, tzinfo=UTC), 3),
        f"{ROOT}/Windows/Prefetch/WHOAMI.EXE-5E6F7A8B.pf": prefetch("WHOAMI.EXE", "C:\\Windows\\System32\\whoami.exe", datetime(2024, 3, 3, 10, 21, tzinfo=UTC), 1),
        f"{ROOT}/Windows/System32/Tasks/Updater": b"\xff\xfe" + TASK_XML.encode("utf-16-le"),
    }
    with zipfile.ZipFile(path, "w", zipfile.ZIP_DEFLATED) as archive:
        for name, data in files.items():
            archive.writestr(name, data)
    return {"prefetch": 2, "scheduled_task": 1}
