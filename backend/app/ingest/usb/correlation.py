from __future__ import annotations

from app.ingest.usb.helpers import extract_drive_letter


def normalize_usb_profile_key(serial: str | None, device_instance_id: str | None, volume_serial: str | None, drive_letter: str | None) -> str | None:
    for value in (serial, device_instance_id, volume_serial, drive_letter):
        if value:
            return str(value).strip().lower()
    return None


def drive_letter_from_path(path: str | None) -> str | None:
    return extract_drive_letter(path)
