from __future__ import annotations

from pathlib import Path, PureWindowsPath
import re

from app.ingest.eztools.base import read_delimited_rows


USB_NAME_HINTS = (
    "setupapi",
    "usbstor",
    "mounteddevices",
    "mountpoints2",
    "portabledevices",
    "deviceclasses",
    "userpnp",
    "kernel-pnp",
    "driverframeworks",
    "usb",
)
USB_HEADER_HINTS = {
    "deviceinstanceid",
    "deviceinstanceid",
    "instanceid",
    "artifacttype",
    "classname",
    "vendor",
    "product",
    "revision",
    "serial",
    "friendlyname",
    "parentidprefix",
    "containerid",
    "classguid",
    "service",
    "driver",
    "firstinstalldate",
    "installdate",
    "lastarrivaldate",
    "lastremovaldate",
    "volumeguid",
    "driveletter",
    "mounteddevice",
    "dosdevices",
    "lastwritetime",
    "keypath",
    "valuename",
    "valuedata",
    "timecreated",
}
USB_PATH_KEYWORDS = ("\\usb\\", "\\usbstor\\", "\\wpdbusenum\\", "\\mounteddevices", "\\portable devices\\")
GENERIC_USB_CLASS_RE = re.compile(r"^USB\\CLASS_[0-9A-F]{2}$", re.IGNORECASE)
GENERIC_USB_ROOT_RE = re.compile(r"^USB\\ROOT_HUB(?:30)?(?:\\.*)?$", re.IGNORECASE)


def canonicalize_header(value: object) -> str:
    return re.sub(r"[^a-z0-9]+", "", str(value).strip().lower())


def normalize_windows_path(value: str | None) -> str | None:
    if value in (None, ""):
        return None
    normalized = str(value).strip().strip('"')
    if normalized.lower() in {"-", "--", "n/a", "na", "(null)", "null", "none"}:
        return None
    return normalized.replace("/", "\\")


def basename_windows(path: str | None) -> str | None:
    normalized = normalize_windows_path(path)
    if not normalized:
        return None
    try:
        return PureWindowsPath(normalized).name or normalized
    except Exception:  # noqa: BLE001
        return Path(normalized.replace("\\", "/")).name or normalized


def suffix_windows(path: str | None) -> str | None:
    normalized = normalize_windows_path(path)
    if not normalized:
        return None
    try:
        suffix = PureWindowsPath(normalized).suffix.lower()
        return suffix or None
    except Exception:  # noqa: BLE001
        suffix = Path(normalized.replace("\\", "/")).suffix.lower()
        return suffix or None


def infer_usb_user_from_path(path: str | None) -> str | None:
    normalized = normalize_windows_path(path)
    if not normalized:
        return None
    match = re.search(r"\\users\\(?P<user>[^\\]+)\\", normalized, re.IGNORECASE)
    return match.group("user") if match else None


def looks_like_setupapi_log(path: Path) -> bool:
    normalized = normalize_windows_path(str(path)) or str(path)
    lower = normalized.lower()
    return lower.endswith("windows\\inf\\setupapi.dev.log")


def looks_like_usb_artifact(path: Path, headers: list[str] | None = None) -> bool:
    lower_name = path.name.lower()
    suffix = path.suffix.lower()
    if suffix == ".log" and looks_like_setupapi_log(path):
        return True
    if suffix in {".csv", ".json", ".jsonl", ".txt", ".log"} and any(token in lower_name for token in USB_NAME_HINTS):
        return True
    if any(keyword in (normalize_windows_path(str(path)) or "").lower() for keyword in USB_PATH_KEYWORDS):
        return True
    header_set = {canonicalize_header(header) for header in (headers or []) if header}
    return len(header_set & USB_HEADER_HINTS) >= 3


def read_usb_csv_rows(path: Path) -> list[dict]:
    return list(read_delimited_rows(path))


def parse_usb_device_instance_id(device_instance_id: str | None) -> dict[str, str | None]:
    raw = normalize_windows_path(device_instance_id)
    result = {
        "raw_instance_id": raw,
        "device_type": None,
        "vendor": None,
        "product": None,
        "revision": None,
        "serial": None,
        "vid": None,
        "pid": None,
    }
    if not raw:
        return result

    upper = raw.upper()
    if upper.startswith("USBSTOR\\"):
        match = re.search(
            r"USBSTOR\\(?P<device_type>[^&\\]+)&Ven_(?P<vendor>[^&\\]+)&Prod_(?P<product>[^&\\]+)&Rev_(?P<revision>[^\\]+)\\(?P<serial>.+)$",
            raw,
            re.IGNORECASE,
        )
        if match:
            serial = re.sub(r"&0$", "", match.group("serial"), flags=re.IGNORECASE)
            result.update(
                {
                    "device_type": match.group("device_type"),
                    "vendor": match.group("vendor").replace("_", " ").strip(),
                    "product": match.group("product").replace("_", " ").strip(),
                    "revision": match.group("revision").replace("_", " ").strip(),
                    "serial": serial.strip(),
                }
            )
        return result

    if upper.startswith("USB\\"):
        match = re.search(r"USB\\VID_(?P<vid>[0-9A-F]{4})&PID_(?P<pid>[0-9A-F]{4})\\(?P<serial>.+)$", raw, re.IGNORECASE)
        if match:
            serial = match.group("serial").strip()
            result.update(
                {
                    "device_type": "USB",
                    "vid": match.group("vid").upper(),
                    "pid": match.group("pid").upper(),
                    "serial": serial,
                }
            )
        elif GENERIC_USB_CLASS_RE.match(raw) or GENERIC_USB_ROOT_RE.match(raw):
            result["device_type"] = "usb_class_generic"
        return result

    if upper.startswith("SWD\\WPDBUSENUM\\") or upper.startswith("WPD\\"):
        result["device_type"] = "WPD"
        result["serial"] = raw.split("\\")[-1]
        return result

    if upper.startswith("STORAGE\\"):
        result["device_type"] = "STORAGE"
        result["serial"] = raw.split("\\")[-1]
        return result

    return result


def extract_drive_letter(value: str | None) -> str | None:
    normalized = normalize_windows_path(value)
    if not normalized:
        return None
    match = re.search(r"(?<![A-Z])([A-Z]:)(?:\\|$)", normalized, re.IGNORECASE)
    return match.group(1).upper() if match else None


def is_probable_usb_path(path: str | None) -> bool:
    drive = extract_drive_letter(path)
    if not drive:
        return False
    return drive.upper() not in {"C:", "D:"}


def clean_setupapi_value(value: str | None) -> str | None:
    normalized = normalize_windows_path(value)
    if not normalized:
        return None
    cleaned = normalized.strip().strip('"').strip("'").strip()
    if re.fullmatch(r"\{[0-9a-fA-F\-]+\}", cleaned):
        return cleaned
    while cleaned and cleaned[-1] in {"}", "]", '"', "'", " "}:
        candidate = cleaned[:-1].rstrip()
        if not candidate:
            break
        cleaned = candidate
    return cleaned or None


def split_usb_values(value: str | list[str] | None) -> list[str]:
    if value in (None, ""):
        return []
    if isinstance(value, list):
        return [str(item).strip() for item in value if str(item).strip()]
    parts = re.split(r"[;\n\r,|]+", str(value))
    return [part.strip() for part in parts if part.strip()]


def is_missing_or_generic_usb_serial(value: str | None) -> bool:
    serial = clean_setupapi_value(value)
    if not serial:
        return True
    upper = serial.upper()
    if upper in {"UNKNOWN", "GENERIC", "0000000000000000", "00000000", "NONE", "N/A"}:
        return True
    if re.fullmatch(r"0+", upper):
        return True
    return False


def canonicalize_usb_device_type(value: str | None, class_name: str | None = None, friendly_name: str | None = None) -> str:
    lowered = str(value or "").strip().lower()
    class_lower = str(class_name or "").strip().lower()
    friendly_lower = str(friendly_name or "").strip().lower()
    if lowered in {"removable_storage", "storage_volume", "storage_device", "usbstor", "mass_storage", "disk"}:
        return "mass_storage"
    if lowered in {"portable_device", "wpd", "mtp"}:
        if any(token in friendly_lower for token in {"iphone", "android", "phone", "pixel", "samsung", "mobile"}):
            return "phone"
        return "mtp"
    if lowered in {"usb_device", "usb_generic"} and "hid" in class_lower:
        return "hid"
    if "hid" in lowered or "hid" in class_lower:
        return "hid"
    if "printer" in lowered or "printer" in class_lower:
        return "printer"
    if lowered in {"driver_update", "usb_class_generic"}:
        return lowered
    return "unknown"


def is_useful_usb_device_instance_id(value: str | None) -> bool:
    normalized = clean_setupapi_value(value)
    if not normalized:
        return False
    upper = normalized.upper()
    if GENERIC_USB_CLASS_RE.match(upper):
        return False
    if GENERIC_USB_ROOT_RE.match(upper):
        return False
    if upper in {"USB\\VID_0000&PID_0000", "USB\\UNKNOWN"}:
        return False
    if upper.startswith("USBSTOR\\"):
        return "\\DISK&VEN_" in "\\" + upper or "&VEN_" in upper and "&PROD_" in upper and len(upper.split("\\")[-1]) > 3
    if upper.startswith("USB\\VID_") and "&PID_" in upper:
        tail = upper.split("\\", 2)
        return len(tail) >= 3 and len(tail[-1].strip()) > 3 and tail[-1].strip() not in {"0", "UNKNOWN"}
    if upper.startswith("SWD\\WPDBUSENUM\\") or upper.startswith("WPD\\"):
        return True
    if upper.startswith("STORAGE\\VOLUME\\"):
        return True
    if upper.startswith("SCSI\\DISK&VEN_"):
        return True
    return False


def looks_like_inf_path(value: str | None) -> bool:
    cleaned = clean_setupapi_value(value)
    if not cleaned:
        return False
    lower = cleaned.lower()
    if "using wdf schema version" in lower:
        return False
    return (
        lower.endswith(".inf")
        or "\\driverstore\\filerepository\\" in lower
        or re.search(r"\boem\d+\.inf\b", lower) is not None
        or re.search(r"\b(?:usbstor|disk|wpdmtp)\.inf\b", lower) is not None
    )


__all__ = [
    "basename_windows",
    "canonicalize_header",
    "canonicalize_usb_device_type",
    "clean_setupapi_value",
    "extract_drive_letter",
    "infer_usb_user_from_path",
    "is_missing_or_generic_usb_serial",
    "is_useful_usb_device_instance_id",
    "looks_like_inf_path",
    "is_probable_usb_path",
    "looks_like_setupapi_log",
    "looks_like_usb_artifact",
    "normalize_windows_path",
    "parse_usb_device_instance_id",
    "read_usb_csv_rows",
    "split_usb_values",
    "suffix_windows",
]
