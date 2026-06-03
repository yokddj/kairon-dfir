from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path
import re

from app.ingest.usb.helpers import (
    clean_setupapi_value,
    is_useful_usb_device_instance_id,
    looks_like_inf_path,
    normalize_windows_path,
    parse_usb_device_instance_id,
)


START_RE = re.compile(r"^>>>\s+\[(?P<section>.+?)\]\s*$")
SECTION_START_RE = re.compile(r"^>>>\s+Section start\s+(?P<ts>\d{4}/\d{2}/\d{2} \d{2}:\d{2}:\d{2}\.\d+)", re.IGNORECASE)
SECTION_END_RE = re.compile(r"^<<<\s+Section end\s+(?P<ts>\d{4}/\d{2}/\d{2} \d{2}:\d{2}:\d{2}\.\d+)", re.IGNORECASE)
KV_RE = re.compile(r"^(?P<prefix>[a-z]{2,4}):\s*(?P<body>.+)$", re.IGNORECASE)

DEVICE_INSTANCE_RE = re.compile(r"(?:device instance id|device id)\s*[-:=]\s*(?P<value>[^\r\n]+)", re.IGNORECASE)
PARENT_INSTANCE_RE = re.compile(r"parent (?:device )?instance id\s*[-:=]\s*(?P<value>[^\r\n]+)", re.IGNORECASE)
HARDWARE_ID_RE = re.compile(r"hardware id\s*[-:=]\s*(?P<value>[^\r\n]+)", re.IGNORECASE)
COMPATIBLE_ID_RE = re.compile(r"compatible ids?\s*[-:=]\s*(?P<value>[^\r\n]+)", re.IGNORECASE)
CLASS_GUID_RE = re.compile(r"class guid\s*[-:=]\s*(?P<value>[^\r\n]+)", re.IGNORECASE)
CLASS_NAME_RE = re.compile(r"class(?: name)?\s*[-:=]\s*(?P<value>[^\r\n]+)", re.IGNORECASE)
SERVICE_RE = re.compile(r"service\s*[-:=]\s*(?P<value>[^\r\n]+)", re.IGNORECASE)
FRIENDLY_RE = re.compile(r"(?:friendly name|device description|device desc)\s*[-:=]\s*(?P<value>[^\r\n]+)", re.IGNORECASE)
CONTAINER_ID_RE = re.compile(r"container id\s*[-:=]\s*(?P<value>[^\r\n]+)", re.IGNORECASE)
PARENT_PREFIX_RE = re.compile(r"parent id prefix\s*[-:=]\s*(?P<value>[^\r\n]+)", re.IGNORECASE)
PROVIDER_RE = re.compile(r"(?:driver )?provider\s*[-:=]\s*(?P<value>[^\r\n]+)", re.IGNORECASE)
DRIVER_DATE_RE = re.compile(r"driver date\s*[-:=]\s*(?P<value>[^\r\n]+)", re.IGNORECASE)
DRIVER_VERSION_RE = re.compile(r"driver version\s*[-:=]\s*(?P<value>[^\r\n]+)", re.IGNORECASE)
RESULT_RE = re.compile(r"(?:result|exit status)\s*[-:=]\s*(?P<value>[^\r\n]+)", re.IGNORECASE)
INF_VALUE_RE = re.compile(r"(?P<value>(?:[A-Z]:\\[^\r\n]*?\.inf|oem\d+\.inf|(?:usbstor|disk|wpdmtp)\.inf))", re.IGNORECASE)


def _read_text(path: Path) -> str:
    for encoding in ("utf-8-sig", "utf-16le", "utf-16", "latin-1"):
        try:
            return path.read_text(encoding=encoding, errors="ignore")
        except Exception:  # noqa: BLE001
            continue
    return path.read_text(encoding="utf-8", errors="ignore")


def _parse_ts(value: str | None) -> str | None:
    if not value:
        return None
    try:
        return datetime.strptime(value.strip(), "%Y/%m/%d %H:%M:%S.%f").replace(tzinfo=UTC).isoformat()
    except Exception:  # noqa: BLE001
        return None


def _extract(pattern: re.Pattern[str], text: str) -> str | None:
    match = pattern.search(text)
    if not match:
        return None
    return clean_setupapi_value(match.group("value"))


def _looks_like_device_install(section_name: str) -> bool:
    lower = section_name.lower()
    return lower.startswith("device install")


def _looks_like_driver_update(section_name: str) -> bool:
    return section_name.strip().lower() == "install driver updates"


def _classify_device_type(instance_id: str | None, section_name: str) -> str:
    parsed = parse_usb_device_instance_id(instance_id)
    parsed_type = str(parsed.get("device_type") or "")
    normalized = str(clean_setupapi_value(instance_id) or "").upper()
    if _looks_like_driver_update(section_name):
        return "driver_update"
    if parsed_type == "usb_class_generic":
        return "usb_class_generic"
    if normalized.startswith("USBSTOR\\"):
        return "removable_storage"
    if normalized.startswith("USB\\VID_"):
        return "usb_device"
    if normalized.startswith("SWD\\WPDBUSENUM\\") or normalized.startswith("WPD\\"):
        return "portable_device"
    if normalized.startswith("STORAGE\\VOLUME\\"):
        return "storage_volume"
    if normalized.startswith("SCSI\\DISK&VEN_"):
        return "removable_storage"
    if normalized.startswith("USB\\CLASS_") or normalized.startswith("USB\\ROOT_HUB"):
        return "usb_class_generic"
    return "usb_generic"


def _extract_inf_path(lines: list[str], warnings: list[str], audit: dict) -> str | None:
    for line in lines:
        if "using wdf schema version" in line.lower():
            warnings.append("setupapi_inf_message_rejected")
            audit["inf_path_rejected_count"] += 1
        match = INF_VALUE_RE.search(line)
        if match:
            candidate = clean_setupapi_value(match.group("value"))
            if looks_like_inf_path(candidate):
                return candidate
        if "driver package" in line.lower():
            candidate = clean_setupapi_value(line.split("=", 1)[-1] if "=" in line else line.split(":", 1)[-1])
            if looks_like_inf_path(candidate):
                return candidate
            if candidate and "using wdf schema version" in candidate.lower():
                warnings.append("setupapi_inf_message_rejected")
                audit["inf_path_rejected_count"] += 1
    return None


def _extract_specific_fields(lines: list[str], block: str, audit: dict) -> tuple[dict, list[str]]:
    warnings: list[str] = []
    section_start = None
    section_end = None
    for line in lines:
        if section_start is None:
            start_match = SECTION_START_RE.search(line)
            if start_match:
                section_start = _parse_ts(start_match.group("ts"))
        end_match = SECTION_END_RE.search(line)
        if end_match:
            section_end = _parse_ts(end_match.group("ts"))

    result_code = _extract(RESULT_RE, block)
    if result_code and result_code != clean_setupapi_value(result_code):
        audit["contaminated_fields_cleaned_count"] += 1

    service = _extract(SERVICE_RE, block)
    driver_provider = _extract(PROVIDER_RE, block)
    driver_date = _extract(DRIVER_DATE_RE, block)
    driver_version = _extract(DRIVER_VERSION_RE, block)
    inf_path = _extract_inf_path(lines, warnings, audit)

    values = {
        "SectionStartTime": section_start,
        "SectionEndTime": section_end,
        "DeviceInstanceId": _extract(DEVICE_INSTANCE_RE, block),
        "ParentDeviceInstanceId": _extract(PARENT_INSTANCE_RE, block),
        "HardwareId": _extract(HARDWARE_ID_RE, block),
        "CompatibleIds": _extract(COMPATIBLE_ID_RE, block),
        "ClassGuid": _extract(CLASS_GUID_RE, block),
        "ClassName": _extract(CLASS_NAME_RE, block),
        "Service": service,
        "FriendlyName": _extract(FRIENDLY_RE, block),
        "ContainerId": _extract(CONTAINER_ID_RE, block),
        "ParentIdPrefix": _extract(PARENT_PREFIX_RE, block),
        "DriverProvider": driver_provider,
        "DriverDate": driver_date,
        "DriverVersion": driver_version,
        "ResultCode": result_code,
        "InfPath": inf_path,
    }
    return values, warnings


def parse_setupapi_dev_log(path: Path, *, source_path: str) -> tuple[list[dict], list[str], dict]:
    text = _read_text(path)
    lines = text.splitlines()
    rows: list[dict] = []
    warnings: list[str] = []
    audit = {
        "setupapi_blocks_read": 0,
        "setupapi_device_install_blocks": 0,
        "setupapi_driver_update_blocks": 0,
        "setupapi_usb_blocks": 0,
        "usb_storage_blocks": 0,
        "usb_vidpid_blocks": 0,
        "usb_class_generic_blocks": 0,
        "low_value_blocks_skipped": 0,
        "low_value_blocks_indexed": 0,
        "useful_usb_devices_indexed": 0,
        "timestamp_from_section_start_count": 0,
        "timestamp_from_section_end_count": 0,
        "source_file_mtime_used_count": 0,
        "contaminated_fields_cleaned_count": 0,
        "inf_path_rejected_count": 0,
        "vendor_product_parsed_count": 0,
        "serial_parsed_count": 0,
    }
    current: list[str] = []
    start_line = 1

    def flush(block_lines: list[str], line_start: int, line_end: int) -> None:
        if not block_lines:
            return
        block = "\n".join(block_lines)
        header_match = START_RE.search(block_lines[0])
        if not header_match:
            return
        audit["setupapi_blocks_read"] += 1
        section_name = clean_setupapi_value(header_match.group("section")) or "unknown"
        section_kind = "driver_update" if _looks_like_driver_update(section_name) else "device_install" if _looks_like_device_install(section_name) else "generic"

        values, row_warnings = _extract_specific_fields(block_lines, block, audit)
        warnings.extend(row_warnings)
        instance_id = values["DeviceInstanceId"] or values["HardwareId"] or values["CompatibleIds"]
        parsed_instance = parse_usb_device_instance_id(instance_id)
        useful_instance = is_useful_usb_device_instance_id(instance_id)
        device_type = _classify_device_type(instance_id, section_name)

        if values["SectionStartTime"]:
            audit["timestamp_from_section_start_count"] += 1
        elif values["SectionEndTime"]:
            audit["timestamp_from_section_end_count"] += 1

        if parsed_instance.get("vendor") or parsed_instance.get("product"):
            audit["vendor_product_parsed_count"] += 1
        if parsed_instance.get("serial"):
            audit["serial_parsed_count"] += 1

        friendly_name = values["FriendlyName"]
        if not parsed_instance.get("vendor") and friendly_name:
            tokens = str(friendly_name).split()
            if tokens:
                parsed_instance["vendor"] = tokens[0]
                if len(tokens) > 1:
                    parsed_instance["product"] = " ".join(tokens[1:])
                audit["vendor_product_parsed_count"] += 1

        artifact_type = "setupapi_device_install"
        event_type = "usb_device_install"
        should_index = True
        if section_kind == "driver_update":
            artifact_type = "setupapi_driver_update"
            event_type = "setupapi_driver_update"
            audit["setupapi_driver_update_blocks"] += 1
        elif device_type == "usb_class_generic":
            artifact_type = "setupapi_usb_class_generic"
            event_type = "usb_class_generic"
            audit["usb_class_generic_blocks"] += 1
            audit["low_value_blocks_indexed"] += 1
        elif useful_instance:
            audit["setupapi_device_install_blocks"] += 1
        else:
            audit["low_value_blocks_skipped"] += 1
            should_index = False

        if not useful_instance and device_type not in {"driver_update", "usb_class_generic"} and section_kind != "driver_update":
            should_index = False

        if not should_index:
            return

        if device_type in {"removable_storage", "storage_volume"}:
            audit["usb_storage_blocks"] += 1
        if str(parsed_instance.get("vid") or "") and str(parsed_instance.get("pid") or ""):
            audit["usb_vidpid_blocks"] += 1
        if useful_instance:
            audit["setupapi_usb_blocks"] += 1
            audit["useful_usb_devices_indexed"] += 1

        install_status = "observed"
        lower_block = block.lower()
        if "success" in lower_block or "device installed" in lower_block or "device configured" in lower_block:
            install_status = "success"

        row = {
            "SourceFile": source_path,
            "Timestamp": values["SectionStartTime"] or values["SectionEndTime"],
            "SectionStartTime": values["SectionStartTime"],
            "SectionEndTime": values["SectionEndTime"],
            "SectionName": section_name,
            "DeviceInstanceId": values["DeviceInstanceId"] or parsed_instance.get("raw_instance_id"),
            "ParentDeviceInstanceId": values["ParentDeviceInstanceId"],
            "HardwareId": values["HardwareId"] or parsed_instance.get("raw_instance_id"),
            "CompatibleIds": values["CompatibleIds"],
            "ClassGuid": values["ClassGuid"],
            "ClassName": values["ClassName"],
            "Service": values["Service"],
            "InfPath": values["InfPath"],
            "DriverProvider": values["DriverProvider"],
            "DriverDate": values["DriverDate"],
            "DriverVersion": values["DriverVersion"],
            "ResultCode": values["ResultCode"],
            "InstallStatus": install_status,
            "FriendlyName": values["FriendlyName"],
            "ContainerId": values["ContainerId"],
            "ParentIdPrefix": values["ParentIdPrefix"],
            "LineStart": line_start,
            "LineEnd": line_end,
            "ArtifactType": artifact_type,
            "EventType": event_type,
            "DeviceType": device_type,
            "RawBlock": block[:16000],
            "Vendor": parsed_instance.get("vendor"),
            "Product": parsed_instance.get("product"),
            "Revision": parsed_instance.get("revision"),
            "Serial": parsed_instance.get("serial"),
            "VID": parsed_instance.get("vid"),
            "PID": parsed_instance.get("pid"),
            "ParseWarnings": row_warnings,
            **parsed_instance,
        }
        rows.append(row)

    for index, line in enumerate(lines, start=1):
        if START_RE.match(line):
            flush(current, start_line, index - 1)
            current = [line]
            start_line = index
            continue
        if current:
            current.append(line)
    flush(current, start_line, len(lines))
    return rows, warnings, audit
