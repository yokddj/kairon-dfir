from __future__ import annotations

from pathlib import Path
import re

from app.ingest.artifact_normalizers import first_value
from app.ingest.identity_extraction import extract_user_from_path, is_valid_username
from app.ingest.usb.helpers import (
    canonicalize_usb_device_type,
    clean_setupapi_value,
    extract_drive_letter,
    infer_usb_user_from_path,
    is_missing_or_generic_usb_serial,
    normalize_windows_path,
    parse_usb_device_instance_id,
    split_usb_values,
)
from app.ingest.windows_event_mapping import risk_score_to_severity


INTERACTIVE_USERS = {"system", "local service", "network service", "administrator"}
UNUSUAL_VID_PID = {"0000:0000", "ffff:ffff"}


def _first_timestamp(row: dict, *names: str) -> str | None:
    return first_value(row, list(names))


def _canonical_parser(parser: str, row: dict, source_path: str | None) -> str:
    lowered = str(parser or "").lower()
    source_lower = str(source_path or "").lower()
    provider = str(first_value(row, ["Provider", "ProviderName", "SourceName"]) or "").lower()
    channel = str(first_value(row, ["Channel"]) or "").lower()
    event_id = first_value(row, ["EventID", "EventId"])

    if lowered in {"usb_setupapi", "setupapi"} or source_lower.endswith("setupapi.dev.log") or source_lower.endswith("setupapi.setup.log"):
        return "usb_setupapi"
    if lowered in {"usb_mounteddevices", "usb_mountpoints2"}:
        return lowered
    if lowered in {"usb_registry", "registry_usb"}:
        return "usb_registry"
    if lowered in {"usb_json", "usb_jsonl", "usb_csv", "usb_raw", "usb_evtx"}:
        return lowered
    if event_id not in (None, "") and any(token in f"{provider} {channel}" for token in ["userpnp", "kernel-pnp", "driverframeworks"]):
        return "usb_evtx"
    if source_lower.endswith(".jsonl"):
        return "usb_jsonl"
    if source_lower.endswith(".json"):
        return "usb_json"
    if source_lower.endswith(".csv"):
        return "usb_csv"
    if source_lower.endswith(".txt"):
        return "usb_raw"
    return "usb_registry"


def _pick_event_type(row: dict, parser: str, usb: dict, volume: dict) -> tuple[str, str, str, str]:
    artifact_type = str(usb.get("artifact_type") or "").lower()
    event_type_hint = str(first_value(row, ["EventType"]) or "").lower()
    provider = str(first_value(row, ["Provider", "ProviderName", "SourceName"]) or "").lower()
    event_id = str(first_value(row, ["EventID", "EventId"]) or "")

    descriptor = usb.get("vendor") or usb.get("product") or usb.get("serial") or usb.get("friendly_name") or usb.get("device_instance_id") or "unknown device"
    if event_type_hint == "setupapi_driver_update" or str(usb.get("device_type") or "") == "driver_update":
        return "setupapi_driver_update", "driver_update_observed", "device", "SetupAPI driver update block observed"
    if event_type_hint == "usb_class_generic" or str(usb.get("device_type") or "") == "usb_class_generic":
        return "usb_class_generic", "usb_class_generic_observed", "device", f"Generic USB class driver observed: {descriptor}"
    if first_value(row, ["LastRemovalTime", "LastRemovalDate"]):
        return "usb_disconnected", "usb_device_disconnected", "device", f"USB device disconnected: {descriptor}"
    if parser == "usb_setupapi" or event_type_hint in {"usb_device_install", "setupapi_device_install"}:
        return "usb_installed", "usb_device_installed", "device", f"USB device installed: {descriptor}"
    if parser == "usb_evtx":
        if event_id in {"410", "411", "420", "430", "20003", "20006"}:
            return "usb_connected", "usb_device_connected", "device", f"USB device connected: {descriptor}"
        if event_id in {"400", "43001"}:
            return "usb_disconnected", "usb_device_disconnected", "device", f"USB device disconnected: {descriptor}"
        if event_id in {"20001"} or "userpnp" in provider:
            return "usb_installed", "usb_device_installed", "device", f"USB device installed: {descriptor}"
        return "usb_observed", "usb_device_observed", "device", f"USB device observed: {descriptor}"
    if first_value(row, ["LastArrivalTime", "LastArrivalDate", "LastConnectedTime"]):
        return "usb_connected", "usb_device_connected", "device", f"USB device connected: {descriptor}"
    if volume.get("drive_letter") or volume.get("guid"):
        return "usb_observed", "usb_device_observed", "device", f"USB device observed: {descriptor}"
    if artifact_type == "usb_mount":
        return "usb_observed", "usb_device_observed", "device", f"USB device observed: {descriptor}"
    return "usb_observed", "usb_device_observed", "device", f"USB device observed: {descriptor}"


def _pick_timestamp(document: dict, row: dict, parser: str, registry: dict) -> None:
    candidates = [
        ("usb_last_arrival_time", _first_timestamp(row, "LastArrivalTime", "LastArrivalDate")),
        ("usb_last_connected_time", _first_timestamp(row, "LastConnectedTime")),
        ("usb_last_removal_time", _first_timestamp(row, "LastRemovalTime", "LastRemovalDate")),
        ("usb_install_time", _first_timestamp(row, "InstallTime", "InstallDate", "FirstInstallTime", "FirstInstallDate")),
        ("setupapi_section_time", _first_timestamp(row, "SectionStartTime", "SectionEndTime")),
        ("registry_last_write", registry.get("last_write")),
    ]
    for precision, value in candidates:
        if value:
            document["@timestamp"] = value
            document["timestamp_precision"] = precision
            document["timezone"] = "UTC"
            return
    if document.get("@timestamp"):
        document["timestamp_precision"] = "event_time" if parser == "usb_evtx" else document.get("timestamp_precision") or "source_file_mtime"
    else:
        document["timestamp_precision"] = "unknown"


def _derive_risk_and_reasons(document: dict) -> tuple[int, list[str], list[str]]:
    usb = document.get("usb", {}) or {}
    volume = document.get("volume", {}) or {}
    user = document.get("user", {}) or {}
    event = document.get("event", {}) or {}
    reasons: list[str] = []
    data_quality: list[str] = list(document.get("data_quality") or [])
    risk = 0

    device_type = str(usb.get("device_type") or "").lower()
    serial = str(usb.get("serial") or "")
    class_name = str(usb.get("class_name") or "").lower()
    vid = str(usb.get("vid") or "").strip()
    pid = str(usb.get("pid") or "").strip()
    install_status = str(usb.get("install_status") or usb.get("result_code") or "").lower()

    if device_type == "mass_storage":
        reasons.append("USB mass storage device observed")
        risk = max(risk, 30)
    elif device_type in {"mtp", "phone"}:
        reasons.append("USB portable device observed")
        risk = max(risk, 25 if device_type == "mtp" else 35)
    elif device_type == "hid" or "hid" in class_name:
        risk = max(risk, 5)

    if event.get("type") == "usb_connected":
        reasons.append("USB device connected recently")
        risk = max(risk, 20 if device_type == "mass_storage" else risk)
    if event.get("type") == "usb_disconnected":
        reasons.append("USB device removed recently")
        risk = max(risk, 15 if device_type == "mass_storage" else risk)
    if event.get("type") in {"setupapi_driver_update", "usb_class_generic"}:
        risk = 0

    if volume.get("drive_letter"):
        reasons.append("USB drive letter assigned")
        risk = max(risk, risk + 10 if device_type == "mass_storage" else 20)

    if is_missing_or_generic_usb_serial(serial):
        reasons.append("USB serial missing or generic")
        data_quality.append("missing_serial")
        risk = max(risk, risk + 10 if device_type in {"mass_storage", "mtp", "phone"} else 15)

    if install_status and install_status not in {"0x0", "success", "observed"}:
        reasons.append("USB install failed")
        risk = max(risk, 30)

    if user.get("name") and str(user.get("name")).lower() not in INTERACTIVE_USERS:
        reasons.append("USB device connected under user context")
        risk = max(risk, risk + 10 if device_type == "mass_storage" else 15)

    vid_pid = f"{vid.lower()}:{pid.lower()}" if vid and pid else ""
    if vid_pid in UNUSUAL_VID_PID:
        reasons.append("USB device has unusual VID/PID")
        risk = max(risk, 20)

    if not usb.get("device_instance_id"):
        data_quality.append("missing_device_instance_id")
    if not (vid and pid):
        data_quality.append("missing_vid_pid")
    if not document.get("@timestamp"):
        data_quality.append("missing_timestamp")
    if not document.get("host", {}).get("name"):
        data_quality.append("missing_host")
    if not user.get("name") and not user.get("sid"):
        data_quality.append("missing_user")

    return min(risk, 100), sorted(dict.fromkeys(reasons)), sorted(dict.fromkeys(data_quality))


def normalize_usb_row(document: dict, row: dict, artifact_meta: dict) -> dict:
    first = lambda *names: first_value(row, list(names))
    usb = document.setdefault("usb", {})
    volume = document.setdefault("volume", {})
    registry = document.setdefault("registry", {})
    host = document.setdefault("host", {})
    user = document.setdefault("user", {})
    windows = document.setdefault("windows", {})
    velociraptor = document.setdefault("velociraptor", {})

    source_file = normalize_windows_path(first("SourceFile")) or artifact_meta.get("source_path")
    parser = _canonical_parser(str(artifact_meta.get("parser") or ""), row, source_file)

    instance_id = normalize_windows_path(first("DeviceInstanceId", "DeviceInstanceID", "InstanceId", "RawInstanceId", "USBSTOR", "HardwareId"))
    parsed_instance = parse_usb_device_instance_id(instance_id)
    vendor = first("Vendor", "Ven") or parsed_instance.get("vendor")
    product = first("Product", "Prod") or parsed_instance.get("product")
    revision = first("Revision", "Rev") or parsed_instance.get("revision")
    serial = first("Serial") or parsed_instance.get("serial")
    friendly_name = first("FriendlyName", "DeviceDesc", "DeviceDescription")
    class_name = first("ClassName")
    device_type = canonicalize_usb_device_type(first("DeviceType") or parsed_instance.get("device_type"), class_name, friendly_name)

    drive_letter = extract_drive_letter(first("DriveLetter", "MountedDevice", "DosDevice", "DosDevices", "ValueName", "Path")) or artifact_meta.get("drive_letter")
    volume_guid = normalize_windows_path(first("VolumeGuid", "MountedDevice", "ValueData"))
    if volume_guid and "volume{" not in volume_guid.lower():
        volume_guid = None

    original_artifact_type = str(first("ArtifactType") or artifact_meta.get("usb_artifact_type") or "").lower()

    if parser == "usb_setupapi":
        artifact_parser = "usb_setupapi"
        usb_artifact_type = original_artifact_type or "usb_setupapi"
        source_tool = "setupapi_dev_log"
        source_format = "log"
    elif parser == "usb_evtx":
        artifact_parser = "usb_evtx"
        usb_artifact_type = "usb_evtx"
        source_tool = "native_evtx"
        source_format = "evtx"
    elif parser == "usb_mounteddevices":
        artifact_parser = "usb_mounteddevices"
        usb_artifact_type = "usb_mount"
        source_tool = artifact_meta.get("source_tool") or "registry_export"
        source_format = artifact_meta.get("source_format") or "csv"
    elif parser == "usb_mountpoints2":
        artifact_parser = "usb_mountpoints2"
        usb_artifact_type = "usb_mount"
        source_tool = artifact_meta.get("source_tool") or "registry_export"
        source_format = artifact_meta.get("source_format") or "csv"
    elif parser == "usb_registry":
        artifact_parser = "usb_registry"
        usb_artifact_type = "usb_registry"
        source_tool = artifact_meta.get("source_tool") or "usb_registry_csv"
        source_format = artifact_meta.get("source_format") or "csv"
    elif parser == "usb_json":
        artifact_parser = "usb_json"
        usb_artifact_type = "usb_registry"
        source_tool = artifact_meta.get("source_tool") or "usb_export"
        source_format = "json"
    elif parser == "usb_jsonl":
        artifact_parser = "usb_jsonl"
        usb_artifact_type = "usb_registry"
        source_tool = artifact_meta.get("source_tool") or "usb_export"
        source_format = "jsonl"
    elif parser == "usb_raw":
        artifact_parser = "usb_raw"
        usb_artifact_type = "usb_raw"
        source_tool = artifact_meta.get("source_tool") or "usb_export"
        source_format = artifact_meta.get("source_format") or "txt"
    else:
        artifact_parser = "usb_csv"
        usb_artifact_type = "usb_registry"
        source_tool = artifact_meta.get("source_tool") or "usb_registry_csv"
        source_format = artifact_meta.get("source_format") or "csv"

    usb.update(
        {
            "artifact_type": usb_artifact_type,
            "device_instance_id": instance_id,
            "parent_device_instance_id": normalize_windows_path(first("ParentDeviceInstanceId")),
            "hardware_id": normalize_windows_path(first("HardwareId")),
            "compatible_ids": split_usb_values(first("CompatibleIds")),
            "vendor": vendor,
            "product": product,
            "revision": revision,
            "serial": serial,
            "vid": first("VID") or parsed_instance.get("vid"),
            "pid": first("PID") or parsed_instance.get("pid"),
            "device_id": first("DeviceId"),
            "friendly_name": friendly_name,
            "container_id": first("ContainerId"),
            "parent_id_prefix": first("ParentIdPrefix"),
            "class_guid": clean_setupapi_value(first("ClassGuid")),
            "class_name": class_name,
            "service": clean_setupapi_value(first("Service")),
            "driver": clean_setupapi_value(first("Driver")),
            "driver_provider": clean_setupapi_value(first("DriverProvider")),
            "driver_date": first("DriverDate"),
            "driver_version": first("DriverVersion"),
            "inf_path": normalize_windows_path(first("InfPath", "DriverPackage")),
            "install_status": first("InstallStatus", "Status"),
            "result_code": clean_setupapi_value(first("ResultCode")),
            "first_install_time": first("FirstInstallTime", "FirstInstallDate"),
            "install_time": first("InstallTime", "InstallDate"),
            "last_arrival_time": first("LastArrivalTime", "LastArrivalDate"),
            "last_connected_time": first("LastConnectedTime"),
            "last_removal_time": first("LastRemovalTime", "LastRemovalDate"),
            "section_start_time": first("SectionStartTime"),
            "section_end_time": first("SectionEndTime"),
            "source_file": source_file,
            "line_start": first("LineStart"),
            "line_end": first("LineEnd"),
            "raw_instance_id": parsed_instance.get("raw_instance_id"),
            "device_type": device_type,
            "parse_warnings": split_usb_values(first("ParseWarnings")),
        }
    )
    volume.update(
        {
            "guid": volume_guid,
            "drive_letter": drive_letter,
            "serial": first("VolumeSerial", "VolumeSerialNumber"),
            "label": first("VolumeLabel"),
            "drive_type": first("DriveType") or ("removable" if drive_letter and drive_letter.upper() not in {"C:", "D:"} else "unknown" if drive_letter else None),
            "created": first("Created"),
            "mounted_device": normalize_windows_path(first("MountedDevice")),
            "dos_device": normalize_windows_path(first("DosDevice", "DosDevices", "ValueName")),
        }
    )
    registry.update(
        {
            "hive": first("Hive"),
            "key_path": normalize_windows_path(first("KeyPath")),
            "value_name": first("ValueName"),
            "value_data": first("ValueData"),
            "last_write": first("LastWriteTime"),
        }
    )
    if parser == "usb_evtx":
        windows.update(
            {
                "event_id": first("EventID", "EventId"),
                "channel": first("Channel"),
                "provider": first("Provider", "ProviderName", "SourceName"),
                "computer": first("Computer"),
                "record_id": first("RecordId", "EventRecordID"),
                "event_data": first("EventData"),
                "raw_xml": first("RawXml"),
            }
        )
        if windows.get("computer"):
            host["name"] = str(windows.get("computer")).lower()
            host["hostname"] = host["name"]

    if first("UserSid") and not user.get("sid"):
        user["sid"] = first("UserSid")
    explicit_user = first("User", "Owner")
    if explicit_user and is_valid_username(str(explicit_user)):
        user["name"] = str(explicit_user).strip()
    if not user.get("name"):
        user["name"] = infer_usb_user_from_path(source_file) or extract_user_from_path(source_file)

    document["artifact"]["type"] = "usb"
    document["artifact"]["parser"] = artifact_parser
    document["artifact"]["name"] = f"USB Device - {vendor or product or serial or friendly_name or 'unknown'}"
    document["source_tool"] = source_tool
    document["source_format"] = source_format
    if source_file:
        document["source_file"] = source_file

    event_type, event_action, event_category, event_message = _pick_event_type(row, artifact_parser, usb, volume)
    document["event"].update(
        {
            "category": event_category,
            "type": event_type,
            "action": event_action,
            "message": event_message,
        }
    )

    _pick_timestamp(document, row, artifact_parser, registry)

    risk_score, suspicious_reasons, data_quality = _derive_risk_and_reasons(document)
    document["risk_score"] = risk_score
    document["event"]["severity"] = "info" if document["event"]["type"] in {"setupapi_driver_update", "usb_class_generic"} else risk_score_to_severity(risk_score)
    document["suspicious_reasons"] = suspicious_reasons
    document["data_quality"] = data_quality
    document["execution"].update(
        {
            "source": "usb",
            "is_execution_confirmed": False,
            "confidence": "low",
            "interpretation": "USB artifacts indicate device presence/connection/installation, not program execution by itself",
        }
    )

    if artifact_parser == "usb_evtx":
        document["timestamp_precision"] = "event_time" if document.get("@timestamp") else document.get("timestamp_precision")

    if volume.get("drive_letter"):
        volume["dos_device"] = volume.get("dos_device") or volume.get("drive_letter")

    basename = Path(str(source_file or "")).name.lower() if source_file else ""
    explicit_host_value = str(first("Computer", "Host", "Hostname") or "").lower()
    if str(host.get("name") or "").lower() in {basename, "system", "software", "ntuser.dat", "setupapi.dev.log", "setupapi.setup.log"} or explicit_host_value in {basename, "setupapi.dev.log", "setupapi.setup.log"}:
        host["name"] = None
        host["hostname"] = None
        document["data_quality"] = sorted(dict.fromkeys((document.get("data_quality") or []) + ["host_name_not_inferred_from_filename", "missing_host"]))

    velociraptor.update(
        {
            "original_path": artifact_meta.get("velociraptor_original_path") or source_file,
            "normalized_windows_path": artifact_meta.get("velociraptor_normalized_windows_path") or source_file,
            "artifact_category": artifact_meta.get("velociraptor_category") or "usb",
            "parser_status": artifact_meta.get("velociraptor_parser_status") or ("parsed" if str(artifact_meta.get("source_tool") or "").startswith("velociraptor") else None),
            "collection_id": artifact_meta.get("velociraptor_collection_id"),
        }
    )

    tags = set(document.get("tags") or [])
    if document["event"]["type"] == "usb_class_generic":
        tags.add("usb_class_generic")
    else:
        tags.add("usb")
    if artifact_parser == "usb_setupapi":
        tags.add("setupapi")
    if artifact_parser == "usb_evtx":
        tags.add("evtx")
    if document["event"]["type"] == "setupapi_driver_update":
        tags.add("driver_update")
    if device_type == "mass_storage":
        tags.update({"usb_storage", "removable_device"})
    elif device_type in {"mtp", "phone"}:
        tags.add("portable_device")
    elif device_type == "hid":
        tags.add("hid")
    if volume.get("drive_letter") or volume.get("guid"):
        tags.add("volume_mapping")
    if volume.get("drive_type") and "removable" in str(volume.get("drive_type") or "").lower():
        tags.add("removable_media")
    document["tags"] = sorted(tags)
    return document
