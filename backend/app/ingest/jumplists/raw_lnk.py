from __future__ import annotations

from datetime import UTC, datetime
import struct
from uuid import UUID


SHELL_LINK_CLSID = bytes.fromhex("0114020000000000C000000000000046")
LINK_FLAG_HAS_LINK_TARGET_ID_LIST = 0x00000001
LINK_FLAG_HAS_LINK_INFO = 0x00000002
LINK_FLAG_HAS_NAME = 0x00000004
LINK_FLAG_HAS_RELATIVE_PATH = 0x00000008
LINK_FLAG_HAS_WORKING_DIR = 0x00000010
LINK_FLAG_HAS_ARGUMENTS = 0x00000020
LINK_FLAG_HAS_ICON_LOCATION = 0x00000040
LINK_FLAG_IS_UNICODE = 0x00000080

FILE_ATTRIBUTE_DIRECTORY = 0x00000010

LINK_INFO_FLAG_VOLUME_ID_AND_LOCAL_BASE_PATH = 0x00000001
LINK_INFO_FLAG_COMMON_NETWORK_RELATIVE_LINK_AND_PATH_SUFFIX = 0x00000002
EXTRA_DATA_TRACKER = 0xA0000003
EXTRA_DATA_ENVIRONMENT = 0xA0000001
EXTRA_DATA_KNOWN_FOLDER = 0xA000000B
EXTRA_DATA_DARWIN = 0xA0000006
EXTRA_DATA_PROPERTY_STORE = 0xA0000009


def _u16(data: bytes, offset: int) -> int:
    return struct.unpack_from("<H", data, offset)[0]


def _u32(data: bytes, offset: int) -> int:
    return struct.unpack_from("<I", data, offset)[0]


def _u64(data: bytes, offset: int) -> int:
    return struct.unpack_from("<Q", data, offset)[0]


def _parse_filetime(value: int) -> str | None:
    if value <= 0:
        return None
    try:
        return datetime.fromtimestamp((value - 116444736000000000) / 10_000_000, tz=UTC).isoformat()
    except Exception:  # noqa: BLE001
        return None


def _guid_from_le(data: bytes) -> str | None:
    if len(data) != 16:
        return None
    try:
        return str(UUID(bytes_le=data))
    except Exception:  # noqa: BLE001
        return None


def _read_c_string(data: bytes, offset: int) -> str | None:
    if offset <= 0 or offset >= len(data):
        return None
    end = data.find(b"\x00", offset)
    if end == -1:
        end = len(data)
    chunk = data[offset:end]
    if not chunk:
        return None
    try:
        return chunk.decode("utf-8", errors="ignore").strip() or None
    except Exception:  # noqa: BLE001
        return None


def _read_utf16z(data: bytes, offset: int) -> str | None:
    if offset <= 0 or offset >= len(data):
        return None
    end = offset
    while end + 1 < len(data):
        if data[end:end + 2] == b"\x00\x00":
            break
        end += 2
    chunk = data[offset:end]
    if not chunk:
        return None
    try:
        return chunk.decode("utf-16le", errors="ignore").strip() or None
    except Exception:  # noqa: BLE001
        return None


def _read_sized_string(data: bytes, offset: int, *, is_unicode: bool) -> tuple[str | None, int]:
    if offset + 2 > len(data):
        return None, offset
    count = _u16(data, offset)
    offset += 2
    if is_unicode:
        size = count * 2
        chunk = data[offset:offset + size]
        return chunk.decode("utf-16le", errors="ignore").strip() or None, offset + size
    chunk = data[offset:offset + count]
    return chunk.decode("utf-8", errors="ignore").strip() or None, offset + count


def is_shell_link_bytes(data: bytes) -> bool:
    return len(data) >= 0x4C and _u32(data, 0) == 0x4C and data[4:20] == SHELL_LINK_CLSID


def _merge_local_path(local_base: str | None, common_suffix: str | None) -> str | None:
    local = (local_base or "").strip()
    suffix = (common_suffix or "").strip()
    if local and suffix:
        if local.lower().endswith(suffix.lower()):
            return local
        if suffix.startswith("\\") or local.endswith("\\"):
            return f"{local.rstrip('\\')}{suffix}"
        return f"{local.rstrip('\\')}\\{suffix}"
    return local or suffix or None


def _parse_volume_id(data: bytes, offset: int) -> dict[str, str | int | None]:
    if offset <= 0 or offset + 16 > len(data):
        return {"drive_type": None, "drive_serial_number": None, "volume_label": None}
    size = _u32(data, offset)
    if size < 16 or offset + size > len(data):
        return {"drive_type": None, "drive_serial_number": None, "volume_label": None}
    drive_type_value = _u32(data, offset + 4)
    drive_serial = _u32(data, offset + 8)
    label_offset = _u32(data, offset + 12)
    label = _read_c_string(data, offset + label_offset) if label_offset else None
    drive_type = {
        2: "removable",
        3: "fixed",
        4: "remote",
        5: "cdrom",
        6: "ramdisk",
    }.get(drive_type_value, str(drive_type_value) if drive_type_value else None)
    return {
        "drive_type": drive_type,
        "drive_serial_number": f"{drive_serial:08X}" if drive_serial else None,
        "volume_label": label,
    }


def _parse_common_network_relative(data: bytes, offset: int) -> dict[str, str | None]:
    result = {"network_path": None, "share_name": None, "device_name": None}
    if offset <= 0 or offset + 20 > len(data):
        return result
    size = _u32(data, offset)
    if size < 20 or offset + size > len(data):
        return result
    net_name_offset = _u32(data, offset + 8)
    device_name_offset = _u32(data, offset + 12)
    result["share_name"] = _read_c_string(data, offset + net_name_offset) if net_name_offset else None
    result["device_name"] = _read_c_string(data, offset + device_name_offset) if device_name_offset else None
    if result["share_name"]:
        result["network_path"] = result["share_name"]
    return result


def _decode_machine_id(data: bytes) -> str | None:
    raw = data.split(b"\x00", 1)[0]
    if not raw:
        return None
    try:
        return raw.decode("ascii", errors="ignore").strip() or None
    except Exception:  # noqa: BLE001
        return None


def _parse_extra_data_blocks(data: bytes, offset: int) -> tuple[dict[str, str | int | None], list[str]]:
    warnings: list[str] = []
    parsed: dict[str, str | int | None] = {
        "machine_id": None,
        "droid": None,
        "birth_droid": None,
        "tracker_droid": None,
        "tracker_birth_droid": None,
        "environment_target": None,
        "known_folder_guid": None,
        "darwin_id": None,
        "has_environment_data_block": False,
        "has_known_folder_data_block": False,
        "has_property_store_data_block": False,
    }
    cursor = offset
    while cursor + 4 <= len(data):
        block_size = _u32(data, cursor)
        if block_size == 0:
            break
        if block_size < 8 or cursor + block_size > len(data):
            warnings.append("ShellLink ExtraData block is truncated or invalid")
            break
        signature = _u32(data, cursor + 4)
        block = data[cursor:cursor + block_size]
        if signature == EXTRA_DATA_TRACKER and block_size >= 0x60:
            parsed["machine_id"] = _decode_machine_id(block[0x10:0x20])
            droid_volume = _guid_from_le(block[0x20:0x30])
            droid_file = _guid_from_le(block[0x30:0x40])
            birth_volume = _guid_from_le(block[0x40:0x50])
            birth_file = _guid_from_le(block[0x50:0x60])
            if droid_volume and droid_file:
                parsed["droid"] = f"{droid_volume}:{droid_file}"
                parsed["tracker_droid"] = parsed["droid"]
            if birth_volume and birth_file:
                parsed["birth_droid"] = f"{birth_volume}:{birth_file}"
                parsed["tracker_birth_droid"] = parsed["birth_droid"]
        elif signature == EXTRA_DATA_ENVIRONMENT:
            parsed["has_environment_data_block"] = True
            environment_ansi = _read_c_string(block, 8)
            environment_unicode = _read_utf16z(block, 0x108) if block_size >= 0x314 else None
            parsed["environment_target"] = environment_unicode or environment_ansi
        elif signature == EXTRA_DATA_KNOWN_FOLDER and block_size >= 0x1C:
            parsed["has_known_folder_data_block"] = True
            parsed["known_folder_guid"] = _guid_from_le(block[8:24])
        elif signature == EXTRA_DATA_PROPERTY_STORE:
            parsed["has_property_store_data_block"] = True
        elif signature == EXTRA_DATA_DARWIN:
            parsed["darwin_id"] = _read_c_string(block, 8)
        cursor += block_size
    return parsed, warnings


def parse_shell_link_bytes(data: bytes, *, stream_name: str | None = None) -> tuple[dict, list[str]]:
    warnings: list[str] = []
    if not is_shell_link_bytes(data):
        return {}, ["ShellLink header not found"]

    flags = _u32(data, 0x14)
    file_attributes = _u32(data, 0x18)
    created = _parse_filetime(_u64(data, 0x1C))
    accessed = _parse_filetime(_u64(data, 0x24))
    modified = _parse_filetime(_u64(data, 0x2C))
    file_size = _u32(data, 0x34)
    icon_index = _u32(data, 0x38)
    show_command = _u32(data, 0x3C)
    hot_key = _u16(data, 0x40)
    offset = 0x4C

    if flags & LINK_FLAG_HAS_LINK_TARGET_ID_LIST:
        if offset + 2 > len(data):
            warnings.append("ShellLink IDList flag set but list is truncated")
            return {}, warnings
        id_list_size = _u16(data, offset)
        offset += 2 + id_list_size

    local_base_path = None
    common_path_suffix = None
    network_path = None
    share_name = None
    device_name = None
    drive_type = None
    drive_serial_number = None
    volume_label = None

    if flags & LINK_FLAG_HAS_LINK_INFO:
        if offset + 0x1C > len(data):
            warnings.append("ShellLink LinkInfo flag set but block is truncated")
            return {}, warnings
        link_info_start = offset
        link_info_size = _u32(data, offset)
        link_info_header_size = _u32(data, offset + 4)
        link_info_flags = _u32(data, offset + 8)
        volume_id_offset = _u32(data, offset + 12)
        local_base_path_offset = _u32(data, offset + 16)
        common_network_relative_offset = _u32(data, offset + 20)
        common_path_suffix_offset = _u32(data, offset + 24)
        local_base_path_unicode_offset = _u32(data, offset + 28) if link_info_header_size >= 0x24 and offset + 36 <= len(data) else 0
        common_path_suffix_unicode_offset = _u32(data, offset + 32) if link_info_header_size >= 0x24 and offset + 36 <= len(data) else 0

        if 0 < link_info_size <= len(data) - offset:
            link_info = data[link_info_start:link_info_start + link_info_size]
            if link_info_flags & LINK_INFO_FLAG_VOLUME_ID_AND_LOCAL_BASE_PATH:
                volume = _parse_volume_id(link_info, volume_id_offset)
                drive_type = volume["drive_type"]
                drive_serial_number = volume["drive_serial_number"]
                volume_label = volume["volume_label"]
                local_base_path = _read_c_string(link_info, local_base_path_offset) if local_base_path_offset else None
                if local_base_path_unicode_offset:
                    local_base_path = _read_utf16z(link_info, local_base_path_unicode_offset) or local_base_path
                if not local_base_path:
                    warnings.append("linkinfo_present_no_local_path")
            if common_path_suffix_offset:
                common_path_suffix = _read_c_string(link_info, common_path_suffix_offset)
                if common_path_suffix_unicode_offset:
                    common_path_suffix = _read_utf16z(link_info, common_path_suffix_unicode_offset) or common_path_suffix
            if link_info_flags & LINK_INFO_FLAG_COMMON_NETWORK_RELATIVE_LINK_AND_PATH_SUFFIX and common_network_relative_offset:
                net = _parse_common_network_relative(link_info, common_network_relative_offset)
                network_path = net["network_path"]
                share_name = net["share_name"]
                device_name = net["device_name"]
            offset = link_info_start + link_info_size
        else:
            warnings.append("linkinfo_parse_failed")

    is_unicode = bool(flags & LINK_FLAG_IS_UNICODE)
    description = relative_path = working_directory = arguments = icon_location = None
    if flags & LINK_FLAG_HAS_NAME:
        description, offset = _read_sized_string(data, offset, is_unicode=is_unicode)
    if flags & LINK_FLAG_HAS_RELATIVE_PATH:
        relative_path, offset = _read_sized_string(data, offset, is_unicode=is_unicode)
    if flags & LINK_FLAG_HAS_WORKING_DIR:
        working_directory, offset = _read_sized_string(data, offset, is_unicode=is_unicode)
    if flags & LINK_FLAG_HAS_ARGUMENTS:
        arguments, offset = _read_sized_string(data, offset, is_unicode=is_unicode)
    if flags & LINK_FLAG_HAS_ICON_LOCATION:
        icon_location, offset = _read_sized_string(data, offset, is_unicode=is_unicode)

    extra, extra_warnings = _parse_extra_data_blocks(data, offset)
    warnings.extend(extra_warnings)

    local_path = _merge_local_path(local_base_path, common_path_suffix)
    target_path = local_path or network_path or common_path_suffix or relative_path or extra.get("environment_target")
    if not target_path and not (flags & LINK_FLAG_HAS_LINK_INFO):
        warnings.append("linkinfo_absent")
    if not target_path and (flags & LINK_FLAG_HAS_LINK_TARGET_ID_LIST):
        warnings.append("target_id_list_present_unresolved")
    if not target_path and extra.get("known_folder_guid"):
        warnings.append("known_folder_unresolved")
    if not target_path and extra.get("has_property_store_data_block"):
        warnings.append("property_store_present_unparsed")
    if not target_path:
        warnings.append("no_resolved_target_path")

    return {
        "StreamName": stream_name,
        "Flags": flags,
        "TargetPath": target_path,
        "TargetIDAbsolutePath": None,
        "LocalPath": local_path,
        "CommonPath": common_path_suffix,
        "RelativePath": relative_path,
        "NetworkPath": network_path,
        "ShareName": share_name,
        "DeviceName": device_name,
        "WorkingDirectory": working_directory,
        "Arguments": arguments,
        "Description": description,
        "IconLocation": icon_location,
        "IconIndex": icon_index or None,
        "ShowCommand": show_command or None,
        "HotKey": hot_key or None,
        "TargetCreated": created,
        "TargetModified": modified,
        "TargetAccessed": accessed,
        "CreationTime": created,
        "ModifiedTime": modified,
        "AccessedTime": accessed,
        "FileSize": file_size or None,
        "FileAttributes": file_attributes or None,
        "IsDirectory": bool(file_attributes & FILE_ATTRIBUTE_DIRECTORY),
        "DriveType": drive_type,
        "VolumeSerialNumber": drive_serial_number,
        "VolumeLabel": volume_label,
        "MachineID": extra.get("machine_id"),
        "TrackerDroid": extra.get("tracker_droid"),
        "TrackerBirthDroid": extra.get("tracker_birth_droid"),
        "Droid": extra.get("droid"),
        "BirthDroid": extra.get("birth_droid"),
        "EnvironmentTarget": extra.get("environment_target"),
        "KnownFolderGuid": extra.get("known_folder_guid"),
        "DarwinId": extra.get("darwin_id"),
        "HasLinkTargetIdList": bool(flags & LINK_FLAG_HAS_LINK_TARGET_ID_LIST),
        "HasLinkInfo": bool(flags & LINK_FLAG_HAS_LINK_INFO),
        "HasKnownFolderDataBlock": bool(extra.get("has_known_folder_data_block")),
        "HasPropertyStoreDataBlock": bool(extra.get("has_property_store_data_block")),
        "HasEnvironmentVariableDataBlock": bool(extra.get("has_environment_data_block")),
        "IsShellTarget": False if target_path else True,
    }, warnings


__all__ = ["is_shell_link_bytes", "parse_shell_link_bytes"]
