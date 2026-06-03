from collections import Counter
from datetime import UTC, datetime, timedelta
from pathlib import Path, PureWindowsPath
import importlib
import io
import struct
import time
from urllib.parse import unquote

from app.analysis.suspicious import normalize_windows_path_for_classification
from app.ingest.raw_parsers.audit import build_raw_parser_audit
from app.ingest.raw_parsers.base import BaseRawParser
from app.ingest.raw_parsers.models import RawParserResult
from app.ingest.velociraptor.path_utils import normalize_velociraptor_path


CACHE_MAGIC_NT5_2 = 0xBADC0FFE
CACHE_HEADER_SIZE_NT5_2 = 0x8
NT5_2_ENTRY_SIZE32 = 0x18
NT5_2_ENTRY_SIZE64 = 0x20

CACHE_MAGIC_NT6_1 = 0xBADC0FEE
CACHE_HEADER_SIZE_NT6_1 = 0x80
NT6_1_ENTRY_SIZE32 = 0x20
NT6_1_ENTRY_SIZE64 = 0x30
CSRSS_FLAG = 0x2

WINXP_MAGIC32 = 0xDEADBEEF
WINXP_HEADER_SIZE32 = 0x190
WINXP_ENTRY_SIZE32 = 0x228
MAX_PATH = 520

WIN8_STATS_SIZE = 0x80
WIN8_MAGIC = b"00ts"
WIN81_MAGIC = b"10ts"
WIN10_STATS_SIZE = 0x30
WIN10_MAGIC = b"10ts"

EXECUTABLE_EXTENSIONS = {".exe", ".dll", ".sys", ".com", ".scr", ".bat", ".cmd", ".ps1", ".vbs", ".js", ".jse", ".wsf", ".msi", ".lnk", ".cpl"}


def shimcache_native_available() -> bool:
    try:
        importlib.import_module("Registry.Registry")
        return True
    except Exception:  # noqa: BLE001
        return False


def _load_registry_module():
    return importlib.import_module("Registry.Registry")


def _decode_windows_path(value: object) -> str | None:
    if value in (None, "", "None"):
        return None
    decoded = unquote(str(value).strip()).replace("/", "\\")
    if decoded.startswith('"') and decoded.endswith('"'):
        decoded = decoded[1:-1]
    return decoded or None


def _normalize_windows_path(value: object) -> str | None:
    decoded = _decode_windows_path(value)
    return normalize_windows_path_for_classification(decoded)


def _basename(path: str | None) -> str | None:
    if not path:
        return None
    try:
        return PureWindowsPath(path).name or None
    except Exception:  # noqa: BLE001
        return Path(path).name or None


def _iso_from_datetime(value: datetime | None) -> str | None:
    if value is None:
        return None
    if value.tzinfo is None:
        value = value.replace(tzinfo=UTC)
    return value.isoformat()


def _filetime_to_datetime(low: int, high: int) -> datetime | None:
    try:
        numeric = (high << 32) | low
        if numeric <= 0:
            return None
        epoch = datetime(1601, 1, 1, tzinfo=UTC)
        return epoch + timedelta(microseconds=numeric / 10)
    except Exception:  # noqa: BLE001
        return None


class _CacheEntryNt5:
    def __init__(self, is_32_bit: bool) -> None:
        self.is_32_bit = is_32_bit
        self.w_length = 0
        self.offset = 0
        self.dw_low_date_time = 0
        self.dw_high_date_time = 0
        self.dw_file_size_low = 0

    def size(self) -> int:
        return NT5_2_ENTRY_SIZE32 if self.is_32_bit else NT5_2_ENTRY_SIZE64

    def update(self, data: bytes) -> None:
        if self.is_32_bit:
            entry = struct.unpack("<2H 3L 2L", data)
        else:
            entry = struct.unpack("<2H 4x Q 2L 2L", data)
        self.w_length = entry[0]
        self.offset = entry[2]
        self.dw_low_date_time = entry[3]
        self.dw_high_date_time = entry[4]
        self.dw_file_size_low = entry[5]


class _CacheEntryNt6:
    def __init__(self, is_32_bit: bool) -> None:
        self.is_32_bit = is_32_bit
        self.w_length = 0
        self.offset = 0
        self.dw_low_date_time = 0
        self.dw_high_date_time = 0
        self.file_flags = 0
        self.flags = 0

    def size(self) -> int:
        return NT6_1_ENTRY_SIZE32 if self.is_32_bit else NT6_1_ENTRY_SIZE64

    def update(self, data: bytes) -> None:
        if self.is_32_bit:
            entry = struct.unpack("<2H 7L", data)
        else:
            entry = struct.unpack("<2H 4x Q 4L 2Q", data)
        self.w_length = entry[0]
        self.offset = entry[2]
        self.dw_low_date_time = entry[3]
        self.dw_high_date_time = entry[4]
        self.file_flags = entry[5]
        self.flags = entry[6]


def _parse_nt5_entries(bin_data: bytes) -> list[dict]:
    entry_list: list[dict] = []
    test_size = struct.unpack("<H", bin_data[8:10])[0]
    test_max_size = struct.unpack("<H", bin_data[10:12])[0]
    is_64_bit = (test_max_size - test_size == 2 and struct.unpack("<L", bin_data[12:16])[0] == 0)
    entry = _CacheEntryNt5(not is_64_bit)
    entry_size = entry.size()
    num_entries = struct.unpack("<L", bin_data[4:8])[0]
    if num_entries == 0:
        return entry_list

    contains_file_size = False
    for offset in range(CACHE_HEADER_SIZE_NT5_2, (num_entries * entry_size) + CACHE_HEADER_SIZE_NT5_2, entry_size):
        entry.update(bin_data[offset:offset + entry_size])
        if entry.dw_file_size_low > 3:
            contains_file_size = True
            break

    for offset in range(CACHE_HEADER_SIZE_NT5_2, (num_entries * entry_size) + CACHE_HEADER_SIZE_NT5_2, entry_size):
        entry.update(bin_data[offset:offset + entry_size])
        original_path = _decode_windows_path(bin_data[entry.offset:entry.offset + entry.w_length].decode("utf-16le", "replace"))
        path = _normalize_windows_path(original_path)
        entry_list.append(
            {
                "path": path,
                "original_path": original_path or path,
                "last_modified_time": _iso_from_datetime(_filetime_to_datetime(entry.dw_low_date_time, entry.dw_high_date_time)),
                "executed": None if contains_file_size else bool(entry.dw_file_size_low & CSRSS_FLAG),
                "file_size": entry.dw_file_size_low if contains_file_size else None,
                "insert_flags": str(entry.dw_file_size_low) if not contains_file_size else None,
                "cache_format": "nt5",
            }
        )
    return entry_list


def _parse_nt6_entries(bin_data: bytes) -> list[dict]:
    entry_list: list[dict] = []
    test_size = struct.unpack("<H", bin_data[CACHE_HEADER_SIZE_NT6_1:CACHE_HEADER_SIZE_NT6_1 + 2])[0]
    test_max_size = struct.unpack("<H", bin_data[CACHE_HEADER_SIZE_NT6_1 + 2:CACHE_HEADER_SIZE_NT6_1 + 4])[0]
    is_64_bit = (
        test_max_size - test_size == 2
        and struct.unpack("<L", bin_data[CACHE_HEADER_SIZE_NT6_1 + 4:CACHE_HEADER_SIZE_NT6_1 + 8])[0] == 0
    )
    entry = _CacheEntryNt6(not is_64_bit)
    entry_size = entry.size()
    num_entries = struct.unpack("<L", bin_data[4:8])[0]
    if num_entries == 0:
        return entry_list

    for offset in range(CACHE_HEADER_SIZE_NT6_1, num_entries * entry_size + CACHE_HEADER_SIZE_NT6_1, entry_size):
        entry.update(bin_data[offset:offset + entry_size])
        original_path = _decode_windows_path(bin_data[entry.offset:entry.offset + entry.w_length].decode("utf-16le", "replace"))
        path = _normalize_windows_path(original_path)
        entry_list.append(
            {
                "path": path,
                "original_path": original_path or path,
                "last_modified_time": _iso_from_datetime(_filetime_to_datetime(entry.dw_low_date_time, entry.dw_high_date_time)),
                "executed": bool(entry.file_flags & CSRSS_FLAG),
                "insert_flags": str(entry.file_flags),
                "shim_flags": str(entry.flags),
                "cache_format": "nt6",
            }
        )
    return entry_list


def _parse_win8_entries(bin_data: bytes, magic: bytes) -> list[dict]:
    entry_list: list[dict] = []
    data = io.BytesIO(bin_data[WIN8_STATS_SIZE:])
    while data.tell() < len(bin_data) - WIN8_STATS_SIZE:
        header = data.read(12)
        if len(header) < 12:
            break
        entry_magic, _crc32_hash, entry_len = struct.unpack("<4sLL", header)
        if entry_magic != magic:
            raise ValueError(f"Invalid version magic tag found: {entry_magic!r}")
        entry_data = io.BytesIO(data.read(entry_len))
        path_len = struct.unpack("<H", entry_data.read(2))[0]
        original_path = _decode_windows_path(entry_data.read(path_len).decode("utf-16le", "replace")) if path_len else None
        path = _normalize_windows_path(original_path) if original_path else None
        package_len = struct.unpack("<H", entry_data.read(2))[0]
        if package_len > 0:
            entry_data.seek(package_len, 1)
        flags, unk_1, low_datetime, high_datetime, unk_2 = struct.unpack("<LLLLL", entry_data.read(20))
        entry_list.append(
            {
                "path": path,
                "original_path": original_path or path,
                "last_modified_time": _iso_from_datetime(_filetime_to_datetime(low_datetime, high_datetime)),
                "executed": bool(flags & CSRSS_FLAG),
                "insert_flags": str(flags),
                "shim_flags": f"{unk_1}:{unk_2}",
                "cache_format": "win8",
            }
        )
    return entry_list


def _parse_win10_entries(bin_data: bytes, *, creators_update: bool = False) -> list[dict]:
    entry_list: list[dict] = []
    start = WIN10_STATS_SIZE + 4 if creators_update else WIN10_STATS_SIZE
    data = io.BytesIO(bin_data[start:])
    while data.tell() < len(bin_data) - start:
        header = data.read(12)
        if len(header) < 12:
            break
        entry_magic, _crc32_hash, entry_len = struct.unpack("<4sLL", header)
        if entry_magic != WIN10_MAGIC:
            raise ValueError(f"Invalid version magic tag found: {entry_magic!r}")
        entry_data = io.BytesIO(data.read(entry_len))
        path_len = struct.unpack("<H", entry_data.read(2))[0]
        original_path = _decode_windows_path(entry_data.read(path_len).decode("utf-16le", "replace")) if path_len else None
        path = _normalize_windows_path(original_path) if original_path else None
        low_datetime, high_datetime = struct.unpack("<LL", entry_data.read(8))
        if (low_datetime + high_datetime) == 0:
            continue
        entry_list.append(
            {
                "path": path,
                "original_path": original_path or path,
                "last_modified_time": _iso_from_datetime(_filetime_to_datetime(low_datetime, high_datetime)),
                "executed": None,
                "cache_format": "win10_creators" if creators_update else "win10",
            }
        )
    return entry_list


def _parse_winxp_entries(bin_data: bytes) -> list[dict]:
    entry_list: list[dict] = []
    num_entries = struct.unpack("<L", bin_data[8:12])[0]
    if num_entries == 0:
        return entry_list
    for offset in range(WINXP_HEADER_SIZE32, (num_entries * WINXP_ENTRY_SIZE32) + WINXP_HEADER_SIZE32, WINXP_ENTRY_SIZE32):
        path_len = bin_data[offset:offset + (MAX_PATH + 8)].find(b"\x00\x00")
        if path_len == 0:
            continue
        original_path = _decode_windows_path(bin_data[offset:offset + path_len + 1].decode("utf-16le", "replace"))
        path = _normalize_windows_path(original_path)
        if not path:
            continue
        entry_data = offset + (MAX_PATH + 8)
        low1, high1 = struct.unpack("<2L", bin_data[entry_data:entry_data + 8])
        low2, high2 = struct.unpack("<2L", bin_data[entry_data + 16:entry_data + 24])
        entry_list.append(
            {
                "path": path,
                "original_path": original_path or path,
                "last_modified_time": _iso_from_datetime(_filetime_to_datetime(low1, high1)),
                "last_update": _iso_from_datetime(_filetime_to_datetime(low2, high2)),
                "executed": None,
                "file_size": struct.unpack("<2L", bin_data[entry_data + 8:entry_data + 16])[0],
                "cache_format": "winxp",
            }
        )
    return entry_list


def _get_shimcache_entries(cachebin: bytes) -> list[dict]:
    if len(cachebin) < 16:
        return []
    magic = struct.unpack("<L", cachebin[0:4])[0]
    if magic == CACHE_MAGIC_NT5_2:
        return _parse_nt5_entries(cachebin)
    if magic == CACHE_MAGIC_NT6_1:
        return _parse_nt6_entries(cachebin)
    if magic == WINXP_MAGIC32:
        return _parse_winxp_entries(cachebin)
    if len(cachebin) > WIN8_STATS_SIZE and cachebin[WIN8_STATS_SIZE:WIN8_STATS_SIZE + 4] == WIN8_MAGIC:
        return _parse_win8_entries(cachebin, WIN8_MAGIC)
    if len(cachebin) > WIN8_STATS_SIZE and cachebin[WIN8_STATS_SIZE:WIN8_STATS_SIZE + 4] == WIN81_MAGIC:
        return _parse_win8_entries(cachebin, WIN81_MAGIC)
    if len(cachebin) > WIN10_STATS_SIZE and cachebin[WIN10_STATS_SIZE:WIN10_STATS_SIZE + 4] == WIN10_MAGIC:
        return _parse_win10_entries(cachebin)
    if len(cachebin) > WIN10_STATS_SIZE and cachebin[WIN10_STATS_SIZE + 4:WIN10_STATS_SIZE + 8] == WIN10_MAGIC:
        return _parse_win10_entries(cachebin, creators_update=True)
    raise ValueError(f"unrecognized_shimcache_magic:0x{magic:x}")


def _registry_value_by_name(key, target_name: str) -> bytes | None:
    target = str(target_name or "").strip().lower()
    for value in key.values():
        try:
            if str(value.name() or "").strip().lower() == target:
                raw = value.value()
                return raw if isinstance(raw, bytes) else bytes(raw)
        except Exception:  # noqa: BLE001
            continue
    return None


def _iter_candidate_key_paths(hive) -> list[str]:
    candidates: list[str] = []
    if hasattr(hive, "root") and callable(hive.root):
        try:
            root_key = hive.root()
            for subkey in root_key.subkeys():
                subkey_path = str(subkey.path())
                lower = subkey_path.lower()
                if lower.startswith("controlset") or lower == "currentcontrolset":
                    candidates.append(f"{subkey_path}\\Control\\Session Manager\\AppCompatCache")
                    candidates.append(f"{subkey_path}\\Control\\Session Manager\\AppCompatibility")
        except Exception:  # noqa: BLE001
            candidates = []
    if not candidates:
        for name in [*(f"ControlSet{index:03d}" for index in range(1, 11)), "CurrentControlSet"]:
            candidates.append(f"{name}\\Control\\Session Manager\\AppCompatCache")
            candidates.append(f"{name}\\Control\\Session Manager\\AppCompatibility")
    return candidates


def _sample_record(row: dict) -> dict:
    return {
        "control_set": row.get("ControlSet"),
        "path": row.get("Path"),
        "original_path": row.get("OriginalPath") or row.get("Path"),
        "normalized_path": row.get("Path"),
        "file_name": row.get("FileName"),
        "last_modified_time": row.get("LastModifiedTime"),
        "last_update": row.get("LastUpdate"),
        "executed": row.get("Executed"),
        "key_path": row.get("KeyPath"),
    }


class ShimcacheRawParser(BaseRawParser):
    parser_name = "shimcache_raw"
    artifact_type = "shimcache"

    def can_parse(self, candidate_or_path: object) -> bool:
        artifact_type = str(getattr(candidate_or_path, "artifact_type", "") or "").lower()
        path = str(getattr(candidate_or_path, "original_path", candidate_or_path) or "").lower()
        normalized = normalize_velociraptor_path(path).lower()
        return artifact_type == "shimcache" or normalized.endswith("windows\\system32\\config\\system")

    def parse(self, path: Path, *, case_id: str, evidence_id: str, artifact_id: str, artifact_meta: dict) -> RawParserResult:
        from app.ingest.normalizer import normalize_row

        start = time.perf_counter()
        warnings: list[str] = []
        errors: list[str] = []
        events: list[dict] = []
        rows: list[dict] = []
        control_sets_seen: list[str] = []
        format_counts: Counter[str] = Counter()
        sample_records: list[dict] = []
        original_source_path = str(artifact_meta.get("source_path") or path)
        normalized_source_path = str(
            artifact_meta.get("velociraptor_normalized_windows_path")
            or normalize_velociraptor_path(original_source_path)
            or original_source_path
        )

        try:
            registry_module = _load_registry_module()
            hive = registry_module.Registry(str(path))
        except Exception as exc:  # noqa: BLE001
            return RawParserResult(
                parser_name=self.parser_name,
                artifact_type="shimcache",
                source_path=normalized_source_path,
                warnings=warnings,
                errors=[f"shimcache_dependency_or_open_failed: {exc}"],
                parser_status="failed_unsupported",
                metadata={
                    "parse_duration_ms": int((time.perf_counter() - start) * 1000),
                    "detected_shimcache_sources": 1,
                    "parser_selected": self.parser_name,
                    "records_extracted": 0,
                    "sample_records": [],
                    "warnings": warnings,
                    "errors": [f"shimcache_dependency_or_open_failed: {exc}"],
                    "reason_if_zero_records": "shimcache_dependency_or_open_failed",
                },
            )

        missing_key_exc = getattr(registry_module, "RegistryKeyNotFoundException", Exception)
        seen_entries: set[tuple[str | None, str | None, str | None, str | None]] = set()
        seen_source_keys: set[str] = set()

        for key_path in _iter_candidate_key_paths(hive):
            try:
                cache_key = hive.open(key_path)
            except missing_key_exc:
                continue
            except Exception as exc:  # noqa: BLE001
                warnings.append(f"key_open_failed:{key_path}:{exc}")
                continue

            cache_data = _registry_value_by_name(cache_key, "AppCompatCache")
            if not cache_data:
                warnings.append(f"missing_value:{key_path}\\AppCompatCache")
                continue

            key_last_update = _iso_from_datetime(getattr(cache_key, "timestamp", lambda: None)())
            control_set = str(key_path.split("\\", 1)[0] or "")
            control_sets_seen.append(control_set)
            seen_source_keys.add(key_path)
            try:
                parsed_entries = _get_shimcache_entries(cache_data)
            except Exception as exc:  # noqa: BLE001
                errors.append(f"parse_failed:{key_path}:{exc}")
                continue

            for index, entry in enumerate(parsed_entries, start=1):
                normalized_path = _normalize_windows_path(entry.get("path"))
                original_path = _decode_windows_path(entry.get("original_path") or entry.get("path"))
                last_modified_time = entry.get("last_modified_time")
                dedup_key = (
                    normalized_path,
                    str(last_modified_time or ""),
                    str(entry.get("executed")),
                    str(index),
                )
                if dedup_key in seen_entries:
                    continue
                seen_entries.add(dedup_key)
                file_name = _basename(normalized_path)
                file_extension = (PureWindowsPath(file_name).suffix.lower() if file_name else "")
                row = {
                    "ArtifactType": "shimcache_raw",
                    "ParserStatus": "parsed_native",
                    "EntryNumber": str(index),
                    "CacheEntryPosition": str(index),
                    "Position": str(index),
                    "Path": normalized_path,
                    "OriginalPath": original_path or normalized_path,
                    "FileName": file_name,
                    "FileExtension": file_extension or None,
                    "LastModifiedTime": last_modified_time,
                    "LastUpdate": entry.get("last_update") or key_last_update,
                    "InsertFlags": entry.get("insert_flags"),
                    "ShimFlags": entry.get("shim_flags"),
                    "Executed": entry.get("executed"),
                    "ControlSet": control_set,
                    "SourceFile": normalized_source_path,
                    "KeyPath": key_path,
                    "TimestampInterpretation": "shimcache_last_modified" if last_modified_time else "shimcache_last_update" if (entry.get("last_update") or key_last_update) else "unknown",
                    "CacheFormat": entry.get("cache_format"),
                }
                rows.append(row)
                format_counts[str(entry.get("cache_format") or "unknown")] += 1
                if len(sample_records) < 5:
                    sample_records.append(_sample_record(row))

        for row in rows:
            try:
                events.append(
                    normalize_row(
                        case_id,
                        evidence_id,
                        artifact_id,
                        row,
                        {
                            **artifact_meta,
                            "artifact_type": "shimcache",
                            "name": artifact_meta.get("name") or "Shimcache raw - SYSTEM",
                            "parser": "shimcache_raw",
                            "source_tool": "native_shimcache",
                            "source_format": "registry_hive",
                            "source_path": normalized_source_path,
                            "velociraptor_original_path": original_source_path,
                            "velociraptor_normalized_windows_path": normalized_source_path,
                            "parser_processed_at": datetime.now(tz=UTC).isoformat(),
                        },
                    )
                )
            except Exception as exc:  # noqa: BLE001
                errors.append(f"normalize_failed:{row.get('Path') or row.get('KeyPath') or 'unknown'}:{exc}")

        if not rows and not errors:
            errors.append("shimcache_parser_returned_empty")

        parser_status = "parsed_native" if events else "failed"
        metadata = {
            "parse_duration_ms": int((time.perf_counter() - start) * 1000),
            "detected_shimcache_sources": len(seen_source_keys),
            "parser_selected": self.parser_name,
            "records_extracted": len(rows),
            "sample_records": sample_records,
            "warnings": warnings,
            "errors": errors,
            "records_parsed": len(rows),
            "records_failed": max(len(rows) - len(events), 0),
            "records_filtered": 0,
            "records_skipped": 0,
            "records_unprocessed": 0,
            "shimcache_sources_seen": len(seen_source_keys),
            "shimcache_events_indexed": len(events),
            "control_sets_seen": sorted(dict.fromkeys(item for item in control_sets_seen if item)),
            "shimcache_format_counts": dict(sorted(format_counts.items())),
            "reason_if_zero_records": None if events else ("shimcache_parser_returned_empty" if not errors else errors[0].split(":", 1)[0]),
        }
        result = RawParserResult(
            parser_name=self.parser_name,
            artifact_type="shimcache",
            source_path=normalized_source_path,
            records_read=len(rows),
            events=events,
            warnings=warnings,
            errors=errors,
            parser_status=parser_status,
            metadata=metadata,
        )
        result.metadata["audit"] = build_raw_parser_audit(result)
        return result
