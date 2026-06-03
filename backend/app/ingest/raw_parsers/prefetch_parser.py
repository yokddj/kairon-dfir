from collections import Counter
from datetime import UTC, datetime, timedelta
from pathlib import Path
import importlib
import re
import struct
import time

from app.ingest.raw_parsers.audit import build_raw_parser_audit
from app.ingest.raw_parsers.base import BaseRawParser
from app.ingest.raw_parsers.models import RawParserResult
from app.ingest.velociraptor.path_utils import normalize_velociraptor_path


SUPPORTED_PREFETCH_VERSIONS = {17, 23, 26, 30, 31}
_PREFETCH_ENTRY_SIZES = {
    17: 40,
    23: 104,
    26: 104,
    30: 104,
    31: 104,
}
SUPPORTED_MAGIC = {"SCCA", "MAM"}
_LOL_BIN_NAMES = {
    "powershell.exe",
    "pwsh.exe",
    "cmd.exe",
    "wscript.exe",
    "cscript.exe",
    "mshta.exe",
    "rundll32.exe",
    "regsvr32.exe",
    "certutil.exe",
    "bitsadmin.exe",
    "msiexec.exe",
    "schtasks.exe",
    "net.exe",
    "net1.exe",
    "sc.exe",
    "whoami.exe",
    "nltest.exe",
    "quser.exe",
    "wevtutil.exe",
    "vssadmin.exe",
    "wbadmin.exe",
    "bcdedit.exe",
}


def _u32(data: bytes, offset: int) -> int:
    return struct.unpack_from("<I", data, offset)[0]


def _u64(data: bytes, offset: int) -> int:
    return struct.unpack_from("<Q", data, offset)[0]


def _safe_u32(data: bytes, offset: int) -> int | None:
    if offset < 0 or offset + 4 > len(data):
        return None
    return _u32(data, offset)


def _safe_u64(data: bytes, offset: int) -> int | None:
    if offset < 0 or offset + 8 > len(data):
        return None
    return _u64(data, offset)


def _filetime_to_iso(value: int | None) -> str | None:
    if not value:
        return None
    try:
        epoch = datetime(1601, 1, 1, tzinfo=UTC)
        return (epoch + timedelta(microseconds=int(value) // 10)).isoformat()
    except Exception:  # noqa: BLE001
        return None


def _decode_utf16le_z(data: bytes) -> str | None:
    if not data:
        return None
    try:
        text = data.decode("utf-16le", errors="ignore").split("\x00", 1)[0].strip()
        return text or None
    except Exception:  # noqa: BLE001
        return None


def _clean_pathish(value: str | None) -> str | None:
    if not value:
        return None
    cleaned = value.strip().replace("/", "\\")
    return cleaned or None


def _parse_prefetch_filename(path: str | Path) -> tuple[str | None, str | None]:
    filename = Path(str(path)).name
    match = re.match(r"(?P<exe>.+?)(?:-(?P<hash>[0-9A-Fa-f]{8}))?\.pf$", filename, flags=re.IGNORECASE)
    if not match:
        return None, None
    return (
        str(match.group("exe") or "").strip() or None,
        str(match.group("hash") or "").upper() or None,
    )


def _read_magic(data: bytes) -> str:
    if len(data) >= 3 and data[:3] == b"MAM":
        return "MAM"
    try:
        return data[4:8].decode("ascii", errors="ignore") if len(data) >= 8 else ""
    except Exception:  # noqa: BLE001
        return ""


def _decompress_mam_prefetch(data: bytes) -> bytes:
    if len(data) < 12 or data[:3] != b"MAM":
        raise ValueError("mam_decompression_failed")
    uncompressed_size = _u32(data, 4)
    if uncompressed_size <= 0:
        raise ValueError("mam_decompression_failed")

    try:
        xpress_lz77 = importlib.import_module("xpress_lz77")
        decompress_fn = xpress_lz77.lz77_huffman_decompress_py
    except Exception as exc:  # noqa: BLE001
        raise ValueError("mam_decompression_not_supported") from exc

    compressed_chunks: list[bytes] = []
    cursor = 12
    framed_stream_valid = True
    while cursor < len(data):
        if cursor + 4 > len(data):
            framed_stream_valid = False
            break
        compressed_size = _u32(data, cursor)
        cursor += 4
        if compressed_size <= 0 or cursor + compressed_size > len(data):
            framed_stream_valid = False
            break
        compressed_chunks.append(data[cursor: cursor + compressed_size])
        cursor += compressed_size

    attempts: list[bytes] = []
    if framed_stream_valid and compressed_chunks:
        attempts.append(b"".join(compressed_chunks))
    if len(data) > 12:
        attempts.append(data[12:])
    if len(data) > 8:
        attempts.append(data[8:])

    seen_inputs: set[bytes] = set()
    for candidate in attempts:
        if not candidate or candidate in seen_inputs:
            continue
        seen_inputs.add(candidate)
        try:
            decompressed = decompress_fn(candidate, uncompressed_size)
        except Exception:  # noqa: BLE001
            continue
        if _read_magic(decompressed) == "SCCA":
            return decompressed

    raise ValueError("mam_decompression_failed")


def _read_prefetch_string_block(data: bytes, offset: int | None, size: int | None) -> list[str]:
    if offset in (None, 0) or size in (None, 0):
        return []
    if offset < 0 or size < 0 or offset + size > len(data):
        return []
    try:
        text = data[offset: offset + size].decode("utf-16le", errors="ignore")
    except Exception:  # noqa: BLE001
        return []
    parts = [part.strip().replace("/", "\\") for part in text.split("\x00") if part.strip()]
    return list(dict.fromkeys(parts))


def _read_directory_strings(data: bytes, base_offset: int, offset: int | None, count: int | None) -> list[str]:
    if offset in (None, 0) or count in (None, 0):
        return []
    cursor = base_offset + int(offset)
    values: list[str] = []
    for _ in range(int(count or 0)):
        if cursor + 2 > len(data):
            break
        length = struct.unpack_from("<H", data, cursor)[0]
        cursor += 2
        byte_length = length * 2
        if cursor + byte_length > len(data):
            break
        value = _decode_utf16le_z(data[cursor: cursor + byte_length])
        cursor += byte_length
        if cursor + 2 <= len(data):
            cursor += 2
        if value:
            values.append(value.replace("/", "\\"))
    return list(dict.fromkeys(values))


def _derive_executable_path(executable_name: str | None, referenced_files: list[str], referenced_directories: list[str], volume_device_path: str | None) -> str | None:
    normalized_name = str(executable_name or "").lower()
    for candidate in referenced_files:
        lower = candidate.lower()
        if normalized_name and lower.endswith("\\" + normalized_name):
            return candidate
    for candidate in referenced_files:
        lower = candidate.lower()
        if lower.endswith(".exe") and (not normalized_name or normalized_name in lower):
            return candidate
    for directory in referenced_directories:
        if normalized_name and (":\\" in directory or directory.startswith("\\\\")):
            return f"{directory.rstrip('\\')}\\{executable_name}"
    if volume_device_path and executable_name:
        return f"{volume_device_path.rstrip('\\')}\\{executable_name}"
    return None


def _infer_timestamp_fields(version: int, info_offset: int, data: bytes) -> tuple[str | None, list[str], int | None]:
    last_runs: list[str] = []
    run_count: int | None = None
    if version == 17:
        single = _filetime_to_iso(_safe_u64(data, info_offset + 36))
        if single:
            last_runs.append(single)
        run_count = _safe_u32(data, info_offset + 60)
    elif version == 23:
        single = _filetime_to_iso(_safe_u64(data, info_offset + 44))
        if single:
            last_runs.append(single)
        run_count = _safe_u32(data, info_offset + 68)
    elif version in {26, 30, 31}:
        for index in range(8):
            parsed = _filetime_to_iso(_safe_u64(data, info_offset + 44 + (index * 8)))
            if parsed:
                last_runs.append(parsed)
        run_count = _safe_u32(data, info_offset + 116)
    else:
        run_count = None
    ordered = sorted(dict.fromkeys(last_runs))
    return (ordered[-1] if ordered else None), ordered, run_count


def parse_prefetch_bytes(data: bytes, *, source_name: str = "") -> tuple[dict, list[str]]:
    warnings: list[str] = []
    if len(data) < 84:
        raise ValueError("Prefetch file too small")
    magic = _read_magic(data)
    if magic == "MAM":
        data = _decompress_mam_prefetch(data)
        magic = _read_magic(data)
    version = _u32(data, 0)
    signature = data[4:8].decode("ascii", errors="ignore")
    file_size = _u32(data, 12)
    executable_name = _decode_utf16le_z(data[16:76])
    executable_from_name, hash_from_name = _parse_prefetch_filename(source_name or executable_name or "")
    prefetch_hash = hash_from_name
    if signature != "SCCA":
        raise ValueError(f"Invalid Prefetch signature: {signature!r}")

    parsed: dict[str, object] = {
        "Version": version,
        "Signature": signature,
        "FileSize": file_size,
        "ExecutableName": executable_name or executable_from_name,
        "PrefetchHash": prefetch_hash,
        "ReferencedFiles": [],
        "ReferencedDirectories": [],
        "VolumeDevicePath": None,
        "VolumeSerialNumber": None,
        "VolumeCreationTime": None,
        "VolumeLabel": None,
        "LastRun": None,
        "LastRuns": [],
        "RunCount": None,
    }
    if version not in SUPPORTED_PREFETCH_VERSIONS:
        warnings.append("unsupported_prefetch_version")
        return parsed, warnings

    info_offset = 84
    metrics_offset = _safe_u32(data, info_offset + 0)
    metrics_count = _safe_u32(data, info_offset + 4)
    _ = metrics_offset, metrics_count
    filename_strings_offset = _safe_u32(data, info_offset + 16)
    filename_strings_size = _safe_u32(data, info_offset + 20)
    volumes_info_offset = _safe_u32(data, info_offset + 24)
    volumes_count = _safe_u32(data, info_offset + 28)
    last_run, last_runs, run_count = _infer_timestamp_fields(version, info_offset, data)
    parsed["LastRun"] = last_run
    parsed["LastRuns"] = last_runs
    parsed["RunCount"] = run_count

    referenced_files = _read_prefetch_string_block(data, filename_strings_offset, filename_strings_size)
    parsed["ReferencedFiles"] = referenced_files
    volume_entry_size = _PREFETCH_ENTRY_SIZES.get(version, 104)
    all_directories: list[str] = []
    volume_paths: list[str] = []
    volume_serials: list[str] = []
    volume_labels: list[str] = []
    volume_created_times: list[str] = []

    if volumes_info_offset is None or volumes_count is None:
        warnings.append("missing_volume_info")
    else:
        for index in range(int(volumes_count or 0)):
            entry_offset = int(volumes_info_offset) + (index * volume_entry_size)
            if entry_offset + 36 > len(data):
                warnings.append("volume_info_truncated")
                break
            device_path_offset = _safe_u32(data, entry_offset + 0)
            device_path_chars = _safe_u32(data, entry_offset + 4)
            creation_filetime = _safe_u64(data, entry_offset + 8)
            serial_number = _safe_u32(data, entry_offset + 16)
            dir_strings_offset = _safe_u32(data, entry_offset + 28)
            dir_strings_count = _safe_u32(data, entry_offset + 32)
            if device_path_offset is not None and device_path_chars not in (None, 0):
                device_start = int(volumes_info_offset) + int(device_path_offset)
                device_end = device_start + (int(device_path_chars) * 2)
                device_path = _decode_utf16le_z(data[device_start:device_end])
                if device_path:
                    volume_paths.append(device_path.replace("/", "\\"))
            if serial_number is not None:
                volume_serials.append(f"{int(serial_number):08X}")
            created = _filetime_to_iso(creation_filetime)
            if created:
                volume_created_times.append(created)
            all_directories.extend(
                _read_directory_strings(
                    data,
                    int(volumes_info_offset),
                    dir_strings_offset,
                    dir_strings_count,
                )
            )

    parsed["ReferencedDirectories"] = list(dict.fromkeys(directory.replace("/", "\\") for directory in all_directories if directory))
    parsed["VolumeDevicePath"] = volume_paths[0] if volume_paths else None
    parsed["VolumeSerialNumber"] = volume_serials[0] if volume_serials else None
    parsed["VolumeCreationTime"] = volume_created_times[0] if volume_created_times else None
    parsed["VolumeLabel"] = volume_labels[0] if volume_labels else None
    executable_path = _derive_executable_path(
        str(parsed.get("ExecutableName") or ""),
        list(parsed.get("ReferencedFiles") or []),
        list(parsed.get("ReferencedDirectories") or []),
        str(parsed.get("VolumeDevicePath") or "") or None,
    )
    parsed["ExecutablePath"] = _clean_pathish(executable_path)
    if not parsed["ExecutablePath"]:
        warnings.append("executable_path_unresolved")
    if not parsed["LastRun"] and not parsed["LastRuns"]:
        warnings.append("missing_last_run_timestamp")
    if not parsed["RunCount"]:
        warnings.append("missing_run_count")
    return parsed, warnings


class PrefetchRawParser(BaseRawParser):
    parser_name = "prefetch_raw"
    artifact_type = "prefetch_raw"

    def can_parse(self, candidate_or_path: object) -> bool:
        path = getattr(candidate_or_path, "original_path", candidate_or_path)
        return str(path or "").lower().endswith(".pf")

    def parse(self, path: Path, *, case_id: str, evidence_id: str, artifact_id: str, artifact_meta: dict) -> RawParserResult:
        from app.ingest.normalizer import normalize_row

        start = time.perf_counter()
        warnings: list[str] = []
        errors: list[str] = []
        events: list[dict] = []
        records_read = 1
        original_source_path = str(artifact_meta.get("source_path") or path)
        normalized_source_path = str(artifact_meta.get("velociraptor_normalized_windows_path") or normalize_velociraptor_path(original_source_path) or original_source_path)
        filename_executable, filename_hash = _parse_prefetch_filename(original_source_path)
        metadata: dict[str, object] = {
            "parse_duration_ms": 0,
            "prefetch_files_seen": 1,
            "prefetch_files_opened": 0,
            "prefetch_files_parsed": 0,
            "prefetch_files_partial": 0,
            "prefetch_files_failed": 0,
            "prefetch_failed_count": 0,
            "prefetch_parsed_records_count": 0,
            "prefetch_normalized_events_count": 0,
            "prefetch_empty_parser_results_count": 0,
            "prefetch_events_indexed": 0,
            "prefetch_unsupported_version_count": 0,
            "prefetch_parse_warnings_count": 0,
            "prefetch_resolved_executable_path_count": 0,
            "prefetch_unresolved_executable_path_count": 0,
            "prefetch_mam_compressed_count": 0,
            "prefetch_decompressed_count": 0,
            "prefetch_decompression_failed_count": 0,
            "suspicious_prefetch_count": 0,
            "lolbin_prefetch_count": 0,
            "prefetch_magic_initial": None,
            "prefetch_magic_is_scca": False,
            "prefetch_magic_is_mam": False,
            "prefetch_version_detected": None,
            "prefetch_compressed": False,
            "prefetch_decompression_attempted": False,
            "prefetch_decompression_success": False,
            "reason_if_zero_records": None,
            "prefetch_magic_counts": {},
            "prefetch_versions_seen": {},
            "top_prefetch_errors": [],
            "examples_failed_files": [],
            "examples_empty_files": [],
            "examples_partial_files": [],
            "examples_success_files": [],
            "records_parsed": 0,
            "records_filtered": 0,
            "records_failed": 0,
            "records_skipped": 0,
            "records_unprocessed": 0,
        }
        try:
            payload = path.read_bytes()
            metadata["prefetch_files_opened"] = 1
            stat = path.stat()
            magic = _read_magic(payload)
            metadata["prefetch_magic_initial"] = magic or "unknown"
            metadata["prefetch_magic_is_scca"] = magic == "SCCA"
            metadata["prefetch_magic_is_mam"] = magic == "MAM"
            metadata["prefetch_magic_counts"] = {magic or "unknown": 1}
            if magic == "MAM":
                metadata["prefetch_mam_compressed_count"] = 1
                metadata["prefetch_compressed"] = True
                metadata["prefetch_decompression_attempted"] = True
            parsed, parser_warnings = parse_prefetch_bytes(payload, source_name=original_source_path)
            if magic == "MAM":
                metadata["prefetch_decompression_success"] = True
                metadata["prefetch_decompressed_count"] = 1
            warnings.extend(parser_warnings)
            version = int(parsed.get("Version") or 0)
            metadata["prefetch_version_detected"] = version or None
            metadata["by_version"] = {str(version): 1} if version else {}
            metadata["prefetch_versions_seen"] = {str(version): 1} if version else {}
            if "unsupported_prefetch_version" in parser_warnings:
                metadata["prefetch_unsupported_version_count"] = 1
                raise ValueError(f"unsupported_prefetch_version:{version}")
            reliable_local_fs_times = Path(original_source_path).resolve() == path.resolve()
            source_created = datetime.fromtimestamp(getattr(stat, "st_birthtime", stat.st_ctime), tz=UTC).isoformat() if reliable_local_fs_times else None
            source_modified = datetime.fromtimestamp(stat.st_mtime, tz=UTC).isoformat() if reliable_local_fs_times else None
            source_accessed = datetime.fromtimestamp(stat.st_atime, tz=UTC).isoformat() if reliable_local_fs_times else None
            last_runs = list(parsed.get("LastRuns") or [])
            parser_status = "parsed_native"
            if not parsed.get("LastRun") and not last_runs and not parsed.get("RunCount"):
                parser_status = "partial"
            row = {
                "SourceFile": normalized_source_path,
                "OriginalSourceFile": original_source_path,
                "NormalizedWindowsPath": normalized_source_path,
                "ExecutableName": parsed.get("ExecutableName") or filename_executable,
                "ExecutablePath": parsed.get("ExecutablePath"),
                "Path": parsed.get("ExecutablePath"),
                "PrefetchHash": parsed.get("PrefetchHash") or filename_hash,
                "Hash": parsed.get("PrefetchHash") or filename_hash,
                "RunCount": parsed.get("RunCount"),
                "LastRun": parsed.get("LastRun"),
                "Version": parsed.get("Version"),
                "Signature": parsed.get("Signature"),
                "FileSize": parsed.get("FileSize"),
                "VolumeSerialNumber": parsed.get("VolumeSerialNumber"),
                "VolumeDevicePath": parsed.get("VolumeDevicePath"),
                "VolumeCreationTime": parsed.get("VolumeCreationTime"),
                "VolumeLabel": parsed.get("VolumeLabel"),
                "ReferencedFiles": "|".join(parsed.get("ReferencedFiles") or []),
                "Directories": "|".join(parsed.get("ReferencedDirectories") or []),
                "LoadedFilesCount": len(parsed.get("ReferencedFiles") or []),
                "ReferencedFilesCount": len(parsed.get("ReferencedFiles") or []),
                "SourceCreated": source_created,
                "SourceModified": source_modified,
                "SourceAccessed": source_accessed,
                "SourceFileMtime": artifact_meta.get("mtime"),
                "SourceFileMtimeConfidence": "high" if reliable_local_fs_times and artifact_meta.get("mtime") else "low" if artifact_meta.get("mtime") else None,
                "ParseWarnings": "; ".join(parser_warnings) if parser_warnings else None,
                "ParserStatus": parser_status,
            }
            previous_runs = list(last_runs)
            if previous_runs and parsed.get("LastRun") and previous_runs[-1] == parsed.get("LastRun"):
                previous_runs = previous_runs[:-1]
            for index, run in enumerate(previous_runs[:8]):
                row[f"PreviousRun{index}"] = run
            document = normalize_row(
                case_id,
                evidence_id,
                artifact_id,
                row,
                {
                    **artifact_meta,
                    "artifact_type": "prefetch",
                    "parser": "prefetch_raw",
                    "source_tool": "native_prefetch",
                    "source_format": "pf",
                    "source_path": normalized_source_path,
                    "velociraptor_original_path": original_source_path,
                    "velociraptor_normalized_windows_path": normalized_source_path,
                    "source_file_mtime": artifact_meta.get("mtime"),
                    "source_file_mtime_confidence": "high" if reliable_local_fs_times and artifact_meta.get("mtime") else "low" if artifact_meta.get("mtime") else None,
                    "parser_processed_at": datetime.now(tz=UTC).isoformat(),
                },
            )
            if document:
                events.append(document)
            metadata["prefetch_files_parsed"] = 1
            metadata["prefetch_parsed_records_count"] = 1
            metadata["prefetch_events_indexed"] = len(events)
            metadata["prefetch_normalized_events_count"] = len(events)
            metadata["prefetch_parse_warnings_count"] = len(parser_warnings)
            if document:
                if str(document.get("event", {}).get("type") or "") == "prefetch_observed":
                    metadata["prefetch_files_partial"] = 1
                metadata["prefetch_resolved_executable_path_count"] = 1 if document.get("process", {}).get("path") else 0
                metadata["prefetch_unresolved_executable_path_count"] = 0 if document.get("process", {}).get("path") else 1
                metadata["suspicious_prefetch_count"] = 1 if "suspicious" in set(document.get("tags") or []) else 0
                metadata["lolbin_prefetch_count"] = 1 if str(document.get("process", {}).get("name") or "").lower() in _LOL_BIN_NAMES or "lolbin" in set(document.get("tags") or []) else 0
                metadata["records_parsed"] = 1
                metadata["sample_event_ids"] = [str(document.get("id") or document.get("event_id") or "")]
                metadata["sample_messages"] = [str((document.get("event") or {}).get("message") or "")]
                metadata["examples_success_files"] = [normalized_source_path]
                if str(document.get("event", {}).get("type") or "") == "prefetch_observed":
                    metadata["examples_partial_files"] = [normalized_source_path]
            else:
                metadata["prefetch_empty_parser_results_count"] = 1
                metadata["records_unprocessed"] = 1
                metadata["examples_empty_files"] = [normalized_source_path]
                metadata["reason_if_zero_records"] = "normalizer_dropped_event"
                warnings.append("normalizer_dropped_event")
        except Exception as exc:  # noqa: BLE001
            error_text = str(exc)
            errors.append(error_text)
            metadata["prefetch_files_failed"] = 1
            metadata["prefetch_failed_count"] = 1
            metadata["records_failed"] = 1
            metadata["top_prefetch_errors"] = [error_text]
            metadata["examples_failed_files"] = [normalized_source_path]
            if error_text.startswith("unsupported_prefetch_version"):
                metadata["prefetch_unsupported_version_count"] = 1
                metadata["reason_if_zero_records"] = "unsupported_version"
                warnings.append("unsupported_prefetch_version")
            elif error_text == "mam_decompression_not_supported":
                metadata["prefetch_mam_compressed_count"] = 1
                metadata["prefetch_decompression_failed_count"] = 1
                metadata["reason_if_zero_records"] = "mam_decompression_not_supported"
                warnings.extend(["mam_compressed_prefetch", "mam_decompression_not_supported"])
            elif error_text == "mam_decompression_failed":
                metadata["prefetch_mam_compressed_count"] = 1
                metadata["prefetch_decompression_failed_count"] = 1
                metadata["reason_if_zero_records"] = "mam_decompression_not_supported"
                warnings.extend(["mam_compressed_prefetch", "mam_decompression_not_supported", "mam_decompression_failed"])
            elif "Invalid Prefetch signature" in error_text:
                metadata["reason_if_zero_records"] = "invalid_signature"
                warnings.append("invalid_signature")
            elif "too small" in error_text.lower():
                metadata["reason_if_zero_records"] = "parser_returned_empty"
                warnings.append("parser_returned_empty")
            else:
                metadata["reason_if_zero_records"] = "exception"
                warnings.append("exception")
        parser_status = "parsed_native" if events else "failed"
        if events and str(events[0].get("event", {}).get("type") or "") == "prefetch_observed":
            parser_status = "partial"
        elif not events and "unsupported_prefetch_version" in warnings:
            parser_status = "failed_unsupported"
        elif not events and "mam_decompression_not_supported" in warnings:
            parser_status = "failed_unsupported"
        elif not events and "mam_decompression_failed" in warnings:
            parser_status = "failed_unsupported"
        elif not events and metadata.get("prefetch_empty_parser_results_count"):
            parser_status = "failed"
        if not events and not metadata.get("reason_if_zero_records"):
            if "normalizer_dropped_event" in warnings:
                metadata["reason_if_zero_records"] = "normalizer_dropped_event"
            elif "parser_returned_empty" in warnings:
                metadata["reason_if_zero_records"] = "parser_returned_empty"
            elif "unsupported_prefetch_version" in warnings:
                metadata["reason_if_zero_records"] = "unsupported_version"
            elif "mam_decompression_not_supported" in warnings or "mam_decompression_failed" in warnings:
                metadata["reason_if_zero_records"] = "mam_decompression_not_supported"
            elif "invalid_signature" in warnings:
                metadata["reason_if_zero_records"] = "invalid_signature"
        result = RawParserResult(
            parser_name=self.parser_name,
            artifact_type="prefetch",
            source_path=normalized_source_path,
            records_read=records_read,
            events=events,
            warnings=warnings,
            errors=errors,
            parser_status=parser_status,
            metadata={
                **metadata,
                "parse_duration_ms": int((time.perf_counter() - start) * 1000),
            },
        )
        result.metadata["audit"] = build_raw_parser_audit(result)
        return result
