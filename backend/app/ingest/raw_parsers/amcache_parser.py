from collections import Counter, defaultdict
from datetime import UTC, datetime, timedelta
from pathlib import Path, PureWindowsPath
import importlib
import struct
import time
from urllib.parse import unquote

from app.ingest.raw_parsers.audit import build_raw_parser_audit
from app.ingest.raw_parsers.base import BaseRawParser
from app.ingest.raw_parsers.models import RawParserResult
from app.ingest.velociraptor.path_utils import normalize_velociraptor_path


AMCACHE_EXECUTABLE_EXTENSIONS = {".exe", ".dll", ".sys", ".com", ".scr", ".bat", ".cmd", ".ps1", ".msi"}
AMCACHE_FIELD_ALIASES = {
    "program_id": ("programid", "id", "programidentifier"),
    "program_name": ("programname", "name", "displayname"),
    "program_version": ("programversion", "version"),
    "publisher": ("publisher", "companyname", "company"),
    "product_name": ("productname", "product"),
    "product_version": ("productversion", "programversion", "version"),
    "file_id": ("fileid", "id"),
    "file_name": ("filename", "name", "originalfilename"),
    "file_path": ("path", "fullpath", "filepath", "lowercaselongpath", "longpath", "lowercasepath"),
    "path_hash": ("longpathhash", "pathhash"),
    "sha1": ("sha1",),
    "sha256": ("sha256",),
    "md5": ("md5",),
    "link_date": ("linkdate",),
    "compile_time": ("compiletime", "pecompiletime"),
    "install_date": ("installdate",),
    "uninstall_date": ("uninstalldate",),
    "language": ("language",),
    "binary_type": ("binarytype", "type"),
    "is_os_component": ("isoscomponent", "oscomponent"),
}
AMCACHE_PROGRAM_BRANCHES = ("Root\\InventoryApplication", "Root\\Programs")
AMCACHE_FILE_BRANCHES = (
    ("Root\\InventoryApplicationFile", "file"),
    ("Root\\InventoryDriverBinary", "driver"),
    ("Root\\File", "file"),
)
AMCACHE_SKIP_SUFFIXES = (".log1", ".log2", ".idx")


def amcache_native_available() -> bool:
    try:
        importlib.import_module("Registry.Registry")
        return True
    except Exception:  # noqa: BLE001
        return False


def _load_registry_module():
    return importlib.import_module("Registry.Registry")


def _canonicalize_name(value: object) -> str:
    return "".join(ch for ch in str(value or "").strip().lower() if ch.isalnum())


def _stringify_registry_value(value: object) -> str | None:
    if value in (None, ""):
        return None
    if isinstance(value, datetime):
        if value.tzinfo is None:
            value = value.replace(tzinfo=UTC)
        return value.isoformat()
    if isinstance(value, bytes):
        if len(value) in {16, 20, 32}:
            return value.hex()
        if len(value) == 8:
            try:
                unpacked = struct.unpack("<Q", value)[0]
                return str(unpacked)
            except Exception:  # noqa: BLE001
                return value.hex()
        for encoding in ("utf-16le", "utf-8", "latin-1"):
            try:
                decoded = value.decode(encoding, errors="ignore").replace("\x00", "").strip()
                if decoded:
                    return decoded
            except Exception:  # noqa: BLE001
                continue
        return value.hex()
    if isinstance(value, (list, tuple, set)):
        joined = "|".join(filter(None, (_stringify_registry_value(item) for item in value)))
        return joined or None
    return str(value).strip() or None


def _iso_from_registry_timestamp(value: object) -> str | None:
    if value in (None, "", 0):
        return None
    if isinstance(value, datetime):
        if value.tzinfo is None:
            value = value.replace(tzinfo=UTC)
        return value.isoformat()
    if isinstance(value, bytes) and len(value) == 8:
        try:
            value = struct.unpack("<Q", value)[0]
        except Exception:  # noqa: BLE001
            return None
    try:
        numeric = int(str(value).strip())
    except Exception:  # noqa: BLE001
        try:
            parsed = datetime.fromisoformat(str(value).strip())
            if parsed.tzinfo is None:
                parsed = parsed.replace(tzinfo=UTC)
            return parsed.isoformat()
        except Exception:  # noqa: BLE001
            return None
    if numeric <= 0:
        return None
    if numeric > 10_000_000_000:
        try:
            epoch = datetime(1601, 1, 1, tzinfo=UTC)
            return (epoch + timedelta(microseconds=numeric // 10)).isoformat()
        except Exception:  # noqa: BLE001
            pass
    try:
        return datetime.fromtimestamp(numeric, tz=UTC).isoformat()
    except Exception:  # noqa: BLE001
        return None


def _normalize_windows_path(value: object) -> str | None:
    raw = _stringify_registry_value(value)
    if not raw:
        return None
    decoded = unquote(raw).strip().replace("/", "\\")
    if decoded.startswith("\\??\\"):
        decoded = decoded[4:]
    if decoded.startswith('"') and decoded.endswith('"'):
        decoded = decoded[1:-1]
    return decoded or None


def _basename(path: str | None) -> str | None:
    if not path:
        return None
    try:
        return PureWindowsPath(path).name or None
    except Exception:  # noqa: BLE001
        return Path(path).name or None


def _extension(path_or_name: str | None) -> str | None:
    if not path_or_name:
        return None
    suffix = PureWindowsPath(path_or_name).suffix or Path(path_or_name).suffix
    return suffix.lower() or None


def _select_value(values: dict[str, str], *keys: str) -> str | None:
    for key in keys:
        for alias in AMCACHE_FIELD_ALIASES.get(key, ()):
            value = values.get(alias)
            if value not in (None, ""):
                return value
    return None


def _iter_registry_keys(root_key):
    yield root_key
    for subkey in root_key.subkeys():
        yield from _iter_registry_keys(subkey)


def _extract_values(key) -> dict[str, str]:
    values: dict[str, str] = {}
    for value in key.values():
        try:
            normalized_name = _canonicalize_name(value.name())
            normalized_value = _stringify_registry_value(value.value())
        except Exception:  # noqa: BLE001
            continue
        if normalized_name and normalized_value not in (None, ""):
            values[normalized_name] = normalized_value
    return values


def _branch_root_name(key_path: str) -> str:
    parts = [segment for segment in str(key_path or "").split("\\") if segment]
    return parts[1] if len(parts) > 1 else (parts[0] if parts else "")


def _row_is_useful(row: dict) -> bool:
    return any(
        row.get(field)
        for field in (
            "ProgramName",
            "ProgramId",
            "Path",
            "FileName",
            "Publisher",
            "ProductName",
            "SHA1",
            "SHA256",
            "MD5",
        )
    )


def _bool_string(value: object) -> str | None:
    if value in (None, ""):
        return None
    normalized = str(value).strip().lower()
    if normalized in {"1", "true", "yes"}:
        return "true"
    if normalized in {"0", "false", "no"}:
        return "false"
    return str(value).strip() or None


def _build_program_index(registry_module, hive, source_file: str) -> dict[str, dict]:
    program_index: dict[str, dict] = {}
    missing_key_exc = getattr(registry_module, "RegistryKeyNotFoundException", Exception)
    for branch in AMCACHE_PROGRAM_BRANCHES:
        try:
            branch_key = hive.open(branch)
        except missing_key_exc:
            continue
        except Exception:  # noqa: BLE001
            continue
        for key in _iter_registry_keys(branch_key):
            key_path = str(key.path())
            if key_path.rstrip("\\").lower() == branch.lower():
                continue
            values = _extract_values(key)
            program_id = _select_value(values, "program_id") or _basename(key_path)
            program_name = _select_value(values, "program_name", "product_name")
            if not program_id and not program_name:
                continue
            program_index[str(program_id or program_name)] = {
                "ProgramId": program_id,
                "ProgramName": program_name,
                "ProgramVersion": _select_value(values, "program_version"),
                "Publisher": _select_value(values, "publisher"),
                "ProductName": _select_value(values, "product_name") or program_name,
                "ProductVersion": _select_value(values, "product_version"),
                "InstallDate": _select_value(values, "install_date"),
                "UninstallDate": _select_value(values, "uninstall_date"),
                "KeyPath": key_path,
                "KeyLastWriteTimestamp": _iso_from_registry_timestamp(getattr(key, "timestamp", lambda: None)()),
                "SourceFile": source_file,
            }
    return program_index


def _build_row_from_key(*, key, values: dict[str, str], branch_kind: str, source_file: str, program_index: dict[str, dict]) -> dict | None:
    key_path = str(key.path())
    program_id = _select_value(values, "program_id") or _basename(key_path)
    linked_program = program_index.get(str(program_id or "")) or {}
    file_path = _normalize_windows_path(_select_value(values, "file_path")) or _normalize_windows_path(linked_program.get("Path"))
    file_name = _basename(file_path) or _select_value(values, "file_name", "program_name", "product_name") or linked_program.get("FileName") or linked_program.get("ProgramName")
    extension = _extension(file_path or file_name)
    program_name = _select_value(values, "program_name", "product_name") or linked_program.get("ProgramName")
    publisher = _select_value(values, "publisher") or linked_program.get("Publisher")
    product_name = _select_value(values, "product_name") or linked_program.get("ProductName") or program_name
    product_version = _select_value(values, "product_version") or linked_program.get("ProductVersion")
    program_version = _select_value(values, "program_version") or linked_program.get("ProgramVersion") or product_version
    install_date = _select_value(values, "install_date") or linked_program.get("InstallDate")
    uninstall_date = _select_value(values, "uninstall_date") or linked_program.get("UninstallDate")
    binary_type = _select_value(values, "binary_type")
    if not binary_type and branch_kind == "driver":
        binary_type = "driver"
    if not binary_type and extension == ".dll":
        binary_type = "dll"
    is_os_component = _bool_string(_select_value(values, "is_os_component"))
    if is_os_component is None and file_path and "\\windows\\" in file_path.lower():
        is_os_component = "true"
    row = {
        "ArtifactType": "amcache_raw",
        "ParserStatus": "parsed_native",
        "ProgramId": program_id or linked_program.get("ProgramId"),
        "ProgramName": program_name,
        "ProgramVersion": program_version,
        "Publisher": publisher,
        "ProductName": product_name,
        "ProductVersion": product_version,
        "FileId": _select_value(values, "file_id") or _basename(key_path),
        "Path": file_path,
        "FileName": file_name,
        "LongPathHash": _select_value(values, "path_hash"),
        "SHA1": _select_value(values, "sha1"),
        "SHA256": _select_value(values, "sha256"),
        "MD5": _select_value(values, "md5"),
        "LinkDate": _select_value(values, "link_date"),
        "CompileTime": _select_value(values, "compile_time"),
        "InstallDate": install_date,
        "UninstallDate": uninstall_date,
        "Language": _select_value(values, "language"),
        "BinaryType": binary_type,
        "IsOsComponent": is_os_component,
        "KeyPath": key_path,
        "KeyLastWriteTimestamp": _iso_from_registry_timestamp(getattr(key, "timestamp", lambda: None)()),
        "SourceFile": source_file,
        "OriginalFileName": _select_value(values, "file_name"),
    }
    if file_path and not row["FileName"]:
        row["FileName"] = _basename(file_path)
    if branch_kind == "program" and not row["ProgramName"] and row["FileName"]:
        row["ProgramName"] = row["FileName"]
    if branch_kind == "driver" and row["BinaryType"] in (None, ""):
        row["BinaryType"] = "driver"
    if not _row_is_useful(row):
        return None
    return row


def _sample_record(row: dict) -> dict:
    return {
        "program_id": row.get("ProgramId"),
        "program_name": row.get("ProgramName"),
        "file_name": row.get("FileName"),
        "file_path": row.get("Path"),
        "publisher": row.get("Publisher"),
        "binary_type": row.get("BinaryType"),
        "key_path": row.get("KeyPath"),
        "key_last_write_time": row.get("KeyLastWriteTimestamp"),
    }


class AmcacheRawParser(BaseRawParser):
    parser_name = "amcache_raw"
    artifact_type = "amcache"

    def can_parse(self, candidate_or_path: object) -> bool:
        artifact_type = str(getattr(candidate_or_path, "artifact_type", "") or "")
        path = str(getattr(candidate_or_path, "original_path", candidate_or_path) or "")
        lower = path.lower()
        return artifact_type == "amcache" or lower.endswith("amcache.hve")

    def parse(self, path: Path, *, case_id: str, evidence_id: str, artifact_id: str, artifact_meta: dict) -> RawParserResult:
        from app.ingest.normalizer import normalize_row

        start = time.perf_counter()
        warnings: list[str] = []
        errors: list[str] = []
        events: list[dict] = []
        rows: list[dict] = []
        branch_counts: Counter[str] = Counter()
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
                artifact_type="amcache",
                source_path=normalized_source_path,
                records_read=0,
                events=[],
                warnings=warnings,
                errors=[f"amcache_dependency_or_open_failed: {exc}"],
                parser_status="failed_unsupported",
                metadata={
                    "parse_duration_ms": int((time.perf_counter() - start) * 1000),
                    "detected_amcache_files": 1,
                    "parser_selected": self.parser_name,
                    "records_extracted": 0,
                    "sample_records": [],
                    "warnings": warnings,
                    "errors": [f"amcache_dependency_or_open_failed: {exc}"],
                    "reason_if_zero_records": "amcache_dependency_or_open_failed",
                },
            )

        program_index = _build_program_index(registry_module, hive, normalized_source_path)
        missing_key_exc = getattr(registry_module, "RegistryKeyNotFoundException", Exception)
        seen_key_paths: set[str] = set()
        for branch in AMCACHE_PROGRAM_BRANCHES:
            try:
                branch_key = hive.open(branch)
            except missing_key_exc:
                warnings.append(f"missing_branch:{branch}")
                continue
            except Exception as exc:  # noqa: BLE001
                warnings.append(f"branch_open_failed:{branch}:{exc}")
                continue
            for key in _iter_registry_keys(branch_key):
                key_path = str(key.path())
                if key_path.rstrip("\\").lower() == branch.lower() or key_path in seen_key_paths:
                    continue
                seen_key_paths.add(key_path)
                row = _build_row_from_key(
                    key=key,
                    values=_extract_values(key),
                    branch_kind="program",
                    source_file=normalized_source_path,
                    program_index=program_index,
                )
                if not row:
                    continue
                branch_counts[_branch_root_name(key_path)] += 1
                rows.append(row)
                if len(sample_records) < 5:
                    sample_records.append(_sample_record(row))

        for branch, branch_kind in AMCACHE_FILE_BRANCHES:
            try:
                branch_key = hive.open(branch)
            except missing_key_exc:
                warnings.append(f"missing_branch:{branch}")
                continue
            except Exception as exc:  # noqa: BLE001
                warnings.append(f"branch_open_failed:{branch}:{exc}")
                continue
            for key in _iter_registry_keys(branch_key):
                key_path = str(key.path())
                if key_path.rstrip("\\").lower() == branch.lower() or key_path in seen_key_paths:
                    continue
                seen_key_paths.add(key_path)
                row = _build_row_from_key(
                    key=key,
                    values=_extract_values(key),
                    branch_kind=branch_kind,
                    source_file=normalized_source_path,
                    program_index=program_index,
                )
                if not row:
                    continue
                branch_counts[_branch_root_name(key_path)] += 1
                rows.append(row)
                if len(sample_records) < 5:
                    sample_records.append(_sample_record(row))

        for row in rows:
            try:
                document = normalize_row(
                    case_id,
                    evidence_id,
                    artifact_id,
                    row,
                    {
                        **artifact_meta,
                        "artifact_type": "amcache",
                        "name": artifact_meta.get("name") or "Amcache raw - Amcache.hve",
                        "parser": "amcache_raw",
                        "source_tool": "native_amcache",
                        "source_format": "registry_hive",
                        "source_path": normalized_source_path,
                        "velociraptor_original_path": original_source_path,
                        "velociraptor_normalized_windows_path": normalized_source_path,
                        "parser_processed_at": datetime.now(tz=UTC).isoformat(),
                    },
                )
                events.append(document)
            except Exception as exc:  # noqa: BLE001
                errors.append(f"normalize_failed:{row.get('KeyPath') or row.get('FileName') or 'unknown'}:{exc}")

        parser_status = "parsed_native" if events else "failed"
        if not rows and not errors:
            errors.append("amcache_parser_returned_empty")
        metadata = {
            "parse_duration_ms": int((time.perf_counter() - start) * 1000),
            "detected_amcache_files": 1,
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
            "amcache_files_seen": 1,
            "amcache_files_parsed": 1 if events else 0,
            "amcache_files_failed": 0 if events else 1,
            "amcache_events_indexed": len(events),
            "amcache_rows_extracted": len(rows),
            "amcache_branch_counts": dict(sorted(branch_counts.items())),
            "reason_if_zero_records": None if events else ("amcache_parser_returned_empty" if not errors else errors[0].split(":", 1)[0]),
        }
        result = RawParserResult(
            parser_name=self.parser_name,
            artifact_type="amcache",
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
