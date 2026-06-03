from collections import Counter
from datetime import UTC
from pathlib import Path
from urllib.parse import unquote
import importlib
import re
import time

from app.ingest.raw_parsers.audit import build_raw_parser_audit
from app.ingest.raw_parsers.base import BaseRawParser
from app.ingest.raw_parsers.models import RawParserResult
from app.ingest.velociraptor.path_utils import normalize_velociraptor_path


def windows_service_native_available() -> bool:
    try:
        importlib.import_module("Registry.Registry")
        return True
    except Exception:  # noqa: BLE001
        return False


def _load_registry_module():
    return importlib.import_module("Registry.Registry")


def _iso_from_datetime(value) -> str | None:
    if value is None:
        return None
    try:
        if value.tzinfo is None:
            value = value.replace(tzinfo=UTC)
        return value.isoformat()
    except Exception:  # noqa: BLE001
        return None


def _decode_path(value: object) -> str | None:
    if value in (None, "", "None"):
        return None
    decoded = unquote(str(value).strip()).replace("/", "\\")
    return decoded or None


def _stringify_value(value: object) -> str | None:
    if value in (None, "", b"", [], ()):
        return None
    if isinstance(value, bytes):
        return value.hex()
    if isinstance(value, (list, tuple)):
        items = [str(item).strip() for item in value if str(item).strip()]
        return "|".join(items) or None
    if isinstance(value, int):
        return str(value)
    text = str(value).strip()
    return text or None


def _registry_value_by_name(key, name: str):
    for value in key.values():
        try:
            if str(value.name() or "").lower() == name.lower():
                return value.value()
        except Exception:  # noqa: BLE001
            continue
    return None


def _subkey_by_name(key, name: str):
    for child in key.subkeys():
        try:
            if str(child.name() or "").lower() == name.lower():
                return child
        except Exception:  # noqa: BLE001
            continue
    return None


def _find_service_control_sets(hive) -> list[tuple[str, object]]:
    service_roots: list[tuple[str, object]] = []
    for root in hive.root().subkeys():
        name = str(root.name() or "")
        if not re.fullmatch(r"ControlSet\d{3}", name, flags=re.IGNORECASE):
            continue
        services_key = _subkey_by_name(root, "Services")
        if services_key is not None:
            service_roots.append((name, services_key))
    return service_roots


def _service_row(service_key, *, control_set: str, source_file: str, source_mtime: str | None) -> dict:
    values = {str(value.name() or ""): value.value() for value in service_key.values()}
    parameters_key = _subkey_by_name(service_key, "Parameters")
    service_name = str(service_key.name() or "")
    key_path = f"{control_set}\\Services\\{service_name}"
    row = {
        "ArtifactType": "service",
        "ParserStatus": "parsed_native",
        "ServiceName": service_name,
        "DisplayName": _stringify_value(values.get("DisplayName")),
        "Description": _stringify_value(values.get("Description")),
        "ImagePath": _decode_path(_stringify_value(values.get("ImagePath"))),
        "StartRaw": values.get("Start"),
        "Start": _stringify_value(values.get("Start")),
        "ServiceTypeRaw": values.get("Type"),
        "Type": _stringify_value(values.get("Type")),
        "ErrorControl": _stringify_value(values.get("ErrorControl")),
        "ObjectName": _stringify_value(values.get("ObjectName")),
        "Group": _stringify_value(values.get("Group")),
        "DependOnService": _stringify_value(values.get("DependOnService")),
        "DependOnGroup": _stringify_value(values.get("DependOnGroup")),
        "FailureActions": _stringify_value(values.get("FailureActions")),
        "RequiredPrivileges": _stringify_value(values.get("RequiredPrivileges")),
        "LaunchProtected": _stringify_value(values.get("LaunchProtected")),
        "ServiceSidType": _stringify_value(values.get("ServiceSidType")),
        "DelayedAutoStart": _stringify_value(values.get("DelayedAutoStart")),
        "TriggerInfo": _stringify_value(values.get("TriggerInfo")),
        "ServiceDll": _decode_path(_stringify_value(_registry_value_by_name(parameters_key, "ServiceDll"))) if parameters_key is not None else None,
        "KeyPath": key_path,
        "ControlSet": control_set,
        "SourceFile": source_file,
        "SourceMtime": source_mtime,
        "LastWriteTime": _iso_from_datetime(service_key.timestamp()),
        "TimestampInterpretation": "service_key_last_write" if service_key.timestamp() else "unknown",
    }
    return row


def _is_useful_service_row(row: dict) -> bool:
    service_name = str(row.get("ServiceName") or "").strip()
    useful_fields = (
        row.get("ImagePath"),
        row.get("ServiceDll"),
        row.get("DisplayName"),
        row.get("Type"),
        row.get("Start"),
    )
    has_signal = any(value not in (None, "", [], ()) for value in useful_fields)
    valid_name = bool(service_name and service_name.lower() not in {"parameters", "security", "enum", "performance"})
    return has_signal or valid_name


class WindowsServiceRawParser(BaseRawParser):
    parser_name = "windows_service_registry"
    artifact_type = "service"

    def can_parse(self, candidate_or_path: object) -> bool:
        artifact_type = str(getattr(candidate_or_path, "artifact_type", "") or "").lower()
        path = str(getattr(candidate_or_path, "original_path", candidate_or_path) or "").lower()
        normalized = normalize_velociraptor_path(path).lower()
        return artifact_type == "service" or normalized.endswith("windows\\system32\\config\\system")

    def parse(self, path: Path, *, case_id: str, evidence_id: str, artifact_id: str, artifact_meta: dict) -> RawParserResult:
        from app.ingest.normalizer import normalize_row

        start = time.perf_counter()
        warnings: list[str] = []
        errors: list[str] = []
        events: list[dict] = []
        rows: list[dict] = []
        control_sets_seen: list[str] = []
        sample_records: list[dict] = []
        start_types: Counter[str] = Counter()
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
                artifact_type="service",
                source_path=normalized_source_path,
                warnings=warnings,
                errors=[f"service_dependency_or_open_failed: {exc}"],
                parser_status="failed_unsupported",
                metadata={
                    "parser_selected": self.parser_name,
                    "detected_service_sources": 1,
                    "records_extracted": 0,
                    "sample_records": [],
                    "warnings": warnings,
                    "errors": [f"service_dependency_or_open_failed: {exc}"],
                    "reason_if_zero_records": "service_dependency_or_open_failed",
                    "parse_duration_ms": int((time.perf_counter() - start) * 1000),
                },
            )

        for control_set, services_key in _find_service_control_sets(hive):
            control_sets_seen.append(control_set)
            for service_key in services_key.subkeys():
                try:
                    row = _service_row(
                        service_key,
                        control_set=control_set,
                        source_file=normalized_source_path,
                        source_mtime=artifact_meta.get("mtime"),
                    )
                    if not _is_useful_service_row(row):
                        continue
                    rows.append(row)
                    start_types[str(row.get("Start") or "unknown")] += 1
                    if len(sample_records) < 5:
                        sample_records.append(
                            {
                                "service_name": row.get("ServiceName"),
                                "display_name": row.get("DisplayName"),
                                "image_path": row.get("ImagePath"),
                                "service_dll": row.get("ServiceDll"),
                                "start_type_raw": row.get("StartRaw"),
                                "key_path": row.get("KeyPath"),
                                "last_write": row.get("LastWriteTime"),
                                "parser_status": "parsed_native",
                            }
                        )
                except Exception as exc:  # noqa: BLE001
                    errors.append(f"service_row_failed:{control_set}:{service_key.name()}:{exc}")

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
                            "artifact_type": "service",
                            "name": artifact_meta.get("name") or "Windows Service raw - SYSTEM",
                            "parser": self.parser_name,
                            "source_tool": "native_windows_service",
                            "source_format": "registry_hive",
                            "source_path": normalized_source_path,
                            "velociraptor_original_path": original_source_path,
                            "velociraptor_normalized_windows_path": normalized_source_path,
                        },
                    )
                )
            except Exception as exc:  # noqa: BLE001
                errors.append(f"normalize_failed:{row.get('ServiceName') or 'unknown'}:{exc}")

        if not rows and not errors:
            errors.append("service_parser_returned_empty")

        for sample, event in zip(sample_records, events[: len(sample_records)], strict=False):
            sample["risk_score"] = event.get("risk_score")
            sample["tags"] = list(event.get("tags") or [])
            sample["suspicious_reasons"] = list(event.get("suspicious_reasons") or [])

        parser_status = "parsed_native" if events else "failed"
        metadata = {
            "parser_selected": self.parser_name,
            "detected_service_sources": 1,
            "records_extracted": len(rows),
            "records_parsed": len(rows),
            "records_failed": max(len(rows) - len(events), 0),
            "records_indexed": len(events),
            "service_events_indexed": len(events),
            "service_control_sets_seen": sorted(dict.fromkeys(control_sets_seen)),
            "service_start_type_counts": dict(sorted(start_types.items())),
            "sample_records": sample_records,
            "warnings": warnings,
            "errors": errors,
            "reason_if_zero_records": None if events else ("service_parser_returned_empty" if not errors else errors[0].split(":", 1)[0]),
            "parse_duration_ms": int((time.perf_counter() - start) * 1000),
        }
        result = RawParserResult(
            parser_name=self.parser_name,
            artifact_type="service",
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
