from collections import Counter
from datetime import UTC, datetime
from pathlib import Path
import time

from app.ingest.jumplists.raw_lnk import parse_shell_link_bytes
from app.ingest.velociraptor.path_utils import normalize_velociraptor_path
from app.ingest.raw_parsers.audit import build_raw_parser_audit
from app.ingest.raw_parsers.base import BaseRawParser
from app.ingest.raw_parsers.models import RawParserResult


def _iso_from_stat_timestamp(value: float | int | None) -> str | None:
    if value in (None, 0):
        return None
    try:
        return datetime.fromtimestamp(float(value), tz=UTC).isoformat()
    except Exception:  # noqa: BLE001
        return None


class LnkRawParser(BaseRawParser):
    parser_name = "lnk_raw"
    artifact_type = "lnk_raw"

    def can_parse(self, candidate_or_path: object) -> bool:
        path = getattr(candidate_or_path, "original_path", candidate_or_path)
        return str(path or "").lower().endswith(".lnk")

    def parse(self, path: Path, *, case_id: str, evidence_id: str, artifact_id: str, artifact_meta: dict) -> RawParserResult:
        from app.ingest.normalizer import normalize_row

        start = time.perf_counter()
        warnings: list[str] = []
        errors: list[str] = []
        events: list[dict] = []
        records_read = 0
        suspicious_counter = Counter()
        try:
            payload = path.read_bytes()
            stat = path.stat()
            original_source_path = str(artifact_meta.get("source_path") or path)
            normalized_source_path = str(artifact_meta.get("velociraptor_normalized_windows_path") or normalize_velociraptor_path(original_source_path) or original_source_path)
            parsed, parser_warnings = parse_shell_link_bytes(payload, stream_name=original_source_path)
            warnings.extend(parser_warnings)
            reliable_local_fs_times = Path(original_source_path).resolve() == path.resolve()
            source_created = _iso_from_stat_timestamp(getattr(stat, "st_birthtime", None)) if reliable_local_fs_times else None
            source_modified = _iso_from_stat_timestamp(stat.st_mtime) if reliable_local_fs_times else None
            source_accessed = _iso_from_stat_timestamp(stat.st_atime) if reliable_local_fs_times else None
            row = {
                "SourceFile": normalized_source_path,
                "OriginalSourceFile": original_source_path,
                "NormalizedWindowsPath": normalized_source_path,
                "TargetPath": parsed.get("TargetPath"),
                "TargetIDAbsolutePath": parsed.get("TargetIDAbsolutePath"),
                "LocalPath": parsed.get("LocalPath"),
                "CommonPath": parsed.get("CommonPath"),
                "RelativePath": parsed.get("RelativePath"),
                "WorkingDirectory": parsed.get("WorkingDirectory"),
                "Arguments": parsed.get("Arguments"),
                "IconLocation": parsed.get("IconLocation"),
                "Description": parsed.get("Description"),
                "NameString": parsed.get("Description"),
                "MachineID": parsed.get("MachineID"),
                "DriveType": parsed.get("DriveType"),
                "DriveSerialNumber": parsed.get("VolumeSerialNumber"),
                "VolumeLabel": parsed.get("VolumeLabel"),
                "NetworkPath": parsed.get("NetworkPath"),
                "NetName": parsed.get("ShareName"),
                "DeviceName": parsed.get("DeviceName"),
                "ShareName": parsed.get("ShareName"),
                "TrackerDroid": parsed.get("TrackerDroid"),
                "TrackerBirthDroid": parsed.get("TrackerBirthDroid"),
                "Droid": parsed.get("Droid"),
                "BirthDroid": parsed.get("BirthDroid"),
                "KnownFolderGuid": parsed.get("KnownFolderGuid"),
                "DarwinId": parsed.get("DarwinId"),
                "HasLinkTargetIdList": parsed.get("HasLinkTargetIdList"),
                "HasLinkInfo": parsed.get("HasLinkInfo"),
                "HasKnownFolderDataBlock": parsed.get("HasKnownFolderDataBlock"),
                "HasPropertyStoreDataBlock": parsed.get("HasPropertyStoreDataBlock"),
                "HasEnvironmentVariableDataBlock": parsed.get("HasEnvironmentVariableDataBlock"),
                "IsShellTarget": parsed.get("IsShellTarget"),
                "TargetCreated": parsed.get("TargetCreated"),
                "TargetModified": parsed.get("TargetModified"),
                "TargetAccessed": parsed.get("TargetAccessed"),
                "EnvironmentTarget": parsed.get("EnvironmentTarget"),
                "SourceCreated": source_created,
                "SourceModified": source_modified,
                "SourceAccessed": source_accessed,
                "SourceFileMtime": artifact_meta.get("mtime"),
                "SourceFileMtimeConfidence": "high" if reliable_local_fs_times and artifact_meta.get("mtime") else "low" if artifact_meta.get("mtime") else None,
                "FileSize": parsed.get("FileSize"),
                "FileAttributes": parsed.get("FileAttributes"),
                "MFTEntry": parsed.get("MFTEntry"),
                "MFTSequence": parsed.get("MFTSequence"),
                "ParseWarnings": "; ".join(parser_warnings) if parser_warnings else None,
            }
            records_read = 1
            document = normalize_row(
                case_id,
                evidence_id,
                artifact_id,
                row,
                {
                    **artifact_meta,
                    "artifact_type": "lnk",
                    "parser": "lnk_raw",
                    "source_tool": "native_lnk",
                    "source_format": "lnk",
                    "source_path": normalized_source_path,
                    "velociraptor_original_path": original_source_path,
                    "velociraptor_normalized_windows_path": normalized_source_path,
                    "source_file_mtime": artifact_meta.get("mtime"),
                    "source_file_mtime_confidence": "high" if reliable_local_fs_times and artifact_meta.get("mtime") else "low" if artifact_meta.get("mtime") else None,
                    "parser_processed_at": datetime.now(tz=UTC).isoformat(),
                },
            )
            events.append(document)
            suspicious_counter.update(document.get("tags") or [])
        except Exception as exc:  # noqa: BLE001
            errors.append(str(exc))
        result = RawParserResult(
            parser_name=self.parser_name,
            artifact_type="lnk",
            source_path=str(artifact_meta.get("source_path") or path),
            records_read=records_read,
            events=events,
            warnings=warnings,
            errors=errors,
            parser_status="parsed_native" if events else "failed",
            metadata={
                "parse_duration_ms": int((time.perf_counter() - start) * 1000),
                "lnk_files_seen": 1,
                "lnk_files_parsed": 1 if events else 0,
                "lnk_files_failed": len(errors),
                "lnk_events_indexed": len(events),
                "records_parsed": 1 if events else 0,
                "records_filtered": 0,
                "records_failed": len(errors),
                "records_skipped": 0,
                "records_unprocessed": 0,
                "suspicious_lnk_count": 1 if "suspicious" in suspicious_counter else 0,
                "missing_target_count": 1 if events and "missing_target_path" in (events[0].get("data_quality") or []) else 0,
                "network_path_count": 1 if events and "network_path" in set(events[0].get("tags") or []) else 0,
                "removable_path_count": 1 if events and "removable_media" in set(events[0].get("tags") or []) else 0,
                "startup_lnk_count": 1 if events and "startup_folder" in set(events[0].get("tags") or []) else 0,
                "cloud_path_count": 1 if events and "cloud_path" in set(events[0].get("tags") or []) else 0,
                "unresolved_target_count": 1 if events and "unresolved_lnk_target" in set(events[0].get("data_quality") or []) else 0,
                "partial_target_count": 1 if events and "partial_lnk_target" in set(events[0].get("data_quality") or []) else 0,
                "parse_warnings": warnings,
            },
        )
        result.metadata["audit"] = build_raw_parser_audit(result)
        return result
