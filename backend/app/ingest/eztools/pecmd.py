from collections import Counter
from datetime import UTC
import logging
from pathlib import Path
import re
from uuid import uuid4

from dateutil import parser as date_parser

from app.analysis.suspicious import detect_suspicious_path, detect_suspicious_powershell
from app.ingest.eztools.base import ArtifactParser, read_delimited_rows


logger = logging.getLogger(__name__)

PE_CMD_HEADER_HINTS = {
    "sourcefilename",
    "sourcefile",
    "filename",
    "executablename",
    "applicationname",
    "runcount",
    "lastrun",
    "lastruntime",
}
WINDOWS_EMPTY_VALUES = {"", "-", "--", "n/a", "na", "(null)", "null"}
LOLBIN_NAMES = {
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
    "schtasks.exe",
    "net.exe",
    "net1.exe",
    "whoami.exe",
    "nltest.exe",
    "ipconfig.exe",
    "netstat.exe",
    "nslookup.exe",
    "curl.exe",
    "wget.exe",
    "robocopy.exe",
    "xcopy.exe",
    "ftp.exe",
    "7z.exe",
    "rar.exe",
    "winrar.exe",
}


def _canonicalize_key(value: object) -> str:
    return re.sub(r"[^a-z0-9]+", "", str(value).strip().lower())


def _normalize_row_keys(row: dict) -> tuple[dict[str, object], dict[str, object]]:
    raw = {str(key): value for key, value in row.items()}
    lowered = {_canonicalize_key(key): value for key, value in raw.items()}
    return raw, lowered


def _get(lowered: dict[str, object], *names: str) -> str | None:
    for name in names:
        value = lowered.get(_canonicalize_key(name))
        if value not in (None, ""):
            return str(value)
    return None


def _normalize_value(value: object | None) -> str | None:
    if value is None:
        return None
    normalized = str(value).strip()
    if normalized.lower() in WINDOWS_EMPTY_VALUES:
        return None
    return normalized


def _parse_timestamp(value: object | None) -> str | None:
    normalized = _normalize_value(value)
    if not normalized:
        return None
    try:
        parsed = date_parser.parse(normalized)
        if parsed.tzinfo is None:
            parsed = parsed.replace(tzinfo=UTC)
        return parsed.isoformat()
    except Exception:  # noqa: BLE001
        return None


def _parse_int(value: object | None) -> int | None:
    normalized = _normalize_value(value)
    if not normalized:
        return None
    try:
        return int(normalized)
    except Exception:  # noqa: BLE001
        return None


def _basename(path: str | None) -> str | None:
    normalized = _normalize_value(path)
    if not normalized:
        return None
    return Path(normalized.replace("\\", "/")).name or None


def _split_multi_value(value: object | None) -> list[str]:
    normalized = _normalize_value(value)
    if not normalized:
        return []
    parts = [item.strip() for item in re.split(r"[;\n|,]+", normalized) if item.strip()]
    return list(dict.fromkeys(parts))


def _extract_runs(lowered: dict[str, object]) -> tuple[str | None, list[str]]:
    last_run = _parse_timestamp(_get(lowered, "LastRun", "LastRunTime"))
    previous_runs = []
    for index in range(8):
        parsed = _parse_timestamp(_get(lowered, f"PreviousRun{index}", f"LastRun{index}"))
        if parsed:
            previous_runs.append(parsed)
    previous_runs = sorted(dict.fromkeys(previous_runs))
    return last_run, previous_runs


def _infer_timestamp(lowered: dict[str, object]) -> tuple[str | None, str]:
    last_run, _ = _extract_runs(lowered)
    if last_run:
        return last_run, "last_run"
    modified = _parse_timestamp(_get(lowered, "Modified", "SourceModified"))
    if modified:
        return modified, "modified"
    created = _parse_timestamp(_get(lowered, "Created", "SourceCreated"))
    if created:
        return created, "created"
    return None, "unknown"


def _execution_name(lowered: dict[str, object]) -> str | None:
    return _normalize_value(
        _get(
            lowered,
            "ExecutableName",
            "ApplicationName",
            "Filename",
            "SourceFilename",
        )
    )


def _prefetch_file_path(lowered: dict[str, object]) -> str | None:
    return _normalize_value(_get(lowered, "SourceFile", "SourceFilename", "Path"))


def _infer_process_path(source_filename: str | None, referenced_files: list[str]) -> str | None:
    pf_path = _normalize_value(source_filename)
    if pf_path and pf_path.lower().endswith(".exe"):
        return pf_path
    for candidate in referenced_files:
        lower = candidate.lower()
        if lower.endswith(".exe") or lower.endswith(".dll") or lower.endswith(".ps1") or lower.endswith(".bat") or lower.endswith(".cmd"):
            return candidate
    return None


def _prefetch_base(case_id: str, evidence_id: str, artifact_id: str, source_file: str, raw_row: dict, artifact_meta: dict, timestamp: str | None, timestamp_type: str) -> dict:
    return {
        "event_id": str(uuid4()),
        "id": str(uuid4()),
        "case_id": case_id,
        "evidence_id": evidence_id,
        "artifact_id": artifact_id,
        "@timestamp": timestamp,
        "timestamp_precision": timestamp_type,
        "timezone": "UTC" if timestamp else "unknown",
        "host": {"name": artifact_meta.get("detected_host"), "hostname": artifact_meta.get("detected_host"), "ip": [], "os": "Windows"},
        "user": {"name": artifact_meta.get("detected_user"), "domain": None, "sid": None, "logon_id": None},
        "source": {"ip": None, "port": None, "hostname": None},
        "destination": {"ip": None, "port": None, "hostname": None},
        "artifact": {
            "type": "prefetch",
            "name": artifact_meta.get("name", source_file),
            "source_path": artifact_meta.get("source_path", source_file),
            "parser": artifact_meta.get("parser", "zimmerman"),
        },
        "event": {
            "category": "execution",
            "type": "process_executed",
            "action": "prefetch_execution_observed",
            "severity": "info",
            "message": artifact_meta.get("name", source_file),
            "timeline_include": True,
        },
        "process": {
            "pid": None,
            "name": None,
            "path": None,
            "command_line": None,
            "parent_pid": None,
            "parent_name": None,
            "parent_path": None,
            "parent_command_line": None,
            "integrity_level": None,
            "token_elevation": None,
        },
        "file": {"path": None, "name": None, "extension": None, "size": None, "hash_sha1": None, "hash_sha256": None, "sha1": None, "sha256": None, "md5": None},
        "execution": {"source": "prefetch", "run_count": None, "first_run": None, "last_run": None, "last_runs": [], "program_name": None, "confidence": None, "is_execution_confirmed": True, "interpretation": "Prefetch indicates program execution on Windows when Prefetch is enabled"},
        "prefetch": {
            "artifact_type": "prefetch",
            "source_file": None,
            "source_filename": None,
            "executable_name": None,
            "executable_path": None,
            "prefetch_hash": None,
            "hash": None,
            "run_count": None,
            "last_run": None,
            "last_runs": [],
            "previous_runs": [],
            "volume_serials": [],
            "volume_names": [],
            "volume_created_times": [],
            "volume_serial_number": None,
            "volume_device_path": None,
            "volume_creation_time": None,
            "volume_label": None,
            "referenced_files": [],
            "referenced_directories": [],
            "directories": [],
            "loaded_files_count": 0,
            "referenced_files_count": 0,
            "parse_warnings": [],
            "parser_status": "completed",
            "timestamp_interpretation": None,
            "file_size": None,
        },
        "windows": {"event_id": None, "channel": None, "provider": None, "computer": None, "record_number": None, "process_id": None, "thread_id": None, "event_data": {}, "payload": {}, "raw_xml": None, "logon_type": None, "service_name": None, "task_name": None},
        "network": {"protocol": None, "direction": None, "application": None, "bytes_sent": None, "bytes_received": None, "source_ip": None, "source_port": None, "destination_ip": None, "destination_port": None, "share_name": None, "share_local_path": None, "relative_target_name": None},
        "task": {"name": None, "path": None, "command": None, "arguments": None, "author": None, "run_as": None, "trigger": None, "enabled": None, "content": None, "working_directory": None, "action": None},
        "service": {"name": None, "display_name": None, "image_path": None, "start_type": None, "service_type": None, "account": None},
        "detection": {"threat_name": None, "threat_id": None, "severity": None, "category": None, "action": None, "path": None, "error_code": None},
        "tags": ["execution", "prefetch"],
        "data_quality": [],
        "risk_score": 0,
        "raw_summary": "",
        "search_text": "",
        "raw": raw_row,
        "suspicious_reasons": [],
        "source_file": source_file,
        "source_tool": "pecmd",
        "source_format": "csv",
    }


def _risk_score(tags: set[str], suspicious_reasons: list[str], run_count: int | None) -> tuple[int, str]:
    score = 20
    if run_count and run_count >= 5:
        score += 5
    if suspicious_reasons:
        score += 20
    if "lolbin" in tags:
        score += 15
    if "powershell" in tags:
        score += 10
    if "suspicious_path" in tags:
        score += 10
    if score >= 70:
        return score, "high"
    if score >= 45:
        return score, "medium"
    if score >= 25:
        return score, "low"
    return score, "info"


def _build_search_text(document: dict) -> str:
    values = [
        document.get("source_file"),
        (document.get("process") or {}).get("name"),
        (document.get("process") or {}).get("path"),
        (document.get("file") or {}).get("path"),
        (document.get("file") or {}).get("name"),
        (document.get("event") or {}).get("message"),
        (document.get("execution") or {}).get("run_count"),
        (document.get("prefetch") or {}).get("source_filename"),
        (document.get("prefetch") or {}).get("executable_name"),
        " ".join((document.get("prefetch") or {}).get("referenced_files") or []),
        " ".join((document.get("prefetch") or {}).get("directories") or []),
        " ".join(document.get("suspicious_reasons") or []),
    ]
    return " | ".join(str(value).strip() for value in values if value not in (None, "", []))[:8192]


def _build_raw_summary(process_name: str | None, process_path: str | None, run_count: int | None, timestamp: str | None) -> str:
    parts = [
        f"Executable={process_name}" if process_name else None,
        f"Path={process_path}" if process_path else None,
        f"RunCount={run_count}" if run_count is not None else None,
        f"LastRun={timestamp}" if timestamp else None,
    ]
    return " | ".join(item for item in parts if item)[:2000]


def _prefetch_tags_and_reasons(process_name: str | None, process_path: str | None, referenced_files: list[str]) -> tuple[set[str], list[str]]:
    tags: set[str] = {"execution", "prefetch"}
    reasons: list[str] = []
    normalized_name = str(process_name or "").lower()
    if normalized_name in LOLBIN_NAMES:
        tags.update({"suspicious", "lolbin"})
        reasons.append(f"Execution of LOLBin: {process_name}")
    if normalized_name in {"powershell.exe", "pwsh.exe"}:
        tags.update({"powershell", "script"})
    reasons.extend(f"Suspicious path: {reason}" for reason in detect_suspicious_path(process_path))
    for item in referenced_files[:25]:
        item_reasons = detect_suspicious_path(item)
        if item_reasons:
            tags.update({"suspicious", "suspicious_path"})
            reasons.extend(f"Referenced file path: {reason}" for reason in item_reasons)
        lowered = item.lower()
        if any(token in lowered for token in ["powershell", "pwsh", "cmd.exe", "wscript", "cscript", "mshta", "rundll32", "regsvr32", "certutil", "bitsadmin"]):
            tags.add("lolbin")
    if process_path and detect_suspicious_path(process_path):
        tags.update({"suspicious", "suspicious_path"})
    ps_reasons = detect_suspicious_powershell(process_path) if process_path else []
    if ps_reasons:
        tags.update({"suspicious", "powershell"})
        reasons.extend(f"PowerShell indicator in path: {reason}" for reason in ps_reasons)
    return tags, sorted(set(reasons))


def parse_pecmd_file(case_id: str, evidence_id: str, artifact_id: str, path: Path, artifact_meta: dict) -> list[dict]:
    rows = read_delimited_rows(path)
    documents: list[dict] = []
    audit = {
        "artifact": path.name,
        "parser": "pecmd",
        "records_read": len(rows),
        "records_parsed": 0,
        "events_indexed": 0,
        "missing_timestamp": 0,
        "missing_executable_name": 0,
        "suspicious_count": 0,
        "lolbin_count": 0,
        "top_executables": {},
        "top_run_count": {},
        "bulk_index_errors": 0,
        "top_errors": [],
    }
    executable_counts: Counter[str] = Counter()
    run_counts: Counter[str] = Counter()

    for row in rows:
        raw_row, lowered = _normalize_row_keys(row)
        timestamp, timestamp_type = _infer_timestamp(lowered)
        last_run, previous_runs = _extract_runs(lowered)
        process_name = _execution_name(lowered)
        pf_path = _prefetch_file_path(lowered)
        referenced_files = _split_multi_value(_get(lowered, "FilesLoaded", "ReferencedFiles"))
        directories = _split_multi_value(_get(lowered, "Directories"))
        process_path = _infer_process_path(pf_path, referenced_files)
        run_count = _parse_int(_get(lowered, "RunCount"))
        if not timestamp:
            audit["missing_timestamp"] += 1
        if not process_name:
            audit["missing_executable_name"] += 1
        tags, suspicious_reasons = _prefetch_tags_and_reasons(process_name, process_path, referenced_files)
        if suspicious_reasons:
            audit["suspicious_count"] += 1
        if "lolbin" in tags:
            audit["lolbin_count"] += 1
        if process_name:
            executable_counts[process_name.upper()] += 1
        if process_name and run_count is not None:
            run_counts[f"{process_name.upper()}:{run_count}"] += 1

        document = _prefetch_base(case_id, evidence_id, artifact_id, path.name, raw_row, artifact_meta, timestamp, timestamp_type)
        document["event"]["message"] = (
            f"Prefetch execution observed: {process_name or 'unknown executable'}"
            + (f" last run {last_run}" if last_run else "")
            + (f" (run count {run_count})" if run_count is not None else "")
        )
        document["process"]["name"] = process_name
        document["process"]["path"] = process_path
        document["file"]["path"] = process_path
        document["file"]["name"] = _basename(process_path) or process_name
        document["file"]["extension"] = Path(process_path).suffix.lower() if process_path else ".exe" if process_name and str(process_name).lower().endswith(".exe") else None
        document["file"]["source_path"] = pf_path
        document["file"]["size"] = _parse_int(_get(lowered, "FileSize"))
        document["execution"].update(
            {
                "run_count": run_count,
                "last_run": last_run,
                "last_runs": previous_runs,
                "program_name": process_name,
                "confidence": "high" if timestamp and process_name and run_count and run_count > 0 else "medium" if process_name else "low",
                "is_execution_confirmed": True,
                "interpretation": "Prefetch indicates program execution on Windows when Prefetch is enabled",
            }
        )
        document["prefetch"].update(
            {
                "source_file": pf_path,
                "source_filename": pf_path,
                "executable_name": process_name,
                "executable_path": process_path,
                "prefetch_hash": _normalize_value(_get(lowered, "Hash")),
                "hash": _normalize_value(_get(lowered, "Hash")),
                "run_count": run_count,
                "last_run": last_run,
                "last_runs": previous_runs,
                "previous_runs": previous_runs,
                "volume_serial_number": _normalize_value(_get(lowered, "Volume0Serial")),
                "volume_device_path": _normalize_value(_get(lowered, "Volume0Name")),
                "volume_creation_time": _parse_timestamp(_get(lowered, "Volume0Created")),
                "volume_label": None,
                "volume_serials": [
                    value
                    for value in [
                        _normalize_value(_get(lowered, "Volume0Serial")),
                        _normalize_value(_get(lowered, "Volume1Serial")),
                    ]
                    if value
                ],
                "volume_names": [
                    value
                    for value in [
                        _normalize_value(_get(lowered, "Volume0Name")),
                        _normalize_value(_get(lowered, "Volume1Name")),
                    ]
                    if value
                ],
                "volume_created_times": [
                    value
                    for value in [
                        _parse_timestamp(_get(lowered, "Volume0Created")),
                        _parse_timestamp(_get(lowered, "Volume1Created")),
                    ]
                    if value
                ],
                "referenced_files": referenced_files,
                "referenced_directories": directories,
                "directories": directories,
                "loaded_files_count": len(referenced_files),
                "referenced_files_count": len(referenced_files),
                "file_size": _parse_int(_get(lowered, "FileSize")),
            }
        )
        document["tags"] = sorted(tags)
        document["suspicious_reasons"] = suspicious_reasons
        document["raw_summary"] = _build_raw_summary(process_name, process_path or pf_path, run_count, last_run or timestamp)
        document["event"]["timeline_include"] = True
        if timestamp_type == "unknown":
            document["data_quality"].append("missing_timestamp")
        if not process_name:
            document["data_quality"].append("missing_executable_name")
        score, severity = _risk_score(tags, suspicious_reasons, run_count)
        document["risk_score"] = score
        document["event"]["severity"] = severity
        document["search_text"] = _build_search_text(document)
        documents.append(document)

    audit["records_parsed"] = len(documents)
    audit["events_indexed"] = len(documents)
    audit["top_executables"] = dict(executable_counts.most_common(10))
    audit["top_run_count"] = dict(run_counts.most_common(10))
    artifact_meta["ingest_audit"] = audit
    return documents


class PECmdParser(ArtifactParser):
    def can_parse(self, path: Path, headers: list[str] | None = None) -> bool:
        lower_name = path.name.lower()
        if "pecmd_output.csv" in lower_name or lower_name.endswith("_pecmd_output.csv") or "pecmd" in lower_name:
            return True
        normalized_headers = {_canonicalize_key(header) for header in (headers or []) if header}
        return len(PE_CMD_HEADER_HINTS & normalized_headers) >= 3 and any(header in normalized_headers for header in {"executablename", "applicationname"})

    def parse(self, path: Path, **kwargs):
        return parse_pecmd_file(
            kwargs["case_id"],
            kwargs["evidence_id"],
            kwargs["artifact_id"],
            path,
            kwargs["artifact_meta"],
        )
