from __future__ import annotations

import csv
from functools import lru_cache
import heapq
from pathlib import Path
import re
import shutil
import subprocess
import tempfile
import time
from typing import Iterable

from app.core.config import get_settings
from app.ingest.eztools.base import ensure_csv_field_limit
from app.ingest.eztools.mftecmd import get_mftecmd_profile, iter_mftecmd_batches, reset_mftecmd_profile


MFTECMD_BACKEND_CSV = "mftecmd_csv"
MFT_SUMMARY_CSV_NAME = "MFTECmd_MFT_Summary.csv"
KNOWN_CASE_TERMS = {
    "script.ps1",
    "maintenance.ps1",
    "psexec",
    "psexesvc",
    "encrypted",
    "duckdns",
    "rundll32",
    "cylr",
    "dumpit",
    "kape",
}
SUSPICIOUS_EXTENSIONS = {
    ".exe",
    ".dll",
    ".ps1",
    ".bat",
    ".cmd",
    ".vbs",
    ".vbe",
    ".js",
    ".jse",
    ".wsf",
    ".hta",
    ".lnk",
    ".scr",
    ".pif",
    ".msi",
    ".iso",
    ".zip",
    ".7z",
    ".rar",
    ".cab",
}
HIGH_VALUE_PATH_PATTERNS = {
    "user_public_path": re.compile(r"\\users\\public(\\|$)", re.I),
    "downloads_path": re.compile(r"\\users\\[^\\]+\\downloads(\\|$)", re.I),
    "desktop_path": re.compile(r"\\users\\[^\\]+\\desktop(\\|$)", re.I),
    "appdata_path": re.compile(r"\\users\\[^\\]+\\appdata(\\|$)", re.I),
    "temp_path": re.compile(r"(\\temp\\|\\temporary internet files\\|\\tmp\\)", re.I),
    "programdata_path": re.compile(r"\\programdata(\\|$)", re.I),
    "startup_path": re.compile(r"\\startup(\\|$)", re.I),
    "tasks_path": re.compile(r"\\tasks(\\|$)", re.I),
    "recycle_bin_path": re.compile(r"\\\$recycle\\.bin(\\|$)", re.I),
}
SUMMARY_EXCLUDED_COLUMNS = {
    "residentdatabase64",
    "residentdatahex",
    "residentdataascii",
}


def _mftecmd_dll_path() -> Path:
    settings = get_settings()
    return Path(getattr(settings, "mftecmd_dotnet_dll", "") or "/opt/eztools/MFTECmd/MFTECmd.dll")


def _mftecmd_command() -> list[str] | None:
    dotnet = shutil.which("dotnet")
    dll_path = _mftecmd_dll_path()
    if dotnet and dll_path.exists():
        return [dotnet, str(dll_path)]
    for name in ("MFTECmd", "mftecmd"):
        binary = shutil.which(name)
        if binary:
            return [binary]
    return None


@lru_cache(maxsize=1)
def detect_mftecmd_backend() -> dict:
    command = _mftecmd_command()
    result = {
        "backend": MFTECMD_BACKEND_CSV,
        "available": bool(command),
        "path": " ".join(command or []),
        "version": "",
        "error": None,
    }
    if not command:
        result["error"] = "MFTECmd command not available"
        return result
    try:
        completed = subprocess.run([*command, "--version"], capture_output=True, text=True, timeout=12, check=False)
        output = (completed.stdout or completed.stderr or "").strip()
        result["version"] = output.splitlines()[0].strip() if output else ""
        if completed.returncode != 0:
            result["error"] = output[:1000] or f"exit_{completed.returncode}"
    except Exception as exc:  # noqa: BLE001
        result["available"] = False
        result["error"] = str(exc)
    return result


def _run_mftecmd_csv(source_path: Path, output_dir: Path, output_name: str) -> subprocess.CompletedProcess[str]:
    command = _mftecmd_command()
    if not command:
        raise RuntimeError("MFTECmd command not available")
    settings = get_settings()
    timeout = max(int(getattr(settings, "mftecmd_timeout_seconds", 0) or 0), 0) or None
    return subprocess.run(
        [*command, "-f", str(source_path), "--csv", str(output_dir), "--csvf", output_name],
        check=False,
        capture_output=True,
        text=True,
        timeout=timeout,
    )


def _count_csv_records(path: Path) -> int:
    with path.open("rb") as handle:
        line_count = sum(1 for _ in handle)
    return max(line_count - 1, 0)


def _canonicalize_key(value: object) -> str:
    return re.sub(r"[^a-z0-9]+", "", str(value or "").strip().lower())


def _lowered_row(row: dict) -> dict[str, object]:
    return {_canonicalize_key(key): value for key, value in row.items()}


def _get(row: dict, *names: str, lowered: dict[str, object] | None = None) -> str:
    lowered = lowered if lowered is not None else _lowered_row(row)
    for name in names:
        value = lowered.get(_canonicalize_key(name))
        if value not in (None, ""):
            return str(value)
    return ""


def _row_path(row: dict, lowered: dict[str, object] | None = None) -> str:
    full_path = _get(row, "FullPath", "Path", lowered=lowered)
    if full_path:
        return full_path
    parent = _get(row, "ParentPath", "DirectoryPath", "FolderPath", lowered=lowered)
    name = _get(row, "FileName", "Name", lowered=lowered)
    if parent and name:
        parent = parent.rstrip("\\/")
        return parent + "\\" + name
    return name or parent


def _row_extension(row: dict, path: str, lowered: dict[str, object] | None = None) -> str:
    extension = _get(row, "Extension", lowered=lowered).strip().lower()
    if extension and not extension.startswith("."):
        extension = f".{extension}"
    if extension:
        return extension
    suffix = Path(path.replace("\\", "/")).suffix.lower()
    return suffix


def score_mft_summary_row(row: dict, lowered: dict[str, object] | None = None, path: str | None = None) -> tuple[int, list[str]]:
    lowered = lowered if lowered is not None else _lowered_row(row)
    path = path if path is not None else _row_path(row, lowered=lowered)
    text = " ".join(str(value or "") for value in [path, _get(row, "FileName", lowered=lowered), _get(row, "Extension", lowered=lowered)]).lower()
    extension = _row_extension(row, path, lowered=lowered)
    reasons: list[str] = []
    score = 0
    for term in KNOWN_CASE_TERMS:
        if term in text:
            reasons.append("known_case_indicator")
            score = max(score, 95)
            break
    if extension in SUSPICIOUS_EXTENSIONS:
        reasons.append("suspicious_extension")
        score = max(score, 70)
    normalized_path = path.replace("/", "\\")
    for reason, pattern in HIGH_VALUE_PATH_PATTERNS.items():
        if pattern.search(normalized_path):
            reasons.append(reason)
            score = max(score, 55)
            break
    in_use = _get(row, "InUse", lowered=lowered).strip().lower()
    deleted = _get(row, "IsDeleted", "Deleted", lowered=lowered).strip().lower()
    if in_use == "false" or deleted in {"true", "1", "yes"}:
        reasons.append("deleted_entry")
        score = max(score, 80)
    timestamp_blob = " ".join(
        _get(row, field, lowered=lowered)
        for field in (
            "Created0x10",
            "LastModified0x10",
            "LastRecordChange0x10",
            "LastAccess0x10",
            "Created0x30",
            "LastModified0x30",
            "LastRecordChange0x30",
            "LastAccess0x30",
        )
    )
    if "2024-03-22" in timestamp_blob:
        reasons.append("incident_window")
        score = max(score, 50)
    if "\\users\\" in normalized_path.lower() and "user_profile_path" not in reasons:
        reasons.append("user_profile_path")
        score = max(score, 35)
    return score, list(dict.fromkeys(reasons))


def _select_high_value_csv_rows(csv_path: Path, selected_path: Path, max_records: int) -> dict:
    ensure_csv_field_limit()
    started = time.perf_counter()
    heap: list[tuple[int, int, dict]] = []
    source_hits = {term.replace(".", "_").replace("-", "_"): 0 for term in KNOWN_CASE_TERMS}
    records_total = 0
    with csv_path.open("r", encoding="utf-8-sig", errors="ignore", newline="") as handle:
        sample = handle.read(4096)
        handle.seek(0)
        try:
            dialect = csv.Sniffer().sniff(sample, delimiters=",;\t|") if sample.strip() else csv.excel
        except csv.Error:
            dialect = csv.excel
        reader = csv.DictReader(handle, dialect=dialect)
        fieldnames = [field for field in (reader.fieldnames or []) if field and _canonicalize_key(field) not in SUMMARY_EXCLUDED_COLUMNS]
        for index, row in enumerate(reader):
            records_total += 1
            lowered = _lowered_row(row)
            path = _row_path(row, lowered=lowered)
            path_text = f"{path} {_get(row, 'FileName', lowered=lowered)}".lower()
            for term in KNOWN_CASE_TERMS:
                if term in path_text:
                    source_hits[term.replace(".", "_").replace("-", "_")] += 1
            score, reasons = score_mft_summary_row(row, lowered=lowered, path=path)
            selected = {key: value for key, value in row.items() if _canonicalize_key(key) not in SUMMARY_EXCLUDED_COLUMNS}
            selected["SummaryScore"] = str(score)
            selected["SummaryReasons"] = ";".join(reasons)
            item = (score, index, selected)
            if len(heap) < max_records:
                heapq.heappush(heap, item)
            elif item > heap[0]:
                heapq.heapreplace(heap, item)
    selected_rows = [item[2] for item in sorted(heap, key=lambda item: (-item[0], item[1]))]
    output_fields = list(dict.fromkeys([*(fieldnames or []), "SummaryScore", "SummaryReasons"]))
    with selected_path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=output_fields, extrasaction="ignore")
        writer.writeheader()
        writer.writerows(selected_rows)
    return {
        "records_total": records_total,
        "records_selected": len(selected_rows),
        "source_hits": source_hits,
        "selection_strategy": "score_top_n_high_value_rows",
        "csv_scan_seconds": round(time.perf_counter() - started, 2),
    }


def _prepare_full_csv_rows(csv_path: Path, full_path: Path) -> dict:
    ensure_csv_field_limit()
    started = time.perf_counter()
    source_hits = {term.replace(".", "_").replace("-", "_"): 0 for term in KNOWN_CASE_TERMS}
    records_total = 0
    with csv_path.open("r", encoding="utf-8-sig", errors="ignore", newline="") as handle:
        sample = handle.read(4096)
        handle.seek(0)
        try:
            dialect = csv.Sniffer().sniff(sample, delimiters=",;\t|") if sample.strip() else csv.excel
        except csv.Error:
            dialect = csv.excel
        reader = csv.DictReader(handle, dialect=dialect)
        fieldnames = [field for field in (reader.fieldnames or []) if field and _canonicalize_key(field) not in SUMMARY_EXCLUDED_COLUMNS]
        output_fields = list(dict.fromkeys([*(fieldnames or []), "SummaryScore", "SummaryReasons"]))
        with full_path.open("w", encoding="utf-8", newline="") as output:
            writer = csv.DictWriter(output, fieldnames=output_fields, extrasaction="ignore")
            writer.writeheader()
            for row in reader:
                records_total += 1
                lowered = _lowered_row(row)
                path = _row_path(row, lowered=lowered)
                path_text = f"{path} {_get(row, 'FileName', lowered=lowered)}".lower()
                for term in KNOWN_CASE_TERMS:
                    if term in path_text:
                        source_hits[term.replace(".", "_").replace("-", "_")] += 1
                score, reasons = score_mft_summary_row(row, lowered=lowered, path=path)
                selected = {key: value for key, value in row.items() if _canonicalize_key(key) not in SUMMARY_EXCLUDED_COLUMNS}
                selected["SummaryScore"] = str(score)
                selected["SummaryReasons"] = ";".join(reasons)
                writer.writerow(selected)
    return {
        "records_total": records_total,
        "records_selected": records_total,
        "source_hits": source_hits,
        "selection_strategy": "full_mft_all_rows_with_scoring",
        "csv_scan_seconds": round(time.perf_counter() - started, 2),
    }


def _resolve_mftecmd_csv(raw_mft_path: Path) -> tuple[Path, float]:
    cache_path = raw_mft_path.parent / MFT_SUMMARY_CSV_NAME
    mftecmd_started = time.perf_counter()
    if cache_path.exists() and cache_path.stat().st_mtime >= raw_mft_path.stat().st_mtime:
        return cache_path, 0.0
    completed = _run_mftecmd_csv(raw_mft_path, raw_mft_path.parent, MFT_SUMMARY_CSV_NAME)
    mftecmd_seconds = round(time.perf_counter() - mftecmd_started, 2)
    if completed.returncode != 0:
        message = (completed.stderr or completed.stdout or f"MFTECmd exited {completed.returncode}").strip()
        raise RuntimeError(message[:2000])
    csv_path = cache_path
    if not csv_path.exists():
        matches = sorted(raw_mft_path.parent.glob("*.csv"))
        if not matches:
            raise RuntimeError("MFTECmd did not produce CSV output")
        csv_path = matches[0]
    return csv_path, mftecmd_seconds


def iter_mftecmd_raw_summary_batches(
    *,
    raw_mft_path: Path,
    case_id: str,
    evidence_id: str,
    artifact_id: str,
    artifact_meta: dict,
    batch_size: int,
    max_records: int,
    max_seconds: int,
    fast_path: bool = True,
) -> Iterable[tuple[list[dict], dict]]:
    started = time.perf_counter()
    with tempfile.TemporaryDirectory(prefix="mftecmd-summary-") as tmp:
        tmp_dir = Path(tmp)
        csv_path, mftecmd_seconds = _resolve_mftecmd_csv(raw_mft_path)
        selected_csv_path = tmp_dir / "MFTECmd_MFT_Summary_Selected.csv"
        selection = _select_high_value_csv_rows(csv_path, selected_csv_path, max(int(max_records), 1))
        records_total = int(selection["records_total"])
        records_selected = int(selection["records_selected"])
        row_started = time.perf_counter()
        limits = {
            "max_records": int(max_records),
            "max_seconds": int(max_seconds),
            "batch_size": int(batch_size),
        }
        records_indexed = 0
        partial_reason = None
        reset_mftecmd_profile()
        csv_meta = {
            **artifact_meta,
            "artifact_type": "mft",
            "parser": MFTECMD_BACKEND_CSV,
            "source_tool": "mftecmd",
            "source_format": "csv",
            "mft_raw_source_path": str(raw_mft_path),
        }
        for batch in iter_mftecmd_batches(
            case_id,
            evidence_id,
            artifact_id,
            selected_csv_path,
            csv_meta,
            batch_size=max(int(batch_size), 1),
            fast_path=fast_path,
        ):
            if max_seconds and time.perf_counter() - row_started >= max_seconds:
                partial_reason = "max_seconds_reached"
                break
            if max_records and records_indexed + len(batch) > max_records:
                batch = batch[: max(max_records - records_indexed, 0)]
                partial_reason = "max_records_reached"
            if not batch:
                break
            records_indexed += len(batch)
            yield batch, {
                "records_total": records_total,
                "records_indexed": records_indexed,
                "records_skipped": max(records_total - records_indexed, 0),
                "coverage_status": "partial_summary" if partial_reason or records_indexed < records_total else "full_summary",
                "partial_reason": partial_reason,
                "limits": limits,
                "elapsed_seconds": round(time.perf_counter() - started, 2),
                "phase_timings": {
                    "mftecmd_seconds": mftecmd_seconds,
                    "csv_scan_seconds": selection["csv_scan_seconds"],
                    "scoring_seconds": selection["csv_scan_seconds"],
                    "normalization_seconds": round(time.perf_counter() - row_started, 2),
                    "indexing_seconds": round(time.perf_counter() - row_started, 2),
                    **get_mftecmd_profile(),
                },
                "backend": MFTECMD_BACKEND_CSV,
                "backend_version": detect_mftecmd_backend().get("version") or "",
                "csv_output": csv_path.name,
                "selection_strategy": selection["selection_strategy"],
                "source_hits": selection["source_hits"],
                "records_selected": records_selected,
            }
            if partial_reason:
                break


def iter_mftecmd_raw_full_batches(
    *,
    raw_mft_path: Path,
    case_id: str,
    evidence_id: str,
    artifact_id: str,
    artifact_meta: dict,
    batch_size: int,
    max_records: int | None = None,
    max_seconds: int = 0,
    fast_path: bool = True,
) -> Iterable[tuple[list[dict], dict]]:
    started = time.perf_counter()
    with tempfile.TemporaryDirectory(prefix="mftecmd-full-") as tmp:
        tmp_dir = Path(tmp)
        csv_path, mftecmd_seconds = _resolve_mftecmd_csv(raw_mft_path)
        full_csv_path = tmp_dir / "MFTECmd_MFT_Full_Selected.csv"
        selection = _prepare_full_csv_rows(csv_path, full_csv_path)
        records_total = int(selection["records_total"])
        limit_records = max(int(max_records or 0), 0)
        row_started = time.perf_counter()
        limits = {
            "max_records": limit_records or None,
            "max_seconds": int(max_seconds),
            "batch_size": int(batch_size),
        }
        records_indexed = 0
        partial_reason = None
        reset_mftecmd_profile()
        csv_meta = {
            **artifact_meta,
            "artifact_type": "mft",
            "parser": MFTECMD_BACKEND_CSV,
            "source_tool": "mftecmd",
            "source_format": "csv",
            "mft_raw_source_path": str(raw_mft_path),
            "mft_index_mode": "full",
        }
        for batch in iter_mftecmd_batches(
            case_id,
            evidence_id,
            artifact_id,
            full_csv_path,
            csv_meta,
            batch_size=max(int(batch_size), 1),
            fast_path=fast_path,
        ):
            if max_seconds and time.perf_counter() - row_started >= max_seconds:
                partial_reason = "max_seconds_reached"
                break
            if limit_records and records_indexed + len(batch) > limit_records:
                batch = batch[: max(limit_records - records_indexed, 0)]
                partial_reason = "max_records_reached"
            if not batch:
                break
            records_indexed += len(batch)
            yield batch, {
                "records_total": records_total,
                "records_indexed": records_indexed,
                "records_skipped": max(records_total - records_indexed, 0),
                "coverage_status": "partial_full" if partial_reason or records_indexed < records_total else "full",
                "partial_reason": partial_reason,
                "limits": limits,
                "elapsed_seconds": round(time.perf_counter() - started, 2),
                "phase_timings": {
                    "mftecmd_seconds": mftecmd_seconds,
                    "csv_scan_seconds": selection["csv_scan_seconds"],
                    "scoring_seconds": selection["csv_scan_seconds"],
                    "normalization_seconds": round(time.perf_counter() - row_started, 2),
                    "indexing_seconds": round(time.perf_counter() - row_started, 2),
                    **get_mftecmd_profile(),
                },
                "backend": MFTECMD_BACKEND_CSV,
                "backend_version": detect_mftecmd_backend().get("version") or "",
                "csv_output": csv_path.name,
                "selection_strategy": selection["selection_strategy"],
                "source_hits": selection["source_hits"],
                "records_selected": records_total,
            }
            if partial_reason:
                break
