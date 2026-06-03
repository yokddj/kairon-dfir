from __future__ import annotations

from collections import Counter
from functools import lru_cache
import hashlib
from pathlib import Path
import re
import shutil
import subprocess
import time

from app.core.config import get_settings
from app.core.storage import build_evidence_root, evidence_staging_dir, sanitize_relative_path
from app.ingest.eztools.recmd import parse_recmd_file
from app.ingest.identity_extraction import extract_user_from_path, is_valid_username


RECMD_BACKEND_CSV = "recmd_csv"
RECMD_USER_ACTIVITY_BATCH = "UserActivity.reb"
USER_ACTIVITY_ARTIFACT_TYPES = {"shellbag", "userassist", "recentdocs", "runmru", "opensavemru"}

_PARSER_TO_ARTIFACT_TYPE = {
    "shellbags_registry": "shellbag",
    "userassist_registry": "userassist",
    "recent_docs_registry": "recentdocs",
    "run_mru_registry": "runmru",
    "opensave_mru_registry": "opensavemru",
}
_ARTIFACT_TYPE_TO_LABEL = {
    "shellbag": "Shellbags",
    "userassist": "UserAssist",
    "recentdocs": "RecentDocs",
    "runmru": "RunMRU",
    "opensavemru": "OpenSaveMRU",
}
_USER_HIVE_RE = re.compile(r"(^|/|\\)users(/|\\)([^/\\]+)(/|\\)", re.I)


def _recmd_dll_path() -> Path:
    settings = get_settings()
    return Path(getattr(settings, "recmd_dotnet_dll", "") or "/opt/eztools/RECmd/RECmd.dll")


def _recmd_root() -> Path:
    dll_path = _recmd_dll_path()
    return dll_path.parent if dll_path.name.lower().endswith(".dll") else dll_path.parent


def _recmd_command() -> list[str] | None:
    dotnet = shutil.which("dotnet")
    dll_path = _recmd_dll_path()
    if dotnet and dll_path.exists():
        return [dotnet, str(dll_path)]
    for name in ("RECmd", "recmd"):
        binary = shutil.which(name)
        if binary:
            return [binary]
    return None


def _recmd_batch_path() -> Path:
    root = _recmd_root()
    candidates = [
        root / "BatchExamples" / RECMD_USER_ACTIVITY_BATCH,
        root / "RECmd" / "BatchExamples" / RECMD_USER_ACTIVITY_BATCH,
        Path("/opt/eztools/RECmd/RECmd/BatchExamples") / RECMD_USER_ACTIVITY_BATCH,
    ]
    for candidate in candidates:
        if candidate.exists():
            return candidate
    return candidates[0]


@lru_cache(maxsize=1)
def detect_recmd_backend() -> dict:
    command = _recmd_command()
    batch_path = _recmd_batch_path()
    result = {
        "backend": RECMD_BACKEND_CSV,
        "available": bool(command) and batch_path.exists(),
        "path": " ".join(command or []),
        "batch": str(batch_path),
        "version": "",
        "error": None,
    }
    if not command:
        result["error"] = "RECmd command not available"
        return result
    if not batch_path.exists():
        result["available"] = False
        result["error"] = f"RECmd batch not available: {batch_path}"
        return result
    try:
        completed = subprocess.run([*command, "--version"], capture_output=True, text=True, timeout=12, check=False)
        output = (completed.stdout or completed.stderr or "").strip()
        result["version"] = output.splitlines()[0].strip() if output else ""
        if completed.returncode != 0 and output:
            result["error"] = output[:1000]
    except Exception as exc:  # noqa: BLE001
        result["available"] = False
        result["error"] = str(exc)
    return result


def _archive_paths(archive_path: Path) -> list[str]:
    completed = subprocess.run(["7z", "l", "-slt", str(archive_path)], capture_output=True, text=True, timeout=600, check=False)
    if completed.returncode != 0:
        return []
    paths: list[str] = []
    for line in completed.stdout.splitlines():
        if not line.startswith("Path = "):
            continue
        value = line.removeprefix("Path = ").strip()
        if value and value != str(archive_path):
            paths.append(value)
    return paths


def _is_user_activity_hive_path(value: str) -> bool:
    normalized = value.replace("\\", "/").lower()
    if "/users/" not in normalized or "/windows/serviceprofiles/" in normalized:
        return False
    return normalized.endswith("/ntuser.dat") or normalized.endswith("/appdata/local/microsoft/windows/usrclass.dat")


def _profile_user_from_hive_path(value: str) -> str | None:
    inferred = extract_user_from_path(value)
    if inferred and is_valid_username(inferred):
        return inferred
    match = _USER_HIVE_RE.search(value)
    candidate = match.group(3) if match else None
    return candidate if candidate and is_valid_username(candidate) else None


def _source_candidates_from_metadata(metadata: dict) -> list[str]:
    values: list[str] = []
    for container in (
        (metadata.get("ingest_plan") or {}).get("disabled_candidates") or [],
        (metadata.get("velociraptor_discovery") or {}).get("candidates") or [],
        metadata.get("raw_artifacts") or [],
        (metadata.get("manifest") or {}).get("artifacts") or [],
    ):
        for entry in container if isinstance(container, list) else []:
            if not isinstance(entry, dict):
                continue
            candidate = str(entry.get("source_path") or entry.get("relative_path") or entry.get("path") or entry.get("name") or "").strip()
            if candidate and _is_user_activity_hive_path(candidate):
                values.append(candidate)
    return list(dict.fromkeys(values))


def find_user_activity_hives(case_id: str, evidence_id: str, metadata: dict) -> list[dict]:
    root = build_evidence_root(case_id, evidence_id)
    search_roots = [evidence_staging_dir(case_id, evidence_id), root / "extracted", root / "original_folder", root / "original"]
    found: dict[str, dict] = {}
    for source_path in _source_candidates_from_metadata(metadata):
        key = source_path.replace("\\", "/")
        found[key] = {"source_path": source_path, "path": None, "profile_user": _profile_user_from_hive_path(source_path), "from_archive": False}
        try:
            relative = sanitize_relative_path(source_path)
        except ValueError:
            continue
        for base in search_roots:
            candidate = base / relative
            if candidate.is_file():
                found[key].update({"path": candidate, "from_archive": False})
                break
    for base in search_roots:
        if not base.exists():
            continue
        for candidate in base.rglob("*"):
            if not candidate.is_file() or not _is_user_activity_hive_path(str(candidate)):
                continue
            try:
                source_path = str(candidate.relative_to(root))
            except ValueError:
                source_path = str(candidate)
            key = source_path.replace("\\", "/")
            found[key] = {"source_path": source_path, "path": candidate, "profile_user": _profile_user_from_hive_path(source_path), "from_archive": False}
    archive_dir = root / "original"
    archives = sorted(path for path in archive_dir.glob("*") if path.is_file() and path.suffix.lower() in {".7z", ".zip"})
    archive_entries: list[str] = []
    for archive in archives:
        archive_entries.extend(_archive_paths(archive))
    for source_path in archive_entries:
        if not _is_user_activity_hive_path(source_path):
            continue
        key = source_path.replace("\\", "/")
        found.setdefault(key, {"source_path": source_path, "path": None, "profile_user": _profile_user_from_hive_path(source_path), "from_archive": True})
    return sorted(found.values(), key=lambda item: str(item.get("source_path") or ""))


def _extract_hive_from_archive(case_id: str, evidence_id: str, source_path: str) -> Path | None:
    root = build_evidence_root(case_id, evidence_id)
    archive_dir = root / "original"
    archives = sorted(path for path in archive_dir.glob("*") if path.is_file() and path.suffix.lower() in {".7z", ".zip"})
    if not archives:
        return None
    digest = hashlib.sha1(source_path.encode("utf-8", "ignore")).hexdigest()[:16]
    output_dir = root / "derived" / "recmd_user_activity" / "hives" / digest
    output_dir.mkdir(parents=True, exist_ok=True)
    target = output_dir / Path(source_path.replace("\\", "/")).name
    if target.is_file():
        return target
    for archive in archives:
        result = subprocess.run(["7z", "e", str(archive), source_path, f"-o{output_dir}", "-y"], capture_output=True, text=True, timeout=600, check=False)
        if result.returncode == 0 and target.is_file():
            return target
    return None


def _run_recmd_csv(hive_path: Path, output_dir: Path, output_name: str) -> subprocess.CompletedProcess[str]:
    command = _recmd_command()
    if not command:
        raise RuntimeError("RECmd command not available")
    settings = get_settings()
    timeout = max(int(getattr(settings, "recmd_timeout_seconds", 0) or 0), 0) or None
    return subprocess.run(
        [
            *command,
            "-f",
            str(hive_path),
            "--bn",
            str(_recmd_batch_path()),
            "--csv",
            str(output_dir),
            "--csvf",
            output_name,
            "--nl",
        ],
        check=False,
        capture_output=True,
        text=True,
        timeout=timeout,
    )


def _specific_artifact_type(document: dict) -> str | None:
    parser = str((document.get("artifact") or {}).get("parser") or "")
    return _PARSER_TO_ARTIFACT_TYPE.get(parser)


def _retarget_user_activity_document(document: dict, *, artifact_type: str, source_path: str, profile_user: str | None) -> dict:
    artifact = document.setdefault("artifact", {})
    artifact["type"] = artifact_type
    artifact["name"] = _ARTIFACT_TYPE_TO_LABEL.get(artifact_type, artifact_type)
    artifact["source_path"] = source_path
    document["source_file"] = source_path
    if profile_user and is_valid_username(profile_user):
        document.setdefault("user", {})["name"] = document.get("user", {}).get("name") or profile_user
        document["profile_user"] = profile_user
        document.setdefault("file", {})["profile_user"] = profile_user
    if artifact_type == "shellbag":
        path = (document.get("shellbag") or {}).get("path") or (document.get("folder") or {}).get("path")
        document["path"] = path
        document["key_entity"] = path
        document["summary"] = f"Shellbag folder: {path or 'unknown'}"
    elif artifact_type == "userassist":
        process = document.get("process") or {}
        target = process.get("path") or process.get("display_name") or process.get("name")
        document.setdefault("program", {})["path"] = process.get("path")
        document["program"]["name"] = process.get("name")
        document["program"]["run_count"] = (document.get("execution") or {}).get("run_count")
        document["key_entity"] = target
        document["summary"] = f"UserAssist execution: {target or 'unknown'}"
    elif artifact_type == "recentdocs":
        file_data = document.get("file") or {}
        target = file_data.get("path") or file_data.get("name")
        document["key_entity"] = target
        document["summary"] = f"Recent document: {target or 'unknown'}"
    elif artifact_type == "runmru":
        command = (document.get("process") or {}).get("command_line") or (document.get("registry") or {}).get("value_data")
        document["command"] = command
        document["key_entity"] = command
        document["summary"] = f"RunMRU command: {command or 'unknown'}"
    elif artifact_type == "opensavemru":
        file_data = document.get("file") or {}
        target = file_data.get("path") or file_data.get("name") or (document.get("user_activity") or {}).get("activity_target")
        document["key_entity"] = target
        document["summary"] = f"Open/Save MRU item: {target or 'unknown'}"
    document["search_text"] = " | ".join(
        str(value)
        for value in [
            document.get("search_text"),
            artifact_type,
            document.get("key_entity"),
            document.get("summary"),
            profile_user,
        ]
        if value
    )[:8192]
    return document


def iter_recmd_user_activity_batches(
    *,
    case_id: str,
    evidence_id: str,
    artifact_id: str,
    artifact_meta: dict,
    batch_size: int,
) -> tuple[list[dict], dict]:
    backend = detect_recmd_backend()
    if not backend.get("available"):
        raise RuntimeError(str(backend.get("error") or "RECmd backend is not available"))
    root = build_evidence_root(case_id, evidence_id)
    output_root = root / "derived" / "recmd_user_activity" / "csv"
    output_root.mkdir(parents=True, exist_ok=True)
    hives = find_user_activity_hives(case_id, evidence_id, artifact_meta)
    started = time.perf_counter()
    counts: Counter[str] = Counter()
    hives_processed = 0
    hives_failed = 0
    errors: list[dict] = []
    batch: list[dict] = []
    for hive in hives:
        source_path = str(hive.get("source_path") or "")
        hive_path = hive.get("path")
        if not hive_path:
            hive_path = _extract_hive_from_archive(case_id, evidence_id, source_path)
        if not hive_path:
            hives_failed += 1
            errors.append({"source_path": source_path, "error": "hive_not_available"})
            continue
        profile_user = str(hive.get("profile_user") or "") or None
        csv_name = f"{hashlib.sha1(source_path.encode('utf-8', 'ignore')).hexdigest()[:16]}_recmd_user_activity.csv"
        csv_path = output_root / csv_name
        if not csv_path.is_file():
            result = _run_recmd_csv(Path(hive_path), output_root, csv_name)
            if result.returncode != 0 or not csv_path.is_file():
                hives_failed += 1
                errors.append({"source_path": source_path, "error": (result.stderr or result.stdout or f"exit_{result.returncode}")[:1000]})
                continue
        hives_processed += 1
        meta = {
            **artifact_meta,
            "name": "RECmd user activity",
            "source_path": source_path,
            "parser": RECMD_BACKEND_CSV,
            "detected_user": profile_user or artifact_meta.get("detected_user"),
        }
        docs = parse_recmd_file(case_id, evidence_id, artifact_id, csv_path, meta)
        for document in docs:
            artifact_type = _specific_artifact_type(document)
            if artifact_type not in USER_ACTIVITY_ARTIFACT_TYPES:
                continue
            counts[artifact_type] += 1
            batch.append(_retarget_user_activity_document(document, artifact_type=artifact_type, source_path=source_path, profile_user=profile_user))
            if len(batch) >= batch_size:
                yield batch, {
                    "backend": RECMD_BACKEND_CSV,
                    "backend_version": backend.get("version") or "",
                    "records_indexed_by_family": dict(counts),
                    "hives_total": len(hives),
                    "hives_processed": hives_processed,
                    "hives_failed": hives_failed,
                    "errors": errors[-10:],
                    "elapsed_seconds": round(time.perf_counter() - started, 2),
                }
                batch = []
    if batch:
        yield batch, {
            "backend": RECMD_BACKEND_CSV,
            "backend_version": backend.get("version") or "",
            "records_indexed_by_family": dict(counts),
            "hives_total": len(hives),
            "hives_processed": hives_processed,
            "hives_failed": hives_failed,
            "errors": errors[-10:],
            "elapsed_seconds": round(time.perf_counter() - started, 2),
        }
    elif not hives:
        yield [], {
            "backend": RECMD_BACKEND_CSV,
            "backend_version": backend.get("version") or "",
            "records_indexed_by_family": {},
            "hives_total": 0,
            "hives_processed": 0,
            "hives_failed": 0,
            "errors": [],
            "elapsed_seconds": round(time.perf_counter() - started, 2),
        }
