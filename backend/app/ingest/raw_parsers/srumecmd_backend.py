from __future__ import annotations

from collections import Counter
from functools import lru_cache
import hashlib
import platform
from pathlib import Path
import shutil
import subprocess
import time

from app.core.config import get_settings
from app.core.storage import build_evidence_root, evidence_staging_dir, sanitize_relative_path
from app.ingest.normalizer import normalize_file


SRUMECMD_BACKEND_CSV = "srumecmd_csv"
SRUM_ARTIFACT_TYPE = "srum"


def _srumecmd_dll_path() -> Path:
    settings = get_settings()
    return Path(getattr(settings, "srumecmd_dotnet_dll", "") or "/opt/eztools/SrumECmd/SrumECmd.dll")


def _srumecmd_command() -> list[str] | None:
    dotnet = shutil.which("dotnet")
    dll_path = _srumecmd_dll_path()
    if dotnet and dll_path.exists():
        return [dotnet, str(dll_path)]
    for name in ("SrumECmd", "srumecmd"):
        binary = shutil.which(name)
        if binary:
            return [binary]
    return None


@lru_cache(maxsize=1)
def detect_srumecmd_backend() -> dict:
    command = _srumecmd_command()
    result = {
        "backend": SRUMECMD_BACKEND_CSV,
        "available": bool(command),
        "path": " ".join(command or []),
        "version": "",
        "error": None,
    }
    if not command:
        result["error"] = "SrumECmd command not available"
        return result
    if platform.system().lower() != "windows":
        result["available"] = False
        result["error"] = "SrumECmd is installed but unsupported on this Linux runtime; it requires Windows ESE libraries"
    try:
        completed = subprocess.run([*command, "--version"], capture_output=True, text=True, timeout=12, check=False)
        output = (completed.stdout or completed.stderr or "").strip()
        result["version"] = output.splitlines()[0].strip() if output else ""
        if completed.returncode != 0 and output and not result.get("error"):
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


def _is_srum_db_path(value: str) -> bool:
    normalized = value.replace("\\", "/").lower()
    return normalized.endswith("/srudb.dat") or normalized.endswith("srudb.dat")


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
            artifact_type = str(entry.get("artifact_type") or "").lower()
            parser = str(entry.get("parser") or "").lower()
            candidate = str(entry.get("source_path") or entry.get("relative_path") or entry.get("path") or entry.get("name") or "").strip()
            if candidate and (_is_srum_db_path(candidate) or artifact_type in {"srum_raw", "srum_database"} or parser == "srum_db"):
                values.append(candidate)
    return list(dict.fromkeys(values))


def find_srum_databases(case_id: str, evidence_id: str, metadata: dict) -> list[dict]:
    root = build_evidence_root(case_id, evidence_id)
    search_roots = [evidence_staging_dir(case_id, evidence_id), root / "extracted", root / "original_folder", root / "original"]
    found: dict[str, dict] = {}
    for source_path in _source_candidates_from_metadata(metadata):
        key = source_path.replace("\\", "/")
        found[key] = {"source_path": source_path, "path": None, "from_archive": False}
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
            if not candidate.is_file() or not _is_srum_db_path(str(candidate)):
                continue
            try:
                source_path = str(candidate.relative_to(root))
            except ValueError:
                source_path = str(candidate)
            found[source_path.replace("\\", "/")] = {"source_path": source_path, "path": candidate, "from_archive": False}
    archive_dir = root / "original"
    archives = sorted(path for path in archive_dir.glob("*") if path.is_file() and path.suffix.lower() in {".7z", ".zip"})
    for archive in archives:
        for source_path in _archive_paths(archive):
            if _is_srum_db_path(source_path):
                found.setdefault(source_path.replace("\\", "/"), {"source_path": source_path, "path": None, "from_archive": True})
    return sorted(found.values(), key=lambda item: str(item.get("source_path") or ""))


def _extract_srum_from_archive(case_id: str, evidence_id: str, source_path: str) -> Path | None:
    root = build_evidence_root(case_id, evidence_id)
    archive_dir = root / "original"
    archives = sorted(path for path in archive_dir.glob("*") if path.is_file() and path.suffix.lower() in {".7z", ".zip"})
    if not archives:
        return None
    digest = hashlib.sha1(source_path.encode("utf-8", "ignore")).hexdigest()[:16]
    output_dir = root / "derived" / "srumecmd" / "sources" / digest
    output_dir.mkdir(parents=True, exist_ok=True)
    target = output_dir / "SRUDB.dat"
    if target.is_file():
        return target
    for archive in archives:
        result = subprocess.run(["7z", "e", str(archive), source_path, f"-o{output_dir}", "-y"], capture_output=True, text=True, timeout=600, check=False)
        if result.returncode == 0:
            extracted = next((path for path in output_dir.iterdir() if path.is_file() and path.name.lower() == "srudb.dat"), None)
            if extracted:
                if extracted != target:
                    extracted.rename(target)
                return target
    return None


def _run_srumecmd_csv(srum_path: Path, output_dir: Path) -> subprocess.CompletedProcess[str]:
    command = _srumecmd_command()
    if not command:
        raise RuntimeError("SrumECmd command not available")
    settings = get_settings()
    timeout = max(int(getattr(settings, "srumecmd_timeout_seconds", 0) or 0), 0) or None
    return subprocess.run(
        [*command, "-f", str(srum_path), "--csv", str(output_dir)],
        check=False,
        capture_output=True,
        text=True,
        timeout=timeout,
    )


def _csv_outputs(output_dir: Path) -> list[Path]:
    return sorted(path for path in output_dir.glob("*.csv") if path.is_file() and "console" not in path.name.lower())


def iter_srumecmd_batches(
    *,
    case_id: str,
    evidence_id: str,
    artifact_id: str,
    artifact_meta: dict,
    batch_size: int,
) -> tuple[list[dict], dict]:
    backend = detect_srumecmd_backend()
    if not backend.get("available"):
        raise RuntimeError(str(backend.get("error") or "SrumECmd backend is not available"))
    root = build_evidence_root(case_id, evidence_id)
    output_root = root / "derived" / "srumecmd" / "csv"
    output_root.mkdir(parents=True, exist_ok=True)
    sources = find_srum_databases(case_id, evidence_id, artifact_meta)
    started = time.perf_counter()
    tables: Counter[str] = Counter()
    event_types: Counter[str] = Counter()
    apps: Counter[str] = Counter()
    sources_parsed = 0
    sources_failed = 0
    errors: list[dict] = []
    batch: list[dict] = []
    for source in sources:
        source_path = str(source.get("source_path") or "")
        local_path = source.get("path")
        if not local_path:
            local_path = _extract_srum_from_archive(case_id, evidence_id, source_path)
        if not local_path:
            sources_failed += 1
            errors.append({"source_path": source_path, "error": "srum_database_not_available"})
            continue
        digest = hashlib.sha1(source_path.encode("utf-8", "ignore")).hexdigest()[:16]
        csv_dir = output_root / digest
        csv_dir.mkdir(parents=True, exist_ok=True)
        if not _csv_outputs(csv_dir):
            result = _run_srumecmd_csv(Path(local_path), csv_dir)
            if result.returncode != 0 or not _csv_outputs(csv_dir):
                sources_failed += 1
                errors.append({"source_path": source_path, "error": (result.stderr or result.stdout or f"exit_{result.returncode}")[:1000]})
                continue
        sources_parsed += 1
        for csv_path in _csv_outputs(csv_dir):
            meta = {
                **artifact_meta,
                "name": f"SRUM - {csv_path.stem}",
                "source_path": source_path,
                "parser": SRUMECMD_BACKEND_CSV,
                "artifact_type": SRUM_ARTIFACT_TYPE,
                "source_tool": "srumecmd",
            }
            docs = normalize_file(case_id, evidence_id, artifact_id, csv_path, meta)
            for document in docs:
                artifact = document.setdefault("artifact", {})
                artifact["type"] = SRUM_ARTIFACT_TYPE
                artifact["parser"] = SRUMECMD_BACKEND_CSV
                artifact["name"] = artifact.get("name") or "SRUM"
                artifact["source_path"] = source_path
                document["source_file"] = source_path
                document["source_tool"] = "srumecmd"
                srum = document.get("srum") if isinstance(document.get("srum"), dict) else {}
                table = str(srum.get("table") or srum.get("artifact_type") or csv_path.stem or "unknown")
                tables[table] += 1
                event_type = str((document.get("event") or {}).get("type") or "srum_record")
                event_types[event_type] += 1
                app = str(srum.get("app_name") or srum.get("application") or (document.get("process") or {}).get("name") or "").strip()
                if app:
                    apps[app] += 1
                batch.append(document)
                if len(batch) >= batch_size:
                    yield batch, {
                        "backend": SRUMECMD_BACKEND_CSV,
                        "backend_version": backend.get("version") or "",
                        "sources_total": len(sources),
                        "sources_parsed": sources_parsed,
                        "sources_failed": sources_failed,
                        "tables": dict(tables),
                        "event_types": dict(event_types),
                        "top_apps": dict(apps.most_common(10)),
                        "errors": errors[-10:],
                        "elapsed_seconds": round(time.perf_counter() - started, 2),
                    }
                    batch = []
    yield batch, {
        "backend": SRUMECMD_BACKEND_CSV,
        "backend_version": backend.get("version") or "",
        "sources_total": len(sources),
        "sources_parsed": sources_parsed,
        "sources_failed": sources_failed,
        "tables": dict(tables),
        "event_types": dict(event_types),
        "top_apps": dict(apps.most_common(10)),
        "errors": errors[-10:],
        "elapsed_seconds": round(time.perf_counter() - started, 2),
    }
