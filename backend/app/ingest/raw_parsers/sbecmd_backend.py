"""Shellbags from raw user hives (UsrClass.dat, NTUSER.DAT) with Eric
Zimmerman's SBECmd. Unlike SrumECmd it is plain .NET and runs on the Linux
worker, so the hive's BagMRU tree is decoded by the reference tool and its
CSV goes through the same Shellbags normalizer as an uploaded SBECmd_Output.

Hive discovery and archive extraction are shared with the RECmd user-activity
backend: both read the same per-profile hives.
"""

from __future__ import annotations

from collections import Counter
from functools import lru_cache
import hashlib
from pathlib import Path
import shutil
import subprocess
import time

from app.core.config import get_settings
from app.core.storage import build_evidence_root
from app.ingest.identity_extraction import is_valid_username
from app.ingest.normalizer import normalize_file
from app.ingest.raw_parsers.recmd_backend import _archive_paths, _extract_hive_from_archive, find_user_activity_hives


SBECMD_BACKEND_CSV = "sbecmd_csv"
SHELLBAGS_ARTIFACT_TYPE = "shellbags"
# Registry transaction logs SBECmd replays when they sit next to a dirty hive.
_HIVE_LOG_SUFFIXES = (".LOG1", ".LOG2")


def _sbecmd_dll_path() -> Path:
    settings = get_settings()
    return Path(getattr(settings, "sbecmd_dotnet_dll", "") or "/opt/eztools/SBECmd/SBECmd.dll")


def _sbecmd_command() -> list[str] | None:
    dotnet = shutil.which("dotnet")
    dll_path = _sbecmd_dll_path()
    if dotnet and dll_path.exists():
        return [dotnet, str(dll_path)]
    for name in ("SBECmd", "sbecmd"):
        binary = shutil.which(name)
        if binary:
            return [binary]
    return None


@lru_cache(maxsize=1)
def detect_sbecmd_backend() -> dict:
    command = _sbecmd_command()
    result = {
        "backend": SBECMD_BACKEND_CSV,
        "available": bool(command),
        "path": " ".join(command or []),
        "version": "",
        "error": None,
    }
    if not command:
        result["error"] = "SBECmd command not available"
        return result
    try:
        completed = subprocess.run([*command, "--version"], capture_output=True, text=True, timeout=12, check=False)
        output = (completed.stdout or completed.stderr or "").strip()
        result["version"] = output.splitlines()[0].strip() if output else ""
    except Exception as exc:  # noqa: BLE001
        result["available"] = False
        result["error"] = str(exc)
    return result


def _stage_hive(case_id: str, evidence_id: str, source_path: str, hive_path: Path, stage_dir: Path) -> Path:
    """SBECmd only takes a directory (-d); give each hive its own, with its
    transaction logs when the collection kept them."""
    if stage_dir.exists():
        shutil.rmtree(stage_dir)
    stage_dir.mkdir(parents=True)
    shutil.copy2(hive_path, stage_dir / hive_path.name)
    siblings = {path.name.lower(): path for path in hive_path.parent.iterdir() if path.is_file()} if hive_path.parent.is_dir() else {}
    archive_entries: list[str] | None = None
    for suffix in _HIVE_LOG_SUFFIXES:
        log_name = f"{hive_path.name}{suffix}"
        local = siblings.get(log_name.lower())
        if local:
            shutil.copy2(local, stage_dir / log_name)
            continue
        if archive_entries is None:
            root = build_evidence_root(case_id, evidence_id)
            archive_entries = [
                entry
                for archive in sorted(path for path in (root / "original").glob("*") if path.is_file() and path.suffix.lower() in {".7z", ".zip"})
                for entry in _archive_paths(archive)
            ]
        wanted = f"{source_path}{suffix}".replace("\\", "/").lower()
        match = next((entry for entry in archive_entries if entry.replace("\\", "/").lower() == wanted), None)
        extracted = _extract_hive_from_archive(case_id, evidence_id, match) if match else None
        if extracted:
            shutil.copy2(extracted, stage_dir / log_name)
    return stage_dir


def _run_sbecmd_csv(stage_dir: Path, output_dir: Path) -> subprocess.CompletedProcess[str]:
    command = _sbecmd_command()
    if not command:
        raise RuntimeError("SBECmd command not available")
    settings = get_settings()
    timeout = max(int(getattr(settings, "sbecmd_timeout_seconds", 0) or 0), 0) or None
    return subprocess.run([*command, "-d", str(stage_dir), "--csv", str(output_dir)], check=False, capture_output=True, text=True, timeout=timeout)


def _csv_outputs(output_dir: Path) -> list[Path]:
    return sorted(path for path in output_dir.glob("*.csv") if path.is_file())


def _progress(backend: dict, hives: list[dict], hives_processed: int, hives_failed: int, counts: Counter, errors: list[dict], started: float) -> dict:
    return {
        "backend": SBECMD_BACKEND_CSV,
        "backend_version": backend.get("version") or "",
        "hives_total": len(hives),
        "hives_processed": hives_processed,
        "hives_failed": hives_failed,
        "records_by_hive": dict(counts),
        "errors": errors[-10:],
        "elapsed_seconds": round(time.perf_counter() - started, 2),
    }


def iter_sbecmd_batches(
    *,
    case_id: str,
    evidence_id: str,
    artifact_id: str,
    artifact_meta: dict,
    batch_size: int,
):
    backend = detect_sbecmd_backend()
    if not backend.get("available"):
        raise RuntimeError(str(backend.get("error") or "SBECmd backend is not available"))
    root = build_evidence_root(case_id, evidence_id)
    work_root = root / "derived" / "sbecmd"
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
        digest = hashlib.sha1(source_path.encode("utf-8", "ignore")).hexdigest()[:16]
        csv_dir = work_root / "csv" / digest
        if not _csv_outputs(csv_dir):
            stage_dir = _stage_hive(case_id, evidence_id, source_path, Path(hive_path), work_root / "hives" / digest)
            csv_dir.mkdir(parents=True, exist_ok=True)
            result = _run_sbecmd_csv(stage_dir, csv_dir)
            if result.returncode != 0 or not _csv_outputs(csv_dir):
                hives_failed += 1
                errors.append({"source_path": source_path, "error": (result.stderr or result.stdout or f"exit_{result.returncode}")[-1000:]})
                continue
        hives_processed += 1
        profile_user = str(hive.get("profile_user") or "") or None
        meta = {
            **artifact_meta,
            "name": "SBECmd Shellbags",
            "source_path": source_path,
            "parser": SBECMD_BACKEND_CSV,
            "artifact_type": SHELLBAGS_ARTIFACT_TYPE,
            "source_tool": "sbecmd",
            "detected_user": profile_user or artifact_meta.get("detected_user"),
        }
        for csv_path in _csv_outputs(csv_dir):
            for document in normalize_file(case_id, evidence_id, artifact_id, csv_path, meta):
                artifact = document.setdefault("artifact", {})
                artifact["type"] = SHELLBAGS_ARTIFACT_TYPE
                artifact["parser"] = SBECMD_BACKEND_CSV
                artifact["source_path"] = source_path
                document["source_file"] = source_path
                document["source_tool"] = "sbecmd"
                document.setdefault("shellbag", {})["hive_path"] = source_path
                if profile_user and is_valid_username(profile_user):
                    document.setdefault("user", {})["name"] = profile_user
                    document["profile_user"] = profile_user
                counts[Path(source_path.replace("\\", "/")).name] += 1
                batch.append(document)
                if len(batch) >= batch_size:
                    yield batch, _progress(backend, hives, hives_processed, hives_failed, counts, errors, started)
                    batch = []
    yield batch, _progress(backend, hives, hives_processed, hives_failed, counts, errors, started)
