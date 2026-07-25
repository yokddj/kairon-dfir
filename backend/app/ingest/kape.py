import csv
import os
from pathlib import Path

from app.ingest.detector import classify_artifact
from app.ingest.eztools.base import ensure_csv_field_limit
from app.ingest.scheduled_tasks.helpers import looks_like_scheduled_task_xml_path

# Directories that hold third-party dependency/build trees rather than forensic
# artifacts. A mounted disk image can contain venvs, node_modules, etc. with
# thousands of files that have no investigative value and only add ingest time
# and false-positive risk (see linux/helpers.py marker matching).
_EXCLUDED_DIR_NAMES = {
    "site-packages", "dist-packages", "node_modules", ".git",
    "__pycache__", "venv", ".venv", "env",
}


def list_kape_artifacts(root: Path) -> list[dict]:
    from app.ingest.linux.helpers import looks_like_linux_artifact
    ACCEPTED_EXTENSIONS = {".csv", ".json", ".jsonl", ".txt", ".xml", ".log", ".yaml", ".yml", ".conf", ".service", ".timer"}
    EXPERIMENTAL_EXTENSIONS = {".pyc", ".pyo"}
    artifacts = []
    candidate_paths: list[Path] = []
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in _EXCLUDED_DIR_NAMES]
        for filename in filenames:
            candidate_paths.append(Path(dirpath) / filename)
    for path in sorted(candidate_paths):
        if not path.is_file() or path.suffix.lower() in EXPERIMENTAL_EXTENSIONS:
            continue
        ext = path.suffix.lower()
        is_accepted_extension = ext in ACCEPTED_EXTENSIONS
        is_scheduled_task = looks_like_scheduled_task_xml_path(path)
        is_linux = bool(looks_like_linux_artifact(path))
        is_extensionless = ext == "" and path.name[0] != "." if path.name else False
        if not is_accepted_extension and not is_scheduled_task and not is_linux and not is_extensionless:
            continue
        headers = []
        if path.suffix.lower() == ".csv":
            try:
                ensure_csv_field_limit()
                with path.open("r", encoding="utf-8-sig", errors="ignore") as handle:
                    reader = csv.reader(handle)
                    headers = next(reader, [])
            except Exception:  # noqa: BLE001
                headers = []
        classification = classify_artifact(path, headers)
        artifacts.append(
            {
                "name": path.name,
                "source_path": str(path.relative_to(root)),
                "artifact_type": classification["artifact_type"],
                "parser": classification["parser"],
                "profile": classification["profile"],
                "artifact_family": classification.get("artifact_family"),
                "linux_artifact_type": classification.get("linux_artifact_type"),
                "reason": classification.get("reason"),
                "path": path,
            }
        )
    return artifacts
