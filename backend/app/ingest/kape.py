import csv
from pathlib import Path

from app.ingest.detector import classify_artifact
from app.ingest.eztools.base import ensure_csv_field_limit
from app.ingest.scheduled_tasks.helpers import looks_like_scheduled_task_xml_path


def list_kape_artifacts(root: Path) -> list[dict]:
    from app.ingest.linux.helpers import looks_like_linux_artifact
    ACCEPTED_EXTENSIONS = {".csv", ".json", ".jsonl", ".txt", ".xml", ".log", ".yaml", ".yml", ".conf", ".service", ".timer"}
    EXPERIMENTAL_EXTENSIONS = {".pyc", ".pyo"}
    artifacts = []
    for path in sorted(root.rglob("*")):
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
