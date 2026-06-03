import csv
from pathlib import Path

from app.ingest.detector import classify_artifact
from app.ingest.eztools.base import ensure_csv_field_limit
from app.ingest.scheduled_tasks.helpers import looks_like_scheduled_task_xml_path


def list_kape_artifacts(root: Path) -> list[dict]:
    artifacts = []
    for path in sorted(root.rglob("*")):
        if not path.is_file() or (path.suffix.lower() not in {".csv", ".json", ".jsonl", ".txt", ".xml"} and not looks_like_scheduled_task_xml_path(path)):
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
                "reason": classification.get("reason"),
                "path": path,
            }
        )
    return artifacts
