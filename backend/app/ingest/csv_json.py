import csv
import json
from pathlib import Path

from app.ingest.browser.detector import looks_like_browser_artifact
from app.ingest.detector import classify_artifact
from app.ingest.eztools.base import ensure_csv_field_limit
from app.ingest.ntfs.helpers import is_ntfs_raw_candidate
from app.ingest.scheduled_tasks.helpers import looks_like_scheduled_task_xml_path
from app.ingest.windows_ui.helpers import is_windows_ui_raw_candidate


def _read_structured_headers(path: Path) -> list[str]:
    suffix = path.suffix.lower()
    if suffix == ".csv":
        try:
            ensure_csv_field_limit()
            with path.open("r", encoding="utf-8-sig", errors="ignore", newline="") as handle:
                reader = csv.reader(handle)
                return next(reader, [])
        except Exception:  # noqa: BLE001
            return []
    if suffix == ".json":
        try:
            payload = json.loads(path.read_text(encoding="utf-8", errors="ignore"))
        except Exception:  # noqa: BLE001
            return []
        if isinstance(payload, list):
            first = next((item for item in payload if isinstance(item, dict)), None)
            return list(first.keys()) if first else []
        if isinstance(payload, dict):
            if isinstance(payload.get("rows"), list):
                first = next((item for item in payload["rows"] if isinstance(item, dict)), None)
                return list(first.keys()) if first else []
            return list(payload.keys())
        return []
    if suffix == ".jsonl":
        try:
            with path.open("r", encoding="utf-8", errors="ignore") as handle:
                for line in handle:
                    line = line.strip()
                    if not line:
                        continue
                    item = json.loads(line)
                    if isinstance(item, dict):
                        return list(item.keys())
        except Exception:  # noqa: BLE001
            return []
        return []
    return []


def _read_csv_headers(path: Path) -> list[str]:
    if path.suffix.lower() != ".csv":
        return []
    return _read_structured_headers(path)


def _is_qmgr_raw_candidate(path: Path) -> bool:
    return path.name.lower() in {"qmgr0.dat", "qmgr1.dat", "qmgr.db"}


def _is_mft_raw_candidate(path: Path) -> bool:
    return path.name == "$MFT" or path.name.lower() == "mft"


def _is_user_activity_raw_hive_candidate(path: Path) -> bool:
    return path.name.lower() in {"ntuser.dat", "usrclass.dat"}


def list_generic_artifacts(root: Path) -> list[dict]:
    path = root if root.is_file() else None
    if path:
        classification = classify_artifact(path, _read_structured_headers(path))
        return [
            {
                "name": path.name,
                "source_path": path.name,
                "artifact_type": classification["artifact_type"],
                "parser": classification["parser"],
                "profile": classification["profile"],
                "reason": classification.get("reason"),
                "path": path,
            }
        ]
    artifacts = []
    for item in sorted(root.rglob("*")):
        normalized_parts = {part.lower() for part in item.parts}
        eligible = (
            item.suffix.lower() in {".csv", ".json", ".jsonl", ".txt", ".xml", ".log", ".evtx"}
            or _is_qmgr_raw_candidate(item)
            or _is_mft_raw_candidate(item)
            or _is_user_activity_raw_hive_candidate(item)
            or is_ntfs_raw_candidate(item)
            or is_windows_ui_raw_candidate(item)
            or looks_like_scheduled_task_xml_path(item)
            or looks_like_browser_artifact(item)
        )
        if item.is_file() and "__macosx" not in normalized_parts and not item.name.startswith("._") and eligible:
            classification = classify_artifact(item, _read_structured_headers(item))
            artifacts.append(
                {
                    "name": item.name,
                    "source_path": str(item.relative_to(root)),
                    "artifact_type": classification["artifact_type"],
                    "parser": classification["parser"],
                    "profile": classification["profile"],
                    "reason": classification.get("reason"),
                    "path": item,
                }
            )
    return artifacts
