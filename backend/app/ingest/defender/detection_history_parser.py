from pathlib import Path

from app.ingest.defender.helpers import parse_json_loose, parse_text_record_blocks


def parse_detection_history_file(path: Path) -> tuple[list[dict], list[str]]:
    warnings: list[str] = []
    text = path.read_text(encoding="utf-8", errors="ignore")
    records = parse_json_loose(text)
    if records:
        return records, warnings
    records = parse_text_record_blocks(text)
    if records:
        return records, warnings
    if any(token in text.lower() for token in ["threat", "resource", "action", "severity", "status"]):
        return [{"Message": line.strip(), "SourceFile": path.name} for line in text.splitlines() if line.strip()], ["DetectionHistory could not be parsed as structured blocks; falling back to message lines."]
    return [], ["DetectionHistory did not contain parseable structured content."]
