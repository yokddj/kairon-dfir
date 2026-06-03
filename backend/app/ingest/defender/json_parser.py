from pathlib import Path

from app.ingest.defender.helpers import parse_json_loose, parse_jsonl_loose, read_text_with_fallbacks

def read_defender_json_rows(path: Path) -> list[dict]:
    text, _ = read_text_with_fallbacks(path)
    rows = parse_json_loose(text)
    if rows:
        return rows
    return parse_jsonl_loose(text)
