from pathlib import Path

from app.ingest.powershell.helpers import read_text_with_fallbacks


def parse_psreadline_history(path: Path) -> tuple[list[dict], list[str]]:
    text = read_text_with_fallbacks(path)
    rows: list[dict] = []
    for line_number, line in enumerate(text.splitlines(), start=1):
        stripped = line.strip()
        if not stripped:
            continue
        rows.append(
            {
                "Command": stripped,
                "LineNumber": line_number,
                "SourceFile": str(path),
            }
        )
    return rows, []
