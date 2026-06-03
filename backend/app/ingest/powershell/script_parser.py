from pathlib import Path

from app.ingest.powershell.helpers import preview_command, read_text_with_fallbacks


def parse_powershell_script_file(path: Path) -> tuple[list[dict], list[str]]:
    text = read_text_with_fallbacks(path)
    return [
        {
            "Command": text,
            "CommandPreview": preview_command(text, 1024),
            "SourceFile": str(path),
            "FilePath": str(path),
        }
    ], []
