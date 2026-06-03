from pathlib import Path
import re

from app.ingest.powershell.helpers import parse_transcript_header, read_text_with_fallbacks


PROMPT_RE = re.compile(r"(?im)^(PS [^\r\n>]*>\s*)(.+)$")
COMMAND_START_RE = re.compile(r"(?im)^Command start time:\s*(.+)$")


def parse_powershell_transcript(path: Path) -> tuple[list[dict], dict]:
    text = read_text_with_fallbacks(path)
    header = parse_transcript_header(text)
    rows: list[dict] = []
    current_command_time = None
    for line_number, line in enumerate(text.splitlines(), start=1):
        start_match = COMMAND_START_RE.match(line.strip())
        if start_match:
            current_command_time = start_match.group(1).strip()
            continue
        prompt_match = PROMPT_RE.match(line)
        if not prompt_match:
            continue
        rows.append(
            {
                "Command": prompt_match.group(2).strip(),
                "LineNumber": line_number,
                "CommandStartTime": current_command_time,
                "SourceFile": str(path),
                "TranscriptStartTime": header.get("transcript_start_time"),
                "TranscriptEndTime": header.get("transcript_end_time"),
                "Username": header.get("username"),
                "RunAsUser": header.get("run_as"),
                "Machine": header.get("machine"),
                "HostApplication": header.get("host_application"),
                "ProcessId": header.get("process_id"),
                "PSVersion": header.get("ps_version"),
                "OS": header.get("os"),
            }
        )
        current_command_time = None
    return rows, {
        "header": header,
        "command_count": len(rows),
    }
