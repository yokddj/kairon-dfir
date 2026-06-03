from pathlib import Path
from urllib.parse import unquote


def normalize_velociraptor_path(path: str) -> str:
    if not path:
        return ""
    decoded = unquote(str(path)).replace("\\", "/")
    parts = [part for part in decoded.split("/") if part not in {"", "."}]
    if not parts:
        return ""
    drive_index = None
    for index, part in enumerate(parts):
        if part.endswith(":") and len(part) == 2 and part[0].isalpha():
            drive_index = index
            break
        if len(part) == 1 and part.isalpha() and index + 1 < len(parts) and parts[index + 1] == ":":
            drive_index = index
            break
    if drive_index is not None:
        parts = parts[drive_index:]
    first = parts[0]
    if first.endswith(":"):
        drive = first[0].upper() + ":"
        rest = parts[1:]
        normalized = "\\".join([drive, *rest]) if rest else drive + "\\"
        return normalized
    if len(first) == 1 and first.isalpha() and len(parts) > 1 and parts[1] == ":":
        drive = first.upper() + ":"
        rest = parts[2:]
        normalized = "\\".join([drive, *rest]) if rest else drive + "\\"
        return normalized
    joined = "\\".join(parts)
    if joined.startswith("Users\\") or joined.startswith("Windows\\") or joined.startswith("ProgramData\\"):
        return f"C:\\{joined}"
    return joined


def relative_display_path(root: Path, path: Path) -> str:
    return str(path.relative_to(root)).replace("\\", "/")
