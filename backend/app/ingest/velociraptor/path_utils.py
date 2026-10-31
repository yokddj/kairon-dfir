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
    root = _windows_root_index(parts)
    if root is not None:
        # KAPE-style and AD1 collections name the volume as a folder ("C/Users/...");
        # others wrap the tree in their own folders ("challenge/Users/...").
        drive = parts[root - 1].upper() if root > 0 and len(parts[root - 1]) == 1 and parts[root - 1].isalpha() else "C"
        return "\\".join([f"{drive}:", *parts[root:]])
    joined = "\\".join(parts)
    if joined.startswith("Users\\") or joined.startswith("Windows\\") or joined.startswith("ProgramData\\"):
        return f"C:\\{joined}"
    return joined


_WINDOWS_DIR_CHILDREN = {"system32", "syswow64", "prefetch", "tasks", "appcompat", "inf", "servicing", "winsxs"}
_PROFILE_CHILDREN = {"appdata", "ntuser.dat", "ntuser.dat.log1", "ntuser.dat.log2", "desktop", "downloads", "documents", "onedrive", "local settings", "application data", "recent"}


def _windows_root_index(parts: list[str]) -> int | None:
    """Where a Windows volume's tree starts inside a collection path, judged
    by its layout (Windows\\System32, Users\\<name>\\AppData...) rather than
    by position, so wrapper folders and drive-letter folders are skipped."""
    lowered = [part.lower() for part in parts]
    for index, part in enumerate(lowered):
        following = lowered[index + 1:index + 3]
        if part == "windows" and following[:1] and following[0] in _WINDOWS_DIR_CHILDREN:
            return index
        if part in {"users", "documents and settings"} and len(following) == 2 and following[1] in _PROFILE_CHILDREN:
            return index
        if part == "programdata" and following[:1] == ["microsoft"]:
            return index
    return None


def relative_display_path(root: Path, path: Path) -> str:
    return str(path.relative_to(root)).replace("\\", "/")
