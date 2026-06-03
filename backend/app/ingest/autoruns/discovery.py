from __future__ import annotations

from pathlib import Path
import re

from app.ingest.autoruns.helpers import looks_like_autoruns_artifact, normalize_windows_path


STARTUP_FOLDER_PATTERNS = (
    r"programdata\\microsoft\\windows\\start menu\\programs\\startup\\",
    r"users\\[^\\]+\\appdata\\roaming\\microsoft\\windows\\start menu\\programs\\startup\\",
)


def looks_like_startup_folder_path(value: str | None) -> bool:
    normalized = normalize_windows_path(value)
    if not normalized:
        return False
    lower = normalized.lower()
    return any(re.search(pattern, lower, flags=re.IGNORECASE) for pattern in STARTUP_FOLDER_PATTERNS)


def looks_like_autoruns_candidate(path: Path, headers: list[str] | None = None) -> bool:
    return looks_like_autoruns_artifact(path, headers)


__all__ = ["looks_like_autoruns_artifact", "looks_like_autoruns_candidate", "looks_like_startup_folder_path"]
