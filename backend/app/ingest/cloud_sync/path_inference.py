from __future__ import annotations

import re

from app.ingest.cloud_sync.helpers import classify_cloud_file, detect_cloud_provider_from_path


WINDOWS_CLOUD_PATH_RE = re.compile(
    r"([A-Za-z]:\\Users\\[^\\]+\\(?:OneDrive(?: - [^\\]+)?|Dropbox|Box(?: Drive| Sync)?|MEGAsync|iCloudDrive|iCloud Photos|Google Drive|My Drive)(?:\\[^\"\\r\\n]+)*)",
    re.IGNORECASE,
)


def infer_cloud_context(path: str | None, *, command_line: str | None = None) -> dict:
    provider, sync_root, account_hint = detect_cloud_provider_from_path(path)
    effective_path = path
    if (not provider or not sync_root) and command_line:
        match = WINDOWS_CLOUD_PATH_RE.search(command_line)
        if match:
            effective_path = match.group(1)
            provider, sync_root, account_hint = detect_cloud_provider_from_path(effective_path)
    tags, reasons, risk = classify_cloud_file(effective_path or path, command_line=command_line)
    return {
        "provider": provider,
        "sync_root": sync_root,
        "account_hint": account_hint,
        "tags": tags,
        "reasons": reasons,
        "risk": risk,
    }


__all__ = ["infer_cloud_context"]
