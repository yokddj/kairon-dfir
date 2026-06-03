from __future__ import annotations

from app.ingest.cloud_sync.helpers import detect_cloud_provider_from_path


def looks_like_cloud_root_path(value: str | None) -> bool:
    provider, sync_root, _ = detect_cloud_provider_from_path(value)
    return bool(provider and sync_root)


__all__ = ["looks_like_cloud_root_path"]
