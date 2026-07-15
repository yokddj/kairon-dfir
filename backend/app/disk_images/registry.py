from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
import re
from typing import Any, Protocol

from app.core.config import get_settings


settings = get_settings()


class ImageFormatAdapter(Protocol):
    key: str
    extensions: tuple[str, ...]
    supported: bool

    def detect(self, path: Path, companions: list[Path]) -> dict[str, Any] | None: ...
    def inspect(self, path: Path, companions: list[Path]) -> dict[str, Any]: ...
    def validate_segments(self, path: Path, companions: list[Path]) -> dict[str, Any]: ...
    def expose_readonly(self, *, evidence_id: str, path: Path, companions: list[Path], workspace: Path) -> dict[str, Any]: ...
    def cleanup(self, context: dict[str, Any]) -> None: ...
    def readiness(self) -> dict[str, Any]: ...


@dataclass
class UnsupportedImageFormatAdapter:
    key: str
    extensions: tuple[str, ...]
    limitation: str
    supported: bool = False

    def detect(self, path: Path, companions: list[Path]) -> dict[str, Any] | None:
        lower_name = path.name.lower()
        if any(lower_name.endswith(ext) for ext in self.extensions):
            return {"format": self.key, "confidence": "extension", "supported": False}
        return None

    def inspect(self, path: Path, companions: list[Path]) -> dict[str, Any]:
        return {"format": self.key, "supported": False, "error": "unsupported_format", "limitations": [self.limitation]}

    def validate_segments(self, path: Path, companions: list[Path]) -> dict[str, Any]:
        return {"format": self.key, "supported": False, "segments": [path.name]}

    def expose_readonly(self, *, evidence_id: str, path: Path, companions: list[Path], workspace: Path) -> dict[str, Any]:
        return {"format": self.key, "supported": False, "error": "unsupported_format", "workspace": str(workspace)}

    def cleanup(self, context: dict[str, Any]) -> None:
        return None

    def readiness(self) -> dict[str, Any]:
        return {"key": self.key, "ready": False, "supported": False, "reason": self.limitation}


class ImageFormatRegistry:
    def __init__(self) -> None:
        self._adapters: dict[str, ImageFormatAdapter] = {}

    def register(self, adapter: ImageFormatAdapter) -> None:
        self._adapters[adapter.key] = adapter

    def get(self, key: str) -> ImageFormatAdapter | None:
        return self._adapters.get(key)

    def list_capabilities(self) -> list[dict[str, Any]]:
        return [adapter.readiness() for adapter in self._adapters.values()]

    def readiness(self) -> dict[str, Any]:
        return {item["key"]: item for item in self.list_capabilities()}

    def detect(self, path: Path, companions: list[Path] | None = None) -> dict[str, Any] | None:
        candidates = companions or []
        best: dict[str, Any] | None = None
        priorities = {"magic": 5, "ewf_signature": 5, "mbr": 4, "gpt": 4, "filesystem": 3, "extension": 2, "filename": 1}
        for adapter in self._adapters.values():
            result = adapter.detect(path, candidates)
            if not result:
                continue
            if best is None or priorities.get(str(result.get("confidence") or ""), 0) > priorities.get(str(best.get("confidence") or ""), 0):
                best = result
        return best


def ewf_series_members(path: Path) -> list[Path]:
    lower_name = path.name.lower()
    match = re.match(r"^(?P<stem>.+)\.(?P<prefix>e|ex)(?P<index>\d{2})$", lower_name)
    if not match:
        return [path]
    stem = path.name[: -len(path.suffix)]
    prefix = match.group("prefix")
    companions = []
    for candidate in sorted(path.parent.iterdir()):
        candidate_match = re.match(rf"^{re.escape(stem)}\.(?P<prefix>{prefix})(?P<index>\d{{2}})$", candidate.name, re.I)
        if candidate_match:
            companions.append(candidate)
    return companions or [path]


_REGISTRY: ImageFormatRegistry | None = None


def get_image_format_registry() -> ImageFormatRegistry:
    global _REGISTRY
    if _REGISTRY is not None:
        return _REGISTRY
    from app.disk_images.raw import RawImageAdapter
    from app.disk_images.ewf import EwfImageAdapter
    from app.disk_images.vmdk import VmdkImageAdapter
    from app.disk_images.vhd import VhdImageAdapter
    from app.disk_images.qcow import QcowImageAdapter
    from app.disk_images.vdi import VdiImageAdapter

    registry = ImageFormatRegistry()
    registry.register(RawImageAdapter())
    registry.register(EwfImageAdapter())
    registry.register(VmdkImageAdapter())
    registry.register(VhdImageAdapter())
    registry.register(QcowImageAdapter())
    registry.register(VdiImageAdapter())
    registry.register(UnsupportedImageFormatAdapter("aff", (".aff", ".aff4"), "AFF/AFF4 is not implemented yet."))
    _REGISTRY = registry
    return registry
