from __future__ import annotations

from pathlib import Path
from typing import Any


class RawImageAdapter:
    key = "raw"
    extensions = (".dd", ".img", ".raw")
    supported = True

    def _header(self, path: Path, size: int = 4096) -> bytes:
        try:
            with path.open("rb") as handle:
                return handle.read(size)
        except OSError:
            return b""

    def detect(self, path: Path, companions: list[Path]) -> dict[str, Any] | None:
        lower_name = path.name.lower()
        header = self._header(path, 4096)
        if len(header) >= 512 and header[510:512] == b"\x55\xaa":
            return {"format": self.key, "confidence": "mbr", "supported": True}
        if len(header) >= 1024 and header[512:520] == b"EFI PART":
            return {"format": self.key, "confidence": "gpt", "supported": True}
        if len(header) >= 2048 and header[1080:1082] == b"\x53\xef":
            return {"format": self.key, "confidence": "filesystem", "supported": True}
        if len(header) >= 11 and header[3:11] in {b"NTFS    ", b"MSDOS5.0", b"mkfs.fat"}:
            return {"format": self.key, "confidence": "filesystem", "supported": True}
        if any(lower_name.endswith(ext) for ext in self.extensions):
            return {"format": self.key, "confidence": "extension", "supported": True}
        return None

    def inspect(self, path: Path, companions: list[Path]) -> dict[str, Any]:
        return {"format": self.key, "supported": True, "path": str(path), "size_bytes": path.stat().st_size}

    def validate_segments(self, path: Path, companions: list[Path]) -> dict[str, Any]:
        return {"format": self.key, "segments": [path.name], "segment_count": 1, "valid": True}

    def expose_readonly(self, *, evidence_id: str, path: Path, companions: list[Path], workspace: Path) -> dict[str, Any]:
        return {"format": self.key, "supported": True, "image_path": str(path), "segments": [str(path)], "workspace": str(workspace), "exported_raw_path": None, "access_strategy": "pytsk3_direct_readonly"}

    def cleanup(self, context: dict[str, Any]) -> None:
        return None

    def readiness(self) -> dict[str, Any]:
        return {"key": self.key, "ready": True, "supported": True, "reason": None}
