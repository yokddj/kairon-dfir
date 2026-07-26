from __future__ import annotations

from pathlib import Path
import re
from typing import Any

from app.disk_images.ewf_img_info import EwfImgInfo, EwfOpenError, pyewf_available


EWF_SIGNATURES = {b"EVF\t\r\n\xff\x00", b"LVF\t\r\n\xff\x00"}


class EwfImageAdapter:
    key = "ewf"
    extensions = (".e01", ".ex01", ".e02", ".e03", ".e04", ".e05")
    supported = True

    def _header(self, path: Path) -> bytes:
        try:
            with path.open("rb") as handle:
                return handle.read(16)
        except OSError:
            return b""

    def detect(self, path: Path, companions: list[Path]) -> dict[str, Any] | None:
        lower_name = path.name.lower()
        header = self._header(path)
        if any(header.startswith(signature) for signature in EWF_SIGNATURES):
            return {"format": self.key, "confidence": "ewf_signature", "supported": self.readiness()["ready"]}
        if any(lower_name.endswith(ext) for ext in self.extensions):
            return {"format": self.key, "confidence": "extension", "supported": self.readiness()["ready"]}
        return None

    def _series(self, path: Path, companions: list[Path]) -> list[Path]:
        series = [item for item in (companions or [path]) if item.parent == path.parent]
        return sorted(series, key=lambda item: item.name.lower())

    def validate_segments(self, path: Path, companions: list[Path]) -> dict[str, Any]:
        series = self._series(path, companions)
        names = [item.name for item in series]
        indexes: list[int] = []
        stem = path.stem
        prefix = None
        for candidate in series:
            match = re.match(r"^(?P<stem>.+)\.(?P<prefix>e|ex)(?P<index>\d{2})$", candidate.name, re.I)
            if not match:
                return {"format": self.key, "valid": False, "error": "invalid_segment_set", "segments": names}
            if prefix is None:
                stem = match.group("stem")
                prefix = match.group("prefix").lower()
            elif match.group("stem") != stem or match.group("prefix").lower() != prefix:
                return {"format": self.key, "valid": False, "error": "invalid_segment_set", "segments": names}
            indexes.append(int(match.group("index")))
        sorted_indexes = sorted(indexes)
        expected = list(range(1, len(sorted_indexes) + 1))
        if len(set(sorted_indexes)) != len(sorted_indexes):
            return {"format": self.key, "valid": False, "error": "duplicate_segment", "segments": names}
        if sorted_indexes != expected:
            return {"format": self.key, "valid": False, "error": "missing_segment", "segments": names, "expected_indexes": expected, "actual_indexes": sorted_indexes}
        return {"format": self.key, "valid": True, "segments": names, "segment_count": len(series)}

    def inspect(self, path: Path, companions: list[Path]) -> dict[str, Any]:
        validation = self.validate_segments(path, companions)
        ready = self.readiness()["ready"]
        return {
            "format": self.key,
            "supported": ready,
            "validation": validation,
            "path": str(path),
            "size_bytes": sum(item.stat().st_size for item in companions or [path] if item.exists()),
        }

    def expose_readonly(self, *, evidence_id: str, path: Path, companions: list[Path], workspace: Path) -> dict[str, Any]:
        # No temporary RAW file is written here (see
        # app.disk_images.ewf_img_info.EwfImgInfo) -- this validates the
        # segment set, then opens (and immediately closes) a real
        # EwfImgInfo purely to confirm pyewf can actually parse this
        # image, the same correctness check `ewfexport` used to perform
        # by actually converting it. service.py opens its own EwfImgInfo
        # for real use afterwards -- exactly how the old flow already
        # opened the exported RAW file independently for discovery and
        # for materialization.
        readiness = self.readiness()
        if not readiness["ready"]:
            return {"format": self.key, "supported": False, "error": "missing_dependency", "reason": readiness["reason"]}
        validation = self.validate_segments(path, companions)
        if not validation.get("valid"):
            return {"format": self.key, "supported": False, "error": validation.get("error"), "validation": validation}
        series = self._series(path, companions)
        try:
            probe = EwfImgInfo(series)
            probe.close()
        except EwfOpenError as exc:
            return {"format": self.key, "supported": False, "error": "corrupt_image", "reason": str(exc)}
        return {
            "format": self.key,
            "supported": True,
            "image_path": str(path),
            "segments": [str(item) for item in series],
            "workspace": str(workspace),
            "exported_raw_path": None,
            "access_strategy": "pyewf_streaming_readonly",
        }

    def cleanup(self, context: dict[str, Any]) -> None:
        # Nothing to clean up: expose_readonly never wrote a temporary
        # RAW file for EWF. Kept as a no-op (rather than removed) so this
        # adapter still satisfies the ImageFormatAdapter Protocol exactly
        # like every other adapter.
        return None

    def readiness(self) -> dict[str, Any]:
        ready = pyewf_available()
        return {"key": self.key, "ready": ready, "supported": True, "reason": None if ready else "pyewf (libewf-python) not installed"}
