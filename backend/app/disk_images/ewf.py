from __future__ import annotations

from pathlib import Path
import re
import shutil
import subprocess
from typing import Any


EWF_SIGNATURES = {b"EVF\t\r\n\xff\x00", b"LVF\t\r\n\xff\x00"}


def _tool_exists(name: str) -> bool:
    return shutil.which(name) is not None


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
        readiness = self.readiness()
        if not readiness["ready"]:
            return {"format": self.key, "supported": False, "error": "missing_dependency", "reason": readiness["reason"]}
        validation = self.validate_segments(path, companions)
        if not validation.get("valid"):
            return {"format": self.key, "supported": False, "error": validation.get("error"), "validation": validation}
        output_prefix = workspace / f"{evidence_id}-ewf-export"
        command = ["ewfexport", "-u", "-t", str(output_prefix), "-f", "raw", str(path)]
        completed = subprocess.run(command, capture_output=True, text=True, shell=False, timeout=7200)
        if completed.returncode != 0:
            return {
                "format": self.key,
                "supported": False,
                "error": "corrupt_image",
                "stderr": completed.stderr[-4000:],
                "stdout": completed.stdout[-4000:],
                "command": command,
            }
        raw_path = output_prefix.with_suffix(".raw")
        if not raw_path.exists():
            candidates = sorted(workspace.glob(f"{output_prefix.name}*"))
            raw_path = next((candidate for candidate in candidates if candidate.is_file() and candidate.suffix.lower() in {".raw", ".img", ".dd"}), raw_path)
        return {
            "format": self.key,
            "supported": True,
            "image_path": str(path),
            "segments": [str(item) for item in companions or [path]],
            "workspace": str(workspace),
            "exported_raw_path": str(raw_path),
            "command": command,
            "access_strategy": "ewfexport_to_temporary_raw_readonly",
        }

    def cleanup(self, context: dict[str, Any]) -> None:
        raw_path = Path(str(context.get("exported_raw_path") or ""))
        if raw_path.exists() and raw_path.is_file():
            raw_path.unlink(missing_ok=True)

    def readiness(self) -> dict[str, Any]:
        return {"key": self.key, "ready": _tool_exists("ewfexport") and _tool_exists("ewfinfo"), "supported": True, "reason": None if _tool_exists("ewfexport") and _tool_exists("ewfinfo") else "ewf-tools missing"}
