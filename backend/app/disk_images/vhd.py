from __future__ import annotations

from pathlib import Path
from typing import Any

from app.disk_images.qemu import (
    _build_authorized_set,
    _check_space_before_convert,
    _format_from_info,
    _format_size,
    _read_header,
    _tool_functional,
    _validate_backing_file,
    _validate_resource_limits,
    qemu_img_check,
    qemu_img_convert_to_raw,
    qemu_img_info,
)

_VHD_SIGNATURES = (b"conectix", b"vhdxfile")

_MAX_CHAIN_DEPTH = 3


class VhdImageAdapter:
    key = "vhd"
    extensions = (".vhd", ".vhdx")
    supported = True

    def _detect_variant(self, path: Path) -> str | None:
        header = _read_header(path, 65536)
        if header:
            if header[:8] == b"vhdxfile":
                return "vhdx"
            if b"conectix" in header[:4096]:
                return "vhd"
        info = qemu_img_info(path)
        fmt = _format_from_info(info, path)
        if fmt in {"vhd", "vhdx"}:
            return fmt
        return None

    def detect(self, path: Path, companions: list[Path]) -> dict[str, Any] | None:
        lower_name = path.name.lower()
        header = _read_header(path, 65536)
        if header and any(sig in header for sig in _VHD_SIGNATURES):
            return {"format": self.key, "confidence": "magic", "supported": self.readiness()["ready"]}
        info = qemu_img_info(path)
        fmt = _format_from_info(info, path)
        if fmt in {"vhd", "vhdx"}:
            return {"format": self.key, "confidence": "qemu_img_format", "variant": fmt, "supported": self.readiness()["ready"]}
        if any(lower_name.endswith(ext) for ext in self.extensions):
            return {"format": self.key, "confidence": "extension", "supported": self.readiness()["ready"]}
        return None

    def inspect(self, path: Path, companions: list[Path]) -> dict[str, Any]:
        info = qemu_img_info(path)
        physical, virtual, allocation = _format_size(info)
        variant = self._detect_variant(path)
        backing = _validate_backing_file(info, path.parent)
        return {
            "format": self.key,
            "variant": variant,
            "supported": self.readiness()["ready"],
            "path": str(path),
            "physical_size": physical,
            "virtual_size": virtual,
            "allocation_type": allocation,
            "has_parent": backing.get("has_backing", False),
            "backing_file": backing.get("backing_file"),
            "backing_present": backing.get("present"),
        }

    def validate_segments(self, path: Path, companions: list[Path]) -> dict[str, Any]:
        return {"format": self.key, "segments": [path.name], "segment_count": 1, "valid": True}

    def expose_readonly(self, *, evidence_id: str, path: Path, companions: list[Path], workspace: Path) -> dict[str, Any]:
        readiness = self.readiness()
        if not readiness["ready"]:
            return {"format": self.key, "supported": False, "error": "missing_dependency", "reason": readiness["reason"]}
        authorized = _build_authorized_set(path.parent, companions)
        info = qemu_img_info(path)
        backing = _validate_backing_file(info, path.parent, authorized_paths=authorized)
        if backing.get("has_backing") and not backing["valid"]:
            return {"format": self.key, "supported": False, "error": backing.get("error"), "backing_file": backing.get("backing_file")}
        if backing.get("has_backing") and not backing.get("present"):
            if not any((path.parent / Path(backing["backing_file"])).exists() for _ in [1]):
                return {"format": self.key, "supported": False, "error": "missing_parent", "backing_file": backing.get("backing_file")}
        chain_check = self._check_chain_depth(path, authorized, 0)
        if chain_check:
            return chain_check
        check_result = qemu_img_check(path)
        if not check_result.get("valid") and check_result.get("errors"):
            return {"format": self.key, "supported": False, "error": "image_check_failed", "check_result": check_result}
        physical, virtual_size, _ = _format_size(info)
        limits = _validate_resource_limits(virtual_size=virtual_size, physical_size=physical)
        if not limits["valid"]:
            return {"format": self.key, "supported": False, **limits}
        space_check = _check_space_before_convert(virtual_size, workspace)
        if not space_check["sufficient"]:
            return {"format": self.key, "supported": False, **space_check}
        output_path = workspace / f"{evidence_id}-vhd-export.raw"
        result = qemu_img_convert_to_raw(input_path=path, output_path=output_path, evidence_id=evidence_id)
        return {
            **result,
            "format": self.key,
            "image_path": str(path),
            "segments": [str(path)],
            "workspace": str(workspace),
        }

    def _check_chain_depth(self, path: Path, authorized: set[str], depth: int) -> dict[str, Any] | None:
        if depth >= _MAX_CHAIN_DEPTH:
            return {"format": self.key, "supported": False, "error": "chain_depth_exceeded", "depth": depth}
        info = qemu_img_info(path)
        backing = _validate_backing_file(info, path.parent, authorized_paths=authorized)
        if not backing.get("has_backing") or not backing.get("present"):
            return None
        backing_path = path.parent / Path(backing["backing_file"])
        if str(backing_path.resolve()) == str(path.resolve()):
            return {"format": self.key, "supported": False, "error": "chain_loop_detected", "path": str(path)}
        return self._check_chain_depth(backing_path, authorized, depth + 1)

    def cleanup(self, context: dict[str, Any]) -> None:
        raw_path = Path(str(context.get("exported_raw_path") or ""))
        if raw_path.exists() and raw_path.is_file():
            raw_path.unlink(missing_ok=True)

    def readiness(self) -> dict[str, Any]:
        functional = _tool_functional("qemu-img")
        return {
            "key": self.key,
            "ready": functional,
            "degraded": False,
            "supported": True,
            "reason": None if functional else "qemu-img not functional",
        }
