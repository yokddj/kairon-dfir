from __future__ import annotations

from pathlib import Path
import shutil
from typing import Any

from app.disk_images.qemu import (
    _format_from_info,
    _format_size,
    _parse_vmdk_descriptor,
    _qemu_img_exists,
    _read_header,
    _validate_vmdk_extents,
    qemu_img_check,
    qemu_img_convert_to_raw,
    qemu_img_info,
)


_VMDK_MAGICS = (b"KDMV", b"VMDK", b"# Disk DescriptorFile")


class VmdkImageAdapter:
    key = "vmdk"
    extensions = (".vmdk",)
    supported = True

    def detect(self, path: Path, companions: list[Path]) -> dict[str, Any] | None:
        lower_name = path.name.lower()
        header = _read_header(path, 65536)
        if header and any(magic in header for magic in _VMDK_MAGICS):
            return {"format": self.key, "confidence": "magic", "supported": self.readiness()["ready"]}
        info = qemu_img_info(path)
        fmt = _format_from_info(info, path)
        if fmt == "vmdk":
            return {"format": self.key, "confidence": "qemu_img_format", "supported": self.readiness()["ready"]}
        if any(lower_name.endswith(ext) for ext in self.extensions):
            return {"format": self.key, "confidence": "extension", "supported": self.readiness()["ready"]}
        return None

    def inspect(self, path: Path, companions: list[Path]) -> dict[str, Any]:
        info = qemu_img_info(path)
        physical, virtual, allocation = _format_size(info)
        validation = self.validate_segments(path, companions)
        return {
            "format": self.key,
            "supported": self.readiness()["ready"],
            "path": str(path),
            "physical_size": physical,
            "virtual_size": virtual,
            "allocation_type": allocation,
            "validation": validation,
        }

    def validate_segments(self, path: Path, companions: list[Path]) -> dict[str, Any]:
        if not self.readiness()["ready"]:
            return {"format": self.key, "valid": False, "error": "missing_dependency"}
        name_lower = path.name.lower()
        if name_lower.endswith(".vmdk"):
            return {"format": self.key, "segments": [path.name], "segment_count": 1, "valid": True}
        return {"format": self.key, "valid": False, "error": "invalid_segment_set", "segments": [path.name]}

    def expose_readonly(self, *, evidence_id: str, path: Path, companions: list[Path], workspace: Path) -> dict[str, Any]:
        readiness = self.readiness()
        if not readiness["ready"]:
            return {"format": self.key, "supported": False, "error": "missing_dependency", "reason": readiness["reason"]}
        descriptor_parse = _parse_vmdk_descriptor(path)
        if descriptor_parse.get("extents"):
            extent_validation = _validate_vmdk_extents(path.parent, descriptor_parse["extents"])
            if not extent_validation["valid"]:
                if extent_validation.get("external"):
                    return {"format": self.key, "supported": False, "error": "external_extent_rejected", "external_extents": extent_validation["external"]}
                if extent_validation.get("missing"):
                    return {"format": self.key, "supported": False, "error": "missing_extent", "missing_extents": extent_validation["missing"]}
        if descriptor_parse.get("errors"):
            return {"format": self.key, "supported": False, "error": "descriptor_rejected", "reasons": descriptor_parse["errors"]}
        check_result = qemu_img_check(path)
        if not check_result.get("valid") and check_result.get("errors"):
            return {"format": self.key, "supported": False, "error": "image_check_failed", "check_result": check_result}
        info = qemu_img_info(path)
        _, virtual_size, _ = _format_size(info)
        if virtual_size > 1099511627776:
            return {"format": self.key, "supported": False, "error": "virtual_size_limit_exceeded", "virtual_size": virtual_size}
        output_path = workspace / f"{evidence_id}-vmdk-export.raw"
        result = qemu_img_convert_to_raw(input_path=path, output_path=output_path, evidence_id=evidence_id)
        return {
            **result,
            "format": self.key,
            "image_path": str(path),
            "segments": [str(path)],
            "workspace": str(workspace),
        }

    def cleanup(self, context: dict[str, Any]) -> None:
        raw_path = Path(str(context.get("exported_raw_path") or ""))
        if raw_path.exists() and raw_path.is_file():
            raw_path.unlink(missing_ok=True)

    def readiness(self) -> dict[str, Any]:
        ready = _qemu_img_exists()
        return {"key": self.key, "ready": ready, "supported": True, "reason": None if ready else "qemu-img missing"}
