from __future__ import annotations

from pathlib import Path
from typing import Any

from app.disk_images.qemu import (
    _build_authorized_set,
    _check_space_before_convert,
    _format_from_info,
    _format_size,
    _parse_vmdk_descriptor,
    _read_header,
    _tool_functional,
    _validate_resource_limits,
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
        descriptor = _parse_vmdk_descriptor(path) if path.suffix.lower() == ".vmdk" else {"extents": []}
        return {
            "format": self.key,
            "supported": self.readiness()["ready"],
            "path": str(path),
            "physical_size": physical,
            "virtual_size": virtual,
            "allocation_type": allocation,
            "extents": descriptor.get("extents", []),
            "descriptor_errors": descriptor.get("errors", []),
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
        authorized = _build_authorized_set(path.parent, companions)
        descriptor_parse = _parse_vmdk_descriptor(path)
        if descriptor_parse.get("extents"):
            extent_validation = _validate_vmdk_extents(path.parent, descriptor_parse["extents"], authorized_paths=authorized)
            if not extent_validation["valid"]:
                if extent_validation.get("external"):
                    return {"format": self.key, "supported": False, "error": "external_extent_rejected", "external_extents": extent_validation["external"]}
                if extent_validation.get("unauthorized"):
                    return {"format": self.key, "supported": False, "error": "extent_not_in_authorized_set", "extents": extent_validation["unauthorized"]}
                if extent_validation.get("missing"):
                    return {"format": self.key, "supported": False, "error": "missing_extent", "missing_extents": extent_validation["missing"]}
        if descriptor_parse.get("errors"):
            return {"format": self.key, "supported": False, "error": "descriptor_rejected", "reasons": descriptor_parse["errors"]}
        check_result = qemu_img_check(path)
        if not check_result.get("valid") and check_result.get("errors"):
            return {"format": self.key, "supported": False, "error": "image_check_failed", "check_result": check_result}
        info = qemu_img_info(path)
        physical, virtual_size, _ = _format_size(info)
        limits = _validate_resource_limits(virtual_size=virtual_size, physical_size=physical)
        if not limits["valid"]:
            return {"format": self.key, "supported": False, **limits}
        space_check = _check_space_before_convert(virtual_size, workspace)
        if not space_check["sufficient"]:
            return {"format": self.key, "supported": False, **space_check}
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
        functional = _tool_functional("qemu-img")
        return {
            "key": self.key,
            "ready": functional,
            "degraded": False,
            "supported": True,
            "reason": None if functional else "qemu-img not functional",
        }
