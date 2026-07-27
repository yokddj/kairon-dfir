from __future__ import annotations

import logging
from enum import Enum
from pathlib import Path
from typing import Any

from app.disk_images.registry import get_image_format_registry
from app.ingest.velociraptor.zip_inventory import is_supported_archive_container, open_evidence_container
from app.services.memory.probe import (
    STATUS_AMBIGUOUS_RAW,
    STATUS_CONFIRMED_MEMORY,
    STATUS_PROBABLE_DISK,
    STATUS_PROBABLE_MEMORY,
    probe_memory_image,
)

logger = logging.getLogger(__name__)


class EvidenceCategory(str, Enum):
    DISK_IMAGE = "disk_image"
    MEMORY_DUMP = "memory_dump"
    AUXILIARY = "auxiliary"
    COLLECTION = "collection"
    MIXED = "mixed"
    ARCHIVE = "archive"
    UNKNOWN = "unknown"


class ClassificationResult:
    def __init__(
        self,
        category: EvidenceCategory,
        *,
        format_key: str | None = None,
        confidence: str = "low",
        reason: str = "",
        metadata: dict[str, Any] | None = None,
    ) -> None:
        self.category = category
        self.format_key = format_key
        self.confidence = confidence
        self.reason = reason
        self.metadata = metadata or {}


class EvidenceClassifier:
    def __init__(self) -> None:
        self._registry = get_image_format_registry()
        self._memory_suffixes = {".mem", ".dmp", ".dump", ".bin", ".vmem", ".lime", ".aff4"}

    def _archive_entries(self, path: Path) -> list[str]:
        try:
            container = open_evidence_container(path)
            return [entry.path for entry in container.list_entries() if not entry.is_dir]
        except Exception as exc:  # noqa: BLE001
            logger.debug("Archive inventory failed for %s: %s", path, exc)
            return []

    def _is_volatility_profile_archive(self, entries: list[str]) -> bool:
        lowered = [entry.replace("\\", "/").lower() for entry in entries]
        has_dwarf = any(entry.endswith("module.dwarf") or "/module.dwarf" in entry for entry in lowered)
        has_system_map = any("system.map-" in entry or entry.endswith("system.map") for entry in lowered)
        has_volatility_path = any("volatility" in entry for entry in lowered)
        return has_dwarf and has_system_map and has_volatility_path

    def _memory_name_hint(self, path: Path) -> str | None:
        lower_name = path.name.lower()
        for token in ("kcore", "memdump", "memory", "ramdump", "vmem", "lime"):
            if token in lower_name:
                return token
        if path.suffix.lower() in self._memory_suffixes:
            return path.suffix.lower().lstrip(".")
        return None

    def classify(self, path: Path) -> ClassificationResult:
        if not path.is_file():
            return ClassificationResult(EvidenceCategory.UNKNOWN, reason="not a file")

        if is_supported_archive_container(path):
            entries = self._archive_entries(path)
            if self._is_volatility_profile_archive(entries):
                return ClassificationResult(
                    EvidenceCategory.AUXILIARY,
                    format_key="zip",
                    confidence="high",
                    reason="Detected Volatility Linux profile archive (module.dwarf + System.map); auxiliary support file, not evidence capture.",
                    metadata={"container_format": "archive", "signals": ["volatility_profile", "module.dwarf", "system.map"], "entry_count": len(entries)},
                )
            return ClassificationResult(
                EvidenceCategory.ARCHIVE,
                format_key="archive",
                confidence="high",
                reason=f"Detected archive container: {path.suffix}",
                metadata={"container_format": "archive", "entry_count": len(entries)},
            )

        memory_probe = probe_memory_image(path)
        if memory_probe.status in {STATUS_CONFIRMED_MEMORY, STATUS_PROBABLE_MEMORY}:
            return ClassificationResult(
                EvidenceCategory.MEMORY_DUMP,
                format_key=memory_probe.detected_format,
                confidence=memory_probe.confidence,
                reason=memory_probe.reason,
                metadata={"memory_probe": memory_probe.to_dict(), "signals": [memory_probe.detected_format]},
            )

        try:
            disk_result = self._registry.detect(path)
            if disk_result:
                fmt = str(disk_result.get("format") or "")
                supported = bool(disk_result.get("supported", True))
                confidence = str(disk_result.get("confidence") or "low")
                if confidence == "extension" and memory_probe.status == STATUS_AMBIGUOUS_RAW:
                    hint = self._memory_name_hint(path)
                    if hint:
                        return ClassificationResult(
                            EvidenceCategory.MEMORY_DUMP,
                            format_key=memory_probe.detected_format,
                            confidence="medium",
                            reason=f"No coherent disk structure was found; filename hints at a memory dump ({hint}).",
                            metadata={"memory_probe": memory_probe.to_dict(), "disk_probe": disk_result, "signals": [f"name:{hint}", "no_disk_structure"], "conflicts": ["raw_extension"]},
                        )
                    return ClassificationResult(
                        EvidenceCategory.UNKNOWN,
                        format_key=fmt,
                        confidence="low",
                        reason="Only a raw image extension was detected; no disk or memory structure was found.",
                        metadata={"memory_probe": memory_probe.to_dict(), "disk_probe": disk_result, "signals": ["raw_extension"], "conflicts": ["no_structural_signature"]},
                    )
                if not supported:
                    return ClassificationResult(
                        EvidenceCategory.UNKNOWN,
                        format_key=fmt,
                        confidence=confidence,
                        reason=f"Detected unsupported disk image format: {fmt}",
                    )
                return ClassificationResult(
                    EvidenceCategory.DISK_IMAGE,
                    format_key=fmt,
                    confidence=confidence,
                    reason=f"Detected disk image: {fmt} (confidence: {confidence})",
                    metadata={**disk_result, "memory_probe": memory_probe.to_dict(), "signals": [confidence]},
                )
        except Exception as exc:
            logger.debug("Disk image detection error for %s: %s", path, exc)

        suffix = path.suffix.lower()
        if suffix in self._memory_suffixes:
            return ClassificationResult(
                EvidenceCategory.MEMORY_DUMP,
                format_key=suffix.lstrip("."),
                confidence="medium",
                reason=f"Detected memory dump by extension: {suffix}",
                metadata={"memory_probe": memory_probe.to_dict(), "signals": ["memory_extension"]},
            )
        if memory_probe.status == STATUS_PROBABLE_DISK:
            return ClassificationResult(
                EvidenceCategory.DISK_IMAGE,
                format_key=memory_probe.detected_format,
                confidence=memory_probe.confidence,
                reason=memory_probe.reason,
                metadata={"memory_probe": memory_probe.to_dict(), "signals": ["disk_structure"]},
            )

        return ClassificationResult(
            EvidenceCategory.UNKNOWN,
            reason="No disk image, archive, auxiliary, or memory dump pattern detected",
            metadata={"memory_probe": memory_probe.to_dict()},
        )


_CLASSIFIER: EvidenceClassifier | None = None


def get_evidence_classifier() -> EvidenceClassifier:
    global _CLASSIFIER
    if _CLASSIFIER is None:
        _CLASSIFIER = EvidenceClassifier()
    return _CLASSIFIER
