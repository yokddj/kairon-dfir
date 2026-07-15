from __future__ import annotations

import logging
from enum import Enum
from pathlib import Path
from typing import Any

from app.disk_images.registry import get_image_format_registry
from app.ingest.velociraptor.zip_inventory import is_supported_archive_container

logger = logging.getLogger(__name__)


class EvidenceCategory(str, Enum):
    DISK_IMAGE = "disk_image"
    MEMORY_DUMP = "memory_dump"
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
        self._memory_suffixes = {".mem", ".dmp", ".vmem", ".lime", ".aff4"}

    def classify(self, path: Path) -> ClassificationResult:
        if not path.is_file():
            return ClassificationResult(EvidenceCategory.UNKNOWN, reason="not a file")

        if is_supported_archive_container(path):
            return ClassificationResult(
                EvidenceCategory.ARCHIVE,
                format_key="archive",
                confidence="high",
                reason=f"Detected archive container: {path.suffix}",
            )

        try:
            disk_result = self._registry.detect(path)
            if disk_result:
                fmt = str(disk_result.get("format") or "")
                supported = bool(disk_result.get("supported", True))
                confidence = str(disk_result.get("confidence") or "low")
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
                    metadata=disk_result,
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
            )

        return ClassificationResult(
            EvidenceCategory.UNKNOWN,
            reason="No disk image, archive, or memory dump pattern detected",
        )


_CLASSIFIER: EvidenceClassifier | None = None


def get_evidence_classifier() -> EvidenceClassifier:
    global _CLASSIFIER
    if _CLASSIFIER is None:
        _CLASSIFIER = EvidenceClassifier()
    return _CLASSIFIER
