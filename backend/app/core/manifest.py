import json
from datetime import datetime
from pathlib import Path

from app.core.storage import sha256_file


def build_file_entry(path: Path, base_dir: Path, *, ignored: bool = False, reason: str | None = None) -> dict:
    relative = str(path.relative_to(base_dir)) if path.exists() and path.is_relative_to(base_dir) else path.name
    return {
        "path": relative,
        "size": path.stat().st_size if path.exists() and path.is_file() else 0,
        "sha256": sha256_file(path) if path.exists() and path.is_file() and not ignored else None,
        "extension": path.suffix.lower(),
        "ignored": ignored,
        "reason": reason,
    }


def default_manifest(evidence: object) -> dict:
    return {
        "evidence_id": getattr(evidence, "id"),
        "case_id": getattr(evidence, "case_id"),
        "original_filename": getattr(evidence, "original_filename"),
        "sha256": getattr(evidence, "sha256"),
        "evidence_type": getattr(getattr(evidence, "evidence_type", None), "value", getattr(evidence, "evidence_type", "unknown")),
        "source_tool": getattr(evidence, "source_tool", None),
        "storage_mode": getattr(getattr(evidence, "storage_mode", None), "value", getattr(evidence, "storage_mode", "uploaded")),
        "is_external": bool(getattr(evidence, "is_external", False)),
        "copy_to_storage": bool(getattr(evidence, "copy_to_storage", True)),
        "original_path": getattr(evidence, "original_path", None),
        "stored_path": getattr(evidence, "stored_path", None),
        "created_at": getattr(evidence, "created_at").isoformat() if getattr(evidence, "created_at", None) else None,
        "processed_at": getattr(evidence, "processed_at", None).isoformat() if getattr(evidence, "processed_at", None) else None,
        "files": [],
        "artifacts": [],
        "stats": {
            "total_files": 0,
            "processed_files": 0,
            "ignored_files": 0,
            "detected_artifacts": 0,
            "results_artifacts_detected": 0,
            "results_artifacts_parsed": 0,
            "raw_artifacts_detected": 0,
            "raw_artifacts_parsed": 0,
            "raw_artifacts_not_parsed": 0,
            "indexed_events": 0,
            "failed_artifacts": 0,
        },
        "errors": [],
    }


def write_manifest(path: Path, manifest: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(manifest, indent=2, ensure_ascii=True), encoding="utf-8")
