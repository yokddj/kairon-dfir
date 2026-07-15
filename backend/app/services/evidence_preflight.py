"""Preflight Inspection for the Unified Evidence Ingestion wizard.

A lightweight, read-only inspection that classifies a staged upload and
previews the processing pipeline before any real ingestion happens. It
reuses the existing, mature discovery pipeline exactly as-is:

- app.ingest.evidence_classifier.EvidenceClassifier for category detection
- app.core.evidence_platforms for platform detection
- app.ingest.velociraptor.zip_inventory.open_evidence_container for
  archive/folder listing (same container abstraction the real upload route
  uses to inventory a Velociraptor/KAPE/manual ZIP or an uploaded folder)
- app.ingest.linux.discovery.build_linux_inventory + looks_like_linux_artifact
  for expected-artifact matching (Linux)
- app.core.artifact_registry.artifact_registry_entries for expected-artifact
  matching (other platforms)
- app.disk_images.service.inspect_disk_image_readonly for disk image format
  detection, volume discovery, and OS installation detection

This module MUST NOT create Evidence/Artifact/DiskImage rows, MUST NOT call
enqueue_ingest, and MUST NOT write anything outside of a disposable temp
directory it cleans up itself. It is intentionally DB-free: no Session is
imported or accepted anywhere in this file.
"""
from __future__ import annotations

import shutil
import tarfile
import zipfile
from pathlib import Path
from typing import Any

from app.core.artifact_registry import artifact_registry_entries
from app.core.config import get_settings
from app.core.evidence_platforms import EvidencePlatform, detect_evidence_platform
from app.disk_images.service import inspect_disk_image_readonly
from app.ingest.evidence_classifier import EvidenceCategory, get_evidence_classifier
from app.ingest.linux.discovery import build_linux_inventory
from app.ingest.linux.helpers import looks_like_linux_artifact
from app.ingest.velociraptor.zip_inventory import ContainerEntry, is_supported_archive_container, open_evidence_container
from app.schemas.evidence_preflight import (
    PreflightClassification,
    PreflightDiagnostic,
    PreflightReport,
    PreflightResourceCheck,
    PreflightStatusCheck,
)

# Rough throughput assumption for the processing-time estimate. There is no
# historical benchmark table to draw from (confirmed during investigation),
# so this is a documented, conservative heuristic, not a measured figure.
_ASSUMED_THROUGHPUT_BYTES_PER_SECOND = 45 * 1024 * 1024
_MIN_ESTIMATED_SECONDS = 30
_STORAGE_SAFETY_MARGIN = 1.15
_NESTED_ARCHIVE_PEEK_LIMIT_BYTES = 200 * 1024 * 1024


def _human(num_bytes: int | None) -> str:
    if num_bytes is None:
        return "unknown"
    value = float(num_bytes)
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if value < 1024 or unit == "TB":
            return f"{value:.1f} {unit}" if unit != "B" else f"{int(value)} {unit}"
        value /= 1024
    return f"{value:.1f} TB"


def _nested_archive_depth(container, entries: list[ContainerEntry], *, max_depth_to_check: int) -> int:
    """Best-effort nested-archive depth scan, bounded to avoid unbounded recursion
    or reading very large inner archives into memory. Returns at least 1 (the
    outer container itself)."""
    deepest = 1

    def _scan_bytes(data: bytes, name: str, remaining: int) -> int:
        if remaining <= 0:
            return 1
        try:
            if name.lower().endswith(".zip"):
                import io

                with zipfile.ZipFile(io.BytesIO(data)) as inner:
                    names = inner.namelist()
            elif is_supported_archive_container(Path(name)):
                import io

                with tarfile.open(fileobj=io.BytesIO(data)) as inner:
                    names = inner.getnames()
            else:
                return 1
        except Exception:  # noqa: BLE001
            return 1
        best = 1
        for inner_name in names:
            if is_supported_archive_container(Path(inner_name)):
                best = max(best, 1 + 1)  # one more nested level detected; do not recurse further for cost reasons
        return best

    for entry in entries:
        if entry.is_dir or entry.ignored:
            continue
        if not is_supported_archive_container(Path(entry.path)):
            continue
        if entry.size and entry.size > _NESTED_ARCHIVE_PEEK_LIMIT_BYTES:
            deepest = max(deepest, 2)  # a nested archive exists; skip reading it, still counts as one more level
            continue
        try:
            with container.open_entry(entry.path) as handle:
                data = handle.read()
            deepest = max(deepest, 1 + _scan_bytes(data, entry.path, max_depth_to_check - 1))
        except Exception:  # noqa: BLE001
            continue
    return deepest


def _expected_parsers_for_archive(entries: list[ContainerEntry], *, platform: str) -> tuple[list[str], int]:
    live_paths = [entry.path for entry in entries if not entry.is_dir and not entry.ignored]
    if platform == EvidencePlatform.linux.value:
        matched_paths = 0
        labels: set[str] = set()
        for rel_path in live_paths:
            hit = looks_like_linux_artifact(rel_path)
            if hit:
                matched_paths += 1
                labels.add(hit[0].replace("_", " "))
        return sorted(labels), matched_paths
    # Windows / other: match by filename against the static artifact registry labels.
    registry_entries = artifact_registry_entries(platforms=[platform] if platform not in {EvidencePlatform.unknown.value, EvidencePlatform.mixed.value} else None)
    labels = set()
    matched_paths = 0
    lowered_labels_by_hint = {e["id"]: e["label"] for e in registry_entries}
    for rel_path in live_paths:
        lower = rel_path.lower()
        for artifact_id, label in lowered_labels_by_hint.items():
            if artifact_id.replace("_", "") in lower.replace("_", "").replace("-", ""):
                labels.add(label)
                matched_paths += 1
                break
    return sorted(labels), matched_paths


def _linux_hostname_distro(container, entries: list[ContainerEntry], tmp_root: Path) -> tuple[str | None, str | None, str | None]:
    candidates = [
        entry.path
        for entry in entries
        if not entry.is_dir
        and entry.size < 65536
        and Path(entry.path).name.lower() in {"hostname", "os-release", "hostnamectl.txt", "version"}
    ]
    if not candidates:
        return None, None, None
    tmp_root.mkdir(parents=True, exist_ok=True)
    container.extract_entries(candidates, tmp_root)
    inventory = build_linux_inventory(tmp_root, [entry.path for entry in entries])
    if not inventory:
        return None, None, None
    return inventory.get("hostname"), inventory.get("distribution"), inventory.get("kernel")


def _inspect_archive_or_folder(path: Path, *, declared_platform: str | None, tmp_dir: Path) -> dict[str, Any]:
    container = open_evidence_container(path)
    entries = container.list_entries()
    live_entries = [entry for entry in entries if not entry.is_dir]
    total_uncompressed = sum(entry.size for entry in live_entries if not entry.ignored)
    total_compressed = sum(entry.compressed_size or entry.size for entry in live_entries if not entry.ignored)
    entry_paths = [entry.path for entry in live_entries]

    detected_platform = detect_evidence_platform(filename=path.name, paths=entry_paths)
    effective_platform = declared_platform if declared_platform and declared_platform != EvidencePlatform.auto.value else detected_platform

    hostname = distro = kernel = None
    if effective_platform == EvidencePlatform.linux.value:
        hostname, distro, kernel = _linux_hostname_distro(container, entries, tmp_dir / "peek")

    expected_parsers, matched_count = _expected_parsers_for_archive(entries, platform=effective_platform)
    nested_depth = _nested_archive_depth(container, entries, max_depth_to_check=get_settings().max_archive_depth + 2)

    return {
        "container_type": container.type,
        "platform": effective_platform,
        "hostname": hostname,
        "distro": distro,
        "version": kernel,
        "expected_parsers": expected_parsers,
        "expected_artifact_count": matched_count,
        "total_uncompressed_bytes": total_uncompressed,
        "total_compressed_bytes": total_compressed if container.type != "directory" else None,
        "nested_archive_depth": nested_depth,
        "entry_count": len(live_entries),
    }


def _resolve_upload_limit(category: str) -> int:
    settings = get_settings()
    if category == EvidenceCategory.MEMORY_DUMP.value:
        return int(settings.memory_max_upload_size)
    return int(settings.backend_max_upload_size)


def run_preflight(path: Path, *, token: str, original_filename: str, declared_platform: str | None, tmp_dir: Path) -> PreflightReport:
    """Inspect a staged evidence file/folder and return a full preflight report.

    path: the staged file or directory to inspect (already on local disk).
    tmp_dir: a disposable scratch directory owned by the caller; this
      function may write small peek files under it but never anything
      resembling a real extraction, and never touches the database.
    """
    settings = get_settings()
    classifier = get_evidence_classifier()
    is_directory = path.is_dir()
    file_size = sum(f.stat().st_size for f in path.rglob("*") if f.is_file()) if is_directory else path.stat().st_size

    diagnostics: list[PreflightDiagnostic] = []
    status_checks: list[PreflightStatusCheck] = []

    if is_directory:
        classification_category = EvidenceCategory.ARCHIVE
        classification_confidence = "high"
        classification_reason = "Folder selected for ingestion"
        format_key = "folder"
    else:
        result = classifier.classify(path)
        classification_category = result.category
        classification_confidence = result.confidence
        classification_reason = result.reason
        format_key = result.format_key

    chain: list[str] = []
    platform = declared_platform or EvidencePlatform.unknown.value
    hostname = distro = version = None
    volumes_count = installations_count = None
    expected_parsers: list[str] = []
    estimated_extracted_bytes: int | None = None
    estimated_temp_storage_bytes: int | None = None
    detected_archive_depth: int | None = None
    detected_backing_chain_depth: int | None = None
    estimated_artifact_count: int | None = None
    warnings: list[str] = []

    is_openable_container = is_directory or classification_category == EvidenceCategory.ARCHIVE
    if is_openable_container:
        chain.append("Archive" if not is_directory else "Folder")
        try:
            info = _inspect_archive_or_folder(path, declared_platform=declared_platform, tmp_dir=tmp_dir)
        except Exception as exc:  # noqa: BLE001
            info = {}
            warnings.append(f"Could not fully inspect contents: {exc}")
        if info:
            platform = info["platform"]
            hostname = info["hostname"]
            distro = info["distro"]
            version = info["version"]
            expected_parsers = info["expected_parsers"]
            estimated_artifact_count = info["expected_artifact_count"]
            estimated_extracted_bytes = info["total_uncompressed_bytes"]
            estimated_temp_storage_bytes = estimated_extracted_bytes
            detected_archive_depth = info["nested_archive_depth"]
            chain.append(f"{platform.title()}" if platform not in {EvidencePlatform.unknown.value, EvidencePlatform.mixed.value} else "Unknown platform")
            if info["container_type"] != "directory":
                chain[0] = "Archive"
        classification_category_value = "archive"
        pipeline_preview = [
            "Archive" if not is_directory else "Folder",
            "Evidence Classification",
            f"{platform.title()} Discovery" if platform not in {EvidencePlatform.unknown.value} else "Platform Discovery",
            "Artifact Discovery",
            "Normalization",
            "Indexing",
            "Search",
            "Timeline",
        ]
    elif classification_category == EvidenceCategory.DISK_IMAGE:
        chain.append("Disk Image")
        workspace = tmp_dir / "disk_image_workspace"
        result = inspect_disk_image_readonly(path, workspace=workspace)
        if not result.get("supported", True):
            error = str(result.get("error") or "unsupported_format")
            warnings.append(f"Disk image inspection failed: {error}")
            if error == "chain_depth_exceeded":
                detected_backing_chain_depth = int((result.get("validation") or {}).get("depth") or 0)
        else:
            volumes = result.get("volumes") or []
            installs = result.get("installations") or []
            volumes_count = len(volumes)
            installations_count = len(installs)
            estimated_extracted_bytes = sum(int(v.get("length_bytes") or 0) for v in volumes)
            estimated_temp_storage_bytes = estimated_extracted_bytes if format_key != "raw" else 0
            if installs:
                first = installs[0]
                platform = str(first.get("platform") or platform)
                hostname = first.get("hostname")
                distro = first.get("distro")
                version = first.get("version")
            registry_entries = artifact_registry_entries(platforms=[platform] if platform not in {EvidencePlatform.unknown.value} else None)
            expected_parsers = sorted({e["label"] for e in registry_entries})
            estimated_artifact_count = len(expected_parsers)
            warnings.extend(result.get("warnings") or [])
        classification_category_value = "disk_image"
        pipeline_preview = [
            "Archive" if is_supported_archive_container(path) else "Disk Image",
            "Disk Image",
            "Volume Discovery",
            f"{platform.title()} Discovery" if platform not in {EvidencePlatform.unknown.value} else "OS Discovery",
            "Artifact Discovery",
            "Normalization",
            "Indexing",
            "Search",
            "Timeline",
        ]
    elif classification_category == EvidenceCategory.MEMORY_DUMP:
        chain.append("Memory Dump")
        platform = declared_platform or EvidencePlatform.memory.value
        estimated_extracted_bytes = file_size
        estimated_temp_storage_bytes = file_size
        expected_parsers = []
        classification_category_value = "memory_dump"
        pipeline_preview = [
            "Memory Dump",
            "Evidence Classification",
            "Memory Registration",
            "Memory Analysis (manual, after ingestion)",
        ]
    else:
        classification_category_value = "unknown"
        pipeline_preview = ["Unknown", "Manual classification required"]

    estimated_final_size_bytes = estimated_extracted_bytes
    estimated_seconds = None
    if estimated_extracted_bytes or file_size:
        basis = max(estimated_extracted_bytes or 0, file_size)
        estimated_seconds = max(_MIN_ESTIMATED_SECONDS, int(basis / _ASSUMED_THROUGHPUT_BYTES_PER_SECOND))

    available_space = shutil.disk_usage(settings.backend_temp_dir).free
    upload_limit = _resolve_upload_limit(classification_category_value)

    resource_check = PreflightResourceCheck(
        file_size_bytes=file_size,
        compressed_size_bytes=None if is_directory else file_size,
        estimated_extracted_bytes=estimated_extracted_bytes,
        estimated_temp_storage_bytes=estimated_temp_storage_bytes,
        estimated_final_size_bytes=estimated_final_size_bytes,
        estimated_processing_seconds=estimated_seconds,
        estimated_artifact_count=estimated_artifact_count,
        detected_archive_depth=detected_archive_depth,
        detected_backing_chain_depth=detected_backing_chain_depth,
        available_disk_space_bytes=available_space,
        configured_upload_limit_bytes=upload_limit,
        configured_extraction_limit_bytes=int(settings.backend_max_extracted_bytes),
        configured_archive_depth_limit=int(settings.max_archive_depth),
        configured_backing_chain_limit=int(settings.disk_image_max_chain_depth),
        temp_directory=str(settings.backend_temp_dir),
    )

    # --- Status checks ---
    supported_ok = classification_category_value != "unknown"
    status_checks.append(PreflightStatusCheck(label="Supported", ok=supported_ok, detail=classification_reason))

    upload_ok = file_size <= upload_limit
    status_checks.append(PreflightStatusCheck(
        label="Within upload limit",
        ok=upload_ok,
        detail=f"{_human(file_size)} of {_human(upload_limit)} allowed",
    ))
    if not upload_ok:
        diagnostics.append(PreflightDiagnostic(
            problem="Upload limit exceeded",
            reason=f"The selected file ({_human(file_size)}) is larger than the configured upload limit ({_human(upload_limit)}).",
            current_configuration={"limit": _human(upload_limit)},
            required_configuration={"limit": f"at least {_human(file_size)}"},
            configuration_key="MEMORY_MAX_UPLOAD_SIZE" if classification_category_value == "memory_dump" else "BACKEND_MAX_UPLOAD_SIZE",
            configuration_file="backend/.env",
            how_to_fix=[
                "Edit backend/.env",
                f"Increase {'MEMORY_MAX_UPLOAD_SIZE' if classification_category_value == 'memory_dump' else 'BACKEND_MAX_UPLOAD_SIZE'} to at least {file_size} bytes",
                "Run ./scripts/upgrade.sh",
            ],
        ))

    storage_needed = int((estimated_temp_storage_bytes or 0) * _STORAGE_SAFETY_MARGIN)
    storage_ok = available_space > storage_needed
    status_checks.append(PreflightStatusCheck(
        label="Enough storage",
        ok=storage_ok,
        detail=f"{_human(available_space)} available, ~{_human(storage_needed)} needed",
    ))
    if not storage_ok:
        diagnostics.append(PreflightDiagnostic(
            problem="Temporary storage too low",
            reason=f"Processing this evidence needs approximately {_human(storage_needed)} of free space in the temp directory, but only {_human(available_space)} is available.",
            current_configuration={"available": _human(available_space), "temp_directory": str(settings.backend_temp_dir)},
            required_configuration={"available": _human(storage_needed)},
            configuration_key="BACKEND_TEMP_DIR",
            configuration_file="backend/.env",
            how_to_fix=[
                "Free space on the temp directory's volume",
                "Or move BACKEND_TEMP_DIR to a volume with more free space",
                "Restart the backend after changing BACKEND_TEMP_DIR",
            ],
        ))

    extraction_ok = estimated_extracted_bytes is None or estimated_extracted_bytes <= settings.backend_max_extracted_bytes
    if estimated_extracted_bytes is not None:
        status_checks.append(PreflightStatusCheck(
            label="Within extraction limit",
            ok=extraction_ok,
            detail=f"~{_human(estimated_extracted_bytes)} estimated of {_human(settings.backend_max_extracted_bytes)} allowed",
        ))
        if not extraction_ok:
            diagnostics.append(PreflightDiagnostic(
                problem="Extraction size exceeded",
                reason=f"The estimated extracted size (~{_human(estimated_extracted_bytes)}) is larger than the configured maximum ({_human(settings.backend_max_extracted_bytes)}).",
                current_configuration={"limit": _human(settings.backend_max_extracted_bytes)},
                required_configuration={"limit": f"at least ~{_human(estimated_extracted_bytes)}"},
                configuration_key="BACKEND_MAX_EXTRACTED_BYTES",
                configuration_file="backend/.env",
                how_to_fix=["Edit backend/.env", "Increase BACKEND_MAX_EXTRACTED_BYTES", "Run ./scripts/upgrade.sh"],
            ))

    if detected_archive_depth is not None:
        depth_ok = detected_archive_depth <= settings.max_archive_depth
        status_checks.append(PreflightStatusCheck(
            label="Within nested archive depth",
            ok=depth_ok,
            detail=f"Detected depth {detected_archive_depth} of {settings.max_archive_depth} allowed",
        ))
        if not depth_ok:
            diagnostics.append(PreflightDiagnostic(
                problem="Nested archives too deep",
                reason=f"This evidence contains archives nested {detected_archive_depth} levels deep, but only {settings.max_archive_depth} is configured.",
                current_configuration={"depth": str(settings.max_archive_depth)},
                required_configuration={"depth": str(detected_archive_depth)},
                configuration_key="MAX_ARCHIVE_DEPTH",
                configuration_file="backend/.env",
                how_to_fix=["Edit backend/.env", "Increase MAX_ARCHIVE_DEPTH", "Run ./scripts/upgrade.sh"],
            ))

    if detected_backing_chain_depth is not None:
        chain_ok = detected_backing_chain_depth <= settings.disk_image_max_chain_depth
        status_checks.append(PreflightStatusCheck(
            label="Within virtual disk chain limit",
            ok=chain_ok,
            detail=f"Detected chain depth {detected_backing_chain_depth} of {settings.disk_image_max_chain_depth} allowed",
        ))
        if not chain_ok:
            diagnostics.append(PreflightDiagnostic(
                problem="Virtual disk backing chain too deep",
                reason=f"This virtual disk references a backing-file chain {detected_backing_chain_depth} levels deep, but only {settings.disk_image_max_chain_depth} is configured.",
                current_configuration={"depth": str(settings.disk_image_max_chain_depth)},
                required_configuration={"depth": str(detected_backing_chain_depth)},
                configuration_key="DISK_IMAGE_MAX_CHAIN_DEPTH",
                configuration_file="backend/.env",
                how_to_fix=["Edit backend/.env", "Increase DISK_IMAGE_MAX_CHAIN_DEPTH", "Run ./scripts/upgrade.sh"],
            ))

    low_confidence = classification_confidence in {"low"} or classification_category_value == "unknown"
    if low_confidence:
        status_checks.append(PreflightStatusCheck(
            label="Classification confidence",
            ok=False,
            detail="We could not confidently determine the evidence type.",
        ))
        diagnostics.append(PreflightDiagnostic(
            problem="Low confidence classification",
            reason="We could not confidently determine the evidence type. You can continue with a manual override.",
            how_to_fix=["Use the Advanced options override to set platform/classification manually"],
        ))

    if any(not check.ok for check in status_checks if check.label in {"Supported", "Within upload limit", "Enough storage", "Within extraction limit", "Within nested archive depth", "Within virtual disk chain limit"}):
        overall_status = "blocked"
    elif low_confidence or warnings:
        overall_status = "warning"
    else:
        overall_status = "ready"

    classification = PreflightClassification(
        category=classification_category_value,
        format_key=format_key,
        confidence=classification_confidence,
        reason=classification_reason,
        chain=chain,
        platform=platform,
        hostname=hostname,
        distro=distro,
        version=version,
        volumes=volumes_count,
        installations=installations_count,
        expected_parsers=expected_parsers,
        warnings=warnings,
    )

    return PreflightReport(
        token=token,
        original_filename=original_filename,
        classification=classification,
        pipeline_preview=pipeline_preview,
        resource_check=resource_check,
        status=overall_status,
        status_checks=status_checks,
        diagnostics=diagnostics,
    )
