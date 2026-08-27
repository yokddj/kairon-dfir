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
from typing import Any, Callable

from app.core.timing import timed_phase

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
    PreflightVolumeDiagnostic,
    PreflightWarning,
)

# The file an operator must actually edit to change a limit. docker-compose
# loads config/defaults.env first and this second, so this is the one that
# wins -- and the one that exists: the diagnostics used to name "backend/.env",
# which is not present in the deployment at all, so following the instructions
# to the letter changed nothing and the upload stayed blocked.
SETTINGS_OVERRIDE_FILE = ".env"


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


_BLOCKING_CHECK_LABELS = {
    "Supported",
    "Within upload limit",
    "Enough storage",
    "Within extraction limit",
    "Within nested archive depth",
    "Within virtual disk chain limit",
}

_CONTAINER_LABELS = {"zip": "ZIP archive", "7z": "7-Zip archive", "directory": "Folder"}


def _duration_bucket(seconds: int | None) -> str | None:
    """Honest, conservative estimate bucket - never implies false progress."""
    if seconds is None:
        return None
    if seconds < 120:
        return "fast"
    if seconds < 1200:
        return "medium"
    if seconds < 7200:
        return "long"
    return "very_long"


def _classify_warning(message: str) -> PreflightWarning:
    lowered = message.lower()
    if any(word in lowered for word in ("fail", "error", "could not", "unreadable", "encrypted")):
        return PreflightWarning(message=message, severity="recommendation")
    return PreflightWarning(message=message, severity="information")


_DETECTED_SIGNATURE_LABELS = {
    "lvm2_physical_volume": "LVM2 physical volume",
}

_STATUS_LABELS = {"readable": "readable", "encrypted_volume": "encrypted", "unreadable_volume": "unreadable"}


def _is_raw_numeric_identifier(value: Any) -> bool:
    """pytsk3's filesystem-type detection occasionally yields a bare numeric
    code instead of a name (an underlying pytsk3 binding quirk, not
    something this translation layer changes or investigates further) --
    never surface that raw number to an analyst; treat it the same as "no
    known name" everywhere a filesystem name is shown."""
    return bool(value) and str(value).isdigit()


def _collect_display_filesystems(volumes: list[dict]) -> list[str]:
    """The distinct, analyst-facing filesystem names across every
    discovered volume (partition or logical volume) -- used for the
    classification summary's "Filesystems:" line. Excludes a raw numeric
    filesystem-type code the same way _translate_volume_diagnostic does
    for a single volume's own row, and preserves first-seen order."""
    return list(dict.fromkeys(str(v["filesystem_type"]) for v in volumes if v.get("filesystem_type") and not _is_raw_numeric_identifier(v.get("filesystem_type"))))


def _translate_volume_diagnostics(volumes: list[dict]) -> list[PreflightVolumeDiagnostic]:
    """Translate every raw volume dict from
    app.disk_images.service._discover_raw_volumes into analyst-facing
    diagnostics, as a batch (rather than one at a time) so an LVM
    container can be correlated with the logical volumes discovered
    inside it (see _discover_logical_volumes' "lvm" metadata marker) --
    a container that was successfully parsed, with its logical volumes
    opened, is presented as a successful discovery rather than a warning,
    and a logical volume itself is labeled distinctly from a partition."""
    children_by_container: dict[int, list[dict]] = {}
    for entry in volumes:
        lvm_marker = (entry.get("metadata") or {}).get("lvm")
        if lvm_marker:
            children_by_container.setdefault(int(lvm_marker["container_partition_index"]), []).append(entry)
    return [
        _translate_volume_diagnostic(volume, children=children_by_container.get(int(volume.get("partition_index") or 0), []))
        for volume in volumes
    ]


def _translate_volume_diagnostic(volume: dict, *, children: list[dict]) -> PreflightVolumeDiagnostic:
    """Translate one raw volume dict. Never surfaces volume["error"]["message"]
    (a raw pytsk3/Python exception string) -- only the small set of
    already-computed, already-known fields (status, filesystem_type,
    encrypted, metadata.encryption_type, metadata.container_signature,
    metadata.lvm) is used to build a plain-language explanation.

    children is every logical-volume entry _discover_logical_volumes found
    inside this volume, if this volume is itself an LVM Physical Volume --
    always empty for a plain partition or a logical volume."""
    status = str(volume.get("status") or "unknown")
    filesystem = volume.get("filesystem_type")
    if _is_raw_numeric_identifier(filesystem):
        filesystem = None
    metadata = volume.get("metadata") or {}
    signature_key = metadata.get("container_signature")
    detected_signature = _DETECTED_SIGNATURE_LABELS.get(signature_key) if signature_key else None
    lvm_marker = metadata.get("lvm")

    if lvm_marker:
        # This volume IS a logical volume, not a partition -- its own
        # readable/unreadable/encrypted outcome is translated the same way
        # a partition's is, just labeled distinctly (see kind/name/
        # container_volume_id below) so the UI can show it nested under
        # the Physical Volume it was found inside of.
        if status == "readable":
            explanation = f"Readable {filesystem} filesystem." if filesystem else "Readable filesystem."
        elif status == "encrypted_volume":
            encryption_type = str(metadata.get("encryption_type") or "").upper()
            label = {"luks": "LUKS", "bitlocker": "BitLocker"}.get(metadata.get("encryption_type"), encryption_type or "an unknown scheme")
            explanation = f"Encrypted logical volume ({label}). Kairon cannot inspect an encrypted volume's contents without the decryption key or passphrase."
        else:
            explanation = "Kairon could not identify a supported filesystem inside this logical volume, so operating system detection cannot continue inside it."
        return PreflightVolumeDiagnostic(
            volume_id=int(volume.get("partition_index") or 0),
            size_bytes=volume.get("length_bytes"),
            filesystem=filesystem,
            ok=status == "readable",
            status=_STATUS_LABELS.get(status, "unreadable"),
            explanation=explanation,
            detected_signature=None,
            kind="logical_volume",
            name=str(lvm_marker.get("logical_volume") or "") or None,
            container_volume_id=int(lvm_marker.get("container_partition_index") or 0),
        )

    if signature_key == "lvm2_physical_volume" and children:
        # Parsing succeeded and at least one logical volume was found
        # inside -- a real, successful discovery, not a warning, even
        # though this container row itself was never opened as a
        # filesystem (see _discover_logical_volumes). Do not imply total
        # failure when only some logical volumes were readable.
        readable_children = sum(1 for child in children if child.get("status") == "readable")
        total_children = len(children)
        if readable_children == total_children:
            explanation = (
                "LVM2 physical volume, parsed successfully. Its logical volume was read as a supported filesystem -- see below."
                if total_children == 1
                else f"LVM2 physical volume, parsed successfully. All {total_children} logical volumes found inside were read as supported filesystems -- see below."
            )
        elif readable_children > 0:
            explanation = f"LVM2 physical volume, parsed successfully. {readable_children} of {total_children} logical volumes found inside were read as supported filesystems -- see below."
        else:
            explanation = f"LVM2 physical volume, parsed successfully. {total_children} logical volume(s) were found inside, but none could be read as a supported filesystem -- see below."
        return PreflightVolumeDiagnostic(
            volume_id=int(volume.get("partition_index") or 0),
            size_bytes=volume.get("length_bytes"),
            filesystem=None,
            ok=readable_children > 0,
            status="container",
            explanation=explanation,
            detected_signature=detected_signature,
            kind="partition",
            name=None,
            container_volume_id=None,
        )

    # A plain partition, or an LVM signature that could not be parsed (or
    # had no logical volumes discovered inside it -- e.g. a Volume Group
    # spanning more than one Physical Volume, out of scope for V1) --
    # unchanged from before PR3: today's diagnostic exactly as it always
    # was, since nothing new was actually discovered in that case.
    if status == "readable":
        explanation = f"Readable {filesystem} filesystem." if filesystem else "Readable filesystem."
    elif status == "encrypted_volume":
        encryption_type = str(metadata.get("encryption_type") or "").upper()
        label = {"luks": "LUKS", "bitlocker": "BitLocker"}.get(metadata.get("encryption_type"), encryption_type or "an unknown scheme")
        explanation = f"Encrypted volume ({label}). Kairon cannot inspect an encrypted volume's contents without the decryption key or passphrase."
    elif status == "unreadable_volume":
        if detected_signature:
            explanation = f"Detected signature: {detected_signature}. Kairon does not currently parse this container format, so operating system detection cannot continue inside this volume."
        else:
            explanation = "Unsupported filesystem. Kairon could not identify a supported filesystem in this volume, so operating system detection cannot continue inside it."
    else:
        explanation = "This volume could not be inspected."

    return PreflightVolumeDiagnostic(
        volume_id=int(volume.get("partition_index") or 0),
        size_bytes=volume.get("length_bytes"),
        filesystem=filesystem,
        ok=status == "readable",
        status=_STATUS_LABELS.get(status, "unreadable"),
        explanation=explanation,
        detected_signature=detected_signature,
        kind="partition",
        name=None,
        container_volume_id=None,
    )


def _resolve_upload_limit(category: str) -> int:
    settings = get_settings()
    if category == EvidenceCategory.MEMORY_DUMP.value:
        # Mirror the resolution used by the dedicated memory upload pipeline
        # (app.services.memory.upload_readiness/upload_sessions/validation)
        # so a memory image is subject to the same limit regardless of
        # whether it was uploaded via Memory Overview or the evidence
        # wizard's memory_dump intake. memory_max_upload_size is a legacy
        # fallback (2 GiB) that predates memory_upload_max_bytes (the
        # actively configured, validated 32 GiB default) and must not be
        # used as the primary limit here.
        return int(settings.memory_upload_max_bytes or settings.memory_max_upload_size)
    return int(settings.backend_max_upload_size)


def run_preflight(
    path: Path,
    *,
    token: str,
    original_filename: str,
    declared_platform: str | None,
    tmp_dir: Path,
    on_stage: Callable[[str], None] | None = None,
) -> PreflightReport:
    """Inspect a staged evidence file/folder and return a full preflight report.

    path: the staged file or directory to inspect (already on local disk).
    tmp_dir: a disposable scratch directory owned by the caller; this
      function may write small peek files under it but never anything
      resembling a real extraction, and never touches the database.
    on_stage: optional best-effort progress callback, fired right before
      each of this function's real (already timed_phase-instrumented) work
      phases starts. Purely observational -- exists so a DB-aware caller
      can mirror live stage progress into something a client can poll
      (see evidence_upload_session.py's finalize path), without this
      module importing a Session or knowing anything about persistence.
    """
    settings = get_settings()
    classifier = get_evidence_classifier()
    is_directory = path.is_dir()
    file_size = sum(f.stat().st_size for f in path.rglob("*") if f.is_file()) if is_directory else path.stat().st_size

    diagnostics: list[PreflightDiagnostic] = []
    status_checks: list[PreflightStatusCheck] = []

    if on_stage:
        on_stage("classifying")
    if is_directory:
        classification_category = EvidenceCategory.ARCHIVE
        classification_confidence = "high"
        classification_reason = "Folder selected for ingestion"
        format_key = "folder"
    else:
        with timed_phase("preflight.classify", token=token, file_size=file_size):
            result = classifier.classify(path)
        classification_category = result.category
        classification_confidence = result.confidence
        classification_reason = result.reason
        format_key = result.format_key

    chain: list[str] = []
    platform = declared_platform or EvidencePlatform.unknown.value
    hostname = distro = version = None
    volumes_count = installations_count = partitions_count = logical_volumes_count = None
    container_label: str | None = None
    contained_object: str | None = None
    filesystems: list[str] = []
    expected_parsers: list[str] = []
    estimated_extracted_bytes: int | None = None
    estimated_temp_storage_bytes: int | None = None
    detected_archive_depth: int | None = None
    detected_backing_chain_depth: int | None = None
    estimated_artifact_count: int | None = None
    warnings: list[str] = []
    volume_diagnostics: list[PreflightVolumeDiagnostic] = []

    is_openable_container = is_directory or classification_category == EvidenceCategory.ARCHIVE
    if is_openable_container:
        chain.append("Archive" if not is_directory else "Folder")
        if on_stage:
            on_stage("inspecting_evidence")
        try:
            with timed_phase("preflight.inspect_archive_or_folder", token=token, file_size=file_size):
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
            container_label = _CONTAINER_LABELS.get(info["container_type"], info["container_type"])
            if platform not in {EvidencePlatform.unknown.value, EvidencePlatform.mixed.value}:
                contained_object = f"{distro or platform.title()} artifact collection ({info['expected_artifact_count']} matched file(s))"
            else:
                contained_object = f"Unclassified file collection ({info['entry_count']} file(s))"
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
        if on_stage:
            on_stage("inspecting_evidence")
        with timed_phase("preflight.inspect_disk_image_readonly", token=token, file_size=file_size):
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
            logical_volume_entries = [v for v in volumes if v.get("partition_type") == "lvm2_logical_volume"]
            # "Partitions" means real partition-table entries only -- a
            # Logical Volume is not one (see _discover_logical_volumes), so
            # it must not inflate this count. logical_volumes_count is
            # deliberately left None (hidden by the frontend) rather than 0
            # when there is nothing LVM-related to report, so a Windows/
            # macOS/non-LVM Linux image's preview is completely unchanged.
            partitions_count = volumes_count - len(logical_volume_entries)
            logical_volumes_count = len(logical_volume_entries) or None
            installations_count = len(installs)
            filesystems = _collect_display_filesystems(volumes)
            estimated_extracted_bytes = sum(int(v.get("length_bytes") or 0) for v in volumes)
            # RAW never materializes a temporary file (pytsk3 reads the
            # upload directly). EWF no longer does either, as of the
            # pyewf streaming sprint: app.disk_images.ewf_img_info.EwfImgInfo
            # reads directly through pyewf, so there is no flat RAW export
            # left to reserve space for -- see
            # app.disk_images.service._open_disk_image_reader. Every other
            # non-raw format (vmdk/vhd/vhdx/qcow2/vdi) is unchanged: it
            # still fully materializes a temporary RAW file via
            # qemu-img convert, so this estimate is still the right one
            # to warn about for those.
            estimated_temp_storage_bytes = 0 if format_key in {"raw", "ewf"} else estimated_extracted_bytes
            volume_diagnostics = _translate_volume_diagnostics(volumes)
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
            container_label = f"{(format_key or 'disk').upper()} disk image"
            if installs:
                contained_object = f"{installations_count} OS installation(s) across {volumes_count} volume(s)"
            elif any(not d.ok for d in volume_diagnostics):
                unreadable = sum(1 for d in volume_diagnostics if not d.ok)
                contained_object = f"{volumes_count} volume(s), no OS installation detected ({unreadable} of {volumes_count} could not be read as a supported filesystem)"
            else:
                contained_object = f"{volumes_count} volume(s), no OS installation detected"
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
        # Memory dumps are staged as-is and never run through extraction
        # (app.ingest.archive._enforce_limits is never called for this
        # category) - leaving estimated_extracted_bytes unset avoids a
        # false "Within extraction limit" block against
        # BACKEND_MAX_EXTRACTED_BYTES for large memory images. Staging
        # still needs the full file size of temp storage, so that estimate
        # is kept.
        estimated_temp_storage_bytes = file_size
        expected_parsers = []
        classification_category_value = "memory_dump"
        container_label = "Raw memory capture"
        contained_object = "Memory dump"
        pipeline_preview = [
            "Memory Dump",
            "Evidence Classification",
            "Memory Registration",
            "Memory Analysis (manual, after ingestion)",
        ]
    elif classification_category == EvidenceCategory.AUXILIARY:
        chain.append("Auxiliary")
        platform = EvidencePlatform.unknown.value
        classification_category_value = "auxiliary"
        container_label = format_key.upper() if format_key else "Auxiliary file"
        contained_object = "Volatility profile or support bundle"
        warnings.append("Auxiliary files support analysis but are not standalone disk or memory evidence captures.")
        pipeline_preview = ["Auxiliary", "Support File Registration", "No evidence ingest route"]
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
        estimated_duration_bucket=_duration_bucket(estimated_seconds),
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
    supported_ok = classification_category_value not in {"unknown", "auxiliary"}
    status_checks.append(PreflightStatusCheck(label="Supported", ok=supported_ok, detail=classification_reason))
    if classification_category_value == "auxiliary":
        diagnostics.append(PreflightDiagnostic(
            problem="Auxiliary file is not evidence",
            reason="This file is a support artifact for memory analysis, not a disk or memory evidence capture, so Kairon will not send it to the disk or memory ingest pipelines.",
            how_to_fix=["Import this file through the memory symbol/profile workflow when available."],
            severity="recommendation",
        ))

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
            configuration_key="MEMORY_UPLOAD_MAX_BYTES" if classification_category_value == "memory_dump" else "BACKEND_MAX_UPLOAD_SIZE",
            configuration_file=SETTINGS_OVERRIDE_FILE,
            how_to_fix=[
                f"Edit {SETTINGS_OVERRIDE_FILE}",
                f"Increase {'MEMORY_UPLOAD_MAX_BYTES' if classification_category_value == 'memory_dump' else 'BACKEND_MAX_UPLOAD_SIZE'} to at least {file_size} bytes",
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
            configuration_file=SETTINGS_OVERRIDE_FILE,
            how_to_fix=[
                "Free space on the temp directory's volume",
                "Or move BACKEND_TEMP_DIR to a volume with more free space",
                "Restart the backend after changing BACKEND_TEMP_DIR",
            ],
        ))

    # BACKEND_MAX_EXTRACTED_BYTES guards app.ingest.archive._enforce_limits'
    # real decompression-bomb risk (a small archive expanding to an
    # unbounded number of real bytes on disk) -- a risk that only exists
    # for the "archive" category, which is the only one that ever actually
    # calls that function. Disk images have no such risk (you cannot
    # extract more bytes than the image physically contains) and are
    # already bounded by their own, dedicated, more generous settings
    # (disk_image_max_bytes_per_volume, disk_image_max_files_per_volume,
    # disk_image_virtual_size_max_bytes) -- applying this archive-specific
    # limit to a disk image's total volume size rejected large-but-entirely
    # normal forensic images against the wrong guard. Memory dumps and
    # unknown files already never set estimated_extracted_bytes at all (see
    # above), so this only needed to additionally exclude disk_image.
    extraction_limit_applies = classification_category_value == "archive"
    extraction_ok = not extraction_limit_applies or estimated_extracted_bytes is None or estimated_extracted_bytes <= settings.backend_max_extracted_bytes
    if extraction_limit_applies and estimated_extracted_bytes is not None:
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
                configuration_file=SETTINGS_OVERRIDE_FILE,
                how_to_fix=[f"Edit {SETTINGS_OVERRIDE_FILE}", "Increase BACKEND_MAX_EXTRACTED_BYTES", "Run ./scripts/upgrade.sh"],
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
                configuration_file=SETTINGS_OVERRIDE_FILE,
                how_to_fix=[f"Edit {SETTINGS_OVERRIDE_FILE}", "Increase MAX_ARCHIVE_DEPTH", "Run ./scripts/upgrade.sh"],
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
                configuration_file=SETTINGS_OVERRIDE_FILE,
                how_to_fix=[f"Edit {SETTINGS_OVERRIDE_FILE}", "Increase DISK_IMAGE_MAX_CHAIN_DEPTH", "Run ./scripts/upgrade.sh"],
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
            severity="recommendation",
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
        container=container_label,
        contained_object=contained_object,
        platform=platform,
        hostname=hostname,
        distro=distro,
        version=version,
        volumes=volumes_count,
        partitions=partitions_count,
        logical_volumes=logical_volumes_count,
        filesystems=filesystems,
        installations=installations_count,
        expected_parsers=expected_parsers,
        warnings=[_classify_warning(message) for message in warnings],
        volume_diagnostics=volume_diagnostics,
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
        evidence_options=[],
    )
