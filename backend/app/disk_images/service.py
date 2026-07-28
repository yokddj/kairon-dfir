from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime
import hashlib
import fnmatch
from functools import lru_cache
import json
from pathlib import Path
import shutil
import subprocess
import time
from typing import Any

import pytsk3
from sqlalchemy.orm import Session

from app.core.artifact_registry import artifact_registry_entry
from app.core.config import get_settings
from app.core.storage import sanitize_relative_path
from app.core.timing import timed_phase
from app.disk_images.ewf_img_info import EwfImgInfo, pyewf_available, pyewf_version
from app.disk_images.lvm import LogicalVolumeReader, LVMMetadataError, parse_physical_volume_metadata
from app.disk_images.lvm.img_info import LogicalVolumeImgInfo
from app.disk_images.registry import ewf_series_members, get_image_format_registry
from app.ingest.linux.helpers import looks_like_linux_artifact
from app.ingest.linux.os_detection import detect_linux_release
from app.models.disk_image import DiskImage, DiskVolume, OSInstallation
from app.models.evidence import Evidence, EvidencePlatform
from app.services.parser_registry import get_parser_registry


settings = get_settings()


@dataclass
class MaterializedDiskImage:
    extract_dir: Path
    extracted_files: list[str]
    manifest_entries: list[dict[str, Any]]
    source_map: dict[str, dict[str, Any]]
    disk_image: DiskImage
    volumes: list[DiskVolume]
    installations: list[OSInstallation]
    warnings: list[str]
    errors: list[dict[str, Any]]


class _PytskFileReader(pytsk3.Img_Info):
    def __init__(self, image_path: Path):
        self._file = image_path.open("rb")
        self._size = image_path.stat().st_size
        super().__init__(url=str(image_path))

    def close(self) -> None:
        try:
            self._file.close()
        except Exception:
            pass

    def read(self, offset: int, size: int) -> bytes:
        self._file.seek(offset)
        return self._file.read(size)

    def get_size(self) -> int:
        return self._size


def _open_disk_image_reader(context: dict[str, Any]) -> "_PytskFileReader | EwfImgInfo":
    """Build the pytsk3.Img_Info every downstream reader (volume/LVM
    discovery, installation detection, materialization) will read every
    byte through, based on what adapter.expose_readonly() returned.

    EWF's own adapter (see app.disk_images.ewf.EwfImageAdapter) never
    writes a temporary RAW file -- context["access_strategy"] ==
    "pyewf_streaming_readonly" is how it signals that bytes should come
    directly from EwfImgInfo (pyewf) instead. Every other format
    (raw, vmdk, vhd/vhdx, qcow/qcow2, vdi) is unchanged: it already wrote
    a real file (or, for raw, never needed to), so _PytskFileReader over
    that path is exactly what ran before this sprint.
    """
    if context.get("access_strategy") == "pyewf_streaming_readonly":
        segments = [Path(item) for item in context.get("segments") or []]
        return EwfImgInfo(segments)
    raw_path = Path(str(context.get("exported_raw_path") or context.get("image_path") or ""))
    return _PytskFileReader(raw_path)


def _now() -> datetime:
    return datetime.now(UTC)


def _run_tool(command: list[str], *, timeout: int, cwd: Path | None = None) -> dict[str, Any]:
    completed = subprocess.run(command, capture_output=True, text=True, shell=False, timeout=timeout, cwd=str(cwd) if cwd else None)
    return {
        "command": command,
        "returncode": completed.returncode,
        "stdout": completed.stdout[-4000:],
        "stderr": completed.stderr[-4000:],
    }


def _tool_version(name: str, version_args: list[str] | None = None) -> str | None:
    args = version_args or ["--version"]
    try:
        completed = subprocess.run([name, *args], capture_output=True, text=True, shell=False, timeout=15)
    except (FileNotFoundError, subprocess.SubprocessError):
        return None
    text = (completed.stdout or completed.stderr or "").strip().splitlines()
    return text[0] if text else None


def disk_image_readiness() -> dict[str, Any]:
    registry = get_image_format_registry()
    return {
        "formats": registry.list_capabilities(),
        "tools": {
            "pytsk3": getattr(pytsk3, "__version__", "available"),
            "pyewf": pyewf_version() or ("available" if pyewf_available() else None),
            "mmls": _tool_version("mmls", ["-V"]),
            "fls": _tool_version("fls", ["-V"]),
            "icat": _tool_version("icat", ["-V"]),
            "qemu_img": _tool_version("qemu-img"),
        },
    }


def detect_disk_image_format(path: Path, companions: list[Path] | None = None) -> dict[str, Any] | None:
    return get_image_format_registry().detect(path, companions or [])


def _ewf_companions(path: Path) -> list[Path]:
    if path.suffix.lower() not in {".e01", ".ex01", ".e02", ".e03", ".e04", ".e05"}:
        return [path]
    return ewf_series_members(path)


def _hash_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        while chunk := handle.read(1024 * 1024):
            digest.update(chunk)
    return digest.hexdigest()


def _filesystem_label(fs_info: pytsk3.FS_Info) -> str | None:
    try:
        return str(getattr(fs_info.info, "ftype", "") or "") or None
    except Exception:
        return None


def _filesystem_type(fs_info: pytsk3.FS_Info) -> str | None:
    try:
        return str(fs_info.info.ftype).split(".")[-1].lower()
    except Exception:
        return None


def _safe_reader_read(img: "_PytskFileReader | EwfImgInfo", offset: int, length: int = 4096) -> bytes:
    """Best-effort signature-detection read (encryption/LVM magic bytes)
    against a volume pytsk3 already failed to open as a filesystem --
    never raises, since an unreadable range here just means no signature
    can be identified, not a reason to abort discovery of the rest of
    the image."""
    try:
        return img.read(max(offset, 0), length)
    except Exception:
        return b""


def _detect_encryption_signature(blob: bytes) -> tuple[bool, str | None]:
    if blob.startswith(b"LUKS\xba\xbe"):
        return True, "luks"
    if blob.startswith(b"-FVE-FS-") or b"bitlocker" in blob[:512].lower():
        return True, "bitlocker"
    return False, None


def _detect_lvm_signature(blob: bytes) -> bool:
    """Best-effort identification only -- not LVM support. LVM2's on-disk
    label header carries a fixed "LABELONE" magic string within the first
    few sectors of a physical volume; checking for it is the same
    lightweight, read-only signature match as _detect_encryption_signature
    above. It does not parse any LVM metadata (volume groups, logical
    volumes, extents) and cannot be used to read anything inside the
    container -- it only lets an otherwise-unreadable volume be labeled
    "possible LVM physical volume" instead of a bare "unsupported
    filesystem", when the signature happens to be present."""
    return b"LABELONE" in blob[:4096]


def _read_small_file(fs_info: pytsk3.FS_Info, path: str, limit: int = 32768) -> str:
    try:
        file_obj = fs_info.open(path)
        data = file_obj.read_random(0, limit)
        return data.decode("utf-8", errors="replace")
    except Exception:
        return ""


def _exists(fs_info: pytsk3.FS_Info, path: str) -> bool:
    try:
        fs_info.open(path)
        return True
    except Exception:
        return False


def _detect_installations(fs_info: pytsk3.FS_Info, volume_id: str) -> list[dict[str, Any]]:
    installations: list[dict[str, Any]] = []
    windows_markers = ["/Windows/System32", "/Windows/System32/config/SYSTEM", "/Windows/System32/config/SOFTWARE", "/Users", "/ProgramData"]
    linux_markers = ["/etc/os-release", "/etc/passwd", "/var/log", "/var/lib/systemd", "/home", "/boot"]
    if sum(1 for marker in windows_markers if _exists(fs_info, marker)) >= 3:
        installations.append(
            {
                "platform": EvidencePlatform.windows.value,
                "hostname": None,
                "version": None,
                "distro": None,
                "root_path": "/",
                "confidence": "high",
                "detection_reasons": windows_markers,
            }
        )
    release_markers = {
        path: _read_small_file(fs_info, path)
        for path in (
            "/etc/os-release",
            "/usr/lib/os-release",
            "/etc/lsb-release",
            "/etc/issue",
            "/etc/debian_version",
            "/etc/redhat-release",
            "/etc/centos-release",
            "/etc/fedora-release",
            "/etc/arch-release",
        )
    }
    os_release = release_markers["/etc/os-release"] or release_markers["/usr/lib/os-release"]
    if os_release or sum(1 for marker in linux_markers if _exists(fs_info, marker)) >= 3:
        hostname_content = _read_small_file(fs_info, "/etc/hostname", limit=4096)
        hostname = hostname_content.splitlines()[0].strip() if hostname_content else None
        release = detect_linux_release(release_markers)
        installations.append(
            {
                "platform": EvidencePlatform.linux.value,
                "hostname": hostname,
                "version": release.version,
                "distro": release.distribution,
                "root_path": "/",
                "confidence": release.confidence if release.distribution else ("high" if os_release else "medium"),
                "detection_reasons": release.reasons + [marker for marker in linux_markers if _exists(fs_info, marker)],
            }
        )
    return installations


# Base + per-container multiplier for a logical volume's synthetic
# partition_index (see _logical_volume_partition_index below). Real
# partition_index values come from pytsk3.Volume_Info's own entry count,
# which is always small (a real partition table never has anywhere close
# to 10,000,000 entries), so this range can never collide with one.
_LVM_LOGICAL_VOLUME_INDEX_BASE = 10_000_000
_LVM_LOGICAL_VOLUME_INDEX_STRIDE = 100_000


def _logical_volume_partition_index(container_partition_index: int, lv_sequence: int) -> int:
    """A deterministic, collision-free partition_index for the lv_sequence-th
    (1-based) logical volume found inside the Physical Volume at
    container_partition_index. Logical volumes need their own partition_index
    values (DiskVolume.partition_index is the join key installs/materialize
    use to find their volume) that can never collide with a real
    partition-table entry's own index."""
    return _LVM_LOGICAL_VOLUME_INDEX_BASE + container_partition_index * _LVM_LOGICAL_VOLUME_INDEX_STRIDE + lv_sequence


def _open_logical_volume_fs_info(read_physical, logical_volume_name: str) -> pytsk3.FS_Info:
    """Parse a Physical Volume's metadata (via read_physical, an
    offset-0-relative ByteRangeReader already bound to that PV's own start)
    and build a pytsk3.FS_Info for the one logical volume named
    logical_volume_name. Used only by _open_persisted_volume_fs_info (see
    below), for materialize_disk_image_sources's second, independent open --
    that call site only has a persisted DiskVolume's metadata_json to
    reconstruct from, not the original in-memory PhysicalVolumeMetadata/
    VolumeGroup objects _discover_logical_volumes built the first time.
    _discover_logical_volumes itself does not call this: it already has the
    parsed VolumeGroup in hand and constructs each logical volume's reader
    directly, without a second parse."""
    pv_metadata = parse_physical_volume_metadata(read_physical)
    logical_volume = next((lv for lv in pv_metadata.volume_group.logical_volumes if lv.name == logical_volume_name), None)
    if logical_volume is None:
        raise ValueError(f"logical volume {logical_volume_name!r} not found while reparsing volume group {pv_metadata.volume_group.name!r}")
    reader = LogicalVolumeReader(logical_volume, pv_metadata.volume_group, read_physical)
    return pytsk3.FS_Info(LogicalVolumeImgInfo(reader))


def _discover_logical_volumes(
    img: "_PytskFileReader",
    *,
    container_offset_bytes: int,
    container_partition_index: int,
    volumes: list[dict[str, Any]],
    installs: list[dict[str, Any]],
) -> None:
    """If the Physical Volume at container_offset_bytes (within img) has
    parseable LVM2 metadata, attempt to open every logical volume it
    declares independently, appending a "volume" dict (and any detected
    installation) to volumes/installs in exactly the same shape
    _discover_raw_volumes already uses for a real partition-table entry --
    no downstream code (installation detection, materialization, the
    DiskVolume/OSInstallation models, preflight's diagnostic translation)
    needs to know a given entry came from a logical volume rather than a
    partition.

    Deliberately silent on any failure: a metadata parse failure, a Volume
    Group spanning more than one Physical Volume (multi-PV logical-volume
    reading is out of scope for V1 -- see the architecture RFC), or any
    other unexpected exception all simply return without adding anything,
    leaving the caller's own diagnostic for container_partition_index (the
    existing "possible LVM physical volume" unreadable-volume diagnostic)
    completely untouched. There is deliberately no separate "partially
    supported" status -- either every logical volume gets attempted, or
    none of them do.
    """

    def read_physical(offset: int, size: int) -> bytes:
        return img.read(container_offset_bytes + offset, size)

    try:
        pv_metadata = parse_physical_volume_metadata(read_physical)
    except Exception:
        return

    volume_group = pv_metadata.volume_group
    if len(volume_group.physical_volumes) > 1:
        return

    for lv_sequence, logical_volume in enumerate(volume_group.logical_volumes, start=1):
        lv_index = _logical_volume_partition_index(container_partition_index, lv_sequence)
        lv_size_bytes = logical_volume.extent_count * volume_group.extent_size_bytes
        lv_metadata = {
            "lvm": {
                "container_partition_index": container_partition_index,
                "container_offset_bytes": container_offset_bytes,
                "volume_group": volume_group.name,
                "logical_volume": logical_volume.name,
            }
        }
        try:
            reader = LogicalVolumeReader(logical_volume, volume_group, read_physical)
            fs_info = pytsk3.FS_Info(LogicalVolumeImgInfo(reader))
            lv_volume = {
                "partition_index": lv_index,
                "offset_bytes": container_offset_bytes,
                "length_bytes": lv_size_bytes,
                "partition_type": "lvm2_logical_volume",
                "filesystem_type": _filesystem_type(fs_info),
                "label": _filesystem_label(fs_info),
                "uuid": logical_volume.id,
                "encrypted": False,
                "readable": True,
                "status": "readable",
                "warnings": [],
                "error": {},
                "metadata": lv_metadata,
            }
            detected = _detect_installations(fs_info, str(lv_index))
            for install in detected:
                installs.append({**install, "partition_index": lv_index})
        except Exception as exc:
            lv_volume = {
                "partition_index": lv_index,
                "offset_bytes": container_offset_bytes,
                "length_bytes": lv_size_bytes,
                "partition_type": "lvm2_logical_volume",
                "filesystem_type": None,
                "label": None,
                "uuid": logical_volume.id,
                "encrypted": False,
                "readable": False,
                "status": "unreadable_volume",
                "warnings": [],
                # error.message is server-side/log-only, same convention as
                # every other unreadable-volume diagnostic in this module --
                # never surfaced raw to the analyst (see
                # evidence_preflight._translate_volume_diagnostic).
                "error": {"code": "unsupported_filesystem", "message": str(exc)},
                "metadata": lv_metadata,
            }
        volumes.append(lv_volume)


@dataclass
class WalkStats:
    """Counters for one _iter_directory walk. Exists so the two conditions
    this walker now refuses to follow (deleted names, traversal cycles) are
    *reported as numbers* rather than as one log line per occurrence -- on
    this sprint's Webserver.E01, 95,894 of the 180,691 directory entries
    inspected (53%) are deleted, so per-entry logging would be pure spam."""

    directories_opened: int = 0
    entries_inspected: int = 0
    allocated_entries_followed: int = 0
    unallocated_entries_skipped: int = 0
    cycles_prevented: int = 0
    max_depth_truncations: int = 0


def _is_allocated_entry(entry) -> bool:
    """Whether a pytsk3 directory entry is a *live* name in the filesystem.

    TSK reports a deleted directory entry with TSK_FS_NAME_FLAG_UNALLOC on
    the name (independently of the inode's own allocation state: the name
    can be deleted while the inode it once pointed to has already been
    recycled by a completely unrelated, live object). Materialization
    reproduces the *live* filesystem, so a deleted name is not a path that
    exists and must not be followed -- see _iter_directory for what
    following one actually did.

    Deliberately conservative: only a positively-set UNALLOC bit makes this
    return False. Missing or malformed flags mean "we do not know", and the
    walker then keeps the entry, because wrongly dropping a live forensic
    path is a far worse failure than wrongly keeping a dead one. Recovering
    deleted files is explicitly not what this path does -- that would be a
    separate capability with its own provenance semantics."""
    name = getattr(getattr(entry, "info", None), "name", None)
    flags = getattr(name, "flags", None)
    if flags is None:
        return True
    try:
        return not (int(flags) & int(pytsk3.TSK_FS_NAME_FLAG_UNALLOC))
    except (TypeError, ValueError):
        return True


def _entry_inode(entry) -> int | None:
    """Inode address behind a directory entry, or None when unavailable."""
    meta = getattr(getattr(entry, "info", None), "meta", None)
    addr = getattr(meta, "addr", None)
    if addr is None:
        return None
    try:
        return int(addr)
    except (TypeError, ValueError):
        return None


def _directory_inode(directory) -> int | None:
    """Inode address of an already-opened pytsk3 Directory, or None."""
    meta = getattr(getattr(getattr(directory, "info", None), "fs_file", None), "meta", None)
    addr = getattr(meta, "addr", None)
    if addr is None:
        return None
    try:
        return int(addr)
    except (TypeError, ValueError):
        return None


def _iter_directory(
    fs_info: pytsk3.FS_Info,
    directory_path: str,
    *,
    depth: int,
    max_depth: int,
    ancestor_inodes: set[int] | None = None,
    stats: WalkStats | None = None,
):
    """Walk the live allocated tree under directory_path.

    Two rules keep this walk linear in the size of the *live* tree, and both
    exist because of a measured failure on a real ext4 image (see this
    sprint's report):

    1. Deleted names are not followed (_is_allocated_entry). A deleted entry
       whose inode has since been recycled points at whatever object owns
       that inode *now* -- which can be a directory somewhere else entirely,
       including one of this path's own ancestors.

    2. A directory whose inode is already on the current ancestor chain is
       not descended into. Rule 1 removes the known cause of that situation,
       but the guard is what makes the walk terminate by construction rather
       than by luck: any future path that produces a loop (corrupt metadata,
       an image type with different semantics) is bounded here instead of
       replicating whole subtrees.

    Before both rules, one such recycled-inode entry made the walker re-enter
    an ancestor and reproduce the entire root tree beneath a phantom path,
    recursively, bounded only by max_depth -- 97% of the files it produced
    were duplicates living at paths that do not exist in the filesystem.

    The guard is an *ancestor chain*, not a global visited set: a directory
    reachable from two unrelated branches is still walked in both, so nothing
    legitimately reachable is suppressed. max_depth stays exactly as it was,
    as an independent bound, and is no longer load-bearing for termination."""
    if stats is None:
        stats = WalkStats()
    if ancestor_inodes is None:
        ancestor_inodes = set()
    if depth > max_depth:
        stats.max_depth_truncations += 1
        return
    try:
        directory = fs_info.open_dir(path=directory_path)
    except Exception:
        return
    stats.directories_opened += 1
    own_inode = _directory_inode(directory)
    # An inode we cannot identify cannot be guarded against; the walk still
    # terminates on max_depth in that case, exactly as it always did.
    pushed = own_inode is not None and own_inode not in ancestor_inodes
    if pushed:
        ancestor_inodes.add(own_inode)
    try:
        for entry in directory:
            try:
                name = entry.info.name.name.decode("utf-8", errors="replace")
            except Exception:
                continue
            if name in {".", ".."}:
                continue
            stats.entries_inspected += 1
            if not _is_allocated_entry(entry):
                # Skipped before the entry is yielded and before it is ever
                # opened as a directory, so a deleted name never reaches the
                # extractor and never costs a directory read.
                stats.unallocated_entries_skipped += 1
                continue
            stats.allocated_entries_followed += 1
            meta = getattr(entry.info, "meta", None)
            full_path = f"{directory_path.rstrip('/')}/{name}" if directory_path != "/" else f"/{name}"
            is_dir = bool(meta and meta.type == pytsk3.TSK_FS_META_TYPE_DIR)
            yield full_path, entry, is_dir
            if is_dir:
                child_inode = _entry_inode(entry)
                if child_inode is not None and child_inode in ancestor_inodes:
                    stats.cycles_prevented += 1
                    continue
                yield from _iter_directory(
                    fs_info,
                    full_path,
                    depth=depth + 1,
                    max_depth=max_depth,
                    ancestor_inodes=ancestor_inodes,
                    stats=stats,
                )
    finally:
        # Unwinding must drop this directory's identity even when the caller
        # abandons the generator early (_materialize_volume_installation
        # breaks out of the walk on its max-files/max-bytes limits), so a
        # later sibling branch is never wrongly treated as a cycle.
        if pushed:
            ancestor_inodes.discard(own_inode)


_LINUX_DISK_EXTRA_SOURCE_PATTERNS = (
    "*/usr/lib/os-release",
    "*/etc/lsb-release",
    "*/etc/debian_version",
    "*/etc/issue",
    "*/var/log/apt/term.log*",
    "*/var/lib/dpkg/status",
    "*/var/lib/snapd/*",
)


@lru_cache(maxsize=1)
def _registry_source_patterns() -> tuple[str, ...]:
    patterns: list[str] = []
    for entry in get_parser_registry().values():
        if str(entry.get("artifact_type") or "").startswith("linux_"):
            patterns.extend(str(pattern) for pattern in entry.get("source_patterns") or [])
    patterns.extend(_LINUX_DISK_EXTRA_SOURCE_PATTERNS)
    return tuple(dict.fromkeys(patterns))


def _matches_source_pattern(path: str, pattern: str) -> bool:
    normalized = "/" + path.replace("\\", "/").lstrip("/")
    return fnmatch.fnmatch(normalized.lower(), pattern.lower())


def _should_materialize(path: str) -> bool:
    lower_path = path.lower()
    if looks_like_linux_artifact(path):
        return True
    if any(_matches_source_pattern(path, pattern) for pattern in _registry_source_patterns()):
        return True
    legacy_patterns = (
        "/windows/system32/config/system",
        "/windows/system32/config/software",
        "/windows/system32/winevt/logs/",
        "/users/",
        "/programdata/",
        "hostnamectl.txt",
        "/logs/journal",
    )
    return any(pattern in lower_path for pattern in legacy_patterns)


# How often (wall-clock seconds) _materialize_volume_installation's walk
# below touches progress_cb, purely to keep the ingest heartbeat alive --
# see that function's own comment for why this exists. Generous margin
# under job_watchdog.py's STALE_INGEST_HEARTBEAT_SECONDS (600s).
_MATERIALIZE_PROGRESS_INTERVAL_SECONDS = 5.0


def _materialize_volume_installation(
    *,
    fs_info: pytsk3.FS_Info,
    install: OSInstallation,
    disk_image: DiskImage,
    volume: DiskVolume,
    destination_root: Path,
    progress_cb=None,
) -> tuple[list[str], list[dict[str, Any]], dict[str, dict[str, Any]], list[str]]:
    extracted_files: list[str] = []
    manifest_entries: list[dict[str, Any]] = []
    source_map: dict[str, dict[str, Any]] = {}
    warnings: list[str] = []
    install_dir = destination_root / f"volume-{volume.partition_index}" / install.platform
    install_dir.mkdir(parents=True, exist_ok=True)
    file_count = 0
    bytes_written = 0
    last_progress_emit = time.monotonic()
    walk_stats = WalkStats()
    for full_path, entry, is_dir in _iter_directory(
        fs_info,
        install.root_path,
        depth=0,
        max_depth=settings.disk_image_max_directory_depth,
        stats=walk_stats,
    ):
        if progress_cb and (time.monotonic() - last_progress_emit) >= _MATERIALIZE_PROGRESS_INTERVAL_SECONDS:
            # This walk can run long on a real filesystem with many
            # directory entries that never match _should_materialize below
            # -- file_count alone (which only advances on an actual match)
            # can go a long stretch without moving, so this check is keyed
            # on wall-clock time, not file_count, and fires unconditionally
            # on every entry visited, matched or not. Before PR3 (LVM
            # integration), a Logical Volume's own root filesystem was
            # never walked at all (always "unreadable"), so this gap in
            # heartbeat coverage during a long walk never had a chance to
            # matter; a real Linux installation's full root filesystem
            # inside a Logical Volume can now take longer than the ingest
            # watchdog's stale-heartbeat timeout to fully walk, which
            # without this would make the watchdog wrongly declare a
            # perfectly healthy, still-working ingest "orphaned" partway
            # through. The percentage this reports is not meant to be
            # precise -- see extraction_progress in app.workers.tasks,
            # which already treats total_files<=0 as "unknown, don't try
            # to compute a real percentage from these numbers".
            progress_cb(
                {
                    "current_action": "materializing_disk_image_files",
                    "processed_files": file_count,
                    "total_files": 0,
                    "current_path": full_path,
                }
            )
            last_progress_emit = time.monotonic()
        meta = getattr(entry.info, "meta", None)
        if meta and meta.type != pytsk3.TSK_FS_META_TYPE_REG:
            continue
        if is_dir or not _should_materialize(full_path):
            continue
        file_count += 1
        if file_count > settings.disk_image_max_files_per_volume:
            warnings.append("max_files_per_volume_exceeded")
            break
        try:
            relative_path = sanitize_relative_path(full_path.lstrip("/"))
        except ValueError:
            warnings.append(f"skipped_invalid_path:{full_path}")
            continue
        if len(str(relative_path)) > settings.disk_image_max_path_length:
            warnings.append(f"skipped_long_path:{full_path}")
            continue
        target = install_dir / relative_path
        target.parent.mkdir(parents=True, exist_ok=True)
        try:
            file_obj = fs_info.open(full_path)
            size = int(getattr(meta, "size", 0) or 0)
            data = b"" if size == 0 else file_obj.read_random(0, size)
        except Exception:
            warnings.append(f"unreadable_file:{full_path}")
            continue
        bytes_written += len(data)
        if bytes_written > settings.disk_image_max_bytes_per_volume:
            warnings.append("max_bytes_per_volume_exceeded")
            break
        target.write_bytes(data)
        relative_output = str(target.relative_to(destination_root))
        extracted_files.append(relative_output)
        manifest_entries.append({"path": relative_output, "ignored": False, "reason": None, "size": len(data), "status": "extracted", "local_path": str(target)})
        source_map[relative_output] = {
            "disk_image_id": disk_image.id,
            "disk_volume_id": volume.id,
            "os_installation_id": install.id,
            "original_source_path": full_path,
            "logical_source_path": relative_output,
            "acquisition_method": "pytsk3_readonly_materialization",
        }
    # One summary line per condition, never one per entry -- see WalkStats.
    if walk_stats.unallocated_entries_skipped:
        warnings.append(f"skipped_deleted_directory_entries:{walk_stats.unallocated_entries_skipped}")
    if walk_stats.cycles_prevented:
        warnings.append(f"prevented_directory_cycles:{walk_stats.cycles_prevented}")
    return extracted_files, manifest_entries, source_map, warnings


def _discover_raw_volumes(context: dict[str, Any]) -> tuple[list[dict[str, Any]], list[dict[str, Any]], list[str]]:
    img = _open_disk_image_reader(context)
    volumes: list[dict[str, Any]] = []
    installs: list[dict[str, Any]] = []
    warnings: list[str] = []
    try:
        try:
            volume_info = pytsk3.Volume_Info(img)
            for index, partition in enumerate(volume_info, start=1):
                desc = getattr(partition, "desc", b"").decode("utf-8", errors="replace").strip() or None
                flags = int(getattr(partition, "flags", 0) or 0)
                start = int(getattr(partition, "start", 0) or 0)
                length = int(getattr(partition, "len", 0) or 0)
                if length <= 0 or flags != 1:
                    continue
                offset_bytes = start * 512
                volume = {
                    "partition_index": index,
                    "offset_bytes": offset_bytes,
                    "length_bytes": length * 512,
                    "partition_type": desc,
                    "filesystem_type": None,
                    "label": None,
                    "uuid": None,
                    "encrypted": False,
                    "readable": False,
                    "status": "discovered",
                    "warnings": [],
                    "error": {},
                    "metadata": {},
                }
                is_lvm_physical_volume = False
                try:
                    fs_info = pytsk3.FS_Info(img, offset=offset_bytes)
                    volume["filesystem_type"] = _filesystem_type(fs_info)
                    volume["label"] = _filesystem_label(fs_info)
                    volume["readable"] = True
                    volume["status"] = "readable"
                    detected = _detect_installations(fs_info, str(index))
                    for install in detected:
                        installs.append({**install, "partition_index": index})
                except Exception as exc:
                    blob = _safe_reader_read(img, offset_bytes)
                    encrypted, encryption_type = _detect_encryption_signature(blob)
                    volume["encrypted"] = encrypted
                    volume["metadata"]["encryption_type"] = encryption_type
                    if not encrypted and _detect_lvm_signature(blob):
                        volume["metadata"]["container_signature"] = "lvm2_physical_volume"
                        is_lvm_physical_volume = True
                    # error.message is retained for server-side logs/support
                    # only -- evidence_preflight.py's volume-diagnostic
                    # translation never surfaces this raw exception text to
                    # the analyst.
                    volume["error"] = {"code": "unsupported_filesystem", "message": str(exc)}
                    volume["status"] = "encrypted_volume" if encrypted else "unreadable_volume"
                volumes.append(volume)
                if is_lvm_physical_volume:
                    # Appended after the partition's own (unchanged) diagnostic
                    # entry, so a logical volume's row always follows the
                    # Physical Volume it was found inside of.
                    _discover_logical_volumes(
                        img,
                        container_offset_bytes=offset_bytes,
                        container_partition_index=index,
                        volumes=volumes,
                        installs=installs,
                    )
        except Exception:
            try:
                fs_info = pytsk3.FS_Info(img)
                volume = {
                    "partition_index": 0,
                    "offset_bytes": 0,
                    "length_bytes": img.get_size(),
                    "partition_type": "filesystem_image",
                    "filesystem_type": _filesystem_type(fs_info),
                    "label": _filesystem_label(fs_info),
                    "uuid": None,
                    "encrypted": False,
                    "readable": True,
                    "status": "readable",
                    "warnings": [],
                    "error": {},
                    "metadata": {},
                }
                detected = _detect_installations(fs_info, "0")
                for install in detected:
                    installs.append({**install, "partition_index": 0})
                volumes.append(volume)
            except Exception as exc:
                blob = _safe_reader_read(img, 0)
                encrypted, encryption_type = _detect_encryption_signature(blob)
                container_signature = None if encrypted else (_detect_lvm_signature(blob) and "lvm2_physical_volume")
                # Whichever branch: still record this as a discovered
                # (whole-image) volume with a translated status, rather
                # than only a bare warning string containing the raw
                # exception -- evidence_preflight.py's volume-diagnostic
                # translation is what turns this into analyst-facing text.
                volumes.append({
                    "partition_index": 0,
                    "offset_bytes": 0,
                    "length_bytes": img.get_size(),
                    "partition_type": "filesystem_image",
                    "filesystem_type": None,
                    "label": None,
                    "uuid": None,
                    "encrypted": encrypted,
                    "readable": False,
                    "status": "encrypted_volume" if encrypted else "unreadable_volume",
                    "warnings": [],
                    "error": {"code": "encrypted_volume" if encrypted else "unsupported_filesystem", "message": str(exc)},
                    "metadata": {"encryption_type": encryption_type, **({"container_signature": container_signature} if container_signature else {})},
                })
                if container_signature:
                    _discover_logical_volumes(
                        img,
                        container_offset_bytes=0,
                        container_partition_index=0,
                        volumes=volumes,
                        installs=installs,
                    )
        return volumes, installs, warnings
    finally:
        img.close()


def upsert_disk_image_record(db: Session, evidence: Evidence, *, format_key: str, original_filename: str, size_bytes: int, sha256: str | None, segment_count: int, status: str, metadata: dict[str, Any], tool_metadata: dict[str, Any], warnings: list[str], error: dict[str, Any]) -> DiskImage:
    disk_image = db.query(DiskImage).filter(DiskImage.evidence_id == evidence.id).one_or_none()
    now = _now().replace(tzinfo=None)
    if disk_image is None:
        disk_image = DiskImage(
            evidence_id=evidence.id,
            original_filename=original_filename,
            format=format_key,
            size_bytes=size_bytes,
            sha256=sha256,
            segment_count=segment_count,
            status=status,
            metadata_json=metadata,
            tool_metadata=tool_metadata,
            warnings_json=warnings,
            error_json=error,
            created_at=now,
            updated_at=now,
        )
        db.add(disk_image)
        db.flush()
    else:
        disk_image.original_filename = original_filename
        disk_image.format = format_key
        disk_image.size_bytes = size_bytes
        disk_image.sha256 = sha256
        disk_image.segment_count = segment_count
        disk_image.status = status
        disk_image.metadata_json = metadata
        disk_image.tool_metadata = tool_metadata
        disk_image.warnings_json = warnings
        disk_image.error_json = error
        disk_image.updated_at = now
        db.flush()
    return disk_image


def _open_persisted_volume_fs_info(image_reader: "_PytskFileReader", volume: DiskVolume) -> pytsk3.FS_Info:
    """Reopen a pytsk3.FS_Info for an already-persisted DiskVolume, for
    materialization. A plain partition is reopened exactly as before (a flat
    byte offset into the raw image); a logical volume -- identified by the
    "lvm" marker _discover_logical_volumes left in metadata_json -- is not a
    single contiguous byte range in the raw image in general, so its owning
    Physical Volume's metadata is reparsed (cheap: a few KB of text) and the
    same LogicalVolumeReader/LogicalVolumeImgInfo chain is rebuilt instead.
    Callers already treat any exception from this the same way regardless of
    which path was taken (skip materializing this volume this run)."""
    lvm_marker = (volume.metadata_json or {}).get("lvm")
    if lvm_marker:
        container_offset_bytes = int(lvm_marker["container_offset_bytes"])
        logical_volume_name = str(lvm_marker["logical_volume"])

        def read_physical(offset: int, size: int) -> bytes:
            return image_reader.read(container_offset_bytes + offset, size)

        return _open_logical_volume_fs_info(read_physical, logical_volume_name)
    if volume.partition_index != 0 or volume.offset_bytes:
        return pytsk3.FS_Info(image_reader, offset=int(volume.offset_bytes))
    return pytsk3.FS_Info(image_reader)


def materialize_disk_image_sources(db: Session, evidence: Evidence, *, extract_dir: Path, image_path: Path | None = None, progress_cb=None) -> MaterializedDiskImage:
    stored_path = image_path or Path(evidence.stored_path)
    extract_dir.mkdir(parents=True, exist_ok=True)
    registry = get_image_format_registry()
    companions = _ewf_companions(stored_path)
    detected = registry.detect(stored_path, companions)
    if not detected:
        raise ValueError("unknown_format")
    adapter = registry.get(str(detected.get("format") or ""))
    if adapter is None:
        raise ValueError("unknown_format")
    if progress_cb:
        progress_cb({"current_action": "detecting_format"})
    readiness = adapter.readiness()
    validation = adapter.validate_segments(stored_path, companions)
    if not validation.get("valid", True):
        disk_image = upsert_disk_image_record(
            db,
            evidence,
            format_key=adapter.key,
            original_filename=stored_path.name,
            size_bytes=sum(item.stat().st_size for item in companions if item.exists()),
            sha256=evidence.sha256,
            segment_count=len(companions),
            status="failed",
            metadata={"validation": validation},
            tool_metadata={"adapter": adapter.key},
            warnings=[],
            error={"code": validation.get("error"), "validation": validation},
        )
        db.commit()
        raise ValueError(str(validation.get("error") or "invalid_segment_set"))
    if progress_cb:
        progress_cb({"current_action": "hashing"})
    segment_hashes = [{"name": item.name, "sha256": _hash_file(item), "size_bytes": item.stat().st_size} for item in companions]
    combined_sha256 = evidence.sha256 if len(companions) == 1 else hashlib.sha256(json.dumps(segment_hashes, sort_keys=True).encode("utf-8")).hexdigest()
    disk_image = upsert_disk_image_record(
        db,
        evidence,
        format_key=adapter.key,
        original_filename=stored_path.name,
        size_bytes=sum(item.stat().st_size for item in companions if item.exists()),
        sha256=combined_sha256,
        segment_count=len(companions),
        status="inspecting_image",
        metadata={"segments": [item.name for item in companions]},
        tool_metadata={"adapter": adapter.key, "operations": [{"step": "hashing", "segment_hashes": segment_hashes}]},
        warnings=[],
        error={},
    )
    db.flush()
    workspace = extract_dir.parent / f"disk-image-{evidence.id}"
    workspace.mkdir(parents=True, exist_ok=True)
    inspect_metadata = adapter.inspect(stored_path, companions)
    if isinstance(inspect_metadata, dict):
        disk_image.metadata_json = {**(disk_image.metadata_json or {}), **{k: v for k, v in inspect_metadata.items() if k not in {"format", "supported", "path", "validation", "segments"}}}
    context: dict[str, Any] | None = None
    if progress_cb:
        progress_cb({"current_action": "inspecting_image"})
    try:
        context = adapter.expose_readonly(evidence_id=evidence.id, path=stored_path, companions=companions, workspace=workspace)
        if not context.get("supported", True):
            disk_image.status = "failed"
            disk_image.error_json = {"code": context.get("error") or "missing_dependency", "details": context}
            disk_image.tool_metadata = {**(disk_image.tool_metadata or {}), "operations": [*(disk_image.tool_metadata or {}).get("operations", []), {"step": "expose_readonly", **context}]}
            db.commit()
            raise ValueError(str(context.get("error") or "missing_dependency"))
        if progress_cb:
            progress_cb({"current_action": "discovering_volumes"})
        volume_specs, install_specs, warnings = _discover_raw_volumes(context)
        for installation in db.query(OSInstallation).join(DiskVolume, OSInstallation.disk_volume_id == DiskVolume.id).filter(DiskVolume.disk_image_id == disk_image.id).all():
            db.delete(installation)
        for volume in db.query(DiskVolume).filter(DiskVolume.disk_image_id == disk_image.id).all():
            db.delete(volume)
        db.flush()
        persisted_volumes: list[DiskVolume] = []
        persisted_installs: list[OSInstallation] = []
        volume_by_index: dict[int, DiskVolume] = {}
        now = _now().replace(tzinfo=None)
        for spec in volume_specs[: settings.disk_image_max_partitions]:
            volume = DiskVolume(
                disk_image_id=disk_image.id,
                partition_index=int(spec["partition_index"]),
                offset_bytes=int(spec["offset_bytes"]),
                length_bytes=int(spec["length_bytes"]),
                partition_type=spec.get("partition_type"),
                filesystem_type=spec.get("filesystem_type"),
                label=spec.get("label"),
                uuid=spec.get("uuid"),
                encrypted=bool(spec.get("encrypted")),
                readable=bool(spec.get("readable")),
                status=str(spec.get("status") or "discovered"),
                warnings_json=list(spec.get("warnings") or []),
                error_json=dict(spec.get("error") or {}),
                metadata_json=dict(spec.get("metadata") or {}),
                created_at=now,
                updated_at=now,
            )
            db.add(volume)
            db.flush()
            persisted_volumes.append(volume)
            volume_by_index[volume.partition_index] = volume
        for spec in install_specs:
            volume = volume_by_index.get(int(spec["partition_index"]))
            if volume is None:
                continue
            install = OSInstallation(
                disk_volume_id=volume.id,
                platform=str(spec.get("platform") or EvidencePlatform.unknown.value),
                hostname=spec.get("hostname"),
                version=spec.get("version"),
                distro=spec.get("distro"),
                root_path=str(spec.get("root_path") or "/"),
                confidence=str(spec.get("confidence") or "medium"),
                detection_reasons=list(spec.get("detection_reasons") or []),
                metadata_json=dict(spec.get("metadata") or {}),
                created_at=now,
                updated_at=now,
            )
            db.add(install)
            db.flush()
            persisted_installs.append(install)
        db.flush()
        extracted_files: list[str] = []
        manifest_entries: list[dict[str, Any]] = []
        source_map: dict[str, dict[str, Any]] = {}
        image_reader = _open_disk_image_reader(context)
        try:
            for volume in persisted_volumes:
                if not volume.readable:
                    continue
                try:
                    fs_info = _open_persisted_volume_fs_info(image_reader, volume)
                except Exception:
                    continue
                installs_for_volume = [install for install in persisted_installs if install.disk_volume_id == volume.id]
                if not installs_for_volume:
                    continue
                for install in installs_for_volume:
                    volume_files, volume_manifest, volume_map, volume_warnings = _materialize_volume_installation(
                        fs_info=fs_info,
                        install=install,
                        disk_image=disk_image,
                        volume=volume,
                        destination_root=extract_dir,
                        progress_cb=progress_cb,
                    )
                    extracted_files.extend(volume_files)
                    manifest_entries.extend(volume_manifest)
                    source_map.update(volume_map)
                    if volume_warnings:
                        volume.warnings_json = list(dict.fromkeys([*(volume.warnings_json or []), *volume_warnings]))
        finally:
            image_reader.close()
    finally:
        if context is not None:
            adapter.cleanup(context)
        shutil.rmtree(workspace, ignore_errors=True)
    disk_image.status = "discovering_artifacts"
    disk_image.metadata_json = {
        **(disk_image.metadata_json or {}),
        "segments": [item.name for item in companions],
        "volumes": [
            {
                "id": volume.id,
                "partition_index": volume.partition_index,
                "offset_bytes": volume.offset_bytes,
                "length_bytes": volume.length_bytes,
                "partition_type": volume.partition_type,
                "filesystem_type": volume.filesystem_type,
                "label": volume.label,
                "uuid": volume.uuid,
                "encrypted": volume.encrypted,
                "readable": volume.readable,
                "status": volume.status,
                "warnings": list(volume.warnings_json or []),
                "error": dict(volume.error_json or {}),
            }
            for volume in persisted_volumes
        ],
        "installations": [
            {
                "id": install.id,
                "disk_volume_id": install.disk_volume_id,
                "platform": install.platform,
                "hostname": install.hostname,
                "version": install.version,
                "distro": install.distro,
                "root_path": install.root_path,
                "confidence": install.confidence,
                "detection_reasons": list(install.detection_reasons or []),
            }
            for install in persisted_installs
        ],
    }
    disk_image.tool_metadata = {
        **(disk_image.tool_metadata or {}),
        "operations": [
            *(disk_image.tool_metadata or {}).get("operations", []),
            {"step": "validate_segments", "result": validation},
            {"step": "expose_readonly", "result": context},
        ],
        "readiness": disk_image_readiness(),
    }
    disk_image.warnings_json = list(dict.fromkeys(warnings))
    disk_image.error_json = {}
    db.commit()
    return MaterializedDiskImage(
        extract_dir=extract_dir,
        extracted_files=extracted_files,
        manifest_entries=manifest_entries,
        source_map=source_map,
        disk_image=disk_image,
        volumes=persisted_volumes,
        installations=persisted_installs,
        warnings=warnings,
        errors=[],
    )


def inspect_disk_image_readonly(path: Path, *, workspace: Path) -> dict[str, Any]:
    """Read-only preview of a disk image: format, volumes, and OS installations.

    Mirrors the first half of materialize_disk_image_sources (detect -> validate
    -> inspect -> expose_readonly -> discover volumes) but never touches the
    database and never persists a DiskImage/DiskVolume/OSInstallation row. Used
    by the evidence preflight inspection so the wizard can preview a disk image
    before any processing job exists. Caller owns workspace and must remove it
    after use; this function always calls adapter.cleanup() on its own context.
    """
    file_size = path.stat().st_size if path.exists() else 0
    companions = _ewf_companions(path)
    with timed_phase("disk_image.detect", path=path.name, file_size=file_size):
        registry = get_image_format_registry()
        detected = registry.detect(path, companions)
    if not detected:
        return {"supported": False, "error": "unknown_format"}
    adapter = registry.get(str(detected.get("format") or ""))
    if adapter is None:
        return {"supported": False, "error": "unknown_format"}
    with timed_phase("disk_image.validate_segments", path=path.name):
        validation = adapter.validate_segments(path, companions)
    if not validation.get("valid", True):
        return {"supported": False, "format": adapter.key, "error": validation.get("error"), "validation": validation}
    with timed_phase("disk_image.inspect", path=path.name):
        inspect_metadata = adapter.inspect(path, companions)
    workspace.mkdir(parents=True, exist_ok=True)
    context: dict[str, Any] = {}
    try:
        # The expensive step for formats like VMDK: converts the entire
        # image to a temporary raw file (see qemu_img_convert_to_raw) so
        # the raw volumes below can be read. Cost scales with the
        # image's allocated data, not just the file's on-disk size. EWF
        # is the one exception (see app.disk_images.ewf.EwfImageAdapter
        # and EwfImgInfo): it reads directly through pyewf, so this step
        # is cheap for EWF regardless of the disk's logical size.
        with timed_phase("disk_image.expose_readonly", path=path.name, format=adapter.key, file_size=file_size):
            context = adapter.expose_readonly(evidence_id="preflight", path=path, companions=companions, workspace=workspace)
        if not context.get("supported", True):
            return {"supported": False, "format": adapter.key, "error": context.get("error") or "missing_dependency", "context": context}
        with timed_phase("disk_image.discover_raw_volumes", path=path.name):
            volumes, installs, warnings = _discover_raw_volumes(context)
        return {
            "supported": True,
            "format": adapter.key,
            "inspect_metadata": inspect_metadata,
            "volumes": volumes,
            "installations": installs,
            "warnings": warnings,
        }
    finally:
        with timed_phase("disk_image.cleanup", path=path.name):
            if context:
                try:
                    adapter.cleanup(context)
                except Exception:  # noqa: BLE001
                    pass
            shutil.rmtree(workspace, ignore_errors=True)
