"""Linux Volatility ISF cache helpers.

Linux symbols are prebuilt Volatility ISF tables.  Kairon validates and
stores them in the worker's offline ``symbols/linux`` cache without using the
Windows PDB resolver, Windows symbol requirement tables, or network providers.
"""
from __future__ import annotations

import hashlib
import json
import lzma
import os
import re
import shutil
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any
from uuid import uuid4

from app.core.config import get_settings

STATUS_KERNEL_IDENTITY_UNKNOWN = "kernel_identity_unknown"
STATUS_SYMBOLS_UNAVAILABLE = "symbols_unavailable"
STATUS_SYMBOLS_INVALID = "symbols_invalid"
STATUS_SYMBOLS_INCOMPATIBLE = "symbols_incompatible"
STATUS_SYMBOLS_READY = "symbols_ready"


class LinuxSymbolError(ValueError):
    """Structured validation error for operator-supplied Linux ISFs."""

    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code
        self.message = message


@dataclass(frozen=True)
class LinuxSymbolIdentity:
    platform: str = "linux"
    architecture: str | None = None
    kernel_release: str | None = None
    banner: str | None = None
    build_id: str | None = None
    framework: str = "volatility3"
    framework_version: str | None = None
    isf_sha256: str | None = None

    @property
    def display(self) -> str:
        parts = [self.platform]
        if self.architecture:
            parts.append(self.architecture)
        if self.kernel_release:
            parts.append(self.kernel_release)
        if self.build_id:
            parts.append(f"build:{self.build_id}")
        if self.banner and self.banner not in parts:
            parts.append(self.banner)
        return " | ".join(parts)

    @property
    def cache_key(self) -> str:
        seed = json.dumps(
            {
                "platform": self.platform,
                "architecture": self.architecture,
                "kernel_release": self.kernel_release,
                "banner": self.banner,
                "build_id": self.build_id,
                "framework": self.framework,
                "framework_version": self.framework_version,
            },
            sort_keys=True,
        )
        return hashlib.sha256(seed.encode("utf-8")).hexdigest()[:32]

    def compatible_with(self, required: "LinuxSymbolIdentity | None") -> bool:
        if required is None:
            return True
        if required.platform and self.platform != required.platform:
            return False
        for field in ("architecture", "kernel_release", "banner", "build_id", "framework_version"):
            expected = getattr(required, field)
            observed = getattr(self, field)
            if expected and observed and str(expected).strip().lower() != str(observed).strip().lower():
                return False
            if expected and not observed:
                return False
        return True


@dataclass(frozen=True)
class LinuxSymbolStatus:
    found: bool
    valid: bool = False
    compatible: bool = False
    volatility_selectable: bool = False
    source: str | None = None
    identity: str | None = None
    identity_details: dict[str, Any] | None = None
    path: str | None = None
    sha256: str | None = None
    reason_code: str = STATUS_SYMBOLS_UNAVAILABLE
    message: str | None = None
    duplicate: bool = False


def linux_symbol_cache_dir(settings: Any | None = None) -> Path:
    settings = settings or get_settings()
    configured = str(getattr(settings, "memory_linux_symbol_cache_root", "") or "").strip()
    if configured:
        return Path(configured)
    value = getattr(settings, "memory_linux_symbol_cache_path", None)
    if value is not None:
        return Path(value)
    return Path(getattr(settings, "memory_native_probe_cache_path")) / "symbols" / "linux"


def expected_linux_identity_from_evidence(evidence: Any) -> LinuxSymbolIdentity | None:
    """Extract a required Linux kernel identity from persisted evidence metadata.

    The runtime may not know the kernel identity until a bounded discovery step
    or operator input records it.  In that case return ``None`` and readiness
    must stay ``kernel_identity_unknown`` rather than guessing compatibility.
    """

    metadata = getattr(evidence, "metadata_json", None)
    if not isinstance(metadata, dict):
        return None
    candidates: list[dict[str, Any]] = []
    for key in ("linux_symbol_identity", "linux_kernel", "kernel_identity"):
        value = metadata.get(key)
        if isinstance(value, dict):
            candidates.append(value)
    memory = metadata.get("memory")
    if isinstance(memory, dict):
        linux = memory.get("linux") or memory.get("kernel")
        if isinstance(linux, dict):
            candidates.append(linux)
    for data in candidates:
        identity = _identity_from_mapping(data, sha256=None)
        if _has_kernel_identity(identity):
            return identity
    return None


def resolve_linux_symbols(
    settings: Any | None = None,
    *,
    required_identity: LinuxSymbolIdentity | None = None,
) -> LinuxSymbolStatus:
    """Return a validated, compatible cached Linux ISF if one exists."""

    if required_identity is None:
        return LinuxSymbolStatus(found=False, reason_code=STATUS_KERNEL_IDENTITY_UNKNOWN, message="Linux kernel identity is not known for this evidence.")
    cache_dir = linux_symbol_cache_dir(settings)
    try:
        sidecars = sorted(cache_dir.glob("*.kairon.json"))
    except OSError:
        return LinuxSymbolStatus(found=False)
    invalid_seen = False
    incompatible_seen = False
    for sidecar in sidecars:
        status = _status_from_sidecar(cache_dir, sidecar, required_identity=required_identity)
        if status.reason_code == STATUS_SYMBOLS_READY:
            return status
        if status.reason_code == STATUS_SYMBOLS_INVALID:
            invalid_seen = True
        if status.reason_code == STATUS_SYMBOLS_INCOMPATIBLE:
            incompatible_seen = True
    if incompatible_seen:
        return LinuxSymbolStatus(found=True, valid=True, compatible=False, reason_code=STATUS_SYMBOLS_INCOMPATIBLE)
    if invalid_seen:
        return LinuxSymbolStatus(found=True, valid=False, compatible=False, reason_code=STATUS_SYMBOLS_INVALID)
    return LinuxSymbolStatus(found=False)


def inspect_linux_isf(upload_path: Path, *, settings: Any | None = None) -> LinuxSymbolIdentity:
    """Parse and validate a Linux ISF WITHOUT promoting it into the cache.

    This is the single validation choke point shared by both
    :func:`import_linux_isf` (admin, always promotes on success) and the
    evidence-scoped validate-then-promote flow (which must be able to
    reject an ISF -- e.g. because it does not match the evidence's
    required kernel identity -- without ever writing it to the shared
    cache). Bounded by the decompressed-size limit below.

    This function has NO internal wall-clock timeout of its own. A
    thread-based timeout here could only stop a *caller* from waiting --
    the parsing work would keep running regardless, still holding the
    GIL, until it happened to finish. Real, enforceable isolation
    requires an OS process boundary: callers that need a hard timeout run
    this function in a subprocess via
    app.services.memory.linux_symbols_validate_subprocess (invoked
    through app.services.memory.subprocess_isolation.run_isolated, which
    SIGKILLs the whole process group on timeout) rather than calling it
    in-process. See app.services.memory.linux_symbol_evidence
    .execute_linux_symbol_validation for that caller.
    """
    settings = settings or get_settings()
    _validate_upload_path(upload_path)
    sha256 = _hash_file(upload_path)
    payload = _load_isf(upload_path, settings=settings)
    identity = _identity_from_isf(payload, sha256=sha256)
    if not _has_kernel_identity(identity):
        raise LinuxSymbolError("KERNEL_IDENTITY_UNKNOWN", "Linux ISF does not expose a kernel release, banner, or build id.")
    _validate_isf_shape(payload)
    return identity


def import_linux_isf(
    upload_path: Path,
    *,
    original_filename: str,
    source: str = "manual_upload",
    settings: Any | None = None,
) -> LinuxSymbolStatus:
    """Validate and promote a Linux ISF into the offline Volatility cache."""

    settings = settings or get_settings()
    if not bool(getattr(settings, "memory_linux_symbol_manual_import_enabled", False)):
        raise LinuxSymbolError("SYMBOL_MANUAL_IMPORT_DISABLED", "Linux symbol manual import is disabled.")
    identity = inspect_linux_isf(upload_path, settings=settings)
    sha256 = identity.isf_sha256 or _hash_file(upload_path)
    cache_dir = linux_symbol_cache_dir(settings)
    cache_dir.mkdir(parents=True, exist_ok=True, mode=0o750)
    cache_key = identity.cache_key
    suffix = ".json.xz" if _is_xz(upload_path) or original_filename.lower().endswith(".xz") else ".json"
    final_name = f"{cache_key}{suffix}"
    final_path = _safe_child(cache_dir, final_name)
    sidecar = _safe_child(cache_dir, f"{final_path.name}.kairon.json")
    if sidecar.exists() or final_path.exists():
        existing = _status_from_sidecar(cache_dir, sidecar, required_identity=identity) if sidecar.exists() else None
        if existing and existing.sha256 == sha256 and existing.valid:
            return LinuxSymbolStatus(
                found=True,
                valid=True,
                compatible=True,
                volatility_selectable=True,
                source=existing.source,
                identity=existing.identity,
                identity_details=existing.identity_details,
                path=existing.path,
                sha256=existing.sha256,
                reason_code=STATUS_SYMBOLS_READY,
                duplicate=True,
            )
        raise LinuxSymbolError("SYMBOL_CACHE_COLLISION", "A different Linux ISF already exists for this cache identity.")
    tmp_path = _safe_child(cache_dir, f".{uuid4().hex}.tmp")
    sidecar_tmp = _safe_child(cache_dir, f".{uuid4().hex}.json.tmp")
    try:
        shutil.copyfile(upload_path, tmp_path, follow_symlinks=False)
        os.replace(tmp_path, final_path)
        sidecar_payload = {
            "schema": "kairon-linux-isf-v1",
            "path": final_path.name,
            "identity": asdict(identity),
            "identity_display": identity.display,
            "cache_key": cache_key,
            "source": source,
            "sha256": sha256,
            "original_filename": _safe_original_name(original_filename),
            "validation": {"isf_json": True, "platform": "linux", "volatility_selectable": True},
        }
        sidecar_tmp.write_text(json.dumps(sidecar_payload, sort_keys=True), encoding="utf-8")
        os.replace(sidecar_tmp, sidecar)
    except Exception:
        tmp_path.unlink(missing_ok=True)
        sidecar_tmp.unlink(missing_ok=True)
        final_path.unlink(missing_ok=True)
        raise
    return LinuxSymbolStatus(
        found=True,
        valid=True,
        compatible=True,
        volatility_selectable=True,
        source=source,
        identity=identity.display,
        identity_details=asdict(identity),
        path=str(final_path),
        sha256=sha256,
        reason_code=STATUS_SYMBOLS_READY,
    )


def _status_from_sidecar(cache_dir: Path, sidecar: Path, *, required_identity: LinuxSymbolIdentity) -> LinuxSymbolStatus:
    try:
        metadata = json.loads(sidecar.read_text(encoding="utf-8"))
        rel = str(metadata.get("path") or "").strip()
        if not rel:
            return LinuxSymbolStatus(found=True, reason_code=STATUS_SYMBOLS_INVALID)
        isf_path = _safe_child(cache_dir, rel)
        if not isf_path.is_file() or isf_path.is_symlink():
            return LinuxSymbolStatus(found=True, reason_code=STATUS_SYMBOLS_INVALID)
        sha256 = _hash_file(isf_path)
        if sha256 != str(metadata.get("sha256") or ""):
            return LinuxSymbolStatus(found=True, reason_code=STATUS_SYMBOLS_INVALID)
        payload = _load_isf(isf_path, settings=_SidecarSettings(max_bytes=isf_path.stat().st_size + 1))
        observed = _identity_from_isf(payload, sha256=sha256)
        sidecar_identity = metadata.get("identity") if isinstance(metadata.get("identity"), dict) else {}
        recorded = _identity_from_mapping(sidecar_identity, sha256=sha256)
        if observed.cache_key != recorded.cache_key:
            return LinuxSymbolStatus(found=True, reason_code=STATUS_SYMBOLS_INVALID)
        if not observed.compatible_with(required_identity):
            return LinuxSymbolStatus(
                found=True,
                valid=True,
                compatible=False,
                source=str(metadata.get("source") or "local_cache"),
                identity=observed.display,
                identity_details=asdict(observed),
                path=str(isf_path),
                sha256=sha256,
                reason_code=STATUS_SYMBOLS_INCOMPATIBLE,
            )
        return LinuxSymbolStatus(
            found=True,
            valid=True,
            compatible=True,
            volatility_selectable=True,
            source=str(metadata.get("source") or "local_cache"),
            identity=observed.display,
            identity_details=asdict(observed),
            path=str(isf_path),
            sha256=sha256,
            reason_code=STATUS_SYMBOLS_READY,
        )
    except (LinuxSymbolError, OSError, json.JSONDecodeError, ValueError):
        return LinuxSymbolStatus(found=True, reason_code=STATUS_SYMBOLS_INVALID)


@dataclass(frozen=True)
class _SidecarSettings:
    max_bytes: int

    @property
    def memory_linux_symbol_isf_upload_max_bytes(self) -> int:
        return self.max_bytes


def _identity_from_isf(payload: dict[str, Any], *, sha256: str) -> LinuxSymbolIdentity:
    metadata = payload.get("metadata") if isinstance(payload.get("metadata"), dict) else {}
    linux = metadata.get("linux") if isinstance(metadata.get("linux"), dict) else {}
    return _identity_from_mapping({**metadata, **linux}, sha256=sha256)


def _identity_from_mapping(data: dict[str, Any], *, sha256: str | None) -> LinuxSymbolIdentity:
    platform = str(data.get("platform") or data.get("os") or "linux").strip().lower()
    if platform not in {"linux", ""}:
        raise LinuxSymbolError("SYMBOL_UNSUPPORTED_PLATFORM", "ISF metadata is not Linux.")
    return LinuxSymbolIdentity(
        platform="linux",
        architecture=_clean(data.get("architecture") or data.get("arch") or data.get("machine")),
        kernel_release=_clean(data.get("kernel_release") or data.get("release") or data.get("kernel_version")),
        banner=_clean(data.get("banner") or data.get("kernel_banner")),
        build_id=_clean(data.get("build_id") or data.get("kernel_build_id")),
        framework=_clean(data.get("framework")) or "volatility3",
        framework_version=_clean(data.get("framework_version") or data.get("volatility_version")),
        isf_sha256=sha256,
    )


def _has_kernel_identity(identity: LinuxSymbolIdentity) -> bool:
    return bool(identity.kernel_release or identity.banner or identity.build_id)


def _validate_upload_path(path: Path) -> None:
    try:
        stat = path.lstat()
    except OSError as exc:
        raise LinuxSymbolError("SYMBOL_IMPORT_REJECTED", "Uploaded ISF was not found.") from exc
    if path.is_symlink() or not path.is_file():
        raise LinuxSymbolError("SYMBOL_IMPORT_REJECTED", "Uploaded ISF must be a regular file.")
    if stat.st_size <= 0:
        raise LinuxSymbolError("SYMBOL_IMPORT_REJECTED", "Uploaded ISF is empty.")


def _load_isf(path: Path, *, settings: Any) -> dict[str, Any]:
    try:
        size = path.stat().st_size
    except OSError as exc:
        raise LinuxSymbolError("SYMBOL_IMPORT_REJECTED", "Uploaded ISF was not found.") from exc
    max_bytes = int(getattr(settings, "memory_linux_symbol_isf_upload_max_bytes", 268435456))
    if size <= 0 or size > max_bytes:
        raise LinuxSymbolError("SYMBOL_IMPORT_REJECTED", "Linux ISF upload exceeds the configured size limit.")
    is_xz = path.name.lower().endswith(".xz") or _is_xz(path)
    if is_xz:
        # The compressed-size check above bounds the bytes read from disk,
        # not the bytes produced by decompression -- a small .xz can still
        # expand far past max_bytes (a decompression bomb). Stream the
        # decompressor in fixed chunks and abort the instant the running
        # decompressed total exceeds the configured limit, so peak memory
        # usage is bounded by the limit itself.
        decompressed_max = int(getattr(settings, "memory_linux_symbol_isf_decompressed_max_bytes", 536870912))
        raw = _read_xz_bounded(path, max_bytes=decompressed_max)
        try:
            payload = json.loads(raw.decode("utf-8"))
        except (json.JSONDecodeError, UnicodeDecodeError) as exc:
            raise LinuxSymbolError("SYMBOL_PARSE_FAILED", "Linux ISF could not be parsed.") from exc
    else:
        try:
            with path.open("r", encoding="utf-8") as handle:
                payload = json.load(handle)
        except (json.JSONDecodeError, OSError, UnicodeDecodeError) as exc:
            raise LinuxSymbolError("SYMBOL_PARSE_FAILED", "Linux ISF could not be parsed.") from exc
    if not isinstance(payload, dict):
        raise LinuxSymbolError("SYMBOL_UNSUPPORTED_FORMAT", "Linux ISF payload is not a JSON object.")
    return payload


def _read_xz_bounded(path: Path, *, max_bytes: int) -> bytes:
    """Decompress an .xz file incrementally, aborting as soon as the
    decompressed total would exceed ``max_bytes``.

    Never materializes more than ``max_bytes`` (plus one chunk) of
    decompressed data in memory, regardless of how large the compressed
    input claims to decompress to.
    """
    decompressor = lzma.LZMADecompressor()
    chunks: list[bytes] = []
    total = 0
    chunk_size = 1024 * 1024
    try:
        with path.open("rb") as handle:
            while True:
                compressed_chunk = handle.read(chunk_size)
                if not compressed_chunk:
                    break
                data = decompressor.decompress(compressed_chunk)
                total += len(data)
                if total > max_bytes:
                    raise LinuxSymbolError(
                        "SYMBOL_IMPORT_REJECTED",
                        "Linux ISF exceeds the configured decompressed size limit.",
                    )
                chunks.append(data)
                if decompressor.eof:
                    break
    except lzma.LZMAError as exc:
        raise LinuxSymbolError("SYMBOL_PARSE_FAILED", "Linux ISF could not be parsed.") from exc
    except OSError as exc:
        raise LinuxSymbolError("SYMBOL_IMPORT_REJECTED", "Uploaded ISF was not found.") from exc
    return b"".join(chunks)


def _validate_isf_shape(payload: dict[str, Any]) -> None:
    metadata = payload.get("metadata")
    if not isinstance(metadata, dict):
        raise LinuxSymbolError("SYMBOL_UNSUPPORTED_FORMAT", "Linux ISF payload has no metadata object.")
    linux = metadata.get("linux")
    if not isinstance(linux, dict):
        raise LinuxSymbolError("SYMBOL_UNSUPPORTED_FORMAT", "Linux ISF payload has no Linux metadata block.")
    if not any(isinstance(payload.get(key), dict) for key in ("symbols", "types", "user_types", "base_types", "enums")):
        raise LinuxSymbolError("SYMBOL_UNSUPPORTED_FORMAT", "Linux ISF payload has no symbol or type tables.")


def _safe_child(parent: Path, name: str) -> Path:
    if "/" in name or "\\" in name or name in {"", ".", ".."}:
        raise LinuxSymbolError("SYMBOL_IMPORT_REJECTED", "Invalid Linux symbol cache path.")
    path = parent / name
    try:
        path.resolve().relative_to(parent.resolve())
    except ValueError as exc:
        raise LinuxSymbolError("SYMBOL_IMPORT_REJECTED", "Invalid Linux symbol cache path.") from exc
    return path


def _hash_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _is_xz(path: Path) -> bool:
    try:
        with path.open("rb") as handle:
            return handle.read(6) == b"\xfd7zXZ\x00"
    except OSError:
        return False


def _clean(value: Any) -> str | None:
    text = str(value or "").strip()
    return text[:512] if text else None


def _safe_original_name(value: str) -> str:
    return re.sub(r"[^A-Za-z0-9_.-]+", "_", Path(value or "upload.isf").name)[:180]
