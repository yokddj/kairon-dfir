from __future__ import annotations

import json
import logging
import shutil
import time
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Literal
from uuid import uuid4

from redis import Redis

from app.core.config import get_settings


GIB = 1024 * 1024 * 1024
SAFETY_MARGIN_BYTES = 2 * GIB
MIN_OUTPUT_ALLOWANCE_BYTES = 256 * 1024 * 1024
MAX_SELECTED_SIZE_BYTES = 64 * GIB
UPLOAD_SLOT_KEY = "kairon:memory-upload:active"
logger = logging.getLogger(__name__)

CapacityPhase = Literal["pre_upload", "streaming", "finalization"]


class MemoryCapacityError(RuntimeError):
    def __init__(self, category: str, message: str):
        super().__init__(message)
        self.category = category


@dataclass(frozen=True)
class FilesystemSnapshot:
    device: int
    available_bytes: int


@dataclass(frozen=True)
class CapacityDecision:
    accepted: bool
    phase: CapacityPhase
    selected_size_bytes: int
    bytes_already_staged: int
    staging_available_bytes: int
    final_available_bytes: int
    output_available_bytes: int
    staging_and_final_same_filesystem: bool
    finalization_strategy: str
    required_additional_bytes: int
    output_allowance_bytes: int
    safety_margin_bytes: int
    shortfall_bytes: int
    requirements_by_device: dict[str, int]

    def as_internal_dict(self) -> dict[str, object]:
        return asdict(self)


def _snapshot(path: Path) -> FilesystemSnapshot:
    path.mkdir(parents=True, exist_ok=True)
    stat = path.stat()
    usage = shutil.disk_usage(path)
    return FilesystemSnapshot(device=int(stat.st_dev), available_bytes=int(usage.free))


def _output_allowance() -> int:
    settings = get_settings()
    return max(int(settings.memory_plugin_output_max_bytes or 0) * 5, MIN_OUTPUT_ALLOWANCE_BYTES)


def _storage_roots() -> tuple[Path, Path, Path]:
    settings = get_settings()
    staging = settings.memory_upload_staging_path
    final = settings.backend_data_dir / "evidence"
    output = settings.memory_output_root or final
    return Path(staging), Path(final), Path(output)


def evaluate_memory_upload_capacity(
    selected_size_bytes: int,
    *,
    phase: CapacityPhase,
    bytes_already_staged: int = 0,
) -> CapacityDecision:
    if selected_size_bytes <= 0:
        raise ValueError("selected_size_bytes must be greater than zero")
    if selected_size_bytes > MAX_SELECTED_SIZE_BYTES:
        raise ValueError("selected_size_bytes is too large")
    if bytes_already_staged < 0 or bytes_already_staged > selected_size_bytes:
        raise ValueError("bytes_already_staged is outside the selected file size")

    staging_root, final_root, output_root = _storage_roots()
    snapshots = {
        "staging": _snapshot(staging_root),
        "final": _snapshot(final_root),
        "output": _snapshot(output_root),
    }
    same_filesystem = snapshots["staging"].device == snapshots["final"].device
    strategy = "atomic_rename" if same_filesystem else "staged_copy"
    allowance = _output_allowance()
    requirements: dict[int, int] = {}
    available: dict[int, int] = {}

    for snapshot in snapshots.values():
        available[snapshot.device] = min(available.get(snapshot.device, snapshot.available_bytes), snapshot.available_bytes)

    def require(role: str, amount: int) -> None:
        device = snapshots[role].device
        requirements[device] = requirements.get(device, 0) + max(0, int(amount))

    involved_devices = {snapshot.device for snapshot in snapshots.values()}
    for device in involved_devices:
        requirements[device] = SAFETY_MARGIN_BYTES

    if phase == "pre_upload":
        require("staging", selected_size_bytes)
        if not same_filesystem:
            require("final", selected_size_bytes)
    elif phase == "streaming":
        require("staging", selected_size_bytes - bytes_already_staged)
        if not same_filesystem:
            require("final", selected_size_bytes)
    elif phase == "finalization":
        if not same_filesystem:
            require("final", selected_size_bytes)
    else:  # pragma: no cover - guarded by the type and retained for runtime callers
        raise ValueError(f"Unsupported memory capacity phase: {phase}")
    require("output", allowance)

    shortfall = max((requirements[device] - available[device] for device in requirements), default=0)
    required_by_role = {str(device): int(value) for device, value in requirements.items()}
    return CapacityDecision(
        accepted=shortfall <= 0,
        phase=phase,
        selected_size_bytes=int(selected_size_bytes),
        bytes_already_staged=int(bytes_already_staged),
        staging_available_bytes=snapshots["staging"].available_bytes,
        final_available_bytes=snapshots["final"].available_bytes,
        output_available_bytes=snapshots["output"].available_bytes,
        staging_and_final_same_filesystem=same_filesystem,
        finalization_strategy=strategy,
        required_additional_bytes=max(requirements.values(), default=0),
        output_allowance_bytes=allowance,
        safety_margin_bytes=SAFETY_MARGIN_BYTES,
        shortfall_bytes=max(0, int(shortfall)),
        requirements_by_device=required_by_role,
    )


def assert_memory_upload_capacity(
    selected_size_bytes: int,
    *,
    phase: CapacityPhase,
    bytes_already_staged: int = 0,
) -> CapacityDecision:
    decision = evaluate_memory_upload_capacity(
        selected_size_bytes,
        phase=phase,
        bytes_already_staged=bytes_already_staged,
    )
    if not decision.accepted:
        raise MemoryCapacityError("insufficient_storage", "Insufficient storage capacity for memory image upload.")
    return decision


def recommended_memory_upload_bytes(max_upload_bytes: int) -> int:
    low, high = 0, max(0, int(max_upload_bytes))
    while low < high:
        candidate = (low + high + 1) // 2
        if evaluate_memory_upload_capacity(candidate, phase="pre_upload").accepted:
            low = candidate
        else:
            high = candidate - 1
    return low


class MemoryUploadSlot:
    def __init__(self, *, request_id: str | None = None, redis_conn: Redis | None = None):
        settings = get_settings()
        self.request_id = request_id or str(uuid4())
        self._redis = redis_conn or Redis.from_url(settings.redis_url)
        configured_timeout = int(settings.memory_upload_request_timeout_seconds or 0)
        self._ttl_seconds = max(300, configured_timeout, int(settings.memory_upload_cleanup_age_seconds or 0))
        self._token = json.dumps({"request_id": self.request_id, "created_at": int(time.time())}, sort_keys=True)
        self._held = False
        self._last_refresh = 0.0

    def acquire(self) -> None:
        try:
            self._held = bool(self._redis.set(UPLOAD_SLOT_KEY, self._token, nx=True, ex=self._ttl_seconds))
        except Exception as exc:  # noqa: BLE001
            raise MemoryCapacityError("concurrency_guard_unavailable", "Memory upload concurrency guard is unavailable.") from exc
        if not self._held:
            raise MemoryCapacityError("upload_in_progress", "Another memory image upload is currently in progress.")
        self._last_refresh = time.monotonic()

    def refresh(self, *, force: bool = False) -> None:
        if not self._held or (not force and time.monotonic() - self._last_refresh < 30):
            return
        script = "if redis.call('get',KEYS[1]) == ARGV[1] then return redis.call('expire',KEYS[1],ARGV[2]) else return 0 end"
        try:
            refreshed = int(self._redis.eval(script, 1, UPLOAD_SLOT_KEY, self._token, self._ttl_seconds))
        except Exception as exc:  # noqa: BLE001
            raise MemoryCapacityError("concurrency_guard_unavailable", "Memory upload concurrency guard could not be renewed.") from exc
        if refreshed != 1:
            raise MemoryCapacityError("upload_reservation_lost", "Memory upload capacity reservation expired.")
        self._last_refresh = time.monotonic()

    def release(self) -> None:
        if not self._held:
            return
        script = "if redis.call('get',KEYS[1]) == ARGV[1] then return redis.call('del',KEYS[1]) else return 0 end"
        try:
            self._redis.eval(script, 1, UPLOAD_SLOT_KEY, self._token)
        except Exception:  # noqa: BLE001
            logger.warning("memory upload slot release failed request_id=%s; TTL expiry will release it", self.request_id)
        finally:
            self._held = False

    def __enter__(self) -> MemoryUploadSlot:
        self.acquire()
        return self

    def __exit__(self, _exc_type, _exc, _tb) -> None:
        self.release()
