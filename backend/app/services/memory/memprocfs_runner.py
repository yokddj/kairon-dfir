"""FindEvil through MemProcFS, run as an isolated child process.

The child (app.services.memory.memprocfs_findevil) loads MemProcFS's native library and does
the scan; this module only starts it with the same containment as Volatility (own session,
timeout, cancellation, output cap; see volatility_runner.run_isolated_process) and maps its
exit codes to the error codes the memory pipeline already reports.
"""

from __future__ import annotations

import os
import sys
from collections.abc import Callable
from pathlib import Path

from app.core.config import get_settings
from app.services.memory.volatility_runner import VolatilityRunnerError, VolatilityRunResult, run_isolated_process

FINDEVIL_PLUGIN = "memprocfs.findevil"
MEMPROCFS_PLUGINS = frozenset({FINDEVIL_PLUGIN})
# Where the child leaves the forensic scan's timeline CSVs, under the run's output directory.
TIMELINE_DIRNAME = "memprocfs-timeline"

_EXIT_CODES = {
    3: ("MEMPROCFS_UNAVAILABLE", "MemProcFS is not installed in the memory worker."),
    4: ("UNSUPPORTED_MEMORY_IMAGE", "MemProcFS could not open this memory image (FindEvil needs a Windows image)."),
    5: ("PLUGIN_REQUIREMENTS_UNSATISFIED", "MemProcFS forensic mode is not available for this image."),
    6: ("PLUGIN_UNSUPPORTED_WINDOWS_BUILD", "FindEvil does not support this Windows version (it needs 64-bit Windows 10 or later)."),
}


def memprocfs_library() -> Path:
    return Path(str(get_settings().memprocfs_library or "/opt/memprocfs/vmm.so"))


def memprocfs_available() -> bool:
    return memprocfs_library().is_file()


def _child_environment() -> dict[str, str]:
    env: dict[str, str] = {}
    for key in ("PATH", "HOME", "TMPDIR", "TEMP", "TMP"):
        value = os.environ.get(key)
        if value:
            env[key] = value
    library_dir = str(memprocfs_library().parent)
    # vmm.so loads leechcore.so and its other companions from its own directory.
    env["LD_LIBRARY_PATH"] = library_dir
    env["PYTHONPATH"] = str(Path(__file__).resolve().parents[3])
    return env


def run_findevil(
    evidence_path: Path,
    work_dir: Path,
    *,
    timeout_seconds: int,
    max_output_bytes: int,
    cancellation_check: Callable[[], bool] | None = None,
) -> VolatilityRunResult:
    library = memprocfs_library()
    if not library.is_file():
        raise VolatilityRunnerError("MEMPROCFS_UNAVAILABLE", "MemProcFS is not installed in the memory worker.")
    # The child stops waiting for the scan a little before the outer timeout kills it, so a
    # slow image reports why instead of only being killed.
    scan_timeout = max(30, int(timeout_seconds) - 30)
    argv = [
        sys.executable,
        "-m",
        "app.services.memory.memprocfs_findevil",
        "--library",
        str(library),
        "--evidence",
        str(evidence_path),
        "--scan-timeout",
        str(scan_timeout),
        "--timeline-dir",
        str(Path(work_dir) / TIMELINE_DIRNAME),
    ]
    stdout, stderr, returncode, duration_ms = run_isolated_process(
        argv,
        work_dir=work_dir,
        env=_child_environment(),
        timeout=int(timeout_seconds),
        max_bytes=int(max_output_bytes),
        label="MemProcFS FindEvil",
        timeout_label=FINDEVIL_PLUGIN,
        cancellation_check=cancellation_check,
    )
    if returncode != 0:
        code, message = _EXIT_CODES.get(returncode, ("PLUGIN_FAILED", "MemProcFS FindEvil failed."))
        detail = (stderr or b"").decode("utf-8", "replace").strip().splitlines()
        if detail and returncode in _EXIT_CODES:
            message = detail[-1][:300]
        raise VolatilityRunnerError(code, message, stdout=stdout, stderr=stderr, return_code=returncode, stdout_length=len(stdout), stderr_length=len(stderr))
    return VolatilityRunResult(
        argv_display=["memprocfs", "-device", "[evidence]", "-forensic", "1", "-disable-symbolserver", "findevil"],
        stdout=stdout,
        stderr=stderr,
        duration_ms=duration_ms,
    )
