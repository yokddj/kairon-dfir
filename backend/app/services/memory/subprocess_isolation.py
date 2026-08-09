"""Generic subprocess isolation with a real, enforced timeout.

Mirrors the process-group kill pattern app.services.memory.volatility_runner
already uses for external Volatility plugin invocations (SIGTERM, then
SIGKILL after a grace period, via a dedicated process group so no child
of the isolated process survives). This module does not import or modify
volatility_runner.py -- it is a small, standalone utility so a second
call site (Linux ISF validation, run in its own interpreter for real
CPU/parsing isolation) does not have to depend on that module's much
larger, plugin-specific surface.

Unlike a ``concurrent.futures.ThreadPoolExecutor`` + ``future.result
(timeout=...)`` timeout, this actually terminates the isolated work: the
child is a real OS process, and SIGKILL genuinely stops it. A thread-based
timeout only stops the *caller* from waiting -- the thread keeps running,
consuming CPU, on the GIL, until it happens to finish naturally.
"""
from __future__ import annotations

import os
import signal
import subprocess
from dataclasses import dataclass


class SubprocessIsolationTimeout(Exception):
    """Raised when the isolated subprocess is killed for exceeding its timeout."""


@dataclass(frozen=True)
class IsolatedProcessResult:
    returncode: int
    stdout: bytes
    stderr: bytes
    duration_ms: int


def run_isolated(
    argv: list[str],
    *,
    timeout_seconds: int,
    termination_grace_seconds: int = 5,
    env: dict[str, str] | None = None,
    cwd: str | None = None,
) -> IsolatedProcessResult:
    """Run ``argv`` in its own process group, bounded by a real timeout.

    On timeout: sends SIGTERM to the whole process group, waits up to
    ``termination_grace_seconds`` for a clean exit, then SIGKILLs the
    group if it is still alive. Always raises ``SubprocessIsolationTimeout``
    in that case -- the caller never sees a truncated/partial result and
    can treat this exactly like any other definitive failure (mark the
    job failed, clean up staging, do not promote anything).
    """
    import time

    started = time.monotonic()
    process = subprocess.Popen(
        argv,
        shell=False,
        cwd=cwd,
        env=env,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        start_new_session=True,
    )
    try:
        stdout, stderr = process.communicate(timeout=max(1, int(timeout_seconds)))
    except subprocess.TimeoutExpired:
        _kill_process_group(process, termination_grace_seconds=termination_grace_seconds)
        raise SubprocessIsolationTimeout(
            f"Isolated subprocess exceeded its {timeout_seconds}-second timeout and was terminated."
        )
    duration_ms = int((time.monotonic() - started) * 1000)
    return IsolatedProcessResult(returncode=process.returncode, stdout=stdout or b"", stderr=stderr or b"", duration_ms=duration_ms)


def _kill_process_group(process: subprocess.Popen[bytes], *, termination_grace_seconds: int) -> None:
    try:
        os.killpg(process.pid, signal.SIGTERM)
    except Exception:  # noqa: BLE001
        try:
            process.terminate()
        except Exception:  # noqa: BLE001
            pass
    try:
        process.communicate(timeout=max(1, int(termination_grace_seconds)))
        return
    except Exception:  # noqa: BLE001
        pass
    try:
        os.killpg(process.pid, signal.SIGKILL)
    except Exception:  # noqa: BLE001
        try:
            process.kill()
        except Exception:  # noqa: BLE001
            pass
    try:
        process.communicate(timeout=1)
    except Exception:  # noqa: BLE001
        pass
