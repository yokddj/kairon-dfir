from __future__ import annotations

import logging
import os
import signal
import subprocess
import time
from dataclasses import dataclass
from pathlib import Path

from app.core.config import get_settings
from app.services.memory.backend_readiness import resolve_configured_executable, sanitize_backend_error


logger = logging.getLogger(__name__)


class VolatilityRunnerError(RuntimeError):
    def __init__(self, code: str, message: str, *, stdout: bytes = b"", stderr: bytes = b""):
        super().__init__(message)
        self.code = code
        self.message = message
        self.stdout = stdout
        self.stderr = stderr


@dataclass(frozen=True)
class VolatilityRunResult:
    argv_display: list[str]
    stdout: bytes
    stderr: bytes
    duration_ms: int


def resolve_volatility_executable() -> tuple[str, str]:
    configured, executable, display, error = resolve_configured_executable(get_settings().volatility3_command)
    if not configured:
        raise VolatilityRunnerError(error or "VOLATILITY_NOT_CONFIGURED", "Volatility 3 is not configured.")
    if not executable:
        raise VolatilityRunnerError("VOLATILITY_NOT_FOUND", "Volatility 3 executable was not found.")
    return executable, display or Path(executable).name


ALLOWED_VOLATILITY_PLUGINS = {"windows.info", "windows.pslist", "windows.pstree", "windows.psscan", "windows.cmdline"}


def build_plugin_argv(executable: str, evidence_path: Path, plugin: str) -> list[str]:
    if plugin not in ALLOWED_VOLATILITY_PLUGINS:
        raise VolatilityRunnerError("PLUGIN_NOT_ALLOWED", "Memory plugin is not allowed.")
    return [executable, "-f", str(evidence_path), "-r", "json", plugin]


def build_windows_info_argv(executable: str, evidence_path: Path) -> list[str]:
    return build_plugin_argv(executable, evidence_path, "windows.info")


def _minimal_environment() -> dict[str, str]:
    env: dict[str, str] = {}
    for key in ("PATH", "SYSTEMROOT", "WINDIR", "HOME", "XDG_CACHE_HOME", "TMPDIR", "TEMP", "TMP"):
        value = os.environ.get(key)
        if value:
            env[key] = value
    env["VOLATILITY_OFFLINE"] = "1"
    return env


def run_plugin(plugin: str, evidence_path: Path, work_dir: Path) -> VolatilityRunResult:
    settings = get_settings()
    executable, display = resolve_volatility_executable()
    argv = build_plugin_argv(executable, evidence_path, plugin)
    timeout = max(1, int(settings.memory_plugin_timeout_seconds))
    max_bytes = max(1, int(settings.memory_plugin_output_max_bytes))
    work_dir.mkdir(parents=True, exist_ok=True)
    logger.info("memory volatility plugin started", extra={"plugin": plugin, "executable": display})
    started = time.monotonic()
    process: subprocess.Popen[bytes] | None = None
    try:
        process = subprocess.Popen(
            argv,
            shell=False,
            cwd=str(work_dir),
            env=_minimal_environment(),
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            start_new_session=True,
        )
        stdout, stderr = process.communicate(timeout=timeout)
    except subprocess.TimeoutExpired as exc:
        if process is not None:
            try:
                os.killpg(process.pid, signal.SIGTERM)
                process.wait(timeout=5)
            except Exception:  # noqa: BLE001
                try:
                    os.killpg(process.pid, signal.SIGKILL)
                except Exception:  # noqa: BLE001
                    process.kill()
        raise VolatilityRunnerError("PLUGIN_TIMEOUT", f"Volatility {plugin} timed out.", stdout=exc.output or b"", stderr=exc.stderr or b"") from exc
    except OSError as exc:
        raise VolatilityRunnerError("BACKEND_START_FAILED", sanitize_backend_error(exc)) from exc

    duration_ms = int((time.monotonic() - started) * 1000)
    if len(stdout or b"") > max_bytes:
        raise VolatilityRunnerError("OUTPUT_TOO_LARGE", "Volatility output exceeded the configured size limit.", stdout=(stdout or b"")[:max_bytes], stderr=(stderr or b"")[:4096])
    if len(stderr or b"") > 65536:
        stderr = (stderr or b"")[:65536]
    if process.returncode != 0:
        message = _classify_failure(stderr or b"")
        raise VolatilityRunnerError(message[0], message[1], stdout=stdout or b"", stderr=stderr or b"")
    return VolatilityRunResult(argv_display=[display, "-f", "[evidence]", "-r", "json", plugin], stdout=stdout or b"", stderr=stderr or b"", duration_ms=duration_ms)


def run_windows_info(evidence_path: Path, work_dir: Path) -> VolatilityRunResult:
    return run_plugin("windows.info", evidence_path, work_dir)


def _classify_failure(stderr: bytes) -> tuple[str, str]:
    text = sanitize_backend_error(stderr.decode("utf-8", errors="replace"))
    lower = text.lower()
    if "symbol" in lower or "requirement" in lower:
        return "PLUGIN_REQUIREMENTS_UNSATISFIED", "Volatility could not satisfy plugin requirements, commonly because symbols are unavailable."
    return "PLUGIN_FAILED", text or "Volatility windows.info failed."
