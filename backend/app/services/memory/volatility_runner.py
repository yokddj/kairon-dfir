from __future__ import annotations

import logging
import os
import signal
import subprocess
import sys
import time
from dataclasses import dataclass
from pathlib import Path

from app.core.config import get_settings
from app.services.memory.backend_readiness import resolve_configured_executable, sanitize_backend_error


logger = logging.getLogger(__name__)


class VolatilityRunnerError(RuntimeError):
    def __init__(self, code: str, message: str, *, stdout: bytes = b"", stderr: bytes = b"", return_code: int | None = None, stdout_length: int | None = None, stderr_length: int | None = None):
        super().__init__(message)
        self.code = code
        self.message = message
        self.stdout = stdout
        self.stderr = stderr
        self.return_code = return_code
        self.stdout_length = len(stdout) if stdout_length is None else stdout_length
        self.stderr_length = len(stderr) if stderr_length is None else stderr_length


@dataclass(frozen=True)
class VolatilityRunResult:
    argv_display: list[str]
    stdout: bytes
    stderr: bytes
    duration_ms: int


def probe_windows_symbol_identity(evidence_path: Path, work_dir: Path) -> dict[str, object] | None:
    settings = get_settings()
    xdg_cache = str(os.environ.get("XDG_CACHE_HOME") or "").strip()
    if not xdg_cache:
        return None
    cache_path = Path(xdg_cache) / "volatility3"
    symbol_path = cache_path / "symbols"
    argv = [
        sys.executable,
        "-m",
        "app.services.memory.symbol_probe",
        "--evidence",
        str(evidence_path),
        "--cache",
        str(cache_path),
        "--symbols",
        str(symbol_path),
    ]
    try:
        result = subprocess.run(
            argv,
            shell=False,
            cwd=str(work_dir),
            env=_minimal_environment(),
            capture_output=True,
            timeout=min(max(10, int(settings.memory_plugin_timeout_seconds)), 180),
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired):
        return None
    marker = b"KAIRON_SYMBOL_REQUIREMENT="
    line = next((item for item in result.stdout.splitlines() if item.startswith(marker)), None)
    if result.returncode != 0 or line is None or len(line) > 1024:
        return None
    try:
        payload = __import__("json").loads(line[len(marker):])
    except (ValueError, TypeError):
        return None
    return payload if isinstance(payload, dict) else None


def resolve_volatility_executable() -> tuple[str, str]:
    configured, executable, display, error = resolve_configured_executable(get_settings().volatility3_command)
    if not configured:
        raise VolatilityRunnerError(error or "VOLATILITY_NOT_CONFIGURED", "Volatility 3 is not configured.")
    if not executable:
        raise VolatilityRunnerError("VOLATILITY_NOT_FOUND", "Volatility 3 executable was not found.")
    return executable, display or Path(executable).name


ALLOWED_VOLATILITY_PLUGINS = {
    "windows.info",
    "windows.pslist",
    "windows.pstree",
    "windows.psscan",
    "windows.cmdline",
    "windows.netscan",
    "windows.dlllist",
    "windows.ldrmodules",
    "windows.handles",
    "windows.modules",
    "windows.driverscan",
    "windows.malfind",
}


def build_plugin_argv(executable: str, evidence_path: Path, plugin: str, *, offline: bool = True, cache_path: Path | None = None, symbol_path: Path | None = None) -> list[str]:
    if plugin not in ALLOWED_VOLATILITY_PLUGINS:
        raise VolatilityRunnerError("PLUGIN_NOT_ALLOWED", "Memory plugin is not allowed.")
    argv = [executable]
    if offline:
        argv.append("--offline")
    if cache_path is not None:
        argv.extend(["--cache-path", str(cache_path)])
    if symbol_path is not None:
        argv.extend(["--symbol-dirs", str(symbol_path)])
    return [*argv, "-f", str(evidence_path), "-r", "json", plugin]


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


def run_plugin(plugin: str, evidence_path: Path, work_dir: Path, *, timeout_seconds: int | None = None, max_output_bytes: int | None = None) -> VolatilityRunResult:
    settings = get_settings()
    executable, display = resolve_volatility_executable()
    # Normal memory analysis is always offline. Managed downloads belong only
    # to the dedicated symbol-fetcher service.
    offline = True
    xdg_cache = str(os.environ.get("XDG_CACHE_HOME") or "").strip()
    cache_path = Path(xdg_cache) / "volatility3" if xdg_cache else None
    symbol_path = cache_path / "symbols" if cache_path else None
    if cache_path is not None and symbol_path is not None:
        cache_path.mkdir(parents=True, exist_ok=True, mode=0o750)
        symbol_path.mkdir(parents=True, exist_ok=True, mode=0o750)
    argv = build_plugin_argv(executable, evidence_path, plugin, offline=offline, cache_path=cache_path, symbol_path=symbol_path)
    timeout = max(1, int(timeout_seconds or settings.memory_plugin_timeout_seconds))
    max_bytes = max(1, int(max_output_bytes or settings.memory_plugin_output_max_bytes))
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
        raise VolatilityRunnerError("PLUGIN_TIMEOUT", f"Volatility {plugin} timed out.", stdout=(exc.output or b"")[:max_bytes], stderr=(exc.stderr or b"")[:65536], stdout_length=len(exc.output or b""), stderr_length=len(exc.stderr or b"")) from exc
    except OSError as exc:
        raise VolatilityRunnerError("BACKEND_START_FAILED", sanitize_backend_error(exc)) from exc

    duration_ms = int((time.monotonic() - started) * 1000)
    stdout_length = len(stdout or b"")
    stderr_length = len(stderr or b"")
    if len(stdout or b"") > max_bytes:
        raise VolatilityRunnerError("OUTPUT_TOO_LARGE", "Volatility output exceeded the configured size limit.", stdout=(stdout or b"")[:max_bytes], stderr=(stderr or b"")[:4096])
    if len(stderr or b"") > 65536:
        stderr = (stderr or b"")[:65536]
    if process.returncode != 0:
        message = _classify_failure(stderr or b"")
        raise VolatilityRunnerError(message[0], message[1], stdout=(stdout or b"")[:max_bytes], stderr=stderr or b"", return_code=process.returncode, stdout_length=stdout_length, stderr_length=stderr_length)
    display_argv = [display]
    if offline:
        display_argv.append("--offline")
    if cache_path is not None:
        display_argv.extend(["--cache-path", "[cache]", "--symbol-dirs", "[symbols]"])
    return VolatilityRunResult(argv_display=[*display_argv, "-f", "[evidence]", "-r", "json", plugin], stdout=stdout or b"", stderr=stderr or b"", duration_ms=duration_ms)


def run_windows_info(evidence_path: Path, work_dir: Path) -> VolatilityRunResult:
    return run_plugin("windows.info", evidence_path, work_dir)


def _classify_failure(stderr: bytes) -> tuple[str, str]:
    raw = stderr.decode("utf-8", errors="replace")
    lower = raw.lower()
    if "read-only file system" in lower and ("symbol" in lower or "pdb" in lower):
        return "MEMORY_SYMBOL_CACHE_NOT_WRITABLE", "Volatility could not use its controlled symbol cache under the read-only worker filesystem."
    if "symbol_table_name" in lower or ("unable to validate" in lower and "symbol" in lower):
        return "SYMBOLS_UNAVAILABLE", "windows.info could not resolve the required Windows symbols under offline-only mode."
    if "unable to validate" in lower and "layer" in lower:
        return "INVALID_MEMORY_LAYER", "Volatility could not construct a valid Windows memory layer for this image."
    if "no suitable" in lower and "layer" in lower:
        return "UNSUPPORTED_MEMORY_IMAGE", "Volatility could not construct a supported Windows memory layer for this image."
    if "unable to validate" in lower or "requirement" in lower:
        return "PLUGIN_REQUIREMENTS_UNSATISFIED", "Volatility could not satisfy the windows.info plugin requirements."
    text = sanitize_backend_error(raw)
    return "PLUGIN_FAILED", text or "Volatility windows.info failed."
