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
from app.services.memory.backend_readiness import resolve_configured_command, resolve_configured_executable, sanitize_backend_error


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


def resolve_volatility_invocation() -> tuple[list[str], str]:
    command = get_settings().volatility3_command
    if " -m " not in str(command or ""):
        configured, executable, display, error = resolve_configured_executable(command)
        if not configured:
            raise VolatilityRunnerError(error or "VOLATILITY_NOT_CONFIGURED", "Volatility 3 is not configured.")
        if not executable:
            raise VolatilityRunnerError("VOLATILITY_NOT_FOUND", "Volatility 3 executable was not found.")
        return [executable], display or Path(executable).name
    configured, argv_prefix, display, error = resolve_configured_command(command)
    if not configured:
        raise VolatilityRunnerError(error or "VOLATILITY_NOT_CONFIGURED", "Volatility 3 is not configured.")
    if not argv_prefix:
        code = "PYTHON_NOT_FOUND" if error == "python_missing" else "VOLATILITY_NOT_FOUND"
        message = "Python executable for Volatility 3 was not found." if error == "python_missing" else "Volatility 3 executable was not found."
        raise VolatilityRunnerError(code, message)
    return argv_prefix, display or Path(argv_prefix[0]).name


ALLOWED_VOLATILITY_PLUGINS = {
    "windows.info",
    "windows.pslist",
    "windows.pstree",
    "windows.psscan",
    "windows.cmdline",
    "windows.envars",
    "windows.getsids",
    "windows.privileges",
    "windows.netscan",
    "windows.netstat",
    "windows.dlllist",
    "windows.ldrmodules",
    "windows.handles",
    "windows.modules",
    "windows.driverscan",
    "windows.malfind",
    "windows.vadinfo",
}


def build_plugin_argv(executable: str | list[str], evidence_path: Path, plugin: str, *, offline: bool = False, cache_path: Path | None = None, symbol_path: Path | None = None) -> list[str]:
    if plugin not in ALLOWED_VOLATILITY_PLUGINS:
        raise VolatilityRunnerError("PLUGIN_NOT_ALLOWED", "Memory plugin is not allowed.")
    argv = [*executable] if isinstance(executable, list) else [executable]
    if offline:
        argv.append("--offline")
    if cache_path is not None:
        argv.extend(["--cache-path", str(cache_path)])
    if symbol_path is not None:
        argv.extend(["--symbol-dirs", str(symbol_path)])
    return [*argv, "-f", str(evidence_path), "-r", "json", plugin]


def build_windows_info_argv(executable: str, evidence_path: Path) -> list[str]:
    return build_plugin_argv(executable, evidence_path, "windows.info")


def _offline_requested_from_environment() -> bool:
    for key in ("KAIRON_VOLATILITY_OFFLINE", "VOLATILITY_OFFLINE"):
        value = str(os.environ.get(key) or "").strip().lower()
        if value in {"1", "true", "yes", "on"}:
            return True
    return False


def _minimal_environment(*, offline: bool = False) -> dict[str, str]:
    env: dict[str, str] = {}
    for key in ("PATH", "SYSTEMROOT", "WINDIR", "HOME", "XDG_CACHE_HOME", "TMPDIR", "TEMP", "TMP"):
        value = os.environ.get(key)
        if value:
            env[key] = value
    if offline:
        env["VOLATILITY_OFFLINE"] = "1"
    return env


def run_plugin(
    plugin: str,
    evidence_path: Path,
    work_dir: Path,
    *,
    timeout_seconds: int | None = None,
    max_output_bytes: int | None = None,
    offline: bool | None = None,
    cache_path: Path | None = None,
    symbol_path: Path | None = None,
) -> VolatilityRunResult:
    settings = get_settings()
    argv_prefix, display = resolve_volatility_invocation()
    if offline is None:
        offline = _offline_requested_from_environment()
    xdg_cache = str(os.environ.get("XDG_CACHE_HOME") or "").strip()
    default_cache_path = Path(xdg_cache) / "volatility3" if xdg_cache else None
    default_symbol_path = default_cache_path / "symbols" if default_cache_path else None
    effective_cache_path = cache_path or default_cache_path
    effective_symbol_path = symbol_path or default_symbol_path
    if effective_cache_path is not None and effective_symbol_path is not None:
        try:
            effective_cache_path.mkdir(parents=True, exist_ok=True, mode=0o750)
            effective_symbol_path.mkdir(parents=True, exist_ok=True, mode=0o750)
            probe = effective_cache_path / ".kairon-write-test"
            probe.write_text("ok", encoding="utf-8")
            probe.unlink(missing_ok=True)
        except OSError as exc:
            raise VolatilityRunnerError("MEMORY_SYMBOL_CACHE_NOT_WRITABLE", "Volatility symbol cache is not writable by the memory worker.") from exc
    argv = build_plugin_argv(argv_prefix, evidence_path, plugin, offline=offline, cache_path=cache_path, symbol_path=symbol_path)
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
            env=_minimal_environment(offline=offline),
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


# Volatility 3 sends progress messages (e.g. ``Scanning FileLayer
# using PageMapScanner...``) to stderr.  We must NOT treat them as
# errors.  The real error is at the end of the stderr stream, after
# a Python traceback.
_PROGRESS_LINE_PREFIXES = (
    "scanning ",
    "constructing ",
    "building ",
    "loading ",
    "opening ",
    "reading ",
    "using ",
    "trying ",
    "attempting ",
    "validating ",
    "verifying ",
    "initialising ",
    "progress:",
    "info:",
    "debug:",
    "warning:",
    "warn:",
    "[",
    "volatility",
)


def _strip_progress_lines(stderr_text: str) -> str:
    """Filter Volatility progress noise out of a stderr string.

    Only lines that look like an actual error (Python tracebacks,
    ``Error:`` lines, exit messages) are returned.
    """
    keep: list[str] = []
    for line in stderr_text.splitlines():
        stripped = line.strip()
        if not stripped:
            continue
        # Always keep Python traceback lines.
        if stripped.startswith(("Traceback ", "  File ", "    ")):
            keep.append(line)
            continue
        lower = stripped.lower()
        # Keep error/exception lines.
        if any(token in lower for token in ("error", "exception", "fatal", "failed", "traceback")):
            keep.append(line)
            continue
        # Discard progress noise.
        if any(lower.startswith(prefix) for prefix in _PROGRESS_LINE_PREFIXES):
            continue
        # Keep anything else (e.g. symbol table dumps, requirement
        # errors, the final ``Volatility 3 Framework`` summary).
        keep.append(line)
    return "\n".join(keep)


def _classify_failure(stderr: bytes) -> tuple[str, str]:
    raw = stderr.decode("utf-8", errors="replace")
    cleaned = _strip_progress_lines(raw)
    lower = cleaned.lower()
    if "read-only file system" in lower and ("symbol" in lower or "pdb" in lower):
        return "MEMORY_SYMBOL_CACHE_NOT_WRITABLE", "Volatility could not use its controlled symbol cache under the read-only worker filesystem."
    if "symbol_table_name" in lower or ("unable to validate" in lower and "symbol" in lower):
        return "SYMBOLS_UNAVAILABLE", "Volatility could not download required symbols."
    if "unable to validate" in lower and "layer" in lower:
        return "INVALID_MEMORY_LAYER", "Volatility could not construct a valid Windows memory layer for this image."
    if "no suitable" in lower and "layer" in lower:
        return "UNSUPPORTED_MEMORY_IMAGE", "Volatility could not construct a supported Windows memory layer for this image."
    if "unable to validate" in lower or "requirement" in lower:
        return "PLUGIN_REQUIREMENTS_UNSATISFIED", "Volatility could not satisfy the windows.info plugin requirements."
    # If everything was progress noise, return a structured error
    # so the UI does not display raw progress text as an error.
    if not cleaned.strip():
        return "MEMORY_PLUGIN_EXECUTION_FAILED", (
            "Volatility did not return a parseable error. The image may be truncated, encrypted, "
            "or unsupported by the installed runtime."
        )
    text = sanitize_backend_error(cleaned)
    return "PLUGIN_FAILED", text or "Volatility windows.info failed."


# Plugins that make up the network_basic profile. Kept in one place for
# compatibility with older capability helpers; profile execution now handles
# individual plugin absence as skipped plugin runs rather than rejecting the
# entire profile up front.
NETWORK_BASIC_REQUIRED_PLUGINS = (
    "windows.netscan",
    "windows.netstat",
)


NETWORK_PLUGIN_CLASSES = {
    "windows.netscan": ("volatility3.plugins.windows.netscan", "NetScan"),
    "windows.netstat": ("volatility3.plugins.windows.netstat", "NetStat"),
}

VOLATILITY_PLUGIN_CLASSES = {
    "windows.psscan": ("volatility3.plugins.windows.psscan", "PsScan"),
    "windows.envars": ("volatility3.plugins.windows.envars", "Envars"),
    "windows.getsids": ("volatility3.plugins.windows.getsids", "GetSIDs"),
    "windows.privileges": ("volatility3.plugins.windows.privileges", "Privs"),
    "windows.netscan": ("volatility3.plugins.windows.netscan", "NetScan"),
    "windows.netstat": ("volatility3.plugins.windows.netstat", "NetStat"),
    "windows.malfind": ("volatility3.plugins.windows.malfind", "Malfind"),
    "windows.vadinfo": ("volatility3.plugins.windows.vadinfo", "VadInfo"),
}


def probe_volatility_plugin(plugin: str) -> bool:
    """Return True when the local Volatility runtime exposes ``plugin``.

    Discovery is done in two layers:

    1. Structured import: we try to ``import`` the module that hosts the
       plugin and verify the expected class is present.  This is the
       authoritative answer: a plugin whose module fails to import is
       NOT usable, even if ``vol --help`` lists it by name.
    2. ``vol --help`` enumeration: used as a secondary signal for
       plugins that are dynamically registered through Volatility's
       plugin system and not visible as a class attribute.

    The result is cached for the lifetime of the process.
    """
    import functools
    cache_attr = "_volatility_plugin_cache"
    cache: dict[str, bool] | None = getattr(probe_volatility_plugin, cache_attr, None)
    if cache is None:
        cache = {}
        setattr(probe_volatility_plugin, cache_attr, cache)
    if plugin in cache:
        return cache[plugin]
    available = _probe_plugin_importable(plugin) or _probe_plugin_listed(plugin)
    cache[plugin] = available
    return available


def _probe_plugin_importable(plugin: str) -> bool:
    """Try to import the module that hosts the plugin class."""
    target = VOLATILITY_PLUGIN_CLASSES.get(plugin)
    if target is None:
        return False
    module_name, class_name = target
    try:
        module = __import__(module_name, fromlist=[class_name])
    except Exception:  # noqa: BLE001
        return False
    return hasattr(module, class_name)


def _probe_plugin_listed(plugin: str) -> bool:
    """Fallback: look for ``plugin`` in the ``vol --help`` output."""
    try:
        executable, _ = resolve_volatility_executable()
    except VolatilityRunnerError:
        return False
    try:
        result = subprocess.run(
            [executable, "--help"],
            shell=False,
            capture_output=True,
            timeout=30,
        )
    except Exception:  # noqa: BLE001
        return False
    output = f"{result.stdout or ''}\n{result.stderr or ''}" if isinstance(result.stdout, str) or isinstance(result.stderr, str) else (result.stdout or b"") + (result.stderr or b"")
    decoded = output if isinstance(output, str) else output.decode("utf-8", errors="replace")
    needle = plugin.replace("windows.", "")
    return f" {needle} " in decoded or f" {needle}," in decoded


def network_basic_available() -> tuple[bool, str]:
    """Probe the installed Volatility runtime for the Windows network
    plugins required by ``network_basic``.

    Returns a tuple ``(available, explanation)``.  ``available`` is
    True only when at least one plugin is importable.  When no
    compatible plugin is present, ``explanation`` is a safe
    human-readable string the UI/API can surface verbatim.

    Diagnostic states (one per required plugin):

    * ``importable``       - module imports and exposes the class
    * ``import_error``     - module file exists but import raises
    * ``absent_in_runtime``- module not present in the runtime
    * ``process_no_volatility`` - volatility3 is not installed in the
      current Python interpreter (e.g. the API process).  The
      capability must be probed in the memory-worker.
    """
    # Detect whether volatility3 is available in this process.  The
    # API process does not install it; only the dedicated memory
    # worker does.  Reporting "missing dependency: volatility3"
    # here is misleading.
    try:
        import volatility3  # noqa: F401
        volatility3_installed = True
        volatility3_path = getattr(volatility3, "__file__", None) or "unknown"
        volatility3_version = _safe_volatility_version()
    except Exception:  # noqa: BLE001
        volatility3_installed = False
        volatility3_path = None
        volatility3_version = None
    if not volatility3_installed:
        return False, (
            "Volatility 3 is not installed in the API process. "
            "Network capability must be probed in the dedicated memory-worker "
            "runtime; check /api/memory/backends for the worker status."
        )
    diagnostics: list[str] = []
    for plugin in NETWORK_BASIC_REQUIRED_PLUGINS:
        if _probe_plugin_importable(plugin):
            diagnostics.append(f"{plugin}: importable")
        else:
            target = NETWORK_PLUGIN_CLASSES.get(plugin)
            if target is None:
                diagnostics.append(f"{plugin}: absent_in_runtime")
                continue
            module_name, _ = target
            try:
                __import__(module_name, fromlist=["*"])
            except ModuleNotFoundError as exc:
                # Distinguish "this specific submodule is missing"
                # from "volatility3 itself is missing" (the latter is
                # already reported above).
                if exc.name and exc.name.startswith("volatility3"):
                    diagnostics.append(
                        f"{plugin}: importable in this process, but the "
                        "import path is being executed in a context that "
                        "cannot find volatility3 (worker probe is authoritative)."
                    )
                else:
                    diagnostics.append(
                        f"{plugin}: importable in this process, but {exc.name} "
                        f"is not installed in the worker image."
                    )
            except Exception as exc:  # noqa: BLE001
                diagnostics.append(f"{plugin}: import_error ({type(exc).__name__}: {exc})")
            else:
                diagnostics.append(f"{plugin}: import_error (class not exposed)")
    importable = any("importable" in d for d in diagnostics)
    return importable, "; ".join(diagnostics) if diagnostics else "No network plugins to probe."


def _safe_volatility_version() -> str | None:
    try:
        from importlib.metadata import version
        return version("volatility3")
    except Exception:  # noqa: BLE001
        return None
