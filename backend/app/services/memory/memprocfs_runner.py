"""FindEvil through MemProcFS, run as an isolated child process.

The child (app.services.memory.memprocfs_findevil) loads MemProcFS's native library and does
the scan; this module only starts it with the same containment as Volatility (own session,
timeout, cancellation, output cap; see volatility_runner.run_isolated_process) and maps its
exit codes to the error codes the memory pipeline already reports.
"""

from __future__ import annotations

import logging
import os
import re
import shutil
import signal
import sys
from collections.abc import Callable
from pathlib import Path

from app.core.config import get_settings
from app.services.memory.volatility_runner import VolatilityRunnerError, VolatilityRunResult, run_isolated_process

logger = logging.getLogger(__name__)

FINDEVIL_PLUGIN = "memprocfs.findevil"
MEMPROCFS_PLUGINS = frozenset({FINDEVIL_PLUGIN})
# Where the child leaves the forensic scan's timeline CSVs, under the run's output directory.
TIMELINE_DIRNAME = "memprocfs-timeline"
# Left under the run's own output directory (not /tmp) so it survives the plugin process and
# is reachable alongside the run's other artifacts if an operator needs to report the crash
# upstream (see docs/memory/memory_operations.md#findevil-crashes).
CRASH_LOG_FILENAME = "memprocfs_findevil_crash.log"

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


def _signal_name(returncode: int) -> str:
    """`returncode` must be negative (Python subprocess's POSIX convention for "killed by
    signal -returncode"). Returns e.g. "SIGSEGV", or "signal 137" for an unnamed one."""
    signal_number = -returncode
    crashed_signal = signal.Signals(signal_number) if signal_number in set(signal.Signals) else None
    return crashed_signal.name if crashed_signal else f"signal {signal_number}"


def _gdb_executable() -> str | None:
    """Return the configured gdb's resolved path, or None if it is not installed. gdb is an
    optional, best-effort diagnostic tool here (see memprocfs_crash_retry_enabled): its absence
    never blocks a normal run, it only means a crash is reported the same way it always was."""
    configured = str(get_settings().memprocfs_gdb_command or "gdb").strip()
    return shutil.which(configured)


# gdb batch mode always exits 0 regardless of the debuggee's outcome, so the real result is
# read back from these two gdb-internal convenience variables instead of the gdb process's own
# exit code. $_exitsignal is only defined (non-void) if the debuggee was killed by a signal;
# $_exitcode is only defined if it exited normally. gdb's own `printf` prints a literal "Value
# can't be converted to integer." for a void value instead of failing the command, so a
# KAIRON_EXITSIGNAL=<digits> line is unambiguous proof of a real signal, never a false positive
# -- but either way (digits or that literal message) the whole line is stripped from the
# child's stdout before anything downstream parses it.
_GDB_SIGNAL_LINE_RE = re.compile(r"^KAIRON_EXITSIGNAL=.*$\n?", re.MULTILINE)
_GDB_EXITCODE_LINE_RE = re.compile(r"^KAIRON_EXITCODE=.*$\n?", re.MULTILINE)
_GDB_SIGNAL_VALUE_RE = re.compile(r"KAIRON_EXITSIGNAL=(\d+)")
_GDB_EXITCODE_VALUE_RE = re.compile(r"KAIRON_EXITCODE=(\d+)")


def _run_findevil_under_gdb(
    argv: list[str],
    *,
    work_dir: Path,
    env: dict[str, str],
    timeout_seconds: int,
    max_output_bytes: int,
    gdb_executable: str,
    cancellation_check: Callable[[], bool] | None,
) -> tuple[bytes, bytes, int | None, int | None, str, int]:
    """Re-run the FindEvil child under gdb to get a real native backtrace if it crashes again,
    and -- since a ptrace'd process sometimes simply does not hit the same timing-sensitive
    crash -- a chance to complete this time instead of needing a fully separate retry.

    Returns (stdout, stderr, exit_code, exit_signal, backtrace_text, duration_ms). stdout is the
    child's own stdout, isolated with `set logging redirect on` from gdb's own banner/session
    text, so the FindEvil JSON parser downstream never has to know gdb was involved.
    """
    crash_log = Path(work_dir) / CRASH_LOG_FILENAME
    gdb_argv = [
        gdb_executable,
        "-nx",
        "-q",
        "-batch",
        "-ex", "set confirm off",
        "-ex", "set pagination off",
        "-ex", f"set logging file {crash_log}",
        "-ex", "set logging redirect on",
        "-ex", "set logging enabled on",
        "-ex", "run",
        "-ex", "bt",
        # If the debuggee was killed by a signal, gdb stops it for inspection instead of letting
        # the signal actually finish killing it, so $_exitsignal stays undefined until the
        # signal is let through: harmless no-op ("The program is not being run.") when the
        # debuggee already exited normally.
        "-ex", "continue",
        "-ex", "set logging enabled off",
        "-ex", "printf \"KAIRON_EXITSIGNAL=%d\\n\", $_exitsignal",
        "-ex", "printf \"KAIRON_EXITCODE=%d\\n\", $_exitcode",
        "-ex", "quit",
        "--args",
        *argv,
    ]
    stdout, stderr, _gdb_returncode, duration_ms = run_isolated_process(
        gdb_argv,
        work_dir=work_dir,
        env=env,
        timeout=int(timeout_seconds) + 30,  # gdb's own startup/attach overhead
        max_bytes=int(max_output_bytes),
        label="MemProcFS FindEvil (gdb retry)",
        timeout_label=FINDEVIL_PLUGIN,
        cancellation_check=cancellation_check,
    )
    # The KAIRON_EXITSIGNAL/KAIRON_EXITCODE marker lines are themselves gdb output and must not
    # leak into the child's real stdout (the FindEvil JSON parser downstream expects only that).
    text = stdout.decode("utf-8", "replace")
    signal_match = _GDB_SIGNAL_VALUE_RE.search(text)
    exitcode_match = _GDB_EXITCODE_VALUE_RE.search(text)
    clean_text = _GDB_SIGNAL_LINE_RE.sub("", _GDB_EXITCODE_LINE_RE.sub("", text))
    clean_stdout = clean_text.encode("utf-8", "replace")
    exit_signal = int(signal_match.group(1)) if signal_match else None
    exit_code = int(exitcode_match.group(1)) if exitcode_match and exit_signal is None else None
    backtrace_text = ""
    if crash_log.is_file():
        try:
            backtrace_text = crash_log.read_text(encoding="utf-8", errors="replace")[:16384]
        except OSError:
            pass
    return clean_stdout, stderr, exit_code, exit_signal, backtrace_text, duration_ms


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
    env = _child_environment()
    stdout, stderr, returncode, duration_ms = run_isolated_process(
        argv,
        work_dir=work_dir,
        env=env,
        timeout=int(timeout_seconds),
        max_bytes=int(max_output_bytes),
        label="MemProcFS FindEvil",
        timeout_label=FINDEVIL_PLUGIN,
        cancellation_check=cancellation_check,
    )
    backtrace_text = ""
    # returncode < 0 is Python subprocess's convention for "killed by signal -returncode" (POSIX;
    # see subprocess.Popen.returncode docs) -- this is the signature of the native crash this
    # retry targets (observed: SIGSEGV inside MemProcFS's own VMMDLL_Initialize), not of
    # MemProcFS's own documented exit codes (3-6, in _EXIT_CODES below), which are normal,
    # intentional process exits and need no retry.
    if returncode < 0 and get_settings().memprocfs_crash_retry_enabled:
        signal_name = _signal_name(returncode)
        gdb_executable = _gdb_executable()
        if gdb_executable is None:
            logger.warning(
                "MemProcFS FindEvil was killed by %s; gdb is not installed, so no crash retry or backtrace is available",
                signal_name,
            )
        else:
            logger.warning("MemProcFS FindEvil was killed by %s; retrying once under gdb for diagnostics", signal_name)
            remaining_timeout = max(30, int(timeout_seconds) - int(duration_ms / 1000))
            retry_stdout, retry_stderr, retry_exit_code, retry_exit_signal, backtrace_text, retry_duration_ms = _run_findevil_under_gdb(
                argv,
                work_dir=work_dir,
                env=env,
                timeout_seconds=remaining_timeout,
                max_output_bytes=max_output_bytes,
                gdb_executable=gdb_executable,
                cancellation_check=cancellation_check,
            )
            duration_ms += retry_duration_ms
            if retry_exit_code == 0:
                # The ptrace'd run simply did not hit the race condition this time: use its
                # result and move on, with a note so this is visible without digging into logs.
                logger.warning("MemProcFS FindEvil completed on the gdb-retried run after crashing with %s on the first attempt", signal_name)
                return VolatilityRunResult(
                    argv_display=["memprocfs", "-device", "[evidence]", "-forensic", "1", "-disable-symbolserver", "findevil"],
                    stdout=retry_stdout,
                    stderr=retry_stderr,
                    duration_ms=duration_ms,
                )
            stdout, stderr = retry_stdout, retry_stderr
            if retry_exit_signal is not None:
                returncode = -retry_exit_signal
            elif retry_exit_code is not None:
                returncode = retry_exit_code
            if backtrace_text:
                logger.warning("MemProcFS FindEvil crash backtrace (gdb):\n%s", backtrace_text)
    if returncode != 0:
        if returncode < 0:
            signal_name = _signal_name(returncode)
            code, message = "PLUGIN_CRASHED", (
                f"MemProcFS FindEvil was killed by {signal_name} (a crash inside MemProcFS itself, "
                "not a Kairon bug -- Kairon's own Find Evil checks still ran)."
                + (" A native backtrace was captured for diagnosis; see the memory worker's logs." if backtrace_text else "")
            )
        else:
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
