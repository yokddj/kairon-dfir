"""Subprocess entrypoint that runs inspect_linux_isf() in isolation.

Invoked as ``python -m app.services.memory.linux_symbols_validate_subprocess
<isf_path> <max_bytes> <decompressed_max_bytes>`` by
app.services.memory.subprocess_isolation.run_isolated() from within the
memory-worker task (app.services.memory.linux_symbol_evidence
.execute_linux_symbol_validation). Running in its own OS process means
the parent can genuinely kill it on timeout (SIGKILL) -- unlike a
thread-based timeout, which only stops the caller from waiting.

Reuses inspect_linux_isf() unchanged -- this file adds no parsing/
validation logic of its own, only a thin CLI wrapper: read args, call the
one real validation function, print its result as JSON.

stdout on success: ``{"ok": true, "identity": {...}}``
stdout on a structured validation error: ``{"ok": false, "code": ..., "message": ...}``
Exit code is always 0 when a JSON result was printed (success or
structured failure) -- exit code 1 with a non-JSON stderr means an
unexpected internal error the caller should treat as VALIDATION_FAILED.
"""
from __future__ import annotations

import json
import sys
from dataclasses import asdict
from pathlib import Path
from types import SimpleNamespace


def main(argv: list[str]) -> int:
    if len(argv) != 4:
        print("usage: linux_symbols_validate_subprocess.py <isf_path> <max_bytes> <decompressed_max_bytes>", file=sys.stderr)
        return 2
    isf_path, max_bytes_raw, decompressed_max_bytes_raw = argv[1], argv[2], argv[3]

    from app.services.memory.linux_symbols import LinuxSymbolError, inspect_linux_isf

    settings = SimpleNamespace(
        memory_linux_symbol_isf_upload_max_bytes=int(max_bytes_raw),
        memory_linux_symbol_isf_decompressed_max_bytes=int(decompressed_max_bytes_raw),
    )
    try:
        identity = inspect_linux_isf(Path(isf_path), settings=settings)
    except LinuxSymbolError as exc:
        print(json.dumps({"ok": False, "code": exc.code, "message": exc.message}))
        return 0
    except Exception as exc:  # noqa: BLE001
        print(json.dumps({"ok": False, "code": "SYMBOL_PARSE_FAILED", "message": "Linux ISF could not be validated."}))
        print(repr(exc), file=sys.stderr)
        return 0
    print(json.dumps({"ok": True, "identity": asdict(identity)}))
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
