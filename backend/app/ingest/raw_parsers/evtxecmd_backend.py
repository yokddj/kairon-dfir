from __future__ import annotations

from collections.abc import Iterable
from functools import lru_cache
from pathlib import Path
import os
import re
import shutil
import subprocess
import tempfile
import time

from app.core.config import get_settings
from app.ingest.eztools.evtxecmd import EvtxECmdParser
from app.ingest.raw_parsers.audit import build_raw_parser_audit
from app.ingest.raw_parsers.models import RawParserResult


EVTXECMD_BACKEND_CSV = "evtxecmd_csv"
EVTX_RAW_PYTHON_BACKEND = "evtx_raw_python"
EVTX_BACKEND_AUTO = "auto"


def _configured_dll_path() -> Path:
    settings = get_settings()
    return Path(
        os.environ.get("EVTXECMD_DOTNET_DLL")
        or getattr(settings, "evtxecmd_dotnet_dll", "")
        or "/opt/evtxecmd/EvtxECmd.dll"
    )


def _evtxecmd_command() -> list[str] | None:
    settings = get_settings()
    configured = str(getattr(settings, "evtxecmd_executable", "") or "").strip()
    if configured:
        configured_path = Path(configured)
        if configured_path.exists() or shutil.which(configured):
            return [configured]
    for name in ("EvtxECmd", "evtxecmd"):
        found = shutil.which(name)
        if found:
            return [found]
    dll_path = _configured_dll_path()
    dotnet = shutil.which("dotnet")
    if dotnet and dll_path.exists():
        return [dotnet, str(dll_path)]
    return None


def _extract_version(text: str) -> str:
    match = re.search(r"EvtxECmd\s+version\s+([^\s]+)", text, flags=re.IGNORECASE)
    if match:
        return match.group(1)
    match = re.search(r"version\s+([0-9][^\s]+)", text, flags=re.IGNORECASE)
    return match.group(1) if match else ""


@lru_cache(maxsize=1)
def detect_evtx_parser_backends() -> dict:
    command = _evtxecmd_command()
    evtxecmd = {
        "available": False,
        "version": "",
        "path": "",
        "supports_csv": False,
        "supports_json": False,
        "error": None,
    }
    if command:
        evtxecmd["path"] = " ".join(command)
        try:
            completed = subprocess.run(
                [*command, "-h"],
                check=False,
                capture_output=True,
                text=True,
                timeout=20,
            )
            help_text = f"{completed.stdout}\n{completed.stderr}"
            evtxecmd.update(
                {
                    "available": completed.returncode in {0, 1},
                    "version": _extract_version(help_text),
                    "supports_csv": "--csv" in help_text or " csv " in help_text.lower(),
                    "supports_json": "--json" in help_text or " json " in help_text.lower(),
                }
            )
            if completed.returncode not in {0, 1}:
                evtxecmd["error"] = help_text.strip()[:1000] or f"exit_{completed.returncode}"
        except Exception as exc:  # noqa: BLE001
            evtxecmd["error"] = str(exc)
    return {
        "evtxecmd": evtxecmd,
        "evtx_raw_python": {
            "available": True,
            "role": "fallback",
            "parser_name": "evtx_raw",
        },
    }


def normalize_evtx_parser_backend(value: object | None) -> str:
    requested = str(value or "").strip().lower()
    if requested in {EVTX_BACKEND_AUTO, EVTXECMD_BACKEND_CSV, "evtxecmd_json", EVTX_RAW_PYTHON_BACKEND, "evtx_raw"}:
        return EVTX_RAW_PYTHON_BACKEND if requested == "evtx_raw" else requested
    return EVTX_BACKEND_AUTO


def select_evtx_parser_backend(value: object | None = None) -> dict:
    requested = normalize_evtx_parser_backend(value or getattr(get_settings(), "evtx_parser_backend", EVTX_BACKEND_AUTO))
    backends = detect_evtx_parser_backends()
    evtxecmd = backends["evtxecmd"]
    if requested == EVTX_BACKEND_AUTO:
        selected = EVTXECMD_BACKEND_CSV if evtxecmd.get("available") and evtxecmd.get("supports_csv") else EVTX_RAW_PYTHON_BACKEND
    elif requested == EVTXECMD_BACKEND_CSV and not evtxecmd.get("available"):
        selected = EVTX_RAW_PYTHON_BACKEND
    elif requested == "evtxecmd_json":
        selected = EVTXECMD_BACKEND_CSV if evtxecmd.get("available") and evtxecmd.get("supports_csv") else EVTX_RAW_PYTHON_BACKEND
    else:
        selected = requested
    return {
        "requested": requested,
        "selected": selected,
        "fallback": requested in {EVTX_BACKEND_AUTO, EVTXECMD_BACKEND_CSV, "evtxecmd_json"} and selected == EVTX_RAW_PYTHON_BACKEND,
        "backends": backends,
        "version": str(evtxecmd.get("version") or ""),
        "error": evtxecmd.get("error"),
    }


def _run_evtxecmd_csv(source_path: Path, output_dir: Path, output_name: str) -> subprocess.CompletedProcess[str]:
    command = _evtxecmd_command()
    if not command:
        raise RuntimeError("EvtxECmd command not available")
    settings = get_settings()
    timeout = max(int(getattr(settings, "evtxecmd_timeout_seconds", 0) or 0), 0) or None
    return subprocess.run(
        [*command, "-f", str(source_path), "--csv", str(output_dir), "--csvf", output_name],
        check=False,
        capture_output=True,
        text=True,
        timeout=timeout,
    )


class EvtxECmdCsvBackend:
    parser_name = EVTXECMD_BACKEND_CSV
    artifact_type = "windows_event"

    def iter_batches(
        self,
        path: Path | str,
        *,
        case_id: str,
        evidence_id: str,
        artifact_id: str,
        artifact_meta: dict,
        batch_size: int,
        progress_cb=None,
    ) -> Iterable[RawParserResult]:
        source_path = Path(path)
        start = time.perf_counter()
        warnings: list[str] = []
        errors: list[str] = []
        records_read = 0
        with tempfile.TemporaryDirectory(prefix="evtxecmd-") as tmp:
            tmp_dir = Path(tmp)
            csv_name = f"{source_path.stem}.csv"
            completed = _run_evtxecmd_csv(source_path, tmp_dir, csv_name)
            if completed.returncode != 0:
                message = (completed.stderr or completed.stdout or f"EvtxECmd exited {completed.returncode}").strip()
                raise RuntimeError(message[:2000])
            csv_path = tmp_dir / csv_name
            if not csv_path.exists():
                matches = sorted(tmp_dir.glob("*.csv"))
                if not matches:
                    raise RuntimeError("EvtxECmd did not produce CSV output")
                csv_path = matches[0]
            parser = EvtxECmdParser()
            csv_meta = {
                **artifact_meta,
                "artifact_type": "windows_event",
                "parser": self.parser_name,
                "source_tool": "evtxecmd",
                "source_format": "csv",
                "source_path": str(artifact_meta.get("source_path") or source_path),
            }
            batch: list[dict] = []
            for document in parser.parse(csv_path, case_id=case_id, evidence_id=evidence_id, artifact_id=artifact_id, artifact_meta=csv_meta):
                records_read += 1
                batch.append(document)
                if progress_cb and records_read % max(int(batch_size or 0), 1) == 0:
                    progress_cb({"records_read": records_read, "events_buffered": len(batch), "errors_count": len(errors), "completed": False})
                if len(batch) >= max(int(batch_size or 0), 1):
                    yield self._result(
                        source_path=str(csv_meta["source_path"]),
                        records_read=records_read,
                        events=batch,
                        warnings=warnings,
                        errors=errors,
                        completed=False,
                        start=start,
                    )
                    batch = []
            if progress_cb:
                progress_cb({"records_read": records_read, "events_buffered": len(batch), "errors_count": len(errors), "completed": True})
            yield self._result(
                source_path=str(csv_meta["source_path"]),
                records_read=records_read,
                events=batch,
                warnings=warnings,
                errors=errors,
                completed=True,
                start=start,
            )

    def _result(
        self,
        *,
        source_path: str,
        records_read: int,
        events: list[dict],
        warnings: list[str],
        errors: list[str],
        completed: bool,
        start: float,
    ) -> RawParserResult:
        result = RawParserResult(
            parser_name=self.parser_name,
            artifact_type="windows_event",
            source_path=source_path,
            records_read=records_read,
            events=events,
            warnings=list(warnings),
            errors=list(errors),
            parser_status="parsed_native" if not errors else "failed",
            metadata={
                "completed": completed,
                "parse_duration_ms": int((time.perf_counter() - start) * 1000),
                "evtx_parser_backend": self.parser_name,
            },
        )
        result.metadata["audit"] = build_raw_parser_audit(result)
        return result
