from __future__ import annotations

import argparse

from app.core.database import SessionLocal
from app.models.evidence import Evidence
from app.models.memory import MemoryPluginRun, MemoryScanRun
from app.services.memory.evidence_access import validate_current_process_evidence_access
from app.services.memory.storage import memory_run_dir
from app.services.memory.symbol_control import record_symbol_requirement
from app.services.memory.volatility_runner import probe_windows_symbol_identity


def discover_for_run(run_id: str) -> bool:
    with SessionLocal() as db:
        run = db.get(MemoryScanRun, run_id)
        if run is None or (run.error_log or {}).get("code") != "SYMBOLS_UNAVAILABLE":
            return False
        plugin = (
            db.query(MemoryPluginRun)
            .filter(MemoryPluginRun.memory_scan_run_id == run.id, MemoryPluginRun.plugin == "windows.info")
            .first()
        )
        evidence = db.get(Evidence, run.evidence_id)
        if plugin is None or evidence is None:
            return False
        access = validate_current_process_evidence_access(evidence)
        payload = probe_windows_symbol_identity(access.path, memory_run_dir(run.case_id, run.evidence_id, run.id))
        return bool(payload and record_symbol_requirement(db, run, plugin.id, payload))


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--run-id", required=True)
    args = parser.parse_args()
    print("recorded" if discover_for_run(args.run_id) else "not-recorded")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
