from __future__ import annotations

import json
import os
from pathlib import Path
from tempfile import NamedTemporaryFile
from typing import Any

from app.core.config import get_settings
from app.core.storage import build_evidence_root, sha256_file


def memory_run_dir(case_id: str, evidence_id: str, run_id: str) -> Path:
    settings = get_settings()
    output_root = settings.memory_output_root
    if output_root:
        path = output_root / "evidence" / case_id / evidence_id / "memory" / "runs" / run_id
    else:
        path = build_evidence_root(case_id, evidence_id) / "memory" / "runs" / run_id
    path.mkdir(parents=True, exist_ok=True, mode=0o750)
    return path


def relative_to_data_dir(path: Path) -> str:
    resolved = path.resolve()
    settings = get_settings()
    output_root = settings.memory_output_root
    for root, prefix in ((settings.backend_data_dir.resolve(), ""), ((output_root.resolve() if output_root else None), "memory-output")):
        if root is None:
            continue
        try:
            relative = resolved.relative_to(root)
            return str(Path(prefix) / relative) if prefix else str(relative)
        except ValueError:
            continue
    return Path(path.name).name


def write_atomic_bytes(path: Path, data: bytes) -> dict[str, Any]:
    settings = get_settings()
    if len(data) > int(settings.memory_plugin_output_max_bytes):
        raise ValueError("output_too_large")
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o750)
    with NamedTemporaryFile("wb", delete=False, dir=str(path.parent), prefix=f".{path.name}.", suffix=".tmp") as handle:
        temp_path = Path(handle.name)
        handle.write(data)
        handle.flush()
        os.fsync(handle.fileno())
    temp_path.replace(path)
    return {"path": relative_to_data_dir(path), "sha256": sha256_file(path), "size": path.stat().st_size}


def write_atomic_json(path: Path, payload: Any) -> dict[str, Any]:
    data = json.dumps(payload, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return write_atomic_bytes(path, data)
