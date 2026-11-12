"""Give Volatility the memory layer of a Windows image whose page tables it cannot find on its own.

Volatility looks for the kernel's page-table base (DTB) by scanning a few physical ranges for a
self-referencing page table. On some captures nothing matches: it builds no memory layer, and
every plugin fails with INVALID_MEMORY_LAYER although the image is fine. MemProcFS finds the DTB
its own way (app.services.memory.memprocfs_dtb, well under a second). With it, Volatility gets
its layer from a configuration file (``vol -c``) instead of its scan: the Intel paging layer at
that DTB over the image's physical layer. Volatility does not read the DTB a crash-dump header
records, so this is also what makes crash dumps it cannot scan readable.

The DTB found is kept in ``evidence.metadata_json["volatility_layer"]``; the configuration is
written next to each use (the evidence path differs between containers).
"""

from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import Any, Callable

from sqlalchemy.orm import Session
from sqlalchemy.orm.attributes import flag_modified

from app.core.database import utc_now_naive
from app.models.evidence import Evidence

logger = logging.getLogger(__name__)

METADATA_KEY = "volatility_layer"
CONFIG_FILENAME = "volatility-layer.json"

_LAYERS = "volatility3.framework.layers."
_PAGING_CLASSES = {
    ("Intel64", False): _LAYERS + "intel.WindowsIntel32e",
    ("Intel64", True): _LAYERS + "intel.WindowsIntel32e",
    ("Intel32", True): _LAYERS + "intel.WindowsIntelPAE",
    ("Intel32", False): _LAYERS + "intel.WindowsIntel",
}
# Containers whose physical addresses are not file offsets and that Volatility reads through a
# layer of its own this module does not build: left to Volatility.
_OTHER_CONTAINERS = (b"\x7fELF", b"EMiL", b"hibr", b"HIBR", b"wake", b"WAKE", b"RSTR", b"rstr")
_VMWARE_STATE_SUFFIXES = (".vmss", ".vmsn")


def _physical_layer(evidence_path: Path) -> dict[str, Any] | None:
    """The physical layer stack of the image, as Volatility configuration under ``memory_layer``."""
    path = Path(evidence_path)
    try:
        with path.open("rb") as handle:
            head = handle.read(8)
    except OSError:
        return None
    location = path.resolve().as_uri()
    file_layer = _LAYERS + "physical.FileLayer"
    if head.startswith(b"PAGEDU64") or head.startswith(b"PAGEDUMP"):
        crash = _LAYERS + ("crash.WindowsCrashDump64Layer" if head.startswith(b"PAGEDU64") else "crash.WindowsCrashDump32Layer")
        return {"memory_layer.class": crash, "memory_layer.base_layer.class": file_layer, "memory_layer.base_layer.location": location}
    if head.startswith(_OTHER_CONTAINERS):
        return None
    if path.suffix.lower() == ".vmem" and any(path.with_suffix(suffix).exists() for suffix in _VMWARE_STATE_SUFFIXES):
        return None
    # A raw capture: physical address = file offset, as MemProcFS read it.
    return {"memory_layer.class": file_layer, "memory_layer.location": location}


def layer_config(evidence_path: Path, found: dict[str, Any]) -> dict[str, Any] | None:
    """Volatility configuration (relative to the plugin) pinning the kernel layer to ``found``'s DTB."""
    paging = _PAGING_CLASSES.get((str(found.get("architecture") or "Intel64"), bool(found.get("pae"))))
    physical = _physical_layer(evidence_path)
    if paging is None or physical is None:
        return None
    config: dict[str, Any] = {"kernel.layer_name.class": paging, "kernel.layer_name.page_map_offset": int(found["page_map_offset"])}
    config.update({f"kernel.layer_name.{key}": value for key, value in physical.items()})
    return config


def recorded(evidence: Evidence) -> dict[str, Any] | None:
    value = (evidence.metadata_json or {}).get(METADATA_KEY)
    return value if isinstance(value, dict) and value.get("page_map_offset") is not None else None


def write_config(work_dir: Path, evidence_path: Path, evidence: Evidence) -> Path | None:
    """Write the pinned layer for this evidence into ``work_dir``; None when it has none."""
    found = recorded(evidence)
    if found is None:
        return None
    config = layer_config(evidence_path, found)
    if config is None:
        return None
    target = Path(work_dir) / CONFIG_FILENAME
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(json.dumps(config, indent=1), encoding="utf-8")
    return target


def find_and_record(
    db: Session,
    evidence: Evidence,
    evidence_path: Path,
    work_dir: Path,
    *,
    timeout_seconds: int = 600,
    cancellation_check: Callable[[], bool] | None = None,
) -> Path | None:
    """Memory worker: ask MemProcFS for the DTB, keep it on the evidence, write the configuration.
    None when MemProcFS has none or this image's layout is one this module does not build."""
    from app.services.memory.memprocfs_runner import memprocfs_available, run_dtb
    from app.services.memory.volatility_runner import VolatilityRunnerError

    if not memprocfs_available() or _physical_layer(evidence_path) is None:
        return None
    try:
        found = run_dtb(Path(evidence_path), Path(work_dir), timeout_seconds=timeout_seconds, cancellation_check=cancellation_check)
    except VolatilityRunnerError as exc:
        logger.info("MemProcFS gave no page-table base for Volatility", extra={"evidence_id": evidence.id, "code": exc.code})
        return None
    metadata = dict(evidence.metadata_json or {})
    metadata[METADATA_KEY] = {
        "page_map_offset": int(found["page_map_offset"]),
        "architecture": str(found.get("architecture") or "Intel64"),
        "pae": bool(found.get("pae")),
        "source": "MemProcFS",
        "at": utc_now_naive().isoformat(timespec="seconds") + "Z",
    }
    metadata.pop("volatility_layer_missing", None)
    evidence.metadata_json = metadata
    flag_modified(evidence, "metadata_json")
    db.add(evidence)
    db.commit()
    return write_config(work_dir, evidence_path, evidence)
