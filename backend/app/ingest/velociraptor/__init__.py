from __future__ import annotations

from importlib import import_module


_EXPORT_MAP = {
    "RAW_UPLOAD_NAME_MAP": ("app.ingest.velociraptor.discovery", "RAW_UPLOAD_NAME_MAP"),
    "RAW_UPLOAD_PATTERNS": ("app.ingest.velociraptor.discovery", "RAW_UPLOAD_PATTERNS"),
    "discover_velociraptor_evidences": ("app.ingest.velociraptor.discovery", "discover_velociraptor_evidences"),
    "list_velociraptor_artifacts": ("app.ingest.velociraptor.discovery", "list_velociraptor_artifacts"),
    "list_velociraptor_upload_artifacts": ("app.ingest.velociraptor.discovery", "list_velociraptor_upload_artifacts"),
    "VelociraptorDiscoveryResult": ("app.ingest.velociraptor.models", "VelociraptorDiscoveryResult"),
    "VelociraptorEvidenceCandidate": ("app.ingest.velociraptor.models", "VelociraptorEvidenceCandidate"),
    "normalize_velociraptor_path": ("app.ingest.velociraptor.path_utils", "normalize_velociraptor_path"),
    "build_selected_velociraptor_artifacts": ("app.ingest.velociraptor.parser_dispatcher", "build_selected_velociraptor_artifacts"),
    "ContainerEntry": ("app.ingest.velociraptor.zip_inventory", "ContainerEntry"),
    "DirectoryEvidenceContainer": ("app.ingest.velociraptor.zip_inventory", "DirectoryEvidenceContainer"),
    "EvidenceContainer": ("app.ingest.velociraptor.zip_inventory", "EvidenceContainer"),
    "ZipEvidenceContainer": ("app.ingest.velociraptor.zip_inventory", "ZipEvidenceContainer"),
    "inventory_summary": ("app.ingest.velociraptor.zip_inventory", "inventory_summary"),
    "open_evidence_container": ("app.ingest.velociraptor.zip_inventory", "open_evidence_container"),
}

__all__ = list(_EXPORT_MAP)


def __getattr__(name: str):
    target = _EXPORT_MAP.get(name)
    if not target:
        raise AttributeError(name)
    module_name, attr_name = target
    module = import_module(module_name)
    value = getattr(module, attr_name)
    globals()[name] = value
    return value

