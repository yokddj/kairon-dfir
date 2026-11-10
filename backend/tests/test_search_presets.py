"""Default searches (quick filters, capability presets) must match what parsers index."""

from app.core.artifact_registry import artifact_registry_entries
from app.search.query_syntax import analyze_query_syntax
from app.services import search_service
from app.services.case_capabilities import CAPABILITY_REGISTRY
from app.services.search_service import QUICK_FILTERS, _artifact_type_values

# Indexed artifact types that are not entries of the artifact registry.
INDEXED_OUTSIDE_REGISTRY = {
    "registry_persistence",  # raw_parsers/registry_persistence_summary.py
    "autoruns",  # detector.py artifact type; events are "autorun" (see alias)
}


def _known_types() -> set[str]:
    known = set(INDEXED_OUTSIDE_REGISTRY)
    for entry in artifact_registry_entries():
        known.add(entry["id"])
        known.update(entry.get("aliases") or [])
    return known


def _quick(filter_id: str) -> dict:
    return next(item["params"] for item in QUICK_FILTERS if item["id"] == filter_id)


def test_disk_capability_presets_only_name_indexed_artifact_types() -> None:
    known = _known_types()
    for entry in CAPABILITY_REGISTRY:
        if entry.get("evidence_domain") == "memory":
            continue
        search = entry.get("search") or {}
        states = [search.get("default_filters") or {}, *[preset.get("state") or {} for preset in search.get("presets") or []]]
        for state in states:
            unknown = set(state.get("artifact_type") or []) - known
            assert not unknown, f"{entry.get('id')}: {sorted(unknown)} is not an indexed artifact type"


def test_autoruns_filter_matches_the_autorun_events() -> None:
    assert "autorun" in _artifact_type_values(["autoruns"])


def test_downloads_covers_every_download_record() -> None:
    event_types = set(_quick("downloads")["event_type"])
    assert {"file_downloaded", "bits_job_transferred", "file_zone_identifier_observed", "download_started"} <= event_types


def test_process_executions_include_sysmon_and_prefetch() -> None:
    event_types = set(_quick("process_executions")["event_type"])
    assert {"process_start", "sysmon_process_created", "prefetch_execution"} <= event_types


def test_powershell_activity_is_logs_or_powershell_processes() -> None:
    params = _quick("powershell_activity")
    assert "process_name" not in params
    info = analyze_query_syntax(params["q"], search_service._build_text_query)
    fields = {item.get("field") for item in info["applied_filters"]}
    assert {"artifact.type", "process.name"} <= fields
