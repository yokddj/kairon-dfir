import json
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
COVERAGE_PATH = ROOT / "docs" / "data" / "parser-coverage.json"
DOC_PATH = ROOT / "docs" / "parser-coverage.md"

ALLOWED_STATUSES = {"stable", "partial", "experimental", "planned", "unsupported", "deprecated"}
ALLOWED_VIEWS = {
    "Artifact Explorer",
    "Search",
    "Timeline",
    "Detections",
    "Command History",
    "Process Graph",
    "Memory views",
    "Rules",
}


def _coverage() -> list[dict]:
    return json.loads(COVERAGE_PATH.read_text(encoding="utf-8"))


def test_parser_coverage_json_is_valid():
    data = _coverage()

    assert isinstance(data, list)
    assert len(data) >= 20


def test_each_family_has_required_fields_and_allowed_status():
    for item in _coverage():
        assert item.get("family")
        assert item.get("display_name")
        assert item.get("status") in ALLOWED_STATUSES
        assert isinstance(item.get("input_formats"), list)
        assert isinstance(item.get("limitations"), list)
        assert isinstance(item.get("normalized_fields"), list)
        assert isinstance(item.get("views"), list)


def test_no_duplicate_families():
    families = [item["family"] for item in _coverage()]

    assert len(families) == len(set(families))


def test_referenced_views_are_allowed():
    unknown = sorted({view for item in _coverage() for view in item.get("views", []) if view not in ALLOWED_VIEWS})

    assert unknown == []


def test_real_expected_families_are_present_with_honest_statuses():
    by_family = {item["family"]: item for item in _coverage()}

    assert by_family["evtx"]["status"] == "stable"
    assert by_family["memory"]["status"] == "experimental"
    assert by_family["linux_macos_triage"]["status"] == "unsupported"
    assert by_family["srum"]["status"] == "partial"
    assert "Raw SRUDB.dat" in " ".join(by_family["srum"]["limitations"])


def test_documentation_references_structured_source_and_collectors():
    content = DOC_PATH.read_text(encoding="utf-8")

    assert "docs/data/parser-coverage.json" in content
    assert "Collector Compatibility" in content
    assert "KAPE" in content
    assert "Velociraptor" in content
    assert "does not redistribute third-party collector binaries" in content
