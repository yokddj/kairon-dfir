from pathlib import Path

import yaml

from app.rules_engine.builtin_catalog import BUILTIN_DETECTION_CATALOG


ROOT = Path(__file__).resolve().parents[2]
DOCS_DIR = ROOT / "docs"

EXPECTED_DOCS = [
    "index.md",
    "architecture.md",
    "quickstart.md",
    "ingestion.md",
    "artifacts.md",
    "evtx.md",
    "prefetch.md",
    "lnk.md",
    "jumplists.md",
    "registry.md",
    "filesystem_mft_usn.md",
    "browser.md",
    "velociraptor_ingest.md",
    "execution_artifacts.md",
    "srum.md",
    "scheduled_tasks.md",
    "defender.md",
    "powershell_artifacts.md",
    "semi_automatic_analysis.md",
    "builtin_rules.md",
    "rule_authoring.md",
    "app_sections.md",
    "opensearch.md",
    "troubleshooting.md",
    "roadmap.md",
    "documentation_maintenance.md",
]


def test_docs_files_exist() -> None:
    for filename in EXPECTED_DOCS:
        assert (DOCS_DIR / filename).exists(), f"Missing docs file: {filename}"


def test_frontend_route_and_sidebar_include_docs() -> None:
    app_tsx = (ROOT / "frontend/src/App.tsx").read_text(encoding="utf-8")
    sidebar_tsx = (ROOT / "frontend/src/components/Sidebar.tsx").read_text(encoding="utf-8")
    assert 'path="/docs"' in app_tsx
    assert 'label: "Docs"' in sidebar_tsx


def test_builtin_catalog_has_minimum_metadata() -> None:
    required = {
        "key",
        "name",
        "description",
        "severity_source",
        "default_enabled",
        "evidence",
        "fields_consulted",
        "example_match",
        "false_positives",
        "investigation_guidance",
    }
    assert BUILTIN_DETECTION_CATALOG, "Builtin detection catalog is empty"
    for key, definition in BUILTIN_DETECTION_CATALOG.items():
        values = definition.__dict__
        assert required <= set(values), f"Builtin detection {key} is missing metadata"
        for field in required:
            assert values[field] not in (None, ""), f"Builtin detection {key} has empty field {field}"


def test_builtin_overrides_file_exists_and_is_valid_yaml() -> None:
    overrides_path = ROOT / "backend/app/rules/builtin_detection_overrides.yaml"
    data = yaml.safe_load(overrides_path.read_text(encoding="utf-8"))
    assert isinstance(data, dict)
    assert "disabled_rules" in data
    assert isinstance(data["disabled_rules"], list)
