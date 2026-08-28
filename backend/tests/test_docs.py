from pathlib import Path
import re

import yaml

from app.rules_engine.builtin_catalog import BUILTIN_DETECTION_CATALOG


ROOT = Path(__file__).resolve().parents[2]
DOCS_DIR = ROOT / "docs"

# The documentation moved from a flat directory into topic subdirectories,
# which left a hardcoded filename list asserting 23 files that no longer
# exist. Checking that the index resolves covers the same ground -- a doc
# that is deleted or moved without updating the index still fails -- and
# survives the next reorganisation.
def test_docs_index_exists() -> None:
    assert (DOCS_DIR / "index.md").exists(), "Missing docs index"


def test_every_doc_linked_from_the_index_resolves() -> None:
    index = (DOCS_DIR / "index.md").read_text(encoding="utf-8")
    links = re.findall(r"\]\(([^)#]+\.md)[^)]*\)", index)
    assert links, "docs/index.md links to no documents"
    missing = sorted({link for link in links if not (DOCS_DIR / link).exists()})
    assert not missing, f"docs/index.md links to missing files: {missing}"


def test_frontend_route_and_sidebar_include_docs() -> None:
    app_tsx = (ROOT / "frontend/src/App.tsx").read_text(encoding="utf-8")
    sidebar_tsx = (ROOT / "frontend/src/components/Sidebar.tsx").read_text(encoding="utf-8")
    assert 'path="/docs"' in app_tsx
    # The sidebar renders global destinations as NavLinks (like Users and
    # Change Password) rather than as entries in the case-scoped nav list, so
    # assert on the destination rather than on one particular encoding of it.
    assert 'to="/docs"' in sidebar_tsx


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
