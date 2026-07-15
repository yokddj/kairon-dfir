from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]


def test_linux_support_doc_documents_collections_inventory_coverage_and_memory() -> None:
    content = (ROOT / "docs" / "linux-support.md").read_text(encoding="utf-8")

    for expected in ["ZIP", "TAR", "Auto-Discovery", "Coverage", "Linux Memory", "not available yet"]:
        assert expected in content


def test_readme_has_linux_support_section_without_claiming_full_memory_analysis() -> None:
    content = (ROOT / "README.md").read_text(encoding="utf-8")

    assert "## Linux Support" in content
    assert "auth logs" in content
    assert "systemd" in content
    assert "does not provide full advanced Linux memory analysis yet" in content
