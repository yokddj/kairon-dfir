from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]


def test_linux_support_doc_documents_collections_inventory_coverage_and_memory() -> None:
    content = (ROOT / "docs" / "linux" / "linux-support.md").read_text(encoding="utf-8")

    for expected in ["ZIP", "TAR", "Auto-Discovery", "Coverage", "Linux Memory", "symbol file for the exact kernel", "../memory/linux_symbols.md"]:
        assert expected in content
    assert "analysis with Volatility is not available" not in content


def test_readme_has_linux_support_section_with_memory_symbol_requirement() -> None:
    content = (ROOT / "README.md").read_text(encoding="utf-8")

    assert "## Linux Support" in content
    assert "authentication and system logs" in content
    assert "systemd" in content
    assert "Linux memory images are analyzed with Volatility 3" in content
    assert "symbol file for the exact kernel" in content
