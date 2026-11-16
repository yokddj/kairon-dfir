"""Free text embedded in an OpenSearch wildcard query must stay literal."""

from __future__ import annotations

from app.core.opensearch import wildcard_literal


def test_backslashes_are_escaped_so_windows_paths_match() -> None:
    # In a wildcard query a backslash escapes the next character: unescaped,
    # "Edge\User Data" looked for "EdgeUser Data" and matched nothing.
    assert wildcard_literal("Edge\\User Data") == "Edge\\\\User Data"


def test_pattern_characters_are_dropped() -> None:
    assert wildcard_literal("*evil?.exe") == "evil.exe"
