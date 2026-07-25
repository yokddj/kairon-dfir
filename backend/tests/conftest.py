import os
from pathlib import Path

import pytest


def pytest_configure():
    os.environ.setdefault("KAIRON_AUTH_ENABLED", "false")


def _load_known_failures() -> set[str]:
    path = Path(__file__).with_name("known_failures.txt")
    if not path.exists():
        return set()
    node_ids = set()
    for line in path.read_text(encoding="utf-8").splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        node_ids.add(stripped)
    return node_ids


_KNOWN_FAILURES = _load_known_failures()


def pytest_collection_modifyitems(config, items):
    """Mark pre-existing, tracked failures as xfail instead of letting the
    whole suite run under CI-wide continue-on-error. A regression in any
    test NOT in tests/known_failures.txt still fails the build; entries in
    that file are visible in the run summary as xfailed, not silently
    absent, and are not gated on being fixed first (strict=False)."""
    if not _KNOWN_FAILURES:
        return
    marker = pytest.mark.xfail(
        reason="Pre-existing failure tracked in tests/known_failures.txt (not a regression from current work)",
        strict=False,
    )
    for item in items:
        if item.nodeid in _KNOWN_FAILURES:
            item.add_marker(marker)
