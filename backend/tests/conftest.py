import os
from pathlib import Path

import pytest
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.ext.compiler import compiles


@compiles(UUID, "sqlite")
def _uuid_as_text_on_sqlite(type_, compiler, **kw):
    # Tests run the models on SQLite, where a column declared UUID has numeric affinity: a random
    # id that happens to read as a number (digits and a single "e") was stored as a float and
    # failed on read. Text affinity keeps every id a string. Production runs on PostgreSQL.
    return "CHAR(36)"


def pytest_configure():
    os.environ.setdefault("KAIRON_AUTH_ENABLED", "false")


@pytest.fixture(autouse=True)
def _restore_cached_settings():
    """Some tests rebuild settings from the environment with get_settings.cache_clear().
    Modules (and other tests) that read get_settings() earlier keep the old instance, so
    later tests patched one object while the code read another. Put the original back."""
    from app.core import config

    original = config.get_settings()
    yield
    if config.get_settings() is original:
        return
    config.get_settings.cache_clear()
    settings_class = config.Settings
    config.Settings = lambda: original
    try:
        config.get_settings()
    finally:
        config.Settings = settings_class


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
