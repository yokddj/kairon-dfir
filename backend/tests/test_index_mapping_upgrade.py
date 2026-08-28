from __future__ import annotations

import inspect

from app.core import opensearch


def _mapping_source() -> str:
    return inspect.getsource(opensearch.ensure_case_index)


def test_new_fields_are_sent_to_indices_that_already_exist() -> None:
    """A mapping added to create() alone only helps people who install fresh.

    ensure_case_index creates an index or, when one is already there, sends the
    current fields to it. A field added only to the create path leaves every
    existing installation on the mapping it was installed with: its Linux data
    stays unqueryable and the promoted Sysmon fields are never indexed, so the
    machine behaves like an older version than the one it is running.
    """
    source = _mapping_source()
    create_at = source.index("indices.create")
    upgrade_at = source.index("put_mapping")
    upgrade_block = source[upgrade_at:]

    for field in ("original_file_name", "integrity_level_name"):
        assert field in upgrade_block, f"{field} is only in the create path"
    assert source.count('"linux"') >= 2, "the linux block must be in both paths"
    assert create_at < upgrade_at


def test_the_linux_block_declares_fields_rather_than_relying_on_dynamic_mapping() -> None:
    """The root mapping is dynamic:false, so a bare enabled object never gets
    subfields and everything written under it is unsearchable."""
    source = _mapping_source()
    linux_at = source.index('"linux"')
    block = source[linux_at : linux_at + 900]

    assert '"properties"' in block
    for field in ("command", "process", "username", "source_ip"):
        assert f'"{field}"' in block, field


def test_extraction_limits_are_not_below_the_code_default() -> None:
    """config/defaults.env used to override the code default down to 2 GiB,
    which refused ordinary triage collections on a fresh install."""
    from pathlib import Path

    defaults = Path(__file__).resolve().parents[2] / "config" / "defaults.env"
    if not defaults.exists():  # not shipped in every deployment layout
        return
    values = {}
    for line in defaults.read_text().splitlines():
        if line.startswith("BACKEND_MAX_EXTRACTED"):
            key, _, value = line.partition("=")
            values[key.strip()] = int(value.strip())

    assert values.get("BACKEND_MAX_EXTRACTED_BYTES", 0) >= 10 * 1024**3
    assert values.get("BACKEND_MAX_EXTRACTED_FILES", 0) >= 100000
