from __future__ import annotations

import inspect

import pytest

from app.services import evidence_preflight


def test_diagnostics_name_the_file_whose_values_actually_win() -> None:
    """A remediation that names the wrong file is worse than none at all.

    Every blocking diagnostic used to tell the operator to edit "backend/.env".
    That file is not part of the deployment: docker-compose loads
    config/defaults.env and then the repository-root .env, so the root .env is
    both the file that exists and the one whose values override the defaults.
    Following the old instruction to the letter changed nothing and the upload
    stayed blocked with the identical message.
    """
    assert evidence_preflight.SETTINGS_OVERRIDE_FILE == ".env"


def test_no_diagnostic_points_at_backend_env_any_more() -> None:
    source = inspect.getsource(evidence_preflight)
    assert 'configuration_file="backend/.env"' not in source
    assert '"Edit backend/.env"' not in source


def test_every_configuration_file_reference_goes_through_the_constant() -> None:
    """One constant, so the five diagnostics can never drift apart again."""
    source = inspect.getsource(evidence_preflight)
    references = [line.strip() for line in source.splitlines() if line.strip().startswith("configuration_file=")]
    assert references, "expected the preflight to still emit configuration_file hints"
    for reference in references:
        assert reference == "configuration_file=SETTINGS_OVERRIDE_FILE,", reference


@pytest.mark.parametrize("key", ["BACKEND_MAX_EXTRACTED_BYTES", "MAX_ARCHIVE_DEPTH", "DISK_IMAGE_MAX_CHAIN_DEPTH"])
def test_limit_diagnostics_still_name_their_setting(key: str) -> None:
    source = inspect.getsource(evidence_preflight)
    assert f'configuration_key="{key}"' in source
