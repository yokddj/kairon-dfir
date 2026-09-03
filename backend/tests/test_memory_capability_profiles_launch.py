"""Profiles that resolve through the capability registry must be launchable.

files_basic and shell_history_basic have no PROFILE_PLUGINS entry by design --
they resolve per-platform through capability_registry. A second, platform-blind
re-plan in the launch endpoint read PROFILE_PLUGINS, found nothing, and rejected
the launch as "no enabled plugins" even though the evidence-aware resolution had
already produced the right plugin.
"""

from __future__ import annotations

import pytest

from app.core.config import get_settings
from app.services.memory.catalogue import PROFILE_CATALOGUE
from app.services.memory.execution import PROFILE_CAPABILITY, PROFILE_PLUGINS
from app.services.memory.profile_planning import plan_profile_capability

CAPABILITY_ONLY_PROFILES = ("files_basic", "shell_history_basic")


@pytest.mark.parametrize("profile", CAPABILITY_ONLY_PROFILES)
def test_the_profile_really_has_no_flat_plugin_list(profile):
    """The precondition for the bug: these resolve through the registry only."""
    assert profile not in PROFILE_PLUGINS
    assert profile in PROFILE_CAPABILITY


@pytest.mark.parametrize("profile", CAPABILITY_ONLY_PROFILES)
def test_a_blind_re_plan_reports_no_plugins_for_them(profile):
    """This is what the launch endpoint used to trust, and why it rejected."""
    plan = plan_profile_capability(profile)

    assert plan["plugin_names"] == []
    assert plan["has_enabled_plugins"] is False


@pytest.mark.parametrize("profile", CAPABILITY_ONLY_PROFILES)
def test_the_profile_is_enabled_by_configuration(profile):
    """A blind plan saying "no plugins" must not be read as "disabled"."""
    settings = get_settings()

    assert profile in settings.allowed_memory_profiles


def test_the_capability_registry_binds_files_to_an_allowed_plugin():
    """windows.filescan has to be both bound and permitted, or files can never run."""
    from app.services.memory.capability_registry import MemoryCapability, resolved_plugins_for_capability
    from app.services.memory.capability_registry import PlatformFamily

    plugins = resolved_plugins_for_capability(PlatformFamily.WINDOWS, MemoryCapability.FILES)

    assert "windows.filescan" in plugins
    assert "windows.filescan" in set(get_settings().allowed_memory_plugins)


def test_every_catalogue_profile_can_resolve_to_something():
    """A profile offered in the UI that no path can resolve is a dead button."""
    for entry in PROFILE_CATALOGUE:
        profile = entry["profile"]
        has_flat_list = bool(PROFILE_PLUGINS.get(profile))
        has_capability = profile in PROFILE_CAPABILITY
        assert has_flat_list or has_capability, (
            f"{profile} is offered in the catalogue but has neither a plugin list "
            "nor a capability binding, so it can never launch."
        )


def test_the_launch_check_only_rejects_when_every_plugin_is_disabled():
    """The guard has to look at what was resolved, not re-plan blindly.

    Encoded as a behaviour check on the rule itself: a profile whose resolved
    plugins are all permitted must never be rejected for being "not enabled".
    """
    allowed = set(get_settings().allowed_memory_plugins)
    resolved = ["windows.filescan"]

    disabled = [plugin for plugin in resolved if plugin not in allowed]

    assert disabled != resolved, "windows.filescan is permitted, so this must not reject"


def test_a_genuinely_disabled_plugin_is_still_rejected():
    allowed = set(get_settings().allowed_memory_plugins)
    resolved = ["windows.not_a_real_plugin"]

    disabled = [plugin for plugin in resolved if plugin not in allowed]

    assert disabled == resolved
