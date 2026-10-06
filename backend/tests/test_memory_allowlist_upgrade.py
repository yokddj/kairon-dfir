"""Deployments whose .env still holds an earlier default allowlist get the analyses added since."""

from app.core.config import Settings

OLD_PROFILES = "metadata_only,processes_basic,processes_extended,network_basic,modules_basic,handles_basic,kernel_basic,suspicious_memory,shell_history_basic,files_basic"
OLD_PLUGINS = "windows.info,windows.pslist,windows.pstree,windows.psscan,windows.cmdline,windows.envars,windows.getsids,windows.privileges,windows.netscan,windows.netstat,windows.dlllist,windows.ldrmodules,windows.handles,windows.modules,windows.driverscan,windows.malfind,windows.vadinfo,windows.consoles,windows.filescan,linux.pslist,linux.pstree,linux.sockstat,linux.bash"


def test_an_unchanged_earlier_default_gets_find_evil() -> None:
    settings = Settings(memory_allowed_profiles=OLD_PROFILES, memory_allowed_plugins=OLD_PLUGINS)
    assert settings.allowed_memory_profiles[-1] == "find_evil"
    assert "memprocfs.findevil" in settings.allowed_memory_plugins


def test_an_operator_list_is_left_alone() -> None:
    settings = Settings(memory_allowed_profiles="metadata_only,processes_basic", memory_allowed_plugins="windows.info,windows.pslist")
    assert settings.allowed_memory_profiles == ["metadata_only", "processes_basic"]
    assert settings.allowed_memory_plugins == ["windows.info", "windows.pslist"]


def test_the_current_default_is_not_extended_twice() -> None:
    settings = Settings()
    assert settings.allowed_memory_profiles.count("find_evil") == 1
    assert settings.allowed_memory_plugins.count("memprocfs.findevil") == 1
