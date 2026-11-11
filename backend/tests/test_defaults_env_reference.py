"""config/defaults.env lists every setting an operator may change, so .env can carry the full
reference (scripts/setup.sh adds the missing ones, commented). A new Settings field must be added
there, or to INTERNAL below with the reason it is not an operator setting."""

from __future__ import annotations

import re
from pathlib import Path

from app.core.config import Settings

ROOT = Path(__file__).resolve().parents[2]

INTERNAL = {
    # Secrets and bootstrap credentials: written to .env by scripts/setup.sh, never in defaults.
    "SESSION_SECRET_KEY", "AI_SECRET_KEY", "OPENSEARCH_PASSWORD", "MEMORY_SYMBOL_EGRESS_GATEWAY_SECRET",
    "BOOTSTRAP_ADMIN_USERNAME", "BOOTSTRAP_ADMIN_PASSWORD", "BOOTSTRAP_ADMIN_EMAIL",
    # Set by setup.sh / docker-compose from other variables (KAIRON_AUTH_ENABLED, the public URL, ...).
    "AUTH_ENABLED", "ALLOWED_ORIGINS_ENV", "BACKEND_CORS_ORIGIN_REGEX", "MEMORY_ENABLED",
    "MEMORY_EVIDENCE_SHARED_GID", "MEMORY_WORKER_UID", "MEMORY_WORKER_GID", "MEMORY_WORKER_CONTAINER_NAME",
    "MEMORY_TOOLS_AUTO_INSTALL_ENABLED", "MEMORY_MAX_UPLOAD_SIZE",
    # Build identity.
    "APP_VENDOR_ID", "APP_BUILD_CHANNEL", "APP_BUILD_FINGERPRINT",
    # Paths of tools and directories inside the images.
    "MEMPROCFS_LIBRARY", "MEMPROCFS_GDB_COMMAND", "EVTXECMD_EXECUTABLE", "EVTXECMD_DOTNET_DLL",
    "MFTECMD_DOTNET_DLL", "SRUMECMD_DOTNET_DLL", "SBECMD_DOTNET_DLL",
    "MEMORY_SYMBOL_IMPORT_QUARANTINE_ROOT", "MEMORY_LINUX_SYMBOL_CACHE_ROOT", "MEMORY_LINUX_SYMBOL_STAGING_ROOT",
    "MEMORY_NATIVE_PROBE_CACHE_ROOT", "MEMORY_NATIVE_PROBE_TASK_QUEUE", "MEMORY_NATIVE_PROBE_PLUGIN",
    # Index names, fixed by the deployment.
    "OPENSEARCH_MEMORY_INDEX_PREFIX", "OPENSEARCH_TABLE_INDEX_PREFIX",
    # Experimental symbol-mismatch analysis: not for operators.
    "MEMORY_SYMBOL_EXPERIMENTAL_MISMATCH_ENABLED", "MEMORY_EXPERIMENTAL_TASK_QUEUE", "OPENSEARCH_MEMORY_EXPERIMENTAL_INDEX_PREFIX",
    "MEMORY_EXPERIMENTAL_CANARY_TIMEOUT_SECONDS", "MEMORY_EXPERIMENTAL_RUN_TIMEOUT_SECONDS", "MEMORY_EXPERIMENTAL_ACK_WARNING_VERSION",
}


def _names(path: Path) -> set[str]:
    return set(re.findall(r"^#?\s*([A-Z][A-Z0-9_]*)=", path.read_text(encoding="utf-8"), re.M))


def test_every_operator_setting_is_in_the_reference():
    listed = _names(ROOT / "config" / "defaults.env") | _names(ROOT / ".env.example")
    missing = sorted(name.upper() for name in Settings.model_fields if name.upper() not in listed and name.upper() not in INTERNAL)
    assert not missing, f"Add these settings to config/defaults.env (or to INTERNAL with a reason): {missing}"


def test_internal_names_are_real_settings():
    assert INTERNAL <= {name.upper() for name in Settings.model_fields}


def _deployment(tmp_path: Path, env_text: str) -> Path:
    import shutil

    (tmp_path / "scripts").mkdir()
    (tmp_path / "config").mkdir()
    shutil.copy(ROOT / "scripts" / "sync-env-reference.sh", tmp_path / "scripts")
    shutil.copy(ROOT / "config" / "defaults.env", tmp_path / "config")
    env = tmp_path / ".env"
    env.write_text(env_text, encoding="utf-8")
    return env


def _upgrade(tmp_path: Path) -> None:
    """What upgrade.sh runs: migrate_memory_allowlists, taken from the pulled setup.sh."""
    import subprocess

    function = subprocess.run(["sed", "-n", "/^migrate_memory_allowlists() {/,/^}/p", str(ROOT / "scripts" / "setup.sh")], capture_output=True, text=True, check=True).stdout
    subprocess.run(["bash", "-c", function + f'\nmigrate_memory_allowlists "{tmp_path / ".env"}"'], check=True, capture_output=True)


def test_an_upgrade_lists_every_missing_setting_commented_and_keeps_the_rest(tmp_path):
    env = _deployment(tmp_path, "KAIRON_DEPLOYMENT_MODE=lan\nBACKEND_MAX_EXTRACTED_BYTES=64424509440\n# BACKEND_LOG_LEVEL=DEBUG\n")
    _upgrade(tmp_path)
    text = env.read_text(encoding="utf-8")
    assert text.startswith("KAIRON_DEPLOYMENT_MODE=lan\nBACKEND_MAX_EXTRACTED_BYTES=64424509440\n# BACKEND_LOG_LEVEL=DEBUG\n")
    active = re.findall(r"^([A-Z][A-Z0-9_]*)=", text, re.M)
    assert active == ["KAIRON_DEPLOYMENT_MODE", "BACKEND_MAX_EXTRACTED_BYTES"]
    commented = _names(env)
    assert _names(ROOT / "config" / "defaults.env") <= commented
    assert text.count("BACKEND_MAX_EXTRACTED_BYTES=") == 1 and text.count("BACKEND_LOG_LEVEL=") == 1
    assert "# BACKEND_MAX_UPLOAD_SIZE=" in text and "# S3_SOURCE_ENABLED=false" in text


def test_a_second_upgrade_adds_nothing(tmp_path):
    env = _deployment(tmp_path, "KAIRON_DEPLOYMENT_MODE=lan\n")
    _upgrade(tmp_path)
    first = env.read_text(encoding="utf-8")
    _upgrade(tmp_path)
    assert env.read_text(encoding="utf-8") == first
