from __future__ import annotations

from typing import Any

from redis import Redis

from app.core import config as config_module
from app.services.memory.execution import PROFILE_PLUGINS
from app.services.memory.worker_capability import list_memory_worker_capabilities


PLUGIN_AVAILABLE = "available"
PLUGIN_UNAVAILABLE = "unavailable"
PLUGIN_DISABLED = "disabled"
PLUGIN_UNKNOWN = "unknown"


def get_settings():
    return config_module.get_settings()


def _current_worker_capability() -> dict[str, Any] | None:
    settings = get_settings()
    try:
        redis_conn = Redis.from_url(settings.redis_url)
        redis_conn.ping()
        capabilities = list_memory_worker_capabilities(redis_conn)
    except Exception:  # noqa: BLE001
        return None
    healthy = [item for item in capabilities if item.get("healthy") and item.get("queue") == settings.memory_queue_name]
    return healthy[0] if healthy else None


def _plugin_worker_state(plugin: str, capability: dict[str, Any] | None) -> tuple[str, str]:
    if not capability:
        return PLUGIN_UNKNOWN, "Plugin capability is unknown; the memory worker will validate it at execution time."
    plugins = capability.get("plugins")
    if not isinstance(plugins, dict):
        return PLUGIN_UNKNOWN, "Plugin capability is unknown; the memory worker will validate it at execution time."
    entry = plugins.get(plugin)
    if not isinstance(entry, dict):
        return PLUGIN_UNKNOWN, "Plugin capability is unknown; the memory worker will validate it at execution time."
    state = str(entry.get("state") or "").strip().lower()
    if state == PLUGIN_AVAILABLE:
        return PLUGIN_AVAILABLE, str(entry.get("reason") or "Available in the memory worker runtime.")
    if state in {PLUGIN_UNAVAILABLE, "unsupported", "unsupported_by_installed_volatility"}:
        return PLUGIN_UNAVAILABLE, str(entry.get("reason") or f"{plugin} is not exposed by the installed Volatility runtime.")
    return PLUGIN_UNKNOWN, str(entry.get("reason") or "Plugin capability is unknown; the memory worker will validate it at execution time.")


def plan_profile_capability(profile: str, *, worker_capability: dict[str, Any] | None = None) -> dict[str, Any]:
    settings = get_settings()
    plugin_names = list(PROFILE_PLUGINS.get(profile, []))
    allowed = set(settings.allowed_memory_plugins)
    capability = _current_worker_capability() if worker_capability is None else worker_capability
    plugins: list[dict[str, str]] = []
    for plugin in plugin_names:
        if plugin not in allowed:
            plugins.append(
                {
                    "plugin": plugin,
                    "state": PLUGIN_DISABLED,
                    "reason": f"{plugin} is disabled by memory plugin configuration.",
                }
            )
            continue
        state, reason = _plugin_worker_state(plugin, capability)
        plugins.append({"plugin": plugin, "state": state, "reason": reason})
    enabled_plugins = [item["plugin"] for item in plugins if item["state"] != PLUGIN_DISABLED]
    known_unavailable = [item for item in plugins if item["state"] == PLUGIN_UNAVAILABLE]
    unknown_plugins = [item for item in plugins if item["state"] == PLUGIN_UNKNOWN]
    available_plugins = [item for item in plugins if item["state"] == PLUGIN_AVAILABLE]
    runnable_plugins = [item for item in plugins if item["state"] in {PLUGIN_AVAILABLE, PLUGIN_UNKNOWN}]
    return {
        "profile": profile,
        "plugins": plugins,
        "plugin_names": plugin_names,
        "enabled_plugins": enabled_plugins,
        "disabled_plugins": [item for item in plugins if item["state"] == PLUGIN_DISABLED],
        "known_unavailable_plugins": known_unavailable,
        "unknown_plugins": unknown_plugins,
        "available_plugins": available_plugins,
        "runnable_plugins": runnable_plugins,
        "has_enabled_plugins": bool(enabled_plugins),
        "available_plugin_count": len(available_plugins) + len(unknown_plugins),
    }


def profile_has_enabled_plugins(profile: str) -> tuple[bool, str | None]:
    plan = plan_profile_capability(profile)
    if plan["plugin_names"] and not plan["has_enabled_plugins"]:
        return False, "No plugins for this profile are enabled by memory plugin configuration."
    return True, None
