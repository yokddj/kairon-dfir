"""Storage and validation for the AI assistant's provider configuration.

The whole configuration lives in a single AppSetting row so it is backed up,
restored and deleted with the rest of the deployment state. API keys inside it
are sealed (see app.services.ai.crypto) and never leave this module in plaintext
except through resolve_provider(), which the chat path calls to build a client.
"""

from __future__ import annotations

from dataclasses import dataclass

from sqlalchemy.orm import Session

from app.core.app_settings import get_setting, set_setting
from app.services.ai.crypto import is_sealed, mask, open_sealed, seal


AI_SETTING_KEY = "AI_ASSISTANT"

PROVIDER_ANTHROPIC = "anthropic"
PROVIDER_OPENAI = "openai"
PROVIDER_OPENAI_COMPATIBLE = "openai_compatible"
PROVIDER_OLLAMA = "ollama"

DEFAULT_MAX_TOKENS = 4096
MIN_MAX_TOKENS = 256
MAX_MAX_TOKENS = 32000

# `local` providers keep every byte of evidence inside the lab. That distinction
# drives the warning the UI shows before a case is exposed to a hosted API, so
# it is part of the provider contract rather than a frontend detail.
PROVIDERS: dict[str, dict] = {
    PROVIDER_ANTHROPIC: {
        "label": "Anthropic (Claude)",
        "hosting": "cloud",
        "requires_api_key": True,
        "default_model": "claude-opus-5",
        "default_base_url": None,
        "base_url_editable": True,
        "help": "API key from console.anthropic.com. Evidence excerpts leave the lab.",
    },
    PROVIDER_OPENAI: {
        "label": "OpenAI",
        "hosting": "cloud",
        "requires_api_key": True,
        "default_model": "",
        "default_base_url": "https://api.openai.com/v1",
        "base_url_editable": True,
        "help": "API key from platform.openai.com. Evidence excerpts leave the lab.",
    },
    PROVIDER_OPENAI_COMPATIBLE: {
        "label": "OpenAI-compatible endpoint",
        "hosting": "custom",
        "requires_api_key": False,
        "default_model": "",
        "default_base_url": "",
        "base_url_editable": True,
        "help": "Any /v1/chat/completions endpoint: vLLM, LM Studio, Groq, OpenRouter, a gateway.",
    },
    PROVIDER_OLLAMA: {
        "label": "Ollama (local)",
        "hosting": "local",
        "requires_api_key": False,
        "default_model": "",
        "default_base_url": "http://host.docker.internal:11434/v1",
        "base_url_editable": True,
        "help": "Runs on your own hardware; nothing about the case leaves the machine.",
    },
}


class AIConfigError(ValueError):
    """Raised for a configuration the operator can fix from the UI."""


@dataclass(frozen=True)
class ResolvedProvider:
    """Everything needed to build a client, including the plaintext key."""

    provider: str
    model: str
    base_url: str | None
    api_key: str | None
    max_tokens: int


def default_config() -> dict:
    return {"enabled": False, "active_provider": None, "max_tokens": DEFAULT_MAX_TOKENS, "providers": {}}


def _coerce(raw: object) -> dict:
    config = default_config()
    if not isinstance(raw, dict):
        return config
    config["enabled"] = bool(raw.get("enabled", False))
    active = raw.get("active_provider")
    config["active_provider"] = active if active in PROVIDERS else None
    try:
        max_tokens = int(raw.get("max_tokens") or DEFAULT_MAX_TOKENS)
    except (TypeError, ValueError):
        max_tokens = DEFAULT_MAX_TOKENS
    config["max_tokens"] = min(max(max_tokens, MIN_MAX_TOKENS), MAX_MAX_TOKENS)
    providers = raw.get("providers")
    if isinstance(providers, dict):
        for key, entry in providers.items():
            if key not in PROVIDERS or not isinstance(entry, dict):
                continue
            config["providers"][key] = {
                "model": str(entry.get("model") or ""),
                "base_url": (str(entry.get("base_url")).strip() or None) if entry.get("base_url") else None,
                "api_key": entry.get("api_key") if is_sealed(entry.get("api_key")) else None,
            }
    return config


def load_config(db: Session) -> dict:
    """Raw configuration, sealed keys included. Never return this to a client."""
    return _coerce(get_setting(db, AI_SETTING_KEY, default_config()))


def save_config(db: Session, config: dict) -> dict:
    stored = _coerce(config)
    set_setting(db, AI_SETTING_KEY, stored)
    return stored


def public_config(config: dict) -> dict:
    """Configuration safe to send to the browser: keys are presence flags only."""
    providers = []
    for key, meta in PROVIDERS.items():
        entry = config.get("providers", {}).get(key, {})
        providers.append(
            {
                "provider": key,
                "label": meta["label"],
                "hosting": meta["hosting"],
                "requires_api_key": meta["requires_api_key"],
                "base_url_editable": meta["base_url_editable"],
                "help": meta["help"],
                "default_model": meta["default_model"],
                "default_base_url": meta["default_base_url"],
                "model": entry.get("model") or "",
                "base_url": entry.get("base_url") or meta["default_base_url"] or "",
                "has_api_key": bool(entry.get("api_key")),
                "configured": _is_configured(key, entry),
            }
        )
    return {
        "enabled": bool(config.get("enabled")),
        "active_provider": config.get("active_provider"),
        "max_tokens": config.get("max_tokens", DEFAULT_MAX_TOKENS),
        "providers": providers,
    }


def _is_configured(provider: str, entry: dict) -> bool:
    meta = PROVIDERS[provider]
    if not entry.get("model"):
        return False
    if meta["requires_api_key"] and not entry.get("api_key"):
        return False
    if not meta["default_base_url"] and meta["base_url_editable"] and provider == PROVIDER_OPENAI_COMPATIBLE:
        return bool(entry.get("base_url"))
    return True


def update_provider(
    db: Session,
    provider: str,
    *,
    model: str | None = None,
    base_url: str | None = None,
    api_key: str | None = None,
) -> dict:
    """Update one provider.

    `api_key` follows three-state semantics because the browser never receives
    the stored key and so cannot echo it back: None leaves it untouched, an
    empty string clears it, anything else replaces it.
    """
    if provider not in PROVIDERS:
        raise AIConfigError(f"Unknown provider: {provider}")
    config = load_config(db)
    entry = dict(config["providers"].get(provider, {"model": "", "base_url": None, "api_key": None}))
    if model is not None:
        entry["model"] = model.strip()
    if base_url is not None:
        cleaned = base_url.strip().rstrip("/")
        entry["base_url"] = cleaned or None
    if api_key is not None:
        entry["api_key"] = seal(api_key.strip()) if api_key.strip() else None
    config["providers"][provider] = entry
    return save_config(db, config)


def delete_provider(db: Session, provider: str) -> dict:
    if provider not in PROVIDERS:
        raise AIConfigError(f"Unknown provider: {provider}")
    config = load_config(db)
    config["providers"].pop(provider, None)
    if config["active_provider"] == provider:
        config["active_provider"] = None
        config["enabled"] = False
    return save_config(db, config)


def update_general(
    db: Session,
    *,
    enabled: bool | None = None,
    active_provider: str | None = None,
    max_tokens: int | None = None,
) -> dict:
    config = load_config(db)
    if active_provider is not None:
        if active_provider not in PROVIDERS:
            raise AIConfigError(f"Unknown provider: {active_provider}")
        config["active_provider"] = active_provider
    if max_tokens is not None:
        config["max_tokens"] = max_tokens
    if enabled is not None:
        if enabled and not config.get("active_provider"):
            raise AIConfigError("Select a provider before enabling the assistant")
        if enabled:
            active = config["active_provider"]
            if not _is_configured(active, config["providers"].get(active, {})):
                raise AIConfigError(f"{PROVIDERS[active]['label']} is not fully configured yet")
        config["enabled"] = enabled
    return save_config(db, config)


def resolve_provider(db: Session, provider: str | None = None) -> ResolvedProvider:
    """Build the credentials for a call. Raises when nothing usable is stored."""
    config = load_config(db)
    target = provider or config.get("active_provider")
    if not target:
        raise AIConfigError("No AI provider is selected")
    if target not in PROVIDERS:
        raise AIConfigError(f"Unknown provider: {target}")
    meta = PROVIDERS[target]
    entry = config["providers"].get(target, {})
    model = entry.get("model") or meta["default_model"]
    if not model:
        raise AIConfigError(f"No model configured for {meta['label']}")
    base_url = entry.get("base_url") or meta["default_base_url"]
    api_key = open_sealed(entry.get("api_key"))
    if meta["requires_api_key"] and not api_key:
        raise AIConfigError(f"No API key stored for {meta['label']}")
    return ResolvedProvider(
        provider=target,
        model=model,
        base_url=base_url,
        api_key=api_key,
        max_tokens=int(config.get("max_tokens", DEFAULT_MAX_TOKENS)),
    )


def masked_api_key(db: Session, provider: str) -> str | None:
    config = load_config(db)
    return mask(open_sealed(config["providers"].get(provider, {}).get("api_key")))
