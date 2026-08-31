"""AI assistant: provider configuration and the case chat stream."""

from __future__ import annotations

import json
from collections.abc import Iterator

from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.responses import StreamingResponse
from sqlalchemy.orm import Session

from app.core.config import get_settings
from app.core.database import get_db
from app.models.case import Case
from app.models.user import User
from app.schemas.ai import AIChatRequest, AIGeneralUpdate, AIProviderProbe, AIProviderUpdate
from app.services.ai.chat import ChatValidationError, stream_answer
from app.services.ai.config import (
    PROVIDERS,
    AIConfigError,
    ResolvedProvider,
    load_config,
    public_config,
    resolve_provider,
    update_general,
    update_provider,
)
from app.services.ai.config import delete_provider as delete_provider_config
from app.services.ai.crypto import CredentialCryptoError, open_sealed
from app.services.ai.providers import ProviderError, build_provider
from app.services.audit import log_audit
from app.services.auth_dependencies import get_current_user, get_effective_case_role, get_optional_user


router = APIRouter(tags=["ai"])


def require_ai_admin(request: Request, db: Session = Depends(get_db)) -> User | None:
    """Admin-only, and a no-op when authentication is disabled (tests, dev)."""
    if not get_settings().auth_enabled:
        return None
    user = get_current_user(request, db)
    if not user.is_admin:
        raise HTTPException(status_code=403, detail="Admin required")
    return user


def _known_provider(provider: str) -> None:
    if provider not in PROVIDERS:
        raise HTTPException(status_code=404, detail=f"Unknown provider: {provider}")


@router.get("/api/ai/config")
def get_ai_config(db: Session = Depends(get_db), _admin: User | None = Depends(require_ai_admin)) -> dict:
    return public_config(load_config(db))


@router.put("/api/ai/config")
def put_ai_config(
    payload: AIGeneralUpdate,
    db: Session = Depends(get_db),
    admin: User | None = Depends(require_ai_admin),
) -> dict:
    try:
        config = update_general(
            db,
            enabled=payload.enabled,
            active_provider=payload.active_provider,
            max_tokens=payload.max_tokens,
        )
    except AIConfigError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    log_audit(
        "ai.config.updated",
        actor_user_id=getattr(admin, "id", None),
        resource_type="ai_config",
        metadata={"enabled": config["enabled"], "active_provider": config["active_provider"]},
    )
    return public_config(config)


@router.put("/api/ai/providers/{provider}")
def put_ai_provider(
    provider: str,
    payload: AIProviderUpdate,
    db: Session = Depends(get_db),
    admin: User | None = Depends(require_ai_admin),
) -> dict:
    _known_provider(provider)
    try:
        config = update_provider(
            db,
            provider,
            model=payload.model,
            base_url=payload.base_url,
            api_key=payload.api_key,
        )
    except (AIConfigError, CredentialCryptoError) as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    log_audit(
        "ai.provider.updated",
        actor_user_id=getattr(admin, "id", None),
        resource_type="ai_provider",
        resource_id=provider,
        # The key itself is never logged; only whether one is now stored.
        metadata={"api_key_changed": payload.api_key is not None},
    )
    return public_config(config)


@router.delete("/api/ai/providers/{provider}")
def delete_ai_provider(
    provider: str,
    db: Session = Depends(get_db),
    admin: User | None = Depends(require_ai_admin),
) -> dict:
    _known_provider(provider)
    config = delete_provider_config(db, provider)
    log_audit(
        "ai.provider.deleted",
        actor_user_id=getattr(admin, "id", None),
        resource_type="ai_provider",
        resource_id=provider,
    )
    return public_config(config)


def _probe_credentials(db: Session, provider: str, probe: AIProviderProbe | None) -> ResolvedProvider:
    """Stored configuration, overlaid with any unsaved values being tested."""
    stored = load_config(db)["providers"].get(provider, {})
    meta = PROVIDERS[provider]
    model = (probe.model if probe and probe.model is not None else stored.get("model")) or meta["default_model"]
    base_url = (
        probe.base_url if probe and probe.base_url is not None else stored.get("base_url")
    ) or meta["default_base_url"]
    if probe and probe.api_key:
        api_key = probe.api_key
    else:
        api_key = open_sealed(stored.get("api_key"))
    if meta["requires_api_key"] and not api_key:
        raise HTTPException(status_code=400, detail=f"No API key stored for {meta['label']}")
    return ResolvedProvider(
        provider=provider,
        model=model or "",
        base_url=(base_url or "").rstrip("/") or None,
        api_key=api_key,
        max_tokens=load_config(db).get("max_tokens", 4096),
    )


@router.post("/api/ai/providers/{provider}/test")
def test_ai_provider(
    provider: str,
    payload: AIProviderProbe | None = None,
    db: Session = Depends(get_db),
    _admin: User | None = Depends(require_ai_admin),
) -> dict:
    _known_provider(provider)
    try:
        credentials = _probe_credentials(db, provider, payload)
        return build_provider(credentials).test_connection()
    except HTTPException:
        raise
    except (ProviderError, AIConfigError, CredentialCryptoError) as exc:
        return {"ok": False, "error": str(exc)}


@router.post("/api/ai/providers/{provider}/models")
def list_ai_provider_models(
    provider: str,
    payload: AIProviderProbe | None = None,
    db: Session = Depends(get_db),
    _admin: User | None = Depends(require_ai_admin),
) -> dict:
    _known_provider(provider)
    try:
        credentials = _probe_credentials(db, provider, payload)
        return {"ok": True, "models": build_provider(credentials).list_models()}
    except HTTPException:
        raise
    except (ProviderError, AIConfigError, CredentialCryptoError) as exc:
        return {"ok": False, "models": [], "error": str(exc)}


@router.get("/api/ai/status")
def get_ai_status(db: Session = Depends(get_db)) -> dict:
    """What the case UI needs to decide whether to offer the assistant."""
    config = load_config(db)
    active = config.get("active_provider")
    if not config.get("enabled") or not active:
        return {"enabled": False, "provider": None, "model": None, "hosting": None}
    entry = config["providers"].get(active, {})
    return {
        "enabled": True,
        "provider": active,
        "label": PROVIDERS[active]["label"],
        "model": entry.get("model") or PROVIDERS[active]["default_model"],
        "hosting": PROVIDERS[active]["hosting"],
    }


def _sse(payload: dict) -> str:
    return f"data: {json.dumps(payload, ensure_ascii=False)}\n\n"


@router.post("/api/cases/{case_id}/ai/chat")
def case_ai_chat(
    case_id: str,
    payload: AIChatRequest,
    db: Session = Depends(get_db),
    user: User | None = Depends(get_optional_user),
) -> StreamingResponse:
    if db.get(Case, case_id) is None:
        raise HTTPException(status_code=404, detail="Case not found")
    if user is not None and get_effective_case_role(user, case_id, db) is None:
        raise HTTPException(status_code=403, detail="Access denied to this case")

    config = load_config(db)
    if not config.get("enabled"):
        raise HTTPException(status_code=409, detail="The AI assistant is not enabled for this deployment")
    try:
        resolve_provider(db, payload.provider)
    except AIConfigError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc

    messages = [message.model_dump() for message in payload.messages]
    actor_user_id = getattr(user, "id", None)

    def event_stream() -> Iterator[str]:
        try:
            for event in stream_answer(
                db,
                case_id=case_id,
                messages=messages,
                actor_user_id=actor_user_id,
                provider=payload.provider,
            ):
                yield _sse({"type": event.type, "text": event.text, **event.data})
        except (ChatValidationError, AIConfigError, CredentialCryptoError) as exc:
            yield _sse({"type": "error", "text": str(exc)})
        yield _sse({"type": "done"})

    return StreamingResponse(
        event_stream(),
        media_type="text/event-stream",
        headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"},
    )
