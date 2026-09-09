from pydantic import BaseModel, Field


class AIProviderUpdate(BaseModel):
    model: str | None = None
    base_url: str | None = None
    # Three-state: omitted leaves the stored key alone, "" clears it, a value
    # replaces it. The browser never receives the stored key, so it cannot
    # round-trip one.
    api_key: str | None = None


class AIGeneralUpdate(BaseModel):
    enabled: bool | None = None
    active_provider: str | None = None
    max_tokens: int | None = Field(default=None, ge=256, le=32000)


class AIProviderProbe(BaseModel):
    """Unsaved credentials, so an operator can test before storing them."""

    model: str | None = None
    base_url: str | None = None
    api_key: str | None = None


class AIChatMessage(BaseModel):
    role: str
    content: str


class AIChatRequest(BaseModel):
    messages: list[AIChatMessage]
    provider: str | None = None
    # Continues an existing thread; omitted on the first question of a new one.
    conversation_id: str | None = None
    # The host the analyst is looking at, so "this host" resolves without asking.
    active_host: str | None = None


class AINaturalLanguageSearchRequest(BaseModel):
    question: str
    provider: str | None = None
