"""Chat providers behind one streaming interface.

Two adapters cover the supported backends: the Anthropic SDK for Claude, and a
single OpenAI-compatible HTTP adapter for OpenAI, Ollama and any other endpoint
that speaks /v1/chat/completions. Both yield the same StreamEvent sequence so
the route and the UI never branch on provider.
"""

from __future__ import annotations

import json
import logging
from abc import ABC, abstractmethod
from collections.abc import Iterator
from dataclasses import dataclass, field

from app.services.ai.config import (
    PROVIDER_ANTHROPIC,
    PROVIDER_OLLAMA,
    PROVIDER_OPENAI,
    PROVIDER_OPENAI_COMPATIBLE,
    ResolvedProvider,
)


logger = logging.getLogger(__name__)

# Claude models that take adaptive thinking. Sending it to an older model is a
# 400, so the list is explicit rather than a prefix guess.
ADAPTIVE_THINKING_MODELS = (
    "claude-fable-5",
    "claude-mythos-5",
    "claude-opus-5",
    "claude-opus-4-8",
    "claude-opus-4-7",
    "claude-opus-4-6",
    "claude-sonnet-5",
    "claude-sonnet-4-6",
)
# Models where a safety decline is rescued server-side by re-running the request
# on a fallback model inside the same call.
SERVER_FALLBACK_MODELS = ("claude-opus-5", "claude-fable-5", "claude-mythos-5")
SERVER_FALLBACK_BETA = "server-side-fallback-2026-07-01"

CONNECT_TIMEOUT_SECONDS = 10.0
READ_TIMEOUT_SECONDS = 180.0


class ProviderError(RuntimeError):
    """A provider call failed in a way worth showing the analyst verbatim."""


@dataclass(frozen=True)
class StreamEvent:
    """One piece of a streamed answer. `type` is text | notice | error."""

    type: str
    text: str = ""
    data: dict = field(default_factory=dict)


class ChatProvider(ABC):
    def __init__(self, credentials: ResolvedProvider) -> None:
        self.credentials = credentials

    @abstractmethod
    def stream_chat(self, *, system: str, messages: list[dict]) -> Iterator[StreamEvent]:
        """Yield the answer as it arrives. `messages` is [{role, content}]."""

    @abstractmethod
    def list_models(self) -> list[str]:
        """Model ids the configured endpoint reports."""

    def test_connection(self) -> dict:
        """Cheap reachability + credential check."""
        models = self.list_models()
        return {"ok": True, "models": models[:50], "model_count": len(models)}


class AnthropicProvider(ChatProvider):
    def _client(self):
        try:
            import anthropic
        except ImportError as exc:  # pragma: no cover - dependency guard
            raise ProviderError(
                "The 'anthropic' package is not installed in the backend image"
            ) from exc
        kwargs: dict = {"api_key": self.credentials.api_key}
        if self.credentials.base_url:
            kwargs["base_url"] = self.credentials.base_url
        return anthropic.Anthropic(**kwargs)

    def _request_kwargs(self, *, system: str, messages: list[dict]) -> dict:
        kwargs: dict = {
            "model": self.credentials.model,
            "max_tokens": self.credentials.max_tokens,
            "system": system,
            "messages": messages,
        }
        if self.credentials.model in ADAPTIVE_THINKING_MODELS:
            kwargs["thinking"] = {"type": "adaptive"}
        return kwargs

    def stream_chat(self, *, system: str, messages: list[dict]) -> Iterator[StreamEvent]:
        client = self._client()
        kwargs = self._request_kwargs(system=system, messages=messages)
        use_fallbacks = self.credentials.model in SERVER_FALLBACK_MODELS

        if use_fallbacks:
            try:
                yield from self._stream(
                    client.beta.messages,
                    dict(kwargs, betas=[SERVER_FALLBACK_BETA], fallbacks="default"),
                )
                return
            except _StreamNotStarted:
                # The SDK or endpoint predates server-side fallbacks. Nothing was
                # emitted yet, so retrying on the plain endpoint is safe.
                logger.info("Server-side fallbacks unavailable; retrying without them")

        yield from self._stream(client.messages, kwargs)

    def _stream(self, messages_api, kwargs: dict) -> Iterator[StreamEvent]:
        started = False
        try:
            stream_ctx = messages_api.stream(**kwargs)
        except TypeError as exc:
            raise _StreamNotStarted(str(exc)) from exc
        try:
            with stream_ctx as stream:
                for text in stream.text_stream:
                    started = True
                    yield StreamEvent(type="text", text=text)
                final = stream.get_final_message()
        except _StreamNotStarted:
            raise
        except Exception as exc:  # noqa: BLE001 - SDK raises a family of errors
            if not started and _looks_like_unsupported_parameter(exc):
                raise _StreamNotStarted(str(exc)) from exc
            raise ProviderError(_readable_anthropic_error(exc)) from exc

        if getattr(final, "stop_reason", None) == "refusal":
            details = getattr(final, "stop_details", None)
            category = getattr(details, "category", None) or "policy"
            yield StreamEvent(
                type="error",
                text=(
                    f"The model declined to answer ({category}). Rephrase the question, "
                    "or use a locally hosted provider for this case."
                ),
            )
        elif getattr(final, "stop_reason", None) == "max_tokens":
            yield StreamEvent(
                type="notice",
                text="Answer truncated at the configured token limit.",
            )

    def list_models(self) -> list[str]:
        client = self._client()
        try:
            return [model.id for model in client.models.list()]
        except Exception as exc:  # noqa: BLE001
            raise ProviderError(_readable_anthropic_error(exc)) from exc


class OpenAICompatibleProvider(ChatProvider):
    """OpenAI, Ollama, and anything else exposing /v1/chat/completions."""

    def _http(self):
        try:
            import httpx
        except ImportError as exc:  # pragma: no cover - dependency guard
            raise ProviderError("The 'httpx' package is not installed in the backend image") from exc
        return httpx

    def _base_url(self) -> str:
        base = (self.credentials.base_url or "").strip().rstrip("/")
        if not base:
            raise ProviderError("No endpoint URL configured for this provider")
        return base

    def _headers(self) -> dict[str, str]:
        headers = {"Content-Type": "application/json"}
        if self.credentials.api_key:
            headers["Authorization"] = f"Bearer {self.credentials.api_key}"
        return headers

    def stream_chat(self, *, system: str, messages: list[dict]) -> Iterator[StreamEvent]:
        httpx = self._http()
        payload = {
            "model": self.credentials.model,
            "max_tokens": self.credentials.max_tokens,
            "stream": True,
            "messages": [{"role": "system", "content": system}, *messages],
        }
        timeout = httpx.Timeout(READ_TIMEOUT_SECONDS, connect=CONNECT_TIMEOUT_SECONDS)
        try:
            with httpx.Client(timeout=timeout) as client:
                with client.stream(
                    "POST",
                    f"{self._base_url()}/chat/completions",
                    headers=self._headers(),
                    json=payload,
                ) as response:
                    if response.status_code >= 400:
                        response.read()
                        raise ProviderError(_readable_http_error(response.status_code, response.text))
                    for line in response.iter_lines():
                        for event in _parse_sse_line(line):
                            yield event
        except ProviderError:
            raise
        except Exception as exc:  # noqa: BLE001
            raise ProviderError(f"Could not reach the provider: {exc}") from exc

    def list_models(self) -> list[str]:
        httpx = self._http()
        timeout = httpx.Timeout(30.0, connect=CONNECT_TIMEOUT_SECONDS)
        try:
            response = httpx.get(f"{self._base_url()}/models", headers=self._headers(), timeout=timeout)
        except Exception as exc:  # noqa: BLE001
            raise ProviderError(f"Could not reach the provider: {exc}") from exc
        if response.status_code >= 400:
            raise ProviderError(_readable_http_error(response.status_code, response.text))
        try:
            data = response.json().get("data") or []
        except ValueError as exc:
            raise ProviderError("The endpoint did not return a model list") from exc
        return sorted(str(item.get("id")) for item in data if isinstance(item, dict) and item.get("id"))


class _StreamNotStarted(RuntimeError):
    """Internal: the request was rejected before any output, so a retry is safe."""


def _parse_sse_line(line: str) -> list[StreamEvent]:
    if not line or not line.startswith("data:"):
        return []
    payload = line[len("data:"):].strip()
    if not payload or payload == "[DONE]":
        return []
    try:
        chunk = json.loads(payload)
    except ValueError:
        return []
    if isinstance(chunk.get("error"), dict):
        message = chunk["error"].get("message") or "The provider reported an error"
        return [StreamEvent(type="error", text=str(message))]
    events: list[StreamEvent] = []
    for choice in chunk.get("choices") or []:
        text = ((choice.get("delta") or {}).get("content")) or ""
        if text:
            events.append(StreamEvent(type="text", text=str(text)))
        if choice.get("finish_reason") == "length":
            events.append(
                StreamEvent(type="notice", text="Answer truncated at the configured token limit.")
            )
    return events


def _looks_like_unsupported_parameter(exc: Exception) -> bool:
    text = str(exc).lower()
    return "fallback" in text or "unexpected keyword" in text or "beta" in text


def _readable_anthropic_error(exc: Exception) -> str:
    status = getattr(exc, "status_code", None)
    if status == 401:
        return "The Anthropic API key was rejected"
    if status == 404:
        return "The configured model does not exist for this API key"
    if status == 429:
        return "Rate limited by the Anthropic API; try again shortly"
    return f"Anthropic API error: {exc}"


def _readable_http_error(status: int, body: str) -> str:
    detail = (body or "").strip()
    try:
        parsed = json.loads(detail)
        detail = str((parsed.get("error") or {}).get("message") or parsed.get("error") or detail)
    except ValueError:
        pass
    detail = detail[:300]
    if status == 401:
        return f"The API key was rejected (401). {detail}".strip()
    if status == 404:
        return f"Endpoint or model not found (404). {detail}".strip()
    if status == 429:
        return f"Rate limited by the provider (429). {detail}".strip()
    return f"Provider returned HTTP {status}. {detail}".strip()


def build_provider(credentials: ResolvedProvider) -> ChatProvider:
    if credentials.provider == PROVIDER_ANTHROPIC:
        return AnthropicProvider(credentials)
    if credentials.provider in (PROVIDER_OPENAI, PROVIDER_OPENAI_COMPATIBLE, PROVIDER_OLLAMA):
        return OpenAICompatibleProvider(credentials)
    raise ProviderError(f"Unsupported provider: {credentials.provider}")
