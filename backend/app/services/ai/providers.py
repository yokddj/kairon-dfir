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
    """One piece of a streamed answer.

    `type` is text | notice | error | tool_use. A tool_use event carries
    {id, name, input} in `data` and means the model paused to look something up;
    the caller runs the tool and feeds the result back.
    """

    type: str
    text: str = ""
    data: dict = field(default_factory=dict)


class ChatProvider(ABC):
    def __init__(self, credentials: ResolvedProvider) -> None:
        self.credentials = credentials

    @abstractmethod
    def stream_chat(
        self, *, system: str, messages: list[dict], tools: list[dict] | None = None
    ) -> Iterator[StreamEvent]:
        """Yield the answer as it arrives. `messages` is [{role, content}].

        When `tools` is given the model may pause and emit tool_use events instead
        of finishing; the caller runs those and calls again with the results.
        """

    @abstractmethod
    def list_models(self) -> list[str]:
        """Model ids the configured endpoint reports."""

    def test_connection(self) -> dict:
        """Cheap reachability + credential check."""
        models = self.list_models()
        return {"ok": True, "models": models[:50], "model_count": len(models)}

    @abstractmethod
    def tool_turn_messages(self, calls: list[dict], results: list[dict]) -> list[dict]:
        """Messages recording that the model called tools and what came back.

        Anthropic and OpenAI disagree on the shape of this exchange, so each
        adapter renders its own and the orchestration loop stays provider-neutral.
        """


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

    def _request_kwargs(self, *, system: str, messages: list[dict], tools: list[dict] | None = None) -> dict:
        kwargs: dict = {
            "model": self.credentials.model,
            "max_tokens": self.credentials.max_tokens,
            "system": system,
            "messages": messages,
        }
        if tools:
            kwargs["tools"] = tools
        if self.credentials.model in ADAPTIVE_THINKING_MODELS:
            kwargs["thinking"] = {"type": "adaptive"}
        return kwargs

    def stream_chat(
        self, *, system: str, messages: list[dict], tools: list[dict] | None = None
    ) -> Iterator[StreamEvent]:
        client = self._client()
        kwargs = self._request_kwargs(system=system, messages=messages, tools=tools)
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

        if getattr(final, "stop_reason", None) == "tool_use":
            for block in getattr(final, "content", None) or []:
                if getattr(block, "type", None) != "tool_use":
                    continue
                yield StreamEvent(
                    type="tool_use",
                    data={
                        "id": getattr(block, "id", ""),
                        "name": getattr(block, "name", ""),
                        "input": getattr(block, "input", None) or {},
                    },
                )
            return

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

    def tool_turn_messages(self, calls: list[dict], results: list[dict]) -> list[dict]:
        return [
            {
                "role": "assistant",
                "content": [
                    {"type": "tool_use", "id": c["id"], "name": c["name"], "input": c.get("input") or {}}
                    for c in calls
                ],
            },
            {
                "role": "user",
                "content": [
                    {"type": "tool_result", "tool_use_id": c["id"], "content": r}
                    for c, r in zip(calls, results)
                ],
            },
        ]


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

    # Newer OpenAI models reject "max_tokens" and require "max_completion_tokens",
    # while Ollama, vLLM and LM Studio only understand the original spelling. The
    # split does not follow anything we can detect from the model id, and hard-coding
    # a list of names would rot within weeks, so we send the classic spelling and let
    # a rejection tell us to switch. The 400 arrives before any token is streamed,
    # so retrying cannot duplicate output.
    TOKEN_LIMIT_FIELDS = ("max_tokens", "max_completion_tokens")

    def stream_chat(
        self, *, system: str, messages: list[dict], tools: list[dict] | None = None
    ) -> Iterator[StreamEvent]:
        body: dict = {
            "model": self.credentials.model,
            "stream": True,
            "messages": [{"role": "system", "content": system}, *messages],
        }
        if tools:
            # OpenAI nests the schema one level deeper than Anthropic does.
            body["tools"] = [
                {
                    "type": "function",
                    "function": {
                        "name": spec["name"],
                        "description": spec.get("description", ""),
                        "parameters": spec.get("input_schema") or {"type": "object", "properties": {}},
                    },
                }
                for spec in tools
            ]
        rejected: ProviderError | None = None
        for field in self.TOKEN_LIMIT_FIELDS:
            try:
                yield from self._stream_once({**body, field: self.credentials.max_tokens})
                return
            except _WrongTokenField as exc:
                rejected = ProviderError(str(exc))
        raise rejected or ProviderError("The endpoint rejected the token limit parameter")

    def _stream_once(self, payload: dict) -> Iterator[StreamEvent]:
        httpx = self._http()
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
                        message = _readable_http_error(response.status_code, response.text)
                        if _rejects_token_field(response.status_code, response.text, payload):
                            raise _WrongTokenField(message)
                        raise ProviderError(message)
                    # Tool call arguments arrive as JSON fragments spread over many
                    # chunks, keyed by index, so they are assembled here and emitted
                    # once the stream ends rather than forwarded piecemeal.
                    pending: dict[int, dict] = {}
                    for line in response.iter_lines():
                        for event in _parse_sse_line(line, pending):
                            yield event
                    yield from _finish_tool_calls(pending)
        except (ProviderError, _WrongTokenField):
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

    def tool_turn_messages(self, calls: list[dict], results: list[dict]) -> list[dict]:
        messages: list[dict] = [
            {
                "role": "assistant",
                "content": None,
                "tool_calls": [
                    {
                        "id": c["id"],
                        "type": "function",
                        "function": {
                            "name": c["name"],
                            "arguments": json.dumps(c.get("input") or {}),
                        },
                    }
                    for c in calls
                ],
            }
        ]
        messages.extend(
            {"role": "tool", "tool_call_id": c["id"], "content": r}
            for c, r in zip(calls, results)
        )
        return messages


class _StreamNotStarted(RuntimeError):
    """Internal: the request was rejected before any output, so a retry is safe."""


class _WrongTokenField(RuntimeError):
    """Internal: the endpoint wants the other spelling of the token limit field."""


def _rejects_token_field(status: int, body: str, payload: dict) -> bool:
    """True when the endpoint refused the token-limit parameter we just sent.

    OpenAI answers an unsupported spelling with a 400 that names the one it wants,
    so we only retry when the response points at a field we did not send.
    """
    if status != 400:
        return False
    text = (body or "").lower()
    return any(
        field not in payload and field in text
        for field in OpenAICompatibleProvider.TOKEN_LIMIT_FIELDS
    )


def _parse_sse_line(line: str, pending: dict[int, dict] | None = None) -> list[StreamEvent]:
    """Turn one SSE line into events, accumulating tool calls into `pending`."""
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
        delta = choice.get("delta") or {}
        text = delta.get("content") or ""
        if text:
            events.append(StreamEvent(type="text", text=str(text)))
        if pending is not None:
            _accumulate_tool_calls(delta.get("tool_calls"), pending)
        if choice.get("finish_reason") == "length":
            events.append(
                StreamEvent(type="notice", text="Answer truncated at the configured token limit.")
            )
    return events


def _accumulate_tool_calls(deltas, pending: dict[int, dict]) -> None:
    """Merge one chunk's tool_calls fragments into the calls being assembled."""
    for delta in deltas or []:
        if not isinstance(delta, dict):
            continue
        index = int(delta.get("index") or 0)
        slot = pending.setdefault(index, {"id": "", "name": "", "arguments": ""})
        if delta.get("id"):
            slot["id"] = str(delta["id"])
        function = delta.get("function") or {}
        if function.get("name"):
            slot["name"] = str(function["name"])
        if function.get("arguments"):
            slot["arguments"] += str(function["arguments"])


def _finish_tool_calls(pending: dict[int, dict]) -> list[StreamEvent]:
    """Emit the assembled tool calls once the stream is done."""
    events: list[StreamEvent] = []
    for index in sorted(pending):
        slot = pending[index]
        if not slot.get("name"):
            continue
        raw = slot.get("arguments") or "{}"
        try:
            arguments = json.loads(raw) if raw.strip() else {}
        except ValueError:
            # A model that emits malformed JSON should hear about it, not crash us.
            arguments = {"__parse_error__": raw[:200]}
        events.append(
            StreamEvent(
                type="tool_use",
                data={
                    "id": slot.get("id") or f"call_{index}",
                    "name": slot["name"],
                    "input": arguments if isinstance(arguments, dict) else {},
                },
            )
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
