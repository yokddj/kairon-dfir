# AI assistant

The AI assistant is an optional chat panel, scoped to the open case, that an
analyst can ask questions in plain language. It is off until an administrator
configures a model provider.

## What it is, and what it is not

The assistant receives a **briefing** about the open case: its name, status and
notes, its hosts with event counts, its evidence items with ingest status, and
its findings. That briefing is everything it sees.

It does **not** read events, logs, registry hives, or timelines. It has no
search capability and no access to OpenSearch. This is deliberate: a case holds
millions of events, and an assistant that appears to have read them while
actually guessing is worse than no assistant at all.

So the questions it answers well are of the form *"where should I look, and what
should I look for"*: which artifacts would evidence persistence on this host,
which event sources would confirm lateral movement, what is missing from the
evidence set. It answers by naming concrete artifacts, indicators and Kairon
views — the search query to run, the timeline to open — which the analyst then
verifies against the real data.

**Its output is not evidence.** Nothing it says belongs in a report until the
analyst has confirmed it against the artifacts.

## Supported providers

| Provider | Hosting | API key | Notes |
| --- | --- | --- | --- |
| Anthropic (Claude) | Third party | Required | Uses the official SDK. |
| OpenAI | Third party | Required | `https://api.openai.com/v1`. |
| OpenAI-compatible endpoint | Depends on the URL | Optional | vLLM, LM Studio, Groq, OpenRouter, an internal gateway. |
| Ollama | Local | Not needed | Default `http://host.docker.internal:11434/v1`. |

The three non-Anthropic providers share one adapter: anything that speaks
`POST /v1/chat/completions` with SSE streaming works.

### Choosing between local and hosted

On a hosted provider, the question and the case briefing leave the lab. That
briefing contains case and host names, evidence filenames and finding titles —
material that is often confidential and sometimes covered by the engagement's
own confidentiality terms. On engagements where that is not acceptable, run
Ollama or another endpoint on your own hardware; the assistant behaves
identically.

The settings page labels each provider with its hosting mode, and the chat panel
shows a banner whenever the active provider is a hosted API.

## Configuration

Administrators configure it at **AI Assistant** in the sidebar
(`/settings/ai`):

1. Fill in a provider's model and endpoint. *Load models* queries the endpoint
   and populates the model dropdown; *Test connection* verifies the credentials
   before you save.
2. Save the provider.
3. Select it under **Active configuration** and enable the assistant.

The whole configuration lives in one `app_settings` row (`AI_ASSISTANT`), so it
travels with the deployment's backups.

### API key storage

Keys are encrypted with AES-GCM before they are written to the database, using a
key derived from `KAIRON_AI_SECRET_KEY` (falling back to the session secret when
that variable is unset). The plaintext key is decrypted only in the request that
calls the provider. It is never returned to the browser — the settings page sees
only whether a key is stored — and it is never written to the audit log.

Rotating `KAIRON_AI_SECRET_KEY` (or the session secret it falls back to)
invalidates the stored keys; the settings page reports this and you re-enter
them.

## Auditing

Every question is recorded in the audit log as `ai.chat.question` with the case,
the analyst, the provider and model used, and the first 500 characters of the
question. Provider failures are recorded as `ai.chat.error`. Configuration
changes are recorded as `ai.config.updated`, `ai.provider.updated` and
`ai.provider.deleted`.

## Prompt injection

The case briefing is built from data recovered from a potentially compromised
system: a hostname, a filename or a finding title can be attacker-controlled and
can carry text aimed at the model. The system prompt instructs the assistant to
treat everything in the briefing as untrusted data and to report an injection
attempt rather than act on it.

The structural protection matters more than the instruction: the assistant has
no tools, takes no actions, and can only produce text. There is nothing for an
injected instruction to reach.

## API

| Method | Path | Access |
| --- | --- | --- |
| GET | `/api/ai/config` | admin |
| PUT | `/api/ai/config` | admin |
| PUT | `/api/ai/providers/{provider}` | admin |
| DELETE | `/api/ai/providers/{provider}` | admin |
| POST | `/api/ai/providers/{provider}/test` | admin |
| POST | `/api/ai/providers/{provider}/models` | admin |
| GET | `/api/ai/status` | any authenticated user |
| POST | `/api/cases/{case_id}/ai/chat` | users with access to the case |

The chat endpoint streams `text/event-stream`. Each frame is a JSON object with
a `type` of `meta`, `text`, `notice`, `error` or `done`.

## Code map

| Path | Responsibility |
| --- | --- |
| `backend/app/services/ai/crypto.py` | Sealing and opening provider API keys. |
| `backend/app/services/ai/config.py` | The `AI_ASSISTANT` setting: storage, validation, resolution. |
| `backend/app/services/ai/providers.py` | The Anthropic and OpenAI-compatible adapters. |
| `backend/app/services/ai/context.py` | Building the case briefing. |
| `backend/app/services/ai/chat.py` | System prompt, guardrails, audit, streaming. |
| `backend/app/api/routes_ai.py` | HTTP surface. |
| `frontend/src/pages/AiSettingsPage.tsx` | Administrator configuration. |
| `frontend/src/components/ai/AiAssistantPanel.tsx` | The chat panel, mounted in the app shell. |
