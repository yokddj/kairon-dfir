# AI assistant

The AI assistant is an optional chat panel, scoped to the open case, that an
analyst can ask questions in plain language. It is off until an administrator
configures a model provider.

## What it is, and what it is not

The assistant starts each conversation with a **briefing** about the open case:
its name, status and notes, its hosts with event counts, its evidence items with
ingest status, and its findings. For anything deeper it calls **read-only lookup
tools** against the same data the analyst can already open in Kairon.

| Tool | What it reads |
| --- | --- |
| `describe_case` | Which artifact types, hosts and fields the case actually has. |
| `list_hosts` | Hosts and their event counts. |
| `search_events` | Events matching a Search query (summaries, with pivot links). |
| `get_event_detail` | One event in full. |
| `get_timeline` | A slice of the case timeline. |
| `search_command_history` | Shell and PowerShell command history. |
| `get_process_tree` | The process tree around a process. |
| `list_persistence`, `list_downloads`, `list_email_artifacts`, `search_memory_artifacts` | Artifact-specific views. |
| `list_findings`, `list_detections` | Findings and detection hits. |

The tools cannot write: the assistant cannot create findings, edit notes, change
the timeline or start any job. Results are capped (20 rows by default, 50 at
most, 600 characters per field) and a single question runs at most 8 rounds of
tool calls, so the assistant works from samples and summaries, not from the whole
case. It cites the events it relied on so the analyst can open them.

Two further features reuse the same provider configuration:

- **Natural-language search** turns a plain-language question into a Search query
  that lands, editable, in the normal Search box. It is a single completion with
  no tool loop and nothing is saved as a conversation.
- **Conversations** are stored per case, so a thread can be resumed or deleted.

**Its output is not evidence.** A model can misread or overstate what a lookup
returned. Nothing it says belongs in a report until the analyst has confirmed it
against the artifacts.

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

On a hosted provider, the question, the case briefing **and every tool result the
assistant requests** leave the lab. That includes case and host names, evidence
filenames, finding titles and the event, command-line and process data the tools
return — material that is often confidential and sometimes covered by the
engagement's own confidentiality terms. On engagements where that is not acceptable, run
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
question. Each tool call is recorded as `ai.chat.tool` with the tool name and its
arguments, so a reviewer can see exactly which data the assistant looked at.
Provider failures are recorded as `ai.chat.error`. Configuration changes are
recorded as `ai.config.updated`, `ai.provider.updated` and `ai.provider.deleted`,
and deleting a conversation as `ai.conversation.deleted`.

## Prompt injection

Everything the assistant reads comes from a potentially compromised system: a
hostname, a filename, a command line or a finding title can be attacker-controlled
and can carry text aimed at the model. The system prompt instructs the assistant
to treat the briefing and every tool result as untrusted data and to report an
injection attempt rather than act on it.

The structural protection matters more than the instruction: every tool is
read-only and scoped to the open case, so an injected instruction cannot change
data, reach another case or start a job. What it can still do is bend the answer
the analyst reads, which is one more reason the output is a lead to verify, not
evidence.

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
| POST | `/api/cases/{case_id}/ai/nl-search` | users with access to the case |
| GET | `/api/cases/{case_id}/ai/conversations` | users with access to the case |
| GET | `/api/cases/{case_id}/ai/conversations/{conversation_id}` | users with access to the case |
| DELETE | `/api/cases/{case_id}/ai/conversations/{conversation_id}` | users with access to the case |

The chat endpoint streams `text/event-stream`. Each frame is a JSON object with
a `type` of `conversation`, `meta`, `text`, `notice`, `error` or `done`. A `notice`
frame announces a tool lookup as it starts.

## Code map

| Path | Responsibility |
| --- | --- |
| `backend/app/services/ai/crypto.py` | Sealing and opening provider API keys. |
| `backend/app/services/ai/config.py` | The `AI_ASSISTANT` setting: storage, validation, resolution. |
| `backend/app/services/ai/providers.py` | The Anthropic and OpenAI-compatible adapters. |
| `backend/app/services/ai/context.py` | Building the case briefing. |
| `backend/app/services/ai/chat.py` | System prompt, tool loop, guardrails, audit, streaming. |
| `backend/app/services/ai/tools.py` | The read-only lookup tools and their schemas. |
| `backend/app/services/ai/nl_query.py` | Natural-language to Search-query translation. |
| `backend/app/services/ai/history.py` | Persisted conversations. |
| `backend/app/api/routes_ai.py` | HTTP surface. |
| `frontend/src/pages/AiSettingsPage.tsx` | Administrator configuration. |
| `frontend/src/components/ai/AiAssistantPanel.tsx` | The chat panel, mounted in the app shell. |
