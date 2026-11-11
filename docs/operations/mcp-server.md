# MCP server

Kairon can expose a case's parsed data, read-only, to any client that speaks
the [Model Context Protocol](https://modelcontextprotocol.io) (MCP): an IDE,
a desktop assistant, a chat application with MCP support, or a custom
integration. This is a generic protocol, not tied to any particular vendor —
the server is useful to whatever MCP-compatible client an analyst or a team
already uses.

## What MCP is, briefly

MCP standardizes how a client (the part a person or a model interacts with)
discovers and calls tools exposed by a server. A client connects, asks what
tools exist (with a name, a description and a JSON Schema of parameters),
and later calls one by name with arguments; the server runs it and returns a
result. That is the entire shape of the protocol Kairon's MCP server
implements.

## What it is, and what it is not

Kairon's MCP server is a thin bridge to the same **read-only lookup tools**
the in-app AI assistant already uses (see
[operations/ai-assistant.md](ai-assistant.md)) — `describe_case`,
`search_events`, `get_timeline`, `list_findings`, `get_process_tree`, and the
rest of that table. Nothing is duplicated: the server fetches the tool
catalog from the backend at startup (and again every 5 minutes, so a backend
upgrade reaches connected clients without a restart) and executes a call by
calling the backend back, so a tool's behavior, its parameters and its
description are defined once.

One tool exists only here, not in the in-app assistant's set: **`list_cases`**,
to resolve a case by name before calling any of the others, all of which take
a `case_id`. The in-app assistant has no equivalent need — its case is
already fixed by the page it runs on — but an external client asking about
"the Smith investigation" needs a way to find that case's id first.

**It cannot write.** The server authenticates with a service token that is
refused on any method but `GET`/`HEAD` (see below), so this holds regardless
of which tools a future client tries to call. It cannot create findings,
edit notes, change the timeline or start a job, the same guarantee the
in-app assistant has. Results are capped the same way too (a sample, not a
dump): see ai-assistant.md's limits.

## Authentication: service tokens

The server authenticates to Kairon's API with a **service token** — a
long-lived, read-only credential for a non-interactive client, distinct from
a browser session. A service token's scope is every case on the deployment,
by design: granting access case by case, the way a human user's access is
granted, would mean re-granting it every time a new case is opened, which
does not fit an always-on integration. A service token is never an
administrator: it is refused on every write (any method but `GET`/`HEAD`)
and, even for reads, on the administration API (`/api/admin/...`, including
user management, other tokens and performance tuning), instance settings
(`/api/system/settings`) and storage configuration (`/api/storage/...`).

Create one as an administrator:

```
POST /api/admin/service-tokens
{"name": "mcp-server"}
```

The response includes the token's plaintext value **once** — store it now;
only its hash is kept afterward, so it cannot be recovered later, the same
as a password. List and revoke tokens with:

```
GET    /api/admin/service-tokens
DELETE /api/admin/service-tokens/{token_id}
```

Revoke a token (and issue a new one) if it is ever exposed, and set
`expires_in_days` at creation for one that should not outlive a fixed
engagement or review period.

## Running the server

The server is a standalone package, `backend/mcp_server/`: it never imports
Kairon's backend code and talks to it purely over HTTP, so it can run on its
own host or container, independent of the backend's own lifecycle.

### With Docker Compose

Off by default; enable its profile and set the token:

```bash
# .env
KAIRON_MCP_SERVICE_TOKEN=<the token from POST /api/admin/service-tokens>
KAIRON_MCP_HTTP_TOKEN=<docker compose run --rm mcp-server --generate-token>

docker compose --profile mcp up -d mcp-server
```

Two different tokens: `KAIRON_MCP_SERVICE_TOKEN` is how this server reads Kairon; `KAIRON_MCP_HTTP_TOKEN` is what MCP clients must present to this server, as `Authorization: Bearer <token>` (most MCP clients that connect to a remote server let you add a header). Without the client token the HTTP transport refuses to start: the service token reads every case, so anything able to reach the port -- including any local process when it is bound to localhost -- could otherwise read them through it. `--no-auth` turns the check off, only for a port nothing untrusted can reach.

This starts it with the streamable HTTP transport on `127.0.0.1:8800` (bind
address configurable via `KAIRON_MCP_BIND`), reachable at
`http://localhost:8800/mcp`. Point an MCP client that supports a remote
server at that URL.

The HTTP transport checks the `Host` and `Origin` headers (protection against
DNS rebinding: a web page in the analyst's browser must not be able to talk
to this server). Localhost is always accepted. To let a client on another
machine connect through a VPN name or a private address, bind beyond
localhost **and** list that name, or the server answers `421`:

```bash
# .env
KAIRON_MCP_BIND=192.0.2.1
KAIRON_MCP_ALLOWED_HOSTS=kairon.vpn.example,192.0.2.1
```

Standalone: `kairon-mcp-server --transport http --host 0.0.0.0 --allowed-host kairon.vpn.example`.

### Standalone, for a local MCP client

Many desktop MCP clients launch a server themselves over stdio rather than
connecting to one already running. Install the package and point it at a
reachable Kairon backend:

```bash
pip install ./backend/mcp_server
export KAIRON_API_URL=http://localhost:8000
export KAIRON_SERVICE_TOKEN=<the token>
kairon-mcp-server                 # stdio, the default
export KAIRON_MCP_HTTP_TOKEN=$(kairon-mcp-server --generate-token)
kairon-mcp-server --transport http --port 8800   # streamable HTTP instead
```

Consult your MCP client's own documentation for how it is configured to
launch or connect to a server; that step is client-specific and outside
Kairon's scope.

## Tools

The catalog comes from `GET /api/ai/tools` (refreshed every 5 minutes), so it
matches what the in-app assistant can do — see the table in
[operations/ai-assistant.md](ai-assistant.md#what-it-is-and-what-it-is-not)
for the current list and what each tool reads. Every tool there takes a
`case_id` here (resolved via `list_cases`); none of them do inside the
in-app assistant, where the case is already known.

## Security notes

- The token is supplied once, via the `KAIRON_SERVICE_TOKEN` environment
  variable, and is never visible to the connected MCP client — which only
  ever sees tool names, descriptions and results, the same surface the
  in-app assistant's model sees.
- Treat the token like a password: anyone who holds it can read every case
  on the deployment for as long as it is valid. Scope its lifetime with
  `expires_in_days` where that fits, and revoke it immediately if it leaks.
- A `case_id` must be a single id as returned by `list_cases`; anything with
  `/`, `..`, `?` or `#` is refused before any request, so text planted in
  case data cannot steer a tool call to another API endpoint.
- The streamable HTTP transport requires its own client token
  (`KAIRON_MCP_HTTP_TOKEN`, compared in constant time); treat it like the
  service token, since it gives the same read access. Still keep the server
  behind the network boundary the rest of the deployment requires (VPN,
  private network, authenticated proxy; see
  [deployment/deployment.md](../deployment/deployment.md)): a static bearer
  token travels in clear over plain HTTP, so use TLS (a reverse proxy) for
  anything beyond localhost. The stdio transport needs no token: the client
  launches the server itself.
- Everything the Prompt injection section of
  [operations/ai-assistant.md](ai-assistant.md#prompt-injection) says about
  untrusted data in tool results applies here identically: a hostname, a
  filename or a command line can be attacker-controlled. The server's job
  is read-only and scoped to the tools it was given; what a connected
  client's own model does with the text it gets back is that client's
  concern, same as any other data source it might read.

## Code map

| Path | Responsibility |
| --- | --- |
| `backend/app/api/routes_ai.py` | `GET /api/ai/tools`, `GET /api/cases/{case_id}/ai/tools/{tool_name}` — the HTTP surface this server calls. |
| `backend/app/services/service_tokens.py` | Service token creation, authentication, revocation. |
| `backend/app/services/auth_dependencies.py` | `ServiceTokenPrincipal`, the read-only-every-case principal. |
| `backend/mcp_server/mcp_server/kairon_client.py` | The HTTP client this server uses to call Kairon's API. |
| `backend/mcp_server/mcp_server/server.py` | Tool catalog bridging, `list_cases`, the MCP server itself. |
