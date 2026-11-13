# MCP server

Kairon can expose a case's parsed data, read-only, to any client that speaks
the [Model Context Protocol](https://modelcontextprotocol.io) (MCP): an IDE,
a desktop assistant, a chat application with MCP support, or a custom
integration. It is a generic protocol, not tied to any vendor: the server
works with whatever MCP-compatible client an analyst or a team already uses,
so that client's model can search a case's events, read its timeline, list
its findings and detections or walk a process tree while you investigate.

- [Set it up](#set-it-up) — four steps, about ten minutes.
- [Tools](#tools) — what a connected client can do.
- [Troubleshooting](#troubleshooting) — the errors you can meet and what they mean.

## What it is, and what it is not

The MCP server is a thin bridge to the same **read-only lookup tools** the
in-app AI assistant uses (see [ai-assistant.md](ai-assistant.md)). Nothing is
duplicated: the server fetches the tool catalog from the backend at startup
(and again every 5 minutes, so a Kairon upgrade reaches connected clients
without restarting it) and runs each call by calling the backend back.

- **It cannot write.** It authenticates with a service token that Kairon
  refuses on any method but `GET`/`HEAD`: no findings, notes, timeline
  changes or jobs, whatever a client tries. Results are capped like the
  in-app assistant's (a sample, not a dump).
- **It sees every case.** A service token's scope is every case on the
  deployment, by design (an always-on integration should not need a new
  grant for every new case). It never reaches the administration API, the
  instance settings or the storage configuration, even for reads.
- **The AI assistant does not need to be enabled.** The tools read the case
  directly; no model provider is involved on Kairon's side. The model is the
  one in your MCP client.

## Set it up

### 1. Create a service token

The server reads Kairon with a **service token** (`kairon_svc_...`): a
long-lived, read-only credential for a non-interactive client.

As an administrator, open **Service Tokens** in the sidebar, give the token a
name (one per integration, e.g. `mcp-server`), pick an expiry and choose
**Create**. The token is shown **once**: copy it now (a password manager, the
server's `.env`). Only its hash is kept, so it cannot be shown again; if you
lose it, create another. The same page lists every token with when it was
last used, and **Revoke** stops one immediately — do it as soon as a token may
have leaked.

**From a script.** The same through the API with `curl`, against the address you open Kairon on
(here `http://localhost:5173`):

```bash
# Sign in as an administrator; the session cookie goes to a temporary file.
curl -s -c kairon.cookies -H 'Content-Type: application/json' \
  -d '{"username": "admin", "password": "<your password>"}' \
  http://localhost:5173/api/auth/login

# Create the token (the response's "token" field). expires_in_days is optional.
curl -s -b kairon.cookies -H 'Content-Type: application/json' \
  -d '{"name": "mcp-server", "expires_in_days": 90}' \
  http://localhost:5173/api/admin/service-tokens

curl -s -b kairon.cookies http://localhost:5173/api/admin/service-tokens                       # list (no secrets)
curl -s -b kairon.cookies -X DELETE http://localhost:5173/api/admin/service-tokens/<token id>  # revoke

rm kairon.cookies
```

### 2. Choose how the server runs

| | **A. Launched by the client (stdio)** | **B. Always-on server (HTTP)** |
| --- | --- | --- |
| Best for | One analyst, a desktop client on their own machine | A team, clients on other machines, clients that only connect to a URL |
| Runs | Your MCP client starts it as a local process | A container next to Kairon (`docker compose --profile mcp`) |
| Client authenticates with | Nothing (the client launched it) | A client token, `Authorization: Bearer <KAIRON_MCP_HTTP_TOKEN>` |
| Needs on the client machine | Python 3.12+ and this repository (or the package) | Only the URL and the client token |

**A. stdio.** Install the package on the machine the MCP client runs on:

```bash
pip install ./backend/mcp_server        # from a checkout of this repository
kairon-mcp-server --help                # check it is on the PATH
```

The client launches `kairon-mcp-server` with two environment variables (step 3
shows where they go):

- `KAIRON_API_URL`: the address you open Kairon on, e.g. `http://localhost:5173`
  (the UI port proxies the API; `http://localhost:8000` also works on the
  Kairon server itself).
- `KAIRON_SERVICE_TOKEN`: the token from step 1.

**B. HTTP with Docker Compose.** On the Kairon server, add two values to `.env`:

```bash
# .env
KAIRON_MCP_SERVICE_TOKEN=<the kairon_svc_... token from step 1>
KAIRON_MCP_HTTP_TOKEN=<output of: docker compose run --rm --no-deps mcp-server --generate-token>
```

and start it:

```bash
docker compose --profile mcp up -d mcp-server
docker compose logs mcp-server      # "Uvicorn running on http://0.0.0.0:8800"
```

It listens on `http://localhost:8800/mcp`. The two tokens are different
things: `KAIRON_MCP_SERVICE_TOKEN` is how the MCP server reads Kairon;
`KAIRON_MCP_HTTP_TOKEN` is what every MCP client must send to the MCP
server. Without the client token the HTTP transport refuses to start: the
service token reads every case, so anything able to reach the port —
including any local process when it only listens on localhost — could
otherwise read them through it. (`--no-auth` turns the check off; only for a
port nothing untrusted can reach.) To reach it from other machines, see
[Remote clients](#remote-clients).

Outside Docker the same server runs with
`KAIRON_MCP_HTTP_TOKEN=$(kairon-mcp-server --generate-token) kairon-mcp-server --transport http --port 8800`
(plus `KAIRON_API_URL` and `KAIRON_SERVICE_TOKEN`).

### 3. Connect your MCP client

Every client has its own configuration format; the values are always the
same: for stdio a command (`kairon-mcp-server`) with the two environment
variables, for HTTP a URL (`http://<server>:8800/mcp`) with an
`Authorization: Bearer <client token>` header. Examples for some common
clients follow; check your client's documentation if its format has changed.

**Claude Code** (`claude mcp add`):

```bash
# A. stdio
claude mcp add kairon -e KAIRON_API_URL=http://localhost:5173 -e KAIRON_SERVICE_TOKEN=kairon_svc_... -- kairon-mcp-server
# B. HTTP
claude mcp add --transport http kairon http://localhost:8800/mcp --header "Authorization: Bearer <client token>"
```

**Claude Desktop** (stdio; `claude_desktop_config.json`, opened from the
app's developer settings):

```json
{
  "mcpServers": {
    "kairon": {
      "command": "kairon-mcp-server",
      "env": { "KAIRON_API_URL": "http://localhost:5173", "KAIRON_SERVICE_TOKEN": "kairon_svc_..." }
    }
  }
}
```

Use the full path of `kairon-mcp-server` (`which kairon-mcp-server`) if the app
does not find it on its own `PATH`.

**VS Code** (HTTP; `.vscode/mcp.json`, the token asked once and kept by VS Code):

```json
{
  "inputs": [{ "type": "promptString", "id": "kairon-token", "description": "Kairon MCP client token", "password": true }],
  "servers": {
    "kairon": {
      "type": "http",
      "url": "http://localhost:8800/mcp",
      "headers": { "Authorization": "Bearer ${input:kairon-token}" }
    }
  }
}
```

A client configuration file holds the token in clear unless the client keeps
it in a secret store, as the VS Code example does: do not commit it.

### 4. Check that it works

Ask the client something like *"List my Kairon cases"*: it should call
`list_cases` and answer with your case names. Then *"In case X, which hosts
are there and what happened on the first one?"* exercises the case tools.

For the HTTP server, this answers `200` with the right token and `401` without it:

```bash
curl -s -o /dev/null -w '%{http_code}\n' -X POST http://localhost:8800/mcp \
  -H 'Content-Type: application/json' -H 'Accept: application/json, text/event-stream' \
  -H 'Authorization: Bearer <client token>' \
  -d '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"check","version":"1"}}}'
```

## Tools

A connected client sees these tools. Every one but `list_cases` takes a
`case_id`, which the client gets from `list_cases` (so you can simply name
the case). The catalog comes from Kairon itself, so it follows upgrades;
[ai-assistant.md](ai-assistant.md#what-it-is-and-what-it-is-not) describes
each tool in detail.

| Tool | Reads |
| --- | --- |
| `list_cases` | The cases, with id, name, status and evidence/host counts; filters by text, status, archived. |
| `describe_case` | Which artifact types, parsers, event types and hosts actually exist in the case, with counts. |
| `list_hosts` | The hosts with their event and evidence counts, and what the evidence says about each (hostname, OS, time zone). |
| `get_host_coverage` | Per host: which telemetry families it has or lacks compared with the others, and from when. |
| `search_events` | The case's parsed events, by text and filters. |
| `get_event_detail` | One event in full, by its id; also memory artifacts (ids starting with `memory:`). |
| `get_timeline` | A window of the case timeline in chronological order. |
| `search_command_history` | Commands actually executed: PowerShell, cmd, scheduled tasks, Prefetch, Linux shell history, memory. |
| `get_process_tree` | One process's parent and children. |
| `list_persistence` | Startup and persistence: run keys, services, scheduled tasks, startup folders... |
| `list_downloads` | Files downloaded from the internet: Mark of the Web, browser history (also MemProcFS's, from memory) and Defender detections that name the download URL (in its logs or still in memory). |
| `list_email_artifacts` | Webmail activity and local mail stores (OST/PST, .eml/.msg, attachment caches). |
| `list_lateral_movement` | Remote logons between machines (Windows network/RDP, Linux SSH). |
| `list_findings` | Findings recorded by the analyst or by detection rules. |
| `list_detections` | Rule-engine detections (Sigma, YARA, built-in). |
| `search_memory_artifacts` | Processes, connections (with their PID and process), modules, command lines, registry values and suspicious findings recovered from memory images. |
| `get_memory_triage` | Per memory image: Defender detections still in memory and processes worth a look. |
| `list_executions` | Programs that ran, each row with its source: memory processes (exited ones too, when a pool scan ran), Prefetch, Amcache, ShimCache, UserAssist and BAM from disk or from memory. |
| `get_memory_registry` | Registry values read from the hives in a memory image: computer name, addresses, users, OS, autoruns, services, and decoded BAM, UserAssist, ShimCache, RunMRU, TypedPaths. |
| `list_memory_files` | File objects still in a memory image (windows.filescan, Linux page cache), by path. |
| `list_memory_file_extractions` | Files recovered from memory images and what each extraction produced. |
| `read_memory_extracted_file` | The content of a recovered file, as text, hex or strings. |
| `list_find_evil` | Find Evil records: YARA matches, injected code, antivirus detections, beacons. |

The tools only read. Recovering a file from memory starts a job, so it is
done in the app (**Memory > Files**); the result is then readable here.

## Remote clients

The HTTP server listens on `127.0.0.1:8800` by default. To let clients on
other machines connect (over the VPN or private network Kairon already sits
behind):

```bash
# .env
KAIRON_MCP_BIND=192.0.2.1                                # the address to listen on
KAIRON_MCP_ALLOWED_HOSTS=kairon.vpn.example,192.0.2.1    # the names clients use in the URL
```

and restart it (`docker compose --profile mcp up -d mcp-server`). The server
checks the `Host` and `Origin` headers against DNS rebinding (a web page in a
browser must not be able to talk to it): localhost is always accepted, any
other name must be listed, or the server answers `421`. Standalone:
`kairon-mcp-server --transport http --host 0.0.0.0 --allowed-host kairon.vpn.example`.

The client token is a static bearer token: over plain HTTP it travels in
clear, so beyond localhost put the server behind a TLS reverse proxy (and
then list the proxy's host name in `KAIRON_MCP_ALLOWED_HOSTS`).

## Troubleshooting

| Where | Message or status | Meaning and fix |
| --- | --- | --- |
| Server start | `KAIRON_API_URL is not set` / `KAIRON_SERVICE_TOKEN is not set` | Set both (step 2). |
| Server start | `The HTTP transport needs a token clients must present` | Set `KAIRON_MCP_HTTP_TOKEN` (at least 32 characters; `--generate-token` makes one). |
| Server start | `Could not load the tool catalog from Kairon at ...: ... 401` | The service token is wrong, revoked or expired (check its status under **Service Tokens**): create a new one (step 1). |
| Server start | `Could not load the tool catalog ...: Could not reach Kairon` | `KAIRON_API_URL` is not reachable from where the server runs (inside Compose it is `http://backend:8000`, set for you). |
| Client | `401` from the server | The client sends no client token, or the wrong one: check the `Authorization: Bearer` header. |
| Client | `421 Misdirected Request` | The URL's host name is not listed in `KAIRON_MCP_ALLOWED_HOSTS` (see [Remote clients](#remote-clients)). |
| Client | `403` | The request carried a browser `Origin` that is not allowed: MCP clients normally send none. |
| Tool result | `Invalid case_id: use an id returned by list_cases` | The model passed a case name or other text as the id; ask it to call `list_cases` first. |
| Tool result | `Case not found` (`404`) | The case was deleted, or the id belongs to another Kairon instance. |
| Tool result | `Service tokens cannot use the administration API` | Expected: the server never reads administrative data. |

## Security notes

- **Two secrets.** The service token (`KAIRON_SERVICE_TOKEN` /
  `KAIRON_MCP_SERVICE_TOKEN`) lives only where the server runs and is never
  shown to MCP clients, which see tool names, descriptions and results. The
  client token (`KAIRON_MCP_HTTP_TOKEN`, HTTP transport only) is what clients
  hold. Both give read access to every case: treat them like passwords,
  revoke or rotate them if they leak (a new client token is just a new value
  in `.env` and a restart).
- A `case_id` must be a single id as returned by `list_cases`; anything with
  `/`, `..`, `?` or `#` is refused before any request, so text planted in
  case data cannot steer a tool call to another API endpoint.
- Tool results contain case data, and case data can be attacker-controlled (a
  host name, a file name, a command line). Everything the
  [Prompt injection](ai-assistant.md#prompt-injection) section of the AI
  assistant's documentation says applies identically: the server is read-only
  and limited to its tools; what a connected client's own model does with the
  text it reads is that client's concern, as with any other data source.
- Keep the HTTP server behind the same network boundary the rest of the
  deployment requires (see [deployment/deployment.md](../deployment/deployment.md)).

## Code map

| Path | Responsibility |
| --- | --- |
| `backend/app/api/routes_ai.py` | `GET /api/ai/tools`, `GET /api/cases/{case_id}/ai/tools/{tool_name}` — the HTTP surface this server calls. |
| `backend/app/api/routes_admin.py` | `/api/admin/service-tokens`: create, list, revoke. |
| `frontend/src/pages/ServiceTokensPage.tsx` | The **Service Tokens** admin page. |
| `backend/app/services/service_tokens.py` | Service token creation, authentication, revocation. |
| `backend/app/services/auth_dependencies.py` | `ServiceTokenPrincipal`, the read-only-every-case principal. |
| `backend/mcp_server/mcp_server/kairon_client.py` | The HTTP client this server uses to call Kairon's API. |
| `backend/mcp_server/mcp_server/server.py` | Tool catalog bridging, `list_cases`, transports, client token, Host/Origin checks. |
