# Managed Windows symbols

Windows memory analysis requires an exact kernel symbol identity (PDB name,
GUID and age). A Windows build number alone is not a safe cache key.

Kairon runs memory analysis in `offline_only` mode by default. Normal analysis
uses only reviewed local ISFs and never opens network access. The managed
acquisition control plane is also disabled by default.

## Security gate

Managed acquisition must not be enabled until BOTH controls exist:

1. **Deployment-enforced HTTPS egress limited to reviewed Microsoft symbol
   infrastructure** (including validated redirects).  The
   `symbol-egress-gateway` is the only component in the symbol subsystem
   that may open outbound connections, and it is restricted to
   `msdl.microsoft.com` (initial) and `*.blob.core.windows.net`
   (redirects).  See [Symbol Egress Gateway](symbol_egress_gateway.md).
2. **Local-operator approval** for the acquisition operation.  See
   [Local Operator Approval](memory_symbol_operator_approval.md).

Application hostname validation is NOT an egress sandbox.  The fetcher is
attached to a Docker `internal: true` network with no default route; the
gateway is the only component connected to a network with a default
route.  See [Memory Runner Security](memory_runner_security.md) for the
network topology.

Kairon reports `SYMBOL_ACQUISITION_NETWORK_ISOLATION_REQUIRED` and performs
no download until the topology has been independently verified and
`MEMORY_SYMBOL_NETWORK_ISOLATION_READY` is set true.

The optional `symbol-fetcher` and `symbol-egress-gateway` services plus the
dedicated `memory-symbols` queue are defined under the `memory-symbols`
Compose profile.  Building them is safe, but real acquisition remains
blocked until both infrastructure egress enforcement and
local-operator approval are in place.

Volatility 3 Framework 2.28.0 contains an HTTP default for its Microsoft
symbol retriever.  Kairon does NOT use that downloader directly for managed
mode.  The fetcher is a stdlib `http.client` client that talks only to the
egress gateway over the internal Docker network; the gateway then opens
the official HTTPS connection.

The official Microsoft entry point reviewed for this design is
`https://msdl.microsoft.com/download/symbols`.  Microsoft may redirect a
request to its Azure storage infrastructure; those destinations are
re-validated at every hop by the gateway.

Only the symbol path components needed by Microsoft Symbol Server may
leave the deployment: PDB filename and the GUID-plus-age identifier.  Case
names, evidence filenames and IDs, dump hashes, hostnames, memory pages,
processes and Kairon credentials must never be transmitted.

## Configuration

The safe baseline is:

```dotenv
MEMORY_SYMBOL_MODE=offline_only
MEMORY_SYMBOL_MANAGED_DOWNLOAD_ENABLED=false
MEMORY_SYMBOL_ALLOWED_HOSTS=
MEMORY_SYMBOL_NETWORK_ISOLATION_READY=false
MEMORY_SYMBOL_LOCAL_APPROVAL_ENABLED=false
MEMORY_SYMBOL_APPROVAL_TTL_SECONDS=600
MEMORY_SYMBOL_APPROVAL_SINGLE_USE=true
MEMORY_SYMBOL_EGRESS_GATEWAY_URL=http://symbol-egress-gateway:8443
MEMORY_SYMBOL_EGRESS_GATEWAY_SECRET=
MEMORY_SYMBOL_EGRESS_REPLAY_WINDOW_SECONDS=60
MEMORY_SYMBOL_EGRESS_MAX_RESPONSE_BYTES=1073741824
```

Optional build and startup:

```bash
docker compose --profile memory-symbols build symbol-fetcher symbol-egress-gateway
docker compose --profile memory-symbols up -d symbol-egress-gateway symbol-fetcher
```

`GET /api/memory/symbols/cache` reports sanitized mode, capacity, gate
state, pending request counts and the fetcher's online status.  The
acquisition request accepts only an authorization acknowledgement; URL,
host, PDB identity, path and command fields are rejected by schema
validation.  The actual queueing step is performed by the local-operator
CLI after explicit approval.

## Cache and third-party artifacts

Runtime symbols belong in the persistent symbol cache, never in Git or an
image.  Microsoft PDBs, generated ISFs and populated caches may be governed
by third-party terms.  Operators should review those terms before
redistributing a cache.  Kairon does not relicense these artifacts.  This is
a conservative implementation posture, not legal advice.

Returning to offline-only operation means disabling managed acquisition and
running Volatility with `--offline`, the controlled cache path and
controlled symbol directories.  Cached artifacts must be validated before
use.
