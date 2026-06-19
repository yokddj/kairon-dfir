# Managed Windows symbols

Windows memory analysis requires an exact kernel symbol identity (PDB name,
GUID and age). A Windows build number alone is not a safe cache key.

Kairon runs memory analysis in `offline_only` mode by default. Normal analysis
uses only reviewed local ISFs and never opens network access. The managed
acquisition control plane is also disabled by default.

## Security gate

Managed acquisition must not be enabled until both controls exist:

1. deployment-enforced HTTPS egress limited to reviewed Microsoft symbol
   infrastructure, including validated redirects; and
2. authenticated administrator authorization for the acquisition operation.

Application hostname validation is not an egress sandbox. Current Docker bridge
networking permits general outbound connections, so setting only
`MEMORY_SYMBOL_MANAGED_DOWNLOAD_ENABLED=true` is insufficient. Kairon reports
`SYMBOL_ACQUISITION_NETWORK_ISOLATION_REQUIRED` and performs no download.

The optional `symbol-fetcher` service and dedicated `memory-symbols` queue are
defined under the `memory-symbols` Compose profile. Building it is safe, but
real acquisition remains blocked until both infrastructure egress enforcement
and authenticated administrator authorization exist. See
[Symbol fetcher security](symbol_fetcher_security.md).

Volatility 3 Framework 2.28.0 contains an HTTP default for its Microsoft symbol
retriever. Kairon must not use that downloader directly for managed mode. A
future fetch component must enforce HTTPS, certificate validation, exact-host
and redirect policy, response limits, identity validation and atomic cache
promotion.

The official Microsoft entry point reviewed for this design is
`https://msdl.microsoft.com/download/symbols`. Microsoft may redirect a request
to its Azure storage infrastructure; those destinations must be observed and
enforced by deployment policy without wildcard egress.

Only the symbol path components needed by Microsoft Symbol Server may leave the
deployment: PDB filename and the GUID-plus-age identifier. Case names, evidence
filenames and IDs, dump hashes, hostnames, memory pages, processes and Kairon
credentials must never be transmitted.

## Configuration

The safe baseline is:

```dotenv
MEMORY_SYMBOL_MODE=offline_only
MEMORY_SYMBOL_MANAGED_DOWNLOAD_ENABLED=false
MEMORY_SYMBOL_ALLOWED_HOSTS=
MEMORY_SYMBOL_NETWORK_ISOLATION_READY=false
MEMORY_SYMBOL_ADMIN_AUTHORIZATION_ENFORCED=false
MEMORY_SYMBOL_ADMIN_AUTHORIZATION_REQUIRED=true
```

Optional build and startup:

```bash
docker compose --profile memory-symbols build symbol-fetcher
docker compose --profile memory-symbols up -d symbol-fetcher
```

`GET /api/memory/symbols/cache` reports sanitized mode, capacity and gate state.
The acquisition request accepts only an authorization acknowledgement; URL,
host, PDB identity, path and command fields are rejected by schema validation.

## Cache and third-party artifacts

Runtime symbols belong in the persistent symbol cache, never in Git or an image.
Microsoft PDBs, generated ISFs and populated caches may be governed by
third-party terms. Operators should review those terms before redistributing a
cache. Kairon does not relicense these artifacts. This is a conservative
implementation posture, not legal advice.

Returning to offline-only operation means disabling managed acquisition and
running Volatility with `--offline`, the controlled cache path and controlled
symbol directories. Cached artifacts must be validated before use.
