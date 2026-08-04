# Symbol Egress Gateway

The symbol egress gateway is the single, narrow-purpose HTTPS proxy that the
`symbol-fetcher` uses to reach Microsoft's official symbol infrastructure.
It is the only component in the symbol subsystem with an outbound route;
the fetcher is attached to an internal-only Docker network and cannot reach
the Internet directly.

## Trust boundary

```
┌─────────────────┐   internal network    ┌──────────────────────┐
│  symbol-        │ ──── HMAC-signed ───► │  symbol-egress-      │ ─── HTTPS ──► msdl.microsoft.com
│  fetcher        │ ◄── streamed body ─── │  gateway             │ ◄── redirect ──── *.blob.core.windows.net
└─────────────────┘                       └──────────────────────┘
       │                                           │
       │  no default route                        │  egress network
       │  (internal: true)                        │  (default route)
```

The gateway is NOT a generic proxy.  It accepts only:

* HTTP method: `POST`
* Path: `/internal/symbol-fetch`
* Authenticated headers: `X-Kairon-Egress-Version`, `X-Kairon-Egress-Request-Id`,
  `X-Kairon-Egress-Timestamp`, `X-Kairon-Egress-Nonce`, `X-Kairon-Egress-Signature`
* JSON body keys: `request_id`, `pdb_name`, `guid`, `age`

Any other method, path, header, or body key is rejected with 4xx.  Clients
do not provide a URL, host, port, or query parameters; the gateway
constructs the official URL from the validated PDB/GUID/age.

## Auth: signed requests

* The fetcher and the gateway share a server-generated 32-byte secret
  (`MEMORY_SYMBOL_EGRESS_GATEWAY_SECRET`).  It is stored only in
  environment variables / secret storage, never committed, and is rotatable
  via the deploy script.
* Each request carries an HMAC-SHA256 over:

  ```
  v1
  {request_id}
  {timestamp}
  {nonce}
  POST
  /internal/symbol-fetch
  sha256(body)
  ```

* Replay protection: the timestamp must be within `MEMORY_SYMBOL_EGRESS_REPLAY_WINDOW_SECONDS`
  of the server clock, and the nonce must not have been used in the last
  `2 * replay_window_seconds`.  Nonces are kept in process memory only
  (restart of the gateway invalidates pending nonces, which is intentional).

## Source / redirect policy

* Initial host: exactly `msdl.microsoft.com` (HTTPS, port 443 only).
* Redirect suffix: a non-apex subdomain ending exactly in `.blob.core.windows.net`.
  Examples accepted by DNS/IP/TLS checks:
  * `a.b.blob.core.windows.net`
  * `symbols123.blob.core.windows.net`
  Examples rejected (in addition to those listed in the redirect allowlist):
  * `blob.core.windows.net` (apex)
  * `evilblob.core.windows.net` (substring match, not label boundary)
  * `x.blob.core.windows.net.attacker.example`
  * `msdl.microsoft.com.attacker.example`
  * any IP literal
  * any private, loopback, link-local, multicast, reserved, or non-global address
* Maximum redirects: `MEMORY_SYMBOL_MAX_REDIRECTS` (default 5).  Each
  redirect is re-validated by hostname and DNS independently.
* TLS: `ssl.create_default_context()` with hostname verification.  TLS
  errors are translated to `EGRESS_TLS_FAILED`.
* Bounded streaming with `Content-Length` pre-check and incremental size
  enforcement; abort if the response exceeds
  `MEMORY_SYMBOL_DOWNLOAD_MAX_BYTES`.

## Defense in depth

Application-level URL allowlisting in the symbol-fetcher remains in place.
The gateway is a second layer of policy.  Either layer alone is not
sufficient to claim network isolation: the only way to claim isolation
is to prove at the Docker network level that the fetcher has no default
route to the Internet.

The fetcher is connected to `symbol-internal` only (an `internal: true`
network).  The gateway is connected to `symbol-internal` and to
`symbol-egress` (a normal bridge with a default route).  No other
service in the project is attached to either network.

## Operational notes

* The gateway refuses to start without `MEMORY_SYMBOL_EGRESS_GATEWAY_SECRET`.
  The compose file must generate or inject the secret before bringing the
  service up.
* The gateway does not log request bodies or upstream bodies.  It logs the
  request id, the validated PDB identity (after policy checks), the
  redirect count, and the error code on failure.
* The fetcher still re-hashes every byte it receives and validates the
  PDB identity before promoting the file.  The gateway does not trust
  upstream responses.
* The gateway does not write to the symbol cache, the evidence store, the
  memory-output, or any application queue.
