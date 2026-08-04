# Symbol fetcher security

## Threat model

The optional `symbol-fetcher` handles untrusted third-party PDB data and is the
only Kairon component that orchestrates managed symbol downloads. It has no
evidence or memory-output mount, no public port, no Docker socket, no devices
and no access to normal or memory-analysis queues. It runs as UID/GID
`10001:10001` with a read-only root filesystem, all capabilities dropped and
`no-new-privileges` enabled. Its only writable persistent mount is the symbol
cache.

The normal memory worker always invokes Volatility with `--offline`. It cannot
delegate a download implicitly and never sends evidence to the fetcher.

## Outbound request

The fetcher DOES NOT make outbound HTTPS connections directly.  All requests
go through the `symbol-egress-gateway` over an internal Docker network.  See
`docs/symbol_egress_gateway.md` for the gateway trust boundary, the signed
request protocol, and the source/redirect policy.

Application-level URL allowlisting (initial host `msdl.microsoft.com`, redirect
suffix `.blob.core.windows.net`) remains in the fetcher as a defense in
depth.  Neither the application policy nor the gateway policy alone is
sufficient to claim network isolation: only the Docker network topology
(internal network for the fetcher) is the binding control.

## Infrastructure egress gate

Application validation does not by itself prevent a compromised process from
opening another socket.  The fetcher is connected only to `symbol-internal`
(an `internal: true` Docker network with no default route).  The
`symbol-egress-gateway` is the only component in the symbol subsystem
connected to a network with a default route (`symbol-egress`).

`MEMORY_SYMBOL_NETWORK_ISOLATION_READY` must remain false until the
deployment has been independently verified to enforce this topology.  The
flag is set true only after:

1. `docker compose config` shows the symbol-fetcher is on `symbol-internal` only.
2. The fetcher has been proven unable to reach the Internet directly.
3. The gateway has been proven to be the only outbound path.
4. The gateway's source and redirect policy tests pass.
5. The runtime security checks pass.

See `docs/memory_operations.md` and `docs/deployment_remote.md` for the
runtime proof procedure.

## Administrator gate

Kairon does not yet provide a mature authenticated administrator role.  The
interim control is a server-side CLI that records explicit local-operator
authorization.  See `docs/memory_symbol_operator_approval.md` for the
lifecycle, the CLI commands, and the approval semantics.

The acquisition API remains blocked with
`SYMBOL_ACQUISITION_LOCAL_APPROVAL_DISABLED` when
`MEMORY_SYMBOL_LOCAL_APPROVAL_ENABLED=false`.  Do not replace this with a
hidden frontend control, source-IP trust, or a static secret header.  A
future authentication sprint must add an authenticated
`memory:symbols:acquire` capability and actor audit identity, and replace
the local-operator CLI.

## Rollback and retention

Stop the optional profile and restore `MEMORY_SYMBOL_MODE=offline_only` and
`MEMORY_SYMBOL_MANAGED_DOWNLOAD_ENABLED=false`.  Cached third-party artifacts
must not be committed, embedded in images or redistributed.  This sprint
does not implement broad cache deletion or automatic eviction.
