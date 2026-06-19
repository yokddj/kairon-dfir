# Symbol fetcher security

## Threat model

The optional `symbol-fetcher` handles untrusted third-party PDB data and is the
only Kairon component designed to perform managed symbol downloads. It has no
evidence or memory-output mount, no public port, no Docker socket, no devices
and no access to normal or memory-analysis queues. It runs as UID/GID
`10001:10001` with a read-only root filesystem, all capabilities dropped and
`no-new-privileges` enabled. Its only writable persistent mount is the symbol
cache.

The normal memory worker always invokes Volatility with `--offline`. It cannot
delegate a download implicitly and never sends evidence to the fetcher.

## Outbound request

The initial destination is exactly `msdl.microsoft.com` over HTTPS port 443.
The request path contains only the validated PDB filename and GUID-plus-age
symbol key. Kairon does not send the case ID, evidence ID, filename, dump hash,
host details, process data or memory pages.

Redirects are bounded and revalidated at every hop. The reviewed redirect
category is a non-apex subdomain ending exactly in `.blob.core.windows.net`.
Lookalike suffixes, HTTP downgrade, user information, non-443 ports, IP
literals, loopback, private, link-local, multicast and non-global resolved
addresses are rejected. TLS uses the system trust store with certificate and
hostname verification. DNS is resolved before connection and the selected
public address is pinned for the TLS connection, reducing DNS-rebinding risk.

Downloads stream to an exclusive `0640` partial, enforce time and byte limits,
and calculate SHA-256 incrementally. PDB MSF identity is checked against the
required GUID/age before promotion. Volatility 3 2.28.0, installed from the
existing SHA-256-pinned lock, generates a compressed ISF. The ISF is parsed and
validated before atomic promotion.

## Infrastructure egress gate

Application validation does not by itself prevent a compromised process from
opening another socket. `MEMORY_SYMBOL_NETWORK_ISOLATION_READY` must remain
false until the deployment has an independently enforceable firewall or egress
proxy policy for the fetcher network. The current Docker bridge is not such a
control. Building the optional service does not authorize network acquisition.

## Administrator gate

Kairon currently has no authenticated administrator role. The acquisition API
therefore remains server-side blocked with
`SYMBOL_ACQUISITION_ADMIN_AUTH_REQUIRED`, even if configuration is changed.
Do not replace this with a hidden frontend control, source-IP trust or a static
secret header. A future authentication sprint must add an authenticated
`memory:symbols:acquire` capability and actor audit identity.

## Rollback and retention

Stop the optional profile and restore `MEMORY_SYMBOL_MODE=offline_only` and
`MEMORY_SYMBOL_MANAGED_DOWNLOAD_ENABLED=false`. Cached third-party artifacts
must not be committed, embedded in images or redistributed. This sprint does
not implement broad cache deletion or automatic eviction.
