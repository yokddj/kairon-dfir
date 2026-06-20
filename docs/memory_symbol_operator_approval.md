# Memory Symbol Local-Operator Approval

Kairon does not yet have a mature authenticated administrator role inside
the application.  Until that exists, the only authorized way to trigger a
real managed symbol acquisition is through a server-side CLI that records
explicit local-operator authorization.

This is an INTERIM control.  It is **not** a replacement for future
application RBAC.  The security boundary is the operator's authorized
access to the deployment host.

## Configuration

| Variable | Default | Purpose |
|---|---|---|
| `MEMORY_SYMBOL_LOCAL_APPROVAL_ENABLED` | `false` | Master switch.  Must be `true` to approve any request. |
| `MEMORY_SYMBOL_APPROVAL_TTL_SECONDS` | `600` | Time-to-live of an approval.  Once expired, the approval is rejected. |
| `MEMORY_SYMBOL_APPROVAL_SINGLE_USE` | `true` | Whether an approval can be consumed more than once. |

`MEMORY_SYMBOL_LOCAL_APPROVAL_ENABLED` MUST default to `false` and MUST
only be flipped to `true` after:

1. The Docker network topology is verified to enforce isolation.
2. The symbol-egress-gateway is reachable and healthy.
3. The symbol-fetcher is online and registered with the same queue.

## Lifecycle of a symbol acquisition request

```
                   ┌──────────────────────────┐
                   │ awaiting_network_isolation│
                   └────────────┬─────────────┘
                                │ (isolation ready)
                                ▼
                   ┌──────────────────────────┐
                   │ awaiting_operator_approval│
                   └────────────┬─────────────┘
                                │ (CLI: approve)
                                ▼
                          ┌────────┐
                          │approved│
                          └───┬────┘
                              │ (CLI: queue, or auto after approve)
                              ▼
                          ┌──────┐
                          │queued│
                          └──┬───┘
                             ▼
                ┌──── resolving → downloading → ... ────┐
                ▼                                          ▼
            ┌──────────┐                            ┌──────────┐
            │ completed│                            │  failed  │
            └──────────┘                            └──────────┘
```

* `expired`: an active approval was not consumed within the TTL.
* `revoked`: an operator explicitly revoked an active approval.
* `stale`: the request lost its requirement (e.g. memory evidence removed).

## CLI usage

Run from the deployment host against the backend container:

```bash
docker compose exec backend python -m app.cli.memory_symbols list-pending
docker compose exec backend python -m app.cli.memory_symbols show --request-id <id>
docker compose exec backend python -m app.cli.memory_symbols approve --request-id <id>
docker compose exec backend python -m app.cli.memory_symbols revoke --request-id <id>
docker compose exec backend python -m app.cli.memory_symbols status --request-id <id>
```

### `approve` workflow

1. The CLI prints a sanitized summary:

   ```json
   {
     "request_id": "...",
     "case_id": "...",
     "evidence_id": "...",
     "pdb_name": "ntkrnlmp.pdb",
     "pdb_guid": "9DC3FC69B1CA4B34707EBC57FD1D6126",
     "pdb_age": 1,
     "architecture": "x64",
     "official_source_category": "official_microsoft_symbols",
     "transmitted_metadata": ["pdb_name", "guid", "age"],
     "no_ram_transmitted": true,
     "third_party_cache": true,
     "current_status": "awaiting_operator_approval"
   }
   ```

   The summary NEVER includes:
   * evidence file paths or sizes
   * RAM content or metadata beyond the symbol identity
   * the gateway URL or the shared secret
   * the user's browser session

2. The CLI then asks for explicit confirmation:

   ```
   Type 'approve' to confirm, or Ctrl+C to abort: 
   ```

   The operator MUST type the literal string `approve`.  Anything else
   aborts.

3. On success, the CLI prints the approval id, the new status, and the
   expiration timestamp.

4. The approval is recorded in `memory_symbol_approvals` with:
   * `actor_category = local_operator`
   * `actor_label = server-operator` (overridable via `--actor`)
   * `requirement_fingerprint` bound to the exact PDB/GUID/age/architecture
   * `expires_at` = now + TTL
   * `audit_metadata_json` with TTL and single-use semantics

### What the CLI does NOT accept

The CLI does not accept custom URLs, hosts, ports, PDB names, GUIDs, ages,
or cache paths.  The exact symbol identity always comes from the stored
trusted `MemorySymbolRequirement`.  Any attempt to override is a bug.

## What the approval binds

* **Request id**: only the matching `MemorySymbolAcquisitionRequest` can consume.
* **Symbol identity**: only requests whose stored `requirement_fingerprint`
  matches the approval's `requirement_fingerprint` are eligible.
* **Time**: must be consumed before `expires_at`.
* **Use count**: by default exactly one; a second consume attempt returns
  `SYMBOL_APPROVAL_NOT_ACTIVE`.

## UI behavior

Ordinary users see the following copy in the memory analysis panel:

* Isolation not ready: "Managed acquisition is unavailable until restricted network egress is configured."
* Local approval disabled: "Managed acquisition is unavailable until server-operator approval is enabled."
* Pending request: "A symbol acquisition request is awaiting server-operator approval."
* Approved and queued: "Symbol acquisition was approved and queued."
* Completed: "Required Windows symbols are now cached."
* Failed/expired/revoked: "The symbol acquisition attempt did not complete. Contact the server operator for details."

The UI MUST NOT show the CLI command, the gateway URL, or the shared
secret to ordinary users.  An authenticated/local administration
documentation page may show the command.

## Rollback

To roll back to offline-only mode after an acquisition:

1. Confirm the symbol is cached.
2. Confirm the next `metadata_only` scan succeeds.
3. Optionally set `MEMORY_SYMBOL_LOCAL_APPROVAL_ENABLED=false` to prevent
   new acquisitions.
4. Optionally set `MEMORY_SYMBOL_NETWORK_ISOLATION_READY=false` to disable
   the egreso path at the runtime gate.  The compose-level network
   isolation remains in effect regardless of this flag.

## Future replacement

When Kairon provides an authenticated administrator role, this CLI will
be replaced by an in-application authorization step.  The
`MemorySymbolApproval` model and lifecycle will continue to apply, but
the actor will be an application-level user rather than a server-local
operator.
