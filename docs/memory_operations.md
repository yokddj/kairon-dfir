# Memory Operations

## Enablement

Default deployment remains disk-only. To run real memory analysis, an administrator must intentionally enable:

- `MEMORY_UPLOAD_ENABLED=true`
- `MEMORY_ANALYSIS_ENABLED=true`
- `MEMORY_ALLOW_EXTERNAL_TOOL_EXECUTION=true`
- `MEMORY_PROCESS_PROFILE_ENABLED=true` for process profiles
- `MEMORY_WORKER_MODE=dedicated_worker`
- `MEMORY_REQUIRE_DEDICATED_WORKER=true`
- `MEMORY_TASK_QUEUE=memory`
- `MEMORY_SYMBOL_NETWORK_ACCESS_ENABLED=false`

Build and start the optional worker only after reviewing the Volatility license notice:

```bash
docker compose --profile memory build memory-worker
docker compose --profile memory up -d memory-worker
```

Kairon does not install Volatility on the host, backend, frontend, or normal worker.

## Workflow

1. Open the case and go to Memory Analysis.
2. Select Add memory image.
3. Review readiness and capacity.
4. Upload the authorized RAM image.
5. Confirm it appears as `memory_dump` in Memory Analysis.
6. Start with `metadata_only`.
7. Run `processes_basic` or `processes_extended` only when process inventory is needed.

Each scan request must include the authorization acknowledgement. Kairon does not expose plugin checkboxes or command-line controls.

The generic Evidence Upload page remains available for backward compatibility and links users to the dedicated memory upload flow when a memory extension is selected.

## Symbols

The default symbol policy is offline only. Kairon does not silently download symbols. If Volatility cannot satisfy requirements, the run fails safely with a sanitized error and should be reported as `implemented_pending_symbols` until symbols are supplied through an approved external process.

## Troubleshooting

- Upload rejected: check `MEMORY_UPLOAD_ENABLED`, extension allowlist, and `MEMORY_UPLOAD_MAX_BYTES`.
- Worker offline: check `docker compose --profile memory ps memory-worker` and `/api/memory/backends`.
- Queue not moving: the normal worker does not consume the memory queue; the dedicated memory worker must be healthy.
- Do not attach RAM images, real Volatility JSON, command lines, symbols, or credentials to public GitHub issues.
