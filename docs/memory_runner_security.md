# Memory Runner Security

## Scope

The current memory runner supports Volatility 3 `windows.info` plus isolated process inventory plugins: `windows.pslist`, `windows.pstree`, `windows.psscan`, and `windows.cmdline`. Volatility 3 is external, optional, not bundled, and governed by its own license. Kairon does not install it automatically.

## Threat model

Memory images can contain credentials, personal data, malware, private keys, and regulated information. Operators must analyze only evidence they own or are authorized to examine. Kairon must not expose memory contents to global disk workflows or third-party services.

Browser memory upload is disabled by default and, when enabled, streams to staging in bounded chunks with incremental SHA-256 and size enforcement. Failed or oversized uploads do not become scannable evidence. Scan requests require an explicit authorization acknowledgement in the request context.

## Command injection protections

- API and UI requests cannot provide executable paths, plugin names, command arguments, output paths, symbol URLs, or environment variables.
- The configured executable comes only from trusted server-side settings.
- Configured command values must be a single executable name or absolute executable path.
- Shell fragments and embedded arguments are rejected.
- Subprocess execution uses `shell=False`.

The fixed argv is:

```text
[resolved_volatility_executable, "-f", validated_evidence_path, "-r", "json", plugin_from_server_profile]
```

## Path validation

The evidence path is resolved from Kairon evidence metadata, not from the request body. The runner rejects missing files, directories, symlinks, special files, empty files, and paths outside approved evidence storage roots.

Uploaded or copied evidence must remain under Kairon's evidence storage tree. Mounted/shared evidence must resolve under administrator-approved evidence roots.

## Subprocess isolation

The runner uses a minimal environment and a per-run working directory. It does not pass application secrets, raw environment files, Docker sockets, host devices, or arbitrary user-controlled values to Volatility.

Plugins run sequentially to reduce CPU/memory pressure and keep the audit trail simple.

The default deployment does not include Volatility. Operators may build an optional dedicated memory worker that runs with no privileged mode, no host PID/device access, read-only evidence mounts, and writable access only to approved temporary/output directories.

## Output limits and timeouts

- `MEMORY_PLUGIN_TIMEOUT_SECONDS` bounds the plugin process.
- `MEMORY_PLUGIN_OUTPUT_MAX_BYTES` bounds captured stdout.
- On timeout, Kairon attempts graceful termination and then kills the process group if necessary.
- Raw stderr is not stored unbounded or returned directly to the UI.

## Symbol and network policy

Kairon does not initiate automatic symbol downloads. `MEMORY_SYMBOL_NETWORK_ACCESS_ENABLED=false` by default. If symbols are unavailable, the run fails safely with a sanitized requirements error and does not retry indefinitely.

The managed-symbol API is independently gated by deployment-level network
isolation and administrator authorization. Hostname checks in application code
are not treated as sufficient egress isolation. See
[Managed Windows symbols](memory_symbols.md).

## Storage policy

Raw plugin output is stored under the isolated evidence run directory:

```text
data/evidence/{case_id}/{evidence_id}/memory/runs/{run_id}/
```

Database rows store relative paths, SHA-256 hashes, sizes, and status metadata. Normalized metadata is indexed only into `dfir-memory-{case_id}`. The existing disk events index is not written by the memory runner.

Process command lines may contain sensitive user data. They are bounded, never logged in full, and exposed only in the isolated Memory Analysis process table/details surfaces.

## Logging redaction

Logs may include run ID, case ID, evidence ID, backend, plugin, state transition, duration, row count, and sanitized error code. Logs must not include raw memory contents, full command lines with evidence paths, environment variables, credentials, raw plugin JSON, or unbounded stdout/stderr.

## Known limitations

- Only `windows.info`, `windows.pslist`, `windows.pstree`, `windows.psscan`, and `windows.cmdline` are supported.
- MemProcFS execution is not implemented.
- No network, registry, credential, malware, file, string, injection, YARA, DLL, handle, driver, service, or hybrid-correlation analysis is implemented.
- Real execution requires either an administrator-provided Volatility 3 executable or the optional operator-built `memory-worker`, plus authorized lab evidence.

## Optional dedicated worker

The optional `memory-worker` Compose profile builds an isolated image locally on the operator's server and installs pinned Volatility 3 from official PyPI during that build. It is not part of the default deployment, is not published as a prebuilt Kairon image, and must not be redistributed without separate license review.

In `MEMORY_WORKER_MODE=dedicated_worker`, memory jobs are routed to the dedicated memory queue. The normal worker continues disk ingest/rules/analysis work and does not need Volatility installed. The backend readiness endpoint relies on the memory worker heartbeat rather than running `vol` in the backend container.
