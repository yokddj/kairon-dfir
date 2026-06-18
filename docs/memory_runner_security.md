# Memory Runner Security

## Scope

The current memory runner supports only Volatility 3 `windows.info` metadata execution. Volatility 3 is external, optional, not bundled, and governed by its own license. Kairon does not install it automatically.

## Threat model

Memory images can contain credentials, personal data, malware, private keys, and regulated information. Operators must analyze only evidence they own or are authorized to examine. Kairon must not expose memory contents to global disk workflows or third-party services.

## Command injection protections

- API and UI requests cannot provide executable paths, plugin names, command arguments, output paths, symbol URLs, or environment variables.
- The configured executable comes only from trusted server-side settings.
- Configured command values must be a single executable name or absolute executable path.
- Shell fragments and embedded arguments are rejected.
- Subprocess execution uses `shell=False`.

The fixed argv is:

```text
[resolved_volatility_executable, "-f", validated_evidence_path, "-r", "json", "windows.info"]
```

## Path validation

The evidence path is resolved from Kairon evidence metadata, not from the request body. The runner rejects missing files, directories, symlinks, special files, empty files, and paths outside approved evidence storage roots.

Uploaded or copied evidence must remain under Kairon's evidence storage tree. Mounted/shared evidence must resolve under administrator-approved evidence roots.

## Subprocess isolation

The runner uses a minimal environment and a per-run working directory. It does not pass application secrets, raw environment files, Docker sockets, host devices, or arbitrary user-controlled values to Volatility.

The current deployment may run the task in the existing worker container. A future dedicated memory worker should run with constrained CPU/memory, no privileged mode, no host PID/device access, read-only evidence mounts, network disabled by default, and writable access only to approved temporary/output directories.

## Output limits and timeouts

- `MEMORY_PLUGIN_TIMEOUT_SECONDS` bounds the plugin process.
- `MEMORY_PLUGIN_OUTPUT_MAX_BYTES` bounds captured stdout.
- On timeout, Kairon attempts graceful termination and then kills the process group if necessary.
- Raw stderr is not stored unbounded or returned directly to the UI.

## Symbol and network policy

Kairon does not initiate automatic symbol downloads. `MEMORY_SYMBOL_NETWORK_ACCESS_ENABLED=false` by default. If symbols are unavailable, the run fails safely with a sanitized requirements error and does not retry indefinitely.

## Storage policy

Raw plugin output is stored under the isolated evidence run directory:

```text
data/evidence/{case_id}/{evidence_id}/memory/runs/{run_id}/
```

Database rows store relative paths, SHA-256 hashes, sizes, and status metadata. Normalized metadata is indexed only into `dfir-memory-{case_id}`. The existing disk events index is not written by the memory runner.

## Logging redaction

Logs may include run ID, case ID, evidence ID, backend, plugin, state transition, duration, row count, and sanitized error code. Logs must not include raw memory contents, full command lines with evidence paths, environment variables, credentials, raw plugin JSON, or unbounded stdout/stderr.

## Known limitations

- Only `windows.info` is supported.
- MemProcFS execution is not implemented.
- No process, network, registry, credential, malware, file, string, injection, YARA, or hybrid-correlation analysis is implemented.
- Real execution requires an administrator-installed Volatility 3 environment and authorized lab evidence.
