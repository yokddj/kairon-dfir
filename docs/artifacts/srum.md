# SRUM

SRUM (`System Resource Usage Monitor`) data is usually stored in `SRUDB.dat` and can contain application/network/resource usage by user/SID and time.

## Current platform status

- SRUM source detection: works when `SRUDB.dat` / related files are present.
- Parser status on Linux: `tooling_missing`.
- SrumECmd: installed, but requires Windows ESE libraries and does not run successfully in the current Linux backend.
- Indexed SRUM docs: none unless a parsed compatible source is provided by another workflow.
- Artifact View: should show a clear tooling-missing/no-data state, not failure.

## What SRUM would provide when a backend is available

- application usage
- network bytes sent/received by application/table
- user SID and best-effort user resolution
- timestamps for timeline correlation
- app/path context for suspicious binaries

SRUM does not usually provide exact destination IP/domain by itself. Treat it as application network usage context.

## Correct user-facing state

If `SRUDB.dat` is present but no Windows parser worker is configured:

> SRUM source detected, but this parser requires a Windows-capable worker.

This is not an evidence failure and should not change `investigation_ready`.

## Next action

Implement `SRUM Windows Worker Parser v1`:

- send SRUDB.dat and needed hives to a Windows worker
- run SrumECmd there
- return CSV/metadata/logs
- normalize output in the Linux backend

