# Memory Upload

Kairon supports browser upload for authorized Windows memory images when an administrator enables `MEMORY_UPLOAD_ENABLED=true`.

The recommended user workflow is:

```text
Case -> Memory Analysis -> Add memory image
```

The generic Evidence Upload form remains supported for backward compatibility, but it points users to the dedicated Memory Image upload page.

Supported default extensions:

- `.raw`
- `.mem`
- `.vmem`
- `.dmp`
- `.lime`

`.aff4` is not enabled by default because container semantics must be reviewed for the deployment before accepting it as a direct memory image upload.

## Safety Model

Memory images may contain credentials, personal data, encryption material, browser data, messages, tokens, and other sensitive information. Upload only evidence you own or are explicitly authorized to analyze. Do not commit RAM images or real plugin output to Git.

The dedicated Memory Upload page requires an authorization acknowledgement before upload:

```text
I confirm that I own this memory image or am explicitly authorized to upload and analyze it.
```

Memory uploads are classified as `memory_dump`, bypass normal disk ingest, and do not create `NormalizedEvent` rows or disk event-index documents. Results remain isolated in Memory Analysis.

## Upload Readiness

`GET /api/cases/{case_id}/memory/upload-readiness` reports a safe upload-capacity summary for the dedicated UI:

- upload enabled/disabled
- configured maximum bytes and display string
- allowed extensions
- available capacity values without host paths
- selected-size acceptance when `selected_size_bytes` is provided
- analysis readiness and dedicated worker status

The endpoint is informational. The upload endpoint remains authoritative and uses the same capacity service during pre-upload, streaming, and finalization.

Each accepted upload also has a durable lifecycle ID. After browser transport reaches 100%, the UI polls:

```text
GET /api/cases/{case_id}/memory/uploads/{upload_id}
```

The status record contains only sanitized state, byte counts, terminal failure category, and the evidence ID after completion. It allows completion to be recovered after a browser disconnect, backend response loss, or a successful file move followed by a database error. Safe reconciliation is idempotent and never overwrites when both staging and canonical files exist.

The standard remote validation target is `MEMORY_UPLOAD_MAX_BYTES=5368709120`, displayed as `5 GiB`. Capacity is grouped by filesystem device:

- same-filesystem finalization requires one input image, output allowance, and one safety margin before upload
- after that input is staged, atomic finalization requires only the remaining output allowance and safety margin
- cross-filesystem finalization checks staging, final-copy, and output requirements independently on their respective filesystems

The previous implementation counted two complete input images against a single free-space value and repeated that pre-upload formula after staging was complete. A valid readiness decision could therefore fail at finalization solely because the controlled staging file had consumed space. The phase-aware model removes that double count.

## Streaming Behavior

Hybrid upload mode is server-authoritative. `GET /api/cases/{case_id}/memory/upload-readiness?selected_size_bytes=...` returns `selected_upload_mode`, `direct_threshold_bytes`, `recommended_chunk_size_bytes`, `default_concurrency`, and `max_parallel_chunks`; the browser follows that policy instead of choosing silently.

Defaults for new sessions:

- `MEMORY_UPLOAD_DIRECT_THRESHOLD_BYTES=1073741824` (1 GiB)
- `MEMORY_UPLOAD_CHUNK_SIZE_BYTES=67108864` (64 MiB)
- `MEMORY_UPLOAD_DEFAULT_CONCURRENCY=2`
- `MEMORY_UPLOAD_MAX_CONCURRENCY=4`
- `MEMORY_UPLOAD_SESSION_TTL_HOURS=24`

Files at or below the direct threshold use one Safari-compatible `XMLHttpRequest` multipart `POST` to `/api/cases/{case_id}/memory/uploads/direct`. The request streams the `UploadFile`; failure before finalization leaves no completed Evidence and cleans direct staging.

Files above the direct threshold use resumable upload sessions. Existing sessions keep their persisted `chunk_size_bytes`; changing defaults affects only newly created sessions. New large sessions use 64 MiB chunks and default to two active chunk requests, bounding browser bytes in flight to roughly 128 MiB plus multipart overhead. The transport remains Safari-compatible: `XMLHttpRequest`, `multipart/form-data`, `FormData` field `chunk`, and HTTP 204 for successful chunk persistence.

The frontend scheduler is server-authoritative:

- fetch current session state before resume
- use `File.slice(start, end)` per missing chunk
- start at most `MEMORY_UPLOAD_DEFAULT_CONCURRENCY` chunks, capped by `MEMORY_UPLOAD_MAX_CONCURRENCY`
- retry failed chunk indices independently with bounded exponential backoff
- fall back to sequential for the current session after repeated transport failure
- never advance offset or progress for unacknowledged chunks
- abort active XHRs on pause/cancel

Progress for resumable uploads is aggregate and bounded:

```text
confirmed server bytes + sum(active unconfirmed chunk uploaded bytes) / total file size
```

Transient bytes are tracked per chunk index, reset for only the failed retrying chunk, and removed when the server acknowledges that chunk. Confirmed bytes always come from the server status, so pause/resume and page reload discard stale browser assumptions. Progress is clamped to 100% and does not count multipart framing overhead as evidence bytes. Direct upload progress remains the browser XHR progress for the single multipart request.

The backend streams memory uploads to disk in bounded chunks:

- configured by `MEMORY_UPLOAD_CHUNK_SIZE_BYTES`
- staged under `MEMORY_UPLOAD_STAGING_ROOT` or backend temp storage
- SHA-256 and byte count are calculated incrementally
- `MEMORY_UPLOAD_MAX_BYTES` is enforced while receiving data
- completed files are atomically moved when staging and canonical storage share a filesystem
- cross-filesystem files are copied to a controlled destination temporary, size/hash verified, then atomically renamed on the destination filesystem
- failed or oversized uploads remove only the known temporary partial file
- one Redis-backed upload slot serializes large memory uploads across backend replicas and expires safely if an uploader disappears
- Redis-backed per-session/chunk/finalize locks guard same-index writes, chunk/finalize races, duplicate finalization, cancellation, and cleanup. Different chunk indices can write concurrently; same-index requests serialize or return a clear conflict. Lock ownership is token-based so one request cannot release another request's lock, locks have bounded expiry for stale recovery, and production fails closed if Redis locking is unavailable. The in-process fallback is isolated to tests.
- verification and finalization have separate configurable warning/hard limits

The database evidence row is created only after storage finalization succeeds. Incomplete uploads are not valid scannable evidence.

Administrative helpers classify orphan states without destructive ambiguity: active sessions are skipped by cleanup; dry-run reports inspected sessions, orphan directories, reclaimable bytes, skipped active sessions, and errors before `apply` removes eligible terminal/orphan staging.

## Maintenance CLI

Run maintenance from the backend container or an equivalent backend environment:

```bash
python -m app.cli.memory_upload_maintenance cleanup --dry-run --json
python -m app.cli.memory_upload_maintenance cleanup --apply --case-id <case-uuid> --older-than-hours 24 --json
python -m app.cli.memory_upload_maintenance reconcile --dry-run --json
```

`cleanup` defaults to dry-run. `--apply` must be explicit. Supported filters include `--case-id`, `--upload-id`, `--older-than-hours`, and `--batch-size`. Output includes `sessions_inspected`, `active_sessions_skipped`, `expired_sessions`, `orphan_directories`, `missing_staging`, `completed_with_staging`, `bytes_reclaimable`, `bytes_removed`, `reconciliation_findings`, and `errors`. Non-empty operational errors return a non-zero exit code.

Cleanup never deletes completed Evidence. It may remove leftover staging for completed uploads after the canonical Evidence exists, and it skips active or locked uploads. Reconciliation is read-only and reports classifications such as DB session with missing staging, staging without DB row, completed upload missing Evidence, and chunk metadata/filesystem drift. Ambiguous repair is never automatic.

Production validation should run `cleanup --dry-run --json` and `reconcile --dry-run --json` only during first deployment validation. Do not apply cleanup to real data until dry-run output has been reviewed.

`Evidence.size_bytes` is stored as PostgreSQL `BIGINT`; browser memory uploads up to the configured 5 GiB limit must not be written to a 32-bit `INTEGER` column.

## Storage Layout

Uploaded memory evidence is stored under the normal evidence storage tree using a server-controlled filename. API/UI callers cannot provide evidence paths, output paths, executable paths, plugins, or command arguments.

The optional `memory-worker` mounts canonical evidence storage read-only and writes only to approved memory output storage.
