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

The standard remote validation target is `MEMORY_UPLOAD_MAX_BYTES=5368709120`, displayed as `5 GiB`. Capacity is grouped by filesystem device:

- same-filesystem finalization requires one input image, output allowance, and one safety margin before upload
- after that input is staged, atomic finalization requires only the remaining output allowance and safety margin
- cross-filesystem finalization checks staging, final-copy, and output requirements independently on their respective filesystems

The previous implementation counted two complete input images against a single free-space value and repeated that pre-upload formula after staging was complete. A valid readiness decision could therefore fail at finalization solely because the controlled staging file had consumed space. The phase-aware model removes that double count.

## Streaming Behavior

The backend streams memory uploads to disk in bounded chunks:

- configured by `MEMORY_UPLOAD_CHUNK_SIZE_BYTES`
- staged under `MEMORY_UPLOAD_STAGING_ROOT` or backend temp storage
- SHA-256 and byte count are calculated incrementally
- `MEMORY_UPLOAD_MAX_BYTES` is enforced while receiving data
- completed files are atomically moved when staging and canonical storage share a filesystem
- cross-filesystem files are copied to a controlled destination temporary, size/hash verified, then atomically renamed on the destination filesystem
- failed or oversized uploads remove only the known temporary partial file
- one Redis-backed upload slot serializes large memory uploads across backend replicas and expires safely if an uploader disappears

The database evidence row is created only after storage finalization succeeds. Incomplete uploads are not valid scannable evidence.

## Storage Layout

Uploaded memory evidence is stored under the normal evidence storage tree using a server-controlled filename. API/UI callers cannot provide evidence paths, output paths, executable paths, plugins, or command arguments.

The optional `memory-worker` mounts canonical evidence storage read-only and writes only to approved memory output storage.
