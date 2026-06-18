# Memory Upload

Kairon supports standard browser upload for authorized Windows memory images when an administrator enables `MEMORY_UPLOAD_ENABLED=true`.

Supported default extensions:

- `.raw`
- `.mem`
- `.vmem`
- `.dmp`
- `.lime`

`.aff4` is not enabled by default because container semantics must be reviewed for the deployment before accepting it as a direct memory image upload.

## Safety Model

Memory images may contain credentials, personal data, encryption material, browser data, messages, tokens, and other sensitive information. Upload only evidence you own or are explicitly authorized to analyze. Do not commit RAM images or real plugin output to Git.

Memory uploads are classified as `memory_dump`, bypass normal disk ingest, and do not create `NormalizedEvent` rows or disk event-index documents. Results remain isolated in Memory Analysis.

## Streaming Behavior

The backend streams memory uploads to disk in bounded chunks:

- configured by `MEMORY_UPLOAD_CHUNK_SIZE_BYTES`
- staged under `MEMORY_UPLOAD_STAGING_ROOT` or backend temp storage
- SHA-256 and byte count are calculated incrementally
- `MEMORY_UPLOAD_MAX_BYTES` is enforced while receiving data
- completed files are atomically moved into canonical evidence storage
- failed or oversized uploads remove only the known temporary partial file

The database evidence row is created only after storage finalization succeeds. Incomplete uploads are not valid scannable evidence.

## Storage Layout

Uploaded memory evidence is stored under the normal evidence storage tree using a server-controlled filename. API/UI callers cannot provide evidence paths, output paths, executable paths, plugins, or command arguments.

The optional `memory-worker` mounts canonical evidence storage read-only and writes only to approved memory output storage.

