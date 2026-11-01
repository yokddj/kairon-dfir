# Large Evidence

## Intake Modes

- `RAW evidence`
- `Parsed evidence`
- `Server-mounted path`

Recommended packaging:

- `Single file`
- `Compressed archive ZIP/TAR/7z`
- `File or directory path` when the evidence is already mounted on the server

For large folders or full extractions:

- select the folder in the evidence wizard (it is packed into one ZIP in the browser
  and sent in resumable chunks, see below)
- or compress the folder to `ZIP/TAR/7z`
- or use `Server-mounted path`

Detection of the specific tooling is automatic. The user does not need to choose whether the archive came from a particular tool.

Common cases:

- a loose `.evtx` file -> `RAW evidence` as `Windows Event Log`
- a ZIP with several `.evtx` files -> `RAW evidence` as a raw collection
- already-structured `CSV/JSON/JSONL` -> `Parsed evidence`
- a large folder or NAS share -> `Server-mounted path`

## Browser Path vs. Server-Mounted Path

The app cannot read paths from the machine you're browsing from just because they exist there.

Examples that do **not** work by themselves:

- `C:\Users\analyst\Desktop\Evidence`
- `/home/user/Evidence`
- `/opt/evidence`

Those paths only work if:

- you do an `Upload file` from the browser, or
- you mount/share that folder on the server under an allowed root.

## `copy_to_storage`

- `true`: copies the evidence into the case's internal storage.
- `false`: keeps a reference to the server-mounted path and avoids duplicating data.

For large evidence, `copy_to_storage=false` is usually preferable when the mounted path is stable and secure.

## Allowed Roots

Host-path import must only use paths under:

- `/mnt/evidence`
- `/data/evidence`
- `/cases`

or the paths configured in `DFIR_ALLOWED_EVIDENCE_ROOTS`.

## Server-Mounted Path Validation

The app validates:

- that the root is allowed
- that the path exists
- that it does not escape via symlink or path traversal
- that the initial sampling does not exceed reasonable limits
- whether it looks like a client-side path (`C:\...`, `/home/user/...`, `\\server\share`, etc.)

## Why Doesn't My Local Path Work?

Because the backend and worker run in Docker or on a remote server.

Solutions:

- use `Upload file` to upload from the browser
- mount the folder on the server, for example:
  - Docker/Linux: `/host/evidence:/mnt/evidence:ro`
  - Windows Docker Desktop: share `C:\Evidence` and mount it as `/mnt/evidence`
  - NAS: mount the share on the server at `/mnt/evidence`
- then register the server's path, not your laptop/desktop's path

## Browser Folder Upload

The evidence wizard's **Select Folder** packs the folder into one uncompressed ZIP in
the browser (`frontend/src/lib/folderZip.ts`, ZIP64 when it passes 4 GB or 65,535
files) and sends it through the same resumable upload as any archive: 64 MB chunks,
retries, preflight. Nothing is copied in the browser; each file is read once to
compute its CRC-32 and again as its chunk is sent. On the server it is an ordinary
ZIP whose root is the folder, so it has no request-size or file-count limit.

The older multipart folder routes (`POST /api/cases/{id}/evidences/upload-folder`,
the Velociraptor folder discovery) still send every file in one request and stay
behind `BACKEND_ENABLE_EXPERIMENTAL_FOLDER_UPLOAD` with their file-count and size
limits.

An interrupted folder upload survives a page reload, within that limit: the browser
cannot reopen the folder by itself, so the analyst has to select it again from
the **Resume upload** step (a folder picker, not a single-file one, for a session
packed from a folder). Kairon re-packs it (fast, local I/O: no compression, just
reading each file once for its CRC-32) and reuses the same upload session by
filename and size, so none of the bytes the server already received are sent
again over the network -- only re-selecting the folder and re-packing it locally
cannot be avoided.

## What Is and Isn't Deleted When Removing Evidence

- If the evidence was copied to internal storage, the case tree can be cleaned up.
- If it was a mounted path with `copy_to_storage=false`, the app must not delete the original external path.

## Disk Space Issues

If the host is tight on disk:

- use mounted evidence
- avoid duplicate copies
- reduce unnecessary extraction
- check `Performance & Resources`
- export the debug pack with a reduced scope, not for the full case unless needed

## Practical Recommendations

- use `RAW evidence` for data that still needs parsing
- use `Parsed evidence` for CSV, JSONL, timeline exports, or other already-structured outputs
- for large collections, prefer `server-mounted path`
- keep evidence on SSD/NVMe if you'll iterate heavily on Search or scoped YARA
- do not launch a full YARA scan over huge shares without selected paths
- if you only need one family, use reduced scopes and evidence/host filters

## Reprocessing Large Raw Evidence

For raw archives and mounted raw collections, the recommended reprocess mode is `Use previous parser selection`. This keeps the ingest reproducible and avoids parsing newly discovered files unless the analyst explicitly chooses to do so.

Use `Refresh discovery and keep previous selection` when the archive or mounted directory changed and you want to review new, missing or changed candidates before reprocessing.

Use `Full rediscovery` only when parser coverage changed or when you intentionally want a new parsing plan.
