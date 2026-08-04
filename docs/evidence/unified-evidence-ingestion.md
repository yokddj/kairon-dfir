# Unified Evidence Ingestion

## What this is

A single guided wizard for adding evidence to a case, replacing the need to
understand Kairon's internal ingestion pipeline before uploading anything.
The wizard does not change how evidence is actually processed — it exposes
the existing, mature pipeline (EvidenceClassifier, Platform Registry,
Artifact Registry, ImageFormatRegistry, DiskImageService, volume/OS
discovery, host assignment, processing queue) through a small set of
plain-language questions, and only asks what Kairon cannot determine
automatically.

## The seven steps

0. **Server Health Check** (new — see below) — a read-only readiness probe
   over Storage, Search, Database, Workers, and the Memory Worker, plus
   available disk space and the configured upload/extraction limits.
   Continuing is blocked only if a *critical* dependency (Storage or
   Database) is down; a non-critical outage (Search, Workers) is shown as a
   warning but does not block the wizard.
1. **What are you adding?** — Disk Image, Memory Dump, Artifact Collection,
   Folder, or Existing Server Path. Each card lists example formats.
2. **Platform** — Auto Detect (recommended), Windows, Linux, macOS
   (coming soon), or Unknown/Other. Auto Detect lets the next step's
   classification decide.
3. **Host** — Auto Assign, assign an existing case host, or create a new
   one. Reuses the same host list and creation flow as the rest of the app.
4. **Choose evidence** — a single upload flow for every supported format.
   There is no separate "memory upload" vs "evidence upload" choice; the
   backend already routes memory images through the same endpoint as
   everything else, keyed off the file extension. As soon as a single file
   is selected, Kairon starts computing its SHA-256 client-side, in chunks,
   showing "Calculating SHA-256... NN%" — see
   [Client-side SHA-256](#client-side-sha-256) below.
5. **Preflight Inspection** (see
   [docs/preflight-inspection.md](preflight-inspection.md)).
6. **Confirmation** — a plain-language summary, gated behind Preflight
   passing (or an explicit manual override), with an explicit
   **Start Processing** action. Nothing is processed before this step.

Advanced options (labels, evidence notes) are collapsed by default under
Step 5.

## Where the wizard lives

`frontend/src/components/EvidenceIngestionWizard.tsx`, opened from an
"Add Evidence" button on the Case Detail overview tab
(`frontend/src/pages/CaseDetail.tsx`). The previous detailed upload form
(`EvidenceUpload.tsx` — Velociraptor candidate selection, EVTX profile
choice, raw folder discovery) remains available underneath a collapsed
"Advanced upload" section for flows the wizard does not yet cover one-to-one.

## Temporary Upload Session: one upload, not two

Evidence is uploaded to the server **exactly once**. Selecting a file (or
folder, or server path) at Step 4 creates a `EvidenceUploadSession` —
`POST /api/cases/{case_id}/evidence-uploads` — which stages the bytes in a
disposable server-side location, computes their SHA-256 once, and runs
Preflight Inspection against that staged copy. When the analyst confirms
**Start Processing**, `POST /api/cases/{case_id}/evidence-uploads/{id}/promote`
reuses the already-staged file — via an in-process `UploadFile` wrapping the
local staged path, moved (not copied) into evidence storage with
`os.replace()` — instead of asking the browser to send the bytes again. See
[docs/preflight-inspection.md#temporary-upload-session](preflight-inspection.md#temporary-upload-session)
for the full lifecycle, expiry, and cleanup guarantees.

This replaced the original design, where Preflight and Start
Processing were two independent HTTP requests and large evidence was sent
over the network twice. That two-request design is why the wizard used to
call the real, unmodified upload endpoints
(`POST /cases/{id}/evidences/upload`, `/disk-images/upload`,
`/evidences/upload` with `folder_upload=true`,
`/cases/{id}/evidences/register-path`) directly a second time at
Confirmation; those endpoints are still exactly what promotion calls under
the hood — just now with the staged bytes, not a fresh upload.

## Client-side SHA-256

`frontend/src/lib/sha256.ts` implements an incremental (chunked) SHA-256
hasher so the wizard can hash a selected file without loading the whole
file into memory at once (`SubtleCrypto.digest()` only accepts one complete
buffer, which does not scale to 100+ GB evidence). The hash is sent to
`evidence-uploads` as `client_sha256`; the server compares it against the
hash it computed while staging the same bytes and flags
`client_sha256_mismatch` on the session if they disagree — surfaced as a
warning banner on the Preflight Inspection step. The hash is **not**
recomputed anywhere else in the flow.

Multi-file selections (folders, and multi-segment disk images such as
split `.E01`/`.E02` images) are not client-hashed — there is no single
"the file" to hash meaningfully client-side for those cases.
