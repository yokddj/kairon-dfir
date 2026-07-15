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

## The six steps

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
   everything else, keyed off the file extension.
5. **Preflight Inspection** (new — see below).
6. **Confirmation** — a plain-language summary, gated behind Preflight
   passing (or an explicit manual override), with an explicit
   **Start Processing** action. Nothing is processed before this step.

Advanced options (platform override, classification override, labels,
evidence notes) are collapsed by default under Step 5.

## Where the wizard lives

`frontend/src/components/EvidenceIngestionWizard.tsx`, opened from an
"Add Evidence" button on the Case Detail overview tab
(`frontend/src/pages/CaseDetail.tsx`). The previous detailed upload form
(`EvidenceUpload.tsx` — Velociraptor candidate selection, EVTX profile
choice, raw folder discovery) remains available underneath a collapsed
"Advanced upload" section for flows the wizard does not yet cover one-to-one.

## What happens after "Start Processing"

The wizard calls the same, unmodified upload endpoints that existed before
this feature (`POST /cases/{id}/evidences/upload`,
`/disk-images/upload`, `/evidences/upload` with `folder_upload=true`, or
`POST /cases/{id}/evidences/register-path` for an existing server path).
Evidence-row creation, ingest enqueueing, and everything after it are
completely unchanged. See [docs/preflight-inspection.md](preflight-inspection.md)
for what happens *before* that point.

## Design decision: two network round-trips for large files

Preflight Inspection and "Start Processing" are two separate requests to
the backend. For a disk image or large archive, this means the file's
bytes may be sent to the server twice — once staged for inspection, once
for real ingestion. This was a deliberate choice: the alternative would
require refactoring the existing, security-critical upload routes in
`backend/app/api/routes_evidence.py` to split "receive bytes" from "create
Evidence row and enqueue," which the ingestion architecture explicitly asks
agents not to redesign. Preflight staging lives in an entirely separate,
DB-free module instead, at the cost of a second upload for the confirmed
case.
