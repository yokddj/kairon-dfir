# Preflight Inspection

## What it is

A read-only inspection of evidence before any processing starts. It
classifies the evidence, previews the exact pipeline Kairon is about to
run, estimates the resources that pipeline will need, and — if something
would fail — explains what, why, and exactly how to fix it, instead of a
generic error.

Service: `backend/app/services/evidence_preflight.py` (`run_preflight`).
Preflight itself never touches the network or the database; it always runs
against an already-staged local file/folder, supplied by the Temporary
Upload Session described below.

## Guarantees

Preflight Inspection:

- **never** creates an `Evidence`, `Artifact`, `DiskImage`, `DiskVolume`, or
  `OSInstallation` row;
- **never** calls `enqueue_ingest` or otherwise starts a worker job;
- **never** writes outside of a disposable temp directory it removes
  itself once the inspection finishes (success or failure).

The service module imports no SQLAlchemy `Session` at all — there is no
code path in it that could touch the database, by construction rather than
by convention.

## Temporary Upload Session

`backend/app/services/evidence_upload_session.py`
(`EvidenceUploadSession` model, `backend/app/models/evidence_upload_session.py`).
Endpoints, all under `backend/app/api/routes_evidence_preflight.py`:

| Endpoint | Purpose |
| --- | --- |
| `GET /api/cases/{case_id}/ingestion-readiness` | Server Health Check (Step 0 below) |
| `POST /api/cases/{case_id}/evidence-uploads` | Stage a file/folder/server path once, run Preflight against it, return `{session, preflight, health}` |
| `POST /api/cases/{case_id}/evidence-uploads/{id}/preflight` | Re-run Preflight against the already-staged copy (e.g. after a platform override) — no re-upload |
| `POST /api/cases/{case_id}/evidence-uploads/{id}/promote` | Confirm processing: reuses the staged bytes to call the real, unmodified upload route (`upload_evidence` / `upload_disk_image` / `upload_evidence_folder` / `register_evidence_path`) |
| `DELETE /api/cases/{case_id}/evidence-uploads/{id}` | Cancel: deletes the staged copy immediately |

Guarantees:

- A staged session **never** creates an `Evidence` row and **never**
  enqueues a worker job — only `promote` does either, and only after
  explicit analyst confirmation.
- Sessions expire automatically (`EVIDENCE_UPLOAD_SESSION_TTL_SECONDS`,
  default 7200s) and are swept by
  `app.services.evidence_operations.reconcile_evidence_operations` (run on
  every Activity Center fetch and at startup) — not by a dedicated function
  in this module.
- Cancelling a session deletes its staged copy immediately; nothing is left
  behind on disk.
- A server-path session (`is_server_path=True`) never deletes the
  analyst's original file — staging just validates and records the path;
  there is nothing to stage or clean up.
- Promotion is a **zero-copy move**, not a second upload: `promote` wraps
  the already-staged local file in an in-process `UploadFile` and calls the
  target upload route directly. `app.core.storage.save_upload()` detects
  the staged file (via a `_preflight_known_sha256`/`_preflight_staged_path`
  marker) and does an atomic `os.replace()` instead of re-reading,
  re-hashing, and re-writing the bytes. This is the mechanism that
  eliminates the double-upload for single-file evidence (disk images,
  memory dumps, archives) — the largest and most time-sensitive case.
  Folder uploads and multi-segment disk images (split `.E01`/`.001` sets)
  still avoid the network retransmission (the bytes never leave the local
  disk a second time) but do not get the zero-copy/no-rehash optimization,
  since the underlying `upload_evidence_folder` /
  multi-segment `save_segmented_uploads()` routes were not changed — a
  deliberate, documented scope limit rather than an oversight.
- Multi-segment disk images (e.g. `.E01`/`.E02`/...) stage the *first*
  segment for Preflight preview (matching this wizard's historical
  "preview the first segment" behavior) and stage the remaining segments as
  siblings; promotion passes the **complete, ordered segment set** to
  `upload_disk_image` — segments 2..N are never dropped.

## Server Health Check (Step 0)

`backend/app/services/ingestion_health.py` (`check_ingestion_readiness`).
Reuses `app.services.task_registry.build_task_health_snapshot()` for
worker/queue detection instead of a second worker-health mechanism. Checks:
Storage (temp directory writable + free space), Search (OpenSearch cluster
health), Database (`SELECT 1`), Workers (active worker on the
ingest/rules/analysis queues), Memory Worker (active worker on the memory
queue). `critical_ready` is true only when Storage and Database are both
reachable — that's the bar for blocking the wizard from proceeding, since
nothing can be staged or recorded without them. A Search or Workers outage
is surfaced as a warning (queued jobs will simply wait) rather than a hard
block.

## How it reuses the existing pipeline

Preflight does not reimplement classification or discovery. It calls the
same components the real ingestion pipeline uses, just stops short of the
steps that persist anything:

| Preflight step | Reused component |
| --- | --- |
| Category detection (archive / disk image / memory dump / unknown) | `app.ingest.evidence_classifier.EvidenceClassifier` |
| Archive/folder listing | `app.ingest.velociraptor.zip_inventory.open_evidence_container` (same container abstraction the real upload route uses for ZIP, 7z/tar family, and folders) |
| Linux artifact matching | `app.ingest.linux.helpers.looks_like_linux_artifact` + `app.ingest.linux.discovery.build_linux_inventory` (hostname/distro read directly from the few small candidate files inside the archive, without a full extraction) |
| Disk image format detection, volume discovery, OS installation detection | `app.disk_images.service.inspect_disk_image_readonly` — a new, additive, read-only wrapper that mirrors the first half of `materialize_disk_image_sources` (detect → validate_segments → inspect → expose_readonly → `_discover_raw_volumes`) and always cleans up its workspace, but stops before `upsert_disk_image_record`/`DiskVolume`/`OSInstallation` persistence |
| Backing-chain depth | `adapter.validate_segments()` — the same chain-depth enforcement QCOW/VMDK/VHD already run during real ingestion; preflight reads the depth off a failed validation rather than recomputing it |
| Expected artifact registry entries | `app.core.artifact_registry.artifact_registry_entries` |

Nothing about `EvidenceClassifier`, the Platform Registry, the Artifact
Registry, `ImageFormatRegistry`, `DiskImageService`, volume/OS discovery,
host assignment, or the processing queue was redesigned for this feature.

## Report sections

### Evidence Classification

Evidence type, **Container** (e.g. "ZIP archive", "RAW disk image"),
**Contained object** (a short human summary — e.g. "Ubuntu 24.04 LTS
artifact collection (12 matched file(s))", "1 OS installation(s) across 2
volume(s)"), category chain (e.g. Archive → Linux), platform, hostname,
distro/version (archives and disk images only), **Volumes**,
**Partitions**, **Filesystems** (disk images only), installation counts,
confidence, expected artifact families, and warnings — each warning tagged
**Information** or **Recommendation** severity (`PreflightWarning.severity`)
rather than a flat, undifferentiated list.

### Processing Pipeline Preview

The exact sequence of stages the real ingestion will run, so the
investigator knows what's about to happen before it happens. The sequence
differs by category — a disk image walks through Volume Discovery before
platform-specific discovery; an archive skips straight to it.

### Preflight Resource Check

File size, estimated extracted/temporary/final size ("Estimated disk
usage" / "Estimated temporary storage" in the UI), expected artifact count,
and every configured limit that could block ingestion: upload size,
extraction size, archive nesting depth, and virtual-disk backing chain
depth, alongside how much is actually available right now (disk space).

**Estimated duration** is shown as one of four honest buckets — Fast
(under 2 minutes), Medium (10–20 minutes), Long (1–2 hours), Very long
(several hours) — computed from the same throughput heuristic as before
(`estimated_duration_bucket` in `PreflightResourceCheck`), rather than a
falsely precise number of seconds or a fake progress bar. No historical
timing table exists to draw from yet, so the bucket is a documented,
conservative heuristic.

### Status and diagnostics

Each check (`Supported`, `Within upload limit`, `Enough storage`, `Within
extraction limit`, `Within nested archive depth`, `Within virtual disk
chain limit`) is shown with a plain ✔/⚠ and a one-line detail. When a check
fails, a matching diagnostic explains the problem, the reason, and — for
configuration-driven limits — the exact configuration key, file, current
value, required value, and concrete steps to fix it. Each diagnostic also
carries a `severity`: `blocking` (upload/storage/extraction/depth limits —
processing cannot proceed) or `recommendation` (low-confidence
classification — overridable), rendered distinctly in the wizard rather
than as uniform red boxes. For example:

```
Blocking: Upload limit exceeded
The selected file (64.0 GB) is larger than the configured upload limit (20.0 GB).
Current value: 20.0 GB
Required value: at least 64.0 GB
Configuration key: BACKEND_MAX_UPLOAD_SIZE
Configuration file: backend/.env
1. Edit backend/.env
2. Increase BACKEND_MAX_UPLOAD_SIZE to at least 68719476736 bytes
3. Run ./scripts/upgrade.sh
```

A low-confidence or unsupported classification is not a hard failure by
itself — the report offers a manual override checkbox instead of blocking
outright, since the investigator may still know what the evidence is even
when Kairon's classifier does not.

## Memory Overview projection

Memory Overview's own upload page (`/cases/{case_id}/memory/upload`) creates
sessions through `POST /cases/{case_id}/memory/uploads`, a separate entry
point from the Evidence Wizard. As of the architecture-consolidation phase,
this endpoint also creates the same `EvidenceUploadSession`/
`EvidenceOperation` projection the Wizard's unified sessions get (via the
same `create_unified_upload_session` used by
`routes_evidence_preflight.init_resumable_evidence_upload` — not a second
projection mechanism), so these uploads are now visible in Activity Center
and, in principle, discoverable through the same
`list_resumable_upload_sessions` API the Wizard's resume panel uses.
Registration continues to run through the plain `"memory"` workflow handler
(`register_memory_evidence_from_upload`), never the Wizard-only
`"evidence_memory_dump"` handler, which layers Wizard-specific concepts
(explicit case-host override, notes) this page has no UI to populate.

**Compatibility strategy for sessions created before this change**:
explicit non-migration. A `MemoryUpload` row created before this deployment
has no projection and never gets one retroactively — it continues to be
served exactly as before by the page's own direct endpoints
(`GET /memory/uploads/active`, `GET /memory/uploads/{id}`, cancel, finalize),
which read the `MemoryUpload` table directly and were never changed. Such a
session simply will not appear in Activity Center or the Wizard's resume
panel; once it completes, cancels, or expires (all unaffected, existing
mechanisms), the gap closes itself. No retrofit, no risk of a duplicate
`Evidence` row, no orphaned session.

## Known limitations

- Nested-archive depth detection is a bounded, best-effort scan: it reads
  inner archives into memory to check for further nesting, but skips
  archives above 200 MB (counted as "at least one more level," not
  precisely measured) to keep the inspection lightweight.
- The processing-duration estimate (and its bucket) is a heuristic, not a
  measured figure.
- Windows-specific pre-ingestion hostname detection (equivalent to the
  Linux `/etc/hostname` peek) is not implemented — Windows disk images
  still get hostname/version from `OSInstallation` detection during volume
  discovery, but Windows *archives* do not get a pre-extraction hostname
  guess the way Linux archives do.
- Folder uploads and multi-segment disk images do not get the zero-copy
  local promotion optimization (see above) — only the network
  retransmission is eliminated for those, not the local re-hash/re-copy.
