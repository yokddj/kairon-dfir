# Preflight Inspection

## What it is

A read-only inspection of evidence before any processing starts. It
classifies the evidence, previews the exact pipeline Kairon is about to
run, estimates the resources that pipeline will need, and — if something
would fail — explains what, why, and exactly how to fix it, instead of a
generic error.

Endpoint: `POST /api/cases/{case_id}/evidence-preflight`
(`backend/app/api/routes_evidence_preflight.py`). Service:
`backend/app/services/evidence_preflight.py` (`run_preflight`).

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

Category chain (e.g. Archive → Linux), platform, hostname, distro/version
(archives and disk images only), volume/installation counts (disk images
only), confidence, and the list of expected parsers matched against the
evidence's actual contents (not just "what this platform generally
supports").

### Processing Pipeline Preview

The exact sequence of stages the real ingestion will run, so the
investigator knows what's about to happen before it happens. The sequence
differs by category — a disk image walks through Volume Discovery before
platform-specific discovery; an archive skips straight to it.

### Preflight Resource Check

File size, estimated extracted/temporary/final size, a rough processing
time estimate, expected artifact count, and every configured limit that
could block ingestion: upload size, extraction size, archive nesting
depth, and virtual-disk backing chain depth, alongside how much is
actually available right now (disk space).

The processing-time estimate is a documented heuristic (a fixed assumed
throughput), not a measured benchmark — no historical timing table exists
to draw from yet.

### Status and diagnostics

Each check (`Supported`, `Within upload limit`, `Enough storage`, `Within
extraction limit`, `Within nested archive depth`, `Within virtual disk
chain limit`) is shown with a plain ✔/⚠ and a one-line detail. When a check
fails, a matching diagnostic explains the problem, the reason, the exact
configuration key and file involved, and concrete steps to fix it — for
example:

```
Upload limit exceeded
The selected file (64.0 GB) is larger than the configured upload limit (20.0 GB).
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

## Known limitations

- Nested-archive depth detection is a bounded, best-effort scan: it reads
  inner archives into memory to check for further nesting, but skips
  archives above 200 MB (counted as "at least one more level," not
  precisely measured) to keep the inspection lightweight.
- The processing-time estimate is a heuristic, not a measured figure.
- Windows-specific pre-ingestion hostname detection (equivalent to the
  Linux `/etc/hostname` peek) is not implemented — Windows disk images
  still get hostname/version from `OSInstallation` detection during volume
  discovery, but Windows *archives* do not get a pre-extraction hostname
  guess the way Linux archives do.
