# Evidence Integrity & Chain of Custody

Kairon DFIR records basic integrity and traceability metadata for uploaded evidence. This is intended to support DFIR analysis workflows with a clear audit trail; it is not a substitute for formal legal chain-of-custody procedures, controlled acquisition tooling, signed evidence bags, notarization, or court-ready forensic proof.

## What Kairon Records

For each evidence item, Kairon records:

- SHA-256 hash when the evidence is uploaded or registered.
- Actual `size_bytes` observed by Kairon.
- Original filename shown to the analyst.
- Evidence type and detected type when available.
- Case id and optional host association.
- User id for the authenticated uploader when available.
- Upload timestamp.
- Processing status and last processed timestamp.
- Integrity status and last integrity check timestamp.
- Chain-of-custody events such as upload, hash computation, processing start/completion/failure, integrity checks, metadata updates, and manifest exports.

## SHA-256 Calculation

Kairon computes SHA-256 in streaming mode. Browser uploads are hashed while bytes are written to storage. Memory image uploads already use streaming hashing in their dedicated upload path. Kairon does not load large evidence files fully into memory for hashing.

Older evidence rows may have `sha256 = null` and `integrity_status = unknown`. They remain visible and usable; Kairon does not block old evidence solely because historical integrity metadata is missing.

## Integrity Status

`unknown`: Integrity has not been checked or no historical hash exists.

`verified`: The current stored file SHA-256 matches the recorded SHA-256.

`mismatch`: The current stored file hash differs from the recorded SHA-256.

`missing_file`: The evidence record exists but the stored file is missing.

`error`: Kairon could not complete the check, for example because the stored path is not a regular file or could not be read.

## Verifying Integrity

Use the Evidence detail view and click **Verify integrity**. Kairon recalculates SHA-256 from the stored evidence file, compares it with the saved hash, updates `integrity_status`, and records an `integrity_checked` custody event.

API endpoints:

- `GET /api/cases/{case_id}/evidence/{evidence_id}/integrity`
- `POST /api/cases/{case_id}/evidence/{evidence_id}/verify-integrity`
- `GET /api/cases/{case_id}/evidence/{evidence_id}/events`
- `GET /api/cases/{case_id}/evidence/{evidence_id}/manifest`

## Exporting a Manifest

Use **Export manifest** in the Evidence detail view or call the manifest endpoint. The manifest is JSON and intentionally omits absolute internal storage paths.

Example:

```json
{
  "case_id": "case-id",
  "evidence_id": "evidence-id",
  "original_filename": "collection.zip",
  "sha256": "...",
  "size_bytes": 123456,
  "evidence_type": "velociraptor_zip",
  "uploaded_by": "Analyst",
  "uploaded_at": "2026-07-10T12:00:00",
  "host": { "id": "host-id", "name": "HOSTA" },
  "integrity_status": "verified",
  "events": []
}
```

## Limits

Kairon integrity metadata confirms what Kairon stored and later re-read. It does not prove how evidence was acquired before upload, who controlled it outside Kairon, or whether external legal custody procedures were followed. Use this feature as a solid DFIR traceability baseline, not as standalone forensic-grade court proof.
