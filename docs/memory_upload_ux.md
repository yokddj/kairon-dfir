# Dedicated Memory Image Upload UX

The recommended memory evidence workflow is:

```text
Case -> Memory Analysis -> Add memory image
```

The generic Evidence Upload form still accepts memory images for backward compatibility, but it points users to the dedicated Memory Upload page for the clearest experience.

## User Flow

1. Open a case.
2. Go to Memory Analysis.
3. Select Add memory image.
4. Review upload readiness and analysis readiness.
5. Select an authorized memory image.
6. Confirm the privacy and authorization acknowledgement.
7. Upload with progress and finalization status.
8. Open Memory Analysis for the uploaded evidence.
9. Start `metadata_only`, `processes_basic`, or `processes_extended` only when analysis is enabled and authorized.

Memory upload and memory analysis are separate steps. Upload may be available while execution is disabled or while the dedicated memory worker is offline.

## Displayed Limits

The UI displays the configured maximum memory upload size. The standard remote validation target is:

- `MEMORY_UPLOAD_MAX_BYTES=5368709120`
- displayed as `5 GiB`

The practical maximum also depends on server storage. The upload readiness check reports safe capacity numbers only; it does not expose host paths, mount names, or internal directories.

For a selected file, Kairon requires enough available capacity for staging, final evidence storage, output allowance, and a safety margin. Near the 5 GiB limit, operators should keep at least 12 GiB free.

## Privacy

The dedicated upload page shows this warning:

> Memory images may contain credentials, personal data, encryption material, browser data, access tokens, and other sensitive information. Upload only evidence that you own or are explicitly authorized to analyze.

The user must acknowledge that they own the memory image or are explicitly authorized to upload and analyze it. This acknowledgement is operational audit context; it is not a legal guarantee.

## Isolation

Uploaded RAM evidence is registered as `memory_dump`, bypasses normal disk ingest, and does not create `NormalizedEvent` rows or disk event-index documents. Memory results remain in the isolated Memory Analysis workspace and memory index only.

Do not commit RAM images, symbols, real Volatility output, credentials, malware samples, screenshots containing evidence, or server-private configuration.
