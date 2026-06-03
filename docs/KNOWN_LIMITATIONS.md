# Known Limitations

This document describes current private-beta limitations. It is intentionally explicit so beta testers do not mistake missing tooling for failed evidence.

## Parser / Artifact Coverage

- SRUM is detected, but raw SRUM parsing on Linux is `tooling_missing` because `SrumECmd` requires Windows ESE libraries. A Windows parser worker is planned.
- Shellbags parsing is pending a supported backend.
- Outlook/OST/PST and rich email-message parsing are pending. Current email-related analysis is based on filesystem, browser, MFT, MOTW and user-activity evidence that is already indexed.
- PECmd is available, but raw Prefetch parsing with PECmd is disabled on Linux when Windows decompression support is required. The internal Prefetch backend remains active.
- EZ Tools for LNK, Jumplist, Amcache and Shimcache are advanced rebuild backends, not default activation for every case.

## Search / Timeline

- Search is the primary exploration workspace. Search Timeline is a filtered view of matching events over time.
- Incident Timeline is curated/reportable. Suggested candidates are not included in reports unless accepted or explicitly selected.
- MFT full indexing can add hundreds of thousands of documents. MFT is not included in broad timeline views by default to avoid flooding.

## Detections

- Sigma smoke tests are intentionally scoped. Full rule-pack execution is manual.
- Detections and risk scores assist triage; they do not replace analyst validation.

## Deployment

- The private beta should run behind VPN, private network or authenticated reverse proxy.
- The app does not provide a complete public-facing security boundary by itself.
- Backups require PostgreSQL and application data at minimum. OpenSearch snapshots are recommended for larger deployments.

