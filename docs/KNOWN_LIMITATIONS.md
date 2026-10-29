# Known Limitations

This document describes current known limitations. It is intentionally explicit so users do not mistake missing tooling for failed evidence.

## Parser / Artifact Coverage

- SRUM is detected, but raw SRUM parsing on Linux is `tooling_missing` because `SrumECmd` requires Windows ESE libraries. A Windows parser worker is planned.
- Shellbags: `SBECmd_Output.csv` (parsed CSV) is supported and indexed. Direct parsing of raw `NTUSER.DAT`/`UsrClass.dat` hives is not implemented; detected raw hives surface as discovery-only.
- Outlook/OST/PST and rich email-message parsing are pending. Current email-related analysis is based on filesystem, browser, MFT, MOTW and user-activity evidence that is already indexed.
- PECmd is available, but raw Prefetch parsing with PECmd is disabled on Linux when Windows decompression support is required. The internal Prefetch backend remains active.
- EZ Tools for LNK, Jumplist, Amcache and Shimcache are advanced rebuild backends, not default activation for every case.

## Linux

- Coverage is partial: not every log format is parsed, ext4 is not parsed natively, binary journals are read without checking their checksums or sealing, and macOS collections are not parsed. The full list is in [linux/linux-support.md](linux/linux-support.md#limitations).
- Cases ingested before a parser existed need their Linux evidence reprocessed to benefit from it.

## Memory Analysis

- Volatility and MemProcFS execution is off until enabled per deployment ([memory/memory_operations.md](memory/memory_operations.md)).
- Linux images need a symbol file for the exact kernel (Volatility 3 ISF or Volatility 2 profile); Windows symbols come from a local cache or an operator-approved download.
- Windows-only views (DLLs, drivers, VADs, MemProcFS) have no Linux equivalent.
- Detections and SIEM export do not read memory results.
- PSReadLine history and PowerShell 4104/4103 records recovered from memory have not been validated on an image that contains them.
- Running Kairon with Memory disabled (`memory_enabled=false`) is possible but not a tested configuration.

## AI assistant

- Off until an administrator configures a model provider. With a hosted provider, the question, the case briefing and every tool result leave the deployment; a local provider keeps them in the lab. See [operations/ai-assistant.md](operations/ai-assistant.md).
- Its answers are not evidence: lookups are capped (rows, characters, rounds), so it works from samples.

## Users and access

- Two roles (Administrator, Standard user). Every user with platform access sees every case: per-case access control is not enabled and multi-tenant isolation is not designed.

## Search / Timeline

- Search is the primary exploration workspace. Search Timeline is a filtered view of matching events over time.
- Incident Timeline is curated/reportable. Suggested candidates are not included in reports unless accepted or explicitly selected.
- MFT full indexing can add hundreds of thousands of documents. MFT is not included in broad timeline views by default to avoid flooding.

## Detections

- Detections are analyst-triggered, not a background scan. Sigma smoke tests are intentionally scoped; full rule-pack execution is manual.
- Detections and risk scores assist triage; they do not replace analyst validation.

## Deployment

- Kairon DFIR should run behind VPN, private network or authenticated reverse proxy.
- The app does not provide a complete public-facing security boundary by itself.
- Backups cover the database, configuration and (full backups) the application data; the search indexes are not backed up and are rebuilt by reprocessing evidence. OpenSearch snapshots are recommended for larger deployments. See [Backup and Restore](deployment/backup-restore.md).

