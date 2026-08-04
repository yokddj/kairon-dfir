# Documentation Maintenance

## Goal

Documentation must change alongside the code. If the tool evolves and the documentation doesn't, it ends up worse than having no docs at all.

## When to Update Docs

Any time you add or change:

- a new parser
- a new evidence type
- a new endpoint
- a new frontend section
- a new builtin rule
- a new `event.type`
- a new normalized field
- a semi-automatic analysis section

## Which Documents to Review

- `docs/artifacts/parser-coverage.md` (canonical parser/artifact status matrix)
- `docs/artifacts/prefetch.md` if Prefetch / PECmd / native_prefetch changes
- `docs/artifacts/lnk.md` if LNK / LECmd / native_lnk changes
- `docs/artifacts/jumplists.md` if Jump Lists / JLECmd / raw automaticDestinations/customDestinations changes
- `docs/artifacts/registry.md` if Registry / RECmd changes
- `docs/artifacts/filesystem_mft_usn.md` if MFT / USN / MFTECmd changes
- `docs/artifacts/browser.md` if history / downloads / search terms change
- `docs/artifacts/execution_artifacts.md` if Amcache / ShimCache / AppCompat changes
- `docs/artifacts/srum.md` if SrumECmd / network usage / semi-auto network sections change
- `docs/artifacts/scheduled_tasks.md` if Task Scheduler XML/CSV, correlations, or persistence semi-auto sections change
- `docs/artifacts/defender.md` if DetectionHistory, MPLog, correlations, or remediation wording change
- `docs/artifacts/powershell_artifacts.md` if PSReadLine, transcripts, observed scripts, or PowerShell correlations change
- `docs/artifacts/recycle_bin.md` if RBCmd, `$I/$R`, correlations, or delete/cleanup semi-auto sections change
- `docs/artifacts/shellbags.md` if SBECmd, raw Shellbags detected from Velociraptor, correlations, or observed-folder semi-auto sections change
- `docs/artifacts/usb.md` if `setupapi.dev.log`, USB/Registry CSVs, removable-media correlations, or USB-copy hypotheses change
- `docs/artifacts/bits.md` if BITS, `qmgr` discovery, parsed CSV/JSON/TXT, notify commands, or PowerShell/Browser/Defender correlations change
- `docs/artifacts/cloud_sync.md` if cloud-provider detection, path inference, staging/exfiltration wording, or Browser/BITS/PowerShell correlations change
- `docs/evidence/velociraptor_ingest.md` if ZIP inventory, discovery, selective extraction, or collection staging changes
- `docs/search-and-investigation/semi_automatic_analysis.md`
- `docs/rules/builtin_rules.md`
- `docs/artifacts/wmi.md`
- `docs/rules/rule_authoring.md`
- `docs/search-and-investigation/app_sections.md`
- `docs/architecture/overview.md`
- `docs/operations/opensearch.md`
- `docs/operations/troubleshooting.md`
- `docs/roadmap.md`

## PR Checklist

- [ ] Added or changed a parser?
- [ ] Updated `docs/artifacts/parser-coverage.md`?
- [ ] Added a new `event.type`?
- [ ] Updated `semi_automatic_analysis.md`?
- [ ] Added a builtin rule?
- [ ] Updated `builtin_rules.md`?
- [ ] Changed the UI?
- [ ] Updated `app_sections.md`?
- [ ] Changed the OpenSearch mapping?
- [ ] Updated `opensearch.md` and `troubleshooting.md`?
- [ ] Added tests?
- [ ] Documented limitations?

## Practical Recommendation

When you change an analysis capability, ask three questions:

1. Where is it used in the UI?
2. What evidence does it consume?
3. What should an analyst check to validate that it works?

If you can't answer those by reading the documentation, the documentation isn't complete.

## Cross-Cutting Reminders

- Any expansion of `Autoruns / ASEP` should update `docs/artifacts/autoruns.md`, `docs/artifacts/parser-coverage.md`, `docs/search-and-investigation/semi_automatic_analysis.md`, and `docs/rules/builtin_rules.md`.
- Any expansion of `Cloud Sync` should update `docs/artifacts/cloud_sync.md`, `docs/artifacts/parser-coverage.md`, `docs/search-and-investigation/semi_automatic_analysis.md`, `docs/operations/troubleshooting.md`, and `docs/rules/builtin_rules.md`.
- Any expansion of `Network / WLAN / DNS` should update `docs/artifacts/network.md`, `docs/artifacts/parser-coverage.md`, `docs/search-and-investigation/semi_automatic_analysis.md`, `docs/operations/troubleshooting.md`, `docs/evidence/velociraptor_ingest.md`, and `docs/rules/builtin_rules.md`.
- Keep `docs/artifacts/parser-coverage.md` aligned with parser statuses, supported native raw types, and deduplication behavior.

## Debug Export Pack

When the validation ZIP's contents change, update `docs/operations/debug_export_pack.md` and any cross-references in troubleshooting, architecture, and roadmap docs. Keep file names, defaults, secret redaction, and declared limitations consistent across all of them.
