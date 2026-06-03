# Raw Parsers and Tool Backends

Raw parsers let Kairon DFIR ingest native artifact files directly or run an external parser backend and then normalize CSV/JSON output.

Current backend status is summarized in [parser_backends.md](parser_backends.md).

## Status meanings

- `parsed_external`: parsed from an external tool output such as EvtxECmd/MFTECmd/RECmd CSV.
- `parsed_native`: parsed directly by Kairon DFIR from the raw artifact.
- `advanced_rebuild`: optional scoped rebuild using an EZ Tool backend.
- `discovery_only`: artifact is detected and preserved, but no stable parser is active.
- `tooling_missing`: parser requires unavailable runtime/tooling.
- `no_data`: parser/source was valid, but no relevant rows were present.

## Stable default paths

- EVTX: EvtxECmd CSV backend.
- MFT: MFTECmd CSV backend, summary/full actions.
- Defender: Defender EVTX normalization over Defender channel rows.
- Prefetch: internal raw parser.
- Scheduled Tasks: XML/internal parser.
- Browser: supported SQLite/CSV/JSON parsers.
- Security/Sysmon/PowerShell: normalized from EVTX.

## Scoped or selected paths

- RECmd User Activity:
  - UserAssist
  - RecentDocs
  - RunMRU
  - OpenSaveMRU

These are scoped user activity extractions from NTUSER.DAT/UsrClass.dat where data exists.

## Advanced-only EZ Tool rebuilds

- LNK: LECmd.
- Jumplist: JLECmd.
- Amcache: AmcacheParser.
- Shimcache/AppCompatCache: AppCompatCacheParser.

Advanced docs are indexed as advanced variants and hidden from default Search unless selected.

## Disabled or missing tooling

- PECmd for raw Prefetch: disabled on Linux because raw `.pf` parsing requires Windows decompression support in this environment.
- SrumECmd: installed but requires Windows ESE libraries; SRUM is `tooling_missing` until a Windows parser worker exists.
- SBECmd/ShellBagsExplorer: not active in this deployment; Shellbags raw hives are pending.
- UsnJrnl2Csv: no active backend.

## Evidence status behavior

Optional parser failure, `tooling_missing`, unsupported artifacts or no-data conditions should not mark an evidence failed when other searchable data exists. Use:

- `completed_with_warnings`
- `investigation_ready=true`
- parser-specific status metadata

instead of hiding investigable data behind `failed`.

