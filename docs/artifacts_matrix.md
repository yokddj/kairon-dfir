# Artifact Support Matrix

This matrix describes current support. It distinguishes artifacts that are detected from artifacts that are parsed and indexed.

| Artifact | Detected | Parsed | Indexed | Backend | Mode | Search | Timeline | Artifact View | Reports | Known limitations | Next action |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| EVTX | yes | yes | yes | EvtxECmd CSV | stable/default | yes | yes | EVTX channels | indirect via events/detections | Message quality depends on available event data. | Keep channel mappings current. |
| Sysmon | yes | yes | yes | EvtxECmd + Sysmon normalizer | stable/default | yes | yes | EVTX/Search | yes via events/commands | Requires Sysmon logs in evidence. | Continue rich-field coverage. |
| Security 4688 | yes | yes | yes | EvtxECmd + Security normalizer | stable/default | yes | yes | EVTX/Search | yes via Command History/Execution Story | Command line may be absent if audit policy disabled. | Maintain process mapping. |
| Security 4663 | yes | yes | yes | EvtxECmd + object normalization | stable/default | yes | yes | EVTX/Search | yes if selected/marked | ObjectName quality depends on event payload. | Keep object.name regression tests. |
| MFT | yes | yes | yes | MFTECmd CSV | stable/explicit summary and full actions | yes | opt-in | MFT / Filesystem | yes if selected/marked | Full MFT is high volume and excluded from default timeline. | MFT Full controls as needed. |
| USN Journal | detected when present | partial | partial/none depending source | no active UsnJrnl2Csv backend | planned/tooling_missing | only if parsed source exists | only if parsed source exists | planned | no | Do not claim raw `$UsnJrnl` support as stable. | Add backend decision. |
| Defender | yes | yes | yes | Defender EVTX parser over Defender channel | stable/default | yes | yes | Defender | yes | Logs may contain only configuration/health events; threat terms can be absent. | Broaden sources if needed. |
| PowerShell EVTX | yes | yes | yes | EvtxECmd | stable/default | yes | yes | EVTX/PowerShell | yes via commands/stories | Script block logging depends on source config. | Continue command extraction. |
| PSReadLine / transcripts | detected if present | partial | yes when present | internal command history extraction | stable/conditional | yes via Command History/Search | yes if timestamped | Command History | yes | PSReadLine often lacks forensic timestamp. | Add more transcript cases. |
| Prefetch | yes | yes | yes | internal raw parser | stable/default | yes | yes | Prefetch | optional | PECmd raw rebuild disabled on Linux. Prefetch has no command line/parent. | Keep internal; consider Windows worker only if needed. |
| Scheduled Tasks | yes | yes | yes | XML/internal normalizer | stable/default | yes | yes | Scheduled Tasks | yes if selected | Trigger/action interpretation can need manual review. | Maintain task action mapping. |
| Browser history/downloads | yes | yes | yes | SQLite/CSV/JSON parsers | stable/default | yes | yes | Browser | yes if selected | Browser artifacts prove navigation/download, not execution. | Keep Chromium/Firefox coverage. |
| LNK | yes | yes | yes | internal default; LECmd advanced | stable default + advanced rebuild | yes | yes if timestamped | LNK | optional | LECmd advanced had richer fields but lower HOSTA coverage. | EZ default activation decision. |
| Jumplist | yes | yes | yes | internal default; JLECmd advanced | stable default + advanced rebuild | yes | yes if timestamped | Jumplist | optional | JLECmd advanced had richer fields but lower HOSTA coverage. | EZ default activation decision. |
| Amcache | yes | yes | yes | internal default; AmcacheParser advanced | stable default + advanced rebuild | yes | yes if timestamped | Amcache | optional | Amcache is inventory/presence, not execution proof. | Decide advanced default later. |
| Shimcache / AppCompatCache | yes | yes | yes | internal default; AppCompatCacheParser advanced | stable default + advanced rebuild | yes | yes if timestamped | Shimcache | optional | Execution flag semantics are cautious. | Decide advanced default later. |
| Services | yes | yes | yes | registry/service parser | stable/default | yes | yes | Services/Autoruns | yes if selected | Service presence is persistence context, not always malicious. | Keep service registry mapping. |
| Autoruns / persistence | yes | partial | yes when parsed | Autoruns/registry/task/WMI sources | stable partial | yes | yes | Autoruns/Persistence | yes if selected | Some sources are discovery-only without parsed exports. | Improve source-specific coverage. |
| UserAssist | yes | yes | yes when hive has data | RECmd scoped extraction | stable partial | yes | yes if timestamped | User Activity | yes if selected | Program execution evidence from Explorer context, not full process tree. | Add more hive fixtures. |
| RecentDocs | yes | yes | yes when hive has data | RECmd scoped extraction | stable partial | yes | yes if timestamped | User Activity | yes if selected | MRU order is not exact open time. | Maintain no-data states. |
| RunMRU | yes | yes | yes when hive has data | RECmd scoped extraction | stable partial | yes | yes if timestamped | User Activity | yes if selected | Key last-write time can represent MRU update. | Maintain no-data states. |
| OpenSaveMRU | yes | yes | yes when hive has data | RECmd scoped extraction | stable partial | yes | yes if timestamped | User Activity | yes if selected | Indicates dialog interaction, not execution. | Maintain no-data states. |
| Shellbags | yes | no | no | none active | planned | no | no | planned/no-data | no | Raw hive candidates are detected but not parsed. | Shellbags Parser v1. |
| SRUM | yes | no | no | SrumECmd requires Windows ESE libraries | tooling_missing | no | no | tooling_missing state | no | SRUDB.dat is detected but no Linux parse is available. | SRUM Windows Worker Parser v1. |
| USB artifacts | yes if source present | partial | yes when parsed | SetupAPI/registry/CSV parsers | stable partial | yes | yes | USB | optional | Exfiltration requires correlation, not USB presence alone. | Continue registry coverage. |
| Recycle Bin | yes if source present | yes | yes when present | `$I/$R` / RBCmd-compatible | stable | yes | yes | Recycle Bin | optional | `$I/$R` pairing depends on available files. | Keep pairing tests. |
| WMI persistence | yes if source present | partial | yes when parsed | WMI CSV/EVTX/registry discovery | stable partial | yes | yes | WMI/Persistence | optional | Raw repository parsing is not complete. | WMI raw parser follow-up. |

## Operational notes

- `Indexed = yes` means the current platform has a working index path when that artifact is present and selected.
- `no-data` is not failure. A detected source can legitimately contain no relevant rows.
- Advanced EZ backend rows are hidden from default Search unless `backend_variant=advanced` or `backend_variant=all` is selected.
- MFT full records are searchable globally when a filename/path query matches, but filesystem timeline is opt-in.

