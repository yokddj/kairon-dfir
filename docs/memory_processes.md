# Memory Processes

Memory process analysis is isolated to Memory Analysis. Results are not added to global Search, Timeline, Artifact Views, Detections, Findings, Reports, SIEM, Persistence, Command History, Execution Stories, or disk process-tree endpoints.

## Supported Plugins

- `windows.pslist`: process list reported by the operating system structures Volatility reads.
- `windows.pstree`: parent-child relationships as reported by Volatility.
- `windows.psscan`: scanned process structures that require analyst interpretation.
- `windows.cmdline`: command-line strings for processes where Volatility can report them.

`windows.info` always runs first for process profiles. If it fails, process plugins are not executed.

## Profiles

- `metadata_only`: `windows.info`
- `processes_basic`: `windows.info`, `windows.pslist`, `windows.pstree`, `windows.cmdline`
- `processes_extended`: `windows.info`, `windows.pslist`, `windows.pstree`, `windows.psscan`, `windows.cmdline`

Process profiles require `MEMORY_PROCESS_PROFILE_ENABLED=true` and external execution enabled by an administrator.

## Normalization

Kairon normalizes process rows into `memory_process` documents and parent-child relationships into `memory_process_edge` documents. Documents are written only to `dfir-memory-{case_id}`.

Merge identity uses PID plus process offset and create time when available. PID reuse can still be ambiguous if a plugin does not provide enough context, so Kairon preserves warnings instead of inventing certainty.

Command lines are bounded and may be missing. Kairon does not infer executable paths from process names.

## Interpretation Limits

`psscan` results are not malware verdicts. A process reported by `psscan` and not `pslist` is shown neutrally as not present in the pslist result and requiring analyst review.

Missing parents are displayed as orphans. Kairon does not create fake parent processes except through explicit placeholder UI semantics.

## Roadmap

Future work may add optional analyst-driven correlation between memory and disk evidence. This sprint intentionally keeps memory process data isolated.
