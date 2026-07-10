# Investigation workflow

Kairon keeps the active case, host and evidence visible while moving between investigation views. Use the context panel at the top of the main workspaces to confirm scope before pivoting.

## Recommended path

1. Start in the case workspace and review `Evidence & Ingest` plus `Processing`.
2. Open an evidence detail page to verify integrity, chain of custody and indexing status.
3. Pivot to `Search` for broad questions scoped to the current host or evidence.
4. Pivot to `Timeline` when event ordering matters.
5. Pivot to `Artifact Views` for focused families such as EVTX, MFT, Registry, Defender, MOTW, Prefetch or user activity.
6. Pivot to `Memory` when the active evidence is a memory capture.
7. Promote important events to `Findings` and review them before reporting.

## Empty or incomplete results

If Search or Artifact Views show no records, check the evidence `Processing` status first. Then review `Parser Coverage` to confirm whether the artifact family is supported, partially supported or intentionally out of scope.

## Shareable links

Case-scoped URLs preserve useful filters such as `host` and `evidence_id`. Share links from Search, Timeline, Artifact Views or Memory when another analyst needs the same investigation context.
