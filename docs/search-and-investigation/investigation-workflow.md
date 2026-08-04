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

## Host context and filtering

The global host selector scopes investigation views by `host_id` when Kairon has resolved a canonical host. URLs also keep the display `host` as a readable fallback for older links and evidence that only has a host name. Host-name matching is normalized case-insensitively and treats short names such as `WS-01` as equivalent to FQDN-style names such as `WS-01.local`.

Host scope applies consistently to `Evidence & Ingest`, `Processing`, `Search`, `Artifact Views`, `Memory` and the investigation context panel. Clear the host filter from the top bar or the context panel when you need to inspect all hosts or evidence without host attribution.

Memory evidence remains isolated per evidence item. If a memory URL points to evidence outside the active host scope, Kairon shows a clear mismatch message instead of silently displaying memory results from another host.

## Evidence host assignment

Evidence can be assigned to a case host during upload, from server-path registration, or later from the evidence detail page. Choose an existing host, create a new host, or leave the evidence `Unassigned` when attribution is not yet known.

Kairon keeps the manual assignment separate from detected host metadata. `Assigned host` controls host-scoped views and filters. `Detected host` remains parser or evidence metadata and is preserved as a hint, even when it differs from the assigned host.

When a host filter is active, evidence with an assigned `host_id` is matched by that assignment first. Evidence without an assignment can still match by normalized detected host name as a fallback. This lets analysts fix memory captures and renamed hosts without losing automatic metadata.

If the assigned host and detected host differ, the UI shows a mismatch indicator. Treat it as an attribution review cue rather than an ingest failure.

## Shareable links

Case-scoped URLs preserve useful filters such as `host_id`, `host` and `evidence_id`. Share links from Search, Timeline, Artifact Views or Memory when another analyst needs the same investigation context.
