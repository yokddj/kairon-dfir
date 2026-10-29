# Search Timeline, Incident Timeline and Reports

## Search Timeline

Search Timeline is a view inside Search for exploring matching events over time. It is not the curated incident story.

Use it when you need to:

- preserve Search filters while moving from results to time order
- inspect events around a query, host, evidence, artifact type, or time range
- open around a specific event
- pivot from findings
- create `key events / bookmarks`
- open in Process Graph
- filter by canonical host including consolidated aliases

Legacy `/timeline` and `/cases/{case_id}/timeline` routes redirect to `Search -> Search Timeline` and preserve filters.

MFT/filesystem records are excluded by default to avoid flooding the view. Use `artifact_type=mft` or `include_filesystem_timeline=true` when filesystem timestamps are the intended scope.

## Incident Timeline

Incident Timeline is the curated, reportable story of the incident. It is built from reviewed evidence, marked events, findings, command history, Defender events, and selected high-signal artifacts.

It should not be treated as:

- all indexed events
- a raw EVTX timeline
- an automatic complete attack path

Use Incident Timeline to:

- group confirmed or high-confidence activity by phase, host, or time
- add analyst notes
- link evidence back to Search and Execution Story
- export a concise timeline into Reports

## Host Identity in Timeline

If the analyst merges aliases for an endpoint:

- the host filter uses the canonical name
- the query also includes `observed_host.name` and associated aliases
- the event detail can show `Observed as` when the original hostname was different

This avoids losing historical events when a hostname changes, when moving from FQDN to NetBIOS, or when consolidating collection names.

## Key Events

Key events are used to:

- highlight milestones
- capture analyst notes
- select material for reports

A report with no key events usually ends up with less narrative and less temporal traceability.

## Report Builder

Lets you select:

- findings
- key events
- Incident Timeline items
- process chains
- analyst notes
- marked events
- Command History suspicious commands
- Execution Story summaries
- Defender events

## Producing a Report

A report is only as good as the curation behind it. The builder does not judge evidence; it lays out what the analyst has confirmed. In order:

1. **Process and check the evidence.** Every evidence item should be *Completed* (or *Completed with warnings* you understand). Failed evidence and parser errors are stated in the report's *Scope → Coverage notes*.
2. **Consolidate hosts.** Merge aliases (FQDN vs NetBIOS, renamed machines) so the report talks about one canonical host.
3. **Triage findings.** Only *confirmed* and *resolved* findings of medium severity or higher enter the report by default. Confirm what is real, mark false positives, archive noise. The executive summary says how many findings are still awaiting review, and the builder preview warns about them too.
4. **Mark the key events.** Bookmark the milestones (initial access, execution, persistence, lateral movement, exfiltration) with *include in report* and a short note: they become the Investigation Timeline. Mark relevant events and commands as *suspicious* or *important*.
5. **Curate the Incident Timeline.** Generate it, accept the items that tell the story, discard the rest. Only accepted items reach the report. Regenerate it after major case changes (the report says when it is out of date).
6. **Triage memory.** Mark Find Evil processes as suspicious, important or not relevant; marked processes are listed in the Memory Analysis section.
7. **Write the narrative.** In the report builder fill *Executive summary* (it leads the section, above the automatic figures), *Recommendations* and *Limitations*, set the author and a title for the reader (for example "Incident response report: ransomware on WS01").
8. **Check the preview.** Sections marked *No matching data · left out of the export* will not appear; adjust filters or sections if something expected is missing.
9. **Export.** PDF to deliver, Markdown to edit or archive. Set the logo, brand name and colour once in the System page settings (`REPORT_BRAND_NAME`, `REPORT_BRAND_SUBTITLE`, `REPORT_BRAND_PRIMARY_COLOR`, `REPORT_INCLUDE_LOGO`, `REPORT_LOGO_PATH`).

## Exports

- `PDF`: rendered server-side (ReportLab) from the same content as Markdown. Cover page (case, author, date, timezone, report reference, handling notice), table of contents with PDF bookmarks, numbered sections, header and *Page X of Y* footer, tables sized to their content and severities in colour.
- `Markdown`: the same sections and numbering, the simplest editable source.

All times are UTC, written `YYYY-MM-DD HH:MM:SS`; the cover and the column headers say so once.

Sections with no matching data (Microsoft Defender or SRUM in a Linux case, an empty IOC list...) are left out of the export and listed once in the appendix. Executive Summary, Scope, Evidence, Hosts, Findings, Recommendations and Appendix are always present, so a report with no findings says so plainly.

## Typical Report Sections

- executive summary: the analyst's text, key figures, findings by severity, findings still awaiting review, key findings
- scope: case, period, host and evidence filters, which findings were included, coverage notes (truncations, failed evidence, parser errors)
- evidence processed: name, type, size, SHA-256, host, events, status
- hosts: canonical hosts and relevant aliases
- findings: one block per finding with severity, risk, confidence, status, observed period, why it matters, related entities, supporting events and next steps
- detections: automated rule matches summarised per rule (severity, matches, hosts, event times when known), clearly labelled as unreviewed leads
- Investigation Timeline (key events) and Incident Timeline (accepted items only)
- process chains
- suspicious command history: an overview table and one detail block per command; one execution seen by several sources is reported once with all of them
- Defender, email, MOTW, SRUM, startup and persistence where the case has them
- Memory Analysis (only when the case has memory images): per image the system and capture time, the analyses run with their item counts, and the Find Evil triage with the processes the analyst marked suspicious or important
- deduplicated IOCs
- recommendations and limitations
- appendix: report parameters and the sections left out for lack of data

## Host Identity in Reports

When the case uses alias management:

- the report should refer to the `Canonical Host`
- it can list known aliases for context
- manual merges should be understood as an analyst decision, not an overwrite of the original evidence

The original observed name remains the useful technical reference for traceability and debugging.

## Limitations

- Charts and graphs (process graph, timelines) are not embedded as images.
- Secrets and tokens are automatically redacted where the export path supports it.
- Narrative quality depends on well-curated findings and key events.
- The report should not replace the case's technical validation.
