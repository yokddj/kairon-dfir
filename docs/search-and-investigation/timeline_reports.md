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

## Exports

- `Markdown`: available and remains the simplest, most editable source.
- `PDF`: should not be considered stable unless validated for the specific deployment.

## Typical Report Sections

- summary
- scope
- findings
- Search Timeline highlights / key events
- Incident Timeline
- process chains
- suspicious command history
- execution story summaries
- Defender detections/configuration events where selected
- canonical hosts and relevant aliases
- deduplicated IOCs
- notes and recommendations

## Host Identity in Reports

When the case uses alias management:

- the report should refer to the `Canonical Host`
- it can list known aliases for context
- manual merges should be understood as an analyst decision, not an overwrite of the original evidence

The original observed name remains the useful technical reference for traceability and debugging.

## Limitations

- Markdown is the validated export.
- Not all charts or complex visualizations are embedded as images.
- Secrets and tokens are automatically redacted where the export path supports it.
- Narrative quality depends on well-curated findings and key events.
- The report should not replace the case's technical validation.
