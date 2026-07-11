# Findings / Notes v1

Findings are analyst-owned notes and conclusions attached to a case. They let investigators document what is relevant, suspicious, pending review, confirmed, or ready to include in a later report without leaving Kairon.

## Notes vs Confirmed Findings

- Use `draft` for working notes, hypotheses, or follow-up reminders.
- Use `review` when a finding needs another analyst pass.
- Use `confirmed` for conclusions that should be considered reportable.
- Use `false_positive` when the lead was reviewed and dismissed.
- Use `archived` to hide old findings without deleting investigative history.

## Severity

Severity can be `info`, `low`, `medium`, `high`, or `critical`.

Use `info` for neutral notes, `medium` for suspicious activity that needs validation, and `critical` only for high-confidence impact or compromise indicators.

## Status

The v1 workflow is intentionally simple: `draft`, `review`, `confirmed`, `false_positive`, and `archived`.

Legacy correlation statuses may still appear for automatically generated findings.

## Tags

Tags group findings by investigation theme, for example `memory`, `ctf`, `persistence`, or `ransomware`.

Tags are normalized to lowercase, trimmed, deduplicated, and safe for filtering.

## Linking

Findings can link to a case, evidence, case host, artifact id, artifact family/type, and a source view such as `memory`, `evidence`, `artifacts`, or `search`.

Contextual Add finding actions prefill these fields when launched from Evidence Detail or Memory.

## Suggested Workflow

1. Create a draft finding when something looks relevant.
2. Link it to the evidence or host that supports it.
3. Add tags for the investigation theme.
4. Raise severity as confidence increases.
5. Move to `review` or `confirmed` after validation.
6. Archive stale or superseded findings instead of deleting them permanently.

## Limitations

Findings / Notes v1 is not a final report generator. It does not implement a complete PDF report workflow or advanced incident timeline generation.
