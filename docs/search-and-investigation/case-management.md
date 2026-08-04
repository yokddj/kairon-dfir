# Case Management

Kairon case management is for organizing many investigations. Status, priority, tags, notes, and the archive/close lifecycle never delete evidence or change access control — permanent removal is a separate, explicit action described in [Deleting a Case](#deleting-a-case).

## Case Status

Cases use these statuses:

- `active`: normal investigation work.
- `closed`: investigation is complete but remains visible and readable.
- `archived`: hidden from the default case list, but all evidence, artifacts, indexes, reports, and activity remain preserved.
- `on_hold`: optional pause state for cases waiting on outside input.

Closing and archiving are reversible. Use `Reopen` to return a closed case to active investigation. Use `Unarchive` to make an archived case visible in the default case list again.

## Priority

Priority is a simple triage field:

- `low`
- `medium`
- `high`
- `critical`

New cases default to `medium`. Use `high` or `critical` for active incidents or high-value CTF/lab work that needs attention first.

## Tags

Tags are lightweight labels for filtering and grouping cases. Examples:

- `ctf`
- `lab`
- `memory`
- `ransomware`
- `windows`
- `client-a`

Tags are normalized to lowercase, trimmed, deduplicated, and limited to simple characters. They are not a taxonomy or permission model.

## Archiving vs Closing

Use `closed` when the investigation is finished but should remain visible in normal case review.

Use `archived` when the case should be hidden from default lists because it is old, completed, or no longer operationally relevant.

Archiving does not delete:

- evidence records;
- uploaded files;
- extracted artifacts;
- OpenSearch indexes;
- hosts;
- memory analysis results;
- reports;
- activity history.

## Search And Filters

The Cases page supports:

- text search across name, description, notes, and tags;
- status filter;
- priority filter;
- tag filter;
- include archived toggle;
- sorting by recent activity, created date, priority, or name.

Archived cases are hidden by default. Enable `Include archived` to show them.

## Recommended Workflow

1. Create the case with a clear name and short description.
2. Set priority before uploading evidence.
3. Add tags such as `ctf`, `memory`, `windows`, or incident family.
4. Use the Case Detail metadata panel to track status, notes, evidence count, host count, and processing summary.
5. Close the case when analysis is complete.
6. Archive the case when it should be hidden from the default operational list.

## Deleting a Case

Use `Delete case` (on the Case Detail page) only when a case must be permanently removed — for example a test case, a duplicate, or a case created by mistake. Unlike archiving or closing, deletion is irreversible.

Deleting a case removes:

- the case record itself;
- its evidence records and uploaded evidence storage on disk;
- extracted artifacts;
- findings, detections, rule runs, rules, and rule sets scoped to the case;
- tags and activity history for the case;
- case access grants for that case;
- the case's OpenSearch index and indexed documents.

The UI requires typing `DELETE` to confirm before the action is enabled, to avoid accidental data loss. If index or storage cleanup fails after the database records are removed, the response reports the failure (`cleanup_error`) so it can be investigated and retried manually; the case and its database-backed records are still gone at that point.

When in doubt between deleting and archiving, prefer `archived` — it is reversible and keeps all evidence, artifacts, and indexes intact for later review.

## Boundaries

Case Management v1 does not add analyst assignment, per-case access, new roles, or permissions. Kairon still uses the existing authentication model.
