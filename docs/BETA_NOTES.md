# Beta Notes

## Intended Audience

This beta is for controlled DFIR labs, demos and private tester environments. It is not a hosted SaaS or public Internet deployment.

## What To Test

- Create a case and upload evidence.
- Use **Index evidence for investigation**.
- Validate Search with command-like queries and Windows paths.
- Review Command History, Artifact Views, Defender, User Activity, MOTW, Startup & Persistence and Incident Timeline.
- Create findings and export Markdown reports.
- Run Sigma smoke tests with one rule or a small subset.

## What Not To Do

- Do not upload evidence you are not allowed to process.
- Do not expose the stack directly to the Internet.
- Do not run broad rule packs over large evidence unless you intend to review the volume.
- Do not commit `.env`, backups, uploads, reports or indexed data.

## Reporting Feedback

Useful beta feedback includes:

- exact route/action/query;
- expected vs actual behavior;
- browser and OS;
- sanitized logs;
- approximate evidence size and artifact type.

Avoid sharing raw evidence or screenshots with sensitive values.

