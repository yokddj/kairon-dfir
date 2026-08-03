# Evaluation Guide

## Who This Is For

This guide is for anyone trying Kairon DFIR for the first time — in a personal lab, a training environment, or a real investigation. Kairon DFIR is self-hosted software, not a hosted SaaS; see [`/SECURITY.md`](../SECURITY.md) for the deployment security boundary before exposing it beyond your own machine.

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

Useful feedback includes:

- exact route/action/query;
- expected vs actual behavior;
- browser and OS;
- sanitized logs;
- approximate evidence size and artifact type.

Avoid sharing raw evidence or screenshots with sensitive values. See [`CONTRIBUTING.md`](../CONTRIBUTING.md) for how to open an issue or pull request.
