# Task Inventory

This file documents the current task contract for the Search-first DFIR flow.

## Core

- `app.workers.tasks.ingest_evidence`
  - Queue: `dfir-ingest`
  - Flow: `Evidence -> Usable Search ingest -> Search / Timeline`
  - Modes: `usable_search`, `full_forensic`

## On-demand

- `app.workers.tasks.run_rules_on_case`
  - Queue: `dfir-rules`
  - Trigger: explicit analyst action
- `app.services.report_service.generate_evidence_summary_report`
  - Queue: inline
  - Trigger: explicit analyst action
- `app.workers.tasks.retry_problematic_artifacts`
  - Queue: `dfir-ingest`
  - Trigger: explicit analyst action

## Advanced / Beta

- `app.workers.tasks.run_case_semi_auto_analysis`
  - Queue: `dfir-analysis`
- `app.services.debug_export.generate_debug_pack`
  - Queue: inline
- `app.services.ingest_benchmarks.create_ingest_benchmark`
  - Queue: `dfir-ingest`

## Maintenance

- `app.services.job_watchdog.run_benchmark_watchdog`
  - Queue: inline
  - Purpose: safe reconciliation and health monitoring

## Contract

- `usable_search` must only auto-trigger core ingest work.
- Rules, reports, enrichment, deep retry and benchmark paths remain explicit on-demand or advanced actions.
- Queue/worker visibility is exposed through:
  - `GET /api/system/task-registry`
  - `GET /api/system/task-health`
