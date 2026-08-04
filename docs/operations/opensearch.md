# OpenSearch in Kairon DFIR

## What it's used for

OpenSearch is the engine for:

- indexing normalized events
- global search
- timeline
- SIEM Lite
- the basis of semi-automated analysis

## Indices per case

The platform creates event indices per case. This allows:

- separating investigations
- deleting a case by clearing its index
- applying controlled mappings

## Why `dynamic: false`

EVTX events can carry highly variable payloads. If OpenSearch automatically expanded all those fields, the total field count would spike.

That's why new indices use:

```json
{
  "dynamic": false
}
```

## Why `raw`, `windows.event_data` and `windows.payload` have `enabled: false`

Those containers are kept for:

- traceability
- event detail
- manual validation

but they must **not** open up thousands of fields in the mapping.

## Which fields are actually searchable

Typical examples:

- `event.type`
- `event.category`
- `event.message`
- `windows.event_id`
- `windows.channel`
- `windows.provider`
- `user.name`
- `source.ip`
- `process.path`
- `process.command_line`
- `execution.source`
- `execution.run_count`
- `execution.last_run`
- `prefetch.executable_name`
- `prefetch.referenced_files`
- `registry.artifact_type`
- `registry.key_path`
- `registry.value_name`
- `registry.value_data`
- `usb.serial`
- `volume.drive_letter`
- `shellbag.path`
- `service.image_path`
- `task.command`
- `tags`
- `suspicious_reasons`
- `search_text`

## Which fields are only visible in detail

- `raw`
- `windows.event_data`
- `windows.payload`
- unmapped parts of the XML/payload

## How to check the mapping

Illustrative example:

```bash
curl http://localhost:9200/<case-index>/_mapping?pretty
```

## If the mapping changes

If you modify the normalized fields or the base mapping:

1. recreate the case or its index
2. reimport the evidence

If you don't do this, you may end up mixing a new parser with an old index.

## Error: total fields limit

This usually means:

- an old index
- misconfigured `dynamic`
- `raw` / `event_data` / `payload` expanding

## Bulk indexing errors

Ingest already attempts to detect bulk errors and not fail silently.

What to check:

- `Activity`
- backend/worker logs
- ingest manifest or audit

## Ingest preflight

Before starting an ingest, reprocess or benchmark, the platform must validate that OpenSearch:

- is reachable
- is not in `red`
- does not have `cluster.blocks.create_index=true`
- does not have `cluster.blocks.write=true`
- does not have relevant indices in `read_only_allow_delete`
- can create the case index if it does not already exist

If that preflight fails:

- parsing does not start
- the run is classified as `infrastructure_blocked_opensearch`
- the UI must show that OpenSearch is not writable

This avoids confusing an infrastructure problem with a parser or throughput problem.

## Useful commands

```bash
curl http://localhost:9200/_cat/indices?v
curl http://localhost:9200/<case-index>/_count?pretty
curl http://localhost:9200/<case-index>/_mapping?pretty
```

Warning:

> Host, port and credentials may vary depending on your deployment.
