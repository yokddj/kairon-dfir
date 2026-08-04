# Evidence Processing Queue

The Processing Queue shows per-evidence processing state for a case. It is an operator view over existing ingest, parser, artifact and memory run data; it does not create a new scheduler.

## States

- `pending`: evidence exists but processing has not started.
- `queued`: processing has been accepted and is waiting for a worker.
- `running`: ingest, reprocess or memory analysis is active.
- `completed`: processing completed without recorded parser failures.
- `completed_with_warnings`: processing produced partial results, but at least one parser warning or parser failure was recorded.
- `failed`: processing failed before a usable completion state.
- `cancelled`: processing was cancelled.
- `unknown`: Kairon cannot map the stored state to a known processing state.

## Partial Results

`completed_with_warnings` does not invalidate the whole evidence. It means some parsers may have failed or warned while other parsers produced artifacts or searchable records. Analysts should open the processing detail, review the parser-level error, and pivot to the generated artifacts or Search results that are available.

## Reprocessing

Kairon already supports evidence reprocess from the evidence detail workflow. The Processing Queue links to evidence detail and artifact/search views. Retry buttons are intentionally not exposed in the queue until the required host, ingest mode and reprocess selection are safe to infer for that evidence.

## Security

The processing APIs summarize errors and parser details. They redact internal filesystem paths and omit sensitive path fields such as `stored_path`, `original_path`, `source_path` and output directories.

## Limits

This view does not guarantee worker liveness or create a real-time queue. It reflects persisted evidence status, ingest run metadata, artifacts and memory scan/plugin runs available in the database.
