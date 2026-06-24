# Kairon DFIR — Memory Pipeline State (Sprint: Batch UUID Alignment v1)

## Sprint progression (most recent at top)

```mermaid
graph TD
    S5["Sprint 5: Batch UUID Alignment v1<br/><b>9792ac8</b><br/>migration v11 + model UUID + 19 tests"]
    S4["Sprint 4: Process Search Focus +<br/>First Analysis Simplification<br/><b>e573cda</b>"]
    S3["Sprint 3: Memory Prep Reconciliation<br/><b>a70e8d4</b><br/>migration v10"]
    S2["Sprint 2: Stale Prep Cleanup<br/><b>158f790</b>"]
    S1["Sprint 1: Golden Path Recovery v1<br/><b>43c5cf1</b><br/>migration v9 + flags + repair"]
    S5 --> S4 --> S3 --> S2 --> S1
```

## Sprint 5 — Root cause and fix (Memory Batch UUID Alignment)

```mermaid
graph LR
    subgraph BEFORE["BEFORE — model vs DB mismatch"]
        M1["SQLAlchemy model<br/>last_advanced_run_id:<br/><b>String(64)</b>"]
        D1["PostgreSQL column<br/>last_advanced_run_id:<br/><b>uuid</b>"]
        E1["INSERT INTO memory_analysis_batches<br/><span style='color:red'>ERROR: column is of type uuid<br/>but expression is of type<br/>character varying</span>"]
        M1 -.declares.-> E1
        D1 -.rejects.-> E1
    end

    subgraph AFTER["AFTER — model + migration v11 + structured errors"]
        M2["SQLAlchemy model<br/>last_advanced_run_id:<br/><b>PgUUID(as_uuid=False)</b>"]
        D2["PostgreSQL column<br/>last_advanced_run_id:<br/><b>uuid</b>"]
        MIG["migration v11<br/>USING NULLIF(col, '')::uuid<br/>(idempotent ALTER)"]
        API["POST /run-all<br/>try create_run_all_batch<br/>except DataError/IntegrityError/ProgrammingError<br/>→ 500 MEMORY_BATCH_DB_SCHEMA_ERROR<br/>(expected_migration_version: 11)"]
        M2 -->|matches| D2
        MIG --> D2
        D2 --> API
    end
```

## Memory batch lifecycle

```mermaid
stateDiagram-v2
    [*] --> queued: POST /run-all<br/>mode=missing_or_failed
    queued --> running: enqueue first profile<br/>(last_advanced_run_id = NULL)
    running --> running: advance_batch()<br/>last_advanced_run_id = run.id<br/>enqueue next
    running --> completed: requested_profiles empty
    running --> completed_with_errors: failed &gt; 0
    running --> failed: metadata_only fundamental failure
    running --> cancelled: cancel_batch() +<br/>no run active
    running --> completed: last profile done
    note right of running
        idempotent: duplicate callback
        with same run.id is a no-op
    end note
    completed --> [*]
    completed_with_errors --> [*]
    failed --> [*]
    cancelled --> [*]
```

## Migration lineage (memory_* tables)

```mermaid
graph LR
    v1["v1<br/>memory_scan_runs_batch_columns"]
    v2["v2<br/>memory_analysis_batches<br/>runtime_columns<br/><i>(last_advanced_run_id VARCHAR(64))</i>"]
    v3["v3<br/>canonical_materialization"]
    v4["v4<br/>evidences_memory_detection"]
    v7["v7<br/>symbol_requirement_backfill"]
    v8["v8<br/>evidence_content_identity"]
    v9["v9<br/>upload_registration_lifecycle"]
    v10["v10<br/>symbol_preparation_reconciliation"]
    v11["v11<br/>last_advanced_run_id<br/><b>uuid</b>"]
    v1 --> v2 --> v3 --> v4 --> v7 --> v8 --> v9 --> v10 --> v11
```

## Current state of remote stack

```mermaid
graph TB
    subgraph REMOTE["192.168.1.19:5173 + :8000"]
        FE["frontend<br/>(nginx / vite)"]
        BE["backend<br/>(FastAPI / Uvicorn)<br/>git: 2c53c34"]
        PG[("PostgreSQL<br/>schema_migrations up to v11<br/>memory_analysis_batches.last_advanced_run_id = uuid")]
    end
    subgraph BATCH["Verified batch"]
        B["id: e01ebc5e-dff4-4cda-9e06-bc9981169068<br/>status: completed<br/>mode: missing_or_failed<br/>last_advanced_run_id: NULL<br/>requested_profiles: []"]
    end
    FE -->|HTTP| BE
    BE -->|SQLAlchemy UUID| PG
    PG --> B
```
