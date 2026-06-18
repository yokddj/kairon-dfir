# Optional Volatility Memory Worker

Kairon can run without any memory worker. Disk-only analysis, existing ingest, Search, Timeline, Artifact Views, detections, reports, and SIEM workflows remain available when the optional profile is absent.

The optional `memory-worker` Compose profile builds a local image on the operator's server. During that operator-initiated build, the image installs `volatility3==2.28.0` from the official PyPI package using the pinned wheel hash:

`68ea2257d25d2ab6160bb29203ce9bf3e91a8a852a420cb819ebb4c4115eaa68`

Kairon does not commit Volatility source, wheels, binaries, symbol packs, plugins, or prebuilt images. Volatility 3 is governed by the Volatility Software License 1.0 and remains a separate third-party dependency. Public redistribution of a prebuilt memory-worker image requires a separate license review. This documentation is not legal advice.

## Build

Review the license notice first:

```sh
cat docker/memory-worker/THIRD_PARTY_NOTICES.md
```

Build and start the optional worker:

```sh
docker compose --profile memory build memory-worker
docker compose --profile memory up -d memory-worker
```

The default `docker compose up -d` does not build or start `memory-worker`.

## Configuration

Production-safe defaults remain disabled:

```sh
MEMORY_ANALYSIS_ENABLED=false
MEMORY_ALLOW_EXTERNAL_TOOL_EXECUTION=false
MEMORY_PROCESS_PROFILE_ENABLED=false
MEMORY_WORKER_MODE=external_command
MEMORY_REQUIRE_DEDICATED_WORKER=true
MEMORY_SYMBOL_NETWORK_ACCESS_ENABLED=false
```

To use the dedicated worker, an administrator must intentionally configure:

```sh
MEMORY_WORKER_MODE=dedicated_worker
MEMORY_ANALYSIS_ENABLED=true
MEMORY_ALLOW_EXTERNAL_TOOL_EXECUTION=true
MEMORY_PROCESS_PROFILE_ENABLED=true
VOLATILITY3_COMMAND=vol
```

The API and UI cannot set executable paths, queues, Docker profiles, or plugin names.

## Isolation

The worker listens only to the configured memory queue, defaults to concurrency 1, exposes no public port, runs as a non-root user, drops Linux capabilities, uses `no-new-privileges`, and mounts evidence read-only. Memory output remains under Kairon's isolated memory storage and `dfir-memory-{case_id}` indexes.

Symbols are not included in the image or repository. The default symbol policy is offline-only. If Volatility cannot satisfy plugin requirements with locally available symbols/cache, the run must fail safely rather than downloading symbols silently.

## Readiness

On startup, `memory-worker` publishes a bounded heartbeat/capability record to Redis with its queue, supported profiles, supported plugins, Volatility version, and symbol policy. The backend readiness endpoint uses this heartbeat in `dedicated_worker` mode and does not require `vol` to be installed in the backend container.

Validate:

```sh
curl -fsS http://127.0.0.1:8000/api/memory/backends
```

Real RAM analysis requires separately authorized, non-sensitive lab evidence outside Git. If no such evidence exists, record:

`REAL_VOLATILITY_VALIDATION_BLOCKED_NO_AUTHORIZED_TEST_EVIDENCE`
