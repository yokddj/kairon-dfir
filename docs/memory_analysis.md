# Memory Analysis

Memory Analysis is the planned Kairon workspace for authorized RAM and memory evidence triage.

The primary upload workflow is now:

```text
Case -> Memory Analysis -> Add memory image
```

This dedicated flow shows upload readiness, storage capacity, privacy warnings, and progress before the evidence appears in Memory Analysis. The generic Evidence Upload form remains compatible, but it is no longer the recommended memory workflow.

## Current status

This version includes isolated Volatility 3 profiles:

- `windows.info`
- `windows.pslist`
- `windows.pstree`
- `windows.psscan`
- `windows.cmdline`

It does not extract network connections, DLLs, handles, services, drivers, registry data, injected memory, credentials, files, strings, YARA results, or malware findings. MemProcFS remains readiness-only.

Memory Analysis is disabled by default:

- `MEMORY_ANALYSIS_ENABLED=false`
- `MEMORY_ALLOW_EXTERNAL_TOOL_EXECUTION=false`

External tools such as Volatility 3 or MemProcFS are optional, external to Kairon, not bundled, and subject to their own licenses. Kairon does not auto-install them during the default Docker build, app startup, tests, or frontend build.

Operators may optionally build a dedicated `memory-worker` image with `docker compose --profile memory build memory-worker`. That image installs pinned Volatility 3 from official PyPI during the operator-initiated build and is not published by Kairon as a prebuilt image. Volatility 3 remains governed by its own license, and redistribution of a prebuilt image requires separate review.

Kairon can report backend readiness for supported external tools. Readiness means only that the server-side configuration points to a valid executable and that a harmless help/version check can run. It does not mean any memory image has been analyzed.

When execution is explicitly enabled by an administrator, Kairon may run Volatility 3 only through named server-controlled profiles against evidence registered as `memory_dump`. The command is built server-side, uses `shell=False`, receives no API-controlled plugin names or arguments, and stores output only under the isolated memory run directory.

## Legal and safety rules

- Use only evidence you own, are authorized to analyze, or lab/demo evidence created for this purpose.
- Do not upload memory dumps containing third-party personal data unless you have authorization.
- Do not commit memory dumps to the repository.
- Do not commit extracted secrets, credentials, malware, or private data.
- Do not vendor Volatility, MemProcFS, plugins, binaries, symbol packs, YARA rules, memory dumps, malware samples, credentials, or third-party forensic outputs.
- Do not implement or run credential extraction, password dumping, secrets harvesting, LSASS dumping, or malware-analysis plugins through Kairon.

## Supported modes

- `empty`: no disk events and no memory evidence.
- `disk_only`: existing disk artifact workflow only.
- `memory_only`: memory evidence registered in the isolated memory workspace.
- `hybrid`: disk events and memory evidence both exist, but memory results remain isolated.

Memory evidence and memory results do not appear in existing Search, Timeline, Artifact Views, Detections, Findings, Reports, SIEM, Command History, Persistence, or Execution Stories.

## Backend readiness checks

Supported readiness targets:

- Volatility 3
- MemProcFS

Readiness checks are read-only and use only administrator-controlled server configuration. Kairon does not accept executable names, command arguments, shell fragments, or paths from API/UI requests.

The configured command must contain only one of:

- an executable name available on the server `PATH`
- an absolute executable path configured by a trusted administrator

The readiness check may call a harmless help/version command with `shell=False`. No memory-image path is supplied, no plugins are run, no mounts are created, no files are written, no MemoryScanRun records are created, and no OpenSearch memory documents are written.

## Profiles

The memory runner is asynchronous. `POST /api/evidences/{evidence_id}/memory/scan` accepts only a named profile:

```json
{"profile":"metadata_only","authorization_acknowledged":true}
```

Before a real run, the API requires an explicit acknowledgement that the operator owns the memory image or is authorized to analyze it and understands RAM may contain sensitive personal or authentication data. This acknowledgement is recorded as run metadata for audit context; it is not a legal guarantee.

Supported profiles:

- `metadata_only`: `windows.info`
- `processes_basic`: `windows.info`, `windows.pslist`, `windows.pstree`, `windows.cmdline`
- `processes_extended`: `windows.info`, `windows.pslist`, `windows.pstree`, `windows.psscan`, `windows.cmdline`

Process profiles are disabled by default with `MEMORY_PROCESS_PROFILE_ENABLED=false`.

Kairon selects the backend and plugins server-side. Each plugin runs sequentially with this argv shape:

```text
[resolved_volatility_executable, "-f", validated_evidence_path, "-r", "json", plugin_from_profile]
```

No executable path, evidence path, plugin name, output path, symbol URL, command argument, or environment variable is accepted from the API or UI.

The runner validates:

- `MEMORY_ANALYSIS_ENABLED=true`
- `MEMORY_ALLOW_EXTERNAL_TOOL_EXECUTION=true`
- `authorization_acknowledged=true`
- Volatility 3 readiness is ready
- evidence exists and is `memory_dump`
- evidence resolves to a regular file under trusted storage roots
- no active run already exists for the same evidence/profile

The runner writes bounded raw JSON and a manifest under the evidence storage tree, stores run metadata in PostgreSQL, and indexes normalized `memory_system_info`, `memory_process`, and `memory_process_edge` only into `dfir-memory-{case_id}`. It never writes to the existing disk events index.

Process differences are presented neutrally. A `psscan`-only process is shown as “Not present in pslist result” and “Requires analyst review”; Kairon does not label it as malware, rootkit activity, or compromise.

Automatic symbol download is not initiated by Kairon. If Volatility cannot satisfy plugin requirements, the run fails safely and reports a sanitized error such as `PLUGIN_REQUIREMENTS_UNSATISFIED`.

Configuration:

- `MEMORY_ANALYSIS_ENABLED=false`
- `MEMORY_ALLOW_EXTERNAL_TOOL_EXECUTION=false`
- `MEMORY_UPLOAD_ENABLED=false`
- `MEMORY_UPLOAD_MAX_BYTES=2147483648`
- `MEMORY_UPLOAD_CHUNK_SIZE_BYTES=4194304`
- `MEMORY_UPLOAD_STAGING_ROOT=`
- `MEMORY_UPLOAD_ALLOWED_EXTENSIONS=.raw,.mem,.vmem,.dmp,.lime`
- `VOLATILITY3_COMMAND=vol`
- `MEMPROCFS_COMMAND=memprocfs`
- `MEMORY_BACKEND_CHECK_TIMEOUT_SECONDS=10`
- `MEMORY_BACKEND_STATUS_CACHE_SECONDS=60`
- `MEMORY_PREFERRED_BACKEND=volatility3`
- `MEMORY_JOB_TIMEOUT_SECONDS=900`
- `MEMORY_PLUGIN_TIMEOUT_SECONDS=600`
- `MEMORY_PLUGIN_OUTPUT_MAX_BYTES=10485760`
- `MEMORY_WORKER_CONCURRENCY=1`
- `MEMORY_ALLOWED_PLUGINS=windows.info,windows.pslist,windows.pstree,windows.psscan,windows.cmdline`
- `MEMORY_ALLOWED_PROFILES=metadata_only,processes_basic,processes_extended`
- `MEMORY_DEFAULT_PROFILE=metadata_only`
- `MEMORY_PROCESS_PROFILE_ENABLED=false`
- `MEMORY_MAX_PROCESS_ROWS=100000`
- `MEMORY_MAX_COMMAND_LINE_LENGTH=16384`
- `MEMORY_MAX_RAW_FIELD_LENGTH=65536`
- `MEMORY_RAW_OUTPUT_RETENTION_ENABLED=true`
- `MEMORY_SYMBOL_NETWORK_ACCESS_ENABLED=false`

Command settings are administrator-controlled and require trusted server access to change. Shell fragments and embedded arguments are rejected.

## Sprint boundary

The current runner scope is isolated metadata and process inventory only. It does not add MemProcFS execution, malfind, netscan, DLL/handle/service/driver extraction, credential extraction, file extraction, malware detection, hybrid correlation, or global Search/Timeline integration.
