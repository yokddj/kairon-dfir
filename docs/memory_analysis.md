# Memory Analysis

Memory Analysis is the planned Kairon workspace for authorized RAM and memory evidence triage.

## Current status

This version is an isolated foundation only. It adds memory evidence data structures, API routes, navigation, empty states, feature flags, and tests. It does not execute external memory forensics tools.

Memory Analysis is disabled by default:

- `MEMORY_ANALYSIS_ENABLED=false`
- `MEMORY_ALLOW_EXTERNAL_TOOL_EXECUTION=false`

External tools such as Volatility 3 or MemProcFS are optional, external to Kairon, not bundled, and subject to their own licenses. Kairon does not auto-install them during Docker build, app startup, tests, or frontend build.

Kairon can report backend readiness for supported external tools. Readiness means only that the server-side configuration points to a valid executable and that a harmless help/version check can run. It does not mean any memory image has been analyzed.

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

Memory evidence does not appear in existing Search, Timeline, Artifact Views, Detections, Findings, Reports, SIEM, Command History, Persistence, or Execution Stories in this foundation.

## Backend readiness checks

Supported readiness targets:

- Volatility 3
- MemProcFS

Readiness checks are read-only and use only administrator-controlled server configuration. Kairon does not accept executable names, command arguments, shell fragments, or paths from API/UI requests.

The configured command must contain only one of:

- an executable name available on the server `PATH`
- an absolute executable path configured by a trusted administrator

The readiness check may call a harmless help/version command with `shell=False`. No memory-image path is supplied, no plugins are run, no mounts are created, no files are written, no MemoryScanRun records are created, and no OpenSearch memory documents are written.

Configuration:

- `MEMORY_ANALYSIS_ENABLED=false`
- `MEMORY_ALLOW_EXTERNAL_TOOL_EXECUTION=false`
- `VOLATILITY3_COMMAND=vol`
- `MEMPROCFS_COMMAND=memprocfs`
- `MEMORY_BACKEND_CHECK_TIMEOUT_SECONDS=10`
- `MEMORY_BACKEND_STATUS_CACHE_SECONDS=60`
- `MEMORY_PREFERRED_BACKEND=volatility3`

Command settings are administrator-controlled and require trusted server access to change. Shell fragments and embedded arguments are rejected.

## Sprint boundary

The current sprint is isolated foundation only. It does not add Volatility execution, MemProcFS execution, process parsing, memory graphs, malfind, netscan, hybrid correlation, or global Search/Timeline integration.
