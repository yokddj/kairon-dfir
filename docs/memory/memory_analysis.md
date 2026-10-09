# Memory Analysis

Memory Analysis is a Preview Kairon capability for authorized RAM and memory evidence triage. See [roadmap.md](../roadmap.md) for its Preview classification and [architecture/optional-capability-boundary.md](../architecture/optional-capability-boundary.md) for what "optional" means technically for this capability.

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
- `windows.envars`
- `windows.getsids`
- `windows.privileges`
- `windows.netscan`
- `windows.netstat`
- `windows.malfind`
- `windows.vadinfo`

It does not dump memory regions, processes or DLLs, extract credentials or create malware findings from memory plugins. Files are recovered from memory only on request and for PowerShell history files. MemProcFS runs its forensic scan as part of Find Evil (FindEvil, timelines, inventories and its built-in YARA rules); see the sections below. The list above is the original metadata profile set; the full plugin list is under Profiles.

The Memory capability itself is mounted by default (`memory_enabled=true`), but plugin execution against a memory image is disabled by default, behind two independent gates:

- `MEMORY_ANALYSIS_ENABLED=false` (default) — actual Volatility 3 / MemProcFS plugin execution stays off until explicitly enabled.
- `MEMORY_ALLOW_EXTERNAL_TOOL_EXECUTION=false` (default) — a second, independent gate on invoking the external tool binary itself.

Setting `memory_enabled=false` removes Memory's routers and startup reconciliation hooks from the running backend entirely — see the "Added"/"Changed" entries under `CHANGELOG.md`'s Unreleased section for when this activation boundary shipped.

External tools such as Volatility 3 or MemProcFS are optional, external to Kairon, not bundled, and subject to their own licenses. Kairon does not auto-install them during the default Docker build, app startup, tests, or frontend build.

Operators may optionally build a dedicated `memory-worker` image with `docker compose --profile memory build memory-worker`. That image installs pinned Volatility 3 from official PyPI and MemProcFS's Linux release binaries (pinned version, SHA-256 checked) during the operator-initiated build, and is not published by Kairon as a prebuilt image. Each tool remains governed by its own license (MemProcFS: AGPL-3.0; see `docker/memory-worker/THIRD_PARTY_NOTICES.md`), and redistribution of a prebuilt image requires separate review.

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
- `processes_extended`: `windows.psscan`, `windows.envars`, `windows.getsids`, `windows.privileges`
- `network_basic`: `windows.netscan`, `windows.netstat`
- `modules_basic`: `windows.dlllist`, `windows.ldrmodules`
- `handles_basic`: `windows.handles`
- `kernel_basic`: `windows.modules`, `windows.driverscan`
- `suspicious_memory`: `windows.malfind`, `windows.vadinfo`
- `shell_history_basic`: `windows.consoles`, `windows.cmdscan` and the PowerShell history file (`kairon.psreadline`: `windows.filescan` + `windows.dumpfiles`) on Windows, `linux.bash` on Linux
- `files_basic`: `windows.filescan`
- `find_evil`: Kairon's checks (`windows.pslist`, `windows.psscan`, `windows.cmdline`, `windows.malfind`, `windows.ldrmodules`) and MemProcFS FindEvil (Windows)

**Run all** runs every profile above except `files_basic`, in this order: metadata, processes, extended processes, shell history, Find Evil, network, modules, handles, kernel, suspicious memory.

### Find Evil

The **Find Evil** tab lists indicators from two sources; the **Source** column says which (both, when the two tools report the same indicator: same process and type, and for memory and module indicators the same address).

- **Kairon**: checks over standard Volatility output, so they work on any image Volatility can read. They encode how Windows normally looks, nothing specific to a case:
  - processes found by scanning memory (`psscan`) but missing from the kernel's list while still having threads and no exit time (`PROC_NOLINK`: hidden), and processes that had already exited (`PROC_TERMINATED`, low);
  - Windows system processes with an unexpected parent (`PROC_PARENT`; a parent PID reused by a later process is ignored), more than one instance of a process Windows runs once (`PROC_DUPLICATE`), names one typo away from a system binary (`PROC_NAME`), system binaries outside System32 (`PROC_PATH`), programs run from temporary or user-writable folders (`PROC_LOCATION`);
  - command interpreters started by an Office application, browser or server (`PROC_SPAWN`), and command lines with attacker patterns (`CMDLINE`: encoded PowerShell, download cradles, LOLBins, backup deletion, credential dumping; discovery commands are low);
  - a PE header in executable private memory (`PE_INJECT`), other executable private memory (`PRIVATE_RWX`, low in browsers, JIT runtimes and the antivirus), and modules outside the Windows and Program Files folders missing from the loader lists (`PE_NOLINK`).
- **MemProcFS**: the indicators MemProcFS's FindEvil reports after its forensic scan: processes missing from the kernel's process list or masquerading, processes with the debug privilege or an unexpected account, injected, unlinked or patched modules, executable memory not backed by a file, high-entropy regions, unusual threads, drivers loaded from odd paths, and Windows Defender detections still in memory.

Each indicator has a **review priority** and a one-line explanation:

- **High**: Defender detections, hidden or masquerading processes, injected modules and writable-executable memory not backed by a file.
- **Medium**: debug privilege, unexpected account, invalid page table, patched loader data, spoofed headers, odd drivers, threads and high-entropy memory.
- **Low**: writable-executable or executable private memory and patched module pages, which browsers, JIT runtimes and Windows itself also produce. On a typical workstation most indicators are low.

The list is sorted by priority and can be filtered by priority, type and PID. Like the suspicious-memory profile, these are leads for review, not verdicts: Kairon does not mark anything as malware or create findings from them.

How it runs: Kairon's checks run first (a few minutes on a 4 GB image); a source plugin that fails only removes its own checks. MemProcFS's library is then loaded in a separate process with the same containment as Volatility (own session, timeout, cancellation, output cap), with the Microsoft symbol server disabled, so it works offline. It needs 64-bit Windows 10 or later; on other images it is reported as unsupported for that build. On a 4 GB Windows 11 image it takes about a minute. MemProcFS 5.19's `vmm.so` is rebuilt in the image from the release's source with the patches in `docker/memory-worker/patches/`: on Windows 11+ images its DNS cache lookup could loop forever (an inner loop reused the outer loop's index), which kept the forensic scan at 90 % and FindEvil from finishing (seen on a Windows 11 24H2 crash dump, which now finishes in about 30 seconds). If a scan still stops making progress, a watchdog stops it after 10 minutes, it is reported as failed with that reason, and the tab shows Kairon's indicators with a note that part of Find Evil did not finish.

If the memory worker dies while an analysis runs (killed, restarted, out of memory, or the host went to sleep), the run is closed as failed (`WORKER_LOST`) when the next analysis starts or is requested from the app, instead of staying "running" forever and blocking a new run.

### Shell history on Windows

The **Shell History** tab has two lists:

- **Typed in shells**: commands typed in console windows, below.
- **Commands executed**: the command line of every process found in memory, in the order they started, with its parent and whether it was running, had exited or was missing from the process list. It covers everything that ran, typed or not (scripts, scheduled tasks, services, programs starting programs), and comes from the Processes analysis.

`windows.consoles` reads the console windows (`conhost.exe`) in memory. Commands are recovered from two places, and each row says which (**Source**):

- **Console history**: the command history conhost keeps per window. `cmd.exe` uses it; PowerShell does not (it keeps its own, PSReadLine, outside the console), so for PowerShell windows this list is empty.
- **Console screen**: the text still on the window's screen. Every line that starts with a prompt (`PS C:\Users\x> command` or `C:\Users\x>command`) gives a command and the directory it ran in (**Directory**); a command that wraps across rows is joined. Only what was still in the window's screen buffer (a few thousand rows; older lines are overwritten) can be recovered, and commands also in the console history are listed once.

`windows.cmdscan` finds the same command-history lists by scanning conhost's memory for them instead of following its console structures, so it still recovers typed commands on builds `windows.consoles` has no layout for (on Windows 11 24H2 `windows.consoles` only reports "Console Information Not Found"). A command both plugins recover is listed once.

- **PowerShell history file**: PSReadLine (PowerShell's line editor since Windows 10) appends every command typed at an interactive prompt to `%APPDATA%\Microsoft\Windows\PowerShell\PSReadLine\<host>_history.txt` (`ConsoleHost_history.txt` for `powershell.exe`/`pwsh.exe`; other hosts such as VS Code have their own). The file outlives the session, so it holds commands from earlier sessions too. `kairon.psreadline` looks for these files with `windows.filescan` and, when Windows still has them cached, recovers them with `windows.dumpfiles`; each command is listed in file order (oldest first) with the user whose profile holds the file (the file path is the Source tooltip). Pages no longer cached are skipped, so a partly cached file gives the commands that were. No file cached is a normal result (PowerShell not used interactively, or evicted), not a failure.

  To check it on a test machine: open PowerShell, type a few commands (`whoami`, `Get-LocalUser`, `ipconfig /all`), keep the window open or read the file once (`Get-Content (Get-PSReadLineOption).HistorySavePath`) so it is in the file cache, take a memory image (DumpIt, WinPmem, a VM snapshot), upload it and run Shell History: the commands appear with Source **PowerShell history file**.

There is no time for these commands. On Windows builds that Volatility's console support does not cover (for example Windows 10 1803, build 17134), the plugin is reported as unsupported for that build, not as a failed run.

**PowerShell event log** (also in the Shell History tab): PowerShell's own event log records still in memory, recovered by MemProcFS's forensic scan when Find Evil runs: script blocks (4104, with their part number when PowerShell split a long block), command invocations (4103) and engine and pipeline records with the host's command line (400, 403, 600, 800). Unlike the console sources, each has the time PowerShell logged it. They exist only when PowerShell logging recorded them (4104 needs script block logging, on by default only for suspicious blocks; 4103 needs module logging).

Every command in the case, from disk and memory, is also in **Command History**, in the sidebar.

### MemProcFS timeline in the case Timeline

The forensic scan Find Evil runs also builds MemProcFS's timelines. The ones Volatility has no equivalent for are added to the case **Timeline** as events of the memory evidence (`artifact.parser: memprocfs`):

| `artifact.type` | What |
| --- | --- |
| `memprocfs_ntfs` | NTFS records (MFT) still in memory: files created, modified, accessed |
| `memprocfs_registry` | Registry key last-write times |
| `memprocfs_eventlog` | Event log records still in memory, with event id, channel, provider and data (searchable as `eventid:`, `channel:`) |
| `memprocfs_web` | Browser history |
| `memprocfs_task` | Scheduled tasks: created, changed, last run, completed |
| `memprocfs_amcache` | Amcache inventory updates |
| `memprocfs_prefetch` | Prefetch executions |
| `memprocfs_kernelobject` | Kernel objects created (devices, symbolic links) |

The same Find Evil run also saves MemProcFS's inventories (see **MemProcFS tab** below).

Process, network and thread timelines are not added: the Processes and Network analyses already give them from Volatility. NTFS and registry can run to hundreds of thousands of rows, so the Timeline hides them by default (like MFT from disk) and shows them when filtered by their type or when searching; the **Memory (MemProcFS)** quick filter shows every MemProcFS timeline. A new Find Evil run replaces the evidence's previous MemProcFS events; at most 1,000,000 are indexed per run (NTFS and registry are indexed last, so the cap falls on them). If the forensic scan does not finish, no timeline is added and Find Evil works as before.

### Volatility's events in the case Timeline

The case **Timeline** also shows the dated events Volatility finds in each memory image, from the active run of each analysis: process starts and exits (Processes), network connections (Network), suspicious memory with its process's start time (Suspicious Memory) and shell commands that carry a time (bash on Linux). They are labelled **Memory** with types `memory_process`, `memory_network`, `memory_suspicious` and `memory_shell`; the **Memory (Volatility)** quick filter shows only them. They follow the Timeline's time range, text search, host, evidence, type and event-type filters; a filter only disk events have (file path, domain, IP, hash, URL, severity, risk) leaves them out. They stay in the memory index and are merged into each page as it is built, so paging stays exact.

### MemProcFS tab

The **MemProcFS** tab of a memory evidence lists the inventories MemProcFS's forensic scan reads, beyond what Volatility's tabs show. They are saved by the Find Evil run (a run from before they were collected has none: run Find Evil again):

| Group | Table | What |
| --- | --- | --- |
| Persistence | Scheduled tasks | Every registered task: command, arguments, account, created, last run, completed |
| Persistence | Services | Services in the Service Control Manager's memory: account, start type, state, image path or command line |
| Network | DNS cache | Names the DNS client had resolved; entries read from freed memory (unreadable names or answers) are hidden and counted |
| Execution | Prefetch, Amcache files, Amcache applications, Amcache shortcuts | Programs that ran or were inventoried, with path, publisher, version, run count and times |
| System | Drivers, Devices, Amcache drivers, Amcache driver packages, Amcache device containers, Amcache PnP devices | Driver and device objects in kernel memory and Amcache's driver and device inventory |
| Detection | YARA matches | Matches of MemProcFS's built-in YARA rules in process and kernel memory |

Each table can be filtered by text; hovering a row shows all its columns. Process, thread, module, handle and network lists are not repeated here: Volatility's tabs have them.

The scheduled tasks and services also appear in the case's **Persistence** view (source **Memory (MemProcFS)**), scored like the disk sources: commands in user-writable folders, script launchers and encoded PowerShell rank first, Windows' own tasks last.

### Timeline tab

Each memory evidence has a **Timeline** tab (next to Shell History) with only that image's events, in time order: process starts and exits and network connections from Volatility (the active Processes and Network runs, plus suspicious memory with its process's start time and shell commands that carry a time), merged with the MemProcFS timelines above. Chips filter by type and show how many events each has; NTFS and registry start off. Text search covers the event, the process name and the PID. Pages follow a cursor, so the last page of 200,000 events loads as fast as the first. The case **Timeline** has the same events next to the rest of the case.

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

The runner writes bounded raw JSON per plugin and a manifest under the evidence storage tree, stores run and plugin metadata in PostgreSQL, and indexes normalized `memory_system_info`, `memory_process`, `memory_process_edge`, selected memory artifacts, and raw-first process observations only into memory-scoped indices. It never writes to the existing disk events index.

Each profile plugin executes independently. If one optional plugin fails or is unavailable, Kairon records the plugin terminal state and continues with later plugins where safe. The profile is marked `completed_with_errors`; successful plugin output remains available for normalization and reindexing. A valid empty JSON result is successful with zero observations. Invalid or partial JSON is a plugin failure.

Plugin availability states are `available`, `unsupported_by_installed_volatility`, `unsupported_for_platform`, and `disabled_by_configuration`. The catalogue shows plugin counts and unavailable-plugin reasons. Missing optional plugins do not make the whole memory backend unavailable.

Suspicious memory output is neutral forensic telemetry. `windows.malfind` and `windows.vadinfo` rows are described as suspicious memory regions reported by Volatility; Kairon does not automatically classify a region as malware and does not create Findings from these rows.

Process differences are presented neutrally. A `psscan`-only process is shown as “Not present in pslist result” and “Requires analyst review”; Kairon does not label it as malware, rootkit activity, or compromise.

Automatic symbol download is not initiated by Kairon. If Volatility cannot satisfy plugin requirements, the run fails safely and reports a sanitized error such as `PLUGIN_REQUIREMENTS_UNSATISFIED`.

Configuration:

- `MEMORY_ANALYSIS_ENABLED=false`
- `MEMORY_ALLOW_EXTERNAL_TOOL_EXECUTION=false`
- `MEMORY_UPLOAD_ENABLED=false`
- `MEMORY_UPLOAD_MAX_BYTES=34359738368` (32 GiB default; the startup validator rejects any value below 10 GiB)
- `MEMORY_UPLOAD_CHUNK_SIZE_BYTES=67108864` (64 MiB default)
- `MEMORY_UPLOAD_STAGING_ROOT=`
- `MEMORY_UPLOAD_ALLOWED_EXTENSIONS=.raw,.mem,.vmem,.dmp,.lime`
- `VOLATILITY3_COMMAND=vol`
- `MEMPROCFS_COMMAND=memprocfs`
- `MEMPROCFS_LIBRARY=/opt/memprocfs/vmm.so`
- `MEMORY_BACKEND_CHECK_TIMEOUT_SECONDS=10`
- `MEMORY_BACKEND_STATUS_CACHE_SECONDS=60`
- `MEMORY_PREFERRED_BACKEND=volatility3`
- `MEMORY_JOB_TIMEOUT_SECONDS=900`
- `MEMORY_PLUGIN_TIMEOUT_SECONDS=600`
- `MEMORY_PLUGIN_OUTPUT_MAX_BYTES=10485760`
- `MEMORY_WORKER_CONCURRENCY=1`
- `MEMORY_ALLOWED_PLUGINS=windows.info,windows.pslist,windows.pstree,windows.psscan,windows.cmdline,windows.envars,windows.getsids,windows.privileges,windows.netscan,windows.netstat,windows.dlllist,windows.ldrmodules,windows.handles,windows.modules,windows.driverscan,windows.malfind,windows.vadinfo,windows.consoles,windows.cmdscan,windows.filescan,kairon.findevil,memprocfs.findevil,kairon.psreadline,linux.pslist,linux.pstree,linux.sockstat,linux.bash`
- `MEMORY_ALLOWED_PROFILES=metadata_only,processes_basic,processes_extended,network_basic,modules_basic,handles_basic,kernel_basic,suspicious_memory,shell_history_basic,files_basic,find_evil`
- `MEMORY_DEFAULT_PROFILE=metadata_only`
- `MEMORY_PROCESS_PROFILE_ENABLED=false`
- `MEMORY_MAX_PROCESS_ROWS=100000`
- `MEMORY_MAX_COMMAND_LINE_LENGTH=16384`
- `MEMORY_MAX_RAW_FIELD_LENGTH=65536`
- `MEMORY_RAW_OUTPUT_RETENTION_ENABLED=true`
- `MEMORY_SYMBOL_NETWORK_ACCESS_ENABLED=false`

Managed symbol acquisition remains a separate, disabled-by-default control
plane. See [Managed Windows symbols](memory_symbols.md). Normal memory analysis
continues to run offline even after a reviewed symbol has been cached.
The optional fetcher never triggers process profiles or an automatic metadata
retry.

Command settings are administrator-controlled and require trusted server access to change. Shell fragments and embedded arguments are rejected.

## Scope Boundary

The current runner scope is isolated memory analysis only. MemProcFS is used for its forensic scan only (FindEvil and the timelines above). It does not add credential extraction, memory dumping, process dumping, DLL dumping, malware verdicts or hybrid correlation; files are recovered only on request and for PowerShell history files.
