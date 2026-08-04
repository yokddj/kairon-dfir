# Parser Coverage Matrix

Kairon supports a growing set of Windows, Linux, and memory artifacts. This page describes exact parser coverage. It is not a promise of complete forensic coverage.

The structured source of truth is [`docs/data/parser-coverage.json`](data/parser-coverage.json). Evidence upload also records platform selection; see [`Evidence Platform Selection`](evidence-platforms.md).

## Status Meanings

| Status | Meaning |
| --- | --- |
| `stable` | Recognized and ingested in normal workflows or explicit supported actions. |
| `partial` | A parser or normalization path exists, but coverage is scoped, source-dependent, or not complete. |
| `experimental` | Works for specific cases and may change. Treat output as analyst-assistive. |
| `planned` | Documented intent, not implemented. |
| `unsupported` | Do not expect parsed results. Detection, if any, is only a placeholder or inventory signal. |
| `deprecated` | Avoid using; kept only for historical reference. |

## General Matrix

| Family | Status | Input formats | Source tools | Main views | Key limitations |
| --- | --- | --- | --- | --- | --- |
| Windows Event Logs / EVTX | stable | EVTX, CSV, JSON, JSONL | EvtxECmd, Velociraptor, KAPE | Artifact Explorer, Search, Timeline, Detections, Command History, Process Graph | Field richness depends on event payload and audit policy. |
| $MFT / MFTECmd | stable | CSV, JSON, JSONL, raw $MFT inventory | MFTECmd, KAPE, Velociraptor | Artifact Explorer, Search, Timeline | Full indexing is explicit because volume can be high. |
| USN Journal | partial | CSV, JSON, JSONL | MFTECmd parsed output | Artifact Explorer, Search, Timeline | No active raw UsnJrnl2Csv backend. |
| Prefetch | stable | PF, CSV | native raw parser, PECmd CSV | Artifact Explorer, Search, Timeline | Prefetch has no parent process or command line. |
| Registry / RECmd | partial | CSV, raw hives | RECmd, KAPE, Velociraptor | Artifact Explorer, Search, Timeline | Not every registry key has a semantic parser. |
| LNK | stable | LNK, CSV | native raw parser, LECmd | Artifact Explorer, Search, Timeline | LNK interaction is not guaranteed execution. |
| Jump Lists | stable | automaticDestinations, customDestinations, CSV | native raw parser, JLECmd | Artifact Explorer, Search, Timeline | Recent-item activity is not direct execution proof. |
| Amcache | stable | Amcache.hve, CSV | native raw parser, AmcacheParser | Artifact Explorer, Search, Timeline | Inventory/presence context, not proof of execution. |
| Shimcache / AppCompat | stable | CSV, registry-derived rows | AppCompatCacheParser, ShimCacheParser | Artifact Explorer, Search, Timeline | Execution semantics are cautious and OS-dependent. |
| Scheduled Tasks | stable | XML, CSV, JSON, JSONL | Task Scheduler XML, KAPE, Velociraptor | Artifact Explorer, Search, Timeline, Detections | Presence requires context. |
| Services | stable | CSV, registry-derived rows | Velociraptor, RECmd, KAPE | Artifact Explorer, Search, Timeline, Detections | Not every service is malicious. |
| Autoruns / ASEP | partial | CSV, TSV, XML, JSON, JSONL | Sysinternals Autoruns, KAPE | Artifact Explorer, Search, Timeline, Detections | Some ASEP sources are inventory-only. |
| Defender | stable | EVTX, CSV, JSON, JSONL, LOG, DetectionHistory | Defender logs, KAPE, Velociraptor | Artifact Explorer, Search, Timeline, Detections | No-data is common and is not parser failure. |
| PowerShell | stable | EVTX, CSV, JSON, JSONL, TXT, PS1 | EvtxECmd, KAPE, Velociraptor | Artifact Explorer, Search, Timeline, Command History, Process Graph | PSReadLine often lacks reliable forensic timestamp. |
| Browser | stable | SQLite, CSV, JSON, JSONL | native SQLite parser, KAPE, Velociraptor | Artifact Explorer, Search, Timeline | Credential and cookie stores are intentionally not parsed. |
| Recycle Bin | stable | $I raw, CSV, JSON, JSONL | native $I parser, RBCmd | Artifact Explorer, Search, Timeline | $I/$R pairing depends on available files. |
| USB | partial | SetupAPI log, CSV, JSON, JSONL, TXT, registry rows | KAPE, Velociraptor | Artifact Explorer, Search, Timeline | USB presence does not prove exfiltration. |
| BITS | partial | CSV, JSON, JSONL, TXT, qmgr inventory | bitsadmin output, KAPE | Artifact Explorer, Search, Timeline, Detections | Raw qmgr support may be inventory-only. |
| Network / DNS / WLAN | partial | CSV, JSON, JSONL, TXT, XML, hosts file | Velociraptor, netsh, ipconfig | Artifact Explorer, Search, Timeline | Many outputs are configuration/context, not events. |
| Cloud Sync | partial | CSV, JSON, JSONL, LOG, TXT, INI | KAPE, Velociraptor, manual collections | Artifact Explorer, Search, Timeline | Does not prove exfiltration by itself. |
| WMI | partial | CSV, JSON, JSONL, EVTX, registry rows | Autoruns, Velociraptor, KAPE | Artifact Explorer, Search, Timeline, Detections | Raw WMI repository parsing is incomplete. |
| Shellbags | partial | CSV | SBECmd output | Artifact Explorer, Search, Timeline | Raw hive shellbag extraction is not stable. |
| SRUM | partial | CSV, JSON, JSONL, SRUDB inventory | SrumECmd parsed output | Artifact Explorer, Search, Timeline | SrumECmd cannot run in current Linux deployment. |
| Email | experimental | EML, MBOX, PST/OST inventory | manual collections, KAPE, Velociraptor | Artifact Explorer, Search | PST/OST support is inventory-oriented. |
| Windows UI local DBs | partial | CSV, raw DB inventory | manual collections, KAPE, Velociraptor | Artifact Explorer, Search, Timeline | Many raw DB files are preserved but not fully parsed. |
| Memory | experimental | RAW, DMP, VMEM, LIME, AFF4 | Volatility 3 optional external backend | Memory views, Process Graph | Isolated from global Search/Timeline/Detections. |
| PCAP / network captures | experimental | PCAP, PCAPNG, Zeek-style outputs | manual collections, Zeek outputs | Artifact Explorer, Search | Not complete PCAP forensic coverage. |
| Sigma/YARA rule files | stable | YAML, YML, YAR, YARA | manual rule upload | Detections, Rules | Rule files are detection content, not evidence artifacts. |

## Format Matrix

| Format | Typical supported families |
| --- | --- |
| EVTX | Windows Event Logs, Defender, PowerShell, WMI Activity, USB/PNP when exported as event rows. |
| CSV / JSON / JSONL | Most parsed Windows artifacts when columns match known collectors or Kairon detectors. |
| SQLite | Browser history/downloads for Chromium and Firefox style stores. |
| XML | Scheduled Tasks and WLAN profiles. |
| Raw registry hives | Scoped user activity and selected registry-derived families only. |
| RAW / DMP / VMEM / LIME / AFF4 | Memory workflow only. |
| PCAP / PCAPNG | Experimental network-capture handling only. |

## Linux Artifact Support

Linux artifacts are now supported with partial parser coverage. Evidence from Linux triage collections is ingested and searchable across 12 artifact families.

See [docs/linux-artifacts.md](linux-artifacts.md) for detailed per-family documentation and collection layout.

| Family | Status | Main sources | Key Fields |
| --- | --- | --- | --- |
| Linux Authentication | partial | auth.log, secure | timestamp, username, process, source_ip, auth_method, event_action |
| Linux Syslog | partial | syslog, messages, kern.log | timestamp, detected_host, process, pid, severity, message |
| Linux Audit | partial | audit.log | timestamp, audit_type, uid, pid, exe, command, success |
| Linux Shell History | partial | .bash_history, .zsh_history | username, shell, command, source_file |
| Linux Cron | partial | crontab, cron.d/* | schedule, username, command, source_file |
| Linux Systemd Units | partial | *.service, *.timer | unit_name, unit_type, exec_start, wanted_by |
| Linux SSH Artifacts | partial | authorized_keys, known_hosts, sshd_config | key_type, key_fingerprint, host_pattern, option, value |
| Linux Identity | partial | passwd, group, shadow | username, uid, gid, home, shell, group_name |
| Linux Sudoers | partial | sudoers, sudoers.d/* | principal, host_spec, run_as, command_spec, options |
| Linux Package Logs | partial | dpkg.log, yum.log, dnf.log | timestamp, package_manager, action, package, version |
| Linux Network Config | partial | hosts, resolv.conf, interfaces, netplan | config_type, interface, address, gateway, dns |
| Linux OS Information | partial | os-release, hostname, /proc/version | hostname, os_name, os_version, kernel_version |
| Linux Memory Images | experimental | .raw, .mem, .lime | filename, size_bytes, sha256, effective_platform |

macOS artifact support remains unsupported.

## Collector Compatibility

Kairon documents compatible outputs, but does not redistribute third-party collector binaries. Users are responsible for obtaining and using third-party tools according to their licenses.

| Collector / Tool | Compatibility notes |
| --- | --- |
| KAPE | Good source for EZ Tools CSV output and common Windows artifacts. Coverage depends on selected targets/modules. |
| Velociraptor | Supported for ZIP discovery, selected artifact outputs, browser SQLite and several Windows triage outputs. |
| Eric Zimmerman tools | EvtxECmd, MFTECmd and RECmd are primary supported parsed-output paths. LECmd, JLECmd, AmcacheParser and AppCompatCacheParser are advanced or compatible-output paths. SrumECmd and SBECmd have limitations in the current deployment. |
| Hayabusa | Detection-style output may be recognized as EVTX/detection context when exported to compatible structured rows. It is not a replacement for raw EVTX parsing. |
| Chainsaw | Not documented as a stable parser family. Compatible outputs may be searchable if exported as generic CSV/JSON with recognizable fields, but no first-class support is claimed. |
| SIFT | Kairon does not integrate SIFT as a collector. Files exported from SIFT workflows may be ingested if they match supported formats. |
| Manual ZIP collections | Supported when files match recognized filenames, extensions or headers. Unsupported files are preserved/detected but may not generate artifacts. |

## Interpreting Processing Queue Results

- `parser failed`: a parser was applicable but recorded an error. Review Processing details and parser error text.
- `parser not applicable`: the evidence did not contain a recognized artifact for that parser family.
- `unsupported format`: Kairon may preserve or inventory the file, but no parsed results should be expected.
- `no artifacts found`: the parser or source can be valid but legitimately empty.
- `partial support`: some fields/views are available, but full forensic semantics are not guaranteed.

## Not Supported Yet

- macOS artifact support is not implemented.
- Virtual Disk Upload is not implemented.
- Raw Shellbags hive parsing is not stable.
- Raw SRUDB.dat parsing is not stable in the current Linux deployment.
- Full PCAP forensics is not claimed.
- Browser credential/cookie stores are intentionally not parsed.
