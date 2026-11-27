# macOS Support (UAC collections)

**Status: Experimental.** Kairon parses macOS from **UAC collections** only, and from them only the
artifacts listed on this page. Disk images of a Mac (APFS) and other macOS collectors are not
supported.

## Accepted collections

A UAC ([Unix-like Artifacts Collector](https://github.com/tclahr/uac)) run on the Mac, uploaded as the
`.tar.gz` UAC writes (or a ZIP or folder holding its output):

```bash
sudo ./uac -p ir_triage /Volumes/USB/output   # triage
sudo ./uac -p full /Volumes/USB/output        # full
```

Run UAC as root and, where possible, from a terminal with **Full Disk Access**: without it macOS
withholds some files from any process (Safari's history, the per-user TCC database, Mail), and the
collection simply lacks them.

### How a UAC collection is recognised

Kairon looks for UAC's own `uac.log` beside its output folders (`[root]/`, `live_response/`,
`bodyfile/`, `hash_executables/`) and reads the header UAC writes there: operating system, host
name, time zone, architecture, UAC version and profile. The command line is not kept (it holds the
output path of the machine that ran UAC). The wizard's preflight reads the same header, also from a `.tar.gz`
(only the first members of the stream, not the whole archive), and shows the platform before the
upload.

- `Operating system: macos` makes the evidence a macOS collection whatever its file name, and its
  platform macOS (a Mac's `/private/var/log/` looks like Linux's `/var/log/` to path markers).
- `Operating system: linux` makes it a Linux collection, read by the Linux parsers; see
  [Linux Support](../linux/linux-support.md). UAC's live-response output is parsed on both (below).
- The host name UAC recorded is a host candidate, and its time zone is used for the times UAC's
  command output prints without one.

Selecting **macOS (UAC)** as the evidence platform in the wizard has the same effect on a collection
whose `uac.log` is missing.

## What is parsed: a closed list

UAC's `full` profile also copies every `*.log`, `*.csv`, `*.json`... it finds on the disk —
documents, other tools' data, even other evidence. None of that is a macOS artifact, and reading it
with filename heuristics produced Windows and Linux events from files that only shared a name. So in
a macOS collection **only the artifacts below are read**; every other file stays in the evidence and
is counted (`macos_collection_summary.files_not_parsed` in the evidence metadata), not indexed.

### macOS artifacts

| Artifact | Location | What you get | Family |
| --- | --- | --- | --- |
| LaunchAgents / LaunchDaemons | `/Library/LaunchAgents`, `/Library/LaunchDaemons`, `~/Library/LaunchAgents` | One row per job: label, program and arguments, triggers (at load, kept alive, interval, calendar, watched paths), user, disabled flag. Timed by the plist's modification time. | `macos_launchd` |
| Quarantine events | `~/Library/Preferences/com.apple.LaunchServices.QuarantineEventsV2` | Files marked as downloaded: the app that saved them, when, data and origin URLs when the app recorded them. | `macos_quarantine` |
| KnowledgeC | `~/Library/Application Support/Knowledge/knowledgeC.db`, `/private/var/db/CoreDuet/Knowledge/knowledgeC.db` | App usage (bundle id, start, end, duration), web and media usage (URL), app intents, display on/off, device locked, Bluetooth connections, notifications. | `macos_knowledgec` |
| TCC | `/Library/Application Support/com.apple.TCC/TCC.db`, `~/Library/Application Support/com.apple.TCC/TCC.db` | Privacy permissions per app (Full Disk Access, Accessibility, Screen Recording, camera, microphone...): allowed, denied or limited, why, and when last changed. | `macos_tcc` |
| Local accounts and groups | `/private/var/db/dslocal/nodes/Default/users/*.plist`, `groups/*.plist` | Name, UID, primary GID, home, shell, real name; creation, last password change and last failed login from `accountPolicyData`; group members (who is in `admin`). Password hashes (`ShadowHashData`) are never read. | `macos_accounts` |
| Shared file lists | `~/Library/Application Support/com.apple.sharedfilelist/*.sfl2`, `.sfl3`, `.sfl4` (also `ApplicationRecentDocuments/<bundle id>.sfl*`) | Recent documents and applications, per-application recent documents, recent servers and hosts, Finder favourites: the item's name and the path, volume and creation date its bookmark keeps, in list order. Items have no time of their own; the list file's modification time is `macos.list_modified`. | `macos_recent_items` |
| System version | `/System/Library/CoreServices/SystemVersion.plist` | Product name, version and build, as Host Facts. | `macos_system_info` |
| install.log | `/private/var/log/install.log` and rotated copies | Every line with its own UTC offset; finished installations (`Installed "Name" (version)`) and package receipts marked. | `macos_logs` |
| wifi.log | `/private/var/log/wifi.log` and rotated `.bz2` copies | Lines with the year and time zone resolved from the host. Repeats folded (below). | `macos_logs` |
| launchd.log | `/private/var/log/com.apple.xpc.launchd/launchd.log*` | launchd's own log with its levels. Repeats folded (below). | `macos_logs` |

launchd.log and wifi.log are mostly the same few messages repeated thousands of times. Lines that
differ only in their numbers (PIDs, counters, addresses) within the same hour are folded into the
first one, which keeps its exact text and time and gains `macos.repeat_count` and
`macos.last_seen` (and "[repeated N times until HH:MM:SS UTC]" in its message). Every distinct
message stays; only the repeats' numbers are lost. On a test Mac this took 165,000 launchd lines
to 56,000 rows and 100,000 wifi lines to 8,700.

### Unified Logs

The main log of a modern Mac (`/private/var/db/diagnostics/*.tracev3` with
`/private/var/db/uuidtext`), decoded by Mandiant's
[`unifiedlog_iterator`](https://github.com/mandiant/macos-UnifiedLogs) (Apache-2.0, a pinned
release binary in the worker image). A Mac writes tens of millions of entries, so by default only
the subsystems and processes of forensic value are indexed (`macos_unified_logs`):

- subsystems: `com.apple.loginwindow*`, `com.apple.authd*`, `com.apple.Authorization*`,
  `com.apple.opendirectoryd*`, `com.apple.syspolicy*` (Gatekeeper), `com.apple.xprotect*`,
  `com.apple.XProtectFramework*`, `com.apple.MRT*`, `com.apple.DiskArbitration*`,
  `com.apple.install*`, `com.apple.packagekit*`, `com.apple.screensharing*`, `com.apple.kext*`;
- processes, for their lines without a subsystem (a process's lines under another subsystem are
  its libraries talking): `sudo`, `su`, `sshd`, `sshd-session`, `screensharingd`, `loginwindow`, `authd`,
  `opendirectoryd`, `installer`, `installd`, `system_installd`, `syspolicyd`, `XProtect`,
  `XprotectService`, `MRT`, `kextload`, `kmutil`, `diskarbitrationd`.

On the test Mac, decoding its 42.5 million entries took about 12 minutes of the ingest. Each row
keeps the time (UTC), subsystem, category, process and its path, PID, effective UID,
log type (Fault entries are medium severity, Error low) and the tracev3 file. Repeats are folded as
in launchd.log. TCC's own log is left out (it is very verbose; `TCC.db` already gives the
decisions). `MACOS_UNIFIED_LOGS_MODE=all` indexes every entry instead, held in memory while
parsed -- only on a worker with memory to spare. The tool's own warnings ("Unknown number size
support", "Failed to read UUIDText") are expected on real data.

### FSEvents (searched on demand)

Each volume's change journal (`/.fseventsd`, `/System/Volumes/Data/.fseventsd`): files and folders
created, removed, renamed or modified, including files that no longer exist. A Mac holds millions
of records (17 million on the test Mac), so they are **not indexed**: **File Changes (FSEvents)**
in the side menu (shown when the case has macOS evidence) searches them on demand by path text, change kind and item
type, newest first (about 6-11 seconds over 17 million records). The evidence lists one
`macos_fsevents` artifact per journal, as detected, not parsed.

- Pages of versions 1, 2 and 3 (`1SLD`, `2SLD`, `3SLD`) are read.
- Records have no time of their own. They are ordered by event id; the **page written** time is
  the modification time of the page file, the latest moment the change can have happened.
- Flags: the item-type bits were checked on a real Mac (every directory record had 0x01000000,
  every file record 0x00800000); the change bits follow the on-disk order documented by
  FSEventsParser. A bit outside that list is shown by its hex value, never named.
- API: `GET /api/cases/{case}/evidences/{evidence}/macos/fsevents?path_contains=...&changes=removed&item_type=file`
  and `.../macos/fsevents/summary`.

### Unix artifacts at their macOS locations

These share their format with Linux and are read by the Linux parsers, so they appear in the same
views (Command History, persistence, SSH, sudoers); their events are marked as macOS (`os.type:
macos`), and the user of a home-directory file comes from `/Users/<name>`.

| Artifact | Location | Family |
| --- | --- | --- |
| Shell histories | `~/.zsh_history`, `~/.bash_history`, `~/.sh_history`, `~/.zsh_sessions/*.history` (also root's, `/var/root`) | `linux_shell_history` |
| Shell start-up files | `~/.zshrc`, `~/.zprofile`, `~/.bash_profile`..., `/etc/zshrc`, `/etc/profile`... | `linux_persistence` |
| PAM | `/etc/pam.d/*` | `linux_persistence` |
| sudoers | `/etc/sudoers`, `/etc/sudoers.d/*` | `linux_sudoers` |
| SSH | `/etc/ssh/sshd_config`, `ssh_config`, `~/.ssh/known_hosts`, `authorized_keys`, `config` | `linux_ssh` |
| Cron | `/private/var/at/tabs/*`, `/usr/lib/cron/tabs/*`, `/etc/crontab` | `linux_cron` |
| Hosts and time zone | `/etc/hosts`, `/etc/localtime` | `linux_network`, `linux_timezone` |
| system.log | `/private/var/log/system.log*` | `linux_generic_log` |

`/etc`, `/var` and `/tmp` are links to `/private/...` on macOS; a file collected under both paths is
read once.

### Browsers

Chromium-based browsers (Chrome, Brave, Edge, Chromium, Vivaldi, Arc, Opera) `History`, Firefox
`places.sqlite` and Safari `History.db` (visits, titles, search terms), in the Browser view. Cookie
and password stores are never parsed.

### UAC live response (macOS and Linux)

UAC saves the output of the commands it runs under `live_response/`, named after each command. The
outputs below are parsed on every UAC collection, macOS or Linux, into the `uac_live_response`
family; everything else under `live_response/`, plus `bodyfile/`, `hash_executables/` and the
find-based listings under `system/`, is kept in the evidence as *detected, not parsed*.

| Output | What you get |
| --- | --- |
| `process/ps_*lstart*.txt` | Running processes: PID, parent PID, user, terminal, state, command line, and the start time (in the host's time zone, converted to UTC). |
| `network/netstat_-an*.txt` | Connections and listening sockets (BSD/macOS and Linux address formats; PID and program when `netstat -p` printed them). |
| `network/lsof_-*i*.txt` | Network files with the process and UID that held them (macOS). |
| `system/launchctl_list.txt` | Jobs launchd had loaded: label, PID if running, last exit status. |
| `system/last*.txt` | Login sessions, reboots and shutdowns; the year `last` does not print is inferred backwards from the collection date. |
| `packages/softwareupdate_--history*.txt` | macOS updates installed, with their date. |
| `packages/brew_list_*.txt`, `pkgutil_--packages.txt` | Installed Homebrew formulae and casks, installer packages. |
| `system/uname_-a.txt`, `system/sw_vers.txt` | Kernel, architecture, product name and version, as Host Facts. |
| `uac.log` (UAC's own) | Host name, FQDN and time zone UAC recorded, as Host Facts (`/etc/localtime` is a link in UAC's tar, which is not followed). |

All of it is a snapshot of the moment UAC ran. Connections, loaded jobs and installed packages are
timed by the start of the collection (`timestamp_status: collection_time`) and stay off the
Timeline; process start times and logins are real events and appear on it.

## Where the results go

- **Search and Timeline**, filterable by family (`macos_launchd`, `macos_knowledgec`...) and by
  `macos.*` / `uac.*` fields.
- **Artifact Views**: a "macOS Artifacts" panel with one button per macOS family present in the
  case (and the shared Unix families), besides the artifact-type selector.
- **macOS workbench** (`/cases/<id>/mac`): Command History, App & Device Usage (KnowledgeC),
  LaunchAgents & LaunchDaemons, Downloads (Quarantine), Recent Items, Privacy Permissions (TCC),
  File System Events (FSEvents, searched on demand), Live Response.
- **Host Information**: product name and version, kernel, architecture and time zone as Host Facts;
  local accounts from dslocal, with group membership (including `admin`), in the host's users.
- **Sigma**: Linux rules run on the shared Unix families as they do on Linux. There are no macOS
  process-creation events (those come from the Endpoint Security framework, not collected by UAC),
  so macOS `process_creation` rules have nothing to match.

## Review leads

Flags are leads for an analyst, never detections:

- A launchd job whose program is in a temporary or shared location (`/tmp`, `/private/tmp`,
  `/var/folders`, `/Users/Shared`), in a hidden directory, or that runs a shell or script
  interpreter with inline code (`bash -c`, `osascript -e`, `python -c`...) is raised to medium.
- A TCC grant of Full Disk Access, Accessibility, Screen Recording, Input Monitoring, synthetic
  input, Endpoint Security or Remote Desktop carries the tag `sensitive_permission`, without a
  higher severity (many legitimate tools need them).
- Accounts with a UID below 500 are the system's own, created with the OS: searchable, kept off
  the Timeline.

## Not parsed

- **ASL** binary logs, **Biome** and **SEGB** streams, Spotlight, Keychains, Mail and Messages: kept in the evidence, not read.
- **UAC's bodyfile** (`bodyfile/bodyfile.txt`) and hash lists: kept, not indexed.
- LaunchAgents and LaunchDaemons under `/System/Library` and `/Library/Apple`: Apple's own, on the
  sealed system volume, not listed.
- Disk images of a Mac (APFS) and collections from tools other than UAC.
- Group membership (who is in `admin`) needs `/private/var/db/dslocal/nodes/Default/groups/`; UAC 3.4.0's `full` profile did not collect it on the collection tested, so the host's users may show no groups.

## Validation

Validated on one UAC 3.4.0 `full` collection of a recent macOS release on Apple silicon, and with
synthetic files in the tests. Not yet checked on real data: Intel Macs and older macOS releases
(KnowledgeC and TCC columns change between releases; the parsers read the columns that exist),
Safari's `History.db`, Firefox on macOS, a per-user `TCC.db`, the `ir_triage` profile, and the
live-response output of a Linux UAC collection (its formats are covered by synthetic tests only).
