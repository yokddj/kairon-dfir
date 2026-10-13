# Linux memory symbols

Volatility 3 reads Linux memory through a symbol file (ISF) built for the exact kernel that was running: structure layouts move between kernel builds, so there is no generic one. Until one is in place, a Linux memory image's analysis is blocked (`BLOCKED_SYMBOLS`) and Kairon asks for it in two places, both showing **Linux memory symbols** with the expected kernel:

- the upload wizard's **Memory Preparation** step;
- the evidence's memory page, where **Evidence readiness** opens itself and is flagged **Needs attention**. The analysis catalogue shows its profiles as **Blocked — Symbols missing** meanwhile.

The upload is off by default; with `MEMORY_LINUX_SYMBOL_MANUAL_IMPORT_ENABLED=true` in the deployment's `.env` it is accepted, and until then the panel says so instead of offering a file picker.

Upload one of these there:

- **A Volatility 3 ISF** (`.json` or `.json.xz`), for example produced by `dwarf2json` from the kernel's debug package.
- **A Volatility 2 Linux profile** (`.zip` with `module.dwarf` and `System.map`), the format CTFs and older guides ship (for example `Debian5_26.zip`). Many old kernels only ever had one.

The upload is validated on the memory worker and, when it matches, stored in the offline Linux symbol cache, where other evidence with the same kernel reuses it.

## How a Volatility 2 profile is converted

`app.services.memory.linux_vol2_profile` runs in an isolated subprocess (10-minute limit) and turns the profile into an ISF:

- structures, unions, enums, typedefs and bitfields come from `module.dwarf`; symbol addresses from `System.map`;
- the kernel banner, which Volatility 3 uses to pick the ISF, is read from the memory image. It is only accepted where System.map's `linux_banner` address points (directly, or moved by a 2 MiB-aligned relocation; raw, LiME and ELF images), so a profile for another build of the same release is refused (**Symbols do not match this memory dump**). A profile for another release is refused by name;
- the types of the kernel globals Volatility 3 reads (`init_task`, `wall_to_monotonic`, `socket_file_ops`...) are added, since a module's dwarfdump does not record them, together with `socket_alloc` and empty placeholders for structures that older kernels lack (`struct cred` appeared in 2.6.29);
- 32-bit PAE kernels are told apart by the size of `pte_t`.

## What a Linux image shows

The analyses, tabs and Overview families offered for a memory image follow its detected platform: only those a registered plugin can produce for it (`app.services.memory.capability_registry`). On Linux that is processes (with the process graph and timeline), network sockets and shell history; Windows-only views such as Handles, VADs, Drivers, Files, Find Evil or MemProcFS are not listed. An image whose platform is not identified yet keeps every view.

## Kernels before 2.6.29

Kairon starts Linux plugins through `app.services.memory.volatility_legacy_linux`, which bridges two places where Volatility 3 assumes a newer kernel: process user and group ids are read from `task_struct` when there is no `task->cred`, and a listening IPv4 socket's destination is read from `inet_sock.daddr` when `sock_common` has no `skc_daddr`. On newer kernels nothing changes.

Checked with the Ulysses CTF (Debian 5, kernel `2.6.26-2-686`, its `Debian5_26.zip`): processes with start times, the process tree, bash history and sockets, including the attacker's reverse shell.
