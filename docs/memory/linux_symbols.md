# Linux memory symbols

Volatility 3 reads Linux memory through a symbol file (ISF) built for the exact kernel that was running: structure layouts move between kernel builds, so there is no generic one. Until one is in place, a Linux memory image's analysis is blocked (`BLOCKED_SYMBOLS`) and the evidence's memory page shows **Linux memory symbols** with the expected kernel.

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

## Kernels before 2.6.29

Kairon starts Linux plugins through `app.services.memory.volatility_legacy_linux`, which bridges two places where Volatility 3 assumes a newer kernel: process user and group ids are read from `task_struct` when there is no `task->cred`, and a listening IPv4 socket's destination is read from `inet_sock.daddr` when `sock_common` has no `skc_daddr`. On newer kernels nothing changes.

Checked with the Ulysses CTF (Debian 5, kernel `2.6.26-2-686`, its `Debian5_26.zip`): processes with start times, the process tree, bash history and sockets, including the attacker's reverse shell.
