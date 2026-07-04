# Machine-Identification Vectors & How to Fake Them

**Status of this doc:** research catalogue + implementation roadmap. It enumerates the
kernel-level ways an untrusted child can identify the host machine, on **Linux**, **macOS**,
and **Windows**, and for each the mechanism we could use to fake it. Raincoat is Linux-first;
the macOS/Windows sections are forward-looking design notes so the model generalizes.

Positioning is unchanged from `docs/SPEC.md`: Raincoat is a *lightweight privacy sandbox*, not
a perfect boundary. Faking identity is **best-effort** and layered — some vectors are closed
cheaply, some need a syscall supervisor, and a hard floor needs a VM we deliberately do not use.

---

## The three tiers (why some vectors are cheap and some are impossible)

A child learns "what machine am I on?" through three distinct channels, in ascending cost to
neutralize:

| Tier | Channel | Neutralize with | Reaches |
|------|---------|-----------------|---------|
| **1. Pseudo-files** | reads of `/proc`, `/sys`, `/etc`, registry, sysctl-backed files | bind-mount an overlay / deny path | any reader |
| **2. Syscalls / kernel calls** | `uname()`, `sysinfo()`, `sysctl()`, `NtQuerySystemInformation`, netlink | intercept the call and rewrite the result | any reader, incl. static/Go binaries |
| **3. CPU instructions** | `CPUID`, `RDTSC`, `RDRAND` — execute in user mode, never trap | **nothing short of a hypervisor** | everything |

Tier 1 is `--ro-bind` of a generated file (Linux) — already done for cpuinfo/kernel/machine-id.
Tier 2 is the interesting frontier and the subject of the implementation here. Tier 3 is the
honest hard limit of a "wrapper, not a VM" design: a program running `CPUID` reads the *real*
CPU brand string regardless of anything user space does.

**Key asymmetry:** on Linux, Tier-1 and Tier-2 often expose the *same* datum by two paths.
`uname -r` is the `uname(2)` syscall (Tier 2); `cat /proc/sys/kernel/osrelease` is a file
(Tier 1). Masking only the file leaves the syscall talking — which is exactly why the syscall
supervisor exists. To be consistent, the fake values MUST match across both paths.

---

## Linux

### Tier 2 — syscalls

| Syscall (`x86_64 nr`) | Exposes | How we fake it | Status |
|---|---|---|---|
| `uname(2)` (63) | `sysname`, `nodename` (hostname), `release` (kernel), `version` (build string), `machine` (arch), `domainname` | seccomp user-notify: write a fake `struct new_utsname` into the child's buffer | **implemented** (set `kernel_osrelease`/`kernel_version`) |
| `sysinfo(2)` (99) | `uptime`, load avg, `totalram`/`freeram` (RAM size), swap, process count | seccomp user-notify: write fake `struct sysinfo` | **implemented** (set `mem_total_kb`/`uptime_seconds`) |
| `sched_getaffinity(2)` (204) | logical CPU count (`nproc`) | seccomp user-notify: write a cpu-set with `cpu_count` bits | **implemented** (`cpu_count`) |
| `getcpu(2)` (309) | current CPU/NUMA node → topology inference | user-notify: pin to 0 | low value |
| `clock_gettime(CLOCK_BOOTTIME)` / `CLOCK_MONOTONIC` | uptime, boot correlation | hard — faking time breaks programs; only offset-able | not planned |
| `ioctl(SIOCGIFHWADDR/SIOCGIFCONF)` | interface **MAC** + names | user-notify is awkward (ioctl arg structs); the **isolated-netns jail** (pasta) is the real fix — child sees only a synthetic iface | covered by egress strict jail; else note |
| `socket(AF_NETLINK, NETLINK_ROUTE)` → `RTM_GETLINK` | interface list + **MAC** | same as above — netns isolation, not per-call faking | covered by netns jail |
| `statfs`/`statvfs`/`fstatfs` | fs type + size of mount points → disk fingerprint | user-notify possible; low priority | not planned |
| `getuid/getgid/getgroups` | numeric identity | bwrap userns uid/gid mapping (not a fake — a remap) | out of scope here |

### Tier 1 — pseudo-files (bind-mount overlays)

| Path | Exposes | Status |
|---|---|---|
| `/proc/cpuinfo` | CPU model/family/stepping/microcode/MHz/flags (+ ARM `Serial`) | **masked** (`cpu_vendor_id`/`cpu_model_name`, x86) |
| `/proc/version` | kernel release + **distro build host** + toolchain | **masked** (`kernel_osrelease`/`kernel_version`) |
| `/proc/sys/kernel/osrelease` · `…/version` · `…/ostype` | `uname` mirror | **masked** (`kernel_osrelease`/`kernel_version`) |
| `/proc/cmdline` | boot cmdline: **root/resume disk UUID**, distro boot image, hardware params | **masked** (`kernel_cmdline`) |
| `/proc/stat` | `btime` (boot wall-clock) + per-cpu lines (core count) | **deferred** — a static overlay would freeze the live CPU counters (breaks `top`/`mpstat`), same dynamic-data problem as `mountinfo` |
| `/proc/sys/kernel/hostname` · `…/domainname` | hostname | UTS namespace (`--unshare-uts --hostname`) |
| `/etc/machine-id` · `/var/lib/dbus/machine-id` | stable per-install ID | **masked** (`machine_id`) |
| `/proc/sys/kernel/random/boot_id` | per-boot UUID (correlation) | **masked** (`boot_id`) |
| `/proc/meminfo` · `/proc/uptime` · `/proc/loadavg` | RAM size, uptime, load | **masked** (`mem_total_kb` / `uptime_seconds`) |
| `/proc/self/mountinfo` · `/proc/mounts` | **host mount layout + real paths** (username in bind paths, `uid=`, block device, and — self-defeatingly — the `.rc-*` mask mounts themselves) | **hard — no clean mechanism.** A `--ro-bind` over `/proc/self/mountinfo` does NOT reach readers (verified): `self` re-resolves per reading process, so the bind lands on bwrap's own pid dir, not the child's; and there is no `mountinfo` syscall to seccomp. Deferred pending a different mechanism (e.g. mounting cwd at a generic path instead of its host path). |
| `/sys/class/dmi/id/*` (`product_uuid`, `product_serial`, `board_serial`, `chassis_serial`, `sys_vendor`, `product_name`) | SMBIOS/DMI serials + **product UUID** | **not exposed** — Raincoat never mounts `/sys` |
| `/sys/class/net/*/address` | interface **MAC** | **not exposed** — no `/sys` mount |
| `/sys/firmware/dmi/tables/*` · `/dev/mem` | raw SMBIOS | not exposed (no `/sys`, no `/dev/mem`) |
| `/proc/net/tcp` etc. | peer IPs (egress upstream) | handled by egress strict-netns jail |

> The `/sys` win is free and worth stating plainly: because the base sandbox binds only `/usr`
> (+ curated `/etc`, `/proc`, `/dev`), the entire DMI/SMBIOS/MAC surface under `/sys` simply
> does not exist in the child. If a profile ever mounts `/sys`, these re-open and would each
> need an overlay.

### Tier 3 — instructions (unreachable without a VM)

`CPUID` (brand string, family/model, hypervisor-present bit, cache topology, RDRAND support),
`RDTSC`/`RDTSCP` (TSC value + frequency), `RDRAND`/`RDSEED`. These execute in user mode and do
not trap to the kernel, so seccomp cannot see them. Faking requires hardware virtualization
(a hypervisor that intercepts the instruction) — out of scope by design. Documented non-goal.

### Linux faking mechanism (Tier 2): seccomp user-notify

`SECCOMP_RET_USER_NOTIF` (kernel ≥ 5.0; `ADDFD` ≥ 5.9) lets a **supervisor** in user space
service trapped syscalls:

1. Raincoat `fork()`s. The child sets `PR_SET_NO_NEW_PRIVS`, installs a small classic-BPF
   filter that returns `USER_NOTIF` for the identity syscalls and `ALLOW` for everything else,
   and gets back a **listener fd** from `seccomp(SECCOMP_SET_MODE_FILTER,
   SECCOMP_FILTER_FLAG_NEW_LISTENER, …)`.
2. The child sends that fd to the parent over a `socketpair` (`SCM_RIGHTS`), then `execve`s
   bwrap. **seccomp filters survive `execve`**, so bwrap and the eventual target inherit it.
3. The parent (supervisor thread, unfiltered) loops on `SECCOMP_IOCTL_NOTIF_RECV`. For each
   trapped `uname`, it writes a fake `struct new_utsname` into the child's memory
   (`/proc/<pid>/mem` at `args[0]`), guards against PID-reuse with `SECCOMP_IOCTL_NOTIF_ID_VALID`,
   and answers `SECCOMP_IOCTL_NOTIF_SEND` with success.

Why not `LD_PRELOAD`: it only covers dynamically-linked libc callers — a static binary or a Go
program issuing the raw syscall bypasses it. seccomp intercepts at the **syscall boundary**, so
it catches those too. That is the whole reason to prefer it for an untrusted-tool threat model.

Caveats: needs `no_new_privs` (fine; bwrap wants it anyway); the supervisor must run off the
main thread to avoid `waitpid`/notify deadlock; pointer-argument syscalls have a TOCTOU subtlety
(we only *write results*, so we stay in the safe subset); x86_64 only for now (syscall numbers
are per-arch). Values are kept consistent with the Tier-1 file masks above.

---

## macOS (Seatbelt backend + DYLD identity interposer landed)

The macOS **Seatbelt backend** is implemented (filesystem hiding, network, and *env-level*
identity — `USER`/`HOME`/`HOSTNAME`/`TZ`; see `docs/MACOS.md`). The machine-fingerprint *syscall*
faking below — the macOS analog of the Linux Tier-2 seccomp supervisor — is **now implemented too**,
via a `DYLD_INSERT_LIBRARIES` interposer (`src/rc_interpose.c`) rather than seccomp (macOS has no
seccomp-notify). It fakes `gethostname`, `uname`, `getlogin`/`getlogin_r`, `getpwuid`/`getpwnam`, and
`sysctlbyname` (`kern.hostname`, `machdep.cpu.brand_string`, `kern.osrelease`/`kern.osversion`,
`hw.memsize`), driven by the same value-driven config as Linux. The Tier-1 `/proc` overlays +
`uname`/`sysinfo` seccomp hook stay Linux-only and gated OFF on macOS (`supports_proc_overlays =
false`, `supports_seccomp_identity = false`); the new capability `supports_dyld_interpose = true`
gates the interposer path instead.

**The SIP finding that forced an in-process pivot.** Injecting the dylib and running through
`/usr/bin/sandbox-exec` does **not** work: `sandbox-exec` is SIP-protected, and the kernel **strips
`DYLD_INSERT_LIBRARIES`** when `exec`ing a SIP-protected binary — so the injection never reaches the
target (measured: `gethostname` stayed real). The backend therefore applies the SBPL profile
**in-process** via `sandbox_init(profile, 0)` in the forked child and `execvp`s the target itself;
since raincoat and the target are unrestricted, the injection **survives** and the sandbox is still
enforced (both measured). Full write-up in [`docs/MACOS.md`](MACOS.md).

No seccomp; the equivalents are `sysctl`, Mach traps, and IOKit. There is no bind-mount trick
for these (they are not files), so Tier-2 faking means **`DYLD_INSERT_LIBRARIES` function
interposition** (userland, no SIP conflict for non-protected binaries) or a heavier
Endpoint-Security/DriverKit approach.

| Vector | API | Exposes |
|---|---|---|
| `sysctlbyname` | `hw.model`, `hw.machine`, `hw.ncpu`, `hw.memsize`, `machdep.cpu.brand_string`, `kern.osrelease`, `kern.osversion`, `kern.hostname`, `kern.boottime`, `kern.uuid` | model (e.g. `MacBookPro18,3`), arch, cores, RAM, CPU brand, kernel, boot time |
| `gethostuuid(2)` | — | **host UUID** (stable, strong ID; a real syscall) |
| IOKit / IORegistry | `IOPlatformExpertDevice` → `IOPlatformUUID`, `IOPlatformSerialNumber`, `board-id`, `model` | **hardware UUID + serial** (licensing-grade) |
| `getifaddrs` / `NET_RT_IFLIST` sysctl | — | interface **MAC**s |
| Mach `host_info` / `host_statistics64` | — | CPU type, memory |
| `uname(3)` | — | sysname/nodename/release/version/machine |
| `getpwuid`/`getpwnam`(`_r`) · `getlogin`(`_r`) | opendirectoryd | **real login name + home dir** — a *user*-identity leak Seatbelt's path denials do NOT close (the lookup is not a file read) |
| CPUID / `hw.optional.*` | — | Intel: CPUID; Apple Silicon: feature flags via sysctl |

**Faking (implemented).** A `__DATA,__interpose` dylib (`src/rc_interpose.c`) injected with
`DYLD_INSERT_LIBRARIES` interposes `gethostname`, `uname`, `getlogin`/`getlogin_r`,
`getpwuid`/`getpwnam`, and `sysctlbyname` (`kern.hostname`, `machdep.cpu.brand_string`,
`kern.osrelease`/`kern.osversion`, `hw.memsize`). Each field is faked only when its `RC_FAKE_*` env
var is set (unset → real value), the same value-driven contract as the Linux knobs. Raincoat scrubs
`DYLD_*` from the child env and then sets its **own** controlled `DYLD_INSERT_LIBRARIES` value (which
wins over the scrub — the scrub still blocks an *attacker's* injection).

**User identity is now faked.** `getpwuid(getuid())->pw_name`/`->pw_dir` and `getlogin()` are the
opendirectoryd path Seatbelt's file-denials could **not** close (the lookup is not a file read); the
interposer now rewrites them to the fake user/home for injectable targets — closing what `docs/MACOS.md`
previously listed as an un-closable residual leak (the honest caveat stays for non-injectable targets).

**Still future (not yet interposed):** `gethostuuid(2)`, the IOKit `IOPlatformUUID` /
`IOPlatformSerialNumber` pair (the highest-value hardware IDs), and `getifaddrs` MACs. Raincoat does
not fake these today.

**Honest limit — macOS Tier-2 is strictly weaker than Linux Tier-2.** DYLD interposition is the
`LD_PRELOAD`-class technique, and macOS has **no seccomp-notify equivalent**. So it only catches
**dynamically-linked libc callers**: a static binary, or one issuing a raw `sysctl(2)`/Mach trap
directly, bypasses the interposer entirely — with no syscall-boundary backstop (short of Endpoint
Security, which is heavy and entitlement-gated). This is the exact opposite of the Linux argument
for preferring seccomp over `LD_PRELOAD`. On top of that, SIP-protected/`hardened-runtime` binaries
ignore `DYLD_INSERT_LIBRARIES` outright, and CPUID on Intel remains Tier 3. The
`IOPlatformUUID`/`IOPlatformSerialNumber` pair is the highest-value target.

**Consistency requirement.** A datum leaks by multiple paths that must agree or you create a
*tell*: on macOS the interposer must keep `sysctlbyname("kern.hostname")`, `gethostname()`, and
`uname().nodename` identical (and matching `$HOSTNAME`) — the same cross-path rule the Linux
`uname(2)` ↔ `/proc/sys/kernel/osrelease` pairing follows.

---

## Windows (design notes — not implemented)

No seccomp; identity comes from Win32 APIs (over `Nt*` syscalls), the **registry**, **WMI**, and
`GetSystemFirmwareTable`. Tier-2 faking means **API hooking** (IAT/inline hooks, e.g. Detours) or
a filter driver (heavy). Documented for completeness; a Linux-first tool does not implement it.

| Vector | API / location | Exposes |
|---|---|---|
| Registry `MachineGuid` | `HKLM\SOFTWARE\Microsoft\Cryptography\MachineGuid` | **stable machine GUID** (the canonical Windows machine ID) |
| Registry BIOS/board | `HKLM\HARDWARE\DESCRIPTION\System\BIOS` | manufacturer, product, **serials** |
| Registry install | `HKLM\…\Windows NT\CurrentVersion` → `ProductId`, `InstallDate`, `DigitalProductId` | install identity |
| `GetSystemFirmwareTable('RSMB')` | — | raw **SMBIOS** (system UUID + serials) — syscall-level |
| WMI | `Win32_ComputerSystemProduct.UUID`, `Win32_BIOS.SerialNumber`, `Win32_Processor.ProcessorId`, `Win32_BaseBoard.SerialNumber`, `Win32_DiskDrive.SerialNumber`, `Win32_NetworkAdapter.MACAddress` | UUID, serials, MACs |
| `GetComputerNameEx` / `GetUserName` | — | hostname, user |
| `GetNativeSystemInfo` / `GlobalMemoryStatusEx` | — | arch, CPU count, RAM |
| `GetVolumeInformation` / `IOCTL_STORAGE_QUERY_PROPERTY` | — | **volume + disk serial** |
| `GetAdaptersAddresses` | — | interface **MAC**s |
| CPUID | instruction | CPU brand, hypervisor bit |
| TPM 2.0 EK | TBS API | hardware-backed endorsement key |

**Faking:** hook `RegQueryValueEx*`, `GetSystemFirmwareTable`, `GetComputerNameEx`,
`GetAdaptersAddresses`, `DeviceIoControl` (storage IOCTLs), and intercept WMI (`IWbemServices`)
queries. `MachineGuid` and the SMBIOS UUID are the highest-value targets. CPUID and TPM-backed
identity remain Tier 3 / hardware-rooted.

---

## Cross-platform summary of faking mechanisms

| Tier | Linux | macOS | Windows |
|---|---|---|---|
| 1 — files | `--ro-bind` overlay; deny mount | (n/a — not file-backed) | (registry hive redirect, limited) |
| 2 — syscalls | **seccomp user-notify** | `DYLD_INSERT_LIBRARIES` interpose | API hooking (Detours/IAT) / filter driver |
| namespaces | UTS/net/mount ns (hostname, MAC) | — | — |
| 3 — instructions | hypervisor only | hypervisor only | hypervisor only |

## Implementation roadmap

**Done (Linux, value-driven — set the value to mask, omit for the real system value):**

- [x] Tier 1: `/proc/cpuinfo` (`cpu_vendor_id`/`cpu_model_name`)
- [x] Tier 1: `/proc/version` + `/proc/sys/kernel/{osrelease,version}` (`kernel_osrelease`/`kernel_version`)
- [x] Tier 1: `/proc/cmdline` — root/resume disk UUID + distro boot image (`kernel_cmdline`)
- [x] Tier 1: `/etc/machine-id` (`machine_id`); `/proc/sys/kernel/random/boot_id` (`boot_id`)
- [x] Tier 1: `/proc/meminfo` (`mem_total_kb`); `/proc/uptime` + `/proc/loadavg` (`uptime_seconds`)
- [x] Tier 2: `uname(2)` via seccomp user-notify (`kernel_osrelease`/`kernel_version`)
- [x] Tier 2: `sysinfo(2)` via seccomp user-notify (`mem_total_kb`/`uptime_seconds`)
- [x] Tier 1 + Tier 2: **CPU core count** — `/proc/cpuinfo` block count + `sched_getaffinity(2)` (`cpu_count`)
- [x] Path de-identification: `[filesystem].remap_cwd` + `[[filesystem.mount]]` present host paths at neutral sandbox paths (see `MOUNT-REMAP.md`)
- [x] Not exposed at all: DMI serials / product UUID / MAC (Raincoat never mounts `/sys`)

**Done (cross-platform architecture + macOS):**

- [x] Capability-gated per backend: `supports_proc_overlays` / `supports_seccomp_identity` /
      `supports_path_remap` / `supports_dyld_interpose`. Tier-1 overlays are portable code gated
      on the flag; the Tier-2 seccomp hook is `#ifdef __linux__` + a Linux-only `seccomp_notify.cpp` TU.
- [x] macOS Seatbelt backend (fs/network/env identity) — see `docs/MACOS.md`
- [x] macOS `DYLD_INSERT_LIBRARIES` interposer — `gethostname`, `uname`, `getlogin`/`getlogin_r`,
      `getpwuid`/`getpwnam`, `sysctlbyname` (hostname/CPU/kernel/RAM/`hw.ncpu`); routes the
      value-driven config to Tier-2 on macOS via an **in-process `sandbox_init` pivot** (SIP strips
      the injection through `sandbox-exec` — measured). Honest limits: libc-caller-only, **no
      seccomp-notify backstop**, SIP/hardened-runtime/static targets opt out — strictly weaker than
      Linux Tier-2. Still future: `gethostuuid`, IOKit UUID/serial, `getifaddrs` MACs.

**Open (candidates):**

- [ ] `uname` on non-x86 arches (per-arch syscall numbers)

**Blocked / deferred (no clean mechanism):**

- [ ] `/proc/self/mountinfo`, `/proc/mounts` — per-reader `self` indirection defeats bind-overlay (verified); no syscall to trap. `remap_cwd` mitigates the *mount-point* path; the mount-*source* field and `uid=`/device remain.
- [ ] `/proc/stat` — a static overlay would freeze the live CPU counters (`btime` is the only static leak; not worth breaking `top`/`mpstat`).
- [ ] `statfs`/`statvfs` syscalls — the path/fd argument resolves in the *child's* mount namespace, so the parent-side supervisor can't baseline the real result cleanly.
- [ ] `getuid`/`getgid`, `sched_setaffinity`, `clock_gettime(CLOCK_BOOTTIME)` — faking these breaks permission/thread/timing logic; the right tool for uid is `--unshare-user` mapping, not a fake.

**Off-platform / non-goal:**

- [ ] Windows API-hook layer (`MachineGuid`, SMBIOS, WMI) — separate effort
- [ ] Tier 3 (`CPUID`/`RDTSC`/`RDRAND`) — needs a VM/hypervisor; explicit non-goal
