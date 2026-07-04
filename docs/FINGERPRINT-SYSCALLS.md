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
| `uname(2)` (63) | `sysname`, `nodename` (hostname), `release` (kernel), `version` (build string), `machine` (arch), `domainname` | seccomp user-notify: write a fake `struct new_utsname` into the child's buffer | **implemented** (`backend.fake_uname`) |
| `sysinfo(2)` (99) | `uptime`, load avg, `totalram`/`freeram` (RAM size), swap, process count | seccomp user-notify: write fake `struct sysinfo` | **implemented** (`backend.fake_sysinfo`) |
| `sched_getaffinity(2)` (204) | logical CPU count (`nproc`) | seccomp user-notify: rewrite the returned cpu-set | planned (risky — breaks pool sizing) |
| `getcpu(2)` (309) | current CPU/NUMA node → topology inference | user-notify: pin to 0 | low value |
| `clock_gettime(CLOCK_BOOTTIME)` / `CLOCK_MONOTONIC` | uptime, boot correlation | hard — faking time breaks programs; only offset-able | not planned |
| `ioctl(SIOCGIFHWADDR/SIOCGIFCONF)` | interface **MAC** + names | user-notify is awkward (ioctl arg structs); the **isolated-netns jail** (pasta) is the real fix — child sees only a synthetic iface | covered by egress strict jail; else note |
| `socket(AF_NETLINK, NETLINK_ROUTE)` → `RTM_GETLINK` | interface list + **MAC** | same as above — netns isolation, not per-call faking | covered by netns jail |
| `statfs`/`statvfs`/`fstatfs` | fs type + size of mount points → disk fingerprint | user-notify possible; low priority | not planned |
| `getuid/getgid/getgroups` | numeric identity | bwrap userns uid/gid mapping (not a fake — a remap) | out of scope here |

### Tier 1 — pseudo-files (bind-mount overlays)

| Path | Exposes | Status |
|---|---|---|
| `/proc/cpuinfo` | CPU model/family/stepping/microcode/MHz/flags (+ ARM `Serial`) | **masked** (`fake_cpuinfo`, x86) |
| `/proc/version` | kernel release + **distro build host** + toolchain | **masked** (`fake_kernel`) |
| `/proc/sys/kernel/osrelease` · `…/version` · `…/ostype` | `uname` mirror | **masked** (`fake_kernel`) |
| `/proc/sys/kernel/hostname` · `…/domainname` | hostname | UTS namespace (`--unshare-uts --hostname`) |
| `/etc/machine-id` · `/var/lib/dbus/machine-id` | stable per-install ID | **masked** (`fake_machine_id`, constant) |
| `/proc/sys/kernel/random/boot_id` | per-boot UUID (correlation) | **masked** (`fake_boot_id`, default on) |
| `/proc/meminfo` · `/proc/uptime` · `/proc/loadavg` | RAM size, uptime, load | **masked** (`fake_meminfo` / `fake_uptime`) |
| `/proc/self/mountinfo` · `/proc/mounts` | **host mount layout + real paths** (strong deanon vector) | partially reduced by bwrap's own mounts; overlay planned |
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

## macOS (design notes — not implemented)

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
| CPUID / `hw.optional.*` | — | Intel: CPUID; Apple Silicon: feature flags via sysctl |

**Faking:** interpose `sysctl`/`sysctlbyname`, `gethostuuid`, `IOServiceGetMatchingService` /
`IORegistryEntryCreateCFProperty`, and `getifaddrs` via a `__DATA,__interpose` dylib injected
with `DYLD_INSERT_LIBRARIES`. Limits: SIP-protected/`hardened-runtime` binaries ignore
`DYLD_INSERT_LIBRARIES`; hardware-instruction reads (CPUID on Intel) remain Tier 3. The
`IOPlatformUUID`/`IOPlatformSerialNumber` pair is the highest-value target.

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

- [x] Tier 1, Linux: `/proc/cpuinfo`, `/proc/version` + `uname` file mirror, `/etc/machine-id`
- [x] Tier 2, Linux: `uname(2)` via seccomp user-notify (`backend.fake_uname`)
- [x] Tier 2, Linux: `sysinfo(2)` (`backend.fake_sysinfo`) + paired `/proc/meminfo`, `/proc/uptime`, `/proc/loadavg` overlays
- [x] Tier 1, Linux: `boot_id` overlay (`backend.fake_boot_id`)
- [ ] Tier 1, Linux: `/proc/self/mountinfo` overlay (host mount-layout deanon vector)
- [ ] `uname` on non-x86 arches (per-arch syscall numbers)
- [ ] macOS `DYLD_INSERT_LIBRARIES` interposer (`sysctl`, `gethostuuid`, IOKit)
- [ ] Windows API-hook layer (`MachineGuid`, SMBIOS, WMI)
- [ ] Tier 3 — explicit non-goal (needs a VM/hypervisor)
