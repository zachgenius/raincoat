# Roadmap

The core sandbox implements the fake home, env scrub, generic identity/locale/timezone,
filesystem restriction, `full`/`off` networking, and the audit log. Several items once on this
roadmap have since shipped.

## Delivered

Documented in the [README](../README.md) / [`EGRESS.md`](EGRESS.md):

- **Curated font set** — masks `/usr/share/fonts` and re-binds only the curated Noto/DejaVu dirs,
  so `fc-list` shows a generic set instead of your host's full font list (best-effort fallback when
  no curated dirs exist).
- **Minimal `/etc`** — generic `/etc/hostname`, `/etc/hosts`, and `/etc/localtime`.
- **Machine-fingerprint masks** (value-driven; [`FINGERPRINT-SYSCALLS.md`](FINGERPRINT-SYSCALLS.md)) —
  present generic CPU (`/proc/cpuinfo`), kernel (`/proc/version` + cmdline), RAM/uptime
  (`/proc/meminfo`, `/proc/uptime`), machine-id and boot-id, and CPU count. On x86_64 the same
  values are enforced at the **syscall level** via a seccomp user-notify supervisor
  (`uname(2)`/`sysinfo(2)`/`sched_getaffinity(2)`), so a static/Go binary can't read the real host
  by calling the raw syscall. DMI serials / product UUID / MAC never leak (no `/sys` mount).
- **Neutral path remapping** ([`MOUNT-REMAP.md`](MOUNT-REMAP.md)) —
  `[filesystem].remap_cwd` and `[[filesystem.mount]]` present the working directory / allow paths
  at neutral mount points (e.g. `/work`) so the child can't read your username/layout via
  `pwd`/`realpath`/`$PWD`.
- **JSON audit logs** — `[audit].format = "json"` / `--audit-format json`, one structured object
  per run alongside the human-readable format; `raincoat report` summarizes either.
- **Tripwire / honeytoken files** — `[filesystem.tripwire]` plants inert decoy credentials in the
  fake home.
- **Egress bridge / endpoint indirection** — hides one upstream's URL from the child
  ([Egress bridge](../README.md#egress-bridge-endpoint-indirection)).
- **Isolated-netns jail** (`pasta`) — `isolate_netns = auto|on|off|strict`; fixes the
  `/proc/net/tcp` upstream leak and hides other host-loopback services, and `strict` blocks general
  internet for a real bridge-only egress firewall.
- **Guarded proxy / domain firewall** — `[network_policy]` host allow/block + metadata-IP blocking,
  a real domain-level egress firewall when composed with the strict jail
  ([Network policy](../README.md#network-policy-guarded-proxy)).
- **Browser isolation** (best-effort) — `[browser]` throwaway profile + generic PATH launch shims
  ([Browser isolation](../README.md#browser-isolation-browser)).
- **Per-job profile templates** — the [`examples/`](../examples/) directory (strict, paranoid,
  ai-agent, node-build, python-tool, egress, api-agent, guarded, browser).
- **macOS best-effort mode** — a reduced-guarantee Seatbelt
  backend behind the platform seam: in-process `sandbox_init` deny-based filtering + a fail-closed
  per-run pre-flight probe, a kernel egress firewall, a best-effort **DYLD identity/fingerprint
  interposer** (hostname/username/CPU/kernel/RAM for non-hardened targets), and honest `[-]` gaps (no
  font/`/etc` masking). Full honest write-up in [`MACOS.md`](MACOS.md).

## Still ahead / genuine non-goals

- **Windows** — a non-goal; there is no bubblewrap/Seatbelt equivalent Raincoat targets.
- **Interactive "ask" mode** — prompt before granting access at run time (reserved as `ask` in the
  `NetMode` enum). Not implemented.
- **General CIDR / allowlist egress firewall** — the guarded proxy is name-based, not CIDR, and the
  strict jail is bridge-only; an arbitrary per-destination allow-list beyond those is future.
  Also: `--map-host-loopback` on newer `pasta`, **transparent interception** of non-proxy-aware
  clients without the jail, and an explicit MITM mode (off by default).
- **DNS policy** — `[dns]` is parsed and reserved but not enforced.
- **Deep anti-fingerprinting** — canvas/WebGL/audio/font-metrics/TLS-JA3 normalization would need
  an instrumented browser build, not a launch shim. Explicit non-goal for the browser layer.
- **uid/gid remap** — the numeric uid/gid stay visible (identity is masked via
  username/hostname/HOME, not the uid); this also leaves `uid=` in `/proc/self/mountinfo`. Would
  need bwrap `--unshare-user` mapping, with its own ownership tradeoffs.
- **Remaining fingerprint vectors** ([`FINGERPRINT-SYSCALLS.md`](FINGERPRINT-SYSCALLS.md)
  has the full roadmap) — `/proc/self/mountinfo` and `/proc/stat` have no clean mechanism
  (per-reader `self` indirection / live counters); CPU **instructions** (`CPUID`/`RDTSC`) can't be
  faked without a VM (Tier-3 non-goal); and macOS (`DYLD_INSERT_LIBRARIES`) / Windows (API hooks)
  interposers are separate efforts.
