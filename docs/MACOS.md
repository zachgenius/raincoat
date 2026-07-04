# Raincoat — macOS (Seatbelt) Backend

Status: **implemented, best-effort.** Behind the platform seam (`src/backend.hpp`) the macOS
build links `src/backend_macos.cpp` + the pure SBPL generator `src/seatbelt.cpp` instead of the
Linux `bwrap` pair. It generates a Seatbelt profile (SBPL) and applies it **in-process** —
`sandbox_init(profile, 0)` in the forked child, which then `execvp`s your command itself (see
[the DYLD identity interposer](#the-dyld-identity-interposer--closing-the-leaks-seatbelt-cannot-fake)
below for why that pivot away from `/usr/bin/sandbox-exec` was necessary). Everything below is
measured on macOS 26.5.1 (Apple Silicon); the honest guarantee downgrade vs the Linux backend is the
whole point of this document — read it before you trust the macOS mode with anything you would not
hand the raw tool.

This is the macOS peer of [`docs/EGRESS.md`](EGRESS.md): same house style, same rule — never claim
a guarantee the backend cannot deliver.

## What it is

- **Mechanism:** Apple **Seatbelt**. Raincoat generates a Seatbelt profile (SBPL — the
  TinyScheme-ish "Sandbox Profile Language") and applies it to the forked child **in-process** via
  the public-but-deprecated `sandbox_init(profile, 0)` (the same libSystem entry `sandbox-exec`
  itself uses), then `execvp`s your command in that now-confined process. The per-run fail-closed
  pre-flight probe (below) still shells out to `/usr/bin/sandbox-exec -f` with the identical SBPL.
  Either way the child runs under a kernel policy.
- **Best-effort by construction.** `sandbox-exec` is **Apple-deprecated**. It still works today and
  is the only mechanism that can confine an *arbitrary* CLI without repackaging it: the supported
  alternative (the App Sandbox) needs a signed `.app` bundle with entitlements, which is a non-starter
  for "wrap whatever binary the user typed." Raincoat uses the deprecated-but-functional path and says
  so, rather than pretending macOS has a supported equivalent of bubblewrap. (Measured: a bare
  `sandbox-exec` run emits **no** deprecation text on stderr, so the child's stderr stays clean — the
  honesty channel is not polluted.)
- **Linux stays the reference backend.** The macOS mode is a reduced-guarantee port. Where a
  guarantee cannot be delivered, the runner **skips** the step (gated on the backend's `Capabilities`)
  rather than emit a dishonest audit note.

## The master caveat: filter, not structure (fail-open, not fail-closed)

This is the one inversion that colours everything else.

| | Linux (bubblewrap) | macOS (Seatbelt) |
|---|---|---|
| Model | **Constructs** a namespace | **Filters** the real filesystem |
| A hidden path… | does not exist inside the sandbox | is physically present but deny-listed |
| A rule that fails to match… | aborts the run (a missing bind is fatal) | **silently grants access** |
| Failure direction | **fail-closed** / structural | **fail-open** / deny-based |

bubblewrap builds a fresh mount namespace: an unlisted path is simply *not there*, and a failed mount
kills the run. Seatbelt leaves the child on your real filesystem and layers a kernel *deny* policy on
top: a hidden file is still on disk, one rule away from being readable, and a deny rule that fails to
match (wrong path spelling, an un-canonicalized `/tmp`, an SBPL quirk) **fails open and silently grants
the access it was supposed to block**. So the guarantees that are `[x] verified / structural` on Linux
become `[~] best-effort / deny-based` on macOS. The audit note and this doc say deny-based, never
"hidden."

Concretely, this forces two rules the Linux path never needs:

- **Every path is `realpath`'d before it reaches the generator.** SBPL `(subpath …)` matches the
  *kernel-canonical* path. A raw `/tmp/...` rule **fails open** (measured: the parent file leaked);
  the canonical `/private/tmp/...` rule works. `backend_macos.cpp` canonicalizes real home, the fake
  home, the sandbox temp/out dirs, the audit dir, every mount, and the fs-deny set before building the
  profile.
- **Deny is last-match-wins, so ordering is load-bearing.** The profile starts `(allow default)`, then
  *subtracts* the real home and `/Users`, *re-allows* the sandbox-private dirs + the working dir + user
  mounts, then *re-denies* the fs-deny set and the audit dir last so a deny beats a broad re-allow
  (e.g. workdir `== $HOME` re-allowed, but `~/.ssh` still denied).

## The honesty substitute: a fail-closed pre-flight probe (every run)

Because a Filter backend fails *open*, "the audit said hidden" is not evidence the path was actually
hidden. Raincoat restores a fail-closed guarantee with a **measured, per-run** check
(`runner.cpp`, "8c. Fail-closed pre-flight probe"):

1. Before your command runs, Raincoat spawns a throwaway probe under the **identical** profile.
2. The probe tries the two invariants this run claims: **read your real `$HOME`**, and — when the
   network is meant to be restricted — **connect to a public IP** (`1.1.1.1:443`).
3. If either **succeeds**, the run is **refused** (fail-closed) with an actionable error, rather than
   executing your command behind a profile that turned out to be permissive.

Verified: a deliberately permissive profile makes the probe abort the run (`exit 10` = home readable,
`exit 11` = outbound reachable, non-zero-other = sandbox not effective). This also catches an OS/SBPL
regression that silently stops enforcing. It is the closest a deny-based backend gets to bubblewrap's
structural fail-closed behaviour — empirical, per run, on your actual host.

## Capability / guarantee matrix (Linux vs macOS)

Per-guarantee, with the backend `Capabilities` flag that gates each one. `[x]` verified structural ·
`[~]` best-effort / deny-based · `[-]` not available on this backend.

| Guarantee | Linux (bwrap) | macOS (Seatbelt) | Gate (`Capabilities`) |
|---|---|---|---|
| Real `$HOME` / credentials hidden | `[x]` structural (never mounted) | `[~]` deny-based `(deny file-read* file-write* (subpath <home>))` + pre-flight probe | `fs_hiding` = `Structural` → `Filter` |
| Username enumeration (`ls /Users`) | `[x]` not present | `[~]` `(deny file-read* (subpath "/Users"))` (measured: EPERM) | `fs_hiding` |
| Filesystem restriction (mounts) | `[x]` structural binds | `[~]` deny-default-permissive + re-allow rules | `fs_hiding` |
| Network off (`--net off`) | `[x]` fresh empty netns (`--unshare-net`) | `[~]` `(deny network*)` kernel policy | `net_off` = `UnshareNet` → `PolicyDeny` |
| Egress firewall (proxy/bridge only) | `[~]` needs the pasta **strict** netns jail; proxy-aware-only without it | **`[x]` kernel firewall for ALL clients, no helper** | `net_firewall_kernel` = false → **true** |
| Identity: `USER` / `LOGNAME` faked | `[x]` env | `[x]` env (applied at `execve`) | `env_apply` = `ViaArgv` → `ViaExec` |
| Hostname masking | `[x]` fresh UTS ns fakes `gethostname()` | `[~]` `$HOSTNAME` env always; `gethostname()`/`uname().nodename` faked by the DYLD interposer for injectable (non-hardened) targets — hardened/static callers still leak | `supports_uts_hostname` = **false**; `supports_dyld_interpose` = **true** |
| Machine fingerprint (CPU brand, kernel release/version, RAM) | `[x]` `/proc` overlays + `uname(2)`/`sysinfo(2)` seccomp user-notify | `[~]` DYLD interposer rewrites `sysctlbyname`/`uname` for injectable targets (value-driven; unset → real) — no seccomp backstop for static/raw-syscall callers | `supports_dyld_interpose` = **true** |
| User identity (`getpwuid`/`getlogin` login name + home) | `[x]` bwrap userns + faked name via env | `[~]` DYLD interposer fakes `pw_name`/`pw_dir` + `getlogin` for injectable targets — previously an un-closable opendirectoryd leak | `supports_dyld_interpose` = **true** |
| Curated generic font set | `[x]` tmpfs + re-bind Noto/DejaVu | `[-]` cannot overlay `/usr/share/fonts` (Core Text, not fontconfig) | `supports_curated_fonts` / `supports_fontconfig_isolation` = **false** |
| Minimal `/etc` view | `[x]` generic hostname/hosts/localtime binds | `[-]` cannot bind a fake `/etc` | `supports_minimal_etc` = **false** |
| Env injection | `[x]` `--clearenv` + `--setenv` in argv | `[x]` installed at `execve` (SBPL has no env directives) | `env_apply` |
| Isolated-netns jail + `/proc/net/tcp` leak fix | `[x]` pasta jail | `[-]` no `/proc`, no netns — kernel firewall replaces it | `supports_netns_jail` = **false** |

## What works (verified on macOS 26.5.1)

- **Real `~/.ssh`, `~/.gitconfig` are denied.** Reading a sentinel under the real `$HOME` returns
  *Operation not permitted*. `file-read*` also blocks `stat()`, so the child cannot even confirm a file
  exists there (measured).
- **`ls /Users` cannot enumerate your username.** deny-home alone was **not** enough — `ls /Users`
  still leaked the account name — so the profile also emits `(deny file-read* (subpath "/Users"))`,
  which turns it into EPERM (measured). The Darwin per-user cache dir (`_CS_DARWIN_USER_CACHE_DIR`,
  under `/private/var/folders/.../C/`), which holds app caches/credentials and is *not* under `$HOME`,
  is folded into the deny set too.
- **Fake identity via env.** `HOME`, `USER`, `LOGNAME`, `HOSTNAME`, `TZ`, `LANG`, `LC_ALL` are set
  to generic values and reach the child at `exec` (SBPL has no env directives, so the runner installs
  the resolved child env into `environ` immediately before `execvp`). Beyond the env, `gethostname()`
  / `uname()` and the CPU/kernel/RAM fingerprint are now *also* faked at the libc layer by the
  [DYLD interposer](#the-dyld-identity-interposer--closing-the-leaks-seatbelt-cannot-fake) below
  (best-effort, injectable targets only).
- **`--net off` blocks outbound.** `(deny network*)` — a raw `connect()` to a public IP fails
  (measured).
- **A real kernel egress firewall** (see below) — the one place macOS is *stronger* than Linux.

## What is downgraded or unsupported on macOS (honest)

- **Structural filesystem invisibility → deny-based Filter.** Covered above; the pre-flight probe is
  the mitigation, not a fix. A hidden file is present-but-denied, not absent.
- **UTS hostname masking → env always, `gethostname()`/`uname()` best-effort.** There is no UTS
  namespace, so masking cannot be structural. The `$HOSTNAME` env value is always faked; on top of
  that the [DYLD interposer](#the-dyld-identity-interposer--closing-the-leaks-seatbelt-cannot-fake)
  below now rewrites `gethostname()` and `uname().nodename` for **injectable** targets, so a tool that
  reads them (rather than `$HOSTNAME`) no longer automatically sees the truth. A **hardened-runtime,
  SIP-protected, or static** binary still leaks the real name — the interposer cannot reach it. This
  is a best-effort improvement, not the structural guarantee Linux's UTS namespace gives.
- **Minimal `/etc` → none.** Raincoat cannot bind a generic `/etc/hostname`/`/etc/hosts`/
  `/etc/localtime`. The gate `supports_minimal_etc` is false, so the runner skips it.
- **Curated fonts / fontconfig masking → none.** macOS resolves fonts via Core Text, not fontconfig,
  and Raincoat cannot overlay `/usr/share/fonts`. No font-list masking is attempted on macOS.
- **pasta netns jail + `/proc/net/tcp` leak-fix → not applicable.** No `/proc`, no network namespace.
  There is nothing to unshare and no `/proc/net/tcp` to leak from; the kernel egress firewall covers
  the strict-egress case instead (and covers it *better* — see below).
- **`--strict` is not kernel default-deny.** A bare `(deny default)` cannot even `execvp`
  `/usr/bin/true` on macOS (it can't load libSystem — measured, exit 71). So macOS `strict` =
  **allow-default + expanded denies + no cwd auto-grant**, not a `(deny default)` allow-list. It is
  honest expanded denial, and the profile says so in a comment.

## Disclosed residual bypasses (present, not hidden)

Deny-based filtering leaves seams the Linux structural model does not. Stated plainly:

- **Username via directory services — now faked for injectable targets (best-effort).** The deny set
  blocks `$HOME` and `/Users`, but `getpwuid(getuid())->pw_name` / `->pw_dir` and `getlogin()` are
  answered by **opendirectoryd**, not by reading the filesystem, so path denials alone cannot touch
  them. The [DYLD interposer](#the-dyld-identity-interposer--closing-the-leaks-seatbelt-cannot-fake)
  below now rewrites `pw_name`/`pw_dir` and the `getlogin`/`getpwnam` family to the fake user/home for
  injectable targets — closing what was previously documented here as an un-closable leak.
  **Residual caveat:** a hardened/SIP/static binary that looks the name up through opendirectoryd
  still recovers it, because the interposer cannot inject into it.
- **Hardlinks on the shared APFS volume.** The child runs on the real volume. A hardlink that already
  references a denied file can reference the same inode by a *different* path; a `(subpath …)` deny
  keyed on the original path does not follow every alias to that inode.
- **Exposure depends on the host's TCC state.** What is reachable at all is also gated by macOS
  **TCC** (Transparency, Consent & Control). If the parent terminal has been granted **Full Disk
  Access**, more of the filesystem is reachable *before* Raincoat's deny rules apply than on a locked
  down terminal — so the same profile can expose different surface on two hosts. Raincoat's deny rules
  sit *on top of* TCC; they do not replace it.

None of these are silent. The point of listing them is that macOS mode reduces casual, opportunistic
leakage — it is not a boundary against a tool that deliberately probes these seams.

## The DYLD identity interposer — closing the leaks Seatbelt cannot fake

Seatbelt is a pure **allow/deny** engine: it can stop a call or let it through, but it cannot
*rewrite a return value*. So the identity leaks above — real `gethostname()`, `uname()`, the
`getpwuid()` login name, the CPU/kernel/RAM fingerprint — survive **any** profile; denying the call
just breaks the tool, and there is no "return a fake" verb. Raincoat closes them with a small
`__DATA,__interpose` dylib (`src/rc_interpose.c`, built next to the `raincoat` binary as
`rc_interpose.dylib`) injected into the child via `DYLD_INSERT_LIBRARIES`. It is the macOS peer of the
Linux Tier-2 identity faking (see [`docs/FINGERPRINT-SYSCALLS.md`](FINGERPRINT-SYSCALLS.md)) — but the
`LD_PRELOAD`-class technique, not seccomp, so **weaker** (see limits).

### The SIP finding that forced the in-process pivot (the crux)

The obvious wiring — inject the dylib and run `/usr/bin/sandbox-exec -f profile.sb -- cmd` — **does
not work**, and *why* is the load-bearing discovery here. `sandbox-exec` lives under `/usr/bin` and is
**SIP-protected**; when the kernel `exec`s a protected binary it **strips `DYLD_INSERT_LIBRARIES` from
the environment** (SIP's restricted-env rule). The injection therefore never reaches the target that
`sandbox-exec` goes on to run. **Measured:** with the dylib injected through `sandbox-exec`,
`gethostname()` still returned the **real** machine name — the interposer was silently absent.

The fix changes the enforcement mechanism, not just the injection. The macOS backend now applies the
SBPL profile **in-process**: the forked child calls `sandbox_init(profile, 0)` itself, installs the
resolved child env into `environ`, and `execvp`s the target **directly** (`runner.cpp`, the
`apply_sbpl` / `env_apply == ViaExec` path). Because *raincoat* and the *target* are both unrestricted
(not SIP-protected), the `DYLD_INSERT_LIBRARIES` value **survives** the `exec`, and the Seatbelt policy
is still enforced — both **measured**: deny-home → `EPERM`, and `gethostname()` → the fake `sandbox`.
`sandbox_init` is a public-but-**deprecated** libSystem call — the *same* deprecation status as
`sandbox-exec` (which uses it internally), so this is no new risk surface, just a different door into
the same mechanism. The per-run fail-closed pre-flight probe still runs via `sandbox-exec -f` with the
identical SBPL, so the enforcement check itself is unchanged.

### What it fakes

All driven by `RC_FAKE_*` env vars the runner sets; an unset (or empty) var means "don't fake this
one — return the real value" (the same value-driven contract as the Linux knobs):

| libc call | Faked field(s) | Driven by |
|---|---|---|
| `gethostname` | whole name | `RC_FAKE_HOSTNAME` |
| `uname` | `nodename`, `release`, `version` | `RC_FAKE_HOSTNAME` / `_OSRELEASE` / `_OSVERSION` |
| `getlogin` / `getlogin_r` | login name | `RC_FAKE_USER` |
| `getpwuid` / `getpwnam` | `pw_name`, `pw_dir` | `RC_FAKE_USER` / `RC_FAKE_HOME` |
| `sysctlbyname` | `kern.hostname`, `machdep.cpu.brand_string`, `kern.osrelease`, `kern.osversion`, `hw.memsize` | the matching `RC_FAKE_*` |

`getpwuid`/`getpwnam`/`getlogin` are exactly the opendirectoryd path that path-denials could not close
— so the "username via directory services" bypass listed above is now **closed for injectable
targets**. `sysctlbyname` honours the two-call size-probe/read protocol and only ever intercepts
*reads* (`newp == NULL`), never sets.

### Value-driven, same config as Linux

The identity values (hostname, username, home) are always faked; the fingerprint knobs are applied
**only when set**, exactly as on Linux:

| Config knob | macOS effect |
|---|---|
| `[identity].hostname` / `.username` | `gethostname`/`uname.nodename`/`kern.hostname`; login name + `pw_name`/`pw_dir` |
| `[backend].kernel_osrelease` / `.kernel_version` | `uname.release`/`.version` + `kern.osrelease`/`kern.osversion` |
| `[backend].cpu_model_name` | `machdep.cpu.brand_string` |
| `[backend].mem_total_kb` | `hw.memsize` (× 1024) |

**Verified on macOS 26.5.1:** with those set, a non-hardened test binary saw
`uname.release = 6.1.0-generic`, CPU brand `Generic CPU`, and `hw.memsize` = 16 GiB; with them unset,
each returned the host's **real** value.

### Honest limits (best-effort — read before you trust it)

The interposer *reduces* identity leakage; it is **not** a boundary. In descending order of how much
it bites:

1. **Injectable targets only.** SIP-protected, **hardened-runtime**, or library-validation binaries
   ignore `DYLD_INSERT_LIBRARIES` entirely. So the **system binaries** — `/bin/sh`, `/usr/bin/*` — are
   **not** faked; only unsigned or ad-hoc-signed targets are. That covers many Homebrew and
   locally-built dev tools (the common case for this tool), but not shell built-ins or Apple utilities.
2. **Dynamically-linked libc callers only, with no backstop.** Interposition sits at the libc symbol,
   so a **statically-linked** binary, or one issuing a **raw `sysctl(2)` / Mach trap**, bypasses it.
   macOS has **no seccomp-notify equivalent**, so — unlike Linux Tier-2 — there is no syscall-boundary
   fallback to catch those. This makes **macOS Tier-2 strictly weaker than Linux Tier-2**, the exact
   inverse of the Linux argument for preferring seccomp over `LD_PRELOAD`.
3. **Not everything is faked.** Numeric `uid`/`gid`, the IOKit `IOPlatformUUID`/serial pair, and CPUID
   (Intel) / `hw.optional.*` feature flags are **not** intercepted. CPUID is Tier-3 (instruction-level)
   and needs a hypervisor — a documented non-goal.
4. **`sandbox_init` / `sandbox-exec` are Apple-deprecated.** They work today and are the only way to
   confine an arbitrary CLI, but there is no supported replacement (see the top of this doc).

The SBPL profile re-allows *reading* the dylib itself, because a dev build of `rc_interpose.dylib` may
sit under a path the profile otherwise denies (e.g. `$HOME`); without that re-allow the loader could
not map it.

## The kernel egress firewall — where macOS is *stronger* than Linux

On Linux, turning the guarded proxy / egress bridge into a real firewall (the child's *only* way out)
needs the **pasta** `strict` netns jail; without it the policy only constrains *proxy-aware* clients
(a tool that ignores `http_proxy` or dials a raw IP walks around it — see
[`docs/EGRESS.md`](EGRESS.md)).

macOS does it in the **kernel, for every client, with no helper.** When an egress bridge and/or the
guarded proxy is active and `isolate_netns = "strict"`, the Seatbelt profile emits:

```scheme
(deny network*)
(allow network-outbound (remote ip "localhost:<port>"))   ; one per loopback proxy/bridge port
```

So *all* outbound is denied at the kernel level and **only** the loopback proxy/bridge port(s) are
reachable — this constrains a raw-socket, non-proxy-aware, or raw-IP client exactly the same as a
cooperating one. DNS is intentionally **not** allowed out: the proxy resolves host-side, so a
non-proxy client is fully contained. Measured details that shaped the rule:

- `(remote ip "127.0.0.1:PORT")` **fails to compile** ("host must be `*` or localhost"); the working
  form is `(remote ip "localhost:<port>")`. `localhost` also covers `::1`, so one rule handles IPv4 +
  IPv6 loopback.
- The firewall is **port-precise**: allowing `localhost:P1` lets the child reach `P1`, while any other
  loopback port and any public IP stay blocked (measured).

Crucially, on macOS `isolate_netns = "strict"` needs **no pasta** and does **not** fail closed — the
gate `net_firewall_kernel = true` tells the runner to realise strict egress with this SBPL rule
instead of the (absent) netns jail. This is the single guarantee where the macOS backend is a strict
*upgrade* over the Linux reference.

## Building and running on macOS

The one build wrinkle is OpenSSL (the egress bridge terminates HTTPS via OpenSSL). Point CMake at
Homebrew's `openssl@3`:

```sh
# 1. Dependency (Apple's sandbox-exec ships with macOS; nothing to install for the sandbox itself)
brew install openssl@3

# 2. Configure + build (CMAKE_PREFIX_PATH lets find_package(OpenSSL) locate the keg-only openssl@3)
cmake -S . -B build -DCMAKE_PREFIX_PATH="$(brew --prefix openssl@3)"
cmake --build build -j
```

The binary lands at `./build/raincoat`. CMake selects the backend at **configure** time: on macOS
(`APPLE`) it links `seatbelt.cpp` + `backend_macos.cpp` and prunes the Linux-only `bwrap` test suites;
the Seatbelt SBPL suite (`tests/test_seatbelt.cpp`) is compiled instead. `ctest --test-dir build` runs
the platform-appropriate set.

### Check your host

`raincoat doctor` is Seatbelt-aware on macOS: it confirms `/usr/bin/sandbox-exec` is present and
executable, runs a **real SBPL smoke test** (loads `(version 1)(allow default)` and runs
`/usr/bin/true` under it), and — even on PASS — **always** prints the honest deprecation warning plus
a note that the egress firewall is kernel-level (no pasta helper needed). There are no apt/dnf/pacman
hints (that is the Linux report).

```
$ raincoat doctor
Raincoat doctor (macOS / Seatbelt)
==================================
  [ OK ] sandbox-exec found: /usr/bin/sandbox-exec
  [ OK ] sandbox-exec SBPL smoke test (`sandbox-exec -p '(version 1)(allow default)' true`): passed
  [WARN] Seatbelt / sandbox-exec is Apple-DEPRECATED — it works today but has no supported replacement
         for wrapping arbitrary CLIs (App Sandbox needs a bundle + entitlements + signing). Raincoat's
         macOS backend is best-effort. See docs/MACOS.md.
  [INFO] egress firewall is kernel-level (Seatbelt (deny network*)); no pasta/slirp4netns helper is needed.

Result: PASS — host is usable. sandbox-exec is present and the SBPL smoke test passed. (Best-effort
backend — see the deprecation warning above.)
```

### Run

```sh
raincoat -- <command> [args...]
```

At launch the backend locates `/usr/bin/sandbox-exec` (`backend_locate`) and refuses with an
actionable error if it is absent or not executable. Then — because a Filter backend fails *open* —
**the authoritative per-run gate is the fail-closed pre-flight probe described above**: it empirically
confirms, on your host, that the generated profile actually denies your real `$HOME` (and blocks
outbound when it should) *before* your command runs, and refuses the run otherwise. `doctor` proves the
host *can* sandbox; the pre-flight probe proves *this* run's profile actually does.
