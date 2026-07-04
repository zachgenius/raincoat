# Raincoat — macOS (Seatbelt) Backend

Status: **implemented, best-effort.** Behind the platform seam (`src/backend.hpp`) the macOS
build links `src/backend_macos.cpp` + the pure SBPL generator `src/seatbelt.cpp` instead of the
Linux `bwrap` pair. It runs your command as
`/usr/bin/sandbox-exec -f <profile.sb> -- <cmd>`. Everything below is measured on macOS 26.5.1
(Apple Silicon); the honest guarantee downgrade vs the Linux backend is the whole point of this
document — read it before you trust the macOS mode with anything you would not hand the raw tool.

This is the macOS peer of [`docs/EGRESS.md`](EGRESS.md): same house style, same rule — never claim
a guarantee the backend cannot deliver.

## What it is

- **Mechanism:** Apple **Seatbelt**, driven through `/usr/bin/sandbox-exec`. Raincoat generates a
  Seatbelt profile (SBPL — the TinyScheme-ish "Sandbox Profile Language") and hands it to
  `sandbox-exec -f`. The child then runs under a kernel policy.
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
| Hostname masking | `[x]` fresh UTS ns fakes `gethostname()` | `[-]` only `$HOSTNAME` env is faked; `gethostname()`/`uname` leak the real name | `supports_uts_hostname` = **false** |
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
- **Fake identity via env.** `HOME`, `USER`, `LOGNAME`, `HOSTNAME` (env only), `TZ`, `LANG`, `LC_ALL`
  are set to generic values and reach the child at `execve` (sandbox-exec passes its environment
  through untouched; SBPL has no env directives, so env is applied at exec, not in the profile).
- **`--net off` blocks outbound.** `(deny network*)` — a raw `connect()` to a public IP fails
  (measured).
- **A real kernel egress firewall** (see below) — the one place macOS is *stronger* than Linux.

## What is downgraded or unsupported on macOS (honest)

- **Structural filesystem invisibility → deny-based Filter.** Covered above; the pre-flight probe is
  the mitigation, not a fix. A hidden file is present-but-denied, not absent.
- **UTS hostname masking → env only.** There is no UTS namespace. `gethostname()` and `uname()` still
  return your **real** machine name; only the `$HOSTNAME` environment variable is faked. A tool that
  calls `gethostname()` (most do, over `$HOSTNAME`) sees the truth.
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

- **Username can still leak via directory services.** The deny set blocks `$HOME` and `/Users`, but
  `getpwuid(getuid())->pw_name` / `->pw_dir` are answered by **opendirectoryd**, not by reading the
  filesystem, so a tool that calls it can still recover your account name and home path. Raincoat fakes
  the `USER`/`LOGNAME`/`HOME` *env* values; it does not intercept the directory-services API.
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
