# Raincoat

**Raincoat is a lightweight privacy sandbox for nosy CLI tools and AI agents.** It helps
prevent untrusted tools from casually inspecting your real home directory, credentials, browser
profiles, locale, timezone, and other machine fingerprints. It swaps in a curated generic font
set (Noto/DejaVu) that masks your host's full installed-font list, and a minimal `/etc` view so
your real hostname/hosts never leak.

It is a thin, Linux-first wrapper around [bubblewrap (`bwrap`)](https://github.com/containers/bubblewrap)
that hands the command you run a *fake* home, a scrubbed environment, a generic locale and
timezone, a curated font environment, a minimal `/etc`, restricted filesystem access, an audit
log (human-readable or JSON) of exactly what it did, and — when you ask for it — a filtering
egress layer: an endpoint-hiding bridge, an isolated-netns jail (via `pasta`), and a domain
allow/block firewall.

```
raincoat -- <command> [args...]
```

---

## The problem

Modern command-line tools and AI coding agents are useful, but many are *curious*. Given the
chance, a tool can read far more than the job requires:

- your real `$HOME` and everything in it — `~/.ssh`, `~/.aws`, `~/.config/gcloud`, `~/.kube`,
  `~/.gnupg`, `~/.docker`, `~/.npmrc`, `~/.git-credentials`, `~/.gitconfig`;
- your browser profiles (`~/.config/google-chrome`, `~/.mozilla`, ...), `~/Documents`,
  `~/Desktop`, `~/Downloads`;
- secrets sitting in your environment — `*_TOKEN`, `*_SECRET`, `*_KEY`, `AWS_*`, `GITHUB_*`,
  `OPENAI_*`, `ANTHROPIC_*`, and friends;
- fingerprinting signal: your username, timezone, locale, and the exact list of fonts installed
  on your machine.

Most of that leakage is *accidental and opportunistic* rather than malicious — but it happens by
default, silently, every time you run something. Raincoat's job is to make the boring, safe
choice the default one: run the tool, but don't let it casually rifle through your machine.

---

## Install / build

Raincoat is a C++17 project built with CMake. Its one runtime dependency is **bubblewrap**.

### 1. Install bubblewrap

```sh
# Ubuntu/Debian
sudo apt install bubblewrap
# Fedora
sudo dnf install bubblewrap
# Arch
sudo pacman -S bubblewrap
```

### 2. Build

```sh
git clone <your-fork-url> Raincoat
cd Raincoat
cmake -S . -B build
cmake --build build -j
```

The binary lands at `./build/raincoat`.

### 3. Check your host

`raincoat doctor` verifies that everything Raincoat needs is present and working — bwrap is
installed and executable, user namespaces are available, and a `bwrap ... true` smoke test
succeeds. It exits non-zero if the host is unusable.

```
$ raincoat doctor
Raincoat doctor
===============
  [ OK ] bubblewrap (bwrap) found: /usr/bin/bwrap
  [ OK ] bwrap version: bubblewrap 0.11.0
  [ OK ] user namespaces available: yes
  [ OK ] bwrap smoke test (`bwrap ... true`): passed
  [ OK ] egress network jail: available (pasta) /usr/bin/pasta

Result: PASS — host is usable. bwrap is present and the smoke test passed.
```

The `egress network jail` line is informational, never a `[FAIL]`: if neither `pasta` nor
`slirp4netns` is installed it reads `[INFO] … unavailable` and the egress bridge simply falls
back to the shared host network namespace (see [Egress bridge](#egress-bridge-endpoint-indirection)).

### Running the tests

```sh
ctest --test-dir build --output-on-failure
```

Integration tests that actually invoke `bwrap` skip gracefully on hosts without it.

---

## Usage

`raincoat -- <cmd>` is shorthand for `raincoat run -- <cmd>`. Everything after the first `--` is
the command to sandbox, passed through verbatim.

```
raincoat run [options] -- <command> [args...]
raincoat doctor      # check the host can sandbox
raincoat init        # write a .raincoat.toml starter config
raincoat report      # summarize the most recent audit log
```

### `run` options

| Flag | Meaning |
|------|---------|
| `--strict` | Deny the working directory by default; network off; scrub aggressively. |
| `--profile <path>` | Load a TOML profile. **CLI flags override the profile.** |
| `--allow-read <path>` | Mount `<path>` read-only at the same absolute path. Repeatable. |
| `--allow-write <path>` | Mount `<path>` read-write at the same absolute path. Repeatable. |
| `--allow-env <NAME>` | Copy `NAME` from your real environment if present. Repeatable. |
| `--set-env <KEY=VALUE>` | Set/override an env var inside the sandbox. Wins over `--allow-env`. Repeatable. |
| `--net <full\|off>` | Network on (`full`) or isolated (`off`). |
| `--workdir <path>` | Working directory inside the sandbox. |
| `--audit-log <path>` | Where to write the audit log. |
| `--audit-format <text\|json>` | Audit-log format. Overrides `[audit].format` in the profile. |
| `--keep-temp` | Do not delete the temporary sandbox dir on exit. |

The examples below are real output from `./build/raincoat`. Only three things will differ
on your machine: your real username and home path (shown here with the placeholders `you` and
`/home/you/...`), the random sandbox suffix (shown as `raincoat-apKPqS`), and the exact number
of scrubbed environment variables (it depends on how many variables your shell exports).

### The environment scrub, in one command

Run `env` inside the sandbox and see what a tool actually gets:

```
$ FOO_TOKEN=supersecret AWS_ACCESS_KEY=abc GITHUB_TOKEN=ghp_x  raincoat -- env
FONTCONFIG_FILE=/tmp/raincoat-apKPqS/fontconfig/fonts.conf
FONTCONFIG_PATH=/tmp/raincoat-apKPqS/fontconfig
HOME=/tmp/raincoat-apKPqS/home/user
HOSTNAME=sandbox
LANG=en_US.UTF-8
LC_ALL=en_US.UTF-8
LOGNAME=user
PATH=/home/you/.local/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
TERM=tmux-256color
TMPDIR=/tmp/raincoat-apKPqS/tmp
TZ=UTC
USER=user
XDG_DATA_DIRS=/usr/local/share:/usr/share
PWD=/home/you/project
```

`FOO_TOKEN`, `AWS_ACCESS_KEY`, and `GITHUB_TOKEN` never made it in. `HOME` points at a throwaway
directory, `USER`/`LOGNAME` are a generic `user`, `HOSTNAME` is a generic `sandbox`, and the
timezone/locale are neutral. Two values are **not** anonymized: `PATH` is preserved from your
parent environment (so it can contain `/home/<you>/...`), and `PWD` is the real launch directory
(see the note below). Override `PATH` with `--set-env PATH=/usr/bin:/bin` if that matters.

Note the `PWD` line: in the default (non-strict) mode Raincoat mounts your current directory at
its real absolute path and `bwrap` sets `PWD` to that path, so `PWD` reflects your real launch
directory — which typically contains your real home and username (e.g.
`/home/you/project`). This is *not* masked, and overriding `PATH` does not affect it. See
[Security limitations](#security-limitations-read-these) for how to avoid it.

### Your real home stays hidden

```
$ raincoat -- sh -c 'ls -la $HOME; cat /home/you/.ssh/id_rsa'
total 4
drwxrwxr-x 2 1000 1000 4096 ...  .
drwx------ 3 1000 1000   60 ...  ..
cat: /home/you/.ssh/id_rsa: No such file or directory
```

The fake `$HOME` is empty, and your real `~/.ssh` simply isn't there.

### Non-strict (default): the working directory is writable

By default Raincoat mounts your current directory read-write so ordinary "run this tool on my
project" workflows just work — while still hiding the rest of your home. (Raincoat refuses to
auto-mount the CWD when the CWD *is* your real home directory; pass explicit `--allow-*` there.)

### Strict mode: nothing unless you say so

```
$ raincoat --strict -- ls
Warning: strict mode with no writable paths allowed; the command may fail. Grant one with --allow-write <path>.
Note: working directory is not mounted; using the fake home (/tmp/raincoat-ZK1ONQ/home/user) instead.
```

In `--strict`, the working directory is *not* mounted. You grant access deliberately:

```
$ raincoat --strict \
    --allow-read  /data/in \
    --allow-write /data/out \
    --workdir     /data/out \
    -- sh -c 'cat /data/in/data.txt; echo done > result.txt; echo x > /data/in/nope.txt'
hello from host
sh: 1: cannot create /data/in/nope.txt: Read-only file system
```

Reading from `/data/in` works (it prints `hello from host`), writing `result.txt` into the
`--allow-write` dir succeeds silently, and writing back into the `--allow-read` dir fails:
`--allow-read` mounts are genuinely read-only, `--allow-write` mounts are read-write, and the
`result.txt` it wrote is visible back on the host under `/data/out`.

### Network off

```
$ raincoat --net full -- ip -o link | wc -l   # -> 5  (real interfaces)
$ raincoat --net off  -- ip -o link | wc -l   # -> 1  (loopback only)
```

`--net off` uses bwrap's `--unshare-net`, so the command sees only an isolated loopback.
Strict mode turns network **off by default** (see the precedence note below).

### Forwarding a single credential

Only the names you list are copied in; `--set-env` overrides `--allow-env`:

```
$ MY_API_KEY=from-parent raincoat --allow-env MY_API_KEY -- printenv MY_API_KEY
from-parent
$ MY_API_KEY=from-parent raincoat --allow-env MY_API_KEY --set-env MY_API_KEY=overridden -- printenv MY_API_KEY
overridden
```

### Config + report

```
$ raincoat init          # writes .raincoat.toml (refuses to overwrite unless --force)
$ raincoat --profile examples/ai-agent.toml -- your-agent ...
$ raincoat report
Raincoat kept an eye on things. Your real HOME stayed hidden behind a fake one
(/tmp/raincoat-apKPqS/home/user), so the tool never got to see your actual home directory. It
ran in strict mode, and network access was cut off (off). 35 environment variables were scrubbed
(only the safe allowlist survived) before the command ever saw them.
Verdict: this tool did not get to see you naked.
```

---

## What Raincoat protects

- **Your real home directory.** The command gets a fresh, empty fake `$HOME`; your real home is
  never mounted by default. `~/.ssh`, `~/.aws`, browser profiles, `~/Documents`, etc. are simply
  absent.
- **Your environment.** The parent environment is *not* inherited wholesale. Only a small safe
  allowlist survives (`PATH`, `TERM`, and a generic `USER`), plus whatever you explicitly allow.
  Sensitive-looking variables (`*_TOKEN`, `*_SECRET`, `*_KEY`, `AWS_*`, `GITHUB_*`, `GOOGLE_*`,
  `OPENAI_*`, `ANTHROPIC_*`, `KUBECONFIG`, `SSH_AUTH_SOCK`, `DOCKER_HOST`, `NPM_TOKEN`,
  `PYPI_TOKEN`, ...) are scrubbed.
- **Your identity fingerprint.** `USER` and `LOGNAME` are forced to a generic `user`, the
  sandbox hostname is set to a generic `sandbox` (your real machine name never leaks through the
  UTS namespace), timezone is `UTC`, and locale is `en_US.UTF-8` — regardless of your real
  settings. (Your numeric `uid`/`gid` are *not* remapped — see limitations.)
- **Your font list.** When fontconfig isolation is on (default), Raincoat masks `/usr/share/fonts`
  with a tmpfs and re-binds **only** a curated generic set — the DejaVu and Noto directories
  (`.../truetype/dejavu`, `.../{truetype,opentype}/noto`) — read-only, and points fontconfig at an
  in-sandbox config that lists just those dirs. So `fc-list` inside the sandbox enumerates a
  generic Noto/DejaVu set instead of your host's full font list (e.g. your installed `lato`,
  `ubuntu`, corporate, or hand-installed families are gone). The generic aliases `serif`,
  `sans-serif`, `monospace`, and `emoji` are strong-pinned to Noto/DejaVu faces. **Honest caveat:**
  the exposed set is *whichever* of those curated dirs exist on your host, so two machines with
  different Noto packages installed can still differ; and if a host has **no** DejaVu/Noto dirs at
  all, Raincoat leaves `/usr/share/fonts` unmasked (best-effort fallback) rather than hiding
  everything. This is real font-list masking, not per-glyph anti-fingerprinting.
- **A minimal `/etc`.** The child sees a generic `/etc/hostname` (`sandbox`), a generic
  `/etc/hosts`, and an `/etc/localtime` pinned to the resolved timezone — so your real machine
  name and host file never leak through `/etc`.
- **Machine fingerprints (value-driven).** Raincoat can present generic CPU, kernel, RAM, uptime,
  machine-id, and boot-id values in place of your host's. These are configured under `[backend]`
  and are **value-driven, not on/off toggles**: *setting* a key makes the child see that value;
  *leaving it unset* shows the real system value. The knobs:
  - `cpu_vendor_id` / `cpu_model_name` → `/proc/cpuinfo` (x86; the logical-processor *count* stays
    the host's so thread-pool sizing still works).
  - `kernel_osrelease` / `kernel_version` → `/proc/version` + `/proc/sys/kernel/{osrelease,version}`;
    `kernel_cmdline` → `/proc/cmdline` (hides the root disk UUID + distro boot image).
  - `machine_id` → `/etc/machine-id` (stable per-install ID); `boot_id` →
    `/proc/sys/kernel/random/boot_id` (per-boot correlation UUID).
  - `mem_total_kb` → `/proc/meminfo`; `uptime_seconds` → `/proc/uptime` + `/proc/loadavg`.

  See `examples/paranoid.toml` for a "mask everything" profile, and `docs/full-config-reference.toml`
  for the annotated list. (Your host's DMI serials, product UUID, and MAC addresses do *not* leak at
  all — Raincoat never mounts `/sys` into the sandbox.)
- **…and at the syscall level, not just the files** *(x86_64)*. Setting `kernel_*` or
  `mem_total_kb` / `uptime_seconds` also engages a **seccomp user-notify** supervisor that
  intercepts the `uname(2)` and `sysinfo(2)` syscalls themselves — so even a statically-linked or
  Go binary issuing the raw syscall (which the `/proc` file overlays and an `LD_PRELOAD` shim both
  miss) gets the fake. The supervisor baselines each call from the host's *real* struct and
  overrides only the fields you set, so unset fields stay truthful. It installs a seccomp filter
  plus a supervisor thread; see `docs/FINGERPRINT-SYSCALLS.md` for the full catalogue across
  Linux/macOS/Windows and the three-tier model. **Honest caveat — the hard floor:** CPU
  *instructions* like `CPUID`/`RDTSC` execute in user mode and never trap, so they can't be faked
  without a hypervisor (a VM) — a deliberate non-goal.
- **The filesystem.** Only the paths you allow (plus the CWD in non-strict mode) are visible.
  `--allow-read` is read-only; `--allow-write` is read-write. A `[filesystem].mode =
  "deny-by-default"` profile drops even the CWD auto-mount, and optional `[filesystem.tripwire]`
  decoys plant inert bait files in the fake home. Optional `[filesystem].remap_cwd = "/work"`
  presents the working directory at a neutral path instead of its real host path, so the child
  can't read your username/layout via `pwd`/`realpath`/`$PWD` (opt-in; breaks absolute-host-path
  arguments, and is a *partial* fix — see `docs/MOUNT-REMAP.md`). `[[filesystem.mount]]` entries
  (`host`/`sandbox`/`mode`) do the same for arbitrary allow-style paths.
- **The network (optional).** `--net off` (the default in strict mode) isolates networking. Beyond
  all-or-nothing, Raincoat also ships an opt-in filtering egress layer — an endpoint-hiding
  **egress bridge**, an isolated-netns **jail** (`pasta`), and a domain-level **guarded proxy**
  firewall. See the [Egress bridge](#egress-bridge-endpoint-indirection) and
  [Network policy](#network-policy-guarded-proxy) sections below.
- **Browser profiles.** Your real Chrome/Firefox profiles are never mounted (the fake home hides
  them); the optional `[browser]` block adds a throwaway profile + generic launch shims for
  Playwright/Puppeteer/Selenium jobs. See [Browser isolation](#browser-isolation-browser).
- **An audit trail.** Every run appends a record to the audit log — mode, network, fake home,
  mounts, which env vars were allowed / set / scrubbed, active-policy notes, and the exact bwrap
  command — in a human-readable block or, with `[audit].format = "json"` (or `--audit-format
  json`), one structured JSON object per run. **Environment *values* are never written to disk**:
  every env value in the logged bwrap command is redacted to `<redacted>` and only variable
  *names* appear. **Caveat:** the *command you run* is logged verbatim (both the `Command:` line
  and the command tail of the bwrap invocation), so a secret you pass as a command-line argument —
  e.g. `curl -H 'Authorization: Bearer <token>'` — **will** appear in the audit log. Put secrets in
  `--set-env`/`--allow-env` (which are redacted), never in argv. `raincoat report` turns the
  latest log (text or JSON) into a plain-language summary.

---

## What Raincoat does **not** protect against

> **Raincoat reduces accidental and opportunistic privacy leakage. It is not a guarantee against
> malicious code, kernel exploits, sandbox escapes, or commands you explicitly allow to access
> sensitive files.**

Raincoat is a *privacy* tool, not a *security boundary*. If you `--allow-write ~/.ssh`, the tool
can read your keys — that's on you. If the sandboxed program exploits a kernel or bwrap
vulnerability to break out, Raincoat cannot stop it. Treat it as a raincoat, not a hazmat suit:
it keeps the everyday drizzle off, and makes no claim to survive a flood.

Raincoat does **not** claim to defeat, evade, or bypass detection by any specific tool, model,
or service.

---

## Platform status

**Linux is the reference backend.** On Linux, Raincoat wraps bubblewrap + user namespaces, which
CONSTRUCTS a fresh namespace: hidden paths simply don't exist, and a failed mount aborts the run —
structural, fail-closed guarantees. This is the platform every guarantee in this README is measured
against.

**macOS is a best-effort Seatbelt backend** (in progress on the `macos-seatbelt-backend` branch).
Instead of bubblewrap it runs your command under Apple's Seatbelt via
`/usr/bin/sandbox-exec -f <profile.sb> -- <cmd>`, behind the same platform seam as the Linux backend
(selected at compile time; the runner skips any guarantee the backend can't deliver rather than fake
the audit note). **Windows remains a non-goal.**

### macOS (best-effort)

The macOS mode reduces casual, opportunistic leakage — but it is a genuinely weaker port, for three
honest reasons. Read [`docs/MACOS.md`](docs/MACOS.md) before trusting it:

1. **It filters, it doesn't construct — so a fail-closed pre-flight probe stands in.** Seatbelt runs
   the child on your **real** filesystem and layers a kernel *deny* policy on top: a hidden file is
   still on disk, and a deny rule that fails to match **fails open** (silently grants access), the
   opposite of bubblewrap's fail-closed structure. To compensate, every macOS run first spawns a
   throwaway probe under the identical profile and **refuses to run** if that probe can still read
   your real `$HOME` (or reach the network when it shouldn't).
2. **`sandbox-exec` is Apple-deprecated.** It works today and is the only way to confine an arbitrary
   CLI, but Apple ships no supported replacement for that use case (the App Sandbox needs a signed
   bundle + entitlements). Raincoat uses the deprecated-but-functional path and says so.
3. **No font / `/etc` masking; hostname/fingerprint faking is best-effort.** macOS uses Core Text (not
   fontconfig) and has no UTS namespace, so the curated font set and the minimal `/etc` view are
   unavailable. Hostname/username/CPU/kernel/RAM *are* now faked — best-effort — by a small **DYLD
   interposer** that rewrites `gethostname()`/`uname()`/`getpwuid()`/`getlogin()`/`sysctl` for
   **non-hardened** targets (unsigned/ad-hoc Homebrew/dev tools); a hardened-runtime, SIP-protected, or
   static binary ignores it and still sees the truth, and there is no seccomp-style backstop as on
   Linux. (One place macOS is actually *stronger*: the guarded-proxy egress firewall is kernel-enforced
   for **all** clients with no pasta helper — see [`docs/MACOS.md`](docs/MACOS.md).)

Same raincoat, thinner fabric: it keeps the everyday drizzle off on macOS too, but the seams are wider
and honestly disclosed.

---

## Dependency: bubblewrap

Raincoat does not sandbox anything itself — it builds an argument vector and hands it to
`bwrap`. Bubblewrap must be installed and functional; `raincoat doctor` checks this. If bwrap is
missing, Raincoat tells you how to install it and exits without running your command:

```
Error: bubblewrap / bwrap was not found.

Install it with your package manager, for example:
  Ubuntu/Debian: sudo apt install bubblewrap
  Fedora: sudo dnf install bubblewrap
  Arch: sudo pacman -S bubblewrap

Then run:
  raincoat doctor
```

---

## Security limitations (read these)

Being honest about the sharp edges:

- **`PATH` may leak your username.** By default `PATH` is preserved from the parent environment,
  and a typical `PATH` contains entries like `/home/<you>/.local/bin`. That reveals your real
  username to the sandboxed command. If that matters to you, override it explicitly:
  `--set-env PATH=/usr/bin:/bin`.
- **The working-directory path (and `PWD`) leak your username/home in non-strict mode.** By
  default Raincoat mounts your current directory at its *real* absolute path (identity mapping, so
  tools that hardcode paths keep working), and `bwrap` sets `PWD` to that path. If you launch from
  under your home — e.g. `/home/<you>/project` — the sandboxed command sees your real username and
  home location in `PWD`, in `pwd`, and in the mount path itself. This is **separate** from the
  `PATH` leak above: overriding `PATH` does **not** suppress it, because `PWD`/`--chdir` come from
  the launch directory, not the environment. To avoid it, run from a neutral directory (e.g.
  `cd /tmp/work && raincoat -- ...`), or use `--strict` and grant a neutrally-named path with
  `--allow-write /work --workdir /work`. Your real home directory is still never *mounted*; it is
  the launch **path string** that is exposed here, not its contents.
- **Strict's network-off is a *default*, not a lock.** Strict mode defaults network to `off`, but
  an explicit `network = "full"` in a profile (or `--net full` on the CLI) overrides it. Precedence
  is: CLI flag > profile value > mode default. If you want a profile that is strict *and* offline,
  set `network = "off"` explicitly.
- **Font masking depends on the curated dirs existing.** When enabled, Raincoat masks
  `/usr/share/fonts` and re-binds only the curated DejaVu/Noto directories, so `fc-list` shows a
  generic Noto/DejaVu set rather than your host's full list. But it exposes *whichever* of those
  curated dirs your host actually has, so two hosts with different Noto packages can still differ;
  and on a host with **no** DejaVu/Noto dirs it falls back to leaving `/usr/share/fonts` unmasked
  (it never hides *all* fonts as a side effect of a missing curated set). This is font-list
  masking, not per-glyph anti-fingerprinting (canvas/metrics signals are untouched).
- **The egress jail needs `pasta`, and only `strict` is a firewall.** The isolated-netns jail
  requires [`pasta`](https://passt.top/) (`raincoat doctor` reports it). At `auto`/`on` it fixes
  the `/proc/net/tcp` upstream leak and hides other host-loopback services, but pasta **NATs**
  general outbound traffic — the child keeps general internet by IP. Only `isolate_netns =
  "strict"` blocks general internet (bridge/proxy port only); with `pasta` absent, `strict` fails
  **closed** (the run is refused). Without any jail (shared loopback), the child keeps general host
  network access and the upstream IP:port is visible via `/proc/net/tcp`.
- **The guarded proxy is a hard firewall only *with* the strict jail.** `[network_policy]`'s
  allow/block list is a real domain-level egress firewall only when composed with `[egress]
  isolate_netns = "strict"` (the jail forwards only the proxy port, so the proxy is the child's
  sole exit). Without the strict jail — shared loopback or the `auto`/`on` NAT jail — it constrains
  only **proxy-aware** clients: a tool that ignores `http_proxy` or dials a raw IP bypasses the
  policy. There is no transparent interception without the jail.
- **Your numeric `uid`/`gid` stay visible.** The `USER`/`LOGNAME` *strings* are masked to a
  generic `user`, but the command runs with your real numeric uid/gid, so `id` still prints e.g.
  `uid=1000 gid=1000 groups=1000,65534`. Host supplementary groups are dropped (only the
  `nogroup` 65534 placeholder remains). uid 1000 is a weak fingerprint;
  there is no `--uid`/`--gid` remap in the MVP.
- **The controlling terminal is shared.** Raincoat does not pass bwrap `--new-session`, so the
  sandboxed process keeps your terminal. On kernels where the legacy `TIOCSTI` ioctl is enabled
  this could in principle be used to inject keystrokes into your shell. Modern distros disable
  `TIOCSTI` by default (`dev.tty.legacy_tiocsti=0`); if yours does not, do not run fully
  untrusted code attached to an interactive terminal.
- **It is not an escape-proof jail.** Raincoat inherits bubblewrap's threat model. It does not
  defend against kernel exploits, bwrap vulnerabilities, side channels, or anything you
  deliberately mount in.
- **Anything you allow, you allow.** `--allow-write`, `--allow-read`, `--allow-env`, and
  `--set-env` are escape hatches by design. Grant the minimum the tool needs.
- **`--net full` shares host networking.** In `full` mode the command has normal network access
  and can reach your LAN and the internet just like any local process.

---

## Example profiles

Profiles are TOML. `--profile <path>` loads one; **CLI flags always override the profile.**
`raincoat init` writes a starter `.raincoat.toml` you can edit. Ready-made, heavily-commented
templates live in [`examples/`](examples/) — see the [index](#the-examples-directory) below. They
use generic placeholders (no real hosts/secrets); adapt the paths and hostnames before use.

### `.raincoat.toml` schema

```toml
strict  = false            # deny CWD unless explicitly allowed
network = "full"           # "full" (host networking) or "off" (isolated)

allow_read  = ["./src"]    # mounted read-only  at the same absolute path (must exist)
allow_write = ["./out"]    # mounted read-write at the same absolute path (must exist)
allow_env   = ["OPENAI_API_KEY"]   # copied from the parent env if present

[env]                      # synthetic locale/timezone handed to the command
TZ     = "UTC"
LANG   = "en_US.UTF-8"
LC_ALL = "en_US.UTF-8"

[fontconfig]
enabled = true             # curated Noto/DejaVu font-set isolation

[audit]
log_file = ".raincoat/audit.log"
```

Every path listed in `allow_read` / `allow_write` **must exist**, or Raincoat refuses to start
with `Error: allowed path does not exist: <path>`. `set_env` is CLI-only (not read from
profiles). Wrong-typed `strict` / `network` / `fontconfig.enabled` values are rejected rather
than silently ignored — a silently-dropped `strict` would be a privacy downgrade. The full
sectioned schema (identity / environment / filesystem / backend / egress / network_policy /
browser / proxy / tripwire) is documented in
[`docs/full-config-reference.toml`](docs/full-config-reference.toml).

### The `examples/` directory

Each template is heavily commented and safe to *parse*; several need you to point paths and
hostnames at real targets first. All values are generic placeholders — **no** real
providers/secrets/hosts.

| Profile | Job | Highlights |
|---------|-----|------------|
| [`strict.toml`](examples/strict.toml) | Fully untrusted tool | `strict`, network off, grants nothing until you add paths. Runs as-is. |
| [`paranoid.toml`](examples/paranoid.toml) | Maximum lockdown | `strict` + net off + deny-by-default fs + genericized identity + curated fonts + tripwire decoys + JSON audit. Runs as-is. |
| [`ai-agent.toml`](examples/ai-agent.toml) | AI coding agent | Non-strict, project RW, network on, a couple of API keys forwarded. |
| [`node-build.toml`](examples/node-build.toml) | npm / pnpm / yarn build | Project RO, `node_modules`/`dist` RW; optional registry allow-list. Pre-create the write dirs. |
| [`python-tool.toml`](examples/python-tool.toml) | pip / poetry / CLI run | Project RO, `out` RW, extra env scrub; optional index allow-list. Pre-create `out`. |
| [`egress.toml`](examples/egress.toml) | Hide one upstream's URL | Egress bridge (endpoint indirection); `isolate_netns` defaults to `auto` (URL hidden, general net retained). |
| [`api-agent.toml`](examples/api-agent.toml) | Agent that may talk to **one** API only | Egress bridge **+ `isolate_netns = "strict"`** = real bridge-only egress firewall. Keep the profile **outside** mounted paths. Needs `pasta`. |
| [`guarded.toml`](examples/guarded.toml) | Domain allow-list firewall | `[network_policy]` guarded proxy **+ strict jail** = real domain-level egress firewall. Needs `pasta`. |
| [`browser.toml`](examples/browser.toml) | Playwright / Puppeteer / Selenium | Browser profile isolation + launch shims + strict egress allow-list. Needs `pasta` for the firewall. |

The `api-agent`, `guarded`, and `browser` templates use `isolate_netns = "strict"`, which requires
[`pasta`](https://passt.top/) and fails **closed** (refuses the run) if it is absent — check with
`raincoat doctor`. Drop them to `"auto"` to accept the weaker (NAT / proxy-aware-clients-only)
guarantee. Below are the two simplest templates in full; the rest are best read in `examples/`.

### `examples/strict.toml` — fully untrusted

Denies the working directory, forces network off, grants nothing until you add paths. Safe to
run as-is (it just warns that no writable paths were allowed and falls back to the fake home).

```toml
strict  = true
network = "off"

allow_read  = []           # adjust to your project, then create the dirs
allow_write = []
allow_env   = []

[env]
TZ     = "UTC"
LANG   = "en_US.UTF-8"
LC_ALL = "en_US.UTF-8"

[fontconfig]
enabled = true

[audit]
log_file = ".raincoat/audit.log"
```

### `examples/ai-agent.toml` — AI coding agent

Non-strict so the agent can edit your project, network on for model APIs, and a couple of API
keys forwarded explicitly. `"."` resolves to the directory you launch from, so it is safe to run
from any project.

```toml
strict  = false
network = "full"

allow_read  = ["."]        # your project (the launch directory)
allow_write = ["."]

allow_env = ["OPENAI_API_KEY", "ANTHROPIC_API_KEY"]   # trim to the provider you use

[env]
TZ     = "UTC"
LANG   = "en_US.UTF-8"
LC_ALL = "en_US.UTF-8"

[fontconfig]
enabled = true

[audit]
log_file = ".raincoat/audit.log"
```

Run either with:

```sh
raincoat --profile examples/strict.toml   -- true
cd /path/to/your/project
raincoat --profile /path/to/ai-agent.toml -- your-agent ...
```

---

## Egress bridge (endpoint indirection)

Raincoat can hand the sandboxed tool a **generic loopback endpoint** while privately
forwarding its traffic to the real upstream. The child is given only a `child_endpoint`
through one injected env var and never sees the real upstream hostname in its environment;
the profile that holds the upstream is not mounted into the sandbox (and is masked with an
empty file if it turns out to be reachable). This is generic and profile-driven — no
provider, model, or service names are baked into Raincoat. Full details and the honest
threat model are in [`docs/EGRESS.md`](docs/EGRESS.md).

Turn it on with an `[egress]` block plus one or more `[[egress.bridge]]` entries. A minimal,
generic profile lives at [`examples/egress.toml`](examples/egress.toml):

```toml
[egress]
mode = "bridge"                     # off | bridge
redact_upstreams_in_audit = true    # record upstreams as "hidden" in the audit
streaming = true                    # stream responses (LLM/agent APIs)

[[egress.bridge]]
name = "primary-api"
env = "API_BASE_URL"                       # the ONLY env var injected for this bridge
child_endpoint = "http://127.0.0.1:18080"  # what the child connects to
upstream_endpoint = "https://upstream.example.com"  # host-side only; never shown to the child
preserve_host = false                      # send the upstream's Host header
```

Run it from a directory that does **not** contain the profile:

```sh
raincoat --profile /path/to/egress.toml -- your-tool ...
```

Inside the sandbox the tool sees only `API_BASE_URL=http://127.0.0.1:18080`; the real
upstream never appears in its environment. HTTP and HTTPS upstreams (TLS terminated to the
upstream via OpenSSL), streaming responses, multiple bridges, `preserve_host` /
strip-header / inject-header policy are all implemented in the MVP. The audit log records:

```
Egress bridge enabled: primary-api
  Child-visible endpoint: http://127.0.0.1:18080
  Upstream endpoint: hidden
  Injected env var: API_BASE_URL
```

### Isolated-netns jail (default when `pasta` is present)

When an egress bridge is active, Raincoat runs the child inside an **isolated network
namespace** whenever [`pasta`](https://passt.top/) is installed (`raincoat doctor` reports
whether it is; opt out with `[egress] isolate_netns = "off"`). It wraps bwrap as
`pasta --config-net -t none -T <bridge-ports> -- bwrap …`; bwrap does *not* `--unshare-net`,
it **joins pasta's** namespace. **Measured on a real host**, this mode:

- keeps the child_endpoint exactly at `127.0.0.1:<port>` (pasta forwards that ns-loopback
  port to the host-side bridge with `-T`), so nothing in your config changes;
- **fixes the `/proc/net/tcp` upstream leak** — the host-side bridge's connection to the real
  upstream lives in the *host* namespace, so it is invisible from inside the child's
  namespace (verified: the upstream IP:port no longer appears in the child's `/proc/net/tcp`);
- is **tighter** than shared mode — `-t none` means only the forwarded bridge port(s) are
  reachable on the ns loopback, so other host-loopback services are *not* reachable.

> **Honest limitation — this is still not a per-destination firewall.** pasta **NATs** general
> outbound traffic, so the child **retains general outbound internet by IP** even in the jail —
> the bridge is URL indirection plus a `/proc-net` fix, not an allow-list firewall. It also
> does not hide that a custom endpoint is in use. This `pasta` build has no
> `--map-host-loopback`, so the host is reached via NAT, not the child's `127.0.0.1`; a true
> egress-only firewall (only the configured upstreams reachable) remains future work.
>
> **Fallback (shared loopback).** When `pasta` is absent, or `isolate_netns = "off"`, Raincoat
> falls back to sharing the **host network namespace** (the net is *not* unshared). Then the
> child also keeps general host network access **and** the upstream's resolved IP:port *is*
> observable via `/proc/net/tcp`. Because both modes need loopback reachability,
> `[egress] mode = "bridge"` conflicts with `--net off` and Raincoat refuses that combination.
> The audit log and a stderr note disclose exactly which mode was used on every run, so the
> behavior is never a silent surprise.

---

## Network policy (guarded proxy)

Where the egress *bridge* redirects one known upstream, the **guarded proxy** enforces a **domain
allow/block policy** over the sandboxed tool's *general* HTTP(S) egress. Turn it on with a
`[network_policy]` block; Raincoat starts a small host-side filtering forward proxy on loopback and
injects `http_proxy`/`https_proxy`/`all_proxy` into the child pointing at it (erasing any inherited
proxy vars, leaving `no_proxy` empty so nothing can be dialed around it). Full detail and the honest
threat model are in [`docs/EGRESS.md`](docs/EGRESS.md#network-policy--guarded-proxy-filtering-forward-proxy).

```toml
[network_policy]
enabled = true
default_action = "deny"                      # "deny" = allow-list mode; "allow" = block-list mode
allow_hosts = ["api.example.com", "example.org"]   # exact or dot-suffix ("example.org" allows sub.example.org)
block_hosts = []                             # always blocked (wins over allow)
block_private_metadata_endpoints = true      # block 169.254.169.254 & friends (default true)

[egress]
isolate_netns = "strict"                     # REQUIRED for a real firewall — see below
```

The proxy checks each request's target host: plain HTTP is parsed and forwarded (or `403`ed);
HTTPS is policy-checked at `CONNECT` and blind-tunnelled (no TLS interception). It also blocks cloud
**metadata endpoints** by default and re-checks every DNS result before dialing (an SSRF /
DNS-rebinding guard).

> **Honest limitation — the composition is what makes it a firewall.** The allow/block list is a
> **real domain-level egress firewall only when composed with `[egress].isolate_netns = "strict"`**
> (which requires [`pasta`](https://passt.top/)): strict forwards *only* the proxy port and blocks
> all other outbound, so the proxy is the child's **only** way out. **Without** the strict jail — on
> the shared host network, or under the `auto`/`on` NAT jail — the proxy only constrains
> **proxy-aware** clients: a tool that ignores `http_proxy` or connects to a **raw IP** bypasses the
> policy. There is no transparent interception without the jail. Raincoat discloses which case is in
> effect in the audit log and on stderr every run. `[network_policy]` needs loopback reachability, so
> it conflicts with `--net off` (Raincoat refuses that combination). A ready-to-edit profile lives at
> [`examples/guarded.toml`](examples/guarded.toml).

---

## Browser isolation (`[browser]`)

The fake `$HOME` already keeps your **real** Chrome/Firefox profiles out of the sandbox — they
are simply never mounted, so a headless-browser tool can't read your cookies, saved passwords,
history, or extensions. The optional `[browser]` block **adds** two best-effort layers on top of
that, aimed at Playwright / Puppeteer / Selenium jobs:

1. an **isolated, throwaway browser profile** dir created inside the sandbox (destroyed with it),
   so the tool gets a clean `--user-data-dir` / `-profile` instead of reusing anything; and
2. optional **generic launch shims** — tiny wrapper scripts placed *ahead of the real browser on
   the child's `PATH`* — that exec the real Chromium/Chrome/Edge/Firefox with low-information
   flags prepended (`--user-data-dir=<isolated>`, `--lang`, `--window-size`, and
   `--disable-gpu`/`--disable-extensions`/`--disable-sync`).

```toml
[browser]
enabled = true
isolate_profile = true          # throwaway --user-data-dir / -profile inside the sandbox
use_launch_shims = true         # PATH wrappers ahead of the real browser
locale = "en-US"                # -> --lang=en-US
viewport = "1280x720"           # -> --window-size=1280,720
timezone = "UTC"                # -> TZ in the child env
disable_gpu = true
disable_extensions = true
disable_sync = true
```

A ready-to-edit profile lives at [`examples/browser.toml`](examples/browser.toml).

> **Honest limitation — the shims are best-effort, not a boundary.** A shim only affects a browser
> launched **by name via `PATH`** (e.g. `google-chrome`, `chromium`, `firefox`). A tool that spawns
> the browser by its **absolute path** (`/usr/bin/google-chrome`), or that passes its **own**
> `--user-data-dir` / conflicting flags, bypasses the shim entirely — Raincoat does **not** rewrite
> a caller's argv or intercept `execve`. The isolated profile and the shim flags reduce casual
> cross-run/profile leakage and normalize a few obvious fingerprint knobs; they are **not**
> deep anti-fingerprinting (canvas/WebGL/audio/font/TLS-JA3 signals are untouched). The real
> protection here is that your **actual** browser profiles are absent from the sandbox in the first
> place. Every run's audit note records the profile dir, whether shims were written, and this
> caveat.

---

## Roadmap

The core sandbox implements the fake home, env scrub, generic identity/locale/timezone,
filesystem restriction, `full`/`off` networking, and the audit log. Several items once on this
roadmap have since shipped.

**Delivered** (documented in the sections above / [`docs/EGRESS.md`](docs/EGRESS.md)):

- **Curated font set** — masks `/usr/share/fonts` and re-binds only the curated Noto/DejaVu dirs,
  so `fc-list` shows a generic set instead of your host's full font list (best-effort fallback when
  no curated dirs exist).
- **Minimal `/etc`** — generic `/etc/hostname`, `/etc/hosts`, and `/etc/localtime`.
- **JSON audit logs** — `[audit].format = "json"` / `--audit-format json`, one structured object
  per run alongside the human-readable format; `raincoat report` summarizes either.
- **Tripwire / honeytoken files** — `[filesystem.tripwire]` plants inert decoy credentials in the
  fake home.
- **Egress bridge / endpoint indirection** — hides one upstream's URL from the child
  ([Egress bridge](#egress-bridge-endpoint-indirection)).
- **Isolated-netns jail** (`pasta`) — `isolate_netns = auto|on|off|strict`; fixes the
  `/proc/net/tcp` upstream leak and hides other host-loopback services, and `strict` blocks general
  internet for a real bridge-only egress firewall.
- **Guarded proxy / domain firewall** — `[network_policy]` host allow/block + metadata-IP blocking,
  a real domain-level egress firewall when composed with the strict jail
  ([Network policy](#network-policy-guarded-proxy)).
- **Browser isolation** (best-effort) — `[browser]` throwaway profile + generic PATH launch shims
  ([Browser isolation](#browser-isolation-browser)).
- **Per-job profile templates** — the [`examples/`](examples/) directory (strict, paranoid,
  ai-agent, node-build, python-tool, egress, api-agent, guarded, browser).
- **macOS best-effort mode** (in progress on `macos-seatbelt-backend`) — a reduced-guarantee Seatbelt
  backend behind the platform seam: in-process `sandbox_init` deny-based filtering + a fail-closed
  per-run pre-flight probe, a kernel egress firewall, a best-effort **DYLD identity/fingerprint
  interposer** (hostname/username/CPU/kernel/RAM for non-hardened targets), and honest `[-]` gaps (no
  font/`/etc` masking). Full honest write-up in [`docs/MACOS.md`](docs/MACOS.md).

**Still ahead / genuine non-goals:**

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
  username/hostname/HOME, not the uid).

---

*Raincoat: it won't stop a hurricane, but it'll keep the casual drizzle off your data.*
