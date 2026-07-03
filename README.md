# Raincoat

**Raincoat is a lightweight privacy sandbox for nosy CLI tools and AI agents.** It helps
prevent untrusted tools from casually inspecting your real home directory, credentials, browser
profiles, locale, timezone, and other machine fingerprints. It also normalizes generic font
aliases (best-effort — it does not hide the installed font list; see the caveat below).

It is a thin, Linux-first wrapper around [bubblewrap (`bwrap`)](https://github.com/containers/bubblewrap)
that hands the command you run a *fake* home, a scrubbed environment, a generic locale and
timezone, a best-effort font environment, restricted filesystem access, optional network
isolation, and an audit log of exactly what it did.

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

Result: PASS — host is usable. bwrap is present and the smoke test passed.
```

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
- **Your font environment (best-effort — see the honest caveat).** Raincoat points fontconfig at
  a minimal in-sandbox config that remaps the `serif` and `monospace` aliases to DejaVu Serif /
  DejaVu Sans Mono. The `sans-serif` alias is also declared, but its normalization is **not
  reliable across hosts** — on some systems `fc-match sans-serif` is still outranked by another
  installed family — so do not count on it. It
  does **not** yet hide your installed font list: because `/usr` is mounted read-only, the config
  still resolves the host's real font directories, so `fc-list` can still enumerate every font on
  your machine. Bundling a fixed generic font set (which would actually make the list uniform) is
  on the roadmap. Treat this as cosmetic normalization today, not fingerprint resistance.
- **The filesystem.** Only the paths you allow (plus the CWD in non-strict mode) are visible.
  `--allow-read` is read-only; `--allow-write` is read-write.
- **The network (optional).** `--net off` (the default in strict mode) isolates networking.
- **An audit trail.** Every run appends a human-readable record to the audit log — mode,
  network, fake home, mounts, which env vars were allowed / set / scrubbed, and the exact bwrap
  command. **Environment *values* are never written to disk**: every env value in the logged
  bwrap command is redacted to `<redacted>` and only variable *names* appear. **Caveat:** the
  *command you run* is logged verbatim (both the `Command:` line and the command tail of the
  bwrap invocation), so a secret you pass as a command-line argument — e.g.
  `curl -H 'Authorization: Bearer <token>'` — **will** appear in the audit log. Put secrets in
  `--set-env`/`--allow-env` (which are redacted), never in argv. `raincoat report` turns the
  latest log into a plain-language summary.

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

**Linux-first.** Raincoat depends on bubblewrap and Linux user namespaces, which is the entire
MVP target. **macOS and Windows are non-goals for the MVP.** A best-effort macOS mode is on the
roadmap but not implemented.

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
- **Font isolation is best-effort.** The MVP ships a minimal fontconfig setup but does **not**
  bundle a fixed font set yet, so it does not hide the installed font list at all — `fc-list`
  inside the sandbox still enumerates every host font (the config resolves the real
  `/usr/share/fonts`). It only remaps the `serif`/`monospace` generic aliases (the `sans-serif`
  remap is best-effort and not reliable across hosts). Real fingerprint resistance
  (a bundled generic font set) is on the roadmap.
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
`raincoat init` writes a starter `.raincoat.toml` you can edit. Two ready-made examples live in
[`examples/`](examples/) and are safe to run as-is.

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
enabled = true             # best-effort font-fingerprint isolation

[audit]
log_file = ".raincoat/audit.log"
```

Every path listed in `allow_read` / `allow_write` **must exist**, or Raincoat refuses to start
with `Error: allowed path does not exist: <path>`. `set_env` is CLI-only (not read from
profiles). Wrong-typed `strict` / `network` / `fontconfig.enabled` values are rejected rather
than silently ignored — a silently-dropped `strict` would be a privacy downgrade.

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

## Roadmap

The MVP implements the fake home, env scrub, generic locale/timezone, best-effort fonts,
filesystem restriction, `full`/`off` networking, and the audit log. Planned and deferred work:

- **Network allowlist mode** — the `NetMode` enum already reserves `allowlist`; let a profile
  permit specific destinations instead of all-or-nothing.
- **Interactive "ask" mode** — prompt before granting access at run time (reserved as `ask`).
- **Browser profile isolation** — first-class handling for Playwright / Puppeteer / Selenium so
  headless-browser tools get a clean profile.
- **Better font/emoji fingerprint resistance** — bundle a fixed generic font set (Noto
  Sans/Serif/Sans Mono/Color Emoji, DejaVu Sans) so the font list is uniform, not best-effort.
- **Honeytoken / tripwire files** — plant decoy credentials in the fake home and flag any tool
  that touches them.
- **macOS best-effort mode** — a reduced-guarantee port for macOS.
- **JSON audit logs** — a machine-readable audit format alongside the human-readable one.
- **Per-command policy templates** — reusable presets for common tools.
- **Agent-specific profiles** — curated starting points for popular AI agents.
- **Egress bridge / endpoint indirection** *(planned, next phase — see [`docs/EGRESS.md`](docs/EGRESS.md))* —
  a host-side HTTP bridge that lets the child connect to a generic local endpoint (e.g.
  `http://127.0.0.1:18080`) while Raincoat privately forwards to the real upstream. The child is
  handed only a configured `child_endpoint` via one env var and never sees the real upstream
  hostname in its environment; the profile holding the upstream is not mounted into the sandbox
  unless you explicitly allow it. Everything is profile-driven and provider-agnostic — no
  hard-coded services. It hides the upstream *hostname* from the child's environment; it does not
  claim to hide that a custom endpoint is in use, and it makes no claim to bypass any specific
  tool or service.

---

*Raincoat: it won't stop a hurricane, but it'll keep the casual drizzle off your data.*
