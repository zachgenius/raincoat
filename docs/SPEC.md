# Raincoat — Full Specification (source of truth for all agents)

Raincoat is a lightweight **privacy sandbox** for running untrusted command-line agents,
harnesses, scripts, and developer tools. It wraps **bubblewrap (`bwrap`)** on Linux.

> Some CLI tools and AI agents are too nosy. Raincoat gives them a fake home, fake locale,
> fake timezone, fake font environment, restricted filesystem access, scrubbed environment
> variables, optional network restrictions, and an audit log.

**Language: C++17. Backend: bubblewrap. Linux-first MVP.** Honest positioning: a lightweight
privacy sandbox, NOT a perfect security boundary. No "military-grade"/"absolute security" claims.

## CLI

```
raincoat -- <command> [args...]          # alias for `raincoat run -- ...`
raincoat run [options] -- <command> ...
raincoat doctor
raincoat init
raincoat report
raincoat --help / -h / --version / -V
```

`raincoat -- <cmd>` behaves exactly like `raincoat run -- <cmd>`.

### Options (for `run`)
```
--strict
--profile <path>
--allow-read <path>       (repeatable)
--allow-write <path>      (repeatable)
--allow-env <NAME>        (repeatable)
--set-env <KEY=VALUE>     (repeatable)
--net <full|off>
--workdir <path>
--audit-log <path>
--audit-format <text|json>
--keep-temp
```

### CLI grammar (global options before the subcommand)
Global options may appear **before** a bare subcommand keyword (`run|doctor|init|report`):
the first such keyword found before the `--` separator selects the subcommand and the
surrounding options apply to it (`raincoat --profile p init`, `raincoat --strict doctor`,
`raincoat --audit-format json run -- cmd`). Everything after the first `--` is the verbatim
target command, so `raincoat -- init` RUNS `init` as a command — it does NOT select the init
subcommand. A value that follows a value-taking flag (e.g. `--profile init`) is that flag's
value, never a subcommand keyword. `raincoat run -- <cmd>` and `raincoat init --force` are
unchanged.

## Default (non-strict) behavior
1. Create a temporary sandbox directory.
2. Create a fake HOME inside it: `<temp>/home/user`, plus `<temp>/tmp`, `<temp>/out`.
3. Set env: `HOME=<temp>/home/user`, `TMPDIR=<temp>/tmp`, `TZ=UTC`,
   `LANG=en_US.UTF-8`, `LC_ALL=en_US.UTF-8`.
4. Clear most inherited environment variables.
5. Preserve only a small safe allowlist by default: `PATH`, `TERM`, and `USER`
   (replace USER with a generic value, e.g. `user`).
6. Do NOT mount the real home directory (hide sensitive files).
7. Mount the current working directory read-write by default (non-strict).
8. Run the target command through `bwrap`.

## Strict mode (`--strict`)
1. Deny access to CWD unless explicitly allowed via --allow-read/--allow-write.
2. Require explicit --allow-read / --allow-write for any project access.
3. Fake home.
4. Network OFF by default.
5. Scrub all non-essential environment variables.
6. Generic locale/timezone.
7. Log a clear warning if the command may not work due to strict isolation
   (e.g. no writable paths were allowed).

## Filesystem
- **Fake HOME**: command must not see real `$HOME`. Create `<temp>/home/user`, `<temp>/tmp`,
  `<temp>/out`. Set `HOME` and `TMPDIR` accordingly.
- **--allow-read <path>**: mount path read-only inside the sandbox at the SAME absolute path.
- **--allow-write <path>**: mount path read-write at the same absolute path.
- **Default CWD**: non-strict => CWD mounted read-write. strict => not mounted unless allowed.
- Real HOME is NEVER mounted by default.
- Sensitive paths that must NOT leak by default (documented as dangerous in comments/tests/docs):
  `~/.ssh ~/.aws ~/.azure ~/.config/gcloud ~/.kube ~/.gnupg ~/.docker ~/.npmrc ~/.pypirc
  ~/.git-credentials ~/.gitconfig ~/.config/gh ~/.config/google-chrome ~/.config/chromium
  ~/.mozilla ~/Documents ~/Desktop ~/Downloads` (+ macOS Library paths, for docs).

## Environment variable scrubbing
- Do NOT inherit the full parent environment; allow only a small safe set (PATH, TERM, USER).
- Explicitly remove variables matching these patterns unless allowed:
  `*_TOKEN *_SECRET *_KEY AWS_* GITHUB_* GOOGLE_* OPENAI_* ANTHROPIC_* KUBECONFIG
  SSH_AUTH_SOCK DOCKER_HOST NPM_TOKEN PYPI_TOKEN`
- `--allow-env NAME` copies NAME from parent env if present.
- `--set-env KEY=VALUE` sets/overrides in sandbox.
- **`--set-env` wins over `--allow-env`.**
- Log which variables were allowed / set / scrubbed. NEVER log secret values.
- The default safe-allowlist entries (PATH/TERM/USER) are not "scrubbed"; scrubbed = present in
  parent but deliberately dropped (esp. sensitive-pattern matches).

## Locale & timezone
- Defaults: `TZ=UTC`, `LANG=en_US.UTF-8`, `LC_ALL=en_US.UTF-8`.
- Minimal `/etc` view (implemented): generic files written into the sandbox temp tree and
  bound read-only, so the host's real `/etc/hostname`/`/etc/hosts` are NEVER exposed:
  - `/etc/hostname` = the generic hostname (`ext.hostname`, default `sandbox`).
  - `/etc/hosts` = `127.0.0.1 localhost` / `::1 localhost` / `127.0.1.1 <hostname>`.
  - `/etc/localtime` = read-only bind of `/usr/share/zoneinfo/<TZ or UTC>` when it exists.
  - `/etc/resolv.conf` is bound only when network is enabled (existing behavior).

## Fonts / fontconfig (curated generic set — real fs-level isolation)
- Goal: target program cannot inspect the host's full installed font list.
- The base `--ro-bind /usr` exposes the host's full `/usr/share/fonts`. When fontconfig is
  ENABLED, Raincoat MASKS it with `--tmpfs /usr/share/fonts` (emitted AFTER `--ro-bind /usr`)
  and then re-binds read-only ONLY the curated generic dirs that exist on the host:
  `/usr/share/fonts/truetype/dejavu`, `/usr/share/fonts/truetype/noto`,
  `/usr/share/fonts/opentype/noto` (Noto Sans/Serif/Sans Mono/Color Emoji + DejaVu Sans).
  The child therefore enumerates only the generic set.
- A curated `fonts.conf` is written into the sandbox fontconfig dir listing ONLY those curated
  dirs plus generic aliases (`sans-serif`→Noto Sans, `serif`→Noto Serif, `monospace`→Noto Sans
  Mono, `emoji`→Noto Color Emoji), with DejaVu as a secondary fallback.
- `FONTCONFIG_PATH`, `FONTCONFIG_FILE`, and a minimal `XDG_DATA_DIRS` are set.
- When fontconfig is DISABLED, `/usr/share/fonts` is NOT masked (current behavior preserved).
- Robust to which curated dirs exist: only existing dirs are re-bound; if none exist, the host
  font tree is left unmasked rather than leaving the child with no fonts.

## Audit format
- `[audit].format = "text" | "json"` (default `text`); CLI `--audit-format <text|json>` overrides.
- `text`: the human-friendly start/end blocks (start written before the fork for tamper-evidence).
- `json`: a single valid JSON object per run written after the child exits (it carries the exit
  code), to the same `audit_log_path`. Same information as the text audit — command, mode, network,
  fake_home, workdir, mounts, env allowed/set/scrubbed NAMES only, timezone, locale, fontconfig,
  egress bridges (upstream "hidden" unless redaction disabled), reserved/active-policy notes,
  already-redacted bwrap command, exit_code — and NEVER any secret VALUE. Strings are JSON-escaped.
- Multiple JSON runs append as JSON-Lines; `raincoat report` parses the latest JSON object (or the
  text blocks) and prints a summary either way.

## Network modes
- Enum reserves: `full | off | allowlist | ask`. MVP implements `full` and `off` only.
- Default: normal mode => full; strict mode => off.
- `off`: use bwrap `--unshare-net` (disable network).
- `full`: normal host networking (do not unshare net).
- Do NOT implement ask/allowlist yet, but design the enum for them.

## Audit log
- Default location: `.raincoat/audit.log` under the working directory. Writing the audit is
  best-effort: if that directory cannot be created/written (e.g. a read-only project dir), the
  audit is silently skipped with a non-fatal `raincoat: note:` on stderr and the run proceeds.
  (The MVP does NOT fall back to a temp dir; `--audit-log <path>` lets you redirect it.)
- `--audit-log <path>` overrides.
- Log events (human-friendly lines):
  Raincoat started; Command; Mode (normal/strict); Network (full/off); Fake HOME; Workdir;
  Allowed read paths; Allowed write paths; Env allowed; Env set; Env scrubbed; Timezone;
  Locale; Fontconfig (enabled/best-effort/unavailable); Bubblewrap command constructed;
  Process exit code. NEVER log environment secret VALUES (every `--setenv` value in the logged
  bwrap command is redacted to `<redacted>`; only NAMES appear). Note the honest boundary: the
  `Command:` line and the command tail of the bwrap invocation are the user's own argv and are
  logged VERBATIM — a secret passed as a command-line argument WILL appear. Secrets belong in
  `--set-env`/`--allow-env` (redacted), never in argv. README documents this caveat.
- `raincoat report`: read latest audit log and print a human-friendly summary. Slightly playful
  tone OK but not unprofessional. Example: "Raincoat hid your real HOME and scrubbed 12
  potentially sensitive environment variables." Optional: "Verdict: this tool did not get to
  see you naked."

## Config file (TOML)
- `raincoat init` creates `.raincoat.toml`.
- `--profile <path>` loads a config file. **CLI flags override profile.**
- Example:
```toml
strict = false
network = "full"
allow_read = ["./src"]
allow_write = ["./out"]
allow_env = ["OPENAI_API_KEY"]
[env]
TZ = "UTC"
LANG = "en_US.UTF-8"
LC_ALL = "en_US.UTF-8"
[fontconfig]
enabled = true
[audit]
log_file = ".raincoat/audit.log"
```

## Error handling (exact-ish messages)
- Missing bwrap:
```
Error: bubblewrap / bwrap was not found.

Install it with your package manager, for example:
  Ubuntu/Debian: sudo apt install bubblewrap
  Fedora: sudo dnf install bubblewrap
  Arch: sudo pacman -S bubblewrap

Then run:
  raincoat doctor
```
- No command:
```
Error: no command provided.

Usage:
  raincoat -- <command> [args...]
```
- Missing path: `Error: allowed path does not exist: ./foo`
- Malformed set-env: `Error: expected --set-env KEY=VALUE`

## Modules
`cli, profile, runner, bwrap, env_guard, fs_guard, net_guard, font_guard, audit, doctor`
(+ a minimal `toml` parser, + `config.hpp` shared types, + `report`, `init`).

## doctor
Check whether host supports the required sandbox backend: bwrap present + executable +
version; user namespaces available; basic `bwrap true` smoke test. Print pass/fail with
install hints. Exit nonzero if unusable.

## Tests (must cover)
1. CLI parsing. 2. Profile loading. 3. Env scrubbing. 4. --allow-env. 5. --set-env override.
6. Strict => net off. 7. Normal => CWD access. 8. Audit log creation. 9. Missing command error.
10. Missing bwrap error handling. Integration tests needing bwrap: mark clearly + skip gracefully
if bwrap unavailable.

## README must cover
What Raincoat is; problem it solves; example usage; what it protects; what it does NOT protect;
Linux-first status; bubblewrap dependency; security limitations; example profiles; roadmap.
Positioning + warning text (verbatim intent):
"Raincoat is a lightweight privacy sandbox for nosy CLI tools and AI agents. It helps prevent
untrusted tools from casually inspecting your real home directory, credentials, browser
profiles, installed fonts, locale, timezone, and other machine fingerprints."
"Raincoat reduces accidental and opportunistic privacy leakage. It is not a guarantee against
malicious code, kernel exploits, sandbox escapes, or commands you explicitly allow to access
sensitive files."
Roadmap: network allowlist mode; interactive ask mode; browser profile isolation
(Playwright/Puppeteer/Selenium); better font/emoji fingerprint resistance; honeytoken/tripwire
files; macOS best-effort; JSON audit logs; per-command policy templates; agent-specific profiles.

## Per-platform capability / guarantee matrix
Raincoat's guarantees are delivered by a per-platform backend behind the seam in `src/backend.hpp`
(EXACTLY ONE linked per build; compile-time selection, no runtime dispatch). **Linux (bubblewrap) is
the reference backend** — it CONSTRUCTS a mount/UTS/net namespace, so hiding is structural and
fail-closed. **macOS (Seatbelt via `/usr/bin/sandbox-exec`) is best-effort** — it FILTERS the real
filesystem with a kernel deny policy, so hiding is deny-based and fail-open, and the runner adds a
per-run fail-closed pre-flight probe to compensate. The runner GATES every platform step on the
backend's `Capabilities` so a guarantee a backend cannot deliver is SKIPPED, never dishonestly audited.
Measured on macOS 26.5.1 (Apple Silicon). Full honest write-up: `docs/MACOS.md`.

| Guarantee | Linux (bwrap) — reference | macOS (Seatbelt) — best-effort |
|---|---|---|
| Filesystem hiding | **Structural / fail-closed**: unlisted paths absent; a missing bind aborts | **Filter / fail-open**: real `$HOME` + `/Users` DENIED over the real fs (present-but-denied); every path realpath'd (a raw `/tmp` rule fails open); a per-run **pre-flight probe** refuses the run if the real `$HOME` is still readable |
| Network off | `--unshare-net` (fresh empty netns) | `(deny network*)` kernel policy |
| Egress firewall (proxy/bridge only) | Needs the pasta **strict** netns jail; without it, proxy-aware clients only | **Kernel firewall for ALL clients, no helper**: `(deny network*)` + `(allow network-outbound (remote ip "localhost:<port>"))`; needs no pasta, does not fail closed — STRONGER than Linux |
| Identity / hostname | Generic `USER`/`LOGNAME`/`HOSTNAME` **+** fresh UTS ns fakes `gethostname()` | Generic `USER`/`LOGNAME` env only; **`gethostname()`/`uname()` leak the real name** (only `$HOSTNAME` env faked); username can still leak via `getpwuid()` |
| Fonts | Curated Noto/DejaVu set (tmpfs mask + re-bind) | **None** — Core Text, not fontconfig; cannot overlay `/usr/share/fonts` |
| Minimal `/etc` | Generic `/etc/hostname`/`hosts`/`localtime` binds | **None** — cannot bind a fake `/etc` |
| Env injection | Baked into argv (`--clearenv` + `--setenv`) | Installed at `execve` (SBPL has no env directives) |

## Build/test environment facts (this host)
- g++ 13.3 (use -std=c++17). cmake 3.28. GoogleTest static libs at
  /usr/lib/x86_64-linux-gnu/libgtest.a and libgtest_main.a; headers /usr/include/gtest.
  Link tests with: -lgtest -lgtest_main -lpthread.
- bwrap present at /usr/bin/bwrap and functional. `--unshare-net` works.
- FS layout: /bin -> usr/bin, /lib -> usr/lib, /lib64 -> usr/lib64, /sbin -> usr/sbin.
  Correct base mount: --ro-bind /usr /usr, --symlink usr/bin /bin, --symlink usr/lib /lib,
  --symlink usr/lib64 /lib64, --symlink usr/sbin /sbin, --proc /proc, --dev /dev.
```
