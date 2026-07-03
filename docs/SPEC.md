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
--keep-temp
```

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
- If practical, provide a minimal `/etc` view: `/etc/hostname`, `/etc/hosts`,
  `/etc/resolv.conf` (only when network enabled), `/etc/localtime` (if needed).
  Do not overcomplicate in MVP.

## Fonts / fontconfig (best-effort in MVP)
- Goal: target program cannot easily inspect host's full installed font list.
- Create a minimal fontconfig dir inside the sandbox; provide a minimal `fonts.conf`.
- Set `FONTCONFIG_PATH`, `FONTCONFIG_FILE`, and `XDG_DATA_DIRS` if needed.
- If bundling fonts is too much for pass 1, create the abstraction + leave clear TODOs.
- README: font isolation is best-effort in MVP. Longer-term generic set: Noto Sans/Serif/Sans
  Mono/Color Emoji, DejaVu Sans.

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

## Build/test environment facts (this host)
- g++ 13.3 (use -std=c++17). cmake 3.28. GoogleTest static libs at
  /usr/lib/x86_64-linux-gnu/libgtest.a and libgtest_main.a; headers /usr/include/gtest.
  Link tests with: -lgtest -lgtest_main -lpthread.
- bwrap present at /usr/bin/bwrap and functional. `--unshare-net` works.
- FS layout: /bin -> usr/bin, /lib -> usr/lib, /lib64 -> usr/lib64, /sbin -> usr/sbin.
  Correct base mount: --ro-bind /usr /usr, --symlink usr/bin /bin, --symlink usr/lib /lib,
  --symlink usr/lib64 /lib64, --symlink usr/sbin /sbin, --proc /proc, --dev /dev.
```
