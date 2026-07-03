# Raincoat — Implementation Progress Tracker

Living checklist for both phases. Status keys: `[x]` done & verified · `[~]` in progress ·
`[ ]` pending · `[-]` intentionally deferred (documented non-goal / later).
Updated as work lands; committed with the code so progress is traceable in git.

Legend for "Where": module source + test file that owns the behavior.

---

## Phase 1 — Core MVP privacy sandbox

### 1.1 Build & project scaffolding
- [x] C++17 project, CMake build, `-Wall -Wextra` clean — *CMakeLists.txt*
- [x] GoogleTest wiring; every module test registered with `ctest` (15 suites, 545 tests) — *CMakeLists.txt*
- [x] Shared type contract — *src/config.hpp*
- [x] Interface contract doc — *docs/DESIGN.md*; behavioural spec — *docs/SPEC.md*
- [x] `assets/fontconfig/fonts.conf`; `examples/strict.toml`, `examples/ai-agent.toml`; `.gitignore`

### 1.2 CLI parsing & dispatch  (cli, main)
- [x] `raincoat -- <cmd>` behaves as `raincoat run -- <cmd>` — *cli / test_cli*
- [x] Subcommands: `run`, `doctor`, `init`, `report` — *cli / test_cli*
- [x] `--help`/`-h`, `--version`/`-V` — *cli / test_cli*
- [x] Options: `--strict --profile --allow-read --allow-write --allow-env --set-env --net --workdir --audit-log --keep-temp` — *cli / test_cli*
- [x] `raincoat init [--force|-f]` sets `init_force` — *cli / test_cli*
- [x] Repeatable flags accumulate; everything after `--` is verbatim command — *cli / test_cli*
- [x] `main` dispatch wired to real behavior for every subcommand — *main* (verified e2e)

### 1.3 Default (non-strict) behavior  (runner)
- [x] Create temp sandbox dir (mkdtemp) — *runner*
- [x] Fake HOME `<temp>/home/user`, plus `<temp>/tmp`, `<temp>/out` — *runner*
- [x] Set `HOME`, `TMPDIR`, `TZ=UTC`, `LANG=en_US.UTF-8`, `LC_ALL=en_US.UTF-8` — *runner + env_guard* (verified)
- [x] Clear most inherited env; preserve safe base (`PATH`, `TERM`), generic `USER=user` — *env_guard / test_env_guard*
- [x] Real HOME never mounted (verified end-to-end: `~/.ssh` not visible) — *runner + fs_guard + test_integration*
- [x] cwd mounted RW by default in non-strict — *fs_guard / test_fs_guard*
- [x] **Guard: do NOT auto-mount cwd when cwd == $HOME** (verified: refuses + warns) — *fs_guard / test_fs_guard + e2e*
- [x] Run target command through `bwrap` (fork/exec, exit-code propagation) — *runner*

### 1.4 Strict mode  (--strict)
- [x] Deny cwd unless explicitly allowed (verified) — *fs_guard / runner*
- [x] Network OFF by default in strict — *runner resolve_config / test_runner*
- [x] Scrub all non-essential env — *env_guard*
- [x] Generic locale/timezone — *env_guard / runner*
- [x] Warn when command may not work (no writable paths) — *runner* (verified warning printed)

### 1.5 Filesystem  (fs_guard, runner, bwrap)
- [x] `--allow-read <path>` → RO mount at same absolute path — *fs_guard / test_fs_guard*
- [x] `--allow-write <path>` → RW mount at same absolute path — *fs_guard / test_fs_guard*
- [x] Missing path → `Error: allowed path does not exist: <path>` — *fs_guard / test_fs_guard*
- [x] Real HOME / sensitive dirs never mounted by default (design + home guard) — *fs_guard*
- [x] End-to-end: sandboxed process cannot see real `~/.ssh` etc. — *test_integration + verified*

### 1.6 Environment scrubbing  (env_guard)
- [x] Sensitive patterns removed: `*_TOKEN *_SECRET *_KEY AWS_* GITHUB_* GOOGLE_* OPENAI_* ANTHROPIC_* KUBECONFIG SSH_AUTH_SOCK DOCKER_HOST NPM_TOKEN PYPI_TOKEN` — *env_guard / test_env_guard*
- [x] `--allow-env NAME` copies from parent if present — *env_guard / test_env_guard*
- [x] `--set-env KEY=VALUE` sets/overrides; **wins over --allow-env** — *env_guard / test_env_guard*
- [x] Identity vars stay faked even against `--allow-env USER` (real login not leaked) — *runner* (verified)
- [x] Malformed `--set-env` → `Error: expected --set-env KEY=VALUE` — *cli / test_cli*
- [x] Log allowed/set/scrubbed by NAME only, never values — *audit / test_audit* (verified no leak)

### 1.7 Locale & timezone
- [x] Defaults `TZ=UTC`, `LANG`/`LC_ALL=en_US.UTF-8` — *env_guard / runner*
- [x] Audit reflects actual TZ/locale even when `--set-env` overrides them — *runner* (verified)
- [-] Full `/etc` view (hostname/hosts/localtime) — *bwrap* (best-effort; resolv.conf + /etc/ssl bound on net full; rest kept minimal per SPEC)

### 1.8 Fonts / fontconfig  (font_guard)  — best-effort MVP
- [x] Minimal fontconfig dir + `fonts.conf` written into sandbox — *font_guard / test_font_guard*
- [x] Sets `FONTCONFIG_PATH`, `FONTCONFIG_FILE` — *font_guard / test_font_guard*
- [x] Status enum Enabled/BestEffort/Unavailable/Disabled — *font_guard*
- [x] Wired into runner env + audit (shows "Fontconfig: enabled") — *runner* (verified)
- [-] Bundle a generic Noto/DejaVu font set — *deferred (README notes best-effort)*

### 1.9 Network  (net_guard, bwrap, runner)
- [x] Enum reserves `full|off|allowlist|ask`; MVP implements full/off — *config.hpp / net_guard*
- [x] `off` → `--unshare-net`; `full` → shared net + resolv.conf bind — *net_guard / bwrap / tests*
- [x] Default full (normal) / off (strict) — *runner resolve_config*
- [x] End-to-end: `--net off` isolates the network namespace — *test_integration + verified*

### 1.10 Audit log  (audit, report, runner)
- [x] Human-friendly start block (command, mode, network, fake HOME, workdir, allowed r/w, env allowed/set/scrubbed, tz, locale, fontconfig, bwrap command) — *audit / test_audit* (verified)
- [x] **Structural secret redaction** of `--setenv` values (argv-level) — *bwrap::redact_argv_for_audit + audit* (verified: all values `<redacted>`)
- [x] `write_audit` append + mkdir -p parent — *audit / test_audit*
- [x] Exit-code end line — *audit / test_audit* (verified)
- [x] Default path `.raincoat/audit.log` (or temp) + `--audit-log` override, written at runtime — *runner* (verified)
- [x] `raincoat report` summarizes latest audit (playful-but-pro) — *report / test_report + main* (verified)

### 1.11 Config file / profile  (toml, profile)
- [x] Minimal TOML parser (comments, bool, strings, inline+multiline arrays, tables, dotted keys) — *toml / test_toml*
- [x] `load_profile` maps all fields via the toml module — *profile / test_profile*
- [x] Reject wrong-typed `strict`/`network`/`fontconfig.enabled`/`audit.log_file` (no silent privacy downgrade) — *profile / test_profile*
- [x] `network` limited to full|off (reject allowlist/ask in MVP) — *profile / test_profile*
- [x] `--profile <path>` load; CLI overrides profile (`merge`) — *profile / test_profile*
- [x] Profile actually loaded + merged in the live run — *runner resolve_config* (verified)
- [ ] Document precedence: strict's net-off is a *default* a profile's `network="full"` overrides — *README* (docs phase)

### 1.12 init  (init)
- [x] `default_toml()` matches SPEC schema — *init / test_init*
- [x] `write_init` refuses overwrite unless `--force` (message points to `--force`) — *init / test_init* (verified)
- [x] `raincoat init` creates `.raincoat.toml` end-to-end — *main* (verified)

### 1.13 doctor  (doctor)
- [x] `find_bwrap` (PATH search), version, userns/smoke check — *doctor / test_doctor*
- [x] `format_doctor` pass/fail + install hints (apt/dnf/pacman) — *doctor / test_doctor*
- [x] `raincoat doctor` end-to-end (exits 0 here; nonzero when unusable) — *main* (verified PASS)

### 1.14 Error handling (exact messages)
- [x] Missing command message — *cli / test_cli*
- [x] Missing path message — *fs_guard / test_fs_guard*
- [x] Malformed set-env message — *cli / test_cli*
- [x] Missing bwrap message (multi-line, install hints) surfaced at run time — *runner* (implemented)

### 1.15 Tests (SPEC's 10 required)
- [x] 1 CLI parsing · [x] 2 Profile loading · [x] 3 Env scrubbing · [x] 4 --allow-env · [x] 5 --set-env override
- [x] 6 Strict ⇒ net off · [x] 7 Normal ⇒ cwd access · [x] 8 Audit log creation
- [x] 9 Missing command error · [x] 10 Missing bwrap handling
- [x] Integration tests invoking real `bwrap` (skip gracefully if absent) — *test_integration*

### 1.16 Docs
- [x] SPEC / DESIGN / EGRESS / PROGRESS docs
- [ ] README: what it is, problem, usage, protects / does-not-protect, Linux-first, bwrap dep, limitations (incl. PATH/username caveat, precedence), example profiles, roadmap — *README.md* (docs phase)
- [ ] Honest positioning + warning text present — *README.md*
- [ ] Example profiles runnable-or-clearly-templates note — *examples/*

### 1.17 Verification gate (Phase 1 done when ALL true)
- [x] `cmake && cmake --build` clean under `-Wall -Wextra`
- [x] `ctest` 100% green (15 suites / 545 tests)
- [x] Real runs work: `raincoat -- env` (secrets hidden, fake HOME), `--net off`, `--strict`, cwd==$HOME guard, `doctor`, `init`, `report` — all verified
- [x] Committed + pushed to master — core (848faba); integration (this commit)
- [ ] README written (final MVP milestone)

---

## Phase 2 — Egress bridge / endpoint indirection  (see docs/EGRESS.md)

Generic, profile-driven. No provider/model/env/service names hard-coded.

### 2.1 Profile schema & parsing
- [ ] `[egress] mode = off|bridge`; `[[egress.bridge]]` array-of-tables — *profile/egress*
- [ ] TOML parser supports `[[array-of-tables]]` — *toml / test_toml*
- [ ] Fields: `name, env, child_endpoint, upstream_endpoint, hide_upstream_from_child, preserve_host` — *egress*

### 2.2 Host-side bridge lifecycle  (egress)
- [ ] Read profile on host BEFORE sandbox start
- [ ] Start local listener per `child_endpoint`; support multiple bridge entries
- [ ] Clean shutdown/teardown with the sandbox

### 2.3 Child visibility / isolation
- [ ] Inject ONLY the configured `env=child_endpoint` into child
- [ ] Child never sees `upstream_endpoint` in its environment
- [ ] Profile file NOT mounted into sandbox unless explicitly allowed
- [ ] Resolve netns reachability (child reaches 127.0.0.1 bridge) — document MVP constraint

### 2.4 Forwarding
- [ ] Basic HTTP forwarding (MVP): method, path, query, headers, body preserved
- [ ] Host header policy via `preserve_host`
- [ ] Streaming responses where practical

### 2.5 Audit
- [ ] Log "Egress bridge enabled: <name>", child endpoint, "Upstream endpoint: hidden", injected env var
- [ ] Never log upstream endpoint or sensitive bodies by default (verbose mode = explicit opt-in, later)

### 2.6 Longer-term (deferred, design so they slot in)
- [-] HTTPS upstreams · [-] header rewrite rules · [-] domain allow/block · [-] transparent egress · [-] explicit MITM (off by default)

### 2.7 Limitations documented (honest)
- [ ] Hides upstream hostname from child env, not the fact a custom endpoint is used
- [ ] HTTPS hostname rewrite may need MITM/cert control/transparent routing
- [ ] No claims of bypassing any specific tool/service detection

### 2.8 Verification gate (Phase 2 done when ALL true)
- [ ] Unit + integration tests: env injection, upstream hidden from child, profile not mounted, HTTP forward + stream, audit redaction
- [ ] Real demo: child hits `child_endpoint`, receives upstream response, upstream absent from child env & audit
- [ ] EGRESS.md limitations reflected in README
- [ ] Committed + pushed to master
