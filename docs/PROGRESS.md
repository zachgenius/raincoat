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
- [x] Minimal `/etc` view: generic `/etc/hostname`, `/etc/hosts`, `/etc/localtime`=UTC (+ resolv.conf/ssl on net full) — *bwrap/runner* (Phase 3; verified)

### 1.8 Fonts / fontconfig  (font_guard)  — best-effort MVP
- [x] Minimal fontconfig dir + `fonts.conf` written into sandbox — *font_guard / test_font_guard*
- [x] Sets `FONTCONFIG_PATH`, `FONTCONFIG_FILE` — *font_guard / test_font_guard*
- [x] Status enum Enabled/BestEffort/Unavailable/Disabled — *font_guard*
- [x] Wired into runner env + audit (shows "Fontconfig: enabled") — *runner* (verified)
- [x] Curated generic Noto/DejaVu font set with real fs-level isolation (host font families masked) — *font_guard/bwrap/runner* (Phase 3; verified: sandbox shows only dejavu+noto vs 12 host families)

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
- [x] Document precedence: strict's net-off is a *default* a profile's `network="full"` overrides — *README*

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
- [x] SPEC / DESIGN / EGRESS / PROGRESS docs + docs/full-config-reference.toml (config demo)
- [x] README: what it is, problem, usage, protects / does-not-protect, Linux-first, bwrap dep, limitations (incl. PATH/username + PWD + uid/gid caveats, precedence), example profiles, roadmap — *README.md*
- [x] Honest positioning + warning text present — *README.md*
- [x] Example profiles documented as project-local templates — *examples/*

### 1.17 Hardening (post-review, verified)
- [x] Hostname no longer leaks — `--hostname sandbox` — *bwrap/runner* (verified)
- [x] Identity vars (USER/LOGNAME/HOSTNAME) stay generic even against `--allow-env` — *env_guard/runner* (verified)
- [x] Fontconfig dir bind-mounted so `FONTCONFIG_FILE` resolves inside the sandbox; `XDG_DATA_DIRS` set — *bwrap/font_guard* (verified)
- [x] Audit log tamper-proof from the child (`--tmpfs` mask over the audit dir when reachable) — *runner/bwrap* (verified: sentinel absent, not deletable)
- [x] `out` scratch dir wired; temp cleanup on SIGINT/SIGTERM/SIGHUP — *runner*
- [x] Honest docs on residual leaks (uid/gid, mounted absolute paths, PWD) — *README*

### 1.18 Verification gate — Phase 1 MVP (ALL true = DONE)
- [x] `cmake && cmake --build` clean under `-Wall -Wextra`
- [x] `ctest` 100% green (16 suites / 572 tests)
- [x] Real runs verified: secrets hidden + fake HOME, `--net off`, `--strict`, cwd==$HOME guard, generic hostname/identity, working fontconfig, tamper-proof audit, `doctor`/`init`/`report`
- [x] Honest README (no overclaims)
- [x] Committed + pushed to master — core (848faba), integration (aaf7e18), MVP milestone (this commit)

**PHASE 1 MVP: COMPLETE ✅**

---

## Phase 1.5 — Config-driven profile (rich sectioned schema)  ✅ COMPLETE

Accepts the rich sectioned config (docs/full-config-reference.toml) — a directional demo, not a
frozen schema. Backward-compatible with the flat MVP schema; unknown keys/sections tolerated.

### 1.5a TOML engine
- [x] `[[array-of-tables]]` (`get_table_array`) + nested `[a.b.c]` tables — *toml / test_toml*
- [x] Unknown keys/sections tolerated (never fatal); wrong-typed known scalars still rejected — *toml/profile*

### 1.5b Parse + map (→ Config.ext)
- [x] Full sectioned schema parsed into `Config.ext` (ExtendedConfig) — *profile / test_profile*
- [x] Backward compatible with flat schema; nested wins over flat — *profile* (verified)
- [x] Reserved/future sections recorded as honest `reserved_notes` — *profile* (verified: 5 notes)

### 1.5c Wire into runtime (verified end-to-end)
- [x] `[identity]` → USER/HOSTNAME/TZ/LANG/LC_ALL/LANGUAGE + config-driven `--hostname` — *env_guard/bwrap/runner*
- [x] `[environment]` deny (scrubbed even vs `--allow-env`) + custom `scrub_patterns` (e.g. AZURE_*) + `.set` — *env_guard* (verified)
- [x] `[filesystem]` deny (never mounted) + `mode=deny-by-default` (strict-like) — *fs_guard*
- [x] `[backend]` toggles → bwrap flags (`--unshare-user/-cgroup`, mounts, die-with-parent) — *bwrap* (verified)
- [x] `[backend].unshare_uts=false` conflict with hostname masking → **fail-safe override + warning** — *runner* (verified)
- [x] `[filesystem.tripwire]` decoys in fake home; `[proxy]` env injection; `[init].create_dirs`; `[report]` toggle
- [x] Reserved network modes (bridge/guarded/proxy) **fail closed to net-off** + honest audit — *runner* (verified)
- [x] No MVP regression (21 suites / 671 tests, -Wall -Wextra clean)

**Note:** the `[egress]`/`[[egress.bridge]]` blocks are parsed and reserved; actual forwarding is Phase 2.
CLI grammar: the subcommand must be the first token (e.g. `raincoat init --profile X`, not `--profile X init`).

---

## Phase 2 — Egress bridge / endpoint indirection  (see docs/EGRESS.md)  ✅ MVP LANDED

Generic, profile-driven. No provider/model/env/service names hard-coded. Host-side HTTP(S)
forward proxy per bridge (`src/egress.*`), wired into the live runner. The isolated-netns
egress jail (pasta) has since landed: `auto`/`on` are a *partial* jail (fix the `/proc-net`
upstream leak + hide other host-loopback services, but still NAT general internet), while
`isolate_netns = "strict"` is a *full* bridge-only egress firewall — it also blocks general
internet via `-o 127.0.0.1` so only the forwarded bridge port(s) are reachable (§2.6). Items
that remain stay honest `[-]` (a general configurable domain/CIDR allow-list firewall beyond
the bridge-only strict case, guarded/DNS policy, transparent/MITM modes).

### 2.1 Profile schema & parsing
- [x] `[egress] mode = off|bridge`; `[[egress.bridge]]` array-of-tables — *profile/egress*
- [x] TOML parser supports `[[array-of-tables]]` — *toml / test_toml*
- [x] Fields: `name, env, child_endpoint, upstream_endpoint, hide_upstream, preserve_host` (+ `preserve_path/query/method`, `strip_headers`, `inject_headers`) — *config/profile/egress*

### 2.2 Host-side bridge lifecycle  (egress)
- [x] Read profile on host BEFORE sandbox start — *runner* (host-side `egress_srv.start` before fork)
- [x] Start local listener per `child_endpoint`; support multiple bridge entries — *egress / test_egress_e2e*
- [x] Clean shutdown/teardown with the sandbox (accept + per-conn threads joined; rollback on bind failure) — *egress*

### 2.3 Child visibility / isolation
- [x] Inject ONLY the configured `env=child_endpoint` into child — *runner* (verified: child sees only the child endpoint)
- [x] Child never sees `upstream_endpoint` in its environment — *runner* (verified e2e)
- [x] Profile file NOT mounted into sandbox unless explicitly allowed; masked (empty shadow) if reachable — *runner* (verified)
- [x] Resolve netns reachability: egress-bridge mode shares host netns so child reaches 127.0.0.1 bridge; `--net off` conflict refused — *runner* (documented MVP constraint)

### 2.4 Forwarding
- [x] HTTP forwarding: method, path, query, headers, body preserved — *egress / test_egress + e2e* (verified)
- [x] Host header policy via `preserve_host` — *egress::build_upstream_head / test_egress*
- [x] Streaming responses where practical (pipe upstream→child until EOF) — *egress / test_egress_e2e*
- [x] HTTPS upstreams (TLS to upstream via OpenSSL) — *egress*

### 2.5 Audit
- [x] Log "Egress bridge enabled: <name>", child endpoint, "Upstream endpoint: hidden", injected env var — *audit / runner* (verified)
- [x] Never log upstream endpoint or sensitive bodies by default; per-bridge + child-readable fail-closed redaction — *runner / test_egress_audit_ro_leak_attack*

### 2.6 Isolated-netns egress jail (pasta) — LANDED (partial network jail)
- [x] Run the child inside pasta's private netns when egress active + pasta present + `isolate_netns != off`: `pasta --config-net -t none -T <bridge-ports> -- bwrap …` (bwrap JOINS, does not `--unshare-net`) — *runner / test_egress_jail_netns* (verified e2e)
- [x] child_endpoint unchanged at `127.0.0.1:<port>` (pasta `-T` forwards ns loopback → host bridge); child reaches the upstream — *runner* (verified: child got `UPSTREAM_OK`)
- [x] **`/proc/net/tcp` upstream leak FIXED** — host-side bridge→upstream socket stays in the host netns, invisible to the child — *runner* (MEASURED: upstream IP:port absent from child `/proc/net/tcp`)
- [x] Tighter than shared mode: `-t none` exposes only the forwarded bridge port(s); other host-loopback services NOT reachable — *runner*
- [x] `[egress].isolate_netns = auto|on|off|strict` knob; `auto` uses the jail when pasta present, else shared fallback; `strict` (explicit-only) also blocks general internet — *config/profile*
- [x] pasta reaped/torn down on every exit path (normal/error/signal), exit code propagated; graceful fallback + warning when pasta requested but absent — *runner / test_egress_jail_pasta_failure_regression*
- [x] `doctor` reports egress-jail availability (pasta/slirp4netns) as `[ OK ]`/`[INFO]`, never `[FAIL]` — *doctor / test_doctor* (verified)
- [x] **Per-destination egress firewall (bridge-only) — for `isolate_netns = "strict"`** — adds `-o 127.0.0.1` (pasta outbound bound to loopback) so general internet is BLOCKED and ONLY the forwarded bridge port(s) are reachable; requires pasta (fails CLOSED if absent) — *runner / test_egress_jail_netns* (MEASURED: child reaches the bridge, but 1.1.1.1 and off-bridge loopback both fail). The `auto`/`on` NAT jail still retains general internet by IP (honest non-goal for those levels).
- [-] **General domain/CIDR allow-list egress firewall** (an arbitrary configurable set of upstreams, not just the bridge) — the `strict` bridge-only case landed above; a configurable per-domain policy remains future
- [-] Host-loopback mapping on newer pasta (`--map-host-loopback`, so the host is at the child's `127.0.0.1`) — this pasta build lacks it
- [-] `guarded` mode + domain allow/block · [-] DNS policy · [-] transparent egress · [-] explicit MITM (off by default)

### 2.7 Limitations documented (honest)
- [x] Hides upstream URL from child env, not the fact a custom endpoint is used — *EGRESS.md / README*
- [x] Shared-loopback fallback (no pasta / `isolate_netns=off`) ⇒ NOT a network jail; upstream IP:port visible via `/proc/net/tcp`; general net access retained — *EGRESS.md / README* (disclosed in the audit every run)
- [x] Isolated-netns jail (pasta), `auto`/`on`: FIXES the `/proc-net` upstream leak + hides other host-loopback services, but still NATs general internet (not a per-destination firewall) — *EGRESS.md / README* (MEASURED; disclosed in the audit + a stderr note every run)
- [x] Isolated-netns jail (pasta), `strict`: also BLOCKS general internet (`-o 127.0.0.1`) so ONLY the forwarded bridge port(s) are reachable — a per-destination (bridge-only) egress firewall; requires pasta, fails CLOSED if absent — *EGRESS.md / runner* (MEASURED: bridge works, 1.1.1.1 + off-bridge loopback both blocked; disclosed in the audit + stderr as "STRICT ISOLATED-NETNS ... per-destination (bridge-only) egress firewall")
- [x] HTTPS hostname rewrite may need MITM/cert control/transparent routing — *EGRESS.md*
- [x] No claims of bypassing any specific tool/service detection — *EGRESS.md / README*

### 2.8 Verification gate (Phase 2)
- [x] Unit + integration tests (7 egress suites / ~90 cases): env injection, upstream hidden from child, profile not mounted, HTTP forward + stream, audit redaction, teardown, honesty regressions
- [x] Real demo: child hits `child_endpoint`, receives upstream response, upstream absent from child env & audit — verified against `./build/raincoat`
- [x] EGRESS.md limitations reflected in README (Egress bridge section + roadmap)
- [x] Committed + pushed to master — egress module (68e702d), egress wiring (99e698e)

**PHASE 2 (egress bridge MVP): COMPLETE ✅**

---

## Phase 3 — Privacy hardening: curated fonts, minimal /etc, JSON audit, CLI grammar

### 3.1 Curated generic font set (real fs-level isolation)
- [x] `font_guard::curated_font_dirs()` probes the known curated dirs (dejavu, noto TrueType, noto OpenType); `FontSetup.font_dirs` populated on the enabled path — *font_guard / test_font_guard*
- [x] bwrap masks `/usr/share/fonts` with `--tmpfs` (after `--ro-bind /usr`) and re-binds ONLY the curated dirs read-only — *bwrap / runner* (verified e2e: sandbox shows only dejavu/noto; host `lato`/`ubuntu`/… gone)
- [x] Generated `fonts.conf` lists only curated dirs + generic aliases (sans-serif→Noto Sans, serif→Noto Serif, monospace→Noto Sans Mono, emoji→Noto Color Emoji) — *font_guard*
- [x] Disabled fontconfig ⇒ `/usr/share/fonts` NOT masked (current behavior preserved) — *runner* (verified)

### 3.2 Minimal /etc view
- [x] Generic `/etc/hostname` (= `ext.hostname`/`sandbox`), `/etc/hosts` (localhost + generic), `/etc/localtime` (RO bind of zoneinfo for resolved TZ/UTC) — *runner* (verified: host `/etc/hostname`/`hosts` never exposed; real host name hidden)
- [x] Audit records "Minimal /etc provided: …" active-policy note — *runner / audit*

### 3.3 JSON audit logs
- [x] `[audit].format = "text"|"json"` + `--audit-format <text|json>` override (CLI wins) — *profile / cli / runner*
- [x] `audit::format_audit_json(rec, exit_code)` — single valid JSON object per run, same info as text, NAMES only, egress upstreams hidden, JSON-escaped, redacted bwrap command; `AuditRecord.warnings` added — *audit / test_audit* (validated with a real JSON parser e2e)
- [x] `raincoat report` detects + summarizes JSON logs (last JSON object) as well as text — *report* (verified)

### 3.4 CLI grammar: global options before the subcommand
- [x] First bare `run|doctor|init|report` keyword before `--` selects the subcommand with preceding options applied; value-flag values are never keywords — *cli / test_cli*
- [x] Ambiguity honored: `-- init` RUNS `init` as a command (not the subcommand); `run -- cmd`, `init --force` unchanged — *cli* (verified: `-- init` actually exec'd the init binary)

**PHASE 3 (privacy hardening): COMPLETE ✅ — 28 suites / 800+ tests green, -Wall -Wextra clean**
