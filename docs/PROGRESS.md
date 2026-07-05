# Raincoat — Implementation Progress Tracker

Living checklist for both phases. Status keys: `[x]` done & verified · `[~]` in progress ·
`[ ]` pending · `[-]` intentionally deferred (documented non-goal / later).
Updated as work lands; committed with the code so progress is traceable in git.

Legend for "Where": module source + test file that owns the behavior.

---

## Phase 1 — Core MVP privacy sandbox

### 1.1 Build & project scaffolding
- [x] C++17 project, CMake build, `-Wall -Wextra` clean — *CMakeLists.txt*
- [x] GoogleTest wiring; every module test registered with `ctest` (currently **47 suites / ~950 test cases**, all green; the per-phase counts in the gate lines below are point-in-time snapshots showing growth, not the live total) — *CMakeLists.txt*
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
- [x] Example profiles documented as project-local templates (all parse-validated) — *examples/{strict,paranoid,ai-agent,node-build,python-tool,egress,api-agent,guarded,browser}.toml*

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
- [x] `guarded` mode + domain allow/block policy (`[network_policy]`) — LANDED in Phase 4 below (guarded proxy `src/proxy.*`)
- [-] DNS policy · [-] transparent egress · [-] explicit MITM (off by default)

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

---

## Phase 4 — Network policy / guarded proxy  (see docs/EGRESS.md § Network policy / guarded proxy)

Generic, profile-driven domain allow/block policy over the child's general HTTP(S) egress,
enforced by a host-side filtering forward proxy (`src/proxy.*`). Distinct from the egress bridge
(which redirects one known upstream). Composes with the strict pasta netns jail: with the jail
the allow/block list is a REAL domain-level egress firewall; WITHOUT it, only proxy-aware clients
are constrained (honest, disclosed every run). No provider/service names hard-coded.

### 4.1 Profile schema & parsing  (config, profile)
- [x] `[network_policy]` → `NetworkPolicy` (`enabled`, `default_action`, `allow_hosts`, `block_hosts`, `block_private_metadata_endpoints`, `metadata_endpoints`) — *config.hpp / profile*
- [x] Typo'd `default_action` REJECTED (not silently defaulted — no privacy downgrade) — *profile / test_profile*

### 4.2 Pure policy engine  (proxy::host_allowed — no sockets, unit-tested)
- [x] `block_hosts` wins (exact + dot-suffix match); blocked host never allowed regardless of default_action — *proxy / test_proxy*
- [x] Metadata blocking: 169.254.169.254, [fd00:ec2::254], metadata.google.internal, bare "metadata", link-local 169.254.0.0/16, numeric forms, + `metadata_endpoints` — *proxy / test_proxy*
- [x] `default_action` = deny (allow-list) / allow (block-list); empty/unparseable host FAILS CLOSED — *proxy / test_proxy*

### 4.3 Runnable filtering forward proxy  (ProxyServer)
- [x] Loopback listener (ephemeral port), thread-per-conn, reaped/torn down on stop — *proxy / test_proxy_composition_teardown*
- [x] Plain HTTP: parse absolute-form request line, apply policy, forward + stream response, 403 on block — *proxy / test_proxy_integration*
- [x] HTTPS via CONNECT: policy-check host, 200 + blind-tunnel if allowed (NO MITM), 403 if blocked — *proxy / test_proxy_integration*
- [x] Post-resolution SSRF / DNS-rebinding guard: recheck EVERY getaddrinfo result before dialing; 403 if a resolved addr is a block/metadata IP — *proxy / test_proxy_attack_round1/2*

### 4.4 Runner wiring  (runner)
- [x] Start guarded proxy on host loopback BEFORE sandbox when `[network_policy].enabled`; publish bound port — *runner / test_proxy_integration*
- [x] Inject `http_proxy`/`https_proxy`/`all_proxy` (lower + UPPER); ERASE any inherited proxy vars; leave `no_proxy` ABSENT so nothing is dialed around it; guarded proxy OVERRIDES external `[proxy]`/`--set-env` — *runner / test_proxy_attack_round3_env_case*
- [x] Conflict with `--net off` refused (guarded proxy needs loopback reachability) — *runner / test_runner*
- [x] Compose with strict netns jail: pasta forwards ONLY the proxy port (`-o 127.0.0.1`), proxy is child's only egress — *runner / test_proxy_composition_teardown* (verified e2e: child ran, firewall note printed)

### 4.5 Audit + honest disclosure
- [x] Audit records network-policy enabled, default action, guarded-proxy endpoint, allow/block COUNTS (never host names), metadata-blocked flag; external-proxy-overridden note — *audit / runner* (text + JSON)
- [x] stderr + audit disclose firewall-vs-proxy-only-clients per mode (strict jail = real firewall; auto/on NAT + shared = proxy-aware clients only) — *runner / test_network_policy_regression_honesty*

### 4.6 Limitations documented (honest)
- [x] Real domain-level egress firewall ONLY with `isolate_netns = "strict"` (pasta); else only proxy-aware clients constrained — *EGRESS.md / README* (disclosed every run)
- [x] No TLS interception (CONNECT blind-tunnel); NAME-vs-IP asymmetry for name block-lists — *EGRESS.md / proxy.hpp*
- [-] Transparent interception of non-proxy-aware clients WITHOUT the jail (a raw-IP / proxy-ignoring client bypasses the policy) — not possible without the strict jail; remains a documented non-goal
- [-] DNS policy (`[dns]`) — parsed/reserved, not enforced
- [-] General CIDR-based egress firewall (the guarded proxy is name-based, not CIDR) — future

### 4.7 Verification gate (Phase 4)
- [x] Unit + integration + attack-regression suites (proxy engine, HTTP/CONNECT forward, SSRF/rebinding guard, env-injection hardening, composition teardown, honesty regressions) — *tests/test_proxy*, *test_proxy_attack_round1/2/3*, *test_proxy_integration*, *test_proxy_composition_teardown*, *test_network_policy_regression_honesty*
- [x] Real demo: `examples/guarded.toml` (network_policy + strict jail) — child ran, stderr firewall note printed; `--net off` conflict refused — verified against `./build/raincoat`
- [x] README (Network policy section + roadmap) + docs/EGRESS.md (§ Network policy / guarded proxy) + `examples/guarded.toml`

**PHASE 4 (network policy / guarded proxy): COMPLETE ✅ — 41 suites green, -Wall -Wextra clean**

---

## Phase 5 — Browser isolation  (best-effort; see README "Browser isolation")

Generic, profile-driven browser fingerprint/profile isolation for headless-browser jobs
(Playwright / Puppeteer / Selenium). The fake HOME already keeps the host's real Chrome/Firefox
profiles out of the child's reach; this ADDS an isolated throwaway profile dir + optional generic
PATH launch shims. Best-effort by construction: the shims only affect a browser launched BY NAME
via PATH — an absolute-path launch or a flag override bypasses them. NOT deep anti-fingerprinting
(canvas/WebGL/audio/font-metrics/JA3 untouched); that stays an honest `[-]` below.

### 5.1 Profile schema & parsing  (config, profile)
- [x] `[browser]` → `BrowserConfig` (`enabled`, `isolate_profile`, `profile_dir`, `timezone`, `locale`, `viewport`, `disable_gpu/extensions/sync`, `use_launch_shims`) — *config.hpp / profile / test_profile*
- [x] Disabled (`enabled=false`) recorded as an honest reserved/"configured but not enabled" note — *profile*

### 5.2 Isolation mechanism  (browser)
- [x] Throwaway profile dir created inside the sandbox root (or explicit `profile_dir`), destroyed with it; skipped when `isolate_profile=false` — *browser / test_browser*
- [x] Generic launch shims for Chromium/Chrome/Edge names + firefox: exec the REAL browser (resolved from PATH minus the shim dir, with absolute fallbacks) with isolation flags PREPENDED before `"$@"` — *browser / test_browser*
- [x] Shell-safe shim generation (single-quote escaping) + recursion guards (own-dir canonicalization via `cd`+`pwd -P`, re-entry sentinel `_RC_BROWSER_SHIM`) — *browser / test_browser_attack_round1/2*
- [x] Malformed non-empty `viewport` surfaced in the audit note (not silently dropped); `--window-size` omitted — *browser*

### 5.3 Runner wiring  (runner)
- [x] Injects browser env (TZ), PREPENDS the shim dir to the child's PATH, binds profile dir RW + shim dir RO into the sandbox — *runner / test_browser_path_e2e_regression*
- [x] Disabled path touches nothing; no regression to non-browser runs — *runner / test_browser_disabled_regression*
- [x] Audit note records profile dir, whether shims were written, gpu/extensions/sync state, and the best-effort caveat — *runner / audit*

### 5.4 Honest limitations documented
- [x] Shims are best-effort — only a by-name PATH launch is caught; absolute-path launches / flag overrides bypass them — *README / browser.hpp / examples/browser.toml*
- [x] Real protection is the already-absent host profiles; the isolated profile + flags reduce casual leakage and normalize a few knobs only — *README*
- [-] **Deep anti-fingerprinting** (canvas/WebGL/audio/font-metrics/TLS-JA3 normalization) — explicit non-goal for this layer; would require an instrumented/patched browser build, not a launch shim
- [-] Intercepting absolute-path or flag-overriding launches (would need argv rewriting / `execve` interception) — out of scope

### 5.5 Verification gate (Phase 5)
- [x] Unit + attack-regression + e2e suites (mechanism via a fake browser stub on PATH that prints its argv; disabled-path + PATH-composition regressions) — *tests/test_browser*, *test_browser_attack_round1/2*, *test_browser_attack_round2_regression*, *test_browser_disabled_regression*, *test_browser_path_e2e_regression*
- [x] README "Browser isolation" section + roadmap tick + `examples/browser.toml` (browser + strict egress allow-list for a Playwright/Puppeteer job)
- [x] No regression: 47 suites green, -Wall -Wextra clean

**PHASE 5 (browser isolation, best-effort): COMPLETE ✅**

---

## Phase 6 — macOS (Seatbelt, best-effort)  (see docs/MACOS.md)

A reduced-guarantee macOS port behind the platform seam (`src/backend.hpp`). One backend TU is
linked per platform (compile-time, no virtuals): `bwrap.cpp`+`backend_linux.cpp` on Linux,
`seatbelt.cpp`+`backend_macos.cpp` on macOS. The runner talks only to the three free functions +
three POD structs and GATES every platform step on the backend's `Capabilities`, so a guarantee
Seatbelt cannot deliver is SKIPPED, never dishonestly audited. **The core inversion:** bwrap
CONSTRUCTS a namespace (fail-closed, structural); Seatbelt FILTERS the real filesystem (fail-open,
deny-based). So structural `[x]` guarantees become best-effort `[~]`, and a per-run fail-closed
pre-flight probe restores a measured fail-closed check. A **DYLD identity/fingerprint interposer**
(via an in-process `sandbox_init` pivot) additionally fakes the hostname/username/CPU/kernel/RAM/
machine-id/boot-id/uptime leaks Seatbelt can only allow/deny, never rewrite — best-effort, injectable
(non-hardened) targets only. A parity audit against the Linux requirements then closed several gaps
where macOS was silently dropping or fail-open on a guarantee (RO mounts writable, audit dir forgeable,
host `/tmp` visible, four fingerprint knobs ignored) and added honest disclosures where a mechanism is
Linux-only. Measured on macOS 26.5.1 (Apple Silicon).

### 6.1 Backend seam  (backend.hpp / backend_macos.cpp / backend_linux.cpp)
- [x] `Capabilities` / `LaunchInputs` / `LaunchPlan` PODs; `backend_capabilities` / `backend_locate` / `backend_build_launch` free functions; compile-time platform selection, no runtime dispatch — *backend.hpp / CMakeLists*
- [x] Linux backend delegates to the unchanged `build_bwrap_argv` + reproduces the pasta wrap; no MVP regression — *backend_linux.cpp / test_backend_golden_argv*
- [x] macOS `Capabilities`: `fs_hiding=Filter`, `net_off=PolicyDeny`, `env_apply=ViaExec`, `net_firewall_kernel=true`, **`supports_dyld_interpose=true`**; `supports_{fontconfig,uts_hostname,minimal_etc,curated_fonts,netns_jail}=false` — *backend_macos.cpp*
- [x] `backend_locate` returns `/usr/bin/sandbox-exec` (actionable error if absent/not X_OK) — *backend_macos.cpp*

### 6.2 SBPL generator  (seatbelt.cpp — pure, no filesystem access)
- [x] `build_seatbelt_profile` is pure string assembly over fully-realpath'd `LaunchInputs` (peer of `build_bwrap_argv`) — *seatbelt.cpp / test_seatbelt*
- [x] Filter model: `(allow default)` then SUBTRACT real home + `/Users`, RE-ALLOW sandbox dirs/workdir/mounts, RE-DENY fs-deny + audit dir + self-profile LAST (last-match-wins) — *seatbelt.cpp / test_seatbelt*
- [x] `sbpl_str` escapes `\`/`"`; a smuggled newline/NUL is unrepresentable → fail CLOSED (`""` + err) — *seatbelt.cpp / test_seatbelt*
- [x] Every path realpath'd caller-side (`backend_macos.cpp`) — a raw `/tmp` rule silently fails open; canonical `/private/tmp` works (MEASURED); one spelling covers the Data-volume firmlink twin (no doubling) — *backend_macos.cpp*
- [x] Darwin per-user cache dir (`_CS_DARWIN_USER_CACHE_DIR`) folded into the deny set (not under `$HOME`) — *backend_macos.cpp*

### 6.3 What WORKS (verified)
- [x] Env scrub / generic identity: `USER`/`LOGNAME`/`HOME`/`TZ`/`LANG` faked, applied at `execve` (SBPL has no env directives) — *runner / backend_macos* (verified)
- [x] Fake `$HOME` hides real home: `~/.ssh`, `~/.gitconfig` → *Operation not permitted*; `file-read*` blocks `stat()` too — *seatbelt* (MEASURED)
- [x] Username-enumeration deny: `(deny file-read* (subpath "/Users"))` → `ls /Users` EPERM (deny-home ALONE leaked it) — *seatbelt* (MEASURED)
- [x] **`--allow-read` is TRULY read-only** (parity fix): RO mounts emit `(allow file-read*)` + `(deny file-write*)`, the write-deny AFTER every RW allow, so an `--allow-read` subdir of the auto-mounted RW cwd stays read-only (under `(allow default)` a bare read-allow leaves it WRITABLE — unlike Linux `--ro-bind`=EROFS) — *seatbelt / test_seatbelt `ReadOnlyMountDeniesWrite`* (MEASURED: write → EPERM)
- [x] **Private `/tmp` (`mount_tmpfs_tmp`, default on)** (parity fix): host `/private/tmp` + the Darwin per-user TEMP dir (`_CS_DARWIN_USER_TEMP_DIR`) EARLY-denied (a new `fs_deny_early` tier emitted BEFORE the re-allows), so the child's own `$TMPDIR` scratch nested under the Darwin TEMP dir survives while sibling/host temp files stay hidden — *seatbelt / backend_macos / test_seatbelt `EarlyDenyPrecedesSandboxReAllows`* (MEASURED: host /tmp hidden, scratch usable)
- [x] **Audit-log tamper protection** (parity fix): on the Filter backend the audit-log PARENT dir is ALWAYS denied by realpath (not only when a RW mount covers it), so the child gets EPERM trying to forge/erase the log while raincoat (unsandboxed parent) still writes it — *runner (Filter branch) / seatbelt* (MEASURED: child forge → EPERM)
- [x] `--net off` → `(deny network*)` blocks outbound to a public IP — *seatbelt* (MEASURED)
- [x] **Kernel egress firewall** (`isolate_netns = "strict"` + egress/proxy): `(deny network*)` + `(allow network-outbound (remote ip "localhost:<port>"))` — constrains ALL clients (not just proxy-aware), NO pasta, port-precise, `localhost` covers `::1`; needs no pasta and does NOT fail closed on macOS — a STRENGTH over Linux — *seatbelt / runner* (MEASURED)
- [x] **Fail-closed pre-flight probe** (every run): spawns a probe under the IDENTICAL profile that tries to read real `$HOME` (+ connect to a public IP when net-restricted); REFUSES the run if either succeeds — restores fail-closed for a Filter backend — *runner* (verified: a permissive profile aborts the run)
- [x] **In-process `sandbox_init` pivot**: the child applies the SBPL via `sandbox_init(profile,0)` and `execvp`s the target ITSELF (not through the SIP-protected `/usr/bin/sandbox-exec`), because SIP STRIPS `DYLD_INSERT_LIBRARIES` when exec'ing a protected binary (MEASURED: injection through sandbox-exec left `gethostname` real). Sandbox stays enforced AND the injection survives (both MEASURED); `sandbox_init` is public-but-deprecated (same status as sandbox-exec) — *runner.cpp / backend_macos* (`apply_sbpl`, `env_apply=ViaExec`)
- [x] **DYLD identity/fingerprint interposer** (`supports_dyld_interpose=true`): a `__DATA,__interpose` dylib (`src/rc_interpose.c`, built next to the binary as `rc_interpose.dylib`) fakes `gethostname`, `uname` (nodename/release/version), `getlogin`/`getlogin_r`, `getpwuid`/`getpwnam` (pw_name+pw_dir), `sysctlbyname` (kern.hostname / machdep.cpu.brand_string / kern.osrelease / kern.osversion / hw.memsize) — closing the identity leaks Seatbelt can only allow/deny, never rewrite — *rc_interpose.c / backend_macos* (MEASURED)
- [x] **Value-driven, same config as Linux**: identity hostname/username always faked; `kernel_osrelease`/`kernel_version`→`uname.release`/`.version`, `cpu_model_name`→CPU brand, `mem_total_kb`→`hw.memsize` only when SET (unset → real). VERIFIED: set → release=6.1.0-generic, cpu="Generic CPU", memsize=16 GiB; unset → real value — *backend_macos / rc_interpose*
- [x] **Interposer identity sourced from the child's RESOLVED env** (parity fix): `RC_FAKE_HOSTNAME`/`_USER`/`_HOME` are taken from the child's actual `$HOSTNAME`/`$USER`/`$HOME`, so `getpwuid`/`getlogin`/`gethostname` can never disagree with the env the child also reads (a mismatch is itself a tell) — *backend_macos*
- [x] **Four more fingerprint knobs wired to the interposer** (parity fix — were SILENTLY IGNORED): `machine_id`→`kern.uuid`+`gethostuuid(2)`, `boot_id`→`kern.bootsessionuuid`, `uptime_seconds`→`kern.boottime` (derived so `now−boottime==uptime`), `cpu_vendor_id`→`machdep.cpu.vendor` (**Intel Macs only** — no such sysctl on Apple Silicon → no-op). `kernel_cmdline` has **no macOS analog** (no `/proc/cmdline`) and is now DISCLOSED as ignored, not silently dropped — *rc_interpose / runner / docs/FINGERPRINT-SYSCALLS.md* (MEASURED: machine_id/uptime faked)
- [x] SBPL re-allows READING the dylib (it may sit under a denied path, e.g. a dev build under `$HOME`) — *backend_macos / seatbelt*

### 6.4 Best-effort on macOS (deny-based, honest `[~]`)
- [~] best-effort (macOS): real-`$HOME` hiding is DENY-based (present-but-denied), not structural absence — mitigated (not fixed) by the pre-flight probe — *seatbelt / runner*
- [~] best-effort (macOS): audit-dir tamper protection is a deny rule over the real audit dir, not a tmpfs mask — *seatbelt*
- [~] best-effort (macOS): hostname/`uname` masking is via the DYLD interposer (`gethostname`/`uname().nodename`), not a UTS ns — INJECTABLE targets only; hardened/SIP/static callers still leak (`supports_uts_hostname=false`, `supports_dyld_interpose=true`) — *rc_interpose / backend_macos*
- [~] best-effort (macOS): CPU/kernel/RAM fingerprint (`sysctlbyname`/`uname`) + username (`getpwuid`/`getlogin`) faked via the interposer — libc-caller-only, NO seccomp-notify backstop, strictly weaker than Linux Tier-2 — *rc_interpose / docs/FINGERPRINT-SYSCALLS.md*
- [~] best-effort (macOS): `die_with_parent` is DOWNGRADED — SIGINT/SIGTERM/SIGHUP are forwarded to the child, but on a raincoat SIGKILL/crash the child is ORPHANED (reparented to launchd); macOS has no `PR_SET_PDEATHSIG` equivalent, so there is no PID-death kill — *runner / docs/MACOS.md* (disclosed in the "backend overrides" audit note)

### 6.5 N/A on macOS (honest `[-]` — gated off, never dishonestly audited)
- [-] N/A on macOS: structural (fail-closed) filesystem invisibility — Seatbelt is a Filter, so it is deny-based/fail-open (`fs_hiding=Filter`)
- [-] N/A on macOS: structural UTS hostname masking — no UTS ns (`supports_uts_hostname=false`); `gethostname()`/`uname()` are instead faked best-effort by the DYLD interposer (see §6.4), NOT structurally
- [-] N/A on macOS: minimal `/etc` view — cannot bind a fake `/etc` (`supports_minimal_etc=false`)
- [-] N/A on macOS: curated-font / fontconfig masking — Core Text, not fontconfig; cannot overlay `/usr/share/fonts` (`supports_curated_fonts`/`supports_fontconfig_isolation=false`)
- [-] N/A on macOS: pasta netns jail + `/proc/net/tcp` leak-fix — no `/proc`, no netns; kernel firewall replaces it (`supports_netns_jail=false`)
- [-] N/A on macOS: namespace toggles `unshare_user/pid/ipc/uts/cgroup` + `mount_dev` — Linux-mechanism (namespaces / minimal `/dev`); Seatbelt has none. The "backend overrides" audit note DISCLOSES they are NOT enforced here (no PID/IPC/user/cgroup isolation, no minimal `/dev`) — *runner / docs/MACOS.md*
- [-] N/A on macOS: `[filesystem].mode = "deny-by-default"` is NOT a structural whitelist (parity disclosure) — it only WITHHOLDS the cwd auto-mount; the rest of the host FS stays `(allow default)`-reachable minus `[filesystem].deny` + the real home. The audit discloses this ("NOT the structural whitelist the Linux backend gives; add explicit denies") — *runner / docs/MACOS.md*
- [-] N/A on macOS: true `(deny default)` strict — a bare deny-default can't even load libSystem (MEASURED, exit 71); macOS `strict` = allow-default + no cwd auto-grant (it WITHHOLDS the cwd auto-mount; the deny set is otherwise IDENTICAL to non-strict — corrected: it never emitted "expanded denies")

### 6.6 Disclosed residual bypasses (present, not hidden — see docs/MACOS.md)
- [x] `getpwuid()->pw_name`/`pw_dir` + `getlogin()` (opendirectoryd, not a file read) — now FAKED by the DYLD interposer for injectable targets (closes the previously-documented un-closable leak); a hardened/SIP/static target still recovers the real name (honest residual) — *rc_interpose / docs/MACOS.md*
- [x] Hardlinks on the shared APFS volume can reference a denied inode by a different path — *docs/MACOS.md*
- [x] Exposure depends on the host's TCC state (Full Disk Access on the parent terminal changes reachable surface) — *docs/MACOS.md*

### 6.7 Verification gate (Phase 6)
- [x] `tests/test_seatbelt.cpp` SBPL golden/assembly suite (compiled only on macOS; Linux `bwrap` suites pruned on macOS) — *CMakeLists*
- [x] Real runs verified on macOS 26.5.1: real `~/.ssh`/`~/.gitconfig` denied, `ls /Users` EPERM, fake identity via env, `--net off` blocks outbound, kernel egress firewall constrains raw clients, pre-flight probe aborts a permissive profile, DYLD interposer fakes `gethostname`/`uname`/`getpwuid`/`sysctl` for a non-system binary (and returns real values when unset)
- [x] Parity fixes verified on macOS 26.5.1: RO mount write BLOCKED (EPERM), host `/tmp` hidden while child scratch survives, audit-log forge attempt → EPERM, `machine_id`/`uptime`/`cpu_vendor` faked, all honesty disclosures present (deny-by-default, backend-override/die-with-parent, `kernel_cmdline` ignored); 43/43 ctest + Linux golden argv 4/4 still green
- [x] docs/MACOS.md (honest design + threat model) + this Phase 6 tracker; README "Platform status" updated to best-effort macOS

**PHASE 6 (macOS Seatbelt, best-effort): COMPLETE ✅**
