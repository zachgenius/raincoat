# Raincoat — Design Contract

This document is the **interface contract** for the codebase. Every module implements the
signatures below. `src/config.hpp` holds the shared types and is the source of truth for data
structures — do not redefine those types elsewhere. The full behavioural spec is in
`docs/SPEC.md` (mirrored from the scratchpad `SPEC.md`).

## Language / build conventions
- **C++17**, no exceptions required across module boundaries (return `bool` + `std::string& err`,
  or `std::optional<T>`; internal use of exceptions is fine but the public module API is
  error-code style).
- Headers in `src/<module>.hpp`, implementations in `src/<module>.cpp`.
- Every module is **loosely coupled**: it includes only `config.hpp`, `util.hpp`, and its own
  direct dependencies (listed below). This keeps each unit standalone-compilable for TDD.
- **Purity for testability**: functions that make decisions (parsing, scrubbing, planning mounts,
  building the bwrap argv, formatting audit text) must be *pure* — inject the environment / cwd /
  parent-env as parameters instead of reading globals. Side-effecting functions (create dirs,
  write files, exec) are thin and separate.

## Tests (GoogleTest)
- One test binary per module: `tests/test_<module>.cpp` with its own `main` provided by
  `-lgtest_main`.
- **Standalone compile recipe** (used during TDD; no shared build dir, so agents never collide):
  ```
  g++ -std=c++17 -Isrc <module>.cpp <deps...> tests/test_<module>.cpp \
      -lgtest -lgtest_main -lpthread -o /tmp/rc-test-<module> && /tmp/rc-test-<module>
  ```
  Per-module dep lists are given below. `config.hpp` is header-only (no .cpp).
- CMake also wires every test via `add_test` / `enable_testing()` so `ctest` runs the whole suite.
- Integration tests that actually invoke `bwrap` must **detect bwrap and skip gracefully**
  (GTEST_SKIP()) when it is missing, so the suite is green on hosts without bubblewrap.

## Module interfaces

### util  (deps: none) — `src/util.hpp` / `util.cpp`
Leaf helpers. No raincoat-specific types.
- `std::optional<std::string> canonicalize(const std::string& path);`  // realpath; nullopt if missing
- `std::string absolutize(const std::string& path, const std::string& base_cwd);` // lexical, no existence req
- `bool path_exists(const std::string& path);`
- `bool is_dir(const std::string& path);`
- `bool make_dirs(const std::string& path, std::string& err);`  // mkdir -p
- `std::map<std::string,std::string> environ_to_map(char** envp);`
- string helpers: `std::string to_upper(std::string s); bool starts_with(const std::string&, const std::string&);`
  `bool ends_with(const std::string&, const std::string&); std::vector<std::string> split(const std::string&, char);`
  `std::string trim(const std::string&);`

### env_guard  (deps: config, util) — matches the scrubbing spec
- `bool is_sensitive_env(const std::string& name);`
  Matches (case-sensitive on the documented forms): suffixes `_TOKEN`, `_SECRET`, `_KEY`;
  prefixes `AWS_`, `GITHUB_`, `GOOGLE_`, `OPENAI_`, `ANTHROPIC_`; exact `KUBECONFIG`,
  `SSH_AUTH_SOCK`, `DOCKER_HOST`, `NPM_TOKEN`, `PYPI_TOKEN`.
- `bool env_name_matches_glob(const std::string& name, const std::string& pattern);`
  Glob-ish match (`*` = any run incl. empty, `?` = exactly one char, else literal; case-sensitive).
- `bool is_scrubbed_name(const std::string& name, const std::vector<std::string>& patterns);`
  `is_sensitive_env(name)` OR (patterns non-empty AND `name` matches any) — this is how
  `ext.scrub_patterns` **EXTEND** the built-in defaults.
- `struct EnvPolicy { std::vector<std::string> deny; std::vector<std::string> scrub_patterns;`
  `  std::string username = "user"; };`  (config.hpp) — carries the `[identity]`/`[environment]`
  policy from `ExtendedConfig`. Default-constructed => original MVP behavior.
- `EnvResolution resolve_env(const std::map<std::string,std::string>& parent,`
  `  const std::vector<std::string>& allow_env,`
  `  const std::vector<std::pair<std::string,std::string>>& set_env,`
  `  const std::map<std::string,std::string>& defaults, bool strict,`
  `  const EnvPolicy& policy = {});`  — the trailing `policy` is optional and defaults to the
  MVP behavior, so the legacy 5-arg call sites/tests are unchanged.
  Semantics:
  1. Start empty.
  2. Base safe allowlist copied from parent if present: `PATH`, `TERM`. These go into `allowed`.
  3. `USER` is set to the generic value `policy.username` (default `"user"`; from `[identity].username`)
     -> `set`. The real username is never leaked.
  4. Apply `defaults` (TZ, LANG, LC_ALL, ...) as `set` values.
  5. For each `allow_env` name: if present in parent, copy value -> `allowed`. **EXCEPT** names that
     are `blocked_from_parent`: the identity-protected `USER`/`LOGNAME`/`HOSTNAME`, any name in
     `policy.deny` (`[environment].deny` — never allowed even if allow-env'd), or (when
     `policy.scrub_patterns` is non-empty) any name matching `is_scrubbed_name`. Blocked names are
     refused entry and fall through to `scrubbed`. NOTE: the built-in `is_sensitive_env` heuristic
     does NOT by itself block an explicit `--allow-env` (so a deliberate `--allow-env OPENAI_API_KEY`
     still works); only the user's own `deny`/`scrub_patterns` policy is strong enough to veto it.
  6. For each `set_env` KEY=VALUE: assign -> `set`. **`set_env` overrides `allow_env`**, defaults, AND
     the deny/scrub policy (a user-chosen synthetic value is not the host's secret).
     `--set-env USER=/LOGNAME=/HOSTNAME=` still wins.
  7. `scrubbed` = every name present in `parent` that is NOT in `resolved` (sorted). Sensitive-pattern
     and denied names that were not explicitly allowed MUST appear here.
  Note: HOME and TMPDIR are injected later by the runner (they depend on the sandbox dir), not here.
  The runner also injects generic `LOGNAME` (= `ext.username`, default "user") and `HOSTNAME`
  (= `ext.hostname`, default "sandbox") — unless the user chose an explicit `--set-env` value —
  mirroring the generic `USER`, so the three identity fingerprints stay anonymized end-to-end.

### fs_guard  (deps: config, util)
- `std::optional<Mount> make_mount(const std::string& user_path, const std::string& cwd,`
  `  MountMode mode, std::string& err);`  // absolutize->canonicalize->exist-check; err quotes user_path
  On missing path set `err = "Error: allowed path does not exist: " + user_path` and return nullopt.
- `std::vector<Mount> plan_mounts(const Config& cfg, const std::string& cwd,`
  `  const std::string& real_home, std::string& err);`
  Builds mounts for every allow_read (RO) and allow_write (RW). In **non-strict** mode, if the cwd
  is not already covered by an allow path, append the cwd as a **ReadWrite** mount — **EXCEPT** when
  the cwd equals (or is an ancestor of) `real_home`: auto-mounting `$HOME` would expose the very
  credentials Raincoat exists to hide (`~/.ssh`, `~/.aws`, ...). In that case do NOT auto-mount;
  instead set a warning (see below) so the runner can tell the user to pass `--allow-write` /
  `--allow-read` explicitly. In **strict** mode, never auto-add the cwd. On any missing path, set
  err and return empty. `real_home` empty => no home guard (used by pure tests that inject it).
  plan_mounts also reads `cfg.ext` directly (no signature change): a path resolving under any
  `ext.fs_deny` entry (`[filesystem].deny`, with a leading `~` expanded against `real_home`) is NEVER
  mounted — an `--allow-read`/`--allow-write` targeting it is refused with
  `"Error: refusing to mount denied path: <path> (matches filesystem deny rule '<rule>')"`, and a
  denied cwd is not auto-mounted (warning surfaced). `ext.fs_deny_by_default` (`[filesystem].mode =
  "deny-by-default"`) suppresses the non-strict cwd auto-mount entirely, exactly like strict mode.
- `std::optional<std::string> fs_deny_hit(const std::string& mount_host_path,`
  `  const std::vector<std::string>& fs_deny, const std::string& real_home);`
  Returns the ORIGINAL spelling of the first `fs_deny` entry that IS or is an ancestor of
  `mount_host_path` (`~` expanded against `real_home`), else nullopt. Used by plan_mounts.
- `bool any_writable(const std::vector<Mount>& mounts);`  // used to warn in strict mode
- `std::string audit_mask_dir(const std::string& audit_log_path, const std::vector<Mount>& mounts);`
  Returns the audit log's PARENT dir in sandbox space whenever the untrusted child could otherwise
  write it, so the runner can `--tmpfs`-mask it and keep the child away from the host audit log.
  **Guiding invariant (attack rounds 1 & 2): the mask may shadow a dir ONLY when doing so loses no
  user data — i.e. the audit dir is raincoat's own `.raincoat`** (raincoat creates/owns it, so an
  empty overlay hides nothing the user placed there and discards no legitimate child output). The
  "raincoat-owned" test is keyed on the dir's basename being `.raincoat` (the default audit dir is
  `<cwd>/.raincoat`). So masking applies to a raincoat-owned `.raincoat` that is child-writable, whether
  reached as a **proper descendant** of a read-write mount (normally the auto-mounted cwd) or exposed
  as its own **lone** read-write mount root (e.g. `--strict --allow-write <cwd>/.raincoat`).
  Returns `""` when no masking is needed/wanted: the audit dir is not inside any writable mount; only a
  read-only mount covers it; the audit dir is **NOT** raincoat-owned (a custom `--audit-log` pointed
  into a user data dir the user `--allow-write`'d, e.g.
  `--strict --allow-write <dir> --audit-log <dir>/run.log`) — masking it would hide the user's real
  files and discard the child's legitimate writes, so we drop tamper-protection for that one custom log
  rather than ever destroy user data; or the user redundantly exposed the exact `.raincoat` as its own
  read-write mount root **while a broader writable mount (the cwd) also covers it** — that deliberate
  mount overrides the default mask so the child sees the dir's real contents.
- The cwd==home refusal should be surfaced to the user; expose it via a `std::string& warning`
  out-param on plan_mounts OR a companion `bool cwd_is_home(cwd, real_home)` predicate the runner
  checks — implementer's choice, but the warning MUST reach the user and the audit log.

### net_guard  (deps: config)
- `std::vector<std::string> net_flags(NetMode m);`  // Off -> {"--unshare-net"}; Full -> {}
- `bool binds_resolv_conf(NetMode m);`              // true only for Full

### font_guard  (deps: config, util)
- `FontSetup setup_fontconfig(const std::string& sandbox_dir, bool enabled,`
  `  const std::string& fonts_conf_source, std::string& err);`
  If `!enabled`: return {status=Disabled}. Else create `<sandbox_dir>/fontconfig/`, write
  `fonts.conf` (copy `fonts_conf_source` if it exists and is readable, otherwise write a minimal
  embedded fallback), and set env: `FONTCONFIG_PATH=<dir>`, `FONTCONFIG_FILE=<dir>/fonts.conf`,
  and a minimal `XDG_DATA_DIRS=/usr/local/share:/usr/share` (system dirs under the read-only `/usr`
  bind, so the child never inherits the host's data-dir list). Status Enabled on full success,
  BestEffort if the file could be created but the source copy failed, Unavailable if the directory
  could not be created. Fill `note` for the audit log. The runner binds `<dir>` read-only into the
  sandbox (see bwrap) so `FONTCONFIG_FILE` actually resolves inside the namespace.

### bwrap  (deps: config, util) — PURE argv assembly, no side effects
- `std::vector<std::string> build_bwrap_argv(const std::string& bwrap_path, const Config& cfg,`
  `  const std::vector<Mount>& mounts, const EnvResolution& env,`
  `  const std::string& fake_home, const std::string& sandbox_tmp, bool bind_resolv_conf,`
  `  const std::string& font_dir = "", const std::string& audit_mask_dir = "",`
  `  const std::string& sandbox_out = "");`
  Emits (argv[0] = bwrap_path). Every namespace/mount flag below is gated on the matching
  `cfg.ext.backend` toggle (`BackendConfig`); the defaults reproduce the MVP argv exactly, so an
  absent profile is unchanged:
  - `--die-with-parent` (iff `backend.die_with_parent`, default true)
  - `--unshare-user` (iff `backend.unshare_user`, default **false**), `--unshare-pid`
    (`backend.unshare_pid`), `--unshare-uts` (`backend.unshare_uts`), `--unshare-ipc`
    (`backend.unshare_ipc`), `--unshare-cgroup` (iff `backend.unshare_cgroup`, default **false**)
  - `--hostname <cfg.ext.hostname>` (default `sandbox`) emitted **only when `--unshare-uts`** is
    (it requires the fresh UTS namespace so the real machine name never leaks)
  - `--unshare-net` iff `cfg.net == NetMode::Off` **and** `backend.unshare_net_when_off` (default true)
  - base system: `--ro-bind /usr /usr`, the four `--symlink`s, `--proc /proc` (iff
    `backend.mount_proc`), `--dev /dev` (iff `backend.mount_dev`)
  - `--ro-bind-try /etc/ssl /etc/ssl` and (iff bind_resolv_conf) `--ro-bind-try /etc/resolv.conf /etc/resolv.conf`
  - `--bind <fake_home> <fake_home>`, `--bind <sandbox_tmp> <sandbox_tmp>` (the temp scratch bind is
    gated on `backend.mount_tmpfs_tmp`, default true), and (iff `sandbox_out` non-empty)
    `--bind <sandbox_out> <sandbox_out>` — the writable scratch `out` dir (SPEC `<temp>/out`)
  - (iff `font_dir` non-empty) `--ro-bind <font_dir> <font_dir>` so `FONTCONFIG_FILE/PATH` resolve
  - for each Mount: `--ro-bind`/`--bind <host> <sandbox>` per mode
  - (iff `audit_mask_dir` non-empty) `--tmpfs <audit_mask_dir>` — emitted AFTER the user mounts so the
    parent (writable cwd) mount already exists; shadows the audit-log dir so the untrusted child
    cannot read/forge/erase the host audit log. The runner computes this via `fs_guard::audit_mask_dir`.
  - `--clearenv` then a `--setenv <K> <V>` pair for **every** entry in `env.resolved`
    (iterate deterministically — std::map is ordered — so tests are stable)
  - `--chdir <cfg.workdir>`
  - then the target command tokens `cfg.command...`
  The function never touches the filesystem; the runner is responsible for creating the dirs it
  references.
- `std::string redact_argv_for_audit(const std::vector<std::string>& argv, size_t num_command_tokens);`
  PURE. Produces a display-safe, human-readable rendering of the bwrap argv for the audit log:
  it redacts **every `--setenv <NAME> <VALUE>`** value to `<redacted>` so secret env VALUES are
  never written to disk (NAMES are shown). Redaction is STRUCTURAL at the vector layer — it
  scans only the bwrap-options region `argv[0 .. size-num_command_tokens)` (so a literal
  `--setenv` inside the sandboxed command is never touched), and on `--setenv` consumes exactly
  the next two tokens (NAME, VALUE). Over-redaction is acceptable (safe direction); under-redaction
  is not. Tokens that are empty or contain spaces are single-quoted for readability. The target
  command tokens are appended verbatim. This is the ONLY correct place to redact — a flattened
  string cannot be re-parsed unambiguously.

### audit  (deps: config) — `AuditRecord` lives in audit.hpp
- `struct AuditRecord { std::string command_line; bool strict; NetMode net; std::string fake_home;`
  `  std::string workdir; std::vector<Mount> mounts; EnvResolution env; FontStatus font;`
  `  std::string timezone; std::string locale; std::string bwrap_command;`
  `  std::optional<std::string> profile_name; std::vector<std::string> active_policy_notes;`
  `  std::vector<std::string> reserved_notes; };`
  The last three carry rich sectioned-config transparency (NAMES/counts only, never secrets) and are
  printed only when non-empty: `profile_name` -> a `Profile:` line; `active_policy_notes` -> an
  `Active policy:` section (which extended policies — env_deny/fs_deny/scrub_patterns/backend
  overrides/tripwire — are ACTIVE this run); `reserved_notes` -> a
  `Reserved (configured, not enforced):` section (sections parsed but not yet enforced).
- `std::string format_audit_start(const AuditRecord& r);`  // the multi-line "Raincoat started" block
- `std::string format_audit_end(int exit_code);`
- `bool write_audit(const std::string& path, const std::string& content, std::string& err);` // append, mkdir -p parent
- MUST NOT print secret values — only NAMES from env.allowed/set/scrubbed.
- `AuditRecord.bwrap_command` is an **already-redacted, display-safe string** produced upstream by
  `bwrap::redact_argv_for_audit(argv, cfg.command.size())`. `format_audit_start` prints it
  VERBATIM — it does NOT re-parse or re-redact a flattened string (that approach is lossy and was
  removed). Audit is defense-in-depth only for env NAME lists.

### report  (deps: none beyond std)
- `std::string summarize_audit(const std::string& audit_text, bool playful = true);`  // pure
  Should surface: HOME hidden, count of scrubbed env vars, network mode, strict/normal. `playful`
  (default true, honoring `[report].playful_summary`) selects the playful narrative (optional closing
  "Verdict: this tool did not get to see you naked.") vs. a plain factual "Raincoat run summary:"
  bullet list. `main` picks the audit path from an explicit positional, else `[report].latest_log`
  (`ext.report_log`), else the default under cwd; `raincoat report [path] [--profile <p>]`.

### init  (deps: util)
- `std::string default_toml();`  // the example .raincoat.toml content; MUST be parseable by our own
  `toml::parse_toml` (round-trip validated in tests, not by a hand-rolled scanner)
- `bool write_init(const std::string& path, bool force, std::string& err);`  // refuse overwrite unless force
  The refusal message must only mention `--force` because the CLI actually supports it: `raincoat
  init [--force|-f]` sets `Options.init_force`, and `main` passes it through to `write_init`.
- `bool create_init_dirs(const std::vector<std::string>& dirs, const std::string& base_cwd,`
  `  std::string& err);`  // mkdir -p each dir (relative -> base_cwd); existing dirs are fine.
  `raincoat init --profile <p>` loads the profile and, after writing `.raincoat.toml`, creates the
  profile's `[init].create_dirs` (`ext.init_create_dirs`).

### doctor  (deps: util)
- `struct DoctorReport { bool bwrap_found=false; std::string bwrap_path; std::string bwrap_version;`
  `  bool userns_ok=false; bool smoke_ok=false; std::vector<std::string> notes;`
  `  bool usable() const { return bwrap_found && smoke_ok; } };`
- `std::optional<std::string> find_bwrap();`  // search PATH for an executable bwrap
- `DoctorReport run_doctor();`
- `std::string format_doctor(const DoctorReport& r);`  // pass/fail lines + install hints if missing

### cli  (deps: config)
- `CliInvocation parse_cli(const std::vector<std::string>& args);`  // args EXCLUDE argv[0]
  - `run|doctor|init|report` as first token selects the subcommand; otherwise default to Run.
  - `--help`/`-h` -> Help; `--version`/`-V` -> Version (only when they appear before `--`).
  - Everything after the first `--` is the target command (verbatim; not parsed).
  - Parses all run options into `Options`. Repeatable flags accumulate.
  - Errors (set `error` to the exact text, then return):
    - malformed set-env (no `=`): `"Error: expected --set-env KEY=VALUE"`
    - unknown `--net` value: a clear message naming valid values (full|off)
    - Run subcommand with an empty command: `"Error: no command provided.\n\nUsage:\n  raincoat -- <command> [args...]"`
  - `--profile <path>` records the path into `options.profile_path`. The `init` and `report`
    subcommands also accept `--profile <path>` (init -> `[init].create_dirs`; report ->
    `[report].latest_log`/`playful_summary`); `report [path]` takes an optional positional audit path
    (stored in `options.command`).

### Config schema mapping (phase 1.5 — rich sectioned profile)
The profile layer accepts BOTH the flat MVP schema AND the rich sectioned schema shown in
`docs/full-config-reference.toml` (a directional demo — field names may change; tolerate unknown
keys/sections, never fatal). Nested sections take precedence over flat top-level keys; the flat
schema still loads (backward compatible). These options are not merely carried — the runner now
WIRES `Config.ext` into the live sandbox (identity/env policy in resolve_env, backend toggles +
hostname in bwrap, fs_deny in plan_mounts, tripwire + bwrap_path + audit notes in run()). Mapping
into `Options`/`Config`+`Config.ext` (`ExtendedConfig`, see config.hpp):
- top-level: `profile_name`→ext.profile_name; `strict`; `network` off|full→NetMode, and
  proxy|bridge|guarded→record an `ext.reserved_notes` entry + fall back to the safe net default
  (Off if strict else Full); `keep_temp`; `workdir`.
- `[identity]`: `username`→ext.username (generic USER/LOGNAME value), `hostname`→ext.hostname
  (drives `--hostname` + HOSTNAME env), `home`→ext.home (reserved/advisory), `timezone`→env TZ,
  `locale`→env LANG+LC_ALL, `language`→env LANGUAGE.
- `[environment]`: `allow`→allow_env, `deny`→ext.env_deny (never allowed, even via allow_env),
  `scrub_patterns`→ext.scrub_patterns (empty ⇒ built-in defaults), `[environment.set]`→set_env,
  `clear` (always true; warn if false).
- `[filesystem]`: `allow_read`/`allow_write`, `deny`→ext.fs_deny (never mounted; audited),
  `mode`="deny-by-default"→ext.fs_deny_by_default (strict-like no-auto-cwd), `create_standard_dirs`,
  `fake_home` (always true), `[filesystem.tripwire]`→ext.tripwire_*.
- `[fontconfig]`: `enabled`→fontconfig_enabled; mode/paths/hide_host_fonts/fontset advisory.
- `[audit]`: `log_file`→audit_log; redact/format/log_* mostly advisory (redaction always on).
- `[backend]`: →ext.backend (bwrap_path, unshare_*, mount_*, die_with_parent; seccomp reserved).
- `[init]`: `create_dirs`→ext.init_create_dirs. `[report]`: `latest_log`→ext.report_log,
  `playful_summary`→ext.playful_report. `[proxy]`: if enabled, inject http/https/all/no_proxy → set_env.
- RESERVED (parse + `ext.reserved_notes` + audit line "configured, not yet enforced", NOT
  enforced): `[browser]`, `[dns]`, `[network_policy]`, `[egress]`/`[[egress.bridge]]` (phase 2),
  network modes bridge/guarded/proxy-as-mode, `[backend].seccomp`.
The `toml` module must support `[[array-of-tables]]` and nested `[a.b.c]` tables for this.

### profile  (deps: toml, config)
- `std::optional<Options> load_profile(const std::string& path, std::string& err);`
  **MUST parse via the `toml` module** (`toml::parse_toml` + the typed getters) — do NOT hand-roll a
  second TOML parser. This is what makes multiline arrays and dotted keys work.
  Maps: `strict`(bool), `network`(string->NetMode), `allow_read/allow_write/allow_env`(string arrays),
  `[env]` table -> `env_defaults`, `[fontconfig].enabled`(bool)->fontconfig_enabled,
  `[audit].log_file`(string)->audit_log. `set_env` is CLI-only (not read from profile).
  **Reject wrong-typed values** rather than silently ignoring them (a silently-dropped `strict` or
  `network` is a privacy downgrade): if `strict`/`network`/`fontconfig.enabled` is present but the
  wrong type, return an error. Only accept `network` = full|off (reject allowlist/ask in the MVP).
  To distinguish "absent" from "present-but-wrong-type", the `toml` module may expose a small
  `contains(dotted_key)` / type-introspection helper (add it to the toml module if needed).
- `Options merge(const Options& profile, const Options& cli);`  // CLI overrides profile
  - lists (allow_read/write/env, set_env) are unioned (profile entries first, then cli; de-duplicated)
  - scalar/optional (strict, net, workdir, audit_log, keep_temp, fontconfig_enabled) take the CLI value
    when set (`*_set` or the optional has a value), otherwise the profile value
  - `env_defaults` = profile's table overlaid by cli's (cli keys win)

### toml  (deps: none) — minimal parser sized to the config schema
- `class TomlTable` (or a small value variant) exposing typed getters used by profile:
  `std::optional<bool> get_bool(const std::string& dotted_key) const;`
  `std::optional<std::string> get_string(const std::string& dotted_key) const;`
  `std::optional<std::vector<std::string>> get_string_array(const std::string& dotted_key) const;`
  `std::map<std::string,std::string> get_table_of_strings(const std::string& table) const;`
- `std::optional<TomlTable> parse_toml(const std::string& text, std::string& err);`
  Must handle: `# comments`, `key = value`, booleans, `"double"`/`'single'` quoted strings,
  inline `["a", "b"]` and multiline arrays, and `[table]` / dotted `[a.b]` headers. It does NOT
  need to be a full TOML implementation — only what the config schema uses — but must reject
  malformed input with a helpful `err` instead of crashing.

### runner  (deps: everything)
- `Config resolve_config(const CliInvocation& inv, const std::map<std::string,std::string>& parent_env,`
  `  const std::string& cwd, std::string& err);`
  Loads the profile (if `profile_path` set), merges (CLI wins), then applies defaults:
  net default = `Off` if strict else `Full`; env_defaults gains TZ=UTC, LANG/LC_ALL=en_US.UTF-8
  when not already present; fontconfig default true; workdir default = cwd (non-strict) or a
  sentinel resolved to the fake home at run time (strict, when cwd is not mounted); audit_log
  default = `.raincoat/audit.log` under cwd (best-effort: skipped with a non-fatal note when that
  directory is not writable — the MVP has no temp-dir fallback).
- `int run(const Config& cfg, const std::map<std::string,std::string>& parent_env,`
  `  const std::string& cwd, const std::string& assets_dir, std::string& err);`
  Orchestrates: mkdtemp sandbox; create home/user, tmp, out (out is bound writable into the sandbox);
  resolve_env (passing an `EnvPolicy` built from `cfg.ext` — env_deny/scrub_patterns/username; +
  inject HOME, TMPDIR, generic USER, and generic LOGNAME/HOSTNAME from `ext.username`/`ext.hostname`
  unless `--set-env` chose them); font setup (merge env, incl. XDG_DATA_DIRS); plant `ext.tripwire_files`
  as inert bait UNDER the fake home when `ext.tripwire_enabled` (a leading `~/` maps to the fake-home
  root; writes can never escape it; the real home is never touched); plan_mounts (validate; enforce
  `ext.fs_deny`/`ext.fs_deny_by_default`; propagate the exact missing-path/denied-path error); pick
  workdir; compute `audit_mask_dir`; build_bwrap_argv (font dir bound RO, out dir bound RW, audit dir
  tmpfs-masked; hostname + backend toggles read from `cfg.ext`); locate bwrap — an executable
  `ext.backend.bwrap_path` (must contain a `/` and be X_OK) overrides auto-find, else `find_bwrap`
  (missing -> the bubblewrap error text); populate the AuditRecord's profile_name/active_policy_notes/
  reserved_notes; write audit start; fork/exec bwrap; wait; write audit end; cleanup temp unless keep_temp.
  A SIGINT/SIGTERM/SIGHUP handler forwards the signal to the bwrap child so `waitpid` returns and the
  normal `cleanup_root()` still removes the temp tree (no leak on interruption). Returns the child's
  exit code (128+signal on signal death).

### main  (deps: cli, runner, doctor, init, report)
Parse argv -> dispatch. Prints help/version. Returns the child exit code for Run; 0/nonzero for
the management subcommands. Missing bwrap and other resolve/run errors print the module-provided
message to stderr and exit nonzero.

## Error message catalogue (must match spec)
- missing bwrap (multi-line, see SPEC.md "Missing bwrap")
- `Error: no command provided.\n\nUsage:\n  raincoat -- <command> [args...]`
- `Error: allowed path does not exist: <path>`
- `Error: expected --set-env KEY=VALUE`
