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
- `EnvResolution resolve_env(const std::map<std::string,std::string>& parent,`
  `  const std::vector<std::string>& allow_env,`
  `  const std::vector<std::pair<std::string,std::string>>& set_env,`
  `  const std::map<std::string,std::string>& defaults, bool strict);`
  Semantics:
  1. Start empty.
  2. Base safe allowlist copied from parent if present: `PATH`, `TERM`. These go into `allowed`.
  3. `USER` is set to the generic value `"user"` (do NOT leak the real username) -> `set`.
  4. Apply `defaults` (TZ, LANG, LC_ALL, ...) as `set` values.
  5. For each `allow_env` name: if present in parent, copy value -> `allowed`.
  6. For each `set_env` KEY=VALUE: assign -> `set`. **`set_env` overrides `allow_env`** and defaults.
  7. `scrubbed` = every name present in `parent` that is NOT in `resolved` (sorted). Sensitive-pattern
     names that were not explicitly allowed MUST appear here.
  Note: HOME and TMPDIR are injected later by the runner (they depend on the sandbox dir), not here.

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
- `bool any_writable(const std::vector<Mount>& mounts);`  // used to warn in strict mode
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
  embedded fallback), and set env: `FONTCONFIG_PATH=<dir>`, `FONTCONFIG_FILE=<dir>/fonts.conf`.
  Status Enabled on full success, BestEffort if the file could be created but the source copy
  failed, Unavailable if the directory could not be created. Fill `note` for the audit log.

### bwrap  (deps: config, util) — PURE argv assembly, no side effects
- `std::vector<std::string> build_bwrap_argv(const std::string& bwrap_path, const Config& cfg,`
  `  const std::vector<Mount>& mounts, const EnvResolution& env,`
  `  const std::string& fake_home, const std::string& sandbox_tmp, bool bind_resolv_conf);`
  Emits (argv[0] = bwrap_path):
  - `--die-with-parent`
  - namespace isolation: `--unshare-pid --unshare-uts --unshare-ipc`
  - `--unshare-net` iff `cfg.net == NetMode::Off`
  - base system: `--ro-bind /usr /usr`, `--symlink usr/bin /bin`, `--symlink usr/lib /lib`,
    `--symlink usr/lib64 /lib64`, `--symlink usr/sbin /sbin`, `--proc /proc`, `--dev /dev`
  - `--ro-bind-try /etc/ssl /etc/ssl` and (iff bind_resolv_conf) `--ro-bind-try /etc/resolv.conf /etc/resolv.conf`
  - `--bind <fake_home> <fake_home>`, `--bind <sandbox_tmp> <sandbox_tmp>`
  - for each Mount: `--ro-bind`/`--bind <host> <sandbox>` per mode
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
  `  std::string timezone; std::string locale; std::string bwrap_command; };`
- `std::string format_audit_start(const AuditRecord& r);`  // the multi-line "Raincoat started" block
- `std::string format_audit_end(int exit_code);`
- `bool write_audit(const std::string& path, const std::string& content, std::string& err);` // append, mkdir -p parent
- MUST NOT print secret values — only NAMES from env.allowed/set/scrubbed.
- `AuditRecord.bwrap_command` is an **already-redacted, display-safe string** produced upstream by
  `bwrap::redact_argv_for_audit(argv, cfg.command.size())`. `format_audit_start` prints it
  VERBATIM — it does NOT re-parse or re-redact a flattened string (that approach is lossy and was
  removed). Audit is defense-in-depth only for env NAME lists.

### report  (deps: none beyond std)
- `std::string summarize_audit(const std::string& audit_text);`  // pure; playful-but-professional summary
  Should surface: HOME hidden, count of scrubbed env vars, network mode, strict/normal. Optional
  closing line: "Verdict: this tool did not get to see you naked."

### init  (deps: util)
- `std::string default_toml();`  // the example .raincoat.toml content; MUST be parseable by our own
  `toml::parse_toml` (round-trip validated in tests, not by a hand-rolled scanner)
- `bool write_init(const std::string& path, bool force, std::string& err);`  // refuse overwrite unless force
  The refusal message must only mention `--force` because the CLI actually supports it: `raincoat
  init [--force|-f]` sets `Options.init_force`, and `main` passes it through to `write_init`.

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
  - `--profile <path>` records the path into `options.profile_path`.

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
  default = `.raincoat/audit.log` under cwd (or temp dir when no project dir is writable).
- `int run(const Config& cfg, const std::map<std::string,std::string>& parent_env,`
  `  const std::string& cwd, const std::string& assets_dir, std::string& err);`
  Orchestrates: mkdtemp sandbox; create home/user, tmp, out; resolve_env (+ inject HOME, TMPDIR,
  generic USER); font setup (merge env); plan_mounts (validate; propagate the exact missing-path
  error); pick workdir; build_bwrap_argv; locate bwrap (missing -> the bubblewrap error text);
  write audit start; fork/exec bwrap; wait; write audit end; cleanup temp unless keep_temp;
  return the child's exit code (128+signal on signal death).

### main  (deps: cli, runner, doctor, init, report)
Parse argv -> dispatch. Prints help/version. Returns the child exit code for Run; 0/nonzero for
the management subcommands. Missing bwrap and other resolve/run errors print the module-provided
message to stderr and exit nonzero.

## Error message catalogue (must match spec)
- missing bwrap (multi-line, see SPEC.md "Missing bwrap")
- `Error: no command provided.\n\nUsage:\n  raincoat -- <command> [args...]`
- `Error: allowed path does not exist: <path>`
- `Error: expected --set-env KEY=VALUE`
