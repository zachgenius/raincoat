// Raincoat — shared type contract.
//
// This header is the single source of truth for the data model that every module
// agrees on. It is intentionally header-only (POD-ish structs, enums, and tiny inline
// helpers) so that any translation unit — including standalone unit tests — can include
// it with zero link dependencies.
//
// DO NOT put logic with side effects here. Keep it declarative.
#pragma once

#include <map>
#include <optional>
#include <string>
#include <utility>
#include <vector>

namespace raincoat {

// ---------------------------------------------------------------------------
// Enums
// ---------------------------------------------------------------------------

// Network isolation modes. The MVP implements Full and Off. Allowlist and Ask are
// reserved so the surrounding code (parsing, audit, bwrap assembly) can be extended
// without breaking the enum's ABI or switch statements.
enum class NetMode { Full, Off, Allowlist, Ask };

// Top-level subcommand selected on the command line.
enum class Subcommand { Run, Doctor, Init, Report, Help, Version };

// How a host path is exposed inside the sandbox.
enum class MountMode { ReadOnly, ReadWrite };

// Outcome of the best-effort fontconfig isolation.
//   Disabled    -> user turned it off (or it was never requested)
//   Enabled     -> a minimal fontconfig view was written successfully
//   BestEffort  -> partially configured; some steps were skipped
//   Unavailable -> requested but could not be set up at all
enum class FontStatus { Disabled, Enabled, BestEffort, Unavailable };

// ---------------------------------------------------------------------------
// Enum <-> string helpers (inline, no link deps)
// ---------------------------------------------------------------------------

inline const char* to_string(NetMode m) {
    switch (m) {
        case NetMode::Full:      return "full";
        case NetMode::Off:       return "off";
        case NetMode::Allowlist: return "allowlist";
        case NetMode::Ask:       return "ask";
    }
    return "full";
}

inline std::optional<NetMode> net_mode_from_string(const std::string& s) {
    if (s == "full")      return NetMode::Full;
    if (s == "off")       return NetMode::Off;
    if (s == "allowlist") return NetMode::Allowlist;
    if (s == "ask")       return NetMode::Ask;
    return std::nullopt;
}

inline const char* to_string(FontStatus s) {
    switch (s) {
        case FontStatus::Disabled:    return "disabled";
        case FontStatus::Enabled:     return "enabled";
        case FontStatus::BestEffort:  return "best-effort";
        case FontStatus::Unavailable: return "unavailable";
    }
    return "disabled";
}

// ---------------------------------------------------------------------------
// Core data structures
// ---------------------------------------------------------------------------

// A single bind of a host path into the sandbox. In the MVP the sandbox path always
// equals the host path (identity mapping) so that tools that hardcode absolute paths
// keep working; the field is kept separate so a /workspace-style remap can be added
// later without changing call sites.
struct Mount {
    std::string host_path;     // absolute, canonical, and known to exist
    std::string sandbox_path;  // absolute path as seen inside the sandbox
    MountMode   mode = MountMode::ReadOnly;
};

// Result of resolving the child process environment. `resolved` is the exact env the
// child receives. The name lists are for the audit log — they carry NAMES ONLY, never
// values, so secrets are never persisted.
struct EnvResolution {
    std::map<std::string, std::string> resolved;   // final env handed to the child
    std::vector<std::string> allowed;   // copied verbatim from parent (base allowlist or --allow-env)
    std::vector<std::string> set;       // assigned via --set-env / env defaults (synthetic values)
    std::vector<std::string> scrubbed;  // present in parent but deliberately dropped
};

// Policy inputs for resolve_env that come from the rich sectioned profile
// (ExtendedConfig). Default-constructing this reproduces the MVP behavior exactly:
// no extra deny list, no extra scrub globs, and the generic username "user". So a
// flat/absent profile is unaffected.
//   deny            -> ext.env_deny: names that must NEVER be copied from the parent,
//                      even when explicitly --allow-env'd (they land in `scrubbed`).
//                      An explicit `--set-env NAME=...` (a user-chosen synthetic value)
//                      still wins — deny blocks host values, not user-chosen ones.
//   scrub_patterns  -> ext.scrub_patterns: glob-ish patterns ("AWS_*", "*_TOKEN").
//                      When non-empty they EXTEND the built-in is_sensitive_env
//                      heuristic and, unlike that heuristic, are strong enough to
//                      override an explicit --allow-env (see env_guard.cpp).
//   username        -> ext.username: the generic value forced onto USER (and, by the
//                      runner, LOGNAME). Defaults to "user".
struct EnvPolicy {
    std::vector<std::string> deny;
    std::vector<std::string> scrub_patterns;
    std::string username = "user";
};

// Result of the fontconfig isolation step.
struct FontSetup {
    FontStatus status = FontStatus::Disabled;
    std::map<std::string, std::string> env;  // FONTCONFIG_PATH, FONTCONFIG_FILE, XDG_DATA_DIRS ...
    std::string dir;   // fontconfig directory created inside the sandbox (may be empty)
    std::string note;  // short human-readable note for the audit log
};

// Bubblewrap backend knobs (from the profile's [backend] section). Defaults match the
// hard-coded MVP behavior so code that ignores these is unaffected.
struct BackendConfig {
    std::string bwrap_path;             // empty => auto-locate via PATH
    bool unshare_user   = false;        // reserved: off by default (can break some tools)
    bool unshare_pid    = true;
    bool unshare_ipc    = true;
    bool unshare_uts    = true;
    bool unshare_cgroup = false;
    bool unshare_net_when_off = true;   // honor NetMode::Off with --unshare-net
    bool mount_proc     = true;
    bool mount_dev      = true;
    bool mount_tmpfs_tmp = true;
    bool die_with_parent = true;
    bool seccomp        = false;        // reserved (not implemented)
};

// One egress bridge: the child sees only `child_endpoint`; Raincoat privately forwards to
// `upstream_endpoint` (kept host-side, never shown to the child). From [[egress.bridge]].
struct EgressBridge {
    std::string name;
    std::string env;                // env var injected into the child (e.g. SOME_BASE_URL)
    std::string child_endpoint;     // e.g. http://127.0.0.1:18080  (what the child connects to)
    std::string upstream_endpoint;  // e.g. https://real-upstream.example.com (host-side only)
    bool hide_upstream = true;
    bool preserve_host = false;     // false => send upstream's Host; true => keep child's Host
    bool preserve_path = true;
    bool preserve_query = true;
    bool preserve_method = true;
    std::vector<std::string> strip_headers;                        // dropped before forwarding
    std::vector<std::pair<std::string, std::string>> inject_headers;  // added to upstream request
};

// The [egress] section. `enabled` is true when mode == "bridge" and at least one bridge is set.
struct EgressConfig {
    bool enabled = false;
    std::string mode;               // disabled | proxy | bridge | guarded
    bool hide_upstreams_from_child = true;
    bool redact_upstreams_in_audit = true;
    bool log_request_bodies = false;
    bool log_response_bodies = false;
    int  timeout_seconds = 120;
    bool streaming = true;
    std::vector<EgressBridge> bridges;
};

// The rich, forward-compatible profile options that go BEYOND the flat MVP schema. These are
// populated by the profile layer from the sectioned config (docs/full-config-reference.toml)
// and carried through merge into Config. Every field defaults to the existing MVP behavior so
// that a flat/absent profile is unchanged. Unknown sections/keys are tolerated (never fatal);
// sections that are configured but not yet enforced are recorded in `reserved_notes` for the
// audit log.
struct ExtendedConfig {
    std::optional<std::string> profile_name;   // informational (audit)
    std::optional<std::string> username;       // [identity].username -> generic USER/LOGNAME value
    std::optional<std::string> hostname;       // [identity].hostname -> generic hostname
    std::optional<std::string> home;           // [identity].home -> reserved (path remap is future/advisory)
    std::vector<std::string> env_deny;         // [environment].deny — never allow these
    std::vector<std::string> scrub_patterns;   // [environment].scrub_patterns — empty => built-in defaults
    std::vector<std::string> fs_deny;          // [filesystem].deny — never mount (enforced + audited)
    std::optional<bool> fs_deny_by_default;    // [filesystem].mode == "deny-by-default"
    std::vector<std::string> tripwire_files;   // [filesystem.tripwire].fake_sensitive_files
    bool tripwire_enabled = false;
    BackendConfig backend;
    std::vector<std::string> init_create_dirs; // [init].create_dirs
    std::optional<bool> playful_report;        // [report].playful_summary
    std::optional<std::string> report_log;     // [report].latest_log
    EgressConfig egress;                       // [egress] + [[egress.bridge]] (phase 2)
    // A RESERVED restrictive network mode ("proxy"/"bridge"/"guarded") was requested but
    // is not yet enforced. Carries the requested mode name so resolve_config can fail
    // CLOSED (fall back to NetMode::Off, never Full) and the runner can warn on stderr.
    // Absent for "full"/"off"/flat profiles, so their behavior is unchanged.
    std::optional<std::string> reserved_net_mode;
    // Names of sections/modes that were configured but are NOT yet enforced (browser, dns,
    // network_policy, egress bridge, guarded/bridge/proxy network modes...). Surfaced in audit
    // so behavior is honest.
    std::vector<std::string> reserved_notes;
};

// Raw options parsed from the CLI and/or a profile, BEFORE merge + defaults are applied.
// The `*_set` booleans record whether a flag was given explicitly, which the profile
// merge needs in order to let CLI flags win over profile values without a tri-state.
struct Options {
    bool strict = false;
    bool strict_set = false;

    std::optional<NetMode> net;   // explicit --net / profile network

    std::vector<std::string> allow_read;
    std::vector<std::string> allow_write;
    std::vector<std::string> allow_env;
    std::vector<std::pair<std::string, std::string>> set_env;   // KEY -> VALUE

    std::optional<std::string> workdir;
    std::optional<std::string> audit_log;
    std::optional<std::string> profile_path;

    bool keep_temp = false;
    bool keep_temp_set = false;

    // `raincoat init --force`: overwrite an existing .raincoat.toml. Only meaningful for the
    // Init subcommand; ignored elsewhere.
    bool init_force = false;

    // Locale/timezone and any other synthetic env defaults (TZ, LANG, LC_ALL, plus the
    // profile's [env] table). These are applied as `set` values in the child env.
    std::map<std::string, std::string> env_defaults;

    std::optional<bool> fontconfig_enabled;

    // Rich sectioned-config options (identity/environment/filesystem/backend/init/report...).
    ExtendedConfig ext;

    std::vector<std::string> command;  // target argv (everything after `--`)
};

// A parsed top-level invocation. If `error` is non-empty it is a ready-to-print,
// user-facing message and no further processing should happen.
struct CliInvocation {
    Subcommand sub = Subcommand::Run;
    Options    options;
    std::string error;
    bool has_error() const { return !error.empty(); }
};

// Fully-resolved configuration after merging profile + CLI and applying defaults.
// This is what the runner executes against. Paths in allow_read/allow_write are still
// the user-provided strings (possibly relative); fs_guard canonicalizes + validates
// them so that the "path does not exist" error can quote the original spelling.
struct Config {
    bool    strict = false;
    NetMode net    = NetMode::Full;

    std::vector<std::string> allow_read;
    std::vector<std::string> allow_write;
    std::vector<std::string> allow_env;
    std::vector<std::pair<std::string, std::string>> set_env;

    std::map<std::string, std::string> env_defaults;  // TZ, LANG, LC_ALL, ...

    bool fontconfig_enabled = true;

    std::string workdir;          // absolute directory to chdir into inside the sandbox
    std::string audit_log_path;   // resolved path for the audit log
    bool        keep_temp = false;

    // Rich sectioned-config options (identity/environment/filesystem/backend/init/report...),
    // resolved from the profile. Defaults leave MVP behavior unchanged.
    ExtendedConfig ext;

    std::vector<std::string> command;  // target argv
};

}  // namespace raincoat
