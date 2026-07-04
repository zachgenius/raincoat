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

// Audit-log output format. Text is the default human-friendly block format; Json
// emits a single structured JSON object per run (same information, never secrets).
enum class AuditFormat { Text, Json };

// Egress network-namespace isolation policy ([egress].isolate_netns).
//   Auto -> use the isolated pasta netns jail WHEN pasta is available on the host,
//           otherwise fall back to the shared-loopback model (with a warning). Default.
//   On   -> prefer the jail; if pasta is absent, fall back to shared-loopback (warn).
//   Off  -> always use the shared-loopback model, even when pasta is present.
enum class NetnsIsolation { Auto, On, Off };

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

inline const char* to_string(AuditFormat f) {
    switch (f) {
        case AuditFormat::Text: return "text";
        case AuditFormat::Json: return "json";
    }
    return "text";
}

inline std::optional<AuditFormat> audit_format_from_string(const std::string& s) {
    if (s == "text") return AuditFormat::Text;
    if (s == "json") return AuditFormat::Json;
    return std::nullopt;
}

inline const char* to_string(NetnsIsolation i) {
    switch (i) {
        case NetnsIsolation::Auto: return "auto";
        case NetnsIsolation::On:   return "on";
        case NetnsIsolation::Off:  return "off";
    }
    return "auto";
}

// Parse the [egress].isolate_netns knob. Accepts the canonical "auto"/"on"/"off"
// plus common synonyms so a profile can spell the intent naturally. Unknown values
// return nullopt (the caller keeps the default rather than aborting the profile).
inline std::optional<NetnsIsolation> netns_isolation_from_string(const std::string& s) {
    if (s == "auto") return NetnsIsolation::Auto;
    if (s == "on" || s == "true" || s == "yes" || s == "jail" || s == "isolate" ||
        s == "isolated")
        return NetnsIsolation::On;
    if (s == "off" || s == "false" || s == "no" || s == "shared" || s == "share")
        return NetnsIsolation::Off;
    return std::nullopt;
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
    // Curated host font directories that exist on this host and should be the ONLY
    // font dirs exposed inside the sandbox (Noto Sans/Serif/Sans Mono/Color Emoji +
    // DejaVu Sans). The runner masks /usr/share/fonts with a tmpfs and re-binds ONLY
    // these read-only, so the child enumerates a generic set instead of the host's
    // full font list. Empty when fontconfig is disabled or none of the curated dirs
    // exist on the host (in which case the runner leaves /usr/share/fonts unmasked).
    std::vector<std::string> font_dirs;
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
    // Per-bridge audit redaction override. When true (default) this bridge's upstream is
    // recorded as "hidden" in the audit even if the global egress.redact_upstreams_in_audit
    // is disabled. Effective redaction = egress.redact_upstreams_in_audit || hide_upstream ||
    // (audit child-readable). To surface exactly one upstream in the audit, disable the
    // global flag AND set that single bridge's hide_upstream=false.
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
    // Network-namespace isolation policy. Auto (default) runs the child inside an
    // isolated pasta netns (a private tap + NAT) when pasta is present, so the
    // host-side bridge's upstream socket lives in the host netns and is invisible to
    // the child's /proc/net/tcp (the shared-loopback /proc-net leak is fixed). When
    // pasta is absent (or Off), the child shares the host loopback (the MVP model).
    NetnsIsolation isolate_netns = NetnsIsolation::Auto;
    std::vector<EgressBridge> bridges;
};

// True when a bridge's real upstream MUST be recorded as "hidden" in the audit rather than
// disclosed. Redaction is forced ON when ANY of:
//   * the global egress.redact_upstreams_in_audit is set (default true), OR
//   * this bridge's own hide_upstream is set (default true), OR
//   * the audit log is child-readable (fail-closed — an un-redacted upstream sitting in a
//     child-readable audit is a leak regardless of the flags).
// So to surface exactly one upstream a user must disable the global flag AND set that single
// bridge's hide_upstream=false AND keep the audit out of the child's reach; every other
// bridge stays hidden by its own default-true hide_upstream.
inline bool audit_hides_upstream(const EgressConfig& egress, const EgressBridge& bridge,
                                 bool audit_child_readable) {
    return egress.redact_upstreams_in_audit || bridge.hide_upstream || audit_child_readable;
}

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
    AuditFormat audit_format = AuditFormat::Text;  // [audit].format ("text"|"json")
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

    // Audit-log format override (CLI --audit-format / profile [audit].format). Optional
    // so the profile merge can let a CLI value win over the profile value; unset falls
    // back to the default (text) in resolve_config.
    std::optional<AuditFormat> audit_format;

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

    // The --profile file this config was loaded from (if any). Carried through so the
    // runner can detect and mask a profile that lands inside a mounted path — the
    // profile contains egress upstream_endpoint values that must never reach the child.
    std::optional<std::string> profile_path;

    std::vector<std::string> command;  // target argv
};

}  // namespace raincoat
