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

// Result of the fontconfig isolation step.
struct FontSetup {
    FontStatus status = FontStatus::Disabled;
    std::map<std::string, std::string> env;  // FONTCONFIG_PATH, FONTCONFIG_FILE, XDG_DATA_DIRS ...
    std::string dir;   // fontconfig directory created inside the sandbox (may be empty)
    std::string note;  // short human-readable note for the audit log
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

    std::vector<std::string> command;  // target argv
};

}  // namespace raincoat
