// Raincoat — browser: best-effort browser fingerprint/profile isolation.
//
// The fake HOME already keeps the host's real Chrome/Firefox profiles out of the
// child's reach. This module ADDS a dedicated, throwaway browser profile directory
// plus (optionally) generic PATH "launch shims": tiny wrapper scripts, placed on the
// child's PATH ahead of the real browser, that start Chromium/Chrome (and Firefox)
// with low-information isolation flags — a private --user-data-dir, a pinned --lang /
// --window-size, and --disable-gpu/extensions/sync. Honest limitation: shims only
// affect a browser launched BY NAME via PATH; a script that hard-codes the browser's
// absolute path, or overrides these flags, is not constrained.
#pragma once

#include <map>
#include <string>

#include "config.hpp"

namespace raincoat {

// Result of the best-effort browser isolation step. Mirrors FontSetup's shape: the
// runner merges `env` into the child environment, PREPENDS `shim_dir` to the child's
// PATH (when non-empty), binds `profile_dir`/`shim_dir` into the sandbox, and records
// `note` in the audit. All strings are child-safe (paths under the sandbox root or the
// user's own configured values — never a secret).
struct BrowserSetup {
    std::map<std::string, std::string> env;  // e.g. TZ (from cfg.timezone) — never a secret
    std::string shim_dir;     // dir holding the generated launch shims (empty => none written)
    std::string profile_dir;  // isolated browser profile dir (created)
    std::string note;         // short human-readable audit note
};

// MOSTLY PURE (the only side effects are creating the profile/shim dirs and writing the
// shim scripts under `sandbox_root`). When cfg.enabled is false it returns an empty
// setup with a disabled note and touches nothing.
//
// When enabled it:
//   * resolves the isolated profile dir (cfg.profile_dir when set, else a default under
//     sandbox_root) and creates it;
//   * computes env to export (TZ from cfg.timezone when set);
//   * when cfg.use_launch_shims, WRITES executable shim scripts into a shim dir for the
//     common Chromium/Chrome names (google-chrome, google-chrome-stable, chromium,
//     chromium-browser, chrome, msedge) and a firefox shim. Each Chromium shim resolves
//     the REAL browser from PATH while EXCLUDING the shim dir (to avoid recursion; falls
//     back to known /usr/bin paths) and execs it with the isolation flags PREPENDED
//     before "$@". The firefox shim execs `firefox -profile <profile_dir> "$@"`.
//
// sandbox_root must be an absolute path. On a hard failure `err` is set (non-fatal for
// the caller: browser isolation is best-effort).
BrowserSetup setup_browser(const BrowserConfig& cfg, const std::string& sandbox_root,
                           std::string& err);

}  // namespace raincoat
