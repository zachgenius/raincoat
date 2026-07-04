// Raincoat — browser: best-effort browser fingerprint/profile isolation.
#include "browser.hpp"

#include <cctype>
#include <filesystem>
#include <fstream>
#include <sstream>
#include <vector>

namespace raincoat {

namespace fs = std::filesystem;

namespace {

// Single-quote a value for safe embedding in a POSIX shell script. Wraps in '...'
// and escapes any embedded single quote as '\'' so the generated shim can never be
// broken (or injected into) by an odd profile_dir/locale/viewport value.
std::string shq(const std::string& s) {
    std::string out = "'";
    for (char c : s) {
        if (c == '\'')
            out += "'\\''";
        else
            out += c;
    }
    out += "'";
    return out;
}

// Parse a "WxH" viewport (e.g. "1280x720") into the Chromium --window-size value
// "W,H". Returns empty when the spec is not two positive integer runs joined by 'x'.
std::string viewport_to_window_size(const std::string& viewport) {
    auto x = viewport.find('x');
    if (x == std::string::npos || x == 0 || x + 1 >= viewport.size()) return {};
    const std::string w = viewport.substr(0, x);
    const std::string h = viewport.substr(x + 1);
    auto all_digits = [](const std::string& v) {
        if (v.empty()) return false;
        for (char c : v)
            if (!std::isdigit(static_cast<unsigned char>(c))) return false;
        return true;
    };
    if (!all_digits(w) || !all_digits(h)) return {};
    return w + "," + h;
}

// Make a file executable (0755), best-effort.
void make_executable(const std::string& path) {
    std::error_code ec;
    fs::permissions(path,
                    fs::perms::owner_all | fs::perms::group_read | fs::perms::group_exec |
                        fs::perms::others_read | fs::perms::others_exec,
                    fs::perm_options::replace, ec);
}

// Write a single shim script: it resolves the REAL `self` executable from PATH while
// EXCLUDING `shim_dir` (recursion guard), falling back to the given absolute
// candidates, then execs it with `prepended` args in front of the caller's "$@".
// Returns true on success.
bool write_shim(const std::string& shim_dir, const std::string& self,
                const std::vector<std::string>& prepended,
                const std::vector<std::string>& fallbacks) {
    std::ostringstream ss;
    ss << "#!/bin/sh\n"
       << "# Raincoat browser isolation shim (generated). Best-effort: only affects a\n"
       << "# browser launched by this name via PATH; an absolute-path launch is not caught.\n"
       << "_rc_self=" << shq(self) << "\n"
       << "_rc_shim_dir=" << shq(shim_dir) << "\n"
       << "_rc_real=''\n"
       // Canonicalize OUR OWN shim dir with a POSIX shell builtin (cd + pwd -P) so we can
       // recognize — and skip — any equivalent spelling of ourselves on PATH (a trailing
       // slash, '.', '//', a symlink) that a plain string compare would miss. This uses NO
       // external tool (no readlink/realpath), so the own-dir guard stays effective even on
       // a minimal/hardened child PATH that lacks those binaries.
       << "_rc_shim_canon=$(cd \"$_rc_shim_dir\" 2>/dev/null && pwd -P)\n"
       // Re-entry sentinel: if a browser shim for THIS name already ran in this exec
       // chain, do NOT rescan PATH (an equivalent spelling could resolve back to us and
       // loop forever). Jump straight to the absolute fallbacks below.
       << "if [ \"$_RC_BROWSER_SHIM\" != \"$_rc_self\" ]; then\n"
       // Scan PATH, skipping our own shim dir (by exact string AND by canonical dir), so we
       // exec the REAL browser and never loop.
       << "  _rc_oldifs=\"$IFS\"\n"
       << "  IFS=':'\n"
       << "  for _d in $PATH; do\n"
       << "    [ -z \"$_d\" ] && _d='.'\n"
       << "    if [ \"$_d\" = \"$_rc_shim_dir\" ]; then continue; fi\n"
       // Canonicalize the candidate DIRECTORY the same builtin way and skip it if it is our
       // own shim dir under a different spelling (trailing slash, '.', '//', a symlink).
       << "    if [ -n \"$_rc_shim_canon\" ]; then\n"
       << "      _rc_dcanon=$(cd \"$_d\" 2>/dev/null && pwd -P)\n"
       << "      if [ \"$_rc_dcanon\" = \"$_rc_shim_canon\" ]; then continue; fi\n"
       << "    fi\n"
       << "    _rc_cand=\"$_d/$_rc_self\"\n"
       << "    [ -x \"$_rc_cand\" ] || continue\n"
       << "    _rc_real=\"$_rc_cand\"; break\n"
       << "  done\n"
       << "  IFS=\"$_rc_oldifs\"\n"
       << "fi\n"
       // Fall back to well-known absolute install paths.
       << "if [ -z \"$_rc_real\" ]; then\n"
       << "  for _c in";
    for (const auto& f : fallbacks) ss << " " << shq(f);
    ss << "; do\n"
       << "    if [ -x \"$_c\" ]; then _rc_real=\"$_c\"; break; fi\n"
       << "  done\n"
       << "fi\n"
       << "if [ -z \"$_rc_real\" ]; then\n"
       << "  echo \"raincoat: browser shim: could not find real $_rc_self on PATH\" >&2\n"
       << "  exit 127\n"
       << "fi\n"
       // Mark that a browser shim for this name has run so a re-exec of the same name
       // cannot rescan PATH and recurse back into us (defense-in-depth vs. the guards).
       << "_RC_BROWSER_SHIM=\"$_rc_self\"\n"
       << "export _RC_BROWSER_SHIM\n"
       // Isolation flags PREPENDED, then the caller's original arguments verbatim.
       << "exec \"$_rc_real\"";
    for (const auto& a : prepended) ss << " " << shq(a);
    ss << " \"$@\"\n";

    const std::string path = (fs::path(shim_dir) / self).string();
    std::ofstream out(path, std::ios::binary | std::ios::trunc);
    if (!out.is_open()) return false;
    out << ss.str();
    out.flush();
    if (!out) return false;
    make_executable(path);
    return true;
}

}  // namespace

BrowserSetup setup_browser(const BrowserConfig& cfg, const std::string& sandbox_root,
                           std::string& err) {
    err.clear();
    BrowserSetup result;

    if (!cfg.enabled) {
        result.note = "browser isolation disabled";
        return result;
    }

    // Require an absolute sandbox_root: composing a relative dir here would silently
    // create files under the process CWD, never the caller's intent.
    if (sandbox_root.empty() || !fs::path(sandbox_root).is_absolute()) {
        result.note = "sandbox_root must be an absolute path";
        err = "Error: browser sandbox_root must be an absolute path: " + sandbox_root;
        return result;
    }

    // Resolve + create the isolated profile dir ONLY when isolate_profile is set. When
    // the user disables isolation we honor that: no throwaway profile is created and no
    // --user-data-dir / firefox -profile is injected (other flags still apply).
    std::error_code ec;
    if (cfg.isolate_profile) {
        // Honor an explicit cfg.profile_dir; otherwise default to a throwaway dir under
        // the sandbox root (destroyed with it).
        result.profile_dir =
            !cfg.profile_dir.empty()
                ? cfg.profile_dir
                : (fs::path(sandbox_root) / "browser" / "profile").string();
        fs::create_directories(result.profile_dir, ec);
        if (!fs::is_directory(result.profile_dir, ec)) {
            result.note = "could not create browser profile dir";
            err = "Error: could not create browser profile dir: " + result.profile_dir;
            result.profile_dir.clear();
            return result;
        }
    }

    // Env to export. At least TZ from cfg.timezone (a generic browser tz) when set.
    if (!cfg.timezone.empty()) result.env["TZ"] = cfg.timezone;

    // Assemble the Chromium isolation flags, PREPENDED before the caller's args.
    std::vector<std::string> chromium_flags;
    if (cfg.isolate_profile)
        chromium_flags.push_back("--user-data-dir=" + result.profile_dir);
    if (!cfg.locale.empty()) chromium_flags.push_back("--lang=" + cfg.locale);
    // Surface a malformed non-empty viewport instead of silently dropping --window-size.
    bool bad_viewport = false;
    if (const std::string ws = viewport_to_window_size(cfg.viewport); !ws.empty())
        chromium_flags.push_back("--window-size=" + ws);
    else if (!cfg.viewport.empty())
        bad_viewport = true;
    if (cfg.disable_gpu) chromium_flags.push_back("--disable-gpu");
    if (cfg.disable_extensions) chromium_flags.push_back("--disable-extensions");
    if (cfg.disable_sync) chromium_flags.push_back("--disable-sync");

    bool wrote_shims = false;
    if (cfg.use_launch_shims) {
        const std::string shim_dir = (fs::path(sandbox_root) / "browser" / "shims").string();
        fs::create_directories(shim_dir, ec);
        if (fs::is_directory(shim_dir, ec)) {
            // Common Chromium/Chrome/Edge invocation names. Each shim execs the real
            // browser (resolved from PATH minus the shim dir) with chromium_flags first.
            const char* chromium_names[] = {"google-chrome", "google-chrome-stable",
                                            "chromium",       "chromium-browser",
                                            "chrome",         "msedge"};
            // Per-name known absolute install locations. Kept NAME-SPECIFIC so, e.g.,
            // the msedge shim never falls back to a chromium binary (which would exec
            // the wrong browser). The primary resolution is always PATH (minus the shim
            // dir); these are last-resort fallbacks only.
            auto extra_fallbacks = [](const std::string& name) -> std::vector<std::string> {
                if (name == "google-chrome" || name == "google-chrome-stable" ||
                    name == "chrome")
                    return {"/opt/google/chrome/google-chrome", "/opt/google/chrome/chrome"};
                if (name == "chromium" || name == "chromium-browser")
                    return {"/snap/bin/chromium"};
                if (name == "msedge")
                    return {"/opt/microsoft/msedge/msedge", "/usr/bin/microsoft-edge"};
                return {};
            };
            std::size_t ok = 0, total = 0;
            for (const char* name : chromium_names) {
                ++total;
                std::vector<std::string> fallbacks = {
                    std::string("/usr/bin/") + name,
                    std::string("/usr/local/bin/") + name,
                };
                for (auto& e : extra_fallbacks(name)) fallbacks.push_back(std::move(e));
                if (write_shim(shim_dir, name, chromium_flags, fallbacks)) ++ok;
            }
            // Firefox shim: best-effort `firefox -profile <profile_dir> "$@"`.
            {
                ++total;
                std::vector<std::string> ff_flags;
                if (cfg.isolate_profile) {
                    ff_flags.push_back("-profile");
                    ff_flags.push_back(result.profile_dir);
                }
                std::vector<std::string> ff_fallbacks = {"/usr/bin/firefox",
                                                         "/usr/local/bin/firefox",
                                                         "/snap/bin/firefox"};
                if (write_shim(shim_dir, "firefox", ff_flags, ff_fallbacks)) ++ok;
            }
            if (ok > 0) {
                result.shim_dir = shim_dir;
                wrote_shims = true;
            }
            (void)total;
        }
    }

    // Human-readable audit note (no secrets: paths are sandbox-local or user-configured).
    std::ostringstream note;
    if (cfg.isolate_profile)
        note << "profile " << result.profile_dir;
    else
        note << "profile isolation off";
    note << ", shims " << (wrote_shims ? "on" : "off") << ", gpu "
         << (cfg.disable_gpu ? "disabled" : "enabled") << "/extensions "
         << (cfg.disable_extensions ? "disabled" : "enabled") << "/sync "
         << (cfg.disable_sync ? "disabled" : "enabled");
    if (bad_viewport)
        note << " (ignored malformed viewport '" << cfg.viewport
             << "': expected WxH, e.g. 1280x720 — --window-size omitted)";
    result.note = note.str();
    return result;
}

}  // namespace raincoat
