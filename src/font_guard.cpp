// Raincoat — font_guard: best-effort fontconfig isolation.
#include "font_guard.hpp"

#include <filesystem>
#include <fstream>
#include <sstream>

namespace raincoat {

namespace fs = std::filesystem;

namespace {

// Minimal embedded fontconfig document used when no usable source is provided.
const char* kFallbackFontsConf =
    "<?xml version=\"1.0\"?>\n"
    "<!DOCTYPE fontconfig SYSTEM \"fonts.dtd\">\n"
    "<fontconfig>\n"
    "  <!-- Raincoat minimal fallback: hide the host's full font list. -->\n"
    "  <dir>/usr/share/fonts</dir>\n"
    "  <cachedir>/tmp/fontconfig-cache</cachedir>\n"
    "  <config></config>\n"
    "</fontconfig>\n";

// Try to read the entire source file. Returns true and fills `out` only if the
// file exists, is a regular file, and could actually be opened for reading.
bool try_read_source(const std::string& source, std::string& out) {
    if (source.empty()) return false;
    std::error_code ec;
    if (!fs::is_regular_file(source, ec) || ec) return false;
    std::ifstream in(source, std::ios::binary);
    if (!in.is_open() || !in.good()) return false;
    std::ostringstream ss;
    ss << in.rdbuf();
    if (in.bad()) return false;
    out = ss.str();
    return true;
}

bool write_all(const std::string& path, const std::string& content) {
    std::ofstream out(path, std::ios::binary | std::ios::trunc);
    if (!out.is_open()) return false;
    out << content;
    out.flush();
    return static_cast<bool>(out);
}

}  // namespace

FontSetup setup_fontconfig(const std::string& sandbox_dir, bool enabled,
                           const std::string& fonts_conf_source, std::string& err) {
    FontSetup result;

    if (!enabled) {
        result.status = FontStatus::Disabled;
        result.note = "fontconfig isolation disabled";
        err.clear();  // no-op path: leave the caller's err buffer clean
        return result;
    }

    err.clear();

    // Refuse to operate on an empty or relative sandbox_dir. Composing a relative
    // "fontconfig/" here would silently create files in the process CWD, which is
    // never what the caller intends. Require an absolute path.
    if (sandbox_dir.empty() || !fs::path(sandbox_dir).is_absolute()) {
        result.status = FontStatus::Unavailable;
        result.note = "sandbox_dir must be an absolute path";
        err = "Error: fontconfig sandbox_dir must be an absolute path: " + sandbox_dir;
        return result;
    }

    const std::string dir = (fs::path(sandbox_dir) / "fontconfig").string();
    const std::string conf = (fs::path(dir) / "fonts.conf").string();

    // Create the fontconfig directory. If the parent is a file (or otherwise not
    // writable) this fails and we cannot proceed.
    std::error_code ec;
    fs::create_directories(dir, ec);
    if (!fs::is_directory(dir, ec)) {
        result.status = FontStatus::Unavailable;
        result.note = "could not create fontconfig directory";
        err = "Error: could not create fontconfig directory: " + dir;
        return result;
    }

    result.dir = dir;

    // Decide the fonts.conf contents: prefer copying the provided source verbatim.
    std::string source_contents;
    const bool source_requested = !fonts_conf_source.empty();
    const bool have_source = try_read_source(fonts_conf_source, source_contents);

    bool wrote = false;
    if (have_source) {
        wrote = write_all(conf, source_contents);
        if (wrote) {
            result.status = FontStatus::Enabled;
            result.note = "fontconfig configured from source " + fonts_conf_source;
        }
    }

    if (!wrote) {
        // Fallback: write the minimal embedded document. A source that was requested
        // but could not be copied (missing / unreadable / write failed) is reported as
        // a copy failure; the absence of any source is reported as "no usable source".
        if (write_all(conf, kFallbackFontsConf)) {
            result.status = FontStatus::BestEffort;
            result.note = source_requested
                              ? "source copy failed; wrote minimal fallback fonts.conf"
                              : "no usable source; wrote minimal fallback fonts.conf";
        } else {
            // Directory exists but we cannot write the config file at all.
            result.status = FontStatus::Unavailable;
            result.note = "could not write fonts.conf";
            result.dir.clear();
            err = "Error: could not write fonts.conf: " + conf;
            return result;
        }
    }

    result.env["FONTCONFIG_PATH"] = dir;
    result.env["FONTCONFIG_FILE"] = conf;
    // Pin XDG_DATA_DIRS to a minimal, known-good value (SPEC "Fonts / fontconfig").
    // The host's XDG_DATA_DIRS is scrubbed from the child env, and fontconfig (plus
    // other toolkits) consults these dirs for font/data lookups. We point only at the
    // system data dirs under the read-only /usr bind, so the child never inherits the
    // host's (potentially fingerprinting) data-dir list.
    result.env["XDG_DATA_DIRS"] = "/usr/local/share:/usr/share";
    return result;
}

}  // namespace raincoat
