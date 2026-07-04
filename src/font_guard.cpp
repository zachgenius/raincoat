// Raincoat — font_guard: best-effort fontconfig isolation.
#include "font_guard.hpp"

#include <filesystem>
#include <fstream>
#include <sstream>

namespace raincoat {

namespace fs = std::filesystem;

namespace {

// The curated generic font directories, in probe order. Only those that exist on
// the host are exposed inside the sandbox (see curated_font_dirs()).
const char* kCuratedFontDirs[] = {
    "/usr/share/fonts/truetype/dejavu",  // DejaVu Sans/Serif/Sans Mono
    "/usr/share/fonts/truetype/noto",    // Noto Sans/Serif/... (TrueType)
    "/usr/share/fonts/opentype/noto",    // Noto (OpenType, incl. Color Emoji)
};

// Build a curated fonts.conf that lists ONLY the given generic font dirs plus the
// four generic-family aliases (sans-serif/serif/monospace/emoji). Combined with the
// runner's tmpfs mask of /usr/share/fonts + read-only re-bind of exactly these dirs,
// fontconfig enumerates a generic set instead of the host's full font list. Falls
// back to a bare /usr/share/fonts <dir> when no curated dir exists so the document
// is still a valid, non-empty fontconfig.
std::string build_curated_fonts_conf(const std::vector<std::string>& dirs) {
    std::ostringstream ss;
    ss << "<?xml version=\"1.0\"?>\n"
          "<!DOCTYPE fontconfig SYSTEM \"urn:fontconfig:fonts.dtd\">\n"
          "<fontconfig>\n"
          "  <!-- Raincoat curated generic font set: hide the host's full font list. -->\n";
    if (dirs.empty()) {
        ss << "  <dir>/usr/share/fonts</dir>\n";
    } else {
        for (const auto& d : dirs) ss << "  <dir>" << d << "</dir>\n";
    }
    ss << "  <cachedir>/tmp/fontconfig-cache</cachedir>\n"
          // The curated dejavu dir also ships DejaVuMathTeXGyre.ttf, a math/symbol
          // face fontconfig treats as a sans candidate. Reject it outright so it can
          // never satisfy a generic-family query (sans-serif would otherwise collapse
          // onto it, since a weak alias loses to it without the host conf.d bindings).
          "  <selectfont><rejectfont><pattern>"
          "<patelt name=\"family\"><string>DejaVu Math TeX Gyre</string></patelt>"
          "</pattern></rejectfont></selectfont>\n"
          // Pin the generic families to real body faces with a STRONG binding so they
          // win regardless of what else is present in the curated dirs.
          "  <match target=\"pattern\"><test name=\"family\"><string>sans-serif</string></test>"
          "<edit name=\"family\" mode=\"prepend\" binding=\"strong\">"
          "<string>Noto Sans</string><string>DejaVu Sans</string></edit></match>\n"
          "  <match target=\"pattern\"><test name=\"family\"><string>serif</string></test>"
          "<edit name=\"family\" mode=\"prepend\" binding=\"strong\">"
          "<string>Noto Serif</string><string>DejaVu Serif</string></edit></match>\n"
          "  <match target=\"pattern\"><test name=\"family\"><string>monospace</string></test>"
          "<edit name=\"family\" mode=\"prepend\" binding=\"strong\">"
          "<string>Noto Sans Mono</string><string>DejaVu Sans Mono</string></edit></match>\n"
          // Emoji needs the same STRONG pin: with only the weak alias below, a bare
          // `fc-match emoji` loses to DejaVu Sans even though Noto Color Emoji exists.
          "  <match target=\"pattern\"><test name=\"family\"><string>emoji</string></test>"
          "<edit name=\"family\" mode=\"prepend\" binding=\"strong\">"
          "<string>Noto Color Emoji</string></edit></match>\n"
          "  <alias><family>sans-serif</family><prefer>"
          "<family>Noto Sans</family><family>DejaVu Sans</family></prefer></alias>\n"
          "  <alias><family>serif</family><prefer>"
          "<family>Noto Serif</family><family>DejaVu Serif</family></prefer></alias>\n"
          "  <alias><family>monospace</family><prefer>"
          "<family>Noto Sans Mono</family><family>DejaVu Sans Mono</family></prefer></alias>\n"
          "  <alias><family>emoji</family><prefer>"
          "<family>Noto Color Emoji</family></prefer></alias>\n"
          "</fontconfig>\n";
    return ss.str();
}

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

std::vector<std::string> curated_font_dirs() {
    std::vector<std::string> out;
    std::error_code ec;
    for (const char* d : kCuratedFontDirs) {
        if (fs::is_directory(d, ec) && !ec) out.emplace_back(d);
    }
    return out;
}

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

    // Detect the curated generic font directories that exist on this host. The runner
    // uses these to mask /usr/share/fonts and re-bind ONLY the curated set read-only.
    result.font_dirs = curated_font_dirs();

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
        // Fallback: write the curated generic fonts.conf (lists only the curated dirs
        // that exist + generic aliases). A source that was requested but could not be
        // copied (missing / unreadable / write failed) is reported as a copy failure;
        // the absence of any source is reported as "no usable source".
        if (write_all(conf, build_curated_fonts_conf(result.font_dirs))) {
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
