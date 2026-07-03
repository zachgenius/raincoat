// Raincoat — report: audit log summarization (pure).
#include "report.hpp"

#include <cctype>
#include <sstream>
#include <string>
#include <vector>

namespace raincoat {

namespace {

std::string trim(const std::string& s) {
    size_t b = 0, e = s.size();
    while (b < e && std::isspace(static_cast<unsigned char>(s[b]))) ++b;
    while (e > b && std::isspace(static_cast<unsigned char>(s[e - 1]))) --e;
    return s.substr(b, e - b);
}

// Return the trimmed value following a "<label>:" prefix, if the given line
// begins with that label. Returns empty optional-style via `found`.
bool line_value(const std::string& line, const std::string& label, std::string& out) {
    const std::string prefix = label + ":";
    if (line.size() < prefix.size()) return false;
    if (line.compare(0, prefix.size(), prefix) != 0) return false;
    out = trim(line.substr(prefix.size()));
    return true;
}

// Count comma-separated names in a value string, tolerating irregular
// whitespace and the "(none)" sentinel (which means zero).
int count_names(const std::string& value) {
    const std::string v = trim(value);
    if (v.empty()) return 0;
    if (v == "(none)") return 0;
    int count = 0;
    std::stringstream ss(v);
    std::string token;
    while (std::getline(ss, token, ',')) {
        if (!trim(token).empty()) ++count;
    }
    return count;
}

// Strip trailing slashes (but keep a lone "/") so path shapes compare cleanly.
std::string strip_trailing_slashes(const std::string& path) {
    std::string p = path;
    while (p.size() > 1 && p.back() == '/') p.pop_back();
    return p;
}

// True if `path` is (or is an ancestor of) a home ROOT itself — e.g. "/",
// "/home", "/home/<name>", or "/root". Mounting a whole home root exposes every
// credential/private subdir at once, so it is at least as sensitive as mounting
// one known credential dir. This catches the worst case that the per-subdir
// markers below miss: granting the entire home directory.
bool looks_home_root(const std::string& path) {
    const std::string p = strip_trailing_slashes(trim(path));
    if (p.empty()) return false;
    if (p == "/" || p == "/home" || p == "/root") return true;
    // "/home/<name>" with no further component is a per-user home root.
    if (p.compare(0, 6, "/home/") == 0) {
        return p.find('/', 6) == std::string::npos;
    }
    // "/root/<name>" is unusual, but "/root" itself is handled above.
    return false;
}

// True if `path` names (or lives under) a directory that is well-known to hold
// credentials / private data, OR is a home root itself. Used to detect when the
// user deliberately mounted something sensitive, so the report stops cheerfully
// claiming home stayed hidden.
bool looks_sensitive_path(const std::string& path) {
    if (looks_home_root(path)) return true;
    static const char* kMarkers[] = {
        "/.ssh",   "/.aws",     "/.azure",     "/.config/gcloud",
        "/.kube",  "/.gnupg",   "/.docker",    "/.npmrc",
        "/.pypirc","/.git-credentials",         "/.gitconfig",
        "/.config/gh",          "/.config/google-chrome",
        "/.config/chromium",    "/.mozilla",   "/Documents",
        "/Desktop","/Downloads",
    };
    for (const char* m : kMarkers) {
        if (path.find(m) != std::string::npos) return true;
    }
    return false;
}

}  // namespace

std::string summarize_audit(const std::string& audit_text) {
    std::string mode;       // strict | normal
    std::string network;    // full | off
    std::string fake_home;
    bool have_scrubbed = false;
    int scrubbed_count = 0;
    bool sensitive_mount = false;  // an allowed path lives under a known-sensitive dir

    // Consider a path string (possibly a comma-separated inline list) against the
    // sensitive-path markers, tripping `sensitive_mount` on any hit.
    auto scan_paths = [&](const std::string& value) {
        std::stringstream ss(value);
        std::string tok;
        while (std::getline(ss, tok, ',')) {
            const std::string p = trim(tok);
            if (!p.empty() && p != "(none)" && looks_sensitive_path(p))
                sensitive_mount = true;
        }
    };

    std::stringstream in(audit_text);
    std::string line;
    bool collecting_paths = false;  // inside an "Allowed ... paths:" block
    while (std::getline(in, line)) {
        // Strip a trailing carriage return in case of CRLF input.
        if (!line.empty() && line.back() == '\r') line.pop_back();

        std::string value;
        if (line_value(line, "Allowed read paths", value) ||
            line_value(line, "Allowed write paths", value)) {
            // The mounts may be inline (test fixtures) or on following "  - path"
            // continuation lines (the real audit format); handle both.
            collecting_paths = true;
            scan_paths(value);
            continue;
        }
        if (collecting_paths) {
            const std::string t = trim(line);
            if (t.rfind("- ", 0) == 0) {  // "  - /path" continuation
                scan_paths(t.substr(2));
                continue;
            }
            if (t == "(none)") continue;
            collecting_paths = false;  // block ended; fall through to normal parse
        }

        if (line_value(line, "Mode", value)) {
            mode = value;
        } else if (line_value(line, "Network", value)) {
            network = value;
        } else if (line_value(line, "Fake HOME", value)) {
            fake_home = value;
        } else if (line_value(line, "Env scrubbed", value)) {
            have_scrubbed = true;
            scrubbed_count = count_names(value);
        }
    }

    if (audit_text.empty()) {
        return "Raincoat has nothing to report — no audit trail was provided.";
    }

    const bool strict = (mode == "strict");
    const std::string mode_word = strict ? "strict" : "normal";

    std::string net_word = network.empty() ? "unknown" : network;
    std::string net_phrase;
    if (net_word == "off") {
        net_phrase = "network access was cut off (off)";
    } else if (net_word == "full") {
        net_phrase = "network access was left open (full)";
    } else {
        net_phrase = "network mode was " + net_word;
    }

    std::ostringstream out;
    out << "Raincoat kept an eye on things. ";
    // The fake-HOME guard hides the real home by DEFAULT, but the user can punch a
    // hole in it with --allow-read/--allow-write. Only make the reassuring claim
    // when nothing sensitive was deliberately mounted in.
    if (sensitive_mount) {
        out << "Your real HOME was swapped for a fake one";
        if (!fake_home.empty()) out << " (" << fake_home << ")";
        out << ", but you explicitly mounted in a path that usually holds "
               "credentials or private data, so the tool could see whatever was "
               "there. ";
    } else {
        out << "Your real HOME stayed hidden behind a fake one";
        if (!fake_home.empty()) out << " (" << fake_home << ")";
        out << ", so the tool never got to see your actual home directory. ";
    }

    out << "It ran in " << mode_word << " mode, and ";
    out << net_phrase << ". ";

    if (have_scrubbed) {
        // These are simply the parent variables that did NOT survive the safe
        // allowlist — not all of them are secrets, so avoid calling them
        // "sensitive"; report them as dropped/scrubbed.
        out << scrubbed_count
            << (scrubbed_count == 1 ? " environment variable was"
                                    : " environment variables were")
            << " scrubbed (only the safe allowlist survived) before the command "
               "ever saw them.";
    } else {
        out << "No environment scrubbing was recorded for this run.";
    }

    if (sensitive_mount) {
        out << "\nVerdict: mostly covered — but you handed over a sensitive path, "
               "so check that mount was intentional.";
    } else {
        out << "\nVerdict: this tool did not get to see you naked.";
    }

    return out.str();
}

}  // namespace raincoat
