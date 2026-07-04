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

// -------------------------------------------------------------------------
// Minimal JSON helpers (for a JSON-format audit line). These are intentionally
// tiny: the audit JSON is emitted by audit.cpp::format_audit_json with a known,
// flat shape (string scalars + arrays-of-strings), so a full parser is overkill.
// -------------------------------------------------------------------------

// Read the string value for "<key>":"..." (first match). Handles the standard JSON
// backslash escapes the writer emits.
bool json_string(const std::string& j, const std::string& key, std::string& out) {
    const std::string pat = "\"" + key + "\":\"";
    std::size_t p = j.find(pat);
    if (p == std::string::npos) return false;
    p += pat.size();
    std::string v;
    for (; p < j.size(); ++p) {
        char c = j[p];
        if (c == '\\' && p + 1 < j.size()) {
            char n = j[++p];
            switch (n) {
                case 'n': v += '\n'; break;
                case 't': v += '\t'; break;
                case 'r': v += '\r'; break;
                case 'b': v += '\b'; break;
                case 'f': v += '\f'; break;
                default:  v += n;    break;  // ", \, /, and \uXXXX tail approx.
            }
            continue;
        }
        if (c == '"') break;
        v += c;
    }
    out = v;
    return true;
}

// Extract the inner text of an array value "<key>":[ ... ]. The audit arrays hold
// only strings, so there are no nested brackets to balance.
bool json_array_inner(const std::string& j, const std::string& key, std::string& inner) {
    const std::string pat = "\"" + key + "\":[";
    std::size_t p = j.find(pat);
    if (p == std::string::npos) return false;
    p += pat.size();
    std::size_t e = j.find(']', p);
    if (e == std::string::npos) return false;
    inner = j.substr(p, e - p);
    return true;
}

// Number of quoted string elements in a JSON array inner text.
int json_array_count(const std::string& inner) {
    int quotes = 0;
    for (std::size_t i = 0; i < inner.size(); ++i) {
        if (inner[i] == '\\') { ++i; continue; }
        if (inner[i] == '"') ++quotes;
    }
    return quotes / 2;
}

// True if a (trimmed) line opens a text-format run block. The real audit writes
// "=== Raincoat started ===" and the test fixtures use "Raincoat started"; both
// carry the phrase, so a substring probe covers either shape.
bool is_text_start_marker(const std::string& trimmed_line) {
    return trimmed_line.find("Raincoat started") != std::string::npos;
}

// Locate the LATEST run in an audit log that may interleave both formats. A single
// `.raincoat/audit.log` accumulates across invocations, and --audit-format is a
// per-invocation flag, so a log can hold an older JSON run followed by a newer text
// run (or vice-versa). We must summarize whichever run appears LAST — never
// unconditionally prefer JSON, which would silently misreport the current posture.
//
// Returns via out-params the 0-based line index at which the latest run begins
// (`start_line`, -1 if none found), whether that run is JSON (`is_json`), and, when
// JSON, the trimmed content of that single-line object (`json_content`).
void locate_latest_run(const std::string& audit_text, long& start_line, bool& is_json,
                       std::string& json_content) {
    start_line = -1;
    is_json = false;
    json_content.clear();

    long last_json_line = -1, last_text_line = -1;
    std::string last_json_content;

    std::istringstream in(audit_text);
    std::string line;
    long idx = -1;
    while (std::getline(in, line)) {
        ++idx;
        if (!line.empty() && line.back() == '\r') line.pop_back();
        const std::string t = trim(line);
        if (!t.empty() && t.front() == '{') {
            last_json_line = idx;
            last_json_content = t;
        }
        if (is_text_start_marker(t)) last_text_line = idx;
    }

    if (last_json_line < 0 && last_text_line < 0) return;  // no recognizable run

    if (last_json_line > last_text_line) {
        start_line = last_json_line;
        is_json = true;
        json_content = last_json_content;
    } else {
        start_line = last_text_line;  // may be -1 → parse from the top (no marker)
        is_json = false;
    }
}

}  // namespace

std::string summarize_audit(const std::string& audit_text, bool playful) {
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

    // Find the LATEST run in the log, regardless of format (the log can interleave
    // JSON and text runs across invocations; we summarize whichever appears last, not
    // whichever happens to be JSON).
    long run_start_line = -1;
    bool run_is_json = false;
    std::string json;  // trimmed JSON object of the latest run, when it is JSON
    locate_latest_run(audit_text, run_start_line, run_is_json, json);

    // JSON-format latest run: parse its single-line object. Extract the same facts the
    // text path derives so the rendering below is shared.
    if (run_is_json && !json.empty()) {
        json_string(json, "mode", mode);
        json_string(json, "network", network);
        json_string(json, "fake_home", fake_home);
        std::string scrubbed_inner;
        if (json_array_inner(json, "env_scrubbed", scrubbed_inner)) {
            have_scrubbed = true;
            scrubbed_count = json_array_count(scrubbed_inner);
        }
        // Scan the allowed read/write path arrays for deliberately-mounted sensitive
        // paths (each element is a quoted string).
        auto scan_json_paths = [&](const std::string& key) {
            std::string inner;
            if (!json_array_inner(json, key, inner)) return;
            std::stringstream ss(inner);
            std::string tok;
            while (std::getline(ss, tok, ',')) {
                // strip surrounding quotes/space
                std::string p = trim(tok);
                if (p.size() >= 2 && p.front() == '"' && p.back() == '"')
                    p = p.substr(1, p.size() - 2);
                if (!p.empty() && looks_sensitive_path(p)) sensitive_mount = true;
            }
        };
        scan_json_paths("allowed_read_paths");
        scan_json_paths("allowed_write_paths");
    }

    std::stringstream in(audit_text);
    std::string line;
    bool collecting_paths = false;  // inside an "Allowed ... paths:" block
    long line_idx = -1;
    // Parse ONLY the latest text run: skip everything before its start marker so an
    // older run's facts (mode/network/scrubbed) cannot leak into the summary.
    const long text_start = run_start_line;  // -1 when no marker → parse from the top
    while (!run_is_json && std::getline(in, line)) {
        ++line_idx;
        if (line_idx < text_start) continue;
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

    // Plain-mode summary (profile [report].playful_summary = false): the same facts,
    // stated flatly as labeled lines with no persona/verdict flourish.
    if (!playful) {
        std::ostringstream p;
        p << "Raincoat run summary:\n";
        p << "  Mode: " << (strict ? "strict" : "normal") << "\n";
        p << "  Network: " << net_word << "\n";
        p << "  Real HOME: "
          << (sensitive_mount ? "hidden, but a sensitive path was explicitly mounted"
                              : "hidden behind a fake home");
        if (!fake_home.empty()) p << " (" << fake_home << ")";
        p << "\n";
        if (have_scrubbed) {
            p << "  Environment variables scrubbed: " << scrubbed_count << "\n";
        } else {
            p << "  Environment variables scrubbed: not recorded\n";
        }
        return p.str();
    }

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
