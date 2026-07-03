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

}  // namespace

std::string summarize_audit(const std::string& audit_text) {
    std::string mode;       // strict | normal
    std::string network;    // full | off
    std::string fake_home;
    bool have_scrubbed = false;
    int scrubbed_count = 0;

    std::stringstream in(audit_text);
    std::string line;
    while (std::getline(in, line)) {
        // Strip a trailing carriage return in case of CRLF input.
        if (!line.empty() && line.back() == '\r') line.pop_back();

        std::string value;
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
    out << "Your real HOME stayed hidden behind a fake one";
    if (!fake_home.empty()) {
        out << " (" << fake_home << ")";
    }
    out << ", so the tool never got to see your actual home directory. ";

    out << "It ran in " << mode_word << " mode, and ";
    out << net_phrase << ". ";

    if (have_scrubbed) {
        out << scrubbed_count
            << (scrubbed_count == 1 ? " sensitive environment variable was"
                                    : " sensitive environment variables were")
            << " scrubbed before the command ever saw them.";
    } else {
        out << "No environment scrubbing was recorded for this run.";
    }

    out << "\nVerdict: this tool did not get to see you naked.";

    return out.str();
}

}  // namespace raincoat
