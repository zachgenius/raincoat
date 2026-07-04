// Raincoat — audit: audit record formatting + writing.
//
// SECURITY INVARIANT: the formatted audit text must never contain any secret
// VALUE. We therefore only ever read env.allowed / env.set / env.scrubbed
// (which carry NAMES ONLY) and never iterate env.resolved (which holds values).
//
// AuditRecord.bwrap_command arrives ALREADY REDACTED — the runner produces it via
// bwrap::redact_argv_for_audit(argv, cfg.command.size()), which structurally
// redacts every --setenv VALUE at the argv vector layer (the only place it can be
// done unambiguously). format_audit_start therefore prints it VERBATIM; it does
// NOT re-parse or re-redact a flattened string (that heuristic was lossy — it
// leaked multi-word values and PEM/OpenSSH key bodies — and has been removed).
#include "audit.hpp"

#include <filesystem>
#include <fstream>
#include <sstream>
#include <system_error>

namespace raincoat {

namespace {

// Render a list of names as a comma-separated list, or "(none)" if empty.
std::string join_names(const std::vector<std::string>& names) {
    if (names.empty()) return "(none)";
    std::ostringstream ss;
    for (std::size_t i = 0; i < names.size(); ++i) {
        if (i) ss << ", ";
        ss << names[i];
    }
    return ss.str();
}

// Escape a string for embedding as a JSON string value (RFC 8259). Control
// characters below 0x20 become \uXXXX; the mandatory escapes handle ", \, and the
// common whitespace controls. This is display-only and never inspects env VALUES.
//
// RFC 8259 requires JSON TEXT to be valid UTF-8. Command args and env var NAMES on
// Linux are arbitrary byte strings (filenames need not be UTF-8), so this validates
// each byte: well-formed UTF-8 multibyte sequences (RFC 3629) pass through verbatim
// (preserving accents/emoji), while any invalid or stray high byte is replaced with
// U+FFFD (emitted as the ASCII escape �) so the audit is always valid JSON.
std::string json_escape(const std::string& s) {
    std::ostringstream o;
    static const char* hex = "0123456789abcdef";
    const std::size_t n = s.size();
    std::size_t i = 0;
    while (i < n) {
        unsigned char c = static_cast<unsigned char>(s[i]);
        if (c < 0x80) {  // ASCII: apply the standard JSON escapes.
            switch (c) {
                case '"':  o << "\\\""; break;
                case '\\': o << "\\\\"; break;
                case '\b': o << "\\b";  break;
                case '\f': o << "\\f";  break;
                case '\n': o << "\\n";  break;
                case '\r': o << "\\r";  break;
                case '\t': o << "\\t";  break;
                default:
                    if (c < 0x20)
                        o << "\\u00" << hex[(c >> 4) & 0xF] << hex[c & 0xF];
                    else
                        o << static_cast<char>(c);
            }
            ++i;
            continue;
        }

        // Multibyte lead byte: determine the expected length and the allowed range
        // of the FIRST continuation byte (RFC 3629 well-formed sequences only).
        std::size_t extra;
        unsigned char lo = 0x80, hi = 0xBF;
        if (c >= 0xC2 && c <= 0xDF)      { extra = 1; }
        else if (c == 0xE0)              { extra = 2; lo = 0xA0; }
        else if (c >= 0xE1 && c <= 0xEC) { extra = 2; }
        else if (c == 0xED)              { extra = 2; hi = 0x9F; }
        else if (c >= 0xEE && c <= 0xEF) { extra = 2; }
        else if (c == 0xF0)              { extra = 3; lo = 0x90; }
        else if (c >= 0xF1 && c <= 0xF3) { extra = 3; }
        else if (c == 0xF4)              { extra = 3; hi = 0x8F; }
        else { o << "\\ufffd"; ++i; continue; }  // 0x80-0xC1, 0xF5-0xFF: never a lead

        bool ok = (i + extra < n);
        for (std::size_t k = 1; ok && k <= extra; ++k) {
            unsigned char cc = static_cast<unsigned char>(s[i + k]);
            unsigned char lob = (k == 1) ? lo : 0x80;
            unsigned char hib = (k == 1) ? hi : 0xBF;
            if (cc < lob || cc > hib) ok = false;
        }
        if (!ok) { o << "\\ufffd"; ++i; continue; }  // truncated / invalid sequence

        for (std::size_t k = 0; k <= extra; ++k) o << static_cast<char>(s[i + k]);
        i += extra + 1;
    }
    return o.str();
}

// Emit a JSON array of strings from a vector (NAMES/paths only — never values).
std::string json_array(const std::vector<std::string>& v) {
    std::ostringstream o;
    o << '[';
    for (std::size_t i = 0; i < v.size(); ++i) {
        if (i) o << ',';
        o << '"' << json_escape(v[i]) << '"';
    }
    o << ']';
    return o.str();
}

}  // namespace

std::string format_audit_start(const AuditRecord& r) {
    std::ostringstream ss;

    ss << "=== Raincoat started ===\n";
    ss << "Command:      " << r.command_line << "\n";
    // Profile name (informational) — printed only when the run came from a profile
    // that named itself. Never a secret.
    if (r.profile_name.has_value() && !r.profile_name->empty()) {
        ss << "Profile:      " << *r.profile_name << "\n";
    }
    ss << "Mode:         " << (r.strict ? "strict" : "normal") << "\n";
    ss << "Network:      " << to_string(r.net) << "\n";
    ss << "Fake HOME:    " << r.fake_home << "\n";
    ss << "Workdir:      " << r.workdir << "\n";

    // Allowed filesystem paths, split by mount mode (paths only, no values).
    ss << "Allowed read paths:\n";
    bool any_ro = false;
    for (const auto& m : r.mounts) {
        if (m.mode == MountMode::ReadOnly) {
            ss << "  - " << m.host_path << "\n";
            any_ro = true;
        }
    }
    if (!any_ro) ss << "  (none)\n";

    ss << "Allowed write paths:\n";
    bool any_rw = false;
    for (const auto& m : r.mounts) {
        if (m.mode == MountMode::ReadWrite) {
            ss << "  - " << m.host_path << "\n";
            any_rw = true;
        }
    }
    if (!any_rw) ss << "  (none)\n";

    // Environment: NAMES ONLY, never values.
    ss << "Env allowed:  " << join_names(r.env.allowed) << "\n";
    ss << "Env set:      " << join_names(r.env.set) << "\n";
    ss << "Env scrubbed: " << join_names(r.env.scrubbed) << "\n";

    ss << "Timezone:     " << r.timezone << "\n";
    ss << "Locale:       " << r.locale << "\n";
    ss << "Fontconfig:   " << to_string(r.font) << "\n";
    // bwrap_command is already redacted upstream (bwrap::redact_argv_for_audit);
    // print it verbatim — never re-parse or re-redact a flattened string.
    ss << "Bubblewrap command:\n";
    ss << "  " << r.bwrap_command << "\n";

    // Active extended policies (secret-free notes) — only when something is active.
    if (!r.active_policy_notes.empty()) {
        ss << "Active policy:\n";
        for (const auto& note : r.active_policy_notes) {
            ss << "  - " << note << "\n";
        }
    }

    // Egress bridges active this run (phase 2). We print the child-visible endpoint and
    // the injected env var NAME; the real upstream is shown ONLY when redaction was
    // explicitly disabled (upstream_hidden == false). Request/response bodies are NEVER
    // logged here. This section never carries a secret VALUE.
    for (const auto& b : r.egress_bridges) {
        ss << "Egress bridge enabled: " << b.name << "\n";
        ss << "  Child-visible endpoint: " << b.child_endpoint << "\n";
        if (b.upstream_hidden) {
            ss << "  Upstream endpoint: hidden\n";
        } else {
            ss << "  Upstream endpoint: " << b.upstream << "\n";
        }
        ss << "  Injected env var: " << b.injected_env << "\n";
    }

    // Network policy / guarded proxy (phase 4). COUNTS only — never the host names, never
    // a secret. The proxy endpoint is a bare loopback host:port (safe). The honest
    // firewall-vs-proxy-aware reality is recorded separately as an active policy note.
    if (r.network_policy_enabled) {
        ss << "Network policy: enabled (default " << r.network_policy_default_action << ")\n";
        ss << "Guarded proxy: " << r.guarded_proxy_endpoint << "\n";
        ss << "  allow hosts: " << r.network_policy_allow_count << "\n";
        ss << "  block hosts: " << r.network_policy_block_count << "\n";
        ss << "  metadata endpoints blocked: "
           << (r.network_policy_metadata_blocked ? "yes" : "no") << "\n";
    }

    // Sections that were configured but are NOT yet enforced. Surfacing them keeps the
    // audit honest about what the rich profile does (and does not) actually do.
    if (!r.reserved_notes.empty()) {
        ss << "Reserved (configured, not enforced):\n";
        for (const auto& note : r.reserved_notes) {
            ss << "  - " << note << "\n";
        }
    }

    return ss.str();
}

std::string format_audit_end(int exit_code) {
    std::ostringstream ss;
    ss << "=== Raincoat finished (exit code " << exit_code << ") ===\n";
    return ss.str();
}

std::string format_audit_json(const AuditRecord& r, int exit_code) {
    // Split mounts into read-only / read-write path lists (paths only, no values),
    // mirroring the text formatter.
    std::vector<std::string> read_paths, write_paths;
    for (const auto& m : r.mounts) {
        if (m.mode == MountMode::ReadWrite) write_paths.push_back(m.host_path);
        else read_paths.push_back(m.host_path);
    }

    std::ostringstream o;
    o << '{';
    auto str_field = [&](const char* key, const std::string& val, bool& first) {
        if (!first) o << ',';
        first = false;
        o << '"' << key << "\":\"" << json_escape(val) << '"';
    };
    auto raw_field = [&](const char* key, const std::string& raw, bool& first) {
        if (!first) o << ',';
        first = false;
        o << '"' << key << "\":" << raw;
    };

    bool first = true;
    str_field("event", "run", first);
    str_field("command", r.command_line, first);
    if (r.profile_name.has_value() && !r.profile_name->empty())
        str_field("profile", *r.profile_name, first);
    str_field("mode", r.strict ? "strict" : "normal", first);
    str_field("network", to_string(r.net), first);
    str_field("fake_home", r.fake_home, first);
    str_field("workdir", r.workdir, first);
    raw_field("allowed_read_paths", json_array(read_paths), first);
    raw_field("allowed_write_paths", json_array(write_paths), first);
    // Environment: NAMES ONLY, never values.
    raw_field("env_allowed", json_array(r.env.allowed), first);
    raw_field("env_set", json_array(r.env.set), first);
    raw_field("env_scrubbed", json_array(r.env.scrubbed), first);
    str_field("timezone", r.timezone, first);
    str_field("locale", r.locale, first);
    str_field("fontconfig", to_string(r.font), first);
    raw_field("active_policy_notes", json_array(r.active_policy_notes), first);
    raw_field("reserved_notes", json_array(r.reserved_notes), first);

    // Egress bridges: child-visible endpoint + injected env NAME; the real upstream is
    // recorded ONLY when redaction was explicitly disabled (upstream_hidden == false).
    {
        if (!first) o << ',';
        first = false;
        o << "\"egress_bridges\":[";
        for (std::size_t i = 0; i < r.egress_bridges.size(); ++i) {
            const auto& b = r.egress_bridges[i];
            if (i) o << ',';
            o << "{\"name\":\"" << json_escape(b.name) << "\",";
            o << "\"child_endpoint\":\"" << json_escape(b.child_endpoint) << "\",";
            o << "\"injected_env\":\"" << json_escape(b.injected_env) << "\",";
            o << "\"upstream_hidden\":" << (b.upstream_hidden ? "true" : "false");
            if (!b.upstream_hidden)
                o << ",\"upstream\":\"" << json_escape(b.upstream) << '"';
            o << '}';
        }
        o << ']';
    }

    // Network policy / guarded proxy (phase 4): counts + endpoint, never host names.
    if (r.network_policy_enabled) {
        raw_field("network_policy_enabled", "true", first);
        str_field("network_policy_default_action", r.network_policy_default_action, first);
        str_field("guarded_proxy", r.guarded_proxy_endpoint, first);
        raw_field("network_policy_allow_hosts",
                  std::to_string(r.network_policy_allow_count), first);
        raw_field("network_policy_block_hosts",
                  std::to_string(r.network_policy_block_count), first);
        raw_field("network_policy_metadata_blocked",
                  r.network_policy_metadata_blocked ? "true" : "false", first);
    }

    if (!r.warnings.empty()) str_field("warnings", r.warnings, first);
    // bwrap_command arrives ALREADY redacted (see the header banner); embed verbatim.
    str_field("bwrap_command", r.bwrap_command, first);
    raw_field("exit_code", std::to_string(exit_code), first);
    o << "}\n";
    return o.str();
}

bool write_audit(const std::string& path, const std::string& content, std::string& err) {
    err.clear();

    std::error_code ec;
    std::filesystem::path p(path);
    std::filesystem::path parent = p.parent_path();
    if (!parent.empty()) {
        std::filesystem::create_directories(parent, ec);
        if (ec) {
            err = "Error: could not create audit log directory '" +
                  parent.string() + "': " + ec.message();
            return false;
        }
    }

    std::ofstream out(p, std::ios::binary | std::ios::app);
    if (!out) {
        err = "Error: could not open audit log for writing: " + path;
        return false;
    }
    out << content;
    out.flush();
    if (!out) {
        err = "Error: could not write to audit log: " + path;
        return false;
    }
    return true;
}

}  // namespace raincoat
