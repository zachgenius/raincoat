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

}  // namespace

std::string format_audit_start(const AuditRecord& r) {
    std::ostringstream ss;

    ss << "=== Raincoat started ===\n";
    ss << "Command:      " << r.command_line << "\n";
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

    return ss.str();
}

std::string format_audit_end(int exit_code) {
    std::ostringstream ss;
    ss << "=== Raincoat finished (exit code " << exit_code << ") ===\n";
    return ss.str();
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
