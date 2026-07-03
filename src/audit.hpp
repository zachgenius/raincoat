// Raincoat — audit: audit record + formatting. AuditRecord lives here.
#pragma once

#include <optional>
#include <string>
#include <vector>

#include "config.hpp"

namespace raincoat {

struct AuditRecord {
    std::string command_line;
    bool strict = false;
    NetMode net = NetMode::Full;
    std::string fake_home;
    std::string workdir;
    std::vector<Mount> mounts;
    EnvResolution env;
    FontStatus font = FontStatus::Disabled;
    std::string timezone;
    std::string locale;
    std::string bwrap_command;

    // Rich sectioned-config transparency (all optional; empty => not printed):
    //   profile_name        -> the [profile_name] the run was configured from.
    //   active_policy_notes -> short, secret-free notes about which extended policies
    //                          are ACTIVE this run (env_deny/fs_deny/scrub_patterns/
    //                          backend overrides/tripwire). NAMES/counts only.
    //   reserved_notes      -> sections that are configured but NOT yet enforced
    //                          (ext.reserved_notes) — surfaced honestly so behavior is
    //                          never silently misrepresented.
    std::optional<std::string> profile_name;
    std::vector<std::string> active_policy_notes;
    std::vector<std::string> reserved_notes;
};

std::string format_audit_start(const AuditRecord& r);
std::string format_audit_end(int exit_code);
bool write_audit(const std::string& path, const std::string& content, std::string& err);

}  // namespace raincoat
