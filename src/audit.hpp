// Raincoat — audit: audit record + formatting. AuditRecord lives here.
#pragma once

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
};

std::string format_audit_start(const AuditRecord& r);
std::string format_audit_end(int exit_code);
bool write_audit(const std::string& path, const std::string& content, std::string& err);

}  // namespace raincoat
