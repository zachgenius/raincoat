// Raincoat — runner: resolve config + orchestrate the sandboxed run.
#pragma once

#include <map>
#include <string>

#include "config.hpp"

namespace raincoat {

Config resolve_config(const CliInvocation& inv,
                      const std::map<std::string, std::string>& parent_env,
                      const std::string& cwd, std::string& err);

int run(const Config& cfg, const std::map<std::string, std::string>& parent_env,
        const std::string& cwd, const std::string& assets_dir, std::string& err);

}  // namespace raincoat
