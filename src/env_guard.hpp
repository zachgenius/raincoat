// Raincoat — env_guard: environment scrubbing / resolution.
#pragma once

#include <map>
#include <string>
#include <utility>
#include <vector>

#include "config.hpp"

namespace raincoat {

bool is_sensitive_env(const std::string& name);

EnvResolution resolve_env(const std::map<std::string, std::string>& parent,
                          const std::vector<std::string>& allow_env,
                          const std::vector<std::pair<std::string, std::string>>& set_env,
                          const std::map<std::string, std::string>& defaults,
                          bool strict);

}  // namespace raincoat
