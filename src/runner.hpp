// Raincoat — runner: resolve config + orchestrate the sandboxed run.
#pragma once

#include <map>
#include <optional>
#include <string>

#include "config.hpp"

namespace raincoat {

// Path of the config to auto-load when no --profile was given, or nullopt. Search order (first
// readable wins): ./.raincoat.toml, then $XDG_CONFIG_HOME/raincoat/config.toml (fallback
// ~/.config/raincoat/config.toml), then ~/.raincoat.toml. Called by the CLI before resolve_config.
std::optional<std::string> discover_default_config(const std::string& cwd);

Config resolve_config(const CliInvocation& inv,
                      const std::map<std::string, std::string>& parent_env,
                      const std::string& cwd, std::string& err);

int run(const Config& cfg, const std::map<std::string, std::string>& parent_env,
        const std::string& cwd, const std::string& assets_dir, std::string& err);

}  // namespace raincoat
