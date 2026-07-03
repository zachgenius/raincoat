// Raincoat — runner: STUB implementations.
#include "runner.hpp"

namespace raincoat {

Config resolve_config(const CliInvocation& /*inv*/,
                      const std::map<std::string, std::string>& /*parent_env*/,
                      const std::string& /*cwd*/, std::string& /*err*/) {
    return Config{};
}

int run(const Config& /*cfg*/, const std::map<std::string, std::string>& /*parent_env*/,
        const std::string& /*cwd*/, const std::string& /*assets_dir*/, std::string& /*err*/) {
    return 0;
}

}  // namespace raincoat
