// Raincoat — profile: load + merge profile options.
#pragma once

#include <optional>
#include <string>

#include "config.hpp"

namespace raincoat {

std::optional<Options> load_profile(const std::string& path, std::string& err);
Options merge(const Options& profile, const Options& cli);

}  // namespace raincoat
