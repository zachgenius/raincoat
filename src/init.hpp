// Raincoat — init: generate an example .raincoat.toml.
#pragma once

#include <string>

namespace raincoat {

std::string default_toml();
bool write_init(const std::string& path, bool force, std::string& err);

}  // namespace raincoat
