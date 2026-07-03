// Raincoat — cli: command-line parsing.
#pragma once

#include <string>
#include <vector>

#include "config.hpp"

namespace raincoat {

CliInvocation parse_cli(const std::vector<std::string>& args);

}  // namespace raincoat
