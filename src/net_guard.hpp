// Raincoat — net_guard: network mode flags.
#pragma once

#include <string>
#include <vector>

#include "config.hpp"

namespace raincoat {

std::vector<std::string> net_flags(NetMode m);
bool binds_resolv_conf(NetMode m);

}  // namespace raincoat
