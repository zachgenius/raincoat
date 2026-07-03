// Raincoat — font_guard: best-effort fontconfig isolation.
#pragma once

#include <string>

#include "config.hpp"

namespace raincoat {

FontSetup setup_fontconfig(const std::string& sandbox_dir, bool enabled,
                           const std::string& fonts_conf_source, std::string& err);

}  // namespace raincoat
