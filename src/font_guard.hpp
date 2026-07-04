// Raincoat — font_guard: best-effort fontconfig isolation.
#pragma once

#include <string>
#include <vector>

#include "config.hpp"

namespace raincoat {

// Probe the host for the curated generic font directories and return those that
// exist (any subset of the known list, in a stable order). This is the ONLY set of
// host font dirs Raincoat exposes inside the sandbox when fontconfig is enabled:
// Noto Sans/Serif/Sans Mono/Color Emoji live under the truetype/opentype "noto"
// dirs and DejaVu Sans under "dejavu". Kept small + hard-coded on purpose so the
// child sees a generic, non-fingerprinting set rather than the host's full list.
std::vector<std::string> curated_font_dirs();

FontSetup setup_fontconfig(const std::string& sandbox_dir, bool enabled,
                           const std::string& fonts_conf_source, std::string& err);

}  // namespace raincoat
