// Raincoat — init: generate an example .raincoat.toml.
#pragma once

#include <string>
#include <vector>

namespace raincoat {

std::string default_toml();
bool write_init(const std::string& path, bool force, std::string& err);

// Create each directory in `dirs` (mkdir -p semantics), resolving relative entries
// against `base_cwd`. Used by `raincoat init` to honor a profile's [init].create_dirs
// (ext.init_create_dirs) in addition to writing .raincoat.toml. Existing directories
// are fine (not an error). On the first failure, set `err` and return false; on
// success clear `err` and return true. An empty list is a no-op success.
bool create_init_dirs(const std::vector<std::string>& dirs, const std::string& base_cwd,
                      std::string& err);

}  // namespace raincoat
