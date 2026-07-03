// Raincoat — util: leaf helpers with no raincoat-specific types.
#pragma once

#include <map>
#include <optional>
#include <string>
#include <vector>

namespace raincoat {

std::optional<std::string> canonicalize(const std::string& path);
std::string absolutize(const std::string& path, const std::string& base_cwd);
bool path_exists(const std::string& path);
bool is_dir(const std::string& path);
bool make_dirs(const std::string& path, std::string& err);
std::map<std::string, std::string> environ_to_map(char** envp);

std::string to_upper(std::string s);
bool starts_with(const std::string& s, const std::string& prefix);
bool ends_with(const std::string& s, const std::string& suffix);
std::vector<std::string> split(const std::string& s, char delim);
std::string trim(const std::string& s);

}  // namespace raincoat
