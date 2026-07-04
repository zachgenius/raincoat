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

// Create a "wakeup" fd pair used to break a blocking poll() when a server is asked to
// stop. On Linux this is a single eventfd (read_fd == write_fd), preserving the historic
// behavior byte-for-byte; on platforms without eventfd (macOS/BSD) it is a non-blocking
// self-pipe (read_fd = pipe read end, write_fd = pipe write end). Poll read_fd for POLLIN;
// poke write_fd to signal. The payload is irrelevant (one-shot). Returns false + err on
// failure. Close both with close_wakeup_fds (skips a double-close when they are equal).
bool make_wakeup_fds(int& read_fd, int& write_fd, std::string& err);
void close_wakeup_fds(int& read_fd, int& write_fd);

std::string to_upper(std::string s);
bool starts_with(const std::string& s, const std::string& prefix);
bool ends_with(const std::string& s, const std::string& suffix);
std::vector<std::string> split(const std::string& s, char delim);
std::string trim(const std::string& s);

}  // namespace raincoat
