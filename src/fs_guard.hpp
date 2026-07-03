// Raincoat — fs_guard: mount planning / validation.
#pragma once

#include <optional>
#include <string>
#include <vector>

#include "config.hpp"

namespace raincoat {

std::optional<Mount> make_mount(const std::string& user_path, const std::string& cwd,
                                MountMode mode, std::string& err);

// True when auto-mounting `cwd` would expose the real home directory — i.e. when
// (canonicalized) `cwd` equals `real_home` or is an ancestor of it. Auto-mounting in
// that case would bind ~/.ssh, ~/.aws, etc. into the sandbox, defeating Raincoat's
// purpose. `real_home == ""` disables the guard and always returns false.
bool cwd_is_home(const std::string& cwd, const std::string& real_home);

// Build mounts for every allow_read (RO) and allow_write (RW), reads first. In
// non-strict mode, append the cwd as a ReadWrite mount when it is not already covered
// by an allow path — EXCEPT when `cwd_is_home(cwd, real_home)` holds, in which case the
// cwd is NOT auto-mounted and `warning` is set to a user-facing message the runner can
// print and log. In strict mode the cwd is never auto-added. On any missing path, set
// `err` and return an empty vector. `real_home == ""` disables the home guard.
std::vector<Mount> plan_mounts(const Config& cfg, const std::string& cwd,
                               const std::string& real_home, std::string& err,
                               std::string& warning);

bool any_writable(const std::vector<Mount>& mounts);

}  // namespace raincoat
