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

// Compute the sandbox-space directory that must be masked with a tmpfs so the
// sandboxed (untrusted) child cannot read, forge, or erase the host audit log.
//
// The runner writes the audit log to `audit_log_path` (default
// `<cwd>/.raincoat/audit.log`), whose parent directory can land inside a
// read-write mount (the auto-mounted cwd in normal mode). Left unmasked, the
// child fully controls that file. This returns the audit log's PARENT directory,
// translated into sandbox space, so the runner can `--tmpfs` it and shadow the real
// log.
//
// GUIDING INVARIANT (attack rounds 1 & 2): the mask may shadow a directory ONLY when
// doing so loses no user data — i.e. the audit dir is raincoat's own `.raincoat`
// (raincoat creates/owns it, so an empty tmpfs overlay hides nothing the user placed
// there and discards no legitimate child output). "raincoat-owned" is keyed on the
// dir's basename being `.raincoat`. So masking applies to a raincoat-owned `.raincoat`
// that is child-writable, reached either as a proper descendant of a read-write mount
// (the normal auto-mounted cwd) OR as its own lone read-write mount root (e.g.
// `--strict --allow-write <cwd>/.raincoat`).
//
// Returns "" when no masking is needed or wanted: the audit dir is not inside any
// writable mount (the child cannot reach it); only a read-only mount covers it; the
// audit dir is NOT raincoat-owned (a custom `--audit-log` into a user data dir the
// user `--allow-write`'d) — masking it would hide the user's real files and discard
// the child's writes, so tamper-protection is dropped for that one custom log rather
// than destroy user data; or the user redundantly exposed the exact `.raincoat` as its
// own read-write mount root while a broader writable mount (the cwd) also covers it —
// that deliberate mount overrides the default mask so the child sees real contents.
std::string audit_mask_dir(const std::string& audit_log_path,
                           const std::vector<Mount>& mounts);

// True when the untrusted child could write the audit log's parent directory through
// some read-write mount (i.e. `audit_mask_dir`'s rw_exact/rw_proper condition holds).
// The runner uses this together with a "" result from `audit_mask_dir` to warn the
// user that the audit log at `audit_log_path` is NOT tamper-protected for this run
// (the child can forge or erase it) — e.g. a custom `--audit-log` in an
// `--allow-write`'d data dir, or a redundant `--allow-write` of `.raincoat`.
bool audit_dir_child_writable(const std::string& audit_log_path,
                              const std::vector<Mount>& mounts);

}  // namespace raincoat
