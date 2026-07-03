// Raincoat — fs_guard: mount planning / validation.
#include "fs_guard.hpp"

#include <filesystem>
#include <system_error>

namespace raincoat {

namespace fs = std::filesystem;

namespace {

// Lexically absolutize a user path against the given cwd. Absolute paths are
// returned unchanged; relative paths are joined onto cwd. No existence needed.
fs::path absolutize_path(const std::string& user_path, const std::string& cwd) {
    fs::path p(user_path);
    if (p.is_absolute()) {
        return p;
    }
    return fs::path(cwd) / p;
}

// Best-effort canonicalization: resolves symlinks/./.. when the path exists, else
// falls back to a lexically-normal absolute form so equality/ancestor checks still work.
fs::path canon_or_lexical(const fs::path& p) {
    std::error_code ec;
    fs::path c = fs::canonical(p, ec);
    if (!ec) {
        return c;
    }
    return p.lexically_normal();
}

// True when `ancestor` equals `descendant` or is a proper (component-wise) ancestor of
// it. Compares whole path components so "/home/user" is NOT treated as an ancestor of
// "/home/user2".
bool is_ancestor_or_equal(const fs::path& ancestor, const fs::path& descendant) {
    auto ai = ancestor.begin();
    auto di = descendant.begin();
    for (; ai != ancestor.end(); ++ai, ++di) {
        if (di == descendant.end() || *ai != *di) {
            return false;
        }
    }
    return true;
}

// Expand a leading "~" in an fs_deny entry against the real home, then reduce it to
// a canonical-or-lexical absolute path for ancestor comparison. "~" alone and "~/x"
// are expanded; a bare "~user" form is left untouched (we only know the current home).
fs::path resolve_deny_entry(const std::string& entry, const std::string& real_home) {
    std::string e = entry;
    if (!real_home.empty()) {
        if (e == "~") {
            e = real_home;
        } else if (e.size() >= 2 && e[0] == '~' && e[1] == '/') {
            e = real_home + e.substr(1);
        }
    }
    return canon_or_lexical(fs::path(e));
}

}  // namespace

std::optional<std::string> fs_deny_hit(const std::string& mount_host_path,
                                       const std::vector<std::string>& fs_deny,
                                       const std::string& real_home,
                                       MountMode mount_mode) {
    fs::path target = canon_or_lexical(fs::path(mount_host_path));
    for (const auto& d : fs_deny) {
        if (d.empty()) continue;
        fs::path denied = resolve_deny_entry(d, real_home);
        if (denied.empty()) continue;
        // (1) The mount root IS a denied path or lives beneath one — refuse outright.
        if (is_ancestor_or_equal(denied, target)) {
            return d;  // return the ORIGINAL spelling for a legible error
        }
        // (2) The mount root is a PROPER ANCESTOR of a denied path: bind-mounting the
        // parent would let the sandbox reach the denied child, so the deny guarantee
        // ("must NEVER be mounted, even when the user explicitly --allow-read/
        // --allow-write's it") requires refusing this mount too.
        if (is_ancestor_or_equal(target, denied)) {
            // For a READ-WRITE bind the denied descendant does NOT need to exist yet:
            // a writable ancestor grants the child creation rights, so it can mkdir +
            // write the denied path straight into the REAL filesystem through the bind.
            // Refuse regardless of current existence. For a READ-ONLY bind a
            // non-existent descendant has nothing to expose, so keep the existence gate
            // there — that also preserves "an ancestor of a not-yet-existing deny entry
            // is not a hit" for read mounts.
            if (mount_mode == MountMode::ReadWrite) {
                return d;
            }
            std::error_code ec;
            if (fs::exists(denied, ec)) {
                return d;
            }
        }
    }
    return std::nullopt;
}

bool cwd_is_home(const std::string& cwd, const std::string& real_home) {
    if (real_home.empty()) {
        return false;  // guard disabled
    }
    fs::path cwd_canon = canon_or_lexical(fs::path(cwd));
    fs::path home_canon = canon_or_lexical(fs::path(real_home));
    // Refuse when the cwd IS the home dir, or an ancestor of it (mounting cwd would
    // then expose the whole home tree). A cwd *below* home (a project subdir) is fine.
    return is_ancestor_or_equal(cwd_canon, home_canon);
}

std::optional<Mount> make_mount(const std::string& user_path, const std::string& cwd,
                                MountMode mode, std::string& err) {
    fs::path abs = absolutize_path(user_path, cwd);

    // canonicalize (realpath): resolves symlinks/./.. AND requires existence.
    std::error_code ec;
    fs::path canon = fs::canonical(abs, ec);
    if (ec) {
        err = "Error: allowed path does not exist: " + user_path;
        return std::nullopt;
    }

    Mount m;
    m.host_path = canon.string();
    m.sandbox_path = m.host_path;  // identity mapping
    m.mode = mode;
    return m;
}

std::vector<Mount> plan_mounts(const Config& cfg, const std::string& cwd,
                               const std::string& real_home, std::string& err,
                               std::string& warning) {
    warning.clear();
    std::vector<Mount> mounts;

    // A path that resolves under any [filesystem].deny entry must NEVER be mounted —
    // even when the user explicitly --allow-read/--allow-write's it. Refuse with a
    // clear error naming the offending deny rule rather than silently exposing it.
    auto refuse_if_denied = [&](const Mount& m, const std::string& user_path) -> bool {
        if (auto hit = fs_deny_hit(m.host_path, cfg.ext.fs_deny, real_home, m.mode)) {
            err = "Error: refusing to mount denied path: " + user_path +
                  " (matches filesystem deny rule '" + *hit + "')";
            return true;
        }
        return false;
    };

    for (const auto& r : cfg.allow_read) {
        auto m = make_mount(r, cwd, MountMode::ReadOnly, err);
        if (!m) {
            return {};
        }
        if (refuse_if_denied(*m, r)) {
            return {};
        }
        mounts.push_back(*m);
    }

    for (const auto& w : cfg.allow_write) {
        auto m = make_mount(w, cwd, MountMode::ReadWrite, err);
        if (!m) {
            return {};
        }
        if (refuse_if_denied(*m, w)) {
            return {};
        }
        mounts.push_back(*m);
    }

    // Non-strict: auto-add the cwd as ReadWrite unless it's already covered. A profile
    // with [filesystem].mode = "deny-by-default" (ext.fs_deny_by_default) suppresses the
    // auto-mount entirely, exactly like strict mode, so ONLY explicit allow paths are
    // exposed.
    const bool suppress_auto_cwd =
        cfg.strict || cfg.ext.fs_deny_by_default.value_or(false);
    if (!suppress_auto_cwd) {
        std::error_code ec;
        fs::path cwd_canon = fs::canonical(fs::path(cwd), ec);
        std::string cwd_key = ec ? cwd : cwd_canon.string();

        bool covered = false;
        for (const auto& m : mounts) {
            if (m.host_path == cwd_key) {
                covered = true;
                break;
            }
        }
        if (!covered) {
            // Privacy guard: never auto-mount the real home (or an ancestor of it) —
            // doing so would expose ~/.ssh, ~/.aws, browser profiles, etc. The user must
            // opt in explicitly via --allow-read / --allow-write.
            if (cwd_is_home(cwd, real_home)) {
                warning =
                    "Warning: refusing to auto-mount your home directory (" + cwd_key +
                    "); pass --allow-read/--allow-write to expose specific paths.";
            } else if (auto deny_hit = fs_deny_hit(cwd_key, cfg.ext.fs_deny, real_home,
                                                   MountMode::ReadWrite)) {
                // The cwd itself resolves under a deny rule: never auto-mount it.
                warning =
                    "Warning: refusing to auto-mount the working directory (" + cwd_key +
                    "); it matches filesystem deny rule '" + *deny_hit +
                    "'. Pass --allow-read/--allow-write to expose specific paths.";
            } else {
                auto m = make_mount(cwd, cwd, MountMode::ReadWrite, err);
                if (!m) {
                    return {};
                }
                mounts.push_back(*m);
            }
        }
    }

    err.clear();
    return mounts;
}

bool any_writable(const std::vector<Mount>& mounts) {
    for (const auto& m : mounts) {
        if (m.mode == MountMode::ReadWrite) {
            return true;
        }
    }
    return false;
}

std::string audit_mask_dir(const std::string& audit_log_path,
                           const std::vector<Mount>& mounts) {
    fs::path parent = fs::path(audit_log_path).parent_path();
    if (parent.empty()) {
        return {};
    }
    // The audit dir usually does not exist yet when this runs (the runner writes
    // the log after building argv), so fall back to a lexically-normal absolute
    // form. cwd is already canonical on Linux, so this matches the mount host_path.
    fs::path parent_canon = canon_or_lexical(parent);

    // Classify every mount that COVERS the audit dir (its root is the audit dir or
    // a proper ancestor of it). We need the full picture before deciding, because
    // the mask/no-mask choice depends on the *combination* of covering mounts, not
    // just the first one found.
    const Mount* rw_exact = nullptr;   // a RW mount rooted EXACTLY at the audit dir
    const Mount* rw_proper = nullptr;  // a RW mount that is a PROPER ancestor of it
    for (const auto& m : mounts) {
        if (m.mode != MountMode::ReadWrite) {
            // Read-only mounts: the child cannot write through them, so they never
            // create a tamper path and never need a mask.
            continue;
        }
        fs::path host = canon_or_lexical(fs::path(m.host_path));
        if (!is_ancestor_or_equal(host, parent_canon)) {
            continue;  // does not cover the audit dir
        }
        if (host == parent_canon) {
            rw_exact = &m;
        } else {
            rw_proper = &m;
        }
    }

    // No writable mount reaches the audit dir: the child cannot tamper (it is
    // outside every RW mount, or only a read-only mount covers it). Nothing to do.
    if (rw_exact == nullptr && rw_proper == nullptr) {
        return {};
    }

    // Guiding invariant (attack rounds 1 & 2): the tmpfs mask may shadow a directory
    // ONLY when doing so loses no user data -- i.e. the audit dir is raincoat's own
    // `.raincoat` (raincoat creates/owns it, so an empty overlay hides nothing the
    // user put there and discards no legitimate child output). For ANY other directory
    // the user pointed a custom --audit-log into, masking would tmpfs-hide the user's
    // real files and silently discard the child's writes on teardown, so we must NOT
    // mask it -- we drop tamper-protection for that one custom log rather than destroy
    // data. The default audit dir is `<cwd>/.raincoat`, so "raincoat-owned" is keyed on
    // the dir's basename being `.raincoat`.
    const bool raincoat_owned = (parent_canon.filename() == ".raincoat");

    // Carve-out: the user explicitly exposed the exact audit dir as its own RW mount
    // root WHILE a broader writable mount (typically the auto-mounted cwd) also covers
    // it. That redundant, deliberate exact mount is the user overriding the default
    // mask to see the dir's real contents -- honor the intent and do NOT shadow it.
    if (rw_exact != nullptr && rw_proper != nullptr) {
        return {};
    }

    // Mask ONLY raincoat-owned `.raincoat`. Any other directory the user pointed a
    // custom --audit-log into -- whether it is its own explicit RW mount root
    // (rw_exact) or merely a proper descendant of the auto-mounted cwd (rw_proper) --
    // holds the user's own files, so tmpfs-shadowing it would hide those files and
    // discard the child's legitimate writes on teardown. Drop tamper-protection for
    // that one custom log rather than destroy user data.
    if (!raincoat_owned) {
        return {};
    }

    // Raincoat-owned audit dir that the child could otherwise tamper with: return it
    // in sandbox space so the runner can tmpfs-shadow it. Masking loses no user data
    // (raincoat owns the dir) and keeps the host audit log tamper-proof. Translate
    // through the covering mount (the exact root if the dir is itself a mount, else the
    // proper-ancestor mount).
    const Mount* via = (rw_exact != nullptr) ? rw_exact : rw_proper;
    fs::path host = canon_or_lexical(fs::path(via->host_path));
    fs::path rel = parent_canon.lexically_relative(host);
    fs::path sandbox = fs::path(via->sandbox_path) / rel;
    return sandbox.lexically_normal().string();
}

bool audit_dir_child_writable(const std::string& audit_log_path,
                              const std::vector<Mount>& mounts) {
    fs::path parent = fs::path(audit_log_path).parent_path();
    if (parent.empty()) {
        return false;
    }
    fs::path parent_canon = canon_or_lexical(parent);
    for (const auto& m : mounts) {
        if (m.mode != MountMode::ReadWrite) {
            continue;  // child cannot write through a read-only mount
        }
        fs::path host = canon_or_lexical(fs::path(m.host_path));
        if (is_ancestor_or_equal(host, parent_canon)) {
            return true;  // a writable mount roots at or above the audit dir
        }
    }
    return false;
}

bool audit_dir_child_readable(const std::string& audit_log_path,
                              const std::vector<Mount>& mounts) {
    fs::path parent = fs::path(audit_log_path).parent_path();
    if (parent.empty()) {
        return false;
    }
    fs::path parent_canon = canon_or_lexical(parent);
    for (const auto& m : mounts) {
        // ANY mount — read-only OR read-write — makes the audit dir child-READABLE.
        // (audit_dir_child_writable deliberately skips read-only mounts; this must not.)
        fs::path host = canon_or_lexical(fs::path(m.host_path));
        if (is_ancestor_or_equal(host, parent_canon)) {
            return true;  // a mount roots at or above the audit dir
        }
    }
    return false;
}

}  // namespace raincoat
