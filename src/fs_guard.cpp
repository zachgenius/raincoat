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

}  // namespace

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

    for (const auto& r : cfg.allow_read) {
        auto m = make_mount(r, cwd, MountMode::ReadOnly, err);
        if (!m) {
            return {};
        }
        mounts.push_back(*m);
    }

    for (const auto& w : cfg.allow_write) {
        auto m = make_mount(w, cwd, MountMode::ReadWrite, err);
        if (!m) {
            return {};
        }
        mounts.push_back(*m);
    }

    // Non-strict: auto-add the cwd as ReadWrite unless it's already covered.
    if (!cfg.strict) {
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

}  // namespace raincoat
